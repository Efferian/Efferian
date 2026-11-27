use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use efferian_authz::{
    ArchivedDependency, AuthContext, AuthzError, ExecutionTarget, NodeAuthTarget, authorize_admin,
    authorize_discovery_target, authorize_node_read, authorize_profile_discover,
    authorize_profile_invoke, authorize_tool_test, check_archived_invoke_metadata,
    check_profile_invoke_metadata,
};
use efferian_protocol::{
    AccountSecretPayload, ExecuteReqPayload, ExecutionId, ManagedAccount, NodeId, PrincipalId,
    ProfileId, ProfileToolBinding, TargetSelector, ToolSpec, UpstreamAccountMode, UpstreamId,
    error_codes as code, validate_http_headers_no_auth_collision,
};
use http::StatusCode;
use rusqlite::{Connection, OptionalExtension, Row};
use serde::Serialize;
use serde_json::{Map, Value};
use utoipa::ToSchema;

use crate::catalog::accounts::{AccountMetadata, account_by_id, invoke_bindings, open_account};
use crate::catalog::profiles::read_edition;
use crate::catalog::tools::{ToolRevision, read_tool_revision, static_account};
use crate::catalog::upstreams::{UpstreamConfig, read_upstream_config};
use crate::execution::state::UpstreamReservation;
use crate::http::{ApiError, ApiResult, AppState};
use crate::node_bridge::{NodeDispatcher, NodeSendError, ReadyNode};
use crate::storage::{
    ExecutionTarget as WriteTarget, FollowUpWrite, InvokeResource, NewExecutionWrite, WriteTx, id,
    json, opt_id,
};
use crate::upstream_dispatch::{InvokeUpstream, UpstreamCredential};

use super::{InvokeInput, invalid_arguments};

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(super) struct AvailableTarget {
    pub(super) node_id: NodeId,
    pub(super) name: String,
}

struct NodeCandidate {
    auth: NodeAuthTarget,
    name: String,
    session_epoch: u64,
    tags: Vec<String>,
}

impl NodeCandidate {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            auth: NodeAuthTarget {
                node_id: id(row, 0)?,
                managed_by_principal_id: opt_id(row, 1)?,
            },
            name: row.get(2)?,
            session_epoch: row.get(3)?,
            tags: json(row, 4)?,
        })
    }

    fn target(&self) -> ExecutionTarget<'_> {
        ExecutionTarget::Managed {
            selected_id: self.auth.node_id,
            node: Some(&self.auth),
        }
    }

    fn matches(&self, selector: &TargetSelector, fixed: Option<NodeId>) -> bool {
        if fixed.is_some_and(|id| id != self.auth.node_id) {
            return false;
        }
        match selector {
            TargetSelector::Fixed { node_ids } => node_ids.contains(&self.auth.node_id),
            TargetSelector::Tag { tag } => self.tags.contains(tag),
        }
    }

    fn ready(&self, bridge: &dyn NodeDispatcher) -> Option<ReadyNode> {
        bridge
            .ready_node(self.auth.node_id)
            .filter(|ready| ready.epoch == self.session_epoch)
    }
}

const ACTIVE_NODE_COLUMNS: &str =
    "SELECT node_id, managed_by_principal_id, name, session_epoch, tags_json
     FROM nodes WHERE revoked_at_ms IS NULL";

fn exact_node(conn: &Connection, target: &str) -> rusqlite::Result<Option<NodeCandidate>> {
    // A branded ID can also be somebody else's node name. Never look up the
    // name after parsing a branded ID, including when that ID is invisible.
    let (column, value) = match NodeId::parse(target) {
        Ok(id) => ("node_id", id.to_string()),
        Err(_) => ("name", target.to_owned()),
    };
    conn.prepare_cached(&format!("{ACTIVE_NODE_COLUMNS} AND {column} = ?1"))?
        .query_row([value], NodeCandidate::read)
        .optional()
}

fn visit_selector_nodes(
    conn: &Connection,
    ctx: &AuthContext,
    selector: &TargetSelector,
    fixed: Option<NodeId>,
    mut visit: impl FnMut(NodeCandidate) -> ApiResult<ControlFlow<()>>,
) -> ApiResult<()> {
    if let Some(node_id) = fixed {
        if let Some(node) = exact_node(conn, &node_id.to_string())?
            && node.matches(selector, fixed)
        {
            let _ = visit(node)?;
        }
        return Ok(());
    }
    let (condition, value) = match selector {
        TargetSelector::Fixed { node_ids } => (
            "node_id IN (SELECT value FROM json_each(?1))",
            serde_json::to_string(node_ids).map_err(|_| ApiError::internal())?,
        ),
        TargetSelector::Tag { tag } => (
            "EXISTS (SELECT 1 FROM json_each(nodes.tags_json) WHERE value = ?1)",
            tag.clone(),
        ),
    };
    let mut sql = format!("{ACTIVE_NODE_COLUMNS} AND {condition}");
    let mut parameters = vec![value];
    if let Some(allowed) = &ctx.token.allowed_nodes {
        sql.push_str(" AND node_id IN (SELECT value FROM json_each(?2))");
        parameters.push(serde_json::to_string(allowed).map_err(|_| ApiError::internal())?);
    }
    sql.push_str(" ORDER BY name COLLATE BINARY");
    let mut statement = conn.prepare_cached(&sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(&parameters))?;
    while let Some(row) = rows.next()? {
        if visit(NodeCandidate::read(row)?)?.is_break() {
            break;
        }
    }
    Ok(())
}

fn visible_node(ctx: &AuthContext, profile_id: ProfileId, node: &NodeCandidate) -> ApiResult<bool> {
    match authorize_discovery_target(ctx, profile_id, node.target()) {
        Ok(()) => Ok(true),
        Err(AuthzError::ResourceNotFound | AuthzError::ScopeNarrowedOut) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn discovery_targets(
    conn: &Connection,
    ctx: &AuthContext,
    profile_id: ProfileId,
    selector: &TargetSelector,
    fixed: Option<NodeId>,
    first_only: bool,
) -> ApiResult<Vec<AvailableTarget>> {
    let mut visible = Vec::new();
    visit_selector_nodes(conn, ctx, selector, fixed, |node| {
        if visible_node(ctx, profile_id, &node)? {
            visible.push(AvailableTarget {
                node_id: node.auth.node_id,
                name: node.name,
            });
            if first_only {
                return Ok(ControlFlow::Break(()));
            }
        }
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(visible)
}

pub(super) struct Candidate {
    resource: InvokeResource,
    pub(super) binding: Option<ProfileToolBinding>,
    revision: ToolRevision,
    selected: Selected,
    pub(super) account: Option<AccountMetadata>,
    pub(super) runtime: Duration,
}

enum Selected {
    Node {
        node_id: NodeId,
        ready: ReadyNode,
    },
    Upstream {
        upstream_id: UpstreamId,
        config: UpstreamConfig,
    },
}

pub(super) struct Prepared {
    pub(super) execution_id: ExecutionId,
    pub(super) dispatch: Dispatch,
}

pub(super) enum Dispatch {
    Node(Box<ExecuteReqPayload>),
    Upstream(Box<InvokeUpstream>),
}

impl Candidate {
    pub(super) fn matches(&self, previous: &Self) -> bool {
        // Revision and edition rows are immutable. Effective disable flags,
        // visibility, permissions, and selector membership were checked again
        // by resolving the current candidate in the writer.
        let same_resource = match (self.resource, previous.resource) {
            (
                InvokeResource::Profile {
                    profile_id: a,
                    version: av,
                },
                InvokeResource::Profile {
                    profile_id: b,
                    version: bv,
                },
            ) => a == b && av == bv,
            (InvokeResource::ToolTest { .. }, InvokeResource::ToolTest { .. }) => true,
            _ => false,
        };
        let same_selection = match (&self.selected, &previous.selected) {
            (
                Selected::Node {
                    node_id: a,
                    ready: ar,
                },
                Selected::Node {
                    node_id: b,
                    ready: br,
                },
            ) => a == b && ar.epoch == br.epoch,
            (
                Selected::Upstream {
                    upstream_id: a,
                    config: ac,
                },
                Selected::Upstream {
                    upstream_id: b,
                    config: bc,
                },
            ) => a == b && ac.config_version == bc.config_version,
            _ => false,
        };
        let account_key = |account: &AccountMetadata| {
            (
                account.account_id,
                account.secret_version,
                account.visibility,
                account.kind,
                account.upstream_id,
                account.owner_principal_id,
            )
        };
        same_resource
            && same_selection
            && self.revision.tool_id == previous.revision.tool_id
            && self.revision.version == previous.revision.version
            && self.account.as_ref().map(account_key) == previous.account.as_ref().map(account_key)
    }

    pub(super) fn prepare(
        &self,
        state: &AppState,
        execution_id: ExecutionId,
        principal_id: PrincipalId,
        arguments: &Map<String, Value>,
        envelope: Option<&[u8]>,
    ) -> ApiResult<Prepared> {
        let schema = self
            .revision
            .definition
            .input_schema
            .as_ref()
            .ok_or_else(ApiError::internal)?;
        let validator = state
            .schemas
            .get_or_compile(
                self.revision.tool_id,
                self.revision.version,
                &self.revision.input_schema_sha256,
                schema,
            )
            .map_err(|_| ApiError::internal())?;
        if !validator.is_valid(&Value::Object(arguments.clone())) {
            return Err(invalid_arguments());
        }
        let secret = match (&self.account, envelope) {
            (Some(account), Some(envelope)) => Some(open_account(&state.vault, account, envelope)?),
            (None, None) => None,
            _ => return Err(ApiError::internal()),
        };
        let dispatch = match &self.selected {
            Selected::Node { .. } => {
                let account =
                    self.account
                        .as_ref()
                        .zip(secret.as_ref())
                        .map(|(account, payload)| ManagedAccount {
                            account_id: account.account_id,
                            upstream_id: account.upstream_id,
                            payload,
                        });
                let policy = state
                    .config
                    .egress_policy()
                    .map_err(|_| ApiError::internal())?;
                let request = self
                    .revision
                    .definition
                    .resolve_managed(
                        execution_id,
                        arguments,
                        account,
                        state.config.max_runtime_ms,
                        &policy,
                    )
                    .map_err(|_| invalid_arguments())?;
                Dispatch::Node(Box::new(request))
            }
            Selected::Upstream {
                upstream_id,
                config,
            } => {
                let ToolSpec::UpstreamRef {
                    upstream_tool_name, ..
                } = &self.revision.definition.spec
                else {
                    return Err(ApiError::internal());
                };
                let auth = match (&self.account, secret) {
                    (Some(account), Some(AccountSecretPayload::HttpAuth { auth })) => {
                        Some(UpstreamCredential {
                            account_id: account.account_id,
                            secret_version: account.secret_version,
                            secret: auth,
                        })
                    }
                    (None, None) => None,
                    _ => return Err(ApiError::internal()),
                };
                validate_http_headers_no_auth_collision(
                    &config.headers,
                    auth.as_ref().map(|auth| auth.secret.header_name()),
                )
                .map_err(|_| invalid_arguments())?;
                Dispatch::Upstream(Box::new(InvokeUpstream {
                    execution_id,
                    principal_id,
                    upstream_id: *upstream_id,
                    config_version: config.config_version,
                    url: config.url.clone(),
                    headers: config.headers.clone(),
                    auth,
                    tool_name: upstream_tool_name.clone(),
                    arguments: arguments.clone(),
                }))
            }
        };
        Ok(Prepared {
            execution_id,
            dispatch,
        })
    }

    pub(super) fn register_dispatch(
        &self,
        tx: &WriteTx<'_>,
        state: &AppState,
        ctx: &AuthContext,
        prepared: &Prepared,
    ) -> ApiResult<Option<UpstreamReservation>> {
        if !state.execution.is_accepting() {
            return Err(ApiError::overloaded());
        }
        let busy = |code| ApiError::new(StatusCode::TOO_MANY_REQUESTS, code).retryable();
        match self.selected {
            Selected::Node { node_id, ready } => {
                let active: usize = tx
                    .conn()
                    .prepare_cached(
                        "SELECT count(*) FROM executions
                     WHERE node_id = ?1 AND state IN ('accepted', 'running')",
                    )?
                    .query_row([node_id.to_string()], |row| row.get(0))?;
                if active
                    >= state
                        .config
                        .max_node_concurrent_executions
                        .min(ready.max_concurrent_executions)
                {
                    return Err(busy(code::NODE_BUSY));
                }
                Ok(None)
            }
            Selected::Upstream { upstream_id, .. } => state
                .execution
                .reserve_upstream(prepared.execution_id, upstream_id, ctx.caller.principal_id)
                .map(Some)
                .ok_or_else(|| busy(code::UPSTREAM_BUSY)),
        }
    }

    pub(super) fn execution_write(
        &self,
        now: i64,
        state: &AppState,
        ctx: &AuthContext,
        input: &InvokeInput,
        execution_id: ExecutionId,
    ) -> NewExecutionWrite {
        let executor = match self.selected {
            Selected::Node { node_id, ready } => WriteTarget::Node {
                node_id,
                session_epoch: ready.epoch,
            },
            Selected::Upstream { upstream_id, .. } => WriteTarget::Upstream(upstream_id),
        };
        let deadline_budget = self.runtime.as_millis() + u128::from(state.config.deadline_grace_ms);
        let deadline_at_ms = now.saturating_add(i64::try_from(deadline_budget).unwrap_or(i64::MAX));
        NewExecutionWrite {
            execution_id,
            request_id: input.request_id,
            caller: ctx.caller.principal_id,
            token: ctx.token.token_id,
            resource: self.resource,
            public_name: input.public_name.clone(),
            requested_target: input.target.clone(),
            arguments: input.digest.clone(),
            executor,
            account_id: self.account.as_ref().map(|account| account.account_id),
            deadline_at_ms,
        }
    }

    pub(super) fn send_to_node(
        &self,
        tx: &mut WriteTx<'_>,
        bridge: Arc<dyn NodeDispatcher>,
        request: ExecuteReqPayload,
    ) {
        let Selected::Node { node_id, ready } = self.selected else {
            return;
        };
        tx.on_commit_follow_up(move || {
            let execution_id = request.execution_id;
            let code = match bridge.try_send_execute(node_id, ready.epoch, request) {
                Ok(()) => return None,
                Err(NodeSendError::Full) => "node_ws_backpressure",
                Err(NodeSendError::Closed) => "node_disconnected_before_dispatch",
            };
            Some(FollowUpWrite::new(move |tx| {
                tx.fail_node_dispatch(execution_id, code)
            }))
        });
    }
}

pub(super) fn resolve_candidate(
    conn: &Connection,
    ctx: &AuthContext,
    state: &AppState,
    resource: InvokeResource,
    input: &InvokeInput,
) -> ApiResult<Candidate> {
    let (profile, binding, tool_id, tool_version) = match resource {
        InvokeResource::Profile {
            profile_id,
            version,
        } => {
            // Owner activity is evaluated by the profile-invoke metadata gate,
            // where it can make an inaccessible target indistinguishable from
            // a missing one. Let that gate see the narrowed target candidates.
            match authorize_profile_discover(ctx, Some(profile_id)) {
                Ok(()) | Err(AuthzError::OwnerDisabled | AuthzError::ManagedByDisabled) => {}
                Err(error) => return Err(error.into()),
            }
            let binding = read_edition(conn, profile_id, version.get())?
                .filter(|edition| edition.disabled_at_ms.is_none())
                .and_then(|edition| {
                    edition
                        .bindings
                        .into_iter()
                        .find(|binding| binding.public_name == input.public_name)
                });
            let Some(binding) = binding else {
                check_profile_invoke_metadata(ctx, Some(profile_id), None)?;
                return Err(ApiError::not_found());
            };
            let (tool_id, version) = (binding.tool_id, binding.tool_version);
            (Some(profile_id), Some(binding), tool_id, version)
        }
        InvokeResource::ToolTest {
            tool_id,
            resolved_version,
            ..
        } => {
            authorize_admin(ctx)?;
            (None, None, tool_id, resolved_version.get())
        }
    };
    let fixed = binding.as_ref().and_then(|binding| binding.fixed_node_id);
    let Some(revision) = read_tool_revision(conn, tool_id, tool_version)? else {
        if profile.is_none() {
            return Err(ApiError::not_found());
        }
        let evidence = match fixed {
            Some(node_id) => exact_node(conn, &node_id.to_string())?,
            None => None,
        };
        let evidence = evidence
            .as_ref()
            .filter(|node| {
                input.target.as_ref().is_none_or(|target| {
                    NodeId::parse(target)
                        .map_or_else(|_| node.name == *target, |id| id == node.auth.node_id)
                })
            })
            .map(NodeCandidate::target);
        return Err(missing_tool(ctx, profile, evidence)?);
    };
    let (selected, account) = match &revision.definition.spec {
        ToolSpec::UpstreamRef {
            upstream_id,
            account_mode,
            ..
        } => {
            let target = ExecutionTarget::Upstream {
                upstream_id: *upstream_id,
                account: *account_mode,
            };
            // Run the activity/target gate before inspecting upstream details.
            // A live caller scoped to nodes cannot see this kind of target.
            let target_visible = match profile {
                Some(id) => match authorize_discovery_target(ctx, id, target) {
                    Ok(()) | Err(AuthzError::OwnerDisabled | AuthzError::ManagedByDisabled) => {
                        Some(target)
                    }
                    Err(AuthzError::ResourceNotFound | AuthzError::ScopeNarrowedOut) => None,
                    Err(error) => return Err(error.into()),
                },
                None => Some(target),
            };
            if target_visible.is_none() {
                metadata_gate(ctx, profile, None)?;
            }
            let config = read_upstream_config(conn, *upstream_id)?;
            let Some(config) = config else {
                return Err(missing_tool(ctx, profile, Some(target))?);
            };
            metadata_gate(ctx, profile, target_visible)
                .map_err(|error| account_reason(error, &config.slug))?;
            check_new_request(state, input, ctx.now_ms)?;
            if input.target.is_some() {
                return Err(invalid_arguments());
            }
            if revision.disabled_at_ms.is_some() || config.disabled_at_ms.is_some() {
                return Err(ApiError::conflict(code::TOOL_DISABLED));
            }
            let bindings = if *account_mode == UpstreamAccountMode::CallerBound {
                invoke_bindings(conn, ctx, *upstream_id)?
            } else {
                Vec::new()
            };
            let requested = match profile {
                Some(id) => authorize_profile_invoke(ctx, Some(id), Some(target), &bindings),
                None => authorize_tool_test(ctx, target, &bindings),
            }
            .map_err(|error| account_reason(error, &config.slug))?;
            let account = resolve_account(conn, ctx, profile, target, &revision, requested)?;
            (
                Selected::Upstream {
                    upstream_id: *upstream_id,
                    config,
                },
                account,
            )
        }
        spec => {
            let selector = spec.target_selector().ok_or_else(ApiError::internal)?;
            let candidates = if let Some(requested) = &input.target {
                let node = exact_node(conn, requested)?;
                match node {
                    Some(node) if node.matches(selector, fixed) => vec![node],
                    Some(node) if authorize_node_read(ctx, &node.auth).is_ok() => {
                        return Err(invalid_arguments());
                    }
                    _ => Vec::new(),
                }
            } else {
                let mut nodes = Vec::new();
                visit_selector_nodes(conn, ctx, selector, fixed, |node| {
                    nodes.push(node);
                    Ok(ControlFlow::Continue(()))
                })?;
                nodes
            };
            let candidates = match profile {
                Some(id) => checked_candidates(ctx, id, candidates)?,
                None => candidates,
            };
            let first_target = candidates.first().map(NodeCandidate::target);
            metadata_gate(ctx, profile, first_target)?;
            let first_target = first_target.ok_or_else(ApiError::not_found)?;
            check_new_request(state, input, ctx.now_ms)?;
            if revision.disabled_at_ms.is_some() {
                return Err(ApiError::conflict(code::TOOL_DISABLED));
            }
            let account = resolve_account(conn, ctx, profile, first_target, &revision, None)?;
            let ready: Vec<_> = candidates
                .iter()
                .filter_map(|node| node.ready(&*state.bridge).map(|ready| (node, ready)))
                .collect();
            match ready.as_slice() {
                [] => {
                    return Err(
                        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, code::NODE_OFFLINE)
                            .retryable(),
                    );
                }
                [(node, ready)] => (
                    Selected::Node {
                        node_id: node.auth.node_id,
                        ready: *ready,
                    },
                    account,
                ),
                _ => {
                    let names: Vec<_> = ready.iter().map(|(node, _)| node.name.as_str()).collect();
                    return Err(
                        ApiError::new(StatusCode::BAD_REQUEST, code::AMBIGUOUS_TARGET)
                            .with_extension("available_targets", serde_json::json!(names)),
                    );
                }
            }
        }
    };

    let runtime_ms = revision.definition.spec.runtime_ms();
    if runtime_ms == 0 || runtime_ms > state.config.max_runtime_ms {
        return Err(invalid_arguments());
    }
    let runtime = Duration::from_millis(runtime_ms);
    Ok(Candidate {
        resource,
        binding,
        revision,
        selected,
        account,
        runtime,
    })
}

fn check_new_request(state: &AppState, input: &InvokeInput, now_ms: i64) -> ApiResult<()> {
    if !state.execution.is_accepting() {
        return Err(ApiError::overloaded());
    }
    input.check_freshness(now_ms)
}

fn checked_candidates(
    ctx: &AuthContext,
    profile: ProfileId,
    candidates: Vec<NodeCandidate>,
) -> ApiResult<Vec<NodeCandidate>> {
    if ctx
        .owner
        .as_ref()
        .is_some_and(|owner| owner.disabled_at_ms.is_some())
    {
        for candidate in &candidates {
            match check_profile_invoke_metadata(ctx, Some(profile), Some(candidate.target())) {
                Err(AuthzError::ResourceNotFound) => {}
                Err(error) => return Err(error.into()),
                Ok(()) => return Err(ApiError::internal()),
            }
        }
        check_profile_invoke_metadata(ctx, Some(profile), None)?;
        return Err(ApiError::not_found());
    }
    let mut visible = Vec::new();
    for candidate in candidates {
        if visible_node(ctx, profile, &candidate)? {
            visible.push(candidate);
        }
    }
    Ok(visible)
}

fn metadata_gate(
    ctx: &AuthContext,
    profile: Option<ProfileId>,
    target: Option<ExecutionTarget<'_>>,
) -> Result<(), AuthzError> {
    match profile {
        Some(id) => check_profile_invoke_metadata(ctx, Some(id), target)?,
        None => {
            let target = target.ok_or(AuthzError::ResourceNotFound)?;
            if !matches!(
                target,
                ExecutionTarget::Upstream {
                    account: UpstreamAccountMode::CallerBound,
                    ..
                }
            ) {
                authorize_tool_test(ctx, target, &[])?;
            }
        }
    }
    Ok(())
}

fn resolve_account(
    conn: &Connection,
    ctx: &AuthContext,
    profile: Option<ProfileId>,
    target: ExecutionTarget<'_>,
    revision: &ToolRevision,
    requested: Option<efferian_protocol::AccountId>,
) -> ApiResult<Option<AccountMetadata>> {
    if let Some(static_account) = static_account(&revision.definition) {
        let account = account_by_id(conn, static_account.account_id)?
            .filter(|account| static_account.matches(account));
        if account.is_none() {
            if let Some(profile_id) = profile {
                check_archived_invoke_metadata(
                    ctx,
                    Some(profile_id),
                    ArchivedDependency::Account { target },
                )?;
            }
            return Err(ApiError::new(StatusCode::GONE, code::ACCOUNT_NOT_FOUND));
        }
        return Ok(account);
    }
    if let Some(requested) = requested {
        // authorize_profile_invoke/authorize_tool_test just selected this exact
        // usable account from the same SQLite snapshot.
        return account_by_id(conn, requested)?
            .map(Some)
            .ok_or_else(ApiError::internal);
    }
    Ok(None)
}

fn missing_tool(
    ctx: &AuthContext,
    profile: Option<ProfileId>,
    evidence: Option<ExecutionTarget<'_>>,
) -> ApiResult<ApiError> {
    if let Some(profile_id) = profile {
        check_archived_invoke_metadata(
            ctx,
            Some(profile_id),
            ArchivedDependency::Tool {
                target_evidence: evidence,
            },
        )?;
    }
    Ok(ApiError::new(StatusCode::GONE, code::TOOL_NOT_FOUND))
}

fn account_reason(error: AuthzError, slug: &str) -> ApiError {
    match error {
        AuthzError::AccountNotBound { .. } => {
            ApiError::from(error).with_extension("upstream_slug", Value::String(slug.to_owned()))
        }
        _ => error.into(),
    }
}
