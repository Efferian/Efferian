//! Admission and authorized discovery for exact tool revisions.

mod discovery;
mod selection;
#[cfg(test)]
mod tests;

use std::num::NonZeroU64;
use std::sync::Arc;

use axum::{extract::State, response::Response};
use efferian_authz::{
    AuthContext, ExecutionAccess, authorize_admin, authorize_execution_access,
    authorize_profile_invoke_replay, check_profile_invoke_metadata,
};
use efferian_protocol::{
    DEFAULT_INLINE_WAIT_MS, DEFAULT_REQUEST_ID_MAX_AGE_MS, DEFAULT_REQUEST_ID_MAX_FUTURE_SKEW_MS,
    ExecutionId, ExecutionMode, MAX_RESOLVED_ACTION_BYTES, MAX_WAIT_MS, PreparedArgumentsDigest,
    ProblemDetails, ProfileToolBinding, RequestId, error_codes as code, validate_public_tool_name,
    validate_slug,
};
use http::StatusCode;
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{Map, Value};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::state::{
    ExecutionDetail, ExecutionMetadata, execution_auth_target, invocation_response,
};
use crate::catalog::accounts::load_account_secret;
use crate::catalog::profiles::read_edition;
use crate::http::{
    ApiCaller, ApiError, ApiJson, ApiPath, ApiQuery, ApiResult, AppState, RouteGroups,
};
use crate::storage::{
    InvokeOutcome, InvokeReplayInput, InvokeResource, InvokeWriteError, RecordedInvocation,
    WriteTx, WriteTxError, id, lookup_invocation_replay,
};
use crate::vault::auth::{AuthenticatedApi, refresh_invoke};

use selection::{Candidate, Dispatch, Prepared, resolve_candidate};

pub(super) fn routes() -> RouteGroups {
    RouteGroups {
        application: OpenApiRouter::new()
            .routes(routes!(profile_invoke))
            .routes(routes!(tool_test))
            .merge(discovery::routes()),
        ..RouteGroups::default()
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileInvokeRequest {
    pub(crate) public_name: String,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub(crate) arguments: Map<String, Value>,
    pub(crate) target: Option<String>,
    pub(crate) request_id: Option<RequestId>,
    #[schema(maximum = 25_000)]
    pub(crate) wait_ms: Option<u32>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct ToolTestRequest {
    #[serde(default)]
    #[schema(value_type = Object)]
    arguments: Map<String, Value>,
    target: Option<String>,
    request_id: Option<RequestId>,
    #[schema(maximum = 25_000, default = 15_000)]
    wait_ms: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolTestQuery {
    version: Option<u64>,
}

#[utoipa::path(
    post, path = "/v1/profiles/{slug}/invoke", tag = "Executions",
    params(("slug" = String, Path, description = "Profile slug")),
    request_body = ProfileInvokeRequest,
    security(("api_bearer" = [])),
    responses(
        (status = 200, description = "Terminal execution", body = ExecutionDetail),
        (status = 202, description = "Active execution", body = ExecutionMetadata),
        (status = 400, description = "`invalid_input`, `invalid_arguments`, `request_id_expired` or `ambiguous_target`. For `ambiguous_target`, `extensions.available_targets` is an array of visible ready node names, for example [\"node-a\", \"node-b\"].", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "`forbidden`, `principal_disabled`, `owner_disabled`, `managed_by_disabled` or `account_not_bound`. For `account_not_bound`, `extensions.reason` and `extensions.upstream_slug` identify the binding issue.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "`not_found` for an unavailable profile, tool or target.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`request_id_conflict`, `tool_disabled` or `hub_identity_mismatch`.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "`tool_not_found` or `account_not_found` for a deleted dependency of the edition.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "`node_busy` or `upstream_busy`.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "`node_offline`, `overloaded` or `storage_pressure`.", body = ProblemDetails, content_type = "application/problem+json"),
    )
)]
async fn profile_invoke(
    State(state): State<AppState>,
    caller: ApiCaller,
    ApiPath(slug): ApiPath<String>,
    ApiJson(request): ApiJson<ProfileInvokeRequest>,
) -> ApiResult<Response> {
    invoke_profile_edition(&state, caller, slug, None, request).await
}

/// Shared admission for the current REST edition and an edition selected by
/// an in-process gateway. A retired edition is never eligible for new work.
pub(crate) async fn invoke_profile_edition(
    state: &AppState,
    caller: ApiCaller,
    slug: String,
    edition: Option<NonZeroU64>,
    request: ProfileInvokeRequest,
) -> ApiResult<Response> {
    validate_public_tool_name(&request.public_name).map_err(|_| ApiError::bad_input())?;
    let input = InvokeInput::new(
        Resource::Profile { slug, edition },
        request.public_name,
        request.arguments,
        request.target,
        request.request_id,
        request.wait_ms,
    )?;
    invoke(state, caller, input).await
}

#[utoipa::path(
    post, path = "/v1/tools/{slug}/test", tag = "Tools",
    params(
        ("slug" = String, Path, description = "Tool slug"),
        ("version" = Option<u64>, Query, minimum = 1, description = "Exact revision; defaults to the current revision"),
    ),
    request_body = ToolTestRequest,
    security(("api_bearer" = [])),
    responses(
        (status = 200, description = "Terminal execution", body = ExecutionDetail),
        (status = 202, description = "Active execution", body = ExecutionMetadata),
        (status = 400, description = "`invalid_input`, `invalid_arguments`, `request_id_expired` or `ambiguous_target`. For `ambiguous_target`, `extensions.available_targets` is an array of visible ready node names, for example [\"node-a\", \"node-b\"].", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "`admin_human_required`, `token_narrowed`, `forbidden` or a disabled caller or parent. For `account_not_bound`, `extensions.reason` and `extensions.upstream_slug` identify the binding issue.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "`not_found` for an unavailable tool, revision or target.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`request_id_conflict`, `tool_disabled` or `hub_identity_mismatch`.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "`tool_not_found` or `account_not_found` for a deleted dependency of the revision.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "`node_busy` or `upstream_busy`.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "`node_offline`, `overloaded` or `storage_pressure`.", body = ProblemDetails, content_type = "application/problem+json"),
    )
)]
async fn tool_test(
    State(state): State<AppState>,
    caller: ApiCaller,
    ApiPath(slug): ApiPath<String>,
    ApiQuery(query): ApiQuery<ToolTestQuery>,
    ApiJson(request): ApiJson<ToolTestRequest>,
) -> ApiResult<Response> {
    let version = query
        .version
        .map(|version| {
            i64::try_from(version).map_err(|_| ApiError::bad_input())?;
            NonZeroU64::new(version).ok_or_else(ApiError::bad_input)
        })
        .transpose()?;
    let input = InvokeInput::new(
        Resource::Tool {
            slug: slug.clone(),
            version,
        },
        slug,
        request.arguments,
        request.target,
        request.request_id,
        request.wait_ms,
    )?;
    invoke(&state, caller, input).await
}

enum Resource {
    Profile {
        slug: String,
        edition: Option<NonZeroU64>,
    },
    Tool {
        slug: String,
        version: Option<NonZeroU64>,
    },
}

struct InvokeInput {
    resource: Resource,
    public_name: String,
    arguments: Map<String, Value>,
    digest: PreparedArgumentsDigest,
    target: Option<String>,
    request_id: RequestId,
    supplied_request_id: bool,
    wait_ms: Option<u32>,
}

impl InvokeInput {
    fn new(
        resource: Resource,
        public_name: String,
        arguments: Map<String, Value>,
        target: Option<String>,
        request_id: Option<RequestId>,
        wait_ms: Option<u32>,
    ) -> ApiResult<Self> {
        let slug = match &resource {
            Resource::Profile { slug, .. } | Resource::Tool { slug, .. } => slug,
        };
        validate_slug(slug).map_err(|_| ApiError::bad_input())?;
        if wait_ms.is_some_and(|wait| wait > MAX_WAIT_MS) {
            return Err(ApiError::bad_input());
        }
        if target.as_ref().is_some_and(String::is_empty) {
            return Err(invalid_arguments());
        }
        let digest = PreparedArgumentsDigest::new(&arguments).map_err(|_| invalid_arguments())?;
        Ok(Self {
            resource,
            public_name,
            arguments,
            digest,
            target,
            request_id: request_id.unwrap_or_else(RequestId::new),
            supplied_request_id: request_id.is_some(),
            wait_ms,
        })
    }

    fn check_freshness(&self, now_ms: i64) -> ApiResult<()> {
        if self.supplied_request_id {
            self.request_id
                .validate_freshness(
                    now_ms,
                    DEFAULT_REQUEST_ID_MAX_AGE_MS,
                    DEFAULT_REQUEST_ID_MAX_FUTURE_SKEW_MS,
                )
                .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, code::REQUEST_ID_EXPIRED))?;
        }
        Ok(())
    }

    fn wait_for(&self, binding: Option<&ProfileToolBinding>) -> u64 {
        u64::from(self.wait_ms.unwrap_or_else(|| {
            binding.map_or(DEFAULT_INLINE_WAIT_MS, |binding| {
                match binding.execution_mode {
                    ExecutionMode::Auto => binding.inline_wait_ms.unwrap_or(DEFAULT_INLINE_WAIT_MS),
                    ExecutionMode::Async => 0,
                }
            })
        }))
    }
}

async fn invoke(state: &AppState, caller: ApiCaller, input: InvokeInput) -> ApiResult<Response> {
    let revocations = state.storage.subscribe_revocations()?;
    let input = Arc::new(input);
    // A concurrent catalog change can invalidate prepared credentials or the
    // selected session. Rebuild once in a fresh snapshot before asking the
    // client to retry. Every writer pass checks replay before using the plan.
    for _ in 0..2 {
        let preparation = preflight(state, &caller.0, Arc::clone(&input)).await?;
        let queued_bytes = input
            .digest
            .canonical_bytes()
            .saturating_add(input.target.as_ref().map_or(0, String::len))
            .saturating_add(if preparation.is_some() {
                MAX_RESOLVED_ACTION_BYTES
            } else {
                0
            });
        let writer = state.clone();
        let proof = caller.0.clone();
        let input = Arc::clone(&input);
        let runtime = tokio::runtime::Handle::current();
        let admitted = state
            .storage
            .execute_work(queued_bytes, move |tx| {
                admit(tx, writer, &proof, &input, preparation, runtime)
            })
            .await?;
        if let Admission::Execution(outcome, wait_ms) = admitted {
            return invocation_response(state, caller, outcome, wait_ms, revocations).await;
        }
    }
    Err(ApiError::overloaded())
}

async fn preflight(
    state: &AppState,
    caller: &AuthenticatedApi,
    input: Arc<InvokeInput>,
) -> ApiResult<Option<(Candidate, ApiResult<Prepared>)>> {
    let principal_id = caller.principal_id;
    let proof = caller.credential.clone();
    let reader = state.clone();
    let query = Arc::clone(&input);
    let candidate = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let now = reader.clock.wall_now_ms();
            let ctx = refresh_invoke(conn, &proof, now)?;
            let resource = identify_resource(conn, &ctx, &query.resource)?;
            if lookup_invocation_replay(conn, ctx.caller.principal_id, query.request_id)?.is_some()
            {
                return Ok(None);
            }
            if !reader.execution.is_accepting() {
                return Ok(None);
            }
            let candidate = resolve_candidate(conn, &ctx, &reader, resource, &query)?;
            let envelope = candidate
                .account
                .as_ref()
                .map(|account| load_account_secret(conn, account))
                .transpose();
            Ok(Some((candidate, envelope)))
        })
        .await;
    let Ok(Some((candidate, envelope))) = candidate else {
        // A durable replay may have appeared since this read snapshot.
        // Treat the writer as the authority on both replay and rejection.
        return Ok(None);
    };
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        let id = ExecutionId::new();
        let prepared = envelope.and_then(|envelope| {
            candidate.prepare(
                &state,
                id,
                principal_id,
                &input.arguments,
                envelope.as_deref(),
            )
        });
        (candidate, prepared)
    })
    .await
    .map(Some)
    .map_err(|_| ApiError::internal())
}

enum Admission {
    Reprepare,
    Execution(InvokeOutcome, u64),
}

fn admit(
    tx: &mut WriteTx<'_>,
    state: AppState,
    caller: &AuthenticatedApi,
    input: &InvokeInput,
    preparation: Option<(Candidate, ApiResult<Prepared>)>,
    runtime: tokio::runtime::Handle,
) -> Result<Admission, WriteTxError<ApiError>> {
    let ctx = refresh_invoke(tx.conn(), &caller.credential, tx.now_ms())?;
    let resource = identify_resource(tx.conn(), &ctx, &input.resource)?;
    if let Some(recorded) =
        tx.lookup_invocation_replay(ctx.caller.principal_id, input.request_id)?
    {
        return replay(tx, &ctx, resource, &recorded, input);
    }
    let current = resolve_candidate(tx.conn(), &ctx, &state, resource, input)?;
    let Some((previous, prepared)) = preparation else {
        return Ok(Admission::Reprepare);
    };
    if !current.matches(&previous) {
        return Ok(Admission::Reprepare);
    }
    let prepared = prepared?;
    let wait_ms = input.wait_for(current.binding.as_ref());
    let reservation = current.register_dispatch(tx, &state, &ctx, &prepared)?;
    let write = current.execution_write(tx.now_ms(), &state, &ctx, input, prepared.execution_id);
    let deadline_at_ms = write.deadline_at_ms;
    let outcome = tx.insert_execution(write).map_err(write_error)?;
    match prepared.dispatch {
        Dispatch::Node(request) => {
            current.send_to_node(tx, state.bridge, *request);
        }
        Dispatch::Upstream(request) => {
            let Some(reservation) = reservation else {
                return Err(WriteTxError::InvalidDatabase(
                    "upstream reservation missing",
                ));
            };
            let timeout = current.runtime.min(std::time::Duration::from_millis(
                state.config.upstream_hard_timeout_ms,
            ));
            let principal_id = ctx.caller.principal_id;
            tx.on_commit(move || {
                runtime.spawn(super::results::run_upstream(
                    state,
                    *request,
                    reservation,
                    principal_id,
                    timeout,
                    deadline_at_ms,
                ));
            });
        }
    }
    Ok(Admission::Execution(outcome, wait_ms))
}

fn replay(
    tx: &WriteTx<'_>,
    ctx: &AuthContext,
    resource: InvokeResource,
    recorded: &RecordedInvocation,
    input: &InvokeInput,
) -> Result<Admission, WriteTxError<ApiError>> {
    let target = execution_auth_target(
        tx.conn(),
        recorded.caller_principal_id,
        recorded.profile_id,
        recorded.node_id,
    )?;
    match resource {
        InvokeResource::Profile { profile_id, .. } => {
            authorize_profile_invoke_replay(ctx, Some(profile_id), &target)?;
            if let Resource::Profile {
                edition: Some(requested),
                ..
            } = &input.resource
                && recorded.profile_version != Some(requested.get())
            {
                return Err(ApiError::conflict(code::REQUEST_ID_CONFLICT).into());
            }
        }
        InvokeResource::ToolTest { .. } => {
            authorize_admin(ctx)?;
            authorize_execution_access(ctx, Some(&target), ExecutionAccess::ReadMetadata)?;
        }
    }
    let outcome = tx
        .verify_invocation_replay(
            recorded,
            &InvokeReplayInput {
                resource,
                public_name: &input.public_name,
                requested_target: input.target.as_deref(),
                arguments: &input.digest,
            },
        )
        .map_err(write_error)?;
    let wait_ms = if let (Some(profile), Some(version), None) =
        (recorded.profile_id, recorded.profile_version, input.wait_ms)
    {
        let edition = read_edition(tx.conn(), profile, version)?;
        let binding = edition.as_ref().and_then(|edition| {
            edition
                .bindings
                .iter()
                .find(|binding| binding.public_name == recorded.public_name)
        });
        input.wait_for(binding)
    } else {
        input.wait_for(None)
    };
    Ok(Admission::Execution(outcome, wait_ms))
}

fn identify_resource(
    conn: &Connection,
    ctx: &AuthContext,
    resource: &Resource,
) -> ApiResult<InvokeResource> {
    match resource {
        Resource::Profile { slug, edition } => {
            let Some((profile_id, current)) = published_profile(conn, slug)? else {
                check_profile_invoke_metadata(ctx, None, None)?;
                return Err(ApiError::not_found());
            };
            Ok(InvokeResource::Profile {
                profile_id,
                version: edition.unwrap_or(current),
            })
        }
        Resource::Tool { slug, version } => {
            authorize_admin(ctx)?;
            let (tool_id, current): (_, u64) = conn
                .prepare_cached("SELECT tool_id, current_version FROM tools WHERE slug = ?1")?
                .query_row([slug], |row| Ok((id(row, 0)?, row.get(1)?)))
                .optional()?
                .ok_or_else(ApiError::not_found)?;
            let current = NonZeroU64::new(current).ok_or_else(ApiError::internal)?;
            Ok(InvokeResource::ToolTest {
                tool_id,
                resolved_version: version.unwrap_or(current),
                requested_version: *version,
            })
        }
    }
}

fn published_profile(
    conn: &Connection,
    slug: &str,
) -> ApiResult<Option<(efferian_protocol::ProfileId, NonZeroU64)>> {
    let published: Option<(_, u64)> = conn
        .prepare_cached(
            "SELECT profile_id, published_version FROM profiles
         WHERE slug = ?1 AND disabled_at_ms IS NULL AND published_version > 0",
        )?
        .query_row([slug], |row| Ok((id(row, 0)?, row.get(1)?)))
        .optional()?;
    published
        .map(|(profile_id, version)| {
            let version = NonZeroU64::new(version).ok_or_else(ApiError::internal)?;
            Ok((profile_id, version))
        })
        .transpose()
}

pub(super) fn invalid_arguments() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, code::INVALID_ARGUMENTS)
}

fn write_error(error: WriteTxError<InvokeWriteError>) -> WriteTxError<ApiError> {
    match error {
        WriteTxError::Domain(InvokeWriteError::RequestIdConflict) => {
            ApiError::conflict(code::REQUEST_ID_CONFLICT).into()
        }
        WriteTxError::Domain(InvokeWriteError::BindingUnavailable) => ApiError::not_found().into(),
        WriteTxError::Domain(_) => ApiError::internal().into(),
        WriteTxError::StoragePressure => WriteTxError::StoragePressure,
        WriteTxError::LastAdmin => WriteTxError::LastAdmin,
        WriteTxError::InvalidDatabase(message) => WriteTxError::InvalidDatabase(message),
        WriteTxError::Sqlite(error) => WriteTxError::Sqlite(error),
    }
}
