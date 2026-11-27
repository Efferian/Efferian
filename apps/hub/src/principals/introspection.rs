use std::collections::{BTreeMap, BTreeSet};

use axum::{Json, extract::State};
use efferian_authz::{
    AuthContext, ExecutionTarget, authorize_admin, authorize_discovery_target,
    authorize_profile_discover,
};
use efferian_protocol::{
    Capability, NodeId, PrincipalId, ProfileId, ProfileToolBinding, TokenId, ToolDefinition,
    ToolSpec, UpstreamAccountMode, UpstreamId,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::UtoipaMethodRouter, routes};

use crate::http::{ApiCaller, ApiError, ApiResult, AppState};
use crate::storage::{StorageStatus, id, json};
use crate::vault::auth::refresh_api;

use super::data::{Principal, principal_by_id};

pub(super) fn me_route() -> UtoipaMethodRouter<AppState> {
    routes!(me)
}

pub(super) fn status_route() -> UtoipaMethodRouter<AppState> {
    routes!(admin_status)
}

#[derive(Serialize, ToSchema)]
struct OwnIdentity {
    principal: Principal,
    token_scope: CurrentTokenScope,
    owned_agents: Vec<OwnedAgent>,
    caller_bound_upstreams: Vec<CallerBoundUpstream>,
}

#[derive(Serialize, ToSchema)]
struct CurrentTokenScope {
    token_id: TokenId,
    label: String,
    max_capability: Option<Capability>,
    allowed_profiles: Option<BTreeSet<ProfileId>>,
    allowed_nodes: Option<BTreeSet<NodeId>>,
    withhold_sensitive: bool,
    expires_at_ms: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct OwnedAgent {
    principal_id: PrincipalId,
    name: String,
    disabled_at_ms: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct CallerBoundUpstream {
    upstream_id: UpstreamId,
    slug: String,
}

#[utoipa::path(
    get,
    path = "/v1/me",
    responses(
        (status = 200, body = OwnIdentity),
        (status = 401, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn me(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
) -> ApiResult<Json<OwnIdentity>> {
    let clock = state.clock;
    let identity = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            identity(conn, ctx)
        })
        .await?;
    Ok(Json(identity))
}

fn identity(conn: &Connection, ctx: AuthContext) -> ApiResult<OwnIdentity> {
    let principal =
        principal_by_id(conn, ctx.caller.principal_id)?.ok_or_else(ApiError::internal)?;
    let label = conn
        .prepare_cached("SELECT label FROM auth_tokens WHERE token_id = ?1")?
        .query_row([ctx.token.token_id.to_string()], |row| row.get(0))?;
    let owned_agents = owned_agents(conn, ctx.caller.principal_id)?;
    let caller_bound_upstreams = caller_bound_upstreams(conn, &ctx)?;
    Ok(OwnIdentity {
        principal,
        token_scope: CurrentTokenScope {
            token_id: ctx.token.token_id,
            label,
            max_capability: ctx.token.max_capability,
            allowed_profiles: ctx.token.allowed_profiles,
            allowed_nodes: ctx.token.allowed_nodes,
            withhold_sensitive: ctx.token.withhold_sensitive,
            expires_at_ms: ctx.token.expires_at_ms,
        },
        owned_agents,
        caller_bound_upstreams,
    })
}

fn owned_agents(conn: &Connection, caller: PrincipalId) -> rusqlite::Result<Vec<OwnedAgent>> {
    let mut stmt = conn.prepare_cached(
        "SELECT p.principal_id, p.name, p.disabled_at_ms FROM principals p JOIN hub_meta h ON h.id = 1
         WHERE p.kind = 'agent' AND p.owner_principal_id = ?1
           AND p.principal_id IS NOT h.gc_purging_principal_id
         ORDER BY p.principal_id COLLATE BINARY ASC",
    )?;
    stmt.query_map([caller.to_string()], |row| {
        Ok(OwnedAgent {
            principal_id: id(row, 0)?,
            name: row.get(1)?,
            disabled_at_ms: row.get(2)?,
        })
    })?
    .collect()
}

fn caller_bound_upstreams(
    conn: &Connection,
    ctx: &AuthContext,
) -> ApiResult<Vec<CallerBoundUpstream>> {
    let mut published = conn.prepare_cached(
        "SELECT p.profile_id, pe.bindings_json
         FROM profiles p JOIN profile_editions pe
           ON pe.profile_id = p.profile_id AND pe.version = p.published_version
         WHERE p.published_version > 0 AND p.disabled_at_ms IS NULL AND pe.disabled_at_ms IS NULL",
    )?;
    let mut pinned_definition = conn.prepare_cached(
        "SELECT tr.definition_json FROM tools t JOIN tool_revisions tr ON tr.tool_id = t.tool_id
         WHERE t.tool_id = ?1 AND tr.version = ?2 AND t.disabled_at_ms IS NULL",
    )?;
    let mut active_upstream = conn.prepare_cached(
        "SELECT slug FROM upstreams WHERE upstream_id = ?1 AND disabled_at_ms IS NULL",
    )?;
    let mut by_slug = BTreeMap::<String, UpstreamId>::new();
    let mut rows = published.query([])?;
    while let Some(row) = rows.next()? {
        let profile_id = id(row, 0)?;
        if authorize_profile_discover(ctx, Some(profile_id)).is_err() {
            continue;
        }
        let bindings: Vec<ProfileToolBinding> = json(row, 1)?;
        for binding in bindings {
            let definition: Option<ToolDefinition> = pinned_definition
                .query_row(
                    params![binding.tool_id.to_string(), binding.tool_version],
                    |row| json(row, 0),
                )
                .optional()?;
            let Some(ToolDefinition {
                spec:
                    ToolSpec::UpstreamRef {
                        upstream_id,
                        account_mode: UpstreamAccountMode::CallerBound,
                        ..
                    },
                ..
            }) = definition
            else {
                continue;
            };
            let target = ExecutionTarget::Upstream {
                upstream_id,
                account: UpstreamAccountMode::CallerBound,
            };
            if authorize_discovery_target(ctx, profile_id, target).is_err() {
                continue;
            }
            if let Some(slug) = active_upstream
                .query_row([upstream_id.to_string()], |row| row.get(0))
                .optional()?
            {
                by_slug.insert(slug, upstream_id);
            }
        }
    }
    Ok(by_slug
        .into_iter()
        .map(|(slug, upstream_id)| CallerBoundUpstream { upstream_id, slug })
        .collect())
}

#[derive(Serialize, ToSchema)]
struct AdminStatus {
    #[serde(flatten)]
    storage: StorageStatus,
    gc_error_count: u64,
    online_nodes_count: usize,
    upstream_pool_connections: usize,
    active_upstream_executions: usize,
}

#[utoipa::path(
    get,
    path = "/v1/admin/status",
    responses(
        (status = 200, body = AdminStatus),
        (status = 401, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn admin_status(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
) -> ApiResult<Json<AdminStatus>> {
    let clock = state.clock;
    let storage = state
        .storage
        .status_snapshot_with(move |conn| -> ApiResult<()> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            authorize_admin(&ctx)?;
            Ok(())
        })
        .await?;
    Ok(Json(AdminStatus {
        storage,
        gc_error_count: state.storage.gc_error_count(),
        online_nodes_count: state.bridge.online_nodes_count(),
        upstream_pool_connections: 0,
        active_upstream_executions: 0,
    }))
}
