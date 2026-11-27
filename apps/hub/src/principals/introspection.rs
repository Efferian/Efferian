use std::collections::{BTreeSet, HashMap, hash_map::Entry};

use axum::{Json, extract::State};
use efferian_authz::{
    AuthContext, ExecutionTarget, PrincipalAccess, authorize_admin, authorize_discovery_target,
    authorize_principal_manage, authorize_profile_discover,
};
use efferian_protocol::{
    Capability, NodeId, PrincipalId, PrincipalKind, ProfileId, ProfileToolBinding, TokenId,
    ToolDefinition, ToolSpec, UpstreamAccountMode, UpstreamId,
};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::UtoipaMethodRouter, routes};

use crate::http::{ApiCaller, ApiError, ApiResult, AppState};
use crate::storage::{id, json};
use crate::vault::auth::refresh_api_with_label;

use super::data::{Principal, owned_agent_principals, principal_by_id};

pub(super) fn me_route() -> UtoipaMethodRouter<AppState> {
    routes!(me)
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
    tag = "Principals",
    responses((status = 200, description = "Current caller identity and effective discovery scope", body = OwnIdentity)),
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
            let (ctx, label) =
                refresh_api_with_label(conn, &caller.credential, clock.wall_now_ms())?;
            identity(conn, ctx, label)
        })
        .await?;
    Ok(Json(identity))
}

fn identity(conn: &Connection, ctx: AuthContext, label: String) -> ApiResult<OwnIdentity> {
    let principal =
        principal_by_id(conn, ctx.caller.principal_id)?.ok_or_else(ApiError::internal)?;
    let owned_agents = owned_agents(conn, &ctx)?;
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

fn owned_agents(conn: &Connection, ctx: &AuthContext) -> ApiResult<Vec<OwnedAgent>> {
    if authorize_admin(ctx).is_err() && ctx.caller.kind != PrincipalKind::Member {
        return Ok(Vec::new());
    }
    let agents = owned_agent_principals(conn, ctx.caller.principal_id)?;
    let mut visible = Vec::with_capacity(agents.len());
    for agent in agents {
        if authorize_principal_manage(ctx, &agent.view(), PrincipalAccess::Read).is_ok() {
            visible.push(OwnedAgent {
                principal_id: agent.principal_id,
                name: agent.name,
                disabled_at_ms: agent.disabled_at_ms,
            });
        }
    }
    Ok(visible)
}

fn caller_bound_upstreams(
    conn: &Connection,
    ctx: &AuthContext,
) -> ApiResult<Vec<CallerBoundUpstream>> {
    if ctx.token.allowed_nodes.is_some() {
        return Ok(Vec::new());
    }
    if let Some(ids) = &ctx.token.allowed_profiles {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids_json = serde_json::to_string(ids).map_err(|_| ApiError::internal())?;
        let mut profiles = conn.prepare_cached(
            "SELECT p.profile_id FROM profiles p
             WHERE p.published_version > 0 AND p.disabled_at_ms IS NULL
               AND p.profile_id IN (SELECT value FROM json_each(?1))",
        )?;
        return upstreams_for_profiles(
            conn,
            ctx,
            profiles.query_map([ids_json], |row| id(row, 0))?,
        );
    }
    let mut profiles = conn.prepare_cached(
        "SELECT profile_id FROM profiles WHERE published_version > 0 AND disabled_at_ms IS NULL",
    )?;
    upstreams_for_profiles(conn, ctx, profiles.query_map([], |row| id(row, 0))?)
}

fn upstreams_for_profiles(
    conn: &Connection,
    ctx: &AuthContext,
    profiles: impl Iterator<Item = rusqlite::Result<ProfileId>>,
) -> ApiResult<Vec<CallerBoundUpstream>> {
    let mut published = conn.prepare_cached(
        "SELECT pe.bindings_json
         FROM profiles p JOIN profile_editions pe
           ON pe.profile_id = p.profile_id AND pe.version = p.published_version
         WHERE p.profile_id = ?1 AND p.published_version > 0
           AND p.disabled_at_ms IS NULL AND pe.disabled_at_ms IS NULL",
    )?;
    let mut pinned_definition = conn.prepare_cached(
        "SELECT tr.definition_json FROM tools t JOIN tool_revisions tr ON tr.tool_id = t.tool_id
         WHERE t.tool_id = ?1 AND tr.version = ?2
           AND t.kind = 'upstream_ref' AND t.disabled_at_ms IS NULL",
    )?;
    let mut active_upstream = conn.prepare_cached(
        "SELECT slug FROM upstreams WHERE upstream_id = ?1 AND disabled_at_ms IS NULL",
    )?;
    let mut revisions = HashMap::new();
    let mut visible = BTreeSet::new();
    for profile_id in profiles {
        let profile_id = profile_id?;
        if authorize_profile_discover(ctx, Some(profile_id)).is_err() {
            continue;
        }
        let Some(bindings) = published
            .query_row([profile_id.to_string()], |row| {
                json::<Vec<ProfileToolBinding>>(row, 0)
            })
            .optional()?
        else {
            continue;
        };
        let mut upstreams = BTreeSet::new();
        for binding in bindings {
            let key = (binding.tool_id, binding.tool_version);
            let upstream_id = match revisions.entry(key) {
                Entry::Occupied(entry) => *entry.get(),
                Entry::Vacant(entry) => *entry.insert(
                    pinned_definition
                        .query_row(
                            params![binding.tool_id.to_string(), binding.tool_version],
                            caller_bound_upstream_id,
                        )
                        .optional()?
                        .flatten(),
                ),
            };
            if let Some(upstream_id) = upstream_id {
                upstreams.insert(upstream_id);
            }
        }
        for upstream_id in upstreams {
            let target = ExecutionTarget::Upstream {
                upstream_id,
                account: UpstreamAccountMode::CallerBound,
            };
            if authorize_discovery_target(ctx, profile_id, target).is_ok() {
                visible.insert(upstream_id);
            }
        }
    }
    let mut result = Vec::new();
    for upstream_id in visible {
        if let Some(slug) = active_upstream
            .query_row([upstream_id.to_string()], |row| row.get(0))
            .optional()?
        {
            result.push(CallerBoundUpstream { upstream_id, slug });
        }
    }
    result.sort_unstable_by(|left, right| left.slug.cmp(&right.slug));
    Ok(result)
}

fn caller_bound_upstream_id(row: &Row<'_>) -> rusqlite::Result<Option<UpstreamId>> {
    let definition: ToolDefinition = json(row, 0)?;
    Ok(match definition.spec {
        ToolSpec::UpstreamRef {
            upstream_id,
            account_mode: UpstreamAccountMode::CallerBound,
            ..
        } => Some(upstream_id),
        _ => None,
    })
}
