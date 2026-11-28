use std::collections::{BTreeMap, BTreeSet};

use axum::{Json, extract::State};
use efferian_authz::{
    AuthContext, ExecutionTarget, PrincipalAccess, authorize_admin, authorize_discovery_target,
    authorize_principal_manage, authorize_profile_discover,
};
use efferian_protocol::{
    Capability, NodeId, PrincipalId, PrincipalKind, ProfileId, TokenId, UpstreamAccountMode,
    UpstreamId,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::UtoipaMethodRouter, routes};

use crate::http::{ApiCaller, ApiError, ApiResult, AppState};
use crate::storage::id;
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
pub(crate) struct CallerBoundUpstream {
    pub(crate) upstream_id: UpstreamId,
    slug: String,
    #[serde(skip)]
    pub(crate) caller_bound_profiles: Vec<ProfileId>,
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

pub(crate) fn caller_bound_upstreams(
    conn: &Connection,
    ctx: &AuthContext,
) -> ApiResult<Vec<CallerBoundUpstream>> {
    if ctx.token.allowed_nodes.is_some() {
        return Ok(Vec::new());
    }
    let profiles = visible_published_profiles(conn, ctx)?;
    if profiles.is_empty() {
        return Ok(Vec::new());
    }
    let mut pinned = conn.prepare_cached(
        "SELECT DISTINCT json_extract(tr.definition_json, '$.spec.upstream_id')
         FROM profiles p
         JOIN profile_editions pe
           ON pe.profile_id = p.profile_id AND pe.version = p.published_version
         JOIN json_each(pe.bindings_json) b
         JOIN tools t ON t.tool_id = json_extract(b.value, '$.tool_id')
         JOIN tool_revisions tr
           ON tr.tool_id = t.tool_id AND tr.version = json_extract(b.value, '$.tool_version')
         WHERE p.profile_id = ?1 AND p.published_version > 0
           AND p.disabled_at_ms IS NULL AND pe.disabled_at_ms IS NULL
           AND t.disabled_at_ms IS NULL
           AND json_extract(tr.definition_json, '$.spec.kind') = 'upstream_ref'
           AND json_extract(tr.definition_json, '$.spec.account_mode') = 'caller_bound'",
    )?;
    let mut active_upstream = conn.prepare_cached(
        "SELECT slug FROM upstreams WHERE upstream_id = ?1 AND disabled_at_ms IS NULL",
    )?;
    let mut visible = BTreeMap::<UpstreamId, Vec<ProfileId>>::new();
    for profile_id in profiles {
        let upstreams: Vec<UpstreamId> = pinned
            .query_map([profile_id.to_string()], |row| id(row, 0))?
            .collect::<rusqlite::Result<_>>()?;
        for upstream_id in upstreams {
            let target = ExecutionTarget::Upstream {
                upstream_id,
                account: UpstreamAccountMode::CallerBound,
            };
            if authorize_discovery_target(ctx, profile_id, target).is_ok() {
                visible.entry(upstream_id).or_default().push(profile_id);
            }
        }
    }
    let mut result = Vec::new();
    for (upstream_id, caller_bound_profiles) in visible {
        if let Some(slug) = active_upstream
            .query_row([upstream_id.to_string()], |row| row.get(0))
            .optional()?
        {
            result.push(CallerBoundUpstream {
                upstream_id,
                slug,
                caller_bound_profiles,
            });
        }
    }
    result.sort_unstable_by(|left, right| left.slug.cmp(&right.slug));
    Ok(result)
}

/// Point check for a single upstream's caller-bound profile visibility.
/// Avoids scanning unrelated upstreams and short-circuits when `first_only` is set.
pub(crate) fn caller_bound_profiles_for_upstream(
    conn: &Connection,
    ctx: &AuthContext,
    upstream_id: UpstreamId,
    first_only: bool,
) -> ApiResult<Vec<ProfileId>> {
    if ctx.token.allowed_nodes.is_some() {
        return Ok(Vec::new());
    }
    let active: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM upstreams WHERE upstream_id = ?1 AND disabled_at_ms IS NULL)",
        )?
        .query_row([upstream_id.to_string()], |row| row.get(0))?;
    if !active {
        return Ok(Vec::new());
    }
    let profiles = visible_published_profiles(conn, ctx)?;
    if profiles.is_empty() {
        return Ok(Vec::new());
    }
    let target = ExecutionTarget::Upstream {
        upstream_id,
        account: UpstreamAccountMode::CallerBound,
    };
    let upstream_text = upstream_id.to_string();
    let mut has_caller_bound = conn.prepare_cached(
        "SELECT EXISTS(
             SELECT 1
             FROM profiles p
             JOIN profile_editions pe
               ON pe.profile_id = p.profile_id AND pe.version = p.published_version
             JOIN json_each(pe.bindings_json) b
             JOIN tools t ON t.tool_id = json_extract(b.value, '$.tool_id')
             JOIN tool_revisions tr
               ON tr.tool_id = t.tool_id AND tr.version = json_extract(b.value, '$.tool_version')
             WHERE p.profile_id = ?1 AND p.published_version > 0
               AND p.disabled_at_ms IS NULL AND pe.disabled_at_ms IS NULL
               AND t.disabled_at_ms IS NULL
               AND json_extract(tr.definition_json, '$.spec.kind') = 'upstream_ref'
               AND json_extract(tr.definition_json, '$.spec.account_mode') = 'caller_bound'
               AND json_extract(tr.definition_json, '$.spec.upstream_id') = ?2
         )",
    )?;
    let mut matching = Vec::new();
    for profile_id in profiles {
        if authorize_discovery_target(ctx, profile_id, target).is_err() {
            continue;
        }
        let found: bool = has_caller_bound
            .query_row(params![profile_id.to_string(), &upstream_text], |row| {
                row.get(0)
            })?;
        if found {
            matching.push(profile_id);
            if first_only {
                break;
            }
        }
    }
    Ok(matching)
}

fn visible_published_profiles(conn: &Connection, ctx: &AuthContext) -> ApiResult<Vec<ProfileId>> {
    let has_global_grant = ctx
        .caller_grants
        .iter()
        .any(|grant| matches!(grant.scope, efferian_protocol::GrantScope::Global));
    let candidate_ids: Option<Vec<ProfileId>> =
        match (&ctx.token.allowed_profiles, has_global_grant) {
            (Some(allowed), _) => Some(allowed.iter().copied().collect()),
            (None, false) => {
                let ids: BTreeSet<ProfileId> = ctx
                    .caller_grants
                    .iter()
                    .filter_map(|grant| match grant.scope {
                        efferian_protocol::GrantScope::Profile(id) => Some(id),
                        efferian_protocol::GrantScope::Global => None,
                    })
                    .collect();
                Some(ids.into_iter().collect())
            }
            (None, true) => None,
        };
    let raw: Vec<ProfileId> = if let Some(ids) = candidate_ids {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids_json = serde_json::to_string(&ids).map_err(|_| ApiError::internal())?;
        let mut stmt = conn.prepare_cached(
            "SELECT p.profile_id FROM profiles p
             WHERE p.published_version > 0 AND p.disabled_at_ms IS NULL
               AND p.profile_id IN (SELECT value FROM json_each(?1))",
        )?;
        stmt.query_map([ids_json], |row| id(row, 0))?
            .collect::<rusqlite::Result<_>>()?
    } else {
        let mut stmt = conn.prepare_cached(
            "SELECT profile_id FROM profiles WHERE published_version > 0 AND disabled_at_ms IS NULL",
        )?;
        stmt.query_map([], |row| id(row, 0))?
            .collect::<rusqlite::Result<_>>()?
    };
    Ok(raw
        .into_iter()
        .filter(|&profile_id| authorize_profile_discover(ctx, Some(profile_id)).is_ok())
        .collect())
}
