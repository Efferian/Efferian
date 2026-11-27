use std::collections::BTreeSet;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use efferian_authz::{
    AuthContext, AuthzError, GrantMutation, GrantView, OrchestratorLimits, SubjectMetadata,
    TokenMintRequest, authorize_admin, authorize_grant_mutation, authorize_subject_metadata_read,
    authorize_token_mint, authorize_token_revoke,
};
use efferian_protocol::{
    ActorId, Capability, GrantId, GrantScope, NodeId, PrincipalId, PrincipalKind, PrincipalPrefix,
    ProblemDetails, ProfileId, SecretString, TokenId, error_codes,
};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::http::{
    ApiCaller, ApiError, ApiJson, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody, OperatorScope,
    Page, RouteGroups, checked_page_limit, point_missing, require_unrestricted_operator,
};
use crate::operations::{active_token_count, normalize_token_label};
use crate::storage::{
    PriorityKind, WriteTxError, id, optional_json, optional_scalar, read_grant_scope,
    read_principal, scalar, scalar_text,
};
use crate::vault::{IssuedCredential, auth::refresh_api};

const MAX_TOKEN_SCOPE_PROFILES: usize = 256;
const MAX_TOKEN_SCOPE_NODES: usize = 256;

pub(crate) fn routes() -> RouteGroups {
    RouteGroups {
        application: OpenApiRouter::new()
            .routes(routes!(list_tokens, mint_token))
            .routes(routes!(list_grants, put_grant)),
        control: OpenApiRouter::new()
            .routes(routes!(revoke_token))
            .routes(routes!(delete_grant)),
        ..RouteGroups::default()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectPageQuery<Id> {
    limit: Option<u16>,
    cursor: Option<Id>,
    principal_id: Option<PrincipalId>,
}

#[derive(Serialize, ToSchema)]
struct TokenMetadata {
    token_id: TokenId,
    principal_id: PrincipalId,
    label: String,
    max_capability: Option<Capability>,
    allowed_profiles: Option<BTreeSet<ProfileId>>,
    allowed_nodes: Option<BTreeSet<NodeId>>,
    withhold_sensitive: bool,
    created_at_ms: i64,
    expires_at_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct MintToken {
    principal_id: PrincipalId,
    label: String,
    max_capability: Option<Capability>,
    #[schema(max_items = 256)]
    allowed_profiles: Option<Vec<ProfileId>>,
    #[schema(max_items = 256)]
    allowed_nodes: Option<Vec<NodeId>>,
    #[serde(default)]
    withhold_sensitive: bool,
    expires_at_ms: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct MintedToken {
    token_id: TokenId,
    #[schema(value_type = String, format = Password)]
    token: SecretString,
}

#[derive(Serialize, ToSchema)]
struct GrantMetadata {
    grant_id: GrantId,
    principal_id: PrincipalId,
    scope: GrantScope,
    capability: Capability,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct PutGrant {
    principal_id: PrincipalId,
    scope: GrantScope,
    capability: Capability,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum GrantOutcome {
    Created,
    Unchanged,
}

#[derive(Serialize, ToSchema)]
struct PutGrantResult {
    outcome: GrantOutcome,
    grant: GrantMetadata,
}

#[utoipa::path(
    get, path = "/v1/tokens", tag = "Tokens",
    security(("api_bearer" = [])),
    params(
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Page size from 1 to 200 (default 50)"),
        ("cursor" = Option<TokenId>, Query, description = "Exclusive token ID cursor"),
        ("principal_id" = Option<PrincipalId>, Query, description = "Filter by token subject"),
    ),
    responses(
        (status = 200, description = "Visible tokens page", body = Page<TokenMetadata>),
        (status = 404, description = "Filtered principal does not exist", body = ProblemDetails, content_type = "application/problem+json"),
    ),
)]
async fn list_tokens(
    State(app): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(query): ApiQuery<SubjectPageQuery<TokenId>>,
) -> ApiResult<Json<Page<TokenMetadata>>> {
    let limit = checked_page_limit(query.limit)?;
    let clock = app.clock;
    let results = app
        .storage
        .read_snapshot::<_, ApiError>(move |conn| {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            read_subject_page(
                conn,
                &ctx,
                query,
                limit,
                SubjectMetadata::Tokens,
                &TOKEN_QUERIES,
                token_row,
            )
        })
        .await?;
    Ok(Json(Page::from_rows(results, limit, |row| row.token_id)))
}

#[utoipa::path(
    post, path = "/v1/tokens", tag = "Tokens",
    security(("api_bearer" = [])),
    request_body = MintToken,
    responses(
        (status = 201, description = "API token issued", body = MintedToken),
        (status = 404, description = "Target principal does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Active token quota exceeded", body = ProblemDetails, content_type = "application/problem+json"),
    ),
)]
async fn mint_token(
    State(app): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiJson(body): ApiJson<MintToken>,
) -> ApiResult<(StatusCode, Json<MintedToken>)> {
    let MintToken {
        principal_id,
        label,
        max_capability,
        allowed_profiles,
        allowed_nodes,
        withhold_sensitive,
        expires_at_ms,
    } = body;
    let label = normalize_token_label(&label)
        .ok_or_else(ApiError::bad_input)?
        .to_owned();
    let allowed_profiles = bounded_set(allowed_profiles, MAX_TOKEN_SCOPE_PROFILES)?;
    let allowed_nodes = bounded_set(allowed_nodes, MAX_TOKEN_SCOPE_NODES)?;

    // The principal prefix identifies the token family without a preflight lookup.
    let token_id = match principal_id.prefix() {
        PrincipalPrefix::Sp => TokenId::new_service(),
        PrincipalPrefix::Usr | PrincipalPrefix::Agt => TokenId::new_user_or_agent(),
    };
    let IssuedCredential {
        key_id,
        verifier,
        secret,
    } = app.vault.issue_token(token_id)?;
    let profiles_json = encode_optional_scope(allowed_profiles.as_ref())?;
    let nodes_json = encode_optional_scope(allowed_nodes.as_ref())?;
    let max_capability_text = max_capability.map(scalar_text).transpose()?;
    let payload_bytes = label.len()
        + profiles_json.as_ref().map_or(0, String::len)
        + nodes_json.as_ref().map_or(0, String::len)
        + verifier.len();
    let max_active_tokens = app.config.max_active_tokens_per_principal;
    let policy = OrchestratorLimits {
        agent_token_ttl_ms: app.config.orchestrator_agent_token_ttl_ms,
        enrollment_ttl_ms: app.config.orchestrator_enrollment_ttl_ms,
    };
    let request = TokenMintRequest {
        max_capability,
        allowed_profiles,
        allowed_nodes,
        withhold_sensitive,
        expires_at_ms,
    };

    app.storage
        .execute_work::<_, ApiError, _>(payload_bytes, move |tx| {
            let conn = tx.conn();
            let now = tx.now_ms();
            let ctx = refresh_api(conn, &caller.credential, now)?;
            require_unrestricted_operator(&ctx, OperatorScope::TokenMint)?;
            let target =
                read_principal(conn, principal_id)?.ok_or_else(|| point_missing(&ctx, true))?;
            let managed_nodes = if ctx.caller.is_orchestrator
                && request
                    .allowed_nodes
                    .as_ref()
                    .is_some_and(|nodes| !nodes.is_empty())
            {
                managed_active_nodes(conn, ctx.caller.principal_id)?
            } else {
                BTreeSet::new()
            };
            authorize_token_mint(&ctx, &target, &request, &policy, &managed_nodes)?;
            if target.disabled_at_ms.is_some() {
                return Err(AuthzError::PrincipalDisabled.into());
            }
            if active_token_count(conn, principal_id, now)? >= max_active_tokens {
                return Err(ApiError::conflict(error_codes::QUOTA_EXCEEDED).into());
            }
            if !token_id.matches_kind(target.kind) {
                return Err(WriteTxError::InvalidDatabase(
                    "token family does not match principal kind",
                ));
            }
            conn.prepare_cached(
                "INSERT INTO auth_tokens (token_id, principal_id, created_by, label, key_id,
                verifier_hmac, max_capability, allowed_profiles_json, allowed_nodes_json,
                withhold_sensitive, expires_at_ms, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?
            .execute(params![
                token_id.to_string(),
                principal_id.to_string(),
                ctx.caller.principal_id.to_string(),
                label,
                key_id,
                verifier.as_str(),
                max_capability_text,
                profiles_json,
                nodes_json,
                request.withhold_sensitive,
                request.expires_at_ms,
                now,
            ])?;
            Ok(())
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(MintedToken {
            token_id,
            token: secret,
        }),
    ))
}

#[utoipa::path(
    post, path = "/v1/tokens/{id}/revoke", tag = "Tokens",
    security(("api_bearer" = [])),
    params(("id" = TokenId, Path, description = "Token ID")),
    responses(
        (status = 204, description = "Token revoked"),
        (status = 404, description = "Token does not exist", body = ProblemDetails, content_type = "application/problem+json"),
    ),
)]
async fn revoke_token(
    State(app): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(token_id): ApiPath<TokenId>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    app.storage
        .execute_priority::<_, ApiError, _>(PriorityKind::RevokeToken, move |tx| {
            let conn = tx.conn();
            let ctx = refresh_api(conn, &caller.credential, tx.now_ms())?;
            require_unrestricted_operator(&ctx, OperatorScope::SubjectOperator)?;
            let principal_id = conn
                .prepare_cached(
                    "SELECT t.principal_id FROM auth_tokens t
                     JOIN hub_meta h ON h.id = 1
                     WHERE t.token_id = ?1 AND t.principal_id IS NOT h.gc_purging_principal_id",
                )?
                .query_row([token_id.to_string()], |row| id(row, 0))
                .optional()?
                .ok_or_else(|| point_missing(&ctx, true))?;
            let target =
                read_principal(conn, principal_id)?.ok_or_else(|| point_missing(&ctx, true))?;
            authorize_token_revoke(&ctx, &target)?;
            tx.revoke_token(ActorId::Principal(ctx.caller.principal_id), token_id)?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get, path = "/v1/grants", tag = "Grants",
    security(("api_bearer" = [])),
    params(
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Page size from 1 to 200 (default 50)"),
        ("cursor" = Option<GrantId>, Query, description = "Exclusive grant ID cursor"),
        ("principal_id" = Option<PrincipalId>, Query, description = "Filter by grant subject"),
    ),
    responses(
        (status = 200, description = "Visible grants page", body = Page<GrantMetadata>),
        (status = 404, description = "Filtered principal does not exist", body = ProblemDetails, content_type = "application/problem+json"),
    ),
)]
async fn list_grants(
    State(app): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(query): ApiQuery<SubjectPageQuery<GrantId>>,
) -> ApiResult<Json<Page<GrantMetadata>>> {
    let limit = checked_page_limit(query.limit)?;
    let clock = app.clock;
    let results = app
        .storage
        .read_snapshot::<_, ApiError>(move |conn| {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            read_subject_page(
                conn,
                &ctx,
                query,
                limit,
                SubjectMetadata::Grants,
                &GRANT_QUERIES,
                grant_row,
            )
        })
        .await?;
    Ok(Json(Page::from_rows(results, limit, |row| row.grant_id)))
}

#[utoipa::path(
    put, path = "/v1/grants", tag = "Grants",
    security(("api_bearer" = [])),
    request_body = PutGrant,
    responses(
        (status = 200, description = "Grant already existed", body = PutGrantResult),
        (status = 201, description = "Grant created", body = PutGrantResult),
        (status = 404, description = "Target principal or profile does not exist", body = ProblemDetails, content_type = "application/problem+json"),
    ),
)]
async fn put_grant(
    State(app): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiJson(request): ApiJson<PutGrant>,
) -> ApiResult<(StatusCode, Json<PutGrantResult>)> {
    if request.capability == Capability::Admin && request.scope != GrantScope::Global {
        return Err(ApiError::bad_input());
    }
    let new_id = GrantId::new();
    let (status, result) = app
        .storage
        .execute_work::<_, ApiError, _>(std::mem::size_of::<PutGrant>(), move |tx| {
            let conn = tx.conn();
            let ctx = refresh_api(conn, &caller.credential, tx.now_ms())?;
            if request.capability == Capability::Admin {
                authorize_admin(&ctx)?;
            } else if request.scope == GrantScope::Global {
                match authorize_admin(&ctx) {
                    Ok(()) => {}
                    Err(error @ AuthzError::UnrestrictedTokenRequired) => {
                        return Err(ApiError::from(error).into());
                    }
                    Err(_) => return Err(ApiError::forbidden().into()),
                }
            } else {
                require_unrestricted_operator(&ctx, OperatorScope::SubjectOperator)?;
            }

            let target = read_principal(conn, request.principal_id)?
                .ok_or_else(|| point_missing(&ctx, true))?;
            let view = GrantView {
                scope: request.scope,
                capability: request.capability,
            };
            authorize_grant_mutation(&ctx, &target, view, GrantMutation::Put)?;
            if let GrantScope::Profile(profile_id) = request.scope {
                let exists: bool = conn
                    .prepare_cached("SELECT EXISTS(SELECT 1 FROM profiles WHERE profile_id = ?1)")?
                    .query_row([profile_id.to_string()], |row| row.get(0))?;
                if !exists {
                    return Err(ApiError::not_found().into());
                }
            }

            let principal_id = request.principal_id.to_string();
            let scope_kind = request.scope.scope_kind_str();
            let scope_id = request.scope.scope_id_string();
            let capability = scalar_text(request.capability)?;
            let created = conn
                .prepare_cached(
                    "INSERT INTO grants (grant_id, principal_id, scope_kind, scope_id, capability, created_by, created_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT (principal_id, scope_kind, scope_id, capability) DO NOTHING",
                )?
                .execute(params![
                    new_id.to_string(),
                    principal_id,
                    scope_kind,
                    scope_id,
                    capability,
                    ctx.caller.principal_id.to_string(),
                    tx.now_ms(),
                ])?
                != 0;
            let (status, outcome, grant_id) = if created {
                (StatusCode::CREATED, GrantOutcome::Created, new_id)
            } else {
                let id = conn
                    .prepare_cached(
                        "SELECT grant_id FROM grants
                         WHERE principal_id = ?1 AND scope_kind = ?2 AND scope_id = ?3 AND capability = ?4",
                    )?
                    .query_row(params![principal_id, scope_kind, scope_id, capability], |row| {
                        id(row, 0)
                    })?;
                (StatusCode::OK, GrantOutcome::Unchanged, id)
            };
            Ok((
                status,
                PutGrantResult {
                    outcome,
                    grant: GrantMetadata {
                        grant_id,
                        principal_id: request.principal_id,
                        scope: request.scope,
                        capability: request.capability,
                    },
                },
            ))
        })
        .await?;
    Ok((status, Json(result)))
}

#[utoipa::path(
    delete, path = "/v1/grants/{id}", tag = "Grants",
    security(("api_bearer" = [])),
    params(("id" = GrantId, Path, description = "Grant ID")),
    responses(
        (status = 204, description = "Grant deleted"),
        (status = 404, description = "Grant does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Cannot remove the last global admin grant", body = ProblemDetails, content_type = "application/problem+json"),
    ),
)]
async fn delete_grant(
    State(app): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(grant_id): ApiPath<GrantId>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    app.storage
        .execute_priority::<_, ApiError, _>(PriorityKind::RevokeGrant, move |tx| {
            let conn = tx.conn();
            let ctx = refresh_api(conn, &caller.credential, tx.now_ms())?;
            require_unrestricted_operator(&ctx, OperatorScope::SubjectOperator)?;
            let grant = conn
                .prepare_cached(
                    "SELECT g.grant_id, g.principal_id, g.scope_kind, g.scope_id, g.capability
                     FROM grants g JOIN hub_meta h ON h.id = 1
                     WHERE g.grant_id = ?1 AND g.principal_id IS NOT h.gc_purging_principal_id",
                )?
                .query_row([grant_id.to_string()], |row| {
                    grant_row(row).map(|(_, grant)| grant)
                })
                .optional()?
                .ok_or_else(|| point_missing(&ctx, true))?;

            let target = read_principal(conn, grant.principal_id)?
                .ok_or_else(|| point_missing(&ctx, true))?;
            let view = GrantView {
                scope: grant.scope,
                capability: grant.capability,
            };
            authorize_grant_mutation(&ctx, &target, view, GrantMutation::Remove)?;
            tx.revoke_grant(grant_id)?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

struct SubjectQueries {
    by_subject: &'static str,
    admin: &'static str,
    member: &'static str,
    orchestrator: &'static str,
}

macro_rules! subject_queries {
    ($select:literal, $id:literal) => {
        SubjectQueries {
            by_subject: concat!(
                $select,
                " WHERE r.principal_id = ?3 AND ",
                $id,
                " COLLATE BINARY > ?1 ORDER BY ",
                $id,
                " COLLATE BINARY ASC LIMIT ?2"
            ),
            admin: concat!(
                $select,
                " WHERE r.principal_id IS NOT (SELECT gc_purging_principal_id FROM hub_meta WHERE id = 1) AND ",
                $id,
                " COLLATE BINARY > ?1 ORDER BY ",
                $id,
                " COLLATE BINARY ASC LIMIT ?2"
            ),
            member: concat!(
                $select,
                " WHERE r.principal_id IN (SELECT p.principal_id FROM principals p JOIN hub_meta h ON h.id = 1 \
                  WHERE p.principal_id IS NOT h.gc_purging_principal_id \
                    AND (p.principal_id = ?3 OR (p.kind = 'agent' AND p.owner_principal_id = ?3))) AND ",
                $id,
                " COLLATE BINARY > ?1 ORDER BY ",
                $id,
                " COLLATE BINARY ASC LIMIT ?2"
            ),
            orchestrator: concat!(
                $select,
                " WHERE r.principal_id IN (SELECT p.principal_id FROM principals p JOIN hub_meta h ON h.id = 1 \
                  WHERE p.principal_id IS NOT h.gc_purging_principal_id AND p.kind = 'agent' \
                    AND p.owner_principal_id IS NULL AND p.managed_by_principal_id = ?3) AND ",
                $id,
                " COLLATE BINARY > ?1 ORDER BY ",
                $id,
                " COLLATE BINARY ASC LIMIT ?2"
            ),
        }
    };
}

const TOKEN_QUERIES: SubjectQueries = subject_queries!(
    "SELECT r.token_id, r.principal_id, r.label, r.max_capability, r.allowed_profiles_json, \
            r.allowed_nodes_json, r.withhold_sensitive, r.created_at_ms, r.expires_at_ms, r.revoked_at_ms \
     FROM auth_tokens r",
    "r.token_id"
);
const GRANT_QUERIES: SubjectQueries = subject_queries!(
    "SELECT r.grant_id, r.principal_id, r.scope_kind, r.scope_id, r.capability FROM grants r",
    "r.grant_id"
);

fn read_subject_page<Id: ToString, Item>(
    conn: &Connection,
    ctx: &AuthContext,
    query: SubjectPageQuery<Id>,
    limit: usize,
    metadata: SubjectMetadata,
    queries: &SubjectQueries,
    mut decode: impl FnMut(&Row<'_>) -> rusqlite::Result<(PrincipalId, Item)>,
) -> ApiResult<Vec<Item>> {
    let mut checked = BTreeSet::new();
    let caller = ctx.caller.principal_id;
    let (sql, subject) = if let Some(subject) = query.principal_id {
        let target = read_principal(conn, subject)?.ok_or_else(|| point_missing(ctx, false))?;
        authorize_subject_metadata_read(ctx, &target, metadata)?;
        checked.insert(subject);
        (queries.by_subject, Some(subject))
    } else if authorize_admin(ctx).is_ok() {
        (queries.admin, None)
    } else if ctx.caller.kind == PrincipalKind::Member {
        (queries.member, Some(caller))
    } else if ctx.caller.is_orchestrator {
        (queries.orchestrator, Some(caller))
    } else {
        return Ok(Vec::new());
    };

    let mut stmt = conn.prepare_cached(sql)?;
    let cursor = query.cursor.map(|id| id.to_string()).unwrap_or_default();
    let mut rows = match subject {
        Some(subject) => stmt.query(params![cursor, limit + 1, subject.to_string()])?,
        None => stmt.query(params![cursor, limit + 1])?,
    };
    let mut items = Vec::new();
    while let Some(row) = rows.next()? {
        let (subject, item) = decode(row)?;
        if checked.insert(subject) {
            let target = read_principal(conn, subject)?.ok_or_else(ApiError::internal)?;
            authorize_subject_metadata_read(ctx, &target, metadata)?;
        }
        items.push(item);
    }
    Ok(items)
}

fn bounded_set<T: Ord>(values: Option<Vec<T>>, max: usize) -> ApiResult<Option<BTreeSet<T>>> {
    let Some(values) = values else {
        return Ok(None);
    };
    if values.len() > max {
        return Err(ApiError::bad_input());
    }
    Ok(Some(values.into_iter().collect()))
}

fn token_row(row: &Row<'_>) -> rusqlite::Result<(PrincipalId, TokenMetadata)> {
    let subject = id(row, 1)?;
    Ok((
        subject,
        TokenMetadata {
            token_id: id(row, 0)?,
            principal_id: subject,
            label: row.get(2)?,
            max_capability: optional_scalar(row, 3)?,
            allowed_profiles: optional_json(row, 4)?,
            allowed_nodes: optional_json(row, 5)?,
            withhold_sensitive: row.get(6)?,
            created_at_ms: row.get(7)?,
            expires_at_ms: row.get(8)?,
            revoked_at_ms: row.get(9)?,
        },
    ))
}

fn grant_row(row: &Row<'_>) -> rusqlite::Result<(PrincipalId, GrantMetadata)> {
    let subject = id(row, 1)?;
    Ok((
        subject,
        GrantMetadata {
            grant_id: id(row, 0)?,
            principal_id: subject,
            scope: read_grant_scope(row, 2, 3)?,
            capability: scalar(row, 4)?,
        },
    ))
}

fn managed_active_nodes(
    conn: &Connection,
    manager: PrincipalId,
) -> rusqlite::Result<BTreeSet<NodeId>> {
    let mut statement = conn.prepare_cached(
        "SELECT node_id FROM nodes WHERE managed_by_principal_id = ?1 AND revoked_at_ms IS NULL",
    )?;
    statement
        .query_map([manager.to_string()], |row| id(row, 0))?
        .collect()
}

fn encode_optional_scope<T: Serialize>(value: Option<&T>) -> ApiResult<Option<String>> {
    value
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| ApiError::internal())
}

#[cfg(test)]
mod tests;
