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
    ApiCaller, ApiError, ApiJson, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody, RouteGroups,
};
use crate::operations::{active_token_count, is_valid_token_label};
use crate::principals::{Page, checked_page_limit, point_missing, reject_narrowed_admin};
use crate::storage::{PriorityKind, WriteTxError, id, read_principal, scalar, scalar_text};
use crate::vault::{
    IssuedCredential,
    auth::{optional_json, optional_scalar, read_grant_scope, refresh_api},
};

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
    allowed_profiles: Option<BTreeSet<ProfileId>>,
    allowed_nodes: Option<BTreeSet<NodeId>>,
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
    get, path = "/v1/tokens",
    security(("api_bearer" = [])),
    params(
        ("limit" = Option<u16>, Query, description = "Page size from 1 to 200 (default 50)"),
        ("cursor" = Option<TokenId>, Query, description = "Exclusive token ID cursor"),
        ("principal_id" = Option<PrincipalId>, Query, description = "Filter by token subject"),
    ),
    responses(
        (status = 200, body = Page<TokenMetadata>),
        (status = 400, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, body = ProblemDetails, content_type = "application/problem+json"),
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
                TOKEN_LIST,
                token_row,
            )
        })
        .await?;
    Ok(Json(Page::from_rows(results, limit, |row| row.token_id)))
}

#[utoipa::path(
    post, path = "/v1/tokens",
    security(("api_bearer" = [])),
    request_body = MintToken,
    responses(
        (status = 201, body = MintedToken),
        (status = 400, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, body = ProblemDetails, content_type = "application/problem+json"),
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
    if !is_valid_token_label(&label) {
        return Err(ApiError::bad_input());
    }
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
            reject_narrowed_admin(&ctx)?;
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
            authorize_token_mint(&ctx, &target, &request, &policy, &managed_nodes)
                .map_err(ApiError::from)?;
            if target.disabled_at_ms.is_some() {
                return Err(ApiError::from(AuthzError::PrincipalDisabled).into());
            }
            if active_token_count(conn, principal_id, now)? >= max_active_tokens {
                return Err(ApiError::conflict(error_codes::QUOTA_EXCEEDED).into());
            }
            if !token_id.matches_kind(target.kind) {
                return Err(WriteTxError::InvalidDatabase(
                    "token family does not match principal kind",
                ));
            }
            conn.execute(
                "INSERT INTO auth_tokens (token_id, principal_id, created_by, label, key_id,
                verifier_hmac, max_capability, allowed_profiles_json, allowed_nodes_json,
                withhold_sensitive, expires_at_ms, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    token_id.to_string(),
                    principal_id.to_string(),
                    ctx.caller.principal_id.to_string(),
                    label,
                    key_id,
                    verifier,
                    max_capability_text,
                    profiles_json,
                    nodes_json,
                    request.withhold_sensitive,
                    request.expires_at_ms,
                    now,
                ],
            )?;
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
    post, path = "/v1/tokens/{id}/revoke",
    security(("api_bearer" = [])),
    params(("id" = TokenId, Path, description = "Token ID")),
    responses(
        (status = 204),
        (status = 400, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, body = ProblemDetails, content_type = "application/problem+json"),
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
            reject_narrowed_admin(&ctx)?;
            let principal_id = conn
                .query_row(
                    "SELECT t.principal_id FROM auth_tokens t
             JOIN hub_meta h ON h.id = 1
             WHERE t.token_id = ?1 AND t.principal_id IS NOT h.gc_purging_principal_id",
                    [token_id.to_string()],
                    |row| id(row, 0),
                )
                .optional()?
                .ok_or_else(|| point_missing(&ctx, true))?;
            let target =
                read_principal(conn, principal_id)?.ok_or_else(|| point_missing(&ctx, true))?;
            authorize_token_revoke(&ctx, &target).map_err(ApiError::from)?;
            tx.revoke_token(ActorId::Principal(ctx.caller.principal_id), token_id)?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get, path = "/v1/grants",
    security(("api_bearer" = [])),
    params(
        ("limit" = Option<u16>, Query, description = "Page size from 1 to 200 (default 50)"),
        ("cursor" = Option<GrantId>, Query, description = "Exclusive grant ID cursor"),
        ("principal_id" = Option<PrincipalId>, Query, description = "Filter by grant subject"),
    ),
    responses(
        (status = 200, body = Page<GrantMetadata>),
        (status = 400, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, body = ProblemDetails, content_type = "application/problem+json"),
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
                GRANT_LIST,
                grant_row,
            )
        })
        .await?;
    Ok(Json(Page::from_rows(results, limit, |row| row.grant_id)))
}

#[utoipa::path(
    put, path = "/v1/grants",
    security(("api_bearer" = [])),
    request_body = PutGrant,
    responses(
        (status = 200, body = PutGrantResult),
        (status = 201, body = PutGrantResult),
        (status = 400, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, body = ProblemDetails, content_type = "application/problem+json"),
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
    let (status, result) = app.storage.execute_work::<_, ApiError, _>(std::mem::size_of::<PutGrant>(), move |tx| {
        let conn = tx.conn();
        let ctx = refresh_api(conn, &caller.credential, tx.now_ms())?;
        if request.capability == Capability::Admin {
            authorize_admin(&ctx).map_err(ApiError::from)?;
        } else {
            reject_narrowed_admin(&ctx)?;
            if request.scope == GrantScope::Global && authorize_admin(&ctx).is_err() {
                return Err(ApiError::forbidden().into());
            }
        }

        let target = read_principal(conn, request.principal_id)?
            .ok_or_else(|| point_missing(&ctx, true))?;
        let view = GrantView { scope: request.scope, capability: request.capability };
        authorize_grant_mutation(&ctx, &target, view, GrantMutation::Put)
            .map_err(ApiError::from)?;
        if let GrantScope::Profile(profile_id) = request.scope {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM profiles WHERE profile_id = ?1)",
                [profile_id.to_string()],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(ApiError::not_found().into());
            }
        }

        let principal_id = request.principal_id.to_string();
        let scope_kind = request.scope.scope_kind_str();
        let scope_id = request.scope.scope_id_string();
        let capability = scalar_text(request.capability)?;
        let created = conn.execute(
            "INSERT INTO grants (grant_id, principal_id, scope_kind, scope_id, capability, created_by, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (principal_id, scope_kind, scope_id, capability) DO NOTHING",
            params![
                new_id.to_string(), principal_id, scope_kind, scope_id, capability,
                ctx.caller.principal_id.to_string(), tx.now_ms(),
            ],
        )? != 0;
        let (status, outcome, grant_id) = if created {
            (StatusCode::CREATED, GrantOutcome::Created, new_id)
        } else {
            let id = conn.query_row(
                "SELECT grant_id FROM grants
                 WHERE principal_id = ?1 AND scope_kind = ?2 AND scope_id = ?3 AND capability = ?4",
                params![principal_id, scope_kind, scope_id, capability],
                |row| id(row, 0),
            )?;
            (StatusCode::OK, GrantOutcome::Unchanged, id)
        };
        Ok((status, PutGrantResult {
            outcome,
            grant: GrantMetadata {
                grant_id,
                principal_id: request.principal_id,
                scope: request.scope,
                capability: request.capability,
            },
        }))
    }).await?;
    Ok((status, Json(result)))
}

#[utoipa::path(
    delete, path = "/v1/grants/{id}",
    security(("api_bearer" = [])),
    params(("id" = GrantId, Path, description = "Grant ID")),
    responses(
        (status = 204),
        (status = 400, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, body = ProblemDetails, content_type = "application/problem+json"),
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
            reject_narrowed_admin(&ctx)?;
            let grant = conn.query_row(
            "SELECT g.grant_id, g.principal_id, g.scope_kind, g.scope_id, g.capability FROM grants g
             JOIN hub_meta h ON h.id = 1
             WHERE g.grant_id = ?1 AND g.principal_id IS NOT h.gc_purging_principal_id",
            [grant_id.to_string()],
            |row| grant_row(row).map(|(_, grant)| grant),
        ).optional()?.ok_or_else(|| point_missing(&ctx, true))?;

            let target = read_principal(conn, grant.principal_id)?
                .ok_or_else(|| point_missing(&ctx, true))?;
            let view = GrantView {
                scope: grant.scope,
                capability: grant.capability,
            };
            authorize_grant_mutation(&ctx, &target, view, GrantMutation::Remove)
                .map_err(ApiError::from)?;
            tx.revoke_grant(grant_id)?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

const TOKEN_LIST: (&str, &str) = (
    "SELECT r.token_id, r.principal_id, r.label, r.max_capability, r.allowed_profiles_json,
            r.allowed_nodes_json, r.withhold_sensitive, r.created_at_ms, r.expires_at_ms, r.revoked_at_ms
     FROM auth_tokens r",
    "r.token_id",
);
const GRANT_LIST: (&str, &str) = (
    "SELECT r.grant_id, r.principal_id, r.scope_kind, r.scope_id, r.capability FROM grants r",
    "r.grant_id",
);

fn read_subject_page<Id: ToString, Item>(
    conn: &Connection,
    ctx: &AuthContext,
    query: SubjectPageQuery<Id>,
    limit: usize,
    metadata: SubjectMetadata,
    (select, id): (&str, &str),
    mut decode: impl FnMut(&Row<'_>) -> rusqlite::Result<(PrincipalId, Item)>,
) -> ApiResult<Vec<Item>> {
    let mut checked = BTreeSet::new();
    let caller = ctx.caller.principal_id;
    // A subject filter can use the principal index directly. An unfiltered
    // delegate page starts with the subjects that delegate can see.
    let (visibility, subject) = if let Some(subject) = query.principal_id {
        let target = read_principal(conn, subject)?.ok_or_else(|| point_missing(ctx, false))?;
        authorize_subject_metadata_read(ctx, &target, metadata)?;
        checked.insert(subject);
        ("r.principal_id = ?3", Some(subject))
    } else if authorize_admin(ctx).is_ok() {
        (
            "r.principal_id IS NOT (SELECT gc_purging_principal_id FROM hub_meta WHERE id = 1)",
            None,
        )
    } else if ctx.caller.kind == PrincipalKind::Member {
        (
            "r.principal_id IN (SELECT p.principal_id FROM principals p JOIN hub_meta h ON h.id = 1
          WHERE p.principal_id IS NOT h.gc_purging_principal_id
            AND (p.principal_id = ?3 OR (p.kind = 'agent' AND p.owner_principal_id = ?3)))",
            Some(caller),
        )
    } else if ctx.caller.is_orchestrator {
        (
            "r.principal_id IN (SELECT p.principal_id FROM principals p JOIN hub_meta h ON h.id = 1
          WHERE p.principal_id IS NOT h.gc_purging_principal_id AND p.kind = 'agent'
            AND p.owner_principal_id IS NULL AND p.managed_by_principal_id = ?3)",
            Some(caller),
        )
    } else {
        return Ok(Vec::new());
    };

    let mut stmt = conn.prepare_cached(&format!(
        "{select} WHERE {visibility} AND {id} COLLATE BINARY > ?1 ORDER BY {id} COLLATE BINARY ASC LIMIT ?2"
    ))?;
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
