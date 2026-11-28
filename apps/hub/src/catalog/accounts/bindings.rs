use std::sync::Arc;

use axum::{Json, extract::State};
use efferian_authz::{
    AccountAccess, AuthContext, BindingMutation, BindingUpstream, BindingView, InvokeBindingView,
    PrincipalView, SubjectMetadata, authorize_account_access, authorize_binding_mutation,
    authorize_binding_read, authorize_subject_metadata_read,
};
use efferian_protocol::{
    AccountId, AccountVisibility, PrincipalId, PrincipalKind, ProblemDetails, ProfileId, UpstreamId,
};
use http::StatusCode;
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    AccountMetadata, AccountQuery, Outcome, account_by_id, account_operator, account_scope,
    authorize_scope_selectors, check_slug, scoped_account,
};
use crate::http::{
    ApiCaller, ApiError, ApiJson, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody, Page,
    checked_page_limit,
};
use crate::principals::introspection::{
    caller_bound_profiles_for_upstream, caller_bound_upstreams,
};
use crate::storage::{StorageError, id, inheriting_agents, json, opt_id, read_principal, scalar};
use crate::upstream_dispatch::UpstreamInvalidation;
use crate::vault::auth::refresh_api;

pub(super) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(put, delete))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingQuery {
    principal_id: Option<PrincipalId>,
    upstream_id: Option<UpstreamId>,
    limit: Option<u16>,
    cursor: Option<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct BindingById {
    account_id: AccountId,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct BindingBySlug {
    account_slug: String,
    owner: Option<PrincipalId>,
    visibility: Option<AccountVisibility>,
}

#[derive(Deserialize, ToSchema)]
#[serde(untagged)]
enum AccountBindingPut {
    Id(BindingById),
    Slug(BindingBySlug),
}

#[derive(Serialize, ToSchema)]
struct AccountBindingMetadata {
    principal_id: PrincipalId,
    upstream_id: UpstreamId,
    upstream_slug: String,
    account_id: AccountId,
    account_slug: String,
    created_at_ms: i64,
}

impl AccountBindingMetadata {
    fn view(&self) -> BindingView {
        BindingView {
            principal_id: self.principal_id,
            upstream_id: self.upstream_id,
            account_id: self.account_id,
        }
    }
}

#[derive(Serialize, ToSchema)]
struct AccountBindingPutResponse {
    outcome: Outcome,
    binding: AccountBindingMetadata,
}

#[utoipa::path(
    get, path = "/v1/account-bindings", tag = "Accounts",
    params(
        ("principal_id" = Option<PrincipalId>, Query, description = "Filter by principal"),
        ("upstream_id" = Option<UpstreamId>, Query, description = "Filter by upstream"),
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Page size (default 50)"),
        ("cursor" = Option<String>, Query, description = "Continuation cursor from the preceding page")
    ),
    responses(
        (status = 200, description = "Visible account bindings page", body = Page<AccountBindingMetadata>)
    ),
    security(("api_bearer" = []))
)]
async fn list(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(query): ApiQuery<BindingQuery>,
) -> ApiResult<Json<Page<AccountBindingMetadata>>> {
    let limit = checked_page_limit(query.limit)?;
    let cursor = query.cursor.as_deref().map(parse_cursor).transpose()?;
    let clock = state.clock;
    let rows = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            list_visible_bindings(conn, &ctx, query, cursor, limit)
        })
        .await?;
    Ok(Json(Page::from_rows(rows, limit, |row| {
        format!("{}.{}", row.principal_id, row.upstream_id)
    })))
}

fn parse_cursor(cursor: &str) -> ApiResult<(PrincipalId, UpstreamId)> {
    let (principal, upstream) = cursor.split_once('.').ok_or_else(ApiError::bad_input)?;
    Ok((
        PrincipalId::parse(principal).map_err(|_| ApiError::bad_input())?,
        UpstreamId::parse(upstream).map_err(|_| ApiError::bad_input())?,
    ))
}

fn list_visible_bindings(
    conn: &Connection,
    ctx: &AuthContext,
    query: BindingQuery,
    cursor: Option<(PrincipalId, UpstreamId)>,
    limit: usize,
) -> ApiResult<Vec<AccountBindingMetadata>> {
    let admin = account_operator(ctx, AccountAccess::Read)?;
    let visible = if admin {
        Vec::new()
    } else {
        let visible = caller_bound_upstreams(conn, ctx)?;
        if visible.is_empty() {
            return Ok(Vec::new());
        }
        visible
    };
    let (after_principal, after_upstream) = cursor.map_or_else(
        || (String::new(), String::new()),
        |(principal, upstream)| (principal.to_string(), upstream.to_string()),
    );
    let collect_rows = |rows: &mut rusqlite::Rows<'_>| -> ApiResult<Vec<AccountBindingMetadata>> {
        let mut result = Vec::with_capacity(limit + 1);
        while let Some(row) = rows.next()? {
            let binding = binding_row(row)?;
            let subject = joined_principal_view(row)?;
            let upstream = BindingUpstream {
                upstream_id: binding.upstream_id,
                caller_bound_profiles: visible
                    .iter()
                    .find(|entry| entry.upstream_id == binding.upstream_id)
                    .map_or(&[], |entry| entry.caller_bound_profiles.as_slice()),
            };
            match authorize_binding_read(ctx, Some(upstream), &subject, &binding.view()) {
                Ok(()) => {
                    result.push(binding);
                    if result.len() > limit {
                        break;
                    }
                }
                Err(efferian_authz::AuthzError::InvalidAuthContext) => {
                    return Err(
                        StorageError::InvalidDatabase("invalid principal projection").into(),
                    );
                }
                Err(_) => {}
            }
        }
        Ok(result)
    };
    const SELECT_FIELDS: &str = "b.principal_id, b.upstream_id, u.slug, b.account_id, a.slug, b.created_at_ms, \
         p.kind, p.owner_principal_id, p.managed_by_principal_id, p.inherit_owner_bindings, \
         p.is_orchestrator, p.allowed_node_tags_json, p.observe_executions, p.disabled_at_ms";
    if !admin {
        let upstream_ids = visible
            .iter()
            .map(|value| value.upstream_id)
            .collect::<Vec<_>>();
        let upstreams = serde_json::to_string(&upstream_ids).map_err(|_| ApiError::internal())?;
        let mut stmt = conn.prepare_cached(&format!(
            "WITH subjects(id) AS (
                 SELECT ?5 WHERE ?3 IS NULL OR ?3 = ?5
                 UNION ALL
                 SELECT principal_id FROM principals
                 WHERE kind = 'agent' AND owner_principal_id = ?5
                   AND (?3 IS NULL OR principal_id = ?3)
             )
             SELECT {SELECT_FIELDS}
             FROM subjects s
             JOIN account_bindings b ON b.principal_id = s.id
             JOIN principals p ON p.principal_id = b.principal_id
             JOIN upstreams u ON u.upstream_id = b.upstream_id
             JOIN accounts a ON a.account_id = b.account_id
             JOIN hub_meta h ON h.id = 1
             WHERE b.principal_id IS NOT h.gc_purging_principal_id
               AND a.owner_principal_id IS NOT h.gc_purging_principal_id
               AND (b.principal_id, b.upstream_id) > (?1, ?2)
               AND (?4 IS NULL OR b.upstream_id = ?4)
               AND b.upstream_id IN (SELECT value FROM json_each(?6))
             ORDER BY b.principal_id COLLATE BINARY, b.upstream_id COLLATE BINARY"
        ))?;
        let mut rows = stmt.query(params![
            after_principal,
            after_upstream,
            query.principal_id.map(|value| value.to_string()),
            query.upstream_id.map(|value| value.to_string()),
            ctx.caller.principal_id.to_string(),
            upstreams,
        ])?;
        return collect_rows(&mut rows);
    }
    match (query.principal_id, query.upstream_id) {
        (Some(principal), Some(upstream)) => {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {SELECT_FIELDS}
                 FROM account_bindings b
                 JOIN principals p ON p.principal_id = b.principal_id
                 JOIN upstreams u ON u.upstream_id = b.upstream_id
                 JOIN accounts a ON a.account_id = b.account_id
                 JOIN hub_meta h ON h.id = 1
                 WHERE b.principal_id = ?3 AND b.upstream_id = ?4
                   AND b.principal_id IS NOT h.gc_purging_principal_id
                   AND a.owner_principal_id IS NOT h.gc_purging_principal_id
                   AND (b.principal_id, b.upstream_id) > (?1, ?2)
                 ORDER BY b.principal_id COLLATE BINARY, b.upstream_id COLLATE BINARY"
            ))?;
            let mut rows = stmt.query(params![
                after_principal,
                after_upstream,
                principal.to_string(),
                upstream.to_string(),
            ])?;
            collect_rows(&mut rows)
        }
        (Some(principal), None) => {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {SELECT_FIELDS}
                 FROM account_bindings b
                 JOIN principals p ON p.principal_id = b.principal_id
                 JOIN upstreams u ON u.upstream_id = b.upstream_id
                 JOIN accounts a ON a.account_id = b.account_id
                 JOIN hub_meta h ON h.id = 1
                 WHERE b.principal_id = ?3
                   AND b.principal_id IS NOT h.gc_purging_principal_id
                   AND a.owner_principal_id IS NOT h.gc_purging_principal_id
                   AND (b.principal_id, b.upstream_id) > (?1, ?2)
                 ORDER BY b.principal_id COLLATE BINARY, b.upstream_id COLLATE BINARY"
            ))?;
            let mut rows = stmt.query(params![
                after_principal,
                after_upstream,
                principal.to_string(),
            ])?;
            collect_rows(&mut rows)
        }
        (None, Some(upstream)) => {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {SELECT_FIELDS}
                 FROM account_bindings b
                 JOIN principals p ON p.principal_id = b.principal_id
                 JOIN upstreams u ON u.upstream_id = b.upstream_id
                 JOIN accounts a ON a.account_id = b.account_id
                 JOIN hub_meta h ON h.id = 1
                 WHERE b.upstream_id = ?3
                   AND b.principal_id IS NOT h.gc_purging_principal_id
                   AND a.owner_principal_id IS NOT h.gc_purging_principal_id
                   AND (b.principal_id, b.upstream_id) > (?1, ?2)
                 ORDER BY b.principal_id COLLATE BINARY, b.upstream_id COLLATE BINARY"
            ))?;
            let mut rows = stmt.query(params![
                after_principal,
                after_upstream,
                upstream.to_string(),
            ])?;
            collect_rows(&mut rows)
        }
        (None, None) => {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {SELECT_FIELDS}
                 FROM account_bindings b
                 JOIN principals p ON p.principal_id = b.principal_id
                 JOIN upstreams u ON u.upstream_id = b.upstream_id
                 JOIN accounts a ON a.account_id = b.account_id
                 JOIN hub_meta h ON h.id = 1
                 WHERE b.principal_id IS NOT h.gc_purging_principal_id
                   AND a.owner_principal_id IS NOT h.gc_purging_principal_id
                   AND (b.principal_id, b.upstream_id) > (?1, ?2)
                 ORDER BY b.principal_id COLLATE BINARY, b.upstream_id COLLATE BINARY"
            ))?;
            let mut rows = stmt.query(params![after_principal, after_upstream])?;
            collect_rows(&mut rows)
        }
    }
}

fn joined_principal_view(row: &Row<'_>) -> Result<PrincipalView, StorageError> {
    let raw_tags: Vec<String> = json(row, 11)?;
    let count = raw_tags.len();
    let allowed_node_tags: std::collections::BTreeSet<String> = raw_tags.into_iter().collect();
    if allowed_node_tags.len() != count {
        return Err(StorageError::InvalidDatabase(
            "duplicate principal node tags",
        ));
    }
    let view = PrincipalView {
        principal_id: id(row, 0)?,
        kind: scalar::<PrincipalKind>(row, 6)?,
        owner_principal_id: opt_id(row, 7)?,
        managed_by_principal_id: opt_id(row, 8)?,
        inherit_owner_bindings: row.get::<_, i64>(9)? != 0,
        is_orchestrator: row.get::<_, i64>(10)? != 0,
        allowed_node_tags,
        observe_executions: row.get::<_, i64>(12)? != 0,
        disabled_at_ms: row.get(13)?,
    };
    view.validate()
        .map_err(|_| StorageError::InvalidDatabase("invalid principal projection"))?;
    Ok(view)
}

#[utoipa::path(
    put, path = "/v1/account-bindings/{principal_id_or_me}/{upstream_slug}", tag = "Accounts",
    params(
        ("principal_id_or_me" = String, Path, description = "Principal ID or the literal me"),
        ("upstream_slug" = String, Path, description = "Upstream slug")
    ),
    request_body = AccountBindingPut,
    responses(
        (status = 200, description = "Account binding updated or unchanged", body = AccountBindingPutResponse),
        (status = 201, description = "Account binding created", body = AccountBindingPutResponse),
        (status = 404, description = "Upstream is inaccessible or a selected resource does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn put(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath((principal, upstream_slug)): ApiPath<(String, String)>,
    ApiJson(request): ApiJson<AccountBindingPut>,
) -> ApiResult<(StatusCode, Json<AccountBindingPutResponse>)> {
    check_slug(&upstream_slug)?;
    if let AccountBindingPut::Slug(query) = &request {
        check_slug(&query.account_slug)?;
    }
    let principal_id = parse_subject(&principal, caller.principal_id)?;
    let dispatcher = state.upstream;
    let response = state
        .storage
        .execute_work::<_, ApiError, _>(upstream_slug.len(), move |tx| {
            let conn = tx.conn();
            let now = tx.now_ms();
            let ctx = refresh_api(conn, &caller.credential, now)?;
            let admin = account_operator(&ctx, AccountAccess::Mutate)?;
            if let AccountBindingPut::Slug(query) = &request {
                authorize_scope_selectors(admin, query.visibility, query.owner)?;
            }
            let (upstream_id, profiles) = binding_upstream(conn, &ctx, admin, &upstream_slug)?;
            let upstream = BindingUpstream { upstream_id, caller_bound_profiles: &profiles };
            let subject = binding_subject(conn, &ctx, admin, principal_id)?;
            let account = request_account(conn, &ctx, admin, request)?;
            authorize_binding_mutation(&ctx, Some(upstream), &subject, &account.view(), BindingMutation::Set)?;

            let existing = binding_at(conn, principal_id, upstream_id)?;
            let outcome = match &existing {
                Some(binding) if binding.account_id == account.account_id => Outcome::Unchanged,
                Some(binding) => {
                    authorize_removal(conn, &ctx, upstream, &subject, binding)?;
                    Outcome::Updated
                },
                None => Outcome::Created,
            };
            if matches!(outcome, Outcome::Unchanged) && let Some(binding) = existing {
                return Ok(AccountBindingPutResponse { outcome, binding });
            }
            conn.execute(
                "INSERT INTO account_bindings (principal_id, upstream_id, account_id, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(principal_id, upstream_id) DO UPDATE SET account_id = excluded.account_id",
                params![principal_id.to_string(), upstream_id.to_string(), account.account_id.to_string(), now],
            )?;
            let affected_children = inheriting_agents(conn, principal_id)?;
            tx.on_commit(move || {
                dispatcher.invalidate(UpstreamInvalidation::Binding {
                    principal_id,
                    upstream_id,
                });
                for child in affected_children {
                    dispatcher.invalidate(UpstreamInvalidation::Binding {
                        principal_id: child,
                        upstream_id,
                    });
                }
            });
            Ok(AccountBindingPutResponse {
                outcome,
                binding: AccountBindingMetadata {
                    principal_id,
                    upstream_id,
                    upstream_slug,
                    account_id: account.account_id,
                    account_slug: account.slug,
                    created_at_ms: existing.map_or(now, |row| row.created_at_ms),
                },
            })
        })
        .await?;
    Ok((response.outcome.status(), Json(response)))
}

#[utoipa::path(
    delete, path = "/v1/account-bindings/{principal_id_or_me}/{upstream_slug}", tag = "Accounts",
    params(
        ("principal_id_or_me" = String, Path, description = "Principal ID or the literal me"),
        ("upstream_slug" = String, Path, description = "Upstream slug")
    ),
    responses(
        (status = 204, description = "Account binding deleted"),
        (status = 404, description = "Account binding or upstream is inaccessible or does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn delete(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath((principal, upstream_slug)): ApiPath<(String, String)>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    check_slug(&upstream_slug)?;
    let principal_id = parse_subject(&principal, caller.principal_id)?;
    let dispatcher = Arc::clone(&state.upstream);
    state
        .storage
        .execute_work::<_, ApiError, _>(upstream_slug.len(), move |tx| {
            let conn = tx.conn();
            let ctx = refresh_api(conn, &caller.credential, tx.now_ms())?;
            let admin = account_operator(&ctx, AccountAccess::Mutate)?;
            let (upstream_id, profiles) = binding_upstream(conn, &ctx, admin, &upstream_slug)?;
            let upstream = BindingUpstream {
                upstream_id,
                caller_bound_profiles: &profiles,
            };
            let subject = binding_subject(conn, &ctx, admin, principal_id)?;
            let existing =
                binding_at(conn, principal_id, upstream_id)?.ok_or_else(ApiError::not_found)?;
            authorize_removal(conn, &ctx, upstream, &subject, &existing)?;
            conn.execute(
                "DELETE FROM account_bindings WHERE principal_id = ?1 AND upstream_id = ?2",
                params![principal_id.to_string(), upstream_id.to_string()],
            )?;
            let affected_children = inheriting_agents(conn, principal_id)?;
            tx.on_commit(move || {
                dispatcher.invalidate(UpstreamInvalidation::Binding {
                    principal_id,
                    upstream_id,
                });
                for child in affected_children {
                    dispatcher.invalidate(UpstreamInvalidation::Binding {
                        principal_id: child,
                        upstream_id,
                    });
                }
            });
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn authorize_removal(
    conn: &Connection,
    ctx: &AuthContext,
    upstream: BindingUpstream<'_>,
    subject: &PrincipalView,
    binding: &AccountBindingMetadata,
) -> ApiResult<()> {
    let account = account_by_id(conn, binding.account_id)?.ok_or_else(ApiError::not_found)?;
    authorize_binding_mutation(
        ctx,
        Some(upstream),
        subject,
        &account.view(),
        BindingMutation::Remove {
            existing: binding.view(),
        },
    )?;
    Ok(())
}

fn parse_subject(principal: &str, caller: PrincipalId) -> ApiResult<PrincipalId> {
    if principal == "me" {
        return Ok(caller);
    }
    PrincipalId::parse(principal).map_err(|_| ApiError::bad_input())
}

fn binding_subject(
    conn: &Connection,
    ctx: &AuthContext,
    admin: bool,
    principal: PrincipalId,
) -> ApiResult<PrincipalView> {
    let target = read_principal(conn, principal)?.ok_or_else(|| {
        if admin {
            ApiError::not_found()
        } else {
            ApiError::forbidden()
        }
    })?;
    authorize_subject_metadata_read(ctx, &target, SubjectMetadata::AccountBindings)?;
    Ok(target)
}

fn request_account(
    conn: &Connection,
    ctx: &AuthContext,
    admin: bool,
    request: AccountBindingPut,
) -> ApiResult<AccountMetadata> {
    let is_slug = matches!(request, AccountBindingPut::Slug(_));
    let account = match request {
        AccountBindingPut::Id(query) => account_by_id(conn, query.account_id)?,
        AccountBindingPut::Slug(query) => {
            let (_, scope) = account_scope(
                conn,
                ctx,
                AccountQuery {
                    visibility: query.visibility,
                    owner: query.owner,
                },
                AccountAccess::Mutate,
            )?;
            scoped_account(conn, &query.account_slug, scope)?
        }
    };
    let account = account.ok_or_else(|| {
        if admin || is_slug {
            ApiError::not_found()
        } else {
            ApiError::forbidden()
        }
    })?;
    authorize_account_access(ctx, &account.view(), AccountAccess::Read)?;
    Ok(account)
}

pub(super) fn ensure_visible_upstream(
    conn: &Connection,
    ctx: &AuthContext,
    admin: bool,
    upstream: Option<UpstreamId>,
) -> ApiResult<()> {
    let Some(upstream) = upstream else {
        return Ok(());
    };
    if admin {
        conn.prepare_cached("SELECT 1 FROM upstreams WHERE upstream_id = ?1")?
            .query_row([upstream.to_string()], |row| row.get::<_, i64>(0))
            .optional()?
            .ok_or_else(ApiError::not_found)?;
    } else if caller_bound_profiles_for_upstream(conn, ctx, upstream, true)?.is_empty() {
        return Err(ApiError::not_found());
    }
    Ok(())
}

fn binding_upstream(
    conn: &Connection,
    ctx: &AuthContext,
    admin: bool,
    slug: &str,
) -> ApiResult<(UpstreamId, Vec<ProfileId>)> {
    let upstream = conn
        .prepare_cached("SELECT upstream_id FROM upstreams WHERE slug = ?1")?
        .query_row([slug], |row| id(row, 0))
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    let profiles = if admin {
        Vec::new()
    } else {
        let profiles = caller_bound_profiles_for_upstream(conn, ctx, upstream, false)?;
        if profiles.is_empty() {
            return Err(ApiError::not_found());
        }
        profiles
    };
    Ok((upstream, profiles))
}

fn binding_at(
    conn: &Connection,
    principal_id: PrincipalId,
    upstream_id: UpstreamId,
) -> rusqlite::Result<Option<AccountBindingMetadata>> {
    conn.prepare_cached(
        "SELECT b.principal_id, b.upstream_id, u.slug, b.account_id, a.slug, b.created_at_ms
         FROM account_bindings b
         JOIN upstreams u ON u.upstream_id = b.upstream_id
         JOIN accounts a ON a.account_id = b.account_id
         WHERE b.principal_id = ?1 AND b.upstream_id = ?2",
    )?
    .query_row(
        params![principal_id.to_string(), upstream_id.to_string()],
        binding_row,
    )
    .optional()
}

fn binding_row(row: &Row<'_>) -> rusqlite::Result<AccountBindingMetadata> {
    Ok(AccountBindingMetadata {
        principal_id: id(row, 0)?,
        upstream_id: id(row, 1)?,
        upstream_slug: row.get(2)?,
        account_id: id(row, 3)?,
        account_slug: row.get(4)?,
        created_at_ms: row.get(5)?,
    })
}

pub(crate) fn bound_account_id(
    conn: &Connection,
    principal: PrincipalId,
    upstream: UpstreamId,
) -> rusqlite::Result<Option<AccountId>> {
    conn.prepare_cached(
        "SELECT account_id FROM account_bindings WHERE principal_id = ?1 AND upstream_id = ?2",
    )?
    .query_row(
        params![principal.to_string(), upstream.to_string()],
        |row| id(row, 0),
    )
    .optional()
}

pub(crate) fn invoke_bindings(
    conn: &Connection,
    ctx: &AuthContext,
    upstream: UpstreamId,
) -> rusqlite::Result<Vec<InvokeBindingView>> {
    let caller = ctx.caller.principal_id;
    let owner = ctx
        .caller
        .owner_principal_id
        .filter(|_| ctx.caller.inherit_owner_bindings);
    for principal_id in [Some(caller), owner].into_iter().flatten() {
        if let Some(account_id) = bound_account_id(conn, principal_id, upstream)? {
            // An explicit binding takes precedence even if its account is missing.
            return Ok(vec![InvokeBindingView {
                binding: BindingView {
                    principal_id,
                    upstream_id: upstream,
                    account_id,
                },
                account: account_by_id(conn, account_id)?.map(|account| account.view()),
            }]);
        }
    }
    Ok(Vec::new())
}
