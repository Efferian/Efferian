//! Account metadata and versioned Vault writes.

mod bindings;

use std::num::NonZeroU64;
use std::sync::Arc;

use axum::{Json, extract::State};
use efferian_authz::{
    AccountAccess, AccountView, AuthContext, AuthzError, authorize_account_access, authorize_admin,
};
use efferian_protocol::{
    AccountId, AccountKind, AccountSecretPayload, AccountVisibility, PrincipalId, PrincipalKind,
    ProblemDetails, UpstreamId, error_codes as code, validate_slug,
};
use http::StatusCode;
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use zeroize::Zeroizing;

use self::bindings::ensure_visible_upstream;
pub(crate) use self::bindings::{bound_account_id, invoke_bindings};
use super::{Outcome, references::account_in_use};
use crate::http::{
    ApiCaller, ApiError, ApiJson, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody, Page,
    RouteGroups, checked_page_limit,
};
use crate::storage::{WriteTxError, id, opt_id, read_principal, scalar, scalar_text};
use crate::upstream_dispatch::UpstreamInvalidation;
use crate::vault::{AccountAad, Vault, auth::refresh_api};

const PUT_ATTEMPTS: usize = 4;

pub(super) fn routes() -> RouteGroups {
    RouteGroups {
        application: OpenApiRouter::new()
            .routes(routes!(list))
            .routes(routes!(get, put, delete))
            .merge(bindings::routes()),
        ..RouteGroups::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub(crate) struct AccountMetadata {
    pub(crate) account_id: AccountId,
    pub(crate) slug: String,
    pub(crate) owner_principal_id: PrincipalId,
    pub(crate) visibility: AccountVisibility,
    pub(crate) kind: AccountKind,
    pub(crate) upstream_id: Option<UpstreamId>,
    pub(crate) secret_version: u64,
    pub(crate) created_at_ms: i64,
    pub(crate) updated_at_ms: i64,
}

impl AccountMetadata {
    pub(crate) fn view(&self) -> AccountView {
        AccountView {
            account_id: self.account_id,
            owner_principal_id: self.owner_principal_id,
            visibility: self.visibility,
            kind: self.kind,
            upstream_id: self.upstream_id,
        }
    }

    fn aad(&self) -> ApiResult<AccountAad> {
        Ok(AccountAad {
            account_id: self.account_id,
            secret_version: NonZeroU64::new(self.secret_version).ok_or_else(ApiError::internal)?,
            kind: self.kind,
        })
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountQuery {
    visibility: Option<AccountVisibility>,
    owner: Option<PrincipalId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountListQuery {
    visibility: Option<AccountVisibility>,
    owner: Option<PrincipalId>,
    limit: Option<u16>,
    cursor: Option<AccountId>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct AccountPut {
    upstream_id: Option<UpstreamId>,
    #[schema(write_only)]
    secret: AccountSecretPayload,
}

#[derive(Serialize, ToSchema)]
struct AccountPutResponse {
    outcome: Outcome,
    account: AccountMetadata,
}

#[derive(Clone, Copy)]
struct AccountScope {
    visibility: AccountVisibility,
    owner: PrincipalId,
}

type CheckedAccount = Option<(AccountMetadata, Vec<u8>)>;

#[utoipa::path(
    get, path = "/v1/accounts", tag = "Accounts",
    params(
        ("visibility" = Option<AccountVisibility>, Query, description = "Filter by account visibility"),
        ("owner" = Option<PrincipalId>, Query, description = "Filter by owner (administrator only)"),
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Page size (default 50)"),
        ("cursor" = Option<AccountId>, Query, description = "Return items after this account ID")
    ),
    responses(
        (status = 200, description = "Visible accounts page", body = Page<AccountMetadata>),
        (status = 404, description = "Specified owner does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn list(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(query): ApiQuery<AccountListQuery>,
) -> ApiResult<Json<Page<AccountMetadata>>> {
    let limit = checked_page_limit(query.limit)?;
    let clock = state.clock;
    let rows = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            let admin = account_operator(&ctx, AccountAccess::Read)?;
            authorize_scope_selectors(admin, query.visibility, query.owner)?;
            check_owner(conn, query.owner)?;
            let (visibility, owner) = if admin {
                (query.visibility, query.owner)
            } else {
                (
                    Some(AccountVisibility::Private),
                    Some(ctx.caller.principal_id),
                )
            };
            let mut stmt = conn.prepare_cached(
                "SELECT a.account_id, a.slug, a.owner_principal_id, a.visibility, a.kind,
                        a.upstream_id, a.secret_version, a.created_at_ms, a.updated_at_ms
                 FROM accounts a JOIN hub_meta h ON h.id = 1
                 WHERE a.owner_principal_id IS NOT h.gc_purging_principal_id
                   AND a.account_id > ?1
                   AND (?2 IS NULL OR a.visibility = ?2)
                   AND (?3 IS NULL OR a.owner_principal_id = ?3)
                 ORDER BY a.account_id COLLATE BINARY LIMIT ?4",
            )?;
            let visibility = visibility.map(scalar_text).transpose()?;
            let rows = stmt.query_map(
                params![
                    query
                        .cursor
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    visibility,
                    owner.map(|value| value.to_string()),
                    limit + 1,
                ],
                account_row,
            )?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await?;
    Ok(Json(Page::from_rows(rows, limit, |row| row.account_id)))
}

#[utoipa::path(
    get, path = "/v1/accounts/{slug}", tag = "Accounts",
    params(
        ("slug" = String, Path, description = "Account slug"),
        ("visibility" = Option<AccountVisibility>, Query, description = "Private by default"),
        ("owner" = Option<PrincipalId>, Query, description = "Private account owner (administrator only)")
    ),
    responses(
        (status = 200, description = "Account metadata", body = AccountMetadata),
        (status = 404, description = "Account or specified owner does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn get(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    ApiQuery(query): ApiQuery<AccountQuery>,
) -> ApiResult<Json<AccountMetadata>> {
    check_slug(&slug)?;
    let clock = state.clock;
    let account = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            let (_, scope) = account_scope(conn, &ctx, query, AccountAccess::Read)?;
            let account = scoped_account(conn, &slug, scope)?.ok_or_else(ApiError::not_found)?;
            authorize_account_access(&ctx, &account.view(), AccountAccess::Read)?;
            Ok(account)
        })
        .await?;
    Ok(Json(account))
}

#[utoipa::path(
    put, path = "/v1/accounts/{slug}", tag = "Accounts",
    params(
        ("slug" = String, Path, description = "Account slug"),
        ("visibility" = Option<AccountVisibility>, Query, description = "Private by default"),
        ("owner" = Option<PrincipalId>, Query, description = "Private account owner (administrator only)")
    ),
    request_body = AccountPut,
    responses(
        (status = 200, description = "Account updated or unchanged", body = AccountPutResponse),
        (status = 201, description = "Account created", body = AccountPutResponse),
        (status = 404, description = "Upstream or specified owner does not exist or is inaccessible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Account kind and upstream are immutable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn put(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    ApiQuery(query): ApiQuery<AccountQuery>,
    ApiJson(request): ApiJson<AccountPut>,
) -> ApiResult<(StatusCode, Json<AccountPutResponse>)> {
    check_slug(&slug)?;
    let request = Arc::new(request);
    for _ in 0..PUT_ATTEMPTS {
        let (scope, current) =
            read_for_put(&state, &caller, &slug, query, Arc::clone(&request)).await?;
        let (before, sealed) = {
            let vault = Arc::clone(&state.vault);
            let request = Arc::clone(&request);
            tokio::task::spawn_blocking(move || prepare_secret(&vault, current, &request))
                .await
                .map_err(|_| ApiError::internal())??
        };

        let slug = slug.clone();
        let dispatcher = Arc::clone(&state.upstream);
        let caller = caller.clone();
        let account_upstream = request.upstream_id;
        let account_kind = request.secret.kind();
        let bytes = sealed.as_ref().map_or(0, |(_, blob)| blob.len());
        let result = state
            .storage
            .execute_work::<_, ApiError, _>(bytes, move |tx| {
                let conn = tx.conn();
                let now = tx.now_ms();
                let ctx = refresh_api(conn, &caller.credential, now)?;
                let (admin, live_scope) = account_scope(conn, &ctx, query, AccountAccess::Mutate)?;
                let live_account = scoped_account(conn, &slug, live_scope)?;
                if live_scope.owner != scope.owner
                    || live_scope.visibility != scope.visibility
                    || live_account != before
                {
                    return Ok(None);
                }
                ensure_visible_upstream(conn, &ctx, admin, account_upstream)?;
                let (account, outcome) = match (live_account, sealed) {
                    (Some(mut account), Some((aad, blob))) => {
                        authorize_account_access(&ctx, &account.view(), AccountAccess::Mutate)?;
                        conn.execute(
                            "UPDATE accounts SET secret_version = ?2, sealed_secret_blob = ?3,
                                                 updated_at_ms = ?4 WHERE account_id = ?1",
                            params![
                                account.account_id.to_string(),
                                aad.secret_version.get(),
                                blob,
                                now
                            ],
                        )?;
                        account.secret_version = aad.secret_version.get();
                        account.updated_at_ms = now;
                        (account, Outcome::Updated)
                    }
                    (None, Some((aad, blob))) => {
                        let account = AccountMetadata {
                            account_id: aad.account_id,
                            slug,
                            owner_principal_id: scope.owner,
                            visibility: scope.visibility,
                            kind: account_kind,
                            upstream_id: account_upstream,
                            secret_version: aad.secret_version.get(),
                            created_at_ms: now,
                            updated_at_ms: now,
                        };
                        authorize_account_access(&ctx, &account.view(), AccountAccess::Mutate)?;
                        insert_account(conn, &account, blob)?;
                        (account, Outcome::Created)
                    }
                    (Some(account), None) => {
                        authorize_account_access(&ctx, &account.view(), AccountAccess::Mutate)?;
                        return Ok(Some(AccountPutResponse {
                            outcome: Outcome::Unchanged,
                            account,
                        }));
                    }
                    (None, None) => return Err(ApiError::internal().into()),
                };
                let account_id = account.account_id;
                tx.on_commit(move || {
                    dispatcher.invalidate(UpstreamInvalidation::Account(account_id))
                });
                Ok(Some(AccountPutResponse { outcome, account }))
            })
            .await?;
        if let Some(response) = result {
            return Ok((response.outcome.status(), Json(response)));
        }
    }
    Err(ApiError::conflict(code::RESOURCE_IN_USE).retryable())
}

async fn read_for_put(
    state: &AppState,
    caller: &crate::vault::auth::AuthenticatedApi,
    slug: &str,
    query: AccountQuery,
    request: Arc<AccountPut>,
) -> ApiResult<(AccountScope, CheckedAccount)> {
    let slug = slug.to_owned();
    let caller = caller.clone();
    let clock = Arc::clone(&state.clock);
    state
        .storage
        .read_snapshot(move |conn| {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            let (admin, scope) = account_scope(conn, &ctx, query, AccountAccess::Mutate)?;
            let current = scoped_account(conn, &slug, scope)?;
            let kind = request.secret.kind();
            if let Some(account) = &current {
                authorize_account_access(&ctx, &account.view(), AccountAccess::Mutate)?;
                if account.kind != kind || account.upstream_id != request.upstream_id {
                    return Err(ApiError::conflict(code::RESOURCE_IN_USE));
                }
            }
            if request.upstream_id.is_some() && kind != AccountKind::HttpAuth {
                return Err(ApiError::bad_input());
            }
            ensure_visible_upstream(conn, &ctx, admin, request.upstream_id)?;
            let current = current
                .map(|account| -> ApiResult<_> {
                    let blob = load_account_secret(conn, &account)?;
                    Ok((account, blob))
                })
                .transpose()?;
            Ok((scope, current))
        })
        .await
}

type SealedSecret = Option<(AccountAad, Vec<u8>)>;

fn prepare_secret(
    vault: &Vault,
    current: CheckedAccount,
    request: &AccountPut,
) -> ApiResult<(Option<AccountMetadata>, SealedSecret)> {
    request
        .secret
        .validate()
        .map_err(|_| ApiError::bad_input())?;
    let (before, aad) = match current {
        Some((account, blob)) => {
            let previous = open_account(vault, &account, &blob)?;
            if previous.ct_eq(&request.secret) {
                return Ok((Some(account), None));
            }
            let mut aad = account.aad()?;
            let next_version = aad
                .secret_version
                .checked_add(1)
                .filter(|next| i64::try_from(next.get()).is_ok())
                .ok_or_else(ApiError::internal)?;
            aad.secret_version = next_version;
            (Some(account), aad)
        }
        None => (
            None,
            AccountAad {
                account_id: AccountId::new(),
                secret_version: NonZeroU64::MIN,
                kind: request.secret.kind(),
            },
        ),
    };
    let plaintext =
        Zeroizing::new(serde_json::to_vec(&request.secret).map_err(|_| ApiError::internal())?);
    let blob = vault.seal_account(&aad, &plaintext)?;
    Ok((before, Some((aad, blob))))
}

#[utoipa::path(
    delete, path = "/v1/accounts/{slug}", tag = "Accounts",
    params(
        ("slug" = String, Path, description = "Account slug"),
        ("visibility" = Option<AccountVisibility>, Query, description = "Private by default"),
        ("owner" = Option<PrincipalId>, Query, description = "Private account owner (administrator only)")
    ),
    responses(
        (status = 204, description = "Account deleted"),
        (status = 404, description = "Account or specified owner does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Account is referenced by the live catalog, a binding, or an active execution", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn delete(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    ApiQuery(query): ApiQuery<AccountQuery>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    check_slug(&slug)?;
    let dispatcher = state.upstream;
    state
        .storage
        .execute_work::<_, ApiError, _>(slug.len(), move |tx| {
            let conn = tx.conn();
            let ctx = refresh_api(conn, &caller.credential, tx.now_ms())?;
            let (_, scope) = account_scope(conn, &ctx, query, AccountAccess::Mutate)?;
            let account = scoped_account(conn, &slug, scope)?.ok_or_else(ApiError::not_found)?;
            authorize_account_access(&ctx, &account.view(), AccountAccess::Mutate)?;
            let account_id = account.account_id;
            if account_in_use(conn, account_id)? {
                return Err(ApiError::conflict(code::RESOURCE_IN_USE).into());
            }
            conn.execute(
                "DELETE FROM accounts WHERE account_id = ?1",
                [account_id.to_string()],
            )?;
            tx.on_commit(move || dispatcher.invalidate(UpstreamInvalidation::Account(account_id)));
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn check_slug(slug: &str) -> ApiResult<()> {
    validate_slug(slug).map_err(|_| ApiError::bad_input())
}

fn account_operator(ctx: &AuthContext, access: AccountAccess) -> ApiResult<bool> {
    match authorize_admin(ctx) {
        Ok(()) => Ok(true),
        Err(error @ AuthzError::UnrestrictedTokenRequired) => Err(error.into()),
        Err(_) if ctx.caller.kind != PrincipalKind::Member => Err(ApiError::forbidden()),
        Err(_) if access == AccountAccess::Mutate && !ctx.token.is_unrestricted() => {
            Err(AuthzError::UnrestrictedTokenRequired.into())
        }
        Err(_) => Ok(false),
    }
}

fn authorize_scope_selectors(
    admin: bool,
    visibility: Option<AccountVisibility>,
    owner: Option<PrincipalId>,
) -> ApiResult<()> {
    if !admin && (owner.is_some() || visibility == Some(AccountVisibility::Shared)) {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn check_owner(conn: &Connection, owner: Option<PrincipalId>) -> ApiResult<()> {
    if let Some(owner) = owner
        && read_principal(conn, owner)?.is_none()
    {
        return Err(ApiError::not_found());
    }
    Ok(())
}

fn account_scope(
    conn: &Connection,
    ctx: &AuthContext,
    query: AccountQuery,
    access: AccountAccess,
) -> ApiResult<(bool, AccountScope)> {
    let admin = account_operator(ctx, access)?;
    authorize_scope_selectors(admin, query.visibility, query.owner)?;
    let visibility = query.visibility.unwrap_or(AccountVisibility::Private);
    if visibility == AccountVisibility::Shared && query.owner.is_some() {
        return Err(ApiError::bad_input());
    }
    check_owner(conn, query.owner)?;
    Ok((
        admin,
        AccountScope {
            visibility,
            owner: query.owner.unwrap_or(ctx.caller.principal_id),
        },
    ))
}

fn scoped_account(
    conn: &Connection,
    slug: &str,
    scope: AccountScope,
) -> rusqlite::Result<Option<AccountMetadata>> {
    account_by_slug(conn, slug, scope.visibility, scope.owner)
}

fn account_row(row: &Row<'_>) -> rusqlite::Result<AccountMetadata> {
    let secret_version = row.get::<_, u64>(6)?;
    if secret_version == 0 {
        return Err(crate::storage::invalid_text_msg(
            6,
            "invalid account secret version",
        ));
    }
    Ok(AccountMetadata {
        account_id: id(row, 0)?,
        slug: row.get(1)?,
        owner_principal_id: id(row, 2)?,
        visibility: scalar(row, 3)?,
        kind: scalar(row, 4)?,
        upstream_id: opt_id(row, 5)?,
        secret_version,
        created_at_ms: row.get(7)?,
        updated_at_ms: row.get(8)?,
    })
}

pub(crate) fn account_by_id(
    conn: &Connection,
    account_id: AccountId,
) -> rusqlite::Result<Option<AccountMetadata>> {
    conn.prepare_cached(
        "SELECT a.account_id, a.slug, a.owner_principal_id, a.visibility, a.kind,
                a.upstream_id, a.secret_version, a.created_at_ms, a.updated_at_ms
         FROM accounts a JOIN hub_meta h ON h.id = 1
         WHERE a.account_id = ?1 AND a.owner_principal_id IS NOT h.gc_purging_principal_id",
    )?
    .query_row([account_id.to_string()], account_row)
    .optional()
}

pub(crate) fn account_by_slug(
    conn: &Connection,
    slug: &str,
    visibility: AccountVisibility,
    owner: PrincipalId,
) -> rusqlite::Result<Option<AccountMetadata>> {
    match visibility {
        AccountVisibility::Private => conn
            .prepare_cached(
                "SELECT a.account_id, a.slug, a.owner_principal_id, a.visibility, a.kind,
                        a.upstream_id, a.secret_version, a.created_at_ms, a.updated_at_ms
                 FROM accounts a JOIN hub_meta h ON h.id = 1
                 WHERE a.slug = ?1 AND a.visibility = 'private' AND a.owner_principal_id = ?2
                   AND a.owner_principal_id IS NOT h.gc_purging_principal_id",
            )?
            .query_row(params![slug, owner.to_string()], account_row)
            .optional(),
        AccountVisibility::Shared => conn
            .prepare_cached(
                "SELECT a.account_id, a.slug, a.owner_principal_id, a.visibility, a.kind,
                        a.upstream_id, a.secret_version, a.created_at_ms, a.updated_at_ms
                 FROM accounts a JOIN hub_meta h ON h.id = 1
                 WHERE a.slug = ?1 AND a.visibility = 'shared'
                   AND a.owner_principal_id IS NOT h.gc_purging_principal_id",
            )?
            .query_row([slug], account_row)
            .optional(),
    }
}

pub(crate) fn load_account_secret(
    conn: &Connection,
    account: &AccountMetadata,
) -> ApiResult<Vec<u8>> {
    conn.prepare_cached(
        "SELECT sealed_secret_blob FROM accounts WHERE account_id = ?1 AND secret_version = ?2",
    )?
    .query_row(
        params![account.account_id.to_string(), account.secret_version],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

pub(crate) fn open_account(
    vault: &Vault,
    account: &AccountMetadata,
    envelope: &[u8],
) -> ApiResult<AccountSecretPayload> {
    let plaintext = vault.open_account(&account.aad()?, envelope)?;
    let payload = serde_json::from_slice::<AccountSecretPayload>(&plaintext)
        .map_err(|_| ApiError::internal())?;
    if payload.kind() != account.kind || payload.validate().is_err() {
        return Err(ApiError::internal());
    }
    Ok(payload)
}

fn insert_account(
    conn: &Connection,
    account: &AccountMetadata,
    envelope: Vec<u8>,
) -> Result<(), WriteTxError<ApiError>> {
    conn.execute(
        "INSERT INTO accounts (account_id, slug, owner_principal_id, visibility, kind, upstream_id,
                               secret_version, created_at_ms, updated_at_ms, sealed_secret_blob)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)",
        params![
            account.account_id.to_string(),
            account.slug,
            account.owner_principal_id.to_string(),
            scalar_text(account.visibility)?,
            scalar_text(account.kind)?,
            account.upstream_id.map(|value| value.to_string()),
            account.secret_version,
            account.created_at_ms,
            envelope,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
