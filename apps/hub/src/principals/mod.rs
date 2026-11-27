//! Principal management and the caller's current identity.

mod data;
mod introspection;

use axum::{Json, extract::State};
use efferian_authz::{
    AuthContext, AuthzError, PrincipalAccess, authorize_admin, authorize_principal_manage,
};
use efferian_protocol::{ActorId, PrincipalId, validate_resource_name};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::http::{
    ApiCaller, ApiError, ApiJson, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody, RouteGroups,
};
use crate::node_bridge::BridgeCloseReason;
use crate::storage::{PriorityKind, read_principal};
use crate::vault::auth::refresh_api;

use self::data::{Principal, PrincipalPut, PrincipalPutResponse, upsert_principal};

pub(crate) fn routes() -> RouteGroups {
    RouteGroups {
        application: OpenApiRouter::new()
            .routes(routes!(list))
            .routes(routes!(get, put, delete))
            .routes(routes!(enable))
            .routes(introspection::me_route())
            .routes(introspection::status_route()),
        control: OpenApiRouter::new().routes(routes!(disable)),
        ..RouteGroups::default()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PageQuery<Id> {
    pub limit: Option<u16>,
    pub cursor: Option<Id>,
}

impl<Id> PageQuery<Id> {
    pub fn checked_limit(&self) -> ApiResult<usize> {
        checked_page_limit(self.limit)
    }
}

pub(crate) fn checked_page_limit(limit: Option<u16>) -> ApiResult<usize> {
    let limit = limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(ApiError::bad_input());
    }
    Ok(usize::from(limit))
}

#[derive(Serialize, ToSchema)]
pub(crate) struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    pub fn from_rows<Id: ToString>(
        mut items: Vec<T>,
        limit: usize,
        id: impl FnOnce(&T) -> Id,
    ) -> Self {
        let next_cursor = if items.len() > limit {
            items.truncate(limit);
            items.last().map(|item| id(item).to_string())
        } else {
            None
        };
        Self { items, next_cursor }
    }
}

pub(crate) fn point_missing(ctx: &AuthContext, mutating: bool) -> ApiError {
    match authorize_admin(ctx) {
        Ok(()) => ApiError::not_found(),
        Err(error @ AuthzError::UnrestrictedTokenRequired) if mutating => error.into(),
        Err(_) => ApiError::forbidden(),
    }
}

pub(crate) fn reject_narrowed_admin(ctx: &AuthContext) -> ApiResult<()> {
    if let Err(error @ AuthzError::UnrestrictedTokenRequired) = authorize_admin(ctx) {
        return Err(error.into());
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/v1/principals",
    params(
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Page size (default 50)"),
        ("cursor" = Option<PrincipalId>, Query, description = "Return items after this principal ID")
    ),
    responses(
        (status = 200, body = Page<Principal>),
        (status = 400, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn list(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(query): ApiQuery<PageQuery<PrincipalId>>,
) -> ApiResult<Json<Page<Principal>>> {
    let limit = query.checked_limit()?;
    let cursor = query.cursor.map(|id| id.to_string());
    let clock = state.clock;
    let page = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            data::list_principals(conn, &ctx, cursor.as_deref(), limit)
        })
        .await?;
    Ok(Json(page))
}

#[utoipa::path(
    get,
    path = "/v1/principals/{principal_ref}",
    params(("principal_ref" = String, Path, description = "Principal name")),
    responses(
        (status = 200, body = Principal),
        (status = 400, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn get(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<Principal>> {
    validate_resource_name(&name).map_err(|_| ApiError::bad_input())?;
    let clock = state.clock;
    let principal = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            let principal =
                data::principal_by_name(conn, &name)?.ok_or_else(|| point_missing(&ctx, false))?;
            authorize_principal_manage(&ctx, &principal.view(), PrincipalAccess::Read)?;
            Ok(principal)
        })
        .await?;
    Ok(Json(principal))
}

#[utoipa::path(
    put,
    path = "/v1/principals/{principal_ref}",
    params(("principal_ref" = String, Path, description = "Principal name")),
    request_body = PrincipalPut,
    responses(
        (status = 200, body = PrincipalPutResponse),
        (status = 201, body = PrincipalPutResponse),
        (status = 400, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 409, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn put(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(name): ApiPath<String>,
    ApiJson(request): ApiJson<PrincipalPut>,
) -> ApiResult<(StatusCode, Json<PrincipalPutResponse>)> {
    validate_resource_name(&name).map_err(|_| ApiError::bad_input())?;
    let new_id = request.new_id();
    let bytes = name.len() + request.work_bytes();
    let config = state.config;
    let result = state
        .storage
        .execute_work(bytes, move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            upsert_principal(tx, &ctx, &config, name, new_id, request)
        })
        .await?;
    Ok((result.status(), Json(result)))
}

#[utoipa::path(
    post,
    path = "/v1/principals/{id}/disable",
    params(("id" = PrincipalId, Path, description = "Principal ID")),
    responses(
        (status = 204),
        (status = 400, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 409, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn disable(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(principal): ApiPath<PrincipalId>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    let bridge = state.bridge;
    state
        .storage
        .execute_priority(PriorityKind::DisablePrincipal, move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            reject_narrowed_admin(&ctx)?;
            let target =
                read_principal(tx.conn(), principal)?.ok_or_else(|| point_missing(&ctx, true))?;
            authorize_principal_manage(&ctx, &target, PrincipalAccess::Disable)
                .map_err(ApiError::from)?;
            if let Some(revoked) =
                tx.disable_principal(ActorId::Principal(ctx.caller.principal_id), principal)?
                && !revoked.is_empty()
            {
                tx.on_commit(move || {
                    for (node, epoch) in revoked {
                        bridge.close_session(node, epoch, BridgeCloseReason::NodeRevoked);
                    }
                });
            }
            Ok::<_, crate::storage::WriteTxError<ApiError>>(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/principals/{id}/enable",
    params(("id" = PrincipalId, Path, description = "Principal ID")),
    responses(
        (status = 204),
        (status = 400, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn enable(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(principal): ApiPath<PrincipalId>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    state
        .storage
        .execute_work(0, move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            reject_narrowed_admin(&ctx)?;
            let target =
                read_principal(tx.conn(), principal)?.ok_or_else(|| point_missing(&ctx, true))?;
            authorize_principal_manage(&ctx, &target, PrincipalAccess::Enable)
                .map_err(ApiError::from)?;
            data::enable_principal(tx, &target)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/v1/principals/{principal_ref}",
    params(("principal_ref" = PrincipalId, Path, description = "Principal ID")),
    responses(
        (status = 204),
        (status = 400, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json"),
        (status = 409, body = efferian_protocol::ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn delete(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(principal): ApiPath<PrincipalId>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    state
        .storage
        .execute_work(0, move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            reject_narrowed_admin(&ctx)?;
            let target =
                read_principal(tx.conn(), principal)?.ok_or_else(|| point_missing(&ctx, true))?;
            authorize_principal_manage(&ctx, &target, PrincipalAccess::Delete)
                .map_err(ApiError::from)?;
            data::delete_principal(tx, &target)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
