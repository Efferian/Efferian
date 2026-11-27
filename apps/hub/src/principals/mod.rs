//! Principal management and the caller's current identity.

mod data;
mod introspection;

use axum::{Json, extract::State};
use efferian_authz::{PrincipalAccess, authorize_principal_manage};
use efferian_protocol::{ActorId, PrincipalId, ProblemDetails, validate_resource_name};
use http::StatusCode;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::http::{
    ApiCaller, ApiError, ApiJson, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody, OperatorScope,
    Page, PageQuery, RouteGroups, point_missing, require_unrestricted_operator,
};
use crate::node_bridge::BridgeCloseReason;
use crate::storage::{PriorityKind, WriteTxError, read_principal};
use crate::vault::auth::refresh_api;

use self::data::{Principal, PrincipalPut, PrincipalPutResponse, upsert_principal};

pub(crate) fn routes() -> RouteGroups {
    RouteGroups {
        application: OpenApiRouter::new()
            .routes(routes!(list))
            .routes(routes!(get, put, delete))
            .routes(routes!(enable))
            .routes(introspection::me_route()),
        control: OpenApiRouter::new().routes(routes!(disable)),
        ..RouteGroups::default()
    }
}

#[utoipa::path(
    get,
    path = "/v1/principals",
    tag = "Principals",
    params(
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Page size (default 50)"),
        ("cursor" = Option<PrincipalId>, Query, description = "Return items after this principal ID")
    ),
    responses(
        (status = 200, description = "Visible principals page", body = Page<Principal>)
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
    tag = "Principals",
    params(("principal_ref" = String, Path, description = "Principal name")),
    responses(
        (status = 200, description = "Principal metadata", body = Principal),
        (status = 404, description = "Principal does not exist", body = ProblemDetails, content_type = "application/problem+json")
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
    tag = "Principals",
    params(("principal_ref" = String, Path, description = "Principal name")),
    request_body = PrincipalPut,
    responses(
        (status = 200, description = "Principal updated or unchanged", body = PrincipalPutResponse),
        (status = 201, description = "Principal created", body = PrincipalPutResponse),
        (status = 404, description = "Referenced parent principal does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Quota or Hub identity conflict", body = ProblemDetails, content_type = "application/problem+json")
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
    tag = "Principals",
    params(("id" = PrincipalId, Path, description = "Principal ID")),
    responses(
        (status = 204, description = "Principal disabled"),
        (status = 404, description = "Principal does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Cannot disable the last active global administrator", body = ProblemDetails, content_type = "application/problem+json")
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
            require_unrestricted_operator(&ctx, OperatorScope::SubjectOperator)?;
            let target =
                read_principal(tx.conn(), principal)?.ok_or_else(|| point_missing(&ctx, true))?;
            authorize_principal_manage(&ctx, &target, PrincipalAccess::Disable)?;
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
            Ok::<_, WriteTxError<ApiError>>(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/principals/{id}/enable",
    tag = "Principals",
    params(("id" = PrincipalId, Path, description = "Principal ID")),
    responses(
        (status = 204, description = "Principal enabled"),
        (status = 404, description = "Principal does not exist", body = ProblemDetails, content_type = "application/problem+json")
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
            require_unrestricted_operator(&ctx, OperatorScope::SubjectOperator)?;
            let target =
                read_principal(tx.conn(), principal)?.ok_or_else(|| point_missing(&ctx, true))?;
            authorize_principal_manage(&ctx, &target, PrincipalAccess::Enable)?;
            data::enable_principal(tx, &target)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/v1/principals/{principal_ref}",
    tag = "Principals",
    params(("principal_ref" = PrincipalId, Path, description = "Principal ID")),
    responses(
        (status = 204, description = "Principal deleted"),
        (status = 404, description = "Principal does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Principal is active, not a managed agent, or still referenced", body = ProblemDetails, content_type = "application/problem+json")
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
            require_unrestricted_operator(&ctx, OperatorScope::SubjectOperator)?;
            let target =
                read_principal(tx.conn(), principal)?.ok_or_else(|| point_missing(&ctx, true))?;
            authorize_principal_manage(&ctx, &target, PrincipalAccess::Delete)?;
            data::delete_principal(tx, &target)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
