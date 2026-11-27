use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use efferian_authz::{
    AuthContext, ExecutionAccess, authorize_execution_access, can_read_sensitive_result,
};
use efferian_protocol::{
    CancelReqPayload, ExecutionId, ExecutionSummary, ExecutorKind, ProblemDetails,
};
use rusqlite::Connection;
use serde::Deserialize;
use tokio::sync::watch;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::http::{
    ApiCaller, ApiError, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody, Page, RouteGroups,
    checked_page_limit,
};
use crate::storage::{
    ExecutionSnapshot, InvokeOutcome, PriorityKind, RevocationWatch, WriteTxError, json,
};
use crate::vault::{ExecutionAad, auth::refresh_api};

mod control;
mod records;

pub(crate) use control::{
    ExecutionControl, UpstreamReservation, finish_upstreams_for_shutdown, recover_upstreams,
    sweep_deadlines,
};
pub(crate) use records::{ExecutionDetail, ExecutionMetadata, execution_auth_target};
use records::{
    ExecutionQuery, ExecutionRow, ResultAccess, parse_cursor, read_execution, read_execution_page,
};

pub(super) fn routes() -> RouteGroups {
    RouteGroups {
        application: OpenApiRouter::new()
            .routes(routes!(list_executions))
            .routes(routes!(get_execution)),
        control: OpenApiRouter::new().routes(routes!(cancel_execution)),
        ..RouteGroups::default()
    }
}

const MAX_WAIT_MS: u64 = 25_000;

pub(crate) fn checked_wait_ms(wait_ms: u64) -> ApiResult<u64> {
    if wait_ms > MAX_WAIT_MS {
        return Err(ApiError::bad_input());
    }
    Ok(wait_ms)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionReadQuery {
    wait_ms: Option<u64>,
    #[serde(default)]
    sensitive: bool,
}

#[utoipa::path(
    get, path = "/v1/executions", tag = "Executions",
    params(
        ("state" = Option<efferian_protocol::ExecutionState>, Query, description = "Filter by state"),
        ("principal_id" = Option<efferian_protocol::PrincipalId>, Query, description = "Filter by caller principal"),
        ("profile_id" = Option<efferian_protocol::ProfileId>, Query, description = "Filter by profile"),
        ("node_id" = Option<efferian_protocol::NodeId>, Query, description = "Filter by node"),
        ("tool_id" = Option<efferian_protocol::ToolId>, Query, description = "Filter by tool"),
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Items per page, defaults to 50"),
        ("cursor" = Option<String>, Query, description = "Exclusive cursor from the previous page"),
    ),
    security(("api_bearer" = [])),
    responses((status = 200, description = "Visible executions in descending creation order", body = Page<ExecutionMetadata>))
)]
async fn list_executions(
    State(state): State<AppState>,
    caller: ApiCaller,
    ApiQuery(query): ApiQuery<ExecutionQuery>,
) -> ApiResult<Json<Page<ExecutionMetadata>>> {
    let limit = checked_page_limit(query.limit)?;
    let cursor = query.cursor.as_deref().map(parse_cursor).transpose()?;
    let clock = state.clock;
    let page = state
        .storage
        .read_snapshot(move |conn| {
            let ctx = refresh_api(conn, &caller.0.credential, clock.wall_now_ms())?;
            read_execution_page(conn, &ctx, query, limit, cursor)
        })
        .await?;
    Ok(Json(page))
}

#[utoipa::path(
    get, path = "/v1/executions/{id}", tag = "Executions",
    params(
        ("id" = ExecutionId, Path, description = "Execution ID"),
        ("wait_ms" = Option<u64>, Query, minimum = 0, maximum = 25000, description = "Maximum wait for terminal state, defaults to zero"),
        ("sensitive" = Option<bool>, Query, description = "Request authorized execution output, defaults to false"),
    ),
    security(("api_bearer" = [])),
    responses(
        (status = 200, description = "Current execution detail", body = ExecutionDetail),
        (status = 404, description = "Execution not visible", body = ProblemDetails, content_type = "application/problem+json"),
    )
)]
async fn get_execution(
    State(state): State<AppState>,
    caller: ApiCaller,
    ApiPath(id): ApiPath<ExecutionId>,
    ApiQuery(query): ApiQuery<ExecutionReadQuery>,
) -> ApiResult<Json<ExecutionDetail>> {
    let wait_ms = checked_wait_ms(query.wait_ms.unwrap_or_default())?;
    if wait_ms != 0 {
        let revocations = state.storage.subscribe_revocations()?;
        wait_if_active(&state, &caller, id, None, wait_ms, revocations).await?;
    }
    let (_, view) = read_view(&state, caller, id, Sensitive::Requested(query.sensitive)).await?;
    Ok(Json(render_detail(&state, view).await?))
}

#[utoipa::path(
    post, path = "/v1/executions/{id}/cancel", tag = "Executions",
    params(("id" = ExecutionId, Path, description = "Execution ID")),
    security(("api_bearer" = [])),
    responses(
        (status = 200, description = "Terminal execution", body = ExecutionMetadata),
        (status = 202, description = "Cancellation requested", body = ExecutionMetadata),
        (status = 404, description = "Execution not visible", body = ProblemDetails, content_type = "application/problem+json"),
    )
)]
async fn cancel_execution(
    State(state): State<AppState>,
    caller: ApiCaller,
    ApiPath(id): ApiPath<ExecutionId>,
    _: EmptyBody,
) -> ApiResult<Response> {
    let bridge = Arc::clone(&state.bridge);
    let upstream = Arc::clone(&state.upstream);
    let execution = Arc::clone(&state.execution);
    let row = state
        .storage
        .execute_priority(PriorityKind::CancelExecution, move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.0.credential, tx.now_ms())?;
            let row = authorized_row(tx.conn(), &ctx, id, ExecutionAccess::Cancel)?;
            if row.fields.state.is_terminal() {
                return Ok::<_, WriteTxError<ApiError>>(row);
            }
            match row.fields.executor_kind {
                ExecutorKind::Node => {
                    let node_id = row
                        .fields
                        .node_id
                        .ok_or(WriteTxError::InvalidDatabase("node execution has no node"))?;
                    tx.cancel_execution(id)?;
                    if let Some(epoch) = tx.active_node_epoch(node_id)? {
                        tx.on_commit(move || {
                            let _ = bridge.try_send_cancel(
                                node_id,
                                epoch,
                                CancelReqPayload { execution_id: id },
                            );
                        });
                    }
                }
                ExecutorKind::Upstream => {
                    if tx.cancel_upstream_execution(id, ctx.caller.principal_id)? {
                        tx.on_commit(move || {
                            execution.cancel_upstream(id);
                            upstream.cancel(id);
                        });
                    }
                }
            }
            Ok(
                read_execution(tx.conn(), id)?.ok_or(WriteTxError::InvalidDatabase(
                    "execution disappeared during cancel",
                ))?,
            )
        })
        .await?;
    let status = if row.fields.state.is_terminal() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((status, Json(row.metadata())).into_response())
}

pub(crate) async fn invocation_response(
    state: &AppState,
    caller: ApiCaller,
    outcome: InvokeOutcome,
    wait_ms: u64,
    revocations: RevocationWatch,
) -> ApiResult<Response> {
    let id = outcome.execution_id;
    let current = outcome
        .waiter
        .as_ref()
        .map_or(outcome.snapshot, |rx| *rx.borrow());
    if wait_ms != 0 && !current.state.is_terminal() {
        wait_if_active(state, &caller, id, outcome.waiter, wait_ms, revocations).await?;
    }
    let (_, view) = read_view(state, caller, id, Sensitive::IfTerminal).await?;
    if view.row.fields.state.is_terminal() {
        Ok(Json(render_detail(state, view).await?).into_response())
    } else {
        Ok((StatusCode::ACCEPTED, Json(view.row.metadata())).into_response())
    }
}

async fn wait_if_active(
    state: &AppState,
    caller: &ApiCaller,
    id: ExecutionId,
    receiver: Option<watch::Receiver<ExecutionSnapshot>>,
    wait_ms: u64,
    mut revocations: RevocationWatch,
) -> ApiResult<()> {
    let Some(_permit) = state.execution.reserve_waiter(caller.0.principal_id) else {
        return Ok(());
    };
    let (ctx, view) = read_view(state, caller.clone(), id, Sensitive::Requested(false)).await?;
    if view.row.fields.state.is_terminal() {
        return Ok(());
    }
    let mut shutdown = state.execution.shutdown_receiver();
    let until = ctx.token.expires_at_ms.map_or(wait_ms, |expiry| {
        wait_ms.min(expiry.saturating_sub(state.clock.wall_now_ms()).max(0) as u64)
    });
    tokio::select! {
        biased;
        _ = shutdown.wait_for(|&shutting_down| shutting_down) => {}
        _ = authorization_changed(&mut revocations, &ctx) => {}
        _ = tokio::time::sleep(Duration::from_millis(until)) => {}
        _ = wait_for_terminal(state, id, receiver) => {}
    }
    Ok(())
}

async fn authorization_changed(revocations: &mut RevocationWatch, ctx: &AuthContext) {
    while let Ok(signal) = revocations.recv().await {
        if signal.affects_caller(ctx) {
            return;
        }
    }
}

async fn wait_for_terminal(
    state: &AppState,
    id: ExecutionId,
    receiver: Option<watch::Receiver<ExecutionSnapshot>>,
) {
    let mut receiver = match receiver {
        Some(receiver) => receiver,
        None => {
            let Ok(Some(receiver)) = state.storage.subscribe_waiter(id).await else {
                return;
            };
            receiver
        }
    };
    let _ = receiver
        .wait_for(|snapshot| snapshot.state.is_terminal())
        .await;
}

#[derive(Clone, Copy)]
enum Sensitive {
    Requested(bool),
    IfTerminal,
}

struct ExecutionView {
    row: ExecutionRow,
    latest_summary: Option<ExecutionSummary>,
    result_access: ResultAccess,
    sealed: Option<Vec<u8>>,
}

async fn read_view(
    state: &AppState,
    caller: ApiCaller,
    id: ExecutionId,
    sensitive: Sensitive,
) -> ApiResult<(AuthContext, ExecutionView)> {
    let clock = Arc::clone(&state.clock);
    state
        .storage
        .read_snapshot(move |conn| {
            let ctx = refresh_api(conn, &caller.0.credential, clock.wall_now_ms())?;
            let row = authorized_row(conn, &ctx, id, ExecutionAccess::ReadMetadata)?;
            let requested = match sensitive {
                Sensitive::Requested(requested) => requested,
                Sensitive::IfTerminal => row.fields.state.is_terminal(),
            };
            let (result_access, latest_summary, sealed) = if !requested {
                (ResultAccess::NotRequested, None, None)
            } else if !can_read_sensitive_result(&ctx, &row.target) {
                (ResultAccess::Denied, None, None)
            } else {
                let (summary, sealed): (ExecutionSummary, Option<Vec<u8>>) = conn
                    .prepare_cached(
                        "SELECT summary_json,
                    CASE WHEN result_expired = 0 AND state NOT IN ('accepted', 'running')
                         THEN sealed_result_blob END
                 FROM executions WHERE execution_id = ?1",
                    )?
                    .query_row([id.to_string()], |row| Ok((json(row, 0)?, row.get(1)?)))?;
                let access = if row.fields.result_expired {
                    ResultAccess::Expired
                } else if sealed.is_some() {
                    ResultAccess::Available
                } else {
                    ResultAccess::Unavailable
                };
                (access, Some(summary), sealed)
            };
            Ok((
                ctx,
                ExecutionView {
                    row,
                    latest_summary,
                    result_access,
                    sealed,
                },
            ))
        })
        .await
}

fn authorized_row(
    conn: &Connection,
    ctx: &AuthContext,
    id: ExecutionId,
    access: ExecutionAccess,
) -> ApiResult<ExecutionRow> {
    let row = read_execution(conn, id)?;
    authorize_execution_access(ctx, row.as_ref().map(|row| &row.target), access)?;
    row.ok_or_else(ApiError::not_found)
}

async fn render_detail(state: &AppState, view: ExecutionView) -> ApiResult<ExecutionDetail> {
    let mut detail = view.row.detail(view.result_access);
    if let Some(summary) = view.latest_summary {
        detail.summary = summary;
    }
    if let Some(sealed) = view.sealed {
        let aad = ExecutionAad {
            execution_id: detail.fields.execution_id,
            caller_principal_id: detail.fields.caller_principal_id,
        };
        detail.result = Some(super::results::open_result(&state.vault, aad, sealed).await?);
    }
    Ok(detail)
}

#[cfg(test)]
mod tests;
