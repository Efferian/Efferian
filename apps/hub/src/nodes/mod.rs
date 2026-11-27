//! Node inventory and credential lifecycle.

mod enrollment;
mod references;

use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode};
use efferian_authz::{
    NodeAuthTarget, authorize_admin, authorize_node_read, authorize_node_revoke_or_delete,
};
use efferian_protocol::{ActorId, NodeId, PlatformOs, PrincipalId, ProblemDetails, error_codes};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::http::{
    ApiCaller, ApiError, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody, RouteGroups,
};
use crate::node_bridge::{BridgeCloseReason, NodeLiveStatus};
use crate::principals::{Page, PageQuery, point_missing, reject_narrowed_admin};
use crate::storage::{PriorityKind, WriteTxError, id, json, opt_id, scalar};
use crate::vault::auth::refresh_api;

type NodeWriteResult<T> = Result<T, WriteTxError<ApiError>>;

pub(crate) fn routes() -> RouteGroups {
    RouteGroups {
        application: OpenApiRouter::new()
            .routes(routes!(list_nodes))
            .routes(routes!(get_node, delete_node))
            .routes(routes!(enrollment::mint_reenrollment)),
        control: OpenApiRouter::new().routes(routes!(revoke_node)),
        enrollment_api: OpenApiRouter::new().routes(routes!(enrollment::mint_enrollment)),
        enrollment_exchange: OpenApiRouter::new().routes(routes!(enrollment::exchange)),
        ..RouteGroups::default()
    }
}

#[derive(Serialize, ToSchema)]
struct NodeSummary {
    node_id: NodeId,
    name: String,
    tags: Vec<String>,
    managed_by_principal_id: Option<PrincipalId>,
    revoked_at_ms: Option<i64>,
    platform_os: Option<PlatformOs>,
    platform_arch: Option<String>,
    allowed_cwd_roots: Vec<String>,
    max_concurrent_executions: Option<u32>,
    last_connected_at_ms: Option<i64>,
    last_disconnected_at_ms: Option<i64>,
    created_at_ms: i64,
    updated_at_ms: i64,
    live_status: NodeLiveStatus,
}

const SUMMARY_COLUMNS: &str = "n.node_id, n.name, n.tags_json, n.managed_by_principal_id,
    n.revoked_at_ms, n.platform_os, n.platform_arch, n.allowed_cwd_roots_json,
    n.max_concurrent_executions, n.last_connected_at_ms, n.last_disconnected_at_ms,
    n.created_at_ms, n.updated_at_ms";

impl NodeSummary {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        let platform_os = match row.get_ref(5)? {
            rusqlite::types::ValueRef::Null => None,
            _ => Some(scalar(row, 5)?),
        };
        Ok(Self {
            node_id: id(row, 0)?,
            name: row.get(1)?,
            tags: json(row, 2)?,
            managed_by_principal_id: opt_id(row, 3)?,
            revoked_at_ms: row.get(4)?,
            platform_os,
            platform_arch: row.get(6)?,
            allowed_cwd_roots: json(row, 7)?,
            max_concurrent_executions: row.get(8)?,
            last_connected_at_ms: row.get(9)?,
            last_disconnected_at_ms: row.get(10)?,
            created_at_ms: row.get(11)?,
            updated_at_ms: row.get(12)?,
            live_status: NodeLiveStatus::Offline,
        })
    }

    fn auth_target(&self) -> NodeAuthTarget {
        NodeAuthTarget {
            node_id: self.node_id,
            managed_by_principal_id: self.managed_by_principal_id,
        }
    }

    fn resolve_status(&mut self, state: &AppState) {
        if self.revoked_at_ms.is_none() {
            self.live_status = state.bridge.live_status(self.node_id);
        }
    }
}

struct StoredNode {
    target: NodeAuthTarget,
    name: String,
    revoked_at_ms: Option<i64>,
    session_epoch: i64,
}

fn stored_node(conn: &Connection, node_id: NodeId) -> rusqlite::Result<Option<StoredNode>> {
    conn.prepare_cached(
        "SELECT name, managed_by_principal_id, revoked_at_ms, session_epoch FROM nodes
         WHERE node_id = ?1",
    )?
    .query_row([node_id.to_string()], |row| {
        Ok(StoredNode {
            target: NodeAuthTarget {
                node_id,
                managed_by_principal_id: opt_id(row, 1)?,
            },
            name: row.get(0)?,
            revoked_at_ms: row.get(2)?,
            session_epoch: row.get(3)?,
        })
    })
    .optional()
}

#[utoipa::path(
    get, path = "/v1/nodes", tag = "Nodes",
    params(
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Items per page, defaults to 50"),
        ("cursor" = Option<NodeId>, Query, description = "Exclusive node ID cursor"),
    ),
    security(("api_bearer" = [])),
    responses((status = 200, body = Page<NodeSummary>), (status = 403, body = ProblemDetails, content_type = "application/problem+json"))
)]
async fn list_nodes(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(page): ApiQuery<PageQuery<NodeId>>,
) -> ApiResult<Json<Page<NodeSummary>>> {
    let limit = page.checked_limit()?;
    let cursor = page.cursor.map(|value| value.to_string());
    let clock = Arc::clone(&state.clock);
    let mut rows = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            let admin = authorize_admin(&ctx).is_ok();
            if !admin && !ctx.caller.is_orchestrator {
                return Err(ApiError::forbidden());
            }

            let manager = ctx.caller.principal_id.to_string();
            let scope = ctx
                .token
                .allowed_nodes
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|_| ApiError::internal())?;
            let mut statement = conn.prepare_cached(&format!(
                "SELECT {SUMMARY_COLUMNS} FROM nodes n
                 WHERE (?1 OR n.managed_by_principal_id = ?2)
                   AND (?3 IS NULL OR n.node_id IN (SELECT value FROM json_each(?3)))
                   AND n.node_id COLLATE BINARY > ?4
                 ORDER BY n.node_id COLLATE BINARY ASC LIMIT ?5",
            ))?;
            let selected = statement.query_map(
                params![
                    admin,
                    manager,
                    scope,
                    cursor.as_deref().unwrap_or_default(),
                    limit + 1
                ],
                NodeSummary::from_row,
            )?;
            let rows = selected.collect::<rusqlite::Result<Vec<_>>>()?;
            for node in &rows {
                authorize_node_read(&ctx, &node.auth_target())?;
            }
            Ok(rows)
        })
        .await?;
    for node in rows.iter_mut().take(limit) {
        node.resolve_status(&state);
    }
    Ok(Json(Page::from_rows(rows, limit, |node| node.node_id)))
}

#[utoipa::path(
    get, path = "/v1/nodes/{id}", tag = "Nodes",
    params(("id" = NodeId, Path)),
    security(("api_bearer" = [])),
    responses((status = 200, body = NodeSummary), (status = 403, body = ProblemDetails, content_type = "application/problem+json"), (status = 404, body = ProblemDetails, content_type = "application/problem+json"))
)]
async fn get_node(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(node_id): ApiPath<NodeId>,
) -> ApiResult<Json<NodeSummary>> {
    let clock = Arc::clone(&state.clock);
    let mut node = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            let stored = stored_node(conn, node_id)?.ok_or_else(|| point_missing(&ctx, false))?;
            authorize_node_read(&ctx, &stored.target)?;
            Ok(conn
                .prepare_cached(&format!(
                    "SELECT {SUMMARY_COLUMNS} FROM nodes n WHERE n.node_id = ?1",
                ))?
                .query_row([node_id.to_string()], NodeSummary::from_row)?)
        })
        .await?;
    node.resolve_status(&state);
    Ok(Json(node))
}

#[utoipa::path(
    post, path = "/v1/nodes/{id}/revoke", tag = "Nodes",
    params(("id" = NodeId, Path)),
    security(("api_bearer" = [])),
    responses((status = 204), (status = 403, body = ProblemDetails, content_type = "application/problem+json"), (status = 404, body = ProblemDetails, content_type = "application/problem+json"))
)]
async fn revoke_node(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(node_id): ApiPath<NodeId>,
    _body: EmptyBody,
) -> ApiResult<StatusCode> {
    state
        .storage
        .execute_priority(PriorityKind::RevokeNode, move |tx| -> NodeWriteResult<()> {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            reject_narrowed_admin(&ctx).map_err(domain)?;
            let stored = stored_node(tx.conn(), node_id)?
                .ok_or_else(|| domain(point_missing(&ctx, true)))?;
            authorize_node_revoke_or_delete(&ctx, &stored.target).map_err(domain)?;
            let actor = ActorId::Principal(ctx.caller.principal_id);
            if let Some((node_id, epoch)) = tx.revoke_node(actor, node_id)? {
                tx.on_commit(move || {
                    state
                        .bridge
                        .close_session(node_id, epoch, BridgeCloseReason::NodeRevoked)
                });
            }
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete, path = "/v1/nodes/{id}", tag = "Nodes",
    params(("id" = NodeId, Path)),
    security(("api_bearer" = [])),
    responses((status = 204), (status = 403, body = ProblemDetails, content_type = "application/problem+json"),
              (status = 404, body = ProblemDetails, content_type = "application/problem+json"), (status = 409, body = ProblemDetails, content_type = "application/problem+json"))
)]
async fn delete_node(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(node_id): ApiPath<NodeId>,
    _body: EmptyBody,
) -> ApiResult<StatusCode> {
    state
        .storage
        .execute_work(0, move |tx| -> NodeWriteResult<()> {
            let conn = tx.conn();
            let ctx = refresh_api(conn, &caller.credential, tx.now_ms())?;
            reject_narrowed_admin(&ctx).map_err(domain)?;
            let stored =
                stored_node(conn, node_id)?.ok_or_else(|| domain(point_missing(&ctx, true)))?;
            authorize_node_revoke_or_delete(&ctx, &stored.target).map_err(domain)?;
            if stored.revoked_at_ms.is_none() || references::node_in_use(conn, node_id)? {
                return Err(domain(ApiError::conflict(error_codes::RESOURCE_IN_USE)));
            }
            conn.execute(
                "DELETE FROM nodes WHERE node_id = ?1",
                [node_id.to_string()],
            )?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn domain(error: impl Into<ApiError>) -> WriteTxError<ApiError> {
    WriteTxError::Domain(error.into())
}

#[cfg(test)]
mod tests;
