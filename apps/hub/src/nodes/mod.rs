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
    ApiCaller, ApiError, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody, OperatorScope, Page,
    PageQuery, RouteGroups, point_missing, require_unrestricted_operator,
};
use crate::node_bridge::{BridgeCloseReason, NodeLiveStatus};
use crate::storage::{PriorityKind, WriteTxError, id, json, opt_id, optional_scalar};
use crate::vault::auth::refresh_api;

type NodeWriteResult<T> = Result<T, WriteTxError<ApiError>>;

// Charge catalog reference checks in the work batch budget so delete_node does
// not stack 32 full scans into a single DbActor transaction.
const DELETE_NODE_WORK_BYTES: usize = 256 * 1024;

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

macro_rules! select_node_summary {
    ($clause:literal) => {
        concat!(
            "SELECT n.node_id, n.name, n.tags_json, n.managed_by_principal_id, ",
            "n.revoked_at_ms, n.platform_os, n.platform_arch, n.allowed_cwd_roots_json, ",
            "n.max_concurrent_executions, n.last_connected_at_ms, n.last_disconnected_at_ms, ",
            "n.created_at_ms, n.updated_at_ms FROM nodes n ",
            $clause
        )
    };
}

impl NodeSummary {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            node_id: id(row, 0)?,
            name: row.get(1)?,
            tags: json(row, 2)?,
            managed_by_principal_id: opt_id(row, 3)?,
            revoked_at_ms: row.get(4)?,
            platform_os: optional_scalar(row, 5)?,
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
    responses((status = 200, description = "Visible nodes page", body = Page<NodeSummary>))
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
            if ctx.token.allowed_nodes.as_ref().is_some_and(std::collections::BTreeSet::is_empty) {
                return Ok(Vec::new());
            }

            let cursor = cursor.as_deref().unwrap_or_default();
            let fetch_limit = limit + 1;
            let rows = if admin {
                // Unrestricted global admin always has allowed_nodes == None.
                let mut statement = conn.prepare_cached(select_node_summary!(
                    "WHERE n.node_id COLLATE BINARY > ?1 ORDER BY n.node_id COLLATE BINARY ASC LIMIT ?2"
                ))?;
                statement
                    .query_map(params![cursor, fetch_limit], NodeSummary::from_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            } else if let Some(allowed) = &ctx.token.allowed_nodes {
                let scope = serde_json::to_string(allowed).map_err(|_| ApiError::internal())?;
                let mut statement = conn.prepare_cached(select_node_summary!(
                    "WHERE n.managed_by_principal_id = ?1 \
                       AND n.node_id IN (SELECT value FROM json_each(?2)) \
                       AND n.node_id COLLATE BINARY > ?3 \
                     ORDER BY n.node_id COLLATE BINARY ASC LIMIT ?4"
                ))?;
                statement
                    .query_map(
                        params![
                            ctx.caller.principal_id.to_string(),
                            scope,
                            cursor,
                            fetch_limit
                        ],
                        NodeSummary::from_row,
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            } else {
                let mut statement = conn.prepare_cached(select_node_summary!(
                    "WHERE n.managed_by_principal_id = ?1 \
                       AND n.node_id COLLATE BINARY > ?2 \
                     ORDER BY n.node_id COLLATE BINARY ASC LIMIT ?3"
                ))?;
                statement
                    .query_map(
                        params![ctx.caller.principal_id.to_string(), cursor, fetch_limit],
                        NodeSummary::from_row,
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
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
    params(("id" = NodeId, Path, description = "Node ID")),
    security(("api_bearer" = [])),
    responses(
        (status = 200, description = "Node metadata and live status", body = NodeSummary),
        (status = 404, description = "Node does not exist", body = ProblemDetails, content_type = "application/problem+json")
    )
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
            let node = conn
                .prepare_cached(select_node_summary!("WHERE n.node_id = ?1"))?
                .query_row([node_id.to_string()], NodeSummary::from_row)
                .optional()?
                .ok_or_else(|| point_missing(&ctx, false))?;
            authorize_node_read(&ctx, &node.auth_target())?;
            Ok(node)
        })
        .await?;
    node.resolve_status(&state);
    Ok(Json(node))
}

#[utoipa::path(
    post, path = "/v1/nodes/{id}/revoke", tag = "Nodes",
    params(("id" = NodeId, Path, description = "Node ID")),
    security(("api_bearer" = [])),
    responses(
        (status = 204, description = "Node revoked"),
        (status = 404, description = "Node does not exist", body = ProblemDetails, content_type = "application/problem+json")
    )
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
            require_unrestricted_operator(&ctx, OperatorScope::NodeOperator)?;
            let stored =
                stored_node(tx.conn(), node_id)?.ok_or_else(|| point_missing(&ctx, true))?;
            authorize_node_revoke_or_delete(&ctx, &stored.target)?;
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
    params(("id" = NodeId, Path, description = "Node ID")),
    security(("api_bearer" = [])),
    responses(
        (status = 204, description = "Node deleted"),
        (status = 404, description = "Node does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Node is active or still referenced", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_node(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(node_id): ApiPath<NodeId>,
    _body: EmptyBody,
) -> ApiResult<StatusCode> {
    // Reject active or still-referenced nodes on the read pool before entering
    // the single-writer DbActor so repeated 409 retries cannot stall Hub writes.
    let clock = Arc::clone(&state.clock);
    let caller = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            require_unrestricted_operator(&ctx, OperatorScope::NodeOperator)?;
            let stored = stored_node(conn, node_id)?.ok_or_else(|| point_missing(&ctx, true))?;
            authorize_node_revoke_or_delete(&ctx, &stored.target)?;
            if stored.revoked_at_ms.is_none() || references::node_in_use_ro(conn, node_id)? {
                return Err(ApiError::conflict(error_codes::RESOURCE_IN_USE));
            }
            Ok(caller)
        })
        .await?;

    state
        .storage
        .execute_work(DELETE_NODE_WORK_BYTES, move |tx| -> NodeWriteResult<()> {
            let conn = tx.conn();
            let ctx = refresh_api(conn, &caller.credential, tx.now_ms())?;
            require_unrestricted_operator(&ctx, OperatorScope::NodeOperator)?;
            let stored = stored_node(conn, node_id)?.ok_or_else(|| point_missing(&ctx, true))?;
            authorize_node_revoke_or_delete(&ctx, &stored.target)?;
            if stored.revoked_at_ms.is_none() || references::node_in_use(conn, node_id)? {
                return Err(ApiError::conflict(error_codes::RESOURCE_IN_USE).into());
            }
            conn.prepare_cached("DELETE FROM nodes WHERE node_id = ?1")?
                .execute([node_id.to_string()])?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
