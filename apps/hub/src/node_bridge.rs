//! The Hub's control and dispatch boundary for the node bridge.

use axum::extract::{
    State,
    ws::{WebSocketUpgrade, rejection::WebSocketUpgradeRejection},
};
use axum::response::{IntoResponse, Response};
use efferian_protocol::{
    BRIDGE_CLOSE_NODE_REVOKED, BRIDGE_CLOSE_SUPERSEDED, CancelReqPayload, ExecuteReqPayload,
    NodeId, ProblemDetails, error_codes,
};
use http::{
    HeaderValue, StatusCode,
    header::{SEC_WEBSOCKET_VERSION, UPGRADE},
};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::http::{ApiError, ApiResult, AppState, NodeCaller, RouteGroups};
use crate::upstream_dispatch::DispatchFuture;
use crate::vault::auth::VerifiedCredential;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[allow(
    dead_code,
    reason = "Syncing and Ready variants are constructed by #7 bridge"
)]
pub enum NodeLiveStatus {
    Offline,
    Syncing,
    Ready,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeCloseReason {
    Superseded,
    NodeRevoked,
}

impl BridgeCloseReason {
    #[allow(dead_code, reason = "WebSocket close code seam for #7")]
    pub const fn code(self) -> u16 {
        match self {
            Self::Superseded => BRIDGE_CLOSE_SUPERSEDED,
            Self::NodeRevoked => BRIDGE_CLOSE_NODE_REVOKED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadyNode {
    pub epoch: u64,
    pub max_concurrent_executions: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "a connected transport can report a full queue")]
pub(crate) enum NodeSendError {
    Full,
    Closed,
}

/// Synchronous methods must return promptly. Close only sessions at or below
/// the supplied epoch, and send work only to the expected ready session.
pub(crate) trait NodeDispatcher: Send + Sync {
    fn live_status(&self, node_id: NodeId) -> NodeLiveStatus;
    fn online_nodes_count(&self) -> usize;
    fn close_session(&self, node_id: NodeId, through_epoch: u64, reason: BridgeCloseReason);

    fn ready_node(&self, _node_id: NodeId) -> Option<ReadyNode> {
        None
    }

    fn try_send_execute(
        &self,
        _node_id: NodeId,
        _epoch: u64,
        _request: ExecuteReqPayload,
    ) -> Result<(), NodeSendError> {
        Err(NodeSendError::Closed)
    }

    fn try_send_cancel(
        &self,
        _node_id: NodeId,
        _epoch: u64,
        _request: CancelReqPayload,
    ) -> Result<(), NodeSendError> {
        Err(NodeSendError::Closed)
    }

    fn connect(
        &self,
        _credential: VerifiedCredential<NodeId>,
        _upgrade: WebSocketUpgrade,
    ) -> DispatchFuture<'_, ApiResult<Response>> {
        Box::pin(async { Err(ApiError::overloaded()) })
    }

    /// Signal shutdown immediately. A failed writer precludes waiting for receipt flush.
    fn shutdown_graceful(&self, _writer_healthy: bool) -> DispatchFuture<'_, ()> {
        Box::pin(async {})
    }
}

pub struct OfflineNodeBridge;

impl NodeDispatcher for OfflineNodeBridge {
    fn live_status(&self, _: NodeId) -> NodeLiveStatus {
        NodeLiveStatus::Offline
    }

    fn online_nodes_count(&self) -> usize {
        0
    }

    fn close_session(&self, _: NodeId, _: u64, _: BridgeCloseReason) {}
}

pub(crate) fn routes() -> RouteGroups {
    RouteGroups {
        node_handshake: OpenApiRouter::new().routes(routes!(connect)),
        ..RouteGroups::default()
    }
}

#[utoipa::path(
    get,
    path = "/v1/bridge/connect",
    tag = "Nodes",
    security(("node_bearer" = [])),
    responses(
        (status = 101, description = "Bridge WebSocket upgrade",
            headers(("Upgrade" = String, description = "websocket"),
                    ("Connection" = String, description = "Upgrade"),
                    ("Sec-WebSocket-Accept" = String, description = "WebSocket acceptance value"))),
        (status = 400, description = "Invalid WebSocket headers", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 426, description = "A WebSocket upgrade is required", body = ProblemDetails, content_type = "application/problem+json",
            headers(("Upgrade" = String, description = "websocket"),
                    ("Sec-WebSocket-Version" = String, description = "Supported WebSocket version"))),
        (status = 429, description = "Node reconnect rate limited", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The bridge cannot admit the handshake", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn connect(
    State(state): State<AppState>,
    NodeCaller(credential): NodeCaller,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> ApiResult<Response> {
    let upgrade = match upgrade {
        Ok(upgrade) => upgrade,
        Err(rejection) => {
            // Match the handshake contract before the bridge sees a request.
            let status = rejection.into_response().status();
            if status == StatusCode::UPGRADE_REQUIRED {
                let mut response =
                    ApiError::new(status, error_codes::INVALID_INPUT).into_response();
                response
                    .headers_mut()
                    .insert(UPGRADE, HeaderValue::from_static("websocket"));
                response
                    .headers_mut()
                    .insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
                return Ok(response);
            }
            return Err(ApiError::bad_input());
        }
    };
    state.bridge.connect(credential, upgrade).await
}
