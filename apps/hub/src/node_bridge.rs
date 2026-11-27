//! Synchronous control surface for the node bridge.

use efferian_protocol::NodeId;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
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
    pub const fn code(self) -> u16 {
        match self {
            Self::Superseded => 4001,
            Self::NodeRevoked => 4003,
        }
    }
}

/// All methods are nonblocking. Close only sessions at or below the supplied epoch.
pub trait NodeBridgeControl: Send + Sync {
    fn live_status(&self, node_id: NodeId) -> NodeLiveStatus;
    fn online_nodes_count(&self) -> usize;
    fn close_session(&self, node_id: NodeId, through_epoch: u64, reason: BridgeCloseReason);
}

pub struct OfflineNodeBridge;

impl NodeBridgeControl for OfflineNodeBridge {
    fn live_status(&self, _: NodeId) -> NodeLiveStatus {
        NodeLiveStatus::Offline
    }

    fn online_nodes_count(&self) -> usize {
        0
    }

    fn close_session(&self, _: NodeId, _: u64, _: BridgeCloseReason) {}
}
