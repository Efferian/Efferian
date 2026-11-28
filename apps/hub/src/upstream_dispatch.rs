//! The Hub's boundary for external MCP discovery and execution.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

pub(crate) use crate::execution::state::UpstreamCancellation;
use bytes::Bytes;
use efferian_protocol::{
    AccountId, DiscoveredUpstreamTool, ExecutionId, HttpAuthSecret, PrincipalId, UpstreamId,
};
use serde_json::{Map, Value};

pub(crate) type DispatchFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[allow(
    dead_code,
    reason = "transport keys sessions by account and secret version"
)]
pub(crate) struct UpstreamCredential {
    pub account_id: AccountId,
    pub secret_version: u64,
    pub secret: HttpAuthSecret,
}

#[allow(
    dead_code,
    reason = "transport consumes the request in a separate implementation"
)]
pub(crate) struct DiscoverUpstream {
    pub upstream_id: UpstreamId,
    pub config_version: u64,
    pub principal_id: PrincipalId,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub auth: Option<UpstreamCredential>,
}

#[allow(
    dead_code,
    reason = "transport consumes the request in a separate implementation"
)]
pub(crate) struct InvokeUpstream {
    pub execution_id: ExecutionId,
    pub upstream_id: UpstreamId,
    pub config_version: u64,
    pub principal_id: PrincipalId,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub auth: Option<UpstreamCredential>,
    pub tool_name: String,
    pub arguments: Map<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "transport reports typed failures after it connects"
)]
pub(crate) enum UpstreamDispatchError {
    Unavailable,
    TimedOut,
    AuthFailed,
    InvalidResponse,
    Disconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UpstreamInvalidation {
    Upstream(UpstreamId),
    Account(AccountId),
    Binding {
        principal_id: PrincipalId,
        upstream_id: UpstreamId,
    },
    Principal(PrincipalId),
}

/// Cancellation and invalidation must return promptly on the SQLite writer thread.
pub(crate) trait UpstreamDispatcher: Send + Sync {
    fn discover(
        &self,
        _request: DiscoverUpstream,
    ) -> DispatchFuture<'_, Result<Vec<DiscoveredUpstreamTool>, UpstreamDispatchError>> {
        Box::pin(async { Err(UpstreamDispatchError::Unavailable) })
    }

    /// Returns the bounded JSON value of the corresponding MCP result.
    ///
    /// Check `cancellation.is_cancelled()` before submitting the first wire
    /// request and observe `cancellation.cancelled().await` while awaiting I/O
    /// so this execution stops promptly without interrupting unrelated pooled
    /// requests.
    fn invoke(
        &self,
        _request: InvokeUpstream,
        _cancellation: UpstreamCancellation,
    ) -> DispatchFuture<'_, Result<Bytes, UpstreamDispatchError>> {
        Box::pin(async { Err(UpstreamDispatchError::Unavailable) })
    }

    fn cancel(&self, _execution_id: ExecutionId) {}

    fn pool_connections_count(&self) -> usize {
        0
    }

    fn invalidate(&self, _invalidation: UpstreamInvalidation) {}

    fn shutdown(&self) -> DispatchFuture<'_, ()> {
        Box::pin(async {})
    }
}

pub(crate) struct OfflineUpstreamDispatcher;

impl UpstreamDispatcher for OfflineUpstreamDispatcher {}
