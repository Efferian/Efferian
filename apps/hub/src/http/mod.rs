//! HTTP authorization, admission and wire framing for the Hub API.

mod admission;
mod error;
mod extract;
mod headers;
mod system;

use std::sync::{Arc, OnceLock};

use axum::{Extension, Router, extract::DefaultBodyLimit, middleware::from_fn_with_state};
use efferian_protocol::error_codes as code;
use http::StatusCode;
use utoipa_axum::router::OpenApiRouter;

use crate::{
    config::Config,
    egress::EgressClient,
    node_bridge::NodeBridgeControl,
    storage::{StorageClock, StorageHandle},
    vault::Vault,
};

use admission::{Admission, ApiLane};
use extract::BodyTier;
use headers::{HeaderPolicy, single_header};

pub use error::{ApiError, ApiResult};
pub use extract::{
    API_LIMIT, ApiCaller, ApiJson, ApiPath, ApiQuery, ENROLLMENT_LIMIT, EmptyBody,
    EnrollmentCaller, MCP_LIMIT, NodeCaller,
};
pub use system::build_openapi_bytes;

#[derive(Clone)]
pub struct AppState {
    pub storage: StorageHandle,
    pub vault: Arc<Vault>,
    pub clock: Arc<dyn StorageClock>,
    pub config: Arc<Config>,
    pub bridge: Arc<dyn NodeBridgeControl>,
    pub egress: EgressClient,
}

#[derive(Default)]
pub(crate) struct RouteGroups {
    pub application: OpenApiRouter<AppState>,
    pub control: OpenApiRouter<AppState>,
    pub enrollment_api: OpenApiRouter<AppState>,
    pub enrollment_exchange: OpenApiRouter<AppState>,
    pub node_handshake: OpenApiRouter<AppState>,
    pub mcp: OpenApiRouter<AppState>,
}

impl RouteGroups {
    pub(crate) fn merge(self, other: Self) -> Self {
        Self {
            application: self.application.merge(other.application),
            control: self.control.merge(other.control),
            enrollment_api: self.enrollment_api.merge(other.enrollment_api),
            enrollment_exchange: self.enrollment_exchange.merge(other.enrollment_exchange),
            node_handshake: self.node_handshake.merge(other.node_handshake),
            mcp: self.mcp.merge(other.mcp),
        }
    }
}

pub fn router(state: AppState, bound_port: u16) -> Result<Router, serde_json::Error> {
    let groups = crate::principals::routes()
        .merge(crate::grants_tokens::routes())
        .merge(crate::nodes::routes());
    assemble(state, bound_port, groups)
}

fn assemble(
    state: AppState,
    bound_port: u16,
    routes: RouteGroups,
) -> Result<Router, serde_json::Error> {
    let policy = Arc::new(HeaderPolicy {
        hub_id: *state.storage.hub_id(),
        allowed_hosts: state.config.allowed_hosts_for_port(bound_port),
        allowed_origins: state.config.allowed_origins.clone(),
    });
    let admission = Admission::new(state.clone());

    let application = limited(routes.application, API_LIMIT).layer(from_fn_with_state(
        (Arc::clone(&admission), ApiLane::Application),
        admission::api,
    ));
    let control = limited(routes.control, API_LIMIT).layer(from_fn_with_state(
        (Arc::clone(&admission), ApiLane::Control),
        admission::api,
    ));
    let enrollment_api =
        limited(routes.enrollment_api, ENROLLMENT_LIMIT).layer(from_fn_with_state(
            (Arc::clone(&admission), ApiLane::Application),
            admission::api,
        ));
    let enrollment_exchange = limited(routes.enrollment_exchange, ENROLLMENT_LIMIT).layer(
        from_fn_with_state(Arc::clone(&admission), admission::enrollment),
    );
    let node_handshake = routes
        .node_handshake
        .layer(from_fn_with_state(Arc::clone(&admission), admission::node));
    let mcp = routes.mcp.layer(from_fn_with_state(
        (admission, ApiLane::Mcp),
        admission::api,
    ));

    let (router, mut doc) = system::routes()
        .merge(application)
        .merge(control)
        .merge(enrollment_api)
        .merge(enrollment_exchange)
        .merge(node_handshake)
        .merge(mcp)
        .split_for_parts();

    system::document_boundary_errors(&mut doc);
    let artifact = Arc::new(OnceLock::from(system::OpenApiArtifact::build(&doc)?));
    Ok(router
        .fallback(|| async { ApiError::not_found() })
        .method_not_allowed_fallback(|| async {
            ApiError::new(StatusCode::METHOD_NOT_ALLOWED, code::METHOD_NOT_ALLOWED)
        })
        .layer(Extension(artifact))
        .layer(from_fn_with_state(policy, headers::guard))
        .with_state(state))
}

fn limited(router: OpenApiRouter<AppState>, bytes: usize) -> OpenApiRouter<AppState> {
    router
        .layer(DefaultBodyLimit::max(bytes))
        .layer(Extension(BodyTier(bytes)))
}

#[cfg(test)]
mod tests;
