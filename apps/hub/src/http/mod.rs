//! HTTP authorization, admission and wire framing for the Hub API.

mod admission;
mod error;
mod extract;
mod headers;
mod system;

use std::sync::Arc;

use axum::{Extension, Router, extract::DefaultBodyLimit, middleware::from_fn_with_state};
use bytes::Bytes;
use efferian_authz::{AuthContext, AuthzError, authorize_admin};
use efferian_protocol::{PrincipalKind, error_codes as code};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
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
#[cfg(test)]
pub use extract::MCP_LIMIT;
pub use extract::{
    API_LIMIT, ApiCaller, ApiJson, ApiPath, ApiQuery, ENROLLMENT_LIMIT, EmptyBody,
    EnrollmentCaller, NodeCaller,
};

#[derive(Clone)]
pub struct AppState {
    pub storage: StorageHandle,
    pub vault: Arc<Vault>,
    pub clock: Arc<dyn StorageClock>,
    pub config: Arc<Config>,
    pub bridge: Arc<dyn NodeBridgeControl>,
    #[allow(dead_code, reason = "upstream HTTP egress seam for #6/#8")]
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

#[derive(Clone, Copy)]
pub(crate) enum OperatorScope {
    /// Global admin, Member, or Orchestrator (principal, token-revoke, and profile-grant mutations).
    SubjectOperator,
    /// Global admin or Member (non-orchestrator token mint; orchestrator may use a narrowed token).
    TokenMint,
    /// Global admin or Orchestrator (node revoke and delete).
    NodeOperator,
}

/// Reject narrowed tokens or ineligible roles before loading a target row so
/// callers cannot distinguish hidden owned resources from foreign or missing IDs.
pub(crate) fn require_unrestricted_operator(
    ctx: &AuthContext,
    scope: OperatorScope,
) -> ApiResult<()> {
    match authorize_admin(ctx) {
        Ok(()) => return Ok(()),
        Err(error @ AuthzError::UnrestrictedTokenRequired) => return Err(error.into()),
        Err(_) => {}
    }
    let eligible = match scope {
        OperatorScope::SubjectOperator => {
            ctx.caller.kind == PrincipalKind::Member || ctx.caller.is_orchestrator
        }
        OperatorScope::TokenMint => {
            if ctx.caller.is_orchestrator {
                return Ok(());
            }
            ctx.caller.kind == PrincipalKind::Member
        }
        OperatorScope::NodeOperator => ctx.caller.is_orchestrator,
    };
    if !eligible {
        return Err(ApiError::forbidden());
    }
    if !ctx.token.is_unrestricted() {
        return Err(AuthzError::UnrestrictedTokenRequired.into());
    }
    Ok(())
}

fn production_routes() -> RouteGroups {
    system::admin_routes()
        .merge(crate::principals::routes())
        .merge(crate::grants_tokens::routes())
        .merge(crate::nodes::routes())
}

pub fn openapi_doc() -> utoipa::openapi::OpenApi {
    let routes = production_routes();
    let (_, mut doc) = system::routes()
        .merge(routes.application)
        .merge(routes.control)
        .merge(routes.enrollment_api)
        .merge(routes.enrollment_exchange)
        .merge(routes.node_handshake)
        .merge(routes.mcp)
        .split_for_parts();
    system::document_boundary_errors(&mut doc);
    doc
}

pub fn openapi_bytes() -> Result<Bytes, serde_json::Error> {
    system::build_openapi_bytes(&openapi_doc())
}

pub fn router(state: AppState, bound_port: u16) -> Result<Router, serde_json::Error> {
    assemble(state, bound_port, production_routes())
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
    let artifact = Arc::new(system::OpenApiArtifact::build(&doc)?);
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
