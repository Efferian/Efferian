use std::collections::{HashMap, hash_map::Entry};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use efferian_protocol::PrincipalId;
use http::Method;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::vault::auth::{
    ParsedBearer, authenticate_api, authenticate_enrollment, authenticate_node,
};

use super::extract::buffer_mcp;
use super::{ApiCaller, ApiError, ApiResult, AppState, EnrollmentCaller, NodeCaller};

pub(super) struct Admission {
    state: AppState,
    pre_auth: Arc<Semaphore>,
    application: Semaphore,
    control: Semaphore,
    per_principal: Arc<PrincipalSlots>,
}

impl Admission {
    pub fn new(state: AppState) -> Arc<Self> {
        let config = &state.config;
        Arc::new(Self {
            pre_auth: Arc::new(Semaphore::new(config.max_pre_auth_in_flight)),
            application: Semaphore::new(config.max_app_requests),
            control: Semaphore::new(config.max_control_requests),
            per_principal: Arc::new(PrincipalSlots {
                limit: config.max_requests_per_principal,
                slots: Mutex::default(),
            }),
            state,
        })
    }

    fn pre_auth_permit(&self) -> ApiResult<OwnedSemaphorePermit> {
        Arc::clone(&self.pre_auth)
            .try_acquire_owned()
            .map_err(|_| ApiError::overloaded())
    }
}

#[derive(Clone, Copy)]
pub(super) enum ApiLane {
    Application,
    Control,
    Mcp,
}

pub(super) async fn api(
    State((admission, lane)): State<(Arc<Admission>, ApiLane)>,
    mut request: Request,
    next: Next,
) -> ApiResult<Response> {
    let pre_auth = admission.pre_auth_permit()?;
    let bearer = ParsedBearer::from_headers(request.headers())?;
    let clock = Arc::clone(&admission.state.clock);
    let vault = Arc::clone(&admission.state.vault);
    let authenticated = admission
        .state
        .storage
        .read_snapshot(move |conn| {
            // Keep the slot even if the HTTP request disappears while SQLite is running.
            let _permit = pre_auth;
            authenticate_api(&vault, conn, bearer, clock.wall_now_ms())
        })
        .await?;
    let principal_id = authenticated.principal_id;
    request.extensions_mut().insert(ApiCaller(authenticated));

    if matches!(lane, ApiLane::Control) {
        let _permit = admission
            .control
            .try_acquire()
            .map_err(|_| ApiError::overloaded())?;
        return Ok(next.run(request).await);
    }
    let _application = admission
        .application
        .try_acquire()
        .map_err(|_| ApiError::overloaded())?;
    let _principal = admission.per_principal.reserve(principal_id)?;
    if matches!(lane, ApiLane::Mcp) && request.method() == Method::POST {
        request = buffer_mcp(request).await?;
    }
    Ok(next.run(request).await)
}

pub(super) async fn enrollment(
    State(admission): State<Arc<Admission>>,
    mut request: Request,
    next: Next,
) -> ApiResult<Response> {
    let pre_auth = admission.pre_auth_permit()?;
    let bearer = ParsedBearer::from_headers(request.headers())?;
    let clock = Arc::clone(&admission.state.clock);
    let vault = Arc::clone(&admission.state.vault);
    let authenticated = admission
        .state
        .storage
        .read_snapshot(move |conn| {
            let _permit = pre_auth;
            authenticate_enrollment(&vault, conn, bearer, clock.wall_now_ms())
        })
        .await?;
    let _application = admission
        .application
        .try_acquire()
        .map_err(|_| ApiError::overloaded())?;
    request
        .extensions_mut()
        .insert(EnrollmentCaller(authenticated));
    Ok(next.run(request).await)
}

pub(super) async fn node(
    State(admission): State<Arc<Admission>>,
    mut request: Request,
    next: Next,
) -> ApiResult<Response> {
    let pre_auth = admission.pre_auth_permit()?;
    let bearer = ParsedBearer::from_headers(request.headers())?;
    let vault = Arc::clone(&admission.state.vault);
    let authenticated = admission
        .state
        .storage
        .read_snapshot(move |conn| {
            let _permit = pre_auth;
            authenticate_node(&vault, conn, bearer)
        })
        .await?;
    request.extensions_mut().insert(NodeCaller(authenticated));
    Ok(next.run(request).await)
}

struct PrincipalSlots {
    limit: usize,
    slots: Mutex<HashMap<PrincipalId, usize>>,
}

impl PrincipalSlots {
    fn reserve(self: &Arc<Self>, principal_id: PrincipalId) -> ApiResult<PrincipalPermit> {
        let mut slots = self.counts();
        let count = slots.entry(principal_id).or_default();
        if *count == self.limit {
            return Err(ApiError::overloaded());
        }
        *count += 1;
        Ok(PrincipalPermit {
            slots: Arc::clone(self),
            principal_id,
        })
    }

    fn counts(&self) -> MutexGuard<'_, HashMap<PrincipalId, usize>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct PrincipalPermit {
    slots: Arc<PrincipalSlots>,
    principal_id: PrincipalId,
}

impl Drop for PrincipalPermit {
    fn drop(&mut self) {
        let mut slots = self.slots.counts();
        if let Entry::Occupied(mut count) = slots.entry(self.principal_id) {
            if *count.get() == 1 {
                count.remove();
            } else {
                *count.get_mut() -= 1;
            }
        }
    }
}
