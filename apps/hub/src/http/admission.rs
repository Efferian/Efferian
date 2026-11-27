use std::collections::{HashMap, hash_map::Entry};
use std::hash::Hash;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use axum::{
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use bytes::Bytes;
use efferian_protocol::{EnrollmentId, PrincipalId, error_codes};
use http::{Method, StatusCode};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::vault::auth::{
    ParsedBearer, authenticate_api, authenticate_enrollment, authenticate_node,
};

use super::extract::buffer_mcp;
use super::{ApiCaller, ApiError, ApiResult, AppState, EnrollmentCaller, NodeCaller};

const MAX_CONCURRENT_EXCHANGES_PER_ENROLLMENT: usize = 4;

pub(super) struct Admission {
    state: AppState,
    pre_auth: Arc<Semaphore>,
    control_pre_auth: Arc<Semaphore>,
    application: Arc<Semaphore>,
    control: Arc<Semaphore>,
    per_principal: Arc<SlotMap<PrincipalId>>,
    per_enrollment: Arc<SlotMap<EnrollmentId>>,
    event_streams: Arc<Semaphore>,
    streams_per_principal: Arc<SlotMap<PrincipalId>>,
}

impl Admission {
    pub fn new(state: AppState) -> Arc<Self> {
        let config = &state.config;
        Arc::new(Self {
            pre_auth: Arc::new(Semaphore::new(config.max_pre_auth_in_flight)),
            control_pre_auth: Arc::new(Semaphore::new(config.max_control_requests)),
            application: Arc::new(Semaphore::new(config.max_app_requests)),
            control: Arc::new(Semaphore::new(config.max_control_requests)),
            per_principal: Arc::new(SlotMap::new(config.max_requests_per_principal)),
            per_enrollment: Arc::new(SlotMap::new(MAX_CONCURRENT_EXCHANGES_PER_ENROLLMENT)),
            event_streams: Arc::new(Semaphore::new(config.max_event_streams)),
            streams_per_principal: Arc::new(SlotMap::new(config.max_event_streams_per_principal)),
            state,
        })
    }

    fn acquire(semaphore: &Arc<Semaphore>) -> ApiResult<OwnedSemaphorePermit> {
        Arc::clone(semaphore)
            .try_acquire_owned()
            .map_err(|_| ApiError::overloaded())
    }
}

#[derive(Clone, Copy)]
pub(super) enum ApiLane {
    Application,
    Control,
    EventStream,
    Mcp,
}

pub(super) async fn api(
    State((admission, lane)): State<(Arc<Admission>, ApiLane)>,
    mut request: Request,
    next: Next,
) -> ApiResult<Response> {
    let pre_auth = if matches!(lane, ApiLane::Control) {
        Admission::acquire(&admission.control_pre_auth)?
    } else {
        Admission::acquire(&admission.pre_auth)?
    };
    let bearer = ParsedBearer::from_headers(request.headers())?;
    let clock = Arc::clone(&admission.state.clock);
    let vault = Arc::clone(&admission.state.vault);
    let authenticated = if matches!(lane, ApiLane::Control) {
        admission
            .state
            .storage
            .read_control_snapshot(move |conn| {
                // Keep the slot even if the HTTP request disappears while SQLite is running.
                let _permit = pre_auth;
                authenticate_api(&vault, conn, bearer, clock.wall_now_ms())
            })
            .await?
    } else {
        admission
            .state
            .storage
            .read_snapshot(move |conn| {
                let _permit = pre_auth;
                authenticate_api(&vault, conn, bearer, clock.wall_now_ms())
            })
            .await?
    };
    let principal_id = authenticated.principal_id;
    request.extensions_mut().insert(ApiCaller(authenticated));

    if matches!(lane, ApiLane::Control) {
        let permit = Admission::acquire(&admission.control)?;
        return Ok(attach_permit(next.run(request).await, permit));
    }
    if matches!(lane, ApiLane::EventStream) {
        let exhausted =
            |_| ApiError::new(StatusCode::TOO_MANY_REQUESTS, error_codes::OVERLOADED).retryable();
        let global = Admission::acquire(&admission.event_streams).map_err(exhausted)?;
        let principal = admission
            .streams_per_principal
            .reserve(principal_id)
            .map_err(exhausted)?;
        return Ok(attach_permit(next.run(request).await, (global, principal)));
    }
    let application = Admission::acquire(&admission.application)?;
    let principal = admission.per_principal.reserve(principal_id)?;
    if matches!(lane, ApiLane::Mcp) && request.method() == Method::POST {
        request = buffer_mcp(request).await?;
    }
    Ok(attach_permit(
        next.run(request).await,
        (application, principal),
    ))
}

pub(super) async fn enrollment(
    State(admission): State<Arc<Admission>>,
    mut request: Request,
    next: Next,
) -> ApiResult<Response> {
    let pre_auth = Admission::acquire(&admission.pre_auth)?;
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
    let enrollment_permit = admission
        .per_enrollment
        .reserve(authenticated.credential.id())?;
    let application = Admission::acquire(&admission.application)?;
    request
        .extensions_mut()
        .insert(EnrollmentCaller(authenticated));
    Ok(attach_permit(
        next.run(request).await,
        (application, enrollment_permit),
    ))
}

pub(super) async fn node(
    State(admission): State<Arc<Admission>>,
    mut request: Request,
    next: Next,
) -> ApiResult<Response> {
    let pre_auth = Admission::acquire(&admission.pre_auth)?;
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

fn attach_permit<P: Send + Unpin + 'static>(response: Response, permit: P) -> Response {
    response.map(|inner| {
        Body::new(PermitBody {
            inner,
            permit: Some(permit),
        })
    })
}

struct PermitBody<P> {
    inner: Body,
    permit: Option<P>,
}

impl<P: Send + Unpin + 'static> HttpBody for PermitBody<P> {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let body = self.get_mut();
        let frame = Pin::new(&mut body.inner).poll_frame(cx);
        if matches!(frame, Poll::Ready(None | Some(Err(_)))) || body.inner.is_end_stream() {
            body.permit.take();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

struct SlotMap<K> {
    limit: usize,
    slots: Mutex<HashMap<K, usize>>,
}

impl<K: Copy + Eq + Hash> SlotMap<K> {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            slots: Mutex::default(),
        }
    }

    fn reserve(self: &Arc<Self>, key: K) -> ApiResult<SlotPermit<K>> {
        let mut slots = self.counts();
        let count = slots.entry(key).or_default();
        if *count == self.limit {
            return Err(ApiError::overloaded());
        }
        *count += 1;
        Ok(SlotPermit {
            slots: Arc::clone(self),
            key,
        })
    }

    fn counts(&self) -> MutexGuard<'_, HashMap<K, usize>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct SlotPermit<K: Copy + Eq + Hash> {
    slots: Arc<SlotMap<K>>,
    key: K,
}

impl<K: Copy + Eq + Hash> Drop for SlotPermit<K> {
    fn drop(&mut self) {
        let mut slots = self.slots.counts();
        if let Entry::Occupied(mut count) = slots.entry(self.key) {
            if *count.get() == 1 {
                count.remove();
            } else {
                *count.get_mut() -= 1;
            }
        }
    }
}
