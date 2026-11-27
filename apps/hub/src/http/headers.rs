use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use efferian_protocol::{HubId, error_codes as code};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
    header::{CACHE_CONTROL, HOST, ORIGIN},
};

use crate::config::{Authority, Origin};

use super::{ApiError, ApiResult};

const HUB_HEADER: HeaderName = HeaderName::from_static("x-efferian-hub");
const NO_BUFFERING: HeaderName = HeaderName::from_static("x-accel-buffering");

pub(super) struct HeaderPolicy {
    pub hub_id: HubId,
    pub allowed_hosts: Vec<Authority>,
    pub allowed_origins: Vec<Origin>,
}

pub(super) async fn guard(
    State(policy): State<Arc<HeaderPolicy>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let no_buffering = path == "/v1/events/stream" || path.starts_with("/mcp/");
    let mut response = match policy.verify(&request) {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if no_buffering {
        response
            .headers_mut()
            .insert(NO_BUFFERING, HeaderValue::from_static("no"));
    }
    response
}

impl HeaderPolicy {
    fn verify(&self, request: &Request) -> ApiResult<()> {
        let headers = request.headers();
        let host: Authority = single_header(headers, HOST)?
            .ok_or_else(ApiError::bad_input)?
            .parse()
            .map_err(|_| ApiError::bad_input())?;
        if let Some(authority) = request.uri().authority() {
            let uri_host = authority
                .as_str()
                .parse()
                .map_err(|_| ApiError::bad_input())?;
            if host != uri_host {
                return Err(ApiError::bad_input());
            }
        }
        let health_probe = request.method() == Method::GET && request.uri().path() == "/v1/health";
        if !health_probe && !self.allowed_hosts.contains(&host) {
            return Err(ApiError::forbidden());
        }

        if let Some(origin) = single_header(headers, ORIGIN)? {
            if origin == "null" {
                return Err(ApiError::forbidden());
            }
            let origin = origin.parse().map_err(|_| ApiError::bad_input())?;
            if !self.allowed_origins.contains(&origin) {
                return Err(ApiError::forbidden());
            }
        }

        if let Some(raw) = single_header(headers, HUB_HEADER)? {
            let hub_id = HubId::parse(raw).map_err(|_| ApiError::bad_input())?;
            if hub_id != self.hub_id {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    code::HUB_IDENTITY_MISMATCH,
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn single_header(headers: &HeaderMap, name: HeaderName) -> ApiResult<Option<&str>> {
    let values = headers.get_all(name);
    let mut values = values.iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ApiError::bad_input());
    }
    value.to_str().map(Some).map_err(|_| ApiError::bad_input())
}
