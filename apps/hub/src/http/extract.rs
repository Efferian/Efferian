use axum::Json;
use axum::body::Body;
use axum::extract::{
    FromRequest, FromRequestParts, Path, Query, Request, rejection::JsonRejection,
};
use efferian_protocol::{NodeId, error_codes as code};
use http::{
    HeaderMap, StatusCode,
    header::{CONTENT_LENGTH, TRANSFER_ENCODING},
    request::Parts,
};
use http_body_util::{BodyExt, Limited};
use hyper::body::Body as _;
use serde::de::DeserializeOwned;

use crate::vault::auth::{AuthenticatedApi, AuthenticatedEnrollment, VerifiedCredential};

use super::{ApiError, ApiResult};

pub const ENROLLMENT_LIMIT: usize = 16 * 1024;
pub const API_LIMIT: usize = 256 * 1024;
pub const MCP_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) struct BodyTier(pub usize);

#[derive(Clone)]
pub struct ApiCaller(pub AuthenticatedApi);

#[derive(Clone)]
pub struct EnrollmentCaller(pub AuthenticatedEnrollment);

#[derive(Clone)]
pub struct NodeCaller(
    #[allow(dead_code, reason = "node bridge handshake extractor seam for #7")]
    pub  VerifiedCredential<NodeId>,
);

macro_rules! extract_caller {
    ($name:ty) => {
        impl<S: Send + Sync> FromRequestParts<S> for $name {
            type Rejection = ApiError;

            async fn from_request_parts(parts: &mut Parts, _: &S) -> ApiResult<Self> {
                parts
                    .extensions
                    .remove::<Self>()
                    .ok_or_else(ApiError::internal)
            }
        }
    };
}

extract_caller!(ApiCaller);
extract_caller!(EnrollmentCaller);
extract_caller!(NodeCaller);

pub struct ApiPath<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> ApiResult<Self> {
        let Path(value) = Path::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::bad_input())?;
        Ok(Self(value))
    }
}

pub struct ApiQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> ApiResult<Self> {
        let Query(value) = Query::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::bad_input())?;
        Ok(Self(value))
    }
}

pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> ApiResult<Self> {
        declared_length(request.headers(), body_limit(&request))?;
        let Json(value) =
            Json::from_request(request, state)
                .await
                .map_err(|error| match error {
                    JsonRejection::MissingJsonContentType(_) => ApiError::new(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        code::UNSUPPORTED_MEDIA_TYPE,
                    ),
                    JsonRejection::BytesRejection(error)
                        if error.status() == StatusCode::PAYLOAD_TOO_LARGE =>
                    {
                        ApiError::too_large()
                    }
                    JsonRejection::BytesRejection(error) => ApiError::body_error(&error),
                    _ => ApiError::bad_input(),
                })?;
        Ok(Self(value))
    }
}

/// Reject a bodyless mutation as soon as the request declares or delivers bytes.
pub struct EmptyBody;

impl<S: Send + Sync> FromRequest<S> for EmptyBody {
    type Rejection = ApiError;

    async fn from_request(request: Request, _: &S) -> ApiResult<Self> {
        match declared_length(request.headers(), body_limit(&request))? {
            Some(0) => return Ok(Self),
            Some(_) => return Err(ApiError::bad_input()),
            None => {}
        }
        let mut body = request.into_body();
        while !body.is_end_stream() {
            let Some(frame) = body.frame().await else {
                break;
            };
            let frame = frame.map_err(|error| ApiError::body_error(&error))?;
            if frame.data_ref().is_some_and(|data| !data.is_empty()) {
                return Err(ApiError::bad_input());
            }
        }
        Ok(Self)
    }
}

fn body_limit(request: &Request) -> usize {
    request
        .extensions()
        .get::<BodyTier>()
        .map_or(API_LIMIT, |tier| tier.0)
}

pub(super) async fn buffer_mcp(request: Request) -> ApiResult<Request> {
    declared_length(request.headers(), MCP_LIMIT)?;
    let (parts, body) = request.into_parts();
    let collected = Limited::new(body, MCP_LIMIT)
        .collect()
        .await
        .map_err(|error| ApiError::body_error(error.as_ref()))?;
    Ok(Request::from_parts(parts, Body::from(collected.to_bytes())))
}

fn declared_length(headers: &HeaderMap, limit: usize) -> ApiResult<Option<u64>> {
    let Some(value) = super::single_header(headers, CONTENT_LENGTH)? else {
        return Ok(None);
    };
    if headers.contains_key(TRANSFER_ENCODING)
        || value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ApiError::bad_input());
    }
    let length = value.parse::<u64>().map_err(|_| ApiError::too_large())?;
    if length > limit as u64 {
        return Err(ApiError::too_large());
    }
    Ok(Some(length))
}
