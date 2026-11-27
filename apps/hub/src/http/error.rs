use std::error::Error;

use axum::Json;
use axum::response::{IntoResponse, Response};
use efferian_authz::AuthzError;
use efferian_protocol::{PROBLEM_JSON_MEDIA_TYPE, ProblemDetails, TraceId, error_codes as code};
use http::{
    HeaderValue, StatusCode,
    header::{CONNECTION, CONTENT_TYPE, WWW_AUTHENTICATE},
};
use http_body_util::LengthLimitError;

use crate::http_transport::ReadIdleTimeout;
use crate::storage::{StorageError, WriteError, WriteTxError};
use crate::vault::{VaultError, auth::CredentialError};

pub type ApiResult<T> = Result<T, ApiError>;

/// An HTTP problem whose public fields never include raw request data or storage errors.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("{status}: {code}")]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    retryable: bool,
}

impl ApiError {
    pub const fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            retryable: false,
        }
    }

    pub const fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }

    pub const fn bad_input() -> Self {
        Self::new(StatusCode::BAD_REQUEST, code::INVALID_INPUT)
    }

    pub const fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, code::FORBIDDEN)
    }

    pub const fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, code::NOT_FOUND)
    }

    pub const fn conflict(code: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, code)
    }

    pub const fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, code::INTERNAL_ERROR)
    }

    pub(crate) const fn too_large() -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, code::BODY_TOO_LARGE)
    }

    pub(crate) const fn overloaded() -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, code::OVERLOADED).retryable()
    }

    pub(crate) fn body_error(error: &(dyn Error + 'static)) -> Self {
        let mut current = Some(error);
        while let Some(error) = current {
            if error.is::<LengthLimitError>() {
                return Self::too_large();
            }
            if error.is::<ReadIdleTimeout>() {
                return Self::new(StatusCode::REQUEST_TIMEOUT, code::REQUEST_TIMEOUT);
            }
            current = error.source();
        }
        Self::bad_input()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let problem = ProblemDetails::new(
            self.status.as_u16(),
            self.code,
            self.status.canonical_reason().unwrap_or("Request failed"),
            self.retryable,
            TraceId::new(),
        );
        let mut response = (self.status, Json(problem)).into_response();
        let headers = response.headers_mut();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(PROBLEM_JSON_MEDIA_TYPE),
        );
        if self.status == StatusCode::UNAUTHORIZED {
            headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        if self.status == StatusCode::REQUEST_TIMEOUT {
            headers.insert(CONNECTION, HeaderValue::from_static("close"));
        }
        response
    }
}

impl From<AuthzError> for ApiError {
    fn from(error: AuthzError) -> Self {
        let status =
            StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        Self::new(status, error.code())
    }
}

impl From<CredentialError> for ApiError {
    fn from(error: CredentialError) -> Self {
        match error {
            CredentialError::Unauthenticated => {
                Self::new(StatusCode::UNAUTHORIZED, code::UNAUTHENTICATED)
            }
            CredentialError::Authz(error) => error.into(),
            CredentialError::Storage(error) => error.into(),
            CredentialError::Vault(error) => error.into(),
        }
    }
}

impl From<StorageError> for ApiError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::Overloaded | StorageError::ShuttingDown | StorageError::ActorStopped => {
                Self::overloaded()
            }
            StorageError::PayloadTooLarge => Self::too_large(),
            StorageError::LastAdmin => Self::conflict(code::LAST_ADMIN),
            StorageError::StoragePressure => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, code::STORAGE_PRESSURE).retryable()
            }
            _ => Self::internal(),
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> Self {
        StorageError::from(error).into()
    }
}

impl From<VaultError> for ApiError {
    fn from(_: VaultError) -> Self {
        Self::internal()
    }
}

impl From<WriteError<ApiError>> for ApiError {
    fn from(error: WriteError<ApiError>) -> Self {
        match error {
            WriteError::Storage(error) => error.into(),
            WriteError::Domain(error) => error,
            WriteError::PreCommitAborted | WriteError::CommitOutcomeUnknown => Self::internal(),
        }
    }
}

impl From<ApiError> for WriteTxError<ApiError> {
    fn from(error: ApiError) -> Self {
        Self::Domain(error)
    }
}

impl From<CredentialError> for WriteTxError<ApiError> {
    fn from(error: CredentialError) -> Self {
        match error {
            CredentialError::Storage(error) => error.into(),
            other => Self::Domain(other.into()),
        }
    }
}
