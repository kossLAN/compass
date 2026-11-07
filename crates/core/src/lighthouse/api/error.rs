use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bunnyhop_proto::{ApiErrorBody, ErrorCode};

use crate::lighthouse::registry::RegisterError;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    body: ApiErrorBody,
}

impl ApiError {
    pub fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            body: ApiErrorBody {
                code,
                message: message.into(),
            },
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::BadRequest, message)
    }

    pub fn rate_limited(message: &'static str) -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RateLimited,
            message,
        )
    }

    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "unknown or revoked token",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

impl From<RegisterError> for ApiError {
    fn from(error: RegisterError) -> Self {
        let (status, code) = match error {
            RegisterError::InvalidAuthKey => (StatusCode::UNAUTHORIZED, ErrorCode::InvalidAuthKey),
            RegisterError::Revoked => (StatusCode::FORBIDDEN, ErrorCode::Revoked),
            RegisterError::UnknownNode => (StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized),
            RegisterError::AddressesExhausted => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::AddressesExhausted,
            ),
            RegisterError::Invalid(_) => (StatusCode::BAD_REQUEST, ErrorCode::BadRequest),
            RegisterError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Internal),
        };

        Self::new(status, code, error.to_string())
    }
}
