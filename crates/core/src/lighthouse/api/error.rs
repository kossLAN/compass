use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use compass_proto::{ApiErrorBody, ErrorCode};

use crate::lighthouse::registry::AnnounceError;

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

    pub fn unlisted() -> Self {
        AnnounceError::Unlisted.into()
    }

    pub fn unannounced() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::Unannounced,
            "this node has not announced itself",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

impl From<AnnounceError> for ApiError {
    fn from(error: AnnounceError) -> Self {
        let (status, code) = match error {
            AnnounceError::Unlisted => (StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized),
            AnnounceError::AddressesExhausted => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::AddressesExhausted,
            ),
            AnnounceError::Invalid(_) => (StatusCode::BAD_REQUEST, ErrorCode::BadRequest),
            AnnounceError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Internal),
        };

        Self::new(status, code, error.to_string())
    }
}
