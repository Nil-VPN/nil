//! API error type and its HTTP mapping.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not implemented")]
    NotImplemented,
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    #[error("invalid recovery phrase: {0}")]
    BadPhrase(String),
    /// Recovery failed: either no account matches the phrase OR the recovery code is wrong. These
    /// are deliberately INDISTINGUISHABLE (same status + message) so the endpoint is not an
    /// account-existence oracle (PD-3).
    #[error("invalid recovery phrase or code")]
    Unauthorized,
    #[error("too many requests")]
    TooManyRequests,
    #[error("internal error")]
    Internal,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::BadPhrase(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = ErrorBody {
            error: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}
