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
    /// Authentication failed. Unknown accounts, invalid registration proofs, and bad request
    /// signatures deliberately share one response so authenticated endpoints are not account-
    /// existence oracles (PD-3).
    #[error("invalid authentication proof")]
    Unauthorized,
    #[error("too many requests")]
    TooManyRequests,
    /// Payment not yet confirmed — the client should retry later. Mirrors the token-issue 402.
    #[error("payment required")]
    PaymentRequired,
    /// The action was already performed (e.g. this payment already activated the subscription).
    #[error("conflict")]
    Conflict,
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
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ApiError::PaymentRequired => StatusCode::PAYMENT_REQUIRED,
            ApiError::Conflict => StatusCode::CONFLICT,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = ErrorBody {
            error: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}
