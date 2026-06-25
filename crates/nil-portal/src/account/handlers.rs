//! HTTP handlers for the account endpoints (architecture spec §7.5, §8, §13.3).

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::Json;

use nil_crypto::account::{self, Phrase, RecoveryCode};
use nil_proto::account::{
    CreateAccountRequest, CreateAccountResponse, RecoverRequest, RecoverResponse,
};

use crate::account::error::ApiError;
use crate::account::model::{AccountRecord, Entitlement};
use crate::state::AppState;

/// `POST /v1/account` — create an account.
///
/// For `{"type":"anonymous"}` the Portal generates a 256-bit secret (derived from a
/// fresh 7-word phrase), an account number `= H(secret)`, and a one-time recovery
/// code, then stores ONLY `H(secret)` + the recovery-code hash + entitlement. The
/// phrase and code are returned to the user and never persisted.
pub async fn create_account(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<CreateAccountRequest>,
) -> Result<(StatusCode, Json<CreateAccountResponse>), ApiError> {
    // Abuse control: cap account creations per client IP to stop storage-exhaustion flooding.
    // The IP is used transiently for the counter only — never stored, logged, or tied to an
    // account (PD-3: no identity in the data we keep).
    if !state.limiter.check(&peer.ip().to_string()) {
        return Err(ApiError::TooManyRequests);
    }
    match req {
        CreateAccountRequest::Anonymous => {
            let derived = account::create_account_os();
            let record = AccountRecord {
                account_number: *derived.account_number.as_bytes(),
                recovery_code_hash: derived.recovery_code_hash,
                entitlement: Entitlement::None,
            };
            state
                .store
                .insert(record)
                .await
                .map_err(|_| ApiError::Internal)?;

            let resp = CreateAccountResponse {
                account_number: derived.account_number.display(),
                recovery_phrase: derived.recovery_phrase.to_vec(),
                recovery_code: derived.recovery_code.display(),
            };
            Ok((StatusCode::CREATED, Json(resp)))
        }
        // Email accounts (encrypted email at rest) are designed but not built in Phase 0.
        CreateAccountRequest::Email { .. } => Err(ApiError::NotImplemented),
    }
}

/// `POST /v1/account/recover` — recover via the 7-word phrase + one-time code.
pub async fn recover_account(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>, ApiError> {
    // Rate-limit per client IP — recovery checks an 8-char one-time code against a known account,
    // so an unthrottled endpoint is a brute-force oracle. The IP is used transiently for the
    // counter only — never stored, logged, or tied to an account (PD-3). Mirrors `create_account`.
    if !state.limiter.check(&peer.ip().to_string()) {
        return Err(ApiError::TooManyRequests);
    }
    let phrase =
        Phrase::parse(&req.recovery_phrase).map_err(|e| ApiError::BadPhrase(e.to_string()))?;
    let account_number = account::account_number_from_phrase(&phrase)
        .map_err(|e| ApiError::BadPhrase(e.to_string()))?;

    // No existence oracle: a well-formed phrase that maps to NO account returns the SAME
    // Unauthorized as a real account with a wrong recovery code (PD-3 — don't confirm whether a
    // given phrase is a registered account; the phrase is itself a bearer credential). A malformed
    // phrase still 400s (BadPhrase) — that's structural validation, not an existence signal.
    let record = state
        .store
        .get(account_number.as_bytes())
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::Unauthorized)?;

    let submitted = RecoveryCode::parse(&req.recovery_code);
    if !account::verify_recovery_code(&submitted, &record.recovery_code_hash) {
        return Err(ApiError::Unauthorized);
    }

    Ok(Json(RecoverResponse {
        account_number: account_number.display(),
        entitlement: record.entitlement.into(),
    }))
}

/// `GET /v1/account` — account + entitlement status. Session-authenticated; Phase 1.
pub async fn get_account() -> ApiError {
    ApiError::NotImplemented
}
