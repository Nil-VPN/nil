//! HTTP handlers for the account endpoints (architecture spec §7.5, §8, §13.3).

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use nil_crypto::account::{verify_registration_signature, AUTH_PUBKEY_LEN, AUTH_SIG_LEN};
use nil_proto::account::{
    AccountAuth, AccountStatusResponse, ChallengeResponse, CreateAccountRequest,
    CreateAccountResponse,
};

use crate::account::auth::{authenticate, AuthError};
use crate::account::error::ApiError;
use crate::account::model::{AccountRecord, Entitlement};
use crate::client_ip::ClientIp;
use crate::state::AppState;
use crate::store::{hex32, StoreError};

/// `POST /v1/account` — create an account.
///
/// For `{"type":"anonymous", ...}` the client generates and retains all secret material. The
/// Portal accepts only `H(secret)`, the public authentication key, and a signature proving
/// possession of the corresponding private key. Recovery material never crosses the network.
pub async fn create_account(
    ClientIp(client_ip): ClientIp,
    State(state): State<AppState>,
    Json(req): Json<CreateAccountRequest>,
) -> Result<(StatusCode, Json<CreateAccountResponse>), ApiError> {
    // Abuse control: cap account creations per client IP to stop storage-exhaustion flooding.
    // The IP is used transiently for the counter only — never stored, logged, or tied to an
    // account (PD-3: no identity in the data we keep).
    if !state.limiter.check(&client_ip.to_string()) {
        return Err(ApiError::TooManyRequests);
    }
    match req {
        CreateAccountRequest::Anonymous {
            account_number,
            auth_pubkey,
            registration_signature,
        } => {
            let account_number = parse_lower_hex::<32>(&account_number).ok_or(
                ApiError::BadRequest("account_number must be 64 lowercase hex characters"),
            )?;
            let auth_pubkey = parse_lower_hex::<AUTH_PUBKEY_LEN>(&auth_pubkey).ok_or(
                ApiError::BadRequest("auth_pubkey must be 64 lowercase hex characters"),
            )?;
            let registration_signature = parse_lower_hex::<AUTH_SIG_LEN>(&registration_signature)
                .ok_or(ApiError::BadRequest(
                "registration_signature must be 128 lowercase hex characters",
            ))?;

            if !verify_registration_signature(
                &account_number,
                &auth_pubkey,
                &registration_signature,
            ) {
                return Err(ApiError::Unauthorized);
            }

            let record = AccountRecord {
                account_number,
                entitlement: Entitlement::None,
                auth_pubkey,
            };
            state.store.insert(record).await.map_err(|e| match e {
                StoreError::Duplicate => ApiError::Conflict,
                StoreError::Backend(_) => ApiError::Internal,
            })?;

            let resp = CreateAccountResponse {
                account_number: hex32(&account_number),
            };
            Ok((StatusCode::CREATED, Json(resp)))
        }
        // Email accounts (encrypted email at rest) are designed but not built in Phase 0.
        CreateAccountRequest::Email { .. } => Err(ApiError::NotImplemented),
    }
}

/// `POST /v1/account/challenge` — mint a single-use, short-TTL nonce for account auth (ADR-0007).
///
/// No request body and no account identifier: a challenge is account-agnostic (the signature, which
/// only the key holder can produce, ties it to an account at verify time), so issuing one reveals
/// nothing — not even whether any account exists. Rate-limited per IP like the other write paths.
pub async fn account_challenge(
    ClientIp(client_ip): ClientIp,
    State(state): State<AppState>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    // The generous auth limiter, NOT the tight create limiter: a challenge is fetched before every
    // authenticated operation (including a background batch prefetch), and mints nothing durable.
    if !state.auth_limiter.check(&client_ip.to_string()) {
        return Err(ApiError::TooManyRequests);
    }
    let now = nil_core::grant::now_unix_secs();
    let challenge = state.challenges.issue(now).map_err(|e| {
        // Never log the nonce; only that minting failed.
        tracing::error!("challenge CSPRNG failed: {e}");
        ApiError::Internal
    })?;
    Ok(Json(ChallengeResponse { challenge }))
}

/// `POST /v1/account/status` — the authenticated subscription state (ADR-0007).
///
/// The client first gets a nonce from `/v1/account/challenge`, signs it with its account auth key,
/// and posts the [`AccountAuth`] proof here. The Portal verifies it, resolves the entitlement
/// against the clock, and returns status only — never any identity. This is what a re-logged-in
/// client calls to learn "am I still subscribed, and until when?".
pub async fn account_status(
    ClientIp(client_ip): ClientIp,
    State(state): State<AppState>,
    Json(auth): Json<AccountAuth>,
) -> Result<Json<AccountStatusResponse>, ApiError> {
    // Generous auth limiter (a client may poll status); not the tight create limiter.
    if !state.auth_limiter.check(&client_ip.to_string()) {
        return Err(ApiError::TooManyRequests);
    }
    // A gate ("is the subscription still live?") → fail-closed clock: unknown clock reads as Expired.
    let now = nil_core::grant::now_unix_secs_for_expiry();
    let record = authenticate(&state, &auth, now)
        .await
        .map_err(map_auth_err)?;
    let entitlement = record.entitlement.resolved(now);
    Ok(Json(AccountStatusResponse {
        entitlement: entitlement.into(),
        until: entitlement.active_until(now),
    }))
}

/// Map an [`AuthError`] to its HTTP error. `Unauthorized` is deliberately one bucket (no
/// account-existence oracle, PD-3); a malformed proof is a 400; a backend failure fails closed.
pub(crate) fn map_auth_err(e: AuthError) -> ApiError {
    match e {
        AuthError::Malformed => ApiError::BadRequest("malformed authentication proof"),
        AuthError::Unauthorized => ApiError::Unauthorized,
        AuthError::Backend => ApiError::Internal,
    }
}

/// `GET /v1/account` — account + entitlement status. Session-authenticated; Phase 1.
pub async fn get_account() -> ApiError {
    ApiError::NotImplemented
}

/// Parse an exact-length canonical lowercase hexadecimal field.
///
/// Registration has one canonical wire representation so alternate case cannot create distinct
/// rate-limit, cache, or audit identities for the same byte string.
fn parse_lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let mut out = [0u8; N];
    for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
        fn nibble(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => unreachable!("caller validated lowercase hex"),
            }
        }
        out[i] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Some(out)
}

#[cfg(test)]
mod registration_encoding_tests {
    use super::parse_lower_hex;

    #[test]
    fn exact_lowercase_hex_is_required() {
        assert_eq!(parse_lower_hex::<2>("00af"), Some([0x00, 0xaf]));
        assert_eq!(parse_lower_hex::<2>("00AF"), None);
        assert_eq!(parse_lower_hex::<2>("00ag"), None);
        assert_eq!(parse_lower_hex::<2>("00"), None);
    }
}
