//! Privacy Pass token *issuer* (architecture spec §7) — the Business-plane half of Pillar 4.
//! The issuer holds the RSA private key and blind-signs token requests that are gated on a
//! confirmed Monero payment (one token per payment). It never sees the unblinded token, so it
//! cannot link a redemption back to the purchase. The *verifier* lives in `nil-coordinator`, a
//! separate trust domain that only ever holds the public key.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use nil_crypto::Issuer;
use nil_proto::token::{IssueRequest, IssueResponse, PubKeyResponse};

use crate::monero::PaymentWatcher;

/// Issuer-side state. Separate from the account `AppState` (different trust concern); merged
/// into the Portal router via `Router::merge`.
#[derive(Clone)]
pub struct TokenState {
    pub issuer: Arc<Issuer>,
    pub watcher: Arc<dyn PaymentWatcher>,
    /// Payment ids already used to issue a token — one token per payment.
    pub issued: Arc<Mutex<HashSet<String>>>,
}

impl TokenState {
    pub fn new(issuer: Arc<Issuer>, watcher: Arc<dyn PaymentWatcher>) -> Self {
        Self { issuer, watcher, issued: Arc::new(Mutex::new(HashSet::new())) }
    }
}

pub fn token_router(state: TokenState) -> Router {
    Router::new()
        .route("/v1/tokens/pubkey", get(pubkey))
        .route("/v1/tokens/issue", post(issue))
        .with_state(state)
}

#[derive(Debug)]
pub enum IssueError {
    /// No confirmed payment for this payment id.
    Unpaid,
    /// A token was already issued for this payment id.
    AlreadyIssued,
    /// The blinded message wasn't valid hex.
    Malformed,
    /// The blind signature operation failed.
    Issuer(String),
}

/// Core issuance logic (HTTP-free, unit-tested): require a confirmed payment, enforce one
/// token per payment, then blind-sign. The issuer never learns the unblinded token.
pub fn issue_logic(state: &TokenState, req: &IssueRequest) -> Result<Vec<u8>, IssueError> {
    if !state.watcher.is_confirmed(&req.payment_id) {
        return Err(IssueError::Unpaid);
    }
    let blind_msg = from_hex(&req.blind_msg).ok_or(IssueError::Malformed)?;
    {
        let mut issued = state.issued.lock().expect("issued mutex");
        if !issued.insert(req.payment_id.clone()) {
            return Err(IssueError::AlreadyIssued);
        }
    }
    state.issuer.blind_sign(&blind_msg).map_err(|e| IssueError::Issuer(format!("{e}")))
}

async fn issue(
    State(state): State<TokenState>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, StatusCode> {
    match issue_logic(&state, &req) {
        Ok(sig) => Ok(Json(IssueResponse { blind_sig: to_hex(&sig) })),
        Err(IssueError::Unpaid) => Err(StatusCode::PAYMENT_REQUIRED),
        Err(IssueError::AlreadyIssued) => Err(StatusCode::CONFLICT),
        Err(IssueError::Malformed) => Err(StatusCode::BAD_REQUEST),
        Err(IssueError::Issuer(e)) => {
            tracing::error!("blind-sign failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn pubkey(State(state): State<TokenState>) -> Result<Json<PubKeyResponse>, StatusCode> {
    state
        .issuer
        .public_der()
        .map(|d| Json(PubKeyResponse { public_der: to_hex(&d) }))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn from_hex(s: &str) -> Option<Vec<u8>> {
    let h = s.as_bytes();
    if h.len() % 2 != 0 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    h.chunks_exact(2).map(|p| Some((nib(p[0])? << 4) | nib(p[1])?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monero::MockWatcher;
    use nil_crypto::{token, Verifier};

    #[test]
    fn payment_gated_issue_round_trips_and_is_single_use() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let pub_der = issuer.public_der().unwrap();
        let watcher = Arc::new(MockWatcher::with_paid(["pay-1".to_string()]));
        let state = TokenState::new(issuer, watcher);

        // Client blinds a fresh token message.
        let msg = b"token-nonce-0123456789abcdef0123".to_vec();
        let req = token::blind(&pub_der, &msg).unwrap();

        // Unpaid payment id → refused.
        let unpaid = IssueRequest { payment_id: "pay-unknown".into(), blind_msg: to_hex(&req.blind_msg) };
        assert!(matches!(issue_logic(&state, &unpaid), Err(IssueError::Unpaid)));

        // Paid → issued; unblind → the token verifies under the public key.
        let paid = IssueRequest { payment_id: "pay-1".into(), blind_msg: to_hex(&req.blind_msg) };
        let blind_sig = issue_logic(&state, &paid).expect("paid request issues");
        let token = token::finalize(&pub_der, &req, &blind_sig).unwrap();
        assert!(Verifier::from_public_der(&pub_der).unwrap().verify(&token, &msg));

        // Same payment id again → refused (one token per payment).
        assert!(matches!(issue_logic(&state, &paid), Err(IssueError::AlreadyIssued)));
    }
}
