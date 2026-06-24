//! Privacy Pass token *issuer* (architecture spec §7) — the Business-plane half of Pillar 4.
//! The issuer holds the RSA private key and blind-signs token requests that are gated on a
//! confirmed Monero payment (one token per payment). It never sees the unblinded token, so it
//! cannot link a redemption back to the purchase. The *verifier* lives in `nil-coordinator`, a
//! separate trust domain that only ever holds the public key.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use nil_core::durable::{DurableSet, TimedDurableSet};
use nil_crypto::Issuer;
use nil_proto::token::{IssueRequest, IssueResponse, PubKeyResponse};

use crate::monero::PaymentWatcher;
use crate::ratelimit::RateLimiter;

/// Per-IP cap on token-issue attempts, and the window it applies over. Issuance is a paid,
/// infrequent operation, so this is generous but still caps a minting flood.
const ISSUE_RATE_MAX: u32 = 30;
const ISSUE_RATE_WINDOW: Duration = Duration::from_secs(60);

/// The issuer's signing capability, abstracted so the RSA private key can live in an HSM/KMS in
/// production rather than process memory (runbook §9 names it the single most sensitive secret).
/// The in-memory [`Issuer`] is the default; an HSM/KMS backend implements this trait and calls
/// the device — `TokenState` never assumes the key is in-process.
pub trait TokenSigner: Send + Sync {
    /// Blind-sign a client's blinded token request.
    fn blind_sign(&self, blind_msg: &[u8]) -> anyhow::Result<Vec<u8>>;
    /// The issuer's public key (DER) — handed to clients and pinned by the verifier.
    fn public_der(&self) -> anyhow::Result<Vec<u8>>;
}

impl TokenSigner for Issuer {
    fn blind_sign(&self, blind_msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        Issuer::blind_sign(self, blind_msg).map_err(|e| anyhow::anyhow!("{e}"))
    }
    fn public_der(&self) -> anyhow::Result<Vec<u8>> {
        Issuer::public_der(self).map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// Issuer-side state. Separate from the account `AppState` (different trust concern); merged
/// into the Portal router via `Router::merge`.
#[derive(Clone)]
pub struct TokenState {
    pub issuer: Arc<dyn TokenSigner>,
    pub watcher: Arc<dyn PaymentWatcher>,
    /// Abuse control on `/v1/tokens/issue`, keyed by client IP.
    pub limiter: Arc<RateLimiter>,
    /// Payment ids already used to issue a token — one token per payment. Durable across
    /// restarts (file-backed in production), or a restart would re-permit a double-issue for an
    /// already-spent payment. Payment ids are non-identifying (they index a Monero payment, not
    /// a person), so this stays PII-free.
    pub issued: Arc<DurableSet>,
    /// Server-minted checkout references awaiting payment (one per `/v1/billing/checkout`).
    /// Issuance is gated on the `payment_id` being a reference WE minted — this is what blocks
    /// front-running of a confirmed payment id by a stranger. Durable for the same reason as
    /// `issued`: a restart must not forget which references are legitimate. References are opaque
    /// and non-identifying (they index a payment, never a person), so this stays PII-free. It is a
    /// TIMED set: abandoned checkouts are pruned by age (TTL), so it stays bounded. Pruning is
    /// fail-closed — it can only deny a stale checkout, never enable a double-issue (that is the
    /// SEPARATE `issued` set, which is never TTL'd).
    pub pending: Arc<TimedDurableSet>,
}

impl TokenState {
    fn limiter() -> Arc<RateLimiter> {
        Arc::new(RateLimiter::new(ISSUE_RATE_MAX, ISSUE_RATE_WINDOW))
    }

    /// Dev/test state with volatile (in-memory) one-token-per-payment and pending-reference sets.
    #[allow(dead_code)] // used by tests; production uses `with_issued` for durable sets
    pub fn new(issuer: Arc<dyn TokenSigner>, watcher: Arc<dyn PaymentWatcher>) -> Self {
        Self {
            issuer,
            watcher,
            issued: Arc::new(DurableSet::in_memory()),
            pending: Arc::new(TimedDurableSet::in_memory()),
            limiter: Self::limiter(),
        }
    }

    /// Production state with caller-provided (durable) one-token-per-payment and pending sets.
    pub fn with_issued(
        issuer: Arc<dyn TokenSigner>,
        watcher: Arc<dyn PaymentWatcher>,
        issued: Arc<DurableSet>,
        pending: Arc<TimedDurableSet>,
    ) -> Self {
        Self { issuer, watcher, issued, pending, limiter: Self::limiter() }
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
    /// The `payment_id` is not a reference this Portal minted via `/v1/billing/checkout`. This
    /// is the front-running guard: a stranger who learns a confirmed Monero payment id still
    /// cannot redeem it, because issuance only proceeds for our own (unguessable) references.
    UnknownReference,
    /// No confirmed payment for this payment id.
    Unpaid,
    /// A token was already issued for this payment id.
    AlreadyIssued,
    /// The blinded message wasn't valid hex.
    Malformed,
    /// The one-token-per-payment record could not be made durable — fail closed (issue nothing)
    /// rather than risk a double-issue on the next restart.
    Unavailable,
    /// The blind signature operation failed.
    Issuer(String),
}

/// Core issuance logic (HTTP-free, unit-tested): require a confirmed payment, enforce one
/// token per payment, then blind-sign. The issuer never learns the unblinded token.
pub fn issue_logic(state: &TokenState, req: &IssueRequest) -> Result<Vec<u8>, IssueError> {
    // Front-running guard: the payment id MUST be a reference we minted via checkout. Checked
    // before the payment lookup so an unminted id is rejected even if some payment confirmed for
    // it. The reference is unguessable (256-bit CSPRNG), so a stranger cannot supply a valid one.
    if !crate::billing::is_known_reference(&state.pending, &req.payment_id) {
        return Err(IssueError::UnknownReference);
    }
    if !state.watcher.is_confirmed(&req.payment_id) {
        return Err(IssueError::Unpaid);
    }
    let blind_msg = from_hex(&req.blind_msg).ok_or(IssueError::Malformed)?;
    // Durably record one-token-per-payment BEFORE signing. Fail closed if it can't be persisted.
    match state.issued.insert(&req.payment_id) {
        Ok(true) => {}                                       // first token for this payment
        Ok(false) => return Err(IssueError::AlreadyIssued),  // already issued
        Err(e) => {
            tracing::error!("issued-set persist failed: {e}");
            return Err(IssueError::Unavailable);
        }
    }
    state.issuer.blind_sign(&blind_msg).map_err(|e| IssueError::Issuer(format!("{e}")))
}

async fn issue(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<TokenState>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, StatusCode> {
    // Abuse control: cap issue attempts per client IP. The IP is used transiently for the
    // counter only — never stored, logged, or tied to an account.
    if !state.limiter.check(&peer.ip().to_string()) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    match issue_logic(&state, &req) {
        Ok(sig) => Ok(Json(IssueResponse { blind_sig: to_hex(&sig) })),
        // Treat an unknown reference like an unpaid one (402): don't reveal to a prober whether a
        // given id is a real-but-unpaid reference vs never minted at all.
        Err(IssueError::UnknownReference) => Err(StatusCode::PAYMENT_REQUIRED),
        Err(IssueError::Unpaid) => Err(StatusCode::PAYMENT_REQUIRED),
        Err(IssueError::AlreadyIssued) => Err(StatusCode::CONFLICT),
        Err(IssueError::Malformed) => Err(StatusCode::BAD_REQUEST),
        Err(IssueError::Unavailable) => Err(StatusCode::SERVICE_UNAVAILABLE),
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
        // "pay-1" is a checkout reference the Portal minted (front-running guard).
        state.pending.insert("pay-1", 0).unwrap();

        // Client blinds a fresh token message.
        let msg = b"token-nonce-0123456789abcdef0123".to_vec();
        let req = token::blind(&pub_der, &msg).unwrap();

        // A payment id we never minted via checkout → refused even though no payment confirmed.
        let unminted = IssueRequest { payment_id: "pay-unknown".into(), blind_msg: to_hex(&req.blind_msg) };
        assert!(matches!(issue_logic(&state, &unminted), Err(IssueError::UnknownReference)));

        // A minted-but-unpaid reference → refused (no confirmed payment).
        state.pending.insert("pay-unpaid", 0).unwrap();
        let unpaid = IssueRequest { payment_id: "pay-unpaid".into(), blind_msg: to_hex(&req.blind_msg) };
        assert!(matches!(issue_logic(&state, &unpaid), Err(IssueError::Unpaid)));

        // Paid → issued; unblind → the token verifies under the public key.
        let paid = IssueRequest { payment_id: "pay-1".into(), blind_msg: to_hex(&req.blind_msg) };
        let blind_sig = issue_logic(&state, &paid).expect("paid request issues");
        let token = token::finalize(&pub_der, &req, &blind_sig).unwrap();
        assert!(Verifier::from_public_der(&pub_der).unwrap().verify(&token, &msg));

        // Same payment id again → refused (one token per payment).
        assert!(matches!(issue_logic(&state, &paid), Err(IssueError::AlreadyIssued)));
    }

    #[test]
    fn one_token_per_payment_survives_a_portal_restart() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nil-portal-issued-{}-{}.log",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);

        // The issuer key and the confirmed payment persist across the restart; only the
        // one-token-per-payment set is reloaded from disk.
        let issuer = Arc::new(Issuer::generate().unwrap());
        let pub_der = issuer.public_der().unwrap();
        let watcher = Arc::new(MockWatcher::with_paid(["pay-1".to_string()]));
        let msg = b"token-nonce-0123456789abcdef0123".to_vec();
        let req = token::blind(&pub_der, &msg).unwrap();
        let paid = IssueRequest { payment_id: "pay-1".into(), blind_msg: to_hex(&req.blind_msg) };

        // Boot 1: file-backed issued set. First issuance for pay-1 succeeds. The pending set is
        // volatile here (its durability is independent); seed it with the minted reference.
        let boot1 = TokenState::with_issued(
            issuer.clone(),
            watcher.clone(),
            Arc::new(DurableSet::open(&path).unwrap()),
            Arc::new(TimedDurableSet::in_memory()),
        );
        boot1.pending.insert("pay-1", 0).unwrap();
        assert!(issue_logic(&boot1, &paid).is_ok(), "first issuance for the payment succeeds");
        drop(boot1); // simulate a Portal restart

        // Boot 2: same issuer/payment, issued set reloaded from the SAME file. The paid id is
        // already spent — re-issuing must be refused (regression guard for double-issue).
        let boot2 = TokenState::with_issued(
            issuer,
            watcher,
            Arc::new(DurableSet::open(&path).unwrap()),
            Arc::new(TimedDurableSet::in_memory()),
        );
        boot2.pending.insert("pay-1", 0).unwrap();
        assert!(
            matches!(issue_logic(&boot2, &paid), Err(IssueError::AlreadyIssued)),
            "a payment that already minted a token must not mint a second one after a restart"
        );

        let _ = std::fs::remove_file(&path);
    }
}
