//! Privacy Pass token *issuer* (architecture spec §7) — the Business-plane half of Pillar 4.
//! The issuer holds the RSA private key and blind-signs token requests that are gated on a
//! confirmed Monero payment (one token per payment). It never sees the unblinded token, so it
//! cannot link a redemption back to the purchase. The *verifier* lives in `nil-coordinator`, a
//! separate trust domain that only ever holds the public key.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use nil_core::durable::{DurableSet, TimedDurableSet};
use nil_crypto::Issuer;
use nil_proto::token::{IssueRequest, IssueResponse, PubKeyResponse, BLIND_TOKEN_HEX_LEN};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::client_ip::ClientIp;
use crate::monero::PaymentWatcher;
use crate::ratelimit::RateLimiter;
use crate::store::memory::InMemoryStore;
use crate::store::{IssuanceCommit, IssuanceLookup, IssuanceResult, Store};

/// Per-IP cap on token-issue attempts, and the window it applies over. Issuance is a paid,
/// infrequent operation, so this is generous but still caps a minting flood.
const ISSUE_RATE_MAX: u32 = 30;
const ISSUE_RATE_WINDOW: Duration = Duration::from_secs(60);
const ISSUANCE_RESULT_TTL_SECS: u64 =
    nil_crypto::token::V2_VALIDITY_SECS + nil_crypto::token::V2_EPOCH_SECS;

/// The issuer's signing capability, abstracted so the RSA private key can live in an HSM/KMS in
/// production rather than process memory (runbook §9 names it the single most sensitive secret).
/// The in-memory [`Issuer`] is the debug/test implementation; the release Portal requires the
/// HSM/KMS backend, which implements this trait and calls
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
    /// Separate transient per-source admission control for checkout creation. It is deliberately
    /// independent from paid issuance so checkout floods cannot consume the issue budget.
    pub checkout_limiter: Arc<RateLimiter>,
    /// Authoritative process-side cap passed to the pending set's atomic bounded insert.
    pub pending_checkout_max: usize,
    /// Read-only legacy fence containing payment ids issued by pre-idempotency versions. New
    /// issuance results are committed to `store`; this set is never appended to.
    pub issued: Arc<DurableSet>,
    /// Authoritative atomic result ledger shared with the account plane. It stores a hashed
    /// checkout reference, blinded-request hash, and cached blind signature, allowing a lost HTTP
    /// response to replay without signing or issuing a second token.
    pub store: Arc<dyn Store>,
    /// Server-minted checkout references awaiting payment (one per `/v1/billing/checkout`).
    /// Issuance is gated on the `payment_id` being a reference WE minted — this is what blocks
    /// front-running of a confirmed payment id by a stranger. Durable for the same reason as
    /// `issued`: a restart must not forget which references are legitimate. References are opaque
    /// and non-identifying (they index a payment, never a person), so this stays PII-free. It is a
    /// TIMED set: abandoned checkouts are pruned by age (TTL), so it stays bounded. Pruning is
    /// fail-closed — it can only deny a stale new checkout, never enable a double-issue (that is
    /// the permanent request-bound Store claim plus the read-only legacy `issued` fence).
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
            store: Arc::new(InMemoryStore::new()),
            pending: Arc::new(TimedDurableSet::in_memory()),
            limiter: Self::limiter(),
            checkout_limiter: Arc::new(RateLimiter::new(
                crate::billing::DEFAULT_CHECKOUT_RATE_MAX,
                crate::billing::CHECKOUT_RATE_WINDOW,
            )),
            pending_checkout_max: crate::billing::DEFAULT_PENDING_CHECKOUT_MAX,
        }
    }

    /// Production state with caller-provided (durable) one-token-per-payment and pending sets.
    pub fn with_issued(
        issuer: Arc<dyn TokenSigner>,
        watcher: Arc<dyn PaymentWatcher>,
        issued: Arc<DurableSet>,
        pending: Arc<TimedDurableSet>,
        store: Arc<dyn Store>,
    ) -> Self {
        Self {
            issuer,
            watcher,
            issued,
            store,
            pending,
            limiter: Self::limiter(),
            checkout_limiter: Arc::new(RateLimiter::new(
                crate::billing::DEFAULT_CHECKOUT_RATE_MAX,
                crate::billing::CHECKOUT_RATE_WINDOW,
            )),
            pending_checkout_max: crate::billing::DEFAULT_PENDING_CHECKOUT_MAX,
        }
    }

    pub fn with_checkout_limits(mut self, source_rate_max: u32, pending_max: usize) -> Self {
        self.checkout_limiter = Arc::new(RateLimiter::new(
            source_rate_max,
            crate::billing::CHECKOUT_RATE_WINDOW,
        ));
        self.pending_checkout_max = pending_max;
        self
    }
}

/// Hard cap on `/v1/tokens/issue` request bodies. A blind message for RSA-2048 is 256 bytes
/// hex-encoded (512 chars) and a payment_id is 64 hex chars; 16 KiB is generous. Without it, Axum's
/// 2 MiB default lets a caller (even one at the rate-limit ceiling) force MiB-scale buffering before
/// the rate-limit check and the RSA blind-sign run. Mirrors the Coordinator's `/v1/redeem` cap.
const TOKEN_BODY_LIMIT: usize = 16 * 1024;

pub fn token_router(state: TokenState) -> Router {
    Router::new()
        .route("/v1/tokens/pubkey", get(pubkey))
        .route("/v1/tokens/issue", post(issue))
        .layer(DefaultBodyLimit::max(TOKEN_BODY_LIMIT))
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
    /// This payment completed for a different blinded request, or exists only in the legacy fence.
    AlreadyIssued,
    /// The blinded message wasn't valid hex.
    Malformed,
    /// The one-token-per-payment record could not be made durable — fail closed (issue nothing)
    /// rather than risk a double-issue on the next restart.
    Unavailable,
    /// The blind signature operation failed.
    Issuer(String),
}

/// Core issuance logic (HTTP-free, unit-tested): bind one confirmed payment to one blinded request
/// and cache the completed signature. Identical retries return the cached response without asking
/// the signer again; a different request can never replace the winner.
pub async fn issue_logic(state: &TokenState, req: &IssueRequest) -> Result<Vec<u8>, IssueError> {
    let blind_msg = from_hex(&req.blind_msg)
        .filter(|message| message.len() * 2 == BLIND_TOKEN_HEX_LEN)
        .ok_or(IssueError::Malformed)?;
    let issuance_key = issuance_key(&req.payment_id);
    let request_hash = issuance_request_hash(&blind_msg);
    let now = nil_core::grant::now_unix_secs_for_expiry();

    // Consult the completed-result ledger first. A client whose successful response was lost must
    // be able to recover it for the full token retry lifetime even after the shorter pending-
    // checkout TTL has elapsed, and a retry must not depend on the payment watcher or HSM being up.
    match state
        .store
        .lookup_issuance(&issuance_key, &request_hash, now)
        .await
        .map_err(|error| {
            tracing::error!("issuance-result lookup failed: {error}");
            IssueError::Unavailable
        })? {
        IssuanceLookup::Replay { blind_sig } => return Ok(blind_sig),
        IssuanceLookup::Conflict => return Err(IssueError::AlreadyIssued),
        IssuanceLookup::Missing => {}
    }

    // Front-running guard for a genuinely new request: the payment id MUST be a reference we
    // minted via checkout. An unminted id is rejected even if some payment confirmed for it.
    if !crate::billing::is_known_reference(&state.pending, &req.payment_id) {
        return Err(IssueError::UnknownReference);
    }
    // Pre-idempotency rows have no request hash or cached result. Keep them fail-closed: replaying
    // one as a new request would double-issue, while inventing a response is impossible.
    if state.issued.contains(&req.payment_id) {
        return Err(IssueError::AlreadyIssued);
    }

    // External payment and signer work happens only for a genuinely new request. A completed retry
    // above remains available even if the watcher or HSM is temporarily unavailable.
    if !state.watcher.is_confirmed(&req.payment_id) {
        return Err(IssueError::Unpaid);
    }
    let blind_sig = Zeroizing::new(
        state
            .issuer
            .blind_sign(&blind_msg)
            .map_err(|e| IssueError::Issuer(format!("{e}")))?,
    );
    if blind_sig.len() * 2 != BLIND_TOKEN_HEX_LEN {
        return Err(IssueError::Issuer(
            "signer returned a wrong-length blind signature".to_string(),
        ));
    }
    let result = IssuanceResult {
        request_hash,
        blind_sig: blind_sig.to_vec(),
        replay_until: now.saturating_add(ISSUANCE_RESULT_TTL_SECS),
    };
    match state
        .store
        .commit_issuance(&issuance_key, result, now)
        .await
        .map_err(|error| {
            tracing::error!("issuance-result commit failed: {error}");
            IssueError::Unavailable
        })? {
        IssuanceCommit::Stored => Ok(blind_sig.to_vec()),
        IssuanceCommit::Replay { blind_sig } => Ok(blind_sig),
        IssuanceCommit::Conflict => Err(IssueError::AlreadyIssued),
    }
}

async fn issue(
    ClientIp(client_ip): ClientIp,
    State(state): State<TokenState>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, StatusCode> {
    // Abuse control: cap issue attempts per client IP. The IP is used transiently for the
    // counter only — never stored, logged, or tied to an account.
    if !state.limiter.check(&client_ip.to_string()) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    match issue_logic(&state, &req).await {
        Ok(mut sig) => {
            let blind_sig = to_hex(&sig);
            sig.zeroize();
            Ok(Json(IssueResponse { blind_sig }))
        }
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

fn issuance_key(payment_id: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"nil/one-shot-issuance/payment/v1\0");
    hash.update(payment_id.as_bytes());
    hash.finalize().into()
}

fn issuance_request_hash(blind_msg: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"nil/one-shot-issuance/blind-request/v1\0");
    hash.update(blind_msg);
    hash.finalize().into()
}

async fn pubkey(State(state): State<TokenState>) -> Result<Json<PubKeyResponse>, StatusCode> {
    state
        .issuer
        .public_der()
        .map(|d| {
            Json(PubKeyResponse {
                public_der: to_hex(&d),
            })
        })
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
    h.chunks_exact(2)
        .map(|p| Some((nib(p[0])? << 4) | nib(p[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monero::MockWatcher;
    use crate::store::file::FileStore;
    use nil_crypto::{token, Verifier};

    #[tokio::test]
    async fn payment_gated_issue_round_trips_and_replays_only_the_same_request() {
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
        let unminted = IssueRequest {
            payment_id: "pay-unknown".into(),
            blind_msg: to_hex(&req.blind_msg),
        };
        assert!(matches!(
            issue_logic(&state, &unminted).await,
            Err(IssueError::UnknownReference)
        ));

        // A minted-but-unpaid reference → refused (no confirmed payment).
        state.pending.insert("pay-unpaid", 0).unwrap();
        let unpaid = IssueRequest {
            payment_id: "pay-unpaid".into(),
            blind_msg: to_hex(&req.blind_msg),
        };
        assert!(matches!(
            issue_logic(&state, &unpaid).await,
            Err(IssueError::Unpaid)
        ));

        // Paid → issued; unblind → the token verifies under the public key.
        let paid = IssueRequest {
            payment_id: "pay-1".into(),
            blind_msg: to_hex(&req.blind_msg),
        };
        let blind_sig = issue_logic(&state, &paid)
            .await
            .expect("paid request issues");
        let token = token::finalize(&pub_der, &req, &blind_sig).unwrap();
        assert!(Verifier::from_public_der(&pub_der)
            .unwrap()
            .verify(&token, &msg));

        // An ambiguous retry of the exact request returns the byte-identical completed result.
        assert_eq!(
            issue_logic(&state, &paid).await.unwrap(),
            blind_sig,
            "response loss must be retry-safe"
        );
        assert_eq!(state.pending.prune_older_than(1).unwrap(), 2);
        assert_eq!(
            issue_logic(&state, &paid).await.unwrap(),
            blind_sig,
            "a completed retry outlives the shorter pending-checkout TTL"
        );

        // The payment cannot be rebound to a different blinded token request.
        let other_message = b"other-token-0123456789abcdef01234".to_vec();
        let other = token::blind(&pub_der, &other_message).unwrap();
        let rebound = IssueRequest {
            payment_id: "pay-1".into(),
            blind_msg: to_hex(&other.blind_msg),
        };
        assert!(matches!(
            issue_logic(&state, &rebound).await,
            Err(IssueError::AlreadyIssued)
        ));
    }

    #[tokio::test]
    async fn completed_issuance_response_survives_a_portal_restart() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let store_path = std::env::temp_dir().join(format!(
            "nil-portal-issuance-results-{}-{}.json",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&store_path);

        // The issuer key and the confirmed payment persist across the restart; only the
        // one-token-per-payment set is reloaded from disk.
        let issuer = Arc::new(Issuer::generate().unwrap());
        let pub_der = issuer.public_der().unwrap();
        let watcher = Arc::new(MockWatcher::with_paid(["pay-1".to_string()]));
        let msg = b"token-nonce-0123456789abcdef0123".to_vec();
        let req = token::blind(&pub_der, &msg).unwrap();
        let paid = IssueRequest {
            payment_id: "pay-1".into(),
            blind_msg: to_hex(&req.blind_msg),
        };

        // Boot 1: the account Store owns the atomic issuance result; the old set is a read-only
        // empty migration fence. Pending-reference durability is independent in this test.
        let boot1 = TokenState::with_issued(
            issuer.clone(),
            watcher.clone(),
            Arc::new(DurableSet::in_memory()),
            Arc::new(TimedDurableSet::in_memory()),
            Arc::new(FileStore::open(&store_path).unwrap()),
        );
        boot1.pending.insert("pay-1", 0).unwrap();
        let expected = issue_logic(&boot1, &paid)
            .await
            .expect("first issuance for the payment succeeds");
        drop(boot1); // simulate a Portal restart

        // Boot 2: same issuer and Store file. The exact request receives the original result rather
        // than a conflict or a second issuance.
        let boot2 = TokenState::with_issued(
            issuer,
            watcher,
            Arc::new(DurableSet::in_memory()),
            Arc::new(TimedDurableSet::in_memory()),
            Arc::new(FileStore::open(&store_path).unwrap()),
        );
        boot2.pending.insert("pay-1", 0).unwrap();
        assert_eq!(
            issue_logic(&boot2, &paid).await.unwrap(),
            expected,
            "the cached result must survive restart"
        );

        let _ = std::fs::remove_file(&store_path);
    }

    #[tokio::test]
    async fn legacy_issued_reference_remains_fail_closed() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let pub_der = issuer.public_der().unwrap();
        let watcher = Arc::new(MockWatcher::with_paid(["pay-old".to_string()]));
        let mut state = TokenState::new(issuer, watcher);
        let legacy = Arc::new(DurableSet::in_memory());
        legacy.insert("pay-old").unwrap();
        state.issued = legacy;
        state.pending.insert("pay-old", 0).unwrap();
        let request = token::blind(&pub_der, b"token-nonce-0123456789abcdef0123").unwrap();
        let req = IssueRequest {
            payment_id: "pay-old".into(),
            blind_msg: to_hex(&request.blind_msg),
        };
        assert!(matches!(
            issue_logic(&state, &req).await,
            Err(IssueError::AlreadyIssued)
        ));
    }
}
