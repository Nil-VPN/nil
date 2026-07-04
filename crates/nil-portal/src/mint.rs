//! Subscription-gated, mint-on-demand blind tokens (ADR-0007) — the payoff of the subscription.
//!
//! `POST /v1/tokens/mint`: an authenticated account with an ACTIVE, unexpired subscription mints a
//! fresh blind Privacy Pass token. It is the SAME blind-sign path as one-shot issuance
//! (`crate::tokens::issue_logic`), but gated on the subscription instead of a one-time payment, and
//! rate-capped per account (an abuse/resale bound). The issuer never sees the unblinded token, so a
//! redemption can't be linked back to the account or to minting — account↔connection unlinkability
//! holds end to end (Pillar 4 / PD-4). The control/data plane sees only the anonymous blind token.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::routing::post;
use axum::{Json, Router};

use nil_core::grant::now_unix_secs_for_expiry;
use nil_proto::account::MintRequest;
use nil_proto::token::IssueResponse;

use crate::account::auth::authenticate;
use crate::account::error::ApiError;
use crate::account::handlers::map_auth_err;
use crate::ratelimit::RateLimiter;
use crate::state::AppState;
use crate::tokens::TokenSigner;

/// Hard cap on the mint request body. A blinded RSA-2048 message is 256 B (512 hex) and the auth
/// proof is ~260 B; 16 KiB is generous. Mirrors the other endpoints' body-amplification guard.
const MINT_BODY_LIMIT: usize = 16 * 1024;

/// Per-IP cap on mint attempts (a cheap DoS guard, independent of the per-account cap below). The IP
/// is used transiently for the counter only — never stored, logged, or tied to an account.
const MINT_IP_RATE_MAX: u32 = 120;
const MINT_IP_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Default per-ACCOUNT mint cap and window: the abuse/resale bound. Generous for real use (a token
/// per connection, reconnects on network changes, a few per multi-hop path) but far below resale
/// scale. Tunable via `NW_MINT_RATE_MAX` (see `main`).
pub const DEFAULT_MINT_ACCOUNT_RATE_MAX: u32 = 120;
pub const MINT_ACCOUNT_RATE_WINDOW: Duration = Duration::from_secs(3600);

/// Mint-plane state: the account [`AppState`] (auth — store + challenges, SHARED with the account
/// router so a `/v1/account/challenge` nonce is consumable here) and the issuer's signing
/// capability. The per-account cap keeps an active account from minting at resale scale.
#[derive(Clone)]
pub struct MintState {
    pub app: AppState,
    pub issuer: Arc<dyn TokenSigner>,
    ip_limiter: Arc<RateLimiter>,
    /// Per-account sliding-window mint cap, keyed by account number. In-memory (PD-2): a transient
    /// counter, never persisted — losing it on restart only resets the window, which is harmless.
    account_limiter: Arc<RateLimiter>,
}

impl MintState {
    pub fn new(app: AppState, issuer: Arc<dyn TokenSigner>, account_rate_max: u32) -> Self {
        Self {
            app,
            issuer,
            ip_limiter: Arc::new(RateLimiter::new(MINT_IP_RATE_MAX, MINT_IP_RATE_WINDOW)),
            account_limiter: Arc::new(RateLimiter::new(account_rate_max, MINT_ACCOUNT_RATE_WINDOW)),
        }
    }
}

pub fn mint_router(state: MintState) -> Router {
    Router::new()
        .route("/v1/tokens/mint", post(mint))
        .layer(DefaultBodyLimit::max(MINT_BODY_LIMIT))
        .with_state(state)
}

/// `POST /v1/tokens/mint` — authenticate → require an active subscription → rate-cap → blind-sign.
async fn mint(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<MintState>,
    Json(req): Json<MintRequest>,
) -> Result<Json<IssueResponse>, ApiError> {
    if !state.ip_limiter.check(&peer.ip().to_string()) {
        return Err(ApiError::TooManyRequests);
    }
    // Auth + subscription are GATES → fail-closed clock (unknown clock ⇒ challenge/expiry treated as
    // expired ⇒ refuse). The challenge is consumed here (single-use), so each mint needs a fresh one.
    let now = now_unix_secs_for_expiry();
    let record = authenticate(&state.app, &req.auth, now).await.map_err(map_auth_err)?;

    // Require an ACTIVE, unexpired subscription. None/Expired (or lapsed Active) ⇒ 402, mirroring the
    // one-shot issuance "unpaid" response — the client must (re)subscribe.
    if record.entitlement.active_until(now).is_none() {
        return Err(ApiError::PaymentRequired);
    }

    // Per-account abuse/resale bound, keyed by the account number (H(secret)). Checked AFTER auth so
    // a forged/unauthenticated request can't burn a real account's mint budget. The account number
    // is the Portal's own lookup key (non-identity); the counter is transient + in-memory (PD-2).
    //
    // Key on the CANONICAL decoded account number (`record.account_number`, re-hexed lowercase), NOT
    // the raw request string: `unhex32` decodes hex case-insensitively and the auth signature covers
    // only the challenge, so `AABB…` and `aabb…` authenticate as the SAME account but would otherwise
    // land in DISTINCT rate-limit buckets — letting one subscription mint at ~2^24× the cap. This is
    // the same hex-case canonicalization the Coordinator applies to nullifiers (nil-coordinator
    // api.rs `to_hex(&msg)`); the mint path must match it.
    if !state.account_limiter.check(&to_hex(&record.account_number)) {
        return Err(ApiError::TooManyRequests);
    }

    let blind_msg = from_hex(&req.blind_msg).ok_or(ApiError::BadRequest("malformed blind message"))?;
    // Same blind-sign as one-shot issuance; the issuer never sees the unblinded token.
    let sig = state.issuer.blind_sign(&blind_msg).map_err(|e| {
        tracing::error!("mint blind-sign failed: {e}");
        ApiError::Internal
    })?;
    Ok(Json(IssueResponse { blind_sig: to_hex(&sig) }))
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let h = s.as_bytes();
    if h.is_empty() || h.len() % 2 != 0 {
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

    use axum::extract::connect_info::ConnectInfo;
    use nil_crypto::account::{create_account_os, AuthKeypair};
    use nil_crypto::{token, Issuer};
    use nil_proto::account::AccountAuth;

    use crate::account::model::{AccountRecord, Entitlement};
    use crate::store::memory::InMemoryStore;
    use crate::store::Store;

    fn peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("1.2.3.4:9999".parse().unwrap())
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// A mint state over a real issuer + in-memory store, with a configurable per-account cap.
    fn state_with(issuer: Arc<Issuer>, account_max: u32) -> MintState {
        let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
        MintState::new(AppState::new(store), issuer, account_max)
    }

    /// Insert a fresh account with the given entitlement; return its keypair + account-number hex.
    async fn add_account(state: &MintState, entitlement: Entitlement) -> (AuthKeypair, String) {
        let d = create_account_os();
        state
            .app
            .store
            .insert(AccountRecord {
                account_number: *d.account_number.as_bytes(),
                recovery_code_hash: d.recovery_code_hash,
                entitlement,
                auth_pubkey: d.auth_public_key,
            })
            .await
            .expect("insert");
        let kp = AuthKeypair::from_phrase(&d.recovery_phrase).expect("kp");
        (kp, hex(d.account_number.as_bytes()))
    }

    fn mint_req(state: &MintState, acct: &str, kp: &AuthKeypair, blind_msg_hex: &str) -> MintRequest {
        let challenge = state.app.challenges.issue(nil_core::grant::now_unix_secs()).expect("issue");
        MintRequest {
            auth: AccountAuth {
                account_number: acct.to_string(),
                challenge: challenge.clone(),
                signature: hex(&kp.sign(challenge.as_bytes())),
            },
            blind_msg: blind_msg_hex.to_string(),
        }
    }

    /// A valid blinded message for the given issuer (so blind_sign succeeds).
    fn blinded(issuer: &Issuer) -> String {
        let pub_der = issuer.public_der().unwrap();
        let msg = b"mint-nonce-0123456789abcdef0123".to_vec();
        let req = token::blind(&pub_der, &msg).unwrap();
        req.blind_msg.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn active_until_now_plus_30d() -> Entitlement {
        // Far-future expiry so it's unambiguously active under the real clock.
        Entitlement::Active { until: 4_000_000_000 }
    }

    #[tokio::test]
    async fn active_account_mints_a_blind_signature() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let state = state_with(issuer.clone(), 1000);
        let blind = blinded(&issuer);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        let resp = mint(peer(), State(state.clone()), Json(mint_req(&state, &acct, &kp, &blind)))
            .await
            .expect("mint ok");
        assert!(!resp.0.blind_sig.is_empty(), "a blind signature is returned");
        assert!(resp.0.blind_sig.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn account_without_active_subscription_is_refused() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let state = state_with(issuer.clone(), 1000);
        let blind = blinded(&issuer);
        // None, Expired, and a LAPSED Active (until in the past) all fail.
        for ent in [Entitlement::None, Entitlement::Expired, Entitlement::Active { until: 1 }] {
            let (kp, acct) = add_account(&state, ent).await;
            match mint(peer(), State(state.clone()), Json(mint_req(&state, &acct, &kp, &blind))).await {
                Err(ApiError::PaymentRequired) => {}
                other => panic!("expected PaymentRequired for {ent:?}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn per_account_rate_cap_is_enforced() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let state = state_with(issuer.clone(), 2); // cap of 2 mints/window
        let blind = blinded(&issuer);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        assert!(mint(peer(), State(state.clone()), Json(mint_req(&state, &acct, &kp, &blind))).await.is_ok());
        assert!(mint(peer(), State(state.clone()), Json(mint_req(&state, &acct, &kp, &blind))).await.is_ok());
        // Third within the window is capped.
        match mint(peer(), State(state.clone()), Json(mint_req(&state, &acct, &kp, &blind))).await {
            Err(ApiError::TooManyRequests) => {}
            other => panic!("expected TooManyRequests, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn per_account_cap_is_not_bypassable_by_hex_case() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let state = state_with(issuer.clone(), 1); // cap of 1 mint/window
        let blind = blinded(&issuer);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        // First mint with the lowercase account number succeeds.
        assert!(mint(peer(), State(state.clone()), Json(mint_req(&state, &acct, &kp, &blind)))
            .await
            .is_ok());

        // Same account, account number in UPPERCASE hex: hex decode is case-insensitive and the auth
        // signature covers only the challenge, so this authenticates as the SAME account. It must
        // therefore hit the SAME per-account bucket and be capped — not handed a fresh mint budget.
        let acct_upper = acct.to_uppercase();
        assert_ne!(acct_upper, acct, "test precondition: the account hex contains at least one a-f");
        match mint(peer(), State(state.clone()), Json(mint_req(&state, &acct_upper, &kp, &blind))).await {
            Err(ApiError::TooManyRequests) => {}
            other => panic!("hex-case variant must share the per-account cap, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_replayed_challenge_does_not_mint() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let state = state_with(issuer.clone(), 1000);
        let blind = blinded(&issuer);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        let req = mint_req(&state, &acct, &kp, &blind);
        assert!(mint(peer(), State(state.clone()), Json(req.clone())).await.is_ok());
        // Same proof again → the challenge was consumed → Unauthorized.
        match mint(peer(), State(state.clone()), Json(req)).await {
            Err(ApiError::Unauthorized) => {}
            other => panic!("expected Unauthorized on replay, got {other:?}"),
        }
    }
}
