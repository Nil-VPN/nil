//! Subscription: a confirmed payment activates/extends an *anonymous* account (ADR-0007).
//!
//! ## Flow
//! 1. `POST /v1/billing/subscribe` — the client authenticates (challenge + signature), the Portal
//!    mints an unguessable 256-bit payment reference and records a **binding** that ties the
//!    reference to the account, then returns the reference. The buyer pays it (Monero / card).
//! 2. `POST /v1/billing/activate` — once the payment confirms, the client authenticates again and
//!    presents the reference; the Portal verifies the binding (only the account that subscribed for
//!    a reference can activate with it), checks the payment is confirmed, and sets the entitlement
//!    to `Active { until = max(now, current_until) + 30d }` (extend/stack). One activation per
//!    reference (a durable guard, like one-token-per-payment).
//!
//! ## Privacy (PD-4)
//! The binding is stored as a **hash** `H("nil.subscription.v1.binding" ‖ reference ‖ account)`,
//! never as a plaintext `reference → account` row, so the database holds no direct payment↔account
//! link: a reader who doesn't already know the (unguessable) reference learns nothing. The Portal
//! (business plane) is *allowed* to know "this anonymous account is a subscriber"; the control/data
//! plane never sees any of this, and connections still ride anonymous blind tokens.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::routing::post;
use axum::{Json, Router};
use sha2::{Digest, Sha256};

use nil_core::durable::{DurableSet, TimedDurableSet};
use nil_core::grant::{now_unix_secs, now_unix_secs_for_expiry};
use nil_proto::account::{AccountAuth, AccountStatusResponse, ActivateRequest};
use nil_proto::token::CheckoutResponse;

use crate::account::auth::authenticate;
use crate::account::error::ApiError;
use crate::account::handlers::map_auth_err;
use crate::account::model::Entitlement;
use crate::billing::mint_reference;
use crate::monero::PaymentWatcher;
use crate::ratelimit::RateLimiter;
use crate::state::AppState;

/// One subscription period, in seconds (30 days). A confirmed payment grants/extends by this much.
const THIRTY_DAYS_SECS: u64 = 30 * 24 * 60 * 60;

/// Hard cap on subscribe/activate request bodies. An auth proof is ~260 B and a reference is 64
/// hex chars; 16 KiB is generous. Mirrors the other endpoints' body-amplification guard.
const SUB_BODY_LIMIT: usize = 16 * 1024;

/// Per-IP cap on subscribe/activate. Activate is polled while a payment confirms, so this is a bit
/// generous (matches the token-issue limiter). The IP is used transiently for the counter only —
/// never stored, logged, or tied to an account.
const SUB_RATE_MAX: u32 = 30;
const SUB_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Subscription-plane state. Embeds the account [`AppState`] (so it shares the SAME account store
/// and challenge set used by `/v1/account/challenge` — auth must be cross-endpoint), plus the
/// payment watcher and the two durable sets that make activation safe.
#[derive(Clone)]
pub struct SubscriptionState {
    pub app: AppState,
    pub watcher: Arc<dyn PaymentWatcher>,
    /// `H(ref‖account)` for references a client has subscribed for but not yet activated. TIMED so
    /// abandoned subscriptions age out; durable so a confirmed payment can be activated after a
    /// restart. Enforces "only the account that subscribed for a reference can activate it".
    pub bindings: Arc<TimedDurableSet>,
    /// `H(ref‖account)` for references already activated — one extension per payment, durable and
    /// never pruned (mirrors the one-token-per-payment `issued` set). Blocks double-extend.
    pub activated: Arc<DurableSet>,
    pub limiter: Arc<RateLimiter>,
}

impl SubscriptionState {
    pub fn new(
        app: AppState,
        watcher: Arc<dyn PaymentWatcher>,
        bindings: Arc<TimedDurableSet>,
        activated: Arc<DurableSet>,
    ) -> Self {
        Self {
            app,
            watcher,
            bindings,
            activated,
            limiter: Arc::new(RateLimiter::new(SUB_RATE_MAX, SUB_RATE_WINDOW)),
        }
    }
}

/// The durable-set key binding a payment reference to an account: a domain-separated hash, so the
/// stored value reveals neither the reference nor the account to a database reader.
fn binding_key(reference: &str, account_number: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"nil.subscription.v1.binding");
    h.update(reference.as_bytes());
    h.update(account_number);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn subscription_router(state: SubscriptionState) -> Router {
    Router::new()
        .route("/v1/billing/subscribe", post(subscribe))
        .route("/v1/billing/activate", post(activate))
        .layer(DefaultBodyLimit::max(SUB_BODY_LIMIT))
        .with_state(state)
}

/// `POST /v1/billing/subscribe` — authenticate, mint a payment reference, bind it to the account.
async fn subscribe(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<SubscriptionState>,
    Json(auth): Json<AccountAuth>,
) -> Result<Json<CheckoutResponse>, ApiError> {
    if !state.limiter.check(&peer.ip().to_string()) {
        return Err(ApiError::TooManyRequests);
    }
    // The challenge is a gate ("is this a live, owned account?") → fail-closed clock.
    let record = authenticate(&state.app, &auth, now_unix_secs_for_expiry())
        .await
        .map_err(map_auth_err)?;
    let account = record.account_number;

    let reference = mint_reference().map_err(|e| {
        tracing::error!("subscribe reference CSPRNG failed: {e}"); // never log the reference
        ApiError::Internal
    })?;
    let key = binding_key(&reference, &account);
    // Record the binding durably BEFORE returning the reference, so a payment that confirms (even
    // after a restart) can still be activated. The TTL stamp uses the issuance clock.
    match state.bindings.insert(&key, now_unix_secs()) {
        Ok(true) => Ok(Json(CheckoutResponse { payment_reference: reference })),
        // A 256-bit reference collision is impossible; refuse rather than hand back a bound one.
        Ok(false) => {
            tracing::error!("subscribe binding collision (impossible) — refusing");
            Err(ApiError::Internal)
        }
        Err(e) => {
            tracing::error!("subscribe binding persist failed: {e}");
            Err(ApiError::Internal)
        }
    }
}

/// `POST /v1/billing/activate` — claim a confirmed payment to activate/extend the subscription.
async fn activate(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<SubscriptionState>,
    Json(req): Json<ActivateRequest>,
) -> Result<Json<AccountStatusResponse>, ApiError> {
    if !state.limiter.check(&peer.ip().to_string()) {
        return Err(ApiError::TooManyRequests);
    }
    let record = authenticate(&state.app, &req.auth, now_unix_secs_for_expiry())
        .await
        .map_err(map_auth_err)?;
    let account = record.account_number;
    let key = binding_key(&req.payment_reference, &account);

    // Front-running / theft guard: the reference must be one THIS account subscribed for. An
    // unknown/expired binding is the same Unauthorized as a bad auth — no oracle.
    if !state.bindings.contains(&key) {
        return Err(ApiError::Unauthorized);
    }
    // The payment must be confirmed on-chain. Not yet ⇒ 402, the client retries later.
    if !state.watcher.is_confirmed(&req.payment_reference) {
        return Err(ApiError::PaymentRequired);
    }
    // The new expiry is MINTED, so use the issuance clock. A broken clock (now == 0, i.e. a system
    // time before the Unix epoch) must NOT mint an epoch-dated grant — refuse, and do so BEFORE
    // consuming the activation guard so the client can retry once the clock is sane (fail closed).
    let mint_now = now_unix_secs();
    if mint_now == 0 {
        tracing::error!("activate: system clock before the Unix epoch — refusing to mint a subscription");
        return Err(ApiError::Internal);
    }

    // One activation per (reference, account): record the guard BEFORE extending, durably. Fail
    // closed — like the one-token-per-payment `issued` set, a persist failure refuses rather than
    // risk a double-extend on the next restart. A replay after success finds it already present.
    match state.activated.insert(&key) {
        Ok(true) => {}
        Ok(false) => return Err(ApiError::Conflict),
        Err(e) => {
            tracing::error!("activated-set persist failed: {e}");
            return Err(ApiError::Internal);
        }
    }

    // Atomically extend by 30d, stacking on the account's PERSISTED expiry (read under the store
    // lock/row, not the pre-guard snapshot in `record`) so two concurrent activations of distinct
    // confirmed payments each add their period instead of one overwriting the other.
    let until = match state.app.store.extend_subscription(&account, mint_now, THIRTY_DAYS_SECS).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            // The account vanished between auth and update (a delete race) — treat as internal.
            tracing::error!("activate: account not found during entitlement extend");
            return Err(ApiError::Internal);
        }
        Err(e) => {
            tracing::error!("activate: extend_subscription failed: {e}");
            return Err(ApiError::Internal);
        }
    };

    let resolved = Entitlement::Active { until }.resolved(mint_now);
    Ok(Json(AccountStatusResponse { entitlement: resolved.into(), until: resolved.active_until(mint_now) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::extract::connect_info::ConnectInfo;
    use nil_crypto::account::{create_account_os, AuthKeypair, DerivedAccount};

    use crate::account::model::AccountRecord;
    use crate::monero::MockWatcher;
    use crate::store::memory::InMemoryStore;
    use crate::store::Store;

    fn peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("1.2.3.4:9999".parse().unwrap())
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn state_with(watcher: Arc<dyn PaymentWatcher>) -> SubscriptionState {
        let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
        // A generous limiter so polling activate in a test doesn't hit 429.
        let mut s = SubscriptionState::new(
            AppState::new(store),
            watcher,
            Arc::new(TimedDurableSet::in_memory()),
            Arc::new(DurableSet::in_memory()),
        );
        s.limiter = Arc::new(RateLimiter::new(10_000, Duration::from_secs(60)));
        s
    }

    /// Insert a fresh account into the store; return its derived material + account-number hex.
    async fn add_account(state: &SubscriptionState) -> (DerivedAccount, AuthKeypair, String) {
        let d = create_account_os();
        state
            .app
            .store
            .insert(AccountRecord {
                account_number: *d.account_number.as_bytes(),
                recovery_code_hash: d.recovery_code_hash,
                entitlement: Entitlement::None,
                auth_pubkey: d.auth_public_key,
            })
            .await
            .expect("insert");
        let kp = AuthKeypair::from_phrase(&d.recovery_phrase).expect("kp");
        let acct_hex = hex(d.account_number.as_bytes());
        (d, kp, acct_hex)
    }

    /// Build a fresh, signed auth proof against the account's live challenge set.
    fn proof(state: &SubscriptionState, acct_hex: &str, kp: &AuthKeypair) -> AccountAuth {
        let challenge = state.app.challenges.issue(now_unix_secs()).expect("issue");
        AccountAuth {
            account_number: acct_hex.to_string(),
            challenge: challenge.clone(),
            signature: hex(&kp.sign(challenge.as_bytes())),
        }
    }

    async fn do_subscribe(state: &SubscriptionState, acct_hex: &str, kp: &AuthKeypair) -> String {
        let auth = proof(state, acct_hex, kp);
        let resp = subscribe(peer(), State(state.clone()), Json(auth)).await.expect("subscribe ok");
        resp.0.payment_reference
    }

    async fn do_activate(
        state: &SubscriptionState,
        acct_hex: &str,
        kp: &AuthKeypair,
        reference: &str,
    ) -> Result<AccountStatusResponse, ApiError> {
        let req = ActivateRequest { auth: proof(state, acct_hex, kp), payment_reference: reference.to_string() };
        activate(peer(), State(state.clone()), Json(req)).await.map(|j| j.0)
    }

    #[tokio::test]
    async fn subscribe_then_activate_grants_about_thirty_days() {
        let watcher = Arc::new(MockWatcher::confirm_everything());
        let state = state_with(watcher);
        let (d, kp, acct) = add_account(&state).await;

        let reference = do_subscribe(&state, &acct, &kp).await;
        let now = now_unix_secs();
        let status = do_activate(&state, &acct, &kp, &reference).await.expect("activate ok");

        assert_eq!(status.entitlement, nil_proto::account::EntitlementDto::Active);
        let until = status.until.expect("active has an expiry");
        assert!(until >= now + THIRTY_DAYS_SECS - 5 && until <= now + THIRTY_DAYS_SECS + 5, "≈ now + 30d");

        // And the store actually reflects the new entitlement.
        let rec = state.app.store.get(d.account_number.as_bytes()).await.unwrap().unwrap();
        assert!(matches!(rec.entitlement, Entitlement::Active { .. }));
    }

    #[tokio::test]
    async fn activating_an_active_subscription_stacks_the_time() {
        let watcher = Arc::new(MockWatcher::confirm_everything());
        let state = state_with(watcher);
        let (d, kp, acct) = add_account(&state).await;

        // Pre-set an active subscription 10 days out (10d from now via the atomic extend).
        let now = now_unix_secs();
        let existing_until = state
            .app
            .store
            .extend_subscription(d.account_number.as_bytes(), now, 10 * 24 * 60 * 60)
            .await
            .unwrap()
            .unwrap();
        assert!(existing_until >= now + 10 * 24 * 60 * 60 - 5);

        let reference = do_subscribe(&state, &acct, &kp).await;
        let status = do_activate(&state, &acct, &kp, &reference).await.expect("activate ok");
        let until = status.until.expect("active");
        // Stacks ON TOP of the existing expiry, not from now.
        assert!(until >= existing_until + THIRTY_DAYS_SECS - 5 && until <= existing_until + THIRTY_DAYS_SECS + 5);
    }

    #[tokio::test]
    async fn the_same_payment_cannot_activate_twice() {
        let watcher = Arc::new(MockWatcher::confirm_everything());
        let state = state_with(watcher);
        let (_d, kp, acct) = add_account(&state).await;

        let reference = do_subscribe(&state, &acct, &kp).await;
        assert!(do_activate(&state, &acct, &kp, &reference).await.is_ok());
        // A second activation of the same reference is a conflict (no double-extend).
        match do_activate(&state, &acct, &kp, &reference).await {
            Err(ApiError::Conflict) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unconfirmed_payment_is_payment_required() {
        // Watcher confirms nothing.
        let watcher = Arc::new(MockWatcher::with_paid([]));
        let state = state_with(watcher);
        let (_d, kp, acct) = add_account(&state).await;

        let reference = do_subscribe(&state, &acct, &kp).await;
        match do_activate(&state, &acct, &kp, &reference).await {
            Err(ApiError::PaymentRequired) => {}
            other => panic!("expected PaymentRequired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn another_account_cannot_activate_someone_elses_reference() {
        let watcher = Arc::new(MockWatcher::confirm_everything());
        let state = state_with(watcher);
        let (_da, kpa, acct_a) = add_account(&state).await;
        let (_db, kpb, acct_b) = add_account(&state).await;

        // A subscribes and gets a reference; B (a different account) tries to activate with it.
        let reference = do_subscribe(&state, &acct_a, &kpa).await;
        match do_activate(&state, &acct_b, &kpb, &reference).await {
            // B's binding key (H(ref‖B)) was never recorded → indistinguishable Unauthorized.
            Err(ApiError::Unauthorized) => {}
            other => panic!("expected Unauthorized, got {other:?}"),
        }
        // And B's attempt did NOT consume A's ability to activate.
        assert!(do_activate(&state, &acct_a, &kpa, &reference).await.is_ok());
    }

    #[tokio::test]
    async fn two_confirmed_payments_stack_cumulatively() {
        // Two DISTINCT confirmed payments on the same account must each add a full period — the
        // second stacks on the first's expiry, never overwrites it (the atomic `extend_subscription`
        // reads the persisted expiry under the store lock, not a pre-guard snapshot).
        let watcher = Arc::new(MockWatcher::confirm_everything());
        let state = state_with(watcher);
        let (_d, kp, acct) = add_account(&state).await;
        let now = now_unix_secs();

        let r1 = do_subscribe(&state, &acct, &kp).await;
        let after1 = do_activate(&state, &acct, &kp, &r1).await.expect("activate 1").until.expect("active");
        assert!(after1 >= now + THIRTY_DAYS_SECS - 5, "first payment grants ~30d");

        let r2 = do_subscribe(&state, &acct, &kp).await;
        let after2 = do_activate(&state, &acct, &kp, &r2).await.expect("activate 2").until.expect("active");
        assert!(
            after2 >= after1 + THIRTY_DAYS_SECS - 5 && after2 <= after1 + THIRTY_DAYS_SECS + 5,
            "the second distinct payment stacks ANOTHER ~30d (≈60d total), it does not overwrite"
        );
    }

    #[tokio::test]
    async fn a_pruned_binding_cannot_be_activated() {
        // An abandoned subscription ages out: once its binding is pruned (the TTL sweep), the payment
        // can no longer be claimed even if the watcher would confirm it — the front-running guard
        // (`bindings.contains`) is checked before the payment, so a missing binding is Unauthorized.
        let watcher = Arc::new(MockWatcher::confirm_everything());
        let state = state_with(watcher);
        let (_d, kp, acct) = add_account(&state).await;

        let reference = do_subscribe(&state, &acct, &kp).await;
        // Prune with a cutoff far past the insertion time → drops the single pending binding.
        let pruned = state.bindings.prune_older_than(now_unix_secs() + 100_000).expect("prune");
        assert_eq!(pruned, 1, "the one pending binding is pruned");
        match do_activate(&state, &acct, &kp, &reference).await {
            Err(ApiError::Unauthorized) => {}
            other => panic!("expected Unauthorized after the binding was pruned, got {other:?}"),
        }
    }
}
