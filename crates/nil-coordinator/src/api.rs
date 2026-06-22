//! The Coordinator's HTTP API (architecture spec §6, §7, §8): redeem a Privacy Pass token for
//! a trust-split path, and publish pinned measurements. This is the **verifier / policy** side
//! of Pillar 4 — it verifies tokens with the issuer's *public* key (never mints them), keeps
//! only a spent-token nullifier set (no identity), and selects operator/jurisdiction-diverse
//! paths. It never imports the Portal (issuer) and never sees traffic.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use nil_core::durable::DurableSet;
use nil_proto::path::{MeasurementsResponse, PathRequest, PathResponse, PinnedMeasurement};
use nil_proto::token::RedeemRequest;

use crate::config::{from_hex, CoordConfig};
use crate::nullifier::NullifierStore;

/// Shared state: the immutable config + the durable spent-token nullifier set.
#[derive(Clone)]
pub struct CoordState {
    pub cfg: Arc<CoordConfig>,
    /// Spent token messages (hex). Identity-free — just "this token was already redeemed".
    /// Durable across restarts (file-backed, or clustered Postgres in production); a volatile set
    /// would re-permit a double-spend of every already-redeemed token. Behind the
    /// [`NullifierStore`] trait so the backend is swappable.
    pub nullifiers: Arc<dyn NullifierStore>,
}

impl CoordState {
    /// Dev/test state with a volatile (in-memory) nullifier set.
    pub fn new(cfg: Arc<CoordConfig>) -> Self {
        Self { cfg, nullifiers: Arc::new(DurableSet::in_memory()) }
    }

    /// Production state with a caller-provided (durable) nullifier set.
    pub fn with_nullifiers(cfg: Arc<CoordConfig>, nullifiers: Arc<dyn NullifierStore>) -> Self {
        Self { cfg, nullifiers }
    }
}

pub fn router(state: CoordState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/path", post(request_path))
        .route("/v1/redeem", post(redeem))
        .route("/v1/measurements", get(measurements))
        .with_state(state)
}

#[derive(Debug, PartialEq)]
pub enum RedeemError {
    /// No issuer public key configured — redemption is disabled.
    NotConfigured,
    /// The token message or signature wasn't valid hex.
    Malformed,
    /// The token signature didn't verify under the issuer's public key.
    BadToken,
    /// The token was already redeemed (nullifier hit) — double-spend.
    AlreadyRedeemed,
    /// The nullifier could not be durably recorded — fail closed (grant nothing) rather than
    /// risk a double-spend on the next restart.
    Unavailable,
    /// No operator/jurisdiction-diverse path of the requested length exists right now.
    NoPath,
}

/// Core redemption logic (HTTP-free, unit-tested): verify the token, enforce single-use via
/// the nullifier set, and select a trust-split path. Returns the path only on success.
pub async fn redeem_logic(state: &CoordState, req: &RedeemRequest) -> Result<PathResponse, RedeemError> {
    let verifier = state.cfg.verifier.as_ref().ok_or(RedeemError::NotConfigured)?;
    let msg = from_hex(&req.msg).ok_or(RedeemError::Malformed)?;
    let token = from_hex(&req.token).ok_or(RedeemError::Malformed)?;

    if !verifier.verify(&token, &msg) {
        return Err(RedeemError::BadToken);
    }
    // Single-use: durably record this token message, rejecting it if already spent. The key is
    // the token itself — there is no account or identity in the nullifier set. We persist BEFORE
    // selecting a path, and fail closed if the record can't be made durable (a path granted on
    // an unpersisted nullifier would be double-spendable after a restart).
    match state.nullifiers.insert_once(&req.msg).await {
        Ok(true) => {}                                        // newly spent — proceed
        Ok(false) => return Err(RedeemError::AlreadyRedeemed), // replay
        Err(e) => {
            tracing::error!("nullifier persist failed: {e}");
            return Err(RedeemError::Unavailable);
        }
    }
    let hops = state.cfg.registry.select_path(state.cfg.path_hops).ok_or(RedeemError::NoPath)?;
    Ok(PathResponse { hops })
}

async fn redeem(
    State(state): State<CoordState>,
    Json(req): Json<RedeemRequest>,
) -> Result<Json<PathResponse>, StatusCode> {
    match redeem_logic(&state, &req).await {
        Ok(path) => Ok(Json(path)),
        Err(RedeemError::NotConfigured) => Err(StatusCode::NOT_IMPLEMENTED),
        Err(RedeemError::Malformed) => Err(StatusCode::BAD_REQUEST),
        Err(RedeemError::BadToken) => Err(StatusCode::UNAUTHORIZED),
        Err(RedeemError::AlreadyRedeemed) => Err(StatusCode::CONFLICT),
        Err(RedeemError::Unavailable) => Err(StatusCode::SERVICE_UNAVAILABLE),
        Err(RedeemError::NoPath) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// `/v1/path` — Phase-2 compatibility: an entitlement-gated path without a token (stub-accepts
/// a non-empty entitlement). Real entitlement is the token redeemed at `/v1/redeem`.
async fn request_path(
    State(state): State<CoordState>,
    Json(req): Json<PathRequest>,
) -> Result<Json<PathResponse>, StatusCode> {
    if req.entitlement.trim().is_empty() {
        return Err(StatusCode::PAYMENT_REQUIRED);
    }
    let hops = state
        .cfg
        .registry
        .select_path(state.cfg.path_hops)
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(PathResponse { hops }))
}

async fn measurements(State(state): State<CoordState>) -> Json<MeasurementsResponse> {
    let mut seen: HashSet<String> = HashSet::new();
    let measurements = state
        .cfg
        .registry
        .nodes
        .iter()
        .filter(|n| seen.insert(n.measurement.clone()))
        .map(|n| PinnedMeasurement { tee: n.tee, measurement: n.measurement.clone(), source: None })
        .collect();
    Json(MeasurementsResponse { measurements })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pathsel::NodeRegistry;
    use nil_crypto::{token, Issuer, Verifier};

    /// A coordinator state whose verifier matches a freshly-generated issuer, plus a valid
    /// `(msg, token)` minted by that issuer.
    fn state_and_token() -> (CoordState, RedeemRequest) {
        let issuer = Issuer::generate().unwrap();
        let pub_der = issuer.public_der().unwrap();
        let verifier = Verifier::from_public_der(&pub_der).unwrap();

        let msg = b"a-random-token-nonce-0123456789ab".to_vec();
        let req = token::blind(&pub_der, &msg).unwrap();
        let blind_sig = issuer.blind_sign(&req.blind_msg).unwrap();
        let tok = token::finalize(&pub_der, &req, &blind_sig).unwrap();

        let cfg = CoordConfig {
            addr: "127.0.0.1:9090".parse().unwrap(),
            registry: NodeRegistry::dev_default(),
            path_hops: 3,
            verifier: Some(verifier),
            nullifier_path: None,
        };
        let redeem = RedeemRequest { msg: hex(&msg), token: hex(&tok) };
        (CoordState::new(Arc::new(cfg)), redeem)
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[tokio::test]
    async fn valid_token_redeems_for_a_diverse_path_exactly_once() {
        let (state, req) = state_and_token();
        // First redemption: a 3-hop trust-split path.
        let path = redeem_logic(&state, &req).await.expect("valid token redeems");
        assert_eq!(path.hops.len(), 3);
        // Replay: the same token is now spent (nullifier) — double-spend rejected.
        assert!(matches!(redeem_logic(&state, &req).await, Err(RedeemError::AlreadyRedeemed)));
    }

    #[tokio::test]
    async fn redeemed_token_stays_spent_across_a_coordinator_restart() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nil-coord-nullifier-{}-{}.log",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);

        // The same config (and thus the same token verifier) persists across the restart; only
        // the nullifier set is reloaded from disk.
        let (state0, req) = state_and_token();
        let cfg = state0.cfg.clone();
        drop(state0);

        // Boot 1: file-backed nullifier. First redemption of this token succeeds.
        let boot1 = CoordState::with_nullifiers(cfg.clone(), Arc::new(DurableSet::open(&path).unwrap()));
        assert!(redeem_logic(&boot1, &req).await.is_ok(), "first redemption succeeds");
        drop(boot1); // simulate a Coordinator crash/restart

        // Boot 2: same verifier, nullifier reloaded from the SAME file. The replayed token must
        // be rejected — this is the regression guard for the volatile-state double-spend bug.
        let boot2 = CoordState::with_nullifiers(cfg, Arc::new(DurableSet::open(&path).unwrap()));
        assert!(
            matches!(redeem_logic(&boot2, &req).await, Err(RedeemError::AlreadyRedeemed)),
            "a token redeemed before the restart must stay spent after it"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn forged_token_is_rejected() {
        let (state, mut req) = state_and_token();
        req.token = hex(&vec![0u8; 256]); // not the issuer's signature
        assert!(matches!(redeem_logic(&state, &req).await, Err(RedeemError::BadToken)));
    }

    #[tokio::test]
    async fn redemption_disabled_without_an_issuer_key() {
        let cfg = CoordConfig {
            addr: "127.0.0.1:9090".parse().unwrap(),
            registry: NodeRegistry::dev_default(),
            path_hops: 3,
            verifier: None,
            nullifier_path: None,
        };
        let state = CoordState::new(Arc::new(cfg));
        let req = RedeemRequest { msg: "00".into(), token: "00".into() };
        assert!(matches!(redeem_logic(&state, &req).await, Err(RedeemError::NotConfigured)));
    }
}
