//! The Coordinator's HTTP API (architecture spec §6, §7, §8): redeem a Privacy Pass token for
//! a trust-split path, and publish pinned measurements. This is the **verifier / policy** side
//! of Pillar 4 — it verifies tokens with the issuer's *public* key (never mints them), keeps
//! only a spent-token nullifier set (no identity), and selects operator/jurisdiction-diverse
//! paths. It never imports the Portal (issuer) and never sees traffic.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use nil_proto::path::{MeasurementsResponse, PathRequest, PathResponse, PinnedMeasurement};
use nil_proto::token::RedeemRequest;

use crate::config::{from_hex, CoordConfig};

/// Shared state: the immutable config + the mutable spent-token nullifier set.
#[derive(Clone)]
pub struct CoordState {
    pub cfg: Arc<CoordConfig>,
    /// Spent token messages (hex). Identity-free — just "this token was already redeemed".
    pub nullifiers: Arc<Mutex<HashSet<String>>>,
}

impl CoordState {
    pub fn new(cfg: Arc<CoordConfig>) -> Self {
        Self { cfg, nullifiers: Arc::new(Mutex::new(HashSet::new())) }
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
    /// No operator/jurisdiction-diverse path of the requested length exists right now.
    NoPath,
}

/// Core redemption logic (HTTP-free, unit-tested): verify the token, enforce single-use via
/// the nullifier set, and select a trust-split path. Returns the path only on success.
pub fn redeem_logic(state: &CoordState, req: &RedeemRequest) -> Result<PathResponse, RedeemError> {
    let verifier = state.cfg.verifier.as_ref().ok_or(RedeemError::NotConfigured)?;
    let msg = from_hex(&req.msg).ok_or(RedeemError::Malformed)?;
    let token = from_hex(&req.token).ok_or(RedeemError::Malformed)?;

    if !verifier.verify(&token, &msg) {
        return Err(RedeemError::BadToken);
    }
    // Single-use: reject if this token message was already spent, else record it. The key is
    // the token itself — there is no account or identity in the nullifier set.
    {
        let mut spent = state.nullifiers.lock().expect("nullifier mutex");
        if !spent.insert(req.msg.clone()) {
            return Err(RedeemError::AlreadyRedeemed);
        }
    }
    let hops = state.cfg.registry.select_path(state.cfg.path_hops).ok_or(RedeemError::NoPath)?;
    Ok(PathResponse { hops })
}

async fn redeem(
    State(state): State<CoordState>,
    Json(req): Json<RedeemRequest>,
) -> Result<Json<PathResponse>, StatusCode> {
    match redeem_logic(&state, &req) {
        Ok(path) => Ok(Json(path)),
        Err(RedeemError::NotConfigured) => Err(StatusCode::NOT_IMPLEMENTED),
        Err(RedeemError::Malformed) => Err(StatusCode::BAD_REQUEST),
        Err(RedeemError::BadToken) => Err(StatusCode::UNAUTHORIZED),
        Err(RedeemError::AlreadyRedeemed) => Err(StatusCode::CONFLICT),
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
        };
        let redeem = RedeemRequest { msg: hex(&msg), token: hex(&tok) };
        (CoordState::new(Arc::new(cfg)), redeem)
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn valid_token_redeems_for_a_diverse_path_exactly_once() {
        let (state, req) = state_and_token();
        // First redemption: a 3-hop trust-split path.
        let path = redeem_logic(&state, &req).expect("valid token redeems");
        assert_eq!(path.hops.len(), 3);
        // Replay: the same token is now spent (nullifier) — double-spend rejected.
        assert!(matches!(redeem_logic(&state, &req), Err(RedeemError::AlreadyRedeemed)));
    }

    #[test]
    fn forged_token_is_rejected() {
        let (state, mut req) = state_and_token();
        req.token = hex(&vec![0u8; 256]); // not the issuer's signature
        assert!(matches!(redeem_logic(&state, &req), Err(RedeemError::BadToken)));
    }

    #[test]
    fn redemption_disabled_without_an_issuer_key() {
        let cfg = CoordConfig {
            addr: "127.0.0.1:9090".parse().unwrap(),
            registry: NodeRegistry::dev_default(),
            path_hops: 3,
            verifier: None,
        };
        let state = CoordState::new(Arc::new(cfg));
        let req = RedeemRequest { msg: "00".into(), token: "00".into() };
        assert!(matches!(redeem_logic(&state, &req), Err(RedeemError::NotConfigured)));
    }
}
