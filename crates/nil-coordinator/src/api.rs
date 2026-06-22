//! The Coordinator's HTTP API (architecture spec §8): hand the client a path + the
//! measurement each hop must attest to, and publish the pinned measurement set.
//!
//! This is the **verifier / policy** side of Pillar 4 — it never issues tokens (that is the
//! Portal's job, kept in a separate trust domain) and never sees traffic. Phase 2 stub-accepts
//! any non-empty entitlement; the real Privacy Pass verifier (separate from the issuer) and
//! trust-split multi-hop selection land in Phase 3.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use nil_proto::path::{MeasurementsResponse, PathRequest, PathResponse, PinnedMeasurement};

use crate::config::CoordConfig;

pub fn router(cfg: Arc<CoordConfig>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/path", post(request_path))
        .route("/v1/measurements", get(measurements))
        .with_state(cfg)
}

/// Whether an entitlement proof is acceptable. Phase 2: any non-empty value (the real
/// Privacy Pass token verifier arrives in Phase 3, in its own module/trust domain).
fn entitlement_ok(req: &PathRequest) -> bool {
    !req.entitlement.trim().is_empty()
}

fn path_for(cfg: &CoordConfig) -> PathResponse {
    PathResponse { hops: vec![cfg.hop.clone()] }
}

fn measurements_for(cfg: &CoordConfig) -> MeasurementsResponse {
    MeasurementsResponse {
        measurements: vec![PinnedMeasurement {
            tee: cfg.hop.tee,
            measurement: cfg.hop.measurement.clone(),
            source: None,
        }],
    }
}

async fn request_path(
    State(cfg): State<Arc<CoordConfig>>,
    Json(req): Json<PathRequest>,
) -> Result<Json<PathResponse>, StatusCode> {
    if !entitlement_ok(&req) {
        // No valid entitlement → no path. (The Coordinator learns only *that* a valid
        // subscriber connected, never *which* one — there is no identity here.)
        return Err(StatusCode::PAYMENT_REQUIRED);
    }
    Ok(Json(path_for(&cfg)))
}

async fn measurements(State(cfg): State<Arc<CoordConfig>>) -> Json<MeasurementsResponse> {
    Json(measurements_for(&cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nil_proto::path::Tee;

    fn cfg() -> CoordConfig {
        CoordConfig {
            addr: "127.0.0.1:9090".parse().unwrap(),
            hop: nil_proto::path::Hop {
                host: "entry.example".into(),
                port: 443,
                tee: Tee::SevSnp,
                measurement: "aa".repeat(48),
                wg_pub: None,
            },
        }
    }

    #[test]
    fn path_returns_the_pinned_hop() {
        let p = path_for(&cfg());
        assert_eq!(p.hops.len(), 1);
        assert_eq!(p.hops[0].host, "entry.example");
        assert_eq!(p.hops[0].measurement, "aa".repeat(48));
    }

    #[test]
    fn measurements_publish_the_pin() {
        let m = measurements_for(&cfg());
        assert_eq!(m.measurements.len(), 1);
        assert_eq!(m.measurements[0].tee, Tee::SevSnp);
    }

    #[test]
    fn empty_entitlement_is_rejected() {
        assert!(!entitlement_ok(&PathRequest { entitlement: "  ".into() }));
        assert!(entitlement_ok(&PathRequest { entitlement: "token".into() }));
    }
}
