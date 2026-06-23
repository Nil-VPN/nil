//! Coordinator path-selection + measurement-publishing DTOs (architecture spec §8).
//!
//! The client redeems a Privacy Pass token at `/v1/redeem` to learn which node(s) to connect to
//! and the measurement each must attest to; it then refuses to tunnel unless `nil-attest` confirms
//! the node's report matches. A single-hop path is the closed alpha; trust-split multi-hop paths
//! with operator/jurisdiction diversity are the next milestone. Pure serde data — no logic.

use serde::{Deserialize, Serialize};

/// TEE family a node attests with (wire form; mirrors `nil_core::Tee`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tee {
    SevSnp,
    Tdx,
}

/// One hop the client should connect to, with the measurement it must attest to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    pub host: String,
    pub port: u16,
    pub tee: Tee,
    /// Pinned code measurement, lowercase hex.
    pub measurement: String,
    /// Node WireGuard static public key (lowercase hex) for the inner PQ-WireGuard handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_pub: Option<String>,
}

/// `POST /v1/redeem` response: the (ordered) hops forming the path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathResponse {
    pub hops: Vec<Hop>,
}

/// One published, transparency-logged measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedMeasurement {
    pub tee: Tee,
    pub measurement: String,
    /// Where the measurement was published (e.g. a Rekor log index/UUID). Informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// `GET /v1/measurements` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementsResponse {
    pub measurements: Vec<PinnedMeasurement>,
}
