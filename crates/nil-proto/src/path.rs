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

/// A pinned minimum SEV-SNP platform TCB (firmware patch levels), wire form of
/// `nil_core::SevSnpTcbFloor`. The client refuses a hop whose reported `current_tcb` is below this
/// (component-wise). `None` fields/absent ⇒ no floor. Kept as a plain DTO so `nil-proto` stays
/// dependency-free; the client maps it to `nil_core::SevSnpTcbFloor` at redemption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SevSnpTcbFloor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmc: Option<u8>,
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
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
    /// Pinned minimum SEV-SNP platform TCB for this hop (offline floor). `None` ⇒ no floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_tcb_sevsnp: Option<SevSnpTcbFloor>,
    /// Pinned transparency-log Ed25519 public key (lowercase hex, 32 bytes). When present, the
    /// client requires this hop's measurement to be proven present in that log via a stapled
    /// inclusion proof, or refuses the hop. `None` ⇒ measurement pin alone gates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_log_key: Option<String>,
    /// Short-lived opaque Coordinator grant for this hop, lowercase hex. The client never
    /// interprets it; it forwards it to the node in CONNECT-IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    /// Fresh nonce bound into both the grant and the node's attestation report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_nonce: Option<String>,
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
