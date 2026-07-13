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

/// Exact Intel TDX workload policy, encoded as canonical lowercase hex. For a TDX hop,
/// `measurement` is NIL's domain-separated SHA-384 identity digest over MRTD and these exact
/// report-body fields. This structure supplies the appraisal values while the independently pinned
/// digest binds them as one identity a compromised Coordinator cannot freely substitute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdxPolicy {
    /// Exact 8-byte TDATTRIBUTES value (16 lowercase hex characters).
    pub td_attributes: String,
    /// Exact 8-byte XFAM value (16 lowercase hex characters).
    pub xfam: String,
    /// Exact 48-byte MRCONFIGID value (96 lowercase hex characters).
    pub mr_config_id: String,
    /// Exact 48-byte MROWNER value (96 lowercase hex characters).
    pub mr_owner: String,
    /// Exact 48-byte MROWNERCONFIG value (96 lowercase hex characters).
    pub mr_owner_config: String,
    /// Exact 48-byte runtime measurement registers (96 lowercase hex characters each).
    pub rt_mr0: String,
    pub rt_mr1: String,
    pub rt_mr2: String,
    pub rt_mr3: String,
    /// Absent requires a TDREPORT 1.0 body; present pins the 48-byte MRSERVICETD in a 1.5 body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mr_service_td: Option<String>,
}

/// One hop the client should connect to, with the measurement it must attest to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    pub host: String,
    pub port: u16,
    pub tee: Tee,
    /// Pinned 48-byte SEV-SNP launch measurement or complete NIL TDX identity, lowercase hex.
    pub measurement: String,
    /// SHA-256 of this node's exact TLS certificate SubjectPublicKeyInfo (lowercase hex). It is
    /// optional on the wire for debug/backward-compatible fixtures, but release Coordinators
    /// require it for every registry node and bind it into the per-hop NWG2 grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_spki_sha256: Option<String>,
    /// Node WireGuard static public key (lowercase hex) for the inner PQ-WireGuard handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_pub: Option<String>,
    /// Pinned minimum SEV-SNP platform TCB for this hop (offline floor). `None` ⇒ no floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_tcb_sevsnp: Option<SevSnpTcbFloor>,
    /// Exact Intel TDX workload policy. Required for TDX hops and invalid for SEV-SNP hops in a
    /// production registry; optional at the serde layer so old responses fail with a policy error
    /// rather than becoming undecodable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx_policy: Option<TdxPolicy>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> TdxPolicy {
        TdxPolicy {
            td_attributes: "0000001000000000".into(),
            xfam: "02".repeat(8),
            mr_config_id: "03".repeat(48),
            mr_owner: "04".repeat(48),
            mr_owner_config: "05".repeat(48),
            rt_mr0: "06".repeat(48),
            rt_mr1: "07".repeat(48),
            rt_mr2: "08".repeat(48),
            rt_mr3: "09".repeat(48),
            mr_service_td: Some("0a".repeat(48)),
        }
    }

    #[test]
    fn tdx_policy_round_trips_on_a_hop() {
        let hop = Hop {
            host: "node.example".into(),
            port: 443,
            tee: Tee::Tdx,
            measurement: "ab".repeat(48),
            tls_spki_sha256: Some("cd".repeat(32)),
            wg_pub: None,
            min_tcb_sevsnp: None,
            tdx_policy: Some(policy()),
            transparency_log_key: None,
            grant: None,
            grant_nonce: None,
        };
        let encoded = serde_json::to_vec(&hop).expect("serialize TDX hop");
        let decoded: Hop = serde_json::from_slice(&encoded).expect("deserialize TDX hop");
        assert_eq!(decoded.tdx_policy, hop.tdx_policy);
    }

    #[test]
    fn tdx_policy_rejects_unknown_fields() {
        let mut value = serde_json::to_value(policy()).expect("serialize policy");
        value
            .as_object_mut()
            .expect("policy object")
            .insert("unreviewed_identity".into(), serde_json::json!("00"));
        assert!(serde_json::from_value::<TdxPolicy>(value).is_err());
    }
}
