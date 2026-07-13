//! Shared domain types for NIL VPN — no async, no wire obligations.
//!
//! These are the in-process types that the [`Transport`](../nil_transport/trait.Transport.html)
//! trait passes between the engine and any tunnel implementation. Serialized wire
//! formats and API DTOs live in `nil-proto`; this crate stays free of serde framing
//! decisions so the transport seam never recompiles when the wire format evolves.
//!
//! The one I/O-touching module is [`durable`] — a small, self-contained, restart-safe key set
//! shared by the control and business planes (the Coordinator nullifier set and the Portal
//! one-token-per-payment set). It is plain `std::fs`, no async, no new dependencies.

pub mod checksum;
pub mod durable;
pub mod grant;
pub mod net;

use serde::{Deserialize, Serialize};

/// Opaque identifier for a live transport session.
///
/// A [`Session`] is a lightweight handle — the transport keeps the heavy per-session
/// state (sockets, queues, crypto) internally, keyed by this id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

/// Which tunnel implementation is in use. Drives the obfuscation cascade
/// (MASQUE → AmneziaWG → wstunnel → REALITY); `Loopback` is a test/scaffold-only
/// variant that never appears on a real wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportKind {
    Masque,
    AmneziaWg,
    Wstunnel,
    Reality,
    Loopback,
}

/// How a transport is meant to look on the wire (its fingerprint profile).
/// `Internal` is the loopback/scaffold profile — never observed by a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Indistinguishable from ordinary HTTPS/QUIC on UDP 443 (MASQUE default).
    HttpsQuic,
    /// WireGuard-derived but DPI-resistant with randomized headers (AmneziaWG).
    Wireguardish,
    /// Looks like a WebSocket-over-TLS application (wstunnel).
    WebSocketTls,
    /// Borrows a real TLS handshake (VLESS+REALITY).
    RealTlsBorrowed,
    /// In-memory loopback; not a wire profile.
    Internal,
}

/// Which TEE family produced an attestation report. The verifier (`nil-attest`) picks the
/// parse + signature-chain path from this. Kept here (not in `nil-attest`) so `NodeEndpoint`
/// can carry an expectation without a dependency cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tee {
    /// AMD SEV-SNP.
    SevSnp,
    /// Intel TDX.
    Tdx,
}

/// An expected code measurement, opaque bytes compared for equality during appraisal. For
/// SEV-SNP this is the 48-byte launch `MEASUREMENT`; for TDX it is NIL's domain-separated
/// SHA-384 digest over MRTD, exact workload policy fields, RTMRs, and report-body identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurement(pub Vec<u8>);

/// A pinned minimum AMD SEV-SNP platform TCB (firmware patch levels). A node whose report shows a
/// `current_tcb` below this floor — even if it has NOT rolled back below its own `committed_tcb` —
/// is running an old patch level that may lack fixes for known SEV-SNP vulnerabilities, so it is
/// treated as out-of-date and refused under default policy. The floor value is deployment-specific
/// (it advances as AMD ships microcode/firmware) and is sourced from `snpguest report` on validated
/// hardware, then pinned by the Coordinator / client — never fetched online. `None` enforces no floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SevSnpTcbFloor {
    /// Firmware (FMC) patch level — present only on Turin+; `None` means "don't require an FMC floor".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmc: Option<u8>,
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

impl SevSnpTcbFloor {
    /// True iff every reported TCB component is at or above this floor, compared COMPONENT-WISE
    /// (not the lexicographic `TcbVersion` order): a node ahead on one component but behind on
    /// another must fail, since any lagging component can be the one carrying a security fix.
    pub fn is_met_by(
        &self,
        fmc: Option<u8>,
        bootloader: u8,
        tee: u8,
        snp: u8,
        microcode: u8,
    ) -> bool {
        bootloader >= self.bootloader
            && tee >= self.tee
            && snp >= self.snp
            && microcode >= self.microcode
            && match self.fmc {
                Some(required) => fmc.unwrap_or(0) >= required,
                None => true,
            }
    }
}

/// Exact Intel TDX workload policy pinned by a relying party.
///
/// A cryptographically valid DCAP quote is only a statement about the values in its TD report;
/// it does not say that those values describe the workload NIL intended to run.  Production TDX
/// appraisal therefore compares every security-relevant, workload-controlled field below rather
/// than treating `MRTD` alone as the guest identity.  The QVL separately authenticates the TDX
/// module/platform TCB and rejects debug/reserved attribute combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdxMeasurement(pub [u8; 48]);

impl AsRef<[u8]> for TdxMeasurement {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 48]> for TdxMeasurement {
    fn from(value: [u8; 48]) -> Self {
        Self(value)
    }
}

// Serde's built-in array implementations stop at 32 elements. Keep the core representation
// length-safe and encode it as the same byte sequence/JSON array used by the surrounding DTOs.
impl Serialize for TdxMeasurement {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TdxMeasurement {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let len = bytes.len();
        let value = bytes.try_into().map_err(|_| {
            <D::Error as serde::de::Error>::custom(format!(
                "TDX measurement must be exactly 48 bytes, got {len}"
            ))
        })?;
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdxPolicy {
    /// Exact TDATTRIBUTES bytes.  This pins the security attributes in addition to the QVL's
    /// unconditional rejection of a debuggable TD.
    pub td_attributes: [u8; 8],
    /// Exact extended-feature mask made available to the TD.
    pub xfam: [u8; 8],
    /// Software-defined non-owner configuration identity.
    pub mr_config_id: TdxMeasurement,
    /// Software-defined TD owner identity.
    pub mr_owner: TdxMeasurement,
    /// Software-defined owner/workload configuration identity.
    pub mr_owner_config: TdxMeasurement,
    /// Runtime measurement registers.  NIL's production image policy assigns RTMR0 to firmware,
    /// RTMR1 to the boot loader/kernel, RTMR2 to the OS/runtime, and RTMR3 to the NIL workload.
    pub rt_mr0: TdxMeasurement,
    pub rt_mr1: TdxMeasurement,
    pub rt_mr2: TdxMeasurement,
    pub rt_mr3: TdxMeasurement,
    /// Quote-body policy: `None` requires a TDREPORT 1.0 body. `Some(value)` requires a TDREPORT
    /// 1.5 body whose `MRSERVICETD` equals `value`.  This prevents silently accepting a new report
    /// shape with an unpinned identity field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mr_service_td: Option<TdxMeasurement>,
}

/// What the client expects a node to attest to — the Coordinator publishes this and the
/// client refuses to tunnel unless the node's report matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestExpectation {
    pub tee: Tee,
    pub measurement: Measurement,
    /// Optional SHA-256 pin of the node certificate's exact DER SubjectPublicKeyInfo. Coordinator
    /// paths in production always carry this; `None` exists only for legacy/debug direct-node
    /// fixtures. When set, the client compares it in constant time before accepting attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_spki_sha256: Option<[u8; 32]>,
    /// Optional pinned minimum SEV-SNP platform TCB. `None` (the default, and the only value for a
    /// TDX endpoint) enforces no floor; a `Some` is checked offline during appraisal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_tcb_sevsnp: Option<SevSnpTcbFloor>,
    /// Exact workload/configuration identity required for Intel TDX. Production TDX endpoints
    /// always carry `Some`; SEV-SNP endpoints must carry `None`. The independently pinned
    /// `measurement` is a digest over these values and MRTD, so a Coordinator cannot broaden this
    /// policy while retaining the same client-trusted identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx_policy: Option<TdxPolicy>,
    /// Optional pinned transparency-log Ed25519 public key (32 bytes). When set, the client requires
    /// the node's measurement to be proven present in that log via a stapled RFC 6962 inclusion
    /// proof before any packet flows; `None` (the default) gates on the measurement pin alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_log_key: Option<[u8; 32]>,
}

/// Where to reach a node, plus (from Phase 2) the node's WireGuard static public key and the
/// expected TEE attestation. Loopback/pre-attestation endpoints leave the optionals `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEndpoint {
    pub host: String,
    pub port: u16,
    pub kind: TransportKind,
    /// The node's WireGuard static public key (Curve25519) for the inner PQ-WireGuard
    /// handshake. `None` for loopback or transports without an inner WG layer.
    pub wg_pub: Option<[u8; 32]>,
    /// What the node must attest to before any packet flows. `None` disables appraisal
    /// (loopback / tests only — a real MASQUE endpoint always carries one).
    pub expected: Option<AttestExpectation>,
    /// Optional short-lived Coordinator grant for this hop. Production Coordinator paths fill
    /// this and the node verifies it before accepting CONNECT-IP. Direct-node/dev paths may
    /// leave it empty only when the node explicitly allows ungranted tunnels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Grant>,
}

impl NodeEndpoint {
    /// A placeholder endpoint for the in-memory loopback transport.
    pub fn loopback() -> Self {
        Self {
            host: "loopback".to_string(),
            port: 0,
            kind: TransportKind::Loopback,
            wg_pub: None,
            expected: None,
            grant: None,
        }
    }
}

/// A short-lived, identity-free credential issued by the Coordinator against a redeemed Privacy
/// Pass token. `token` is intentionally opaque to clients/transports; the Coordinator mints it
/// and the node verifies it via [`grant`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub token: Vec<u8>,
    /// Fresh per-connection nonce created alongside the grant by the Coordinator. The client sends it
    /// to the node in the RA-TLS challenge, and `nil-attest` requires it to be bound into the report's
    /// `report_data` — proving the report was minted for *this* connection (freshness).
    pub nonce: [u8; 32],
}

// A grant is a live bearer credential. Its ordinary debug representation must remain safe even if
// a future caller uses `tracing!(?grant)` or includes it in an error context.
impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Grant([REDACTED])")
    }
}

impl Grant {
    /// A placeholder grant for transports (e.g. loopback) that don't check it yet. The
    /// zero nonce is fine here because loopback performs no attestation.
    pub fn mock() -> Self {
        Self {
            token: Vec::new(),
            nonce: [0u8; 32],
        }
    }
}

#[cfg(test)]
mod grant_debug_tests {
    use super::Grant;

    #[test]
    fn grant_debug_never_exposes_bearer_bytes() {
        let grant = Grant {
            token: vec![0xde, 0xad, 0xbe, 0xef],
            nonce: [0x11; 32],
        };
        assert_eq!(format!("{grant:?}"), "Grant([REDACTED])");
    }
}

/// A live transport session handle. `Copy` because it carries no owned state — the
/// transport owns the real per-session resources, keyed by [`SessionId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub kind: TransportKind,
}

/// A single IP packet flowing through the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPacket(Vec<u8>);

impl IpPacket {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for IpPacket {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Errors at the transport seam. Implementations map their internal failures onto
/// these so the engine never depends on a specific tunnel's error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("session not found: {0:?}")]
    SessionNotFound(SessionId),
    #[error("transport closed")]
    Closed,
    #[error("invalid packet: {0}")]
    InvalidPacket(String),
    #[error("transport error: {0}")]
    Transport(String),
}

/// Result alias used across the transport seam.
pub type Result<T> = std::result::Result<T, Error>;
