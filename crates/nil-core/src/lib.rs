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
/// SEV-SNP this is the 48-byte launch `MEASUREMENT`; for TDX a domain-separated digest over
/// the TD measurements (`MRTD`/`RTMR`s) so both TEEs compare uniformly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurement(pub Vec<u8>);

/// What the client expects a node to attest to — the Coordinator publishes this and the
/// client refuses to tunnel unless the node's report matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestExpectation {
    pub tee: Tee,
    pub measurement: Measurement,
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
        }
    }
}

/// A short-lived, identity-free credential issued by the Coordinator against a
/// redeemed Privacy Pass token. Phase 0 treats it as an opaque byte blob; the real
/// grant format lands with the Coordinator in Phase 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub token: Vec<u8>,
    /// Fresh per-connection nonce. The client generates it, sends it to the node in the
    /// RA-TLS challenge, and `nil-attest` requires it to be bound into the report's
    /// `report_data` — proving the report was minted for *this* connection (freshness).
    pub nonce: [u8; 32],
}

impl Grant {
    /// A placeholder grant for transports (e.g. loopback) that don't check it yet. The
    /// zero nonce is fine here because loopback performs no attestation.
    pub fn mock() -> Self {
        Self { token: Vec::new(), nonce: [0u8; 32] }
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
