//! Shared domain types for NIL VPN — no I/O, no async, no wire obligations.
//!
//! These are the in-process types that the [`Transport`](../nil_transport/trait.Transport.html)
//! trait passes between the engine and any tunnel implementation. Serialized wire
//! formats and API DTOs live in `nil-proto`; this crate stays free of serde framing
//! decisions so the transport seam never recompiles when the wire format evolves.

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

/// Where to reach a node. In later phases this carries the node's public key and
/// the expected TEE measurement; Phase 0 keeps it to addressing only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEndpoint {
    pub host: String,
    pub port: u16,
    pub kind: TransportKind,
}

impl NodeEndpoint {
    /// A placeholder endpoint for the in-memory loopback transport.
    pub fn loopback() -> Self {
        Self {
            host: "loopback".to_string(),
            port: 0,
            kind: TransportKind::Loopback,
        }
    }
}

/// A short-lived, identity-free credential issued by the Coordinator against a
/// redeemed Privacy Pass token. Phase 0 treats it as an opaque byte blob; the real
/// grant format lands with the Coordinator in Phase 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub token: Vec<u8>,
}

impl Grant {
    /// A placeholder grant for transports (e.g. loopback) that don't check it yet.
    pub fn mock() -> Self {
        Self { token: Vec::new() }
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
