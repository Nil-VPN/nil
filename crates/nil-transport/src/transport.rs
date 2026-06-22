//! The `Transport` trait, defined exactly as in architecture spec §4.
//!
//! The bare `Result` in the spec binds to [`nil_core::Result`]; the referenced types
//! (`NodeEndpoint`, `Grant`, `Session`, `IpPacket`, `TransportKind`, `Profile`) all
//! live in `nil-core`. The trait body is otherwise reproduced verbatim.

use async_trait::async_trait;
use nil_core::{Grant, IpPacket, NodeEndpoint, Profile, Result, Session, TransportKind};

#[async_trait]
pub trait Transport: Send + Sync {
    /// Negotiate the outer tunnel to a node (after RA-TLS verification).
    async fn connect(&self, target: NodeEndpoint, creds: Grant) -> Result<Session>;
    /// Inject an IP packet into the tunnel.
    async fn send(&self, session: &Session, packet: IpPacket) -> Result<()>;
    /// Receive the next IP packet from the tunnel.
    async fn recv(&self, session: &Session) -> Result<IpPacket>;
    /// Tear down cleanly (and trigger kill-switch hold on failure).
    async fn close(&self, session: Session) -> Result<()>;

    fn kind(&self) -> TransportKind; // Masque | AmneziaWg | Wstunnel | Reality
    fn fingerprint_profile(&self) -> Profile; // how it should look on the wire
}
