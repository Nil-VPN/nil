//! The `Transport` trait, defined exactly as in architecture spec §4.
//!
//! The bare `Result` in the spec binds to [`nil_core::Result`]; the referenced types
//! (`NodeEndpoint`, `Grant`, `Session`, `IpPacket`, `TransportKind`, `Profile`) all
//! live in `nil-core`. The spec methods are reproduced verbatim; [`Transport::tunnel_mtu`] is
//! an additive, defaulted accessor the datapath uses to size the TUN (it changes no behavior
//! for existing transports).

use std::net::Ipv4Addr;

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

    /// Usable inner MTU for a live session (the largest IP packet the tunnel can carry in one
    /// frame), if known. The datapath sizes the TUN device from this; nested transports use it
    /// to shrink each hop's payload. `None` ⇒ unknown (the default; e.g. loopback).
    fn tunnel_mtu(&self, _session: &Session) -> Option<usize> {
        None
    }

    /// The inner IPv4 address the node assigned this session from its tunnel pool (RFC 9484
    /// ADDRESS_ASSIGN subset), if the node signalled one. The datapath applies it to the TUN so
    /// concurrent clients never collide on one inner address. `None` ⇒ no assignment (the default;
    /// loopback/dev, or a node that doesn't assign) ⇒ the datapath keeps its configured address
    /// (single-client fallback). Additive + defaulted: changes nothing for existing transports.
    fn assigned_ip(&self, _session: &Session) -> Option<Ipv4Addr> {
        None
    }
}
