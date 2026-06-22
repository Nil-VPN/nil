//! Node configuration from environment. No identifying state is persisted.

use std::net::{Ipv4Addr, SocketAddr};

/// A node's position in a trust-split path (architecture spec §6). Entry sees the client IP
/// but not the destination; exit sees the destination but not the client IP; middle sees
/// neither. Phase 2/3 implements the exit datapath (NAT to the internet); entry/middle
/// forwarding to the next hop is the nested-tunnel integration tracked with the inner-WG work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    Entry,
    Middle,
    Exit,
}

impl NodeRole {
    fn from_env_str(s: &str) -> Self {
        match s {
            "entry" => NodeRole::Entry,
            "middle" => NodeRole::Middle,
            _ => NodeRole::Exit,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// UDP listen address (default `0.0.0.0:443`; privileged port → needs root).
    pub bind: SocketAddr,
    /// Name of the node's TUN device.
    pub tun_name: String,
    /// Address assigned to the node end of the tunnel.
    pub node_tun_ip: Ipv4Addr,
    /// Tunnel subnet prefix length.
    pub prefix: u8,
    /// `network/prefix` CIDR for the NAT source match (e.g. `10.74.0.0/24`).
    pub tunnel_cidr: String,
    /// Egress interface for NAT (default `eth0` — the container's uplink).
    pub egress: String,
    /// TUN MTU (kept under the QUIC datagram limit; see nil-transport MTU notes).
    pub mtu: u16,
    /// What this node attests to (from the environment). `None` ⇒ serve unattested (dev).
    pub attest: Option<crate::attest::NodeAttest>,
    /// This node's position in a trust-split path (`NW_NODE_ROLE`: entry|middle|exit).
    pub role: NodeRole,
}

impl NodeConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let bind = std::env::var("NW_NODE_BIND")
            .unwrap_or_else(|_| "0.0.0.0:443".to_string())
            .parse()
            .map_err(|e| anyhow::anyhow!("NW_NODE_BIND: {e}"))?;
        let egress = std::env::var("NW_NODE_EGRESS").unwrap_or_else(|_| "eth0".to_string());
        // Phase 1 fixed addressing (no ADDRESS_ASSIGN capsule yet — see ADR/plan).
        Ok(Self {
            bind,
            tun_name: std::env::var("NW_NODE_TUN").unwrap_or_else(|_| "nil0".to_string()),
            node_tun_ip: "10.74.0.1".parse().expect("valid ip"),
            prefix: 24,
            tunnel_cidr: "10.74.0.0/24".to_string(),
            egress,
            // The TUN carries decapsulated client IP packets out to the next hop / internet. For
            // a trust-split path those packets are the next hop's QUIC wrapped in udpip (spec
            // §6), up to the outer tunnel's MTU (~1411 B at the 1420 B payload ceiling), in BOTH
            // directions. A 1280 TUN silently drops the larger nested handshake/response packets,
            // so it must clear the wrapped size; 1420 matches the QUIC payload ceiling. (Single
            // hop is unaffected: real packets stay ≤ the client's ~1280 TUN.)
            mtu: 1420,
            attest: crate::attest::NodeAttest::from_env(),
            role: NodeRole::from_env_str(
                &std::env::var("NW_NODE_ROLE").unwrap_or_else(|_| "exit".to_string()),
            ),
        })
    }
}
