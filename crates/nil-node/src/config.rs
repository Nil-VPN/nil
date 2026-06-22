//! Node configuration from environment. No identifying state is persisted.

use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// UDP listen address (default `0.0.0.0:443`; privileged port → needs root).
    pub bind: SocketAddr,
    /// Name of the node's TUN device.
    pub tun_name: String,
    /// Address assigned to the node end of the tunnel.
    pub node_tun_ip: Ipv4Addr,
    /// The client's (statically assigned) tunnel address — Phase 1 has one client.
    pub client_ip: Ipv4Addr,
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
            client_ip: "10.74.0.2".parse().expect("valid ip"),
            prefix: 24,
            tunnel_cidr: "10.74.0.0/24".to_string(),
            egress,
            mtu: 1280,
            attest: crate::attest::NodeAttest::from_env(),
        })
    }
}
