//! NIL VPN headless client (`nil-cli`).
//!
//! Brings up a MASQUE/CONNECT-IP tunnel to a `nil-node` and routes this host's traffic
//! through it (TUN + fail-closed kill-switch via `nil-datapath`). This is the Linux/Docker
//! test client and a real headless CLI. The Tauri desktop app reuses the same
//! `MasqueTransport` + `nil-datapath` pieces (macOS datapath is Phase 1b).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
use nil_core::{NodeEndpoint, TransportKind};
use nil_datapath::{Tunnel, TunnelConfig};
use nil_transport::{MasqueTransport, Transport};
use tracing_subscriber::EnvFilter;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let host = env_or("NW_NODE_HOST", "node");
    let port: u16 = env_or("NW_NODE_PORT", "443").parse().context("NW_NODE_PORT")?;
    let tun_name = env_or("NW_TUN", "nil0");
    let client_ip: Ipv4Addr = env_or("NW_CLIENT_IP", "10.74.0.2").parse().context("NW_CLIENT_IP")?;
    let peer_ip: Ipv4Addr = env_or("NW_PEER_IP", "10.74.0.1").parse().context("NW_PEER_IP")?;
    let dns: Vec<IpAddr> = env_or("NW_DNS", "1.1.1.1")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().parse::<IpAddr>().map_err(|e| anyhow::anyhow!("NW_DNS {s}: {e}")))
        .collect::<Result<_>>()?;
    let kill_switch = env_or("NW_KILLSWITCH", "1") != "0";

    let transport: Arc<dyn Transport> = Arc::new(MasqueTransport::new());
    let cfg = TunnelConfig {
        node: NodeEndpoint {
            host: host.clone(),
            port,
            kind: TransportKind::Masque,
            wg_pub: None,     // wired from NW_NODE_WG_PUB in the PqWgTransport step
            expected: None,   // wired from the Coordinator's pinned measurement in the wiring step
        },
        tun_name,
        client_ip,
        peer_ip,
        prefix: 24,
        mtu: 1280,
        dns,
        kill_switch,
    };

    tracing::info!(%host, port, "nil-cli connecting to node…");
    let tunnel = Tunnel::up(transport, cfg).await?;
    tracing::info!("nil-cli connected — tunnel up. Ctrl-C to disconnect.");

    tokio::signal::ctrl_c().await.context("waiting for ctrl_c")?;
    tracing::info!("disconnecting…");
    tunnel.down().await?;
    Ok(())
}
