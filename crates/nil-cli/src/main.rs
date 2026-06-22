//! NIL VPN headless client (`nil-cli`).
//!
//! Brings up a MASQUE/CONNECT-IP tunnel to a `nil-node` and routes this host's traffic
//! through it (TUN + fail-closed kill-switch via `nil-datapath`). This is the Linux/Docker
//! test client and a real headless CLI. The Tauri desktop app reuses the same
//! `MasqueTransport` + `nil-datapath` pieces (macOS datapath is Phase 1b).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
use nil_core::{AttestExpectation, Measurement, NodeEndpoint, Tee, TransportKind};
use nil_datapath::{Tunnel, TunnelConfig};
use nil_transport::connectip;
use nil_transport::{MasqueTransport, PqWgTransport, Transport};
use tracing_subscriber::EnvFilter;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Build the pinned attestation expectation from the environment. In production the client
/// gets this from the Coordinator's `RequestPath`; the Docker harness injects it directly.
/// `NW_EXPECTED_MEASUREMENT` = hex measurement, `NW_EXPECTED_TEE` = `sev-snp`|`tdx`.
/// Unset ⇒ `None` ⇒ the connection is unattested (a warning is logged).
fn expected_from_env() -> Result<Option<AttestExpectation>> {
    let Ok(hex) = std::env::var("NW_EXPECTED_MEASUREMENT") else { return Ok(None) };
    let bytes = connectip::from_hex(hex.trim().as_bytes())
        .ok_or_else(|| anyhow::anyhow!("NW_EXPECTED_MEASUREMENT is not valid hex"))?;
    let tee = match env_or("NW_EXPECTED_TEE", "sev-snp").as_str() {
        "tdx" => Tee::Tdx,
        "sev-snp" => Tee::SevSnp,
        other => anyhow::bail!("NW_EXPECTED_TEE must be sev-snp or tdx, got {other}"),
    };
    Ok(Some(AttestExpectation { tee, measurement: Measurement(bytes) }))
}

/// The node's WireGuard static public key (hex) from `NW_NODE_WG_PUB`. Present ⇒ run the inner
/// PQ-WireGuard layer over MASQUE; absent ⇒ plain MASQUE.
fn wg_pub_from_env() -> Result<Option<[u8; 32]>> {
    let Ok(h) = std::env::var("NW_NODE_WG_PUB") else { return Ok(None) };
    let bytes = connectip::from_hex(h.trim().as_bytes())
        .ok_or_else(|| anyhow::anyhow!("NW_NODE_WG_PUB is not valid hex"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("NW_NODE_WG_PUB must be 32 bytes"))?;
    Ok(Some(arr))
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
    let expected = expected_from_env()?;
    let wg_pub = wg_pub_from_env()?;

    // With a node WireGuard key, run the inner PQ-WireGuard layer over MASQUE (the TUN MTU
    // drops by WireGuard's 32-byte overhead); otherwise plain MASQUE.
    let (transport, mtu): (Arc<dyn Transport>, u16) = if wg_pub.is_some() {
        (Arc::new(PqWgTransport::new(Arc::new(MasqueTransport::new()))), 1232)
    } else {
        (Arc::new(MasqueTransport::new()), 1280)
    };
    let cfg = TunnelConfig {
        node: NodeEndpoint {
            host: host.clone(),
            port,
            kind: TransportKind::Masque,
            wg_pub,
            expected,
        },
        tun_name,
        client_ip,
        peer_ip,
        prefix: 24,
        mtu,
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
