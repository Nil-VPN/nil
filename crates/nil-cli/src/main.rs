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
use nil_transport::{MasqueConfig, MasqueTransport, PathTransport, PqWgTransport, Transport};
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

/// A multi-hop trust-split path from `NW_PATH`: a comma-separated list of `host:port` hops,
/// outermost (entry) first, innermost (exit) last — e.g. `entry:443,middle:443,exit:443`. Set
/// ⇒ build a nested-MASQUE onion (architecture spec §6); unset ⇒ single hop. Every hop is
/// pinned to the same `expected` measurement here (the Docker harness builds all nodes from one
/// binary); in production the Coordinator supplies a distinct, operator-diverse pin per hop.
fn path_from_env(expected: &Option<AttestExpectation>) -> Result<Option<Vec<NodeEndpoint>>> {
    let Ok(spec) = std::env::var("NW_PATH") else { return Ok(None) };
    let mut hops = Vec::new();
    for (i, item) in spec.split(',').map(str::trim).filter(|s| !s.is_empty()).enumerate() {
        let (host, port) = item
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("NW_PATH hop {i} must be host:port, got {item:?}"))?;
        let port: u16 = port.parse().with_context(|| format!("NW_PATH hop {i} port {port:?}"))?;
        hops.push(NodeEndpoint {
            host: host.to_string(),
            port,
            kind: TransportKind::Masque,
            wg_pub: None,
            expected: expected.clone(),
        });
    }
    if hops.is_empty() {
        anyhow::bail!("NW_PATH is set but lists no hops");
    }
    Ok(Some(hops))
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
    let path = path_from_env(&expected)?;

    // Pick the transport. The datapath sizes the TUN from the tunnel's *negotiated* MTU, so the
    // value here is just a ceiling (nested hops shrink it further).
    //   - NW_PATH set        → multi-hop trust-split onion (plain nested MASQUE).
    //   - NW_NODE_WG_PUB set → inner PQ-WireGuard over a single MASQUE hop.
    //   - otherwise          → a single plain MASQUE hop.
    // `routing_node` is the directly-reachable hop the datapath excepts from the kill-switch.
    let (transport, routing_node, mtu): (Arc<dyn Transport>, NodeEndpoint, u16) =
        if let Some(hops) = path {
            if wg_pub.is_some() {
                tracing::warn!(
                    "NW_PATH set — ignoring NW_NODE_WG_PUB; multi-hop uses plain nested MASQUE"
                );
            }
            let entry = hops[0].clone();
            tracing::info!(hops = hops.len(), entry = %entry.host, "multi-hop trust-split path");
            // The inner hops' QUIC is stamped with the client tunnel address so the relaying
            // nodes' NAT (scoped to their tunnel CIDR) rewrites it and replies route back.
            let inner = MasqueTransport::with_config(MasqueConfig {
                nested_client_ip: Some(client_ip),
                ..Default::default()
            });
            let t = PathTransport::new(Arc::new(inner), hops);
            (Arc::new(t), entry, 1280)
        } else {
            let node = NodeEndpoint {
                host: host.clone(),
                port,
                kind: TransportKind::Masque,
                wg_pub,
                expected,
            };
            if wg_pub.is_some() {
                (Arc::new(PqWgTransport::new(Arc::new(MasqueTransport::new()))), node, 1232)
            } else {
                (Arc::new(MasqueTransport::new()), node, 1280)
            }
        };
    let cfg = TunnelConfig {
        node: routing_node,
        tun_name,
        client_ip,
        peer_ip,
        prefix: 24,
        mtu,
        dns,
        kill_switch,
    };

    tracing::info!(node = %cfg.node.host, port = cfg.node.port, "nil-cli connecting…");
    let tunnel = Tunnel::up(transport, cfg).await?;
    tracing::info!("nil-cli connected — tunnel up. Ctrl-C to disconnect.");

    tokio::signal::ctrl_c().await.context("waiting for ctrl_c")?;
    tracing::info!("disconnecting…");
    tunnel.down().await?;
    Ok(())
}
