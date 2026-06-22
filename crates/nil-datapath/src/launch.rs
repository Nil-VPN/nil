//! Build the client transport + [`TunnelConfig`] from the environment — the shared launcher
//! used by BOTH the headless `nil-cli` and the desktop GUI engine, so the two can never drift
//! on how a tunnel is configured (architecture spec §3: the client reuses the exact same code).
//!
//! Behind the `launch` feature, which pulls the MASQUE / PQ-WireGuard transports. It selects:
//!   - `NW_PATH` set  → a multi-hop trust-split onion ([`PathTransport`], spec §6);
//!   - `NW_NODE_WG_PUB` set → inner PQ-WireGuard over a single MASQUE hop (spec §4.2);
//!   - otherwise → a single plain MASQUE hop.
//!
//! The datapath sizes the TUN from the tunnel's *negotiated* MTU, so the `mtu` here is only a
//! ceiling.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
use nil_core::{AttestExpectation, Measurement, NodeEndpoint, Tee, TransportKind};
use nil_transport::{connectip, MasqueConfig, MasqueTransport, PathTransport, PqWgTransport, Transport};

use crate::TunnelConfig;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Whether the environment configures a real node/path (vs. nothing → the GUI uses loopback).
pub fn is_configured() -> bool {
    std::env::var("NW_NODE_HOST").is_ok() || std::env::var("NW_PATH").is_ok()
}

/// The pinned attestation expectation (`NW_EXPECTED_MEASUREMENT` hex + `NW_EXPECTED_TEE`).
/// Unset ⇒ `None` ⇒ the connection is unattested (a warning is logged by the transport).
pub fn expected_from_env() -> Result<Option<AttestExpectation>> {
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

/// The node's WireGuard static public key (hex) from `NW_NODE_WG_PUB`, if set.
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

/// A multi-hop trust-split path from `NW_PATH` (`host:port,host:port,...`, entry first). Every
/// hop is pinned to the same `expected` measurement here; production gets a per-operator pin per
/// hop from the Coordinator.
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

/// Build the transport and a [`TunnelConfig`] from the environment. The returned `node` is the
/// directly-reachable hop (a single node, or a path's entry) the kill-switch excepts.
pub fn from_env() -> Result<(Arc<dyn Transport>, TunnelConfig)> {
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

    let (transport, routing_node, mtu): (Arc<dyn Transport>, NodeEndpoint, u16) =
        if let Some(hops) = path {
            if wg_pub.is_some() {
                tracing::warn!("NW_PATH set — ignoring NW_NODE_WG_PUB; multi-hop uses plain nested MASQUE");
            }
            let entry = hops[0].clone();
            tracing::info!(hops = hops.len(), "multi-hop trust-split path");
            // The inner hops' QUIC is stamped with the client tunnel address so the relaying
            // nodes' NAT (scoped to their tunnel CIDR) rewrites it and replies route back.
            let inner = MasqueTransport::with_config(MasqueConfig {
                nested_client_ip: Some(client_ip),
                ..Default::default()
            });
            (Arc::new(PathTransport::new(Arc::new(inner), hops)), entry, 1280)
        } else {
            let node = NodeEndpoint { host: host.clone(), port, kind: TransportKind::Masque, wg_pub, expected };
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
    Ok((transport, cfg))
}
