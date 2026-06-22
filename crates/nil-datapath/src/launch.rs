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
use nil_transport::cascade::{Cascade, CascadeTransport, DnsLivenessProbe};
use nil_transport::{
    connectip, AmneziaWgTransport, MasqueConfig, MasqueTransport, PathTransport, PqWgTransport, Transport,
    WstunnelTransport,
};

use crate::TunnelConfig;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// The AmneziaWG cascade fallback rung, if `NW_CASCADE` is set. Reads the fallback node's WG
/// pubkey (`NW_NODE_AMNEZIA_WG_PUB`, hex) and endpoint (`NW_NODE_AMNEZIA_HOST` /
/// `NW_NODE_AMNEZIA_PORT`, defaulting to the primary host / 443).
fn amneziawg_fallback_from_env() -> Result<Option<AmneziaWgTransport>> {
    if std::env::var("NW_CASCADE").is_err() {
        return Ok(None);
    }
    let Ok(h) = std::env::var("NW_NODE_AMNEZIA_WG_PUB") else {
        return Ok(None); // AmneziaWG rung is optional; a deployment may run wstunnel-only.
    };
    let bytes = connectip::from_hex(h.trim().as_bytes())
        .ok_or_else(|| anyhow::anyhow!("NW_NODE_AMNEZIA_WG_PUB is not valid hex"))?;
    let wg_pub: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("NW_NODE_AMNEZIA_WG_PUB must be 32 bytes"))?;
    let host = std::env::var("NW_NODE_AMNEZIA_HOST").ok();
    // Fail loudly on a present-but-invalid port (matching NW_NODE_PORT) rather than silently
    // falling back to the target port — an operator who typo'd a custom obfuscation port must hear
    // about it, not dial 443 by surprise.
    let port = std::env::var("NW_NODE_AMNEZIA_PORT")
        .ok()
        .map(|p| p.parse::<u16>().context("NW_NODE_AMNEZIA_PORT"))
        .transpose()?;
    Ok(Some(AmneziaWgTransport::new(wg_pub, host, port)))
}

/// The wstunnel cascade fallback rung (WireGuard over WebSocket-over-TLS), if `NW_CASCADE` is set
/// AND `NW_NODE_WSTUNNEL_WG_PUB` (hex) is given. Endpoint from `NW_NODE_WSTUNNEL_HOST` /
/// `NW_NODE_WSTUNNEL_PORT` (defaulting to the primary host / 443). Optional: a deployment may run
/// AmneziaWG, wstunnel, both, or neither as fallbacks.
fn wstunnel_fallback_from_env() -> Result<Option<WstunnelTransport>> {
    if std::env::var("NW_CASCADE").is_err() {
        return Ok(None);
    }
    let Ok(h) = std::env::var("NW_NODE_WSTUNNEL_WG_PUB") else {
        return Ok(None);
    };
    let bytes = connectip::from_hex(h.trim().as_bytes())
        .ok_or_else(|| anyhow::anyhow!("NW_NODE_WSTUNNEL_WG_PUB is not valid hex"))?;
    let wg_pub: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("NW_NODE_WSTUNNEL_WG_PUB must be 32 bytes"))?;
    let host = std::env::var("NW_NODE_WSTUNNEL_HOST").ok();
    // Fail loudly on a present-but-invalid port (see NW_NODE_AMNEZIA_PORT).
    let port = std::env::var("NW_NODE_WSTUNNEL_PORT")
        .ok()
        .map(|p| p.parse::<u16>().context("NW_NODE_WSTUNNEL_PORT"))
        .transpose()?;
    Ok(Some(WstunnelTransport::new(wg_pub, host, port)))
}

/// Whether the environment configures a real node/path (vs. nothing → the GUI uses loopback).
/// Includes `NW_COORDINATOR_URL` (the production source): `from_env` treats it as the
/// top-priority path source, so the GUI must not silently fall back to the loopback mock when
/// only the Coordinator URL is set.
pub fn is_configured() -> bool {
    std::env::var("NW_NODE_HOST").is_ok()
        || std::env::var("NW_PATH").is_ok()
        || std::env::var("NW_COORDINATOR_URL").is_ok()
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

/// Env-derived tunnel parameters shared by both launch entrypoints. The ONLY difference between
/// [`from_env`] and [`from_env_with_token`] is how the path is resolved (env token vs an
/// explicitly-supplied, in-process one); everything else comes from here.
struct TunnelParams {
    host: String,
    port: u16,
    tun_name: String,
    client_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    dns: Vec<IpAddr>,
    kill_switch: bool,
    allow_unattested: bool,
    expected: Option<AttestExpectation>,
    wg_pub: Option<[u8; 32]>,
}

fn params_from_env() -> Result<TunnelParams> {
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
    // Fail-closed by default: a MASQUE hop with no pinned measurement refuses to connect unless
    // NW_ALLOW_UNATTESTED is explicitly TRUE (dev/loopback only). `env_flag` accepts only "1"/"true"
    // — so `NW_ALLOW_UNATTESTED=0` keeps the gate ON (not the `is_ok()` footgun where any value,
    // including `0`, would loosen it). See `MasqueConfig::allow_unattested`.
    let allow_unattested = nil_core::net::env_flag("NW_ALLOW_UNATTESTED");
    let expected = expected_from_env()?;
    let wg_pub = wg_pub_from_env()?;
    Ok(TunnelParams { host, port, tun_name, client_ip, peer_ip, dns, kill_switch, allow_unattested, expected, wg_pub })
}

/// Build the transport + a [`TunnelConfig`] from resolved params + a resolved path. `path` is
/// `Some` for a trust-split / Coordinator-redeemed path (its first hop is the kill-switch
/// exception), `None` for a single configured node (which may be wrapped in the obfuscation
/// cascade). The transport assembly is identical regardless of how the path was obtained.
fn assemble(p: TunnelParams, path: Option<Vec<NodeEndpoint>>) -> Result<(Arc<dyn Transport>, TunnelConfig)> {
    let (transport, routing_node, mtu): (Arc<dyn Transport>, NodeEndpoint, u16) =
        if let Some(hops) = path {
            if p.wg_pub.is_some() {
                tracing::warn!("a path is configured — ignoring NW_NODE_WG_PUB; multi-hop uses plain nested MASQUE");
            }
            let entry = hops[0].clone();
            tracing::info!(hops = hops.len(), "trust-split path");
            // The inner hops' QUIC is stamped with the client tunnel address so the relaying
            // nodes' NAT (scoped to their tunnel CIDR) rewrites it and replies route back.
            let inner = MasqueTransport::with_config(MasqueConfig {
                nested_client_ip: Some(p.client_ip),
                allow_unattested: p.allow_unattested,
                ..Default::default()
            });
            (Arc::new(PathTransport::new(Arc::new(inner), hops)), entry, 1280)
        } else {
            let node = NodeEndpoint {
                host: p.host.clone(),
                port: p.port,
                kind: TransportKind::Masque,
                wg_pub: p.wg_pub,
                expected: p.expected.clone(),
            };
            // Primary rung: PQ-WireGuard-over-MASQUE if a node WG key is pinned, else plain MASQUE.
            let (primary, base_mtu): (Arc<dyn Transport>, u16) = if p.wg_pub.is_some() {
                let inner = MasqueTransport::with_config(MasqueConfig { allow_unattested: p.allow_unattested, ..Default::default() });
                (Arc::new(PqWgTransport::new(Arc::new(inner))), 1232)
            } else {
                (Arc::new(MasqueTransport::with_config(MasqueConfig { allow_unattested: p.allow_unattested, ..Default::default() })), 1280)
            };
            // With NW_CASCADE, wrap [primary, AmneziaWG?, wstunnel?] in a cascade that steps down
            // (timeout / dead-tunnel) and verifies each rung with a DNS liveness probe before
            // committing. Each fallback rung is independently optional (a deployment may run
            // either, both, or neither).
            let mut rungs: Vec<Arc<dyn Transport>> = vec![primary];
            if let Some(awg) = amneziawg_fallback_from_env()? {
                rungs.push(Arc::new(awg));
            }
            if let Some(wst) = wstunnel_fallback_from_env()? {
                rungs.push(Arc::new(wst));
            }
            if rungs.len() > 1 {
                tracing::info!(
                    rungs = rungs.len(),
                    "obfuscation cascade enabled (MASQUE primary → {} fallback rung(s))",
                    rungs.len() - 1
                );
                let cascade = Cascade::new(rungs)
                    .with_liveness_probe(Arc::new(DnsLivenessProbe::default()));
                (Arc::new(CascadeTransport::new(cascade)), node, base_mtu)
            } else {
                if std::env::var("NW_CASCADE").is_ok() {
                    anyhow::bail!(
                        "NW_CASCADE set but no fallback rung configured — set NW_NODE_AMNEZIA_WG_PUB and/or NW_NODE_WSTUNNEL_WG_PUB"
                    );
                }
                (rungs.into_iter().next().expect("primary rung"), node, base_mtu)
            }
        };

    // When the cascade is on, each fallback node's traffic must also bypass the tunnel (else the
    // fallback rung's own packets to its node would loop through the TUN, and — since the
    // kill-switch only opens the PRIMARY node on :443 — its custom port would be dropped). Only
    // except hosts that an ACTUALLY-ASSEMBLED fallback rung reaches (gated on the same key vars
    // that gate the rungs above), so NW_CASCADE alone never punches an all-ports kill-switch hole.
    let mut also_except: Vec<String> = Vec::new();
    if std::env::var("NW_CASCADE").is_ok() {
        let mut except_host = |env_key: &str| {
            let h = std::env::var(env_key).unwrap_or_else(|_| p.host.clone());
            if !also_except.contains(&h) {
                also_except.push(h);
            }
        };
        if std::env::var("NW_NODE_AMNEZIA_WG_PUB").is_ok() {
            except_host("NW_NODE_AMNEZIA_HOST");
        }
        if std::env::var("NW_NODE_WSTUNNEL_WG_PUB").is_ok() {
            except_host("NW_NODE_WSTUNNEL_HOST");
        }
    }

    let cfg = TunnelConfig {
        node: routing_node,
        tun_name: p.tun_name,
        client_ip: p.client_ip,
        peer_ip: p.peer_ip,
        prefix: 24,
        mtu,
        dns: p.dns,
        kill_switch: p.kill_switch,
        also_except,
    };
    Ok((transport, cfg))
}

/// Build the transport and a [`TunnelConfig`] from the environment. Path priority: (1) redeem a
/// Privacy Pass token at the Coordinator (`NW_COORDINATOR_URL` + `NW_TOKEN_MSG`/`NW_TOKEN[_FILE]`);
/// (2) a static `NW_PATH` onion (dev); (3) a single `NW_NODE_HOST`. Used by `nil-cli` (headless).
pub async fn from_env() -> Result<(Arc<dyn Transport>, TunnelConfig)> {
    let p = params_from_env()?;
    let path = if let Ok(url) = std::env::var("NW_COORDINATOR_URL") {
        Some(crate::redeem::redeem_path_from_env(&url).await?)
    } else {
        path_from_env(&p.expected)?
    };
    assemble(p, path)
}

/// Like [`from_env`], but the path is redeemed with a CALLER-SUPPLIED token (`msg` + `token`, both
/// hex) instead of `NW_TOKEN_MSG`/`NW_TOKEN`. The desktop engine holds the unblinded token
/// in-process (from its local token store) and passes it here — avoiding a bearer credential in
/// the process-global environment. All other tunnel params still come from the environment.
pub async fn from_env_with_token(
    coord_url: &str,
    msg: &str,
    token: &str,
) -> Result<(Arc<dyn Transport>, TunnelConfig)> {
    let p = params_from_env()?;
    let path = Some(crate::redeem::redeem_path(coord_url, msg, token).await?);
    assemble(p, path)
}
