//! Build the client transport + [`TunnelConfig`] from the environment — the shared launcher
//! used by BOTH the headless `nil-cli` and the desktop GUI engine, so the two can never drift
//! on how a tunnel is configured (architecture spec §3: the client reuses the exact same code).
//!
//! Behind the `launch` feature, which pulls the MASQUE / PQ-WireGuard transports. It selects:
//!   - `NW_PATH` set  → a multi-hop trust-split onion ([`PathTransport`], spec §6);
//!   - `NW_NODE_WG_PUB` set → inner PQ-WireGuard over a single MASQUE hop (spec §4.2);
//!   - otherwise → a single plain MASQUE hop.
//!
//! A Coordinator-redeemed path (`NW_COORDINATOR_URL`) takes priority and is the production
//! multi-hop default (entry/middle/exit, exercised end-to-end by `deploy/verify-e2e.sh`). A single
//! configured node is a debug-only fallback: release builds reject it regardless of
//! `NW_FORCE_SINGLE_HOP` because one hop is not trust-split (PD-8). Endpoint rotation and
//! all-PQ-per-hop intermediate forwarding are tracked follow-ups (see `nil-transport::path`).
//!
//! The datapath sizes the TUN from the tunnel's *negotiated* MTU, so the `mtu` here is only a
//! ceiling.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
use nil_core::{AttestExpectation, Measurement, NodeEndpoint, SevSnpTcbFloor, Tee, TransportKind};
use nil_proto::path::TdxPolicy as WireTdxPolicy;
#[cfg(feature = "dev-fallbacks")]
use nil_transport::cascade::{Cascade, CascadeTransport, DnsLivenessProbe};
use nil_transport::{
    connectip, MasqueConfig, MasqueTransport, PathTransport, PqWgTransport, Transport,
};
#[cfg(feature = "dev-fallbacks")]
use nil_transport::{AmneziaWgTransport, WstunnelTransport};
#[cfg(feature = "selector")]
use nil_transport::{
    RealityConfig, RealityTransport, Selector, SelectorTransport, UdpReachabilityProbe,
};

use crate::TunnelConfig;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// The AmneziaWG cascade fallback rung, if `NW_CASCADE` is set. Reads the fallback node's WG
/// pubkey (`NW_NODE_AMNEZIA_WG_PUB`, hex) and endpoint (`NW_NODE_AMNEZIA_HOST` /
/// `NW_NODE_AMNEZIA_PORT`, defaulting to the primary host / 443).
#[cfg(feature = "dev-fallbacks")]
fn amneziawg_fallback_from_env() -> Result<Option<AmneziaWgTransport>> {
    if !nil_core::net::dev_env_flag("NW_CASCADE") {
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
#[cfg(feature = "dev-fallbacks")]
fn wstunnel_fallback_from_env() -> Result<Option<WstunnelTransport>> {
    if !nil_core::net::dev_env_flag("NW_CASCADE") {
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

/// Parse a fallback rung's WG pubkey (`<pub_var>`, hex) + optional endpoint (`<host_var>` /
/// `<port_var>`) — the shared shape used by the network-aware selector to build the AmneziaWG and
/// wstunnel rungs. Unlike [`amneziawg_fallback_from_env`], this is NOT gated on `NW_CASCADE` (the
/// selector is opt-in via `NW_SELECTOR` instead). `None` ⇒ `<pub_var>` unset (the rung is optional).
/// A parsed fallback rung endpoint: WG static pubkey + optional host/port override.
#[cfg(feature = "selector")]
type WgEndpoint = ([u8; 32], Option<String>, Option<u16>);

#[cfg(feature = "selector")]
fn parse_wg_endpoint(pub_var: &str, host_var: &str, port_var: &str) -> Result<Option<WgEndpoint>> {
    let Ok(h) = std::env::var(pub_var) else {
        return Ok(None);
    };
    let bytes = connectip::from_hex(h.trim().as_bytes())
        .ok_or_else(|| anyhow::anyhow!("{pub_var} is not valid hex"))?;
    let wg_pub: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{pub_var} must be 32 bytes"))?;
    let host = std::env::var(host_var).ok();
    let port = std::env::var(port_var)
        .ok()
        .map(|p| p.parse::<u16>().with_context(|| port_var.to_string()))
        .transpose()?;
    Ok(Some((wg_pub, host, port)))
}

/// The REALITY cascade rung for the selector's resistant path. Reads `NW_REALITY_WG_PUB` (hex),
/// endpoint (`NW_REALITY_HOST` / `NW_REALITY_PORT`, defaulting to the primary host / 443), and the
/// borrowed-site SNI (`NW_REALITY_SNI`). `None` ⇒ `NW_REALITY_WG_PUB` unset (the rung is optional).
/// Returns the rung AND its except-host (captured from the SINGLE `NW_REALITY_HOST` read), so the
/// caller's kill-switch exception matches the host the transport actually dials (no second env read
/// that could TOCTOU-mismatch).
#[cfg(feature = "selector")]
fn reality_from_env() -> Result<Option<(RealityTransport, Option<String>)>> {
    let Some((wg_pub, host, port)) =
        parse_wg_endpoint("NW_REALITY_WG_PUB", "NW_REALITY_HOST", "NW_REALITY_PORT")?
    else {
        return Ok(None);
    };
    let sni = std::env::var("NW_REALITY_SNI").ok();
    let except_host = host.clone();
    Ok(Some((
        RealityTransport::with_config(RealityConfig {
            node_wg_pub: wg_pub,
            host,
            port,
            sni,
        }),
        except_host,
    )))
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
    let Ok(hex) = std::env::var("NW_EXPECTED_MEASUREMENT") else {
        if std::env::var_os("NW_TDX_POLICY_JSON").is_some() {
            anyhow::bail!(
                "NW_TDX_POLICY_JSON requires NW_EXPECTED_MEASUREMENT and NW_EXPECTED_TEE=tdx"
            );
        }
        return Ok(None);
    };
    let bytes = connectip::from_hex(hex.trim().as_bytes())
        .ok_or_else(|| anyhow::anyhow!("NW_EXPECTED_MEASUREMENT is not valid hex"))?;
    let tee = match env_or("NW_EXPECTED_TEE", "sev-snp").as_str() {
        "tdx" => Tee::Tdx,
        "sev-snp" => Tee::SevSnp,
        other => anyhow::bail!("NW_EXPECTED_TEE must be sev-snp or tdx, got {other}"),
    };
    let min_tcb_sevsnp = min_tcb_sevsnp_from_env()?;
    if tee == Tee::Tdx && min_tcb_sevsnp.is_some() {
        anyhow::bail!("NW_MIN_TCB_SEVSNP is invalid when NW_EXPECTED_TEE=tdx");
    }
    let tdx_policy = tdx_policy_from_env(tee)?;
    Ok(Some(AttestExpectation {
        tee,
        measurement: Measurement(bytes),
        tls_spki_sha256: tls_spki_sha256_from_env()?,
        min_tcb_sevsnp,
        tdx_policy,
        transparency_log_key: transparency_log_key_from_env()?,
    }))
}

/// A direct TDX node must carry the same complete, canonical workload policy as a
/// Coordinator-published hop. The value is one JSON object matching `nil_proto::path::TdxPolicy`;
/// splitting it across many environment variables would make partial configuration too easy.
fn tdx_policy_from_env(tee: Tee) -> Result<Option<nil_core::TdxPolicy>> {
    match (tee, std::env::var("NW_TDX_POLICY_JSON")) {
        (Tee::Tdx, Ok(raw)) => {
            let wire: WireTdxPolicy = serde_json::from_str(&raw)
                .context("NW_TDX_POLICY_JSON must be a complete TDX policy JSON object")?;
            crate::redeem::tdx_policy_from_wire(wire)
                .context("NW_TDX_POLICY_JSON contains an invalid TDX policy")
                .map(Some)
        }
        (Tee::Tdx, Err(std::env::VarError::NotPresent)) => anyhow::bail!(
            "NW_EXPECTED_TEE=tdx requires a complete NW_TDX_POLICY_JSON; MRTD alone is insufficient"
        ),
        (Tee::Tdx, Err(std::env::VarError::NotUnicode(_))) => {
            anyhow::bail!("NW_TDX_POLICY_JSON must be valid UTF-8 JSON")
        }
        (Tee::SevSnp, Ok(_)) => {
            anyhow::bail!("NW_TDX_POLICY_JSON is invalid when NW_EXPECTED_TEE=sev-snp")
        }
        (Tee::SevSnp, Err(std::env::VarError::NotUnicode(_))) => {
            anyhow::bail!("NW_TDX_POLICY_JSON must be valid UTF-8 JSON")
        }
        (Tee::SevSnp, Err(std::env::VarError::NotPresent)) => Ok(None),
    }
}

/// Optional stable TLS identity pin for a direct debug node. Coordinator-redeemed production
/// paths receive this per hop from the registry instead.
fn tls_spki_sha256_from_env() -> Result<Option<[u8; 32]>> {
    let Ok(hex) = std::env::var("NW_EXPECTED_TLS_SPKI_SHA256") else {
        return Ok(None);
    };
    let bytes = connectip::from_hex(hex.trim().as_bytes())
        .ok_or_else(|| anyhow::anyhow!("NW_EXPECTED_TLS_SPKI_SHA256 is not valid hex"))?;
    Ok(Some(bytes.try_into().map_err(|_| {
        anyhow::anyhow!("NW_EXPECTED_TLS_SPKI_SHA256 must be 32 bytes (64 hex chars)")
    })?))
}

/// Parse an optional pinned transparency-log Ed25519 public key from `NW_TRANSPARENCY_LOG_KEY`
/// (64 hex chars = 32 bytes). When set, the client requires the node's measurement to be proven
/// present in that log via a stapled inclusion proof; unset ⇒ `None` ⇒ measurement pin alone gates.
pub fn transparency_log_key_from_env() -> Result<Option<[u8; 32]>> {
    let Ok(hex) = std::env::var("NW_TRANSPARENCY_LOG_KEY") else {
        return Ok(None);
    };
    let bytes = connectip::from_hex(hex.trim().as_bytes())
        .ok_or_else(|| anyhow::anyhow!("NW_TRANSPARENCY_LOG_KEY is not valid hex"))?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("NW_TRANSPARENCY_LOG_KEY must be 32 bytes (64 hex chars)"))?;
    Ok(Some(key))
}

/// Parse an optional pinned SEV-SNP minimum-TCB floor from `NW_MIN_TCB_SEVSNP`. Format is four
/// dot-separated bytes `bootloader.tee.snp.microcode` (as read from `snpguest report` on validated
/// hardware, e.g. `"3.0.8.115"`); unset ⇒ `None` ⇒ no floor. FMC (Turin) pinning is not yet exposed
/// here — the floor's `fmc` stays `None` (don't-care), which is correct for the Milan/Genoa alpha.
fn min_tcb_sevsnp_from_env() -> Result<Option<SevSnpTcbFloor>> {
    let Ok(raw) = std::env::var("NW_MIN_TCB_SEVSNP") else {
        return Ok(None);
    };
    let parts: Vec<&str> = raw.trim().split('.').collect();
    let [bootloader, tee, snp, microcode] = parts.as_slice() else {
        anyhow::bail!(
            "NW_MIN_TCB_SEVSNP must be four dot-separated bytes bootloader.tee.snp.microcode"
        );
    };
    let byte = |s: &str, name: &str| -> Result<u8> {
        s.parse::<u8>()
            .with_context(|| format!("NW_MIN_TCB_SEVSNP {name} is not a 0-255 integer"))
    };
    Ok(Some(SevSnpTcbFloor {
        fmc: None,
        bootloader: byte(bootloader, "bootloader")?,
        tee: byte(tee, "tee")?,
        snp: byte(snp, "snp")?,
        microcode: byte(microcode, "microcode")?,
    }))
}

/// Audit B1 — the CLIENT-SIDE, Coordinator-INDEPENDENT set of measurements the client will accept
/// for ANY redeemed hop, as raw bytes. This is the pin the redeem cross-check
/// ([`crate::redeem::redeem_path`]) tests each Coordinator-provided hop measurement against, so a
/// compromised/coerced Coordinator cannot substitute a measurement pointing at a node it controls.
///
/// Sourced from (union of, so single-hop and multi-hop deployments share one mechanism):
///   - `NW_EXPECTED_MEASUREMENT` (single hex value, the existing per-node pin), and
///   - `NW_PINNED_MEASUREMENTS` (comma-separated hex, the set for a multi-operator trust-split path).
///
/// Empty ⇒ no client pin ⇒ the redeemed path stays Coordinator-trusted (a WARN is logged there).
/// For the pin to be MEANINGFUL it must come from a genuinely independent source (out-of-band
/// config, the user-verified reproducible-build measurement, or a future operator-signed registry);
/// see the residual-trust note on [`crate::redeem::cross_check_pins`]. PII-free: this never logs the
/// measurement bytes.
pub fn pinned_measurements_from_env() -> Result<Vec<Vec<u8>>> {
    let mut pins: Vec<Vec<u8>> = Vec::new();
    if let Ok(hex) = std::env::var("NW_EXPECTED_MEASUREMENT") {
        let bytes = connectip::from_hex(hex.trim().as_bytes())
            .ok_or_else(|| anyhow::anyhow!("NW_EXPECTED_MEASUREMENT is not valid hex"))?;
        pins.push(bytes);
    }
    if let Ok(list) = std::env::var("NW_PINNED_MEASUREMENTS") {
        for (i, item) in list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .enumerate()
        {
            let bytes = connectip::from_hex(item.as_bytes()).ok_or_else(|| {
                anyhow::anyhow!("NW_PINNED_MEASUREMENTS entry {i} is not valid hex")
            })?;
            if !pins.contains(&bytes) {
                pins.push(bytes);
            }
        }
    }
    Ok(pins)
}

/// The node's WireGuard static public key (hex) from `NW_NODE_WG_PUB`, if set.
fn wg_pub_from_env() -> Result<Option<[u8; 32]>> {
    let Ok(h) = std::env::var("NW_NODE_WG_PUB") else {
        return Ok(None);
    };
    let bytes = connectip::from_hex(h.trim().as_bytes())
        .ok_or_else(|| anyhow::anyhow!("NW_NODE_WG_PUB is not valid hex"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("NW_NODE_WG_PUB must be 32 bytes"))?;
    Ok(Some(arr))
}

/// A multi-hop trust-split path from `NW_PATH` (`host:port[@wg_pub_hex],...`, entry first). Every
/// hop is pinned to the same `expected` measurement here; production gets a per-operator pin per
/// hop from the Coordinator. An optional `@`-suffixed 32-byte hex WireGuard public key makes that
/// hop an inner **PQ-WireGuard** carrier (the client PQ-wraps every hop that has one, so a path
/// where every hop carries a key is an all-PQ onion); a hop with no `@key` stays plain nested MASQUE.
fn path_from_env(expected: &Option<AttestExpectation>) -> Result<Option<Vec<NodeEndpoint>>> {
    let Ok(spec) = std::env::var("NW_PATH") else {
        return Ok(None);
    };
    let mut hops = Vec::new();
    for (i, item) in spec
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        let (host, port, wg_pub) =
            parse_nw_path_hop(item).with_context(|| format!("NW_PATH hop {i}"))?;
        hops.push(NodeEndpoint {
            host,
            port,
            kind: TransportKind::Masque,
            wg_pub,
            expected: expected.clone(),
            grant: None,
        });
    }
    if hops.is_empty() {
        anyhow::bail!("NW_PATH is set but lists no hops");
    }
    Ok(Some(hops))
}

/// Parse one `NW_PATH` hop: `host:port` (plain nested MASQUE) or `host:port@wg_pub_hex` (an inner
/// PQ-WireGuard carrier — the client PQ-wraps that hop). Pure (no env) so the grammar is unit-tested.
/// The `@`-split runs first: a WireGuard pubkey is 64 hex chars (no ':' or '@'), and '@' can't appear
/// in a `host:port`, so this is unambiguous.
fn parse_nw_path_hop(item: &str) -> Result<(String, u16, Option<[u8; 32]>)> {
    let (hostport, wg_pub) = match item.split_once('@') {
        Some((hp, key_hex)) => {
            let bytes = connectip::from_hex(key_hex.trim().as_bytes())
                .ok_or_else(|| anyhow::anyhow!("wg_pub is not hex"))?;
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("wg_pub must be 32 bytes"))?;
            (hp, Some(key))
        }
        None => (item, None),
    };
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("must be host:port[@wg_pub], got {item:?}"))?;
    let port: u16 = port.parse().with_context(|| format!("port {port:?}"))?;
    Ok((host.to_string(), port, wg_pub))
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
    let port: u16 = env_or("NW_NODE_PORT", "443")
        .parse()
        .context("NW_NODE_PORT")?;
    let tun_name = env_or("NW_TUN", "nil0");
    let client_ip: Ipv4Addr = env_or("NW_CLIENT_IP", "10.74.0.2")
        .parse()
        .context("NW_CLIENT_IP")?;
    let peer_ip: Ipv4Addr = env_or("NW_PEER_IP", "10.74.0.1")
        .parse()
        .context("NW_PEER_IP")?;
    let dns: Vec<IpAddr> = env_or("NW_DNS", "1.1.1.1")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.trim()
                .parse::<IpAddr>()
                .map_err(|e| anyhow::anyhow!("NW_DNS {s}: {e}"))
        })
        .collect::<Result<_>>()?;
    let kill_switch = env_or("NW_KILLSWITCH", "1") != "0";
    // Fail-closed by default: a MASQUE hop with no pinned measurement refuses to connect unless
    // NW_ALLOW_UNATTESTED is explicitly TRUE (dev/loopback only). `dev_env_flag` accepts only "1"/"true"
    // — so `NW_ALLOW_UNATTESTED=0` keeps the gate ON (not the `is_ok()` footgun where any value,
    // including `0`, would loosen it), and always returns false outside debug builds. See
    // `MasqueConfig::allow_unattested`.
    let allow_unattested = nil_core::net::dev_env_flag("NW_ALLOW_UNATTESTED");
    let expected = expected_from_env()?;
    let wg_pub = wg_pub_from_env()?;
    Ok(TunnelParams {
        host,
        port,
        tun_name,
        client_ip,
        peer_ip,
        dns,
        kill_switch,
        allow_unattested,
        expected,
        wg_pub,
    })
}

/// Apply independently supplied release trust roots to a static (`NW_NODE_HOST` / `NW_PATH`)
/// configuration. A static endpoint does not carry a Coordinator-provided measurement, so the
/// operator must select one measurement with `NW_EXPECTED_MEASUREMENT`; that selection is accepted
/// only when it belongs to `client_pins`. The embedded transparency-log key always replaces the
/// process-environment value, preventing runtime configuration from broadening release trust.
fn apply_direct_trust(
    mut params: TunnelParams,
    client_pins: &[Vec<u8>],
    client_transparency_log_key: [u8; 32],
) -> Result<TunnelParams> {
    if client_pins.is_empty() {
        anyhow::bail!("the embedded release trust bundle contains no effective node measurement");
    }

    let expected = params.expected.as_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "a direct node/path requires NW_EXPECTED_MEASUREMENT to select an embedded release measurement"
        )
    })?;
    if !client_pins.contains(&expected.measurement.0) {
        anyhow::bail!("NW_EXPECTED_MEASUREMENT does not match the embedded release trust bundle");
    }

    expected.transparency_log_key = Some(client_transparency_log_key);
    // An expectation is mandatory above, but also clear the development escape hatch so a later
    // transport refactor cannot accidentally turn an appraisal error into an unattested session.
    params.allow_unattested = false;
    Ok(params)
}

/// Whether the resolved path is effectively single-hop: no path at all, or a path of fewer than
/// two hops. A single-hop tunnel is **not** trust-split — the one node sees BOTH the client's IP
/// and the destination, so this is a privacy property the operator/user must be told about (PD-8).
/// Multi-hop nested-MASQUE trust-split (entry/middle/exit) is the production default and is
/// exercised end-to-end by the Docker data-plane e2e harness (`deploy/verify-e2e.sh`); single-hop
/// is available only to builds with debug assertions.
fn is_single_hop(path: &Option<Vec<NodeEndpoint>>) -> bool {
    path.as_ref().map_or(true, |hops| hops.len() < 2)
}

/// Build a network-aware [`SelectorTransport`] + [`TunnelConfig`] for a single configured node
/// (`NW_SELECTOR`). The selector probes the path then orders the cascade fast-first (Clean) or
/// resistant-first (Hostile); the resistant rungs are always the tail (so a wrong "clean" guess
/// steps down, never hard-fails). `primary` is the MASQUE / PQ-WG rung already built by [`assemble`].
///
/// `also_except` lists ONLY the hosts of rungs that were actually assembled — same kill-switch
/// invariant as the static cascade: `NW_SELECTOR` alone never punches an all-ports firewall hole.
#[cfg(feature = "selector")]
fn finish_selector(
    p: TunnelParams,
    node: NodeEndpoint,
    primary: Arc<dyn Transport>,
    base_mtu: u16,
) -> Result<(Arc<dyn Transport>, TunnelConfig)> {
    let mut fast: Vec<Arc<dyn Transport>> = vec![primary.clone()];
    let mut resistant: Vec<Arc<dyn Transport>> = Vec::new();
    let mut also_except: Vec<String> = Vec::new();
    let note_except = |also_except: &mut Vec<String>, host: &Option<String>| {
        let h = host.clone().unwrap_or_else(|| p.host.clone());
        if !also_except.contains(&h) {
            also_except.push(h);
        }
    };

    // Fast path: AmneziaWG (UDP, speed-first) after the MASQUE/PQ-WG primary.
    if let Some((wg, host, port)) = parse_wg_endpoint(
        "NW_NODE_AMNEZIA_WG_PUB",
        "NW_NODE_AMNEZIA_HOST",
        "NW_NODE_AMNEZIA_PORT",
    )? {
        note_except(&mut also_except, &host);
        fast.push(Arc::new(AmneziaWgTransport::new(wg, host, port)));
    }

    // Resistant path: REALITY first, then wstunnel.
    let mut has_resistant = false;
    if let Some((reality, reality_host)) = reality_from_env()? {
        note_except(&mut also_except, &reality_host); // single NW_REALITY_HOST read (no TOCTOU)
        resistant.push(Arc::new(reality));
        has_resistant = true;
    }
    if let Some((wg, host, port)) = parse_wg_endpoint(
        "NW_NODE_WSTUNNEL_WG_PUB",
        "NW_NODE_WSTUNNEL_HOST",
        "NW_NODE_WSTUNNEL_PORT",
    )? {
        note_except(&mut also_except, &host);
        resistant.push(Arc::new(WstunnelTransport::new(wg, host, port)));
        has_resistant = true;
    }
    // Fail-closed: NW_SELECTOR is for surviving a hostile network, where the fast rungs are skipped
    // and ONLY the resistant tail runs. With no real resistant rung the tail would be just the
    // MASQUE primary the probe already deemed unreachable → no connection. Refuse that config at
    // startup rather than hand the user a silent connectivity hole on a hostile network.
    if !has_resistant {
        anyhow::bail!(
            "NW_SELECTOR requires at least one resistant rung — set NW_REALITY_WG_PUB and/or \
             NW_NODE_WSTUNNEL_WG_PUB (without one, a hostile network has no working transport)"
        );
    }
    // MASQUE backstop on the resistant tail (the same primary instance — a cheap Arc clone): the
    // last resort after the real resistant rungs (unreachable on a Clean path, where the fast
    // primary already leads).
    resistant.push(primary);

    tracing::info!(
        fast = fast.len(),
        resistant = resistant.len(),
        "network-aware selector enabled (probe → fast/resistant cascade)"
    );
    let selector = Selector::new(Arc::new(UdpReachabilityProbe::default()), fast, resistant);
    let transport: Arc<dyn Transport> = Arc::new(SelectorTransport::new(selector));

    let cfg = TunnelConfig {
        node,
        tun_name: p.tun_name,
        client_ip: p.client_ip,
        peer_ip: p.peer_ip,
        prefix: 24,
        mtu: base_mtu,
        dns: p.dns,
        kill_switch: p.kill_switch,
        also_except,
    };
    Ok((transport, cfg))
}

/// Build the transport + a [`TunnelConfig`] from resolved params + a resolved path. `path` is
/// `Some` for a trust-split / Coordinator-redeemed path (its first hop is the kill-switch
/// exception), `None` for a single configured node (which may be wrapped in the obfuscation
/// cascade). The transport assembly is identical regardless of how the path was obtained.
fn assemble(
    p: TunnelParams,
    path: Option<Vec<NodeEndpoint>>,
) -> Result<(Arc<dyn Transport>, TunnelConfig)> {
    if is_single_hop(&path) {
        // Trust-split is a release invariant, not an operator acknowledgement. Keeping this branch
        // under `debug_assertions` ensures NW_FORCE_SINGLE_HOP cannot reactivate one-hop service in
        // a production artifact even when the environment is compromised or misconfigured.
        #[cfg(not(debug_assertions))]
        anyhow::bail!(
            "production builds require a trust-split path of at least two hops; \
             NW_FORCE_SINGLE_HOP is a development-only override"
        );

        #[cfg(debug_assertions)]
        if !nil_core::net::dev_env_flag("NW_FORCE_SINGLE_HOP") {
            // Tailor the remediation: if a Coordinator IS configured, "set NW_COORDINATOR_URL" is
            // wrong advice (it returned a 1-hop path) — the fix is operator-side. Only suggest
            // configuring a Coordinator when there isn't one.
            if std::env::var("NW_COORDINATOR_URL").is_ok() {
                tracing::warn!(
                    "single-hop path: this node sees BOTH your IP and your destination — NOT \
                     trust-split. The Coordinator returned a single-hop path. \
                     Set NW_FORCE_SINGLE_HOP=1 only in development to acknowledge this warning."
                );
            } else {
                tracing::warn!(
                    "single-hop mode: this node sees BOTH your IP and your destination — NOT \
                     trust-split. Set NW_COORDINATOR_URL for a multi-hop path, or use \
                     NW_FORCE_SINGLE_HOP=1 only in development to acknowledge this warning."
                );
            }
        }
    }

    #[cfg(not(feature = "dev-fallbacks"))]
    if std::env::var_os("NW_CASCADE").is_some() || std::env::var_os("NW_SELECTOR").is_some() {
        anyhow::bail!(
            "NW_CASCADE/NW_SELECTOR requires a debug build with the explicit `dev-fallbacks` feature"
        );
    }
    let (transport, routing_node, mtu): (Arc<dyn Transport>, NodeEndpoint, u16) = if let Some(
        hops,
    ) = path
    {
        if p.wg_pub.is_some() {
            // The single-node NW_NODE_WG_PUB does not apply to a multi-hop path. Per-hop PQ keys
            // ride on each hop's own `wg_pub` (from the Coordinator-redeemed path); the exit hop's
            // is PQ-wrapped by PathTransport. The static NW_PATH dev shim carries no per-hop keys,
            // so it stays plain nested MASQUE.
            tracing::warn!("a path is configured — ignoring single-node NW_NODE_WG_PUB; per-hop PQ uses each hop's own key");
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
        (
            Arc::new(PathTransport::new(Arc::new(inner), hops)),
            entry,
            1280,
        )
    } else {
        let node = NodeEndpoint {
            host: p.host.clone(),
            port: p.port,
            kind: TransportKind::Masque,
            wg_pub: p.wg_pub,
            expected: p.expected.clone(),
            grant: None,
        };
        // Primary rung: PQ-WireGuard-over-MASQUE if a node WG key is pinned, else plain MASQUE.
        let (primary, base_mtu): (Arc<dyn Transport>, u16) = if p.wg_pub.is_some() {
            let inner = MasqueTransport::with_config(MasqueConfig {
                allow_unattested: p.allow_unattested,
                ..Default::default()
            });
            (Arc::new(PqWgTransport::new(Arc::new(inner))), 1232)
        } else {
            (
                Arc::new(MasqueTransport::with_config(MasqueConfig {
                    allow_unattested: p.allow_unattested,
                    ..Default::default()
                })),
                1280,
            )
        };
        // Network-aware selector (opt-in via NW_SELECTOR): probe the path once, then order the
        // cascade fast-first (Clean) or resistant-first (Hostile). Only for a single configured
        // node — the multi-hop path branch above is unaffected. Behind the `selector` feature +
        // NW_SELECTOR so the static cascade stays the default (back-compat).
        #[cfg(feature = "selector")]
        if nil_core::net::dev_env_flag("NW_SELECTOR") {
            return finish_selector(p, node, primary, base_mtu);
        }

        #[cfg(feature = "dev-fallbacks")]
        {
            // With NW_CASCADE, wrap [primary, AmneziaWG?, wstunnel?] in a development-only
            // cascade. These rungs are compiled out entirely unless `dev-fallbacks` is explicit.
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
                    "development obfuscation cascade enabled (MASQUE primary → {} fallback rung(s))",
                    rungs.len() - 1
                );
                let cascade =
                    Cascade::new(rungs).with_liveness_probe(Arc::new(DnsLivenessProbe::default()));
                (Arc::new(CascadeTransport::new(cascade)), node, base_mtu)
            } else {
                if nil_core::net::dev_env_flag("NW_CASCADE") {
                    anyhow::bail!(
                        "NW_CASCADE set but no fallback rung configured — set NW_NODE_AMNEZIA_WG_PUB and/or NW_NODE_WSTUNNEL_WG_PUB"
                    );
                }
                (
                    rungs.into_iter().next().expect("primary rung"),
                    node,
                    base_mtu,
                )
            }
        }

        #[cfg(not(feature = "dev-fallbacks"))]
        (primary, node, base_mtu)
    };

    // When the cascade is on, each fallback node's traffic must also bypass the tunnel (else the
    // fallback rung's own packets to its node would loop through the TUN, and — since the
    // kill-switch only opens the PRIMARY node on :443 — its custom port would be dropped). Only
    // except hosts that an ACTUALLY-ASSEMBLED fallback rung reaches (gated on the same key vars
    // that gate the rungs above), so NW_CASCADE alone never punches an all-ports kill-switch hole.
    #[cfg(feature = "dev-fallbacks")]
    let mut also_except: Vec<String> = Vec::new();
    #[cfg(feature = "dev-fallbacks")]
    if nil_core::net::dev_env_flag("NW_CASCADE") {
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
    #[cfg(not(feature = "dev-fallbacks"))]
    let also_except: Vec<String> = Vec::new();

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
        // Audit B1: a redeemed path no longer trusts the Coordinator's per-hop measurement on
        // faith — it is cross-checked against the client's own pin (NW_EXPECTED_MEASUREMENT /
        // NW_PINNED_MEASUREMENTS) inside `redeem_path`, which fails closed on a mismatch.
        let client_pins = pinned_measurements_from_env()?;
        let client_log_key = transparency_log_key_from_env()?;
        Some(crate::redeem::redeem_path_from_env(&url, &client_pins, client_log_key).await?)
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
    // Audit B1 cross-check (see `from_env`): the desktop engine reads its independent pin from the
    // same env vars and the redeem path refuses any hop whose Coordinator-provided measurement is
    // not in it.
    let client_pins = pinned_measurements_from_env()?;
    let client_log_key = transparency_log_key_from_env()?;
    from_env_with_token_and_trust(coord_url, msg, token, &client_pins, client_log_key).await
}

/// Release-client variant of [`from_env_with_token`]. The caller supplies roots decoded from the
/// bundle embedded in the client binary, so neither a process env value nor the Coordinator can
/// broaden which guest measurements or transparency-log key the desktop app trusts.
pub async fn from_env_with_token_and_trust(
    coord_url: &str,
    msg: &str,
    token: &str,
    client_pins: &[Vec<u8>],
    client_transparency_log_key: Option<[u8; 32]>,
) -> Result<(Arc<dyn Transport>, TunnelConfig)> {
    let p = params_from_env()?;
    let path = Some(
        crate::redeem::redeem_path(
            coord_url,
            msg,
            token,
            client_pins,
            client_transparency_log_key,
        )
        .await?,
    );
    assemble(p, path)
}

/// Release-client launcher for a static node or `NW_PATH`. The caller supplies measurements and
/// the transparency-log key decoded from the bundle embedded in the client binary. Environment or
/// persisted settings may select one embedded measurement, but cannot introduce a new measurement,
/// omit transparency-log verification, or enable the unattested development escape hatch.
pub async fn from_env_with_direct_trust(
    client_pins: &[Vec<u8>],
    client_transparency_log_key: [u8; 32],
) -> Result<(Arc<dyn Transport>, TunnelConfig)> {
    if std::env::var("NW_COORDINATOR_URL").is_ok() {
        anyhow::bail!(
            "from_env_with_direct_trust cannot be used with NW_COORDINATOR_URL; redeem the path with Coordinator trust checks"
        );
    }
    let p = apply_direct_trust(params_from_env()?, client_pins, client_transparency_log_key)?;
    let path = path_from_env(&p.expected)?;
    assemble(p, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nw_path_hop_plain_is_masque_no_key() {
        let (host, port, wg) = parse_nw_path_hop("entry.example:443").expect("plain host:port");
        assert_eq!(host, "entry.example");
        assert_eq!(port, 443);
        assert_eq!(wg, None, "no @key ⇒ plain nested MASQUE (back-compat)");
    }

    #[test]
    fn nw_path_hop_with_key_is_pq_carrier() {
        let key_hex = "ab".repeat(32); // 32 bytes
        let (host, port, wg) =
            parse_nw_path_hop(&format!("exit.example:443@{key_hex}")).expect("host:port@key");
        assert_eq!(host, "exit.example");
        assert_eq!(port, 443);
        assert_eq!(
            wg,
            Some([0xab; 32]),
            "an @wg_pub makes the hop a PQ-WireGuard carrier"
        );
    }

    #[test]
    fn nw_path_hop_rejects_bad_key() {
        // Non-hex and wrong-length keys must fail (fail closed — never silently drop the key).
        assert!(parse_nw_path_hop("h:443@zz").is_err(), "non-hex key");
        assert!(
            parse_nw_path_hop("h:443@abcd").is_err(),
            "wrong-length key (not 32 bytes)"
        );
        assert!(parse_nw_path_hop("no-port").is_err(), "missing :port");
    }

    fn measurement(byte: u8) -> AttestExpectation {
        AttestExpectation {
            tee: Tee::SevSnp,
            measurement: Measurement(vec![byte; 48]),
            tls_spki_sha256: None,
            min_tcb_sevsnp: None,
            tdx_policy: None,
            transparency_log_key: None,
        }
    }

    /// Base params with no node WG key, no cascade. `expected`/`wg_pub` are overridden per test.
    /// These tests rely on `NW_CASCADE` being UNSET in the test process (no test sets it), so
    /// `assemble` takes the no-cascade branch deterministically and `also_except` stays empty.
    fn base_params() -> TunnelParams {
        TunnelParams {
            host: "node.example".to_string(),
            port: 443,
            tun_name: "nil0".to_string(),
            client_ip: "10.74.0.2".parse().unwrap(),
            peer_ip: "10.74.0.1".parse().unwrap(),
            dns: vec!["1.1.1.1".parse().unwrap()],
            kill_switch: true,
            allow_unattested: false,
            expected: None,
            wg_pub: None,
        }
    }

    #[test]
    fn single_hop_detection_drives_the_honest_disclosure() {
        // The PD-8 disclosure fires for no-path and 1-hop; a >=2-hop path is trust-split and silent.
        assert!(is_single_hop(&None), "no path is single-hop");
        assert!(
            is_single_hop(&Some(vec![NodeEndpoint::loopback()])),
            "a 1-hop path is single-hop (one node sees IP + destination)"
        );
        assert!(
            !is_single_hop(&Some(vec![
                NodeEndpoint::loopback(),
                NodeEndpoint::loopback()
            ])),
            "a 2-hop path is trust-split (no honest-disclosure warning)"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn single_hop_plain_masque_carries_the_pin_and_default_mtu() {
        let mut p = base_params();
        p.expected = Some(measurement(0xab));
        let (transport, cfg) = assemble(p, None).expect("assemble single-hop");
        // The configured node pin propagates verbatim into the routing node the datapath uses.
        assert_eq!(cfg.node.expected, Some(measurement(0xab)));
        assert_eq!(cfg.node.host, "node.example");
        assert_eq!(cfg.node.wg_pub, None);
        // Plain MASQUE → 1280 ceiling; no cascade → no extra except hosts.
        assert_eq!(cfg.mtu, 1280);
        assert!(cfg.also_except.is_empty());
        // On the wire it's MASQUE regardless of the inner layering (Pillar 1).
        assert_eq!(transport.kind(), nil_core::TransportKind::Masque);
        assert_eq!(cfg.client_ip, "10.74.0.2".parse::<Ipv4Addr>().unwrap());
        assert!(cfg.kill_switch);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn single_hop_with_wg_pub_selects_pqwg_and_shrinks_mtu() {
        let mut p = base_params();
        p.expected = Some(measurement(0xcd));
        p.wg_pub = Some([7u8; 32]);
        let (_transport, cfg) = assemble(p, None).expect("assemble pqwg single-hop");
        // The node WG key flows into the routing endpoint, and the PQ-WireGuard primary shrinks
        // the usable MTU to 1232 (vs 1280 plain) — the observable signal the PqWg branch was taken.
        assert_eq!(cfg.node.wg_pub, Some([7u8; 32]));
        assert_eq!(cfg.node.expected, Some(measurement(0xcd)));
        assert_eq!(cfg.mtu, 1232);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_assembly_rejects_single_hop_even_when_the_override_would_be_requested() {
        let mut p = base_params();
        p.expected = Some(measurement(0xab));
        assert!(
            assemble(p, None).is_err(),
            "a release artifact must not assemble a one-hop path"
        );
    }

    #[test]
    fn path_uses_the_entry_hop_as_routing_node() {
        let p = base_params();
        let hops = vec![
            NodeEndpoint {
                host: "entry.example".to_string(),
                port: 443,
                kind: TransportKind::Masque,
                wg_pub: None,
                expected: Some(measurement(0x11)),
                grant: None,
            },
            NodeEndpoint {
                host: "exit.example".to_string(),
                port: 443,
                kind: TransportKind::Masque,
                wg_pub: None,
                expected: Some(measurement(0x22)),
                grant: None,
            },
        ];
        let (transport, cfg) = assemble(p, Some(hops)).expect("assemble path");
        // The datapath's kill-switch host-route exception is the ENTRY hop (hops[0]); inner hops
        // are reached through the tunnel and must not appear as the routing node.
        assert_eq!(cfg.node.host, "entry.example");
        assert_eq!(cfg.node.expected, Some(measurement(0x11)));
        // Multi-hop nested MASQUE uses the 1280 onion ceiling and stays MASQUE on the wire.
        assert_eq!(cfg.mtu, 1280);
        assert_eq!(transport.kind(), nil_core::TransportKind::Masque);
        assert!(cfg.also_except.is_empty());
    }

    #[test]
    fn path_ignores_a_stray_node_wg_pub() {
        // A path is configured AND a node WG key is set: the multi-hop branch must ignore the
        // single-node WG key (it runs plain nested MASQUE) and still route via the entry hop.
        let mut p = base_params();
        p.wg_pub = Some([9u8; 32]);
        let hops = vec![
            NodeEndpoint {
                host: "entry.example".to_string(),
                port: 443,
                kind: TransportKind::Masque,
                wg_pub: None,
                expected: Some(measurement(0x33)),
                grant: None,
            },
            NodeEndpoint {
                host: "exit.example".to_string(),
                port: 443,
                kind: TransportKind::Masque,
                wg_pub: None,
                expected: Some(measurement(0x44)),
                grant: None,
            },
        ];
        let (_t, cfg) = assemble(p, Some(hops)).expect("assemble path with stray wg_pub");
        assert_eq!(cfg.node.host, "entry.example");
        // The routing node is the entry hop verbatim — the stray single-node wg_pub does not leak
        // into it (the entry hop carried `None`).
        assert_eq!(cfg.node.wg_pub, None);
        assert_eq!(cfg.mtu, 1280);
    }

    #[test]
    fn direct_release_trust_requires_an_explicit_embedded_measurement() {
        let err = apply_direct_trust(base_params(), &[vec![0xab; 48]], [0xcd; 32])
            .err()
            .expect("an unpinned direct node must fail closed");
        assert!(err.to_string().contains("requires NW_EXPECTED_MEASUREMENT"));

        let mut p = base_params();
        p.expected = Some(measurement(0xee));
        let err = apply_direct_trust(p, &[vec![0xab; 48]], [0xcd; 32])
            .err()
            .expect("a runtime-only measurement must not broaden embedded trust");
        assert!(err
            .to_string()
            .contains("does not match the embedded release trust bundle"));
    }

    #[test]
    fn direct_release_trust_forces_the_embedded_log_key_and_attestation_gate() {
        let mut p = base_params();
        let mut expected = measurement(0xab);
        expected.transparency_log_key = Some([0x11; 32]);
        p.expected = Some(expected);
        p.allow_unattested = true;

        let p = apply_direct_trust(p, &[vec![0xab; 48], vec![0xbc; 48]], [0xcd; 32])
            .expect("the selected measurement belongs to the embedded set");
        let expected = p.expected.expect("release expectation");
        assert_eq!(expected.measurement, Measurement(vec![0xab; 48]));
        assert_eq!(expected.transparency_log_key, Some([0xcd; 32]));
        assert!(!p.allow_unattested);
    }
}
