//! Network-extension connect path (Android/iOS, and macOS behind the `macos-system-extension`
//! feature). The OS datapath lives in a separate process — Android's `VpnService` (`:vpn`, via the
//! `nil-android` JNI engine), iOS's `NEPacketTunnelProvider`, or the macOS system extension (both
//! via the shared `nil-apple` engine) — so the in-process loopback mock is NOT a real tunnel there.
//! This module is the User-plane half: it redeems the unlinkable Privacy Pass token at the
//! Coordinator (exactly as the desktop engine does) and hands the resulting **attested node endpoint
//! + short-lived grant** to the platform plugin, which starts the native datapath.
//!
//! Identity never crosses into the datapath process: only a node host/port, the pinned
//! measurement, and an opaque grant are passed out of here. The token redemption (and the bearer
//! token itself) stays in this app process.
//!
//! Privacy: logs **nothing identifying** — no node address, token, grant, or measurement (PD-2).

use serde::Serialize;

use nil_proto::path::{PathResponse, Tee as WireTee};
use nil_proto::token::RedeemRequest;
use nil_transport::connectip;

use crate::tokens::StoredToken;

/// Minimum hops in a redeemed path. The closed alpha ships SINGLE-HOP deliberately (trust-split is
/// the next milestone), so 1 is allowed; 0 is always rejected. Mirrors `nil-datapath::redeem`.
const MIN_HOPS: usize = 1;
/// Sanity cap on a Coordinator-returned path (a not-fully-trusted domain). Mirrors the datapath.
const MAX_HOPS: usize = 8;
/// Cap the `/v1/redeem` body — a `PathResponse` is tiny; refuse a hostile Coordinator OOMing us.
const MAX_BODY: usize = 64 * 1024;
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Everything the native VpnService/PacketTunnel needs to bring up the attested tunnel — and
/// nothing identifying. The grant fields are hex (empty when the Coordinator returns no grant, e.g.
/// a dev node that allows ungranted tunnels); the native side passes them straight to the node.
/// camelCase so it crosses the Tauri bridge to the Kotlin/Swift plugin unchanged.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartArgs {
    pub node_host: String,
    pub node_port: u16,
    pub server_name: String,
    /// Pinned guest-launch measurement (hex). Never empty on the real path — every redeemed hop
    /// carries its own pin, so the native attestation gate always has something to check.
    pub measurement_hex: String,
    pub tee_name: String,
    /// Opaque Coordinator grant (hex); empty if the hop carries none.
    pub grant_hex: String,
    /// Per-connection grant nonce (hex, 32 bytes); empty if the hop carries no grant.
    pub grant_nonce_hex: String,
}

// Mobile kill-switch (honest model): the native datapath is ALWAYS fail-closed *while connected* —
// the VpnService/PacketTunnel captures the default route (`0.0.0.0/0` + `::/0`) so nothing bypasses
// the TUN, and the engine blackholes the TUN if the tunnel drops. That posture is unconditional, so
// there is no per-connection "block without VPN" StartArg (an earlier `block_without_vpn: bool` was
// hardcoded `true`, never read by the Kotlin/Swift side, and conflated with `setBlocking`, which is
// only the fd's I/O mode — it implied a configurable control that did not exist; PD-8). The PERSISTENT
// guarantee — block traffic when the VPN *process* is down — is the OS "Always-on VPN / Block
// connections without VPN" SYSTEM setting, which an app can deep-link the user to but cannot silently
// enable; the UI must be honest about that. See the Android/iOS DEVICE_VERIFY notes.

#[derive(Debug, thiserror::Error)]
pub enum ExtensionError {
    #[error("no connection token — buy one before connecting")]
    NoTokens,
    #[error("no Coordinator configured — set one in Settings before connecting")]
    NoCoordinator,
    #[error("{0}")]
    UnsafeUrl(String),
    #[error("couldn't reach the path service: {0}")]
    Unreachable(String),
    #[error("the path service rejected the request (HTTP {0})")]
    Rejected(u16),
    #[error("path service returned an unusable path")]
    BadPath,
    #[error("the path's node measurement is not in the client's pinned set (possible substitution)")]
    PinMismatch,
}

/// The client-side, Coordinator-INDEPENDENT measurement pins the mobile client will accept for the
/// redeemed hop. Mirrors the desktop `nil_datapath::launch::pinned_measurements_from_env` so the
/// mobile attestation cross-check uses the SAME operator-controlled anchor, not whatever the
/// Coordinator claims (audit B1). Sourced from `NW_EXPECTED_MEASUREMENT` (single) and
/// `NW_PINNED_MEASUREMENTS` (comma-separated). Empty = no independent anchor (Coordinator-trusted,
/// warned). A mobile build can also seed these from app config before connecting; env keeps parity
/// with the desktop/CI path and makes the cross-check unit-testable.
pub fn client_pins_from_env() -> Vec<Vec<u8>> {
    let mut pins: Vec<Vec<u8>> = Vec::new();
    if let Ok(hex) = std::env::var("NW_EXPECTED_MEASUREMENT") {
        if let Some(bytes) = connectip::from_hex(hex.trim().as_bytes()) {
            pins.push(bytes);
        }
    }
    if let Ok(list) = std::env::var("NW_PINNED_MEASUREMENTS") {
        for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Some(bytes) = connectip::from_hex(item.as_bytes()) {
                if !pins.contains(&bytes) {
                    pins.push(bytes);
                }
            }
        }
    }
    pins
}

/// Redeem `token` at `coord_url` and resolve the (single-hop, alpha) attested start args for the
/// native datapath. Fail-closed: an unsafe URL, an unreachable/rejecting Coordinator, or an
/// empty/oversized/malformed/unattested path all error (→ the native tunnel never comes up).
pub async fn resolve_start_args(
    coord_url: &str,
    token: &StoredToken,
    client_pins: &[Vec<u8>],
) -> Result<StartArgs, ExtensionError> {
    if coord_url.trim().is_empty() {
        return Err(ExtensionError::NoCoordinator);
    }
    // The token is a bearer credential — never POST it in cleartext to a non-loopback host (a
    // plaintext link also lets a MITM rewrite the per-hop measurement). Same gate as the datapath.
    if !nil_core::net::env_flag("NW_INSECURE_CONTROL_PLANE") {
        nil_core::net::require_tls_or_loopback(coord_url).map_err(ExtensionError::UnsafeUrl)?;
    }

    let req = RedeemRequest {
        msg: token.msg.clone(),
        token: token.token.clone(),
    };
    let url = format!("{}/v1/redeem", coord_url.trim_end_matches('/'));
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| ExtensionError::Unreachable(e.to_string()))?;

    let resp = http
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| ExtensionError::Unreachable(e.to_string()))?;
    if !resp.status().is_success() {
        // No token/identifier in the log — only the status (PD-2).
        return Err(ExtensionError::Rejected(resp.status().as_u16()));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| ExtensionError::Unreachable(e.to_string()))?;
    if body.len() > MAX_BODY {
        return Err(ExtensionError::BadPath);
    }
    start_args_from_response(&body, client_pins)
}

/// Pure: parse a `/v1/redeem` body into the native start args (first hop). Unit-tested without a
/// network. Fails closed on an empty/oversized/unattested/malformed path.
fn start_args_from_response(
    body: &[u8],
    client_pins: &[Vec<u8>],
) -> Result<StartArgs, ExtensionError> {
    let resp: PathResponse = serde_json::from_slice(body).map_err(|_| ExtensionError::BadPath)?;
    if resp.hops.len() < MIN_HOPS || resp.hops.len() > MAX_HOPS {
        return Err(ExtensionError::BadPath);
    }
    if resp.hops.len() > 1 {
        // The native single-hop datapath uses only the first hop today; warn that multi-hop
        // trust-split forwarding isn't wired on mobile yet (honesty — SOUL §6).
        tracing::warn!(
            "coordinator returned a multi-hop path but the mobile datapath is single-hop today; \
             using the first hop only (multi-hop trust-split forwarding is the next milestone)"
        );
    }
    // Take the directly-reachable hop (entry). The native gate attests it before any packet flows.
    let hop = resp.hops.into_iter().next().ok_or(ExtensionError::BadPath)?;

    // Every redeemed hop MUST carry a measurement — the native attestation gate has nothing to
    // check otherwise. An empty/invalid measurement fails closed here rather than silently
    // connecting unattested.
    let measurement_hex = hop.measurement.trim().to_string();
    let measurement = match connectip::from_hex(measurement_hex.as_bytes()) {
        Some(b) if !b.is_empty() => b,
        _ => return Err(ExtensionError::BadPath),
    };

    // Audit B1 (substitution defense): cross-check the Coordinator-provided measurement against the
    // client's INDEPENDENT pin set before trusting it. If the client has any pin configured, the
    // redeemed measurement MUST be in it or the path is refused (fail-closed) — so a compromised
    // Coordinator can't point a mobile client at a rogue node within policy. With no pin we fall
    // back to Coordinator-trust but say so loudly (mirrors the desktop `cross_check_pins`).
    if client_pins.is_empty() {
        tracing::warn!(
            "no client-side measurement pin (NW_EXPECTED_MEASUREMENT / NW_PINNED_MEASUREMENTS unset): \
             the redeemed hop is COORDINATOR-TRUSTED — pin from an independent source to cross-check"
        );
    } else if !client_pins.iter().any(|pin| pin == &measurement) {
        // No measurement bytes or host in the log (PD-2): the mismatch alone is the signal.
        tracing::error!(
            "redeemed hop measurement is not in the client's pinned set — refusing the path \
             (possible measurement substitution by the Coordinator)"
        );
        return Err(ExtensionError::PinMismatch);
    }
    let tee_name = match hop.tee {
        WireTee::SevSnp => "sev-snp",
        WireTee::Tdx => "tdx",
    }
    .to_string();

    // Grant + nonce travel together or not at all (matches the datapath's per-hop grant rule).
    // Validate the hex now so a malformed grant fails closed instead of reaching the node.
    let (grant_hex, grant_nonce_hex) = match (hop.grant, hop.grant_nonce) {
        (Some(g), Some(n)) => {
            let g = g.trim().to_string();
            let n = n.trim().to_string();
            if connectip::from_hex(g.as_bytes()).is_none() {
                return Err(ExtensionError::BadPath);
            }
            match connectip::from_hex(n.as_bytes()) {
                Some(b) if b.len() == 32 => {}
                _ => return Err(ExtensionError::BadPath),
            }
            (g, n)
        }
        (None, None) => (String::new(), String::new()),
        _ => return Err(ExtensionError::BadPath),
    };

    Ok(StartArgs {
        server_name: hop.host.clone(),
        node_host: hop.host,
        node_port: hop.port,
        measurement_hex,
        tee_name,
        grant_hex,
        grant_nonce_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meas() -> String {
        "ab".repeat(48)
    }

    #[test]
    fn parses_single_hop_with_measurement() {
        let m = meas();
        let body = format!(
            r#"{{"hops":[{{"host":"entry.example","port":443,"tee":"sev-snp","measurement":"{m}"}}]}}"#
        );
        let a = start_args_from_response(body.as_bytes(), &[]).expect("parse");
        assert_eq!(a.node_host, "entry.example");
        assert_eq!(a.node_port, 443);
        assert_eq!(a.server_name, "entry.example");
        assert_eq!(a.tee_name, "sev-snp");
        assert_eq!(a.measurement_hex, m);
        assert!(a.grant_hex.is_empty() && a.grant_nonce_hex.is_empty());
    }

    #[test]
    fn carries_the_grant_through() {
        let m = meas();
        let grant = "cd".repeat(90);
        let nonce = "11".repeat(32);
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"tdx","measurement":"{m}","grant":"{grant}","grant_nonce":"{nonce}"}}]}}"#
        );
        let a = start_args_from_response(body.as_bytes(), &[]).expect("parse");
        assert_eq!(a.tee_name, "tdx");
        assert_eq!(a.grant_hex, grant);
        assert_eq!(a.grant_nonce_hex, nonce);
    }

    #[test]
    fn rejects_empty_path() {
        let body = br#"{"hops":[]}"#;
        assert!(matches!(
            start_args_from_response(body, &[]),
            Err(ExtensionError::BadPath)
        ));
    }

    #[test]
    fn rejects_unattested_hop() {
        // No/empty measurement → fail closed (the native gate would have nothing to check).
        let body = br#"{"hops":[{"host":"e.example","port":443,"tee":"sev-snp","measurement":""}]}"#;
        assert!(matches!(
            start_args_from_response(body, &[]),
            Err(ExtensionError::BadPath)
        ));
    }

    #[test]
    fn rejects_half_a_grant() {
        let m = meas();
        let grant = "cd".repeat(90);
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}","grant":"{grant}"}}]}}"#
        );
        assert!(matches!(
            start_args_from_response(body.as_bytes(), &[]),
            Err(ExtensionError::BadPath)
        ));
    }

    #[test]
    fn rejects_bad_nonce_length() {
        let m = meas();
        let grant = "cd".repeat(90);
        let nonce = "11".repeat(16); // 16 bytes, not 32
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}","grant":"{grant}","grant_nonce":"{nonce}"}}]}}"#
        );
        assert!(matches!(
            start_args_from_response(body.as_bytes(), &[]),
            Err(ExtensionError::BadPath)
        ));
    }

    #[test]
    fn accepts_measurement_in_the_client_pin() {
        // Audit B1: a redeemed measurement that IS in the client's independent pin set passes.
        let m = meas();
        let pin = connectip::from_hex(m.as_bytes()).expect("hex");
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}"}}]}}"#
        );
        let a = start_args_from_response(body.as_bytes(), &[pin]).expect("pinned measurement accepted");
        assert_eq!(a.measurement_hex, m);
    }

    #[test]
    fn rejects_measurement_not_in_the_client_pin() {
        // Audit B1: a Coordinator-substituted measurement NOT in the client's pin is refused
        // fail-closed (the native tunnel never comes up), even though it is well-formed hex.
        let m = meas(); // "ab" * 48 — the (substituted) measurement the Coordinator returned
        let other_pin = connectip::from_hex("cd".repeat(48).as_bytes()).expect("hex"); // the client's real pin
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}"}}]}}"#
        );
        assert!(matches!(
            start_args_from_response(body.as_bytes(), &[other_pin]),
            Err(ExtensionError::PinMismatch)
        ));
    }
}
