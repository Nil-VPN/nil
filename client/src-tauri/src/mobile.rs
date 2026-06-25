//! Mobile (Android/iOS) connect path. The OS datapath lives in a separate process — Android's
//! `VpnService` (`:vpn`, via the `nil-android` JNI engine) or iOS's `NEPacketTunnelProvider` — so
//! the engine's loopback mock is NOT a real tunnel on mobile. This module is the User-plane half:
//! it redeems the unlinkable Privacy Pass token at the Coordinator (exactly as the desktop engine
//! does) and hands the resulting **attested node endpoint + short-lived grant** to the platform
//! plugin, which starts the native datapath.
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
pub enum MobileError {
    #[error("no connection token — buy one before connecting")]
    NoTokens,
    #[error("no Coordinator configured — set one in Settings before connecting on mobile")]
    NoCoordinator,
    #[error("{0}")]
    UnsafeUrl(String),
    #[error("couldn't reach the path service: {0}")]
    Unreachable(String),
    #[error("the path service rejected the request (HTTP {0})")]
    Rejected(u16),
    #[error("path service returned an unusable path")]
    BadPath,
}

/// Redeem `token` at `coord_url` and resolve the (single-hop, alpha) attested start args for the
/// native datapath. Fail-closed: an unsafe URL, an unreachable/rejecting Coordinator, or an
/// empty/oversized/malformed/unattested path all error (→ the native tunnel never comes up).
pub async fn resolve_start_args(
    coord_url: &str,
    token: &StoredToken,
) -> Result<StartArgs, MobileError> {
    if coord_url.trim().is_empty() {
        return Err(MobileError::NoCoordinator);
    }
    // The token is a bearer credential — never POST it in cleartext to a non-loopback host (a
    // plaintext link also lets a MITM rewrite the per-hop measurement). Same gate as the datapath.
    if !nil_core::net::env_flag("NW_INSECURE_CONTROL_PLANE") {
        nil_core::net::require_tls_or_loopback(coord_url).map_err(MobileError::UnsafeUrl)?;
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
        .map_err(|e| MobileError::Unreachable(e.to_string()))?;

    let resp = http
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| MobileError::Unreachable(e.to_string()))?;
    if !resp.status().is_success() {
        // No token/identifier in the log — only the status (PD-2).
        return Err(MobileError::Rejected(resp.status().as_u16()));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| MobileError::Unreachable(e.to_string()))?;
    if body.len() > MAX_BODY {
        return Err(MobileError::BadPath);
    }
    start_args_from_response(&body)
}

/// Pure: parse a `/v1/redeem` body into the native start args (first hop). Unit-tested without a
/// network. Fails closed on an empty/oversized/unattested/malformed path.
fn start_args_from_response(body: &[u8]) -> Result<StartArgs, MobileError> {
    let resp: PathResponse = serde_json::from_slice(body).map_err(|_| MobileError::BadPath)?;
    if resp.hops.len() < MIN_HOPS || resp.hops.len() > MAX_HOPS {
        return Err(MobileError::BadPath);
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
    let hop = resp.hops.into_iter().next().ok_or(MobileError::BadPath)?;

    // Every redeemed hop MUST carry a measurement — the native attestation gate has nothing to
    // check otherwise. An empty/invalid measurement fails closed here rather than silently
    // connecting unattested.
    let measurement_hex = hop.measurement.trim().to_string();
    if measurement_hex.is_empty()
        || connectip::from_hex(measurement_hex.as_bytes()).is_none()
    {
        return Err(MobileError::BadPath);
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
                return Err(MobileError::BadPath);
            }
            match connectip::from_hex(n.as_bytes()) {
                Some(b) if b.len() == 32 => {}
                _ => return Err(MobileError::BadPath),
            }
            (g, n)
        }
        (None, None) => (String::new(), String::new()),
        _ => return Err(MobileError::BadPath),
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
        let a = start_args_from_response(body.as_bytes()).expect("parse");
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
        let a = start_args_from_response(body.as_bytes()).expect("parse");
        assert_eq!(a.tee_name, "tdx");
        assert_eq!(a.grant_hex, grant);
        assert_eq!(a.grant_nonce_hex, nonce);
    }

    #[test]
    fn rejects_empty_path() {
        let body = br#"{"hops":[]}"#;
        assert!(matches!(
            start_args_from_response(body),
            Err(MobileError::BadPath)
        ));
    }

    #[test]
    fn rejects_unattested_hop() {
        // No/empty measurement → fail closed (the native gate would have nothing to check).
        let body = br#"{"hops":[{"host":"e.example","port":443,"tee":"sev-snp","measurement":""}]}"#;
        assert!(matches!(
            start_args_from_response(body),
            Err(MobileError::BadPath)
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
            start_args_from_response(body.as_bytes()),
            Err(MobileError::BadPath)
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
            start_args_from_response(body.as_bytes()),
            Err(MobileError::BadPath)
        ));
    }
}
