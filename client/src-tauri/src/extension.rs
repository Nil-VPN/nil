//! Network-extension connect path (Android/iOS, and macOS behind the `macos-system-extension`
//! feature). The OS datapath lives in a separate process — Android's `VpnService` (`:vpn`, via the
//! `nil-android` JNI engine), iOS's `NEPacketTunnelProvider`, or the macOS system extension (both
//! via the shared `nil-apple` engine) — so the in-process loopback mock is NOT a real tunnel there.
//! This module is the User-plane half: it redeems the blind-signed Privacy Pass token at the
//! Coordinator and hands the resulting **attested node endpoint + short-lived grant** to the
//! platform plugin, which starts the native datapath. The current native engines support one hop;
//! production Coordinators require a trust-split path of at least two. Non-debug native clients
//! therefore fail before consuming a pass until native multi-hop is implemented.
//!
//! Identity never crosses into the datapath process: only a node host/port, the pinned
//! measurement, and an opaque grant are passed out of here. The token redemption (and the bearer
//! token itself) stays in this app process.
//!
//! Privacy: logs **nothing identifying** — no node address, token, grant, or measurement (PD-2).

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use nil_proto::path::{PathResponse, Tee as WireTee};
use nil_proto::token::RedeemRequest;
use nil_transport::connectip;

use crate::tokens::StoredToken;

/// The single hop supported by the development native-engine harness. A production Coordinator
/// deliberately returns at least two hops, so this shape is never accepted by a packaged client.
const MIN_HOPS: usize = 1;
/// Cap the `/v1/redeem` body — a `PathResponse` is tiny; refuse a hostile Coordinator OOMing us.
const MAX_BODY: usize = 64 * 1024;
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Everything the native VpnService/PacketTunnel needs to bring up the attested tunnel — and
/// nothing identifying. The grant fields are hex (empty when the Coordinator returns no grant, e.g.
/// a dev node that allows ungranted tunnels); the native side passes them straight to the node.
/// camelCase so it crosses the Tauri bridge to the Kotlin/Swift plugin unchanged.
#[derive(Clone, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct StartArgs {
    /// Random local lifecycle binding. It is neither a token nor an account identifier; native
    /// status must echo it before Rust commits the matching encrypted pending reservation.
    pub reservation_id: String,
    pub node_host: String,
    pub node_port: u16,
    pub server_name: String,
    /// Pinned guest-launch measurement (hex). Never empty on the real path — every redeemed hop
    /// carries its own pin, so the native attestation gate always has something to check.
    pub measurement_hex: String,
    /// Stable SHA-256 identity of the node's exact TLS SPKI (hex). Empty is retained only for
    /// legacy/debug fixtures; release Coordinators require it and native appraisal consumes it.
    pub tls_spki_sha256_hex: String,
    /// Ed25519 public key for the measurement transparency log (32 bytes, hex). In a release
    /// build this is the embedded key, after the Coordinator's copy has been cross-checked against
    /// it. The native verifier consumes this value directly when appraising the stapled proof.
    pub transparency_log_key_hex: String,
    pub tee_name: String,
    /// Complete offline SEV-SNP firmware floor from the redeemed hop. Native engines must carry
    /// this verbatim into `AttestExpectation`; omitting it would make mobile appraisal weaker than
    /// desktop appraisal for the same Coordinator response.
    pub min_tcb_sevsnp: Option<NativeSevSnpTcbFloor>,
    /// Opaque Coordinator grant (hex); empty if the hop carries none.
    pub grant_hex: String,
    /// Per-connection grant nonce (hex, 32 bytes); empty if the hop carries no grant.
    pub grant_nonce_hex: String,
}

/// Bridge-safe representation of [`nil_proto::path::SevSnpTcbFloor`]. Kept local to the native
/// contract so its fields can participate in `StartArgs`' eager zeroization without imposing that
/// implementation detail on the protocol DTO crate.
#[derive(Clone, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct NativeSevSnpTcbFloor {
    pub fmc: Option<u8>,
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

// This object crosses process boundaries and contains both routing metadata and a live bearer
// grant. Keep accidental `tracing!(?args)` / panic formatting from disclosing any of it.
impl std::fmt::Debug for StartArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StartArgs([REDACTED])")
    }
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
    #[error(
        "native multi-hop is not implemented yet; this platform's release build cannot connect without weakening the production trust-split requirement"
    )]
    NativeMultiHopUnavailable,
    #[error(
        "native TDX is not implemented yet; the current platform bridge cannot carry the complete TDX workload policy"
    )]
    NativeTdxUnavailable,
    #[error("{0}")]
    UnsafeUrl(String),
    #[error("couldn't reach the path service: {0}")]
    Unreachable(String),
    #[error("the path service rejected the request (HTTP {0})")]
    Rejected(u16),
    #[error("path service returned an unusable path")]
    BadPath,
    #[error(
        "the path's node measurement is not in the client's pinned set (possible substitution)"
    )]
    PinMismatch,
    #[error("the path's transparency-log key does not match the client's independent key")]
    TransparencyKeyMismatch,
    #[error("invalid client trust configuration: {0}")]
    TrustConfig(String),
}

/// Refuse to spend a pass in a packaged native client whose datapath cannot honor the production
/// Coordinator's multi-hop path. Debug-assertion builds retain the one-hop device/integration
/// harness. This is intentionally a compile-profile decision, not an environment override.
pub fn require_supported_connection_profile() -> Result<(), ExtensionError> {
    if cfg!(debug_assertions) {
        Ok(())
    } else {
        Err(ExtensionError::NativeMultiHopUnavailable)
    }
}

/// The client-side, Coordinator-INDEPENDENT measurement pins the mobile client will accept for the
/// redeemed hop. Mirrors the desktop `nil_datapath::launch::pinned_measurements_from_env` so the
/// mobile attestation cross-check uses the SAME operator-controlled anchor, not whatever the
/// Coordinator claims (audit B1). Sourced from `NW_EXPECTED_MEASUREMENT` (single) and
/// `NW_PINNED_MEASUREMENTS` (comma-separated). Empty = no independent anchor (Coordinator-trusted,
/// warned). A mobile build can also seed these from app config before connecting; env keeps parity
/// with the desktop/CI path and makes the cross-check unit-testable.
pub fn client_pins_from_env() -> Result<Vec<Vec<u8>>, ExtensionError> {
    crate::trust::effective_node_measurements_from_env().map_err(ExtensionError::TrustConfig)
}

/// Redeem `token` at `coord_url` and resolve the (single-hop, alpha) attested start args for the
/// native datapath. Fail-closed: an unsafe URL, an unreachable/rejecting Coordinator, or an
/// empty/oversized/malformed/unattested path all error (→ the native tunnel never comes up).
pub async fn resolve_start_args(
    coord_url: &str,
    token: &StoredToken,
    client_pins: &[Vec<u8>],
    client_transparency_log_key: Option<[u8; 32]>,
) -> Result<StartArgs, ExtensionError> {
    require_supported_connection_profile()?;
    if coord_url.trim().is_empty() {
        return Err(ExtensionError::NoCoordinator);
    }
    // The token is a bearer credential — never POST it in cleartext to a non-loopback host (a
    // plaintext link also lets a MITM rewrite the per-hop measurement). Same gate as the datapath.
    crate::netpolicy::require_safe_control_url(coord_url).map_err(ExtensionError::UnsafeUrl)?;

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
    start_args_from_response_with_trust(&body, client_pins, client_transparency_log_key)
}

/// Pure: parse a `/v1/redeem` body into the native start args (first hop). Unit-tested without a
/// network. Fails closed on an empty/oversized/unattested/malformed path.
#[cfg(test)]
fn start_args_from_response(
    body: &[u8],
    client_pins: &[Vec<u8>],
) -> Result<StartArgs, ExtensionError> {
    start_args_from_response_with_trust(body, client_pins, None)
}

fn start_args_from_response_with_trust(
    body: &[u8],
    client_pins: &[Vec<u8>],
    client_transparency_log_key: Option<[u8; 32]>,
) -> Result<StartArgs, ExtensionError> {
    let resp: PathResponse = serde_json::from_slice(body).map_err(|_| ExtensionError::BadPath)?;
    // The native extension currently implements one MASQUE hop only. Accepting a longer path and
    // silently using its entry would discard the Coordinator's intended exit/security properties.
    if resp.hops.len() != MIN_HOPS {
        return Err(ExtensionError::BadPath);
    }
    // Take the directly-reachable hop (entry). The native gate attests it before any packet flows.
    let hop = resp
        .hops
        .into_iter()
        .next()
        .ok_or(ExtensionError::BadPath)?;

    // The current Kotlin/Swift IPC and native FFI carry MRTD but not the complete TDX workload
    // policy (TDATTRIBUTES/XFAM/config identities/RTMRs). Never discard that policy and fail later:
    // reject before StartArgs crosses the process boundary until the native contract carries it.
    if hop.tee == WireTee::Tdx {
        return Err(ExtensionError::NativeTdxUnavailable);
    }

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

    // The Coordinator may carry a transparency key per hop so the native appraisal policy can use
    // it. Parse it even in debug builds: a present-but-malformed key must never silently disable the
    // proof gate. Independently cross-check that value here before handing the hop to the data-plane
    // process; a missing/different key in a release bundle is a hard failure, not a Coordinator
    // default. We pass the independently trusted key (not an unchecked wire string) to native.
    let returned_transparency_key = match hop.transparency_log_key.as_deref() {
        Some(value) => connectip::from_hex(value.trim().as_bytes())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or(ExtensionError::BadPath)
            .map(Some)?,
        None => None,
    };
    if let Some(expected_key) = client_transparency_log_key {
        if returned_transparency_key != Some(expected_key) {
            return Err(ExtensionError::TransparencyKeyMismatch);
        }
    }
    let transparency_log_key_hex = client_transparency_log_key
        .or(returned_transparency_key)
        .map(|key| key.iter().map(|byte| format!("{byte:02x}")).collect())
        .unwrap_or_default();
    let tls_spki_sha256_hex = match hop.tls_spki_sha256.as_deref() {
        Some(value) => {
            let value = value.trim();
            match connectip::from_hex(value.as_bytes()) {
                Some(bytes) if bytes.len() == 32 => value.to_string(),
                _ => return Err(ExtensionError::BadPath),
            }
        }
        None => String::new(),
    };
    let tee_name = "sev-snp".to_string();
    let min_tcb_sevsnp = hop.min_tcb_sevsnp.map(|floor| NativeSevSnpTcbFloor {
        fmc: floor.fmc,
        bootloader: floor.bootloader,
        tee: floor.tee,
        snp: floor.snp,
        microcode: floor.microcode,
    });

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
        reservation_id: String::new(),
        server_name: hop.host.clone(),
        node_host: hop.host,
        node_port: hop.port,
        measurement_hex,
        tls_spki_sha256_hex,
        transparency_log_key_hex,
        tee_name,
        min_tcb_sevsnp,
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

    #[cfg(debug_assertions)]
    #[test]
    fn debug_profile_retains_the_native_single_hop_harness() {
        assert!(require_supported_connection_profile().is_ok());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_profile_refuses_native_before_a_pass_can_be_spent() {
        assert!(matches!(
            require_supported_connection_profile(),
            Err(ExtensionError::NativeMultiHopUnavailable)
        ));
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
        assert!(a.min_tcb_sevsnp.is_none());
        assert_eq!(a.measurement_hex, m);
        assert!(a.tls_spki_sha256_hex.is_empty());
        assert!(a.transparency_log_key_hex.is_empty());
        assert!(a.grant_hex.is_empty() && a.grant_nonce_hex.is_empty());
    }

    #[test]
    fn carries_tls_spki_identity_to_native_start_args() {
        let m = meas();
        let tls = "cd".repeat(32);
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}}]}}"#
        );
        let args = start_args_from_response(body.as_bytes(), &[]).expect("parse TLS identity");
        assert_eq!(args.tls_spki_sha256_hex, tls);
        let wire = serde_json::to_value(&args).expect("serialize native start args");
        assert_eq!(wire["tlsSpkiSha256Hex"], tls);
    }

    #[test]
    fn rejects_malformed_tls_spki_identity() {
        let m = meas();
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"abcd"}}]}}"#
        );
        assert!(matches!(
            start_args_from_response(body.as_bytes(), &[]),
            Err(ExtensionError::BadPath)
        ));
    }

    #[test]
    fn carries_complete_sev_snp_tcb_floor_to_native_start_args() {
        let m = meas();
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}","min_tcb_sevsnp":{{"fmc":7,"bootloader":3,"tee":0,"snp":8,"microcode":115}}}}]}}"#
        );
        let args = start_args_from_response(body.as_bytes(), &[]).expect("parse TCB floor");
        let floor = args.min_tcb_sevsnp.as_ref().expect("native TCB floor");
        assert_eq!(floor.fmc, Some(7));
        assert_eq!(floor.bootloader, 3);
        assert_eq!(floor.tee, 0);
        assert_eq!(floor.snp, 8);
        assert_eq!(floor.microcode, 115);

        let wire = serde_json::to_value(&args).expect("serialize native start args");
        assert_eq!(wire["minTcbSevsnp"]["fmc"], 7);
        assert_eq!(wire["minTcbSevsnp"]["microcode"], 115);
        assert!(wire.get("min_tcb_sevsnp").is_none());
    }

    #[test]
    fn carries_the_grant_through() {
        let m = meas();
        let grant = "cd".repeat(90);
        let nonce = "11".repeat(32);
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}","grant":"{grant}","grant_nonce":"{nonce}"}}]}}"#
        );
        let a = start_args_from_response(body.as_bytes(), &[]).expect("parse");
        assert_eq!(a.tee_name, "sev-snp");
        assert_eq!(a.grant_hex, grant);
        assert_eq!(a.grant_nonce_hex, nonce);
    }

    #[test]
    fn debug_format_redacts_routing_and_bearer_material() {
        let m = meas();
        let grant = "cd".repeat(90);
        let nonce = "11".repeat(32);
        let body = format!(
            r#"{{"hops":[{{"host":"secret.example","port":443,"tee":"sev-snp","measurement":"{m}","grant":"{grant}","grant_nonce":"{nonce}"}}]}}"#
        );
        let args = start_args_from_response(body.as_bytes(), &[]).expect("parse");
        let rendered = format!("{args:?}");
        assert_eq!(rendered, "StartArgs([REDACTED])");
        assert!(!rendered.contains("secret.example"));
        assert!(!rendered.contains(&grant));
        assert!(!rendered.contains(&nonce));
    }

    #[test]
    fn rejects_tdx_before_building_native_start_args() {
        let m = meas();
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"tdx","measurement":"{m}"}}]}}"#
        );
        assert!(matches!(
            start_args_from_response(body.as_bytes(), &[]),
            Err(ExtensionError::NativeTdxUnavailable)
        ));
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
        let body =
            br#"{"hops":[{"host":"e.example","port":443,"tee":"sev-snp","measurement":""}]}"#;
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
        let a =
            start_args_from_response(body.as_bytes(), &[pin]).expect("pinned measurement accepted");
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

    #[test]
    fn rejects_missing_or_substituted_transparency_key() {
        let m = meas();
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}"}}]}}"#
        );
        assert!(matches!(
            start_args_from_response_with_trust(body.as_bytes(), &[], Some([0xcd; 32])),
            Err(ExtensionError::TransparencyKeyMismatch)
        ));

        let wrong = "ef".repeat(32);
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}","transparency_log_key":"{wrong}"}}]}}"#
        );
        assert!(matches!(
            start_args_from_response_with_trust(body.as_bytes(), &[], Some([0xcd; 32])),
            Err(ExtensionError::TransparencyKeyMismatch)
        ));

        let key = "cd".repeat(32);
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}","transparency_log_key":"{key}"}}]}}"#
        );
        let args = start_args_from_response_with_trust(body.as_bytes(), &[], Some([0xcd; 32]))
            .expect("matching independently pinned transparency key");
        assert_eq!(args.transparency_log_key_hex, key);
        let wire = serde_json::to_value(&args).expect("serialize native start args");
        assert_eq!(wire["transparencyLogKeyHex"], key);
        assert!(wire.get("transparency_log_key_hex").is_none());
    }

    #[test]
    fn rejects_malformed_transparency_key_even_without_an_independent_pin() {
        let m = meas();
        let body = format!(
            r#"{{"hops":[{{"host":"e.example","port":443,"tee":"sev-snp","measurement":"{m}","transparency_log_key":"abcd"}}]}}"#
        );
        assert!(matches!(
            start_args_from_response(body.as_bytes(), &[]),
            Err(ExtensionError::BadPath)
        ));
    }
}
