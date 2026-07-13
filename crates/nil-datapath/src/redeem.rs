//! Client-side Privacy Pass redemption: exchange a token for a trust-split path at the Coordinator
//! (architecture spec §6–§8). This is the seam that makes the control plane *real at runtime* — the
//! token the Portal issued is redeemed here for the actual path, replacing the static `NW_PATH` dev
//! shim. Each [`nil_proto::path::Hop`] carries its OWN `tee` + `measurement`, so the returned
//! endpoints are per-hop attested (no single shared pin), feeding the MASQUE attestation gate.
//!
//! The token is the unblinded Privacy Pass token (a bearer credential): preferably from
//! `NW_TOKEN_FILE` (a file doesn't leak via `/proc/<pid>/environ` or process listings), else from
//! `NW_TOKEN` (env) + a warning; its message nonce is `NW_TOKEN_MSG`. The Portal → blind → issue →
//! finalize acquisition is a separate client step (see `nil-provision`). Behind the `launch` feature.

use std::time::Duration;

use anyhow::{Context, Result};
use nil_core::{
    AttestExpectation, Grant, Measurement, NodeEndpoint, SevSnpTcbFloor, TdxMeasurement, TdxPolicy,
    Tee, TransportKind,
};
use nil_proto::path::{Hop, PathResponse, TdxPolicy as WireTdxPolicy, Tee as WireTee};
use nil_proto::token::RedeemRequest;
use nil_transport::connectip;

/// Minimum structurally valid hop count. Debug builds may exercise a one-hop development path, but
/// release builds impose the stronger trust-split policy below and reject anything below two hops.
const MIN_HOPS: usize = 1;
/// Sanity cap on a Coordinator-returned path (the Coordinator is a distinct, not-fully-trusted
/// domain). A real path is a handful of hops; anything larger is rejected.
const MAX_HOPS: usize = 8;
/// Cap the `/v1/redeem` response body — a `PathResponse` is tiny; refuse a hostile/compromised
/// Coordinator trying to OOM the client with an unbounded body.
const MAX_BODY: usize = 64 * 1024;
/// Bound the control-plane round-trip: a Coordinator that accepts the connection but never
/// responds must fail (→ kill-switch holds) rather than hang `from_env()` forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Read the token message + the token itself. The token (bearer credential) is preferred from a
/// file (`NW_TOKEN_FILE`); the env var (`NW_TOKEN`) works but is warned about.
fn read_token() -> Result<RedeemRequest> {
    let msg = std::env::var("NW_TOKEN_MSG")
        .context("NW_COORDINATOR_URL is set but NW_TOKEN_MSG (token nonce, hex) is missing")?;
    let token = if let Ok(path) = std::env::var("NW_TOKEN_FILE") {
        std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("read NW_TOKEN_FILE {path}: {e}"))?
            .trim()
            .to_string()
    } else {
        tracing::warn!(
            "NW_TOKEN (env) holds a bearer credential that leaks via /proc/<pid>/environ and \
             process listings; prefer NW_TOKEN_FILE in production"
        );
        std::env::var("NW_TOKEN")
            .context("NW_COORDINATOR_URL is set but neither NW_TOKEN_FILE nor NW_TOKEN is set")?
    };
    Ok(RedeemRequest { msg, token })
}

/// Redeem the token in `NW_TOKEN_MSG` + `NW_TOKEN[_FILE]` at the Coordinator. Used by `nil-cli`
/// (headless); the desktop engine holds the token in-process and calls [`redeem_path`] directly.
///
/// `client_pins` is the client-side, Coordinator-INDEPENDENT set of measurements the client will
/// accept for ANY hop (see [`crate::launch::pinned_measurements_from_env`]). Threaded through so
/// the cross-check in [`redeem_path`] uses the operator's own pin, not whatever the Coordinator
/// claims (audit B1, see [`cross_check_trust`]).
pub async fn redeem_path_from_env(
    coord_url: &str,
    client_pins: &[Vec<u8>],
    client_transparency_log_key: Option<[u8; 32]>,
) -> Result<Vec<NodeEndpoint>> {
    let req = read_token()?;
    redeem_path(
        coord_url,
        &req.msg,
        &req.token,
        client_pins,
        client_transparency_log_key,
    )
    .await
}

/// Redeem an explicitly-supplied token (`msg` + `token`, both hex) at the Coordinator (`coord_url`)
/// and return the attested path. Fails closed if a release build's URL is not HTTPS, the
/// Coordinator rejects/stalls, the response is empty/oversized/malformed, OR a returned hop's
/// measurement is not in `client_pins` (the substitution cross-check, see [`cross_check_trust`]).
pub async fn redeem_path(
    coord_url: &str,
    msg: &str,
    token: &str,
    client_pins: &[Vec<u8>],
    client_transparency_log_key: Option<[u8; 32]>,
) -> Result<Vec<NodeEndpoint>> {
    // The token is a bearer credential — never POST it in cleartext to a non-loopback host. A
    // plaintext link also lets a MITM rewrite the per-hop measurements. Release builds require
    // HTTPS unconditionally; debug builds may use genuine loopback HTTP or explicitly opt into a
    // trusted local test network.
    if !nil_core::net::dev_env_flag("NW_INSECURE_CONTROL_PLANE") {
        nil_core::net::require_https_or_debug_loopback(coord_url)
            .map_err(|e| {
                #[cfg(debug_assertions)]
                return anyhow::anyhow!(
                    "NW_COORDINATOR_URL: {e} (or set NW_INSECURE_CONTROL_PLANE=1 for a trusted local development network)"
                );
                #[cfg(not(debug_assertions))]
                anyhow::anyhow!("NW_COORDINATOR_URL: {e}; production builds require HTTPS")
            })?;
    }

    let req = RedeemRequest {
        msg: msg.to_owned(),
        token: token.to_owned(),
    };
    let url = format!("{}/v1/redeem", coord_url.trim_end_matches('/'));
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("build coordinator http client")?;
    let mut resp = http
        .post(&url)
        .json(&req)
        .send()
        .await
        .context("POST /v1/redeem")?;
    if !resp.status().is_success() {
        // No token/identifier in the log — only the status (PD-2).
        anyhow::bail!(
            "coordinator rejected token redemption: HTTP {}",
            resp.status().as_u16()
        );
    }
    // Read the body with a hard cap (don't trust the Coordinator's Content-Length / stream length).
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("read /v1/redeem body")? {
        if body.len() + chunk.len() > MAX_BODY {
            anyhow::bail!("coordinator /v1/redeem response exceeds {MAX_BODY} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    path_from_response_with_trust(&body, client_pins, client_transparency_log_key)
}

/// Pure: parse a `/v1/redeem` [`PathResponse`] body into attested [`NodeEndpoint`]s, then
/// cross-check each hop's Coordinator-provided measurement against the client's independent pin
/// (see [`cross_check_trust`]). Unit-tested without a network. Fails closed on an empty,
/// single-hop in production (non-trust-split), oversized, or
/// pin-mismatched path.
#[cfg(test)]
fn path_from_response(body: &[u8], client_pins: &[Vec<u8>]) -> Result<Vec<NodeEndpoint>> {
    path_from_response_with_trust(body, client_pins, None)
}

fn path_from_response_with_trust(
    body: &[u8],
    client_pins: &[Vec<u8>],
    client_transparency_log_key: Option<[u8; 32]>,
) -> Result<Vec<NodeEndpoint>> {
    let resp: PathResponse = serde_json::from_slice(body).context("parse PathResponse")?;
    if resp.hops.len() < MIN_HOPS {
        anyhow::bail!("coordinator returned an empty path");
    }
    if resp.hops.len() > MAX_HOPS {
        anyhow::bail!(
            "coordinator returned {} hops (> {MAX_HOPS})",
            resp.hops.len()
        );
    }
    if resp.hops.len() == 1 {
        #[cfg(not(debug_assertions))]
        anyhow::bail!(
            "coordinator returned a single-hop path; production builds require at least two hops for trust splitting"
        );

        #[cfg(debug_assertions)]
        if !nil_core::net::dev_env_flag("NW_FORCE_SINGLE_HOP") {
            tracing::warn!(
                "single-hop path: the exit node sees BOTH your IP and your destination — NOT trust-split \
                 (development only; production requires at least two hops)"
            );
        }
    }
    let endpoints: Vec<NodeEndpoint> = resp
        .hops
        .into_iter()
        .enumerate()
        .map(|(i, h)| hop_to_endpoint(i, h))
        .collect::<Result<_>>()?;
    cross_check_trust(&endpoints, client_pins, client_transparency_log_key)?;
    Ok(endpoints)
}

/// Audit B1 — client-side measurement-transparency cross-check (fail-closed).
///
/// The Coordinator hands the client each hop's pinned attestation measurement in the `/v1/redeem`
/// response, and the MASQUE gate would otherwise attest every hop against *that* value on faith.
/// A compromised or coerced Coordinator can substitute a measurement to point the client at a
/// rogue/backdoored node it controls. This cross-check removes that blind trust: if the client
/// has ANY independent pin configured, every hop's Coordinator-provided measurement MUST be in the
/// pinned set or the whole path is refused (kill-switch holds, no tunnel).
///
/// THREAT MODEL — what this defends against: a Coordinator (compromised, coerced, or a malicious
/// future operator) swapping in a measurement for a node it controls. With a pin, the substituted
/// measurement is not in the client's set, so the path is refused before any packet flows.
///
/// RESIDUAL TRUST — what this does NOT defend against (do not overclaim):
///   - The client still trusts the Coordinator to SELECT which nodes / which jurisdiction the path
///     uses (availability and routing). A pin says "only these measurements are acceptable"; it
///     does not say "this is the node you should be using."
///   - The pin is only as good as its INDEPENDENCE. It must come from a genuinely independent
///     source — out-of-band operator config, the published reproducible-build measurement the user
///     verified themselves, or (future) an operator-signed measurement registry. If the same
///     operator who runs the Coordinator also tells the user what to pin, the independence — and so
///     the value of this check — is weaker.
///   - A fully independent trust anchor (operator-signed registry entries, or Sigstore/Rekor
///     verification of the published measurement) is a further step not implemented here.
///
/// With NO pin configured the function keeps today's behavior: it logs a clear WARN that the path
/// is Coordinator-trusted (no independent pin) and accepts it (back-compat). Logs are PII-free:
/// no measurement bytes and no hop hosts ever reach a log line.
fn cross_check_trust(
    endpoints: &[NodeEndpoint],
    client_pins: &[Vec<u8>],
    client_transparency_log_key: Option<[u8; 32]>,
) -> Result<()> {
    if client_pins.is_empty() {
        // No independent anchor — fall back to trusting the Coordinator's per-hop pins, but say so
        // loudly so an operator never believes an independent cross-check is in force when it isn't.
        tracing::warn!(
            "no client-side measurement pin (NW_EXPECTED_MEASUREMENT / NW_PINNED_MEASUREMENTS unset): \
             the redeemed path is COORDINATOR-TRUSTED — a compromised Coordinator could substitute a \
             hop measurement and it would be accepted. Pin from an independent source to cross-check"
        );
    }
    for (idx, ep) in endpoints.iter().enumerate() {
        // Every redeemed hop carries a measurement (`hop_to_endpoint` always sets `expected`).
        let expectation = ep.expected.as_ref().ok_or_else(|| {
            anyhow::anyhow!("redeemed path hop {idx}: missing attestation expectation")
        })?;
        if !client_pins.is_empty()
            && !client_pins
                .iter()
                .any(|pin| pin == &expectation.measurement.0)
        {
            // Substitution detected (or simply an unpinned node) — refuse the WHOLE path, fail
            // closed. No measurement bytes, no host in the log (PD-2 / no-PII): only the hop index.
            anyhow::bail!(
                "redeemed path hop {idx}: Coordinator-provided measurement is not in the \
                 client's pinned set (NW_EXPECTED_MEASUREMENT / NW_PINNED_MEASUREMENTS) — \
                 refusing the path (possible measurement substitution by the Coordinator)"
            );
        }
        if let Some(pinned_key) = client_transparency_log_key {
            if expectation.transparency_log_key != Some(pinned_key) {
                anyhow::bail!(
                    "redeemed path hop {idx}: Coordinator-provided transparency-log key does not \
                     match the client's independent key — refusing the path"
                );
            }
        }
    }
    if !client_pins.is_empty() || client_transparency_log_key.is_some() {
        tracing::info!(
            hops = endpoints.len(),
            measurement_pinned = !client_pins.is_empty(),
            transparency_key_pinned = client_transparency_log_key.is_some(),
            "redeemed path cross-checked against independent client trust roots"
        );
    }
    Ok(())
}

/// Convert a wire [`Hop`] into a [`NodeEndpoint`] with its per-hop pinned attestation expectation.
/// A hop ALWAYS carries a measurement, so the endpoint always pins one — the MASQUE gate then
/// attests every hop (never unattested). Errors identify the hop by INDEX, never by host:port, so
/// the granted path's node addresses never reach a log line (no-IPs-in-logs invariant).
fn hop_to_endpoint(idx: usize, h: Hop) -> Result<NodeEndpoint> {
    let measurement = connectip::from_hex(h.measurement.trim().as_bytes())
        .ok_or_else(|| anyhow::anyhow!("redeemed path hop {idx}: measurement is not hex"))?;
    let tee = match h.tee {
        WireTee::SevSnp => Tee::SevSnp,
        WireTee::Tdx => Tee::Tdx,
    };
    let tls_spki_sha256 = match h.tls_spki_sha256 {
        Some(hex) => {
            let bytes = connectip::from_hex(hex.trim().as_bytes()).ok_or_else(|| {
                anyhow::anyhow!("redeemed path hop {idx}: tls_spki_sha256 is not hex")
            })?;
            Some(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                anyhow::anyhow!("redeemed path hop {idx}: tls_spki_sha256 must be 32 bytes")
            })?)
        }
        None => {
            #[cfg(not(debug_assertions))]
            anyhow::bail!("redeemed path hop {idx}: missing production TLS SPKI identity pin");
            #[cfg(debug_assertions)]
            None
        }
    };
    // A hop's `wg_pub`, when present, drives per-hop PQ-WireGuard-over-MASQUE. `PathTransport`
    // PQ-wraps EVERY hop that carries a key (not just the exit): the carrier for hop N+1 is hop N's
    // PQ-WG session, so each leg rides the hybrid PSK (see `PathTransport::connect`). A malformed key
    // fails the path closed regardless of which hop it is.
    let wg_pub =
        match h.wg_pub {
            Some(s) => {
                let bytes = connectip::from_hex(s.trim().as_bytes())
                    .ok_or_else(|| anyhow::anyhow!("redeemed path hop {idx}: wg_pub is not hex"))?;
                Some(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                    anyhow::anyhow!("redeemed path hop {idx}: wg_pub must be 32 bytes")
                })?)
            }
            None => None,
        };
    let grant = match (h.grant, h.grant_nonce) {
        (Some(token_hex), Some(nonce_hex)) => {
            let token = connectip::from_hex(token_hex.trim().as_bytes())
                .ok_or_else(|| anyhow::anyhow!("redeemed path hop {idx}: grant is not hex"))?;
            let nonce_bytes =
                connectip::from_hex(nonce_hex.trim().as_bytes()).ok_or_else(|| {
                    anyhow::anyhow!("redeemed path hop {idx}: grant_nonce is not hex")
                })?;
            let nonce = <[u8; 32]>::try_from(nonce_bytes.as_slice()).map_err(|_| {
                anyhow::anyhow!("redeemed path hop {idx}: grant_nonce must be 32 bytes")
            })?;
            Some(Grant { token, nonce })
        }
        (None, None) => None,
        _ => anyhow::bail!(
            "redeemed path hop {idx}: grant and grant_nonce must be provided together"
        ),
    };
    // Per-hop offline attestation floors published by the Coordinator. Both are enforced by the
    // MASQUE gate (`nil_attest::appraise`): a `current_tcb` below the floor, or a measurement absent
    // from the pinned transparency log, fails the hop closed. Absent ⇒ measurement pin alone gates.
    if tee == Tee::Tdx && h.min_tcb_sevsnp.is_some() {
        anyhow::bail!("redeemed path hop {idx}: min_tcb_sevsnp is invalid for TDX");
    }
    let min_tcb_sevsnp = h.min_tcb_sevsnp.map(|f| SevSnpTcbFloor {
        fmc: f.fmc,
        bootloader: f.bootloader,
        tee: f.tee,
        snp: f.snp,
        microcode: f.microcode,
    });
    let tdx_policy = match (tee, h.tdx_policy) {
        (Tee::Tdx, Some(policy)) => Some(tdx_policy_from_wire(policy).map_err(|error| {
            anyhow::anyhow!("redeemed path hop {idx}: invalid TDX policy: {error}")
        })?),
        (Tee::Tdx, None) => {
            anyhow::bail!("redeemed path hop {idx}: missing mandatory TDX policy")
        }
        (Tee::SevSnp, Some(_)) => {
            anyhow::bail!("redeemed path hop {idx}: TDX policy is invalid for SEV-SNP")
        }
        (Tee::SevSnp, None) => None,
    };
    let transparency_log_key = match h.transparency_log_key {
        Some(hex) => {
            let bytes = connectip::from_hex(hex.trim().as_bytes()).ok_or_else(|| {
                anyhow::anyhow!("redeemed path hop {idx}: transparency_log_key is not hex")
            })?;
            Some(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                anyhow::anyhow!("redeemed path hop {idx}: transparency_log_key must be 32 bytes")
            })?)
        }
        None => None,
    };
    Ok(NodeEndpoint {
        host: h.host,
        port: h.port,
        kind: TransportKind::Masque,
        wg_pub,
        expected: Some(AttestExpectation {
            tee,
            measurement: Measurement(measurement),
            tls_spki_sha256,
            min_tcb_sevsnp,
            tdx_policy,
            transparency_log_key,
        }),
        grant,
    })
}

fn decode_policy_hex<const N: usize>(field: &str, value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("{field} must be exactly {N} bytes of canonical lowercase hex");
    }
    nil_core::grant::from_hex(value)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("{field} is not valid canonical hex"))
}

/// Convert the dependency-free wire DTO into length-safe core policy types. For TDX, the hop's
/// independently pinned `measurement` is the NIL identity digest over MRTD plus these values; this
/// conversion supplies the exact values the appraisal gate recomputes and checks against it. It is
/// also used by the direct-node environment path so both sources enforce one fail-closed grammar.
pub(crate) fn tdx_policy_from_wire(dto: WireTdxPolicy) -> Result<TdxPolicy> {
    let td_attributes = decode_policy_hex::<8>("tdx_policy.td_attributes", &dto.td_attributes)?;
    if td_attributes[0] & 0x01 != 0 {
        anyhow::bail!("tdx_policy.td_attributes must not enable TDX debug mode");
    }
    let rt_mr0 = decode_policy_hex::<48>("tdx_policy.rt_mr0", &dto.rt_mr0)?;
    let rt_mr1 = decode_policy_hex::<48>("tdx_policy.rt_mr1", &dto.rt_mr1)?;
    let rt_mr2 = decode_policy_hex::<48>("tdx_policy.rt_mr2", &dto.rt_mr2)?;
    let rt_mr3 = decode_policy_hex::<48>("tdx_policy.rt_mr3", &dto.rt_mr3)?;
    for (name, value) in [
        ("rt_mr0", &rt_mr0),
        ("rt_mr1", &rt_mr1),
        ("rt_mr2", &rt_mr2),
        ("rt_mr3", &rt_mr3),
    ] {
        if value.iter().all(|byte| *byte == 0) {
            anyhow::bail!("tdx_policy.{name} must be nonzero");
        }
    }

    Ok(TdxPolicy {
        td_attributes,
        xfam: decode_policy_hex("tdx_policy.xfam", &dto.xfam)?,
        mr_config_id: TdxMeasurement(decode_policy_hex(
            "tdx_policy.mr_config_id",
            &dto.mr_config_id,
        )?),
        mr_owner: TdxMeasurement(decode_policy_hex("tdx_policy.mr_owner", &dto.mr_owner)?),
        mr_owner_config: TdxMeasurement(decode_policy_hex(
            "tdx_policy.mr_owner_config",
            &dto.mr_owner_config,
        )?),
        rt_mr0: TdxMeasurement(rt_mr0),
        rt_mr1: TdxMeasurement(rt_mr1),
        rt_mr2: TdxMeasurement(rt_mr2),
        rt_mr3: TdxMeasurement(rt_mr3),
        mr_service_td: dto
            .mr_service_td
            .as_deref()
            .map(|value| decode_policy_hex("tdx_policy.mr_service_td", value).map(TdxMeasurement))
            .transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No client-side pin → keep today's Coordinator-trusted behavior (back-compat path).
    const NO_PINS: &[Vec<u8>] = &[];

    /// The 48-byte measurement these fixtures use, as raw bytes (matches `"ab".repeat(48)` hex).
    fn ab_measurement() -> Vec<u8> {
        vec![0xab; 48]
    }

    fn tls_spki_hex() -> String {
        "11".repeat(32)
    }

    fn wire_tdx_policy() -> WireTdxPolicy {
        WireTdxPolicy {
            td_attributes: "0000001000000000".into(),
            xfam: "02".repeat(8),
            mr_config_id: "03".repeat(48),
            mr_owner: "04".repeat(48),
            mr_owner_config: "05".repeat(48),
            rt_mr0: "06".repeat(48),
            rt_mr1: "07".repeat(48),
            rt_mr2: "08".repeat(48),
            rt_mr3: "09".repeat(48),
            mr_service_td: Some("0a".repeat(48)),
        }
    }

    fn tdx_policy_json() -> String {
        serde_json::to_string(&wire_tdx_policy()).expect("serialize TDX fixture")
    }

    #[test]
    fn parses_a_three_hop_attested_path() {
        let m = "ab".repeat(48); // 48-byte SEV-SNP-ish measurement, hex
        let tls = tls_spki_hex();
        let tdx_policy = tdx_policy_json();
        let body = format!(
            r#"{{"hops":[
                {{"host":"entry.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}},
                {{"host":"middle.example","port":443,"tee":"tdx","measurement":"{m}","tls_spki_sha256":"{tls}","tdx_policy":{tdx_policy}}},
                {{"host":"exit.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}}
            ]}}"#
        );
        let hops = path_from_response(body.as_bytes(), NO_PINS).expect("parse");
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].host, "entry.example");
        // Every hop pins its own measurement — never unattested.
        assert!(
            hops.iter().all(|h| h.expected.is_some()),
            "each hop must carry a pinned measurement"
        );
        let tdx = hops[1].expected.as_ref().unwrap();
        assert_eq!(tdx.tee, Tee::Tdx);
        let policy = tdx.tdx_policy.as_ref().expect("TDX policy propagated");
        assert_eq!(policy.td_attributes, [0, 0, 0, 0x10, 0, 0, 0, 0]);
        assert_eq!(policy.rt_mr3, TdxMeasurement([0x09; 48]));
        assert_eq!(policy.mr_service_td, Some(TdxMeasurement([0x0a; 48])));
    }

    #[test]
    fn tdx_hop_requires_a_complete_canonical_policy() {
        let m = "ab".repeat(48);
        let tls = tls_spki_hex();
        let missing = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"tdx","measurement":"{m}","tls_spki_sha256":"{tls}"}}]}}"#
        );
        let error = path_from_response(missing.as_bytes(), NO_PINS).unwrap_err();
        assert!(error.to_string().contains("missing mandatory TDX policy"));

        let mut malformed = wire_tdx_policy();
        malformed.mr_owner = "AA".repeat(48);
        let malformed = serde_json::to_string(&malformed).unwrap();
        let body = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"tdx","measurement":"{m}","tls_spki_sha256":"{tls}","tdx_policy":{malformed}}}]}}"#
        );
        let error = path_from_response(body.as_bytes(), NO_PINS).unwrap_err();
        assert!(error.to_string().contains("tdx_policy.mr_owner"));

        let mut zero_rtmr = wire_tdx_policy();
        zero_rtmr.rt_mr3 = "00".repeat(48);
        let zero_rtmr = serde_json::to_string(&zero_rtmr).unwrap();
        let body = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"tdx","measurement":"{m}","tls_spki_sha256":"{tls}","tdx_policy":{zero_rtmr}}}]}}"#
        );
        let error = path_from_response(body.as_bytes(), NO_PINS).unwrap_err();
        assert!(error
            .to_string()
            .contains("tdx_policy.rt_mr3 must be nonzero"));

        let mut debug = wire_tdx_policy();
        debug.td_attributes = "0100001000000000".into();
        let debug = serde_json::to_string(&debug).unwrap();
        let body = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"tdx","measurement":"{m}","tls_spki_sha256":"{tls}","tdx_policy":{debug}}}]}}"#
        );
        let error = path_from_response(body.as_bytes(), NO_PINS).unwrap_err();
        assert!(error.to_string().contains("must not enable TDX debug mode"));
    }

    #[test]
    fn redeemed_hop_rejects_cross_tee_policy_fields() {
        let m = "ab".repeat(48);
        let tls = tls_spki_hex();
        let tdx_policy = tdx_policy_json();
        let sev_with_tdx = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}","tdx_policy":{tdx_policy}}}]}}"#
        );
        assert!(path_from_response(sev_with_tdx.as_bytes(), NO_PINS).is_err());

        let tdx_with_sev = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"tdx","measurement":"{m}","tls_spki_sha256":"{tls}","tdx_policy":{tdx_policy},"min_tcb_sevsnp":{{"bootloader":1,"tee":2,"snp":3,"microcode":4}}}}]}}"#
        );
        assert!(path_from_response(tdx_with_sev.as_bytes(), NO_PINS).is_err());
    }

    #[test]
    fn parses_per_hop_grant() {
        let m = "ab".repeat(48);
        let grant = "cd".repeat(90);
        let nonce = "11".repeat(32);
        let tls = tls_spki_hex();
        let body = format!(
            r#"{{"hops":[
                {{"host":"entry.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}","grant":"{grant}","grant_nonce":"{nonce}"}},
                {{"host":"exit.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}}
            ]}}"#
        );
        let hops = path_from_response(body.as_bytes(), NO_PINS).expect("parse");
        let g = hops[0].grant.as_ref().expect("grant");
        assert_eq!(g.token, vec![0xcd; 90]);
        assert_eq!(g.nonce, [0x11; 32]);
    }

    #[test]
    fn coordinator_hop_min_tcb_floor_and_transparency_key_reach_the_appraisal_policy() {
        // A Coordinator-published hop carrying a min-TCB floor + a transparency-log key must surface
        // them on the hop's AttestExpectation, so the MASQUE gate enforces them (they were previously
        // dropped to None on the redeemed path, making both defenses inert in production).
        let m = "ab".repeat(48);
        let key = "cd".repeat(32); // 32-byte Ed25519 log key, hex
        let tls = tls_spki_hex();
        let body = format!(
            r#"{{"hops":[
               {{"host":"entry.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}",
                "min_tcb_sevsnp":{{"bootloader":3,"tee":0,"snp":8,"microcode":115}},
                "transparency_log_key":"{key}"}},
               {{"host":"exit.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}}
            ]}}"#
        );
        let hops = path_from_response(body.as_bytes(), NO_PINS).expect("parse");
        let exp = hops[0].expected.as_ref().expect("pinned expectation");
        assert_eq!(
            exp.min_tcb_sevsnp,
            Some(SevSnpTcbFloor {
                fmc: None,
                bootloader: 3,
                tee: 0,
                snp: 8,
                microcode: 115
            }),
            "the per-hop TCB floor must reach the appraisal policy"
        );
        assert_eq!(
            exp.transparency_log_key,
            Some([0xcd; 32]),
            "the per-hop transparency-log key must reach the appraisal policy"
        );
        assert_eq!(exp.tls_spki_sha256, Some([0x11; 32]));
    }

    #[test]
    fn independent_transparency_key_rejects_missing_or_substituted_coordinator_key() {
        let m = "ab".repeat(48);
        let tls = tls_spki_hex();
        let missing = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}}]}}"#
        );
        assert!(path_from_response_with_trust(
            missing.as_bytes(),
            &[ab_measurement()],
            Some([0xcd; 32]),
        )
        .is_err());

        let wrong = "ef".repeat(32);
        let substituted = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}","transparency_log_key":"{wrong}"}}]}}"#
        );
        assert!(path_from_response_with_trust(
            substituted.as_bytes(),
            &[ab_measurement()],
            Some([0xcd; 32]),
        )
        .is_err());

        let key = "cd".repeat(32);
        let matching = format!(
            r#"{{"hops":[
                {{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}","transparency_log_key":"{key}"}},
                {{"host":"b","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}","transparency_log_key":"{key}"}}
            ]}}"#
        );
        assert!(path_from_response_with_trust(
            matching.as_bytes(),
            &[ab_measurement()],
            Some([0xcd; 32]),
        )
        .is_ok());
    }

    #[test]
    fn absent_floor_and_transparency_key_stay_none() {
        // TLS identity is present, while optional TCB/transparency policy remains absent.
        let m = "ab".repeat(48);
        let tls = tls_spki_hex();
        let body = format!(
            r#"{{"hops":[
                {{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}},
                {{"host":"b","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}}
            ]}}"#
        );
        let hops = path_from_response(body.as_bytes(), NO_PINS).expect("parse");
        let exp = hops[0].expected.as_ref().expect("pinned expectation");
        assert_eq!(exp.min_tcb_sevsnp, None);
        assert_eq!(exp.transparency_log_key, None);
        assert_eq!(exp.tls_spki_sha256, Some([0x11; 32]));
    }

    #[test]
    fn malformed_transparency_log_key_fails_the_path_closed() {
        let m = "ab".repeat(48);
        let tls = tls_spki_hex();
        // Not hex → whole path rejected (fail closed, no silently-dropped key).
        let bad_hex = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}","transparency_log_key":"zz"}}]}}"#
        );
        assert!(
            path_from_response(bad_hex.as_bytes(), NO_PINS).is_err(),
            "non-hex key must fail"
        );
        // Right hex, wrong length (not 32 bytes) → rejected too.
        let wrong_len = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}","transparency_log_key":"abcd"}}]}}"#
        );
        assert!(
            path_from_response(wrong_len.as_bytes(), NO_PINS).is_err(),
            "a non-32-byte key must fail"
        );
    }

    #[test]
    fn malformed_tls_spki_identity_pin_fails_the_path_closed() {
        let m = "ab".repeat(48);
        for digest in ["zz".to_string(), "11".repeat(31)] {
            let body = format!(
                r#"{{"hops":[{{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{digest}"}}]}}"#
            );
            assert!(path_from_response(body.as_bytes(), NO_PINS).is_err());
        }
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_rejects_a_multi_hop_path_without_tls_identity_pins() {
        let m = "ab".repeat(48);
        let body = format!(
            r#"{{"hops":[
                {{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}"}},
                {{"host":"b","port":443,"tee":"sev-snp","measurement":"{m}"}}
            ]}}"#
        );
        let error = path_from_response(body.as_bytes(), NO_PINS).unwrap_err();
        assert!(error.to_string().contains("missing production TLS SPKI"));
    }

    #[test]
    fn grant_requires_a_paired_32_byte_nonce() {
        // A grant MUST be bound to a per-connection nonce, and that nonce must be exactly 32 bytes.
        // Any half-specified or wrong-length grant fails the whole path closed (no unbound grant).
        let m = "ab".repeat(48);
        let grant = "cd".repeat(90);
        let tls = tls_spki_hex();

        // grant with NO grant_nonce → rejected (must be provided together).
        let only_grant = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}","grant":"{grant}"}}]}}"#
        );
        assert!(
            path_from_response(only_grant.as_bytes(), NO_PINS).is_err(),
            "a grant with no grant_nonce is rejected"
        );

        // grant_nonce with NO grant → rejected.
        let nonce = "11".repeat(32);
        let only_nonce = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}","grant_nonce":"{nonce}"}}]}}"#
        );
        assert!(
            path_from_response(only_nonce.as_bytes(), NO_PINS).is_err(),
            "a grant_nonce with no grant is rejected"
        );

        // grant + a WRONG-LENGTH (16-byte) nonce → rejected.
        let short = "11".repeat(16);
        let bad_len = format!(
            r#"{{"hops":[{{"host":"a","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}","grant":"{grant}","grant_nonce":"{short}"}}]}}"#
        );
        assert!(
            path_from_response(bad_len.as_bytes(), NO_PINS).is_err(),
            "the grant nonce must be exactly 32 bytes"
        );
    }

    #[test]
    fn empty_path_fails_closed() {
        assert!(
            path_from_response(br#"{"hops":[]}"#, NO_PINS).is_err(),
            "an empty path must be rejected"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn single_hop_path_is_accepted_only_in_debug_builds() {
        // A debug harness may exercise a one-hop path (with a not-trust-split warning), while the
        // corresponding release-cfg test below proves that production rejects it.
        let m = "ab".repeat(48);
        let body = format!(
            r#"{{"hops":[{{"host":"only.example","port":443,"tee":"sev-snp","measurement":"{m}"}}]}}"#
        );
        let hops = path_from_response(body.as_bytes(), NO_PINS)
            .expect("single-hop accepted by the debug harness");
        assert_eq!(hops.len(), 1);
        assert!(
            hops[0].expected.is_some(),
            "the single hop still pins a measurement (attested)"
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn single_hop_path_is_rejected_in_release_even_with_an_override_in_the_environment() {
        let m = "ab".repeat(48);
        let body = format!(
            r#"{{"hops":[{{"host":"only.example","port":443,"tee":"sev-snp","measurement":"{m}"}}]}}"#
        );
        // `dev_env_flag` is compile-time disabled here, so no process environment value can turn
        // this into an accepted production path.
        assert!(path_from_response(body.as_bytes(), NO_PINS).is_err());
    }

    #[test]
    fn malformed_measurement_is_rejected() {
        let body = r#"{"hops":[
            {"host":"a","port":443,"tee":"sev-snp","measurement":"aabb"},
            {"host":"b","port":443,"tee":"sev-snp","measurement":"nothex!!"}
        ]}"#;
        assert!(path_from_response(body.as_bytes(), NO_PINS).is_err());
    }

    // ---- Audit B1: client-side measurement-transparency cross-check ----

    #[test]
    fn matching_pin_is_accepted() {
        // (a) A redeemed path whose hop measurement matches the client's independent pin is accepted.
        let m = "ab".repeat(48);
        let tls = tls_spki_hex();
        let body = format!(
            r#"{{"hops":[
                {{"host":"entry.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}},
                {{"host":"exit.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}}
            ]}}"#
        );
        let pins = vec![ab_measurement()];
        let hops = path_from_response(body.as_bytes(), &pins).expect("matching pin accepted");
        assert_eq!(hops.len(), 2);
    }

    #[test]
    fn substituted_measurement_is_refused() {
        // (b) The substitution attack: the Coordinator returns a hop whose measurement is NOT in
        // the client's pinned set → the WHOLE path is refused (fail closed, kill-switch holds).
        let pinned = "ab".repeat(48);
        let rogue = "cd".repeat(48); // a measurement the operator never pinned (rogue node)
        let tls = tls_spki_hex();
        let body = format!(
            r#"{{"hops":[
                {{"host":"entry.example","port":443,"tee":"sev-snp","measurement":"{pinned}","tls_spki_sha256":"{tls}"}},
                {{"host":"exit.example","port":443,"tee":"sev-snp","measurement":"{rogue}","tls_spki_sha256":"{tls}"}}
            ]}}"#
        );
        let pins = vec![ab_measurement()]; // only the genuine measurement is pinned
        assert!(
            path_from_response(body.as_bytes(), &pins).is_err(),
            "a substituted (unpinned) hop measurement must be refused"
        );
    }

    #[test]
    fn no_pin_path_is_accepted_for_back_compat() {
        // (c) With no client pin configured, the path stays Coordinator-trusted (a WARN is logged
        // by `cross_check_pins`) and is accepted — preserving today's behavior.
        let m = "ef".repeat(48);
        let tls = tls_spki_hex();
        let body = format!(
            r#"{{"hops":[
                {{"host":"entry.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}},
                {{"host":"exit.example","port":443,"tee":"sev-snp","measurement":"{m}","tls_spki_sha256":"{tls}"}}
            ]}}"#
        );
        let hops = path_from_response(body.as_bytes(), NO_PINS)
            .expect("no-pin path accepted (back-compat)");
        assert_eq!(hops.len(), 2);
    }

    #[test]
    fn multi_value_pin_accepts_any_listed_measurement() {
        // A multi-hop path where each hop matches a DIFFERENT entry in the pinned set (the
        // per-operator / per-jurisdiction case): all hops are accepted because every measurement
        // is somewhere in the set.
        let entry_m = "ab".repeat(48);
        let exit_m = "cd".repeat(48);
        let tls = tls_spki_hex();
        let tdx_policy = tdx_policy_json();
        let body = format!(
            r#"{{"hops":[
                {{"host":"entry.example","port":443,"tee":"sev-snp","measurement":"{entry_m}","tls_spki_sha256":"{tls}"}},
                {{"host":"exit.example","port":443,"tee":"tdx","measurement":"{exit_m}","tls_spki_sha256":"{tls}","tdx_policy":{tdx_policy}}}
            ]}}"#
        );
        let pins = vec![vec![0xab; 48], vec![0xcd; 48]];
        let hops = path_from_response(body.as_bytes(), &pins).expect("both pinned → accepted");
        assert_eq!(hops.len(), 2);
    }
}
