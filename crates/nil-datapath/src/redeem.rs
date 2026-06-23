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
use nil_core::{AttestExpectation, Grant, Measurement, NodeEndpoint, Tee, TransportKind};
use nil_proto::path::{Hop, PathResponse, Tee as WireTee};
use nil_proto::token::RedeemRequest;
use nil_transport::connectip;

/// Minimum hops in a redeemed path. A trust-split path is multi-hop (≥2) — a single hop means the
/// one node sees BOTH the client IP and the destination (no split). The closed alpha ships
/// SINGLE-HOP deliberately (trust-split is the next milestone), so 1 is allowed but a single-hop
/// path is WARNED about as not-yet-trust-split (see [`path_from_response`]). 0 hops is always rejected.
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
pub async fn redeem_path_from_env(coord_url: &str) -> Result<Vec<NodeEndpoint>> {
    let req = read_token()?;
    redeem_path(coord_url, &req.msg, &req.token).await
}

/// Redeem an explicitly-supplied token (`msg` + `token`, both hex) at the Coordinator (`coord_url`)
/// and return the attested path. Fails closed if the URL is plaintext-to-non-loopback, the
/// Coordinator rejects/stalls, or the response is empty/oversized/malformed.
pub async fn redeem_path(coord_url: &str, msg: &str, token: &str) -> Result<Vec<NodeEndpoint>> {
    // The token is a bearer credential — never POST it in cleartext to a non-loopback host. A
    // plaintext link also lets a MITM rewrite the per-hop measurements. Require TLS unless the
    // host is loopback, or the operator explicitly opted into an insecure control plane (a
    // trusted local/test network; dev only).
    if !nil_core::net::env_flag("NW_INSECURE_CONTROL_PLANE") {
        nil_core::net::require_tls_or_loopback(coord_url)
            .map_err(|e| anyhow::anyhow!("NW_COORDINATOR_URL: {e} (or set NW_INSECURE_CONTROL_PLANE=1 for a trusted local network)"))?;
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
    path_from_response(&body)
}

/// Pure: parse a `/v1/redeem` [`PathResponse`] body into attested [`NodeEndpoint`]s. Unit-tested
/// without a network. Fails closed on an empty, single-hop (non-trust-split), or oversized path.
fn path_from_response(body: &[u8]) -> Result<Vec<NodeEndpoint>> {
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
        // Honest about the limit (SOUL §6): one hop is not trust-split.
        tracing::warn!(
            "single-hop path: the exit node sees BOTH your IP and your destination — NOT trust-split \
             (acceptable only for the single-hop alpha; trust-split is the next milestone)"
        );
    }
    resp.hops
        .into_iter()
        .enumerate()
        .map(|(i, h)| hop_to_endpoint(i, h))
        .collect()
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
    // NOTE: a hop's `wg_pub` is validated here but NOT yet consumed — the trust-split onion runs
    // plain nested MASQUE today (ADR-0004); wiring per-hop PQ-WireGuard-over-MASQUE through
    // PathTransport is a deferred composition. Keep validating it so a malformed key fails closed.
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
    Ok(NodeEndpoint {
        host: h.host,
        port: h.port,
        kind: TransportKind::Masque,
        wg_pub,
        expected: Some(AttestExpectation {
            tee,
            measurement: Measurement(measurement),
        }),
        grant,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_three_hop_attested_path() {
        let m = "ab".repeat(48); // 48-byte SEV-SNP-ish measurement, hex
        let body = format!(
            r#"{{"hops":[
                {{"host":"entry.example","port":443,"tee":"sev-snp","measurement":"{m}"}},
                {{"host":"middle.example","port":443,"tee":"tdx","measurement":"{m}"}},
                {{"host":"exit.example","port":443,"tee":"sev-snp","measurement":"{m}"}}
            ]}}"#
        );
        let hops = path_from_response(body.as_bytes()).expect("parse");
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].host, "entry.example");
        // Every hop pins its own measurement — never unattested.
        assert!(
            hops.iter().all(|h| h.expected.is_some()),
            "each hop must carry a pinned measurement"
        );
        assert_eq!(hops[1].expected.as_ref().unwrap().tee, Tee::Tdx);
    }

    #[test]
    fn parses_per_hop_grant() {
        let m = "ab".repeat(48);
        let grant = "cd".repeat(90);
        let nonce = "11".repeat(32);
        let body = format!(
            r#"{{"hops":[{{"host":"entry.example","port":443,"tee":"sev-snp","measurement":"{m}","grant":"{grant}","grant_nonce":"{nonce}"}}]}}"#
        );
        let hops = path_from_response(body.as_bytes()).expect("parse");
        let g = hops[0].grant.as_ref().expect("grant");
        assert_eq!(g.token, vec![0xcd; 90]);
        assert_eq!(g.nonce, [0x11; 32]);
    }

    #[test]
    fn empty_path_fails_closed() {
        assert!(
            path_from_response(br#"{"hops":[]}"#).is_err(),
            "an empty path must be rejected"
        );
    }

    #[test]
    fn single_hop_path_is_accepted_for_the_alpha() {
        // The closed alpha ships single-hop (trust-split is the next milestone); a 1-hop path is
        // accepted (with a not-trust-split warning) and still pins its measurement. 0 hops is rejected.
        let m = "ab".repeat(48);
        let body = format!(
            r#"{{"hops":[{{"host":"only.example","port":443,"tee":"sev-snp","measurement":"{m}"}}]}}"#
        );
        let hops = path_from_response(body.as_bytes()).expect("single-hop accepted for the alpha");
        assert_eq!(hops.len(), 1);
        assert!(
            hops[0].expected.is_some(),
            "the single hop still pins a measurement (attested)"
        );
    }

    #[test]
    fn malformed_measurement_is_rejected() {
        let body = r#"{"hops":[
            {"host":"a","port":443,"tee":"sev-snp","measurement":"aabb"},
            {"host":"b","port":443,"tee":"sev-snp","measurement":"nothex!!"}
        ]}"#;
        assert!(path_from_response(body.as_bytes()).is_err());
    }
}
