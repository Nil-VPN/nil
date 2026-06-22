//! Client-side Privacy Pass redemption: exchange a token for a trust-split path at the Coordinator
//! (architecture spec §6–§8). This is the seam that makes the control plane *real at runtime* — the
//! token the Portal issued is redeemed here for the actual path, replacing the static `NW_PATH` dev
//! shim. Each [`nil_proto::path::Hop`] carries its OWN `tee` + `measurement`, so the returned
//! endpoints are per-hop attested (no single shared pin), feeding the MASQUE attestation gate.
//!
//! The token itself comes from `NW_TOKEN_MSG` + `NW_TOKEN` (hex) for now — the Portal → blind →
//! unblind → local token store acquisition is a separate client step. Behind the `launch` feature.

use anyhow::{Context, Result};
use nil_core::{AttestExpectation, Measurement, NodeEndpoint, Tee, TransportKind};
use nil_proto::path::{Hop, PathResponse, Tee as WireTee};
use nil_proto::token::RedeemRequest;
use nil_transport::connectip;

/// Redeem the token in `NW_TOKEN_MSG`/`NW_TOKEN` at the Coordinator (`coord_url`) and return the
/// attested trust-split path. Errors (fail closed) if the token env is missing, the Coordinator
/// rejects the token, or the response is empty/malformed.
pub async fn redeem_path_from_env(coord_url: &str) -> Result<Vec<NodeEndpoint>> {
    let msg = std::env::var("NW_TOKEN_MSG")
        .context("NW_COORDINATOR_URL is set but NW_TOKEN_MSG (token nonce, hex) is missing")?;
    let token = std::env::var("NW_TOKEN")
        .context("NW_COORDINATOR_URL is set but NW_TOKEN (unblinded token, hex) is missing")?;
    let req = RedeemRequest { msg, token };

    let url = format!("{}/v1/redeem", coord_url.trim_end_matches('/'));
    let http = reqwest::Client::builder()
        .build()
        .context("build coordinator http client")?;
    let resp = http
        .post(&url)
        .json(&req)
        .send()
        .await
        .context("POST /v1/redeem")?;
    if !resp.status().is_success() {
        // Don't log the token or any identifier — just the status (PD-2).
        anyhow::bail!("coordinator rejected token redemption: HTTP {}", resp.status().as_u16());
    }
    let body = resp.bytes().await.context("read /v1/redeem body")?;
    path_from_response(&body)
}

/// Pure: parse a `/v1/redeem` [`PathResponse`] body into attested [`NodeEndpoint`]s. Unit-tested
/// without a network. Fails closed on an empty path.
fn path_from_response(body: &[u8]) -> Result<Vec<NodeEndpoint>> {
    let resp: PathResponse = serde_json::from_slice(body).context("parse PathResponse")?;
    if resp.hops.is_empty() {
        anyhow::bail!("coordinator returned an empty path");
    }
    resp.hops.into_iter().map(hop_to_endpoint).collect()
}

/// Convert a wire [`Hop`] (host/port/tee/measurement/wg_pub) into a [`NodeEndpoint`] with its
/// per-hop pinned attestation expectation. A hop ALWAYS carries a measurement, so the resulting
/// endpoint always pins one — the MASQUE gate then attests every hop (never unattested).
fn hop_to_endpoint(h: Hop) -> Result<NodeEndpoint> {
    let measurement = connectip::from_hex(h.measurement.trim().as_bytes())
        .ok_or_else(|| anyhow::anyhow!("hop {}:{} measurement is not hex", h.host, h.port))?;
    let tee = match h.tee {
        WireTee::SevSnp => Tee::SevSnp,
        WireTee::Tdx => Tee::Tdx,
    };
    let wg_pub = match h.wg_pub {
        Some(s) => {
            let bytes = connectip::from_hex(s.trim().as_bytes())
                .ok_or_else(|| anyhow::anyhow!("hop {}:{} wg_pub is not hex", h.host, h.port))?;
            Some(
                <[u8; 32]>::try_from(bytes.as_slice())
                    .map_err(|_| anyhow::anyhow!("hop {}:{} wg_pub must be 32 bytes", h.host, h.port))?,
            )
        }
        None => None,
    };
    Ok(NodeEndpoint {
        host: h.host,
        port: h.port,
        kind: TransportKind::Masque,
        wg_pub,
        expected: Some(AttestExpectation { tee, measurement: Measurement(measurement) }),
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
        assert!(hops.iter().all(|h| h.expected.is_some()), "each hop must carry a pinned measurement");
        assert_eq!(hops[1].expected.as_ref().unwrap().tee, Tee::Tdx);
    }

    #[test]
    fn empty_path_fails_closed() {
        assert!(path_from_response(br#"{"hops":[]}"#).is_err(), "an empty path must be rejected");
    }

    #[test]
    fn malformed_measurement_is_rejected() {
        let body = r#"{"hops":[{"host":"x","port":443,"tee":"sev-snp","measurement":"nothex!!"}]}"#;
        assert!(path_from_response(body.as_bytes()).is_err());
    }
}
