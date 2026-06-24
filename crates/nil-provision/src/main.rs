//! NIL VPN client provisioning helper.
//!
//! Acquires an unlinkable Privacy Pass token from the Portal — `GET /v1/tokens/pubkey` → blind a
//! fresh random message → `POST /v1/tokens/issue` (the Portal blind-signs, gated on a confirmed
//! payment) → finalize — and prints the token env (`NW_TOKEN_MSG` / `NW_TOKEN`) for `nil-cli` to
//! then redeem at the Coordinator for a trust-split path. This is the "separate client step" the
//! datapath redeem module references; it completes the client control flow.
//!
//! `NW_PAYMENT_ID` is the *checkout reference* the Portal minted via `POST /v1/billing/checkout`
//! (and which the buyer paid) — not a free-chosen string. Issuance enforces that front-running
//! guard, so an id that was never minted by checkout is refused even if a payment confirmed for it.
//!
//! Privacy: it talks ONLY to the Business plane (Portal) and never sees a packet. The token is
//! blinded locally, so the Portal's signature cannot be linked to the token the Coordinator later
//! sees (Pillar 4). Nothing identifying is printed — only the opaque token bytes.

use std::time::Duration;

use anyhow::{Context, Result};
use nil_crypto::token;
use nil_proto::token::{IssueRequest, IssueResponse, PubKeyResponse};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Decode hex, operating on BYTES (not `&str` indexing) so a malformed multi-byte response field
/// returns an error instead of panicking on a codepoint boundary.
fn unhex(s: &str) -> Result<Vec<u8>> {
    let b = s.trim().as_bytes();
    if b.len() % 2 != 0 {
        anyhow::bail!("odd-length hex");
    }
    fn nib(c: u8) -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => anyhow::bail!("invalid hex"),
        }
    }
    b.chunks_exact(2).map(|p| Ok((nib(p[0])? << 4) | nib(p[1])?)).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let portal = std::env::var("NW_PORTAL_URL").context("NW_PORTAL_URL (Portal base URL) is required")?;
    let payment_id = std::env::var("NW_PAYMENT_ID")
        .context("NW_PAYMENT_ID (the checkout reference from POST /v1/billing/checkout) is required")?;
    let portal = portal.trim_end_matches('/');
    // The blinded request, the blind signature, and the payment id are sensitive — never send them
    // in cleartext to a non-loopback Portal. Require TLS unless loopback, or an explicit dev opt-in.
    if !nil_core::net::env_flag("NW_INSECURE_CONTROL_PLANE") {
        nil_core::net::require_tls_or_loopback(portal)
            .map_err(|e| anyhow::anyhow!("NW_PORTAL_URL: {e} (or set NW_INSECURE_CONTROL_PLANE=1 for a trusted local network)"))?;
    }
    // Bound the round-trips so a hung Portal can't block provisioning forever.
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")?;

    // 1. Fetch the issuer's public key (needed to blind locally).
    let pk: PubKeyResponse = http
        .get(format!("{portal}/v1/tokens/pubkey"))
        .send()
        .await
        .context("GET /v1/tokens/pubkey")?
        .error_for_status()
        .context("pubkey request failed")?
        .json()
        .await
        .context("parse pubkey response")?;
    let pubkey_der = unhex(&pk.public_der)?;

    // 2. Blind a fresh random token message. The blinding secret stays in this process.
    let mut msg = [0u8; 32];
    getrandom::getrandom(&mut msg).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
    let req = token::blind(&pubkey_der, &msg).map_err(|e| anyhow::anyhow!("blind: {e}"))?;

    // 3. Ask the Portal to blind-sign (it verifies the payment is confirmed, never seeing `msg`).
    let issue = IssueRequest { payment_id, blind_msg: hex(&req.blind_msg) };
    let resp = http
        .post(format!("{portal}/v1/tokens/issue"))
        .json(&issue)
        .send()
        .await
        .context("POST /v1/tokens/issue")?;
    if !resp.status().is_success() {
        // No identifiers in the error — just the status.
        anyhow::bail!("Portal refused token issuance: HTTP {}", resp.status().as_u16());
    }
    let issued: IssueResponse = resp.json().await.context("parse issue response")?;
    let blind_sig = unhex(&issued.blind_sig)?;

    // 4. Unblind → the final, unlinkable token. Emit the env for the Coordinator redemption.
    let tok = token::finalize(&pubkey_der, &req, &blind_sig).map_err(|e| anyhow::anyhow!("finalize: {e}"))?;
    println!("NW_TOKEN_MSG={}", hex(&msg));
    println!("NW_TOKEN={}", hex(&tok));
    Ok(())
}
