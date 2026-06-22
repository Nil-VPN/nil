//! NIL VPN client provisioning helper.
//!
//! Acquires an unlinkable Privacy Pass token from the Portal — `GET /v1/tokens/pubkey` → blind a
//! fresh random message → `POST /v1/tokens/issue` (the Portal blind-signs, gated on a confirmed
//! payment) → finalize — and prints the token env (`NW_TOKEN_MSG` / `NW_TOKEN`) for `nil-cli` to
//! then redeem at the Coordinator for a trust-split path. This is the "separate client step" the
//! datapath redeem module references; it completes the client control flow.
//!
//! Privacy: it talks ONLY to the Business plane (Portal) and never sees a packet. The token is
//! blinded locally, so the Portal's signature cannot be linked to the token the Coordinator later
//! sees (Pillar 4). Nothing identifying is printed — only the opaque token bytes.

use anyhow::{Context, Result};
use nil_crypto::token;
use nil_proto::token::{IssueRequest, IssueResponse, PubKeyResponse};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        anyhow::bail!("odd-length hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("invalid hex"))
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let portal = std::env::var("NW_PORTAL_URL").context("NW_PORTAL_URL (Portal base URL) is required")?;
    let payment_id =
        std::env::var("NW_PAYMENT_ID").context("NW_PAYMENT_ID (a confirmed payment id) is required")?;
    let portal = portal.trim_end_matches('/');
    let http = reqwest::Client::builder().build().context("build http client")?;

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
