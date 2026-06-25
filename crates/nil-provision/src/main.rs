//! NIL VPN client provisioning helper.
//!
//! Acquires an unlinkable Privacy Pass token from the Portal and prints the token env
//! (`NW_TOKEN_MSG` / `NW_TOKEN`) for `nil-cli` to then redeem at the Coordinator for a trust-split
//! path. This is the "separate client step" the datapath redeem module references; it completes the
//! client control flow. The real flow is:
//!
//! 1. **checkout** — `POST /v1/billing/checkout` mints an unguessable payment *reference*. The
//!    front-running guard means issuance only proceeds for a reference WE minted, so a stranger who
//!    learns a confirmed payment id still cannot redeem it. The buyer pays that reference (as their
//!    Monero payment id). Pass `NW_PAYMENT_ID` to skip this and use an already-minted reference.
//! 2. **pubkey + blind** — `GET /v1/tokens/pubkey`, blind a fresh random message LOCALLY (once).
//! 3. **issue (poll)** — `POST /v1/tokens/issue`; the Portal blind-signs only once the payment for
//!    the reference confirms on-chain. Until then it returns 402, so we optionally poll at a wide
//!    interval (`NW_CHECKOUT_POLL_ATTEMPTS` / `NW_CHECKOUT_POLL_INTERVAL_SECS`).
//! 4. **finalize** — unblind locally into the opaque, unlinkable token.
//!
//! Privacy: it talks ONLY to the Business plane (Portal) and never sees a packet. The token is
//! blinded locally, so the Portal's signature cannot be linked to the token the Coordinator later
//! sees (Pillar 4). The payment reference indexes a payment, never a person (PD-3/PD-4). Nothing
//! identifying is printed: the human-facing reference/address go to STDERR; STDOUT carries only the
//! opaque `NW_TOKEN_*` lines a caller parses. The reference is never logged at `info`.

use std::time::Duration;

use anyhow::{Context, Result};
use nil_crypto::token;
use nil_proto::token::{CheckoutResponse, IssueRequest, IssueResponse, PubKeyResponse};

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

/// Mint a fresh, unguessable payment reference via `POST /v1/billing/checkout`, and print it (and
/// the deposit address, if configured) to STDERR for the human to pay. Returns the reference to
/// issue against. A Portal that predates checkout (404/405) is reported clearly so the operator can
/// fall back to an out-of-band reference via `NW_PAYMENT_ID` — the only server-incompatible case.
async fn checkout(http: &reqwest::Client, portal: &str) -> Result<String> {
    let resp = http
        .post(format!("{portal}/v1/billing/checkout"))
        .send()
        .await
        .context("POST /v1/billing/checkout")?;
    let status = resp.status();
    if matches!(status.as_u16(), 404 | 405) {
        anyhow::bail!(
            "this Portal has no /v1/billing/checkout (it predates the front-running guard). Obtain \
             a payment reference out-of-band and pass it as NW_PAYMENT_ID."
        );
    }
    if !status.is_success() {
        anyhow::bail!("checkout failed: HTTP {}", status.as_u16());
    }
    let co: CheckoutResponse = resp.json().await.context("parse checkout response")?;
    // Human-facing prompt on STDERR only (never logged): the reference + where to pay. STDOUT stays
    // reserved for the NW_TOKEN_* lines a caller parses.
    eprintln!("checkout: pay this reference as your Monero payment id, then issuance proceeds:");
    eprintln!("  reference: {}", co.payment_reference);
    if let Ok(addr) = std::env::var("NW_MONERO_ADDRESS") {
        if !addr.is_empty() {
            eprintln!("  deposit address: {addr}");
        }
    }
    Ok(co.payment_reference)
}

#[tokio::main]
async fn main() -> Result<()> {
    let portal = std::env::var("NW_PORTAL_URL").context("NW_PORTAL_URL (Portal base URL) is required")?;
    let portal = portal.trim_end_matches('/');
    // The blinded request, the blind signature, and the payment reference are sensitive — never
    // send them in cleartext to a non-loopback Portal. Require TLS unless loopback, or a dev opt-in.
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

    // 1. The payment reference: a pre-minted one via NW_PAYMENT_ID (back-compat / already paid), or
    //    mint a fresh one via checkout. NW_PAYMENT_ID also covers a Portal that predates checkout.
    let payment_id = match std::env::var("NW_PAYMENT_ID") {
        Ok(p) if !p.is_empty() => p,
        _ => checkout(&http, portal).await?,
    };

    // 2. Fetch the issuer's public key (needed to blind locally).
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

    // 3. Blind a fresh random token message ONCE. The blinding secret stays in this process; the
    //    same blinded request is reused across poll attempts (a 402 attempt issues nothing).
    let mut msg = [0u8; 32];
    getrandom::getrandom(&mut msg).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
    let req = token::blind(&pubkey_der, &msg).map_err(|e| anyhow::anyhow!("blind: {e}"))?;
    let issue = IssueRequest { payment_id: payment_id.clone(), blind_msg: hex(&req.blind_msg) };

    // 4. Ask the Portal to blind-sign (it verifies the payment confirmed, never seeing `msg`). The
    //    Portal returns 402 until the payment for the reference confirms on-chain; poll at a WIDE
    //    interval (the issue endpoint is rate-limited, so a tight poll would be throttled).
    let attempts: u32 = std::env::var("NW_CHECKOUT_POLL_ATTEMPTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let interval = Duration::from_secs(
        std::env::var("NW_CHECKOUT_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(20),
    );
    let mut last_status = 0u16;
    for attempt in 1..=attempts {
        let resp = http
            .post(format!("{portal}/v1/tokens/issue"))
            .json(&issue)
            .send()
            .await
            .context("POST /v1/tokens/issue")?;
        if resp.status().is_success() {
            let issued: IssueResponse = resp.json().await.context("parse issue response")?;
            let blind_sig = unhex(&issued.blind_sig)?;
            // 5. Unblind → the final, unlinkable token. Emit the env for the Coordinator redemption.
            let tok = token::finalize(&pubkey_der, &req, &blind_sig)
                .map_err(|e| anyhow::anyhow!("finalize: {e}"))?;
            println!("NW_TOKEN_MSG={}", hex(&msg));
            println!("NW_TOKEN={}", hex(&tok));
            return Ok(());
        }
        last_status = resp.status().as_u16();
        // Both 402 (payment not yet confirmed) and 429 (the issue endpoint is rate-limited — a
        // fixed-window cap that resets, so it's transient) are retryable while attempts remain;
        // anything else is terminal. Draining the budgeted attempts through a throttle beats giving
        // up on the first 429 — and polling is exactly what adds the request volume that trips it.
        if matches!(last_status, 402 | 429) && attempt < attempts {
            let why = if last_status == 429 { "rate-limited by the Portal" } else { "payment not yet confirmed" };
            eprintln!("{why} (attempt {attempt}/{attempts}); waiting {}s…", interval.as_secs());
            tokio::time::sleep(interval).await;
        } else {
            break;
        }
    }
    // No identifiers in the error — just the status and how to proceed. The payment reference is a
    // payment index (PD-3/PD-4); it must not be echoed into an error that lands on stderr / CI logs
    // / shell history. The caller still has it in NW_PAYMENT_ID, so we guide the retry without
    // reprinting the value.
    match last_status {
        402 => anyhow::bail!(
            "payment not confirmed after {attempts} attempt(s); pay the reference shown at checkout, \
             then re-run with the same NW_PAYMENT_ID (or raise NW_CHECKOUT_POLL_ATTEMPTS)."
        ),
        409 => anyhow::bail!("a token was already issued for this payment reference"),
        429 => anyhow::bail!(
            "the issue endpoint is rate-limited (HTTP 429) and attempts are exhausted; widen \
             NW_CHECKOUT_POLL_INTERVAL_SECS / raise NW_CHECKOUT_POLL_ATTEMPTS, or retry shortly."
        ),
        other => anyhow::bail!("Portal refused token issuance: HTTP {other}"),
    }
}
