//! Headless end-to-end harness for the desktop client ENGINE (no GUI/webview).
//!
//! Drives the EXACT account → buy → connect → disconnect path the Tauri commands use, so CI/e2e
//! exercises the engine the GUI actually runs — not just `nil-cli`. Reaching `ENGINE-CONNECTED`
//! proves the full chain: token redeemed at the Coordinator, the node's hardware attestation
//! verified, the TUN up, routing + kill-switch armed (the engine returns `Connected` only after
//! `Tunnel::up` succeeds, which includes the attestation gate).
//!
//! Env: `PORTAL_URL`, `NW_COORDINATOR_URL`, `NW_PAYMENT_ID` (comp/payment id), the usual datapath
//! vars (`NW_NODE_HOST` / `NW_EXPECTED_MEASUREMENT` / `NW_ALLOW_UNATTESTED` …), and optionally
//! `NW_E2E_EGRESS_URL` (curled through the tunnel) + `NW_E2E_HOLD_SECS`. Prints greppable markers
//! and exits non-zero on the first failure (fail-closed).
//!
//! `NW_SUBSCRIBE=1` exercises the merged subscription flow (ADR-0007) instead of the legacy buy:
//! cache the phrase-derived auth key → subscribe → activate (against an `NW_MOCK_PAID_ALL` portal) →
//! mint a token ON DEMAND (the `maybe_mint_on_demand` path) → connect → then a RE-LOGIN leg proves a
//! fresh client re-derived only from the phrase still sees Active and mints again (reconnect, no new
//! payment). Markers: `SUBSCRIBE-OK`, `ACTIVATE-OK`, `MINT-ON-DEMAND-OK`, `RELOGIN-RECONNECT-OK`.

use std::time::Duration;

use nil_client_lib::account::PortalClient;
use nil_client_lib::authstore::AuthStore;
use nil_client_lib::engine::AppEngine;
use nil_client_lib::tokens::TokenClient;
use nil_client_lib::tokenstore::TokenStore;
use nil_proto::account::EntitlementDto;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|s| !s.is_empty())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("E2E-FAIL {e}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let portal = env("PORTAL_URL").unwrap_or_else(|| "http://127.0.0.1:8080".into());
    println!(
        "E2E portal={portal} coordinator={}",
        env("NW_COORDINATOR_URL").unwrap_or_else(|| "<none>".into())
    );

    // 1. Anonymous account — proves the client↔Portal 7-word contract.
    let acct = PortalClient::with_base_url(portal.clone())
        .create_anonymous()
        .await
        .map_err(|e| anyhow::anyhow!("account: {e}"))?;
    anyhow::ensure!(acct.recovery_phrase.len() == 7, "expected a 7-word recovery phrase");
    println!("ACCOUNT-OK words={}", acct.recovery_phrase.len());

    // 2. Token store (temp). Acquire one token via the REAL checkout flow (NW_CHECKOUT=1: mint a
    //    server reference, then issue against it — exercises the front-running guard end to end) or
    //    a pre-minted reference (NW_PAYMENT_ID, back-compat). With neither, no token is bought.
    let store_path = std::env::temp_dir().join(format!("nil-e2e-tokens-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&store_path);
    let store = TokenStore::open(store_path.clone());
    let client = TokenClient::with_base_url(portal.clone());

    if env("NW_SUBSCRIBE").is_some() {
        // Subscription path (ADR-0007). Cache the phrase-derived auth key at rest exactly as the real
        // client does on create/recover ("login"), then subscribe → activate → mint on demand.
        let material = nil_client_lib::derive_auth_material(&acct.recovery_phrase)
            .map_err(|e| anyhow::anyhow!("derive auth material: {e}"))?;
        let auth_path = std::env::temp_dir().join(format!("nil-e2e-auth-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&auth_path);
        AuthStore::open(auth_path.clone())
            .save(&material)
            .map_err(|e| anyhow::anyhow!("auth store: {e}"))?;

        let portal_client = PortalClient::with_base_url(portal.clone());
        let reference = portal_client
            .subscribe(&material)
            .await
            .map_err(|e| anyhow::anyhow!("subscribe: {e}"))?
            .payment_reference;
        println!("SUBSCRIBE-OK ref_len={}", reference.len());
        let status = portal_client
            .activate(&material, reference)
            .await
            .map_err(|e| anyhow::anyhow!("activate: {e}"))?;
        anyhow::ensure!(status.entitlement == EntitlementDto::Active, "activate did not yield Active");
        println!("ACTIVATE-OK entitlement=active until={:?}", status.until);

        // Mint ON DEMAND (mirrors `maybe_mint_on_demand`): empty buffer + cached material → mint one.
        let pre = store.count().map_err(|e| anyhow::anyhow!("token count: {e}"))?;
        anyhow::ensure!(pre == 0, "token buffer must be empty before mint-on-demand");
        let token = client.mint(&material).await.map_err(|e| anyhow::anyhow!("mint: {e}"))?;
        store.add(&[token]).map_err(|e| anyhow::anyhow!("token store: {e}"))?;
        let _ = std::fs::remove_file(&auth_path);
        println!("MINT-ON-DEMAND-OK");
    } else {
        // Legacy buy path: real checkout (NW_CHECKOUT=1) or a pre-minted reference (NW_PAYMENT_ID).
        let reference = if let Some(pid) = env("NW_PAYMENT_ID") {
            Some(pid)
        } else if env("NW_CHECKOUT").is_some() {
            let co = client.init_checkout().await.map_err(|e| anyhow::anyhow!("checkout: {e}"))?;
            println!("CHECKOUT-OK ref_len={}", co.payment_reference.len());
            Some(co.payment_reference)
        } else {
            None
        };
        if let Some(reference) = reference {
            let token = client
                .acquire(&reference)
                .await
                .map_err(|e| anyhow::anyhow!("acquire: {e}"))?;
            store.add(&[token]).map_err(|e| anyhow::anyhow!("token store: {e}"))?;
        }
    }
    let bal = store.count().map_err(|e| anyhow::anyhow!("token count: {e}"))?;
    println!("TOKEN-BALANCE={bal}");

    // 3. Connect via the engine (real attested datapath when NW_COORDINATOR_URL is set; otherwise
    //    the loopback mock). The engine redeems the token + verifies attestation before any packet.
    let engine = AppEngine::new();
    let token = store.take_one().map_err(|e| anyhow::anyhow!("take_one: {e}"))?;
    let st = engine.connect(token).await.map_err(|e| anyhow::anyhow!("connect: {e}"))?;
    println!("ENGINE-CONNECTED state={st:?}");

    // 4. Optional egress proof through the tunnel.
    if let Some(url) = env("NW_E2E_EGRESS_URL") {
        match std::process::Command::new("curl").args(["-s", "--max-time", "15", &url]).output() {
            Ok(o) => println!("EGRESS={}", String::from_utf8_lossy(&o.stdout).trim()),
            Err(e) => println!("EGRESS-ERR {e}"),
        }
    }

    // 5. Optional hold (so a wrapping script can probe), then disconnect cleanly.
    if let Some(s) = env("NW_E2E_HOLD_SECS").and_then(|s| s.parse::<u64>().ok()) {
        tokio::time::sleep(Duration::from_secs(s)).await;
    }
    let st = engine.disconnect().await.map_err(|e| anyhow::anyhow!("disconnect: {e}"))?;
    println!("ENGINE-DISCONNECTED state={st:?}");
    let _ = std::fs::remove_file(&store_path);

    // RE-LOGIN: a fresh client that re-derived auth material from the SAME phrase (no shared state)
    // must still see Active and mint again — the core acceptance: reconnect on any device, no new
    // payment. This is what "recover then connect" does in the real client.
    if env("NW_SUBSCRIBE").is_some() {
        let material = nil_client_lib::derive_auth_material(&acct.recovery_phrase)
            .map_err(|e| anyhow::anyhow!("re-login derive: {e}"))?;
        let status = PortalClient::with_base_url(portal.clone())
            .status(&material)
            .await
            .map_err(|e| anyhow::anyhow!("re-login status: {e}"))?;
        anyhow::ensure!(status.entitlement == EntitlementDto::Active, "re-login: subscription not Active");
        let token = TokenClient::with_base_url(portal.clone())
            .mint(&material)
            .await
            .map_err(|e| anyhow::anyhow!("re-login mint: {e}"))?;
        anyhow::ensure!(token.msg.len() == 64, "re-login: mint produced no usable token");
        println!("RELOGIN-RECONNECT-OK");
    }
    println!("E2E-OK");
    Ok(())
}
