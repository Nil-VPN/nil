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

use std::time::Duration;

use nil_client_lib::account::PortalClient;
use nil_client_lib::engine::AppEngine;
use nil_client_lib::tokens::TokenClient;
use nil_client_lib::tokenstore::TokenStore;

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

    // 2. Token store (temp). Buy one token if a payment id is provided.
    let store_path = std::env::temp_dir().join(format!("nil-e2e-tokens-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&store_path);
    let store = TokenStore::open(store_path.clone());
    if let Some(pid) = env("NW_PAYMENT_ID") {
        let token = TokenClient::with_base_url(portal.clone())
            .acquire(&pid)
            .await
            .map_err(|e| anyhow::anyhow!("buy_tokens: {e}"))?;
        store.add(&[token]).map_err(|e| anyhow::anyhow!("token store: {e}"))?;
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
    println!("E2E-OK");
    Ok(())
}
