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
//! prefetch a bounded batch → connect using one already-local pass → then a RE-LOGIN leg proves a
//! fresh client re-derived only from the phrase still sees Active and can prefetch again (no new
//! payment). Markers: `SUBSCRIBE-OK`, `ACTIVATE-OK`, `BATCH-PREFETCH-OK`,
//! `RELOGIN-RECONNECT-OK`.

use std::time::Duration;

use nil_client_lib::account::PortalClient;
use nil_client_lib::authstore::AuthStore;
use nil_client_lib::engine::AppEngine;
use nil_client_lib::securestore::SecureVault;
use nil_client_lib::tokens::TokenClient;
use nil_client_lib::tokenstore::TokenStore;
use nil_proto::account::EntitlementDto;

const E2E_PREFETCH_BATCH: usize = 8;

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
    let coordinator = env("NW_COORDINATOR_URL");
    println!(
        "E2E portal={portal} coordinator={}",
        coordinator.clone().unwrap_or_else(|| "<none>".into())
    );

    // 1. Anonymous account — proves local mnemonic generation + public-only Portal registration.
    let acct = PortalClient::with_base_url(portal.clone())
        .create_anonymous()
        .await
        .map_err(|e| anyhow::anyhow!("account: {e}"))?;
    anyhow::ensure!(
        acct.recovery_phrase.len() == 12,
        "expected a 12-word recovery phrase"
    );
    println!("ACCOUNT-OK words={}", acct.recovery_phrase.len());

    // 2. Token store (temp). Acquire one token via the REAL checkout flow (NW_CHECKOUT=1: mint a
    //    server reference, then issue against it — exercises the front-running guard end to end) or
    //    a pre-minted reference (NW_PAYMENT_ID, back-compat). With neither, no token is bought.
    let vault_path =
        std::env::temp_dir().join(format!("nil-e2e-secure-{}/vault.bin", std::process::id()));
    let _ = std::fs::remove_file(&vault_path);
    let vault = SecureVault::open_platform(vault_path.clone())?;
    let store = TokenStore::new(vault.clone());
    let client = TokenClient::with_base_url(portal.clone());

    if env("NW_SUBSCRIBE").is_some() {
        // Subscription path. Cache the phrase-derived auth key at rest exactly as the real client
        // does on create/recover ("login"), then subscribe → activate → batch-prefetch.
        let material = nil_client_lib::derive_auth_material(&acct.recovery_phrase)
            .map_err(|e| anyhow::anyhow!("derive auth material: {e}"))?;
        AuthStore::new(vault.clone())
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
        anyhow::ensure!(
            status.entitlement == EntitlementDto::Active,
            "activate did not yield Active"
        );
        println!("ACTIVATE-OK entitlement=active until={:?}", status.until);

        // Exercise the same canonical batch protocol as the randomized background worker. The E2E
        // invokes it directly so the test never sleeps for privacy jitter.
        let pre = store
            .count()
            .map_err(|e| anyhow::anyhow!("token count: {e}"))?;
        anyhow::ensure!(pre == 0, "token buffer must be empty before batch prefetch");
        let completed = client
            .mint_batch_into_store(&material, E2E_PREFETCH_BATCH, &store)
            .await
            .map_err(|e| anyhow::anyhow!("batch prefetch: {e}"))?;
        let added = store
            .commit_mint(&completed.request_id, completed.tokens.clone())
            .map_err(|e| anyhow::anyhow!("token store: {e}"))?;
        println!("BATCH-PREFETCH-OK count={added}");
    } else {
        // Legacy buy path: real checkout (NW_CHECKOUT=1) or a pre-minted reference (NW_PAYMENT_ID).
        let reference = if let Some(pid) = env("NW_PAYMENT_ID") {
            Some(pid)
        } else if env("NW_CHECKOUT").is_some() {
            let co = client
                .init_checkout()
                .await
                .map_err(|e| anyhow::anyhow!("checkout: {e}"))?;
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
            store
                .add(&[token])
                .map_err(|e| anyhow::anyhow!("token store: {e}"))?;
        }
    }
    let bal = store
        .count()
        .map_err(|e| anyhow::anyhow!("token count: {e}"))?;
    println!("TOKEN-BALANCE={bal}");

    // 3. Connect via the engine (real attested datapath when NW_COORDINATOR_URL is set; otherwise
    //    the debug-assertions-only loopback seam). Build this local harness with `--profile e2e`,
    //    never true `--release`, which deliberately compiles the fallback out.
    let engine = AppEngine::new();
    let reservation = if coordinator.is_some() {
        store
            .reserve_one()
            .map_err(|e| anyhow::anyhow!("reserve_one: {e}"))?
    } else {
        None
    };
    let token = reservation
        .as_ref()
        .map(|reservation| reservation.token.clone());
    let st = engine
        .connect(token)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e}"))?;
    if let Some(reservation) = reservation {
        store
            .commit_redemption(&reservation.reservation_id)
            .map_err(|e| anyhow::anyhow!("commit_redemption: {e}"))?;
    }
    println!("ENGINE-CONNECTED state={st:?}");

    // 4. Optional egress proof through the tunnel.
    if let Some(url) = env("NW_E2E_EGRESS_URL") {
        match std::process::Command::new("curl")
            .args(["-s", "--max-time", "15", &url])
            .output()
        {
            Ok(o) => println!("EGRESS={}", String::from_utf8_lossy(&o.stdout).trim()),
            Err(e) => println!("EGRESS-ERR {e}"),
        }
    }

    // 5. Optional hold (so a wrapping script can probe), then disconnect cleanly.
    if let Some(s) = env("NW_E2E_HOLD_SECS").and_then(|s| s.parse::<u64>().ok()) {
        tokio::time::sleep(Duration::from_secs(s)).await;
    }
    let st = engine
        .disconnect()
        .await
        .map_err(|e| anyhow::anyhow!("disconnect: {e}"))?;
    println!("ENGINE-DISCONNECTED state={st:?}");
    let _ = std::fs::remove_file(&vault_path);

    // RE-LOGIN: a fresh client that re-derived auth material from the SAME phrase (no shared state)
    // must still see Active and prefetch again — the core acceptance: recover on any device, wait
    // for its randomized background batch, then connect without a new payment.
    if env("NW_SUBSCRIBE").is_some() {
        let material = nil_client_lib::derive_auth_material(&acct.recovery_phrase)
            .map_err(|e| anyhow::anyhow!("re-login derive: {e}"))?;
        let status = PortalClient::with_base_url(portal.clone())
            .status(&material)
            .await
            .map_err(|e| anyhow::anyhow!("re-login status: {e}"))?;
        anyhow::ensure!(
            status.entitlement == EntitlementDto::Active,
            "re-login: subscription not Active"
        );
        let tokens = TokenClient::with_base_url(portal.clone())
            .mint_batch(&material, 2)
            .await
            .map_err(|e| anyhow::anyhow!("re-login prefetch: {e}"))?;
        anyhow::ensure!(
            tokens.len() == 2 && tokens.iter().all(|token| token.msg.len() == 64),
            "re-login: batch prefetch produced unusable tokens"
        );
        println!("RELOGIN-RECONNECT-OK");
    }
    println!("E2E-OK");
    Ok(())
}
