//! Live subscription flow against a running `nil-portal`. Exercises the REAL client code
//! (`PortalClient` / `TokenClient` / the cached auth material) over HTTP — the path the Tauri
//! commands use — which the unit tests can't cover (they stop at the server). Ignored by default;
//! run it with a portal up and the mock-paid watcher (so activation confirms instantly):
//!
//!   NW_MOCK_PAID_ALL=1 NW_PORTAL_ADDR=127.0.0.1:8080 cargo run -p nil-portal &
//!   PORTAL_URL=http://127.0.0.1:8080 cargo test -p nil-client --test subscription_flow -- --ignored --nocapture

use nil_client_lib::account::PortalClient;
use nil_client_lib::authstore::AccountAuthMaterial;
use nil_client_lib::tokens::TokenClient;
use nil_proto::account::EntitlementDto;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Derive the cacheable auth material from a recovery phrase, exactly as the client does on login.
fn material_from_phrase(phrase: &[String]) -> AccountAuthMaterial {
    let parsed = nil_crypto::account::Phrase::parse(phrase).expect("phrase parses");
    let account_number =
        nil_crypto::account::account_number_from_phrase(&parsed).expect("account number");
    let keypair = nil_crypto::account::AuthKeypair::from_phrase(&parsed).expect("auth key");
    AccountAuthMaterial {
        account_number: hex(account_number.as_bytes()),
        auth_seed: hex(&keypair.to_seed_bytes()),
    }
}

#[tokio::test]
#[ignore = "needs a running nil-portal at PORTAL_URL with NW_MOCK_PAID_ALL=1"]
async fn subscribe_activate_mint_and_relogin() {
    let url = std::env::var("PORTAL_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let portal = PortalClient::with_base_url(url.clone());
    let tokens = TokenClient::with_base_url(url);

    // 1. Create an anonymous account; derive the auth material the client caches on "login".
    let account = portal.create_anonymous().await.expect("create account");
    let material = material_from_phrase(&account.recovery_phrase);

    // 2. A fresh account is NOT subscribed.
    let pre = portal.status(&material).await.expect("status (pre)");
    assert_ne!(pre.entitlement, EntitlementDto::Active, "a fresh account is not active");
    assert!(pre.until.is_none());

    // 3. Mint must be refused before subscribing (no active subscription).
    assert!(tokens.mint(&material).await.is_err(), "mint refused without a subscription");

    // 4. Subscribe → reference; activate (mock-paid confirms instantly) → Active with an expiry.
    let reference = portal.subscribe(&material).await.expect("subscribe").payment_reference;
    let activated = portal.activate(&material, reference.clone()).await.expect("activate");
    assert_eq!(activated.entitlement, EntitlementDto::Active);
    let until = activated.until.expect("active has an expiry");

    // 5. The SAME reference cannot extend twice (one extension per payment).
    assert!(portal.activate(&material, reference).await.is_err(), "no double-extend");

    // 6. Mint on demand against the active subscription → a real, well-formed unblinded token.
    let token = tokens.mint(&material).await.expect("mint while active");
    assert_eq!(token.msg.len(), 64, "msg is 32-byte hex");
    assert!(!token.token.is_empty() && token.token.bytes().all(|c| c.is_ascii_hexdigit()));

    // 7. Mint AGAIN — the subscription is unlimited-while-active, so a second token mints too, and
    //    the two are distinct (each connection spends its own).
    let token2 = tokens.mint(&material).await.expect("mint a second token");
    assert_ne!(token.msg, token2.msg, "each mint is a fresh, distinct token");

    // 8. RE-LOGIN simulation: a brand-new client (fresh PortalClient/TokenClient) that only re-derived
    //    the same material from the phrase — no shared state — still sees Active and can still mint.
    //    This is the core acceptance: log back in on any device → reconnect with no new payment.
    let relogin_material = material_from_phrase(&account.recovery_phrase);
    assert_eq!(relogin_material, material, "the phrase deterministically re-derives the auth material");
    let fresh_portal = PortalClient::with_base_url(std::env::var("PORTAL_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into()));
    let fresh_tokens = TokenClient::with_base_url(std::env::var("PORTAL_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into()));
    let relogin_status = fresh_portal.status(&relogin_material).await.expect("status after re-login");
    assert_eq!(relogin_status.entitlement, EntitlementDto::Active, "re-login sees the active subscription");
    assert_eq!(relogin_status.until, Some(until), "same expiry after re-login");
    let relogin_token = fresh_tokens.mint(&relogin_material).await.expect("mint after re-login");
    assert_eq!(relogin_token.msg.len(), 64, "a re-logged-in device mints a usable token");

    println!("OK: create → subscribe → activate → mint x2 → re-login → status Active → mint again");
}
