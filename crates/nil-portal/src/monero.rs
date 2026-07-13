//! Self-hosted Monero payment watcher (architecture spec §7). Token issuance is gated on a
//! confirmed Monero payment, but payment is decoupled from identity: the only handle is a
//! payment id the buyer chooses — never an account, never traffic. The watcher answers one
//! question: "has a confirmed payment for this id been seen?".
//!
//! [`MoneroRpcWatcher`] polls a self-hosted `monero-wallet-rpc` (`get_transfers {"in":true}`) in
//! the background and marks each incoming transfer with enough confirmations as confirmed; the
//! hot path ([`PaymentWatcher::is_confirmed`]) just checks that in-memory set, so it stays sync
//! and fast. The poll loop needs a live monerod + watch-only wallet (out of CI scope), but the
//! parsing/confirmation logic ([`parse_confirmed`]) is pure and unit-tested. Fail closed: no
//! confirmed transfer ⇒ no token.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use serde::Deserialize;

/// Answers whether a payment has been confirmed. Implementations watch a self-hosted
/// monero-wallet-rpc; tests use the in-memory mock.
pub trait PaymentWatcher: Send + Sync {
    fn is_confirmed(&self, payment_id: &str) -> bool;
}

/// Test/dev watcher: a fixed (or mutable) set of confirmed payment ids — or, for integration
/// harnesses that pay a *server-minted checkout reference* (a 256-bit value unknowable when the
/// Portal starts, so it cannot be pre-seeded), a mode that treats every id as confirmed.
#[cfg(any(debug_assertions, test))]
pub struct MockWatcher {
    confirmed: Mutex<HashSet<String>>,
    /// Dev/integration only: confirm ANY payment id, standing in for "the buyer paid the reference
    /// the server just minted". This does NOT weaken the front-running guard: issuance still
    /// requires the id to be one the Portal minted via `/v1/billing/checkout`
    /// ([`crate::billing::is_known_reference`]), so an un-minted id is rejected regardless of
    /// confirmation. Enabled via `NW_MOCK_PAID_ALL`; the mock is not compiled into builds without
    /// debug assertions (except test harnesses).
    confirm_all: bool,
}

#[cfg(any(debug_assertions, test))]
impl MockWatcher {
    pub fn with_paid<I: IntoIterator<Item = String>>(ids: I) -> Self {
        Self {
            confirmed: Mutex::new(ids.into_iter().collect()),
            confirm_all: false,
        }
    }
    /// A dev/integration watcher that treats every payment id as confirmed (see `confirm_all`).
    pub fn confirm_everything() -> Self {
        Self {
            confirmed: Mutex::new(HashSet::new()),
            confirm_all: true,
        }
    }
    /// Mark a payment confirmed (e.g. when the real watcher observes it). Used by tests.
    #[allow(dead_code)]
    pub fn confirm(&self, payment_id: &str) {
        self.confirmed
            .lock()
            .expect("mock watcher mutex")
            .insert(payment_id.to_string());
    }
}

#[cfg(any(debug_assertions, test))]
impl PaymentWatcher for MockWatcher {
    fn is_confirmed(&self, payment_id: &str) -> bool {
        self.confirm_all
            || self
                .confirmed
                .lock()
                .expect("mock watcher mutex")
                .contains(payment_id)
    }
}

/// Monero's "no payment id" sentinel (short payment ids are zero when absent).
///
/// NOTE — short (8-byte) payment ids are DEPRECATED upstream and matched here only for
/// backward compatibility. The modern, recommended way to attribute an incoming payment is a
/// per-payment *subaddress*: the wallet derives a unique subaddress per checkout, and an
/// incoming transfer's `subaddr_index` (returned by `get_transfers`) identifies the checkout
/// without any payment id at all. That is strictly better for privacy and reliability (no
/// integrated-address payment id to leak or fat-finger, no on-chain encrypted-payment-id
/// quirks). [`parse_confirmed_by_subaddress`] implements that matching; the payment-id path
/// remains for wallets/flows that still send a short id. See the architecture spec §7.
const NULL_PAYMENT_ID: &str = "0000000000000000";

/// `get_transfers` response (only the fields we need).
#[derive(Deserialize)]
struct RpcResponse {
    result: Option<TransfersResult>,
}
#[derive(Deserialize)]
struct TransfersResult {
    #[serde(default, rename = "in")]
    incoming: Vec<Transfer>,
}
#[derive(Deserialize)]
struct Transfer {
    #[serde(default)]
    payment_id: String,
    #[serde(default)]
    confirmations: u64,
    /// Amount received, in atomic units (1 XMR = 1e12). Used to reject underpayment.
    #[serde(default)]
    amount: u64,
    /// The subaddress the transfer arrived on (`{"major":m,"minor":n}`). The recommended,
    /// payment-id-free way to attribute a payment to a checkout: one fresh subaddress per
    /// checkout, identified by its `minor` index within the wallet account.
    #[serde(default)]
    #[allow(dead_code)]
    // read by parse_confirmed_by_subaddress (subaddress-based checkout path)
    subaddr_index: SubaddrIndex,
}

/// Monero subaddress index (`major` = account, `minor` = address within the account).
#[derive(Deserialize, Default, Clone, Copy)]
#[allow(dead_code)] // fields read by parse_confirmed_by_subaddress
struct SubaddrIndex {
    #[serde(default)]
    major: u32,
    #[serde(default)]
    minor: u32,
}

/// Pure core: from a `get_transfers` JSON-RPC response, the set of payment ids whose incoming
/// transfer has at least `min_confirmations`, **paid at least `min_atomic` atomic units**, and a
/// real, non-null payment id. The amount check closes the "any confirmed payment mints a token
/// regardless of how little was paid" hole. Unit-tested.
pub fn parse_confirmed(
    body: &[u8],
    min_confirmations: u64,
    min_atomic: u64,
) -> anyhow::Result<HashSet<String>> {
    let resp: RpcResponse =
        serde_json::from_slice(body).map_err(|e| anyhow::anyhow!("parse get_transfers: {e}"))?;
    let Some(result) = resp.result else {
        return Ok(HashSet::new());
    };
    Ok(result
        .incoming
        .into_iter()
        .filter(|t| {
            t.confirmations >= min_confirmations
                && t.amount >= min_atomic
                && !t.payment_id.is_empty()
                && t.payment_id != NULL_PAYMENT_ID
        })
        .map(|t| t.payment_id)
        .collect())
}

/// Pure core (preferred path): from a `get_transfers` response, the set of `"major/minor"`
/// subaddress indices whose incoming transfer is sufficiently confirmed AND paid at least
/// `min_atomic`. This is the modern, payment-id-free attribution: a checkout allocates a fresh
/// subaddress and gates issuance on that subaddress index appearing here. Same confirmation and
/// underpayment guards as [`parse_confirmed`]; no dependency on a (deprecated) short payment id.
/// The returned key format (`"<major>/<minor>"`) is stable and what a subaddress-based checkout
/// should store as its reference. Unit-tested.
// Reachable API for a subaddress-based checkout flow; exercised by tests today.
#[allow(dead_code)]
pub fn parse_confirmed_by_subaddress(
    body: &[u8],
    min_confirmations: u64,
    min_atomic: u64,
) -> anyhow::Result<HashSet<String>> {
    let resp: RpcResponse =
        serde_json::from_slice(body).map_err(|e| anyhow::anyhow!("parse get_transfers: {e}"))?;
    let Some(result) = resp.result else {
        return Ok(HashSet::new());
    };
    Ok(result
        .incoming
        .into_iter()
        .filter(|t| t.confirmations >= min_confirmations && t.amount >= min_atomic)
        .map(|t| format!("{}/{}", t.subaddr_index.major, t.subaddr_index.minor))
        .collect())
}

/// Refuse a wallet-rpc URL that would send the (unauthenticated) JSON-RPC in plaintext to a
/// non-loopback host. `monero-wallet-rpc` should be bound to loopback (co-located with the
/// Portal) or fronted by TLS; a remote plaintext endpoint is an unauthenticated-RPC exposure.
/// (Digest `--rpc-login` for a genuinely remote wallet is a follow-up — it needs challenge/response
/// auth reqwest doesn't do natively; loopback binding is the real mitigation today.)
pub fn validate_rpc_url(url: &str) -> anyhow::Result<()> {
    // Shared guard (exact-host loopback check — not a `127.` prefix match, which a host like
    // `127.0.0.1.evil.com` would have slipped past). The RPC is unauthenticated, so a plaintext
    // non-loopback endpoint is an exposure: bind the wallet to loopback or front it with TLS.
    nil_core::net::require_https_or_debug_loopback(url)
        .map_err(|e| anyhow::anyhow!("NW_MONERO_RPC: {e}"))
}

/// Watches a self-hosted `monero-wallet-rpc`: a background loop polls `get_transfers` and marks
/// sufficiently-confirmed payments; `is_confirmed` checks the resulting set.
pub struct MoneroRpcWatcher {
    rpc_url: String,
    min_confirmations: u64,
    /// Minimum accepted payment in atomic units (1 XMR = 1e12). A confirmed transfer below this
    /// does NOT confirm the payment id — closes the underpayment hole.
    min_atomic: u64,
    confirmed: Mutex<HashSet<String>>,
    http: reqwest::Client,
}

impl MoneroRpcWatcher {
    pub fn new(rpc_url: String, min_atomic: u64) -> Self {
        Self {
            rpc_url,
            min_confirmations: 10,
            min_atomic,
            confirmed: Mutex::new(HashSet::new()),
            http: reqwest::Client::new(),
        }
    }

    /// Poll the wallet once: fetch incoming transfers and fold the confirmed payment ids into the
    /// set. Returns how many newly-confirmed ids were added.
    pub async fn poll_once(&self) -> anyhow::Result<usize> {
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": "0", "method": "get_transfers", "params": { "in": true }
        });
        let body = self
            .http
            .post(format!("{}/json_rpc", self.rpc_url.trim_end_matches('/')))
            .json(&req)
            .send()
            .await?
            .bytes()
            .await?;
        let confirmed = parse_confirmed(&body, self.min_confirmations, self.min_atomic)?;
        let mut set = self.confirmed.lock().expect("watcher mutex");
        let before = set.len();
        set.extend(confirmed);
        Ok(set.len() - before)
    }

    /// Background poll loop (spawn from `main`). Each failure is logged and retried; a transient
    /// RPC outage never confirms a payment that wasn't there (fail-closed).
    pub async fn poll_loop(self: std::sync::Arc<Self>, interval: Duration) {
        loop {
            match self.poll_once().await {
                Ok(n) if n > 0 => {
                    tracing::info!(newly_confirmed = n, "monero: confirmed new payment(s)")
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("monero poll failed (will retry): {e}"),
            }
            tokio::time::sleep(interval).await;
        }
    }
}

impl PaymentWatcher for MoneroRpcWatcher {
    fn is_confirmed(&self, payment_id: &str) -> bool {
        self.confirmed
            .lock()
            .expect("watcher mutex")
            .contains(payment_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_watcher_tracks_confirmed_payments() {
        let w = MockWatcher::with_paid(["pay-1".to_string()]);
        assert!(w.is_confirmed("pay-1"));
        assert!(!w.is_confirmed("pay-2"));
        w.confirm("pay-2");
        assert!(w.is_confirmed("pay-2"));
    }

    #[test]
    fn confirm_everything_mode_confirms_any_id() {
        // The dev/integration mode for server-minted checkout references (unknowable at startup):
        // every id reads as paid. The front-running guard (is_known_reference) is what still
        // restricts issuance to minted references — that is exercised in billing.rs tests.
        let w = MockWatcher::confirm_everything();
        assert!(w.is_confirmed("any-reference-at-all"));
        assert!(w.is_confirmed(""));
    }

    #[test]
    fn parse_confirmed_requires_confirmations_amount_and_a_real_payment_id() {
        let body = br#"{"id":"0","jsonrpc":"2.0","result":{"in":[
            {"payment_id":"aaaaaaaaaaaaaaaa","confirmations":12,"amount":1000},
            {"payment_id":"bbbbbbbbbbbbbbbb","confirmations":3,"amount":2000},
            {"payment_id":"cccccccccccccccc","confirmations":20,"amount":500},
            {"payment_id":"0000000000000000","confirmations":99,"amount":3000}
        ]}}"#;
        // Require 10 confirmations AND at least 1000 atomic units.
        let confirmed = parse_confirmed(body, 10, 1000).expect("parse");
        assert!(
            confirmed.contains("aaaaaaaaaaaaaaaa"),
            "12 conf, 1000 ≥ 1000 → confirmed"
        );
        assert!(
            !confirmed.contains("bbbbbbbbbbbbbbbb"),
            "3 < 10 confirmations → not yet"
        );
        assert!(
            !confirmed.contains("cccccccccccccccc"),
            "amount 500 < 1000 → underpaid, rejected"
        );
        assert!(
            !confirmed.contains("0000000000000000"),
            "null payment id is ignored"
        );
        assert_eq!(confirmed.len(), 1);
    }

    #[test]
    fn parse_confirmed_by_subaddress_keys_on_minor_index_with_the_same_guards() {
        let body = br#"{"id":"0","jsonrpc":"2.0","result":{"in":[
            {"subaddr_index":{"major":0,"minor":7},"confirmations":12,"amount":1000},
            {"subaddr_index":{"major":0,"minor":8},"confirmations":3,"amount":2000},
            {"subaddr_index":{"major":0,"minor":9},"confirmations":20,"amount":500}
        ]}}"#;
        let confirmed = parse_confirmed_by_subaddress(body, 10, 1000).expect("parse");
        assert!(
            confirmed.contains("0/7"),
            "12 conf, 1000 ≥ 1000 → confirmed"
        );
        assert!(!confirmed.contains("0/8"), "3 < 10 confirmations → not yet");
        assert!(
            !confirmed.contains("0/9"),
            "amount 500 < 1000 → underpaid, rejected"
        );
        assert_eq!(confirmed.len(), 1);
    }

    #[test]
    fn parse_confirmed_handles_an_empty_or_resultless_response() {
        assert!(parse_confirmed(br#"{"result":{}}"#, 10, 0)
            .unwrap()
            .is_empty());
        assert!(
            parse_confirmed(br#"{"error":{"code":-1,"message":"x"}}"#, 10, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn validate_rpc_url_requires_https_with_debug_only_loopback_http() {
        assert_eq!(
            validate_rpc_url("http://127.0.0.1:18082").is_ok(),
            cfg!(debug_assertions)
        );
        assert_eq!(
            validate_rpc_url("http://localhost:18082/json_rpc").is_ok(),
            cfg!(debug_assertions)
        );
        assert!(
            validate_rpc_url("https://wallet.example.internal").is_ok(),
            "https remote ok"
        );
        assert!(
            validate_rpc_url("http://wallet.example.com:18082").is_err(),
            "plaintext remote refused"
        );
        assert!(validate_rpc_url("not-a-url").is_err());
    }
}
