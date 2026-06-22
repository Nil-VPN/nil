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

/// Test/dev watcher: a fixed (or mutable) set of confirmed payment ids.
pub struct MockWatcher {
    confirmed: Mutex<HashSet<String>>,
}

impl MockWatcher {
    pub fn with_paid<I: IntoIterator<Item = String>>(ids: I) -> Self {
        Self { confirmed: Mutex::new(ids.into_iter().collect()) }
    }
    /// Mark a payment confirmed (e.g. when the real watcher observes it). Used by tests.
    #[allow(dead_code)]
    pub fn confirm(&self, payment_id: &str) {
        self.confirmed.lock().expect("mock watcher mutex").insert(payment_id.to_string());
    }
}

impl PaymentWatcher for MockWatcher {
    fn is_confirmed(&self, payment_id: &str) -> bool {
        self.confirmed.lock().expect("mock watcher mutex").contains(payment_id)
    }
}

/// Monero's "no payment id" sentinel (short payment ids are zero when absent).
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

/// Refuse a wallet-rpc URL that would send the (unauthenticated) JSON-RPC in plaintext to a
/// non-loopback host. `monero-wallet-rpc` should be bound to loopback (co-located with the
/// Portal) or fronted by TLS; a remote plaintext endpoint is an unauthenticated-RPC exposure.
/// (Digest `--rpc-login` for a genuinely remote wallet is a follow-up — it needs challenge/response
/// auth reqwest doesn't do natively; loopback binding is the real mitigation today.)
pub fn validate_rpc_url(url: &str) -> anyhow::Result<()> {
    let u = url.trim();
    let (scheme, rest) = u
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("NW_MONERO_RPC must be an http(s) URL"))?;
    let host = rest.split(['/', ':']).next().unwrap_or("");
    let is_loopback =
        host == "localhost" || host == "::1" || host.starts_with("127.");
    if scheme.eq_ignore_ascii_case("https") || is_loopback {
        return Ok(());
    }
    anyhow::bail!(
        "refusing plaintext monero-wallet-rpc to non-loopback host {host:?}: bind the wallet to \
         loopback or use https — the RPC is unauthenticated"
    )
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
                Ok(n) if n > 0 => tracing::info!(newly_confirmed = n, "monero: confirmed new payment(s)"),
                Ok(_) => {}
                Err(e) => tracing::warn!("monero poll failed (will retry): {e}"),
            }
            tokio::time::sleep(interval).await;
        }
    }
}

impl PaymentWatcher for MoneroRpcWatcher {
    fn is_confirmed(&self, payment_id: &str) -> bool {
        self.confirmed.lock().expect("watcher mutex").contains(payment_id)
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
    fn parse_confirmed_requires_confirmations_amount_and_a_real_payment_id() {
        let body = br#"{"id":"0","jsonrpc":"2.0","result":{"in":[
            {"payment_id":"aaaaaaaaaaaaaaaa","confirmations":12,"amount":1000},
            {"payment_id":"bbbbbbbbbbbbbbbb","confirmations":3,"amount":2000},
            {"payment_id":"cccccccccccccccc","confirmations":20,"amount":500},
            {"payment_id":"0000000000000000","confirmations":99,"amount":3000}
        ]}}"#;
        // Require 10 confirmations AND at least 1000 atomic units.
        let confirmed = parse_confirmed(body, 10, 1000).expect("parse");
        assert!(confirmed.contains("aaaaaaaaaaaaaaaa"), "12 conf, 1000 ≥ 1000 → confirmed");
        assert!(!confirmed.contains("bbbbbbbbbbbbbbbb"), "3 < 10 confirmations → not yet");
        assert!(!confirmed.contains("cccccccccccccccc"), "amount 500 < 1000 → underpaid, rejected");
        assert!(!confirmed.contains("0000000000000000"), "null payment id is ignored");
        assert_eq!(confirmed.len(), 1);
    }

    #[test]
    fn parse_confirmed_handles_an_empty_or_resultless_response() {
        assert!(parse_confirmed(br#"{"result":{}}"#, 10, 0).unwrap().is_empty());
        assert!(parse_confirmed(br#"{"error":{"code":-1,"message":"x"}}"#, 10, 0).unwrap().is_empty());
    }

    #[test]
    fn validate_rpc_url_allows_loopback_or_https_only() {
        assert!(validate_rpc_url("http://127.0.0.1:18082").is_ok());
        assert!(validate_rpc_url("http://localhost:18082/json_rpc").is_ok());
        assert!(validate_rpc_url("https://wallet.example.internal").is_ok(), "https remote ok");
        assert!(validate_rpc_url("http://wallet.example.com:18082").is_err(), "plaintext remote refused");
        assert!(validate_rpc_url("not-a-url").is_err());
    }
}
