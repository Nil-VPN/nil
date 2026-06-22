//! Self-hosted Monero payment watcher (architecture spec §7). Token issuance is gated on a
//! confirmed Monero payment, but payment is decoupled from identity: the only handle is a
//! payment id the buyer chooses — never an account, never traffic. The watcher answers one
//! question: "has a confirmed payment for this id been seen?".

use std::collections::HashSet;
use std::sync::Mutex;

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
    /// Mark a payment confirmed (e.g. when the real watcher observes it). Used by tests and
    /// the future RPC poller.
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

/// Deployment watcher skeleton: polls a self-hosted `monero-wallet-rpc` for incoming, confirmed
/// transfers. Wiring the RPC needs a running monerod + monero-wallet-rpc (out of scope for CI),
/// so this is documented for deployment and conservatively reports "not confirmed" until wired.
pub struct MoneroRpcWatcher {
    pub rpc_url: String,
    pub min_confirmations: u64,
}

impl MoneroRpcWatcher {
    pub fn new(rpc_url: String) -> Self {
        Self { rpc_url, min_confirmations: 10 }
    }
}

impl PaymentWatcher for MoneroRpcWatcher {
    fn is_confirmed(&self, _payment_id: &str) -> bool {
        // TODO(deploy): JSON-RPC `get_transfers {"in":true}` (or `get_payments` by payment_id)
        // against self-hosted monero-wallet-rpc at `self.rpc_url`; require a matching transfer
        // with `confirmations >= self.min_confirmations`. Needs a live wallet RPC + a watch-only
        // wallet keyed to the receiving address. Fail closed (no payment ⇒ no token) until wired.
        tracing::warn!(
            rpc = %self.rpc_url,
            min_confirmations = self.min_confirmations,
            "MoneroRpcWatcher is a deployment skeleton — configure monero-wallet-rpc"
        );
        false
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
}
