//! Dev/staging-only data-plane diagnostic counters (feature `dev-trace`).
//!
//! PII-FREE BY CONSTRUCTION: logs only this node's ROLE + per-direction packet/byte COUNTS — never
//! an address, port, token, payload, or any user-linkable value (so `no_pii_in_logs` stays green
//! without a `soul-allow`). It exists to localize WHERE traffic dies in the 3-hop onion: compare the
//! counters across entry/middle/exit and the hop whose forwarding stalls is the break.
//!
//! Compiled OUT of production: a `hw-attest` build with `dev-trace` is a `compile_error!` (see
//! `attest.rs`), and prod images build `hw-attest` only. This must never run on a real node.

use std::time::{Duration, Instant};

use crate::config::NodeRole;

/// Rate-limit the summary so a busy datapath doesn't flood stdout — running totals, logged at most
/// this often (and only when something changed since the last emit).
const LOG_EVERY: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Counts {
    from_client_pkts: u64,
    from_client_bytes: u64,
    to_tun_pkts: u64,
    to_tun_bytes: u64,
    tun_reply_pkts: u64,
    tun_reply_bytes: u64,
    to_client_pkts: u64,
    to_client_bytes: u64,
    // Reply datagrams that `dgram_send` REFUSED (the previously-silent `let _ =` drop). Split by
    // cause so a failing run says which bug it is: `oversized` = the datagram exceeded the peer's
    // writable limit (an MTU/headroom problem); the rest = queue-full/other (a congestion/flow-control
    // problem). This is THE counter that distinguishes the two — and it proved the data-plane bug was
    // neither (oversized stayed 0): the cause was an exit-position node lacking open egress.
    to_client_drop_pkts: u64,
    to_client_drop_bytes: u64,
    to_client_oversized_pkts: u64,
}

/// Per-node running data-plane counters. The four directions, for this node's role:
/// - `from_client`  : datagrams decoded off the inbound MASQUE/CONNECT-IP tunnel
/// - `to_tun`       : decapsulated packets handed to the TUN (kernel forwards/egresses them)
/// - `tun_reply`    : packets read back off the TUN (replies returning through the kernel)
/// - `to_client`    : datagrams re-encapsulated back out toward the client
pub struct Diag {
    role: NodeRole,
    c: Counts,
    last: Option<Instant>,
    dirty: bool,
}

impl Diag {
    pub fn new(role: NodeRole) -> Self {
        Self {
            role,
            c: Counts::default(),
            last: None,
            dirty: false,
        }
    }

    pub fn record_from_client(&mut self, pkts: usize, bytes: usize) {
        self.c.from_client_pkts += pkts as u64;
        self.c.from_client_bytes += bytes as u64;
        self.dirty |= pkts > 0;
    }

    pub fn record_to_tun(&mut self, pkts: usize, bytes: usize) {
        self.c.to_tun_pkts += pkts as u64;
        self.c.to_tun_bytes += bytes as u64;
        self.dirty |= pkts > 0;
    }

    pub fn record_tun_reply(&mut self, bytes: usize) {
        self.c.tun_reply_pkts += 1;
        self.c.tun_reply_bytes += bytes as u64;
        self.dirty = true;
    }

    pub fn record_to_client(&mut self, bytes: usize) {
        self.c.to_client_pkts += 1;
        self.c.to_client_bytes += bytes as u64;
        self.dirty = true;
    }

    /// A reply datagram that `dgram_send` refused — the formerly-silent drop. `oversized` is true
    /// when the datagram was larger than the peer's writable datagram limit (vs. a queue/other error).
    pub fn record_to_client_drop(&mut self, bytes: usize, oversized: bool) {
        self.c.to_client_drop_pkts += 1;
        self.c.to_client_drop_bytes += bytes as u64;
        if oversized {
            self.c.to_client_oversized_pkts += 1;
        }
        self.dirty = true;
    }

    /// Emit the running totals — rate-limited, and only when a counter moved since the last emit.
    pub fn tick(&mut self) {
        if !self.dirty {
            return;
        }
        let now = Instant::now();
        if self.last.is_some_and(|t| now.duration_since(t) < LOG_EVERY) {
            return;
        }
        self.last = Some(now);
        self.dirty = false;
        tracing::info!(
            role = ?self.role,
            from_client_pkts = self.c.from_client_pkts,
            from_client_bytes = self.c.from_client_bytes,
            to_tun_pkts = self.c.to_tun_pkts,
            to_tun_bytes = self.c.to_tun_bytes,
            tun_reply_pkts = self.c.tun_reply_pkts,
            tun_reply_bytes = self.c.tun_reply_bytes,
            to_client_pkts = self.c.to_client_pkts,
            to_client_bytes = self.c.to_client_bytes,
            to_client_drop_pkts = self.c.to_client_drop_pkts,
            to_client_drop_bytes = self.c.to_client_drop_bytes,
            to_client_oversized_pkts = self.c.to_client_oversized_pkts,
            "dev-trace: data-plane counters"
        );
    }
}
