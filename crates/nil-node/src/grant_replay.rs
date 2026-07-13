//! Process-local, fail-closed single-use enforcement for verified NWG2 grants.
//!
//! A valid grant is still a bearer credential. The node therefore records the anonymous
//! `(Coordinator key ID, grant nonce)` pair until the grant expires and refuses a second use. The
//! cache has a hard capacity: when valid, unexpired entries fill it, new tunnels are rejected
//! rather than silently disabling replay protection.
//!
//! The cache is intentionally memory-only. To prevent a process restart from immediately making
//! every previously observed grant reusable, it also refuses grants issued before this process
//! started. Because NWG2 timestamps have one-second precision, a restart in the same second leaves
//! a sub-second replay window; eliminating that residual requires a durable anonymous redemption
//! store or a node boot identifier signed by the Coordinator.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use nil_core::grant::VerifiedGrant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// The same anonymous grant identifier was already accepted by this process.
    Replayed,
    /// The grant predates this process and may have been accepted before a restart.
    PredatesProcess,
    /// The bounded cache contains only unexpired entries, so protection must fail closed.
    Capacity,
    /// Defensive guard for callers that bypass normal NWG2 expiry verification.
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct ReplayKey {
    key_id: [u8; 32],
    nonce: [u8; 32],
}

/// Bounded cache of anonymous, unexpired NWG2 redemption identifiers.
pub struct GrantReplayCache {
    process_started_at: u64,
    capacity: usize,
    entries: HashMap<ReplayKey, u64>,
    expirations: BinaryHeap<Reverse<(u64, ReplayKey)>>,
}

impl GrantReplayCache {
    pub fn new(process_started_at: u64, capacity: usize) -> Self {
        assert!(capacity > 0, "grant replay cache capacity must be non-zero");
        Self {
            process_started_at,
            capacity,
            entries: HashMap::with_capacity(capacity.min(4096)),
            expirations: BinaryHeap::new(),
        }
    }

    /// Atomically mark a fully verified grant as used.
    ///
    /// Call this before sending a successful CONNECT-IP response. A failure to send the response
    /// must not make the same bearer grant safe to try again from another connection.
    pub fn consume(&mut self, grant: &VerifiedGrant, now: u64) -> Result<(), ReplayError> {
        self.prune(now);

        if now >= grant.expires_at {
            return Err(ReplayError::Expired);
        }
        if grant.issued_at < self.process_started_at {
            return Err(ReplayError::PredatesProcess);
        }

        let key = ReplayKey {
            key_id: grant.key_id,
            nonce: grant.nonce,
        };
        if self.entries.contains_key(&key) {
            return Err(ReplayError::Replayed);
        }
        if self.entries.len() >= self.capacity {
            return Err(ReplayError::Capacity);
        }

        self.entries.insert(key, grant.expires_at);
        self.expirations.push(Reverse((grant.expires_at, key)));
        Ok(())
    }

    fn prune(&mut self, now: u64) {
        while let Some(Reverse((expires_at, key))) = self.expirations.peek().copied() {
            if expires_at > now {
                break;
            }
            self.expirations.pop();
            if self.entries.get(&key) == Some(&expires_at) {
                self.entries.remove(&key);
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nil_core::grant::{GrantAudience, GrantRole, GrantTransport};
    use nil_core::Tee;

    fn verified(key: u8, nonce: u8, issued_at: u64, expires_at: u64) -> VerifiedGrant {
        VerifiedGrant {
            key_id: [key; 32],
            issued_at,
            expires_at,
            nonce: [nonce; 32],
            audience: GrantAudience::new(
                "test",
                "exit-1",
                GrantRole::Exit,
                GrantTransport::Masque,
                Tee::SevSnp,
                [0x44; 48],
                [0x55; 32],
                None,
                None,
            )
            .unwrap(),
        }
    }

    #[test]
    fn a_grant_is_accepted_exactly_once() {
        let mut cache = GrantReplayCache::new(100, 4);
        let grant = verified(1, 2, 100, 200);
        assert_eq!(cache.consume(&grant, 100), Ok(()));
        assert_eq!(cache.consume(&grant, 101), Err(ReplayError::Replayed));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn key_id_is_part_of_the_replay_identity() {
        let mut cache = GrantReplayCache::new(100, 4);
        assert_eq!(cache.consume(&verified(1, 2, 100, 200), 100), Ok(()));
        assert_eq!(cache.consume(&verified(2, 2, 100, 200), 100), Ok(()));
    }

    #[test]
    fn expired_entries_are_pruned_before_capacity_is_checked() {
        let mut cache = GrantReplayCache::new(100, 1);
        assert_eq!(cache.consume(&verified(1, 1, 100, 110), 100), Ok(()));
        assert_eq!(cache.consume(&verified(1, 2, 110, 120), 110), Ok(()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn live_capacity_exhaustion_fails_closed() {
        let mut cache = GrantReplayCache::new(100, 1);
        assert_eq!(cache.consume(&verified(1, 1, 100, 200), 100), Ok(()));
        assert_eq!(
            cache.consume(&verified(1, 2, 100, 200), 100),
            Err(ReplayError::Capacity)
        );
    }

    #[test]
    fn pre_restart_grants_are_refused() {
        let mut cache = GrantReplayCache::new(101, 4);
        assert_eq!(
            cache.consume(&verified(1, 1, 100, 200), 101),
            Err(ReplayError::PredatesProcess)
        );
        assert_eq!(cache.consume(&verified(1, 2, 101, 200), 101), Ok(()));
    }

    #[test]
    fn expired_input_is_rejected_even_if_verification_was_bypassed() {
        let mut cache = GrantReplayCache::new(100, 4);
        assert_eq!(
            cache.consume(&verified(1, 1, 100, 101), 101),
            Err(ReplayError::Expired)
        );
    }
}
