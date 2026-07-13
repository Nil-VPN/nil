//! Ephemeral, in-memory rate limiter for abuse control on the issuer endpoint (a token-minting
//! flood is the obvious abuse vector). Fixed-window, keyed by client IP.
//!
//! PII-free: it holds only a transient per-key counter that resets each window and is never
//! logged or persisted — a restart simply forgets it. Public endpoints key it by transient source
//! IP; authenticated batch minting also uses the Portal's existing anonymous `H(secret)` account
//! number solely in memory.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// A fixed-window rate limiter. Costs are charged under one bucket lock, so a batch can never be
/// partially admitted or race several one-unit checks past the cap.
pub struct RateLimiter {
    max: u32,
    window: Duration,
    buckets: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Count a hit for `key`; `true` if within the cap this window, `false` if the cap is
    /// exceeded. The window resets when it has fully elapsed for that key.
    pub fn check(&self, key: &str) -> bool {
        self.check_n(key, 1)
    }

    /// Atomically charge `cost` units. A zero-cost operation is refused, and arithmetic saturates
    /// on overflow so wraparound can never reopen an exhausted bucket.
    pub fn check_n(&self, key: &str, cost: u32) -> bool {
        self.charge_n(key, cost).is_some()
    }

    /// Reserve a successful charge that is automatically refunded unless explicitly committed.
    /// Used around fallible external signing/storage so a transient failure does not burn an
    /// authenticated account's allowance. A rejected over-limit charge remains fail-closed.
    pub fn reserve_n(self: &Arc<Self>, key: &str, cost: u32) -> Option<RateLimitReservation> {
        let window_start = self.charge_n(key, cost)?;
        Some(RateLimitReservation {
            limiter: Arc::downgrade(self),
            key: key.to_string(),
            window_start,
            cost,
            committed: false,
        })
    }

    fn charge_n(&self, key: &str, cost: u32) -> Option<Instant> {
        if cost == 0 {
            return None;
        }
        let now = Instant::now();
        // Recover from a poisoned lock instead of panicking (no unwrap/expect in non-test code, and
        // a poisoned rate-limiter must not take down the issue endpoint). Mirrors the coordinator's
        // ratelimit: the bucket map is plain counters, so a poisoned guard's data is still usable.
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Opportunistic GC so a flood of distinct keys can't grow the map without bound.
        if buckets.len() > 4096 {
            buckets.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = buckets.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(cost);
        (entry.1 <= self.max).then_some(entry.0)
    }

    fn refund(&self, key: &str, window_start: Instant, cost: u32) {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let remove = if let Some((start, used)) = buckets.get_mut(key) {
            if *start == window_start {
                *used = used.saturating_sub(cost);
                *used == 0
            } else {
                false
            }
        } else {
            false
        };
        if remove {
            buckets.remove(key);
        }
    }
}

pub struct RateLimitReservation {
    limiter: Weak<RateLimiter>,
    key: String,
    window_start: Instant,
    cost: u32,
    committed: bool,
}

impl RateLimitReservation {
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for RateLimitReservation {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(limiter) = self.limiter.upgrade() {
                limiter.refund(&self.key, self.window_start, self.cost);
            }
        }
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_the_per_key_cap_within_a_window() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        assert!(rl.check("1.2.3.4"));
        assert!(rl.check("1.2.3.4"));
        assert!(rl.check("1.2.3.4"));
        assert!(
            !rl.check("1.2.3.4"),
            "4th hit in the window is over the cap"
        );
        // A different key has its own budget.
        assert!(rl.check("5.6.7.8"));
    }

    #[test]
    fn resets_after_the_window_elapses() {
        let rl = RateLimiter::new(1, Duration::from_millis(0)); // window already elapsed
        assert!(rl.check("k"));
        // With a zero window, every check starts a fresh window → always allowed.
        assert!(rl.check("k"));
    }

    #[test]
    fn batch_cost_is_charged_atomically_and_saturates_fail_closed() {
        let rl = RateLimiter::new(5, Duration::from_secs(60));
        assert!(rl.check_n("k", 3));
        assert!(rl.check_n("k", 2));
        assert!(!rl.check_n("k", 1), "all five units were already consumed");
        assert!(!rl.check_n("other", 6), "an oversized charge is refused");
        assert!(
            !rl.check_n("other", 1),
            "a refused oversized charge still exhausts the bucket fail-closed"
        );
        assert!(!rl.check_n("zero", 0));
    }

    #[test]
    fn reservation_refunds_only_the_same_live_window_unless_committed() {
        let rl = Arc::new(RateLimiter::new(2, Duration::from_secs(60)));
        {
            let _reservation = rl.reserve_n("k", 2).expect("reserved");
        }
        assert!(rl.check_n("k", 2), "drop refunded the reservation");

        let other = Arc::new(RateLimiter::new(2, Duration::from_secs(60)));
        other.reserve_n("k", 2).expect("reserved").commit();
        assert!(!other.check("k"), "committed charge remains consumed");
    }
}
