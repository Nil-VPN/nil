//! Ephemeral, in-memory rate limiter for abuse control on the issuer endpoint (a token-minting
//! flood is the obvious abuse vector). Fixed-window, keyed by client IP.
//!
//! PII-free: it holds only a transient per-key counter that resets each window and is never
//! logged or persisted — it is not an account, and a restart simply forgets it. Keyed by IP
//! because the issuer has no account identity to key on (and must not gain one).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A fixed-window rate limiter. `check(key)` counts a hit and returns whether it is within the
/// per-window cap.
pub struct RateLimiter {
    max: u32,
    window: Duration,
    buckets: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self { max, window, buckets: Mutex::new(HashMap::new()) }
    }

    /// Count a hit for `key`; `true` if within the cap this window, `false` if the cap is
    /// exceeded. The window resets when it has fully elapsed for that key.
    pub fn check(&self, key: &str) -> bool {
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
        entry.1 += 1;
        entry.1 <= self.max
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
        assert!(!rl.check("1.2.3.4"), "4th hit in the window is over the cap");
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
}
