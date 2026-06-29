//! Shared application state injected into every handler.

use std::sync::Arc;
use std::time::Duration;

use crate::account::auth::ChallengeStore;
use crate::ratelimit::RateLimiter;
use crate::store::Store;

/// Per-IP cap on account creation, and the window it applies over. Account creation writes a
/// record to the store; without a cap a single source could flood the store to exhaust storage.
/// Generous (a human creates very few accounts) but enough to stop an automated flood. The IP is
/// used transiently for the counter only — never stored, logged, or tied to an account.
const CREATE_RATE_MAX: u32 = 10;
const CREATE_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Cloneable handle to the Portal's dependencies. `Arc<dyn Store>` lets us swap the
/// in-memory store for a Postgres one (Phase 1) without touching handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    /// Abuse control on `POST /v1/account` (create), keyed by client IP. Caps storage-exhaustion
    /// flooding. PII-free: a transient per-window counter, never persisted or logged.
    pub limiter: Arc<RateLimiter>,
    /// Single-use, short-TTL account-auth challenges (ADR-0007). In-memory and non-identifying:
    /// throwaway nonces a client signs to prove account ownership before minting.
    pub challenges: Arc<ChallengeStore>,
}

impl AppState {
    /// Build the account-plane state with the default create rate limiter.
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self {
            store,
            limiter: Arc::new(RateLimiter::new(CREATE_RATE_MAX, CREATE_RATE_WINDOW)),
            challenges: Arc::new(ChallengeStore::new()),
        }
    }
}
