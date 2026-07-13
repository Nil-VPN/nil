//! Privacy-preserving subscription token prefetch.
//!
//! A connect action must never make an account-authenticated issuer request. Instead, one
//! background worker coalesces refill hints, waits a random delay, and obtains a bounded batch of
//! tokens that all use the protocol's shared hourly expiry epoch. The Portal sees one batch tied to
//! an anonymous account; later connects spend only already-unlinked bearer credentials.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::{Mutex, MutexGuard, Notify};

use crate::authstore::AuthStore;
use crate::config::ConfigState;
use crate::tokens::TokenClient;
use crate::tokenstore::TokenStore;

/// Small enough to limit bearer stockpiling, large enough to decouple several connects from one
/// issuance transcript. Every v2 token expires within the same coarse one-day policy window.
pub(crate) const REFILL_TARGET: usize = 8;
/// Schedule a refill after a connect once the buffer reaches this threshold.
pub(crate) const REFILL_LOW_WATERMARK: usize = 3;

const HINT_DELAY_MIN_SECS: u64 = 30;
const HINT_DELAY_MAX_SECS: u64 = 5 * 60;
const PERIODIC_DELAY_MIN_SECS: u64 = 3 * 60 * 60;
const PERIODIC_DELAY_MAX_SECS: u64 = 6 * 60 * 60;

/// Process-wide refill coordination. `Notify` coalesces many UI/connect hints into one job; the
/// mutex prevents overlapping issuance requests. `generation` cancels an in-flight refill if the
/// user logs out or switches accounts before its network response returns.
#[derive(Clone)]
pub(crate) struct TokenRefillState {
    wake: Arc<Notify>,
    gate: Arc<Mutex<()>>,
    generation: Arc<AtomicU64>,
}

impl Default for TokenRefillState {
    fn default() -> Self {
        Self {
            wake: Arc::new(Notify::new()),
            gate: Arc::new(Mutex::new(())),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl TokenRefillState {
    /// Ask the background worker to consider a refill. Calls are intentionally coalesced.
    pub(crate) fn request(&self) {
        self.wake.notify_one();
    }

    /// Cancel any in-flight response, then serialize a logout/account replacement with the final
    /// refill commit. The caller keeps this guard through its vault changes, closing the otherwise
    /// possible check-then-add race where a completed refill could repopulate a just-cleared vault.
    pub(crate) async fn begin_account_change(&self) -> MutexGuard<'_, ()> {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.gate.lock().await
    }

    /// Serialize another async credential transaction with logout/account replacement and the
    /// subscription refiller. In particular, one-payment issuance must not begin its pending vault
    /// record after a concurrent logout has already cleared the store and returned.
    pub(crate) async fn begin_credential_operation(&self) -> MutexGuard<'_, ()> {
        self.gate.lock().await
    }

    pub(crate) fn request_if_low(&self, store: &TokenStore) -> Result<(), String> {
        if store.count().map_err(|error| error.to_string())? <= REFILL_LOW_WATERMARK {
            self.request();
        }
        Ok(())
    }
}

/// Run the single app-lifetime refill worker. Network/storage failures are deliberately reduced to
/// a generic fact in logs: URLs, account identifiers, challenges, and token material are never
/// emitted. The next hint or periodic wake retries.
pub(crate) async fn run_worker<R: Runtime>(app: AppHandle<R>) {
    let controller = app.state::<TokenRefillState>().inner().clone();

    loop {
        let periodic = random_duration(PERIODIC_DELAY_MIN_SECS, PERIODIC_DELAY_MAX_SECS);
        let hinted = tokio::select! {
            () = controller.wake.notified() => true,
            () = tokio::time::sleep(periodic) => false,
        };
        if hinted {
            tokio::time::sleep(random_duration(HINT_DELAY_MIN_SECS, HINT_DELAY_MAX_SECS)).await;
        }

        let store = app.state::<TokenStore>().inner().clone();
        let auth = app.state::<AuthStore>().inner().clone();
        let portal_url = app.state::<ConfigState>().get().portal_url;
        match refill_once(&controller, &store, &auth, portal_url).await {
            Ok(added) if added > 0 => {
                tracing::info!(
                    count = added,
                    "prefetched blind-signed connection-token batch"
                );
            }
            Ok(_) => {}
            Err(_) => {
                tracing::warn!("background connection-token prefetch deferred");
            }
        }
    }
}

async fn refill_once(
    controller: &TokenRefillState,
    store: &TokenStore,
    auth: &AuthStore,
    portal_url: String,
) -> Result<usize, String> {
    let _guard = controller.gate.lock().await;
    let generation = controller.generation.load(Ordering::Acquire);
    store
        .prune_expired(now_unix_secs()?)
        .map_err(|error| error.to_string())?;

    let current = store.count().map_err(|error| error.to_string())?;
    let Some(batch_size) = refill_batch_size(current) else {
        return Ok(0);
    };
    let Some(material) = auth.load().map_err(|error| error.to_string())? else {
        return Ok(0);
    };

    let completed = TokenClient::with_base_url(portal_url)
        .mint_batch_into_store(&material, batch_size, store)
        .await
        .map_err(|error| error.to_string())?;

    // A logout/account switch can race the HTTP request. Never commit credentials minted with the
    // superseded account, even though the tokens themselves contain no account identifier.
    if controller.generation.load(Ordering::Acquire) != generation
        || auth.load().map_err(|error| error.to_string())?.as_ref() != Some(&material)
    {
        return Ok(0);
    }
    let added = store
        .commit_mint(&completed.request_id, completed.tokens.clone())
        .map_err(|error| error.to_string())?;
    Ok(added)
}

pub(crate) fn prune_expired(store: &TokenStore) -> Result<usize, String> {
    store
        .prune_expired(now_unix_secs()?)
        .map_err(|error| error.to_string())
}

pub(crate) fn now_unix_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            "system clock is before the Unix epoch; token expiry is unavailable".to_string()
        })
}

fn refill_batch_size(current: usize) -> Option<usize> {
    (current <= REFILL_LOW_WATERMARK)
        .then(|| REFILL_TARGET.saturating_sub(current))
        .filter(|n| *n > 0)
}

fn random_duration(min_secs: u64, max_secs: u64) -> Duration {
    debug_assert!(min_secs <= max_secs);
    let mut bytes = [0_u8; 8];
    if getrandom::getrandom(&mut bytes).is_err() {
        // A failed RNG must never collapse privacy jitter to an immediate request.
        return Duration::from_secs(max_secs);
    }
    Duration::from_secs(jitter_secs_from(
        u64::from_le_bytes(bytes),
        min_secs,
        max_secs,
    ))
}

fn jitter_secs_from(sample: u64, min_secs: u64, max_secs: u64) -> u64 {
    let width = max_secs.saturating_sub(min_secs).saturating_add(1);
    min_secs.saturating_add(sample % width)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refill_only_below_the_low_watermark_and_never_exceeds_target() {
        assert_eq!(refill_batch_size(0), Some(8));
        assert_eq!(refill_batch_size(2), Some(6));
        assert_eq!(refill_batch_size(3), Some(5));
        assert_eq!(refill_batch_size(4), None);
        assert_eq!(refill_batch_size(8), None);
        assert_eq!(refill_batch_size(usize::MAX), None);
    }

    #[test]
    fn jitter_is_inclusive_and_never_immediate() {
        assert_eq!(jitter_secs_from(0, 30, 300), 30);
        assert_eq!(jitter_secs_from(270, 30, 300), 300);
        assert!((30..=300).contains(&jitter_secs_from(u64::MAX, 30, 300)));
    }

    #[tokio::test]
    async fn account_change_invalidates_first_and_waits_for_refill_commit_gate() {
        let controller = TokenRefillState::default();
        let refill_guard = controller.gate.lock().await;
        let changing = controller.clone();
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let _account_change = changing.begin_account_change().await;
            entered_tx.send(()).await.unwrap();
        });

        tokio::task::yield_now().await;
        assert_eq!(controller.generation.load(Ordering::Acquire), 1);
        assert!(
            entered_rx.try_recv().is_err(),
            "account change must wait for the commit gate"
        );
        drop(refill_guard);
        entered_rx.recv().await.expect("account change entered");
        task.await.unwrap();
    }
}
