//! NIL VPN Business plane (`nil-portal`).
//!
//! The only plane that knows who you are (for email accounts) — and it is
//! cryptographically and topologically separated from any traffic. It mints anonymous
//! credentials and (later) Privacy Pass tokens; it never sees a packet.
//!
//! Phase 0 implements the no-email anonymous account flow (architecture spec §7.5).

mod account;
mod app;
mod billing;
#[cfg(feature = "card-payments")]
mod cards;
mod mint;
mod monero;
mod ratelimit;
mod state;
mod store;
mod subscription;
mod tokens;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use nil_core::durable::{DurableSet, TimedDurableSet};
use nil_crypto::Issuer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::mint::{mint_router, MintState};
use crate::monero::{MockWatcher, MoneroRpcWatcher, PaymentWatcher};
use crate::state::AppState;
use crate::store::{file::FileStore, memory::InMemoryStore, Store};
use crate::subscription::{subscription_router, SubscriptionState};
use crate::tokens::{token_router, TokenSigner, TokenState};

/// Resolve the minimum accepted Monero payment (atomic units) for a LIVE watcher. Fails closed: an
/// unset/empty minimum would accept ANY confirmed amount — a dust payment would mint a full token
/// (payment bypass) — so it is an error unless `dev_fallback` explicitly opts into accept-any.
fn resolve_min_atomic(raw: Option<String>, dev_fallback: bool) -> anyhow::Result<u64> {
    match raw.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => s
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("NW_MONERO_MIN_ATOMIC must be a u64 of atomic units")),
        _ if dev_fallback => Ok(0),
        _ => anyhow::bail!(
            "NW_MONERO_RPC is set but NW_MONERO_MIN_ATOMIC is not: a live watcher with no minimum \
             accepts ANY confirmed amount (a dust payment would mint a full token). Set \
             NW_MONERO_MIN_ATOMIC to the per-plan price in atomic units (1 XMR = 1_000_000_000_000), \
             or set NW_ALLOW_DEV_FALLBACKS=1 to explicitly accept any amount in dev."
        ),
    }
}

/// (composed payment watcher, optional card rail = (card watcher shared with the composite, the
/// MoR signing secret)). Aliased so the dual-rail wiring below isn't a clippy::type_complexity wall.
#[cfg(feature = "card-payments")]
type WatcherAndCardRail = (Arc<dyn PaymentWatcher>, Option<(Arc<cards::CardWatcher>, Vec<u8>)>);

/// The non-Postgres account-store selection: durable JSON file (`NW_PORTAL_STORE`) or volatile
/// in-memory (dev only). Shared by both `postgres`-feature configurations.
fn file_or_memory_store() -> Result<Arc<dyn Store>> {
    match std::env::var("NW_PORTAL_STORE") {
        Ok(path) => {
            let s = FileStore::open(&path).map_err(|e| anyhow::anyhow!("open account store {path}: {e}"))?;
            tracing::info!(%path, "durable account store loaded");
            Ok(Arc::new(s))
        }
        Err(_) => {
            tracing::warn!("NW_PORTAL_STORE unset — accounts are VOLATILE (dev only; lost on restart)");
            Ok(Arc::new(InMemoryStore::new()))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // Account store selection (ADR-0003), all PII-free:
    //  - clustered Postgres when NW_PORTAL_PG_URL is set and the `postgres` feature is built;
    //  - else durable JSON file when NW_PORTAL_STORE is set;
    //  - else volatile in-memory + a warning (dev only).
    #[cfg(feature = "postgres")]
    let store: Arc<dyn Store> = match std::env::var("NW_PORTAL_PG_URL") {
        Ok(url) => {
            let s = store::postgres::PgStore::connect(&url)
                .await
                .map_err(|e| anyhow::anyhow!("connect Postgres account store: {e}"))?;
            tracing::info!("durable Postgres account store connected (clustered)");
            Arc::new(s)
        }
        Err(_) => file_or_memory_store()?,
    };
    #[cfg(not(feature = "postgres"))]
    let store: Arc<dyn Store> = file_or_memory_store()?;

    // Privacy Pass issuer: reload from NW_TOKEN_SECRET (hex DER) or mint a fresh key. The
    // PUBLIC key is logged so the operator can pin it in the Coordinator (NW_TOKEN_PUBKEY).
    let issuer = Arc::new(load_or_generate_issuer()?);
    if let Ok(pk) = issuer.public_der() {
        tracing::info!(token_pubkey = %hex(&pk), "Privacy Pass issuer ready — pin this as the Coordinator's NW_TOKEN_PUBKEY");
    }
    // Payment watcher: real monero-wallet-rpc if NW_MONERO_RPC is set (a background task polls it
    // for confirmed transfers), else a dev mock.
    let watcher: Arc<dyn PaymentWatcher> = match std::env::var("NW_MONERO_RPC") {
        Ok(url) => {
            // Refuse a plaintext, non-loopback (unauthenticated) wallet-rpc before we ever poll it.
            monero::validate_rpc_url(&url)?;
            // Minimum accepted payment, atomic units (1 XMR = 1e12). A LIVE watcher with no minimum
            // accepts ANY confirmed amount — a dust payment would mint a full token (payment bypass) —
            // so an unset minimum FAILS CLOSED unless the dev fallback is explicitly enabled.
            let raw = std::env::var("NW_MONERO_MIN_ATOMIC").ok();
            let dev_fallback = nil_core::net::env_flag("NW_ALLOW_DEV_FALLBACKS");
            if raw.as_deref().map(str::trim).unwrap_or("").is_empty() && dev_fallback {
                tracing::warn!(
                    "NW_ALLOW_DEV_FALLBACKS=1: live Monero watcher accepting ANY confirmed amount \
                     (NW_MONERO_MIN_ATOMIC unset) — DEV ONLY, never production"
                );
            }
            let min_atomic = resolve_min_atomic(raw, dev_fallback)?;
            tracing::info!("watching self-hosted monero-wallet-rpc for confirmed payments");
            let w = Arc::new(MoneroRpcWatcher::new(url, min_atomic));
            tokio::spawn(w.clone().poll_loop(Duration::from_secs(30)));
            w
        }
        // Dev only: a mock watcher so the integration harness can mint a token without a live
        // monerod. Never reachable in production — a real NW_MONERO_RPC takes precedence above.
        // NW_MOCK_PAID_ALL confirms every id (for checkout references unknowable at startup);
        // NW_MOCK_PAID seeds a fixed set of already-"paid" ids (comma-separated).
        Err(_) if nil_core::net::env_flag("NW_MOCK_PAID_ALL") => {
            // Integration harnesses pay a server-minted checkout reference, which is random and so
            // can't be listed in NW_MOCK_PAID ahead of time. This mock confirms every id — the
            // front-running guard still requires the id to be a minted checkout reference, so the
            // composed flow (checkout → issue) is exercised without a live monerod. Dev only.
            tracing::warn!("NW_MOCK_PAID_ALL set — mock watcher CONFIRMS EVERY payment (dev/integration only)");
            Arc::new(MockWatcher::confirm_everything())
        }
        Err(_) => {
            let paid: Vec<String> = std::env::var("NW_MOCK_PAID")
                .ok()
                .map(|s| s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect())
                .unwrap_or_default();
            if !paid.is_empty() {
                tracing::warn!(count = paid.len(), "NW_MOCK_PAID set — mock payment watcher (dev/integration only)");
            }
            Arc::new(MockWatcher::with_paid(paid))
        }
    };

    // Pending checkout-reference set: a TIMED set so abandoned checkouts are pruned by age (TTL)
    // and it stays bounded. Durable when NW_PENDING_PATH is set, else volatile + a warning (a
    // restart with a volatile set forgets which references were minted, so issuance for an in-flight
    // checkout would fail closed until a new checkout is started).
    let pending = match std::env::var("NW_PENDING_PATH") {
        Ok(path) => {
            let s = TimedDurableSet::open(&path).map_err(|e| anyhow::anyhow!("open pending store {path}: {e}"))?;
            tracing::info!(%path, pending = s.len(), "durable checkout-reference set loaded");
            Arc::new(s)
        }
        Err(_) => {
            tracing::warn!("NW_PENDING_PATH unset — the checkout-reference set is VOLATILE (dev only; a restart drops in-flight checkouts)");
            Arc::new(TimedDurableSet::in_memory())
        }
    };

    // Card (Merchant-of-Record) rail: a signed webhook marks a checkout reference paid/revoked,
    // mirroring the Monero watcher. DUAL-RAIL — runs alongside Monero so a freeze on one rail can't
    // down the service. Enabled by NW_CARD_WEBHOOK_SECRET (the MoR's signing secret); unset ⇒
    // Monero-only. The card watcher only confirms references that `/v1/billing/checkout` minted, and
    // never sees a card/email/name/account (PD-3/PD-4) — see `cards`.
    #[cfg(feature = "card-payments")]
    let (watcher, card_rail): WatcherAndCardRail =
        match std::env::var("NW_CARD_WEBHOOK_SECRET") {
            Ok(secret) if !secret.trim().is_empty() => {
                let revoked = match std::env::var("NW_CARD_REVOKED_PATH") {
                    Ok(p) => Arc::new(
                        DurableSet::open(&p)
                            .map_err(|e| anyhow::anyhow!("open card revoked store {p}: {e}"))?,
                    ),
                    // Fail-closed: a volatile revoked set would let a refunded payment be re-issued
                    // after a restart (the processor retries the confirm; the lost revocation no
                    // longer blocks it). Refuse to enable the card rail without durable revocation.
                    Err(_) => anyhow::bail!(
                        "NW_CARD_REVOKED_PATH must be set when the card-payments rail is enabled \
                         (NW_CARD_WEBHOOK_SECRET) — card revocations MUST survive restarts"
                    ),
                };
                let card = Arc::new(cards::CardWatcher::new(pending.clone(), revoked));
                tracing::info!("card (Merchant-of-Record) webhook rail enabled (dual-rail with Monero)");
                let composite: Arc<dyn PaymentWatcher> = Arc::new(cards::CompositeWatcher::new(vec![
                    watcher,
                    card.clone() as Arc<dyn PaymentWatcher>,
                ]));
                (composite, Some((card, secret.into_bytes())))
            }
            _ => (watcher, None),
        };

    // Clone the (possibly composite) watcher for the subscription plane before it moves into the
    // token state — both planes ask the SAME watcher "has this reference been paid?".
    let watcher_for_sub = watcher.clone();
    // Clone the issuer for the mint plane before it moves into the token state — mint blind-signs
    // with the SAME issuer key as one-shot issuance, just gated on a subscription.
    let issuer_for_mint: Arc<dyn TokenSigner> = issuer.clone();

    // One-token-per-payment set: durable when NW_ISSUED_PATH is set, else volatile + a warning
    // (a restart with a volatile set could re-issue a token for an already-spent payment).
    let token_state = match std::env::var("NW_ISSUED_PATH") {
        Ok(path) => {
            let s = DurableSet::open(&path).map_err(|e| anyhow::anyhow!("open issued store {path}: {e}"))?;
            tracing::info!(%path, issued = s.len(), "durable one-token-per-payment set loaded");
            TokenState::with_issued(issuer, watcher, Arc::new(s), pending)
        }
        Err(_) => {
            tracing::warn!("NW_ISSUED_PATH unset — the one-token-per-payment set is VOLATILE (dev only; a restart can re-issue a paid token)");
            // Volatile issued set, but keep whatever (possibly durable) pending set we built above.
            TokenState::with_issued(issuer, watcher, Arc::new(DurableSet::in_memory()), pending)
        }
    };

    // TTL-prune the pending checkout-reference set in the background so abandoned checkouts don't
    // accumulate (the set would otherwise grow unbounded). NW_CHECKOUT_TTL_SECS (default 1h) must
    // exceed worst-case Monero confirmation latency, since pruning a reference whose payment lands
    // after the TTL denies that checkout. Pruning is FAIL-CLOSED: it can only refuse a stale
    // checkout (issuance returns "unknown reference" 402), never enable a double-issue (that guard
    // is the SEPARATE, never-pruned `issued` set).
    // Floor the TTL at the prune interval: a TTL below it (or a malformed/zero value) would prune
    // references almost as fast as they're minted, denying legitimate in-flight checkouts.
    const CHECKOUT_TTL_FLOOR_SECS: u64 = 300;
    let ttl_secs = match std::env::var("NW_CHECKOUT_TTL_SECS") {
        Ok(s) => match s.parse::<u64>() {
            Ok(v) if v >= CHECKOUT_TTL_FLOOR_SECS => v,
            Ok(v) => {
                tracing::warn!(
                    requested = v, floor = CHECKOUT_TTL_FLOOR_SECS,
                    "NW_CHECKOUT_TTL_SECS below the floor — clamping (a tiny TTL would prune in-flight checkouts)"
                );
                CHECKOUT_TTL_FLOOR_SECS
            }
            Err(_) => {
                tracing::warn!(value = %s, "NW_CHECKOUT_TTL_SECS is not a u64 — using the 3600s default");
                3600
            }
        },
        Err(_) => 3600,
    };
    let pending_for_prune = token_state.pending.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            let cutoff = nil_core::grant::now_unix_secs().saturating_sub(ttl_secs);
            match pending_for_prune.prune_older_than(cutoff) {
                Ok(0) => {}
                Ok(n) => tracing::info!(pruned = n, "pending checkout-reference TTL prune"),
                Err(e) => tracing::warn!("pending-set prune failed (non-fatal): {e}"),
            }
        }
    });

    // Subscription durable sets (ADR-0007), both PII-free (each holds only opaque hashes of a
    // payment reference + account number — no plaintext payment↔account link):
    //  - bindings: references a client subscribed for but hasn't activated yet. TIMED so abandoned
    //    subscriptions age out (pruned by the same task as `pending`). Durable so a payment that
    //    confirms after a restart can still be activated.
    //  - activated: references already used to extend a subscription — one extension per payment,
    //    durable and never pruned (like the one-token-per-payment `issued` set).
    // Couple the two sets' durability: `bindings` + `activated` TOGETHER form the anti-double-extend
    // invariant. A durable binding that outlives a VOLATILE activated set re-opens a paid reference
    // for re-extension after a restart, so refuse that asymmetry at startup rather than fall back to
    // a volatile activated set (mirrors the NW_CARD_REVOKED_PATH bail above). The reverse — durable
    // activated, volatile bindings — is harmless (a lost binding only fails closed), so allow it.
    if std::env::var("NW_SUB_BINDINGS_PATH").is_ok() && std::env::var("NW_SUB_ACTIVATED_PATH").is_err() {
        anyhow::bail!(
            "NW_SUB_ACTIVATED_PATH must be set when NW_SUB_BINDINGS_PATH is — the anti-double-extend \
             guard MUST survive restarts (a durable subscription binding outliving a volatile \
             activated set would re-open an already-paid reference for re-extension after a restart)"
        );
    }
    let sub_bindings = match std::env::var("NW_SUB_BINDINGS_PATH") {
        Ok(path) => {
            let s = TimedDurableSet::open(&path)
                .map_err(|e| anyhow::anyhow!("open subscription bindings store {path}: {e}"))?;
            tracing::info!(%path, bindings = s.len(), "durable subscription-binding set loaded");
            Arc::new(s)
        }
        Err(_) => {
            tracing::warn!("NW_SUB_BINDINGS_PATH unset — subscription bindings are VOLATILE (dev only; a restart drops in-flight subscriptions)");
            Arc::new(TimedDurableSet::in_memory())
        }
    };
    let sub_activated = match std::env::var("NW_SUB_ACTIVATED_PATH") {
        Ok(path) => {
            let s = DurableSet::open(&path)
                .map_err(|e| anyhow::anyhow!("open subscription activated store {path}: {e}"))?;
            tracing::info!(%path, activated = s.len(), "durable subscription-activated set loaded");
            Arc::new(s)
        }
        Err(_) => {
            tracing::warn!("NW_SUB_ACTIVATED_PATH unset — the subscription-activated set is VOLATILE (dev only; a restart can re-extend an already-claimed payment)");
            Arc::new(DurableSet::in_memory())
        }
    };
    // TTL-prune the subscription-binding set on the same schedule/policy as `pending` (abandoned
    // subscriptions age out; fail-closed — pruning can only deny a stale binding, never enable a
    // double-extend, which is the separate, never-pruned `activated` set).
    let bindings_for_prune = sub_bindings.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            let cutoff = nil_core::grant::now_unix_secs().saturating_sub(ttl_secs);
            match bindings_for_prune.prune_older_than(cutoff) {
                Ok(0) => {}
                Ok(n) => tracing::info!(pruned = n, "subscription-binding TTL prune"),
                Err(e) => tracing::warn!("subscription-binding prune failed (non-fatal): {e}"),
            }
        }
    });

    // Per-account mint cap (the abuse/resale bound). Tunable via NW_MINT_RATE_MAX; default is
    // generous for real use (a token per connection, reconnects, multi-hop) but far below resale.
    let mint_rate_max = match std::env::var("NW_MINT_RATE_MAX") {
        Ok(s) => match s.parse::<u32>() {
            Ok(v) if v > 0 => v,
            _ => {
                tracing::warn!(value = %s, "NW_MINT_RATE_MAX is not a positive u32 — using the default");
                mint::DEFAULT_MINT_ACCOUNT_RATE_MAX
            }
        },
        Err(_) => mint::DEFAULT_MINT_ACCOUNT_RATE_MAX,
    };

    // Share ONE account state across the account, subscription, and mint routers so a challenge
    // issued by `/v1/account/challenge` is consumable by `/v1/billing/activate` and `/v1/tokens/mint`
    // (same in-memory challenge set).
    let app_state = AppState::new(store);
    let sub_state =
        SubscriptionState::new(app_state.clone(), watcher_for_sub, sub_bindings, sub_activated);
    let mint_state = MintState::new(app_state.clone(), issuer_for_mint, mint_rate_max);

    #[allow(unused_mut)] // `mut` is only needed when the card-payments feature merges its router.
    let mut app = app::router(app_state)
        .merge(token_router(token_state.clone()))
        .merge(billing::billing_router(token_state))
        .merge(subscription_router(sub_state))
        .merge(mint_router(mint_state));
    #[cfg(feature = "card-payments")]
    if let Some((card, secret)) = card_rail {
        app = app.merge(cards::cards_router(card, secret));
    }
    let app = app.layer(TraceLayer::new_for_http());

    let addr = std::env::var("NW_PORTAL_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "nil-portal listening (Business plane: accounts + Privacy Pass issuer)"); // soul-allow: the Portal's own bind address (operational), not a user-linkable value
    // ConnectInfo so the issuer endpoint can rate-limit by client IP (the IP is used transiently
    // for the limiter only — never stored or tied to an account).
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

/// Load the issuer signing key. Order of preference:
///   1. `NW_TOKEN_SECRET_FILE` — a raw DER key file (or a path a KMS/secrets-mount populates).
///      Preferred: a file doesn't leak through `/proc/<pid>/environ` or process listings the way
///      an env var does (runbook §9 — the issuer key is the most sensitive secret).
///   2. `NW_TOKEN_SECRET` — hex DER (convenient for the Docker harness).
///   3. Generate an ephemeral key (dev) + a warning.
///
/// For an HSM/KMS deployment the signing key never leaves the device: implement
/// [`crate::tokens::TokenSigner`] against the HSM and construct `TokenState` with it instead of
/// an in-memory `Issuer`.
///
/// Rotation (zero downtime): generate a new key, add its public DER to the Coordinator's
/// `NW_TOKEN_PUBKEY` list (it accepts a comma-separated set), switch the Portal to the new key,
/// then drop the old public key once outstanding old-key tokens have expired.
fn load_or_generate_issuer() -> Result<Issuer> {
    if let Ok(path) = std::env::var("NW_TOKEN_SECRET_FILE") {
        let der = std::fs::read(&path).map_err(|e| anyhow::anyhow!("read NW_TOKEN_SECRET_FILE {path}: {e}"))?;
        return Issuer::from_secret_der(&der).map_err(|e| anyhow::anyhow!("NW_TOKEN_SECRET_FILE: {e}"));
    }
    if let Ok(hex_der) = std::env::var("NW_TOKEN_SECRET") {
        tracing::warn!(
            "NW_TOKEN_SECRET (env) in use — the issuer key leaks via /proc/<pid>/environ and process \
             listings; prefer NW_TOKEN_SECRET_FILE (or an HSM/KMS TokenSigner) in production"
        );
        let der = decode_hex(hex_der.trim()).ok_or_else(|| anyhow::anyhow!("NW_TOKEN_SECRET not hex"))?;
        return Issuer::from_secret_der(&der).map_err(|e| anyhow::anyhow!("NW_TOKEN_SECRET: {e}"));
    }
    tracing::warn!(
        "no issuer key configured (NW_TOKEN_SECRET_FILE / NW_TOKEN_SECRET) — generating an \
         EPHEMERAL key; tokens won't survive a restart and the Coordinator must pin the logged pubkey"
    );
    Issuer::generate().map_err(|e| anyhow::anyhow!("issuer keygen: {e}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let h = s.as_bytes();
    if h.len() % 2 != 0 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    h.chunks_exact(2).map(|p| Some((nib(p[0])? << 4) | nib(p[1])?)).collect()
}

#[cfg(test)]
mod tests {
    use super::resolve_min_atomic;

    #[test]
    fn a_set_minimum_parses() {
        assert_eq!(resolve_min_atomic(Some("300000000000".into()), false).unwrap(), 300_000_000_000);
    }

    #[test]
    fn unset_minimum_fails_closed_without_dev_fallback() {
        // The payment-bypass guard: a live watcher with no minimum must refuse to boot.
        assert!(resolve_min_atomic(None, false).is_err(), "unset minimum must fail closed");
        assert!(resolve_min_atomic(Some("   ".into()), false).is_err(), "blank minimum must fail closed");
    }

    #[test]
    fn unset_minimum_allows_zero_only_with_dev_fallback() {
        assert_eq!(resolve_min_atomic(None, true).unwrap(), 0, "dev fallback accepts any amount");
    }

    #[test]
    fn malformed_minimum_is_rejected_even_with_dev_fallback() {
        // A present-but-garbage value is always an error (a typo must never silently mean 0).
        assert!(resolve_min_atomic(Some("nope".into()), true).is_err());
    }
}
