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
mod client_ip;
#[cfg(feature = "hsm")]
mod hsm;
mod mint;
mod monero;
mod ratelimit;
mod security;
mod state;
mod store;
mod subscription;
mod tokens;

use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use nil_core::durable::{DurableSet, TimedDurableSet};
use nil_crypto::Issuer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use crate::mint::{mint_router, MintState};
#[cfg(debug_assertions)]
use crate::monero::MockWatcher;
use crate::monero::{MoneroRpcWatcher, PaymentWatcher};
use crate::state::AppState;
use crate::store::{file::FileStore, memory::InMemoryStore, Store};
use crate::subscription::{subscription_router, SubscriptionState};
use crate::tokens::{token_router, TokenSigner, TokenState};

const REPLAY_PRUNE_INTERVAL_SECS: u64 = 300;
#[cfg(any(feature = "hsm", test))]
const MAX_HSM_PIN_BYTES: u64 = 1024;
/// Two prune intervals: one covers scheduler alignment and one is rollout/clock margin.
const LEGACY_ACTIVATION_FENCE_MARGIN_SECS: u64 = 2 * REPLAY_PRUNE_INTERVAL_SECS;

fn legacy_activation_fence_retirement_wait(ttl_secs: u64) -> u64 {
    ttl_secs.saturating_add(LEGACY_ACTIVATION_FENCE_MARGIN_SECS)
}

/// Load a pre-atomic line-set fence as a genuinely read-only in-memory lookup. Unlike
/// [`DurableSet::open`], this neither creates a missing file nor retains an append handle: a typo or
/// missing migration artifact fails startup, and this version cannot accidentally add new entries.
fn load_legacy_fence(path: &str) -> std::io::Result<DurableSet> {
    let file = std::fs::File::open(path)?;
    let fence = DurableSet::in_memory();
    for line in BufReader::new(file).lines() {
        let key = line?;
        let key = key.trim();
        if !key.is_empty() {
            let _ = fence.insert(key)?;
        }
    }
    Ok(fence)
}

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
             NW_MONERO_MIN_ATOMIC to the per-plan price in atomic units (1 XMR = 1_000_000_000_000). \
             A debug-assertion integration build may explicitly accept any amount."
        ),
    }
}

/// Builds without debug assertions must have at least one observer that can establish a real
/// payment. Kept pure so the production posture is testable from a normal test binary.
fn validate_payment_posture(has_real_rail: bool, release_build: bool) -> anyhow::Result<()> {
    if release_build && !has_real_rail {
        anyhow::bail!(
            "Portal builds without debug assertions require a real payment rail: configure \
             NW_MONERO_RPC, or build the \
             card-payments feature and configure NW_CARD_WEBHOOK_SECRET"
        );
    }
    Ok(())
}

/// The issuance-result schema changes are deliberately a stop-the-world migration. Old Portal
/// processes write a separate issued-file claim and cleartext cached result; new processes commit
/// an encrypted request-bound result in the shared account store. Running both generations at once
/// could let each authority sign the same payment independently, so production requires an
/// explicit operator acknowledgement and retains the old issued set as a read-only fence.
fn validate_issuance_cutover(
    issued_path_present: bool,
    operator_acknowledged: bool,
    release_build: bool,
) -> anyhow::Result<()> {
    if release_build && !issued_path_present {
        anyhow::bail!(
            "NW_ISSUED_PATH is required for the one-shot issuance migration; the legacy spent set \
             must remain mounted read-only"
        );
    }
    if release_build && !operator_acknowledged {
        anyhow::bail!(
            "set NW_ISSUANCE_STOP_THE_WORLD_CUTOVER=1 only after every old nil-portal instance is \
             stopped. Mixed old/new Portal versions are NOT issuance-safe: they use independent \
             authorities and can sign the same paid checkout twice"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn open_result_key_file(path: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options.open(path)
}

#[cfg(not(unix))]
fn open_result_key_file(path: &str) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().read(true).open(path)
}

/// Load the independent 32-byte AEAD key used only for persisted replay payloads. It is not the
/// RSA issuer key and must be shared by every Portal replica using the same durable store.
fn read_portal_result_key(path: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut file = open_result_key_file(path)
        .map_err(|e| anyhow::anyhow!("open NW_PORTAL_RESULT_KEY_FILE {path}: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| anyhow::anyhow!("stat NW_PORTAL_RESULT_KEY_FILE {path}: {e}"))?;
    if !metadata.is_file() {
        anyhow::bail!("NW_PORTAL_RESULT_KEY_FILE {path} must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "NW_PORTAL_RESULT_KEY_FILE {path} is group/world-accessible (mode {:o}); use an \
                 owner-only file (chmod 600)",
                mode & 0o7777
            );
        }
    }
    if metadata.len() != 32 {
        anyhow::bail!(
            "NW_PORTAL_RESULT_KEY_FILE {path} must contain exactly 32 raw bytes (found {})",
            metadata.len()
        );
    }
    let mut key = Zeroizing::new([0u8; 32]);
    file.read_exact(key.as_mut())
        .map_err(|e| anyhow::anyhow!("read NW_PORTAL_RESULT_KEY_FILE {path}: {e}"))?;
    let mut extra = Zeroizing::new([0u8; 1]);
    if file
        .read(extra.as_mut())
        .map_err(|e| anyhow::anyhow!("finish reading NW_PORTAL_RESULT_KEY_FILE {path}: {e}"))?
        != 0
    {
        anyhow::bail!("NW_PORTAL_RESULT_KEY_FILE {path} changed while being read");
    }
    Ok(key)
}

fn load_portal_result_key(release_build: bool) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    if let Ok(path) = std::env::var("NW_PORTAL_RESULT_KEY_FILE") {
        return read_portal_result_key(&path);
    }
    if release_build {
        anyhow::bail!(
            "NW_PORTAL_RESULT_KEY_FILE must point to an owner-only file containing exactly 32 raw \
             bytes; all Portal replicas sharing a store must use the same replay-result key"
        );
    }
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(key.as_mut())
        .map_err(|_| anyhow::anyhow!("portal replay-result key entropy unavailable"))?;
    tracing::warn!(
        "NW_PORTAL_RESULT_KEY_FILE unset — using an ephemeral development result key; persisted \
         retries become fail-closed conflicts after restart"
    );
    Ok(key)
}

#[cfg(debug_assertions)]
fn mock_paid_ids_from_env() -> Vec<String> {
    std::env::var("NW_MOCK_PAID")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(debug_assertions)]
fn fallback_payment_watcher() -> Arc<dyn PaymentWatcher> {
    if nil_core::net::dev_env_flag("NW_MOCK_PAID_ALL") {
        tracing::warn!(
            "NW_MOCK_PAID_ALL set — mock watcher CONFIRMS EVERY payment (debug/integration only)"
        );
        return Arc::new(MockWatcher::confirm_everything());
    }
    let paid = mock_paid_ids_from_env();
    if !paid.is_empty() {
        tracing::warn!(
            count = paid.len(),
            "NW_MOCK_PAID set — mock payment watcher (debug/integration only)"
        );
    }
    Arc::new(MockWatcher::with_paid(paid))
}

#[cfg(not(debug_assertions))]
fn fallback_payment_watcher() -> Arc<dyn PaymentWatcher> {
    Arc::new(RejectAllPayments)
}

#[cfg(not(debug_assertions))]
struct RejectAllPayments;

#[cfg(not(debug_assertions))]
impl PaymentWatcher for RejectAllPayments {
    fn is_confirmed(&self, _payment_id: &str) -> bool {
        false
    }
}

fn validate_issuer_secret_posture(
    environment_secret_present: bool,
    release_build: bool,
) -> anyhow::Result<()> {
    if release_build && environment_secret_present {
        anyhow::bail!(
            "Portal builds without debug assertions refuse NW_TOKEN_SECRET in the process \
             environment; production requires the PKCS#11 HSM backend"
        );
    }
    Ok(())
}

/// Release binaries may issue only through the PKCS#11 backend. A software DER key remains useful
/// for debug integration, but accepting it in an optimized public service would retain the
/// network-reachable RSA timing exposure tracked as NIL-018.
fn validate_issuer_backend_posture(
    hsm_module_present: bool,
    software_key_file_present: bool,
    hsm_feature_built: bool,
    release_build: bool,
) -> anyhow::Result<()> {
    if hsm_module_present && software_key_file_present {
        anyhow::bail!(
            "configure exactly one issuer backend: remove NW_TOKEN_SECRET_FILE when NW_TOKEN_HSM_MODULE is set"
        );
    }
    if hsm_module_present && !hsm_feature_built {
        anyhow::bail!(
            "NW_TOKEN_HSM_MODULE is set but nil-portal was built without the `hsm` feature"
        );
    }
    if release_build && (!hsm_feature_built || !hsm_module_present) {
        anyhow::bail!(
            "Portal builds without debug assertions require the PKCS#11 HSM backend; build with `--features hsm` and set NW_TOKEN_HSM_MODULE"
        );
    }
    Ok(())
}

/// (composed payment watcher, optional card rail = (card watcher shared with the composite, the
/// MoR signing secret)). Aliased so the dual-rail wiring below isn't a clippy::type_complexity wall.
#[cfg(feature = "card-payments")]
type WatcherAndCardRail = (
    Arc<dyn PaymentWatcher>,
    Option<(Arc<cards::CardWatcher>, Vec<u8>)>,
);

/// The non-Postgres account-store selection: durable JSON file (`NW_PORTAL_STORE`) containing both
/// accounts and atomic subscription-activation results, or volatile in-memory (dev only). Shared
/// by both `postgres`-feature configurations.
fn file_or_memory_store(result_key: [u8; 32]) -> Result<Arc<dyn Store>> {
    match std::env::var("NW_PORTAL_STORE") {
        Ok(path) => {
            let s = FileStore::open_with_result_key(&path, result_key)
                .map_err(|e| anyhow::anyhow!("open account store {path}: {e}"))?;
            tracing::info!(%path, "durable account store loaded");
            Ok(Arc::new(s))
        }
        Err(_) => {
            if !nil_core::net::dev_env_flag("NW_ALLOW_DEV_FALLBACKS") {
                anyhow::bail!("NW_PORTAL_STORE or NW_PORTAL_PG_URL must be set outside development; refusing a volatile account store");
            }
            tracing::warn!(
                "NW_PORTAL_STORE unset — development fallback uses a volatile account store"
            );
            Ok(Arc::new(InMemoryStore::new()))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // One-shot HSM provisioning: generate the issuer keypair in the device, then exit. An explicit
    // ops step (never auto-provision on a normal start — a fresh key would invalidate every issued
    // token and break the Coordinator pin).
    #[cfg(feature = "hsm")]
    if std::env::var("NW_TOKEN_HSM_PROVISION").is_ok() {
        return hsm::provision_from_env();
    }

    validate_issuance_cutover(
        std::env::var_os("NW_ISSUED_PATH").is_some(),
        std::env::var("NW_ISSUANCE_STOP_THE_WORLD_CUTOVER").as_deref() == Ok("1"),
        !cfg!(debug_assertions),
    )?;
    if std::env::var_os("NW_PORTAL_PG_URL").is_some()
        && std::env::var_os("NW_PORTAL_STORE").is_some()
    {
        anyhow::bail!(
            "NW_PORTAL_PG_URL and NW_PORTAL_STORE are both set; configure exactly one durable \
             account/result authority"
        );
    }
    #[cfg(not(feature = "postgres"))]
    if std::env::var_os("NW_PORTAL_PG_URL").is_some() {
        anyhow::bail!(
            "NW_PORTAL_PG_URL is set but nil-portal was built without the `postgres` feature; \
             rebuild with --features postgres instead of silently selecting another store"
        );
    }
    let result_key = load_portal_result_key(!cfg!(debug_assertions))?;

    // Account/result store selection (ADR-0003), PII-minimized as inventoried in RETAINED_DATA.md:
    //  - clustered Postgres when NW_PORTAL_PG_URL is set and the `postgres` feature is built;
    //  - else durable JSON file when NW_PORTAL_STORE is set. Both durable backends commit an
    //    activation key, entitlement extension, and cached result atomically;
    //  - else volatile in-memory + a warning (dev only).
    #[cfg(feature = "postgres")]
    let store: Arc<dyn Store> = match std::env::var("NW_PORTAL_PG_URL") {
        Ok(url) => {
            let s = store::postgres::PgStore::connect(&url, *result_key)
                .await
                .map_err(|e| anyhow::anyhow!("connect Postgres account store: {e}"))?;
            tracing::info!("durable Postgres account store connected (clustered)");
            Arc::new(s)
        }
        Err(_) => file_or_memory_store(*result_key)?,
    };
    #[cfg(not(feature = "postgres"))]
    let store: Arc<dyn Store> = file_or_memory_store(*result_key)?;
    drop(result_key);

    // Do one cleanup pass before accepting traffic rather than retaining stale encrypted response
    // payloads or completed quota windows until the first five-minute background interval.
    let startup_prune_now = nil_core::grant::now_unix_secs_for_expiry();
    match store.prune_issuance_results(startup_prune_now).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(pruned = n, "expired one-shot results pruned at startup"),
        Err(error) => tracing::warn!("startup issuance-result prune failed: {error}"),
    }
    match store.prune_mint_results(startup_prune_now).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(pruned = n, "expired mint/quota rows pruned at startup"),
        Err(error) => tracing::warn!("startup mint-result prune failed: {error}"),
    }

    // Privacy Pass issuer: use an HSM/KMS-backed or file-backed key in production. Builds with
    // debug assertions may also use NW_TOKEN_SECRET or generate an ephemeral key. The PUBLIC key
    // is logged so the operator can pin it in the Coordinator (NW_TOKEN_PUBKEY).
    let issuer: Arc<dyn TokenSigner> = build_issuer()?;
    if let Ok(pk) = issuer.public_der() {
        tracing::info!(token_pubkey = %hex(&pk), "Privacy Pass issuer ready — pin this as the Coordinator's NW_TOKEN_PUBKEY");
    }
    // Payment watcher: real monero-wallet-rpc if NW_MONERO_RPC is set (a background task polls it
    // for confirmed transfers). Debug-assertion builds may use a mock; other builds receive a
    // reject-all fallback and fail startup unless a real card rail is configured.
    let monero_rpc = std::env::var("NW_MONERO_RPC");
    let has_real_monero = monero_rpc.is_ok();
    let watcher: Arc<dyn PaymentWatcher> = match monero_rpc {
        Ok(url) => {
            // Refuse a plaintext, non-loopback (unauthenticated) wallet-rpc before we ever poll it.
            monero::validate_rpc_url(&url)?;
            // Minimum accepted payment, atomic units (1 XMR = 1e12). A LIVE watcher with no minimum
            // accepts ANY confirmed amount — a dust payment would mint a full token (payment bypass) —
            // so an unset minimum FAILS CLOSED unless the dev fallback is explicitly enabled.
            let raw = std::env::var("NW_MONERO_MIN_ATOMIC").ok();
            let dev_fallback = nil_core::net::dev_env_flag("NW_ALLOW_DEV_FALLBACKS");
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
        // Builds with debug assertions may select a mock watcher. Builds without them compile that
        // selection out entirely and receive a watcher that can never confirm a payment; startup
        // later refuses it unless the card rail is genuinely configured.
        Err(_) => fallback_payment_watcher(),
    };

    // Pending checkout-reference set: a TIMED set so abandoned checkouts are pruned by age (TTL)
    // and it stays bounded. Durable when NW_PENDING_PATH is set, else volatile + a warning (a
    // restart with a volatile set forgets which references were minted, so issuance for an in-flight
    // checkout would fail closed until a new checkout is started).
    let pending = match std::env::var("NW_PENDING_PATH") {
        Ok(path) => {
            let s = TimedDurableSet::open(&path)
                .map_err(|e| anyhow::anyhow!("open pending store {path}: {e}"))?;
            tracing::info!(%path, pending = s.len(), "durable checkout-reference set loaded");
            Arc::new(s)
        }
        Err(_) => {
            if !nil_core::net::dev_env_flag("NW_ALLOW_DEV_FALLBACKS") {
                anyhow::bail!("NW_PENDING_PATH must be set outside development; refusing a volatile checkout replay store");
            }
            tracing::warn!("NW_PENDING_PATH unset — development fallback uses a volatile checkout-reference set");
            Arc::new(TimedDurableSet::in_memory())
        }
    };

    // Card (Merchant-of-Record) rail: a signed webhook marks a checkout reference paid/revoked,
    // mirroring the Monero watcher. DUAL-RAIL — runs alongside Monero so a freeze on one rail can't
    // down the service. Enabled by NW_CARD_WEBHOOK_SECRET (the MoR's signing secret); unset ⇒
    // Monero-only. The card watcher only confirms references that `/v1/billing/checkout` minted, and
    // never sees a card/email/name/account (PD-3/PD-4) — see `cards`.
    #[cfg(feature = "card-payments")]
    let (watcher, card_rail): WatcherAndCardRail = match std::env::var("NW_CARD_WEBHOOK_SECRET") {
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
            tracing::info!(
                "card (Merchant-of-Record) webhook rail enabled (dual-rail with Monero)"
            );
            let composite: Arc<dyn PaymentWatcher> = Arc::new(cards::CompositeWatcher::new(vec![
                watcher,
                card.clone() as Arc<dyn PaymentWatcher>,
            ]));
            (composite, Some((card, secret.into_bytes())))
        }
        _ => (watcher, None),
    };

    #[cfg(feature = "card-payments")]
    let has_real_card = card_rail.is_some();
    #[cfg(not(feature = "card-payments"))]
    let has_real_card = false;
    validate_payment_posture(has_real_monero || has_real_card, !cfg!(debug_assertions))?;

    // Clone the (possibly composite) watcher for the subscription plane before it moves into the
    // token state — both planes ask the SAME watcher "has this reference been paid?".
    let watcher_for_sub = watcher.clone();
    // Clone the issuer for the mint plane before it moves into the token state — mint blind-signs
    // with the SAME issuer key as one-shot issuance, just gated on a subscription.
    let issuer_for_mint: Arc<dyn TokenSigner> = issuer.clone();

    // Pre-idempotency one-token-per-payment set: retained read-only as a migration fence. New
    // request-bound results commit to the shared account Store, atomically and cluster-wide; the
    // legacy file has no cached signature, so its rows remain fail-closed conflicts.
    let checkout_rate_max = match std::env::var("NW_CHECKOUT_RATE_MAX") {
        Ok(value) => match value.parse::<u32>() {
            Ok(value) if value > 0 => value,
            _ => {
                tracing::warn!(
                    value,
                    "NW_CHECKOUT_RATE_MAX is not a positive u32 — using the default"
                );
                billing::DEFAULT_CHECKOUT_RATE_MAX
            }
        },
        Err(_) => billing::DEFAULT_CHECKOUT_RATE_MAX,
    };
    let pending_checkout_max = match std::env::var("NW_PENDING_MAX_ENTRIES") {
        Ok(value) => match value.parse::<usize>() {
            Ok(value) if value > 0 => value,
            _ => {
                tracing::warn!(
                    value,
                    "NW_PENDING_MAX_ENTRIES is not a positive usize — using the default"
                );
                billing::DEFAULT_PENDING_CHECKOUT_MAX
            }
        },
        Err(_) => billing::DEFAULT_PENDING_CHECKOUT_MAX,
    };
    if pending.len() >= pending_checkout_max {
        tracing::warn!(
            pending = pending.len(),
            cap = pending_checkout_max,
            "pending checkout store starts at capacity; checkout remains fail-closed until prune"
        );
    }
    let token_state = match std::env::var("NW_ISSUED_PATH") {
        Ok(path) => {
            let s = load_legacy_fence(&path)
                .map_err(|e| anyhow::anyhow!("open read-only legacy issued fence {path}: {e}"))?;
            tracing::info!(%path, issued = s.len(), read_only = true, "legacy one-token-per-payment fence loaded");
            TokenState::with_issued(issuer, watcher, Arc::new(s), pending, store.clone())
        }
        Err(_) => {
            if !nil_core::net::dev_env_flag("NW_ALLOW_DEV_FALLBACKS") {
                anyhow::bail!("NW_ISSUED_PATH must be set outside development during the idempotent-issuance migration; refusing to discard the read-only legacy fence");
            }
            tracing::warn!(
                "NW_ISSUED_PATH unset — development has no pre-idempotency issuance fence; new results remain atomic in the shared Store"
            );
            TokenState::with_issued(
                issuer,
                watcher,
                Arc::new(DurableSet::in_memory()),
                pending,
                store.clone(),
            )
        }
    }
    .with_checkout_limits(checkout_rate_max, pending_checkout_max);

    // TTL-prune the pending checkout-reference set in the background so abandoned checkouts don't
    // accumulate (the set would otherwise grow unbounded). NW_CHECKOUT_TTL_SECS (default 1h) must
    // exceed worst-case Monero confirmation latency, since pruning a reference whose payment lands
    // after the TTL denies that checkout. Pruning is FAIL-CLOSED: it can only refuse a stale
    // checkout (issuance returns "unknown reference" 402), never enable a double-issue (that guard
    // is the permanent result ledger in the shared Store plus the read-only legacy fence).
    // Floor the TTL at the prune interval: a TTL below it (or a malformed/zero value) would prune
    // references almost as fast as they're minted, denying legitimate in-flight checkouts.
    const CHECKOUT_TTL_FLOOR_SECS: u64 = REPLAY_PRUNE_INTERVAL_SECS;
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
            tokio::time::sleep(Duration::from_secs(REPLAY_PRUNE_INTERVAL_SECS)).await;
            let cutoff = nil_core::grant::now_unix_secs().saturating_sub(ttl_secs);
            match pending_for_prune.prune_older_than(cutoff) {
                Ok(0) => {}
                Ok(n) => tracing::info!(pruned = n, "pending checkout-reference TTL prune"),
                Err(e) => tracing::warn!("pending-set prune failed (non-fatal): {e}"),
            }
        }
    });

    // Subscription migration state (ADR-0007), PII-free (each entry is an opaque hash of a payment
    // reference + account number — no plaintext payment↔account link):
    //  - bindings: references a client subscribed for but hasn't activated yet. TIMED so abandoned
    //    subscriptions age out (pruned by the same task as `pending`). Durable so a payment that
    //    confirms after a restart can still be activated.
    //  - legacy activated fence: read-only hashes written by pre-atomic versions. New activations
    //    commit their claim + entitlement + cached result in the account Store and NEVER append to
    //    this file. During a rolling upgrade, however, discarding the old fence could re-extend a
    //    still-live pre-upgrade binding, so production continues to require it fail-closed.
    //
    // Define T0 as the time the LAST old Portal instance stopped and every replacement was running
    // the atomic Store activation code. A deployment becomes eligible to retire this fence only
    // after it has run continuously through:
    //
    //   max NW_CHECKOUT_TTL_SECS used during rollout + 600 seconds
    //
    // The 600 seconds are two prune intervals: scheduler alignment plus rollout/clock margin. There
    // must also be no binding-prune failures during that window. This release still requires the
    // path; remove it only with a later release that explicitly removes the startup requirement.
    if std::env::var("NW_SUB_BINDINGS_PATH").is_ok()
        && std::env::var("NW_SUB_ACTIVATED_PATH").is_err()
    {
        anyhow::bail!(
            "NW_SUB_ACTIVATED_PATH must be set when NW_SUB_BINDINGS_PATH is during the atomic-activation \
             migration; refusing to discard the read-only legacy fence while a pre-upgrade binding \
             could still be live"
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
            if !nil_core::net::dev_env_flag("NW_ALLOW_DEV_FALLBACKS") {
                anyhow::bail!("NW_SUB_BINDINGS_PATH must be set outside development; refusing a volatile subscription binding store");
            }
            tracing::warn!("NW_SUB_BINDINGS_PATH unset — development fallback uses a volatile subscription binding set");
            Arc::new(TimedDurableSet::in_memory())
        }
    };
    let legacy_fence_retirement_wait_secs = legacy_activation_fence_retirement_wait(ttl_secs);
    let sub_activated = match std::env::var("NW_SUB_ACTIVATED_PATH") {
        Ok(path) => {
            let s = load_legacy_fence(&path).map_err(|e| {
                anyhow::anyhow!("open legacy subscription activation fence {path}: {e}")
            })?;
            tracing::info!(
                %path,
                entries = s.len(),
                read_only = true,
                current_config_retirement_wait_secs = legacy_fence_retirement_wait_secs,
                "legacy subscription activation fence loaded"
            );
            Arc::new(s)
        }
        Err(_) => {
            if !nil_core::net::dev_env_flag("NW_ALLOW_DEV_FALLBACKS") {
                anyhow::bail!(
                    "NW_SUB_ACTIVATED_PATH must be set outside development during the atomic-activation \
                     migration; refusing to start without the read-only pre-upgrade replay fence. \
                     Keep it from T0 (last old instance stopped) for at least \
                     the maximum NW_CHECKOUT_TTL_SECS used during rollout + 600 seconds with no \
                     binding-prune failures"
                );
            }
            tracing::warn!(
                "NW_SUB_ACTIVATED_PATH unset — development has no pre-upgrade activation fence; \
                 new activations remain atomic in the account Store"
            );
            Arc::new(DurableSet::in_memory())
        }
    };
    // TTL-prune the subscription-binding set on the same schedule/policy as `pending` (abandoned
    // subscriptions age out; fail-closed — pruning can only deny a stale binding). Successful prune
    // cycles also advance the legacy-fence retirement window described above.
    let bindings_for_prune = sub_bindings.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(REPLAY_PRUNE_INTERVAL_SECS)).await;
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

    // Completed batch-mint responses are retained only for the bounded v2 token lifetime. The
    // key is a hash of a random request id and the value contains blinded signatures only; pruning
    // removes the short-lived retry material without touching accounts or subscription state.
    let store_for_result_prune = store.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(REPLAY_PRUNE_INTERVAL_SECS)).await;
            let now = nil_core::grant::now_unix_secs_for_expiry();
            match store_for_result_prune.prune_issuance_results(now).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(pruned = n, "expired one-shot issuance responses pruned"),
                Err(error) => tracing::warn!("issuance-result prune failed (non-fatal): {error}"),
            }
            match store_for_result_prune.prune_mint_results(now).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(pruned = n, "expired mint-result replay rows pruned"),
                Err(error) => tracing::warn!("mint-result prune failed (non-fatal): {error}"),
            }
        }
    });

    // Share ONE account state across the account, subscription, and mint routers so a challenge
    // issued by `/v1/account/challenge` is consumable by `/v1/billing/activate` and `/v1/tokens/mint`
    // (same in-memory challenge set).
    let app_state = AppState::new(store);
    let sub_state = SubscriptionState::new(
        app_state.clone(),
        watcher_for_sub,
        sub_bindings,
        sub_activated,
    );
    let mint_state = MintState::new(app_state.clone(), issuer_for_mint, mint_rate_max);

    #[allow(unused_mut)] // `mut` is only needed when the card-payments feature merges its router.
    let mut app = app::router(app_state)
        .merge(token_router(token_state.clone()))
        .merge(billing::billing_router(token_state))
        .merge(subscription_router(sub_state))
        .merge(mint_router(mint_state))
        .merge(security::security_router());
    #[cfg(feature = "card-payments")]
    if let Some((card, secret)) = card_rail {
        app = app.merge(cards::cards_router(card, secret));
    }
    let client_ip_policy = client_ip::ClientIpPolicy::from_env(!cfg!(debug_assertions))?;
    let app = app
        .layer(TraceLayer::new_for_http())
        .layer(axum::Extension(client_ip_policy));

    let addr = std::env::var("NW_PORTAL_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "nil-portal listening (Business plane: accounts + Privacy Pass issuer)"); // soul-allow: the Portal's own bind address (operational), not a user-linkable value
                                                                                                    // ConnectInfo so the issuer endpoint can rate-limit by client IP (the IP is used transiently
                                                                                                    // for the limiter only — never stored or tied to an account).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Load the software issuer key used only by debug/integration builds. Optimized Portal builds
/// never call this path: [`build_issuer`] requires the PKCS#11 backend so the private operation and
/// key stay outside the network-facing process heap. Debug precedence is owner-only DER file,
/// debug-only environment DER, then an explicitly enabled ephemeral fallback.
///
/// Rotation (zero downtime): generate a new key, add its public DER to the Coordinator's
/// `NW_TOKEN_PUBKEY` list (it accepts a comma-separated set), switch the Portal to the new key,
/// then drop the old public key once outstanding old-key tokens have expired.
/// A key-file mode is safe only if no group/other bits are set — the issuer key must be owner-only.
/// Pure so it can be unit-tested without touching the filesystem. (Only consulted on Unix, where the
/// deploy target runs; on non-Unix it is exercised solely by the test.)
#[cfg_attr(not(unix), allow(dead_code))]
fn key_file_mode_is_safe(mode: u32) -> bool {
    mode & 0o077 == 0
}

/// Refuse to load an issuer key from a group/world-accessible file: a readable private key means
/// anyone with local access can mint unlimited free tokens (full payment bypass). Fail closed unless
/// the dev override is set. No-op on non-Unix (Windows perms are ACL-based; not the deploy target).
#[cfg(unix)]
fn ensure_key_file_perms(path: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("stat NW_TOKEN_SECRET_FILE {path}: {e}"))?
        .permissions()
        .mode();
    if !key_file_mode_is_safe(mode) && !nil_core::net::dev_env_flag("NW_ALLOW_DEV_FALLBACKS") {
        anyhow::bail!(
            "NW_TOKEN_SECRET_FILE {path} is group/world-accessible (mode {:o}); the issuer private \
             key must be owner-only (chmod 600) — a readable key means anyone with local access can \
             mint unlimited free tokens. Fix the permissions; only debug-assertion integration \
             builds can override this check.",
            mode & 0o7777
        );
    }
    Ok(())
}
#[cfg(not(unix))]
fn ensure_key_file_perms(_path: &str) -> Result<()> {
    Ok(())
}

#[cfg(any(feature = "hsm", test))]
fn open_hsm_pin_file(path: &str) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    options.open(path)
}

/// Load the PKCS#11 user PIN from a small owner-only regular file. One final LF (the normal secret
/// file convention) is removed; all other line breaks/NULs are rejected so bridge/config mistakes
/// cannot silently select a different PIN. The returned allocation zeroizes on drop.
#[cfg(any(feature = "hsm", test))]
fn read_hsm_pin_file(path: &str, enforce_private_permissions: bool) -> Result<Zeroizing<String>> {
    let file = open_hsm_pin_file(path)
        .map_err(|error| anyhow::anyhow!("open NW_TOKEN_HSM_PIN_FILE {path}: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("stat NW_TOKEN_HSM_PIN_FILE {path}: {error}"))?;
    if !metadata.is_file() {
        anyhow::bail!("NW_TOKEN_HSM_PIN_FILE {path} must be a regular file");
    }
    if metadata.len() == 0 || metadata.len() > MAX_HSM_PIN_BYTES {
        anyhow::bail!("NW_TOKEN_HSM_PIN_FILE {path} must contain 1..={MAX_HSM_PIN_BYTES} bytes");
    }
    #[cfg(unix)]
    if enforce_private_permissions {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "NW_TOKEN_HSM_PIN_FILE {path} is group/world-accessible (mode {:o}); use an owner-only file",
                mode & 0o7777
            );
        }
    }
    let mut pin = Zeroizing::new(String::with_capacity(metadata.len() as usize));
    file.take(MAX_HSM_PIN_BYTES + 1)
        .read_to_string(&mut pin)
        .map_err(|error| anyhow::anyhow!("read NW_TOKEN_HSM_PIN_FILE {path}: {error}"))?;
    if pin.len() as u64 > MAX_HSM_PIN_BYTES {
        anyhow::bail!("NW_TOKEN_HSM_PIN_FILE {path} exceeds {MAX_HSM_PIN_BYTES} bytes");
    }
    if pin.ends_with('\n') {
        pin.pop();
    }
    if pin.is_empty() || pin.chars().any(|ch| matches!(ch, '\0' | '\r' | '\n')) {
        anyhow::bail!("NW_TOKEN_HSM_PIN_FILE {path} contains an invalid PIN encoding");
    }
    Ok(pin)
}

#[cfg(feature = "hsm")]
fn load_hsm_pin(release_build: bool) -> Result<Zeroizing<String>> {
    let file = std::env::var("NW_TOKEN_HSM_PIN_FILE").ok();
    let inline = std::env::var("NW_TOKEN_HSM_PIN").ok().map(Zeroizing::new);
    if file.is_some() && inline.is_some() {
        anyhow::bail!("set only NW_TOKEN_HSM_PIN_FILE; NW_TOKEN_HSM_PIN is debug-only");
    }
    match (file, inline) {
        (Some(path), None) => read_hsm_pin_file(&path, release_build),
        (None, Some(_)) if release_build => anyhow::bail!(
            "Portal builds without debug assertions forbid NW_TOKEN_HSM_PIN in the environment; use NW_TOKEN_HSM_PIN_FILE"
        ),
        (None, Some(pin)) if !pin.is_empty() => Ok(pin),
        (None, Some(_)) => anyhow::bail!("NW_TOKEN_HSM_PIN must not be empty"),
        (None, None) => anyhow::bail!("NW_TOKEN_HSM_PIN_FILE is not set"),
        (Some(_), Some(_)) => unreachable!("handled above"),
    }
}

#[cfg(feature = "hsm")]
fn hsm_slot_from_env(release_build: bool) -> Result<Option<u64>> {
    parse_hsm_slot(
        std::env::var("NW_TOKEN_HSM_SLOT").ok().as_deref(),
        release_build,
    )
}

/// A set-but-malformed slot must never silently choose the first token-bearing slot. Optimized
/// deployments also require an explicit stable slot so host token enumeration order cannot select
/// another issuer key after reboot or hardware maintenance.
#[cfg(any(feature = "hsm", test))]
fn parse_hsm_slot(raw: Option<&str>, required: bool) -> Result<Option<u64>> {
    match raw {
        Some(value)
            if value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
                || (value.len() > 1 && value.starts_with('0')) =>
        {
            anyhow::bail!("NW_TOKEN_HSM_SLOT must be canonical unsigned decimal")
        }
        Some(value) => value
            .parse::<u64>()
            .map(Some)
            .map_err(|_| anyhow::anyhow!("NW_TOKEN_HSM_SLOT must be canonical unsigned decimal")),
        None if required => anyhow::bail!(
            "Portal builds without debug assertions require an explicit NW_TOKEN_HSM_SLOT"
        ),
        None => Ok(None),
    }
}

/// Select the issuer signing backend. Optimized builds require a PKCS#11 module plus a file-backed
/// PIN and cannot fall back to software RSA. Debug builds retain the software issuer for isolated
/// tests. Returned as `Arc<dyn TokenSigner>` so request handling is agnostic to key location.
fn build_issuer() -> Result<Arc<dyn TokenSigner>> {
    let release_build = !cfg!(debug_assertions);
    let hsm_module = std::env::var("NW_TOKEN_HSM_MODULE").ok();
    validate_issuer_secret_posture(std::env::var_os("NW_TOKEN_SECRET").is_some(), release_build)?;
    validate_issuer_backend_posture(
        hsm_module.is_some(),
        std::env::var_os("NW_TOKEN_SECRET_FILE").is_some(),
        cfg!(feature = "hsm"),
        release_build,
    )?;
    #[cfg(feature = "hsm")]
    if let Some(module) = hsm_module {
        let pin = load_hsm_pin(release_build)?;
        let label =
            std::env::var("NW_TOKEN_HSM_KEY_LABEL").unwrap_or_else(|_| "nil-issuer".to_string());
        let slot = hsm_slot_from_env(release_build)?;
        tracing::info!("issuer key: PKCS#11 HSM module {module} (key never leaves the device)");
        return Ok(Arc::new(hsm::Pkcs11Signer::open(
            &module,
            slot,
            pin.as_str(),
            &label,
        )?));
    }
    Ok(Arc::new(load_or_generate_issuer()?))
}

fn load_or_generate_issuer() -> Result<Issuer> {
    if let Ok(path) = std::env::var("NW_TOKEN_SECRET_FILE") {
        ensure_key_file_perms(&path)?;
        let der = std::fs::read(&path)
            .map_err(|e| anyhow::anyhow!("read NW_TOKEN_SECRET_FILE {path}: {e}"))?;
        return Issuer::from_secret_der(&der)
            .map_err(|e| anyhow::anyhow!("NW_TOKEN_SECRET_FILE: {e}"));
    }
    #[cfg(debug_assertions)]
    if let Ok(hex_der) = std::env::var("NW_TOKEN_SECRET") {
        tracing::warn!(
            "NW_TOKEN_SECRET (env) in use — the issuer key leaks via /proc/<pid>/environ and process \
             listings; prefer NW_TOKEN_SECRET_FILE (or an HSM/KMS TokenSigner) in production"
        );
        let der =
            decode_hex(hex_der.trim()).ok_or_else(|| anyhow::anyhow!("NW_TOKEN_SECRET not hex"))?;
        return Issuer::from_secret_der(&der).map_err(|e| anyhow::anyhow!("NW_TOKEN_SECRET: {e}"));
    }
    if !nil_core::net::dev_env_flag("NW_ALLOW_DEV_FALLBACKS") {
        anyhow::bail!(
            "NW_TOKEN_SECRET_FILE or NW_TOKEN_HSM_MODULE must be configured; refusing an ephemeral \
             issuer key (debug-assertion integration builds may opt into that fallback)"
        );
    }
    tracing::warn!("no issuer key configured — development fallback generates an ephemeral key");
    Issuer::generate().map_err(|e| anyhow::anyhow!("issuer keygen: {e}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
#[cfg(debug_assertions)]
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
    h.chunks_exact(2)
        .map(|p| Some((nib(p[0])? << 4) | nib(p[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        legacy_activation_fence_retirement_wait, load_legacy_fence, parse_hsm_slot,
        read_hsm_pin_file, read_portal_result_key, resolve_min_atomic, validate_issuance_cutover,
        validate_issuer_backend_posture, validate_issuer_secret_posture, validate_payment_posture,
        LEGACY_ACTIVATION_FENCE_MARGIN_SECS, MAX_HSM_PIN_BYTES,
    };

    #[test]
    fn production_issuance_cutover_requires_fence_and_stop_the_world_ack() {
        assert!(validate_issuance_cutover(true, true, true).is_ok());
        assert!(validate_issuance_cutover(false, true, true).is_err());
        assert!(validate_issuance_cutover(true, false, true).is_err());
        assert!(
            validate_issuance_cutover(false, false, false).is_ok(),
            "debug/test builds do not require a migration ceremony"
        );
    }

    #[test]
    fn portal_result_key_is_exact_raw_owner_only_material() {
        let path =
            std::env::temp_dir().join(format!("nil-portal-result-key-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, [0x6a; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            *read_portal_result_key(path.to_str().unwrap()).unwrap(),
            [0x6a; 32]
        );
        std::fs::write(&path, [0x6a; 31]).unwrap();
        assert!(read_portal_result_key(path.to_str().unwrap()).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&path, [0x6a; 32]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(read_portal_result_key(path.to_str().unwrap()).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let link = path.with_extension("link");
            let _ = std::fs::remove_file(&link);
            symlink(&path, &link).unwrap();
            assert!(
                read_portal_result_key(link.to_str().unwrap()).is_err(),
                "O_NOFOLLOW must reject a swappable symlink key path"
            );
            let _ = std::fs::remove_file(link);
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_activation_fence_is_loaded_read_only_and_must_exist() {
        let path = std::env::temp_dir().join(format!(
            "nil-portal-legacy-activation-fence-{}",
            std::process::id()
        ));
        let missing = path.with_extension("missing");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&missing);
        std::fs::write(&path, "first\nsecond\nfirst\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        let fence = load_legacy_fence(path.to_str().unwrap()).unwrap();
        assert!(fence.contains("first"));
        assert!(fence.contains("second"));
        assert_eq!(fence.len(), 2);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(load_legacy_fence(missing.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_activation_fence_wait_includes_ttl_and_two_prune_intervals() {
        assert_eq!(
            legacy_activation_fence_retirement_wait(3_600),
            3_600 + LEGACY_ACTIVATION_FENCE_MARGIN_SECS
        );
        assert_eq!(legacy_activation_fence_retirement_wait(u64::MAX), u64::MAX);
    }

    #[test]
    fn a_set_minimum_parses() {
        assert_eq!(
            resolve_min_atomic(Some("300000000000".into()), false).unwrap(),
            300_000_000_000
        );
    }

    #[test]
    fn unset_minimum_fails_closed_without_dev_fallback() {
        // The payment-bypass guard: a live watcher with no minimum must refuse to boot.
        assert!(
            resolve_min_atomic(None, false).is_err(),
            "unset minimum must fail closed"
        );
        assert!(
            resolve_min_atomic(Some("   ".into()), false).is_err(),
            "blank minimum must fail closed"
        );
    }

    #[test]
    fn unset_minimum_allows_zero_only_with_dev_fallback() {
        assert_eq!(
            resolve_min_atomic(None, true).unwrap(),
            0,
            "dev fallback accepts any amount"
        );
    }

    #[test]
    fn malformed_minimum_is_rejected_even_with_dev_fallback() {
        // A present-but-garbage value is always an error (a typo must never silently mean 0).
        assert!(resolve_min_atomic(Some("nope".into()), true).is_err());
    }

    #[test]
    fn issuer_key_file_perms_are_owner_only() {
        use super::key_file_mode_is_safe;
        // Owner-only variants are safe.
        assert!(key_file_mode_is_safe(0o600), "0600 is owner rw only");
        assert!(key_file_mode_is_safe(0o400), "0400 is owner r only");
        assert!(
            key_file_mode_is_safe(0o700),
            "0700 (owner rwx) has no group/other bits"
        );
        // Any group or other bit → unsafe (a readable key = free minting).
        assert!(!key_file_mode_is_safe(0o640), "group-readable is unsafe");
        assert!(!key_file_mode_is_safe(0o604), "other-readable is unsafe");
        assert!(
            !key_file_mode_is_safe(0o644),
            "group+other readable is unsafe"
        );
        assert!(!key_file_mode_is_safe(0o660), "group-writable is unsafe");
    }

    #[test]
    fn release_requires_a_real_payment_rail() {
        assert!(validate_payment_posture(true, true).is_ok());
        assert!(validate_payment_posture(false, true).is_err());
        assert!(
            validate_payment_posture(false, false).is_ok(),
            "debug integration may use its explicitly gated mock watcher"
        );
    }

    #[test]
    fn release_refuses_an_environment_issuer_secret_even_with_other_backends_available() {
        assert!(validate_issuer_secret_posture(true, true).is_err());
        assert!(validate_issuer_secret_posture(false, true).is_ok());
        assert!(validate_issuer_secret_posture(true, false).is_ok());
    }

    #[test]
    fn release_requires_exactly_the_compiled_hsm_backend() {
        assert!(validate_issuer_backend_posture(true, false, true, true).is_ok());
        assert!(validate_issuer_backend_posture(false, false, true, true).is_err());
        assert!(validate_issuer_backend_posture(true, false, false, true).is_err());
        assert!(validate_issuer_backend_posture(true, true, true, true).is_err());
        assert!(validate_issuer_backend_posture(false, true, false, true).is_err());
        assert!(
            validate_issuer_backend_posture(false, true, false, false).is_ok(),
            "debug integration retains its owner-only software-key fixture"
        );
    }

    #[test]
    fn hsm_slot_is_explicit_and_canonical_in_release() {
        assert_eq!(parse_hsm_slot(Some("0"), true).unwrap(), Some(0));
        assert_eq!(parse_hsm_slot(Some("42"), true).unwrap(), Some(42));
        assert!(parse_hsm_slot(None, true).is_err());
        assert_eq!(parse_hsm_slot(None, false).unwrap(), None);
        for malformed in ["", " 7", "7 ", "+7", "-1", "07", "7x"] {
            assert!(
                parse_hsm_slot(Some(malformed), true).is_err(),
                "malformed slot {malformed:?} must never select the first token"
            );
        }
    }

    #[test]
    fn hsm_pin_file_is_private_bounded_and_canonical() {
        let path = std::env::temp_dir().join(format!("nil-portal-hsm-pin-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"123456\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            read_hsm_pin_file(path.to_str().unwrap(), true)
                .unwrap()
                .as_str(),
            "123456"
        );

        std::fs::write(&path, b"12\n34").unwrap();
        assert!(read_hsm_pin_file(path.to_str().unwrap(), true).is_err());
        std::fs::write(&path, vec![b'7'; MAX_HSM_PIN_BYTES as usize + 1]).unwrap();
        assert!(read_hsm_pin_file(path.to_str().unwrap(), true).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            std::fs::write(&path, b"123456").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(read_hsm_pin_file(path.to_str().unwrap(), true).is_err());
            assert!(read_hsm_pin_file(path.to_str().unwrap(), false).is_ok());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let link = path.with_extension("link");
            let _ = std::fs::remove_file(&link);
            symlink(&path, &link).unwrap();
            assert!(read_hsm_pin_file(link.to_str().unwrap(), true).is_err());
            let _ = std::fs::remove_file(link);
        }
        let _ = std::fs::remove_file(path);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_ignores_mock_paid_id_environment() {
        std::env::set_var("NW_MOCK_PAID", "pretend-paid");
        assert!(!super::fallback_payment_watcher().is_confirmed("pretend-paid"));
        std::env::remove_var("NW_MOCK_PAID");
    }
}
