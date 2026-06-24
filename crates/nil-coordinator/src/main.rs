//! NIL VPN Control plane (`nil-coordinator`).
//!
//! Hands the client a trust-split path and the measurement each hop must attest to, and
//! publishes the pinned measurement set from the reproducible-build transparency log. It is
//! the verifier/policy tier: it learns *that* a valid subscriber connected, never *which*
//! one, and never sees traffic. Token *issuance* lives in the Portal, a separate trust domain
//! (Pillar 4) — this binary never imports it.
//!
//! Phase 2 publishes a single pinned node. Phase 3 adds the Privacy Pass token verifier and
//! operator/jurisdiction-diverse multi-hop path selection.

mod api;
mod config;
mod nullifier;
mod pathsel;
mod ratelimit;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use nil_core::durable::{DurableSet, EpochDurableSet};
use tracing_subscriber::EnvFilter;

/// The non-Postgres nullifier-set selection: epoch-partitioned [`EpochDurableSet`]
/// (`NW_NULLIFIER_DIR`, bounded-by-epoch GC), else the flat file-backed [`DurableSet`]
/// (`NW_NULLIFIER_PATH`, no GC), else volatile in-memory (dev only). Shared by both
/// `postgres`-feature configurations.
fn file_or_volatile_nullifiers(cfg: &Arc<config::CoordConfig>) -> Result<api::CoordState> {
    // Epoch-partitioned store (bounded by epoch). The legacy single file (NW_NULLIFIER_PATH), if
    // also set, is migrated in as the epoch-0 partition so already-spent tokens stay spent.
    if let Some(dir) = &cfg.nullifier_dir {
        let file = dir.join("nullifiers.epoch.log");
        let set = EpochDurableSet::open(&file, cfg.nullifier_path.as_deref())
            .map_err(|e| anyhow::anyhow!("open epoch nullifier store {}: {e}", file.display()))?;
        tracing::info!(path = %file.display(), spent = set.len(), "epoch-partitioned nullifier set loaded");
        return Ok(api::CoordState::with_nullifiers(cfg.clone(), Arc::new(set)));
    }
    match &cfg.nullifier_path {
        Some(path) => {
            let set = DurableSet::open(path)
                .map_err(|e| anyhow::anyhow!("open nullifier store {}: {e}", path.display()))?;
            tracing::info!(path = %path.display(), spent = set.len(), "durable nullifier set loaded");
            Ok(api::CoordState::with_nullifiers(cfg.clone(), Arc::new(set)))
        }
        None => {
            // A volatile nullifier set re-permits a double-spend of every redeemed token after a
            // restart — never acceptable in production. Refuse to boot unless an operator has
            // explicitly opted into dev fallbacks; the friction is intentional (fail closed).
            if !nil_core::net::env_flag("NW_ALLOW_DEV_FALLBACKS") {
                anyhow::bail!(
                    "NW_NULLIFIER_PATH unset (no durable spent-token set): a volatile set would \
                     re-permit double-spend of every redeemed token after a restart. Set \
                     NW_NULLIFIER_PATH (or NW_NULLIFIER_PG_URL with the `postgres` feature), or set \
                     NW_ALLOW_DEV_FALLBACKS=1 to explicitly accept a VOLATILE dev nullifier set."
                );
            }
            tracing::warn!(
                "NW_ALLOW_DEV_FALLBACKS=1: the spent-token nullifier set is VOLATILE (dev only); \
                 a restart will re-permit double-spend of every redeemed token"
            );
            Ok(api::CoordState::new(cfg.clone()))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = Arc::new(config::CoordConfig::from_env()?);
    let addr = cfg.addr;
    tracing::info!(
        %addr,
        nodes = cfg.registry.nodes.len(),
        path_hops = cfg.path_hops,
        redeem = cfg.verifier.is_some(),
        durable_nullifiers = cfg.nullifier_path.is_some() || cfg.nullifier_dir.is_some(),
        epoch_partitioned = cfg.nullifier_dir.is_some(),
        "nil-coordinator listening (redeem + measurements)"
    );

    // The spent-token nullifier set MUST be durable: a restart with a volatile set would
    // re-permit a double-spend of every already-redeemed token. Backends (all identity-free):
    //  - clustered Postgres (cross-instance single-use) when NW_NULLIFIER_PG_URL is set and the
    //    `postgres` feature is built;
    //  - else file-backed when NW_NULLIFIER_PATH is set;
    //  - else volatile in-memory + a loud warning (dev only).
    #[cfg(feature = "postgres")]
    let state = match std::env::var("NW_NULLIFIER_PG_URL") {
        Ok(url) => {
            let pg = nullifier::PgNullifierStore::connect(&url)
                .await
                .map_err(|e| anyhow::anyhow!("connect Postgres nullifier store: {e}"))?;
            tracing::info!("clustered Postgres nullifier set connected (cross-instance single-use)");
            api::CoordState::with_nullifiers(cfg.clone(), Arc::new(pg))
        }
        Err(_) => file_or_volatile_nullifiers(&cfg)?,
    };
    #[cfg(not(feature = "postgres"))]
    let state = file_or_volatile_nullifiers(&cfg)?;

    // Bounded-by-epoch GC: at startup, drop any nullifier partition whose KEY the verifier no longer
    // holds. `retained` = the (key-derived) epochs of the currently-held keys (current + the
    // operator's grace window, as listed in NW_TOKEN_PUBKEY), UNIONED with the reserved LEGACY_EPOCH
    // (migrated legacy nullifiers are never auto-dropped — a still-held legacy key keeps its tokens
    // verifiable, and the fixed legacy remnant is bounded). This is SAFE because a token signed by a
    // retired key no longer verifies — it is rejected at redeem before it can re-enter the set (see
    // the nullifier.rs invariant), and the epoch is derived from the key so it can't be renumbered.
    // It runs right after an operator retires a key from NW_TOKEN_PUBKEY. A failure is non-fatal: the
    // set just stays larger, which is always safe (more retention can never cause a double-spend).
    if let Some(verifier) = cfg.verifier.as_ref() {
        // Honest signal: if multiple issuer keys are configured (a rotation is under way) but the
        // backend can't GC by epoch (the flat single-file / in-memory store), the spent-token set
        // will only GROW — rotating keys will NOT shrink it. Tell the operator rather than let them
        // believe rotation bounds the set.
        if verifier.key_count() > 1 && !state.nullifiers.supports_epoch_gc() {
            tracing::warn!(
                "multiple issuer keys are configured but this nullifier backend does NOT GC by \
                 epoch (flat/in-memory store) — the spent-token set will only grow. Use \
                 NW_NULLIFIER_DIR (or NW_NULLIFIER_PG_URL with the postgres feature) for \
                 bounded-by-epoch GC."
            );
        }
        let mut retained = verifier.epochs();
        retained.insert(nil_crypto::LEGACY_EPOCH);
        match state.nullifiers.drop_epochs(&retained).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(
                dropped = n,
                retained_epochs = ?retained,
                "nullifier GC: dropped retired-epoch partition(s)"
            ),
            Err(e) => tracing::warn!("nullifier GC (drop_epochs) failed (non-fatal, set stays larger): {e}"),
        }
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // ConnectInfo so `/v1/redeem` can rate-limit by client IP (the IP is used transiently for the
    // limiter only — never stored, logged, or tied to an account).
    axum::serve(
        listener,
        api::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
