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
mod pathsel;

use std::sync::Arc;

use anyhow::Result;
use nil_core::durable::DurableSet;
use tracing_subscriber::EnvFilter;

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
        durable_nullifiers = cfg.nullifier_path.is_some(),
        "nil-coordinator listening (redeem + path + measurements)"
    );

    // The spent-token nullifier set MUST be durable: a restart with a volatile set would
    // re-permit a double-spend of every already-redeemed token. File-backed when
    // NW_NULLIFIER_PATH is set; otherwise volatile + a loud warning (dev only).
    let state = match &cfg.nullifier_path {
        Some(path) => {
            let set = DurableSet::open(path)
                .map_err(|e| anyhow::anyhow!("open nullifier store {}: {e}", path.display()))?;
            tracing::info!(path = %path.display(), spent = set.len(), "durable nullifier set loaded");
            api::CoordState::with_nullifiers(cfg.clone(), Arc::new(set))
        }
        None => {
            tracing::warn!(
                "NW_NULLIFIER_PATH unset — the spent-token nullifier set is VOLATILE (dev only); \
                 a restart will re-permit double-spend of every redeemed token"
            );
            api::CoordState::new(cfg.clone())
        }
    };

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, api::router(state)).await?;
    Ok(())
}
