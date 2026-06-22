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

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = std::sync::Arc::new(config::CoordConfig::from_env()?);
    let addr = cfg.addr;
    tracing::info!(%addr, hop = %cfg.hop.host, "nil-coordinator listening (RequestPath + measurements)");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, api::router(cfg)).await?;
    Ok(())
}
