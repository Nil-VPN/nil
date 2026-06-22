//! NIL VPN Control plane (`nil-coordinator`).
//!
//! Verifies anonymous Privacy Pass tokens, selects trust-split paths across legally
//! independent operators, and issues short-lived, identity-free per-hop grants. It
//! learns *that* a valid subscriber connected, never *which* one.
//!
//! Phase 0 is a stub: it starts, logs, and idles until Ctrl-C. No networking yet.

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let addr = std::env::var("NW_COORDINATOR_ADDR").unwrap_or_else(|_| "127.0.0.1:9090".to_string());
    tracing::info!(%addr, "nil-coordinator starting (Phase 0 stub — control plane, no RPC yet)");

    tokio::signal::ctrl_c().await?;
    tracing::info!("nil-coordinator shutting down");
    Ok(())
}
