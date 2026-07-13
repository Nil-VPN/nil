//! NIL VPN headless client (`nil-cli`).
//!
//! Brings up a MASQUE/CONNECT-IP tunnel (single hop, PQ-WireGuard, or a multi-hop trust-split
//! onion) to a `nil-node` and routes this host's traffic through it (TUN + fail-closed
//! kill-switch via `nil-datapath`). This is the Linux/Docker test client and a real headless
//! CLI. The transport + tunnel config are built by `nil_datapath::launch` from the environment —
//! the SAME builder the Tauri desktop engine uses, so the two can never drift.

#[cfg(all(not(debug_assertions), feature = "dev-fallbacks"))]
compile_error!(
    "nil-cli: `dev-fallbacks` is development-only and cannot be compiled without debug assertions"
);
#[cfg(all(not(debug_assertions), feature = "synthetic-attest"))]
compile_error!(
    "nil-cli: `synthetic-attest` is development-only and cannot be compiled without debug assertions"
);
#[cfg(all(not(debug_assertions), feature = "dev-trace"))]
compile_error!(
    "nil-cli: `dev-trace` is development-only and cannot be compiled without debug assertions"
);

use anyhow::{Context, Result};
use nil_datapath::{launch, Tunnel};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let (transport, cfg) = launch::from_env().await?;
    tracing::info!("nil-cli connecting…");
    let mut tunnel = Tunnel::up(transport, cfg).await?;
    tracing::info!("nil-cli connected — tunnel up. Ctrl-C to disconnect.");

    tokio::signal::ctrl_c()
        .await
        .context("waiting for ctrl_c")?;
    tracing::info!("disconnecting…");
    tunnel.down().await?;
    Ok(())
}
