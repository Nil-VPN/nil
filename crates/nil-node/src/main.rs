//! NIL VPN Data plane node (`nil-node`).
//!
//! Carries packets and holds no durable state. Runs INSIDE a TEE; presents an RA-TLS
//! attestation report on every handshake; keeps **no disk logs** (ephemeral storage,
//! no access logs on the datapath). Entry sees the client IP not the destination; exit
//! the reverse; middle neither.
//!
//! Phase 0 is a stub: it starts, logs, and idles until Ctrl-C. No tunnel datapath yet
//! (MASQUE/`quiche` lands in Phase 1).

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stdout only — never to disk. The datapath must remain logless.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let role = std::env::var("NW_NODE_ROLE").unwrap_or_else(|_| "exit".to_string());
    tracing::info!(%role, "nil-node starting (Phase 0 stub — data plane, no datapath yet)");

    tokio::signal::ctrl_c().await?;
    tracing::info!("nil-node shutting down");
    Ok(())
}
