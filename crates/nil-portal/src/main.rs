//! NIL VPN Business plane (`nil-portal`).
//!
//! The only plane that knows who you are (for email accounts) — and it is
//! cryptographically and topologically separated from any traffic. It mints anonymous
//! credentials and (later) Privacy Pass tokens; it never sees a packet.
//!
//! Phase 0 implements the no-email anonymous account flow (architecture spec §7.5).

mod account;
mod app;
mod state;
mod store;

use std::sync::Arc;

use anyhow::Result;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::state::AppState;
use crate::store::{memory::InMemoryStore, Store};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // Phase 0 store is in-memory (volatile). A Postgres-backed `Store` slots in behind
    // the same trait in Phase 1 — see ADR-0003.
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = app::router(AppState { store }).layer(TraceLayer::new_for_http());

    let addr = std::env::var("NW_PORTAL_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "nil-portal listening (Business plane)");
    axum::serve(listener, app).await?;
    Ok(())
}
