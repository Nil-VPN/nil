//! NIL VPN Business plane (`nil-portal`).
//!
//! The only plane that knows who you are (for email accounts) — and it is
//! cryptographically and topologically separated from any traffic. It mints anonymous
//! credentials and (later) Privacy Pass tokens; it never sees a packet.
//!
//! Phase 0 implements the no-email anonymous account flow (architecture spec §7.5).

mod account;
mod app;
mod monero;
mod state;
mod store;
mod tokens;

use std::sync::Arc;

use anyhow::Result;
use nil_crypto::Issuer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::monero::{MockWatcher, MoneroRpcWatcher, PaymentWatcher};
use crate::state::AppState;
use crate::store::{memory::InMemoryStore, Store};
use crate::tokens::{token_router, TokenState};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // Phase 0 store is in-memory (volatile). A Postgres-backed `Store` slots in behind
    // the same trait in Phase 1 — see ADR-0003.
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());

    // Privacy Pass issuer: reload from NW_TOKEN_SECRET (hex DER) or mint a fresh key. The
    // PUBLIC key is logged so the operator can pin it in the Coordinator (NW_TOKEN_PUBKEY).
    let issuer = Arc::new(load_or_generate_issuer()?);
    if let Ok(pk) = issuer.public_der() {
        tracing::info!(token_pubkey = %hex(&pk), "Privacy Pass issuer ready — pin this as the Coordinator's NW_TOKEN_PUBKEY");
    }
    // Payment watcher: real monero-wallet-rpc if NW_MONERO_RPC is set, else a dev mock.
    let watcher: Arc<dyn PaymentWatcher> = match std::env::var("NW_MONERO_RPC") {
        Ok(url) => Arc::new(MoneroRpcWatcher::new(url)),
        Err(_) => Arc::new(MockWatcher::with_paid(std::iter::empty())),
    };

    let app = app::router(AppState { store })
        .merge(token_router(TokenState::new(issuer, watcher)))
        .layer(TraceLayer::new_for_http());

    let addr = std::env::var("NW_PORTAL_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "nil-portal listening (Business plane: accounts + Privacy Pass issuer)");
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_or_generate_issuer() -> Result<Issuer> {
    match std::env::var("NW_TOKEN_SECRET") {
        Ok(hex_der) => {
            let der = decode_hex(hex_der.trim()).ok_or_else(|| anyhow::anyhow!("NW_TOKEN_SECRET not hex"))?;
            Ok(Issuer::from_secret_der(&der).map_err(|e| anyhow::anyhow!("NW_TOKEN_SECRET: {e}"))?)
        }
        Err(_) => Ok(Issuer::generate().map_err(|e| anyhow::anyhow!("issuer keygen: {e}"))?),
    }
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
