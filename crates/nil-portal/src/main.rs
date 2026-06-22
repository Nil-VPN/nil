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
use nil_core::durable::DurableSet;
use nil_crypto::Issuer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::monero::{MockWatcher, MoneroRpcWatcher, PaymentWatcher};
use crate::state::AppState;
use crate::store::{file::FileStore, memory::InMemoryStore, Store};
use crate::tokens::{token_router, TokenState};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // Account store: durable (JSON file) when NW_PORTAL_STORE is set; otherwise volatile
    // in-memory + a warning (dev only). Both keep only PII-free records (ADR-0003).
    let store: Arc<dyn Store> = match std::env::var("NW_PORTAL_STORE") {
        Ok(path) => {
            let s = FileStore::open(&path).map_err(|e| anyhow::anyhow!("open account store {path}: {e}"))?;
            tracing::info!(%path, "durable account store loaded");
            Arc::new(s)
        }
        Err(_) => {
            tracing::warn!("NW_PORTAL_STORE unset — accounts are VOLATILE (dev only; lost on restart)");
            Arc::new(InMemoryStore::new())
        }
    };

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

    // One-token-per-payment set: durable when NW_ISSUED_PATH is set, else volatile + a warning
    // (a restart with a volatile set could re-issue a token for an already-spent payment).
    let token_state = match std::env::var("NW_ISSUED_PATH") {
        Ok(path) => {
            let s = DurableSet::open(&path).map_err(|e| anyhow::anyhow!("open issued store {path}: {e}"))?;
            tracing::info!(%path, issued = s.len(), "durable one-token-per-payment set loaded");
            TokenState::with_issued(issuer, watcher, Arc::new(s))
        }
        Err(_) => {
            tracing::warn!("NW_ISSUED_PATH unset — the one-token-per-payment set is VOLATILE (dev only; a restart can re-issue a paid token)");
            TokenState::new(issuer, watcher)
        }
    };

    let app = app::router(AppState { store })
        .merge(token_router(token_state))
        .layer(TraceLayer::new_for_http());

    let addr = std::env::var("NW_PORTAL_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "nil-portal listening (Business plane: accounts + Privacy Pass issuer)");
    axum::serve(listener, app).await?;
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
