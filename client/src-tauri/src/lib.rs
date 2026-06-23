//! NIL VPN client (User plane) — Tauri commands bridging the frontend to the engine
//! and the Business plane. Honest by construction: a VPN is not anonymity, and when no
//! Coordinator is configured the loopback transport (no real tunnel) is used — the UI says so.

mod account;
mod config;
mod engine;
mod killswitch;
mod leakguard;
mod splittunnel;
mod tokens;
mod tokenstore;

use tauri::State;

use account::{AnonymousAccount, Location, PortalClient, RecoverResult};
use config::{ClientConfig, ConfigState};
use engine::{AppEngine, ConnState};
use tokens::TokenClient;
use tokenstore::TokenStore;

// ---- Settings: operator endpoints + toggles (persisted; applied to the datapath env) ----

#[tauri::command]
fn get_config(config: State<'_, ConfigState>) -> ClientConfig {
    config.get()
}

#[tauri::command]
fn set_config(cfg: ClientConfig, config: State<'_, ConfigState>) -> Result<(), String> {
    config.set(cfg).map_err(|e| e.to_string())
}

// ---- Account commands (talk to the live Portal at the configured URL) ----

#[tauri::command]
async fn create_anonymous_account(
    config: State<'_, ConfigState>,
) -> Result<AnonymousAccount, String> {
    PortalClient::with_base_url(config.get().portal_url)
        .create_anonymous()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn create_email_account(_email: String) -> Result<AnonymousAccount, String> {
    // Email accounts (encrypted email at rest) are designed but not built in this preview.
    Err("Email accounts aren't available in this preview yet — create an anonymous account instead.".to_string())
}

#[tauri::command]
async fn recover_account(
    phrase: Vec<String>,
    recovery_code: String,
    config: State<'_, ConfigState>,
) -> Result<RecoverResult, String> {
    PortalClient::with_base_url(config.get().portal_url)
        .recover(phrase, recovery_code)
        .await
        .map_err(|e| e.to_string())
}

// ---- Engine commands ----

#[tauri::command]
async fn connect(
    engine: State<'_, AppEngine>,
    store: State<'_, TokenStore>,
    config: State<'_, ConfigState>,
) -> Result<ConnState, String> {
    // Sync the datapath env to the latest configured endpoints/toggles, then arm leak protection
    // before the tunnel comes up.
    config.reapply_env();
    leakguard::arm().map_err(|e| e.to_string())?;
    // Consume one token (removed from disk before use, so a crash never replays a spent token).
    // None is fine for the loopback/dev path; the engine returns NoTokens if a Coordinator is
    // configured but the store is empty (fail closed — never connect unattested/unpaid).
    let token = store.take_one().map_err(|e| e.to_string())?;
    engine.connect(token).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn disconnect(engine: State<'_, AppEngine>) -> Result<ConnState, String> {
    engine.disconnect().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn status(engine: State<'_, AppEngine>) -> Result<ConnState, String> {
    Ok(engine.state().await)
}

// ---- Token commands (buy = blind→issue→finalize against the Portal; balance = local count) ----

#[tauri::command]
async fn token_balance(store: State<'_, TokenStore>) -> Result<usize, String> {
    store.count().map_err(|e| e.to_string())
}

#[tauri::command]
async fn buy_tokens(
    payment_id: String,
    config: State<'_, ConfigState>,
    store: State<'_, TokenStore>,
) -> Result<usize, String> {
    // One token per confirmed payment (the Portal enforces it). Top up with a new payment id.
    let token = TokenClient::with_base_url(config.get().portal_url)
        .acquire(&payment_id)
        .await
        .map_err(|e| e.to_string())?;
    store.add(&[token]).map_err(|e| e.to_string())?;
    store.count().map_err(|e| e.to_string())
}

// ---- Locations / transport / security toggles ----

#[tauri::command]
async fn list_locations() -> Result<Vec<Location>, String> {
    // Real per-hop path selection is the Coordinator's job; the client asks for "automatic".
    Ok(vec![Location {
        id: "auto".to_string(),
        label: "Automatic — Coordinator-selected path".to_string(),
    }])
}

#[tauri::command]
async fn set_transport_mode(_mode: String) -> Result<(), String> {
    // MASQUE is the default; AmneziaWG/wstunnel cascade selection is driven by the node config.
    Ok(())
}

#[tauri::command]
async fn set_split_tunnel(enabled: bool, apps: Vec<String>) -> Result<(), String> {
    // Documented no-op today — real per-app/per-route enforcement lands with the datapath split
    // tunnel. The UI labels it honestly so it never claims protection it doesn't yet provide.
    splittunnel::configure(enabled, &apps).map_err(|e| e.to_string())
}

#[tauri::command]
fn toggle_kill_switch(enabled: bool, config: State<'_, ConfigState>) -> Result<(), String> {
    // The kill-switch is enforced by the datapath (`NW_KILLSWITCH`, armed atomically by the
    // tunnel) — so the toggle persists into config and takes effect on the next connect. The
    // platform hook stays for future per-OS toggles (e.g. mobile always-on).
    killswitch::set_enabled(enabled).map_err(|e| e.to_string())?;
    let mut cfg = config.get();
    cfg.kill_switch = enabled;
    config.set(cfg).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppEngine::new())
        .setup(|app| {
            use tauri::Manager;
            let dir = app.path().app_local_data_dir()?;
            // The token store lives in the app's local-data dir — only the device holds tokens
            // (they're unlinkable to the account/payment, so this is privacy-safe).
            app.manage(TokenStore::open(dir.join("tokens.json")));
            // Persisted config (operator endpoints + toggles), applied to the datapath env now so
            // a Coordinator/Portal set in Settings is live without any env vars.
            app.manage(ConfigState::new(dir.join("config.json")));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_config,
            set_config,
            create_anonymous_account,
            create_email_account,
            recover_account,
            connect,
            disconnect,
            status,
            list_locations,
            set_transport_mode,
            set_split_tunnel,
            toggle_kill_switch,
            buy_tokens,
            token_balance,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
