//! NIL VPN client (User plane) — Tauri commands bridging the frontend to the engine
//! and the Business plane. Honest by construction: a VPN is not anonymity, and Phase 0
//! uses the loopback transport (no real tunnel) — the UI says so.

mod account;
mod engine;
mod killswitch;
mod leakguard;
mod splittunnel;
mod tokens;
mod tokenstore;

use tauri::State;

use account::{AnonymousAccount, Location, PortalClient, RecoverResult};
use engine::{AppEngine, ConnState};
use tokens::TokenClient;
use tokenstore::TokenStore;

// ---- Account commands (talk to the live Portal; errors surface in the UI) ----

#[tauri::command]
async fn create_anonymous_account(
    portal: State<'_, PortalClient>,
) -> Result<AnonymousAccount, String> {
    portal.create_anonymous().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn create_email_account(_email: String) -> Result<AnonymousAccount, String> {
    // Email accounts (encrypted email at rest) are designed but not built in Phase 0.
    Err("Email accounts aren't available in this preview yet — create an anonymous account instead.".to_string())
}

#[tauri::command]
async fn recover_account(
    phrase: Vec<String>,
    recovery_code: String,
    portal: State<'_, PortalClient>,
) -> Result<RecoverResult, String> {
    portal
        .recover(phrase, recovery_code)
        .await
        .map_err(|e| e.to_string())
}

// ---- Engine commands (drive the loopback state machine) ----

#[tauri::command]
async fn connect(
    engine: State<'_, AppEngine>,
    store: State<'_, TokenStore>,
) -> Result<ConnState, String> {
    // Arm leak protection before the tunnel comes up.
    leakguard::arm().map_err(|e| e.to_string())?;
    // Consume one token (removed from disk before use, so a crash never replays a spent token).
    // None is fine for the loopback/dev path; the engine returns NoTokens if a Coordinator is
    // configured but the store is empty (fail closed — never connect unattested/unpaid).
    let token = store.take_one().map_err(|e| e.to_string())?;
    engine.connect(token).await.map_err(|e| e.to_string())
}

// ---- Token commands (buy = blind→issue→finalize against the Portal; balance = local count) ----

#[tauri::command]
async fn token_balance(store: State<'_, TokenStore>) -> Result<usize, String> {
    store.count().map_err(|e| e.to_string())
}

#[tauri::command]
async fn buy_tokens(
    payment_id: String,
    tokens: State<'_, TokenClient>,
    store: State<'_, TokenStore>,
) -> Result<usize, String> {
    // One token per confirmed payment (the Portal enforces it). Top up with a new payment id.
    let token = tokens.acquire(&payment_id).await.map_err(|e| e.to_string())?;
    store.add(&[token]).map_err(|e| e.to_string())?;
    store.count().map_err(|e| e.to_string())
}

#[tauri::command]
async fn disconnect(engine: State<'_, AppEngine>) -> Result<ConnState, String> {
    engine.disconnect().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn status(engine: State<'_, AppEngine>) -> Result<ConnState, String> {
    Ok(engine.state().await)
}

// ---- Stubs (mocked data / no-ops in Phase 0) ----

#[tauri::command]
async fn list_locations() -> Result<Vec<Location>, String> {
    Ok(vec![Location {
        id: "auto".to_string(),
        label: "Automatic (mocked — loopback)".to_string(),
    }])
}

#[tauri::command]
async fn set_transport_mode(_mode: String) -> Result<(), String> {
    // MASQUE/cascade selection arrives in Phase 1/4. Phase 0 always uses loopback.
    Ok(())
}

#[tauri::command]
async fn set_split_tunnel(enabled: bool, apps: Vec<String>) -> Result<(), String> {
    splittunnel::configure(enabled, &apps).map_err(|e| e.to_string())
}

#[tauri::command]
async fn toggle_kill_switch(enabled: bool) -> Result<(), String> {
    killswitch::set_enabled(enabled).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppEngine::new())
        .manage(PortalClient::from_env())
        .manage(TokenClient::from_env())
        .setup(|app| {
            // The token store lives in the app's local-data dir — only the device holds tokens
            // (they're unlinkable to the account/payment, so this is privacy-safe).
            use tauri::Manager;
            let dir = app.path().app_local_data_dir()?;
            app.manage(TokenStore::open(dir.join("tokens.json")));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
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
