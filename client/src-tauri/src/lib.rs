//! NIL VPN client (User plane) — Tauri commands bridging the frontend to the engine
//! and the Business plane. Honest by construction: a VPN is not anonymity. With a Coordinator
//! configured, Connect brings up the real attested MASQUE datapath — directly via the in-process
//! engine on desktop, or via the native `VpnService`/`PacketTunnel` plugin on mobile (the app
//! process redeems the token and passes only a node endpoint + measurement + grant to it). With no
//! Coordinator configured, the in-memory loopback transport (no real tunnel) is used — the UI says so.

// `pub` so the headless e2e harness (src/bin/nil-client-e2e.rs) can drive the EXACT same
// account → token → engine path the Tauri commands use (no GUI), closing the "test the engine,
// not just nil-cli" gap.
pub mod account;
pub mod authstore;
pub mod config;
pub mod engine;
mod killswitch;
mod leakguard;
// The network-extension connect path (redeem → attested node endpoint + grant for the native
// datapath). Built where the OS datapath runs in a separate process: Android/iOS, and macOS behind
// the `macos-system-extension` feature (the NEPacketTunnelProvider system extension).
#[cfg(any(
    target_os = "android",
    target_os = "ios",
    feature = "macos-system-extension"
))]
pub mod extension;
mod splittunnel;
pub mod tokens;
pub mod tokenstore;

use tauri::State;

use account::{AnonymousAccount, Location, PortalClient, RecoverResult};
use authstore::{AccountAuthMaterial, AuthStore};
use config::{ClientConfig, ConfigState};
use engine::{AppEngine, ConnState};
use nil_proto::account::AccountStatusResponse;
use tokens::TokenClient;
use tokenstore::TokenStore;

/// Derive the cacheable auth material (account number + Ed25519 auth seed) from a recovery phrase,
/// so the client can mint tokens on demand while subscribed WITHOUT re-entering the phrase
/// (ADR-0007). We cache the derived seed, never the phrase itself. Used on create + recover ("login").
/// `pub` so the headless e2e harness (`bin/nil-client-e2e.rs`) derives auth material the SAME way.
pub fn derive_auth_material(phrase: &[String]) -> Result<AccountAuthMaterial, String> {
    let parsed = nil_crypto::account::Phrase::parse(phrase).map_err(|e| e.to_string())?;
    let account_number =
        nil_crypto::account::account_number_from_phrase(&parsed).map_err(|e| e.to_string())?;
    let keypair = nil_crypto::account::AuthKeypair::from_phrase(&parsed).map_err(|e| e.to_string())?;
    let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
    Ok(AccountAuthMaterial {
        account_number: hex(account_number.as_bytes()),
        auth_seed: hex(&keypair.to_seed_bytes()),
    })
}

/// Serializes tests that read or mutate the shared `NW_*` process env — the engine connect-path
/// tests (which read `NW_COORDINATOR_URL`) vs. the config `apply_env` tests (which set it).
/// `std::env` is process-global, so without this they race when the test harness runs them in
/// parallel (a config test setting `NW_COORDINATOR_URL` makes a concurrent loopback `connect`
/// take the real-path branch and fail `NoTokens`). A `tokio::sync::Mutex` because the engine tests
/// hold the guard across `connect().await` (a `std` guard held across await trips clippy and risks
/// deadlock); a `OnceLock` because `tokio::sync::Mutex::new` isn't `const`. Test-only.
#[cfg(test)]
pub(crate) fn env_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

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
    auth: State<'_, AuthStore>,
) -> Result<AnonymousAccount, String> {
    let account = PortalClient::with_base_url(config.get().portal_url)
        .create_anonymous()
        .await
        .map_err(|e| e.to_string())?;
    // Cache the derived auth key (never the phrase) so this device can mint on demand while
    // subscribed — this is the "login". The phrase is still shown to the user once, by the UI.
    let material = derive_auth_material(&account.recovery_phrase)?;
    auth.save(&material).map_err(|e| e.to_string())?;
    Ok(account)
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
    auth: State<'_, AuthStore>,
) -> Result<RecoverResult, String> {
    let result = PortalClient::with_base_url(config.get().portal_url)
        .recover(phrase.clone(), recovery_code)
        .await
        .map_err(|e| e.to_string())?;
    // Recovery is "log in on this device": cache the derived auth key so re-login can mint on demand
    // and reconnect without re-entering the phrase (the whole point of the subscription model).
    let material = derive_auth_material(&phrase)?;
    auth.save(&material).map_err(|e| e.to_string())?;
    Ok(result)
}

// ---- Subscription commands (ADR-0007: subscribe → pay → activate; mint-on-demand at connect) ----

/// Begin (or renew) a subscription: returns the payment reference to pay (e.g. as the Monero
/// payment id). Poll [`activate`] with this reference once the payment confirms.
#[tauri::command]
async fn subscribe(
    config: State<'_, ConfigState>,
    auth: State<'_, AuthStore>,
) -> Result<String, String> {
    let material = auth
        .load()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no account on this device — create or recover an account first".to_string())?;
    let checkout = PortalClient::with_base_url(config.get().portal_url)
        .subscribe(&material)
        .await
        .map_err(|e| e.to_string())?;
    Ok(checkout.payment_reference)
}

/// Claim a confirmed payment to activate/extend the subscription. Returns the new status; surfaces a
/// "payment not confirmed yet" error (so the UI polls at a wide interval) until the payment lands.
#[tauri::command]
async fn activate_subscription(
    payment_reference: String,
    config: State<'_, ConfigState>,
    auth: State<'_, AuthStore>,
) -> Result<AccountStatusResponse, String> {
    if payment_reference.len() > MAX_PAYMENT_ID {
        return Err("payment reference too long".to_string());
    }
    let material = auth
        .load()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no account on this device — create or recover an account first".to_string())?;
    PortalClient::with_base_url(config.get().portal_url)
        .activate(&material, payment_reference)
        .await
        .map_err(|e| e.to_string())
}

/// The authenticated subscription status (entitlement + expiry) for the cached account. Returns
/// `None` if no account is cached on this device (the UI shows the create/recover screen).
#[tauri::command]
async fn subscription_status(
    config: State<'_, ConfigState>,
    auth: State<'_, AuthStore>,
) -> Result<Option<AccountStatusResponse>, String> {
    let Some(material) = auth.load().map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    PortalClient::with_base_url(config.get().portal_url)
        .status(&material)
        .await
        .map(Some)
        .map_err(|e| e.to_string())
}

/// Forget the cached account on this device (log out). Does NOT touch the account at the Portal —
/// the user can recover it again with their phrase. Also clears any leftover unlinkable tokens.
#[tauri::command]
async fn logout(auth: State<'_, AuthStore>, store: State<'_, TokenStore>) -> Result<(), String> {
    auth.clear().map_err(|e| e.to_string())?;
    // Tokens are unlinkable, but a logged-out device should hold nothing usable.
    store.clear().map_err(|e| e.to_string())
}

// ---- Engine commands ----

#[tauri::command]
async fn connect(
    engine: State<'_, AppEngine>,
    store: State<'_, TokenStore>,
    config: State<'_, ConfigState>,
    auth: State<'_, AuthStore>,
) -> Result<ConnState, String> {
    // Sync the datapath env to the latest configured endpoints/toggles, then arm leak protection
    // before the tunnel comes up.
    config.reapply_env();
    // Fail fast BEFORE consuming a token: opening a TUN device needs root on macOS/Linux, and the
    // single-use token is removed from disk + redeemed at the Coordinator below — so without this
    // gate an unprivileged connect (e.g. `pnpm tauri dev`) would burn a token on a connect that
    // cannot succeed. Only gate the real-datapath path (`is_configured()`); the loopback/dev mock
    // needs no privilege. No token is touched on this branch.
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    if nil_datapath::launch::is_configured() {
        nil_datapath::preflight_privilege().map_err(|_| {
            "NIL VPN needs to run with administrator/root privileges to open the network tunnel. \
             No token was used — quit and relaunch with elevated privileges."
                .to_string()
        })?;
    }
    leakguard::arm().map_err(|e| e.to_string())?;
    // Mint-on-demand (ADR-0007): if the local buffer is empty but a subscribed account is cached,
    // mint one fresh unlinkable token now so re-login "just works". Done AFTER the privilege gate so
    // we never mint a token we can't use; a no-account / not-subscribed case falls through (the
    // engine then fails closed on an empty store when a Coordinator is configured).
    maybe_mint_on_demand(&store, &config, &auth).await?;
    // Consume one token (removed from disk before use, so a crash never replays a spent token).
    // None is fine for the loopback/dev path; the engine returns NoTokens if a Coordinator is
    // configured but the store is empty (fail closed — never connect unattested/unpaid).
    let token = store.take_one().map_err(|e| e.to_string())?;
    engine.connect(token).await.map_err(|e| e.to_string())
}

/// If the token buffer is empty and a subscribed account is cached, mint exactly one token on
/// demand (ADR-0007). No cached account ⇒ no-op (loopback/dev or not-logged-in). A `NotSubscribed`
/// mint surfaces a clear error so the UI can prompt the user to subscribe/renew.
async fn maybe_mint_on_demand(
    store: &TokenStore,
    config: &ConfigState,
    auth: &AuthStore,
) -> Result<(), String> {
    if store.count().map_err(|e| e.to_string())? > 0 {
        return Ok(()); // already have a token to spend
    }
    let Some(material) = auth.load().map_err(|e| e.to_string())? else {
        return Ok(()); // no account cached — nothing to mint with
    };
    let token = TokenClient::with_base_url(config.get().portal_url)
        .mint(&material)
        .await
        .map_err(|e| e.to_string())?;
    store.add(&[token]).map_err(|e| e.to_string())
}

#[tauri::command]
async fn disconnect(engine: State<'_, AppEngine>) -> Result<ConnState, String> {
    engine.disconnect().await.map_err(|e| e.to_string())
}

/// Network-extension path (mobile + macOS system extension): redeem one on-device token at the
/// Coordinator and return the attested start args (node endpoint + pinned measurement + opaque
/// grant) for the native datapath. The frontend then hands these to the `nil-vpn` plugin, which
/// starts the OS `VpnService`/`PacketTunnel` — the real attested MASQUE tunnel, NOT the loopback
/// mock. Identity never leaves this app process; only the node endpoint, measurement, and grant
/// cross into the datapath process.
///
/// Fail-closed: the token is removed from disk BEFORE redemption (a crash never replays a spent
/// token), and a missing token / Coordinator / bad path all error so the native tunnel never comes
/// up unattested or unpaid.
#[cfg(any(
    target_os = "android",
    target_os = "ios",
    feature = "macos-system-extension"
))]
#[tauri::command]
async fn extension_connect(
    store: State<'_, TokenStore>,
    config: State<'_, ConfigState>,
    auth: State<'_, AuthStore>,
) -> Result<extension::StartArgs, String> {
    let cfg = config.get();
    // Mint-on-demand (ADR-0007): if the buffer is empty but a subscribed account is cached, mint one
    // fresh unlinkable token so re-login reconnects without re-entering the phrase.
    maybe_mint_on_demand(&store, &config, &auth).await?;
    let token = store
        .take_one()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| extension::ExtensionError::NoTokens.to_string())?;
    // Cross-check the redeemed hop's measurement against the client's INDEPENDENT pin (audit B1):
    // with a configured pin, a compromised Coordinator can't substitute a rogue node's measurement.
    let client_pins = extension::client_pins_from_env();
    extension::resolve_start_args(&cfg.coordinator_url, &token, &client_pins)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn status(engine: State<'_, AppEngine>) -> Result<ConnState, String> {
    Ok(engine.state().await)
}

/// The host platform, so the frontend can route Connect to the native datapath on mobile
/// (`VpnService`/`PacketTunnel`) vs. the in-process engine on desktop. One of:
/// "android" | "ios" | "macos" | "linux" | "windows" | "other".
#[tauri::command]
fn platform() -> &'static str {
    if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "other"
    }
}

// ---- Token commands (buy = blind→issue→finalize against the Portal; balance = local count) ----

#[tauri::command]
async fn token_balance(store: State<'_, TokenStore>) -> Result<usize, String> {
    store.count().map_err(|e| e.to_string())
}

/// A payment reference is a short opaque id (UUID / checkout reference, ~32–64 bytes). Reject
/// anything implausibly long at the IPC boundary so a hostile/compromised WebView can't make the
/// client allocate + serialize + transmit a huge string before the Portal's own body limit rejects
/// it (defense-in-depth — don't defer hostile-input rejection to the network).
const MAX_PAYMENT_ID: usize = 256;

#[tauri::command]
async fn buy_tokens(
    payment_id: String,
    config: State<'_, ConfigState>,
    store: State<'_, TokenStore>,
) -> Result<usize, String> {
    if payment_id.len() > MAX_PAYMENT_ID {
        return Err("payment id too long".to_string());
    }
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
    // The kill-switch is enforced by the datapath (`NW_KILLSWITCH`, armed atomically by the tunnel)
    // and takes effect on the next connect. `set_enabled` is a no-op platform seam (see
    // `killswitch`); the env write is done ONLY by `config.update` below, which flips `kill_switch`
    // and writes `NW_KILLSWITCH` UNDER the config write lock — so a concurrent connect/`reapply_env`
    // can never observe a half-applied value, AND a concurrent full `set_config` save can't
    // lost-update it (the whole read-modify-write runs under the lock, not the old get→mutate→set
    // that spanned two lock acquisitions). (An earlier unlocked env write in `set_enabled` raced
    // `reapply_env` and could leave the switch OFF — fail-open.)
    killswitch::set_enabled(enabled).map_err(|e| e.to_string())?;
    config
        .update(|cfg| cfg.kill_switch = enabled)
        .map_err(|e| e.to_string())
}

/// Register the native VPN datapath plugin on mobile. The Kotlin `NilVpnPlugin` (and the iOS
/// `PacketTunnel` equivalent) lives in the app process and starts the OS `VpnService` /
/// `NEPacketTunnelProvider` — the seam that makes the in-app Connect bring up the REAL attested
/// MASQUE tunnel instead of the loopback mock. The plugin identifier matches the Kotlin package.
#[cfg(target_os = "android")]
fn init_vpn_plugin<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("nil-vpn")
        .setup(|_app, api| {
            // Instantiates `com.nilvpn.NilVpnPlugin` and registers it with the Tauri plugin
            // manager, exposing its `startVPN` / `stopVPN` commands to the WebView.
            let _handle = api.register_android_plugin("com.nilvpn", "NilVpnPlugin")?;
            Ok(())
        })
        .build()
}

#[cfg(target_os = "ios")]
fn init_vpn_plugin<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("nil-vpn")
        .setup(|_app, api| {
            let _handle = api.register_ios_plugin(init_nil_vpn_plugin)?;
            Ok(())
        })
        .build()
}

// The iOS plugin registration entry point (exported by the Swift `NilVpnPlugin`).
#[cfg(target_os = "ios")]
extern "C" {
    fn init_nil_vpn_plugin();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init());

    // On mobile, register the native VPN plugin so in-app Connect drives the OS datapath.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder.plugin(init_vpn_plugin());

    builder
        .manage(AppEngine::new())
        .setup(|app| {
            use tauri::Manager;
            let dir = app.path().app_local_data_dir()?;
            // The token store lives in the app's local-data dir — only the device holds tokens
            // (they're unlinkable to the account/payment, so this is privacy-safe).
            app.manage(TokenStore::open(dir.join("tokens.json")));
            // The account auth cache (ADR-0007): the derived auth seed + account number, so the
            // device can mint on demand while subscribed. Owner-only at rest; never the phrase.
            app.manage(AuthStore::open(dir.join("auth.json")));
            // Persisted config (operator endpoints + toggles), applied to the datapath env now so
            // a Coordinator/Portal set in Settings is live without any env vars.
            app.manage(ConfigState::new(dir.join("config.json")));
            Ok(())
        })
        .invoke_handler(invoke_handler())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// Desktop handler set (in-process datapath; no network-extension redeem command).
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "macos-system-extension"
)))]
fn invoke_handler<R: tauri::Runtime>() -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static
{
    tauri::generate_handler![
        get_config,
        set_config,
        create_anonymous_account,
        create_email_account,
        recover_account,
        connect,
        disconnect,
        status,
        platform,
        list_locations,
        set_transport_mode,
        set_split_tunnel,
        toggle_kill_switch,
        buy_tokens,
        token_balance,
        subscribe,
        activate_subscription,
        subscription_status,
        logout,
    ]
}

// Network-extension handler set (mobile + macOS system extension): adds `extension_connect`
// (redeem → native datapath start args).
#[cfg(any(
    target_os = "android",
    target_os = "ios",
    feature = "macos-system-extension"
))]
fn invoke_handler<R: tauri::Runtime>() -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static
{
    tauri::generate_handler![
        get_config,
        set_config,
        create_anonymous_account,
        create_email_account,
        recover_account,
        connect,
        disconnect,
        status,
        platform,
        list_locations,
        set_transport_mode,
        set_split_tunnel,
        toggle_kill_switch,
        buy_tokens,
        token_balance,
        subscribe,
        activate_subscription,
        subscription_status,
        logout,
        extension_connect,
    ]
}
