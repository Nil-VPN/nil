//! NIL VPN client (User plane) — Tauri commands bridging the frontend to the engine
//! and the Business plane. Honest by construction: a VPN is not anonymity. With a Coordinator
//! configured, Connect brings up the real attested MASQUE datapath — directly via the in-process
//! engine on desktop, or via the native `VpnService`/`PacketTunnel` plugin on mobile (the app
//! process redeems the token and passes only a node endpoint + measurement + grant to it). With no
//! Coordinator configured, release builds refuse to connect. Debug builds retain an explicitly
//! labelled in-memory loopback seam for local integration only.

// `pub` so the headless e2e harness (src/bin/nil-client-e2e.rs) can drive the EXACT same
// account → token → engine path the Tauri commands use (no GUI), closing the "test the engine,
// not just nil-cli" gap.
pub mod account;
pub mod authstore;
pub mod config;
pub mod engine;
mod killswitch;
mod leakguard;
mod netpolicy;
// The network-extension connect path (redeem → attested node endpoint + grant for the native
// datapath). Built where the OS datapath runs in a separate process: Android/iOS, and macOS behind
// the `macos-system-extension` feature (the NEPacketTunnelProvider system extension).
#[cfg(any(
    target_os = "android",
    target_os = "ios",
    feature = "macos-system-extension"
))]
pub mod extension;
pub mod securestore;
mod splittunnel;
mod tokenrefill;
pub mod tokens;
pub mod tokenstore;
pub mod trust;

use tauri::State;

#[cfg(target_os = "android")]
struct SecureStorePluginState(std::sync::Arc<dyn securestore::Sealer>);

/// Private Rust-held handle to the mobile VPN plugin. The WebView has no direct `nil-vpn`
/// capability: consent, bearer start args, status reconciliation, and completion all stay behind
/// this stateful Rust boundary.
#[cfg(any(target_os = "android", target_os = "ios"))]
struct NativeVpnPluginState {
    handle: tauri::plugin::PluginHandle<tauri::Wry>,
    lifecycle: tokio::sync::Mutex<()>,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeVpnPreparation {
    authorized: bool,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeVpnStatus {
    state: String,
    #[serde(default)]
    reservation_id: Option<String>,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeConnectAttempt {
    reservation_id: String,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
impl NativeVpnPluginState {
    async fn prepare(&self) -> Result<NativeVpnPreparation, String> {
        self.handle
            .run_mobile_plugin_async("prepareVpn", ())
            .await
            .map_err(|_| "native VPN permission preflight failed".to_string())
    }

    async fn start(&self, args: &extension::StartArgs) -> Result<(), String> {
        self.handle
            .run_mobile_plugin_async("startVpn", args)
            .await
            .map_err(|_| "native VPN start failed".to_string())
    }

    async fn status(&self) -> Result<NativeVpnStatus, String> {
        self.handle
            .run_mobile_plugin_async("statusVpn", ())
            .await
            .map_err(|_| "native VPN status check failed".to_string())
    }

    async fn stop(&self) -> Result<(), String> {
        self.handle
            .run_mobile_plugin_async("stopVpn", ())
            .await
            .map_err(|_| "native VPN stop failed".to_string())
    }

    async fn open_settings(&self) -> Result<(), String> {
        self.handle
            .run_mobile_plugin_async("openVpnSettings", ())
            .await
            .map_err(|_| "could not open native VPN settings".to_string())
    }
}

use account::{AnonymousAccount, Location, PortalClient, RecoverResult};
use authstore::{AccountAuthMaterial, AuthStore};
use config::{ClientConfig, ConfigState};
use engine::{AppEngine, ConnState};
use nil_proto::account::AccountStatusResponse;
use tokenrefill::TokenRefillState;
use tokens::TokenClient;
use tokenstore::TokenStore;

/// Derive the cacheable auth material (account number + Ed25519 auth seed) from a recovery phrase,
/// so the background batch refiller can authenticate while subscribed WITHOUT re-entering the
/// phrase. We cache the derived seed, never the phrase itself. Used on create + recover ("login").
/// `pub` so the headless e2e harness (`bin/nil-client-e2e.rs`) derives auth material the SAME way.
pub fn derive_auth_material(phrase: &[String]) -> Result<AccountAuthMaterial, String> {
    let parsed = nil_crypto::account::Phrase::parse(phrase).map_err(|e| e.to_string())?;
    let account_number =
        nil_crypto::account::account_number_from_phrase(&parsed).map_err(|e| e.to_string())?;
    let keypair =
        nil_crypto::account::AuthKeypair::from_phrase(&parsed).map_err(|e| e.to_string())?;
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
) -> Result<AnonymousAccount, String> {
    PortalClient::with_base_url(config.get().portal_url)
        .create_anonymous()
        .await
        .map_err(|e| e.to_string())
}

/// Finish onboarding only after the user confirms the mnemonic is backed up. Delaying the local
/// auth-cache write avoids leaving an apparently usable but unrecoverable account if the app closes
/// while the words are still on screen.
#[tauri::command]
async fn confirm_anonymous_account(
    phrase: Vec<String>,
    account_number: String,
    store: State<'_, TokenStore>,
    refill: State<'_, TokenRefillState>,
) -> Result<(), String> {
    let phrase = zeroize::Zeroizing::new(phrase);
    let material = derive_auth_material(&phrase)?;
    if material.account_number != account_number {
        return Err("recovery phrase does not match the registered account".to_string());
    }
    let _account_change = refill.begin_account_change().await;
    store.replace_account(&material).map_err(|e| e.to_string())
}

#[tauri::command]
async fn recover_account(
    phrase: Vec<String>,
    config: State<'_, ConfigState>,
    store: State<'_, TokenStore>,
    refill: State<'_, TokenRefillState>,
) -> Result<RecoverResult, String> {
    // Recovery is entirely local derivation followed by ordinary proof-of-possession auth. The
    // mnemonic is never POSTed to the Portal; only account_number + challenge signature leave.
    let phrase = zeroize::Zeroizing::new(phrase);
    let material = derive_auth_material(&phrase)?;
    let status = PortalClient::with_base_url(config.get().portal_url)
        .status(&material)
        .await
        .map_err(|e| e.to_string())?;
    let _account_change = refill.begin_account_change().await;
    store
        .replace_account(&material)
        .map_err(|e| e.to_string())?;
    if status.entitlement == nil_proto::account::EntitlementDto::Active {
        refill.request();
    }
    Ok(RecoverResult {
        account_number: material.account_number.clone(),
        entitlement: status.entitlement,
    })
}

// ---- Subscription commands (subscribe → pay → activate → randomized batch prefetch) ----

/// Begin (or renew) a subscription: returns the payment reference to pay (e.g. as the Monero
/// payment id). Poll [`activate`] with this reference once the payment confirms.
#[tauri::command]
async fn subscribe(
    config: State<'_, ConfigState>,
    auth: State<'_, AuthStore>,
) -> Result<String, String> {
    let material = auth.load().map_err(|e| e.to_string())?.ok_or_else(|| {
        "no account on this device — create or recover an account first".to_string()
    })?;
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
    refill: State<'_, TokenRefillState>,
) -> Result<AccountStatusResponse, String> {
    if payment_reference.len() > tokens::MAX_PAYMENT_REFERENCE_LEN {
        return Err("payment reference too long".to_string());
    }
    let material = auth.load().map_err(|e| e.to_string())?.ok_or_else(|| {
        "no account on this device — create or recover an account first".to_string()
    })?;
    let status = PortalClient::with_base_url(config.get().portal_url)
        .activate(&material, payment_reference)
        .await
        .map_err(|e| e.to_string())?;
    if status.entitlement == nil_proto::account::EntitlementDto::Active {
        refill.request();
    }
    Ok(status)
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
/// the user can recover it again with their phrase. Also clears any leftover bearer passes.
#[tauri::command]
async fn logout(
    store: State<'_, TokenStore>,
    refill: State<'_, TokenRefillState>,
) -> Result<(), String> {
    let _account_change = refill.begin_account_change().await;
    // One atomic sealed replace: a crash can never leave auth without passes (or passes without
    // auth), and a stale async completion is still blocked by its reservation/request ID.
    store.clear_all_credentials().map_err(|e| e.to_string())
}

// ---- Engine commands ----

#[tauri::command]
async fn connect(
    engine: State<'_, AppEngine>,
    store: State<'_, TokenStore>,
    config: State<'_, ConfigState>,
    refill: State<'_, TokenRefillState>,
) -> Result<ConnState, String> {
    // Sync the datapath env to the latest configured endpoints/toggles, then arm leak protection
    // before the tunnel comes up.
    config.reapply_env();
    // Fail fast BEFORE reserving a token: opening a TUN device needs root on macOS/Linux, and the
    // single-use token is reserved + redeemed at the Coordinator below — so without this gate an
    // unprivileged connect (e.g. `pnpm tauri dev`) would strand a token on a connect that
    // cannot succeed. Debug direct/loopback modes remain local integration paths; production uses
    // the Coordinator path only. No pass is touched on this branch.
    let cfg = config.get();
    let coordinator_configured = !cfg.coordinator_url.trim().is_empty();
    if coordinator_configured {
        netpolicy::require_safe_control_url(&cfg.coordinator_url)?;
    }
    #[cfg(all(
        any(target_os = "macos", target_os = "linux", target_os = "windows"),
        debug_assertions
    ))]
    let datapath_configured = nil_datapath::launch::is_configured();
    #[cfg(all(
        any(target_os = "macos", target_os = "linux", target_os = "windows"),
        not(debug_assertions)
    ))]
    let datapath_configured = coordinator_configured;
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    if datapath_configured {
        nil_datapath::preflight_privilege().map_err(|_| {
            "NIL VPN needs to run with administrator/root privileges to open the network tunnel. \
             No token was used — quit and relaunch with elevated privileges."
                .to_string()
        })?;
    }
    tokenrefill::prune_expired(&store)?;
    if coordinator_configured && store.count().map_err(|e| e.to_string())? == 0 {
        refill.request();
        return Err(
            "connection passes are being prepared in the background; keep NIL open and try again shortly"
                .to_string(),
        );
    }
    leakguard::arm().map_err(|e| e.to_string())?;
    // Only a Coordinator redemption consumes a pass. Debug direct/loopback paths never burn a
    // locally prepared pass, and release refuses those paths in the engine.
    let reservation = if coordinator_configured {
        store.reserve_one().map_err(|e| e.to_string())?
    } else {
        None
    };
    let token = reservation
        .as_ref()
        .map(|reservation| reservation.token.clone());
    match engine.connect(token).await {
        Ok(state) => {
            if coordinator_configured {
                let reservation_id = reservation
                    .as_ref()
                    .ok_or_else(|| "no pending connection-pass reservation exists".to_string())?
                    .reservation_id
                    .as_str();
                if let Err(error) = store.commit_redemption(reservation_id) {
                    // Do not report a protected tunnel as successfully committed when its bearer
                    // reservation could not be cleared. Best-effort teardown keeps the UI and
                    // encrypted credential state conservative and consistent.
                    let _ = engine.disconnect().await;
                    return Err(format!(
                        "tunnel came up but token completion could not be stored: {error}"
                    ));
                }
                request_refill_if_low_best_effort(&refill, &store);
            }
            Ok(state)
        }
        Err(error) => Err(error.to_string()),
    }
}

#[tauri::command]
async fn disconnect(engine: State<'_, AppEngine>) -> Result<ConnState, String> {
    engine.disconnect().await.map_err(|e| e.to_string())
}

/// Reserve and redeem one pass, returning native start material bound to its persisted random
/// reservation. This helper does no plugin IPC so the macOS System Extension seam can retain its
/// existing control integration while Android/iOS keep the complete lifecycle private in Rust.
#[cfg(any(
    target_os = "android",
    target_os = "ios",
    feature = "macos-system-extension"
))]
async fn prepare_extension_start(
    store: State<'_, TokenStore>,
    config: State<'_, ConfigState>,
    refill: State<'_, TokenRefillState>,
) -> Result<extension::StartArgs, String> {
    // The native engines currently support one hop, while production Coordinators require at
    // least two. Refuse before touching local storage so a packaged mobile/System Extension build
    // cannot burn a pass on a path it cannot honor. Debug device harnesses remain available.
    extension::require_supported_connection_profile().map_err(|e| e.to_string())?;
    let cfg = config.get();
    if cfg.coordinator_url.trim().is_empty() {
        return Err(extension::ExtensionError::NoCoordinator.to_string());
    }
    // Validate before reserving the single-use pass. A release HTTP URL (including localhost) or a
    // malformed URL must fail without touching a locally prepared credential.
    netpolicy::require_safe_control_url(&cfg.coordinator_url)?;
    tokenrefill::prune_expired(&store)?;
    let reservation = store
        .reserve_one()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            refill.request();
            "connection passes are being prepared in the background; keep NIL open and try again shortly"
                .to_string()
        })?;
    // Cross-check the redeemed hop's measurement against the client's INDEPENDENT pin (audit B1):
    // with a configured pin, a compromised Coordinator can't substitute a rogue node's measurement.
    let client_pins = extension::client_pins_from_env().map_err(|e| e.to_string())?;
    let transparency_key = trust::effective_transparency_log_key_from_env()?;
    let mut args = extension::resolve_start_args(
        &cfg.coordinator_url,
        &reservation.token,
        &client_pins,
        transparency_key,
    )
    .await
    .map_err(|e| e.to_string())?;
    args.reservation_id = reservation.reservation_id;
    Ok(args)
}

/// Android/iOS connect boundary. Consent is checked before reserving; the bearer grant travels from
/// Rust directly into the private plugin handle and never enters JavaScript.
#[cfg(any(target_os = "android", target_os = "ios"))]
#[tauri::command]
async fn extension_connect(
    vpn: State<'_, NativeVpnPluginState>,
    store: State<'_, TokenStore>,
    config: State<'_, ConfigState>,
    refill: State<'_, TokenRefillState>,
) -> Result<NativeConnectAttempt, String> {
    let _lifecycle = vpn.lifecycle.lock().await;
    let current = vpn.status().await?;
    if matches!(current.state.as_str(), "connecting" | "up") {
        return Err("the native VPN is already connecting or connected".to_string());
    }
    if current.state == "dead" {
        // A DEAD VpnService intentionally still owns the full-route TUN so traffic remains
        // fail-closed. Tear that session down before any Coordinator redemption; the next user
        // attempt can then reuse the same still-pending pass without re-entering the service.
        vpn.stop().await?;
        return Err(
            "The previous VPN session was stopped after losing connectivity. Tap Connect again."
                .to_string(),
        );
    }
    if current.state != "down" {
        return Err("native VPN returned an invalid status".to_string());
    }
    let preparation = vpn.prepare().await?;
    if !preparation.authorized {
        return Err(
            "Grant the VPN permission in the system dialog, then tap Connect again.".to_string(),
        );
    }

    let args = prepare_extension_start(store, config, refill).await?;
    let reservation_id = args.reservation_id.clone();
    if let Err(error) = vpn.start(&args).await {
        let _ = vpn.stop().await;
        return Err(error);
    }
    Ok(NativeConnectAttempt { reservation_id })
}

/// Query the native engine and commit only when it echoes the exact reservation ID and reports
/// `up`. A stale status file/session can therefore never authorize clearing a newer pending pass.
#[cfg(any(target_os = "android", target_os = "ios"))]
#[tauri::command]
async fn extension_connection_status(
    reservation_id: String,
    vpn: State<'_, NativeVpnPluginState>,
    store: State<'_, TokenStore>,
    refill: State<'_, TokenRefillState>,
) -> Result<ConnState, String> {
    let _lifecycle = vpn.lifecycle.lock().await;
    let status = vpn.status().await?;
    match status.state.as_str() {
        "connecting" | "up" => {
            if status.reservation_id.as_deref() != Some(reservation_id.as_str()) {
                let _ = vpn.stop().await;
                return Err(
                    "native VPN status did not match the pending connection attempt".to_string(),
                );
            }
            if status.state == "connecting" {
                return Ok(ConnState::Connecting);
            }
            if let Err(error) = store.commit_redemption(&reservation_id) {
                let _ = vpn.stop().await;
                return Err(format!(
                    "tunnel came up but token completion could not be stored: {error}"
                ));
            }
            request_refill_if_low_best_effort(&refill, &store);
            Ok(ConnState::Connected)
        }
        "down" | "dead" => Ok(ConnState::Disconnected),
        _ => {
            let _ = vpn.stop().await;
            Err("native VPN returned an invalid status".to_string())
        }
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[tauri::command]
async fn extension_disconnect(vpn: State<'_, NativeVpnPluginState>) -> Result<ConnState, String> {
    let _lifecycle = vpn.lifecycle.lock().await;
    vpn.stop().await?;
    Ok(ConnState::Disconnected)
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[tauri::command]
async fn extension_status(
    vpn: State<'_, NativeVpnPluginState>,
    store: State<'_, TokenStore>,
    refill: State<'_, TokenRefillState>,
) -> Result<ConnState, String> {
    let _lifecycle = vpn.lifecycle.lock().await;
    let status = vpn.status().await?;
    match status.state.as_str() {
        "up" => {
            // App death can occur after the out-of-process engine reaches `up` but before the
            // original WebView poll commits. Reconcile that crash window on startup/status. The
            // bounded completion receipt also authenticates an already-committed live session;
            // never accept an unbound/stale `up` record merely because no pass is pending.
            let Some(binding) = store
                .redemption_binding()
                .map_err(|error| error.to_string())?
            else {
                let _ = vpn.stop().await;
                return Err("native VPN status had no local connection binding".to_string());
            };
            if status.reservation_id.as_deref() != Some(binding.reservation_id.as_str()) {
                let _ = vpn.stop().await;
                return Err(
                    "native VPN status did not match the local connection binding".to_string(),
                );
            }
            if binding.pending {
                if let Err(error) = store.commit_redemption(&binding.reservation_id) {
                    let _ = vpn.stop().await;
                    return Err(format!(
                        "tunnel came up but token completion could not be stored: {error}"
                    ));
                }
                request_refill_if_low_best_effort(&refill, &store);
            }
            Ok(ConnState::Connected)
        }
        "connecting" => {
            let Some(binding) = store
                .redemption_binding()
                .map_err(|error| error.to_string())?
            else {
                let _ = vpn.stop().await;
                return Err("native VPN status had no pending connection binding".to_string());
            };
            if !binding.pending
                || status.reservation_id.as_deref() != Some(binding.reservation_id.as_str())
            {
                let _ = vpn.stop().await;
                return Err(
                    "native VPN status did not match the pending connection attempt".to_string(),
                );
            }
            Ok(ConnState::Connecting)
        }
        "down" | "dead" => Ok(ConnState::Disconnected),
        _ => Err("native VPN returned an invalid status".to_string()),
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[tauri::command]
async fn extension_open_vpn_settings(vpn: State<'_, NativeVpnPluginState>) -> Result<(), String> {
    vpn.open_settings().await
}

/// Desktop System Extension integration cannot use Tauri's mobile `PluginHandle` API. Preserve the
/// existing start-args handoff, but bind completion to the exact persisted reservation ID.
#[cfg(all(
    not(any(target_os = "android", target_os = "ios")),
    feature = "macos-system-extension"
))]
#[tauri::command]
async fn extension_connect(
    store: State<'_, TokenStore>,
    config: State<'_, ConfigState>,
    refill: State<'_, TokenRefillState>,
) -> Result<extension::StartArgs, String> {
    prepare_extension_start(store, config, refill).await
}

#[cfg(all(
    not(any(target_os = "android", target_os = "ios")),
    feature = "macos-system-extension"
))]
#[tauri::command]
async fn extension_commit_redemption(
    reservation_id: String,
    store: State<'_, TokenStore>,
    refill: State<'_, TokenRefillState>,
) -> Result<(), String> {
    store
        .commit_redemption(&reservation_id)
        .map_err(|e| e.to_string())?;
    request_refill_if_low_best_effort(&refill, &store);
    Ok(())
}

/// Refill is deliberately decoupled from Connect. Once a tunnel is up and its reserved pass has
/// been durably committed, failure to enqueue a future background refill must not turn that
/// successful connection into an error or tear it down. The worker will retry on its next periodic
/// wake; keep the log free of paths, account material, or bearer data.
fn request_refill_if_low_best_effort(refill: &TokenRefillState, store: &TokenStore) {
    if refill.request_if_low(store).is_err() {
        tracing::warn!("background token-refill scheduling failed; periodic retry remains enabled");
    }
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
    store
        .redeemable_count(tokenrefill::now_unix_secs()?)
        .map_err(|e| e.to_string())
}

/// A payment reference is a short opaque id (UUID / checkout reference, ~32–64 bytes). Reject
/// anything implausibly long at the IPC boundary so a hostile/compromised WebView can't make the
/// client allocate + serialize + transmit a huge string before the Portal's own body limit rejects
/// it (defense-in-depth — don't defer hostile-input rejection to the network).
#[tauri::command]
async fn buy_tokens(
    payment_id: String,
    config: State<'_, ConfigState>,
    store: State<'_, TokenStore>,
    refill: State<'_, TokenRefillState>,
) -> Result<usize, String> {
    if payment_id.len() > tokens::MAX_PAYMENT_REFERENCE_LEN {
        return Err("payment id too long".to_string());
    }
    // One token per confirmed payment (the Portal enforces it). Serialize the complete pending →
    // network → commit transaction with logout/account replacement; otherwise logout can clear the
    // vault while this command is fetching the issuer key, followed by this stale command creating
    // a new pending record and repopulating the just-cleared store.
    let _credential_operation = refill.begin_credential_operation().await;
    tokenrefill::prune_expired(&store)?;
    // Persist the exact blinded request before POST and atomically commit its finalized token so
    // response loss/restart never forces a different request for a payment the Portal consumed.
    TokenClient::with_base_url(config.get().portal_url)
        .acquire_into_store(&payment_id, &store)
        .await
        .map_err(|e| e.to_string())
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
    // Production artifacts contain the MASQUE path only. Alternate selection remains an explicit
    // debug-feature harness and is not configurable through this release UI command.
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
fn init_vpn_plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("nil-vpn")
        .setup(|app, api| {
            use tauri::Manager;
            // Instantiates `com.nilvpn.NilVpnPlugin` and registers it with the Tauri plugin
            // manager. The handle remains private Rust state; no bearer grant crosses the WebView.
            let handle = api.register_android_plugin("com.nilvpn", "NilVpnPlugin")?;
            app.manage(NativeVpnPluginState {
                handle,
                lifecycle: tokio::sync::Mutex::new(()),
            });
            Ok(())
        })
        .build()
}

/// Register the private Android Keystore bridge. Unlike `nil-vpn`, this plugin has no WebView ACL
/// permission; its handle is retained only in Rust state and raw vault plaintext never crosses JS.
#[cfg(target_os = "android")]
fn init_secure_store_plugin<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("nil-secure-store")
        .setup(|app, api| {
            use tauri::Manager;
            let handle = api.register_android_plugin("com.nilvpn", "NilSecureStorePlugin")?;
            app.manage(SecureStorePluginState(securestore::platform_sealer(handle)));
            Ok(())
        })
        .build()
}

#[cfg(target_os = "ios")]
fn init_vpn_plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("nil-vpn")
        .setup(|app, api| {
            use tauri::Manager;
            let handle = api.register_ios_plugin(init_nil_vpn_plugin)?;
            app.manage(NativeVpnPluginState {
                handle,
                lifecycle: tokio::sync::Mutex::new(()),
            });
            Ok(())
        })
        .build()
}

// The iOS plugin registration entry point, exported by the Swift `NilVpnPlugin`
// (`@_cdecl("init_nil_vpn_plugin")`). `ios_plugin_binding!` generates the correctly-typed FFI
// binding (`unsafe extern "C" fn() -> *const c_void`) that `register_ios_plugin` requires — a
// hand-written `extern "C" { fn init_nil_vpn_plugin(); }` has the wrong signature and fails to link.
#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_nil_vpn_plugin);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();

    // Single-instance MUST be the FIRST plugin (Tauri requirement). A second launch focuses the
    // existing window instead of starting a second app process — which would bring up a SECOND
    // tunnel + kill-switch over the first, an incoherent (and potentially leaky) state for a VPN.
    // Desktop only; mobile OSes already enforce single-instance for a packaged app.
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        use tauri::Manager;
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
    }));

    let builder = builder.plugin(tauri_plugin_opener::init());

    // Register secure storage before app setup constructs the encrypted vault.
    #[cfg(target_os = "android")]
    let builder = builder.plugin(init_secure_store_plugin());

    // On mobile, register the native VPN plugin so in-app Connect drives the OS datapath.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder.plugin(init_vpn_plugin());

    builder
        .manage(AppEngine::new())
        .setup(|app| {
            use tauri::Manager;
            let dir = app.path().app_local_data_dir()?;
            let secure_dir = dir.join("secure");
            securestore::harden_storage_directory(&secure_dir)?;
            let vault_path = secure_dir.join("vault.bin");
            #[cfg(target_os = "android")]
            let vault = {
                let sealer = app.state::<SecureStorePluginState>().0.clone();
                securestore::SecureVault::open(vault_path, sealer)
            };
            #[cfg(not(target_os = "android"))]
            let vault = securestore::SecureVault::open_platform(vault_path)?;

            // One verified migration transaction imports the two historical plaintext files and
            // unlinks them only after the OS-sealed vault reopens byte-for-byte. An existing vault
            // always wins; if its OS key is unavailable startup fails instead of regenerating it.
            vault.migrate_legacy(&dir.join("auth.json"), &dir.join("tokens.json"))?;
            app.manage(TokenStore::new(vault.clone()));
            app.manage(AuthStore::new(vault));
            // Persisted config (operator endpoints + toggles), applied to the datapath env now so
            // a Coordinator/Portal set in Settings is live without any env vars.
            app.manage(ConfigState::new(dir.join("config.json")));
            app.manage(TokenRefillState::default());

            // One coalescing worker performs subscription refills independently of Connect. Startup,
            // activation, recovery, and low-watermark hints all wait random privacy jitter before a
            // bounded batch request; periodic wakes cover a long-running idle client.
            app.state::<TokenRefillState>().request();
            tauri::async_runtime::spawn(tokenrefill::run_worker(app.handle().clone()));
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
fn invoke_handler<R: tauri::Runtime>(
) -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        get_config,
        set_config,
        create_anonymous_account,
        confirm_anonymous_account,
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

// Mobile handler set: all native plugin calls remain behind Rust commands.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn invoke_handler<R: tauri::Runtime>(
) -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        get_config,
        set_config,
        create_anonymous_account,
        confirm_anonymous_account,
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
        extension_connection_status,
        extension_disconnect,
        extension_status,
        extension_open_vpn_settings,
    ]
}

// macOS System Extension seam. Tauri's private mobile PluginHandle calls are unavailable on
// desktop, so preserve the existing start-args handoff while requiring an ID-bound completion.
#[cfg(all(
    not(any(target_os = "android", target_os = "ios")),
    feature = "macos-system-extension"
))]
fn invoke_handler<R: tauri::Runtime>(
) -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        get_config,
        set_config,
        create_anonymous_account,
        confirm_anonymous_account,
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
        extension_commit_redemption,
    ]
}
