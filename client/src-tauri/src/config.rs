//! Persisted client configuration (User plane). Lets a user point the app at the live
//! Portal/Coordinator from the GUI **Settings** screen instead of environment variables.
//!
//! The values are applied to the process environment ([`ClientConfig::apply_env`]) at startup and
//! whenever Settings are saved, so the shared datapath launcher (`nil_datapath::launch`, which
//! reads `NW_*`) and the Portal/token clients pick them up without any other code changing — zero
//! datapath drift, the proven `launch.rs` path stays byte-identical. The file holds ONLY operator
//! endpoints + toggles; no account, token, payment, or identity ever lands here (PD-1/PD-3).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Live production defaults (closed alpha). A fresh install already points at the real infra; the
/// node is reached THROUGH the Coordinator's redeemed/attested path, never hardcoded here.
const DEFAULT_PORTAL_URL: &str = "https://api.nilvpn.com";
const DEFAULT_COORDINATOR_URL: &str = "https://ctrl.nilvpn.com";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientConfig {
    /// Business plane (accounts + Privacy Pass issuer).
    pub portal_url: String,
    /// Control plane (token redemption → attested path). Empty ⇒ no real path (loopback/dev).
    pub coordinator_url: String,
    /// Operator Monero deposit address shown on the buy screen (display only; never a secret).
    pub monero_address: String,
    /// Optional pinned guest-launch measurement (hex). Empty ⇒ rely on the Coordinator-delivered
    /// per-hop pin (the normal path); set only for a direct single-node override.
    pub expected_measurement: String,
    /// TEE family for `expected_measurement` ("sev-snp" | "tdx").
    pub expected_tee: String,
    /// Fail-closed kill-switch (block all traffic if the tunnel drops). On by default.
    pub kill_switch: bool,
    /// Advanced: a direct single node `host` (port via NW_NODE_PORT), bypassing the Coordinator.
    /// Empty ⇒ use the Coordinator. Pair with `expected_measurement` (a direct node carries no
    /// Coordinator-delivered pin, so it must be pinned here or the gate fails closed).
    pub node_host: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::live_defaults()
    }
}

impl ClientConfig {
    pub fn live_defaults() -> Self {
        ClientConfig {
            portal_url: DEFAULT_PORTAL_URL.to_string(),
            coordinator_url: DEFAULT_COORDINATOR_URL.to_string(),
            monero_address: String::new(),
            expected_measurement: String::new(),
            expected_tee: "sev-snp".to_string(),
            kill_switch: true,
            node_host: String::new(),
        }
    }

    /// Load from `path`; if absent or corrupt, seed from the environment (so an env-configured
    /// launch still works) falling back to live defaults per field. Never fails the app.
    pub fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<ClientConfig>(&bytes) {
                Ok(cfg) => cfg,
                Err(e) => {
                    tracing::warn!(
                        "client config parse failed ({e}); falling back to env/defaults"
                    );
                    Self::from_env()
                }
            },
            Err(_) => Self::from_env(),
        }
    }

    /// Seed from the environment, falling back to live defaults per field.
    fn from_env() -> Self {
        let d = Self::live_defaults();
        let env_or = |k: &str, dflt: String| {
            std::env::var(k)
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or(dflt)
        };
        ClientConfig {
            portal_url: env_or("PORTAL_URL", d.portal_url),
            coordinator_url: env_or("NW_COORDINATOR_URL", d.coordinator_url),
            monero_address: env_or("NW_MONERO_ADDRESS", d.monero_address),
            expected_measurement: env_or("NW_EXPECTED_MEASUREMENT", d.expected_measurement),
            expected_tee: env_or("NW_EXPECTED_TEE", d.expected_tee),
            kill_switch: std::env::var("NW_KILLSWITCH")
                .map(|v| v != "0")
                .unwrap_or(d.kill_switch),
            node_host: env_or("NW_NODE_HOST", d.node_host),
        }
    }

    /// Atomic, `0600` write (mirrors [`crate::tokenstore`]). Persists only operator endpoints +
    /// toggles — nothing identifying.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let body = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        write_private_atomic(path, &body)
    }

    /// Apply to the process environment so `nil_datapath::launch` (which reads `NW_*`) and the
    /// Portal/token clients see it. Empty fields are REMOVED so the datapath treats them as unset
    /// (e.g. no Coordinator ⇒ `is_configured()` false ⇒ loopback). Called at startup and on Settings
    /// save. Edition 2021: `set_var`/`remove_var` are safe (single-writer here, guarded by the
    /// `ConfigState` lock against concurrent saves).
    pub fn apply_env(&self) {
        set_or_clear("PORTAL_URL", &self.portal_url);
        set_or_clear("NW_COORDINATOR_URL", &self.coordinator_url);
        set_or_clear("NW_NODE_HOST", &self.node_host);
        set_or_clear("NW_EXPECTED_MEASUREMENT", &self.expected_measurement);
        set_or_clear("NW_EXPECTED_TEE", &self.expected_tee);
        std::env::set_var("NW_KILLSWITCH", if self.kill_switch { "1" } else { "0" });
    }
}

fn write_private_atomic(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(&tmp)?;
        f.write_all(body)?;
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn set_or_clear(key: &str, val: &str) {
    if val.is_empty() {
        std::env::remove_var(key);
    } else {
        std::env::set_var(key, val);
    }
}

/// Tauri-managed config: the in-memory config + where it persists. The `RwLock` serializes saves
/// (and the env application underneath them) against reads.
pub struct ConfigState {
    cfg: RwLock<ClientConfig>,
    path: PathBuf,
}

impl ConfigState {
    /// Load from disk (env/defaults fallback) and apply to the process env immediately.
    pub fn new(path: PathBuf) -> Self {
        let cfg = ClientConfig::load(&path);
        cfg.apply_env();
        ConfigState {
            cfg: RwLock::new(cfg),
            path,
        }
    }

    pub fn get(&self) -> ClientConfig {
        self.cfg.read().expect("config lock poisoned").clone()
    }

    /// Replace, persist, and re-apply to the env (atomic under the write lock).
    pub fn set(&self, new: ClientConfig) -> std::io::Result<()> {
        let mut g = self.cfg.write().expect("config lock poisoned");
        new.save(&self.path)?;
        new.apply_env();
        *g = new;
        Ok(())
    }

    /// Re-apply the current config to the env (called before connect so the datapath always reads
    /// the latest endpoints/toggles).
    pub fn reapply_env(&self) {
        self.cfg.read().expect("config lock poisoned").apply_env();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> PathBuf {
        // A process-unique counter, not a timestamp: two tests in the same binary running in
        // parallel can land on the same nanosecond and then collide on one path (one test's
        // teardown races the other's `save`, flaking the run). A monotonic counter guarantees
        // uniqueness regardless of timing.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nil-config-test-{}-{n}/config.json",
            std::process::id()
        ));
        p
    }

    #[test]
    fn live_defaults_point_at_production() {
        let d = ClientConfig::live_defaults();
        assert!(d.portal_url.contains("api.nilvpn.com"));
        assert!(d.coordinator_url.contains("ctrl.nilvpn.com"));
        assert!(d.kill_switch, "kill-switch on by default (fail-closed)");
        assert!(
            d.expected_measurement.is_empty(),
            "Coordinator delivers the pin by default"
        );
    }

    #[test]
    fn save_load_roundtrip_and_missing_file_falls_back() {
        let path = tmp_path();
        // Missing file → env/live defaults.
        let loaded = ClientConfig::load(&path);
        assert_eq!(
            loaded.coordinator_url,
            ClientConfig::live_defaults().coordinator_url
        );
        // Round-trip a custom config.
        let mut cfg = ClientConfig::live_defaults();
        cfg.coordinator_url = "https://ctrl.example.test".into();
        cfg.kill_switch = false;
        cfg.save(&path).expect("save");
        let back = ClientConfig::load(&path);
        assert_eq!(back, cfg);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path();
        ClientConfig::live_defaults().save(&path).expect("save");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config holds endpoints; keep it owner-only");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn config_holds_no_identity_fields() {
        // Tripwire: the persisted shape must never gain an account/token/payment field.
        let json = serde_json::to_string(&ClientConfig::live_defaults()).unwrap();
        for forbidden in ["account", "token", "payment", "recovery", "secret"] {
            assert!(
                !json.contains(forbidden),
                "config must not carry `{forbidden}`"
            );
        }
    }
}
