//! The connection lifecycle / state machine (architecture spec §9).
//!
//! On **desktop** (macOS/Linux/Windows), `connect` brings up the real attested MASQUE datapath
//! through `nil-datapath::Tunnel` — TUN device, default-route swap, fail-closed kill-switch, and
//! packet pump. Production builds require a Coordinator-redeemed path. The direct/static launcher
//! and in-memory loopback echo exist only with `debug_assertions` for local integration; those
//! branches are absent from release binaries, which fail explicitly when no production path exists.
//!
//! On **mobile** the real datapath is a separate-process `NEPacketTunnelProvider`/`VpnService`
//! (built separately): the frontend routes Connect to the native plugin (`extension_connect` in
//! `lib.rs` → the `nil-vpn` plugin), NOT to this engine, so the mobile Connect path is the real
//! attested tunnel. Debug desktop builds may use the loopback seam when nothing is configured.
//!
//! All tunnel logic stays behind the `Transport` trait — the engine never knows which transport
//! is active.

use std::sync::Arc;

#[cfg(debug_assertions)]
use nil_core::{Grant, IpPacket, NodeEndpoint};
#[cfg(debug_assertions)]
use nil_transport::{loopback::LoopbackTransport, Transport};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::tokens::StoredToken;

/// Observable connection state, mirrored to the frontend as a lowercase string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("cannot connect while {0:?}")]
    NotDisconnected(ConnState),
    #[error("cannot disconnect while {0:?}")]
    NotConnected(ConnState),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("no connection token — buy one before connecting")]
    NoTokens,
    #[error(
        "no production datapath is configured — configure an HTTPS Coordinator before connecting"
    )]
    NoProductionPath,
}

/// What is currently connected.
enum Active {
    Disconnected,
    /// In-memory loopback echo for debug builds and optimized E2E builds with debug assertions.
    #[cfg(debug_assertions)]
    Loopback {
        transport: Box<dyn Transport>,
        session: nil_core::Session,
    },
    /// The real OS datapath: a live tunnel that has armed routing + the kill-switch (desktop).
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    Tunnel(nil_datapath::Tunnel),
}

struct EngineInner {
    state: ConnState,
    active: Active,
}

/// Cloneable engine handle, stored as Tauri managed state. The `Arc<Mutex<…>>` lets
/// async commands clone it and `.await` without holding a `State` borrow across the
/// await point.
#[derive(Clone)]
pub struct AppEngine(Arc<Mutex<EngineInner>>);

impl Default for AppEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AppEngine {
    pub fn new() -> Self {
        AppEngine(Arc::new(Mutex::new(EngineInner {
            state: ConnState::Disconnected,
            active: Active::Disconnected,
        })))
    }

    pub async fn state(&self) -> ConnState {
        self.0.lock().await.state
    }

    /// Connect through the Coordinator-backed production datapath. Debug builds may additionally
    /// use the direct/static launcher or loopback seam. `token` is required only for a Coordinator
    /// redemption; release builds never reinterpret its absence as permission to use a mock path.
    pub async fn connect(&self, token: Option<StoredToken>) -> Result<ConnState, EngineError> {
        let mut g = self.0.lock().await;
        if g.state != ConnState::Disconnected {
            return Err(EngineError::NotDisconnected(g.state));
        }
        g.state = ConnState::Connecting;

        // Real datapath (desktop only, when configured). On any failure reset to Disconnected so
        // the UI reflects fail-closed — the Tunnel rolls back any partial arm before erroring.
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            #[cfg(debug_assertions)]
            let datapath_configured = nil_datapath::launch::is_configured();
            #[cfg(not(debug_assertions))]
            let datapath_configured =
                std::env::var("NW_COORDINATOR_URL").is_ok_and(|url| !url.trim().is_empty());

            if datapath_configured {
                return match Self::bring_up_configured(token).await {
                    Ok(tunnel) => {
                        g.active = Active::Tunnel(tunnel);
                        g.state = ConnState::Connected;
                        Ok(g.state)
                    }
                    Err(e) => {
                        g.state = ConnState::Disconnected;
                        Err(e)
                    }
                };
            }
        }

        #[cfg(debug_assertions)]
        {
            let _ = token; // debug loopback does not consume a connection pass
                           // Loopback seam: round-trip a probe so local builds exercise the Transport boundary.
            match Self::bring_up_loopback().await {
                Ok((transport, session)) => {
                    g.active = Active::Loopback { transport, session };
                    g.state = ConnState::Connected;
                    Ok(g.state)
                }
                Err(e) => {
                    g.state = ConnState::Disconnected;
                    Err(e)
                }
            }
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = token;
            g.state = ConnState::Disconnected;
            Err(EngineError::NoProductionPath)
        }
    }

    #[cfg(debug_assertions)]
    async fn bring_up_loopback() -> Result<(Box<dyn Transport>, nil_core::Session), EngineError> {
        let transport: Box<dyn Transport> = Box::new(LoopbackTransport::new());
        let session = transport
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .map_err(|e| EngineError::Transport(e.to_string()))?;
        // Prove the seam: round-trip a probe packet through the transport.
        let probe = IpPacket::new(b"nil-loopback-probe".to_vec());
        transport
            .send(&session, probe.clone())
            .await
            .map_err(|e| EngineError::Transport(e.to_string()))?;
        let echo = transport
            .recv(&session)
            .await
            .map_err(|e| EngineError::Transport(e.to_string()))?;
        debug_assert_eq!(echo.as_bytes(), probe.as_bytes());
        Ok((transport, session))
    }

    /// Build the transport + config (shared with `nil-cli`) and bring up the real attested tunnel.
    /// With a Coordinator configured (`NW_COORDINATOR_URL`), the path is redeemed using the
    /// in-process `token` (no bearer credential in the environment). Only debug builds may instead
    /// use `NW_PATH` / `NW_NODE_HOST`, without consuming a pass.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn bring_up_configured(
        token: Option<StoredToken>,
    ) -> Result<nil_datapath::Tunnel, EngineError> {
        let coordinator = std::env::var("NW_COORDINATOR_URL")
            .ok()
            .filter(|url| !url.trim().is_empty());
        let (transport, cfg) = if let Some(coord) = coordinator {
            crate::netpolicy::require_safe_control_url(&coord).map_err(EngineError::Transport)?;
            let tok = token.ok_or(EngineError::NoTokens)?;
            // These roots come from the bundle embedded at build time. Config/env pins may select
            // a subset, but `trust` never unions in a measurement or log key, so the Coordinator's
            // response is independently cross-checked before any node is dialled.
            let measurements = crate::trust::effective_node_measurements_from_env()
                .map_err(EngineError::Transport)?;
            let transparency_key = crate::trust::effective_transparency_log_key_from_env()
                .map_err(EngineError::Transport)?;
            nil_datapath::launch::from_env_with_token_and_trust(
                &coord,
                &tok.msg,
                &tok.token,
                &measurements,
                transparency_key,
            )
            .await
            .map_err(|e| EngineError::Transport(e.to_string()))?
        } else {
            #[cfg(debug_assertions)]
            {
                if crate::trust::embedded().is_some() {
                    // A static endpoint carries no Coordinator-signed expectation. Require settings
                    // to select one embedded measurement, then force the embedded transparency-log
                    // key into the appraisal policy.
                    let measurements = crate::trust::effective_node_measurements_from_env()
                        .map_err(EngineError::Transport)?;
                    let transparency_key = crate::trust::effective_transparency_log_key_from_env()
                        .map_err(EngineError::Transport)?
                        .ok_or_else(|| {
                            EngineError::Transport(
                                "embedded trust bundle is missing a transparency-log key"
                                    .to_string(),
                            )
                        })?;
                    nil_datapath::launch::from_env_with_direct_trust(
                        &measurements,
                        transparency_key,
                    )
                    .await
                    .map_err(|e| EngineError::Transport(e.to_string()))?
                } else {
                    nil_datapath::launch::from_env()
                        .await
                        .map_err(|e| EngineError::Transport(e.to_string()))?
                }
            }
            #[cfg(not(debug_assertions))]
            {
                return Err(EngineError::NoProductionPath);
            }
        };
        // No node address in logs (SOUL §3 / PD-2); structured tracing, not raw stderr.
        tracing::debug!("bringing up real datapath");
        nil_datapath::Tunnel::up(transport, cfg)
            .await
            .map_err(|e| EngineError::Transport(e.to_string()))
    }

    /// Tear the tunnel down cleanly. For the real datapath this restores routing/DNS/firewall
    /// before dropping the session, so there is no leak window.
    pub async fn disconnect(&self) -> Result<ConnState, EngineError> {
        let mut g = self.0.lock().await;
        if !matches!(g.state, ConnState::Connected | ConnState::Disconnecting) {
            return Err(EngineError::NotConnected(g.state));
        }
        g.state = ConnState::Disconnecting;
        match std::mem::replace(&mut g.active, Active::Disconnected) {
            #[cfg(debug_assertions)]
            Active::Loopback { transport, session } => {
                transport
                    .close(session)
                    .await
                    .map_err(|e| EngineError::Transport(e.to_string()))?;
            }
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            Active::Tunnel(mut tunnel) => {
                if let Err(error) = tunnel.down().await {
                    // Preserve the exact rollback journal. The UI remains Disconnecting and a
                    // repeated Disconnect retries only the mutations that are still pending.
                    g.active = Active::Tunnel(tunnel);
                    return Err(EngineError::Transport(error.to_string()));
                }
            }
            Active::Disconnected => {}
        }
        g.state = ConnState::Disconnected;
        Ok(g.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Debug tests run on the host (a desktop target), so they must NOT hit the real datapath: they
    // rely on no node being configured (NW_NODE_HOST / NW_PATH unset), in which case `connect`
    // uses the loopback mock.
    #[cfg(debug_assertions)]
    fn assert_unconfigured() {
        assert!(
            std::env::var("NW_NODE_HOST").is_err()
                && std::env::var("NW_PATH").is_err()
                && std::env::var("NW_COORDINATOR_URL").is_err(),
            "engine tests require node/path/Coordinator variables to be unset"
        );
    }

    /// Hold the shared env lock and clear `NW_COORDINATOR_URL` so a parallel `config` test's
    /// `apply_env` can't make this loopback `connect(None)` take the real (token-required) path and
    /// fail `NoTokens`. `std::env` is process-global; the lock serializes the env-reading connect
    /// tests against the env-mutating config tests. The (tokio) guard is held for the whole test
    /// body — including across `connect().await`.
    #[cfg(debug_assertions)]
    async fn loopback_env_guard() -> tokio::sync::MutexGuard<'static, ()> {
        let g = crate::env_test_lock().lock().await;
        std::env::remove_var("NW_COORDINATOR_URL");
        g
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn connect_disconnect_cycle() {
        let _env = loopback_env_guard().await;
        assert_unconfigured();
        let engine = AppEngine::new();
        assert_eq!(engine.state().await, ConnState::Disconnected);
        assert_eq!(
            engine.connect(None).await.expect("connect"),
            ConnState::Connected
        );
        assert_eq!(engine.state().await, ConnState::Connected);
        assert_eq!(
            engine.disconnect().await.expect("disconnect"),
            ConnState::Disconnected
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn double_connect_is_rejected() {
        let _env = loopback_env_guard().await;
        assert_unconfigured();
        let engine = AppEngine::new();
        engine.connect(None).await.expect("first connect");
        assert!(matches!(
            engine.connect(None).await,
            Err(EngineError::NotDisconnected(ConnState::Connected))
        ));
        engine.disconnect().await.expect("cleanup");
    }
    #[cfg(not(debug_assertions))]
    #[tokio::test]
    async fn release_rejects_missing_coordinator_and_debug_direct_paths() {
        let _guard = crate::env_test_lock().lock().await;
        let saved = ["NW_COORDINATOR_URL", "NW_NODE_HOST", "NW_PATH"]
            .map(|key| (key, std::env::var(key).ok()));
        for (key, _) in &saved {
            std::env::remove_var(key);
        }

        let engine = AppEngine::new();
        let no_path = engine.connect(None).await;
        std::env::set_var("NW_NODE_HOST", "127.0.0.1");
        std::env::set_var("NW_PATH", "debug-static-path");
        let direct_path = engine.connect(None).await;

        for (key, value) in saved {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }

        assert!(matches!(no_path, Err(EngineError::NoProductionPath)));
        assert!(matches!(direct_path, Err(EngineError::NoProductionPath)));
        assert_eq!(engine.state().await, ConnState::Disconnected);
    }

    #[tokio::test]
    async fn disconnect_when_idle_is_rejected() {
        let engine = AppEngine::new();
        assert!(matches!(
            engine.disconnect().await,
            Err(EngineError::NotConnected(ConnState::Disconnected))
        ));
    }
}
