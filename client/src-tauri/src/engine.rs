//! The connection lifecycle / state machine (architecture spec §9).
//!
//! On **desktop** (macOS/Linux/Windows), when a node/path is configured in the environment
//! (`NW_NODE_HOST` or `NW_PATH`, the same vars `nil-cli` reads), `connect` brings up the real
//! attested MASQUE datapath through `nil-datapath::Tunnel` — TUN device, default-route swap,
//! fail-closed kill-switch, and the packet pump — exactly as the headless CLI does (they share
//! `nil_datapath::launch`, so they can't drift). With nothing configured, or on **mobile**
//! (where the datapath is a `NEPacketTunnelProvider`/`VpnService`, built separately), it falls
//! back to the in-memory loopback echo transport so the UI/state machine still exercise the
//! `Transport` seam end to end without touching real networking.
//!
//! All tunnel logic stays behind the `Transport` trait — the engine never knows which transport
//! is active.

use std::sync::Arc;

use nil_core::{Grant, IpPacket, NodeEndpoint};
use nil_transport::loopback::LoopbackTransport;
use nil_transport::Transport;
use serde::Serialize;
use tokio::sync::Mutex;

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
}

/// What is currently connected.
enum Active {
    Disconnected,
    /// In-memory loopback echo (dev / mobile / nothing configured).
    Loopback { transport: Box<dyn Transport>, session: nil_core::Session },
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

    /// Connect: the real datapath if a node/path is configured (desktop), else the loopback mock.
    pub async fn connect(&self) -> Result<ConnState, EngineError> {
        let mut g = self.0.lock().await;
        if g.state != ConnState::Disconnected {
            return Err(EngineError::NotDisconnected(g.state));
        }
        g.state = ConnState::Connecting;

        // Real datapath (desktop only, when configured). On any failure reset to Disconnected so
        // the UI reflects fail-closed — the Tunnel rolls back any partial arm before erroring.
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            if nil_datapath::launch::is_configured() {
                return match Self::bring_up_real().await {
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

        // Loopback fallback: open a session and round-trip a probe to prove the seam works.
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

    /// Build the transport + config from the environment (shared with `nil-cli`) and bring up
    /// the real attested tunnel.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn bring_up_real() -> Result<nil_datapath::Tunnel, EngineError> {
        let (transport, cfg) =
            nil_datapath::launch::from_env().await.map_err(|e| EngineError::Transport(e.to_string()))?;
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
        if g.state != ConnState::Connected {
            return Err(EngineError::NotConnected(g.state));
        }
        g.state = ConnState::Disconnecting;
        match std::mem::replace(&mut g.active, Active::Disconnected) {
            Active::Loopback { transport, session } => {
                transport
                    .close(session)
                    .await
                    .map_err(|e| EngineError::Transport(e.to_string()))?;
            }
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            Active::Tunnel(tunnel) => {
                tunnel.down().await.map_err(|e| EngineError::Transport(e.to_string()))?;
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

    // These run on the host (a desktop target), so they must NOT hit the real datapath: they
    // rely on no node being configured (NW_NODE_HOST / NW_PATH unset), in which case `connect`
    // uses the loopback mock.
    fn assert_unconfigured() {
        assert!(
            std::env::var("NW_NODE_HOST").is_err() && std::env::var("NW_PATH").is_err(),
            "engine tests require NW_NODE_HOST / NW_PATH to be unset (they exercise loopback)"
        );
    }

    #[tokio::test]
    async fn connect_disconnect_cycle() {
        assert_unconfigured();
        let engine = AppEngine::new();
        assert_eq!(engine.state().await, ConnState::Disconnected);
        assert_eq!(engine.connect().await.expect("connect"), ConnState::Connected);
        assert_eq!(engine.state().await, ConnState::Connected);
        assert_eq!(engine.disconnect().await.expect("disconnect"), ConnState::Disconnected);
    }

    #[tokio::test]
    async fn double_connect_is_rejected() {
        assert_unconfigured();
        let engine = AppEngine::new();
        engine.connect().await.expect("first connect");
        assert!(matches!(
            engine.connect().await,
            Err(EngineError::NotDisconnected(ConnState::Connected))
        ));
        engine.disconnect().await.expect("cleanup");
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
