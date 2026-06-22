//! The connection lifecycle / state machine (architecture spec §9).
//!
//! Phase 0 is a *mock*: it drives the real [`Transport`] seam through the in-memory
//! loopback echo transport, so the UI and the state machine are exercised end to end
//! without a real tunnel. All tunnel logic stays behind the `Transport` trait — the
//! engine never knows which transport is active. Phase 1 swaps loopback for MASQUE
//! with zero changes here.

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

struct EngineInner {
    state: ConnState,
    transport: Box<dyn Transport>,
    session: Option<nil_core::Session>,
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
            transport: Box::new(LoopbackTransport::new()),
            session: None,
        })))
    }

    pub async fn state(&self) -> ConnState {
        self.0.lock().await.state
    }

    /// Connect through the active transport. For loopback this opens a session, sends
    /// a probe packet, and reads the echo back — proving the engine↔transport seam
    /// works before we report `Connected`.
    pub async fn connect(&self) -> Result<ConnState, EngineError> {
        let mut g = self.0.lock().await;
        if g.state != ConnState::Disconnected {
            return Err(EngineError::NotDisconnected(g.state));
        }
        g.state = ConnState::Connecting;

        let session = g
            .transport
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .map_err(|e| EngineError::Transport(e.to_string()))?;

        // Prove the seam: round-trip a probe packet through the transport.
        let probe = IpPacket::new(b"nil-loopback-probe".to_vec());
        g.transport
            .send(&session, probe.clone())
            .await
            .map_err(|e| EngineError::Transport(e.to_string()))?;
        let echo = g
            .transport
            .recv(&session)
            .await
            .map_err(|e| EngineError::Transport(e.to_string()))?;
        debug_assert_eq!(echo.as_bytes(), probe.as_bytes());

        g.session = Some(session);
        g.state = ConnState::Connected;
        Ok(g.state)
    }

    /// Tear the tunnel down cleanly.
    pub async fn disconnect(&self) -> Result<ConnState, EngineError> {
        let mut g = self.0.lock().await;
        if g.state != ConnState::Connected {
            return Err(EngineError::NotConnected(g.state));
        }
        g.state = ConnState::Disconnecting;
        if let Some(session) = g.session.take() {
            g.transport
                .close(session)
                .await
                .map_err(|e| EngineError::Transport(e.to_string()))?;
        }
        g.state = ConnState::Disconnected;
        Ok(g.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_disconnect_cycle() {
        let engine = AppEngine::new();
        assert_eq!(engine.state().await, ConnState::Disconnected);
        assert_eq!(engine.connect().await.expect("connect"), ConnState::Connected);
        assert_eq!(engine.state().await, ConnState::Connected);
        assert_eq!(
            engine.disconnect().await.expect("disconnect"),
            ConnState::Disconnected
        );
    }

    #[tokio::test]
    async fn double_connect_is_rejected() {
        let engine = AppEngine::new();
        engine.connect().await.expect("first connect");
        assert!(matches!(
            engine.connect().await,
            Err(EngineError::NotDisconnected(ConnState::Connected))
        ));
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
