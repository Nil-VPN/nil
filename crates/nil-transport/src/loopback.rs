//! In-memory loopback echo transport — the Phase 0 scaffold implementation.
//!
//! Anything sent into a session is echoed straight back on the next `recv`. It carries
//! no real traffic and never touches a network, but it exercises the full [`Transport`]
//! seam end to end so the client engine and the test suite can drive a realistic
//! connect → send → recv → close lifecycle.
//!
//! State model (mirrors a real transport): [`Session`] is a lightweight `Copy` handle;
//! the heavy per-session state lives here in a map keyed by [`SessionId`]. A real
//! `quiche`/`boringtun` connection is far too heavy to live in the handle.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use nil_core::{
    Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind,
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex as AsyncMutex;

use crate::Transport;

/// Per-session queue. `tx` is pushed by `send`; `recv` drains `rx` (the echo).
struct SessionState {
    tx: UnboundedSender<IpPacket>,
    rx: AsyncMutex<UnboundedReceiver<IpPacket>>,
}

/// An in-memory echo transport. Cheap to construct; holds all live sessions.
#[derive(Default)]
pub struct LoopbackTransport {
    next_id: AtomicU64,
    sessions: Mutex<HashMap<SessionId, Arc<SessionState>>>,
}

impl LoopbackTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a session's state, cloning the `Arc` out so the std mutex is released
    /// before any `.await` (never hold a `std::Mutex` across an await point).
    fn state(&self, session: &Session) -> Result<Arc<SessionState>> {
        let map = self
            .sessions
            .lock()
            .map_err(|_| Error::Transport("loopback session map poisoned".into()))?;
        map.get(&session.id)
            .cloned()
            .ok_or(Error::SessionNotFound(session.id))
    }
}

#[async_trait]
impl Transport for LoopbackTransport {
    async fn connect(&self, _target: NodeEndpoint, _creds: Grant) -> Result<Session> {
        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = unbounded_channel();
        let state = Arc::new(SessionState {
            tx,
            rx: AsyncMutex::new(rx),
        });
        let mut map = self
            .sessions
            .lock()
            .map_err(|_| Error::Transport("loopback session map poisoned".into()))?;
        map.insert(id, state);
        Ok(Session {
            id,
            kind: TransportKind::Loopback,
        })
    }

    async fn send(&self, session: &Session, packet: IpPacket) -> Result<()> {
        let state = self.state(session)?;
        // Enqueue for echo. Failure means the receiver was dropped → treat as closed.
        state.tx.send(packet).map_err(|_| Error::Closed)
    }

    async fn recv(&self, session: &Session) -> Result<IpPacket> {
        let state = self.state(session)?; // std mutex already released here
        let mut rx = state.rx.lock().await;
        rx.recv().await.ok_or(Error::Closed)
    }

    async fn close(&self, session: Session) -> Result<()> {
        let mut map = self
            .sessions
            .lock()
            .map_err(|_| Error::Transport("loopback session map poisoned".into()))?;
        map.remove(&session.id)
            .ok_or(Error::SessionNotFound(session.id))?;
        Ok(())
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Loopback
    }

    fn fingerprint_profile(&self) -> Profile {
        Profile::Internal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_echo_roundtrip() {
        let t = LoopbackTransport::new();
        let session = t
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("connect");

        let pkt = IpPacket::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        t.send(&session, pkt.clone()).await.expect("send");
        let got = t.recv(&session).await.expect("recv");
        assert_eq!(got, pkt, "loopback must echo the exact packet back");

        t.close(session).await.expect("close");

        // `Session` is Copy, so this still type-checks after close — but the state is
        // gone, so the send must fail. (Handle survives; resources do not.)
        assert!(
            t.send(&session, IpPacket::new(vec![0x01])).await.is_err(),
            "send after close must error (session state removed)"
        );
    }

    #[tokio::test]
    async fn distinct_sessions_have_independent_queues() {
        let t = LoopbackTransport::new();
        let a = t
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("connect a");
        let b = t
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("connect b");
        assert_ne!(a.id, b.id, "each session gets a fresh id");

        // Each session echoes only its own packets — no cross-talk.
        t.send(&a, IpPacket::new(vec![0xAA])).await.expect("send a");
        t.send(&b, IpPacket::new(vec![0xBB])).await.expect("send b");
        assert_eq!(t.recv(&a).await.expect("recv a").as_bytes(), &[0xAA]);
        assert_eq!(t.recv(&b).await.expect("recv b").as_bytes(), &[0xBB]);
    }

    #[test]
    fn kind_and_profile_are_loopback() {
        let t = LoopbackTransport::new();
        assert_eq!(t.kind(), TransportKind::Loopback);
        assert_eq!(t.fingerprint_profile(), Profile::Internal);
    }
}
