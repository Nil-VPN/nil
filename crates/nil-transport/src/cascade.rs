//! Obfuscation cascade (architecture spec §4.3). The client walks an ordered list of
//! transports — each looking like a more mundane protocol — and steps down to the next rung
//! when one is blocked:
//!
//! ```text
//! MASQUE/QUIC (UDP 443, looks like HTTPS)   ← default
//!     │ blocked?
//!     ▼  AmneziaWG (DPI-resistant WireGuard, randomized headers)
//!     │ blocked?
//!     ▼  wstunnel (WebSocket-over-TLS)
//!     │ blocked?
//!     ▼  VLESS + REALITY (borrows a real TLS handshake)
//! ```
//!
//! The `Transport` trait is the only seam, so the cascade is just "try `connect`, and on
//! failure try the next rung." A blocked transport surfaces as a `connect` error/timeout.
//!
//! MASQUE is fully implemented (the `masque` feature). The lower rungs are **Phase-4
//! scaffolds**: they carry the correct `kind()`/`fingerprint_profile()` and slot into the
//! cascade, but their datapaths are not built yet — `connect` returns a clear error, so the
//! cascade simply steps past them to MASQUE today. AmneziaWG will reuse the PQ-WireGuard core
//! ([`crate::pqwg`]); wstunnel is WebSocket-over-TLS; REALITY borrows a real TLS handshake.

use std::sync::Arc;

use async_trait::async_trait;
use nil_core::{Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, TransportKind};

use crate::Transport;

/// An ordered set of transports to try, most-preferred first.
pub struct Cascade {
    rungs: Vec<Arc<dyn Transport>>,
}

impl Cascade {
    /// Build a cascade from an ordered rung list (e.g. `[masque, amnezia, wstunnel, reality]`).
    pub fn new(rungs: Vec<Arc<dyn Transport>>) -> Self {
        Self { rungs }
    }

    /// Try each rung in order; return the first that connects, along with its transport so the
    /// caller can pump packets through the rung that won. Steps down on any rung's failure
    /// (a blocked transport surfaces as a `connect` error/timeout). Errors only if every rung
    /// fails — at which point the kill-switch holds (no session is returned).
    pub async fn connect(
        &self,
        target: NodeEndpoint,
        creds: Grant,
    ) -> Result<(Arc<dyn Transport>, Session)> {
        let mut last: Option<Error> = None;
        for rung in &self.rungs {
            match rung.connect(target.clone(), creds.clone()).await {
                Ok(session) => {
                    tracing::info!(kind = ?rung.kind(), "cascade connected");
                    return Ok((rung.clone(), session));
                }
                Err(e) => {
                    tracing::warn!(kind = ?rung.kind(), "cascade rung blocked, stepping down: {e}");
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| Error::Transport("cascade has no rungs".into())))
    }

    /// The configured rung kinds, in order (for diagnostics/UI).
    pub fn rung_kinds(&self) -> Vec<TransportKind> {
        self.rungs.iter().map(|r| r.kind()).collect()
    }
}

/// Shared body for the not-yet-implemented cascade rungs.
macro_rules! scaffold_transport {
    ($name:ident, $kind:expr, $profile:expr, $label:literal) => {
        #[doc = concat!($label, " transport — Phase-4 scaffold (datapath not implemented yet).")]
        #[derive(Default)]
        pub struct $name;

        #[async_trait]
        impl Transport for $name {
            async fn connect(&self, _target: NodeEndpoint, _creds: Grant) -> Result<Session> {
                Err(Error::Transport(concat!($label, " transport is a Phase-4 scaffold").into()))
            }
            async fn send(&self, _session: &Session, _packet: IpPacket) -> Result<()> {
                Err(Error::Closed)
            }
            async fn recv(&self, _session: &Session) -> Result<IpPacket> {
                Err(Error::Closed)
            }
            async fn close(&self, _session: Session) -> Result<()> {
                Ok(())
            }
            fn kind(&self) -> TransportKind {
                $kind
            }
            fn fingerprint_profile(&self) -> Profile {
                $profile
            }
        }
    };
}

scaffold_transport!(
    AmneziaWgTransport,
    TransportKind::AmneziaWg,
    Profile::Wireguardish,
    "AmneziaWG"
);
scaffold_transport!(
    WstunnelTransport,
    TransportKind::Wstunnel,
    Profile::WebSocketTls,
    "wstunnel (WebSocket-over-TLS)"
);
scaffold_transport!(
    RealityTransport,
    TransportKind::Reality,
    Profile::RealTlsBorrowed,
    "VLESS+REALITY"
);

#[cfg(test)]
mod tests {
    use super::*;
    use nil_core::SessionId;

    /// A transport that always fails to connect (simulates a blocked rung).
    struct Blocked(TransportKind);
    #[async_trait]
    impl Transport for Blocked {
        async fn connect(&self, _t: NodeEndpoint, _c: Grant) -> Result<Session> {
            Err(Error::Transport("blocked by DPI".into()))
        }
        async fn send(&self, _s: &Session, _p: IpPacket) -> Result<()> { Err(Error::Closed) }
        async fn recv(&self, _s: &Session) -> Result<IpPacket> { Err(Error::Closed) }
        async fn close(&self, _s: Session) -> Result<()> { Ok(()) }
        fn kind(&self) -> TransportKind { self.0 }
        fn fingerprint_profile(&self) -> Profile { Profile::Internal }
    }

    /// A transport that always connects.
    struct Working(TransportKind);
    #[async_trait]
    impl Transport for Working {
        async fn connect(&self, _t: NodeEndpoint, _c: Grant) -> Result<Session> {
            Ok(Session { id: SessionId(7), kind: self.0 })
        }
        async fn send(&self, _s: &Session, _p: IpPacket) -> Result<()> { Ok(()) }
        async fn recv(&self, _s: &Session) -> Result<IpPacket> { Err(Error::Closed) }
        async fn close(&self, _s: Session) -> Result<()> { Ok(()) }
        fn kind(&self) -> TransportKind { self.0 }
        fn fingerprint_profile(&self) -> Profile { Profile::Internal }
    }

    #[tokio::test]
    async fn steps_down_to_the_first_working_rung() {
        // MASQUE blocked, AmneziaWG blocked, wstunnel works → cascade lands on wstunnel.
        let cascade = Cascade::new(vec![
            Arc::new(Blocked(TransportKind::Masque)),
            Arc::new(Blocked(TransportKind::AmneziaWg)),
            Arc::new(Working(TransportKind::Wstunnel)),
            Arc::new(RealityTransport),
        ]);
        let (t, session) = cascade
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("cascade finds a working rung");
        assert_eq!(t.kind(), TransportKind::Wstunnel, "stepped down past the blocked rungs");
        assert_eq!(session.kind, TransportKind::Wstunnel);
    }

    #[tokio::test]
    async fn errors_when_every_rung_is_blocked() {
        let cascade = Cascade::new(vec![
            Arc::new(Blocked(TransportKind::Masque)),
            Arc::new(AmneziaWgTransport),
            Arc::new(WstunnelTransport),
            Arc::new(RealityTransport),
        ]);
        // All rungs fail (one blocked + three scaffolds) → no session, kill-switch holds.
        assert!(cascade.connect(NodeEndpoint::loopback(), Grant::mock()).await.is_err());
    }

    #[test]
    fn scaffolds_carry_the_right_wire_profiles() {
        assert_eq!(AmneziaWgTransport.kind(), TransportKind::AmneziaWg);
        assert_eq!(AmneziaWgTransport.fingerprint_profile(), Profile::Wireguardish);
        assert_eq!(WstunnelTransport.fingerprint_profile(), Profile::WebSocketTls);
        assert_eq!(RealityTransport.fingerprint_profile(), Profile::RealTlsBorrowed);
    }
}
