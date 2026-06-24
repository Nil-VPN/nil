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
//! The `Transport` trait is the only seam, so the cascade is "try `connect`, verify the tunnel
//! is actually alive, and on failure try the next rung."
//!
//! A real DPI block rarely surfaces as a prompt `connect` error — it usually **hangs** (the
//! handshake packets are silently dropped), or lets the handshake complete and then drops the
//! data. So stepping down only on an immediate error would wedge on the first rung. The cascade
//! therefore (1) bounds each rung's `connect` with a **timeout** and (2) optionally runs a
//! post-connect **liveness probe** before committing to a rung.
//!
//! MASQUE is fully implemented (the `masque` feature). The lower rungs are **scaffolds** at the
//! `Transport` level: they carry the correct `kind()`/`fingerprint_profile()` and slot into the
//! cascade, but their `connect` returns a clear error, so the cascade steps past them to MASQUE
//! today. AmneziaWG's DPI-defeating obfuscation core (magic headers + junk that erase WG's
//! 148/92-byte + message-type fingerprint) is implemented and tested in [`crate::amneziawg`],
//! reusing the PQ-WireGuard crypto ([`crate::pqwg`]); only its live UDP datapath remains. wstunnel
//! is WebSocket-over-TLS; REALITY borrows a real TLS handshake.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use nil_core::{Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind};

use crate::Transport;

/// Default per-rung `connect` timeout. A backstop for a rung that hangs (DPI dropping the
/// handshake) — it is intentionally longer than MASQUE's own internal handshake timeout, so a
/// working rung's own error fires first and only a truly wedged rung hits this.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// A post-connect check that the chosen rung actually carries traffic. A rung can complete its
/// handshake and then have its data silently dropped (a common censor behaviour); a `false`
/// verdict makes the cascade close that rung and step down.
#[async_trait]
pub trait LivenessProbe: Send + Sync {
    async fn is_alive(&self, transport: &Arc<dyn Transport>, session: &Session) -> bool;
}

/// An ordered set of transports to try, most-preferred first.
pub struct Cascade {
    rungs: Vec<Arc<dyn Transport>>,
    connect_timeout: Duration,
    probe: Option<Arc<dyn LivenessProbe>>,
}

impl Cascade {
    /// Build a cascade from an ordered rung list (e.g. `[masque, amnezia, wstunnel, reality]`),
    /// with the default connect timeout and no liveness probe.
    pub fn new(rungs: Vec<Arc<dyn Transport>>) -> Self {
        Self { rungs, connect_timeout: DEFAULT_CONNECT_TIMEOUT, probe: None }
    }

    /// Override the per-rung connect timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Run `probe` after each rung connects; step down if it reports the tunnel dead.
    pub fn with_liveness_probe(mut self, probe: Arc<dyn LivenessProbe>) -> Self {
        self.probe = Some(probe);
        self
    }

    /// Try each rung in order; return the first that connects **and** passes the liveness probe,
    /// along with its transport so the caller can pump packets through the rung that won. Steps
    /// down when a rung errors, **times out**, or connects but fails the probe. Errors only if
    /// every rung fails — at which point the kill-switch holds (no session is returned).
    pub async fn connect(
        &self,
        target: NodeEndpoint,
        creds: Grant,
    ) -> Result<(Arc<dyn Transport>, Session)> {
        let mut last: Option<Error> = None;
        for rung in &self.rungs {
            let kind = rung.kind();
            let session = match tokio::time::timeout(
                self.connect_timeout,
                rung.connect(target.clone(), creds.clone()),
            )
            .await
            {
                Ok(Ok(session)) => session,
                Ok(Err(e)) => {
                    tracing::warn!(?kind, "cascade rung blocked, stepping down: {e}");
                    last = Some(e);
                    continue;
                }
                Err(_elapsed) => {
                    tracing::warn!(?kind, timeout = ?self.connect_timeout, "cascade rung timed out, stepping down");
                    last = Some(Error::Transport(format!("{kind:?} connect timed out")));
                    continue;
                }
            };

            // Connected — verify it actually carries traffic before committing.
            if let Some(probe) = &self.probe {
                if !probe.is_alive(rung, &session).await {
                    tracing::warn!(?kind, "cascade rung connected but failed liveness, stepping down");
                    let _ = rung.close(session).await;
                    last = Some(Error::Transport(format!("{kind:?} connected but failed the liveness probe")));
                    continue;
                }
            }

            tracing::info!(?kind, "cascade connected");
            return Ok((rung.clone(), session));
        }
        Err(last.unwrap_or_else(|| Error::Transport("cascade has no rungs".into())))
    }

    /// The configured rung kinds, in order (for diagnostics/UI).
    pub fn rung_kinds(&self) -> Vec<TransportKind> {
        self.rungs.iter().map(|r| r.kind()).collect()
    }
}

/// A built-in liveness probe: send a DNS query through the tunnel and treat any inbound packet
/// within the timeout as "alive". The query rides the tunnel exactly like real traffic (the
/// node NATs it to the resolver), so it exercises the full data path — not just the handshake.
pub struct DnsLivenessProbe {
    resolver: std::net::SocketAddrV4,
    client: std::net::SocketAddrV4,
    timeout: Duration,
}

impl Default for DnsLivenessProbe {
    fn default() -> Self {
        use std::net::{Ipv4Addr, SocketAddrV4};
        Self {
            resolver: SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53),
            client: SocketAddrV4::new(Ipv4Addr::new(10, 74, 0, 2), 40000),
            timeout: Duration::from_secs(5),
        }
    }
}

#[async_trait]
impl LivenessProbe for DnsLivenessProbe {
    async fn is_alive(&self, transport: &Arc<dyn Transport>, session: &Session) -> bool {
        let pkt = crate::udpip::wrap(self.client, self.resolver, &dns_query("example.com"));
        if transport.send(session, IpPacket::new(pkt)).await.is_err() {
            return false;
        }
        // Any inbound packet within the window means the data path is live.
        matches!(tokio::time::timeout(self.timeout, transport.recv(session)).await, Ok(Ok(_)))
    }
}

/// Build a minimal DNS A-record query (recursion desired). The answer is irrelevant — we only
/// need a packet that elicits *some* response.
fn dns_query(name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(name.len() + 18);
    q.extend_from_slice(&[0x13, 0x37]); // transaction id
    q.extend_from_slice(&[0x01, 0x00]); // flags: recursion desired
    q.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // an/ns/ar counts = 0
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root label
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    q
}

/// The transport that won a cascade, plus its session.
type Winner = (Arc<dyn Transport>, Session);

/// Adapts a [`Cascade`] to the [`Transport`] seam so the datapath drives it like any single
/// transport: `connect` runs the cascade and remembers the rung that won; `send`/`recv`/`close`/
/// `tunnel_mtu` delegate to that winning rung's session.
pub struct CascadeTransport {
    cascade: Cascade,
    winners: Mutex<HashMap<SessionId, Winner>>,
    next_id: AtomicU64,
}

impl CascadeTransport {
    pub fn new(cascade: Cascade) -> Self {
        Self { cascade, winners: Mutex::new(HashMap::new()), next_id: AtomicU64::new(0) }
    }

    fn winner(&self, session: &Session) -> Result<Winner> {
        self.winners
            .lock()
            .map_err(|_| Error::Transport("cascade map poisoned".into()))?
            .get(&session.id)
            .cloned()
            .ok_or(Error::SessionNotFound(session.id))
    }
}

#[async_trait]
impl Transport for CascadeTransport {
    async fn connect(&self, target: NodeEndpoint, creds: Grant) -> Result<Session> {
        let (transport, inner) = self.cascade.connect(target, creds).await?;
        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let kind = transport.kind();
        self.winners
            .lock()
            .map_err(|_| Error::Transport("cascade map poisoned".into()))?
            .insert(id, (transport, inner));
        Ok(Session { id, kind })
    }

    async fn send(&self, session: &Session, packet: IpPacket) -> Result<()> {
        let (t, inner) = self.winner(session)?;
        t.send(&inner, packet).await
    }

    async fn recv(&self, session: &Session) -> Result<IpPacket> {
        let (t, inner) = self.winner(session)?;
        t.recv(&inner).await
    }

    async fn close(&self, session: Session) -> Result<()> {
        let (t, inner) = {
            let mut map = self
                .winners
                .lock()
                .map_err(|_| Error::Transport("cascade map poisoned".into()))?;
            map.remove(&session.id).ok_or(Error::SessionNotFound(session.id))?
        };
        t.close(inner).await
    }

    fn kind(&self) -> TransportKind {
        // Nominal before a rung wins; the established session carries the winner's kind.
        TransportKind::Masque
    }

    fn fingerprint_profile(&self) -> Profile {
        Profile::HttpsQuic
    }

    fn tunnel_mtu(&self, session: &Session) -> Option<usize> {
        let (t, inner) = self.winner(session).ok()?;
        t.tunnel_mtu(&inner)
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
// The cascade-local scaffolds above (`AmneziaWgTransport`, `WstunnelTransport`, and this
// `RealityTransport`) are thin placeholders that carry the right `kind()`/`fingerprint_profile()`
// and slot into the cascade for the step-down tests; the REAL transports live in their own modules
// behind feature flags ([`crate::amneziawg`], [`crate::wstunnel`], [`crate::reality`]) and are what
// a deployment actually wires into a [`Cascade`]. They share only the `TransportKind`, never the
// type, so there is no name conflict. See [`crate::reality`] for which REALITY properties the real
// rung does / does not yet achieve.
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

    /// A transport whose `connect` hangs forever — simulates a DPI block that drops the
    /// handshake instead of refusing it.
    struct Hangs(TransportKind);
    #[async_trait]
    impl Transport for Hangs {
        async fn connect(&self, _t: NodeEndpoint, _c: Grant) -> Result<Session> {
            std::future::pending::<()>().await; // never resolves
            unreachable!()
        }
        async fn send(&self, _s: &Session, _p: IpPacket) -> Result<()> { Err(Error::Closed) }
        async fn recv(&self, _s: &Session) -> Result<IpPacket> { Err(Error::Closed) }
        async fn close(&self, _s: Session) -> Result<()> { Ok(()) }
        fn kind(&self) -> TransportKind { self.0 }
        fn fingerprint_profile(&self) -> Profile { Profile::Internal }
    }

    #[tokio::test]
    async fn times_out_a_hanging_rung_and_steps_down() {
        // MASQUE hangs (DPI drops the handshake) → after the timeout, step down to wstunnel.
        let cascade = Cascade::new(vec![
            Arc::new(Hangs(TransportKind::Masque)),
            Arc::new(Working(TransportKind::Wstunnel)),
        ])
        .with_connect_timeout(Duration::from_millis(50));
        let (t, _s) = cascade
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("times out the hanging rung and lands on the next");
        assert_eq!(t.kind(), TransportKind::Wstunnel);
    }

    /// A probe that deems a rung alive only if its session kind matches.
    struct AliveIf(TransportKind);
    #[async_trait]
    impl LivenessProbe for AliveIf {
        async fn is_alive(&self, _t: &Arc<dyn Transport>, s: &Session) -> bool {
            s.kind == self.0
        }
    }

    #[tokio::test]
    async fn steps_down_a_rung_that_connects_but_is_dead() {
        // Both rungs "connect", but the probe says only wstunnel actually carries traffic, so the
        // cascade must reject the handshake-only MASQUE rung and step down.
        let cascade = Cascade::new(vec![
            Arc::new(Working(TransportKind::Masque)),
            Arc::new(Working(TransportKind::Wstunnel)),
        ])
        .with_liveness_probe(Arc::new(AliveIf(TransportKind::Wstunnel)));
        let (t, _s) = cascade
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("steps down past the dead rung");
        assert_eq!(t.kind(), TransportKind::Wstunnel, "rejected the connected-but-dead MASQUE rung");
    }

    #[tokio::test]
    async fn errors_when_all_rungs_connect_but_are_dead() {
        // Every rung handshakes but none carries traffic → no session, kill-switch holds.
        let cascade = Cascade::new(vec![
            Arc::new(Working(TransportKind::Masque)),
            Arc::new(Working(TransportKind::Wstunnel)),
        ])
        .with_liveness_probe(Arc::new(AliveIf(TransportKind::Reality))); // never matches
        assert!(cascade.connect(NodeEndpoint::loopback(), Grant::mock()).await.is_err());
    }

    /// An in-process echo transport: `recv` returns whatever was last `send`, tagged with the
    /// rung's kind in byte 0 so a test can prove which rung actually carried the packet. Used to
    /// drive the `CascadeTransport` seam end-to-end after a step-down.
    struct Echo(TransportKind, std::sync::Mutex<Option<Vec<u8>>>);
    impl Echo {
        fn new(kind: TransportKind) -> Self {
            Self(kind, std::sync::Mutex::new(None))
        }
    }
    #[async_trait]
    impl Transport for Echo {
        async fn connect(&self, _t: NodeEndpoint, _c: Grant) -> Result<Session> {
            Ok(Session { id: SessionId(1), kind: self.0 })
        }
        async fn send(&self, _s: &Session, p: IpPacket) -> Result<()> {
            let mut buf = p.into_bytes();
            buf.insert(0, self.0 as u8); // tag with the rung that carried it
            *self.1.lock().expect("echo lock") = Some(buf);
            Ok(())
        }
        async fn recv(&self, _s: &Session) -> Result<IpPacket> {
            self.1
                .lock()
                .expect("echo lock")
                .take()
                .map(IpPacket::new)
                .ok_or(Error::Closed)
        }
        async fn close(&self, _s: Session) -> Result<()> { Ok(()) }
        fn kind(&self) -> TransportKind { self.0 }
        fn fingerprint_profile(&self) -> Profile { Profile::Internal }
    }

    #[tokio::test]
    async fn cascade_transport_routes_traffic_through_the_rung_that_won() {
        // MASQUE is blocked; the cascade steps down to the wstunnel echo rung. Driving the
        // CascadeTransport seam (connect → send → recv) must route through THAT rung — proving the
        // adapter binds the session to the winner, not just that connect picked one.
        let cascade = Cascade::new(vec![
            Arc::new(Blocked(TransportKind::Masque)),
            Arc::new(Echo::new(TransportKind::Wstunnel)),
        ]);
        let ct = CascadeTransport::new(cascade);
        let session = ct
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("cascade lands on the working rung");
        assert_eq!(session.kind, TransportKind::Wstunnel, "session carries the winner's kind");

        ct.send(&session, IpPacket::new(vec![0xAA, 0xBB]))
            .await
            .expect("send routes to the winning rung");
        let got = ct.recv(&session).await.expect("recv routes to the winning rung");
        assert_eq!(
            got.as_bytes(),
            &[TransportKind::Wstunnel as u8, 0xAA, 0xBB],
            "the wstunnel rung (not the blocked MASQUE rung) carried the packet"
        );

        // After close, the session is gone and the seam reports SessionNotFound (no dangling rung).
        ct.close(session).await.expect("close tears down the winner");
        assert!(matches!(
            ct.send(&session, IpPacket::new(vec![0])).await,
            Err(Error::SessionNotFound(_))
        ));
    }

    #[test]
    fn dns_query_is_well_formed() {
        let q = dns_query("example.com");
        assert_eq!(&q[0..2], &[0x13, 0x37], "transaction id");
        assert_eq!(&q[4..6], &[0x00, 0x01], "one question");
        // 12-byte header + 1+7 "example" + 1+3 "com" + 1 root + 2 qtype + 2 qclass = 29 bytes.
        assert_eq!(q.len(), 29);
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x01, 0x00, 0x01], "QTYPE=A QCLASS=IN");
    }
}
