//! Network-aware transport **selector** (architecture spec §4.3, the dual-path refinement of the
//! obfuscation cascade). Before any tunnel is built the client takes one cheap, identity-free look
//! at the network and picks a rung *order*:
//!
//! ```text
//! probe UDP/QUIC reachability to the node
//!     │
//!     ├─ Clean   → fast path first  [ MASQUE / PQ-WG-over-MASQUE , AmneziaWG ]  (speed)
//!     │            then the resistant tail appended underneath
//!     └─ Hostile → resistant path   [ REALITY , wstunnel , MASQUE ]            (survival)
//!        Unknown → treated as Hostile (fail toward survival)
//! ```
//!
//! Two invariants make this safe:
//!   1. **The resistant rungs are ALWAYS the tail.** Even on a "clean" guess they sit underneath the
//!      fast rungs, so a wrong guess (a fast rung that handshakes then gets dropped) *steps down*
//!      into them — it never hard-fails. A misclassification costs a little latency, never
//!      connectivity.
//!   2. **The probe carries no user identity** (PD-1/PD-3). It is one UDP datagram that looks like
//!      the start of an ordinary QUIC connection; it embeds no token, account, or destination, and
//!      its result (a 3-value [`PathClass`]) is held in memory only and never logged with anything
//!      user-linkable.
//!
//! The selector reuses the existing [`Cascade`] machinery wholesale: [`Selector::build_cascade`]
//! probes, orders the rungs, and hands back a `Cascade` (with the DNS liveness probe attached) that
//! behaves exactly like the static one. [`SelectorTransport`] adapts it to the [`Transport`] seam,
//! mirroring [`crate::cascade::CascadeTransport`] — so the datapath drives it like any single
//! transport and the `Transport` trait is untouched.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use nil_core::{Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind};
use tokio::net::UdpSocket;

use crate::cascade::{Cascade, DnsLivenessProbe};
use crate::Transport;

/// How a probe classifies the path to a node before any tunnel exists. `Unknown` is explicit (a
/// probe that could not reach a verdict) rather than a guess; [`PathClass::coerce`] folds it to
/// `Hostile` wherever a rung order is chosen, so an ambiguous network never skips the resistant
/// rungs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathClass {
    /// UDP/QUIC reaches the node — the fast path is worth trying first.
    Clean,
    /// UDP/QUIC appears blocked — lead with the censorship-resistant rungs.
    Hostile,
    /// The probe could not classify (couldn't send, ambiguous). Folded to `Hostile`.
    Unknown,
}

impl PathClass {
    /// Fail toward survival: anything not provably `Clean` becomes `Hostile`.
    pub fn coerce(self) -> PathClass {
        match self {
            PathClass::Clean => PathClass::Clean,
            PathClass::Hostile | PathClass::Unknown => PathClass::Hostile,
        }
    }
}

/// Classifies the network path to a node **without carrying any user identity**. The verdict is a
/// hint for rung ordering, never a gate — the resistant rungs are always retained — so a wrong
/// verdict only costs a little latency.
#[async_trait]
pub trait NetworkProbe: Send + Sync {
    async fn classify(&self, target: &NodeEndpoint) -> PathClass;
}

/// Default probe budget: one small UDP round-trip. Short enough not to stall `connect`, long enough
/// to catch a working path on a slow mobile link.
pub const DEFAULT_PROBE_BUDGET: Duration = Duration::from_millis(800);

/// QUIC pads a connection's first datagram to at least 1200 bytes; the probe matches that so it
/// looks like the start of an ordinary QUIC connection rather than a novel packet shape.
const PROBE_DATAGRAM_LEN: usize = 1200;

/// Varies the probe's connection IDs across calls (so repeated probes aren't byte-identical) without
/// pulling a CSPRNG dependency. The value is a connection-ID tag only — it carries no user identity.
static PROBE_NONCE: AtomicU64 = AtomicU64::new(0);

/// An identity-free UDP reachability probe. It sends ONE QUIC **Version-Negotiation-eliciting**
/// datagram (a long-header packet naming an unsupported QUIC version) to the node's UDP port. Per
/// RFC 9000 §6 a server that doesn't support the version MUST answer with a Version Negotiation
/// packet — so *any* reply within the budget proves UDP/QUIC traverses to the node (`Clean`).
/// Silence ⇒ `Hostile` (a censor is likely dropping it); an un-sendable socket ⇒ `Unknown`.
///
/// Why not a zeroed datagram: a real QUIC node silently drops junk, so a zeroed probe would
/// mis-classify every clean network as hostile. A version-negotiation trigger is the lightest packet
/// a conformant QUIC server is *required* to answer.
pub struct UdpReachabilityProbe {
    budget: Duration,
}

impl Default for UdpReachabilityProbe {
    fn default() -> Self {
        Self { budget: DEFAULT_PROBE_BUDGET }
    }
}

impl UdpReachabilityProbe {
    /// Probe with a custom budget (tests use a short one).
    pub fn with_budget(budget: Duration) -> Self {
        Self { budget }
    }
}

#[async_trait]
impl NetworkProbe for UdpReachabilityProbe {
    async fn classify(&self, target: &NodeEndpoint) -> PathClass {
        // NB: never log target.host/port here — PD-3.
        let class = match run_udp_probe(&target.host, target.port, self.budget).await {
            ProbeOutcome::Reply => PathClass::Clean,
            ProbeOutcome::Silent => PathClass::Hostile,
            ProbeOutcome::Unsendable => PathClass::Unknown,
        };
        tracing::debug!(?class, "selector network probe");
        class
    }
}

enum ProbeOutcome {
    Reply,
    Silent,
    Unsendable,
}

async fn run_udp_probe(host: &str, port: u16, budget: Duration) -> ProbeOutcome {
    let Ok(sock) = UdpSocket::bind(("0.0.0.0", 0)).await else {
        return ProbeOutcome::Unsendable;
    };
    if sock.connect((host, port)).await.is_err() {
        return ProbeOutcome::Unsendable;
    }
    if sock.send(&quic_version_negotiation_trigger()).await.is_err() {
        return ProbeOutcome::Unsendable;
    }
    let mut buf = [0u8; 2048];
    match tokio::time::timeout(budget, sock.recv(&mut buf)).await {
        Ok(Ok(_)) => ProbeOutcome::Reply,
        // An ICMP-driven socket error (e.g. port unreachable) means *something* answered but not a
        // usable QUIC endpoint; treat as silent (not clean) — conservative, fail toward survival.
        Ok(Err(_)) => ProbeOutcome::Silent,
        Err(_elapsed) => ProbeOutcome::Silent,
    }
}

/// Build a long-header QUIC packet that names an unsupported version, padded to the QUIC Initial
/// minimum. A conformant server answers with a Version Negotiation packet (RFC 9000 §6). Carries no
/// user-identifying bytes — only a per-call connection-ID tag.
fn quic_version_negotiation_trigger() -> Vec<u8> {
    // Connection IDs: seed from the OS CSPRNG once (so probes don't start at all-zero CIDs), then
    // give the DCID and SCID DISTINCT values per probe. A conformant QUIC client never reuses one
    // value for both, so identical CIDs would be a NIL-probe fingerprint a censor could match
    // (PD-3: the probe must look like an ordinary QUIC connection start). RFC 9000 §6: any
    // unsupported version elicits a Version Negotiation reply regardless of the CIDs.
    static CID_SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let base = *CID_SEED.get_or_init(|| {
        let mut b = [0u8; 8];
        let _ = getrandom::getrandom(&mut b); // best-effort entropy; CIDs aren't a secret
        u64::from_be_bytes(b)
    });
    let n = PROBE_NONCE.fetch_add(2, Ordering::Relaxed);
    let dcid = base.wrapping_add(n).to_be_bytes();
    let scid = base.wrapping_add(n).wrapping_add(1).to_be_bytes(); // DCID != SCID

    let mut p = vec![0u8; PROBE_DATAGRAM_LEN];
    p[0] = 0xC0 | 0x03; // long header form + fixed bit
    p[1..5].copy_from_slice(&[0x1a, 0x2a, 0x3a, 0x4a]); // an unsupported version (never 0x00000000)
    p[5] = 8; // DCID length
    p[6..14].copy_from_slice(&dcid);
    p[14] = 8; // SCID length
    p[15..23].copy_from_slice(&scid);
    // bytes 23.. stay zero (padding to the Initial minimum)
    p
}

/// The network-aware selector: a probe plus a `fast` and a `resistant` ordered rung set. The
/// resistant set is always the tail (see the module invariants). Holds the last probe verdict for
/// UI diagnostics — transport-class only, never anything user-linkable.
pub struct Selector {
    probe: Arc<dyn NetworkProbe>,
    fast: Vec<Arc<dyn Transport>>,
    resistant: Vec<Arc<dyn Transport>>,
    last_class: Mutex<Option<PathClass>>,
}

impl Selector {
    /// `fast` leads only on a `Clean` path; `resistant` is always appended as the tail (and is the
    /// whole list on a `Hostile`/`Unknown` path).
    pub fn new(
        probe: Arc<dyn NetworkProbe>,
        fast: Vec<Arc<dyn Transport>>,
        resistant: Vec<Arc<dyn Transport>>,
    ) -> Self {
        Self { probe, fast, resistant, last_class: Mutex::new(None) }
    }

    /// Probe the path and build the ordered [`Cascade`] (with the DNS liveness probe attached). On
    /// `Clean`, the fast rungs lead and the resistant rungs follow as the tail; otherwise only the
    /// resistant rungs are used. The liveness probe means a rung that handshakes-then-drops is
    /// rejected and the cascade steps down.
    pub async fn build_cascade(&self, target: &NodeEndpoint) -> Cascade {
        let class = self.probe.classify(target).await.coerce();
        if let Ok(mut g) = self.last_class.lock() {
            *g = Some(class);
        }
        let mut rungs: Vec<Arc<dyn Transport>> =
            Vec::with_capacity(self.fast.len() + self.resistant.len());
        if class == PathClass::Clean {
            rungs.extend(self.fast.iter().cloned());
        }
        rungs.extend(self.resistant.iter().cloned());
        // `class` is a coarse network-shape verdict (Clean/Hostile/Unknown) with NO user identity in
        // it — safe to log (architecture §4.3). It only orders the cascade rungs; it never gates, and
        // the resistant rungs are always retained regardless.
        tracing::info!(?class, rungs = rungs.len(), "selector built cascade");
        Cascade::new(rungs).with_liveness_probe(Arc::new(DnsLivenessProbe::default()))
    }

    /// The last probe verdict, for UI diagnostics. `None` until the first `build_cascade`.
    /// Transport-class only — never user-identifying.
    pub fn selected_class(&self) -> Option<PathClass> {
        self.last_class.lock().ok().and_then(|g| *g)
    }
}

/// The transport that won the selector's cascade, plus its session.
type Winner = (Arc<dyn Transport>, Session);

/// Adapts a [`Selector`] to the [`Transport`] seam, mirroring [`crate::cascade::CascadeTransport`]:
/// `connect` probes, builds the ordered cascade, runs it, and remembers the rung that won;
/// `send`/`recv`/`close`/`tunnel_mtu` delegate to that winner's session.
pub struct SelectorTransport {
    selector: Selector,
    winners: Mutex<HashMap<SessionId, Winner>>,
    next_id: AtomicU64,
}

impl SelectorTransport {
    pub fn new(selector: Selector) -> Self {
        Self { selector, winners: Mutex::new(HashMap::new()), next_id: AtomicU64::new(0) }
    }

    fn winner(&self, session: &Session) -> Result<Winner> {
        self.winners
            .lock()
            .map_err(|_| Error::Transport("selector map poisoned".into()))?
            .get(&session.id)
            .cloned()
            .ok_or(Error::SessionNotFound(session.id))
    }

    /// The path class the probe chose for the last connect (UI diagnostics; never user-linkable).
    pub fn selected_class(&self) -> Option<PathClass> {
        self.selector.selected_class()
    }

    /// The [`TransportKind`] of the rung that actually won this session (UI diagnostics).
    pub fn winning_kind(&self, session: &Session) -> Option<TransportKind> {
        self.winner(session).ok().map(|(t, _)| t.kind())
    }
}

#[async_trait]
impl Transport for SelectorTransport {
    async fn connect(&self, target: NodeEndpoint, creds: Grant) -> Result<Session> {
        let cascade = self.selector.build_cascade(&target).await;
        let (transport, inner) = cascade.connect(target, creds).await?;
        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let kind = transport.kind();
        self.winners
            .lock()
            .map_err(|_| Error::Transport("selector map poisoned".into()))?
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
                .map_err(|_| Error::Transport("selector map poisoned".into()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe that returns a fixed verdict (no network).
    struct FixedProbe(PathClass);
    #[async_trait]
    impl NetworkProbe for FixedProbe {
        async fn classify(&self, _t: &NodeEndpoint) -> PathClass {
            self.0
        }
    }

    /// A rung that always fails to connect.
    struct Blocked(TransportKind);
    #[async_trait]
    impl Transport for Blocked {
        async fn connect(&self, _t: NodeEndpoint, _c: Grant) -> Result<Session> {
            Err(Error::Transport("blocked".into()))
        }
        async fn send(&self, _s: &Session, _p: IpPacket) -> Result<()> { Err(Error::Closed) }
        async fn recv(&self, _s: &Session) -> Result<IpPacket> { Err(Error::Closed) }
        async fn close(&self, _s: Session) -> Result<()> { Ok(()) }
        fn kind(&self) -> TransportKind { self.0 }
        fn fingerprint_profile(&self) -> Profile { Profile::Internal }
    }

    /// A rung that connects and answers `recv` (so it passes the DNS liveness probe).
    struct Live(TransportKind);
    #[async_trait]
    impl Transport for Live {
        async fn connect(&self, _t: NodeEndpoint, _c: Grant) -> Result<Session> {
            Ok(Session { id: SessionId(7), kind: self.0 })
        }
        async fn send(&self, _s: &Session, _p: IpPacket) -> Result<()> { Ok(()) }
        async fn recv(&self, _s: &Session) -> Result<IpPacket> { Ok(IpPacket::new(vec![0u8])) }
        async fn close(&self, _s: Session) -> Result<()> { Ok(()) }
        fn kind(&self) -> TransportKind { self.0 }
        fn fingerprint_profile(&self) -> Profile { Profile::Internal }
    }

    fn live(kind: TransportKind) -> Arc<dyn Transport> { Arc::new(Live(kind)) }

    #[test]
    fn unknown_coerces_to_hostile() {
        assert_eq!(PathClass::Unknown.coerce(), PathClass::Hostile);
        assert_eq!(PathClass::Hostile.coerce(), PathClass::Hostile);
        assert_eq!(PathClass::Clean.coerce(), PathClass::Clean);
    }

    fn selector_with(probe: PathClass) -> Selector {
        Selector::new(
            Arc::new(FixedProbe(probe)),
            vec![live(TransportKind::Masque), live(TransportKind::AmneziaWg)],
            vec![live(TransportKind::Reality), live(TransportKind::Wstunnel)],
        )
    }

    #[tokio::test]
    async fn clean_leads_fast_then_appends_resistant_tail() {
        let s = selector_with(PathClass::Clean);
        let kinds = s.build_cascade(&NodeEndpoint::loopback()).await.rung_kinds();
        assert_eq!(
            kinds,
            vec![
                TransportKind::Masque,
                TransportKind::AmneziaWg,
                TransportKind::Reality,
                TransportKind::Wstunnel,
            ],
            "clean: fast rungs first, resistant tail appended"
        );
        assert_eq!(s.selected_class(), Some(PathClass::Clean));
    }

    #[tokio::test]
    async fn hostile_uses_only_the_resistant_rungs() {
        let s = selector_with(PathClass::Hostile);
        let kinds = s.build_cascade(&NodeEndpoint::loopback()).await.rung_kinds();
        assert_eq!(kinds, vec![TransportKind::Reality, TransportKind::Wstunnel]);
        assert_eq!(s.selected_class(), Some(PathClass::Hostile));
    }

    #[tokio::test]
    async fn unknown_probe_is_treated_like_hostile() {
        let s = selector_with(PathClass::Unknown);
        let kinds = s.build_cascade(&NodeEndpoint::loopback()).await.rung_kinds();
        assert_eq!(
            kinds,
            vec![TransportKind::Reality, TransportKind::Wstunnel],
            "unknown coerces to hostile: no fast rungs"
        );
        // The verdict recorded is the coerced one.
        assert_eq!(s.selected_class(), Some(PathClass::Hostile));
    }

    #[tokio::test]
    async fn clean_guess_with_dead_fast_rung_steps_into_resistant_tail() {
        // Probe says Clean, but the fast rung is blocked; the cascade must step down into the
        // appended resistant tail and still connect — a wrong guess costs latency, not connectivity.
        let selector = Selector::new(
            Arc::new(FixedProbe(PathClass::Clean)),
            vec![Arc::new(Blocked(TransportKind::Masque))],
            vec![live(TransportKind::Wstunnel)],
        );
        let st = SelectorTransport::new(selector);
        let session = st
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("steps down into the resistant tail");
        assert_eq!(session.kind, TransportKind::Wstunnel, "won via the resistant rung");
        assert_eq!(st.selected_class(), Some(PathClass::Clean), "diagnostics expose the probe verdict");
        assert_eq!(st.winning_kind(&session), Some(TransportKind::Wstunnel));

        // Close tears the winner down; the seam then reports SessionNotFound (no dangling rung).
        st.close(session).await.expect("close tears down the winner");
        assert!(matches!(
            st.send(&session, IpPacket::new(vec![0])).await,
            Err(Error::SessionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn hostile_path_connects_through_a_resistant_rung() {
        let selector = Selector::new(
            Arc::new(FixedProbe(PathClass::Hostile)),
            vec![Arc::new(Blocked(TransportKind::Masque))], // never tried on a hostile path
            vec![live(TransportKind::Reality)],
        );
        let st = SelectorTransport::new(selector);
        let session = st
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("hostile path connects via the resistant rung");
        assert_eq!(session.kind, TransportKind::Reality);
    }

    #[test]
    fn version_negotiation_trigger_is_well_formed() {
        let p = quic_version_negotiation_trigger();
        assert_eq!(p.len(), PROBE_DATAGRAM_LEN, "padded to the QUIC Initial minimum");
        assert_eq!(p[0] & 0x80, 0x80, "long header form bit set");
        assert_eq!(p[0] & 0x40, 0x40, "fixed bit set");
        assert_ne!(&p[1..5], &[0, 0, 0, 0], "version is not 0x00000000 (which would be VN itself)");
        assert_eq!(p[5], 8, "DCID length");
        assert_eq!(p[14], 8, "SCID length");
        // DCID and SCID must DIFFER (a conformant client never reuses one for both) so the probe
        // isn't a NIL-specific fingerprint.
        assert_ne!(&p[6..14], &p[15..23], "DCID and SCID must differ (RFC 9000; anti-fingerprint)");
    }
}
