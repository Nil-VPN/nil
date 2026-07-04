//! Inner PQ-WireGuard crypto core (architecture spec §4.2): a `boringtun` Noise tunnel keyed
//! by the `nil-crypto` post-quantum hybrid PSK (ML-KEM-1024 + Classic McEliece 460896). The
//! tunnel is safe if *either* the classical X25519 Noise handshake or the PQ PSK holds.
//!
//! [`PqWgCore`] is the reusable building block: it owns one `Tunn`, seeded with the hybrid PSK,
//! and exposes socket-agnostic handshake / encapsulate / decapsulate steps. A full
//! `Transport` wrapper that carries these over an inner MASQUE tunnel (and the matching node
//! responder) is the remaining integration — it shares this core with the Phase 4 AmneziaWG
//! transport, so the crypto lives here once. The PQ PSK exchange itself is in
//! [`nil_crypto::psk`]; here we just consume the derived [`Psk`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use nil_core::{
    Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind,
};
use nil_crypto::psk::{PqCiphertexts, PqInitiator, Psk};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{MasqueTransport, Transport};

/// PQ handshake timeout (KEM exchange + WireGuard Noise handshake over the inner tunnel).
const PQWG_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// A WireGuard static X25519 keypair.
pub struct WgKeypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl WgKeypair {
    /// Generate a fresh keypair from the OS CSPRNG (via `getrandom`, avoiding an rand_core
    /// version pin).
    pub fn generate() -> std::io::Result<Self> {
        use zeroize::Zeroize;
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| std::io::Error::other(format!("wg key entropy: {e}")))?;
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        // `StaticSecret` self-zeroizes on drop, but the raw `bytes` seed is a plain [u8;32] Copy that
        // `StaticSecret::from` copied out of — scrub it so no un-zeroized copy of the private scalar
        // lingers on the stack (matches the crate's Zeroizing discipline; PD-2).
        bytes.zeroize();
        Ok(Self { secret, public })
    }
}

/// The result of feeding one inbound WireGuard datagram to [`PqWgCore::decapsulate`].
#[derive(Debug)]
pub enum WgStep {
    /// A decapsulated inner IP packet to hand to the TUN.
    Ip(Vec<u8>),
    /// A WireGuard control datagram (handshake response, keepalive, cookie) to send back.
    Network(Vec<u8>),
    /// Nothing to do.
    Done,
    /// WireGuard rejected the datagram (e.g. PSK mismatch, replay, bad MAC).
    Err(WireGuardError),
}

/// One end of a PQ-keyed WireGuard tunnel.
pub struct PqWgCore {
    tunn: Tunn,
}

impl PqWgCore {
    /// Build a tunnel end: our static secret, the peer's static public, and the hybrid PSK
    /// (mixed into the Noise IKpsk2 handshake). `index` disambiguates concurrent sessions.
    pub fn new(my_secret: StaticSecret, peer_public: PublicKey, psk: &Psk, index: u32) -> Self {
        let tunn = Tunn::new(my_secret, peer_public, Some(*psk.as_bytes()), Some(25), index, None);
        Self { tunn }
    }

    /// Build a tunnel end with **no** preshared key — classical WireGuard (X25519 Noise only).
    /// Used by the AmneziaWG cascade rung (a censorship fallback): its PQ hybrid PSK exchange
    /// (the ~512 KiB McEliece offer) needs a reliable channel the raw-UDP rung doesn't have, so
    /// for now the rung's security is WireGuard + obfuscation. The default MASQUE transport stays
    /// PQ-by-default. TODO: a reliable-UDP sublayer to carry the offer so the fallback is PQ too.
    pub fn without_psk(my_secret: StaticSecret, peer_public: PublicKey, index: u32) -> Self {
        let tunn = Tunn::new(my_secret, peer_public, None, Some(25), index, None);
        Self { tunn }
    }

    /// Initiator: produce the first handshake datagram to send to the peer.
    pub fn handshake_init(&mut self) -> std::result::Result<Vec<u8>, WireGuardError> {
        let mut dst = vec![0u8; 2048];
        match self.tunn.format_handshake_initiation(&mut dst, false) {
            TunnResult::WriteToNetwork(p) => Ok(p.to_vec()),
            TunnResult::Err(e) => Err(e),
            _ => Err(WireGuardError::ConnectionExpired),
        }
    }

    /// Feed one inbound WireGuard datagram; returns what to do next.
    pub fn decapsulate(&mut self, datagram: &[u8]) -> WgStep {
        let mut dst = vec![0u8; 65535];
        match self.tunn.decapsulate(None, datagram, &mut dst) {
            TunnResult::WriteToNetwork(p) => WgStep::Network(p.to_vec()),
            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => WgStep::Ip(p.to_vec()),
            TunnResult::Done => WgStep::Done,
            TunnResult::Err(e) => WgStep::Err(e),
        }
    }

    /// Encapsulate an inner IP packet into a WireGuard transport datagram for the peer.
    pub fn encapsulate(&mut self, ip: &[u8]) -> std::result::Result<Vec<u8>, WireGuardError> {
        let mut dst = vec![0u8; ip.len() + 32];
        match self.tunn.encapsulate(ip, &mut dst) {
            TunnResult::WriteToNetwork(p) => Ok(p.to_vec()),
            TunnResult::Err(e) => Err(e),
            // `Done` here means the packet was queued pending a handshake — caller should have
            // completed the handshake first.
            _ => Err(WireGuardError::ConnectionExpired),
        }
    }

    /// Drive periodic WireGuard timers (rekey, keepalive, handshake retransmit). Returns a
    /// datagram to send if the timers produced one.
    pub fn tick(&mut self) -> Option<Vec<u8>> {
        let mut dst = vec![0u8; 2048];
        match self.tunn.update_timers(&mut dst) {
            TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
            _ => None,
        }
    }
}

// ---- The nested transport: PQ-WireGuard carried inside a MASQUE tunnel --------------------

const PUMP_QUEUE: usize = 1024;

/// Length-prefix (`u32` BE) each part and concatenate — the control-message framing for the
/// PQ handshake over the MASQUE control channel. Public so the node responder uses the exact
/// same codec (anti-drift).
pub fn encode_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// Largest single part `decode_parts` will allocate. The biggest legitimate part is the Classic
/// McEliece-460896 public key (~512 KiB) carried in a PQ offer; cap at that + slack so a hostile
/// length prefix can't drive a huge per-part allocation. This matters because `decode_parts` runs
/// directly on raw WebSocket frames in the wstunnel rung, where the (large default) frame size is
/// otherwise the only bound. Derived from the KEM constant so it tracks the parameters.
const MAX_PART: usize = nil_crypto::psk::MCELIECE_PK_LEN + 4096;

pub fn decode_parts(mut b: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut parts = Vec::new();
    while !b.is_empty() {
        if b.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        // Reject an over-large part before allocating it (fail-closed on a hostile length prefix).
        if len > MAX_PART {
            return None;
        }
        b = &b[4..];
        if b.len() < len {
            return None;
        }
        parts.push(b[..len].to_vec());
        b = &b[len..];
    }
    Some(parts)
}

struct PqWgSession {
    inner_session: Session,
    to_wire: mpsc::Sender<IpPacket>,
    from_wire: AsyncMutex<mpsc::Receiver<IpPacket>>,
    shutdown: CancellationToken,
    _driver: JoinHandle<()>,
}

/// Inner PQ-WireGuard over an outer MASQUE tunnel (architecture spec §4.2). Implements the
/// `Transport` seam, so the datapath/cascade use it exactly like plain MASQUE — it just adds a
/// post-quantum WireGuard crypto core *inside* the QUIC datagrams (the wire stays HTTPS/QUIC).
///
/// `connect`: bring up the inner MASQUE tunnel (attested) → exchange the PQ hybrid PSK over the
/// reliable control channel → run the WireGuard Noise handshake over the datagram channel →
/// pump IP packets through `Tunn` encapsulate/decapsulate.
pub struct PqWgTransport {
    inner: Arc<MasqueTransport>,
    sessions: Mutex<HashMap<SessionId, Arc<PqWgSession>>>,
    next_id: AtomicU64,
}

impl PqWgTransport {
    pub fn new(inner: Arc<MasqueTransport>) -> Self {
        Self { inner, sessions: Mutex::new(HashMap::new()), next_id: AtomicU64::new(0) }
    }

    fn state(&self, session: &Session) -> Result<Arc<PqWgSession>> {
        self.sessions
            .lock()
            .map_err(|_| Error::Transport("pqwg session map poisoned".into()))?
            .get(&session.id)
            .cloned()
            .ok_or(Error::SessionNotFound(session.id))
    }

    /// Usable inner-TUN MTU: the MASQUE tunnel MTU minus WireGuard's 32-byte transport overhead.
    pub fn tunnel_mtu(&self, session: &Session) -> Option<usize> {
        let s = self.state(session).ok()?;
        self.inner.tunnel_mtu(&s.inner_session).map(|m| m.saturating_sub(32))
    }
}

impl PqWgTransport {
    /// Run the PQ-WireGuard handshake + spawn the data pump over an **already-established** inner
    /// MASQUE session, registering and returning a PQ-WG session. Shared by [`Transport::connect`]
    /// (which first dials the outer MASQUE tunnel itself) and by the trust-split [`crate::path`]
    /// onion (which hands in an already-nested exit hop's MASQUE session — see spec §4.2 + §6).
    ///
    /// `node_wg_pub` is the WireGuard static public key of the node terminating `inner_session`.
    pub async fn wrap_session(
        &self,
        inner_session: Session,
        node_wg_pub: [u8; 32],
    ) -> Result<Session> {
        // PQ hybrid PSK exchange over the reliable control channel. The client (KEM initiator)
        // ships its WG static public key + both KEM public keys; the node returns the two KEM
        // ciphertexts; both derive the same PSK (which never crosses the wire).
        let (initiator, offer) = PqInitiator::generate();
        let client_kp = WgKeypair::generate().map_err(|e| Error::Transport(format!("wg keygen: {e}")))?;
        let offer_msg =
            encode_parts(&[client_kp.public.as_bytes(), &offer.mlkem_ek, &offer.mceliece_pk]);
        self.inner.control_send(&inner_session, offer_msg).await?;

        let cts_msg = tokio::time::timeout(PQWG_HANDSHAKE_TIMEOUT, self.inner.control_recv(&inner_session))
            .await
            .map_err(|_| Error::Transport("PQ handshake timed out".into()))??;
        let parts = decode_parts(&cts_msg).ok_or_else(|| Error::Transport("malformed PQ ciphertexts".into()))?;
        if parts.len() != 2 {
            return Err(Error::Transport("PQ ciphertexts: expected 2 parts".into()));
        }
        let cts = PqCiphertexts { mlkem_ct: parts[0].clone(), mceliece_ct: parts[1].clone() };
        let psk = initiator.finish(&cts).map_err(|e| Error::Transport(format!("PQ decapsulate: {e}")))?;

        // WireGuard Noise handshake (IKpsk2, the PSK mixed in) over the datagram channel.
        let mut core = PqWgCore::new(client_kp.secret, PublicKey::from(node_wg_pub), &psk, 1);
        let init = core.handshake_init().map_err(|e| Error::Transport(format!("wg init: {e:?}")))?;
        self.inner.send(&inner_session, IpPacket::new(init)).await?;
        let resp = tokio::time::timeout(PQWG_HANDSHAKE_TIMEOUT, self.inner.recv(&inner_session))
            .await
            .map_err(|_| Error::Transport("wg handshake timed out".into()))??;
        match core.decapsulate(resp.as_bytes()) {
            WgStep::Network(keepalive) => {
                self.inner.send(&inner_session, IpPacket::new(keepalive)).await?;
            }
            other => return Err(Error::Transport(format!("wg handshake failed: {other:?}"))),
        }
        tracing::info!("PQ-WireGuard tunnel established inside MASQUE");

        // Spawn the data pump (owns the Tunn).
        let (to_tx, to_rx) = mpsc::channel(PUMP_QUEUE);
        let (from_tx, from_rx) = mpsc::channel(PUMP_QUEUE);
        let shutdown = CancellationToken::new();
        let driver = tokio::spawn(pump(core, self.inner.clone(), inner_session, to_rx, from_tx, shutdown.clone()));

        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let sess = Arc::new(PqWgSession {
            inner_session,
            to_wire: to_tx,
            from_wire: AsyncMutex::new(from_rx),
            shutdown,
            _driver: driver,
        });
        self.sessions
            .lock()
            .map_err(|_| Error::Transport("pqwg session map poisoned".into()))?
            .insert(id, sess);
        // On the wire this is MASQUE/QUIC — the WireGuard layer is hidden inside the datagrams.
        Ok(Session { id, kind: TransportKind::Masque })
    }
}

#[async_trait]
impl Transport for PqWgTransport {
    async fn connect(&self, target: NodeEndpoint, creds: Grant) -> Result<Session> {
        let node_wg_pub = target
            .wg_pub
            .ok_or_else(|| Error::Transport("PqWg: endpoint carries no node WireGuard key".into()))?;

        // 1. Outer MASQUE tunnel (attestation appraised inside).
        let inner_session = self.inner.connect(target, creds).await?;
        // 2-4. PQ exchange + WG handshake + data pump over that inner session.
        self.wrap_session(inner_session, node_wg_pub).await
    }

    async fn send(&self, session: &Session, packet: IpPacket) -> Result<()> {
        let s = self.state(session)?;
        s.to_wire.send(packet).await.map_err(|_| Error::Closed)
    }

    async fn recv(&self, session: &Session) -> Result<IpPacket> {
        let s = self.state(session)?;
        let mut rx = s.from_wire.lock().await;
        rx.recv().await.ok_or(Error::Closed)
    }

    async fn close(&self, session: Session) -> Result<()> {
        let s = {
            let mut map = self
                .sessions
                .lock()
                .map_err(|_| Error::Transport("pqwg session map poisoned".into()))?;
            map.remove(&session.id)
        }
        .ok_or(Error::SessionNotFound(session.id))?;
        s.shutdown.cancel();
        self.inner.close(s.inner_session).await
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Masque // MASQUE on the wire; PQ-WireGuard is the hidden inner layer
    }

    fn fingerprint_profile(&self) -> Profile {
        Profile::HttpsQuic
    }

    fn tunnel_mtu(&self, session: &Session) -> Option<usize> {
        // Inherent method (priority over this trait method): MASQUE MTU minus WG's 32 bytes.
        PqWgTransport::tunnel_mtu(self, session)
    }

    fn assigned_ip(&self, session: &Session) -> Option<std::net::Ipv4Addr> {
        // Delegate to the underlying MASQUE session: when a PQ-WG session is used as a nesting
        // carrier (a per-hop-PQ onion), the next hop's udpip source must still be the inner node's
        // ADDRESS_ASSIGN'd per-client IP, so concurrent clients don't collide at that node.
        let s = self.state(session).ok()?;
        self.inner.assigned_ip(&s.inner_session)
    }
}

/// The data pump: app IP packets → WG encapsulate → inner MASQUE; inner MASQUE → WG
/// decapsulate → app. A 250 ms timer drives WireGuard keepalive/rekey.
async fn pump(
    mut core: PqWgCore,
    inner: Arc<MasqueTransport>,
    inner_session: Session,
    mut to_rx: mpsc::Receiver<IpPacket>,
    from_tx: mpsc::Sender<IpPacket>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            pkt = to_rx.recv() => match pkt {
                Some(ip) => {
                    if let Ok(wire) = core.encapsulate(ip.as_bytes()) {
                        if inner.send(&inner_session, IpPacket::new(wire)).await.is_err() { break; }
                    }
                }
                None => break,
            },
            wire = inner.recv(&inner_session) => match wire {
                Ok(dg) => drain_decapsulate(&mut core, &inner, &inner_session, dg.as_bytes(), &from_tx).await,
                Err(_) => break, // inner tunnel closed → kill-switch holds
            },
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                if let Some(b) = core.tick() {
                    let _ = inner.send(&inner_session, IpPacket::new(b)).await;
                }
            }
        }
    }
}

/// Feed one inbound WireGuard datagram to the core, draining follow-up control writes (the
/// `decapsulate`-then-poll-with-empty pattern boringtun requires).
async fn drain_decapsulate(
    core: &mut PqWgCore,
    inner: &Arc<MasqueTransport>,
    inner_session: &Session,
    datagram: &[u8],
    from_tx: &mpsc::Sender<IpPacket>,
) {
    let mut input = datagram.to_vec();
    loop {
        match core.decapsulate(&input) {
            WgStep::Ip(ip) => {
                let _ = from_tx.try_send(IpPacket::new(ip));
                break;
            }
            WgStep::Network(b) => {
                let _ = inner.send(inner_session, IpPacket::new(b)).await;
                input = Vec::new(); // re-poll with empty to drain any further queued writes
            }
            WgStep::Done | WgStep::Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nil_crypto::psk::{responder_encapsulate, PqInitiator};

    /// A minimal IPv4/UDP packet (header + 4-byte payload) to round-trip through the tunnel.
    fn sample_ipv4() -> Vec<u8> {
        // version/IHL, DSCP, total len(28), id, flags/frag, ttl, proto=UDP(17), checksum(0),
        // src 10.74.0.2, dst 10.74.0.1, then an 8-byte UDP header + 0 payload.
        let mut p = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
            10, 74, 0, 2, 10, 74, 0, 1,
            0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
        ];
        // fix length already 28; leave checksum 0 (boringtun doesn't validate L3 checksum).
        p.truncate(28);
        p
    }

    fn complete_handshake(client: &mut PqWgCore, node: &mut PqWgCore) {
        let init = client.handshake_init().expect("init");
        let resp = match node.decapsulate(&init) {
            WgStep::Network(b) => b,
            other => panic!("expected handshake response, got {other:?}"),
        };
        let keepalive = match client.decapsulate(&resp) {
            WgStep::Network(b) => b,
            other => panic!("expected keepalive, got {other:?}"),
        };
        match node.decapsulate(&keepalive) {
            WgStep::Done | WgStep::Network(_) => {}
            other => panic!("expected handshake completion, got {other:?}"),
        }
    }

    #[test]
    fn pq_psk_drives_a_wireguard_tunnel_and_packet_round_trips() {
        // 1. PQ hybrid PSK exchange (client = KEM initiator).
        let (initiator, offer) = PqInitiator::generate();
        let (cts, node_psk) = responder_encapsulate(&offer).expect("node encapsulate");
        let client_psk = initiator.finish(&cts).expect("client finish");
        assert_eq!(client_psk.as_bytes(), node_psk.as_bytes(), "both sides derive the same PQ PSK");

        // 2. WG static keypairs + two cores fed the same PQ PSK.
        let client_kp = WgKeypair::generate().unwrap();
        let node_kp = WgKeypair::generate().unwrap();
        let mut client = PqWgCore::new(client_kp.secret, node_kp.public, &client_psk, 1);
        let mut node = PqWgCore::new(node_kp.secret, client_kp.public, &node_psk, 2);

        // 3. Noise IKpsk2 handshake (mixes the PQ PSK).
        complete_handshake(&mut client, &mut node);

        // 4. A real IP packet survives encrypt → (wire) → decrypt.
        let ip = sample_ipv4();
        let wire = client.encapsulate(&ip).expect("encapsulate");
        match node.decapsulate(&wire) {
            WgStep::Ip(got) => assert_eq!(got, ip, "the inner IP packet survives the PQ-WG tunnel"),
            other => panic!("expected decapsulated IP, got {other:?}"),
        }
    }

    #[test]
    fn mismatched_psk_fails_the_handshake() {
        let (initiator, offer) = PqInitiator::generate();
        let (cts, _node_psk) = responder_encapsulate(&offer).expect("node encapsulate");
        let client_psk = initiator.finish(&cts).expect("client finish");

        // The node uses a DIFFERENT PSK (a fresh independent exchange) — the IKpsk2 handshake
        // must fail because the preshared key doesn't match.
        let (other_init, other_offer) = PqInitiator::generate();
        let (other_cts, _) = responder_encapsulate(&other_offer).unwrap();
        let wrong_psk = other_init.finish(&other_cts).unwrap();
        assert_ne!(client_psk.as_bytes(), wrong_psk.as_bytes());

        let client_kp = WgKeypair::generate().unwrap();
        let node_kp = WgKeypair::generate().unwrap();
        let mut client = PqWgCore::new(client_kp.secret, node_kp.public, &client_psk, 1);
        let mut node = PqWgCore::new(node_kp.secret, client_kp.public, &wrong_psk, 2);

        // In Noise IKpsk2 the PSK is mixed during the *response*, so the mismatch surfaces
        // when the initiator processes the response (or the responder rejects the init).
        let init = client.handshake_init().expect("init");
        let resp = match node.decapsulate(&init) {
            WgStep::Network(b) => b,
            WgStep::Err(_) => return, // responder rejected outright — also fine
            other => panic!("unexpected responder step {other:?}"),
        };
        assert!(
            matches!(client.decapsulate(&resp), WgStep::Err(_)),
            "a mismatched PQ PSK must make the WireGuard handshake fail"
        );
    }
}
