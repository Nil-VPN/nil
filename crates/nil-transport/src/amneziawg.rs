//! AmneziaWG-style obfuscation (architecture spec §4.3, cascade rung 2): WireGuard whose
//! on-wire bytes don't carry WireGuard's tell-tale fingerprint. Plain WireGuard is trivially
//! DPI-classified by its fixed 4-byte message-type word (`1/2/3/4`) and its fixed handshake
//! packet sizes (init **148** B, response **92** B, cookie **64** B) — the very "148/92-byte
//! fingerprint" NIL must never expose. This module hides both, reusing [`crate::pqwg::PqWgCore`]
//! for the actual crypto (so there is no new cryptography — only framing).
//!
//! Obfuscation (both ends run our code, so we define our own framing — not Amnezia
//! wire-compatible):
//!   - **Magic headers** replace the 4-byte WG type word: a distinct 4-byte `H[t]` per type
//!     `t∈{1,2,3,4}`, so the `1/2/3/4` constant disappears.
//!   - **Junk tails** of random length are appended to the *fixed-size* handshake packets, so
//!     the 148/92/64-byte sizes disappear. The receiver knows the real WG length per type and
//!     strips the tail. Data packets are already variable-length, so they get no tail.
//!   - **Junk packets**: a few random datagrams sent before the handshake. They match no magic
//!     header, so [`ObfsParams::deobfuscate`] returns `None` and the responder ignores them.
//!
//! The live UDP datapath + node responder that pump WireGuard through this codec are the
//! remaining integration; the codec + crypto composition are verified in-memory below (a full
//! WG handshake and data packet survive the round-trip, and the WG fingerprint is gone).

/// Fixed WireGuard packet lengths (bytes) by message type — the sizes a censor matches on.
const WG_LEN: [usize; 4] = [
    148, // 1: handshake initiation
    92,  // 2: handshake response
    64,  // 3: cookie reply
    0,   // 4: transport data (variable; 0 ⇒ "keep the whole body")
];

/// Obfuscation parameters shared by both ends (a deployment derives these from a shared key; the
/// defaults below are distinct, non-WireGuard 4-byte magics). `junk_*` size the pre-handshake
/// junk datagrams; `tail_*` size the junk appended to handshake packets.
#[derive(Clone, Debug)]
pub struct ObfsParams {
    /// `H[t-1]` = the 4-byte magic that replaces the WG type word for message type `t`.
    pub headers: [[u8; 4]; 4],
    /// Magic header for the **preface** packet (the client's 32-byte WG static pubkey). WireGuard
    /// responders need the initiator's static key in advance, and the raw-UDP rung has no control
    /// channel, so the client sends it in one obfuscated packet before the handshake.
    pub preface_header: [u8; 4],
    pub junk_count: usize,
    pub junk_min: usize,
    pub junk_max: usize,
    pub tail_min: usize,
    pub tail_max: usize,
}

impl Default for ObfsParams {
    fn default() -> Self {
        Self {
            // Distinct from each other and from WG's 01/02/03/04 00 00 00 type words.
            headers: [
                [0x9e, 0x21, 0xc4, 0x07],
                [0x3b, 0xd5, 0x88, 0x1a],
                [0x6f, 0x0c, 0xa3, 0xe2],
                [0xd4, 0x77, 0x19, 0x5b],
            ],
            preface_header: [0x5c, 0xa8, 0x3f, 0xd1],
            junk_count: 4,
            junk_min: 32,
            junk_max: 192,
            tail_min: 8,
            tail_max: 64,
        }
    }
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    // Best-effort entropy; on failure the buffer stays zero (still valid junk).
    let _ = getrandom::getrandom(&mut v);
    v
}

/// A length in `[min, max]` (inclusive), chosen from the OS CSPRNG. `min` if the range is empty.
fn rand_len(min: usize, max: usize) -> usize {
    if max <= min {
        return min;
    }
    let span = (max - min + 1) as u64;
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b);
    min + (u64::from_le_bytes(b) % span) as usize
}

impl ObfsParams {
    /// Obfuscate one WireGuard packet for the wire. `wg` must begin with the 4-byte WG type word.
    pub fn obfuscate(&self, wg: &[u8]) -> Vec<u8> {
        if wg.len() < 4 {
            return wg.to_vec();
        }
        let t = wg[0];
        let idx = match t {
            1..=4 => (t - 1) as usize,
            _ => {
                // Unknown type — pass through with no obfuscation (shouldn't happen from WG).
                return wg.to_vec();
            }
        };
        let mut out = Vec::with_capacity(wg.len() + self.tail_max);
        out.extend_from_slice(&self.headers[idx]); // magic header replaces the type word
        out.extend_from_slice(&wg[4..]); // the rest of the WG packet
        // Append a junk tail to the fixed-size handshake/cookie packets to erase their size tell.
        if WG_LEN[idx] != 0 {
            out.extend_from_slice(&rand_bytes(rand_len(self.tail_min, self.tail_max)));
        }
        out
    }

    /// Recover the WireGuard packet from a wire datagram, or `None` if it isn't one of ours
    /// (e.g. a junk packet) — the caller ignores `None`.
    pub fn deobfuscate(&self, wire: &[u8]) -> Option<Vec<u8>> {
        if wire.len() < 4 {
            return None;
        }
        let header = &wire[0..4];
        let idx = self.headers.iter().position(|h| h == header)?;
        let t = (idx + 1) as u8;
        let mut wg = Vec::with_capacity(wire.len());
        wg.extend_from_slice(&[t, 0, 0, 0]); // restore the WG type word
        if WG_LEN[idx] == 0 {
            // Variable-length data packet: the whole remaining body is real.
            wg.extend_from_slice(&wire[4..]);
        } else {
            // Fixed-size packet: take exactly the WG body, dropping the junk tail.
            let body = WG_LEN[idx].checked_sub(4)?;
            if wire.len() < 4 + body {
                return None; // truncated — not a valid packet of this type
            }
            wg.extend_from_slice(&wire[4..4 + body]);
        }
        Some(wg)
    }

    /// Pre-handshake junk datagrams to send before the real WireGuard initiation. They match no
    /// magic header, so the peer's `deobfuscate` drops them.
    pub fn junk_packets(&self) -> Vec<Vec<u8>> {
        (0..self.junk_count).map(|_| rand_bytes(rand_len(self.junk_min, self.junk_max))).collect()
    }

    /// Obfuscate the preface (the client's 32-byte WG static pubkey) the responder needs before
    /// the handshake. `preface_header ‖ pubkey ‖ junk-tail`.
    pub fn obfuscate_preface(&self, pubkey: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 32 + self.tail_max);
        out.extend_from_slice(&self.preface_header);
        out.extend_from_slice(pubkey);
        out.extend_from_slice(&rand_bytes(rand_len(self.tail_min, self.tail_max)));
        out
    }

    /// Recover the client's WG static pubkey from a preface packet, or `None` if `wire` isn't one.
    pub fn try_preface(&self, wire: &[u8]) -> Option<[u8; 32]> {
        if wire.len() < 4 + 32 || wire[0..4] != self.preface_header {
            return None;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&wire[4..36]);
        Some(pk)
    }
}

// ---- The AmneziaWG transport: obfuscated WireGuard directly on UDP (cascade rung 2) ---------

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boringtun::x25519::PublicKey;
use nil_core::{Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;

use crate::pqwg::{PqWgCore, WgKeypair, WgStep};
use crate::Transport;

const AWG_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AWG_QUEUE: usize = 1024;
const AWG_TICK: Duration = Duration::from_millis(250);

/// Configuration for the AmneziaWG rung.
pub struct AmneziaWgConfig {
    /// The node's WireGuard static public key.
    pub node_wg_pub: [u8; 32],
    /// Host of the node's AmneziaWG responder. `None` ⇒ use the connect target's host (the
    /// fallback rung often runs on a separate node from the MASQUE one).
    pub host: Option<String>,
    /// UDP port to reach the node's AmneziaWG responder on. `None` ⇒ use the target's port.
    pub port: Option<u16>,
    /// Obfuscation parameters (must match the node's).
    pub obfs: ObfsParams,
}

struct AwgSession {
    to_wire: mpsc::Sender<IpPacket>,
    from_wire: AsyncMutex<mpsc::Receiver<IpPacket>>,
    shutdown: CancellationToken,
    _driver: tokio::task::JoinHandle<()>,
}

/// Obfuscated WireGuard directly on UDP — the cascade's DPI-resistant fallback when MASQUE/QUIC
/// is blocked. Implements [`Transport`], so the datapath/cascade drive it like any other rung.
pub struct AmneziaWgTransport {
    cfg: Arc<AmneziaWgConfig>,
    sessions: Mutex<HashMap<SessionId, Arc<AwgSession>>>,
    next_id: AtomicU64,
}

impl AmneziaWgTransport {
    pub fn new(node_wg_pub: [u8; 32], host: Option<String>, port: Option<u16>) -> Self {
        Self::with_config(AmneziaWgConfig { node_wg_pub, host, port, obfs: ObfsParams::default() })
    }

    pub fn with_config(cfg: AmneziaWgConfig) -> Self {
        Self { cfg: Arc::new(cfg), sessions: Mutex::new(HashMap::new()), next_id: AtomicU64::new(0) }
    }

    fn state(&self, session: &Session) -> Result<Arc<AwgSession>> {
        self.sessions
            .lock()
            .map_err(|_| Error::Transport("amneziawg session map poisoned".into()))?
            .get(&session.id)
            .cloned()
            .ok_or(Error::SessionNotFound(session.id))
    }
}

async fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    let hp = format!("{host}:{port}");
    let mut addrs = tokio::net::lookup_host(&hp)
        .await
        .map_err(|e| Error::Transport(format!("resolve {hp}: {e}")))?;
    addrs.next().ok_or_else(|| Error::Transport(format!("no address for {hp}")))
}

#[async_trait]
impl Transport for AmneziaWgTransport {
    async fn connect(&self, target: NodeEndpoint, _creds: Grant) -> Result<Session> {
        let host = self.cfg.host.as_deref().unwrap_or(&target.host);
        let port = self.cfg.port.unwrap_or(target.port);
        let peer = resolve(host, port).await?;
        let bind = if peer.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| Error::Transport(format!("udp bind: {e}")))?;
        socket.connect(peer).await.map_err(|e| Error::Transport(format!("udp connect: {e}")))?;
        let obfs = self.cfg.obfs.clone();

        // Pre-handshake junk (the peer ignores it), then the obfuscated WireGuard handshake.
        for junk in obfs.junk_packets() {
            let _ = socket.send(&junk).await;
        }
        let client_kp = WgKeypair::generate().map_err(|e| Error::Transport(format!("wg keygen: {e}")))?;
        let client_pub = *client_kp.public.as_bytes();
        let mut core = PqWgCore::without_psk(client_kp.secret, PublicKey::from(self.cfg.node_wg_pub), 1);
        let init = core.handshake_init().map_err(|e| Error::Transport(format!("wg init: {e:?}")))?;
        // Preface (our WG pubkey, so the responder can build its Tunn) then the handshake init.
        socket
            .send(&obfs.obfuscate_preface(&client_pub))
            .await
            .map_err(|e| Error::Transport(format!("send preface: {e}")))?;
        socket
            .send(&obfs.obfuscate(&init))
            .await
            .map_err(|e| Error::Transport(format!("send handshake: {e}")))?;

        // Await the (obfuscated) handshake response, then send the completing keepalive.
        let mut buf = vec![0u8; 65535];
        let resp = tokio::time::timeout(AWG_HANDSHAKE_TIMEOUT, async {
            loop {
                let n = socket
                    .recv(&mut buf)
                    .await
                    .map_err(|e| Error::Transport(format!("recv handshake: {e}")))?;
                if let Some(wg) = obfs.deobfuscate(&buf[..n]) {
                    return Ok::<Vec<u8>, Error>(wg);
                }
                // junk / not ours → keep waiting
            }
        })
        .await
        .map_err(|_| Error::Transport("amneziawg handshake timed out".into()))??;

        match core.decapsulate(&resp) {
            WgStep::Network(keepalive) => {
                socket
                    .send(&obfs.obfuscate(&keepalive))
                    .await
                    .map_err(|e| Error::Transport(format!("send keepalive: {e}")))?;
            }
            other => return Err(Error::Transport(format!("amneziawg handshake failed: {other:?}"))),
        }
        tracing::info!("AmneziaWG tunnel established (obfuscated WireGuard over UDP)");

        let (to_tx, to_rx) = mpsc::channel(AWG_QUEUE);
        let (from_tx, from_rx) = mpsc::channel(AWG_QUEUE);
        let shutdown = CancellationToken::new();
        let driver = tokio::spawn(awg_driver(socket, core, obfs, to_rx, from_tx, shutdown.clone()));

        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let sess = Arc::new(AwgSession {
            to_wire: to_tx,
            from_wire: AsyncMutex::new(from_rx),
            shutdown,
            _driver: driver,
        });
        self.sessions
            .lock()
            .map_err(|_| Error::Transport("amneziawg session map poisoned".into()))?
            .insert(id, sess);
        Ok(Session { id, kind: TransportKind::AmneziaWg })
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
                .map_err(|_| Error::Transport("amneziawg session map poisoned".into()))?;
            map.remove(&session.id)
        }
        .ok_or(Error::SessionNotFound(session.id))?;
        s.shutdown.cancel();
        Ok(())
    }

    fn kind(&self) -> TransportKind {
        TransportKind::AmneziaWg
    }

    fn fingerprint_profile(&self) -> Profile {
        Profile::Wireguardish
    }
}

/// The data pump: app IP packets → WG encapsulate → obfuscate → UDP; UDP → deobfuscate → WG
/// decapsulate → app. A timer drives WireGuard keepalive/rekey.
async fn awg_driver(
    socket: UdpSocket,
    mut core: PqWgCore,
    obfs: ObfsParams,
    mut to_rx: mpsc::Receiver<IpPacket>,
    from_tx: mpsc::Sender<IpPacket>,
    shutdown: CancellationToken,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            pkt = to_rx.recv() => match pkt {
                Some(ip) => {
                    if let Ok(wire) = core.encapsulate(ip.as_bytes()) {
                        let _ = socket.send(&obfs.obfuscate(&wire)).await;
                    }
                }
                None => return,
            },
            r = socket.recv(&mut buf) => match r {
                Ok(n) => {
                    if let Some(wg) = obfs.deobfuscate(&buf[..n]) {
                        let mut input = wg;
                        loop {
                            match core.decapsulate(&input) {
                                WgStep::Ip(ip) => { let _ = from_tx.try_send(IpPacket::new(ip)); break; }
                                WgStep::Network(b) => { let _ = socket.send(&obfs.obfuscate(&b)).await; input = Vec::new(); }
                                WgStep::Done | WgStep::Err(_) => break,
                            }
                        }
                    }
                }
                Err(e) => { tracing::debug!("amneziawg udp recv: {e}"); return; }
            },
            _ = tokio::time::sleep(AWG_TICK) => {
                if let Some(b) = core.tick() {
                    let _ = socket.send(&obfs.obfuscate(&b)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqwg::{PqWgCore, WgKeypair, WgStep};
    use nil_crypto::psk::{responder_encapsulate, PqInitiator};

    fn wg_packet(t: u8, body_len: usize) -> Vec<u8> {
        let mut p = vec![t, 0, 0, 0];
        p.extend(std::iter::repeat(0xAB).take(body_len));
        p
    }

    #[test]
    fn round_trips_every_message_type_and_hides_the_fingerprint() {
        let p = ObfsParams::default();
        // (type, total WG length) for the three fixed-size packets + a data packet.
        for (t, len) in [(1u8, 148usize), (2, 92), (3, 64), (4, 80)] {
            let wg = wg_packet(t, len - 4);
            let wire = p.obfuscate(&wg);
            // The WG type word (1/2/3/4 at byte 0) must NOT appear at the wire's start.
            assert_ne!(wire[0], t, "type-{t} word must be replaced by a magic header");
            assert_eq!(&wire[0..4], &p.headers[(t - 1) as usize], "magic header present");
            // Fixed-size handshakes must not be their tell-tale length on the wire.
            if len != 80 {
                assert!(wire.len() > len, "handshake packet padded past its WG size");
            }
            let back = p.deobfuscate(&wire).expect("our packet deobfuscates");
            assert_eq!(back, wg, "type-{t} WG packet survives the round-trip exactly");
        }
    }

    #[test]
    fn junk_packets_are_ignored_by_the_peer() {
        let p = ObfsParams::default();
        let junk = p.junk_packets();
        assert_eq!(junk.len(), p.junk_count);
        for j in junk {
            // Astronomically unlikely to match a 4-byte magic; treat any match as a test miss.
            assert!(p.deobfuscate(&j).is_none(), "junk must not look like a real packet");
        }
    }

    /// The real proof: a full PQ-WireGuard handshake + a data packet, with EVERY datagram passed
    /// through the obfuscation codec, completes and round-trips — obfuscation composes with the
    /// crypto and never corrupts a packet.
    #[test]
    fn wireguard_handshake_and_data_survive_the_obfuscation_layer() {
        let obfs = ObfsParams::default();
        // Shared PQ hybrid PSK (as the AmneziaWG rung will derive it).
        let (initiator, offer) = PqInitiator::generate();
        let (cts, node_psk) = responder_encapsulate(&offer).expect("node encapsulate");
        let client_psk = initiator.finish(&cts).expect("client finish");
        let client_kp = WgKeypair::generate().unwrap();
        let node_kp = WgKeypair::generate().unwrap();
        let mut client = PqWgCore::new(client_kp.secret, node_kp.public, &client_psk, 1);
        let mut node = PqWgCore::new(node_kp.secret, client_kp.public, &node_psk, 2);

        // Send a wire helper: obfuscate at the sender, deobfuscate at the receiver.
        let hop = |obfs: &ObfsParams, pkt: &[u8]| -> Vec<u8> {
            let wire = obfs.obfuscate(pkt);
            obfs.deobfuscate(&wire).expect("peer recovers our packet")
        };

        // Handshake init → response → keepalive, each crossing the obfuscation layer.
        let init = client.handshake_init().expect("init");
        let resp = match node.decapsulate(&hop(&obfs, &init)) {
            WgStep::Network(b) => b,
            other => panic!("expected handshake response, got {other:?}"),
        };
        let keepalive = match client.decapsulate(&hop(&obfs, &resp)) {
            WgStep::Network(b) => b,
            other => panic!("expected keepalive, got {other:?}"),
        };
        match node.decapsulate(&hop(&obfs, &keepalive)) {
            WgStep::Done | WgStep::Network(_) => {}
            other => panic!("expected handshake completion, got {other:?}"),
        }

        // A real IP packet survives encrypt → obfuscate → (wire) → deobfuscate → decrypt.
        let ip = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 74, 0, 2,
            10, 74, 0, 1, 0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
        ];
        let wire = client.encapsulate(&ip).expect("encapsulate");
        match node.decapsulate(&hop(&obfs, &wire)) {
            WgStep::Ip(got) => assert_eq!(got, ip, "the inner IP packet survives obfuscated PQ-WG"),
            other => panic!("expected decapsulated IP, got {other:?}"),
        }
    }
}
