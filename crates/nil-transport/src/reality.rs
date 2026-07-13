//! REALITY / VLESS cascade rung (architecture spec §4.3, cascade rung 4): WireGuard carried inside
//! a TLS session, gated by a VLESS-style shared-key auth handshake — the last-resort fallback when
//! MASQUE (QUIC), AmneziaWG (UDP), and wstunnel (WebSocket-over-TLS) are all blocked.
//!
//! As with the wstunnel rung, the inner WireGuard ([`crate::pqwg::PqWgCore`]) is the security
//! boundary (the node's static key is pinned, the TLS server cert is **not** verified — security
//! never depends on it); the outer TLS is purely the obfuscation envelope. What distinguishes this
//! rung from wstunnel is the *intended* wire shape: a censor inspecting the connection should see an
//! ordinary TLS connection to what looks like a normal HTTPS site, and an active prober that does
//! not hold the shared key should be indistinguishable from a stray browser hitting that site.
//!
//! ## Framing
//! TLS gives a reliable, ordered **byte stream** (not message frames like WebSocket), so every
//! record here is explicitly length-delimited: `u16-big-endian length ‖ payload`. The exchange is:
//!   1. client → node: the 16-byte **VLESS auth ID** (see [`derive_auth_id`]) followed by the
//!      client's 32-byte WG static pubkey, in one record. The node validates the auth ID before it
//!      will serve a tunnel; a prober that doesn't hold the node's key sends the wrong (or no) ID
//!      and the node falls back to "ordinary site" behaviour (it never reveals a tunnel).
//!   2. node → client / client → node: each subsequent record is one WireGuard datagram.
//!
//! ## HONEST status — which REALITY properties are / are NOT achieved
//! REALITY's defining trick is that the outer TLS handshake is **byte-for-byte a real browser
//! connecting to a real foreign site**: the client forges a uTLS-grade ClientHello (exact JA3/JA4
//! of, say, Chrome), the SNI names a real third-party site, the node steals (proxies) that real
//! site's certificate for clients it can't authenticate, and only an authenticated client (one
//! holding the shared key, detected via a tag hidden in the ClientHello's key_share) is switched to
//! the tunnel. Faithfully reproducing that requires careful TLS-record forgery and a live reverse
//! proxy to the borrowed site — too large to do correctly here.
//!
//! This module therefore implements the **VLESS-over-TLS** part faithfully and the REALITY
//! TLS-borrow part only cosmetically:
//!   - ACHIEVED: a real TLS session; a VLESS-style shared-key auth gate (the node serves a tunnel
//!     only to a client that presents the key-derived auth ID); the inner PQ-capable WireGuard as
//!     the actual security/auth boundary; a full in-process connect + responder + packet round-trip.
//!   - ACHIEVED (cosmetic): the client sends an SNI that names a plausible foreign site
//!     ([`RealityConfig::sni`]) rather than the node, so the SNI a passive observer sees is not the
//!     node's identity.
//!   - NOT YET ACHIEVED (the remaining REALITY-specific work): the TLS handshake is a **genuine
//!     self-signed** rustls handshake, NOT a borrowed/forged foreign-site handshake — its ClientHello
//!     fingerprint is rustls's, not a real browser's, and the server presents a self-signed cert,
//!     not a proxied real-site cert. An active prober that fingerprints the ClientHello or inspects
//!     the cert can still distinguish this from the site named in the SNI. Closing that gap is the
//!     uTLS-ClientHello-forgery + cert-stealing reverse-proxy work tracked for a later phase.
//!
//! ## Alpha decision (why the TLS-borrow is deferred, not faked)
//! Both the full TLS-borrow (forged ClientHello + a pass-through relay that hands an active prober
//! the *real* site's certificate) and the lighter "browser-fingerprint-only" variant require the
//! client to emit a **custom ClientHello** (a real-browser JA3/JA4, with the auth tag carried in the
//! TLS `SessionId` so the node can tell a key-holder from a prober *before* it responds). `rustls`
//! does not expose ClientHello customisation, so closing this gap needs either a vetted
//! ClientHello-capable TLS dependency (a forked/patched stack — a supply-chain commitment) or a
//! hand-rolled ClientHello plus a TLS-*shaped* channel (no real TLS session). For the alpha we
//! deliberately ship **neither**: an unreviewed forked TLS stack or a half-baked hand-rolled TLS
//! would be *more* fingerprintable and harder to audit than an honest "this rung's outer shape is a
//! real, self-signed TLS session" — and that cuts against PD-5/PD-8. What is deferred is this rung's
//! **unobservability to an active prober**, NOT its security: the inner PQ-capable WireGuard
//! ([`crate::pqwg::PqWgCore`]) is the cryptographic boundary, so the rung is safe to use today as
//! the cascade's last-resort fallback. The network-aware selector (the `selector` feature) routes
//! to it on a hostile network; its honest limit (a determined active prober can still distinguish
//! it from the named site) must be stated wherever the rung is described.
//!
//! ## PQ status (same honest limitation as the wstunnel rung)
//! This rung runs *classical* WireGuard (`PqWgCore::without_psk`, X25519 only); it does NOT carry
//! the post-quantum hybrid PSK the default MASQUE transport does. The reliable TLS byte stream
//! *could* carry the PQ exchange (like `PqWgTransport` over MASQUE) — the downgrade is incidental,
//! not fundamental — but wiring the PQ hybrid PSK over the auth handshake is deferred. Until then,
//! treat this last-resort rung as classical-crypto only.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boringtun::x25519::PublicKey;
use nil_core::{
    Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::pqwg::{PqWgCore, WgKeypair, WgStep};
use crate::Transport;

const REALITY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REALITY_QUEUE: usize = 1024;
const REALITY_TICK: Duration = Duration::from_millis(250);
/// Cap on a single length-delimited record so a malformed/hostile length can't make us allocate an
/// unbounded buffer. A WireGuard datagram plus framing is far under this; 64 KiB matches a TLS
/// record's natural ceiling.
const REALITY_MAX_RECORD: usize = 64 * 1024;

/// Length of the VLESS-style auth ID (REALITY's "short ID" analogue). 16 bytes ⇒ 128-bit, the same
/// width as a VLESS UUID, so the value is unguessable without the node's key.
pub const REALITY_AUTH_ID_LEN: usize = 16;

/// HKDF `info` label for the VLESS auth ID. A fixed, version-tagged domain separator so the derived
/// ID can't collide with any other use of the node's static key (e.g. the wstunnel request path).
const REALITY_AUTH_LABEL: &[u8] = b"nil-vpn/reality/vless-auth-id/v1";

/// A plausible default SNI for the borrowed-TLS envelope when a deployment doesn't configure one.
/// This is **cosmetic** today (the handshake is a genuine self-signed rustls handshake, not a real
/// borrow of this site) — see the module-level honest-status note.
const REALITY_DEFAULT_SNI: &str = "www.microsoft.com";

/// Derive the 16-byte VLESS-style **auth ID** both peers agree on, deterministically from the node's
/// pinned WireGuard static public key — the shared identity the client already pins and the node
/// already owns. A prober that does not hold the node's key cannot present the right ID, so the node
/// declines to reveal a tunnel to it (it behaves like an ordinary TLS site). This is the VLESS
/// shared-key gate; the inner WireGuard remains the real security boundary.
///
/// `HKDF-SHA256(ikm = node_wg_pub, info = REALITY_AUTH_LABEL)` truncated to [`REALITY_AUTH_ID_LEN`].
/// Pure + shared by client and node (re-exported as [`crate::reality::derive_auth_id`]) so the
/// contract can never drift.
pub fn derive_auth_id(node_wg_pub: &[u8; 32]) -> [u8; REALITY_AUTH_ID_LEN] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, node_wg_pub);
    let mut id = [0u8; REALITY_AUTH_ID_LEN];
    // `expand` only fails for an absurd output length; 16 bytes is well within one HKDF block.
    hk.expand(REALITY_AUTH_LABEL, &mut id)
        .expect("REALITY_AUTH_ID_LEN is a valid HKDF output length");
    id
}

/// Configuration for the REALITY/VLESS rung.
pub struct RealityConfig {
    /// The node's WireGuard static public key (the inner crypto's pinned identity, and the seed for
    /// the VLESS auth ID).
    pub node_wg_pub: [u8; 32],
    /// Host of the node's REALITY responder. `None` ⇒ the connect target's host.
    pub host: Option<String>,
    /// Port of the node's REALITY responder. `None` ⇒ the target's port.
    pub port: Option<u16>,
    /// The SNI to present in the TLS ClientHello — the borrowed foreign-site name. Cosmetic today
    /// (see the module honest-status note). `None` ⇒ [`REALITY_DEFAULT_SNI`].
    pub sni: Option<String>,
}

struct RealitySession {
    to_wire: mpsc::Sender<IpPacket>,
    from_wire: AsyncMutex<mpsc::Receiver<IpPacket>>,
    shutdown: CancellationToken,
    _driver: tokio::task::JoinHandle<()>,
}

/// WireGuard inside a VLESS-gated TLS session — the cascade's last-resort fallback. Implements
/// [`Transport`], so the cascade/datapath drive it like any rung.
pub struct RealityTransport {
    cfg: Arc<RealityConfig>,
    sessions: Mutex<HashMap<SessionId, Arc<RealitySession>>>,
    next_id: AtomicU64,
}

impl RealityTransport {
    pub fn new(node_wg_pub: [u8; 32], host: Option<String>, port: Option<u16>) -> Self {
        Self::with_config(RealityConfig {
            node_wg_pub,
            host,
            port,
            sni: None,
        })
    }

    pub fn with_config(cfg: RealityConfig) -> Self {
        Self {
            cfg: Arc::new(cfg),
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    fn state(&self, session: &Session) -> Result<Arc<RealitySession>> {
        self.sessions
            .lock()
            .map_err(|_| Error::Transport("reality session map poisoned".into()))?
            .get(&session.id)
            .cloned()
            .ok_or(Error::SessionNotFound(session.id))
    }
}

/// A rustls verifier that accepts any server certificate. The REALITY rung's security is the inner
/// WireGuard (pinned node key), not TLS — TLS is only the obfuscation envelope. (This is the TLS
/// analogue of the AmneziaWG rung's unauthenticated UDP, and identical in spirit to the wstunnel
/// rung's `NoVerify`.)
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
        ]
    }
}

fn tls_config() -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Transport(format!("rustls config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    Ok(config)
}

/// A REALITY TLS stream over TCP.
type RealityTls = TlsStream<TcpStream>;

#[async_trait]
impl Transport for RealityTransport {
    async fn connect(&self, target: NodeEndpoint, _creds: Grant) -> Result<Session> {
        let host = self.cfg.host.clone().unwrap_or_else(|| target.host.clone());
        let port = self.cfg.port.unwrap_or(target.port);
        let sni = self
            .cfg
            .sni
            .clone()
            .unwrap_or_else(|| REALITY_DEFAULT_SNI.to_string());

        // TCP → TLS. The SNI is the (cosmetic) borrowed foreign-site name, not the node's identity.
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            // Don't embed the node endpoint (host:port) in the error — the cascade logs this string
            // at WARN on step-down, and node IPs must never reach a log line.
            .map_err(|e| Error::Transport(format!("reality tcp connect failed: {e}")))?;
        let server_name = rustls::pki_types::ServerName::try_from(sni)
            .map_err(|e| Error::Transport(format!("reality invalid SNI: {e}")))?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config()?));
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| Error::Transport(format!("reality tls handshake failed: {e}")))?;

        // VLESS auth gate: record 1 is [auth_id ‖ client_wg_pub]. The node validates the auth ID
        // (derived from its pinned key) before it will serve a tunnel; a prober without the key
        // can't produce it. Then the inner WireGuard handshake, one datagram per record.
        let auth_id = derive_auth_id(&self.cfg.node_wg_pub);
        let client_kp =
            WgKeypair::generate().map_err(|e| Error::Transport(format!("wg keygen: {e}")))?;
        let mut hello = Vec::with_capacity(REALITY_AUTH_ID_LEN + 32);
        hello.extend_from_slice(&auth_id);
        hello.extend_from_slice(client_kp.public.as_bytes());
        write_record(&mut tls, &hello).await?;

        let mut core =
            PqWgCore::without_psk(client_kp.secret, PublicKey::from(self.cfg.node_wg_pub), 1);
        let init = core
            .handshake_init()
            .map_err(|e| Error::Transport(format!("wg init: {e:?}")))?;
        write_record(&mut tls, &init).await?;

        // Await the handshake response, then send the completing keepalive.
        let resp = tokio::time::timeout(REALITY_HANDSHAKE_TIMEOUT, read_record(&mut tls))
            .await
            .map_err(|_| Error::Transport("reality handshake timed out".into()))??;
        match core.decapsulate(&resp) {
            WgStep::Network(keepalive) => write_record(&mut tls, &keepalive).await?,
            other => {
                return Err(Error::Transport(format!(
                    "reality handshake failed: {other:?}"
                )))
            }
        }
        // Honest posture (surface the limit where the rung is actually used, not only in the docs):
        // the outer TLS is a genuine self-signed handshake with a rustls (not browser) ClientHello,
        // so an ACTIVE PROBER can still distinguish it from the SNI'd site — this is a
        // censorship-survival fallback, NOT active-prober-resistant — and its inner WireGuard is
        // classical (non-PQ). No address/identity is logged (PD-3).
        tracing::warn!(
            "connected via the REALITY fallback rung: its outer shape is a real self-signed TLS \
             session (not a borrowed foreign-site handshake), so it is NOT active-prober-resistant, \
             and its inner WireGuard is classical (non-PQ) — use only as the last-resort fallback"
        );

        let (to_tx, to_rx) = mpsc::channel(REALITY_QUEUE);
        let (from_tx, from_rx) = mpsc::channel(REALITY_QUEUE);
        let shutdown = CancellationToken::new();
        let driver = tokio::spawn(reality_driver(tls, core, to_rx, from_tx, shutdown.clone()));

        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let sess = Arc::new(RealitySession {
            to_wire: to_tx,
            from_wire: AsyncMutex::new(from_rx),
            shutdown,
            _driver: driver,
        });
        self.sessions
            .lock()
            .map_err(|_| Error::Transport("reality session map poisoned".into()))?
            .insert(id, sess);
        Ok(Session {
            id,
            kind: TransportKind::Reality,
        })
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
                .map_err(|_| Error::Transport("reality session map poisoned".into()))?;
            map.remove(&session.id)
        }
        .ok_or(Error::SessionNotFound(session.id))?;
        s.shutdown.cancel();
        Ok(())
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Reality
    }

    fn fingerprint_profile(&self) -> Profile {
        Profile::RealTlsBorrowed
    }

    fn tunnel_mtu(&self, _session: &Session) -> Option<usize> {
        // Conservative inner-TUN MTU for the WireGuard-over-TLS-over-TCP path. The carrier is TCP,
        // so an oversized inner packet only costs extra segmentation (it does not blackhole the way
        // it would over UDP/QUIC), but advertising a value avoids inheriting the primary rung's
        // larger MTU when this rung wins. 1280 (the IPv6 minimum) is safely below any path MSS once
        // WG (~32B) + the 2-byte record framing + TLS records are accounted for.
        Some(1280)
    }
}

/// Write one length-delimited record: `u16-big-endian length ‖ data`. Shared with the node-side
/// responder via [`crate::reality::write_record_to`] / the framing contract documented at the top
/// of this module.
async fn write_record(tls: &mut RealityTls, data: &[u8]) -> Result<()> {
    write_record_to(tls, data).await
}

/// Generic length-delimited record write over any async writer — used by both the client transport
/// and the node responder so the framing contract can't drift between the two ends.
pub async fn write_record_to<W>(w: &mut W, data: &[u8]) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    if data.len() > REALITY_MAX_RECORD {
        return Err(Error::Transport("reality record exceeds max size".into()));
    }
    let len = (data.len() as u16).to_be_bytes();
    w.write_all(&len)
        .await
        .map_err(|e| Error::Transport(format!("reality write len: {e}")))?;
    w.write_all(data)
        .await
        .map_err(|e| Error::Transport(format!("reality write body: {e}")))?;
    w.flush()
        .await
        .map_err(|e| Error::Transport(format!("reality flush: {e}")))
}

/// Read one length-delimited record. EOF before/while reading a record is reported as
/// [`Error::Closed`].
async fn read_record(tls: &mut RealityTls) -> Result<Vec<u8>> {
    read_record_from(tls).await
}

/// Generic length-delimited record read over any async reader — used by both ends so the framing
/// contract can't drift.
pub async fn read_record_from<R>(r: &mut R) -> Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 2];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(Error::Closed),
        Err(e) => return Err(Error::Transport(format!("reality read len: {e}"))),
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > REALITY_MAX_RECORD {
        return Err(Error::Transport("reality record exceeds max size".into()));
    }
    let mut body = vec![0u8; len];
    match r.read_exact(&mut body).await {
        Ok(_) => Ok(body),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(Error::Closed),
        Err(e) => Err(Error::Transport(format!("reality read body: {e}"))),
    }
}

/// The data pump: app IP → WG encapsulate → TLS record; TLS record → WG decapsulate → app. A timer
/// drives WireGuard keepalive/rekey. The TLS stream is split so reads and writes proceed
/// independently.
async fn reality_driver(
    tls: RealityTls,
    mut core: PqWgCore,
    mut to_rx: mpsc::Receiver<IpPacket>,
    from_tx: mpsc::Sender<IpPacket>,
    shutdown: CancellationToken,
) {
    let (mut rd, mut wr): (ReadHalf<RealityTls>, WriteHalf<RealityTls>) = tokio::io::split(tls);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => { let _ = wr.shutdown().await; return; }
            pkt = to_rx.recv() => match pkt {
                Some(ip) => {
                    if let Ok(wire) = core.encapsulate(ip.as_bytes()) {
                        if write_record_to(&mut wr, &wire).await.is_err() { return; }
                    }
                }
                None => return,
            },
            rec = read_record_from(&mut rd) => match rec {
                Ok(b) => {
                    let mut input = b;
                    loop {
                        match core.decapsulate(&input) {
                            WgStep::Ip(ip) => { let _ = from_tx.try_send(IpPacket::new(ip)); break; }
                            WgStep::Network(out) => {
                                if write_record_to(&mut wr, &out).await.is_err() { return; }
                                input = Vec::new();
                            }
                            WgStep::Done | WgStep::Err(_) => break,
                        }
                    }
                }
                Err(_) => return, // closed or framing error
            },
            _ = tokio::time::sleep(REALITY_TICK) => {
                if let Some(b) = core.tick() {
                    if write_record_to(&mut wr, &b).await.is_err() { return; }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_id_is_deterministic_and_key_bound() {
        let a = [7u8; 32];
        let b = [9u8; 32];
        assert_eq!(
            derive_auth_id(&a),
            derive_auth_id(&a),
            "same key derives the same auth id"
        );
        assert_ne!(
            derive_auth_id(&a),
            derive_auth_id(&b),
            "different keys derive different auth ids"
        );
        assert_eq!(derive_auth_id(&a).len(), REALITY_AUTH_ID_LEN);
    }

    #[tokio::test]
    async fn record_framing_round_trips() {
        // The length-delimited record codec must survive an in-memory duplex round-trip, including
        // an empty record and a maximal-ish one.
        let (mut client, mut server) = tokio::io::duplex(128 * 1024);
        let payloads: Vec<Vec<u8>> = vec![vec![], vec![0xAA], vec![0x42u8; 4096]];
        let expected = payloads.clone();
        let writer = tokio::spawn(async move {
            for p in &payloads {
                write_record_to(&mut client, p).await.expect("write record");
            }
        });
        for want in expected {
            let got = read_record_from(&mut server).await.expect("read record");
            assert_eq!(got, want, "record survives the framing round-trip");
        }
        writer.await.expect("writer task");
    }

    #[tokio::test]
    async fn read_record_reports_closed_on_eof() {
        let (client, mut server) = tokio::io::duplex(16);
        drop(client); // EOF immediately
        assert!(matches!(
            read_record_from(&mut server).await,
            Err(Error::Closed)
        ));
    }
}
