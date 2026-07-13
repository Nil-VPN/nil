//! wstunnel cascade rung (architecture spec §4.3): WireGuard carried over **WebSocket-over-TLS**
//! — a distinct, HTTPS-shaped wire fingerprint for when MASQUE (QUIC) and AmneziaWG (UDP) are
//! both blocked. The inner WireGuard ([`crate::pqwg::PqWgCore`]) provides the crypto/auth (the
//! node's static key is pinned, like the AmneziaWG rung); the TLS WebSocket is purely the
//! obfuscation envelope, so the TLS server cert is **not** verified (security never depends on
//! it — confidentiality/authentication are the inner WireGuard's).
//!
//! Framing: the first WebSocket binary frame is the client's 32-byte WG static pubkey (the
//! responder needs the initiator's static key up front); the second binary frame is the client's
//! PQ hybrid-PSK offer (`encode_parts([ml-kem ek, mceliece pk])`); the node replies with one frame
//! of ciphertexts (`encode_parts([ml-kem ct, mceliece ct])`). Every subsequent binary frame is one
//! WireGuard datagram. WS-over-TLS is reliable + ordered, so no junk/obfuscation codec is needed.
//!
//! **PQ status:** this rung is now **PQ-by-default** like the primary MASQUE transport. Before the
//! WireGuard Noise handshake, the client and node run the same ML-KEM-1024 + Classic McEliece
//! hybrid PSK exchange ([`nil_crypto::psk`]) that `PqWgTransport` runs over MASQUE — carried over
//! the reliable WS control frames (which, unlike the AmneziaWG rung's raw-UDP channel, can ship the
//! ~512 KiB McEliece offer). The derived PSK is mixed into the WireGuard IKpsk2 handshake, so the
//! tunnel is safe if *either* the classical X25519 Noise handshake or the PQ PSK holds. The TLS
//! envelope is still NOT a trust boundary (no server-cert verification); the inner PQ-WireGuard is.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boringtun::x25519::PublicKey;
use futures_util::{SinkExt, StreamExt};
use nil_core::{
    Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind,
};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;
use tokio_util::sync::CancellationToken;

use crate::pqwg::{decode_parts, encode_parts, PqWgCore, WgKeypair, WgStep};
use crate::Transport;
use nil_crypto::psk::{PqCiphertexts, PqInitiator};

const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Separate, more generous bound for the PQ hybrid-PSK exchange: the node's Classic McEliece
/// `responder_encapsulate` is CPU-heavy (seconds, especially in debug builds), so the WG-handshake
/// slowloris bound (`WS_HANDSHAKE_TIMEOUT`) is too tight for the ciphertexts round-trip. Mirrors
/// `pqwg::PQWG_HANDSHAKE_TIMEOUT`.
const WS_PQ_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const WS_QUEUE: usize = 1024;
const WS_TICK: Duration = Duration::from_millis(250);

/// HKDF `info` label for the secret request path. A fixed, version-tagged domain separator so the
/// derived path can't collide with any other use of the node's static key.
const WS_PATH_LABEL: &[u8] = b"nil-vpn/wstunnel/request-path/v1";
/// Bytes of HKDF output expanded into the path (32 bytes ⇒ a 64-hex-char path component).
const WS_PATH_LEN: usize = 32;

/// Derive the **secret** WebSocket request path both peers agree on, deterministically from the
/// node's pinned WireGuard static public key — the shared identity the client already pins and the
/// node already owns. An active prober that doesn't know the node's key cannot guess the path, so
/// the node `404`s every other path and the rung is not trivially probeable on `/`.
///
/// `HKDF-SHA256(ikm = node_wg_pub, info = WS_PATH_LABEL)` expanded to [`WS_PATH_LEN`] bytes, then
/// lowercase-hex, prefixed with `/`. Pure + shared by client and node (re-exported as
/// [`crate::wstunnel::derive_request_path`]) so the contract can never drift.
pub fn derive_request_path(node_wg_pub: &[u8; 32]) -> String {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, node_wg_pub);
    let mut okm = [0u8; WS_PATH_LEN];
    // `expand` only fails for an absurd output length; WS_PATH_LEN is well within one HKDF block.
    hk.expand(WS_PATH_LABEL, &mut okm)
        .expect("WS_PATH_LEN is a valid HKDF output length");
    let mut path = String::with_capacity(1 + WS_PATH_LEN * 2);
    path.push('/');
    path.push_str(&crate::connectip::to_hex(&okm));
    path
}

/// Configuration for the wstunnel rung.
pub struct WstunnelConfig {
    /// The node's WireGuard static public key (the inner crypto's pinned identity).
    pub node_wg_pub: [u8; 32],
    /// Host of the node's wstunnel responder. `None` ⇒ the connect target's host.
    pub host: Option<String>,
    /// Port of the node's wstunnel responder. `None` ⇒ the target's port.
    pub port: Option<u16>,
}

struct WsSession {
    to_wire: mpsc::Sender<IpPacket>,
    from_wire: AsyncMutex<mpsc::Receiver<IpPacket>>,
    shutdown: CancellationToken,
    _driver: tokio::task::JoinHandle<()>,
}

/// WireGuard over WebSocket-over-TLS — the cascade's HTTPS-shaped fallback. Implements
/// [`Transport`], so the cascade/datapath drive it like any rung.
pub struct WstunnelTransport {
    cfg: Arc<WstunnelConfig>,
    sessions: Mutex<HashMap<SessionId, Arc<WsSession>>>,
    next_id: AtomicU64,
}

impl WstunnelTransport {
    pub fn new(node_wg_pub: [u8; 32], host: Option<String>, port: Option<u16>) -> Self {
        Self {
            cfg: Arc::new(WstunnelConfig {
                node_wg_pub,
                host,
                port,
            }),
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    fn state(&self, session: &Session) -> Result<Arc<WsSession>> {
        self.sessions
            .lock()
            .map_err(|_| Error::Transport("wstunnel session map poisoned".into()))?
            .get(&session.id)
            .cloned()
            .ok_or(Error::SessionNotFound(session.id))
    }
}

/// A rustls verifier that accepts any server certificate. The wstunnel rung's security is the
/// inner WireGuard (pinned node key), not TLS — TLS is only the HTTPS-WebSocket envelope. (This
/// is the TLS analogue of the AmneziaWG rung's unauthenticated UDP.)
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

fn tls_connector() -> Result<Connector> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Transport(format!("rustls config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config)))
}

#[async_trait]
impl Transport for WstunnelTransport {
    async fn connect(&self, target: NodeEndpoint, _creds: Grant) -> Result<Session> {
        let host = self.cfg.host.clone().unwrap_or_else(|| target.host.clone());
        let port = self.cfg.port.unwrap_or(target.port);
        // Request the secret path derived from the node's pinned key, not `/`. The node 404s every
        // other path, so the rung can't be confirmed by an active prober that lacks the node key.
        let path = derive_request_path(&self.cfg.node_wg_pub);
        let url = format!("wss://{host}:{port}{path}");

        let connector = tls_connector()?;
        let (mut ws, _resp) =
            tokio_tungstenite::connect_async_tls_with_config(&url, None, false, Some(connector))
                .await
                // Don't embed the node endpoint (host:port) in the error — the cascade logs this
                // string at WARN on step-down, and node IPs must never reach a log line.
                .map_err(|e| Error::Transport(format!("wstunnel connect failed: {e}")))?;

        // Frame 1: our WG static pubkey.
        let client_kp =
            WgKeypair::generate().map_err(|e| Error::Transport(format!("wg keygen: {e}")))?;
        ws_send(&mut ws, client_kp.public.as_bytes().to_vec()).await?;

        // Frame 2: the PQ hybrid-PSK offer (ML-KEM-1024 ek + Classic McEliece pk, ~512 KiB). The
        // reliable WS channel carries it (unlike the raw-UDP AmneziaWG rung). The node replies with
        // the two KEM ciphertexts; both sides derive the same PSK, which never crosses the wire.
        let (initiator, offer) = PqInitiator::generate();
        ws_send(
            &mut ws,
            encode_parts(&[&offer.mlkem_ek, &offer.mceliece_pk]),
        )
        .await?;
        let cts_msg = tokio::time::timeout(WS_PQ_HANDSHAKE_TIMEOUT, ws_recv_binary(&mut ws))
            .await
            .map_err(|_| Error::Transport("wstunnel PQ handshake timed out".into()))??;
        let parts = decode_parts(&cts_msg)
            .ok_or_else(|| Error::Transport("wstunnel: malformed PQ ciphertexts".into()))?;
        if parts.len() != 2 {
            return Err(Error::Transport(
                "wstunnel PQ ciphertexts: expected 2 parts".into(),
            ));
        }
        let cts = PqCiphertexts {
            mlkem_ct: parts[0].clone(),
            mceliece_ct: parts[1].clone(),
        };
        let psk = initiator
            .finish(&cts)
            .map_err(|e| Error::Transport(format!("wstunnel PQ decapsulate: {e}")))?;

        // The WireGuard IKpsk2 handshake, with the hybrid PSK mixed in (PQ-by-default).
        let mut core = PqWgCore::new(
            client_kp.secret,
            PublicKey::from(self.cfg.node_wg_pub),
            &psk,
            1,
        );
        let init = core
            .handshake_init()
            .map_err(|e| Error::Transport(format!("wg init: {e:?}")))?;
        ws_send(&mut ws, init).await?;

        // Await the handshake response, then send the completing keepalive.
        let resp = tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, ws_recv_binary(&mut ws))
            .await
            .map_err(|_| Error::Transport("wstunnel handshake timed out".into()))??;
        match core.decapsulate(&resp) {
            WgStep::Network(keepalive) => ws_send(&mut ws, keepalive).await?,
            other => {
                return Err(Error::Transport(format!(
                    "wstunnel handshake failed: {other:?}"
                )))
            }
        }
        tracing::info!("wstunnel tunnel established (PQ-WireGuard over WebSocket-over-TLS)");

        let (to_tx, to_rx) = mpsc::channel(WS_QUEUE);
        let (from_tx, from_rx) = mpsc::channel(WS_QUEUE);
        let shutdown = CancellationToken::new();
        let driver = tokio::spawn(ws_driver(ws, core, to_rx, from_tx, shutdown.clone()));

        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let sess = Arc::new(WsSession {
            to_wire: to_tx,
            from_wire: AsyncMutex::new(from_rx),
            shutdown,
            _driver: driver,
        });
        self.sessions
            .lock()
            .map_err(|_| Error::Transport("wstunnel session map poisoned".into()))?
            .insert(id, sess);
        Ok(Session {
            id,
            kind: TransportKind::Wstunnel,
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
                .map_err(|_| Error::Transport("wstunnel session map poisoned".into()))?;
            map.remove(&session.id)
        }
        .ok_or(Error::SessionNotFound(session.id))?;
        s.shutdown.cancel();
        Ok(())
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Wstunnel
    }

    fn fingerprint_profile(&self) -> Profile {
        Profile::WebSocketTls
    }

    fn tunnel_mtu(&self, _session: &Session) -> Option<usize> {
        // Conservative inner-TUN MTU for the WireGuard-over-WebSocket-over-TLS-over-TCP path.
        // The carrier is TCP, so an oversized inner packet only costs extra segmentation (it does
        // not blackhole the way it would over UDP/QUIC), but advertising a value avoids inheriting
        // the primary rung's larger MTU when this rung wins. 1280 (the IPv6 minimum) is safely
        // below any path MSS once WG (~32B) + WS framing + TLS records are accounted for.
        Some(1280)
    }
}

/// A WebSocket stream over either plain TCP or TLS (tungstenite's MaybeTlsStream).
type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_send(ws: &mut Ws, data: Vec<u8>) -> Result<()> {
    ws.send(Message::Binary(data))
        .await
        .map_err(|e| Error::Transport(format!("wstunnel send: {e}")))
}

/// Receive the next binary frame, skipping ping/pong/text.
async fn ws_recv_binary(ws: &mut Ws) -> Result<Vec<u8>> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => return Ok(b),
            Some(Ok(_)) => continue, // ping/pong/text/close-frame handling: ignore non-binary
            Some(Err(e)) => return Err(Error::Transport(format!("wstunnel recv: {e}"))),
            None => return Err(Error::Closed),
        }
    }
}

/// The data pump: app IP → WG encapsulate → WS binary; WS binary → WG decapsulate → app. A timer
/// drives WireGuard keepalive/rekey.
async fn ws_driver(
    ws: Ws,
    mut core: PqWgCore,
    mut to_rx: mpsc::Receiver<IpPacket>,
    from_tx: mpsc::Sender<IpPacket>,
    shutdown: CancellationToken,
) {
    let (mut sink, mut stream) = ws.split();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => { let _ = sink.close().await; return; }
            pkt = to_rx.recv() => match pkt {
                Some(ip) => {
                    if let Ok(wire) = core.encapsulate(ip.as_bytes()) {
                        if sink.send(Message::Binary(wire)).await.is_err() { return; }
                    }
                }
                None => return,
            },
            msg = stream.next() => match msg {
                Some(Ok(Message::Binary(b))) => {
                    let mut input = b;
                    loop {
                        match core.decapsulate(&input) {
                            WgStep::Ip(ip) => { let _ = from_tx.try_send(IpPacket::new(ip)); break; }
                            WgStep::Network(b) => {
                                if sink.send(Message::Binary(b)).await.is_err() { return; }
                                input = Vec::new();
                            }
                            WgStep::Done | WgStep::Err(_) => break,
                        }
                    }
                }
                Some(Ok(_)) => {} // ignore non-binary frames
                Some(Err(e)) => { tracing::debug!("wstunnel ws recv: {e}"); return; }
                None => return,
            },
            _ = tokio::time::sleep(WS_TICK) => {
                if let Some(b) = core.tick() {
                    if sink.send(Message::Binary(b)).await.is_err() { return; }
                }
            }
        }
    }
}
