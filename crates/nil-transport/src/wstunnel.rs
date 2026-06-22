//! wstunnel cascade rung (architecture spec §4.3): WireGuard carried over **WebSocket-over-TLS**
//! — a distinct, HTTPS-shaped wire fingerprint for when MASQUE (QUIC) and AmneziaWG (UDP) are
//! both blocked. The inner WireGuard ([`crate::pqwg::PqWgCore`]) provides the crypto/auth (the
//! node's static key is pinned, like the AmneziaWG rung); the TLS WebSocket is purely the
//! obfuscation envelope, so the TLS server cert is **not** verified (security never depends on
//! it — confidentiality/authentication are the inner WireGuard's).
//!
//! Framing: the first WebSocket binary frame is the client's 32-byte WG static pubkey (the
//! responder needs the initiator's static key up front); every subsequent binary frame is one
//! WireGuard datagram. WS-over-TLS is reliable + ordered, so no junk/obfuscation codec is needed.
//!
//! **PQ status (honest limitation):** this rung currently runs *classical* WireGuard
//! (`PqWgCore::without_psk`, X25519 only) — it does NOT carry the post-quantum hybrid PSK that the
//! default MASQUE transport (`PqWgTransport`) does. Unlike the AmneziaWG rung (whose raw-UDP
//! channel genuinely cannot ship the ~512 KiB McEliece offer), this rung's reliable WS channel
//! *could* carry the PQ exchange (exactly as `PqWgTransport` does over MASQUE), so the downgrade
//! here is incidental, not fundamental. TODO: run the PQ hybrid PSK exchange over the WS control
//! frames before the WG handshake to make wstunnel PQ-by-default like the primary transport. Until
//! then, treat this last-resort rung as classical-crypto only.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boringtun::x25519::PublicKey;
use futures_util::{SinkExt, StreamExt};
use nil_core::{Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;
use tokio_util::sync::CancellationToken;

use crate::pqwg::{PqWgCore, WgKeypair, WgStep};
use crate::Transport;

const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WS_QUEUE: usize = 1024;
const WS_TICK: Duration = Duration::from_millis(250);

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
            cfg: Arc::new(WstunnelConfig { node_wg_pub, host, port }),
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
            ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384, ED25519, RSA_PSS_SHA256, RSA_PSS_SHA384,
            RSA_PSS_SHA512, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
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
        let url = format!("wss://{host}:{port}/");

        let connector = tls_connector()?;
        let (mut ws, _resp) =
            tokio_tungstenite::connect_async_tls_with_config(&url, None, false, Some(connector))
                .await
                // Don't embed the node endpoint (host:port) in the error — the cascade logs this
                // string at WARN on step-down, and node IPs must never reach a log line.
                .map_err(|e| Error::Transport(format!("wstunnel connect failed: {e}")))?;

        // Frame 1: our WG static pubkey. Then the WireGuard handshake as binary frames.
        let client_kp = WgKeypair::generate().map_err(|e| Error::Transport(format!("wg keygen: {e}")))?;
        let mut core = PqWgCore::without_psk(client_kp.secret, PublicKey::from(self.cfg.node_wg_pub), 1);
        ws_send(&mut ws, client_kp.public.as_bytes().to_vec()).await?;
        let init = core.handshake_init().map_err(|e| Error::Transport(format!("wg init: {e:?}")))?;
        ws_send(&mut ws, init).await?;

        // Await the handshake response, then send the completing keepalive.
        let resp = tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, ws_recv_binary(&mut ws))
            .await
            .map_err(|_| Error::Transport("wstunnel handshake timed out".into()))??;
        match core.decapsulate(&resp) {
            WgStep::Network(keepalive) => ws_send(&mut ws, keepalive).await?,
            other => return Err(Error::Transport(format!("wstunnel handshake failed: {other:?}"))),
        }
        tracing::info!("wstunnel tunnel established (WireGuard over WebSocket-over-TLS)");

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
        Ok(Session { id, kind: TransportKind::Wstunnel })
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
type Ws = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

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
