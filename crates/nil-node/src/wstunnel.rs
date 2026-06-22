//! Node-side wstunnel responder (architecture spec §4.3, cascade rung 3): WireGuard carried over
//! WebSocket-over-TLS — the matching half of the client's `nil_transport::WstunnelTransport`.
//!
//! Selected by `NW_NODE_WSTUNNEL`; the node runs this instead of the MASQUE server (a separate
//! node/container), so it owns the exit TUN. Phase 1 serves a single client (one connection at a
//! time). Logs its WireGuard public key for the client to pin (`NW_NODE_WSTUNNEL_WG_PUB`).
//! The TLS uses a self-signed dev cert and is NOT the security boundary — the inner WireGuard is
//! (unattested, pinned-key trust; the TLS is the HTTPS-WebSocket envelope).

use std::sync::Arc;
use std::time::Duration;

/// Bound on the TLS+WS+preface handshake. A peer that connects and then stalls (slowloris) or
/// never sends its pubkey preface must not occupy the single-client slot indefinitely.
const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

use boringtun::x25519::{PublicKey, StaticSecret};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tun_rs::AsyncDevice;

use nil_transport::{connectip, PqWgCore, WgKeypair, WgStep};

use crate::config::NodeConfig;

pub async fn run(cfg: &NodeConfig, tun: Arc<AsyncDevice>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.bind).await?;
    let kp = WgKeypair::generate().map_err(|e| anyhow::anyhow!("node wg keygen: {e}"))?;
    tracing::info!(
        wg_pub = %connectip::to_hex(kp.public.as_bytes()),
        "wstunnel responder listening — pin this as the client's NW_NODE_WSTUNNEL_WG_PUB"
    );
    let node_secret = kp.secret;
    let acceptor = tls_acceptor()?;
    let mut tun_buf = vec![0u8; 65535];

    loop {
        // Accept the next connection while staying responsive to ctrl_c.
        let accepted = tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("nil-node (wstunnel) shutting down");
                break;
            }
            r = listener.accept() => r,
        };
        let Ok((tcp, _)) = accepted else { continue };

        // Bound the TLS + WS upgrade so a peer that stalls mid-handshake (slowloris) can't wedge
        // the node. TLS/WS accept errors are dropped silently — they are attacker-triggerable
        // (TLS is no-client-auth) and the data plane keeps no connection logs.
        let upgrade = tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, async {
            let tls = acceptor.accept(tcp).await.ok()?;
            tokio_tungstenite::accept_async(tls).await.ok()
        })
        .await;
        let ws = match upgrade {
            Ok(Some(ws)) => ws,
            _ => continue, // timed out or failed → drop, keep serving
        };

        // Serve this client to completion (single-client Phase 1), then accept the next — but keep
        // ctrl_c responsive so a long-lived (or stuck) session never starves shutdown. The preface
        // read inside `serve` is itself bounded, so a connected-but-silent peer frees the slot.
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("nil-node (wstunnel) shutting down");
                break;
            }
            _ = serve(ws, &node_secret, &tun, &mut tun_buf) => {}
        }
    }
    Ok(())
}

/// Serve one WebSocket client: read its pubkey preface, build the WireGuard responder, and pump
/// WS frames ↔ the exit TUN until the connection closes.
async fn serve<S>(
    mut ws: WebSocketStream<S>,
    node_secret: &StaticSecret,
    tun: &Arc<AsyncDevice>,
    tun_buf: &mut [u8],
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Frame 1: the client's WG static pubkey. Bounded — a peer that completes the WS upgrade but
    // never sends the preface must not hold the single-client slot forever.
    let client_pub = match tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, recv_binary(&mut ws)).await {
        Ok(Some(b)) if b.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            k
        }
        _ => return, // timed out / no / short preface → drop the connection
    };
    let mut core = PqWgCore::without_psk(node_secret.clone(), PublicKey::from(client_pub), 2);
    let (mut sink, mut stream) = ws.split();

    loop {
        tokio::select! {
            msg = stream.next() => match msg {
                Some(Ok(Message::Binary(b))) => {
                    let mut input = b;
                    loop {
                        match core.decapsulate(&input) {
                            WgStep::Ip(ip) => { let _ = tun.send(&ip).await; break; }
                            WgStep::Network(out) => {
                                if sink.send(Message::Binary(out)).await.is_err() { return; }
                                input = Vec::new();
                            }
                            WgStep::Done | WgStep::Err(_) => break,
                        }
                    }
                }
                Some(Ok(_)) => {}            // ignore non-binary frames
                _ => return,                  // close / error
            },
            r = tun.recv(tun_buf) => {
                let Ok(n) = r else { return };
                nil_core::checksum::fix_l4_checksums(&mut tun_buf[..n]);
                if let Ok(wire) = core.encapsulate(&tun_buf[..n]) {
                    if sink.send(Message::Binary(wire)).await.is_err() { return; }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                if let Some(b) = core.tick() {
                    if sink.send(Message::Binary(b)).await.is_err() { return; }
                }
            }
        }
    }
}

async fn recv_binary<S>(ws: &mut WebSocketStream<S>) -> Option<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => return Some(b),
            Some(Ok(_)) => continue,
            _ => return None,
        }
    }
}

/// A TLS acceptor with a fresh self-signed dev cert (the TLS is the obfuscation envelope, not the
/// trust boundary — the inner WireGuard is).
fn tls_acceptor() -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let ck = rcgen::generate_simple_self_signed(vec!["nil-node".to_string(), "localhost".to_string()])?;
    let cert_der = ck.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(ck.key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("wstunnel server key: {e}"))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("rustls server config: {e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| anyhow::anyhow!("rustls single cert: {e}"))?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}
