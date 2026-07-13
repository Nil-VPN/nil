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
/// Deadline for the PQ KEM encapsulation (Classic McEliece is CPU-heavy — can take ~seconds). It
/// runs on a blocking thread; this bounds how long a hostile offer can occupy one.
const WS_PQ_ENCAP_TIMEOUT: Duration = Duration::from_secs(30);

use boringtun::x25519::{PublicKey, StaticSecret};
use futures_util::{SinkExt, StreamExt};
use nil_crypto::psk::{responder_encapsulate, PqOffer};
use nil_transport::pqwg::{decode_parts, encode_parts};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http;
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
    // The single secret path the node serves: derived from its own pinned WG static key, the same
    // shared identity the client derives from. Any other path gets a 404 so the rung is not
    // confirmable by an active prober that doesn't know the node's key. Shared derivation with the
    // client (`nil_transport::derive_request_path`) so the contract can't drift.
    let expected_path = nil_transport::derive_request_path(kp.public.as_bytes());
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
        //
        // Path gate: only the secret path derived from this node's key upgrades; every other path
        // gets a `404` (the WS handshake callback rejects it). An active prober on `/` therefore
        // can't confirm the rung. The path is not user-linkable (it's a function of the node's
        // static key, identical for every client), so logging nothing about it keeps PD-3 intact.
        let expected_path = expected_path.clone();
        let acceptor = acceptor.clone();
        let upgrade = tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, async move {
            let tls = acceptor.accept(tcp).await.ok()?;
            // The `Result<Response, ErrorResponse>` shape is dictated by the tokio-tungstenite
            // accept-callback API; both variants are owned `http::Response` values we cannot box.
            #[allow(clippy::result_large_err)]
            let gate = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                if req.uri().path() == expected_path {
                    return Ok(resp);
                }
                // Wrong path → 404, exactly like a vanilla web server with nothing at that URL.
                let mut deny = ErrorResponse::new(None);
                *deny.status_mut() = http::StatusCode::NOT_FOUND;
                Err(deny)
            };
            tokio_tungstenite::accept_hdr_async(tls, gate).await.ok()
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

    // Frame 2: the client's PQ hybrid-PSK offer (ML-KEM-1024 ek + Classic McEliece pk). We
    // encapsulate against it to derive the shared PSK and reply with the two ciphertexts; both
    // sides then key the WireGuard IKpsk2 handshake with the PSK (PQ-by-default, like MASQUE).
    // A malformed/short offer drops the connection (the slot frees; no PII is logged).
    let psk = match tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, recv_binary(&mut ws)).await {
        Ok(Some(offer_bytes)) => {
            let Some(parts) = decode_parts(&offer_bytes) else {
                return;
            };
            if parts.len() != 2 {
                return;
            }
            let offer = PqOffer {
                mlkem_ek: parts[0].clone(),
                mceliece_pk: parts[1].clone(),
            };
            // Classic McEliece encapsulation is CPU-heavy (can take ~seconds in debug). Run it on a
            // blocking thread with a deadline so a hostile/valid-but-expensive offer can't peg an
            // async worker and stall the node (including Ctrl-C). A timeout / join error / KEM error
            // all drop the connection (fail-closed; the slot frees; no PII logged).
            let (cts, psk) = match tokio::time::timeout(
                WS_PQ_ENCAP_TIMEOUT,
                tokio::task::spawn_blocking(move || responder_encapsulate(&offer)),
            )
            .await
            {
                Ok(Ok(Ok(pair))) => pair,
                _ => return,
            };
            if ws
                .send(Message::Binary(encode_parts(&[
                    &cts.mlkem_ct,
                    &cts.mceliece_ct,
                ])))
                .await
                .is_err()
            {
                return;
            }
            psk
        }
        _ => return, // timed out / no offer → drop the connection
    };
    let mut core = PqWgCore::new(node_secret.clone(), PublicKey::from(client_pub), &psk, 2);
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
    let ck =
        rcgen::generate_simple_self_signed(vec!["nil-node".to_string(), "localhost".to_string()])?;
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
