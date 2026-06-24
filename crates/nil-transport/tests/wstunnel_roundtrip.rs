//! Round-trip proof for the wstunnel rung (WireGuard over WebSocket-over-TLS), without Docker.
//!
//! Stands up a real WS-over-TLS responder on loopback (self-signed cert, the same shape as the
//! `nil-node` wstunnel responder) that runs a WireGuard responder core and echoes decapsulated IP
//! packets back. Then drives the production `WstunnelTransport` against it and asserts a packet
//! survives the full path: TLS handshake (no-verify) → WS framing → WG IKpsk2-less handshake →
//! encapsulate → wire → decapsulate → echo → back to the client. This exercises every glue layer
//! the Docker e2e does, but in-process and deterministically.

#![cfg(feature = "wstunnel")]

use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use futures_util::{SinkExt, StreamExt};
use nil_core::{Grant, IpPacket, NodeEndpoint, TransportKind};
use nil_transport::{
    derive_request_path, PqWgCore, Transport, WgKeypair, WgStep, WstunnelTransport,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::{http, Message};
use tokio_tungstenite::WebSocketStream;

/// A self-signed TLS acceptor (the TLS is an obfuscation envelope, not the trust boundary).
fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = ck.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(ck.key_pair.serialize_der()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// Serve exactly one client: read its pubkey preface, complete the WG handshake, then echo every
/// decapsulated IP packet back through the tunnel.
async fn serve<S>(mut ws: WebSocketStream<S>, node_secret: StaticSecret)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Frame 1: client WG pubkey.
    let preface = loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => break b,
            Some(Ok(_)) => continue,
            _ => return,
        }
    };
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(&preface);
    let mut core = PqWgCore::without_psk(node_secret, PublicKey::from(client_pub), 2);
    let (mut sink, mut stream) = ws.split();

    while let Some(Ok(msg)) = stream.next().await {
        let Message::Binary(b) = msg else { continue };
        let mut input = b;
        loop {
            match core.decapsulate(&input) {
                WgStep::Ip(ip) => {
                    // Echo the inner IP packet straight back through the tunnel.
                    if let Ok(wire) = core.encapsulate(&ip) {
                        let _ = sink.send(Message::Binary(wire)).await;
                    }
                    break;
                }
                WgStep::Network(out) => {
                    if sink.send(Message::Binary(out)).await.is_err() {
                        return;
                    }
                    input = Vec::new();
                }
                WgStep::Done | WgStep::Err(_) => break,
            }
        }
    }
}

#[tokio::test]
async fn wstunnel_packet_round_trips_through_ws_tls_wireguard() {
    let node_kp = WgKeypair::generate().unwrap();
    let node_pub = *node_kp.public.as_bytes();
    let node_secret = node_kp.secret;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = tls_acceptor();

    // The responder serves ONLY the secret path derived from the node's pinned key (mirrors the
    // `nil-node` gate); any other path gets a 404. This proves the client requests that exact path.
    let expected_path = derive_request_path(&node_pub);
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        #[allow(clippy::result_large_err)]
        let gate = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
            if req.uri().path() == expected_path {
                Ok(resp)
            } else {
                Err(http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(None)
                    .unwrap())
            }
        };
        let ws = tokio_tungstenite::accept_hdr_async(tls, gate).await.unwrap();
        serve(ws, node_secret).await;
    });

    let transport = WstunnelTransport::new(node_pub, Some("127.0.0.1".to_string()), Some(port));
    let target = NodeEndpoint {
        host: "127.0.0.1".to_string(),
        port,
        kind: TransportKind::Wstunnel,
        wg_pub: Some(node_pub),
        expected: None,
        grant: None,
    };
    let session = tokio::time::timeout(
        Duration::from_secs(10),
        transport.connect(target, Grant::mock()),
    )
    .await
    .expect("connect timed out")
    .expect("wstunnel connect failed");

    // A minimal well-formed IPv4 packet (header only; the echo responder doesn't inspect it).
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[9] = 17; // UDP
    let payload = [0xde, 0xad, 0xbe, 0xef];
    pkt.extend_from_slice(&payload);
    let total = (pkt.len() as u16).to_be_bytes();
    pkt[2] = total[0];
    pkt[3] = total[1];

    transport
        .send(&session, IpPacket::new(pkt.clone()))
        .await
        .unwrap();

    let got = tokio::time::timeout(Duration::from_secs(10), transport.recv(&session))
        .await
        .expect("recv timed out")
        .expect("recv failed");
    assert_eq!(
        got.as_bytes(),
        pkt.as_slice(),
        "echoed packet must match what we sent"
    );

    transport.close(session).await.unwrap();
}

/// The derived path is deterministic and key-bound: same key → same path; different key → different
/// path; and it is a single hex `/`-prefixed component (64 hex chars = 32 bytes of HKDF output).
#[test]
fn request_path_is_deterministic_and_key_bound() {
    let a = [7u8; 32];
    let b = [9u8; 32];
    let pa = derive_request_path(&a);
    let pb = derive_request_path(&b);
    assert_eq!(pa, derive_request_path(&a), "same key derives the same path");
    assert_ne!(pa, pb, "different node keys derive different paths");
    assert!(pa.starts_with('/'), "path is rooted");
    assert_eq!(pa.len(), 1 + 64, "/ + 32 bytes of lowercase hex");
    assert!(
        pa[1..].bytes().all(|c| c.is_ascii_hexdigit()),
        "path body is hex"
    );
}

/// A client that pins the WRONG node key derives the WRONG path; the responder (which serves only
/// the path derived from its real key) 404s the upgrade, so `connect` fails. This is the active-
/// probe defense: without the node's key you cannot reach the WebSocket at all.
#[tokio::test]
async fn wrong_path_is_refused() {
    let node_kp = WgKeypair::generate().unwrap();
    let node_pub = *node_kp.public.as_bytes();
    let node_secret = node_kp.secret;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = tls_acceptor();

    // Responder gates on the path derived from its REAL key.
    let expected_path = derive_request_path(&node_pub);
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(tls) = acceptor.accept(tcp).await else {
            return;
        };
        #[allow(clippy::result_large_err)]
        let gate = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
            if req.uri().path() == expected_path {
                Ok(resp)
            } else {
                Err(http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(None)
                    .unwrap())
            }
        };
        // The wrong-path upgrade is rejected here; nothing further is served.
        let _ = tokio_tungstenite::accept_hdr_async(tls, gate).await;
        let _ = node_secret;
    });

    // The client pins a DIFFERENT key, so it requests a different (wrong) path.
    let mut wrong_pub = node_pub;
    wrong_pub[0] ^= 0xff;
    assert_ne!(
        derive_request_path(&wrong_pub),
        derive_request_path(&node_pub),
        "the wrong key must derive a different path for this test to be meaningful"
    );
    let transport = WstunnelTransport::new(wrong_pub, Some("127.0.0.1".to_string()), Some(port));
    let target = NodeEndpoint {
        host: "127.0.0.1".to_string(),
        port,
        kind: TransportKind::Wstunnel,
        wg_pub: Some(wrong_pub),
        expected: None,
        grant: None,
    };
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        transport.connect(target, Grant::mock()),
    )
    .await
    .expect("connect attempt should not hang");
    assert!(
        result.is_err(),
        "connect on the wrong path must be refused (404), not establish a tunnel"
    );
}
