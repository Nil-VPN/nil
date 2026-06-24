//! Round-trip proof for the REALITY/VLESS rung (WireGuard over VLESS-gated TLS), without Docker.
//!
//! Stands up a real TLS responder on loopback (self-signed cert, the same shape as the `nil-node`
//! reality responder) that validates the VLESS auth ID, runs a WireGuard responder core, and echoes
//! decapsulated IP packets back. Then drives the production `RealityTransport` against it and asserts
//! a packet survives the full path: TCP → TLS handshake (no-verify) → length-delimited records →
//! VLESS auth gate → WG IKpsk2-less handshake → encapsulate → wire → decapsulate → echo → back to
//! the client. This exercises every glue layer in-process and deterministically.
//!
//! Mirrors `tests/wstunnel_roundtrip.rs`. See `src/reality.rs` for which REALITY properties this
//! rung does / does not yet achieve (the TLS is genuine self-signed, not a borrowed foreign-site
//! handshake — that is the remaining REALITY-specific work).

#![cfg(feature = "reality")]

use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use nil_core::{Grant, IpPacket, NodeEndpoint, TransportKind};
use nil_transport::{
    derive_auth_id, read_record_from, write_record_to, PqWgCore, RealityTransport, Transport,
    WgKeypair, WgStep, REALITY_AUTH_ID_LEN,
};
use tokio::io::{split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::TcpListener;
use tokio_rustls::server::TlsStream;

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

/// Serve exactly one client: validate its VLESS auth record, complete the WG handshake, then echo
/// every decapsulated IP packet back through the tunnel. Returns early (dropping the connection) if
/// the auth ID is wrong — exactly what the production responder does.
async fn serve<S>(tls: TlsStream<S>, node_secret: StaticSecret, expected_auth: [u8; REALITY_AUTH_ID_LEN])
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr): (ReadHalf<TlsStream<S>>, WriteHalf<TlsStream<S>>) = split(tls);

    // Record 1: [auth_id ‖ client WG pubkey].
    let Ok(hello) = read_record_from(&mut rd).await else { return };
    if hello.len() != REALITY_AUTH_ID_LEN + 32 || hello[..REALITY_AUTH_ID_LEN] != expected_auth {
        return; // wrong/short auth → drop without revealing a tunnel
    }
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(&hello[REALITY_AUTH_ID_LEN..]);
    let mut core = PqWgCore::without_psk(node_secret, PublicKey::from(client_pub), 2);

    while let Ok(rec) = read_record_from(&mut rd).await {
        let mut input = rec;
        loop {
            match core.decapsulate(&input) {
                WgStep::Ip(ip) => {
                    // Echo the inner IP packet straight back through the tunnel.
                    if let Ok(wire) = core.encapsulate(&ip) {
                        let _ = write_record_to(&mut wr, &wire).await;
                    }
                    break;
                }
                WgStep::Network(out) => {
                    if write_record_to(&mut wr, &out).await.is_err() {
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
async fn reality_packet_round_trips_through_tls_vless_wireguard() {
    let node_kp = WgKeypair::generate().unwrap();
    let node_pub = *node_kp.public.as_bytes();
    let node_secret = node_kp.secret;
    let expected_auth = derive_auth_id(&node_pub);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = tls_acceptor();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        serve(tls, node_secret, expected_auth).await;
    });

    let transport = RealityTransport::new(node_pub, Some("127.0.0.1".to_string()), Some(port));
    let target = NodeEndpoint {
        host: "127.0.0.1".to_string(),
        port,
        kind: TransportKind::Reality,
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
    .expect("reality connect failed");

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

/// The auth ID is deterministic and key-bound: same key → same ID; different key → different ID.
#[test]
fn auth_id_is_deterministic_and_key_bound() {
    let a = [7u8; 32];
    let b = [9u8; 32];
    assert_eq!(derive_auth_id(&a), derive_auth_id(&a), "same key derives the same auth id");
    assert_ne!(derive_auth_id(&a), derive_auth_id(&b), "different node keys derive different auth ids");
    assert_eq!(derive_auth_id(&a).len(), REALITY_AUTH_ID_LEN);
}

/// A client that pins the WRONG node key presents the WRONG auth ID; the responder (which validates
/// the ID derived from its real key) drops the connection, so `connect` cannot complete the inner
/// WireGuard handshake and fails. This is the VLESS shared-key defense: without the node's key you
/// cannot pass the gate.
#[tokio::test]
async fn wrong_auth_id_is_refused() {
    let node_kp = WgKeypair::generate().unwrap();
    let node_pub = *node_kp.public.as_bytes();
    let node_secret = node_kp.secret;
    // The responder validates against the auth ID derived from its REAL key.
    let expected_auth = derive_auth_id(&node_pub);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = tls_acceptor();

    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else { return };
        let Ok(tls) = acceptor.accept(tcp).await else { return };
        // Wrong auth → serve() drops the connection without revealing a tunnel.
        serve(tls, node_secret, expected_auth).await;
    });

    // The client pins a DIFFERENT key, so it derives a different (wrong) auth ID.
    let mut wrong_pub = node_pub;
    wrong_pub[0] ^= 0xff;
    assert_ne!(
        derive_auth_id(&wrong_pub),
        derive_auth_id(&node_pub),
        "the wrong key must derive a different auth id for this test to be meaningful"
    );
    let transport = RealityTransport::new(wrong_pub, Some("127.0.0.1".to_string()), Some(port));
    let target = NodeEndpoint {
        host: "127.0.0.1".to_string(),
        port,
        kind: TransportKind::Reality,
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
        "connect with the wrong auth id must be refused, not establish a tunnel"
    );
}
