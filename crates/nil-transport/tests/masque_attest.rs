//! Accept/reject proof for the MASQUE attestation gate, driven through the real
//! `MasqueTransport::connect` path — not just the `nil-attest` appraiser unit.
//!
//! Stands up a minimal in-process MASQUE / CONNECT-IP node on loopback (a real quiche QUIC + H3
//! server with a self-signed RA-TLS cert) that answers the extended `CONNECT` with `200` and a
//! synthetic attestation report bound to ITS cert SPKI + the client's freshness nonce. Then drives
//! the production `MasqueTransport` against it:
//!
//!  - **accept**: a client that pins the node's real measurement appraises the report and the
//!    `connect` future resolves to a `Session`.
//!  - **reject**: a client that pins a DIFFERENT measurement must refuse — `connect` errors and no
//!    tunnel comes up (kill-switch holds). This exercises the single ready gate (`attest_peer`)
//!    over the wire, including the cert-SPKI + nonce binding, which the appraiser unit alone can't.
//!
//! Only built under `synthetic-attest` (the synthetic trust anchor is unreachable otherwise).

#![cfg(feature = "synthetic-attest")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nil_core::{AttestExpectation, Grant, Measurement, NodeEndpoint, Tee, TransportKind};
use nil_transport::{connectip, MasqueTransport, Transport};
use tokio::net::UdpSocket;

const MAX_UDP_PAYLOAD: usize = 1420;

/// The node's pinned measurement (what an honest, matching client expects).
const NODE_MEASUREMENT: [u8; 48] = [0x5Au8; 48];

/// A self-signed RA-TLS dev cert written to a temp dir; carries the SPKI the report binds to.
struct TestCert {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    spki: Vec<u8>,
    dir: std::path::PathBuf,
}

impl TestCert {
    fn generate() -> TestCert {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let spki = nil_attest::ratls::spki_of(ck.cert.der()).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "nil-masque-attest-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, ck.cert.pem()).unwrap();
        std::fs::write(&key_path, ck.key_pair.serialize_pem()).unwrap();
        TestCert { cert_path, key_path, spki, dir }
    }
}

impl Drop for TestCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn server_config(cert: &TestCert) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file(cert.cert_path.to_str().unwrap())
        .unwrap();
    config
        .load_priv_key_from_pem_file(cert.key_path.to_str().unwrap())
        .unwrap();
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.enable_dgram(true, 65536, 65536);
    config
}

fn header_value<'a>(list: &'a [quiche::h3::Header], name: &[u8]) -> Option<&'a [u8]> {
    use quiche::h3::NameValue;
    list.iter().find(|h| h.name() == name).map(|h| h.value())
}

/// A minimal single-connection MASQUE node: accept one QUIC connection, answer the CONNECT-IP
/// request with `200` + a synthetic attestation report bound to (cert SPKI, client nonce). Runs
/// until the client closes or the test drops the task.
async fn run_node(socket: UdpSocket, cert: Arc<TestCert>, local: SocketAddr) {
    let mut config = server_config(&cert);
    let mut h3_config = quiche::h3::Config::new().unwrap();
    h3_config.enable_extended_connect(true);

    let mut buf = vec![0u8; 65535];
    let mut out = vec![0u8; MAX_UDP_PAYLOAD];

    // Accept exactly one connection (no Retry — this is a loopback test, not the spoof-DoS path).
    let mut conn: Option<quiche::Connection> = None;
    let mut h3: Option<quiche::h3::Connection> = None;
    let mut answered = false;

    loop {
        let timeout = conn
            .as_ref()
            .and_then(|c| c.timeout())
            .unwrap_or(Duration::from_millis(50));
        tokio::select! {
            r = socket.recv_from(&mut buf) => {
                let Ok((len, from)) = r else { continue };
                let info = quiche::RecvInfo { from, to: local };
                if conn.is_none() {
                    let hdr = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };
                    if hdr.ty != quiche::Type::Initial { continue; }
                    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
                    getrandom::getrandom(&mut scid).unwrap();
                    let scid = quiche::ConnectionId::from_ref(&scid);
                    let mut c = quiche::accept(&scid, None, local, from, &mut config).unwrap();
                    let _ = c.recv(&mut buf[..len], info);
                    conn = Some(c);
                } else if let Some(c) = conn.as_mut() {
                    let _ = c.recv(&mut buf[..len], info);
                }
            }
            _ = tokio::time::sleep(timeout) => {
                if let Some(c) = conn.as_mut() { c.on_timeout(); }
            }
        }

        let Some(c) = conn.as_mut() else { continue };
        if h3.is_none() && c.is_established() {
            if let Ok(h) = quiche::h3::Connection::with_transport(c, &h3_config) {
                h3 = Some(h);
            }
        }
        if let Some(h) = h3.as_mut() {
            loop {
                match h.poll(c) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        if answered { continue; }
                        // Build the synthetic report hex for the client's nonce. The owned string
                        // outlives `resp` (which borrows its bytes) below.
                        let report_hex: Option<String> =
                            header_value(&list, connectip::ATTEST_NONCE_HEADER.as_bytes())
                                .and_then(connectip::from_hex)
                                .and_then(|nb| <[u8; 32]>::try_from(nb.as_slice()).ok())
                                .map(|nonce| {
                                    let evidence = nil_attest::testkit::synthetic_evidence(
                                        Tee::SevSnp,
                                        &NODE_MEASUREMENT,
                                        &cert.spki,
                                        &nonce,
                                    );
                                    connectip::to_hex(&evidence)
                                });
                        let mut resp = vec![
                            quiche::h3::Header::new(b":status", b"200"),
                            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
                        ];
                        if let Some(rh) = report_hex.as_deref() {
                            resp.push(quiche::h3::Header::new(
                                connectip::ATTEST_REPORT_HEADER.as_bytes(),
                                rh.as_bytes(),
                            ));
                        }
                        let _ = h.send_response(c, stream_id, &resp, false);
                        answered = true;
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(_) => break,
                }
            }
        }

        // Flush.
        loop {
            match c.send(&mut out) {
                Ok((len, info)) => {
                    let _ = socket.send_to(&out[..len], info.to).await;
                }
                Err(quiche::Error::Done) => break,
                Err(_) => break,
            }
        }
        if c.is_closed() {
            return;
        }
    }
}

fn endpoint(port: u16, measurement: [u8; 48]) -> NodeEndpoint {
    NodeEndpoint {
        host: "127.0.0.1".to_string(),
        port,
        kind: TransportKind::Masque,
        wg_pub: None,
        expected: Some(AttestExpectation {
            tee: Tee::SevSnp,
            measurement: Measurement(measurement.to_vec()),
            min_tcb_sevsnp: None,
        }),
        grant: None,
    }
}

async fn spawn_node() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();
    let port = local.port();
    let cert = Arc::new(TestCert::generate());
    tokio::spawn(run_node(socket, cert, local));
    port
}

#[tokio::test]
async fn masque_connect_accepts_a_matching_attestation() {
    let port = spawn_node().await;
    let transport = MasqueTransport::new();
    // Client pins the node's REAL measurement → the report appraises → tunnel comes up.
    let target = endpoint(port, NODE_MEASUREMENT);
    let session = tokio::time::timeout(
        Duration::from_secs(10),
        transport.connect(target, Grant { token: Vec::new(), nonce: [0x11u8; 32] }),
    )
    .await
    .expect("connect must not hang")
    .expect("a matching attestation must be accepted");
    assert_eq!(session.kind, TransportKind::Masque);
    let _ = transport.close(session).await;
}

#[tokio::test]
async fn masque_connect_rejects_a_mismatched_measurement() {
    let port = spawn_node().await;
    let transport = MasqueTransport::new();
    // Client pins a DIFFERENT measurement → appraisal fails → connect errors, no tunnel.
    let mut wrong = NODE_MEASUREMENT;
    wrong[0] ^= 0xff;
    let target = endpoint(port, wrong);
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        transport.connect(target, Grant { token: Vec::new(), nonce: [0x22u8; 32] }),
    )
    .await
    .expect("connect must not hang");
    assert!(
        res.is_err(),
        "a mismatched measurement must be refused (kill-switch holds — no tunnel)"
    );
}
