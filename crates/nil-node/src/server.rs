//! The MASQUE / CONNECT-IP server: a quiche QUIC + HTTP/3 accept loop that answers the
//! extended `CONNECT` with `200` and shuttles IP packets between QUIC DATAGRAMs and the
//! node's TUN. Single-threaded loop (quiche `Connection` is `!Sync`); Phase 1 focuses on a
//! single client (the demo). No identifying state is persisted.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tun_rs::AsyncDevice;

use nil_transport::connectip;

use crate::cert::DevCert;
use crate::config::NodeConfig;

const MAX_UDP_PAYLOAD: usize = 1350;

struct Client {
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    ci_stream: Option<u64>,
    flow_id: u64,
    tunnel_up: bool,
}

pub async fn run(cfg: &NodeConfig, cert: &DevCert, tun: Arc<AsyncDevice>) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(cfg.bind).await?;
    let local = socket.local_addr()?;
    tracing::info!(%local, "MASQUE/CONNECT-IP server listening");

    let mut config = build_server_config(cert)?;
    let mut h3_config = quiche::h3::Config::new()?;
    h3_config.enable_extended_connect(true);

    let mut clients: HashMap<Vec<u8>, Client> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut tun_buf = vec![0u8; 65535];
    let mut out = vec![0u8; MAX_UDP_PAYLOAD];

    loop {
        let min_timeout = clients
            .values()
            .filter_map(|c| c.conn.timeout())
            .min()
            .unwrap_or(Duration::from_secs(3600));

        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("nil-node shutting down");
                break;
            }
            r = socket.recv_from(&mut buf) => {
                match r {
                    Ok((len, from)) => {
                        if let Err(e) = handle_packet(&mut clients, &mut buf[..len], from, local, &mut config) {
                            tracing::debug!("handle_packet: {e}");
                        }
                    }
                    Err(e) => tracing::warn!("udp recv: {e}"),
                }
            }
            r = tun.recv(&mut tun_buf) => {
                match r {
                    Ok(n) => {
                        // Internet reply → finalize checksums (the kernel may hand us a
                        // partial-checksum forwarded packet) → encapsulate to the client.
                        nil_core::checksum::fix_ipv4_checksums(&mut tun_buf[..n]);
                        if let Some(client) = clients.values_mut().find(|c| c.tunnel_up) {
                            let dg = connectip::encode_datagram(client.flow_id, &tun_buf[..n]);
                            let _ = client.conn.dgram_send(&dg);
                        }
                    }
                    Err(e) => tracing::warn!("tun recv: {e}"),
                }
            }
            _ = tokio::time::sleep(min_timeout) => {
                for c in clients.values_mut() {
                    c.conn.on_timeout();
                }
            }
        }

        // Drive H3 + decapsulate inbound client packets to the TUN.
        let mut to_tun: Vec<Vec<u8>> = Vec::new();
        for client in clients.values_mut() {
            drive_h3(client, &h3_config, &cert.spki, cfg.attest.as_ref());
            if client.h3.is_some() {
                loop {
                    match client.conn.dgram_recv(&mut buf) {
                        Ok(n) => {
                            if let Ok((_fid, ip)) = connectip::decode_datagram(&buf[..n]) {
                                to_tun.push(ip.to_vec());
                            }
                        }
                        Err(quiche::Error::Done) => break,
                        Err(_) => break,
                    }
                }
            }
        }
        for pkt in &to_tun {
            let _ = tun.send(pkt).await;
        }

        for client in clients.values_mut() {
            flush(&mut client.conn, &socket, &mut out).await;
        }
        clients.retain(|_, c| !c.conn.is_closed());
    }
    Ok(())
}

fn handle_packet(
    clients: &mut HashMap<Vec<u8>, Client>,
    pkt: &mut [u8],
    from: SocketAddr,
    local: SocketAddr,
    config: &mut quiche::Config,
) -> anyhow::Result<()> {
    let (key, ty) = {
        let hdr = quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN)?;
        (hdr.dcid.to_vec(), hdr.ty)
    };

    let info = quiche::RecvInfo { from, to: local };
    if let Some(client) = clients.get_mut(&key) {
        let _ = client.conn.recv(pkt, info);
        return Ok(());
    }

    if ty != quiche::Type::Initial {
        return Ok(()); // unknown connection, not an Initial — ignore
    }

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    getrandom::getrandom(&mut scid).map_err(|_| anyhow::anyhow!("scid entropy"))?;
    let scid_cid = quiche::ConnectionId::from_ref(&scid);
    let conn = quiche::accept(&scid_cid, None, local, from, config)?;
    tracing::info!(%from, "new QUIC connection accepted");

    let mut client = Client { conn, h3: None, ci_stream: None, flow_id: 0, tunnel_up: false };
    let _ = client.conn.recv(pkt, info);
    clients.insert(scid.to_vec(), client);
    Ok(())
}

fn drive_h3(
    client: &mut Client,
    h3_config: &quiche::h3::Config,
    node_spki: &[u8],
    attest: Option<&crate::attest::NodeAttest>,
) {
    if client.h3.is_none() && client.conn.is_established() {
        match quiche::h3::Connection::with_transport(&mut client.conn, h3_config) {
            Ok(h3) => client.h3 = Some(h3),
            Err(e) => {
                tracing::warn!("h3 with_transport: {e}");
                return;
            }
        }
    }
    let Some(h3) = client.h3.as_mut() else { return };

    loop {
        match h3.poll(&mut client.conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                let method = header_value(&list, b":method");
                let protocol = header_value(&list, b":protocol");
                if method.as_deref() == Some(&b"CONNECT"[..])
                    && protocol.as_deref() == Some(&b"connect-ip"[..])
                {
                    let mut resp = vec![
                        quiche::h3::Header::new(b":status", b"200"),
                        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
                    ];
                    // RA-TLS: bind a report to our TLS key + the client's nonce and return it
                    // so the client can appraise us before sending traffic (spec §5).
                    if let Some(nonce_hex) = header_value(&list, connectip::ATTEST_NONCE_HEADER.as_bytes()) {
                        if let Some(nb) = connectip::from_hex(&nonce_hex) {
                            if let Ok(nonce) = <[u8; 32]>::try_from(nb.as_slice()) {
                                if let Some(report) = crate::attest::report_hex(node_spki, attest, &nonce) {
                                    resp.push(quiche::h3::Header::new(
                                        connectip::ATTEST_REPORT_HEADER.as_bytes(),
                                        report.as_bytes(),
                                    ));
                                }
                            }
                        }
                    }
                    if h3.send_response(&mut client.conn, stream_id, &resp, false).is_ok() {
                        client.ci_stream = Some(stream_id);
                        client.flow_id = stream_id / 4;
                        client.tunnel_up = true;
                        tracing::info!(stream_id, flow_id = stream_id / 4, "CONNECT-IP tunnel up");
                    }
                } else {
                    let resp = [quiche::h3::Header::new(b":status", b"501")];
                    let _ = h3.send_response(&mut client.conn, stream_id, &resp, true);
                }
            }
            Ok((sid, quiche::h3::Event::Finished)) | Ok((sid, quiche::h3::Event::Reset(_))) => {
                if Some(sid) == client.ci_stream {
                    client.tunnel_up = false;
                }
            }
            Ok(_) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(e) => {
                tracing::warn!("h3 poll: {e}");
                break;
            }
        }
    }
}

async fn flush(conn: &mut quiche::Connection, socket: &UdpSocket, out: &mut [u8]) {
    loop {
        match conn.send(out) {
            Ok((len, info)) => {
                if socket.send_to(&out[..len], info.to).await.is_err() {
                    return;
                }
            }
            Err(quiche::Error::Done) => return,
            Err(e) => {
                tracing::warn!("conn.send: {e}");
                let _ = conn.close(false, 0x1, b"send");
                return;
            }
        }
    }
}

fn build_server_config(cert: &DevCert) -> anyhow::Result<quiche::Config> {
    let cert_path = cert.cert_path.to_str().ok_or_else(|| anyhow::anyhow!("cert path"))?;
    let key_path = cert.key_path.to_str().ok_or_else(|| anyhow::anyhow!("key path"))?;
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file(cert_path)?;
    config.load_priv_key_from_pem_file(key_path)?;
    config.set_application_protos(&[b"h3"])?;
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
    Ok(config)
}

fn header_value(list: &[quiche::h3::Header], name: &[u8]) -> Option<Vec<u8>> {
    use quiche::h3::NameValue;
    list.iter().find(|h| h.name() == name).map(|h| h.value().to_vec())
}
