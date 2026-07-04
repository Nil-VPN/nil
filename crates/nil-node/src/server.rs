//! The MASQUE / CONNECT-IP server: a quiche QUIC + HTTP/3 accept loop that answers the
//! extended `CONNECT` with `200` and shuttles IP packets between QUIC DATAGRAMs and the
//! node's TUN. Single-threaded loop (quiche `Connection` is `!Sync`); Phase 1 focuses on a
//! single client (the demo). No identifying state is persisted.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tun_rs::AsyncDevice;

use boringtun::x25519::StaticSecret;
use nil_transport::connectip;
use nil_transport::pqwg::{WgKeypair, WgStep};
use subtle::ConstantTimeEq;

use crate::cert::DevCert;
use crate::config::NodeConfig;
use crate::pqwg::ClientPqWg;

// Must match the client's `nil_transport::masque` value: the negotiated datagram size is the
// min of both peers' advertised `max_udp_payload_size`, so a lower value here would re-cap every
// hop and starve the trust-split onion's innermost QUIC of its 1200 B floor. 1420 keeps the wire
// packet (+28 B IPv4/UDP) under 1500.
const MAX_UDP_PAYLOAD: usize = 1420;

/// When a client has NO pool-assigned inner address (ADDRESS_ASSIGN fallback — pool exhausted, at
/// most one such client routes at a time), cap how many distinct inner source IPs it may register.
/// Bounds `client_routes` so a single authenticated tunnel cannot stream packets with attacker-
/// chosen (esp. IPv6, 2^128) inner sources and grow the map until the node OOMs. Clients WITH an
/// assigned address are bound to exactly that one IP (see `learn_client_route`).
const MAX_LEARNED_ROUTES_PER_CLIENT: usize = 4;

struct Client {
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    ci_stream: Option<u64>,
    flow_id: u64,
    tunnel_up: bool,
    /// Inner IPv4 this client was assigned from the pool (RFC 9484 ADDRESS_ASSIGN subset), once the
    /// CONNECT-IP tunnel came up. Released back to the pool on disconnect.
    assigned_ip: Option<std::net::Ipv4Addr>,
    /// Per-client PQ-WireGuard responder state (`Some` only when `NW_NODE_PQWG` is set).
    pqwg: Option<ClientPqWg>,
}

pub async fn run(cfg: &NodeConfig, cert: &DevCert, tun: Arc<AsyncDevice>) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(cfg.bind).await?;
    let local = socket.local_addr()?;
    tracing::info!(%local, "MASQUE/CONNECT-IP server listening");

    let mut config = build_server_config(cert)?;
    let mut h3_config = quiche::h3::Config::new()?;
    h3_config.enable_extended_connect(true);

    // PQ-WireGuard responder (architecture spec §4.2): when enabled, generate the node's
    // WireGuard static key and run an inner Noise tunnel keyed by the PQ hybrid PSK.
    let pqwg_enabled = std::env::var("NW_NODE_PQWG").is_ok();
    let node_wg: Option<StaticSecret> = if pqwg_enabled {
        let kp = WgKeypair::generate().map_err(|e| anyhow::anyhow!("node wg keygen: {e}"))?;
        tracing::info!(
            wg_pub = %connectip::to_hex(kp.public.as_bytes()),
            "PQ-WireGuard responder enabled — pin this as the client's NW_NODE_WG_PUB"
        );
        Some(kp.secret)
    } else {
        None
    };

    // Per-process key for stateless QUIC Retry (source-address validation). Ephemeral: not
    // persisted, regenerated each start (PD-2). See `crate::retry`.
    let retry_key = crate::retry::RetryKey::generate()?;

    // Inner-tunnel address pool (RFC 9484 ADDRESS_ASSIGN subset): hands each concurrent client a
    // unique inner IPv4 so two clients never collide on one tunnel address. In-memory only.
    let mut pool = crate::pool::AddressPool::default_v4();

    let mut clients: HashMap<Vec<u8>, Client> = HashMap::new();
    let mut client_routes: HashMap<IpAddr, Vec<u8>> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut tun_buf = vec![0u8; 65535];
    let mut out = vec![0u8; MAX_UDP_PAYLOAD];

    // Dev/staging-only PII-free data-plane counters (feature `dev-trace`; compiled out of prod).
    #[cfg(feature = "dev-trace")]
    let mut diag = crate::devtrace::Diag::new(cfg.role);

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
                        match handle_packet(&mut clients, &mut buf[..len], from, local, &mut config, pqwg_enabled, &retry_key) {
                            Ok(Some(reply)) => {
                                // A stateless Retry / version-negotiation packet: send it and keep
                                // NO connection state (the client re-Initials with the token).
                                let _ = socket.send_to(&reply, from).await;
                            }
                            Ok(None) => {}
                            Err(e) => tracing::debug!("handle_packet: {e}"),
                        }
                    }
                    Err(e) => tracing::warn!("udp recv: {e}"),
                }
            }
            r = tun.recv(&mut tun_buf) => {
                match r {
                    Ok(n) => {
                        // Internet reply → finalize checksums, IPv4 or IPv6 (the kernel may hand
                        // us a partial-checksum forwarded packet) → (PQ-WireGuard encapsulate, if
                        // enabled) → encapsulate to the client as a CONNECT-IP datagram.
                        nil_core::checksum::fix_l4_checksums(&mut tun_buf[..n]);
                        #[cfg(feature = "dev-trace")]
                        diag.record_tun_reply(n);
                        let dst = packet_dst_ip(&tun_buf[..n]);
                        if let Some(client_id) = dst.and_then(|ip| client_routes.get(&ip).cloned()) {
                            if let Some(client) = clients.get_mut(&client_id).filter(|c| c.tunnel_up) {
                                let payload = match client.pqwg.as_mut().and_then(|p| p.tunn.as_mut()) {
                                    Some(tunn) => tunn.encapsulate(&tun_buf[..n]).ok(),
                                    None => Some(tun_buf[..n].to_vec()),
                                };
                                if let Some(pl) = payload {
                                    let dg = connectip::encode_datagram(client.flow_id, &pl);
                                    let _send = client.conn.dgram_send(&dg);
                                    #[cfg(feature = "dev-trace")]
                                    match _send {
                                        Ok(()) => diag.record_to_client(dg.len()),
                                        Err(_) => {
                                            let lim = client.conn.dgram_max_writable_len().unwrap_or(0);
                                            diag.record_to_client_drop(dg.len(), dg.len() > lim);
                                        }
                                    }
                                }
                            }
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

        #[cfg(feature = "dev-trace")]
        diag.tick();

        // Drive H3 + the control channel, then bring inbound client datagrams to the TUN
        // (PQ-WireGuard-decapsulating them first when that layer is active).
        let mut to_tun: Vec<Vec<u8>> = Vec::new();
        for (client_id, client) in clients.iter_mut() {
            drive_h3(
                client,
                client_id,
                &h3_config,
                &cert.spki,
                cfg,
                node_wg.as_ref(),
                &mut pool,
                &mut client_routes,
            );
            if client.h3.is_none() {
                continue;
            }
            // Gather datagrams first so the conn borrow is released before WG decapsulation.
            let mut raw: Vec<Vec<u8>> = Vec::new();
            while let Ok(n) = client.conn.dgram_recv(&mut buf) {
                raw.push(buf[..n].to_vec());
            }
            #[cfg(feature = "dev-trace")]
            diag.record_from_client(raw.len(), raw.iter().map(Vec::len).sum());
            let mut net_replies: Vec<Vec<u8>> = Vec::new();
            // The client's pool-assigned inner address (Copy); route learning is bound to it so a
            // tunnel cannot register arbitrary/unbounded inner sources.
            let assigned = client.assigned_ip;
            for dg in raw {
                let Ok((_fid, payload)) = connectip::decode_datagram(&dg) else {
                    continue;
                };
                match client.pqwg.as_mut().and_then(|p| p.tunn.as_mut()) {
                    // PQ-WireGuard active: the datagram is a WG transport message.
                    Some(tunn) => {
                        let mut input = payload.to_vec();
                        loop {
                            match tunn.decapsulate(&input) {
                                WgStep::Ip(ip) => {
                                    if learn_client_route(&mut client_routes, client_id, assigned, &ip) {
                                        to_tun.push(ip);
                                    }
                                    break;
                                }
                                WgStep::Network(b) => {
                                    net_replies.push(b);
                                    input = Vec::new();
                                }
                                WgStep::Done | WgStep::Err(_) => break,
                            }
                        }
                    }
                    // Plain MASQUE: the datagram is a raw IP packet.
                    None => {
                        if learn_client_route(&mut client_routes, client_id, assigned, payload) {
                            to_tun.push(payload.to_vec());
                        }
                    }
                }
            }
            for r in net_replies {
                let dg = connectip::encode_datagram(client.flow_id, &r);
                let _send = client.conn.dgram_send(&dg);
                #[cfg(feature = "dev-trace")]
                match _send {
                    Ok(()) => diag.record_to_client(dg.len()),
                    Err(_) => {
                        let lim = client.conn.dgram_max_writable_len().unwrap_or(0);
                        diag.record_to_client_drop(dg.len(), dg.len() > lim);
                    }
                }
            }
        }
        #[cfg(feature = "dev-trace")]
        diag.record_to_tun(to_tun.len(), to_tun.iter().map(Vec::len).sum());
        for pkt in &to_tun {
            let _ = tun.send(pkt).await;
        }

        for client in clients.values_mut() {
            flush(&mut client.conn, &socket, &mut out).await;
        }
        // Reap closed connections, releasing each one's pool address back so it can be reassigned
        // (no persisted state outlives the live session — PD-2).
        clients.retain(|client_id, c| {
            if c.conn.is_closed() {
                pool.release(client_id);
                false
            } else {
                true
            }
        });
        client_routes.retain(|_, id| clients.contains_key(id));
    }
    Ok(())
}

/// Process one inbound UDP datagram. Returns `Some(reply)` when the node must answer with a
/// stateless packet (QUIC version negotiation or a Retry for source-address validation) and keep
/// NO connection state; `None` when the packet was fed to an existing/new connection (or dropped).
fn handle_packet(
    clients: &mut HashMap<Vec<u8>, Client>,
    pkt: &mut [u8],
    from: SocketAddr,
    local: SocketAddr,
    config: &mut quiche::Config,
    pqwg_enabled: bool,
    retry_key: &crate::retry::RetryKey,
) -> anyhow::Result<Option<Vec<u8>>> {
    let hdr = quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN)?;
    let key = hdr.dcid.to_vec();

    let info = quiche::RecvInfo { from, to: local };
    if let Some(client) = clients.get_mut(&key) {
        let _ = client.conn.recv(pkt, info);
        return Ok(None);
    }

    if hdr.ty != quiche::Type::Initial {
        return Ok(None); // unknown connection, not an Initial — ignore
    }

    // Version negotiation: an Initial advertising a version we don't speak gets a VN packet (also
    // makes the listener look like an ordinary QUIC server — Pillar 1). Stateless.
    if !quiche::version_is_supported(hdr.version) {
        let mut out = vec![0u8; MAX_UDP_PAYLOAD];
        let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)?;
        out.truncate(len);
        return Ok(Some(out));
    }

    // Source-address validation (RFC 9000 §8.1). Until the client proves it can receive at its
    // claimed address, the node commits no connection state and emits only a small Retry — closing
    // the spoofed-source amplification/DoS vector.
    let token = hdr.token.as_deref().unwrap_or_default();
    let odcid: Vec<u8> = if token.is_empty() {
        // No token yet → challenge with a Retry carrying a token bound to (source addr, this DCID).
        let mut new_scid = [0u8; quiche::MAX_CONN_ID_LEN];
        getrandom::getrandom(&mut new_scid).map_err(|_| anyhow::anyhow!("scid entropy"))?;
        let new_scid = quiche::ConnectionId::from_ref(&new_scid);
        let new_token = retry_key.mint(&from, &hdr.dcid);
        let mut out = vec![0u8; MAX_UDP_PAYLOAD];
        let len = quiche::retry(&hdr.scid, &hdr.dcid, &new_scid, &new_token, hdr.version, &mut out)?;
        out.truncate(len);
        // No source address logged (PD-3): the data plane retains no source IP.
        tracing::debug!("QUIC Retry issued (source-address validation)");
        return Ok(Some(out));
    } else {
        // Client echoed a token: validate it for THIS source address. A forged/replayed/cross-
        // address token recovers no odcid → drop (no state committed).
        match retry_key.validate(&from, token) {
            Some(odcid) => odcid,
            None => {
                tracing::debug!("dropping Initial with an invalid Retry token");
                return Ok(None);
            }
        }
    };

    // The client copied our Retry's SCID into its DCID, so `hdr.dcid` IS our Retry SCID — and it
    // MUST become the connection's SCID. quiche derives the `retry_source_connection_id` transport
    // parameter from the scid passed to `accept`, and the client rejects the handshake with
    // InvalidTransportParam unless that matches the SCID it saw in our Retry. Generating a fresh
    // random scid here desynchronised them, breaking EVERY real (source-validated) connection while
    // the loopback tests — which skip Retry — stayed green. `odcid` (recovered from the validated
    // token) is the original pre-Retry DCID, which quiche needs to complete the handshake transcript.
    let scid_cid = quiche::ConnectionId::from_ref(&hdr.dcid);
    let odcid_cid = quiche::ConnectionId::from_ref(&odcid);
    let conn = quiche::accept(&scid_cid, Some(&odcid_cid), local, from, config)?;
    // No source address logged: nil-node is the data plane (SOUL §3 / PD-3 — no source-IP retention).
    tracing::info!("new QUIC connection accepted (source-validated)");

    let mut client = Client {
        conn,
        h3: None,
        ci_stream: None,
        flow_id: 0,
        tunnel_up: false,
        assigned_ip: None,
        pqwg: if pqwg_enabled {
            Some(ClientPqWg::default())
        } else {
            None
        },
    };
    let _ = client.conn.recv(pkt, info);
    // Key the connection by its SCID (`hdr.dcid` post-Retry = `key`): subsequent client packets
    // address it with this as their DCID, matching the `clients.get_mut(&key)` lookup above.
    clients.insert(key, client);
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn drive_h3(
    client: &mut Client,
    client_id: &[u8],
    h3_config: &quiche::h3::Config,
    node_spki: &[u8],
    cfg: &NodeConfig,
    node_secret: Option<&StaticSecret>,
    pool: &mut crate::pool::AddressPool,
    routes: &mut HashMap<IpAddr, Vec<u8>>,
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
                    if let Err(reason) = authorize_connect(&list, cfg) {
                        tracing::warn!(reason, "CONNECT-IP refused before tunnel setup");
                        let resp = [quiche::h3::Header::new(b":status", b"403")];
                        let _ = h3.send_response(&mut client.conn, stream_id, &resp, true);
                        continue;
                    }
                    // ADDRESS_ASSIGN (RFC 9484 subset): allocate a UNIQUE inner IPv4 for this
                    // client from the pool. Idempotent per connection. If the pool is exhausted the
                    // response omits the header — the client then keeps its configured address
                    // (single-client fallback); only one such client can be routed at a time, but we
                    // never hand two clients the same live address.
                    let assigned = pool.assign(client_id);
                    if assigned.is_none() {
                        tracing::warn!("address pool exhausted; client keeps its configured address");
                    }
                    // Build the 200 response (capsule-protocol + optional ADDRESS_ASSIGN + optional
                    // RA-TLS report bound to our TLS key + the client's nonce). Pure + unit-tested.
                    let resp = build_connect_ok_response(&list, assigned, node_spki, cfg.attest.as_ref());
                    if h3
                        .send_response(&mut client.conn, stream_id, &resp, false)
                        .is_ok()
                    {
                        client.ci_stream = Some(stream_id);
                        client.flow_id = stream_id / 4;
                        client.tunnel_up = true;
                        // Record + pre-register the assigned address so replies route to this
                        // client even before its first outbound packet, and so the route is bound
                        // to this connection authoritatively (not just learned-on-first-packet).
                        if let Some(ip) = assigned {
                            client.assigned_ip = Some(ip);
                            routes.insert(IpAddr::V4(ip), client_id.to_vec());
                        }
                        tracing::info!(stream_id, flow_id = stream_id / 4, "CONNECT-IP tunnel up");
                    } else if let Some(ip) = assigned {
                        // The 200 didn't go out — don't keep the address reserved for a tunnel that
                        // never came up.
                        let _ = ip;
                        pool.release(client_id);
                    }
                } else {
                    let resp = [quiche::h3::Header::new(b":status", b"501")];
                    let _ = h3.send_response(&mut client.conn, stream_id, &resp, true);
                }
            }
            Ok((sid, quiche::h3::Event::Data)) => {
                // Reliable control bytes on the CONNECT-IP stream → the PQ-WireGuard handshake
                // (the client's KEM offer). Reassembled + answered by the responder.
                if Some(sid) == client.ci_stream {
                    if let (Some(cpq), Some(secret)) = (client.pqwg.as_mut(), node_secret) {
                        let mut tmp = vec![0u8; 65535];
                        while let Ok(n) = h3.recv_body(&mut client.conn, sid, &mut tmp) {
                            cpq.on_control_bytes(secret, &tmp[..n]);
                        }
                    }
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

    // Flush any queued control replies (the PQ ciphertexts) onto the CONNECT-IP stream.
    if let (Some(sid), Some(cpq)) = (client.ci_stream, client.pqwg.as_mut()) {
        if !cpq.ctrl_out.is_empty() {
            let chunk = cpq.ctrl_out.make_contiguous();
            if let Ok(written) = h3.send_body(&mut client.conn, sid, chunk, false) {
                cpq.ctrl_out.drain(..written);
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
    let cert_path = cert
        .cert_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("cert path"))?;
    let key_path = cert
        .key_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("key path"))?;
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
    list.iter()
        .find(|h| h.name() == name)
        .map(|h| h.value().to_vec())
}

/// Build the `200` CONNECT-IP response header set: `:status 200` + `capsule-protocol: ?1`, plus
/// the ADDRESS_ASSIGN header when `assigned` is `Some`, plus the RA-TLS attestation report bound to
/// `node_spki` + the client's nonce when the request carried a well-formed nonce and a report can
/// be produced. Pure (no quiche connection, no I/O) so the wire contract is unit-testable; the
/// quiche header values own their bytes, so the returned `Vec` outlives the borrowed inputs.
fn build_connect_ok_response(
    request_headers: &[quiche::h3::Header],
    assigned: Option<std::net::Ipv4Addr>,
    node_spki: &[u8],
    attest: Option<&crate::attest::NodeAttest>,
) -> Vec<quiche::h3::Header> {
    let mut resp = vec![
        quiche::h3::Header::new(b":status", b"200"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    if let Some(ip) = assigned {
        resp.push(quiche::h3::Header::new(
            connectip::ASSIGNED_IP_HEADER.as_bytes(),
            ip.to_string().as_bytes(),
        ));
    }
    // RA-TLS: bind a report to our TLS key + the client's nonce so the client can appraise us
    // before sending traffic (spec §5). Absent/malformed nonce, or no report provider → no header,
    // and the client (which pins a measurement) then fails closed.
    if let Some(nonce_hex) = header_value(request_headers, connectip::ATTEST_NONCE_HEADER.as_bytes())
    {
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
    resp
}

fn authorize_connect(headers: &[quiche::h3::Header], cfg: &NodeConfig) -> Result<(), &'static str> {
    let nonce_hex = header_value(headers, connectip::ATTEST_NONCE_HEADER.as_bytes())
        .ok_or("missing attestation nonce")?;
    let nonce_bytes = connectip::from_hex(&nonce_hex).ok_or("malformed attestation nonce")?;
    let nonce =
        <[u8; 32]>::try_from(nonce_bytes.as_slice()).map_err(|_| "malformed attestation nonce")?;

    let Some(key) = cfg.grant_key.as_ref() else {
        if cfg.allow_ungranted {
            tracing::warn!("accepting grantless CONNECT-IP because NW_ALLOW_UNGRANTED=1");
            return Ok(());
        }
        return Err("grant verifier not configured");
    };
    let attest = cfg
        .attest
        .as_ref()
        .ok_or("attested node identity not configured")?;
    let binding = nil_core::grant::binding_for(attest.tee, &attest.measurement);
    let grant_hex = header_value(headers, connectip::TUNNEL_GRANT_HEADER.as_bytes())
        .ok_or("missing tunnel grant")?;
    let grant = connectip::from_hex(&grant_hex).ok_or("malformed tunnel grant")?;
    // Fail CLOSED on a broken clock: `now_unix_secs_for_expiry` returns u64::MAX on a clock error,
    // so an expired grant is rejected rather than accepted (a plain `now = 0` would make `exp < now`
    // always false → every expired grant accepted, defeating the TTL).
    let verified = nil_core::grant::verify(
        &grant,
        key,
        &binding,
        nil_core::grant::now_unix_secs_for_expiry(),
    )
    .map_err(|_| "invalid tunnel grant")?;
    // Constant-time, for uniformity with the rest of the auth path (the grant HMAC and the
    // attestation report_data/measurement are already compared constant-time). The nonce isn't a
    // secret a holder can't already see, so this is hygiene/consistency rather than a live oracle.
    if !bool::from(verified.nonce.ct_eq(&nonce)) {
        return Err("tunnel grant nonce mismatch");
    }
    Ok(())
}

/// Route a client's inner IP packet to the TUN, learning its inner source address on first sight.
///
/// Learning is deliberately constrained so a single authenticated tunnel cannot inflate the global
/// `routes` map (memory-exhaustion DoS) or spoof another client's inner source:
/// - With a pool-`assigned` address, ONLY that exact address is accepted (it is also pre-registered
///   at tunnel-up), so the client is bound to one route and any other/spoofed source is dropped.
/// - Without an assigned address (fallback, ≤1 routed client), distinct learned sources are capped
///   at [`MAX_LEARNED_ROUTES_PER_CLIENT`].
fn learn_client_route(
    routes: &mut HashMap<IpAddr, Vec<u8>>,
    client_id: &[u8],
    assigned: Option<std::net::Ipv4Addr>,
    packet: &[u8],
) -> bool {
    let Some(src) = packet_src_ip(packet) else {
        tracing::debug!("dropping malformed client IP packet");
        return false;
    };
    match routes.get(&src) {
        Some(owner) if owner.as_slice() != client_id => {
            tracing::warn!("dropping packet from duplicate tunnel source address");
            false
        }
        Some(_) => true,
        None => match assigned {
            // Assigned client: accept only its assigned inner IP (normally already pre-registered).
            Some(ip) if IpAddr::V4(ip) == src => {
                routes.insert(src, client_id.to_vec());
                true
            }
            Some(_) => {
                // A source other than the assigned address — a spoof/hijack attempt. Drop, and log
                // nothing user-linkable (no source IP) per PD-3.
                tracing::debug!("dropping client packet whose inner source != assigned address");
                false
            }
            // Fallback (no assigned address): bound how many distinct sources this client can learn.
            None => {
                let learned =
                    routes.values().filter(|id| id.as_slice() == client_id).count();
                if learned >= MAX_LEARNED_ROUTES_PER_CLIENT {
                    tracing::debug!("dropping client packet: per-client learned-route cap reached");
                    return false;
                }
                routes.insert(src, client_id.to_vec());
                true
            }
        },
    }
}

fn packet_src_ip(packet: &[u8]) -> Option<IpAddr> {
    packet_ip(packet, true)
}

fn packet_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    packet_ip(packet, false)
}

fn packet_ip(packet: &[u8], source: bool) -> Option<IpAddr> {
    let version = packet.first()? >> 4;
    match version {
        4 if packet.len() >= 20 => {
            let offset = if source { 12 } else { 16 };
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            )))
        }
        6 if packet.len() >= 40 => {
            let offset = if source { 8 } else { 24 };
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[offset..offset + 16]);
            Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiche::h3::{Header, NameValue};
    use std::net::Ipv4Addr;

    /// Find a response header value by (lowercase) name.
    fn find<'a>(resp: &'a [Header], name: &[u8]) -> Option<&'a [u8]> {
        resp.iter().find(|h| h.name() == name).map(|h| h.value())
    }

    /// A CONNECT-IP request header list carrying `nonce` as the lowercase-hex attest-nonce header.
    fn request_with_nonce(nonce: &[u8; 32]) -> Vec<Header> {
        vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"connect-ip"),
            Header::new(
                connectip::ATTEST_NONCE_HEADER.as_bytes(),
                connectip::to_hex(nonce).as_bytes(),
            ),
        ]
    }

    #[test]
    fn ok_response_is_200_with_capsule_protocol() {
        // No assignment, no attest config → just the status + capsule-protocol line.
        let resp = build_connect_ok_response(&request_with_nonce(&[0u8; 32]), None, b"spki", None);
        assert_eq!(find(&resp, b":status"), Some(&b"200"[..]), "CONNECT-IP accepted with 200");
        assert_eq!(
            find(&resp, b"capsule-protocol"),
            Some(&b"?1"[..]),
            "capsule-protocol negotiated"
        );
    }

    #[test]
    fn address_assign_header_present_only_when_assigned() {
        // With an assignment, the ADDRESS_ASSIGN header carries the dotted-quad inner IP.
        let ip = Ipv4Addr::new(10, 74, 0, 7);
        let resp =
            build_connect_ok_response(&request_with_nonce(&[0u8; 32]), Some(ip), b"spki", None);
        assert_eq!(
            find(&resp, connectip::ASSIGNED_IP_HEADER.as_bytes()),
            Some(b"10.74.0.7".as_slice()),
            "assigned inner IP echoed as ADDRESS_ASSIGN"
        );

        // Pool exhausted (None) → no ADDRESS_ASSIGN header (client keeps its configured address).
        let resp = build_connect_ok_response(&request_with_nonce(&[0u8; 32]), None, b"spki", None);
        assert!(
            find(&resp, connectip::ASSIGNED_IP_HEADER.as_bytes()).is_none(),
            "no ADDRESS_ASSIGN header when the pool is exhausted"
        );
    }

    #[test]
    fn no_attest_report_header_without_attest_config() {
        // No NodeAttest configured → no report header even though the request carried a nonce.
        let resp = build_connect_ok_response(&request_with_nonce(&[7u8; 32]), None, b"spki", None);
        assert!(
            find(&resp, connectip::ATTEST_REPORT_HEADER.as_bytes()).is_none(),
            "no report header when the node has no attestation identity"
        );
    }

    #[test]
    fn route_learning_is_bounded_and_bound_to_assigned_ip() {
        // Minimal IPv4/IPv6 packets carrying a chosen source address.
        fn v4(src: [u8; 4]) -> Vec<u8> {
            let mut p = vec![0u8; 20];
            p[0] = 0x45;
            p[12..16].copy_from_slice(&src);
            p
        }
        fn v6(src: [u8; 16]) -> Vec<u8> {
            let mut p = vec![0u8; 40];
            p[0] = 0x60;
            p[8..24].copy_from_slice(&src);
            p
        }
        let cid = b"client-1".as_slice();

        // Assigned client: only the assigned inner IP is ever learned; spoofed v4/v6 sources are
        // dropped and never inserted — the table cannot grow past that one route.
        let assigned = Ipv4Addr::new(10, 74, 0, 9);
        let mut routes: HashMap<IpAddr, Vec<u8>> = HashMap::new();
        assert!(learn_client_route(&mut routes, cid, Some(assigned), &v4([10, 74, 0, 9])));
        for i in 0..1000u16 {
            let src = [100, 0, (i >> 8) as u8, (i & 0xff) as u8];
            assert!(
                !learn_client_route(&mut routes, cid, Some(assigned), &v4(src)),
                "a source other than the assigned address must be dropped"
            );
        }
        let mut v6src = [0u8; 16];
        v6src[0] = 0xfd;
        assert!(!learn_client_route(&mut routes, cid, Some(assigned), &v6(v6src)), "spoofed v6 dropped");
        assert_eq!(routes.len(), 1, "an assigned client is bound to exactly one route");

        // Fallback (no assigned address): distinct learned sources are capped, so a single tunnel
        // streaming distinct inner sources cannot OOM the node.
        let mut routes: HashMap<IpAddr, Vec<u8>> = HashMap::new();
        let mut learned = 0;
        for i in 0..1000u16 {
            let src = [10, 8, (i >> 8) as u8, (i & 0xff) as u8];
            if learn_client_route(&mut routes, cid, None, &v4(src)) {
                learned += 1;
            }
        }
        assert_eq!(learned, MAX_LEARNED_ROUTES_PER_CLIENT, "fallback learning is capped");
        assert_eq!(routes.len(), MAX_LEARNED_ROUTES_PER_CLIENT, "route table stays bounded");
    }

    /// Coverage for the QUIC source-address-validation (Retry) path of `handle_packet`, which had
    /// none: drive a real quiche client through Initial → Retry → token'd Initial → `accept` →
    /// established. Guards the broad flow — Retry issuance, token mint/validate, and `accept`.
    ///
    /// HONEST SCOPE: this does NOT reproduce the specific scid-desync bug it sits next to (the node
    /// `accept`ing with a fresh random scid instead of `hdr.dcid`, so `retry_source_connection_id`
    /// mismatched the Retry and real clients got `InvalidTransportParam`). That failure only
    /// manifests over the real datapath (UDP sockets + the production driver), not this in-memory
    /// lockstep pump — verified by reintroducing the bug here and watching the test still pass. The
    /// regression guard for the scid-desync is the full-stack `deploy/verify-e2e.sh` (in CI via
    /// `dataplane-e2e.yml`), which went red→green on the fix. Kept here for the Retry-path coverage.
    #[test]
    fn retry_handshake_establishes_through_source_validation() {
        let cert = DevCert::generate(vec!["localhost".into()]).expect("dev cert");
        let mut server_config = build_server_config(&cert).expect("server config");
        let retry_key = crate::retry::RetryKey::generate().expect("retry key");

        let server_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:55555".parse().unwrap();

        // A minimal client config (params mirror the node; the self-signed RA-TLS cert is trusted
        // here because attestation is appraised at the app layer, not at the QUIC layer).
        let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        client_config.set_application_protos(&[b"h3"]).unwrap();
        client_config.verify_peer(false);
        client_config.set_max_idle_timeout(5_000);
        client_config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD);
        client_config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD);
        client_config.set_initial_max_data(1_000_000);
        client_config.set_initial_max_stream_data_bidi_local(100_000);
        client_config.set_initial_max_stream_data_bidi_remote(100_000);
        client_config.set_initial_max_streams_bidi(10);
        client_config.set_initial_max_streams_uni(10);
        // Mirror the production client's HTTPS/QUIC shaping (build_client_config / apply_quic_shape).
        // The Retry-scid desync only manifested against a client shaped like this (the trigger the
        // minimal loopback config did not reproduce), so the regression test must shape too.
        client_config.grease(true);
        client_config.set_active_connection_id_limit(4);
        client_config.set_disable_active_migration(true);
        client_config.set_max_connection_window(24 * 1024 * 1024);
        client_config.set_max_stream_window(16 * 1024 * 1024);

        let cscid = quiche::ConnectionId::from_ref(&[0x42u8; quiche::MAX_CONN_ID_LEN]);
        let mut client =
            quiche::connect(Some("localhost"), &cscid, client_addr, server_addr, &mut client_config)
                .expect("client connect");

        let mut clients: HashMap<Vec<u8>, Client> = HashMap::new();
        let mut out = [0u8; 2048];
        let mut saw_retry = false;

        // Pump packets between client and server until the client completes the handshake. Bounded
        // so a stuck handshake fails the test instead of hanging.
        for _ in 0..40 {
            // Client → server.
            loop {
                match client.send(&mut out) {
                    Ok((len, _)) => {
                        let mut pkt = out[..len].to_vec();
                        if let Some(resp) =
                            handle_packet(&mut clients, &mut pkt, client_addr, server_addr, &mut server_config, false, &retry_key)
                                .expect("handle_packet")
                        {
                            // A stateless reply (Retry / version negotiation) — feed it back.
                            saw_retry = true;
                            let mut rb = resp;
                            let _ = client.recv(&mut rb, quiche::RecvInfo { from: server_addr, to: client_addr });
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => panic!("client send: {e}"),
                }
            }
            // Server connection(s) → client.
            for c in clients.values_mut() {
                loop {
                    match c.conn.send(&mut out) {
                        Ok((len, _)) => {
                            let _ = client.recv(&mut out[..len], quiche::RecvInfo { from: server_addr, to: client_addr });
                        }
                        Err(quiche::Error::Done) => break,
                        Err(e) => panic!("server send: {e}"),
                    }
                }
            }
            if client.is_established() {
                break;
            }
        }

        assert!(saw_retry, "the node must challenge the first Initial with a Retry");
        assert!(
            client.is_established(),
            "client must complete the handshake through Retry — retry_source_connection_id must \
             match the Retry SCID (regression: a fresh random accept scid breaks this)"
        );
    }

    /// The attest-report header is only produced (and only appraises) when the `synthetic-attest`
    /// report provider is built in. Accept: the report binds to (spki, nonce) and appraises against
    /// the matching policy. Reject: the SAME report fails appraisal under a DIFFERENT nonce
    /// (freshness) — proving the binding is real, not cosmetic.
    #[cfg(feature = "synthetic-attest")]
    #[test]
    fn attest_report_header_binds_to_nonce_and_spki() {
        use nil_attest::{appraise, AppraisalPolicy};
        use nil_core::{Measurement, Tee};

        let measurement = [0xABu8; 48];
        let attest = crate::attest::NodeAttest {
            tee: Tee::SevSnp,
            measurement,
        };
        let spki = b"node-tls-spki-bytes";
        let nonce = [0x42u8; 32];

        let resp =
            build_connect_ok_response(&request_with_nonce(&nonce), None, spki, Some(&attest));
        let report_hex = find(&resp, connectip::ATTEST_REPORT_HEADER.as_bytes())
            .expect("synthetic node returns an attestation report");
        let evidence =
            connectip::from_hex(report_hex).expect("report header is lowercase hex");

        let policy = AppraisalPolicy::new(Tee::SevSnp, Measurement(measurement.to_vec()));
        // Accept: correct spki + correct nonce → appraisal succeeds.
        appraise(&evidence, spki, &policy, &nonce)
            .expect("report bound to (spki, nonce) appraises against the pinned policy");
        // Reject: a different nonce breaks the report_data freshness binding.
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 0xff;
        assert!(
            appraise(&evidence, spki, &policy, &wrong_nonce).is_err(),
            "the report must NOT appraise under a different connection nonce (freshness)"
        );
        // Reject: a different pinned measurement is refused.
        let wrong_policy =
            AppraisalPolicy::new(Tee::SevSnp, Measurement(vec![0x00u8; 48]));
        assert!(
            appraise(&evidence, spki, &wrong_policy, &nonce).is_err(),
            "the report must NOT appraise against a different pinned measurement"
        );
    }

    #[test]
    fn authorize_refuses_missing_nonce() {
        // A dev node that allows ungranted clients still requires the attestation nonce header.
        let cfg = test_cfg(true);
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"connect-ip"),
        ];
        assert_eq!(
            authorize_connect(&headers, &cfg),
            Err("missing attestation nonce")
        );
    }

    #[test]
    fn authorize_allows_ungranted_dev_node_with_nonce() {
        // allow_ungranted + no grant key + a nonce header → accepted (local/dev bypass).
        let cfg = test_cfg(true);
        assert!(authorize_connect(&request_with_nonce(&[1u8; 32]), &cfg).is_ok());
    }

    #[test]
    fn authorize_refuses_when_grant_verifier_unconfigured_and_not_dev() {
        // Production posture: no grant key and NOT allow_ungranted → CONNECT-IP is refused.
        let cfg = test_cfg(false);
        assert_eq!(
            authorize_connect(&request_with_nonce(&[1u8; 32]), &cfg),
            Err("grant verifier not configured")
        );
    }

    fn test_cfg(allow_ungranted: bool) -> NodeConfig {
        NodeConfig {
            bind: "127.0.0.1:0".parse().expect("valid addr"),
            tun_name: "nil0".into(),
            node_tun_ip: Ipv4Addr::new(10, 74, 0, 1),
            prefix: 24,
            tunnel_cidr: "10.74.0.0/24".into(),
            egress: "eth0".into(),
            mtu: 1420,
            attest: None,
            role: crate::config::NodeRole::Exit,
            grant_key: None,
            allow_ungranted,
        }
    }
}
