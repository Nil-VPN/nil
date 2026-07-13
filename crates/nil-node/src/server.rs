//! The MASQUE / CONNECT-IP server: a quiche QUIC + HTTP/3 accept loop that answers the
//! extended `CONNECT` with `200` and shuttles IP packets between QUIC DATAGRAMs and the
//! node's TUN. Single-threaded loop (quiche `Connection` is `!Sync`); serves many clients
//! concurrently, each assigned a unique inner IP from an address pool and routed by destination IP
//! (see `crate::pool` + `client_routes`). No identifying state is persisted.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tun_rs::AsyncDevice;

use boringtun::x25519::StaticSecret;
use nil_transport::connectip;
use nil_transport::pqwg::{WgKeypair, WgStep};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::cert::NodeCert;
use crate::config::NodeConfig;
use crate::grant_replay::{GrantReplayCache, ReplayError};
use crate::pqwg::ClientPqWg;

// Must match the client's `nil_transport::masque` value: the negotiated datagram size is the
// min of both peers' advertised `max_udp_payload_size`, so a lower value here would re-cap every
// hop and starve the trust-split onion's innermost QUIC of its 1200 B floor. 1420 keeps the wire
// packet (+28 B IPv4/UDP) under 1500.
const MAX_UDP_PAYLOAD: usize = 1420;
/// Hard cap on decoded HTTP/3 request fields. CONNECT-IP needs only a few small pseudo-headers, a
/// 64-byte nonce hex value, and one bounded NWG2 token.
const MAX_FIELD_SECTION_SIZE: u64 = 8 * 1024;

/// When a client has NO pool-assigned inner address (ADDRESS_ASSIGN fallback — pool exhausted, at
/// most one such client routes at a time), cap how many distinct inner source IPs it may register.
/// Bounds `client_routes` so a single authenticated tunnel cannot stream packets with attacker-
/// chosen (esp. IPv6, 2^128) inner sources and grow the map until the node OOMs. Clients WITH an
/// assigned address are bound to exactly that one IP (see `learn_client_route`).
const MAX_LEARNED_ROUTES_PER_CLIENT: usize = 4;

/// Packet destinations admitted after CONNECT-IP authorization. Only an exit may inject arbitrary
/// inner IP into its TUN; entry/middle connections carry one Coordinator-signed exact next hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketPolicy {
    Exit,
    Relay(SocketAddrV4),
}

impl PacketPolicy {
    /// Apply the signed relay boundary to a fully decapsulated inner packet. Intermediate traffic
    /// must be one complete, unfragmented IPv4 UDP datagram to the exact signed address and port.
    /// This prevents direct-to-exit, reordered-path, IPv6, and arbitrary UDP/443 relay attempts.
    fn admits(self, packet: &[u8]) -> bool {
        match self {
            Self::Exit => true,
            Self::Relay(endpoint) => relay_packet_targets(packet, endpoint),
        }
    }
}

struct Client {
    conn: quiche::Connection,
    /// IP proven reachable by the stateless Retry exchange. The server disables QUIC active
    /// migration and retains this address for predecessor-bound NWG2 authorization.
    peer_ip: IpAddr,
    h3: Option<quiche::h3::Connection>,
    ci_stream: Option<u64>,
    flow_id: u64,
    tunnel_up: bool,
    /// Signed NWG2 onward-routing policy retained for the lifetime of this CONNECT-IP tunnel.
    packet_policy: Option<PacketPolicy>,
    /// Inner IPv4 this client was assigned from the pool (RFC 9484 ADDRESS_ASSIGN subset), once the
    /// CONNECT-IP tunnel came up. Released back to the pool on disconnect.
    assigned_ip: Option<std::net::Ipv4Addr>,
    /// Per-client PQ-WireGuard responder state (`Some` only when `NW_NODE_PQWG` is set).
    pqwg: Option<ClientPqWg>,
}

pub async fn run(cfg: &NodeConfig, cert: &NodeCert, tun: Arc<AsyncDevice>) -> anyhow::Result<()> {
    // Capture this before accepting traffic. The replay cache rejects grants minted before this
    // process started, so restarting cannot broadly erase the single-use history.
    let process_started_at = nil_core::grant::now_unix_secs_for_expiry();
    let mut grant_replays = GrantReplayCache::new(process_started_at, cfg.grant_replay_capacity);
    let socket = UdpSocket::bind(cfg.bind).await?;
    let local = socket.local_addr()?;
    tracing::info!(%local, "MASQUE/CONNECT-IP server listening");

    let mut config = build_server_config(cert)?;
    let mut h3_config = quiche::h3::Config::new()?;
    h3_config.enable_extended_connect(true);
    h3_config.set_max_field_section_size(MAX_FIELD_SECTION_SIZE);

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
                        match handle_packet(
                            &mut clients,
                            &mut buf[..len],
                            from,
                            local,
                            &mut config,
                            pqwg_enabled,
                            &retry_key,
                            cfg.max_connections,
                            cfg.max_connections_per_ip,
                        ) {
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
                &mut grant_replays,
            );
            if client.h3.is_none() {
                continue;
            }
            // Never admit client datagrams before an authorized CONNECT-IP stream exists.
            // H3 transport setup alone is not an authorization event: an unauthenticated peer can
            // otherwise inject raw IP into the exit TUN before authorize_connect() runs.
            if !client.tunnel_up {
                while client.conn.dgram_recv(&mut buf).is_ok() {}
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
            let packet_policy = client.packet_policy;
            for dg in raw {
                // Cover-traffic padding (context id 1) and malformed datagrams are dropped here —
                // padding must never reach the exit TUN (it carries no inner packet).
                let payload = match connectip::decode_datagram(&dg) {
                    Ok((fid, connectip::DatagramPayload::Ip(ip)))
                        if accepts_client_datagrams(client.tunnel_up, fid, client.flow_id) =>
                    {
                        ip
                    }
                    Ok((_fid, connectip::DatagramPayload::Ip(_))) => continue,
                    Ok((_fid, connectip::DatagramPayload::Padding)) => continue,
                    Err(_) => continue,
                };
                match client.pqwg.as_mut().and_then(|p| p.tunn.as_mut()) {
                    // PQ-WireGuard active: the datagram is a WG transport message.
                    Some(tunn) => {
                        let mut input = payload.to_vec();
                        loop {
                            match tunn.decapsulate(&input) {
                                WgStep::Ip(ip) => {
                                    if packet_policy.is_some_and(|policy| policy.admits(&ip))
                                        && learn_client_route(
                                            &mut client_routes,
                                            client_id,
                                            assigned,
                                            &ip,
                                        )
                                    {
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
                    None => {
                        if pqwg_enabled {
                            // PQ-WireGuard node, but this client's inner tunnel is NOT yet
                            // established: a datagram here is a premature/opening WG message, NEVER a
                            // raw IP packet. Drop it (fail closed) rather than mis-route it to the
                            // TUN — the client retransmits its WG handshake init until the responder
                            // (built from the control-channel PQ offer) has created `tunn`. This also
                            // means a PQ node never routes un-encapsulated inner traffic. (Required
                            // for the all-PQ multi-hop onion, where every hop is a PQ responder.)
                            continue;
                        }
                        // Plain MASQUE node: the datagram is a raw IP packet.
                        if packet_policy.is_some_and(|policy| policy.admits(payload))
                            && learn_client_route(&mut client_routes, client_id, assigned, payload)
                        {
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
#[allow(clippy::too_many_arguments)]
fn handle_packet(
    clients: &mut HashMap<Vec<u8>, Client>,
    pkt: &mut [u8],
    from: SocketAddr,
    local: SocketAddr,
    config: &mut quiche::Config,
    pqwg_enabled: bool,
    retry_key: &crate::retry::RetryKey,
    max_connections: usize,
    max_connections_per_ip: usize,
) -> anyhow::Result<Option<Vec<u8>>> {
    let hdr = quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN)?;
    let key = hdr.dcid.to_vec();

    let info = quiche::RecvInfo { from, to: local };
    if let Some(client) = clients.get_mut(&key) {
        if client.peer_ip != from.ip() {
            tracing::debug!("dropping QUIC packet whose source IP differs from validated peer");
            return Ok(None);
        }
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
        let len = quiche::retry(
            &hdr.scid,
            &hdr.dcid,
            &new_scid,
            &new_token,
            hdr.version,
            &mut out,
        )?;
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
    let same_source = clients
        .values()
        .filter(|client| client.peer_ip == from.ip())
        .take(max_connections_per_ip)
        .count();
    if !connection_capacity_available(
        clients.len(),
        same_source,
        max_connections,
        max_connections_per_ip,
    ) {
        tracing::debug!("dropping new QUIC connection at capacity");
        return Ok(None);
    }
    let conn = quiche::accept(&scid_cid, Some(&odcid_cid), local, from, config)?;
    // Deliberately emit no per-connection success event: even without source addresses, timestamped
    // accepts would turn the default node log into a session-volume timeline (PD-2/PD-3).

    let mut client = Client {
        conn,
        peer_ip: from.ip(),
        h3: None,
        ci_stream: None,
        flow_id: 0,
        tunnel_up: false,
        packet_policy: None,
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

/// Admit only within both process-wide and Retry-validated source-address ceilings. Kept pure so
/// boundary behavior is regression-tested without constructing heavyweight QUIC connections.
fn connection_capacity_available(
    total: usize,
    same_source: usize,
    max_total: usize,
    max_per_source: usize,
) -> bool {
    total < max_total && same_source < max_per_source
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
    grant_replays: &mut GrantReplayCache,
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
                if method == Some(&b"CONNECT"[..]) && protocol == Some(&b"connect-ip"[..]) {
                    // One source-validated QUIC connection carries at most one CONNECT-IP tunnel.
                    // A second stream must not replace the signed route policy or reinterpret two
                    // one-use grants as multiplexed authorization on one transport connection.
                    if client.ci_stream.is_some() {
                        let resp = [quiche::h3::Header::new(b":status", b"409")];
                        let _ = h3.send_response(&mut client.conn, stream_id, &resp, true);
                        continue;
                    }
                    let packet_policy = match authorize_connect(
                        &list,
                        cfg,
                        node_spki,
                        client.peer_ip,
                        grant_replays,
                    ) {
                        Ok(policy) => policy,
                        Err(reason) => {
                            // No peer/path fields and no default-level per-session event: a normal
                            // node log must not reconstruct a connection timeline.
                            tracing::debug!(reason, "CONNECT-IP authorization refused");
                            let resp = [quiche::h3::Header::new(b":status", b"403")];
                            let _ = h3.send_response(&mut client.conn, stream_id, &resp, true);
                            continue;
                        }
                    };
                    // ADDRESS_ASSIGN (RFC 9484 subset): allocate a UNIQUE inner IPv4 for this
                    // client from the pool. Idempotent per connection. If the pool is exhausted the
                    // response omits the header — the client then keeps its configured address
                    // (single-client fallback); only one such client can be routed at a time, but we
                    // never hand two clients the same live address.
                    let assigned = pool.assign(client_id);
                    if assigned.is_none() {
                        tracing::warn!(
                            "address pool exhausted; client keeps its configured address"
                        );
                    }
                    // Build the 200 response (capsule-protocol + optional ADDRESS_ASSIGN + optional
                    // RA-TLS report bound to our TLS key + the client's nonce). Pure + unit-tested.
                    let resp =
                        build_connect_ok_response(&list, assigned, node_spki, cfg.attest.as_ref());
                    if h3
                        .send_response(&mut client.conn, stream_id, &resp, false)
                        .is_ok()
                    {
                        client.ci_stream = Some(stream_id);
                        client.flow_id = stream_id / 4;
                        client.tunnel_up = true;
                        client.packet_policy = Some(packet_policy);
                        // Record + pre-register the assigned address so replies route to this
                        // client even before its first outbound packet, and so the route is bound
                        // to this connection authoritatively (not just learned-on-first-packet).
                        if let Some(ip) = assigned {
                            client.assigned_ip = Some(ip);
                            routes.insert(IpAddr::V4(ip), client_id.to_vec());
                        }
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
                    client.packet_policy = None;
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
    // Batch equal-size QUIC packets to the same peer and hand each run to the kernel via UDP GSO
    // (one sendmsg on Linux); fall back to per-packet send_to otherwise. A packet SHORTER than the
    // running segment size is the final segment of a GSO batch (GSO requires equal segments except
    // the last), so it closes the current batch.
    let mut batch: Vec<u8> = Vec::new();
    let mut seg: usize = 0;
    let mut dest: Option<SocketAddr> = None;
    loop {
        match conn.send(out) {
            Ok((len, info)) => {
                // A destination change (rare within one connection) flushes the current batch first.
                if let Some(d) = dest {
                    if d != info.to {
                        send_batch(socket, &batch, seg, d).await;
                        batch.clear();
                        seg = 0;
                    }
                }
                dest = Some(info.to);
                if seg == 0 || len == seg {
                    if seg == 0 {
                        seg = len;
                    }
                    batch.extend_from_slice(&out[..len]);
                } else if len < seg {
                    // Short packet: append as the final segment, then flush the batch.
                    batch.extend_from_slice(&out[..len]);
                    send_batch(socket, &batch, seg, info.to).await;
                    batch.clear();
                    seg = 0;
                } else {
                    // len > seg (a larger packet after a shorter run): flush, then start anew.
                    send_batch(socket, &batch, seg, info.to).await;
                    batch.clear();
                    batch.extend_from_slice(&out[..len]);
                    seg = len;
                }
                // Bound the batch to the kernel's ~64-segment / 64 KiB GSO limit.
                if seg > 0 && (batch.len() >= 64 * seg || batch.len() >= 60_000) {
                    send_batch(socket, &batch, seg, info.to).await;
                    batch.clear();
                    seg = 0;
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                tracing::warn!("conn.send: {e}");
                let _ = conn.close(false, 0x1, b"send");
                break;
            }
        }
    }
    if let Some(d) = dest {
        send_batch(socket, &batch, seg, d).await;
    }
}

/// Emit one accumulated egress batch: a single `send_to` for one packet, a UDP GSO `sendmsg` for a
/// multi-segment batch on Linux, or a per-segment `send_to` fallback (non-Linux, or a kernel without
/// GSO). `batch` is a concatenation of `seg`-sized packets whose final segment may be shorter.
async fn send_batch(socket: &UdpSocket, batch: &[u8], seg: usize, dest: SocketAddr) {
    if batch.is_empty() || seg == 0 {
        return;
    }
    if batch.len() <= seg {
        let _ = socket.send_to(batch, dest).await;
        return;
    }
    if crate::gso::send_segmented(socket, batch, seg, dest)
        .await
        .is_ok()
    {
        return;
    }
    let mut off = 0;
    while off < batch.len() {
        let end = (off + seg).min(batch.len());
        if socket.send_to(&batch[off..end], dest).await.is_err() {
            return;
        }
        off = end;
    }
}

fn build_server_config(cert: &NodeCert) -> anyhow::Result<quiche::Config> {
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
    // This endpoint accepts one small CONNECT request and a bounded PQ control exchange. QUIC
    // DATAGRAM traffic is not charged to stream flow-control, so multi-megabyte windows and one
    // hundred public streams only enlarged unauthenticated memory exposure.
    config.set_initial_max_data(512 * 1024);
    config.set_initial_max_stream_data_bidi_local(64 * 1024);
    config.set_initial_max_stream_data_bidi_remote(64 * 1024);
    config.set_initial_max_stream_data_uni(64 * 1024);
    config.set_initial_max_streams_bidi(4);
    config.set_initial_max_streams_uni(8);
    config.set_disable_active_migration(true);
    config.enable_dgram(true, 65536, 65536);
    Ok(config)
}

fn header_value<'a>(list: &'a [quiche::h3::Header], name: &[u8]) -> Option<&'a [u8]> {
    use quiche::h3::NameValue;
    list.iter().find(|h| h.name() == name).map(|h| h.value())
}

/// Borrow one security-sensitive header and reject ambiguous duplicate encodings.
fn unique_header_value<'a>(
    list: &'a [quiche::h3::Header],
    name: &[u8],
) -> Result<Option<&'a [u8]>, &'static str> {
    use quiche::h3::NameValue;
    let mut matches = list.iter().filter(|header| header.name() == name);
    let value = matches.next().map(|header| header.value());
    if matches.next().is_some() {
        return Err("duplicate authorization header");
    }
    Ok(value)
}

fn is_lower_hex(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
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
    if let Some(nonce_hex) =
        unique_header_value(request_headers, connectip::ATTEST_NONCE_HEADER.as_bytes())
            .ok()
            .flatten()
    {
        if nonce_hex.len() == 64 && is_lower_hex(nonce_hex) {
            let Some(nb) = connectip::from_hex(nonce_hex) else {
                return resp;
            };
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

fn authorize_connect(
    headers: &[quiche::h3::Header],
    cfg: &NodeConfig,
    node_spki: &[u8],
    peer_ip: IpAddr,
    grant_replays: &mut GrantReplayCache,
) -> Result<PacketPolicy, &'static str> {
    let nonce_hex = unique_header_value(headers, connectip::ATTEST_NONCE_HEADER.as_bytes())?
        .ok_or("missing attestation nonce")?;
    if nonce_hex.len() != 64 || !is_lower_hex(nonce_hex) {
        return Err("malformed attestation nonce");
    }
    let nonce_bytes = connectip::from_hex(nonce_hex).ok_or("malformed attestation nonce")?;
    let nonce =
        <[u8; 32]>::try_from(nonce_bytes.as_slice()).map_err(|_| "malformed attestation nonce")?;

    let Some(verifier) = cfg.grant_verifier.as_ref() else {
        #[cfg(debug_assertions)]
        {
            if cfg.allow_ungranted {
                if cfg.role != crate::config::NodeRole::Exit {
                    return Err("ungranted intermediate has no exact next-hop policy");
                }
                tracing::warn!("accepting grantless CONNECT-IP in development mode");
                return Ok(PacketPolicy::Exit);
            }
        }
        #[cfg(not(debug_assertions))]
        let _ = cfg.allow_ungranted;
        return Err("grant verifier not configured");
    };
    let attest = cfg
        .attest
        .as_ref()
        .ok_or("attested node identity not configured")?;
    let realm = cfg
        .grant_realm
        .as_deref()
        .ok_or("grant realm not configured")?;
    let node_id = cfg.node_id.as_deref().ok_or("node id not configured")?;
    // Derive the audience from the actual live certificate, never from environment/config. A
    // cloned VM can self-assert the same node_id and measurement, but its TLS key hashes
    // differently and therefore cannot satisfy the victim node's Coordinator-signed NWG2 grant.
    let tls_spki_sha256: [u8; 32] = Sha256::digest(node_spki).into();
    let node_identity = nil_core::grant::GrantNodeIdentity::new(
        realm,
        node_id,
        cfg.role.grant_role(),
        nil_core::grant::GrantTransport::Masque,
        attest.tee,
        attest.measurement,
        tls_spki_sha256,
    )
    .map_err(|_| "invalid node grant identity")?;
    let grant_hex = unique_header_value(headers, connectip::TUNNEL_GRANT_HEADER.as_bytes())?
        .ok_or("missing tunnel grant")?;
    if grant_hex.is_empty()
        || grant_hex.len() > nil_core::grant::MAX_GRANT_TOKEN_LEN * 2
        || grant_hex.len() % 2 != 0
        || !is_lower_hex(grant_hex)
    {
        return Err("malformed tunnel grant");
    }
    let grant = connectip::from_hex(grant_hex).ok_or("malformed tunnel grant")?;
    // Fail CLOSED on a broken clock: `now_unix_secs_for_expiry` returns u64::MAX on a clock error,
    // so an expired grant is rejected rather than accepted (a plain `now = 0` would make `exp < now`
    // always false → every expired grant accepted, defeating the TTL).
    let now = nil_core::grant::now_unix_secs_for_expiry();
    let verified = verifier
        .verify_for_node(&grant, &node_identity, now)
        .map_err(|_| "invalid tunnel grant")?;
    if verified
        .audience
        .previous_hop()
        .is_some_and(|expected| peer_ip != IpAddr::V4(expected))
    {
        return Err("tunnel grant predecessor mismatch");
    }
    // Constant-time for consistency with the attestation report_data/measurement comparisons. The
    // nonce isn't a secret a holder cannot already see, so this is hygiene rather than a live
    // oracle. Binding it here prevents replaying a valid grant onto a different QUIC connection.
    if !bool::from(verified.nonce.ct_eq(&nonce)) {
        return Err("tunnel grant nonce mismatch");
    }
    grant_replays
        .consume(&verified, now)
        .map_err(|error| match error {
            ReplayError::Replayed => "tunnel grant already used",
            ReplayError::PredatesProcess => "tunnel grant predates node process",
            ReplayError::Capacity => "tunnel grant replay cache full",
            ReplayError::Expired => "invalid tunnel grant",
        })?;
    match verified.audience.next_hop() {
        Some(endpoint) => Ok(PacketPolicy::Relay(endpoint)),
        None => Ok(PacketPolicy::Exit),
    }
}

/// Parse only the IPv4/UDP fields required by the relay boundary, with strict length and fragment
/// checks. No allocation and no address resolution occurs on this attacker-controlled path.
fn relay_packet_targets(packet: &[u8], endpoint: SocketAddrV4) -> bool {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return false;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20
        || ihl
            .checked_add(8)
            .map_or(true, |minimum| minimum > packet.len())
    {
        return false;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len != packet.len() || total_len < ihl + 8 {
        return false;
    }
    // Reject reserved flag, MF, and every nonzero fragment offset. DF (0x4000) is permitted.
    let flags_and_offset = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_and_offset & 0xbfff != 0 || packet[9] != 17 {
        return false;
    }
    if packet[16..20] != endpoint.ip().octets() {
        return false;
    }
    let udp_len = usize::from(u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]));
    if udp_len < 8 || ihl.checked_add(udp_len) != Some(total_len) {
        return false;
    }
    u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]) == endpoint.port()
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
            tracing::debug!("dropping packet from duplicate tunnel source address");
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
                let learned = routes
                    .values()
                    .filter(|id| id.as_slice() == client_id)
                    .count();
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

fn accepts_client_datagrams(tunnel_up: bool, flow_id: u64, authorized_flow_id: u64) -> bool {
    tunnel_up && flow_id == authorized_flow_id
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
    use nil_core::grant::{
        GrantAudience, GrantRole, GrantSigningKey, GrantTransport, GrantVerifier,
    };
    use nil_core::Tee;
    use quiche::h3::{Header, NameValue};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    const TEST_REALM: &str = "prod-us-east";
    const TEST_NODE_ID: &str = "exit-1";
    const TEST_MEASUREMENT: [u8; 48] = [0xabu8; 48];
    const TEST_NODE_SPKI: &[u8] = b"test-node-stable-tls-subject-public-key-info";

    fn test_next_hop() -> SocketAddrV4 {
        "192.0.2.80:443".parse().unwrap()
    }

    fn test_previous_hop() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

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

    fn audience(
        realm: &str,
        node_id: &str,
        role: GrantRole,
        transport: GrantTransport,
        tee: Tee,
        measurement: [u8; 48],
    ) -> GrantAudience {
        GrantAudience::new(
            realm,
            node_id,
            role,
            transport,
            tee,
            measurement,
            Sha256::digest(TEST_NODE_SPKI).into(),
            match role {
                GrantRole::Entry => None,
                GrantRole::Middle | GrantRole::Exit => Some(test_previous_hop()),
            },
            match role {
                GrantRole::Entry | GrantRole::Middle => Some(test_next_hop()),
                GrantRole::Exit => None,
            },
        )
        .unwrap()
    }

    fn request_with_grant(
        signing_key: &GrantSigningKey,
        grant_audience: &GrantAudience,
        nonce: [u8; 32],
    ) -> Vec<Header> {
        let grant = nil_core::grant::mint(
            signing_key,
            grant_audience,
            nonce,
            Duration::from_secs(120),
            nil_core::grant::now_unix_secs(),
        )
        .unwrap();
        let mut headers = request_with_nonce(&nonce);
        headers.push(Header::new(
            connectip::TUNNEL_GRANT_HEADER.as_bytes(),
            connectip::to_hex(&grant.token).as_bytes(),
        ));
        headers
    }

    fn configured_cfg(verifier: GrantVerifier) -> NodeConfig {
        let mut cfg = test_cfg(false);
        cfg.attest = Some(crate::attest::NodeAttest {
            tee: Tee::SevSnp,
            measurement: TEST_MEASUREMENT,
        });
        cfg.role = crate::config::NodeRole::Exit;
        cfg.grant_verifier = Some(verifier);
        cfg.grant_realm = Some(TEST_REALM.into());
        cfg.node_id = Some(TEST_NODE_ID.into());
        cfg
    }

    fn authorize(headers: &[Header], cfg: &NodeConfig) -> Result<PacketPolicy, &'static str> {
        let started = nil_core::grant::now_unix_secs_for_expiry().saturating_sub(1);
        let mut replays = GrantReplayCache::new(started, 128);
        authorize_connect(
            headers,
            cfg,
            TEST_NODE_SPKI,
            IpAddr::V4(test_previous_hop()),
            &mut replays,
        )
    }

    fn expected_audience() -> GrantAudience {
        audience(
            TEST_REALM,
            TEST_NODE_ID,
            GrantRole::Exit,
            GrantTransport::Masque,
            Tee::SevSnp,
            TEST_MEASUREMENT,
        )
    }

    fn ipv4_udp_packet(destination: Ipv4Addr, port: u16, flags_and_offset: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        let total_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[6..8].copy_from_slice(&flags_and_offset.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 74, 0, 2]);
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&49152u16.to_be_bytes());
        packet[22..24].copy_from_slice(&port.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        packet
    }

    #[test]
    fn ok_response_is_200_with_capsule_protocol() {
        // No assignment, no attest config → just the status + capsule-protocol line.
        let resp = build_connect_ok_response(&request_with_nonce(&[0u8; 32]), None, b"spki", None);
        assert_eq!(
            find(&resp, b":status"),
            Some(&b"200"[..]),
            "CONNECT-IP accepted with 200"
        );
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
        assert!(learn_client_route(
            &mut routes,
            cid,
            Some(assigned),
            &v4([10, 74, 0, 9])
        ));
        for i in 0..1000u16 {
            let src = [100, 0, (i >> 8) as u8, (i & 0xff) as u8];
            assert!(
                !learn_client_route(&mut routes, cid, Some(assigned), &v4(src)),
                "a source other than the assigned address must be dropped"
            );
        }
        let mut v6src = [0u8; 16];
        v6src[0] = 0xfd;
        assert!(
            !learn_client_route(&mut routes, cid, Some(assigned), &v6(v6src)),
            "spoofed v6 dropped"
        );
        assert_eq!(
            routes.len(),
            1,
            "an assigned client is bound to exactly one route"
        );

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
        assert_eq!(
            learned, MAX_LEARNED_ROUTES_PER_CLIENT,
            "fallback learning is capped"
        );
        assert_eq!(
            routes.len(),
            MAX_LEARNED_ROUTES_PER_CLIENT,
            "route table stays bounded"
        );
    }

    #[test]
    fn datagrams_require_an_authorized_matching_flow() {
        assert!(!accepts_client_datagrams(false, 7, 7));
        assert!(!accepts_client_datagrams(true, 6, 7));
        assert!(accepts_client_datagrams(true, 7, 7));
    }

    #[test]
    fn connection_admission_enforces_global_and_per_source_caps() {
        assert!(connection_capacity_available(0, 0, 1024, 32));
        assert!(connection_capacity_available(31, 31, 1024, 32));
        assert!(
            !connection_capacity_available(32, 32, 1024, 32),
            "one validated source cannot consume the whole global pool"
        );
        assert!(
            connection_capacity_available(32, 1, 1024, 32),
            "another source retains an independent admission budget"
        );
        assert!(!connection_capacity_available(1024, 0, 1024, 32));
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
        let cert = NodeCert::generate(vec!["localhost".into()]).expect("dev cert");
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
        let mut client = quiche::connect(
            Some("localhost"),
            &cscid,
            client_addr,
            server_addr,
            &mut client_config,
        )
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
                        if let Some(resp) = handle_packet(
                            &mut clients,
                            &mut pkt,
                            client_addr,
                            server_addr,
                            &mut server_config,
                            false,
                            &retry_key,
                            1024,
                            32,
                        )
                        .expect("handle_packet")
                        {
                            // A stateless reply (Retry / version negotiation) — feed it back.
                            saw_retry = true;
                            let mut rb = resp;
                            let _ = client.recv(
                                &mut rb,
                                quiche::RecvInfo {
                                    from: server_addr,
                                    to: client_addr,
                                },
                            );
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
                            let _ = client.recv(
                                &mut out[..len],
                                quiche::RecvInfo {
                                    from: server_addr,
                                    to: client_addr,
                                },
                            );
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

        assert!(
            saw_retry,
            "the node must challenge the first Initial with a Retry"
        );
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
        let evidence = connectip::from_hex(report_hex).expect("report header is lowercase hex");

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
        let wrong_policy = AppraisalPolicy::new(Tee::SevSnp, Measurement(vec![0x00u8; 48]));
        assert!(
            appraise(&evidence, spki, &wrong_policy, &nonce).is_err(),
            "the report must NOT appraise against a different pinned measurement"
        );
    }

    #[test]
    fn authorize_accepts_nwg2_for_exact_node_audience_and_connection_nonce() {
        let signer = GrantSigningKey::from_seed([0x11; 32]);
        let cfg =
            configured_cfg(GrantVerifier::from_public_key(signer.public_key_bytes()).unwrap());
        let headers = request_with_grant(&signer, &expected_audience(), [0x42; 32]);
        assert_eq!(authorize(&headers, &cfg), Ok(PacketPolicy::Exit));
        let mut clone_replays = GrantReplayCache::new(
            nil_core::grant::now_unix_secs_for_expiry().saturating_sub(1),
            128,
        );
        assert_eq!(
            authorize_connect(
                &headers,
                &cfg,
                b"clone-cert-key-with-the-same-node-id-and-measurement",
                IpAddr::V4(test_previous_hop()),
                &mut clone_replays,
            ),
            Err("invalid tunnel grant"),
            "a victim-node grant must not authorize a clone presenting another TLS key"
        );
    }

    #[test]
    fn intermediate_authorization_retains_the_signed_next_hop() {
        let signer = GrantSigningKey::from_seed([0x12; 32]);
        let mut cfg =
            configured_cfg(GrantVerifier::from_public_key(signer.public_key_bytes()).unwrap());
        cfg.role = crate::config::NodeRole::Middle;
        let relay_audience = audience(
            TEST_REALM,
            TEST_NODE_ID,
            GrantRole::Middle,
            GrantTransport::Masque,
            Tee::SevSnp,
            TEST_MEASUREMENT,
        );
        let headers = request_with_grant(&signer, &relay_audience, [0x43; 32]);
        assert_eq!(
            authorize(&headers, &cfg),
            Ok(PacketPolicy::Relay(test_next_hop()))
        );
    }

    #[test]
    fn later_hop_grants_require_the_retry_validated_predecessor_ip() {
        let signer = GrantSigningKey::from_seed([0x13; 32]);
        let verifier = GrantVerifier::from_public_key(signer.public_key_bytes()).unwrap();

        for (role, expected_policy, nonce) in [
            (
                GrantRole::Middle,
                PacketPolicy::Relay(test_next_hop()),
                [0x51; 32],
            ),
            (GrantRole::Exit, PacketPolicy::Exit, [0x52; 32]),
        ] {
            let mut cfg = configured_cfg(verifier.clone());
            cfg.role = match role {
                GrantRole::Middle => crate::config::NodeRole::Middle,
                GrantRole::Exit => crate::config::NodeRole::Exit,
                GrantRole::Entry => unreachable!(),
            };
            let grant_audience = audience(
                TEST_REALM,
                TEST_NODE_ID,
                role,
                GrantTransport::Masque,
                Tee::SevSnp,
                TEST_MEASUREMENT,
            );
            let headers = request_with_grant(&signer, &grant_audience, nonce);
            let started = nil_core::grant::now_unix_secs_for_expiry().saturating_sub(1);
            let mut replays = GrantReplayCache::new(started, 128);

            assert_eq!(
                authorize_connect(
                    &headers,
                    &cfg,
                    TEST_NODE_SPKI,
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)),
                    &mut replays,
                ),
                Err("tunnel grant predecessor mismatch"),
                "a client dialing a later hop directly must be rejected"
            );
            assert_eq!(
                authorize_connect(
                    &headers,
                    &cfg,
                    TEST_NODE_SPKI,
                    IpAddr::V6("2001:db8::1".parse().unwrap()),
                    &mut replays,
                ),
                Err("tunnel grant predecessor mismatch")
            );
            assert_eq!(
                authorize_connect(
                    &headers,
                    &cfg,
                    TEST_NODE_SPKI,
                    IpAddr::V4(test_previous_hop()),
                    &mut replays,
                ),
                Ok(expected_policy),
                "a predecessor mismatch must not consume the valid one-use grant"
            );
        }
    }

    #[test]
    fn intermediate_packet_gate_allows_only_exact_unfragmented_ipv4_udp_socket() {
        let endpoint = test_next_hop();
        let policy = PacketPolicy::Relay(endpoint);
        assert!(policy.admits(&ipv4_udp_packet(*endpoint.ip(), endpoint.port(), 0)));
        assert!(policy.admits(&ipv4_udp_packet(*endpoint.ip(), endpoint.port(), 0x4000))); // DF is not fragmentation.

        assert!(!policy.admits(&ipv4_udp_packet(*endpoint.ip(), 8443, 0)));
        assert!(!policy.admits(&ipv4_udp_packet(Ipv4Addr::new(203, 0, 113, 90), 443, 0))); // arbitrary UDP/443 / direct-to-exit attempt
        assert!(!policy.admits(&ipv4_udp_packet(Ipv4Addr::new(198, 51, 100, 19), 443, 0))); // reordered middle hop

        for fragment_bits in [0x2000, 0x0001, 0x2001, 0x8000] {
            assert!(
                !policy.admits(&ipv4_udp_packet(
                    *endpoint.ip(),
                    endpoint.port(),
                    fragment_bits
                )),
                "fragment/reserved bits {fragment_bits:#06x} must fail closed"
            );
        }

        let mut tcp = ipv4_udp_packet(*endpoint.ip(), endpoint.port(), 0);
        tcp[9] = 6;
        assert!(!policy.admits(&tcp));

        let mut ipv6 = vec![0u8; 48];
        ipv6[0] = 0x60;
        ipv6[4..6].copy_from_slice(&8u16.to_be_bytes());
        ipv6[6] = 17;
        ipv6[40..42].copy_from_slice(&49152u16.to_be_bytes());
        ipv6[42..44].copy_from_slice(&endpoint.port().to_be_bytes());
        ipv6[44..46].copy_from_slice(&8u16.to_be_bytes());
        assert!(!policy.admits(&ipv6));

        let mut trailing = ipv4_udp_packet(*endpoint.ip(), endpoint.port(), 0);
        trailing.push(0);
        assert!(!policy.admits(&trailing));
        assert!(PacketPolicy::Exit.admits(&ipv6));
    }

    #[test]
    fn authorize_rejects_every_nwg2_audience_dimension_mismatch() {
        let signer = GrantSigningKey::from_seed([0x22; 32]);
        let cfg =
            configured_cfg(GrantVerifier::from_public_key(signer.public_key_bytes()).unwrap());
        let cases = [
            (
                "realm",
                audience(
                    "prod-eu-west",
                    TEST_NODE_ID,
                    GrantRole::Exit,
                    GrantTransport::Masque,
                    Tee::SevSnp,
                    TEST_MEASUREMENT,
                ),
            ),
            (
                "node id",
                audience(
                    TEST_REALM,
                    "exit-2",
                    GrantRole::Exit,
                    GrantTransport::Masque,
                    Tee::SevSnp,
                    TEST_MEASUREMENT,
                ),
            ),
            (
                "role",
                audience(
                    TEST_REALM,
                    TEST_NODE_ID,
                    GrantRole::Middle,
                    GrantTransport::Masque,
                    Tee::SevSnp,
                    TEST_MEASUREMENT,
                ),
            ),
            (
                "transport",
                audience(
                    TEST_REALM,
                    TEST_NODE_ID,
                    GrantRole::Exit,
                    GrantTransport::AmneziaWg,
                    Tee::SevSnp,
                    TEST_MEASUREMENT,
                ),
            ),
            (
                "tee",
                audience(
                    TEST_REALM,
                    TEST_NODE_ID,
                    GrantRole::Exit,
                    GrantTransport::Masque,
                    Tee::Tdx,
                    TEST_MEASUREMENT,
                ),
            ),
            (
                "measurement",
                audience(
                    TEST_REALM,
                    TEST_NODE_ID,
                    GrantRole::Exit,
                    GrantTransport::Masque,
                    Tee::SevSnp,
                    [0xcdu8; 48],
                ),
            ),
        ];

        for (dimension, wrong_audience) in cases {
            let headers = request_with_grant(&signer, &wrong_audience, [0x43; 32]);
            assert_eq!(
                authorize(&headers, &cfg),
                Err("invalid tunnel grant"),
                "grant with wrong {dimension} must be rejected"
            );
        }

        let clone_audience = GrantAudience::new(
            TEST_REALM,
            TEST_NODE_ID,
            GrantRole::Exit,
            GrantTransport::Masque,
            Tee::SevSnp,
            TEST_MEASUREMENT,
            [0x99; 32],
            Some(test_previous_hop()),
            None,
        )
        .unwrap();
        let clone_headers = request_with_grant(&signer, &clone_audience, [0x44; 32]);
        assert_eq!(
            authorize(&clone_headers, &cfg),
            Err("invalid tunnel grant"),
            "a clone with the same self-asserted node ID and measurement but another TLS key must be rejected"
        );
    }

    #[test]
    fn authorize_rejects_untrusted_signer_and_revoked_rotation_key() {
        let active = GrantSigningKey::from_seed([0x33; 32]);
        let staged = GrantSigningKey::from_seed([0x44; 32]);
        let nonce = [0x45; 32];
        let headers = request_with_grant(&active, &expected_audience(), nonce);

        let rotating =
            GrantVerifier::new([active.public_key_bytes(), staged.public_key_bytes()]).unwrap();
        assert_eq!(
            authorize(&headers, &configured_cfg(rotating)),
            Ok(PacketPolicy::Exit)
        );

        let after_revocation = GrantVerifier::from_public_key(staged.public_key_bytes()).unwrap();
        assert_eq!(
            authorize(&headers, &configured_cfg(after_revocation)),
            Err("invalid tunnel grant"),
            "removing a key from the verifier set revokes grants signed by it"
        );

        let unknown = GrantSigningKey::from_seed([0x55; 32]);
        let unknown_headers = request_with_grant(&unknown, &expected_audience(), nonce);
        let trusted = GrantVerifier::from_public_key(active.public_key_bytes()).unwrap();
        assert_eq!(
            authorize(&unknown_headers, &configured_cfg(trusted)),
            Err("invalid tunnel grant"),
            "a valid signature from an untrusted signer is not authority"
        );
    }

    #[test]
    fn authorize_rejects_grant_bound_to_a_different_connection_nonce() {
        let signer = GrantSigningKey::from_seed([0x66; 32]);
        let cfg =
            configured_cfg(GrantVerifier::from_public_key(signer.public_key_bytes()).unwrap());
        let grant_nonce = [0x10; 32];
        let mut headers = request_with_grant(&signer, &expected_audience(), grant_nonce);
        let nonce_header = headers
            .iter_mut()
            .find(|header| header.name() == connectip::ATTEST_NONCE_HEADER.as_bytes())
            .expect("nonce header");
        *nonce_header = Header::new(
            connectip::ATTEST_NONCE_HEADER.as_bytes(),
            connectip::to_hex(&[0x20; 32]).as_bytes(),
        );
        assert_eq!(
            authorize(&headers, &cfg),
            Err("tunnel grant nonce mismatch")
        );
    }

    #[test]
    fn authorize_consumes_a_valid_grant_once() {
        let signer = GrantSigningKey::from_seed([0x67; 32]);
        let cfg =
            configured_cfg(GrantVerifier::from_public_key(signer.public_key_bytes()).unwrap());
        let headers = request_with_grant(&signer, &expected_audience(), [0x12; 32]);
        let mut replays = GrantReplayCache::new(
            nil_core::grant::now_unix_secs_for_expiry().saturating_sub(1),
            128,
        );
        assert_eq!(
            authorize_connect(
                &headers,
                &cfg,
                TEST_NODE_SPKI,
                IpAddr::V4(test_previous_hop()),
                &mut replays,
            ),
            Ok(PacketPolicy::Exit)
        );
        assert_eq!(
            authorize_connect(
                &headers,
                &cfg,
                TEST_NODE_SPKI,
                IpAddr::V4(test_previous_hop()),
                &mut replays,
            ),
            Err("tunnel grant already used")
        );
    }

    #[test]
    fn authorize_rejects_duplicate_security_headers() {
        let signer = GrantSigningKey::from_seed([0x68; 32]);
        let cfg =
            configured_cfg(GrantVerifier::from_public_key(signer.public_key_bytes()).unwrap());
        let mut duplicate_nonce = request_with_grant(&signer, &expected_audience(), [0x13; 32]);
        duplicate_nonce.push(Header::new(
            connectip::ATTEST_NONCE_HEADER.as_bytes(),
            connectip::to_hex(&[0x13; 32]).as_bytes(),
        ));
        assert_eq!(
            authorize(&duplicate_nonce, &cfg),
            Err("duplicate authorization header")
        );

        let mut duplicate_grant = request_with_grant(&signer, &expected_audience(), [0x14; 32]);
        let copied = duplicate_grant
            .iter()
            .find(|header| header.name() == connectip::TUNNEL_GRANT_HEADER.as_bytes())
            .expect("grant header")
            .value()
            .to_vec();
        duplicate_grant.push(Header::new(
            connectip::TUNNEL_GRANT_HEADER.as_bytes(),
            &copied,
        ));
        assert_eq!(
            authorize(&duplicate_grant, &cfg),
            Err("duplicate authorization header")
        );
    }

    #[test]
    fn authorize_bounds_and_canonicalizes_header_hex_before_decode() {
        let signer = GrantSigningKey::from_seed([0x69; 32]);
        let cfg =
            configured_cfg(GrantVerifier::from_public_key(signer.public_key_bytes()).unwrap());

        let mut oversized = request_with_nonce(&[0x15; 32]);
        oversized.push(Header::new(
            connectip::TUNNEL_GRANT_HEADER.as_bytes(),
            &vec![b'a'; nil_core::grant::MAX_GRANT_TOKEN_LEN * 2 + 2],
        ));
        assert_eq!(authorize(&oversized, &cfg), Err("malformed tunnel grant"));

        let mut uppercase_nonce = request_with_grant(&signer, &expected_audience(), [0xab; 32]);
        let header = uppercase_nonce
            .iter_mut()
            .find(|header| header.name() == connectip::ATTEST_NONCE_HEADER.as_bytes())
            .expect("nonce header");
        *header = Header::new(
            connectip::ATTEST_NONCE_HEADER.as_bytes(),
            connectip::to_hex(&[0xab; 32])
                .to_ascii_uppercase()
                .as_bytes(),
        );
        assert_eq!(
            authorize(&uppercase_nonce, &cfg),
            Err("malformed attestation nonce")
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
        assert_eq!(authorize(&headers, &cfg), Err("missing attestation nonce"));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn authorize_allows_ungranted_dev_node_with_nonce() {
        // allow_ungranted + no grant verifier + a nonce header → accepted (local/dev bypass).
        let cfg = test_cfg(true);
        assert!(authorize(&request_with_nonce(&[1u8; 32]), &cfg).is_ok());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn authorize_refuses_ungranted_mode_in_release_even_when_requested_programmatically() {
        let cfg = test_cfg(true);
        assert_eq!(
            authorize(&request_with_nonce(&[1u8; 32]), &cfg),
            Err("grant verifier not configured")
        );
    }

    #[test]
    fn authorize_refuses_when_grant_verifier_unconfigured_and_not_dev() {
        // Production posture: no grant verifier and NOT allow_ungranted → CONNECT-IP is refused.
        let cfg = test_cfg(false);
        assert_eq!(
            authorize(&request_with_nonce(&[1u8; 32]), &cfg),
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
            grant_verifier: None,
            grant_realm: None,
            node_id: None,
            tls_key_file: None,
            allow_ungranted,
            max_connections: 1024,
            max_connections_per_ip: 32,
            grant_replay_capacity: 65_536,
        }
    }
}
