//! MASQUE / CONNECT-IP client transport (architecture spec §4.1), built on `quiche`.
//!
//! This is the default production transport: an HTTP/3 extended `CONNECT` with
//! `:protocol=connect-ip` (RFC 9484) over QUIC on UDP 443, with IP packets carried as
//! HTTP/3 DATAGRAMs (framed by [`crate::connectip`]). On the wire it is ordinary
//! HTTPS/QUIC.
//!
//! ## Structure
//! `quiche::Connection` is single-threaded (`!Sync`), so each session has exactly one
//! **driver task** that owns the connection and the UDP socket and runs the QUIC/H3 event
//! loop. [`MasqueTransport::send`]/[`recv`](MasqueTransport::recv) cross bounded channels
//! to/from that task — the [`Transport`] seam stays identical to loopback.
//!
//! ## Phase 1 caveat (honest)
//! TLS peer verification is currently a dev placeholder (`verify_peer(false)` when
//! [`MasqueConfig::insecure_dev`]); this is **NOT attestation**. `nil-attest` RA-TLS
//! (SEV-SNP/TDX appraisal) replaces it in Phase 2 (spec §5).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use nil_core::{Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;

use crate::connectip;
use crate::Transport;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const OUTBOUND_QUEUE: usize = 1024;
const INBOUND_QUEUE: usize = 1024;
const MAX_UDP_PAYLOAD: usize = 1350;

/// Client-side MASQUE configuration.
#[derive(Clone, Debug)]
pub struct MasqueConfig {
    /// TLS SNI / `:authority`. Defaults to the target host at connect time.
    pub server_name: Option<String>,
    /// Phase 1 dev: skip TLS peer verification (self-signed node cert). NOT attestation.
    pub insecure_dev: bool,
}

impl Default for MasqueConfig {
    fn default() -> Self {
        // Phase 1 default trusts the dev node cert without verification (RA-TLS is Phase 2).
        Self { server_name: None, insecure_dev: true }
    }
}

/// Heavy per-session state, owned by the transport and keyed by [`SessionId`].
struct MasqueSession {
    to_wire: mpsc::Sender<IpPacket>,
    from_wire: AsyncMutex<mpsc::Receiver<IpPacket>>,
    shutdown: CancellationToken,
    _driver: tokio::task::JoinHandle<()>,
    /// Max writable QUIC datagram payload negotiated at handshake.
    max_dgram_payload: usize,
}

/// The default, production MASQUE/QUIC transport.
#[derive(Default)]
pub struct MasqueTransport {
    config: MasqueConfig,
    next_id: AtomicU64,
    sessions: Mutex<HashMap<SessionId, Arc<MasqueSession>>>,
}

impl MasqueTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: MasqueConfig) -> Self {
        Self { config, ..Default::default() }
    }

    /// Usable tunnel MTU for a session (datagram payload minus CONNECT-IP framing overhead),
    /// so the datapath can size the TUN device.
    pub fn tunnel_mtu(&self, session: &Session) -> Option<usize> {
        let s = self.state(session).ok()?;
        Some(s.max_dgram_payload.saturating_sub(connectip::MAX_FRAMING_OVERHEAD))
    }

    fn state(&self, session: &Session) -> Result<Arc<MasqueSession>> {
        let map = self
            .sessions
            .lock()
            .map_err(|_| Error::Transport("masque session map poisoned".into()))?;
        map.get(&session.id).cloned().ok_or(Error::SessionNotFound(session.id))
    }
}

#[async_trait]
impl Transport for MasqueTransport {
    async fn connect(&self, target: NodeEndpoint, _creds: Grant) -> Result<Session> {
        let peer = resolve(&target).await?;
        let bind: SocketAddr = if peer.is_ipv6() {
            "[::]:0".parse().expect("valid v6 bind")
        } else {
            "0.0.0.0:0".parse().expect("valid v4 bind")
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| Error::Transport(format!("udp bind: {e}")))?;
        let local = socket
            .local_addr()
            .map_err(|e| Error::Transport(format!("local_addr: {e}")))?;

        let (to_tx, to_rx) = mpsc::channel(OUTBOUND_QUEUE);
        let (from_tx, from_rx) = mpsc::channel(INBOUND_QUEUE);
        let (ready_tx, ready_rx) = oneshot::channel();
        let shutdown = CancellationToken::new();

        let authority = self
            .config
            .server_name
            .clone()
            .unwrap_or_else(|| target.host.clone());
        let driver = tokio::spawn(driver_run(
            socket,
            peer,
            local,
            authority,
            self.config.insecure_dev,
            to_rx,
            from_tx,
            ready_tx,
            shutdown.clone(),
        ));

        let ready = match tokio::time::timeout(HANDSHAKE_TIMEOUT, ready_rx).await {
            Ok(Ok(Ok(info))) => info,
            Ok(Ok(Err(e))) => {
                shutdown.cancel();
                return Err(e);
            }
            Ok(Err(_)) => {
                shutdown.cancel();
                return Err(Error::Transport("masque driver exited before handshake".into()));
            }
            Err(_) => {
                shutdown.cancel();
                return Err(Error::Transport("masque handshake timed out".into()));
            }
        };

        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let state = Arc::new(MasqueSession {
            to_wire: to_tx,
            from_wire: AsyncMutex::new(from_rx),
            shutdown,
            _driver: driver,
            max_dgram_payload: ready.max_dgram_payload,
        });
        self.sessions
            .lock()
            .map_err(|_| Error::Transport("masque session map poisoned".into()))?
            .insert(id, state);
        Ok(Session { id, kind: TransportKind::Masque })
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
                .map_err(|_| Error::Transport("masque session map poisoned".into()))?;
            map.remove(&session.id)
        }
        .ok_or(Error::SessionNotFound(session.id))?;
        s.shutdown.cancel();
        Ok(())
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Masque
    }

    fn fingerprint_profile(&self) -> Profile {
        Profile::HttpsQuic
    }
}

/// Resolve a [`NodeEndpoint`] to a socket address.
async fn resolve(target: &NodeEndpoint) -> Result<SocketAddr> {
    let host_port = format!("{}:{}", target.host, target.port);
    let mut addrs = tokio::net::lookup_host(host_port.clone())
        .await
        .map_err(|e| Error::Transport(format!("resolve {host_port}: {e}")))?;
    addrs
        .next()
        .ok_or_else(|| Error::Transport(format!("no address for {host_port}")))
}

struct ReadyInfo {
    max_dgram_payload: usize,
}

#[allow(clippy::too_many_arguments)]
async fn driver_run(
    socket: UdpSocket,
    peer: SocketAddr,
    local: SocketAddr,
    authority: String,
    insecure_dev: bool,
    mut to_rx: mpsc::Receiver<IpPacket>,
    from_tx: mpsc::Sender<IpPacket>,
    ready_tx: oneshot::Sender<Result<ReadyInfo>>,
    shutdown: CancellationToken,
) {
    let mut ready_tx = Some(ready_tx);
    macro_rules! fail {
        ($e:expr) => {{
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(Err($e));
            }
        }};
    }

    let mut config = match build_client_config(insecure_dev) {
        Ok(c) => c,
        Err(e) => {
            fail!(e);
            return;
        }
    };

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    if getrandom::getrandom(&mut scid_bytes).is_err() {
        fail!(Error::Transport("scid entropy unavailable".into()));
        return;
    }
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = match quiche::connect(Some(&authority), &scid, local, peer, &mut config) {
        Ok(c) => c,
        Err(e) => {
            fail!(Error::Transport(format!("quiche connect: {e}")));
            return;
        }
    };

    let h3_config = match quiche::h3::Config::new() {
        Ok(c) => c,
        Err(e) => {
            fail!(Error::Transport(format!("h3 config: {e}")));
            return;
        }
    };

    let mut h3: Option<quiche::h3::Connection> = None;
    let mut ci_stream: Option<u64> = None;
    let mut flow_id: u64 = 0;
    let mut out = vec![0u8; MAX_UDP_PAYLOAD];
    let mut buf = vec![0u8; 65535];

    flush(&mut conn, &socket, &mut out).await;

    loop {
        let timeout = conn.timeout().unwrap_or(Duration::from_secs(3600));
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                let _ = conn.close(true, 0x100, b"bye");
                flush(&mut conn, &socket, &mut out).await;
                return;
            }
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((len, from)) => {
                        let info = quiche::RecvInfo { from, to: local };
                        if let Err(e) = conn.recv(&mut buf[..len], info) {
                            tracing::debug!("masque conn.recv: {e}");
                        }
                    }
                    Err(e) => tracing::warn!("masque udp recv: {e}"),
                }
            }
            _ = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
            maybe = to_rx.recv(), if h3.is_some() => {
                match maybe {
                    Some(pkt) => {
                        let dg = connectip::encode_datagram(flow_id, pkt.as_bytes());
                        if let Err(e) = conn.dgram_send(&dg) {
                            tracing::trace!("masque dgram_send drop: {e}");
                        }
                    }
                    None => {
                        // All app senders dropped → close cleanly.
                        let _ = conn.close(true, 0x100, b"done");
                        flush(&mut conn, &socket, &mut out).await;
                        return;
                    }
                }
            }
        }

        // Establish H3 + send the CONNECT-IP request once the QUIC handshake completes.
        if h3.is_none() && conn.is_established() {
            match quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
                Ok(mut h3c) => {
                    let headers = connect_ip_headers(&authority);
                    match h3c.send_request(&mut conn, &headers, false) {
                        Ok(sid) => {
                            ci_stream = Some(sid);
                            flow_id = sid / 4;
                            h3 = Some(h3c);
                        }
                        Err(e) => {
                            fail!(Error::Transport(format!("send CONNECT-IP: {e}")));
                            let _ = conn.close(true, 0x101, b"req");
                            flush(&mut conn, &socket, &mut out).await;
                            return;
                        }
                    }
                }
                Err(e) => {
                    fail!(Error::Transport(format!("h3 with_transport: {e}")));
                    return;
                }
            }
        }

        // Drain H3 events (response status, stream teardown).
        if let Some(h3c) = h3.as_mut() {
            loop {
                match h3c.poll(&mut conn) {
                    Ok((sid, quiche::h3::Event::Headers { list, .. })) => {
                        if Some(sid) == ci_stream {
                            match status_of(&list) {
                                Some(code) if (200..300).contains(&code) => {
                                    if let Some(tx) = ready_tx.take() {
                                        let mdp = conn.dgram_max_writable_len().unwrap_or(1200);
                                        let _ = tx.send(Ok(ReadyInfo { max_dgram_payload: mdp }));
                                        tracing::info!(%peer, flow_id, "MASQUE CONNECT-IP established");
                                    }
                                }
                                other => {
                                    fail!(Error::Transport(format!(
                                        "CONNECT-IP refused: status {other:?}"
                                    )));
                                    let _ = conn.close(true, 0x102, b"status");
                                    flush(&mut conn, &socket, &mut out).await;
                                    return;
                                }
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Finished))
                    | Ok((sid, quiche::h3::Event::Reset(_))) => {
                        if Some(sid) == ci_stream {
                            fail!(Error::Closed);
                            let _ = conn.close(true, 0x103, b"tunnel-closed");
                            flush(&mut conn, &socket, &mut out).await;
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => {
                        tracing::warn!("masque h3 poll: {e}");
                        break;
                    }
                }
            }
        }

        // Drain inbound IP packets carried as QUIC DATAGRAMs.
        if h3.is_some() {
            loop {
                match conn.dgram_recv(&mut buf) {
                    Ok(len) => match connectip::decode_datagram(&buf[..len]) {
                        Ok((fid, ip)) if fid == flow_id => {
                            let _ = from_tx.try_send(IpPacket::new(ip.to_vec()));
                        }
                        _ => {}
                    },
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        tracing::debug!("masque dgram_recv: {e}");
                        break;
                    }
                }
            }
        }

        flush(&mut conn, &socket, &mut out).await;

        if conn.is_closed() {
            fail!(Error::Closed);
            tracing::info!(%peer, "MASQUE connection closed");
            return;
        }
    }
}

/// Send all pending QUIC packets out the UDP socket.
async fn flush(conn: &mut quiche::Connection, socket: &UdpSocket, out: &mut [u8]) {
    loop {
        match conn.send(out) {
            Ok((len, info)) => {
                if let Err(e) = socket.send_to(&out[..len], info.to).await {
                    tracing::warn!("masque udp send: {e}");
                    return;
                }
            }
            Err(quiche::Error::Done) => return,
            Err(e) => {
                tracing::warn!("masque conn.send: {e}");
                let _ = conn.close(false, 0x1, b"send");
                return;
            }
        }
    }
}

fn build_client_config(insecure_dev: bool) -> Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| Error::Transport(format!("quiche config: {e}")))?;
    config
        .set_application_protos(&[b"h3"])
        .map_err(|e| Error::Transport(format!("set_application_protos: {e}")))?;
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
    if insecure_dev {
        // Phase 1 dev only — NOT attestation. Replaced by nil-attest RA-TLS in Phase 2.
        config.verify_peer(false);
        tracing::warn!(
            "DEV INSECURE: TLS peer verification DISABLED — connection is NOT attested (Phase 1 dev only)"
        );
    }
    Ok(config)
}

fn connect_ip_headers(authority: &str) -> Vec<quiche::h3::Header> {
    use quiche::h3::Header;
    vec![
        Header::new(b":method", b"CONNECT"),
        Header::new(b":protocol", b"connect-ip"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", authority.as_bytes()),
        Header::new(b":path", connectip::IP_FULL_TUNNEL_TEMPLATE.as_bytes()),
        Header::new(b"capsule-protocol", b"?1"),
    ]
}

fn status_of(list: &[quiche::h3::Header]) -> Option<u16> {
    use quiche::h3::NameValue;
    list.iter()
        .find(|h| h.name() == b":status")
        .and_then(|h| std::str::from_utf8(h.value()).ok())
        .and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_and_profile_are_masque() {
        let t = MasqueTransport::new();
        assert_eq!(t.kind(), TransportKind::Masque);
        assert_eq!(t.fingerprint_profile(), Profile::HttpsQuic);
    }
}
