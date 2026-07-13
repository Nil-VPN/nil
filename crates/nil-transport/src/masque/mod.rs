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
//! ## Trust (Phase 2)
//! The node presents a self-signed RA-TLS certificate with its SEV-SNP/TDX report embedded in
//! an X.509 extension, so BoringSSL chain verification is off (`verify_peer(false)`). All node
//! trust comes from `nil-attest` appraising that report — against the Coordinator-pinned
//! measurement and a per-connection nonce — at the single ready gate before any packet flows
//! (spec §5). No expectation pinned ⇒ the connection is unattested and the driver warns.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use nil_core::{
    Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;

use nil_attest::{appraise, AppraisalPolicy};

use crate::connectip;
use crate::Transport;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const OUTBOUND_QUEUE: usize = 1024;
const INBOUND_QUEUE: usize = 1024;
const CONTROL_QUEUE: usize = 16;
/// Max QUIC UDP payload for the **outermost** (real-socket) hop. 1420 keeps the wire packet
/// (+28 B IPv4/UDP) at 1448 — under 1500 on every common path — while leaving headroom for the
/// trust-split onion: each nested hop costs ~72 B (udpip + inner QUIC/datagram framing), so a
/// 3-hop path's innermost QUIC payload (~1258 B) still clears QUIC's mandatory 1200 B floor.
/// Nested hops derive a smaller value from the outer tunnel's negotiated MTU (see
/// [`MasqueTransport::connect_nested`]).
const MAX_UDP_PAYLOAD: usize = 1420;
/// IPv4 (20) + UDP (8) header bytes [`crate::udpip`] adds when wrapping an inner QUIC packet to
/// ride an outer tunnel. A nested hop's QUIC packets must fit in `outer_tunnel_mtu - this`.
const UDPIP_OVERHEAD: usize = 28;
/// QUIC's mandatory floor for `max_udp_payload_size` (RFC 9000 §18.2 / quiche). A nested hop
/// whose computed inner payload drops below this is rejected — the path is too deep to carry
/// QUIC within the available MTU.
const MIN_QUIC_UDP_PAYLOAD: usize = 1200;
/// Largest control-stream frame (the PQ-WireGuard handshake messages) the client will reassemble.
/// The legitimate response (ML-KEM-1024 ct ~1568 B + Classic McEliece ct ~128 B + framing) is well
/// under this; 8 KiB caps `ctrl_in` so a hostile node's oversized length prefix can't drive
/// unbounded buffering. Matches the node responder's cap (`nil-node` pqwg).
const MAX_CTRL_FRAME: usize = 8 * 1024;
/// Source address stamped on a nested hop's inner QUIC packets (the udpip wrap). It must lie
/// inside every relaying node's tunnel CIDR so the node's NAT (`MASQUERADE -s <cidr>`) rewrites
/// it on egress and the un-NAT'd reply routes back through the node's TUN. The harness uses
/// `10.74.0.0/24`, so this defaults to the client tunnel address; deployments with a different
/// inner CIDR override it via [`MasqueConfig::nested_client_ip`].
const DEFAULT_NESTED_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 74, 0, 2);
/// Source port for a nested hop's inner QUIC packets (arbitrary; each hop is a distinct node so
/// there is no conntrack collision).
const NESTED_CLIENT_PORT: u16 = 51820;

/// Client-side MASQUE configuration.
///
/// `Debug` is hand-written (not derived) because the android `socket_hook` is a closure, which is
/// not `Debug`; the impl formats the data fields and omits the hook.
#[derive(Clone, Default)]
pub struct MasqueConfig {
    /// TLS SNI / `:authority`. Defaults to the target host at connect time.
    pub server_name: Option<String>,
    /// Source address for nested hops' inner QUIC packets (see [`DEFAULT_NESTED_CLIENT_IP`]).
    /// Must lie inside the relaying nodes' tunnel CIDR. `None` ⇒ the default. Only relevant when
    /// this transport is used as the inner of a [`crate::path::PathTransport`].
    pub nested_client_ip: Option<Ipv4Addr>,
    /// Permit a connection with NO pinned attestation measurement (dev/loopback only).
    /// **Defaults to `false` — fail closed (PD-2/Pillar 2):** without a pinned measurement the
    /// tunnel refuses to come up, so a forgotten `NW_EXPECTED_MEASUREMENT` cannot silently carry
    /// traffic unattested. Set `true` (e.g. `NW_ALLOW_UNATTESTED=1`) only for local dev.
    pub allow_unattested: bool,
    /// **Android only.** Invoked with the raw fd of the outer UDP socket right after `bind` and
    /// before `connect`, so the app can `VpnService.protect(fd)` it — otherwise the tunnel's own
    /// QUIC to the node would be routed back into the VpnService TUN (a loop). Returning `false`
    /// aborts the connection fail-closed. Absent on other platforms (the desktop datapath pins a
    /// host route to the node instead).
    #[cfg(target_os = "android")]
    pub socket_hook: Option<std::sync::Arc<dyn Fn(std::os::fd::RawFd) -> bool + Send + Sync>>,
}

impl std::fmt::Debug for MasqueConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueConfig")
            .field("server_name", &self.server_name)
            .field("nested_client_ip", &self.nested_client_ip)
            .field("allow_unattested", &self.allow_unattested)
            .finish_non_exhaustive()
    }
}

/// Heavy per-session state, owned by the transport and keyed by [`SessionId`].
struct MasqueSession {
    to_wire: mpsc::Sender<IpPacket>,
    from_wire: AsyncMutex<mpsc::Receiver<IpPacket>>,
    /// Reliable control channel (length-prefixed messages over the CONNECT-IP request stream):
    /// app → driver. Used by the inner PQ-WireGuard handshake to ship its (large) KEM offer.
    ctrl_to: mpsc::Sender<Vec<u8>>,
    /// Reliable control channel: driver → app.
    ctrl_from: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    shutdown: CancellationToken,
    _driver: tokio::task::JoinHandle<()>,
    /// Max writable QUIC datagram payload negotiated at handshake.
    max_dgram_payload: usize,
    /// Inner IPv4 the node assigned via the `nil-assigned-ip` response header (RFC 9484
    /// ADDRESS_ASSIGN subset), if any. The datapath applies it to the TUN.
    assigned_ip: Option<Ipv4Addr>,
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
        Self {
            config,
            ..Default::default()
        }
    }

    /// Usable tunnel MTU for a session (datagram payload minus CONNECT-IP framing overhead),
    /// so the datapath can size the TUN device.
    pub fn tunnel_mtu(&self, session: &Session) -> Option<usize> {
        let s = self.state(session).ok()?;
        Some(
            s.max_dgram_payload
                .saturating_sub(connectip::MAX_FRAMING_OVERHEAD),
        )
    }

    /// The node-assigned inner IPv4 for a session (`nil-assigned-ip` response header), if the node
    /// signalled one. The datapath applies it to the TUN (ADDRESS_ASSIGN subset).
    pub fn assigned_ip(&self, session: &Session) -> Option<Ipv4Addr> {
        self.state(session).ok().and_then(|s| s.assigned_ip)
    }

    fn state(&self, session: &Session) -> Result<Arc<MasqueSession>> {
        let map = self
            .sessions
            .lock()
            .map_err(|_| Error::Transport("masque session map poisoned".into()))?;
        map.get(&session.id)
            .cloned()
            .ok_or(Error::SessionNotFound(session.id))
    }

    /// Send a reliable, ordered control message over the CONNECT-IP request stream (not the
    /// lossy datagram path). Used by [`crate::pqwg`] to ship the PQ-WireGuard KEM offer.
    pub async fn control_send(&self, session: &Session, msg: Vec<u8>) -> Result<()> {
        let s = self.state(session)?;
        s.ctrl_to.send(msg).await.map_err(|_| Error::Closed)
    }

    /// Receive the next reliable control message from the CONNECT-IP request stream.
    pub async fn control_recv(&self, session: &Session) -> Result<Vec<u8>> {
        let s = self.state(session)?;
        let mut rx = s.ctrl_from.lock().await;
        rx.recv().await.ok_or(Error::Closed)
    }

    /// Connect a hop **over an existing outer tunnel** — the building block of the trust-split
    /// onion (architecture spec §6). The inner QUIC rides the outer CONNECT-IP tunnel (as
    /// IPv4/UDP packets to `target`); the outer node forwards them by NAT, so the next hop sees
    /// a QUIC connection from the previous node, never the original client.
    pub async fn connect_nested(
        &self,
        target: NodeEndpoint,
        creds: Grant,
        outer: Arc<dyn Transport>,
        outer_session: Session,
    ) -> Result<Session> {
        let peer = resolve(&target).await?;
        let peer_v4 = match peer {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => {
                return Err(Error::Transport(
                    "nested MASQUE requires an IPv4 next hop".into(),
                ))
            }
        };
        // The inner QUIC packets ride the outer tunnel as IPv4/UDP, so they must fit in the
        // outer's usable MTU after udpip wrapping. Shrink this hop's QUIC payload accordingly;
        // reject if it would fall below QUIC's mandatory floor (the path is too deep).
        let outer_mtu = outer.tunnel_mtu(&outer_session).ok_or_else(|| {
            Error::Transport("nested MASQUE: outer tunnel has no negotiated MTU".into())
        })?;
        let max_udp_payload = outer_mtu
            .checked_sub(UDPIP_OVERHEAD)
            .filter(|&m| m >= MIN_QUIC_UDP_PAYLOAD)
            .ok_or_else(|| {
                Error::Transport(format!(
                    "nested MASQUE: path too deep — outer MTU {outer_mtu}B leaves < {MIN_QUIC_UDP_PAYLOAD}B \
                     for the inner QUIC payload"
                ))
            })?;
        // The inner client address (inside the nodes' tunnel CIDR) stamped as the udpip SOURCE of
        // this hop's inner QUIC. The OUTER node (the hop we tunnel through) decapsulates these,
        // learns `source → this client` for reply routing, and NATs the source away before the
        // next hop. So the source MUST be unique per client at that outer node, or two concurrent
        // onion clients collide in its route table and the second is dropped. Use the inner IP the
        // outer node ASSIGNED us (ADDRESS_ASSIGN / `nil-assigned-ip`, distinct per client from its
        // pool); fall back to the configured/default fixed address only when the node didn't assign
        // one (single-client/dev — unchanged behavior).
        let inner_ip = nested_source_ip(
            outer.assigned_ip(&outer_session),
            self.config.nested_client_ip,
        );
        let local = SocketAddrV4::new(inner_ip, NESTED_CLIENT_PORT);
        let authority = self
            .config
            .server_name
            .clone()
            .unwrap_or_else(|| target.host.clone());
        let policy = policy_for(&target);
        let chan = PacketChannel::Tunnel(TunnelChannel {
            outer,
            outer_session,
            local,
            peer: peer_v4,
        });
        self.finish_connect(chan, peer, authority, creds, policy, max_udp_payload)
            .await
    }

    /// Spawn the driver over `chan` and register the session once the CONNECT-IP handshake
    /// (and attestation) completes. Shared by [`Self::connect`] and [`Self::connect_nested`].
    async fn finish_connect(
        &self,
        chan: PacketChannel,
        peer: SocketAddr,
        authority: String,
        grant: Grant,
        policy: Option<AppraisalPolicy>,
        max_udp_payload: usize,
    ) -> Result<Session> {
        let (to_tx, to_rx) = mpsc::channel(OUTBOUND_QUEUE);
        let (from_tx, from_rx) = mpsc::channel(INBOUND_QUEUE);
        let (ctrl_to_tx, ctrl_to_rx) = mpsc::channel(CONTROL_QUEUE);
        let (ctrl_from_tx, ctrl_from_rx) = mpsc::channel(CONTROL_QUEUE);
        let (ready_tx, ready_rx) = oneshot::channel();
        let shutdown = CancellationToken::new();

        let driver = tokio::spawn(driver_run(
            chan,
            peer,
            authority,
            grant,
            policy,
            self.config.allow_unattested,
            max_udp_payload,
            to_rx,
            from_tx,
            ctrl_to_rx,
            ctrl_from_tx,
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
                return Err(Error::Transport(
                    "masque driver exited before handshake".into(),
                ));
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
            ctrl_to: ctrl_to_tx,
            ctrl_from: AsyncMutex::new(ctrl_from_rx),
            shutdown,
            _driver: driver,
            max_dgram_payload: ready.max_dgram_payload,
            assigned_ip: ready.assigned_ip,
        });
        self.sessions
            .lock()
            .map_err(|_| Error::Transport("masque session map poisoned".into()))?
            .insert(id, state);
        Ok(Session {
            id,
            kind: TransportKind::Masque,
        })
    }
}

#[async_trait]
impl Transport for MasqueTransport {
    async fn connect(&self, target: NodeEndpoint, creds: Grant) -> Result<Session> {
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
        // Android: hand the bound socket's fd to the app so it can `VpnService.protect()` it, so
        // the tunnel's own QUIC to the node bypasses the VpnService TUN (no loop). The bind →
        // protect → connect ordering matters. No-op / absent on other platforms.
        #[cfg(target_os = "android")]
        if let Some(hook) = &self.config.socket_hook {
            use std::os::fd::AsRawFd;
            if !hook(socket.as_raw_fd()) {
                return Err(Error::Transport(
                    "android VpnService.protect refused the QUIC socket".into(),
                ));
            }
        }
        let authority = self
            .config
            .server_name
            .clone()
            .unwrap_or_else(|| target.host.clone());
        let policy = policy_for(&target);
        self.finish_connect(
            PacketChannel::Udp { socket, local },
            peer,
            authority,
            creds,
            policy,
            MAX_UDP_PAYLOAD,
        )
        .await
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

    fn tunnel_mtu(&self, session: &Session) -> Option<usize> {
        // Inherent method (priority over this trait method) does the real work.
        MasqueTransport::tunnel_mtu(self, session)
    }

    fn assigned_ip(&self, session: &Session) -> Option<Ipv4Addr> {
        MasqueTransport::assigned_ip(self, session)
    }
}

/// Resolve a [`NodeEndpoint`] to a socket address.
async fn resolve(target: &NodeEndpoint) -> Result<SocketAddr> {
    // PII-free errors: never embed the node host/port in an error string. These errors propagate
    // up and are logged on the client (e.g. into Android logcat via the nil-android FFI boundary),
    // and the node address is routing metadata we deliberately keep out of logs (PD-2/PD-3). The
    // resolver's `{e}` is an OS-level category ("Name or service not known"), not the host name.
    // Tuple resolution handles DNS names and bare IPv4/IPv6 literals without constructing an
    // ambiguous `host:port` string (an IPv6 registry endpoint must not fail after token use).
    let mut addrs = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|e| Error::Transport(format!("resolve node endpoint: {e}")))?;
    addrs
        .next()
        .ok_or_else(|| Error::Transport("no address resolved for node endpoint".into()))
}

/// Build the appraisal policy from a node endpoint's pinned attestation expectation, if any.
/// `None` ⇒ unattested (loopback/dev). The node must attest to the measurement the Coordinator
/// pinned in the endpoint.
fn policy_for(target: &NodeEndpoint) -> Option<AppraisalPolicy> {
    target.expected.as_ref().map(|e| {
        AppraisalPolicy::new(e.tee, e.measurement.clone())
            .with_tls_spki_sha256(e.tls_spki_sha256)
            .with_min_tcb_sevsnp(e.min_tcb_sevsnp)
            .with_tdx_policy(e.tdx_policy.clone())
            .with_transparency_log_key(e.transparency_log_key)
    })
}

/// How a driver moves QUIC packets to and from its peer. The outermost hop uses a real UDP
/// socket; a nested hop in the trust-split onion (architecture spec §6) tunnels its QUIC inside
/// an outer CONNECT-IP tunnel via [`TunnelChannel`]. The driver loop is identical either way —
/// this is the only seam.
enum PacketChannel {
    Udp {
        socket: UdpSocket,
        local: SocketAddr,
    },
    Tunnel(TunnelChannel),
}

impl PacketChannel {
    /// The local address quiche binds the connection to.
    fn local(&self) -> SocketAddr {
        match self {
            PacketChannel::Udp { local, .. } => *local,
            PacketChannel::Tunnel(t) => SocketAddr::V4(t.local),
        }
    }

    /// Receive one QUIC packet from the peer into `buf`, returning `(len, source)`.
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        match self {
            PacketChannel::Udp { socket, .. } => socket.recv_from(buf).await,
            PacketChannel::Tunnel(t) => t.recv(buf).await,
        }
    }

    /// Send one QUIC packet to `dst`.
    async fn send_to(&self, pkt: &[u8], dst: SocketAddr) -> std::io::Result<()> {
        match self {
            PacketChannel::Udp { socket, .. } => socket.send_to(pkt, dst).await.map(|_| ()),
            PacketChannel::Tunnel(t) => t.send_to(pkt, dst).await,
        }
    }
}

/// A QUIC packet channel that rides an outer CONNECT-IP tunnel. Each inner QUIC packet is
/// wrapped in a userspace IPv4/UDP datagram ([`crate::udpip`]) addressed to the next hop and
/// handed to the outer transport as an IP packet; the outer node NATs it onward, so the next
/// hop sees a QUIC connection from the previous node — never the original client.
struct TunnelChannel {
    outer: Arc<dyn Transport>,
    outer_session: Session,
    /// Our fixed inner client address (the outer node NATs it away).
    local: SocketAddrV4,
    /// The next hop, as seen inside the outer tunnel.
    peer: SocketAddrV4,
}

impl TunnelChannel {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        loop {
            let ip = self
                .outer
                .recv(&self.outer_session)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let Some((src, _dst, payload)) = crate::udpip::unwrap(ip.as_bytes()) else {
                continue; // not a well-formed IPv4/UDP packet
            };
            if src != self.peer {
                continue; // not from our next hop
            }
            let n = payload.len().min(buf.len());
            buf[..n].copy_from_slice(&payload[..n]);
            return Ok((n, SocketAddr::V4(src)));
        }
    }

    async fn send_to(&self, pkt: &[u8], dst: SocketAddr) -> std::io::Result<()> {
        // quiche always sends to the single configured peer; fall back to it for any v6 `to`.
        let dst = match dst {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => self.peer,
        };
        let wrapped = crate::udpip::wrap(self.local, dst, pkt);
        self.outer
            .send(&self.outer_session, IpPacket::new(wrapped))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

struct ReadyInfo {
    max_dgram_payload: usize,
    /// Node-assigned inner IPv4 from the CONNECT-IP response (`nil-assigned-ip`), if present.
    assigned_ip: Option<Ipv4Addr>,
}

#[allow(clippy::too_many_arguments)]
async fn driver_run(
    chan: PacketChannel,
    peer: SocketAddr,
    authority: String,
    grant: Grant,
    policy: Option<AppraisalPolicy>,
    allow_unattested: bool,
    max_udp_payload: usize,
    mut to_rx: mpsc::Receiver<IpPacket>,
    from_tx: mpsc::Sender<IpPacket>,
    mut ctrl_to_rx: mpsc::Receiver<Vec<u8>>,
    ctrl_from_tx: mpsc::Sender<Vec<u8>>,
    ready_tx: oneshot::Sender<Result<ReadyInfo>>,
    shutdown: CancellationToken,
) {
    let local = chan.local();
    let mut ready_tx = Some(ready_tx);
    // Reliable control-channel buffers carried on the CONNECT-IP request stream.
    let mut ctrl_out: std::collections::VecDeque<u8> = std::collections::VecDeque::new();
    let mut ctrl_in: Vec<u8> = Vec::new();
    macro_rules! fail {
        ($e:expr) => {{
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(Err($e));
            }
        }};
    }

    let mut config = match build_client_config(max_udp_payload) {
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

    flush(&mut conn, &chan, &mut out).await;

    loop {
        let timeout = conn.timeout().unwrap_or(Duration::from_secs(3600));
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                let _ = conn.close(true, 0x100, b"bye");
                flush(&mut conn, &chan, &mut out).await;
                return;
            }
            res = chan.recv(&mut buf) => {
                match res {
                    Ok((len, from)) => {
                        let info = quiche::RecvInfo { from, to: local };
                        if let Err(e) = conn.recv(&mut buf[..len], info) {
                            tracing::debug!("masque conn.recv: {e}");
                        }
                    }
                    Err(e) => tracing::warn!("masque packet-channel recv: {e}"),
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
                        flush(&mut conn, &chan, &mut out).await;
                        return;
                    }
                }
            }
            maybe = ctrl_to_rx.recv(), if h3.is_some() => {
                if let Some(msg) = maybe {
                    // Frame as [u32 BE len][payload] and queue for the reliable request stream.
                    ctrl_out.extend((msg.len() as u32).to_be_bytes());
                    ctrl_out.extend(msg);
                }
            }
        }

        // Establish H3 + send the CONNECT-IP request once the QUIC handshake completes.
        if h3.is_none() && conn.is_established() {
            match quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
                Ok(mut h3c) => {
                    let headers = connect_ip_headers(&authority, &grant);
                    match h3c.send_request(&mut conn, &headers, false) {
                        Ok(sid) => {
                            ci_stream = Some(sid);
                            flow_id = sid / 4;
                            h3 = Some(h3c);
                        }
                        Err(e) => {
                            fail!(Error::Transport(format!("send CONNECT-IP: {e}")));
                            let _ = conn.close(true, 0x101, b"req");
                            flush(&mut conn, &chan, &mut out).await;
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
                                    // THE attestation gate: appraise the node's RA-TLS cert
                                    // before signaling ready. This is the only ready-Ok site,
                                    // so a failed/absent appraisal can never yield a tunnel.
                                    match attest_peer(
                                        &conn,
                                        &list,
                                        policy.as_ref(),
                                        allow_unattested,
                                        &grant.nonce,
                                    ) {
                                        Ok(()) => {
                                            if let Some(tx) = ready_tx.take() {
                                                let mdp =
                                                    conn.dgram_max_writable_len().unwrap_or(1200);
                                                let assigned_ip = assigned_ip_of(&list);
                                                let _ = tx.send(Ok(ReadyInfo {
                                                    max_dgram_payload: mdp,
                                                    assigned_ip,
                                                }));
                                                tracing::info!(
                                                    flow_id,
                                                    assigned = assigned_ip.is_some(),
                                                    "MASQUE CONNECT-IP established"
                                                );
                                                // Dev/staging-only: the negotiated usable MTU for
                                                // THIS hop. For a nested onion each hop shrinks it
                                                // (~72 B/hop); the innermost value is the end-to-end
                                                // tunnel MTU — a too-tight margin over the 1200 QUIC
                                                // floor is a prime suspect for data-not-flowing.
                                                #[cfg(feature = "dev-trace")]
                                                tracing::info!(
                                                    flow_id,
                                                    max_dgram_payload = mdp,
                                                    usable_mtu = mdp.saturating_sub(
                                                        connectip::MAX_FRAMING_OVERHEAD
                                                    ),
                                                    "dev-trace: negotiated tunnel MTU"
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            fail!(e);
                                            let _ = conn.close(true, 0x104, b"attestation");
                                            flush(&mut conn, &chan, &mut out).await;
                                            return;
                                        }
                                    }
                                }
                                other => {
                                    fail!(Error::Transport(format!(
                                        "CONNECT-IP refused: status {other:?}"
                                    )));
                                    let _ = conn.close(true, 0x102, b"status");
                                    flush(&mut conn, &chan, &mut out).await;
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
                            flush(&mut conn, &chan, &mut out).await;
                            return;
                        }
                    }
                    Ok((sid, quiche::h3::Event::Data)) => {
                        // Reliable control bytes on the CONNECT-IP request stream → reassemble
                        // [u32 len][payload] frames and hand them to the app (the PQ handshake).
                        if Some(sid) == ci_stream {
                            while let Ok(n) = h3c.recv_body(&mut conn, sid, &mut buf) {
                                ctrl_in.extend_from_slice(&buf[..n]);
                            }
                            while ctrl_in.len() >= 4 {
                                let len = u32::from_be_bytes([
                                    ctrl_in[0], ctrl_in[1], ctrl_in[2], ctrl_in[3],
                                ]) as usize;
                                if len > MAX_CTRL_FRAME {
                                    // A hostile/buggy node claiming an oversized control frame must
                                    // not drive unbounded client-side buffering (a `0xFFFFFFFF`
                                    // prefix would make the loop wait for ~4 GiB). Drop reassembly —
                                    // the PQ handshake then fails → the tunnel never comes up → the
                                    // kill-switch holds (fail-closed).
                                    tracing::warn!("masque control frame length exceeds cap — dropping reassembly buffer");
                                    ctrl_in.clear();
                                    break;
                                }
                                if ctrl_in.len() < 4 + len {
                                    break;
                                }
                                let payload = ctrl_in[4..4 + len].to_vec();
                                ctrl_in.drain(..4 + len);
                                let _ = ctrl_from_tx.try_send(payload);
                            }
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

        // Flush any queued control bytes onto the CONNECT-IP request stream (reliable, ordered;
        // flow-control may accept only part — the rest retries on the next loop).
        if let (Some(h3c), Some(sid)) = (h3.as_mut(), ci_stream) {
            if !ctrl_out.is_empty() {
                let chunk = ctrl_out.make_contiguous();
                if let Ok(written) = h3c.send_body(&mut conn, sid, chunk, false) {
                    ctrl_out.drain(..written);
                }
            }
        }

        // Drain inbound IP packets carried as QUIC DATAGRAMs.
        if h3.is_some() {
            loop {
                match conn.dgram_recv(&mut buf) {
                    Ok(len) => match connectip::decode_datagram(&buf[..len]) {
                        // Only real inner IP packets on our flow reach the TUN; cover-traffic
                        // padding (context id 1), other flows, and malformed datagrams are dropped.
                        Ok((fid, connectip::DatagramPayload::Ip(ip))) if fid == flow_id => {
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

        flush(&mut conn, &chan, &mut out).await;

        if conn.is_closed() {
            fail!(Error::Closed);
            tracing::info!("MASQUE connection closed");
            return;
        }
    }
}

/// Send all pending QUIC packets out the packet channel (UDP socket, or wrapped through an
/// outer tunnel for a nested hop).
async fn flush(conn: &mut quiche::Connection, chan: &PacketChannel, out: &mut [u8]) {
    loop {
        match conn.send(out) {
            Ok((len, info)) => {
                if let Err(e) = chan.send_to(&out[..len], info.to).await {
                    tracing::warn!("masque packet-channel send: {e}");
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

/// Transport-parameter values shaped toward an ordinary HTTPS/QUIC (web-browser) profile.
///
/// **Honesty note (Pillar 1):** true DPI-indistinguishability from a real browser cannot be
/// *verified* without a passive-fingerprinting lab (transport-param ordering, the QUIC bit, the
/// exact set/values a given browser+version emits, ClientHello/ALPN ordering, etc. all matter and
/// vary by release). This profile only removes the *obvious* tells of a hand-rolled non-browser
/// stack — GREASE on (a real client greases), browser-plausible flow-control windows and
/// connection-id limit, and active-migration disabled (browsers don't migrate) — so a passive
/// observer can't trivially bucket us by anaemic/odd transport params. It is a hardening step,
/// not a proof of indistinguishability.
///
/// Held as a separate, pure value so the chosen profile is unit-testable without constructing a
/// `quiche::Config` (whose fields are private and have no public getters in quiche 0.22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QuicShapeProfile {
    /// Send GREASE values (RFC 9287 / §18.1). Real clients grease; a non-greasing endpoint is a
    /// tell. quiche already defaults this to `true`; we set it explicitly so the intent is pinned.
    grease: bool,
    /// `active_connection_id_limit` — browsers advertise a small handful (commonly 2–8).
    active_conn_id_limit: u64,
    /// `disable_active_migration` — browser QUIC clients do not migrate connections, so they set
    /// this. A client that leaves migration enabled stands out.
    disable_active_migration: bool,
    /// Per-connection flow-control window ceiling. A round, browser-plausible value rather than
    /// the open-ended default.
    max_connection_window: u64,
    /// Per-stream flow-control window ceiling (browser-plausible).
    max_stream_window: u64,
}

/// The HTTPS/QUIC profile we shape toward. Values are deliberately round and within the range
/// common browser QUIC stacks use; they are a moving target across releases, so treat these as a
/// reasonable approximation, not a byte-exact clone of any one browser.
const HTTPS_QUIC_PROFILE: QuicShapeProfile = QuicShapeProfile {
    grease: true,
    active_conn_id_limit: 4,
    disable_active_migration: true,
    max_connection_window: 24 * 1024 * 1024,
    max_stream_window: 16 * 1024 * 1024,
};

/// Build the client QUIC config. `max_udp_payload` caps both the size of UDP payloads we will
/// receive (advertised to the peer, so it caps *its* sends too) and the size of packets we
/// send. The outermost hop uses [`MAX_UDP_PAYLOAD`]; a nested hop uses a smaller value so its
/// QUIC packets fit inside the outer tunnel after [`crate::udpip`] wrapping.
pub(crate) fn build_client_config(max_udp_payload: usize) -> Result<quiche::Config> {
    // Own the BoringSSL context so the OUTER TLS ClientHello matches a real browser (Chrome HTTP/3)
    // fingerprint — a censor fingerprints this handshake (JA4/JA4+) regardless of the SNI (Pillar 1).
    // quiche still sets TLS 1.3 + the QUIC method + early-data context per connection (Handshake::init),
    // so this builder only carries the fingerprint-relevant knobs:
    //   - X25519MLKEM768 first in the group list → NIL offers the post-quantum key share Chrome ships
    //     by default (2025); its ABSENCE was itself a fingerprint (see the fingerprint-parity harness).
    //   - TLS-level GREASE (RFC 8701) → real clients grease the ClientHello; not greasing is a tell.
    //     (quiche's own `grease` flag only greases the QUIC layer, not the TLS ClientHello.)
    // verify stays OFF: node trust is the RA-TLS attestation appraised AFTER the handshake (the single
    // ready gate in `driver_run`), never a CA chain — so this changes camouflage, not the trust model.
    use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
    let mut tls = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| Error::Transport(format!("boring ssl ctx: {e}")))?;
    tls.set_verify(SslVerifyMode::NONE);
    tls.set_grease_enabled(true);
    // Permute ClientHello extension order per connection (Chrome/BoringSSL anti-ossification). A
    // FIXED extension order is itself a stable fingerprint; Chrome randomizes, so NIL does too.
    // (Invisible to JA4, which sorts extensions — this defeats exact-byte / order-sensitive matchers.)
    tls.set_permute_extensions(true);
    // Group order mirrors Chrome HTTP/3: the PQ hybrid first, then classical fallbacks. The PQ
    // group needs boring's `pq-experimental` feature (X25519MLKEM768 in the BoringSSL build).
    tls.set_curves_list("X25519MLKEM768:X25519:P-256:P-384")
        .map_err(|e| Error::Transport(format!("boring set_curves_list: {e}")))?;

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)
        .map_err(|e| Error::Transport(format!("quiche config: {e}")))?;
    config
        .set_application_protos(&[b"h3"])
        .map_err(|e| Error::Transport(format!("set_application_protos: {e}")))?;
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(max_udp_payload);
    config.set_max_send_udp_payload_size(max_udp_payload);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.enable_dgram(true, 65536, 65536);
    // Shape the transport params toward an ordinary HTTPS/QUIC profile so a passive observer
    // can't trivially distinguish us by hand-rolled/anaemic params (Pillar 1). See
    // `QuicShapeProfile` for the honesty caveat — this reduces the obvious tells, it does NOT
    // prove DPI-indistinguishability.
    apply_quic_shape(&mut config, &HTTPS_QUIC_PROFILE);
    // The node presents a self-signed RA-TLS cert (the attestation report is embedded in an
    // X.509 extension, not chained to a public CA), so BoringSSL-level chain verification is
    // intentionally off. ALL node trust comes from `attest_peer` appraising the embedded
    // report after the handshake — see the single ready gate in `driver_run`.
    config.verify_peer(false);
    Ok(config)
}

/// Apply a [`QuicShapeProfile`] to a `quiche::Config`. Split out so the *values* are exercised by
/// a unit test (quiche's `Config` exposes no getters, so the test asserts the profile constant).
fn apply_quic_shape(config: &mut quiche::Config, p: &QuicShapeProfile) {
    config.grease(p.grease);
    config.set_active_connection_id_limit(p.active_conn_id_limit);
    config.set_disable_active_migration(p.disable_active_migration);
    config.set_max_connection_window(p.max_connection_window);
    config.set_max_stream_window(p.max_stream_window);
}

/// The single attestation gate. With a pinned policy, appraise the node's attestation
/// evidence (from the CONNECT-IP response header) against it — bound to the node's TLS key
/// (`peer_cert()` SPKI) and the client nonce. With NO policy the decision is delegated to
/// [`unattested_gate`], which **fails closed** unless `allow_unattested` was explicitly set.
fn attest_peer(
    conn: &quiche::Connection,
    headers: &[quiche::h3::Header],
    policy: Option<&AppraisalPolicy>,
    allow_unattested: bool,
    nonce: &[u8; 32],
) -> Result<()> {
    let Some(policy) = policy else {
        return unattested_gate(allow_unattested);
    };
    #[cfg(not(debug_assertions))]
    if policy.tls_spki_sha256.is_none() {
        return Err(Error::Transport(
            "attestation failed: production endpoint has no TLS SPKI identity pin".into(),
        ));
    }
    let cert = conn.peer_cert().ok_or_else(|| {
        Error::Transport("attestation failed: node presented no certificate".into())
    })?;
    let spki = nil_attest::ratls::spki_of(cert)
        .map_err(|e| Error::Transport(format!("attestation failed: {e}")))?;
    let report_hex = header_value(headers, connectip::ATTEST_REPORT_HEADER.as_bytes())
        .ok_or_else(|| Error::Transport("attestation failed: node returned no report".into()))?;
    let evidence = connectip::from_hex(report_hex)
        .ok_or_else(|| Error::Transport("attestation failed: malformed report header".into()))?;
    let verdict = appraise(&evidence, &spki, policy, nonce)
        .map_err(|e| Error::Transport(format!("attestation failed: {e}")))?;
    tracing::info!(tee = ?verdict.tee, "node attestation verified");
    Ok(())
}

/// Fail-closed gate for a connection with no pinned measurement. Refuses the tunnel unless the
/// caller explicitly opted into unattested mode (dev/loopback). This is the fix for the
/// fail-OPEN bug where a missing `NW_EXPECTED_MEASUREMENT` silently carried traffic unattested
/// (PD-2 / Pillar 2: "no attestation pass → kill-switch holds → no traffic"). Pure + unit-tested.
fn unattested_gate(allow_unattested: bool) -> Result<()> {
    #[cfg(not(debug_assertions))]
    {
        let _ = allow_unattested;
        Err(Error::Transport(
            "refusing to bring up an unattested MASQUE tunnel: unattested mode is not compiled into production builds"
                .into(),
        ))
    }
    #[cfg(debug_assertions)]
    {
        if allow_unattested {
            tracing::warn!(
                "MASQUE connection is UNATTESTED (no pinned measurement) — dev/loopback only"
            );
            return Ok(());
        }
        Err(Error::Transport(
            "refusing to bring up an unattested MASQUE tunnel: no pinned measurement. Set \
             NW_EXPECTED_MEASUREMENT (production), or NW_ALLOW_UNATTESTED=1 for local dev/loopback only."
                .into(),
        ))
    }
}

/// Find an H3 header value by (lowercase) name.
fn header_value<'a>(headers: &'a [quiche::h3::Header], name: &[u8]) -> Option<&'a [u8]> {
    use quiche::h3::NameValue;
    headers.iter().find(|h| h.name() == name).map(|h| h.value())
}

fn connect_ip_headers(authority: &str, grant: &Grant) -> Vec<quiche::h3::Header> {
    use quiche::h3::Header;
    let mut headers = vec![
        Header::new(b":method", b"CONNECT"),
        Header::new(b":protocol", b"connect-ip"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", authority.as_bytes()),
        Header::new(b":path", connectip::IP_FULL_TUNNEL_TEMPLATE.as_bytes()),
        Header::new(b"capsule-protocol", b"?1"),
        // RA-TLS freshness challenge: the node must bind this nonce into its report's
        // report_data, proving the report was minted for this connection.
        Header::new(
            connectip::ATTEST_NONCE_HEADER.as_bytes(),
            connectip::to_hex(&grant.nonce).as_bytes(),
        ),
    ];
    if !grant.token.is_empty() {
        headers.push(Header::new(
            connectip::TUNNEL_GRANT_HEADER.as_bytes(),
            connectip::to_hex(&grant.token).as_bytes(),
        ));
    }
    headers
}

fn status_of(list: &[quiche::h3::Header]) -> Option<u16> {
    use quiche::h3::NameValue;
    list.iter()
        .find(|h| h.name() == b":status")
        .and_then(|h| std::str::from_utf8(h.value()).ok())
        .and_then(|s| s.parse().ok())
}

/// Pick the udpip SOURCE address for a nested hop's inner QUIC. Precedence: the inner IP the outer
/// node ASSIGNED us (distinct per client → no collision in that node's reply-route table when
/// several onion clients share it) > a configured fixed address > the default. Pure so the
/// precedence is unit-tested without a live connection.
fn nested_source_ip(assigned: Option<Ipv4Addr>, configured: Option<Ipv4Addr>) -> Ipv4Addr {
    assigned.or(configured).unwrap_or(DEFAULT_NESTED_CLIENT_IP)
}

/// Parse the node's `nil-assigned-ip` response header (dotted-quad IPv4) — the ADDRESS_ASSIGN
/// subset. Absent or malformed ⇒ `None` (the datapath then keeps its configured address).
fn assigned_ip_of(list: &[quiche::h3::Header]) -> Option<Ipv4Addr> {
    header_value(list, connectip::ASSIGNED_IP_HEADER.as_bytes())
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|s| s.trim().parse::<Ipv4Addr>().ok())
}

#[cfg(test)]
mod fingerprint;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_bare_ipv6_registry_endpoint_without_ambiguous_host_port_formatting() {
        let endpoint = NodeEndpoint {
            host: "::1".to_string(),
            port: 443,
            kind: nil_core::TransportKind::Masque,
            wg_pub: None,
            expected: None,
            grant: None,
        };
        let resolved = resolve(&endpoint).await.expect("IPv6 literal resolves");
        assert_eq!(resolved, "[::1]:443".parse().unwrap());
    }

    #[test]
    fn kind_and_profile_are_masque() {
        let t = MasqueTransport::new();
        assert_eq!(t.kind(), TransportKind::Masque);
        assert_eq!(t.fingerprint_profile(), Profile::HttpsQuic);
    }

    #[test]
    fn endpoint_tdx_policy_reaches_the_appraisal_gate() {
        let tdx_policy = nil_core::TdxPolicy {
            td_attributes: [0, 0, 0, 0x10, 0, 0, 0, 0],
            xfam: [2; 8],
            mr_config_id: nil_core::TdxMeasurement([3; 48]),
            mr_owner: nil_core::TdxMeasurement([4; 48]),
            mr_owner_config: nil_core::TdxMeasurement([5; 48]),
            rt_mr0: nil_core::TdxMeasurement([6; 48]),
            rt_mr1: nil_core::TdxMeasurement([7; 48]),
            rt_mr2: nil_core::TdxMeasurement([8; 48]),
            rt_mr3: nil_core::TdxMeasurement([9; 48]),
            mr_service_td: Some(nil_core::TdxMeasurement([10; 48])),
        };
        let endpoint = NodeEndpoint {
            host: "node.example".into(),
            port: 443,
            kind: TransportKind::Masque,
            wg_pub: None,
            expected: Some(nil_core::AttestExpectation {
                tee: nil_core::Tee::Tdx,
                measurement: nil_core::Measurement(vec![11; 48]),
                tls_spki_sha256: Some([12; 32]),
                min_tcb_sevsnp: None,
                tdx_policy: Some(tdx_policy.clone()),
                transparency_log_key: Some([13; 32]),
            }),
            grant: None,
        };
        let policy = policy_for(&endpoint).expect("attested endpoint has a policy");
        assert_eq!(policy.tdx_policy, Some(tdx_policy));
        assert_eq!(policy.tls_spki_sha256, Some([12; 32]));
        assert_eq!(policy.transparency_log_key, Some([13; 32]));
    }

    #[test]
    fn nested_source_ip_prefers_the_node_assigned_address() {
        let assigned = Ipv4Addr::new(10, 74, 0, 7);
        let configured = Ipv4Addr::new(10, 74, 0, 9);
        // The outer node's ADDRESS_ASSIGN'd IP wins — this is the per-client uniqueness that stops
        // two concurrent onion clients colliding in that node's reply-route table.
        assert_eq!(nested_source_ip(Some(assigned), Some(configured)), assigned);
        assert_eq!(nested_source_ip(Some(assigned), None), assigned);
        // No assignment → the configured fixed address, else the default (single-client/dev).
        assert_eq!(nested_source_ip(None, Some(configured)), configured);
        assert_eq!(nested_source_ip(None, None), DEFAULT_NESTED_CLIENT_IP);
    }

    #[test]
    fn https_quic_shape_profile_removes_the_obvious_tells() {
        // The shaping profile toward an ordinary HTTPS/QUIC client: GREASE on (real clients
        // grease), active migration disabled (browsers don't migrate), a small connection-id
        // limit, and round browser-plausible flow-control windows. This is a config-assertion
        // test on the chosen values (quiche's Config has no getters). It does NOT — and cannot
        // here — prove DPI-indistinguishability; that needs a passive-fingerprinting lab.
        let p = HTTPS_QUIC_PROFILE;
        assert!(
            p.grease,
            "a real QUIC client sends GREASE; not greasing is a tell"
        );
        assert!(
            p.disable_active_migration,
            "browser QUIC clients disable active migration"
        );
        assert!(
            (2..=8).contains(&p.active_conn_id_limit),
            "connection-id limit must be in the browser-plausible 2..=8 range, got {}",
            p.active_conn_id_limit
        );
        assert!(
            p.max_stream_window <= p.max_connection_window,
            "the per-stream window must not exceed the per-connection window"
        );
    }

    #[test]
    fn build_client_config_applies_the_shape_without_panicking() {
        // Smoke test: the shaped config builds for both an outermost hop and a small nested
        // payload (the apply path runs end to end). quiche exposes no getters, so we can only
        // assert it constructs; the values are covered by `https_quic_shape_profile_*` above.
        build_client_config(MAX_UDP_PAYLOAD).expect("outermost config builds");
        build_client_config(MIN_QUIC_UDP_PAYLOAD).expect("nested-floor config builds");
    }

    #[test]
    fn default_config_is_fail_closed() {
        // Secure by default: a transport built with no explicit opt-out must require attestation.
        assert!(
            !MasqueConfig::default().allow_unattested,
            "default must fail closed"
        );
    }

    #[test]
    fn unattested_gate_fails_closed_unless_explicitly_allowed() {
        // No pinned measurement + not allowed → tunnel refused (the fix for the fail-open bug).
        assert!(
            unattested_gate(false).is_err(),
            "missing measurement must refuse the tunnel"
        );
        #[cfg(debug_assertions)]
        assert!(
            unattested_gate(true).is_ok(),
            "explicit opt-in permits unattested dev use"
        );
        #[cfg(not(debug_assertions))]
        assert!(
            unattested_gate(true).is_err(),
            "production builds must reject unattested mode even when requested programmatically"
        );
    }
}
