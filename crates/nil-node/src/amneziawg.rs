//! Node-side AmneziaWG responder (architecture spec §4.3, cascade rung 2): the matching half of
//! the client's `nil_transport::AmneziaWgTransport`. Obfuscated WireGuard directly on UDP — the
//! censorship fallback used when MASQUE/QUIC is blocked.
//!
//! Selected by `NW_NODE_AMNEZIA`; the node runs this *instead of* the MASQUE server (a separate
//! node/container), so it owns the exit TUN outright. It serves **multiple concurrent clients**:
//! each is keyed by its UDP source address, with an inner-tunnel-IP → client routing table so
//! replies arriving on the shared exit TUN dispatch to the right client. It logs its WireGuard
//! public key for clients to pin (`NW_NODE_WG_PUB`).
//!
//! Trust model: unlike MASQUE, this rung has no RA-TLS channel, so it is **not TEE-attested** —
//! the client authenticates the node by its pinned WireGuard static key only. That is the
//! accepted tradeoff for a WireGuard-based circumvention fallback; the default MASQUE transport
//! remains attested.
//!
//! Address assignment is **out-of-band today**: each client must use a distinct inner tunnel IP
//! (the deployment sets distinct `NW_CLIENT_IP`s), and the responder learns the mapping from the
//! source address of the client's first inner packet. A true in-band ADDRESS_ASSIGN — which would
//! require the `Transport` seam to surface a node-assigned address back to the datapath — is
//! deferred; if two clients collide on one inner IP, the later one wins the route (documented).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tun_rs::AsyncDevice;

use nil_transport::{connectip, ObfsParams, PqWgCore, WgKeypair, WgStep};

use crate::config::NodeConfig;

/// Max concurrent clients one responder tracks. Bounds memory against a preface flood (a real
/// deployment scales horizontally behind several nodes). WireGuard cookie/rate-limiting is the
/// proper anti-flood; out of scope for this fallback rung.
const MAX_CLIENTS: usize = 256;

/// One tracked client, keyed in the responder by its UDP source address.
struct Client {
    /// The client's WireGuard static pubkey (from its preface) — for dedup/logging.
    pubkey: [u8; 32],
    core: PqWgCore,
    /// Set once the client has produced real (decapsulated) traffic.
    established: bool,
    /// Insertion order — used to evict the oldest *non-established* client at capacity.
    seq: u64,
}

/// An action the async loop must perform — returned by the (sync, testable) packet handlers so
/// the responder logic is decoupled from the socket and TUN.
enum Action {
    /// Send already-obfuscated bytes to a client's UDP address.
    SendTo(SocketAddr, Vec<u8>),
    /// Write a decapsulated inner IP packet to the exit TUN.
    ToTun(Vec<u8>),
}

/// The multi-client AmneziaWG responder — pure packet handling, no I/O, so it unit-tests without
/// sockets or a TUN.
struct Responder {
    node_secret: StaticSecret,
    obfs: ObfsParams,
    clients: HashMap<SocketAddr, Client>,
    /// Inner tunnel IP → owning client's UDP address (so the shared exit TUN routes replies).
    routes: HashMap<Ipv4Addr, SocketAddr>,
    next_seq: u64,
}

impl Responder {
    fn new(node_secret: StaticSecret) -> Self {
        Self {
            node_secret,
            obfs: ObfsParams::default(),
            clients: HashMap::new(),
            routes: HashMap::new(),
            next_seq: 0,
        }
    }

    /// Handle one inbound UDP datagram (a preface or a WireGuard message).
    fn handle_udp(&mut self, wire: &[u8], from: SocketAddr) -> Vec<Action> {
        // A preface (the client's WG pubkey) (re)builds the entry for *its own* source address. It
        // no longer locks out other clients (multi-client), so an off-path preface from a new
        // address cannot tear down an established peer keyed by a different address.
        if let Some(client_pub) = self.obfs.try_preface(wire) {
            self.admit(client_pub, from);
            return Vec::new();
        }
        let Some(wg) = self.obfs.deobfuscate(wire) else { return Vec::new() };
        // Select the client's WireGuard core by UDP source address.
        if !self.clients.contains_key(&from) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut input = wg;
        loop {
            // Re-borrow each iteration so we can also touch self.routes/self.obfs (disjoint fields).
            let client = self.clients.get_mut(&from).expect("client present");
            match client.core.decapsulate(&input) {
                WgStep::Ip(ip) => {
                    client.established = true;
                    if let Some(src) = ipv4_src(&ip) {
                        self.routes.insert(src, from);
                    }
                    out.push(Action::ToTun(ip));
                    break;
                }
                WgStep::Network(b) => {
                    out.push(Action::SendTo(from, self.obfs.obfuscate(&b)));
                    input = Vec::new();
                }
                WgStep::Done | WgStep::Err(_) => break,
            }
        }
        out
    }

    /// A reply arriving on the shared exit TUN → route to the owning client by destination IP.
    fn handle_tun(&mut self, ip: &[u8]) -> Vec<Action> {
        let Some(dst) = ipv4_dst(ip) else { return Vec::new() };
        let Some(&addr) = self.routes.get(&dst) else { return Vec::new() };
        let Some(client) = self.clients.get_mut(&addr) else { return Vec::new() };
        match client.core.encapsulate(ip) {
            Ok(wire) => vec![Action::SendTo(addr, self.obfs.obfuscate(&wire))],
            Err(_) => Vec::new(),
        }
    }

    /// WireGuard timer tick for every client (keepalive/rekey).
    fn tick(&mut self) -> Vec<Action> {
        let obfs = &self.obfs;
        let mut out = Vec::new();
        for (addr, client) in self.clients.iter_mut() {
            if let Some(b) = client.core.tick() {
                out.push(Action::SendTo(*addr, obfs.obfuscate(&b)));
            }
        }
        out
    }

    /// Admit (or refresh) the client for `from`. At capacity, evict the oldest *non-established*
    /// client so a flood of never-completing prefaces cannot lock out real peers.
    fn admit(&mut self, client_pub: [u8; 32], from: SocketAddr) {
        if let Some(existing) = self.clients.get(&from) {
            // Same address re-prefacing with the same key: don't reset an in-progress handshake.
            if existing.pubkey == client_pub {
                return;
            }
        } else if self.clients.len() >= MAX_CLIENTS {
            let victim = self
                .clients
                .iter()
                .filter(|(_, c)| !c.established)
                .min_by_key(|(_, c)| c.seq)
                .map(|(a, _)| *a);
            match victim {
                Some(a) => {
                    self.clients.remove(&a);
                }
                None => {
                    tracing::warn!(
                        "AmneziaWG responder at capacity ({MAX_CLIENTS} established clients); dropping preface"
                    );
                    return;
                }
            }
        }
        let core = PqWgCore::without_psk(self.node_secret.clone(), PublicKey::from(client_pub), 2);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.clients
            .insert(from, Client { pubkey: client_pub, core, established: false, seq });
    }
}

fn ipv4_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    (pkt.len() >= 20 && (pkt[0] >> 4) == 4).then(|| Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}
fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    (pkt.len() >= 20 && (pkt[0] >> 4) == 4).then(|| Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

pub async fn run(cfg: &NodeConfig, tun: Arc<AsyncDevice>) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(cfg.bind).await?;
    let kp = WgKeypair::generate().map_err(|e| anyhow::anyhow!("node wg keygen: {e}"))?;
    tracing::info!(
        wg_pub = %connectip::to_hex(kp.public.as_bytes()),
        "AmneziaWG responder listening (multi-client) — pin this as the client's NW_NODE_WG_PUB"
    );
    let mut responder = Responder::new(kp.secret);
    let mut buf = vec![0u8; 65535];
    let mut tun_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("nil-node (AmneziaWG) shutting down");
                break;
            }
            r = socket.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { continue };
                for action in responder.handle_udp(&buf[..n], from) {
                    perform(&socket, &tun, action).await;
                }
            }
            r = tun.recv(&mut tun_buf) => {
                let Ok(n) = r else { continue };
                // Internet reply → finalize checksums → route to the owning client.
                nil_core::checksum::fix_l4_checksums(&mut tun_buf[..n]);
                for action in responder.handle_tun(&tun_buf[..n]) {
                    perform(&socket, &tun, action).await;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                for action in responder.tick() {
                    perform(&socket, &tun, action).await;
                }
            }
        }
    }
    Ok(())
}

async fn perform(socket: &UdpSocket, tun: &Arc<AsyncDevice>, action: Action) {
    match action {
        Action::SendTo(addr, bytes) => {
            let _ = socket.send_to(&bytes, addr).await;
        }
        Action::ToTun(ip) => {
            let _ = tun.send(&ip).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::x25519::PublicKey;
    use nil_transport::WgKeypair;

    /// Pull the single obfuscated payload out of a one-`SendTo` action list.
    fn one_send(actions: Vec<Action>) -> Vec<u8> {
        assert_eq!(actions.len(), 1, "expected exactly one SendTo");
        match actions.into_iter().next().unwrap() {
            Action::SendTo(_, bytes) => bytes,
            Action::ToTun(_) => panic!("expected SendTo, got ToTun"),
        }
    }

    /// A minimal well-formed IPv4 packet with the given source/destination. The total-length
    /// field (bytes 2-3) MUST be set — boringtun reads it to size the decapsulated packet.
    fn ipv4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45; // IPv4, IHL=5
        p[2..4].copy_from_slice(&28u16.to_be_bytes()); // total length
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    /// Bring a client to "established" against the responder and return its core + the IP it uses.
    fn establish(responder: &mut Responder, node_pub: PublicKey, addr: SocketAddr, index: u32) -> PqWgCore {
        let obfs = ObfsParams::default();
        let kp = WgKeypair::generate().unwrap();
        let mut core = PqWgCore::without_psk(kp.secret, node_pub, index);

        // Preface (client pubkey) → responder admits the client.
        responder.handle_udp(&obfs.obfuscate_preface(kp.public.as_bytes()), addr);
        // Handshake init → responder replies with the handshake response.
        let init = core.handshake_init().unwrap();
        let response = one_send(responder.handle_udp(&obfs.obfuscate(&init), addr));
        // Client processes the response and emits the completing keepalive; feed it back so the
        // responder's session is confirmed (else the client's first *data* packet is deferred
        // behind that pending keepalive).
        match core.decapsulate(&obfs.deobfuscate(&response).unwrap()) {
            WgStep::Network(keepalive) => {
                responder.handle_udp(&obfs.obfuscate(&keepalive), addr);
            }
            other => panic!("expected handshake response, got {other:?}"),
        }
        core
    }

    #[test]
    fn two_clients_route_replies_independently() {
        let node_kp = WgKeypair::generate().unwrap();
        let node_pub = node_kp.public;
        let mut responder = Responder::new(node_kp.secret);

        let addr_a: SocketAddr = "203.0.113.1:51820".parse().unwrap();
        let addr_b: SocketAddr = "203.0.113.2:51820".parse().unwrap();
        let mut core_a = establish(&mut responder, node_pub, addr_a, 101);
        let mut core_b = establish(&mut responder, node_pub, addr_b, 102);
        assert_eq!(responder.clients.len(), 2, "both clients tracked concurrently");

        let obfs = ObfsParams::default();
        let ip_a = [10, 74, 0, 2];
        let ip_b = [10, 74, 0, 3];

        // Each client sends an outbound packet from its own inner IP → responder learns the route.
        for (core, ip, addr) in [(&mut core_a, ip_a, addr_a), (&mut core_b, ip_b, addr_b)] {
            let data = core.encapsulate(&ipv4(ip, [1, 1, 1, 1])).unwrap();
            let actions = responder.handle_udp(&obfs.obfuscate(&data), addr);
            let to_tun: Vec<_> = actions
                .into_iter()
                .filter_map(|a| match a {
                    Action::ToTun(p) => Some(p),
                    _ => None,
                })
                .collect();
            assert_eq!(to_tun.len(), 1, "one inner packet reaches the TUN");
            assert_eq!(ipv4_src(&to_tun[0]), Some(Ipv4Addr::from(ip)));
        }
        assert_eq!(responder.routes.get(&Ipv4Addr::from(ip_a)), Some(&addr_a));
        assert_eq!(responder.routes.get(&Ipv4Addr::from(ip_b)), Some(&addr_b));

        // A reply addressed to client B's inner IP must encapsulate to B (not A), and decapsulate
        // cleanly on B's core — proving the shared-TUN dispatch picks the correct client.
        let reply_to_b = ipv4([1, 1, 1, 1], ip_b);
        let wire = one_send(responder.handle_tun(&reply_to_b));
        match core_b.decapsulate(&obfs.deobfuscate(&wire).unwrap()) {
            WgStep::Ip(got) => assert_eq!(ipv4_dst(&got), Some(Ipv4Addr::from(ip_b))),
            other => panic!("client B should receive its reply, got {other:?}"),
        }

        // And a reply to A's inner IP routes to A.
        let reply_to_a = ipv4([1, 1, 1, 1], ip_a);
        let wire = one_send(responder.handle_tun(&reply_to_a));
        match core_a.decapsulate(&obfs.deobfuscate(&wire).unwrap()) {
            WgStep::Ip(got) => assert_eq!(ipv4_dst(&got), Some(Ipv4Addr::from(ip_a))),
            other => panic!("client A should receive its reply, got {other:?}"),
        }
    }

    #[test]
    fn unknown_inner_ip_reply_is_dropped_not_misrouted() {
        let node_kp = WgKeypair::generate().unwrap();
        let mut responder = Responder::new(node_kp.secret);
        // No clients/routes yet: a TUN reply for an unknown inner IP yields no action (never
        // misrouted to some arbitrary client).
        let actions = responder.handle_tun(&ipv4([1, 1, 1, 1], [10, 74, 0, 9]));
        assert!(actions.is_empty());
    }

    #[test]
    fn admit_dedups_and_caps_evicting_oldest_non_established() {
        let node_kp = WgKeypair::generate().unwrap();
        let mut r = Responder::new(node_kp.secret);
        let addr = |i: usize| -> SocketAddr { format!("127.0.0.1:{}", 1000 + i).parse().unwrap() };

        // A duplicate preface (same addr + same pubkey) must not create a second entry.
        r.admit([7u8; 32], addr(0));
        r.admit([7u8; 32], addr(0));
        assert_eq!(r.clients.len(), 1, "duplicate preface deduped");

        // Fill to capacity with distinct, non-established clients.
        for i in 1..MAX_CLIENTS {
            r.admit([i as u8; 32], addr(i));
        }
        assert_eq!(r.clients.len(), MAX_CLIENTS);

        // One more at capacity evicts the oldest non-established entry (addr(0), seq 0), keeping
        // the map bounded — a preface flood can't lock out room for new peers.
        r.admit([255u8; 32], addr(MAX_CLIENTS));
        assert_eq!(r.clients.len(), MAX_CLIENTS, "stays bounded at capacity");
        assert!(!r.clients.contains_key(&addr(0)), "oldest non-established evicted");
        assert!(r.clients.contains_key(&addr(MAX_CLIENTS)), "new client admitted");
    }
}
