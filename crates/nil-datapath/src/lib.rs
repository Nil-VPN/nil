//! Client-side system datapath: a [`Tunnel`] controller that connects a [`Transport`],
//! brings up a TUN device, flips the default route through it (with a host-route exception
//! for the node so the tunnel's own QUIC packets don't loop), arms a fail-closed
//! kill-switch, and runs the bidirectional packet pump.
//!
//! The OS-specific routing/kill-switch/DNS lives behind [`NetControl`]: Linux (verified in
//! Docker), macOS (verified in a tart VM), and Windows (routing/DNS + a fail-closed Windows
//! Firewall kill-switch, verified in a Windows-on-ARM VM — see `windows.rs`) are complete. All
//! three fail closed: IPv6 is dropped wholesale (the tunnel is IPv4-only) and a dropped pump
//! holds the kill-switch. The [`Transport`] trait stays the only seam to the tunnel — this crate
//! never knows which transport is active.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use nil_core::{IpPacket, NodeEndpoint, Session};
use nil_transport::Transport;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "launch")]
pub mod launch;
#[cfg(feature = "launch")]
mod redeem;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// How to bring up the tunnel.
pub struct TunnelConfig {
    pub node: NodeEndpoint,
    pub tun_name: String,
    pub client_ip: Ipv4Addr,
    pub peer_ip: Ipv4Addr,
    pub prefix: u8,
    pub mtu: u16,
    pub dns: Vec<IpAddr>,
    pub kill_switch: bool,
    /// Extra hosts whose direct traffic must bypass the tunnel (host-route exception + kill-switch
    /// allow), beyond `node`. Used for obfuscation-cascade fallback nodes (e.g. the AmneziaWG
    /// node): if a fallback rung's own UDP to its node went through the TUN it would loop.
    pub also_except: Vec<String>,
}

/// Inputs the OS layer needs to arm routing/kill-switch/DNS.
pub struct ArmParams {
    pub node_ip: IpAddr,
    pub tun_name: String,
    pub dns: Vec<IpAddr>,
    pub kill_switch: bool,
    /// Additional node IPs to host-route-except + allow through the kill-switch (cascade
    /// fallback nodes). Empty for a single-node tunnel.
    pub also_except: Vec<IpAddr>,
}

/// OS-specific routing, kill-switch, and DNS control. `teardown` must be idempotent and
/// safe to call after a partial `arm`.
pub trait NetControl: Send {
    fn arm(&mut self, params: &ArmParams) -> anyhow::Result<()>;
    fn teardown(&mut self);
}

/// Fallback for targets without a native datapath impl. Compiles everywhere so the workspace
/// builds on any host; refuses to arm at runtime.
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
)))]
struct StubNet;
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
)))]
impl NetControl for StubNet {
    fn arm(&mut self, _params: &ArmParams) -> anyhow::Result<()> {
        anyhow::bail!("system datapath is implemented for Linux, macOS, and Windows only")
    }
    fn teardown(&mut self) {}
}

#[cfg(target_os = "linux")]
fn new_net_control() -> Box<dyn NetControl> {
    Box::new(linux::LinuxNet::default())
}
#[cfg(target_os = "macos")]
fn new_net_control() -> Box<dyn NetControl> {
    Box::new(macos::MacNet::default())
}
#[cfg(target_os = "windows")]
fn new_net_control() -> Box<dyn NetControl> {
    Box::new(windows::WinNet::default())
}
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
)))]
fn new_net_control() -> Box<dyn NetControl> {
    Box::new(StubNet)
}

/// A live tunnel: the transport session, the OS networking it armed, and the pump tasks.
pub struct Tunnel {
    transport: Arc<dyn Transport>,
    session: Option<Session>,
    net: Box<dyn NetControl>,
    cancel: CancellationToken,
    /// Tripped by a pump task when the packet pump exits for ANY reason other than a clean
    /// teardown (tunnel hung, transport closed, TUN error). The owning engine observes this via
    /// [`Tunnel::closed`]/[`Tunnel::is_up`] and transitions itself to Disconnected. The
    /// kill-switch is NOT released here — it holds until [`Tunnel::down`] runs, so a dropped
    /// tunnel fails closed (no leak window) (Pillar 2 / SOUL: dead tunnel → traffic stops).
    pump_dead: CancellationToken,
    pumps: Vec<JoinHandle<()>>,
    _tun: Arc<tun_rs::AsyncDevice>,
}

impl Tunnel {
    /// Connect the transport, bring up the TUN + routes + kill-switch, and start pumping.
    /// Desktop only — Android brings the tunnel up over a `VpnService`-provided fd (`up_with_fd`
    /// in `android.rs`), so routing/DNS/MTU/kill-switch are the OS's job, not ours.
    #[cfg(not(target_os = "android"))]
    pub async fn up(
        transport: Arc<dyn Transport>,
        mut cfg: TunnelConfig,
    ) -> anyhow::Result<Tunnel> {
        // `cfg.node` is the directly-reachable hop: a single node, or the *entry* of a
        // multi-hop path. Its IP is the kill-switch host-route exception so the tunnel's own
        // QUIC doesn't loop; inner hops are reached through the tunnel and need no exception.
        let node_ip = resolve_ip(&cfg.node).await?;
        // Extra hosts to except (cascade fallback nodes); skip any that don't resolve.
        let mut also_except = Vec::new();
        for host in &cfg.also_except {
            if let Ok(ip) = resolve_host(host).await {
                also_except.push(ip);
            }
        }
        // No node host/IP in logs — even on the client device, a session timeline must not be
        // reconstructable from tracing output (SOUL §3 / PD-2).
        tracing::info!("connecting MASQUE tunnel");

        // Fresh per-connection nonce: the transport sends it to the node, which must bind it
        // into its attestation report's report_data, and the appraisal checks the binding.
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("nonce entropy: {e}"))?;
        let grant = cfg.node.grant.clone().unwrap_or(nil_core::Grant {
            token: Vec::new(),
            nonce,
        });

        let session = transport
            .connect(cfg.node.clone(), grant)
            .await
            .map_err(|e| anyhow::anyhow!("transport connect: {e}"))?;
        tracing::info!("tunnel session established; bringing up TUN + routes");

        // ADDRESS_ASSIGN (RFC 9484 subset): if the node assigned us a unique inner IPv4, apply it
        // to the TUN instead of the configured constant — so two concurrent clients never collide
        // on one inner address. Absent ⇒ keep the configured `client_ip` (single-client fallback).
        if let Some(ip) = apply_assigned_ip(cfg.client_ip, transport.assigned_ip(&session)) {
            tracing::info!("applying node-assigned inner address to TUN");
            cfg.client_ip = ip;
        }

        // Size the TUN to the tunnel's negotiated usable MTU. Each nested hop shrinks it (the
        // inner QUIC rides the outer tunnel), so a multi-hop onion ends up smaller than a single
        // tunnel; clamp to the configured ceiling so we never grow it past what the OS expects.
        if let Some(m) = clamp_mtu(cfg.mtu, transport.tunnel_mtu(&session)) {
            tracing::info!(
                negotiated = m,
                configured = cfg.mtu,
                "sizing TUN to negotiated tunnel MTU"
            );
            cfg.mtu = m;
        }

        let tun = Arc::new(open_tun(&cfg).map_err(|e| anyhow::anyhow!("open tun: {e}"))?);
        // Resolve the actual interface name (macOS auto-assigns utunN; Linux honors our name).
        let tun_name = tun.name().map_err(|e| anyhow::anyhow!("tun name: {e}"))?;

        let mut net = new_net_control();
        if let Err(e) = net.arm(&ArmParams {
            node_ip,
            tun_name: tun_name.clone(),
            dns: cfg.dns.clone(),
            kill_switch: cfg.kill_switch,
            also_except,
        }) {
            // Bringing up the network failed — tear down what we armed and close the session.
            net.teardown();
            let _ = transport.close(session).await;
            return Err(e);
        }

        let cancel = CancellationToken::new();
        // Tripped by whichever pump exits first (hang/dead-tunnel/TUN error). Distinct from
        // `cancel` (which WE trip on a clean `down`), so the engine can tell "the tunnel died
        // under us" from "we tore it down".
        let pump_dead = CancellationToken::new();
        let pumps = spawn_pumps(transport.clone(), session, tun.clone(), &cancel, &pump_dead);
        tracing::info!(tun = %tun_name, "tunnel up");

        Ok(Tunnel {
            transport,
            session: Some(session),
            net,
            cancel,
            pump_dead,
            pumps,
            _tun: tun,
        })
    }

    /// Resolves when the packet pump dies on its own (tunnel hung, transport closed, or TUN
    /// error) — i.e. NOT via a clean [`Tunnel::down`]. The kill-switch is still armed at this
    /// point and stays armed (fail-closed); the caller should react by tearing the tunnel down
    /// and surfacing a Disconnected state. Cheap to clone/await; safe to call repeatedly.
    pub fn closed(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let dead = self.pump_dead.clone();
        async move { dead.cancelled().await }
    }

    /// Whether the packet pump is still alive. `false` once a pump has exited on its own. The
    /// engine can poll this between sends to detect a silently-dropped tunnel.
    pub fn is_up(&self) -> bool {
        !self.pump_dead.is_cancelled()
    }

    /// Tear down cleanly: stop the pump, restore networking, close the session.
    pub async fn down(mut self) -> anyhow::Result<()> {
        self.cancel.cancel();
        for h in self.pumps.drain(..) {
            let _ = h.await;
        }
        // Restore routes/DNS/firewall BEFORE closing the session so there is no leak window.
        self.net.teardown();
        if let Some(s) = self.session.take() {
            let _ = self.transport.close(s).await;
        }
        tracing::info!("tunnel down; networking restored");
        Ok(())
    }
}

/// Error from [`preflight_privilege`] — the local, pre-token capability check.
#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    /// The process lacks the privilege needed to create a TUN device (root on macOS/Linux).
    #[error("opening a network tunnel device requires root/administrator privileges")]
    NeedsPrivilege,
}

/// Cheap, side-effect-free check that this process *can* open a TUN device, meant to run BEFORE
/// any single-use token is consumed. On macOS/Linux, creating a `utun` / `/dev/net/tun` device is
/// privileged and fails with `EPERM` for a non-root process — so we model exactly that cause with
/// an effective-uid check, rather than probe-opening (and tearing down) a real interface, which is
/// exactly the kind of side effect a pre-flight must avoid.
///
/// `Ok` here is necessary but not sufficient: the real [`open_tun`] remains the authority and still
/// fails closed. This only lets the caller refuse a doomed connect *before* spending a token.
/// Windows (wintun, a different admin model) and any non-desktop target return `Ok` and rely on the
/// later open to fail closed.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn preflight_privilege() -> Result<(), PreflightError> {
    // `libc`/`nix` aren't workspace deps; a one-line extern adds no supply-chain surface.
    extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: POSIX `geteuid` is infallible — no args, no errno, no memory access.
    if unsafe { geteuid() } != 0 {
        return Err(PreflightError::NeedsPrivilege);
    }
    Ok(())
}

/// Non-(macOS/Linux) targets: no cheap pre-check; the later [`open_tun`] is the fail-closed gate.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn preflight_privilege() -> Result<(), PreflightError> {
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn open_tun(cfg: &TunnelConfig) -> std::io::Result<tun_rs::AsyncDevice> {
    #[allow(unused_mut)]
    let mut builder = tun_rs::DeviceBuilder::new()
        .ipv4(cfg.client_ip, cfg.prefix, Some(cfg.peer_ip))
        .mtu(cfg.mtu);
    // macOS requires a `utun*` name (auto-assigned); Linux and Windows (the wintun adapter
    // name) honor our chosen name.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        builder = builder.name(cfg.tun_name.clone());
    }
    builder.build_async()
}

/// Decide whether a node-assigned inner IPv4 should replace the configured `client_ip`. Returns
/// `Some(new_ip)` only when the node assigned an address that differs from the configured one
/// (`None` ⇒ keep the configured address: no assignment, or it already matches). Pure — extracted
/// from [`Tunnel::up`] so the ADDRESS_ASSIGN apply path is unit-testable without a TUN device.
fn apply_assigned_ip(configured: Ipv4Addr, assigned: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
    match assigned {
        Some(ip) if ip != configured => Some(ip),
        _ => None,
    }
}

/// Clamp the configured TUN MTU down to the tunnel's negotiated usable MTU. Returns `Some(m)` only
/// when the negotiated MTU is known AND smaller than the configured ceiling (we never grow the TUN
/// past what the OS expects); `None` ⇒ keep the configured MTU. Pure — extracted from
/// [`Tunnel::up`] for unit testing.
fn clamp_mtu(configured: u16, negotiated: Option<usize>) -> Option<u16> {
    let m = negotiated?.min(u16::MAX as usize) as u16;
    (m < configured).then_some(m)
}

fn spawn_pumps(
    transport: Arc<dyn Transport>,
    session: Session,
    tun: Arc<tun_rs::AsyncDevice>,
    cancel: &CancellationToken,
    pump_dead: &CancellationToken,
) -> Vec<JoinHandle<()>> {
    // TUN → tunnel: read IP packets off the OS and send them through the transport.
    // NB: both pumps share a CLONE of the SAME `cancel` token (not a child), so when one pump
    // dies uncleanly its `cancel.cancel()` also wakes the sibling — the whole tunnel winds down
    // together. `down()` cancels the same token, which the pumps treat as a clean teardown.
    let to_wire = {
        let (tun, transport, cancel, dead) =
            (tun.clone(), transport.clone(), cancel.clone(), pump_dead.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return, // clean teardown — not a death
                    r = tun.recv(&mut buf) => match r {
                        Ok(n) => {
                            // Finalize checksums (IPv4 or IPv6) in case the kernel handed us a
                            // partial-checksum packet.
                            nil_core::checksum::fix_l4_checksums(&mut buf[..n]);
                            if transport.send(&session, IpPacket::new(buf[..n].to_vec())).await.is_err() {
                                break; // tunnel closed → signal death; kill-switch holds
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
            // Reached only on an UNCLEAN exit (transport/TUN error). Trip the watchdog AND cancel
            // the sibling pump so the whole tunnel winds down together. The kill-switch stays
            // armed until `down()` — a dead tunnel must fail closed, never leak.
            dead.cancel();
            cancel.cancel();
        })
    };
    // tunnel → TUN: receive IP packets from the transport and write them to the OS.
    let from_wire = {
        let (tun, transport, cancel, dead) =
            (tun.clone(), transport.clone(), cancel.clone(), pump_dead.clone());
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return, // clean teardown — not a death
                    r = transport.recv(&session) => match r {
                        Ok(pkt) => {
                            if tun.send(pkt.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break, // tunnel closed → signal death; kill-switch holds
                    }
                }
            }
            dead.cancel();
            cancel.cancel();
        })
    };
    vec![to_wire, from_wire]
}

#[cfg(not(target_os = "android"))]
async fn resolve_ip(node: &NodeEndpoint) -> anyhow::Result<IpAddr> {
    resolve_host(&node.host).await
}

/// Resolve a bare host (or IP literal) to an `IpAddr` (port-agnostic — used for host-route
/// exceptions).
#[cfg(not(target_os = "android"))]
async fn resolve_host(host: &str) -> anyhow::Result<IpAddr> {
    let hp = format!("{host}:0");
    let mut addrs = tokio::net::lookup_host(hp.clone())
        .await
        .map_err(|e| anyhow::anyhow!("resolve {hp}: {e}"))?;
    addrs
        .next()
        .map(|s| s.ip())
        .ok_or_else(|| anyhow::anyhow!("no address for {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nil_core::Grant;
    use nil_transport::loopback::LoopbackTransport;

    /// The pre-token privilege gate must be deterministic and side-effect-free (it runs before a
    /// single-use token is spent, so it can't churn state), and its verdict must track root exactly:
    /// `Ok` iff effective-uid 0. Holds both as root (CI containers) and unprivileged (dev).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn preflight_tracks_euid_and_is_repeatable() {
        extern "C" {
            fn geteuid() -> u32;
        }
        let is_root = unsafe { geteuid() } == 0;
        let first = preflight_privilege();
        let second = preflight_privilege();
        assert_eq!(
            first.is_ok(),
            second.is_ok(),
            "deterministic: same verdict every call"
        );
        assert_eq!(first.is_ok(), is_root, "Ok iff running as root");
        if !is_root {
            assert!(matches!(first, Err(PreflightError::NeedsPrivilege)));
        }
    }

    #[test]
    fn assigned_ip_replaces_only_a_distinct_node_assignment() {
        let configured: Ipv4Addr = "10.74.0.2".parse().unwrap();
        // No assignment ⇒ keep configured (single-client fallback).
        assert_eq!(apply_assigned_ip(configured, None), None);
        // Node assigned the SAME address ⇒ no change (don't churn the TUN needlessly).
        assert_eq!(apply_assigned_ip(configured, Some(configured)), None);
        // Node assigned a DIFFERENT address ⇒ apply it (concurrent-client collision avoidance).
        let assigned: Ipv4Addr = "10.74.0.9".parse().unwrap();
        assert_eq!(apply_assigned_ip(configured, Some(assigned)), Some(assigned));
    }

    #[test]
    fn mtu_clamps_down_never_up() {
        // Unknown negotiated MTU ⇒ keep the configured ceiling.
        assert_eq!(clamp_mtu(1280, None), None);
        // Negotiated smaller (nested onion shrinks it) ⇒ clamp down.
        assert_eq!(clamp_mtu(1280, Some(1232)), Some(1232));
        // Negotiated equal or larger ⇒ never grow past the OS-expected ceiling.
        assert_eq!(clamp_mtu(1280, Some(1280)), None);
        assert_eq!(clamp_mtu(1280, Some(1500)), None);
        // A pathological > u16::MAX negotiated value saturates, then clamps as usual.
        assert_eq!(clamp_mtu(1280, Some(usize::MAX)), None);
    }

    /// The packet pump's core: a packet read off the source is checksum-finalized, pushed through
    /// the transport (`send`), and the echo comes back via `recv` byte-for-byte (decapsulate). This
    /// exercises the encapsulate→decapsulate round-trip over the in-memory loopback transport
    /// (the same `Transport` seam the real pump drives — the OS TUN endpoints are not mockable
    /// offline, so we drive the transport directly, matching `spawn_pumps`' send/recv sequence).
    #[tokio::test]
    async fn pump_roundtrips_a_packet_over_loopback() {
        let transport = LoopbackTransport::new();
        let session = transport
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("connect");

        // A minimal well-formed IPv4 header (20 bytes, no L4) so `fix_l4_checksums` is exercised
        // on the to-wire side exactly as the real pump does before `send`.
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[2] = 0x00;
        pkt[3] = 20; // total length
        nil_core::checksum::fix_l4_checksums(&mut pkt);

        transport
            .send(&session, IpPacket::new(pkt.clone()))
            .await
            .expect("send");
        let got = transport.recv(&session).await.expect("recv");
        assert_eq!(
            got.as_bytes(),
            pkt.as_slice(),
            "loopback pump must round-trip the packet unchanged"
        );

        transport.close(session).await.expect("close");
        // After teardown the session state is gone → a further send fails (kill-switch-hold
        // semantics: a dead tunnel surfaces as a transport error to the pump).
        assert!(
            transport
                .send(&session, IpPacket::new(vec![0x45]))
                .await
                .is_err(),
            "send after close must error"
        );
    }

    /// Two concurrent sessions never cross packets — the pump for one tunnel must not receive
    /// another's traffic (the loopback transport keys queues by session id).
    #[tokio::test]
    async fn pump_sessions_do_not_cross_talk() {
        let transport = LoopbackTransport::new();
        let a = transport
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("connect a");
        let b = transport
            .connect(NodeEndpoint::loopback(), Grant::mock())
            .await
            .expect("connect b");

        transport
            .send(&a, IpPacket::new(vec![0xAA]))
            .await
            .expect("send a");
        transport
            .send(&b, IpPacket::new(vec![0xBB]))
            .await
            .expect("send b");
        assert_eq!(transport.recv(&a).await.expect("recv a").as_bytes(), &[0xAA]);
        assert_eq!(transport.recv(&b).await.expect("recv b").as_bytes(), &[0xBB]);
    }
}
