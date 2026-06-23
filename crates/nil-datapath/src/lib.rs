//! Client-side system datapath: a [`Tunnel`] controller that connects a [`Transport`],
//! brings up a TUN device, flips the default route through it (with a host-route exception
//! for the node so the tunnel's own QUIC packets don't loop), arms a fail-closed
//! kill-switch, and runs the bidirectional packet pump.
//!
//! The OS-specific routing/kill-switch/DNS lives behind [`NetControl`]: Linux (verified in
//! Docker) and macOS (verified in a tart VM) are complete; Windows implements routing/DNS and
//! is verified in a Windows-on-ARM VM (its WFP kill-switch lands in that same pass — see
//! `windows.rs`). The [`Transport`] trait stays the only seam to the tunnel — this crate never
//! knows which transport is active.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use nil_core::{Grant, IpPacket, NodeEndpoint, Session};
use nil_transport::Transport;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "launch")]
pub mod launch;
#[cfg(feature = "launch")]
mod redeem;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "android")]
mod android;

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
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "android")))]
struct StubNet;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "android")))]
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
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "android")))]
fn new_net_control() -> Box<dyn NetControl> {
    Box::new(StubNet)
}

/// A live tunnel: the transport session, the OS networking it armed, and the pump tasks.
pub struct Tunnel {
    transport: Arc<dyn Transport>,
    session: Option<Session>,
    net: Box<dyn NetControl>,
    cancel: CancellationToken,
    pumps: Vec<JoinHandle<()>>,
    _tun: Arc<tun_rs::AsyncDevice>,
}

impl Tunnel {
    /// Connect the transport, bring up the TUN + routes + kill-switch, and start pumping.
    /// Desktop only — Android brings the tunnel up over a `VpnService`-provided fd (`up_with_fd`
    /// in `android.rs`), so routing/DNS/MTU/kill-switch are the OS's job, not ours.
    #[cfg(not(target_os = "android"))]
    pub async fn up(transport: Arc<dyn Transport>, mut cfg: TunnelConfig) -> anyhow::Result<Tunnel> {
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
        let grant = Grant { token: Vec::new(), nonce };

        let session = transport
            .connect(cfg.node.clone(), grant)
            .await
            .map_err(|e| anyhow::anyhow!("transport connect: {e}"))?;
        tracing::info!("tunnel session established; bringing up TUN + routes");

        // Size the TUN to the tunnel's negotiated usable MTU. Each nested hop shrinks it (the
        // inner QUIC rides the outer tunnel), so a multi-hop onion ends up smaller than a single
        // tunnel; clamp to the configured ceiling so we never grow it past what the OS expects.
        if let Some(m) = transport.tunnel_mtu(&session) {
            let m = m.min(u16::MAX as usize) as u16;
            if m < cfg.mtu {
                tracing::info!(negotiated = m, configured = cfg.mtu, "sizing TUN to negotiated tunnel MTU");
                cfg.mtu = m;
            }
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
        let pumps = spawn_pumps(transport.clone(), session, tun.clone(), &cancel);
        tracing::info!(tun = %tun_name, "tunnel up");

        Ok(Tunnel { transport, session: Some(session), net, cancel, pumps, _tun: tun })
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

fn spawn_pumps(
    transport: Arc<dyn Transport>,
    session: Session,
    tun: Arc<tun_rs::AsyncDevice>,
    cancel: &CancellationToken,
) -> Vec<JoinHandle<()>> {
    // TUN → tunnel: read IP packets off the OS and send them through the transport.
    let to_wire = {
        let (tun, transport, cancel) = (tun.clone(), transport.clone(), cancel.child_token());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    r = tun.recv(&mut buf) => match r {
                        Ok(n) => {
                            // Finalize checksums (IPv4 or IPv6) in case the kernel handed us a
                            // partial-checksum packet.
                            nil_core::checksum::fix_l4_checksums(&mut buf[..n]);
                            if transport.send(&session, IpPacket::new(buf[..n].to_vec())).await.is_err() {
                                break; // tunnel closed → kill-switch holds
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        })
    };
    // tunnel → TUN: receive IP packets from the transport and write them to the OS.
    let from_wire = {
        let (tun, transport, cancel) = (tun.clone(), transport.clone(), cancel.child_token());
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    r = transport.recv(&session) => match r {
                        Ok(pkt) => {
                            if tun.send(pkt.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break, // tunnel closed → kill-switch holds
                    }
                }
            }
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
