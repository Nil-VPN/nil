//! NIL VPN iOS engine — a C-ABI staticlib linked into the `NEPacketTunnelProvider` Network
//! Extension. iOS has no TUN fd: packets flow over the extension's `NEPacketTunnelFlow`, so the
//! pump is callback-driven (not `tun-rs`). The MASQUE transport is reused unchanged; the extension
//! reads packets and calls [`nil_ingest_packets`], and the engine injects decapsulated packets via
//! the `write` callback. Routing/DNS/MTU are the extension's `NEPacketTunnelNetworkSettings`, and
//! the extension's own sockets bypass the tunnel by default — so there is no `protect()`/NetControl.
//!
//! Identity never reaches the extension — only a node endpoint + optional pinned measurement; the
//! unlinkable token is redeemed in the container app.

use std::ffi::{c_char, c_void, CStr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use nil_core::{AttestExpectation, Grant, IpPacket, Measurement, NodeEndpoint, Tee, TransportKind};
use nil_transport::{MasqueConfig, MasqueTransport, Transport};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Inbound write callback: inject a decapsulated IP packet into `packetFlow`. `af` = 2 (AF_INET)
/// or 30 (AF_INET6).
pub type NilWriteCb = extern "C" fn(ctx: *mut c_void, pkt: *const u8, len: usize, af: i32);
/// Status callback. `state`: 0=connecting, 1=connected, 2=failed, 3=stopped.
pub type NilStatusCb = extern "C" fn(ctx: *mut c_void, state: i32, detail: *const c_char);

/// Tunnel configuration handed in from Swift.
#[repr(C)]
pub struct NilConfig {
    pub node_host: *const c_char,
    pub node_port: u16,
    pub server_name: *const c_char,     // nullable
    pub measurement_hex: *const c_char, // nullable / empty
    pub allow_unattested: bool,
}

/// Opaque tunnel handle returned to Swift.
pub struct NilTunnel {
    ingest: mpsc::UnboundedSender<Vec<u8>>,
    cancel: CancellationToken,
    mtu: Arc<AtomicU16>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// The Swift-provided context + callbacks. The extension guarantees they outlive the tunnel.
struct Callbacks {
    ctx: *mut c_void,
    write: NilWriteCb,
    status: NilStatusCb,
}
// SAFETY: the callbacks + ctx are only invoked from the engine thread; Swift keeps them alive for
// the tunnel's lifetime (until nil_stop).
unsafe impl Send for Callbacks {}
impl Callbacks {
    fn status(&self, state: i32) {
        (self.status)(self.ctx, state, std::ptr::null());
    }
    fn write(&self, pkt: &[u8]) {
        let af = if matches!(pkt.first().map(|b| b >> 4), Some(6)) { 30 } else { 2 };
        (self.write)(self.ctx, pkt.as_ptr(), pkt.len(), af);
    }
}

unsafe fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok().map(|s| s.to_owned()).filter(|s| !s.is_empty())
}

/// Start the tunnel. Returns null on a config error; otherwise an owned handle (free via
/// [`nil_stop`]). Connection is asynchronous; progress is reported through `status_cb`.
///
/// # Safety
/// `cfg` must be a valid `NilConfig` with valid (or null) C strings; `ctx`/callbacks must stay
/// valid until `nil_stop`.
#[no_mangle]
pub unsafe extern "C" fn nil_start(
    cfg: *const NilConfig,
    ctx: *mut c_void,
    write_cb: NilWriteCb,
    status_cb: NilStatusCb,
) -> *mut NilTunnel {
    let Some(cfg) = cfg.as_ref() else { return std::ptr::null_mut() };
    let Some(host) = cstr(cfg.node_host) else { return std::ptr::null_mut() };
    let sni = cstr(cfg.server_name);
    let allow = cfg.allow_unattested;
    let port = cfg.node_port;
    let expected = if allow {
        None
    } else {
        match cstr(cfg.measurement_hex) {
            Some(h) => match hex(&h) {
                Some(b) => Some(AttestExpectation { tee: Tee::SevSnp, measurement: Measurement(b) }),
                None => return std::ptr::null_mut(),
            },
            None => None,
        }
    };

    let (ingest_tx, mut ingest_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let cancel = CancellationToken::new();
    let mtu = Arc::new(AtomicU16::new(0));
    let cbs = Callbacks { ctx, write: write_cb, status: status_cb };
    let (mtu_t, cancel_t) = (mtu.clone(), cancel.clone());

    let thread = std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
            cbs.status(2);
            return;
        };
        rt.block_on(async move {
            cbs.status(0); // connecting
            let mcfg = MasqueConfig { server_name: sni, allow_unattested: allow, ..Default::default() };
            let transport: Arc<dyn Transport> = Arc::new(MasqueTransport::with_config(mcfg));
            let node = NodeEndpoint { host, port, kind: TransportKind::Masque, wg_pub: None, expected };

            let mut nonce = [0u8; 32];
            if getrandom::getrandom(&mut nonce).is_err() {
                cbs.status(2);
                return;
            }
            let session = match transport.connect(node, Grant { token: Vec::new(), nonce }).await {
                Ok(s) => s,
                Err(_) => {
                    cbs.status(2);
                    return;
                }
            };
            if let Some(m) = transport.tunnel_mtu(&session) {
                mtu_t.store(m.min(u16::MAX as usize) as u16, Ordering::Relaxed);
            }
            cbs.status(1); // connected

            loop {
                tokio::select! {
                    _ = cancel_t.cancelled() => break,
                    pkt = ingest_rx.recv() => match pkt {
                        Some(mut p) => {
                            nil_core::checksum::fix_l4_checksums(&mut p);
                            if transport.send(&session, IpPacket::new(p)).await.is_err() { break; }
                        }
                        None => break,
                    },
                    r = transport.recv(&session) => match r {
                        Ok(p) => cbs.write(p.as_bytes()),
                        Err(_) => break,
                    },
                }
            }
            let _ = transport.close(session).await;
            cbs.status(3); // stopped
        });
    });

    Box::into_raw(Box::new(NilTunnel { ingest: ingest_tx, cancel, mtu, thread: Some(thread) }))
}

/// Feed packets read from `packetFlow` into the tunnel. Arrays are parallel and `count` long.
///
/// # Safety
/// `t` must be a live handle from [`nil_start`]; the arrays must be valid for `count` elements.
#[no_mangle]
pub unsafe extern "C" fn nil_ingest_packets(
    t: *const NilTunnel,
    pkts: *const *const u8,
    lens: *const usize,
    _afs: *const i32,
    count: usize,
) {
    let Some(t) = t.as_ref() else { return };
    for i in 0..count {
        let p = *pkts.add(i);
        let l = *lens.add(i);
        if p.is_null() || l == 0 {
            continue;
        }
        let _ = t.ingest.send(std::slice::from_raw_parts(p, l).to_vec());
    }
}

/// The end-to-end usable MTU negotiated through the tunnel (0 until connected).
///
/// # Safety
/// `t` must be a live handle from [`nil_start`].
#[no_mangle]
pub unsafe extern "C" fn nil_negotiated_mtu(t: *const NilTunnel) -> u16 {
    t.as_ref().map(|t| t.mtu.load(Ordering::Relaxed)).unwrap_or(0)
}

/// Stop the tunnel, join the engine thread, and free the handle.
///
/// # Safety
/// `t` must be a handle from [`nil_start`], not used afterward. Call at most once.
#[no_mangle]
pub unsafe extern "C" fn nil_stop(t: *mut NilTunnel) {
    if t.is_null() {
        return;
    }
    let mut t = Box::from_raw(t);
    t.cancel.cancel();
    if let Some(h) = t.thread.take() {
        let _ = h.join();
    }
}

fn hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}
