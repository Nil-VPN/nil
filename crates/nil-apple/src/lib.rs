//! NIL VPN Apple engine — a C-ABI staticlib linked into the `NEPacketTunnelProvider` Network
//! Extension, shared by the iOS app extension and the macOS system extension. Neither has a TUN fd:
//! packets flow over the extension's `NEPacketTunnelFlow`, so the pump is callback-driven (not
//! `tun-rs`). The MASQUE transport is reused unchanged; the extension reads packets and calls
//! [`nil_ingest_packets`], and the engine injects decapsulated packets via the `write` callback.
//! Routing/DNS/MTU are the extension's `NEPacketTunnelNetworkSettings`, and the extension's own
//! sockets bypass the tunnel by default — so there is no `protect()`/NetControl.
//!
//! Identity never reaches the extension — only a node endpoint, optional pinned measurement, and the
//! per-connection Privacy Pass grant (token + attestation nonce). The unlinkable token is redeemed in
//! the container app; the account/payment identity never crosses this boundary.

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
    pub tee_name: *const c_char,        // nullable / empty => sev-snp
    pub allow_unattested: bool,
    /// Privacy Pass grant for this connection, redeemed in the container app and passed as hex.
    /// `grant_hex` is the unblinded token bytes; `grant_nonce_hex` is the 32-byte RA-TLS freshness
    /// nonce the node must bind into its attestation report. Both nullable/empty: when absent the
    /// engine falls back to an empty token + a fresh random nonce (unauthenticated/Phase-1 path).
    pub grant_hex: *const c_char,
    pub grant_nonce_hex: *const c_char,
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
        let af = if matches!(pkt.first().map(|b| b >> 4), Some(6)) {
            30
        } else {
            2
        };
        (self.write)(self.ctx, pkt.as_ptr(), pkt.len(), af);
    }
}

unsafe fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p)
        .to_str()
        .ok()
        .map(|s| s.to_owned())
        .filter(|s| !s.is_empty())
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
    let Some(cfg) = cfg.as_ref() else {
        return std::ptr::null_mut();
    };
    let Some(host) = cstr(cfg.node_host) else {
        return std::ptr::null_mut();
    };
    let sni = cstr(cfg.server_name);
    let tee = cstr(cfg.tee_name)
        .map(|s| parse_tee(&s))
        .unwrap_or(Tee::SevSnp);
    let allow = cfg.allow_unattested;
    let port = cfg.node_port;
    let expected = if allow {
        None
    } else {
        match cstr(cfg.measurement_hex) {
            Some(h) => match hex(&h) {
                Some(b) => Some(AttestExpectation {
                    tee,
                    measurement: Measurement(b),
                    min_tcb_sevsnp: None,
                    transparency_log_key: None,
                }),
                None => return std::ptr::null_mut(),
            },
            None => None,
        }
    };
    // Privacy Pass grant redeemed in the container app: token bytes + the 32-byte RA-TLS freshness
    // nonce, both as hex (either may be absent). An empty/absent token is fine (Phase-1 path); a
    // malformed nonce is a hard config error so we never silently connect with a bad freshness value.
    let grant_token = cstr(cfg.grant_hex).and_then(|h| hex(&h)).unwrap_or_default();
    let grant_nonce: Option<[u8; 32]> = match cstr(cfg.grant_nonce_hex) {
        Some(h) => match hex(&h).and_then(|b| <[u8; 32]>::try_from(b).ok()) {
            Some(n) => Some(n),
            None => return std::ptr::null_mut(),
        },
        None => None,
    };

    let (ingest_tx, mut ingest_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let cancel = CancellationToken::new();
    let mtu = Arc::new(AtomicU16::new(0));
    let cbs = Callbacks {
        ctx,
        write: write_cb,
        status: status_cb,
    };
    let (mtu_t, cancel_t) = (mtu.clone(), cancel.clone());

    let thread = std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            cbs.status(2);
            return;
        };
        rt.block_on(async move {
            cbs.status(0); // connecting
            let mcfg = MasqueConfig {
                server_name: sni,
                allow_unattested: allow,
                ..Default::default()
            };
            let transport: Arc<dyn Transport> = Arc::new(MasqueTransport::with_config(mcfg));

            // Use the redeemed grant's freshness nonce when present; otherwise a fresh random one
            // (unauthenticated/Phase-1 path). MASQUE only emits the token header when non-empty.
            let nonce = match grant_nonce {
                Some(n) => n,
                None => {
                    let mut n = [0u8; 32];
                    if getrandom::getrandom(&mut n).is_err() {
                        cbs.status(2);
                        return;
                    }
                    n
                }
            };
            let grant = Grant {
                token: grant_token,
                nonce,
            };
            let node = NodeEndpoint {
                host,
                port,
                kind: TransportKind::Masque,
                wg_pub: None,
                expected,
                grant: Some(grant.clone()),
            };

            let session = match transport.connect(node, grant).await {
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

    Box::into_raw(Box::new(NilTunnel {
        ingest: ingest_tx,
        cancel,
        mtu,
        thread: Some(thread),
    }))
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
    t.as_ref()
        .map(|t| t.mtu.load(Ordering::Relaxed))
        .unwrap_or(0)
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
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn parse_tee(s: &str) -> Tee {
    if s.eq_ignore_ascii_case("tdx") {
        Tee::Tdx
    } else {
        Tee::SevSnp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    extern "C" fn noop_write(_: *mut c_void, _: *const u8, _: usize, _: i32) {}
    extern "C" fn noop_status(_: *mut c_void, _: i32, _: *const c_char) {}

    #[test]
    fn hex_parses_even_and_rejects_odd() {
        assert_eq!(hex("11aaff"), Some(vec![0x11, 0xaa, 0xff]));
        assert_eq!(hex("  11aa  "), Some(vec![0x11, 0xaa])); // trimmed
        assert_eq!(hex("abc"), None); // odd length
        assert_eq!(hex("zz"), None); // non-hex
    }

    /// A malformed grant nonce (not 32 bytes) is a hard config error: `nil_start` must return null
    /// BEFORE spawning the engine thread or touching the network — so a bad freshness value can
    /// never reach the node. `allow_unattested` here isolates the grant path from measurement parsing.
    #[test]
    fn rejects_grant_nonce_of_wrong_length() {
        let host = CString::new("node.example").unwrap();
        let short_nonce = CString::new("aa").unwrap(); // 1 byte, not 32
        let cfg = NilConfig {
            node_host: host.as_ptr(),
            node_port: 443,
            server_name: std::ptr::null(),
            measurement_hex: std::ptr::null(),
            tee_name: std::ptr::null(),
            allow_unattested: true,
            grant_hex: std::ptr::null(),
            grant_nonce_hex: short_nonce.as_ptr(),
        };
        let t = unsafe { nil_start(&cfg, std::ptr::null_mut(), noop_write, noop_status) };
        assert!(t.is_null(), "a wrong-length grant nonce must be rejected");
    }

    #[test]
    fn parse_tee_maps_tdx_case_insensitively_and_defaults_to_sev_snp() {
        // "tdx" (any case) → Tdx; everything else → the SEV-SNP default. Never panics — an unknown
        // TEE name from config falls back to a real, attestable TEE rather than erroring.
        assert_eq!(parse_tee("tdx"), Tee::Tdx);
        assert_eq!(parse_tee("TDX"), Tee::Tdx);
        assert_eq!(parse_tee("Tdx"), Tee::Tdx);
        assert_eq!(parse_tee("sev-snp"), Tee::SevSnp);
        assert_eq!(parse_tee("SEV-SNP"), Tee::SevSnp);
        assert_eq!(parse_tee(""), Tee::SevSnp);
        assert_eq!(parse_tee("something-unknown"), Tee::SevSnp);
    }

    /// A null node host is a config error → null, no thread spawned.
    #[test]
    fn rejects_missing_node_host() {
        let cfg = NilConfig {
            node_host: std::ptr::null(),
            node_port: 443,
            server_name: std::ptr::null(),
            measurement_hex: std::ptr::null(),
            tee_name: std::ptr::null(),
            allow_unattested: true,
            grant_hex: std::ptr::null(),
            grant_nonce_hex: std::ptr::null(),
        };
        let t = unsafe { nil_start(&cfg, std::ptr::null_mut(), noop_write, noop_status) };
        assert!(t.is_null(), "a null node host must be rejected");
    }
}
