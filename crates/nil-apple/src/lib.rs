//! NIL VPN Apple engine — a C-ABI staticlib linked into the `NEPacketTunnelProvider` Network
//! Extension, shared by the iOS app extension and the macOS system extension. Neither has a TUN fd:
//! packets flow over the extension's `NEPacketTunnelFlow`, so the pump is callback-driven (not
//! `tun-rs`). The MASQUE transport is reused unchanged; the extension reads packets and calls
//! [`nil_ingest_packets`], and the engine injects decapsulated packets via the `write` callback.
//! Routing/DNS/MTU are the extension's `NEPacketTunnelNetworkSettings`, and the extension's own
//! sockets bypass the tunnel by default — so there is no `protect()`/NetControl.
//!
//! Identity never reaches the extension — only a node endpoint, optional pinned measurement, and the
//! per-connection Privacy Pass grant (token + attestation nonce). The blind-signed token is redeemed in
//! the container app; the account/payment identity never crosses this boundary.

use std::ffi::{c_char, c_void, CStr};
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use nil_core::{
    AttestExpectation, Grant, IpPacket, Measurement, NodeEndpoint, SevSnpTcbFloor, Tee,
    TransportKind,
};
use nil_transport::{MasqueConfig, MasqueTransport, Transport};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Bound copied packet memory even if `NEPacketTunnelFlow` produces faster than the network can
/// drain. At a 64 KiB defensive packet ceiling this is at most 16 MiB plus allocator overhead.
const INGEST_QUEUE_CAPACITY: usize = 256;
const MAX_INGEST_PACKET: usize = u16::MAX as usize;

/// Inbound write callback: inject a decapsulated IP packet into `packetFlow`. `af` = 2 (AF_INET)
/// or 30 (AF_INET6).
pub type NilWriteCb = extern "C" fn(ctx: *mut c_void, pkt: *const u8, len: usize, af: i32);
/// Status callback. `state`: 0=connecting, 1=connected, 2=failed, 3=stopped.
pub type NilStatusCb = extern "C" fn(ctx: *mut c_void, state: i32, detail: *const c_char);

/// C-ABI representation of the optional SEV-SNP firmware floor. `fmc == -1` means the deployment
/// does not require an FMC level (pre-Turin); otherwise it must fit in one byte.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NilSevSnpTcbFloor {
    pub fmc: i16,
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

/// Tunnel configuration handed in from Swift.
#[repr(C)]
pub struct NilConfig {
    pub node_host: *const c_char,
    pub node_port: u16,
    pub server_name: *const c_char,     // nullable
    pub measurement_hex: *const c_char, // nullable / empty
    /// SHA-256 of the node's exact TLS SPKI (32 bytes, hex); nullable only for debug fixtures.
    pub tls_spki_sha256_hex: *const c_char,
    /// Ed25519 public key for the measurement transparency log (32 bytes, hex). Mandatory for
    /// attested release builds; optional only in debug builds for local development.
    pub transparency_log_key_hex: *const c_char,
    pub tee_name: *const c_char, // nullable / empty => sev-snp
    pub allow_unattested: bool,
    /// Whether `min_tcb_sevsnp` is present. The separate bit preserves the distinction between an
    /// absent policy and a valid all-zero floor with no FMC requirement.
    pub has_min_tcb_sevsnp: bool,
    pub min_tcb_sevsnp: NilSevSnpTcbFloor,
    /// Privacy Pass grant for this connection, redeemed in the container app and passed as hex.
    /// `grant_hex` is the unblinded token bytes; `grant_nonce_hex` is the 32-byte RA-TLS freshness
    /// nonce the node must bind into its attestation report. Both nullable/empty: when absent the
    /// engine falls back to an empty token + a fresh random nonce (unauthenticated/Phase-1 path).
    pub grant_hex: *const c_char,
    pub grant_nonce_hex: *const c_char,
}

/// Opaque tunnel handle returned to Swift.
pub struct NilTunnel {
    ingest: mpsc::Sender<Vec<u8>>,
    dropped_packets: Arc<AtomicU64>,
    cancel: CancellationToken,
    mtu: Arc<AtomicU16>,
    assigned_ipv4: Arc<AtomicU32>,
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
    let tee = cstr(cfg.tee_name).and_then(|s| parse_tee(&s));
    let allow = cfg.allow_unattested;
    if allow && !cfg!(debug_assertions) {
        return std::ptr::null_mut();
    }
    // MRTD alone is not a complete TDX workload identity. The Apple providerConfiguration/FFI
    // does not carry the additional TDX policy yet, so refuse it before spawning the engine.
    if tee == Some(Tee::Tdx) {
        return std::ptr::null_mut();
    }
    let min_tcb_sevsnp = match decode_min_tcb(cfg.has_min_tcb_sevsnp, cfg.min_tcb_sevsnp) {
        Some(value) => value,
        None => return std::ptr::null_mut(),
    };
    let tls_spki_sha256 = match cstr(cfg.tls_spki_sha256_hex) {
        Some(h) => match hex(&h).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
            Some(digest) => Some(digest),
            None => return std::ptr::null_mut(),
        },
        None => None,
    };
    // Parse a supplied key strictly in every build. A release extension also refuses an absent key,
    // preventing a stale/tampered providerConfiguration from silently disabling transparency after
    // the container app validated its embedded release trust bundle.
    let transparency_log_key = match cstr(cfg.transparency_log_key_hex) {
        Some(h) => match hex(&h).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
            Some(key) => Some(key),
            None => return std::ptr::null_mut(),
        },
        None if !allow && !cfg!(debug_assertions) => return std::ptr::null_mut(),
        None => None,
    };
    if allow
        && (tls_spki_sha256.is_some() || min_tcb_sevsnp.is_some() || transparency_log_key.is_some())
    {
        // Policy without attestation cannot be enforced. Refuse contradictory bridge input rather
        // than silently discarding any field.
        return std::ptr::null_mut();
    }
    let port = cfg.node_port;
    let expected = if allow {
        None
    } else {
        match cstr(cfg.measurement_hex) {
            Some(h) => match hex(&h) {
                Some(b) if b.len() == 48 => {
                    let Some(tee) = tee else {
                        return std::ptr::null_mut();
                    };
                    Some(AttestExpectation {
                        tee,
                        measurement: Measurement(b),
                        tls_spki_sha256,
                        min_tcb_sevsnp,
                        tdx_policy: None,
                        transparency_log_key,
                    })
                }
                None => return std::ptr::null_mut(),
                Some(_) => return std::ptr::null_mut(),
            },
            None => return std::ptr::null_mut(),
        }
    };
    // Privacy Pass grant redeemed in the container app: token bytes + the 32-byte RA-TLS freshness
    // nonce, both as hex (either may be absent). An empty/absent token is fine (Phase-1 path); a
    // malformed nonce is a hard config error so we never silently connect with a bad freshness value.
    let grant_token = cstr(cfg.grant_hex)
        .and_then(|h| hex(&h))
        .unwrap_or_default();
    let grant_nonce: Option<[u8; 32]> = match cstr(cfg.grant_nonce_hex) {
        Some(h) => match hex(&h).and_then(|b| <[u8; 32]>::try_from(b).ok()) {
            Some(n) => Some(n),
            None => return std::ptr::null_mut(),
        },
        None => None,
    };

    let (ingest_tx, mut ingest_rx) = mpsc::channel::<Vec<u8>>(INGEST_QUEUE_CAPACITY);
    let dropped_packets = Arc::new(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let mtu = Arc::new(AtomicU16::new(0));
    let assigned_ipv4 = Arc::new(AtomicU32::new(0));
    let cbs = Callbacks {
        ctx,
        write: write_cb,
        status: status_cb,
    };
    let (mtu_t, assigned_ipv4_t, cancel_t) = (mtu.clone(), assigned_ipv4.clone(), cancel.clone());

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
            if let Some(ip) = transport.assigned_ip(&session) {
                assigned_ipv4_t.store(u32::from(ip), Ordering::Release);
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
        dropped_packets,
        cancel,
        mtu,
        assigned_ipv4,
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
        enqueue_packet(
            &t.ingest,
            &t.dropped_packets,
            std::slice::from_raw_parts(p, l),
        );
    }
}

fn enqueue_packet(sender: &mpsc::Sender<Vec<u8>>, dropped: &AtomicU64, packet: &[u8]) {
    if packet.len() <= MAX_INGEST_PACKET
        && sender.capacity() > 0
        && sender.try_send(packet.to_vec()).is_ok()
    {
        return;
    }
    let _ = dropped.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

/// Number of inbound packets dropped because the bounded queue was full/closed or the packet
/// exceeded the defensive size cap. This counter contains no endpoint or user identifier.
///
/// # Safety
/// `t` must be a live handle from [`nil_start`].
#[no_mangle]
pub unsafe extern "C" fn nil_dropped_packets(t: *const NilTunnel) -> u64 {
    t.as_ref()
        .map(|t| t.dropped_packets.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Node-assigned inner IPv4 as a host integer whose bytes are in network order (`10.74.0.2` is
/// `0x0a4a0002`), or zero until connected/when the peer did not assign one.
///
/// # Safety
/// `t` must be a live handle from [`nil_start`].
#[no_mangle]
pub unsafe extern "C" fn nil_assigned_ipv4(t: *const NilTunnel) -> u32 {
    t.as_ref()
        .map(|t| t.assigned_ipv4.load(Ordering::Acquire))
        .unwrap_or(0)
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

fn parse_tee(s: &str) -> Option<Tee> {
    if s.eq_ignore_ascii_case("tdx") {
        Some(Tee::Tdx)
    } else if s.eq_ignore_ascii_case("sev-snp") {
        Some(Tee::SevSnp)
    } else {
        None
    }
}

/// `None` is reserved for malformed bridge data; `Some(None)` is a deliberately absent floor.
fn decode_min_tcb(present: bool, floor: NilSevSnpTcbFloor) -> Option<Option<SevSnpTcbFloor>> {
    if !present {
        return Some(None);
    }
    let fmc = match floor.fmc {
        -1 => None,
        0..=255 => Some(floor.fmc as u8),
        _ => return None,
    };
    Some(Some(SevSnpTcbFloor {
        fmc,
        bootloader: floor.bootloader,
        tee: floor.tee,
        snp: floor.snp,
        microcode: floor.microcode,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    extern "C" fn noop_write(_: *mut c_void, _: *const u8, _: usize, _: i32) {}
    extern "C" fn noop_status(_: *mut c_void, _: i32, _: *const c_char) {}

    fn no_tcb_floor() -> NilSevSnpTcbFloor {
        NilSevSnpTcbFloor {
            fmc: -1,
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
        }
    }

    #[test]
    fn hex_parses_even_and_rejects_odd() {
        assert_eq!(hex("11aaff"), Some(vec![0x11, 0xaa, 0xff]));
        assert_eq!(hex("  11aa  "), Some(vec![0x11, 0xaa])); // trimmed
        assert_eq!(hex("abc"), None); // odd length
        assert_eq!(hex("zz"), None); // non-hex
    }

    #[test]
    fn apple_ingest_queue_is_bounded_and_counts_drops_without_metadata() {
        let (sender, _receiver) = mpsc::channel(1);
        let dropped = AtomicU64::new(0);
        enqueue_packet(&sender, &dropped, &[0x45, 0, 0, 1]);
        enqueue_packet(&sender, &dropped, &[0x45, 0, 0, 2]);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);

        enqueue_packet(&sender, &dropped, &vec![0u8; MAX_INGEST_PACKET + 1]);
        assert_eq!(dropped.load(Ordering::Relaxed), 2);
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
            tls_spki_sha256_hex: std::ptr::null(),
            transparency_log_key_hex: std::ptr::null(),
            tee_name: std::ptr::null(),
            allow_unattested: true,
            has_min_tcb_sevsnp: false,
            min_tcb_sevsnp: no_tcb_floor(),
            grant_hex: std::ptr::null(),
            grant_nonce_hex: short_nonce.as_ptr(),
        };
        let t = unsafe { nil_start(&cfg, std::ptr::null_mut(), noop_write, noop_status) };
        assert!(t.is_null(), "a wrong-length grant nonce must be rejected");
    }

    #[test]
    fn parse_tee_rejects_unknown_values() {
        assert_eq!(parse_tee("tdx"), Some(Tee::Tdx));
        assert_eq!(parse_tee("TDX"), Some(Tee::Tdx));
        assert_eq!(parse_tee("sev-snp"), Some(Tee::SevSnp));
        assert_eq!(parse_tee("SEV-SNP"), Some(Tee::SevSnp));
        assert_eq!(parse_tee(""), None);
        assert_eq!(parse_tee("something-unknown"), None);
    }

    #[test]
    fn apple_bridge_preserves_complete_sev_snp_tcb_floor() {
        let decoded = decode_min_tcb(
            true,
            NilSevSnpTcbFloor {
                fmc: 7,
                bootloader: 3,
                tee: 0,
                snp: 8,
                microcode: 115,
            },
        )
        .expect("valid bridge floor")
        .expect("present bridge floor");
        assert_eq!(decoded.fmc, Some(7));
        assert_eq!(decoded.bootloader, 3);
        assert_eq!(decoded.tee, 0);
        assert_eq!(decoded.snp, 8);
        assert_eq!(decoded.microcode, 115);

        assert!(decode_min_tcb(
            true,
            NilSevSnpTcbFloor {
                fmc: 256,
                ..no_tcb_floor()
            }
        )
        .is_none());
    }

    /// A null node host is a config error → null, no thread spawned.
    #[test]
    fn rejects_missing_node_host() {
        let cfg = NilConfig {
            node_host: std::ptr::null(),
            node_port: 443,
            server_name: std::ptr::null(),
            measurement_hex: std::ptr::null(),
            tls_spki_sha256_hex: std::ptr::null(),
            transparency_log_key_hex: std::ptr::null(),
            tee_name: std::ptr::null(),
            allow_unattested: true,
            has_min_tcb_sevsnp: false,
            min_tcb_sevsnp: no_tcb_floor(),
            grant_hex: std::ptr::null(),
            grant_nonce_hex: std::ptr::null(),
        };
        let t = unsafe { nil_start(&cfg, std::ptr::null_mut(), noop_write, noop_status) };
        assert!(t.is_null(), "a null node host must be rejected");
    }

    #[test]
    fn rejects_malformed_transparency_log_key_before_connecting() {
        let host = CString::new("node.example").unwrap();
        let measurement = CString::new("ab".repeat(48)).unwrap();
        let tee = CString::new("sev-snp").unwrap();
        let short_key = CString::new("cd").unwrap();
        let cfg = NilConfig {
            node_host: host.as_ptr(),
            node_port: 443,
            server_name: std::ptr::null(),
            measurement_hex: measurement.as_ptr(),
            tls_spki_sha256_hex: std::ptr::null(),
            transparency_log_key_hex: short_key.as_ptr(),
            tee_name: tee.as_ptr(),
            allow_unattested: false,
            has_min_tcb_sevsnp: false,
            min_tcb_sevsnp: no_tcb_floor(),
            grant_hex: std::ptr::null(),
            grant_nonce_hex: std::ptr::null(),
        };
        let t = unsafe { nil_start(&cfg, std::ptr::null_mut(), noop_write, noop_status) };
        assert!(
            t.is_null(),
            "a malformed transparency-log key must be rejected"
        );
    }

    #[test]
    fn rejects_malformed_tls_spki_identity_before_connecting() {
        let host = CString::new("node.example").unwrap();
        let measurement = CString::new("ab".repeat(48)).unwrap();
        let tee = CString::new("sev-snp").unwrap();
        let short_digest = CString::new("cd").unwrap();
        let cfg = NilConfig {
            node_host: host.as_ptr(),
            node_port: 443,
            server_name: std::ptr::null(),
            measurement_hex: measurement.as_ptr(),
            tls_spki_sha256_hex: short_digest.as_ptr(),
            transparency_log_key_hex: std::ptr::null(),
            tee_name: tee.as_ptr(),
            allow_unattested: false,
            has_min_tcb_sevsnp: false,
            min_tcb_sevsnp: no_tcb_floor(),
            grant_hex: std::ptr::null(),
            grant_nonce_hex: std::ptr::null(),
        };
        let t = unsafe { nil_start(&cfg, std::ptr::null_mut(), noop_write, noop_status) };
        assert!(t.is_null(), "a malformed TLS SPKI pin must be rejected");
    }
}
