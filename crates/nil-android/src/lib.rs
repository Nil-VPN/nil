//! NIL VPN Android JNI engine. Built as `libnil_android.so` and loaded by the Kotlin `:vpn`
//! service process (`NilVpnService` / `NilNative`). It owns the MASQUE datapath: it builds the
//! transport with a `socket_hook` that calls `VpnService.protect(fd)` (so the tunnel's own QUIC
//! to the node bypasses the TUN), then runs [`nil_datapath::Tunnel::up_with_fd`] over the
//! VpnService-provided TUN fd. Identity never reaches this process — only a node endpoint and an
//! optional pinned measurement; the blind-signed Privacy Pass token is redeemed in the app process.
#![cfg(target_os = "android")]

use std::os::fd::RawFd;
use std::sync::{Arc, Mutex, OnceLock};

use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::{JNIEnv, JavaVM};

use nil_core::{
    AttestExpectation, Grant, Measurement, NodeEndpoint, SevSnpTcbFloor, Tee, TransportKind,
};
use nil_datapath::{Tunnel, TunnelConfig};
use nil_transport::{MasqueConfig, MasqueTransport, Transport};

/// Cached JavaVM so the `protect()` callback can attach the QUIC I/O thread and call into Kotlin.
static JVM: OnceLock<JavaVM> = OnceLock::new();

/// A live engine: the tokio runtime + the tunnel it brought up.
struct Engine {
    rt: tokio::runtime::Runtime,
    tunnel: Mutex<Option<Tunnel>>,
}

#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("nil-android"),
    );
    let _ = JVM.set(vm);
    jni::sys::JNI_VERSION_1_6 as jint
}

fn jstr(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|v| v.into()).unwrap_or_default()
}

/// Start the tunnel over the VpnService TUN fd. Returns an opaque handle (0 on failure).
#[no_mangle]
pub extern "system" fn Java_com_nilvpn_NilNative_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
    node_host: JString,
    node_port: jint,
    mtu: jint,
    server_name: JString,
    measurement_hex: JString,
    tls_spki_sha256_hex: JString,
    transparency_log_key_hex: JString,
    tee_name: JString,
    min_tcb_present: jboolean,
    min_tcb_fmc: jint,
    min_tcb_bootloader: jint,
    min_tcb_tee: jint,
    min_tcb_snp: jint,
    min_tcb_microcode: jint,
    grant_hex: JString,
    grant_nonce_hex: JString,
    allow_unattested: jboolean,
    vpn_service: JObject,
) -> jlong {
    let host = jstr(&mut env, &node_host);
    let sni = jstr(&mut env, &server_name);
    let meas_hex = jstr(&mut env, &measurement_hex);
    let tls_spki_hex = jstr(&mut env, &tls_spki_sha256_hex);
    let log_key_hex = jstr(&mut env, &transparency_log_key_hex);
    let tee_name = jstr(&mut env, &tee_name);
    let grant_hex = jstr(&mut env, &grant_hex);
    let grant_nonce_hex = jstr(&mut env, &grant_nonce_hex);
    let allow = allow_unattested != 0;
    if allow && !cfg!(debug_assertions) {
        log::error!("allow_unattested is unavailable in release Android builds");
        return 0;
    }
    if tee_name.eq_ignore_ascii_case("tdx") {
        log::error!(
            "TDX is unavailable in the Android native bridge until it carries the complete workload policy"
        );
        return 0;
    }
    let min_tcb_sevsnp = match decode_min_tcb(
        min_tcb_present != 0,
        min_tcb_fmc,
        min_tcb_bootloader,
        min_tcb_tee,
        min_tcb_snp,
        min_tcb_microcode,
    ) {
        Some(value) => value,
        None => {
            log::error!("invalid SEV-SNP minimum TCB bridge values");
            return 0;
        }
    };

    let tls_spki_sha256 = if tls_spki_hex.trim().is_empty() {
        None
    } else {
        match hex_to_bytes(&tls_spki_hex).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
            Some(digest) => Some(digest),
            None => {
                log::error!("TLS SPKI SHA-256 identity must be 32 bytes of hex");
                return 0;
            }
        }
    };

    // A present key is always parsed strictly. Release engines additionally require it, so a
    // stale/tampered app-to-service contract cannot silently turn off the transparency proof gate
    // after the container app cross-checked the embedded trust bundle.
    let transparency_log_key = if log_key_hex.trim().is_empty() {
        if !allow && !cfg!(debug_assertions) {
            log::error!("a transparency-log key is required in release Android builds");
            return 0;
        }
        None
    } else {
        match hex_to_bytes(&log_key_hex).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
            Some(key) => Some(key),
            None => {
                log::error!("transparency-log key must be 32 bytes of hex");
                return 0;
            }
        }
    };
    if allow
        && (tls_spki_sha256.is_some() || min_tcb_sevsnp.is_some() || transparency_log_key.is_some())
    {
        log::error!("attestation policy cannot be paired with allow_unattested");
        return 0;
    }

    // protect() callback: invoked at the UDP bind site (bind → protect → connect) so the tunnel's
    // own QUIC to the node bypasses the VpnService TUN (no loop).
    let vpn_global = match env.new_global_ref(vpn_service) {
        Ok(g) => g,
        Err(e) => {
            log::error!("new_global_ref(vpnService): {e}");
            return 0;
        }
    };
    let socket_hook: Arc<dyn Fn(RawFd) -> bool + Send + Sync> = Arc::new(move |fd: RawFd| {
        if let Some(vm) = JVM.get() {
            if let Ok(mut env) = vm.attach_current_thread() {
                match env
                    .call_method(&vpn_global, "protect", "(I)Z", &[JValue::Int(fd as jint)])
                    .and_then(|v| v.z())
                {
                    Ok(true) => return true,
                    Ok(false) => log::error!("VpnService.protect returned false"),
                    Err(e) => log::error!("VpnService.protect failed: {e}"),
                }
            }
        }
        false
    });

    let expected = if allow {
        None
    } else {
        match hex_to_bytes(&meas_hex) {
            Some(b) if b.len() == 48 => {
                let tee = match parse_tee(&tee_name) {
                    Some(tee) => tee,
                    None => {
                        log::error!("unknown TEE name");
                        return 0;
                    }
                };
                // The JNI contract does not yet carry the complete TDX workload policy. Raw MRTD
                // is insufficient, so reject before spawning an engine instead of constructing a
                // policy that can only fail later.
                if tee == Tee::Tdx {
                    log::error!("native Android TDX requires the complete workload-policy ABI");
                    return 0;
                }
                Some(AttestExpectation {
                    tee,
                    measurement: Measurement(b),
                    tls_spki_sha256,
                    min_tcb_sevsnp,
                    tdx_policy: None,
                    transparency_log_key,
                })
            }
            _ => {
                log::error!("measurement must be 48 bytes of hex");
                return 0;
            }
        }
    };

    let cfg = MasqueConfig {
        server_name: if sni.is_empty() { None } else { Some(sni) },
        allow_unattested: allow,
        socket_hook: Some(socket_hook),
        ..Default::default()
    };
    let transport: Arc<dyn Transport> = Arc::new(MasqueTransport::with_config(cfg));

    // The Coordinator-issued grant for this hop, redeemed in the app process and threaded through
    // here (token + per-connection nonce, both hex). Both present → a real grant the node verifies
    // before accepting CONNECT-IP; both empty → no grant (a dev node that allows ungranted tunnels).
    // A present-but-malformed grant fails closed (returns 0) rather than connecting ungranted.
    let grant = match (
        grant_hex.trim().is_empty(),
        grant_nonce_hex.trim().is_empty(),
    ) {
        (true, true) => None,
        (false, false) => {
            let token = match hex_to_bytes(&grant_hex) {
                Some(b) => b,
                None => {
                    log::error!("grant is not valid hex");
                    return 0;
                }
            };
            let nonce = match hex_to_bytes(&grant_nonce_hex) {
                Some(b) if b.len() == 32 => {
                    let mut n = [0u8; 32];
                    n.copy_from_slice(&b);
                    n
                }
                _ => {
                    log::error!("grant nonce must be 32 bytes of hex");
                    return 0;
                }
            };
            Some(Grant { token, nonce })
        }
        _ => {
            log::error!("grant and grant nonce must be provided together");
            return 0;
        }
    };

    let node = NodeEndpoint {
        host,
        port: node_port as u16,
        kind: TransportKind::Masque,
        wg_pub: None,
        expected,
        grant,
    };
    // The VpnService.Builder already set the TUN address/DNS/MTU/routes at establish(); up_with_fd
    // only uses `node`. The other fields are placeholders the NoopNet ignores.
    let tcfg = TunnelConfig {
        node,
        tun_name: "nil0".to_string(),
        client_ip: std::net::Ipv4Addr::new(10, 74, 0, 2),
        peer_ip: std::net::Ipv4Addr::new(10, 74, 0, 1),
        prefix: 24,
        mtu: mtu as u16,
        dns: Vec::new(),
        kill_switch: false,
        also_except: Vec::new(),
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("tokio runtime: {e}");
            return 0;
        }
    };
    let tunnel = match rt.block_on(Tunnel::up_with_fd(transport, tcfg, tun_fd as RawFd)) {
        Ok(t) => t,
        Err(e) => {
            log::error!("tunnel up_with_fd: {e}");
            return 0;
        }
    };
    log::info!("nil-android tunnel up");
    let engine = Box::new(Engine {
        rt,
        tunnel: Mutex::new(Some(tunnel)),
    });
    Box::into_raw(engine) as jlong
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

/// `None` is malformed input; `Some(None)` is a deliberately absent policy. JNI uses `-1` as the
/// no-FMC sentinel because FMC does not exist on pre-Turin processors.
fn decode_min_tcb(
    present: bool,
    fmc: jint,
    bootloader: jint,
    tee: jint,
    snp: jint,
    microcode: jint,
) -> Option<Option<SevSnpTcbFloor>> {
    if !present {
        return Some(None);
    }
    let fmc = match fmc {
        -1 => None,
        0..=255 => Some(fmc as u8),
        _ => return None,
    };
    Some(Some(SevSnpTcbFloor {
        fmc,
        bootloader: u8::try_from(bootloader).ok()?,
        tee: u8::try_from(tee).ok()?,
        snp: u8::try_from(snp).ok()?,
        microcode: u8::try_from(microcode).ok()?,
    }))
}

/// Tear the tunnel down and free the engine. Idempotent on a 0 handle.
#[no_mangle]
pub extern "system" fn Java_com_nilvpn_NilNative_nativeStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: `handle` is the Box<Engine> pointer returned by nativeStart; Kotlin calls this once.
    let engine = unsafe { Box::from_raw(handle as *mut Engine) };
    if let Ok(mut guard) = engine.tunnel.lock() {
        if let Some(mut tunnel) = guard.take() {
            let _ = engine.rt.block_on(tunnel.down());
        }
    }
    log::info!("nil-android tunnel down");
}

/// Real tunnel health for the app↔service IPC, as tiny JSON `{"state":"up|dead|down"}`:
/// - `down`  — no engine (handle 0): never started, or already stopped.
/// - `up`    — the pumps are live (`Tunnel::is_up()`), traffic flows.
/// - `dead`  — the engine exists but a pump exited (hung/dead tunnel/TUN error): the full-route TUN
///   still blackholes (fail-closed), but traffic is NOT flowing — the caller must surface this, not
///   keep claiming "connected". This is what makes the status honest instead of optimistic.
#[no_mangle]
pub extern "system" fn Java_com_nilvpn_NilNative_nativeStatus(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let state = if handle == 0 {
        "down"
    } else {
        // SAFETY: `handle` is the Box<Engine> pointer returned by nativeStart and remains valid
        // until nativeStop frees it; the Kotlin side only polls between start and stop. We BORROW
        // (never `Box::from_raw`, which would free it).
        let engine = unsafe { &*(handle as *const Engine) };
        match engine.tunnel.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(tunnel) if tunnel.is_up() => "up",
                _ => "dead",
            },
            Err(_) => "dead",
        }
    };
    let json = format!("{{\"state\":\"{state}\"}}");
    env.new_string(json)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
