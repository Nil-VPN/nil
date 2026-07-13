//! Node-side REALITY/VLESS responder (architecture spec §4.3, cascade rung 4): WireGuard carried
//! inside a VLESS-shared-key-gated TLS session — the matching half of the client's
//! `nil_transport::RealityTransport`.
//!
//! Selected by `NW_NODE_REALITY`; the node runs this instead of the MASQUE server (a separate
//! node/container), so it owns the exit TUN. Phase 1 serves a single client (one connection at a
//! time). Logs its WireGuard public key for the client to pin (`NW_NODE_REALITY_WG_PUB`). The TLS
//! uses a self-signed dev cert and is NOT the security boundary — the inner WireGuard is (unattested,
//! pinned-key trust; the TLS is the obfuscation envelope).
//!
//! ## VLESS auth gate
//! The first length-delimited record from the client is `[16-byte auth ID ‖ 32-byte client WG
//! pubkey]`. The auth ID is derived from this node's pinned WG static key
//! (`nil_transport::derive_auth_id`, shared with the client so the contract can't drift). The
//! responder validates it in **constant time** before building a WireGuard core; a connection that
//! presents the wrong (or no) ID is dropped without ever revealing a tunnel — the prober just sees a
//! TLS connection that closed. This is the VLESS shared-key gate; the inner WireGuard is the real
//! security boundary.
//!
//! ## HONEST status (see `nil_transport::reality` for the full note)
//! This is the VLESS-over-TLS responder, faithfully implemented. The REALITY-specific TLS borrow
//! (presenting a *proxied real foreign-site* cert to clients we can't authenticate, instead of a
//! self-signed cert, and switching only key-holding clients to the tunnel) is NOT implemented — an
//! unauthenticated prober here is simply dropped after the TLS handshake rather than reverse-proxied
//! to a real site. Closing that gap is the cert-stealing-reverse-proxy work tracked for a later
//! phase. PQ status: classical WireGuard only (same as the wstunnel rung).

use std::sync::Arc;
use std::time::Duration;

/// Bound on the TLS + auth-record handshake. A peer that connects and then stalls (slowloris) or
/// never sends its auth record must not occupy the single-client slot indefinitely.
const REALITY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::io::{split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::TcpListener;
use tokio_rustls::server::TlsStream;

use nil_transport::{
    connectip, derive_auth_id, read_record_from, write_record_to, PqWgCore, WgKeypair, WgStep,
    REALITY_AUTH_ID_LEN,
};
use tun_rs::AsyncDevice;

use crate::config::NodeConfig;

pub async fn run(cfg: &NodeConfig, tun: Arc<AsyncDevice>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.bind).await?;
    let kp = WgKeypair::generate().map_err(|e| anyhow::anyhow!("node wg keygen: {e}"))?;
    tracing::info!(
        wg_pub = %connectip::to_hex(kp.public.as_bytes()),
        "reality responder listening — pin this as the client's NW_NODE_REALITY_WG_PUB"
    );
    let node_secret = kp.secret;
    // The VLESS auth ID this node expects: derived from its own pinned WG static key, the same
    // shared identity the client derives from. Shared derivation with the client
    // (`nil_transport::derive_auth_id`) so the contract can't drift.
    let expected_auth = derive_auth_id(kp.public.as_bytes());
    let acceptor = tls_acceptor()?;
    let mut tun_buf = vec![0u8; 65535];

    loop {
        let accepted = tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("nil-node (reality) shutting down");
                break;
            }
            r = listener.accept() => r,
        };
        let Ok((tcp, _)) = accepted else { continue };

        // Bound the TLS accept so a peer that stalls mid-handshake (slowloris) can't wedge the node.
        // TLS accept errors are dropped silently — they are attacker-triggerable (TLS is
        // no-client-auth) and the data plane keeps no connection logs.
        let acceptor = acceptor.clone();
        let upgrade = tokio::time::timeout(REALITY_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await;
        let tls = match upgrade {
            Ok(Ok(tls)) => tls,
            _ => continue, // timed out or TLS failed → drop, keep serving
        };

        // Serve this client to completion (single-client Phase 1), then accept the next — but keep
        // ctrl_c responsive so a long-lived (or stuck) session never starves shutdown. The auth
        // read inside `serve` is itself bounded, so a connected-but-silent peer frees the slot.
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("nil-node (reality) shutting down");
                break;
            }
            _ = serve(tls, &node_secret, &expected_auth, &tun, &mut tun_buf) => {}
        }
    }
    Ok(())
}

/// Serve one TLS client: validate its VLESS auth record, build the WireGuard responder, and pump
/// length-delimited records ↔ the exit TUN until the connection closes.
async fn serve<S>(
    tls: TlsStream<S>,
    node_secret: &StaticSecret,
    expected_auth: &[u8; REALITY_AUTH_ID_LEN],
    tun: &Arc<AsyncDevice>,
    tun_buf: &mut [u8],
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr): (ReadHalf<TlsStream<S>>, WriteHalf<TlsStream<S>>) = split(tls);

    // Record 1: [auth_id ‖ client WG pubkey]. Bounded — a peer that completes the TLS handshake but
    // never sends its auth record must not hold the single-client slot forever.
    let hello =
        match tokio::time::timeout(REALITY_HANDSHAKE_TIMEOUT, read_record_from(&mut rd)).await {
            Ok(Ok(b)) if b.len() == REALITY_AUTH_ID_LEN + 32 => b,
            _ => return, // timed out / closed / malformed auth record → drop
        };
    // Constant-time auth check: a wrong ID is dropped without revealing a tunnel (the prober sees a
    // plain TLS connection close). A timing side-channel on a key-derived ID is low-value, but a
    // constant-time compare costs nothing and keeps the gate honest.
    if !constant_time_eq(&hello[..REALITY_AUTH_ID_LEN], expected_auth) {
        return;
    }
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(&hello[REALITY_AUTH_ID_LEN..]);
    let mut core = PqWgCore::without_psk(node_secret.clone(), PublicKey::from(client_pub), 2);

    loop {
        tokio::select! {
            rec = read_record_from(&mut rd) => match rec {
                Ok(b) => {
                    let mut input = b;
                    loop {
                        match core.decapsulate(&input) {
                            WgStep::Ip(ip) => { let _ = tun.send(&ip).await; break; }
                            WgStep::Network(out) => {
                                if write_record_to(&mut wr, &out).await.is_err() { return; }
                                input = Vec::new();
                            }
                            WgStep::Done | WgStep::Err(_) => break,
                        }
                    }
                }
                Err(_) => return, // close / framing error
            },
            r = tun.recv(tun_buf) => {
                let Ok(n) = r else { return };
                nil_core::checksum::fix_l4_checksums(&mut tun_buf[..n]);
                if let Ok(wire) = core.encapsulate(&tun_buf[..n]) {
                    if write_record_to(&mut wr, &wire).await.is_err() { return; }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                if let Some(b) = core.tick() {
                    if write_record_to(&mut wr, &b).await.is_err() { return; }
                }
            }
        }
    }
}

/// Constant-time equality for the (fixed-length) auth ID. Avoids a data-dependent early return.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A TLS acceptor with a fresh self-signed dev cert (the TLS is the obfuscation envelope, not the
/// trust boundary — the inner WireGuard is). See the module honest-status note: a real REALITY
/// deployment would present a *proxied real foreign-site* cert here, not a self-signed one.
fn tls_acceptor() -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let ck =
        rcgen::generate_simple_self_signed(vec!["nil-node".to_string(), "localhost".to_string()])?;
    let cert_der = ck.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(ck.key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("reality server key: {e}"))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("rustls server config: {e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| anyhow::anyhow!("rustls single cert: {e}"))?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}
