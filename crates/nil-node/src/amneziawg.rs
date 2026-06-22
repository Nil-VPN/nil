//! Node-side AmneziaWG responder (architecture spec §4.3, cascade rung 2): the matching half of
//! the client's `nil_transport::AmneziaWgTransport`. Obfuscated WireGuard directly on UDP — the
//! censorship fallback used when MASQUE/QUIC is blocked.
//!
//! Selected by `NW_NODE_AMNEZIA`; the node runs this *instead of* the MASQUE server (a separate
//! node/container), so it owns the exit TUN outright — no dual-socket / shared-TUN dispatch.
//! Phase 1 serves a single client. It logs its WireGuard public key for the client to pin
//! (`NW_NODE_WG_PUB`).
//!
//! Trust model: unlike MASQUE, this rung has no RA-TLS channel, so it is **not TEE-attested** —
//! the client authenticates the node by its pinned WireGuard static key only. That is the
//! accepted tradeoff for a WireGuard-based circumvention fallback; the default MASQUE transport
//! remains attested.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tun_rs::AsyncDevice;

use nil_transport::{connectip, ObfsParams, PqWgCore, WgKeypair, WgStep};

use crate::config::NodeConfig;

pub async fn run(cfg: &NodeConfig, tun: Arc<AsyncDevice>) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(cfg.bind).await?;
    let kp = WgKeypair::generate().map_err(|e| anyhow::anyhow!("node wg keygen: {e}"))?;
    tracing::info!(
        wg_pub = %connectip::to_hex(kp.public.as_bytes()),
        "AmneziaWG responder listening — pin this as the client's NW_NODE_WG_PUB"
    );
    let node_secret: StaticSecret = kp.secret;
    let obfs = ObfsParams::default();

    // Single client (Phase 1): its source address + the WireGuard responder core, built once the
    // client's preface (its static pubkey) arrives.
    let mut client: Option<(SocketAddr, PqWgCore)> = None;
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
                let wire = &buf[..n];
                // Preface: the client's WG static pubkey → (re)build the responder for this peer.
                if let Some(client_pub) = obfs.try_preface(wire) {
                    let core = PqWgCore::without_psk(node_secret.clone(), PublicKey::from(client_pub), 2);
                    client = Some((from, core));
                    continue;
                }
                // Otherwise a WireGuard message: decapsulate against the current client's core.
                if let Some(wg) = obfs.deobfuscate(wire) {
                    if let Some((src, core)) = client.as_mut() {
                        *src = from; // track the client's current source address
                        let mut input = wg;
                        loop {
                            match core.decapsulate(&input) {
                                WgStep::Ip(ip) => { let _ = tun.send(&ip).await; break; }
                                WgStep::Network(b) => {
                                    let _ = socket.send_to(&obfs.obfuscate(&b), from).await;
                                    input = Vec::new();
                                }
                                WgStep::Done | WgStep::Err(_) => break,
                            }
                        }
                    }
                }
            }
            r = tun.recv(&mut tun_buf) => {
                let Ok(n) = r else { continue };
                // Internet reply → finalize checksums → encapsulate to the client → obfuscate.
                nil_core::checksum::fix_l4_checksums(&mut tun_buf[..n]);
                if let Some((src, core)) = client.as_mut() {
                    if let Ok(wire) = core.encapsulate(&tun_buf[..n]) {
                        let _ = socket.send_to(&obfs.obfuscate(&wire), *src).await;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                if let Some((src, core)) = client.as_mut() {
                    if let Some(b) = core.tick() {
                        let _ = socket.send_to(&obfs.obfuscate(&b), *src).await;
                    }
                }
            }
        }
    }
    Ok(())
}
