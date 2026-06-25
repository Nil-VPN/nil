//! NIL VPN Data plane node (`nil-node`) — Phase 1 MASQUE/CONNECT-IP exit.
//!
//! Accepts an HTTP/3 extended `CONNECT` with `:protocol=connect-ip` over QUIC (UDP 443),
//! decapsulates IP packets from QUIC DATAGRAMs onto a TUN device, and NATs them to the
//! internet (Linux). Replies route back through the TUN and are re-encapsulated to the
//! client. Runs inside a Linux container/TEE; keeps **no disk logs** (stdout only) and
//! persists nothing identifying.
//!
//! Phase 1 presents a self-signed dev TLS cert (NOT attestation — RA-TLS is Phase 2, §5).

mod amneziawg;
mod attest;
mod cert;
mod config;
mod exit;
#[cfg(feature = "hw-attest")]
mod hw;
mod pool;
mod pqwg;
mod reality;
mod retry;
mod server;
mod wstunnel;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Logs to stdout only — never to disk (datapath must stay logless).
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = config::NodeConfig::from_env()?;

    // Production attestation posture (hw-attest build): refuse the dev escape hatches that would let
    // a real attested node be coerced into an open or fake-attested relay (PD-5/PD-6). These hold
    // even if an operator sets the env vars by mistake — a hardware node fails closed at startup.
    #[cfg(feature = "hw-attest")]
    {
        if cfg.allow_ungranted {
            anyhow::bail!(
                "hw-attest (production) build refuses NW_ALLOW_UNGRANTED — a real attested node must \
                 require a Coordinator grant and never serve grantless CONNECT-IP (open-relay risk)"
            );
        }
        if cfg.attest.is_none() {
            anyhow::bail!(
                "hw-attest (production) build refuses to start without NW_NODE_MEASUREMENT — a real \
                 attested node must publish the measurement clients pin (else it serves unattested)"
            );
        }
        // The node must be able to produce a COMPLETE attestation evidence blob at startup.
        // Otherwise it passes the env checks above, accepts QUIC connections, but fails EVERY
        // attestation silently (report_hex returns None → the client fails closed) while the node
        // stays "up" — an operational fail-open that looks healthy. Run the whole evidence path once
        // with throwaway inputs (configfs-TSM report fetch + VCEK/collateral load + encode) and bail
        // if ANY step fails, surfacing the specific cause: whether configfs-TSM is unavailable
        // (kernel < 6.7 / not mounted) OR the VCEK/DCAP collateral is unprovisioned, a node that
        // cannot attest refuses to start rather than serve unattested. (Both are equally fatal — a
        // missing VCEK makes every report unverifiable just as surely as a missing TSM interface.)
        if let Some(att) = cfg.attest.as_ref() {
            if let Err(e) = crate::hw::report_evidence(att.tee, &[0u8; 32], &[0u8; 32]) {
                anyhow::bail!(
                    "hw-attest: attestation self-check failed at startup — the node would serve \
                     unattested (every connection's report would be missing): {e}"
                );
            }
        }
        tracing::info!("hw-attest production posture: attestation evidence path verified + Coordinator grant required + measurement pinned");
    }

    // `bind`/`egress` are the node operator's own infra addresses (operational, not
    // user-linkable); the tunnel-internal addressing (node/client IPs) is deliberately
    // NOT logged — it reads as user data and the datapath must stay logless (SOUL §3 / PD-3).
    tracing::info!(
        bind = %cfg.bind, egress = %cfg.egress, tun = %cfg.tun_name, role = ?cfg.role,
        "nil-node starting (MASQUE/CONNECT-IP; no disk logs)"
    );

    let exit = exit::Exit::setup(&cfg)?;

    // NW_NODE_AMNEZIA selects the obfuscated-WireGuard fallback responder (a separate node from
    // the MASQUE one); otherwise the default MASQUE/CONNECT-IP server. Both own the exit TUN and
    // run until Ctrl-C; `exit` drops afterward and tears down the NAT rules.
    if std::env::var("NW_NODE_AMNEZIA").is_ok() {
        tracing::info!("node mode: AmneziaWG responder (obfuscated WireGuard cascade fallback)");
        amneziawg::run(&cfg, exit.tun()).await?;
    } else if std::env::var("NW_NODE_WSTUNNEL").is_ok() {
        tracing::info!("node mode: wstunnel responder (WireGuard over WebSocket-over-TLS cascade fallback)");
        wstunnel::run(&cfg, exit.tun()).await?;
    } else if std::env::var("NW_NODE_REALITY").is_ok() {
        tracing::info!("node mode: reality responder (WireGuard over VLESS-gated TLS cascade fallback)");
        reality::run(&cfg, exit.tun()).await?;
    } else {
        let cert = cert::DevCert::generate(vec!["nil-node".to_string(), "localhost".to_string()])?;
        server::run(&cfg, &cert, exit.tun()).await?;
    }
    Ok(())
}
