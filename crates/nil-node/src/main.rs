//! NIL VPN Data plane node (`nil-node`) — Phase 1 MASQUE/CONNECT-IP exit.
//!
//! Accepts an HTTP/3 extended `CONNECT` with `:protocol=connect-ip` over QUIC (UDP 443),
//! decapsulates IP packets from QUIC DATAGRAMs onto a TUN device, and NATs them to the
//! internet (Linux). Replies route back through the TUN and are re-encapsulated to the
//! client. Runs inside a Linux container/TEE; keeps **no disk logs** (stdout only) and
//! persists nothing identifying.
//!
//! Phase 1 presents a self-signed dev TLS cert (NOT attestation — RA-TLS is Phase 2, §5).

#[cfg(all(not(debug_assertions), feature = "dev-fallbacks"))]
compile_error!(
    "nil-node: `dev-fallbacks` is development-only and cannot be compiled without debug assertions"
);
#[cfg(all(not(debug_assertions), feature = "synthetic-attest"))]
compile_error!(
    "nil-node: `synthetic-attest` is development-only and cannot be compiled without debug assertions"
);
#[cfg(all(not(debug_assertions), feature = "dev-trace"))]
compile_error!(
    "nil-node: `dev-trace` is development-only and cannot be compiled without debug assertions"
);
#[cfg(all(feature = "hw-attest", feature = "dev-fallbacks"))]
compile_error!(
    "nil-node: `dev-fallbacks` and `hw-attest` are mutually exclusive until every fallback responder enforces grant and hardware-attestation parity"
);

#[cfg(feature = "dev-fallbacks")]
mod amneziawg;
mod attest;
mod cert;
mod config;
#[cfg(feature = "dev-trace")]
mod devtrace;
mod exit;
mod grant_replay;
mod gso;
#[cfg(feature = "hw-attest")]
mod hw;
mod pool;
mod pqwg;
#[cfg(feature = "dev-fallbacks")]
mod reality;
mod retry;
mod server;
#[cfg(feature = "dev-fallbacks")]
mod wstunnel;

use anyhow::Result;
use std::path::Path;
use tracing_subscriber::EnvFilter;

const TLS_KEY_USAGE: &str = "usage: nil-node tls-keygen PATH";

/// Handle offline TLS identity provisioning before service config or logging starts. The private
/// key is written owner-only and never printed; stdout contains only its registry-safe SPKI hash.
fn run_tls_key_command() -> Result<bool> {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args.len() == 1 {
        return Ok(false);
    }
    if args.len() != 3 || args.get(1).and_then(|arg| arg.to_str()) != Some("tls-keygen") {
        anyhow::bail!(TLS_KEY_USAGE);
    }
    let digest = cert::generate_tls_key(Path::new(&args[2]))?;
    println!("tls_spki_sha256={}", nil_core::grant::to_hex(&digest));
    Ok(true)
}

#[tokio::main]
async fn main() -> Result<()> {
    if run_tls_key_command()? {
        return Ok(());
    }
    // Logs to stdout only — never to disk (datapath must stay logless).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = config::NodeConfig::from_env()?;

    #[cfg(not(feature = "dev-fallbacks"))]
    if std::env::var_os("NW_NODE_AMNEZIA").is_some()
        || std::env::var_os("NW_NODE_WSTUNNEL").is_some()
        || std::env::var_os("NW_NODE_REALITY").is_some()
    {
        anyhow::bail!(
            "fallback responder mode requires a debug build with the explicit `dev-fallbacks` feature"
        );
    }

    // Production attestation posture (hw-attest build): refuse the dev escape hatches that would let
    // a real attested node be coerced into an open or fake-attested relay (PD-5/PD-6). These hold
    // even if an operator sets the env vars by mistake — a hardware node fails closed at startup.
    #[cfg(feature = "hw-attest")]
    {
        if std::env::var_os("NW_NODE_AMNEZIA").is_some()
            || std::env::var_os("NW_NODE_WSTUNNEL").is_some()
            || std::env::var_os("NW_NODE_REALITY").is_some()
        {
            anyhow::bail!(
                "hw-attest production build refuses fallback responders: alternate transports do not yet provide the full grant and attestation gate"
            );
        }
        if cfg.allow_ungranted {
            anyhow::bail!(
                "hw-attest (production) build refuses NW_ALLOW_UNGRANTED — a real attested node must \
                 require a Coordinator grant and never serve grantless CONNECT-IP (open-relay risk)"
            );
        }
        if cfg.grant_verifier.is_none() {
            anyhow::bail!(
                "hw-attest (production) build refuses to start without NW_GRANT_VERIFY_KEYS_FILE — otherwise every CONNECT-IP request would fail authorization"
            );
        }
        if cfg.grant_realm.is_none() || cfg.node_id.is_none() {
            anyhow::bail!(
                "hw-attest (production) build requires NW_GRANT_REALM and NW_NODE_ID for audience-bound grants"
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
        tracing::info!("hw-attest production posture: attestation evidence path verified + audience-bound Coordinator grant required + measurement pinned");
    }

    // `bind`/`egress` are the node operator's own infra addresses (operational, not
    // user-linkable); the tunnel-internal addressing (node/client IPs) is deliberately
    // NOT logged — it reads as user data and the datapath must stay logless (SOUL §3 / PD-3).
    tracing::info!(
        bind = %cfg.bind, egress = %cfg.egress, tun = %cfg.tun_name, role = ?cfg.role,
        "nil-node starting (MASQUE/CONNECT-IP; no disk logs)"
    );

    let exit = exit::Exit::setup(&cfg)?;

    // Alternate responders are an explicit development capability until they enforce the same
    // per-connection grant and hardware-attestation contract as MASQUE.
    #[cfg(feature = "dev-fallbacks")]
    {
        if nil_core::net::dev_env_flag("NW_NODE_AMNEZIA") {
            tracing::info!("node mode: development AmneziaWG fallback responder");
            amneziawg::run(&cfg, exit.tun()).await?;
            return Ok(());
        }
        if nil_core::net::dev_env_flag("NW_NODE_WSTUNNEL") {
            tracing::info!("node mode: development wstunnel fallback responder");
            wstunnel::run(&cfg, exit.tun()).await?;
            return Ok(());
        }
        if nil_core::net::dev_env_flag("NW_NODE_REALITY") {
            tracing::info!("node mode: development REALITY fallback responder");
            reality::run(&cfg, exit.tun()).await?;
            return Ok(());
        }
    }

    let subject_alt_names = vec!["nil-node".to_string(), "localhost".to_string()];
    let cert = match cfg.tls_key_file.as_deref() {
        Some(path) => cert::NodeCert::from_key_file(path, subject_alt_names)?,
        None => {
            #[cfg(debug_assertions)]
            {
                tracing::warn!(
                    "generating an ephemeral TLS identity for debug; registry-pinned grants require NW_NODE_TLS_KEY_FILE"
                );
                cert::NodeCert::generate(subject_alt_names)?
            }
            #[cfg(not(debug_assertions))]
            {
                let _ = subject_alt_names;
                anyhow::bail!("release node requires NW_NODE_TLS_KEY_FILE")
            }
        }
    };
    server::run(&cfg, &cert, exit.tun()).await?;
    Ok(())
}
