//! Android datapath: bring the tunnel up over a TUN fd handed in by the `VpnService`
//! (`Builder.establish().detachFd()`), instead of opening our own device.
//!
//! Routing, DNS, MTU, and the kill-switch are configured by the `VpnService` at `establish()`
//! time (and "Always-on VPN / Block connections without VPN" enforces fail-closed at the OS
//! level), so there is no in-process [`NetControl`] to arm — hence [`NoopNet`]. The MASQUE
//! transport's own QUIC to the node bypasses the TUN via the `socket_hook` (the app's
//! `VpnService.protect(fd)`), which `nil-android` sets when it builds the transport.

use std::os::fd::RawFd;
use std::sync::Arc;

use nil_core::Grant;
use nil_transport::Transport;
use tokio_util::sync::CancellationToken;

use crate::{spawn_pumps, ArmParams, NetControl, Tunnel, TunnelConfig};

/// No-op networking: the `VpnService.Builder` already configured routes/DNS/MTU at `establish()`.
struct NoopNet;

impl NetControl for NoopNet {
    fn arm(&mut self, _params: &ArmParams) -> anyhow::Result<()> {
        Ok(())
    }
    fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

impl Tunnel {
    /// Bring the tunnel up over a `VpnService`-provided TUN fd (Android). `tun_fd` is owned (from
    /// `ParcelFileDescriptor.detachFd()`); we adopt it and the device closes it on drop. The
    /// `transport` must already be built with a `socket_hook` that `protect()`s its UDP socket so
    /// the tunnel's own QUIC to the node bypasses the TUN (no loop). The VpnService set the TUN MTU
    /// at `establish()`, so we don't resize it here — just pump.
    pub async fn up_with_fd(
        transport: Arc<dyn Transport>,
        cfg: TunnelConfig,
        tun_fd: RawFd,
    ) -> anyhow::Result<Tunnel> {
        tracing::info!("connecting MASQUE tunnel (android, VpnService-provided TUN)");

        // Adopt the detached fd immediately. Rust owns it on every return path, including a
        // connection/attestation failure; delaying adoption would leak the OS VPN interface when
        // `transport.connect` failed.
        // SAFETY: `tun_fd` is an owned fd handed over by the VpnService via `detachFd()`.
        let tun = Arc::new(
            unsafe { tun_rs::AsyncDevice::from_fd(tun_fd) }
                .map_err(|e| anyhow::anyhow!("adopt tun fd: {e}"))?,
        );

        // Fresh per-connection nonce, bound into the node's attestation report (same as `up`).
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("nonce entropy: {e}"))?;
        let grant = cfg.node.grant.clone().unwrap_or(Grant {
            token: Vec::new(),
            nonce,
        });

        let session = transport
            .connect(cfg.node.clone(), grant)
            .await
            .map_err(|e| anyhow::anyhow!("transport connect: {e}"))?;
        tracing::info!("tunnel session established (android)");

        // Android's VpnService must choose its address before handing us the fd. Until the JNI
        // contract becomes two-phase, only the pool's configured fallback address is usable.
        // Refuse a different ADDRESS_ASSIGN rather than reporting a tunnel whose packets the node
        // will drop (the Apple provider can apply its assignment after connect).
        if transport.assigned_ip(&session) != Some(cfg.client_ip) {
            let _ = transport.close(session).await;
            anyhow::bail!(
                "node did not assign the exact inner address required by the current Android VpnService ABI"
            );
        }

        let net: Box<dyn NetControl> = Box::new(NoopNet);
        let cancel = CancellationToken::new();
        // Tripped by whichever pump exits first (hang/dead-tunnel/TUN error). Distinct from
        // `cancel` (which we trip on a clean `down`), so the engine can tell "the tunnel died
        // under us" from "we tore it down". Mirrors the desktop `up()` path.
        let pump_dead = CancellationToken::new();
        let pumps = spawn_pumps(transport.clone(), session, tun.clone(), &cancel, &pump_dead);
        tracing::info!("tunnel up (android)");

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
}
