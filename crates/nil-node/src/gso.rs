//! UDP GSO (generic segmentation offload) for the egress hot path.
//!
//! `quiche` produces many equal-size QUIC packets to the same peer per flush; on Linux we hand a
//! whole run to the kernel in ONE `sendmsg` carrying a `UDP_SEGMENT` control message, and the
//! kernel/NIC segments it — far fewer syscalls than one `send_to` per packet, which is the bulk of
//! a userspace-QUIC VPN's egress cost (Tailscale measured ~4x from GSO+GRO). UDP GSO requires every
//! segment to be the SAME size except the last, which may be shorter.
//!
//! Fail-safe by construction: on any error (a kernel without GSO, `EIO`, a bad address family) or on
//! a non-Linux target, [`send_segmented`] returns `Err` and the caller falls back to per-packet
//! sends — so behavior is never worse than today. PD-3: nothing here logs an address or payload.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

/// Send `batch` — a concatenation of equal-`segment_size` packets (the final one may be shorter) —
/// to `dest` as a single UDP GSO datagram. `Err` means the caller should fall back to per-packet.
#[cfg(target_os = "linux")]
pub async fn send_segmented(
    socket: &UdpSocket,
    batch: &[u8],
    segment_size: usize,
    dest: SocketAddr,
) -> std::io::Result<()> {
    use std::io::IoSlice;
    use std::os::fd::AsRawFd;

    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, SockaddrStorage};

    let seg = u16::try_from(segment_size)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let addr: SockaddrStorage = match dest {
        SocketAddr::V4(a) => a.into(),
        SocketAddr::V6(a) => a.into(),
    };
    loop {
        socket.writable().await?;
        let res = socket.try_io(tokio::io::Interest::WRITABLE, || {
            let iov = [IoSlice::new(batch)];
            let cmsg = [ControlMessage::UdpGsoSegments(&seg)];
            sendmsg(socket.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), Some(&addr))
                .map(|_| ())
                .map_err(std::io::Error::from)
        });
        match res {
            Ok(()) => return Ok(()),
            // try_io surfaces a would-block as WouldBlock; re-arm readiness and retry.
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn send_segmented(
    _socket: &UdpSocket,
    _batch: &[u8],
    _segment_size: usize,
    _dest: SocketAddr,
) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// On Linux, a GSO batch of N equal segments + a short tail must arrive at a peer as N+1
    /// intact, correctly-bounded datagrams. Runs only on Linux (the Docker CI/e2e host); validates
    /// the segmentation end to end over loopback.
    #[tokio::test]
    async fn gso_batch_arrives_as_individual_datagrams() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = rx.local_addr().unwrap();

        let seg = 1200usize;
        let full = 4; // four full segments...
        let tail = 300usize; // ...plus a shorter final one
        let mut batch = Vec::new();
        for i in 0..full {
            batch.resize(batch.len() + seg, i as u8 + 1);
        }
        batch.resize(batch.len() + tail, 0xEEu8);

        // If the kernel lacks GSO, skip rather than fail (older CI kernels).
        if send_segmented(&tx, &batch, seg, dest).await.is_err() {
            eprintln!("kernel lacks UDP_SEGMENT; skipping GSO round-trip");
            return;
        }

        let mut got = Vec::new();
        let mut buf = vec![0u8; 65535];
        for _ in 0..(full + 1) {
            let n = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv(&mut buf))
                .await
                .expect("a segment should arrive")
                .unwrap();
            got.push(buf[..n].to_vec());
        }
        assert_eq!(got.len(), full + 1, "N full + 1 tail segment");
        for (i, d) in got.iter().take(full).enumerate() {
            assert_eq!(d.len(), seg, "full segment {i} is one MSS");
            assert!(d.iter().all(|&b| b == i as u8 + 1), "segment {i} bytes intact");
        }
        assert_eq!(got[full].len(), tail, "final short segment");
        assert!(got[full].iter().all(|&b| b == 0xEE), "tail bytes intact");
    }
}
