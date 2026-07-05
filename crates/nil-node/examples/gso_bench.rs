//! GSO vs per-packet egress micro-benchmark (Linux only).
//!
//! Measures the send-side syscall cost that UDP GSO removes: pushing the same total number of
//! equal-size UDP packets to a draining loopback receiver, once as one `send_to` per packet and
//! once as GSO batches (one `sendmsg` with UDP_SEGMENT per 64 segments). Prints packets/sec for each
//! and the speedup ratio. Runs for free on a GitHub Actions Linux runner (see the `gso-bench`
//! workflow) — no VPS needed. The absolute pps is runner-dependent; the RATIO is the meaningful
//! result (it isolates the syscall reduction, which is GSO's win).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("gso_bench: Linux only (UDP GSO is a Linux kernel feature)");
}

#[cfg(target_os = "linux")]
fn main() {
    use std::io::IoSlice;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, SockaddrStorage};

    const SEG: usize = 1400; // one MSS-ish segment
    const BATCH: usize = 64; // segments per GSO sendmsg (kernel max)
    const TOTAL: usize = 2_000_000; // total packets per mode

    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_read_timeout(Some(std::time::Duration::from_millis(200))).unwrap();
    // Big receive buffer so the receiver rarely drops; we want to measure the SENDER.
    let dest = rx.local_addr().unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();

    // Drain the receiver in a background thread until told to stop.
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let drain = std::thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        let mut n: u64 = 0;
        while !stop2.load(Ordering::Relaxed) {
            if rx.recv(&mut buf).is_ok() {
                n += 1; // else: a 200ms timeout tick, re-check the stop flag
            }
        }
        n
    });

    // --- Mode A: one send_to per packet ---
    let pkt = vec![0xABu8; SEG];
    let t0 = Instant::now();
    for _ in 0..TOTAL {
        let _ = tx.send_to(&pkt, dest);
    }
    let per_packet = t0.elapsed();

    // --- Mode B: GSO — one sendmsg per BATCH segments ---
    let addr: SockaddrStorage = match dest {
        std::net::SocketAddr::V4(a) => a.into(),
        std::net::SocketAddr::V6(a) => a.into(),
    };
    let seg16 = SEG as u16;
    let batch = vec![0xCDu8; SEG * BATCH];
    let t1 = Instant::now();
    let mut sent = 0;
    while sent < TOTAL {
        let iov = [IoSlice::new(&batch)];
        let cmsg = [ControlMessage::UdpGsoSegments(&seg16)];
        // Blocking socket: retry on EAGAIN/EINTR.
        loop {
            match sendmsg(tx.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), Some(&addr)) {
                Ok(_) => break,
                Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    eprintln!("gso_bench: sendmsg failed ({e}); kernel may lack UDP_SEGMENT");
                    stop.store(true, Ordering::Relaxed);
                    let _ = drain.join();
                    return;
                }
            }
        }
        sent += BATCH;
    }
    let gso = t1.elapsed();

    stop.store(true, Ordering::Relaxed);
    let _ = drain.join();

    let pps = |d: std::time::Duration| TOTAL as f64 / d.as_secs_f64();
    let a = pps(per_packet);
    let b = pps(gso);
    println!("=== NIL UDP GSO egress micro-benchmark (Linux) ===");
    println!("packets per mode: {TOTAL}, segment size: {SEG} B, GSO batch: {BATCH} segments");
    println!("per-packet send_to : {a:>12.0} pkt/s  ({:.2?})", per_packet);
    println!("GSO sendmsg batches: {b:>12.0} pkt/s  ({:.2?})", gso);
    println!("SPEEDUP (GSO / per-packet): {:.2}x", b / a);
    println!("(absolute pps is runner-dependent; the ratio isolates the syscall reduction GSO buys.)");
}
