#![cfg(feature = "fast-path")]
//! Fast-path perf gate (Epic 7): a dependency-free throughput micro-bench of the data-plane
//! per-packet hotpath — the AmneziaWG obfuscation transform, which the recon flagged as the
//! dominant per-packet cost on the obfuscated rungs. It:
//!   1. prints throughput for CI trend-tracking,
//!   2. asserts the `obfuscate` → `deobfuscate` round-trip stays CORRECT for every packet (the real,
//!      deterministic, never-flaky regression guard),
//!   3. asserts a COARSE throughput floor — far below any real machine — so a catastrophic (≥100x)
//!      regression trips it without flaking on a noisy shared CI runner,
//!   4. asserts NO PII in any bench output (PD-3).
//!
//! ## Not yet (the Linux-runtime follow-up this gate will measure)
//! UDP **GSO/GRO** kernel batching (`sendmmsg`/`UDP_SEGMENT`) is the actual fast-path optimisation.
//! It is deferred here because it is Linux-only and unsafe-syscall-heavy — it cannot be compiled or
//! exercised on a non-Linux dev host, so shipping it blind would violate PD-5 ("prove, don't
//! promise"). This harness establishes the baseline + the no-regression/no-PII contract the GSO work
//! will be held to when it lands on a Linux node/CI.

use std::time::Instant;

use nil_transport::ObfsParams;

/// A typical inner WireGuard transport-data datagram under the QUIC payload ceiling.
const PKT_LEN: usize = 1392;
const ITERS: usize = 100_000;

#[test]
fn obfuscation_hotpath_throughput_and_correctness() {
    let obfs = ObfsParams::derive(&[0x42u8; 32]);

    // A deterministic synthetic packet — no real addresses/tokens (PD-3). Byte 0 = 4 marks a
    // WireGuard *transport-data* message (variable length ⇒ no junk tail ⇒ exact round-trip); the
    // remaining 3 type-word bytes are zero, which `deobfuscate` restores verbatim.
    let mut pkt = vec![0xABu8; PKT_LEN];
    pkt[0] = 4;
    pkt[1] = 0;
    pkt[2] = 0;
    pkt[3] = 0;

    let start = Instant::now();
    let mut ok = 0usize;
    for _ in 0..ITERS {
        let wire = obfs.obfuscate(&pkt);
        match obfs.deobfuscate(&wire) {
            // Correctness IS the regression guard: a broken transform fails here, deterministically.
            Some(round) if round == pkt => ok += 1,
            _ => panic!("obfuscate -> deobfuscate did not round-trip"),
        }
    }
    let elapsed = start.elapsed();
    assert_eq!(ok, ITERS, "every packet must round-trip");

    let mb = (ITERS * PKT_LEN) as f64 / (1024.0 * 1024.0);
    let secs = elapsed.as_secs_f64().max(1e-9);
    let mbps = mb / secs;
    let report = format!(
        "fast-path obfuscation hotpath: {ITERS} pkts x {PKT_LEN}B round-trip = {mbps:.1} MB/s"
    );
    println!("{report}");

    // Coarse no-regression floor: any real machine does FAR more than 1 MB/s here; tripping this
    // means a catastrophic regression, not runner noise. A precise baseline-relative gate is the
    // Linux-runtime follow-up alongside real GSO.
    assert!(
        mbps > 1.0,
        "obfuscation throughput collapsed ({mbps:.3} MB/s) — catastrophic regression"
    );

    // PD-3: the bench output must carry no user-linkable address tokens.
    let lower = report.to_lowercase();
    for tok in [
        "addr",
        "peer",
        "socketaddr",
        "client_ip",
        ".host",
        ".port",
        "%addr",
    ] {
        assert!(
            !lower.contains(tok),
            "bench output leaked a forbidden token: {tok}"
        );
    }
}
