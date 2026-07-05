//! RA-TLS attestation probe — connect to a live MASQUE node and report whether the
//! attestation gate ACCEPTS (correct pinned measurement) or REJECTS (wrong pin / no report).
//!
//! Connect-only: it performs the QUIC + CONNECT-IP handshake and the single attestation gate,
//! then drops the session. It NEVER brings up a TUN or routes a packet, so it is safe to run
//! from any machine. This is the focused proof for Pillar 2 against real hardware.
//!
//! Run (accept):
//!   NODE_HOST=203.0.113.10 NODE_PORT=443 \
//!   NODE_MEASUREMENT=<48-byte-hex> \
//!   cargo run -p nil-transport --features masque --example attest_probe
//!
//! Run (reject): add PROBE_TWEAK=1 to corrupt the pinned measurement — the gate MUST refuse.
//!
//! Requires the `masque` feature (it drives the real MASQUE transport); without it `main` is an
//! inert stub so a masque-off feature build still compiles this example.

#[cfg(not(feature = "masque"))]
fn main() {
    eprintln!("attest_probe requires --features masque");
}

#[cfg(feature = "masque")]
use std::env;

#[cfg(feature = "masque")]
use nil_core::{AttestExpectation, Grant, Measurement, NodeEndpoint, Tee, TransportKind};
#[cfg(feature = "masque")]
use nil_transport::{MasqueConfig, MasqueTransport, Transport};

#[cfg(feature = "masque")]
fn from_hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[cfg(feature = "masque")]
fn main() {
    let host = env::var("NODE_HOST").expect("set NODE_HOST");
    let port: u16 = env::var("NODE_PORT")
        .unwrap_or_else(|_| "443".into())
        .parse()
        .expect("port");
    let meas_hex = env::var("NODE_MEASUREMENT").expect("set NODE_MEASUREMENT (48-byte hex)");
    let mut measurement = from_hex(&meas_hex);
    assert_eq!(
        measurement.len(),
        48,
        "SEV-SNP measurement must be 48 bytes"
    );

    let tweak = env::var("PROBE_TWEAK").is_ok();
    if tweak {
        measurement[0] ^= 0xff;
        eprintln!("[probe] PROBE_TWEAK set — corrupted measurement byte 0; expecting REJECT");
    }

    // Fresh per-connection nonce (the node must bind it into report_data).
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).expect("nonce");

    let endpoint = NodeEndpoint {
        host: host.clone(),
        port,
        kind: TransportKind::Masque,
        wg_pub: None,
        expected: Some(AttestExpectation {
            tee: Tee::SevSnp,
            measurement: Measurement(measurement),
            min_tcb_sevsnp: None,
            transparency_log_key: None,
        }),
        grant: None,
    };
    let grant = Grant {
        token: Vec::new(),
        nonce,
    };

    // Fail-closed config (the production default): no measurement pinned would refuse, and a
    // mismatch refuses. We DO pin one, so a genuine matching report is required to pass.
    let transport = MasqueTransport::with_config(MasqueConfig {
        allow_unattested: false,
        ..Default::default()
    });

    eprintln!(
        "[probe] connecting to {host}:{port} (pin {}…, tweak={tweak})",
        &meas_hex[..16]
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let res = rt.block_on(async move { transport.connect(endpoint, grant).await });

    match res {
        Ok(s) => println!(
            "RESULT=ATTESTED-OK (session={s:?}) — node's real report verified against the pin"
        ),
        Err(e) => println!("RESULT=REFUSED — {e}"),
    }
}
