//! Node-side attestation: build the report the client appraises, bound to this node's TLS key
//! and the client's freshness nonce. Uses the SAME `nil-attest` codec/binding the client
//! verifies with, so the two can't drift.
//!
//! A production node fetches a hardware SEV-SNP/TDX report (needs a TEE). For CI / a laptop,
//! the `synthetic-attest` feature mints a report signed by `nil-attest`'s test CA so the
//! Docker accept/reject harness works without hardware — never enabled in a shipped node.

use nil_core::Tee;

/// What this node attests to. Populated from the environment (the operator sets it from the
/// reproducible build's published measurement). The fields are only consumed when a report
/// provider is built in (e.g. `synthetic-attest`), so a bare node build doesn't read them.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "synthetic-attest"), allow(dead_code))]
pub struct NodeAttest {
    pub tee: Tee,
    pub measurement: [u8; 48],
}

impl NodeAttest {
    /// Read `NW_NODE_MEASUREMENT` (48-byte hex) + `NW_NODE_TEE` (`sev-snp`|`tdx`). `None` when
    /// unset → the node serves unattested (dev), and a pinning client will refuse it.
    pub fn from_env() -> Option<Self> {
        let raw = std::env::var("NW_NODE_MEASUREMENT").ok()?;
        let bytes = nil_transport::connectip::from_hex(raw.trim().as_bytes())?;
        if bytes.len() != 48 {
            tracing::warn!("NW_NODE_MEASUREMENT must be 48 bytes of hex; ignoring");
            return None;
        }
        let mut measurement = [0u8; 48];
        measurement.copy_from_slice(&bytes);
        let tee = match std::env::var("NW_NODE_TEE").unwrap_or_else(|_| "sev-snp".into()).as_str() {
            "tdx" => Tee::Tdx,
            _ => Tee::SevSnp,
        };
        Some(Self { tee, measurement })
    }
}

/// The hex `nil-attest-report` header value for this connection's `nonce`, or `None` if no
/// report can be produced (not configured, or no report provider built in).
pub fn report_hex(spki: &[u8], attest: Option<&NodeAttest>, nonce: &[u8; 32]) -> Option<String> {
    let attest = attest?;
    #[cfg(feature = "synthetic-attest")]
    {
        let evidence =
            nil_attest::testkit::synthetic_evidence(attest.tee, &attest.measurement, spki, nonce);
        Some(nil_transport::connectip::to_hex(&evidence))
    }
    #[cfg(not(feature = "synthetic-attest"))]
    {
        // Production: fetch a real hardware SEV-SNP/TDX report (configfs-TSM). Compile-checked
        // everywhere; only succeeds on a TEE guest, else returns None and the client fails closed.
        #[cfg(feature = "hw-attest")]
        {
            match crate::hw::report_evidence(attest.tee, spki, nonce) {
                Ok(evidence) => Some(nil_transport::connectip::to_hex(&evidence)),
                Err(e) => {
                    tracing::error!("hardware attestation report failed: {e}");
                    None
                }
            }
        }
        #[cfg(not(feature = "hw-attest"))]
        {
            let _ = (spki, attest, nonce);
            tracing::warn!(
                "attestation configured but no report provider built in (need a TEE + `hw-attest`, or `synthetic-attest`)"
            );
            None
        }
    }
}
