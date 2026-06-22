//! Attestation for NIL VPN's verifiable-trust pillar (architecture spec §5).
//!
//! Phase 2 home for parsing and appraising AMD SEV-SNP / Intel TDX attestation reports
//! and verifying a node's RA-TLS certificate (report embedded in an X.509 extension)
//! against a measurement the Coordinator publishes. The client refuses to tunnel
//! unless the report matches the pinned measurement and a client nonce proves
//! freshness — "prove it, don't promise it."
//!
//! Phase 0 is a placeholder so the crate compiles and the workspace map matches §3.

/// Attestation appraisal errors (placeholder until Phase 2).
#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    /// The node's measurement did not match the Coordinator's pinned policy.
    #[error("measurement mismatch")]
    MeasurementMismatch,
    /// Not yet implemented in this phase.
    #[error("attestation not implemented before Phase 2")]
    NotImplemented,
}
