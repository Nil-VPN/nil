//! Appraisal errors. Each maps a specific failure in the RA-TLS / report-verification
//! pipeline so the client (and tests) can distinguish "wrong code" from "broken evidence".

use nil_core::Tee;

#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    /// The RA-TLS leaf certificate carried no NIL attestation extension.
    #[error("RA-TLS certificate has no attestation extension")]
    MissingExtension,
    /// The certificate could not be parsed, or its SPKI didn't match the TLS key in use.
    #[error("certificate parse/binding error: {0}")]
    Cert(String),
    /// The embedded evidence (report/quote/collateral) was malformed.
    #[error("malformed attestation evidence: {0}")]
    Malformed(String),
    /// The extension named a TEE we don't support (or a synthetic tag in a release build).
    #[error("unsupported TEE tag: {0:#x}")]
    UnsupportedTee(u8),
    /// The report didn't come from the TEE family the policy expected.
    #[error("TEE mismatch: policy expects {expected:?}, evidence is {found:?}")]
    TeeMismatch { expected: Tee, found: Tee },
    /// The report signature or the vendor cert chain failed verification.
    #[error("report signature / cert-chain verification failed: {0}")]
    ChainVerification(String),
    /// The node's measurement did not match the Coordinator's pinned policy. The Display
    /// string "measurement mismatch" is asserted by the Docker accept/reject harness.
    #[error("measurement mismatch")]
    MeasurementMismatch,
    /// `report_data` did not bind the node's TLS key and the client nonce — the report was
    /// not minted for this connection (relay/stale).
    #[error("report_data binding mismatch (wrong TLS key or stale nonce)")]
    ReportDataMismatch,
    /// The platform TCB is out of date / revoked and the policy does not allow it.
    #[error("TCB not up to date: {0}")]
    TcbNotUpToDate(String),
}
