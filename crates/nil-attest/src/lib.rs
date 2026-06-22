//! Attestation for NIL VPN's verifiable-trust pillar (architecture spec §5).
//!
//! Parses and appraises AMD SEV-SNP and Intel TDX attestation reports and verifies a node's
//! RA-TLS certificate (the report embedded in an X.509 extension) against a measurement the
//! Coordinator publishes. The client refuses to tunnel unless the report's signature chain
//! verifies to the hardware vendor root, the measurement matches the pinned policy, and a
//! client nonce is bound into `report_data` to prove freshness — "prove it, don't promise it".
//!
//! Layout:
//! - [`report::sevsnp`] / [`report::tdx`] — per-TEE cryptographic verification (pure-Rust,
//!   offline) producing normalized [`report::Evidence`].
//! - [`policy`] — what the Coordinator pins ([`AppraisalPolicy`]) and the positive [`Verdict`].
//! - [`error`] — typed [`AttestError`] failures.
//! - `ratls` + `appraise` (next increment) — parse the leaf cert, dispatch to a backend, and
//!   enforce the measurement + `report_data` binding TEE-agnostically.

pub mod error;
pub mod policy;
pub mod report;

pub use error::AttestError;
pub use policy::{AppraisalPolicy, Measurement, Tee, TcbStatus, Verdict};
pub use report::Evidence;
