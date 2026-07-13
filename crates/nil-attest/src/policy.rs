//! Appraisal policy + verdict. The policy is what the Coordinator pins and the client
//! enforces; the verdict is the positive result the transport gates the tunnel on.

pub use nil_core::{Measurement, SevSnpTcbFloor, TdxPolicy, Tee};

/// Platform Trusted Computing Base status distilled from a report/quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcbStatus {
    /// Patch level is current.
    UpToDate,
    /// Out of date or needs hardening (the report still verified cryptographically).
    OutOfDate(String),
}

/// What the client requires of a node before any packet flows. Sourced from the
/// Coordinator-published, transparency-logged measurement (architecture spec §5).
#[derive(Debug, Clone)]
pub struct AppraisalPolicy {
    pub tee: Tee,
    pub expected_measurement: Measurement,
    /// SHA-256 of the exact TLS certificate SubjectPublicKeyInfo published for this registry
    /// node. Production Coordinator paths always pin it; `None` is retained only for explicit
    /// direct-node/debug fixtures.
    pub tls_spki_sha256: Option<[u8; 32]>,
    /// If false (the default), an out-of-date TCB is rejected even when the report verifies.
    pub allow_tcb_out_of_date: bool,
    /// Pinned minimum SEV-SNP platform TCB, enforced offline during appraisal. `None` = no floor.
    /// Ignored for TDX (its patch level comes from the signed DCAP verdict, not a pinned floor).
    pub min_tcb_sevsnp: Option<SevSnpTcbFloor>,
    /// Exact TDX workload policy.  It is mandatory for TDX appraisal and invalid for SEV-SNP;
    /// accepting a quote with only an MRTD pin would leave its runtime/configuration identity
    /// unconstrained.
    pub tdx_policy: Option<TdxPolicy>,
    /// Pinned transparency-log Ed25519 public key (32 bytes). When set, the node's measurement must
    /// be proven present in that log via a stapled RFC 6962 inclusion proof, or the tunnel is
    /// refused — turning a Coordinator-*asserted* measurement into a client-*verified*, publicly
    /// logged one. `None` disables the check (the measurement pin alone gates the tunnel).
    pub transparency_log_key: Option<[u8; 32]>,
}

impl AppraisalPolicy {
    pub fn new(tee: Tee, expected_measurement: Measurement) -> Self {
        Self {
            tee,
            expected_measurement,
            tls_spki_sha256: None,
            allow_tcb_out_of_date: false,
            min_tcb_sevsnp: None,
            tdx_policy: None,
            transparency_log_key: None,
        }
    }

    /// Pin the stable node TLS SubjectPublicKeyInfo digest (builder).
    pub fn with_tls_spki_sha256(mut self, digest: Option<[u8; 32]>) -> Self {
        self.tls_spki_sha256 = digest;
        self
    }

    /// Pin a minimum SEV-SNP TCB floor (builder). No-op semantics for TDX policies.
    pub fn with_min_tcb_sevsnp(mut self, floor: Option<SevSnpTcbFloor>) -> Self {
        self.min_tcb_sevsnp = floor;
        self
    }

    /// Pin the exact Intel TDX workload policy (builder).
    pub fn with_tdx_policy(mut self, policy: Option<TdxPolicy>) -> Self {
        self.tdx_policy = policy;
        self
    }

    /// Pin the transparency-log key the node's measurement must be proven logged under (builder).
    pub fn with_transparency_log_key(mut self, key: Option<[u8; 32]>) -> Self {
        self.transparency_log_key = key;
        self
    }
}

/// A successful appraisal. The transport only signals "tunnel ready" when it holds one.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub tee: Tee,
    pub measurement: Measurement,
    pub tcb_status: TcbStatus,
}
