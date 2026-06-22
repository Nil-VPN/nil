//! Appraisal policy + verdict. The policy is what the Coordinator pins and the client
//! enforces; the verdict is the positive result the transport gates the tunnel on.

pub use nil_core::{Measurement, Tee};

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
    /// If false (the default), an out-of-date TCB is rejected even when the report verifies.
    pub allow_tcb_out_of_date: bool,
}

impl AppraisalPolicy {
    pub fn new(tee: Tee, expected_measurement: Measurement) -> Self {
        Self { tee, expected_measurement, allow_tcb_out_of_date: false }
    }
}

/// A successful appraisal. The transport only signals "tunnel ready" when it holds one.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub tee: Tee,
    pub measurement: Measurement,
    pub tcb_status: TcbStatus,
}
