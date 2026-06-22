//! Per-TEE report verification. Each backend takes raw evidence (the report/quote plus the
//! collateral needed to verify it offline) and, on success, returns normalized [`Evidence`]:
//! the code measurement, the 64-byte `report_data` binding slot, and the TCB status. The
//! upper layer ([`crate::appraise`]) compares the measurement to policy and checks the
//! `report_data` binding — that logic is TEE-agnostic and lives there, not here.

use nil_core::Tee;

use crate::policy::TcbStatus;

pub mod sevsnp;
pub mod tdx;

/// Normalized, cryptographically-verified attestation evidence.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub tee: Tee,
    /// The code measurement: SEV-SNP launch `MEASUREMENT` (48 B) or TDX `MRTD` (48 B).
    pub measurement: Vec<u8>,
    /// The 64-byte field the TEE binds to attester-supplied data — here, the TLS key + nonce.
    pub report_data: [u8; 64],
    pub tcb_status: TcbStatus,
}
