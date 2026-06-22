//! The account domain model — and the proof that we store no identity.

use nil_proto::account::EntitlementDto;

/// Subscription/entitlement state. Carries no identity — only what the account may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entitlement {
    None,
    Active,
    Expired,
}

impl From<Entitlement> for EntitlementDto {
    fn from(e: Entitlement) -> Self {
        match e {
            Entitlement::None => EntitlementDto::None,
            Entitlement::Active => EntitlementDto::Active,
            Entitlement::Expired => EntitlementDto::Expired,
        }
    }
}

/// The ONLY data persisted for an anonymous account.
///
/// There is deliberately no email, no name, no signup IP, and no timestamp field — the
/// absence *is* the privacy guarantee (a hard privacy invariant; architecture spec §7.5).
/// Even a full Portal compromise yields no personal identity for an anonymous account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    /// `= H(secret)`; doubles as the store's lookup key.
    pub account_number: [u8; 32],
    /// `SHA-256(domain || recovery_code)` — never the code itself.
    pub recovery_code_hash: [u8; 32],
    pub entitlement: Entitlement,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tripwire on the "store only H(secret) + entitlement" invariant. This exhaustive
    /// destructuring (no `..`) fails to COMPILE the moment anyone adds a field such as
    /// an email or signup IP, forcing a conscious review before any PII can be stored.
    #[test]
    fn account_record_has_exactly_three_non_identifying_fields() {
        let AccountRecord {
            account_number: _,
            recovery_code_hash: _,
            entitlement: _,
        } = AccountRecord {
            account_number: [0u8; 32],
            recovery_code_hash: [0u8; 32],
            entitlement: Entitlement::None,
        };
    }
}
