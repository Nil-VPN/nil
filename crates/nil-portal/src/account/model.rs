//! The account domain model — and the proof that we store no identity.

use nil_proto::account::EntitlementDto;

/// Subscription/entitlement state. Carries no identity — only what the account may do, and (for an
/// active subscription) when it lapses. `until` is a unix-secs expiry tied to an ANONYMOUS account
/// (H(secret)), not to any person — a coarse billing fact, not identity-linked, so it stays within
/// PD-2's "no timestamps *tied to identity*" rule (the one timestamp we keep; ADR-0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entitlement {
    None,
    Active { until: u64 },
    Expired,
}

impl Entitlement {
    /// Collapse a lapsed subscription to `Expired` for the given clock: an `Active { until }` whose
    /// expiry has passed reads as `Expired`. Pure derivation, not a stored mutation — so no background
    /// sweeper is needed and the store lazily reflects lapses on read.
    pub fn resolved(self, now_secs: u64) -> Entitlement {
        match self {
            Entitlement::Active { until } if until <= now_secs => Entitlement::Expired,
            other => other,
        }
    }

    /// The active-until expiry iff currently active (for surfacing "Active until …" to the client).
    pub fn active_until(self, now_secs: u64) -> Option<u64> {
        match self.resolved(now_secs) {
            Entitlement::Active { until } => Some(until),
            _ => None,
        }
    }
}

impl From<Entitlement> for EntitlementDto {
    fn from(e: Entitlement) -> Self {
        match e {
            Entitlement::None => EntitlementDto::None,
            Entitlement::Active { .. } => EntitlementDto::Active,
            Entitlement::Expired => EntitlementDto::Expired,
        }
    }
}

/// The ONLY data persisted for an anonymous account.
///
/// There is deliberately no email, no name, and no signup IP — the absence *is* the privacy
/// guarantee (a hard privacy invariant; architecture spec §7.5). The single timestamp that may be
/// present is the subscription expiry *inside* `entitlement` — tied to the anonymous account, never
/// to a person (ADR-0007). `auth_pubkey` is the **public** half of a per-account Ed25519 key derived
/// and retained by the client — an anonymous key (no identity), used to verify signed challenges.
/// Recovery material is deliberately absent. Even a full Portal compromise yields no account
/// secret or personal identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    /// `= H(secret)`; doubles as the store's lookup key.
    pub account_number: [u8; 32],
    pub entitlement: Entitlement,
    /// Public half of the account's auth key (ADR-0007). All-zero may remain on a legacy account
    /// that predates client-side registration; it can never pass authentication.
    pub auth_pubkey: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_resolves_to_expired_once_the_clock_passes_until() {
        let e = Entitlement::Active { until: 1_000 };
        // Before expiry: still active, and surfaces its until.
        assert_eq!(e.resolved(999), Entitlement::Active { until: 1_000 });
        assert_eq!(e.active_until(999), Some(1_000));
        // At/after expiry: collapses to Expired and surfaces no until (`until <= now`).
        assert_eq!(e.resolved(1_000), Entitlement::Expired);
        assert_eq!(e.resolved(1_001), Entitlement::Expired);
        assert_eq!(e.active_until(1_000), None);
    }

    #[test]
    fn none_and_expired_never_become_active() {
        assert_eq!(Entitlement::None.resolved(0), Entitlement::None);
        assert_eq!(Entitlement::None.active_until(0), None);
        assert_eq!(Entitlement::Expired.resolved(0), Entitlement::Expired);
        assert_eq!(Entitlement::Expired.active_until(0), None);
    }

    #[test]
    fn dto_mapping_drops_the_until_but_keeps_the_state() {
        assert_eq!(
            EntitlementDto::from(Entitlement::None),
            EntitlementDto::None
        );
        assert_eq!(
            EntitlementDto::from(Entitlement::Active { until: 42 }),
            EntitlementDto::Active
        );
        assert_eq!(
            EntitlementDto::from(Entitlement::Expired),
            EntitlementDto::Expired
        );
    }

    /// Tripwire on the "store only non-identifying account fields" invariant. This exhaustive
    /// destructuring (no `..`) fails to COMPILE the moment anyone adds a field such as an email or
    /// signup IP, forcing a conscious review before any PII can be stored. The set was widened from
    /// three fields: `account_number`, subscription `entitlement`, and the per-account anonymous
    /// `auth_pubkey`. Adding anything identity-bearing must stop here and be justified against a
    /// Prime Directive.
    #[test]
    fn account_record_has_exactly_three_non_identifying_fields() {
        let AccountRecord {
            account_number: _,
            entitlement: _,
            auth_pubkey: _,
        } = AccountRecord {
            account_number: [0u8; 32],
            entitlement: Entitlement::None,
            auth_pubkey: [0u8; 32],
        };
    }
}
