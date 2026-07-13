//! Encrypted on-device store of unblinded Privacy Pass tokens.
//!
//! Tokens contain no account/payment identifier, and the shared vault schema stores only each
//! `{msg, token}` pair beside the separately scoped auth cache. [`TokenStore`] owns no file path or
//! plaintext serializer: every operation is one transaction on the process-shared [`SecureVault`].

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::authstore::AccountAuthMaterial;
use crate::securestore::{PendingRedemption, SecureVault, VaultError, RESERVATION_ID_HEX_LEN};
use crate::tokens::{PendingMintBatch, PendingPaidIssue, StoredToken, TokenError};

/// A working copy of one durably reserved pass plus the random, non-secret identifier that must be
/// presented to complete exactly this reservation. Debug output is fully redacted because the
/// contained pass is a bearer credential.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenReservation {
    pub reservation_id: String,
    pub token: StoredToken,
}

/// One native lifecycle binding loaded atomically from the vault. `pending` distinguishes a tunnel
/// that still needs to consume its reserved pass from an already acknowledged live connection.
#[cfg(any(target_os = "android", target_os = "ios"))]
pub(crate) struct RedemptionBinding {
    pub reservation_id: String,
    pub pending: bool,
}

#[derive(PartialEq, Eq)]
pub(crate) enum PaidIssueBegin {
    Pending(PendingPaidIssue),
    Completed { token_count: usize },
}

impl std::fmt::Debug for PaidIssueBegin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending(_) => f.write_str("PaidIssueBegin::Pending([REDACTED])"),
            Self::Completed { token_count } => f
                .debug_struct("PaidIssueBegin::Completed")
                .field("token_count", token_count)
                .finish(),
        }
    }
}

impl std::fmt::Debug for TokenReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenReservation([REDACTED])")
    }
}

#[derive(Clone)]
pub struct TokenStore {
    vault: SecureVault,
}

impl TokenStore {
    pub fn new(vault: SecureVault) -> Self {
        Self { vault }
    }

    /// Atomically switch the cached account and clear every bearer/pending credential. One sealed
    /// replace avoids crash states where old auth survives with new/cleared tokens (or vice versa).
    pub fn replace_account(&self, material: &AccountAuthMaterial) -> Result<(), TokenError> {
        let material = material.clone();
        self.vault
            .mutate(move |vault| {
                vault.clear_sensitive();
                vault.auth = Some(material);
                Ok(())
            })
            .map_err(map_vault_error)
    }

    /// Atomically remove account auth, queued passes, in-flight redemption, and pending issuance.
    pub fn clear_all_credentials(&self) -> Result<(), TokenError> {
        self.vault
            .mutate(|vault| {
                vault.clear_sensitive();
                Ok(())
            })
            .map_err(map_vault_error)
    }

    /// All stored tokens (empty if the vault does not exist yet).
    pub fn load(&self) -> Result<Vec<StoredToken>, TokenError> {
        self.vault
            .load()
            .map(|vault| vault.tokens.clone())
            .map_err(map_vault_error)
    }

    pub fn count(&self) -> Result<usize, TokenError> {
        self.vault
            .load()
            .map(|vault| {
                vault
                    .tokens
                    .len()
                    .saturating_add(usize::from(vault.pending_redemption.is_some()))
            })
            .map_err(map_vault_error)
    }

    /// Non-secret lifecycle binding for startup reconciliation with an already-running native VPN.
    /// A pending reservation wins over the previous completion receipt, closing the ABA window.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) fn redemption_binding(&self) -> Result<Option<RedemptionBinding>, TokenError> {
        self.vault
            .load()
            .map(|vault| {
                vault
                    .pending_redemption
                    .as_ref()
                    .map(|pending| RedemptionBinding {
                        reservation_id: pending.reservation_id.clone(),
                        pending: true,
                    })
                    .or_else(|| {
                        vault
                            .last_redemption_id
                            .as_ref()
                            .map(|reservation_id| RedemptionBinding {
                                reservation_id: reservation_id.clone(),
                                pending: false,
                            })
                    })
            })
            .map_err(map_vault_error)
    }

    /// Count credentials that can still be redeemed at `now` without mutating the vault. The UI
    /// uses this view so an expired encrypted entry never enables Connect while the delayed
    /// background cleanup is still pending.
    pub fn redeemable_count(&self, now: u64) -> Result<usize, TokenError> {
        self.vault
            .load()
            .map(|vault| {
                let queued = vault
                    .tokens
                    .iter()
                    .filter(|token| token.is_redeemable_at(now))
                    .count();
                queued.saturating_add(usize::from(
                    vault
                        .pending_redemption
                        .as_ref()
                        .is_some_and(|pending| pending.token.is_redeemable_at(now)),
                ))
            })
            .map_err(map_vault_error)
    }

    /// Remove locally expired or malformed credentials before refill/accounting. Version-2 expiry
    /// is coarse and already public to the Coordinator at redemption; no per-token timestamp is
    /// stored. Legacy messages are retained for the explicitly bounded server migration window.
    pub fn prune_expired(&self, now: u64) -> Result<usize, TokenError> {
        let mut removed = 0_usize;
        self.vault
            .mutate(|vault| {
                if vault
                    .pending_mint
                    .as_ref()
                    .is_some_and(|pending| !pending.is_recoverable_at(now))
                {
                    if let Some(pending) = vault.pending_mint.as_mut() {
                        removed = removed.saturating_add(pending.requests.len());
                        pending.zeroize();
                    }
                    vault.pending_mint = None;
                }
                if vault
                    .pending_paid_issue
                    .as_ref()
                    .is_some_and(|pending| !pending.is_recoverable_at(now))
                {
                    if let Some(pending) = vault.pending_paid_issue.as_mut() {
                        pending.zeroize();
                    }
                    vault.pending_paid_issue = None;
                    removed = removed.saturating_add(1);
                }
                vault.tokens.retain_mut(|token| {
                    if token.is_redeemable_at(now) {
                        true
                    } else {
                        token.msg.zeroize();
                        token.token.zeroize();
                        removed += 1;
                        false
                    }
                });
                if vault
                    .pending_redemption
                    .as_ref()
                    .is_some_and(|pending| !pending.token.is_redeemable_at(now))
                {
                    if let Some(pending) = vault.pending_redemption.as_mut() {
                        pending.clear_sensitive();
                    }
                    vault.pending_redemption = None;
                    removed += 1;
                }
                Ok(())
            })
            .map_err(map_vault_error)?;
        Ok(removed)
    }

    /// Append acquired tokens without changing the cached account.
    pub fn add(&self, tokens: &[StoredToken]) -> Result<(), TokenError> {
        let tokens = tokens.to_vec();
        self.vault
            .mutate(move |vault| {
                vault.tokens.extend(tokens);
                Ok(())
            })
            .map_err(map_vault_error)
    }

    /// Return the exact durable batch issuance state, if an earlier request is incomplete.
    pub(crate) fn pending_mint(&self) -> Result<Option<PendingMintBatch>, TokenError> {
        self.vault
            .load()
            .map(|vault| vault.pending_mint.clone())
            .map_err(map_vault_error)
    }

    /// Persist a newly prepared batch before any authenticated issuer request. A concurrent/existing
    /// pending batch wins so callers always retry one stable request rather than minting a second.
    pub(crate) fn begin_mint(
        &self,
        proposed: PendingMintBatch,
    ) -> Result<PendingMintBatch, TokenError> {
        self.vault
            .mutate(move |vault| {
                if vault.pending_mint.is_none() {
                    vault.pending_mint = Some(proposed);
                }
                vault.pending_mint.clone().ok_or(VaultError::NoPendingMint)
            })
            .map_err(map_vault_error)
    }

    /// Atomically add every finalized token and clear only the issuance state that produced them.
    /// A stale response after logout/account replacement can never populate the new vault.
    pub fn commit_mint(
        &self,
        request_id: &str,
        tokens: Vec<StoredToken>,
    ) -> Result<usize, TokenError> {
        let request_id = request_id.to_owned();
        self.vault
            .mutate(move |vault| {
                let pending = vault
                    .pending_mint
                    .as_mut()
                    .ok_or(VaultError::NoPendingMint)?;
                if !constant_time_id_eq(&pending.request_id, &request_id) {
                    return Err(VaultError::MintRequestMismatch);
                }
                let added = tokens.len();
                vault.tokens.extend(tokens);
                pending.zeroize();
                vault.pending_mint = None;
                Ok(added)
            })
            .map_err(map_vault_error)
    }

    /// Return an exact one-payment issuance request left incomplete by response loss or restart.
    pub(crate) fn pending_paid_issue(&self) -> Result<Option<PendingPaidIssue>, TokenError> {
        self.vault
            .load()
            .map(|vault| vault.pending_paid_issue.clone())
            .map_err(map_vault_error)
    }

    /// Whether the most recently completed one-payment operation already matches this reference.
    /// The receipt is a domain-separated hash and is not stored beside any particular token.
    pub(crate) fn paid_issue_completed(&self, payment_id: &str) -> Result<bool, TokenError> {
        let expected = paid_issue_receipt(payment_id);
        self.vault
            .load()
            .map(|vault| {
                vault
                    .last_paid_issue_hash
                    .as_deref()
                    .is_some_and(|receipt| constant_time_id_eq(receipt, &expected))
            })
            .map_err(map_vault_error)
    }

    /// Persist one payment-gated blinded request before contacting the Portal. An already-pending
    /// request wins; callers must compare its payment reference before retrying it.
    pub(crate) fn begin_paid_issue(
        &self,
        proposed: PendingPaidIssue,
    ) -> Result<PaidIssueBegin, TokenError> {
        let receipt = paid_issue_receipt(&proposed.payment_id);
        self.vault
            .mutate(move |vault| {
                if vault
                    .last_paid_issue_hash
                    .as_deref()
                    .is_some_and(|stored| constant_time_id_eq(stored, &receipt))
                {
                    return Ok(PaidIssueBegin::Completed {
                        token_count: vault.tokens.len(),
                    });
                }
                if vault.pending_paid_issue.is_none() {
                    vault.pending_paid_issue = Some(proposed);
                }
                vault
                    .pending_paid_issue
                    .clone()
                    .map(PaidIssueBegin::Pending)
                    .ok_or(VaultError::NoPendingPaidIssue)
            })
            .map_err(map_vault_error)
    }

    /// Atomically add the finalized one-payment token and clear only the matching persisted
    /// issuance state. A stale response cannot populate a vault after logout or another checkout.
    pub(crate) fn commit_paid_issue(
        &self,
        payment_id: &str,
        token: StoredToken,
    ) -> Result<usize, TokenError> {
        let payment_id = payment_id.to_owned();
        let receipt = paid_issue_receipt(&payment_id);
        self.vault
            .mutate(move |vault| {
                let Some(pending) = vault.pending_paid_issue.as_mut() else {
                    if vault
                        .last_paid_issue_hash
                        .as_deref()
                        .is_some_and(|stored| constant_time_id_eq(stored, &receipt))
                    {
                        return Ok(vault.tokens.len());
                    }
                    return Err(VaultError::NoPendingPaidIssue);
                };
                if !constant_time_id_eq(&pending.payment_id, &payment_id) {
                    return Err(VaultError::PaidIssueMismatch);
                }
                vault.tokens.push(token);
                pending.zeroize();
                vault.pending_paid_issue = None;
                vault.last_paid_issue_hash = Some(receipt);
                Ok(vault.tokens.len())
            })
            .map_err(map_vault_error)
    }

    /// Atomically reserve one pass for Coordinator redemption and return a working copy. If a
    /// prior attempt crashed or lost its response, return that same reservation instead of
    /// consuming another pass. The authoritative copy remains encrypted in the vault until
    /// [`Self::commit_redemption`] records tunnel success.
    pub fn reserve_one(&self) -> Result<Option<TokenReservation>, TokenError> {
        self.vault
            .mutate(|vault| {
                if vault.pending_redemption.is_none() && !vault.tokens.is_empty() {
                    let mut pending = PendingRedemption::new(vault.tokens.remove(0))?;
                    // A 256-bit collision is fantastically unlikely, but explicitly reject it so
                    // the ABA invariant is structural rather than probabilistic.
                    while vault
                        .last_redemption_id
                        .as_deref()
                        .is_some_and(|last| constant_time_id_eq(last, &pending.reservation_id))
                    {
                        pending.reservation_id = crate::securestore::new_reservation_id()?;
                    }
                    vault.pending_redemption = Some(pending);
                }
                Ok(vault
                    .pending_redemption
                    .as_ref()
                    .map(|pending| TokenReservation {
                        reservation_id: pending.reservation_id.clone(),
                        token: pending.token.clone(),
                    }))
            })
            .map_err(map_vault_error)
    }

    /// Durably forget the pass reserved by [`Self::reserve_one`] after the tunnel has actually
    /// reported success. The exact most-recent completion is idempotent, while a stale completion
    /// can never affect a different pending pass.
    pub fn commit_redemption(&self, reservation_id: &str) -> Result<(), TokenError> {
        if !valid_reservation_id(reservation_id) {
            return Err(TokenError::ReservationMismatch);
        }
        let reservation_id = reservation_id.to_owned();
        self.vault
            .mutate(move |vault| {
                let Some(pending) = vault.pending_redemption.as_mut() else {
                    if vault
                        .last_redemption_id
                        .as_deref()
                        .is_some_and(|last| constant_time_id_eq(last, &reservation_id))
                    {
                        return Ok(());
                    }
                    return Err(VaultError::NoPendingReservation);
                };
                if !constant_time_id_eq(&pending.reservation_id, &reservation_id) {
                    return Err(VaultError::ReservationMismatch);
                }
                pending.clear_sensitive();
                vault.pending_redemption = None;
                if let Some(last) = vault.last_redemption_id.as_mut() {
                    last.zeroize();
                }
                vault.last_redemption_id = Some(reservation_id);
                Ok(())
            })
            .map_err(map_vault_error)
    }

    /// Drop all tokens without changing the cached account. Idempotent.
    pub fn clear(&self) -> Result<(), TokenError> {
        self.vault
            .mutate(|vault| {
                for token in &mut vault.tokens {
                    token.msg.zeroize();
                    token.token.zeroize();
                }
                vault.tokens.clear();
                if let Some(pending_mint) = vault.pending_mint.as_mut() {
                    pending_mint.zeroize();
                }
                vault.pending_mint = None;
                if let Some(pending_issue) = vault.pending_paid_issue.as_mut() {
                    pending_issue.zeroize();
                }
                vault.pending_paid_issue = None;
                if let Some(receipt) = vault.last_paid_issue_hash.as_mut() {
                    receipt.zeroize();
                }
                vault.last_paid_issue_hash = None;
                if let Some(pending) = vault.pending_redemption.as_mut() {
                    pending.clear_sensitive();
                }
                vault.pending_redemption = None;
                if let Some(last) = vault.last_redemption_id.as_mut() {
                    last.zeroize();
                }
                vault.last_redemption_id = None;
                Ok(())
            })
            .map_err(map_vault_error)
    }
}

fn valid_reservation_id(value: &str) -> bool {
    value.len() == RESERVATION_ID_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn constant_time_id_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn paid_issue_receipt(payment_id: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"nil/client/paid-issue-receipt/v1\0");
    hash.update(payment_id.as_bytes());
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn map_vault_error(error: VaultError) -> TokenError {
    match error {
        VaultError::NoPendingReservation => TokenError::NoPendingReservation,
        VaultError::ReservationMismatch => TokenError::ReservationMismatch,
        VaultError::NoPendingMint => TokenError::NoPendingMint,
        VaultError::MintRequestMismatch => TokenError::MintRequestMismatch,
        VaultError::NoPendingPaidIssue => TokenError::NoPendingPaidIssue,
        VaultError::PaidIssueMismatch => TokenError::PaidIssueMismatch,
        other => TokenError::Storage(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authstore::{AccountAuthMaterial, AuthStore};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_store() -> (TokenStore, PathBuf) {
        static N: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        let n = N.fetch_add(1, Ordering::Relaxed);
        path.push(format!(
            "nil-tokenstore-test-{}-{n}/secure/vault.bin",
            std::process::id()
        ));
        (
            TokenStore::new(crate::securestore::test_vault(path.clone())),
            path,
        )
    }

    fn tok(index: usize) -> StoredToken {
        StoredToken {
            msg: format!("{index:064x}"),
            token: format!("{index:0512x}"),
        }
    }

    fn auth() -> AccountAuthMaterial {
        AccountAuthMaterial {
            account_number: "ab".repeat(32),
            auth_seed: "cd".repeat(32),
        }
    }

    fn pending_mint(index: usize) -> PendingMintBatch {
        PendingMintBatch {
            request_id: format!("{index:064x}"),
            account_number: "ab".repeat(32),
            issuer_public_der: "30".repeat(32),
            requests: vec![crate::tokens::PendingBlindRequest {
                blind_msg: format!("{index:0512x}"),
                msg: format!("{index:064x}"),
                secret: format!("{:0512x}", index.saturating_add(1)),
                msg_randomizer: None,
            }],
        }
    }

    fn pending_paid_issue(index: usize) -> PendingPaidIssue {
        PendingPaidIssue {
            payment_id: format!("payment-{index}"),
            issuer_public_der: "30".repeat(32),
            request: crate::tokens::PendingBlindRequest {
                blind_msg: format!("{index:0512x}"),
                msg: format!("{index:064x}"),
                secret: format!("{:0512x}", index.saturating_add(1)),
                msg_randomizer: None,
            },
        }
    }

    #[test]
    fn missing_vault_loads_empty_without_creating_plaintext() {
        let (store, path) = tmp_store();
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.reserve_one().unwrap().is_none());
        assert!(store.load().unwrap().is_empty());
        assert!(path.exists(), "reserve_one durably commits the empty vault");
    }

    #[test]
    fn add_reserve_commit_consumes_one_at_a_time_and_persists_completion() {
        let (store, path) = tmp_store();
        store.add(&[tok(1), tok(2)]).unwrap();
        assert_eq!(store.count().unwrap(), 2);

        let first = store.reserve_one().unwrap().expect("one");
        store.commit_redemption(&first.reservation_id).unwrap();
        let second = store.reserve_one().unwrap().expect("two");
        store.commit_redemption(&second.reservation_id).unwrap();
        assert_ne!(first.token, second.token, "distinct tokens consumed");
        assert!(store.reserve_one().unwrap().is_none());

        let reopened = TokenStore::new(crate::securestore::test_vault(path));
        assert_eq!(reopened.count().unwrap(), 0);
    }

    #[test]
    fn reservation_survives_restart_and_retries_the_same_pass_until_committed() {
        let (store, path) = tmp_store();
        store.add(&[tok(1), tok(2)]).unwrap();

        let first = store.reserve_one().unwrap().expect("reserved pass");
        assert_eq!(first.token, tok(1));
        assert_eq!(store.count().unwrap(), 2, "a pending pass still has value");
        assert_eq!(
            store.reserve_one().unwrap(),
            Some(first.clone()),
            "an ambiguous retry must not consume the next pass"
        );

        let reopened = TokenStore::new(crate::securestore::test_vault(path));
        assert_eq!(reopened.reserve_one().unwrap(), Some(first.clone()));
        reopened.commit_redemption(&first.reservation_id).unwrap();
        reopened
            .commit_redemption(&first.reservation_id)
            .expect("exact duplicated completion is acknowledged");
        assert_eq!(reopened.count().unwrap(), 1);
        let second = reopened.reserve_one().unwrap().unwrap();
        assert_eq!(second.token, tok(2));
        assert!(matches!(
            reopened.commit_redemption(&first.reservation_id),
            Err(TokenError::ReservationMismatch)
        ));
        assert_eq!(reopened.reserve_one().unwrap(), Some(second));
    }

    #[test]
    fn expired_pending_pass_is_pruned_without_touching_a_current_pass() {
        let (store, _) = tmp_store();
        let now = 1_800_000_000_u64;
        let v2 = |index: usize, expiry: u64| {
            let mut msg = [0_u8; 32];
            msg[..4].copy_from_slice(&nil_crypto::token::V2_MAGIC);
            msg[4..12].copy_from_slice(&expiry.to_be_bytes());
            msg[12..].fill(index as u8);
            StoredToken {
                msg: msg.iter().map(|byte| format!("{byte:02x}")).collect(),
                token: format!("{index:0512x}"),
            }
        };
        store.add(&[v2(1, now - 1), v2(2, now + 60)]).unwrap();
        assert!(store.reserve_one().unwrap().is_some());
        assert_eq!(store.prune_expired(now).unwrap(), 1);
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(store.reserve_one().unwrap().unwrap().token, v2(2, now + 60));
    }

    #[test]
    fn stale_completion_cannot_clear_a_newer_reservation() {
        let (store, _) = tmp_store();
        store.add(&[tok(1)]).unwrap();
        let stale = store.reserve_one().unwrap().expect("first reservation");

        // Models logout/recovery or expiry clearing A before another async completion arrives.
        store.clear().unwrap();
        store.add(&[tok(2)]).unwrap();
        let current = store.reserve_one().unwrap().expect("new reservation");
        assert_ne!(stale.reservation_id, current.reservation_id);

        assert!(matches!(
            store.commit_redemption(&stale.reservation_id),
            Err(TokenError::ReservationMismatch)
        ));
        assert_eq!(store.reserve_one().unwrap(), Some(current.clone()));
        store
            .commit_redemption(&current.reservation_id)
            .expect("matching completion commits");
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn pending_mint_survives_restart_and_commits_tokens_atomically() {
        let (store, path) = tmp_store();
        let pending = pending_mint(41);
        assert_eq!(store.begin_mint(pending.clone()).unwrap(), pending);
        assert_eq!(store.count().unwrap(), 0);

        let reopened = TokenStore::new(crate::securestore::test_vault(path));
        assert_eq!(reopened.pending_mint().unwrap(), Some(pending.clone()));
        assert!(matches!(
            reopened.commit_mint(&"ff".repeat(32), vec![tok(8)]),
            Err(TokenError::MintRequestMismatch)
        ));
        assert_eq!(reopened.count().unwrap(), 0);
        assert_eq!(reopened.pending_mint().unwrap(), Some(pending.clone()));

        assert_eq!(
            reopened
                .commit_mint(&pending.request_id, vec![tok(8), tok(9)])
                .unwrap(),
            2
        );
        assert_eq!(reopened.count().unwrap(), 2);
        assert!(reopened.pending_mint().unwrap().is_none());
    }

    #[test]
    fn existing_pending_mint_wins_and_clear_removes_it() {
        let (store, _) = tmp_store();
        let first = pending_mint(51);
        let second = pending_mint(52);
        assert_eq!(store.begin_mint(first.clone()).unwrap(), first);
        assert_eq!(store.begin_mint(second).unwrap(), first);
        store.clear().unwrap();
        assert!(store.pending_mint().unwrap().is_none());
    }

    #[test]
    fn paid_issue_survives_restart_and_only_matching_completion_commits() {
        let (store, path) = tmp_store();
        let pending = pending_paid_issue(81);
        assert_eq!(
            store.begin_paid_issue(pending.clone()).unwrap(),
            PaidIssueBegin::Pending(pending.clone())
        );

        let reopened = TokenStore::new(crate::securestore::test_vault(path));
        assert_eq!(
            reopened.pending_paid_issue().unwrap(),
            Some(pending.clone())
        );
        assert!(matches!(
            reopened.commit_paid_issue("another-payment", tok(8)),
            Err(TokenError::PaidIssueMismatch)
        ));
        assert_eq!(reopened.count().unwrap(), 0);
        assert_eq!(
            reopened.pending_paid_issue().unwrap(),
            Some(pending.clone())
        );

        assert_eq!(
            reopened
                .commit_paid_issue(&pending.payment_id, tok(8))
                .unwrap(),
            1
        );
        assert_eq!(reopened.load().unwrap(), vec![tok(8)]);
        assert!(reopened.pending_paid_issue().unwrap().is_none());
        assert!(reopened.paid_issue_completed(&pending.payment_id).unwrap());
        assert!(!reopened.paid_issue_completed("another-payment").unwrap());
        assert_eq!(
            reopened.begin_paid_issue(pending_paid_issue(81)).unwrap(),
            PaidIssueBegin::Completed { token_count: 1 }
        );
    }

    #[test]
    fn another_paid_issue_cannot_replace_pending_state_and_clear_removes_it() {
        let (store, _) = tmp_store();
        let first = pending_paid_issue(91);
        let second = pending_paid_issue(92);
        assert_eq!(
            store.begin_paid_issue(first.clone()).unwrap(),
            PaidIssueBegin::Pending(first.clone())
        );
        assert_eq!(
            store.begin_paid_issue(second).unwrap(),
            PaidIssueBegin::Pending(first)
        );
        store.clear().unwrap();
        assert!(store.pending_paid_issue().unwrap().is_none());
    }

    #[test]
    fn expired_pending_mint_is_pruned_instead_of_blocking_refill_forever() {
        let (store, _) = tmp_store();
        let now = 1_800_000_000_u64;
        let mut pending = pending_mint(71);
        let mut message = [0_u8; 32];
        message[..4].copy_from_slice(&nil_crypto::token::V2_MAGIC);
        message[4..12].copy_from_slice(&(now - 1).to_be_bytes());
        pending.requests[0].msg = message.iter().map(|byte| format!("{byte:02x}")).collect();
        store.begin_mint(pending).unwrap();

        assert_eq!(store.prune_expired(now).unwrap(), 1);
        assert!(store.pending_mint().unwrap().is_none());
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn expired_pending_paid_issue_is_pruned_before_a_new_checkout_retry() {
        let (store, _) = tmp_store();
        let now = 1_800_000_000_u64;
        let mut pending = pending_paid_issue(72);
        let mut message = [0_u8; 32];
        message[..4].copy_from_slice(&nil_crypto::token::V2_MAGIC);
        message[4..12].copy_from_slice(&(now - 1).to_be_bytes());
        pending.request.msg = message.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(matches!(
            store.begin_paid_issue(pending).unwrap(),
            PaidIssueBegin::Pending(_)
        ));

        assert_eq!(store.prune_expired(now).unwrap(), 1);
        assert!(store.pending_paid_issue().unwrap().is_none());
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn auth_and_token_facades_preserve_each_others_fields() {
        let (_, path) = tmp_store();
        let shared = crate::securestore::test_vault(path);
        let auth_store = AuthStore::new(shared.clone());
        let token_store = TokenStore::new(shared);

        auth_store.save(&auth()).unwrap();
        token_store.add(&[tok(1), tok(2)]).unwrap();
        assert_eq!(auth_store.load().unwrap(), Some(auth()));
        assert_eq!(token_store.count().unwrap(), 2);

        auth_store.clear().unwrap();
        assert_eq!(token_store.count().unwrap(), 2);
        auth_store.save(&auth()).unwrap();
        token_store.clear().unwrap();
        assert_eq!(auth_store.load().unwrap(), Some(auth()));
    }

    #[test]
    fn account_replace_and_logout_are_single_vault_transactions() {
        let (_, path) = tmp_store();
        let shared = crate::securestore::test_vault(path);
        let auth_store = AuthStore::new(shared.clone());
        let token_store = TokenStore::new(shared);
        auth_store.save(&auth()).unwrap();
        token_store.add(&[tok(1), tok(2)]).unwrap();
        token_store.begin_mint(pending_mint(61)).unwrap();
        token_store
            .begin_paid_issue(pending_paid_issue(62))
            .unwrap();
        let reservation = token_store.reserve_one().unwrap().unwrap();
        assert_eq!(token_store.count().unwrap(), 2);

        let replacement = AccountAuthMaterial {
            account_number: "11".repeat(32),
            auth_seed: "22".repeat(32),
        };
        token_store.replace_account(&replacement).unwrap();
        assert_eq!(auth_store.load().unwrap(), Some(replacement));
        assert_eq!(token_store.count().unwrap(), 0);
        assert!(token_store.pending_mint().unwrap().is_none());
        assert!(token_store.pending_paid_issue().unwrap().is_none());
        assert!(matches!(
            token_store.commit_redemption(&reservation.reservation_id),
            Err(TokenError::NoPendingReservation)
        ));

        token_store.clear_all_credentials().unwrap();
        assert!(auth_store.load().unwrap().is_none());
        assert_eq!(token_store.count().unwrap(), 0);
    }

    #[test]
    fn prune_expired_removes_only_stale_v2_tokens() {
        let (store, _) = tmp_store();
        let now = 1_800_000_000_u64;
        let v2 = |index: usize, expiry: u64| {
            let mut msg = [0_u8; 32];
            msg[..4].copy_from_slice(&nil_crypto::token::V2_MAGIC);
            msg[4..12].copy_from_slice(&expiry.to_be_bytes());
            msg[12..].fill(index as u8);
            StoredToken {
                msg: msg.iter().map(|byte| format!("{byte:02x}")).collect(),
                token: format!("{index:0512x}"),
            }
        };
        let current = v2(2, now + 60);
        store
            .add(&[tok(1), v2(3, now - 1), current.clone()])
            .unwrap();

        assert_eq!(store.redeemable_count(now).unwrap(), 2);
        assert_eq!(store.prune_expired(now).unwrap(), 1);
        assert_eq!(store.load().unwrap(), vec![tok(1), current]);
    }

    /// Locks the no-waste guarantee: `connect` runs privilege preflight before `take_one`.
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn failed_preflight_leaves_token_count_unchanged() {
        let (store, _) = tmp_store();
        store.add(&[tok(1), tok(2)]).unwrap();
        assert_eq!(store.count().unwrap(), 2);

        let gate = nil_datapath::preflight_privilege();
        let consumed = if gate.is_ok() {
            let reserved = store.reserve_one().unwrap();
            if let Some(reservation) = reserved.as_ref() {
                store
                    .commit_redemption(&reservation.reservation_id)
                    .unwrap();
            }
            reserved
        } else {
            None
        };

        if gate.is_ok() {
            assert!(consumed.is_some(), "privileged: proceeds and consumes one");
            assert_eq!(store.count().unwrap(), 1);
        } else {
            assert!(consumed.is_none(), "no token consumed when the gate fails");
            assert_eq!(store.count().unwrap(), 2);
        }
    }

    #[test]
    fn vault_file_contains_no_token_or_linking_metadata() {
        let (store, path) = tmp_store();
        let stored = tok(7);
        store.add(std::slice::from_ref(&stored)).unwrap();
        let pending_issue = pending_paid_issue(101);
        store.begin_paid_issue(pending_issue.clone()).unwrap();
        let raw = std::fs::read(path).unwrap();
        for forbidden in [
            stored.msg.clone(),
            stored.token.clone(),
            pending_issue.payment_id.clone(),
            pending_issue.request.blind_msg.clone(),
            "payment".to_string(),
            "account".to_string(),
            "msg".to_string(),
            "token".to_string(),
        ] {
            assert!(
                !raw.windows(forbidden.len())
                    .any(|window| window == forbidden.as_bytes()),
                "vault ciphertext exposed token/linking material"
            );
        }
    }
}
