//! In-memory account store for Phase 0. Volatile across restarts — fine for the
//! skeleton (exit criteria are build/test/tauri-dev). Replaced by a Postgres-backed
//! `Store` in Phase 1 behind the same trait (ADR-0003).

use std::collections::HashMap;

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::{
    IssuanceCommit, IssuanceLookup, IssuanceResult, MintCommit, MintLookup, MintQuota, MintResult,
    Store, StoreError, SubscriptionActivation,
};
use crate::account::model::{AccountRecord, Entitlement};

#[derive(Default)]
struct MemoryState {
    accounts: HashMap<[u8; 32], AccountRecord>,
    /// Domain-separated `SHA-256(reference || account)` -> expiry returned by the first commit.
    activation_results: HashMap<[u8; 32], u64>,
    /// Hashed checkout reference -> request-bound cached blind signature.
    issuance_results: HashMap<[u8; 32], IssuanceResult>,
    /// Random request-id hash -> short-lived request-bound batch result.
    mint_results: HashMap<[u8; 32], MintResult>,
    /// `(domain-separated account hash, window start)` -> `(window end, used token count)`.
    /// `(quota key, window start) -> (window end, used, configured max)`.
    mint_quotas: HashMap<([u8; 32], u64), (u64, u32, u32)>,
}

#[derive(Default)]
pub struct InMemoryStore {
    /// Accounts and activation results share one lock so claim + extension is indivisible.
    inner: RwLock<MemoryState>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn insert(&self, record: AccountRecord) -> Result<(), StoreError> {
        let mut state = self.inner.write().await;
        if state.accounts.contains_key(&record.account_number) {
            return Err(StoreError::Duplicate);
        }
        state.accounts.insert(record.account_number, record);
        Ok(())
    }

    async fn get(&self, account_number: &[u8; 32]) -> Result<Option<AccountRecord>, StoreError> {
        Ok(self
            .inner
            .read()
            .await
            .accounts
            .get(account_number)
            .cloned())
    }

    async fn activate_subscription(
        &self,
        account_number: &[u8; 32],
        activation_key: &[u8; 32],
        now_secs: u64,
        by_secs: u64,
    ) -> Result<Option<SubscriptionActivation>, StoreError> {
        let mut state = self.inner.write().await;
        if !state.accounts.contains_key(account_number) {
            return Ok(None);
        }
        if let Some(&until) = state.activation_results.get(activation_key) {
            return Ok(Some(SubscriptionActivation::Replay { until }));
        }

        let rec = state
            .accounts
            .get_mut(account_number)
            .expect("account existence checked under the same write lock");
        let base = rec.entitlement.active_until(now_secs).unwrap_or(now_secs);
        let until = base.saturating_add(by_secs);
        rec.entitlement = Entitlement::Active { until };
        state.activation_results.insert(*activation_key, until);
        Ok(Some(SubscriptionActivation::NewlyActivated { until }))
    }

    async fn lookup_issuance(
        &self,
        issuance_key: &[u8; 32],
        request_hash: &[u8; 32],
        now_secs: u64,
    ) -> Result<IssuanceLookup, StoreError> {
        let state = self.inner.read().await;
        Ok(match state.issuance_results.get(issuance_key) {
            None => IssuanceLookup::Missing,
            Some(result)
                if &result.request_hash == request_hash
                    && result.replay_until > now_secs
                    && !result.blind_sig.is_empty() =>
            {
                IssuanceLookup::Replay {
                    blind_sig: result.blind_sig.clone(),
                }
            }
            Some(_) => IssuanceLookup::Conflict,
        })
    }

    async fn commit_issuance(
        &self,
        issuance_key: &[u8; 32],
        result: IssuanceResult,
        now_secs: u64,
    ) -> Result<IssuanceCommit, StoreError> {
        if result.replay_until <= now_secs || result.blind_sig.is_empty() {
            return Err(StoreError::Backend(
                "refusing to store an expired or empty issuance result".into(),
            ));
        }
        let mut state = self.inner.write().await;
        if let Some(existing) = state.issuance_results.get(issuance_key) {
            return Ok(
                if existing.request_hash == result.request_hash
                    && existing.replay_until > now_secs
                    && !existing.blind_sig.is_empty()
                {
                    IssuanceCommit::Replay {
                        blind_sig: existing.blind_sig.clone(),
                    }
                } else {
                    IssuanceCommit::Conflict
                },
            );
        }
        state.issuance_results.insert(*issuance_key, result);
        Ok(IssuanceCommit::Stored)
    }

    async fn prune_issuance_results(&self, now_secs: u64) -> Result<usize, StoreError> {
        let mut state = self.inner.write().await;
        let mut removed = 0usize;
        for result in state.issuance_results.values_mut() {
            if result.replay_until <= now_secs && !result.blind_sig.is_empty() {
                use zeroize::Zeroize;
                result.blind_sig.zeroize();
                result.blind_sig.clear();
                removed += 1;
            }
        }
        Ok(removed)
    }

    async fn lookup_mint(
        &self,
        request_key: &[u8; 32],
        request_hash: &[u8; 32],
        now_secs: u64,
    ) -> Result<MintLookup, StoreError> {
        let mut state = self.inner.write().await;
        if state
            .mint_results
            .get(request_key)
            .is_some_and(|result| result.expires_at <= now_secs)
        {
            state.mint_results.remove(request_key);
        }
        Ok(match state.mint_results.get(request_key) {
            None => MintLookup::Missing,
            Some(result)
                if &result.request_hash == request_hash && !result.blind_sigs.is_empty() =>
            {
                MintLookup::Replay {
                    blind_sigs: result.blind_sigs.clone(),
                }
            }
            Some(_) => MintLookup::Conflict,
        })
    }

    async fn commit_mint(
        &self,
        request_key: &[u8; 32],
        result: MintResult,
        quota: MintQuota,
        now_secs: u64,
    ) -> Result<MintCommit, StoreError> {
        if result.expires_at <= now_secs {
            return Err(StoreError::Backend(
                "refusing to store an already-expired mint result".into(),
            ));
        }
        let mut state = self.inner.write().await;
        if state
            .mint_results
            .get(request_key)
            .is_some_and(|existing| existing.expires_at <= now_secs)
        {
            state.mint_results.remove(request_key);
        }
        if let Some(existing) = state.mint_results.get(request_key) {
            return Ok(
                if existing.request_hash == result.request_hash && !existing.blind_sigs.is_empty() {
                    MintCommit::Replay {
                        blind_sigs: existing.blind_sigs.clone(),
                    }
                } else {
                    MintCommit::Conflict
                },
            );
        }
        if !quota.is_well_formed(now_secs) {
            return Err(StoreError::Backend("invalid mint quota window".into()));
        }
        if quota.cost > quota.max {
            return Ok(MintCommit::QuotaExceeded);
        }
        let quota_key = (quota.quota_key, quota.window_start);
        let (window_end, used, stored_max) = state
            .mint_quotas
            .get(&quota_key)
            .copied()
            .unwrap_or((quota.window_end, 0, quota.max));
        if window_end != quota.window_end || stored_max != quota.max {
            return Err(StoreError::Backend(
                "mint quota window/max conflicts with persisted state".into(),
            ));
        }
        let Some(next_used) = used.checked_add(quota.cost) else {
            return Ok(MintCommit::QuotaExceeded);
        };
        if next_used > quota.max {
            return Ok(MintCommit::QuotaExceeded);
        }
        state.mint_results.insert(*request_key, result);
        state
            .mint_quotas
            .insert(quota_key, (quota.window_end, next_used, quota.max));
        Ok(MintCommit::Stored)
    }

    async fn prune_mint_results(&self, now_secs: u64) -> Result<usize, StoreError> {
        let mut state = self.inner.write().await;
        let before = state.mint_results.len();
        state
            .mint_results
            .retain(|_, result| result.expires_at > now_secs);
        let removed_results = before.saturating_sub(state.mint_results.len());
        let quota_before = state.mint_quotas.len();
        state
            .mint_quotas
            .retain(|_, (window_end, _, _)| *window_end > now_secs);
        Ok(removed_results.saturating_add(quota_before.saturating_sub(state.mint_quotas.len())))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn record() -> AccountRecord {
        AccountRecord {
            account_number: [1; 32],
            entitlement: Entitlement::None,
            auth_pubkey: [2; 32],
        }
    }

    fn quota(now: u64, cost: u32, max: u32) -> MintQuota {
        MintQuota {
            quota_key: [0x91; 32],
            window_start: now - (now % 10_000),
            window_end: now - (now % 10_000) + 10_000,
            cost,
            max,
        }
    }

    #[tokio::test]
    async fn concurrent_retries_extend_exactly_once() {
        let store = Arc::new(InMemoryStore::new());
        store.insert(record()).await.unwrap();
        let mut calls = Vec::new();
        for _ in 0..16 {
            let store = store.clone();
            calls.push(tokio::spawn(async move {
                store
                    .activate_subscription(&[1; 32], &[9; 32], 1_000, 300)
                    .await
                    .unwrap()
                    .unwrap()
            }));
        }

        let mut newly = 0;
        for call in calls {
            match call.await.unwrap() {
                SubscriptionActivation::NewlyActivated { until } => {
                    newly += 1;
                    assert_eq!(until, 1_300);
                }
                SubscriptionActivation::Replay { until } => assert_eq!(until, 1_300),
            }
        }
        assert_eq!(newly, 1);
        assert_eq!(
            store.get(&[1; 32]).await.unwrap().unwrap().entitlement,
            Entitlement::Active { until: 1_300 }
        );
    }

    #[tokio::test]
    async fn issuance_replays_only_the_identical_blinded_request() {
        let store = InMemoryStore::new();
        let key = [7; 32];
        let first = IssuanceResult {
            request_hash: [8; 32],
            blind_sig: vec![9; 256],
            replay_until: 2_000,
        };
        assert_eq!(
            store.lookup_issuance(&key, &[8; 32], 1_000).await.unwrap(),
            IssuanceLookup::Missing
        );
        assert_eq!(
            store
                .commit_issuance(&key, first.clone(), 1_000)
                .await
                .unwrap(),
            IssuanceCommit::Stored
        );
        assert_eq!(
            store.lookup_issuance(&key, &[8; 32], 1_500).await.unwrap(),
            IssuanceLookup::Replay {
                blind_sig: first.blind_sig.clone()
            }
        );
        assert_eq!(
            store.lookup_issuance(&key, &[6; 32], 1_500).await.unwrap(),
            IssuanceLookup::Conflict
        );
        assert_eq!(
            store
                .commit_issuance(
                    &key,
                    IssuanceResult {
                        request_hash: [6; 32],
                        blind_sig: vec![5; 256],
                        replay_until: 2_000,
                    },
                    1_500,
                )
                .await
                .unwrap(),
            IssuanceCommit::Conflict
        );
        assert_eq!(store.prune_issuance_results(2_000).await.unwrap(), 1);
        assert_eq!(
            store.lookup_issuance(&key, &[8; 32], 2_000).await.unwrap(),
            IssuanceLookup::Conflict,
            "the spent claim survives after its replay payload is scrubbed"
        );
    }

    #[tokio::test]
    async fn mint_result_replays_until_expiry_then_can_be_replaced() {
        let store = InMemoryStore::new();
        let key = [0x31; 32];
        let first = MintResult {
            request_hash: [0x32; 32],
            blind_sigs: vec![vec![0x33; 256], vec![0x34; 256]],
            expires_at: 2_000,
        };
        assert_eq!(
            store
                .commit_mint(&key, first.clone(), quota(1_000, 2, 10), 1_000)
                .await
                .unwrap(),
            MintCommit::Stored
        );
        assert_eq!(
            store.lookup_mint(&key, &[0x32; 32], 1_999).await.unwrap(),
            MintLookup::Replay {
                blind_sigs: first.blind_sigs.clone()
            }
        );
        assert_eq!(
            store.lookup_mint(&key, &[0x35; 32], 1_999).await.unwrap(),
            MintLookup::Conflict
        );
        assert_eq!(
            store.lookup_mint(&key, &[0x35; 32], 2_000).await.unwrap(),
            MintLookup::Missing
        );
        assert_eq!(store.prune_mint_results(2_000).await.unwrap(), 0);

        let second = MintResult {
            request_hash: [0x35; 32],
            blind_sigs: vec![vec![0x36; 256]],
            expires_at: 3_000,
        };
        assert_eq!(
            store
                .commit_mint(&key, second, quota(2_000, 1, 10), 2_000)
                .await
                .unwrap(),
            MintCommit::Stored
        );
        assert_eq!(store.prune_mint_results(3_000).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn concurrent_result_winner_charges_quota_once_and_distinct_requests_hit_cap() {
        let store = Arc::new(InMemoryStore::new());
        let result = MintResult {
            request_hash: [0xa2; 32],
            blind_sigs: vec![vec![0xa3; 256]],
            expires_at: 2_000,
        };
        let mut calls = Vec::new();
        for _ in 0..16 {
            let store = store.clone();
            let result = result.clone();
            calls.push(tokio::spawn(async move {
                store
                    .commit_mint(&[0xa1; 32], result, quota(1_000, 1, 2), 1_000)
                    .await
                    .unwrap()
            }));
        }
        let mut stored = 0;
        for call in calls {
            match call.await.unwrap() {
                MintCommit::Stored => stored += 1,
                MintCommit::Replay { blind_sigs } => assert_eq!(blind_sigs.len(), 1),
                other => panic!("unexpected concurrent outcome: {other:?}"),
            }
        }
        assert_eq!(stored, 1);

        let second = MintResult {
            request_hash: [0xb2; 32],
            blind_sigs: vec![vec![0xb3; 256]],
            expires_at: 2_000,
        };
        assert_eq!(
            store
                .commit_mint(&[0xb1; 32], second, quota(1_000, 1, 2), 1_000)
                .await
                .unwrap(),
            MintCommit::Stored,
            "retries of the first request consumed only one unit"
        );
        let third = MintResult {
            request_hash: [0xc2; 32],
            blind_sigs: vec![vec![0xc3; 256]],
            expires_at: 2_000,
        };
        assert_eq!(
            store
                .commit_mint(&[0xc1; 32], third, quota(1_000, 1, 2), 1_000)
                .await
                .unwrap(),
            MintCommit::QuotaExceeded
        );
        assert_eq!(
            store
                .lookup_mint(&[0xc1; 32], &[0xc2; 32], 1_000)
                .await
                .unwrap(),
            MintLookup::Missing,
            "a rejected charge must not leave a committed result"
        );

        let drifted = MintResult {
            request_hash: [0xd2; 32],
            blind_sigs: vec![vec![0xd3; 256]],
            expires_at: 2_000,
        };
        assert!(matches!(
            store
                .commit_mint(&[0xd1; 32], drifted, quota(1_000, 1, 3), 1_000)
                .await,
            Err(StoreError::Backend(message)) if message.contains("window/max")
        ));
        assert_eq!(
            store
                .lookup_mint(&[0xd1; 32], &[0xd2; 32], 1_000)
                .await
                .unwrap(),
            MintLookup::Missing,
            "replica cap drift must roll back the result"
        );
    }
}
