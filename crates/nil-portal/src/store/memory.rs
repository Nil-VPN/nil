//! In-memory account store for Phase 0. Volatile across restarts — fine for the
//! skeleton (exit criteria are build/test/tauri-dev). Replaced by a Postgres-backed
//! `Store` in Phase 1 behind the same trait (ADR-0003).

use std::collections::HashMap;

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::{Store, StoreError};
use crate::account::model::{AccountRecord, Entitlement};

#[derive(Default)]
pub struct InMemoryStore {
    inner: RwLock<HashMap<[u8; 32], AccountRecord>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn insert(&self, record: AccountRecord) -> Result<(), StoreError> {
        let mut map = self.inner.write().await;
        if map.contains_key(&record.account_number) {
            return Err(StoreError::Duplicate);
        }
        map.insert(record.account_number, record);
        Ok(())
    }

    async fn get(&self, account_number: &[u8; 32]) -> Result<Option<AccountRecord>, StoreError> {
        Ok(self.inner.read().await.get(account_number).cloned())
    }

    async fn extend_subscription(
        &self,
        account_number: &[u8; 32],
        now_secs: u64,
        by_secs: u64,
    ) -> Result<Option<u64>, StoreError> {
        let mut map = self.inner.write().await;
        let Some(rec) = map.get_mut(account_number) else {
            return Ok(None);
        };
        // Base read from the live record under the write lock → atomic stack (no lost update).
        let base = rec.entitlement.active_until(now_secs).unwrap_or(now_secs);
        let until = base.saturating_add(by_secs);
        rec.entitlement = Entitlement::Active { until };
        Ok(Some(until))
    }
}
