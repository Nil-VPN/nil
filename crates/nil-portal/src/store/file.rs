//! File-backed account store (durable across restarts) behind the same [`Store`] trait as the
//! in-memory one (ADR-0003). It persists the account map as JSON, written atomically
//! (temp file + rename), and reloads it on open. A Postgres-backed `Store` slots in behind the
//! same trait for a clustered deployment.
//!
//! **Still PII-free.** It persists exactly the three non-identifying [`AccountRecord`] fields
//! (`H(secret)`, the recovery-code hash, and the entitlement) as hex — no email, name, IP, or
//! timestamp. A full disk compromise yields no personal identity for an anonymous account.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::{Store, StoreError};
use crate::account::model::{AccountRecord, Entitlement};

/// On-disk representation of one account (hex-encoded; PII-free by construction).
#[derive(Serialize, Deserialize)]
struct RecordDto {
    account_number: String,
    recovery_code_hash: String,
    entitlement: String,
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let h = s.as_bytes();
    if h.len() != 64 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = [0u8; 32];
    for (i, p) in h.chunks_exact(2).enumerate() {
        out[i] = (nib(p[0])? << 4) | nib(p[1])?;
    }
    Some(out)
}

fn ent_str(e: Entitlement) -> &'static str {
    match e {
        Entitlement::None => "none",
        Entitlement::Active => "active",
        Entitlement::Expired => "expired",
    }
}

fn ent_from(s: &str) -> Option<Entitlement> {
    match s {
        "none" => Some(Entitlement::None),
        "active" => Some(Entitlement::Active),
        "expired" => Some(Entitlement::Expired),
        _ => None,
    }
}

impl RecordDto {
    fn from_record(r: &AccountRecord) -> Self {
        Self {
            account_number: hex32(&r.account_number),
            recovery_code_hash: hex32(&r.recovery_code_hash),
            entitlement: ent_str(r.entitlement).to_string(),
        }
    }

    fn to_record(&self) -> Option<AccountRecord> {
        Some(AccountRecord {
            account_number: unhex32(&self.account_number)?,
            recovery_code_hash: unhex32(&self.recovery_code_hash)?,
            entitlement: ent_from(&self.entitlement)?,
        })
    }
}

/// A durable, JSON-file-backed account store.
pub struct FileStore {
    path: PathBuf,
    inner: RwLock<HashMap<[u8; 32], AccountRecord>>,
}

impl FileStore {
    /// Open (creating the parent dir if needed) and load any persisted accounts.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut map = HashMap::new();
        if let Ok(bytes) = std::fs::read(&path) {
            if !bytes.is_empty() {
                let dtos: Vec<RecordDto> = serde_json::from_slice(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                for dto in dtos {
                    if let Some(rec) = dto.to_record() {
                        map.insert(rec.account_number, rec);
                    }
                }
            }
        }
        Ok(Self { path, inner: RwLock::new(map) })
    }

    /// Atomically write the whole map to disk (temp file + rename).
    fn persist(&self, map: &HashMap<[u8; 32], AccountRecord>) -> io::Result<()> {
        let dtos: Vec<RecordDto> = map.values().map(RecordDto::from_record).collect();
        let json = serde_json::to_vec_pretty(&dtos)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[async_trait]
impl Store for FileStore {
    async fn insert(&self, record: AccountRecord) -> Result<(), StoreError> {
        let mut map = self.inner.write().await;
        if map.contains_key(&record.account_number) {
            return Err(StoreError::Duplicate);
        }
        let key = record.account_number;
        map.insert(key, record);
        // Fail closed: if the durable write fails, roll back the in-memory insert so memory and
        // disk stay consistent and the caller sees the account was not created.
        if let Err(e) = self.persist(&map) {
            map.remove(&key);
            return Err(StoreError::Backend(e.to_string()));
        }
        Ok(())
    }

    async fn get(&self, account_number: &[u8; 32]) -> Result<Option<AccountRecord>, StoreError> {
        Ok(self.inner.read().await.get(account_number).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("nil-portal-store-{}-{n}.json", std::process::id()))
    }

    fn record(byte: u8, ent: Entitlement) -> AccountRecord {
        AccountRecord { account_number: [byte; 32], recovery_code_hash: [byte ^ 0xff; 32], entitlement: ent }
    }

    #[tokio::test]
    async fn accounts_survive_a_restart_and_dedup() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);

        {
            let s = FileStore::open(&path).expect("open");
            s.insert(record(1, Entitlement::Active)).await.expect("insert 1");
            // Duplicate account number is rejected.
            assert!(matches!(s.insert(record(1, Entitlement::None)).await, Err(StoreError::Duplicate)));
            s.insert(record(2, Entitlement::None)).await.expect("insert 2");
        } // drop = restart

        let s2 = FileStore::open(&path).expect("reopen");
        let got = s2.get(&[1u8; 32]).await.expect("get").expect("account 1 persisted");
        assert_eq!(got.entitlement, Entitlement::Active);
        assert_eq!(got.recovery_code_hash, [0xfeu8; 32]);
        assert!(s2.get(&[2u8; 32]).await.expect("get").is_some());
        assert!(s2.get(&[3u8; 32]).await.expect("get").is_none());

        let _ = std::fs::remove_file(&path);
    }
}
