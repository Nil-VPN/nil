//! File-backed account store (durable across restarts) behind the same [`Store`] trait as the
//! in-memory one (ADR-0003). It persists the account map as JSON, written atomically
//! (temp file + rename), and reloads it on open. A Postgres-backed `Store` slots in behind the
//! same trait for a clustered deployment.
//!
//! **Still PII-free.** It persists exactly the three non-identifying [`AccountRecord`] fields
//! (`H(secret)`, the recovery-code hash, and the entitlement) as hex — no email, name, IP, or
//! timestamp. A full disk compromise yields no personal identity for an anonymous account.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::{ent_from, ent_str, hex32, unhex32, Store, StoreError};
use crate::account::model::AccountRecord;

/// On-disk representation of one account (hex-encoded; PII-free by construction).
#[derive(Serialize, Deserialize)]
struct RecordDto {
    account_number: String,
    recovery_code_hash: String,
    entitlement: String,
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

    /// Atomically AND durably write the whole map to disk: write the temp file, `fsync` it,
    /// rename over the target, then `fsync` the parent directory. The rename gives torn-read
    /// protection; the fsyncs give crash durability — so `insert` returning `Ok` means the account
    /// is on disk, matching the sibling `DurableSet`'s "accepted ⇒ fsync'd" guarantee.
    fn persist(&self, map: &HashMap<[u8; 32], AccountRecord>) -> io::Result<()> {
        let dtos: Vec<RecordDto> = map.values().map(RecordDto::from_record).collect();
        let json = serde_json::to_vec_pretty(&dtos)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let tmp = self.path.with_extension("tmp");
        {
            // Owner-only (0600) on Unix: the account store holds every account's H(secret) lookup
            // key; a world-readable file would let any local process enumerate registered accounts.
            // The rename preserves the temp's inode + mode, so the final file inherits 0600.
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(&json)?;
            f.flush()?;
            f.sync_all()?; // fsync the temp data BEFORE the rename, or a crash can leave it unflushed
        }
        std::fs::rename(&tmp, &self.path)?;
        // fsync the parent directory so the rename itself survives a crash. Best-effort: some
        // platforms (e.g. Windows) don't allow opening a directory for fsync.
        if let Some(parent) = self.path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
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
    use crate::account::model::Entitlement;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("nil-portal-store-{}-{n}.json", std::process::id()))
    }

    fn record(byte: u8, ent: Entitlement) -> AccountRecord {
        AccountRecord { account_number: [byte; 32], recovery_code_hash: [byte ^ 0xff; 32], entitlement: ent }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn account_store_file_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let s = FileStore::open(&path).expect("open");
        s.insert(record(7, Entitlement::None)).await.expect("insert");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "account store holds H(secret) keys — owner-only");
        let _ = std::fs::remove_file(&path);
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
