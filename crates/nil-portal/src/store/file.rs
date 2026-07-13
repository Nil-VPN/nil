//! File-backed account store (durable across restarts) behind the same [`Store`] trait as the
//! in-memory one (ADR-0003). It persists the account map and subscription-activation results in
//! one JSON snapshot, written atomically (temp file + rename), and reloads it on open. Keeping the
//! two maps in the same snapshot makes payment claim + entitlement extension crash-atomic. A
//! Postgres-backed `Store` slots in behind the same trait for a clustered deployment.
//!
//! **Still PII-minimized.** Account rows persist exactly the three [`AccountRecord`] fields:
//! `H(secret)`, entitlement, and the public authentication key. The same snapshot also holds hashed
//! operation keys, encrypted replay payloads, and logical expiries/quota windows documented in
//! `RETAINED_DATA.md`. No recovery material, email, name, source IP,
//! destination, or traffic record is written. Legacy `recovery_code_hash` input remains readable;
//! it is never serialized again.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use zeroize::Zeroize;

use super::{
    auth_from, auth_str, decode_mint_payload, encode_mint_payload, ent_from, ent_str, hex32,
    unhex32, IssuanceCommit, IssuanceLookup, IssuanceResult, MintCommit, MintLookup, MintQuota,
    MintResult, ResultCipher, ResultKind, Store, StoreError, SubscriptionActivation,
};
use crate::account::model::{AccountRecord, Entitlement};

/// On-disk representation of one account (hex-encoded; PII-free by construction).
#[derive(Serialize, Deserialize)]
struct RecordDto {
    account_number: String,
    /// Backward-compatible read of the pre-client-generated-account format. Deliberately ignored
    /// and never serialized again.
    #[serde(default, rename = "recovery_code_hash", skip_serializing)]
    _recovery_code_hash: Option<String>,
    entitlement: String,
    // Additive (ADR-0007): default "" so a record written before the auth key reads back as the
    // all-zero "no auth key" sentinel rather than failing to parse.
    #[serde(default)]
    auth_pubkey: String,
}

impl RecordDto {
    fn from_record(r: &AccountRecord) -> Self {
        Self {
            account_number: hex32(&r.account_number),
            _recovery_code_hash: None,
            entitlement: ent_str(r.entitlement),
            auth_pubkey: auth_str(&r.auth_pubkey),
        }
    }

    fn to_record(&self) -> Option<AccountRecord> {
        Some(AccountRecord {
            account_number: unhex32(&self.account_number)?,
            entitlement: ent_from(&self.entitlement)?,
            auth_pubkey: auth_from(&self.auth_pubkey)?,
        })
    }
}

/// Current on-disk format. The former format was a bare `Vec<RecordDto>`; [`DiskDto`] continues
/// to accept it and the next successful write upgrades it to this atomic snapshot.
#[derive(Serialize, Deserialize)]
struct SnapshotDto {
    accounts: Vec<RecordDto>,
    #[serde(default)]
    activation_results: HashMap<String, u64>,
    #[serde(default)]
    issuance_results: HashMap<String, IssuanceDto>,
    #[serde(default)]
    mint_results: HashMap<String, MintDto>,
    #[serde(default)]
    mint_quotas: Vec<MintQuotaDto>,
}

#[derive(Serialize, Deserialize)]
struct IssuanceDto {
    request_hash: String,
    #[serde(default)]
    result_blob: String,
    /// Pre-encryption development rows are accepted only as spent/no-result migration markers.
    #[serde(default, rename = "blind_sig", skip_serializing)]
    _blind_sig: String,
    #[serde(default)]
    replay_until: u64,
}

#[derive(Serialize, Deserialize)]
struct MintDto {
    request_hash: String,
    #[serde(default)]
    result_blob: String,
    /// Pre-encryption development rows remain conflict markers until their expiry.
    #[serde(default, rename = "blind_sigs", skip_serializing)]
    _blind_sigs: Vec<String>,
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
struct MintQuotaDto {
    quota_key: String,
    window_start: u64,
    window_end: u64,
    used: u32,
    /// Zero only for an interrupted/pre-max migration row; such a row conflicts fail-closed.
    #[serde(default)]
    max_value: u32,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DiskDto {
    Snapshot(SnapshotDto),
    LegacyAccounts(Vec<RecordDto>),
}

#[derive(Default)]
struct FileState {
    accounts: HashMap<[u8; 32], AccountRecord>,
    activation_results: HashMap<[u8; 32], u64>,
    issuance_results: HashMap<[u8; 32], IssuanceResult>,
    mint_results: HashMap<[u8; 32], MintResult>,
    mint_quotas: HashMap<([u8; 32], u64), (u64, u32, u32)>,
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex_bytes(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            Some((nibble(pair[0])? << 4) | nibble(pair[1])?)
        })
        .collect()
}

/// A durable, JSON-file-backed account store.
pub struct FileStore {
    path: PathBuf,
    /// Stable sidecar inode held exclusively for this process lifetime. Locking the snapshot file
    /// itself would be bypassed after its first atomic rename.
    #[cfg(unix)]
    _process_lock: std::fs::File,
    /// One lock covers both maps, matching the one-snapshot durability boundary.
    inner: RwLock<FileState>,
    cipher: ResultCipher,
    /// A rename happened but its parent-directory fsync failed. Until a later sync proves that
    /// rename durable, no read/replay may trust the newer in-memory state.
    durability_uncertain: AtomicBool,
    #[cfg(test)]
    fail_parent_syncs: AtomicUsize,
}

struct PersistError {
    error: io::Error,
    /// True once the atomic rename has installed the new snapshot. Callers must then keep their
    /// in-memory mutation so a reported directory-fsync error cannot diverge memory from the path.
    committed_to_path: bool,
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl FileStore {
    /// Open (creating the parent dir if needed) and load any persisted accounts.
    pub fn open_with_result_key<P: AsRef<Path>>(path: P, result_key: [u8; 32]) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let cipher = ResultCipher::new(result_key);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        #[cfg(unix)]
        let process_lock = open_process_lock(&path)?;
        let mut state = FileState::default();
        let mut result_payload_rewrite_needed = false;
        match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => {
                let disk: DiskDto = serde_json::from_slice(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let (accounts, activation_results, issuance_results, mint_results, mint_quotas) =
                    match disk {
                        DiskDto::Snapshot(snapshot) => (
                            snapshot.accounts,
                            snapshot.activation_results,
                            snapshot.issuance_results,
                            snapshot.mint_results,
                            snapshot.mint_quotas,
                        ),
                        DiskDto::LegacyAccounts(accounts) => (
                            accounts,
                            HashMap::new(),
                            HashMap::new(),
                            HashMap::new(),
                            Vec::new(),
                        ),
                    };
                for dto in accounts {
                    let rec = dto.to_record().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "account store contains an invalid record",
                        )
                    })?;
                    state.accounts.insert(rec.account_number, rec);
                }
                for (key, until) in activation_results {
                    let key = unhex32(&key).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "account store contains an invalid activation key",
                        )
                    })?;
                    state.activation_results.insert(key, until);
                }
                for (key, result) in issuance_results {
                    if !result._blind_sig.is_empty() {
                        // Legacy cleartext replay payloads are deliberately not imported. Rewrite
                        // immediately so merely starting the new version scrubs them from disk.
                        result_payload_rewrite_needed = true;
                    }
                    let key = unhex32(&key).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "account store contains an invalid issuance key",
                        )
                    })?;
                    let request_hash = unhex32(&result.request_hash).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "account store contains an invalid issuance request hash",
                        )
                    })?;
                    let blind_sig = if result.result_blob.is_empty() {
                        Vec::new()
                    } else {
                        let stored = unhex_bytes(&result.result_blob).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "account store contains an invalid issuance result ciphertext",
                            )
                        })?;
                        match cipher.open(
                            ResultKind::OneShot,
                            &key,
                            &request_hash,
                            result.replay_until,
                            &stored,
                        ) {
                            Ok(signature)
                                if signature.len() * 2 == nil_proto::token::BLIND_TOKEN_HEX_LEN =>
                            {
                                signature.to_vec()
                            }
                            Ok(_) | Err(_) => {
                                tracing::warn!(
                                    "one-shot replay result unavailable; preserving spent claim"
                                );
                                Vec::new()
                            }
                        }
                    };
                    state.issuance_results.insert(
                        key,
                        IssuanceResult {
                            request_hash,
                            blind_sig,
                            replay_until: result.replay_until,
                        },
                    );
                }
                for (key, result) in mint_results {
                    if !result._blind_sigs.is_empty() {
                        result_payload_rewrite_needed = true;
                    }
                    let key = unhex32(&key).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "account store contains an invalid mint request key",
                        )
                    })?;
                    let request_hash = unhex32(&result.request_hash).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "account store contains an invalid mint request hash",
                        )
                    })?;
                    let blind_sigs = if result.result_blob.is_empty() {
                        Vec::new()
                    } else {
                        let stored = unhex_bytes(&result.result_blob).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "account store contains an invalid mint result ciphertext",
                            )
                        })?;
                        match cipher
                            .open(
                                ResultKind::SubscriptionMint,
                                &key,
                                &request_hash,
                                result.expires_at,
                                &stored,
                            )
                            .and_then(|payload| decode_mint_payload(&payload))
                        {
                            Ok(signatures) => signatures,
                            Err(_) => {
                                tracing::warn!("mint replay result unavailable; preserving live conflict marker");
                                Vec::new()
                            }
                        }
                    };
                    state.mint_results.insert(
                        key,
                        MintResult {
                            request_hash,
                            blind_sigs,
                            expires_at: result.expires_at,
                        },
                    );
                }
                for quota in mint_quotas {
                    let quota_key = unhex32(&quota.quota_key).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid mint quota key")
                    })?;
                    if quota.window_start >= quota.window_end {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid mint quota window",
                        ));
                    }
                    state.mint_quotas.insert(
                        (quota_key, quota.window_start),
                        (quota.window_end, quota.used, quota.max_value),
                    );
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let store = Self {
            path,
            #[cfg(unix)]
            _process_lock: process_lock,
            inner: RwLock::new(state),
            cipher,
            durability_uncertain: AtomicBool::new(false),
            #[cfg(test)]
            fail_parent_syncs: AtomicUsize::new(0),
        };
        if result_payload_rewrite_needed {
            let state = store.inner.try_read().map_err(|_| {
                io::Error::other("new account store unexpectedly locked during result migration")
            })?;
            store.persist(&state).map_err(|error| error.error)?;
        }
        Ok(store)
    }

    #[cfg(test)]
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::open_with_result_key(path, [0x5a; 32])
    }

    /// Atomically AND durably write the whole map to disk: write the temp file, `fsync` it,
    /// rename over the target, then `fsync` the parent directory. The rename gives torn-read
    /// protection; the fsyncs give crash durability — so `insert` returning `Ok` means the account
    /// is on disk, matching the sibling `DurableSet`'s "accepted ⇒ fsync'd" guarantee.
    fn write_snapshot_and_rename(&self, state: &FileState) -> io::Result<()> {
        let issuance_results = state
            .issuance_results
            .iter()
            .map(|(key, result)| {
                let result_blob = if result.blind_sig.is_empty() {
                    String::new()
                } else {
                    let ciphertext = self
                        .cipher
                        .seal(
                            ResultKind::OneShot,
                            key,
                            &result.request_hash,
                            result.replay_until,
                            &result.blind_sig,
                        )
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    hex_bytes(&ciphertext)
                };
                Ok((
                    hex32(key),
                    IssuanceDto {
                        request_hash: hex32(&result.request_hash),
                        result_blob,
                        _blind_sig: String::new(),
                        replay_until: result.replay_until,
                    },
                ))
            })
            .collect::<io::Result<HashMap<_, _>>>()?;
        let mint_results = state
            .mint_results
            .iter()
            .map(|(key, result)| {
                let result_blob = if result.blind_sigs.is_empty() {
                    String::new()
                } else {
                    let payload = encode_mint_payload(&result.blind_sigs)
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    let ciphertext = self
                        .cipher
                        .seal(
                            ResultKind::SubscriptionMint,
                            key,
                            &result.request_hash,
                            result.expires_at,
                            &payload,
                        )
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    hex_bytes(&ciphertext)
                };
                Ok((
                    hex32(key),
                    MintDto {
                        request_hash: hex32(&result.request_hash),
                        result_blob,
                        _blind_sigs: Vec::new(),
                        expires_at: result.expires_at,
                    },
                ))
            })
            .collect::<io::Result<HashMap<_, _>>>()?;
        let snapshot = SnapshotDto {
            accounts: state
                .accounts
                .values()
                .map(RecordDto::from_record)
                .collect(),
            activation_results: state
                .activation_results
                .iter()
                .map(|(key, until)| (hex32(key), *until))
                .collect(),
            issuance_results,
            mint_results,
            mint_quotas: state
                .mint_quotas
                .iter()
                .map(
                    |((quota_key, window_start), (window_end, used, max_value))| MintQuotaDto {
                        quota_key: hex32(quota_key),
                        window_start: *window_start,
                        window_end: *window_end,
                        used: *used,
                        max_value: *max_value,
                    },
                )
                .collect(),
        };
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec_pretty(&snapshot)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );
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
        Ok(())
    }

    fn persist(&self, state: &FileState) -> Result<(), PersistError> {
        self.write_snapshot_and_rename(state)
            .map_err(|error| PersistError {
                error,
                committed_to_path: false,
            })?;
        self.durability_uncertain.store(true, Ordering::SeqCst);
        self.sync_parent_directory().map_err(|error| PersistError {
            error,
            committed_to_path: true,
        })?;
        self.durability_uncertain.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn sync_parent_directory(&self) -> io::Result<()> {
        #[cfg(test)]
        if self
            .fail_parent_syncs
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                if remaining > 0 {
                    Some(remaining - 1)
                } else {
                    None
                }
            })
            .is_ok()
        {
            return Err(io::Error::other("injected parent-directory fsync failure"));
        }
        #[cfg(unix)]
        {
            let parent = self
                .path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    fn ensure_durable(&self) -> Result<(), StoreError> {
        if !self.durability_uncertain.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.sync_parent_directory().map_err(|error| {
            StoreError::Backend(format!(
                "account-store durability remains uncertain after rename: {error}"
            ))
        })?;
        self.durability_uncertain.store(false, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(test)]
    fn inject_parent_sync_failures(&self, count: usize) {
        self.fail_parent_syncs.store(count, Ordering::SeqCst);
    }
}

#[cfg(unix)]
fn open_process_lock(snapshot_path: &Path) -> io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::OpenOptionsExt;

    let mut bytes = snapshot_path.as_os_str().as_bytes().to_vec();
    bytes.extend_from_slice(b".lock");
    let lock_path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options.open(&lock_path)?;
    // SAFETY: `file` owns a valid open descriptor for the duration of the call. The descriptor is
    // retained in FileStore, so the advisory lock remains held until that store is dropped.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!(
                "account store {} is already locked by another Portal process: {error}",
                snapshot_path.display()
            ),
        ));
    }
    Ok(file)
}

#[async_trait]
impl Store for FileStore {
    async fn insert(&self, record: AccountRecord) -> Result<(), StoreError> {
        let mut state = self.inner.write().await;
        self.ensure_durable()?;
        if state.accounts.contains_key(&record.account_number) {
            return Err(StoreError::Duplicate);
        }
        let key = record.account_number;
        state.accounts.insert(key, record);
        // Fail closed: if the durable write fails, roll back the in-memory insert so memory and
        // disk stay consistent and the caller sees the account was not created.
        if let Err(e) = self.persist(&state) {
            if !e.committed_to_path {
                state.accounts.remove(&key);
            }
            return Err(StoreError::Backend(e.to_string()));
        }
        Ok(())
    }

    async fn get(&self, account_number: &[u8; 32]) -> Result<Option<AccountRecord>, StoreError> {
        let state = self.inner.read().await;
        self.ensure_durable()?;
        Ok(state.accounts.get(account_number).cloned())
    }

    async fn activate_subscription(
        &self,
        account_number: &[u8; 32],
        activation_key: &[u8; 32],
        now_secs: u64,
        by_secs: u64,
    ) -> Result<Option<SubscriptionActivation>, StoreError> {
        let mut state = self.inner.write().await;
        self.ensure_durable()?;
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
        let previous = rec.entitlement;
        let base = rec.entitlement.active_until(now_secs).unwrap_or(now_secs);
        let until = base.saturating_add(by_secs);
        rec.entitlement = Entitlement::Active { until };
        state.activation_results.insert(*activation_key, until);

        // One snapshot contains both mutations. A failed write rolls both in-memory changes back;
        // a successful atomic rename exposes both together after a restart.
        if let Err(error) = self.persist(&state) {
            if !error.committed_to_path {
                state.activation_results.remove(activation_key);
                if let Some(rec) = state.accounts.get_mut(account_number) {
                    rec.entitlement = previous;
                }
            }
            return Err(StoreError::Backend(error.to_string()));
        }
        Ok(Some(SubscriptionActivation::NewlyActivated { until }))
    }

    async fn lookup_issuance(
        &self,
        issuance_key: &[u8; 32],
        request_hash: &[u8; 32],
        now_secs: u64,
    ) -> Result<IssuanceLookup, StoreError> {
        let state = self.inner.read().await;
        self.ensure_durable()?;
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
        self.ensure_durable()?;
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
        if let Err(error) = self.persist(&state) {
            if !error.committed_to_path {
                state.issuance_results.remove(issuance_key);
            }
            return Err(StoreError::Backend(error.to_string()));
        }
        Ok(IssuanceCommit::Stored)
    }

    async fn prune_issuance_results(&self, now_secs: u64) -> Result<usize, StoreError> {
        let mut state = self.inner.write().await;
        self.ensure_durable()?;
        let previous = state.issuance_results.clone();
        let mut removed = 0usize;
        for result in state.issuance_results.values_mut() {
            if result.replay_until <= now_secs && !result.blind_sig.is_empty() {
                result.blind_sig.zeroize();
                result.blind_sig.clear();
                removed += 1;
            }
        }
        if removed == 0 {
            return Ok(0);
        }
        if let Err(error) = self.persist(&state) {
            if !error.committed_to_path {
                state.issuance_results = previous;
            }
            return Err(StoreError::Backend(error.to_string()));
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
        self.ensure_durable()?;
        if state
            .mint_results
            .get(request_key)
            .is_some_and(|result| result.expires_at <= now_secs)
        {
            let expired = state
                .mint_results
                .remove(request_key)
                .ok_or_else(|| StoreError::Backend("expired mint result disappeared".into()))?;
            if let Err(error) = self.persist(&state) {
                if !error.committed_to_path {
                    state.mint_results.insert(*request_key, expired);
                }
                return Err(StoreError::Backend(error.to_string()));
            }
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
        self.ensure_durable()?;
        let expired = if state
            .mint_results
            .get(request_key)
            .is_some_and(|existing| existing.expires_at <= now_secs)
        {
            state.mint_results.remove(request_key)
        } else {
            None
        };
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
        let quota_previous = state.mint_quotas.get(&quota_key).copied();
        let (window_end, used, stored_max) =
            quota_previous.unwrap_or((quota.window_end, 0, quota.max));
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
        if let Err(error) = self.persist(&state) {
            if !error.committed_to_path {
                state.mint_results.remove(request_key);
                if let Some(expired) = expired {
                    state.mint_results.insert(*request_key, expired);
                }
                if let Some(previous) = quota_previous {
                    state.mint_quotas.insert(quota_key, previous);
                } else {
                    state.mint_quotas.remove(&quota_key);
                }
            }
            return Err(StoreError::Backend(error.to_string()));
        }
        Ok(MintCommit::Stored)
    }

    async fn prune_mint_results(&self, now_secs: u64) -> Result<usize, StoreError> {
        let mut state = self.inner.write().await;
        self.ensure_durable()?;
        let previous_results = state.mint_results.clone();
        let previous_quotas = state.mint_quotas.clone();
        state
            .mint_results
            .retain(|_, result| result.expires_at > now_secs);
        state
            .mint_quotas
            .retain(|_, (window_end, _, _)| *window_end > now_secs);
        let removed = previous_results
            .len()
            .saturating_sub(state.mint_results.len())
            .saturating_add(
                previous_quotas
                    .len()
                    .saturating_sub(state.mint_quotas.len()),
            );
        if removed == 0 {
            return Ok(0);
        }
        if let Err(error) = self.persist(&state) {
            if !error.committed_to_path {
                state.mint_results = previous_results;
                state.mint_quotas = previous_quotas;
            }
            return Err(StoreError::Backend(error.to_string()));
        }
        Ok(removed)
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
        AccountRecord {
            account_number: [byte; 32],
            entitlement: ent,
            auth_pubkey: [byte ^ 0x0f; 32],
        }
    }

    fn quota(now: u64, cost: u32, max: u32) -> MintQuota {
        MintQuota {
            quota_key: [0x81; 32],
            window_start: 4_000.min(now),
            window_end: 6_000,
            cost,
            max,
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn account_store_file_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let s = FileStore::open(&path).expect("open");
        s.insert(record(7, Entitlement::None))
            .await
            .expect("insert");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "account store holds H(secret) keys — owner-only"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn file_store_refuses_a_second_process_authority() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let first = FileStore::open(&path).expect("first authority");
        assert!(
            FileStore::open(&path).is_err(),
            "a second FileStore could race snapshots and duplicate issuance"
        );
        drop(first);
        assert!(FileStore::open(&path).is_ok(), "drop releases the lock");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }

    #[tokio::test]
    async fn accounts_survive_a_restart_and_dedup() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);

        {
            let s = FileStore::open(&path).expect("open");
            s.insert(record(
                1,
                Entitlement::Active {
                    until: 1_900_000_000,
                },
            ))
            .await
            .expect("insert 1");
            // Duplicate account number is rejected.
            assert!(matches!(
                s.insert(record(1, Entitlement::None)).await,
                Err(StoreError::Duplicate)
            ));
            s.insert(record(2, Entitlement::None))
                .await
                .expect("insert 2");
        } // drop = restart

        let s2 = FileStore::open(&path).expect("reopen");
        let got = s2
            .get(&[1u8; 32])
            .await
            .expect("get")
            .expect("account 1 persisted");
        assert_eq!(
            got.entitlement,
            Entitlement::Active {
                until: 1_900_000_000
            }
        );
        assert_eq!(
            got.auth_pubkey, [0x0eu8; 32],
            "auth pubkey survives a restart"
        );
        assert!(s2.get(&[2u8; 32]).await.expect("get").is_some());
        assert!(s2.get(&[3u8; 32]).await.expect("get").is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn legacy_recovery_hash_is_read_but_never_written_again() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let legacy = serde_json::json!([{
            "account_number": "11".repeat(32),
            "recovery_code_hash": "22".repeat(32),
            "entitlement": "none",
            "auth_pubkey": "33".repeat(32),
        }]);
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).expect("write legacy fixture");

        let s = FileStore::open(&path).expect("legacy file opens");
        assert!(
            s.get(&[0x11; 32]).await.unwrap().is_some(),
            "legacy account survives migration"
        );
        s.insert(record(0x44, Entitlement::None))
            .await
            .expect("rewrite store");

        let rewritten: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for row in rewritten["accounts"].as_array().unwrap() {
            assert!(
                row.get("recovery_code_hash").is_none(),
                "obsolete recovery verifier must not be retained"
            );
        }
        assert!(rewritten["activation_results"].is_object());
        assert!(rewritten["issuance_results"].is_object());
        assert!(rewritten["mint_results"].is_object());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn activation_extension_persists_across_restart() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let now = 1_500_000_000u64;
        {
            let s = FileStore::open(&path).expect("open");
            s.insert(record(5, Entitlement::None))
                .await
                .expect("insert");
            let until = s
                .activate_subscription(&[5u8; 32], &[0x15; 32], now, 30 * 24 * 60 * 60)
                .await
                .expect("activate")
                .expect("present")
                .until();
            assert_eq!(until, now + 30 * 24 * 60 * 60);
        } // restart
        let s2 = FileStore::open(&path).expect("reopen");
        let got = s2.get(&[5u8; 32]).await.expect("get").expect("present");
        assert_eq!(
            got.entitlement,
            Entitlement::Active {
                until: now + 30 * 24 * 60 * 60
            },
            "extension survived restart"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn distinct_activation_keys_stack_on_the_persisted_value() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let s = FileStore::open(&path).expect("open");
        s.insert(record(6, Entitlement::None))
            .await
            .expect("insert");

        let now = 1_000_000u64;
        let day = 24 * 60 * 60;
        // The first distinct activation starts from `now` (None → max(now, -) = now).
        let u1 = s
            .activate_subscription(&[6u8; 32], &[0x16; 32], now, 30 * day)
            .await
            .expect("activate 1")
            .expect("present")
            .until();
        assert_eq!(u1, now + 30 * day);
        // The second activation reads the PERSISTED until and stacks (the lost-update regression):
        // each distinct payment adds its period rather than overwriting from a stale snapshot.
        let u2 = s
            .activate_subscription(&[6u8; 32], &[0x26; 32], now, 30 * day)
            .await
            .expect("activate 2")
            .expect("present")
            .until();
        assert_eq!(
            u2,
            now + 60 * day,
            "second extend stacks on the persisted first"
        );
        // A lapsed/now-in-the-future clock still starts no earlier than `now`.
        let later = u2 + 100 * day; // well past the current expiry
        let u3 = s
            .activate_subscription(&[6u8; 32], &[0x36; 32], later, 30 * day)
            .await
            .expect("activate 3")
            .expect("present")
            .until();
        assert_eq!(
            u3,
            later + 30 * day,
            "an expired sub re-starts from now, not the stale past expiry"
        );

        // Missing account → None.
        assert!(s
            .activate_subscription(&[7u8; 32], &[0x47; 32], now, day)
            .await
            .expect("missing")
            .is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn activation_result_and_entitlement_commit_together_and_replay_after_restart() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let expected_until = 1_000_000 + 30 * 24 * 60 * 60;
        {
            let store = FileStore::open(&path).expect("open");
            store
                .insert(record(8, Entitlement::None))
                .await
                .expect("insert");
            assert_eq!(
                store
                    .activate_subscription(&[8; 32], &[0xa8; 32], 1_000_000, 30 * 24 * 60 * 60,)
                    .await
                    .expect("activate")
                    .expect("account"),
                SubscriptionActivation::NewlyActivated {
                    until: expected_until
                }
            );
        }

        let restarted = FileStore::open(&path).expect("restart");
        assert_eq!(
            restarted
                .activate_subscription(&[8; 32], &[0xa8; 32], 9_000_000, 99)
                .await
                .expect("replay")
                .expect("account"),
            SubscriptionActivation::Replay {
                until: expected_until
            }
        );
        assert_eq!(
            restarted.get(&[8; 32]).await.unwrap().unwrap().entitlement,
            Entitlement::Active {
                until: expected_until
            },
            "a replay after restart must not extend again"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn issuance_result_replays_after_restart_and_rejects_rebinding() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let result = IssuanceResult {
            request_hash: [0xc1; 32],
            blind_sig: vec![0xd2; nil_proto::token::BLIND_TOKEN_HEX_LEN / 2],
            replay_until: 2_000,
        };
        {
            let store = FileStore::open(&path).expect("open");
            assert_eq!(
                store
                    .commit_issuance(&[0xb0; 32], result.clone(), 1_000)
                    .await
                    .unwrap(),
                IssuanceCommit::Stored
            );
        }

        let restarted = FileStore::open(&path).expect("restart");
        assert_eq!(
            restarted
                .lookup_issuance(&[0xb0; 32], &[0xc1; 32], 1_500)
                .await
                .unwrap(),
            IssuanceLookup::Replay {
                blind_sig: result.blind_sig.clone()
            }
        );
        assert_eq!(
            restarted
                .lookup_issuance(&[0xb0; 32], &[0xee; 32], 1_500)
                .await
                .unwrap(),
            IssuanceLookup::Conflict
        );
        assert_eq!(restarted.prune_issuance_results(2_000).await.unwrap(), 1);
        drop(restarted);
        let pruned = FileStore::open(&path).unwrap();
        assert_eq!(
            pruned
                .lookup_issuance(&[0xb0; 32], &[0xc1; 32], 2_000)
                .await
                .unwrap(),
            IssuanceLookup::Conflict,
            "pruning removes only the replay payload, never the spent claim"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn replay_payload_is_encrypted_at_rest_and_wrong_key_fails_closed() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let result = IssuanceResult {
            request_hash: [0x51; 32],
            blind_sig: vec![0x52; nil_proto::token::BLIND_TOKEN_HEX_LEN / 2],
            replay_until: 2_000,
        };
        {
            let store = FileStore::open_with_result_key(&path, [0x41; 32]).unwrap();
            assert_eq!(
                store
                    .commit_issuance(&[0x50; 32], result.clone(), 1_000)
                    .await
                    .unwrap(),
                IssuanceCommit::Stored
            );
        }
        let snapshot = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
        assert!(snapshot.contains("result_blob"));
        assert!(!snapshot.contains("blind_sig"));
        assert!(
            !snapshot.contains(&"52".repeat(nil_proto::token::BLIND_TOKEN_HEX_LEN / 2)),
            "the clear blind signature must not appear in the durable snapshot"
        );

        let wrong_key = FileStore::open_with_result_key(&path, [0x42; 32]).unwrap();
        assert_eq!(
            wrong_key
                .lookup_issuance(&[0x50; 32], &[0x51; 32], 1_500)
                .await
                .unwrap(),
            IssuanceLookup::Conflict,
            "key mismatch preserves the spent claim and never signs again"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn legacy_cleartext_replay_payload_is_scrubbed_on_open_and_kept_spent() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let mut issuance_results = serde_json::Map::new();
        issuance_results.insert(
            "60".repeat(32),
            serde_json::json!({
                "request_hash": "61".repeat(32),
                "blind_sig": "62".repeat(nil_proto::token::BLIND_TOKEN_HEX_LEN / 2),
                "replay_until": 2_000
            }),
        );
        let legacy = serde_json::json!({
            "accounts": [],
            "activation_results": {},
            "issuance_results": issuance_results,
            "mint_results": {},
            "mint_quotas": []
        });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let store = FileStore::open(&path).unwrap();
        assert_eq!(
            store
                .lookup_issuance(&[0x60; 32], &[0x61; 32], 1_000)
                .await
                .unwrap(),
            IssuanceLookup::Conflict
        );
        let rewritten = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
        assert!(!rewritten.contains("blind_sig"));
        assert!(!rewritten.contains(&"62".repeat(nil_proto::token::BLIND_TOKEN_HEX_LEN / 2)));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn failed_snapshot_leaves_issuance_retryable() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let store = FileStore::open(&path).expect("open");
        std::fs::create_dir(&path).unwrap();
        let result = IssuanceResult {
            request_hash: [0xf1; 32],
            blind_sig: vec![0xf2; nil_proto::token::BLIND_TOKEN_HEX_LEN / 2],
            replay_until: 2_000,
        };
        assert!(store
            .commit_issuance(&[0xf0; 32], result.clone(), 1_000)
            .await
            .is_err());
        assert_eq!(
            store
                .lookup_issuance(&[0xf0; 32], &[0xf1; 32], 1_000)
                .await
                .unwrap(),
            IssuanceLookup::Missing
        );

        std::fs::remove_dir(&path).unwrap();
        assert_eq!(
            store
                .commit_issuance(&[0xf0; 32], result, 1_000)
                .await
                .unwrap(),
            IssuanceCommit::Stored
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
    }

    #[tokio::test]
    async fn post_rename_sync_failure_cannot_replay_from_uncertain_memory() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let store = FileStore::open(&path).expect("open");
        let result = IssuanceResult {
            request_hash: [0xe1; 32],
            blind_sig: vec![0xe2; nil_proto::token::BLIND_TOKEN_HEX_LEN / 2],
            replay_until: 2_000,
        };
        // The first failure happens after rename; the second makes the immediate retry unable to
        // prove the rename durable. It must not return Replay from newer in-memory state.
        store.inject_parent_sync_failures(2);
        assert!(store
            .commit_issuance(&[0xe0; 32], result.clone(), 1_000)
            .await
            .is_err());
        assert!(store
            .commit_issuance(&[0xe0; 32], result.clone(), 1_000)
            .await
            .is_err());

        // Once a later parent sync succeeds, the installed snapshot is proven durable and the
        // exact result may safely replay.
        assert_eq!(
            store
                .lookup_issuance(&[0xe0; 32], &[0xe1; 32], 1_000)
                .await
                .unwrap(),
            IssuanceLookup::Replay {
                blind_sig: result.blind_sig.clone()
            }
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn mint_result_replays_after_restart_and_prunes_durably() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let result = MintResult {
            request_hash: [0x72; 32],
            blind_sigs: vec![
                vec![0x73; nil_proto::token::BLIND_TOKEN_HEX_LEN / 2],
                vec![0x74; nil_proto::token::BLIND_TOKEN_HEX_LEN / 2],
            ],
            expires_at: 5_000,
        };
        {
            let store = FileStore::open(&path).unwrap();
            assert_eq!(
                store
                    .commit_mint(&[0x71; 32], result.clone(), quota(4_000, 2, 10), 4_000)
                    .await
                    .unwrap(),
                MintCommit::Stored
            );
        }
        let restarted = FileStore::open(&path).unwrap();
        assert_eq!(
            restarted
                .lookup_mint(&[0x71; 32], &[0x72; 32], 4_999)
                .await
                .unwrap(),
            MintLookup::Replay {
                blind_sigs: result.blind_sigs.clone()
            }
        );
        assert_eq!(restarted.prune_mint_results(5_000).await.unwrap(), 1);
        drop(restarted);
        let pruned = FileStore::open(&path).unwrap();
        assert_eq!(
            pruned
                .lookup_mint(&[0x71; 32], &[0x72; 32], 5_000)
                .await
                .unwrap(),
            MintLookup::Missing
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn failed_snapshot_rolls_back_both_claim_and_extension() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let store = FileStore::open(&path).expect("open");
        store
            .insert(record(9, Entitlement::None))
            .await
            .expect("insert");

        // Replacing the destination file with a directory forces the final rename to fail after
        // the temporary snapshot is written. The in-memory transaction must still roll back.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(store
            .activate_subscription(&[9; 32], &[0xb9; 32], 5_000, 500)
            .await
            .is_err());
        assert_eq!(
            store.get(&[9; 32]).await.unwrap().unwrap().entitlement,
            Entitlement::None
        );

        // Repair the destination. The same key is still unclaimed and can now commit exactly once.
        std::fs::remove_dir(&path).unwrap();
        assert_eq!(
            store
                .activate_subscription(&[9; 32], &[0xb9; 32], 5_000, 500)
                .await
                .unwrap()
                .unwrap(),
            SubscriptionActivation::NewlyActivated { until: 5_500 }
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
    }
}
