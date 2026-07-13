//! Atomic anonymous token spending with a short-lived replayable redemption result.
//!
//! A successful redemption commits one authoritative record containing the permanent Privacy Pass
//! nullifier and an AEAD-encrypted `PathResponse`. An identical retry before the grants expire gets
//! that exact stored response; it never mints another usable set of grants. After expiry, cleanup
//! removes the ciphertext while retaining the nullifier indefinitely (or until a future safe,
//! fleet-coordinated issuer-epoch retirement).
//!
//! The durable record has no account, payment, source-IP, destination, or other identity. The
//! unblinded token message is nevertheless a persistent bearer identifier. Replay ciphertext is
//! bound by AES-256-GCM AAD to `(format version, epoch, canonical nullifier, replay_until)`, so rows
//! cannot be swapped. File backends are crash-safe and single-process; Postgres supplies the
//! cross-replica atomicity boundary.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use zeroize::Zeroizing;

const RECORD_VERSION: &str = "NR2";
const AAD_DOMAIN: &[u8] = b"nilvpn.redemption-result.v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Generous bound above the public path response cap. Applied before encryption/decryption and
/// before a file record is accepted, so corrupt storage cannot force an unbounded allocation.
pub const MAX_REPLAY_RESULT_BYTES: usize = 64 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = NONCE_LEN + MAX_REPLAY_RESULT_BYTES + TAG_LEN;
/// Historical pre-NTV2 rows could contain other even-length hex messages. They can no longer pass
/// redemption validation, but migration must preserve them rather than silently weaken spent state.
const MAX_STORED_NULLIFIER_HEX: usize = 16 * 1024;
const MAX_RECORD_LINE_BYTES: usize =
    4 + 1 + 10 + 1 + MAX_STORED_NULLIFIER_HEX + 1 + 20 + 1 + MAX_CIPHERTEXT_BYTES * 2 + 1;
const LEGACY_EPOCH: u32 = 0;

/// Result of the authoritative nullifier/result commit.
pub enum CommitOutcome {
    /// The first commit or a live retry. `response` is the exact first committed JSON bytes.
    Granted {
        response: Zeroizing<Vec<u8>>,
        newly_committed: bool,
    },
    /// The token is permanently spent, but has no live replay result (legacy, expired, or corrupt).
    AlreadySpent,
}

impl fmt::Debug for CommitOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted {
                response,
                newly_committed,
            } => f
                .debug_struct("Granted")
                .field(
                    "response",
                    &format_args!("[REDACTED; {} bytes]", response.len()),
                )
                .field("newly_committed", newly_committed)
                .finish(),
            Self::AlreadySpent => f.write_str("AlreadySpent"),
        }
    }
}

/// One atomic durability boundary for the permanent nullifier and temporary replay ciphertext.
#[async_trait]
pub trait NullifierStore: Send + Sync {
    /// Atomically spend `key` or return its first live result. `proposed_response` is persisted only
    /// when the key is absent. Existing legacy/expired rows never acquire a new result.
    async fn commit_or_replay(
        &self,
        epoch: u32,
        key: &str,
        replay_until: u64,
        proposed_response: &[u8],
        now: u64,
    ) -> io::Result<CommitOutcome>;

    /// Remove expired replay ciphertext while preserving every permanent spent marker atomically.
    /// Returns the number of ciphertexts removed.
    async fn prune_expired_replays(&self, now: u64) -> io::Result<usize>;

    /// Future maintenance primitive. `retained` must be backed by shared fleet-wide issuer-key
    /// retirement state and rollout grace; one replica's verifier list is never sufficient.
    #[allow(dead_code)]
    async fn drop_epochs(&self, _retained: &BTreeSet<u32>) -> io::Result<usize> {
        Ok(0)
    }

    fn supports_epoch_gc(&self) -> bool {
        false
    }

    async fn approx_len(&self) -> Option<usize> {
        None
    }
}

#[derive(Clone)]
struct ReplayCipher {
    key: Zeroizing<[u8; 32]>,
}

impl ReplayCipher {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    fn aad(epoch: u32, key: &str, replay_until: u64) -> Zeroizing<Vec<u8>> {
        let mut aad = Zeroizing::new(Vec::with_capacity(AAD_DOMAIN.len() + 4 + 8 + key.len()));
        aad.extend_from_slice(AAD_DOMAIN);
        aad.extend_from_slice(&epoch.to_be_bytes());
        aad.extend_from_slice(&replay_until.to_be_bytes());
        aad.extend_from_slice(key.as_bytes());
        aad
    }

    fn seal(
        &self,
        epoch: u32,
        key: &str,
        replay_until: u64,
        plaintext: &[u8],
    ) -> io::Result<Vec<u8>> {
        if plaintext.is_empty() || plaintext.len() > MAX_REPLAY_RESULT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "redemption replay result is empty or exceeds its fixed bound",
            ));
        }
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| io::Error::other("redemption replay nonce entropy unavailable"))?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| io::Error::other("invalid redemption replay key"))?;
        let aad = Self::aad(epoch, key, replay_until);
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| io::Error::other("encrypt redemption replay result"))?;
        let mut stored = Vec::with_capacity(NONCE_LEN + encrypted.len());
        stored.extend_from_slice(&nonce);
        stored.extend_from_slice(&encrypted);
        Ok(stored)
    }

    fn open(
        &self,
        epoch: u32,
        key: &str,
        replay_until: u64,
        stored: &[u8],
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        if !(NONCE_LEN + TAG_LEN..=MAX_CIPHERTEXT_BYTES).contains(&stored.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "redemption replay ciphertext has an invalid length",
            ));
        }
        let (nonce, ciphertext) = stored.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| io::Error::other("invalid redemption replay key"))?;
        let aad = Self::aad(epoch, key, replay_until);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "redemption replay ciphertext authentication failed",
                )
            })?;
        if plaintext.is_empty() || plaintext.len() > MAX_REPLAY_RESULT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "redemption replay plaintext has an invalid length",
            ));
        }
        Ok(Zeroizing::new(plaintext))
    }
}

#[derive(Clone)]
struct StoredRecord {
    epoch: u32,
    replay_until: Option<u64>,
    ciphertext: Option<Vec<u8>>,
}

impl StoredRecord {
    fn spent_only(epoch: u32) -> Self {
        Self {
            epoch,
            replay_until: None,
            ciphertext: None,
        }
    }

    fn live_ciphertext(&self, now: u64) -> Option<(u64, &[u8])> {
        match (self.replay_until, self.ciphertext.as_deref()) {
            (Some(until), Some(ciphertext)) if now < until => Some((until, ciphertext)),
            _ => None,
        }
    }
}

fn validate_commit(
    key: &str,
    replay_until: u64,
    proposed_response: &[u8],
    now: u64,
) -> io::Result<()> {
    if key.len() != 64
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nullifier must be exactly 32 bytes of canonical lowercase hex",
        ));
    }
    if replay_until <= now {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "redemption replay result is already expired",
        ));
    }
    if proposed_response.is_empty() || proposed_response.len() > MAX_REPLAY_RESULT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "redemption replay result is empty or exceeds its fixed bound",
        ));
    }
    Ok(())
}

fn live_outcome(
    cipher: &ReplayCipher,
    key: &str,
    record: &StoredRecord,
    now: u64,
    newly_committed: bool,
) -> Option<CommitOutcome> {
    let (until, ciphertext) = record.live_ciphertext(now)?;
    match cipher.open(record.epoch, key, until, ciphertext) {
        Ok(response) => Some(CommitOutcome::Granted {
            response,
            newly_committed,
        }),
        Err(error) => {
            tracing::warn!(reason = %error, "redemption replay ciphertext unavailable; preserving spent marker");
            Some(CommitOutcome::AlreadySpent)
        }
    }
}

/// Volatile development/test implementation. It still stores ciphertext rather than bearer
/// plaintext so behavior matches durable backends.
pub struct MemoryNullifierStore {
    records: Mutex<HashMap<String, StoredRecord>>,
    cipher: ReplayCipher,
    partitioned: bool,
}

impl MemoryNullifierStore {
    pub fn new(key: [u8; 32]) -> Self {
        Self::with_partitioning(key, false)
    }

    #[cfg(test)]
    pub(crate) fn epoch_partitioned(key: [u8; 32]) -> Self {
        Self::with_partitioning(key, true)
    }

    fn with_partitioning(key: [u8; 32], partitioned: bool) -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            cipher: ReplayCipher::new(key),
            partitioned,
        }
    }
}

#[async_trait]
impl NullifierStore for MemoryNullifierStore {
    async fn commit_or_replay(
        &self,
        epoch: u32,
        key: &str,
        replay_until: u64,
        proposed_response: &[u8],
        now: u64,
    ) -> io::Result<CommitOutcome> {
        validate_commit(key, replay_until, proposed_response, now)?;
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(existing) = records.get_mut(key) {
            if let Some(outcome) = live_outcome(&self.cipher, key, existing, now, false) {
                return Ok(outcome);
            }
            existing.replay_until = None;
            existing.ciphertext = None;
            return Ok(CommitOutcome::AlreadySpent);
        }
        let ciphertext = self
            .cipher
            .seal(epoch, key, replay_until, proposed_response)?;
        let record = StoredRecord {
            epoch,
            replay_until: Some(replay_until),
            ciphertext: Some(ciphertext),
        };
        records.insert(key.to_string(), record.clone());
        Ok(live_outcome(&self.cipher, key, &record, now, true)
            .expect("newly sealed replay result is live"))
    }

    async fn prune_expired_replays(&self, now: u64) -> io::Result<usize> {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut removed = 0;
        for record in records.values_mut() {
            if record.replay_until.is_some_and(|until| now >= until) {
                removed += usize::from(record.ciphertext.take().is_some());
                record.replay_until = None;
            }
        }
        Ok(removed)
    }

    async fn drop_epochs(&self, retained: &BTreeSet<u32>) -> io::Result<usize> {
        if !self.partitioned || retained.is_empty() {
            return Ok(0);
        }
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let before = records.len();
        records.retain(|_, record| retained.contains(&record.epoch));
        Ok(before - records.len())
    }

    fn supports_epoch_gc(&self) -> bool {
        self.partitioned
    }

    async fn approx_len(&self) -> Option<usize> {
        Some(
            self.records
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileMode {
    Flat,
    Epoch,
}

struct FileInner {
    records: HashMap<String, StoredRecord>,
    file: Option<File>,
}

/// Crash-safe single-process file backend. Each accepted append is one complete newline-terminated
/// record followed by flush+fsync. A failed append is rolled back to the last committed file
/// length, and startup removes a bounded non-newline-terminated final fragment, so a crash before
/// commit cannot create a half-record spent marker. Cleanup uses temp+fsync+rename and rewrites
/// expired entries as spent-only records.
pub struct FileNullifierStore {
    inner: Mutex<FileInner>,
    path: PathBuf,
    mode: FileMode,
    cipher: ReplayCipher,
    /// Held for the store lifetime so two Coordinator processes cannot race on one file ledger.
    _process_lock: File,
    /// Epoch migration also locks the legacy flat ledger so an older process cannot append after
    /// the one-shot fold-in.
    _legacy_process_lock: Option<File>,
}

impl FileNullifierStore {
    pub fn open_flat<P: AsRef<Path>>(path: P, key: [u8; 32], now: u64) -> io::Result<Self> {
        Self::open(path.as_ref(), None, FileMode::Flat, key, now)
    }

    pub fn open_epoch<P: AsRef<Path>>(
        path: P,
        legacy_path: Option<&Path>,
        key: [u8; 32],
        now: u64,
    ) -> io::Result<Self> {
        Self::open(path.as_ref(), legacy_path, FileMode::Epoch, key, now)
    }

    fn open(
        path: &Path,
        legacy_path: Option<&Path>,
        mode: FileMode,
        key: [u8; 32],
        now: u64,
    ) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let process_lock = acquire_process_lock(path)?;
        let legacy_process_lock = if mode == FileMode::Epoch {
            legacy_path
                .filter(|legacy_path| *legacy_path != path && legacy_path.exists())
                .map(acquire_process_lock)
                .transpose()?
        } else {
            None
        };
        truncate_unterminated_tail(path)?;
        let mut records = load_records(path, mode)?;
        let mut folded_legacy = false;
        if mode == FileMode::Epoch {
            if let Some(legacy_path) = legacy_path {
                if legacy_path != path && legacy_path.exists() {
                    for (key, record) in load_records(legacy_path, FileMode::Flat)? {
                        if let std::collections::hash_map::Entry::Vacant(entry) = records.entry(key)
                        {
                            entry.insert(record);
                            folded_legacy = true;
                        }
                    }
                }
            }
        }
        let file = open_private(path, true)?;
        // A first redemption may create the ledger and immediately crash. Persist the directory
        // entry before accepting any append so a successful file fsync cannot outlive its name.
        sync_parent_directory(path)?;
        let store = Self {
            inner: Mutex::new(FileInner {
                records,
                file: Some(file),
            }),
            path: path.to_path_buf(),
            mode,
            cipher: ReplayCipher::new(key),
            _process_lock: process_lock,
            _legacy_process_lock: legacy_process_lock,
        };
        let expired = store.prune_expired_sync(now)?;
        if folded_legacy && expired == 0 {
            let mut inner = store
                .inner
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let records = inner.records.clone();
            store.rewrite_locked(&mut inner, records)?;
        }
        if mode == FileMode::Epoch {
            if let Some(legacy_path) = legacy_path {
                if legacy_path != path && legacy_path.exists() {
                    let mut aside = legacy_path.as_os_str().to_owned();
                    aside.push(".migrated");
                    std::fs::rename(legacy_path, PathBuf::from(aside))?;
                }
            }
        }
        Ok(store)
    }

    fn prune_expired_sync(&self, now: u64) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let mut rewritten = inner.records.clone();
        let mut removed = 0;
        for record in rewritten.values_mut() {
            if record.replay_until.is_some_and(|until| now >= until) {
                removed += usize::from(record.ciphertext.take().is_some());
                record.replay_until = None;
            }
        }
        if removed > 0 {
            self.rewrite_locked(&mut inner, rewritten)?;
        }
        Ok(removed)
    }

    fn rewrite_locked(
        &self,
        inner: &mut FileInner,
        records: HashMap<String, StoredRecord>,
    ) -> io::Result<()> {
        let tmp = sidecar_path(&self.path, ".redemption-rewrite.tmp");
        let result = (|| -> io::Result<()> {
            {
                let mut file = open_private(&tmp, false)?;
                let mut ordered = records.iter().collect::<Vec<_>>();
                ordered.sort_unstable_by(|left, right| left.0.cmp(right.0));
                for (key, record) in ordered {
                    let line = encode_record(key, record)?;
                    file.write_all(&line)?;
                }
                file.flush()?;
                file.sync_all()?;
            }
            std::fs::rename(&tmp, &self.path)?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }
        // The rename has happened, so align the live handle/map with the new inode even if the
        // directory fsync reports an error. Both the old and new image preserve permanent spent
        // markers; reporting the fsync error merely keeps callers fail closed on uncertain media.
        inner.file = None;
        inner.records = records;
        inner.file = Some(open_private(&self.path, true)?);
        sync_parent_directory(&self.path)
    }
}

#[async_trait]
impl NullifierStore for FileNullifierStore {
    async fn commit_or_replay(
        &self,
        epoch: u32,
        key: &str,
        replay_until: u64,
        proposed_response: &[u8],
        now: u64,
    ) -> io::Result<CommitOutcome> {
        validate_commit(key, replay_until, proposed_response, now)?;
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(existing) = inner.records.get(key) {
            if let Some(outcome) = live_outcome(&self.cipher, key, existing, now, false) {
                return Ok(outcome);
            }
            if existing.ciphertext.is_some() {
                let mut rewritten = inner.records.clone();
                if let Some(record) = rewritten.get_mut(key) {
                    record.replay_until = None;
                    record.ciphertext = None;
                }
                self.rewrite_locked(&mut inner, rewritten)?;
            }
            return Ok(CommitOutcome::AlreadySpent);
        }

        let ciphertext = self
            .cipher
            .seal(epoch, key, replay_until, proposed_response)?;
        let record = StoredRecord {
            epoch,
            replay_until: Some(replay_until),
            ciphertext: Some(ciphertext),
        };
        let line = encode_record(key, &record)?;
        append_and_sync(&mut inner.file, &line)?;
        inner.records.insert(key.to_string(), record.clone());
        Ok(live_outcome(&self.cipher, key, &record, now, true)
            .expect("newly sealed replay result is live"))
    }

    async fn prune_expired_replays(&self, now: u64) -> io::Result<usize> {
        self.prune_expired_sync(now)
    }

    async fn drop_epochs(&self, retained: &BTreeSet<u32>) -> io::Result<usize> {
        if self.mode != FileMode::Epoch || retained.is_empty() {
            return Ok(0);
        }
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let mut rewritten = inner.records.clone();
        let before = rewritten.len();
        rewritten.retain(|_, record| retained.contains(&record.epoch));
        let removed = before - rewritten.len();
        if removed > 0 {
            self.rewrite_locked(&mut inner, rewritten)?;
        }
        Ok(removed)
    }

    fn supports_epoch_gc(&self) -> bool {
        self.mode == FileMode::Epoch
    }

    async fn approx_len(&self) -> Option<usize> {
        Some(
            self.inner
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .records
                .len(),
        )
    }
}

fn open_private(path: &Path, append: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true);
    if append {
        options.append(true);
    } else {
        options.write(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn append_and_sync(file_slot: &mut Option<File>, line: &[u8]) -> io::Result<()> {
    let mut file = file_slot
        .take()
        .ok_or_else(|| io::Error::other("redemption file store has no writable append handle"))?;
    let committed_len = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            *file_slot = Some(file);
            return Err(error);
        }
    };
    let append = (|| -> io::Result<()> {
        file.write_all(line)?;
        file.flush()?;
        file.sync_all()
    })();
    if let Err(append_error) = append {
        // `write_all` may have written a prefix before failing. Never let a later append join onto
        // that fragment and turn it into a malformed or false spent record. If rollback itself is
        // uncertain, return the combined error; the caller keeps the in-memory ledger unchanged.
        if let Err(rollback_error) = file.set_len(committed_len).and_then(|()| file.sync_all()) {
            // Keep the append handle poisoned: a later request must not append after storage whose
            // exact committed boundary is unknown. Existing in-memory replay records remain safe.
            return Err(io::Error::other(format!(
                "redemption append failed ({append_error}); rollback failed ({rollback_error})"
            )));
        }
        *file_slot = Some(file);
        return Err(append_error);
    }
    *file_slot = Some(file);
    Ok(())
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path.parent().filter(|path| !path.as_os_str().is_empty());
        File::open(parent.unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    }
    Ok(())
}

fn acquire_process_lock(path: &Path) -> io::Result<File> {
    // Append instead of replacing the extension: `ledger` and `ledger.epoch` are distinct stores
    // during one-shot migration and must never accidentally contend on the same sidecar.
    let lock_path = sidecar_path(path, ".redemption.lock");
    let file = open_private(&lock_path, true)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "redemption ledger {} is already open by another process; use Postgres for multiple Coordinator replicas",
                    path.display()
                ),
            ));
        }
    }
    Ok(file)
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn truncate_unterminated_tail(path: &Path) -> io::Result<()> {
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let length = file.metadata()?.len();
    if length == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)?;
    if byte[0] == b'\n' {
        return Ok(());
    }
    let mut position = length - 1;
    let mut scanned = 1usize;
    let truncate_at = loop {
        if position == 0 {
            break 0;
        }
        if scanned >= MAX_RECORD_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unterminated redemption record exceeds its fixed recovery bound",
            ));
        }
        position -= 1;
        file.seek(SeekFrom::Start(position))?;
        file.read_exact(&mut byte)?;
        scanned += 1;
        if byte[0] == b'\n' {
            break position + 1;
        }
    };
    file.set_len(truncate_at)?;
    file.sync_all()?;
    Ok(())
}

fn encode_record(key: &str, record: &StoredRecord) -> io::Result<Zeroizing<Vec<u8>>> {
    validate_stored_key(key)?;
    let (until, ciphertext) = match (record.replay_until, record.ciphertext.as_deref()) {
        (Some(until), Some(ciphertext)) => (until.to_string(), nil_core::grant::to_hex(ciphertext)),
        (None, None) => ("-".to_string(), "-".to_string()),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inconsistent redemption record",
            ))
        }
    };
    let line = format!(
        "{RECORD_VERSION} {} {key} {until} {ciphertext}\n",
        record.epoch
    );
    if line.len() > MAX_RECORD_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "redemption record exceeds its fixed bound",
        ));
    }
    Ok(Zeroizing::new(line.into_bytes()))
}

fn load_records(path: &Path, mode: FileMode) -> io::Result<HashMap<String, StoredRecord>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error),
    };
    let mut reader = BufReader::new(file);
    let mut records = HashMap::new();
    loop {
        let mut line = Vec::new();
        // `BufRead::read_until` otherwise allocates until an attacker-controlled newline. Limit
        // the read itself, not merely the parser that runs afterward.
        let read = (&mut reader)
            .take((MAX_RECORD_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_RECORD_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "redemption record line exceeds its fixed bound",
            ));
        }
        if line.last() != Some(&b'\n') {
            // A crash can leave only the final append fragment. It was never durably committed or
            // returned, so ignore it rather than creating an unreplayable spent marker.
            break;
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let text = std::str::from_utf8(&line).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "redemption record is not UTF-8")
        })?;
        let (key, record) = parse_record(text, mode)?;
        records.entry(key).or_insert(record);
    }
    Ok(records)
}

fn parse_record(line: &str, mode: FileMode) -> io::Result<(String, StoredRecord)> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.first() == Some(&RECORD_VERSION) {
        if fields.len() != 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed redemption record",
            ));
        }
        let epoch = fields[1]
            .parse::<u32>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid redemption epoch"))?;
        let key = fields[2];
        validate_stored_key(key)?;
        let record = if fields[3] == "-" && fields[4] == "-" {
            StoredRecord::spent_only(epoch)
        } else {
            let replay_until = fields[3]
                .parse::<u64>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid replay expiry"))?;
            if fields[4].len() > MAX_CIPHERTEXT_BYTES * 2
                || fields[4].len() % 2 != 0
                || !fields[4]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid replay ciphertext encoding",
                ));
            }
            let ciphertext = nil_core::grant::from_hex(fields[4]).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid replay ciphertext")
            })?;
            StoredRecord {
                epoch,
                replay_until: Some(replay_until),
                ciphertext: Some(ciphertext),
            }
        };
        return Ok((key.to_string(), record));
    }

    match fields.as_slice() {
        // Legacy flat file: one canonical nullifier per line.
        [key] => {
            validate_stored_key(key)?;
            Ok(((*key).to_string(), StoredRecord::spent_only(LEGACY_EPOCH)))
        }
        // Legacy epoch file: `<epoch> <key>`. Accept during flat migration too; over-retaining the
        // epoch tag is harmless and makes a rollback/misconfiguration fail closed.
        [epoch, key] => {
            let epoch = epoch.parse::<u32>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid legacy redemption epoch",
                )
            })?;
            validate_stored_key(key)?;
            Ok(((*key).to_string(), StoredRecord::spent_only(epoch)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            match mode {
                FileMode::Flat => "malformed flat nullifier record",
                FileMode::Epoch => "malformed epoch nullifier record",
            },
        )),
    }
}

fn validate_stored_key(key: &str) -> io::Result<()> {
    if !key.is_empty()
        && key.len() <= MAX_STORED_NULLIFIER_HEX
        && key.len() % 2 == 0
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stored nullifier is not canonical lowercase hex",
        ))
    }
}

/// Whether crossing `n` permanent spent entries should fire the one-time soft-size warning.
pub fn should_warn(n: usize, threshold: usize) -> bool {
    threshold != 0 && n == threshold
}

#[cfg(feature = "postgres")]
pub use pg::PgNullifierStore;

#[cfg(feature = "postgres")]
mod pg {
    use std::time::Duration;

    use super::*;
    use tokio_postgres::Client;

    pub const SCHEMA: &str = "\
        CREATE TABLE IF NOT EXISTS nullifiers (msg TEXT PRIMARY KEY, epoch BIGINT NOT NULL DEFAULT 0, replay_until BIGINT NULL, replay_blob BYTEA NULL); \
        ALTER TABLE nullifiers ADD COLUMN IF NOT EXISTS epoch BIGINT NOT NULL DEFAULT 0; \
        ALTER TABLE nullifiers ALTER COLUMN epoch TYPE BIGINT USING epoch::BIGINT; \
        ALTER TABLE nullifiers ADD COLUMN IF NOT EXISTS replay_until BIGINT NULL; \
        ALTER TABLE nullifiers ADD COLUMN IF NOT EXISTS replay_blob BYTEA NULL; \
        CREATE INDEX IF NOT EXISTS nullifiers_epoch_idx ON nullifiers (epoch); \
        CREATE INDEX IF NOT EXISTS nullifiers_replay_expiry_idx ON nullifiers (replay_until) WHERE replay_blob IS NOT NULL";

    /// A single row lock/UPSERT is the cross-replica authority. On conflict it returns the first
    /// live ciphertext unchanged; expired or legacy rows atomically clear replay fields but remain
    /// permanently spent.
    const COMMIT_SQL: &str = "\
        INSERT INTO nullifiers (msg, epoch, replay_until, replay_blob) VALUES ($1, $2, $3, $4) \
        ON CONFLICT (msg) DO UPDATE SET \
          replay_until = CASE WHEN nullifiers.replay_until > $5 THEN nullifiers.replay_until ELSE NULL END, \
          replay_blob = CASE WHEN nullifiers.replay_until > $5 THEN nullifiers.replay_blob ELSE NULL END \
        RETURNING epoch, replay_until, replay_blob";
    const PRUNE_SQL: &str = "\
        UPDATE nullifiers SET replay_until = NULL, replay_blob = NULL \
        WHERE replay_blob IS NOT NULL AND replay_until <= $1";
    const DROP_SQL: &str = "DELETE FROM nullifiers WHERE epoch <> ALL($1)";
    const DB_TIMEOUT: Duration = Duration::from_secs(2);

    pub(super) fn ensure_loopback_for_notls(conn_str: &str) -> io::Result<()> {
        let config: tokio_postgres::Config = conn_str.parse().map_err(|error| {
            io::Error::other(format!("invalid postgres connection string: {error}"))
        })?;
        for host in config.get_hosts() {
            if let tokio_postgres::config::Host::Tcp(host) = host {
                let loopback = host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .map(|ip| ip.is_loopback())
                        .unwrap_or(false);
                if !loopback {
                    return Err(io::Error::other(format!(
                        "refusing NoTls Postgres connection to non-loopback host {host:?}: use a TLS-connected client"
                    )));
                }
            }
        }
        Ok(())
    }

    pub struct PgNullifierStore {
        client: Client,
        cipher: ReplayCipher,
    }

    impl PgNullifierStore {
        /// Wrap an already TLS-connected production client.
        pub fn new(client: Client, key: [u8; 32]) -> Self {
            Self {
                client,
                cipher: ReplayCipher::new(key),
            }
        }

        /// Development/local connection helper. Refuses cleartext transport off loopback.
        pub async fn connect(conn_str: &str, key: [u8; 32]) -> io::Result<Self> {
            ensure_loopback_for_notls(conn_str)?;
            let (client, connection) = tokio_postgres::connect(conn_str, tokio_postgres::NoTls)
                .await
                .map_err(|error| io::Error::other(format!("postgres connect: {error}")))?;
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    tracing::error!("postgres connection closed: {error}");
                }
            });
            client
                .batch_execute(SCHEMA)
                .await
                .map_err(|error| io::Error::other(format!("postgres schema: {error}")))?;
            Ok(Self::new(client, key))
        }
    }

    #[async_trait]
    impl NullifierStore for PgNullifierStore {
        async fn commit_or_replay(
            &self,
            epoch: u32,
            key: &str,
            replay_until: u64,
            proposed_response: &[u8],
            now: u64,
        ) -> io::Result<CommitOutcome> {
            validate_commit(key, replay_until, proposed_response, now)?;
            let ciphertext = self
                .cipher
                .seal(epoch, key, replay_until, proposed_response)?;
            let epoch_i64 = i64::from(epoch);
            let replay_i64 = i64::try_from(replay_until).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "replay expiry exceeds Postgres BIGINT",
                )
            })?;
            let now_i64 = i64::try_from(now).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "current time exceeds Postgres BIGINT",
                )
            })?;
            let row = tokio::time::timeout(
                DB_TIMEOUT,
                self.client.query_one(
                    COMMIT_SQL,
                    &[&key, &epoch_i64, &replay_i64, &ciphertext, &now_i64],
                ),
            )
            .await
            .map_err(|_| io::Error::other("postgres redemption commit timed out"))?
            .map_err(|error| io::Error::other(format!("postgres redemption commit: {error}")))?;
            let stored_epoch: i64 = row.get(0);
            let stored_until: Option<i64> = row.get(1);
            let stored_ciphertext: Option<Vec<u8>> = row.get(2);
            let (Some(stored_until), Some(stored_ciphertext)) = (stored_until, stored_ciphertext)
            else {
                return Ok(CommitOutcome::AlreadySpent);
            };
            let stored_epoch = u32::try_from(stored_epoch).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stored redemption epoch is invalid",
                )
            })?;
            let stored_until = u64::try_from(stored_until).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stored replay expiry is invalid",
                )
            })?;
            if now >= stored_until {
                return Ok(CommitOutcome::AlreadySpent);
            }
            let newly_committed = stored_ciphertext == ciphertext;
            match self
                .cipher
                .open(stored_epoch, key, stored_until, &stored_ciphertext)
            {
                Ok(response) => Ok(CommitOutcome::Granted {
                    response,
                    newly_committed,
                }),
                Err(error) => {
                    tracing::warn!(reason = %error, "Postgres redemption replay ciphertext unavailable; preserving spent row");
                    Ok(CommitOutcome::AlreadySpent)
                }
            }
        }

        async fn prune_expired_replays(&self, now: u64) -> io::Result<usize> {
            let now = i64::try_from(now).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "current time exceeds Postgres BIGINT",
                )
            })?;
            let affected =
                tokio::time::timeout(DB_TIMEOUT, self.client.execute(PRUNE_SQL, &[&now]))
                    .await
                    .map_err(|_| io::Error::other("postgres replay cleanup timed out"))?
                    .map_err(|error| {
                        io::Error::other(format!("postgres replay cleanup: {error}"))
                    })?;
            Ok(affected as usize)
        }

        async fn drop_epochs(&self, retained: &BTreeSet<u32>) -> io::Result<usize> {
            if retained.is_empty() {
                return Ok(0);
            }
            let epochs = retained.iter().copied().map(i64::from).collect::<Vec<_>>();
            let affected =
                tokio::time::timeout(DB_TIMEOUT, self.client.execute(DROP_SQL, &[&epochs]))
                    .await
                    .map_err(|_| io::Error::other("postgres nullifier drop_epochs timed out"))?
                    .map_err(|error| {
                        io::Error::other(format!("postgres nullifier drop_epochs: {error}"))
                    })?;
            Ok(affected as usize)
        }

        fn supports_epoch_gc(&self) -> bool {
            true
        }
    }

    #[cfg(test)]
    mod schema_audit {
        use super::{COMMIT_SQL, SCHEMA};

        const DOCUMENTED_COLUMNS: &[&str] = &["msg", "epoch", "replay_until", "replay_blob"];
        const PII_TOKENS: &[&str] = &[
            "email",
            "ip",
            "name",
            "phone",
            "addr",
            "user_id",
            "account_id",
            "payment",
            "session",
            "identity",
            "device",
        ];

        fn schema_columns(ddl: &str, table: &str) -> Vec<String> {
            fn push(columns: &mut Vec<String>, value: &str) {
                let value = value.to_ascii_lowercase();
                if !columns.contains(&value) {
                    columns.push(value);
                }
            }
            let uppercase = ddl.to_ascii_uppercase();
            let table = table.to_ascii_uppercase();
            let mut columns = Vec::new();
            for statement in uppercase.split(';') {
                let statement = statement.trim();
                if let Some(rest) = statement.strip_prefix("CREATE TABLE") {
                    let Some(open) = rest.find('(') else { continue };
                    if !rest[..open].contains(&table) {
                        continue;
                    }
                    let close = rest.rfind(')').unwrap_or(rest.len());
                    for definition in rest[open + 1..close].split(',') {
                        if let Some(column) = definition.split_whitespace().next() {
                            if !matches!(column, "CONSTRAINT" | "PRIMARY" | "UNIQUE" | "CHECK") {
                                push(&mut columns, column);
                            }
                        }
                    }
                } else if let Some(rest) = statement.strip_prefix("ALTER TABLE") {
                    let rest = rest.trim();
                    if rest.split_whitespace().next() != Some(table.as_str()) {
                        continue;
                    }
                    for addition in rest.split(" ADD ").skip(1) {
                        let mut tokens = addition.split_whitespace();
                        let mut column = tokens.next();
                        if column == Some("COLUMN") {
                            column = tokens.next();
                        }
                        if column == Some("IF") {
                            let _ = tokens.next();
                            let _ = tokens.next();
                            column = tokens.next();
                        }
                        if let Some(column) = column {
                            push(&mut columns, column);
                        }
                    }
                }
            }
            columns
        }

        #[test]
        fn schema_has_exactly_documented_anonymous_columns() {
            assert_eq!(schema_columns(SCHEMA, "nullifiers"), DOCUMENTED_COLUMNS);
            for column in schema_columns(SCHEMA, "nullifiers") {
                for token in PII_TOKENS {
                    assert!(!column.contains(token), "PII-like schema column {column:?}");
                }
            }
        }

        #[test]
        fn upsert_is_one_cross_replica_authority() {
            let normalized = COMMIT_SQL.to_ascii_uppercase();
            assert!(normalized.contains("ON CONFLICT (MSG) DO UPDATE"));
            assert!(normalized.contains("RETURNING EPOCH, REPLAY_UNTIL, REPLAY_BLOB"));
            assert!(!normalized.contains("DO NOTHING"));
        }
    }

    #[cfg(test)]
    mod live_integration {
        use super::*;

        /// Set `NW_TEST_POSTGRES_URL` to a disposable loopback database to exercise the real row
        /// lock across two independent clients. CI without Postgres still runs the SQL/schema
        /// audits above rather than silently substituting an in-memory mock.
        #[tokio::test]
        async fn two_clients_observe_one_cross_replica_result_when_database_is_available() {
            let Ok(url) = std::env::var("NW_TEST_POSTGRES_URL") else {
                return;
            };
            let key = [0x61; 32];
            let left = PgNullifierStore::connect(&url, key).await.unwrap();
            let right = PgNullifierStore::connect(&url, key).await.unwrap();
            let mut token = [0u8; 32];
            getrandom::getrandom(&mut token).unwrap();
            let token = nil_core::grant::to_hex(&token);

            let (left_result, right_result) = tokio::join!(
                left.commit_or_replay(11, &token, 500, b"left", 100),
                right.commit_or_replay(11, &token, 500, b"right", 100),
            );
            let outcomes = [left_result.unwrap(), right_result.unwrap()];
            let mut values = Vec::new();
            let mut new_count = 0;
            for outcome in outcomes {
                match outcome {
                    CommitOutcome::Granted {
                        response,
                        newly_committed,
                    } => {
                        values.push(response.to_vec());
                        new_count += usize::from(newly_committed);
                    }
                    CommitOutcome::AlreadySpent => panic!("live result must be replayable"),
                }
            }
            assert_eq!(values[0], values[1]);
            assert_eq!(new_count, 1);
            left.client
                .execute("DELETE FROM nullifiers WHERE msg = $1", &[&token])
                .await
                .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    const KEY: [u8; 32] = [0x42; 32];
    const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn granted(outcome: CommitOutcome) -> (Vec<u8>, bool) {
        match outcome {
            CommitOutcome::Granted {
                response,
                newly_committed,
            } => (response.to_vec(), newly_committed),
            CommitOutcome::AlreadySpent => panic!("expected live replay result"),
        }
    }

    #[tokio::test]
    async fn memory_commit_replays_exact_first_result_and_expires_permanently() {
        let store = MemoryNullifierStore::new(KEY);
        let first = granted(
            store
                .commit_or_replay(7, TOKEN, 200, br#"{"winner":1}"#, 100)
                .await
                .unwrap(),
        );
        let replay = granted(
            store
                .commit_or_replay(7, TOKEN, 220, br#"{"loser":2}"#, 101)
                .await
                .unwrap(),
        );
        assert_eq!(first, (br#"{"winner":1}"#.to_vec(), true));
        assert_eq!(replay, (br#"{"winner":1}"#.to_vec(), false));
        assert!(matches!(
            store
                .commit_or_replay(7, TOKEN, 300, b"replacement", 200)
                .await
                .unwrap(),
            CommitOutcome::AlreadySpent
        ));
        assert_eq!(store.approx_len().await, Some(1));
    }

    #[tokio::test]
    async fn concurrent_memory_commit_has_one_replayable_winner() {
        let store = Arc::new(MemoryNullifierStore::new(KEY));
        let left = store.clone();
        let right = store.clone();
        let (left, right) = tokio::join!(
            async move {
                left.commit_or_replay(9, TOKEN, 500, b"left", 100)
                    .await
                    .unwrap()
            },
            async move {
                right
                    .commit_or_replay(9, TOKEN, 500, b"right", 100)
                    .await
                    .unwrap()
            }
        );
        let (left_value, left_new) = granted(left);
        let (right_value, right_new) = granted(right);
        assert_eq!(left_value, right_value);
        assert_ne!(left_new, right_new);
    }

    #[tokio::test]
    async fn file_restart_replays_then_compacts_ciphertext_but_keeps_spent_marker() {
        let path = std::env::temp_dir().join(format!(
            "nil-redemption-ledger-{}-{}",
            std::process::id(),
            nil_core::grant::now_unix_secs()
        ));
        let response = br#"{"hops":[{"grant":"bearer-secret"}]}"#;
        {
            let store = FileNullifierStore::open_flat(&path, KEY, 100).unwrap();
            let (committed, new) = granted(
                store
                    .commit_or_replay(3, TOKEN, 200, response, 100)
                    .await
                    .unwrap(),
            );
            assert_eq!(committed, response);
            assert!(new);
        }
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw
            .windows(b"bearer-secret".len())
            .any(|w| w == b"bearer-secret"));
        {
            let store = FileNullifierStore::open_flat(&path, KEY, 150).unwrap();
            let (replayed, new) = granted(
                store
                    .commit_or_replay(3, TOKEN, 220, b"different", 150)
                    .await
                    .unwrap(),
            );
            assert_eq!(replayed, response);
            assert!(!new);
        }
        {
            let store = FileNullifierStore::open_flat(&path, KEY, 200).unwrap();
            assert!(matches!(
                store
                    .commit_or_replay(3, TOKEN, 300, b"replacement", 200)
                    .await
                    .unwrap(),
                CommitOutcome::AlreadySpent
            ));
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(TOKEN));
        assert!(text.contains(" - -\n"));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn legacy_rows_are_permanently_spent_without_a_replay_result() {
        let path = std::env::temp_dir().join(format!(
            "nil-redemption-legacy-{}-{}",
            std::process::id(),
            nil_core::grant::now_unix_secs()
        ));
        std::fs::write(&path, format!("{TOKEN}\naabb\n")).unwrap();
        let store = FileNullifierStore::open_flat(&path, KEY, 100).unwrap();
        assert!(matches!(
            store
                .commit_or_replay(4, TOKEN, 200, b"new", 100)
                .await
                .unwrap(),
            CommitOutcome::AlreadySpent
        ));
        assert_eq!(store.approx_len().await, Some(2));
        assert_eq!(store.prune_expired_replays(u64::MAX).await.unwrap(), 0);
        drop(store);
        let reopened = FileNullifierStore::open_flat(&path, KEY, 100).unwrap();
        assert_eq!(
            reopened.approx_len().await,
            Some(2),
            "historical non-32-byte rows remain fail-closed during migration"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn wrong_restart_key_fails_closed_without_replacing_the_spent_result() {
        let path = std::env::temp_dir().join(format!(
            "nil-redemption-wrong-key-{}-{}",
            std::process::id(),
            nil_core::grant::now_unix_secs()
        ));
        {
            let store = FileNullifierStore::open_flat(&path, KEY, 100).unwrap();
            let _ = store
                .commit_or_replay(5, TOKEN, 200, b"first", 100)
                .await
                .unwrap();
        }
        let store = FileNullifierStore::open_flat(&path, [0x99; 32], 101).unwrap();
        assert!(matches!(
            store
                .commit_or_replay(5, TOKEN, 220, b"replacement", 101)
                .await
                .unwrap(),
            CommitOutcome::AlreadySpent
        ));
        assert_eq!(store.approx_len().await, Some(1));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(sidecar_path(&path, ".redemption.lock"));
    }

    #[tokio::test]
    async fn crash_torn_final_append_is_removed_before_a_retry_commits() {
        let path = std::env::temp_dir().join(format!(
            "nil-redemption-torn-{}-{}",
            std::process::id(),
            nil_core::grant::now_unix_secs()
        ));
        std::fs::write(&path, format!("{RECORD_VERSION} 1 {TOKEN} 200 001122")).unwrap();
        {
            let store = FileNullifierStore::open_flat(&path, KEY, 100).unwrap();
            let (response, newly) = granted(
                store
                    .commit_or_replay(1, TOKEN, 200, b"retry-wins", 100)
                    .await
                    .unwrap(),
            );
            assert_eq!(response, b"retry-wins");
            assert!(newly);
        }
        let store = FileNullifierStore::open_flat(&path, KEY, 101).unwrap();
        let (response, newly) = granted(
            store
                .commit_or_replay(1, TOKEN, 200, b"other", 101)
                .await
                .unwrap(),
        );
        assert_eq!(response, b"retry-wins");
        assert!(!newly);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(sidecar_path(&path, ".redemption.lock"));
    }

    #[test]
    fn oversized_unterminated_tail_is_rejected_after_a_bounded_scan() {
        let path = std::env::temp_dir().join(format!(
            "nil-redemption-oversized-tail-{}-{}",
            std::process::id(),
            nil_core::grant::now_unix_secs()
        ));
        std::fs::write(&path, vec![b'x'; MAX_RECORD_LINE_BYTES + 1]).unwrap();
        let error = FileNullifierStore::open_flat(&path, KEY, 100)
            .err()
            .expect("oversized recovery tail must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(sidecar_path(&path, ".redemption.lock"));
    }

    #[test]
    fn oversized_complete_record_is_rejected_by_the_bounded_reader() {
        let path = std::env::temp_dir().join(format!(
            "nil-redemption-oversized-line-{}-{}",
            std::process::id(),
            nil_core::grant::now_unix_secs()
        ));
        let mut line = vec![b'x'; MAX_RECORD_LINE_BYTES];
        line.push(b'\n');
        std::fs::write(&path, line).unwrap();
        let error = FileNullifierStore::open_flat(&path, KEY, 100)
            .err()
            .expect("oversized record must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(sidecar_path(&path, ".redemption.lock"));
    }

    #[tokio::test]
    async fn epoch_file_folds_legacy_and_drops_only_explicitly_retired_epochs() {
        let legacy = std::env::temp_dir().join(format!(
            "nil-redemption-flat-{}-{}",
            std::process::id(),
            nil_core::grant::now_unix_secs()
        ));
        let epoch = legacy.with_extension("epoch");
        let other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        std::fs::write(&legacy, format!("{TOKEN}\n")).unwrap();
        let store = FileNullifierStore::open_epoch(&epoch, Some(&legacy), KEY, 100).unwrap();
        let _ = store
            .commit_or_replay(8, other, 200, b"result", 100)
            .await
            .unwrap();
        assert_eq!(store.approx_len().await, Some(2));
        assert_eq!(store.drop_epochs(&BTreeSet::from([8])).await.unwrap(), 1);
        assert_eq!(store.approx_len().await, Some(1));
        let _ = std::fs::remove_file(&epoch);
        let _ = std::fs::remove_file(sidecar_path(&legacy, ".migrated"));
        let _ = std::fs::remove_file(sidecar_path(&legacy, ".redemption.lock"));
        let _ = std::fs::remove_file(sidecar_path(&epoch, ".redemption.lock"));
    }

    #[tokio::test]
    async fn write_failure_does_not_create_an_in_memory_spent_marker() {
        let path = std::env::temp_dir().join(format!(
            "nil-redemption-fault-{}-{}",
            std::process::id(),
            nil_core::grant::now_unix_secs()
        ));
        let store = FileNullifierStore::open_flat(&path, KEY, 100).unwrap();
        store
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .file = None;
        assert!(store
            .commit_or_replay(1, TOKEN, 200, b"result", 100)
            .await
            .is_err());
        assert_eq!(store.approx_len().await, Some(0));
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn file_backend_refuses_a_second_process_writer() {
        let path = std::env::temp_dir().join(format!(
            "nil-redemption-lock-{}-{}",
            std::process::id(),
            nil_core::grant::now_unix_secs()
        ));
        let first = FileNullifierStore::open_flat(&path, KEY, 100).unwrap();
        let error = FileNullifierStore::open_flat(&path, KEY, 100)
            .err()
            .expect("second writer must fail");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(first);
        FileNullifierStore::open_flat(&path, KEY, 100)
            .expect("lock releases when the first store closes");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(sidecar_path(&path, ".redemption.lock"));
    }

    #[tokio::test]
    async fn aad_prevents_ciphertext_swapping() {
        let cipher = ReplayCipher::new(KEY);
        let ciphertext = cipher.seal(1, TOKEN, 200, b"result").unwrap();
        assert!(cipher.open(2, TOKEN, 200, &ciphertext).is_err());
        assert!(cipher
            .open(
                1,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                200,
                &ciphertext
            )
            .is_err());
        assert!(cipher.open(1, TOKEN, 201, &ciphertext).is_err());
    }

    #[test]
    fn should_warn_fires_only_on_the_exact_crossing() {
        assert!(!should_warn(9, 10));
        assert!(should_warn(10, 10));
        assert!(!should_warn(11, 10));
        assert!(!should_warn(0, 0));
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn notls_connect_refuses_non_loopback() {
        use super::pg::ensure_loopback_for_notls;
        assert!(ensure_loopback_for_notls("postgres://u@127.0.0.1:5432/db").is_ok());
        assert!(ensure_loopback_for_notls("postgres://u@localhost/db").is_ok());
        assert!(ensure_loopback_for_notls("postgres://u@10.0.0.5/db").is_err());
    }
}
