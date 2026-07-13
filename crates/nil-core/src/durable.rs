//! A durable, append-only set of opaque keys — restart-safe single-use enforcement.
//!
//! The Coordinator's spent-token nullifier set (architecture spec §7/§8) and the Portal's
//! one-token-per-payment set MUST survive a process restart: if they live only in memory, a
//! restart silently re-permits a **double-spend** of every already-redeemed Privacy Pass token
//! (and a double-issue of every paid token). [`DurableSet`] is that storage — an in-memory set
//! mirrored to an append-only file, where each insert is flushed and `fsync`'d *before* it is
//! reported as accepted, so a crash can never lose an already-accepted key.
//!
//! **PII-free by contract.** Callers may store ONLY non-identifying values — token messages,
//! payment ids, hashes. The set must never hold an account number, email, or IP. This keeps the
//! "empty by design" posture (a full disk compromise yields a list of opaque keys without account
//! identifiers; timing or external records can still create correlation).
//!
//! The dev/test [`DurableSet::in_memory`] variant carries no file and is **not** durable; the
//! binaries log a warning when they fall back to it.
//!
//! **One live writer instance per path.** A mutex serializes threads sharing that instance; these
//! flat-file primitives do not coordinate a second instance or take an inter-process lock. Another
//! writer can race deduplication or compaction and invalidate the guarantee. Clustered deployments
//! must use their shared database store (or an external exclusive lock), never point multiple
//! replicas at the same file.
//!
//! **Lock poisoning is recovered, not propagated.** Every `Mutex::lock()` below uses
//! `unwrap_or_else(|e| e.into_inner())`. No code path holds these locks across an unwinding panic
//! (I/O goes through `?`, and the collections abort rather than unwind on allocation failure), so a
//! poisoned lock is effectively unreachable here. Recovering it anyway keeps the single-use guard
//! functioning instead of turning one stray panic into a cascade of panics on a spend-critical path,
//! and keeps this module free of `expect()`/`unwrap()` on the lock. Recovery is safe: the protected
//! set is only ever mutated *after* the durable write, so its in-memory contents are consistent.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Open `path` creating it owner-only (`0600`) on Unix. These files hold sensitive tokens — the
/// Coordinator's spent-token nullifier messages and the Portal's payment references — which must not
/// be world-readable: a local user could otherwise read them and enumerate redemption/checkout
/// activity (PD-2). `append` selects append-vs-truncate. On non-Unix the OS default applies (Windows
/// ACLs are inherited; the sensitive deployments are Linux nodes/Portal).
fn open_private<P: AsRef<Path>>(path: P, append: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true);
    if append {
        opts.append(true);
    } else {
        opts.write(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Open an existing durable log for both strict startup reads and later append-only writes. This
/// deliberately does not create the file: callers use [`open_or_create_private_append`] for the
/// one startup point where `NotFound` is allowed to mean an empty store, and compaction uses this
/// stricter form so a replacement that vanished cannot silently be recreated empty.
fn open_private_append_existing(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).append(true);
    opts.open(path)
}

/// Open an authoritative durable log, creating it owner-only only when the existing-file open
/// returns `NotFound`. Every other error is propagated instead of being mistaken for an empty
/// store. `create_new` closes the race where two starters both observe `NotFound`.
fn open_or_create_private_append(path: &Path) -> io::Result<(File, bool)> {
    match open_private_append_existing(path) {
        Ok(file) => Ok((file, false)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut opts = OpenOptions::new();
            opts.read(true).append(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(path) {
                Ok(file) => Ok((file, true)),
                // Another process may have won the create race. It is safe to open that exact
                // file, but a second `NotFound` (for example, a concurrent delete) is an error.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    open_private_append_existing(path).map(|file| (file, false))
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

/// The directory whose metadata contains `path`. Rust represents the parent of a bare relative
/// filename as an empty path; opening that fails, so normalize it to the current directory.
///
/// Only reached by the Unix directory-sync path below (and its unit test); gated so non-Unix
/// release builds do not reject it as dead code under `-D warnings`.
#[cfg(any(unix, test))]
fn durable_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Persist a create/rename directory entry. File `fsync` alone does not guarantee that the name
/// still resolves to that inode after a crash. Durable deployments are Unix; other targets lack a
/// portable standard-library directory-sync primitive and retain their platform's default.
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(durable_parent(path))?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Read only newline-terminated records from an already-open authoritative log. An unterminated
/// final record is indistinguishable from a torn append, and silently skipping a malformed record
/// can forget an accepted single-use key, so both conditions fail startup closed.
fn read_complete_records(file: &File, path: &Path) -> io::Result<Vec<String>> {
    let mut contents = String::new();
    BufReader::new(file.try_clone()?).read_to_string(&mut contents)?;
    if contents.is_empty() {
        return Ok(Vec::new());
    }
    if !contents.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("durable log {} has a torn final record", path.display()),
        ));
    }
    contents.pop();
    Ok(contents.split('\n').map(ToOwned::to_owned).collect())
}

fn invalid_record(path: &Path, line: usize, reason: &str) -> io::Error {
    // Never include the record itself: durable keys are intentionally opaque and may still be
    // sensitive operational data.
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "malformed durable log {} record {line}: {reason}",
            path.display()
        ),
    )
}

/// Append one complete record and make it durable. The record is submitted as one buffer so a
/// failed write cannot leave `key` followed by a later successful retry glued into one line. On
/// *any* write/flush/fsync error, close and clear the handle: its file may contain an uncertain
/// prefix, and no later call may report memory-only success or append behind that prefix.
fn append_record(file: &mut Option<File>, record: &[u8]) -> io::Result<()> {
    let result = match file.as_mut() {
        Some(file) => file
            .write_all(record)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all()),
        None => Err(io::Error::other(
            "durable store has no writable file handle",
        )),
    };
    if result.is_err() {
        *file = None;
    }
    result
}

struct Inner {
    seen: HashSet<String>,
    /// Append target. `None` means either an intentionally volatile set (`path == None`) or a
    /// fail-closed file-backed set whose handle became uncertain (`path != None`).
    file: Option<File>,
}

/// A set of opaque keys backed (optionally) by an append-only file. Cheap to clone behind an
/// `Arc`; all methods take `&self`.
pub struct DurableSet {
    inner: Mutex<Inner>,
    path: Option<PathBuf>,
}

impl DurableSet {
    /// A volatile, memory-only set (dev/tests). NOT durable across restarts.
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(Inner {
                seen: HashSet::new(),
                file: None,
            }),
            path: None,
        }
    }

    /// Open (creating if needed) a file-backed durable set, loading any keys already on disk.
    /// Only `NotFound` creates an empty store. Read errors, empty records, invalid UTF-8, and a torn
    /// final record fail startup closed: guessing at damaged single-use state could forget an
    /// accepted key and reopen a replay.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let (file, created) = open_or_create_private_append(&path)?;
        let mut seen = HashSet::new();
        for (index, key) in read_complete_records(&file, &path)?.into_iter().enumerate() {
            if key.is_empty() {
                return Err(invalid_record(&path, index + 1, "key is empty"));
            }
            // Do not trim: leading/trailing whitespace is valid opaque-key material and was
            // accepted by `insert`; changing it on reload would lose an accepted key.
            seen.insert(key);
        }
        if created {
            file.sync_all()?;
        }
        // Required even for a just-created relative path: an accepted append is not restart-safe
        // if a crash can lose the directory entry that names its inode.
        sync_parent_dir(&path)?;
        Ok(Self {
            inner: Mutex::new(Inner {
                seen,
                file: Some(file),
            }),
            path: Some(path),
        })
    }

    /// Record `key` as used. `Ok(true)` ⇒ newly inserted (the caller may proceed); `Ok(false)`
    /// ⇒ already present (reject as a double-spend/double-issue). `Err` ⇒ it could NOT be
    /// durably recorded — the caller MUST **fail closed** (treat as not accepted, grant nothing),
    /// because a key reported accepted but not persisted would re-open the double-spend window
    /// on the next restart.
    ///
    /// The on-disk write happens *before* the in-memory insert and while holding the lock, so a
    /// failed write leaves the set unchanged and reports the key as not-yet-accepted.
    pub fn insert(&self, key: &str) -> io::Result<bool> {
        if key.is_empty() || key.contains('\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable key must be non-empty and must not contain a newline (the on-disk format is line-delimited)",
            ));
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.seen.contains(key) {
            return Ok(false);
        }
        if self.path.is_some() {
            let mut record = Vec::with_capacity(key.len() + 1);
            record.extend_from_slice(key.as_bytes());
            record.push(b'\n');
            append_record(&mut inner.file, &record)?;
        }
        inner.seen.insert(key.to_string());
        Ok(true)
    }

    /// Whether `key` has been recorded.
    pub fn contains(&self, key: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .seen
            .contains(key)
    }

    /// Number of recorded keys.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .seen
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this set is durable (file-backed) vs volatile (memory-only).
    pub fn is_durable(&self) -> bool {
        self.path.is_some()
    }
}

/// Reserved epoch for migrated legacy nullifiers (bare-key lines from the old single-file format).
/// MUST match `nil_crypto::LEGACY_EPOCH` — key-derived epochs there are forced `>= 1`, so 0 never
/// collides with a real key's partition. (nil-core does not depend on nil-crypto, hence the mirror.)
pub const LEGACY_EPOCH: u32 = 0;

struct EpochInner {
    /// key (opaque token message) → the epoch its token was verified under. Dedup is by key (a
    /// token message is globally unique random bytes); the epoch is retained so a whole epoch's
    /// partition can be dropped at once.
    seen: HashMap<String, u32>,
    file: Option<File>,
    #[cfg(test)]
    fail_next_compaction_parent_sync: bool,
    #[cfg(test)]
    fail_next_compaction_reopen: bool,
}

/// A durable set PARTITIONED BY EPOCH, for the Coordinator's spent-token nullifiers. Each recorded
/// key carries the issuer epoch (key generation) whose key verified its token; a whole epoch's
/// partition can be dropped at once via [`Self::drop_epochs`]. That eviction is SAFE only because a
/// token whose epoch key is retired no longer verifies, so its nullifier can never be re-inserted —
/// see `nil-coordinator::nullifier` for the single-use invariant and its proof. This is what turns
/// the unbounded-by-design set into a bounded-by-epoch one WITHOUT reopening a double-spend.
///
/// On-disk format: one `"<epoch> <key>"` line per entry (append-only). [`Self::drop_epochs`]
/// compacts the file by atomically rewriting it (temp + fsync + rename) with only the retained
/// partitions, so the drop is durable across a restart. PII-free by contract, like [`DurableSet`].
pub struct EpochDurableSet {
    inner: Mutex<EpochInner>,
    path: Option<PathBuf>,
}

impl EpochDurableSet {
    /// A volatile, memory-only epoch set (dev/tests). NOT durable across restarts.
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(EpochInner {
                seen: HashMap::new(),
                file: None,
                #[cfg(test)]
                fail_next_compaction_parent_sync: false,
                #[cfg(test)]
                fail_next_compaction_reopen: false,
            }),
            path: None,
        }
    }

    /// Open a file-backed epoch-partitioned set, loading existing `"<epoch> <key>"` lines.
    ///
    /// A `legacy_path` (the old single-file `NW_NULLIFIER_PATH`, bare `"<key>"` lines) is migrated
    /// as a ONE-SHOT FOLD-IN: any legacy key not already present is appended to the epoch file under
    /// [`LEGACY_EPOCH`] (and fsync'd), then the legacy file is renamed aside so it is never
    /// re-seeded on a later boot. The fold-in is idempotent — if the rename fails, the next boot
    /// re-reads it and the already-present keys dedup. (`LEGACY_EPOCH` is the reserved partition the
    /// Coordinator always retains, so migrated nullifiers are never GC'd out from under a
    /// still-held legacy key.)
    pub fn open<P: AsRef<Path>>(path: P, legacy_path: Option<&Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Load the epoch-tagged file FIRST (authoritative). Only a genuinely missing file starts
        // empty; malformed/torn state fails startup closed rather than forgetting a spent key.
        let (mut file, created) = open_or_create_private_append(&path)?;
        let mut seen: HashMap<String, u32> = HashMap::new();
        for (index, line) in read_complete_records(&file, &path)?.into_iter().enumerate() {
            let (epoch_text, key) = line
                .split_once(' ')
                .ok_or_else(|| invalid_record(&path, index + 1, "missing epoch separator"))?;
            if key.is_empty() || key.contains(' ') {
                return Err(invalid_record(
                    &path,
                    index + 1,
                    "key is empty or contains a space",
                ));
            }
            let epoch = epoch_text
                .parse::<u32>()
                .map_err(|_| invalid_record(&path, index + 1, "epoch is not a u32"))?;
            if let Some(previous) = seen.insert(key.to_string(), epoch) {
                if previous != epoch {
                    return Err(invalid_record(
                        &path,
                        index + 1,
                        "key appears under conflicting epochs",
                    ));
                }
            }
        }
        if created {
            file.sync_all()?;
        }
        sync_parent_dir(&path)?;
        // One-shot legacy fold-in (durable), then remove the legacy file.
        if let Some(lp) = legacy_path {
            let legacy = match File::open(lp) {
                Ok(file) => Some(file),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
            if let Some(legacy) = legacy {
                let mut folded = 0usize;
                for (index, key) in read_complete_records(&legacy, lp)?.into_iter().enumerate() {
                    if key.is_empty() || key.contains(' ') {
                        return Err(invalid_record(
                            lp,
                            index + 1,
                            "legacy key is empty or cannot be represented in the epoch format",
                        ));
                    }
                    if seen.contains_key(&key) {
                        continue;
                    }
                    file.write_all(format!("{LEGACY_EPOCH} {key}\n").as_bytes())?;
                    seen.insert(key, LEGACY_EPOCH);
                    folded += 1;
                }
                if folded > 0 {
                    file.flush()?;
                    file.sync_all()?;
                }
                // Rename the legacy file ASIDE (to `<name>.migrated`) rather than DELETE it: this
                // stops it being re-folded on a later boot, but preserves the pre-migration data (a
                // delete would lose it on an accidental revert). Best-effort is intentional here:
                // the fold-in above is fsync'd, so losing/failing this rename only causes safe
                // over-retention and an idempotent re-fold on the next boot. Migration is one-way:
                // post-migration spends live only in the epoch file, so the aside is recovery data
                // for the pre-migration set, not a store to which an old binary may safely revert.
                let mut aside = lp.as_os_str().to_owned();
                aside.push(".migrated");
                let _ = std::fs::rename(lp, std::path::PathBuf::from(aside));
            }
        }
        Ok(Self {
            inner: Mutex::new(EpochInner {
                seen,
                file: Some(file),
                #[cfg(test)]
                fail_next_compaction_parent_sync: false,
                #[cfg(test)]
                fail_next_compaction_reopen: false,
            }),
            path: Some(path),
        })
    }

    /// Record `key` as spent under `epoch`. `Ok(true)` ⇒ newly recorded; `Ok(false)` ⇒ already
    /// present (double-spend); `Err` ⇒ not durably recorded → caller MUST fail closed. The fsync
    /// happens before the in-memory insert, exactly like [`DurableSet::insert`].
    pub fn insert_in_epoch(&self, epoch: u32, key: &str) -> io::Result<bool> {
        if key.is_empty() || key.contains('\n') || key.contains(' ') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "epoch-durable key must be non-empty and must not contain a space or newline (on-disk format is `<epoch> <key>`)",
            ));
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.seen.contains_key(key) {
            return Ok(false);
        }
        if self.path.is_some() {
            let record = format!("{epoch} {key}\n");
            append_record(&mut inner.file, record.as_bytes())?;
        }
        inner.seen.insert(key.to_string(), epoch);
        Ok(true)
    }

    /// Whether `key` has been recorded (in any epoch).
    pub fn contains(&self, key: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .seen
            .contains_key(key)
    }

    /// Total recorded keys across all partitions.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .seen
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every partition whose epoch is NOT in `retained`, returning the number of entries
    /// removed. The file is rewritten atomically (temp + fsync + rename), so the drop survives a
    /// restart. **SAFETY:** `retained` MUST be a superset of epochs accepted by every live verifier
    /// replica, established through shared retirement state and rollout grace. One process's local
    /// key list is not sufficient during a rolling deployment; dropping a still-accepted partition
    /// would reopen a double-spend.
    pub fn drop_epochs(&self, retained: &BTreeSet<u32>) -> io::Result<usize> {
        if retained.is_empty() {
            // Defensive: an empty retained set would wipe every partition. Refuse to nuke the set
            // even if a future fleet-retirement caller is misconfigured.
            return Ok(0);
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let to_drop = inner
            .seen
            .values()
            .filter(|e| !retained.contains(e))
            .count();
        if to_drop == 0 {
            return Ok(0);
        }
        // Commit-after-durable (mirrors insert_in_epoch's fsync-before-insert): compact the file
        // FIRST, and only mutate the in-memory set after the rewrite is durable. On any I/O error
        // the in-memory set is left unchanged and the error propagates, so memory stays consistent
        // with disk (never smaller than what's persisted).
        if let Some(path) = &self.path {
            let survivors: Vec<(String, u32)> = inner
                .seen
                .iter()
                .filter(|(_, e)| retained.contains(e))
                .map(|(k, e)| (k.clone(), *e))
                .collect();
            let tmp = path.with_extension("compact.tmp");
            #[cfg(test)]
            let fail_parent_sync = std::mem::take(&mut inner.fail_next_compaction_parent_sync);
            #[cfg(test)]
            let fail_reopen = std::mem::take(&mut inner.fail_next_compaction_reopen);
            // Close the old append handle before the rename. After a successful rename it names an
            // unlinked inode on Unix (and can block the rename on Windows); retaining it after any
            // later failure would let a future append report success to the wrong file.
            inner.file = None;
            // Write + rename + parent-dir fsync in one fallible step; on ANY error, remove the temp
            // file before propagating and leave the store without a writable handle. Inserts then
            // fail closed until a restart/reopen establishes the authoritative path again.
            let compact = || -> io::Result<File> {
                {
                    let mut f = open_private(&tmp, false)?;
                    for (k, e) in &survivors {
                        f.write_all(format!("{e} {k}\n").as_bytes())?;
                    }
                    f.flush()?;
                    f.sync_all()?;
                }
                std::fs::rename(&tmp, path)?;
                // Losing this rename by itself would only restore dropped entries (safe
                // over-retention). It is nevertheless required before reopening for append:
                // otherwise an accepted post-compaction key could land only in a replacement inode
                // whose name is lost on crash.
                #[cfg(test)]
                if fail_parent_sync {
                    return Err(io::Error::other(
                        "injected epoch compaction parent-sync failure",
                    ));
                }
                sync_parent_dir(path)?;
                #[cfg(test)]
                if fail_reopen {
                    return Err(io::Error::other("injected epoch compaction reopen failure"));
                }
                open_private_append_existing(path)
            };
            let replacement = match compact() {
                Ok(file) => file,
                Err(error) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(error);
                }
            };
            // Replacement durability and the fresh append handle are both established. Only now
            // commit the in-memory drop and make writes available again.
            inner.seen.retain(|_, e| retained.contains(e));
            inner.file = Some(replacement);
            return Ok(to_drop);
        }
        // Volatile in-memory set — just commit the retain.
        inner.seen.retain(|_, e| retained.contains(e));
        Ok(to_drop)
    }

    pub fn is_durable(&self) -> bool {
        self.path.is_some()
    }
}

struct TimedInner {
    /// key (opaque reference) → the unix time (secs) it was inserted. Dedup is by key; the
    /// timestamp drives TTL pruning.
    seen: HashMap<String, u64>,
    file: Option<File>,
    #[cfg(test)]
    fail_next_compaction_parent_sync: bool,
    #[cfg(test)]
    fail_next_compaction_reopen: bool,
}

/// Outcome of an atomic capacity-bounded timed-set insertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimedInsert {
    Inserted,
    AlreadyPresent,
    CapacityReached,
}

/// A durable set whose entries carry an insertion TIME, so old ones can be pruned by age — for the
/// Portal's pending checkout-reference set, which would otherwise grow unbounded as abandoned
/// checkouts accumulate. A checkout reference is NOT a Privacy Pass token (it is a pre-payment,
/// server-minted, never-blinded value indexing a payment, not a person — PD-3/PD-4), so attaching
/// an insertion time leaks nothing.
///
/// **Pruning is fail-closed and cannot cause a double-issue.** Removing a pending reference only
/// makes a later `/v1/tokens/issue` for it return "unknown reference" (402) — it never grants
/// anything. One-token-per-payment is enforced by the SEPARATE issued set, which this never
/// touches. The only failure mode is pruning a reference whose payment confirms after the TTL
/// (an availability tradeoff), so the TTL is set well above worst-case confirmation latency.
///
/// On-disk format: one `"<key> <unix>"` line per entry (append-only). [`Self::prune_older_than`]
/// compacts the file by atomically rewriting it (temp + fsync + rename + parent-dir fsync,
/// commit-after-durable). PII-free by contract, like [`DurableSet`].
pub struct TimedDurableSet {
    inner: Mutex<TimedInner>,
    path: Option<PathBuf>,
}

impl TimedDurableSet {
    /// A volatile, memory-only timed set (dev/tests). NOT durable across restarts.
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(TimedInner {
                seen: HashMap::new(),
                file: None,
                #[cfg(test)]
                fail_next_compaction_parent_sync: false,
                #[cfg(test)]
                fail_next_compaction_reopen: false,
            }),
            path: None,
        }
    }

    /// Open a file-backed timed set, loading existing `"<key> <unix>"` lines. Only `NotFound`
    /// creates an empty set; malformed/torn state fails startup closed.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let (file, created) = open_or_create_private_append(&path)?;
        let mut seen: HashMap<String, u64> = HashMap::new();
        for (index, line) in read_complete_records(&file, &path)?.into_iter().enumerate() {
            let (key, timestamp_text) = line
                .split_once(' ')
                .ok_or_else(|| invalid_record(&path, index + 1, "missing timestamp separator"))?;
            if key.is_empty() || timestamp_text.contains(' ') {
                return Err(invalid_record(
                    &path,
                    index + 1,
                    "key is empty or timestamp contains extra fields",
                ));
            }
            let timestamp = timestamp_text.parse::<u64>().map_err(|_| {
                invalid_record(&path, index + 1, "timestamp is not a unix-time u64")
            })?;
            if let Some(previous) = seen.insert(key.to_string(), timestamp) {
                if previous != timestamp {
                    return Err(invalid_record(
                        &path,
                        index + 1,
                        "key appears with conflicting timestamps",
                    ));
                }
            }
        }
        if created {
            file.sync_all()?;
        }
        sync_parent_dir(&path)?;
        Ok(Self {
            inner: Mutex::new(TimedInner {
                seen,
                file: Some(file),
                #[cfg(test)]
                fail_next_compaction_parent_sync: false,
                #[cfg(test)]
                fail_next_compaction_reopen: false,
            }),
            path: Some(path),
        })
    }

    /// Record `key` with insertion time `now_unix`. `Ok(true)` ⇒ newly inserted; `Ok(false)` ⇒
    /// already present; `Err` ⇒ not durably recorded → caller fails closed. fsync before the
    /// in-memory insert, like [`DurableSet::insert`].
    pub fn insert(&self, key: &str, now_unix: u64) -> io::Result<bool> {
        match self.insert_with_capacity(key, now_unix, None)? {
            TimedInsert::Inserted => Ok(true),
            TimedInsert::AlreadyPresent => Ok(false),
            TimedInsert::CapacityReached => Err(io::Error::other(
                "unbounded timed-set insertion unexpectedly reached capacity",
            )),
        }
    }

    /// Atomically insert a timed key only while the set is below `max_entries`. Duplicate
    /// detection wins over the capacity check, so an idempotent retry remains
    /// [`TimedInsert::AlreadyPresent`] even when the set is full. The duplicate check, capacity
    /// decision, durable append, and in-memory commit all occur under one mutex; callers may use a
    /// preliminary [`Self::len`] check to avoid expensive work, but this method is the authoritative
    /// race-free admission gate within this process. Like the other flat-file operations, it is not
    /// a cross-process capacity or deduplication lock.
    pub fn insert_if_below_capacity(
        &self,
        key: &str,
        now_unix: u64,
        max_entries: usize,
    ) -> io::Result<TimedInsert> {
        self.insert_with_capacity(key, now_unix, Some(max_entries))
    }

    fn insert_with_capacity(
        &self,
        key: &str,
        now_unix: u64,
        max_entries: Option<usize>,
    ) -> io::Result<TimedInsert> {
        if key.is_empty() || key.contains('\n') || key.contains(' ') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timed-durable key must be non-empty and must not contain a space or newline (on-disk format is `<key> <unix>`)",
            ));
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.seen.contains_key(key) {
            return Ok(TimedInsert::AlreadyPresent);
        }
        if max_entries.is_some_and(|capacity| inner.seen.len() >= capacity) {
            return Ok(TimedInsert::CapacityReached);
        }
        if self.path.is_some() {
            let record = format!("{key} {now_unix}\n");
            append_record(&mut inner.file, record.as_bytes())?;
        }
        inner.seen.insert(key.to_string(), now_unix);
        Ok(TimedInsert::Inserted)
    }

    /// Whether `key` is present.
    pub fn contains(&self, key: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .seen
            .contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .seen
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_durable(&self) -> bool {
        self.path.is_some()
    }

    /// Remove every entry inserted strictly before `cutoff_unix`, returning the count removed. The
    /// file is rewritten atomically (temp + fsync + rename + parent-dir fsync), commit-after-durable
    /// (in-memory set mutated only after the rewrite is durable). Pruning is fail-closed — see the
    /// type docs: it can only deny a stale checkout, never enable a double-issue.
    pub fn prune_older_than(&self, cutoff_unix: u64) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let to_drop = inner.seen.values().filter(|t| **t < cutoff_unix).count();
        if to_drop == 0 {
            return Ok(0);
        }
        if let Some(path) = &self.path {
            let survivors: Vec<(String, u64)> = inner
                .seen
                .iter()
                .filter(|(_, t)| **t >= cutoff_unix)
                .map(|(k, t)| (k.clone(), *t))
                .collect();
            let tmp = path.with_extension("compact.tmp");
            #[cfg(test)]
            let fail_parent_sync = std::mem::take(&mut inner.fail_next_compaction_parent_sync);
            #[cfg(test)]
            let fail_reopen = std::mem::take(&mut inner.fail_next_compaction_reopen);
            // Once rename happens the old handle is stale. Close it before replacement and leave
            // it absent on every error so a later insert cannot succeed against an unlinked inode.
            inner.file = None;
            let compact = || -> io::Result<File> {
                {
                    let mut f = open_private(&tmp, false)?;
                    for (k, t) in &survivors {
                        f.write_all(format!("{k} {t}\n").as_bytes())?;
                    }
                    f.flush()?;
                    f.sync_all()?;
                }
                std::fs::rename(&tmp, path)?;
                // Prune-rename loss alone restores stale refs (safe over-retention), but the
                // replacement name must be durable before it receives any newly accepted ref.
                #[cfg(test)]
                if fail_parent_sync {
                    return Err(io::Error::other(
                        "injected timed compaction parent-sync failure",
                    ));
                }
                sync_parent_dir(path)?;
                #[cfg(test)]
                if fail_reopen {
                    return Err(io::Error::other("injected timed compaction reopen failure"));
                }
                open_private_append_existing(path)
            };
            let replacement = match compact() {
                Ok(file) => file,
                Err(error) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(error);
                }
            };
            // Commit only after replacement durability and append readiness are both established.
            inner.seen.retain(|_, t| *t >= cutoff_unix);
            inner.file = Some(replacement);
            return Ok(to_drop);
        }
        inner.seen.retain(|_, t| *t >= cutoff_unix);
        Ok(to_drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A unique temp path with no RNG (process id + a monotonic counter).
    fn temp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("nil-durable-test-{}-{n}.log", std::process::id()))
    }

    #[test]
    fn bare_relative_paths_sync_the_current_directory() {
        assert_eq!(durable_parent(Path::new("relative.log")), Path::new("."));
        assert_eq!(
            durable_parent(Path::new("nested/relative.log")),
            Path::new("nested")
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_backed_sets_are_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        let p1 = temp_path();
        let _ = std::fs::remove_file(&p1);
        let s = DurableSet::open(&p1).expect("open");
        s.insert("k").unwrap();
        assert_eq!(mode(&p1), 0o600, "nullifier/issued log must be owner-only");
        drop(s);
        let _ = std::fs::remove_file(&p1);

        let p2 = temp_path();
        let _ = std::fs::remove_file(&p2);
        let t = TimedDurableSet::open(&p2).expect("open");
        t.insert("ref", 1).unwrap();
        assert_eq!(mode(&p2), 0o600, "pending-reference set must be owner-only");
        drop(t);
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn in_memory_dedups_but_is_not_durable() {
        let s = DurableSet::in_memory();
        assert!(!s.is_durable());
        assert!(s.insert("alpha").unwrap(), "first insert is new");
        assert!(!s.insert("alpha").unwrap(), "duplicate insert is rejected");
        assert!(s.contains("alpha"));
        assert!(!s.contains("beta"));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn file_backed_set_survives_a_restart() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);

        {
            let s = DurableSet::open(&path).expect("open");
            assert!(s.is_durable());
            assert!(s.insert("token-msg-1").unwrap());
            assert!(
                !s.insert("token-msg-1").unwrap(),
                "immediate replay rejected"
            );
            assert!(s.insert("token-msg-2").unwrap());
            assert!(s.insert("  opaque whitespace  ").unwrap());
        } // drop = simulate a process restart

        // Re-open the SAME file: the keys must still be present (this is the double-spend fix).
        let s2 = DurableSet::open(&path).expect("reopen");
        assert!(s2.contains("token-msg-1"));
        assert!(s2.contains("token-msg-2"));
        assert!(
            s2.contains("  opaque whitespace  "),
            "opaque keys must not be trimmed while loading"
        );
        assert!(
            !s2.insert("token-msg-1").unwrap(),
            "a redeemed key stays spent after restart"
        );
        assert!(s2.insert("token-msg-3").unwrap());

        // And a third open sees all three.
        drop(s2);
        let s3 = DurableSet::open(&path).expect("reopen 2");
        assert_eq!(s3.len(), 4);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_newline_in_key() {
        let s = DurableSet::in_memory();
        assert!(s.insert("bad\nkey").is_err());
        assert!(s.insert("").is_err());
        assert!(!s.contains("bad\nkey"));
    }

    #[test]
    fn every_file_format_rejects_torn_or_malformed_state() {
        let flat = temp_path();
        std::fs::write(&flat, b"unterminated-key").unwrap();
        assert_eq!(
            DurableSet::open(&flat).err().unwrap().kind(),
            io::ErrorKind::InvalidData,
            "a torn flat record must not be treated as an empty or usable store"
        );

        let epoch = temp_path();
        std::fs::write(&epoch, b"not-an-epoch key\n").unwrap();
        assert_eq!(
            EpochDurableSet::open(&epoch, None).err().unwrap().kind(),
            io::ErrorKind::InvalidData,
            "a malformed epoch record must fail startup closed"
        );

        let timed = temp_path();
        std::fs::write(&timed, b"ref not-a-time\n").unwrap();
        assert_eq!(
            TimedDurableSet::open(&timed).err().unwrap().kind(),
            io::ErrorKind::InvalidData,
            "a malformed timed record must fail startup closed"
        );

        let blank = temp_path();
        std::fs::write(&blank, b"\n").unwrap();
        assert_eq!(
            DurableSet::open(&blank).err().unwrap().kind(),
            io::ErrorKind::InvalidData,
            "blank records are not valid opaque keys"
        );

        for path in [flat, epoch, timed, blank] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn malformed_legacy_epoch_source_is_not_ignored() {
        let legacy = temp_path();
        let epoch = temp_path();
        std::fs::write(&legacy, b"torn-legacy-key").unwrap();

        assert_eq!(
            EpochDurableSet::open(&epoch, Some(&legacy))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(legacy.exists(), "failed migration must retain its source");

        let _ = std::fs::remove_file(legacy);
        let _ = std::fs::remove_file(epoch);
    }

    #[test]
    fn append_error_clears_the_uncertain_handle() {
        let path = temp_path();
        std::fs::write(&path, b"existing\n").unwrap();
        let mut handle = Some(File::open(&path).unwrap());

        assert!(append_record(&mut handle, b"new\n").is_err());
        assert!(
            handle.is_none(),
            "a failed append handle must never be reused"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn file_backed_set_never_degrades_to_memory_only_success() {
        let path = temp_path();
        let set = DurableSet::open(&path).unwrap();
        set.inner.lock().unwrap().file = None;

        assert!(set.insert("must-not-be-accepted").is_err());
        assert!(!set.contains("must-not-be-accepted"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn torn_append_state_blocks_both_same_process_retry_and_restart() {
        let path = temp_path();
        let set = DurableSet::open(&path).unwrap();
        {
            // Reproduce the observable state after a lower-level writer persisted a prefix and
            // then returned an error: the hardened append path clears its handle in this state.
            let mut inner = set.inner.lock().unwrap();
            let file = inner.file.as_mut().unwrap();
            file.write_all(b"partial-key").unwrap();
            file.sync_all().unwrap();
            inner.file = None;
        }

        assert!(set.insert("later-key").is_err());
        assert!(!set.contains("later-key"));
        drop(set);
        assert_eq!(
            DurableSet::open(&path).err().unwrap().kind(),
            io::ErrorKind::InvalidData,
            "startup must not append behind or skip an uncertain prefix"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn epoch_set_dedups_and_drops_only_unretained_partitions() {
        let s = EpochDurableSet::in_memory();
        assert!(
            s.insert_in_epoch(1, "tok-a").unwrap(),
            "first insert is new"
        );
        assert!(
            !s.insert_in_epoch(1, "tok-a").unwrap(),
            "replay in the same epoch is rejected"
        );
        // A token message is globally unique, so dedup is by key regardless of epoch.
        assert!(
            !s.insert_in_epoch(2, "tok-a").unwrap(),
            "same key under another epoch still dedups"
        );
        assert!(s.insert_in_epoch(2, "tok-b").unwrap());
        assert!(s.insert_in_epoch(3, "tok-c").unwrap());
        assert_eq!(s.len(), 3);

        // Retire epoch 1: only its partition is dropped; 2 and 3 survive.
        let dropped = s.drop_epochs(&BTreeSet::from([2, 3])).unwrap();
        assert_eq!(dropped, 1, "exactly the epoch-1 entry is removed");
        assert!(!s.contains("tok-a"), "epoch-1 key is gone");
        assert!(
            s.contains("tok-b") && s.contains("tok-c"),
            "retained partitions intact"
        );
        // The current epoch is never dropped (it is always in `retained`).
        assert_eq!(
            s.drop_epochs(&BTreeSet::from([2, 3])).unwrap(),
            0,
            "no-op when nothing to drop"
        );
    }

    #[test]
    fn epoch_set_survives_restart_and_compacts_on_drop() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        {
            let s = EpochDurableSet::open(&path, None).expect("open");
            assert!(s.insert_in_epoch(1, "old").unwrap());
            assert!(s.insert_in_epoch(2, "new").unwrap());
        } // restart
        let s2 = EpochDurableSet::open(&path, None).expect("reopen");
        assert!(
            s2.contains("old") && s2.contains("new"),
            "both survive a restart"
        );
        assert!(
            !s2.insert_in_epoch(2, "new").unwrap(),
            "a recorded key stays spent across restart"
        );
        // Drop epoch 1 and confirm the compaction is durable: a third open must NOT see "old".
        assert_eq!(s2.drop_epochs(&BTreeSet::from([2])).unwrap(), 1);
        drop(s2);
        let s3 = EpochDurableSet::open(&path, None).expect("reopen 2");
        assert!(
            !s3.contains("old"),
            "dropped partition stays dropped after restart (compacted)"
        );
        assert!(s3.contains("new"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn epoch_parent_sync_failure_blocks_all_later_appends() {
        let path = temp_path();
        let set = EpochDurableSet::open(&path, None).unwrap();
        assert!(set.insert_in_epoch(1, "old").unwrap());
        assert!(set.insert_in_epoch(2, "kept").unwrap());
        set.inner.lock().unwrap().fail_next_compaction_parent_sync = true;

        assert!(set.drop_epochs(&BTreeSet::from([2])).is_err());
        assert!(
            set.contains("old"),
            "memory must not commit a drop whose replacement is uncertain"
        );
        assert!(set.insert_in_epoch(2, "later").is_err());
        assert!(!set.contains("later"));

        drop(set);
        // A clean reopen re-establishes parent durability and a live append handle. The visible
        // replacement already contains the intended survivors; a crash before this point could
        // instead restore `old`, which is safe over-retention.
        let reopened = EpochDurableSet::open(&path, None).unwrap();
        assert!(reopened.contains("kept"));
        assert!(reopened.insert_in_epoch(2, "later").unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn epoch_set_folds_in_a_legacy_file_once_then_renames_it_aside() {
        // Seed a legacy bare-key file (the old NW_NULLIFIER_PATH format).
        let legacy = temp_path();
        let path = temp_path();
        let _ = std::fs::remove_file(&legacy);
        let _ = std::fs::remove_file(&path);
        {
            let old = DurableSet::open(&legacy).unwrap();
            old.insert("legacy-tok").unwrap();
        }
        let s = EpochDurableSet::open(&path, Some(legacy.as_path())).expect("open with legacy");
        assert!(
            s.contains("legacy-tok"),
            "legacy key folded in under LEGACY_EPOCH"
        );
        assert!(
            !s.insert_in_epoch(LEGACY_EPOCH, "legacy-tok").unwrap(),
            "already spent"
        );
        // One-shot: the legacy file is renamed aside (not deleted) so it is never re-seeded on a
        // later boot, yet the pre-migration data is preserved for recovery.
        assert!(
            !legacy.exists(),
            "original legacy path no longer present after fold-in"
        );
        let mut aside = legacy.as_os_str().to_owned();
        aside.push(".migrated");
        let aside = std::path::PathBuf::from(aside);
        assert!(
            aside.exists(),
            "legacy data preserved at the .migrated sibling (not destroyed)"
        );
        let _ = std::fs::remove_file(&aside);
        drop(s);

        // Reopen WITHOUT the legacy path: the folded entry persists in the epoch file itself.
        let s2 = EpochDurableSet::open(&path, None).expect("reopen");
        assert!(
            s2.contains("legacy-tok"),
            "folded legacy entry persists in the epoch file"
        );
        // The primitive drops the legacy partition only if LEGACY_EPOCH is not retained — the
        // Coordinator always unions LEGACY_EPOCH into `retained`, so in production it is never
        // auto-dropped (a still-held legacy key keeps its tokens unverifiable-safe).
        assert_eq!(s2.drop_epochs(&BTreeSet::from([1])).unwrap(), 1);
        assert!(!s2.contains("legacy-tok"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn timed_set_dedups_and_prunes_by_age() {
        let s = TimedDurableSet::in_memory();
        assert!(s.insert("ref-old", 100).unwrap(), "first insert is new");
        assert!(
            !s.insert("ref-old", 999).unwrap(),
            "duplicate key is rejected (time ignored)"
        );
        assert!(s.insert("ref-new", 200).unwrap());
        assert_eq!(s.len(), 2);

        // Prune everything inserted strictly before t=150: ref-old (100) goes, ref-new (200) stays.
        assert_eq!(s.prune_older_than(150).unwrap(), 1);
        assert!(!s.contains("ref-old"));
        assert!(s.contains("ref-new"));
        assert_eq!(
            s.prune_older_than(150).unwrap(),
            0,
            "no-op when nothing is old enough"
        );
        // A pruned reference can be re-inserted (a fresh checkout reuses neither — refs are random).
        assert!(
            s.insert("ref-old", 300).unwrap(),
            "a pruned key is absent and can be re-inserted"
        );

        // A space/newline in the key is rejected (would corrupt the "<key> <unix>" line format).
        assert!(s.insert("bad key", 1).is_err());
        assert!(s.insert("bad\nkey", 1).is_err());
        assert!(s.insert("", 1).is_err());
    }

    #[test]
    fn timed_set_capacity_admission_is_atomic_and_duplicate_first() {
        let path = temp_path();
        let set = TimedDurableSet::open(&path).unwrap();

        assert_eq!(
            set.insert_if_below_capacity("first", 10, 0).unwrap(),
            TimedInsert::CapacityReached
        );
        assert_eq!(
            set.insert_if_below_capacity("first", 10, 2).unwrap(),
            TimedInsert::Inserted
        );
        assert_eq!(
            set.insert_if_below_capacity("first", 999, 0).unwrap(),
            TimedInsert::AlreadyPresent,
            "idempotent duplicate detection wins even at zero capacity"
        );
        assert_eq!(
            set.insert_if_below_capacity("second", 20, 2).unwrap(),
            TimedInsert::Inserted
        );
        assert_eq!(
            set.insert_if_below_capacity("rejected", 30, 2).unwrap(),
            TimedInsert::CapacityReached
        );
        assert!(!set.contains("rejected"));
        drop(set);

        let reopened = TimedDurableSet::open(&path).unwrap();
        assert_eq!(reopened.len(), 2);
        assert!(reopened.contains("first") && reopened.contains("second"));
        assert!(!reopened.contains("rejected"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn timed_set_survives_restart_and_prune_is_durable() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        {
            let s = TimedDurableSet::open(&path).expect("open");
            assert!(s.insert("ref-a", 100).unwrap());
            assert!(s.insert("ref-b", 500).unwrap());
        } // restart
        let s2 = TimedDurableSet::open(&path).expect("reopen");
        assert!(
            s2.contains("ref-a") && s2.contains("ref-b"),
            "both survive a restart with their times"
        );
        // Prune ref-a (100 < 300); confirm the compaction is durable: a third open must not see it.
        assert_eq!(s2.prune_older_than(300).unwrap(), 1);
        // Insert a NEW ref AFTER the prune — it must write through the rebound append handle (the
        // pre-prune handle pointed at the now-renamed-away inode), so it must survive a restart too.
        assert!(s2.insert("ref-c", 600).unwrap());
        drop(s2);
        let s3 = TimedDurableSet::open(&path).expect("reopen 2");
        assert!(
            !s3.contains("ref-a"),
            "pruned entry stays pruned after restart (compacted)"
        );
        assert!(s3.contains("ref-b"));
        assert!(
            s3.contains("ref-c"),
            "a ref inserted AFTER a prune survives (rebound append handle is live)"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn timed_reopen_failure_never_reuses_the_pre_rename_handle() {
        let path = temp_path();
        let set = TimedDurableSet::open(&path).unwrap();
        assert!(set.insert("old", 1).unwrap());
        assert!(set.insert("kept", 100).unwrap());
        set.inner.lock().unwrap().fail_next_compaction_reopen = true;

        assert!(set.prune_older_than(50).is_err());
        assert!(
            set.contains("old"),
            "memory must remain conservatively over-retained on reopen failure"
        );
        assert!(set.insert("must-not-vanish", 200).is_err());
        assert!(!set.contains("must-not-vanish"));
        drop(set);

        let reopened = TimedDurableSet::open(&path).unwrap();
        assert!(!reopened.contains("old"));
        assert!(reopened.contains("kept"));
        assert!(reopened.insert("after-recovery", 300).unwrap());
        drop(reopened);
        let final_open = TimedDurableSet::open(&path).unwrap();
        assert!(final_open.contains("after-recovery"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn poisoned_lock_recovers_and_still_dedups() {
        use std::sync::Arc;
        // Poison the internal mutex by panicking while holding it in another thread, then confirm the
        // public API recovers the guard (no panic cascade) AND the single-use invariant still holds —
        // a recovered poison must never reopen a double-spend. This exercises the otherwise-unreachable
        // `unwrap_or_else(|e| e.into_inner())` recovery branch used at every lock site.
        let s = Arc::new(DurableSet::in_memory());
        assert!(s.insert("alpha").unwrap());
        let s2 = s.clone();
        let joined = std::thread::spawn(move || {
            let _g = s2.inner.lock().expect("fresh lock");
            panic!("poison the lock while it is held");
        })
        .join();
        assert!(
            joined.is_err(),
            "the helper thread panicked, poisoning the mutex"
        );

        // Reads recover the poisoned guard rather than propagating the panic.
        assert!(s.contains("alpha"), "contains() recovers a poisoned lock");
        assert_eq!(s.len(), 1);
        // And the dedup invariant still holds after recovery (no double-spend).
        assert!(
            !s.insert("alpha").unwrap(),
            "replay still rejected after poison recovery"
        );
        assert!(
            s.insert("beta").unwrap(),
            "a fresh key still inserts after recovery"
        );
        assert_eq!(s.len(), 2);
    }
}
