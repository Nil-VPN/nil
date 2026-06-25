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
//! "empty by design" posture (a full disk compromise yields a list of opaque, unlinkable keys).
//!
//! The dev/test [`DurableSet::in_memory`] variant carries no file and is **not** durable; the
//! binaries log a warning when they fall back to it.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
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

struct Inner {
    seen: HashSet<String>,
    /// Append target; `None` ⇒ memory-only (volatile).
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
        Self { inner: Mutex::new(Inner { seen: HashSet::new(), file: None }), path: None }
    }

    /// Open (creating if needed) a file-backed durable set, loading any keys already on disk.
    /// A torn final line from a prior crash loads as an extra opaque key, which is harmless —
    /// it can only cause an unknown key to read as "already used" (fail-closed), never the
    /// reverse.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut seen = HashSet::new();
        if let Ok(f) = File::open(&path) {
            for line in BufReader::new(f).lines() {
                let key = line?;
                let key = key.trim();
                if !key.is_empty() {
                    seen.insert(key.to_string());
                }
            }
        }
        let file = open_private(&path, true)?;
        Ok(Self { inner: Mutex::new(Inner { seen, file: Some(file) }), path: Some(path) })
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
        if key.contains('\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable key must not contain a newline (the on-disk format is line-delimited)",
            ));
        }
        let mut inner = self.inner.lock().expect("DurableSet mutex poisoned");
        if inner.seen.contains(key) {
            return Ok(false);
        }
        if let Some(file) = inner.file.as_mut() {
            file.write_all(key.as_bytes())?;
            file.write_all(b"\n")?;
            file.flush()?;
            file.sync_all()?;
        }
        inner.seen.insert(key.to_string());
        Ok(true)
    }

    /// Whether `key` has been recorded.
    pub fn contains(&self, key: &str) -> bool {
        self.inner.lock().expect("DurableSet mutex poisoned").seen.contains(key)
    }

    /// Number of recorded keys.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("DurableSet mutex poisoned").seen.len()
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
        Self { inner: Mutex::new(EpochInner { seen: HashMap::new(), file: None }), path: None }
    }

    /// Open a file-backed epoch-partitioned set, loading existing `"<epoch> <key>"` lines.
    ///
    /// A `legacy_path` (the old single-file `NW_NULLIFIER_PATH`, bare `"<key>"` lines) is migrated
    /// as a ONE-SHOT FOLD-IN: any legacy key not already present is appended to the epoch file under
    /// [`LEGACY_EPOCH`] (and fsync'd), then the legacy file is removed so it is never re-seeded on a
    /// later boot. The fold-in is idempotent — if removal fails, the next boot re-reads it and the
    /// already-present keys dedup. (`LEGACY_EPOCH` is the reserved partition the Coordinator always
    /// retains, so migrated nullifiers are never GC'd out from under a still-held legacy key.)
    pub fn open<P: AsRef<Path>>(path: P, legacy_path: Option<&Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Load the epoch-tagged file FIRST (authoritative). A malformed/torn line is skipped — at
        // worst a present key reads as absent (a re-record), never the reverse (fail-closed).
        let mut seen: HashMap<String, u32> = HashMap::new();
        if let Ok(f) = File::open(&path) {
            for line in BufReader::new(f).lines() {
                let line = line?;
                let line = line.trim();
                if let Some((e, k)) = line.split_once(' ') {
                    if let (Ok(epoch), false) = (e.parse::<u32>(), k.is_empty()) {
                        seen.insert(k.to_string(), epoch);
                    }
                }
            }
        }
        let mut file = open_private(&path, true)?;
        // One-shot legacy fold-in (durable), then remove the legacy file.
        if let Some(lp) = legacy_path {
            if let Ok(f) = File::open(lp) {
                let mut folded = 0usize;
                for line in BufReader::new(f).lines() {
                    let key = line?;
                    let key = key.trim();
                    if key.is_empty() || seen.contains_key(key) {
                        continue;
                    }
                    file.write_all(format!("{LEGACY_EPOCH} {key}\n").as_bytes())?;
                    seen.insert(key.to_string(), LEGACY_EPOCH);
                    folded += 1;
                }
                if folded > 0 {
                    file.flush()?;
                    file.sync_all()?;
                }
            }
            // Rename the legacy file ASIDE (to `<name>.migrated`) rather than DELETE it: this stops
            // it being re-folded on a later boot, but preserves the pre-migration data (a delete
            // would lose it on an accidental revert). Best-effort — the fold-in above is already
            // durable, so a failed rename only causes a harmless idempotent re-fold (dedup) next
            // boot. NOTE: migration to the epoch store is ONE-WAY — post-migration spends live ONLY
            // in the epoch file, so reverting to the flat store would reopen a double-spend of
            // those; the renamed-aside file is for recovery of the pre-migration set only.
            let mut aside = lp.as_os_str().to_owned();
            aside.push(".migrated");
            let _ = std::fs::rename(lp, std::path::PathBuf::from(aside));
        }
        Ok(Self { inner: Mutex::new(EpochInner { seen, file: Some(file) }), path: Some(path) })
    }

    /// Record `key` as spent under `epoch`. `Ok(true)` ⇒ newly recorded; `Ok(false)` ⇒ already
    /// present (double-spend); `Err` ⇒ not durably recorded → caller MUST fail closed. The fsync
    /// happens before the in-memory insert, exactly like [`DurableSet::insert`].
    pub fn insert_in_epoch(&self, epoch: u32, key: &str) -> io::Result<bool> {
        if key.contains('\n') || key.contains(' ') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "epoch-durable key must not contain a space or newline (on-disk format is `<epoch> <key>`)",
            ));
        }
        let mut inner = self.inner.lock().expect("EpochDurableSet mutex poisoned");
        if inner.seen.contains_key(key) {
            return Ok(false);
        }
        if let Some(file) = inner.file.as_mut() {
            file.write_all(format!("{epoch} {key}\n").as_bytes())?;
            file.flush()?;
            file.sync_all()?;
        }
        inner.seen.insert(key.to_string(), epoch);
        Ok(true)
    }

    /// Whether `key` has been recorded (in any epoch).
    pub fn contains(&self, key: &str) -> bool {
        self.inner.lock().expect("EpochDurableSet mutex poisoned").seen.contains_key(key)
    }

    /// Total recorded keys across all partitions.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("EpochDurableSet mutex poisoned").seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every partition whose epoch is NOT in `retained`, returning the number of entries
    /// removed. The file is rewritten atomically (temp + fsync + rename), so the drop survives a
    /// restart. **SAFETY:** `retained` MUST be a superset of the epochs whose keys the verifier
    /// still accepts — dropping a partition whose key still verifies would reopen a double-spend.
    /// The caller (Coordinator) derives `retained` from the verifier's held epochs, so a dropped
    /// partition's tokens are already unverifiable (see the nullifier.rs invariant + proof).
    pub fn drop_epochs(&self, retained: &BTreeSet<u32>) -> io::Result<usize> {
        if retained.is_empty() {
            // Defensive: an empty retained set would wipe every partition. The verifier always
            // holds >=1 epoch (from_public_ders rejects an empty key set) and the Coordinator unions
            // in LEGACY_EPOCH, so this is unreachable — refuse to nuke the set rather than risk it.
            return Ok(0);
        }
        let mut inner = self.inner.lock().expect("EpochDurableSet mutex poisoned");
        let to_drop = inner.seen.values().filter(|e| !retained.contains(e)).count();
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
            // Write + rename + parent-dir fsync in one fallible step; on ANY error, remove the temp
            // file before propagating so a failed compaction leaves no stale `.compact.tmp` behind.
            let compact = || -> io::Result<()> {
                {
                    let mut f =
                        open_private(&tmp, false)?;
                    for (k, e) in &survivors {
                        f.write_all(format!("{e} {k}\n").as_bytes())?;
                    }
                    f.flush()?;
                    f.sync_all()?;
                }
                std::fs::rename(&tmp, path)?;
                // fsync the parent directory so the rename (and thus the drop) is durable across a
                // crash. Best-effort: a lost rename only re-loads the dropped entries (more
                // retention), which is always safe — it can never reopen a double-spend.
                if let Some(parent) = path.parent() {
                    let dir = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
                    if let Ok(d) = File::open(dir) {
                        let _ = d.sync_all();
                    }
                }
                Ok(())
            };
            if let Err(e) = compact() {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
            // Compaction (rewrite + rename + fsync) is durable: disk now holds survivors only.
            // Commit the in-memory set to MATCH disk BEFORE the fallible append-handle reopen, so a
            // reopen error can never leave memory holding dropped entries while disk dropped them
            // (a divergence; harmless here since over-retention is safe, but we keep memory == disk).
            // The reopen is then best-effort: on failure keep the previous handle (the next insert/
            // drop or a restart rebinds it). Done under the lock, so no insert can race the swap.
            inner.seen.retain(|_, e| retained.contains(e));
            if let Ok(f) = open_private(path, true) {
                inner.file = Some(f);
            }
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
        Self { inner: Mutex::new(TimedInner { seen: HashMap::new(), file: None }), path: None }
    }

    /// Open a file-backed timed set, loading existing `"<key> <unix>"` lines. A malformed/torn line
    /// is skipped on load (fail-closed: at worst a present key reads as absent → a re-insert).
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut seen: HashMap<String, u64> = HashMap::new();
        if let Ok(f) = File::open(&path) {
            for line in BufReader::new(f).lines() {
                let line = line?;
                let line = line.trim();
                if let Some((k, t)) = line.split_once(' ') {
                    if let (false, Ok(ts)) = (k.is_empty(), t.parse::<u64>()) {
                        seen.insert(k.to_string(), ts);
                    }
                }
            }
        }
        let file = open_private(&path, true)?;
        Ok(Self { inner: Mutex::new(TimedInner { seen, file: Some(file) }), path: Some(path) })
    }

    /// Record `key` with insertion time `now_unix`. `Ok(true)` ⇒ newly inserted; `Ok(false)` ⇒
    /// already present; `Err` ⇒ not durably recorded → caller fails closed. fsync before the
    /// in-memory insert, like [`DurableSet::insert`].
    pub fn insert(&self, key: &str, now_unix: u64) -> io::Result<bool> {
        if key.contains('\n') || key.contains(' ') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timed-durable key must not contain a space or newline (on-disk format is `<key> <unix>`)",
            ));
        }
        let mut inner = self.inner.lock().expect("TimedDurableSet mutex poisoned");
        if inner.seen.contains_key(key) {
            return Ok(false);
        }
        if let Some(file) = inner.file.as_mut() {
            file.write_all(format!("{key} {now_unix}\n").as_bytes())?;
            file.flush()?;
            file.sync_all()?;
        }
        inner.seen.insert(key.to_string(), now_unix);
        Ok(true)
    }

    /// Whether `key` is present.
    pub fn contains(&self, key: &str) -> bool {
        self.inner.lock().expect("TimedDurableSet mutex poisoned").seen.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("TimedDurableSet mutex poisoned").seen.len()
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
        let mut inner = self.inner.lock().expect("TimedDurableSet mutex poisoned");
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
            let compact = || -> io::Result<()> {
                {
                    let mut f =
                        open_private(&tmp, false)?;
                    for (k, t) in &survivors {
                        f.write_all(format!("{k} {t}\n").as_bytes())?;
                    }
                    f.flush()?;
                    f.sync_all()?;
                }
                std::fs::rename(&tmp, path)?;
                if let Some(parent) = path.parent() {
                    let dir = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
                    if let Ok(d) = File::open(dir) {
                        let _ = d.sync_all();
                    }
                }
                Ok(())
            };
            if let Err(e) = compact() {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
            // The compaction (rewrite + rename + fsync) is durable: disk now holds survivors only.
            // Commit the in-memory set to MATCH disk BEFORE the fallible append-handle reopen, so a
            // reopen error can never leave memory holding pruned refs while disk dropped them. The
            // reopen is then best-effort: on failure, log and keep the file handle as-is — the next
            // insert/prune or a restart rebinds it. (A divergence here would only be fail-closed
            // anyway, but keeping memory == disk avoids the stale-handle write entirely.)
            inner.seen.retain(|_, t| *t >= cutoff_unix);
            // Best-effort reopen: on failure keep the previous handle (nil-core has no logger). The
            // next insert/prune or a restart rebinds it; memory already matches disk, so the only
            // effect of a stale handle is that a subsequent insert may fail to persist — which is
            // fail-closed for issuance (a non-durable pending ref is forgotten on restart).
            if let Ok(f) = open_private(path, true) {
                inner.file = Some(f);
            }
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
            assert!(!s.insert("token-msg-1").unwrap(), "immediate replay rejected");
            assert!(s.insert("token-msg-2").unwrap());
        } // drop = simulate a process restart

        // Re-open the SAME file: the keys must still be present (this is the double-spend fix).
        let s2 = DurableSet::open(&path).expect("reopen");
        assert!(s2.contains("token-msg-1"));
        assert!(s2.contains("token-msg-2"));
        assert!(!s2.insert("token-msg-1").unwrap(), "a redeemed key stays spent after restart");
        assert!(s2.insert("token-msg-3").unwrap());

        // And a third open sees all three.
        drop(s2);
        let s3 = DurableSet::open(&path).expect("reopen 2");
        assert_eq!(s3.len(), 3);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_newline_in_key() {
        let s = DurableSet::in_memory();
        assert!(s.insert("bad\nkey").is_err());
        assert!(!s.contains("bad\nkey"));
    }

    #[test]
    fn epoch_set_dedups_and_drops_only_unretained_partitions() {
        let s = EpochDurableSet::in_memory();
        assert!(s.insert_in_epoch(1, "tok-a").unwrap(), "first insert is new");
        assert!(!s.insert_in_epoch(1, "tok-a").unwrap(), "replay in the same epoch is rejected");
        // A token message is globally unique, so dedup is by key regardless of epoch.
        assert!(!s.insert_in_epoch(2, "tok-a").unwrap(), "same key under another epoch still dedups");
        assert!(s.insert_in_epoch(2, "tok-b").unwrap());
        assert!(s.insert_in_epoch(3, "tok-c").unwrap());
        assert_eq!(s.len(), 3);

        // Retire epoch 1: only its partition is dropped; 2 and 3 survive.
        let dropped = s.drop_epochs(&BTreeSet::from([2, 3])).unwrap();
        assert_eq!(dropped, 1, "exactly the epoch-1 entry is removed");
        assert!(!s.contains("tok-a"), "epoch-1 key is gone");
        assert!(s.contains("tok-b") && s.contains("tok-c"), "retained partitions intact");
        // The current epoch is never dropped (it is always in `retained`).
        assert_eq!(s.drop_epochs(&BTreeSet::from([2, 3])).unwrap(), 0, "no-op when nothing to drop");
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
        assert!(s2.contains("old") && s2.contains("new"), "both survive a restart");
        assert!(!s2.insert_in_epoch(2, "new").unwrap(), "a recorded key stays spent across restart");
        // Drop epoch 1 and confirm the compaction is durable: a third open must NOT see "old".
        assert_eq!(s2.drop_epochs(&BTreeSet::from([2])).unwrap(), 1);
        drop(s2);
        let s3 = EpochDurableSet::open(&path, None).expect("reopen 2");
        assert!(!s3.contains("old"), "dropped partition stays dropped after restart (compacted)");
        assert!(s3.contains("new"));
        let _ = std::fs::remove_file(&path);
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
        assert!(s.contains("legacy-tok"), "legacy key folded in under LEGACY_EPOCH");
        assert!(!s.insert_in_epoch(LEGACY_EPOCH, "legacy-tok").unwrap(), "already spent");
        // One-shot: the legacy file is renamed aside (not deleted) so it is never re-seeded on a
        // later boot, yet the pre-migration data is preserved for recovery.
        assert!(!legacy.exists(), "original legacy path no longer present after fold-in");
        let mut aside = legacy.as_os_str().to_owned();
        aside.push(".migrated");
        let aside = std::path::PathBuf::from(aside);
        assert!(aside.exists(), "legacy data preserved at the .migrated sibling (not destroyed)");
        let _ = std::fs::remove_file(&aside);
        drop(s);

        // Reopen WITHOUT the legacy path: the folded entry persists in the epoch file itself.
        let s2 = EpochDurableSet::open(&path, None).expect("reopen");
        assert!(s2.contains("legacy-tok"), "folded legacy entry persists in the epoch file");
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
        assert!(!s.insert("ref-old", 999).unwrap(), "duplicate key is rejected (time ignored)");
        assert!(s.insert("ref-new", 200).unwrap());
        assert_eq!(s.len(), 2);

        // Prune everything inserted strictly before t=150: ref-old (100) goes, ref-new (200) stays.
        assert_eq!(s.prune_older_than(150).unwrap(), 1);
        assert!(!s.contains("ref-old"));
        assert!(s.contains("ref-new"));
        assert_eq!(s.prune_older_than(150).unwrap(), 0, "no-op when nothing is old enough");
        // A pruned reference can be re-inserted (a fresh checkout reuses neither — refs are random).
        assert!(s.insert("ref-old", 300).unwrap(), "a pruned key is absent and can be re-inserted");

        // A space/newline in the key is rejected (would corrupt the "<key> <unix>" line format).
        assert!(s.insert("bad key", 1).is_err());
        assert!(s.insert("bad\nkey", 1).is_err());
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
        assert!(s2.contains("ref-a") && s2.contains("ref-b"), "both survive a restart with their times");
        // Prune ref-a (100 < 300); confirm the compaction is durable: a third open must not see it.
        assert_eq!(s2.prune_older_than(300).unwrap(), 1);
        // Insert a NEW ref AFTER the prune — it must write through the rebound append handle (the
        // pre-prune handle pointed at the now-renamed-away inode), so it must survive a restart too.
        assert!(s2.insert("ref-c", 600).unwrap());
        drop(s2);
        let s3 = TimedDurableSet::open(&path).expect("reopen 2");
        assert!(!s3.contains("ref-a"), "pruned entry stays pruned after restart (compacted)");
        assert!(s3.contains("ref-b"));
        assert!(s3.contains("ref-c"), "a ref inserted AFTER a prune survives (rebound append handle is live)");
        let _ = std::fs::remove_file(&path);
    }
}
