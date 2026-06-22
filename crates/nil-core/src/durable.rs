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

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
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
}
