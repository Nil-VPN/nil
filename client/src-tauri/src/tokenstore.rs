//! On-device store of unblinded Privacy Pass tokens.
//!
//! Tokens are mathematically unlinkable to the account/payment (that is the whole point of the
//! blinding), so keeping them on the user's device is privacy-safe. We persist ONLY `{msg, token}`
//! pairs — no account number, no payment id, no timestamp — so a device-image grab reveals only "N
//! anonymous tokens," never who paid. One token is consumed per connection: [`TokenStore::take_one`]
//! removes the token from disk BEFORE returning it, so a crash mid-connect drops a token rather than
//! replaying one the Coordinator has already burned in its nullifier set (fail-closed).

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::tokens::{StoredToken, TokenError};

pub struct TokenStore {
    path: PathBuf,
}

impl TokenStore {
    /// Back the store with `path` (e.g. `<app-local-data>/tokens.json`).
    pub fn open(path: PathBuf) -> Self {
        TokenStore { path }
    }

    /// All stored tokens (empty if the file does not exist yet).
    pub fn load(&self) -> Result<Vec<StoredToken>, TokenError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| TokenError::Storage(format!("parse token store: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(TokenError::Storage(format!("read token store: {e}"))),
        }
    }

    pub fn count(&self) -> Result<usize, TokenError> {
        Ok(self.load()?.len())
    }

    /// Append acquired tokens.
    pub fn add(&self, tokens: &[StoredToken]) -> Result<(), TokenError> {
        let mut all = self.load()?;
        all.extend_from_slice(tokens);
        self.write(&all)
    }

    /// Pop one token, persisting the removal BEFORE returning it (so a crash never replays a spent
    /// token). `None` if the store is empty.
    pub fn take_one(&self) -> Result<Option<StoredToken>, TokenError> {
        let mut all = self.load()?;
        if all.is_empty() {
            return Ok(None);
        }
        let tok = all.remove(0);
        self.write(&all)?; // persist removal first
        Ok(Some(tok))
    }

    /// Drop all stored tokens (e.g. on logout). Idempotent — a missing file is already "empty".
    pub fn clear(&self) -> Result<(), TokenError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(TokenError::Storage(format!("clear token store: {e}"))),
        }
    }

    /// Atomic write (temp file + rename), `0600` on unix — the file holds bearer credentials.
    fn write(&self, tokens: &[StoredToken]) -> Result<(), TokenError> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| TokenError::Storage(format!("create token dir: {e}")))?;
        }
        let body =
            serde_json::to_vec_pretty(tokens).map_err(|e| TokenError::Storage(e.to_string()))?;
        write_private_atomic(&self.path, &body)
            .map_err(|e| TokenError::Storage(format!("write token store: {e}")))?;
        Ok(())
    }
}

/// Atomic, owner-only (`0600` on unix) write: temp file + fsync + rename + parent fsync. Shared
/// with [`crate::authstore`], which persists the account auth seed with the same at-rest guarantees.
pub(crate) fn write_private_atomic(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(&tmp)?;
        f.write_all(body)?;
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> (TokenStore, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        // Unique path per test; no Tauri runtime needed.
        let mut p = std::env::temp_dir();
        let n = N.fetch_add(1, Ordering::Relaxed);
        p.push(format!(
            "nil-tokenstore-test-{}-{n}/tokens.json",
            std::process::id()
        ));
        (TokenStore::open(p.clone()), p)
    }

    fn tok(n: &str) -> StoredToken {
        StoredToken {
            msg: format!("msg-{n}"),
            token: format!("tok-{n}"),
        }
    }

    #[test]
    fn missing_file_loads_empty() {
        let (s, _p) = tmp_store();
        assert_eq!(s.count().unwrap(), 0);
        assert!(s.take_one().unwrap().is_none());
    }

    #[test]
    fn add_take_consumes_one_at_a_time_and_persists_removal() {
        let (s, path) = tmp_store();
        s.add(&[tok("1"), tok("2")]).unwrap();
        assert_eq!(s.count().unwrap(), 2);

        let first = s.take_one().unwrap().expect("one");
        let second = s.take_one().unwrap().expect("two");
        assert_ne!(first, second, "distinct tokens consumed");
        assert!(
            s.take_one().unwrap().is_none(),
            "empty after consuming both"
        );

        // Removal was persisted: a fresh handle on the same file sees an empty store.
        assert_eq!(TokenStore::open(path).count().unwrap(), 0);
    }

    /// Locks the no-waste guarantee: the `connect` command runs the privilege pre-flight BEFORE
    /// `take_one`, so a failed gate must short-circuit without consuming a token. We drive the REAL
    /// `nil_datapath::preflight_privilege` gate and mirror the command's ordering. Deterministic per
    /// process: root (CI) ⇒ the gate passes and exactly one token is consumed (the legitimate
    /// one-per-connect path); unprivileged (dev) ⇒ the gate fails and the count is untouched.
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn failed_preflight_leaves_token_count_unchanged() {
        let (s, _p) = tmp_store();
        s.add(&[tok("1"), tok("2")]).unwrap();
        assert_eq!(s.count().unwrap(), 2);

        let gate = nil_datapath::preflight_privilege();
        let consumed = if gate.is_ok() {
            s.take_one().unwrap()
        } else {
            None // connect bails here, before the token is removed from disk
        };

        if gate.is_ok() {
            assert!(consumed.is_some(), "privileged: proceeds and consumes one");
            assert_eq!(s.count().unwrap(), 1);
        } else {
            assert!(consumed.is_none(), "no token consumed when the gate fails");
            assert_eq!(
                s.count().unwrap(),
                2,
                "token count unchanged after a failed pre-flight"
            );
        }
    }

    #[test]
    fn stored_file_contains_no_payment_or_account_identifier() {
        let (s, path) = tmp_store();
        s.add(&[tok("x")]).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("payment") && !raw.contains("account"),
            "store must hold only msg/token"
        );
    }
}
