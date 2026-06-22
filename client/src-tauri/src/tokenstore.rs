//! On-device store of unblinded Privacy Pass tokens.
//!
//! Tokens are mathematically unlinkable to the account/payment (that is the whole point of the
//! blinding), so keeping them on the user's device is privacy-safe. We persist ONLY `{msg, token}`
//! pairs — no account number, no payment id, no timestamp — so a device-image grab reveals only "N
//! anonymous tokens," never who paid. One token is consumed per connection: [`TokenStore::take_one`]
//! removes the token from disk BEFORE returning it, so a crash mid-connect drops a token rather than
//! replaying one the Coordinator has already burned in its nullifier set (fail-closed).

use std::path::PathBuf;

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

    /// Atomic write (temp file + rename), `0600` on unix — the file holds bearer credentials.
    fn write(&self, tokens: &[StoredToken]) -> Result<(), TokenError> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| TokenError::Storage(format!("create token dir: {e}")))?;
        }
        let body =
            serde_json::to_vec_pretty(tokens).map_err(|e| TokenError::Storage(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &body).map_err(|e| TokenError::Storage(format!("write token store: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| TokenError::Storage(format!("rename token store: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> (TokenStore, std::path::PathBuf) {
        // Unique path per test; no Tauri runtime needed.
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("nil-tokenstore-test-{}-{n}/tokens.json", std::process::id()));
        (TokenStore::open(p.clone()), p)
    }

    fn tok(n: &str) -> StoredToken {
        StoredToken { msg: format!("msg-{n}"), token: format!("tok-{n}") }
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
        assert!(s.take_one().unwrap().is_none(), "empty after consuming both");

        // Removal was persisted: a fresh handle on the same file sees an empty store.
        assert_eq!(TokenStore::open(path).count().unwrap(), 0);
    }

    #[test]
    fn stored_file_contains_no_payment_or_account_identifier() {
        let (s, path) = tmp_store();
        s.add(&[tok("x")]).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("payment") && !raw.contains("account"), "store must hold only msg/token");
    }
}
