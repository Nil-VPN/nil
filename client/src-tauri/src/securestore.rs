//! Platform-neutral encrypted credential vault.
//!
//! [`SecureVault`] deliberately owns one mutex for the complete read/decrypt/mutate/encrypt/
//! atomic-replace transaction. The account-auth and token-store facades must share clones of the
//! same handle; splitting those operations across independent locks would reintroduce lost updates.
//!
//! This module does not choose a platform key store. A [`Sealer`] implementation supplies the
//! authenticated encryption/key protection boundary (Keychain/Keystore/DPAPI/Secret Service).
//! The only bytes written here are a small versioned envelope around the sealer's ciphertext.

use std::collections::HashSet;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::authstore::AccountAuthMaterial;
use crate::tokens::{PendingMintBatch, PendingPaidIssue, StoredToken};

#[cfg(any(test, target_os = "macos", target_os = "ios", target_os = "linux"))]
mod aes;
#[cfg(target_os = "android")]
mod android;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "android")]
pub(crate) use android::platform_sealer;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use apple::platform_sealer;
#[cfg(target_os = "linux")]
pub(crate) use linux::platform_sealer;
#[cfg(target_os = "windows")]
pub(crate) use windows::platform_sealer;

pub const VAULT_SCHEMA_V1: u8 = 1;
pub const VAULT_AAD: &[u8] = b"com.nilvpn.client/secure-vault/v1";

const FILE_MAGIC: &[u8; 8] = b"NILVLT01";
const FILE_VERSION: u8 = 1;
const FILE_HEADER_LEN: usize = FILE_MAGIC.len() + 1 + 4;

/// Bounds attacker-controlled allocation before and after the platform sealer runs.
pub const MAX_VAULT_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_VAULT_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_STORED_TOKENS: usize = 16_384;

const AUTH_HEX_LEN: usize = 64;
const TOKEN_MESSAGE_HEX_LEN: usize = 64;
const TOKEN_SIGNATURE_HEX_LEN: usize = nil_crypto::token::TOKEN_MODULUS_BITS / 4;
pub(crate) const RESERVATION_ID_HEX_LEN: usize = 64;
const MAX_LEGACY_AUTH_BYTES: usize = 16 * 1024;
const MAX_LEGACY_TOKENS_BYTES: usize = MAX_VAULT_PLAINTEXT_BYTES;

/// Apply platform backup protections to the directory that contains the encrypted vault.
pub fn harden_storage_directory(path: &Path) -> Result<(), VaultError> {
    std::fs::create_dir_all(path).map_err(|source| VaultError::Io {
        operation: "create secure vault directory",
        source,
    })?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    apple::exclude_from_backup(path)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("protected-storage operation failed: {0}")]
    Sealer(String),
    #[error("sealed vault authentication failed")]
    Authentication,
    #[error("secure vault lock was poisoned")]
    LockPoisoned,
    #[error("secure vault I/O during {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("unsafe secure-vault file: {0}")]
    UnsafeFile(&'static str),
    #[error("secure-vault {kind} exceeds the {max}-byte limit")]
    TooLarge { kind: &'static str, max: usize },
    #[error("invalid secure-vault envelope: {0}")]
    Envelope(&'static str),
    #[error("unsupported secure-vault envelope version {0}")]
    EnvelopeVersion(u8),
    #[error("unsupported secure-vault schema version {0}")]
    SchemaVersion(u8),
    #[error("invalid secure-vault JSON: {0}")]
    Parse(String),
    #[error("invalid secure-vault value: {0}")]
    Validation(String),
    #[error("secure-vault migration verification failed")]
    MigrationVerification,
    #[error("no pending token reservation exists")]
    NoPendingReservation,
    #[error("stale token-reservation completion refused")]
    ReservationMismatch,
    #[error("no pending subscription mint exists")]
    NoPendingMint,
    #[error("stale subscription-mint completion refused")]
    MintRequestMismatch,
    #[error("no pending paid token issuance exists")]
    NoPendingPaidIssue,
    #[error("stale paid token-issuance completion refused")]
    PaidIssueMismatch,
}

/// Temporary compatibility spelling for the core's internal helpers. Public platform-facing APIs
/// use [`VaultError`] directly.
type SecureStoreError = VaultError;

/// Platform authenticated-encryption/key-protection boundary.
///
/// Implementations must generate a fresh nonce for every [`Sealer::seal`] call, authenticate
/// `aad`, and never export a platform-protected key outside their private implementation.
pub(crate) trait Sealer: Send + Sync {
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError>;
    fn open(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError>;
    fn destroy_key(&self) -> Result<(), VaultError>;
}

fn io_error(operation: &'static str, source: io::Error) -> SecureStoreError {
    SecureStoreError::Io { operation, source }
}

/// Version-one plaintext. Debug output is intentionally redacted and dropping the value scrubs all
/// credential strings before their allocations are released.
#[derive(Serialize, PartialEq, Eq)]
pub struct VaultV1 {
    pub schema: u8,
    pub auth: Option<AccountAuthMaterial>,
    pub tokens: Vec<StoredToken>,
    /// Crash-recoverable subscription issuance state. It contains only blinded/token crypto state
    /// plus the anonymous account number already present in `auth`, and is OS-sealed with the vault.
    pub(crate) pending_mint: Option<PendingMintBatch>,
    /// Crash-recoverable one-payment issuance state. The opaque payment reference and exact
    /// blinding material remain inside the OS-sealed vault until the finalized token is committed.
    pub(crate) pending_paid_issue: Option<PendingPaidIssue>,
    /// Domain-separated hash of the most recently completed payment reference. It is deliberately
    /// not attached to a token and is bounded to one value; it lets a post-commit process restart
    /// acknowledge the same UI retry without asking the Portal to bind a different request.
    pub(crate) last_paid_issue_hash: Option<String>,
    /// A bearer pass durably reserved for an in-flight Coordinator redemption. Keeping it inside
    /// the same OS-sealed transaction as `tokens` prevents a crash between "remove" and "POST"
    /// from silently burning the pass. It carries no account or payment metadata.
    pub pending_redemption: Option<PendingRedemption>,
    /// Random identifier of the most recently committed redemption. This bounded local receipt
    /// makes an exact duplicated native completion idempotent and lets app-restart reconciliation
    /// prove that a live native tunnel belongs to the credential already consumed from this vault.
    /// It is never sent to the Portal or Coordinator and carries no account/payment information.
    pub(crate) last_redemption_id: Option<String>,
}

/// One locally reserved bearer credential. The random identifier is not a credential and carries
/// no account/payment data; it binds asynchronous completion to this exact pending entry so a stale
/// tunnel callback can never clear a newer reservation (the classic ABA race).
#[derive(Serialize, PartialEq, Eq)]
pub struct PendingRedemption {
    pub reservation_id: String,
    pub token: StoredToken,
}

impl PendingRedemption {
    fn from_legacy(token: StoredToken) -> Result<Self, VaultError> {
        Ok(Self {
            reservation_id: new_reservation_id()?,
            token,
        })
    }

    pub(crate) fn new(token: StoredToken) -> Result<Self, VaultError> {
        Self::from_legacy(token)
    }

    pub(crate) fn clear_sensitive(&mut self) {
        self.reservation_id.zeroize();
        self.token.msg.zeroize();
        self.token.token.zeroize();
    }
}

impl Clone for PendingRedemption {
    fn clone(&self) -> Self {
        Self {
            reservation_id: self.reservation_id.clone(),
            token: self.token.clone(),
        }
    }
}

impl Drop for PendingRedemption {
    fn drop(&mut self) {
        self.clear_sensitive();
    }
}

impl fmt::Debug for PendingRedemption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingRedemption([REDACTED])")
    }
}

impl VaultV1 {
    pub fn empty() -> Self {
        Self {
            schema: VAULT_SCHEMA_V1,
            auth: None,
            tokens: Vec::new(),
            pending_mint: None,
            pending_paid_issue: None,
            last_paid_issue_hash: None,
            pending_redemption: None,
            last_redemption_id: None,
        }
    }

    pub fn validate(&self) -> Result<(), SecureStoreError> {
        if self.schema != VAULT_SCHEMA_V1 {
            return Err(SecureStoreError::SchemaVersion(self.schema));
        }
        let credential_count = self
            .tokens
            .len()
            .saturating_add(usize::from(self.pending_redemption.is_some()));
        if credential_count > MAX_STORED_TOKENS {
            return Err(SecureStoreError::Validation(format!(
                "token count exceeds {MAX_STORED_TOKENS}"
            )));
        }

        if let Some(auth) = &self.auth {
            validate_lower_hex(&auth.account_number, AUTH_HEX_LEN, "auth.account_number")?;
            validate_lower_hex(&auth.auth_seed, AUTH_HEX_LEN, "auth.auth_seed")?;
        }
        if let Some(pending_mint) = &self.pending_mint {
            pending_mint
                .validate()
                .map_err(SecureStoreError::Validation)?;
        }
        if let Some(pending_issue) = &self.pending_paid_issue {
            pending_issue
                .validate()
                .map_err(SecureStoreError::Validation)?;
        }
        if let Some(receipt) = &self.last_paid_issue_hash {
            validate_lower_hex(receipt, 64, "last_paid_issue_hash")?;
        }

        let mut messages = HashSet::with_capacity(self.tokens.len());
        for (index, token) in self.tokens.iter().enumerate() {
            validate_lower_hex(
                &token.msg,
                TOKEN_MESSAGE_HEX_LEN,
                &format!("tokens[{index}].msg"),
            )?;
            validate_lower_hex(
                &token.token,
                TOKEN_SIGNATURE_HEX_LEN,
                &format!("tokens[{index}].token"),
            )?;
            if !messages.insert(token.msg.as_str()) {
                return Err(SecureStoreError::Validation(format!(
                    "tokens[{index}].msg duplicates another bearer token"
                )));
            }
        }
        if let Some(token) = &self.pending_redemption {
            validate_lower_hex(
                &token.reservation_id,
                RESERVATION_ID_HEX_LEN,
                "pending_redemption.reservation_id",
            )?;
            validate_lower_hex(
                &token.token.msg,
                TOKEN_MESSAGE_HEX_LEN,
                "pending_redemption.token.msg",
            )?;
            validate_lower_hex(
                &token.token.token,
                TOKEN_SIGNATURE_HEX_LEN,
                "pending_redemption.token.token",
            )?;
            if !messages.insert(token.token.msg.as_str()) {
                return Err(SecureStoreError::Validation(
                    "pending_redemption.msg duplicates a queued bearer token".to_string(),
                ));
            }
            if self
                .last_redemption_id
                .as_deref()
                .is_some_and(|last| last == token.reservation_id.as_str())
            {
                return Err(SecureStoreError::Validation(
                    "pending and completed redemption ids must differ".to_string(),
                ));
            }
        }
        if let Some(reservation_id) = &self.last_redemption_id {
            validate_lower_hex(reservation_id, RESERVATION_ID_HEX_LEN, "last_redemption_id")?;
        }
        Ok(())
    }

    /// Explicitly scrub credentials before reusing a value. [`Drop`] calls the same operation.
    pub fn clear_sensitive(&mut self) {
        if let Some(auth) = self.auth.as_mut() {
            auth.account_number.zeroize();
            auth.auth_seed.zeroize();
        }
        self.auth = None;
        for token in &mut self.tokens {
            token.msg.zeroize();
            token.token.zeroize();
        }
        self.tokens.clear();
        if let Some(pending_mint) = self.pending_mint.as_mut() {
            pending_mint.zeroize();
        }
        self.pending_mint = None;
        if let Some(pending_issue) = self.pending_paid_issue.as_mut() {
            pending_issue.zeroize();
        }
        self.pending_paid_issue = None;
        if let Some(receipt) = self.last_paid_issue_hash.as_mut() {
            receipt.zeroize();
        }
        self.last_paid_issue_hash = None;
        if let Some(token) = self.pending_redemption.as_mut() {
            token.clear_sensitive();
        }
        self.pending_redemption = None;
        if let Some(reservation_id) = self.last_redemption_id.as_mut() {
            reservation_id.zeroize();
        }
        self.last_redemption_id = None;
    }
}

impl Default for VaultV1 {
    fn default() -> Self {
        Self::empty()
    }
}

impl Drop for VaultV1 {
    fn drop(&mut self) {
        self.clear_sensitive();
    }
}

impl fmt::Debug for VaultV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultV1")
            .field("schema", &self.schema)
            .field("has_auth", &self.auth.is_some())
            .field("token_count", &self.tokens.len())
            .field("has_pending_mint", &self.pending_mint.is_some())
            .field("has_pending_paid_issue", &self.pending_paid_issue.is_some())
            .field(
                "has_paid_issue_receipt",
                &self.last_paid_issue_hash.is_some(),
            )
            .field("has_pending_redemption", &self.pending_redemption.is_some())
            .field("has_redemption_receipt", &self.last_redemption_id.is_some())
            .finish()
    }
}

impl<'de> Deserialize<'de> for VaultV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = StrictVaultWire::deserialize(deserializer)?;
        wire.into_vault().map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictVaultWire {
    schema: u8,
    auth: Option<StrictAuthWire>,
    tokens: Vec<StrictTokenWire>,
    #[serde(default)]
    pending_mint: Option<PendingMintBatch>,
    #[serde(default)]
    pending_paid_issue: Option<PendingPaidIssue>,
    #[serde(default)]
    last_paid_issue_hash: Option<String>,
    /// Backward-compatible addition to the v1 plaintext schema. Old authenticated vaults omit it
    /// and therefore load with no in-flight reservation; unknown fields remain rejected.
    #[serde(default)]
    pending_redemption: Option<StrictPendingWire>,
    /// Backward-compatible completion receipt. Vaults written before retry-safe native completion
    /// omit it and load with no acknowledged reservation.
    #[serde(default)]
    last_redemption_id: Option<String>,
}

impl Drop for StrictVaultWire {
    fn drop(&mut self) {
        if let Some(receipt) = self.last_paid_issue_hash.as_mut() {
            receipt.zeroize();
        }
        if let Some(reservation_id) = self.last_redemption_id.as_mut() {
            reservation_id.zeroize();
        }
    }
}

impl StrictVaultWire {
    fn into_vault(mut self) -> Result<VaultV1, VaultError> {
        let auth = self.auth.take().map(StrictAuthWire::into_auth);
        let tokens = self
            .tokens
            .drain(..)
            .map(StrictTokenWire::into_token)
            .collect();
        let pending_mint = self.pending_mint.take();
        let pending_paid_issue = self.pending_paid_issue.take();
        let last_paid_issue_hash = self.last_paid_issue_hash.take();
        let pending_redemption = self
            .pending_redemption
            .take()
            .map(StrictPendingWire::into_pending)
            .transpose()?;
        let last_redemption_id = self.last_redemption_id.take();
        Ok(VaultV1 {
            schema: self.schema,
            auth,
            tokens,
            pending_mint,
            pending_paid_issue,
            last_paid_issue_hash,
            pending_redemption,
            last_redemption_id,
        })
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StrictPendingWire {
    Bound(StrictBoundPendingWire),
    /// Compatibility with the first development vault shape, where `pending_redemption` was the
    /// token object directly. Released vaults that predate reservations omit the field entirely.
    Legacy(StrictTokenWire),
}

impl StrictPendingWire {
    fn into_pending(self) -> Result<PendingRedemption, VaultError> {
        match self {
            Self::Bound(bound) => Ok(bound.into_pending()),
            Self::Legacy(token) => PendingRedemption::from_legacy(token.into_token()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictBoundPendingWire {
    reservation_id: String,
    token: StrictTokenWire,
}

impl StrictBoundPendingWire {
    fn into_pending(mut self) -> PendingRedemption {
        PendingRedemption {
            reservation_id: std::mem::take(&mut self.reservation_id),
            token: StoredToken {
                msg: std::mem::take(&mut self.token.msg),
                token: std::mem::take(&mut self.token.token),
            },
        }
    }
}

impl Drop for StrictBoundPendingWire {
    fn drop(&mut self) {
        self.reservation_id.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictAuthWire {
    account_number: String,
    auth_seed: String,
}

impl StrictAuthWire {
    fn into_auth(mut self) -> AccountAuthMaterial {
        AccountAuthMaterial {
            account_number: std::mem::take(&mut self.account_number),
            auth_seed: std::mem::take(&mut self.auth_seed),
        }
    }
}

impl Drop for StrictAuthWire {
    fn drop(&mut self) {
        self.account_number.zeroize();
        self.auth_seed.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictTokenWire {
    msg: String,
    token: String,
}

impl StrictTokenWire {
    fn into_token(mut self) -> StoredToken {
        StoredToken {
            msg: std::mem::take(&mut self.msg),
            token: std::mem::take(&mut self.token),
        }
    }
}

impl Drop for StrictTokenWire {
    fn drop(&mut self) {
        self.msg.zeroize();
        self.token.zeroize();
    }
}

fn validate_lower_hex(
    value: &str,
    expected_len: usize,
    field: &str,
) -> Result<(), SecureStoreError> {
    if value.len() != expected_len {
        return Err(SecureStoreError::Validation(format!(
            "{field} must be exactly {expected_len} lowercase hex characters"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SecureStoreError::Validation(format!(
            "{field} must contain lowercase hex only"
        )));
    }
    Ok(())
}

pub(crate) fn new_reservation_id() -> Result<String, VaultError> {
    let mut bytes = Zeroizing::new([0_u8; RESERVATION_ID_HEX_LEN / 2]);
    getrandom::getrandom(bytes.as_mut())
        .map_err(|_| VaultError::Sealer("reservation-id entropy unavailable".into()))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[derive(Clone)]
pub struct SecureVault {
    inner: Arc<Mutex<VaultInner>>,
}

struct VaultInner {
    path: PathBuf,
    sealer: Arc<dyn Sealer>,
}

impl SecureVault {
    pub(crate) fn open(path: PathBuf, sealer: Arc<dyn Sealer>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VaultInner { path, sealer })),
        }
    }

    /// Construct a vault with the target OS's production credential backend. Android registers its
    /// Keystore plugin at runtime and instead calls [`SecureVault::open`] with that private handle.
    #[cfg(not(target_os = "android"))]
    pub fn open_platform(path: PathBuf) -> Result<Self, VaultError> {
        Ok(Self::open(path, platform_sealer()?))
    }

    #[cfg(target_os = "android")]
    pub fn open_platform(_path: PathBuf) -> Result<Self, VaultError> {
        Err(VaultError::Sealer(
            "Android secure storage requires the app's private Keystore plugin handle".into(),
        ))
    }

    pub fn path(&self) -> Result<PathBuf, SecureStoreError> {
        Ok(self.lock()?.path.clone())
    }

    pub fn is_initialized(&self) -> Result<bool, SecureStoreError> {
        let inner = self.lock()?;
        regular_file_exists(&inner.path, "vault")
    }

    /// Decrypt a fresh snapshot. The caller owns the returned value; its [`Drop`] implementation
    /// scrubs every contained credential.
    pub fn load(&self) -> Result<VaultV1, SecureStoreError> {
        let inner = self.lock()?;
        load_locked(&inner)
    }

    /// Serialize one complete read/decrypt/mutate/encrypt/atomic-replace transaction.
    ///
    /// The callback result is returned only after the replacement is durable. If either the
    /// callback, validation, sealing, or write fails, the previously committed file remains the
    /// authoritative state.
    pub fn mutate<R>(
        &self,
        mutation: impl FnOnce(&mut VaultV1) -> Result<R, SecureStoreError>,
    ) -> Result<R, SecureStoreError> {
        let inner = self.lock()?;
        let mut vault = load_locked(&inner)?;
        let result = mutation(&mut vault)?;
        vault.validate()?;
        persist_locked(&inner, &vault)?;
        Ok(result)
    }

    pub fn replace(&self, vault: &VaultV1) -> Result<(), SecureStoreError> {
        let inner = self.lock()?;
        vault.validate()?;
        persist_locked(&inner, vault)
    }

    /// Destroy the OS-protected key first, then unlink the now-unrecoverable ciphertext. This does
    /// not claim secure deletion from flash media.
    pub fn destroy(&self) -> Result<(), SecureStoreError> {
        let inner = self.lock()?;
        let exists = regular_file_exists(&inner.path, "vault")?;
        inner.sealer.destroy_key()?;
        if exists {
            std::fs::remove_file(&inner.path).map_err(|e| io_error("remove vault", e))?;
            sync_parent(&inner.path)?;
        }
        Ok(())
    }

    /// Migrate the two historical plaintext stores. A present vault is always decrypted first and
    /// is never replaced from legacy data. Legacy files are unlinked only after a newly written
    /// vault has been reopened and compared, or after an existing vault has authenticated.
    pub fn migrate_legacy(
        &self,
        legacy_auth_path: &Path,
        legacy_tokens_path: &Path,
    ) -> Result<MigrationOutcome, SecureStoreError> {
        let inner = self.lock()?;
        let paths = LegacyPaths {
            auth: legacy_auth_path.to_path_buf(),
            tokens: legacy_tokens_path.to_path_buf(),
        };
        ensure_distinct_paths(&inner.path, &paths)?;

        if regular_file_exists(&inner.path, "vault")? {
            let _verified = load_locked(&inner)?;
            remove_legacy_if_present(&paths.auth, "legacy auth")?;
            remove_legacy_if_present(&paths.tokens, "legacy tokens")?;
            return Ok(MigrationOutcome::VaultAlreadyPresent);
        }

        let (auth_present, auth) = read_legacy_auth(&paths.auth)?;
        let (tokens_present, tokens) = read_legacy_tokens(&paths.tokens)?;
        if !auth_present && !tokens_present {
            return Ok(MigrationOutcome::NoLegacyData);
        }

        let token_count = tokens.len();
        let had_auth = auth.is_some();
        let vault = VaultV1 {
            schema: VAULT_SCHEMA_V1,
            auth,
            tokens,
            pending_mint: None,
            pending_paid_issue: None,
            last_paid_issue_hash: None,
            pending_redemption: None,
            last_redemption_id: None,
        };
        vault.validate()?;
        persist_locked(&inner, &vault)?;

        let verified = match load_locked(&inner) {
            Ok(verified) => verified,
            Err(error) => {
                let _ = std::fs::remove_file(&inner.path);
                return Err(error);
            }
        };
        if verified != vault {
            drop(verified);
            let _ = std::fs::remove_file(&inner.path);
            return Err(SecureStoreError::MigrationVerification);
        }
        drop(verified);

        remove_legacy_if_present(&paths.auth, "legacy auth")?;
        remove_legacy_if_present(&paths.tokens, "legacy tokens")?;
        Ok(MigrationOutcome::Migrated {
            had_auth,
            token_count,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, VaultInner>, SecureStoreError> {
        self.inner
            .lock()
            .map_err(|_| SecureStoreError::LockPoisoned)
    }
}

impl fmt::Debug for SecureVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureVault").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyPaths {
    pub auth: PathBuf,
    pub tokens: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    NoLegacyData,
    VaultAlreadyPresent,
    Migrated { had_auth: bool, token_count: usize },
}

fn ensure_distinct_paths(vault: &Path, legacy: &LegacyPaths) -> Result<(), SecureStoreError> {
    if vault == legacy.auth || vault == legacy.tokens || legacy.auth == legacy.tokens {
        return Err(SecureStoreError::UnsafeFile(
            "vault, legacy auth, and legacy token paths must be distinct",
        ));
    }
    Ok(())
}

fn load_locked(inner: &VaultInner) -> Result<VaultV1, SecureStoreError> {
    let Some(file) = read_optional_private_file(&inner.path, "vault", MAX_VAULT_FILE_BYTES)? else {
        return Ok(VaultV1::empty());
    };
    let ciphertext = decode_envelope(&file)?;
    let plaintext = inner.sealer.open(ciphertext, VAULT_AAD)?;
    if plaintext.len() > MAX_VAULT_PLAINTEXT_BYTES {
        return Err(SecureStoreError::TooLarge {
            kind: "plaintext",
            max: MAX_VAULT_PLAINTEXT_BYTES,
        });
    }
    if plaintext.is_empty() {
        return Err(SecureStoreError::Envelope("empty plaintext"));
    }
    let vault: VaultV1 =
        serde_json::from_slice(&plaintext).map_err(|e| SecureStoreError::Parse(e.to_string()))?;
    vault.validate()?;
    Ok(vault)
}

fn persist_locked(inner: &VaultInner, vault: &VaultV1) -> Result<(), SecureStoreError> {
    vault.validate()?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(vault).map_err(|e| SecureStoreError::Parse(e.to_string()))?,
    );
    if plaintext.len() > MAX_VAULT_PLAINTEXT_BYTES {
        return Err(SecureStoreError::TooLarge {
            kind: "plaintext",
            max: MAX_VAULT_PLAINTEXT_BYTES,
        });
    }
    let ciphertext = inner.sealer.seal(&plaintext, VAULT_AAD)?;
    let envelope = encode_envelope(&ciphertext)?;
    atomic_write_private(&inner.path, &envelope)
}

fn encode_envelope(ciphertext: &[u8]) -> Result<Vec<u8>, SecureStoreError> {
    let total =
        FILE_HEADER_LEN
            .checked_add(ciphertext.len())
            .ok_or(SecureStoreError::TooLarge {
                kind: "ciphertext",
                max: MAX_VAULT_FILE_BYTES - FILE_HEADER_LEN,
            })?;
    if ciphertext.is_empty() {
        return Err(SecureStoreError::Envelope("empty ciphertext"));
    }
    if total > MAX_VAULT_FILE_BYTES || ciphertext.len() > u32::MAX as usize {
        return Err(SecureStoreError::TooLarge {
            kind: "ciphertext",
            max: MAX_VAULT_FILE_BYTES - FILE_HEADER_LEN,
        });
    }
    let mut envelope = Vec::with_capacity(total);
    envelope.extend_from_slice(FILE_MAGIC);
    envelope.push(FILE_VERSION);
    envelope.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    envelope.extend_from_slice(ciphertext);
    Ok(envelope)
}

fn decode_envelope(file: &[u8]) -> Result<&[u8], SecureStoreError> {
    if file.len() > MAX_VAULT_FILE_BYTES {
        return Err(SecureStoreError::TooLarge {
            kind: "file",
            max: MAX_VAULT_FILE_BYTES,
        });
    }
    if file.len() < FILE_HEADER_LEN {
        return Err(SecureStoreError::Envelope("truncated header"));
    }
    if &file[..FILE_MAGIC.len()] != FILE_MAGIC {
        return Err(SecureStoreError::Envelope("bad magic"));
    }
    let version = file[FILE_MAGIC.len()];
    if version != FILE_VERSION {
        return Err(SecureStoreError::EnvelopeVersion(version));
    }
    let len_offset = FILE_MAGIC.len() + 1;
    let declared = u32::from_be_bytes(
        file[len_offset..len_offset + 4]
            .try_into()
            .expect("fixed envelope length field"),
    ) as usize;
    if declared == 0 {
        return Err(SecureStoreError::Envelope("empty ciphertext"));
    }
    let expected = FILE_HEADER_LEN
        .checked_add(declared)
        .ok_or(SecureStoreError::Envelope("invalid ciphertext length"))?;
    if expected != file.len() {
        return Err(SecureStoreError::Envelope(
            "declared ciphertext length does not match the file",
        ));
    }
    Ok(&file[FILE_HEADER_LEN..])
}

fn read_legacy_auth(path: &Path) -> Result<(bool, Option<AccountAuthMaterial>), SecureStoreError> {
    let Some(bytes) = read_optional_private_file(path, "legacy auth", MAX_LEGACY_AUTH_BYTES)?
    else {
        return Ok((false, None));
    };
    let wire: StrictAuthWire = serde_json::from_slice(&bytes)
        .map_err(|e| SecureStoreError::Parse(format!("legacy auth: {e}")))?;
    Ok((true, Some(wire.into_auth())))
}

fn read_legacy_tokens(path: &Path) -> Result<(bool, Vec<StoredToken>), SecureStoreError> {
    let Some(bytes) = read_optional_private_file(path, "legacy tokens", MAX_LEGACY_TOKENS_BYTES)?
    else {
        return Ok((false, Vec::new()));
    };
    let mut wire: Vec<StrictTokenWire> = serde_json::from_slice(&bytes)
        .map_err(|e| SecureStoreError::Parse(format!("legacy tokens: {e}")))?;
    let tokens = wire.drain(..).map(StrictTokenWire::into_token).collect();
    Ok((true, tokens))
}

fn read_optional_private_file(
    path: &Path,
    kind: &'static str,
    max: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(SecureStoreError::UnsafeFile("symbolic links are refused"));
            }
            Err(error) => return Err(io_error("open file", error)),
        }
    };
    #[cfg(not(unix))]
    let file = {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error("inspect file", error)),
        };
        validate_private_regular_file(&metadata, kind)?;
        File::open(path).map_err(|e| io_error("open file", e))?
    };

    // Validate the metadata from the exact opened handle. On Unix O_NOFOLLOW closes the path-swap
    // window; checking a path and opening it in separate operations would not.
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect opened file", error))?;
    validate_private_regular_file(&metadata, kind)?;
    if metadata.len() > max as u64 {
        return Err(SecureStoreError::TooLarge { kind, max });
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take((max as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("read file", e))?;
    if bytes.len() > max {
        return Err(SecureStoreError::TooLarge { kind, max });
    }
    Ok(Some(bytes))
}

fn regular_file_exists(path: &Path, kind: &'static str) -> Result<bool, SecureStoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_private_regular_file(&metadata, kind)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect file", error)),
    }
}

fn validate_private_regular_file(
    metadata: &std::fs::Metadata,
    _kind: &'static str,
) -> Result<(), SecureStoreError> {
    if metadata.file_type().is_symlink() {
        return Err(SecureStoreError::UnsafeFile("symbolic links are refused"));
    }
    if !metadata.is_file() {
        return Err(SecureStoreError::UnsafeFile("expected a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 || mode & 0o400 == 0 {
            return Err(SecureStoreError::UnsafeFile(
                "credential files must be owner-readable and inaccessible to group/other",
            ));
        }
    }
    Ok(())
}

fn remove_legacy_if_present(path: &Path, kind: &'static str) -> Result<(), SecureStoreError> {
    if !regular_file_exists(path, kind)? {
        return Ok(());
    }
    std::fs::remove_file(path).map_err(|e| io_error("remove legacy file", e))?;
    sync_parent(path)
}

fn atomic_write_private(path: &Path, body: &[u8]) -> Result<(), SecureStoreError> {
    if body.len() > MAX_VAULT_FILE_BYTES {
        return Err(SecureStoreError::TooLarge {
            kind: "file",
            max: MAX_VAULT_FILE_BYTES,
        });
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_error("create vault directory", e))?;
        let metadata = std::fs::symlink_metadata(parent)
            .map_err(|e| io_error("inspect vault directory", e))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SecureStoreError::UnsafeFile(
                "vault parent must be a real directory",
            ));
        }
    }
    if regular_file_exists(path, "vault")? {
        // Validation above intentionally happens before replacement; a symlink or directory is
        // never silently replaced with a credential file.
    }

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let file_name =
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(SecureStoreError::UnsafeFile(
                "vault path needs a UTF-8 file name",
            ))?;
    let temp = path.with_file_name(format!(".{file_name}.tmp-{}-{id}", std::process::id()));
    let mut cleanup = TempCleanup::new(temp.clone());

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|e| io_error("create vault temporary file", e))?;
    file.write_all(body)
        .map_err(|e| io_error("write vault temporary file", e))?;
    file.flush()
        .map_err(|e| io_error("flush vault temporary file", e))?;
    file.sync_all()
        .map_err(|e| io_error("sync vault temporary file", e))?;
    drop(file);

    replace_file(&temp, path).map_err(|e| io_error("replace vault", e))?;
    cleanup.disarm();
    sync_parent(path)
}

#[cfg(not(windows))]
fn replace_file(temp: &Path, destination: &Path) -> io::Result<()> {
    std::fs::rename(temp, destination)
}

#[cfg(windows)]
fn replace_file(temp: &Path, destination: &Path) -> io::Result<()> {
    windows::replace_file(temp, destination)
}

fn sync_parent(path: &Path) -> Result<(), SecureStoreError> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| io_error("sync vault directory", e))?;
    }
    Ok(())
}

struct TempCleanup {
    path: Option<PathBuf>,
}

impl TempCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Real authenticated encryption with a deterministic in-memory key, available only to unit tests
/// in sibling store facades. A fresh factory call can reopen the same test file; production code
/// cannot name or instantiate this provider.
#[cfg(test)]
pub(crate) fn test_vault(path: PathBuf) -> SecureVault {
    SecureVault::open(
        path,
        Arc::new(aes::AesGcmSealer::new(FacadeTestKeyProvider(Mutex::new(
            Some([0x42; 32]),
        )))),
    )
}

#[cfg(test)]
struct FacadeTestKeyProvider(Mutex<Option<[u8; 32]>>);

#[cfg(test)]
impl aes::KeyProvider for FacadeTestKeyProvider {
    fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| VaultError::LockPoisoned)?
            .map(Zeroizing::new))
    }

    fn load_or_create(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let mut key = self.0.lock().map_err(|_| VaultError::LockPoisoned)?;
        Ok(Zeroizing::new(*key.get_or_insert([0x42; 32])))
    }

    fn destroy(&self) -> Result<(), VaultError> {
        let mut key = self.0.lock().map_err(|_| VaultError::LockPoisoned)?;
        if let Some(value) = key.as_mut() {
            value.zeroize();
        }
        *key = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::thread;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "nil-securestore-{name}-{}-{id}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("test directory");
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct TestSealer {
        key: Mutex<[u8; 32]>,
        destroyed: AtomicBool,
        fail_next_seal: AtomicBool,
    }

    impl TestSealer {
        fn new(byte: u8) -> Self {
            Self {
                key: Mutex::new([byte; 32]),
                destroyed: AtomicBool::new(false),
                fail_next_seal: AtomicBool::new(false),
            }
        }

        fn fail_next_seal(&self) {
            self.fail_next_seal.store(true, Ordering::SeqCst);
        }
    }

    impl Sealer for TestSealer {
        fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
            if self.destroyed.load(Ordering::SeqCst) {
                return Err(VaultError::Sealer("test key destroyed".into()));
            }
            if self.fail_next_seal.swap(false, Ordering::SeqCst) {
                return Err(VaultError::Sealer("injected seal failure".into()));
            }
            let key = self.key.lock().expect("test key lock");
            let mut ciphertext = Vec::with_capacity(8 + plaintext.len());
            ciphertext.extend_from_slice(&test_tag(&key[..], aad, plaintext).to_be_bytes());
            ciphertext.extend(
                plaintext
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ key[index % key.len()] ^ aad[index % aad.len()]),
            );
            Ok(ciphertext)
        }

        fn open(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
            if self.destroyed.load(Ordering::SeqCst) {
                return Err(VaultError::Sealer("test key destroyed".into()));
            }
            if ciphertext.len() < 8 {
                return Err(VaultError::Authentication);
            }
            let expected = u64::from_be_bytes(
                ciphertext[..8]
                    .try_into()
                    .map_err(|_| VaultError::Authentication)?,
            );
            let key = self.key.lock().expect("test key lock");
            let mut plaintext: Vec<u8> = ciphertext[8..]
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ key[index % key.len()] ^ aad[index % aad.len()])
                .collect();
            if test_tag(&key[..], aad, &plaintext) != expected {
                plaintext.zeroize();
                return Err(VaultError::Authentication);
            }
            Ok(Zeroizing::new(plaintext))
        }

        fn destroy_key(&self) -> Result<(), VaultError> {
            self.key.lock().expect("test key lock").zeroize();
            self.destroyed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn test_tag(key: &[u8], aad: &[u8], plaintext: &[u8]) -> u64 {
        // Test-only keyed checksum; production security is exclusively a platform Sealer concern.
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in key.iter().chain(aad).chain(plaintext) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    fn auth(byte: char) -> AccountAuthMaterial {
        AccountAuthMaterial {
            account_number: byte.to_string().repeat(AUTH_HEX_LEN),
            auth_seed: "d".repeat(AUTH_HEX_LEN),
        }
    }

    fn token(index: usize) -> StoredToken {
        StoredToken {
            msg: format!("{index:064x}"),
            token: format!("{index:0512x}"),
        }
    }

    fn pending(index: usize) -> PendingRedemption {
        PendingRedemption {
            reservation_id: format!("{:064x}", index.saturating_add(10_000)),
            token: token(index),
        }
    }

    fn store(dir: &TestDir) -> (SecureVault, Arc<TestSealer>) {
        let sealer = Arc::new(TestSealer::new(0xa5));
        (
            SecureVault::open(dir.join("secure/vault.bin"), sealer.clone()),
            sealer,
        )
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn missing_vault_is_empty_and_first_mutation_creates_encrypted_file() {
        let dir = TestDir::new("roundtrip");
        let (vault, _) = store(&dir);
        assert!(!vault.is_initialized().unwrap());
        assert_eq!(vault.load().unwrap().tokens.len(), 0);

        vault
            .mutate(|state| {
                state.auth = Some(auth('a'));
                state.tokens.push(token(1));
                Ok(())
            })
            .unwrap();
        assert!(vault.is_initialized().unwrap());

        let loaded = vault.load().unwrap();
        assert_eq!(loaded.auth.as_ref().unwrap().account_number, "a".repeat(64));
        assert_eq!(loaded.tokens.len(), 1);
        let raw = std::fs::read(vault.path().unwrap()).unwrap();
        assert!(!raw
            .windows(64)
            .any(|window| window
                == b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert_eq!(&raw[..FILE_MAGIC.len()], FILE_MAGIC);
    }

    #[test]
    fn one_shared_mutex_prevents_lost_concurrent_updates() {
        let dir = TestDir::new("concurrency");
        let (vault, _) = store(&dir);
        let threads: Vec<_> = (1..=24)
            .map(|index| {
                let vault = vault.clone();
                thread::spawn(move || {
                    vault
                        .mutate(|state| {
                            state.tokens.push(token(index));
                            Ok(())
                        })
                        .unwrap();
                })
            })
            .collect();
        for handle in threads {
            handle.join().unwrap();
        }

        let loaded = vault.load().unwrap();
        assert_eq!(loaded.tokens.len(), 24);
        let messages: HashSet<_> = loaded.tokens.iter().map(|value| &value.msg).collect();
        assert_eq!(messages.len(), 24);
    }

    #[test]
    fn failed_seal_leaves_the_previous_commit_byte_for_byte() {
        let dir = TestDir::new("transaction");
        let (vault, sealer) = store(&dir);
        vault
            .mutate(|state| {
                state.tokens.push(token(1));
                Ok(())
            })
            .unwrap();
        let path = vault.path().unwrap();
        let before = std::fs::read(&path).unwrap();

        sealer.fail_next_seal();
        let error = vault
            .mutate(|state| {
                state.tokens.push(token(2));
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(error, SecureStoreError::Sealer(_)));
        assert_eq!(std::fs::read(path).unwrap(), before);
        assert_eq!(vault.load().unwrap().tokens.len(), 1);
    }

    #[test]
    fn envelope_rejects_wrong_version_truncation_trailing_data_and_tampering() {
        let dir = TestDir::new("corrupt");
        let (vault, _) = store(&dir);
        vault.replace(&VaultV1::empty()).unwrap();
        let path = vault.path().unwrap();
        let valid = std::fs::read(&path).unwrap();

        let mut wrong_version = valid.clone();
        wrong_version[FILE_MAGIC.len()] = 2;
        write_private(&path, &wrong_version);
        assert!(matches!(
            vault.load(),
            Err(SecureStoreError::EnvelopeVersion(2))
        ));

        write_private(&path, &valid[..FILE_HEADER_LEN - 1]);
        assert!(matches!(
            vault.load(),
            Err(SecureStoreError::Envelope("truncated header"))
        ));

        let mut trailing = valid.clone();
        trailing.push(0);
        write_private(&path, &trailing);
        assert!(matches!(vault.load(), Err(SecureStoreError::Envelope(_))));

        let mut tampered = valid;
        *tampered.last_mut().unwrap() ^= 1;
        write_private(&path, &tampered);
        assert!(matches!(
            vault.load(),
            Err(SecureStoreError::Authentication)
        ));
    }

    #[test]
    fn plaintext_schema_and_values_are_strict() {
        let dir = TestDir::new("strict");
        let (vault, sealer) = store(&dir);
        let path = vault.path().unwrap();

        let unsupported = serde_json::json!({"schema": 2, "auth": null, "tokens": []});
        let sealed = sealer
            .seal(unsupported.to_string().as_bytes(), VAULT_AAD)
            .unwrap();
        write_private(&path, &encode_envelope(&sealed).unwrap());
        assert!(matches!(
            vault.load(),
            Err(SecureStoreError::SchemaVersion(2))
        ));

        let unknown = serde_json::json!({
            "schema": 1,
            "auth": {"account_number": "a".repeat(64), "auth_seed": "b".repeat(64), "extra": true},
            "tokens": []
        });
        let sealed = sealer
            .seal(unknown.to_string().as_bytes(), VAULT_AAD)
            .unwrap();
        write_private(&path, &encode_envelope(&sealed).unwrap());
        assert!(matches!(vault.load(), Err(SecureStoreError::Parse(_))));

        let mut state = VaultV1::empty();
        state.auth = Some(AccountAuthMaterial {
            account_number: "A".repeat(64),
            auth_seed: "b".repeat(64),
        });
        assert!(matches!(
            state.validate(),
            Err(SecureStoreError::Validation(_))
        ));

        // Vaults written before pending-redemption recovery omit the optional field and remain
        // readable; this is a backward-compatible v1 extension, not a plaintext downgrade.
        let legacy_v1 = serde_json::json!({"schema": 1, "auth": null, "tokens": []});
        let sealed = sealer
            .seal(legacy_v1.to_string().as_bytes(), VAULT_AAD)
            .unwrap();
        write_private(&path, &encode_envelope(&sealed).unwrap());
        assert!(vault.load().unwrap().pending_redemption.is_none());

        // The brief pre-ID development shape stored the token object directly. It upgrades to a
        // fresh random binding and the next write persists that binding without losing the pass.
        let legacy_pending = serde_json::json!({
            "schema": 1,
            "auth": null,
            "tokens": [],
            "pending_redemption": token(7),
        });
        let sealed = sealer
            .seal(legacy_pending.to_string().as_bytes(), VAULT_AAD)
            .unwrap();
        write_private(&path, &encode_envelope(&sealed).unwrap());
        let upgraded = vault.load().unwrap();
        let reservation_id = upgraded
            .pending_redemption
            .as_ref()
            .unwrap()
            .reservation_id
            .clone();
        assert_eq!(reservation_id.len(), RESERVATION_ID_HEX_LEN);
        vault.replace(&upgraded).unwrap();
        let reloaded = vault.load().unwrap();
        assert_eq!(
            reloaded.pending_redemption.as_ref().unwrap().reservation_id,
            reservation_id
        );
    }

    #[test]
    fn duplicate_tokens_and_oversized_token_sets_are_rejected() {
        let mut state = VaultV1::empty();
        state.tokens = vec![token(1), token(1)];
        assert!(matches!(
            state.validate(),
            Err(SecureStoreError::Validation(_))
        ));

        state.tokens = vec![token(1)];
        state.pending_redemption = Some(pending(1));
        assert!(matches!(
            state.validate(),
            Err(SecureStoreError::Validation(_))
        ));

        state.pending_redemption = Some(pending(MAX_STORED_TOKENS + 1));
        state.tokens = (0..MAX_STORED_TOKENS).map(token).collect();
        assert!(matches!(
            state.validate(),
            Err(SecureStoreError::Validation(_))
        ));
    }

    #[test]
    fn secret_buffers_and_vault_values_support_eager_scrubbing() {
        let mut bytes = Zeroizing::new(vec![0x5a; 32]);
        bytes.zeroize();
        assert!(bytes.iter().all(|byte| *byte == 0));

        let mut state = VaultV1 {
            schema: VAULT_SCHEMA_V1,
            auth: Some(auth('a')),
            tokens: vec![token(1)],
            pending_mint: None,
            pending_paid_issue: None,
            last_paid_issue_hash: None,
            pending_redemption: Some(pending(2)),
            last_redemption_id: None,
        };
        state.clear_sensitive();
        assert!(state.auth.is_none());
        assert!(state.tokens.is_empty());
        assert!(state.pending_redemption.is_none());
    }

    #[test]
    fn legacy_migration_verifies_then_unlinks_plaintext() {
        let dir = TestDir::new("migration");
        let (vault, _) = store(&dir);
        let paths = LegacyPaths {
            auth: dir.join("auth.json"),
            tokens: dir.join("tokens.json"),
        };
        write_private(&paths.auth, &serde_json::to_vec(&auth('a')).unwrap());
        write_private(
            &paths.tokens,
            &serde_json::to_vec(&vec![token(1), token(2)]).unwrap(),
        );

        assert_eq!(
            vault.migrate_legacy(&paths.auth, &paths.tokens).unwrap(),
            MigrationOutcome::Migrated {
                had_auth: true,
                token_count: 2
            }
        );
        assert!(!paths.auth.exists());
        assert!(!paths.tokens.exists());
        let loaded = vault.load().unwrap();
        assert!(loaded.auth.is_some());
        assert_eq!(loaded.tokens.len(), 2);
    }

    #[test]
    fn existing_authenticated_vault_wins_and_cleans_stale_legacy_files() {
        let dir = TestDir::new("existing");
        let (vault, _) = store(&dir);
        vault
            .mutate(|state| {
                state.tokens.push(token(1));
                Ok(())
            })
            .unwrap();
        let paths = LegacyPaths {
            auth: dir.join("auth.json"),
            tokens: dir.join("tokens.json"),
        };
        write_private(&paths.auth, &serde_json::to_vec(&auth('b')).unwrap());
        write_private(&paths.tokens, &serde_json::to_vec(&vec![token(9)]).unwrap());

        assert_eq!(
            vault.migrate_legacy(&paths.auth, &paths.tokens).unwrap(),
            MigrationOutcome::VaultAlreadyPresent
        );
        assert!(!paths.auth.exists() && !paths.tokens.exists());
        let loaded = vault.load().unwrap();
        assert_eq!(loaded.tokens[0].msg, token(1).msg);
    }

    #[test]
    fn corrupt_existing_vault_never_falls_back_to_legacy_plaintext() {
        let dir = TestDir::new("no-fallback");
        let (vault, _) = store(&dir);
        let vault_path = vault.path().unwrap();
        write_private(&vault_path, b"not a vault");
        let paths = LegacyPaths {
            auth: dir.join("auth.json"),
            tokens: dir.join("tokens.json"),
        };
        write_private(&paths.auth, &serde_json::to_vec(&auth('a')).unwrap());

        assert!(vault.migrate_legacy(&paths.auth, &paths.tokens).is_err());
        assert!(paths.auth.exists(), "legacy data remains for recovery");
        assert_eq!(std::fs::read(vault_path).unwrap(), b"not a vault");
    }

    #[cfg(unix)]
    #[test]
    fn legacy_symlinks_are_refused_without_following_or_deleting_them() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new("symlink");
        let (vault, _) = store(&dir);
        let target = dir.join("target.json");
        write_private(&target, &serde_json::to_vec(&auth('a')).unwrap());
        let paths = LegacyPaths {
            auth: dir.join("auth.json"),
            tokens: dir.join("tokens.json"),
        };
        symlink(&target, &paths.auth).unwrap();

        assert!(matches!(
            vault.migrate_legacy(&paths.auth, &paths.tokens),
            Err(SecureStoreError::UnsafeFile(_))
        ));
        assert!(target.exists());
        assert!(paths
            .auth
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!vault.is_initialized().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn committed_vault_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("permissions");
        let (vault, _) = store(&dir);
        vault.replace(&VaultV1::empty()).unwrap();
        let mode = std::fs::metadata(vault.path().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn destroy_revokes_the_key_before_removing_ciphertext() {
        let dir = TestDir::new("destroy");
        let (vault, sealer) = store(&dir);
        vault.replace(&VaultV1::empty()).unwrap();
        vault.destroy().unwrap();
        assert!(sealer.destroyed.load(Ordering::SeqCst));
        assert!(!vault.is_initialized().unwrap());
        assert!(matches!(
            sealer.seal(b"x", VAULT_AAD),
            Err(VaultError::Sealer(_))
        ));
    }

    #[test]
    fn credential_facades_contain_no_plaintext_file_backend() {
        for (name, source) in [
            ("authstore", include_str!("authstore.rs")),
            ("tokenstore", include_str!("tokenstore.rs")),
        ] {
            let production_source = source
                .split_once("#[cfg(test)]")
                .map_or(source, |(production, _)| production);
            for forbidden in [
                "std::fs::write",
                "std::fs::read",
                "write_private_atomic",
                "serde_json::to_vec",
            ] {
                assert!(
                    !production_source.contains(forbidden),
                    "{name} reintroduced plaintext persistence via {forbidden}"
                );
            }
        }
    }

    #[test]
    fn webview_capabilities_do_not_expose_private_credential_or_vpn_plugins() {
        for capability in [
            include_str!("../capabilities/default.json"),
            include_str!("../capabilities/mobile.json"),
        ] {
            assert!(
                !capability.contains("nil-secure-store"),
                "raw secure-store commands must remain Rust-only"
            );
            assert!(
                !capability.contains("nil-vpn:"),
                "native VPN commands and bearer start args must remain Rust-only"
            );
        }
    }
}
