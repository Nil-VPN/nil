//! Client-side Privacy Pass token acquisition (User plane → Business plane only).
//!
//! Mirrors `nil-provision`: `GET /v1/tokens/pubkey` → blind a fresh random message LOCALLY →
//! `POST /v1/tokens/issue` (the Portal blind-signs, gated on a confirmed payment) → finalize
//! (unblind). The Portal never sees the unblinded token, so its signature cannot be linked to the
//! token the Coordinator later redeems — that is Pillar 4 (payment ⊥ usage). The acquired token is
//! a bearer credential; it is persisted by [`crate::tokenstore`].
//!
//! ## Unlinkability caveat — issuer-key consistency (RFC 9576)
//! Blind RSA makes a token unlinkable to its issuance *for a given issuer key*. It does NOT by
//! itself defend against **key-tagging**: a compelled/malicious Portal could serve a distinct
//! issuer key per cohort/client and, together with the Coordinator (which learns the key-derived
//! epoch at redemption), re-link a session to the account that funded it — the very joint-operator
//! attack Pillar 4 / PD-7 claim to resist. Release clients therefore use the globally consistent
//! issuer keys embedded in their reviewed trust bundle and refuse every other key. In debug builds
//! with no bundle, `NW_TOKEN_ISSUER_PUBKEYS` retains the optional local-development pin behavior.
//!
//! Privacy: this module talks ONLY to the Portal and never sees a packet. It logs **counts only** —
//! never a payment id, message, token, or blind signature (PD-2).

use serde::{Deserialize, Serialize};
use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop};

use nil_proto::account::{MintBatchRequest, MintBatchResponse};
use nil_proto::token::{
    BlindMessageBatch, CheckoutResponse, IssueRequest, IssueResponse, PubKeyResponse,
    BLIND_TOKEN_HEX_LEN, MAX_MINT_BATCH_SIZE,
};

use crate::authstore::AccountAuthMaterial;
use crate::tokenstore::{PaidIssueBegin, TokenStore};

const DEFAULT_PORTAL_URL: &str = "http://127.0.0.1:8080";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_ID_HEX_LEN: usize = 64;
const ACCOUNT_NUMBER_HEX_LEN: usize = 64;
const TOKEN_MESSAGE_HEX_LEN: usize = 64;
const BLINDING_FACTOR_HEX_LEN: usize = nil_crypto::token::TOKEN_MODULUS_BITS / 4;
const MAX_ISSUER_DER_HEX_LEN: usize = 8 * 1024;
pub(crate) const MAX_PAYMENT_REFERENCE_LEN: usize = 256;

/// One unblinded, redeemable token (both fields lowercase hex). `msg` is the nullifier key the
/// Coordinator records on redemption; `token` is the issuer's signature over `msg`. We store ONLY
/// these two values — never an account number, payment id, or timestamp alongside them — because
/// blinding removes a direct cryptographic issuance join (storing more would re-create one).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct StoredToken {
    pub msg: String,
    pub token: String,
}

impl std::fmt::Debug for StoredToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredToken([REDACTED])")
    }
}

impl StoredToken {
    /// Whether this credential is still worth attempting at `now` (unix seconds). Version-2
    /// messages carry the shared coarse expiry enforced by the Coordinator. Legacy 32-byte
    /// messages have no local expiry and remain eligible only for the server-side migration
    /// window; malformed messages are never kept in the refill buffer.
    pub(crate) fn is_redeemable_at(&self, now: u64) -> bool {
        let Some(msg) = from_hex(&self.msg) else {
            return false;
        };
        if nil_crypto::token::is_v2_message(&msg) {
            nil_crypto::token::v2_message_is_current(&msg, now)
        } else {
            msg.len() == 32
        }
    }
}

/// Encrypted, crash-recoverable state for one authenticated batch issuance. Retrying reconstructs
/// the exact same blinded requests and sends the same random request ID with a fresh auth challenge;
/// an ambiguous response can therefore never silently create a different batch.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingMintBatch {
    pub request_id: String,
    pub account_number: String,
    pub issuer_public_der: String,
    pub requests: Vec<PendingBlindRequest>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingBlindRequest {
    pub blind_msg: String,
    pub msg: String,
    pub secret: String,
    pub msg_randomizer: Option<String>,
}

/// Encrypted, crash-recoverable state for one payment-gated issuance. The payment reference is
/// retained only in the OS-protected client vault and only while the response is ambiguous or the
/// payment is awaiting confirmation. Keeping the exact blinded request is required: the Portal
/// permanently binds a paid reference to the first request and cannot safely sign a replacement.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingPaidIssue {
    pub payment_id: String,
    pub issuer_public_der: String,
    pub request: PendingBlindRequest,
}

impl std::fmt::Debug for PendingPaidIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingPaidIssue([REDACTED])")
    }
}

pub struct CompletedMintBatch {
    pub request_id: String,
    pub tokens: Vec<StoredToken>,
}

impl std::fmt::Debug for CompletedMintBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletedMintBatch")
            .field("token_count", &self.tokens.len())
            .finish_non_exhaustive()
    }
}

impl Drop for CompletedMintBatch {
    fn drop(&mut self) {
        self.request_id.zeroize();
        for token in &mut self.tokens {
            token.zeroize();
        }
    }
}

impl std::fmt::Debug for PendingMintBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingMintBatch")
            .field("request_count", &self.requests.len())
            .finish_non_exhaustive()
    }
}

impl PendingMintBatch {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !is_exact_lower_hex(&self.request_id, REQUEST_ID_HEX_LEN) {
            return Err("pending mint request_id must be 32 bytes of lowercase hex".into());
        }
        if !is_exact_lower_hex(&self.account_number, ACCOUNT_NUMBER_HEX_LEN) {
            return Err("pending mint account_number must be 32 bytes of lowercase hex".into());
        }
        if self.issuer_public_der.is_empty()
            || self.issuer_public_der.len() > MAX_ISSUER_DER_HEX_LEN
            || self.issuer_public_der.len() % 2 != 0
            || !is_lower_hex(&self.issuer_public_der)
        {
            return Err("pending mint issuer key is malformed".into());
        }
        if !(1..=MAX_MINT_BATCH_SIZE).contains(&self.requests.len()) {
            return Err("pending mint batch size is invalid".into());
        }
        for request in &self.requests {
            if !is_exact_lower_hex(&request.blind_msg, BLIND_TOKEN_HEX_LEN)
                || !is_exact_lower_hex(&request.msg, TOKEN_MESSAGE_HEX_LEN)
                || !is_exact_lower_hex(&request.secret, BLINDING_FACTOR_HEX_LEN)
                || request
                    .msg_randomizer
                    .as_ref()
                    .is_some_and(|value| !is_exact_lower_hex(value, TOKEN_MESSAGE_HEX_LEN))
            {
                return Err("pending mint blinding state is malformed".into());
            }
        }
        Ok(())
    }

    fn token_requests(&self) -> Result<Vec<nil_crypto::token::TokenRequest>, TokenError> {
        self.requests
            .iter()
            .map(PendingBlindRequest::token_request)
            .collect()
    }

    pub(crate) fn is_recoverable_at(&self, now: u64) -> bool {
        !self.requests.is_empty()
            && self.requests.iter().all(|request| {
                from_hex(&request.msg).is_some_and(|message| {
                    nil_crypto::token::is_v2_message(&message)
                        && nil_crypto::token::v2_message_is_current(&message, now)
                })
            })
    }
}

impl PendingPaidIssue {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.payment_id.is_empty()
            || self.payment_id.len() > MAX_PAYMENT_REFERENCE_LEN
            || self.payment_id.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err("pending paid-issuance reference is malformed".into());
        }
        if self.issuer_public_der.is_empty()
            || self.issuer_public_der.len() > MAX_ISSUER_DER_HEX_LEN
            || self.issuer_public_der.len() % 2 != 0
            || !is_lower_hex(&self.issuer_public_der)
        {
            return Err("pending paid-issuance issuer key is malformed".into());
        }
        if !is_exact_lower_hex(&self.request.blind_msg, BLIND_TOKEN_HEX_LEN)
            || !is_exact_lower_hex(&self.request.msg, TOKEN_MESSAGE_HEX_LEN)
            || !is_exact_lower_hex(&self.request.secret, BLINDING_FACTOR_HEX_LEN)
            || self
                .request
                .msg_randomizer
                .as_ref()
                .is_some_and(|value| !is_exact_lower_hex(value, TOKEN_MESSAGE_HEX_LEN))
        {
            return Err("pending paid-issuance blinding state is malformed".into());
        }
        Ok(())
    }

    pub(crate) fn is_recoverable_at(&self, now: u64) -> bool {
        from_hex(&self.request.msg).is_some_and(|message| {
            nil_crypto::token::is_v2_message(&message)
                && nil_crypto::token::v2_message_is_current(&message, now)
        })
    }

    fn token_request(&self) -> Result<nil_crypto::token::TokenRequest, TokenError> {
        self.request.token_request()
    }
}

impl PendingBlindRequest {
    fn from_token_request(request: &nil_crypto::token::TokenRequest) -> Self {
        let persisted = request.export_persisted();
        Self {
            blind_msg: to_hex(&persisted.blind_msg),
            msg: to_hex(&persisted.msg),
            secret: to_hex(&persisted.secret),
            msg_randomizer: persisted.msg_randomizer.as_ref().map(|value| to_hex(value)),
        }
    }

    fn token_request(&self) -> Result<nil_crypto::token::TokenRequest, TokenError> {
        let randomizer = self
            .msg_randomizer
            .as_deref()
            .map(|value| {
                from_hex(value)
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .ok_or_else(|| TokenError::Crypto("persisted randomizer is malformed".into()))
            })
            .transpose()?;
        let persisted = nil_crypto::token::PersistedTokenRequest {
            blind_msg: from_hex(&self.blind_msg)
                .ok_or_else(|| TokenError::Crypto("persisted blind message is malformed".into()))?,
            msg: from_hex(&self.msg)
                .ok_or_else(|| TokenError::Crypto("persisted token message is malformed".into()))?,
            secret: from_hex(&self.secret).ok_or_else(|| {
                TokenError::Crypto("persisted blinding secret is malformed".into())
            })?,
            msg_randomizer: randomizer,
        };
        nil_crypto::token::TokenRequest::from_persisted(&persisted)
            .map_err(|error| TokenError::Crypto(error.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("payment not confirmed yet — wait for the payment to confirm, then try again")]
    PaymentNotConfirmed,
    #[error("a token was already issued for this payment")]
    AlreadyIssued,
    #[error("the token service rejected the request (HTTP {0})")]
    IssuerRejected(u16),
    #[error("no active subscription — subscribe (or renew) to connect")]
    NotSubscribed,
    #[error("this Portal has no checkout endpoint (it predates the front-running guard)")]
    CheckoutUnsupported,
    #[error("the Portal served an unexpected token issuer key (not pinned) — refusing to proceed")]
    UnexpectedIssuerKey,
    #[error("couldn't reach the token service — is nil-portal running? ({0})")]
    Unreachable(String),
    #[error("{0}")]
    UnsafeUrl(String),
    #[error("token crypto failed: {0}")]
    Crypto(String),
    #[error("token mint batch must contain 1..={MAX_MINT_BATCH_SIZE} items (got {0})")]
    InvalidBatchSize(usize),
    #[error("token issuer returned {actual} signatures for {expected} requests")]
    BatchLengthMismatch { expected: usize, actual: usize },
    #[error("token storage failed: {0}")]
    Storage(String),
    #[error("no pending connection-pass reservation exists")]
    NoPendingReservation,
    #[error("stale connection-pass completion refused")]
    ReservationMismatch,
    #[error("no pending subscription mint exists")]
    NoPendingMint,
    #[error("stale subscription-mint completion refused")]
    MintRequestMismatch,
    #[error("no pending paid token issuance exists")]
    NoPendingPaidIssue,
    #[error("another paid token issuance is already pending")]
    PaidIssueMismatch,
}

/// Talks to the Portal's token issuer. Built lazily (never connects at startup); reads `PORTAL_URL`.
#[derive(Clone)]
pub struct TokenClient {
    http: reqwest::Client,
    base_url: String,
    /// Effective expected issuer public keys (decoded DER). Embedded release keys are authoritative;
    /// an env pin can only narrow that set and can never add another trusted issuer.
    pinned_issuer_keys: Vec<Vec<u8>>,
    /// True for an embedded release bundle (including a bundle narrowed to no matching env key).
    /// This prevents an empty intersection from accidentally becoming the debug "accept any" mode.
    issuer_pin_required: bool,
}

impl Default for TokenClient {
    fn default() -> Self {
        Self::from_env()
    }
}

impl TokenClient {
    pub fn from_env() -> Self {
        let base_url =
            std::env::var("PORTAL_URL").unwrap_or_else(|_| DEFAULT_PORTAL_URL.to_string());
        Self::with_base_url(base_url)
    }

    /// Build against an explicit Portal URL (from the GUI config). Does not connect.
    pub fn with_base_url(base_url: String) -> Self {
        let pins = crate::trust::effective_issuer_pins();
        TokenClient {
            http: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("reqwest client"),
            base_url,
            pinned_issuer_keys: pins.keys,
            issuer_pin_required: pins.required,
        }
    }

    /// Fail closed if the Portal-served issuer key is not one we pinned. This is a no-op only in
    /// debug builds without an embedded bundle; release builds always require a reviewed pin set.
    fn check_issuer_pubkey(&self, pubkey_der: &[u8]) -> Result<(), TokenError> {
        if !self.issuer_pin_required {
            return Ok(());
        }
        if self
            .pinned_issuer_keys
            .iter()
            .any(|k| k.as_slice() == pubkey_der)
        {
            Ok(())
        } else {
            // A pinned deployment served an unexpected key: possible per-cohort key-tagging. Refuse
            // to blind under it (no key material logged, PD-2).
            tracing::warn!(
                "issuer pubkey is not pinned — refusing to blind (possible key-tagging)"
            );
            Err(TokenError::UnexpectedIssuerKey)
        }
    }

    /// Mint a fresh, unguessable payment reference via `POST /v1/billing/checkout`. The buyer pays
    /// this reference (as their Monero payment id); it is then passed to [`Self::acquire`] once the
    /// payment confirms. The front-running guard means issuance only proceeds for a reference WE
    /// minted, so this checkout step is mandatory against a hardened Portal. A Portal that predates
    /// checkout returns 404/405 → [`TokenError::CheckoutUnsupported`], so the caller can fall back to
    /// the legacy manual payment-id flow. The reference indexes a payment, never a person (PD-3/PD-4).
    pub async fn init_checkout(&self) -> Result<CheckoutResponse, TokenError> {
        self.ensure_safe_base_url()?;
        let base = self.base_url.trim_end_matches('/');

        let resp = self
            .http
            .post(format!("{base}/v1/billing/checkout"))
            .send()
            .await
            .map_err(net_err)?;
        if let Some(err) = checkout_error_for_status(resp.status().as_u16()) {
            return Err(err);
        }
        // Log a count/fact only — never the reference itself (PD-2).
        tracing::info!("checkout: minted a payment reference");
        resp.json().await.map_err(net_err)
    }

    /// Acquire ONE unblinded token against a `payment_id` (a checkout reference from
    /// [`Self::init_checkout`]). The blinding secret stays in this process; the Portal blind-signs
    /// without ever seeing `msg`. The Portal returns `402` (→ [`TokenError::PaymentNotConfirmed`])
    /// until the payment confirms, so a caller polls by retrying this at a WIDE interval (the issue
    /// endpoint is rate-limited); a `402` attempt issues nothing, so retrying is safe. One token per
    /// payment is enforced (a repeat → `AlreadyIssued`).
    pub async fn acquire(&self, payment_id: &str) -> Result<StoredToken, TokenError> {
        self.ensure_safe_base_url()?;
        let base = self.base_url.trim_end_matches('/');

        // 1. Fetch the issuer's public key so we can blind locally.
        let pk: PubKeyResponse = self
            .http
            .get(format!("{base}/v1/tokens/pubkey"))
            .send()
            .await
            .map_err(net_err)?
            .error_for_status()
            .map_err(net_err)?
            .json()
            .await
            .map_err(net_err)?;
        let pubkey_der = from_hex(&pk.public_der)
            .ok_or_else(|| TokenError::Crypto("issuer pubkey not hex".into()))?;
        // Fail closed if a pinned deployment served an unexpected issuer key (anti key-tagging).
        self.check_issuer_pubkey(&pubkey_der)?;

        // 2. Blind a fresh random 32-byte message. The blinding secret never leaves this process.
        let msg = nil_crypto::token::new_v2_message()
            .map_err(|e| TokenError::Crypto(format!("token message: {e}")))?;
        let req = nil_crypto::token::blind(&pubkey_der, &msg)
            .map_err(|e| TokenError::Crypto(e.to_string()))?;

        // 3. Payment-gated blind-sign. 402 = not-yet-confirmed; 409 = already issued for this payment.
        let issue = IssueRequest {
            payment_id: payment_id.to_owned(),
            blind_msg: to_hex(&req.blind_msg),
        };
        let resp = self
            .http
            .post(format!("{base}/v1/tokens/issue"))
            .json(&issue)
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(match status.as_u16() {
                402 => TokenError::PaymentNotConfirmed,
                409 => TokenError::AlreadyIssued,
                other => TokenError::IssuerRejected(other),
            });
        }
        let issued: IssueResponse = resp.json().await.map_err(net_err)?;
        let blind_sig = from_hex(&issued.blind_sig)
            .ok_or_else(|| TokenError::Crypto("blind_sig not hex".into()))?;

        // 4. Unblind → the final token, with no direct cryptographic join to this request.
        let tok = nil_crypto::token::finalize(&pubkey_der, &req, &blind_sig)
            .map_err(|e| TokenError::Crypto(e.to_string()))?;
        tracing::info!("acquired 1 Privacy Pass token");
        Ok(StoredToken {
            msg: to_hex(&msg),
            token: to_hex(&tok),
        })
    }

    /// Crash-consistent one-payment acquisition used by the application command. The exact
    /// blinding state is sealed before the POST, identical retries reuse it after response loss or
    /// restart, and finalization plus pending-state removal is one vault transaction.
    pub async fn acquire_into_store(
        &self,
        payment_id: &str,
        store: &TokenStore,
    ) -> Result<usize, TokenError> {
        if payment_id.is_empty()
            || payment_id.len() > MAX_PAYMENT_REFERENCE_LEN
            || payment_id.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(TokenError::Crypto("payment reference is malformed".into()));
        }
        self.ensure_safe_base_url()?;
        let base = self.base_url.trim_end_matches('/');

        if store.paid_issue_completed(payment_id)? {
            return store.count();
        }

        let pending = match store.pending_paid_issue()? {
            Some(pending) => pending,
            None => {
                let pk: PubKeyResponse = self
                    .http
                    .get(format!("{base}/v1/tokens/pubkey"))
                    .send()
                    .await
                    .map_err(net_err)?
                    .error_for_status()
                    .map_err(net_err)?
                    .json()
                    .await
                    .map_err(net_err)?;
                let pubkey_der = from_hex(&pk.public_der)
                    .ok_or_else(|| TokenError::Crypto("issuer pubkey not hex".into()))?;
                self.check_issuer_pubkey(&pubkey_der)?;
                let msg = nil_crypto::token::new_v2_message()
                    .map_err(|error| TokenError::Crypto(format!("token message: {error}")))?;
                let request = nil_crypto::token::blind(&pubkey_der, &msg)
                    .map_err(|error| TokenError::Crypto(error.to_string()))?;
                let proposed = PendingPaidIssue {
                    payment_id: payment_id.to_owned(),
                    issuer_public_der: to_hex(&pubkey_der),
                    request: PendingBlindRequest::from_token_request(&request),
                };
                proposed.validate().map_err(TokenError::Crypto)?;
                match store.begin_paid_issue(proposed)? {
                    PaidIssueBegin::Pending(pending) => pending,
                    PaidIssueBegin::Completed { token_count } => return Ok(token_count),
                }
            }
        };

        if !constant_time_text_eq(&pending.payment_id, payment_id) {
            return Err(TokenError::PaidIssueMismatch);
        }
        pending.validate().map_err(TokenError::Crypto)?;
        let pubkey_der = from_hex(&pending.issuer_public_der)
            .ok_or_else(|| TokenError::Crypto("persisted issuer pubkey not hex".into()))?;
        self.check_issuer_pubkey(&pubkey_der)?;
        let request = pending.token_request()?;
        let issue = IssueRequest {
            payment_id: pending.payment_id.clone(),
            blind_msg: pending.request.blind_msg.clone(),
        };
        let response = self
            .http
            .post(format!("{base}/v1/tokens/issue"))
            .json(&issue)
            .send()
            .await
            .map_err(net_err)?;
        let status = response.status();
        if !status.is_success() {
            return Err(match status.as_u16() {
                402 => TokenError::PaymentNotConfirmed,
                409 => TokenError::PaidIssueMismatch,
                other => TokenError::IssuerRejected(other),
            });
        }
        let issued: IssueResponse = response.json().await.map_err(net_err)?;
        let blind_sig = from_hex(&issued.blind_sig)
            .ok_or_else(|| TokenError::Crypto("blind_sig not hex".into()))?;
        let signature = nil_crypto::token::finalize(&pubkey_der, &request, &blind_sig)
            .map_err(|error| TokenError::Crypto(error.to_string()))?;
        let count = store.commit_paid_issue(
            payment_id,
            StoredToken {
                msg: pending.request.msg.clone(),
                token: to_hex(&signature),
            },
        )?;
        tracing::info!("acquired 1 Privacy Pass token");
        Ok(count)
    }

    /// Compatibility convenience for callers that need exactly one token. Subscription prefetch
    /// uses [`Self::mint_batch`] so one authenticated issuance transcript covers several later
    /// connections.
    pub async fn mint(&self, material: &AccountAuthMaterial) -> Result<StoredToken, TokenError> {
        let mut tokens = self.mint_batch(material, 1).await?;
        tokens.pop().ok_or(TokenError::BatchLengthMismatch {
            expected: 1,
            actual: 0,
        })
    }

    /// Mint a bounded batch against one ACTIVE subscription proof. The issuer key is fetched and
    /// checked once, all messages are generated locally with one shared coarse expiry, and every
    /// blind signature is unblinded locally in request order. The Portal learns the anonymous
    /// account and batch size at issuance, but never any redeemable token or later connection.
    pub async fn mint_batch(
        &self,
        material: &AccountAuthMaterial,
        count: usize,
    ) -> Result<Vec<StoredToken>, TokenError> {
        if !(1..=MAX_MINT_BATCH_SIZE).contains(&count) {
            return Err(TokenError::InvalidBatchSize(count));
        }
        self.ensure_safe_base_url()?;
        let base = self.base_url.trim_end_matches('/');

        // 1. Fetch and pin the issuer key once for the complete batch.
        let pk: PubKeyResponse = self
            .http
            .get(format!("{base}/v1/tokens/pubkey"))
            .send()
            .await
            .map_err(net_err)?
            .error_for_status()
            .map_err(net_err)?
            .json()
            .await
            .map_err(net_err)?;
        let pubkey_der = from_hex(&pk.public_der)
            .ok_or_else(|| TokenError::Crypto("issuer pubkey not hex".into()))?;
        // Fail closed if a pinned deployment served an unexpected issuer key (anti key-tagging).
        self.check_issuer_pubkey(&pubkey_der)?;

        // 2. Create independent blinded messages under one shared coarse expiry. Blinding state
        // never leaves this process and is kept in the same order as the wire array.
        let messages = nil_crypto::token::new_v2_message_batch(count)
            .map_err(|e| TokenError::Crypto(format!("token messages: {e}")))?;
        let requests = messages
            .iter()
            .map(|message| {
                nil_crypto::token::blind(&pubkey_der, message)
                    .map_err(|e| TokenError::Crypto(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let blind_msgs = BlindMessageBatch::try_from(
            requests
                .iter()
                .map(|request| to_hex(&request.blind_msg))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| TokenError::InvalidBatchSize(count))?;

        // 3. Prove account ownership once for the complete batch.
        let auth = crate::account::auth_proof(&self.http, base, material)
            .await
            .map_err(portal_err)?;

        // 4. Subscription-gated batch blind-sign.
        let mint = MintBatchRequest {
            auth,
            request_id: new_request_id()?,
            blind_msgs,
        };
        let resp = self
            .http
            .post(format!("{base}/v2/tokens/mint"))
            .json(&mint)
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(match status.as_u16() {
                402 => TokenError::NotSubscribed, // no active subscription
                other => TokenError::IssuerRejected(other),
            });
        }
        let issued: MintBatchResponse = resp.json().await.map_err(net_err)?;
        // 5. Unblind every reply locally. A malformed or reordered item aborts the complete
        // client-side batch; already-finalized temporary values are zeroized when the vector drops.
        let tokens = finalize_mint_batch(&pubkey_der, requests, issued.blind_sigs.into_vec())?;
        tracing::info!(
            count = tokens.len(),
            "minted Privacy Pass token batch (subscription)"
        );
        Ok(tokens)
    }

    /// Crash-consistent production batch mint. The complete blinding state and request ID are
    /// sealed in `store` before the authenticated POST. Every retry uses the exact same ordered
    /// blinded messages and ID (with only a fresh single-use auth challenge), and final tokens are
    /// added in the same vault transaction that clears that pending state.
    pub async fn mint_batch_into_store(
        &self,
        material: &AccountAuthMaterial,
        count: usize,
        store: &TokenStore,
    ) -> Result<CompletedMintBatch, TokenError> {
        if !(1..=MAX_MINT_BATCH_SIZE).contains(&count) {
            return Err(TokenError::InvalidBatchSize(count));
        }
        self.ensure_safe_base_url()?;
        let base = self.base_url.trim_end_matches('/');

        let pending = match store.pending_mint()? {
            Some(pending) => pending,
            None => {
                let pk: PubKeyResponse = self
                    .http
                    .get(format!("{base}/v1/tokens/pubkey"))
                    .send()
                    .await
                    .map_err(net_err)?
                    .error_for_status()
                    .map_err(net_err)?
                    .json()
                    .await
                    .map_err(net_err)?;
                let pubkey_der = from_hex(&pk.public_der)
                    .ok_or_else(|| TokenError::Crypto("issuer pubkey not hex".into()))?;
                self.check_issuer_pubkey(&pubkey_der)?;
                let messages = nil_crypto::token::new_v2_message_batch(count)
                    .map_err(|e| TokenError::Crypto(format!("token messages: {e}")))?;
                let requests = messages
                    .iter()
                    .map(|message| {
                        nil_crypto::token::blind(&pubkey_der, message)
                            .map_err(|e| TokenError::Crypto(e.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let proposed = PendingMintBatch {
                    request_id: new_request_id()?,
                    account_number: material.account_number.clone(),
                    issuer_public_der: to_hex(&pubkey_der),
                    requests: requests
                        .iter()
                        .map(PendingBlindRequest::from_token_request)
                        .collect(),
                };
                proposed.validate().map_err(TokenError::Crypto)?;
                store.begin_mint(proposed)?
            }
        };

        // Account replacement clears pending issuance under the refill gate. This additional check
        // fails closed if a corrupted or independently-created facade ever violates that contract.
        if pending.account_number != material.account_number {
            return Err(TokenError::MintRequestMismatch);
        }
        pending.validate().map_err(TokenError::Crypto)?;
        let pubkey_der = from_hex(&pending.issuer_public_der)
            .ok_or_else(|| TokenError::Crypto("persisted issuer pubkey not hex".into()))?;
        self.check_issuer_pubkey(&pubkey_der)?;
        let requests = pending.token_requests()?;
        let blind_msgs = BlindMessageBatch::try_from(
            requests
                .iter()
                .map(|request| to_hex(&request.blind_msg))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| TokenError::InvalidBatchSize(requests.len()))?;
        let auth = crate::account::auth_proof(&self.http, base, material)
            .await
            .map_err(portal_err)?;
        let mint = MintBatchRequest {
            auth,
            request_id: pending.request_id.clone(),
            blind_msgs,
        };
        let resp = self
            .http
            .post(format!("{base}/v2/tokens/mint"))
            .json(&mint)
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(match status.as_u16() {
                402 => TokenError::NotSubscribed,
                409 => TokenError::MintRequestMismatch,
                other => TokenError::IssuerRejected(other),
            });
        }
        let issued: MintBatchResponse = resp.json().await.map_err(net_err)?;
        let tokens = finalize_mint_batch(&pubkey_der, requests, issued.blind_sigs.into_vec())?;
        Ok(CompletedMintBatch {
            request_id: pending.request_id.clone(),
            tokens,
        })
    }

    fn ensure_safe_base_url(&self) -> Result<(), TokenError> {
        crate::netpolicy::require_safe_control_url(&self.base_url).map_err(TokenError::UnsafeUrl)
    }
}

/// Map an account [`crate::account::PortalError`] (from the shared `auth_proof` challenge fetch) onto
/// a [`TokenError`], so the mint path surfaces one error type.
fn portal_err(e: crate::account::PortalError) -> TokenError {
    use crate::account::PortalError as P;
    match e {
        P::UnsafeUrl(s) => TokenError::UnsafeUrl(s),
        P::Unreachable(s) => TokenError::Unreachable(s),
        P::Unauthorized => TokenError::IssuerRejected(401),
        P::PaymentNotConfirmed => TokenError::NotSubscribed,
        P::Crypto(s) => TokenError::Crypto(s),
        P::Status(s) => TokenError::Unreachable(format!("auth: {s}")),
    }
}

/// Map a `/v1/billing/checkout` HTTP status to a client error (or `None` on success). Pure, so the
/// 404/405 → [`TokenError::CheckoutUnsupported`] fallback (a Portal that predates checkout) and the
/// non-2xx → [`TokenError::IssuerRejected`] mapping are unit-testable without a network round-trip.
fn checkout_error_for_status(status: u16) -> Option<TokenError> {
    match status {
        200..=299 => None,
        404 | 405 => Some(TokenError::CheckoutUnsupported),
        other => Some(TokenError::IssuerRejected(other)),
    }
}

fn net_err(e: reqwest::Error) -> TokenError {
    match e.status() {
        Some(s) => TokenError::IssuerRejected(s.as_u16()),
        None => TokenError::Unreachable(e.to_string()),
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn constant_time_text_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn new_request_id() -> Result<String, TokenError> {
    let mut bytes = zeroize::Zeroizing::new([0_u8; REQUEST_ID_HEX_LEN / 2]);
    getrandom::getrandom(bytes.as_mut())
        .map_err(|error| TokenError::Crypto(format!("request-id entropy: {error}")))?;
    Ok(to_hex(bytes.as_ref()))
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn is_exact_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && is_lower_hex(value)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn finalize_mint_batch(
    pubkey_der: &[u8],
    requests: Vec<nil_crypto::token::TokenRequest>,
    blind_sigs: Vec<String>,
) -> Result<Vec<StoredToken>, TokenError> {
    if blind_sigs.len() != requests.len() {
        return Err(TokenError::BatchLengthMismatch {
            expected: requests.len(),
            actual: blind_sigs.len(),
        });
    }

    let mut tokens = Vec::with_capacity(requests.len());
    for (request, blind_sig_hex) in requests.into_iter().zip(blind_sigs) {
        if !is_exact_lower_hex(&blind_sig_hex, BLIND_TOKEN_HEX_LEN) {
            return Err(TokenError::Crypto(
                "blind signature is not exact lowercase hex".to_string(),
            ));
        }
        let blind_sig = from_hex(&blind_sig_hex)
            .ok_or_else(|| TokenError::Crypto("blind signature is not lowercase hex".into()))?;
        let token = nil_crypto::token::finalize(pubkey_der, &request, &blind_sig)
            .map_err(|e| TokenError::Crypto(e.to_string()))?;
        tokens.push(StoredToken {
            msg: to_hex(&request.msg),
            token: to_hex(&token),
        });
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_token_roundtrips_and_holds_only_msg_and_token() {
        let t = StoredToken {
            msg: "aa".into(),
            token: "bb".into(),
        };
        let json = serde_json::to_string(&t).unwrap();
        // No identifying field names — only the two opaque hex values.
        assert!(json.contains("msg") && json.contains("token"));
        assert!(!json.contains("payment") && !json.contains("account"));
        assert_eq!(serde_json::from_str::<StoredToken>(&json).unwrap(), t);
    }

    #[test]
    fn paid_issue_state_reconstructs_the_exact_blinded_request_after_restart() {
        let issuer = nil_crypto::Issuer::generate().unwrap();
        let public_der = issuer.public_der().unwrap();
        let message = nil_crypto::token::new_v2_message().unwrap();
        let request = nil_crypto::token::blind(&public_der, &message).unwrap();
        let pending = PendingPaidIssue {
            payment_id: "ab".repeat(32),
            issuer_public_der: to_hex(&public_der),
            request: PendingBlindRequest::from_token_request(&request),
        };
        pending.validate().unwrap();

        let sealed_plaintext = serde_json::to_vec(&pending).unwrap();
        let restored: PendingPaidIssue = serde_json::from_slice(&sealed_plaintext).unwrap();
        let restored_request = restored.token_request().unwrap();
        assert_eq!(restored.request.blind_msg, to_hex(&request.blind_msg));
        assert_eq!(restored.request.msg, to_hex(&message));

        let blind_sig = issuer.blind_sign(&restored_request.blind_msg).unwrap();
        let token =
            nil_crypto::token::finalize(&public_der, &restored_request, &blind_sig).unwrap();
        assert!(nil_crypto::Verifier::from_public_der(&public_der)
            .unwrap()
            .verify(&token, &message));
        assert_eq!(format!("{restored:?}"), "PendingPaidIssue([REDACTED])");
    }

    #[test]
    fn local_expiry_filter_keeps_current_and_legacy_tokens_only() {
        let now = 1_800_000_000;
        let v2 = |expiry: u64| {
            let mut msg = [0_u8; 32];
            msg[..4].copy_from_slice(&nil_crypto::token::V2_MAGIC);
            msg[4..12].copy_from_slice(&expiry.to_be_bytes());
            StoredToken {
                msg: to_hex(&msg),
                token: "aa".repeat(256),
            }
        };

        assert!(v2(now + 60).is_redeemable_at(now));
        assert!(!v2(now - 1).is_redeemable_at(now));
        assert!(!v2(now + nil_crypto::token::V2_VALIDITY_SECS + 3_601).is_redeemable_at(now));
        assert!(StoredToken {
            msg: "11".repeat(32),
            token: "22".repeat(256),
        }
        .is_redeemable_at(now));
        assert!(!StoredToken {
            msg: "not-hex".to_string(),
            token: "22".repeat(256),
        }
        .is_redeemable_at(now));
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(to_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(from_hex("00abff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(from_hex("xyz"), None);
        assert_eq!(from_hex("abc"), None); // odd length
        assert!(is_exact_lower_hex("00abff", 6));
        assert!(!is_exact_lower_hex("00ABff", 6));
        assert!(!is_exact_lower_hex(" 00abff", 6));
    }

    #[test]
    fn rejects_plaintext_remote_portal_url_before_request() {
        let client = TokenClient::with_base_url("http://portal.example.com".to_string());
        assert!(matches!(
            client.ensure_safe_base_url(),
            Err(TokenError::UnsafeUrl(_))
        ));
    }

    #[test]
    fn checkout_status_mapping_handles_unsupported_and_errors() {
        // Success: no error. The actual reference parse is wire-tested in nil-proto.
        assert!(checkout_error_for_status(200).is_none());
        assert!(checkout_error_for_status(201).is_none());
        // A Portal that predates the checkout endpoint → graceful fallback signal.
        assert!(matches!(
            checkout_error_for_status(404),
            Some(TokenError::CheckoutUnsupported)
        ));
        assert!(matches!(
            checkout_error_for_status(405),
            Some(TokenError::CheckoutUnsupported)
        ));
        // Any other non-2xx is surfaced as a rejection with its code (no fallback).
        assert!(matches!(
            checkout_error_for_status(503),
            Some(TokenError::IssuerRejected(503))
        ));
        assert!(matches!(
            checkout_error_for_status(429),
            Some(TokenError::IssuerRejected(429))
        ));
    }

    #[test]
    fn issuer_key_pin_fails_closed_on_an_unexpected_key() {
        let mut client = TokenClient::with_base_url("https://portal.example.com".to_string());

        // No pin configured → any issuer key is accepted (default alpha behavior).
        client.pinned_issuer_keys = Vec::new();
        client.issuer_pin_required = false;
        assert!(client.check_issuer_pubkey(&[9, 9, 9]).is_ok());

        // Pin configured → only a pinned key is accepted; anything else fails closed.
        client.pinned_issuer_keys = vec![vec![1, 2, 3], vec![4, 5, 6]];
        client.issuer_pin_required = true;
        assert!(
            client.check_issuer_pubkey(&[1, 2, 3]).is_ok(),
            "a pinned key is accepted"
        );
        assert!(
            client.check_issuer_pubkey(&[4, 5, 6]).is_ok(),
            "a second pinned key is accepted"
        );
        assert!(
            matches!(
                client.check_issuer_pubkey(&[7, 8, 9]),
                Err(TokenError::UnexpectedIssuerKey)
            ),
            "an unpinned key must be refused (anti key-tagging)"
        );

        // An embedded set narrowed to no key is still pinned and rejects all keys (never fail open).
        client.pinned_issuer_keys.clear();
        assert!(matches!(
            client.check_issuer_pubkey(&[1, 2, 3]),
            Err(TokenError::UnexpectedIssuerKey)
        ));
    }

    #[test]
    fn accepts_https_portal_urls() {
        let https = TokenClient::with_base_url("https://portal.example.com".to_string());
        assert!(https.ensure_safe_base_url().is_ok());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_accepts_loopback_portal_urls() {
        let local = TokenClient::with_base_url("http://127.0.0.1:8080".to_string());
        assert!(local.ensure_safe_base_url().is_ok());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_rejects_loopback_portal_urls() {
        let local = TokenClient::with_base_url("http://127.0.0.1:8080".to_string());
        assert!(matches!(
            local.ensure_safe_base_url(),
            Err(TokenError::UnsafeUrl(_))
        ));
    }

    #[tokio::test]
    async fn mint_batch_rejects_invalid_sizes_before_network_or_auth() {
        let client = TokenClient::with_base_url("https://portal.example.com".to_string());
        let material = AccountAuthMaterial {
            account_number: "11".repeat(32),
            auth_seed: "22".repeat(32),
        };
        for count in [0, MAX_MINT_BATCH_SIZE + 1, usize::MAX] {
            assert!(matches!(
                client.mint_batch(&material, count).await,
                Err(TokenError::InvalidBatchSize(actual)) if actual == count
            ));
        }
    }

    #[test]
    fn batch_finalization_preserves_order_and_rejects_bad_response_shapes() {
        let issuer = nil_crypto::token::Issuer::generate().unwrap();
        let public_der = issuer.public_der().unwrap();
        let messages = nil_crypto::token::new_v2_message_batch(4).unwrap();
        let requests = messages
            .iter()
            .map(|message| nil_crypto::token::blind(&public_der, message).unwrap())
            .collect::<Vec<_>>();
        let signatures = requests
            .iter()
            .map(|request| to_hex(&issuer.blind_sign(&request.blind_msg).unwrap()))
            .collect::<Vec<_>>();

        let tokens = finalize_mint_batch(&public_der, requests, signatures.clone()).unwrap();
        assert_eq!(
            tokens
                .iter()
                .map(|token| token.msg.clone())
                .collect::<Vec<_>>(),
            messages
                .iter()
                .map(|message| to_hex(message))
                .collect::<Vec<_>>()
        );
        let verifier = nil_crypto::token::Verifier::from_public_der(&public_der).unwrap();
        assert!(tokens.iter().all(|token| verifier.verify(
            &from_hex(&token.token).unwrap(),
            &from_hex(&token.msg).unwrap()
        )));

        let reordered_requests = messages
            .iter()
            .take(2)
            .map(|message| nil_crypto::token::blind(&public_der, message).unwrap())
            .collect::<Vec<_>>();
        let mut reordered_signatures = reordered_requests
            .iter()
            .map(|request| to_hex(&issuer.blind_sign(&request.blind_msg).unwrap()))
            .collect::<Vec<_>>();
        reordered_signatures.swap(0, 1);
        assert!(matches!(
            finalize_mint_batch(&public_der, reordered_requests, reordered_signatures),
            Err(TokenError::Crypto(_))
        ));

        let one_request = vec![nil_crypto::token::blind(&public_der, &messages[0]).unwrap()];
        assert!(matches!(
            finalize_mint_batch(&public_der, one_request, Vec::new()),
            Err(TokenError::BatchLengthMismatch {
                expected: 1,
                actual: 0
            })
        ));
        let one_request = vec![nil_crypto::token::blind(&public_der, &messages[0]).unwrap()];
        let mut uppercase = signatures[0].clone();
        uppercase.replace_range(..1, "A");
        assert!(matches!(
            finalize_mint_batch(&public_der, one_request, vec![uppercase]),
            Err(TokenError::Crypto(_))
        ));
    }

    #[test]
    fn stored_token_debug_never_exposes_bearer_material() {
        let stored = StoredToken {
            msg: "ab".repeat(32),
            token: "cd".repeat(nil_crypto::token::TOKEN_MODULUS_BITS / 8),
        };
        let rendered = format!("{stored:?}");
        assert_eq!(rendered, "StoredToken([REDACTED])");
        assert!(!rendered.contains(&stored.msg));
        assert!(!rendered.contains(&stored.token));
    }
}
