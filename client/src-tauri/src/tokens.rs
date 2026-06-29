//! Client-side Privacy Pass token acquisition (User plane → Business plane only).
//!
//! Mirrors `nil-provision`: `GET /v1/tokens/pubkey` → blind a fresh random message LOCALLY →
//! `POST /v1/tokens/issue` (the Portal blind-signs, gated on a confirmed payment) → finalize
//! (unblind). The Portal never sees the unblinded token, so its signature cannot be linked to the
//! token the Coordinator later redeems — that is Pillar 4 (payment ⊥ usage). The acquired token is
//! a bearer credential; it is persisted by [`crate::tokenstore`] and is mathematically UNLINKABLE
//! to the account or payment.
//!
//! Privacy: this module talks ONLY to the Portal and never sees a packet. It logs **counts only** —
//! never a payment id, message, token, or blind signature (PD-2).

use serde::{Deserialize, Serialize};
use std::time::Duration;

use nil_proto::account::MintRequest;
use nil_proto::token::{CheckoutResponse, IssueRequest, IssueResponse, PubKeyResponse};

use crate::authstore::AccountAuthMaterial;

const DEFAULT_PORTAL_URL: &str = "http://127.0.0.1:8080";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// One unblinded, redeemable token (both fields lowercase hex). `msg` is the nullifier key the
/// Coordinator records on redemption; `token` is the issuer's signature over `msg`. We store ONLY
/// these two values — never an account number, payment id, or timestamp alongside them — because
/// the blinding makes them unlinkable to the purchase (storing more would re-create the link).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredToken {
    pub msg: String,
    pub token: String,
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
    #[error("couldn't reach the token service — is nil-portal running? ({0})")]
    Unreachable(String),
    #[error("{0}")]
    UnsafeUrl(String),
    #[error("token crypto failed: {0}")]
    Crypto(String),
    #[error("token storage failed: {0}")]
    Storage(String),
}

/// Talks to the Portal's token issuer. Built lazily (never connects at startup); reads `PORTAL_URL`.
#[derive(Clone)]
pub struct TokenClient {
    http: reqwest::Client,
    base_url: String,
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
        TokenClient {
            http: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("reqwest client"),
            base_url,
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

        // 2. Blind a fresh random 32-byte message. The blinding secret never leaves this process.
        let mut msg = [0u8; 32];
        getrandom::getrandom(&mut msg).map_err(|e| TokenError::Crypto(format!("rng: {e}")))?;
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

        // 4. Unblind → the final, unlinkable token.
        let tok = nil_crypto::token::finalize(&pubkey_der, &req, &blind_sig)
            .map_err(|e| TokenError::Crypto(e.to_string()))?;
        tracing::info!("acquired 1 Privacy Pass token");
        Ok(StoredToken {
            msg: to_hex(&msg),
            token: to_hex(&tok),
        })
    }

    /// Mint ONE unblinded token against an ACTIVE subscription (ADR-0007). Mirrors [`Self::acquire`]
    /// but gated on the account's subscription instead of a one-time payment: it proves account
    /// ownership (single-use challenge + signature) and calls `POST /v1/tokens/mint`. The blinding
    /// secret stays in this process; the Portal blind-signs without seeing `msg`, so the minted token
    /// stays unlinkable to the account. `402` ⇒ no active subscription ([`TokenError::NotSubscribed`]).
    pub async fn mint(&self, material: &AccountAuthMaterial) -> Result<StoredToken, TokenError> {
        self.ensure_safe_base_url()?;
        let base = self.base_url.trim_end_matches('/');

        // 1. Issuer pubkey → blind a fresh random message locally (the secret never leaves here).
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
        let mut msg = [0u8; 32];
        getrandom::getrandom(&mut msg).map_err(|e| TokenError::Crypto(format!("rng: {e}")))?;
        let req = nil_crypto::token::blind(&pubkey_der, &msg)
            .map_err(|e| TokenError::Crypto(e.to_string()))?;

        // 2. Prove account ownership (fresh single-use challenge per mint).
        let auth = crate::account::auth_proof(&self.http, base, material)
            .await
            .map_err(portal_err)?;

        // 3. Subscription-gated blind-sign.
        let mint = MintRequest { auth, blind_msg: to_hex(&req.blind_msg) };
        let resp = self
            .http
            .post(format!("{base}/v1/tokens/mint"))
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
        let issued: IssueResponse = resp.json().await.map_err(net_err)?;
        let blind_sig = from_hex(&issued.blind_sig)
            .ok_or_else(|| TokenError::Crypto("blind_sig not hex".into()))?;

        // 4. Unblind → the final, unlinkable token.
        let tok = nil_crypto::token::finalize(&pubkey_der, &req, &blind_sig)
            .map_err(|e| TokenError::Crypto(e.to_string()))?;
        tracing::info!("minted 1 Privacy Pass token (subscription)");
        Ok(StoredToken { msg: to_hex(&msg), token: to_hex(&tok) })
    }

    fn ensure_safe_base_url(&self) -> Result<(), TokenError> {
        if nil_core::net::env_flag("NW_INSECURE_CONTROL_PLANE") {
            return Ok(());
        }
        nil_core::net::require_tls_or_loopback(&self.base_url).map_err(TokenError::UnsafeUrl)
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
    fn hex_roundtrip() {
        assert_eq!(to_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(from_hex("00abff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(from_hex("xyz"), None);
        assert_eq!(from_hex("abc"), None); // odd length
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
        assert!(matches!(checkout_error_for_status(404), Some(TokenError::CheckoutUnsupported)));
        assert!(matches!(checkout_error_for_status(405), Some(TokenError::CheckoutUnsupported)));
        // Any other non-2xx is surfaced as a rejection with its code (no fallback).
        assert!(matches!(checkout_error_for_status(503), Some(TokenError::IssuerRejected(503))));
        assert!(matches!(checkout_error_for_status(429), Some(TokenError::IssuerRejected(429))));
    }

    #[test]
    fn accepts_https_and_loopback_portal_urls() {
        let https = TokenClient::with_base_url("https://portal.example.com".to_string());
        let local = TokenClient::with_base_url("http://127.0.0.1:8080".to_string());
        assert!(https.ensure_safe_base_url().is_ok());
        assert!(local.ensure_safe_base_url().is_ok());
    }
}
