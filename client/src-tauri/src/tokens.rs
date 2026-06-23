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

use nil_proto::token::{IssueRequest, IssueResponse, PubKeyResponse};

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

    /// Acquire ONE unblinded token against a confirmed `payment_id`. The blinding secret stays in
    /// this process; the Portal blind-signs without ever seeing `msg`. The Portal enforces
    /// one-token-per-payment (a repeat → `AlreadyIssued`); top up with a new payment.
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

    fn ensure_safe_base_url(&self) -> Result<(), TokenError> {
        if nil_core::net::env_flag("NW_INSECURE_CONTROL_PLANE") {
            return Ok(());
        }
        nil_core::net::require_tls_or_loopback(&self.base_url).map_err(TokenError::UnsafeUrl)
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
    fn accepts_https_and_loopback_portal_urls() {
        let https = TokenClient::with_base_url("https://portal.example.com".to_string());
        let local = TokenClient::with_base_url("http://127.0.0.1:8080".to_string());
        assert!(https.ensure_safe_base_url().is_ok());
        assert!(local.ensure_safe_base_url().is_ok());
    }
}
