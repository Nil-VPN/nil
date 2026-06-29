//! Talks to the Business plane (`nil-portal`) over HTTP.
//!
//! Account creation is a real `POST /v1/account` to the Portal, so Phase 0 actually
//! validates the client↔Portal 7-word contract. The client is built lazily and never
//! connects at startup, so a Portal that is down surfaces as an error in the UI — it
//! never stops the app from launching (fail-soft).

use serde::{Deserialize, Serialize};
use std::time::Duration;

use nil_proto::account::{AccountAuth, AccountStatusResponse, ActivateRequest, ChallengeResponse};
use nil_proto::token::CheckoutResponse;

use crate::authstore::AccountAuthMaterial;

const DEFAULT_PORTAL_URL: &str = "http://127.0.0.1:8080";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct PortalClient {
    http: reqwest::Client,
    base_url: String,
}

impl Default for PortalClient {
    fn default() -> Self {
        Self::from_env()
    }
}

impl PortalClient {
    /// Read `PORTAL_URL` (default `http://127.0.0.1:8080`). Does not connect.
    pub fn from_env() -> Self {
        let base_url =
            std::env::var("PORTAL_URL").unwrap_or_else(|_| DEFAULT_PORTAL_URL.to_string());
        Self::with_base_url(base_url)
    }

    /// Build against an explicit Portal URL (from the GUI config). Does not connect.
    pub fn with_base_url(base_url: String) -> Self {
        PortalClient {
            http: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("reqwest client"),
            base_url,
        }
    }

    pub async fn create_anonymous(&self) -> Result<AnonymousAccount, PortalError> {
        self.ensure_safe_base_url()?;
        self.http
            .post(format!("{}/v1/account", self.base_url))
            .json(&serde_json::json!({ "type": "anonymous" }))
            .send()
            .await?
            .error_for_status()?
            .json::<AnonymousAccount>()
            .await
            .map_err(Into::into)
    }

    pub async fn recover(
        &self,
        recovery_phrase: Vec<String>,
        recovery_code: String,
    ) -> Result<RecoverResult, PortalError> {
        self.ensure_safe_base_url()?;
        self.http
            .post(format!("{}/v1/account/recover", self.base_url))
            .json(&serde_json::json!({
                "recovery_phrase": recovery_phrase,
                "recovery_code": recovery_code,
            }))
            .send()
            .await?
            .error_for_status()?
            .json::<RecoverResult>()
            .await
            .map_err(Into::into)
    }

    /// Subscribe: prove account ownership, then mint a payment reference to pay (ADR-0007). The
    /// buyer pays the returned reference; [`Self::activate`] is polled once it confirms.
    pub async fn subscribe(
        &self,
        material: &AccountAuthMaterial,
    ) -> Result<CheckoutResponse, PortalError> {
        self.ensure_safe_base_url()?;
        let base = self.base_url.trim_end_matches('/');
        let auth = auth_proof(&self.http, base, material).await?;
        let resp = self
            .http
            .post(format!("{base}/v1/billing/subscribe"))
            .json(&auth)
            .send()
            .await?
            .error_for_status()?;
        resp.json().await.map_err(Into::into)
    }

    /// Claim a confirmed payment to activate/extend the subscription. Returns the new status; a
    /// not-yet-confirmed payment surfaces as [`PortalError::PaymentNotConfirmed`] so the caller
    /// polls at a wide interval (each call needs a fresh challenge — built here).
    pub async fn activate(
        &self,
        material: &AccountAuthMaterial,
        payment_reference: String,
    ) -> Result<AccountStatusResponse, PortalError> {
        self.ensure_safe_base_url()?;
        let base = self.base_url.trim_end_matches('/');
        let auth = auth_proof(&self.http, base, material).await?;
        let resp = self
            .http
            .post(format!("{base}/v1/billing/activate"))
            .json(&ActivateRequest { auth, payment_reference })
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(match status.as_u16() {
                402 => PortalError::PaymentNotConfirmed,
                401 => PortalError::Unauthorized,
                other => PortalError::Status(other.to_string()),
            });
        }
        resp.json().await.map_err(Into::into)
    }

    /// The authenticated subscription status (entitlement + expiry) — what a re-logged-in client
    /// calls to learn "am I still subscribed, and until when?".
    pub async fn status(
        &self,
        material: &AccountAuthMaterial,
    ) -> Result<AccountStatusResponse, PortalError> {
        self.ensure_safe_base_url()?;
        let base = self.base_url.trim_end_matches('/');
        let auth = auth_proof(&self.http, base, material).await?;
        let resp = self
            .http
            .post(format!("{base}/v1/account/status"))
            .json(&auth)
            .send()
            .await?
            .error_for_status()?;
        resp.json().await.map_err(Into::into)
    }

    fn ensure_safe_base_url(&self) -> Result<(), PortalError> {
        if nil_core::net::env_flag("NW_INSECURE_CONTROL_PLANE") {
            return Ok(());
        }
        nil_core::net::require_tls_or_loopback(&self.base_url).map_err(PortalError::UnsafeUrl)
    }
}

/// Fetch a single-use challenge and sign it with the account's cached auth key, producing the
/// [`AccountAuth`] proof attached to subscribe / activate / status / mint. Shared with the token
/// client's mint path (`crate::tokens`). The auth seed never leaves this process; only the public
/// signature crosses the wire. The challenge is signed over its ASCII bytes (matching the Portal).
pub async fn auth_proof(
    http: &reqwest::Client,
    base_url: &str,
    material: &AccountAuthMaterial,
) -> Result<AccountAuth, PortalError> {
    let base = base_url.trim_end_matches('/');
    let chal: ChallengeResponse = http
        .post(format!("{base}/v1/account/challenge"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let seed = parse_hex32(&material.auth_seed)
        .ok_or_else(|| PortalError::Crypto("cached auth seed is not 32-byte hex".into()))?;
    let kp = nil_crypto::account::AuthKeypair::from_seed(&seed);
    Ok(AccountAuth {
        account_number: material.account_number.clone(),
        signature: to_hex(&kp.sign(chal.challenge.as_bytes())),
        challenge: chal.challenge,
    })
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parse exactly 32 bytes of hex (64 chars), else `None`.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let h = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, p) in h.chunks_exact(2).enumerate() {
        out[i] = (nib(p[0])? << 4) | nib(p[1])?;
    }
    Some(out)
}

/// Response from anonymous signup — mirrors `nil-proto::CreateAccountResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousAccount {
    pub account_number: String,
    pub recovery_phrase: Vec<String>,
    pub recovery_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverResult {
    pub account_number: String,
    pub entitlement: String,
}

/// A mocked VPN location (Phase 0 — real path selection arrives with the Coordinator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub id: String,
    pub label: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PortalError {
    #[error("{0}")]
    UnsafeUrl(String),
    #[error("couldn't reach the account service — is nil-portal running? ({0})")]
    Unreachable(String),
    #[error("the account service returned an error ({0})")]
    Status(String),
    /// `POST /v1/billing/activate` before the payment confirmed — the caller polls and retries.
    #[error("payment not confirmed yet — wait for the payment to confirm, then try again")]
    PaymentNotConfirmed,
    /// The account auth proof was rejected (wrong key / expired challenge / no such account).
    #[error("account authentication failed")]
    Unauthorized,
    /// Local auth-material problem (e.g. the cached auth seed is malformed).
    #[error("account auth material error: {0}")]
    Crypto(String),
}

impl From<reqwest::Error> for PortalError {
    fn from(e: reqwest::Error) -> Self {
        if let Some(status) = e.status() {
            PortalError::Status(status.to_string())
        } else {
            PortalError::Unreachable(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plaintext_remote_portal_url_before_request() {
        let client = PortalClient::with_base_url("http://portal.example.com".to_string());
        assert!(matches!(
            client.ensure_safe_base_url(),
            Err(PortalError::UnsafeUrl(_))
        ));
    }

    #[test]
    fn accepts_https_and_loopback_portal_urls() {
        let https = PortalClient::with_base_url("https://portal.example.com".to_string());
        let local = PortalClient::with_base_url("http://127.0.0.1:8080".to_string());
        assert!(https.ensure_safe_base_url().is_ok());
        assert!(local.ensure_safe_base_url().is_ok());
    }
}
