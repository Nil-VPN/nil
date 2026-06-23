//! Talks to the Business plane (`nil-portal`) over HTTP.
//!
//! Account creation is a real `POST /v1/account` to the Portal, so Phase 0 actually
//! validates the client↔Portal 7-word contract. The client is built lazily and never
//! connects at startup, so a Portal that is down surfaces as an error in the UI — it
//! never stops the app from launching (fail-soft).

use serde::{Deserialize, Serialize};
use std::time::Duration;

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

    fn ensure_safe_base_url(&self) -> Result<(), PortalError> {
        if nil_core::net::env_flag("NW_INSECURE_CONTROL_PLANE") {
            return Ok(());
        }
        nil_core::net::require_tls_or_loopback(&self.base_url).map_err(PortalError::UnsafeUrl)
    }
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
