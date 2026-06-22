//! Account API DTOs for the Business plane (`nil-portal`).
//!
//! Mirrors architecture spec §7.5 / §13.3. The Business plane is the only plane that
//! handles these; nothing here ever reaches the control or data plane.

use serde::{Deserialize, Serialize};

/// Request body for `POST /v1/account`.
///
/// Internally tagged on `type`: `{"type":"anonymous"}` or
/// `{"type":"email","email":"a@b.c"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CreateAccountRequest {
    /// No-email account: the Portal generates the credential. Nothing personal is sent.
    Anonymous,
    /// Email account (Phase 0 stub): only an encrypted email would be retained.
    Email { email: String },
}

/// Response for a successful anonymous `POST /v1/account`.
///
/// The `recovery_phrase` is exactly 7 words and is shown to the user **once**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAccountResponse {
    pub account_number: String,
    pub recovery_phrase: Vec<String>,
    pub recovery_code: String,
}

/// Request body for `POST /v1/account/recover`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverRequest {
    pub recovery_phrase: Vec<String>,
    pub recovery_code: String,
}

/// Response for a successful recovery — status only, never any identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverResponse {
    pub account_number: String,
    pub entitlement: EntitlementDto,
}

/// Subscription/entitlement state. Carries no identity — just what the account is
/// entitled to. A freshly created account is [`EntitlementDto::None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntitlementDto {
    None,
    Active,
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_request_deserializes_from_type_tag() {
        let req: CreateAccountRequest = serde_json::from_str(r#"{"type":"anonymous"}"#).unwrap();
        assert_eq!(req, CreateAccountRequest::Anonymous);
    }

    #[test]
    fn email_request_deserializes_with_field() {
        let req: CreateAccountRequest =
            serde_json::from_str(r#"{"type":"email","email":"a@b.c"}"#).unwrap();
        assert_eq!(
            req,
            CreateAccountRequest::Email {
                email: "a@b.c".to_string()
            }
        );
    }

    #[test]
    fn create_response_shape_matches_spec() {
        let resp = CreateAccountResponse {
            account_number: "K7Q2M-9XR4T".to_string(),
            recovery_phrase: (1..=7).map(|i| format!("word{i}")).collect(),
            recovery_code: "XXXX-XXXX".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["recovery_phrase"].as_array().unwrap().len(), 7);
        assert!(json["account_number"].is_string());
        assert!(json["recovery_code"].is_string());
    }
}
