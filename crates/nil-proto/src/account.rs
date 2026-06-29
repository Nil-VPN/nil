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
    /// Subscription expiry (unix secs) iff `entitlement == Active`; lets the client show
    /// "Active until …". Additive + optional so older clients (which read `entitlement` as a bare
    /// string) keep working. Tied to the anonymous account, never to a person (ADR-0007).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
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

/// Response for `POST /v1/account/challenge` — a single-use, short-TTL nonce the client signs with
/// its account auth key to prove ownership (ADR-0007). The nonce is opaque and non-identifying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Lowercase-hex challenge nonce. The client signs these ASCII bytes with its auth key.
    pub challenge: String,
}

/// Proof of account ownership attached to an authenticated request (e.g. mint, account-tied
/// checkout). All three fields are anonymous: the account number is `H(secret)`, the auth key is a
/// per-account anonymous key, and the challenge is a throwaway nonce. Nothing identity-bearing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountAuth {
    /// Lowercase hex of the 32-byte account number (`H(secret)`), as the client derives from the
    /// recovery phrase. The Portal uses it as the store lookup key.
    pub account_number: String,
    /// The challenge nonce returned by `POST /v1/account/challenge` (echoed back).
    pub challenge: String,
    /// Lowercase hex of the 64-byte Ed25519 signature over the challenge's ASCII bytes.
    pub signature: String,
}

/// Response for `POST /v1/account/status` — the authenticated subscription state. Status only,
/// never any identity (the caller already knows which account it authenticated as).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountStatusResponse {
    pub entitlement: EntitlementDto,
    /// Subscription expiry (unix secs) iff `entitlement == Active` — lets the client show
    /// "Active until …". Tied to the anonymous account, never to a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

/// Request body for `POST /v1/billing/activate` — claim a confirmed payment to activate/extend the
/// authenticated account's subscription (ADR-0007). The `payment_reference` is the one returned by
/// `POST /v1/billing/subscribe`; the auth proof binds the claim to the account that subscribed, so a
/// confirmed reference can only ever extend the account that created it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivateRequest {
    pub auth: AccountAuth,
    pub payment_reference: String,
}

/// Request body for `POST /v1/tokens/mint` — an authenticated, subscription-gated blind-token mint
/// (ADR-0007). The same blind-sign path as one-shot issuance, but gated on an *active subscription*
/// (rate-capped per account) instead of a one-time payment. The issuer never sees the unblinded
/// token, so mint↔redeem stays unlinkable (account↔connection unlinkability holds). The response is
/// a [`crate::token::IssueResponse`] (the blind signature; the client unblinds locally).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintRequest {
    pub auth: AccountAuth,
    /// Lowercase hex of the blinded token message (the client blinds locally, unblinds the reply).
    pub blind_msg: String,
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
