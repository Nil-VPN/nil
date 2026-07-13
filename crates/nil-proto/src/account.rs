//! Account API DTOs for the Business plane (`nil-portal`).
//!
//! Mirrors architecture spec §7.5 / §13.3. The Business plane is the only plane that
//! handles these; nothing here ever reaches the control or data plane.

use serde::{Deserialize, Serialize};

/// Request body for `POST /v1/account`.
///
/// Internally tagged on `type`. Anonymous accounts are derived entirely by the client: the Portal
/// receives only the account's opaque identifier, public authentication key, and a proof that the
/// registering client possesses the corresponding private key. Recovery material never crosses
/// the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum CreateAccountRequest {
    /// No-email account. All values are exact lowercase hex: 32-byte account number, 32-byte
    /// Ed25519 public key, and 64-byte registration signature respectively.
    Anonymous {
        account_number: String,
        auth_pubkey: String,
        registration_signature: String,
    },
    /// Email account (Phase 0 stub): only an encrypted email would be retained.
    Email { email: String },
}

/// Response for a successful anonymous `POST /v1/account`.
///
/// The account number is returned as canonical lowercase 64-character hex. No secret or recovery
/// material is ever returned by the Portal because the client generated and retained it locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAccountResponse {
    pub account_number: String,
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

/// Original single-item request body for `POST /v1/tokens/mint`.
///
/// This wire shape is retained for v1 compatibility. The server derives its retry key from the
/// canonical authenticated account and decoded blinded request, so a fresh auth challenge can
/// safely retry the same operation without adding a required v1 field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintRequest {
    pub auth: AccountAuth,
    pub blind_msg: String,
}

/// Request body for `POST /v2/tokens/mint` — one account proof authenticates a bounded batch of
/// blinded messages. The Portal validates the complete batch before signing and charges abuse
/// limits by item count; it never sees any unblinded token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintBatchRequest {
    pub auth: AccountAuth,
    /// Fresh 256-bit lowercase-hex idempotency key. A retry uses the same value and ordered blind
    /// messages with a new single-use authentication challenge.
    pub request_id: String,
    pub blind_msgs: crate::token::BlindMessageBatch,
}

/// Same-order response for `POST /v2/tokens/mint`. Each signature corresponds to the blinded
/// message at the same array index; the client unblinds each one locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintBatchResponse {
    pub blind_sigs: crate::token::BlindSignatureBatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_request_deserializes_with_public_registration_material() {
        let account_number = "ab".repeat(32);
        let auth_pubkey = "cd".repeat(32);
        let registration_signature = "ef".repeat(64);
        let json = serde_json::json!({
            "type": "anonymous",
            "account_number": account_number,
            "auth_pubkey": auth_pubkey,
            "registration_signature": registration_signature,
        });
        let req: CreateAccountRequest = serde_json::from_value(json).unwrap();
        assert_eq!(
            req,
            CreateAccountRequest::Anonymous {
                account_number,
                auth_pubkey,
                registration_signature,
            }
        );
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
    fn anonymous_request_rejects_recovery_material() {
        let json = serde_json::json!({
            "type": "anonymous",
            "account_number": "ab".repeat(32),
            "auth_pubkey": "cd".repeat(32),
            "registration_signature": "ef".repeat(64),
            "recovery_phrase": ["must", "stay", "on", "the", "client"],
        });
        assert!(
            serde_json::from_value::<CreateAccountRequest>(json).is_err(),
            "recovery material must not be accepted by the registration protocol"
        );
    }

    #[test]
    fn create_response_shape_matches_spec() {
        let resp = CreateAccountResponse {
            account_number: "ab".repeat(32),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["account_number"], "ab".repeat(32));
        assert_eq!(
            json.as_object().unwrap().len(),
            1,
            "Portal returns no recovery material"
        );
    }

    #[test]
    fn v1_single_and_v2_batch_mint_shapes_are_versioned() {
        let auth = AccountAuth {
            account_number: "ab".repeat(32),
            challenge: "cd".repeat(32),
            signature: "ef".repeat(64),
        };
        let request = MintRequest {
            auth: auth.clone(),
            blind_msg: "11".repeat(256),
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["blind_msg"], "11".repeat(256));
        assert!(json.get("request_id").is_none());
        assert!(json.get("blind_msgs").is_none());
        assert_eq!(
            serde_json::from_value::<MintRequest>(json).unwrap(),
            request
        );

        let batch_request = MintBatchRequest {
            auth,
            request_id: "aa".repeat(32),
            blind_msgs: crate::token::BlindMessageBatch::try_from(vec![
                "11".repeat(256),
                "22".repeat(256),
            ])
            .unwrap(),
        };
        let json = serde_json::to_value(&batch_request).unwrap();
        assert_eq!(json["request_id"], "aa".repeat(32));
        assert_eq!(json["blind_msgs"].as_array().unwrap().len(), 2);
        assert!(json.get("blind_msg").is_none());
        assert_eq!(
            serde_json::from_value::<MintBatchRequest>(json).unwrap(),
            batch_request
        );

        let response = MintBatchResponse {
            blind_sigs: crate::token::BlindSignatureBatch::try_from(vec![
                "33".repeat(256),
                "44".repeat(256),
            ])
            .unwrap(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["blind_sigs"].as_array().unwrap().len(), 2);
        assert!(json.get("blind_sig").is_none());
    }
}
