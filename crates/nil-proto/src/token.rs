//! Privacy Pass token API DTOs (architecture spec §7). The issuer (Portal) and verifier
//! (Coordinator) live in separate trust domains; these are the shapes that cross the wire.
//! All byte fields are lowercase hex. Pure serde data.

use serde::{Deserialize, Serialize};

/// One authenticated subscription-mint request can refill this many anonymous tokens. The bound
/// keeps request buffering and issuer work predictable while amortizing account authentication.
pub const MAX_MINT_BATCH_SIZE: usize = 16;

/// RSA-2048 blinded messages and blind signatures are exactly 256 bytes / 512 lowercase-hex
/// characters on this protocol version.
pub const BLIND_TOKEN_HEX_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchSizeError {
    actual: usize,
}

impl BatchSizeError {
    pub fn actual(self) -> usize {
        self.actual
    }
}

impl std::fmt::Display for BatchSizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "batch must contain 1..={MAX_MINT_BATCH_SIZE} items, got {}",
            self.actual
        )
    }
}

impl std::error::Error for BatchSizeError {}

macro_rules! bounded_batch {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
        #[serde(transparent)]
        pub struct $name(Vec<String>);

        impl $name {
            pub fn as_slice(&self) -> &[String] {
                &self.0
            }

            pub fn iter(&self) -> impl ExactSizeIterator<Item = &String> {
                self.0.iter()
            }

            pub fn len(&self) -> usize {
                self.0.len()
            }

            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }

            pub fn into_vec(self) -> Vec<String> {
                self.0
            }
        }

        impl TryFrom<Vec<String>> for $name {
            type Error = BatchSizeError;

            fn try_from(values: Vec<String>) -> Result<Self, Self::Error> {
                if values.is_empty() || values.len() > MAX_MINT_BATCH_SIZE {
                    return Err(BatchSizeError {
                        actual: values.len(),
                    });
                }
                Ok(Self(values))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let values = Vec::<String>::deserialize(deserializer)?;
                Self::try_from(values).map_err(serde::de::Error::custom)
            }
        }
    };
}

bounded_batch!(BlindMessageBatch);
bounded_batch!(BlindSignatureBatch);

/// `POST /v1/billing/checkout` (Portal) response: the server-minted payment reference the buyer
/// uses as their Monero payment id and then passes as `payment_id` to `/v1/tokens/issue`. It is a
/// 256-bit CSPRNG value (lowercase hex), unguessable so it cannot be front-run. It indexes a
/// *payment*, never a person — same privacy class as the Monero payment id it becomes (PD-3/PD-4).
///
/// Shared here (not Portal-local) so the clients — `nil-provision` and the desktop `TokenClient`
/// — deserialize it with a typed DTO instead of poking at raw JSON. No identity fields, ever.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResponse {
    pub payment_reference: String,
}

/// `GET /v1/tokens/pubkey` (Portal): the issuer's public key (DER hex) — clients blind under
/// it and the Coordinator verifies with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyResponse {
    pub public_der: String,
}

/// `POST /v1/tokens/issue` (Portal): a blinded token request, gated on a confirmed payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueRequest {
    /// Reference to a confirmed payment (e.g. a Monero payment id / integrated-address tag).
    pub payment_id: String,
    /// The client's blinded token message (hex).
    pub blind_msg: String,
}

/// `POST /v1/tokens/issue` response: the issuer's blind signature (hex). The client unblinds
/// it locally into the token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueResponse {
    pub blind_sig: String,
}

/// `POST /v1/billing/webhook` (Portal): a Merchant-of-Record payment event. The MoR knows the
/// payer's card identity; NIL receives only the OPAQUE processor transaction id (for the
/// processor's own replay idempotency) and the server-minted `payment_reference` (the same opaque
/// value the buyer got from `/v1/billing/checkout`). No card number, email, name, or amount ever
/// crosses this DTO — the MoR validates the amount on its side; NIL needs only "this reference is
/// paid / refunded" (PD-3/PD-4: who-pays stays at the MoR, never linked to traffic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// The processor event class. A confirmed-payment class marks the reference paid; a
    /// refund/chargeback class revokes it. Unrecognised values are acknowledged and ignored.
    pub event_type: String,
    /// The processor's opaque transaction id — only for the processor's idempotent retries.
    pub transaction_id: String,
    /// The server-minted checkout reference this payment is for (the buyer passed it as MoR custom
    /// data). Same opaque 256-bit value `/v1/billing/checkout` returned; indexes a payment, never a
    /// person.
    pub payment_reference: String,
}

/// `POST /v1/redeem` (Coordinator): redeem an unblinded token for a trust-split path. The
/// Coordinator verifies the token (public key), checks it against the spent-token nullifier
/// set, and — only on success — returns the path. It learns *that* a valid token was redeemed,
/// never *which* purchase produced it (blinding) and never any identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemRequest {
    /// The unblinded token message (hex) — also the nullifier key.
    pub msg: String,
    /// The issuer's signature over `msg` (hex) — the token proper.
    pub token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_batches_reject_empty_and_oversized_arrays_during_deserialization() {
        assert!(serde_json::from_str::<BlindMessageBatch>("[]").is_err());
        assert!(
            serde_json::from_value::<BlindMessageBatch>(serde_json::json!(vec![
                "aa";
                MAX_MINT_BATCH_SIZE
                    + 1
            ]))
            .is_err()
        );

        let maximum = BlindMessageBatch::try_from(vec!["aa".to_string(); MAX_MINT_BATCH_SIZE])
            .expect("the documented maximum is accepted");
        assert_eq!(maximum.len(), MAX_MINT_BATCH_SIZE);
        assert_eq!(
            BlindMessageBatch::try_from(Vec::new())
                .unwrap_err()
                .actual(),
            0
        );
    }

    #[test]
    fn signature_batches_use_the_same_nonempty_bound() {
        let batch = BlindSignatureBatch::try_from(vec!["bb".to_string(), "cc".to_string()])
            .expect("bounded response");
        let json = serde_json::to_string(&batch).unwrap();
        assert_eq!(json, r#"["bb","cc"]"#);
        assert_eq!(
            serde_json::from_str::<BlindSignatureBatch>(&json).unwrap(),
            batch
        );
        assert!(BlindSignatureBatch::try_from(Vec::new()).is_err());
    }

    #[test]
    fn checkout_response_wire_shape_is_a_single_opaque_reference() {
        // The shared DTO both clients (nil-provision, desktop TokenClient) and the Portal use. It
        // must carry ONLY the opaque reference — no identity fields — and round-trip by field name
        // so a hardened Portal's response deserializes on the client.
        let json = r#"{"payment_reference":"deadbeef00"}"#;
        let co: CheckoutResponse = serde_json::from_str(json).expect("parse checkout response");
        assert_eq!(co.payment_reference, "deadbeef00");
        let back = serde_json::to_string(&co).expect("serialize");
        assert!(back.contains("payment_reference"));
        // Privacy tripwire: nothing identity- or payment-amount-linkable rides on this DTO.
        assert!(!back.contains("account") && !back.contains("email") && !back.contains("amount"));
    }

    #[test]
    fn webhook_event_carries_no_identity_or_amount() {
        // The MoR webhook DTO must surface ONLY the event class + opaque ids — never card/email/
        // name/amount, so a hostile/curious Portal log or store can't learn who-pays from it.
        let ev = WebhookEvent {
            event_type: "confirmed".into(),
            transaction_id: "txn_opaque_123".into(),
            payment_reference: "deadbeef".into(),
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        for forbidden in ["card", "email", "name", "amount", "cardholder", "billing"] {
            assert!(
                !json.contains(forbidden),
                "WebhookEvent must not carry {forbidden:?}"
            );
        }
        // And it round-trips by field name from a processor body.
        let back: WebhookEvent = serde_json::from_str(
            r#"{"event_type":"refund","transaction_id":"t","payment_reference":"r"}"#,
        )
        .expect("parse");
        assert_eq!(back.event_type, "refund");
    }
}
