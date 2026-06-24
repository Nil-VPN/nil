//! Privacy Pass token API DTOs (architecture spec §7). The issuer (Portal) and verifier
//! (Coordinator) live in separate trust domains; these are the shapes that cross the wire.
//! All byte fields are lowercase hex. Pure serde data.

use serde::{Deserialize, Serialize};

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
}
