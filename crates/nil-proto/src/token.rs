//! Privacy Pass token API DTOs (architecture spec §7). The issuer (Portal) and verifier
//! (Coordinator) live in separate trust domains; these are the shapes that cross the wire.
//! All byte fields are lowercase hex. Pure serde data.

use serde::{Deserialize, Serialize};

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
