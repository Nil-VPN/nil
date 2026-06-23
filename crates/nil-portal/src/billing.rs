//! Checkout: server-minted, unguessable payment references (architecture spec §7, Pillar 4).
//!
//! ## Why this exists — the front-running fix
//! Token issuance is gated on a *confirmed Monero payment*. Before checkout, the `payment_id`
//! on `/v1/tokens/issue` was a free client string: anyone who learned a confirmed payment id
//! (it is observable to the payer, and a short payment id is low-entropy) could race to redeem
//! it first and steal the token. Whoever submitted a confirmed id first won.
//!
//! Checkout closes that race. `POST /v1/billing/checkout` mints a high-entropy (256-bit),
//! server-generated reference, records it as *pending*, and returns it. The buyer uses that
//! reference as the Monero payment id (e.g. an integrated-address tag) when they pay. Issuance
//! now requires BOTH that the reference is one we minted (in the pending set) AND that it is
//! confirmed on-chain. An attacker cannot front-run because they cannot guess a 256-bit
//! reference, and a reference that was never minted is rejected even if some payment confirmed.
//!
//! ## Privacy
//! The reference indexes a *payment*, never a person — there is no account, email, IP, or
//! traffic anywhere near it. It is exactly the same privacy class as the Monero payment id it
//! becomes (PD-3/PD-4: who-pays is separated from what-flows). The pending set is a
//! [`DurableSet`] of these opaque references and holds nothing identifying.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Json, Router};
use axum::routing::post;
use serde::{Deserialize, Serialize};

use crate::tokens::TokenState;

/// `POST /v1/billing/checkout` response: the server-minted payment reference the buyer must use
/// as their Monero payment id. Lowercase hex, 256 bits of CSPRNG entropy — unguessable, so it
/// cannot be front-run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResponse {
    /// The opaque payment reference. Use this as the Monero payment id when paying, then pass it
    /// as `payment_id` to `/v1/tokens/issue`.
    pub payment_reference: String,
}

/// Length of a minted reference in bytes (256 bits). A Monero short payment id is 8 bytes (16
/// hex) — see [`crate::monero`] for why short ids are deprecated; a 32-byte reference here is
/// independent of the on-chain id width and is what we gate issuance on regardless.
const REFERENCE_BYTES: usize = 32;

/// Mint a fresh, unguessable payment reference (lowercase hex). 256 bits from the OS CSPRNG.
fn mint_reference() -> Result<String, getrandom::Error> {
    let mut raw = [0u8; REFERENCE_BYTES];
    getrandom::getrandom(&mut raw)?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn billing_router(state: TokenState) -> Router {
    Router::new().route("/v1/billing/checkout", post(checkout)).with_state(state)
}

/// `POST /v1/billing/checkout` — mint a pending payment reference and return it. No request body
/// is required (a plan/price selector can be added later without changing the privacy posture).
async fn checkout(State(state): State<TokenState>) -> Result<Json<CheckoutResponse>, StatusCode> {
    let reference = mint_reference().map_err(|e| {
        // Never log the reference itself; only that minting failed.
        tracing::error!("checkout reference CSPRNG failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    // Record as pending BEFORE returning it, durably. A reference handed to a buyer but not
    // persisted would be rejected at issuance after a restart (fail-closed) — recording first
    // avoids charging a buyer for a reference we'd later refuse.
    match state.pending.insert(&reference) {
        Ok(true) => Ok(Json(CheckoutResponse { payment_reference: reference })),
        // A 256-bit collision is cryptographically impossible; treat it as an error rather than
        // hand back a reference already bound to another (possibly paid) checkout.
        Ok(false) => {
            tracing::error!("checkout reference collision (impossible) — refusing");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(e) => {
            tracing::error!("checkout pending-set persist failed: {e}");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// Whether `reference` is one this Portal minted via checkout (i.e. issuance is allowed to
/// proceed for it once the payment also confirms). Used by [`crate::tokens::issue_logic`].
pub fn is_known_reference(pending: &Arc<nil_core::durable::DurableSet>, reference: &str) -> bool {
    pending.contains(reference)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::monero::MockWatcher;
    use crate::tokens::{issue_logic, IssueError};
    use nil_crypto::{token, Issuer};
    use nil_proto::token::IssueRequest;

    #[test]
    fn minted_references_are_256_bit_hex_and_unique() {
        let a = mint_reference().expect("mint");
        let b = mint_reference().expect("mint");
        assert_eq!(a.len(), REFERENCE_BYTES * 2, "32 bytes => 64 hex chars");
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two mints must not collide");
    }

    #[test]
    fn issuance_requires_a_minted_reference_even_when_the_payment_confirmed() {
        // Front-running scenario: the attacker knows a confirmed payment id but it was NOT minted
        // by our checkout. Issuance must refuse it.
        let issuer = Arc::new(Issuer::generate().unwrap());
        let pub_der = issuer.public_der().unwrap();
        let stolen_id = "deadbeefdeadbeef".to_string();
        // The buyer's legitimate checkout reference, minted server-side.
        let reference = mint_reference().unwrap();
        // The chain has confirmed BOTH the stolen id and the buyer's reference.
        let watcher = Arc::new(MockWatcher::with_paid([stolen_id.clone(), reference.clone()]));
        let state = TokenState::new(issuer, watcher);

        let msg = b"token-nonce-0123456789abcdef0123".to_vec();
        let req = token::blind(&pub_der, &msg).unwrap();
        let hexmsg: String = req.blind_msg.iter().map(|b| format!("{b:02x}")).collect();

        // Confirmed on chain, but never minted via checkout → rejected (the guard).
        let stolen = IssueRequest { payment_id: stolen_id, blind_msg: hexmsg.clone() };
        assert!(matches!(issue_logic(&state, &stolen), Err(IssueError::UnknownReference)));

        // The buyer's reference WAS minted via checkout (recorded pending) and is confirmed →
        // issuance succeeds.
        state.pending.insert(&reference).unwrap();
        let ok = IssueRequest { payment_id: reference, blind_msg: hexmsg };
        assert!(issue_logic(&state, &ok).is_ok());
    }
}
