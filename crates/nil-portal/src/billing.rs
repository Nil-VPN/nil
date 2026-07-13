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
//! becomes (PD-3/PD-4: who-pays is separated from what-flows). The pending set is a bounded,
//! TTL-pruned [`nil_core::durable::TimedDurableSet`] of these opaque references and holds nothing
//! identifying.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};

use crate::client_ip::ClientIp;
use nil_core::durable::TimedInsert;
use nil_proto::token::CheckoutResponse;

use crate::tokens::TokenState;

/// Length of a minted reference in bytes (256 bits). A Monero short payment id is 8 bytes (16
/// hex) — see [`crate::monero`] for why short ids are deprecated; a 32-byte reference here is
/// independent of the on-chain id width and is what we gate issuance on regardless.
const REFERENCE_BYTES: usize = 32;

/// Checkout creation is intentionally much cheaper than signing, but it still consumes CSPRNG,
/// durable append, and pending-set space. This transient source cap is separate from issuance.
pub(crate) const DEFAULT_CHECKOUT_RATE_MAX: u32 = 30;
pub(crate) const CHECKOUT_RATE_WINDOW: Duration = Duration::from_secs(60);
/// Hard upper bound on pending checkout references between TTL pruning cycles. At 65 bytes of
/// opaque reference plus timestamp text per append this is operationally modest while leaving
/// substantial headroom for legitimate traffic. Production may tune it explicitly.
pub(crate) const DEFAULT_PENDING_CHECKOUT_MAX: usize = 100_000;

/// Mint a fresh, unguessable payment reference (lowercase hex). 256 bits from the OS CSPRNG.
/// Shared with the subscription flow (`crate::subscription`), which mints references the same way.
pub(crate) fn mint_reference() -> Result<String, getrandom::Error> {
    let mut raw = [0u8; REFERENCE_BYTES];
    getrandom::getrandom(&mut raw)?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn billing_router(state: TokenState) -> Router {
    Router::new()
        .route("/v1/billing/checkout", post(checkout))
        .with_state(state)
}

/// `POST /v1/billing/checkout` — mint a pending payment reference and return it. No request body
/// is required (a plan/price selector can be added later without changing the privacy posture).
async fn checkout(
    ClientIp(client_ip): ClientIp,
    State(state): State<TokenState>,
) -> Result<Json<CheckoutResponse>, StatusCode> {
    if !state.checkout_limiter.check(&client_ip.to_string()) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    // Cheap preliminary guard before entropy or fsync. `insert_if_below_capacity` repeats this
    // under the set mutex, closing races between concurrent requests.
    if state.pending.len() >= state.pending_checkout_max {
        tracing::warn!(
            cap = state.pending_checkout_max,
            "pending checkout cap reached; refusing new checkout"
        );
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let reference = mint_reference().map_err(|e| {
        // Never log the reference itself; only that minting failed.
        tracing::error!("checkout reference CSPRNG failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    // Record as pending BEFORE returning it, durably. A reference handed to a buyer but not
    // persisted would be rejected at issuance after a restart (fail-closed) — recording first
    // avoids charging a buyer for a reference we'd later refuse.
    match state.pending.insert_if_below_capacity(
        &reference,
        nil_core::grant::now_unix_secs(),
        state.pending_checkout_max,
    ) {
        Ok(TimedInsert::Inserted) => Ok(Json(CheckoutResponse {
            payment_reference: reference,
        })),
        // A 256-bit collision is cryptographically impossible; treat it as an error rather than
        // hand back a reference already bound to another (possibly paid) checkout.
        Ok(TimedInsert::AlreadyPresent) => {
            tracing::error!("checkout reference collision (impossible) — refusing");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Ok(TimedInsert::CapacityReached) => {
            tracing::warn!(
                cap = state.pending_checkout_max,
                "pending checkout cap reached during concurrent admission"
            );
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
        Err(e) => {
            tracing::error!("checkout pending-set persist failed: {e}");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// Whether `reference` is one this Portal minted via checkout (i.e. issuance is allowed to
/// proceed for it once the payment also confirms). Used by [`crate::tokens::issue_logic`].
pub fn is_known_reference(
    pending: &Arc<nil_core::durable::TimedDurableSet>,
    reference: &str,
) -> bool {
    pending.contains(reference)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::monero::MockWatcher;
    use crate::tokens::{issue_logic, IssueError};
    use nil_crypto::{token, Issuer};
    use nil_proto::token::IssueRequest;

    fn peer(last_octet: u8) -> ClientIp {
        ClientIp(std::net::IpAddr::from([198, 51, 100, last_octet]))
    }

    #[tokio::test]
    async fn checkout_is_source_limited_and_globally_capacity_bounded() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let watcher = Arc::new(MockWatcher::with_paid(Vec::<String>::new()));
        let capped = TokenState::new(issuer.clone(), watcher.clone()).with_checkout_limits(10, 0);
        assert_eq!(
            checkout(peer(1), State(capped)).await.unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE,
            "zero capacity refuses before creating a reference"
        );

        let limited = TokenState::new(issuer, watcher).with_checkout_limits(1, 10);
        assert!(checkout(peer(1), State(limited.clone())).await.is_ok());
        assert_eq!(
            checkout(peer(1), State(limited.clone())).await.unwrap_err(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert!(
            checkout(peer(2), State(limited.clone())).await.is_ok(),
            "a distinct direct source has a separate transient bucket"
        );
        assert_eq!(limited.pending.len(), 2);
    }

    #[test]
    fn minted_references_are_256_bit_hex_and_unique() {
        let a = mint_reference().expect("mint");
        let b = mint_reference().expect("mint");
        assert_eq!(a.len(), REFERENCE_BYTES * 2, "32 bytes => 64 hex chars");
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two mints must not collide");
    }

    #[tokio::test]
    async fn issuance_requires_a_minted_reference_even_when_the_payment_confirmed() {
        // Front-running scenario: the attacker knows a confirmed payment id but it was NOT minted
        // by our checkout. Issuance must refuse it.
        let issuer = Arc::new(Issuer::generate().unwrap());
        let pub_der = issuer.public_der().unwrap();
        let stolen_id = "deadbeefdeadbeef".to_string();
        // The buyer's legitimate checkout reference, minted server-side.
        let reference = mint_reference().unwrap();
        // The chain has confirmed BOTH the stolen id and the buyer's reference.
        let watcher = Arc::new(MockWatcher::with_paid([
            stolen_id.clone(),
            reference.clone(),
        ]));
        let state = TokenState::new(issuer, watcher);

        let msg = b"token-nonce-0123456789abcdef0123".to_vec();
        let req = token::blind(&pub_der, &msg).unwrap();
        let hexmsg: String = req.blind_msg.iter().map(|b| format!("{b:02x}")).collect();

        // Confirmed on chain, but never minted via checkout → rejected (the guard).
        let stolen = IssueRequest {
            payment_id: stolen_id,
            blind_msg: hexmsg.clone(),
        };
        assert!(matches!(
            issue_logic(&state, &stolen).await,
            Err(IssueError::UnknownReference)
        ));

        // The buyer's reference WAS minted via checkout (recorded pending) and is confirmed →
        // issuance succeeds.
        state.pending.insert(&reference, 0).unwrap();
        let ok = IssueRequest {
            payment_id: reference,
            blind_msg: hexmsg,
        };
        assert!(issue_logic(&state, &ok).await.is_ok());
    }

    #[tokio::test]
    async fn pruning_a_stale_pending_reference_fails_issuance_closed_without_double_issue() {
        // A checkout reference minted at t=100, then a confirmed payment for it.
        let issuer = Arc::new(Issuer::generate().unwrap());
        let pub_der = issuer.public_der().unwrap();
        let reference = mint_reference().unwrap();
        let watcher = Arc::new(MockWatcher::with_paid([reference.clone()]));
        let state = TokenState::new(issuer, watcher);
        state.pending.insert(&reference, 100).unwrap();

        let msg = b"token-nonce-0123456789abcdef0123".to_vec();
        let req = token::blind(&pub_der, &msg).unwrap();
        let hexmsg: String = req.blind_msg.iter().map(|b| format!("{b:02x}")).collect();

        // TTL prune removes the stale reference (inserted at 100, cutoff 1000) → issuance now
        // fails CLOSED with UnknownReference (402), never granting a token for the pruned checkout.
        assert_eq!(state.pending.prune_older_than(1000).unwrap(), 1);
        let after = IssueRequest {
            payment_id: reference.clone(),
            blind_msg: hexmsg.clone(),
        };
        assert!(matches!(
            issue_logic(&state, &after).await,
            Err(IssueError::UnknownReference)
        ));

        // And the one-token-per-payment guard (the SEPARATE issued set) is untouched by pruning:
        // re-minting the reference + re-confirming lets issuance succeed exactly ONCE, then 409.
        state.pending.insert(&reference, 2000).unwrap();
        let again = IssueRequest {
            payment_id: reference,
            blind_msg: hexmsg,
        };
        assert!(
            issue_logic(&state, &again).await.is_ok(),
            "a fresh checkout for the ref issues once"
        );
        assert!(
            issue_logic(&state, &again).await.is_ok(),
            "an identical retry returns the cached result"
        );
        let second_request = token::blind(&pub_der, b"different-token-0123456789abcdef01").unwrap();
        let rebound = IssueRequest {
            payment_id: again.payment_id.clone(),
            blind_msg: second_request
                .blind_msg
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        };
        assert!(
            matches!(
                issue_logic(&state, &rebound).await,
                Err(IssueError::AlreadyIssued)
            ),
            "a different blinded request cannot reuse the payment"
        );
    }
}
