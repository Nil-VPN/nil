//! Card payments via a **Merchant-of-Record** (Paddle / Lemon Squeezy), behind the
//! `card-payments` feature. A second payment rail alongside Monero — a freeze on one cannot down
//! the service.
//!
//! ## Why this mirrors the Monero watcher (and touches no account)
//! The MoR holds the payer's card identity and absorbs the sanctions/chargeback/compliance risk;
//! NIL receives only a signed webhook saying "this opaque checkout reference is paid / refunded".
//! So the card rail is just another [`PaymentWatcher`](crate::monero::PaymentWatcher): the webhook
//! marks a reference confirmed, and the EXISTING `tokens::issue_logic` gate (front-running guard +
//! one-token-per-payment) is reused unchanged. The webhook NEVER sees or stores a card number,
//! email, name, amount, or account — it deals only in the opaque reference, exactly like the Monero
//! payment id (PD-3/PD-4). Privacy Pass tokens are anonymous bearer credentials, so issuance is
//! account-independent by design; the webhook therefore never touches the account store.
//!
//! ## Honest limits (PD-8)
//! - Card payment is *pseudonymity*, not anonymity: the MoR knows the payer. Monero remains the
//!   blind-token rail. Marketing must not claim card payments or later use are uncorrelatable.
//! - Revocation blocks FUTURE issuance for a refunded/charged-back reference; an already-issued
//!   bearer token cannot be recalled (a property of Privacy Pass). The revoked set is durable.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use hmac::{Hmac, Mac};
use nil_core::durable::{DurableSet, TimedDurableSet};
use nil_proto::token::WebhookEvent;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::monero::PaymentWatcher;

/// A card-payment confirmation set the webhook updates. It is a [`PaymentWatcher`], so the existing
/// token-issue gate consults it exactly like the Monero watcher.
pub struct CardWatcher {
    /// References the MoR has confirmed paid. In-memory: a confirmation only matters until the buyer
    /// redeems their token; a restart that forgets it fails closed (the buyer re-triggers via the
    /// processor or support) — never re-issues.
    confirmed: Mutex<HashSet<String>>,
    /// Refunded / charged-back references — DURABLE so a revocation survives a restart (a refunded
    /// reference must never become issuable again).
    revoked: Arc<DurableSet>,
    /// The server-minted checkout references. A webhook may only confirm a reference that was
    /// actually minted by `/v1/billing/checkout` (fail-closed front-running guard, like Monero).
    pending: Arc<TimedDurableSet>,
}

impl CardWatcher {
    pub fn new(pending: Arc<TimedDurableSet>, revoked: Arc<DurableSet>) -> Self {
        Self {
            confirmed: Mutex::new(HashSet::new()),
            revoked,
            pending,
        }
    }

    /// Mark a checkout reference paid — ONLY if it was actually minted by `/v1/billing/checkout`
    /// (fail-closed: a webhook naming an unminted reference is ignored, mirroring the Monero
    /// front-running guard). Idempotent. Returns whether it was accepted.
    pub fn confirm(&self, reference: &str) -> bool {
        // Fail-closed: a refunded reference is NEVER re-confirmed (defense-in-depth — do not rely on
        // is_confirmed alone), and only a reference `/v1/billing/checkout` actually minted is
        // accepted (the front-running guard, mirroring Monero).
        if self.revoked.contains(reference) {
            return false;
        }
        if !self.pending.contains(reference) {
            return false;
        }
        if let Ok(mut c) = self.confirmed.lock() {
            c.insert(reference.to_string());
        }
        true
    }

    /// Revoke a reference (refund / chargeback): durably record it so future issuance is blocked,
    /// and drop it from the confirmed set. Idempotent. Already-issued bearer tokens cannot be
    /// recalled (honest limit).
    ///
    /// Fails closed: if the durable write fails it returns the error (the webhook then returns 500
    /// so the processor retries) and does NOT drop the in-memory confirmation — a lost revocation
    /// must never silently let a refunded payment be re-issued after a restart.
    pub fn revoke(&self, reference: &str) -> std::io::Result<()> {
        self.revoked.insert(reference)?; // persist FIRST; propagate Err on failure
        if let Ok(mut c) = self.confirmed.lock() {
            c.remove(reference);
        }
        Ok(())
    }
}

impl PaymentWatcher for CardWatcher {
    fn is_confirmed(&self, payment_id: &str) -> bool {
        // Revocation wins: a refunded reference is never confirmed, even if a stale/replayed
        // confirm re-added it.
        if self.revoked.contains(payment_id) {
            return false;
        }
        self.confirmed
            .lock()
            .map(|c| c.contains(payment_id))
            .unwrap_or(false)
    }
}

/// Dual-rail watcher: a payment is confirmed if ANY underlying rail confirms it (Monero OR card),
/// so a freeze on one rail can't deny issuance on the other.
pub struct CompositeWatcher {
    rails: Vec<Arc<dyn PaymentWatcher>>,
}

impl CompositeWatcher {
    pub fn new(rails: Vec<Arc<dyn PaymentWatcher>>) -> Self {
        Self { rails }
    }
}

impl PaymentWatcher for CompositeWatcher {
    fn is_confirmed(&self, payment_id: &str) -> bool {
        self.rails.iter().any(|w| w.is_confirmed(payment_id))
    }
}

/// Constant-time HMAC-SHA256 verification of `sig_hex` over the raw `body` with `secret`. MoR
/// processors (Lemon Squeezy `X-Signature`, Paddle `Paddle-Signature`) sign the raw request body
/// and send the hex MAC in a header.
fn verify_hmac(secret: &[u8], body: &[u8], sig_hex: &str) -> bool {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    let Some(provided) = nil_core::grant::from_hex(sig_hex.trim()) else {
        return false;
    };
    if provided.len() != expected.len() {
        return false;
    }
    expected.as_slice().ct_eq(provided.as_slice()).into()
}

/// Router state: the card watcher (shared with the composite payment watcher) + the MoR signing
/// secret. Cheap to clone (Arcs).
#[derive(Clone)]
pub struct CardState {
    card: Arc<CardWatcher>,
    secret: Arc<Vec<u8>>,
}

/// Hard cap on the webhook body. A MoR event JSON (Lemon Squeezy / Paddle) is well under 16 KiB.
/// Without it, Axum's 2 MiB default lets an unauthenticated caller force MiB-scale buffering (the
/// `Bytes` extractor buffers the full body BEFORE the HMAC check) on this un-rate-limited public
/// endpoint. Mirrors the ACCOUNT/TOKEN/MINT/SUB body-amplification guards on the sibling routers.
const WEBHOOK_BODY_LIMIT: usize = 16 * 1024;

/// `POST /v1/billing/webhook`: the MoR posts a signed payment event here.
pub fn cards_router(card: Arc<CardWatcher>, secret: Vec<u8>) -> Router {
    Router::new()
        .route("/v1/billing/webhook", post(webhook))
        .layer(DefaultBodyLimit::max(WEBHOOK_BODY_LIMIT))
        .with_state(CardState {
            card,
            secret: Arc::new(secret),
        })
}

/// HMAC-verify the raw body, then mark the reference paid (confirmed) or revoked
/// (refund/chargeback). Logs only the event class + outcome — never the reference, txn id, or any
/// identity (PD-3). `confirm`/`revoke` are idempotent, so a processor retry is safe.
async fn webhook(State(state): State<CardState>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let sig = headers
        .get("x-signature")
        .or_else(|| headers.get("paddle-signature"))
        .and_then(|v| v.to_str().ok());
    let Some(sig) = sig else {
        return StatusCode::BAD_REQUEST; // no signature header → reject
    };
    if !verify_hmac(&state.secret, &body, sig) {
        return StatusCode::FORBIDDEN; // bad signature → reject (no state change)
    }
    let Ok(event) = serde_json::from_slice::<WebhookEvent>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    if is_confirm_event(&event.event_type) {
        let accepted = state.card.confirm(&event.payment_reference);
        // No reference/txn in the log (PD-3) — only whether it matched a minted checkout.
        tracing::info!(accepted, "card webhook: payment-confirmed event");
        StatusCode::OK
    } else if is_revoke_event(&event.event_type) {
        // Fail-closed: if the revocation can't be DURABLY recorded, return 500 so the processor
        // retries — a 200 here would stop retries and let the refunded reference survive a restart.
        match state.card.revoke(&event.payment_reference) {
            Ok(()) => {
                tracing::info!("card webhook: refund/chargeback event (reference revoked)");
                StatusCode::OK
            }
            Err(e) => {
                tracing::error!(
                    "card revoke persist failed: {e} — returning 500 so the processor retries"
                );
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    } else {
        // Unrecognised event class: acknowledge so the processor stops retrying; change nothing.
        StatusCode::OK
    }
}

fn is_confirm_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "confirmed" | "payment_succeeded" | "order_completed" | "subscription_payment_success"
    )
}

fn is_revoke_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "refund" | "refunded" | "chargeback" | "subscription_cancelled"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watcher_with_minted(reference: &str) -> CardWatcher {
        let pending = Arc::new(TimedDurableSet::in_memory());
        pending.insert(reference, 0).expect("mint reference");
        CardWatcher::new(pending, Arc::new(DurableSet::in_memory()))
    }

    #[test]
    fn confirm_only_works_for_a_minted_reference() {
        let w = watcher_with_minted("ref-minted");
        assert!(
            !w.confirm("ref-unminted"),
            "fail closed: unminted reference is not confirmed"
        );
        assert!(!w.is_confirmed("ref-unminted"));
        assert!(w.confirm("ref-minted"), "a minted reference is accepted");
        assert!(w.is_confirmed("ref-minted"));
    }

    #[test]
    fn refund_revokes_and_blocks_future_issuance() {
        let w = watcher_with_minted("ref");
        assert!(w.confirm("ref"));
        assert!(w.is_confirmed("ref"));
        w.revoke("ref").expect("revoke persists");
        assert!(
            !w.is_confirmed("ref"),
            "a refunded reference is no longer confirmed"
        );
        // Revocation is sticky: a replayed confirm is rejected outright (fail-closed) and cannot
        // re-confirm a revoked reference.
        assert!(!w.confirm("ref"), "confirm() rejects a revoked reference");
        assert!(
            !w.is_confirmed("ref"),
            "revocation wins over a replayed confirm"
        );
    }

    #[test]
    fn confirm_and_revoke_are_idempotent() {
        let w = watcher_with_minted("ref");
        assert!(w.confirm("ref"));
        assert!(w.confirm("ref"), "double-confirm is a harmless no-op");
        w.revoke("ref").expect("revoke persists");
        w.revoke("ref").expect("double-revoke is idempotent");
        assert!(!w.is_confirmed("ref"));
    }

    #[test]
    fn composite_confirms_if_any_rail_does() {
        let card = Arc::new(watcher_with_minted("ref"));
        card.confirm("ref");
        // A second rail that confirms nothing.
        let empty = Arc::new(watcher_with_minted("other"));
        let composite =
            CompositeWatcher::new(vec![empty.clone() as Arc<dyn PaymentWatcher>, card.clone()]);
        assert!(
            composite.is_confirmed("ref"),
            "card rail confirms → composite confirms"
        );
        assert!(!composite.is_confirmed("nope"));
    }

    #[test]
    fn hmac_verifies_correct_signature_and_rejects_tampering() {
        let secret = b"mor-signing-secret";
        let body = br#"{"event_type":"confirmed","transaction_id":"t","payment_reference":"r"}"#;
        // Compute the reference MAC the way verify_hmac does.
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(body);
        let good = mac.finalize().into_bytes();
        let good_hex: String = good.iter().map(|b| format!("{b:02x}")).collect();

        assert!(
            verify_hmac(secret, body, &good_hex),
            "correct signature verifies"
        );
        assert!(
            !verify_hmac(secret, body, &"00".repeat(32)),
            "wrong signature is rejected"
        );
        assert!(
            !verify_hmac(b"other-secret", body, &good_hex),
            "wrong key is rejected"
        );
        assert!(
            !verify_hmac(secret, b"tampered body", &good_hex),
            "tampered body is rejected"
        );
        assert!(
            !verify_hmac(secret, body, "not-hex!!"),
            "malformed hex is rejected"
        );
    }

    #[test]
    fn event_class_matchers() {
        assert!(is_confirm_event("confirmed") && is_confirm_event("payment_succeeded"));
        assert!(is_revoke_event("refund") && is_revoke_event("chargeback"));
        assert!(!is_confirm_event("refund") && !is_revoke_event("confirmed"));
        assert!(!is_confirm_event("unknown") && !is_revoke_event("unknown"));
    }

    #[tokio::test]
    async fn oversized_webhook_body_is_rejected_before_handling() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt; // for `oneshot`

        // A body far above WEBHOOK_BODY_LIMIT must be refused (413) by the body-limit layer, before
        // the `Bytes` extractor buffers it — blocks pre-auth memory amplification on this public,
        // un-rate-limited endpoint.
        let pending = Arc::new(TimedDurableSet::in_memory());
        let router = cards_router(
            Arc::new(CardWatcher::new(pending, Arc::new(DurableSet::in_memory()))),
            b"mor-signing-secret".to_vec(),
        );
        let big = "a".repeat(64 * 1024);
        let req = Request::builder()
            .method("POST")
            .uri("/v1/billing/webhook")
            .header("content-type", "application/json")
            .body(Body::from(big))
            .expect("request builds");
        let resp = router.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn webhook_handler_gates_on_signature_then_confirms_or_revokes() {
        use axum::http::HeaderValue;
        let secret = b"mor-signing-secret".to_vec();
        let pending = Arc::new(TimedDurableSet::in_memory());
        pending.insert("ref-1", 0).unwrap();
        let card = Arc::new(CardWatcher::new(pending, Arc::new(DurableSet::in_memory())));
        let state = CardState {
            card: card.clone(),
            secret: Arc::new(secret.clone()),
        };
        let body =
            br#"{"event_type":"confirmed","transaction_id":"t","payment_reference":"ref-1"}"#
                .to_vec();
        let sign = |b: &[u8]| -> String {
            let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
            mac.update(b);
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect()
        };

        // No signature header → 400, and nothing is confirmed.
        assert_eq!(
            webhook(
                State(state.clone()),
                HeaderMap::new(),
                Bytes::from(body.clone())
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        assert!(!card.is_confirmed("ref-1"));

        // Wrong signature → 403, still nothing confirmed (no state change on a bad MAC).
        let mut bad = HeaderMap::new();
        bad.insert("x-signature", HeaderValue::from_static("00"));
        assert_eq!(
            webhook(State(state.clone()), bad, Bytes::from(body.clone())).await,
            StatusCode::FORBIDDEN
        );
        assert!(!card.is_confirmed("ref-1"));

        // Correct signature + confirm event → 200 and the reference is now paid.
        let mut good = HeaderMap::new();
        good.insert("x-signature", HeaderValue::from_str(&sign(&body)).unwrap());
        assert_eq!(
            webhook(State(state.clone()), good, Bytes::from(body.clone())).await,
            StatusCode::OK
        );
        assert!(
            card.is_confirmed("ref-1"),
            "a correctly-signed confirm event marks the reference paid"
        );

        // A correctly-signed refund event → 200 and revokes it (future issuance blocked).
        let refund =
            br#"{"event_type":"refunded","transaction_id":"t","payment_reference":"ref-1"}"#
                .to_vec();
        let mut rh = HeaderMap::new();
        rh.insert(
            "x-signature",
            HeaderValue::from_str(&sign(&refund)).unwrap(),
        );
        assert_eq!(
            webhook(State(state.clone()), rh, Bytes::from(refund)).await,
            StatusCode::OK
        );
        assert!(
            !card.is_confirmed("ref-1"),
            "a signed refund event revokes the reference"
        );
    }
}
