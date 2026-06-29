//! Router construction. Kept separate from `main` so tests can build the full Axum
//! stack (extractors, serde, status codes) without binding a socket.

use axum::extract::DefaultBodyLimit;
use axum::routing::post;
use axum::Router;

use crate::account::handlers::{
    account_challenge, account_status, create_account, get_account, recover_account,
};
use crate::state::AppState;

/// Hard cap on account-endpoint request bodies. A create body is ~30 B and a recover body
/// (7-word phrase + 8-char code) is ~150 B; 16 KiB is generous. Without it, Axum's 2 MiB default
/// lets an attacker force MiB-scale buffering before the handler (and its rate-limit) runs — the
/// same body-amplification surface the Coordinator caps on `/v1/redeem`.
const ACCOUNT_BODY_LIMIT: usize = 16 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/account", post(create_account).get(get_account))
        .route("/v1/account/recover", post(recover_account))
        .route("/v1/account/challenge", post(account_challenge))
        .route("/v1/account/status", post(account_status))
        .layer(DefaultBodyLimit::max(ACCOUNT_BODY_LIMIT))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use http_body_util::BodyExt;
    use tower::ServiceExt; // for `oneshot`

    use crate::store::memory::InMemoryStore;
    use crate::store::Store;

    fn store() -> Arc<dyn Store> {
        Arc::new(InMemoryStore::new())
    }

    /// Build the account router with a mocked peer address so `ConnectInfo<SocketAddr>` resolves
    /// in tests (the create handler rate-limits by client IP).
    fn app(store: Arc<dyn Store>) -> Router {
        router(AppState::new(store)).layer(MockConnectInfo("1.2.3.4:5000".parse::<SocketAddr>().unwrap()))
    }

    fn post_json(uri: &str, json: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(json.to_owned()))
            .expect("request builds")
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("valid json body")
    }

    #[tokio::test]
    async fn anonymous_create_returns_seven_word_contract() {
        let resp = app(store())
            .oneshot(post_json("/v1/account", r#"{"type":"anonymous"}"#))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let v = body_json(resp).await;
        assert!(!v["account_number"].as_str().expect("account_number").is_empty());
        assert_eq!(
            v["recovery_phrase"].as_array().expect("phrase array").len(),
            7,
            "anonymous signup must return exactly 7 words"
        );
        assert!(!v["recovery_code"].as_str().expect("recovery_code").is_empty());
    }

    #[tokio::test]
    async fn create_then_recover_roundtrips() {
        let store = store();
        let created = body_json(
            app(store.clone())
                .oneshot(post_json("/v1/account", r#"{"type":"anonymous"}"#))
                .await
                .expect("create"),
        )
        .await;

        let recover_body = serde_json::json!({
            "recovery_phrase": created["recovery_phrase"],
            "recovery_code": created["recovery_code"],
        })
        .to_string();

        let resp = app(store.clone())
            .oneshot(post_json("/v1/account/recover", &recover_body))
            .await
            .expect("recover");
        assert_eq!(resp.status(), StatusCode::OK);

        let v = body_json(resp).await;
        assert_eq!(v["account_number"], created["account_number"]);
        assert_eq!(v["entitlement"], "none");
    }

    #[tokio::test]
    async fn recover_with_wrong_code_is_unauthorized() {
        let store = store();
        let created = body_json(
            app(store.clone())
                .oneshot(post_json("/v1/account", r#"{"type":"anonymous"}"#))
                .await
                .expect("create"),
        )
        .await;

        let recover_body = serde_json::json!({
            "recovery_phrase": created["recovery_phrase"],
            "recovery_code": "00000000",
        })
        .to_string();

        let resp = app(store)
            .oneshot(post_json("/v1/account/recover", &recover_body))
            .await
            .expect("recover");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn recover_unknown_account_is_indistinguishable_from_wrong_code() {
        // A well-formed phrase for an account that was never created must return the SAME response
        // as a real account with a wrong code (401) — no account-existence oracle (PD-3).
        let body = serde_json::json!({
            "recovery_phrase": ["abandon","ability","able","about","above","absent","absorb"],
            "recovery_code": "ABCDEFGH",
        })
        .to_string();
        let resp = app(store())
            .oneshot(post_json("/v1/account/recover", &body))
            .await
            .expect("recover");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "unknown account == wrong code");
    }

    #[tokio::test]
    async fn recover_malformed_phrase_is_bad_request() {
        let body = serde_json::json!({
            "recovery_phrase": ["abandon","ability","able"],
            "recovery_code": "ABCDEFGH",
        })
        .to_string();
        let resp = app(store())
            .oneshot(post_json("/v1/account/recover", &body))
            .await
            .expect("recover");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn email_type_is_not_implemented() {
        let resp = app(store())
            .oneshot(post_json("/v1/account", r#"{"type":"email","email":"a@b.c"}"#))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn create_account_is_rate_limited_per_ip() {
        // A single IP that floods account creation must eventually be capped (429) so it can't
        // exhaust storage. Drive the same router (shared limiter) past the per-window cap.
        let app = app(store());
        let mut saw_429 = false;
        for _ in 0..40 {
            let resp = app
                .clone()
                .oneshot(post_json("/v1/account", r#"{"type":"anonymous"}"#))
                .await
                .expect("oneshot");
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                saw_429 = true;
                break;
            }
        }
        assert!(saw_429, "a per-IP flood must be capped with 429");
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_before_handling() {
        // A body far above ACCOUNT_BODY_LIMIT must be refused (413) by the body-limit layer,
        // before the handler buffers/parses it — blocks memory amplification.
        let big = "a".repeat(64 * 1024);
        let resp = app(store())
            .oneshot(post_json("/v1/account", &big))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn recover_is_rate_limited_per_ip() {
        // Recovery verifies an 8-char one-time code, so an unthrottled endpoint is a brute-force
        // oracle. A per-IP flood must be capped with 429 (the limiter fires before the DB lookup).
        let app = app(store());
        let body = serde_json::json!({
            "recovery_phrase": ["abandon","ability","able","about","above","absent","absorb"],
            "recovery_code": "ABCDEFGH",
        })
        .to_string();
        let mut saw_429 = false;
        for _ in 0..40 {
            let resp = app
                .clone()
                .oneshot(post_json("/v1/account/recover", &body))
                .await
                .expect("oneshot");
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                saw_429 = true;
                break;
            }
        }
        assert!(saw_429, "a per-IP recover flood must be capped with 429");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[tokio::test]
    async fn status_endpoint_authenticates_and_reports_entitlement() {
        use nil_crypto::account::{account_number_from_phrase, AuthKeypair, Phrase};

        // ONE app instance so the create/challenge/status calls share the same store + challenge set.
        let app = app(store());

        let created = body_json(
            app.clone()
                .oneshot(post_json("/v1/account", r#"{"type":"anonymous"}"#))
                .await
                .expect("create"),
        )
        .await;
        let words: Vec<String> = created["recovery_phrase"]
            .as_array()
            .expect("phrase")
            .iter()
            .map(|w| w.as_str().expect("word").to_string())
            .collect();
        let phrase = Phrase::parse(&words).expect("phrase parses");
        let kp = AuthKeypair::from_phrase(&phrase).expect("derive auth key");
        let acct_hex = hex(account_number_from_phrase(&phrase).expect("account number").as_bytes());

        // Get a challenge and sign it with the account auth key.
        let ch = body_json(
            app.clone()
                .oneshot(post_json("/v1/account/challenge", ""))
                .await
                .expect("challenge"),
        )
        .await;
        let challenge = ch["challenge"].as_str().expect("challenge").to_string();
        let sig_hex = hex(&kp.sign(challenge.as_bytes()));

        let body = serde_json::json!({
            "account_number": acct_hex,
            "challenge": challenge,
            "signature": sig_hex,
        })
        .to_string();
        let resp = app
            .clone()
            .oneshot(post_json("/v1/account/status", &body))
            .await
            .expect("status");
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["entitlement"], "none", "a fresh account has no subscription");
        assert!(v.get("until").is_none(), "no expiry when not active");

        // Replaying the same proof must fail — the challenge was single-use.
        let replay = app
            .oneshot(post_json("/v1/account/status", &body))
            .await
            .expect("status replay");
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED, "challenge is single-use");
    }

    #[tokio::test]
    async fn status_with_a_bogus_challenge_is_unauthorized() {
        let app = app(store());
        let created = body_json(
            app.clone()
                .oneshot(post_json("/v1/account", r#"{"type":"anonymous"}"#))
                .await
                .expect("create"),
        )
        .await;
        use nil_crypto::account::{account_number_from_phrase, AuthKeypair, Phrase};
        let words: Vec<String> = created["recovery_phrase"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap().to_string())
            .collect();
        let phrase = Phrase::parse(&words).unwrap();
        let kp = AuthKeypair::from_phrase(&phrase).unwrap();
        let acct_hex = hex(account_number_from_phrase(&phrase).unwrap().as_bytes());
        // A nonce the Portal never issued.
        let challenge = "ab".repeat(32);
        let body = serde_json::json!({
            "account_number": acct_hex,
            "challenge": challenge,
            "signature": hex(&kp.sign(challenge.as_bytes())),
        })
        .to_string();
        let resp = app
            .oneshot(post_json("/v1/account/status", &body))
            .await
            .expect("status");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn challenge_endpoint_returns_distinct_hex_nonces() {
        // The route is wired and mints a fresh 32-byte (64 hex) nonce each call.
        let app = app(store());
        let a = body_json(
            app.clone()
                .oneshot(post_json("/v1/account/challenge", ""))
                .await
                .expect("challenge"),
        )
        .await;
        let b = body_json(
            app.oneshot(post_json("/v1/account/challenge", ""))
                .await
                .expect("challenge"),
        )
        .await;
        let ca = a["challenge"].as_str().expect("challenge string");
        let cb = b["challenge"].as_str().expect("challenge string");
        assert_eq!(ca.len(), 64, "32-byte nonce => 64 hex chars");
        assert!(ca.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(ca, cb, "each challenge is a fresh nonce");
    }

    #[tokio::test]
    async fn get_account_is_not_implemented() {
        let resp = app(store())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/account")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
