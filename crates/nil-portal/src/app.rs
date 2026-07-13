//! Router construction. Kept separate from `main` so tests can build the full Axum
//! stack (extractors, serde, status codes) without binding a socket.

use axum::extract::DefaultBodyLimit;
use axum::routing::post;
use axum::Router;

use crate::account::handlers::{account_challenge, account_status, create_account, get_account};
use crate::state::AppState;

/// Hard cap on account-endpoint request bodies. A registration carries only three small hex
/// fields; 16 KiB is generous. Without it, Axum's 2 MiB default lets an attacker force MiB-scale
/// buffering before the handler (and its rate-limit) runs.
const ACCOUNT_BODY_LIMIT: usize = 16 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/account", post(create_account).get(get_account))
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
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use http_body_util::BodyExt;
    use nil_crypto::account::{create_account_os, AuthKeypair};
    use tower::ServiceExt; // for `oneshot`

    use crate::store::memory::InMemoryStore;
    use crate::store::Store;

    fn store() -> Arc<dyn Store> {
        Arc::new(InMemoryStore::new())
    }

    /// Build the account router with a mocked peer address so `ConnectInfo<SocketAddr>` resolves
    /// in tests (the create handler rate-limits by client IP).
    fn app(store: Arc<dyn Store>) -> Router {
        router(AppState::new(store))
            .layer(axum::Extension(ConnectInfo(
                "1.2.3.4:5000".parse::<SocketAddr>().unwrap(),
            )))
            .layer(axum::Extension(crate::client_ip::ClientIpPolicy::direct()))
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

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Build the wire registration entirely from client-side account material. The Portal sees
    /// only the values embedded in `body`; `kp` stays with the simulated client.
    fn anonymous_registration() -> (String, String, AuthKeypair) {
        let derived = create_account_os();
        let kp = AuthKeypair::from_phrase(&derived.recovery_phrase).expect("derive auth key");
        let account_number = hex(derived.account_number.as_bytes());
        let body = serde_json::json!({
            "type": "anonymous",
            "account_number": account_number,
            "auth_pubkey": hex(&kp.public_key_bytes()),
            "registration_signature": hex(&kp.sign_registration(derived.account_number.as_bytes())),
        })
        .to_string();
        (body, account_number, kp)
    }

    #[tokio::test]
    async fn anonymous_create_accepts_client_proof_and_returns_only_canonical_account_number() {
        let (body, account_number, _kp) = anonymous_registration();
        let resp = app(store())
            .oneshot(post_json("/v1/account", &body))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let v = body_json(resp).await;
        assert_eq!(v["account_number"], account_number);
        assert_eq!(
            v.as_object().unwrap().len(),
            1,
            "Portal must return no recovery material"
        );
    }

    #[tokio::test]
    async fn anonymous_create_rejects_a_registration_signature_from_another_key() {
        let (mut body, _account_number, _kp) = anonymous_registration();
        let attacker = create_account_os();
        let attacker_kp = AuthKeypair::from_phrase(&attacker.recovery_phrase).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let account: [u8; 32] =
            crate::store::unhex32(json["account_number"].as_str().unwrap()).unwrap();
        json["registration_signature"] =
            serde_json::Value::String(hex(&attacker_kp.sign_registration(&account)));
        body = json.to_string();
        let resp = app(store())
            .oneshot(post_json("/v1/account", &body))
            .await
            .expect("create");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn anonymous_create_rejects_noncanonical_or_wrong_length_hex() {
        let (body, _account_number, _kp) = anonymous_registration();
        for (field, replacement) in [
            ("account_number", "AA".repeat(32)),
            ("auth_pubkey", "00".repeat(31)),
            ("registration_signature", "gg".repeat(64)),
        ] {
            let mut json: serde_json::Value = serde_json::from_str(&body).unwrap();
            json[field] = serde_json::Value::String(replacement);
            let resp = app(store())
                .oneshot(post_json("/v1/account", &json.to_string()))
                .await
                .expect("create");
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "field {field}");
        }
    }

    #[tokio::test]
    async fn duplicate_client_registration_is_a_conflict() {
        let (body, _account_number, _kp) = anonymous_registration();
        let app = app(store());
        assert_eq!(
            app.clone()
                .oneshot(post_json("/v1/account", &body))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        let resp = app
            .oneshot(post_json("/v1/account", &body))
            .await
            .expect("duplicate create");
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn server_recovery_endpoint_no_longer_exists() {
        let resp = app(store())
            .oneshot(post_json("/v1/account/recover", "{}"))
            .await
            .expect("removed route");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn email_type_is_not_implemented() {
        let resp = app(store())
            .oneshot(post_json(
                "/v1/account",
                r#"{"type":"email","email":"a@b.c"}"#,
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn create_account_is_rate_limited_per_ip() {
        // A single IP that floods account creation must eventually be capped (429) so it can't
        // exhaust storage. Drive the same router (shared limiter) past the per-window cap.
        let app = app(store());
        let (body, _account_number, _kp) = anonymous_registration();
        let mut saw_429 = false;
        for _ in 0..40 {
            let resp = app
                .clone()
                .oneshot(post_json("/v1/account", &body))
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
    async fn status_endpoint_authenticates_and_reports_entitlement() {
        // ONE app instance so the create/challenge/status calls share the same store + challenge set.
        let app = app(store());
        let (registration, acct_hex, kp) = anonymous_registration();
        let created = app
            .clone()
            .oneshot(post_json("/v1/account", &registration))
            .await
            .expect("create");
        assert_eq!(created.status(), StatusCode::CREATED);

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
        assert_eq!(
            v["entitlement"], "none",
            "a fresh account has no subscription"
        );
        assert!(v.get("until").is_none(), "no expiry when not active");

        // Replaying the same proof must fail — the challenge was single-use.
        let replay = app
            .oneshot(post_json("/v1/account/status", &body))
            .await
            .expect("status replay");
        assert_eq!(
            replay.status(),
            StatusCode::UNAUTHORIZED,
            "challenge is single-use"
        );
    }

    #[tokio::test]
    async fn status_with_a_bogus_challenge_is_unauthorized() {
        let app = app(store());
        let (registration, acct_hex, kp) = anonymous_registration();
        let created = app
            .clone()
            .oneshot(post_json("/v1/account", &registration))
            .await
            .expect("create");
        assert_eq!(created.status(), StatusCode::CREATED);
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
