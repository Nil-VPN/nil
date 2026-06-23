//! Router construction. Kept separate from `main` so tests can build the full Axum
//! stack (extractors, serde, status codes) without binding a socket.

use axum::routing::post;
use axum::Router;

use crate::account::handlers::{create_account, get_account, recover_account};
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/account", post(create_account).get(get_account))
        .route("/v1/account/recover", post(recover_account))
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
    async fn recover_unknown_account_is_not_found() {
        // Seven valid wordlist words for an account that was never created.
        let body = serde_json::json!({
            "recovery_phrase": ["abandon","ability","able","about","above","absent","absorb"],
            "recovery_code": "ABCDEFGH",
        })
        .to_string();
        let resp = app(store())
            .oneshot(post_json("/v1/account/recover", &body))
            .await
            .expect("recover");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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
