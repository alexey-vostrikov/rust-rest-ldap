//! The small HTTP surface: the reload callback and a health endpoint.
//!
//! gorestldap listened for `HEAD /callback` with an `Authorization: Token …`
//! header and reloaded the data on it, which is how a Django admin could push a
//! change. The token comparison here is constant time, because the endpoint is
//! reachable by anyone who can route to the port.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, head};
use subtle::ConstantTimeEq;

use crate::reload::Source;

/// Shared state of the HTTP surface.
pub struct HttpState {
    pub source: Arc<Source>,
    /// Token expected in `Authorization: Token <token>`; `None` disables the
    /// callback entirely.
    pub callback_token: Option<String>,
}

/// Builds the router: `HEAD /callback` reloads, `GET /healthz` reports readiness.
pub fn router(state: Arc<HttpState>) -> Router {
    Router::new()
        .route("/callback", head(callback))
        .route("/healthz", get(healthz))
        .with_state(state)
}

async fn healthz() -> (StatusCode, &'static str) {
    (StatusCode::OK, "ok\n")
}

async fn callback(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> (StatusCode, &'static str) {
    let Some(expected) = state.callback_token.as_deref() else {
        return (StatusCode::NOT_FOUND, "");
    };

    if !token_matches(&headers, expected) {
        return (StatusCode::UNAUTHORIZED, "");
    }

    match state.source.reload().await {
        Ok(_) => (StatusCode::OK, ""),
        // A backend that cannot be read is reported as such instead of pretending
        // the reload happened.
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, ""),
    }
}

/// Accepts `Authorization: Token <value>` and `Bearer <value>`, compares in
/// constant time.
fn token_matches(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };

    let provided = value
        .strip_prefix("Token ")
        .or_else(|| value.strip_prefix("Bearer "))
        .unwrap_or(value);

    provided.len() == expected.len() && bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::time::Duration;
    use tempfile::tempdir;
    use tower::ServiceExt as _;

    async fn source(dir: &std::path::Path, users: &str) -> (Arc<Source>, std::path::PathBuf) {
        let users_path = dir.join("users.json");
        let groups_path = dir.join("groups.json");
        std::fs::write(&users_path, users).expect("users");
        std::fs::write(&groups_path, "[]").expect("groups");

        let config = crate::config::Config {
            backend: "file".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            listen_addr: "127.0.0.1:0".to_string(),
            update_interval: Duration::from_secs(300),
            log_path: None,
            debug: false,
            log_timestamp: false,
            log_caller: false,
            backends: Default::default(),
            respect_control_criticality: true,
            users_ou_name: "users".to_string(),
            groups_ou_name: "groups".to_string(),
            use_tls: false,
            server_cert: None,
            server_key: None,
            http_listen_addr: None,
            callback_auth_token: Some("secret".to_string()),
            passwords: Default::default(),
            schema: crate::schema::Schema::core(),
            schema_mode: crate::schema::Mode::Strict,
            indexes: crate::index::IndexConfig::default(),
            acl: Default::default(),
            allow_plaintext_simple_bind: true,
        };
        let backend_config = serde_json::json!({
            "users_path": users_path,
            "groups_path": groups_path,
        });
        let backend =
            crate::backend::Backend::from_config("file", Some(&backend_config)).expect("backend");

        let (loaded, _directory) = crate::reload::Source::load(&config, backend)
            .await
            .expect("load");
        (loaded, users_path)
    }

    fn state(source: Arc<Source>, token: Option<&str>) -> Arc<HttpState> {
        Arc::new(HttpState {
            source,
            callback_token: token.map(|token| token.to_string()),
        })
    }

    async fn send(
        router: Router,
        method: &str,
        path: &str,
        authorization: Option<&str>,
    ) -> StatusCode {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(value) = authorization {
            builder = builder.header("authorization", value);
        }
        let request = builder.body(Body::empty()).expect("request");
        router.oneshot(request).await.expect("response").status()
    }

    #[tokio::test]
    async fn callback_with_a_good_token_reloads() {
        let dir = tempdir().expect("tempdir");
        let (source, users) = source(dir.path(), r#"[{"cn":"admin","objectClass":["top"]}]"#).await;
        let router = router(state(Arc::clone(&source), Some("secret")));

        std::fs::write(
            &users,
            r#"[{"cn":"admin","objectClass":["top"]},{"cn":"alice","objectClass":["top"]}]"#,
        )
        .expect("update");

        let status = send(router, "HEAD", "/callback", Some("Token secret")).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(source.directory().await.users().len(), 2);
        assert_eq!(source.generation().await, 1);
    }

    #[tokio::test]
    async fn callback_with_a_wrong_token_changes_nothing() {
        let dir = tempdir().expect("tempdir");
        let (source, _users) =
            source(dir.path(), r#"[{"cn":"admin","objectClass":["top"]}]"#).await;
        let router = router(state(Arc::clone(&source), Some("secret")));

        let status = send(router, "HEAD", "/callback", Some("Token wrong")).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(source.generation().await, 0);
    }

    #[tokio::test]
    async fn callback_without_a_token_header_is_unauthorized() {
        let dir = tempdir().expect("tempdir");
        let (source, _users) = source(dir.path(), "[]").await;
        let router = router(state(source, Some("secret")));

        assert_eq!(
            send(router, "HEAD", "/callback", None).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn a_bearer_token_is_accepted_too() {
        let dir = tempdir().expect("tempdir");
        let (source, _users) = source(dir.path(), "[]").await;
        let router = router(state(source, Some("secret")));

        assert_eq!(
            send(router, "HEAD", "/callback", Some("Bearer secret")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn callback_is_disabled_without_a_configured_token() {
        let dir = tempdir().expect("tempdir");
        let (source, _users) = source(dir.path(), "[]").await;
        let router = router(state(source, None));

        assert_eq!(
            send(router, "HEAD", "/callback", Some("Token anything")).await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn broken_backend_is_reported_as_a_server_error() {
        let dir = tempdir().expect("tempdir");
        let (source, users) = source(dir.path(), "[]").await;
        let router = router(state(Arc::clone(&source), Some("secret")));
        std::fs::write(&users, "{ broken").expect("break");

        assert_eq!(
            send(router, "HEAD", "/callback", Some("Token secret")).await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(source.generation().await, 0);
    }

    #[tokio::test]
    async fn healthz_answers_ok() {
        let dir = tempdir().expect("tempdir");
        let (source, _users) = source(dir.path(), "[]").await;
        let router = router(state(source, None));

        assert_eq!(send(router, "GET", "/healthz", None).await, StatusCode::OK);
    }
}
