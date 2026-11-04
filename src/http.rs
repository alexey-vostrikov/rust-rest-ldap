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
use axum::routing::{get, head, post};
use subtle::ConstantTimeEq;

use crate::reload::Source;

/// Shared state of the HTTP surface.
pub struct HttpState {
    pub source: Arc<Source>,
    /// Counters to expose at `/metrics`.
    pub metrics: Arc<crate::metrics::Metrics>,
    /// Token expected in `Authorization: Token <token>`; `None` disables the
    /// callback entirely.
    pub callback_token: Option<String>,
}

/// Builds the router: `HEAD /callback` reloads, `GET /healthz` reports readiness.
pub fn router(state: Arc<HttpState>) -> Router {
    Router::new()
        .route("/callback", head(callback))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/reindex", post(reindex))
        .route("/schema/reload", post(schema_reload))
        .with_state(state)
}

/// `POST /reindex`: rebuild the indexes over the snapshot in memory.
///
/// Authorised with the same token as the callback, because it is an operation rather than a
/// reading. The answer is the measurement itself: entries, attributes, bytes and how long it
/// took. There is nothing to repair - every write rebuilds the index - so this exists to
/// answer "what does a rebuild cost here", which is what decides whether an attribute
/// deserves a trigram index.
async fn reindex(State(state): State<Arc<HttpState>>, headers: HeaderMap) -> (StatusCode, String) {
    let Some(expected) = state.callback_token.as_deref() else {
        return (StatusCode::NOT_FOUND, String::new());
    };

    if !token_matches(&headers, expected) {
        return (StatusCode::UNAUTHORIZED, String::new());
    }

    match state.source.reindex().await {
        Ok(done) => (
            StatusCode::OK,
            format!(
                "entries={} attributes={} bytes={} millis={}\n",
                done.entries,
                done.attributes,
                done.bytes,
                done.elapsed.as_millis()
            ),
        ),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err}\n")),
    }
}

/// `POST /schema/reload`: re-read the schema files and adopt them.
///
/// The same operation as SIGUSR2, for a deployment that has no shell on the host. It refuses
/// with 409 when the data already breaks the new schema: the file was read and understood,
/// and what it describes does not fit - which is a different thing from a broken file, and
/// the status code is what lets a script tell them apart.
async fn schema_reload(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> (StatusCode, String) {
    let Some(expected) = state.callback_token.as_deref() else {
        return (StatusCode::NOT_FOUND, String::new());
    };

    if !token_matches(&headers, expected) {
        return (StatusCode::UNAUTHORIZED, String::new());
    }

    match state.source.reload_schema().await {
        Ok(done) => {
            let mut body = format!("attributes={} classes={}\n", done.attributes, done.classes);
            for warning in &done.warnings {
                body.push_str(&format!("warning: {warning}\n"));
            }
            (StatusCode::OK, body)
        }
        // The data does not fit the schema that was read: 409, not 500, because nothing
        // failed - the change was understood and cannot be adopted.
        Err(crate::backend::BackendError::SchemaViolations { count, first }) => (
            StatusCode::CONFLICT,
            format!(
                "{count} entries break the new schema: {}\n",
                first.join("; ")
            ),
        ),
        // A file that cannot be read or parsed: the input is wrong, not the state.
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err}\n")),
    }
}

async fn healthz() -> (StatusCode, &'static str) {
    (StatusCode::OK, "ok\n")
}

/// Prometheus text exposition.
///
/// No authentication, deliberately: the numbers describe the software, not the data — how
/// many searches, how many failed, how big the directory is. A scraper that needs a secret
/// is a scraper that gets configured wrong once and then goes unwatched.
async fn metrics(
    State(state): State<Arc<HttpState>>,
) -> (StatusCode, [(String, String); 1], String) {
    (
        StatusCode::OK,
        [(
            "content-type".to_string(),
            // The versioned content type: Prometheus 2.x negotiates it, and an unversioned
            // one is deprecated.
            "text/plain; version=0.0.4; charset=utf-8".to_string(),
        )],
        state.metrics.render(),
    )
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
            schema_files: Vec::new(),
            schema_definitions: Vec::new(),
            indexes: crate::index::IndexConfig::default(),
            referrals: Default::default(),
            server_id: 0,
            peers: Vec::new(),
            journal_keep: None,
            journal_max_age: None,
            conflict_log: None,
            sasl: Default::default(),
            acl: Default::default(),
            allow_unencrypted_bind: true,
            dangerous_settings: Vec::new(),
            integrity: crate::integrity::IntegrityConfig::default(),
            limits: Default::default(),
            observability: crate::config::ObservabilityConfig::default(),
            bootstrap: None,
            locale: (crate::i18n::Locale::english(), crate::i18n::Source::Default),
            locale_file: None,
            document: None,
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
            metrics: crate::metrics::Metrics::new(),
            source,
            callback_token: token.map(|token| token.to_string()),
        })
    }

    /// A source whose schema is read from a file, for the reload endpoint.
    async fn source_with_schema(
        dir: &std::path::Path,
        users: &std::path::Path,
        groups: &std::path::Path,
        schema: &std::path::Path,
    ) -> (Arc<Source>, std::path::PathBuf) {
        let text = format!(
            "base_dn: dc=example,dc=com
schema:
  files:
    - {}
backends:
  file:
    users_path: {}
    groups_path: {}
",
            schema.display(),
            users.display(),
            groups.display()
        );
        let config = crate::config::resolve(crate::config::Args::default(), Some(&text), |_| None)
            .expect("config");
        let backend = crate::backend::Backend::from_config("file", config.backends.get("file"))
            .expect("backend");
        let (source, _) = Source::load(&config, backend).await.expect("load");
        let _ = dir;

        (source, users.to_path_buf())
    }

    /// Sends a request and returns the body as well, for the endpoint that answers with one.
    async fn send_body(
        router: Router,
        method: &str,
        path: &str,
        token: Option<&str>,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            builder = builder.header("Authorization", token);
        }
        let request = builder.body(Body::empty()).expect("request");

        let response = router.oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("body");

        (status, String::from_utf8_lossy(&bytes).to_string())
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
    async fn reindex_reports_what_it_cost() {
        let dir = tempdir().expect("tempdir");
        let (source, _users) =
            source(dir.path(), r#"[{"cn":"admin","objectClass":["top"]}]"#).await;
        let router = router(state(Arc::clone(&source), Some("secret")));

        let (status, body) = send_body(router, "POST", "/reindex", Some("Token secret")).await;

        assert_eq!(status, StatusCode::OK);
        // The fixture configures no indexes, so the attribute count is zero and the number
        // that matters is the entries: the naming context, both units and the one user. The
        // point of the assertion is that the answer *is* the measurement, not a bare "ok".
        assert!(
            body.contains("entries=4") && body.contains("attributes=0") && body.contains("millis="),
            "the answer is the measurement: {body}"
        );
    }

    #[tokio::test]
    async fn reindex_needs_the_token() {
        // It rebuilds rather than reads, so it is authorised like the callback. A directory
        // whose index anyone can rebuild on demand is one where anyone can spend its CPU.
        let dir = tempdir().expect("tempdir");
        let (source, _users) = source(dir.path(), "[]").await;

        assert_eq!(
            send(
                router(state(Arc::clone(&source), Some("secret"))),
                "POST",
                "/reindex",
                Some("Token wrong")
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(
                router(state(Arc::clone(&source), Some("secret"))),
                "POST",
                "/reindex",
                None
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        // And an unconfigured token disables it with the callback, rather than leaving it open.
        assert_eq!(
            send(
                router(state(source, None)),
                "POST",
                "/reindex",
                Some("Token anything")
            )
            .await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn reindex_does_not_reload_the_backend() {
        // The indexes are rebuilt over the snapshot in memory: the generation counter, which
        // counts reloads of the store, must not move.
        let dir = tempdir().expect("tempdir");
        let (source, _users) =
            source(dir.path(), r#"[{"cn":"admin","objectClass":["top"]}]"#).await;
        let router = router(state(Arc::clone(&source), Some("secret")));

        assert_eq!(
            send(router, "POST", "/reindex", Some("Token secret")).await,
            StatusCode::OK
        );
        assert_eq!(source.generation().await, 0);
        assert_eq!(source.directory().await.users().len(), 1);
    }

    #[tokio::test]
    async fn schema_reload_answers_with_what_it_ended_up_with() {
        // The answer is the count, because that is what tells the operator the file was read
        // at all: an endpoint that answered "ok" would be indistinguishable from one that
        // silently ignored a missing path.
        let dir = tempdir().expect("tempdir");
        let (source, _users) =
            source(dir.path(), r#"[{"cn":"admin","objectClass":["top"]}]"#).await;
        let router = router(state(Arc::clone(&source), Some("secret")));

        let (status, body) =
            send_body(router, "POST", "/schema/reload", Some("Token secret")).await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("attributes=") && body.contains("classes="),
            "the answer is the count in force afterwards: {body}"
        );
    }

    #[tokio::test]
    async fn schema_reload_needs_the_token() {
        let dir = tempdir().expect("tempdir");
        let (source, _users) = source(dir.path(), "[]").await;

        assert_eq!(
            send(
                router(state(Arc::clone(&source), Some("secret"))),
                "POST",
                "/schema/reload",
                Some("Token wrong")
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(
                router(state(source, None)),
                "POST",
                "/schema/reload",
                Some("Token any")
            )
            .await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn a_schema_file_that_does_not_parse_is_a_bad_request() {
        // 400 and not 500: the input is wrong. A script that retries on 5xx would retry a
        // file that will never parse.
        let dir = tempdir().expect("tempdir");
        let users = dir.path().join("users.json");
        std::fs::write(&users, "[]").expect("write");
        let groups = dir.path().join("groups.json");
        std::fs::write(&groups, "[]").expect("write");
        let schema = dir.path().join("local.schema");
        std::fs::write(&schema, "\n").expect("write");

        let (source, _users) = source_with_schema(dir.path(), &users, &groups, &schema).await;
        let router = router(state(Arc::clone(&source), Some("secret")));

        std::fs::write(&schema, "attributetype ( broken\n").expect("break");

        let (status, body) =
            send_body(router, "POST", "/schema/reload", Some("Token secret")).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("local.schema"), "{body}");
    }

    #[tokio::test]
    async fn a_schema_the_data_breaks_is_a_conflict() {
        // 409 and not 400: the file was read and understood, and what it describes does not
        // fit the data. The distinction is what lets a script decide whether to fix the file
        // or the data.
        let dir = tempdir().expect("tempdir");
        let users = dir.path().join("users.json");
        std::fs::write(
            &users,
            r#"[{"cn":"alice","sn":"Smith","objectClass":["top","person","projectPerson"]}]"#,
        )
        .expect("write");
        let groups = dir.path().join("groups.json");
        std::fs::write(&groups, "[]").expect("write");
        let schema = dir.path().join("local.schema");
        std::fs::write(
            &schema,
            "objectclass ( 1.3.6.1.4.1.99999.2.1 NAME 'projectPerson' SUP top AUXILIARY MUST cn )\n",
        )
        .expect("write");

        let (source, _users) = source_with_schema(dir.path(), &users, &groups, &schema).await;
        let router = router(state(Arc::clone(&source), Some("secret")));

        std::fs::write(
            &schema,
            "objectclass ( 1.3.6.1.4.1.99999.2.1 NAME 'projectPerson' SUP top AUXILIARY MUST ( cn $ description ) )\n",
        )
        .expect("make the data invalid");

        let (status, body) =
            send_body(router, "POST", "/schema/reload", Some("Token secret")).await;

        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.contains("alice"), "{body}");
    }

    #[tokio::test]
    async fn healthz_answers_ok() {
        let dir = tempdir().expect("tempdir");
        let (source, _users) = source(dir.path(), "[]").await;
        let router = router(state(source, None));

        assert_eq!(send(router, "GET", "/healthz", None).await, StatusCode::OK);
    }
}
