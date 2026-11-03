//! The `rest` backend against a real HTTP service on a real socket.
//!
//! The service is an axum router that records what it was asked, so the tests can check the
//! request the backend sends - method, path, header, body - not only what it parsed from the
//! answer. What the backend stores is somebody else's server, so the request IS the contract.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use rust_rest_ldap::backend::{Backend, EntryChange};
use rust_rest_ldap::model::User;

/// One request as the mock service saw it.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    authorization: Option<String>,
    body: String,
}

/// What the mock service answers.
#[derive(Clone)]
struct Service {
    seen: Arc<Mutex<Vec<Seen>>>,
    /// Status for every answer.
    status: u16,
    /// Body keyed by path, so one service can serve users and groups.
    bodies: Arc<dyn Fn(&str) -> String + Send + Sync>,
    /// How long to wait before answering, for the timeout test.
    delay: Option<Duration>,
}

/// Starts the mock service and returns its base URL and what it saw.
async fn service(
    status: u16,
    bodies: impl Fn(&str) -> String + Send + Sync + 'static,
    delay: Option<Duration>,
) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));

    let service = Service {
        seen: Arc::clone(&seen),
        status,
        bodies: Arc::new(bodies),
        delay,
    };

    let app = Router::new().fallback(any(handle)).with_state(service);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (format!("http://{addr}"), seen)
}

async fn handle(State(service): State<Service>, request: axum::extract::Request) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let authorization = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());

    let body = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .unwrap_or_else(|_| Bytes::new());
    let body = String::from_utf8_lossy(&body).to_string();

    service.seen.lock().expect("lock").push(Seen {
        method,
        path: path.clone(),
        authorization,
        body,
    });

    if let Some(delay) = service.delay {
        tokio::time::sleep(delay).await;
    }

    let text = (service.bodies)(&path);

    (
        axum::http::StatusCode::from_u16(service.status).expect("status"),
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        text,
    )
        .into_response()
}

fn users_json() -> String {
    r#"[
        {"cn": "alice", "uid": "alice", "mail": "alice@example.com", "objectClass": ["inetOrgPerson"]},
        {"cn": "bob", "uid": "bob", "objectClass": ["inetOrgPerson"]}
    ]"#
    .to_string()
}

fn groups_json() -> String {
    r#"[{"cn": "admins", "memberUid": ["alice"]}]"#.to_string()
}

fn backend(url: &str, token: Option<&str>, timeout: Option<&str>) -> Backend {
    let mut config = serde_json::json!({
        "url": url,
        "users_path": "/ldap/user",
        "groups_path": "/ldap/group",
    });

    if let Some(token) = token {
        config["auth_token"] = serde_json::json!(token);
    }
    if let Some(timeout) = timeout {
        config["http_request_timeout"] = serde_json::json!(timeout);
    }

    Backend::from_config("rest", Some(&config)).expect("backend")
}

#[tokio::test]
async fn users_and_groups_are_read_from_the_two_paths() {
    let (url, seen) = service(
        200,
        |path| {
            if path.ends_with("/group") {
                groups_json()
            } else {
                users_json()
            }
        },
        None,
    )
    .await;

    let backend = backend(&url, None, None);
    assert_eq!(backend.name(), "rest");

    let data = backend.load().await.expect("load");

    assert_eq!(data.users.len(), 2, "both users are read");
    assert_eq!(data.users[0].cn, "alice");
    assert_eq!(data.users[0].mail.as_deref(), Some("alice@example.com"));
    assert_eq!(data.groups.len(), 1);
    assert_eq!(data.groups[0].cn, "admins");

    let paths: Vec<String> = seen
        .lock()
        .expect("lock")
        .iter()
        .map(|request| format!("{} {}", request.method, request.path))
        .collect();
    assert_eq!(
        paths,
        vec!["GET /ldap/user", "GET /ldap/group"],
        "two GETs, users first"
    );
}

#[tokio::test]
async fn the_token_travels_as_a_token_authorization_header() {
    let (url, seen) = service(
        200,
        |path| {
            if path.ends_with("/group") {
                groups_json()
            } else {
                users_json()
            }
        },
        None,
    )
    .await;

    backend(&url, Some("s3cret-token"), None)
        .load()
        .await
        .expect("load");

    for request in seen.lock().expect("lock").iter() {
        assert_eq!(
            request.authorization.as_deref(),
            Some("Token s3cret-token"),
            "the service is authenticated the way gorestldap authenticated to it"
        );
    }
}

#[tokio::test]
async fn a_service_that_refuses_is_reported_with_its_own_explanation() {
    // The body of a refusal is the service's explanation, and losing it turns a fixable
    // mistake into a bare status code.
    let (url, _seen) = service(403, |_| "token expired".to_string(), None).await;

    let error = backend(&url, Some("old"), None)
        .load()
        .await
        .expect_err("must fail");

    let text = error.to_string();
    assert!(text.contains("403"), "{text}");
    assert!(text.contains("token expired"), "{text}");
}

#[tokio::test]
async fn a_write_sends_the_whole_object_to_the_object_path() {
    let (url, seen) = service(200, |_| "{}".to_string(), None).await;
    let backend = backend(&url, None, None);

    let before = User {
        cn: "alice".to_string(),
        uid: Some("alice".to_string()),
        ..User::default()
    };
    let mut after = before.clone();
    after.mail = Some("alice@example.com".to_string());

    backend
        .update(&EntryChange::User {
            old: Box::new(before.clone()),
            new: Box::new(after.clone()),
        })
        .await
        .expect("update");

    let seen = seen.lock().expect("lock");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "PUT");
    assert_eq!(seen[0].path, "/ldap/user/alice");

    // The whole object, not the diff: PUT replaces, and RFC 9110 §9.3.4 lets a server treat
    // the fields it did not receive as absent.
    let sent: serde_json::Value = serde_json::from_str(&seen[0].body).expect("json");
    assert_eq!(sent["cn"], "alice");
    assert_eq!(sent["uid"], "alice", "an unchanged field is still sent");
    assert_eq!(sent["mail"], "alice@example.com");
}

#[tokio::test]
async fn a_name_with_a_slash_does_not_address_another_endpoint() {
    let (url, seen) = service(200, |_| "{}".to_string(), None).await;

    let user = User {
        cn: "a/b".to_string(),
        ..User::default()
    };

    backend(&url, None, None)
        .update(&EntryChange::User {
            old: Box::new(user.clone()),
            new: Box::new(user),
        })
        .await
        .expect("update");

    let seen = seen.lock().expect("lock");
    assert_eq!(
        seen[0].path, "/ldap/user/a%2Fb",
        "unencoded, this would address /ldap/user/a/b - a different resource, and the request \
         would have looked successful"
    );
}

#[tokio::test]
async fn a_service_that_does_not_answer_in_time_is_abandoned() {
    let (url, _seen) = service(200, |_| users_json(), Some(Duration::from_millis(500))).await;

    let error = backend(&url, None, Some("50ms"))
        .load()
        .await
        .expect_err("must fail");

    let text = error.to_string();
    assert!(
        text.contains("50ms"),
        "the answer names the limit the operator set: {text}"
    );
}

#[tokio::test]
async fn a_path_prefix_in_the_address_is_honoured() {
    let (url, seen) = service(
        200,
        |path| {
            if path.ends_with("/group") {
                groups_json()
            } else {
                users_json()
            }
        },
        None,
    )
    .await;

    let backend = Backend::from_config(
        "rest",
        Some(&serde_json::json!({
            "url": format!("{url}/api/v1"),
            "users_path": "/ldap/user",
            "groups_path": "/ldap/group",
        })),
    )
    .expect("backend");

    backend.load().await.expect("load");

    let paths: Vec<String> = seen
        .lock()
        .expect("lock")
        .iter()
        .map(|r| r.path.clone())
        .collect();
    assert_eq!(paths, vec!["/api/v1/ldap/user", "/api/v1/ldap/group"]);
}

#[test]
fn a_configuration_that_cannot_work_is_refused_at_construction() {
    let cases = [
        (serde_json::json!({"url": "localhost:8000"}), "no scheme"),
        (
            serde_json::json!({"url": "http://localhost:8000", "http_request_timeout": "soon"}),
            "not a duration",
        ),
        (
            serde_json::json!({"url": "http://localhost:8000", "ca_file": "/nonexistent/ca.pem"}),
            "does not exist",
        ),
    ];

    for (config, expected) in cases {
        let error = Backend::from_config("rest", Some(&config)).expect_err("must refuse");
        assert!(
            error.to_string().contains(expected),
            "expected '{expected}' in: {error}"
        );
    }
}

#[tokio::test]
async fn a_whole_entry_is_written_back_as_the_object_it_describes() {
    // What the write path actually sends: the directory holds entries, so a modify arrives as a
    // whole entry. The service's model is smaller, so the entry is read back into a user.
    let (url, seen) = service(200, |_| "{}".to_string(), None).await;

    let attributes = rust_rest_ldap::model::Attributes::new()
        .push(rust_rest_ldap::model::Attribute::new(
            "objectClass",
            vec![
                "top".to_string(),
                "person".to_string(),
                "inetOrgPerson".to_string(),
            ],
        ))
        .push(rust_rest_ldap::model::Attribute::single("cn", "alice"))
        .push(rust_rest_ldap::model::Attribute::single("sn", "Smith"))
        .push(rust_rest_ldap::model::Attribute::single("uid", "alice"))
        .push(rust_rest_ldap::model::Attribute::single(
            "mail",
            "alice@example.com",
        ));

    let entry =
        rust_rest_ldap::model::Entry::new("cn=alice,ou=users,dc=example,dc=com", attributes);

    backend(&url, None, None)
        .update(&EntryChange::Upsert { entry })
        .await
        .expect("update");

    let seen = seen.lock().expect("lock");
    assert_eq!(seen[0].method, "PUT");
    assert_eq!(
        seen[0].path, "/ldap/user/alice",
        "a user goes to the users collection"
    );

    let sent: serde_json::Value = serde_json::from_str(&seen[0].body).expect("json");
    assert_eq!(sent["cn"], "alice");
    assert_eq!(sent["sn"], "Smith");
    assert_eq!(sent["mail"], "alice@example.com");
    assert_eq!(
        sent["objectClass"][2], "inetOrgPerson",
        "the object classes travel with the object"
    );
}

#[tokio::test]
async fn a_group_entry_goes_to_the_groups_collection() {
    let (url, seen) = service(200, |_| "{}".to_string(), None).await;

    let attributes = rust_rest_ldap::model::Attributes::new()
        .push(rust_rest_ldap::model::Attribute::new(
            "objectClass",
            vec!["top".to_string(), "posixGroup".to_string()],
        ))
        .push(rust_rest_ldap::model::Attribute::single("cn", "admins"))
        .push(rust_rest_ldap::model::Attribute::new(
            "memberUid",
            vec!["alice".to_string()],
        ));

    let entry =
        rust_rest_ldap::model::Entry::new("cn=admins,ou=groups,dc=example,dc=com", attributes);

    backend(&url, None, None)
        .update(&EntryChange::Upsert { entry })
        .await
        .expect("update");

    let seen = seen.lock().expect("lock");
    assert_eq!(
        seen[0].path, "/ldap/group/admins",
        "posixGroup means the groups collection"
    );

    let sent: serde_json::Value = serde_json::from_str(&seen[0].body).expect("json");
    assert_eq!(sent["memberUid"][0], "alice");
}

#[tokio::test]
async fn a_delete_is_refused_because_the_endpoint_is_not_part_of_this_protocol() {
    let (url, seen) = service(200, |_| "{}".to_string(), None).await;

    let error = backend(&url, None, None)
        .update(&EntryChange::Delete {
            dn: "cn=alice,ou=users,dc=example,dc=com".to_string(),
        })
        .await
        .expect_err("must refuse");

    assert!(
        error.to_string().contains("delete it there"),
        "the refusal says what to do instead: {error}"
    );
    assert!(
        seen.lock().expect("lock").is_empty(),
        "nothing was sent: guessing a delete endpoint would send a request nobody asked for"
    );
}
