//! A change through `cn=config` reaches the running server, not just the store.
//!
//! The whole point of a writable configuration subtree is that an operator does not restart to
//! change a rule. These tests drive the real server over a real socket: a client changes a
//! setting, and the next operation meets the new rule. If the server only wrote the generation
//! and kept its old policy, every one of these would pass on the store and fail on the wire.

use std::sync::Arc;
use std::time::Duration;

use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, ChangeOperation, LdapDn, ModifyRequest, ModifyRequestChanges,
    PartialAttribute, ProtocolOp, ResultCode,
};
use rust_rest_ldap::client::{Client, Options};
use rust_rest_ldap::config::{Args, Config, Document};
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const ADMIN_PASSWORD: &str = "admin-secret";

/// The document this server starts with: plain bind allowed, so a test can bind at once and
/// then watch the rule change under a connected client.
fn document(path: &std::path::Path) -> String {
    format!(
        "\
base_dn: {BASE}
listen_addr: 127.0.0.1:0
backend: redb
backends:
  redb:
    path: {}
AllowDangerousSettings: \"Yes I know this is bad idea\"
bind:
  AllowUnencryptedBind: \"Yes I know this is bad idea\"
",
        path.display()
    )
}

fn config(text: &str) -> Config {
    rust_rest_ldap::config::resolve(Args::default(), Some(text), |_| None).expect("config")
}

/// A running server whose configuration lives in a generation store.
async fn server() -> (String, String, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("tempdir");
    let database = directory.path().join("directory.redb");
    let store = directory.path().join("config.d");

    let text = document(&database);
    rust_rest_ldap::config_store::Store::open(&store)
        .commit(&text, "test", "initial")
        .expect("seed the store");

    let mut config = config(&text);
    config.document = Some(
        Document::new(&text, format!("store:{} generation 1", store.display()))
            .with_store(Some(store.clone())),
    );
    let config = Arc::new(config);

    let backend = rust_rest_ldap::backend::Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": database.display().to_string()})),
    )
    .expect("backend");
    backend
        .apply(&[rust_rest_ldap::backend::EntryChange::Upsert {
            entry: admin_entry(),
        }])
        .await
        .expect("seed");

    let security = Security::from_config(&config).with_schema(
        rust_rest_ldap::security::shared_schema(rust_rest_ldap::schema::Schema::core()),
    );
    let live = rust_rest_ldap::security::live((*config).clone(), security);
    let (source, _) = rust_rest_ldap::reload::Source::load(&config, backend)
        .await
        .expect("source");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("addr");
    let (_stop, shutdown) = tokio::sync::watch::channel(false);

    tokio::spawn(async move {
        let _ = rust_rest_ldap::server::serve(
            listener,
            None,
            false,
            source,
            live,
            shutdown,
            Duration::from_secs(2),
        )
        .await;
    });

    (
        format!("ldap://{addr}"),
        format!("store:{}", store.display()),
        directory,
    )
}

/// The administrator, with the hash the server understands.
fn admin_entry() -> rust_rest_ldap::model::Entry {
    use rust_rest_ldap::model::{Attribute, Attributes, Entry};

    let hash = rust_rest_ldap::password::hash(
        ADMIN_PASSWORD,
        rust_rest_ldap::password::StoreScheme::Argon2id,
    )
    .expect("hash");
    let attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec![
                "top".to_string(),
                "person".to_string(),
                "organizationalPerson".to_string(),
                "inetOrgPerson".to_string(),
            ],
        ))
        .push(Attribute::single("cn", "admin"))
        .push(Attribute::single("sn", "Admin"))
        .push(Attribute::single("uid", "admin"))
        .push(Attribute::single("userPassword", &hash))
        .push(Attribute::single("ldapAdmin", "true").internal());

    Entry::new(ADMIN_DN, attributes)
}

async fn connect(url: &str) -> Client {
    Client::connect(url, Options::default())
        .await
        .expect("connect")
}

/// Changes one setting through the subtree, returning the diagnostic the server answered with.
async fn change(client: &Client, dn: &str, attribute: &str, value: &str) -> String {
    let request = ModifyRequest {
        object: LdapDn::from(dn),
        changes: vec![ModifyRequestChanges {
            operation: ChangeOperation::Replace,
            modification: PartialAttribute::new(
                AttributeDescription::from(attribute),
                rasn::types::SetOf::from_vec(vec![OctetString::from(value.as_bytes().to_vec())]),
            ),
        }],
    };

    ask(client, request).await
}

/// Removes a setting: the only way to switch a dangerous one off, since `false` is not a
/// sentence this dialect accepts.
async fn remove(client: &Client, dn: &str, attribute: &str) -> String {
    let request = ModifyRequest {
        object: LdapDn::from(dn),
        changes: vec![ModifyRequestChanges {
            operation: ChangeOperation::Delete,
            modification: PartialAttribute::new(
                AttributeDescription::from(attribute),
                rasn::types::SetOf::from_vec(Vec::new()),
            ),
        }],
    };

    ask(client, request).await
}

async fn ask(client: &Client, request: ModifyRequest) -> String {
    let answers = client
        .request(ProtocolOp::ModifyRequest(request), "ModifyResponse")
        .await
        .expect("modify");

    match &answers[0].protocol_op {
        ProtocolOp::ModifyResponse(response) => {
            assert_eq!(
                response.0.result_code,
                ResultCode::Success,
                "{}",
                response.0.diagnostic_message.0
            );
            response.0.diagnostic_message.0.to_string()
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn a_new_rule_meets_the_next_client_without_a_restart() {
    // The visible effect: plain binds work, the operator writes `false`, and the next bind on a
    // NEW connection is refused with strongerAuthRequired. Same process, same store, no restart.
    let (url, _origin, _dir) = server().await;

    let admin = connect(&url).await;
    admin
        .bind(ADMIN_DN, ADMIN_PASSWORD)
        .await
        .expect("the plain bind is allowed by the starting rule");

    let diagnostic = remove(&admin, "cn=bind,cn=config", "restldap-AllowUnencryptedBind").await;
    assert!(
        !diagnostic.contains("after a restart"),
        "the rule is meant to take effect at once: {diagnostic}"
    );

    let next = connect(&url).await;
    let refused = next.bind(ADMIN_DN, ADMIN_PASSWORD).await;

    assert!(
        refused.is_err(),
        "the new rule refuses a plain bind, and the old policy would have allowed it"
    );
    let error = refused.expect_err("refused");
    assert!(
        error.to_string().contains("Strong")
            || error.to_string().contains("8")
            || format!("{error:?}").contains("StrongerAuthRequired"),
        "the refusal is strongerAuthRequired, not something else: {error}"
    );
}

#[tokio::test]
async fn a_setting_that_needs_a_restart_says_so_and_still_commits() {
    let (url, origin, _dir) = server().await;
    let admin = connect(&url).await;
    admin.bind(ADMIN_DN, ADMIN_PASSWORD).await.expect("bind");

    let diagnostic = change(&admin, "cn=config", "restldap-listen-addr", "127.0.0.1:1").await;

    assert!(
        diagnostic.contains("after a restart"),
        "the answer names the wait: {diagnostic}"
    );
    assert!(
        diagnostic.contains("listen_addr"),
        "and names the setting: {diagnostic}"
    );

    // The store holds the new value even though the socket did not move: the generation is a
    // fact, and pretending otherwise would make the history disagree with the disk.
    let path = origin.strip_prefix("store:").expect("origin").to_string();
    let text = rust_rest_ldap::config_store::Store::open(&path)
        .read_current()
        .expect("read")
        .expect("generation");
    assert!(text.contains("listen_addr: 127.0.0.1:1"), "{text}");

    // And the server still answers on the port it bound: the change did not break it.
    let again = connect(&url).await;
    again
        .bind(ADMIN_DN, ADMIN_PASSWORD)
        .await
        .expect("still serving");
}

#[tokio::test]
async fn the_server_is_still_running_after_a_change_it_could_not_adopt() {
    // A change that leaves an unparseable configuration is refused before the commit, so the
    // only way to reach "could not adopt" is a document that parses here and not there. That
    // is covered in the unit tests; what matters on the wire is that a refused change leaves
    // the server answering.
    let (url, origin, _dir) = server().await;
    let admin = connect(&url).await;
    admin.bind(ADMIN_DN, ADMIN_PASSWORD).await.expect("bind");

    let request = ModifyRequest {
        object: LdapDn::from("cn=config"),
        changes: vec![ModifyRequestChanges {
            operation: ChangeOperation::Replace,
            modification: PartialAttribute::new(
                AttributeDescription::from("restldap-backend"),
                rasn::types::SetOf::from_vec(vec![OctetString::from(b"no-such-backend".to_vec())]),
            ),
        }],
    };

    let answers = admin
        .request(ProtocolOp::ModifyRequest(request), "ModifyResponse")
        .await
        .expect("modify");

    match &answers[0].protocol_op {
        ProtocolOp::ModifyResponse(response) => {
            assert_eq!(
                response.0.result_code,
                ResultCode::ConstraintViolation,
                "a backend that does not exist is not a configuration"
            );
            assert!(
                response
                    .0
                    .diagnostic_message
                    .0
                    .contains("invalid configuration"),
                "{}",
                response.0.diagnostic_message.0
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let path = origin.strip_prefix("store:").expect("origin").to_string();
    assert_eq!(
        rust_rest_ldap::config_store::Store::open(&path)
            .history()
            .expect("history")
            .len(),
        1,
        "nothing was committed"
    );

    let again = connect(&url).await;
    again
        .bind(ADMIN_DN, ADMIN_PASSWORD)
        .await
        .expect("still serving");
}

#[tokio::test]
async fn the_answer_to_a_change_names_the_generation_in_the_history() {
    let (url, origin, _dir) = server().await;
    let admin = connect(&url).await;
    admin.bind(ADMIN_DN, ADMIN_PASSWORD).await.expect("bind");

    remove(&admin, "cn=bind,cn=config", "restldap-AllowUnencryptedBind").await;

    let path = origin.strip_prefix("store:").expect("origin").to_string();
    let store = rust_rest_ldap::config_store::Store::open(&path);
    let history = store.history().expect("history");

    assert_eq!(history.len(), 2);
    let last = history.last().expect("a generation");
    assert_eq!(last.author, ADMIN_DN, "the history says who");
    assert!(
        last.note.contains("AllowUnencryptedBind"),
        "and which setting, spelled as the document spells it: {}",
        last.note
    );
}
