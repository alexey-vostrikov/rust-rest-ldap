//! The write path end to end: a modify reaches the store and comes back in a search.
//!
//! The point of these tests is the sentence the server must never break: when a client
//! gets `success`, the change is in the store, and the next search sees it. So the
//! chain is real — `Source` over a `redb` file, the dispatch layer building the
//! change, `apply` persisting it, and a fresh search reading the result.

use std::sync::Arc;

use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, AttributeValueAssertion, ChangeOperation, Filter, LdapDn, LdapMessage,
    ModifyRequest, ModifyRequestChanges, PartialAttribute, ProtocolOp, ResultCode, SearchRequest,
    SearchRequestDerefAliases, SearchRequestScope,
};
use rrl_directory::backend::{Backend, EntryChange};
use rrl_directory::config::{Args, Config};
use rrl_directory::ldap::session::{Identity, Session};
use rrl_directory::ldap::{Action, handle};
use rrl_directory::model::{Attribute, Attributes, Entry};
use rrl_directory::reload::Source;
use rrl_directory::security::Security;

const BASE: &str = "dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";

fn entry(dn: &str, cn: &str, mail: &str) -> Entry {
    let attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec![
                "top".to_string(),
                "person".to_string(),
                "inetOrgPerson".to_string(),
            ],
        ))
        .push(Attribute::single("cn", cn))
        .push(Attribute::single("sn", "Surname"))
        .push(Attribute::single("uid", cn))
        .push(Attribute::single("mail", mail));
    Entry::new(dn, attributes)
}

fn config(path: &std::path::Path) -> Config {
    let text = format!(
        "\
base_dn: {BASE}
backends:
  redb:
    path: {}
",
        path.display()
    );
    rrl_directory::config::resolve(Args::default(), Some(&text), |_| None).expect("config")
}

/// A source over an empty redb file, seeded with two users.
async fn source(path: &std::path::Path) -> Arc<Source> {
    let config = config(path);
    let backend = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("backend");
    backend
        .apply(&[
            EntryChange::Upsert {
                entry: entry(ALICE_DN, "alice", "alice@example.com"),
            },
            EntryChange::Upsert {
                entry: entry(
                    "cn=bob,ou=users,dc=example,dc=com",
                    "bob",
                    "bob@example.com",
                ),
            },
        ])
        .await
        .expect("seed");

    let (source, _) = Source::load(&config, backend).await.expect("load");
    source
}

fn admin() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(ADMIN_DN, true));
    session
}

fn modify_request(dn: &str, attribute: &str, value: &str) -> ModifyRequest {
    ModifyRequest {
        object: LdapDn::from(dn),
        changes: vec![ModifyRequestChanges {
            operation: ChangeOperation::Replace,
            modification: PartialAttribute::new(
                AttributeDescription::from(attribute),
                rasn::types::SetOf::from_vec(vec![OctetString::from(value.as_bytes())]),
            ),
        }],
    }
}

fn search_request(attribute: &str, value: &str) -> SearchRequest {
    SearchRequest::new(
        LdapDn::from(BASE),
        SearchRequestScope::WholeSubtree,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        Filter::EqualityMatch(AttributeValueAssertion::new(
            AttributeDescription::from(attribute),
            OctetString::from(value.as_bytes()),
        )),
        vec![rasn_ldap::LdapString::from("mail")],
    )
}

async fn run_search(
    source: &Arc<Source>,
    attribute: &str,
    value: &str,
) -> (ResultCode, Vec<(String, Vec<String>)>) {
    let directory = source.directory().await;
    let security = Security::default();
    let mut session = admin();

    // The security bundle carries the schema; the write tests need it to match the
    // one the source was loaded with.
    let security = Security {
        schema: rrl_directory::security::shared_schema(rrl_directory::schema::Schema::core()),
        ..security
    };

    let action = handle(
        &mut session,
        &directory,
        &security,
        LdapMessage::new(
            2,
            ProtocolOp::SearchRequest(search_request(attribute, value)),
        ),
    );

    let messages = match action {
        Action::Reply(messages) => messages,
        other => panic!("unexpected action: {other:?}"),
    };

    let mut found = Vec::new();
    let mut code = ResultCode::Other;
    for message in messages {
        match message.protocol_op {
            ProtocolOp::SearchResEntry(result) => {
                let mail: Vec<String> = result
                    .attributes
                    .iter()
                    .filter(|attribute| attribute.r#type.0.eq_ignore_ascii_case("mail"))
                    .flat_map(|attribute| {
                        attribute
                            .vals
                            .iter()
                            .map(|value| String::from_utf8_lossy(value.as_ref()).into_owned())
                    })
                    .collect();
                found.push((result.object_name.0.clone(), mail));
            }
            ProtocolOp::SearchResDone(done) => code = done.0.result_code,
            _ => {}
        }
    }

    (code, found)
}

#[tokio::test]
async fn a_modify_reaches_the_store_and_a_search_finds_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("directory.redb");
    let source = source(&path).await;

    let directory = source.directory().await;
    let security = Security::default();
    let mut session = admin();
    let action = handle(
        &mut session,
        &directory,
        &security,
        LdapMessage::new(
            1,
            ProtocolOp::ModifyRequest(modify_request(ALICE_DN, "mail", "new@example.com")),
        ),
    );

    let (changes, success, message_id, failure) = match action {
        Action::Persist(action) => (
            action.changes,
            action.success,
            action.message_id,
            action.failure,
        ),
        other => panic!("expected a write, got {other:?}"),
    };

    // The reply is only sent after the store accepted the change.
    let written = source.apply(&changes).await;
    match written {
        Ok(_) => {
            assert_eq!(
                response_code(&success),
                ResultCode::Success,
                "message {message_id:?}"
            );
        }
        Err(err) => {
            let _ = failure;
            panic!("the store must accept the change: {err}");
        }
    }

    let (code, found) = run_search(&source, "mail", "new@example.com").await;
    assert_eq!(code, ResultCode::Success);
    assert_eq!(
        found,
        vec![(ALICE_DN.to_string(), vec!["new@example.com".to_string()])],
        "the new value must be searchable straight away"
    );

    // And the old value is gone.
    let (_, old) = run_search(&source, "mail", "alice@example.com").await;
    assert!(old.is_empty(), "the replaced value must not match any more");
}

#[tokio::test]
async fn the_write_survives_a_restart_of_the_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("directory.redb");
    let source = source(&path).await;

    let directory = source.directory().await;
    let action = handle(
        &mut admin(),
        &directory,
        &Security::default(),
        LdapMessage::new(
            1,
            ProtocolOp::ModifyRequest(modify_request(ALICE_DN, "mail", "durable@example.com")),
        ),
    );
    let Action::Persist(action) = action else {
        panic!("expected a write");
    };
    source.apply(&action.changes).await.expect("apply");

    // redb holds an exclusive lock on the file, so a restart means the old handle
    // has to be gone first — exactly as it would be when the process exits.
    drop(source);

    // A new process would open the same file and load from it.
    let backend = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("reopen");
    let config = config(&path);
    let (restarted, _) = Source::load(&config, backend).await.expect("reload");

    let (_, found) = run_search(&restarted, "mail", "durable@example.com").await;
    assert_eq!(
        found.len(),
        1,
        "a change acknowledged before the restart must still be there"
    );
}

#[tokio::test]
async fn a_snapshot_taken_before_the_write_keeps_the_old_value() {
    // A session that started its operation before the write must not see a half
    // state: this is why the snapshot is an Arc and the swap replaces it whole.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("directory.redb");
    let source = source(&path).await;

    let before = source.directory().await;
    let old_value = before
        .find(ALICE_DN)
        .and_then(|entry| entry.attributes().get("mail"))
        .expect("mail")
        .values
        .to_vec();

    let action = handle(
        &mut admin(),
        &before,
        &Security::default(),
        LdapMessage::new(
            1,
            ProtocolOp::ModifyRequest(modify_request(ALICE_DN, "mail", "after@example.com")),
        ),
    );
    let Action::Persist(action) = action else {
        panic!("expected a write");
    };
    source.apply(&action.changes).await.expect("apply");

    assert_eq!(
        before
            .find(ALICE_DN)
            .and_then(|entry| entry.attributes().get("mail"))
            .expect("mail")
            .values
            .to_vec(),
        old_value,
        "the snapshot taken before the write is unchanged"
    );

    let after = source.directory().await;
    assert_eq!(
        after
            .find(ALICE_DN)
            .and_then(|entry| entry.attributes().get("mail"))
            .expect("mail")
            .values
            .to_vec(),
        vec!["after@example.com".to_string()],
        "the next snapshot shows the new value"
    );
}

fn response_code(message: &LdapMessage) -> ResultCode {
    match &message.protocol_op {
        ProtocolOp::ModifyResponse(response) => response.0.result_code,
        other => panic!("not a modify response: {other:?}"),
    }
}
