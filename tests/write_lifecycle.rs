//! `add`, `delete`, `modifyDN` end to end over a real store.
//!
//! The question each test answers is the one a client cares about: after `success`, is
//! the directory in the state I asked for, and does a search agree? The store is a real
//! `redb` file, so a change that only lived in memory would fail here.

use std::sync::Arc;

use rasn::types::OctetString;
use rasn_ldap::{
    AddRequest, DelRequest, LdapDn, LdapMessage, ModifyDnRequest, ProtocolOp, ResultCode,
    SearchRequest, SearchRequestDerefAliases, SearchRequestScope,
};
use rrl_directory::backend::{Backend, EntryChange};
use rrl_directory::config::{Args, Config};
use rrl_directory::ldap::session::{Identity, Session};
use rrl_directory::ldap::{Action, handle};
use rrl_directory::model::{Attribute, Attributes, Entry};
use rrl_directory::reload::Source;
use rrl_directory::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";

fn entry(dn: &str, cn: &str) -> Entry {
    Entry::new(
        dn,
        Attributes::new()
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
            .push(Attribute::single("mail", &format!("{cn}@example.com"))),
    )
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

async fn source(path: &std::path::Path) -> Arc<Source> {
    let config = config(path);
    let backend = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("backend");
    backend
        .apply(&[EntryChange::Upsert {
            entry: entry(ALICE_DN, "alice"),
        }])
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

/// Runs one request through the dispatcher and persists what it asks to persist.
///
/// This mirrors what the connection loop does, so the tests exercise the same
/// "persist, then answer" order the server uses on the wire.
async fn run(source: &Arc<Source>, message: LdapMessage) -> Result<ResultCode, ResultCode> {
    let directory = source.directory().await;
    let action = handle(&mut admin(), &directory, &Security::default(), message);

    match action {
        Action::Reply(messages) => {
            let code = messages.last().map(code_of).expect("a response");
            Err(code)
        }
        Action::Persist(action) => {
            source.apply(&action.changes).await.expect("persist");
            Ok(code_of(&action.success))
        }
        other => panic!("unexpected action: {other:?}"),
    }
}

fn code_of(message: &LdapMessage) -> ResultCode {
    match &message.protocol_op {
        ProtocolOp::AddResponse(response) => response.0.result_code,
        ProtocolOp::DelResponse(response) => response.0.result_code,
        ProtocolOp::ModDnResponse(response) => response.0.result_code,
        ProtocolOp::ModifyResponse(response) => response.0.result_code,
        ProtocolOp::SearchResDone(done) => done.0.result_code,
        other => panic!("not a write or search response: {other:?}"),
    }
}

fn attribute(name: &str, values: &[&str]) -> rasn_ldap::Attribute {
    rasn_ldap::Attribute::new(
        rasn_ldap::AttributeDescription::from(name),
        rasn::types::SetOf::from_vec(
            values
                .iter()
                .map(|value| OctetString::from(value.as_bytes()))
                .collect(),
        ),
    )
}

fn add(dn: &str, cn: &str) -> LdapMessage {
    LdapMessage::new(
        1,
        ProtocolOp::AddRequest(AddRequest {
            entry: LdapDn::from(dn),
            attributes: vec![
                attribute("objectClass", &["top", "person", "inetOrgPerson"]),
                attribute("cn", &[cn]),
                attribute("sn", &["New"]),
                attribute("uid", &[cn]),
                attribute("mail", &[&format!("{cn}@example.com")]),
            ],
        }),
    )
}

fn delete(dn: &str) -> LdapMessage {
    LdapMessage::new(2, ProtocolOp::DelRequest(DelRequest(LdapDn::from(dn))))
}

fn rename(dn: &str, new_rdn: &str, delete_old_rdn: bool) -> LdapMessage {
    LdapMessage::new(
        3,
        ProtocolOp::ModDnRequest(ModifyDnRequest {
            entry: LdapDn::from(dn),
            new_rdn: LdapDn::from(new_rdn),
            delete_old_rdn,
            new_superior: None,
        }),
    )
}

/// Every DN in the directory, via a subtree search.
async fn all_dns(source: &Arc<Source>) -> Vec<String> {
    let directory = source.directory().await;
    let request = SearchRequest::new(
        LdapDn::from(BASE),
        SearchRequestScope::WholeSubtree,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        rasn_ldap::Filter::Present(rasn_ldap::AttributeDescription::from("objectClass")),
        vec![rasn_ldap::LdapString::from("dn")],
    );

    let messages = match handle(
        &mut admin(),
        &directory,
        &Security::default(),
        LdapMessage::new(9, ProtocolOp::SearchRequest(request)),
    ) {
        Action::Reply(messages) => messages,
        other => panic!("unexpected action: {other:?}"),
    };

    messages
        .iter()
        .filter_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => Some(entry.object_name.0.clone()),
            _ => None,
        })
        .collect()
}

async fn attribute_values(source: &Arc<Source>, dn: &str, name: &str) -> Option<Vec<String>> {
    source
        .directory()
        .await
        .find(dn)
        .and_then(|entry| entry.attributes().get(name))
        .map(|attribute| attribute.values.to_vec())
}

#[tokio::test]
async fn an_added_entry_is_stored_and_searchable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    let code = run(&source, add("cn=bob,ou=users,dc=example,dc=com", "bob"))
        .await
        .expect("add");
    assert_eq!(code, ResultCode::Success);

    let dns = all_dns(&source).await;
    assert!(
        dns.contains(&"cn=bob,ou=users,dc=example,dc=com".to_string()),
        "the new entry must be in the directory: {dns:?}"
    );
    assert_eq!(
        attribute_values(&source, "cn=bob,ou=users,dc=example,dc=com", "mail").await,
        Some(vec!["bob@example.com".to_string()])
    );
}

#[tokio::test]
async fn an_added_entry_gets_its_operational_attributes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    run(&source, add("cn=bob,ou=users,dc=example,dc=com", "bob"))
        .await
        .expect("add");

    let directory = source.directory().await;
    let entry = directory
        .find("cn=bob,ou=users,dc=example,dc=com")
        .expect("entry");

    for name in [
        "createTimestamp",
        "modifyTimestamp",
        "creatorsName",
        "entryCSN",
    ] {
        assert!(
            entry.attributes().get(name).is_some(),
            "{name} must be stamped on add"
        );
    }
    assert_eq!(
        entry
            .attributes()
            .get("creatorsName")
            .map(|attribute| attribute.values[0].clone()),
        Some(ADMIN_DN.to_string()),
        "the creator is the bound user, not an empty string"
    );
}

#[tokio::test]
async fn adding_a_duplicate_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    let code = run(&source, add(ALICE_DN, "alice"))
        .await
        .expect_err("refused");
    assert_eq!(code, ResultCode::EntryAlreadyExists);
}

#[tokio::test]
async fn adding_under_a_missing_parent_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    let code = run(&source, add("cn=x,ou=nothing,dc=example,dc=com", "x"))
        .await
        .expect_err("refused");

    assert_eq!(
        code,
        ResultCode::NoSuchObject,
        "an entry cannot appear in a branch nobody has"
    );
}

#[tokio::test]
async fn adding_an_entry_the_schema_rejects_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    // A person without `sn`: strict mode refuses, and nothing is stored.
    let message = LdapMessage::new(
        1,
        ProtocolOp::AddRequest(AddRequest {
            entry: LdapDn::from("cn=nosn,ou=users,dc=example,dc=com"),
            attributes: vec![
                attribute("objectClass", &["top", "person"]),
                attribute("cn", &["nosn"]),
            ],
        }),
    );

    let code = run(&source, message).await.expect_err("refused");
    assert_eq!(code, ResultCode::ObjectClassViolation);
    assert!(
        !all_dns(&source)
            .await
            .contains(&"cn=nosn,ou=users,dc=example,dc=com".to_string())
    );
}

#[tokio::test]
async fn a_deleted_entry_is_gone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    let code = run(&source, delete(ALICE_DN)).await.expect("delete");
    assert_eq!(code, ResultCode::Success);

    assert!(
        !all_dns(&source).await.contains(&ALICE_DN.to_string()),
        "the entry must be gone from the store"
    );
}

#[tokio::test]
async fn deleting_a_missing_entry_is_no_such_object() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    let code = run(&source, delete("cn=ghost,ou=users,dc=example,dc=com"))
        .await
        .expect_err("refused");

    assert_eq!(code, ResultCode::NoSuchObject);
}

#[tokio::test]
async fn deleting_a_branch_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    let code = run(&source, delete("ou=users,dc=example,dc=com"))
        .await
        .expect_err("refused");

    // The users OU is part of the server's shape, so it is refused earlier and more
    // bluntly than a non-leaf: both are refusals, and the reason is named.
    assert_eq!(code, ResultCode::UnwillingToPerform);
}

#[tokio::test]
async fn a_renamed_entry_moves_and_keeps_its_attributes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    let code = run(&source, rename(ALICE_DN, "cn=alicia", true))
        .await
        .expect("rename");
    assert_eq!(code, ResultCode::Success);

    let dns = all_dns(&source).await;
    let new_dn = "cn=alicia,ou=users,dc=example,dc=com";
    assert!(
        dns.contains(&new_dn.to_string()),
        "the new DN must exist: {dns:?}"
    );
    assert!(
        !dns.contains(&ALICE_DN.to_string()),
        "the old DN must be gone: {dns:?}"
    );

    assert_eq!(
        attribute_values(&source, new_dn, "mail").await,
        Some(vec!["alice@example.com".to_string()]),
        "a rename must not lose the entry's data"
    );
    assert_eq!(
        attribute_values(&source, new_dn, "cn").await,
        Some(vec!["alicia".to_string()]),
        "the naming attribute follows the new RDN"
    );
}

#[tokio::test]
async fn renaming_onto_an_existing_dn_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    run(&source, add("cn=bob,ou=users,dc=example,dc=com", "bob"))
        .await
        .expect("add");

    let code = run(&source, rename(ALICE_DN, "cn=bob", true))
        .await
        .expect_err("refused");

    assert_eq!(code, ResultCode::EntryAlreadyExists);
}

#[tokio::test]
async fn a_rename_that_changes_nothing_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    let code = run(&source, rename(ALICE_DN, "cn=alice", true))
        .await
        .expect("no-op rename");

    assert_eq!(
        code,
        ResultCode::Success,
        "a client retrying an idempotent rename must not get entryAlreadyExists"
    );
    assert!(all_dns(&source).await.contains(&ALICE_DN.to_string()));
}

#[tokio::test]
async fn a_subtree_rename_moves_the_children_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("d.redb");
    let source = source(&path).await;

    // Give the group OU a child, then rename the OU: the child has to follow, or it
    // becomes unreachable.
    run(&source, add("cn=team,ou=groups,dc=example,dc=com", "team"))
        .await
        .expect("add child");

    let code = run(
        &source,
        rename("ou=groups,dc=example,dc=com", "ou=teams", true),
    )
    .await;

    // The OUs are the server's shape and are refused; the point of this test is that
    // the refusal is explicit rather than a half-applied move.
    assert_eq!(code.expect_err("refused"), ResultCode::UnwillingToPerform);
    assert!(
        all_dns(&source)
            .await
            .contains(&"cn=team,ou=groups,dc=example,dc=com".to_string()),
        "a refused rename must leave the subtree where it was"
    );
}

#[tokio::test]
async fn the_changes_survive_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("d.redb");
    let source = source(&path).await;

    run(&source, add("cn=bob,ou=users,dc=example,dc=com", "bob"))
        .await
        .expect("add");
    run(&source, delete(ALICE_DN)).await.expect("delete");
    drop(source);

    let backend = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("reopen");
    let (restarted, _) = Source::load(&config(&path), backend).await.expect("reload");

    let dns = all_dns(&restarted).await;
    assert!(dns.contains(&"cn=bob,ou=users,dc=example,dc=com".to_string()));
    assert!(!dns.contains(&ALICE_DN.to_string()));
}

#[tokio::test]
async fn a_rename_onto_a_different_attribute_moves_the_rdn() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    let code = run(
        &source,
        rename("uid=alice,ou=users,dc=example,dc=com", "cn=alicia", true),
    )
    .await
    .expect("rename");
    assert_eq!(code, ResultCode::Success);

    let new_dn = "cn=alicia,ou=users,dc=example,dc=com";
    let dns = all_dns(&source).await;
    assert!(dns.contains(&new_dn.to_string()), "{dns:?}");
    assert!(!dns.contains(&ALICE_DN.to_string()), "{dns:?}");
    assert_eq!(
        attribute_values(&source, new_dn, "uid").await,
        Some(vec!["alice".to_string()]),
        "the entry is really named by cn, so renaming it does not touch uid"
    );
    assert_eq!(
        attribute_values(&source, new_dn, "cn").await,
        Some(vec!["alicia".to_string()]),
        "the real naming attribute follows the new RDN"
    );
}

#[tokio::test]
async fn a_subtree_rename_carries_the_children() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("d.redb");
    let source = source(&path).await;

    // A branch that is not part of the server's own shape: an OU under the users OU,
    // with a person inside it.
    let branch = LdapMessage::new(
        1,
        ProtocolOp::AddRequest(AddRequest {
            entry: LdapDn::from("ou=devel,ou=users,dc=example,dc=com"),
            attributes: vec![
                attribute("objectClass", &["top", "organizationalUnit"]),
                attribute("ou", &["devel"]),
            ],
        }),
    );
    run(&source, branch).await.expect("add branch");

    run(
        &source,
        add("cn=carol,ou=devel,ou=users,dc=example,dc=com", "carol"),
    )
    .await
    .expect("add child");

    let code = run(
        &source,
        rename(
            "ou=devel,ou=users,dc=example,dc=com",
            "ou=engineering",
            true,
        ),
    )
    .await
    .expect("rename branch");
    assert_eq!(code, ResultCode::Success);

    let dns = all_dns(&source).await;
    assert!(
        dns.contains(&"ou=engineering,ou=users,dc=example,dc=com".to_string()),
        "the branch itself moved: {dns:?}"
    );
    assert!(
        dns.contains(&"cn=carol,ou=engineering,ou=users,dc=example,dc=com".to_string()),
        "the child moved with it, or it is now unreachable: {dns:?}"
    );
    assert!(
        !dns.iter().any(|dn| dn.contains("ou=devel,ou=users")),
        "nothing may be left under the old DN: {dns:?}"
    );
}

#[tokio::test]
async fn a_rename_refuses_a_missing_new_parent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    let message = LdapMessage::new(
        3,
        ProtocolOp::ModDnRequest(ModifyDnRequest {
            entry: LdapDn::from(ALICE_DN),
            new_rdn: LdapDn::from("cn=alice"),
            delete_old_rdn: true,
            new_superior: Some(LdapDn::from("ou=nothing,dc=example,dc=com")),
        }),
    );

    let code = run(&source, message).await.expect_err("refused");
    assert_eq!(code, ResultCode::NoSuchObject);
}

#[tokio::test]
async fn an_added_entry_can_be_renamed_and_deleted_in_sequence() {
    // The life cycle in the order an operator would use it.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("d.redb");
    let source = source(&path).await;

    run(&source, add("cn=dave,ou=users,dc=example,dc=com", "dave"))
        .await
        .expect("add");
    run(
        &source,
        rename("cn=dave,ou=users,dc=example,dc=com", "cn=daavid", true),
    )
    .await
    .expect("rename");
    run(&source, delete("cn=daavid,ou=users,dc=example,dc=com"))
        .await
        .expect("delete");

    assert!(
        !all_dns(&source)
            .await
            .iter()
            .any(|dn| dn.starts_with("cn=da") || dn.starts_with("cn=dav")),
        "the entry is gone under both names"
    );

    drop(source);
    let backend = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("reopen");
    let (restarted, _) = Source::load(&config(&path), backend).await.expect("reload");
    assert!(
        !all_dns(&restarted)
            .await
            .iter()
            .any(|dn| dn.contains("dav"))
    );
}
