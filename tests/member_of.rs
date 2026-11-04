//! `memberOf` maintained by the server, end to end over a real store.
//!
//! The attribute is derived from the group side, so what these tests check is not "a value
//! exists" but the property that makes it useful: after `success`, the group and the members
//! agree, whichever side the client changed. A group that lists a user whose entry does not
//! name the group is a directory that contradicts itself, and a client reading in that window
//! - or a replica that receives only half of it - believes the half it saw.
//!
//! The four operations are covered because they are four different ways to change the same set:
//! `add` starts from nothing, `modify` changes the list, `modifyDN` keeps the list but moves the
//! group, and `delete` ends at nothing.

use std::sync::Arc;

use rasn::types::OctetString;
use rasn_ldap::{
    AddRequest, DelRequest, LdapDn, LdapMessage, ModifyDnRequest, ModifyRequest,
    ModifyRequestChanges, ProtocolOp, ResultCode,
};
use rust_rest_ldap::backend::{Backend, EntryChange};
use rust_rest_ldap::config::{Args, Config};
use rust_rest_ldap::ldap::session::{Identity, Session};
use rust_rest_ldap::ldap::{Action, handle};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::reload::Source;
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";
const BOB_DN: &str = "cn=bob,ou=users,dc=example,dc=com";
const ADMINS_DN: &str = "cn=admins,ou=groups,dc=example,dc=com";

fn person(dn: &str, cn: &str) -> Entry {
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
            .push(Attribute::single("uid", cn)),
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
    rust_rest_ldap::config::resolve(Args::default(), Some(&text), |_| None).expect("config")
}

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
                entry: person(ALICE_DN, "alice"),
            },
            EntryChange::Upsert {
                entry: person(BOB_DN, "bob"),
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

/// Runs one request through the dispatcher and persists what it asks to persist.
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
        other => panic!("not a write response: {other:?}"),
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

fn add_group(dn: &str, cn: &str, members: &[&str]) -> LdapMessage {
    let mut attributes = vec![
        attribute("objectClass", &["top", "groupOfNames"]),
        attribute("cn", &[cn]),
    ];
    if !members.is_empty() {
        attributes.push(attribute("member", members));
    }

    LdapMessage::new(
        1,
        ProtocolOp::AddRequest(AddRequest {
            entry: LdapDn::from(dn),
            attributes,
        }),
    )
}

fn modify(
    dn: &str,
    operation: rasn_ldap::ChangeOperation,
    name: &str,
    values: &[&str],
) -> LdapMessage {
    LdapMessage::new(
        2,
        ProtocolOp::ModifyRequest(ModifyRequest {
            object: LdapDn::from(dn),
            changes: vec![ModifyRequestChanges {
                operation,
                modification: rasn_ldap::PartialAttribute::new(
                    rasn_ldap::AttributeDescription::from(name),
                    rasn::types::SetOf::from_vec(
                        values
                            .iter()
                            .map(|value| OctetString::from(value.as_bytes()))
                            .collect(),
                    ),
                ),
            }],
        }),
    )
}

fn delete(dn: &str) -> LdapMessage {
    LdapMessage::new(3, ProtocolOp::DelRequest(DelRequest(LdapDn::from(dn))))
}

fn rename(dn: &str, new_rdn: &str) -> LdapMessage {
    LdapMessage::new(
        4,
        ProtocolOp::ModDnRequest(ModifyDnRequest {
            entry: LdapDn::from(dn),
            new_rdn: LdapDn::from(new_rdn),
            delete_old_rdn: true,
            new_superior: None,
        }),
    )
}

async fn member_of(source: &Arc<Source>, dn: &str) -> Vec<String> {
    source
        .directory()
        .await
        .find(dn)
        .and_then(|entry| entry.attributes().get("memberOf"))
        .map(|attribute| {
            attribute
                .values
                .iter()
                .map(|value| value.to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn a_group_added_with_a_member_gives_that_member_the_group_dn() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;

    run(&source, add_group(ADMINS_DN, "admins", &[ALICE_DN]))
        .await
        .expect("add");

    assert_eq!(
        member_of(&source, ALICE_DN).await,
        vec![ADMINS_DN.to_string()],
        "the value is the group's DN: a client that only knows the DN can resolve it"
    );
    assert!(
        member_of(&source, BOB_DN).await.is_empty(),
        "a user the group does not list gains nothing"
    );
}

#[tokio::test]
async fn adding_and_removing_a_member_moves_the_value_in_the_same_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;
    run(&source, add_group(ADMINS_DN, "admins", &[ALICE_DN]))
        .await
        .expect("add");

    run(
        &source,
        modify(
            ADMINS_DN,
            rasn_ldap::ChangeOperation::Add,
            "member",
            &[BOB_DN],
        ),
    )
    .await
    .expect("add member");
    assert_eq!(
        member_of(&source, BOB_DN).await,
        vec![ADMINS_DN.to_string()],
        "the new member is stamped by the same change set that wrote the group"
    );

    run(
        &source,
        modify(
            ADMINS_DN,
            rasn_ldap::ChangeOperation::Delete,
            "member",
            &[ALICE_DN],
        ),
    )
    .await
    .expect("delete member");
    assert!(
        member_of(&source, ALICE_DN).await.is_empty(),
        "the removed member keeps nothing: an empty attribute is removed, not left blank"
    );
    assert_eq!(
        member_of(&source, BOB_DN).await,
        vec![ADMINS_DN.to_string()],
        "and the one who stayed is untouched"
    );
}

#[tokio::test]
async fn a_renamed_group_moves_its_members_onto_the_new_dn() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;
    run(&source, add_group(ADMINS_DN, "admins", &[ALICE_DN]))
        .await
        .expect("add");

    run(&source, rename(ADMINS_DN, "cn=administrators"))
        .await
        .expect("rename");

    let new_dn = "cn=administrators,ou=groups,dc=example,dc=com";
    assert_eq!(
        member_of(&source, ALICE_DN).await,
        vec![new_dn.to_string()],
        "the old DN is gone and the new one is there - a value left behind names nothing"
    );
}

#[tokio::test]
async fn a_deleted_group_leaves_no_member_naming_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;
    run(&source, add_group(ADMINS_DN, "admins", &[ALICE_DN, BOB_DN]))
        .await
        .expect("add");

    run(&source, delete(ADMINS_DN)).await.expect("delete");

    assert!(
        member_of(&source, ALICE_DN).await.is_empty(),
        "alice no longer names a group that does not exist"
    );
    assert!(member_of(&source, BOB_DN).await.is_empty(), "nor does bob");
}

#[tokio::test]
async fn a_client_cannot_write_member_of() {
    // Otherwise any client could declare itself a member of anything, and the attribute would
    // stop meaning what it says.
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(&dir.path().join("d.redb")).await;
    run(&source, add_group(ADMINS_DN, "admins", &[ALICE_DN]))
        .await
        .expect("add");

    let refusal = run(
        &source,
        modify(
            BOB_DN,
            rasn_ldap::ChangeOperation::Add,
            "memberOf",
            &[ADMINS_DN],
        ),
    )
    .await;

    assert!(
        refusal.is_err(),
        "the server maintains memberOf, so a client write is refused"
    );
    assert!(
        member_of(&source, BOB_DN).await.is_empty(),
        "and nothing was written"
    );
}
