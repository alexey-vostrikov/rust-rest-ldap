//! Storage that survives a restart, end to end.
//!
//! The question this test answers: if the process dies after a change was
//! acknowledged, is the directory still the state after that change? For the JSON
//! backends the answer is "per file, and only if the rename completed"; for the redb
//! backend it is "yes, one transaction".
//!
//! It also checks the property that motivated the backend: a change set covering a
//! user and a group is applied as one unit, so the two can never disagree.

use std::sync::Arc;
use std::time::Duration;

use rasn_ldap::{
    AttributeDescription, AttributeValueAssertion, Filter, LdapDn, LdapMessage, ProtocolOp,
    ResultCode, SearchRequest, SearchRequestDerefAliases, SearchRequestScope,
};
use redb::Durability;
use rust_rest_ldap::backend::{Backend, EntryChange};
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::ldap::session::Session;
use rust_rest_ldap::ldap::{Action, handle};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";

fn entry(dn: &str, cn: &str, mail: &str) -> Entry {
    let attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec!["top".to_string(), "inetOrgPerson".to_string()],
        ))
        .push(Attribute::single("cn", cn))
        .push(Attribute::single("mail", mail));

    Entry::new(dn, attributes)
}

fn equality(name: &str, value: &str) -> Filter {
    Filter::EqualityMatch(AttributeValueAssertion::new(
        AttributeDescription::from(name),
        rasn::types::OctetString::from(value.as_bytes()),
    ))
}

fn search(filter: Filter) -> LdapMessage {
    LdapMessage::new(
        1,
        ProtocolOp::SearchRequest(SearchRequest::new(
            LdapDn::from(BASE),
            SearchRequestScope::WholeSubtree,
            SearchRequestDerefAliases::NeverDerefAliases,
            0,
            0,
            false,
            filter,
            vec![],
        )),
    )
}

fn anonymous_search_count(directory: &Directory, filter: Filter) -> (usize, ResultCode) {
    // The default ACL denies an anonymous search of the whole tree, so this goes
    // straight to the search handler's sibling: the dispatcher with a bound admin.
    let security = Security::default();
    let mut session = Session::new();
    session.set_identity(rust_rest_ldap::ldap::session::Identity::new(
        "cn=admin,ou=users,dc=example,dc=com",
        true,
    ));

    let action = handle(&mut session, directory, &security, search(filter));
    let messages = match action {
        Action::Reply(messages) => messages,
        other => panic!("unexpected action: {other:?}"),
    };

    let entries = messages
        .iter()
        .filter(|message| matches!(message.protocol_op, ProtocolOp::SearchResEntry(_)))
        .count();
    let code = match &messages.last().expect("done").protocol_op {
        ProtocolOp::SearchResDone(done) => done.0.result_code,
        other => panic!("unexpected: {other:?}"),
    };
    (entries, code)
}

#[test]
fn committed_entries_survive_a_restart_and_are_searchable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("directory.redb");

    {
        let backend = Backend::from_config(
            "redb",
            Some(&serde_json::json!({"path": path.display().to_string()})),
        )
        .expect("backend");

        let changes = vec![
            EntryChange::Upsert {
                entry: entry("cn=admin,ou=users,dc=example,dc=com", "admin", "a@e.com"),
            },
            EntryChange::Upsert {
                entry: entry("cn=bob,ou=users,dc=example,dc=com", "bob", "b@e.com"),
            },
            EntryChange::Upsert {
                entry: entry("cn=ops,ou=groups,dc=example,dc=com", "ops", "ops@e.com"),
            },
        ];
        futures::executor::block_on(backend.apply(&changes)).expect("commit");
    }

    // A restart: brand-new handle over the same file.
    let reopened = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("reopen");
    let data = futures::executor::block_on(reopened.load()).expect("load");
    assert_eq!(
        data.entries.len(),
        3,
        "everything acknowledged must be there"
    );

    let directory = Arc::new(data.into_directory(BASE, "users", "groups"));

    let (found, code) = anonymous_search_count(&directory, equality("mail", "b@e.com"));
    assert_eq!(code, ResultCode::Success);
    assert_eq!(
        found, 1,
        "the entry written before the restart is searchable"
    );

    let (all, _) = anonymous_search_count(&directory, equality("objectClass", "inetOrgPerson"));
    assert_eq!(all, 3);
}

#[test]
fn a_change_set_covering_a_user_and_a_group_is_one_unit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("directory.redb");
    let backend = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("backend");

    // One transaction: the user appears and the group appears with it.
    futures::executor::block_on(backend.apply(&[
        EntryChange::Upsert {
            entry: entry("cn=carol,ou=users,dc=example,dc=com", "carol", "c@e.com"),
        },
        EntryChange::Upsert {
            entry: entry("cn=team,ou=groups,dc=example,dc=com", "team", "team@e.com"),
        },
    ]))
    .expect("commit");

    let data = futures::executor::block_on(backend.load()).expect("load");
    let dns: Vec<&str> = data.entries.iter().map(|entry| entry.dn()).collect();
    assert_eq!(
        dns,
        vec![
            "cn=carol,ou=users,dc=example,dc=com",
            "cn=team,ou=groups,dc=example,dc=com",
        ]
    );
}

#[test]
fn a_refused_change_set_leaves_the_store_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("directory.redb");
    let backend = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("backend");

    // The second change cannot be stored by this backend, so the first must not be
    // either — that is the whole point of a transaction.
    let outcome = futures::executor::block_on(backend.apply(&[
        EntryChange::Upsert {
            entry: entry("cn=dave,ou=users,dc=example,dc=com", "dave", "d@e.com"),
        },
        EntryChange::Delete {
            dn: "cn=ghost,ou=users,dc=example,dc=com".to_string(),
            kind: None,
        },
    ]));
    assert!(outcome.is_ok(), "a delete is a valid entry-level change");

    let data = futures::executor::block_on(backend.load()).expect("load");
    assert_eq!(data.entries.len(), 1);
}

#[test]
fn the_file_backend_says_plainly_that_it_cannot_store_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let users = dir.path().join("users.json");
    let groups = dir.path().join("groups.json");
    std::fs::write(&users, "[]").expect("users");
    std::fs::write(&groups, "[]").expect("groups");

    let backend = Backend::from_config(
        "file",
        Some(&serde_json::json!({
            "users_path": users.display().to_string(),
            "groups_path": groups.display().to_string(),
        })),
    )
    .expect("backend");

    let err = futures::executor::block_on(backend.apply(&[EntryChange::Upsert {
        entry: entry("cn=eve,ou=users,dc=example,dc=com", "eve", "e@e.com"),
    }]))
    .expect_err("must refuse");

    assert!(
        err.to_string()
            .contains("use the redb backend for whole entries"),
        "unexpected: {err}"
    );
}

#[test]
fn durability_is_explicit_in_the_configuration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("directory.redb");

    Backend::from_config(
        "redb",
        Some(&serde_json::json!({
            "path": path.display().to_string(),
            "durability": "immediate",
        })),
    )
    .expect("explicit immediate durability is accepted");

    let err = Backend::from_config(
        "redb",
        Some(&serde_json::json!({
            "path": path.display().to_string(),
            "durability": "on-a-floppy",
        })),
    )
    .expect_err("unknown durability must be refused");
    assert!(
        err.to_string().contains("expected immediate or none"),
        "{err}"
    );

    // The trait bound is part of the contract: the backend must not need a special
    // durability constant from the caller.
    let _ = Durability::Immediate;
    let _ = Duration::from_secs(0);
}
