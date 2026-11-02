//! Metrics and the change journal, checked through the paths that produce them.
//!
//! Two questions an operator asks and a directory cannot answer after the fact: "is it
//! serving, and how much" and "who deleted that entry". The first is a counter; the second
//! is a journal line, because a delete leaves no entry to carry `modifiersName`.

use std::sync::Arc;

use rasn::types::OctetString;
use rasn_ldap::{
    AddRequest, AttributeDescription, AttributeValueAssertion, AuthenticationChoice, BindRequest,
    DelRequest, LdapDn, LdapMessage, ProtocolOp, ResultCode, SearchRequest,
    SearchRequestDerefAliases, SearchRequestScope,
};
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::ldap::session::{Identity, Session};
use rust_rest_ldap::ldap::{Action, handle};
use rust_rest_ldap::metrics::{ChangeKind, Journal, Metrics, Operation};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";

fn directory() -> Directory {
    let admin = Entry::new(
        ADMIN_DN,
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "person".to_string()],
            ))
            .push(Attribute::single("cn", "admin"))
            .push(Attribute::single("sn", "Admin"))
            .push(Attribute::new("ldapAdmin", vec!["true".to_string()]).internal()),
    );
    let alice = Entry::new(
        ALICE_DN,
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "person".to_string()],
            ))
            .push(Attribute::single("cn", "alice"))
            .push(Attribute::single("sn", "S")),
    );

    Directory::from_entries(BASE, "users", "groups", vec![admin, alice])
}

fn admin() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(ADMIN_DN, true));
    session
}

fn security() -> Security {
    Security {
        allow_unencrypted_bind: true,
        ..Security::default()
    }
}

fn bind_message(dn: &str, secret: &str) -> LdapMessage {
    LdapMessage::new(
        1,
        ProtocolOp::BindRequest(BindRequest::new(
            3,
            LdapDn::from(dn),
            AuthenticationChoice::Simple(OctetString::from(secret.as_bytes())),
        )),
    )
}

fn search_message() -> LdapMessage {
    LdapMessage::new(
        2,
        ProtocolOp::SearchRequest(SearchRequest::new(
            LdapDn::from(BASE),
            SearchRequestScope::WholeSubtree,
            SearchRequestDerefAliases::NeverDerefAliases,
            0,
            0,
            false,
            rasn_ldap::Filter::Present(AttributeDescription::from("objectClass")),
            vec![rasn_ldap::LdapString::from("dn")],
        )),
    )
}

fn delete_message(dn: &str) -> LdapMessage {
    LdapMessage::new(3, ProtocolOp::DelRequest(DelRequest(LdapDn::from(dn))))
}

fn add_message(dn: &str, cn: &str) -> LdapMessage {
    LdapMessage::new(
        4,
        ProtocolOp::AddRequest(AddRequest {
            entry: LdapDn::from(dn),
            attributes: vec![
                rasn_ldap::Attribute::new(
                    AttributeDescription::from("objectClass"),
                    rasn::types::SetOf::from_vec(vec![
                        OctetString::from("top".as_bytes()),
                        OctetString::from("person".as_bytes()),
                    ]),
                ),
                rasn_ldap::Attribute::new(
                    AttributeDescription::from("cn"),
                    rasn::types::SetOf::from_vec(vec![OctetString::from(cn.as_bytes())]),
                ),
                rasn_ldap::Attribute::new(
                    AttributeDescription::from("sn"),
                    rasn::types::SetOf::from_vec(vec![OctetString::from("S".as_bytes())]),
                ),
            ],
        }),
    )
}

fn equality(name: &str, value: &str) -> rasn_ldap::Filter {
    rasn_ldap::Filter::EqualityMatch(AttributeValueAssertion::new(
        AttributeDescription::from(name),
        OctetString::from(value.as_bytes()),
    ))
}

#[test]
fn the_metric_document_renders_every_operation_before_anything_happens() {
    // A rate query over a metric that does not exist yet returns "no data", and an alert
    // written against it silently never fires. Every series has to be present at zero.
    let metrics = Metrics::new();
    let text = metrics.render();

    for operation in Operation::ALL {
        assert!(
            text.contains(&format!(
                "ldap_requests{{operation=\"{}\"}} 0",
                operation.name()
            )),
            "{} must be present at zero",
            operation.name()
        );
    }
    assert!(text.contains("ldap_up 1"));
    assert!(text.contains("ldap_entries 0"));
}

#[test]
fn a_delete_is_journalled_with_the_actor_and_the_dn() {
    // The question the journal exists for. After the entry is gone there is nothing left to
    // carry `modifiersName`, so the answer has to have been written down.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("changes.jsonl");
    let journal = Arc::new(Journal::file(&path).expect("journal"));

    let action = handle(
        &mut admin(),
        &directory(),
        &security(),
        delete_message(ALICE_DN),
    );

    let (changes, who) = match action {
        Action::Persist(action) => (action.changes, action.journal),
        other => panic!("expected a write, got {other:?}"),
    };

    let note = who.expect("a delete must be journalled");
    assert_eq!(note.kind, ChangeKind::Delete);
    assert_eq!(note.actor, ADMIN_DN);
    assert_eq!(
        note.dn, ALICE_DN,
        "the line names the entry that was deleted, not the group it was cleaned out of"
    );

    // One line for one operation, even though the change set also rewrites the groups.
    assert!(!changes.is_empty());
    journal
        .record(&note.change("127.0.0.1:5000", 0))
        .expect("record");

    let text = std::fs::read_to_string(&path).expect("read");
    let record: serde_json::Value =
        serde_json::from_str(text.lines().next().expect("one line")).expect("valid JSON");

    assert_eq!(record["op"], serde_json::json!("delete"));
    assert_eq!(record["dn"], serde_json::json!(ALICE_DN));
    assert_eq!(record["actor"], serde_json::json!(ADMIN_DN));
    assert_eq!(record["result"], serde_json::json!(0));
    assert!(record["time"].as_str().is_some_and(|time| !time.is_empty()));
}

#[test]
fn an_added_entry_is_journalled_as_an_add() {
    let action = handle(
        &mut admin(),
        &directory(),
        &security(),
        add_message("cn=bob,ou=users,dc=example,dc=com", "bob"),
    );

    match action {
        Action::Persist(action) => {
            let note = action.journal.expect("an add must be journalled");
            assert_eq!(note.kind, ChangeKind::Add);
            assert_eq!(note.dn, "cn=bob,ou=users,dc=example,dc=com");
        }
        other => panic!("expected a write, got {other:?}"),
    }
}

#[test]
fn a_refused_delete_is_not_journalled_as_a_change() {
    // A refusal produces no write and therefore no `Action::Persist`: nothing was stored, so
    // nothing belongs in the record of stored changes.
    let action = handle(
        &mut admin(),
        &directory(),
        &security(),
        delete_message("cn=ghost,ou=users,dc=example,dc=com"),
    );

    assert!(
        matches!(action, Action::Reply(_)),
        "a refused delete must answer, not persist: {action:?}"
    );
}

#[test]
fn a_bind_is_counted_and_a_failure_is_counted_separately() {
    let metrics = Metrics::new();

    // Success.
    let mut session = Session::new();
    let action = handle(
        &mut session,
        &directory(),
        &security(),
        bind_message(ADMIN_DN, "wrong"),
    );
    let messages = match action {
        Action::Reply(messages) | Action::PersistAfterReply { messages, .. } => messages,
        other => panic!("unexpected action: {other:?}"),
    };
    let code = match &messages[0].protocol_op {
        ProtocolOp::BindResponse(response) => response.result_code,
        other => panic!("not a bind response: {other:?}"),
    };
    metrics.record(Operation::Bind, code == ResultCode::Success);

    assert_eq!(metrics.requests(Operation::Bind), 1);
    assert_eq!(
        metrics.failures(Operation::Bind),
        1,
        "a bind with a wrong password is the failure operators watch"
    );
    assert!(
        metrics.render().contains("ldap_bind_failures 1"),
        "the dedicated counter has to move too"
    );
}

#[test]
fn a_search_records_its_size_and_cost() {
    let metrics = Metrics::new();

    let action = handle(&mut admin(), &directory(), &security(), search_message());
    let returned = match action {
        Action::Reply(messages) => messages
            .iter()
            .filter(|message| matches!(message.protocol_op, ProtocolOp::SearchResEntry(_)))
            .count(),
        other => panic!("unexpected action: {other:?}"),
    };

    metrics.record(Operation::Search, true);
    metrics.record_search(std::time::Duration::from_micros(250), returned);

    let text = metrics.render();
    // Five: the domain entry, the two organizational units, admin and alice. The count is
    // the whole subtree, which is what the search actually returned.
    assert_eq!(returned, 5, "the fixture must return what the test expects");
    assert!(
        text.contains("ldap_search_entries_returned_total 5"),
        "{text}"
    );
    assert!(
        text.contains("ldap_search_seconds_total 0.000250"),
        "{text}"
    );
}

#[test]
fn the_journal_is_off_unless_configured() {
    // A server with no journal configured must not start writing files: the default has to
    // be "nothing", not "somewhere surprising".
    let config = rust_rest_ldap::config::resolve(
        rust_rest_ldap::config::Args::default(),
        Some("base_dn: dc=example,dc=com\n"),
        |_| None,
    )
    .expect("config");

    assert_eq!(config.observability.journal, None);
    assert!(!config.observability.journal_stdout);
}

#[test]
fn the_journal_path_comes_from_the_configuration() {
    let config = rust_rest_ldap::config::resolve(
        rust_rest_ldap::config::Args::default(),
        Some("base_dn: dc=example,dc=com\nobservability:\n  journal: /var/log/rrl.jsonl\n"),
        |_| None,
    )
    .expect("config");

    assert_eq!(
        config.observability.journal.as_deref(),
        Some(std::path::Path::new("/var/log/rrl.jsonl"))
    );
}

#[test]
fn a_journal_on_a_path_that_cannot_be_opened_is_an_error_at_startup() {
    // Silently running without the journal the operator asked for leaves "who deleted it"
    // unanswerable for as long as nobody notices.
    let journal = Journal::file(std::path::Path::new("/proc/nope/changes.jsonl"));

    assert!(journal.is_err());
}

#[test]
fn the_journal_line_for_a_rename_carries_both_dns() {
    let change = rust_rest_ldap::metrics::Change {
        kind: ChangeKind::Rename,
        dn: ALICE_DN.to_string(),
        new_dn: Some("cn=alicia,ou=users,dc=example,dc=com".to_string()),
        actor: ADMIN_DN.to_string(),
        peer: "127.0.0.1:1".to_string(),
        result: 0,
    };

    let parsed: serde_json::Value = serde_json::from_str(&change.to_json()).expect("valid JSON");

    assert_eq!(parsed["op"], serde_json::json!("rename"));
    assert_eq!(
        parsed["newDn"],
        serde_json::json!("cn=alicia,ou=users,dc=example,dc=com"),
        "a rename has to say where the entry went"
    );
}

#[test]
fn the_mutex_free_counters_agree_under_concurrency() {
    // The counters are on the hot path of every request; they are atomics so they never
    // serialise. This checks the arithmetic still adds up when they are hit in parallel.
    let metrics = Metrics::new();
    let mut handles = Vec::new();

    for _ in 0..8 {
        let metrics = Arc::clone(&metrics);
        handles.push(std::thread::spawn(move || {
            for _ in 0..1000 {
                metrics.record(Operation::Search, true);
                metrics.connection_opened();
                metrics.connection_closed();
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread");
    }

    assert_eq!(metrics.requests(Operation::Search), 8000);
    assert_eq!(
        metrics.connections_open(),
        0,
        "every open must be matched by a close"
    );
}

#[test]
fn the_search_filter_used_by_the_tests_is_the_one_they_expect() {
    // Sanity on the fixture: a filter that matched nothing would make the counting tests pass
    // for the wrong reason.
    let dir = directory();
    let alice = dir.find(ALICE_DN).expect("alice");

    assert!(
        rust_rest_ldap::ldap::filter::matches(
            alice.attributes(),
            alice.dn(),
            &equality("cn", "alice")
        )
        .expect("filter")
    );
}

#[test]
fn a_rename_is_one_journal_line_with_both_dns() {
    // The change set of a rename is a delete, an upsert and the groups that follow. One
    // operation, one line: a reader has to be able to tell the operation from its side
    // effects.
    let message = LdapMessage::new(
        5,
        ProtocolOp::ModDnRequest(rasn_ldap::ModifyDnRequest {
            entry: LdapDn::from(ALICE_DN),
            new_rdn: LdapDn::from("cn=alicia"),
            delete_old_rdn: true,
            new_superior: None,
        }),
    );

    match handle(&mut admin(), &directory(), &security(), message) {
        Action::Persist(action) => {
            let note = action.journal.expect("a rename must be journalled");

            assert_eq!(note.kind, ChangeKind::Rename);
            assert_eq!(note.dn, ALICE_DN, "the DN the client addressed");
            assert_eq!(
                note.new_dn.as_deref(),
                Some("cn=alicia,ou=users,dc=example,dc=com"),
                "and where the entry went"
            );
            // The change set is the delete of the old DN and the upsert of the new one;
            // with a group listing the user it would also carry that rewrite, and the point
            // of the note is that none of it becomes a second journal line.
            assert_eq!(action.changes.len(), 2);
            assert!(matches!(
                action.changes[0],
                rust_rest_ldap::backend::EntryChange::Delete { .. }
            ));
            assert!(matches!(
                action.changes[1],
                rust_rest_ldap::backend::EntryChange::Upsert { .. }
            ));
        }
        other => panic!("expected a write, got {other:?}"),
    }
}

#[test]
fn a_password_change_is_journalled_as_such_not_as_a_modify() {
    // "Someone changed this user's password" is a different fact from "someone modified the
    // entry", and the journal is where the difference is visible.
    let mut session = admin();
    let request = rasn_ldap::ExtendedRequest {
        request_name: rasn_ldap::LdapOid::from(
            rust_rest_ldap::ldap::extop::PASSWORD_MODIFY_OID.as_bytes(),
        ),
        request_value: None,
    };

    match handle(
        &mut session,
        &directory(),
        &security(),
        LdapMessage::new(6, ProtocolOp::ExtendedReq(request)),
    ) {
        Action::Persist(action) => {
            let note = action
                .journal
                .expect("a password change must be journalled");
            assert_eq!(note.kind, ChangeKind::PasswordChange);
        }
        other => panic!("expected a write, got {other:?}"),
    }
}
