//! `modify` over the protocol: what a client sends, what it gets back, what is stored.
//!
//! The handler is checked directly rather than over a socket, so a failing assertion
//! names the result code instead of a broken stream. The persistence side is in
//! `tests/write_path.rs`.

use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, AttributeValueAssertion, ChangeOperation, LdapMessage,
    ModifyRequestChanges, PartialAttribute, ProtocolOp, ResultCode,
};
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::ldap::modify::{self, Outcome};
use rust_rest_ldap::ldap::session::{Identity, Session};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";

fn entry(cn: &str, mail: &[&str]) -> Entry {
    let mut attributes = Attributes::new()
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
        // The `uid=<cn>,ou=users,…` alias resolves through this attribute.
        .push(Attribute::single("uid", cn))
        .push(
            Attribute::new("userPassword", vec!["{SSHA}AbC".to_string()])
                .case_sensitive()
                .sensitive(),
        );
    if !mail.is_empty() {
        attributes = attributes.push(Attribute::new(
            "mail",
            mail.iter().map(|value| value.to_string()).collect(),
        ));
    }
    Entry::new(format!("cn={cn},ou=users,{BASE}"), attributes)
}

fn directory() -> Directory {
    Directory::from_entries(
        BASE,
        "users",
        "groups",
        vec![
            entry("alice", &["alice@example.com", "a@example.com"]),
            entry("bob", &["bob@example.com"]),
        ],
    )
}

fn admin() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(ADMIN_DN, true));
    session
}

fn alice() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(ALICE_DN, false));
    session
}

fn anonymous() -> Session {
    Session::new()
}

fn change(op: ChangeOperation, attribute: &str, values: &[&str]) -> ModifyRequestChanges {
    ModifyRequestChanges {
        operation: op,
        modification: PartialAttribute::new(
            AttributeDescription::from(attribute),
            rasn::types::SetOf::from_vec(
                values
                    .iter()
                    .map(|value| OctetString::from(value.as_bytes()))
                    .collect(),
            ),
        ),
    }
}

fn request(dn: &str, changes: Vec<ModifyRequestChanges>) -> rasn_ldap::ModifyRequest {
    rasn_ldap::ModifyRequest {
        object: rasn_ldap::LdapDn::from(dn),
        changes,
    }
}

fn run(session: &Session, dn: &str, changes: Vec<ModifyRequestChanges>) -> Outcome {
    modify::handle_modify(
        session,
        &directory(),
        1,
        &request(dn, changes),
        None,
        &Security::default(),
    )
}

fn code(message: &LdapMessage) -> ResultCode {
    match &message.protocol_op {
        ProtocolOp::ModifyResponse(response) => response.0.result_code,
        other => panic!("not a modify response: {other:?}"),
    }
}

/// The result code of a rejected request.
fn rejection(session: &Session, dn: &str, changes: Vec<ModifyRequestChanges>) -> ResultCode {
    match run(session, dn, changes) {
        Outcome::Reject(message) => code(&message),
        Outcome::Persist { .. } => panic!("expected a rejection, got a write"),
    }
}

/// The entry a request would store.
fn persisted(session: &Session, dn: &str, changes: Vec<ModifyRequestChanges>) -> Entry {
    match run(session, dn, changes) {
        Outcome::Persist { entry, success, .. } => {
            assert_eq!(code(&success), ResultCode::Success);
            entry
        }
        Outcome::Reject(message) => {
            panic!("expected a write, got {:?}: {message:?}", code(&message))
        }
    }
}

fn values(entry: &Entry, name: &str) -> Option<Vec<String>> {
    entry
        .attributes()
        .get(name)
        .map(|attribute| attribute.values.to_vec())
}

#[test]
fn replace_changes_the_value_and_asks_for_a_write() {
    let updated = persisted(
        &admin(),
        ALICE_DN,
        vec![change(
            ChangeOperation::Replace,
            "mail",
            &["new@example.com"],
        )],
    );

    assert_eq!(
        values(&updated, "mail"),
        Some(vec!["new@example.com".to_string()])
    );
}

#[test]
fn add_appends_a_value() {
    let updated = persisted(
        &admin(),
        ALICE_DN,
        vec![change(ChangeOperation::Add, "mail", &["third@example.com"])],
    );

    assert_eq!(
        values(&updated, "mail"),
        Some(vec![
            "alice@example.com".to_string(),
            "a@example.com".to_string(),
            "third@example.com".to_string()
        ])
    );
}

#[test]
fn delete_removes_the_whole_attribute() {
    let updated = persisted(
        &admin(),
        ALICE_DN,
        vec![change(ChangeOperation::Delete, "mail", &[])],
    );

    assert_eq!(values(&updated, "mail"), None);
}

#[test]
fn several_changes_are_one_unit() {
    let updated = persisted(
        &admin(),
        ALICE_DN,
        vec![
            change(ChangeOperation::Delete, "mail", &[]),
            change(ChangeOperation::Add, "mail", &["only@example.com"]),
            change(
                ChangeOperation::Add,
                "telephoneNumber",
                &["+7 495 000-00-00"],
            ),
        ],
    );

    assert_eq!(
        values(&updated, "mail"),
        Some(vec!["only@example.com".to_string()])
    );
    assert_eq!(
        values(&updated, "telephoneNumber"),
        Some(vec!["+7 495 000-00-00".to_string()])
    );
}

#[test]
fn a_missing_entry_is_no_such_object() {
    assert_eq!(
        rejection(
            &admin(),
            "cn=nobody,ou=users,dc=example,dc=com",
            vec![change(ChangeOperation::Replace, "sn", &["X"])],
        ),
        ResultCode::NoSuchObject
    );
}

#[test]
fn a_malformed_dn_is_invalid_dn_syntax() {
    assert_eq!(
        rejection(
            &admin(),
            "cn=broken,,",
            vec![change(ChangeOperation::Replace, "sn", &["X"])],
        ),
        ResultCode::InvalidDnSyntax
    );
}

#[test]
fn the_domain_and_the_ous_are_not_modifiable() {
    for dn in [
        BASE,
        "ou=users,dc=example,dc=com",
        "ou=groups,dc=example,dc=com",
    ] {
        assert_eq!(
            rejection(
                &admin(),
                dn,
                vec![change(ChangeOperation::Replace, "o", &["X"])]
            ),
            ResultCode::UnwillingToPerform,
            "{dn} must be refused"
        );
    }
}

#[test]
fn a_user_may_modify_their_own_entry() {
    let updated = persisted(
        &alice(),
        ALICE_DN,
        vec![change(
            ChangeOperation::Replace,
            "mail",
            &["mine@example.com"],
        )],
    );

    assert_eq!(
        values(&updated, "mail"),
        Some(vec!["mine@example.com".to_string()])
    );
}

#[test]
fn a_user_may_not_modify_someone_elses_entry() {
    assert_eq!(
        rejection(
            &alice(),
            "cn=bob,ou=users,dc=example,dc=com",
            vec![change(ChangeOperation::Replace, "mail", &["x@example.com"])],
        ),
        ResultCode::InsufficientAccessRights
    );
}

#[test]
fn an_anonymous_session_may_not_modify_anything() {
    assert_eq!(
        rejection(
            &anonymous(),
            ALICE_DN,
            vec![change(ChangeOperation::Replace, "mail", &["x@example.com"])],
        ),
        ResultCode::InsufficientAccessRights
    );
}

#[test]
fn deleting_a_missing_attribute_is_no_such_attribute() {
    assert_eq!(
        rejection(
            &admin(),
            ALICE_DN,
            vec![change(ChangeOperation::Delete, "telephoneNumber", &[])],
        ),
        ResultCode::NoSuchAttribute
    );
}

#[test]
fn adding_an_existing_value_is_attribute_or_value_exists() {
    assert_eq!(
        rejection(
            &admin(),
            ALICE_DN,
            vec![change(ChangeOperation::Add, "mail", &["ALICE@example.com"],)],
        ),
        ResultCode::AttributeOrValueExists
    );
}

#[test]
fn modifying_an_operational_attribute_is_a_constraint_violation() {
    let security = Security::default();
    let mut directory = directory();
    // Give the entry an operational attribute the way the server would.
    let with_uuid = Entry::new(
        ALICE_DN,
        directory
            .find(ALICE_DN)
            .expect("alice")
            .attributes()
            .clone()
            .push(Attribute::single("entryUUID", "aaaa-bbbb").operational()),
    );
    let entries: Vec<Entry> = directory
        .all()
        .iter()
        .map(|entry| {
            if entry.dn() == ALICE_DN {
                with_uuid.clone()
            } else {
                entry.clone()
            }
        })
        .collect();
    directory = Directory::from_entries(BASE, "users", "groups", entries);

    let outcome = modify::handle_modify(
        &admin(),
        &directory,
        1,
        &request(
            ALICE_DN,
            vec![change(ChangeOperation::Replace, "entryUUID", &["cccc"])],
        ),
        None,
        &security,
    );

    match outcome {
        Outcome::Reject(message) => assert_eq!(code(&message), ResultCode::ConstraintViolation),
        Outcome::Persist { .. } => panic!("an operational attribute must not be written"),
    }
}

#[test]
fn a_write_that_would_break_the_schema_is_refused() {
    // Removing `sn` leaves a person entry that MUST it: strict mode refuses.
    assert_eq!(
        rejection(
            &admin(),
            ALICE_DN,
            vec![change(ChangeOperation::Delete, "sn", &[])],
        ),
        ResultCode::ObjectClassViolation
    );
}

#[test]
fn schema_off_lets_the_write_through() {
    let security = Security {
        schema_mode: rust_rest_ldap::schema::Mode::Off,
        ..Security::default()
    };

    let outcome = modify::handle_modify(
        &admin(),
        &directory(),
        1,
        &request(ALICE_DN, vec![change(ChangeOperation::Delete, "sn", &[])]),
        None,
        &security,
    );

    match outcome {
        Outcome::Persist { entry, .. } => assert_eq!(values(&entry, "sn"), None),
        Outcome::Reject(message) => panic!("schema off must not refuse: {:?}", code(&message)),
    }
}

#[test]
fn the_password_hash_survives_a_modify_of_another_attribute() {
    let updated = persisted(
        &admin(),
        ALICE_DN,
        vec![change(ChangeOperation::Replace, "mail", &["x@example.com"])],
    );

    let password = updated.attributes().get("userPassword").expect("password");
    assert_eq!(password.values.to_vec(), vec!["{SSHA}AbC".to_string()]);
    assert!(password.flags.case_sensitive && password.flags.sensitive);
}

#[test]
fn the_dn_of_the_stored_entry_is_the_requested_one() {
    let updated = persisted(
        &admin(),
        "uid=alice,ou=users,dc=example,dc=com",
        vec![change(ChangeOperation::Replace, "mail", &["x@example.com"])],
    );

    assert_eq!(
        updated.dn(),
        ALICE_DN,
        "the entry is stored under its real DN, not the alias the client used"
    );
}

#[test]
fn a_filter_attribute_after_a_modify_reflects_the_new_value() {
    // The stored entry is what a later search matches: this checks the value is not
    // only in the reply, but in the entry handed to the store.
    let updated = persisted(
        &admin(),
        ALICE_DN,
        vec![change(
            ChangeOperation::Replace,
            "mail",
            &["moved@example.com"],
        )],
    );

    let assertion = AttributeValueAssertion::new(
        AttributeDescription::from("mail"),
        OctetString::from("moved@example.com".as_bytes()),
    );
    let filter = rasn_ldap::Filter::EqualityMatch(assertion);

    assert!(
        rust_rest_ldap::ldap::filter::matches(updated.attributes(), updated.dn(), &filter)
            .expect("filter"),
        "the stored entry must match the new value"
    );
}
