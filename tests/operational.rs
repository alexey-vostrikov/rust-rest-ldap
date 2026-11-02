//! Operational attributes: they must be visible on request, invisible in `*`, and
//! impossible for a client to write.
//!
//! RFC 4511 §4.5.1.8 splits the attribute selection: `*` means user attributes, `+`
//! means operational ones. A client that asks for `+` and gets nothing cannot audit the
//! directory, and a client that sees `entryCSN` in a plain `*` search has to filter it
//! out on its side. Both failures are quiet, which is why they are tested here.

use std::time::SystemTime;

use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, ChangeOperation, LdapDn, ModifyRequest, ModifyRequestChanges,
    PartialAttribute, ProtocolOp, ResultCode, SearchRequest, SearchRequestDerefAliases,
    SearchRequestScope,
};
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::ldap::modify::{self, Outcome};
use rust_rest_ldap::ldap::search::handle_search;
use rust_rest_ldap::ldap::session::{Identity, Session};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::operational::{self, ATTR_ENTRY_CSN, ATTR_MODIFY_TIMESTAMP};
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";

fn alice() -> Entry {
    Entry::new(
        ALICE_DN,
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec![
                    "top".to_string(),
                    "person".to_string(),
                    "inetOrgPerson".to_string(),
                ],
            ))
            .push(Attribute::single("cn", "alice"))
            .push(Attribute::single("sn", "Surname"))
            .push(Attribute::single("uid", "alice"))
            .push(Attribute::single("mail", "alice@example.com")),
    )
}

fn directory() -> Directory {
    Directory::from_entries(BASE, "users", "groups", vec![alice()])
}

fn admin() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(ADMIN_DN, true));
    session
}

/// A stamped entry, as the write path would store it.
fn stamped() -> Entry {
    let at = operational::parse_generalized_time("20261102143012.123456Z").expect("parse");
    operational::stamp_write(&alice(), ADMIN_DN, at)
}

fn search(directory: &Directory, base: &str, attributes: &[&str]) -> Vec<(String, Vec<String>)> {
    let request = SearchRequest::new(
        LdapDn::from(base),
        SearchRequestScope::BaseObject,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        rasn_ldap::Filter::Present(AttributeDescription::from("objectClass")),
        attributes
            .iter()
            .map(|name| rasn_ldap::LdapString::from(*name))
            .collect(),
    );

    let messages = handle_search(&admin(), directory, 1, &request, None, &Security::default());

    let mut out = Vec::new();
    for message in messages {
        if let ProtocolOp::SearchResEntry(entry) = message.protocol_op {
            for attribute in entry.attributes {
                out.push((
                    attribute.r#type.0.to_string(),
                    attribute
                        .vals
                        .iter()
                        .map(|value| String::from_utf8_lossy(value.as_ref()).into_owned())
                        .collect(),
                ));
            }
        }
    }
    out
}

fn names(attributes: &[(String, Vec<String>)]) -> Vec<String> {
    attributes
        .iter()
        .map(|(name, _)| name.to_lowercase())
        .collect()
}

fn value(attributes: &[(String, Vec<String>)], name: &str) -> Option<String> {
    attributes
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .and_then(|(_, values)| values.first().cloned())
}

#[test]
fn plus_returns_the_operational_attributes() {
    let directory = Directory::from_entries(BASE, "users", "groups", vec![stamped()]);
    let found = search(&directory, ALICE_DN, &["+"]);

    for name in [
        "createtimestamp",
        "modifytimestamp",
        "creatorsname",
        "modifiersname",
        "entrycsn",
        "entrydn",
    ] {
        assert!(
            names(&found).contains(&name.to_string()),
            "{name} must be returned for +, got {:?}",
            names(&found)
        );
    }
}

#[test]
fn star_does_not_return_the_operational_attributes() {
    let directory = Directory::from_entries(BASE, "users", "groups", vec![stamped()]);
    let found = names(&search(&directory, ALICE_DN, &["*"]));

    for name in [
        "createtimestamp",
        "modifytimestamp",
        "creatorsname",
        "modifiersname",
        "entrycsn",
    ] {
        assert!(
            !found.contains(&name.to_string()),
            "{name} must not be returned for *, got {found:?}"
        );
    }
    assert!(
        found.contains(&"cn".to_string()),
        "user attributes are there"
    );
}

#[test]
fn an_explicit_request_returns_the_named_operational_attribute() {
    let directory = Directory::from_entries(BASE, "users", "groups", vec![stamped()]);
    let found = search(&directory, ALICE_DN, &["createTimestamp"]);

    assert_eq!(
        value(&found, "createTimestamp").as_deref(),
        Some("20261102143012.123456Z")
    );
}

#[test]
fn the_values_are_what_the_schema_expects() {
    let directory = Directory::from_entries(BASE, "users", "groups", vec![stamped()]);
    let schema = rust_rest_ldap::schema::Schema::core();
    let found = search(&directory, ALICE_DN, &["+"]);

    for name in ["createtimestamp", "modifytimestamp"] {
        let value = value(&found, name).expect(name);
        let definition = schema.resolved(name).expect(name);
        let syntax = definition.syntax.expect("syntax");
        assert!(
            syntax.accepts(&value),
            "{name}: '{value}' must match its published syntax"
        );
    }
}

#[test]
fn a_client_cannot_write_the_operational_attributes() {
    let at = operational::parse_generalized_time("20261102143012.123456Z").expect("parse");
    let entry = operational::stamp_write(&alice(), ADMIN_DN, at);
    let directory = Directory::from_entries(BASE, "users", "groups", vec![entry]);

    let request = ModifyRequest {
        object: LdapDn::from(ALICE_DN),
        changes: vec![ModifyRequestChanges {
            operation: ChangeOperation::Replace,
            modification: PartialAttribute::new(
                AttributeDescription::from(ATTR_MODIFY_TIMESTAMP),
                rasn::types::SetOf::from_vec(vec![OctetString::from(
                    "20200101000000.000000Z".as_bytes(),
                )]),
            ),
        }],
    };

    match modify::handle_modify(&admin(), &directory, 1, &request, &Security::default()) {
        Outcome::Reject(message) => {
            let code = match &message.protocol_op {
                ProtocolOp::ModifyResponse(response) => response.0.result_code,
                other => panic!("not a modify response: {other:?}"),
            };
            assert_eq!(code, ResultCode::ConstraintViolation);
        }
        Outcome::Persist { .. } => panic!("an operational attribute must not be writable"),
    }
}

#[test]
fn a_modify_through_the_protocol_stamps_the_write() {
    let directory = directory();
    let request = ModifyRequest {
        object: LdapDn::from(ALICE_DN),
        changes: vec![ModifyRequestChanges {
            operation: ChangeOperation::Replace,
            modification: PartialAttribute::new(
                AttributeDescription::from("mail"),
                rasn::types::SetOf::from_vec(vec![OctetString::from("new@example.com".as_bytes())]),
            ),
        }],
    };

    let before = SystemTime::now();
    let stored =
        match modify::handle_modify(&admin(), &directory, 1, &request, &Security::default()) {
            Outcome::Persist { entry, .. } => entry,
            Outcome::Reject(message) => panic!("expected a write: {message:?}"),
        };

    let created = value(
        &stored
            .attributes()
            .values()
            .iter()
            .map(|attribute| (attribute.name.to_string(), attribute.values.to_vec()))
            .collect::<Vec<_>>(),
        "createTimestamp",
    )
    .expect("createTimestamp");
    assert!(
        operational::parse_generalized_time(&created).expect("parse") >= before,
        "the creation stamp must be the moment of the write, not an invented one"
    );

    let csn = stored.attributes().get(ATTR_ENTRY_CSN).expect("entryCSN");
    assert!(!csn.values[0].is_empty());
    assert!(csn.flags.operational);
}

#[test]
fn a_second_write_moves_the_modification_and_keeps_the_creation() {
    let first = stamped();
    let directory = Directory::from_entries(BASE, "users", "groups", vec![first.clone()]);

    let request = ModifyRequest {
        object: LdapDn::from(ALICE_DN),
        changes: vec![ModifyRequestChanges {
            operation: ChangeOperation::Replace,
            modification: PartialAttribute::new(
                AttributeDescription::from("mail"),
                rasn::types::SetOf::from_vec(vec![OctetString::from(
                    "later@example.com".as_bytes(),
                )]),
            ),
        }],
    };

    let second =
        match modify::handle_modify(&admin(), &directory, 1, &request, &Security::default()) {
            Outcome::Persist { entry, .. } => entry,
            Outcome::Reject(message) => panic!("expected a write: {message:?}"),
        };

    assert_eq!(
        second
            .attributes()
            .get("createTimestamp")
            .map(|attribute| attribute.values.to_vec()),
        first
            .attributes()
            .get("createTimestamp")
            .map(|attribute| attribute.values.to_vec()),
        "a modify is not a creation"
    );
    assert_ne!(
        second
            .attributes()
            .get(ATTR_MODIFY_TIMESTAMP)
            .map(|attribute| attribute.values.to_vec()),
        first
            .attributes()
            .get(ATTR_MODIFY_TIMESTAMP)
            .map(|attribute| attribute.values.to_vec()),
        "the modification time has to move"
    );
}
