//! The schema over the protocol, through the dispatcher a client actually reaches.
//!
//! The unit tests in `src/ldap/schema_entry.rs` check the entry. This file checks the two
//! things a client experiences and a test of the entry alone cannot: that a search for
//! `cn=Subschema` reaches the entry without passing the ACL as a data entry, and that a
//! normal entry tells you where the schema is.

use rasn_ldap::{
    AttributeDescription, LdapDn, LdapMessage, ProtocolOp, ResultCode, SearchRequest,
    SearchRequestDerefAliases, SearchRequestScope,
};
use rrl_directory::directory::Directory;
use rrl_directory::ldap::session::{Identity, Session};
use rrl_directory::ldap::{Action, handle};
use rrl_directory::model::{Attribute, Attributes, Entry};
use rrl_directory::security::Security;

const BASE: &str = "dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";

fn directory() -> Directory {
    let alice = Entry::new(
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
            .push(Attribute::single("uid", "alice")),
    );

    Directory::from_entries(BASE, "users", "groups", vec![alice])
}

fn admin() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new("cn=admin,ou=users,dc=example,dc=com", true));
    session
}

fn search(
    session: &mut Session,
    base: &str,
    scope: SearchRequestScope,
    attributes: &[&str],
) -> Vec<LdapMessage> {
    let request = SearchRequest::new(
        LdapDn::from(base),
        scope,
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

    let directory = directory();
    let security = Security {
        allow_unencrypted_bind: true,
        ..Security::default()
    };

    match handle(
        session,
        &directory,
        &security,
        LdapMessage::new(1, ProtocolOp::SearchRequest(request)),
    ) {
        Action::Reply(messages) => messages,
        other => panic!("unexpected action: {other:?}"),
    }
}

/// Attribute names of the single returned entry, lowercased.
fn entry_attributes(messages: &[LdapMessage]) -> Vec<String> {
    messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => Some(
                entry
                    .attributes
                    .iter()
                    .map(|attribute| attribute.r#type.0.to_lowercase())
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

fn entry_values(messages: &[LdapMessage], name: &str) -> Vec<String> {
    messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => Some(entry),
            _ => None,
        })
        .map(|entry| {
            entry
                .attributes
                .iter()
                .filter(|attribute| attribute.r#type.0.eq_ignore_ascii_case(name))
                .flat_map(|attribute| {
                    attribute
                        .vals
                        .iter()
                        .map(|value| String::from_utf8_lossy(value.as_ref()).into_owned())
                })
                .collect()
        })
        .unwrap_or_default()
}

fn entry_dn(messages: &[LdapMessage]) -> Option<String> {
    messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => Some(entry.object_name.0.clone()),
            _ => None,
        })
}

fn result_code(messages: &[LdapMessage]) -> ResultCode {
    messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResDone(done) => Some(done.0.result_code),
            _ => None,
        })
        .expect("a search always ends with a done")
}

#[test]
fn a_client_reads_the_schema_over_the_protocol() {
    let messages = search(
        &mut admin(),
        "cn=Subschema",
        SearchRequestScope::BaseObject,
        &["attributeTypes", "objectClasses"],
    );

    assert_eq!(result_code(&messages), ResultCode::Success);
    assert!(
        !entry_values(&messages, "attributeTypes").is_empty(),
        "the whole point of the subentry is that it carries the definitions"
    );
    assert!(!entry_values(&messages, "objectClasses").is_empty());
}

#[test]
fn the_answer_carries_the_dn_the_client_asked_for() {
    // A client that compares the returned DN with its base must not see `cn=subschema`
    // when it asked for `cn=Subschema`.
    let messages = search(
        &mut admin(),
        "cn=Subschema",
        SearchRequestScope::BaseObject,
        &["cn"],
    );

    assert_eq!(entry_dn(&messages).as_deref(), Some("cn=Subschema"));
}

#[test]
fn the_other_spelling_works_too() {
    let messages = search(
        &mut admin(),
        "cn=schema",
        SearchRequestScope::BaseObject,
        &["attributeTypes"],
    );

    assert_eq!(result_code(&messages), ResultCode::Success);
    assert!(!entry_values(&messages, "attributeTypes").is_empty());
}

#[test]
fn a_star_search_returns_the_entry_without_the_definitions() {
    let messages = search(
        &mut admin(),
        "cn=Subschema",
        SearchRequestScope::BaseObject,
        &["*"],
    );
    let names = entry_attributes(&messages);

    assert!(names.contains(&"objectclass".to_string()));
    assert!(
        !names.contains(&"attributetypes".to_string()),
        "definitions are operational and must be asked for: {names:?}"
    );
}

#[test]
fn a_plus_search_returns_them() {
    let messages = search(
        &mut admin(),
        "cn=Subschema",
        SearchRequestScope::BaseObject,
        &["+"],
    );
    let names = entry_attributes(&messages);

    assert!(names.contains(&"attributetypes".to_string()));
    assert!(names.contains(&"objectclasses".to_string()));
    assert!(names.contains(&"ldapsyntaxes".to_string()));
}

#[test]
fn a_one_level_search_of_the_subentry_finds_nothing() {
    // The entry has no children. Answering with itself would be wrong: one level means
    // the immediate subordinates.
    let messages = search(
        &mut admin(),
        "cn=Subschema",
        SearchRequestScope::SingleLevel,
        &["*"],
    );

    assert_eq!(result_code(&messages), ResultCode::Success);
    assert!(entry_dn(&messages).is_none());
}

#[test]
fn a_normal_entry_says_where_its_schema_is() {
    // RFC 4512 §3.4: every entry names the subentry that governs it, so a client does
    // not have to know the DN in advance.
    let messages = search(
        &mut admin(),
        ALICE_DN,
        SearchRequestScope::BaseObject,
        &["+"],
    );

    assert_eq!(
        entry_values(&messages, "subschemaSubentry"),
        vec!["cn=Subschema".to_string()],
        "the entry must point at the published schema"
    );
}

#[test]
fn the_root_dse_names_the_schema() {
    let messages = search(
        &mut admin(),
        "",
        SearchRequestScope::BaseObject,
        &["subschemaSubentry"],
    );

    assert_eq!(
        entry_values(&messages, "subschemaSubentry"),
        vec!["cn=Subschema".to_string()],
        "discovery starts at the root DSE"
    );
}

#[test]
fn the_definitions_describe_what_the_server_enforces() {
    // The claim the publication makes: read the schema from the server, and the rules it
    // states are the rules the write path applies. `cn` and `sn` are MUST for a person,
    // which is what the schema check refuses to break.
    let messages = search(
        &mut admin(),
        "cn=Subschema",
        SearchRequestScope::BaseObject,
        &["objectClasses", "attributeTypes"],
    );
    let classes = entry_values(&messages, "objectClasses");
    let person = classes
        .iter()
        .find(|definition| definition.contains("'person'"))
        .expect("person must be published");

    assert!(person.contains("MUST"), "{person}");
    assert!(person.contains("sn"), "{person}");
    assert!(person.contains("cn"), "{person}");
}

#[test]
fn an_anonymous_client_may_read_the_schema() {
    // A client needs the schema to build a bind request; refusing it before bind would
    // make the server unusable for every tool that explores first.
    let mut session = Session::new();
    let messages = search(
        &mut session,
        "cn=Subschema",
        SearchRequestScope::BaseObject,
        &["attributeTypes"],
    );

    assert_eq!(
        result_code(&messages),
        ResultCode::Success,
        "the schema is not secret: it describes the software, not the data"
    );
    assert!(!entry_values(&messages, "attributeTypes").is_empty());
}
