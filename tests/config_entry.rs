//! `cn=config` over the protocol: what an administrator reads and what a client cannot.
//!
//! The subtree is generated from the configuration document, so these tests drive it through
//! the dispatch layer the server uses - the same `handle` a connection calls - rather than
//! calling the renderer. What matters to an operator is the answer on the wire: which entries,
//! which attributes, and which refusal when the bind did not carry the admin flag.

use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, AttributeValueAssertion, ChangeOperation, Filter, LdapDn, LdapMessage,
    ModifyRequest, ModifyRequestChanges, PartialAttribute, ProtocolOp, ResultCode, SearchRequest,
    SearchRequestDerefAliases, SearchRequestScope,
};
use rust_rest_ldap::config::Document;
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::ldap::session::{Identity, Session};
use rust_rest_ldap::ldap::{Action, handle};
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const CONFIG_DN: &str = "cn=config";

const DOCUMENT: &str = "\
base_dn: dc=example,dc=com
backend: redb
listen_addr: 127.0.0.1:1389
use_tls: false
backends:
  redb:
    path: ./directory.redb
indexes:
  default: [pres]
  attributes:
    cn: [eq, pres]
";

fn directory() -> Directory {
    Directory::from_entries(BASE, "users", "groups", Vec::new())
}

fn security(document: Option<&str>) -> Security {
    Security {
        config_document: document
            .map(|text| Document::new(text, "store:/etc/config.d generation 3")),
        ..Security::default()
    }
}

fn admin() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(ADMIN_DN, true));
    session
}

fn user() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new("cn=alice,ou=users,dc=example,dc=com", false));
    session
}

fn search_request(base: &str, scope: SearchRequestScope, attributes: &[&str]) -> SearchRequest {
    SearchRequest::new(
        LdapDn::from(base),
        scope,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        Filter::Present(AttributeDescription::from("objectClass")),
        attributes
            .iter()
            .map(|name| rasn_ldap::LdapString::from(*name))
            .collect(),
    )
}

/// One entry as it came off the wire: its DN and the attributes with their values.
type WireEntry = (String, Vec<(String, Vec<String>)>);

struct Answer {
    code: ResultCode,
    diagnostic: String,
    entries: Vec<WireEntry>,
}

fn run(session: &mut Session, request: SearchRequest, security: &Security) -> Answer {
    let directory = directory();
    let action = handle(
        session,
        &directory,
        security,
        LdapMessage::new(2, ProtocolOp::SearchRequest(request)),
    );

    let messages = match action {
        Action::Reply(messages) => messages,
        other => panic!("unexpected action: {other:?}"),
    };

    let mut answer = Answer {
        code: ResultCode::Other,
        diagnostic: String::new(),
        entries: Vec::new(),
    };

    for message in messages {
        match message.protocol_op {
            ProtocolOp::SearchResEntry(result) => {
                let attributes = result
                    .attributes
                    .iter()
                    .map(|attribute| {
                        (
                            attribute.r#type.0.to_string(),
                            attribute
                                .vals
                                .iter()
                                .map(|value| String::from_utf8_lossy(value.as_ref()).into_owned())
                                .collect(),
                        )
                    })
                    .collect();
                answer
                    .entries
                    .push((result.object_name.0.clone(), attributes));
            }
            ProtocolOp::SearchResDone(done) => {
                answer.code = done.0.result_code;
                answer.diagnostic = done.0.diagnostic_message.0.to_string();
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    answer
}

fn values(entry: &WireEntry, name: &str) -> Vec<String> {
    entry
        .1
        .iter()
        .filter(|(attribute, _)| attribute.eq_ignore_ascii_case(name))
        .flat_map(|(_, values)| values.clone())
        .collect()
}

fn dns(answer: &Answer) -> Vec<String> {
    answer.entries.iter().map(|(dn, _)| dn.clone()).collect()
}

#[test]
fn an_administrator_reads_the_whole_configuration_in_one_search() {
    let security = security(Some(DOCUMENT));
    let answer = run(
        &mut admin(),
        search_request(CONFIG_DN, SearchRequestScope::WholeSubtree, &["*", "+"]),
        &security,
    );

    assert_eq!(answer.code, ResultCode::Success, "{}", answer.diagnostic);
    assert_eq!(
        dns(&answer),
        vec![
            "cn=config",
            "cn=backends,cn=config",
            "cn=redb,cn=backends,cn=config",
            "cn=indexes,cn=config",
            "cn=attributes,cn=indexes,cn=config",
        ]
    );

    let base = &answer.entries[0];
    assert_eq!(values(base, "restldap-backend"), vec!["redb"]);
    assert_eq!(values(base, "restldap-listen-addr"), vec!["127.0.0.1:1389"]);
    assert_eq!(
        values(base, "restldap-origin"),
        vec!["store:/etc/config.d generation 3"],
        "the answer says which generation is in force"
    );
}

#[test]
fn the_origin_is_operational_and_not_returned_by_a_star_search() {
    // Same rule as `cn=Subschema`: `*` is the entry, `+` is the machinery. An operator who
    // wants to know which generation runs asks for it, and does not get it mixed into a dump.
    let security = security(Some(DOCUMENT));
    let answer = run(
        &mut admin(),
        search_request(CONFIG_DN, SearchRequestScope::BaseObject, &["*"]),
        &security,
    );

    assert_eq!(answer.code, ResultCode::Success, "{}", answer.diagnostic);
    assert_eq!(answer.entries.len(), 1);
    assert!(
        values(&answer.entries[0], "restldap-origin").is_empty(),
        "operational attributes need `+`: {:?}",
        answer.entries[0].1
    );
    assert_eq!(values(&answer.entries[0], "restldap-backend"), vec!["redb"]);
}

#[test]
fn nobody_without_the_admin_flag_reads_it() {
    // The document carries every token in the file. An anonymous client and a bound user get
    // the same refusal, and it names the reason instead of pretending the subtree is absent.
    for session in [Session::new(), user()] {
        let security = security(Some(DOCUMENT));
        let answer = run(
            &mut { session },
            search_request(CONFIG_DN, SearchRequestScope::WholeSubtree, &["*"]),
            &security,
        );

        assert_eq!(answer.code, ResultCode::InsufficientAccessRights);
        assert!(
            answer.diagnostic.contains("only an administrator"),
            "{}",
            answer.diagnostic
        );
        assert!(answer.entries.is_empty(), "no entry may leak");
    }
}

#[test]
fn the_sections_are_one_level_below_the_base() {
    let security = security(Some(DOCUMENT));
    let answer = run(
        &mut admin(),
        search_request(CONFIG_DN, SearchRequestScope::SingleLevel, &["*"]),
        &security,
    );

    assert_eq!(answer.code, ResultCode::Success, "{}", answer.diagnostic);
    assert_eq!(
        dns(&answer),
        vec!["cn=backends,cn=config", "cn=indexes,cn=config"]
    );

    let base = run(
        &mut admin(),
        search_request(CONFIG_DN, SearchRequestScope::BaseObject, &["*", "+"]),
        &security,
    );
    assert_eq!(dns(&base), vec!["cn=config"], "base scope answers the base");
}

#[test]
fn a_filter_narrows_the_subtree_like_any_other() {
    let security = security(Some(DOCUMENT));
    let mut request = search_request(CONFIG_DN, SearchRequestScope::WholeSubtree, &["*"]);
    request.filter = Filter::EqualityMatch(AttributeValueAssertion::new(
        AttributeDescription::from("restldap-backend"),
        OctetString::from(b"redb".to_vec()),
    ));

    let answer = run(&mut admin(), request, &security);

    assert_eq!(answer.code, ResultCode::Success, "{}", answer.diagnostic);
    assert_eq!(
        dns(&answer),
        vec!["cn=config"],
        "only the entry that carries the setting matches"
    );
}

#[test]
fn a_section_can_be_read_on_its_own() {
    let security = security(Some(DOCUMENT));
    let answer = run(
        &mut admin(),
        search_request(
            "cn=redb,cn=backends,cn=config",
            SearchRequestScope::BaseObject,
            &["restldap-path"],
        ),
        &security,
    );

    assert_eq!(answer.code, ResultCode::Success, "{}", answer.diagnostic);
    assert_eq!(dns(&answer), vec!["cn=redb,cn=backends,cn=config"]);
    assert_eq!(
        answer.entries[0].1.len(),
        1,
        "the selection was one attribute: {:?}",
        answer.entries[0].1
    );
    assert_eq!(
        values(&answer.entries[0], "restldap-path"),
        vec!["./directory.redb"]
    );
}

#[test]
fn a_name_under_the_subtree_that_does_not_exist_is_no_such_object() {
    let security = security(Some(DOCUMENT));
    let answer = run(
        &mut admin(),
        search_request(
            "cn=nothing,cn=config",
            SearchRequestScope::BaseObject,
            &["*"],
        ),
        &security,
    );

    assert_eq!(answer.code, ResultCode::NoSuchObject);
    assert!(answer.diagnostic.contains("cn=nothing,cn=config"));
}

#[test]
fn a_server_started_from_flags_alone_says_it_has_no_document() {
    let security = security(None);
    let answer = run(
        &mut admin(),
        search_request(CONFIG_DN, SearchRequestScope::WholeSubtree, &["*", "+"]),
        &security,
    );

    assert_eq!(answer.code, ResultCode::Success, "{}", answer.diagnostic);
    assert_eq!(dns(&answer), vec!["cn=config"]);
    assert_eq!(values(&answer.entries[0], "restldap-origin"), vec!["none"]);
}

#[test]
fn a_write_to_the_subtree_is_refused_with_a_reason() {
    // Otherwise the request reaches the directory, finds nothing and answers `noSuchObject`,
    // which reads as "your DN is wrong" - and an operator then hunts for a typo that is not
    // there.
    let security = security(Some(DOCUMENT));
    let directory = directory();
    let mut session = admin();

    let modify = ModifyRequest {
        object: LdapDn::from("cn=config"),
        changes: vec![ModifyRequestChanges {
            operation: ChangeOperation::Replace,
            modification: PartialAttribute::new(
                AttributeDescription::from("restldap-backend"),
                rasn::types::SetOf::from_vec(vec![OctetString::from(b"file".to_vec())]),
            ),
        }],
    };

    let action = handle(
        &mut session,
        &directory,
        &security,
        LdapMessage::new(3, ProtocolOp::ModifyRequest(modify)),
    );

    let messages = match action {
        Action::Reply(messages) => messages,
        other => panic!("unexpected action: {other:?}"),
    };

    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::ModifyResponse(response) => {
            assert_eq!(response.0.result_code, ResultCode::UnwillingToPerform);
            assert!(
                response
                    .0
                    .diagnostic_message
                    .0
                    .contains("cn=config is read-only"),
                "{}",
                response.0.diagnostic_message.0
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn a_delete_of_a_section_is_refused_before_anything_is_looked_up() {
    let security = security(Some(DOCUMENT));
    let directory = directory();
    let mut session = admin();

    let action = handle(
        &mut session,
        &directory,
        &security,
        LdapMessage::new(
            4,
            ProtocolOp::DelRequest(rasn_ldap::DelRequest(LdapDn::from("cn=backends,cn=config"))),
        ),
    );

    let messages = match action {
        Action::Reply(messages) => messages,
        other => panic!("unexpected action: {other:?}"),
    };

    match &messages[0].protocol_op {
        ProtocolOp::DelResponse(response) => {
            assert_eq!(response.0.result_code, ResultCode::UnwillingToPerform);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn an_ordinary_search_of_the_naming_context_is_untouched() {
    // The subtree lives beside the directory, not in it: a subtree search of the base DN must
    // not pick up configuration entries and must not start requiring the admin flag.
    let security = security(Some(DOCUMENT));
    let answer = run(
        &mut Session::new(),
        search_request(BASE, SearchRequestScope::WholeSubtree, &["*"]),
        &security,
    );

    assert_ne!(
        answer.code,
        ResultCode::InsufficientAccessRights,
        "the configuration check must not gate the directory"
    );
    assert!(
        !dns(&answer).iter().any(|dn| dn.contains("cn=config")),
        "{:?}",
        dns(&answer)
    );
}
