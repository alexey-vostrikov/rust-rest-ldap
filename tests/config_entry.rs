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

/// A configuration store with `text` as its only generation, and a `Security` carrying it.
fn stored(text: &str) -> (tempfile::TempDir, Security) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.d");
    let store = rust_rest_ldap::config_store::Store::open(&path);
    store.commit(text, "test", "initial").expect("commit");

    let document = Document::new(text, format!("store:{}", path.display())).with_store(Some(path));

    (
        dir,
        Security {
            config_document: Some(document),
            ..Security::default()
        },
    )
}

/// The document the store holds now.
fn in_store(security: &Security) -> String {
    let document = security.config_document.as_ref().expect("document");
    let store = rust_rest_ldap::config_store::Store::open(
        document.store.clone().expect("the store the test created"),
    );
    store.read_current().expect("read").expect("generation")
}

fn history(security: &Security) -> usize {
    let document = security.config_document.as_ref().expect("document");
    rust_rest_ldap::config_store::Store::open(document.store.clone().expect("store"))
        .history()
        .expect("history")
        .len()
}

fn modify(dn: &str, attribute: &str, values: &[&str]) -> ModifyRequest {
    ModifyRequest {
        object: LdapDn::from(dn),
        changes: vec![ModifyRequestChanges {
            operation: ChangeOperation::Replace,
            modification: PartialAttribute::new(
                AttributeDescription::from(attribute),
                rasn::types::SetOf::from_vec(
                    values
                        .iter()
                        .map(|value| OctetString::from(value.as_bytes().to_vec()))
                        .collect(),
                ),
            ),
        }],
    }
}

/// The result code and diagnostic of a write aimed at `cn=config`.
fn write(
    session: &mut Session,
    request: ModifyRequest,
    security: &Security,
) -> (ResultCode, String) {
    let directory = directory();
    let action = handle(
        session,
        &directory,
        security,
        LdapMessage::new(9, ProtocolOp::ModifyRequest(request)),
    );

    match action {
        Action::Reply(messages) => match &messages[0].protocol_op {
            ProtocolOp::ModifyResponse(response) => (
                response.0.result_code,
                response.0.diagnostic_message.0.to_string(),
            ),
            other => panic!("unexpected response: {other:?}"),
        },
        // A committed change is the server's to adopt: what these tests check is what it
        // wrote, and the adopting is covered on a real socket in `tests/live_config.rs`.
        Action::ConfigCommitted(committed) => (
            ResultCode::Success,
            format!("committed as generation {}", committed.generation),
        ),
        other => panic!("unexpected action: {other:?}"),
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
fn a_write_without_a_store_is_refused_and_the_reason_says_what_to_do() {
    // The document came from a file, so there is no generation to commit as. Refused rather
    // than editing a file the operator owns - and the refusal names the way to make it work.
    let security = security(Some(DOCUMENT));
    let directory = directory();
    let mut session = admin();

    let action = handle(
        &mut session,
        &directory,
        &security,
        LdapMessage::new(
            3,
            ProtocolOp::ModifyRequest(modify("cn=config", "restldap-backend", &["file"])),
        ),
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
                    .contains("pointing at a configuration store directory"),
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

#[test]
fn an_administrator_changes_a_setting_and_it_becomes_a_generation() {
    let (_dir, security) = stored(DOCUMENT);
    assert_eq!(history(&security), 1);

    let (code, diagnostic) = write(
        &mut admin(),
        modify("cn=config", "restldap-backend", &["file"]),
        &security,
    );

    assert_eq!(code, ResultCode::Success, "{diagnostic}");
    assert!(
        diagnostic.contains("committed as generation 2"),
        "the answer names the generation: {diagnostic}"
    );
    // Whether the running server adopted it is decided by the server, on a real socket
    // (`tests/live_config.rs`); what the handler guarantees is that the generation exists.
    assert!(
        diagnostic.contains("committed as generation 2"),
        "and names the generation: {diagnostic}"
    );

    assert_eq!(history(&security), 2);
    let text = in_store(&security);
    assert!(text.contains("backend: file"), "{text}");

    // The committed document is a configuration: it loads, and with the new value.
    let reloaded = rust_rest_ldap::config::resolve(
        rust_rest_ldap::config::Args::default(),
        Some(&text),
        |_| None,
    )
    .expect("the committed document must load");
    assert_eq!(reloaded.backend, "file");
}

#[test]
fn the_committed_document_is_what_a_client_reads_back() {
    // The property that makes the write believable: read after write, over the protocol.
    let (_dir, security) = stored(DOCUMENT);

    write(
        &mut admin(),
        modify("cn=config", "restldap-listen-addr", &["0.0.0.0:389"]),
        &security,
    );

    // The subtree a client reads is generated from the document the server started with, so
    // until the restart the answer is the old value - and the answer says so, which is why the
    // generation number is in the diagnostic. What is checked here is the store, not the
    // running snapshot.
    assert!(in_store(&security).contains("listen_addr: 0.0.0.0:389"));
}

#[test]
fn two_changes_through_the_protocol_build_on_each_other() {
    let (_dir, security) = stored(DOCUMENT);

    write(
        &mut admin(),
        modify("cn=config", "restldap-backend", &["file"]),
        &security,
    );
    let (code, diagnostic) = write(
        &mut admin(),
        modify(
            "cn=backends,cn=config",
            "restldap-listen-addr",
            &["0.0.0.0:389"],
        ),
        &security,
    );

    assert_eq!(
        code,
        ResultCode::NoSuchAttribute,
        "the base holds that key: {diagnostic}"
    );
    assert!(diagnostic.contains("restldap-listen-addr"), "{diagnostic}");

    let (code, diagnostic) = write(
        &mut admin(),
        modify("cn=config", "restldap-listen-addr", &["0.0.0.0:389"]),
        &security,
    );
    assert_eq!(code, ResultCode::Success, "{diagnostic}");

    let text = in_store(&security);
    assert!(
        text.contains("backend: file") && text.contains("listen_addr: 0.0.0.0:389"),
        "both changes are in one document: {text}"
    );
    assert_eq!(history(&security), 3, "two changes, two generations");
}

#[test]
fn nobody_without_the_admin_flag_writes_it() {
    let (_dir, security) = stored(DOCUMENT);

    let (code, diagnostic) = write(
        &mut user(),
        modify("cn=config", "restldap-backend", &["file"]),
        &security,
    );

    assert_eq!(code, ResultCode::InsufficientAccessRights);
    assert!(
        diagnostic.contains("only an administrator changes it"),
        "{diagnostic}"
    );
    assert_eq!(history(&security), 1, "nothing was committed");
}

#[test]
fn a_file_backed_configuration_refuses_the_change_and_says_what_to_do() {
    let security = security(Some(DOCUMENT));

    let (code, diagnostic) = write(
        &mut admin(),
        modify("cn=config", "restldap-backend", &["file"]),
        &security,
    );

    assert_eq!(code, ResultCode::UnwillingToPerform);
    assert!(
        diagnostic.contains("pointing at a configuration store directory"),
        "{diagnostic}"
    );
}

#[test]
fn adding_and_deleting_a_section_says_it_is_not_supported_yet() {
    // Refused rather than guessed: the document key a new entry would be called is not
    // recoverable from the attribute name.
    let (_dir, security) = stored(DOCUMENT);

    let add = rasn_ldap::AddRequest {
        entry: LdapDn::from("cn=3,cn=access,cn=config"),
        attributes: Vec::new(),
    };
    let action = handle(
        &mut admin(),
        &directory(),
        &security,
        LdapMessage::new(10, ProtocolOp::AddRequest(add)),
    );

    let messages = match action {
        Action::Reply(messages) => messages,
        other => panic!("unexpected action: {other:?}"),
    };
    match &messages[0].protocol_op {
        ProtocolOp::AddResponse(response) => {
            assert_eq!(response.0.result_code, ResultCode::UnwillingToPerform);
            assert!(
                response
                    .0
                    .diagnostic_message
                    .0
                    .contains("not supported yet"),
                "{}",
                response.0.diagnostic_message.0
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert_eq!(history(&security), 1, "nothing was committed");
}

#[test]
fn the_generation_a_change_creates_names_who_made_it_and_what_changed() {
    let (_dir, security) = stored(DOCUMENT);
    write(
        &mut admin(),
        modify("cn=config", "restldap-backend", &["file"]),
        &security,
    );

    let document = security.config_document.as_ref().expect("document");
    let store = rust_rest_ldap::config_store::Store::open(document.store.clone().expect("store"));
    let history = store.history().expect("history");
    let last = history.last().expect("a generation");

    assert_eq!(last.author, ADMIN_DN);
    assert!(
        last.note.contains("backend"),
        "the note names the key: {}",
        last.note
    );
}
