//! An attribute the ported server never knew about, end to end.
//!
//! The point of generalizing the entry model (E1) is that new data does not need new
//! code: an entry carrying `telephoneNumber`, `employeeNumber` or anything else must
//! be stored, filtered, projected and returned like the built-in attributes. This
//! test goes through the real dispatcher, not through the model, so it proves the
//! whole path and not just the adapter.

use std::sync::Arc;

use rasn_ldap::{
    AttributeDescription, AttributeValueAssertion, AuthenticationChoice, BindRequest, Filter,
    LdapDn, LdapMessage, ProtocolOp, ResultCode, SearchRequest, SearchRequestDerefAliases,
    SearchRequestScope,
};
use rrl_directory::directory::Directory;
use rrl_directory::ldap::session::Session;
use rrl_directory::ldap::{Action, handle};
use rrl_directory::mapping::direct;
use rrl_directory::model::Attribute;
use rrl_directory::security::Security;

const BASE: &str = "dc=example,dc=com";

fn directory() -> Arc<Directory> {
    let text = r#"[
        {
            "dn": "cn=admin,ou=users,dc=example,dc=com",
            "attributes": {
                "objectClass": ["top", "inetOrgPerson"],
                "cn": "admin",
                "uid": "admin",
                "ldapAdmin": "true",
                "userPassword": "{SSHA}rapW2TNEFWp6HxD/nfwsjcBCD8Pi3Bvj",
                "telephoneNumber": "+7 495 000-00-00",
                "employeeNumber": 42,
                "department": "Operations"
            }
        },
        {
            "dn": "cn=guest,ou=users,dc=example,dc=com",
            "attributes": {
                "objectClass": ["top", "inetOrgPerson"],
                "cn": "guest",
                "telephoneNumber": "+7 495 111-11-11",
                "department": "Support"
            }
        }
    ]"#;

    let entries = direct::entries(text).expect("direct entries");
    Arc::new(Directory::from_entries(BASE, "users", "groups", entries))
}

fn security() -> Arc<Security> {
    // `{SSHA}` is what the fixture uses, so the strict default has to be relaxed for
    // this one scheme — which is exactly the per-scheme policy of the previous step.
    let config = rrl_directory::password::policy::PasswordConfig {
        allow_weak_hashes: Some(rrl_directory::password::policy::WEAK_ACKNOWLEDGEMENT.to_string()),
        allowed_weak_hashes: Some("ssha".to_string()),
        upgrade_on_bind: None,
        allow_weak: Vec::new(),
        store_scheme: None,
    };
    Arc::new(Security {
        passwords: rrl_directory::password::PasswordPolicy::from_config(Some(&config))
            .expect("policy"),
        // The fixture binds over a duplex stream, not TLS.
        allow_unencrypted_bind: true,
        ..Security::default()
    })
}

fn bind(message_id: u32) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::BindRequest(BindRequest::new(
            3,
            LdapDn::from("cn=admin,ou=users,dc=example,dc=com"),
            AuthenticationChoice::Simple(rasn::types::OctetString::from_static(b"admin")),
        )),
    )
}

fn search(message_id: u32, filter: Filter, attributes: &[&str]) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::SearchRequest(SearchRequest::new(
            LdapDn::from(BASE),
            SearchRequestScope::WholeSubtree,
            SearchRequestDerefAliases::NeverDerefAliases,
            0,
            0,
            false,
            filter,
            attributes
                .iter()
                .map(|name| rasn_ldap::LdapString::from(*name))
                .collect(),
        )),
    )
}

fn equality(name: &str, value: &str) -> Filter {
    Filter::EqualityMatch(AttributeValueAssertion::new(
        AttributeDescription::from(name),
        rasn::types::OctetString::from(value.as_bytes()),
    ))
}

fn messages(action: Action) -> Vec<LdapMessage> {
    match action {
        Action::Reply(messages) => messages,
        // A bind against a `{SSHA}` entry answers and then rewrites the hash; the
        // answer is what this test is after.
        Action::PersistAfterReply { messages, .. } => messages,
        other => panic!("unexpected action: {other:?}"),
    }
}

fn result_code(message: &LdapMessage) -> ResultCode {
    match &message.protocol_op {
        ProtocolOp::SearchResDone(done) => done.0.result_code,
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn a_filter_on_an_unknown_attribute_finds_the_entry() {
    let mut session = Session::new();
    let directory = directory();
    let security = security();
    let bound = handle(&mut session, &directory, &security, bind(1));
    assert_eq!(messages(bound).len(), 1);

    let action = handle(
        &mut session,
        &directory,
        &security,
        search(2, equality("telephoneNumber", "+7 495 111-11-11"), &["cn"]),
    );
    let messages = messages(action);

    let entries: Vec<&LdapMessage> = messages
        .iter()
        .filter(|message| matches!(message.protocol_op, ProtocolOp::SearchResEntry(_)))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "the phone number must select exactly one entry"
    );
    match &entries[0].protocol_op {
        ProtocolOp::SearchResEntry(entry) => {
            assert_eq!(entry.object_name.0, "cn=guest,ou=users,dc=example,dc=com");
            assert_eq!(entry.attributes.len(), 1, "only the requested attribute");
            assert_eq!(entry.attributes[0].r#type.0, "cn");
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert_eq!(
        result_code(messages.last().expect("done")),
        ResultCode::Success
    );
}

#[test]
fn the_unknown_attribute_is_projected_and_keeps_its_value() {
    let mut session = Session::new();
    let directory = directory();
    let security = security();
    let _ = handle(&mut session, &directory, &security, bind(1));

    let action = handle(
        &mut session,
        &directory,
        &security,
        search(
            2,
            equality("employeeNumber", "42"),
            &["telephoneNumber", "department"],
        ),
    );
    let messages = messages(action);
    let entry = messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => Some(entry),
            _ => None,
        })
        .expect("one entry");

    assert_eq!(entry.object_name.0, "cn=admin,ou=users,dc=example,dc=com");
    let rendered: Vec<(String, Vec<u8>)> = entry
        .attributes
        .iter()
        .map(|attribute| {
            (
                attribute.r#type.0.clone(),
                attribute
                    .vals
                    .iter()
                    .next()
                    .expect("value")
                    .as_ref()
                    .to_vec(),
            )
        })
        .collect();
    assert_eq!(
        rendered,
        vec![
            ("telephoneNumber".to_string(), b"+7 495 000-00-00".to_vec()),
            ("department".to_string(), b"Operations".to_vec()),
        ]
    );
}

#[test]
fn the_admin_flag_of_a_direct_entry_is_internal_and_grants_admin() {
    let text = r#"[
        {
            "dn": "cn=ops,ou=users,dc=example,dc=com",
            "attributes": {"objectClass": ["top"], "cn": "ops", "ldapAdmin": "true"}
        }
    ]"#;
    let entries = direct::entries(text).expect("entries");
    let directory = Directory::from_entries(BASE, "users", "groups", entries);
    let entry = directory
        .find("cn=ops,ou=users,dc=example,dc=com")
        .expect("entry");

    let visible = entry
        .attributes()
        .select(entry.dn(), &["*".to_string()])
        .into_iter()
        .map(|attribute| attribute.name.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        visible,
        vec!["cn".to_string(), "objectClass".to_string()],
        "the admin flag must not be projected, whichever adapter produced the entry"
    );
    assert!(
        entry.is_admin(),
        "the adapter marks ldapAdmin internal, so the entry carries admin rights"
    );
}

#[test]
fn model_attribute_builder_is_public_for_other_crates() {
    // The integration test crate builds entries itself; the constructors it needs
    // must stay public.
    let attribute = Attribute::single("cn", "x").case_sensitive();
    assert_eq!(&*attribute.name, "cn");
    assert!(attribute.flags.case_sensitive);
}
