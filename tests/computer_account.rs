//! A computer account created the way a joining Samba member creates one.
//!
//! `net ads join` ends with an LDAP `add` of the machine's account, and every attribute in that add
//! comes from the member: `dNSHostName`, four `servicePrincipalName` values,
//! `userAccountControl = 4128` (`WORKSTATION_TRUST_ACCOUNT` and `PASSWD_NOTREQD`), and the machine
//! password. A directory whose schema does not know these names refuses the whole add, and the
//! member reports a schema error where the truth is a missing attribute type.
//!
//! The test drives the path a client drives - the dispatcher, the schema check, the store - and the
//! schema it hands the dispatcher is the AD extension over the core, which is the schema an AD
//! domain runs with.

use std::sync::Arc;

use rasn::types::{OctetString, SetOf};
use rasn_ldap::{
    AddRequest, AttributeDescription, LdapDn, LdapMessage, ProtocolOp, ResultCode, SearchRequest,
    SearchRequestDerefAliases, SearchRequestScope,
};
use rrl_directory::backend::{Backend, EntryChange};
use rrl_directory::config::{Args, Config};
use rrl_directory::ldap::session::{Identity, Session};
use rrl_directory::ldap::{Action, handle};
use rrl_directory::model::{Attribute, Attributes, Entry};
use rrl_directory::reload::Source;
use rrl_directory::security::{Security, shared_schema};

const BASE: &str = "dc=ad,dc=example,dc=com";
const ADMIN_DN: &str = "cn=administrator,cn=users,dc=ad,dc=example,dc=com";
const MACHINE_DN: &str = "cn=samba,cn=computers,dc=ad,dc=example,dc=com";

/// A configuration that stands in for a domain controller: a keytab is what makes the server
/// publish the AD vocabulary, and without one it deliberately publishes none - a server that
/// cannot accept a ticket must not invite a client to rely on AD flags it does not maintain.
///
/// The keytab is not read while the configuration is resolved, so a real one is not needed here.
fn config(path: &std::path::Path, keytab: &std::path::Path) -> Config {
    let text = format!(
        "\
base_dn: {BASE}
backends:
  redb:
    path: {}
sasl:
  keytab: {}
  realms:
    - name: AD.EXAMPLE.COM
      dn: cn={{user}},cn=users,{BASE}
",
        path.display(),
        keytab.display(),
        BASE = BASE
    );
    rrl_directory::config::resolve(Args::default(), Some(&text), |_| None).expect("config")
}

async fn source(path: &std::path::Path, keytab: &std::path::Path) -> (Arc<Source>, Backend) {
    let config = config(path, keytab);
    let backend = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("backend");
    backend
        .apply(&[
            // The container the member's account is created in. An `add` needs its parent to exist,
            // and in a domain that container is there before any member arrives - `CN=Computers` is
            // created with the domain. An `organizationalRole` is the core-schema class whose only
            // requirement is a `cn`, which is what this one is: a place for other entries.
            EntryChange::Upsert {
                entry: Entry::new(
                    "cn=computers,dc=ad,dc=example,dc=com",
                    Attributes::new()
                        .push(Attribute::new(
                            "objectClass",
                            vec!["top".to_string(), "organizationalRole".to_string()],
                        ))
                        .push(Attribute::single("cn", "computers")),
                ),
            },
            EntryChange::Upsert {
                entry: Entry::new(
                    ADMIN_DN,
                    // A core-schema entry: the source loads with `Schema::core()` before any extension
                    // is named in the configuration, and an `inetOrgPerson` is enough for an identity
                    // the test binds as. Whether the administrator is an AD `user` is not what this
                    // test is about.
                    Attributes::new()
                        .push(Attribute::new(
                            "objectClass",
                            vec![
                                "top".to_string(),
                                "person".to_string(),
                                "organizationalPerson".to_string(),
                                "inetOrgPerson".to_string(),
                            ],
                        ))
                        .push(Attribute::single("cn", "administrator"))
                        .push(Attribute::single("sn", "Administrator")),
                ),
            },
        ])
        .await
        .expect("seed");

    let (source, _) = Source::load(&config, backend.clone()).await.expect("load");
    (source, backend)
}

/// The security bundle the dispatcher checks against: the schema the source was loaded with, not a
/// core one built here. A test that supplies its own schema proves what the test set up, and this
/// one has to prove what a configured server does.
fn security(source: &Arc<Source>, backend: &Backend) -> Security {
    Security {
        schema: shared_schema((*source.schema()).clone()),
        // A domain controller issues a SID to every principal it creates, and a computer is one.
        // Without an issuer the write path is an ordinary directory's and issues nothing - which is
        // what `objectSid is missing` meant here before this line existed.
        domain: Some(std::sync::Arc::new(
            rrl_directory::sid::domain::Issuer::open(backend, [7u8; 16]).expect("an issuer"),
        )),
        ..Security::default()
    }
}

fn admin() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(ADMIN_DN, true));
    session
}

fn attribute(name: &str, values: &[&str]) -> rasn_ldap::Attribute {
    rasn_ldap::Attribute::new(
        AttributeDescription::from(name),
        SetOf::from_vec(
            values
                .iter()
                .map(|value| OctetString::from(value.as_bytes()))
                .collect(),
        ),
    )
}

/// The account a member asks for, attribute for attribute as `net ads join` sends it.
///
/// The four SPNs are not decoration: the member logs on to its own name over SMB, asks for
/// `cifs/<name>`, and the KDC resolves each of them against this list.
fn add_computer() -> LdapMessage {
    LdapMessage::new(
        1,
        ProtocolOp::AddRequest(AddRequest {
            entry: LdapDn::from(MACHINE_DN),
            attributes: vec![
                attribute(
                    "objectClass",
                    &["top", "person", "organizationalPerson", "user", "computer"],
                ),
                attribute("cn", &["samba"]),
                attribute("sn", &["samba"]),
                attribute("sAMAccountName", &["samba$"]),
                attribute("dNSHostName", &["samba.ad.example.com"]),
                attribute(
                    "servicePrincipalName",
                    &[
                        "HOST/samba",
                        "HOST/samba.ad.example.com",
                        "RestrictedKrbHost/samba",
                        "RestrictedKrbHost/samba.ad.example.com",
                    ],
                ),
                attribute("userAccountControl", &["4128"]),
                attribute("msDS-SupportedEncryptionTypes", &["24"]),
            ],
        }),
    )
}

fn response_code(message: &rasn_ldap::LdapMessage) -> ResultCode {
    match &message.protocol_op {
        ProtocolOp::AddResponse(body) => body.0.result_code,
        ProtocolOp::SearchResDone(body) => body.0.result_code,
        other => panic!("unexpected response: {other:?}"),
    }
}

/// Runs one request through the dispatcher and persists what it asks to persist.
async fn run(source: &Arc<Source>, backend: &Backend, message: LdapMessage) -> ResultCode {
    let directory = source.directory().await;
    match handle(
        &mut admin(),
        &directory,
        &security(source, backend),
        message,
    ) {
        Action::Reply(messages) => messages.last().map(response_code).expect("a response"),
        Action::Persist(action) => {
            source.apply(&action.changes).await.expect("persist");
            response_code(&action.success)
        }
        other => panic!("unexpected action: {other:?}"),
    }
}

async fn read_back(source: &Arc<Source>, backend: &Backend) -> Vec<(String, Vec<String>)> {
    let directory = source.directory().await;
    let request = SearchRequest::new(
        LdapDn::from(MACHINE_DN),
        SearchRequestScope::BaseObject,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        rasn_ldap::Filter::Present(AttributeDescription::from("objectClass")),
        vec![rasn_ldap::LdapString::from("*")],
    );
    let messages = match handle(
        &mut admin(),
        &directory,
        &security(source, backend),
        LdapMessage::new(2, ProtocolOp::SearchRequest(request)),
    ) {
        Action::Reply(messages) => messages,
        other => panic!("a search is not a write: {other:?}"),
    };

    for message in &messages {
        if let ProtocolOp::SearchResEntry(entry) = &message.protocol_op {
            return entry
                .attributes
                .iter()
                .map(|attribute| {
                    (
                        attribute.r#type.0.to_string(),
                        attribute
                            .vals
                            .iter()
                            .map(|value| String::from_utf8_lossy(value.as_ref()).to_string())
                            .collect(),
                    )
                })
                .collect();
        }
    }
    panic!("the computer account is not in the directory after a successful add");
}

#[tokio::test]
async fn a_member_can_add_its_computer_account() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("directory.redb");
    let keytab = dir.path().join("service.keytab");
    std::fs::write(&keytab, b"").expect("an empty keytab stands in for the file");
    let (source, backend) = source(&path, &keytab).await;

    let code = run(&source, &backend, add_computer()).await;
    assert_eq!(
        code,
        ResultCode::Success,
        "the member's add was refused by the schema"
    );

    let attributes = read_back(&source, &backend).await;
    let value = |name: &str| {
        attributes
            .iter()
            .find(|(attribute, _)| attribute.eq_ignore_ascii_case(name))
            .map(|(_, values)| values.clone())
            .unwrap_or_else(|| panic!("{name} is missing from the entry the member wrote"))
    };

    assert_eq!(value("dNSHostName"), vec!["samba.ad.example.com"]);
    assert_eq!(value("sAMAccountName"), vec!["samba$"]);
    assert_eq!(value("userAccountControl"), vec!["4128"]);
    assert_eq!(
        value("servicePrincipalName").len(),
        4,
        "all four SPNs have to survive, not just the first"
    );
    // A `computer` is a security principal: the SID is issued by the write path, not by the member,
    // and every ticket that names the machine depends on it.
    assert!(
        !value("objectSid").is_empty(),
        "a computer account without a SID cannot be named by a ticket"
    );
}
