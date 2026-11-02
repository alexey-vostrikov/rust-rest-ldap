//! `whoami` and Password Modify over the dispatcher, and through a real store.
//!
//! What a client cares about: after a successful password change, the new password binds
//! and the old one does not. That is checked here against a real redb file, because a
//! change that only reaches memory would pass every in-process assertion and still be
//! useless.

use rasn_ldap::{ExtendedRequest, LdapDn, LdapMessage, LdapOid, ProtocolOp, ResultCode};
use rust_rest_ldap::backend::{Backend, EntryChange};
use rust_rest_ldap::config::{Args, Config};
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::ldap::extop::{PASSWORD_MODIFY_OID, WHOAMI_OID};
use rust_rest_ldap::ldap::session::{Identity, Session};
use rust_rest_ldap::ldap::{Action, handle};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::password::StoreScheme;
use rust_rest_ldap::password::store::hash as hash_password;
use rust_rest_ldap::reload::Source;
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";

const SECRET: &str = "old password";

fn alice(hash: &str) -> Entry {
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
            .push(Attribute::single("sn", "S"))
            .push(Attribute::single("uid", "alice"))
            .push(
                Attribute::new("userPassword", vec![hash.to_string()])
                    .case_sensitive()
                    .sensitive(),
            ),
    )
}

fn admin() -> Entry {
    alice(&hash_password("admin", StoreScheme::Argon2id).expect("hash"))
}

fn directory() -> Directory {
    let mut admin_entry = admin();
    admin_entry = Entry::new(
        ADMIN_DN,
        admin_entry
            .attributes()
            .clone()
            .replace(Attribute::new("ldapAdmin", vec!["true".to_string()]).internal()),
    );

    Directory::from_entries(
        BASE,
        "users",
        "groups",
        vec![
            admin_entry,
            alice(&hash_password(SECRET, StoreScheme::Argon2id).expect("hash")),
        ],
    )
}

fn security() -> Security {
    Security {
        allow_unencrypted_bind: true,
        ..Security::default()
    }
}

fn session(dn: &str, admin: bool) -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(dn, admin));
    session
}

fn extended(message_id: u32, oid: &str, value: Option<Vec<u8>>) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::ExtendedReq(ExtendedRequest {
            request_name: LdapOid::from(oid.as_bytes()),
            request_value: value.map(|bytes| bytes.into()),
        }),
    )
}

/// Builds a Password Modify request value.
fn request_value(user: Option<&str>, old: Option<&str>, new: Option<&str>) -> Vec<u8> {
    let mut inner = Vec::new();
    let mut push = |tag: u8, text: &str| {
        inner.push(tag);
        let bytes = text.as_bytes();
        if bytes.len() < 0x80 {
            inner.push(bytes.len() as u8);
        } else {
            inner.push(0x81);
            inner.push(bytes.len() as u8);
        }
        inner.extend_from_slice(bytes);
    };

    if let Some(user) = user {
        push(0x80, user);
    }
    if let Some(old) = old {
        push(0x81, old);
    }
    if let Some(new) = new {
        push(0x82, new);
    }
    drop(push);

    let mut out = vec![0x30];
    if inner.len() < 0x80 {
        out.push(inner.len() as u8);
    } else {
        out.push(0x81);
        out.push(inner.len() as u8);
    }
    out.extend_from_slice(&inner);
    out
}

fn code(message: &LdapMessage) -> ResultCode {
    match &message.protocol_op {
        ProtocolOp::ExtendedResp(response) => response.result_code,
        other => panic!("not an extended response: {other:?}"),
    }
}

fn value_of(message: &LdapMessage) -> Option<Vec<u8>> {
    match &message.protocol_op {
        ProtocolOp::ExtendedResp(response) => response
            .response_value
            .as_ref()
            .map(|value| value.as_ref().to_vec()),
        other => panic!("not an extended response: {other:?}"),
    }
}

/// Runs a request through the dispatcher and returns the reply.
fn run(
    session: &mut Session,
    directory: &Directory,
    message: LdapMessage,
) -> (ResultCode, Option<Vec<u8>>) {
    match handle(session, directory, &security(), message) {
        Action::Reply(messages) => {
            let last = messages.last().expect("a response");
            (code(last), value_of(last))
        }
        Action::Persist(action) => (code(&action.success), value_of(&action.success)),
        other => panic!("unexpected action: {other:?}"),
    }
}

#[test]
fn whoami_answers_the_bound_identity() {
    let (code, value) = run(
        &mut session(ALICE_DN, false),
        &directory(),
        extended(1, WHOAMI_OID, None),
    );

    assert_eq!(code, ResultCode::Success);
    assert_eq!(
        String::from_utf8(value.expect("a value")).expect("utf8"),
        format!("dn:{ALICE_DN}")
    );
}

#[test]
fn whoami_answers_empty_for_anonymous() {
    // RFC 4532: an empty value, not an error. A client uses this to check whether it is
    // bound at all.
    let (code, value) = run(
        &mut Session::new(),
        &directory(),
        extended(1, WHOAMI_OID, None),
    );

    assert_eq!(code, ResultCode::Success);
    assert_eq!(value.as_deref(), Some(b"".as_slice()));
}

#[test]
fn an_unknown_extended_operation_is_refused() {
    let (code, _) = run(
        &mut session(ADMIN_DN, true),
        &directory(),
        extended(1, "1.3.6.1.4.1.99999.1", None),
    );

    assert_eq!(code, ResultCode::UnwillingToPerform);
}

#[test]
fn a_user_changes_their_own_password_with_the_old_one() {
    let value = request_value(None, Some(SECRET), Some("new password"));
    let (code, reply) = run(
        &mut session(ALICE_DN, false),
        &directory(),
        extended(1, PASSWORD_MODIFY_OID, Some(value)),
    );

    assert_eq!(code, ResultCode::Success);
    assert_eq!(
        reply, None,
        "RFC 3062 omits the response value when the server generated nothing"
    );
}

#[test]
fn a_user_changing_their_own_password_must_prove_the_old_one() {
    let value = request_value(None, None, Some("new password"));
    let (code, _) = run(
        &mut session(ALICE_DN, false),
        &directory(),
        extended(1, PASSWORD_MODIFY_OID, Some(value)),
    );

    assert_eq!(code, ResultCode::UnwillingToPerform);
}

#[test]
fn a_wrong_old_password_is_refused() {
    let value = request_value(None, Some("not the old one"), Some("new"));
    let (code, _) = run(
        &mut session(ALICE_DN, false),
        &directory(),
        extended(1, PASSWORD_MODIFY_OID, Some(value)),
    );

    assert_eq!(code, ResultCode::InvalidCredentials);
}

#[test]
fn an_administrator_resets_without_the_old_password() {
    // A forgotten password is exactly the case where nobody knows the old one.
    let value = request_value(Some(ALICE_DN), None, Some("reset by admin"));
    let (code, _) = run(
        &mut session(ADMIN_DN, true),
        &directory(),
        extended(1, PASSWORD_MODIFY_OID, Some(value)),
    );

    assert_eq!(code, ResultCode::Success);
}

#[test]
fn a_user_may_not_change_someone_elses_password() {
    let value = request_value(Some(ADMIN_DN), Some(SECRET), Some("takeover"));
    let (code, _) = run(
        &mut session(ALICE_DN, false),
        &directory(),
        extended(1, PASSWORD_MODIFY_OID, Some(value)),
    );

    assert_eq!(code, ResultCode::InsufficientAccessRights);
}

#[test]
fn an_anonymous_password_change_is_refused() {
    let value = request_value(Some(ALICE_DN), None, Some("x"));
    let (code, _) = run(
        &mut Session::new(),
        &directory(),
        extended(1, PASSWORD_MODIFY_OID, Some(value)),
    );

    assert_eq!(code, ResultCode::UnwillingToPerform);
}

#[test]
fn an_empty_request_gets_a_generated_password() {
    // Empty SEQUENCE: change my own password, no old one supplied. An administrator may,
    // and the answer carries the new password.
    let (code, value) = run(
        &mut session(ADMIN_DN, true),
        &directory(),
        extended(1, PASSWORD_MODIFY_OID, Some(vec![0x30, 0x00])),
    );

    assert_eq!(code, ResultCode::Success);
    let encoded = value.expect("a generated password must come back");
    let text = String::from_utf8_lossy(&encoded[2..]).into_owned();

    assert_eq!(encoded[0], 0x30);
    assert_eq!(
        encoded[2], 0x80,
        "the value is a context-tagged octet string"
    );
    assert!(!text.is_empty(), "the password must not be empty");
}

#[test]
fn a_password_change_needs_an_acceptable_transport() {
    let strict = Security {
        allow_unencrypted_bind: false,
        ..Security::default()
    };
    let value = request_value(None, Some(SECRET), Some("new"));

    let mut session = session(ALICE_DN, false);
    let action = handle(
        &mut session,
        &directory(),
        &strict,
        extended(1, PASSWORD_MODIFY_OID, Some(value)),
    );

    let messages = match action {
        Action::Reply(messages) => messages,
        other => panic!("a refused change must not write: {other:?}"),
    };
    assert_eq!(code(&messages[0]), ResultCode::StrongerAuthRequired);
}

#[test]
fn the_hash_is_written_with_the_configured_scheme() {
    let value = request_value(Some(ALICE_DN), None, Some("scheme check"));
    let messages = match handle(
        &mut session(ADMIN_DN, true),
        &directory(),
        &security(),
        extended(1, PASSWORD_MODIFY_OID, Some(value)),
    ) {
        Action::Persist(action) => action.changes,
        other => panic!("expected a write, got {other:?}"),
    };

    let EntryChange::Upsert { entry } = &messages[0] else {
        panic!("expected an upsert");
    };
    let hash = entry
        .attributes()
        .get("userPassword")
        .expect("userPassword")
        .values[0]
        .clone();

    assert!(
        hash.starts_with("$argon2id$"),
        "a password set through the protocol must be hashed like any other: {hash}"
    );
    assert!(
        entry
            .attributes()
            .get("userPassword")
            .expect("userPassword")
            .flags
            .sensitive,
        "and must stay hidden"
    );
}

// ---------------------------------------------------------------------------
// Through a real store: the new password has to bind, the old one must not.
// ---------------------------------------------------------------------------

fn config(path: &std::path::Path) -> Config {
    let text = format!(
        r#"
base_dn: {BASE}
AllowDangerousSettings: "Yes I know this is bad idea"
backends:
  redb:
    path: {}
bind:
  AllowUnencryptedBind: "Yes I know this is bad idea"
"#,
        path.display()
    );
    rust_rest_ldap::config::resolve(Args::default(), Some(&text), |_| None).expect("config")
}

fn bind_message(dn: &str, secret: &str) -> LdapMessage {
    LdapMessage::new(
        9,
        ProtocolOp::BindRequest(rasn_ldap::BindRequest::new(
            3,
            LdapDn::from(dn),
            rasn_ldap::AuthenticationChoice::Simple(rasn::types::OctetString::from(
                secret.as_bytes(),
            )),
        )),
    )
}

async fn bind_code(directory: &Directory, dn: &str, secret: &str) -> ResultCode {
    let mut session = Session::new();
    match handle(
        &mut session,
        directory,
        &security(),
        bind_message(dn, secret),
    ) {
        Action::Reply(messages) | Action::PersistAfterReply { messages, .. } => {
            match &messages[0].protocol_op {
                ProtocolOp::BindResponse(response) => response.result_code,
                other => panic!("not a bind response: {other:?}"),
            }
        }
        Action::Persist(action) => match &action.success.protocol_op {
            ProtocolOp::BindResponse(response) => response.result_code,
            other => panic!("not a bind response: {other:?}"),
        },
        other => panic!("unexpected action: {other:?}"),
    }
}

#[tokio::test]
async fn the_new_password_binds_and_the_old_one_stops_working() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("d.redb");
    let config = config(&path);

    let backend = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("backend");
    backend
        .apply(&[
            EntryChange::Upsert { entry: admin() },
            EntryChange::Upsert {
                entry: alice(&hash_password(SECRET, StoreScheme::Argon2id).expect("hash")),
            },
        ])
        .await
        .expect("seed");

    let (source, directory) = Source::load(&config, backend).await.expect("load");

    assert_eq!(
        bind_code(&directory, ALICE_DN, SECRET).await,
        ResultCode::Success,
        "the old password works before the change"
    );

    let value = request_value(None, Some(SECRET), Some("brand new password"));
    let changes = match handle(
        &mut session(ALICE_DN, false),
        &directory,
        &security(),
        extended(1, PASSWORD_MODIFY_OID, Some(value)),
    ) {
        Action::Persist(action) => action.changes,
        other => panic!("expected a write, got {other:?}"),
    };
    source.apply(&changes).await.expect("persist");

    let after = source.directory().await;
    assert_eq!(
        bind_code(&after, ALICE_DN, "brand new password").await,
        ResultCode::Success,
        "the new password has to work, or the operation is theatre"
    );
    assert_eq!(
        bind_code(&after, ALICE_DN, SECRET).await,
        ResultCode::InvalidCredentials,
        "and the old one must stop working"
    );
}

#[tokio::test]
async fn the_change_survives_a_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("d.redb");
    let config = config(&path);

    let backend = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("backend");
    backend
        .apply(&[
            EntryChange::Upsert { entry: admin() },
            EntryChange::Upsert {
                entry: alice(&hash_password(SECRET, StoreScheme::Argon2id).expect("hash")),
            },
        ])
        .await
        .expect("seed");

    let (source, directory) = Source::load(&config, backend).await.expect("load");

    let value = request_value(Some(ALICE_DN), None, Some("admin reset"));
    let changes = match handle(
        &mut session(ADMIN_DN, true),
        &directory,
        &security(),
        extended(1, PASSWORD_MODIFY_OID, Some(value)),
    ) {
        Action::Persist(action) => action.changes,
        other => panic!("expected a write, got {other:?}"),
    };
    source.apply(&changes).await.expect("persist");
    drop(source);

    let reopened = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("reopen");
    let (restarted, _) = Source::load(&config, reopened).await.expect("reload");

    let snapshot = restarted.directory().await;
    assert_eq!(
        bind_code(&snapshot, ALICE_DN, "admin reset").await,
        ResultCode::Success,
        "a password set before the restart must survive it"
    );
}
