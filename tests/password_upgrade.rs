//! Password hash upgrade on bind: the one moment the password is known.
//!
//! A directory that has been running for years holds `{SSHA}` hashes. They cannot be
//! converted offline, because a hash cannot be turned back into a password. The bind is
//! the only moment the server sees the password itself, so it is the only moment the
//! upgrade can happen without asking anybody for anything.
//!
//! What must never happen: a failed upgrade breaking a bind that already succeeded, and
//! a hash upgraded for a password that was wrong.

use std::sync::Arc;

use rasn_ldap::{AuthenticationChoice, BindRequest, LdapDn, LdapMessage, ProtocolOp, ResultCode};
use rust_rest_ldap::backend::{Backend, EntryChange};
use rust_rest_ldap::config::{Args, Config};
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::ldap::bind;
use rust_rest_ldap::ldap::session::Session;
use rust_rest_ldap::ldap::{Action, handle};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::password::store::hash as hash_password;
use rust_rest_ldap::password::{PasswordPolicy, StoreScheme, policy::PasswordConfig};
use rust_rest_ldap::reload::Source;
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const SECRET: &str = "correct horse battery staple";

/// `{SSHA}` of `secret`, produced the way an old directory would have it.
fn ssha(secret: &str) -> String {
    use sha1::{Digest, Sha1};

    let salt = b"0123456789abcdef";
    let mut hasher = Sha1::new();
    hasher.update(secret.as_bytes());
    hasher.update(salt);
    let digest = hasher.finalize();

    let mut blob = digest.to_vec();
    blob.extend_from_slice(salt);

    format!("{{SSHA}}{}", base64_encode(&blob))
}

fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

fn entry(dn: &str, hash: &str) -> Entry {
    Entry::new(
        dn,
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
            .push(
                Attribute::new("userPassword", vec![hash.to_string()])
                    .case_sensitive()
                    .sensitive(),
            ),
    )
}

/// Policy that allows `{SSHA}` so an old directory can still be used.
fn legacy_policy(upgrade: Option<bool>) -> PasswordPolicy {
    PasswordPolicy::from_config(Some(&PasswordConfig {
        upgrade_on_bind: upgrade,
        allow_weak_hashes: Some(rust_rest_ldap::password::policy::WEAK_ACKNOWLEDGEMENT.to_string()),
        allowed_weak_hashes: Some("ssha".to_string()),
        allow_weak: Vec::new(),
        store_scheme: None,
    }))
    .expect("policy")
}

fn security(policy: PasswordPolicy) -> Security {
    Security {
        passwords: policy,
        // These tests bind over a plain duplex stream: the transport rule is not what
        // they are about, and it has its own tests.
        allow_unencrypted_bind: true,
        ..Security::default()
    }
}

fn bind_request(dn: &str, secret: &str) -> BindRequest {
    BindRequest::new(
        3,
        LdapDn::from(dn),
        AuthenticationChoice::Simple(rasn::types::OctetString::from(secret.as_bytes())),
    )
}

fn code(message: &LdapMessage) -> ResultCode {
    match &message.protocol_op {
        ProtocolOp::BindResponse(response) => response.result_code,
        other => panic!("not a bind response: {other:?}"),
    }
}

/// Runs a bind and returns the code plus any entry the handler wants stored.
fn run(
    directory: &Directory,
    dn: &str,
    secret: &str,
    policy: PasswordPolicy,
) -> (ResultCode, Option<Entry>) {
    let mut session = Session::new();
    let outcome = bind::handle_bind_outcome(
        &mut session,
        directory,
        1,
        &bind_request(dn, secret),
        &security(policy),
    );

    (code(&outcome.message), outcome.upgrade)
}

fn directory(hash: &str) -> Directory {
    Directory::from_entries(BASE, "users", "groups", vec![entry(ALICE_DN, hash)])
}

#[test]
fn a_weak_hash_is_upgraded_after_a_successful_bind() {
    let directory = directory(&ssha(SECRET));

    let (code, upgrade) = run(&directory, ALICE_DN, SECRET, legacy_policy(None));

    assert_eq!(code, ResultCode::Success);
    let upgrade = upgrade.expect("a weak hash must be upgraded");
    let new_hash = upgrade
        .attributes()
        .get("userPassword")
        .expect("userPassword")
        .values[0]
        .clone();

    assert!(
        new_hash.starts_with("$argon2id$"),
        "the new hash must be in the configured scheme, got {new_hash}"
    );
    assert_ne!(new_hash, ssha(SECRET), "and it must actually be new");
    assert_eq!(upgrade.dn(), ALICE_DN, "the entry keeps its DN");
}

#[test]
fn the_upgraded_hash_verifies_the_same_password() {
    // The upgrade is only worth anything if the user can still log in afterwards.
    let directory = directory(&ssha(SECRET));
    let (_, upgrade) = run(&directory, ALICE_DN, SECRET, legacy_policy(None));
    let new_hash = upgrade
        .expect("upgrade")
        .attributes()
        .get("userPassword")
        .expect("hash")
        .values[0]
        .clone();

    let strict = PasswordPolicy::strict();
    assert_eq!(
        rust_rest_ldap::password::verify(SECRET, &new_hash, &strict),
        Ok(true),
        "the new hash must accept the password that produced it"
    );
    assert_eq!(
        rust_rest_ldap::password::verify("wrong", &new_hash, &strict),
        Ok(false)
    );
}

#[test]
fn a_wrong_password_upgrades_nothing() {
    let directory = directory(&ssha(SECRET));

    let (code, upgrade) = run(
        &directory,
        ALICE_DN,
        "not the password",
        legacy_policy(None),
    );

    assert_eq!(code, ResultCode::InvalidCredentials);
    assert!(
        upgrade.is_none(),
        "an upgrade for a password that did not authenticate would lock the user out"
    );
}

#[test]
fn a_hash_already_in_the_store_scheme_is_left_alone() {
    let hash = hash_password(SECRET, StoreScheme::Argon2id).expect("hash");
    let directory = directory(&hash);

    let (code, upgrade) = run(&directory, ALICE_DN, SECRET, legacy_policy(None));

    assert_eq!(code, ResultCode::Success);
    assert!(
        upgrade.is_none(),
        "rewriting a hash that is already correct would touch the store on every bind"
    );
}

#[test]
fn the_upgrade_can_be_switched_off() {
    let directory = directory(&ssha(SECRET));

    let (code, upgrade) = run(&directory, ALICE_DN, SECRET, legacy_policy(Some(false)));

    assert_eq!(code, ResultCode::Success, "the bind still works");
    assert!(
        upgrade.is_none(),
        "with the option off the store must not be touched"
    );
}

#[test]
fn the_upgrade_keeps_the_attribute_flags() {
    let directory = directory(&ssha(SECRET));
    let (_, upgrade) = run(&directory, ALICE_DN, SECRET, legacy_policy(None));

    let password = upgrade
        .expect("upgrade")
        .attributes()
        .get("userPassword")
        .expect("userPassword")
        .clone();

    assert!(
        password.flags.sensitive && password.flags.case_sensitive,
        "an upgraded hash must stay hidden from * and compared exactly"
    );
}

#[test]
fn the_entry_keeps_its_other_attributes() {
    let directory = directory(&ssha(SECRET));
    let (_, upgrade) = run(&directory, ALICE_DN, SECRET, legacy_policy(None));
    let upgraded = upgrade.expect("upgrade");

    assert_eq!(
        upgraded
            .attributes()
            .get("uid")
            .map(|attribute| attribute.values.to_vec()),
        Some(vec!["alice".to_string()])
    );
    assert_eq!(
        upgraded
            .attributes()
            .get("objectClass")
            .map(|attribute| attribute.values.len()),
        Some(3),
        "nothing but the password may change"
    );
}

#[test]
fn a_password_the_server_cannot_parse_is_not_touched() {
    // An unreadable hash fails the bind; there is nothing to upgrade because the server
    // cannot tell whether the password was right.
    let directory = directory("{UNKNOWNSCHEME}whatever");

    let (code, upgrade) = run(&directory, ALICE_DN, SECRET, legacy_policy(None));

    assert_eq!(code, ResultCode::InvalidCredentials);
    assert!(upgrade.is_none());
}

#[test]
fn the_dispatcher_answers_before_it_persists() {
    // The bind succeeded, so the client must see `success` even though a write follows.
    let directory = directory(&ssha(SECRET));
    let mut session = Session::new();

    let action = handle(
        &mut session,
        &directory,
        &security(legacy_policy(None)),
        LdapMessage::new(1, ProtocolOp::BindRequest(bind_request(ALICE_DN, SECRET))),
    );

    match action {
        Action::PersistAfterReply { messages, changes } => {
            assert_eq!(messages.len(), 1);
            assert_eq!(code(&messages[0]), ResultCode::Success);
            assert_eq!(changes.len(), 1, "one entry to store");
            assert!(matches!(changes[0], EntryChange::Upsert { .. }));
        }
        other => panic!("expected reply-then-persist, got {other:?}"),
    }
}

#[test]
fn a_bind_with_nothing_to_upgrade_answers_plainly() {
    let hash = hash_password(SECRET, StoreScheme::Argon2id).expect("hash");
    let directory = directory(&hash);
    let mut session = Session::new();

    let action = handle(
        &mut session,
        &directory,
        &security(legacy_policy(None)),
        LdapMessage::new(1, ProtocolOp::BindRequest(bind_request(ALICE_DN, SECRET))),
    );

    assert!(
        matches!(action, Action::Reply(_)),
        "no write, no persist step: {action:?}"
    );
}

// ---------------------------------------------------------------------------
// Through a real store: the upgrade has to reach the file, not just the response.
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
passwords:
  AllowWeakHashes: "Yes I know this is bad idea"
  AllowedWeakHashes: "ssha"
"#,
        path.display()
    );
    rust_rest_ldap::config::resolve(Args::default(), Some(&text), |_| None).expect("config")
}

#[tokio::test]
async fn the_upgraded_hash_survives_a_reload() {
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
            EntryChange::Upsert {
                entry: entry(ALICE_DN, &ssha(SECRET)),
            },
            EntryChange::Upsert {
                entry: entry(
                    ADMIN_DN,
                    &hash_password("admin", StoreScheme::Argon2id).expect("hash"),
                ),
            },
        ])
        .await
        .expect("seed");

    let (source, directory) = Source::load(&config, backend).await.expect("load");
    let security = Security::from_config(&config);

    let mut session = Session::new();
    let action = handle(
        &mut session,
        &directory,
        &security,
        LdapMessage::new(1, ProtocolOp::BindRequest(bind_request(ALICE_DN, SECRET))),
    );

    let changes = match action {
        Action::PersistAfterReply { messages, changes } => {
            assert_eq!(code(&messages[0]), ResultCode::Success);
            changes
        }
        other => panic!("expected an upgrade to persist, got {other:?}"),
    };

    source.apply(&changes).await.expect("persist");

    // A fresh load is what a restart would see.
    let snapshot = source.directory().await;
    let stored = snapshot
        .find(ALICE_DN)
        .expect("alice")
        .attributes()
        .get("userPassword")
        .expect("hash")
        .values[0]
        .clone();

    assert!(
        stored.starts_with("$argon2id$"),
        "the stored hash must be the upgraded one, got {stored}"
    );

    // And the next bind still works, with no second upgrade.
    let mut session = Session::new();
    let action = handle(
        &mut session,
        source.directory().await.as_ref(),
        &security,
        LdapMessage::new(2, ProtocolOp::BindRequest(bind_request(ALICE_DN, SECRET))),
    );
    assert!(
        matches!(action, Action::Reply(_)),
        "a second bind must not write again: {action:?}"
    );
}

#[tokio::test]
async fn the_upgrade_does_not_widen_what_may_be_verified() {
    // Upgrading a hash is not the same as allowing weak schemes: with the default
    // policy a `{SSHA}` entry cannot bind at all, so there is nothing to upgrade.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("d.redb");
    let config = config(&path);

    let backend = Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("backend");
    backend
        .apply(&[EntryChange::Upsert {
            entry: entry(ALICE_DN, &ssha(SECRET)),
        }])
        .await
        .expect("seed");

    let (source, _) = Source::load(&config, backend).await.expect("load");
    let strict = Security {
        passwords: PasswordPolicy::strict(),
        allow_unencrypted_bind: true,
        ..Security::default()
    };

    let mut session = Session::new();
    let action = handle(
        &mut session,
        source.directory().await.as_ref(),
        &strict,
        LdapMessage::new(1, ProtocolOp::BindRequest(bind_request(ALICE_DN, SECRET))),
    );

    let messages = match action {
        Action::Reply(messages) => messages,
        other => panic!("a refused bind must not write: {other:?}"),
    };
    assert_eq!(code(&messages[0]), ResultCode::InvalidCredentials);
}

#[tokio::test]
async fn a_backend_that_cannot_store_does_not_break_the_bind() {
    // The file backend refuses whole-entry writes. The bind must still succeed, because
    // the password was right; only the upgrade is lost, and that is logged.
    let dir = tempfile::tempdir().expect("tempdir");
    let users = dir.path().join("users.json");
    let groups = dir.path().join("groups.json");
    std::fs::write(
        &users,
        format!(
            r#"[{{"objectClass":["top","person","inetOrgPerson"],"cn":"alice","sn":"S","uid":"alice","userPassword":"{}"}}]"#,
            ssha(SECRET)
        ),
    )
    .expect("write users");
    std::fs::write(&groups, "[]").expect("write groups");

    let text = format!(
        r#"
base_dn: {BASE}
AllowDangerousSettings: "Yes I know this is bad idea"
backends:
  file:
    users_path: {}
    groups_path: {}
bind:
  AllowUnencryptedBind: "Yes I know this is bad idea"
passwords:
  AllowWeakHashes: "Yes I know this is bad idea"
  AllowedWeakHashes: "ssha"
"#,
        users.display(),
        groups.display()
    );
    let config =
        rust_rest_ldap::config::resolve(Args::default(), Some(&text), |_| None).expect("config");
    let backend = Backend::from_config(
        "file",
        Some(&serde_json::json!({
            "users_path": users.display().to_string(),
            "groups_path": groups.display().to_string(),
        })),
    )
    .expect("backend");

    let (source, _) = Source::load(&config, backend).await.expect("load");
    let security = Security::from_config(&config);

    let mut session = Session::new();
    let action = handle(
        &mut session,
        source.directory().await.as_ref(),
        &security,
        LdapMessage::new(1, ProtocolOp::BindRequest(bind_request(ALICE_DN, SECRET))),
    );

    let (messages, changes) = match action {
        Action::PersistAfterReply { messages, changes } => (messages, changes),
        other => panic!("expected an upgrade attempt, got {other:?}"),
    };
    assert_eq!(
        code(&messages[0]),
        ResultCode::Success,
        "the bind is correct regardless of whether the new hash lands"
    );

    // This is the failure the server logs instead of reporting.
    assert!(
        source.apply(&changes).await.is_err(),
        "the file backend must refuse rather than silently drop the write"
    );
    let _ = Arc::new(());
}
