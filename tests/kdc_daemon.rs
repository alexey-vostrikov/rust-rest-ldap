//! The KDC in the daemon, answering a real client over a real socket.
//!
//! Everything else about Kerberos in this crate is tested against an engine (`tests/kdc_inprocess.rs`)
//! or against a certificate (`tests/channel_binding.rs`). Neither says anything about the two things
//! this file is about: that the engine is reachable on port 88 at all, and that the realm it answers
//! for is the directory this server holds. So the client here is `krb5`'s, the socket is a real UDP
//! and TCP one, and the account it logs in as was written through the server's own write path.
//!
//! The negative test is the one that keeps the positive one honest: a KDC that hands a ticket to
//! anybody passes any test that only asks for a ticket.
#![cfg(feature = "kdc")]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rust_heimdal_kdc::crypto::{Enctype, OwnCipher};
use rust_heimdal_kdc::hdb::HdbEntry;
use rust_heimdal_kdc::hdb::ldap::dn_for;
use rust_heimdal_kdc::name::Principal;

use rust_rest_ldap::backend::{Backend, EntryChange};
use rust_rest_ldap::kerberos::{KerberosConfig, Settings, bootstrap, serve};
use rust_rest_ldap::model::Entry;
use rust_rest_ldap::reload::Source;

const REALM: &str = "EXAMPLE.COM";
const BASE_DN: &str = "dc=example,dc=com";
const PASSWORD: &str = "correct horse battery staple";
const SERVICE: &str = "ldap/host.example.com";

/// A source over a fresh redb store, with an account in it that has Kerberos keys.
async fn source_with_account(dir: &std::path::Path, account: &str) -> Arc<Source> {
    let store = dir.join("directory.redb");
    let text = format!(
        "base_dn: {BASE_DN}\n\
         backend: redb\n\
         backends:\n  redb:\n    path: {}\n\
         indexes:\n  default: [pres, eq, sub]\n\
         kerberos:\n  enabled: true\n",
        store.display()
    );
    let config = rust_rest_ldap::config::resolve(
        rust_rest_ldap::config::Args::default(),
        Some(&text),
        |_| None,
    )
    .expect("config");
    let backend = Backend::from_config("redb", config.backends.get("redb")).expect("backend");

    // The account, written the way the realm reads it back: `to_attributes`/`from_attributes` are
    // the KDC's own mapping, so this seeds the entry a KDC-side password change would have written.
    let cipher = OwnCipher;
    let mut changes = Vec::new();
    for (name, service) in [(account.to_string(), false), (SERVICE.to_string(), true)] {
        let principal = Principal::parse(&format!("{name}@{REALM}")).expect("a principal");
        let mut entry = HdbEntry::user(principal.clone());
        if service {
            // Without SERVER the TGS refuses a ticket for it - see `TODO.md` in the KDC: the answer
            // is `S_PRINCIPAL_UNKNOWN`, and it reads as a policy refusal in the message.
            entry.flags =
                rust_heimdal_kdc::hdb::flags::SERVER | rust_heimdal_kdc::hdb::flags::FORWARDABLE;
        }
        for enctype in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
            entry
                .add_password_key(&cipher, enctype, PASSWORD.as_bytes(), 1)
                .expect("a key");
        }
        changes.push(EntryChange::Upsert {
            entry: Entry::new(
                dn_for(&principal, BASE_DN),
                bootstrap::attributes_of(&entry),
            ),
        });
    }
    backend.apply(&changes).await.expect("seed");

    let (source, _) = Source::load(&config, backend).await.expect("source");
    source
}

/// A `kerberos:` section bound to a port the kernel picks.
fn settings(realm: &str) -> Settings {
    let config = KerberosConfig {
        enabled: true,
        realm: Some(realm.to_string()),
        port: Some(0),
        master_key_file: None,
    };
    Settings::resolve(&config, BASE_DN, IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("settings")
}

fn master_file(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("master");
    std::fs::write(&path, "the realm master password\n").expect("write");
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_logs_in_against_the_daemon() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_with_account(dir.path(), "alice").await;
    let master = master_file(dir.path());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let running = serve::start(
        &settings(REALM),
        Arc::clone(&source),
        BASE_DN.to_string(),
        Some(&master),
        shutdown_rx,
    )
    .await
    .expect("the KDC starts");

    let client = krb5::KdcClient::new(REALM, [running.bind.to_string().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).expect("a principal");
    let tgt = client
        .login_with_password(&alice, PASSWORD)
        .expect("a TGT from the daemon's own port");

    // The TGT alone proves the AS exchange; a ticket *for a service* proves the realm has a
    // `krbtgt` the KDC decrypts the TGT with - the half a bootstrap can get wrong and still appear
    // to work. Both exchanges run over this socket.
    let service = krb5::Principal::parse(&format!("{SERVICE}@{REALM}")).expect("a principal");
    client
        .service_ticket(&tgt, &service)
        .expect("a TGS-REP for the service the directory holds");

    let _ = shutdown_tx.send(true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_password_gets_no_ticket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_with_account(dir.path(), "alice").await;
    let master = master_file(dir.path());
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let running = serve::start(
        &settings(REALM),
        Arc::clone(&source),
        BASE_DN.to_string(),
        Some(&master),
        shutdown_rx,
    )
    .await
    .expect("the KDC starts");

    let client = krb5::KdcClient::new(REALM, [running.bind.to_string().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).expect("a principal");
    assert!(
        client
            .login_with_password(&alice, "not the password")
            .is_err(),
        "the daemon must not issue a ticket for a password that is not the key's"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_realm_without_a_krbtgt_and_without_a_master_password_does_not_start() {
    // The failure this prevents is the quiet one: a KDC that starts, answers, and refuses every
    // logon with an error an operator reads as "wrong password". With no way to derive `krbtgt`,
    // there is nothing to start.
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_with_account(dir.path(), "alice").await;
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let error = serve::start(
        &settings(REALM),
        Arc::clone(&source),
        BASE_DN.to_string(),
        None,
        shutdown_rx,
    )
    .await
    .expect_err("a realm without a krbtgt cannot be served");

    assert!(error.contains("krbtgt"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_realm_is_provisioned_once_and_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let master = master_file(dir.path());

    let store = dir.path().join("directory.redb");
    let text = format!(
        "base_dn: {BASE_DN}\n\
         backend: redb\n\
         backends:\n  redb:\n    path: {}\n\
         indexes:\n  default: [pres, eq, sub]\n\
         kerberos:\n  enabled: true\n",
        store.display()
    );
    let config = rust_rest_ldap::config::resolve(
        rust_rest_ldap::config::Args::default(),
        Some(&text),
        |_| None,
    )
    .expect("config");

    let krbtgt_dn = {
        let principal = Principal::parse(&format!("krbtgt/{REALM}@{REALM}")).expect("principal");
        dn_for(&principal, BASE_DN)
    };

    let entries_after_first = {
        let backend = Backend::from_config("redb", config.backends.get("redb")).expect("backend");
        let (source, _) = Source::load(&config, backend).await.expect("source");
        let (tx, rx) = tokio::sync::watch::channel(false);
        // Held for the length of the block: dropping the source is not enough, because the KDC's
        // own task holds one too, and a store still open is a store the second start cannot open.
        let _running = serve::start(
            &settings(REALM),
            Arc::clone(&source),
            BASE_DN.to_string(),
            Some(&master),
            rx,
        )
        .await
        .expect("start");
        assert!(
            source.directory().await.find(&krbtgt_dn).is_some(),
            "the first start must provision krbtgt"
        );
        let entries = default_entries(&source).await;
        let _ = tx.send(true);
        // The tasks notice the shutdown on their next select; the store's lock is released when
        // the last `Arc<Source>` goes, which is the moment those tasks return.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        drop(source);
        entries
    };

    // The second start finds the entry and must not touch the master password at all: the file is
    // removed, and a start that read it would fail here rather than in production.
    std::fs::remove_file(&master).expect("remove the master password");
    let backend = Backend::from_config("redb", config.backends.get("redb")).expect("backend");
    let (source, _) = Source::load(&config, backend).await.expect("source");
    let (_tx, rx) = tokio::sync::watch::channel(false);
    // Held, not read: the tasks it carries are what keep the store open, and the assertion below is
    // about the start succeeding without the master password, not about the handle.
    let _running = serve::start(
        &settings(REALM),
        Arc::clone(&source),
        BASE_DN.to_string(),
        Some(&master),
        rx,
    )
    .await
    .expect("a restart with the entry already there needs no master password");

    assert_eq!(
        default_entries(&source).await,
        entries_after_first,
        "the second start must not rewrite the realm"
    );
}

async fn default_entries(source: &Source) -> usize {
    source
        .directory()
        .await
        .entries(BASE_DN, rust_rest_ldap::directory::Scope::Subtree)
        .len()
}
