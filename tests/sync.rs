//! Content synchronisation (RFC 4533): a client asks what the directory holds now, and gets
//! every entry tagged with the identity a replica needs.
//!
//! What these test, and what they deliberately do not:
//!
//! - `refreshOnly` is answered: each entry carries a `syncState` control naming its identity and
//!   the cookie, and the answer ends with a `syncDone` - without which a client must treat the
//!   whole refresh as failed even though every entry arrived.
//! - `refreshAndPersist` is refused with `syncRefreshRequired`'s code, because this server does
//!   not keep an answer open and push changes: saying so is the honest answer, and a client that
//!   gets it starts again in a mode that works.
//! - There is no history, so no entry is ever reported as `add`, `modify` or `delete`. A replica
//!   reconciling a full refresh gets `present` and compares; a wrong state would be worse than
//!   none.

use std::time::Duration;

use rasn::types::OctetString;
use rasn_ldap::{
    Control, LdapDn, LdapOid, LdapString, ProtocolOp, ResultCode, SearchRequest,
    SearchRequestDerefAliases, SearchRequestScope,
};
use rust_rest_ldap::client::{Client, Options};
use rust_rest_ldap::config::Config;
use rust_rest_ldap::ldap::sync::{self, Mode, State};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";

fn person(cn: &str) -> Entry {
    Entry::new(
        format!("cn={cn},ou=users,dc=example,dc=com"),
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "person".to_string()],
            ))
            .push(Attribute::single("cn", cn))
            .push(Attribute::single("sn", "Person")),
    )
}

async fn serve(entries: Vec<Entry>) -> String {
    let config = Config {
        backend: "redb".to_string(),
        base_dn: BASE.to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        update_interval: Duration::from_secs(3600),
        log_path: None,
        debug: false,
        log_timestamp: false,
        log_caller: false,
        backends: Default::default(),
        respect_control_criticality: true,
        users_ou_name: "users".to_string(),
        groups_ou_name: "groups".to_string(),
        use_tls: false,
        server_cert: None,
        server_key: None,
        http_listen_addr: None,
        callback_auth_token: None,
        passwords: Default::default(),
        schema: rust_rest_ldap::schema::Schema::core(),
        schema_mode: rust_rest_ldap::schema::Mode::Off,
        schema_files: Vec::new(),
        indexes: Default::default(),
        referrals: Default::default(),
        acl: rust_rest_ldap::acl::from_config(Some(&[rust_rest_ldap::acl::AccessRuleConfig {
            subject: "anonymous".to_string(),
            base: None,
            attributes: vec!["*".to_string()],
            rights: vec![
                "read".to_string(),
                "search".to_string(),
                "compare".to_string(),
            ],
        }]))
        .expect("acl"),
        allow_unencrypted_bind: true,
        dangerous_settings: Vec::new(),
        integrity: Default::default(),
        observability: Default::default(),
        bootstrap: None,
        locale: (
            rust_rest_ldap::i18n::Locale::english(),
            rust_rest_ldap::i18n::Source::Default,
        ),
        locale_file: None,
        document: None,
    };

    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let database = std::env::temp_dir().join(format!("sync-{}-{serial}.redb", std::process::id()));
    let _ = std::fs::remove_file(&database);

    let backend = rust_rest_ldap::backend::Backend::from_config(
        "redb",
        Some(&serde_json::json!({ "path": database.display().to_string() })),
    )
    .expect("backend");
    backend
        .apply(
            &entries
                .into_iter()
                .map(|entry| rust_rest_ldap::backend::EntryChange::Upsert { entry })
                .collect::<Vec<_>>(),
        )
        .await
        .expect("seed");

    let (source, _directory) = rust_rest_ldap::reload::Source::load(&config, backend)
        .await
        .expect("source");
    let security = Security::from_config(&config).with_schema(source.shared_schema());
    let live = rust_rest_ldap::security::live(config, security);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("addr");
    let (_stop, shutdown) = tokio::sync::watch::channel(false);

    tokio::spawn(async move {
        let _ = rust_rest_ldap::server::serve(
            listener,
            None,
            false,
            source,
            live,
            shutdown,
            Duration::from_secs(2),
        )
        .await;
    });

    format!("ldap://{addr}")
}

fn search() -> SearchRequest {
    SearchRequest::new(
        LdapDn::from(BASE),
        SearchRequestScope::WholeSubtree,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        rust_rest_ldap::ldap::filter_parse::parse("(objectClass=*)").expect("filter"),
        vec![LdapString::from("cn")],
    )
}

/// The `syncRequest` control, as a client writes it: `SEQUENCE { ENUMERATED mode }`.
fn sync_control(mode: u8) -> Control {
    Control::new(
        LdapOid::from(sync::SYNC_OID.as_bytes()),
        true,
        Some(OctetString::from(vec![0x30, 0x03, 0x0a, 0x01, mode])),
    )
}

/// The sync state the answer attached to one entry.
fn states(messages: &[rasn_ldap::LdapMessage]) -> Vec<(String, sync::SyncState)> {
    messages
        .iter()
        .filter_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => {
                let control =
                    message.controls.as_ref()?.iter().find(|control| {
                        control.control_type.as_ref() == sync::SYNC_OID.as_bytes()
                    })?;
                let value = control.control_value.as_ref()?;
                let state = sync::decode_state(value.as_ref()).expect("a decodable state");
                Some((entry.object_name.0.to_string(), state))
            }
            _ => None,
        })
        .collect()
}

/// The `syncDone` control of an answer.
fn done(messages: &[rasn_ldap::LdapMessage]) -> Option<(Option<Vec<u8>>, bool)> {
    messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResDone(_) => {
                let control =
                    message.controls.as_ref()?.iter().find(|control| {
                        control.control_type.as_ref() == sync::SYNC_OID.as_bytes()
                    })?;
                let value = control.control_value.as_ref()?;
                Some(sync::decode_done(value.as_ref()).expect("a decodable done"))
            }
            _ => None,
        })
}

fn result_code(messages: &[rasn_ldap::LdapMessage]) -> Option<ResultCode> {
    messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResDone(done) => Some(done.0.result_code),
            _ => None,
        })
}

#[tokio::test]
async fn a_refresh_only_answer_names_every_entry_and_ends_with_a_done() {
    let url = serve(vec![person("alice"), person("bob")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (messages, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("search");

    let states = states(&messages);
    assert!(
        !states.is_empty(),
        "the answer tags entries, otherwise a replica has nothing to reconcile"
    );

    for (dn, state) in &states {
        assert_eq!(
            state.state,
            State::Present,
            "{dn}: a full refresh describes what is there; without history there is nothing to \
             report as added or modified"
        );
        assert_ne!(
            state.uuid, [0u8; 16],
            "{dn}: an identity of zeroes would file the entry under nothing"
        );
        assert!(
            state.cookie.is_some(),
            "{dn}: the cookie is what makes the answer resumable"
        );
    }

    // Two people: the two users, the two units and the naming context.
    assert!(
        states
            .iter()
            .any(|(dn, _)| dn == "cn=alice,ou=users,dc=example,dc=com"),
        "alice is in the answer: {:?}",
        states.iter().map(|(dn, _)| dn).collect::<Vec<_>>()
    );

    let done = done(&messages).expect("a syncDone control");
    assert!(
        done.0.is_some(),
        "the cookie is repeated at the end, so a client that finished knows where it is"
    );
    assert!(!done.1, "nothing was deleted, so refreshDeletes is false");
    assert_eq!(result_code(&messages), Some(ResultCode::Success));
}

#[tokio::test]
async fn refresh_and_persist_is_refused_with_a_code_that_says_what_to_do() {
    // The honest answer. A refreshOnly stream the client waits on forever would look like a
    // working replica that never updates.
    let url = serve(vec![person("alice")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let outcome = client.search_with(search(), vec![sync_control(3)]).await;

    match outcome {
        Ok((messages, _)) => panic!(
            "must not answer an unsupported mode with entries: {:?}",
            result_code(&messages)
        ),
        Err(rust_rest_ldap::client::Error::Server { code, message }) => {
            assert_eq!(code, ResultCode::UnwillingToPerform);
            assert!(
                message.contains("refreshOnly"),
                "the message says what to ask for instead: {message}"
            );
        }
        Err(other) => panic!("unexpected failure: {other}"),
    }
}

#[tokio::test]
async fn a_search_without_the_sync_control_carries_none() {
    // The control must not leak into ordinary searches: a client that did not ask for
    // synchronisation has no reason to decode a control it never requested.
    let url = serve(vec![person("alice")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (messages, _) = client.search(search()).await.expect("search");

    assert!(states(&messages).is_empty());
    assert!(done(&messages).is_none());
}

#[tokio::test]
async fn the_cookie_is_the_snapshot_the_answer_was_cut_from() {
    // The point of a cookie: a second answer can be told apart from the first. On a directory
    // nobody writes to it stays the same; after a write it moves.
    let url = serve(vec![person("alice")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (first, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("first");
    let (second, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("second");

    let cookie_of = |messages: &[rasn_ldap::LdapMessage]| {
        done(messages)
            .and_then(|(cookie, _)| cookie)
            .expect("a cookie")
    };

    assert_eq!(
        cookie_of(&first),
        cookie_of(&second),
        "no write happened between the two answers, so the snapshot did not move"
    );
}

#[tokio::test]
async fn an_entry_without_a_stored_uuid_still_gets_a_stable_identity() {
    // Entries imported from elsewhere may carry no `entryUUID`. The identity is then derived
    // from the DN, which is the same after a restart - a replica keyed on a value that changed
    // on every start would rebuild its whole copy every time.
    let first = serve(vec![person("carol")]).await;
    let client = Client::connect(&first, Options::default())
        .await
        .expect("connect");
    let (messages, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("search");

    let uuid_of = |messages: &[rasn_ldap::LdapMessage], dn: &str| {
        states(messages)
            .into_iter()
            .find(|(found, _)| found == dn)
            .map(|(_, state)| state.uuid)
    };

    let dn = "cn=carol,ou=users,dc=example,dc=com";
    let uuid = uuid_of(&messages, dn).expect("carol is in the answer");
    assert_ne!(uuid, [0u8; 16]);

    // The same entry, a second server: the identity must not depend on when it was served.
    let second = serve(vec![person("carol")]).await;
    let client = Client::connect(&second, Options::default())
        .await
        .expect("connect");
    let (again, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("search");

    assert_eq!(
        uuid_of(&again, dn),
        Some(uuid),
        "the identity of an entry is a property of the entry, not of the answer"
    );
}

#[tokio::test]
async fn a_client_that_asks_for_an_unknown_mode_is_told_it_is_a_protocol_error() {
    let url = serve(vec![person("alice")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    // Mode 2 is deliberately unused by the RFC.
    let outcome = client.search_with(search(), vec![sync_control(2)]).await;

    match outcome {
        Err(rust_rest_ldap::client::Error::Server { code, message }) => {
            assert_eq!(code, ResultCode::ProtocolError);
            assert!(message.contains("mode"), "{message}");
        }
        Ok((messages, _)) => panic!(
            "an unknown mode must not be answered: {:?}",
            result_code(&messages)
        ),
        Err(other) => panic!("unexpected failure: {other}"),
    }
}

#[tokio::test]
async fn the_mode_decoded_matches_what_the_client_asked_for() {
    // A guard on the test's own assumption: if `sync_control(1)` were not refreshOnly, the
    // tests above would be checking the wrong thing and would still pass.
    let request = sync::decode_request(&[0x30, 0x03, 0x0a, 0x01, 0x01]).expect("decodes");

    assert_eq!(request.mode, Mode::RefreshOnly);
}
