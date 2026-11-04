//! Content synchronisation (RFC 4533): a client asks what the directory holds now, and gets
//! every entry tagged with the identity a replica needs.
//!
//! What these test, and what they deliberately do not:
//!
//! - `refreshOnly` is answered: each entry carries a `syncState` control naming its identity and
//!   the cookie, and the answer ends with a `syncDone` - without which a client must treat the
//!   whole refresh as failed even though every entry arrived.
//! - `refreshAndPersist` keeps the answer open: the refresh stage ends with a `syncInfo` rather
//!   than a `searchResDone`, and changes are pushed afterwards without being asked for.
//! - The journal makes a resumed refresh cheap: an entry whose `entryCSN` is not newer than the
//!   cookie goes back as an empty `present` entry, and - past a threshold - a whole set of them
//!   goes back as one `syncIdSet` message instead of one message each.

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
    // Stamped, because that is what an entry written through the protocol always is: `entryCSN`
    // is what a resumed refresh compares against, and an entry without one cannot be called
    // unchanged.
    rust_rest_ldap::operational::stamp_write(
        &raw_person(cn),
        "cn=admin,dc=example,dc=com",
        std::time::SystemTime::now(),
    )
}

fn raw_person(cn: &str) -> Entry {
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
        server_id: 0,
        peers: Vec::new(),
        journal_keep: None,
        acl: rust_rest_ldap::acl::from_config(Some(&[rust_rest_ldap::acl::AccessRuleConfig {
            subject: "anonymous".to_string(),
            base: None,
            attributes: vec!["*".to_string()],
            rights: vec![
                "read".to_string(),
                "search".to_string(),
                "compare".to_string(),
                // The changed-entry test writes through the protocol, so the policy has to allow
                // it - a modify refused by the ACL looks exactly like one that did nothing.
                "write".to_string(),
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

/// The `syncRequest` control with a cookie: a client that already has a copy, asking for what
/// changed since.
fn sync_control_resuming(mode: u8, cookie: &[u8]) -> Control {
    let mut body = vec![0x0a, 0x01, mode, 0x04];
    body.push(cookie.len() as u8);
    body.extend_from_slice(cookie);

    let mut value = vec![0x30];
    value.push(body.len() as u8);
    value.extend_from_slice(&body);

    Control::new(
        LdapOid::from(sync::SYNC_OID.as_bytes()),
        true,
        Some(OctetString::from(value)),
    )
}

/// A paged-results control, so a refresh can be made deliberately incomplete.
fn paged_control(size: u32) -> Control {
    let mut value = vec![0x30, 0x05, 0x02, 0x01, size as u8, 0x04, 0x00];
    value.truncate(7);

    Control::new(
        LdapOid::from(b"1.2.840.113556.1.4.319".as_slice()),
        true,
        Some(OctetString::from(vec![
            0x30, 0x05, 0x02, 0x01, size as u8, 0x04, 0x00,
        ])),
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
/// The `syncIdSet` messages in an answer, as the UUIDs they name.
fn id_sets(messages: &[rasn_ldap::LdapMessage]) -> Vec<Vec<[u8; 16]>> {
    messages
        .iter()
        .filter_map(|message| match &message.protocol_op {
            ProtocolOp::IntermediateResponse(response) => {
                response
                    .response_name
                    .as_ref()
                    .filter(|oid| oid.as_ref() == sync::SYNC_OID.as_bytes())?;
                let value = response.response_value.as_ref()?.as_ref();
                assert_eq!(value[0], 0xa3, "a syncIdSet, not another syncInfo");

                // The length is in long form once the set grows past 127 bytes, which twelve
                // UUIDs already do.
                let mut offset = 1;
                let first = value[offset];
                offset += 1;
                if first & 0x80 != 0 {
                    offset += (first & 0x7f) as usize;
                }
                let mut rest = &value[offset..];
                if rest.first() == Some(&0x04) {
                    let length = rest[1] as usize;
                    rest = &rest[2 + length..];
                }
                if rest.first() == Some(&0x01) {
                    rest = &rest[3..];
                }
                assert_eq!(rest[0], 0x31, "the set of UUIDs");

                // A length in long form once the set passes 127 bytes, which it does at eight
                // UUIDs.
                let mut offset = 1;
                let first = rest[offset];
                offset += 1;
                let length = if first & 0x80 != 0 {
                    let count = (first & 0x7f) as usize;
                    let value = rest[offset..offset + count]
                        .iter()
                        .fold(0usize, |acc, byte| (acc << 8) | *byte as usize);
                    offset += count;
                    value
                } else {
                    first as usize
                };

                let body = &rest[offset..offset + length];
                let mut uuids = Vec::new();
                let mut index = 0;
                while index < body.len() {
                    assert_eq!(body[index], 0x04);
                    let length = body[index + 1] as usize;
                    let mut uuid = [0u8; 16];
                    uuid.copy_from_slice(&body[index + 2..index + 2 + length]);
                    uuids.push(uuid);
                    index += 2 + length;
                }
                Some(uuids)
            }
            _ => None,
        })
        .collect()
}

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

/// Every entry of a synchronised answer with its state and how many attributes it carried.
fn synchronised(messages: &[rasn_ldap::LdapMessage]) -> Vec<(String, sync::SyncState, usize)> {
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
                Some((
                    entry.object_name.0.to_string(),
                    state,
                    entry.attributes.len(),
                ))
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
            State::Add,
            "{dn}: RFC 4533 §1.3.1 - an entry the client does not have goes as add, with its \
             attributes"
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
async fn a_persistent_search_is_answered_and_then_pushes_what_changes() {
    // RFC 4533 §1.3.2: the refresh stage ends with a `syncInfo` message rather than a
    // `searchResDone`, and after it the server pushes changes on the same connection.
    let url = serve(vec![person("alice")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (refresh, id) = client
        .search_persist(search(), vec![sync_control(3)])
        .await
        .expect("persistent refresh");

    assert!(
        states(&refresh)
            .iter()
            .any(|(dn, _)| dn == "cn=alice,ou=users,dc=example,dc=com"),
        "the refresh stage sends the content as usual"
    );
    assert!(
        matches!(
            refresh.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::IntermediateResponse(_))
        ),
        "the refresh ends with syncInfo, not with searchResDone - the search is not over"
    );

    // A write, from another client, as a replica would see it.
    let other = Client::connect(&url, Options::default())
        .await
        .expect("connect");
    let new_dn = "cn=bob,ou=users,dc=example,dc=com";
    // Not `person`: that is stamped with operational attributes, and RFC 4511 forbids a client
    // from supplying those.
    let added = raw_person("bob");
    other
        .request(
            ProtocolOp::AddRequest(rasn_ldap::AddRequest {
                entry: LdapDn::from(new_dn),
                attributes: added
                    .attributes()
                    .values()
                    .iter()
                    .filter(|attribute| !attribute.values.is_empty())
                    .map(|attribute| {
                        rasn_ldap::Attribute::new(
                            rasn_ldap::AttributeDescription::from(attribute.name.to_string()),
                            rasn::types::SetOf::from_vec(
                                attribute
                                    .values
                                    .iter()
                                    .map(|value| {
                                        rasn_ldap::AttributeValue::from(value.as_bytes().to_vec())
                                    })
                                    .collect(),
                            ),
                        )
                    })
                    .collect(),
            }),
            "add response",
        )
        .await
        .expect("add");

    // The push arrives without anyone asking again: that is the difference between this and a
    // poll.
    let pushed = tokio::time::timeout(std::time::Duration::from_secs(5), client.next_change())
        .await
        .expect("a change must be pushed, not waited for")
        .expect("no transport error")
        .expect("a message");

    assert_eq!(pushed.message_id, id, "it belongs to the persistent search");
    let entries = synchronised(std::slice::from_ref(&pushed));
    assert_eq!(entries.len(), 1, "one pushed entry");
    assert_eq!(entries[0].0, new_dn);
    assert_eq!(entries[0].1.state, State::Add, "a new entry arrives as add");
    assert!(
        entries[0].2 > 0,
        "and with its attributes, or the client cannot apply it"
    );
}

#[tokio::test]
async fn a_persistent_search_is_told_about_a_deletion_it_did_not_ask_about() {
    // The half of replication that a refresh cannot express: an entry that is gone leaves no
    // trace in the directory, so only a push can say so.
    let url = serve(vec![person("alice"), person("bob")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (_, id) = client
        .search_persist(search(), vec![sync_control(3)])
        .await
        .expect("persistent refresh");

    let other = Client::connect(&url, Options::default())
        .await
        .expect("connect");
    other
        .request(
            ProtocolOp::DelRequest(rasn_ldap::DelRequest(LdapDn::from(
                "cn=bob,ou=users,dc=example,dc=com",
            ))),
            "delete response",
        )
        .await
        .expect("delete");

    let pushed = tokio::time::timeout(std::time::Duration::from_secs(5), client.next_change())
        .await
        .expect("a deletion must be pushed")
        .expect("no transport error")
        .expect("a message");

    assert_eq!(pushed.message_id, id);
    let entries = synchronised(std::slice::from_ref(&pushed));
    assert_eq!(
        entries.len(),
        1,
        "an empty entry carrying the state is how a removal is sent (RFC 4533 §1.3.2)"
    );
    assert_eq!(entries[0].0, "cn=bob,ou=users,dc=example,dc=com");
    assert_eq!(entries[0].1.state, State::Delete);
    assert_eq!(entries[0].2, 0, "a deletion carries no attributes");
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
async fn a_complete_refresh_asks_the_client_to_prune_what_it_was_not_sent() {
    // RFC 4533 §1.3.1: `refreshDeletes` FALSE means "drop every entry I did not identify as
    // present". That is how a refreshOnly answer reports a deletion at all - and it is only safe
    // when the answer is the whole content, which an unpaged, unlimited one is.
    let url = serve(vec![person("alice"), person("bob")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (messages, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("refresh");

    assert!(
        !done(&messages).expect("done").1,
        "a complete refresh prunes: an entry the client holds and did not get back is gone"
    );
}

#[tokio::test]
async fn a_resumed_refresh_sends_only_the_changes_with_their_attributes() {
    // The payoff of the journal and the CSN cookie, and the reason the two exist: an unchanged
    // entry goes back as an **empty** entry with state `present`, so a poll costs the changes
    // rather than the directory - while the client still learns which entries are still there.
    let url = serve(vec![person("alice"), person("bob")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (first, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("first refresh");
    let cookie = done(&first)
        .and_then(|(cookie, _)| cookie)
        .expect("a cookie");
    // The cookie carries the CSN, not only the snapshot: without it a resume cannot tell which
    // entries changed.
    let (_, csn) = sync::decode_cookie(&cookie).expect("a cookie of ours");
    assert!(
        csn.is_some(),
        "the journal exists, so the cookie must say how far it had got"
    );

    // A second refresh over an untouched directory: everything is unchanged.
    let (second, _) = client
        .search_with(search(), vec![sync_control_resuming(1, &cookie)])
        .await
        .expect("resumed refresh");

    let entries: Vec<(String, sync::SyncState, usize)> = synchronised(&second);
    assert!(
        !entries.is_empty(),
        "the client is told what is still there"
    );
    // A user entry is stamped with `entryCSN` on every write, so it can be reported unchanged: a
    // `present` state and no attributes, which is what makes a poll cost the changes rather than
    // the directory.
    let (_, state, attributes) = entries
        .iter()
        .find(|(dn, _, _)| dn == "cn=alice,ou=users,dc=example,dc=com")
        .expect("alice is in the answer");
    assert_eq!(
        state.state,
        State::Present,
        "unchanged since the cookie, so present rather than add"
    );
    assert_eq!(*attributes, 0, "an unchanged entry carries no attributes");

    // What is sent in full is what cannot be called unchanged. The directory synthesises the
    // naming context and the two units, and those carry no `entryCSN`, so there is nothing to
    // compare: they go as `add` with their attributes. Three entries per poll, and honest -
    // claiming "unchanged" about them would be a guess.
    assert!(
        entries
            .iter()
            .filter(|(dn, _, _)| !dn.starts_with("cn="))
            .all(|(_, state, _)| state.state == State::Add),
        "entries without a CSN are sent in full: {:?}",
        entries
            .iter()
            .map(|(dn, state, _)| (dn.clone(), state.state))
            .collect::<Vec<_>>()
    );
    assert!(
        !done(&second).expect("done").1,
        "the answer is still complete, so pruning stays safe"
    );
}

#[tokio::test]
async fn a_resumed_refresh_over_many_unchanged_entries_sends_one_set_not_a_message_each() {
    // RFC 4533 §1.3.1 lets the server name unchanged entries as a set of UUIDs instead of one
    // empty message per entry. Ten thousand untouched entries are then forty messages rather than
    // ten thousand - and the client learns exactly the same thing.
    let people: Vec<Entry> = (0..12)
        .map(|index| person(&format!("user{index:02}")))
        .collect();
    let url = serve(people.clone()).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (first, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("first refresh");
    let cookie = done(&first)
        .and_then(|(cookie, _)| cookie)
        .expect("a cookie");

    let (second, _) = client
        .search_with(search(), vec![sync_control_resuming(1, &cookie)])
        .await
        .expect("resumed refresh");

    let sets = id_sets(&second);
    assert_eq!(sets.len(), 1, "twelve UUIDs fit in one message");
    assert_eq!(
        sets[0].len(),
        12,
        "every unchanged entry is named once: {}",
        sets[0].len()
    );

    // The UUIDs are the entries' own, so a client can match them to what it holds. These fixtures
    // carry no stored `entryUUID`, so the server derives one from the DN - which is the identity a
    // client was given in the first refresh and therefore the one it expects back.
    let expected = sync::uuid_bytes(&rust_rest_ldap::directory::entry_uuid(
        "cn=user00,ou=users,dc=example,dc=com",
    ))
    .expect("sixteen octets");
    assert!(
        sets[0].contains(&expected),
        "the set names the entries' own UUIDs"
    );

    // And nothing is sent twice: a collapsed entry is not also written as an empty entry.
    let entries = synchronised(&second);
    assert!(
        !entries
            .iter()
            .any(|(dn, state, _)| dn.starts_with("cn=user") && state.state == State::Present),
        "a collapsed present entry carries no message of its own: {:?}",
        entries
            .iter()
            .map(|(dn, state, _)| (dn.clone(), state.state))
            .collect::<Vec<_>>()
    );

    // The synthetic entries have no CSN, so they are still sent in full: a set says nothing about
    // content the client may not have.
    assert!(
        entries
            .iter()
            .any(|(dn, state, _)| dn == BASE && state.state == State::Add),
        "the naming context still comes in full"
    );
}

#[tokio::test]
async fn a_few_unchanged_entries_are_not_worth_a_set() {
    // The threshold exists so that a small answer is not made more expensive than it was: below
    // it, one empty entry per entry beats a set message plus the bookkeeping.
    let url = serve(vec![person("alice"), person("bob")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (first, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("first refresh");
    let cookie = done(&first)
        .and_then(|(cookie, _)| cookie)
        .expect("a cookie");

    let (second, _) = client
        .search_with(search(), vec![sync_control_resuming(1, &cookie)])
        .await
        .expect("resumed refresh");

    assert!(
        id_sets(&second).is_empty(),
        "two unchanged entries do not justify a set"
    );
    assert_eq!(
        synchronised(&second)
            .iter()
            .filter(|(_, state, _)| state.state == State::Present)
            .count(),
        2,
        "they come as empty entries, as before"
    );
}

#[tokio::test]
async fn a_resumed_refresh_sends_a_changed_entry_with_its_attributes() {
    let url = serve(vec![person("alice")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (first, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("first refresh");
    let cookie = done(&first)
        .and_then(|(cookie, _)| cookie)
        .expect("a cookie");

    // One write through the protocol, which stamps a newer entryCSN.
    let mut changed = person("alice");
    changed = rust_rest_ldap::operational::stamp_write(
        &changed,
        "cn=admin,dc=example,dc=com",
        std::time::SystemTime::now() + std::time::Duration::from_secs(1),
    );
    let dn = changed.dn().to_string();
    let responses = client
        .request(
            ProtocolOp::ModifyRequest(rasn_ldap::ModifyRequest {
                object: LdapDn::from(dn.as_str()),
                changes: vec![rasn_ldap::ModifyRequestChanges {
                    operation: rasn_ldap::ChangeOperation::Replace,
                    modification: rasn_ldap::PartialAttribute::new(
                        rasn_ldap::AttributeDescription::from("sn"),
                        rasn::types::SetOf::from_vec(vec![rasn_ldap::AttributeValue::from(
                            b"Changed".as_slice(),
                        )]),
                    ),
                }],
            }),
            "modify response",
        )
        .await
        .expect("modify");

    // `request` does not fail on a non-success result code, so the code is checked here: a
    // refused modify would otherwise read as "the entry did not change", which is exactly the
    // assertion this test makes about the server.
    let modified_code = responses
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::ModifyResponse(response) => Some(response.0.result_code),
            _ => None,
        })
        .expect("a modify response");
    assert_eq!(
        modified_code,
        ResultCode::Success,
        "the modify has to be accepted for the test to be about synchronisation"
    );

    let (second, _) = client
        .search_with(search(), vec![sync_control_resuming(1, &cookie)])
        .await
        .expect("resumed refresh");

    let entries = synchronised(&second);
    let (_, state, attributes) = entries
        .iter()
        .find(|(found, _, _)| found == &dn)
        .expect("the changed entry is in the answer");

    assert_eq!(state.state, State::Add, "changed since the cookie");
    assert!(
        *attributes > 0,
        "a changed entry is sent with its attributes, or the client cannot apply the change"
    );
}

#[tokio::test]
async fn a_paged_refresh_refuses_to_let_the_client_prune() {
    // The reason this matters: with paging, entries are left out because they did not fit the
    // page - not because they were deleted. Signalling deletes there would make a client delete
    // live entries, and nothing would say so.
    let url = serve(vec![person("alice"), person("bob"), person("carol")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (first, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("first refresh");
    let cookie = done(&first)
        .and_then(|(cookie, _)| cookie)
        .expect("a cookie");

    let (second, _) = client
        .search_with(
            search(),
            vec![sync_control_resuming(1, &cookie), paged_control(1)],
        )
        .await
        .expect("paged refresh");

    assert!(
        done(&second).expect("done").1,
        "a page is not the whole directory, so the client must keep what it has instead of \
         pruning what it was not sent"
    );
}

#[tokio::test]
async fn a_size_limited_refresh_is_an_error_to_the_client_so_no_delete_hint_reaches_it() {
    let url = serve(vec![person("alice"), person("bob"), person("carol")]).await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (first, _) = client
        .search_with(search(), vec![sync_control(1)])
        .await
        .expect("first refresh");
    let cookie = done(&first)
        .and_then(|(cookie, _)| cookie)
        .expect("a cookie");

    let mut limited = search();
    limited.size_limit = 1;

    let outcome = client
        .search_with(limited, vec![sync_control_resuming(1, &cookie)])
        .await;

    // The client refuses the answer as a whole, which is the strongest form of "the absence of an
    // entry proves nothing": it never gets as far as reconciling. The server, for its part, does
    // not set `refreshDeletes` on an answer it cut short - the two halves agree, and neither
    // invites a client to delete a live entry.
    match outcome {
        Err(rust_rest_ldap::client::Error::Server { code, .. }) => {
            assert_eq!(code, ResultCode::SizeLimitExceeded);
        }
        Ok((messages, _)) => panic!(
            "a size-limited answer must not be accepted: {:?}",
            result_code(&messages)
        ),
        Err(other) => panic!("unexpected failure: {other}"),
    }
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
