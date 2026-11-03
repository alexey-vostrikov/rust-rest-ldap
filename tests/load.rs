//! Ten thousand entries, paged reads and concurrent clients: the numbers, and the answers.
//!
//! Two different kinds of assertion live here and they are kept apart on purpose.
//!
//! The **answers** are asserted: a paged read of ten thousand entries returns every entry
//! exactly once, and concurrent clients neither lose a write nor see a half-applied one. Those
//! are properties of the code, and a test that does not check them is worthless.
//!
//! The **timings** are printed, not asserted. A threshold in a test suite is a flaky test
//! waiting for a busy machine; the figures are here so a report can quote what this machine did,
//! and so a regression shows up as a number that moved rather than as a claim that something got
//! slower.
//!
//! **Memory is not measured here at all.** `VmRSS` read from `/proc` inside a test binary
//! reports what the whole process holds, including what the previous tests allocated and the
//! allocator did not return - the first attempt measured 66 MiB before and after building ten
//! thousand entries, which is not a number, it is the allocator's high-water mark. `tests/memory`
//! has a counting allocator that measures the real cost of a directory, and that is where the
//! figure belongs.
//!
//! Run with `--release -- --nocapture` to see the numbers; in a debug build they are three to
//! ten times larger and mean nothing.

use std::time::{Duration, Instant};

use rasn::types::{OctetString, SetOf};
use rasn_ldap::{
    AttributeDescription, Control, Filter, LdapDn, LdapOid, LdapString, ProtocolOp, ResultCode,
    SearchRequest, SearchRequestDerefAliases, SearchRequestScope,
};
use rust_rest_ldap::client::{Client, Options};
use rust_rest_ldap::config::{Args, Config};
use rust_rest_ldap::ldap::paged;
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const ADMIN_PASSWORD: &str = "admin-secret";

/// The size the performance question is asked at.
const ENTRIES: usize = 10_000;

fn document(path: &std::path::Path) -> String {
    format!(
        "\
base_dn: {BASE}
listen_addr: 127.0.0.1:0
backend: redb
schema:
  mode: warn
backends:
  redb:
    path: {}
AllowDangerousSettings: \"Yes I know this is bad idea\"
bind:
  AllowUnencryptedBind: \"Yes I know this is bad idea\"
indexes:
  default: [pres]
  attributes:
    cn: [eq, pres]
    uid: [eq]
",
        path.display()
    )
}

fn config(text: &str) -> Config {
    rust_rest_ldap::config::resolve(Args::default(), Some(text), |_| None).expect("config")
}

/// One person entry, cheap to build and distinguishable in a result.
fn person(dn: String, name: &str, sn: &str) -> Entry {
    let attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            // inetOrgPerson is what allows `uid`: without it every entry produces a schema
            // warning, and ten thousand lines of noise hide the numbers this test prints.
            vec![
                "top".to_string(),
                "person".to_string(),
                "organizationalPerson".to_string(),
                "inetOrgPerson".to_string(),
            ],
        ))
        .push(Attribute::single("cn", name))
        .push(Attribute::single("sn", sn))
        .push(Attribute::single("uid", name));

    Entry::new(dn, attributes)
}

fn user_entry(index: usize) -> Entry {
    let name = format!("user{index:05}");
    person(
        format!("cn={name},ou=users,{BASE}"),
        &name,
        &format!("Surname{index:05}"),
    )
}

fn admin_entry() -> Entry {
    let hash = rust_rest_ldap::password::hash(
        ADMIN_PASSWORD,
        rust_rest_ldap::password::StoreScheme::Argon2id,
    )
    .expect("hash");

    let attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec![
                "top".to_string(),
                "person".to_string(),
                "organizationalPerson".to_string(),
                "inetOrgPerson".to_string(),
            ],
        ))
        .push(Attribute::single("cn", "admin"))
        .push(Attribute::single("sn", "Admin"))
        .push(Attribute::single("uid", "admin"))
        .push(Attribute::single("userPassword", &hash))
        .push(Attribute::single("ldapAdmin", "true").internal());

    Entry::new(ADMIN_DN, attributes)
}

/// A server holding `ENTRIES` users, its address, and how long seeding took.
async fn server() -> (String, tempfile::TempDir, Duration) {
    let directory = tempfile::tempdir().expect("tempdir");
    let database = directory.path().join("directory.redb");

    let text = document(&database);
    let config = config(&text);
    let backend = rust_rest_ldap::backend::Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": database.display().to_string()})),
    )
    .expect("backend");

    // Seeding is measured: how long ten thousand entries take to reach the store is one of the
    // numbers the performance question asks for.
    let started = Instant::now();
    let mut changes = Vec::with_capacity(ENTRIES + 1);
    changes.push(rust_rest_ldap::backend::EntryChange::Upsert {
        entry: admin_entry(),
    });
    for index in 0..ENTRIES {
        changes.push(rust_rest_ldap::backend::EntryChange::Upsert {
            entry: user_entry(index),
        });
    }
    backend.apply(&changes).await.expect("seed");
    let seeding = started.elapsed();

    let security = Security::from_config(&config);
    let live = rust_rest_ldap::security::live(config.clone(), security);
    let (source, _) = rust_rest_ldap::reload::Source::load(&config, backend)
        .await
        .expect("source");

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

    (format!("ldap://{addr}"), directory, seeding)
}

async fn connect(url: &str) -> Client {
    let client = Client::connect(url, Options::default())
        .await
        .expect("connect");
    client.bind(ADMIN_DN, ADMIN_PASSWORD).await.expect("bind");
    client
}

fn search_request(filter: Filter, attributes: &[&str]) -> SearchRequest {
    SearchRequest::new(
        LdapDn::from(BASE),
        SearchRequestScope::WholeSubtree,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        filter,
        attributes
            .iter()
            .map(|name| LdapString::from(*name))
            .collect(),
    )
}

fn present() -> Filter {
    Filter::Present(AttributeDescription::from("objectClass"))
}

fn equality(attribute: &str, value: &str) -> Filter {
    Filter::EqualityMatch(rasn_ldap::AttributeValueAssertion::new(
        AttributeDescription::from(attribute),
        OctetString::from(value.as_bytes().to_vec()),
    ))
}

/// The entries of an answer, and the server's verdict on the whole search.
fn entries_of(messages: &[rasn_ldap::LdapMessage]) -> (Vec<String>, ResultCode) {
    let mut dns = Vec::new();
    let mut code = ResultCode::Other;

    for message in messages {
        match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => dns.push(entry.object_name.0.clone()),
            ProtocolOp::SearchResDone(done) => code = done.0.result_code,
            other => panic!("unexpected response: {other:?}"),
        }
    }

    (dns, code)
}

/// One page, and the cookie that continues it; `None` when the cursor is closed.
async fn page(
    client: &Client,
    size: u32,
    cookie: Option<Vec<u8>>,
) -> (Vec<String>, Option<Vec<u8>>) {
    let control = Control::new(
        LdapOid::from(paged::PAGED_RESULTS_OID.as_bytes()),
        // Critical: a server that does not understand paging must refuse rather than send the
        // whole result, which is what the page size was protecting against.
        true,
        Some(OctetString::from(paged::encode(&paged::Page::new(
            size,
            cookie.unwrap_or_default(),
        )))),
    );

    let (messages, outcome) = client
        .search_with(search_request(present(), &["cn"]), vec![control])
        .await
        .expect("search");

    assert_eq!(
        outcome.code,
        ResultCode::Success,
        "a page was refused: {}",
        outcome.diagnostic
    );

    let (dns, _) = entries_of(&messages);

    let mut next = None;
    for message in &messages {
        for control in message.controls.iter().flatten() {
            let paged_control =
                control.control_type.as_ref() == paged::PAGED_RESULTS_OID.as_bytes();
            let Some(value) = control.control_value.as_ref().filter(|_| paged_control) else {
                continue;
            };
            // `.ok()` and then a guard: `Result` has no `filter`, and clippy refuses the two
            // nested `if`s this replaced.
            if let Some(decoded) = paged::decode(value.as_ref())
                .ok()
                .filter(|page| !page.cookie.is_empty())
            {
                next = Some(decoded.cookie);
            }
        }
    }

    (dns, next)
}

/// The attributes of an entry as an add request carries them.
fn add_request(entry: &Entry) -> rasn_ldap::AddRequest {
    let attributes = entry
        .attributes()
        .values()
        .iter()
        .filter(|attribute| !attribute.values.is_empty())
        .map(|attribute| {
            rasn_ldap::Attribute::new(
                AttributeDescription::from(attribute.name.to_string()),
                SetOf::from_vec(
                    attribute
                        .values
                        .iter()
                        .map(|value| rasn_ldap::AttributeValue::from(value.as_bytes().to_vec()))
                        .collect(),
                ),
            )
        })
        .collect();

    rasn_ldap::AddRequest {
        entry: LdapDn::from(entry.dn()),
        attributes,
    }
}

async fn add(client: &Client, entry: &Entry) {
    let messages = client
        .request(ProtocolOp::AddRequest(add_request(entry)), "add response")
        .await
        .unwrap_or_else(|err| panic!("add of '{}' failed: {err}", entry.dn()));

    match messages.last().map(|message| &message.protocol_op) {
        Some(ProtocolOp::AddResponse(response)) => {
            assert_eq!(
                response.0.result_code,
                ResultCode::Success,
                "add of '{}': {}",
                entry.dn(),
                response.0.diagnostic_message.0
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn ten_thousand_entries_are_read_page_by_page_exactly_once() {
    let (url, _dir, seeding) = server().await;
    let client = connect(&url).await;

    // --- the answer: every entry, exactly once ---
    let size = 500;
    let mut seen: Vec<String> = Vec::new();
    let mut cookie: Option<Vec<u8>> = None;
    let mut pages = 0;

    let started = Instant::now();
    loop {
        let (dns, next) = page(&client, size, cookie).await;

        assert!(
            dns.len() <= size as usize,
            "a page of {size} returned {} entries",
            dns.len()
        );

        seen.extend(dns);
        pages += 1;
        match next {
            Some(next) => cookie = Some(next),
            None => break,
        }

        assert!(pages < 1000, "the paging cursor does not advance");
    }
    let paged_read = started.elapsed();

    // The base and the two OUs come first, then every user and the administrator.
    assert_eq!(
        seen.len(),
        ENTRIES + 4,
        "every entry exactly once, and none twice: {pages} pages of {size}"
    );

    let unique: std::collections::HashSet<&String> = seen.iter().collect();
    assert_eq!(
        unique.len(),
        seen.len(),
        "the pages overlap: a client reading them all would see duplicates"
    );

    for index in [0, ENTRIES / 2, ENTRIES - 1] {
        let dn = format!("cn=user{index:05},ou=users,{BASE}");
        assert!(
            unique.contains(&dn),
            "'{dn}' is missing from the paged result"
        );
    }

    // --- the numbers ---
    let lookup = {
        let started = Instant::now();
        let (messages, outcome) = client
            .search(search_request(
                equality("uid", &format!("user{:05}", ENTRIES / 2)),
                &["cn"],
            ))
            .await
            .expect("search");
        assert_eq!(outcome.code, ResultCode::Success);
        let (found, _) = entries_of(&messages);
        assert_eq!(found.len(), 1, "an indexed lookup finds its entry");
        started.elapsed()
    };

    println!("--- {ENTRIES} entries ---");
    println!("seeding into redb:          {seeding:?}");
    println!(
        "paged read, {size} per page: {paged_read:?} in {pages} pages ({:.2?} per page)",
        paged_read / pages.max(1) as u32
    );
    println!("indexed equality lookup:    {lookup:?}");
}

#[tokio::test]
async fn a_page_size_of_one_walks_the_whole_directory() {
    // The pathological page size: the cookie has to advance by exactly one each time, and the
    // last page must close the cursor rather than repeat or drop the final entry.
    let (url, _dir, _seeding) = server().await;
    let client = connect(&url).await;

    let mut seen = Vec::new();
    let mut cookie = None;
    let mut pages = 0;

    loop {
        let (dns, next) = page(&client, 1, cookie).await;
        seen.extend(dns);
        pages += 1;

        match next {
            Some(next) => cookie = Some(next),
            None => break,
        }
        assert!(pages <= ENTRIES + 5, "a page of one is not advancing");
    }

    assert_eq!(pages, ENTRIES + 4, "one entry per page, {pages} pages");
    assert_eq!(
        seen.len(),
        pages,
        "every page carried an entry, so the walk neither repeated nor skipped"
    );
}

#[tokio::test]
async fn concurrent_clients_read_and_write_without_losing_anything() {
    // What concurrency can break here: a write that another client's reload overwrites, a
    // search that reads a half-applied change, or a connection that answers the wrong request.
    let (url, _dir, _seeding) = server().await;

    const CLIENTS: usize = 8;
    const WRITES: usize = 25;

    let started = Instant::now();
    let mut tasks = Vec::new();

    for client_index in 0..CLIENTS {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let client = connect(&url).await;

            for write in 0..WRITES {
                let name = format!("conc{client_index:02}{write:03}");
                let entry = person(format!("cn={name},ou=users,{BASE}"), &name, "Concurrent");

                add(&client, &entry).await;

                // Every write is followed by a search, so reads run against a changing
                // directory rather than a frozen one.
                let (answers, outcome) = client
                    .search(search_request(equality("uid", &name), &["uid"]))
                    .await
                    .expect("search");

                assert_eq!(outcome.code, ResultCode::Success);
                let (found, _) = entries_of(&answers);
                assert!(
                    !found.is_empty(),
                    "'{name}' was added and the very next search does not see it: a write \
                     that answers success and is not visible breaks the one promise the write \
                     path makes"
                );
            }
        }));
    }

    for task in tasks {
        task.await.expect("a client task panicked");
    }

    let elapsed = started.elapsed();

    // Every write is in the store: nothing was lost, and nothing answered success in vain.
    let client = connect(&url).await;
    let (answers, outcome) = client
        .search(search_request(present(), &["uid"]))
        .await
        .expect("search");
    assert_eq!(outcome.code, ResultCode::Success);

    let (found, _) = entries_of(&answers);
    assert_eq!(
        found.len(),
        ENTRIES + 4 + CLIENTS * WRITES,
        "every one of the {} concurrent writes is in the directory",
        CLIENTS * WRITES
    );

    println!("--- {CLIENTS} clients, {WRITES} writes each ---");
    println!(
        "{} writes with a search after each: {elapsed:?} ({:.2?} per write)",
        CLIENTS * WRITES,
        elapsed / (CLIENTS * WRITES) as u32
    );
}

#[tokio::test]
async fn a_search_reads_one_snapshot_while_another_client_writes() {
    // The property the reload design exists for: one operation sees one directory. If a search
    // could see a half-applied change, a page could be missing entries that the change added or
    // count twice the ones it moved - and with ten thousand entries a reader would never spot
    // it by eye.
    let (url, _dir, _seeding) = server().await;

    let writer = connect(&url).await;
    let reader = connect(&url).await;

    let writing = tokio::spawn(async move {
        for index in 0..50 {
            let name = format!("snap{index:03}");
            let entry = person(format!("cn={name},ou=users,{BASE}"), &name, "Snapshot");
            add(&writer, &entry).await;
        }
    });

    // Reads run while the writes land; each must be a whole set of entries, never a fraction.
    let mut counts = Vec::new();
    for _ in 0..20 {
        let (answers, outcome) = reader
            .search(search_request(present(), &["cn"]))
            .await
            .expect("search");

        assert_eq!(outcome.code, ResultCode::Success);
        let (found, code) = entries_of(&answers);
        assert_eq!(code, ResultCode::Success, "a search ended without its done");
        counts.push(found.len());
    }

    writing.await.expect("the writer panicked");

    assert!(
        counts.windows(2).all(|pair| pair[0] <= pair[1]),
        "the number of entries went down during the run: {counts:?}"
    );
    assert!(
        counts.iter().all(|count| *count >= ENTRIES + 4),
        "a search returned fewer entries than the directory had before the writes: {counts:?}"
    );
    assert!(
        counts.iter().all(|count| *count <= ENTRIES + 4 + 50),
        "a search returned more entries than the writer added: {counts:?}"
    );

    println!("--- entry counts seen while 50 writes landed ---");
    println!("{counts:?}");
}
