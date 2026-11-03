//! The client session: what the utilities of phase F are built on.
//!
//! Two kinds of test here. The ones against our own server prove that the client and the
//! server agree on the wire. The ones against a scripted socket prove the things a
//! well-behaved server never does and a broken one always does: answers in the wrong order,
//! silence, a connection that dies in the middle of a result, and an answer larger than the
//! client is willing to hold.

use std::time::Duration;

use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, AttributeValueAssertion, Filter, LdapDn, LdapMessage, ProtocolOp,
    ResultCode, SearchRequest, SearchRequestDerefAliases, SearchRequestScope,
};
use rust_rest_ldap::client::{Client, Error, Limits, Options};
use rust_rest_ldap::config::{Args, Config};
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::reload::Source;
use rust_rest_ldap::security::Security;

/// The live handle the server takes, starting from `security`.
fn live_security(security: Security) -> rust_rest_ldap::security::Shared {
    let running =
        rust_rest_ldap::config::resolve(rust_rest_ldap::config::Args::default(), None, |_| None)
            .expect("the default configuration resolves");
    rust_rest_ldap::security::live(running, security)
}

const BASE: &str = "dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";

fn entry(dn: &str, cn: &str, mail: &str) -> Entry {
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
            .push(Attribute::single("cn", cn))
            .push(Attribute::single("sn", "Surname"))
            .push(Attribute::single("uid", cn))
            .push(Attribute::single("mail", mail)),
    )
}

fn config(path: &std::path::Path) -> Config {
    // Anonymous read: the tests ask the server the questions a script would ask, and what
    // they are checking is the wire, not the access policy.
    let text = format!(
        "base_dn: {BASE}\n\
         access:\n\
         \x20 - subject: anonymous\n\
         \x20   attributes: [\"*\"]\n\
         \x20   rights: [read, search, compare]\n\
         backends:\n  redb:\n    path: {}\n",
        path.display()
    );
    rust_rest_ldap::config::resolve(Args::default(), Some(&text), |_| None).expect("config")
}

/// A directory-in-a-socket: the real server on a real port, serving alice and bob.
async fn server() -> (String, tokio::task::JoinHandle<()>) {
    // One database per test: the tests run in parallel in one process, and a shared path
    // means the second one finds the file locked by the first.
    let directory = tempfile::tempdir().expect("tempdir");
    let dir = directory.path().join("directory.redb");
    // The server outlives this call, so the directory has to outlive the test.
    std::mem::forget(directory);

    let config = config(&dir);
    let backend = rust_rest_ldap::backend::Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": dir.display().to_string()})),
    )
    .expect("backend");
    let data = rust_rest_ldap::backend::DirectoryData {
        entries: vec![
            entry(ALICE_DN, "alice", "alice@example.com"),
            entry(
                "cn=bob,ou=users,dc=example,dc=com",
                "bob",
                "bob@example.com",
            ),
        ],
        ..Default::default()
    };
    backend
        .apply(
            &data
                .entries
                .iter()
                .cloned()
                .map(|entry| rust_rest_ldap::backend::EntryChange::Upsert { entry })
                .collect::<Vec<_>>(),
        )
        .await
        .expect("seed");

    let security = Security::from_config(&config);
    let (source, _directory) = Source::load(&config, backend).await.expect("source");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("addr");
    let (stop, shutdown) = tokio::sync::watch::channel(false);

    let serving = tokio::spawn(async move {
        let _ = rust_rest_ldap::server::serve(
            listener,
            None,
            false,
            source,
            live_security(security),
            shutdown,
            Duration::from_secs(2),
        )
        .await;
    });

    // The handle stops the server when the test is done; the address is what a client needs.
    std::mem::forget(stop);
    (format!("ldap://{addr}"), serving)
}

fn search(base: &str, filter: Filter) -> SearchRequest {
    SearchRequest::new(
        LdapDn::from(base),
        SearchRequestScope::WholeSubtree,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        filter,
        vec![rasn_ldap::LdapString::from("cn")],
    )
}

fn present(name: &str) -> Filter {
    Filter::Present(AttributeDescription::from(name))
}

fn equality(name: &str, value: &str) -> Filter {
    Filter::EqualityMatch(AttributeValueAssertion::new(
        AttributeDescription::from(name),
        OctetString::from(value.as_bytes()),
    ))
}

fn dns(entries: &[LdapMessage]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => Some(entry.object_name.to_string()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// Against the real server.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_search_over_the_wire_returns_the_entries_and_the_result() {
    let (url, serving) = server().await;

    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");
    let (entries, result) = client
        .search(search(BASE, present("objectClass")))
        .await
        .expect("search");

    assert_eq!(result.code, ResultCode::Success);
    let mut found = dns(&entries);
    found.sort();
    assert_eq!(
        found,
        vec![
            ALICE_DN.to_string(),
            "cn=bob,ou=users,dc=example,dc=com".to_string(),
            BASE.to_string(),
            "ou=groups,dc=example,dc=com".to_string(),
            "ou=users,dc=example,dc=com".to_string(),
        ],
        "the whole subtree, including the units the server synthesises"
    );

    serving.abort();
}

#[tokio::test]
async fn a_filter_is_applied_by_the_server_not_by_the_client() {
    let (url, serving) = server().await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (entries, result) = client
        .search(search(BASE, equality("uid", "bob")))
        .await
        .expect("search");

    assert_eq!(result.code, ResultCode::Success);
    assert_eq!(
        dns(&entries),
        vec!["cn=bob,ou=users,dc=example,dc=com".to_string()]
    );

    serving.abort();
}

#[tokio::test]
async fn two_searches_at_once_each_get_their_own_answer() {
    // One connection, two requests in flight. The client registers both message ids and
    // hands out each response to the request that asked for it.
    let (url, serving) = server().await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (first, second) = tokio::join!(
        client.search(search(BASE, equality("uid", "alice"))),
        client.search(search(BASE, equality("uid", "bob"))),
    );

    let (first, second) = (first.expect("alice"), second.expect("bob"));
    assert_eq!(dns(&first.0), vec![ALICE_DN.to_string()]);
    assert_eq!(
        dns(&second.0),
        vec!["cn=bob,ou=users,dc=example,dc=com".to_string()]
    );

    serving.abort();
}

#[tokio::test]
async fn an_unbind_closes_the_connection_and_a_later_request_says_so() {
    let (url, serving) = server().await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    client.unbind().await.expect("unbind");

    // Not a hang and not a silent empty result: the connection is gone, and the next
    // caller hears about it.
    let err = client
        .search(search(BASE, present("objectClass")))
        .await
        .expect_err("must refuse");
    assert!(matches!(err, Error::Closed), "expected Closed, got {err}");

    serving.abort();
}

// ---------------------------------------------------------------------------------------
// Against a scripted socket: the ways a server misbehaves.
// ---------------------------------------------------------------------------------------

/// A socket that runs a script, one closure per received message.
async fn scripted<F>(script: F) -> String
where
    F: FnOnce(
            tokio::net::TcpStream,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            script(stream).await;
        }
    });

    format!("ldap://{addr}")
}

#[tokio::test]
async fn responses_are_matched_by_message_id_even_when_they_come_back_reversed() {
    // A server is free to answer in any order (RFC 4511 §4.2: "the client may send
    // multiple requests and the server may respond in any order"). A client that assumes
    // the first response belongs to the first request reads the wrong answer — the kind of
    // bug that shows up as a search returning another user's data.
    let url = scripted(|mut stream| {
        Box::pin(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let first = rust_rest_ldap::ldap::codec::read_message(&mut stream)
                .await
                .expect("first");
            let second = rust_rest_ldap::ldap::codec::read_message(&mut stream)
                .await
                .expect("second");

            let first = rust_rest_ldap::ldap::codec::decode(&first).expect("decode");
            let second = rust_rest_ldap::ldap::codec::decode(&second).expect("decode");

            // Answer the SECOND request first, both messages of the pair each time.
            for answer in [
                answer(second.message_id, "cn=second"),
                answer(first.message_id, "cn=first"),
            ] {
                for message in answer {
                    let bytes = rust_rest_ldap::ldap::codec::encode(&message).expect("encode");
                    stream.write_all(&bytes).await.expect("write");
                }
            }

            // Hold the connection open so the client is not also dealing with a close.
            let mut sink = [0u8; 1];
            let _ = stream.read(&mut sink).await;
        })
    })
    .await;

    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let (first, second) = tokio::join!(
        client.search(search(BASE, equality("uid", "first"))),
        client.search(search(BASE, equality("uid", "second"))),
    );

    assert_eq!(
        dns(&first.expect("first").0),
        vec!["cn=first".to_string()],
        "the answer to the first request, not the first answer to arrive"
    );
    assert_eq!(
        dns(&second.expect("second").0),
        vec!["cn=second".to_string()],
        "the answer to the second request"
    );
}

/// One entry and a success, both for `message_id`, naming `cn`.
///
/// A search is only complete when the server says so: an entry on its own is half an
/// answer, and the client has to keep reading after it.
fn answer(message_id: rasn_ldap::MessageId, cn: &str) -> Vec<LdapMessage> {
    vec![
        rust_rest_ldap::ldap::responses::search_result_entry(
            message_id,
            cn,
            &[Attribute::single("cn", cn.trim_start_matches("cn="))],
        ),
        rust_rest_ldap::ldap::responses::search_done(message_id, ResultCode::Success, ""),
    ]
}

#[tokio::test]
async fn a_silent_server_gives_a_timeout_and_not_an_eternal_wait() {
    let url = scripted(|stream| {
        Box::pin(async move {
            // Read the request, then say nothing at all, keeping the socket open.
            let mut stream = stream;
            let _ = rust_rest_ldap::ldap::codec::read_message(&mut stream).await;
            std::future::pending::<()>().await;
        })
    })
    .await;

    let options = Options {
        timeout: Duration::from_millis(200),
        ..Options::default()
    };
    let client = Client::connect(&url, options).await.expect("connect");

    let started = std::time::Instant::now();
    let err = client
        .search(search(BASE, present("objectClass")))
        .await
        .expect_err("must time out");

    assert!(
        matches!(err, Error::Timeout { .. }),
        "expected Timeout, got {err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the timeout must be the configured one, not however long the test allows"
    );
}

#[tokio::test]
async fn a_connection_that_dies_mid_result_is_an_error_not_a_short_answer() {
    // The worst failure mode of a directory client: half a result presented as the whole
    // one. A script walking the output would act on a truncated list and never know.
    let url = scripted(|mut stream| {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;

            let request = rust_rest_ldap::ldap::codec::read_message(&mut stream)
                .await
                .expect("request");
            let request = rust_rest_ldap::ldap::codec::decode(&request).expect("decode");

            // Only the entry: the server dies before it can say the result is complete.
            let entry = answer(request.message_id, "cn=only").remove(0);
            let bytes = rust_rest_ldap::ldap::codec::encode(&entry).expect("encode");
            stream.write_all(&bytes).await.expect("write");
            stream.flush().await.expect("flush");
            // No SearchResultDone, and then the socket goes away.
            drop(stream);
        })
    })
    .await;

    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let err = client
        .search(search(BASE, present("objectClass")))
        .await
        .expect_err("must not report a partial result as complete");

    assert!(matches!(err, Error::Closed), "expected Closed, got {err}");
}

#[tokio::test]
async fn an_answer_over_the_size_limit_is_refused_before_it_is_read_in_full() {
    // The limit exists to keep one broken or hostile server from exhausting the client's
    // memory. It has to be enforced on the frame header, not after the body arrived.
    let url = scripted(|mut stream| {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;

            let request = rust_rest_ldap::ldap::codec::read_message(&mut stream)
                .await
                .expect("request");
            let request = rust_rest_ldap::ldap::codec::decode(&request).expect("decode");

            let big = huge_entry(request.message_id, 4096);
            let bytes = rust_rest_ldap::ldap::codec::encode(&big).expect("encode");
            let _ = stream.write_all(&bytes).await;
            std::future::pending::<()>().await;
        })
    })
    .await;

    let options = Options {
        limits: Limits {
            max_message: 512,
            ..Limits::default()
        },
        ..Options::default()
    };
    let client = Client::connect(&url, options).await.expect("connect");

    let err = client
        .search(search(BASE, present("objectClass")))
        .await
        .expect_err("must refuse the oversized answer");

    assert!(
        matches!(err, Error::TooLarge { .. }),
        "expected TooLarge, got {err}"
    );
}

fn huge_entry(message_id: rasn_ldap::MessageId, length: usize) -> LdapMessage {
    rust_rest_ldap::ldap::responses::search_result_entry(
        message_id,
        "cn=huge",
        &[Attribute::single("description", &"x".repeat(length))],
    )
}

#[tokio::test]
async fn a_url_without_a_scheme_is_refused_with_the_schemes_that_exist() {
    let err = Client::connect("localhost:389", Options::default())
        .await
        .expect_err("must refuse");
    let text = err.to_string();
    assert!(
        text.contains("ldap://") && text.contains("ldaps://"),
        "the message must name the schemes that are understood: {text}"
    );
}

#[tokio::test]
async fn a_bind_with_the_wrong_password_reaches_the_server_and_is_refused_there() {
    let (url, serving) = server().await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    // What the server decides, not what the client guessed: a simple bind in the clear is
    // refused by default here, and the code that comes back is the server's. A client that
    // turned every refusal into "wrong password" would hide a configuration mistake behind
    // a message about credentials.
    let err = client
        .bind(ADMIN_DN, "wrong")
        .await
        .expect_err("must refuse");
    match err {
        Error::Server { code, .. } => assert_eq!(code, ResultCode::StrongerAuthRequired),
        other => panic!("expected the server's own code, got {other}"),
    }

    serving.abort();
}

#[tokio::test]
async fn a_directory_without_data_still_answers_a_search() {
    // The rootDSE is the one entry every server has, and it is how an operator finds out
    // what a server supports before knowing anything else about it.
    let (url, serving) = server().await;
    let client = Client::connect(&url, Options::default())
        .await
        .expect("connect");

    let mut base_search = search("", present("objectClass"));
    base_search.scope = SearchRequestScope::BaseObject;
    let (entries, result) = client.search(base_search).await.expect("rootDSE");

    assert_eq!(result.code, ResultCode::Success);
    // `entries` holds every message of the answer, the final `searchResDone` included: the
    // entries are the ones that are entries.
    assert_eq!(dns(&entries).len(), 1, "the rootDSE is one entry");

    serving.abort();
}

#[tokio::test]
async fn the_directory_type_is_the_one_the_server_serves() {
    // A reminder for the next step: the client hands back protocol messages, and the
    // directory is what those messages describe. Keeping the two apart is what lets the
    // utilities print LDIF without a second implementation of the same question.
    let directory = Directory::from_entries(
        BASE,
        "users",
        "groups",
        vec![entry(ALICE_DN, "alice", "alice@example.com")],
    );
    assert!(directory.find(ALICE_DN).is_some());
}

// ---------------------------------------------------------------------------------------
// TLS: LDAPS from the first byte, and StartTLS in the middle of a connection.
// ---------------------------------------------------------------------------------------

/// A server with TLS, and the certificate it presents.
async fn tls_server(ldaps: bool) -> (String, std::path::PathBuf, tokio::task::JoinHandle<()>) {
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");

    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().to_path_buf();
    let cert_path = path.join("cert.pem");
    let key_path = path.join("key.pem");
    std::fs::write(&cert_path, generated.cert.pem()).expect("cert");
    std::fs::write(&key_path, generated.signing_key.serialize_pem()).expect("key");
    // The certificate has to outlive the server, which is listening on the connection the
    // test opened after this function returned.
    std::mem::forget(directory);

    let config = config(&path.join("directory.redb"));
    let backend = rust_rest_ldap::backend::Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.join("directory.redb").display().to_string()})),
    )
    .expect("backend");
    let entry = entry(ALICE_DN, "alice", "alice@example.com");
    backend
        .apply(&[rust_rest_ldap::backend::EntryChange::Upsert { entry }])
        .await
        .expect("seed");

    let security = Security::from_config(&config);
    let (source, _directory) = Source::load(&config, backend).await.expect("source");
    let acceptor = rust_rest_ldap::tls::acceptor(&cert_path, &key_path).expect("acceptor");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("addr");

    let serving = tokio::spawn(async move {
        let _ = rust_rest_ldap::server::serve(
            listener,
            Some(acceptor),
            // `ldaps` decides whether the first byte is a TLS record or an LDAP message.
            ldaps,
            source,
            live_security(security),
            tokio::sync::watch::channel(false).1,
            Duration::from_secs(2),
        )
        .await;
    });

    let scheme = if ldaps { "ldaps" } else { "ldap" };
    (format!("{scheme}://{addr}"), cert_path, serving)
}

#[tokio::test]
async fn ldaps_checks_the_certificate_against_the_file_it_was_given() {
    let (url, cert, serving) = tls_server(true).await;
    let url = url.replace("127.0.0.1", "localhost");

    let client = Client::connect(
        &url,
        Options {
            // The certificate names `localhost`, and so does the URL: that is the point of
            // serving it as the trust anchor.
            trust: rust_rest_ldap::client::Trust::File(cert),
            ..Options::default()
        },
    )
    .await
    .expect("ldaps");

    let (entries, result) = client
        .search(search(BASE, equality("uid", "alice")))
        .await
        .expect("search");
    assert_eq!(result.code, ResultCode::Success);
    assert_eq!(dns(&entries), vec![ALICE_DN.to_string()]);

    serving.abort();
}

#[tokio::test]
async fn ldaps_refuses_a_certificate_it_cannot_verify() {
    // Without a trust anchor the handshake fails, and it has to fail here rather than after
    // a password has been sent into a connection nobody authenticated.
    let (url, _cert, serving) = tls_server(true).await;
    let url = url.replace("127.0.0.1", "localhost");

    let err = Client::connect(&url, Options::default())
        .await
        .expect_err("must refuse an unverifiable certificate");

    assert!(
        matches!(err, Error::Tls(_)),
        "expected a TLS refusal, got {err}"
    );

    serving.abort();
}

#[tokio::test]
async fn starttls_upgrades_a_plain_connection_and_the_search_runs_over_it() {
    let (url, cert, serving) = tls_server(false).await;
    let url = url.replace("127.0.0.1", "localhost");

    let client = Client::connect(
        &url,
        Options {
            trust: rust_rest_ldap::client::Trust::File(cert),
            ..Options::default()
        },
    )
    .await
    .expect("connect");

    // A plain request works before the upgrade: that is what makes StartTLS start.
    let (before, _) = client
        .search(search(BASE, equality("uid", "alice")))
        .await
        .expect("plain search");
    assert_eq!(dns(&before), vec![ALICE_DN.to_string()]);

    client.starttls().await.expect("starttls");

    // And the same request works after it, over the upgraded connection.
    let (after, result) = client
        .search(search(BASE, equality("uid", "alice")))
        .await
        .expect("tls search");
    assert_eq!(result.code, ResultCode::Success);
    assert_eq!(dns(&after), vec![ALICE_DN.to_string()]);

    serving.abort();
}

#[tokio::test]
async fn a_search_over_the_entry_limit_stops_rather_than_filling_memory() {
    let (url, serving) = server().await;

    let client = Client::connect(
        &url,
        Options {
            limits: rust_rest_ldap::client::Limits {
                max_entries: Some(1),
                ..Default::default()
            },
            ..Options::default()
        },
    )
    .await
    .expect("connect");

    // The fixture's subtree holds five entries; one is the limit.
    let err = client
        .search(search(BASE, present("objectClass")))
        .await
        .expect_err("must stop at the limit");

    assert!(
        matches!(err, Error::TooManyEntries { limit: 1 }),
        "expected TooManyEntries, got {err}"
    );

    serving.abort();
}

#[tokio::test]
async fn the_insecure_policy_accepts_what_no_authority_signed_and_says_so_in_its_name() {
    // The escape hatch for a lab certificate, and the reason it is called insecure: the
    // connection is encrypted and nobody's identity was checked. A client that silently
    // fell back to this after a failed verification would be worse than one that refused.
    let (url, _cert, serving) = tls_server(true).await;
    let url = url.replace("127.0.0.1", "localhost");

    let client = Client::connect(
        &url,
        Options {
            trust: rust_rest_ldap::client::Trust::Insecure,
            ..Options::default()
        },
    )
    .await
    .expect("connect");

    let (entries, _) = client
        .search(search(BASE, equality("uid", "alice")))
        .await
        .expect("search");
    assert_eq!(dns(&entries), vec![ALICE_DN.to_string()]);

    serving.abort();
}
