//! A subtree this server does not hold: the client is told where it lives, and gets an answer.
//!
//! The acceptance for this is a client's experience, not an internal one: a client asks this
//! server for a DN outside its tree, is referred to the server that holds it, asks there, and
//! ends up with the entry. So the test runs two servers and a real client, exactly as an
//! operator would.

use std::time::Duration;

use rasn::types::OctetString;
use rasn_ldap::{
    Control, LdapDn, LdapOid, LdapString, ResultCode, SearchRequest, SearchRequestScope,
};
use rust_rest_ldap::client::{Client, Options};
use rust_rest_ldap::config::Config;
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::security::Security;

const LOCAL_BASE: &str = "dc=example,dc=com";
const REMOTE_BASE: &str = "dc=remote,dc=test";

fn person(dn: &str, cn: &str) -> Entry {
    Entry::new(
        dn,
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "person".to_string()],
            ))
            .push(Attribute::single("cn", cn))
            .push(Attribute::single("sn", "Person")),
    )
}

/// A server holding the entries it is given, with the security policy it is given.
async fn serve(
    base: &str,
    entries: Vec<Entry>,
    referrals: Vec<(&str, &str)>,
) -> (String, tokio::sync::watch::Sender<bool>) {
    let _ = Directory::from_entries(base, "users", "groups", entries.clone());

    let config = Config {
        backend: "null".to_string(),
        base_dn: base.to_string(),
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
        server_id: 0,
        referrals: rust_rest_ldap::referral::Referrals::new(
            referrals
                .iter()
                .map(|(dn, url)| rust_rest_ldap::referral::Referral {
                    dn: dn.to_string(),
                    url: url.to_string(),
                })
                .collect(),
        )
        .expect("referrals"),
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

    // The null backend stores nothing, so a redb file in a temporary directory is what a test
    // can seed and serve from.
    // One store per server: two servers holding the same number of entries used to derive the
    // same file name and the second refused to open it.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let database =
        std::env::temp_dir().join(format!("referral-{}-{serial}.redb", std::process::id()));
    let _ = std::fs::remove_file(&database);
    let backend = rust_rest_ldap::backend::Backend::from_config(
        "redb",
        Some(&serde_json::json!({ "path": database.display().to_string() })),
    )
    .expect("backend");
    backend
        .apply(
            &entries
                .iter()
                .cloned()
                .map(|entry| rust_rest_ldap::backend::EntryChange::Upsert { entry })
                .collect::<Vec<_>>(),
        )
        .await
        .expect("seed");

    let (source, _directory) = rust_rest_ldap::reload::Source::load(&config, backend)
        .await
        .expect("source");

    let security = Security::from_config(&config)
        .with_schema(source.shared_schema())
        .with_password_upgrade(false);
    assert_eq!(
        security.referrals.len(),
        referrals.len(),
        "the policy the server runs with must carry the referrals the test configured"
    );
    let live = rust_rest_ldap::security::live(config, security);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("addr");
    let (stop, shutdown) = tokio::sync::watch::channel(false);

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

    (format!("ldap://{addr}"), stop)
}

/// The result code a failed search reports.
///
/// A client is right to turn a `noSuchObject` answer into an error - scripts check the code -
/// so the tests that expect no answer read the error rather than the messages.
async fn expect_refusal(
    client: &Client,
    request: SearchRequest,
    controls: Option<Vec<Control>>,
) -> ResultCode {
    let result = match controls {
        Some(controls) => client.search_with(request, controls).await,
        None => client.search(request).await,
    };

    match result {
        Ok((messages, _)) => result_code(&messages).expect("a done message"),
        Err(rust_rest_ldap::client::Error::Server { code, .. }) => code,
        Err(other) => panic!("unexpected failure: {other}"),
    }
}

fn search(base: &str, filter: &str) -> SearchRequest {
    SearchRequest::new(
        LdapDn::from(base),
        SearchRequestScope::WholeSubtree,
        rasn_ldap::SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        rust_rest_ldap::ldap::filter_parse::parse(filter).expect("filter"),
        vec![LdapString::from("cn")],
    )
}

fn manage_dsa_it() -> Control {
    Control::new(
        LdapOid::from(b"2.16.840.1.113730.3.4.2".as_slice()),
        true,
        Some(OctetString::from_static(b"")),
    )
}

/// The DNs of the entries in a search answer.
fn dns(messages: &[rasn_ldap::LdapMessage]) -> Vec<String> {
    messages
        .iter()
        .filter_map(|message| match &message.protocol_op {
            rasn_ldap::ProtocolOp::SearchResEntry(entry) => Some(entry.object_name.0.to_string()),
            _ => None,
        })
        .collect()
}

/// The URIs of the references in a search answer.
fn references(messages: &[rasn_ldap::LdapMessage]) -> Vec<String> {
    messages
        .iter()
        .filter_map(|message| match &message.protocol_op {
            rasn_ldap::ProtocolOp::SearchResRef(reference) => Some(
                reference
                    .0
                    .iter()
                    .map(|uri| uri.0.to_string())
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect()
}

fn result_code(messages: &[rasn_ldap::LdapMessage]) -> Option<ResultCode> {
    messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            rasn_ldap::ProtocolOp::SearchResDone(done) => Some(done.0.result_code),
            _ => None,
        })
}

#[tokio::test]
async fn a_base_this_server_does_not_hold_is_referred_to_the_one_that_does() {
    // The server that holds the remote subtree.
    let (remote_url, _remote_stop) = serve(
        REMOTE_BASE,
        vec![
            // The intermediate unit is an entry of its own: a search whose base is not in the
            // directory is `noSuchObject` even on the server that holds what is below it.
            Entry::new(
                "ou=people,dc=remote,dc=test",
                Attributes::new()
                    .push(Attribute::single("objectClass", "organizationalUnit"))
                    .push(Attribute::single("ou", "people")),
            ),
            person("cn=alice,ou=people,dc=remote,dc=test", "alice"),
        ],
        Vec::new(),
    )
    .await;

    // The server the client talks to first: it holds its own tree and knows where the other is.
    let (local_url, _local_stop) = serve(
        LOCAL_BASE,
        vec![person("cn=bob,ou=users,dc=example,dc=com", "bob")],
        vec![(REMOTE_BASE, &remote_url)],
    )
    .await;

    let client = Client::connect(&local_url, Options::default())
        .await
        .expect("connect");

    let messages = client
        .search(search("ou=people,dc=remote,dc=test", "(objectClass=*)"))
        .await
        .expect("search")
        .0;

    assert!(
        dns(&messages).is_empty(),
        "this server holds none of that subtree, so it returns no entries of its own"
    );
    assert_eq!(
        references(&messages),
        vec![remote_url.clone()],
        "the client is told exactly where the subtree lives"
    );
    assert_eq!(
        result_code(&messages),
        Some(ResultCode::Success),
        "RFC 4511 §4.5.3: a referral is not an error, it is an answer"
    );

    // And the client following it gets the entry - which is what the whole thing is for.
    let remote = Client::connect(&remote_url, Options::default())
        .await
        .expect("connect to the referred server");
    let found = remote
        .search(search("ou=people,dc=remote,dc=test", "(objectClass=*)"))
        .await
        .expect("search")
        .0;

    // The base itself and the entry below it: a subtree search from the unit returns both,
    // which is what any client asking that question expects.
    assert_eq!(
        dns(&found),
        vec![
            "cn=alice,ou=people,dc=remote,dc=test".to_string(),
            "ou=people,dc=remote,dc=test".to_string(),
        ],
        "the referred server answers with the subtree it holds"
    );
}

#[tokio::test]
async fn a_base_nobody_covers_is_still_no_such_object() {
    // A referral must not turn every wrong base into a redirect: a typo has to stay a typo.
    let (local_url, _stop) = serve(
        LOCAL_BASE,
        vec![person("cn=bob,ou=users,dc=example,dc=com", "bob")],
        vec![(REMOTE_BASE, "ldap://remote.example/dc=remote,dc=test")],
    )
    .await;

    let client = Client::connect(&local_url, Options::default())
        .await
        .expect("connect");
    let code = expect_refusal(
        &client,
        search("ou=typo,dc=example,dc=com", "(objectClass=*)"),
        None,
    )
    .await;

    assert_eq!(
        code,
        ResultCode::NoSuchObject,
        "a base nobody covers stays a wrong base"
    );
}

#[tokio::test]
async fn managed_sa_it_asks_for_the_answer_here_and_gets_no_redirect() {
    // RFC 3296: the control says "treat referral objects as ordinary entries". This server's
    // referrals are configured rather than stored, so the part of that which applies is the
    // client's request not to be redirected - and, just as important, a critical control this
    // server recognises must not be refused as an unknown extension.
    let (local_url, _stop) = serve(
        LOCAL_BASE,
        vec![person("cn=bob,ou=users,dc=example,dc=com", "bob")],
        vec![(REMOTE_BASE, "ldap://remote.example/dc=remote,dc=test")],
    )
    .await;

    let client = Client::connect(&local_url, Options::default())
        .await
        .expect("connect");
    let code = expect_refusal(
        &client,
        search("ou=people,dc=remote,dc=test", "(objectClass=*)"),
        Some(vec![manage_dsa_it()]),
    )
    .await;

    assert_eq!(
        code,
        ResultCode::NoSuchObject,
        "the client asked not to be redirected, and this server holds nothing there - so it says \
         so instead of sending it elsewhere"
    );
}

#[tokio::test]
async fn the_local_tree_is_unaffected_by_a_referral_covering_a_broader_dn() {
    // A referral for `dc=com` - a real thing to configure in a wide deployment - must not
    // swallow the subtree this server actually holds.
    let (local_url, _stop) = serve(
        LOCAL_BASE,
        vec![person("cn=bob,ou=users,dc=example,dc=com", "bob")],
        vec![("dc=other,dc=test", "ldap://other.example/dc=other,dc=test")],
    )
    .await;

    let client = Client::connect(&local_url, Options::default())
        .await
        .expect("connect");
    let messages = client
        .search(search(LOCAL_BASE, "(objectClass=*)"))
        .await
        .expect("search")
        .0;

    assert!(
        references(&messages).is_empty(),
        "the local tree is answered here, not referred"
    );
    assert_eq!(result_code(&messages), Some(ResultCode::Success));
    assert!(
        dns(&messages)
            .iter()
            .any(|dn| dn == "cn=bob,ou=users,dc=example,dc=com"),
        "the local entry is in the answer: {:?}",
        dns(&messages)
    );
}
