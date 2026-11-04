//! Two servers, two processes, one directory.
//!
//! These are the only tests in the repository that start the real binary as a child process, and
//! they do it for a reason: `server_id` lives in a process-global, so two nodes with different ids
//! cannot coexist in one test process. A test that faked one of them would prove nothing about the
//! thing being tested - that two independent servers converge.
//!
//! What they establish:
//!
//! - an entry written on one node reaches the other without being asked for again;
//! - a deletion reaches the other too, which a poll cannot do: a deleted entry leaves nothing in
//!   the directory to compare against, so only a pushed change can say it is gone;
//! - an entry the second node already has is not rewritten, so replication settles instead of
//!   running for ever.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rasn::types::SetOf;
use rasn_ldap::{
    AddRequest, Attribute as PartialAttribute, AttributeDescription, AttributeValue, DelRequest,
    LdapDn, ProtocolOp,
};
use rust_rest_ldap::client::{Client, Options};

const BASE: &str = "dc=example,dc=com";

/// A port nobody is listening on right now.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
    listener.local_addr().expect("an address").port()
}

fn config(port: u16, server_id: u16, peer: Option<u16>, path: &Path) -> String {
    let peers = match peer {
        None => String::new(),
        Some(peer_port) => format!(
            "peers:\n  - url: ldap://127.0.0.1:{peer_port}\n    server_id: {}\n",
            3 - server_id
        ),
    };

    format!(
        "base_dn: {BASE}\n\
         listen_addr: 127.0.0.1:{port}\n\
         backend: redb\n\
         backends:\n  redb:\n    path: {}\n\
         schema:\n  mode: off\n\
         server_id: {server_id}\n\
         {peers}\
         access:\n  - subject: anonymous\n    attributes: [\"*\"]\n    rights: [read, search, compare, write]\n",
        path.display()
    )
}

struct Node {
    child: std::process::Child,
    _dir: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts one node and waits until it accepts connections.
fn start(port: u16, server_id: u16, peer: Option<u16>) -> Node {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dir.redb");
    let config_path = dir.path().join("config.yaml");

    let mut file = std::fs::File::create(&config_path).expect("config file");
    file.write_all(config(port, server_id, peer, &path).as_bytes())
        .expect("write config");

    let binary: PathBuf = env!("CARGO_BIN_EXE_rust-rest-ldap").into();
    let mut child = std::process::Command::new(binary)
        .arg("-c")
        .arg(&config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start the server");

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Node { child, _dir: dir };
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // The child is reaped before the panic: a process left running would hold its port and its
    // store file, and the next run would fail for a reason that belongs to this one.
    let _ = child.kill();
    let _ = child.wait();
    panic!("the server on port {port} never started listening");
}

/// A search for one entry, the way a client builds it.
fn query(base: &str, filter: &str, attributes: &[&str]) -> rasn_ldap::SearchRequest {
    rasn_ldap::SearchRequest::new(
        LdapDn::from(base),
        rasn_ldap::SearchRequestScope::BaseObject,
        rasn_ldap::SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        rust_rest_ldap::ldap::filter_parse::parse(filter).expect("filter"),
        attributes
            .iter()
            .map(|name| rasn_ldap::LdapString::from(*name))
            .collect(),
    )
}

fn url(port: u16) -> String {
    format!("ldap://127.0.0.1:{port}")
}

fn person(cn: &str) -> AddRequest {
    let dn = format!("cn={cn},ou=users,{BASE}");
    AddRequest {
        entry: LdapDn::from(dn.as_str()),
        attributes: vec![
            PartialAttribute::new(
                AttributeDescription::from("objectClass"),
                SetOf::from_vec(vec![
                    AttributeValue::from(b"top".to_vec()),
                    AttributeValue::from(b"person".to_vec()),
                ]),
            ),
            PartialAttribute::new(
                AttributeDescription::from("cn"),
                SetOf::from_vec(vec![AttributeValue::from(cn.as_bytes().to_vec())]),
            ),
            PartialAttribute::new(
                AttributeDescription::from("sn"),
                SetOf::from_vec(vec![AttributeValue::from(b"Person".to_vec())]),
            ),
        ],
    }
}

async fn add(port: u16, cn: &str) {
    let client = Client::connect(&url(port), Options::default())
        .await
        .expect("connect");
    client
        .request(ProtocolOp::AddRequest(person(cn)), "add response")
        .await
        .expect("add");
}

async fn delete(port: u16, cn: &str) {
    let client = Client::connect(&url(port), Options::default())
        .await
        .expect("connect");
    let dn = format!("cn={cn},ou=users,{BASE}");
    client
        .request(
            ProtocolOp::DelRequest(DelRequest(LdapDn::from(dn.as_str()))),
            "delete response",
        )
        .await
        .expect("delete");
}

/// Whether the node holds the entry, asked the way a client would.
async fn holds(port: u16, cn: &str) -> bool {
    let client = match Client::connect(&url(port), Options::default()).await {
        Ok(client) => client,
        Err(_) => return false,
    };

    let base = format!("cn={cn},ou=users,{BASE}");
    let filter = format!("(cn={cn})");

    match client.search(query(&base, &filter, &["cn"])).await {
        // The client turns `noSuchObject` into an error, which is a different answer from "found
        // nothing" and has to be read as one.
        Ok((messages, _)) => !messages.is_empty(),
        Err(_) => false,
    }
}

/// Waits until `condition` holds, or fails with what was being waited for.
async fn eventually<F, Fut>(what: &str, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if condition().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_entry_written_on_one_node_appears_on_the_other() {
    let (first, second) = (free_port(), free_port());
    let a = start(first, 1, None);
    let b = start(second, 2, Some(first));

    add(first, "alice").await;

    eventually("alice to reach the second node", || holds(second, "alice")).await;

    // The entry keeps the CSN of the node that wrote it: the second node applied the change, it
    // did not make one. A node that stamped what it received would replicate for ever.
    let client = Client::connect(&url(second), Options::default())
        .await
        .expect("connect");
    let base = format!("cn=alice,ou=users,{BASE}");
    let (messages, _) = client
        .search(query(&base, "(cn=alice)", &["entryCSN"]))
        .await
        .expect("search");
    let csn = rust_rest_ldap::client::entry_of(&messages[0])
        .expect("an entry")
        .attributes()
        .get("entryCSN")
        .and_then(|attribute| attribute.values.first())
        .cloned()
        .expect("a csn");

    let parsed = rust_rest_ldap::replication::Csn::parse(&csn).expect("a parseable csn");
    assert_eq!(
        parsed.server, 1,
        "the change belongs to the node that made it, not to the one that received it"
    );

    drop((a, b));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deletion_reaches_the_other_node_too() {
    // The half a refresh cannot express. An entry that is gone leaves nothing behind, so a node
    // that only polls would keep it for ever - and in a full-mesh multi-master it cannot use "you
    // did not name it" either, because another node may have just created it.
    let (first, second) = (free_port(), free_port());
    let a = start(first, 1, None);
    let b = start(second, 2, Some(first));

    add(first, "bob").await;
    eventually("bob to reach the second node", || holds(second, "bob")).await;

    delete(first, "bob").await;

    eventually("the deletion to reach the second node", || async {
        !holds(second, "bob").await
    })
    .await;

    drop((a, b));
}
