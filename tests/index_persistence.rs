//! The stored index: a start reads it instead of building it, and stops trusting it when the
//! data moves.
//!
//! Building the index over three million entries took six minutes, and an operator who waits six
//! minutes for every restart turns the index off - so what is tested here is not "the snapshot
//! exists" but the two claims that make it usable: a restart over unchanged data does not rebuild
//! it, and a restart after a change never reuses the one built before it.

use std::sync::Arc;

use rust_rest_ldap::backend::{Backend, EntryChange};
use rust_rest_ldap::config::{Args, Config};
use rust_rest_ldap::index::Query;
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::reload::Source;

const BASE: &str = "dc=example,dc=com";

fn person(cn: &str, stamp: &str) -> Entry {
    Entry::new(
        format!("cn={cn},ou=users,{BASE}"),
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "inetOrgPerson".to_string()],
            ))
            .push(Attribute::single("cn", cn))
            .push(Attribute::single("sn", "Surname"))
            .push(Attribute::single("uid", cn))
            .push(Attribute::single("entryCSN", stamp).operational()),
    )
}

fn config(path: &std::path::Path) -> Config {
    let text = format!(
        "\
base_dn: {BASE}
indexes:
  attributes:
    cn: [eq, sub]
    uid: [eq]
backends:
  redb:
    path: {}
",
        path.display()
    );
    rust_rest_ldap::config::resolve(Args::default(), Some(&text), |_| None).expect("config")
}

fn open(path: &std::path::Path) -> Backend {
    Backend::from_config(
        "redb",
        Some(&serde_json::json!({"path": path.display().to_string()})),
    )
    .expect("backend")
}

async fn load(path: &std::path::Path) -> Arc<Source> {
    let config = config(path);
    let backend = open(path);
    let (source, _) = Source::load(&config, backend).await.expect("load");
    source
}

/// How many entries the index reports for `uid=<name>`.
///
/// A count rather than the bitmap itself: the id is a position in the canonical order, and
/// asserting a particular number would test the order of the fixture rather than the index.
async fn matches_from_index(source: &Arc<Source>, uid: &str) -> Option<u64> {
    source
        .directory()
        .await
        .index()
        .candidates(&Query::Equality {
            attribute: "uid".into(),
            value: uid.into(),
        })
        .map(|bitmap| bitmap.len())
}

/// Redb holds the file lock while a store is open, and a source owns one - so reading the stored
/// snapshot means letting the source go, which is what a restart does anyway.
fn stored_snapshot(path: &std::path::Path) -> Vec<u8> {
    open(path)
        .load_index()
        .expect("read")
        .expect("a snapshot")
        .0
}

#[tokio::test]
async fn a_restart_over_unchanged_data_reuses_the_stored_index() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("d.redb");

    {
        let backend = open(&path);
        backend
            .apply(&[
                EntryChange::Upsert {
                    entry: person("alice", "20260101000000.000000Z#000001#001#000000"),
                },
                EntryChange::Upsert {
                    entry: person("bob", "20260101000000.000000Z#000002#001#000000"),
                },
            ])
            .await
            .expect("seed");
    }

    let first = load(&path).await;
    assert_eq!(
        matches_from_index(&first, "alice").await,
        Some(1),
        "the first start builds an index that answers"
    );
    drop(first);

    let built = stored_snapshot(&path);
    assert!(
        !built.is_empty(),
        "the first start has to keep what it built, or the next one rebuilds it"
    );

    // A second start on the same data reads the snapshot instead of rebuilding. Equal bytes are
    // the observable consequence: a rebuild would write a new one, and the fingerprint it carries
    // is recomputed from the data it just read.
    let second = load(&path).await;
    assert_eq!(
        matches_from_index(&second, "alice").await,
        Some(1),
        "the index that was read answers what the built one answered"
    );
    drop(second);

    assert_eq!(
        built,
        stored_snapshot(&path),
        "a start over unchanged data neither rebuilds nor rewrites the snapshot"
    );
}

#[tokio::test]
async fn a_change_between_starts_is_replayed_rather_than_rebuilt() {
    // Before the deltas existed this test asserted the opposite: a write invalidated the
    // snapshot, and the next start rebuilt the index - a minute of work for every restart on a
    // node that is written to. Now the store records what each change set did to the index, and
    // the next start replays it.
    //
    // What has to hold is not "the bytes changed" but "the index in force answers about the data
    // in force": an index that missed the write would not find the new entry, and an index that
    // kept the deleted one would answer about an entry that is gone.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("d.redb");

    {
        let backend = open(&path);
        backend
            .apply(&[EntryChange::Upsert {
                entry: person("alice", "20260101000000.000000Z#000001#001#000000"),
            }])
            .await
            .expect("seed");
    }

    let source = load(&path).await;
    source
        .apply(&[EntryChange::Upsert {
            entry: person("carol", "20260101000000.000000Z#000002#001#000000"),
        }])
        .await
        .expect("apply");
    drop(source);

    let before_restart = stored_snapshot(&path);

    let after = load(&path).await;
    assert_eq!(
        matches_from_index(&after, "carol").await,
        Some(1),
        "the index in force knows the entry that was written after the snapshot was made"
    );
    assert_eq!(
        matches_from_index(&after, "alice").await,
        Some(1),
        "and still knows the one from before it"
    );
    drop(after);

    assert_eq!(
        before_restart,
        stored_snapshot(&path),
        "the start replayed the stored deltas instead of rebuilding, so the snapshot is untouched"
    );
}

#[tokio::test]
async fn a_deletion_between_starts_is_replayed_too() {
    // The case a delta gets wrong most easily: a removal has no entry to add, only postings to
    // take away. Left unreplayed, the index would answer about an entry that is gone.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("d.redb");

    {
        let backend = open(&path);
        backend
            .apply(&[
                EntryChange::Upsert {
                    entry: person("alice", "20260101000000.000000Z#000001#001#000000"),
                },
                EntryChange::Upsert {
                    entry: person("bob", "20260101000000.000000Z#000002#001#000000"),
                },
            ])
            .await
            .expect("seed");
    }

    let source = load(&path).await;
    source
        .apply(&[EntryChange::Delete {
            dn: format!("cn=bob,ou=users,{BASE}"),
            kind: None,
        }])
        .await
        .expect("delete");
    drop(source);

    let after = load(&path).await;
    assert_eq!(
        matches_from_index(&after, "bob").await,
        Some(0),
        "the replayed index does not answer about an entry that was deleted"
    );
    assert_eq!(
        matches_from_index(&after, "alice").await,
        Some(1),
        "and keeps the one that stayed"
    );
}
