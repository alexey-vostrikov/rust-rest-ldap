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
    config_with(path, "")
}

/// The same configuration with extra lines inside `indexes:`, for the tests that set the rewrite
/// threshold.
fn config_with(path: &std::path::Path, indexes_extra: &str) -> Config {
    let text = format!(
        "\
base_dn: {BASE}
indexes:
  attributes:
    cn: [eq, sub]
    uid: [eq]
{indexes_extra}backends:
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

#[tokio::test]
async fn the_snapshot_is_rewritten_once_the_recorded_changes_outgrow_it() {
    // The deltas exist so a restart does not rebuild the index, and they are worth their space
    // only while replaying them costs less than the snapshot they save. A node written to and
    // never restarted otherwise accumulates them in a table nobody reads.
    //
    // The threshold here is one byte, so a single change is past it: what is tested is that the
    // rewrite happens at all, not where exactly the line is drawn.
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

    // A first start writes the snapshot the rewrite is measured against.
    drop(load(&path).await);

    let config = config_with(&path, "  snapshot_delta_bytes: 1\n");

    // Read before a source exists: the source holds the store open, and a second opener is
    // refused rather than served.
    let built = stored_snapshot(&path);

    let backend = open(&path);
    let (source, _) = Source::load(&config, backend).await.expect("load");

    source
        .apply(&[EntryChange::Upsert {
            entry: person("carol", "20260101000000.000000Z#000002#001#000000"),
        }])
        .await
        .expect("apply");

    // The rewrite is deliberately off the client's path, and the task holds the store open while
    // it runs - so the source has to go before the store can be read back at all.
    drop(source);
    let rewritten = wait_for_snapshot_change(&path, &built).await;
    assert!(
        rewritten,
        "the snapshot is rewritten once the recorded changes are past the threshold"
    );

    // What the rewrite bought: no deltas left to replay, and a snapshot that still answers for
    // the entry which only ever arrived through one.
    let deltas = open(&path).index_delta_bytes(0).expect("deltas");
    assert_eq!(deltas, 0, "the changes the new snapshot covers are dropped");

    let after = load(&path).await;
    assert_eq!(
        matches_from_index(&after, "carol").await,
        Some(1),
        "the rewritten snapshot includes the entry that arrived after the old one"
    );
    assert_eq!(
        matches_from_index(&after, "alice").await,
        Some(1),
        "and the one from before it"
    );
}

/// Waits for the background rewrite, which runs on a blocking thread after the write is answered.
///
/// The store is opened without the panic `open` uses, because the rewrite task holds it open
/// while it runs and that is the normal state this function is waiting out, not a failure.
async fn wait_for_snapshot_change(path: &std::path::Path, built: &[u8]) -> bool {
    for _ in 0..600 {
        let opened = Backend::from_config(
            "redb",
            Some(&serde_json::json!({"path": path.display().to_string()})),
        );
        if let Ok(backend) = opened
            && let Ok(Some((bytes, _))) = backend.load_index()
            && bytes != built
        {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    false
}
