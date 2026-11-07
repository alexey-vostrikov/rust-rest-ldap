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
async fn a_write_onto_a_mapped_index_is_recorded_rather_than_materialised() {
    // What this rules out is the cost that made the memory ceiling a promise instead of a boundary:
    // touching one entry used to pull every posting out of the snapshot file into maps, which on a
    // million entries is 1.14 GB for one modify (ub-log §108). The change is now a record applied
    // to each answer, so its price follows the number of changes, not the size of the directory.
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

    // The first start has no snapshot to read and builds the index from the data; it writes one on
    // the way out. The second start is the one that maps it - and that is the state this test is
    // about, because a mapped index is where a write used to materialise everything.
    //
    // The rewrite threshold is set out of reach on purpose: with it in reach the write converges the
    // snapshot instead of leaving an overlay, and the test would then be measuring convergence. That
    // has its own test below.
    let config = config_with(
        &path,
        "  snapshot_delta_bytes: 1073741824\n  snapshot_rewrite_min_seconds: 0\n",
    );
    drop(
        Source::load(&config, open(&path))
            .await
            .expect("first start"),
    );
    let (source, _) = Source::load(&config, open(&path))
        .await
        .expect("second start");

    let before = source.directory().await;
    assert!(
        before.index().is_mapped(),
        "the second start must map the snapshot rather than decode it"
    );
    assert_eq!(before.index().overlay_len(), 0);
    drop(before);

    source
        .apply(&[EntryChange::Upsert {
            entry: person("carol", "20260101000000.000000Z#000002#001#000000"),
        }])
        .await
        .expect("apply");

    let after = source.directory().await;
    assert_eq!(
        after.index().overlay_len(),
        1,
        "the change is one record to apply, not a materialised index"
    );
    assert!(
        after.index().is_mapped(),
        "the write must not pull the postings into memory"
    );
    assert_eq!(
        matches_from_index(&source, "carol").await,
        Some(1),
        "an entry written after the snapshot is found through the overlay"
    );
    assert_eq!(
        matches_from_index(&source, "alice").await,
        Some(1),
        "and the one that was in the snapshot is still found"
    );
}

#[tokio::test]
async fn the_overlay_stops_growing_at_its_cap_and_the_index_materialises_once() {
    // The question the design has to answer: does the overlay grow without bound on a server that
    // is written to forever? It must not - every query pays one comparison per record, and the
    // memory follows writes rather than the directory. The cap is the answer: past it the index
    // does what it did before (pulls the postings into maps, once) and stops paying per query.
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

    // A tiny cap, so the test does not need ten thousand writes to reach it.
    let config = config_with(
        &path,
        "  snapshot_overlay_max: 2\n  snapshot_delta_bytes: 1073741824\n  snapshot_rewrite_min_seconds: 0\n",
    );
    drop(
        Source::load(&config, open(&path))
            .await
            .expect("first start"),
    );

    let (source, _) = Source::load(&config, open(&path))
        .await
        .expect("second start");
    assert!(source.directory().await.index().is_mapped(), "mapped");

    for index in 0..4 {
        source
            .apply(&[EntryChange::Upsert {
                entry: person(
                    &format!("user{index}"),
                    "20260101000000.000000Z#000002#001#000000",
                ),
            }])
            .await
            .expect("apply");
    }

    let directory = source.directory().await;
    assert!(
        directory.index().overlay_len() <= 2,
        "the overlay must not grow past its cap, found {}",
        directory.index().overlay_len()
    );
    assert!(
        !directory.index().is_mapped(),
        "past the cap the postings are in memory, which is the price of a bounded overlay"
    );
    // And every write is still findable, which is what the cap must not cost.
    for index in 0..4 {
        assert_eq!(
            matches_from_index(&source, &format!("user{index}")).await,
            Some(1),
            "user{index} must be found"
        );
    }
}

#[tokio::test]
async fn a_rewrite_converges_the_overlay_instead_of_leaving_it_in_memory() {
    // The step without which the overlay never empties: a rewrite writes the file, and the live
    // index keeps mapping the old one, so the recorded changes stay for the life of the process.
    // Convergence swaps the snapshot for a fresh one built from the file just written - one pointer,
    // so a reader holding the old view keeps it.
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

    // A threshold of one byte: the first write rewrites the snapshot, which is what a deployment
    // sees after enough changes rather than after one.
    let config = config_with(
        &path,
        "  snapshot_delta_bytes: 1\n  snapshot_rewrite_min_seconds: 0\n",
    );
    drop(
        Source::load(&config, open(&path))
            .await
            .expect("first start"),
    );

    let (source, _) = Source::load(&config, open(&path))
        .await
        .expect("second start");
    assert_eq!(source.directory().await.index().overlay_len(), 0);

    source
        .apply(&[EntryChange::Upsert {
            entry: person("carol", "20260101000000.000000Z#000002#001#000000"),
        }])
        .await
        .expect("apply");

    // The rewrite runs in the background; wait for it rather than sleeping a guessed interval.
    let converged = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let directory = source.directory().await;
            if directory.snapshot() > 0 && directory.index().overlay_len() == 0 {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the rewrite converges within the timeout");

    assert!(
        converged,
        "the overlay must empty once the snapshot covers it"
    );
    let directory = source.directory().await;
    assert!(
        directory.index().is_mapped(),
        "and the postings must be in the file again, not in maps"
    );

    // Convergence must not cost a change: everything written is still findable afterwards.
    assert_eq!(matches_from_index(&source, "carol").await, Some(1));
    assert_eq!(matches_from_index(&source, "alice").await, Some(1));
}

#[tokio::test]
async fn a_rewrite_waits_for_its_interval_however_much_has_changed() {
    // The defect this pins: a rewrite costs a pass over the whole index, so a byte threshold alone
    // lets a busy server spend its time copying. Measured on a growing directory - thirty-one
    // thousand adds caused fifty-eight rewrites and the write rate halved. The floor is what turns
    // "much has changed" into "much has changed and we can afford a copy".
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

    // Threshold of one byte, floor of an hour: everything says "rewrite", the floor says "not yet".
    let config = config_with(
        &path,
        "  snapshot_delta_bytes: 1\n  snapshot_rewrite_min_seconds: 3600\n",
    );
    drop(
        Source::load(&config, open(&path))
            .await
            .expect("first start"),
    );
    let (source, _) = Source::load(&config, open(&path))
        .await
        .expect("second start");

    let before = std::fs::metadata(format!("{}.index", path.display()))
        .expect("the snapshot file")
        .modified()
        .expect("a modification time");

    source
        .apply(&[EntryChange::Upsert {
            entry: person("carol", "20260101000000.000000Z#000002#001#000000"),
        }])
        .await
        .expect("apply");

    // Long enough for the background task to have run if it were going to.
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    let after = std::fs::metadata(format!("{}.index", path.display()))
        .expect("the snapshot file")
        .modified()
        .expect("a modification time");
    assert_eq!(before, after, "the floor must hold the rewrite back");

    // And the change is not lost while it waits: it is an overlay record and the index answers.
    assert_eq!(matches_from_index(&source, "carol").await, Some(1));
    let directory = source.directory().await;
    assert_eq!(directory.index().overlay_len(), 1);
    assert!(directory.index().is_mapped());
}

#[tokio::test]
async fn convergence_covers_writes_that_happened_during_the_rewrite() {
    // The defect this pins: convergence refused whenever the store had moved, and on a server taking
    // writes the store always has. Measured over thirty-one thousand adds: fifty-eight rewrites,
    // zero convergences, so the overlay path never engaged and every write went into the maps.
    //
    // Here the rewrite and a write race on purpose: the write lands after the file was written and
    // before convergence runs, which is the ordinary case on a busy server.
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

    let config = config_with(
        &path,
        "  snapshot_delta_bytes: 1\n  snapshot_rewrite_min_seconds: 0\n",
    );
    drop(
        Source::load(&config, open(&path))
            .await
            .expect("first start"),
    );
    let (source, _) = Source::load(&config, open(&path))
        .await
        .expect("second start");

    // One write triggers the rewrite; the ones after it land while the snapshot is being written.
    source
        .apply(&[EntryChange::Upsert {
            entry: person("bob", "20260101000000.000000Z#000002#001#000000"),
        }])
        .await
        .expect("trigger");
    for index in 0..20 {
        source
            .apply(&[EntryChange::Upsert {
                entry: person(
                    &format!("race{index}"),
                    &format!("20260101000000.00000{index}#000003#001#000000"),
                ),
            }])
            .await
            .expect("race");
    }

    // Convergence has to produce a snapshot that covers the racing writes. The overlay is *not*
    // expected to be empty afterwards - the racing writes are not in the file, so they stay as
    // overlay records; what must hold is that the live index moved to the new file and lost nothing.
    let before = source.directory().await.snapshot();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    loop {
        if source.directory().await.snapshot() > before {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "convergence never advanced the live snapshot"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let directory = source.directory().await;
    assert!(
        directory.index().is_mapped(),
        "convergence must leave the index reading the file, not materialised"
    );
    drop(directory);

    // Nothing may be lost on the way: every add, before and during the rewrite, is still found.
    for name in ["alice", "bob"] {
        assert_eq!(
            matches_from_index(&source, name).await,
            Some(1),
            "{name} is lost"
        );
    }
    for index in 0..20 {
        assert_eq!(
            matches_from_index(&source, &format!("race{index}")).await,
            Some(1),
            "race{index} is lost by convergence"
        );
    }
}

#[tokio::test]
async fn a_replaced_value_leaves_the_index_it_used_to_be_in() {
    // The half of the overlay that is easy to get wrong: adding where the new value matches is
    // obvious, removing where the old one matched is not - the postings are in a read-only file,
    // and a record that only adds would answer about a value the entry no longer holds.
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
    assert_eq!(matches_from_index(&source, "alice").await, Some(1));

    // The same entry, with its uid changed: `person` puts the name in the DN too, so the DN stays
    // and only the indexed attribute moves - which is exactly the case where the old postings are
    // wrong and the new ones do not exist yet.
    let renamed = Entry::new(
        format!("cn=alice,ou=users,{BASE}"),
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "inetOrgPerson".to_string()],
            ))
            .push(Attribute::single("cn", "alice"))
            .push(Attribute::single("sn", "Surname"))
            .push(Attribute::single("uid", "bob"))
            .push(
                Attribute::single("entryCSN", "20260101000000.000000Z#000002#001#000000")
                    .operational(),
            ),
    );
    source
        .apply(&[EntryChange::Upsert { entry: renamed }])
        .await
        .expect("apply");

    assert_eq!(
        matches_from_index(&source, "alice").await,
        Some(0),
        "the value the entry no longer holds must stop matching"
    );
    assert_eq!(
        matches_from_index(&source, "bob").await,
        Some(1),
        "and the value it holds now must match"
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

    let config = config_with(
        &path,
        "  snapshot_delta_bytes: 1\n  snapshot_rewrite_min_seconds: 0\n",
    );

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

/// The snapshot is a file beside the store, not a row in it.
///
/// It was a row once, and writing 2.16 GB of postings as one redb value is what made a
/// three-million-entry start sit in `D` for a quarter of an hour. The file is the fix, so the file
/// is what this checks - and the store must still name it, or a start would trust bytes whose
/// extent is a guess.
#[tokio::test]
async fn the_snapshot_is_a_file_beside_the_store() {
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

    drop(load(&path).await);

    let snapshot = dir.path().join("d.redb.index");
    assert!(
        snapshot.exists(),
        "the snapshot is written next to the store, under the store's own name"
    );
    assert!(
        std::fs::metadata(&snapshot).expect("metadata").len() > 0,
        "and it holds the postings, not an empty file"
    );

    // No temporary left behind: a crash may leave one, but a clean run must not.
    let leftovers: Vec<String> = std::fs::read_dir(dir.path())
        .expect("read_dir")
        .filter_map(|item| item.ok())
        .map(|item| item.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
}

/// A snapshot file with no counter in the store is ignored, not trusted.
///
/// The two are written in that order - file, then counter - so a crash between them leaves exactly
/// this state. Trusting the file would mean replaying deltas onto a snapshot whose extent nobody
/// recorded, which is an index that answers about entries it never had.
#[tokio::test]
async fn a_snapshot_file_without_a_counter_is_not_trusted() {
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
    let backend = open(&path);
    backend
        .save_index(b"not a snapshot anyone recorded", 1)
        .expect("save");
    backend.clear_index().expect("clear");
    drop(backend);

    // A file that looks like a snapshot, with nothing in the store to say what it covers.
    std::fs::write(dir.path().join("d.redb.index"), b"stray bytes").expect("stray");

    let backend = open(&path);
    assert!(
        backend.load_index().expect("load").is_none(),
        "a file whose counter is absent is not a snapshot this start may use"
    );
    drop(backend);

    let source = load(&path).await;
    assert_eq!(
        matches_from_index(&source, "alice").await,
        Some(1),
        "and the index is built from the store instead, which answers"
    );
}

/// Clearing forgets both halves: a file left behind would be adopted by the next start if ever a
/// counter were written again.
#[tokio::test]
async fn clearing_removes_the_file_and_the_counter() {
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
    drop(load(&path).await);
    assert!(
        dir.path().join("d.redb.index").exists(),
        "a snapshot exists"
    );

    let backend = open(&path);
    backend.clear_index().expect("clear");
    assert!(
        backend.load_index().expect("load").is_none(),
        "after clearing, nothing is offered"
    );
    assert!(
        !dir.path().join("d.redb.index").exists(),
        "and the file is gone with the counter"
    );
}
