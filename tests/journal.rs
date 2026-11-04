//! The change journal: what happened, in order, and what a replica can ask of it.
//!
//! The journal exists so that "what changed since" has an answer that is not "read the whole
//! store". Each record carries the `entryCSN` of the change, which is fixed width - so the keys
//! sort chronologically and a range scan answers the question directly.
//!
//! Two properties the tests here are about, and one that is deliberately absent:
//!
//! - a change and its record are written in **one transaction**, so neither exists without the
//!   other;
//! - a deletion leaves a **tombstone**: a record with a CSN and no entry. Without it, a node that
//!   was offline re-sends its copy of an entry somebody else deleted and the entry comes back;
//! - there is no history of an attribute's previous values. The journal says what happened, not
//!   what it was before - undoing a change is not what a replica needs, and storing every old
//!   value would make the journal the size of the directory's whole past.

use rust_rest_ldap::backend::redb_store::{ChangeKind, ChangeRecord};
use rust_rest_ldap::backend::{Backend, EntryChange};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};

fn store(dir: &std::path::Path) -> Backend {
    Backend::from_config(
        "redb",
        Some(&serde_json::json!({ "path": dir.join("d.redb").display().to_string() })),
    )
    .expect("backend")
}

/// An entry as a client would write it: with the operational stamps the protocol layer adds.
fn person(cn: &str, sn: &str) -> Entry {
    let entry = Entry::new(
        format!("cn={cn},ou=users,dc=example,dc=com"),
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "person".to_string()],
            ))
            .push(Attribute::single("cn", cn))
            .push(Attribute::single("sn", sn)),
    );

    rust_rest_ldap::operational::stamp_write(
        &entry,
        "cn=admin,dc=example,dc=com",
        SystemTime::now(),
    )
}

use std::time::SystemTime;

#[tokio::test]
async fn a_write_leaves_one_record_saying_what_it_was() {
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = store(dir.path());

    backend
        .apply(&[EntryChange::Upsert {
            entry: person("alice", "A"),
        }])
        .await
        .expect("write");

    let records = backend.journal_since(None).expect("journal");
    assert_eq!(records.len(), 1, "one write, one record");
    assert_eq!(records[0].kind, ChangeKind::Add);
    assert_eq!(records[0].dn, "cn=alice,ou=users,dc=example,dc=com");
    assert!(
        records[0].entry.is_some(),
        "an addition carries the entry, or a replica cannot apply it"
    );
    assert!(
        !records[0].uuid.is_empty(),
        "the identity a replica keys on must be there"
    );
}

#[tokio::test]
async fn writing_the_same_dn_again_is_a_modify_and_not_a_second_add() {
    // The distinction the store makes itself, in the same transaction: asking the directory in
    // memory would be a second source of truth, and the two disagree exactly when a reload has
    // not happened yet.
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = store(dir.path());

    backend
        .apply(&[EntryChange::Upsert {
            entry: person("alice", "A"),
        }])
        .await
        .expect("first");
    backend
        .apply(&[EntryChange::Upsert {
            entry: person("alice", "B"),
        }])
        .await
        .expect("second");

    let kinds: Vec<ChangeKind> = backend
        .journal_since(None)
        .expect("journal")
        .into_iter()
        .map(|record| record.kind)
        .collect();

    assert_eq!(kinds, vec![ChangeKind::Add, ChangeKind::Modify]);
}

#[tokio::test]
async fn a_deletion_leaves_a_tombstone_with_no_entry() {
    // Without the tombstone a node that was offline re-sends its copy and the entry returns;
    // the record is what tells it the entry is gone rather than missing.
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = store(dir.path());

    backend
        .apply(&[EntryChange::Upsert {
            entry: person("alice", "A"),
        }])
        .await
        .expect("write");
    backend
        .apply(&[EntryChange::Delete {
            dn: "cn=alice,ou=users,dc=example,dc=com".to_string(),
            kind: None,
        }])
        .await
        .expect("delete");

    let records = backend.journal_since(None).expect("journal");
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].kind, ChangeKind::Delete);
    assert!(
        records[1].entry.is_none(),
        "a tombstone has no entry - the entry is what went away"
    );
    assert!(
        !records[1].csn.is_empty(),
        "the tombstone needs its own ordering key, or a replica cannot tell when it happened"
    );
}

#[tokio::test]
async fn a_deletion_of_an_entry_that_was_never_there_is_still_recorded() {
    // A replica that never learned about the entry still has to learn that it is gone; a record
    // we skip is a record it will never see.
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = store(dir.path());

    backend
        .apply(&[EntryChange::Delete {
            dn: "cn=ghost,ou=users,dc=example,dc=com".to_string(),
            kind: None,
        }])
        .await
        .expect("delete");

    let records = backend.journal_since(None).expect("journal");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, ChangeKind::Delete);
}

#[tokio::test]
async fn since_a_csn_returns_only_what_came_after_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = store(dir.path());

    for name in ["alice", "bob", "carol"] {
        backend
            .apply(&[EntryChange::Upsert {
                entry: person(name, "X"),
            }])
            .await
            .expect("write");
    }

    let all = backend.journal_since(None).expect("journal");
    assert_eq!(all.len(), 3);

    let after_first = backend.journal_since(Some(&all[0].csn)).expect("journal");
    assert_eq!(
        after_first.len(),
        2,
        "strictly after, so the record the cookie names is not sent again"
    );
    assert_eq!(after_first[0].csn, all[1].csn);
}

#[tokio::test]
async fn the_journal_is_ordered_by_time_because_the_key_is() {
    // The property the whole design rests on: `entryCSN` is fixed width, so text order is
    // chronological order and no separate index is needed.
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = store(dir.path());

    for name in ["alice", "bob", "carol"] {
        backend
            .apply(&[EntryChange::Upsert {
                entry: person(name, "X"),
            }])
            .await
            .expect("write");
    }

    let records = backend.journal_since(None).expect("journal");
    let csns: Vec<&String> = records.iter().map(|record| &record.csn).collect();
    let mut sorted = csns.clone();
    sorted.sort();

    assert_eq!(
        csns, sorted,
        "the journal must read in the order it happened"
    );
    assert_eq!(
        backend.journal_head().expect("head").as_ref(),
        csns.last().copied(),
        "the head is the newest record"
    );
}

#[tokio::test]
async fn pruning_moves_the_floor_so_a_laggard_knows_what_it_lost() {
    // A client resuming from a cookie older than the floor has missed changes nobody will send
    // it: the surviving records simply start later, and nothing in them says the gap exists. The
    // floor is the only thing that can say so.
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = store(dir.path());

    for name in ["alice", "bob", "carol"] {
        backend
            .apply(&[EntryChange::Upsert {
                entry: person(name, "X"),
            }])
            .await
            .expect("write");
    }

    let before = backend
        .journal_floor()
        .expect("floor")
        .expect("three records, so a floor");
    let oldest_csn = backend.journal_since(None).expect("journal")[0].csn.clone();
    assert_eq!(
        before, oldest_csn,
        "before pruning the floor is the first record"
    );

    backend.journal_prune(1).expect("prune");

    let after = backend
        .journal_floor()
        .expect("floor")
        .expect("one record left");
    assert!(
        after > before,
        "pruning moves the floor forward: {after} must be newer than {before}"
    );

    // A resume from the pruned cookie is exactly the silent loss this protects against: the range
    // starts after the floor and carries no hint that anything was dropped.
    let resumed = backend.journal_since(Some(&before)).expect("journal");
    assert_eq!(resumed.len(), 1, "only what survived comes back");
    assert!(
        after > before,
        "and the caller has no way to see the gap except by comparing with the floor"
    );
}

#[tokio::test]
async fn pruning_keeps_the_newest_and_forgets_the_rest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = store(dir.path());

    for name in ["alice", "bob", "carol", "dave"] {
        backend
            .apply(&[EntryChange::Upsert {
                entry: person(name, "X"),
            }])
            .await
            .expect("write");
    }

    let removed = backend.journal_prune(2).expect("prune");
    assert_eq!(removed, 2);

    let kept: Vec<String> = backend
        .journal_since(None)
        .expect("journal")
        .into_iter()
        .map(|record| record.dn)
        .collect();
    assert_eq!(kept.len(), 2);
    assert!(
        kept[0].contains("carol") && kept[1].contains("dave"),
        "the newest survive: {kept:?}"
    );

    // Pruning again below the size is a no-op, not an error.
    assert_eq!(backend.journal_prune(10).expect("prune"), 0);
}

#[tokio::test]
async fn a_record_survives_a_reopen_because_it_lives_with_the_entries() {
    // The journal is in the same database as the entries, so it is as durable as they are - and
    // a change and its record cannot half-happen, because they are one transaction.
    let dir = tempfile::tempdir().expect("tempdir");

    {
        let backend = store(dir.path());
        backend
            .apply(&[EntryChange::Upsert {
                entry: person("alice", "A"),
            }])
            .await
            .expect("write");
    }

    let again = store(dir.path());
    let records: Vec<ChangeRecord> = again.journal_since(None).expect("journal");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].dn, "cn=alice,ou=users,dc=example,dc=com");
    assert_eq!(records[0].kind, ChangeKind::Add);
}

#[tokio::test]
async fn a_backend_without_a_journal_says_so_instead_of_pretending() {
    // The JSON backends have nowhere to put a record and REST is somebody else's service. An
    // empty answer is "no history here", which is true - and a replica must re-initialise rather
    // than wait for records that will never come.
    let dir = tempfile::tempdir().expect("tempdir");
    let users = dir.path().join("users.json");
    let groups = dir.path().join("groups.json");
    std::fs::write(&users, "[]").expect("users");
    std::fs::write(&groups, "[]").expect("groups");

    let backend = Backend::from_config(
        "file",
        Some(&serde_json::json!({
            "users_path": users.display().to_string(),
            "groups_path": groups.display().to_string(),
        })),
    )
    .expect("backend");

    assert!(backend.journal_since(None).expect("journal").is_empty());
    assert_eq!(backend.journal_head().expect("head"), None);
    assert_eq!(backend.journal_prune(1).expect("prune"), 0);
}
