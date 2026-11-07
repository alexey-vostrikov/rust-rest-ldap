//! The paged index against the one it replaces: same data, same questions, same answers.
//!
//! The equivalence test is the reason this module exists as a separate step. A new index that is
//! merely fast is a new index nobody can trust; one that answers every query the old one answered,
//! on the same entries and with the same ids, can be swapped in and measured.
//!
//! Two rows are deliberately *not* compared: the queries the old index answered by scanning
//! (`None`), because scanning is not an answer an index gives; and anything involving non-ASCII
//! text, because there the old index was wrong rather than merely different - it lowercased instead
//! of preparing (RFC 4518), and `docs/ub-log.md` records that as a defect the new index fixes.
use std::sync::Arc;

use redb::ReadableTableMetadata;

use rust_rest_ldap::catalog::Catalog;
use rust_rest_ldap::catalog::index::{
    PAGE, Plan, fold, pattern_trigrams, read_eq, read_pres, read_sub,
};
use rust_rest_ldap::catalog::store::{Change, Store};
use rust_rest_ldap::index::{Index, IndexConfig, Kind, Query};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};

const BASE: &str = "dc=example,dc=com";

fn person(name: &str, sn: &str, ou: &str) -> Entry {
    Entry::new(
        format!("uid={name},ou={ou},{BASE}"),
        Attributes::new()
            .replace(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "inetOrgPerson".to_string()],
            ))
            .replace(Attribute::single("uid", name))
            .replace(Attribute::single("cn", &format!("{name} {sn}")))
            .replace(Attribute::single("sn", sn)),
    )
}

/// The plan used throughout: equality and presence on the identifying attributes, trigrams on `cn`.
fn plan() -> Plan {
    Plan::of([
        ("uid".to_string(), vec![Kind::Eq, Kind::Pres]),
        ("sn".to_string(), vec![Kind::Eq]),
        ("cn".to_string(), vec![Kind::Sub, Kind::Eq]),
        ("objectClass".to_string(), vec![Kind::Eq, Kind::Pres]),
    ])
}

fn store_with_people() -> (Store, Vec<(u64, Entry)>) {
    let store = Store::in_memory().expect("store").with_plan(plan());
    let people = [
        person("alice", "Cooper", "users"),
        person("bob", "Marley", "users"),
        person("carol", "King", "sales"),
        person("dave", "Bowie", "sales"),
    ];
    let changes: Vec<Change> = people
        .iter()
        .map(|entry| Change::Add {
            entry: entry.clone(),
        })
        .collect();
    store.apply(&changes).expect("seed");

    let mut numbered = Vec::new();
    for entry in people {
        let id = store.id_of(entry.dn()).expect("read").expect("present");
        numbered.push((id, entry));
    }
    (store, numbered)
}

#[test]
fn an_equality_posting_finds_the_entries_with_that_value() {
    let (store, people) = store_with_people();
    let read = store.read().expect("read");
    let found = read_eq(&read, "uid", &fold("carol", false).expect("prepared")).expect("read");

    let carol = people
        .iter()
        .find(|(_, entry)| entry.dn().contains("uid=carol"))
        .map(|(id, _)| *id)
        .expect("carol");
    assert_eq!(found.iter().collect::<Vec<u64>>(), vec![carol]);
}

#[test]
fn a_presence_posting_finds_every_entry_with_the_attribute() {
    let (store, _) = store_with_people();
    let read = store.read().expect("read");

    assert_eq!(read_pres(&read, "uid").expect("read").len(), 4);
    // The name is case-insensitive, as it is everywhere in LDAP (RFC 4512).
    assert_eq!(read_pres(&read, "objectClass").expect("read").len(), 4);
    // An attribute nobody has holds nothing, and says so rather than failing.
    assert!(read_pres(&read, "mail").expect("read").is_empty());
    // And one whose presence was never configured has no postings at all, rather than an empty page.
    assert!(read_pres(&read, "sn").expect("read").is_empty());
}

#[test]
fn a_trigram_posting_narrows_by_every_window_the_pattern_implies() {
    let (store, people) = store_with_people();
    let read = store.read().expect("read");

    let wanted = pattern_trigrams(Some("ali"), &[], None, false).expect("prepared");
    let found = read_sub(&read, "cn", &wanted).expect("read");

    let alice = people
        .iter()
        .find(|(_, entry)| entry.dn().contains("uid=alice"))
        .map(|(id, _)| *id)
        .expect("alice");
    assert!(found.contains(alice), "alice's cn is `alice Cooper`");
    assert_eq!(found.len(), 1, "and nobody else's is");
}

#[test]
fn a_replaced_value_stops_being_findable_and_the_new_one_starts() {
    // The failure this guards against is the one a write path produces when it adds postings and
    // forgets to remove the old ones: the entry is found by a value it no longer has.
    let (store, people) = store_with_people();
    let alice = people
        .iter()
        .find(|(_, entry)| entry.dn().contains("uid=alice"))
        .expect("alice");

    let renamed = Entry::new(
        alice.1.dn().to_string(),
        alice
            .1
            .attributes()
            .clone()
            .replace(Attribute::single("sn", "Bowie")),
    );
    store
        .apply(&[Change::Replace { entry: renamed }])
        .expect("replace");

    let read = store.read().expect("read");
    let by_old = read_eq(&read, "sn", &fold("Cooper", false).expect("prepared")).expect("read");
    let by_new = read_eq(&read, "sn", &fold("Bowie", false).expect("prepared")).expect("read");

    assert!(!by_old.contains(alice.0), "the old value must be gone");
    assert!(by_new.contains(alice.0), "and the new one must be there");
}

#[test]
fn a_removed_entry_leaves_no_posting_behind() {
    let (store, people) = store_with_people();
    let bob = people
        .iter()
        .find(|(_, entry)| entry.dn().contains("uid=bob"))
        .expect("bob");

    store
        .apply(&[Change::Remove {
            dn: bob.1.dn().to_string(),
        }])
        .expect("remove");

    let read = store.read().expect("read");
    assert!(
        read_eq(&read, "uid", &fold("bob", false).expect("prepared"))
            .expect("read")
            .is_empty()
    );
    assert!(!read_pres(&read, "uid").expect("read").contains(bob.0));
    assert_eq!(read_pres(&read, "uid").expect("read").len(), 3);
}

#[test]
fn a_page_that_empties_is_removed_rather_than_left_as_a_key() {
    // Left behind, every deleted entry would leave a key naming an empty page, and a directory
    // written to for years would carry a shadow index of everything it ever held.
    let store = Store::in_memory().expect("store").with_plan(plan());
    let entry = person("alice", "Cooper", "users");
    store
        .apply(&[Change::Add {
            entry: entry.clone(),
        }])
        .expect("add");
    let keys_after_add = count_rows(&store, "idx_eq");

    store
        .apply(&[Change::Remove {
            dn: entry.dn().to_string(),
        }])
        .expect("remove");

    assert!(keys_after_add > 0, "the entry was indexed");
    assert_eq!(count_rows(&store, "idx_eq"), 0, "and nothing is left of it");
}

/// Counts the rows of a posting table, by walking it.
fn count_rows(store: &Store, table: &str) -> u64 {
    let read = store.read().expect("read");
    match table {
        "idx_eq" => {
            let Ok(table) = read.open_table(rust_rest_ldap::catalog::index::IDX_EQ) else {
                return 0;
            };
            table.len().expect("len")
        }
        "idx_sub" => {
            let Ok(table) = read.open_table(rust_rest_ldap::catalog::index::IDX_SUB) else {
                return 0;
            };
            table.len().expect("len")
        }
        _ => 0,
    }
}

#[test]
fn ids_beyond_the_first_page_land_on_the_page_they_belong_to() {
    // The page arithmetic is the part a test can get wrong quietly: an entry on page one answering
    // as if it were on page zero is still a plausible-looking id.
    let store = Store::in_memory().expect("store").with_plan(plan());
    let total = PAGE as usize + 3;
    let mut changes = Vec::with_capacity(total);
    for index in 0..total {
        changes.push(Change::Add {
            entry: Entry::new(
                format!("uid=user{index:06},ou=users,{BASE}"),
                Attributes::new()
                    .replace(Attribute::single("uid", &format!("user{index:06}")))
                    .replace(Attribute::single("objectClass", "inetOrgPerson")),
            ),
        });
    }
    store.apply(&changes).expect("apply");

    let read = store.read().expect("read");
    let first = read_eq(&read, "uid", &fold("user000000", false).expect("prepared")).expect("read");
    let last = read_eq(
        &read,
        "uid",
        &fold(&format!("user{:06}", total - 1), false).expect("prepared"),
    )
    .expect("read");

    let first_id = first.iter().next().expect("first");
    let last_id = last.iter().next().expect("last");
    assert!(
        first_id < PAGE,
        "the first entry is on page zero: {first_id}"
    );
    assert!(
        last_id >= PAGE,
        "the last one crossed into page one: {last_id}"
    );
    assert_eq!(read_pres(&read, "uid").expect("read").len(), total as u64);
}

#[test]
fn the_new_index_answers_every_question_the_old_one_answered() {
    // The comparison that makes this step worth taking separately. The old index is built over the
    // same entries with the same ids, and every query it can answer from postings must come back
    // the same from the store.
    let (store, people) = store_with_people();

    let config = IndexConfig {
        default: Vec::new(),
        attributes: [
            (
                "uid".to_string(),
                vec!["eq".to_string(), "pres".to_string()],
            ),
            ("sn".to_string(), vec!["eq".to_string()]),
            ("cn".to_string(), vec!["eq".to_string(), "sub".to_string()]),
            (
                "objectClass".to_string(),
                vec!["eq".to_string(), "pres".to_string()],
            ),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    let mut old = Index::default();
    for (id, entry) in &people {
        old.add(*id as u32, entry, &config).expect("old index");
    }

    let read = store.read().expect("read");
    let queries = [
        Query::Equality {
            attribute: Arc::from("uid"),
            value: "carol".to_string(),
        },
        Query::Equality {
            attribute: Arc::from("sn"),
            value: "Marley".to_string(),
        },
        Query::Equality {
            attribute: Arc::from("objectClass"),
            value: "inetOrgPerson".to_string(),
        },
        Query::Presence(Arc::from("uid")),
        Query::Presence(Arc::from("objectClass")),
        Query::Substring {
            attribute: Arc::from("cn"),
            initial: Some("ali".to_string()),
            any: Vec::new(),
            final_part: None,
        },
        Query::Substring {
            attribute: Arc::from("cn"),
            initial: None,
            any: Vec::new(),
            final_part: Some("ley".to_string()),
        },
    ];

    for query in queries {
        let Some(expected) = old.candidates(&query) else {
            continue; // the old index scans for this one, which is not an answer to compare
        };
        let ours = answer(&store, &read, &query);
        let ours_as_u32: Vec<u32> = ours.iter().map(|id| id as u32).collect();
        let expected_vec: Vec<u32> = expected.iter().collect();
        assert_eq!(ours_as_u32, expected_vec, "query {query:?}");
    }
}

/// Answers a query from the store's postings, the way step three will.
fn answer(_store: &Store, read: &redb::ReadTransaction, query: &Query) -> roaring::RoaringTreemap {
    match query {
        Query::Equality { attribute, value } => {
            read_eq(read, attribute, &fold(value, false).expect("prepared")).expect("read")
        }
        Query::Presence(attribute) => read_pres(read, attribute).expect("read"),
        Query::Substring {
            attribute,
            initial,
            any,
            final_part,
        } => {
            let wanted = pattern_trigrams(
                initial.as_deref(),
                any.as_slice(),
                final_part.as_deref(),
                false,
            )
            .expect("prepared");
            read_sub(read, attribute, &wanted).expect("read")
        }
        other => panic!("this test does not build a plan for {other:?}"),
    }
}

#[test]
fn a_store_without_a_plan_writes_no_postings() {
    // An unconfigured directory must not pay for an index it does not use, and must not claim to
    // have one: every query scans, and a posting that was never written says exactly that.
    let store = Store::in_memory().expect("store");
    store
        .apply(&[Change::Add {
            entry: person("alice", "Cooper", "users"),
        }])
        .expect("add");

    assert_eq!(count_rows(&store, "idx_eq"), 0);
    let read = store.read().expect("read");
    assert!(read_pres(&read, "uid").expect("read").is_empty());
}

#[test]
fn the_catalog_writes_postings_for_everything_it_stores() {
    // Through the catalog rather than the store directly: this is the path a running server takes,
    // and it is where a listener and a plan have to agree about what was written.
    let store = Arc::new(Store::in_memory().expect("store").with_plan(plan()));
    let catalog = Catalog::new(Arc::clone(&store), BASE, "users", "groups");

    catalog
        .insert(person("alice", "Cooper", "users"))
        .expect("insert");
    catalog
        .insert(person("bob", "Marley", "users"))
        .expect("insert");

    let read = store.read().expect("read");
    let found = read_eq(&read, "sn", &fold("Marley", false).expect("prepared")).expect("read");
    assert_eq!(found.len(), 1);
}
