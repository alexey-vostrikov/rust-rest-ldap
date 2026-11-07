//! Search over the catalog, and the same search over the model it replaces.
//!
//! Two kinds of test here, and they answer different questions.
//!
//! * **Behaviour.** A search over the catalog returns what the filter says it should: a range ordered
//!   as numbers, a substring narrowed and then verified, a scope that is a key range, a combination
//!   whose unanswerable half must not empty the answer.
//! * **Equivalence.** The old model - every entry in a vector, an index of roaring bitmaps - answers
//!   the same filters over the same entries with the same DNs. That is the check `docs/storage.md`
//!   asks for at this step, and it is what makes the next step a switch rather than a rewrite.
use std::sync::Arc;

use redb::ReadableTableMetadata;
use rust_rest_ldap::catalog::Catalog;
use rust_rest_ldap::catalog::index::Plan;
use rust_rest_ldap::catalog::search::{Request, Search};
use rust_rest_ldap::catalog::store::Store;
use rust_rest_ldap::directory::{Directory, Scope};
use rust_rest_ldap::index::{Index, IndexConfig, Kind};
use rust_rest_ldap::ldap::filter;
use rust_rest_ldap::model::{Attribute, Attributes, Entry};

const BASE: &str = "dc=example,dc=com";

fn plan() -> Plan {
    Plan::of([
        ("uid".to_string(), vec![Kind::Eq, Kind::Pres]),
        ("cn".to_string(), vec![Kind::Eq, Kind::Sub]),
        ("sn".to_string(), vec![Kind::Eq]),
        ("age".to_string(), vec![Kind::Ord]),
        ("objectClass".to_string(), vec![Kind::Eq, Kind::Pres]),
    ])
}

fn config() -> IndexConfig {
    IndexConfig {
        default: Vec::new(),
        attributes: [
            (
                "uid".to_string(),
                vec!["eq".to_string(), "pres".to_string()],
            ),
            ("cn".to_string(), vec!["eq".to_string(), "sub".to_string()]),
            ("sn".to_string(), vec!["eq".to_string()]),
            ("age".to_string(), vec!["ord".to_string()]),
            (
                "objectClass".to_string(),
                vec!["eq".to_string(), "pres".to_string()],
            ),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    }
}

fn person(name: &str, sn: &str, age: &str, ou: &str) -> Entry {
    Entry::new(
        format!("uid={name},ou={ou},{BASE}"),
        Attributes::new()
            .replace(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "inetOrgPerson".to_string()],
            ))
            .replace(Attribute::single("uid", name))
            .replace(Attribute::single("cn", &format!("{name} {sn}")))
            .replace(Attribute::single("sn", sn))
            .replace(Attribute::single("age", age)),
    )
}

fn people() -> Vec<Entry> {
    vec![
        person("alice", "Cooper", "30", "users"),
        person("bob", "Marley", "9", "users"),
        person("carol", "King", "10", "sales"),
        person("dave", "Bowie", "45", "sales"),
        person("erin", "Black", "7", "support"),
    ]
}

fn catalog_with(entries: &[Entry]) -> Arc<Catalog> {
    let store = Arc::new(Store::in_memory().expect("store").with_plan(plan()));
    let catalog = Arc::new(Catalog::new(Arc::clone(&store), BASE, "users", "groups"));
    for entry in entries {
        catalog.insert(entry.clone()).expect("insert");
    }
    catalog
}

/// The old model, built the way the server builds it: a directory plus the index over its positions.
///
/// `from_entries` synthesizes the domain entry and the two organizational units, which is the shape a
/// running server has. The index is built over the directory's own positions, so the ids the two
/// models hand out are their own - only the answers are compared.
fn old_model(entries: &[Entry]) -> (Directory, Index) {
    let directory = Directory::from_entries(BASE, "users", "groups", entries.to_vec());
    let mut index = Index::default();
    for (id, entry) in directory.entries_with_ids(BASE, Scope::Subtree) {
        index.add(id as u32, entry, &config()).expect("index");
    }
    (directory, index)
}

fn names(entries: &[(u64, Entry)]) -> Vec<String> {
    let mut found: Vec<String> = entries
        .iter()
        .map(|(_, entry)| rust_rest_ldap::dn::first_value(entry.dn()).unwrap_or_default())
        .collect();
    found.sort();
    found
}

fn insensitive(_: &str) -> bool {
    false
}

/// Parses a filter the way a client would send it, so the test compares what the server compares.
fn parsed(text: &str) -> rasn_ldap::Filter {
    rust_rest_ldap::ldap::filter_parse::parse(text).expect("the filter parses")
}

fn search(catalog: &Arc<Catalog>, text: &str, base: &str, scope: Scope) -> Vec<String> {
    let filter = parsed(text);
    let search = Search::new(Arc::clone(catalog));
    let request = Request {
        base: base.to_string(),
        scope,
        query: filter::to_query(&filter),
        filter,
    };
    let found = search.run(&request, &insensitive).expect("search");
    names(&found.entries)
}

#[test]
fn an_equality_search_finds_the_entry_and_only_it() {
    let catalog = catalog_with(&people());
    assert_eq!(
        search(&catalog, "(uid=carol)", BASE, Scope::Subtree),
        vec!["carol"]
    );
}

#[test]
fn a_range_ordered_as_numbers_includes_ten_above_nine() {
    // The false negative a text ordering would produce: `10` sorts before `9` as text.
    let catalog = catalog_with(&people());
    assert_eq!(
        search(&catalog, "(age>=10)", BASE, Scope::Subtree),
        vec!["alice", "carol", "dave"],
        "7 and 9 are below the bound, and 10 is above it"
    );
}

#[test]
fn a_substring_is_narrowed_by_the_index_and_then_verified() {
    // The verification step earns its keep here: the trigram posting for `^ali` also holds values
    // that merely contain the windows, and the filter is what removes them.
    let catalog = catalog_with(&people());
    assert_eq!(
        search(&catalog, "(cn=ali*)", BASE, Scope::Subtree),
        vec!["alice"]
    );
    assert_eq!(
        search(&catalog, "(cn=*ing)", BASE, Scope::Subtree),
        vec!["carol"]
    );
}

#[test]
fn a_scope_decides_what_is_in_reach() {
    let catalog = catalog_with(&people());

    assert_eq!(
        search(
            &catalog,
            "(objectClass=inetOrgPerson)",
            &format!("ou=sales,{BASE}"),
            Scope::Subtree
        ),
        vec!["carol", "dave"]
    );
    assert_eq!(
        search(
            &catalog,
            "(objectClass=inetOrgPerson)",
            "uid=alice,ou=users,dc=example,dc=com",
            Scope::Base
        ),
        vec!["alice"]
    );
    assert!(
        search(
            &catalog,
            "(uid=alice)",
            &format!("ou=sales,{BASE}"),
            Scope::Subtree
        )
        .is_empty(),
        "alice is not under sales"
    );
}

#[test]
fn a_conjunction_of_an_indexed_and_an_unindexed_part_still_answers() {
    // `(!(uid=bob))` is the part no index describes. It must narrow nothing rather than empty the
    // answer, and the filter must still remove bob.
    let catalog = catalog_with(&people());
    assert_eq!(
        search(
            &catalog,
            "(&(objectClass=inetOrgPerson)(!(uid=bob)))",
            BASE,
            Scope::Subtree
        ),
        vec!["alice", "carol", "dave", "erin"]
    );
}

#[test]
fn a_disjunction_returns_both_sides() {
    let catalog = catalog_with(&people());
    assert_eq!(
        search(&catalog, "(|(uid=alice)(uid=erin))", BASE, Scope::Subtree),
        vec!["alice", "erin"]
    );
}

#[test]
fn the_same_filters_return_the_same_entries_from_the_old_model() {
    // The equivalence check `docs/storage.md` asks for at this step: same entries, same ids, same
    // DNs out - so the next step can be a switch rather than a rewrite.
    // Both models get *the same entries*: the old directory synthesizes the naming context and the
    // two organizational units, and a catalog without them would differ on `(!(uid=...))` for the
    // honest reason that it holds less. Equivalence means equal data, not equal intent.
    let (directory, index) = old_model(&people());
    let same: Vec<Entry> = directory
        .entries_with_ids(BASE, Scope::Subtree)
        .into_iter()
        .map(|(_, entry)| entry.clone())
        .collect();
    let catalog = catalog_with(&same);

    let filters = [
        "(uid=alice)",
        "(uid=nobody)",
        "(objectClass=inetOrgPerson)",
        "(cn=ali*)",
        "(cn=*ley)",
        "(sn=Cooper)",
        "(age>=10)",
        "(age<=9)",
        "(&(objectClass=inetOrgPerson)(age>=10))",
        "(|(uid=alice)(uid=bob))",
        "(!(uid=alice))",
        "(&(cn=*ar*)(age>=10))",
    ];

    for text in filters {
        let filter = parsed(text);

        // The old model: candidates from its index, then the walk in scope, then the filter.
        let query = filter::to_query(&filter);
        let candidates = index.candidates(&query);
        // `resolved_at` hands back `Cow` because a skeleton-mode directory may have to fetch the
        // record it is answering with; here every entry is already in memory.
        let in_scope: Vec<(usize, std::borrow::Cow<'_, Entry>)> = match candidates {
            Some(candidates) => directory.resolved_at(&candidates),
            None => directory
                .entries_with_ids(BASE, Scope::Subtree)
                .into_iter()
                .map(|(id, entry)| (id, std::borrow::Cow::Borrowed(entry)))
                .collect(),
        };
        let mut expected: Vec<String> = in_scope
            .iter()
            .filter(|(_, entry)| {
                rust_rest_ldap::directory::in_scope_for(entry.dn(), BASE, Scope::Subtree)
                    && filter::matches(entry.attributes(), entry.dn(), &filter).unwrap_or(false)
            })
            .map(|(_, entry)| rust_rest_ldap::dn::first_value(entry.dn()).unwrap_or_default())
            .collect();
        expected.sort();

        let ours = search(&catalog, text, BASE, Scope::Subtree);
        assert_eq!(ours, expected, "{text}");
    }
}

#[test]
fn an_ordered_posting_orders_negative_numbers_below_zero() {
    // The sign flip in the key is easy to get wrong in a way that only shows with negatives: without
    // it, a negative number sorts *after* every positive one in an unsigned byte comparison.
    let entries: Vec<Entry> = [("-5", "erin"), ("0", "alice"), ("7", "bob")]
        .iter()
        .map(|(age, name)| person(name, "X", age, "users"))
        .collect();
    let catalog = catalog_with(&entries);

    assert_eq!(
        search(&catalog, "(age>=-1)", BASE, Scope::Subtree),
        vec!["alice", "bob"],
        "-5 is below -1"
    );
    assert_eq!(
        search(&catalog, "(age>=-10)", BASE, Scope::Subtree),
        vec!["alice", "bob", "erin"]
    );
}

#[test]
fn a_page_of_an_ordered_posting_is_removed_when_its_last_entry_goes() {
    // An ordered index that left emptied pages behind would grow with every deleted entry, and a
    // range would walk a graveyard of keys naming nothing.
    let catalog = catalog_with(&people());
    let store = catalog.store().clone();

    let before = store
        .read()
        .expect("read")
        .open_table(rust_rest_ldap::catalog::index::IDX_ORD)
        .map(|table| table.len().expect("len"))
        .unwrap_or(0);
    assert!(before > 0, "the ordered index wrote something");

    for entry in people() {
        catalog.remove(entry.dn()).expect("remove");
    }

    let after = store
        .read()
        .expect("read")
        .open_table(rust_rest_ldap::catalog::index::IDX_ORD)
        .map(|table| table.len().expect("len"))
        .unwrap_or(0);
    assert_eq!(after, 0, "nothing is left of the ordered index");
}
