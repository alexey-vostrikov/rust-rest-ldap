//! What the index is worth, measured rather than assumed.
//!
//! The assertions here are about *answers*, not timings: a timing threshold in a test
//! suite is a flaky test waiting to happen. The numbers are printed so the report can
//! quote what this machine actually did.

use std::time::Instant;

use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, AttributeValueAssertion, Filter, ProtocolOp, SearchRequest,
    SearchRequestDerefAliases, SearchRequestScope,
};
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::index::IndexConfig;
use rust_rest_ldap::ldap::search::handle_search;
use rust_rest_ldap::ldap::session::{Identity, Session};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";
const ENTRIES: usize = 20_000;

fn entries(count: usize) -> Vec<Entry> {
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let name = format!("user{index:05}");
        let attributes = Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "person".to_string()],
            ))
            .push(Attribute::single("cn", &name))
            .push(Attribute::single("sn", &format!("Surname{index:05}")))
            .push(Attribute::single("uid", &name))
            .push(Attribute::single("mail", &format!("{name}@example.com")));
        entries.push(Entry::new(format!("cn={name},ou=users,{BASE}"), attributes));
    }
    entries
}

fn config() -> IndexConfig {
    IndexConfig {
        default: vec!["pres".to_string()],
        attributes: [
            ("cn", vec!["eq", "pres"]),
            ("uid", vec!["eq"]),
            ("mail", vec!["eq"]),
            ("objectClass", vec!["eq"]),
        ]
        .into_iter()
        .map(|(attribute, kinds)| {
            (
                attribute.to_string(),
                kinds.into_iter().map(str::to_string).collect(),
            )
        })
        .collect(),
        ..Default::default()
    }
}

fn count(directory: &Directory, filter: Filter) -> usize {
    let request = SearchRequest::new(
        rasn_ldap::LdapDn::from(BASE),
        SearchRequestScope::WholeSubtree,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        filter,
        vec![rasn_ldap::LdapString::from("dn")],
    );
    let mut session = Session::new();
    session.set_identity(Identity::new("cn=admin,ou=users,dc=example,dc=com", true));

    handle_search(&session, directory, 1, &request, None, &Security::default())
        .iter()
        .filter(|message| matches!(message.protocol_op, ProtocolOp::SearchResEntry(_)))
        .count()
}

fn equality(name: &str, value: &str) -> Filter {
    Filter::EqualityMatch(AttributeValueAssertion::new(
        AttributeDescription::from(name),
        OctetString::from(value.as_bytes()),
    ))
}

#[test]
fn the_index_pays_for_itself_on_a_large_directory() {
    let plain = Directory::from_entries(BASE, "users", "groups", entries(ENTRIES));
    let build_start = Instant::now();
    let indexed = plain.clone().with_indexes(&config()).expect("indexes");
    let build_time = build_start.elapsed();

    let filter = equality("cn", &format!("user{:05}", ENTRIES - 1));

    let start = Instant::now();
    let plain_matches = count(&plain, filter.clone());
    let plain_time = start.elapsed();

    let start = Instant::now();
    let indexed_matches = count(&indexed, filter.clone());
    let indexed_time = start.elapsed();

    println!(
        "entries: {ENTRIES}, index build: {build_time:?}, index size: {} KiB",
        indexed.index().size_bytes() / 1024
    );
    println!(
        "filter (cn=user{:05}): scan {plain_time:?}, indexed {indexed_time:?}, x{:.0}",
        ENTRIES - 1,
        plain_time.as_secs_f64() / indexed_time.as_secs_f64().max(f64::EPSILON)
    );

    assert_eq!(plain_matches, 1);
    assert_eq!(indexed_matches, 1);
    assert!(
        indexed_time < plain_time,
        "the index must be faster on an equality that matches one entry: \
         scan {plain_time:?} vs indexed {indexed_time:?}"
    );
}

/// The time of the fastest of `runs` executions.
///
/// A single measurement on a loaded machine is the sum of the work and whatever else the
/// scheduler had to do; the minimum is the closest thing to the work alone. `cargo test` runs the
/// tests of one binary in parallel by default, so the single-measurement version of these
/// assertions failed under load while the code was unchanged - a flaky test is worse than none.
fn best_of<T>(runs: usize, mut body: impl FnMut() -> T) -> (T, std::time::Duration) {
    let mut best = std::time::Duration::MAX;
    let mut result = None;

    for _ in 0..runs {
        let started = std::time::Instant::now();
        let value = body();
        let elapsed = started.elapsed();
        if elapsed < best {
            best = elapsed;
            result = Some(value);
        }
    }

    (result.expect("at least one run"), best)
}

#[test]
fn a_broad_filter_is_not_slower_with_an_index() {
    let plain = Directory::from_entries(BASE, "users", "groups", entries(ENTRIES));
    let indexed = plain.clone().with_indexes(&config()).expect("indexes");

    let filter = Filter::Present(AttributeDescription::from("objectClass"));

    let (plain_matches, plain_time) = best_of(5, || count(&plain, filter.clone()));
    let (indexed_matches, indexed_time) = best_of(5, || count(&indexed, filter.clone()));

    println!("filter (objectClass=*): scan {plain_time:?}, indexed {indexed_time:?}");

    assert_eq!(plain_matches, ENTRIES + 3, "domain and two OUs match too");
    assert_eq!(indexed_matches, plain_matches);
    // Everything matches, so the index only adds a bitmap test per entry. A few tens
    // of percent is noise; a doubling would mean the bitmap check is in the wrong loop.
    assert!(
        indexed_time < plain_time * 2,
        "a filter that matches everything must not be substantially slower: \
         scan {plain_time:?} vs indexed {indexed_time:?}"
    );
}
