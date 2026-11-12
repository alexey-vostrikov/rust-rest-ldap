//! Baseline measurements: how long a search takes before any index exists.
//!
//! Run with `cargo test --release --test baseline -- --nocapture` (the wrapper:
//! `./scripts/cargo.sh test --release --test baseline -- --nocapture`).
//!
//! These are not assertions about speed — they are the numbers the design of the
//! index has to beat, and they are re-measured in the same run that reports them,
//! so a stale figure cannot be quoted by accident.

use std::time::Instant;

use rasn_ldap::{AttributeDescription, AttributeValueAssertion, Filter};
use rrl_directory::directory::{Directory, Scope};
use rrl_directory::ldap::filter;
use rrl_directory::model::User;

fn directory(entries: usize) -> Directory {
    let users = (0..entries)
        .map(|index| User {
            object_class: vec![
                "top".to_string(),
                "posixAccount".to_string(),
                "inetOrgPerson".to_string(),
            ],
            cn: format!("user{index:05}"),
            uid: Some(format!("user{index:05}")),
            sn: Some(format!("Surname{index:05}")),
            mail: Some(format!("user{index:05}@example.com")),
            uid_number: Some(1000 + index as u32),
            gid_number: Some(2000),
            ..User::default()
        })
        .collect();

    Directory::new("dc=example,dc=com", "users", "groups", users, vec![])
}

fn equality(name: &str, value: &str) -> Filter {
    Filter::EqualityMatch(AttributeValueAssertion::new(
        AttributeDescription::from(name),
        rasn::types::OctetString::from(value.as_bytes()),
    ))
}

fn presence(name: &str) -> Filter {
    Filter::Present(AttributeDescription::from(name))
}

fn substring(name: &str, initial: &str) -> Filter {
    Filter::Substrings(rasn_ldap::SubstringFilter::new(
        AttributeDescription::from(name),
        vec![rasn_ldap::SubstringChoice::Initial(
            rasn::types::OctetString::from(initial.as_bytes()),
        )],
    ))
}

/// Time one search: enumerate candidates by scope, then evaluate the filter on each.
fn timed_search(directory: &Directory, base: &str, scope: Scope, probe: &Filter) -> (usize, f64) {
    let started = Instant::now();
    let mut matched = 0;
    for entry in directory.entries(base, scope) {
        let dn = entry.dn();
        if filter::matches(entry.attributes(), dn, probe).expect("supported filter") {
            matched += 1;
        }
    }
    (matched, started.elapsed().as_secs_f64() * 1000.0)
}

#[test]
fn baseline_search_costs() {
    let sizes = [1_000usize, 10_000, 20_000];

    println!("\n=== baseline: full scan, per search ===");
    println!(
        "{:>7} {:>12} {:>12} {:>12} {:>12}",
        "entries", "eq (ms)", "pres (ms)", "sub (ms)", "dn only (ms)"
    );

    for size in sizes {
        let directory = directory(size);

        let (_, eq) = timed_search(
            &directory,
            "dc=example,dc=com",
            Scope::Subtree,
            &equality("cn", &format!("user{:05}", size / 2)),
        );
        let (presence_hits, pres) = timed_search(
            &directory,
            "dc=example,dc=com",
            Scope::Subtree,
            &presence("objectClass"),
        );
        let (substring_hits, sub) = timed_search(
            &directory,
            "dc=example,dc=com",
            Scope::Subtree,
            &substring("cn", "user"),
        );
        let (_, walk) = timed_search(
            &directory,
            "dc=example,dc=com",
            Scope::Subtree,
            &presence("nosuchattribute"),
        );

        assert_eq!(presence_hits, size + 3, "domain, both ous and every user");
        assert_eq!(substring_hits, size, "every cn starts with user");

        println!("{size:>7} {eq:>12.3} {pres:>12.3} {sub:>12.3} {walk:>12.3}");
    }
}

#[test]
fn baseline_memory_per_entry() {
    // Rough size of one user entry as built by the model, for the index budget:
    // an index that costs more than the entries themselves defeats the purpose.
    let user = User {
        object_class: vec![
            "top".to_string(),
            "posixAccount".to_string(),
            "inetOrgPerson".to_string(),
        ],
        cn: "user00042".to_string(),
        uid: Some("user00042".to_string()),
        sn: Some("Surname00042".to_string()),
        mail: Some("user00042@example.com".to_string()),
        user_password: Some("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_string()),
        ..User::default()
    };
    let attributes =
        rrl_directory::mapping::gorestldap::user_entry(&user, "dc=example,dc=com", "users")
            .attributes()
            .clone();

    let values: usize = attributes
        .values()
        .iter()
        .map(|attribute| {
            attribute.name.len()
                + attribute
                    .values
                    .iter()
                    .map(|value| value.len() + 24)
                    .sum::<usize>()
        })
        .sum();

    println!("\n=== baseline: one entry ===");
    println!("attributes: {}", attributes.values().len());
    println!("values+names bytes (approx): {values}");
    println!("struct bytes: {}", std::mem::size_of::<User>());
    println!(
        "arc per entry overhead: {}",
        std::mem::size_of::<String>() * 2
    );
}
