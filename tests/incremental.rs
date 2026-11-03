//! An in-place write must be indistinguishable from a reload, and must not read the store.
//!
//! The speed is the point, but the correctness is the condition: a directory that is patched in
//! memory instead of re-read is a directory that can drift from its store. These tests hold both
//! ends - the store is not read again, and what the server answers is what a reload would answer.

use std::time::Duration;

use rust_rest_ldap::backend::{Backend, EntryChange};
use rust_rest_ldap::directory::Scope;
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::reload::Source;

fn person(cn: &str, sn: &str) -> Entry {
    Entry::new(
        format!("cn={cn},ou=users,dc=example,dc=com"),
        Attributes::new()
            .push(Attribute::single("objectClass", "inetOrgPerson"))
            .push(Attribute::single("cn", cn))
            .push(Attribute::single("sn", sn))
            .push(Attribute::single("mail", &format!("{cn}@example.com"))),
    )
}

/// A source over a redb store with `count` seeded entries, and the config it was built from.
async fn seeded(dir: &std::path::Path, count: usize) -> std::sync::Arc<Source> {
    let store = dir.join("directory.redb");
    let text = format!(
        "base_dn: dc=example,dc=com\n\
         backend: redb\n\
         backends:\n  redb:\n    path: {}\n\
         indexes:\n  default: [pres, eq, sub]\n",
        store.display()
    );
    let config = rust_rest_ldap::config::resolve(
        rust_rest_ldap::config::Args::default(),
        Some(&text),
        |_| None,
    )
    .expect("config");

    let backend = Backend::from_config("redb", config.backends.get("redb")).expect("backend");
    let changes: Vec<EntryChange> = (0..count)
        .map(|i| EntryChange::Upsert {
            entry: person(&format!("u{i}"), "Original"),
        })
        .collect();
    backend.apply(&changes).await.expect("seed");

    let (source, _) = Source::load(&config, backend).await.expect("load");
    source
}

/// What the server answers for one DN, read the way a search would read it.
async fn dn_of(source: &Source, dn: &str) -> Option<Entry> {
    source
        .directory()
        .await
        .entries("dc=example,dc=com", Scope::Subtree)
        .into_iter()
        .find(|entry| entry.dn().eq_ignore_ascii_case(dn))
        .cloned()
}

/// The id of one entry, which is its position in canonical order.
async fn candidates_of(source: &Source, dn: &str) -> u32 {
    source
        .directory()
        .await
        .position(dn)
        .expect("the entry is in the directory") as u32
}

#[tokio::test]
async fn a_modify_replaces_the_entry_without_reading_the_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = seeded(dir.path(), 50).await;

    let reads_before = source.store_reads();
    let generation_before = source.generation().await;

    let changed = person("u7", "Changed");
    let entries = source
        .apply(&[EntryChange::Upsert {
            entry: changed.clone(),
        }])
        .await
        .expect("apply");

    assert_eq!(
        source.store_reads(),
        reads_before,
        "a replace is applied in place: the store must not be read again"
    );
    assert_eq!(
        source.generation().await,
        generation_before + 1,
        "the snapshot still moves, or a paged search would not notice the change"
    );
    assert_eq!(
        entries,
        50 + 3,
        "the naming context, two units and the users"
    );

    let seen = dn_of(&source, "cn=u7,ou=users,dc=example,dc=com")
        .await
        .expect("the entry is there");
    assert_eq!(
        seen.attributes().get("sn").map(|a| a.values.to_vec()),
        Some(vec!["Changed".to_string()])
    );

    // And the index followed the entry, not just the entries vector: asked the way a search asks
    // it, the index must name the entry under its new value and not under the old one.
    let directory = source.directory().await;
    let index = directory.index();
    let new_value = rust_rest_ldap::index::Query::Equality {
        attribute: "sn".into(),
        value: "changed".to_string(),
    };
    let candidates = index
        .candidates(&new_value)
        .expect("the index answers this");
    assert!(
        candidates.len() == 1,
        "the index must name exactly the one entry under its new value, found {}",
        candidates.len()
    );

    let old_value = rust_rest_ldap::index::Query::Equality {
        attribute: "sn".into(),
        value: "original".to_string(),
    };
    if let Some(candidates) = index.candidates(&old_value) {
        assert!(
            !candidates.contains(candidates_of(&source, "cn=u7,ou=users,dc=example,dc=com").await),
            "the entry must not still be found under the value it no longer has"
        );
    }
}

#[tokio::test]
async fn what_an_in_place_write_leaves_is_what_a_reload_would_have_read() {
    // The guarantee the old path had for free, held explicitly: memory after the patch equals
    // memory after reading the store back.
    let dir = tempfile::tempdir().expect("tempdir");
    let source = seeded(dir.path(), 40).await;

    source
        .apply(&[EntryChange::Upsert {
            entry: person("u3", "Patched"),
        }])
        .await
        .expect("apply");

    let patched = source.directory().await;
    let patched_entries = patched.all().to_vec();
    let patched_index = patched.index().clone();
    drop(patched);

    // The same source reads the store back - the path the write used to take, and the thing the
    // in-place path has to match. (A second source is not an option: the redb file is held open
    // by the first, which is also why the write path cannot open a second one to double-check.)
    source.reload().await.expect("reload");
    let reloaded = source.directory().await;

    assert_eq!(
        patched_entries,
        reloaded.all().to_vec(),
        "an in-place write must leave the directory where a reload would"
    );
    assert_eq!(patched_index, *reloaded.index(), "and the index with it");
}

#[tokio::test]
async fn an_add_still_reloads_because_it_moves_every_id_after_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = seeded(dir.path(), 20).await;

    let reads_before = source.store_reads();

    source
        .apply(&[EntryChange::Upsert {
            entry: person("brand-new", "New"),
        }])
        .await
        .expect("apply");

    assert_eq!(
        source.store_reads(),
        reads_before + 1,
        "a new entry changes the id of every entry after it, so the index is rebuilt"
    );
    assert!(
        dn_of(&source, "cn=brand-new,ou=users,dc=example,dc=com")
            .await
            .is_some(),
        "and the entry is there"
    );
}

#[tokio::test]
async fn a_delete_still_reloads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = seeded(dir.path(), 20).await;

    let reads_before = source.store_reads();

    source
        .apply(&[EntryChange::Delete {
            dn: "cn=u4,ou=users,dc=example,dc=com".to_string(),
        }])
        .await
        .expect("apply");

    assert_eq!(source.store_reads(), reads_before + 1);
    assert!(
        dn_of(&source, "cn=u4,ou=users,dc=example,dc=com")
            .await
            .is_none(),
        "the entry is gone"
    );
}

#[tokio::test]
async fn a_file_backend_write_still_reloads_because_the_store_rewrites_its_document() {
    // The file backend keeps users and groups as one JSON document per kind: what it stores after
    // a change is not a copy of the entry that was sent, so memory is not patched from the change
    // set. This test exists so that the fast path cannot silently start covering it.
    let dir = tempfile::tempdir().expect("tempdir");
    let users = dir.path().join("users.json");
    let groups = dir.path().join("groups.json");
    std::fs::write(
        &users,
        r#"[{"cn":"ann","sn":"A","objectClass":["top","inetOrgPerson"],"mail":"ann@example.com"}]"#,
    )
    .expect("write");
    std::fs::write(&groups, "[]").expect("write");

    let text = format!(
        "base_dn: dc=example,dc=com\nbackends:\n  file:\n    users_path: {}\n    groups_path: {}\n",
        users.display(),
        groups.display()
    );
    let config = rust_rest_ldap::config::resolve(
        rust_rest_ldap::config::Args::default(),
        Some(&text),
        |_| None,
    )
    .expect("config");
    let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
    let (source, _) = Source::load(&config, backend).await.expect("load");

    let reads_before = source.store_reads();

    // The backend finds the entry to replace by comparing it with what it stored, so the test
    // reads the stored value back instead of inventing one that merely looks the same.
    let stored: Vec<rust_rest_ldap::model::User> =
        serde_json::from_str(&std::fs::read_to_string(&users).expect("read")).expect("users");
    let user = stored.into_iter().next().expect("one user");
    let mut changed = user.clone();
    changed.mail = Some("ann@new.example".to_string());

    source
        .apply(&[EntryChange::User {
            old: Box::new(user),
            new: Box::new(changed),
        }])
        .await
        .expect("apply");

    assert_eq!(
        source.store_reads(),
        reads_before + 1,
        "the file backend's document is not the entry that was sent, so it is read back"
    );
}

#[tokio::test]
async fn an_in_place_write_answers_in_the_same_time_as_before_the_change_was_made() {
    // Not a threshold - a comparison. The number that matters is that a write no longer costs the
    // whole directory, so the check is that the in-place path is far cheaper than the reload it
    // replaced, on the same machine, in the same run.
    let dir = tempfile::tempdir().expect("tempdir");
    let source = seeded(dir.path(), 5_000).await;

    let started = std::time::Instant::now();
    source.reload().await.expect("reload");
    let reload = started.elapsed();

    let started = std::time::Instant::now();
    source
        .apply(&[EntryChange::Upsert {
            entry: person("u42", "Written"),
        }])
        .await
        .expect("apply");
    let in_place = started.elapsed();

    println!(
        "5 000 entries: reload {:?}, in-place write {:?}",
        reload, in_place
    );
    assert!(
        in_place * 2 < reload,
        "the in-place write must be cheaper than a reload: {:?} against {:?}",
        in_place,
        reload
    );
    // And the answer is still right.
    assert!(
        dn_of(&source, "cn=u42,ou=users,dc=example,dc=com")
            .await
            .is_some()
    );
    let _ = Duration::from_secs(0);
}

#[tokio::test]
async fn a_search_that_started_before_the_write_does_not_see_it() {
    // The reason the patch is allowed to skip the copy: only when nobody holds the snapshot. A
    // search in flight holds one, and a client reading a directory must never watch an entry it
    // already received change under it.
    let dir = tempfile::tempdir().expect("tempdir");
    let source = seeded(dir.path(), 30).await;

    // A reader takes the snapshot the way a search does.
    let held = source.directory().await;

    source
        .apply(&[EntryChange::Upsert {
            entry: person("u5", "Written"),
        }])
        .await
        .expect("apply");

    let seen_by_the_reader = held
        .entries("dc=example,dc=com", Scope::Subtree)
        .into_iter()
        .find(|entry| {
            entry
                .dn()
                .eq_ignore_ascii_case("cn=u5,ou=users,dc=example,dc=com")
        })
        .expect("the entry");
    assert_eq!(
        seen_by_the_reader
            .attributes()
            .get("sn")
            .map(|attribute| attribute.values.to_vec()),
        Some(vec!["Original".to_string()]),
        "a snapshot already held must not change under its reader"
    );
    assert_eq!(
        held.snapshot() + 1,
        source.directory().await.snapshot(),
        "and the write still moved the snapshot on, so a paged search notices"
    );

    let fresh = dn_of(&source, "cn=u5,ou=users,dc=example,dc=com")
        .await
        .expect("the entry");
    assert_eq!(
        fresh
            .attributes()
            .get("sn")
            .map(|attribute| attribute.values.to_vec()),
        Some(vec!["Written".to_string()]),
        "a reader that comes after the write sees the new value"
    );
}

#[tokio::test]
async fn a_write_that_breaks_the_schema_is_refused_before_anything_is_patched() {
    // The refusal has to happen before the snapshot is touched: a half-applied write that was
    // then refused would leave a directory nobody wrote.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path().join("directory.redb");

    let text = format!(
        "base_dn: dc=example,dc=com\n\
         backend: redb\n\
         backends:\n  redb:\n    path: {}\n\
         schema:\n  mode: strict\n",
        store.display()
    );
    let config = rust_rest_ldap::config::resolve(
        rust_rest_ldap::config::Args::default(),
        Some(&text),
        |_| None,
    )
    .expect("config");
    let backend = Backend::from_config("redb", config.backends.get("redb")).expect("backend");
    // No `mail` in the seed: the write below would add one, and the assertion is that it did not.
    let seed = Entry::new(
        "cn=u1,ou=users,dc=example,dc=com",
        Attributes::new()
            .push(Attribute::single("objectClass", "person"))
            .push(Attribute::single("cn", "u1"))
            .push(Attribute::single("sn", "Original")),
    );
    backend
        .apply(&[EntryChange::Upsert { entry: seed }])
        .await
        .expect("seed");
    let (source, _) = Source::load(&config, backend).await.expect("load");

    // `person` does not allow `mail`; this entry claims it does not need it but carries one.
    let broken = Entry::new(
        "cn=u1,ou=users,dc=example,dc=com",
        Attributes::new()
            .push(Attribute::single("objectClass", "person"))
            .push(Attribute::single("cn", "u1"))
            .push(Attribute::single("sn", "Original"))
            .push(Attribute::single("mail", "u1@example.com")),
    );

    let result = source.apply(&[EntryChange::Upsert { entry: broken }]).await;

    assert!(result.is_err(), "a strict schema refuses it: {result:?}");
    let after = dn_of(&source, "cn=u1,ou=users,dc=example,dc=com")
        .await
        .expect("the entry");
    assert!(
        after.attributes().get("mail").is_none(),
        "the refused entry must not be in the snapshot"
    );
}
