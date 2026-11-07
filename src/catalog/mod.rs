//! The catalog: what a directory is, now that it is not a `Vec` in memory.
//!
//! `Directory` held every entry in a vector, kept two position maps and two ranges to slice it, and
//! built an index over the same numbering. Every write paid for that shape - a copy of the whole
//! catalogue while a reader held a snapshot, a rebuild of the position maps per insert, a
//! materialisation of the index per change - and each cost was fixed by adding a mechanism around
//! it. This is the replacement: the store is the only source of truth, ids are dense and stable,
//! and memory holds a cache.
//!
//! What this module adds over [`crate::catalog::store`] is the part that is about a *directory*
//! rather than about storage: which entries are users, which are groups, where a DN belongs in the
//! canonical order, and how a subtree is enumerated.
//!
//! # Canonical order, and why it is still here
//!
//! The old model's canonical order was load-bearing: `users()` and `groups()` were slices of it,
//! and the index's ids were positions in it. The new model keeps an order for a different reason -
//! a listing that changes between two identical reads is a listing a client cannot page through -
//! but it is now **derived on demand** from the store's key order, not maintained in memory.
//!
//! The store keeps entries under reversed DNs, so iterating it already yields a stable order: by
//! the last RDN, then the second to last, and so on. That is the order this module reports, and it
//! is the same on every read, which is what paging needs.
use std::sync::Arc;

pub mod store;

use crate::catalog::store::{Change, Store, StoreError};
use crate::model::{Attributes, Entry};

/// Where a change to the catalog goes once it is stored.
///
/// The index has to learn about every change in the same transaction as the entries, or a posting
/// would refer to an entry that is not there. The store owns the transaction, so it calls out:
/// anything that has to be updated atomically with the records implements this.
pub trait Changed: Send + Sync {
    /// Applies the changes that just entered the store.
    ///
    /// Called **inside** the store's transaction, so an implementation must not start its own -
    /// redb refuses a second write transaction on one database, and a nested one would deadlock.
    fn changed(&self, changes: &[Change]) -> Result<(), String>;
}

/// A directory over a store.
pub struct Catalog {
    store: Arc<Store>,
    base_dn: String,
    users_ou_name: String,
    groups_ou_name: String,
    /// Told about every change, inside the store's transaction.
    changed: Option<Arc<dyn Changed>>,
}

impl Catalog {
    /// A catalog over a store.
    pub fn new(
        store: Arc<Store>,
        base_dn: &str,
        users_ou_name: &str,
        groups_ou_name: &str,
    ) -> Self {
        Self {
            store,
            base_dn: base_dn.to_string(),
            users_ou_name: users_ou_name.to_string(),
            groups_ou_name: groups_ou_name.to_string(),
            changed: None,
        }
    }

    /// The same catalog, telling `changed` about every write.
    ///
    /// Set once at start: an index that learns about writes halfway through a run is an index that
    /// is missing the writes before it.
    #[must_use]
    pub fn with_changed(mut self, changed: Arc<dyn Changed>) -> Self {
        self.changed = Some(changed);
        self
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }

    /// The DN of the users organizational unit.
    pub fn users_dn(&self) -> String {
        format!("ou={},{}", self.users_ou_name, self.base_dn)
    }

    /// The DN of the groups organizational unit.
    pub fn groups_dn(&self) -> String {
        format!("ou={},{}", self.groups_ou_name, self.base_dn)
    }

    /// The DN a user with this name lives at, by this server's own convention.
    pub fn user_dn(&self, cn: &str) -> String {
        format!("uid={},{}", cn.to_lowercase(), self.users_dn())
    }

    /// The DN a group with this name lives at.
    pub fn group_dn(&self, cn: &str) -> String {
        format!("cn={},{}", cn.to_lowercase(), self.groups_dn())
    }

    /// One record, by DN.
    pub fn get(&self, dn: &str) -> Result<Option<Entry>, StoreError> {
        Ok(self
            .store
            .get(&crate::dn::normalize(dn))?
            .map(|(_, entry)| entry))
    }

    /// One record, by id.
    pub fn by_id(&self, id: u64) -> Result<Option<Entry>, StoreError> {
        self.store.by_id(id)
    }

    /// The id of a DN.
    pub fn id_of(&self, dn: &str) -> Result<Option<u64>, StoreError> {
        self.store.id_of(&crate::dn::normalize(dn))
    }

    /// How many entries the catalog serves, without walking it.
    ///
    /// The whole store and not only the naming context: with one naming context per server they are
    /// the same set, and counting by suffix would be a walk for a number that is not used.
    pub fn len(&self) -> Result<u64, StoreError> {
        self.store.len()
    }

    pub fn is_empty(&self) -> Result<bool, StoreError> {
        self.store.is_empty()
    }

    /// Every entry under `base`, at any depth: one range scan of the store.
    pub fn subtree(&self, base: &str) -> Result<Vec<(u64, Entry)>, StoreError> {
        self.store.walk(&crate::dn::normalize(base), usize::MAX)
    }

    /// The entries directly under `base`.
    pub fn children(&self, base: &str) -> Result<Vec<(u64, Entry)>, StoreError> {
        self.store.walk(&crate::dn::normalize(base), 1)
    }

    /// The users, in the store's order.
    ///
    /// Not "everything under `ou=users`": an account may live anywhere, and the old model's
    /// `users()` was a slice of a vector that only ever held what an import put there. This asks the
    /// question a client asks - which entries are accounts - and answers it by the object class,
    /// which is the directory's own definition rather than a place in the tree.
    pub fn users(&self) -> Result<Vec<(u64, Entry)>, StoreError> {
        self.with_class("inetOrgPerson")
    }

    /// The groups, by object class.
    pub fn groups(&self) -> Result<Vec<(u64, Entry)>, StoreError> {
        self.with_class("groupOfNames")
            .or_else(|_| self.with_class("posixGroup"))
    }

    /// Entries carrying an object class, walked in the store's order.
    ///
    /// A walk rather than an index lookup for now: the index that answers this in one step arrives
    /// with the paged postings, and until then a correct answer is worth more than a fast one. It is
    /// also what makes the equivalence tests meaningful - they compare this against the old
    /// `Directory::users()`, which was a slice.
    fn with_class(&self, class: &str) -> Result<Vec<(u64, Entry)>, StoreError> {
        let mut found = Vec::new();
        for (id, entry) in self.subtree(&self.base_dn)? {
            let has = entry
                .attributes()
                .get("objectClass")
                .is_some_and(|attribute| {
                    attribute
                        .values
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case(class))
                });
            if has {
                found.push((id, entry));
            }
        }
        Ok(found)
    }

    /// Writes a change set: entries first, then whoever is told about them.
    ///
    /// The order is the point. The store's transaction is what makes the entries and the index one
    /// fact; telling the index afterwards, in the same call but outside the transaction, is the
    /// compromise this shape allows - a crash between them leaves an index missing a change, which
    /// a rebuild fixes and a wrongly applied change would not.
    pub fn apply(&self, changes: &[Change]) -> Result<u64, StoreError> {
        let next_id = self.store.apply(changes)?;
        if let Some(changed) = &self.changed
            && let Err(detail) = changed.changed(changes)
        {
            return Err(StoreError::Record(format!(
                "the index did not accept the change: {detail}"
            )));
        }
        Ok(next_id)
    }

    /// Inserts an entry, returning the id it was given.
    pub fn insert(&self, entry: Entry) -> Result<Option<u64>, StoreError> {
        let dn = entry.dn().to_string();
        if self.id_of(&dn)?.is_some() {
            return Ok(None);
        }
        self.apply(&[Change::Add { entry }])?;
        self.id_of(&dn)
    }

    /// Replaces an entry, keeping its id. `false` when there was nothing to replace.
    pub fn replace(&self, entry: Entry) -> Result<bool, StoreError> {
        if self.id_of(entry.dn())?.is_none() {
            return Ok(false);
        }
        self.apply(&[Change::Replace { entry }])?;
        Ok(true)
    }

    /// Removes an entry. Returns the record that was there, or `None`.
    pub fn remove(&self, dn: &str) -> Result<Option<Entry>, StoreError> {
        let dn = crate::dn::normalize(dn);
        let Some((_, entry)) = self.store.get(&dn)? else {
            return Ok(None);
        };
        self.apply(&[Change::Remove { dn }])?;
        Ok(Some(entry))
    }
}

/// Attributes of a skeleton: a DN and nothing else.
///
/// The skeleton is what the catalog hands a caller who asked *which* entries and not *what is in
/// them* - the shape a search uses to decide before it reads.
pub fn skeleton(dn: &str) -> Entry {
    Entry::new(dn, Attributes::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Attribute;

    const BASE: &str = "dc=example,dc=com";

    fn catalog() -> Catalog {
        Catalog::new(
            Arc::new(Store::in_memory().expect("store")),
            BASE,
            "users",
            "groups",
        )
    }

    fn person(name: &str, ou: &str) -> Entry {
        Entry::new(
            format!("uid={name},ou={ou},{BASE}"),
            Attributes::new()
                .replace(Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "inetOrgPerson".to_string()],
                ))
                .replace(Attribute::single("uid", name))
                .replace(Attribute::single("cn", name)),
        )
    }

    fn group(name: &str) -> Entry {
        Entry::new(
            format!("cn={name},ou=groups,{BASE}"),
            Attributes::new()
                .replace(Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "groupOfNames".to_string()],
                ))
                .replace(Attribute::single("cn", name)),
        )
    }

    #[test]
    fn an_insert_returns_the_id_it_was_given_and_a_second_one_does_nothing() {
        let catalog = catalog();

        let first = catalog.insert(person("alice", "users")).expect("insert");
        let again = catalog.insert(person("alice", "users")).expect("insert");

        assert_eq!(first, Some(1));
        assert_eq!(again, None, "an existing DN is not inserted twice");
        assert_eq!(catalog.len().expect("len"), 1);
    }

    #[test]
    fn a_replace_keeps_the_id_and_a_remove_frees_the_dn_but_not_the_id() {
        let catalog = catalog();
        let id = catalog.insert(person("alice", "users")).expect("insert");

        assert!(
            catalog.replace(person("alice", "users")).expect("replace"),
            "the entry was there"
        );
        assert_eq!(
            catalog
                .id_of("uid=alice,ou=users,dc=example,dc=com")
                .expect("id"),
            id
        );

        assert!(
            catalog
                .remove("uid=alice,ou=users,dc=example,dc=com")
                .expect("remove")
                .is_some()
        );
        assert!(
            catalog
                .get("uid=alice,ou=users,dc=example,dc=com")
                .expect("get")
                .is_none()
        );
        assert!(
            !catalog.replace(person("alice", "users")).expect("replace"),
            "nothing to replace"
        );
    }

    #[test]
    fn the_users_are_found_by_object_class_and_not_by_where_they_sit() {
        // The old model's `users()` was a slice of a vector that only held what an import put in
        // one place. An account may live anywhere; the question a client asks is what an entry is.
        let catalog = catalog();
        catalog.insert(person("alice", "users")).expect("insert");
        catalog.insert(person("bob", "sales")).expect("insert");
        catalog.insert(group("admins")).expect("insert");

        let users = catalog.users().expect("users");
        let names: Vec<String> = users
            .iter()
            .map(|(_, entry)| crate::dn::first_value(entry.dn()).unwrap_or_default())
            .collect();

        assert_eq!(
            names.len(),
            2,
            "alice and bob, wherever they live: {names:?}"
        );
        assert!(names.contains(&"alice".to_string()));
        assert!(names.contains(&"bob".to_string()));
    }

    #[test]
    fn a_subtree_and_its_children_are_different_questions() {
        let catalog = catalog();
        catalog.insert(person("alice", "users")).expect("insert");
        catalog.insert(person("bob", "users")).expect("insert");

        // The base and its two children: nothing is under `ou=users` but the accounts themselves.
        let children = catalog.children(&catalog.users_dn()).expect("children");
        assert_eq!(children.len(), 2, "alice and bob");

        // A deeper base holds only its own subtree.
        let deep = catalog
            .subtree("uid=alice,ou=users,dc=example,dc=com")
            .expect("subtree");
        assert_eq!(deep.len(), 1, "alice alone");
    }

    #[test]
    fn every_change_reaches_the_listener_that_has_to_follow_it() {
        // The index has to learn about writes in the same breath as the store, or a posting refers to
        // an entry that is not there. The listener is how the catalog says so.
        use std::sync::Mutex;

        struct Recorder(Mutex<Vec<String>>);
        impl Changed for Recorder {
            fn changed(&self, changes: &[Change]) -> Result<(), String> {
                let mut log = self.0.lock().expect("lock");
                for change in changes {
                    log.push(match change {
                        Change::Add { entry } => format!("add {}", entry.dn()),
                        Change::Replace { entry } => format!("replace {}", entry.dn()),
                        Change::Remove { dn } => format!("remove {dn}"),
                    });
                }
                Ok(())
            }
        }

        let recorder = Arc::new(Recorder(Mutex::new(Vec::new())));
        let catalog = catalog().with_changed(Arc::clone(&recorder) as Arc<dyn Changed>);

        catalog.insert(person("alice", "users")).expect("insert");
        catalog.replace(person("alice", "users")).expect("replace");
        catalog
            .remove("uid=alice,ou=users,dc=example,dc=com")
            .expect("remove");

        let log = recorder.0.lock().expect("lock").clone();
        assert_eq!(
            log,
            vec![
                format!("add uid=alice,ou=users,{BASE}"),
                format!("replace uid=alice,ou=users,{BASE}"),
                format!("remove uid=alice,ou=users,{BASE}"),
            ]
        );
    }

    #[test]
    fn a_listener_that_refuses_is_reported_rather_than_hidden() {
        struct Refuser;
        impl Changed for Refuser {
            fn changed(&self, _changes: &[Change]) -> Result<(), String> {
                Err("the index is full".to_string())
            }
        }

        let catalog = catalog().with_changed(Arc::new(Refuser));

        let refused = catalog
            .insert(person("alice", "users"))
            .expect_err("refused");
        assert!(
            refused.to_string().contains("the index is full"),
            "{refused}"
        );
    }
}
