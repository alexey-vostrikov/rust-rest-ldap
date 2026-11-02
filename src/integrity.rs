//! Integrity: values that must stay unique, and members that must not dangle.
//!
//! Two rules that a directory gets wrong quietly, and both are cheap to enforce:
//!
//! 1. **Uniqueness.** `cn` and `uid` identify an account. Two users with the same `uid`
//!    make `uid=alice,ou=users,…` ambiguous: a bind picks the first one it finds, so the
//!    other account cannot be logged into at all, and nothing says why.
//!
//! 2. **Referential integrity.** `memberUid` in a group is a reference to a user. Delete
//!    the user and the group keeps a name that no longer resolves — a membership that
//!    looks like a person and is not. The fix belongs where the delete happens.
//!
//! Both are configurable and both default to on, because the failure they prevent is
//! silent: a duplicate or a dangling member does not produce an error anywhere, it just
//! makes the data wrong.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::directory::Directory;
use crate::dn;
use crate::model::{Attribute, Entry};

/// The default unique attributes: the two that name an account.
pub const DEFAULT_UNIQUE: [&str; 2] = ["cn", "uid"];

/// `integrity:` section of the configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct IntegrityConfig {
    /// Values of these attributes must be unique among the entries of the users OU.
    pub unique: Vec<String>,
    /// Turn the uniqueness check off; the field stays so a config can say so.
    pub allow_duplicates: bool,
    /// Remove a deleted or renamed user from every group that lists it.
    pub referential_integrity: bool,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            unique: DEFAULT_UNIQUE.iter().map(|name| name.to_string()).collect(),
            allow_duplicates: false,
            referential_integrity: true,
        }
    }
}

impl IntegrityConfig {
    /// The attributes to check, lowercased, or empty when the check is off.
    pub fn unique_attributes(&self) -> Vec<String> {
        if self.allow_duplicates {
            return Vec::new();
        }
        let mut names: Vec<String> = self
            .unique
            .iter()
            .map(|name| name.trim().to_lowercase())
            .filter(|name| !name.is_empty())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

/// A value that is already taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Duplicate {
    pub attribute: String,
    pub value: String,
    pub holder: String,
}

impl std::fmt::Display for Duplicate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} '{}' is already used by {}",
            self.attribute, self.value, self.holder
        )
    }
}

/// Checks `candidate` against the directory for every configured attribute.
///
/// `exclude_dn` is the entry being changed: renaming `cn=alice` to `cn=alice` must not
/// collide with itself, and a modify must not see its own old values as a duplicate.
pub fn check_unique(
    directory: &Directory,
    candidate: &Entry,
    exclude_dn: &str,
    attributes: &[String],
) -> Result<(), Duplicate> {
    let exclude = dn::normalize(exclude_dn);

    // Only accounts are covered. A group named `cn=alice` lives in a different
    // container and a different namespace: refusing it because a user is called alice
    // would forbid a perfectly ordinary directory.
    let users_ou = directory.ou_dn(directory.users_ou_name());
    if !candidate.dn().ends_with(&format!(",{users_ou}")) {
        return Ok(());
    }

    for name in attributes {
        let Some(attribute) = candidate.attributes().get(name) else {
            continue;
        };

        for value in attribute.values.iter() {
            if let Some(holder) = find_value(directory, name, value, &exclude) {
                return Err(Duplicate {
                    attribute: name.clone(),
                    value: value.clone(),
                    holder,
                });
            }
        }
    }

    Ok(())
}

/// The DN of an entry that already has `value`, ignoring `exclude`.
fn find_value(directory: &Directory, name: &str, value: &str, exclude: &str) -> Option<String> {
    let wanted = value.to_lowercase();

    directory
        .all()
        .iter()
        .filter(|entry| dn::normalize(entry.dn()) != exclude)
        // Only entries of the users OU are accounts; the domain and the OUs carry `dc`
        // and `ou`, not `cn`, so they cannot collide anyway, but the scope is explicit
        // so a future OU does not start colliding by accident.
        .filter(|entry| {
            entry
                .dn()
                .ends_with(&format!(",{}", directory.ou_dn(directory.users_ou_name())))
        })
        .find(|entry| {
            entry.attributes().get(name).is_some_and(|attribute| {
                attribute
                    .values
                    .iter()
                    .any(|candidate| candidate.to_lowercase() == wanted)
            })
        })
        .map(|entry| entry.dn().to_string())
}

/// Groups that list `member` in `memberUid`, with the entry to write instead.
///
/// Returns one entry per affected group, with the value removed; a group whose last
/// member went loses the attribute entirely, because an empty one is not storable.
pub fn strip_members(directory: &Directory, member: &str) -> Vec<Entry> {
    let wanted = member.to_lowercase();
    let mut updated = Vec::new();

    for group in directory.groups() {
        let Some(attribute) = group.attributes().get("memberUid") else {
            continue;
        };
        if !attribute
            .values
            .iter()
            .any(|value| value.to_lowercase() == wanted)
        {
            continue;
        }

        let remaining: Vec<String> = attribute
            .values
            .iter()
            .filter(|value| value.to_lowercase() != wanted)
            .cloned()
            .collect();

        let mut rebuilt = Attribute::new("memberUid", remaining.clone());
        rebuilt.flags = attribute.flags;

        let attributes = if remaining.is_empty() {
            group.attributes().clone().without("memberUid")
        } else {
            group.attributes().clone().replace(rebuilt)
        };

        updated.push(Entry::new(group.dn(), attributes));
    }

    updated
}

/// The names a user is listed by in `memberUid`: `uid` and `cn`, whichever exist.
///
/// gorestldap let a group list either, and the data in the wild uses both, so a delete
/// has to clear both or it leaves a membership behind under the other name.
pub fn member_names(entry: &Entry) -> Vec<String> {
    ["uid", "cn"]
        .into_iter()
        .filter_map(|name| {
            entry
                .attributes()
                .get(name)
                .and_then(|attribute| attribute.values.first().cloned())
        })
        .collect()
}

/// Groups whose `memberUid` must follow a rename.
///
/// A rename changes `cn` (and possibly `uid`), which is exactly what a group lists. Left
/// alone, the group keeps pointing at a name nobody answers to, and the membership looks
/// real while resolving to nothing. The old value is replaced by the new one in place, so
/// the group keeps its position and its other members.
pub fn retarget_members(directory: &Directory, before: &Entry, after: &Entry) -> Vec<Entry> {
    let pairs: Vec<(String, String)> = ["uid", "cn"]
        .into_iter()
        .filter_map(|name| {
            let old = before
                .attributes()
                .get(name)
                .and_then(|attribute| attribute.values.first().cloned())?;
            let new = after
                .attributes()
                .get(name)
                .and_then(|attribute| attribute.values.first().cloned())?;

            // Only a changed value can dangle; an unchanged one needs no write.
            (!old.eq_ignore_ascii_case(&new)).then_some((old, new))
        })
        .collect();

    if pairs.is_empty() {
        return Vec::new();
    }

    let mut updated = Vec::new();
    for group in directory.groups() {
        let Some(attribute) = group.attributes().get("memberUid") else {
            continue;
        };

        let mut values = attribute.values.to_vec();
        let mut changed = false;
        for value in values.iter_mut() {
            for (old, new) in &pairs {
                if value.eq_ignore_ascii_case(old) {
                    *value = new.clone();
                    changed = true;
                }
            }
        }
        if !changed {
            continue;
        }

        let mut rebuilt = Attribute::new("memberUid", values.clone());
        rebuilt.flags = attribute.flags;
        updated.push(Entry::new(
            group.dn(),
            group.attributes().clone().replace(rebuilt),
        ));
    }

    updated
}

/// Every group entry that has to be rewritten because `removed` went away.
pub fn changes_for_removed(directory: &Directory, removed: &Entry) -> Vec<Entry> {
    let mut by_dn: BTreeMap<String, Entry> = BTreeMap::new();

    for name in member_names(removed) {
        for group in strip_members(directory, &name) {
            by_dn.insert(group.dn().to_string(), group);
        }
    }

    by_dn.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Attributes;

    const BASE: &str = "dc=example,dc=com";
    const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";
    const BOB_DN: &str = "cn=bob,ou=users,dc=example,dc=com";

    fn user(dn: &str, cn: &str, uid: &str) -> Entry {
        Entry::new(
            dn,
            Attributes::new()
                .push(Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "person".to_string()],
                ))
                .push(Attribute::single("cn", cn))
                .push(Attribute::single("sn", "S"))
                .push(Attribute::single("uid", uid)),
        )
    }

    fn group(dn: &str, cn: &str, members: &[&str]) -> Entry {
        let mut attributes = Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "posixGroup".to_string()],
            ))
            .push(Attribute::single("cn", cn))
            .push(Attribute::single("gidNumber", "2000"));
        if !members.is_empty() {
            attributes = attributes.push(Attribute::new(
                "memberUid",
                members.iter().map(|m| m.to_string()).collect(),
            ));
        }
        Entry::new(dn, attributes)
    }

    fn directory() -> Directory {
        Directory::from_entries(
            BASE,
            "users",
            "groups",
            vec![
                user(ALICE_DN, "alice", "alice"),
                user(BOB_DN, "bob", "bob"),
                group(
                    "cn=team,ou=groups,dc=example,dc=com",
                    "team",
                    &["alice", "bob"],
                ),
                group("cn=solo,ou=groups,dc=example,dc=com", "solo", &["alice"]),
            ],
        )
    }

    fn unique() -> Vec<String> {
        IntegrityConfig::default().unique_attributes()
    }

    #[test]
    fn the_default_unique_attributes_are_cn_and_uid() {
        assert_eq!(unique(), vec!["cn".to_string(), "uid".to_string()]);
    }

    #[test]
    fn an_existing_cn_is_a_duplicate() {
        let candidate = user(
            "cn=other,ou=users,dc=example,dc=com",
            "alice",
            "someone-else",
        );

        let duplicate = check_unique(&directory(), &candidate, candidate.dn(), &unique())
            .expect_err("cn alice is taken");

        assert_eq!(duplicate.attribute, "cn");
        assert_eq!(duplicate.value, "alice");
        assert_eq!(duplicate.holder, ALICE_DN);
    }

    #[test]
    fn an_existing_uid_is_a_duplicate() {
        let candidate = user("cn=someone,ou=users,dc=example,dc=com", "someone", "alice");

        let duplicate = check_unique(&directory(), &candidate, candidate.dn(), &unique())
            .expect_err("uid alice is taken");

        assert_eq!(duplicate.attribute, "uid");
    }

    #[test]
    fn case_does_not_make_it_unique() {
        // `Alice` and `alice` are the same account name to every client that folds case,
        // which is all of them.
        let candidate = user("cn=new,ou=users,dc=example,dc=com", "ALICE", "new");

        assert!(check_unique(&directory(), &candidate, candidate.dn(), &unique()).is_err());
    }

    #[test]
    fn a_free_value_passes() {
        let candidate = user("cn=carol,ou=users,dc=example,dc=com", "carol", "carol");

        assert_eq!(
            check_unique(&directory(), &candidate, candidate.dn(), &unique()),
            Ok(())
        );
    }

    #[test]
    fn an_entry_does_not_collide_with_itself() {
        // A modify or a rename that keeps the value must not be refused as a duplicate
        // of the entry being changed.
        let existing = directory().find(ALICE_DN).expect("alice").clone();

        assert_eq!(
            check_unique(&directory(), &existing, ALICE_DN, &unique()),
            Ok(())
        );
    }

    #[test]
    fn only_accounts_are_checked() {
        // The domain entry has no cn/uid, and a group's cn may repeat a user's: groups
        // and users are different namespaces in this server.
        let candidate = group("cn=alice,ou=groups,dc=example,dc=com", "alice", &[]);

        assert_eq!(
            check_unique(&directory(), &candidate, candidate.dn(), &unique()),
            Ok(()),
            "a group called alice must not collide with the user"
        );
    }

    #[test]
    fn duplicates_can_be_allowed_in_the_configuration() {
        let config = IntegrityConfig {
            allow_duplicates: true,
            ..IntegrityConfig::default()
        };

        assert!(config.unique_attributes().is_empty());
    }

    #[test]
    fn the_unique_list_is_configurable() {
        let config = IntegrityConfig {
            unique: vec!["Mail".to_string(), " ".to_string(), "mail".to_string()],
            ..IntegrityConfig::default()
        };

        assert_eq!(config.unique_attributes(), vec!["mail".to_string()]);
    }

    #[test]
    fn the_duplicate_message_names_the_holder() {
        let duplicate = Duplicate {
            attribute: "uid".to_string(),
            value: "alice".to_string(),
            holder: ALICE_DN.to_string(),
        };

        assert_eq!(
            duplicate.to_string(),
            "uid 'alice' is already used by cn=alice,ou=users,dc=example,dc=com"
        );
    }

    #[test]
    fn deleting_a_user_removes_it_from_every_group() {
        let alice = directory().find(ALICE_DN).expect("alice").clone();
        let updated = changes_for_removed(&directory(), &alice);

        assert_eq!(updated.len(), 2, "two groups list alice");

        let team = updated
            .iter()
            .find(|entry| entry.dn().contains("cn=team"))
            .expect("team");
        assert_eq!(
            team.attributes()
                .get("memberUid")
                .map(|attribute| attribute.values.to_vec()),
            Some(vec!["bob".to_string()]),
            "only alice goes"
        );

        let solo = updated
            .iter()
            .find(|entry| entry.dn().contains("cn=solo"))
            .expect("solo");
        assert!(
            solo.attributes().get("memberUid").is_none(),
            "a group whose last member left loses the attribute entirely"
        );
    }

    #[test]
    fn a_user_nobody_lists_affects_no_group() {
        let carol = user("cn=carol,ou=users,dc=example,dc=com", "carol", "carol");

        assert!(changes_for_removed(&directory(), &carol).is_empty());
    }

    #[test]
    fn both_names_are_cleared() {
        // A group may list a user by uid or by cn; gorestldap accepted both, so a delete
        // has to remove both or it leaves one membership behind.
        let directory = Directory::from_entries(
            BASE,
            "users",
            "groups",
            vec![
                user(ALICE_DN, "alice", "alice"),
                group(
                    "cn=by-uid,ou=groups,dc=example,dc=com",
                    "by-uid",
                    &["alice"],
                ),
                group("cn=by-cn,ou=groups,dc=example,dc=com", "by-cn", &["alice"]),
            ],
        );
        let alice = directory.find(ALICE_DN).expect("alice").clone();

        let updated = changes_for_removed(&directory, &alice);

        assert_eq!(updated.len(), 2, "both spellings are cleared");
        for entry in &updated {
            assert!(entry.attributes().get("memberUid").is_none());
        }
    }

    #[test]
    fn a_group_keeps_its_flags() {
        let directory = directory();
        let alice = directory.find(ALICE_DN).expect("alice").clone();

        for entry in changes_for_removed(&directory, &alice) {
            if let Some(attribute) = entry.attributes().get("memberUid") {
                assert_eq!(
                    attribute.flags,
                    directory
                        .groups()
                        .iter()
                        .find(|group| group.dn() == entry.dn())
                        .and_then(|group| group.attributes().get("memberUid"))
                        .expect("original")
                        .flags,
                    "rewriting a group must not change what its attributes are"
                );
            }
        }
    }

    #[test]
    fn a_rename_updates_the_groups() {
        let directory = directory();
        let before = directory.find(ALICE_DN).expect("alice").clone();

        // Rename cn=alice to cn=alicia; uid stays alice.
        let mut attributes = before.attributes().clone();
        attributes = attributes.replace(Attribute::single("cn", "alicia"));
        let after = Entry::new("cn=alicia,ou=users,dc=example,dc=com", attributes);

        let updated = retarget_members(&directory, &before, &after);

        assert_eq!(updated.len(), 2, "both groups list the old cn");
        let team = updated
            .iter()
            .find(|entry| entry.dn().contains("cn=team"))
            .expect("team");
        assert_eq!(
            team.attributes()
                .get("memberUid")
                .map(|attribute| attribute.values.to_vec()),
            Some(vec!["alicia".to_string(), "bob".to_string()]),
            "the old name is replaced in place, the rest is untouched"
        );
    }

    #[test]
    fn a_rename_that_keeps_both_names_writes_nothing() {
        let directory = directory();
        let alice = directory.find(ALICE_DN).expect("alice").clone();

        // Moving to another container keeps cn and uid: no group needs to change.
        let moved = Entry::new(
            "cn=alice,ou=staff,dc=example,dc=com",
            alice.attributes().clone(),
        );

        assert!(retarget_members(&directory, &alice, &moved).is_empty());
    }

    #[test]
    fn a_rename_of_a_user_nobody_lists_writes_nothing() {
        let directory = directory();
        let carol = user("cn=carol,ou=users,dc=example,dc=com", "carol", "carol");
        let mut attributes = carol.attributes().clone();
        attributes = attributes.replace(Attribute::single("cn", "caroline"));
        let renamed = Entry::new("cn=caroline,ou=users,dc=example,dc=com", attributes);

        assert!(retarget_members(&directory, &carol, &renamed).is_empty());
    }

    #[test]
    fn the_names_of_a_user_come_from_uid_and_cn() {
        let entry = user(ALICE_DN, "Alice", "alice.user");

        assert_eq!(
            member_names(&entry),
            vec!["alice.user".to_string(), "Alice".to_string()],
            "uid first, then cn"
        );
    }

    #[test]
    fn a_user_without_uid_still_reports_cn() {
        let entry = Entry::new(
            ALICE_DN,
            Attributes::new()
                .push(Attribute::single("cn", "alice"))
                .push(Attribute::single("sn", "S")),
        );

        assert_eq!(member_names(&entry), vec!["alice".to_string()]);
    }
}
