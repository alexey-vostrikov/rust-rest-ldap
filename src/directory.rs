//! In-memory directory: entries, their DNs, lookup and scope traversal.
//!
//! The directory is immutable: a reload builds a new one and the server swaps the
//! reference, so a request never observes a half-updated tree and no lock has to
//! guard entry mutation.
//!
//! Entries live in one flat `Vec` in the canonical order (domain, the two
//! organizational units, users, groups) with a DN index on top. That order is what
//! the server returns, and it is also the dense numbering the index of E3 will use:
//! a subtree is then a contiguous range.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

use uuid::Uuid;

use crate::dn;
use crate::index::{Index, IndexConfig, IndexError, Query};
use crate::mapping::gorestldap;
use crate::model::{
    ATTR_ENTRY_UUID, ATTR_HAS_SUBORDINATES, ATTR_OBJECT_CLASS, Attribute, Attributes, Entry, Group,
    User,
};

/// Search scope, mirroring RFC 4511 values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Base,
    OneLevel,
    Subtree,
}

/// Directory contents loaded from a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    base_dn: String,
    users_ou_name: String,
    groups_ou_name: String,
    /// Domain entry, the two organizational units, users, groups, everything else.
    entries: Vec<Entry>,
    /// Canonical-order ranges, so `users()` and `groups()` are slices, not filters.
    users: Range<usize>,
    groups: Range<usize>,
    by_dn: HashMap<String, usize>,
    /// Search indexes over the same id numbering. Empty unless `with_indexes` ran.
    index: Arc<Index>,
    /// Which snapshot of the directory this is.
    ///
    /// A paged search hands the client a cookie that says where the next page starts. An offset
    /// alone is not enough to continue safely: if the directory changed between pages, the same
    /// offset points at a different entry, and the client silently skips or repeats records.
    /// The cookie carries this number too, so a page that continues a snapshot which no longer
    /// exists is refused instead of answered wrongly.
    snapshot: u64,
}

impl Directory {
    /// Builds the directory from gorestldap-shaped users and groups.
    ///
    /// The domain entry and the two organizational units are synthesized here: they
    /// belong to the shape of this server, not to the backend data.
    pub fn new(
        base_dn: &str,
        users_ou_name: &str,
        groups_ou_name: &str,
        users: Vec<User>,
        groups: Vec<Group>,
    ) -> Self {
        let base_dn = dn::normalize(base_dn);
        let users_ou_name = users_ou_name.to_lowercase();
        let groups_ou_name = groups_ou_name.to_lowercase();

        let mut entries = vec![
            domain_entry(&base_dn),
            ou_entry(&users_ou_name, &base_dn),
            ou_entry(&groups_ou_name, &base_dn),
        ];

        let users_start = entries.len();
        entries.extend(
            users
                .iter()
                .map(|user| gorestldap::user_entry(user, &base_dn, &users_ou_name)),
        );
        let users_range = users_start..entries.len();

        let groups_start = entries.len();
        entries.extend(
            groups
                .iter()
                .map(|group| gorestldap::group_entry(group, &base_dn, &groups_ou_name)),
        );
        let groups_range = groups_start..entries.len();

        Self::assemble(
            base_dn,
            users_ou_name,
            groups_ou_name,
            entries,
            users_range,
            groups_range,
        )
    }

    /// Builds the directory from entries that are already shaped — the direct JSON
    /// adapter today, any other source later.
    ///
    /// Entries below the users or groups OU are placed in the canonical position;
    /// everything else keeps DN order after them.
    /// The same directory, marked as snapshot `snapshot`.
    #[must_use]
    pub fn at_snapshot(mut self, snapshot: u64) -> Self {
        self.snapshot = snapshot;
        self
    }

    /// The snapshot this directory is.
    pub fn snapshot(&self) -> u64 {
        self.snapshot
    }

    pub fn from_entries(
        base_dn: &str,
        users_ou_name: &str,
        groups_ou_name: &str,
        extra: Vec<Entry>,
    ) -> Self {
        let base_dn = dn::normalize(base_dn);
        let users_ou_name = users_ou_name.to_lowercase();
        let groups_ou_name = groups_ou_name.to_lowercase();
        let users_ou_dn = format!("ou={users_ou_name},{base_dn}");
        let groups_ou_dn = format!("ou={groups_ou_name},{base_dn}");

        let mut entries = vec![
            domain_entry(&base_dn),
            ou_entry(&users_ou_name, &base_dn),
            ou_entry(&groups_ou_name, &base_dn),
        ];

        let (mut users, mut groups, mut other): (Vec<Entry>, Vec<Entry>, Vec<Entry>) =
            (Vec::new(), Vec::new(), Vec::new());
        for entry in extra {
            // The naming context and the two units are synthesised above when the store does
            // not carry them - which is every JSON backend and every directory grown over the
            // protocol. A store that *does* carry them (an import, a migration from OpenLDAP)
            // would otherwise hold each one twice: a search would return two entries with the
            // same DN, and an export would write both.
            if entry.dn() == base_dn || entry.dn() == users_ou_dn || entry.dn() == groups_ou_dn {
                continue;
            }

            if is_descendant(entry.dn(), &users_ou_dn) {
                users.push(entry);
            } else if is_descendant(entry.dn(), &groups_ou_dn) {
                groups.push(entry);
            } else {
                other.push(entry);
            }
        }
        users.sort_by(|left, right| left.dn().cmp(right.dn()));
        groups.sort_by(|left, right| left.dn().cmp(right.dn()));
        other.sort_by(|left, right| left.dn().cmp(right.dn()));

        let users_start = entries.len();
        entries.extend(users);
        let users_range = users_start..entries.len();

        let groups_start = entries.len();
        entries.extend(groups);
        let groups_range = groups_start..entries.len();

        entries.extend(other);

        Self::assemble(
            base_dn,
            users_ou_name,
            groups_ou_name,
            entries,
            users_range,
            groups_range,
        )
    }

    fn assemble(
        base_dn: String,
        users_ou_name: String,
        groups_ou_name: String,
        entries: Vec<Entry>,
        users: Range<usize>,
        groups: Range<usize>,
    ) -> Self {
        let mut by_dn = HashMap::with_capacity(entries.len());
        for (position, entry) in entries.iter().enumerate() {
            by_dn.insert(entry.dn().to_string(), position);
        }

        Self {
            base_dn,
            users_ou_name,
            groups_ou_name,
            entries,
            users,
            groups,
            by_dn,
            // Zero until the source that built it says which snapshot this is: a directory
            // built by hand in a test has no history to be inconsistent with.
            snapshot: 0,
            index: Arc::new(Index::default()),
        }
    }

    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }

    pub fn users_ou_name(&self) -> &str {
        &self.users_ou_name
    }

    pub fn groups_ou_name(&self) -> &str {
        &self.groups_ou_name
    }

    /// Users, in canonical order.
    pub fn users(&self) -> &[Entry] {
        &self.entries[self.users.clone()]
    }

    /// Groups, in canonical order.
    pub fn groups(&self) -> &[Entry] {
        &self.entries[self.groups.clone()]
    }

    pub fn ou_dn(&self, ou_name: &str) -> String {
        format!("ou={},{}", ou_name.to_lowercase(), self.base_dn)
    }

    pub fn user_dn(&self, cn: &str) -> String {
        format!(
            "cn={},{}",
            cn.to_lowercase(),
            self.ou_dn(&self.users_ou_name)
        )
    }

    pub fn group_dn(&self, cn: &str) -> String {
        format!(
            "cn={},{}",
            cn.to_lowercase(),
            self.ou_dn(&self.groups_ou_name)
        )
    }

    /// Every entry, in canonical order.
    pub fn all(&self) -> &[Entry] {
        &self.entries
    }

    /// Builds the configured indexes over this snapshot.
    ///
    /// Kept separate from the constructors so every existing caller keeps working
    /// without a configuration, and so a test can compare an indexed directory with
    /// the same directory unindexed.
    pub fn with_indexes(mut self, config: &IndexConfig) -> Result<Self, IndexError> {
        self.index = Arc::new(Index::build(&self.entries, config)?);
        Ok(self)
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Position of an entry in the canonical order, which is its id in the indexes.
    pub fn position(&self, entry_dn: &str) -> Option<usize> {
        self.by_dn.get(&dn::normalize(entry_dn)).copied()
    }

    /// Entries matching `base_object` and `scope` together with their ids.
    pub fn entries_with_ids(&self, base_object: &str, scope: Scope) -> Vec<(usize, &Entry)> {
        let base_object = dn::normalize(base_object);

        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| in_scope(entry.dn(), &base_object, scope))
            .collect()
    }

    /// Candidate ids for a query, or `None` when the index cannot help.
    pub fn candidates(&self, query: &Query) -> Option<roaring::RoaringBitmap> {
        self.index.candidates(query)
    }

    /// Entries matching `base_object` and `scope`, in canonical order.
    pub fn entries(&self, base_object: &str, scope: Scope) -> Vec<&Entry> {
        let base_object = dn::normalize(base_object);

        self.entries
            .iter()
            .filter(|entry| in_scope(entry.dn(), &base_object, scope))
            .collect()
    }

    /// Finds the entry addressed by `entry`.
    ///
    /// A DN is looked up directly. When that fails and the RDN names a user by `cn`
    /// or `uid`, the entry is looked up by that attribute inside the users OU:
    /// gorestldap accepted `uid=alice,ou=users,…` for an entry named
    /// `cn=alice,ou=users,…`, and clients rely on it.
    pub fn find(&self, entry: &str) -> Option<&Entry> {
        let entry = dn::normalize(entry);

        if let Some(position) = self.by_dn.get(&entry) {
            return self.entries.get(*position);
        }

        let (attribute, value, suffix) = dn::split_first_rdn(&entry);
        if attribute != "cn" && attribute != "uid" {
            return None;
        }
        if suffix != self.ou_dn(&self.users_ou_name) {
            return None;
        }

        self.users().iter().find(|candidate| {
            candidate
                .attributes()
                .get(&attribute)
                .is_some_and(|attribute| {
                    attribute
                        .values
                        .iter()
                        .any(|candidate| candidate.to_lowercase() == value)
                })
        })
    }

    /// True when the entry `user_dn` is a member of the group with `cn`.
    ///
    /// Groups hold `memberUid`, which carries the user's `uid` (gorestldap
    /// semantics) or, in older data, the `cn`; both are accepted.
    pub fn is_member(&self, group_cn: &str, user_dn: &str) -> bool {
        let Some(user) = self.find(user_dn) else {
            return false;
        };
        let group_cn = group_cn.to_lowercase();
        let Some(group) = self
            .groups()
            .iter()
            .find(|group| dn::first_value(group.dn()).as_deref() == Some(group_cn.as_str()))
        else {
            return false;
        };
        let Some(members) = group.attributes().get("memberUid") else {
            return false;
        };

        let uid = first_value(user.attributes(), "uid")
            .unwrap_or_default()
            .to_lowercase();
        let cn = first_value(user.attributes(), "cn")
            .unwrap_or_default()
            .to_lowercase();

        members.values.iter().any(|member| {
            let member = member.to_lowercase();
            (!uid.is_empty() && member == uid) || (!cn.is_empty() && member == cn)
        })
    }

    /// Number of entries; used by logging and tests.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn first_value(attributes: &Attributes, name: &str) -> Option<String> {
    attributes
        .get(name)
        .and_then(|attribute| attribute.values.first().cloned())
}

fn domain_entry(base_dn: &str) -> Entry {
    let attributes = Attributes::new()
        .push(Attribute::new(
            ATTR_OBJECT_CLASS,
            vec!["top".to_string(), "domain".to_string()],
        ))
        .push(Attribute::single(ATTR_ENTRY_UUID, &entry_uuid(base_dn)).operational())
        .push(Attribute::single(ATTR_HAS_SUBORDINATES, "TRUE").operational());

    Entry::new(base_dn.to_string(), attributes)
}

fn ou_entry(ou_name: &str, base_dn: &str) -> Entry {
    let ou_dn = format!("ou={ou_name},{base_dn}");
    let attributes = Attributes::new()
        .push(Attribute::new(
            ATTR_OBJECT_CLASS,
            vec!["top".to_string(), "organizationalUnit".to_string()],
        ))
        .push(Attribute::single(ATTR_ENTRY_UUID, &entry_uuid(&ou_dn)).operational())
        .push(Attribute::single(ATTR_HAS_SUBORDINATES, "TRUE").operational());

    Entry::new(ou_dn, attributes)
}

/// Deterministic entry UUID: UUIDv5 in the OID namespace, as gorestldap does.
fn entry_uuid(dn: &str) -> String {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, dn.as_bytes()).to_string()
}

fn in_scope(entry_dn: &str, base_object: &str, scope: Scope) -> bool {
    match scope {
        Scope::Base => entry_dn == base_object,
        Scope::OneLevel => is_direct_child(entry_dn, base_object),
        Scope::Subtree => entry_dn == base_object || is_descendant(entry_dn, base_object),
    }
}

fn is_descendant(entry_dn: &str, base_object: &str) -> bool {
    entry_dn
        .strip_suffix(base_object)
        .and_then(|head| head.strip_suffix(','))
        .is_some()
}

fn is_direct_child(entry_dn: &str, base_object: &str) -> bool {
    match entry_dn
        .strip_suffix(base_object)
        .and_then(|head| head.strip_suffix(','))
    {
        Some(rdn) => !rdn.contains(','),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "dc=example,dc=com";
    const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
    const ALICE_DN: &str = "cn=alice cooper,ou=users,dc=example,dc=com";
    const GROUP_DN: &str = "cn=group_a,ou=groups,dc=example,dc=com";

    fn admin() -> User {
        User {
            ldap_admin: true,
            cn: "admin".to_string(),
            uid: Some("admin".to_string()),
            object_class: vec!["top".to_string()],
            ..User::default()
        }
    }

    fn alice() -> User {
        User {
            cn: "Alice Cooper".to_string(),
            uid: Some("alice".to_string()),
            object_class: vec!["top".to_string()],
            ..User::default()
        }
    }

    fn group(name: &str) -> Group {
        Group {
            cn: name.to_string(),
            member_uid: vec!["admin".to_string()],
            object_class: vec!["top".to_string()],
            ..Group::default()
        }
    }

    fn directory() -> Directory {
        Directory::new(
            BASE,
            "users",
            "groups",
            vec![admin(), alice()],
            vec![group("primary_group"), group("group_a")],
        )
    }

    fn dns(entries: &[&Entry]) -> Vec<String> {
        entries.iter().map(|entry| entry.dn().to_string()).collect()
    }

    #[test]
    fn a_store_that_carries_the_base_and_the_units_does_not_get_them_twice() {
        // An imported or migrated store holds its own `dc=` and `ou=` entries. Synthesising
        // them on top would put two entries with the same DN in the directory: a search
        // returns both and an export writes both, which is how a round trip through
        // `--export-ldif` came to hold `dc=example,dc=com` twice.
        let base = "dc=example,dc=com";
        let users = "ou=users,dc=example,dc=com";
        let groups = "ou=groups,dc=example,dc=com";

        let stored = vec![
            Entry::new(
                base,
                Attributes::new()
                    .push(Attribute::single("objectClass", "top"))
                    .push(Attribute::single("objectClass", "domain"))
                    .push(Attribute::single("dc", "example")),
            ),
            Entry::new(
                users,
                Attributes::new()
                    .push(Attribute::single("objectClass", "organizationalUnit"))
                    .push(Attribute::single("ou", "users")),
            ),
        ];

        let directory = Directory::from_entries(base, "users", "groups", stored);

        let dns: Vec<&str> = directory.all().iter().map(|entry| entry.dn()).collect();
        assert_eq!(
            dns.iter().filter(|dn| **dn == base).count(),
            1,
            "the base appears once, whichever side supplied it: {dns:?}"
        );
        assert_eq!(
            dns.iter().filter(|dn| **dn == users).count(),
            1,
            "and so does the users unit: {dns:?}"
        );
        // The unit the store did not carry is still synthesised.
        assert!(dns.contains(&groups));
    }

    #[test]
    fn dns_follow_the_gorestldap_layout() {
        let directory = directory();

        assert_eq!(directory.base_dn(), BASE);
        assert_eq!(directory.user_dn("admin"), ADMIN_DN);
        assert_eq!(directory.user_dn("Alice Cooper"), ALICE_DN);
        assert_eq!(directory.group_dn("group_a"), GROUP_DN);
        assert_eq!(directory.ou_dn("users"), "ou=users,dc=example,dc=com");
    }

    #[test]
    fn entries_are_ordered_domain_ous_users_groups() {
        let directory = directory();
        let all: Vec<&Entry> = directory.all().iter().collect();

        assert_eq!(
            dns(&all),
            vec![
                "dc=example,dc=com",
                "ou=users,dc=example,dc=com",
                "ou=groups,dc=example,dc=com",
                ADMIN_DN,
                ALICE_DN,
                "cn=primary_group,ou=groups,dc=example,dc=com",
                GROUP_DN,
            ]
        );
        assert_eq!(directory.users().len(), 2);
        assert_eq!(directory.groups().len(), 2);
        assert_eq!(directory.len(), 7);
    }

    #[test]
    fn base_scope_returns_only_the_named_entry() {
        let directory = directory();

        let entries = directory.entries("CN=Admin, ou=USERS, dc=example, dc=com", Scope::Base);

        assert_eq!(dns(&entries), vec![ADMIN_DN]);
    }

    #[test]
    fn one_level_scope_of_the_root_returns_the_ous() {
        let directory = directory();

        assert_eq!(
            dns(&directory.entries(BASE, Scope::OneLevel)),
            vec!["ou=users,dc=example,dc=com", "ou=groups,dc=example,dc=com"]
        );
    }

    #[test]
    fn one_level_scope_of_users_ou_returns_users_only() {
        let directory = directory();

        assert_eq!(
            dns(&directory.entries("ou=users,dc=example,dc=com", Scope::OneLevel)),
            vec![ADMIN_DN, ALICE_DN]
        );
    }

    #[test]
    fn subtree_scope_of_the_root_returns_everything() {
        assert_eq!(directory().entries(BASE, Scope::Subtree).len(), 7);
    }

    #[test]
    fn subtree_scope_of_a_leaf_returns_the_leaf_itself() {
        let directory = directory();

        assert_eq!(
            dns(&directory.entries(ADMIN_DN, Scope::Subtree)),
            vec![ADMIN_DN]
        );
    }

    #[test]
    fn unknown_base_object_returns_nothing() {
        let directory = directory();

        assert!(
            directory
                .entries("ou=nothing,dc=example,dc=com", Scope::Subtree)
                .is_empty()
        );
    }

    #[test]
    fn find_resolves_every_entry_by_dn() {
        let directory = directory();

        for expected in [
            "dc=example,dc=com",
            "ou=groups,dc=example,dc=com",
            ADMIN_DN,
            ALICE_DN,
            GROUP_DN,
        ] {
            assert_eq!(
                directory.find(expected).map(|entry| entry.dn()),
                Some(expected),
                "expected to find {expected}"
            );
        }
    }

    #[test]
    fn find_accepts_a_uid_rdn_for_an_entry_named_by_cn() {
        let directory = directory();

        let entry = directory
            .find("uid=alice,ou=users,dc=example,dc=com")
            .expect("user by uid");

        assert_eq!(entry.dn(), ALICE_DN);
    }

    #[test]
    fn find_is_case_insensitive_and_tolerates_spaces() {
        let directory = directory();

        assert!(
            directory
                .find("CN=ADMIN, OU=Users, DC=Example, DC=Com")
                .is_some()
        );
    }

    #[test]
    fn find_rejects_unknown_entries_and_wrong_suffix() {
        let directory = directory();

        assert!(
            directory
                .find("cn=nobody,ou=users,dc=example,dc=com")
                .is_none()
        );
        assert!(
            directory
                .find("cn=admin,ou=groups,dc=example,dc=com")
                .is_none()
        );
        assert!(directory.find("cn=admin,dc=example,dc=com").is_none());
        assert!(
            directory
                .find("uid=admin,ou=groups,dc=example,dc=com")
                .is_none()
        );
    }

    #[test]
    fn domain_ou_uuids_are_deterministic_and_distinct() {
        let uuids = |directory: &Directory| -> Vec<Option<String>> {
            directory
                .all()
                .iter()
                .take(3)
                .map(|entry| {
                    entry
                        .attributes()
                        .get(ATTR_ENTRY_UUID)
                        .map(|attribute| attribute.values.join(","))
                })
                .collect()
        };

        let first = uuids(&directory());
        let second = uuids(&directory());

        assert_eq!(first, second, "same data must give the same uuids");
        assert_ne!(first[0], first[1], "domain and users ou differ");
    }

    #[test]
    fn domain_entry_is_marked_with_subordinates() {
        let directory = directory();
        let domain = directory.find(BASE).expect("domain");

        assert_eq!(
            domain
                .attributes()
                .get(ATTR_HAS_SUBORDINATES)
                .map(|attribute| attribute.values.to_vec()),
            Some(vec!["TRUE".to_string()])
        );
    }

    #[test]
    fn empty_directory_still_exposes_domain_and_ous() {
        let directory = Directory::new(BASE, "users", "groups", vec![], vec![]);

        assert_eq!(directory.len(), 3);
        assert!(directory.users().is_empty());
    }

    #[test]
    fn membership_uses_uid_or_cn_from_member_uid() {
        let directory = directory();

        assert!(directory.is_member("group_a", ADMIN_DN));
        assert!(directory.is_member("GROUP_A", ADMIN_DN), "case insensitive");
        assert!(!directory.is_member("group_a", ALICE_DN));
        assert!(!directory.is_member("nosuchgroup", ADMIN_DN));
        assert!(
            !directory.is_member("group_a", "cn=nobody,ou=users,dc=example,dc=com"),
            "unknown member is never a member"
        );
    }

    #[test]
    fn membership_matches_member_uid_against_cn_too() {
        let directory = Directory::new(
            BASE,
            "users",
            "groups",
            vec![User {
                cn: "Alice Cooper".to_string(),
                object_class: vec!["top".to_string()],
                ..User::default()
            }],
            vec![Group {
                cn: "old_group".to_string(),
                member_uid: vec!["alice cooper".to_string()],
                object_class: vec!["top".to_string()],
                ..Group::default()
            }],
        );

        assert!(directory.is_member("old_group", ALICE_DN));
    }

    #[test]
    fn from_entries_places_entries_below_their_ou() {
        let directory = Directory::from_entries(
            BASE,
            "users",
            "groups",
            vec![
                Entry::new(
                    GROUP_DN,
                    Attributes::new().push(Attribute::single("cn", "group_a")),
                ),
                Entry::new(
                    ADMIN_DN,
                    Attributes::new().push(Attribute::single("cn", "admin")),
                ),
                Entry::new(
                    "cn=unrelated,ou=people,dc=example,dc=com",
                    Attributes::new().push(Attribute::single("cn", "unrelated")),
                ),
            ],
        );

        assert_eq!(directory.users().len(), 1);
        assert_eq!(directory.groups().len(), 1);
        assert_eq!(directory.len(), 6, "domain, two ous and three entries");
        assert_eq!(
            directory.users()[0].dn(),
            ADMIN_DN,
            "users keep their place in the canonical order"
        );
        assert!(
            directory
                .find("cn=unrelated,ou=people,dc=example,dc=com")
                .is_some()
        );
    }
}
