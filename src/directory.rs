//! In-memory directory: entries, their DNs, lookup and scope traversal.
//!
//! The directory is immutable: a reload builds a new one and the server swaps the
//! reference, so a request never observes a half-updated tree and no lock has to
//! guard entry mutation.

use uuid::Uuid;

use crate::dn;
use crate::model::{Attributes, Domain, Group, OrganizationalUnit, User};

/// Search scope, mirroring RFC 4511 values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Base,
    OneLevel,
    Subtree,
}

/// A reference to one entry of the directory.
#[derive(Debug, Clone, Copy)]
pub enum Entry<'a> {
    Domain(&'a Domain),
    OrganizationalUnit(&'a OrganizationalUnit),
    User(&'a User),
    Group(&'a Group),
}

impl Entry<'_> {
    pub fn attributes(&self) -> Attributes {
        match self {
            Entry::Domain(entry) => entry.attributes(),
            Entry::OrganizationalUnit(entry) => entry.attributes(),
            Entry::User(entry) => entry.attributes(),
            Entry::Group(entry) => entry.attributes(),
        }
    }

    pub fn is_leaf(&self) -> bool {
        matches!(self, Entry::User(_) | Entry::Group(_))
    }
}

/// Directory contents loaded from a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    base_dn: String,
    users_ou_name: String,
    groups_ou_name: String,
    domain: Domain,
    ous: Vec<OrganizationalUnit>,
    users: Vec<User>,
    groups: Vec<Group>,
}

impl Directory {
    /// Builds the directory for `base_dn` with the given users and groups.
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

        let dc = dn::first_value(&base_dn).unwrap_or_default();
        let mut domain = Domain::new(&dc, None);
        domain.entry_uuid = Some(entry_uuid(&domain_dn(&base_dn)));
        domain.has_subordinates = Some("TRUE".to_string());

        let ous = [&users_ou_name, &groups_ou_name]
            .into_iter()
            .map(|name| {
                let ou_dn = ou_dn(name, &base_dn);
                let mut ou = OrganizationalUnit::new(name, None);
                ou.entry_uuid = Some(entry_uuid(&ou_dn));
                ou.has_subordinates = Some("TRUE".to_string());
                ou
            })
            .collect();

        Self {
            base_dn,
            users_ou_name,
            groups_ou_name,
            domain,
            ous,
            users,
            groups,
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

    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    pub fn users(&self) -> &[User] {
        &self.users
    }

    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    pub fn ou_dn(&self, ou_name: &str) -> String {
        ou_dn(ou_name, &self.base_dn)
    }

    pub fn user_dn(&self, user: &User) -> String {
        user_dn(user, &self.base_dn, &self.users_ou_name)
    }

    pub fn group_dn(&self, group: &Group) -> String {
        group_dn(group, &self.base_dn, &self.groups_ou_name)
    }

    /// DN of an entry.
    pub fn entry_dn(&self, entry: &Entry) -> String {
        match entry {
            Entry::Domain(_) => self.base_dn.clone(),
            Entry::OrganizationalUnit(ou) => self.ou_dn(&ou.ou),
            Entry::User(user) => self.user_dn(user),
            Entry::Group(group) => self.group_dn(group),
        }
    }

    /// All entries in the order the server returns them: the domain entry, the
    /// two organizational units, then users and groups.
    pub fn all(&self) -> Vec<Entry<'_>> {
        let mut out: Vec<Entry<'_>> = Vec::with_capacity(3 + self.users.len() + self.groups.len());
        out.push(Entry::Domain(&self.domain));
        for ou in &self.ous {
            out.push(Entry::OrganizationalUnit(ou));
        }
        for user in &self.users {
            out.push(Entry::User(user));
        }
        for group in &self.groups {
            out.push(Entry::Group(group));
        }
        out
    }

    /// Entries matching `base_object` and `scope`, in the canonical order.
    pub fn entries(&self, base_object: &str, scope: Scope) -> Vec<Entry<'_>> {
        let base_object = dn::normalize(base_object);

        self.all()
            .into_iter()
            .filter(|entry| in_scope(&self.entry_dn(entry), &base_object, scope))
            .collect()
    }

    /// Finds the entry addressed by `entry` (already normalized or not).
    ///
    /// Users can be addressed by `cn` or `uid`, groups by `cn`, organizational
    /// units by `ou`, the domain by its own base DN.
    pub fn find(&self, entry: &str) -> Option<Entry<'_>> {
        let entry = dn::normalize(entry);
        let (attribute, value, suffix) = dn::split_first_rdn(&entry);

        if entry == self.base_dn {
            return Some(Entry::Domain(&self.domain));
        }

        if suffix == self.base_dn
            && let Some(ou) = self.ous.iter().find(|ou| ou.ou == value)
        {
            return Some(Entry::OrganizationalUnit(ou));
        }

        if suffix == self.ou_dn(&self.users_ou_name) {
            let user = self.users.iter().find(|user| match attribute.as_str() {
                "cn" => user.cn.to_lowercase() == value,
                "uid" => user.uid.as_deref().map(str::to_lowercase) == Some(value.clone()),
                _ => false,
            });
            if let Some(user) = user {
                return Some(Entry::User(user));
            }
        }

        if suffix == self.ou_dn(&self.groups_ou_name) && attribute == "cn" {
            let group = self
                .groups
                .iter()
                .find(|group| group.cn.to_lowercase() == value);
            if let Some(group) = group {
                return Some(Entry::Group(group));
            }
        }

        None
    }
}

fn domain_dn(base_dn: &str) -> String {
    base_dn.to_string()
}

fn ou_dn(ou_name: &str, base_dn: &str) -> String {
    format!("ou={},{}", ou_name.to_lowercase(), base_dn)
}

fn user_dn(user: &User, base_dn: &str, users_ou_name: &str) -> String {
    format!(
        "cn={},{}",
        user.cn.to_lowercase(),
        ou_dn(users_ou_name, base_dn)
    )
}

fn group_dn(group: &Group, base_dn: &str, groups_ou_name: &str) -> String {
    format!(
        "cn={},{}",
        group.cn.to_lowercase(),
        ou_dn(groups_ou_name, base_dn)
    )
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

    fn admin() -> User {
        User {
            ldap_admin: true,
            cn: "admin".to_string(),
            uid: Some("admin".to_string()),
            ..User::default()
        }
    }

    fn alice() -> User {
        User {
            cn: "Alice Cooper".to_string(),
            uid: Some("alice".to_string()),
            ..User::default()
        }
    }

    fn group(name: &str) -> Group {
        Group {
            cn: name.to_string(),
            member_uid: vec!["admin".to_string()],
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

    fn dns(entries: &[Entry<'_>], dir: &Directory) -> Vec<String> {
        entries.iter().map(|entry| dir.entry_dn(entry)).collect()
    }

    #[test]
    fn dns_follow_the_gorestldap_layout() {
        let dir = directory();

        assert_eq!(dir.base_dn(), BASE);
        assert_eq!(dir.user_dn(&admin()), "cn=admin,ou=users,dc=example,dc=com");
        assert_eq!(
            dir.user_dn(&alice()),
            "cn=alice cooper,ou=users,dc=example,dc=com"
        );
        assert_eq!(
            dir.group_dn(&group("group_a")),
            "cn=group_a,ou=groups,dc=example,dc=com"
        );
        assert_eq!(dir.ou_dn("users"), "ou=users,dc=example,dc=com");
    }

    #[test]
    fn all_entries_are_ordered_domain_ous_users_groups() {
        let dir = directory();

        assert_eq!(
            dns(&dir.all(), &dir),
            vec![
                "dc=example,dc=com",
                "ou=users,dc=example,dc=com",
                "ou=groups,dc=example,dc=com",
                "cn=admin,ou=users,dc=example,dc=com",
                "cn=alice cooper,ou=users,dc=example,dc=com",
                "cn=primary_group,ou=groups,dc=example,dc=com",
                "cn=group_a,ou=groups,dc=example,dc=com",
            ]
        );
    }

    #[test]
    fn base_scope_returns_only_the_named_entry() {
        let dir = directory();

        let entries = dir.entries("CN=Admin, ou=USERS, dc=example, dc=com", Scope::Base);

        assert_eq!(
            dns(&entries, &dir),
            vec!["cn=admin,ou=users,dc=example,dc=com"]
        );
    }

    #[test]
    fn one_level_scope_of_the_root_returns_the_ous() {
        let dir = directory();

        let entries = dir.entries(BASE, Scope::OneLevel);

        assert_eq!(
            dns(&entries, &dir),
            vec!["ou=users,dc=example,dc=com", "ou=groups,dc=example,dc=com"]
        );
    }

    #[test]
    fn one_level_scope_of_users_ou_returns_users_only() {
        let dir = directory();

        let entries = dir.entries("ou=users,dc=example,dc=com", Scope::OneLevel);

        assert_eq!(
            dns(&entries, &dir),
            vec![
                "cn=admin,ou=users,dc=example,dc=com",
                "cn=alice cooper,ou=users,dc=example,dc=com",
            ]
        );
    }

    #[test]
    fn subtree_scope_of_the_root_returns_everything() {
        let dir = directory();

        assert_eq!(dir.entries(BASE, Scope::Subtree).len(), 7);
    }

    #[test]
    fn subtree_scope_of_a_leaf_returns_the_leaf_itself() {
        let dir = directory();

        let entries = dir.entries("cn=admin,ou=users,dc=example,dc=com", Scope::Subtree);

        assert_eq!(
            dns(&entries, &dir),
            vec!["cn=admin,ou=users,dc=example,dc=com"]
        );
    }

    #[test]
    fn unknown_base_object_returns_nothing() {
        let dir = directory();

        assert!(
            dir.entries("ou=nothing,dc=example,dc=com", Scope::Subtree)
                .is_empty()
        );
    }

    #[test]
    fn find_resolves_domain_ous_users_and_groups() {
        let dir = directory();

        assert!(matches!(
            dir.find("dc=example,dc=com"),
            Some(Entry::Domain(_))
        ));
        assert!(matches!(
            dir.find("ou=groups,dc=example,dc=com"),
            Some(Entry::OrganizationalUnit(_))
        ));
        assert!(matches!(
            dir.find("cn=admin,ou=users,dc=example,dc=com"),
            Some(Entry::User(_))
        ));
        assert!(matches!(
            dir.find("cn=group_a,ou=groups,dc=example,dc=com"),
            Some(Entry::Group(_))
        ));
    }

    #[test]
    fn find_accepts_uid_rdn_for_users() {
        let dir = directory();

        let entry = dir
            .find("uid=alice,ou=users,dc=example,dc=com")
            .expect("user by uid");

        assert!(matches!(entry, Entry::User(user) if user.cn == "Alice Cooper"));
    }

    #[test]
    fn find_is_case_insensitive_and_tolerates_spaces() {
        let dir = directory();

        assert!(dir.find("CN=ADMIN, OU=Users, DC=Example, DC=Com").is_some());
    }

    #[test]
    fn find_rejects_unknown_entries_and_wrong_suffix() {
        let dir = directory();

        assert!(dir.find("cn=nobody,ou=users,dc=example,dc=com").is_none());
        assert!(dir.find("cn=admin,ou=groups,dc=example,dc=com").is_none());
        assert!(dir.find("cn=admin,dc=example,dc=com").is_none());
        assert!(dir.find("uid=admin,ou=groups,dc=example,dc=com").is_none());
    }

    #[test]
    fn domain_ou_uuids_are_deterministic_and_distinct() {
        let first = directory();
        let second = directory();

        let uuid = |dir: &Directory, entry: &Entry<'_>| {
            dir.entry_dn(entry);
            match entry {
                Entry::Domain(domain) => domain.entry_uuid.clone(),
                Entry::OrganizationalUnit(ou) => ou.entry_uuid.clone(),
                _ => None,
            }
        };

        let left = first
            .all()
            .iter()
            .map(|entry| uuid(&first, entry))
            .collect::<Vec<_>>();
        let right = second
            .all()
            .iter()
            .map(|entry| uuid(&second, entry))
            .collect::<Vec<_>>();

        assert_eq!(left, right, "same data must give the same uuids");
        assert_ne!(left[0], left[1], "domain and users ou differ");
    }

    #[test]
    fn domain_entry_keeps_first_dc_and_has_subordinates() {
        let dir = directory();

        assert_eq!(dir.domain().dc, "example");
        assert_eq!(dir.domain().has_subordinates.as_deref(), Some("TRUE"));
    }

    #[test]
    fn empty_directory_still_exposes_domain_and_ous() {
        let dir = Directory::new(BASE, "users", "groups", vec![], vec![]);

        assert_eq!(dir.all().len(), 3);
    }
}
