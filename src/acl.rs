//! Access control.
//!
//! gorestldap had one flag: `ldapAdmin` could do anything, everyone else could
//! only touch their own entry, and `userPassword` was returned to anyone who could
//! read the entry. Here access is a list of rules evaluated in order — the first
//! rule that matches the requester, the entry and the attribute decides.
//!
//! A rule with an empty `rights` list is an explicit deny: it matches and grants
//! nothing, which is how `userPassword` is kept away from its own owner without
//! special-casing the attribute in code.

use serde::Deserialize;
use thiserror::Error;

use crate::directory::Directory;
use crate::dn;

/// Who is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// No identity (an anonymous session).
    Anonymous,
    /// Any bound identity.
    Users,
    /// The bound identity is the entry itself.
    SelfEntry,
    /// The identity carries the directory's admin flag.
    Admin,
    /// One specific entry.
    Dn(String),
    /// A member of the named group.
    Group(String),
}

/// What may be done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rights {
    pub read: bool,
    pub search: bool,
    pub compare: bool,
    pub write: bool,
    pub auth: bool,
}

impl Rights {
    pub const fn none() -> Self {
        Self {
            read: false,
            search: false,
            compare: false,
            write: false,
            auth: false,
        }
    }

    pub const fn all() -> Self {
        Self {
            read: true,
            search: true,
            compare: true,
            write: true,
            auth: true,
        }
    }

    /// Rights for a regular user on their own entry: everything except reading the
    /// password hash, which is granted separately if the operator wants it.
    pub const fn self_service() -> Self {
        Self {
            read: true,
            search: true,
            compare: true,
            write: true,
            auth: true,
        }
    }
}

/// One rule: subject + entry scope + attribute scope -> rights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub subject: Subject,
    /// DN the rule applies to (the entry itself or anything below it).
    pub base: Option<String>,
    /// Attribute names the rule covers; empty or `*` means every attribute.
    pub attributes: Vec<String>,
    pub rights: Rights,
}

impl Rule {
    fn matches_entry(&self, requester: &Requester, directory: &Directory, entry_dn: &str) -> bool {
        if !self.matches_subject(requester, directory, entry_dn) {
            return false;
        }
        match &self.base {
            None => true,
            Some(base) => {
                let entry_dn = dn::normalize(entry_dn);
                entry_dn == *base
                    || entry_dn
                        .strip_suffix(base.as_str())
                        .and_then(|head| head.strip_suffix(','))
                        .is_some()
            }
        }
    }

    fn matches_subject(
        &self,
        requester: &Requester,
        directory: &Directory,
        entry_dn: &str,
    ) -> bool {
        match &self.subject {
            Subject::Anonymous => requester.dn.is_none(),
            Subject::Users => requester.dn.is_some(),
            Subject::SelfEntry => requester
                .dn
                .as_deref()
                .is_some_and(|bound| bound == dn::normalize(entry_dn)),
            Subject::Admin => requester.admin,
            Subject::Dn(rule_dn) => requester.dn.as_deref() == Some(rule_dn.as_str()),
            Subject::Group(group) => requester.holds_group(group, directory),
        }
    }

    fn covers(&self, attribute: Option<&str>) -> bool {
        if self.attributes.is_empty() || self.attributes.iter().any(|name| name == "*") {
            return true;
        }
        match attribute {
            None => false,
            Some(attribute) => self
                .attributes
                .iter()
                .any(|name| name.eq_ignore_ascii_case(attribute)),
        }
    }
}

/// The party asking for access.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Requester {
    /// Normalized DN of the bound entry, `None` when anonymous.
    pub dn: Option<String>,
    /// The bound entry carries the backend's admin flag.
    pub admin: bool,
    /// Group entries the session holds by its ticket rather than by `memberUid`.
    ///
    /// A Windows client's memberships come from the PAC; this directory's groups were never told
    /// about them. Kept here so the rules below ask one question - "does this session hold that
    /// group" - and not two.
    pub groups: Vec<String>,
}

impl Requester {
    pub fn anonymous() -> Self {
        Self::default()
    }

    pub fn new(dn: &str, admin: bool) -> Self {
        Self {
            dn: Some(dn::normalize(dn)),
            admin,
            groups: Vec::new(),
        }
    }

    /// Whether the session holds this group, by the directory's own membership or by its ticket.
    ///
    /// `group` is the name a rule wrote (`group=admins`), matched against the naming attribute of
    /// the group entries the ticket granted - the same way [`Directory::is_member`] matches it
    /// against the directory's own groups.
    pub fn holds_group(&self, group: &str, directory: &Directory) -> bool {
        if let Some(bound) = self.dn.as_deref()
            && directory.is_member(group, bound)
        {
            return true;
        }

        let wanted = group.trim().to_lowercase();
        self.groups.iter().any(|dn| {
            crate::dn::first_value(dn).is_some_and(|name| name.eq_ignore_ascii_case(&wanted))
        })
    }
}

/// Ordered rule list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    rules: Vec<Rule>,
}

impl Default for Acl {
    /// Defaults keep the gorestldap model (admin sees everything, a user sees
    /// their own entry) but close the `userPassword` hole: the hash is readable by
    /// an admin only, and never through `*`.
    fn default() -> Self {
        Self {
            rules: vec![
                Rule {
                    subject: Subject::Admin,
                    base: None,
                    attributes: vec!["*".to_string()],
                    rights: Rights::all(),
                },
                Rule {
                    subject: Subject::SelfEntry,
                    base: None,
                    attributes: vec!["userPassword".to_string()],
                    rights: Rights::none(),
                },
                Rule {
                    subject: Subject::SelfEntry,
                    base: None,
                    attributes: vec!["*".to_string()],
                    rights: Rights::self_service(),
                },
            ],
        }
    }
}

impl Acl {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Rights granted for `attribute` on `entry_dn`; `None` asks about the entry
    /// itself (for search/compare/auth on the whole record).
    ///
    /// The first matching rule decides, so a deny placed before a broader grant
    /// wins.
    pub fn rights(
        &self,
        requester: &Requester,
        directory: &Directory,
        entry_dn: &str,
        attribute: Option<&str>,
    ) -> Rights {
        self.rules
            .iter()
            .find(|rule| {
                rule.matches_entry(requester, directory, entry_dn) && rule.covers(attribute)
            })
            .map(|rule| rule.rights)
            .unwrap_or_default()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AclError {
    #[error(
        "unknown access subject '{0}', expected admin, users, anonymous, self, dn=<dn> or group=<cn>"
    )]
    UnknownSubject(String),
    #[error("unknown access right '{0}', expected read, search, compare, write or auth")]
    UnknownRight(String),
}

/// `access:` entry of the configuration file.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessRuleConfig {
    pub subject: String,
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub attributes: Vec<String>,
    #[serde(default)]
    pub rights: Vec<String>,
}

impl AccessRuleConfig {
    fn into_rule(self) -> Result<Rule, AclError> {
        let subject = parse_subject(&self.subject)?;

        let mut rights = Rights::none();
        for right in &self.rights {
            match right.trim().to_ascii_lowercase().as_str() {
                "read" => rights.read = true,
                "search" => rights.search = true,
                "compare" => rights.compare = true,
                "write" => rights.write = true,
                "auth" => rights.auth = true,
                other => return Err(AclError::UnknownRight(other.to_string())),
            }
        }
        if self.rights.is_empty() && !self.attributes.is_empty() {
            // An empty rights list on an attribute rule is a deny; say so in the
            // log rather than silently granting nothing everywhere.
            rights = Rights::none();
        }

        Ok(Rule {
            subject,
            base: self.base.as_deref().map(dn::normalize),
            attributes: self.attributes,
            rights,
        })
    }
}

fn parse_subject(subject: &str) -> Result<Subject, AclError> {
    let subject = subject.trim();
    let lower = subject.to_ascii_lowercase();

    if lower == "admin" {
        return Ok(Subject::Admin);
    }
    if lower == "users" {
        return Ok(Subject::Users);
    }
    if lower == "anonymous" {
        return Ok(Subject::Anonymous);
    }
    if lower == "self" {
        return Ok(Subject::SelfEntry);
    }
    if let Some(rest) = lower.strip_prefix("dn=") {
        return Ok(Subject::Dn(dn::normalize(rest)));
    }
    if let Some(rest) = lower.strip_prefix("group=") {
        return Ok(Subject::Group(rest.trim().to_string()));
    }

    Err(AclError::UnknownSubject(subject.to_string()))
}

/// Builds the ACL from the configuration; `None` keeps the default policy.
pub fn from_config(rules: Option<&[AccessRuleConfig]>) -> Result<Acl, AclError> {
    match rules {
        None => Ok(Acl::default()),
        Some(rules) => Ok(Acl::new(
            rules
                .iter()
                .cloned()
                .map(AccessRuleConfig::into_rule)
                .collect::<Result<Vec<_>, _>>()?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Group, User};

    const BASE: &str = "dc=example,dc=com";
    const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
    const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";

    fn directory() -> Directory {
        Directory::new(
            BASE,
            "users",
            "groups",
            vec![
                User {
                    cn: "admin".to_string(),
                    uid: Some("admin".to_string()),
                    ldap_admin: true,
                    ..User::default()
                },
                User {
                    cn: "alice".to_string(),
                    uid: Some("alice".to_string()),
                    ..User::default()
                },
            ],
            vec![Group {
                cn: "auditors".to_string(),
                member_uid: vec!["alice".to_string()],
                ..Group::default()
            }],
        )
    }

    fn admin() -> Requester {
        Requester::new(ADMIN_DN, true)
    }

    fn alice() -> Requester {
        Requester::new(ALICE_DN, false)
    }

    fn rule_for(subject: &str) -> Acl {
        from_config(Some(&[AccessRuleConfig {
            subject: subject.to_string(),
            base: None,
            attributes: Vec::new(),
            rights: vec!["read".to_string(), "search".to_string()],
        }]))
        .expect("the rule parses")
    }

    #[test]
    fn a_group_from_a_ticket_counts_as_membership_without_a_member_uid_entry() {
        // The Windows case: the client's groups arrive in the PAC, and no entry in this directory
        // lists the client as a `memberUid` - it never asked to be one. A rule that names the group
        // has to hold all the same, or every AD client with kerberos is denied what its groups
        // grant. Driven through `rights`, which is the decision a search actually asks for, so the
        // test fails if `matches_subject` stops consulting the ticket.
        let directory = directory();

        // `auditors` lists alice as a member, and alice's ticket can say the same thing: two
        // paths, one answer.
        let by_directory = rule_for("group=auditors");
        assert!(
            by_directory
                .rights(&alice(), &directory, ALICE_DN, None)
                .read
        );
        let ticket_says_so = Requester {
            dn: Some(dn::normalize(ALICE_DN)),
            admin: false,
            groups: vec!["cn=auditors,ou=groups,dc=example,dc=com".to_string()],
        };
        assert!(
            by_directory
                .rights(&ticket_says_so, &directory, ALICE_DN, None)
                .read
        );

        // A group the ticket holds and the directory knows nothing about still counts, which is
        // the whole point: it is how an AD group reaches a rule here without being imported.
        let admins = rule_for("group=Domain Admins");
        let outsider = Requester {
            dn: Some(dn::normalize(ALICE_DN)),
            admin: false,
            groups: vec!["cn=Domain Admins,ou=groups,dc=example,dc=com".to_string()],
        };
        assert!(admins.rights(&outsider, &directory, ALICE_DN, None).read);
        assert!(
            !admins.rights(&alice(), &directory, ALICE_DN, None).read,
            "without the ticket there is no membership, so the two paths are not confused"
        );

        // And the directory's own answer is not widened by having a ticket at all.
        assert!(
            !by_directory
                .rights(&admin(), &directory, ALICE_DN, None)
                .read
        );
    }

    #[test]
    fn admin_reads_every_attribute_including_the_password() {
        let acl = Acl::default();
        let directory = directory();

        assert!(
            acl.rights(&admin(), &directory, ALICE_DN, Some("userPassword"))
                .read
        );
        assert!(acl.rights(&admin(), &directory, BASE, None).search);
    }

    #[test]
    fn owner_reads_own_entry_but_not_the_password_hash() {
        let acl = Acl::default();
        let directory = directory();

        assert!(
            acl.rights(&alice(), &directory, ALICE_DN, Some("mail"))
                .read
        );
        assert!(
            !acl.rights(&alice(), &directory, ALICE_DN, Some("userPassword"))
                .read,
            "an owner must not read their own hash"
        );
        assert!(acl.rights(&alice(), &directory, ALICE_DN, None).auth);
    }

    #[test]
    fn owner_cannot_read_other_entries() {
        let acl = Acl::default();
        let directory = directory();

        let rights = acl.rights(&alice(), &directory, ADMIN_DN, Some("mail"));

        assert_eq!(rights, Rights::none());
    }

    #[test]
    fn anonymous_gets_nothing() {
        let acl = Acl::default();
        let directory = directory();

        assert_eq!(
            acl.rights(&Requester::anonymous(), &directory, BASE, None),
            Rights::none()
        );
    }

    #[test]
    fn first_matching_rule_wins_so_deny_before_grant_holds() {
        let acl = Acl::new(vec![
            Rule {
                subject: Subject::Users,
                base: None,
                attributes: vec!["userPassword".to_string()],
                rights: Rights::none(),
            },
            Rule {
                subject: Subject::Users,
                base: None,
                attributes: vec!["*".to_string()],
                rights: Rights::all(),
            },
        ]);
        let directory = directory();

        assert!(
            !acl.rights(&alice(), &directory, ALICE_DN, Some("userPassword"))
                .read
        );
        assert!(
            acl.rights(&alice(), &directory, ALICE_DN, Some("mail"))
                .read
        );
    }

    #[test]
    fn base_limits_the_rule_to_a_subtree() {
        let acl = Acl::new(vec![Rule {
            subject: Subject::Users,
            base: Some("ou=users,dc=example,dc=com".to_string()),
            attributes: vec!["*".to_string()],
            rights: Rights {
                read: true,
                ..Rights::none()
            },
        }]);
        let directory = directory();

        assert!(
            acl.rights(&alice(), &directory, ALICE_DN, Some("mail"))
                .read
        );
        assert!(
            !acl.rights(
                &alice(),
                &directory,
                "cn=group_a,ou=groups,dc=example,dc=com",
                Some("cn")
            )
            .read
        );
    }

    #[test]
    fn group_subject_uses_directory_membership() {
        let acl = Acl::new(vec![Rule {
            subject: Subject::Group("auditors".to_string()),
            base: None,
            attributes: vec!["mail".to_string()],
            rights: Rights {
                read: true,
                ..Rights::none()
            },
        }]);
        let directory = directory();

        assert!(acl.rights(&alice(), &directory, BASE, Some("mail")).read);
        assert!(!acl.rights(&admin(), &directory, BASE, Some("mail")).read);
        assert!(!acl.rights(&alice(), &directory, BASE, Some("cn")).read);
    }

    #[test]
    fn dn_subject_matches_exactly_one_identity() {
        let acl = Acl::new(vec![Rule {
            subject: Subject::Dn(dn::normalize(ALICE_DN)),
            base: None,
            attributes: vec![],
            rights: Rights {
                read: true,
                ..Rights::none()
            },
        }]);
        let directory = directory();

        assert!(acl.rights(&alice(), &directory, BASE, Some("cn")).read);
        assert!(!acl.rights(&admin(), &directory, BASE, Some("cn")).read);
    }

    #[test]
    fn config_rules_are_parsed_with_names_and_rights() {
        let config = vec![AccessRuleConfig {
            subject: "group=auditors".to_string(),
            base: Some("DC=Example, DC=Com".to_string()),
            attributes: vec!["cn".to_string(), "mail".to_string()],
            rights: vec!["read".to_string(), "compare".to_string()],
        }];

        let acl = from_config(Some(&config)).expect("acl");
        let rule = &acl.rules()[0];

        assert_eq!(rule.subject, Subject::Group("auditors".to_string()));
        assert_eq!(rule.base.as_deref(), Some(BASE));
        assert!(rule.rights.read && rule.rights.compare);
        assert!(!rule.rights.write && !rule.rights.auth && !rule.rights.search);
    }

    #[test]
    fn unknown_subject_and_right_are_rejected() {
        let subject = AccessRuleConfig {
            subject: "everyone".to_string(),
            base: None,
            attributes: vec![],
            rights: vec!["read".to_string()],
        };
        assert_eq!(
            from_config(Some(&[subject])),
            Err(AclError::UnknownSubject("everyone".to_string()))
        );

        let right = AccessRuleConfig {
            subject: "users".to_string(),
            base: None,
            attributes: vec![],
            rights: vec!["delete".to_string()],
        };
        assert_eq!(
            from_config(Some(&[right])),
            Err(AclError::UnknownRight("delete".to_string()))
        );
    }

    #[test]
    fn empty_config_list_is_an_empty_acl() {
        let acl = from_config(Some(&[])).expect("acl");

        assert!(
            acl.rules().is_empty(),
            "an explicit empty list grants nothing"
        );
    }
}
