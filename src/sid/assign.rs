//! Which entries get a SID, and what happens when one arrives already carrying it.
//!
//! The write path asks this module one question per add, and the answer has three branches that are
//! easy to get wrong in the same way - by being convenient:
//!
//! **A security principal gets one.** Not every entry: an `organizationalUnit` is not something a
//! ticket names and nobody grants it access, so a SID on one would be a number spent for nothing,
//! and the RID space is the one resource a domain cannot replenish.
//!
//! **An entry that arrived with one keeps it, in the form the store uses.** An import from an
//! existing directory carries `objectSid`, and that SID is what every ACL elsewhere already names -
//! replacing it with a fresh one would silently detach every permission from the account. The text
//! form is converted to the binary one, because an operator types `S-1-5-21-...` and the store's form
//! is octets.
//!
//! **A SID that is neither form is refused, not replaced.** An add that says `objectSid: garbage`
//! is a client that believes it is creating a specific account; quietly giving it a different
//! identity is the one outcome nobody can debug.
//!
//! # The RID is spent even if the write fails
//!
//! `assign` runs before the schema check, because the schema has something to say about
//! `objectSid` and checking it after the fact would check a different entry. So a write refused
//! later has spent a number. That is the intended trade: a number skipped is invisible, a number
//! reused is an account with somebody else's rights. The allocator records the position before the
//! SID is returned for exactly this reason.

use crate::model::{Attribute, Attributes};
use crate::security::Security;
use crate::sid::{ATTRIBUTE, Sid};

/// The object classes that make an entry a security principal, and so the thing a SID identifies.
///
/// `user` covers `computer`, which extends it in the AD schema; `group` is the other half of what
/// access control names. Nothing else: a SID on an OU or a container is a number spent for nothing.
const PRINCIPAL_CLASSES: [&str; 4] = ["user", "computer", "group", "inetorgperson"];

/// Whether an entry with these classes is something a ticket can name.
#[must_use]
pub fn is_principal(attributes: &Attributes) -> bool {
    let Some(classes) = attributes.get(crate::model::ATTR_OBJECT_CLASS) else {
        return false;
    };
    classes.values.iter().any(|class| {
        PRINCIPAL_CLASSES
            .iter()
            .any(|candidate| class.eq_ignore_ascii_case(candidate))
    })
}

/// What the write path should do with this entry's SID.
#[derive(Debug, PartialEq, Eq)]
pub enum Assigned {
    /// The entry has no SID and this server issues none: an ordinary directory.
    Nothing,
    /// The attribute was added, or its value rewritten in the store's form.
    Attribute(Attribute),
    /// The entry carried a SID this server cannot read.
    Refused(String),
}

impl Assigned {
    /// The attribute to write, if there is one.
    #[must_use]
    pub fn attribute(self) -> Option<Attribute> {
        match self {
            Assigned::Attribute(attribute) => Some(attribute),
            _ => None,
        }
    }
}

/// Decides the `objectSid` of a new entry.
///
/// Takes the attributes as the client sent them and the security policy of this server, and returns
/// what to write. The caller adds the attribute and lets the schema check the result - this function
/// deliberately does not write anything itself, so that a caller cannot forget the check.
pub fn decide(attributes: &Attributes, security: &Security) -> Assigned {
    let Some(issuer) = &security.domain else {
        // Not a domain. An entry may still carry a SID - an imported one - and it is converted so
        // that the store keeps one form, but nothing is issued.
        return match attributes.get(ATTRIBUTE) {
            Some(existing) => canonical(existing),
            None => Assigned::Nothing,
        };
    };

    match attributes.get(ATTRIBUTE) {
        Some(existing) => canonical(existing),
        None if is_principal(attributes) => match issuer.take() {
            Ok(sid) => Assigned::Attribute(sid.attribute(ATTRIBUTE)),
            // The counter is exhausted, or the store refused. Either way there is no identity to
            // give, and an account created without one would be an account no ACL can name.
            Err(err) => Assigned::Refused(err.to_string()),
        },
        None => Assigned::Nothing,
    }
}

/// The store's form of a SID the client supplied.
///
/// A client that wrote the text form gets it back as octets; a client that wrote base64 of the
/// octets gets exactly what it wrote. Either way the value is read once here, which is where a
/// malformed one is caught with a message about the SID rather than a schema violation about a
/// syntax.
fn canonical(existing: &Attribute) -> Assigned {
    let Some(value) = existing.values.first() else {
        return Assigned::Refused(format!("'{ATTRIBUTE}' has no value"));
    };
    match Sid::from_directory_value(value) {
        Ok(sid) => Assigned::Attribute(sid.attribute(ATTRIBUTE)),
        Err(err) => Assigned::Refused(format!("'{ATTRIBUTE}': {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::backend::Backend;
    use crate::sid::domain::{Domain, Issuer};
    use crate::sid::reserved;

    /// An issuer over a redb store in a temporary directory.
    fn issuer(dir: &std::path::Path) -> Arc<Issuer> {
        let path = dir.join("directory.redb");
        let text = format!(
            "base_dn: dc=example,dc=com\n\
             backend: redb\n\
             backends:\n  redb:\n    path: {}\n\
             indexes:\n  default: [pres, eq, sub]\n",
            path.display()
        );
        let config = crate::config::resolve(crate::config::Args::default(), Some(&text), |_| None)
            .expect("config");
        let backend = Backend::from_config("redb", config.backends.get("redb")).expect("backend");
        let domain = Domain::ensure(&backend, [42u8; 16]).expect("a domain");
        Arc::new(Issuer::new(backend, domain))
    }

    fn account(classes: &[&str]) -> Attributes {
        Attributes::new().push(Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            classes.iter().map(|class| (*class).to_string()).collect(),
        ))
    }

    #[test]
    fn a_new_account_gets_a_sid_from_the_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let issuer = issuer(dir.path());
        let security = Security::default().with_domain(Arc::clone(&issuer));

        let assigned = decide(&account(&["top", "person", "user"]), &security);
        let attribute = assigned.attribute().expect("a SID");

        let sid = Sid::from_directory_value(&attribute.values[0]).expect("a SID");
        assert_eq!(
            sid.parent(),
            Some(issuer.sid()),
            "the SID belongs to this domain"
        );
        assert_eq!(sid.rid(), Some(crate::sid::FIRST_UNRESERVED_RID));
        assert!(attribute.flags.binary, "the store's form is octets");
    }

    #[test]
    fn two_accounts_get_two_sids() {
        let dir = tempfile::tempdir().expect("tempdir");
        let security = Security::default().with_domain(issuer(dir.path()));

        let first = decide(&account(&["user"]), &security)
            .attribute()
            .expect("a SID");
        let second = decide(&account(&["user"]), &security)
            .attribute()
            .expect("a SID");

        assert_ne!(first.values[0], second.values[0]);
    }

    #[test]
    fn a_group_is_a_principal_and_an_ou_is_not() {
        // The rule that keeps the RID space for things access control can name. A SID on an OU
        // would be a number spent for nothing, and the space cannot be replenished.
        let dir = tempfile::tempdir().expect("tempdir");
        let security = Security::default().with_domain(issuer(dir.path()));

        assert!(is_principal(&account(&["top", "group"])));
        assert!(is_principal(&account(&[
            "top",
            "person",
            "organizationalPerson",
            "inetOrgPerson"
        ])));
        assert!(is_principal(&account(&["top", "user", "computer"])));
        assert!(!is_principal(&account(&["top", "organizationalUnit"])));
        assert!(!is_principal(&account(&[
            "top",
            "dcObject",
            "organization"
        ])));

        assert_eq!(
            decide(&account(&["top", "organizationalUnit"]), &security),
            Assigned::Nothing
        );
    }

    #[test]
    fn an_imported_sid_is_kept_and_rewritten_in_the_store_form() {
        // An import carries the SID every ACL elsewhere already names. Replacing it with a fresh one
        // would detach every permission from the account, silently.
        let dir = tempfile::tempdir().expect("tempdir");
        let issuer = issuer(dir.path());
        let security = Security::default().with_domain(Arc::clone(&issuer));

        let imported = Sid::parse("S-1-5-21-9-9-9-1500").expect("a SID");
        let attributes =
            account(&["user"]).push(Attribute::single(ATTRIBUTE, &imported.to_string()));

        let assigned = decide(&attributes, &security).attribute().expect("a SID");
        let written = Sid::from_directory_value(&assigned.values[0]).expect("a SID");

        assert_eq!(written, imported, "the imported identity is kept");
        assert_ne!(
            written.parent(),
            Some(issuer.sid()),
            "and it is not ours - which is exactly why it must not be replaced"
        );
        assert!(
            assigned.flags.binary,
            "the text form is converted, not stored as text"
        );
        // The counter did not move: nothing was issued.
        assert_eq!(issuer.peek(), crate::sid::FIRST_UNRESERVED_RID);
    }

    #[test]
    fn a_value_that_is_neither_form_is_refused_rather_than_replaced() {
        // A client that says `objectSid: garbage` believes it is creating a specific account.
        // Quietly giving it a different identity is the one outcome nobody can debug.
        let dir = tempfile::tempdir().expect("tempdir");
        let security = Security::default().with_domain(issuer(dir.path()));
        let attributes = account(&["user"]).push(Attribute::single(ATTRIBUTE, "garbage"));

        match decide(&attributes, &security) {
            Assigned::Refused(detail) => assert!(detail.contains("objectSid"), "{detail}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_directory_that_is_not_a_domain_issues_nothing() {
        // The ordinary case, and the reason this is opt-in: an LDAP server that has never heard of a
        // domain must not start handing out SIDs because it happens to hold a `user` entry.
        let security = Security::default();
        assert_eq!(
            decide(&account(&["top", "person", "user"]), &security),
            Assigned::Nothing
        );

        // A SID that arrives in the import is still converted, so the store keeps one form.
        let sid = Sid::parse("S-1-5-21-1-2-3-500").expect("a SID");
        let attributes = account(&["user"]).push(Attribute::single(ATTRIBUTE, &sid.to_string()));
        let assigned = decide(&attributes, &security).attribute().expect("a SID");
        assert_eq!(
            Sid::from_directory_value(&assigned.values[0]).expect("a SID"),
            sid
        );
    }

    #[test]
    fn a_reserved_rid_can_be_put_on_the_built_in_account() {
        // The one case where a SID is chosen rather than issued: the domain's own administrator is
        // `...-500` to every client in the world before the client has asked anything.
        let dir = tempfile::tempdir().expect("tempdir");
        let issuer = issuer(dir.path());
        let admin = issuer.reserved(reserved::ADMINISTRATOR).expect("a SID");

        assert_eq!(admin.rid(), Some(reserved::ADMINISTRATOR));
        assert_eq!(
            issuer.peek(),
            crate::sid::FIRST_UNRESERVED_RID,
            "a built-in RID takes no number from the sequence"
        );
    }
}
