//! The `WKGUID` naming a well-known container, and how a search base reaches it.
//!
//! A Samba member does not look for `cn=Computers` by name. It searches
//!
//! ```text
//! <WKGUID=AA312825768811D1ADED00C04FD8D5CD,dc=AD,dc=EXAMPLE,dc=COM>
//! ```
//!
//! which is MS-ADTS 6.1.1.4.2: the first RDN names a GUID, not a value, and a directory that has a
//! `wellKnownObjects` attribute on the parent replaces it with the DN recorded there. Measured on
//! the join stand: unresolved, the search found nothing, Samba fell back to the `samr` pipe (which
//! `IPC$` does not serve) and reported `The object name is not found` - a message about a name that
//! was never wrong, the question was.
//!
//! # Why a default location exists here
//!
//! `wellKnownObjects` is data in an AD domain root, and this directory synthesises that root rather
//! than storing it: a value nothing writes would be absent on every fresh install, and the join
//! would fail at the same place. So the table below is AD's own default for the two containers it
//! creates with a domain, used only when the parent carries no value for the GUID.

use crate::directory::Directory;

/// `CN=Computers`, where a domain puts a machine account unless told otherwise.
pub const COMPUTERS: &str = "AA312825768811D1ADED00C04FD8D5CD";

/// `CN=Users`, the container a domain creates beside it.
pub const USERS: &str = "A9D1CA15768811D1ADED00C04FD8D5CD";

/// The attribute AD stores those locations in.
const WELL_KNOWN_OBJECTS: &str = "wellKnownObjects";

/// A search base that names a GUID instead of a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base {
    /// The GUID, upper case without dashes, as it appears in the RDN.
    pub guid: String,
    /// The entry whose `wellKnownObjects` answers for it - the domain naming context, in practice.
    pub parent: String,
}

/// Reads `<WKGUID=<guid>,<parent>` as such a base, or `None` for an ordinary DN.
///
/// Deliberately narrow: only `WKGUID` in the first RDN, and only a 32-hex-digit value. A base whose
/// first RDN merely *starts* with those letters is an ordinary entry with an unusual name, and
/// treating it as well-known would make an entry unreachable by its own DN.
pub fn parse(base: &str) -> Option<Base> {
    let (first, rest) = base.split_once(',')?;
    let value = first.trim().strip_prefix("WKGUID=").or_else(|| {
        first
            .trim()
            .strip_prefix("wkgUID=")
            .or_else(|| first.trim().strip_prefix("wkgUid="))
            .or_else(|| first.trim().strip_prefix("wkguid="))
    })?;
    let value = value.trim();
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(Base {
        guid: value.to_ascii_uppercase(),
        parent: rest.trim().to_string(),
    })
}

/// The DN the GUID names, or `None` when nothing answers for it.
///
/// `wellKnownObjects` wins over the table: a domain that moved its computers container says so
/// there, and a hard-coded answer would send the member to a container the domain no longer uses.
pub fn resolve(base: &Base, directory: &Directory) -> Option<String> {
    if let Some(recorded) = recorded(base, directory) {
        return Some(recorded);
    }

    let label = match base.guid.as_str() {
        COMPUTERS => "computers",
        USERS => "users",
        _ => return None,
    };
    Some(format!("cn={label},{}", base.parent))
}

/// The DN `wellKnownObjects` records for this GUID, if the parent carries one.
fn recorded(base: &Base, directory: &Directory) -> Option<String> {
    let parent = directory.find(&base.parent)?;
    let attribute = parent.attributes().get(WELL_KNOWN_OBJECTS)?;

    for value in &attribute.values {
        // `B:32:<guid>:<dn>` - the "B" means the identifier is a 32-bit-GUID in binary form, and
        // AD writes the GUID without dashes. A value in any other form is not this one.
        let mut parts = value.splitn(4, ':');
        let (Some("B"), Some("32"), Some(guid), Some(dn)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if guid.eq_ignore_ascii_case(&base.guid) && !dn.is_empty() {
            return Some(dn.to_ascii_lowercase());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, Attributes, Entry};

    const BASE: &str = "dc=example,dc=com";
    /// A parent that can carry `wellKnownObjects` in a test: the naming context itself is
    /// synthesised by `Directory::from_entries` and would be replaced by any fixture of the same DN.
    const PARENT: &str = "cn=root,dc=example,dc=com";

    fn directory_with(well_known: &[&str]) -> Directory {
        let entry = Entry::new(
            PARENT.to_string(),
            Attributes::new()
                .push(Attribute::new(
                    crate::model::ATTR_OBJECT_CLASS,
                    vec!["top".to_string(), "domain".to_string()],
                ))
                .push(Attribute::new(
                    WELL_KNOWN_OBJECTS,
                    well_known.iter().map(|value| value.to_string()).collect(),
                )),
        );
        Directory::from_entries(BASE, "users", "groups", vec![entry])
    }

    fn base() -> Base {
        parse(&format!("WKGUID={COMPUTERS},{PARENT}")).expect("a well-known base")
    }

    #[test]
    fn the_base_samba_searches_with_parses_to_a_guid_and_a_parent() {
        // The angle brackets in a capture are Samba's `dsdb_dn` notation and are not sent: the
        // search carries the DN itself, and the client strips them before calling.
        assert!(parse(&format!("<WKGUID={COMPUTERS},{PARENT}>")).is_none());

        let parsed = base();
        assert_eq!(parsed.guid, COMPUTERS);
        assert_eq!(parsed.parent, PARENT);
    }

    #[test]
    fn an_ordinary_dn_is_not_a_well_known_base() {
        for candidate in [
            "dc=example,dc=com",
            "cn=computers,dc=example,dc=com",
            "WKGUID=,dc=example,dc=com",
            "WKGUID=notahexguid,dc=example,dc=com",
            "WKGUID=A312825768811D1ADED00C04FD8D5CD,dc=example,dc=com",
            "WKGUID",
        ] {
            assert!(parse(candidate).is_none(), "{candidate}");
        }
    }

    #[test]
    fn a_value_in_well_known_objects_answers_before_the_table() {
        // A domain that moved its computers container records the new place; a hard-coded answer
        // would send the member to one the domain no longer uses.
        let directory =
            directory_with(&[&format!("B:32:{COMPUTERS}:OU=Machines,DC=example,DC=com")]);

        assert_eq!(
            resolve(&base(), &directory),
            Some("ou=machines,dc=example,dc=com".to_string())
        );
    }

    #[test]
    fn a_guid_with_no_value_resolves_to_the_location_ad_creates() {
        let directory = directory_with(&[]);

        assert_eq!(
            resolve(&base(), &directory),
            Some(format!("cn=computers,{PARENT}"))
        );
    }

    #[test]
    fn a_value_of_another_shape_is_skipped_rather_than_misread() {
        // AD also writes values whose identifier is not a GUID; only `B:32` can match, and a value
        // of the wrong shape must not be read as the answer.
        let directory = directory_with(&[
            &format!("D:32:{COMPUTERS}:OU=Wrong,DC=example,DC=com"),
            &format!("B:16:{COMPUTERS}:OU=Wrong,DC=example,DC=com"),
            "B:32:00000000000000000000000000000000:OU=Other,DC=example,DC=com",
        ]);

        assert_eq!(
            resolve(&base(), &directory),
            Some(format!("cn=computers,{PARENT}"))
        );
    }

    #[test]
    fn an_unknown_guid_is_not_guessed() {
        let directory = directory_with(&[]);
        let unknown =
            parse(&format!("WKGUID=0123456789ABCDEF0123456789ABCDEF,{PARENT}")).expect("parsed");

        assert_eq!(resolve(&unknown, &directory), None);
    }

    #[test]
    fn the_guid_is_matched_without_regard_to_case() {
        let directory = directory_with(&[&format!(
            "B:32:{}:OU=Lower,DC=example,DC=com",
            COMPUTERS.to_ascii_lowercase()
        )]);

        assert_eq!(
            resolve(&base(), &directory),
            Some("ou=lower,dc=example,dc=com".to_string())
        );
    }
}
