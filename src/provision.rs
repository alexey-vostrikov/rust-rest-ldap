//! The containers a domain has before anybody joins it.
//!
//! `cn=Computers` is not a convenience: a member's join searches for it by GUID
//! (`WKGUID=AA312825…`, see [`crate::ldap::wkguid`]) and adds its machine account there, so a
//! directory that answers the search with a DN that does not exist turns a join into
//! `The object name is not found`. A real domain creates this container with the domain itself, not
//! when the first machine arrives.
//!
//! Written at start rather than on demand, for the same reason the bootstrap administrator is:
//! `add` needs a parent, and the parent of every machine account is this one. A member cannot be
//! asked to create the branch it is about to hang from.
//!
//! # Not `OU`
//!
//! AD calls it `container` (1.2.840.113556.1.5.2) and puts it beside `CN=Users`, and a client that
//! reads `objectClass` expects that name. An `organizationalUnit` with a `cn=` RDN would answer the
//! search and then be the wrong kind of object to every reader that checks.

use crate::backend::{Backend, EntryChange};
use crate::model::{Attribute, Attributes, Entry};

/// The class of a plain container, `1.2.840.113556.1.5.2`.
pub const CONTAINER_CLASS: &str = "container";

/// The containers a domain root holds from the start, as DNs under `base_dn`.
pub fn containers(base_dn: &str) -> Vec<String> {
    vec![format!("cn=computers,{base_dn}")]
}

/// Creates the ones that are missing, and says which it created.
///
/// Missing is read from the store rather than assumed: a directory grown from an import already
/// has them, and a second `add` of the same DN would either be refused by the write path or, worse
/// on a backend that does not check, hold the entry twice.
pub async fn ensure_containers(backend: &Backend, base_dn: &str) -> Result<Vec<String>, String> {
    let data = backend
        .load()
        .await
        .map_err(|err| format!("the store could not be read: {err}"))?;
    let existing: Vec<String> = data
        .entries
        .iter()
        .map(|entry| entry.dn().to_owned())
        .collect();

    let mut created = Vec::new();
    for dn in containers(base_dn) {
        if existing.iter().any(|have| have.eq_ignore_ascii_case(&dn)) {
            continue;
        }
        backend
            .apply(&[EntryChange::Upsert {
                entry: container_entry(&dn),
            }])
            .await
            .map_err(|err| format!("'{dn}' could not be created: {err}"))?;
        created.push(dn);
    }
    Ok(created)
}

/// A container entry: the class AD uses, and the common name its RDN names.
pub fn container_entry(dn: &str) -> Entry {
    let label = dn
        .split_once(',')
        .map(|(first, _)| first)
        .unwrap_or(dn)
        .trim()
        .strip_prefix("cn=")
        .unwrap_or_default()
        .to_string();

    let attributes = Attributes::new()
        .push(Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            vec!["top".to_string(), CONTAINER_CLASS.to_string()],
        ))
        .push(Attribute::single("cn", &label))
        .push(Attribute::single(crate::model::ATTR_ENTRY_UUID, "").operational());

    Entry::new(dn.to_string(), attributes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_domain_has_a_computers_container_from_the_start() {
        // The DN a member's WKGUID search resolves to, and the only one: a directory that names a
        // different container in the well-known table is resolved by that value instead.
        assert_eq!(
            containers("dc=example,dc=com"),
            vec!["cn=computers,dc=example,dc=com".to_string()]
        );
    }

    #[test]
    fn the_container_is_the_class_a_client_expects() {
        let entry = container_entry("cn=computers,dc=example,dc=com");

        assert_eq!(
            entry
                .attributes()
                .get(crate::model::ATTR_OBJECT_CLASS)
                .map(|attribute| attribute.values.to_vec()),
            Some(vec!["top".to_string(), "container".to_string()])
        );
        assert_eq!(
            entry
                .attributes()
                .get("cn")
                .map(|attribute| attribute.values.to_vec()),
            Some(vec!["computers".to_string()])
        );
    }
}
