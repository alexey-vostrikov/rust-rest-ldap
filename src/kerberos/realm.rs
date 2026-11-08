//! The realm, read out of this server's own directory.
//!
//! Implements `rust_heimdal_kdc::hdb::ldap::Directory`, which is the whole contract a KDC has with
//! whatever holds its principals: read one, write one, delete one, list them. Three of the four are
//! the directory's job here, so what this file mostly is, is a translation between two spellings of
//! "attribute" - and a statement about the fourth, which is refused.
//!
//! # Where an entry is
//!
//! `dn_for` puts a principal at `krb5PrincipalName=<principal>,krb5RealmName=<REALM>,<base>`, and that
//! is the first place this looks, because it is a key lookup and the KDC does it on every request. A
//! directory, though, is overwhelmingly made of entries that were not created by a realm bootstrap:
//! `cn=alice,ou=users,dc=example,dc=com` is an account, and asking an operator to keep a second copy
//! of it under another DN is asking for the two copies to drift. So when the canonical DN is absent,
//! the entry is found by its `userPrincipalName` or `krb5PrincipalName` value, and read through the
//! same mapping.
//!
//! That fallback is a scan, and its cost is why it is the fallback: the canonical DN answers a KDC
//! in one lookup, and the scan runs only for accounts that live where a person put them.

use std::sync::{Arc, RwLock};

use rust_heimdal_kdc::Error;
use rust_heimdal_kdc::hdb::ldap::{Attributes, Directory as Realm, attrs, dn_for, from_attributes};
use rust_heimdal_kdc::name::Principal;

use crate::directory::Directory;
use crate::model::Entry;

/// A realm over a snapshot of the directory.
///
/// The snapshot is replaced rather than mutated: the reload path already publishes one whole
/// `Arc<Directory>` per change, and a realm that held its own copy of the entries would be a second
/// thing to keep in step. `refresh` takes the new one; the KDC's own requests read the current one
/// under a read lock, which is a pointer copy.
#[derive(Debug)]
pub struct RealmView {
    realm: String,
    base_dn: String,
    directory: RwLock<Arc<Directory>>,
}

impl RealmView {
    /// A view over `directory`, for the realm `realm` under `base_dn`.
    pub fn new(
        realm: impl Into<String>,
        base_dn: impl Into<String>,
        directory: Arc<Directory>,
    ) -> Self {
        RealmView {
            realm: realm.into(),
            base_dn: base_dn.into(),
            directory: RwLock::new(directory),
        }
    }

    /// Takes a fresh snapshot.
    pub fn refresh(&self, directory: Arc<Directory>) {
        // A poisoned lock means a panic while somebody held it; the snapshot behind it is still a
        // whole snapshot, and refusing to serve tickets for ever because of one panicked reader is
        // worse than the panic.
        let mut current = match self.directory.write() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        *current = directory;
    }

    fn current(&self) -> Arc<Directory> {
        let current = match self.directory.read() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        Arc::clone(&current)
    }

    /// The entry for `principal`, by the canonical DN first and by its principal name second.
    fn entry_for(&self, principal: &Principal) -> Option<Entry> {
        let directory = self.current();

        let canonical = dn_for(principal, &self.base_dn);
        if let Some(entry) = directory.find(&canonical) {
            return Some(entry.clone());
        }

        // Not the canonical DN, so this account was created where a person put it. Compared on the
        // value rather than the DN, and on the two attributes a directory uses for the same fact:
        // `userPrincipalName` is the Microsoft spelling that a Windows client writes, and
        // `krb5PrincipalName` is the one a realm bootstrap writes.
        let wanted = principal.to_string();
        directory
            .all()
            .iter()
            .find(|entry| {
                [attrs::PRINCIPAL_NAME, "userPrincipalName"]
                    .iter()
                    .any(|name| match entry.attributes().get(name) {
                        Some(attribute) => attribute
                            .values
                            .iter()
                            .any(|value| value.eq_ignore_ascii_case(&wanted)),
                        None => false,
                    })
            })
            .cloned()
    }
}

impl Realm for RealmView {
    fn get(&self, principal: &Principal) -> rust_heimdal_kdc::Result<Option<Attributes>> {
        let Some(entry) = self.entry_for(principal) else {
            return Ok(None);
        };
        let attributes = to_realm_attributes(entry.attributes());
        // Decoded here rather than returned as found: a mapping that hands back attributes it has
        // not read is a mapping that cannot tell "no keys" from "keys this build cannot parse", and
        // the KDC's answer to those two is the same only by accident.
        from_attributes(&attributes).map_err(|err| {
            Error::Hdb(format!(
                "entry '{}' does not read back as a principal: {err}",
                entry.dn()
            ))
        })?;
        Ok(Some(attributes))
    }

    fn put(&self, principal: &Principal, _attributes: &Attributes) -> rust_heimdal_kdc::Result<()> {
        // Not a limitation of this adapter but a decision: an account has a password policy, an
        // access check and a replication history, and all three live on the LDAP path. A KDC-side
        // write would create an entry that skipped them, and the entry would then be
        // indistinguishable from one that did not.
        Err(Error::Hdb(format!(
            "the realm is read-only here: write '{principal}' through LDAP"
        )))
    }

    fn delete(&self, principal: &Principal) -> rust_heimdal_kdc::Result<bool> {
        Err(Error::Hdb(format!(
            "the realm is read-only here: delete '{principal}' through LDAP"
        )))
    }

    fn list(&self) -> rust_heimdal_kdc::Result<Vec<Principal>> {
        let directory = self.current();
        let mut out = Vec::new();
        for entry in directory.all() {
            let Some(values) = entry.attributes().get(attrs::PRINCIPAL_NAME) else {
                continue;
            };
            for value in values.values.iter() {
                // A value that is not a principal is somebody else's attribute with a familiar
                // name; skipping it keeps one bad entry from hiding the whole realm.
                if let Ok(principal) = Principal::parse(value)
                    && principal.realm.eq_ignore_ascii_case(&self.realm)
                {
                    out.push(principal);
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }
}

impl RealmView {
    /// The realm this view answers for.
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

/// This server's attributes as the realm's.
///
/// Values stay as they are, except in the one place the two disagree by construction: a key is DER
/// and the store holds strings, so it is base64 - the same encoding LDAP itself uses to carry a
/// binary value in a text file. An attribute that does not decode is passed through untouched: the
/// mapping in the KDC decides what to make of it, and a silent `unwrap_or_default` here would turn a
/// corrupt key into a valid empty one.
fn to_realm_attributes(attributes: &crate::model::Attributes) -> Attributes {
    let mut out = Attributes::new();
    for attribute in attributes.values() {
        let name = attribute.name.as_ref();
        let binary = is_binary(name);
        for value in attribute.values.iter() {
            let bytes = if binary {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(value.trim())
                    .unwrap_or_else(|_| value.as_bytes().to_vec())
            } else {
                value.as_bytes().to_vec()
            };
            out.add(name, bytes);
        }
    }
    out
}

/// Attributes whose value is octets, not text.
///
/// Kept as a list rather than read from the schema on purpose: this is the realm's own set, it is
/// the set `rust-heimdal-kdc` defines, and a schema lookup here would make the mapping depend on
/// which schema file the server was started with.
fn is_binary(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let name = name.split(';').next().unwrap_or(&name);
    matches!(name, "krb5key" | "supplementalcredentials")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_attribute_is_read_as_octets() {
        use base64::Engine as _;
        let key = vec![0x30, 0x1f, 0x00, 0xff, 0x10, 0x20];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&key);
        let mut attributes = crate::model::Attributes::new();
        attributes = attributes.push(crate::model::Attribute {
            name: Arc::from("krb5Key"),
            values: vec![encoded].into_boxed_slice(),
            flags: crate::model::AttributeFlags::default(),
            value_csns: None,
        });

        let realm = to_realm_attributes(&attributes);
        assert_eq!(realm.first("krb5Key"), Some(&key[..]));
    }

    #[test]
    fn a_value_that_is_not_base64_is_passed_through() {
        // A key that does not decode is a key somebody wrote by hand or corrupted. Turning it into
        // an empty one would make a principal that cannot be authenticated, with no error anywhere;
        // passing it through makes `from_attributes` fail and the entry named.
        let mut attributes = crate::model::Attributes::new();
        attributes = attributes.push(crate::model::Attribute {
            name: Arc::from("krb5Key"),
            values: vec!["not base64 at all!!".to_string()].into_boxed_slice(),
            flags: crate::model::AttributeFlags::default(),
            value_csns: None,
        });

        let realm = to_realm_attributes(&attributes);
        assert_eq!(
            realm.first("krb5Key"),
            Some("not base64 at all!!".as_bytes())
        );
    }

    #[test]
    fn a_text_attribute_keeps_its_bytes() {
        let mut attributes = crate::model::Attributes::new();
        attributes = attributes.push(crate::model::Attribute {
            name: Arc::from("krb5PrincipalName"),
            values: vec!["alice@EXAMPLE.COM".to_string()].into_boxed_slice(),
            flags: crate::model::AttributeFlags::default(),
            value_csns: None,
        });

        let realm = to_realm_attributes(&attributes);
        assert_eq!(
            realm.first("krb5PrincipalName"),
            Some("alice@EXAMPLE.COM".as_bytes())
        );
    }
}
