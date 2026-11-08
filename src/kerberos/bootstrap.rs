//! `krbtgt/<REALM>`: the one entry a realm cannot be given by hand.
//!
//! Every other principal is an account somebody creates, with a password that is hashed by the
//! directory like any other. This one is different in both halves: its key is derived from the
//! realm's master password, which no account holds, and it is not a person, so there is nothing for
//! an administrator to type. That is why it is created here rather than by the bootstrap section
//! that seeds an administrator.
//!
//! # Read the file once, and only when the entry is missing
//!
//! The master password is the difference between a realm and a directory of names: whoever has it can
//! mint a ticket for any principal, including the one a client trusts to tell it who else is
//! legitimate. So it is read at start, used to derive a key, and not kept - and the file is not
//! touched at all on a restart where the entry already exists, which is every restart after the
//! first.
//!
//! # Why the write bypasses the schema
//!
//! The attributes are Heimdal's (`krb5Principal`, `krb5Key`), and strict schema validation would
//! refuse them unless the realm's schema had been loaded into this server. The write path used by
//! LDAP clients does check the schema, and rightly; this one is the server provisioning its own
//! realm, and the object classes it writes come from the library that will read them back.

use std::path::Path;

use rust_heimdal_kdc::crypto::{Enctype, OwnCipher};
use rust_heimdal_kdc::hdb::HdbEntry;
use rust_heimdal_kdc::hdb::ldap::{attrs, dn_for, to_attributes};
use rust_heimdal_kdc::name::Principal;

use crate::backend::EntryChange;
use crate::model::{Attribute, AttributeFlags, Attributes, Entry};
use crate::reload::Source;

/// What the last start did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The entry was there; the master password was never read.
    AlreadyThere { dn: String },
    /// The entry was written.
    Created { dn: String },
}

/// The enctypes a fresh `krbtgt` gets.
///
/// All four the engine implements, so that a client negotiating any of them finds a key instead of
/// a `KDC_ERR_ETYPE_NOSUPP` it would report as a configuration fault. RC4 is deliberately absent:
/// this realm has no reason to speak it, and a key that can be attacked offline with a commodity
/// GPU is a key that will be.
const ENCTYPES: [Enctype; 4] = [
    Enctype::Aes256Sha384,
    Enctype::Aes128Sha256,
    Enctype::Aes256Sha1,
    Enctype::Aes128Sha1,
];

/// Reads the master password from `path`.
///
/// Trailing whitespace is dropped and nothing else is: a password with a space in it is a password,
/// and a file that a shell wrote ends with a newline that is not part of it.
pub fn master_password(path: &Path) -> std::io::Result<Vec<u8>> {
    let text = std::fs::read_to_string(path)?;
    Ok(text.trim_end_matches(['\n', '\r']).as_bytes().to_vec())
}

/// Creates `krbtgt/<realm>` if the realm does not have one.
///
/// `master` is read only when the entry is absent, so a caller that has a file can read it lazily -
/// which is what keeps a secret off the heap on every ordinary start.
pub async fn ensure_krbtgt(
    source: &Source,
    realm: &str,
    base_dn: &str,
    master_file: Option<&Path>,
) -> Result<Outcome, String> {
    let principal = Principal::parse(&format!("krbtgt/{realm}@{realm}"))
        .map_err(|err| format!("krbtgt/{realm}@{realm} is not a principal: {err}"))?;
    let dn = dn_for(&principal, base_dn);

    // The snapshot, not a scan of the backend: this runs on every start, and on a directory of a
    // million entries loading it again to answer one question is the difference between a start and
    // a wait.
    if source.directory().await.find(&dn).is_some() {
        return Ok(Outcome::AlreadyThere { dn });
    }

    let path = master_file.ok_or_else(|| {
        format!(
            "the realm has no '{dn}' and no `kerberos.master_key_file` to derive one from: \
             a realm without a krbtgt cannot issue a single ticket"
        )
    })?;
    let password = master_password(path).map_err(|err| format!("master password: {err}"))?;
    if password.is_empty() {
        return Err("the master password file is empty".to_string());
    }

    let cipher = OwnCipher;
    let mut entry = HdbEntry::krbtgt(realm);
    for enctype in ENCTYPES {
        entry
            .add_password_key(&cipher, enctype, &password, 1)
            .map_err(|err| format!("a key for {enctype:?}: {err}"))?;
    }

    let attributes = attributes_of(&entry);
    source
        .apply(&[EntryChange::Upsert {
            entry: Entry::new(dn.clone(), attributes),
        }])
        .await
        .map_err(|err| format!("writing '{dn}': {err}"))?;

    Ok(Outcome::Created { dn })
}

/// The realm's attributes in this server's spelling.
///
/// The one disagreement between the two is how octets sit in a string-valued store, and base64 is
/// the answer LDAP itself gives: a key is DER, `krb5Key` is binary, and the reader in
/// `crate::kerberos::realm` decodes exactly these names.
pub fn attributes_of(entry: &HdbEntry) -> Attributes {
    to_directory_attributes(&to_attributes(entry))
}

fn to_directory_attributes(attributes: &rust_heimdal_kdc::hdb::ldap::Attributes) -> Attributes {
    use base64::Engine as _;

    let mut out = Attributes::new();
    for name in attributes.names() {
        let binary = matches!(name.to_ascii_lowercase().as_str(), attrs::KEY);
        let mut values = Vec::new();
        for value in attributes.get(name) {
            let text = if binary {
                base64::engine::general_purpose::STANDARD.encode(value)
            } else {
                match std::str::from_utf8(value) {
                    Ok(text) => text.to_string(),
                    // A text attribute that is not text: kept rather than dropped, so the entry
                    // says what was written and a reader reports the contradiction.
                    Err(_) => base64::engine::general_purpose::STANDARD.encode(value),
                }
            };
            values.push(text);
        }
        // `push` is a builder here rather than a mutator: the entry's attributes are built once,
        // and a method that mutated in place would let a half-built set be handed to a write.
        out = out.push(Attribute {
            name: std::sync::Arc::from(name),
            values: values.into_boxed_slice(),
            flags: AttributeFlags::default(),
            value_csns: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_written_as_base64_and_a_name_as_text() {
        let cipher = OwnCipher;
        let mut entry = HdbEntry::krbtgt("EXAMPLE.COM");
        entry
            .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
            .unwrap();

        let written = attributes_of(&entry);
        let keys = written.get(attrs::KEY).expect("the key attribute exists");
        assert!(!keys.values.is_empty());
        // Base64, not the raw DER: the store holds text, and a key that went in as text has to come
        // back out as the same octets - which the realm view's own test checks from the other side.
        assert!(keys.values[0].is_ascii());

        let name = written
            .get(attrs::PRINCIPAL_NAME)
            .expect("the principal name exists");
        assert_eq!(name.values[0], "krbtgt/EXAMPLE.COM@EXAMPLE.COM");
    }

    #[test]
    fn a_master_password_keeps_every_character_but_the_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master");
        std::fs::write(&path, "  spaced password  \n").unwrap();
        assert_eq!(master_password(&path).unwrap(), b"  spaced password  ");
    }
}
