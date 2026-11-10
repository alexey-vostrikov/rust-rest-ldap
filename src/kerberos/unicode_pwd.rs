//! `unicodePwd` → the keys the KDC reads.
//!
//! A machine account is created by a join that writes `unicodePwd` (MS-ADTS: a quoted UTF-16LE
//! string) and nothing else about its password. A directory that stores that value and stops has an
//! account that cannot log in: the KDC looks for `krb5Key`, and every ticket request for the machine
//! answers `S_PRINCIPAL_UNKNOWN`. Measured on the join stand: the account appeared with
//! `objectSid`, `dNSHostName` and four `servicePrincipalName` and no keys at all.
//!
//! # Why here, and not in the KDC
//!
//! The write arrives over LDAP, and this is the process that owns the store: deriving the keys in
//! the KDC would mean the KDC writing into the directory on every first read of a new account, which
//! is a second writer for the same entry. Derivation happens once, in the change that carried the
//! password, so the entry is complete the moment it exists.
//!
//! # What is deliberately not derived
//!
//! The NT hash, the LM hash and the machine's session-key material (`supplementalCredentials`) are
//! what `samr_SetUserInfo2` and Netlogon's secure channel need. They are **not** derived here: a
//! hash this server computes and stores is a hash it must also be able to verify with the same
//! algorithm, and the two halves belong to one task (RRL-2.23) rather than to half of it.

use crate::model::Attributes;

/// The attribute a client writes a password into.
pub const UNICODE_PWD: &str = "unicodePwd";

/// The passwords this module derives from, when a write carries one.
pub fn password_of(attributes: &Attributes) -> Option<String> {
    let attribute = attributes.get(UNICODE_PWD)?;
    attribute.values.iter().find_map(|value| decode(value))
}

/// The password inside one `unicodePwd` value.
///
/// AD's own encoding, in the order the shapes appear in the wild: quotes and UTF-16LE what a client
/// writes over LDAP (MS-ADTS 3.1.1.3.1.5 says the value is a quoted UTF-16 string), plain UTF-16LE
/// what some tools send after stripping the quotes, and UTF-8 what a test or an import writes
/// because it is a text attribute in every other directory. A value that is none of those is not a
/// password and is skipped rather than guessed at.
fn decode(value: &str) -> Option<String> {
    // The store holds text, so a binary value arrives base64: the writer that puts octets in a
    // string-valued attribute uses that spelling (`kerberos::bootstrap` records the same rule for
    // keys).
    let octets = match base64_decode(value) {
        Some(bytes) if looks_utf16(&bytes) => bytes,
        Some(bytes) if !bytes.is_empty() && bytes[0] == b'"' => bytes,
        _ => return Some(value.to_string()).filter(|text| !text.is_empty()),
    };

    let mut units: Vec<u16> = octets
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    // The quotes are part of the wire form and not of the password.
    if units.first() == Some(&u16::from(b'"')) {
        units.remove(0);
    }
    if units.last() == Some(&u16::from(b'"')) {
        units.pop();
    }
    String::from_utf16(&units)
        .ok()
        .filter(|password| !password.is_empty())
}

/// Whether these octets plausibly are UTF-16LE text: a quote first, or every other octet zero.
fn looks_utf16(octets: &[u8]) -> bool {
    if octets.first() == Some(&b'"') {
        return true;
    }
    octets.len().is_multiple_of(2)
        && octets.len() >= 4
        && octets.iter().skip(1).step_by(2).all(|&high| high == 0)
}

/// Base64, when the text is a value that `base64` wrote.
fn base64_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(value).ok()
}

/// The attributes that carry the derived keys, or `None` when the entry holds no password.
///
/// `principal` decides the salt and nothing else: Heimdal's default salt is built from the principal
/// and the realm, and a client derives its key from the salt the KDC sends in `ETYPE-INFO2` - so any
/// salt works as long as this server stores it, which `attributes_of` does.
pub fn keys(
    attributes: &Attributes,
    principal: &str,
    realm: &str,
) -> Option<Result<Attributes, String>> {
    let password = password_of(attributes)?;
    Some(derive(&password, principal, realm))
}

fn derive(password: &str, principal: &str, realm: &str) -> Result<Attributes, String> {
    use rust_kdc::crypto::{Cipher, Enctype, OwnCipher};

    let name = rust_kdc::name::Principal::parse(&format!("{principal}@{realm}"))
        .map_err(|err| format!("'{principal}@{realm}' is not a principal: {err}"))?;
    let mut entry = rust_kdc::hdb::HdbEntry::user(name);
    // The enctypes a modern client asks for, and the two every KDC still answers with: a machine
    // that cannot get AES gets nothing at all from a realm that publishes only AES.
    const ENCTYPES: [Enctype; 4] = [
        Enctype::Aes256Sha384,
        Enctype::Aes128Sha256,
        Enctype::Aes256Sha1,
        Enctype::Aes128Sha1,
    ];
    // AD's salt, not the one MIT's default constructs. The two agree for an account whose name is
    // its principal name and differ for every machine: AD salts with `REALMhostNAME`, lower-cased,
    // and a client in ADS mode derives its key that way without asking. Measured on the AD-join
    // stand: with the MIT salt, `kinit HOST$` after a successful join answered `Preauthentication
    // failed` - the account existed, the password was the one the client had just set, and the two
    // sides had ground different keys out of it.
    //
    // The salt is written into the entry, so the KDC publishes it in `ETYPE-INFO2` and a client
    // that reads the reply derives the same key rather than assuming one.
    let salt = ad_salt(realm, principal);
    for enctype in ENCTYPES {
        let key = OwnCipher
            .s2k(enctype, password.as_bytes(), salt.as_bytes(), None)
            .map_err(|err| format!("a key for {enctype:?}: {err}"))?;
        entry.add_key(key, 1, Some(salt.as_bytes().to_vec()));
    }

    let derived = crate::kerberos::bootstrap::attributes_of(&entry);
    // Only what the KDC reads from a stored account: the principal name is the entry's own
    // (`sAMAccountName`, `userPrincipalName`), not a second one written over it.
    let mut out = Attributes::new();
    for name in KEPT {
        if let Some(attribute) = derived.get(name) {
            out = out.push(attribute.clone());
        }
    }
    Ok(out)
}

/// The salt AD derives an account's keys with: `REALM` + `host` + the account name, lower-cased.
///
/// The trailing `$` of a machine account is not part of it - the name AD salts with is the one a
/// person would say out loud, and the mark is there to keep a machine from colliding with a user.
fn ad_salt(realm: &str, account: &str) -> String {
    format!(
        "{}{}{}",
        realm.to_ascii_uppercase(),
        "host",
        account.trim_end_matches('$').to_ascii_lowercase()
    )
}

/// The derived attributes that belong on an account entry.
///
/// `krb5Key` and the key version are the answer to "what are this account's keys"; the principal
/// name and realm describe a *realm* entry, and writing them over an account would rename the
/// account in the realm's eyes to whatever this derivation happened to pass in.
const KEPT: [&str; 3] = [
    rust_kdc::hdb::ldap::attrs::KEY,
    rust_kdc::hdb::ldap::attrs::KEY_VERSION_NUMBER,
    "msDS-KeyVersionNumber",
];

/// The keys of a password this caller holds in the clear, for an account it is about to create.
///
/// The bootstrap path has the password because it has to hash it anyway; going through
/// `unicodePwd` there would mean writing the clear password into the entry first and deleting it
/// afterwards, which is a window nobody needs.
pub fn keys_for(password: &str, principal: &str, realm: &str) -> Result<Attributes, String> {
    derive(password, principal, realm)
}

/// The attributes of `derived` merged into `into`, and `unicodePwd` dropped.
///
/// `unicodePwd` is write-only in AD and this server was storing it: a search returned the
/// account's password in the clear, in UTF-16, which is a password store with extra steps. The
/// value has served its purpose by the time the keys exist.
pub fn merge_keys(into: &Attributes, derived: &Attributes) -> Attributes {
    let mut attributes = into.clone();
    for name in KEPT {
        if let Some(attribute) = derived.get(name) {
            attributes = attributes.push(attribute.clone());
        }
    }
    attributes.without("unicodePwd")
}

/// The entry with its keys derived from a password it carries, or unchanged.
///
/// Called where a write is turned into changes, so the entry that reaches the store is already
/// complete: a reader that arrives between the two writes would otherwise find an account without
/// keys and tell its client the machine does not exist.
///
/// `None` when this server is not a domain controller: a directory with no keytab has no realm to
/// name in `krb5PrincipalRealm`, and keys nothing can be asked for are a claim about a realm that is
/// not this one.
pub fn seal(
    entry: &crate::model::Entry,
    security: &crate::security::Security,
) -> crate::model::Entry {
    let Some(gssapi) = security.gssapi.as_ref() else {
        return entry.clone();
    };
    let Some(realm) = gssapi.realms().next() else {
        return entry.clone();
    };
    let Some(principal) = account_name(entry.attributes()) else {
        return entry.clone();
    };
    let Some(derived) = keys(entry.attributes(), &principal, realm) else {
        return entry.clone();
    };
    let derived = match derived {
        Ok(derived) => derived,
        Err(err) => {
            // Said once, and the write stands: refusing the client's write because this server
            // failed to derive would lose the password it sent, and an operator can act on a line
            // in the log in a way they cannot act on an entry with no keys.
            eprintln!("kerberos: the keys of '{principal}' were not derived: {err}");
            return entry.clone();
        }
    };

    crate::model::Entry::new(
        entry.dn().to_string(),
        merge_keys(entry.attributes(), &derived),
    )
}

/// The name the realm knows this account by: `sAMAccountName`, then `userPrincipalName`, then `cn`.
fn account_name(attributes: &crate::model::Attributes) -> Option<String> {
    for name in ["sAMAccountName", "userPrincipalName", "cn"] {
        if let Some(attribute) = attributes.get(name)
            && let Some(value) = attribute.values.first()
        {
            return Some(value.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Attribute;

    fn with_password(value: &str) -> Attributes {
        Attributes::new().push(Attribute::single(UNICODE_PWD, value))
    }

    #[test]
    fn a_quoted_utf16_password_is_read_without_its_quotes() {
        // MS-ADTS: the LDAP form is a quoted UTF-16 string. The quotes are framing, not part of it,
        // and a key derived from `"secret"` is a key no client can compute.
        // The quotes are UTF-16 units like everything else: one byte of `"` followed by the text
        // shifts every pair and decodes to nonsense that reads like an encoding bug.
        let mut quoted: Vec<u8> = Vec::new();
        for unit in "\"secret\"".encode_utf16() {
            quoted.extend_from_slice(&unit.to_le_bytes());
        }
        let encoded = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(&quoted)
        };

        assert_eq!(
            password_of(&with_password(&encoded)),
            Some("secret".to_string())
        );
    }

    #[test]
    fn a_plain_text_password_is_read_as_it_stands() {
        // An import or a test writes the value as text; refusing it would make the derivation work
        // only for the clients that happen to speak the binary form.
        assert_eq!(
            password_of(&with_password("secret")),
            Some("secret".to_string())
        );
    }

    #[test]
    fn an_entry_without_a_password_derives_nothing() {
        assert_eq!(password_of(&Attributes::new()), None);
    }
}
