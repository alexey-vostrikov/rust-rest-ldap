//! The vocabulary a realm's entries are written in.
//!
//! `rust-heimdal-kdc` writes a principal as Heimdal's attributes (`krb5PrincipalName`, `krb5Key`,
//! `krb5KDCFlags`, ...) with Heimdal's object classes. This server validates against its own
//! published schema in strict mode, and against a schema that has never heard of those names every
//! realm entry is an `ObjectClassViolation` - including the `krbtgt` the KDC provisions itself, which
//! turns a working realm into a server that will not start.
//!
//! So the definitions are published, for the same reason `ad_schema` publishes the Microsoft ones:
//! an entry this server holds and serves has to be describable, or the directory and the KDC
//! disagree about what is in the directory.
//!
//! # Two deliberate deviations from Heimdal's `hdb.schema`
//!
//! **`krb5Principal` is structural here, auxiliary in Heimdal.** Heimdal's own `hdb-ldap.c` does not
//! validate structure, so an entry whose classes are all auxiliary is fine there. This directory
//! does validate, and an entry with no structural class is the one thing a schema can never accept.
//! A realm entry is a principal and nothing else, so making the class structural says exactly that.
//!
//! **The two Microsoft spellings are defined here, not in `ad_schema`.** `msDS-KeyVersionNumber` and
//! `supplementalCredentials` are written by the KDC's AD projection, and `ad_schema` does not carry
//! them: it is applied for a keytab, while these are needed the moment a realm exists. Defining them
//! in both would be a duplicate definition, so they are here - beside the thing that writes them.
//!
//! The OIDs for the `krb5*` names are Heimdal's (`1.3.6.1.4.1.5322.10.*`), so a client that resolves
//! an attribute by OID finds the same definition it would on a Heimdal KDC.
use crate::schema::Schema;

/// The Kerberos definitions, in RFC 4512 form.
pub const KERBEROS_EXTENSION: &str = r#"
# --- attributes ----------------------------------------------------------------------------
#
# The principal, written `name@REALM`. `caseExactMatch` on purpose: `alice` and `Alice` are two
# principals, and a directory that folded them would hand one account's ticket to another.
attributetype ( 1.3.6.1.4.1.5322.10.1.1 NAME 'krb5PrincipalName'
    EQUALITY caseExactMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )

attributetype ( 1.3.6.1.4.1.5322.10.1.2 NAME 'krb5PrincipalRealm'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )

# The realm component as its own RDN, which is how `dn_for` names an entry.
attributetype ( 1.3.6.1.4.1.5322.10.1.3 NAME 'krb5RealmName'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )

# A key is DER: the enctype, the octets and the kvno, per key version. Octets, not text, even
# though this store carries it as base64 - the declaration has to say what the value is.
attributetype ( 1.3.6.1.4.1.5322.10.1.4 NAME 'krb5Key'
    EQUALITY octetStringMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )

attributetype ( 1.3.6.1.4.1.5322.10.1.5 NAME 'krb5KeyVersionNumber'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

# Heimdal's flag word: which kinds of ticket this principal may have.
attributetype ( 1.3.6.1.4.1.5322.10.1.6 NAME 'krb5KDCFlags'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

attributetype ( 1.3.6.1.4.1.5322.10.1.7 NAME 'krb5EncryptionType'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )

attributetype ( 1.3.6.1.4.1.5322.10.1.8 NAME 'krb5ValidStart'
    EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )

attributetype ( 1.3.6.1.4.1.5322.10.1.9 NAME 'krb5ValidEnd'
    EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )

attributetype ( 1.3.6.1.4.1.5322.10.1.10 NAME 'krb5PasswordEnd'
    EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )

attributetype ( 1.3.6.1.4.1.5322.10.1.11 NAME 'krb5MaxLife'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

attributetype ( 1.3.6.1.4.1.5322.10.1.12 NAME 'krb5MaxRenew'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

attributetype ( 1.3.6.1.4.1.5322.10.1.13 NAME 'krb5ExtendedAttributes'
    EQUALITY octetStringMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )

# Microsoft's spelling of the key version. A Windows client reads this one and never `krb5KeyVersionNumber`,
# so the same fact is published twice - by the KDC, not by this file.
attributetype ( 1.2.840.113556.1.4.178 NAME 'msDS-KeyVersionNumber'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

# AD's own key blob: the keys and their salts, in a format only Windows parses in full. Written for
# an audit tool to find; this server never reads a key back out of it.
attributetype ( 1.2.840.113556.1.4.750.1 NAME 'supplementalCredentials'
    EQUALITY octetStringMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )

# `msDS-SupportedEncryptionTypes` is declared by the AD vocabulary (`ad_schema`, under AD's real
# OID 1.2.840.113556.1.4.1963), and it was also declared here under the wrong OID
# 1.2.840.113556.1.4.890. Two declarations of one name are refused at load - "name
# 'msds-supportedencryptiontypes' is defined twice" - which is exactly the configuration a domain
# controller runs (realm vocabulary and AD vocabulary together), so the duplication made that
# configuration unstartable. The class below still names the attribute; a `MAY` that refers to
# another document's definition is normal, and the AD vocabulary is always loaded with this one.

# --- classes -------------------------------------------------------------------------------
#
# Structural, where Heimdal has it auxiliary: see the module note. `MUST` follows the DN this
# server builds for a principal - a name and a realm - so an entry that is in the realm by its
# naming is also valid by its attributes.
objectclass ( 1.3.6.1.4.1.5322.10.2.1 NAME 'krb5Principal' SUP top STRUCTURAL
    MUST ( krb5PrincipalName $ krb5PrincipalRealm )
    MAY ( krb5RealmName $ krb5Key $ krb5KeyVersionNumber $ krb5KDCFlags $ krb5EncryptionType $
          krb5ValidStart $ krb5ValidEnd $ krb5PasswordEnd $ krb5MaxLife $ krb5MaxRenew $
          krb5ExtendedAttributes $ msDS-KeyVersionNumber $ msDS-SupportedEncryptionTypes $
          supplementalCredentials $ userAccountControl $ servicePrincipalName ) )

# The KDC's own view of a principal: the flags and the keys. Auxiliary, because it adds to a
# principal rather than being a kind of object.
objectclass ( 1.3.6.1.4.1.5322.10.2.2 NAME 'krb5KDCEntry' SUP krb5Principal AUXILIARY
    MAY ( krb5Key $ krb5KeyVersionNumber $ krb5KDCFlags $ krb5EncryptionType $ krb5ValidStart $
          krb5ValidEnd $ krb5PasswordEnd $ krb5MaxLife $ krb5MaxRenew $ krb5ExtendedAttributes ) )
"#;

/// Adds the Kerberos definitions to `schema`.
pub fn extend(schema: &mut Schema) -> Result<(), String> {
    schema
        .extend(KERBEROS_EXTENSION)
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_kerberos() -> Schema {
        let mut schema = Schema::core();
        extend(&mut schema).expect("the Kerberos extension parses");
        schema
    }

    #[test]
    fn a_principal_entry_validates() {
        use crate::model::{Attribute, Attributes, Entry};

        let schema = with_kerberos();
        let entry = Entry::new(
            "krb5PrincipalName=alice@EXAMPLE.COM,krb5RealmName=EXAMPLE.COM,dc=example,dc=com",
            Attributes::new()
                .push(Attribute::new(
                    "objectClass",
                    vec!["krb5Principal".to_string()],
                ))
                .push(Attribute::single("krb5PrincipalName", "alice@EXAMPLE.COM"))
                .push(Attribute::single("krb5PrincipalRealm", "EXAMPLE.COM"))
                .push(Attribute::single("krb5KeyVersionNumber", "1"))
                .push(Attribute::single("krb5KDCFlags", "12")),
        );

        // The entry the KDC writes, checked the way the server checks a client's add. If this
        // fails, a realm cannot be provisioned at all and the failure names a class nobody wrote.
        if let Err(violations) = schema.check(&entry) {
            let reported: Vec<_> = violations.iter().map(|v| format!("{v:?}")).collect();
            panic!("a principal entry must validate: {reported:?}");
        }
    }
}
