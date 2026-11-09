//! Schema that makes this directory answer to clients expecting an Active Directory.
//!
//! Kerberos is not only a bind mechanism. A client that authenticates by ticket is usually a
//! client from an AD world - `sssd`, a Windows host, a Samba tool - and such a client does not ask
//! "who is uid=alice". It asks for `userPrincipalName`, `sAMAccountName`, `userAccountControl`,
//! `objectGUID`, `servicePrincipalName`. Against a schema that has never heard of them, every one
//! of those questions fails with `undefinedAttributeType`, and the answer looks like a broken
//! directory rather than a missing definition.
//!
//! So the extension is tied to Kerberos mode: a server that accepts tickets is a server claiming
//! to stand in for a domain controller, and it should publish the vocabulary of one. A server
//! without a keytab stays exactly as it was - it is somebody's LDAP directory, not an impostor
//! domain controller, and adding `userAccountControl` to it would invite clients to rely on
//! something nothing maintains.
//!
//! # The OIDs are Microsoft's, deliberately
//!
//! These are the real `1.2.840.113556.1.4.*` attribute and `1.2.840.113556.1.5.*` class
//! identifiers, not private ones. A schema published under invented OIDs would be compatible in
//! name only: a client that resolves `userPrincipalName` by OID - which is what a schema-aware
//! client does - would not find it. Samba 4 and OpenLDAP's `ad` contrib schema do the same, for
//! the same reason.
//!
//! What this is **not**: an implementation of AD semantics. There is no `objectSid` allocation, no
//! USN tracking, no `msDS-*` replication metadata. The definitions exist so that questions can be
//! asked and answered; the answers come from ordinary LDAP entries, and where a value has to be
//! synthesised this file says so instead of pretending.
use crate::schema::Schema;

/// The AD definitions, in RFC 4512 form.
///
/// Kept as text rather than built up in code because the schema module already parses this form,
/// and a definition written the way an administrator writes one is a definition they can read,
/// diff and extend.
pub const AD_EXTENSION: &str = r#"
# --- attributes AD clients ask for -------------------------------------------------------
#
# `userPrincipalName` is the name a ticket is issued to, and the modern way to find an account:
# `alice@EXAMPLE.COM` rather than a DN the caller must already know.
attributetype ( 1.2.840.113556.1.4.656 NAME 'userPrincipalName'
    EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )

# The pre-Windows-2000 logon name. Still the attribute Samba tools and many scripts match on.
attributetype ( 1.2.840.113556.1.4.221 NAME 'sAMAccountName'
    EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )

# `userAccountControl` is a bit field, and the reason it is here rather than decorative: the
# disabled and locked bits are honoured on a GSSAPI bind, so an account that says it is disabled
# cannot log in by ticket even though Kerberos never asked this server about a password.
attributetype ( 1.2.840.113556.1.4.8 NAME 'userAccountControl'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

# The identity an entry had in the directory it came from. Binary in AD; declared as octets here
# because that is the truth even when the value is carried as text.
attributetype ( 1.2.840.113556.1.4.146 NAME 'objectGUID'
    EQUALITY octetStringMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )

attributetype ( 1.2.840.113556.1.4.122 NAME 'objectSid'
    EQUALITY octetStringMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )

# The names a service is known by, `ldap/host.example.com`. Needed for the reverse question: which
# account may hold this ticket.
attributetype ( 1.2.840.113556.1.4.771 NAME 'servicePrincipalName'
    EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

attributetype ( 1.2.840.113556.1.4.120 NAME 'primaryGroupID'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

# Group kind and scope: security or distribution, global or universal.
attributetype ( 1.2.840.113556.1.4.750 NAME 'groupType'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

# 0 means "never expires", 0x7FFFFFFFFFFFFFFF means the same thing the other way round. Both
# spellings exist in the wild, which is why the attribute is declared and not interpreted here.
attributetype ( 1.2.840.113556.1.4.53 NAME 'accountExpires'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

attributetype ( 1.2.840.113556.1.4.96 NAME 'pwdLastSet'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

# --- classes -----------------------------------------------------------------------------
#
# `user` extends `organizationalPerson`, as it does in AD, so an entry imported from an AD dump
# validates as it stands. `cn` and `sn` stay required: AD requires them too, and a `user` without
# a name is not a compatibility problem but a broken record.
objectclass ( 1.2.840.113556.1.5.9 NAME 'user' SUP organizationalPerson STRUCTURAL
    MAY ( userPrincipalName $ sAMAccountName $ userAccountControl $ objectGUID $ objectSid $
          servicePrincipalName $ primaryGroupID $ accountExpires $ pwdLastSet $ mail $
          displayName $ telephoneNumber $ title $ description $ memberOf $ unicodePwd ) )

objectclass ( 1.2.840.113556.1.5.8 NAME 'group' SUP top STRUCTURAL
    MUST cn
    MAY ( sAMAccountName $ groupType $ member $ memberOf $ objectGUID $ objectSid $ description ) )

# A computer account: the machine identity Kerberos actually uses most of the time.
objectclass ( 1.2.840.113556.1.5.5 NAME 'computer' SUP user STRUCTURAL
    MAY ( sAMAccountName $ userAccountControl $ servicePrincipalName $ dNSHostName $
          msDS-SupportedEncryptionTypes $ operatingSystem $ operatingSystemVersion ) )

# The name a machine is reached by, and the one `net ads join` writes first. A member reads it back
# to find itself in the directory.
attributetype ( 1.2.840.113556.1.4.619 NAME 'dNSHostName'
    EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )

# The enctypes an account is willing to use. Written by the member once it has seen the KDC; read
# when the KDC decides which key to issue. An integer, not a bit string: so AD declares it.
attributetype ( 1.2.840.113556.1.4.1963 NAME 'msDS-SupportedEncryptionTypes'
    EQUALITY integerMatch ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

# The password of an account, as a client writes it. AD carries it as an octet string and never
# returns it; that it is write-only is the ACL rules' business, not the syntax's.
attributetype ( 1.2.840.113556.1.4.90 NAME 'unicodePwd'
    EQUALITY octetStringMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )

attributetype ( 1.2.840.113556.1.4.373 NAME 'operatingSystem'
    EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )

attributetype ( 1.2.840.113556.1.4.375 NAME 'operatingSystemVersion'
    EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
"#;

/// The bits of `userAccountControl` this server acts on.
///
/// Not the whole flag word: AD defines a couple of dozen bits and most of them describe password
/// policy, which a directory that never sees a password has no business deciding. These three are
/// the ones that answer "may this account authenticate at all", and that question is ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserAccountControl(u32);

impl UserAccountControl {
    /// The account is disabled.
    pub const ACCOUNTDISABLE: u32 = 0x0002;
    /// The account is locked out by policy.
    pub const LOCKOUT: u32 = 0x0010;
    /// The account is a machine account created with a broken password and never used.
    pub const PASSWD_NOTREQD: u32 = 0x0020;

    /// Reads the attribute's value.
    ///
    /// `None` for anything that is not a number, and the caller must decide: a flag word this
    /// server cannot read is not permission to authenticate, nor is it proof of a problem.
    pub fn parse(text: &str) -> Option<Self> {
        text.trim().parse::<u32>().ok().map(Self)
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    pub fn is_disabled(self) -> bool {
        self.0 & Self::ACCOUNTDISABLE != 0
    }

    pub fn is_locked_out(self) -> bool {
        self.0 & Self::LOCKOUT != 0
    }

    /// Whether this account may complete a bind.
    ///
    /// Deliberately not "everything except disabled": a flag word with only the bits this server
    /// does not understand set is an ordinary enabled account, and refusing it would break exactly
    /// the accounts the extension exists to serve.
    pub fn may_authenticate(self) -> bool {
        !self.is_disabled() && !self.is_locked_out()
    }

    /// The reason a bind was refused, in words an operator can act on.
    pub fn refusal(self) -> Option<&'static str> {
        if self.is_disabled() {
            return Some(
                "the account is disabled (userAccountControl ACCOUNTDISABLE): a ticket proves who \
                 the client is, but a disabled account may not use one",
            );
        }
        if self.is_locked_out() {
            return Some(
                "the account is locked out (userAccountControl LOCKOUT): unlock it before it may \
                 authenticate again",
            );
        }
        None
    }
}

/// The schema with the AD definitions added.
///
/// Returns the schema unchanged when it cannot parse the extension, and says so: a directory that
/// silently runs without half its published vocabulary is worse than one that starts with none,
/// and the definitions above are constants that a test parses on every run.
pub fn extend(schema: &mut Schema) -> Result<(), String> {
    schema.extend(AD_EXTENSION).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_ad() -> Schema {
        let mut schema = Schema::core();
        extend(&mut schema).expect("the AD extension parses");
        schema
    }

    #[test]
    fn the_extension_parses_and_publishes_the_attributes_ad_clients_ask_for() {
        // The whole point: a client asking for these must not get `undefinedAttributeType`.
        let schema = with_ad();

        for name in [
            "userprincipalname",
            "samaccountname",
            "useraccountcontrol",
            "objectguid",
            "objectsid",
            "serviceprincipalname",
            "primarygroupid",
            "grouptype",
            "accountexpires",
            "pwdlastset",
            "dnshostname",
            "msds-supportedencryptiontypes",
            "unicodepwd",
        ] {
            assert!(
                schema.attribute(name).is_some(),
                "{name} must be defined, or a client asking for it gets a refusal"
            );
        }
    }

    #[test]
    fn the_extension_publishes_the_ad_object_classes() {
        let schema = with_ad();

        for name in ["user", "group", "computer"] {
            assert!(schema.class(name).is_some(), "{name} must be defined");
        }
    }

    #[test]
    fn an_entry_shaped_like_an_ad_user_validates() {
        // A dump from a real directory is the test that matters: if `user` here refused what `user`
        // means there, the extension would be a vocabulary nobody can speak.
        let schema = with_ad();
        let entry = crate::model::Entry::new(
            "cn=Alice,ou=users,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(crate::model::Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "person".to_string(), "user".to_string()],
                ))
                .push(crate::model::Attribute::single("cn", "Alice"))
                .push(crate::model::Attribute::single("sn", "Kerberos"))
                .push(crate::model::Attribute::single(
                    "userPrincipalName",
                    "alice@EXAMPLE.COM",
                ))
                .push(crate::model::Attribute::single("sAMAccountName", "alice"))
                .push(crate::model::Attribute::single("userAccountControl", "512")),
        );

        if let Err(violations) = schema.check(&entry) {
            panic!("an AD-shaped user must validate: {violations:?}");
        }
    }

    #[test]
    fn an_entry_shaped_like_a_computer_that_joined_validates() {
        // Exactly what `net ads join` writes, attribute by attribute: the four SPNs it derives from
        // its own name, the host name a member reads back to find itself, the account flags, and the
        // enctypes. If any of these is missing from the schema, the member's single `add` is refused
        // as a whole and the failure reads as a schema complaint rather than as a missing attribute
        // - which is the state this test was written to end.
        let schema = with_ad();
        let entry = crate::model::Entry::new(
            "cn=samba,cn=computers,dc=ad,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(crate::model::Attribute::new(
                    "objectClass",
                    vec![
                        "top".to_string(),
                        "person".to_string(),
                        "organizationalPerson".to_string(),
                        "user".to_string(),
                        "computer".to_string(),
                    ],
                ))
                .push(crate::model::Attribute::single("cn", "samba"))
                .push(crate::model::Attribute::single("sn", "samba"))
                .push(crate::model::Attribute::single("sAMAccountName", "samba$"))
                .push(crate::model::Attribute::single(
                    "dNSHostName",
                    "samba.ad.example.com",
                ))
                .push(crate::model::Attribute::new(
                    "servicePrincipalName",
                    vec![
                        "HOST/samba".to_string(),
                        "HOST/samba.ad.example.com".to_string(),
                        "RestrictedKrbHost/samba".to_string(),
                        "RestrictedKrbHost/samba.ad.example.com".to_string(),
                    ],
                ))
                .push(crate::model::Attribute::single(
                    "userAccountControl",
                    "4128",
                ))
                .push(crate::model::Attribute::single(
                    "msDS-SupportedEncryptionTypes",
                    "24",
                )),
        );

        if let Err(violations) = schema.check(&entry) {
            panic!("a computer account as a member writes it must validate: {violations:?}");
        }
    }

    #[test]
    fn an_attribute_the_class_does_not_allow_is_still_caught() {
        // The extension must not turn strict checking into "anything goes": a class list that
        // allowed everything would pass the test above for the wrong reason.
        let schema = with_ad();
        let entry = crate::model::Entry::new(
            "cn=Bob,ou=users,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(crate::model::Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "person".to_string(), "user".to_string()],
                ))
                .push(crate::model::Attribute::single("cn", "Bob"))
                .push(crate::model::Attribute::single("sn", "Person"))
                .push(crate::model::Attribute::single("shadowLastChange", "19000")),
        );

        assert!(
            schema.check(&entry).is_err(),
            "an attribute outside the class list is a violation, extension or not"
        );
    }

    #[test]
    fn the_extension_is_not_part_of_the_core_schema() {
        // A server without a keytab must not publish AD vocabulary: it is not claiming to be a
        // domain controller, and a client that found these would rely on flags nothing maintains.
        let core = Schema::core();
        assert!(core.attribute("userprincipalname").is_none());
        assert!(core.class("user").is_none());
    }

    #[test]
    fn the_flag_word_decides_who_may_authenticate() {
        // 512 = NORMAL_ACCOUNT, the value a healthy AD user carries.
        assert!(
            UserAccountControl::parse("512")
                .expect("parsed")
                .may_authenticate()
        );
        // 514 = NORMAL_ACCOUNT | ACCOUNTDISABLE.
        assert!(
            !UserAccountControl::parse("514")
                .expect("parsed")
                .may_authenticate()
        );
        // 528 = NORMAL_ACCOUNT | LOCKOUT.
        assert!(
            !UserAccountControl::parse("528")
                .expect("parsed")
                .may_authenticate()
        );
        // Bits this server does not interpret alone leave the account usable.
        assert!(
            UserAccountControl::parse("66048")
                .expect("parsed")
                .may_authenticate(),
            "DONT_EXPIRE_PASSWORD is not a reason to refuse a ticket"
        );
    }

    #[test]
    fn a_flag_word_that_is_not_a_number_is_not_a_refusal() {
        // The caller decides what to do with `None`; this function must not guess that a value it
        // cannot read means "disabled", which would lock out an account over a typo.
        assert_eq!(UserAccountControl::parse("enabled"), None);
        assert_eq!(UserAccountControl::parse(""), None);
        assert_eq!(UserAccountControl::parse("-512"), None);
    }

    #[test]
    fn the_refusal_names_the_flag_that_caused_it() {
        let disabled = UserAccountControl::parse("514").expect("parsed");
        assert!(
            disabled
                .refusal()
                .is_some_and(|why| why.contains("disabled")),
            "{:?}",
            disabled.refusal()
        );

        let locked = UserAccountControl::parse("528").expect("parsed");
        assert!(
            locked.refusal().is_some_and(|why| why.contains("locked")),
            "{:?}",
            locked.refusal()
        );

        assert_eq!(
            UserAccountControl::parse("512").expect("parsed").refusal(),
            None
        );
    }
}
