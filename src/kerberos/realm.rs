//! The realm, read out of this server's own directory.
//!
//! Implements `rust_kdc::hdb::ldap::Directory`, which is the whole contract a KDC has with
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

use rust_kdc::Error;
use rust_kdc::hdb::ldap::{Attributes, Directory as Realm, attrs, dn_for, from_attributes};
use rust_kdc::name::Principal;

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
    ///
    /// Both lookups go through `record`, not through the snapshot. A restarted server holds a
    /// snapshot of *skeletons* - DN and indexed attributes, records read from the store when an
    /// answer needs them - so `all()` and `find()` return entries whose attribute list is empty.
    /// Measured: after a restart the realm could not find `admin@REALM` at all, because the scan
    /// below looked for `userPrincipalName` on identities that carry no attributes, and the KDC
    /// answered `KDC_ERR_C_PRINCIPAL_UNKNOWN` for an account the directory still held.
    fn entry_for(&self, principal: &Principal) -> Option<Entry> {
        let directory = self.current();

        let canonical = dn_for(principal, &self.base_dn);
        if let Some(entry) = directory.record(&canonical) {
            return Some(entry.into_owned());
        }

        // Not the canonical DN, so this account was created where a person put it. Compared on the
        // value rather than the DN, and on the two attributes a directory uses for the same fact:
        // `userPrincipalName` is the Microsoft spelling that a Windows client writes, and
        // `krb5PrincipalName` is the one a realm bootstrap writes.
        let wanted = principal.to_string();
        // `sAMAccountName` is the third spelling, and the one a machine is written under: `kinit
        // HOST$` asks for `HOST$@REALM` and the account the join created calls itself `HOST$` in
        // that attribute alone. It carries no realm, so it is compared against the name part.
        let account = principal.components.join("/");
        let matches = |entry: &Entry| {
            [attrs::PRINCIPAL_NAME, "userPrincipalName"]
                .iter()
                .any(|name| match entry.attributes().get(name) {
                    Some(attribute) => attribute
                        .values
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case(&wanted)),
                    None => false,
                })
                || entry
                    .attributes()
                    .get("sAMAccountName")
                    .is_some_and(|attribute| {
                        attribute
                            .values
                            .iter()
                            .any(|value| value.eq_ignore_ascii_case(&account))
                    })
        };
        self.first_complete(|entry| matches(entry))
    }

    /// The first entry whose *complete* record matches, read one DN at a time.
    ///
    /// A scan is already the fallback - the canonical DN answers a lookup in one read - and this
    /// keeps it honest on a snapshot of skeletons by reading each candidate from the store.
    fn first_complete(&self, matches: impl Fn(&Entry) -> bool) -> Option<Entry> {
        let directory = self.current();
        for identity in directory.entries_in_order() {
            let Some(record) = directory.record(identity.dn()) else {
                continue;
            };
            if matches(&record) {
                return Some(record.into_owned());
            }
        }
        None
    }
}

impl RealmView {
    /// The entry's attributes, with a principal name added when the entry has none.
    ///
    /// A directory in AD shape names an account by `sAMAccountName` and `userPrincipalName`, and
    /// knows nothing about `krb5PrincipalName` - that is Heimdal's attribute, written by a realm
    /// bootstrap. `from_attributes` refuses an entry without it ("this is not a principal"), so a
    /// machine account created by `net ads join`, or a user created by an administrator in an AD
    /// console, would be readable by every path except the one that issues tickets for it.
    ///
    /// `asked` is the principal the client sent, which is the name the entry must answer to: for a
    /// lookup by name it is exactly what the entry matched on, and for a lookup by service
    /// principal name the account's own name is used instead.
    fn published(&self, entry: &Entry, asked: &Principal) -> Attributes {
        let mut attributes = to_realm_attributes(entry.attributes());
        if !attributes.has(attrs::PRINCIPAL_NAME) {
            attributes.add(attrs::PRINCIPAL_NAME, asked.to_string());
        }
        if !attributes.has(attrs::PRINCIPAL_REALM) {
            attributes.add(attrs::PRINCIPAL_REALM, asked.realm.clone());
        }
        attributes
    }

    /// The account name of an entry, as a principal of this realm.
    ///
    /// `sAMAccountName` first, because that is the name a machine is written under, then
    /// `userPrincipalName`, then `krb5PrincipalName` - the name a realm bootstrap writes, and the
    /// only one a non-AD entry has. Anything the entry offers is better than refusing a ticket for
    /// an account that exists.
    fn name_of(&self, entry: &Entry) -> Option<Principal> {
        for name in ["sAMAccountName", "userPrincipalName", attrs::PRINCIPAL_NAME] {
            if let Some(value) = entry
                .attributes()
                .get(name)
                .and_then(|attribute| attribute.values.first())
            {
                let candidate = if value.contains('@') {
                    value.clone()
                } else {
                    format!("{value}@{}", self.realm)
                };
                if let Ok(principal) = Principal::parse(&candidate)
                    && principal.realm.eq_ignore_ascii_case(&self.realm)
                {
                    return Some(principal);
                }
            }
        }
        None
    }
}

impl Realm for RealmView {
    fn get(&self, principal: &Principal) -> rust_kdc::Result<Option<Attributes>> {
        let Some(entry) = self.entry_for(principal) else {
            return Ok(None);
        };
        let attributes = self.published(&entry, principal);
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

    /// The entry that publishes `spn` as a service principal name.
    ///
    /// A realm in AD shape does not name its machine accounts the way a client asks for them: the
    /// client wants `cifs/host.ad.example.com`, the account is `HOST$`, and the name the client used
    /// lives in `servicePrincipalName`. Looking up by principal alone misses it, and a Samba member
    /// cannot get the one ticket its join needs.
    ///
    /// A scan rather than an index lookup, because this directory publishes `servicePrincipalName`
    /// with an `eq` index only when an operator asked for it: correctness first, and the number of
    /// entries this is asked about is one per ticket. When the index is there the attribute is
    /// what a search would use, and this becomes the same work done by hand.
    fn get_by_spn(&self, spn: &str) -> rust_kdc::Result<Option<Attributes>> {
        let Some(entry) = self.first_complete(|entry| {
            entry
                .attributes()
                .get("servicePrincipalName")
                .is_some_and(|attribute| {
                    attribute
                        .values
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case(spn))
                })
        }) else {
            return Ok(None);
        };

        // The principal this entry answers to, when the entry does not name itself: a machine
        // account is `HOST$`, and the ticket the client asked for is for `cifs/host...`.
        let Some(account) = self.name_of(&entry) else {
            return Err(Error::Hdb(format!(
                "entry '{}' publishes '{spn}' and no account name, so there is no principal to \
                 seal a ticket for",
                entry.dn()
            )));
        };

        // Not decoded here, unlike `get`: the caller checks that the entry really publishes this
        // name, and an entry that fails to read back should be refused with that in hand rather than
        // with a decode error about a mapping.
        let attributes = self.published(&entry, &account);
        Ok(Some(attributes))
    }

    fn put(&self, principal: &Principal, _attributes: &Attributes) -> rust_kdc::Result<()> {
        // Not a limitation of this adapter but a decision: an account has a password policy, an
        // access check and a replication history, and all three live on the LDAP path. A KDC-side
        // write would create an entry that skipped them, and the entry would then be
        // indistinguishable from one that did not.
        Err(Error::Hdb(format!(
            "the realm is read-only here: write '{principal}' through LDAP"
        )))
    }

    fn delete(&self, principal: &Principal) -> rust_kdc::Result<bool> {
        Err(Error::Hdb(format!(
            "the realm is read-only here: delete '{principal}' through LDAP"
        )))
    }

    fn list(&self) -> rust_kdc::Result<Vec<Principal>> {
        let directory = self.current();
        let mut out = Vec::new();
        for identity in directory.entries_in_order() {
            let Some(entry) = directory.record(identity.dn()) else {
                continue;
            };
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

    use rust_kdc::crypto::{Enctype, OwnCipher};
    use rust_kdc::hdb::Hdb as _;
    use rust_kdc::hdb::HdbEntry;
    use rust_kdc::hdb::ldap::LdapHdb;

    use crate::model::{Attribute, Attributes, Entry};

    const BASE: &str = "dc=example,dc=com";
    const REALM: &str = "EXAMPLE.COM";

    /// A realm view over a directory holding the entries given.
    fn realm(entries: Vec<Entry>) -> RealmView {
        RealmView::new(
            REALM,
            BASE,
            Arc::new(Directory::from_entries(BASE, "users", "groups", entries)),
        )
    }

    /// An account as the KDC would write it: the principal's attributes in this store's spelling.
    fn principal_entry(name: &str, dn: Option<&str>) -> Entry {
        let principal = Principal::parse(&format!("{name}@{REALM}")).expect("a principal");
        let mut entry = HdbEntry::user(principal.clone());
        entry
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"pw", 1)
            .expect("a key");
        let dn = match dn {
            Some(dn) => dn.to_string(),
            None => dn_for(&principal, BASE),
        };
        Entry::new(dn, crate::kerberos::bootstrap::attributes_of(&entry))
    }

    #[test]
    fn a_principal_is_read_by_the_dn_the_kdc_would_have_written() {
        let view = realm(vec![principal_entry("alice", None)]);
        let alice = Principal::parse(&format!("alice@{REALM}")).expect("a principal");

        let attributes = view
            .get(&alice)
            .expect("the read succeeds")
            .expect("the principal is there");

        assert_eq!(
            attributes.first(attrs::PRINCIPAL_NAME),
            Some(format!("alice@{REALM}").as_bytes())
        );
        // The keys come back as the octets that went in, which is the round trip base64 exists for.
        assert!(!attributes.get(attrs::KEY).is_empty(), "the keys survived");
    }

    #[test]
    fn an_account_is_found_where_a_person_put_it() {
        // A directory is mostly entries nobody created for the realm's sake: an account lives at
        // `cn=...` under the users OU, not at `krb5PrincipalName=...`. Asking an operator to keep a
        // second copy under another DN is asking the two to drift, so the realm finds it by the name
        // it carries - `userPrincipalName`, the Microsoft spelling a Windows client writes.
        let entry = Entry::new(
            format!("cn=bob,ou=users,{BASE}"),
            Attributes::new()
                .push(Attribute::single("objectClass", "user"))
                .push(Attribute::single("cn", "bob"))
                .push(Attribute::single(
                    "userPrincipalName",
                    &format!("bob@{REALM}"),
                ))
                .push(Attribute::single(
                    "krb5PrincipalName",
                    &format!("bob@{REALM}"),
                ))
                .push(Attribute::single("krb5PrincipalRealm", REALM))
                .push(Attribute::single("krb5KeyVersionNumber", "1")),
        );
        let view = realm(vec![entry]);
        let bob = Principal::parse(&format!("bob@{REALM}")).expect("a principal");

        let attributes = view.get(&bob).expect("the read succeeds");
        assert!(
            attributes.is_some(),
            "an account is found by its principal name, not only at the realm's own DN"
        );
    }

    #[test]
    fn a_principal_nobody_has_is_absent_rather_than_an_error() {
        // The difference matters to the KDC: an absent principal is an unknown-user answer to the
        // client, and an error is a server fault. Answering one with the other turns a typo in a
        // login into an alarm.
        let view = realm(vec![principal_entry("alice", None)]);
        let nobody = Principal::parse(&format!("nobody@{REALM}")).expect("a principal");
        assert!(view.get(&nobody).expect("the read succeeds").is_none());
    }

    #[test]
    fn listing_names_the_principals_of_this_realm_and_no_others() {
        // `list` is what `kadmin` would use, and what a replication or an audit tool would ask. Two
        // things it must not do: invent a principal out of a value that is not one, and answer for
        // another realm - this process is one realm's KDC, and a ticket for a second would be a
        // ticket it cannot key.
        let foreign = Entry::new(
            format!("cn=carol,ou=users,{BASE}"),
            Attributes::new()
                .push(Attribute::single(
                    "krb5PrincipalName",
                    "carol@OTHER.EXAMPLE",
                ))
                .push(Attribute::single("krb5PrincipalRealm", "OTHER.EXAMPLE")),
        );
        let garbage = Entry::new(
            format!("cn=dave,ou=users,{BASE}"),
            Attributes::new().push(Attribute::single("krb5PrincipalName", "not a principal")),
        );
        let view = realm(vec![
            principal_entry("alice", None),
            principal_entry("bob", None),
            foreign,
            garbage,
        ]);

        let principals = view.list().expect("the listing succeeds");
        let names: Vec<String> = principals.iter().map(|p| p.to_string()).collect();

        assert!(names.contains(&format!("alice@{REALM}")), "{names:?}");
        assert!(names.contains(&format!("bob@{REALM}")), "{names:?}");
        assert!(
            !names.iter().any(|name| name.contains("carol")),
            "another realm's principal is not ours to issue: {names:?}"
        );
        assert!(
            !names.iter().any(|name| name.contains("dave")),
            "a value that is not a principal is skipped rather than guessed at: {names:?}"
        );
    }

    #[test]
    fn writing_through_the_realm_is_refused_and_says_where_to_go() {
        // Not a missing feature: an account has a password policy, an access check and a replication
        // history, and all three live on the LDAP path. A KDC-side write would create the one entry
        // in the directory that skipped them, and nothing downstream could tell it apart.
        let view = realm(vec![principal_entry("alice", None)]);
        let alice = Principal::parse(&format!("alice@{REALM}")).expect("a principal");

        let put = view.put(&alice, &rust_kdc::hdb::ldap::Attributes::new());
        let delete = view.delete(&alice);

        for error in [
            put.expect_err("a write is refused"),
            delete.expect_err("a delete is refused"),
        ] {
            let text = error.to_string();
            assert!(
                text.contains("through LDAP"),
                "the refusal must name the path that is allowed: {text}"
            );
        }
    }

    #[test]
    fn the_view_serves_the_snapshot_it_was_last_given() {
        // A realm that held its own copy of the entries would be a second thing to keep in step with
        // the directory; `refresh` is how the writer hands it the new one, and this is the read that
        // proves the hand-over happens.
        let view = realm(vec![principal_entry("alice", None)]);
        let bob = Principal::parse(&format!("bob@{REALM}")).expect("a principal");
        assert!(view.get(&bob).expect("read").is_none());

        view.refresh(Arc::new(Directory::from_entries(
            BASE,
            "users",
            "groups",
            vec![principal_entry("bob", None)],
        )));

        assert!(
            view.get(&bob).expect("read").is_some(),
            "after a refresh the new snapshot is what is served"
        );
    }

    /// The account a Samba member's join asks about: the client wants `cifs/host.ad.example.com`,
    /// the account is `HOST$`, and only `servicePrincipalName` connects the two. A realm that found
    /// entries by principal alone would answer `None`, the TGS would refuse the one ticket the join
    /// needs, and the failure would read as a service that does not exist.

    #[test]
    fn a_machine_account_is_found_by_the_service_name_it_publishes() {
        let host = Principal::parse(&format!("HOST$@{REALM}")).expect("a principal");
        let mut entry = HdbEntry::user(host.clone());
        entry
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"pw", 1)
            .expect("a key");

        let attributes = crate::kerberos::bootstrap::attributes_of(&entry)
            .push(Attribute::single(
                "servicePrincipalName",
                "cifs/host.ad.example.com",
            ))
            .push(Attribute::single(
                "servicePrincipalName",
                "host/host.ad.example.com",
            ));
        let view = realm(vec![Entry::new(dn_for(&host, BASE), attributes)]);

        // By the name a client asks for, which is not the account's name.
        let found = view
            .get_by_spn("cifs/host.ad.example.com")
            .expect("the read succeeds")
            .expect("the account that publishes it");
        assert_eq!(
            found.first(attrs::PRINCIPAL_NAME),
            Some(format!("HOST$@{REALM}").as_bytes()),
            "the entry is the machine account, not a principal named cifs/host"
        );

        // Ignoring case: a client spells the service name its own way and made no claim about case.
        assert!(
            view.get_by_spn("CIFS/Host.AD.Example.Com")
                .expect("read")
                .is_some()
        );

        // And a name nobody publishes is absent rather than approximated.
        assert!(
            view.get_by_spn("ldap/other.example.com")
                .expect("read")
                .is_none()
        );
    }

    /// A restarted server holds a snapshot of identities, not records, and the realm has to read
    /// through it.
    ///
    /// Measured on the AD-join stand: after a restart `kinit admin@REALM` answered
    /// `C_PRINCIPAL_UNKNOWN` for an account the directory still held and LDAP search still found.
    /// The lookup scanned `all()` for `userPrincipalName`, and a skeleton's attribute list is
    /// empty - so every account that lives where a person put it, rather than at the canonical DN,
    /// became invisible the moment the server was restarted.
    #[test]
    fn a_snapshot_of_skeletons_still_answers_for_an_account() {
        // `principal_entry` appends the realm itself: the name goes in bare, or the principal is
        // `alice@EXAMPLE.COM@EXAMPLE.COM` and nothing finds it.
        let entry = principal_entry("alice", Some(&format!("cn=alice,ou=users,{BASE}")));
        let full = std::collections::HashMap::from([(entry.dn().to_string(), entry.clone())]);

        // The snapshot the restart builds: identities only, records a read away.
        let mut directory = Directory::from_entries(BASE, "users", "groups", vec![entry]);
        directory.release_records();
        directory.attach_source(Arc::new(Store(full)));
        assert!(
            directory.is_skeleton(),
            "the test must exercise the skeleton path"
        );
        assert!(
            directory
                .find(&format!("cn=alice,ou=users,{BASE}"))
                .is_some_and(|entry| entry.attributes().values().is_empty()),
            "a skeleton holds no attributes, which is what made the scan find nothing"
        );

        let view = RealmView::new(REALM, BASE, Arc::new(directory));
        let principal = Principal::parse(&format!("alice@{REALM}")).expect("a principal");
        assert!(
            view.first_complete(|entry| entry
                .attributes()
                .get(attrs::PRINCIPAL_NAME)
                .is_some_and(|a| a.values.iter().any(|v| v.contains("alice"))))
                .is_some(),
            "the scan must find a record the snapshot does not hold"
        );
        assert!(
            view.entry_for(&principal).is_some(),
            "the lookup by principal name must find the account"
        );
        let attributes = view
            .get(&principal)
            .expect("the lookup itself succeeds")
            .expect("the account exists");
        assert!(
            attributes.has(attrs::KEY),
            "the record must be read from the store, keys and all"
        );
    }

    /// Where a skeleton's records come from.
    struct Store(std::collections::HashMap<String, Entry>);

    impl crate::directory::EntrySource for Store {
        fn get(&self, dn: &str) -> Option<Entry> {
            self.0.get(&crate::dn::normalize(dn)).cloned().or_else(|| {
                self.0
                    .values()
                    .find(|entry| crate::dn::normalize(entry.dn()) == crate::dn::normalize(dn))
                    .cloned()
            })
        }
    }

    #[test]
    fn the_realm_reaches_the_kdc_through_the_adapter() {
        // The seam itself: `LdapHdb` over this `Directory` is what the KDC is given, and a principal
        // fetched through it has to arrive with its keys - not merely be present.
        let view = realm(vec![principal_entry("alice", None)]);
        let hdb = LdapHdb::new(Arc::new(view) as Arc<dyn Realm>);
        let alice = Principal::parse(&format!("alice@{REALM}")).expect("a principal");

        let entry = hdb
            .fetch(&alice)
            .expect("the fetch succeeds")
            .expect("the principal is there");

        assert_eq!(entry.principal, alice);
        assert!(!entry.keys.is_empty(), "the keys crossed the adapter");
    }

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
