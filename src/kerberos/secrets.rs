//! What a machine account is, told to the SMB layer.
//!
//! `netr_ServerAuthenticate3` checks a secure channel against the account's NT hash and reports its
//! RID. `rrl-smb` is a library and holds no directory, so it asks the daemon that has one through
//! `MachineSecrets`; this module is that answer.
//!
//! # Where the hash comes from
//!
//! `supplementalCredentials`, under `Primary:NT`, as the hexadecimal text of sixteen octets - the
//! same attribute the KDC's keys live in, written in one blob by
//! `crate::kerberos::unicode_pwd::derive` so that a write cannot leave an account with keys and no
//! hash. An account with no such property is an account this server cannot check a channel for, and
//! it says so rather than answering with a hash nobody set.
//!
//! # Why the RID is read here and not stored
//!
//! It is the last sub-authority of `objectSid`, which the server already writes when it creates an
//! account. A second copy would be a second thing to keep in step with the first.

use std::sync::Arc;

#[cfg(feature = "smb")]
use smb_server::MachineAccount;

/// The directory, as the SMB layer sees it.
///
/// Holds the snapshot the server reloads: a machine account created an instant ago must be
/// checkable on the next connection, and a copy taken at start would refuse a channel for an account
/// that exists.
#[derive(Debug)]
pub struct DirectorySecrets {
    /// The current snapshot, replaced as the directory changes.
    ///
    /// A std lock and not the source's async one: the trait is synchronous, and it is called from a
    /// connection's own task - a machine account created a moment ago must be checkable on the next
    /// connection, which a snapshot taken at start would refuse.
    directory: std::sync::RwLock<Arc<crate::directory::Directory>>,
}

impl DirectorySecrets {
    pub fn new(directory: Arc<crate::directory::Directory>) -> Self {
        Self {
            directory: std::sync::RwLock::new(directory),
        }
    }

    /// The snapshot the next call will read.
    fn current(&self) -> Arc<crate::directory::Directory> {
        let current = match self.directory.read() {
            Ok(current) => current,
            // A poisoned lock means a panic while a caller held it; the snapshot behind it is still
            // a whole snapshot, and refusing every channel for ever is the worse answer.
            Err(poisoned) => poisoned.into_inner(),
        };
        Arc::clone(&current)
    }

    /// Keeps the snapshot current for as long as the daemon runs.
    ///
    /// Driven by the write notices the source already publishes: a machine account is created and
    /// then immediately used to establish a channel, so a snapshot that lagged behind the write
    /// would answer `NO_SUCH_USER` for an account the join had just made.
    pub fn follow(
        secrets: Arc<Self>,
        source: Arc<crate::reload::Source>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut notices = source.subscribe();
            loop {
                tokio::select! {
                    changed = stop.changed() => {
                        if changed.is_err() || *stop.borrow() {
                            return;
                        }
                    }
                    notice = notices.recv() => {
                        // A lagging subscriber re-reads the snapshot, which is the honest recovery;
                        // a closed channel means the source is gone and this task with it.
                        match notice {
                            Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                secrets.replace(source.directory().await);
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                        }
                    }
                }
            }
        })
    }

    /// Takes a fresh snapshot.
    pub fn replace(&self, directory: Arc<crate::directory::Directory>) {
        match self.directory.write() {
            Ok(mut current) => *current = directory,
            Err(poisoned) => *poisoned.into_inner() = directory,
        }
    }
}

#[cfg(feature = "smb")]
impl smb_server::MachineSecrets for DirectorySecrets {
    fn machine(&self, account: &str) -> Option<MachineAccount> {
        let directory = self.current();
        // Read through `record`, not through the snapshot: a snapshot taken by a start holds
        // *skeletons* - DN and indexed attributes, with the record a read away - so a scan over
        // `all()` sees an empty attribute list for every account that existed before the restart.
        // Measured on the AD-join stand: `machine()` answered "no such account" for a machine that
        // was in the directory, and the secure channel was refused with `NO_SUCH_USER`.
        let entry = first_complete(&directory, |entry| {
            entry
                .attributes()
                .get("sAMAccountName")
                .is_some_and(|attribute| {
                    attribute
                        .values
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case(account))
                })
        })?;

        let nt_hash = nt_hash_of(entry.attributes())?;
        if std::env::var_os("RRL_PW_DIAG").is_some() {
            let hex: String = nt_hash.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!(
                "pw-diag: checked '{account}' with nt_hash={hex} at {}",
                entry.dn()
            );
        }
        let rid = rid_of(entry.attributes())?;
        Some(MachineAccount { nt_hash, rid })
    }
}

/// Where a domain account's NT hash comes from, for the NTLM logon a machine makes before it has a
/// ticket.
///
/// `Add-Computer` cannot present a Kerberos ticket for a domain it has not joined - the domain has
/// not issued it one - so its first `SESSION_SETUP` is NTLM against a real account. With an empty
/// static user table the server answered `NT proof mismatch` for a password that was right, and the
/// guest reported "the user name or password is incorrect".
///
/// Two names resolve to one account, in the order a client sends them: `sAMAccountName`, which NTLM
/// carries (`AD\admin`), then `userPrincipalName`, which some clients and every ticket use. Both are
/// compared case-insensitively, as the directory compares them.
#[cfg(feature = "smb")]
impl smb_server::LogonUsers for DirectorySecrets {
    fn user(&self, account: &str) -> Option<smb_server::UserCreds> {
        let (nt_hash, _) = logon_account(&self.current(), account)?;
        Some(smb_server::UserCreds { nt_hash })
    }
}

/// The NT hash and DN of `account`, when this directory serves it and it may log on.
///
/// One function for both protocols on purpose. NTLM is checked in two places - the SMB session a
/// join opens, and the LDAP bind the join authenticates with - and a second copy of "is this account
/// allowed" is a second answer to the same question, differing exactly where nobody looks. Measured
/// on the AD-join stand: the LDAP bind was refused while the SMB logon beside it succeeded, and the
/// difference was that only one of the two had a directory to ask.
///
/// `None` covers "no such account" and "may not log on" alike: NTLM's defence against enumeration is
/// that both take the same time and give the same status, and an answer that distinguished them
/// would hand a client a list of real accounts.
pub(crate) fn logon_account(
    directory: &crate::directory::Directory,
    account: &str,
) -> Option<([u8; 16], String)> {
    // A scan must read records, not the snapshot: after a restart the snapshot holds skeletons - a
    // DN with an empty attribute list - and an account `ldapsearch` shows reads as "not in the
    // directory" here.
    let entry = first_complete(directory, |entry| {
        ["sAMAccountName", "userPrincipalName"].iter().any(|name| {
            entry.attributes().get(name).is_some_and(|attribute| {
                attribute
                    .values
                    .iter()
                    .any(|value| value.eq_ignore_ascii_case(account))
            })
        })
    })?;

    // A flag word this build cannot read is not permission either - `parse` says `None` for anything
    // that is not a number, and an entry whose flags cannot be read is one the KDC refuses too (see
    // `resolve_identity` in the SASL binder), so refusing it here keeps the three paths agreeing
    // rather than inventing a policy per protocol.
    let flags = entry
        .attributes()
        .get("userAccountControl")
        .and_then(|attribute| attribute.values.first())
        .and_then(|text| crate::ad_schema::UserAccountControl::parse(text))?;
    if !flags.may_authenticate() {
        return None;
    }

    let nt_hash = nt_hash_of(entry.attributes())?;
    Some((nt_hash, entry.dn().to_string()))
}

/// The first entry whose *complete* record matches, read one entry at a time.
///
/// A snapshot a start loaded from the stored index holds skeletons: the DN and the indexed
/// attributes, with the record itself a read away. `all()` therefore answers with empty attribute
/// lists for every entry that existed before the restart, and a scan that matches against them finds
/// nothing - measured on the AD-join stand, where `ldapsearch` showed the account and this scan said
/// it was not in the directory.
///
/// The cost is one store read per candidate, which is what a *lookup* costs and not what a search
/// costs: these are called once per logon, not once per entry of an answer.
fn first_complete(
    directory: &crate::directory::Directory,
    matches: impl Fn(&crate::model::Entry) -> bool,
) -> Option<crate::model::Entry> {
    for identity in directory.all() {
        let Some(record) = directory.record(identity.dn()) else {
            continue;
        };
        if matches(&record) {
            return Some(record.into_owned());
        }
    }
    None
}

/// The NT hash `supplementalCredentials` holds, or `None` when the account has none.
fn nt_hash_of(attributes: &crate::model::Attributes) -> Option<[u8; 16]> {
    let encoded = attributes
        .get(rrl_kdc::hdb::ldap::attrs::AD_SUPPLEMENTAL_CREDENTIALS)?
        .values
        .first()?;
    let blob = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?
    };
    // The NT hash is the RC4 key: `supplementalCredentials` holds it as a `rc4-hmac` credential, and
    // that is the only place a Windows logon's NT proof string can be checked against.
    let credentials = rrl_kdc::hdb::ad_blob::credentials(&blob).ok()?;
    let hash = credentials
        .into_iter()
        .find(|credential| credential.enctype == rrl_kdc::crypto::Enctype::Rc4Hmac)?
        .key;
    hash.try_into().ok()
}

/// The account's RID: the last sub-authority of its `objectSid`.
///
/// A SID is `S-1-5-21-a-b-c-rid`, and on the wire it is a revision octet, a sub-authority count, six
/// octets of identifier authority, then the sub-authorities as little-endian words. The last one is
/// the RID, which is why no separate attribute is kept for it.
fn rid_of(attributes: &crate::model::Attributes) -> Option<u32> {
    let encoded = attributes.get("objectSid")?.values.first()?;
    let sid = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?
    };
    let count = *sid.get(1)? as usize;
    if count == 0 {
        return None;
    }
    let end = 8 + count * 4;
    let last = sid.get(end - 4..end)?;
    Some(u32::from_le_bytes(last.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, Entry};

    fn machine(hash: Option<&[u8]>, sid: Option<&[u8]>) -> Entry {
        let mut attributes = crate::model::Attributes::new()
            .push(Attribute::single("sAMAccountName", "SAMBA$"))
            .push(Attribute::single("objectClass", "computer"));
        if let Some(sid) = sid {
            use base64::Engine as _;
            attributes = attributes.push(Attribute::single(
                "objectSid",
                &base64::engine::general_purpose::STANDARD.encode(sid),
            ));
        }
        if let Some(hash) = hash {
            let hash: [u8; 16] = hash.try_into().expect("sixteen octets");
            // The NT hash is the entry's `rc4-hmac` key, so the blob is built from an entry that has
            // one: that is what `supplementalCredentials` holds in AD, and what `nt_hash_of` reads back.
            let mut holder = rrl_kdc::hdb::HdbEntry::user(
                rrl_kdc::name::Principal::parse("SAMBA$@EXAMPLE.COM").expect("a name"),
            );
            holder.kvno = 1;
            holder.keys.push(rrl_kdc::hdb::HdbKey {
                kvno: 1,
                key: rrl_kdc::crypto::Key::new(rrl_kdc::crypto::Enctype::Rc4Hmac, hash.to_vec())
                    .expect("sixteen octets"),
                salt: None,
                mkvno: None,
            });
            use base64::Engine as _;
            attributes = attributes.push(Attribute::single(
                rrl_kdc::hdb::ldap::attrs::AD_SUPPLEMENTAL_CREDENTIALS,
                &base64::engine::general_purpose::STANDARD
                    .encode(rrl_kdc::hdb::ad_blob::supplemental_credentials(&holder)),
            ));
        }
        Entry::new("cn=samba,cn=computers,dc=example,dc=com", attributes)
    }

    /// A SID as the directory stores it: `S-1-5-21-1-2-3-1105`.
    fn sid_with_rid(rid: u32) -> Vec<u8> {
        let mut sid = vec![1u8, 5];
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
        // S-1-5-21-a-b-c-rid: five sub-authorities, and the count octet above says five.
        for sub in [21u32, 1, 2, 3, rid] {
            sid.extend_from_slice(&sub.to_le_bytes());
        }
        sid
    }

    #[test]
    fn a_machine_account_gives_its_hash_and_rid() {
        let sid = sid_with_rid(1105);
        let entry = machine(Some(&[0x11; 16]), Some(&sid));
        let directory = Arc::new(crate::directory::Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            vec![entry],
        ));
        let secrets = DirectorySecrets::new(directory);

        let account = smb_server::MachineSecrets::machine(&secrets, "SAMBA$").expect("found");
        assert_eq!(account.nt_hash, [0x11; 16]);
        assert_eq!(account.rid, 1105, "the last sub-authority is the RID");
        assert!(
            !format!("{account:?}").contains("11, 11"),
            "the hash must not print: {:?}",
            account
        );
    }

    #[test]
    fn an_account_without_a_hash_is_not_answered_for() {
        // Answering with a hash nobody set would authenticate a client against a password that does
        // not exist, which is worse than refusing the channel.
        let directory = Arc::new(crate::directory::Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            vec![machine(None, Some(&sid_with_rid(1105)))],
        ));
        let secrets = DirectorySecrets::new(directory);
        assert!(smb_server::MachineSecrets::machine(&secrets, "SAMBA$").is_none());
    }

    #[test]
    fn a_name_this_directory_does_not_hold_is_not_answered_for() {
        let directory = Arc::new(crate::directory::Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            vec![machine(Some(&[0x11; 16]), Some(&sid_with_rid(1105)))],
        ));
        let secrets = DirectorySecrets::new(directory);
        assert!(smb_server::MachineSecrets::machine(&secrets, "OTHER$").is_none());
    }

    /// A person's account, as a directory in AD shape holds one: `sAMAccountName`, a UPN, flags, and
    /// a hash in the same `supplementalCredentials` a machine's lives in.
    fn person(name: &str, flags: &str, hash: Option<[u8; 16]>) -> Entry {
        use base64::Engine as _;
        let mut attributes = crate::model::Attributes::new()
            .push(Attribute::single("sAMAccountName", name))
            .push(Attribute::single("cn", name))
            .push(Attribute::single("objectClass", "user"))
            .push(Attribute::single("userAccountControl", flags));
        if let Some(hash) = hash {
            let mut holder = rrl_kdc::hdb::HdbEntry::user(
                rrl_kdc::name::Principal::parse(&format!("{name}@EXAMPLE.COM")).expect("a name"),
            );
            holder.kvno = 1;
            holder.keys.push(rrl_kdc::hdb::HdbKey {
                kvno: 1,
                key: rrl_kdc::crypto::Key::new(rrl_kdc::crypto::Enctype::Rc4Hmac, hash.to_vec())
                    .expect("sixteen octets"),
                salt: None,
                mkvno: None,
            });
            attributes = attributes.push(Attribute::single(
                rrl_kdc::hdb::ldap::attrs::AD_SUPPLEMENTAL_CREDENTIALS,
                &base64::engine::general_purpose::STANDARD
                    .encode(rrl_kdc::hdb::ad_blob::supplemental_credentials(&holder)),
            ));
        }
        Entry::new(format!("cn={name},ou=users,dc=example,dc=com"), attributes)
    }

    fn with(entries: Vec<Entry>) -> DirectorySecrets {
        DirectorySecrets::new(Arc::new(crate::directory::Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            entries,
        )))
    }

    /// The logon a Windows machine makes before it has a ticket: `Add-Computer` sends NTLM, and the
    /// account it names is one only the directory knows.
    #[test]
    fn a_domain_account_answers_an_ntlm_logon_with_its_hash() {
        let secrets = with(vec![person("admin", "512", Some([0x42; 16]))]);
        let creds =
            smb_server::LogonUsers::user(&secrets, "admin").expect("the directory holds it");
        assert_eq!(creds.nt_hash, [0x42; 16]);
    }

    /// Case does not have to match: a Windows client sends the name the way the account is written
    /// and the directory compares it without regard to case.
    #[test]
    fn the_account_name_is_matched_without_regard_to_case() {
        let secrets = with(vec![person("Admin", "512", Some([0x42; 16]))]);
        assert!(smb_server::LogonUsers::user(&secrets, "ADMIN").is_some());
    }

    /// A disabled account answers exactly as an account that does not exist. NTLM's defence against
    /// enumeration is that both take the same time and give the same status; a hook that said
    /// "disabled" would hand a client a list of real accounts.
    #[test]
    fn a_disabled_account_answers_as_an_absent_one() {
        // 0x0002 is ACCOUNTDISABLE; 512 is an ordinary enabled account.
        let secrets = with(vec![
            person("fired", "514", Some([0x42; 16])),
            person("missing", "512", None),
        ]);
        assert!(smb_server::LogonUsers::user(&secrets, "fired").is_none());
        assert!(smb_server::LogonUsers::user(&secrets, "absent").is_none());
    }

    /// An account with no hash cannot be checked: answering with a hash nobody set would
    /// authenticate a client against a password that does not exist.
    #[test]
    fn a_domain_account_without_a_hash_is_not_answered_for() {
        let secrets = with(vec![person("nokey", "512", None)]);
        assert!(smb_server::LogonUsers::user(&secrets, "nokey").is_none());
    }

    /// A store keyed by the DN exactly as written, as the redb backend is.
    struct Store(std::collections::HashMap<String, Entry>);

    impl crate::directory::EntrySource for Store {
        fn get(&self, dn: &str) -> Option<Entry> {
            self.0.get(dn).cloned()
        }
    }

    /// The snapshot a restart builds answers with skeletons, and both lookups must read past them.
    ///
    /// Measured on the AD-join stand: after a restart `ldapsearch` showed the account, and this
    /// module answered "not in the directory" for it, because `all()` hands out DNs with empty
    /// attribute lists. The same shape broke `machine()` for every machine account that existed
    /// before the restart - accounts created while running are inserted whole, so the join's own
    /// machine account never showed it.
    #[test]
    fn a_restart_reads_the_record_behind_a_skeleton() {
        let admin = person("admin", "512", Some([0x42; 16]));
        let machine = machine(Some(&[0x11; 16]), Some(&sid_with_rid(1105)));

        // The containers `from_entries` adds, plus both accounts - the numbering has to cover every
        // entry or the snapshot is refused, and rightly.
        let all: Vec<String> = [
            "dc=example,dc=com".to_string(),
            "ou=users,dc=example,dc=com".to_string(),
            "ou=groups,dc=example,dc=com".to_string(),
            admin.dn().to_string(),
            machine.dn().to_string(),
        ]
        .into_iter()
        .collect();
        let skeletons: Vec<(String, crate::model::Attributes)> = all
            .iter()
            .map(|dn| (dn.clone(), crate::model::Attributes::new()))
            .collect();
        let numbering: std::collections::HashMap<String, u32> = all
            .iter()
            .enumerate()
            .map(|(position, dn)| (dn.clone(), 500 - position as u32))
            .collect();
        let store: std::collections::HashMap<String, Entry> = [
            (admin.dn().to_string(), admin),
            (machine.dn().to_string(), machine),
        ]
        .into_iter()
        .collect();

        let directory = crate::directory::Directory::from_skeletons(
            "dc=example,dc=com",
            "users",
            "groups",
            skeletons,
            crate::index::Index::default(),
            &numbering,
            900,
        )
        .expect("the numbering covers every entry")
        .with_source(Arc::new(Store(store)));

        let secrets = DirectorySecrets::new(Arc::new(directory));
        assert_eq!(
            smb_server::LogonUsers::user(&secrets, "admin")
                .expect("the directory holds it")
                .nt_hash,
            [0x42; 16]
        );
        assert_eq!(
            smb_server::MachineSecrets::machine(&secrets, "SAMBA$")
                .expect("the directory holds it")
                .rid,
            1105
        );
    }
}
