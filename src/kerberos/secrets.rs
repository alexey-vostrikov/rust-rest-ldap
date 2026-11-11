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

impl smb_server::MachineSecrets for DirectorySecrets {
    fn machine(&self, account: &str) -> Option<MachineAccount> {
        let directory = self.current();
        let diag = std::env::var_os("RRD_KEY_DIAG").is_some();
        let entry = directory.all().iter().find(|entry| {
            entry
                .attributes()
                .get("sAMAccountName")
                .is_some_and(|attribute| {
                    attribute
                        .values
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case(account))
                })
        });

        let Some(entry) = entry else {
            if diag {
                let known: Vec<&str> = directory
                    .all()
                    .iter()
                    .filter_map(|entry| entry.attributes().get("sAMAccountName"))
                    .flat_map(|attribute| attribute.values.iter().map(|v| &**v))
                    .collect();
                eprintln!("secrets-diag: no entry named {account}; sAMAccountName seen: {known:?}");
            }
            return None;
        };

        if diag {
            let names: Vec<&str> = entry
                .attributes()
                .values()
                .iter()
                .map(|attribute| &*attribute.name)
                .collect();
            eprintln!("secrets-diag: {account} -> {} names={names:?}", entry.dn());
        }
        let nt_hash = nt_hash_of(entry.attributes())?;
        let rid = rid_of(entry.attributes())?;
        Some(MachineAccount { nt_hash, rid })
    }
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
    let hash = rrl_kdc::hdb::ad_blob::nt_hash(&blob).ok()?;
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
            use base64::Engine as _;
            attributes = attributes.push(Attribute::single(
                rrl_kdc::hdb::ldap::attrs::AD_SUPPLEMENTAL_CREDENTIALS,
                &base64::engine::general_purpose::STANDARD.encode(
                    rrl_kdc::hdb::ad_blob::supplemental_credentials_with_nt(
                        &rrl_kdc::hdb::HdbEntry::user(
                            rrl_kdc::name::Principal::parse("SAMBA$@EXAMPLE.COM").expect("a name"),
                        ),
                        &hash,
                    ),
                ),
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
}
