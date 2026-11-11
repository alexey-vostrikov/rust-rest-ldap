//! Writing a machine's password, as `netr_ServerPasswordSet2` delivers it.
//!
//! The join creates the computer account over LDAP with one password and then replaces it through
//! netlogon, and the keytab is written for the second: a server that acknowledges that call without
//! writing leaves the directory on the first password and the member on the second, and the next
//! `kinit` answers `Preauthentication failed` for an account that exists with keys nobody derived.
//! Measured on the stand: none of the directory's `krb5Key` blobs held the keytab's key.
//!
//! The write goes through the same derivation as an LDAP write of `unicodePwd` - `seal` turns a
//! password into `krb5Key` and `supplementalCredentials` in one blob - so a password that arrives
//! here is indistinguishable, afterwards, from one that arrived over LDAP.

use std::sync::Arc;

use smb_server::MachinePasswords;

/// The directory, as the SMB layer writes to it.
pub struct DirectoryPasswords {
    /// The source that persists a change and publishes it to readers.
    source: Arc<crate::reload::Source>,
    /// The policy in force: `seal` reads the realm and the enctypes from it.
    security: crate::security::Security,
}

/// The trait this implements wants `Debug`, and the source is not: its own `Debug` would be a
/// snapshot of a whole directory in a log line, so the name is what a diagnostic needs.
impl std::fmt::Debug for DirectoryPasswords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryPasswords").finish_non_exhaustive()
    }
}

impl DirectoryPasswords {
    pub fn new(source: Arc<crate::reload::Source>, security: crate::security::Security) -> Self {
        Self { source, security }
    }

    /// The account's entry, found by the name the call carried.
    async fn find(&self, account: &str) -> Option<crate::model::Entry> {
        let directory = self.source.directory().await;
        directory
            .all()
            .iter()
            .find(|entry| {
                entry
                    .attributes()
                    .get("sAMAccountName")
                    .is_some_and(|attribute| {
                        attribute
                            .values
                            .iter()
                            .any(|value| value.eq_ignore_ascii_case(account))
                    })
            })
            .cloned()
    }
}

#[async_trait::async_trait]
impl MachinePasswords for DirectoryPasswords {
    async fn set_password(&self, account: &str, password: &[u8]) -> bool {
        let Some(entry) = self.find(account).await else {
            tracing::warn!(account, "machine password: no such account");
            return false;
        };

        // The wire form of `unicodePwd` for octets that are already UTF-16LE: the quotes are code
        // units, not octets, and the value goes in base64 because the store holds text.
        let mut quoted = vec![b'"', 0];
        quoted.extend_from_slice(password);
        quoted.extend_from_slice(&[b'"', 0]);
        let encoded = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(&quoted)
        };

        // Replaced, not pushed: an account that already carries `unicodePwd` must not end up with
        // two, and the seal reads whichever it finds first.
        let attributes = entry
            .attributes()
            .clone()
            .without("unicodePwd")
            .push(crate::model::Attribute::single("unicodePwd", &encoded));
        let replaced = crate::model::Entry::new(entry.dn(), attributes);
        // The same derivation an LDAP write makes: keys and the NT hash in one blob, and the
        // plaintext dropped rather than stored.
        let sealed = crate::kerberos::unicode_pwd::seal(&replaced, &self.security);

        match self
            .source
            .apply(&[crate::backend::EntryChange::Upsert { entry: sealed }])
            .await
        {
            Ok(_) => {
                tracing::info!(
                    account,
                    "machine password: written through the same path as unicodePwd"
                );
                true
            }
            Err(err) => {
                tracing::warn!(account, %err, "machine password: the store refused the write");
                false
            }
        }
    }
}
