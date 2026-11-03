//! The first administrator.
//!
//! An empty directory cannot be filled over the protocol: `add` needs a bind, and a bind
//! needs an entry with a password that does not exist yet. Every directory solves this
//! outside the protocol - `slapadd` for OpenLDAP, an installer for a commercial one - and so
//! does this one, with an entry named in the configuration that is created at startup.
//!
//! The rules that keep it from becoming a hole:
//!
//! - it runs only when the store holds **nothing at all**, so a configuration left in place
//!   after go-live is inert rather than destructive;
//! - it runs only on a backend that keeps writes, because seeding a file the server reads
//!   would either vanish at the next reload or fail halfway;
//! - the password is refused when empty or whitespace, which is the shape a broken secret
//!   mount takes;
//! - the DN must be inside the base, because a bind only searches there: an administrator
//!   created outside it would be seeded and never found, which is worse than a refusal.

use crate::backend::{Backend, BackendError, EntryChange};
use crate::config::BootstrapConfig;
use crate::dn;
use crate::model::{ATTR_LDAP_ADMIN, Attribute, Attributes, Entry};
use crate::password::store::hash;
use crate::password::{PasswordPolicy, StoreScheme};
use thiserror::Error;

/// What to create, and with which password.
///
/// The password is deliberately not `Debug`: a spec printed into a log or a panic message
/// would put the administrator's password in a file the operator does not think about.
#[derive(Clone, PartialEq, Eq)]
pub struct Spec {
    dn: String,
    password: Secret,
}

/// A password that does not print itself.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// The password, for the one call that hashes it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl std::fmt::Debug for Spec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spec")
            .field("dn", &self.dn)
            .field("password", &self.password)
            .finish()
    }
}

impl Spec {
    /// Builds the spec, filling in the default DN.
    ///
    /// The default is the administrator of the users unit: inside the base, under a `cn`
    /// that `person` accepts, and where every other account of this directory lives.
    pub fn new(
        dn: Option<&str>,
        base_dn: &str,
        users_ou_name: &str,
        password: &str,
    ) -> Result<Self, Error> {
        // A password that is empty or only whitespace is a secret that did not load. It is
        // refused here rather than at the bind, where it would look like a typo.
        if password.trim().is_empty() {
            return Err(Error::EmptyPassword);
        }

        let given = match dn {
            Some(dn) => dn.trim().to_string(),
            None => format!("cn=admin,ou={users_ou_name},{base_dn}"),
        };

        // Stored normalized, like every other DN the server compares: `CN=Admin,
        // DC=Example, DC=Com` and `cn=admin,dc=example,dc=com` are the same entry, and a
        // directory holding both spellings would hold two.
        let dn = dn::normalize(&given);

        if !dn::is_valid(&dn) {
            return Err(Error::InvalidDn { dn: given });
        }

        // A bind searches under the base, so anything outside it is unreachable.
        let base = dn::normalize(base_dn);
        if dn == base {
            // Not "outside the base": the base is the naming context, and an entry with
            // the base's own DN would replace the tree the administrator should live in.
            return Err(Error::AtBase { dn });
        }
        if !dn.ends_with(&format!(",{base}")) {
            return Err(Error::OutsideBase {
                dn,
                base_dn: base_dn.to_string(),
            });
        }

        Ok(Self {
            dn,
            password: Secret(password.to_string()),
        })
    }

    /// The DN the administrator will be created under.
    pub fn dn(&self) -> &str {
        &self.dn
    }
}

/// What the seed did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The store was empty and the administrator now exists.
    Created { dn: String },
    /// The store already held something; nothing was touched.
    NotEmpty { entries: usize },
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(
        "the bootstrap administrator has an empty password; a secret that does not load \
         looks exactly like this, and an administrator with no password is worse than none"
    )]
    EmptyPassword,
    #[error("the bootstrap DN '{dn}' is not a valid distinguished name")]
    InvalidDn { dn: String },
    #[error(
        "the bootstrap DN '{dn}' is the base DN itself; the base is the naming context, \
         not an entry to create, and the administrator has to live inside it"
    )]
    AtBase { dn: String },
    #[error(
        "the bootstrap DN '{dn}' is outside the base DN '{base_dn}'; a bind only searches \
         inside the base, so this administrator would be created and never found"
    )]
    OutsideBase { dn: String, base_dn: String },
    #[error(
        "bootstrap is configured for the '{backend}' backend, which stores users and groups \
         as fixed objects and has no place for a whole entry; use the 'redb' backend, or \
         prepare the store with an offline tool"
    )]
    BackendCannotStoreEntries { backend: String },
    #[error("cannot read the bootstrap password from '{path}': {source}")]
    PasswordFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "the bootstrap password is named by the environment variable '{name}', which is \
         not set or not readable; an unset secret is not an empty password"
    )]
    PasswordEnvUnset { name: String },
    #[error("hashing the bootstrap password failed: {0}")]
    Hash(String),
    #[error(transparent)]
    Backend(#[from] BackendError),
}

/// Reads the password the configuration points at.
///
/// The environment is a parameter rather than `std::env`: tests set their own names, and a
/// function that reads the process environment cannot be tested without changing it for
/// every other test running in the same process.
///
/// A trailing newline is dropped. `echo secret > password.txt` is what an operator writes,
/// and a password that fails because of an invisible byte is a support ticket that takes an
/// afternoon to diagnose.
pub fn password(
    config: &BootstrapConfig,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Secret, Error> {
    let text = match (&config.password_file, &config.password_env) {
        (Some(path), _) => std::fs::read_to_string(path).map_err(|source| Error::PasswordFile {
            path: path.display().to_string(),
            source,
        })?,
        (None, Some(name)) => {
            env(name).ok_or_else(|| Error::PasswordEnvUnset { name: name.clone() })?
        }
        // Unreachable through `Config::resolve`, which refuses a section with no source.
        // Refused here too, because this function is public and a caller may build the
        // section itself.
        (None, None) => String::new(),
    };

    let text = text.trim_end_matches(['\r', '\n']);
    if text.trim().is_empty() {
        return Err(Error::EmptyPassword);
    }

    Ok(Secret(text.to_string()))
}

/// Creates the administrator if the store is empty, using the default password policy.
pub async fn seed(backend: &Backend, spec: &Spec) -> Result<Outcome, Error> {
    seed_with(backend, spec, &PasswordPolicy::strict()).await
}

/// Creates the administrator if the store is empty.
pub async fn seed_with(
    backend: &Backend,
    spec: &Spec,
    policy: &PasswordPolicy,
) -> Result<Outcome, Error> {
    // Refused before the store is read: a backend that cannot keep the write would create
    // an administrator that disappears at the next restart, and the operator would find
    // out by not being able to log in.
    if !backend.stores_entries() {
        return Err(Error::BackendCannotStoreEntries {
            backend: backend.name().to_string(),
        });
    }

    let existing = backend.load().await?;
    let entries = existing.entries.len() + existing.users.len();

    // Not `is_empty` on one of the three lists: a backend that reports users and groups
    // separately is still a directory with data in it.
    if entries > 0 {
        return Ok(Outcome::NotEmpty { entries });
    }

    let entry = entry_for(spec, policy)?;
    backend
        .apply(&[EntryChange::Upsert { entry }])
        .await
        .map_err(Error::Backend)?;

    Ok(Outcome::Created {
        dn: spec.dn().to_string(),
    })
}

/// The entry an administrator with this DN and password consists of.
fn entry_for(spec: &Spec, policy: &PasswordPolicy) -> Result<Entry, Error> {
    // Nothing secret in the message: the scheme is configuration, the password is not.
    let hashed = hash(spec.password.expose(), policy.store_scheme())
        .map_err(|err| Error::Hash(err.to_string()))?;

    // The naming attribute comes from the DN: `cn=admin` needs `cn: admin`, `uid=root`
    // needs `uid: root`. Taken rather than assumed, because the default is `cn` but the
    // configured DN need not be.
    let (attribute, value, _) = dn::split_first_rdn(spec.dn());
    let mut attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec![
                "top".to_string(),
                "person".to_string(),
                "inetOrgPerson".to_string(),
            ],
        ))
        .push(Attribute::single(attribute.as_str(), &value))
        // `sn` is mandatory for `person` and there is nothing better to put here than the
        // name from the DN; an administrator is not a person in the directory's own sense.
        .push(Attribute::single("sn", &value))
        .push(
            Attribute::new("userPassword", vec![hashed])
                .case_sensitive()
                .sensitive(),
        )
        .push(Attribute::new(ATTR_LDAP_ADMIN, vec!["true".to_string()]).internal());

    if attribute != "cn" {
        // `person` requires `cn` regardless of what the DN uses, and a schema check in
        // strict mode would reject the entry without it.
        attributes = attributes.push(Attribute::single("cn", &value));
    }

    Ok(Entry::new(spec.dn(), attributes))
}

/// The scheme the seed password will be stored with, for the startup banner.
pub fn scheme_name(policy: &PasswordPolicy) -> &'static str {
    match policy.store_scheme() {
        StoreScheme::Argon2id => "argon2id",
        StoreScheme::Pbkdf2Sha512 => "pbkdf2-sha512",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_dn_lands_in_the_users_unit() {
        let spec = Spec::new(None, "dc=example,dc=com", "users", "s").expect("spec");
        assert_eq!(spec.dn(), "cn=admin,ou=users,dc=example,dc=com");
    }

    #[test]
    fn a_dn_equal_to_the_base_is_refused() {
        // `dc=example,dc=com` is the base itself, not a child of it. An entry with that DN
        // would replace the naming context the administrator is supposed to live in.
        let err = Spec::new(Some("dc=example,dc=com"), "dc=example,dc=com", "users", "s")
            .expect_err("must refuse");
        assert!(matches!(err, Error::AtBase { .. }), "{err}");
    }

    #[test]
    fn the_dn_is_stored_normalized() {
        // Case and spacing are not identity in a DN. Keeping the spelling as given would
        // let two configurations create what look like two administrators and behave as one.
        let spec = Spec::new(
            Some("CN=Admin, OU=Users, DC=Example, DC=Com"),
            "dc=example,dc=com",
            "users",
            "s",
        )
        .expect("case must not matter");
        assert_eq!(spec.dn(), "cn=admin,ou=users,dc=example,dc=com");
    }

    #[test]
    fn a_suffix_that_merely_looks_like_the_base_is_refused() {
        // `dc=notexample,dc=com` ends with `dc=example,dc=com` as a string but is a
        // different tree. The comma is what makes it a suffix of the DN and not of the text.
        let err = Spec::new(
            Some("cn=admin,dc=notexample,dc=com"),
            "dc=example,dc=com",
            "users",
            "s",
        )
        .expect_err("must refuse");
        assert!(matches!(err, Error::OutsideBase { .. }), "{err}");
    }

    #[test]
    fn the_spec_does_not_print_its_password() {
        let spec = Spec::new(None, "dc=example,dc=com", "users", "hunter2").expect("spec");
        let printed = format!("{spec:?}");
        assert!(
            !printed.contains("hunter2"),
            "a spec in a log must not carry the password: {printed}"
        );
    }

    #[test]
    fn the_naming_attribute_follows_the_dn() {
        let spec = Spec::new(
            Some("uid=root,ou=users,dc=example,dc=com"),
            "dc=example,dc=com",
            "users",
            "s",
        )
        .expect("spec");

        let entry = entry_for(&spec, &PasswordPolicy::strict()).expect("entry");
        assert_eq!(
            entry
                .attributes()
                .get("uid")
                .and_then(|attribute| attribute.values.first())
                .map(String::as_str),
            Some("root")
        );
        // And `cn`, which `person` requires, is still there for a schema check.
        assert!(entry.attributes().get("cn").is_some());
    }

    #[test]
    fn the_scheme_name_matches_the_policy() {
        assert_eq!(scheme_name(&PasswordPolicy::strict()), "argon2id");
    }
}

#[cfg(test)]
mod password_source_tests {
    use super::*;
    use std::path::PathBuf;

    fn section(file: Option<PathBuf>, env: Option<&str>) -> BootstrapConfig {
        BootstrapConfig {
            dn: None,
            password_file: file,
            password_env: env.map(str::to_string),
        }
    }

    #[test]
    fn a_file_is_read_and_its_trailing_newline_dropped() {
        // What `echo secret > password.txt` writes. Without the trim, the password the
        // operator typed and the password the server hashed differ by one byte, and the
        // bind fails for a reason nothing in the output explains.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "s3cret\n").expect("write");

        let secret = password(&section(Some(path), None), |_| None).expect("read");
        assert_eq!(secret.expose(), "s3cret");
    }

    #[test]
    fn a_file_with_an_empty_password_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "\n").expect("write");

        let err = password(&section(Some(path), None), |_| None).expect_err("must refuse");
        assert!(matches!(err, Error::EmptyPassword), "{err}");
    }

    #[test]
    fn a_missing_file_is_reported_with_its_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent.txt");

        let err = password(&section(Some(path.clone()), None), |_| None).expect_err("must fail");
        match err {
            Error::PasswordFile { path: reported, .. } => {
                assert_eq!(reported, path.display().to_string());
            }
            other => panic!("expected PasswordFile, got {other}"),
        }
    }

    #[test]
    fn an_environment_variable_is_read_from_the_one_it_was_given() {
        let secret = password(&section(None, Some("RRL_TEST_SECRET")), |name| {
            (name == "RRL_TEST_SECRET").then(|| "from-env".to_string())
        })
        .expect("read");

        assert_eq!(secret.expose(), "from-env");
    }

    #[test]
    fn an_unset_variable_says_which_one() {
        // An unset secret is a deployment mistake with an obvious fix, and the message has
        // to name the variable: "no password" sends the operator to the wrong file.
        let err = password(&section(None, Some("RRL_MISSING")), |_| None).expect_err("must fail");
        match err {
            Error::PasswordEnvUnset { name } => assert_eq!(name, "RRL_MISSING"),
            other => panic!("expected PasswordEnvUnset, got {other}"),
        }
    }

    #[test]
    fn a_password_given_by_both_sources_prefers_the_file() {
        // `Config::resolve` refuses this shape, so this only pins the order for a caller
        // that builds the section itself: one answer, and it is the documented one.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "from-file").expect("write");

        let secret = password(&section(Some(path), Some("RRL_TEST_SECRET")), |_| {
            Some("from-env".to_string())
        })
        .expect("read");

        assert_eq!(secret.expose(), "from-file");
    }
}
