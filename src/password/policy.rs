//! Password policy: which weak schemes may still be read, and what is written.

use std::collections::BTreeSet;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

use super::Scheme;

/// Weak schemes that a deployment may re-enable one at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WeakScheme {
    Ssha,
    Sha,
    Smd5,
    Md5,
    Ssha256,
    Ssha384,
    Ssha512,
    Sha256,
    Sha384,
    Sha512,
    CryptMd5,
    CryptSha256,
    CryptSha512,
    Cleartext,
}

impl WeakScheme {
    /// Every weak scheme, in the order the error message lists them.
    pub const ALL: [WeakScheme; 14] = [
        WeakScheme::Ssha,
        WeakScheme::Sha,
        WeakScheme::Smd5,
        WeakScheme::Md5,
        WeakScheme::Ssha256,
        WeakScheme::Ssha384,
        WeakScheme::Ssha512,
        WeakScheme::Sha256,
        WeakScheme::Sha384,
        WeakScheme::Sha512,
        WeakScheme::CryptMd5,
        WeakScheme::CryptSha256,
        WeakScheme::CryptSha512,
        WeakScheme::Cleartext,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            WeakScheme::Ssha => "ssha",
            WeakScheme::Sha => "sha",
            WeakScheme::Smd5 => "smd5",
            WeakScheme::Md5 => "md5",
            WeakScheme::Ssha256 => "ssha256",
            WeakScheme::Ssha384 => "ssha384",
            WeakScheme::Ssha512 => "ssha512",
            WeakScheme::Sha256 => "sha256",
            WeakScheme::Sha384 => "sha384",
            WeakScheme::Sha512 => "sha512",
            WeakScheme::CryptMd5 => "crypt-md5",
            WeakScheme::CryptSha256 => "crypt-sha256",
            WeakScheme::CryptSha512 => "crypt-sha512",
            WeakScheme::Cleartext => "cleartext",
        }
    }

    fn from_scheme(scheme: Scheme) -> Option<Self> {
        match scheme {
            Scheme::Ssha => Some(WeakScheme::Ssha),
            Scheme::Sha => Some(WeakScheme::Sha),
            Scheme::Smd5 => Some(WeakScheme::Smd5),
            Scheme::Md5 => Some(WeakScheme::Md5),
            Scheme::Ssha256 => Some(WeakScheme::Ssha256),
            Scheme::Ssha384 => Some(WeakScheme::Ssha384),
            Scheme::Ssha512 => Some(WeakScheme::Ssha512),
            Scheme::Sha256 => Some(WeakScheme::Sha256),
            Scheme::Sha384 => Some(WeakScheme::Sha384),
            Scheme::Sha512 => Some(WeakScheme::Sha512),
            Scheme::CryptMd5 => Some(WeakScheme::CryptMd5),
            Scheme::CryptSha256 => Some(WeakScheme::CryptSha256),
            Scheme::CryptSha512 => Some(WeakScheme::CryptSha512),
            Scheme::Cleartext => Some(WeakScheme::Cleartext),
            _ => None,
        }
    }
}

impl FromStr for WeakScheme {
    type Err = PolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        WeakScheme::ALL
            .into_iter()
            .find(|scheme| scheme.name().eq_ignore_ascii_case(value.trim()))
            .ok_or_else(|| PolicyError::UnknownWeakScheme {
                name: value.trim().to_string(),
            })
    }
}

/// Scheme used when the server writes a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum StoreScheme {
    #[default]
    Argon2id,
    Pbkdf2Sha512,
}

impl StoreScheme {
    /// The `Scheme` a hash written with this store scheme is detected as.
    pub fn scheme(&self) -> super::Scheme {
        match self {
            StoreScheme::Argon2id => super::Scheme::Argon2id,
            StoreScheme::Pbkdf2Sha512 => super::Scheme::Pbkdf2Sha512,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            StoreScheme::Argon2id => "argon2id",
            StoreScheme::Pbkdf2Sha512 => "pbkdf2-sha512",
        }
    }
}

impl FromStr for StoreScheme {
    type Err = PolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "argon2id" | "argon2" => Ok(StoreScheme::Argon2id),
            "pbkdf2-sha512" | "pbkdf2_sha512" => Ok(StoreScheme::Pbkdf2Sha512),
            other => Err(PolicyError::UnknownStoreScheme(other.to_string())),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error(
        "unknown weak password scheme '{name}', known schemes: {known}",
        known = WeakScheme::ALL.iter().map(|scheme| scheme.name()).collect::<Vec<_>>().join(", ")
    )]
    UnknownWeakScheme { name: String },
    #[error("unknown password storage scheme '{0}', known schemes: argon2id, pbkdf2-sha512")]
    UnknownStoreScheme(String),
    #[error(
        "weak password schemes are configured ({requested}) but AllowWeakHashes is not set; \
         if that is really what you want, add AllowWeakHashes: 'Yes I know this is bad idea' \
         to the passwords section"
    )]
    WeakSchemesNotAcknowledged { requested: String },
}

/// The sentence that unlocks weak password schemes.
///
/// Shared with every other dangerous setting, so an operator has one sentence to
/// remember and the code has one place to change the wording.
pub use crate::danger::ACKNOWLEDGEMENT as WEAK_ACKNOWLEDGEMENT;

/// What the server does with password hashes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswordPolicy {
    allowed_weak: BTreeSet<WeakScheme>,
    store_scheme: StoreScheme,
    /// Rewrite a stored hash into `store_scheme` on a successful bind.
    ///
    /// The bind is the only moment the server sees the password itself, so it is the
    /// only moment a weak hash can be upgraded without asking the user for anything.
    upgrade_on_bind: bool,
}

impl PasswordPolicy {
    /// Default: every weak scheme refused, new passwords in Argon2id, and a stored
    /// hash that is not already in that scheme is rewritten on the next successful
    /// bind.
    pub fn strict() -> Self {
        Self {
            upgrade_on_bind: true,
            ..Self::default()
        }
    }

    /// Policy taken from the `passwords:` configuration section.
    pub fn from_config(config: Option<&PasswordConfig>) -> Result<Self, PolicyError> {
        let Some(config) = config else {
            return Ok(Self::strict());
        };

        let requested = config.requested_weak();

        // A list without the sentence is a configuration error, not a warning: the
        // operator asked for something dangerous and did not say they meant it. The
        // server refuses to start rather than quietly deciding for them.
        if !requested.is_empty() && !config.acknowledges_weak_hashes() {
            return Err(PolicyError::WeakSchemesNotAcknowledged {
                requested: requested.join(", "),
            });
        }

        let mut allowed_weak = BTreeSet::new();
        for name in &requested {
            allowed_weak.insert(WeakScheme::from_str(name)?);
        }
        let store_scheme = match &config.store_scheme {
            Some(name) => StoreScheme::from_str(name)?,
            None => StoreScheme::default(),
        };

        Ok(Self {
            allowed_weak,
            store_scheme,
            // Off only when the operator says so: a directory full of `{SSHA}` is the
            // reason this exists, and the safe default is to fix it quietly.
            upgrade_on_bind: config.upgrade_on_bind.unwrap_or(true),
        })
    }

    pub fn store_scheme(&self) -> StoreScheme {
        self.store_scheme
    }

    /// True when the scheme may be used to check a password.
    pub fn may_verify(&self, scheme: Scheme) -> bool {
        match WeakScheme::from_scheme(scheme) {
            None => true,
            Some(weak) => self.allowed_weak.contains(&weak),
        }
    }

    pub fn upgrade_on_bind(&self) -> bool {
        self.upgrade_on_bind
    }

    /// True when `stored` is not in the configured storage scheme and should be
    /// rewritten the next time the password is known.
    ///
    /// A value the server cannot parse is not a candidate: rewriting it would mean
    /// guessing what it is. A value already in the configured scheme needs nothing.
    pub fn needs_rehash(&self, stored: &str) -> bool {
        if !self.upgrade_on_bind {
            return false;
        }

        let Ok((scheme, _)) = super::detect(stored) else {
            return false;
        };

        scheme != self.store_scheme.scheme()
    }

    pub fn allowed_weak(&self) -> impl Iterator<Item = WeakScheme> + '_ {
        self.allowed_weak.iter().copied()
    }
}

/// `passwords:` section of the configuration file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PasswordConfig {
    /// The sentence that unlocks weak schemes: `Yes I know this is bad idea`.
    ///
    /// A list on its own is not enough. A weak hash is not a preference, it is a
    /// decision to keep a directory readable by anyone who steals the file, and the
    /// operator has to say so in words before the server agrees to verify one.
    #[serde(rename = "AllowWeakHashes", alias = "allow_weak_hashes")]
    pub allow_weak_hashes: Option<String>,
    /// Weak schemes that may still be verified: `ssha, crypt-sha512`.
    #[serde(rename = "AllowedWeakHashes", alias = "allowed_weak_hashes")]
    pub allowed_weak_hashes: Option<String>,
    /// Old spelling: a bare list. Still read, but only together with the sentence.
    pub allow_weak: Vec<String>,
    /// Rewrite a stored hash into `store_scheme` on a successful bind; default true.
    pub upgrade_on_bind: Option<bool>,
    /// Scheme used when the server writes a password: `argon2id` (default) or
    /// `pbkdf2-sha512`.
    pub store_scheme: Option<String>,
}

impl PasswordConfig {
    /// Every weak scheme the operator asked for, from whichever spelling was used.
    pub fn requested_weak(&self) -> Vec<String> {
        let mut names: Vec<String> = self.allow_weak.clone();

        if let Some(list) = &self.allowed_weak_hashes {
            names.extend(
                list.split(',')
                    .map(|name| name.trim().to_string())
                    .filter(|name| !name.is_empty()),
            );
        }

        names
    }

    /// True when the operator wrote the sentence that unlocks weak schemes.
    pub fn acknowledges_weak_hashes(&self) -> bool {
        self.allow_weak_hashes
            .as_deref()
            .is_some_and(crate::danger::Danger::acknowledges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_policy_refuses_every_weak_scheme() {
        let policy = PasswordPolicy::strict();

        for scheme in [
            Scheme::Ssha,
            Scheme::Sha,
            Scheme::Md5,
            Scheme::Smd5,
            Scheme::Sha512,
            Scheme::Ssha512,
            Scheme::CryptSha512,
            Scheme::Cleartext,
        ] {
            assert!(
                !policy.may_verify(scheme),
                "{} must be refused",
                scheme.name()
            );
        }
    }

    #[test]
    fn strict_policy_accepts_strong_schemes() {
        let policy = PasswordPolicy::strict();

        for scheme in [
            Scheme::Argon2id,
            Scheme::Bcrypt,
            Scheme::Yescrypt,
            Scheme::Pbkdf2Sha256,
            Scheme::Pbkdf2Sha512,
        ] {
            assert!(
                policy.may_verify(scheme),
                "{} must be accepted",
                scheme.name()
            );
        }
    }

    #[test]
    fn weak_schemes_shown_in_config_are_verified_individually() {
        let config = PasswordConfig {
            allow_weak_hashes: Some(super::WEAK_ACKNOWLEDGEMENT.to_string()),
            allowed_weak_hashes: None,
            upgrade_on_bind: None,
            allow_weak: vec!["ssha".to_string()],
            store_scheme: None,
        };

        let policy = PasswordPolicy::from_config(Some(&config)).expect("policy");

        assert!(policy.may_verify(Scheme::Ssha));
        assert!(
            !policy.may_verify(Scheme::Sha),
            "allowing ssha must not allow sha"
        );
        assert!(
            !policy.may_verify(Scheme::CryptSha512),
            "nor other weak schemes"
        );
    }

    #[test]
    fn several_weak_schemes_can_be_allowed_together() {
        let config = PasswordConfig {
            allow_weak_hashes: Some(super::WEAK_ACKNOWLEDGEMENT.to_string()),
            allowed_weak_hashes: None,
            upgrade_on_bind: None,
            allow_weak: vec!["SSHA".to_string(), "crypt-sha512".to_string()],
            store_scheme: None,
        };

        let policy = PasswordPolicy::from_config(Some(&config)).expect("policy");

        assert!(policy.may_verify(Scheme::Ssha));
        assert!(policy.may_verify(Scheme::CryptSha512));
        assert_eq!(
            policy.allowed_weak().collect::<Vec<_>>(),
            vec![WeakScheme::Ssha, WeakScheme::CryptSha512]
        );
    }

    #[test]
    fn unknown_weak_scheme_is_rejected_with_the_list() {
        let config = PasswordConfig {
            allow_weak_hashes: Some(super::WEAK_ACKNOWLEDGEMENT.to_string()),
            allowed_weak_hashes: None,
            upgrade_on_bind: None,
            allow_weak: vec!["ssha1".to_string()],
            store_scheme: None,
        };

        let err = PasswordPolicy::from_config(Some(&config)).expect_err("must reject");

        assert_eq!(
            err,
            PolicyError::UnknownWeakScheme {
                name: "ssha1".to_string()
            }
        );
        assert!(
            err.to_string()
                .contains("known schemes: ssha, sha, smd5, md5")
        );
    }

    #[test]
    fn store_scheme_is_read_from_config() {
        let config = PasswordConfig {
            allow_weak_hashes: Some(super::WEAK_ACKNOWLEDGEMENT.to_string()),
            allowed_weak_hashes: None,
            upgrade_on_bind: None,
            allow_weak: Vec::new(),
            store_scheme: Some("PBKDF2-SHA512".to_string()),
        };

        let policy = PasswordPolicy::from_config(Some(&config)).expect("policy");

        assert_eq!(policy.store_scheme(), StoreScheme::Pbkdf2Sha512);
    }

    #[test]
    fn unknown_store_scheme_is_rejected() {
        let config = PasswordConfig {
            allow_weak_hashes: Some(super::WEAK_ACKNOWLEDGEMENT.to_string()),
            allowed_weak_hashes: None,
            upgrade_on_bind: None,
            allow_weak: Vec::new(),
            store_scheme: Some("md5".to_string()),
        };

        assert_eq!(
            PasswordPolicy::from_config(Some(&config)),
            Err(PolicyError::UnknownStoreScheme("md5".to_string()))
        );
    }

    #[test]
    fn missing_section_means_strict() {
        assert_eq!(
            PasswordPolicy::from_config(None).expect("policy"),
            PasswordPolicy::strict()
        );
    }
}
