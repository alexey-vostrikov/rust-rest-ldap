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
}

/// What the server does with password hashes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswordPolicy {
    allowed_weak: BTreeSet<WeakScheme>,
    store_scheme: StoreScheme,
}

impl PasswordPolicy {
    /// Default: every weak scheme refused, new passwords in Argon2id.
    pub fn strict() -> Self {
        Self::default()
    }

    /// Policy taken from the `passwords:` configuration section.
    pub fn from_config(config: Option<&PasswordConfig>) -> Result<Self, PolicyError> {
        let Some(config) = config else {
            return Ok(Self::strict());
        };

        let mut allowed_weak = BTreeSet::new();
        for name in &config.allow_weak {
            allowed_weak.insert(WeakScheme::from_str(name)?);
        }
        let store_scheme = match &config.store_scheme {
            Some(name) => StoreScheme::from_str(name)?,
            None => StoreScheme::default(),
        };

        Ok(Self {
            allowed_weak,
            store_scheme,
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

    pub fn allowed_weak(&self) -> impl Iterator<Item = WeakScheme> + '_ {
        self.allowed_weak.iter().copied()
    }
}

/// `passwords:` section of the configuration file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PasswordConfig {
    /// Weak schemes that may still be verified, e.g. `[ssha, crypt-sha512]`.
    pub allow_weak: Vec<String>,
    /// Scheme used when the server writes a password: `argon2id` (default) or
    /// `pbkdf2-sha512`.
    pub store_scheme: Option<String>,
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
            allow_weak: Vec::new(),
            store_scheme: Some("PBKDF2-SHA512".to_string()),
        };

        let policy = PasswordPolicy::from_config(Some(&config)).expect("policy");

        assert_eq!(policy.store_scheme(), StoreScheme::Pbkdf2Sha512);
    }

    #[test]
    fn unknown_store_scheme_is_rejected() {
        let config = PasswordConfig {
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
