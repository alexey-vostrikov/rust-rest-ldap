//! Password hashes: the schemes the directory can read and the ones it writes.
//!
//! The stored value carries its own scheme as a prefix (`{SSHA}…`, `{CRYPT}$6$…`,
//! `$argon2id$…`), the way `crypt(3)` carries the algorithm in the setting string.
//! Reading therefore has to recognise every scheme that real directories put in
//! `userPassword`, while writing only ever produces a strong one.
//!
//! Weak schemes are refused unless the operator allows them one by one: an old
//! hash in the data is not a reason to keep accepting a broken algorithm on a new
//! deployment, but a migration may need to read one for a while.

pub mod policy;
pub mod store;
pub mod verify;

pub use policy::{PasswordPolicy, StoreScheme, WeakScheme};
pub use store::hash;
pub use verify::{PasswordError, verify};

/// How much an offline attacker gains from a stolen hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// Fast hash or no hash at all: cracking is cheap.
    Weak,
    /// Key-derivation function with a work factor.
    Strong,
}

/// Password hash schemes found in LDAP directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Netscape SSHA: `{SSHA}` + base64(sha1(password || salt) || salt).
    Ssha,
    /// `{SHA}` + base64(sha1(password)), no salt.
    Sha,
    /// `{SMD5}` + base64(md5(password || salt) || salt).
    Smd5,
    /// `{MD5}` + base64(md5(password)), no salt.
    Md5,
    Ssha256,
    Ssha384,
    Ssha512,
    Sha256,
    Sha384,
    Sha512,
    Pbkdf2Sha256,
    Pbkdf2Sha512,
    Argon2id,
    Argon2i,
    Argon2d,
    Bcrypt,
    Yescrypt,
    CryptMd5,
    CryptSha256,
    CryptSha512,
    CryptScrypt,
    /// `{CLEARTEXT}`: the password itself.
    Cleartext,
}

impl Scheme {
    /// Name used in configuration and in diagnostics.
    pub fn name(&self) -> &'static str {
        match self {
            Scheme::Ssha => "ssha",
            Scheme::Sha => "sha",
            Scheme::Smd5 => "smd5",
            Scheme::Md5 => "md5",
            Scheme::Ssha256 => "ssha256",
            Scheme::Ssha384 => "ssha384",
            Scheme::Ssha512 => "ssha512",
            Scheme::Sha256 => "sha256",
            Scheme::Sha384 => "sha384",
            Scheme::Sha512 => "sha512",
            Scheme::Pbkdf2Sha256 => "pbkdf2-sha256",
            Scheme::Pbkdf2Sha512 => "pbkdf2-sha512",
            Scheme::Argon2id => "argon2id",
            Scheme::Argon2i => "argon2i",
            Scheme::Argon2d => "argon2d",
            Scheme::Bcrypt => "bcrypt",
            Scheme::Yescrypt => "yescrypt",
            Scheme::CryptMd5 => "crypt-md5",
            Scheme::CryptSha256 => "crypt-sha256",
            Scheme::CryptSha512 => "crypt-sha512",
            Scheme::CryptScrypt => "crypt-scrypt",
            Scheme::Cleartext => "cleartext",
        }
    }

    pub fn strength(&self) -> Strength {
        match self {
            Scheme::Ssha
            | Scheme::Sha
            | Scheme::Smd5
            | Scheme::Md5
            | Scheme::Ssha256
            | Scheme::Ssha384
            | Scheme::Ssha512
            | Scheme::Sha256
            | Scheme::Sha384
            | Scheme::Sha512
            | Scheme::CryptMd5
            | Scheme::CryptSha256
            | Scheme::CryptSha512
            | Scheme::Cleartext => Strength::Weak,
            Scheme::Pbkdf2Sha256
            | Scheme::Pbkdf2Sha512
            | Scheme::Argon2id
            | Scheme::Argon2i
            | Scheme::Argon2d
            | Scheme::Bcrypt
            | Scheme::Yescrypt
            | Scheme::CryptScrypt => Strength::Strong,
        }
    }

    pub fn is_weak(&self) -> bool {
        self.strength() == Strength::Weak
    }
}

/// Splits a stored value into its scheme and the scheme-specific payload.
///
/// A value without a recognised prefix is an error, never "plain text": treating
/// an unrecognised value as the password itself would authenticate anyone whose
/// hash the server could not parse.
pub fn detect(stored: &str) -> Result<(Scheme, &str), PasswordError> {
    if let Some(rest) = stored.strip_prefix('{') {
        let (name, payload) = match rest.split_once('}') {
            Some(split) => split,
            None => {
                return Err(PasswordError::Malformed {
                    scheme: "prefixed",
                    reason: "closing brace is missing",
                });
            }
        };
        let scheme = match name.to_ascii_uppercase().as_str() {
            "SSHA" => Scheme::Ssha,
            "SHA" => Scheme::Sha,
            "SMD5" => Scheme::Smd5,
            "MD5" => Scheme::Md5,
            "SSHA256" => Scheme::Ssha256,
            "SSHA384" => Scheme::Ssha384,
            "SSHA512" => Scheme::Ssha512,
            "SHA256" => Scheme::Sha256,
            "SHA384" => Scheme::Sha384,
            "SHA512" => Scheme::Sha512,
            "PBKDF2_SHA256" | "PBKDF2-SHA256" => Scheme::Pbkdf2Sha256,
            "PBKDF2_SHA512" | "PBKDF2-SHA512" => Scheme::Pbkdf2Sha512,
            "ARGON2" | "ARGON2ID" => Scheme::Argon2id,
            "CLEARTEXT" => Scheme::Cleartext,
            "CRYPT" => return detect_crypt(payload),
            other => return Err(PasswordError::UnsupportedScheme(other.to_ascii_lowercase())),
        };
        return Ok((scheme, payload));
    }

    if stored.starts_with('$') {
        return detect_crypt(stored);
    }

    Err(PasswordError::Unprefixed)
}

fn detect_crypt(value: &str) -> Result<(Scheme, &str), PasswordError> {
    let scheme = if value.starts_with("$1$") {
        Scheme::CryptMd5
    } else if value.starts_with("$5$") {
        Scheme::CryptSha256
    } else if value.starts_with("$6$") {
        Scheme::CryptSha512
    } else if value.starts_with("$7$") {
        Scheme::CryptScrypt
    } else if value.starts_with("$y$") || value.starts_with("$gy$") {
        Scheme::Yescrypt
    } else if value.starts_with("$2") {
        Scheme::Bcrypt
    } else if value.starts_with("$argon2id$") {
        Scheme::Argon2id
    } else if value.starts_with("$argon2i$") {
        Scheme::Argon2i
    } else if value.starts_with("$argon2d$") {
        Scheme::Argon2d
    } else {
        return Err(PasswordError::UnsupportedScheme(
            value.split('$').nth(1).unwrap_or_default().to_string(),
        ));
    };
    Ok((scheme, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_netscape_prefixes() {
        assert_eq!(detect("{SSHA}abc").map(|(s, _)| s), Ok(Scheme::Ssha));
        assert_eq!(detect("{ssha}abc").map(|(s, _)| s), Ok(Scheme::Ssha));
        assert_eq!(detect("{SSHA512}abc").map(|(s, _)| s), Ok(Scheme::Ssha512));
        assert_eq!(detect("{SHA}abc").map(|(s, _)| s), Ok(Scheme::Sha));
        assert_eq!(detect("{SMD5}abc").map(|(s, _)| s), Ok(Scheme::Smd5));
        assert_eq!(detect("{MD5}abc").map(|(s, _)| s), Ok(Scheme::Md5));
    }

    #[test]
    fn detects_389_ds_pbkdf2_prefixes() {
        assert_eq!(
            detect("{PBKDF2_SHA256}1000$c2FsdA==$aGFzaA=="),
            Ok((Scheme::Pbkdf2Sha256, "1000$c2FsdA==$aGFzaA=="))
        );
        assert_eq!(
            detect("{PBKDF2-SHA512}1000$c2FsdA==$aGFzaA==").map(|(s, _)| s),
            Ok(Scheme::Pbkdf2Sha512)
        );
    }

    #[test]
    fn detects_crypt_family_with_and_without_the_prefix() {
        let sha512 = "$6$salt$hash";
        assert_eq!(detect(sha512).map(|(s, _)| s), Ok(Scheme::CryptSha512));
        assert_eq!(
            detect(&format!("{{CRYPT}}{sha512}")),
            Ok((Scheme::CryptSha512, sha512))
        );
        assert_eq!(
            detect("$5$salt$hash").map(|(s, _)| s),
            Ok(Scheme::CryptSha256)
        );
        assert_eq!(detect("$1$salt$hash").map(|(s, _)| s), Ok(Scheme::CryptMd5));
        assert_eq!(
            detect("$y$j9T$salt$hash").map(|(s, _)| s),
            Ok(Scheme::Yescrypt)
        );
        assert_eq!(detect("$2b$12$salt").map(|(s, _)| s), Ok(Scheme::Bcrypt));
        assert_eq!(
            detect("$7$C6..../....salt").map(|(s, _)| s),
            Ok(Scheme::CryptScrypt)
        );
    }

    #[test]
    fn detects_argon2_phc_strings() {
        assert_eq!(
            detect("$argon2id$v=19$m=19456,t=2,p=1$abc$def").map(|(s, _)| s),
            Ok(Scheme::Argon2id)
        );
        assert_eq!(
            detect("$argon2i$v=19$m=4096,t=3,p=1$abc$def").map(|(s, _)| s),
            Ok(Scheme::Argon2i)
        );
        assert_eq!(
            detect("{ARGON2}$argon2id$v=19$m=19456,t=2,p=1$abc$def").map(|(s, _)| s),
            Ok(Scheme::Argon2id)
        );
    }

    #[test]
    fn value_without_prefix_is_refused() {
        assert_eq!(detect("secret"), Err(PasswordError::Unprefixed));
        assert_eq!(detect(""), Err(PasswordError::Unprefixed));
    }

    #[test]
    fn unknown_prefix_names_the_scheme() {
        assert_eq!(
            detect("{BXCRYPT}abc"),
            Err(PasswordError::UnsupportedScheme("bxcrypt".to_string()))
        );
        assert_eq!(
            detect("$9$abc"),
            Err(PasswordError::UnsupportedScheme("9".to_string()))
        );
    }

    #[test]
    fn prefix_without_closing_brace_is_malformed() {
        assert_eq!(
            detect("{SSHA"),
            Err(PasswordError::Malformed {
                scheme: "prefixed",
                reason: "closing brace is missing",
            })
        );
    }

    #[test]
    fn strength_classes_match_the_documented_split() {
        for weak in [
            Scheme::Ssha,
            Scheme::Sha,
            Scheme::Md5,
            Scheme::Smd5,
            Scheme::Ssha256,
            Scheme::Ssha384,
            Scheme::Ssha512,
            Scheme::Sha256,
            Scheme::Sha384,
            Scheme::Sha512,
            Scheme::CryptMd5,
            Scheme::CryptSha256,
            Scheme::CryptSha512,
            Scheme::Cleartext,
        ] {
            assert!(weak.is_weak(), "{} must be weak", weak.name());
        }
        for strong in [
            Scheme::Argon2id,
            Scheme::Argon2i,
            Scheme::Argon2d,
            Scheme::Bcrypt,
            Scheme::Yescrypt,
            Scheme::Pbkdf2Sha256,
            Scheme::Pbkdf2Sha512,
            Scheme::CryptScrypt,
        ] {
            assert!(!strong.is_weak(), "{} must be strong", strong.name());
        }
    }
}
