//! Checking a password against a stored hash.

use argon2::Argon2;
use argon2::password_hash::PasswordVerifier as _;
use argon2::password_hash::phc::PasswordHash as Argon2Hash;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::policy::PasswordPolicy;
use super::{Scheme, detect};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswordError {
    #[error("stored value has no password scheme prefix")]
    Unprefixed,
    #[error("unsupported password scheme '{0}'")]
    UnsupportedScheme(String),
    #[error("malformed {scheme} hash: {reason}")]
    Malformed {
        scheme: &'static str,
        reason: &'static str,
    },
    #[error("password scheme '{0}' is disabled by policy")]
    WeakSchemeDisabled(&'static str),
    #[error("error hashing password with {scheme}: {reason}")]
    Hash {
        scheme: &'static str,
        reason: String,
    },
}

/// Checks `password` against the stored hash.
///
/// `Ok(false)` means "wrong password"; an error means the stored value itself is
/// unusable or forbidden, which the caller must not report as a wrong password
/// without saying why.
pub fn verify(
    password: &str,
    stored: &str,
    policy: &PasswordPolicy,
) -> Result<bool, PasswordError> {
    let (scheme, payload) = detect(stored)?;

    if !policy.may_verify(scheme) {
        return Err(PasswordError::WeakSchemeDisabled(scheme.name()));
    }

    match scheme {
        Scheme::Ssha => salted_digest::<Sha1, 20>(password, payload, scheme),
        Scheme::Ssha256 => salted_digest::<Sha256, 32>(password, payload, scheme),
        Scheme::Ssha384 => salted_digest::<Sha384, 48>(password, payload, scheme),
        Scheme::Ssha512 => salted_digest::<Sha512, 64>(password, payload, scheme),
        Scheme::Sha => bare_digest::<Sha1, 20>(password, payload, scheme),
        Scheme::Sha256 => bare_digest::<Sha256, 32>(password, payload, scheme),
        Scheme::Sha384 => bare_digest::<Sha384, 48>(password, payload, scheme),
        Scheme::Sha512 => bare_digest::<Sha512, 64>(password, payload, scheme),
        Scheme::Smd5 => salted_digest::<md5::Md5, 16>(password, payload, scheme),
        Scheme::Md5 => bare_digest::<md5::Md5, 16>(password, payload, scheme),
        Scheme::Pbkdf2Sha256 => pbkdf2_check(password, payload, scheme, Pbkdf2Digest::Sha256),
        Scheme::Pbkdf2Sha512 => pbkdf2_check(password, payload, scheme, Pbkdf2Digest::Sha512),
        Scheme::Argon2id | Scheme::Argon2i | Scheme::Argon2d => {
            argon2_verify(password, payload, scheme)
        }
        Scheme::Bcrypt => bcrypt_verify(password, payload, scheme),
        Scheme::Yescrypt => yescrypt_verify(password, stored, scheme),
        Scheme::CryptSha256 | Scheme::CryptSha512 => sha_crypt_verify(password, payload, scheme),
        Scheme::CryptScrypt => Err(PasswordError::UnsupportedScheme("crypt-scrypt".to_string())),
        Scheme::CryptMd5 => Err(PasswordError::UnsupportedScheme("crypt-md5".to_string())),
        Scheme::Cleartext => Ok(ct_eq(password.as_bytes(), payload.as_bytes())),
    }
}

/// `{SSHA*}` / `{SMD5}`: base64(digest(password || salt) || salt).
fn salted_digest<D, const N: usize>(
    password: &str,
    payload: &str,
    scheme: Scheme,
) -> Result<bool, PasswordError>
where
    D: Digest + Default,
{
    let decoded = BASE64
        .decode(payload)
        .map_err(|_| malformed(scheme, "not valid base64"))?;
    if decoded.len() <= N {
        return Err(malformed(scheme, "no salt in value"));
    }
    let (expected, salt) = decoded.split_at(N);

    let mut hasher = D::default();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let actual = hasher.finalize();

    Ok(ct_eq(expected, actual.as_slice()))
}

/// `{SHA*}` / `{MD5}`: base64(digest(password)), no salt.
fn bare_digest<D, const N: usize>(
    password: &str,
    payload: &str,
    scheme: Scheme,
) -> Result<bool, PasswordError>
where
    D: Digest + Default,
{
    let decoded = BASE64
        .decode(payload)
        .map_err(|_| malformed(scheme, "not valid base64"))?;
    if decoded.len() != N {
        return Err(malformed(scheme, "digest has the wrong length"));
    }

    let mut hasher = D::default();
    hasher.update(password.as_bytes());
    let actual = hasher.finalize();

    Ok(ct_eq(&decoded, actual.as_slice()))
}

/// Digest used by a PBKDF2 stored value.
#[derive(Clone, Copy)]
enum Pbkdf2Digest {
    Sha256,
    Sha512,
}

/// `{PBKDF2_SHA256}` and `{PBKDF2_SHA512}`: `iterations$base64(salt)$base64(hash)`.
fn pbkdf2_check(
    password: &str,
    payload: &str,
    scheme: Scheme,
    digest: Pbkdf2Digest,
) -> Result<bool, PasswordError> {
    let mut parts = payload.split('$');
    let iterations = parts
        .next()
        .ok_or_else(|| malformed(scheme, "iteration count is missing"))?;
    let salt = parts
        .next()
        .ok_or_else(|| malformed(scheme, "salt is missing"))?;
    let expected = parts
        .next()
        .ok_or_else(|| malformed(scheme, "hash is missing"))?;

    let iterations: u32 = iterations
        .trim()
        .parse()
        .map_err(|_| malformed(scheme, "iteration count is not a number"))?;
    if iterations == 0 {
        return Err(malformed(scheme, "iteration count is zero"));
    }

    let salt = BASE64
        .decode(salt)
        .map_err(|_| malformed(scheme, "salt is not valid base64"))?;
    let expected = BASE64
        .decode(expected)
        .map_err(|_| malformed(scheme, "hash is not valid base64"))?;
    if expected.is_empty() {
        return Err(malformed(scheme, "hash is empty"));
    }

    let mut actual = vec![0u8; expected.len()];
    match digest {
        Pbkdf2Digest::Sha256 => {
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut actual);
        }
        Pbkdf2Digest::Sha512 => {
            pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), &salt, iterations, &mut actual);
        }
    }

    Ok(ct_eq(&expected, &actual))
}

fn argon2_verify(password: &str, payload: &str, scheme: Scheme) -> Result<bool, PasswordError> {
    let parsed = Argon2Hash::new(payload).map_err(|_| malformed(scheme, "not a PHC string"))?;
    let hasher = match scheme {
        Scheme::Argon2i => Argon2::new(
            argon2::Algorithm::Argon2i,
            argon2::Version::V0x13,
            argon2::Params::default(),
        ),
        Scheme::Argon2d => Argon2::new(
            argon2::Algorithm::Argon2d,
            argon2::Version::V0x13,
            argon2::Params::default(),
        ),
        _ => Argon2::default(),
    };

    match hasher.verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
        Err(err) => Err(PasswordError::Hash {
            scheme: scheme.name(),
            reason: err.to_string(),
        }),
    }
}

fn bcrypt_verify(password: &str, payload: &str, scheme: Scheme) -> Result<bool, PasswordError> {
    bcrypt::verify(password, payload).map_err(|err| PasswordError::Hash {
        scheme: scheme.name(),
        reason: err.to_string(),
    })
}

fn yescrypt_verify(password: &str, stored: &str, scheme: Scheme) -> Result<bool, PasswordError> {
    let parsed = yescrypt::PasswordHash::new(stored.to_string())
        .map_err(|_| malformed(scheme, "not a valid yescrypt value"))?;

    match yescrypt::Yescrypt::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(yescrypt::password_hash::Error::PasswordInvalid) => Ok(false),
        Err(err) => Err(PasswordError::Hash {
            scheme: scheme.name(),
            reason: err.to_string(),
        }),
    }
}

fn sha_crypt_verify(password: &str, payload: &str, scheme: Scheme) -> Result<bool, PasswordError> {
    use sha_crypt::PasswordVerifier as _;

    match sha_crypt::ShaCrypt::default().verify_password(password.as_bytes(), payload) {
        Ok(()) => Ok(true),
        Err(sha_crypt::password_hash::Error::PasswordInvalid) => Ok(false),
        Err(err) => Err(PasswordError::Hash {
            scheme: scheme.name(),
            reason: err.to_string(),
        }),
    }
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn malformed(scheme: Scheme, reason: &'static str) -> PasswordError {
    PasswordError::Malformed {
        scheme: scheme.name(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::policy::PasswordConfig;
    use crate::password::{PasswordPolicy, Scheme};

    /// Default policy: weak schemes refused.
    fn strict() -> PasswordPolicy {
        PasswordPolicy::strict()
    }

    /// Policy that re-enables the named weak schemes.
    fn permissive(schemes: &[&str]) -> PasswordPolicy {
        PasswordPolicy::from_config(Some(&PasswordConfig {
            allow_weak: schemes.iter().map(|name| name.to_string()).collect(),
            store_scheme: None,
        }))
        .expect("policy")
    }

    // External vectors, not produced by this code:
    //   $5$/$6$        — `openssl passwd -5 -6 -salt saltstring 'Hello world!'`
    //   yescrypt       — `mkpasswd -m yescrypt 'Hello world!'` (libxcrypt)
    //   PBKDF2-SHA256/512 — python hashlib.pbkdf2_hmac(..., 1000)
    //   {SSHA}         — examples/file/users.json of gorestldap (admin)
    const SHA256CRYPT: &str = "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5";
    const SHA512CRYPT: &str = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
    const YESCRYPT: &str =
        "$y$j9T$uyHcJ.9SD0dGa2D4dkct7/$BV.3gTvVIC/1L76g7lZ7lBw75sl857AXBvnR60Lt1dB";
    const PBKDF2_SHA256: &str =
        "{PBKDF2_SHA256}1000$c2FsdHlzYWx0$oIgMi9S7dLu8k+PDlBEWBwiZq8zhNvsXEiih3FOLmfw=";
    const PBKDF2_SHA512: &str = "{PBKDF2_SHA512}1000$c2FsdHlzYWx0$zon0VCBKmg4oZsfvqhI3cDlh5haI9onLq6t0oQRv8a3dhJ9/jyq11SOmkKH78qHh7fKFDTcSXE4Z8rVMjbzwXg==";
    const SSHA_ADMIN: &str = "{SSHA}rapW2TNEFWp6HxD/nfwsjcBCD8Pi3Bvj";

    #[test]
    fn crypt_sha512_from_openssl_verifies() {
        let policy = permissive(&["crypt-sha512"]);

        assert_eq!(verify("Hello world!", SHA512CRYPT, &policy), Ok(true));
        assert_eq!(verify("Hello world", SHA512CRYPT, &policy), Ok(false));
    }

    #[test]
    fn crypt_sha256_from_openssl_verifies() {
        let policy = permissive(&["crypt-sha256"]);

        assert_eq!(verify("Hello world!", SHA256CRYPT, &policy), Ok(true));
        assert_eq!(verify("helloworld!", SHA256CRYPT, &policy), Ok(false));
    }

    #[test]
    fn crypt_prefixed_value_verifies_too() {
        let policy = permissive(&["crypt-sha512"]);

        assert_eq!(
            verify("Hello world!", &format!("{{CRYPT}}{SHA512CRYPT}"), &policy),
            Ok(true)
        );
    }

    #[test]
    fn yescrypt_from_libxcrypt_verifies() {
        let policy = PasswordPolicy::strict();

        assert_eq!(verify("Hello world!", YESCRYPT, &policy), Ok(true));
        assert_eq!(verify("Hello World!", YESCRYPT, &policy), Ok(false));
    }

    #[test]
    fn pbkdf2_sha256_from_hashlib_verifies() {
        let policy = PasswordPolicy::strict();

        assert_eq!(verify("Hello world!", PBKDF2_SHA256, &policy), Ok(true));
        assert_eq!(verify("wrong", PBKDF2_SHA256, &policy), Ok(false));
    }

    #[test]
    fn pbkdf2_sha512_from_hashlib_verifies() {
        let policy = PasswordPolicy::strict();

        assert_eq!(verify("Hello world!", PBKDF2_SHA512, &policy), Ok(true));
        assert_eq!(verify("wrong", PBKDF2_SHA512, &policy), Ok(false));
    }

    #[test]
    fn gorestldap_ssha_verifies_only_when_allowed() {
        assert_eq!(
            verify("admin", SSHA_ADMIN, &strict()),
            Err(PasswordError::WeakSchemeDisabled("ssha"))
        );
        assert_eq!(
            verify("admin", SSHA_ADMIN, &permissive(&["ssha"])),
            Ok(true)
        );
        assert_eq!(
            verify("wrong", SSHA_ADMIN, &permissive(&["ssha"])),
            Ok(false)
        );
    }

    #[test]
    fn weak_scheme_allowed_individually_does_not_open_others() {
        let policy = permissive(&["sha512"]);

        assert_eq!(
            verify("admin", SSHA_ADMIN, &policy),
            Err(PasswordError::WeakSchemeDisabled("ssha"))
        );
        assert_eq!(
            verify("Hello world!", SHA512CRYPT, &policy),
            Err(PasswordError::WeakSchemeDisabled("crypt-sha512"))
        );
    }

    #[test]
    fn unsalted_digests_verify_when_allowed() {
        // base64(sha1("secret")), as python hashlib encodes it.
        let policy = permissive(&["sha"]);
        let hash = "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=".to_string();

        assert_eq!(verify("secret", &hash, &policy), Ok(true));
        assert_eq!(verify("Secret", &hash, &policy), Ok(false));
    }

    #[test]
    fn salted_sha2_family_verifies_when_allowed() {
        let policy = permissive(&["ssha512"]);
        let mut decoded = Vec::new();
        {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha512::default();
            hasher.update(b"secret");
            hasher.update(b"12345678");
            decoded.extend_from_slice(&hasher.finalize());
        }
        decoded.extend_from_slice(b"12345678");
        let stored = format!("{{SSHA512}}{}", BASE64.encode(&decoded));

        assert_eq!(verify("secret", &stored, &policy), Ok(true));
        assert_eq!(verify("Secret", &stored, &policy), Ok(false));
    }

    #[test]
    fn cleartext_is_refused_by_default_and_verifiable_when_enabled() {
        assert_eq!(
            verify("secret", "{CLEARTEXT}secret", &strict()),
            Err(PasswordError::WeakSchemeDisabled("cleartext"))
        );
        assert_eq!(
            verify("secret", "{CLEARTEXT}secret", &permissive(&["cleartext"])),
            Ok(true)
        );
        assert_eq!(
            verify("other", "{CLEARTEXT}secret", &permissive(&["cleartext"])),
            Ok(false)
        );
    }

    #[test]
    fn unprefixed_value_is_never_compared_as_plain_text() {
        assert_eq!(
            verify("secret", "secret", &strict()),
            Err(PasswordError::Unprefixed)
        );
    }

    #[test]
    fn broken_values_are_reported_as_malformed_not_as_wrong_password() {
        let policy = permissive(&["ssha", "crypt-sha512"]);

        assert_eq!(
            verify("secret", "{SSHA}not base64!!", &policy),
            Err(PasswordError::Malformed {
                scheme: "ssha",
                reason: "not valid base64",
            })
        );
        assert_eq!(
            verify("secret", "{SSHA}aGVsbG8=", &policy),
            Err(PasswordError::Malformed {
                scheme: "ssha",
                reason: "no salt in value",
            })
        );
        assert_eq!(
            verify("secret", "$6$salt", &policy),
            Err(PasswordError::Hash {
                scheme: "crypt-sha512",
                reason: sha_crypt::ShaCrypt::default()
                    .verify_password(b"secret", "$6$salt")
                    .expect_err("must fail")
                    .to_string(),
            })
        );
    }

    #[test]
    fn argon2_wrong_algorithm_name_is_unsupported() {
        assert_eq!(
            verify("x", "$argon9$v=19$m=1$s$h", &strict()),
            Err(PasswordError::UnsupportedScheme("argon9".to_string()))
        );
    }

    #[test]
    fn schema_names_are_stable() {
        assert_eq!(Scheme::Ssha.name(), "ssha");
        assert_eq!(
            crate::password::WeakScheme::CryptSha512.name(),
            "crypt-sha512"
        );
    }
}
