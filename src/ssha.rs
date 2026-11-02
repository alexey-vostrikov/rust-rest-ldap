//! Salted SHA-1 password hashes (`{SSHA}`), as used by gorestldap backends.
//!
//! Format: `{SSHA}` followed by the base64 of `sha1(password || salt) || salt`.
//! The digest comparison is constant time because the value comes from an
//! unauthenticated client.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const SSHA_PREFIX: &str = "{SSHA}";
const DIGEST_LEN: usize = 20;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SshaError {
    #[error("wrong hash length")]
    WrongLength,
    #[error("hash must start with {{SSHA}} scheme")]
    WrongScheme,
    #[error("error decoding hash: {0}")]
    Base64(String),
    #[error("no salt in hash")]
    NoSalt,
}

/// Checks `password` against the `{SSHA}` hash string `hash`.
///
/// Returns `Ok(true)` for a match, `Ok(false)` for a mismatch, and an error when
/// the stored hash itself is unusable (the caller must not treat that as a match
/// or as a client-side credential error).
pub fn validate_password(password: &str, hash: &str) -> Result<bool, SshaError> {
    let decoded = decode_hash(hash)?;
    let (digest, salt) = decoded.split_at(DIGEST_LEN);

    let expected = digest_with_salt(password, salt);
    Ok(bool::from(expected.ct_eq(digest)))
}

/// Builds the `{SSHA}` hash string for `password` and `salt`.
pub fn hash_password(password: &str, salt: &[u8]) -> String {
    let mut value = digest_with_salt(password, salt).to_vec();
    value.extend_from_slice(salt);
    format!("{SSHA_PREFIX}{}", BASE64.encode(value))
}

fn digest_with_salt(password: &str, salt: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    hasher.finalize().into()
}

fn decode_hash(hash: &str) -> Result<Vec<u8>, SshaError> {
    if hash.len() < SSHA_PREFIX.len() + 1 {
        return Err(SshaError::WrongLength);
    }
    let encoded = match hash.strip_prefix(SSHA_PREFIX) {
        Some(encoded) => encoded,
        None => return Err(SshaError::WrongScheme),
    };

    let decoded = BASE64
        .decode(encoded)
        .map_err(|err| SshaError::Base64(err.to_string()))?;
    if decoded.len() <= DIGEST_LEN {
        return Err(SshaError::NoSalt);
    }

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"12345678";

    #[test]
    fn matching_password_is_accepted() {
        let hash = hash_password("secret", SALT);

        assert_eq!(validate_password("secret", &hash), Ok(true));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let hash = hash_password("secret", SALT);

        assert_eq!(
            validate_password("Secret", &hash),
            Ok(false),
            "passwords are case sensitive"
        );
        assert_eq!(validate_password("", &hash), Ok(false));
        assert_eq!(validate_password("secret ", &hash), Ok(false));
    }

    #[test]
    fn empty_password_is_supported() {
        let hash = hash_password("", SALT);

        assert_eq!(validate_password("", &hash), Ok(true));
        assert_eq!(validate_password("x", &hash), Ok(false));
    }

    #[test]
    fn non_ascii_password_is_hashed_as_utf8() {
        let hash = hash_password("пароль", SALT);

        assert_eq!(validate_password("пароль", &hash), Ok(true));
    }

    #[test]
    fn hash_from_gorestldap_example_validates() {
        // examples/file/users.json of gorestldap: password "admin", 4-byte salt.
        let hash = "{SSHA}rapW2TNEFWp6HxD/nfwsjcBCD8Pi3Bvj";

        assert_eq!(validate_password("admin", hash), Ok(true));
        assert_eq!(validate_password("wrong", hash), Ok(false));
    }

    #[test]
    fn hash_without_salt_is_rejected() {
        let saltless = format!("{SSHA_PREFIX}{}", BASE64.encode([0u8; DIGEST_LEN]));

        assert_eq!(
            validate_password("secret", &saltless),
            Err(SshaError::NoSalt)
        );
    }

    #[test]
    fn hash_with_wrong_scheme_is_rejected() {
        let hash = "{SHA}2jmj7l5rSw0yVb/vlWAYkK/YBwk=";

        assert_eq!(
            validate_password("secret", hash),
            Err(SshaError::WrongScheme)
        );
    }

    #[test]
    fn short_hash_is_rejected() {
        assert_eq!(
            validate_password("secret", "{SSHA}"),
            Err(SshaError::WrongLength)
        );
        assert_eq!(validate_password("secret", ""), Err(SshaError::WrongLength));
    }

    #[test]
    fn broken_base64_is_rejected_with_reason() {
        let err = validate_password("secret", "{SSHA}not base64!!").expect_err("must reject");

        assert!(matches!(err, SshaError::Base64(_)), "unexpected {err:?}");
    }

    #[test]
    fn hash_is_salted_so_the_same_password_gives_different_strings() {
        let first = hash_password("secret", b"aaaaaaaa");
        let second = hash_password("secret", b"bbbbbbbb");

        assert_ne!(first, second);
        assert_eq!(validate_password("secret", &first), Ok(true));
        assert_eq!(validate_password("secret", &second), Ok(true));
    }
}
