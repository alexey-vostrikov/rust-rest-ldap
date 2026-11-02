//! Writing new passwords.
//!
//! Only strong schemes are produced: Argon2id by default, PBKDF2-SHA512 when the
//! directory has to be consumed by a server that understands only that (389 DS
//! and FreeIPA read `{PBKDF2_SHA512}`).

use argon2::password_hash::PasswordHasher as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::Sha512;

use super::policy::StoreScheme;
use super::verify::PasswordError;

/// Iteration count for PBKDF2-SHA512 stored values, matching current guidance
/// rather than the 10 000 that older servers used.
pub const PBKDF2_ITERATIONS: u32 = 210_000;

const PBKDF2_SALT_LEN: usize = 16;
const PBKDF2_OUTPUT_LEN: usize = 64;

/// Hashes `password` with the configured storage scheme.
pub fn hash(password: &str, scheme: StoreScheme) -> Result<String, PasswordError> {
    match scheme {
        StoreScheme::Argon2id => hash_argon2id(password),
        StoreScheme::Pbkdf2Sha512 => hash_pbkdf2(password, PBKDF2_ITERATIONS, &random_salt()),
    }
}

fn hash_argon2id(password: &str) -> Result<String, PasswordError> {
    argon2::Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|err| PasswordError::Hash {
            scheme: "argon2id",
            reason: err.to_string(),
        })
}

/// `{PBKDF2_SHA512}iterations$base64(salt)$base64(hash)`.
fn hash_pbkdf2(password: &str, iterations: u32, salt: &[u8]) -> Result<String, PasswordError> {
    let mut output = [0u8; PBKDF2_OUTPUT_LEN];
    pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, iterations, &mut output);

    Ok(format!(
        "{{PBKDF2_SHA512}}{iterations}${}${}",
        BASE64.encode(salt),
        BASE64.encode(output)
    ))
}

fn random_salt() -> [u8; PBKDF2_SALT_LEN] {
    let mut salt = [0u8; PBKDF2_SALT_LEN];
    getrandom::fill(&mut salt).expect("system random number generator is unavailable");
    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::PasswordPolicy;
    use crate::password::verify::verify;

    fn policy() -> PasswordPolicy {
        PasswordPolicy::strict()
    }

    #[test]
    fn argon2id_output_verifies_and_wrong_password_does_not() {
        let stored = hash("correct horse", StoreScheme::Argon2id).expect("hash");

        assert!(stored.starts_with("$argon2id$"), "{stored}");
        assert_eq!(verify("correct horse", &stored, &policy()), Ok(true));
        assert_eq!(verify("wrong", &stored, &policy()), Ok(false));
    }

    #[test]
    fn argon2id_store_is_salted_so_the_same_password_differs() {
        let first = hash("correct horse", StoreScheme::Argon2id).expect("hash");
        let second = hash("correct horse", StoreScheme::Argon2id).expect("hash");

        assert_ne!(first, second);
        assert_eq!(verify("correct horse", &first, &policy()), Ok(true));
        assert_eq!(verify("correct horse", &second, &policy()), Ok(true));
    }

    #[test]
    fn pbkdf2_output_has_the_389_ds_shape_and_verifies() {
        let stored = hash("correct horse", StoreScheme::Pbkdf2Sha512).expect("hash");

        assert!(
            stored.starts_with(&format!("{{PBKDF2_SHA512}}{PBKDF2_ITERATIONS}$")),
            "{stored}"
        );
        assert_eq!(stored.split('$').count(), 3);
        assert_eq!(verify("correct horse", &stored, &policy()), Ok(true));
        assert_eq!(verify("wrong", &stored, &policy()), Ok(false));
    }

    #[test]
    fn pbkdf2_with_a_known_salt_matches_an_external_vector() {
        // Computed with python hashlib.pbkdf2_hmac("sha512", b"Hello world!",
        // b"saltysalt", 1000, 64), the same parameters 389 DS stores.
        let stored = hash_pbkdf2("Hello world!", 1000, b"saltysalt").expect("hash");

        assert_eq!(
            stored,
            "{PBKDF2_SHA512}1000$c2FsdHlzYWx0$zon0VCBKmg4oZsfvqhI3cDlh5haI9onLq6t0oQRv8a3dhJ9/jyq11SOmkKH78qHh7fKFDTcSXE4Z8rVMjbzwXg=="
        );
        assert_eq!(verify("Hello world!", &stored, &policy()), Ok(true));
    }

    #[test]
    fn empty_password_can_be_hashed_and_verified() {
        let argon2 = hash("", StoreScheme::Argon2id).expect("hash");
        let pbkdf2 = hash("", StoreScheme::Pbkdf2Sha512).expect("hash");

        assert_eq!(verify("", &argon2, &policy()), Ok(true));
        assert_eq!(verify("", &pbkdf2, &policy()), Ok(true));
        assert_eq!(verify("x", &argon2, &policy()), Ok(false));
    }

    #[test]
    fn random_salt_does_not_repeat() {
        let first = random_salt();
        let second = random_salt();

        assert_ne!(first, second);
        assert_eq!(first.len(), PBKDF2_SALT_LEN);
    }
}
