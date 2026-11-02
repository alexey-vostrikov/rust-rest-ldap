//! Extended operations the server answers beyond StartTLS: `whoami` and Password Modify.
//!
//! `whoami` (RFC 4532) is one line: the client asks who the server thinks it is bound as,
//! and gets `dn:<dn>` or an empty value for anonymous. It exists so a script can check
//! what its credentials actually mean without searching the tree.
//!
//! Password Modify (RFC 3062) is the operation clients use to change a password. Without
//! it the only route is a `modify` on `userPassword`, which needs the write right on that
//! attribute — so a user could not change their own password in a directory whose ACL
//! denies exactly that, which is the usual hardening.
//!
//! The request and response are SEQUENCEs of context-tagged OCTET STRINGs:
//!
//! ```text
//! PasswdModifyRequestValue ::= SEQUENCE {
//!     userIdentity  [0] OCTET STRING OPTIONAL
//!     oldPasswd     [1] OCTET STRING OPTIONAL
//!     newPasswd     [2] OCTET STRING OPTIONAL }
//! ```
//!
//! rasn's derive macros do not reach a type defined in this crate, so the BER is written
//! and read here — the same decision the paged-results control took, for the same reason.

use rasn_ldap::{LdapMessage, MessageId, ResultCode};

use super::responses::extended_response_with_value;
use super::session::Session;
use crate::directory::Directory;
use crate::dn;
use crate::model::Entry;
use crate::password::{store, verify};
use crate::security::Security;

/// OID of the `whoami` extended request (RFC 4532).
pub const WHOAMI_OID: &str = "1.3.6.1.4.1.4203.1.11.3";
/// OID of the Password Modify extended request (RFC 3062).
pub const PASSWORD_MODIFY_OID: &str = "1.3.6.1.4.1.4203.1.11.1";

/// Which extended operation a name asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    WhoAmI,
    PasswordModify,
    Unknown,
}

pub fn operation(request_name: &[u8]) -> Operation {
    match request_name {
        name if name == WHOAMI_OID.as_bytes() => Operation::WhoAmI,
        name if name == PASSWORD_MODIFY_OID.as_bytes() => Operation::PasswordModify,
        _ => Operation::Unknown,
    }
}

/// The decoded Password Modify request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswordModify {
    /// Whose password; absent means the bound user's own.
    pub user_identity: Option<String>,
    /// Required unless the requester may write the attribute without it.
    pub old_password: Option<String>,
    /// Absent asks the server to generate one.
    pub new_password: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("the request value is not a BER sequence")]
    NotASequence,
    #[error("the request value is truncated")]
    Truncated,
    #[error("unexpected element with tag {0}")]
    UnexpectedTag(u8),
    #[error("the request value has trailing bytes")]
    TrailingBytes,
}

/// Decodes the request value of a Password Modify request.
pub fn decode(value: &[u8]) -> Result<PasswordModify, DecodeError> {
    let mut reader = Reader::new(value);
    let body = reader.sequence()?;

    let mut request = PasswordModify::default();
    let mut inner = Reader::new(body);

    while !inner.is_empty() {
        let (tag, content) = inner.tagged()?;
        let text = String::from_utf8_lossy(content).into_owned();

        match tag {
            0x80 => request.user_identity = Some(text),
            0x81 => request.old_password = Some(text),
            0x82 => request.new_password = Some(text),
            other => return Err(DecodeError::UnexpectedTag(other)),
        }
    }

    Ok(request)
}

/// Encodes a Password Modify response, which carries only an optional generated password.
pub fn encode_response(generated: Option<&str>) -> Vec<u8> {
    match generated {
        None => vec![0x30, 0x00],
        Some(password) => {
            let content = password.as_bytes();
            let mut inner = vec![0x80];
            push_length(&mut inner, content.len());
            inner.extend_from_slice(content);

            let mut out = vec![0x30];
            push_length(&mut out, inner.len());
            out.extend_from_slice(&inner);
            out
        }
    }
}

fn push_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(length as u8);
        return;
    }

    let bytes: Vec<u8> = length
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0)
        .collect();
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(&bytes);
}

/// Minimal BER reader: one sequence, then context-tagged octet strings.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Reads `SEQUENCE` and returns its contents.
    fn sequence(&mut self) -> Result<&'a [u8], DecodeError> {
        if self.bytes.first() != Some(&0x30) {
            return Err(DecodeError::NotASequence);
        }
        self.bytes = &self.bytes[1..];
        let length = self.length()?;
        self.take(length)
    }

    /// Reads a context-tagged element and returns its tag and contents.
    fn tagged(&mut self) -> Result<(u8, &'a [u8]), DecodeError> {
        let tag = *self.bytes.first().ok_or(DecodeError::Truncated)?;
        self.bytes = &self.bytes[1..];
        let length = self.length()?;
        Ok((tag, self.take(length)?))
    }

    fn length(&mut self) -> Result<usize, DecodeError> {
        let first = *self.bytes.first().ok_or(DecodeError::Truncated)?;
        self.bytes = &self.bytes[1..];

        if first & 0x80 == 0 {
            return Ok(first as usize);
        }

        let count = (first & 0x7f) as usize;
        if count == 0 {
            // Indefinite length is not allowed in LDAP (RFC 4511 §5.1).
            return Err(DecodeError::Truncated);
        }
        if self.bytes.len() < count {
            return Err(DecodeError::Truncated);
        }

        let mut length = 0usize;
        for byte in &self.bytes[..count] {
            length = (length << 8) | *byte as usize;
        }
        self.bytes = &self.bytes[count..];
        Ok(length)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        if self.bytes.len() < length {
            return Err(DecodeError::Truncated);
        }
        let (head, tail) = self.bytes.split_at(length);
        self.bytes = tail;
        Ok(head)
    }
}

/// What an extended request turned into.
pub enum Outcome {
    /// Send this message and change nothing.
    Reply(LdapMessage),
    /// Persist the entry, then answer with `success` carrying `response_value`.
    Persist { entry: Entry, success: LdapMessage },
}

/// Handles `whoami`.
pub fn handle_whoami(session: &Session, message_id: MessageId) -> Vec<LdapMessage> {
    let identity = session
        .identity()
        .map(|identity| identity.dn.clone())
        .unwrap_or_default();

    // RFC 4532: `dn:` followed by the DN, or the empty string for anonymous. The value is
    // an octet string, and answering with the authzId form keeps a client that compares
    // prefixes working.
    let value = if identity.is_empty() {
        String::new()
    } else {
        format!("dn:{identity}")
    };

    vec![extended_response_with_value(
        message_id,
        ResultCode::Success,
        "",
        Some(WHOAMI_OID),
        Some(value.as_bytes()),
    )]
}

/// Handles Password Modify (RFC 3062).
///
/// The rules, in the order they are checked:
/// - the transport must be acceptable for a password in flight, as for a simple bind;
/// - a password may only be set by a bound session;
/// - changing someone else's password needs the write right on their entry;
/// - changing your own needs the old password, which is what stops a stolen connection
///   from becoming a stolen account. An administrator may skip it, because resetting a
///   forgotten password is exactly the case where nobody knows the old one.
pub fn handle_password_modify(
    session: &Session,
    directory: &Directory,
    message_id: MessageId,
    request_value: Option<&[u8]>,
    security: &Security,
) -> Outcome {
    let reject = |code: ResultCode, diagnostic: &str| -> Outcome {
        Outcome::Reply(extended_response_with_value(
            message_id,
            code,
            diagnostic,
            Some(PASSWORD_MODIFY_OID),
            None,
        ))
    };

    if !session.is_encrypted() && !security.allow_unencrypted_bind {
        return reject(
            ResultCode::StrongerAuthRequired,
            "the password would travel in the clear; use LDAPS or StartTLS",
        );
    }

    let Some(identity) = session.identity().cloned() else {
        return reject(
            ResultCode::UnwillingToPerform,
            "a password change needs a bound session",
        );
    };

    let request = match request_value {
        None => PasswordModify::default(),
        Some(value) => match decode(value) {
            Ok(request) => request,
            Err(err) => return reject(ResultCode::ProtocolError, &err.to_string()),
        },
    };

    let target_dn = match request.user_identity.as_deref() {
        None => identity.dn.clone(),
        Some(identity_value) => {
            // RFC 3062 allows `dn:<dn>`, `u:<uid>` and a bare DN. The bare form is what
            // every client sends, but the prefixes cost three lines and avoid a surprise.
            let value = identity_value.strip_prefix("dn:").unwrap_or(identity_value);
            dn::normalize(value)
        }
    };

    let Some(entry) = directory.find(&target_dn) else {
        return reject(ResultCode::NoSuchObject, "target entry not found");
    };

    let requester = session.requester();
    let own_entry = requester
        .dn
        .as_deref()
        .is_some_and(|own| dn::normalize(own) == dn::normalize(entry.dn()));

    let may_write = security
        .acl
        .rights(&requester, directory, entry.dn(), Some("userPassword"))
        .write;

    if !own_entry && !may_write {
        return reject(
            ResultCode::InsufficientAccessRights,
            "not allowed to change this entry's password",
        );
    }

    // The old password is what proves the person is the person, not just whoever is
    // holding the connection. An administrator resetting a forgotten password cannot know
    // it, which is why the rule applies only outside that case.
    if own_entry && !identity.admin {
        let Some(old) = request.old_password.as_deref() else {
            return reject(
                ResultCode::UnwillingToPerform,
                "changing your own password requires the old one",
            );
        };

        let stored = entry
            .attributes()
            .get("userPassword")
            .and_then(|attribute| attribute.values.first())
            .cloned()
            .unwrap_or_default();

        match verify::verify(old, &stored, &security.passwords) {
            Ok(true) => {}
            Ok(false) => {
                return reject(ResultCode::InvalidCredentials, "wrong old password");
            }
            Err(err) => {
                return reject(
                    ResultCode::InvalidCredentials,
                    &format!("cannot verify the old password: {err}"),
                );
            }
        }
    }

    // No new password means "make me one": a client that wants a strong random password
    // should not have to invent it, and the server already has a generator.
    let (password, generated) = match request.new_password.clone() {
        Some(password) if !password.is_empty() => (password, false),
        _ => (generate_password(), true),
    };

    let hash = match store::hash(&password, security.passwords.store_scheme()) {
        Ok(hash) => hash,
        Err(err) => {
            return reject(
                ResultCode::Other,
                &format!("cannot hash the password: {err}"),
            );
        }
    };

    let mut attribute = crate::model::Attribute::single("userPassword", &hash)
        .case_sensitive()
        .sensitive();
    if let Some(existing) = entry.attributes().get("userPassword") {
        attribute.flags = existing.flags;
    }

    let updated = Entry::new(entry.dn(), entry.attributes().clone().replace(attribute));
    let stamped =
        crate::operational::stamp_write(&updated, &identity.dn, std::time::SystemTime::now());

    let value = generated.then_some(password.as_str());
    Outcome::Persist {
        entry: stamped,
        success: {
            let encoded = value.map(|password| encode_response(Some(password)));
            extended_response_with_value(
                message_id,
                ResultCode::Success,
                "",
                Some(PASSWORD_MODIFY_OID),
                encoded.as_deref(),
            )
        },
    }
}

/// A random password for a client that asked for one.
///
/// 24 bytes of entropy in base64: long enough that nobody memorises it, and the client
/// shows it once. The alphabet is the base64 one, so it survives being copied out of a
/// terminal.
fn generate_password() -> String {
    let mut bytes = [0u8; 18];
    getrandom::fill(&mut bytes).expect("system random number generator is unavailable");

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(24);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 6) as usize & 0x3f] as char);
        out.push(ALPHABET[triple as usize & 0x3f] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_request(parts: &[(u8, &str)]) -> Vec<u8> {
        let mut inner = Vec::new();
        for (tag, value) in parts {
            inner.push(*tag);
            push_length(&mut inner, value.len());
            inner.extend_from_slice(value.as_bytes());
        }

        let mut out = vec![0x30];
        push_length(&mut out, inner.len());
        out.extend_from_slice(&inner);
        out
    }

    #[test]
    fn the_rfc_oids_are_recognised() {
        assert_eq!(operation(b"1.3.6.1.4.1.4203.1.11.3"), Operation::WhoAmI);
        assert_eq!(
            operation(b"1.3.6.1.4.1.4203.1.11.1"),
            Operation::PasswordModify
        );
        assert_eq!(operation(b"1.3.6.1.4.1.1466.20037"), Operation::Unknown);
        assert_eq!(operation(b""), Operation::Unknown);
    }

    #[test]
    fn a_full_request_is_decoded() {
        let value = encode_request(&[
            (0x80, "cn=alice,ou=users,dc=example,dc=com"),
            (0x81, "old"),
            (0x82, "new"),
        ]);

        assert_eq!(
            decode(&value),
            Ok(PasswordModify {
                user_identity: Some("cn=alice,ou=users,dc=example,dc=com".to_string()),
                old_password: Some("old".to_string()),
                new_password: Some("new".to_string()),
            })
        );
    }

    #[test]
    fn an_empty_sequence_means_change_my_own_password() {
        assert_eq!(
            decode(&[0x30, 0x00]),
            Ok(PasswordModify::default()),
            "every field is optional: absent identity is 'me', absent new password asks the server to make one"
        );
    }

    #[test]
    fn only_the_new_password_is_allowed_to_be_present() {
        let value = encode_request(&[(0x82, "fresh")]);

        assert_eq!(
            decode(&value),
            Ok(PasswordModify {
                user_identity: None,
                old_password: None,
                new_password: Some("fresh".to_string()),
            })
        );
    }

    #[test]
    fn a_long_value_uses_the_long_length_form() {
        let long = "x".repeat(200);
        let value = encode_request(&[(0x82, &long)]);

        assert_eq!(
            decode(&value).expect("decoded").new_password,
            Some(long),
            "a length above 127 has to be read back correctly"
        );
    }

    #[test]
    fn a_request_that_is_not_a_sequence_is_refused() {
        assert_eq!(decode(&[0x04, 0x01, b'x']), Err(DecodeError::NotASequence));
    }

    #[test]
    fn a_truncated_request_is_refused() {
        assert_eq!(
            decode(&[0x30, 0x05, 0x80, 0x01, b'a']),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn an_unknown_tag_is_refused() {
        let value = encode_request(&[(0x83, "x")]);

        assert_eq!(decode(&value), Err(DecodeError::UnexpectedTag(0x83)));
    }

    #[test]
    fn an_indefinite_length_is_refused() {
        // RFC 4511 §5.1 forbids it in LDAP; accepting it would need a loop and a bound.
        assert_eq!(
            decode(&[0x30, 0x80, 0x00, 0x00]),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn a_response_without_a_generated_password_is_an_empty_sequence() {
        assert_eq!(encode_response(None), vec![0x30, 0x00]);
    }

    #[test]
    fn a_response_with_a_generated_password_round_trips() {
        let encoded = encode_response(Some("AbC123"));

        let mut reader = Reader::new(&encoded);
        let body = reader.sequence().expect("sequence");
        let mut inner = Reader::new(body);
        let (tag, content) = inner.tagged().expect("tagged");

        assert_eq!(tag, 0x80);
        assert_eq!(content, b"AbC123");
    }

    #[test]
    fn a_generated_password_is_long_and_url_safe() {
        let first = generate_password();
        let second = generate_password();

        assert_eq!(first.len(), 24);
        assert_ne!(
            first, second,
            "two calls must not produce the same password"
        );
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'),
            "the alphabet has to be copy-paste safe: {first}"
        );
    }
}
