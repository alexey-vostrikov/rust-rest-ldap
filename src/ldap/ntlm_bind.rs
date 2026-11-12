//! NTLM inside a `GSS-SPNEGO` bind: the logon a Windows machine makes before it has a ticket.
//!
//! `Add-Computer` authenticates to the directory with an administrator's credentials, and at that
//! moment the domain has issued it no ticket - it is not a member yet. `wldap32` therefore answers
//! `Negotiate` with NTLMSSP, and the token on the wire is a **bare** NTLM message rather than a
//! SPNEGO wrapper: measured on the AD-join stand, the first octets are `4e 54 4c 4d 53 53 50 00`
//! ("NTLMSSP\0"), not `60` (a GSS-API SPNEGO token).
//!
//! Everything that decides whether a password is right lives in `smb_server`, which is where the SMB
//! session checks the same account. That is deliberate: a second implementation of NTLMv2 is a
//! second place to be wrong, and the two would disagree exactly where nobody looks. What this module
//! adds is the SASL framing - which round a message belongs to, and what the directory says about the
//! account.
//!
//! No security layer is negotiated. NTLM over SASL offers none in this server's answer, and the join
//! does not ask for one: it signs and seals nothing after the bind, which is also why a client that
//! insists on `conf`/`integrity` gets a refusal rather than a channel that silently does not exist.

use crate::directory::Directory;
use crate::ldap::sasl_bind::{Round, SaslError};
use crate::ldap::session::Session;
use crate::security::Security;

/// The signature every NTLM message starts with, including the terminating NUL.
pub(crate) const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// The message type field sits here, little-endian: 1 NEGOTIATE, 2 CHALLENGE, 3 AUTHENTICATE.
const TYPE_AT: usize = 8;

/// Whether this token is a bare NTLM message rather than anything Kerberos.
///
/// Checked before the SPNEGO branch, because a bare NTLM message does not start with `0x60` and every
/// Kerberos path would refuse it as undecodable - which reads as a broken ticket rather than as a
/// client asking for a mechanism this server now accepts.
pub(crate) fn is_ntlm(token: &[u8]) -> bool {
    token.len() > TYPE_AT && &token[..8] == SIGNATURE
}

/// The message type of a bare NTLM token, or `None` when the field is not there.
fn message_type(token: &[u8]) -> Option<u32> {
    let raw: [u8; 4] = token.get(TYPE_AT..TYPE_AT + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

/// The target information a challenge carries.
///
/// The names are what a client shows its user and what a workstation remembers about the domain; none
/// of them takes part in verifying the answer, which is computed over the server challenge alone. They
/// come from the realm, because that is the one name this server is configured with, and the machine
/// name is left empty rather than invented.
fn target(security: &Security) -> smb_server::NtlmTargetInfo {
    let realm = security
        .gssapi
        .as_ref()
        .and_then(|gssapi| gssapi.realms().next())
        .unwrap_or("")
        .to_string();
    let netbios = realm
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let dns_domain = realm.to_ascii_lowercase();
    smb_server::NtlmTargetInfo::new(
        netbios.clone(),
        netbios,
        String::new(),
        dns_domain,
        String::new(),
    )
}

/// The current time in FILETIME units, which is what the challenge's `MsvAvTimestamp` is.
///
/// A client compares it against its own clock and refuses an answer that is too old, so reading it
/// from a fixed value would make every logon look replayed.
fn now_filetime() -> u64 {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    // 100-nanosecond intervals since 1601-01-01, the epoch FILETIME counts from.
    since_epoch / 100 + 11_644_473_600_000_000
}

/// Handles one round of a bare-NTLM exchange.
///
/// Two rounds reach here: the client's NEGOTIATE, answered with a challenge, and its AUTHENTICATE,
/// answered with an identity or a refusal. Anything else is a message this server has no place for and
/// is refused by name.
pub(crate) fn step(
    session: &mut Session,
    directory: &Directory,
    token: &[u8],
    security: &Security,
) -> Result<Round, SaslError> {
    match message_type(token) {
        // NEGOTIATE: the client says what it can do, and the server answers with a challenge it will
        // check the answer against. The bytes of this message are not needed afterwards: MIC
        // validation over the negotiate is what a client signs for itself, and the join does not
        // require one.
        Some(1) => {
            let mut challenge = [0u8; 8];
            getrandom::fill(&mut challenge).map_err(|err| {
                SaslError::Sequence(format!("no randomness for the NTLM challenge: {err}"))
            })?;
            session.set_ntlm_challenge(Some(challenge));

            let mut server =
                smb_server::NtlmServer::new(challenge, target(security), now_filetime());
            let answer = server.challenge();
            tracing::debug!(
                round = "negotiate",
                challenge = ?challenge,
                reply = answer.len(),
                "ntlm: challenge sent"
            );
            Ok(Round {
                code: rasn_ldap::ResultCode::SaslBindInProgress,
                credentials: Some(answer),
                identity: None,
                diagnostic: String::new(),
                wrap: None,
            })
        }

        // AUTHENTICATE: the answer to that challenge. The verification is `smb_server`'s, and the
        // account is the directory's.
        Some(3) => {
            let Some(challenge) = session.ntlm_challenge() else {
                return Err(SaslError::Sequence(
                    "an NTLM answer arrived with no challenge outstanding: the exchange was reset, \
                     or this connection never sent one"
                        .to_string(),
                ));
            };

            let server = smb_server::NtlmServer::new(challenge, target(security), now_filetime());
            // The lookup is the directory, and it answers as slowly for an unknown account as for a
            // wrong password because the hash it returns for the former is all zeroes.
            let account = |user: &str, domain: &str| {
                let name = if domain.is_empty() || user.contains('@') {
                    user.to_string()
                } else {
                    format!("{domain}\\{user}")
                };
                // `sAMAccountName` is written without the domain, `userPrincipalName` with it, and a
                // client sends either spelling: both are tried, the bare name last.
                crate::kerberos::secrets::logon_account(directory, &name)
                    .or_else(|| crate::kerberos::secrets::logon_account(directory, user))
                    .map(|(nt_hash, _)| smb_server::UserCreds { nt_hash })
            };

            let outcome = server.authenticate(token, account).map_err(|err| {
                tracing::info!(error = %err, "ntlm: the answer did not verify");
                SaslError::Ticket(err.to_string())
            })?;

            let smb_server::Identity::User { user, .. } = &outcome.identity else {
                return Err(SaslError::Ticket(
                    "an anonymous NTLM logon cannot bind LDAP: a bind has to name an identity"
                        .to_string(),
                ));
            };

            // The entry, not the name the client sent: an ACL names a DN, and the DN is what the
            // directory says the account is. Absent here means the account went away between the two
            // rounds, which is a refusal rather than a session without a subject.
            let Some((_, dn)) = lookup_entry(directory, user.as_str()) else {
                return Err(SaslError::Ticket(format!(
                    "'{user}' authenticated and is no longer in the directory"
                )));
            };
            let entry = directory
                .record(&dn)
                .map(|record| record.into_owned())
                .ok_or_else(|| SaslError::Ticket(format!("'{dn}' could not be read back")))?;
            let identity = crate::ldap::session::Identity::new(&dn, entry.is_admin());

            tracing::info!(dn = %dn, "ntlm: logon accepted");
            session.set_ntlm_challenge(None);
            Ok(Round {
                code: rasn_ldap::ResultCode::Success,
                credentials: None,
                identity: Some(identity),
                diagnostic: String::new(),
                wrap: None,
            })
        }

        Some(other) => Err(SaslError::Sequence(format!(
            "NTLM message type {other} has no place in a bind: this server expects 1 (negotiate) \
             and then 3 (authenticate)"
        ))),
        None => Err(SaslError::Undecodable(
            "the token starts with the NTLM signature and carries no message type".to_string(),
        )),
    }
}

/// The DN of `account`, when the directory knows it and will let it log on.
fn lookup_entry(directory: &Directory, account: &str) -> Option<((), String)> {
    crate::kerberos::secrets::logon_account(directory, account).map(|(_, dn)| ((), dn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, Entry};

    const PASSWORD: &str = "admin-Password-1";
    const ACCOUNT: &str = "admin";
    const DOMAIN: &str = "AD";

    /// A directory holding one enabled account, the way a bootstrap writes it: a hash in
    /// `supplementalCredentials`, which is what both protocols verify against.
    fn directory() -> Directory {
        use base64::Engine as _;
        let nt = rrl_crypto::nt::hash(
            &PASSWORD
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>(),
        )
        .expect("a hash");
        let attributes = crate::model::Attributes::new()
            .push(Attribute::single("sAMAccountName", ACCOUNT))
            .push(Attribute::single("cn", ACCOUNT))
            .push(Attribute::single("objectClass", "user"))
            .push(Attribute::single("userAccountControl", "512"))
            .push(Attribute::single(
                rrl_kdc::hdb::ldap::attrs::AD_SUPPLEMENTAL_CREDENTIALS,
                &base64::engine::general_purpose::STANDARD.encode(
                    rrl_kdc::hdb::ad_blob::supplemental_credentials_with_nt(
                        &rrl_kdc::hdb::HdbEntry::user(
                            rrl_kdc::name::Principal::parse("admin@EXAMPLE.COM").expect("a name"),
                        ),
                        &nt,
                    ),
                ),
            ));
        Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            vec![Entry::new(
                "cn=admin,ou=users,dc=example,dc=com",
                attributes,
            )],
        )
    }

    fn word(value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }

    /// A NEGOTIATE_MESSAGE: the signature, the type, and the flags a Windows client actually sends.
    fn negotiate() -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(SIGNATURE);
        message.extend_from_slice(&word(1));
        message.extend_from_slice(&word(0x0008_8207)); // Unicode, NTLM, always-sign, target-info
        message
    }

    /// The eight octets of server challenge inside a CHALLENGE_MESSAGE, which is what the client
    /// computes its answer over.
    fn challenge_of(reply: &[u8]) -> [u8; 8] {
        assert_eq!(&reply[..8], SIGNATURE, "the reply is an NTLM message");
        assert_eq!(word(2).to_vec(), reply[8..12], "message type 2");
        reply[24..32].try_into().expect("eight octets")
    }

    /// An AUTHENTICATE_MESSAGE carrying a correctly computed NTLMv2 answer.
    ///
    /// Built from MS-NLMP 2.2.1.3 and 3.3.2: the proof is
    /// `HMAC-MD5(NTOWFv2, server_challenge || blob)`, and the blob carries the client's own
    /// challenge and an empty target-info list. No MIC and no session key: a bind does not need
    /// either, and a test that supplied them would test a path nothing takes.
    fn authenticate(challenge: &[u8; 8], password: &str, user: &str) -> Vec<u8> {
        use hmac::{Hmac, KeyInit, Mac};
        type HmacMd5 = Hmac<md5::Md5>;

        let nt = rrl_crypto::nt::hash(
            &password
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>(),
        )
        .expect("a hash");
        let mut key = HmacMd5::new_from_slice(&nt).expect("a key");
        // NTOWFv2: over the upper-cased user name and the domain, UTF-16LE, with no separator.
        for part in [user.to_uppercase(), DOMAIN.to_string()] {
            key.update(
                &part
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<u8>>(),
            );
        }
        let response_key = key.finalize().into_bytes();

        let mut blob = Vec::new();
        blob.extend_from_slice(&[1, 1]); // responserversion, hi-responserversion
        blob.extend_from_slice(&[0u8; 6]); // reserved
        blob.extend_from_slice(&0x01d0_0000_0000_0000u64.to_le_bytes()); // a fixed client time
        blob.extend_from_slice(&[0xaa; 8]); // client challenge
        blob.extend_from_slice(&[0u8; 4]); // reserved
        blob.extend_from_slice(&[0u8; 4]); // target info: empty, and its terminator
        blob.extend_from_slice(&[0u8; 4]);

        let mut mac = HmacMd5::new_from_slice(&response_key).expect("a key");
        mac.update(challenge);
        mac.update(&blob);
        let proof = mac.finalize().into_bytes();

        let mut response = Vec::new();
        response.extend_from_slice(&proof);
        response.extend_from_slice(&blob);

        let mut message = Vec::new();
        message.extend_from_slice(SIGNATURE);
        message.extend_from_slice(&word(3));
        let utf16 =
            |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let user_bytes = utf16(user);
        let domain_bytes = utf16(DOMAIN);
        // Where the payload starts: 8 signature + 4 type + 6 descriptors of 8 + 4 flags + 8 version.
        // Getting this wrong is what "field slice out of range" means, and it is the one number in
        // this message that is easy to be off by a constant about.
        let base = 8 + 4 + 6 * 8 + 4 + 8;
        let fields = [
            (0usize, 0usize), // LM response: empty
            (response.len(), base),
            (domain_bytes.len(), base + response.len()),
            (user_bytes.len(), base + response.len() + domain_bytes.len()),
            (0usize, 0usize), // workstation: empty
            (0usize, 0usize), // session key: empty
        ];
        for (length, offset) in fields {
            message.extend_from_slice(&(length as u16).to_le_bytes());
            message.extend_from_slice(&(length as u16).to_le_bytes());
            message.extend_from_slice(&(offset as u32).to_le_bytes());
        }
        message.extend_from_slice(&word(0x0008_8201)); // negotiated flags
        message.extend_from_slice(&[0u8; 8]); // version
        message.extend_from_slice(&response);
        message.extend_from_slice(&domain_bytes);
        message.extend_from_slice(&user_bytes);
        message
    }

    fn security() -> Security {
        Security::default()
    }

    /// The two rounds `Add-Computer` makes, end to end: a challenge, then an answer that verifies.
    #[test]
    fn a_correct_answer_proves_the_account_and_names_its_entry() {
        let directory = directory();
        let mut session = Session::new();

        let round = step(&mut session, &directory, &negotiate(), &security()).expect("a challenge");
        assert_eq!(round.code, rasn_ldap::ResultCode::SaslBindInProgress);
        let reply = round.credentials.expect("a challenge message");
        let challenge = challenge_of(&reply);

        let round = step(
            &mut session,
            &directory,
            &authenticate(&challenge, PASSWORD, ACCOUNT),
            &security(),
        )
        .expect("the answer verifies");
        assert_eq!(round.code, rasn_ldap::ResultCode::Success);
        let identity = round.identity.expect("an identity");
        assert_eq!(
            identity.dn, "cn=admin,ou=users,dc=example,dc=com",
            "the identity is the entry, not the name the client typed"
        );
        assert!(session.ntlm_challenge().is_none(), "the challenge is spent");
    }

    /// A wrong password is a refusal, and it is the same refusal an absent account gets.
    #[test]
    fn a_wrong_password_does_not_verify() {
        let directory = directory();
        let mut session = Session::new();
        let round = step(&mut session, &directory, &negotiate(), &security()).expect("a challenge");
        let challenge = challenge_of(&round.credentials.expect("a challenge message"));

        let result = step(
            &mut session,
            &directory,
            &authenticate(&challenge, "not the password", ACCOUNT),
            &security(),
        );
        assert!(result.is_err(), "a wrong password must not verify");
    }

    /// An answer with no challenge outstanding is refused rather than checked against zeroes - a
    /// zero challenge is one an attacker can replay a captured answer against.
    #[test]
    fn an_answer_without_a_challenge_is_refused() {
        let directory = directory();
        let mut session = Session::new();
        let result = step(
            &mut session,
            &directory,
            &authenticate(&[0u8; 8], PASSWORD, ACCOUNT),
            &security(),
        );
        let message = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("an answer with no challenge must not verify"),
        };
        assert!(message.contains("no challenge"), "{message}");
    }

    #[test]
    fn a_message_that_is_not_negotiate_or_authenticate_is_named() {
        let directory = directory();
        let mut session = Session::new();
        let mut challenge_message = Vec::from(*SIGNATURE);
        challenge_message.extend_from_slice(&word(2));

        let result = step(&mut session, &directory, &challenge_message, &security());
        match result {
            Err(error) => assert!(error.to_string().contains("message type 2"), "{error}"),
            Ok(_) => panic!("a CHALLENGE_MESSAGE is not something a client sends here"),
        }
    }

    #[test]
    fn a_bare_ntlm_message_is_recognised_and_a_kerberos_one_is_not() {
        assert!(is_ntlm(&negotiate()));
        assert!(!is_ntlm(&[0x60, 0x1e, 0x06, 0x06]));
        assert!(!is_ntlm(b"NTLM"));
    }
}
