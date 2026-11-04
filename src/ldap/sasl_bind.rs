//! SASL bind: the accept half of GSSAPI.
//!
//! An LDAP SASL bind is a conversation, not a request. The client sends a token, the server
//! answers `saslBindInProgress` with a token of its own, and the bind ends either with `success`
//! and an identity or with a failure code. GSSAPI needs three rounds:
//!
//! 1. the client's AP-REQ (a ticket plus an authenticator), answered with an AP-REP;
//! 2. RFC 4752 §3.1: the client's choice of security layer, answered with the server's;
//! 3. an empty final token, which proves the client can process what it was sent.
//!
//! # Why three rounds and not one
//!
//! A ticket proves the client knows a secret; the AP-REP proves **the server** does too, and the
//! key that protects the AP-REP is the session key from the ticket. Skipping the exchange means a
//! client cannot tell a real server from one replaying a captured ticket. The third round exists
//! for the same reason in reverse: the client must show it could unwrap what the server sent.
//!
//! # What this deliberately does not do
//!
//! - **No security layer.** The client selects "none" (the first bit of its layer mask), and this
//!   server refuses anything else rather than pretending: LDAP has its own TLS, and a SASL layer
//!   underneath it would be a second encryption whose failures nobody tests. The login is
//!   therefore only accepted on an encrypted connection, where the ticket cannot be captured in
//!   the first place.
//! - **No channel binding.** `tls-server-end-point` would tie the ticket to the TLS session, and
//!   the library does not do it. This is a recorded limitation, and the reason a plaintext GSSAPI
//!   bind is refused.
//! - **No proxy authorization** from the SASL authzid. The token carries an optional requested
//!   identity, and honouring it without an ACL check named for that operation would be a way to
//!   become somebody else.
use rasn_ldap::{AuthenticationChoice, BindRequest, MessageId, ResultCode};

use super::responses::bind_response;
use super::session::{Identity, Session};
use crate::directory::Directory;
use crate::security::Security;

/// How the client wrapped its token.
///
/// The reply has to be wrapped the same way, or a conforming client will not parse it: a
/// SPNEGO client expects `NegTokenResp`, a GSS-API client expects the AP-REP inside an
/// `[APPLICATION 0]` context token, and a client speaking RFC 4121 framing expects the reply at
/// the top level. Remembering which one arrived is cheaper than guessing on the way back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// A bare AP-REQ: DER `[APPLICATION 14]`.
    Bare,
    /// A GSS-API initial context token: `[APPLICATION 0] { oid, inner }`.
    Gss,
    /// SPNEGO: `NegTokenInit`, possibly inside the same context token.
    Spnego,
    /// RFC 4121 mechanism token: `01 00` and then the AP-REQ.
    MechToken,
}

/// Where a GSSAPI exchange stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The AP-REQ was accepted; the RFC 4752 security-layer token is expected next.
    Layered,
    /// The layer was agreed; the final empty token is expected.
    Final,
}

/// The state a GSSAPI conversation keeps between two binds on one connection.
///
/// Holds the session key from the ticket, which is a secret: hence the hand-written `Debug`
/// below. Without the key the client's next token cannot be unwrapped, and without that token
/// there is nothing proving the client received the AP-REP.
pub struct Exchange {
    session_key: rskrb5::keytab::EncryptionKey,
    principal: String,
    identity: Identity,
    framing: Framing,
    stage: Stage,
}

impl Exchange {
    /// Where this exchange stands.
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// Moves it on.
    pub fn set_stage(&mut self, stage: Stage) {
        self.stage = stage;
    }
}

impl std::fmt::Debug for Exchange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Exchange")
            .field("principal", &self.principal)
            .field("dn", &self.identity.dn)
            .field("framing", &self.framing)
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

/// The mechanisms this server answers to.
///
/// `GSSAPI` is what `ldapsearch -Y GSSAPI` asks for; `GSS-SPNEGO` is the same conversation with a
/// different wrapper, and accepting both costs nothing because the framing is detected anyway.
pub const MECHANISMS: [&str; 2] = ["GSSAPI", "GSS-SPNEGO"];

/// Whether this request is a SASL bind this module handles.
pub fn is_gssapi(request: &BindRequest) -> bool {
    match &request.authentication {
        AuthenticationChoice::Sasl(credentials) => {
            let name = credentials.mechanism.0.to_string();
            MECHANISMS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(&name))
        }
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaslError {
    /// The token is not a Kerberos AP-REQ in any framing this server knows.
    Undecodable(String),
    /// The ticket was not accepted, and the library said why.
    Ticket(String),
    /// The realm has no subtree configured.
    Realm(String),
    /// The security layer the client asked for is not one this server offers.
    Layer(String),
    /// A token arrived out of order.
    Sequence(String),
}

impl std::fmt::Display for SaslError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undecodable(detail) => {
                write!(
                    formatter,
                    "the SASL token is not a Kerberos ticket: {detail}"
                )
            }
            Self::Ticket(detail) => write!(formatter, "the ticket was refused: {detail}"),
            Self::Realm(realm) => write!(
                formatter,
                "the ticket is for realm '{realm}', which has no subtree on this server"
            ),
            Self::Layer(detail) => write!(formatter, "security layer: {detail}"),
            Self::Sequence(detail) => write!(formatter, "SASL bind out of order: {detail}"),
        }
    }
}

/// Handles one round of a GSSAPI bind.
///
/// Returns the response and, once the conversation has succeeded, leaves the identity on the
/// session. Every failure resets the session: RFC 4513 says a failed bind leaves the connection
/// anonymous, and a half-finished exchange must not be resumable into an authenticated state.
pub fn handle_gssapi(
    session: &mut Session,
    directory: &Directory,
    message_id: MessageId,
    request: &BindRequest,
    security: &Security,
) -> rasn_ldap::LdapMessage {
    let Some(gssapi) = security.gssapi.clone() else {
        session.reset();
        return bind_response(
            message_id,
            ResultCode::AuthMethodNotSupported,
            "SASL is not configured on this server: no keytab, so no ticket can be accepted",
        );
    };

    if request.version != 3 {
        session.reset();
        return bind_response(
            message_id,
            ResultCode::ProtocolError,
            &format!("only LDAP version 3 is supported, got {}", request.version),
        );
    }

    let token = match &request.authentication {
        AuthenticationChoice::Sasl(credentials) => credentials
            .credentials
            .as_ref()
            .map(|value| value.as_ref().to_vec())
            .unwrap_or_default(),
        _ => Vec::new(),
    };

    let outcome = match session.sasl_stage() {
        None => begin(session, directory, &gssapi, token, security),
        Some(Stage::Layered) => layers(session, token),
        Some(Stage::Final) => finish(session, token),
    };

    match outcome {
        Ok(Round {
            code,
            credentials,
            identity,
            diagnostic,
        }) => {
            if let Some(identity) = identity {
                session.set_identity(identity);
                session.clear_sasl();
            }
            sasl_response(message_id, code, &diagnostic, credentials)
        }
        Err(err) => {
            // A failed round is a failed bind: the connection goes back to anonymous and the
            // conversation is dropped, so a captured token cannot be replayed into a second try.
            session.reset();
            bind_response(message_id, ResultCode::InvalidCredentials, &err.to_string())
        }
    }
}

/// One round's result.
struct Round {
    code: ResultCode,
    credentials: Option<Vec<u8>>,
    identity: Option<Identity>,
    diagnostic: String,
}

/// The first round: accept the ticket, answer with the server's half.
fn begin(
    session: &mut Session,
    directory: &Directory,
    gssapi: &crate::sasl::Gssapi,
    token: Vec<u8>,
    security: &Security,
) -> Result<Round, SaslError> {
    if token.is_empty() {
        return Err(SaslError::Sequence(
            "the first token of a GSSAPI bind must carry the ticket".to_string(),
        ));
    }

    // A ticket accepted over a plaintext connection can be replayed by anyone who watched it
    // go by: without channel binding the server cannot tell the original from the copy. Refused
    // here, before the ticket is even decrypted, so the answer says nothing about the ticket.
    if !session.is_encrypted() && !security.allow_unencrypted_bind {
        return Err(SaslError::Layer(
            "a Kerberos ticket is accepted only over TLS or StartTLS on this server: without \
             channel binding a captured ticket can be replayed, and the rule is stated here \
             rather than discovered later"
                .to_string(),
        ));
    }

    let (ap_req, framing) = unwrap(token)?;

    let mut validator = rskrb5::service::ServiceValidator::new(gssapi.keytab())
        .with_shared_replay_cache(gssapi.replay());

    if let Some(parts) = gssapi.service_principal() {
        let components: Vec<&str> = parts.iter().map(String::as_str).collect();
        validator = validator.with_keytab_principal(components);
    }

    let validated = validator
        .validate_ap_req(&ap_req)
        .map_err(|err| SaslError::Ticket(err.to_string()))?;

    let mapped = gssapi
        .identity(&validated.client, directory.base_dn())
        .ok_or_else(|| SaslError::Realm(validated.client.realm.clone()))?;

    // The entry decides whether this principal is an administrator: the flag lives on the entry,
    // and a ticket says who the client is, not what it may do.
    let admin = directory
        .find(&mapped.dn)
        .map(|entry| entry.is_admin())
        .unwrap_or(false);
    let identity = Identity::new(&mapped.dn, admin);

    // The AP-REP is what proves the server holds the service key. Built with an explicit
    // confounder because the library asks for one rather than drawing its own.
    let mut confounder = vec![0u8; 16];
    getrandom::fill(&mut confounder)
        .map_err(|err| SaslError::Ticket(format!("no randomness for the AP-REP: {err}")))?;

    let ap_rep = validated
        .build_ap_rep_with_confounder(
            &confounder,
            rskrb5::service::ApRepOptions {
                subkey: None,
                sequence_number: None,
                kvno: None,
            },
        )
        .map_err(|err| SaslError::Ticket(err.to_string()))?;

    session.set_sasl(Exchange {
        session_key: validated.session_key.clone(),
        principal: mapped.principal.clone(),
        identity,
        framing,
        stage: Stage::Layered,
    });

    Ok(Round {
        code: ResultCode::SaslBindInProgress,
        credentials: Some(wrap_reply(&ap_rep, framing, true)?),
        identity: None,
        diagnostic: String::new(),
    })
}

/// The second round: agree the security layer, and refuse anything but "none".
fn layers(session: &mut Session, token: Vec<u8>) -> Result<Round, SaslError> {
    let exchange = session
        .sasl_exchange()
        .ok_or_else(|| SaslError::Sequence("no GSSAPI exchange in progress".to_string()))?;

    let allowed = if exchange.session_key.etype == 0 {
        Vec::new()
    } else {
        unwrap_signed(&token, &exchange.session_key)?
    };

    // RFC 4752 §3.1: four octets of layer mask, three octets of maximum buffer, then the
    // authorization identity the client would like to act as.
    if allowed.len() < 4 {
        return Err(SaslError::Layer(format!(
            "the security layer token is {} bytes, at least four are needed for the layer mask",
            allowed.len()
        )));
    }

    let mask = u32::from_be_bytes([allowed[0], allowed[1], allowed[2], allowed[3]]);

    // Bit 0 is "no security layer", bit 1 integrity, bit 2 confidentiality. Only 0 is offered.
    const NO_LAYER: u32 = 1;
    if mask & NO_LAYER == 0 {
        return Err(SaslError::Layer(
            "this server does not implement a SASL security layer: it offers only \"none\", and \
             TLS is where the encryption belongs. The client's mask did not include it"
                .to_string(),
        ));
    }

    // The requested authorization identity is deliberately not honoured: acting as somebody else
    // needs an ACL rule for exactly that, and a token field is not one.
    if allowed.len() > 7 {
        let authzid = String::from_utf8_lossy(&allowed[7..]).trim().to_string();
        if !authzid.is_empty() {
            return Err(SaslError::Layer(
                "requested proxy authorization is not supported: bind as the principal itself, or \
                 use the proxy authorization control, which the access rules can refuse"
                    .to_string(),
            ));
        }
    }

    session.set_sasl_stage(Stage::Final);

    // The server's answer: the selected layer, and a buffer size that means nothing when no
    // layer was selected - zero, rather than a number a client might act on.
    let mut reply = Vec::with_capacity(4);
    reply.extend_from_slice(&NO_LAYER.to_be_bytes());

    Ok(Round {
        code: ResultCode::SaslBindInProgress,
        credentials: Some(reply),
        identity: None,
        diagnostic: String::new(),
    })
}

/// The third round: the client proves it unwrapped what was sent, and the bind succeeds.
fn finish(session: &mut Session, token: Vec<u8>) -> Result<Round, SaslError> {
    let exchange = session
        .sasl_exchange()
        .ok_or_else(|| SaslError::Sequence("no GSSAPI exchange in progress".to_string()))?;

    if !token.is_empty() {
        return Err(SaslError::Sequence(format!(
            "the last token of a GSSAPI bind must be empty, got {} bytes",
            token.len()
        )));
    }

    Ok(Round {
        code: ResultCode::Success,
        credentials: None,
        identity: Some(exchange.identity.clone()),
        diagnostic: String::new(),
    })
}

/// Strips the framing and returns the AP-REQ and how it arrived.
pub fn unwrap(token: Vec<u8>) -> Result<(Vec<u8>, Framing), SaslError> {
    let bad = |detail: String| SaslError::Undecodable(detail);

    // SPNEGO first: its decoder also accepts the GSS-API context wrapper, and rejects a bare
    // AP-REQ - which is exactly the discrimination needed here.
    if let Ok(spnego) = rskrb5::spnego::SpnegoToken::decode(&token)
        && let Ok(ap_req) = spnego.krb5_ap_req()
    {
        return Ok((ap_req, Framing::Spnego));
    }

    // RFC 4121 mechanism token: two octets of TOK_ID, then the message.
    if token.len() > 2 && token[0] == 0x01 && token[1] == 0x00 {
        return Ok((token[2..].to_vec(), Framing::MechToken));
    }

    // A GSS-API initial context token that is not SPNEGO: [APPLICATION 0] { oid, inner }.
    if token.first() == Some(&0x60) {
        let inner = context_token_inner(&token).map_err(bad)?;
        return match inner.first() {
            // Older GSS-API framing puts the bare AP-REQ inside.
            Some(0x6e) => Ok((inner, Framing::Gss)),
            // RFC 4121 framing puts a mechanism token inside.
            Some(0x01) if inner.get(1) == Some(&0x00) => Ok((inner[2..].to_vec(), Framing::Gss)),
            other => Err(bad(format!(
                "the GSS-API context token carries {other:02x?} where a ticket was expected"
            ))),
        };
    }

    // A bare AP-REQ: DER [APPLICATION 14].
    if token.first() == Some(&0x6e) {
        return Ok((token, Framing::Bare));
    }

    Err(bad(format!(
        "the token starts with {:02x?}, which is not a Kerberos ticket in any framing this \
         server knows",
        token.first()
    )))
}

/// The contents of a GSS-API `[APPLICATION 0]` context token, past the mechanism OID.
fn context_token_inner(token: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = Der::new(token);
    let outer = reader.next().map_err(|err| err.to_string())?;
    if outer.tag != 0x60 {
        return Err(format!("expected [APPLICATION 0], found {:02x}", outer.tag));
    }

    let mut inner = Der::new(outer.value);
    let oid = inner.next().map_err(|err| err.to_string())?;
    if oid.tag != 0x06 {
        return Err(format!("expected an OID, found {:02x}", oid.tag));
    }

    Ok(inner.remaining().to_vec())
}

/// Wraps the server's reply the way the client's token arrived.
fn wrap_reply(payload: &[u8], framing: Framing, initial: bool) -> Result<Vec<u8>, SaslError> {
    let bad = |err: rskrb5::spnego::Error| SaslError::Undecodable(err.to_string());

    match framing {
        Framing::Bare => Ok(payload.to_vec()),
        Framing::MechToken => {
            let mut out = vec![0x02, 0x00];
            out.extend_from_slice(payload);
            Ok(out)
        }
        Framing::Gss => {
            let token = rskrb5::spnego::Krb5MechToken::ap_rep(payload.to_vec());
            Ok(context_token_wrap(&token.encode().map_err(bad)?))
        }
        Framing::Spnego => {
            let krb5 = rskrb5::spnego::Krb5MechToken::ap_rep(payload.to_vec());
            let resp = if initial {
                rskrb5::spnego::NegTokenResp::accept_completed()
                    .with_response_token(krb5.encode().map_err(bad)?)
            } else {
                rskrb5::spnego::NegTokenResp::accept_completed()
            };
            resp.encode().map_err(bad)
        }
    }
}

/// Wraps bytes in a GSS-API `[APPLICATION 0] { Kerberos OID, inner }` context token.
fn context_token_wrap(inner: &[u8]) -> Vec<u8> {
    // 1.2.840.113554.1.2.2, the Kerberos V5 mechanism, DER-encoded.
    const KRB5_OID: [u8; 11] = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
    ];

    let mut content = Vec::with_capacity(KRB5_OID.len() + inner.len());
    content.extend_from_slice(&KRB5_OID);
    content.extend_from_slice(inner);

    let mut out = vec![0x60];
    out.extend(der_length(content.len()));
    out.extend_from_slice(&content);
    out
}

/// A DER length, in the short form when it fits.
fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }

    let bytes = length.to_be_bytes();
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[start..];

    let mut out = vec![0x80 | significant.len() as u8];
    out.extend_from_slice(significant);
    out
}

/// The minimum DER reader this module needs: one TLV at a time.
struct Der<'a> {
    bytes: &'a [u8],
    offset: usize,
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn next(&mut self) -> Result<Tlv<'a>, &'static str> {
        if self.offset + 2 > self.bytes.len() {
            return Err("truncated DER header");
        }

        let tag = self.bytes[self.offset];
        let first = self.bytes[self.offset + 1];
        let mut cursor = self.offset + 2;

        let length = if first & 0x80 == 0 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 || cursor + count > self.bytes.len() {
                return Err("unsupported DER length");
            }
            let mut value = 0usize;
            for byte in &self.bytes[cursor..cursor + count] {
                value = (value << 8) | *byte as usize;
            }
            cursor += count;
            value
        };

        if cursor + length > self.bytes.len() {
            return Err("truncated DER value");
        }

        let value = &self.bytes[cursor..cursor + length];
        self.offset = cursor + length;

        Ok(Tlv { tag, value })
    }
}

/// Verifies and returns the payload of a sign-only GSS token from the client.
///
/// RFC 4121 §7.2: an initiator signing with an acceptor's key uses 25, sealing uses 24. The
/// library hands back the payload after the checksum is verified, so a token that was tampered
/// with fails here rather than at the layer check.
fn unwrap_signed(token: &[u8], key: &rskrb5::keytab::EncryptionKey) -> Result<Vec<u8>, SaslError> {
    let bad = |err: rskrb5::spnego::Error| SaslError::Layer(err.to_string());

    // A client may seal the negotiation token as well as sign it; both are legal, so both are
    // tried, and the sealed path is the one that has to decrypt before it can verify.
    if let Ok(wrap) = rskrb5::spnego::WrapToken::decode(token, false) {
        if wrap.is_sealed() {
            return wrap
                .decrypt_payload(key, rskrb5::spnego::GSSAPI_INITIATOR_SEAL_USAGE)
                .map_err(bad);
        }

        if let Some(payload) = wrap.payload.clone() {
            let intact = wrap
                .verify(key, rskrb5::spnego::GSSAPI_INITIATOR_SIGN_USAGE)
                .map_err(bad)?;
            if !intact {
                return Err(SaslError::Layer(
                    "the security layer token did not verify against the session key".to_string(),
                ));
            }
            return Ok(payload);
        }
    }

    if let Ok(mic) = rskrb5::spnego::MicToken::decode(token, false)
        && let Some(payload) = mic.payload.clone()
    {
        let intact = mic
            .verify(key, rskrb5::spnego::GSSAPI_INITIATOR_SIGN_USAGE)
            .map_err(bad)?;
        if !intact {
            return Err(SaslError::Layer(
                "the security layer token did not verify against the session key".to_string(),
            ));
        }
        return Ok(payload);
    }

    Err(SaslError::Layer(
        "the security layer token is neither a signed nor a sealed GSS token".to_string(),
    ))
}

/// A bind response that carries server credentials.
fn sasl_response(
    message_id: MessageId,
    code: ResultCode,
    diagnostic: &str,
    credentials: Option<Vec<u8>>,
) -> rasn_ldap::LdapMessage {
    rasn_ldap::LdapMessage::new(
        message_id,
        rasn_ldap::ProtocolOp::BindResponse(rasn_ldap::BindResponse::new(
            code,
            rasn_ldap::LdapDn::from(""),
            diagnostic.into(),
            None,
            credentials.map(rasn::types::OctetString::from),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal DER AP-REQ: `[APPLICATION 14]` with a two-octet body. Enough to prove the
    /// framing is stripped correctly, and deliberately not a ticket.
    fn ap_req_bytes() -> Vec<u8> {
        vec![0x6e, 0x02, 0xaa, 0xbb]
    }

    fn gss_wrap(inner: &[u8]) -> Vec<u8> {
        context_token_wrap(inner)
    }

    #[test]
    fn a_bare_ap_req_is_recognised() {
        let (ap_req, framing) = unwrap(ap_req_bytes()).expect("a ticket");
        assert_eq!(ap_req, ap_req_bytes());
        assert_eq!(framing, Framing::Bare);
    }

    #[test]
    fn an_rfc4121_mechanism_token_is_stripped_to_its_message() {
        // 01 00 is TOK_ID for AP-REQ in RFC 4121's framing.
        let mut token = vec![0x01, 0x00];
        token.extend_from_slice(&ap_req_bytes());

        let (ap_req, framing) = unwrap(token).expect("a ticket");
        assert_eq!(ap_req, ap_req_bytes());
        assert_eq!(framing, Framing::MechToken);
    }

    #[test]
    fn a_gss_api_context_token_carrying_a_bare_ap_req_is_recognised() {
        // What cyrus-sasl's GSSAPI plugin sends: [APPLICATION 0] { krb5 OID, AP-REQ }.
        let (ap_req, framing) = unwrap(gss_wrap(&ap_req_bytes())).expect("a ticket");
        assert_eq!(ap_req, ap_req_bytes());
        assert_eq!(framing, Framing::Gss);
    }

    #[test]
    fn a_gss_api_context_token_carrying_a_mechanism_token_is_recognised() {
        let mut inner = vec![0x01, 0x00];
        inner.extend_from_slice(&ap_req_bytes());
        let (ap_req, framing) = unwrap(gss_wrap(&inner)).expect("a ticket");
        assert_eq!(ap_req, ap_req_bytes());
        assert_eq!(framing, Framing::Gss);
    }

    #[test]
    fn something_that_is_not_a_ticket_is_refused_with_what_it_started_with() {
        // The bytes come from an unauthenticated client, so the answer must not be a panic and
        // must say what arrived.
        let error = unwrap(vec![0x30, 0x02, 0x01, 0x02]).expect_err("must refuse");
        match error {
            SaslError::Undecodable(detail) => {
                assert!(detail.contains("0x30") || detail.contains("30"), "{detail}")
            }
            other => panic!("expected an undecodable token, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_token_is_refused() {
        assert!(unwrap(Vec::new()).is_err());
    }

    #[test]
    fn a_truncated_context_token_does_not_panic() {
        // A three-octet "context token" whose length says more than it has.
        assert!(unwrap(vec![0x60, 0x7f, 0x00]).is_err());
        // A header that ends mid-length.
        assert!(unwrap(vec![0x60]).is_err());
    }

    #[test]
    fn the_reply_is_wrapped_the_way_the_token_arrived() {
        // A client that spoke SPNEGO expects NegTokenResp; one that spoke bare GSS-API expects
        // the AP-REP inside a context token. Guessing wrong means a client that cannot parse the
        // answer, which looks like a server that hung.
        let ap_rep = vec![0x6f, 0x02, 0x01, 0x02];

        assert_eq!(
            wrap_reply(&ap_rep, Framing::Bare, true).expect("bare"),
            ap_rep
        );

        let mech = wrap_reply(&ap_rep, Framing::MechToken, true).expect("mech");
        assert_eq!(&mech[..2], &[0x02, 0x00], "TOK_ID for AP-REP");
        assert_eq!(&mech[2..], &ap_rep[..]);

        let gss = wrap_reply(&ap_rep, Framing::Gss, true).expect("gss");
        assert_eq!(gss[0], 0x60, "an [APPLICATION 0] context token");

        let spnego = wrap_reply(&ap_rep, Framing::Spnego, true).expect("spnego");
        // NegTokenResp ::= [APPLICATION 1] or [1]; either way the accept-completed state is
        // present, which is what tells a SPNEGO client the conversation is over mechanism-wise.
        assert!(!spnego.is_empty());
    }

    #[test]
    fn a_long_der_length_takes_the_long_form() {
        assert_eq!(der_length(0), vec![0x00]);
        assert_eq!(der_length(127), vec![0x7f]);
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(der_length(70000), vec![0x83, 0x01, 0x11, 0x70]);
    }

    /// A security policy that has an acceptor, so the SASL path is reachable in a test.
    fn security_with_keytab() -> (Security, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.keytab");

        let mut keytab = rskrb5::keytab::Keytab::new();
        keytab
            .add_entry_from_password(
                rskrb5::keytab::Principal::new("EXAMPLE.COM", 1, ["ldap", "host.example.com"]),
                b"secret",
                std::time::SystemTime::now(),
                1,
                18,
            )
            .expect("an entry");
        keytab.save(&path).expect("saved");

        let gssapi = crate::sasl::Gssapi::load(
            &crate::sasl::SaslConfig {
                keytab: Some(path),
                service_principal: None,
                realms: vec![crate::sasl::RealmConfig {
                    name: "EXAMPLE.COM".to_string(),
                    dn: None,
                }],
            },
            "dc=example,dc=com",
        )
        .expect("loaded")
        .expect("some sasl");

        (
            Security::default().with_gssapi(Some(std::sync::Arc::new(gssapi))),
            dir,
        )
    }

    fn gssapi_request(token: Option<Vec<u8>>) -> BindRequest {
        BindRequest::new(
            3,
            rasn_ldap::LdapDn::from(""),
            rasn_ldap::AuthenticationChoice::Sasl(rasn_ldap::SaslCredentials::new(
                rasn_ldap::LdapString::from("GSSAPI"),
                token.map(rasn::types::OctetString::from),
            )),
        )
    }

    fn session() -> Session {
        let mut session = Session::new();
        // A ticket is accepted only on an encrypted connection; the tests that reach the token
        // need that precondition to hold.
        session.set_encrypted(true);
        session
    }

    #[test]
    fn a_bind_with_no_token_is_refused_as_out_of_sequence() {
        let (_security, _dir) = security_with_keytab();
        let mut session = session();

        let response = handle_gssapi(
            &mut session,
            &crate::directory::Directory::from_entries(
                "dc=example,dc=com",
                "users",
                "groups",
                Vec::new(),
            ),
            1,
            &gssapi_request(None),
            &_security,
        );

        let rasn_ldap::ProtocolOp::BindResponse(body) = &response.protocol_op else {
            panic!("expected a bind response");
        };
        assert_eq!(body.result_code, ResultCode::InvalidCredentials);
        assert!(
            body.diagnostic_message.0.contains("must carry the ticket"),
            "{}",
            body.diagnostic_message.0
        );
        assert!(
            session.identity().is_none(),
            "and the session stays anonymous"
        );
        assert!(
            session.sasl_exchange().is_none(),
            "with no exchange left over"
        );
    }

    #[test]
    fn a_token_that_is_not_a_ticket_is_refused_without_panicking() {
        // The bytes come from an unauthenticated client. Reaching the parser with garbage must
        // produce a refusal, not a panic that takes the listener down.
        let (security, _dir) = security_with_keytab();
        let mut session = session();

        let response = handle_gssapi(
            &mut session,
            &crate::directory::Directory::from_entries(
                "dc=example,dc=com",
                "users",
                "groups",
                Vec::new(),
            ),
            1,
            &gssapi_request(Some(vec![0x30, 0x02, 0x01, 0x02])),
            &security,
        );

        let rasn_ldap::ProtocolOp::BindResponse(body) = &response.protocol_op else {
            panic!("expected a bind response");
        };
        assert_eq!(body.result_code, ResultCode::InvalidCredentials);
        assert!(session.identity().is_none());
    }

    #[test]
    fn a_ticket_on_a_plaintext_connection_is_refused_before_it_is_decrypted() {
        // Without channel binding a captured ticket can be replayed by whoever watched it, so the
        // rule is enforced before the ticket is looked at - which also means the answer does not
        // depend on whether the ticket was valid.
        let (security, _dir) = security_with_keytab();
        let mut session = Session::new();
        assert!(!session.is_encrypted());

        let response = handle_gssapi(
            &mut session,
            &crate::directory::Directory::from_entries(
                "dc=example,dc=com",
                "users",
                "groups",
                Vec::new(),
            ),
            1,
            &gssapi_request(Some(ap_req_bytes())),
            &security,
        );

        let rasn_ldap::ProtocolOp::BindResponse(body) = &response.protocol_op else {
            panic!("expected a bind response");
        };
        assert!(
            body.diagnostic_message.0.contains("only over TLS"),
            "{}",
            body.diagnostic_message.0
        );
    }

    #[test]
    fn a_second_round_without_a_first_is_refused() {
        // A client that starts at round two gets a refusal rather than a panic on a missing
        // exchange, and the session does not acquire an identity from nowhere.
        let (security, _dir) = security_with_keytab();
        let mut session = session();
        session.set_sasl_stage(Stage::Layered);

        let response = handle_gssapi(
            &mut session,
            &crate::directory::Directory::from_entries(
                "dc=example,dc=com",
                "users",
                "groups",
                Vec::new(),
            ),
            1,
            &gssapi_request(Some(vec![1, 0, 0, 0])),
            &security,
        );

        let rasn_ldap::ProtocolOp::BindResponse(body) = &response.protocol_op else {
            panic!("expected a bind response");
        };
        assert_eq!(body.result_code, ResultCode::InvalidCredentials);
        assert!(session.identity().is_none());
    }

    #[test]
    fn the_mechanism_names_are_matched_without_regard_to_case() {
        // Clients differ in spelling and some send `GSS-SPNEGO` for the same conversation.
        for name in ["GSSAPI", "gssapi", "GSS-SPNEGO", "gss-spnego"] {
            let request = BindRequest::new(
                3,
                rasn_ldap::LdapString::from(""),
                rasn_ldap::AuthenticationChoice::Sasl(rasn_ldap::SaslCredentials::new(
                    rasn_ldap::LdapString::from(name),
                    None,
                )),
            );
            assert!(is_gssapi(&request), "{name} must be recognised");
        }

        let simple = BindRequest::new(
            3,
            rasn_ldap::LdapString::from(""),
            rasn_ldap::AuthenticationChoice::Simple(rasn::types::OctetString::from(b"x".to_vec())),
        );
        assert!(!is_gssapi(&simple));
    }
}
