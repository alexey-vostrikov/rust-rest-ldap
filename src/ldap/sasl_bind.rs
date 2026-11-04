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
///
/// The rounds follow libsasl's state machine, which is what every real client speaks - not the
/// three rounds RFC 4752 describes read literally. The difference cost a live debugging session:
///
/// 1. the client's AP-REQ, answered with an AP-REP;
/// 2. an **empty** token from the client (its GSS context is complete and it has nothing to say),
///    answered with the server's security-layer mask, wrapped;
/// 3. the client's own wrapped choice, answered with `success`.
///
/// That is four messages and three transitions, and a server that expects the layer token in
/// round two refuses every cyrus-sasl client with "not a signed or sealed GSS token" - which
/// reads like a bug in the token and is a bug in the ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The AP-REP was sent; the client's empty token is expected, and answered with our mask.
    OfferSent,
    /// Our mask was sent; the client's wrapped choice is expected, and ends the exchange.
    ChoiceExpected,
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
    /// The ticket's session key, for the tokens that follow.
    pub fn session_key(&self) -> &rskrb5::keytab::EncryptionKey {
        &self.session_key
    }

    /// The entry this principal maps to, once the exchange completes.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

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

    // A fresh SASL bind starts by making the connection anonymous, per RFC 4513 - but only a
    // fresh one: the rounds of an exchange in progress must not clear what they depend on.
    if session.sasl_stage().is_none() {
        session.reset();
    }

    let outcome = match session.sasl_stage() {
        None => begin(session, directory, &gssapi, token, security),
        Some(Stage::OfferSent) => offer_layer(session, token),
        Some(Stage::ChoiceExpected) => accept_choice(session, token),
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
        .with_shared_replay_cache(gssapi.replay())
        // No PAC validation: this server takes no authorization decision from the PAC - who may
        // do what comes from the entry and the access rules, not from a Windows group list. The
        // ticket's own signature, checked with the service key, is what proves the client.
        // Left on, a KDC that issues a PAC this library cannot parse refuses every good ticket;
        // a live run against MIT's KDC showed exactly that.
        .without_pac_validation();

    if let Some(parts) = gssapi.service_principal() {
        let components: Vec<&str> = parts.iter().map(String::as_str).collect();
        validator = validator.with_keytab_principal(components);
    }

    let validated = validator
        .validate_ap_req(&ap_req)
        .map_err(|err| SaslError::Ticket(err.to_string()))?;

    let identity = resolve_identity(gssapi, directory, &validated.client)?;

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

    // The key the rest of the exchange is protected with. RFC 4121 §3.3.1: when the initiator puts
    // a subkey in its authenticator, **that** is the context key and the ticket's session key is
    // not used again. A server that keeps using the session key produces tokens the client cannot
    // verify - "a token had an invalid MIC" - which looks like a broken checksum and is a wrong
    // key.
    let context_key = validated
        .subkey
        .clone()
        .unwrap_or_else(|| validated.session_key.clone());

    session.set_sasl(Exchange {
        session_key: context_key,
        principal: format!("{}@{}", validated.client.name(), validated.client.realm),
        identity,
        framing,
        stage: Stage::OfferSent,
    });

    Ok(Round {
        code: ResultCode::SaslBindInProgress,
        credentials: Some(wrap_reply(&ap_rep, framing, true)?),
        identity: None,
        diagnostic: String::new(),
    })
}

/// The second round: answer the client's empty token with our security-layer mask.
///
/// libsasl's server, and therefore 389 DS, says it exactly: "GSSAPI server is not expecting data
/// at this stage" and refuses anything but an empty token. The mask is four octets - which layers
/// this server offers, then a three-octet maximum buffer - and it is **wrapped**, because the
/// client unwraps it with the session key before reading it.
fn offer_layer(session: &mut Session, token: Vec<u8>) -> Result<Round, SaslError> {
    if !token.is_empty() {
        return Err(SaslError::Sequence(format!(
            "the token after the ticket must be empty (the client's GSS context is complete), got \
             {} bytes",
            token.len()
        )));
    }

    let session_key = session
        .sasl_exchange()
        .ok_or_else(|| SaslError::Sequence("no GSSAPI exchange in progress".to_string()))?
        .session_key()
        .clone();

    // RFC 4752 §3.1: the four octets are **one** mask byte followed by a **three**-octet maximum
    // buffer size - not a 32-bit number. Sending `00 00 00 01` advertises a mask of zero, i.e. no
    // layers at all, and a client answers "mechanism too weak" because there is nothing it may
    // select. libsasl builds the same four octets as `sasldata[0] |= LAYER_NONE` plus
    // `sasldata[1..3] = maxbufsize`.
    const NO_LAYER: u8 = 1;
    let mask = vec![NO_LAYER, 0, 0, 0];

    let wrapped = wrap_signed(&mask, &session_key)?;
    session.set_sasl_stage(Stage::ChoiceExpected);

    Ok(Round {
        code: ResultCode::SaslBindInProgress,
        credentials: Some(wrapped),
        identity: None,
        diagnostic: String::new(),
    })
}

/// The last round: the client's wrapped choice, and the bind succeeds.
///
/// The token is the client's four-octet selection (plus an optional authorization identity),
/// wrapped with the session key. Verifying the wrap is the point: it proves the client could
/// process what the server sent, which a client that only knows the ticket could not.
fn accept_choice(session: &mut Session, token: Vec<u8>) -> Result<Round, SaslError> {
    let exchange = session
        .sasl_exchange()
        .ok_or_else(|| SaslError::Sequence("no GSSAPI exchange in progress".to_string()))?;
    let session_key = exchange.session_key().clone();
    let identity = exchange.identity().clone();

    let chosen = unwrap_signed(&token, &session_key)?;

    if chosen.len() < 4 {
        return Err(SaslError::Layer(format!(
            "the client's choice is {} bytes, four are needed for the layer mask",
            chosen.len()
        )));
    }

    const NO_LAYER: u8 = 1;
    if chosen[0] & NO_LAYER == 0 {
        return Err(SaslError::Layer(
            "the client selected a security layer and this server offers only \"none\": TLS is \
             where the encryption belongs. A client that insists on a SASL layer needs a server \
             that implements one"
                .to_string(),
        ));
    }

    // Anything after the four octets is the authorization identity the client would like to act
    // as. Not honoured: becoming somebody else is a right an access rule grants, not a field in a
    // token, and the proxy authorization control is where that decision belongs.
    if chosen.len() > 4 {
        let authzid = String::from_utf8_lossy(&chosen[4..]).trim().to_string();
        if !authzid.is_empty() {
            return Err(SaslError::Layer(format!(
                "requested proxy authorization as '{authzid}' is not supported: bind as the \
                 principal itself, or use the proxy authorization control, which the access rules \
                 can refuse"
            )));
        }
    }

    Ok(Round {
        code: ResultCode::Success,
        credentials: None,
        identity: Some(identity),
        diagnostic: String::new(),
    })
}

/// Turns a verified principal into the entry it authenticates as.
///
/// Two namings, in this order, and the order matters:
///
/// 1. **`userPrincipalName`.** In a directory that publishes AD vocabulary the UPN *is* the
///    account name, and it need not follow from the DN: `alice@EXAMPLE.COM` can live at
///    `cn=Alice Smith,ou=staff,...`. A template alone would look for `uid=alice` and find nothing,
///    then refuse a client whose ticket is perfectly good. More than one entry carrying the same
///    UPN is a refusal, not a first-match: two accounts with one name is precisely the case where
///    picking one silently hands over somebody else's record.
/// 2. **The realm template,** for everything that is not AD-shaped - including this server's own
///    `uid={user},ou=users,{base}`.
///
/// Once the entry is known, `userAccountControl` decides whether it may authenticate. That check
/// is the reason the attribute is in the schema at all: Kerberos never sends this server a
/// password, so nothing else would ever notice that the account was disabled.
fn resolve_identity(
    gssapi: &crate::sasl::Gssapi,
    directory: &Directory,
    principal: &rskrb5::service::Principal,
) -> Result<Identity, SaslError> {
    // The realm filter applies to both namings. A realm nobody mapped has no subtree, and a UPN
    // that happens to match is not permission to ignore the realm it came with.
    let by_template = gssapi
        .identity(principal, directory.base_dn())
        .ok_or_else(|| SaslError::Realm(principal.realm.clone()))?;

    let upn = by_template.principal.clone();

    // One pass over the directory, and the entry itself rather than its DN: the account flags are
    // on the entry, and asking the index for it afterwards would be a second lookup that can miss
    // - entries loaded from a backend are not all in the by-DN map, which a test caught here.
    let mut by_upn: Vec<&crate::model::Entry> = Vec::new();
    let mut by_dn: Option<&crate::model::Entry> = None;

    for entry in directory.all() {
        if crate::dn::normalize(entry.dn()) == by_template.dn {
            by_dn = Some(entry);
        }
        if entry
            .attributes()
            .get("userPrincipalName")
            .is_some_and(|attribute| {
                attribute
                    .values
                    .iter()
                    .any(|value| value.eq_ignore_ascii_case(&upn))
            })
        {
            by_upn.push(entry);
        }
    }

    let entry = match by_upn.len() {
        // AD-shaped: the UPN names the account, and its DN need not follow from the principal.
        1 => Some(by_upn[0]),
        // Two accounts with one name is exactly the case where picking one silently hands over
        // somebody else's record.
        many if many > 1 => {
            let dns: Vec<&str> = by_upn.iter().map(|entry| entry.dn()).collect();
            return Err(SaslError::Ticket(format!(
                "'{upn}' is the userPrincipalName of {many} entries ({}), so a ticket naming it \
                 cannot be resolved to one identity",
                dns.join(", ")
            )));
        }
        // Not AD-shaped: the realm template is the naming, as it was before this existed.
        _ => by_dn,
    };

    // The account's own answer about whether it may authenticate. Kerberos never sends this server
    // a password, so nothing else would notice a disabled account.
    if let Some(entry) = entry
        && let Some(flags) = entry
            .attributes()
            .get("userAccountControl")
            .and_then(|attribute| attribute.values.first())
            .and_then(|text| crate::ad_schema::UserAccountControl::parse(text))
        && let Some(reason) = flags.refusal()
    {
        return Err(SaslError::Ticket(reason.to_string()));
    }

    let dn = entry
        .map(|entry| crate::dn::normalize(entry.dn()))
        .unwrap_or_else(|| by_template.dn.clone());
    let admin = entry.map(|entry| entry.is_admin()).unwrap_or(false);

    Ok(Identity::new(&dn, admin))
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
        // `Krb5MechToken::encode` already produces the whole `[APPLICATION 0] { OID, TOK_ID,
        // message }` context token. Wrapping it again - which is what this code did until a live
        // client said "Invalid token was supplied" - puts a second OID inside the first, and a
        // double-wrapped token is exactly as unparseable as it sounds.
        Framing::Gss => rskrb5::spnego::Krb5MechToken::ap_rep(payload.to_vec())
            .encode()
            .map_err(bad),
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
///
/// Used by the tests to build the shapes a client sends, and by nothing else: the server's own
/// replies come from `Krb5MechToken::encode`, which does this itself.
#[cfg(test)]
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
#[cfg(test)]
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
                .verify(key, rskrb5::spnego::GSSAPI_INITIATOR_SEAL_USAGE)
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

/// Signs a payload as the acceptor, the mirror of [`unwrap_signed`].
fn wrap_signed(payload: &[u8], key: &rskrb5::keytab::EncryptionKey) -> Result<Vec<u8>, SaslError> {
    let mut token =
        rskrb5::spnego::WrapToken::new(rskrb5::spnego::GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR, 0);
    token.payload = Some(payload.to_vec());
    // RFC 4121 §7.2: a **Wrap** token is protected with 22 (acceptor) / 24 (initiator); 23 and 25
    // are for **MIC** tokens. Using 23 here produced a token the client could parse and could not
    // verify - "a token had an invalid MIC" - which is the least helpful way for a key usage to be
    // wrong. The crate's own test vectors verify WrapTokens with the SEAL usage, which is the same
    // fact stated in code.
    token
        .set_checksum(key, rskrb5::spnego::GSSAPI_ACCEPTOR_SEAL_USAGE)
        .map_err(|err| SaslError::Layer(err.to_string()))?;
    token
        .encode()
        .map_err(|err| SaslError::Layer(err.to_string()))
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

    /// A token as a client sends it: wrapped and signed by the **initiator**.
    ///
    /// Not `wrap_signed`, which produces an acceptor token - that is what the server sends, and its
    /// flag is what tells a reader which side made it. A test that used the server's wrapper to
    /// stand in for a client would be testing the wrong direction and would never notice.
    fn client_choice(payload: &[u8], key: &rskrb5::keytab::EncryptionKey) -> Vec<u8> {
        rskrb5::spnego::WrapToken::new_initiator(payload, key)
            .expect("an initiator wrap")
            .encode()
            .expect("encoded")
    }

    /// A session holding an exchange at a given stage with a known key.
    ///
    /// Built directly rather than by playing a real ticket through the round: the ticket's
    /// cryptography is the library's to test and a real client's to prove, while what this module
    /// decides is the shape of the exchange - which token is expected when, and what goes back.
    fn exchanging(stage: Stage) -> Session {
        let key = rskrb5::keytab::EncryptionKey {
            etype: 18,
            value: vec![0x11; 32],
        };

        let mut session = Session::new();
        session.set_encrypted(true);
        session.set_sasl(Exchange {
            session_key: key,
            principal: "alice@EXAMPLE.COM".to_string(),
            identity: Identity::new("uid=alice,ou=users,dc=example,dc=com", false),
            framing: Framing::Bare,
            stage,
        });
        session
    }

    fn bind_response_body(response: &rasn_ldap::LdapMessage) -> &rasn_ldap::BindResponse {
        match &response.protocol_op {
            rasn_ldap::ProtocolOp::BindResponse(body) => body,
            other => panic!("expected a bind response, got {other:?}"),
        }
    }

    #[test]
    fn the_layer_offer_is_one_mask_byte_and_three_of_buffer_size() {
        // This is the byte order that cost a live debugging session: sent as a 32-bit integer,
        // `01 00 00 00` becomes `00 00 00 01`, which advertises a mask of zero - no layers at all -
        // and the client answers "mechanism too weak" because there is nothing it may select.
        let (security, _dir) = security_with_keytab();
        let mut session = exchanging(Stage::OfferSent);
        let directory = crate::directory::Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            Vec::new(),
        );

        let response = handle_gssapi(
            &mut session,
            &directory,
            1,
            &gssapi_request(Some(Vec::new())),
            &security,
        );
        let body = bind_response_body(&response);
        assert_eq!(body.result_code, ResultCode::SaslBindInProgress);

        let credentials = body
            .server_sasl_creds
            .as_ref()
            .expect("the offer")
            .as_ref()
            .to_vec();

        let key = session
            .sasl_exchange()
            .expect("still exchanging")
            .session_key()
            .clone();
        // Decoded as an **acceptor** token, which is what it is: the flag says so, and a client
        // checks it. Reading it back as an initiator token would be the wrong side of the exchange.
        let mut token =
            rskrb5::spnego::WrapToken::decode(&credentials, true).expect("an acceptor wrap");
        assert!(
            token
                .verify(&key, rskrb5::spnego::GSSAPI_ACCEPTOR_SEAL_USAGE)
                .expect("verifiable"),
            "the offer is signed with the wrap key usage a client checks, not the MIC one"
        );
        let plain = token.payload.take().expect("with a payload");

        assert_eq!(
            plain,
            vec![0x01, 0x00, 0x00, 0x00],
            "one mask byte (\"no layer\") followed by a three-octet buffer size of zero"
        );
    }

    #[test]
    fn the_offer_moves_the_exchange_to_expecting_a_choice() {
        let (security, _dir) = security_with_keytab();
        let mut session = exchanging(Stage::OfferSent);
        let directory = crate::directory::Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            Vec::new(),
        );

        handle_gssapi(
            &mut session,
            &directory,
            1,
            &gssapi_request(Some(Vec::new())),
            &security,
        );

        assert_eq!(
            session.sasl_stage(),
            Some(Stage::ChoiceExpected),
            "the next token is the client's choice, not another empty one"
        );
    }

    #[test]
    fn a_token_where_the_client_has_nothing_to_say_is_refused() {
        // libsasl's server says it plainly: "GSSAPI server is not expecting data at this stage".
        // A client that sends its layer choice straight after the ticket is following RFC 4752 as
        // written rather than the state machine everybody implements, and telling it so beats
        // trying to parse the token as something else.
        let (security, _dir) = security_with_keytab();
        let mut session = exchanging(Stage::OfferSent);
        let directory = crate::directory::Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            Vec::new(),
        );

        let response = handle_gssapi(
            &mut session,
            &directory,
            1,
            &gssapi_request(Some(vec![0x01, 0, 0, 0])),
            &security,
        );

        let body = bind_response_body(&response);
        assert_eq!(body.result_code, ResultCode::InvalidCredentials);
        assert!(
            body.diagnostic_message.0.contains("must be empty"),
            "{}",
            body.diagnostic_message.0
        );
        assert_eq!(session.sasl_stage(), None, "and the exchange is dropped");
    }

    #[test]
    fn a_choice_of_no_layer_completes_the_bind_with_the_mapped_identity() {
        let (security, _dir) = security_with_keytab();
        let mut session = exchanging(Stage::ChoiceExpected);
        let key = session
            .sasl_exchange()
            .expect("exchanging")
            .session_key()
            .clone();
        let choice = client_choice(&[0x01, 0x00, 0x00, 0x00], &key);

        let directory = crate::directory::Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            Vec::new(),
        );

        let response = handle_gssapi(
            &mut session,
            &directory,
            1,
            &gssapi_request(Some(choice)),
            &security,
        );

        let body = bind_response_body(&response);
        assert_eq!(body.result_code, ResultCode::Success);
        assert_eq!(
            session.identity().map(|identity| identity.dn.as_str()),
            Some("uid=alice,ou=users,dc=example,dc=com"),
            "the entry the realm table mapped the principal to"
        );
        assert_eq!(session.sasl_stage(), None, "the exchange is finished");
    }

    #[test]
    fn a_client_that_insists_on_a_security_layer_is_refused() {
        // Only "no layer" is offered, so only "no layer" may be chosen. Accepting a layer this
        // server does not implement would mean the client encrypts what the server reads as
        // plaintext - a connection that fails on the first search rather than at the bind.
        let (security, _dir) = security_with_keytab();
        let mut session = exchanging(Stage::ChoiceExpected);
        let key = session
            .sasl_exchange()
            .expect("exchanging")
            .session_key()
            .clone();
        // Integrity only: bit 1 set, bit 0 clear.
        let choice = client_choice(&[0x02, 0x00, 0x00, 0x00], &key);

        let directory = crate::directory::Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            Vec::new(),
        );

        let response = handle_gssapi(
            &mut session,
            &directory,
            1,
            &gssapi_request(Some(choice)),
            &security,
        );

        let body = bind_response_body(&response);
        assert_eq!(body.result_code, ResultCode::InvalidCredentials);
        assert!(
            body.diagnostic_message.0.contains("offers only"),
            "{}",
            body.diagnostic_message.0
        );
    }

    #[test]
    fn a_requested_authorization_identity_is_not_honoured() {
        // The token's trailing field asks to act as somebody else. Becoming another identity is a
        // right an access rule grants, not a field a client may set.
        let (security, _dir) = security_with_keytab();
        let mut session = exchanging(Stage::ChoiceExpected);
        let key = session
            .sasl_exchange()
            .expect("exchanging")
            .session_key()
            .clone();
        let mut payload = vec![0x01, 0x00, 0x00, 0x00];
        payload.extend_from_slice(b"uid=admin,ou=users,dc=example,dc=com");
        let choice = client_choice(&payload, &key);

        let directory = crate::directory::Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            Vec::new(),
        );

        let response = handle_gssapi(
            &mut session,
            &directory,
            1,
            &gssapi_request(Some(choice)),
            &security,
        );

        let body = bind_response_body(&response);
        assert_eq!(body.result_code, ResultCode::InvalidCredentials);
        assert!(
            body.diagnostic_message.0.contains("proxy authorization"),
            "{}",
            body.diagnostic_message.0
        );
        assert!(session.identity().is_none(), "and nobody is bound");
    }

    /// A directory holding the given entries, under the usual naming context.
    fn directory_with(entries: Vec<crate::model::Entry>) -> crate::directory::Directory {
        crate::directory::Directory::from_entries("dc=example,dc=com", "users", "groups", entries)
    }

    fn ad_user(cn: &str, upn: &str, flags: Option<&str>) -> crate::model::Entry {
        let mut attributes = crate::model::Attributes::new()
            .push(crate::model::Attribute::new(
                "objectClass",
                vec!["top".to_string(), "person".to_string(), "user".to_string()],
            ))
            .push(crate::model::Attribute::single("cn", cn))
            .push(crate::model::Attribute::single("sn", "Kerberos"))
            .push(crate::model::Attribute::single("userPrincipalName", upn));

        if let Some(flags) = flags {
            attributes =
                attributes.push(crate::model::Attribute::single("userAccountControl", flags));
        }

        crate::model::Entry::new(cn, attributes)
    }

    fn principal(text: &str) -> rskrb5::service::Principal {
        let (name, realm) = text.split_once('@').expect("a realm");
        rskrb5::service::Principal {
            realm: realm.to_string(),
            name_type: 1,
            components: name.split('/').map(str::to_string).collect(),
        }
    }

    /// An acceptor for `EXAMPLE.COM`, without needing a keytab on disk.
    fn acceptor() -> std::sync::Arc<crate::sasl::Gssapi> {
        let (security, _dir) = security_with_keytab();
        security
            .gssapi
            .clone()
            .expect("the test policy has an acceptor")
    }

    #[test]
    fn an_account_is_found_by_its_user_principal_name_not_only_by_the_template() {
        // The case a template cannot serve: the UPN says alice@EXAMPLE.COM, the entry lives at
        // `cn=Alice Smith`, and `uid=alice` does not exist. Without this, a perfectly good ticket
        // is refused because the directory is shaped like AD rather than like this server.
        let directory = directory_with(vec![ad_user(
            "cn=Alice Smith,ou=users,dc=example,dc=com",
            "alice@EXAMPLE.COM",
            Some("512"),
        )]);

        let identity = resolve_identity(&acceptor(), &directory, &principal("alice@EXAMPLE.COM"))
            .expect("resolved");

        assert_eq!(identity.dn, "cn=alice smith,ou=users,dc=example,dc=com");
    }

    #[test]
    fn the_template_is_still_used_when_no_entry_carries_the_upn() {
        // Not every deployment is AD-shaped, and the default naming must keep working.
        let directory = directory_with(vec![]);

        let identity = resolve_identity(&acceptor(), &directory, &principal("alice@EXAMPLE.COM"))
            .expect("resolved");

        assert_eq!(identity.dn, "uid=alice,ou=users,dc=example,dc=com");
    }

    #[test]
    fn a_upn_shared_by_two_entries_is_a_refusal_not_a_first_match() {
        // Two accounts with one name is exactly the case where picking one silently hands over
        // somebody else's record.
        let directory = directory_with(vec![
            ad_user(
                "cn=Alice One,ou=users,dc=example,dc=com",
                "alice@EXAMPLE.COM",
                None,
            ),
            ad_user(
                "cn=Alice Two,ou=users,dc=example,dc=com",
                "alice@EXAMPLE.COM",
                None,
            ),
        ]);

        let error = resolve_identity(&acceptor(), &directory, &principal("alice@EXAMPLE.COM"))
            .expect_err("must refuse");

        let text = error.to_string();
        assert!(text.contains("2 entries"), "{text}");
        assert!(
            text.to_lowercase().contains("cn=alice one"),
            "both entries are named, so an operator can resolve it: {text}"
        );
    }

    #[test]
    fn a_disabled_account_cannot_authenticate_by_ticket() {
        // Kerberos never sends this server a password, so nothing else would ever notice that the
        // account was disabled. This is the reason `userAccountControl` is in the schema.
        let directory = directory_with(vec![ad_user(
            "cn=Alice Smith,ou=users,dc=example,dc=com",
            "alice@EXAMPLE.COM",
            Some("514"),
        )]);

        let error = resolve_identity(&acceptor(), &directory, &principal("alice@EXAMPLE.COM"))
            .expect_err("must refuse");

        assert!(error.to_string().contains("disabled"), "{error}");
    }

    #[test]
    fn a_locked_out_account_cannot_authenticate_by_ticket() {
        let directory = directory_with(vec![ad_user(
            "cn=Alice Smith,ou=users,dc=example,dc=com",
            "alice@EXAMPLE.COM",
            Some("528"),
        )]);

        let error = resolve_identity(&acceptor(), &directory, &principal("alice@EXAMPLE.COM"))
            .expect_err("must refuse");

        assert!(error.to_string().contains("locked"), "{error}");
    }

    #[test]
    fn an_enabled_account_with_bits_this_server_does_not_interpret_is_allowed() {
        // 66048 = NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD. Interpreting an unknown bit as a refusal
        // would lock out exactly the accounts the extension exists to serve.
        let directory = directory_with(vec![ad_user(
            "cn=Alice Smith,ou=users,dc=example,dc=com",
            "alice@EXAMPLE.COM",
            Some("66048"),
        )]);

        assert!(resolve_identity(&acceptor(), &directory, &principal("alice@EXAMPLE.COM")).is_ok());
    }

    #[test]
    fn an_entry_with_no_flag_word_is_not_refused_for_the_lack_of_one() {
        // An ordinary LDAP entry never claimed to have a flag; it is not broken for not having one.
        let directory = directory_with(vec![ad_user(
            "cn=Alice Smith,ou=users,dc=example,dc=com",
            "alice@EXAMPLE.COM",
            None,
        )]);

        assert!(resolve_identity(&acceptor(), &directory, &principal("alice@EXAMPLE.COM")).is_ok());
    }

    #[test]
    fn a_realm_nobody_mapped_is_refused_even_when_a_upn_matches() {
        // The UPN must not become a way around the realm table: a ticket from an unconfigured
        // realm is refused before any entry is looked for.
        let directory = directory_with(vec![ad_user(
            "cn=Alice Smith,ou=users,dc=example,dc=com",
            "alice@EVIL.ORG",
            Some("512"),
        )]);

        let error = resolve_identity(&acceptor(), &directory, &principal("alice@EVIL.ORG"))
            .expect_err("must refuse");

        assert!(error.to_string().contains("EVIL.ORG"), "{error}");
    }

    #[test]
    fn a_second_round_without_a_first_is_refused() {
        // A client that starts at round two gets a refusal rather than a panic on a missing
        // exchange, and the session does not acquire an identity from nowhere.
        let (security, _dir) = security_with_keytab();
        let mut session = session();
        session.set_sasl_stage(Stage::OfferSent);

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
