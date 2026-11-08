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
//! - **Channel binding is offered, not required.** The acceptor is given the RFC 5929
//!   `tls-server-end-point` binding computed from the certificate this server presents, so a client
//!   that bound its ticket is refused when the binding does not match. A client that sends none is
//!   accepted, which is MIT's rule and the reason this cannot break a working client - and it is
//!   also why a plaintext GSSAPI bind is still refused: nothing binds a captured ticket to a session
//!   that has no certificate.
//! - **No proxy authorization** from the SASL authzid. The token carries an optional requested
//!   identity, and honouring it without an ACL check named for that operation would be a way to
//!   become somebody else.
use rasn_ldap::{AuthenticationChoice, BindRequest, MessageId, ResultCode};

use super::responses::bind_response;
use super::session::{Identity, Session};
use crate::directory::Directory;
use crate::security::Security;

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
    /// The RFC 4121 per-message layer, keyed on the context key.
    ///
    /// Carries the key rather than exposing it: the rounds that follow the ticket are wrap tokens,
    /// and the only thing anybody needs from that key is to seal and open them.
    tokens: krb5::token::PerMessageTokens<krb5::token::ContextKey>,
    principal: String,
    identity: Identity,
    stage: Stage,
}

impl Exchange {
    /// The per-message layer for the tokens that follow.
    pub fn tokens(&self) -> &krb5::token::PerMessageTokens<krb5::token::ContextKey> {
        &self.tokens
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

/// The acceptor's options, as one function rather than three statements in `begin`.
///
/// Split out for one reason: what the server *passes* to the acceptor cannot be observed from a test
/// that drives the acceptor directly, and a mutation that replaced the channel binding with `None`
/// left every test green while quietly removing the protection. A function with a return value is
/// something a test can read.
///
/// `AcceptOptions` is `#[non_exhaustive]`, so it is built from `default()` and then adjusted - which
/// is how the crate documents it, so a field added in a later version does not break this call.
fn accept_options(
    security: &Security,
    gssapi: &crate::sasl::Gssapi,
) -> krb5::acceptor::AcceptOptions {
    let mut options = krb5::acceptor::AcceptOptions::default();
    // One cache for the whole process: a captured AP-REQ replayed on a *new* connection has to be
    // refused, and a per-connection cache would refuse nothing.
    options.replay_cache = Some(gssapi.replay());
    // RFC 5929 `tls-server-end-point`, when this server has a certificate to compute it from.
    //
    // What it buys, in krb5's own terms: a client that bound its ticket to a TLS session must have
    // bound it to *this* one, or the ticket is refused. A client that sent no binding is accepted
    // as before - which is why turning this on cannot break a client that was working, and why a
    // ticket captured off a plaintext connection is still only stopped by the TLS rule above.
    options.channel_bindings = security.channel_binding.clone();
    options
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

    // The whole token goes to the acceptor, which tells GSS-framed from bare by what it finds and
    // answers in the same framing. This crate no longer decodes SPNEGO, the GSS-API context token or
    // the RFC 4121 token id itself: `krb5` does, and its SPNEGO acceptor is tested against MIT's own
    // initiator, which is the only thing that makes a framing claim worth anything.
    //
    // A token that opens with neither framing is refused before the acceptor parses it: its own
    // complaint would be about DER, while the client's mistake is about what it sent.
    if !matches!(token.first(), Some(0x60) | Some(0x6e)) {
        return Err(SaslError::Undecodable(format!(
            "the token starts with {:02x?}, which is not a Kerberos ticket in any framing this \
             server knows",
            token.first()
        )));
    }

    // Whether the PAC's signature is checked at all is the operator's setting, and the default is
    // "not at all" - see `pac_policy`. `krb5` verifies whatever PAC it finds and keeps it only if it
    // verifies, so a realm that issues none is not an error there; the setting decides what this
    // module then *requires*, which is a different question and the operator's.
    let pac = gssapi.pac();

    // One cache for the whole process: a captured AP-REQ replayed on a *new* connection has to be
    // refused, and a per-connection cache would refuse nothing.
    let options = accept_options(security, gssapi);
    let mut acceptor = krb5::spnego::SpnegoAcceptor::with_options(gssapi.keytab(), options);

    let reply = acceptor
        .step(&token)
        .map_err(|err| SaslError::Ticket(err.to_string()))?
        .ok_or_else(|| SaslError::Ticket("the acceptor produced no reply".to_string()))?;

    let context = acceptor.into_context().ok_or_else(|| {
        SaslError::Ticket("the ticket was accepted without a context".to_string())
    })?;

    // The policy, applied to what the ticket claims. A refusal here is a failed bind with the
    // reason attached: the client's Kerberos credentials are genuine and the ticket is still
    // unusable, which is a different answer from "wrong password" and has to read as one.
    let claim = context.pac.as_ref().and_then(crate::pac_policy::Claim::of);
    let admitted = crate::pac_policy::admit(claim, pac, std::time::SystemTime::now())
        .map_err(|refusal| SaslError::Ticket(refusal.to_string()))?;

    let client = krb5::Principal::parse(&context.client_principal).map_err(|err| {
        SaslError::Ticket(format!("the client principal could not be read: {err}"))
    })?;
    let mut identity = resolve_identity(gssapi, directory, &client)?;

    // The groups the ticket granted, resolved to entries of this directory. Off unless the operator
    // asked for it: it changes what `memberOf` and a `group=` access rule answer for a session, and
    // that is a decision about the directory rather than a side effect of accepting tickets.
    if pac.groups
        && let Some(admitted) = admitted.as_ref()
    {
        let (found, unmatched) = crate::pac_policy::resolve_groups(
            directory
                .all()
                .iter()
                .map(|entry| (entry.dn(), entry.attributes())),
            &admitted.group_sids,
        );
        if !unmatched.is_empty() {
            // Said once per bind, and only when it happened: a SID nobody holds is a group where a
            // search must not match, and silence about it makes a missing import look like a
            // working group.
            eprintln!(
                "gssapi: {} group SID(s) from the PAC of {} match no entry here: {}",
                unmatched.len(),
                admitted.login,
                unmatched.join(", ")
            );
        }
        identity = identity.with_groups(found.into_iter().map(|(dn, _)| dn).collect());
    }

    // The context key, from the crate's own RFC 4121 §2 order: the acceptor subkey if one was
    // asserted, else the initiator's subkey, else the ticket's session key. Taking the ticket key
    // where a subkey was offered produces tokens the client cannot verify - "a token had an invalid
    // MIC" - which looks like a broken checksum and is a wrong key.
    let tokens = context
        .per_message_tokens()
        .map_err(|err| SaslError::Ticket(err.to_string()))?;

    session.set_sasl(Exchange {
        tokens,
        principal: context.client_principal.clone(),
        identity,
        stage: Stage::OfferSent,
    });

    Ok(Round {
        code: ResultCode::SaslBindInProgress,
        credentials: Some(reply),
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

    // The borrow ends with the block: `set_sasl_stage` needs the session mutably, and the token
    // layer holds the key rather than being cloneable out of it.
    let wrapped = {
        let exchange = session
            .sasl_exchange()
            .ok_or_else(|| SaslError::Sequence("no GSSAPI exchange in progress".to_string()))?;

        // RFC 4752 §3.1: the four octets are **one** mask byte followed by a **three**-octet
        // maximum buffer size - not a 32-bit number. Sending `00 00 00 01` advertises a mask of
        // zero, i.e. no layers at all, and a client answers "mechanism too weak" because there is
        // nothing it may select. libsasl builds the same four octets as `sasldata[0] |=
        // LAYER_NONE` plus `sasldata[1..3] = maxbufsize`.
        const NO_LAYER: u8 = 1;
        let mask = vec![NO_LAYER, 0, 0, 0];

        wrap_signed(&mask, exchange.tokens())?
    };
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
    let identity = exchange.identity().clone();
    let chosen = unwrap_signed(&token, exchange.tokens())?;

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
    principal: &krb5::Principal,
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

/// Verifies and returns the payload of the client's security-layer token.
///
/// RFC 4752 §3.1: the client's choice comes back protected by the negotiated layer, and
/// `unwrap` hands back the payload only after the MIC over it has been checked - there is no path
/// here that yields bytes it has not verified.
///
/// Both protections are accepted, and that is the whole point of this function. A client that
/// negotiates "no layer" still protects its choice **with integrity**: cyrus-sasl, and therefore
/// every OpenLDAP and Samba client, sends a Wrap token with `Sealed` clear. Reading it with the
/// sealed reader fails with "Wrap token has Sealed=false, but the privacy service was requested",
/// which reads like a defect in the token and was a defect in the reading - it cost a live
/// debugging session against a real `ldapsearch`, and the unit tests missed it because they built
/// the choice with `emit_wrap`, the sealed spelling, and so only ever exercised half the wire.
fn unwrap_signed(
    token: &[u8],
    tokens: &krb5::token::PerMessageTokens<krb5::token::ContextKey>,
) -> Result<Vec<u8>, SaslError> {
    // RFC 4121 §4.2.2: bit 1 of the Flags octet, the third octet of the token header.
    const SEALED: u8 = 0x02;
    let sealed = token.get(2).is_some_and(|flags| flags & SEALED != 0);
    let verified = if sealed {
        tokens.unwrap(token)
    } else {
        tokens.verify_wrap_unsealed(token)
    };
    verified.map(|verified| verified.message).map_err(|err| {
        SaslError::Layer(format!(
            "the client's security-layer choice could not be unwrapped: {err}"
        ))
    })
}

/// Seals a payload for the client, which unwraps it with the context key.
fn wrap_signed(
    payload: &[u8],
    tokens: &krb5::token::PerMessageTokens<krb5::token::ContextKey>,
) -> Result<Vec<u8>, SaslError> {
    // Sequence 0: this is the first and only message this side sends on the context.
    tokens
        .emit_wrap(0, payload)
        .map_err(|err| SaslError::Layer(err.to_string()))
}

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

    /// A minimal DER AP-REQ: `[APPLICATION 14]` with a two-octet body.
    ///
    /// Deliberately not a ticket. The tests that use it stop before the ticket would be decrypted -
    /// at the TLS check, or at the framing check - and a real ticket here would only be a fixture
    /// that expires.
    fn ap_req_bytes() -> Vec<u8> {
        vec![0x6e, 0x02, 0xaa, 0xbb]
    }

    /// What the server hands the acceptor, read back.
    ///
    /// The mutation this holds against: replacing `options.channel_bindings = ...` with `None` used
    /// to leave every test green, because `tests/channel_binding.rs` drives the acceptor directly
    /// and proves the RFC 5929 arithmetic without ever asking whether the server passes a binding
    /// at all. The arithmetic was right and the wiring could have been absent - the protection lives
    /// in the second, and it is the second this reads.
    #[test]
    fn the_acceptor_is_given_the_servers_channel_binding() {
        let (security, _dir) = security_with_keytab();
        let gssapi = security
            .gssapi
            .clone()
            .expect("the fixture has an acceptor");

        // A server with no certificate has no binding to give, and `None` is the honest answer: an
        // invented one is a binding no client computes.
        let bare = accept_options(&security, &gssapi);
        assert!(bare.channel_bindings.is_none());

        // With one, it is the same binding - not a copy that could drift, and not dropped on the way.
        let binding = krb5::ChannelBindings::new(b"tls-server-end-point:the-certificate".to_vec());
        let mut security = security;
        security.channel_binding = Some(binding.clone());
        let options = accept_options(&security, &gssapi);

        assert_eq!(
            options
                .channel_bindings
                .as_ref()
                .map(|b| b.application_data.clone()),
            Some(binding.application_data),
        );
        // The cache as well: a per-connection one would refuse no replay at all, and its absence is
        // as silent as a missing binding.
        assert!(
            options.replay_cache.is_some(),
            "the replay cache is process-wide"
        );
    }

    /// A security policy that has an acceptor, so the SASL path is reachable in a test.
    fn security_with_keytab() -> (Security, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.keytab");

        // A key rather than a password: `krb5` writes keytabs from key material, which is what a
        // `ktadd` produces. Nothing here decrypts with it - the tests below either drive the
        // exchange with a fabricated context key or check that a ticket-less token is refused.
        let mut keytab = krb5::Keytab::new();
        // `ServiceKey` is `#[non_exhaustive]`: a typed value is what the crate asks for, and it
        // keeps a field added upstream from breaking this fixture.
        keytab.add(krb5::ServiceKey::new(
            "ldap/host.example.com",
            "EXAMPLE.COM",
            1,
            krb5::EncType::AES256CtsHmacSha196,
            vec![0x11; 32],
        ));
        keytab.save(&path).expect("saved");

        let gssapi = crate::sasl::Gssapi::load(
            &crate::sasl::SaslConfig {
                pac: crate::pac_policy::PacConfig::default(),
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
    fn client_choice(
        payload: &[u8],
        tokens: &krb5::token::PerMessageTokens<krb5::token::ContextKey>,
    ) -> Vec<u8> {
        tokens.emit_wrap(0, payload).expect("an initiator wrap")
    }

    /// A session holding an exchange at a given stage with a known key.
    ///
    /// Built directly rather than by playing a real ticket through the round: the ticket's
    /// cryptography is the library's to test and a real client's to prove, while what this module
    /// decides is the shape of the exchange - which token is expected when, and what goes back.
    /// AES256-CTS-HMAC-SHA1-96 over a fixed key: the enctype every modern KDC issues by default.
    fn test_key() -> krb5::token::ContextKey {
        krb5::token::ContextKey::new(18, &[0x11; 32]).expect("a key of the right length")
    }

    /// The same key from the client's side, which is what verifies what the server produced.
    fn initiator_tokens() -> krb5::token::PerMessageTokens<krb5::token::ContextKey> {
        krb5::token::PerMessageTokens::new(test_key(), krb5::token::Role::Initiator, false)
    }

    fn exchanging(stage: Stage) -> Session {
        let mut session = Session::new();
        session.set_encrypted(true);
        session.set_sasl(Exchange {
            tokens: krb5::token::PerMessageTokens::new(
                test_key(),
                krb5::token::Role::Acceptor,
                false,
            ),
            principal: "alice@EXAMPLE.COM".to_string(),
            identity: Identity::new("uid=alice,ou=users,dc=example,dc=com", false),
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

        // Opened from the **initiator** side, which is what a client is: the layer picks the seal
        // usage from the side it speaks for, so a token sealed with the wrong usage fails here.
        let opened = initiator_tokens()
            .unwrap(&credentials)
            .expect("the offer opens with the client's key");
        let plain = opened.message;

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
    fn a_choice_protected_with_integrity_only_is_accepted() {
        // What every cyrus-sasl client actually sends: RFC 4752 §3.1 says the choice is protected
        // "in the negotiated layer", and with no confidentiality that is a Wrap token whose
        // `Sealed` bit is clear. Reading it with the sealed reader produced "Wrap token has
        // Sealed=false, but the privacy service was requested" against a live `ldapsearch` — a
        // defect in the reading, not in the token, and invisible to every other test here because
        // they all built the choice with `emit_wrap`.
        let (security, _dir) = security_with_keytab();
        let mut session = exchanging(Stage::ChoiceExpected);
        let choice = initiator_tokens()
            .emit_wrap_unsealed(0, &[0x01, 0x00, 0x00, 0x00], 0)
            .expect("an integrity-only wrap");

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
        assert_eq!(
            body.result_code,
            ResultCode::Success,
            "an integrity-only choice must be read: {}",
            body.diagnostic_message.0
        );
        assert_eq!(session.sasl_stage(), None);
    }

    #[test]
    fn a_choice_with_no_protection_at_all_is_refused() {
        // The other half of the same decision: accepting integrity-only must not become accepting
        // anything. A token whose MIC does not verify is a client that cannot process what the
        // server sent, which is exactly what round three exists to prove.
        let (security, _dir) = security_with_keytab();
        let mut session = exchanging(Stage::ChoiceExpected);
        let mut choice = initiator_tokens()
            .emit_wrap_unsealed(0, &[0x01, 0x00, 0x00, 0x00], 0)
            .expect("an integrity-only wrap");
        // Flip a bit in the checksum, which is the last octets of the token.
        let last = choice.len() - 1;
        choice[last] ^= 0x01;

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
            body.diagnostic_message.0.contains("could not be unwrapped"),
            "{}",
            body.diagnostic_message.0
        );
    }

    #[test]
    fn a_choice_of_no_layer_completes_the_bind_with_the_mapped_identity() {
        let (security, _dir) = security_with_keytab();
        let mut session = exchanging(Stage::ChoiceExpected);
        let choice = client_choice(&[0x01, 0x00, 0x00, 0x00], &initiator_tokens());

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
        // Integrity only: bit 1 set, bit 0 clear.
        let choice = client_choice(&[0x02, 0x00, 0x00, 0x00], &initiator_tokens());

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
        let mut payload = vec![0x01, 0x00, 0x00, 0x00];
        payload.extend_from_slice(b"uid=admin,ou=users,dc=example,dc=com");
        let choice = client_choice(&payload, &initiator_tokens());

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

    fn principal(text: &str) -> krb5::Principal {
        krb5::Principal::parse(text).expect("a well-formed principal")
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
