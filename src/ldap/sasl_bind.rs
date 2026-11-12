//! SASL bind: the accept half of GSSAPI.
//!
//! An LDAP SASL bind is a conversation, not a request. The client sends a token, the server
//! answers `saslBindInProgress` with a token of its own, and the bind ends either with `success`
//! and an identity or with a failure code. Two conversations exist, and which one runs is decided
//! by the mechanism name and by whether the first bind carried anything:
//!
//! **`GSSAPI`, client-first** - what `ldapsearch -Y GSSAPI` speaks, and libsasl's three rounds:
//!
//! 1. the client's AP-REQ (a ticket plus an authenticator), answered with an AP-REP;
//! 2. the client's empty token, answered with the server's security-layer mask;
//! 3. the client's wrapped choice of layer, and the bind succeeds.
//!
//! **`GSS-SPNEGO`, server-first** - what a Samba member speaks (`ads_sasl_bind`), and two rounds
//! fewer of ceremony:
//!
//! 1. a bind naming the mechanism and carrying nothing, answered with a `NegTokenInit` that lists
//!    the mechanisms (see [`super::spnego_offer`]);
//! 2. the client's `NegTokenInit` carrying the AP-REQ, answered with `accept-completed` and the
//!    server's AP-REP;
//! 3. an empty token, which is the bind's last request, answered with `success`.
//!
//! Step 1 is not politeness. Samba never sends a token first, so a server that waits for one
//! refuses every domain member with `Authentication method not supported` before the ticket is
//! even on the wire - and that is the refusal this module used to give.
//!
//! # Why more than one round at all
//!
//! A ticket proves the client knows a secret; the AP-REP proves **the server** does too, and the
//! key that protects the AP-REP is the session key from the ticket. Skipping the exchange means a
//! client cannot tell a real server from one replaying a captured ticket. The rounds after it exist
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
    /// The client's ticket was accepted and `accept-completed` sent.
    ///
    /// The last round of a `GSS-SPNEGO` bind, which is not the libsasl sequence above: there is no
    /// wrapped security-layer mask between the ticket and the end, only an empty token from the
    /// client, because a client that negotiates through `gensec` (Samba's `ads_sasl_bind`) has no
    /// RFC 4752 layer to negotiate at all.
    SpnegoAccepted,
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

    /// Takes what the finished exchange leaves behind: the per-message tokens and the identity.
    ///
    /// Needed because the conversation outlives the bind. After `success` the client wraps every
    /// LDAP message with the key from the ticket, and the same key has to be here, with sequence
    /// numbers that continue from where the negotiation left them.
    pub fn into_parts(
        self,
    ) -> (
        krb5::token::PerMessageTokens<krb5::token::ContextKey>,
        Identity,
    ) {
        (self.tokens, self.identity)
    }
}

/// The SASL security layer of one connection: confidentiality of every message after the bind.
///
/// RFC 4422 §3.2 puts a four-octet big-endian length in front of each SASL buffer; RFC 4752 §3.2
/// makes that buffer a `gss_wrap` output, so what travels is
///
/// ```text
/// 00 00 00 b7 | 05 04 02 ff 00 00 00 1c … | sealed LDAP message …
/// \_________/   \__/ \/ \/ \__/ \__/ \__/
///  length        TOK_ID Sealed  EC   RRC   SND_SEQ
/// ```
///
/// Sequence numbers are this side's own: the peer's SND_SEQ must arrive in order on a connection,
/// and one that repeats is a replayed message, not a retransmission - LDAP over TCP has no
/// retransmissions, and a duplicated wrap is either a bug or an attack.
pub struct Wrap {
    tokens: krb5::token::PerMessageTokens<krb5::token::ContextKey>,
    send: u64,
    /// The peer's next sequence number, once its first message has shown where it starts.
    ///
    /// `None` until then on purpose: RFC 4121 §4.2.1 says the initial SND_SEQ *should* be random to
    /// keep known-plaintext attacks out, and MIT's and Heimdal's acceptors do exactly that. Measured
    /// on the stand: Samba's first sealed message carried 316063208, so a server that insists on 0
    /// refuses every join after a successful bind.
    recv: Option<u64>,
    /// Whether the layer is still waiting for the `success` that announces it.
    ///
    /// The bind response itself is plain LDAP: the client starts wrapping only after it reads that
    /// answer, so a server that sealed its own success would be sealing something the client is
    /// not yet looking at.
    pending: bool,
}

impl Wrap {
    /// A layer that takes effect after the next message this side writes.
    fn pending(tokens: krb5::token::PerMessageTokens<krb5::token::ContextKey>) -> Self {
        Self {
            tokens,
            send: 0,
            recv: None,
            pending: true,
        }
    }

    /// A layer that takes effect immediately, for tests that drive the framing directly.
    #[cfg(test)]
    pub fn active_for_test(tokens: krb5::token::PerMessageTokens<krb5::token::ContextKey>) -> Self {
        Self {
            tokens,
            send: 0,
            recv: None,
            pending: false,
        }
    }

    /// Whether a message written now must be sealed.
    pub fn is_active(&self) -> bool {
        !self.pending
    }

    /// Lets the layer take effect: called once the announcing response has been written.
    pub fn activate(&mut self) {
        self.pending = false;
    }

    /// Seals one LDAP message, with the four-octet length RFC 4422 §3.2 puts in front of it.
    pub fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>, String> {
        let token = self
            .tokens
            .emit_wrap(self.send, message)
            .map_err(|err| format!("the SASL layer could not seal a reply: {err}"))?;
        self.send += 1;
        let mut framed = Vec::with_capacity(4 + token.len());
        framed.extend_from_slice(&(token.len() as u32).to_be_bytes());
        framed.extend_from_slice(&token);
        Ok(framed)
    }

    /// Opens one sealed message: the token's own length prefix has already been stripped.
    pub fn open(&mut self, token: &[u8]) -> Result<Vec<u8>, String> {
        let verified = self
            .tokens
            .unwrap(token)
            .map_err(|err| format!("the client's SASL layer could not be opened: {err}"))?;
        // The first message names the starting point; every one after it must be exactly one more.
        // Accepting a jump would reopen the replay the sequence number exists to close, and
        // accepting the initial value from the client is not a concession: RFC 4121 §4.2.1 lets it
        // start anywhere.
        match self.recv {
            None => self.recv = Some(verified.seq.wrapping_add(1)),
            Some(next) if verified.seq == next => self.recv = Some(next.wrapping_add(1)),
            Some(next) => {
                return Err(format!(
                    "the client's message carries sequence number {} where {} was next: a repeated \
                     or reordered wrap on one connection is not a retransmission",
                    verified.seq, next
                ));
            }
        }
        Ok(verified.message)
    }
}

impl std::fmt::Debug for Wrap {
    /// Hand-written for the same reason [`Exchange`]'s is: the token layer holds the session key.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Wrap")
            .field("send", &self.send)
            .field("recv", &self.recv)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
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

/// The mechanism a Samba client names, and the one that speaks server-first.
///
/// Spelled here, in one place, because it is compared against what arrives in a bind: a second
/// spelling in the branch that offers would be a server that advertises one name and recognises
/// another.
const SPNEGO_MECHANISM: &str = "GSS-SPNEGO";

/// The NTLMSSP OID, DER-encoded: `1.3.6.1.4.1.311.2.2.10`.
///
/// `GSS-SPNEGO` is a container, and which mechanism is inside decides who can answer: a client that
/// put NTLMSSP there is asking for something this server does not offer, and saying "the token is
/// not a Kerberos ticket" sends the operator to look at the ticket instead of at the client's
/// choice. The OID is the only part of a negTokenInit that names the arm without parsing DER.
const NTLMSSP_OID: [u8; 12] = [
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
];

/// Whether a token offers NTLMSSP among its mechanisms.
///
/// A scan, not a parse: the OID appears in the clear in every negTokenInit that offers NTLM, and a
/// full DER walk to learn one fact would be a parser to keep correct for a message this server
/// refuses anyway. A token that offers both Kerberos and NTLM still contains the OID, and is
/// reported as offering NTLM - which is true, and the reason the refusal says what it says.
pub fn offers_ntlmssp(token: &[u8]) -> bool {
    token
        .windows(NTLMSSP_OID.len())
        .any(|window| window == NTLMSSP_OID)
}

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

/// Whether this bind begins an exchange rather than continuing one.
///
/// Three things can be in flight, and each of them means "not fresh": a libsasl exchange (`sasl`), an
/// SPNEGO offer the server has sent, and an NTLM challenge. The last one is easy to forget because it
/// keeps no `Exchange` - there is no ticket - and forgetting it wipes the challenge on the very round
/// that has to check the answer against it. Measured on the AD-join stand: the client's answer was
/// refused as arriving "with no challenge outstanding".
fn starts_fresh(session: &Session) -> bool {
    session.sasl_stage().is_none()
        && !session.spnego_offered()
        && session.ntlm_challenge().is_none()
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
    // The mechanism and the token's first bytes, on every round: a client that fails here names
    // neither, and which mechanism arrived is the first thing to know. `GSS-SPNEGO` can carry either
    // Kerberos or NTLM inside, and the two need different answers.
    if let AuthenticationChoice::Sasl(credentials) = &request.authentication {
        tracing::debug!(
            mechanism = %credentials.mechanism.0,
            token = credentials.credentials.as_ref().map_or(0, |value| value.len()),
            first = credentials.credentials.as_ref().map_or_else(String::new, |value| {
                value.iter().take(8).map(|b| format!("{b:02x}")).collect()
            }),
            "sasl bind"
        );
    }

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

    let (mechanism, token) = match &request.authentication {
        AuthenticationChoice::Sasl(credentials) => (
            credentials.mechanism.0.to_string(),
            credentials
                .credentials
                .as_ref()
                .map(|value| value.as_ref().to_vec())
                .unwrap_or_default(),
        ),
        _ => (String::new(), Vec::new()),
    };

    // A fresh SASL bind starts by making the connection anonymous, per RFC 4513 - but only a
    // fresh one: the rounds of an exchange in progress must not clear what they depend on.
    // An NTLM challenge in flight is a conversation too: it has no `Exchange` because there is no
    // ticket, so without naming it here every round would wipe the challenge it is meant to check -
    // measured, and it looked like the client sending an answer nobody had asked for.
    if starts_fresh(session) {
        session.reset();
    }

    // A bare NTLM message comes before every Kerberos path: it does not start with `0x60`, so the
    // SPNEGO branches would refuse it as undecodable, and the refusal would read as a broken ticket
    // rather than as the mechanism a Windows machine uses before it has one. Measured on the AD-join
    // stand: `Add-Computer` sends exactly this and nothing else.
    #[cfg(feature = "smb")]
    let ntlm = super::ntlm_bind::is_ntlm(&token);
    // A four-octet token after a completed NTLM bind is RFC 4752's layer choice, not an LDAP message:
    // it arrives before any request and would otherwise be refused as a malformed one.
    #[cfg(feature = "smb")]
    let ntlm_layer = token.len() == 4 && session.ntlm_negotiate().is_some();

    // Every LDAP operation a client asks for, by name and number. `Add-Computer` moves through
    // several - a search for the domain, an add of the machine account, a modify of its attributes -
    // and when it stops with `ERROR_CALL_NOT_IMPLEMENTED` the one thing needed is which operation it
    // was on. Silent at `debug` for a bind that arrives every few seconds, and one line per request
    // otherwise.
    // The bind is the one operation this function is called for, so the interesting names are the
    // others: a client that arrives with a search asks for something else entirely.
    tracing::debug!(mechanism = %mechanism, "ldap: bind");
    #[cfg(not(feature = "smb"))]
    let ntlm = false;

    let outcome = if ntlm_layer {
        #[cfg(feature = "smb")]
        {
            super::ntlm_bind::layer_round(session, &token)
        }
        #[cfg(not(feature = "smb"))]
        unreachable!("`ntlm_layer` is a constant false without the smb feature")
    } else if ntlm {
        #[cfg(feature = "smb")]
        {
            super::ntlm_bind::step(session, directory, &token, security)
        }
        #[cfg(not(feature = "smb"))]
        unreachable!("`ntlm` is a constant false without the smb feature")
    } else {
        match session.sasl_stage() {
            Some(Stage::OfferSent) => offer_layer(session, token),
            Some(Stage::ChoiceExpected) => accept_choice(session, token),
            Some(Stage::SpnegoAccepted) => spnego_finish(session, token),
            // No exchange and no offer yet. A `GSS-SPNEGO` bind that carries no token is not a
            // client with nothing to say - it is a client waiting for the server to name the
            // mechanisms, which is what Samba's `ads_sasl_bind` does. See `super::spnego_offer`.
            // An offer that is outstanding is answered by the next bind, unless the client changed
            // mechanism: a bind that is not a continuation of the same conversation starts over, which
            // is RFC 4513's rule and also the only reading under which a client that abandons SPNEGO
            // for plain `GSSAPI` is not sent down the wrong path.
            None if session.spnego_offered() => {
                if mechanism.eq_ignore_ascii_case(SPNEGO_MECHANISM) {
                    spnego_accept(session, directory, &gssapi, token, security)
                } else {
                    session.reset();
                    begin(session, directory, &gssapi, token, security)
                }
            }
            None if token.is_empty() && mechanism.eq_ignore_ascii_case(SPNEGO_MECHANISM) => {
                offer_spnego(session)
            }
            None => begin(session, directory, &gssapi, token, security),
        }
    };

    match outcome {
        Ok(Round {
            code,
            credentials,
            identity,
            diagnostic,
            wrap,
        }) => {
            if let Some(identity) = identity {
                session.set_identity(identity);
                session.clear_sasl();
            }
            // Installed after the identity, because `reset` (inside a successful bind's own path
            // nowhere) would drop it; and it stays "pending" until the response below is written.
            if let Some(wrap) = wrap {
                session.set_wrap(wrap);
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
pub(crate) struct Round {
    pub(crate) code: ResultCode,
    pub(crate) credentials: Option<Vec<u8>>,
    pub(crate) identity: Option<Identity>,
    pub(crate) diagnostic: String,
    /// The security layer this round puts in place, when it is the last one.
    ///
    /// Set only by `spnego_finish`: a client on `gensec` has no RFC 4752 mask to negotiate and
    /// starts sealing the moment it reads `success`, so the server has to be ready with the key and
    /// with sequence number zero on both directions.
    pub(crate) wrap: Option<Wrap>,
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

/// Refuses a ticket over a connection that cannot bind it to anything.
///
/// One rule, one place: the client that sends its ticket first and the client that waits to be
/// offered a mechanism are refused on the same terms, and a second copy of this paragraph would be
/// a second chance for them to differ.
fn require_encrypted(session: &Session, security: &Security) -> Result<(), SaslError> {
    // A ticket accepted over a plaintext connection can be replayed by anyone who watched it
    // go by: without channel binding the server cannot tell the original from the copy. Refused
    // here, before the ticket is even decrypted, so the answer says nothing about the ticket.
    if session.is_encrypted() || security.allow_unencrypted_bind {
        return Ok(());
    }
    Err(SaslError::Layer(
        "a Kerberos ticket is accepted only over TLS or StartTLS on this server: without \
         channel binding a captured ticket can be replayed, and the rule is stated here \
         rather than discovered later"
            .to_string(),
    ))
}

/// The identity a verified ticket authenticates as.
///
/// Shared by both doors a ticket comes through - a client that sends it first, and a client that
/// waits for the mechanism list and then sends it in a `NegTokenInit` - because the policy applied
/// to a ticket must not depend on which of them the client walked through.
fn admitted_identity(
    directory: &Directory,
    gssapi: &crate::sasl::Gssapi,
    context: &krb5::acceptor::KerberosContext,
) -> Result<Identity, SaslError> {
    // Whether the PAC's signature is checked at all is the operator's setting, and the default is
    // "not at all" - see `pac_policy`. `krb5` verifies whatever PAC it finds and keeps it only if it
    // verifies, so a realm that issues none is not an error there; the setting decides what this
    // module then *requires*, which is a different question and the operator's.
    let pac = gssapi.pac();

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

    Ok(identity)
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

    require_encrypted(session, security)?;

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

    // A `GSS-SPNEGO` conversation whose inner mechanism is NTLMSSP is not a Kerberos token that
    // failed to parse - it is a client asking for a mechanism this server does not offer, and the
    // refusal has to say which. See `NTLMSSP_OID`.
    if offers_ntlmssp(&token) {
        return Err(SaslError::Undecodable(
            "the SPNEGO token offers NTLMSSP, which this server does not accept: it accepts \
             Kerberos, so a Samba member joins with `net ads join -k` and a ticket from `kinit`"
                .to_string(),
        ));
    }

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

    let identity = admitted_identity(directory, gssapi, &context)?;

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
        wrap: None,
    })
}

/// A `GSS-SPNEGO` bind that carries no token: the server answers first, with the mechanism list.
///
/// This is the shape of the conversation a domain member speaks (`MS-ADTS`'s SASL, Samba's
/// `ads_sasl_bind`): the client sends the mechanism name and nothing else, the server replies with
/// a `NegTokenInit` naming what it has, and only then does the client send its ticket. A server
/// that expects the ticket in the first message refuses every such client before reading one - and
/// with a message about the authentication method, which is why this looked like a missing
/// implementation rather than a missing first move.
///
/// Refused when this server has no acceptor: there is nothing to offer, and an empty mechanism list
/// would be a client sent to look for another controller.
fn offer_spnego(session: &mut Session) -> Result<Round, SaslError> {
    session.set_spnego_offered(true);

    Ok(Round {
        code: ResultCode::SaslBindInProgress,
        credentials: Some(super::spnego_offer::offer()),
        identity: None,
        diagnostic: String::new(),
        wrap: None,
    })
}

/// The client's answer to that offer: a `NegTokenInit` whose token is the AP-REQ.
///
/// The whole token goes to the same acceptor the client-first path uses: it parses the mechanism
/// list, keeps the Kerberos arm and accepts the ticket carried optimistically in it. What differs
/// is only who spoke first, and the acceptor's answer is a `NegTokenResp` either way.
fn spnego_accept(
    session: &mut Session,
    directory: &Directory,
    gssapi: &crate::sasl::Gssapi,
    token: Vec<u8>,
    security: &Security,
) -> Result<Round, SaslError> {
    if token.is_empty() {
        return Err(SaslError::Sequence(
            "the mechanism list was sent and the client answered with nothing: the next token must \
             carry the ticket"
                .to_string(),
        ));
    }

    require_encrypted(session, security)?;

    if !matches!(token.first(), Some(0x60) | Some(0x6e)) {
        return Err(SaslError::Undecodable(format!(
            "the token starts with {:02x?}, which is not a Kerberos ticket in any framing this \
             server knows",
            token.first()
        )));
    }

    if offers_ntlmssp(&token) {
        return Err(SaslError::Undecodable(
            "the SPNEGO token offers NTLMSSP, which this server does not accept: it accepts \
             Kerberos, so a Samba member joins with `net ads join -k` and a ticket from `kinit`"
                .to_string(),
        ));
    }

    let options = accept_options(security, gssapi);
    let mut acceptor = krb5::spnego::SpnegoAcceptor::with_options(gssapi.keytab(), options);

    let reply = acceptor
        .step(&token)
        .map_err(|err| SaslError::Ticket(err.to_string()))?
        .ok_or_else(|| SaslError::Ticket("the acceptor produced no reply".to_string()))?;

    // The acceptor answers `request-mic` instead of accepting when the client's Kerberos OID is
    // not the first it offered: SPNEGO then requires a mechListMIC round, which this server does
    // not implement. Named rather than passed through, because the answer the acceptor would give
    // (`SaslError::Ticket` about a missing context) reads like a broken ticket, and the ticket is
    // fine - the client's mechanism order is what this server will not take.
    if !acceptor.is_established() {
        return Err(SaslError::Sequence(
            "the client offered a mechanism other than Kerberos before it, and this server answers \
             only the order that needs no mechListMIC round: Samba and MIT both offer Kerberos \
             first when a ticket is available (`kinit`, then `net ads join -k`)"
                .to_string(),
        ));
    }

    let context = acceptor.into_context().ok_or_else(|| {
        SaslError::Ticket("the ticket was accepted without a context".to_string())
    })?;
    let identity = admitted_identity(directory, gssapi, &context)?;

    let tokens = context
        .per_message_tokens()
        .map_err(|err| SaslError::Ticket(err.to_string()))?;

    session.set_spnego_offered(false);
    session.set_sasl(Exchange {
        tokens,
        principal: context.client_principal.clone(),
        identity,
        stage: Stage::SpnegoAccepted,
    });

    Ok(Round {
        code: ResultCode::SaslBindInProgress,
        credentials: Some(reply),
        identity: None,
        diagnostic: String::new(),
        wrap: None,
    })
}

/// The end of a `GSS-SPNEGO` bind: an empty token, and the client is who the ticket said.
///
/// A client that negotiates through `gensec` closes the bind with one more request carrying nothing
/// (`ads_sasl_spnego_gensec_bind` loops until it gets `LDAP_SUCCESS` with no token back), and the
/// answer to that is the success this returns. There is no RFC 4752 round here on purpose: that
/// layer is libsasl's, and a Samba client has no such thing - requiring it is what leaves a join
/// waiting for a message the client will never send.
fn spnego_finish(session: &mut Session, token: Vec<u8>) -> Result<Round, SaslError> {
    if !token.is_empty() {
        return Err(SaslError::Sequence(format!(
            "after accept-completed this server expects an empty token to close the bind, got {} \
             bytes: the SASL security layer is negotiated by the GSSAPI mechanism, not here",
            token.len()
        )));
    }

    // The exchange is taken, not read: the layer that follows the bind needs the same key, and the
    // conversation has nothing left to say. `into_parts` moves it rather than copying, because
    // `PerMessageTokens` is not `Clone` and should not be - two copies of a context would drift
    // apart in their sequence numbers.
    let (tokens, identity) = session
        .take_sasl()
        .ok_or_else(|| SaslError::Sequence("no GSSAPI exchange in progress".to_string()))?
        .into_parts();

    Ok(Round {
        code: ResultCode::Success,
        credentials: None,
        identity: Some(identity),
        diagnostic: String::new(),
        wrap: Some(Wrap::pending(tokens)),
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
        wrap: None,
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
        // The libsasl path negotiates the layer in the mask instead: this server offers "none", so
        // there is nothing to wrap and nothing to keep.
        wrap: None,
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

    /// NTLMSSP's OID spelled out, `1.3.6.1.4.1.311.2.2.10`, and deliberately not `NTLMSSP_OID`.
    ///
    /// A fixture built from the constant it tests moves with it: changing one octet of the constant
    /// used to leave these tests green, because both sides changed together. These bytes come from
    /// the OID's own arithmetic, so a wrong constant now fails instead of agreeing with itself.
    const NTLMSSP_AS_SENT: [u8; 12] = [
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ];

    /// The OID, in the framing a client puts it in: `[APPLICATION 0]` wrapping `[0]` wrapping the
    /// mechanism list. Only the bytes the scan looks for matter here.
    fn spnego_offering(oid: &[u8]) -> Vec<u8> {
        let mut token = vec![0x60, 0x00, 0x06, 0x00, 0x2b, 0x06];
        token.extend_from_slice(oid);
        token
    }

    #[test]
    fn a_spnego_token_offering_ntlmssp_is_refused_by_name() {
        // `net ads join` with a password puts NTLMSSP inside GSS-SPNEGO: Samba's own trace says
        // `Starting GENSEC submechanism ntlmssp`, and the LDAP bind that follows is refused. Which
        // refusal matters to the operator: "this is not a Kerberos ticket" sends them to look at
        // the ticket, while the truth is that the client was never asked for one.
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
            &gssapi_request(Some(spnego_offering(&NTLMSSP_AS_SENT))),
            &security,
        );

        let rasn_ldap::ProtocolOp::BindResponse(body) = &response.protocol_op else {
            panic!("expected a bind response");
        };
        assert_eq!(body.result_code, ResultCode::InvalidCredentials);
        assert!(
            body.diagnostic_message.0.contains("NTLMSSP"),
            "the refusal names the mechanism that arrived: {}",
            body.diagnostic_message.0
        );
        assert!(
            body.diagnostic_message.0.contains("-k"),
            "and says how a Samba member does reach Kerberos: {}",
            body.diagnostic_message.0
        );
        assert!(session.identity().is_none());
    }

    #[test]
    fn a_kerberos_token_is_not_mistaken_for_ntlm() {
        // The scan must not answer yes to a ticket. The Kerberos OID sits in the same position in
        // the same framing, so a substring that matched loosely would refuse every real bind - the
        // kind of defect that only appears against a client that works.
        let kerberos_oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
        assert!(!offers_ntlmssp(&spnego_offering(&kerberos_oid)));
        assert!(offers_ntlmssp(&spnego_offering(&NTLMSSP_AS_SENT)));
        // And a bare AP-REQ, which is what `-Y GSSAPI` sends: no negTokenInit, no OID list.
        assert!(!offers_ntlmssp(&ap_req_bytes()));
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

    fn spnego_request(token: Option<Vec<u8>>) -> BindRequest {
        BindRequest::new(
            3,
            rasn_ldap::LdapString::from(""),
            rasn_ldap::AuthenticationChoice::Sasl(rasn_ldap::SaslCredentials::new(
                rasn_ldap::LdapString::from("GSS-SPNEGO"),
                token.map(rasn::types::OctetString::from),
            )),
        )
    }

    fn empty_directory() -> crate::directory::Directory {
        crate::directory::Directory::from_entries(
            "dc=example,dc=com",
            "users",
            "groups",
            Vec::new(),
        )
    }

    fn credentials_of(response: &rasn_ldap::LdapMessage) -> Vec<u8> {
        bind_response_body(response)
            .server_sasl_creds
            .as_ref()
            .expect("the server sent a token")
            .as_ref()
            .to_vec()
    }

    #[test]
    fn an_empty_spnego_bind_is_answered_with_the_mechanism_list() {
        // Samba's `ads_sasl_bind` sends the mechanism name and nothing else and waits for this
        // answer: a server that expects a ticket here refuses a domain member before it sends one,
        // with a message about the authentication method.
        let (security, _dir) = security_with_keytab();
        let mut session = session();

        let response = handle_gssapi(
            &mut session,
            &empty_directory(),
            1,
            &spnego_request(None),
            &security,
        );

        let body = bind_response_body(&response);
        assert_eq!(body.result_code, ResultCode::SaslBindInProgress);
        assert_eq!(
            credentials_of(&response),
            super::super::spnego_offer::offer(),
            "the reply is the NegTokenInit, byte for byte"
        );
        assert!(
            session.spnego_offered(),
            "the next bind on this connection is the client's answer to it"
        );
        assert!(
            session.sasl_exchange().is_none(),
            "no ticket has arrived, so there is no exchange to keep"
        );
        assert!(session.identity().is_none(), "and still anonymous");
    }

    #[test]
    fn a_second_empty_spnego_bind_is_refused_rather_than_offered_again() {
        // Offering twice would be a loop: a client that did not get the first answer must not be
        // able to make the server talk to itself.
        let (security, _dir) = security_with_keytab();
        let mut session = session();
        let directory = empty_directory();

        handle_gssapi(
            &mut session,
            &directory,
            1,
            &spnego_request(None),
            &security,
        );
        let response = handle_gssapi(
            &mut session,
            &directory,
            2,
            &spnego_request(None),
            &security,
        );

        let body = bind_response_body(&response);
        assert_eq!(body.result_code, ResultCode::InvalidCredentials);
        assert!(
            body.diagnostic_message.0.contains("carry the ticket"),
            "{}",
            body.diagnostic_message.0
        );
        assert!(
            !session.spnego_offered(),
            "a failed bind leaves nothing to resume"
        );
    }

    #[test]
    fn the_end_of_an_spnego_bind_is_an_empty_token_and_the_tickets_identity() {
        // What `ads_sasl_spnego_gensec_bind` does last: one bind carrying nothing, expecting
        // LDAP_SUCCESS and no token back. A server that waits for an RFC 4752 layer choice here
        // waits for a message a Samba client never sends.
        let (security, _dir) = security_with_keytab();
        let mut session = exchanging(Stage::SpnegoAccepted);
        let expected = session
            .sasl_exchange()
            .expect("the fixture holds one")
            .identity()
            .dn
            .clone();

        let response = handle_gssapi(
            &mut session,
            &empty_directory(),
            1,
            &spnego_request(Some(Vec::new())),
            &security,
        );

        let body = bind_response_body(&response);
        assert_eq!(body.result_code, ResultCode::Success);
        assert!(body.server_sasl_creds.is_none(), "success carries no token");
        assert_eq!(
            session.identity().map(|identity| identity.dn.clone()),
            Some(expected),
            "the binding identity is the one the ticket resolved to"
        );
        assert!(
            session.sasl_exchange().is_none(),
            "and the conversation is over"
        );
    }

    #[test]
    fn the_root_dse_publishes_the_mechanisms_a_client_may_bind_with() {
        // Samba's `ads_sasl_bind` searches the root DSE for this attribute and compares each value
        // literally: a server that implements SASL and does not publish it is refused with
        // `Authentication method not supported` before a token is sent. The attribute is built in
        // `search`, and read here because this is where a Security with an acceptor can be had.
        use rasn_ldap::{Filter, ProtocolOp, SearchRequestDerefAliases, SearchRequestScope};

        let (security, _dir) = security_with_keytab();
        let request = rasn_ldap::SearchRequest::new(
            rasn_ldap::LdapDn::from(""),
            SearchRequestScope::BaseObject,
            SearchRequestDerefAliases::NeverDerefAliases,
            0,
            0,
            false,
            Filter::Present(rasn_ldap::AttributeDescription::from(
                "objectClass".to_string(),
            )),
            Vec::new(),
        );

        let values = |security: &Security| -> Vec<String> {
            let messages = crate::ldap::search::handle_search(
                &Session::new(),
                &empty_directory(),
                1,
                &request,
                None,
                security,
            );
            let ProtocolOp::SearchResEntry(entry) = &messages[0].protocol_op else {
                panic!("the root DSE is an entry");
            };
            entry
                .attributes
                .iter()
                .find(|attribute| attribute.r#type.0 == "supportedSASLMechanisms")
                .map(|attribute| {
                    attribute
                        .vals
                        .iter()
                        .map(|value| String::from_utf8_lossy(value).into_owned())
                        .collect()
                })
                .unwrap_or_default()
        };

        assert_eq!(
            values(&security),
            vec!["GSSAPI".to_string(), "GSS-SPNEGO".to_string()],
            "the mechanisms this server answers to, and the spelling Samba compares against"
        );

        // And not on a server that cannot accept a ticket: naming a mechanism every attempt must
        // refuse is the same lie as not naming one that works.
        assert!(
            values(&Security::default()).is_empty(),
            "no acceptor, nothing to advertise"
        );
    }

    #[test]
    fn data_after_accept_completed_is_refused_with_the_reason() {
        let (security, _dir) = security_with_keytab();
        let mut session = exchanging(Stage::SpnegoAccepted);

        let response = handle_gssapi(
            &mut session,
            &empty_directory(),
            1,
            &spnego_request(Some(vec![0x01, 0x00, 0x00, 0x00])),
            &security,
        );

        let body = bind_response_body(&response);
        assert_eq!(body.result_code, ResultCode::InvalidCredentials);
        assert!(
            body.diagnostic_message.0.contains("empty token"),
            "{}",
            body.diagnostic_message.0
        );
        assert!(session.identity().is_none());
    }

    /// A message with no meaning beyond its bytes: the layer moves octets, and which operation they
    /// encode is not what these tests measure.
    fn sample_message(message_id: u32) -> rasn_ldap::LdapMessage {
        crate::ldap::responses::search_done(message_id, ResultCode::Success, "")
    }

    /// The client's half of the layer, standing where Samba's `gensec` stands.
    ///
    /// Same key, `Role::Initiator`: a wrap made here is what the server has to open, and one it
    /// makes is what this verifies. Anything less would test the server against itself.
    fn sealed_by_client(
        tokens: &krb5::token::PerMessageTokens<krb5::token::ContextKey>,
        seq: u64,
        message: &[u8],
    ) -> Vec<u8> {
        let token = tokens.emit_wrap(seq, message).expect("a client wrap");
        let mut framed = (token.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&token);
        framed
    }

    #[tokio::test]
    async fn a_sealed_request_is_opened_and_the_reply_is_sealed_back() {
        // The whole layer in one message each way: four-octet length, RFC 4121 Wrap, LDAP inside.
        // A server that only unseals, or only seals, fails one half of this.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let wrap = Wrap::active_for_test(krb5::token::PerMessageTokens::new(
            test_key(),
            krb5::token::Role::Acceptor,
            false,
        ));
        let client = initiator_tokens();
        let (mut wire, mut loop_side) = tokio::io::duplex(4096);

        // The client's search request, sealed: what Samba sends after `success`.
        let request = crate::ldap::codec::encode(&sample_message(1)).expect("encoded");
        wire.write_all(&sealed_by_client(&client, 0, &request))
            .await
            .expect("written");
        let mut wrap = wrap;
        let read = crate::ldap::codec::read_message_with(&mut loop_side, Some(&mut wrap))
            .await
            .expect("opened");
        assert_eq!(
            read, request,
            "the plaintext is the LDAP message, byte for byte"
        );

        // And the answer travels sealed, in the client's direction.
        let done = crate::ldap::responses::search_done(9, ResultCode::Success, "");
        crate::ldap::codec::write_message_with(&mut loop_side, &done, Some(&mut wrap))
            .await
            .expect("sealed");

        let mut head = [0u8; 4];
        wire.read_exact(&mut head).await.expect("the length");
        let len = u32::from_be_bytes(head) as usize;
        let mut token = vec![0u8; len];
        wire.read_exact(&mut token).await.expect("the token");
        let opened = client.unwrap(&token).expect("the client opens the reply");
        assert_eq!(opened.seq, 0, "the server's own sequence starts at zero");
        assert_eq!(
            opened.message,
            crate::ldap::codec::encode(&done).expect("encoded")
        );
    }

    #[tokio::test]
    async fn a_repeated_sequence_number_is_refused_as_a_replay() {
        // The first message may start anywhere (RFC 4121 §4.2.1: MIT's acceptor picks a random
        // number, and the stand showed 316063208), but the second must be one more. A repeat is a
        // replay: LDAP over TCP never retransmits, so accepting it would execute a captured message
        // twice.
        use tokio::io::AsyncWriteExt;

        let mut wrap = Wrap::active_for_test(krb5::token::PerMessageTokens::new(
            test_key(),
            krb5::token::Role::Acceptor,
            false,
        ));
        let client = initiator_tokens();
        let (mut wire, mut loop_side) = tokio::io::duplex(4096);
        let request = crate::ldap::codec::encode(&sample_message(2)).expect("encoded");

        // An arbitrary starting point, then the same one again.
        for _ in 0..2 {
            wire.write_all(&sealed_by_client(&client, 7, &request))
                .await
                .expect("written");
        }
        crate::ldap::codec::read_message_with(&mut loop_side, Some(&mut wrap))
            .await
            .expect("the first message sets the base");

        let err = crate::ldap::codec::read_message_with(&mut loop_side, Some(&mut wrap))
            .await
            .expect_err("out of order");

        assert!(
            err.to_string().contains("sequence number"),
            "the refusal names the sequence: {err}"
        );
    }

    #[tokio::test]
    async fn the_announcing_response_is_plain_and_the_next_one_is_sealed() {
        // The client starts sealing only after it reads `success`, so a server that sealed its own
        // success would be sending ciphertext to a peer still reading BER. That is the whole reason
        // the layer is installed "pending".
        use tokio::io::AsyncReadExt;

        let mut wrap = Wrap::pending(krb5::token::PerMessageTokens::new(
            test_key(),
            krb5::token::Role::Acceptor,
            false,
        ));
        let (mut wire, mut loop_side) = tokio::io::duplex(4096);
        let done = crate::ldap::responses::search_done(1, ResultCode::Success, "");

        crate::ldap::codec::write_message_with(&mut loop_side, &done, Some(&mut wrap))
            .await
            .expect("written");
        // Read whole, or the rest of this message stays in the buffer and the next read sees it:
        // that is exactly the confusion this test exists to rule out.
        let first = crate::ldap::codec::read_message(&mut wire)
            .await
            .expect("a plain frame");
        assert_eq!(first[0], 0x30, "the first message is plain BER");

        crate::ldap::codec::write_message_with(&mut loop_side, &done, Some(&mut wrap))
            .await
            .expect("written");
        let mut head = [0u8; 4];
        wire.read_exact(&mut head).await.expect("readable");
        let len = u32::from_be_bytes(head) as usize;
        assert!(
            len > 0 && len < 4096,
            "the second message is a SASL buffer, length first"
        );
        let mut token = vec![0u8; len];
        wire.read_exact(&mut token).await.expect("the token");
        assert_eq!(&token[..2], &[0x05, 0x04], "an RFC 4121 Wrap token");
    }

    /// A round that has to check an NTLM answer is not a fresh bind.
    ///
    /// The defect this pins: `starts_fresh` deciding only on the libsasl exchange and the SPNEGO offer
    /// wiped the challenge on the round that answers it, and the client was told its answer arrived
    /// "with no challenge outstanding".
    #[test]
    fn an_ntlm_challenge_in_flight_is_not_a_fresh_bind() {
        let mut session = Session::new();
        assert!(
            super::starts_fresh(&session),
            "an untouched session starts an exchange"
        );

        session.set_ntlm_challenge(Some(([7u8; 8], 1_700_000_000)));
        assert!(
            !super::starts_fresh(&session),
            "the answer to a challenge continues the exchange"
        );

        session.set_ntlm_challenge(None);
        assert!(
            super::starts_fresh(&session),
            "a spent challenge leaves nothing in flight"
        );
    }
}
