//! Per-connection state.
//!
//! gorestldap kept the same data in an untyped `interface{}` attached to the
//! client (`SetAddData`/`GetAddData`) and asserted the type on every read. Here
//! the state is a plain struct owned by the connection task.

use crate::acl::Requester;
use crate::dn;

/// Who the connection is bound as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Normalized DN of the bound user entry.
    pub dn: String,
    /// LDAP administrators may act on every entry.
    pub admin: bool,
    /// Group entries this identity holds by its Kerberos ticket rather than by `memberUid`.
    ///
    /// A Windows client's group list arrives in the PAC, not in this directory's group entries:
    /// the client never asked to be a `memberUid` anywhere. Resolving the PAC's SIDs to DNs here
    /// keeps the access rules working unchanged - a rule that names a group asks whether the
    /// session holds that group, and it does not have to care which of the two ways it got it.
    ///
    /// Empty for every bind that is not a ticket with a PAC, which is the ordinary case.
    pub groups: Vec<String>,
}

impl Identity {
    pub fn new(dn: &str, admin: bool) -> Self {
        Self {
            dn: dn::normalize(dn),
            admin,
            groups: Vec::new(),
        }
    }

    /// The same identity, holding these group entries.
    #[must_use]
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.groups = groups;
        self
    }
}

/// Connection state: the identity and whether the transport is encrypted.
#[derive(Debug, Default)]
pub struct Session {
    identity: Option<Identity>,
    encrypted: bool,
    /// A SASL conversation half-way through, if one is.
    ///
    /// It lives on the connection because the protocol puts it there: a GSSAPI bind is several
    /// requests, and the state between them - the ticket session key and what was already agreed -
    /// belongs to the exchange, not to the directory. Dropped by any new bind and by [`Session::reset`],
    /// so a failed attempt cannot be resumed.
    sasl: Option<super::sasl_bind::Exchange>,
    /// Whether the server has sent the first SPNEGO token and is waiting for the client's.
    ///
    /// Outside [`Session::sasl`] because there is nothing to keep there yet: no ticket has been
    /// accepted, so there is no session key, no principal and no identity - an `Exchange` built
    /// before the ticket would be three empty fields pretending to be a conversation. This is the
    /// one fact that has to survive the round, and it is gone the moment the ticket arrives or the
    /// bind fails.
    spnego_offered: bool,
    /// The server challenge this connection is waiting for an NTLM answer to.
    ///
    /// NTLM has no ticket, so the only thing the second round has to agree with the first about is
    /// the challenge: without it the `NTProofStr` cannot be recomputed, and an empty value would
    /// verify anything. Dropped by [`Session::reset`] like the rest of a half-finished bind, so a
    /// client that abandons the exchange cannot resume it.
    ntlm_challenge: Option<[u8; 8]>,
    /// The SASL security layer, once the bind established one.
    ///
    /// Held here rather than in the exchange because it outlives the conversation: every message
    /// after the bind is sealed, and the key that seals them is the one the ticket carried. Dropped
    /// with the identity, which is what [`Session::reset`] does - a connection that loses its
    /// identity must not keep a channel the other side still believes in.
    wrap: Option<super::sasl_bind::Wrap>,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Records whether the transport is encrypted (LDAPS or after StartTLS).
    pub fn set_encrypted(&mut self, encrypted: bool) {
        self.encrypted = encrypted;
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// The session as an ACL subject.
    pub fn requester(&self) -> Requester {
        match &self.identity {
            Some(identity) => Requester {
                dn: Some(identity.dn.clone()),
                admin: identity.admin,
                groups: identity.groups.clone(),
            },
            None => Requester::anonymous(),
        }
    }

    pub fn set_identity(&mut self, identity: Identity) {
        self.identity = Some(identity);
    }

    /// Drops the identity: an anonymous session.
    ///
    /// Also abandons a SASL exchange in progress, because a conversation that was interrupted
    /// must not be pickable up again: the next token would be accepted against a state the
    /// client no longer believes in.
    pub fn reset(&mut self) {
        self.identity = None;
        self.sasl = None;
        self.spnego_offered = false;
        self.ntlm_challenge = None;
        self.wrap = None;
    }

    /// The challenge this connection must see answered, when an NTLM bind is under way.
    pub fn ntlm_challenge(&self) -> Option<[u8; 8]> {
        self.ntlm_challenge
    }

    /// Records the challenge the client was given, or `None` once it has been answered.
    ///
    /// There is no separate stage for this exchange: a challenge that is outstanding *is* the state,
    /// and a second field saying so would be a second thing to keep in step with the first.
    pub fn set_ntlm_challenge(&mut self, challenge: Option<[u8; 8]>) {
        self.ntlm_challenge = challenge;
    }

    /// The SASL exchange in progress, if any.
    pub fn sasl_exchange(&self) -> Option<&super::sasl_bind::Exchange> {
        self.sasl.as_ref()
    }

    /// Where that exchange stands.
    pub fn sasl_stage(&self) -> Option<super::sasl_bind::Stage> {
        self.sasl.as_ref().map(|exchange| exchange.stage())
    }

    /// Records the exchange the next round belongs to.
    pub fn set_sasl(&mut self, exchange: super::sasl_bind::Exchange) {
        self.sasl = Some(exchange);
    }

    /// Moves the exchange to its next stage.
    pub fn set_sasl_stage(&mut self, stage: super::sasl_bind::Stage) {
        if let Some(exchange) = &mut self.sasl {
            exchange.set_stage(stage);
        }
    }

    /// Ends the exchange, keeping the identity it produced.
    pub fn clear_sasl(&mut self) {
        self.sasl = None;
    }

    /// Takes the exchange out of the session: the last round consumes it.
    pub fn take_sasl(&mut self) -> Option<super::sasl_bind::Exchange> {
        self.sasl.take()
    }

    /// The security layer of this connection, for the framing code.
    pub fn wrap(&mut self) -> Option<&mut super::sasl_bind::Wrap> {
        self.wrap.as_mut()
    }

    /// Installs the layer a successful bind established.
    pub fn set_wrap(&mut self, wrap: super::sasl_bind::Wrap) {
        self.wrap = Some(wrap);
    }

    /// Whether the first SPNEGO token was sent and the client's answer is expected.
    pub fn spnego_offered(&self) -> bool {
        self.spnego_offered
    }

    /// Records that it was sent. The next bind is read as the client's answer to it.
    pub fn set_spnego_offered(&mut self, offered: bool) {
        self.spnego_offered = offered;
    }

    pub fn is_admin(&self) -> bool {
        self.identity
            .as_ref()
            .map(|identity| identity.admin)
            .unwrap_or(false)
    }

    /// Admin sees everything; a regular user only their own entry; an anonymous
    /// session (no identity) sees nothing.
    pub fn may_access(&self, entry_dn: &str) -> bool {
        match &self.identity {
            Some(identity) if identity.admin => true,
            Some(identity) => identity.dn == dn::normalize(entry_dn),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_DN: &str = "cn=admin,ou=users,dc=example,dc=com";

    #[test]
    fn new_session_is_anonymous() {
        let session = Session::new();

        assert!(session.identity().is_none());
        assert!(!session.is_admin());
        assert!(!session.may_access(USER_DN));
    }

    #[test]
    fn identity_dn_is_normalized() {
        let identity = Identity::new("CN=Admin, OU=Users, DC=Example, DC=Com", false);

        assert_eq!(identity.dn, USER_DN);
    }

    #[test]
    fn admin_reaches_every_entry() {
        let mut session = Session::new();
        session.set_identity(Identity::new(USER_DN, true));

        assert!(session.is_admin());
        assert!(session.may_access(USER_DN));
        assert!(session.may_access("cn=alice,ou=users,dc=example,dc=com"));
        assert!(session.may_access("dc=example,dc=com"));
    }

    #[test]
    fn regular_user_reaches_only_own_entry() {
        let mut session = Session::new();
        session.set_identity(Identity::new(USER_DN, false));

        assert!(!session.is_admin());
        assert!(session.may_access(USER_DN));
        assert!(session.may_access("CN=Admin, ou=Users, DC=Example, DC=com"));
        assert!(!session.may_access("cn=alice,ou=users,dc=example,dc=com"));
    }

    #[test]
    fn encryption_state_is_tracked_per_session() {
        let mut session = Session::new();
        assert!(!session.is_encrypted());

        session.set_encrypted(true);

        assert!(session.is_encrypted());
    }

    #[test]
    fn requester_carries_the_bound_identity() {
        let mut session = Session::new();
        assert_eq!(session.requester(), Requester::anonymous());

        session.set_identity(Identity::new(USER_DN, true));

        let requester = session.requester();
        assert_eq!(requester.dn.as_deref(), Some(USER_DN));
        assert!(requester.admin);
    }

    #[test]
    fn reset_makes_the_session_anonymous_again() {
        let mut session = Session::new();
        session.set_identity(Identity::new(USER_DN, true));

        session.reset();

        assert!(session.identity().is_none());
        assert!(!session.may_access(USER_DN));
    }
}
