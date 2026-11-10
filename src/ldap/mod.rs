//! LDAP protocol layer: framing, operations and the per-message dispatcher.

pub mod assertion;
pub mod bind;
pub mod codec;
pub mod compare;
pub mod config_entry;
pub mod extop;
pub mod filter;
pub mod filter_parse;
pub mod modify;
pub mod paged;
pub mod responses;
pub mod sasl_bind;
pub mod schema_entry;
pub mod search;
pub mod session;
pub mod sort;
pub mod spnego_offer;
pub mod starttls;
pub mod sync;
pub mod wkguid;
pub mod write;

use rasn_ldap::{LdapMessage, ProtocolOp, ResultCode};

use crate::backend::EntryChange;
use crate::directory::Directory;
use crate::metrics::{ChangeKind, Note};
use crate::security::Security;
use session::Session;

/// What the connection loop does after one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send these messages and keep the connection open.
    Reply(Vec<LdapMessage>),
    /// Keep the connection open without responding (abandon).
    Silent,
    /// Answer with a success response, then switch the connection to TLS.
    StartTls(rasn_ldap::MessageId),
    /// Persist these changes, then send `success`; on a backend error send `failure`.
    ///
    /// The reply is only sent after the write, so a client never sees `success` for a
    /// change that did not reach the store.
    Persist(Box<PersistAction>),
    /// Send these messages, then persist `changes` without letting a failure change
    /// the answer.
    ///
    /// For a write the client did not ask for and that cannot invalidate the reply: the
    /// password-hash upgrade after a successful bind. The bind is correct whether or not
    /// the new hash is stored, so an error here is logged, not reported.
    PersistAfterReply {
        messages: Vec<LdapMessage>,
        changes: Vec<EntryChange>,
    },
    /// A change to `cn=config` was committed.
    ///
    /// The protocol layer decided what the change means and wrote the document; the server
    /// decides whether the running process can adopt it, because that needs the configuration
    /// it started with and the policy handle - neither of which a handler holds.
    ConfigCommitted(Box<ConfigCommitted>),
    /// Send these messages, then keep the search open and push what changes.
    ///
    /// Only a `refreshAndPersist` search produces this. The subscriber is registered *before* the
    /// messages are sent, so a change that lands while the answer is being written is delivered
    /// rather than lost between the refresh and the subscription.
    Persisted {
        messages: Vec<LdapMessage>,
        subscription: Box<crate::ldap::search::Subscription>,
    },
    /// Close the connection (unbind, protocol violation).
    Close,
}

/// The DN of the entry a single-entry change set is about.
fn entry_dn_of(changes: &[EntryChange]) -> String {
    changes
        .first()
        .map(|change| match change {
            EntryChange::Upsert { entry } => entry.dn().to_string(),
            EntryChange::Delete { dn, .. } => dn.clone(),
            _ => String::new(),
        })
        .unwrap_or_default()
}

/// Who is making this change, for the journal.
///
/// The empty string means anonymous, which no write allows: seeing it in a journal entry
/// would mean a write got past the access checks, and that is worth noticing.
fn actor(session: &Session) -> String {
    session
        .identity()
        .map(|identity| identity.dn.clone())
        .unwrap_or_default()
}

/// What a write turned into.
///
/// A boxed struct rather than fields on the variant: with the response messages and the
/// journal note it is nearly 300 bytes, and `Action` is returned for every message on every
/// connection. One allocation per write — writes are rare next to searches — is cheaper than
/// copying that payload through every dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistAction {
    pub changes: Vec<EntryChange>,
    pub success: LdapMessage,
    pub message_id: rasn_ldap::MessageId,
    /// Which response carries the failure; the diagnostic has to include the backend's
    /// error text, which is only known when the write failed.
    pub failure: FailureResponse,
    /// What to write into the change journal: the operation as the client sees it, not as
    /// the change set looks. The handler knows which DN it addressed and where a rename
    /// went; the change set also contains side effects that are not the operation and must
    /// not be journalled as if they were.
    pub journal: Option<crate::metrics::Note>,
}

/// Handles a write aimed at `cn=config`.
///
/// Only `modify` changes a document: adding and deleting a section would have to decide what
/// the new document key is called, and the attribute name cannot say (see the rules in
/// [`config_entry::change`]). Those operations are refused with the reason, not with a guess.
fn config_change(
    session: &Session,
    security: &Security,
    message_id: rasn_ldap::MessageId,
    response: FailureResponse,
    op: &ProtocolOp,
) -> Action {
    let Some(document) = security.config_document.as_ref() else {
        return Action::Reply(vec![response.message(
            message_id,
            ResultCode::UnwillingToPerform,
            "this server was configured by flags and defaults alone, so it has no document to \
             change",
        )]);
    };

    let ProtocolOp::ModifyRequest(request) = op else {
        return Action::Reply(vec![response.message(
            message_id,
            ResultCode::UnwillingToPerform,
            "adding and deleting entries in cn=config is not supported yet: change a value with \
             modify, and add or remove a section by editing the document",
        )]);
    };

    match config_entry::change(document, session, request) {
        Ok(committed) if committed.keys.is_empty() => Action::Reply(vec![response.message(
            message_id,
            ResultCode::Success,
            &format!(
                "nothing to change: every setting already has that value, and generation {} \
                 stays in force",
                committed.generation
            ),
        )]),
        Ok(committed) => Action::ConfigCommitted(Box::new(ConfigCommitted {
            generation: committed.generation,
            document: committed.document,
            // `success` now and the diagnostic filled in by the server: whether the settings
            // took effect is the server's answer, not the handler's guess.
            response: response.message(message_id, ResultCode::Success, ""),
            message_id,
        })),
        Err(refusal) => Action::Reply(vec![response.message(
            message_id,
            refusal.code,
            &refusal.detail,
        )]),
    }
}

/// The entry a write operation addresses, and the response shape it expects.
///
/// Used for the one decision taken before dispatch: whether the request aims at `cn=config`,
/// which is not part of the directory.
fn config_write_target(op: &ProtocolOp) -> Option<(FailureResponse, String)> {
    match op {
        ProtocolOp::ModifyRequest(request) => {
            Some((FailureResponse::Modify, request.object.0.to_string()))
        }
        ProtocolOp::AddRequest(request) => {
            Some((FailureResponse::Add, request.entry.0.to_string()))
        }
        ProtocolOp::DelRequest(request) => Some((FailureResponse::Del, request.0.to_string())),
        ProtocolOp::ModDnRequest(request) => {
            Some((FailureResponse::ModDn, request.entry.0.to_string()))
        }
        _ => None,
    }
}

/// A committed configuration change, waiting for the server to adopt it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigCommitted {
    /// The generation the changed document was committed as.
    pub generation: u64,
    /// The document in force, as committed.
    pub document: String,
    /// The response to send, once the server has decided what it could adopt.
    pub response: LdapMessage,
    pub message_id: rasn_ldap::MessageId,
}

/// Response to send when a write does not reach the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureResponse {
    Modify,
    Add,
    Del,
    ModDn,
    Extended,
}

impl FailureResponse {
    /// Builds the failure message of the right shape.
    pub fn message(
        &self,
        message_id: rasn_ldap::MessageId,
        code: ResultCode,
        diagnostic: &str,
    ) -> LdapMessage {
        match self {
            FailureResponse::Modify => responses::modify_response(message_id, code, diagnostic),
            FailureResponse::Add => responses::add_response(message_id, code, diagnostic),
            FailureResponse::Del => responses::del_response(message_id, code, diagnostic),
            FailureResponse::ModDn => responses::modify_dn_response(message_id, code, diagnostic),
            FailureResponse::Extended => responses::extended_response(
                message_id,
                code,
                diagnostic,
                Some(extop::PASSWORD_MODIFY_OID),
            ),
        }
    }
}

/// Dispatches one message.
///
/// Operations this server does not implement answer with their own result
/// envelope and `unwillingToPerform`, so a client sees a real LDAP error instead
/// of a dropped connection.
pub fn handle(
    session: &mut Session,
    directory: &Directory,
    security: &Security,
    message: LdapMessage,
) -> Action {
    let message_id = message.message_id;
    let controls = message.controls.clone();

    // `cn=config` is not the directory: the subtree is generated from the configuration
    // document, so a change there is a new generation of that document, not an entry in the
    // store. Handled before dispatch so the request never reaches the directory, where it would
    // find nothing and answer `noSuchObject` - which reads as "your DN is wrong".
    if let Some((response, _)) =
        config_write_target(&message.protocol_op).filter(|(_, dn)| config_entry::is_config_dn(dn))
    {
        return config_change(
            session,
            security,
            message_id,
            response,
            &message.protocol_op,
        );
    }

    match message.protocol_op {
        ProtocolOp::BindRequest(request) => {
            let outcome =
                bind::handle_bind_outcome(session, directory, message_id, &request, security);

            match outcome.upgrade {
                None => Action::Reply(vec![outcome.message]),
                Some(entry) => Action::PersistAfterReply {
                    messages: vec![outcome.message],
                    changes: vec![EntryChange::Upsert { entry }],
                },
            }
        }
        ProtocolOp::UnbindRequest(_) => {
            session.reset();
            Action::Close
        }
        ProtocolOp::AbandonRequest(_) => Action::Silent,
        ProtocolOp::SearchRequest(request) => {
            let messages = search::handle_search(
                session,
                directory,
                message_id,
                &request,
                controls.as_ref(),
                security,
            );

            // A `refreshAndPersist` search that produced an answer stays open. The decision is
            // taken here rather than inside the handler because the handler returns messages and
            // this returns a plan for the connection - and because the subscription has to be
            // registered before the answer is written, or a change landing while it is being
            // written would be lost between the refresh and the subscription.
            let persistent = controls.into_iter().flatten().any(|control| {
                control.control_type.as_ref() == sync::SYNC_OID.as_bytes()
                    && control
                        .control_value
                        .as_ref()
                        .and_then(|value| sync::decode_request(value.as_ref()).ok())
                        .is_some_and(|request| request.mode == sync::Mode::RefreshAndPersist)
            });

            // A refusal is not something to keep open: `messages` then carries a `searchResDone`
            // with a failure code, and the client is told rather than left waiting.
            // The `syncInfo` message is what says the refresh finished; a failure answer has a
            // `searchResDone` instead and must not leave the search open.
            let answered = messages
                .iter()
                .any(|message| matches!(message.protocol_op, ProtocolOp::IntermediateResponse(_)));

            match (persistent, answered) {
                (true, true) => Action::Persisted {
                    messages,
                    subscription: Box::new(search::Subscription {
                        message_id,
                        base_object: request.base_object.0.to_string(),
                        scope: search::scope_of(&request),
                        filter: request.filter.clone(),
                        requester: session.requester(),
                        selection: request
                            .attributes
                            .iter()
                            .map(|attribute| attribute.0.clone())
                            .collect(),
                    }),
                },
                _ => Action::Reply(messages),
            }
        }
        ProtocolOp::CompareRequest(request) => Action::Reply(vec![compare::handle_compare(
            session, directory, message_id, &request, security,
        )]),
        ProtocolOp::ModifyRequest(request) => {
            match modify::handle_modify(
                session,
                directory,
                message_id,
                &request,
                controls.as_ref(),
                security,
            ) {
                modify::Outcome::Reject(message) => Action::Reply(vec![message]),
                modify::Outcome::Persist {
                    entry,
                    extra,
                    success,
                } => {
                    let note = Note::new(ChangeKind::Modify, entry.dn(), actor(session));

                    // The entry the client addressed first, then the members whose `memberOf`
                    // followed it: one transaction, and the journal line names the entry the
                    // request was about.
                    let mut changes = vec![EntryChange::Upsert { entry }];
                    changes.extend(extra.into_iter().map(|entry| EntryChange::Upsert { entry }));

                    Action::Persist(Box::new(PersistAction {
                        changes,
                        success,
                        message_id,
                        failure: FailureResponse::Modify,
                        journal: Some(note),
                    }))
                }
            }
        }
        ProtocolOp::AddRequest(request) => {
            match write::handle_add(session, directory, message_id, &request, security) {
                write::Outcome::Reject(message) => Action::Reply(vec![message]),
                write::Outcome::Persist { changes, success } => {
                    let note = Note::new(ChangeKind::Add, entry_dn_of(&changes), actor(session));

                    Action::Persist(Box::new(PersistAction {
                        changes,
                        success,
                        message_id,
                        failure: FailureResponse::Add,
                        journal: Some(note),
                    }))
                }
            }
        }
        ProtocolOp::DelRequest(request) => {
            match write::handle_delete(session, directory, message_id, &request, security) {
                write::Outcome::Reject(message) => Action::Reply(vec![message]),
                write::Outcome::Persist { changes, success } => {
                    let note = Note::new(ChangeKind::Delete, entry_dn_of(&changes), actor(session));

                    Action::Persist(Box::new(PersistAction {
                        changes,
                        success,
                        message_id,
                        failure: FailureResponse::Del,
                        journal: Some(note),
                    }))
                }
            }
        }
        ProtocolOp::ModDnRequest(request) => {
            match write::handle_modify_dn(session, directory, message_id, &request, security) {
                write::Outcome::Reject(message) => Action::Reply(vec![message]),
                write::Outcome::Persist { changes, success } => {
                    // The rename is the pair the handler knows: the DN the client addressed
                    // and the one it asked for. The change set also moves a subtree and
                    // rewrites the groups that list the user, and none of that is a second
                    // rename.
                    let note = write::renamed_dn(&changes)
                        .map(|(old, new)| Note::renamed(old, new, actor(session)));

                    Action::Persist(Box::new(PersistAction {
                        changes,
                        success,
                        message_id,
                        failure: FailureResponse::ModDn,
                        journal: note,
                    }))
                }
            }
        }
        ProtocolOp::ExtendedReq(request) => {
            if starttls::is_starttls(request.request_name.as_ref()) {
                // The connection loop owns the acceptor, so availability is decided
                // there: the dispatcher only recognises the operation.
                return Action::StartTls(message_id);
            }

            match extop::operation(request.request_name.as_ref()) {
                extop::Operation::WhoAmI => {
                    Action::Reply(extop::handle_whoami(session, message_id))
                }
                extop::Operation::PasswordModify => {
                    let value = request
                        .request_value
                        .as_ref()
                        .map(|value| value.as_ref().to_vec());

                    match extop::handle_password_modify(
                        session,
                        directory,
                        message_id,
                        value.as_deref(),
                        security,
                    ) {
                        extop::Outcome::Reply(message) => Action::Reply(vec![message]),
                        extop::Outcome::Persist { entry, success } => {
                            let note =
                                Note::new(ChangeKind::PasswordChange, entry.dn(), actor(session));

                            Action::Persist(Box::new(PersistAction {
                                changes: vec![EntryChange::Upsert { entry }],
                                success,
                                message_id,
                                failure: FailureResponse::Extended,
                                journal: Some(note),
                            }))
                        }
                    }
                }
                extop::Operation::Unknown => Action::Reply(vec![responses::extended_response(
                    message_id,
                    ResultCode::UnwillingToPerform,
                    "unsupported extended operation",
                    None,
                )]),
            }
        }
        // A client must not send responses to the server.
        _ => Action::Close,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::User;
    use crate::password::{StoreScheme, hash as hash_password};
    use rasn_ldap::{
        AddRequest, AttributeDescription, AttributeValueAssertion, AuthenticationChoice,
        BindRequest, BindResponse, CompareRequest, DelRequest, LdapDn, LdapString, MessageId,
        ModifyDnRequest, UnbindRequest,
    };

    const BASE: &str = "dc=example,dc=com";
    const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";

    /// Policy for the dispatcher tests: they talk to handlers, not to a socket, and
    /// several of them bind in the clear. The setting is switched on here so the
    /// unencrypted-bind refusal does not hide what the test is about.
    fn security() -> Security {
        Security {
            allow_unencrypted_bind: true,
            ..Security::default()
        }
    }

    fn directory() -> Directory {
        Directory::new(
            BASE,
            "users",
            "groups",
            vec![User {
                ldap_admin: true,
                cn: "admin".to_string(),
                user_password: Some(
                    hash_password("admin-secret", StoreScheme::Argon2id).expect("hash"),
                ),
                ..User::default()
            }],
            vec![],
        )
    }

    fn bind_message(message_id: MessageId, password: &[u8]) -> LdapMessage {
        LdapMessage::new(
            message_id,
            ProtocolOp::BindRequest(BindRequest::new(
                3,
                LdapDn::from(ADMIN_DN),
                AuthenticationChoice::Simple(rasn::types::OctetString::from_slice(password)),
            )),
        )
    }

    fn codes(action: &Action) -> Vec<ResultCode> {
        match action {
            Action::Reply(messages) => messages
                .iter()
                .map(|message| match &message.protocol_op {
                    ProtocolOp::BindResponse(response) => response.result_code,
                    ProtocolOp::SearchResDone(done) => done.0.result_code,
                    ProtocolOp::CompareResponse(response) => response.0.result_code,
                    ProtocolOp::ModifyResponse(response) => response.0.result_code,
                    ProtocolOp::AddResponse(response) => response.0.result_code,
                    ProtocolOp::DelResponse(response) => response.0.result_code,
                    ProtocolOp::ModDnResponse(response) => response.0.result_code,
                    ProtocolOp::ExtendedResp(response) => response.result_code,
                    other => panic!("unexpected response: {other:?}"),
                })
                .collect(),
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn bind_is_dispatched_and_updates_the_session() {
        let directory = directory();
        let mut session = Session::new();

        let action = handle(
            &mut session,
            &directory,
            &security(),
            bind_message(1, b"admin-secret"),
        );

        assert_eq!(codes(&action), vec![ResultCode::Success]);
        assert!(session.is_admin());
    }

    #[test]
    fn unbind_closes_the_connection_and_drops_the_identity() {
        let directory = directory();
        let mut session = Session::new();
        handle(
            &mut session,
            &directory,
            &security(),
            bind_message(1, b"admin-secret"),
        );

        let action = handle(
            &mut session,
            &directory,
            &security(),
            LdapMessage::new(2, ProtocolOp::UnbindRequest(UnbindRequest)),
        );

        assert_eq!(action, Action::Close);
        assert!(session.identity().is_none());
    }

    #[test]
    fn write_operations_answer_in_their_own_envelope() {
        // Every operation now has a handler, so the property worth pinning is the
        // envelope: a client tells the answer apart by the response type, and a wrong
        // type is as bad as a wrong code.
        let directory = directory();
        let mut session = Session::new();

        // (request, expected code, the work of recognising the response envelope)
        type Case = (LdapMessage, ResultCode, fn(&ProtocolOp) -> bool);
        let cases: Vec<Case> = vec![
            (
                LdapMessage::new(
                    4,
                    ProtocolOp::AddRequest(AddRequest {
                        entry: LdapDn::from("cn=x,ou=users,dc=example,dc=com"),
                        attributes: vec![],
                    }),
                ),
                // The parent exists, but an anonymous session may not write.
                ResultCode::InsufficientAccessRights,
                |op| matches!(op, ProtocolOp::AddResponse(_)),
            ),
            (
                LdapMessage::new(
                    5,
                    ProtocolOp::DelRequest(DelRequest(LdapDn::from(
                        "cn=missing,ou=users,dc=example,dc=com",
                    ))),
                ),
                ResultCode::NoSuchObject,
                |op| matches!(op, ProtocolOp::DelResponse(_)),
            ),
            (
                LdapMessage::new(
                    6,
                    ProtocolOp::ModDnRequest(ModifyDnRequest {
                        entry: LdapDn::from("cn=missing,ou=users,dc=example,dc=com"),
                        new_rdn: LdapDn::from("cn=y"),
                        delete_old_rdn: true,
                        new_superior: None,
                    }),
                ),
                ResultCode::NoSuchObject,
                |op| matches!(op, ProtocolOp::ModDnResponse(_)),
            ),
            (
                LdapMessage::new(
                    7,
                    ProtocolOp::CompareRequest(CompareRequest {
                        entry: LdapDn::from("cn=missing,dc=example,dc=com"),
                        ava: AttributeValueAssertion::new(
                            AttributeDescription::from("cn"),
                            rasn::types::OctetString::from_static(b"x"),
                        ),
                    }),
                ),
                ResultCode::NoSuchObject,
                |op| matches!(op, ProtocolOp::CompareResponse(_)),
            ),
        ];

        for (message, expected, envelope) in cases {
            let action = handle(&mut session, &directory, &security(), message);
            let messages = match action {
                Action::Reply(messages) => messages,
                other => panic!("expected a reply, got {other:?}"),
            };

            let last = messages.last().expect("a response");
            assert!(
                envelope(&last.protocol_op),
                "wrong response type: {:?}",
                last.protocol_op
            );
            assert_eq!(
                codes(&Action::Reply(messages)),
                vec![expected],
                "unexpected code for {:?}",
                expected
            );
        }
    }

    #[test]
    fn search_is_dispatched_to_the_search_handler() {
        let directory = directory();
        let mut session = Session::new();
        handle(
            &mut session,
            &directory,
            &security(),
            bind_message(1, b"admin-secret"),
        );

        let search = LdapMessage::new(
            2,
            ProtocolOp::SearchRequest(rasn_ldap::SearchRequest::new(
                LdapDn::from(BASE),
                rasn_ldap::SearchRequestScope::WholeSubtree,
                rasn_ldap::SearchRequestDerefAliases::NeverDerefAliases,
                0,
                0,
                false,
                rasn_ldap::Filter::Present(AttributeDescription::from("objectClass")),
                vec![],
            )),
        );

        let action = handle(&mut session, &directory, &security(), search);

        match action {
            Action::Reply(messages) => {
                assert!(
                    messages.len() > 1,
                    "a subtree search must return entries, got {}",
                    messages.len()
                );
                assert!(matches!(
                    messages.last().expect("done").protocol_op,
                    ProtocolOp::SearchResDone(_)
                ));
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn client_sent_response_closes_the_connection() {
        let directory = directory();
        let mut session = Session::new();
        let response = LdapMessage::new(
            8,
            ProtocolOp::BindResponse(BindResponse::new(
                ResultCode::Success,
                LdapDn::from(""),
                LdapString::from(""),
                None,
                None,
            )),
        );

        assert_eq!(
            handle(&mut session, &directory, &security(), response),
            Action::Close
        );
    }
}
