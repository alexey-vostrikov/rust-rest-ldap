//! LDAP protocol layer: framing, operations and the per-message dispatcher.

pub mod assertion;
pub mod bind;
pub mod codec;
pub mod compare;
pub mod extop;
pub mod filter;
pub mod modify;
pub mod paged;
pub mod responses;
pub mod schema_entry;
pub mod search;
pub mod session;
pub mod starttls;
pub mod write;

use rasn_ldap::{LdapMessage, ProtocolOp, ResultCode};

use crate::backend::EntryChange;
use crate::directory::Directory;
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
    Persist {
        changes: Vec<EntryChange>,
        success: LdapMessage,
        message_id: rasn_ldap::MessageId,
        /// Which response carries the failure; the diagnostic has to include the
        /// backend's error text, which is only known when the write failed.
        failure: FailureResponse,
    },
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
    /// Close the connection (unbind, protocol violation).
    Close,
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
        ProtocolOp::SearchRequest(request) => Action::Reply(search::handle_search(
            session,
            directory,
            message_id,
            &request,
            controls.as_ref(),
            security,
        )),
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
                modify::Outcome::Persist { entry, success } => Action::Persist {
                    changes: vec![EntryChange::Upsert { entry }],
                    success,
                    message_id,
                    failure: FailureResponse::Modify,
                },
            }
        }
        ProtocolOp::AddRequest(request) => {
            match write::handle_add(session, directory, message_id, &request, security) {
                write::Outcome::Reject(message) => Action::Reply(vec![message]),
                write::Outcome::Persist { changes, success } => Action::Persist {
                    changes,
                    success,
                    message_id,
                    failure: FailureResponse::Add,
                },
            }
        }
        ProtocolOp::DelRequest(request) => {
            match write::handle_delete(session, directory, message_id, &request, security) {
                write::Outcome::Reject(message) => Action::Reply(vec![message]),
                write::Outcome::Persist { changes, success } => Action::Persist {
                    changes,
                    success,
                    message_id,
                    failure: FailureResponse::Del,
                },
            }
        }
        ProtocolOp::ModDnRequest(request) => {
            match write::handle_modify_dn(session, directory, message_id, &request, security) {
                write::Outcome::Reject(message) => Action::Reply(vec![message]),
                write::Outcome::Persist { changes, success } => Action::Persist {
                    changes,
                    success,
                    message_id,
                    failure: FailureResponse::ModDn,
                },
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
                        extop::Outcome::Persist { entry, success } => Action::Persist {
                            changes: vec![EntryChange::Upsert { entry }],
                            success,
                            message_id,
                            failure: FailureResponse::Extended,
                        },
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
