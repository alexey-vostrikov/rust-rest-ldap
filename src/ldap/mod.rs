//! LDAP protocol layer: framing, operations and the per-message dispatcher.

pub mod bind;
pub mod codec;
pub mod filter;
pub mod paged;
pub mod responses;
pub mod search;
pub mod session;

use rasn_ldap::{LdapMessage, ProtocolOp, ResultCode};

use crate::directory::Directory;
use crate::password::PasswordPolicy;
use session::Session;

/// What the connection loop does after one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send these messages and keep the connection open.
    Reply(Vec<LdapMessage>),
    /// Keep the connection open without responding (abandon).
    Silent,
    /// Close the connection (unbind, protocol violation).
    Close,
}

/// Dispatches one message.
///
/// Operations this server does not implement answer with their own result
/// envelope and `unwillingToPerform`, so a client sees a real LDAP error instead
/// of a dropped connection.
pub fn handle(
    session: &mut Session,
    directory: &Directory,
    respect_critical_controls: bool,
    passwords: &PasswordPolicy,
    message: LdapMessage,
) -> Action {
    let message_id = message.message_id;
    let controls = message.controls.clone();

    match message.protocol_op {
        ProtocolOp::BindRequest(request) => Action::Reply(vec![bind::handle_bind(
            session, directory, message_id, &request, passwords,
        )]),
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
            respect_critical_controls,
        )),
        ProtocolOp::CompareRequest(_) => Action::Reply(vec![responses::compare_response(
            message_id,
            ResultCode::UnwillingToPerform,
            "compare is not implemented yet",
        )]),
        ProtocolOp::ModifyRequest(_) => Action::Reply(vec![responses::modify_response(
            message_id,
            ResultCode::UnwillingToPerform,
            "modify is not implemented yet",
        )]),
        ProtocolOp::AddRequest(_) => Action::Reply(vec![responses::add_response(
            message_id,
            ResultCode::UnwillingToPerform,
            "add is not supported",
        )]),
        ProtocolOp::DelRequest(_) => Action::Reply(vec![responses::del_response(
            message_id,
            ResultCode::UnwillingToPerform,
            "delete is not supported",
        )]),
        ProtocolOp::ModDnRequest(_) => Action::Reply(vec![responses::modify_dn_response(
            message_id,
            ResultCode::UnwillingToPerform,
            "modify dn is not supported",
        )]),
        ProtocolOp::ExtendedReq(_) => Action::Reply(vec![responses::extended_response(
            message_id,
            ResultCode::UnwillingToPerform,
            "extended operations are not supported",
            None,
        )]),
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

    fn policy() -> PasswordPolicy {
        PasswordPolicy::strict()
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
            true,
            &policy(),
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
            true,
            &policy(),
            bind_message(1, b"admin-secret"),
        );

        let action = handle(
            &mut session,
            &directory,
            true,
            &policy(),
            LdapMessage::new(2, ProtocolOp::UnbindRequest(UnbindRequest)),
        );

        assert_eq!(action, Action::Close);
        assert!(session.identity().is_none());
    }

    #[test]
    fn unsupported_operations_answer_with_their_own_envelope() {
        let directory = directory();
        let mut session = Session::new();

        let add = LdapMessage::new(
            4,
            ProtocolOp::AddRequest(AddRequest {
                entry: LdapDn::from("cn=x,dc=example,dc=com"),
                attributes: vec![],
            }),
        );
        let delete = LdapMessage::new(
            5,
            ProtocolOp::DelRequest(DelRequest(LdapDn::from("cn=x,dc=example,dc=com"))),
        );
        let modify_dn = LdapMessage::new(
            6,
            ProtocolOp::ModDnRequest(ModifyDnRequest {
                entry: LdapDn::from("cn=x,dc=example,dc=com"),
                new_rdn: LdapDn::from("cn=y"),
                delete_old_rdn: true,
                new_superior: None,
            }),
        );
        let compare = LdapMessage::new(
            7,
            ProtocolOp::CompareRequest(CompareRequest {
                entry: LdapDn::from("cn=x,dc=example,dc=com"),
                ava: AttributeValueAssertion::new(
                    AttributeDescription::from("cn"),
                    rasn::types::OctetString::from_static(b"x"),
                ),
            }),
        );

        for message in [add, delete, modify_dn, compare] {
            let action = handle(&mut session, &directory, true, &policy(), message);
            assert_eq!(codes(&action), vec![ResultCode::UnwillingToPerform]);
        }
    }

    #[test]
    fn search_is_dispatched_to_the_search_handler() {
        let directory = directory();
        let mut session = Session::new();
        handle(
            &mut session,
            &directory,
            true,
            &policy(),
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

        let action = handle(&mut session, &directory, true, &policy(), search);

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
            handle(&mut session, &directory, true, &policy(), response),
            Action::Close
        );
    }
}
