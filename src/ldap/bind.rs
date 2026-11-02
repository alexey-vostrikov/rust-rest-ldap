//! Bind operation: simple authentication against user entries.

use rasn_ldap::{AuthenticationChoice, BindRequest, MessageId, ResultCode};

use super::responses::bind_response;
use super::session::{Identity, Session};
use crate::directory::{Directory, Entry};
use crate::dn;
use crate::password::{PasswordPolicy, verify};

/// Handles a bind request and updates the session identity.
///
/// The identity is cleared first: per RFC 4513 a failed bind leaves the
/// connection anonymous, and gorestldap kept the previous ACL in that case.
pub fn handle_bind(
    session: &mut Session,
    directory: &Directory,
    message_id: MessageId,
    request: &BindRequest,
    passwords: &PasswordPolicy,
) -> rasn_ldap::LdapMessage {
    session.reset();

    if request.version != 3 {
        return bind_response(
            message_id,
            ResultCode::ProtocolError,
            &format!("only LDAP version 3 is supported, got {}", request.version),
        );
    }

    let password = match &request.authentication {
        AuthenticationChoice::Simple(password) => {
            String::from_utf8_lossy(password.as_ref()).into_owned()
        }
        other => {
            return bind_response(
                message_id,
                ResultCode::AuthMethodNotSupported,
                &format!("authentication method {other:?} is not supported"),
            );
        }
    };

    let bind_dn = dn::normalize(&request.name.0);

    // Anonymous bind: empty name and empty password.
    if bind_dn.is_empty() && password.is_empty() {
        return bind_response(message_id, ResultCode::Success, "");
    }

    if bind_dn.is_empty() {
        return bind_response(
            message_id,
            ResultCode::UnwillingToPerform,
            "unauthenticated bind (empty name with a password) is not allowed",
        );
    }

    if !dn::is_valid(&bind_dn) {
        return bind_response(
            message_id,
            ResultCode::InvalidDnSyntax,
            &format!("wrong dn '{bind_dn}'"),
        );
    }

    let user = match directory.find(&bind_dn) {
        Some(Entry::User(user)) => user,
        _ => {
            return bind_response(
                message_id,
                ResultCode::NoSuchObject,
                &format!("dn '{bind_dn}' not found"),
            );
        }
    };

    let stored_hash = match &user.user_password {
        Some(hash) if !hash.is_empty() => hash,
        _ => {
            return bind_response(
                message_id,
                ResultCode::InvalidCredentials,
                "user has no password set",
            );
        }
    };

    match verify(&password, stored_hash, passwords) {
        Ok(true) => {
            session.set_identity(Identity::new(&bind_dn, user.ldap_admin));
            bind_response(message_id, ResultCode::Success, "")
        }
        Ok(false) => bind_response(message_id, ResultCode::InvalidCredentials, "wrong password"),
        Err(err) => bind_response(
            message_id,
            ResultCode::InvalidCredentials,
            &format!("wrong password for dn '{bind_dn}': {err}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Group, User};
    use crate::password::{StoreScheme, hash as hash_password};

    fn policy() -> PasswordPolicy {
        PasswordPolicy::strict()
    }

    fn hash(value: &str) -> String {
        hash_password(value, StoreScheme::Argon2id).expect("hash")
    }

    const BASE: &str = "dc=example,dc=com";
    const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
    const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";

    fn directory() -> Directory {
        let admin = User {
            ldap_admin: true,
            cn: "admin".to_string(),
            uid: Some("admin".to_string()),
            user_password: Some(hash("admin-secret")),
            ..User::default()
        };
        let alice = User {
            cn: "alice".to_string(),
            uid: Some("alice".to_string()),
            user_password: Some(hash("alice-secret")),
            ..User::default()
        };
        let passwordless = User {
            cn: "nopassword".to_string(),
            ..User::default()
        };
        let group = Group {
            cn: "group_a".to_string(),
            ..Group::default()
        };

        Directory::new(
            BASE,
            "users",
            "groups",
            vec![admin, alice, passwordless],
            vec![group],
        )
    }

    fn request(version: u8, name: &str, password: &[u8]) -> BindRequest {
        BindRequest::new(
            version,
            rasn_ldap::LdapDn::from(name),
            AuthenticationChoice::Simple(rasn::types::OctetString::from_slice(password)),
        )
    }

    fn code(message: &rasn_ldap::LdapMessage) -> ResultCode {
        match &message.protocol_op {
            rasn_ldap::ProtocolOp::BindResponse(response) => response.result_code,
            other => panic!("unexpected response: {other:?}"),
        }
    }

    fn diagnostic(message: &rasn_ldap::LdapMessage) -> String {
        match &message.protocol_op {
            rasn_ldap::ProtocolOp::BindResponse(response) => response.diagnostic_message.0.clone(),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn valid_credentials_bind_the_admin() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            1,
            &request(3, ADMIN_DN, b"admin-secret"),
            &policy(),
        );

        assert_eq!(code(&response), ResultCode::Success);
        assert_eq!(diagnostic(&response), "");
        let identity = session.identity().expect("identity");
        assert_eq!(identity.dn, ADMIN_DN);
        assert!(identity.admin);
    }

    #[test]
    fn regular_user_binds_without_admin_rights() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            2,
            &request(3, ALICE_DN, b"alice-secret"),
            &policy(),
        );

        assert_eq!(code(&response), ResultCode::Success);
        let identity = session.identity().expect("identity");
        assert_eq!(identity.dn, ALICE_DN);
        assert!(!identity.admin);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            3,
            &request(3, ADMIN_DN, b"not-the-password"),
            &policy(),
        );

        assert_eq!(code(&response), ResultCode::InvalidCredentials);
        assert_eq!(diagnostic(&response), "wrong password");
        assert!(session.identity().is_none());
    }

    #[test]
    fn unknown_entry_is_reported_as_missing_object() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            4,
            &request(3, "cn=nobody,ou=users,dc=example,dc=com", b"x"),
            &policy(),
        );

        assert_eq!(code(&response), ResultCode::NoSuchObject);
        assert_eq!(
            diagnostic(&response),
            "dn 'cn=nobody,ou=users,dc=example,dc=com' not found"
        );
    }

    #[test]
    fn binding_as_a_group_or_the_domain_is_rejected() {
        let directory = directory();
        let mut session = Session::new();

        let group = handle_bind(
            &mut session,
            &directory,
            5,
            &request(3, "cn=group_a,ou=groups,dc=example,dc=com", b"x"),
            &policy(),
        );
        let domain = handle_bind(
            &mut session,
            &directory,
            6,
            &request(3, BASE, b"x"),
            &policy(),
        );

        assert_eq!(code(&group), ResultCode::NoSuchObject);
        assert_eq!(code(&domain), ResultCode::NoSuchObject);
    }

    #[test]
    fn unsupported_attribute_in_dn_is_rejected() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            7,
            &request(3, "mail=admin@example.com,dc=example,dc=com", b"x"),
            &policy(),
        );

        assert_eq!(code(&response), ResultCode::InvalidDnSyntax);
    }

    #[test]
    fn sasl_bind_is_not_supported() {
        let directory = directory();
        let mut session = Session::new();
        let sasl = BindRequest::new(
            3,
            rasn_ldap::LdapDn::from(ADMIN_DN),
            AuthenticationChoice::Sasl(rasn_ldap::SaslCredentials::new(
                rasn_ldap::LdapString::from("GSSAPI"),
                None,
            )),
        );

        let response = handle_bind(&mut session, &directory, 8, &sasl, &policy());

        assert_eq!(code(&response), ResultCode::AuthMethodNotSupported);
        assert!(diagnostic(&response).contains("GSSAPI"));
    }

    #[test]
    fn version_two_is_rejected() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            9,
            &request(2, ADMIN_DN, b"admin-secret"),
            &policy(),
        );

        assert_eq!(code(&response), ResultCode::ProtocolError);
        assert_eq!(
            diagnostic(&response),
            "only LDAP version 3 is supported, got 2"
        );
    }

    #[test]
    fn anonymous_bind_succeeds_without_an_identity() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            10,
            &request(3, "", b""),
            &policy(),
        );

        assert_eq!(code(&response), ResultCode::Success);
        assert!(session.identity().is_none());
    }

    #[test]
    fn unauthenticated_bind_is_refused() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            11,
            &request(3, "", b"secret"),
            &policy(),
        );

        assert_eq!(code(&response), ResultCode::UnwillingToPerform);
        assert_eq!(
            diagnostic(&response),
            "unauthenticated bind (empty name with a password) is not allowed"
        );
    }

    #[test]
    fn user_without_password_cannot_bind() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            12,
            &request(3, "cn=nopassword,ou=users,dc=example,dc=com", b"x"),
            &policy(),
        );

        assert_eq!(code(&response), ResultCode::InvalidCredentials);
        assert_eq!(diagnostic(&response), "user has no password set");
    }

    #[test]
    fn failed_bind_drops_the_previous_identity() {
        let directory = directory();
        let mut session = Session::new();
        handle_bind(
            &mut session,
            &directory,
            13,
            &request(3, ADMIN_DN, b"admin-secret"),
            &policy(),
        );
        assert!(session.identity().is_some());

        handle_bind(
            &mut session,
            &directory,
            14,
            &request(3, ADMIN_DN, b"wrong"),
            &policy(),
        );

        assert!(session.identity().is_none());
    }

    #[test]
    fn bind_by_uid_rdn_also_works() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            15,
            &request(3, "uid=alice,ou=users,dc=example,dc=com", b"alice-secret"),
            &policy(),
        );

        assert_eq!(code(&response), ResultCode::Success);
        assert_eq!(
            session.identity().expect("identity").dn,
            "uid=alice,ou=users,dc=example,dc=com"
        );
    }

    #[test]
    fn bind_dn_case_and_spaces_are_normalized() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            16,
            &request(3, "CN=Admin, OU=Users, DC=Example, DC=Com", b"admin-secret"),
            &policy(),
        );

        assert_eq!(code(&response), ResultCode::Success);
        assert_eq!(session.identity().expect("identity").dn, ADMIN_DN);
    }
}
