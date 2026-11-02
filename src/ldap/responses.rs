//! Builders for LDAP responses.
//!
//! Every result type in `rasn-ldap` needs its own envelope, so the builders live
//! in one place: handlers decide a result code, not the shape of the message.

use rasn::types::{OctetString, SetOf};
use rasn_ldap::{
    AddResponse, AttributeDescription, AttributeValue, BindResponse, CompareResponse, Control,
    Controls, DelResponse, ExtendedResponse, LdapDn, LdapMessage, LdapOid, LdapResult, MessageId,
    ModifyDnResponse, ModifyResponse, PartialAttribute, ProtocolOp, ResultCode, SearchResultDone,
    SearchResultEntry, SearchResultReference,
};

use super::paged::{self, PAGED_RESULTS_OID, Page};

use crate::model::Attribute;

/// Builds the `LdapResult` shared by all responses.
pub fn ldap_result(code: ResultCode, diagnostic: &str) -> LdapResult {
    LdapResult::new(code, LdapDn::from(""), diagnostic.into())
}

pub fn bind_response(message_id: MessageId, code: ResultCode, diagnostic: &str) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::BindResponse(BindResponse::new(
            code,
            LdapDn::from(""),
            diagnostic.into(),
            None,
            None,
        )),
    )
}

pub fn search_result_entry(
    message_id: MessageId,
    dn: &str,
    attributes: &[Attribute],
) -> LdapMessage {
    let attributes = attributes
        .iter()
        .map(|attribute| {
            PartialAttribute::new(
                AttributeDescription::from(attribute.name.clone()),
                SetOf::from_vec(
                    attribute
                        .values
                        .iter()
                        .map(|value| AttributeValue::from(value.as_bytes()))
                        .collect(),
                ),
            )
        })
        .collect();

    LdapMessage::new(
        message_id,
        ProtocolOp::SearchResEntry(SearchResultEntry::new(LdapDn::from(dn), attributes)),
    )
}

pub fn search_done(message_id: MessageId, code: ResultCode, diagnostic: &str) -> LdapMessage {
    search_done_with_controls(message_id, code, diagnostic, Vec::new())
}

pub fn search_done_with_controls(
    message_id: MessageId,
    code: ResultCode,
    diagnostic: &str,
    controls: Controls,
) -> LdapMessage {
    let mut message = LdapMessage::new(
        message_id,
        ProtocolOp::SearchResDone(SearchResultDone(ldap_result(code, diagnostic))),
    );
    if !controls.is_empty() {
        message.controls = Some(controls);
    }
    message
}

pub fn search_reference(message_id: MessageId, uris: Vec<String>) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::SearchResRef(SearchResultReference(
            uris.into_iter().map(LdapDn::from).collect(),
        )),
    )
}

pub fn compare_response(message_id: MessageId, code: ResultCode, diagnostic: &str) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::CompareResponse(CompareResponse(ldap_result(code, diagnostic))),
    )
}

pub fn modify_response(message_id: MessageId, code: ResultCode, diagnostic: &str) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::ModifyResponse(ModifyResponse(ldap_result(code, diagnostic))),
    )
}

pub fn add_response(message_id: MessageId, code: ResultCode, diagnostic: &str) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::AddResponse(AddResponse(ldap_result(code, diagnostic))),
    )
}

pub fn del_response(message_id: MessageId, code: ResultCode, diagnostic: &str) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::DelResponse(DelResponse(ldap_result(code, diagnostic))),
    )
}

pub fn modify_dn_response(
    message_id: MessageId,
    code: ResultCode,
    diagnostic: &str,
) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::ModDnResponse(ModifyDnResponse(ldap_result(code, diagnostic))),
    )
}

pub fn extended_response(
    message_id: MessageId,
    code: ResultCode,
    diagnostic: &str,
    response_name: Option<&str>,
) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::ExtendedResp(ExtendedResponse {
            result_code: code,
            matched_dn: LdapDn::from(""),
            diagnostic_message: diagnostic.into(),
            referral: None,
            response_name: response_name.map(|name| LdapOid::from(name.as_bytes())),
            response_value: None,
        }),
    )
}

/// Control that reports the page the client just received (RFC 2696).
///
/// The size field of a response is zero: this server does not fix the page size.
pub fn paged_results_control(page: &Page) -> Control {
    Control::new(
        LdapOid::from(PAGED_RESULTS_OID.as_bytes()),
        false,
        Some(OctetString::from(paged::encode(page))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_carries_code_and_diagnostic_message() {
        let message = search_done(7, ResultCode::UnwillingToPerform, "not supported");

        assert_eq!(message.message_id, 7);
        match &message.protocol_op {
            ProtocolOp::SearchResDone(done) => {
                assert_eq!(done.0.result_code, ResultCode::UnwillingToPerform);
                assert_eq!(done.0.diagnostic_message.0, "not supported");
                assert_eq!(done.0.matched_dn.0, "");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn bind_response_has_no_sasl_credentials() {
        let message = bind_response(1, ResultCode::Success, "");

        match &message.protocol_op {
            ProtocolOp::BindResponse(response) => {
                assert_eq!(response.result_code, ResultCode::Success);
                assert!(response.server_sasl_creds.is_none());
                assert!(response.referral.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn search_entry_carries_every_attribute_value() {
        let attributes = vec![
            Attribute::new("cn", vec!["admin".to_string()]),
            Attribute::new(
                "memberOf",
                vec!["group_a".to_string(), "group_b".to_string()],
            ),
        ];

        let message = search_result_entry(3, "cn=admin,ou=users,dc=example,dc=com", &attributes);

        match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => {
                assert_eq!(entry.object_name.0, "cn=admin,ou=users,dc=example,dc=com");
                assert_eq!(entry.attributes.len(), 2);
                assert_eq!(entry.attributes[0].r#type.0, "cn");
                assert_eq!(entry.attributes[1].vals.len(), 2);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn search_done_without_controls_has_none() {
        let message = search_done(2, ResultCode::Success, "");

        assert!(
            message.controls.is_none(),
            "empty control list must stay absent"
        );
    }

    #[test]
    fn search_done_carries_controls_when_given() {
        let message = search_done_with_controls(
            4,
            ResultCode::Success,
            "",
            vec![paged_results_control(&Page::new(0, Vec::new()))],
        );

        let controls = message.controls.expect("controls");
        assert_eq!(controls.len(), 1);
    }

    #[test]
    fn paged_results_control_encodes_the_page() {
        let control = paged_results_control(&Page::new(0, Vec::new()));

        assert_eq!(control.control_type.as_ref(), b"1.2.840.113556.1.4.319");
        assert!(!control.criticality);
        let value = control.control_value.expect("control value");
        assert_eq!(value.as_ref(), &[0x30, 0x05, 0x02, 0x01, 0x00, 0x04, 0x00]);
    }

    #[test]
    fn paged_results_control_keeps_the_cookie() {
        let control = paged_results_control(&Page::new(0, b"page-2".to_vec()));
        let value = control.control_value.expect("control value");

        assert_eq!(
            value.as_ref(),
            &[
                0x30, 0x0b, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'a', b'g', b'e', b'-', b'2'
            ]
        );
    }

    #[test]
    fn unsupported_operation_responses_keep_their_own_envelope() {
        assert!(matches!(
            add_response(1, ResultCode::UnwillingToPerform, "").protocol_op,
            ProtocolOp::AddResponse(_)
        ));
        assert!(matches!(
            del_response(1, ResultCode::UnwillingToPerform, "").protocol_op,
            ProtocolOp::DelResponse(_)
        ));
        assert!(matches!(
            modify_dn_response(1, ResultCode::UnwillingToPerform, "").protocol_op,
            ProtocolOp::ModDnResponse(_)
        ));
        assert!(matches!(
            compare_response(1, ResultCode::CompareFalse, "").protocol_op,
            ProtocolOp::CompareResponse(_)
        ));
        assert!(matches!(
            modify_response(1, ResultCode::Success, "").protocol_op,
            ProtocolOp::ModifyResponse(_)
        ));
    }

    #[test]
    fn extended_response_can_carry_a_response_name() {
        let message = extended_response(
            9,
            ResultCode::ProtocolError,
            "unsupported",
            Some("1.3.6.1.4.1.4203.1.11.3"),
        );

        match &message.protocol_op {
            ProtocolOp::ExtendedResp(response) => {
                assert_eq!(
                    response
                        .response_name
                        .as_ref()
                        .map(|oid| oid.as_ref().to_vec()),
                    Some(b"1.3.6.1.4.1.4203.1.11.3".to_vec())
                );
                assert_eq!(response.diagnostic_message.0, "unsupported");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn search_reference_carries_uris() {
        let message = search_reference(5, vec!["ldap://other/dc=example,dc=com".to_string()]);

        match &message.protocol_op {
            ProtocolOp::SearchResRef(reference) => {
                assert_eq!(reference.0.len(), 1);
                assert_eq!(reference.0[0].0, "ldap://other/dc=example,dc=com");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
