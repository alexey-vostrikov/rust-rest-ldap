//! `compare`: one value in, one verdict out, and nothing leaked on the way.
//!
//! The interesting cases are the refusals, not the happy path. A compare that answered
//! for an attribute the requester cannot read would turn the ACL into a slow leak: ask
//! about a hash value, get `compareFalse`, ask again with one more character.

use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, AttributeValueAssertion, CompareRequest, LdapDn, LdapMessage, ProtocolOp,
    ResultCode,
};
use rrl_directory::acl::Requester;
use rrl_directory::directory::Directory;
use rrl_directory::ldap::compare::handle_compare;
use rrl_directory::ldap::session::{Identity, Session};
use rrl_directory::model::{Attribute, Attributes, Entry};
use rrl_directory::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";
const BOB_DN: &str = "cn=bob,ou=users,dc=example,dc=com";

const ALICE_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g";

fn entry(cn: &str) -> Entry {
    Entry::new(
        format!("cn={cn},ou=users,{BASE}"),
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec![
                    "top".to_string(),
                    "person".to_string(),
                    "inetOrgPerson".to_string(),
                ],
            ))
            .push(Attribute::single("cn", cn))
            .push(Attribute::single("sn", "Surname"))
            .push(Attribute::single("uid", cn))
            .push(Attribute::single("mail", &format!("{cn}@example.com")))
            .push(
                Attribute::new("userPassword", vec![ALICE_HASH.to_string()])
                    .case_sensitive()
                    .sensitive(),
            )
            .push(Attribute::new(
                "memberOf",
                vec!["admins".to_string(), "users".to_string()],
            )),
    )
}

fn directory() -> Directory {
    Directory::from_entries(BASE, "users", "groups", vec![entry("alice"), entry("bob")])
}

fn admin() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(ADMIN_DN, true));
    session
}

fn alice() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(ALICE_DN, false));
    session
}

fn anonymous() -> Session {
    Session::new()
}

fn compare(session: &Session, dn: &str, attribute: &str, value: &str) -> ResultCode {
    let request = CompareRequest {
        entry: LdapDn::from(dn),
        ava: AttributeValueAssertion::new(
            AttributeDescription::from(attribute),
            OctetString::from(value.as_bytes()),
        ),
    };

    let message: LdapMessage =
        handle_compare(session, &directory(), 1, &request, &Security::default());

    match &message.protocol_op {
        ProtocolOp::CompareResponse(response) => response.0.result_code,
        other => panic!("not a compare response: {other:?}"),
    }
}

#[test]
fn a_matching_value_is_compare_true() {
    assert_eq!(
        compare(&admin(), ALICE_DN, "cn", "alice"),
        ResultCode::CompareTrue
    );
}

#[test]
fn a_different_value_is_compare_false() {
    assert_eq!(
        compare(&admin(), ALICE_DN, "cn", "bob"),
        ResultCode::CompareFalse
    );
}

#[test]
fn a_multi_valued_attribute_matches_any_of_its_values() {
    assert_eq!(
        compare(&admin(), ALICE_DN, "memberOf", "users"),
        ResultCode::CompareTrue
    );
    assert_eq!(
        compare(&admin(), ALICE_DN, "memberOf", "admins"),
        ResultCode::CompareTrue
    );
    assert_eq!(
        compare(&admin(), ALICE_DN, "memberOf", "nobody"),
        ResultCode::CompareFalse
    );
}

#[test]
fn comparison_folds_case_for_ordinary_attributes() {
    assert_eq!(
        compare(&admin(), ALICE_DN, "mail", "ALICE@EXAMPLE.COM"),
        ResultCode::CompareTrue
    );
}

#[test]
fn a_password_hash_is_compared_exactly() {
    assert_eq!(
        compare(&admin(), ALICE_DN, "userPassword", ALICE_HASH),
        ResultCode::CompareTrue,
        "an admin may compare the hash"
    );
    assert_eq!(
        compare(
            &admin(),
            ALICE_DN,
            "userPassword",
            &ALICE_HASH.to_uppercase()
        ),
        ResultCode::CompareFalse,
        "a hash is case-sensitive even when the case differs only in the encoding"
    );
}

#[test]
fn a_user_may_compare_their_own_entry_but_not_the_password_hash() {
    assert_eq!(
        compare(&alice(), ALICE_DN, "cn", "alice"),
        ResultCode::CompareTrue
    );
    assert_eq!(
        compare(&alice(), ALICE_DN, "userPassword", ALICE_HASH),
        ResultCode::InsufficientAccessRights,
        "a self-service read does not include the hash, and neither does compare"
    );
}

#[test]
fn a_user_may_not_compare_someone_elses_entry() {
    assert_eq!(
        compare(&alice(), BOB_DN, "cn", "bob"),
        ResultCode::InsufficientAccessRights
    );
}

#[test]
fn an_anonymous_session_may_not_compare() {
    assert_eq!(
        compare(&anonymous(), ALICE_DN, "cn", "alice"),
        ResultCode::InsufficientAccessRights
    );
}

#[test]
fn a_missing_attribute_is_no_such_attribute() {
    assert_eq!(
        compare(&admin(), ALICE_DN, "telephoneNumber", "1"),
        ResultCode::NoSuchAttribute
    );
}

#[test]
fn a_missing_entry_is_no_such_object() {
    assert_eq!(
        compare(
            &admin(),
            "cn=nobody,ou=users,dc=example,dc=com",
            "cn",
            "nobody"
        ),
        ResultCode::NoSuchObject
    );
}

#[test]
fn a_broken_dn_is_invalid_dn_syntax() {
    assert_eq!(
        compare(&admin(), "cn=broken,,", "cn", "x"),
        ResultCode::InvalidDnSyntax
    );
}

#[test]
fn entry_dn_is_refused_rather_than_answered() {
    assert_eq!(
        compare(&admin(), ALICE_DN, "entryDN", ALICE_DN),
        ResultCode::UnwillingToPerform,
        "entryDN is computed, not stored, and gorestldap refused it too"
    );
}

#[test]
fn the_answer_never_carries_an_entry() {
    let request = CompareRequest {
        entry: LdapDn::from(ALICE_DN),
        ava: AttributeValueAssertion::new(
            AttributeDescription::from("cn"),
            OctetString::from("alice".as_bytes()),
        ),
    };
    let message = handle_compare(&admin(), &directory(), 1, &request, &Security::default());

    assert!(
        matches!(message.protocol_op, ProtocolOp::CompareResponse(_)),
        "a compare answers with a result, not with data: {:?}",
        message.protocol_op
    );
}

#[test]
fn access_control_is_checked_before_the_attribute_is_named() {
    // A requester with no rights must not learn whether the attribute exists: this is
    // the difference between `insufficientAccessRights` and `noSuchAttribute`.
    assert_eq!(
        compare(&anonymous(), ALICE_DN, "telephoneNumber", "1"),
        ResultCode::InsufficientAccessRights,
        "an anonymous compare of a missing attribute must not say it is missing"
    );
}

#[test]
fn the_result_matches_a_search_for_the_same_value() {
    // The compare rule and the filter rule must agree; two implementations of
    // "equal" would drift and one of them would start lying.
    let directory = directory();
    let alice_entry = directory.find(ALICE_DN).expect("alice");

    let filter = rasn_ldap::Filter::EqualityMatch(AttributeValueAssertion::new(
        AttributeDescription::from("memberOf"),
        OctetString::from("admins".as_bytes()),
    ));
    let by_filter =
        rrl_directory::ldap::filter::matches(alice_entry.attributes(), alice_entry.dn(), &filter)
            .expect("filter");

    assert_eq!(
        by_filter,
        compare(&admin(), ALICE_DN, "memberOf", "admins") == ResultCode::CompareTrue
    );
}

#[test]
fn a_read_right_is_what_decides() {
    // Pinning the mechanism, not just the outcome: the default ACL grants the same
    // rights that a search of the attribute would need.
    let directory = directory();
    let access = Security::default().acl;
    let requester = Requester::new(ALICE_DN, false);

    assert!(
        access
            .rights(&requester, &directory, ALICE_DN, Some("cn"))
            .read,
        "self-service includes ordinary attributes"
    );
    assert!(
        !access
            .rights(&requester, &directory, ALICE_DN, Some("userPassword"))
            .read,
        "and excludes the hash, which is what makes the compare refusal right"
    );
}
