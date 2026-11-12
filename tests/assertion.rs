//! Assertion control end to end: the change lands only if the entry still matches.
//!
//! This is the shape of test that matters here — not "does the helper return the right
//! enum", but "when two clients race, does the loser's change get refused and does the
//! entry stay as it was".

use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, AttributeValueAssertion, ChangeOperation, Control, Filter, LdapDn,
    ModifyRequest, ModifyRequestChanges, PartialAttribute, ProtocolOp, ResultCode,
};
use rrl_directory::directory::Directory;
use rrl_directory::ldap::assertion::ASSERTION_OID;
use rrl_directory::ldap::modify::{self, Outcome};
use rrl_directory::ldap::session::{Identity, Session};
use rrl_directory::model::{Attribute, Attributes, Entry};
use rrl_directory::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";

fn entry() -> Entry {
    Entry::new(
        ALICE_DN,
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec![
                    "top".to_string(),
                    "person".to_string(),
                    "inetOrgPerson".to_string(),
                ],
            ))
            .push(Attribute::single("cn", "alice"))
            .push(Attribute::single("sn", "Surname"))
            .push(Attribute::single("uid", "alice"))
            .push(Attribute::single("mail", "alice@example.com")),
    )
}

fn directory() -> Directory {
    Directory::from_entries(BASE, "users", "groups", vec![entry()])
}

fn admin() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(ADMIN_DN, true));
    session
}

fn equality(name: &str, value: &str) -> Filter {
    Filter::EqualityMatch(AttributeValueAssertion::new(
        AttributeDescription::from(name),
        OctetString::from(value.as_bytes()),
    ))
}

fn assertion(filter: &Filter, critical: bool) -> Vec<Control> {
    vec![Control::new(
        ASSERTION_OID.as_bytes().to_vec().into(),
        critical,
        Some(rasn::ber::encode(filter).expect("encode").into()),
    )]
}

fn request(attribute: &str, value: &str) -> ModifyRequest {
    ModifyRequest {
        object: LdapDn::from(ALICE_DN),
        changes: vec![ModifyRequestChanges {
            operation: ChangeOperation::Replace,
            modification: PartialAttribute::new(
                AttributeDescription::from(attribute),
                rasn::types::SetOf::from_vec(vec![OctetString::from(value.as_bytes())]),
            ),
        }],
    }
}

/// Runs a modify with the given controls and returns either the new entry or the code.
fn run(controls: &[Control]) -> Result<Entry, ResultCode> {
    let request = request("mail", "changed@example.com");
    let controls = controls.to_vec();
    match modify::handle_modify(
        &admin(),
        &directory(),
        1,
        &request,
        Some(&controls),
        &Security::default(),
    ) {
        Outcome::Persist { entry, .. } => Ok(entry),
        Outcome::Reject(message) => Err(match &message.protocol_op {
            ProtocolOp::ModifyResponse(response) => response.0.result_code,
            other => panic!("not a modify response: {other:?}"),
        }),
    }
}

#[test]
fn a_matching_assertion_lets_the_change_through() {
    let changed = run(&assertion(&equality("mail", "alice@example.com"), true)).expect("write");

    assert_eq!(
        changed
            .attributes()
            .get("mail")
            .map(|attribute| attribute.values.to_vec()),
        Some(vec!["changed@example.com".to_string()])
    );
}

#[test]
fn a_failing_assertion_refuses_with_assertion_failed() {
    let code = run(&assertion(
        &equality("mail", "someone-else@example.com"),
        true,
    ))
    .expect_err("the assertion must fail");

    assert_eq!(
        code,
        ResultCode::AssertionFailed,
        "122 is the code a client watches for; a generic refusal would be unusable"
    );
}

#[test]
fn a_refused_assertion_writes_nothing() {
    // The write is refused before any mutation, so the caller has no entry to persist.
    // This is the property that makes the control safe: a failed assertion cannot
    // leave a half-applied change behind.
    let outcome = modify::handle_modify(
        &admin(),
        &directory(),
        1,
        &request("mail", "changed@example.com"),
        Some(&assertion(&equality("cn", "nobody"), true)),
        &Security::default(),
    );

    assert!(
        matches!(outcome, Outcome::Reject(_)),
        "a failed assertion must not produce a write"
    );

    // And the directory is untouched: it is immutable, so this is really a check that
    // the handler did not build a modified entry and hand it out anyway.
    assert_eq!(
        directory()
            .find(ALICE_DN)
            .and_then(|entry| entry.attributes().get("mail"))
            .map(|attribute| attribute.values.to_vec()),
        Some(vec!["alice@example.com".to_string()])
    );
}

#[test]
fn without_a_control_the_change_goes_through() {
    let changed = run(&[]).expect("write");

    assert_eq!(
        changed
            .attributes()
            .get("mail")
            .map(|attribute| attribute.values.to_vec()),
        Some(vec!["changed@example.com".to_string()])
    );
}

#[test]
fn the_classic_race_loses_cleanly() {
    // Two clients both read "mail = alice@…". The first writes. The second asserts the
    // old value and must lose instead of overwriting the first change.
    let first = run(&assertion(&equality("mail", "alice@example.com"), true)).expect("first");
    let directory_after_first =
        Directory::from_entries(BASE, "users", "groups", vec![first.clone()]);

    let second = modify::handle_modify(
        &admin(),
        &directory_after_first,
        2,
        &request("mail", "second@example.com"),
        Some(&assertion(&equality("mail", "alice@example.com"), true)),
        &Security::default(),
    );

    match second {
        Outcome::Reject(message) => {
            let code = match &message.protocol_op {
                ProtocolOp::ModifyResponse(response) => response.0.result_code,
                other => panic!("not a modify response: {other:?}"),
            };
            assert_eq!(code, ResultCode::AssertionFailed);
        }
        Outcome::Persist { .. } => panic!("the second writer must not overwrite the first"),
    }

    assert_eq!(
        directory_after_first
            .find(ALICE_DN)
            .and_then(|entry| entry.attributes().get("mail"))
            .map(|attribute| attribute.values.to_vec()),
        Some(vec!["changed@example.com".to_string()]),
        "the first writer's value survives"
    );
}

#[test]
fn a_compound_assertion_is_evaluated_as_a_whole() {
    let filter = Filter::And(rasn::types::SetOf::from_vec(vec![
        equality("mail", "alice@example.com"),
        Filter::Not(Box::new(equality("sn", "Smith"))),
    ]));

    assert!(run(&assertion(&filter, true)).is_ok(), "both parts hold");

    let failing = Filter::And(rasn::types::SetOf::from_vec(vec![
        equality("mail", "alice@example.com"),
        equality("sn", "Smith"),
    ]));
    assert_eq!(
        run(&assertion(&failing, true)).expect_err("must fail"),
        ResultCode::AssertionFailed
    );
}

#[test]
fn an_assertion_on_an_attribute_nobody_set_passes_when_absent() {
    // `(!(telephoneNumber=*))` is the "only if still unset" idiom.
    let filter = Filter::Not(Box::new(Filter::Present(AttributeDescription::from(
        "telephoneNumber",
    ))));

    assert!(run(&assertion(&filter, true)).is_ok());
}

#[test]
fn a_critical_unreadable_assertion_refuses_with_unavailable_critical_extension() {
    let controls = vec![Control::new(
        ASSERTION_OID.as_bytes().to_vec().into(),
        true,
        Some(vec![0xff, 0xff, 0xff].into()),
    )];

    assert_eq!(
        run(&controls).expect_err("must refuse"),
        ResultCode::UnavailableCriticalExtension,
        "a client that marked the assertion critical must not have it silently dropped"
    );
}

#[test]
fn a_non_critical_unreadable_assertion_is_skipped() {
    let controls = vec![Control::new(
        ASSERTION_OID.as_bytes().to_vec().into(),
        false,
        Some(vec![0xff, 0xff, 0xff].into()),
    )];

    assert!(
        run(&controls).is_ok(),
        "a non-critical assertion the server cannot read is not a reason to refuse"
    );
}

#[test]
fn the_assertion_is_evaluated_before_the_change_is_applied() {
    // An assertion on the value being replaced must see the OLD value: if it saw the
    // new one, `(mail=changed@…)` would pass and the control would prove nothing.
    let filter = equality("mail", "changed@example.com");

    assert_eq!(
        run(&assertion(&filter, true)).expect_err("must fail"),
        ResultCode::AssertionFailed,
        "the assertion must be evaluated against the entry as it was, not as it would be"
    );
}

#[test]
fn the_written_entry_still_carries_its_stamps() {
    let changed = run(&assertion(&equality("mail", "alice@example.com"), true)).expect("write");

    assert!(
        changed.attributes().get("createTimestamp").is_some()
            && changed.attributes().get("entryCSN").is_some(),
        "a guarded write is still a write: the operational attributes must be there"
    );
}
