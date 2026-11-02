//! Assertion control: apply the change only if the entry still looks the way the
//! client expects (RFC 4528, OID 1.3.6.1.1.12).
//!
//! The problem it solves is a race that a read-then-write cannot close: a client reads
//! an entry, decides on a change, and by the time the change arrives someone else has
//! rewritten the attribute. Without an assertion the change lands on data the client
//! never saw.
//!
//! The control carries a whole LDAP filter, not a single value, so it can express
//! "(modifyTimestamp=…)" or "(&(memberUid=ann)(!(memberUid=bob)))". When the filter
//! does not match, the operation is refused with `assertionFailed` (122) and **nothing
//! is written**.
//!
//! Criticality matters and is easy to get wrong in the dangerous direction: a client
//! that marks the assertion critical is saying "do not proceed if you cannot check
//! this". Ignoring a critical assertion would turn a safety feature into a silent
//! no-op, so an undecodable critical assertion refuses the request.

use rasn_ldap::Controls;

use crate::ldap::filter;
use crate::model::Entry;

pub const ASSERTION_OID: &str = "1.3.6.1.1.12";

/// What the client asserted, or why it could not be evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assertion {
    /// No assertion control was sent; the operation proceeds as usual.
    Absent,
    /// The entry satisfies the filter.
    Matches,
    /// The entry does not satisfy the filter.
    Failed,
    /// A critical assertion that cannot be decoded or evaluated.
    Unusable(String),
}

/// Reads the assertion control, if any, and evaluates it against `entry`.
pub fn evaluate(controls: Option<&Controls>, entry: &Entry) -> Assertion {
    let Some(controls) = controls else {
        return Assertion::Absent;
    };

    let Some(control) = controls
        .iter()
        .find(|control| control.control_type.as_ref() == ASSERTION_OID.as_bytes())
    else {
        return Assertion::Absent;
    };

    let Some(value) = control.control_value.as_ref() else {
        // A control without a value cannot carry a filter. Non-critical means the
        // client did not insist, so the change may proceed; critical means it did.
        return if control.criticality {
            Assertion::Unusable("assertion control without a value".to_string())
        } else {
            Assertion::Absent
        };
    };

    let filter: rasn_ldap::Filter = match rasn::ber::decode(value.as_ref()) {
        Ok(filter) => filter,
        Err(err) => {
            return if control.criticality {
                Assertion::Unusable(format!("cannot decode the assertion filter: {err}"))
            } else {
                Assertion::Absent
            };
        }
    };

    match filter::matches(entry.attributes(), entry.dn(), &filter) {
        Ok(true) => Assertion::Matches,
        Ok(false) => Assertion::Failed,
        Err(err) => {
            if control.criticality {
                Assertion::Unusable(format!("cannot evaluate the assertion: {err}"))
            } else {
                // A filter the server cannot evaluate is not the same as a filter that
                // did not match, but with a non-critical control the client said it
                // could live with the check being skipped, and skipping means going on.
                Assertion::Absent
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, Attributes};
    use rasn_ldap::{AttributeDescription, AttributeValueAssertion, Control};

    fn entry() -> Entry {
        Entry::new(
            "cn=ann,ou=users,dc=example,dc=com",
            Attributes::new()
                .push(Attribute::single("cn", "ann"))
                .push(Attribute::single("sn", "Doe"))
                .push(Attribute::new(
                    "memberUid",
                    vec!["ann".to_string(), "bob".to_string()],
                )),
        )
    }

    fn equality(name: &str, value: &str) -> rasn_ldap::Filter {
        rasn_ldap::Filter::EqualityMatch(AttributeValueAssertion::new(
            AttributeDescription::from(name),
            rasn::types::OctetString::from(value.as_bytes()),
        ))
    }

    fn control(filter: &rasn_ldap::Filter, critical: bool) -> Controls {
        let value = rasn::ber::encode(filter).expect("encode");
        vec![Control::new(
            ASSERTION_OID.as_bytes().to_vec().into(),
            critical,
            Some(value.into()),
        )]
    }

    #[test]
    fn no_control_means_no_assertion() {
        assert_eq!(evaluate(None, &entry()), Assertion::Absent);
        assert_eq!(evaluate(Some(&Vec::new()), &entry()), Assertion::Absent);
    }

    #[test]
    fn a_matching_assertion_passes() {
        let controls = control(&equality("cn", "ann"), true);

        assert_eq!(evaluate(Some(&controls), &entry()), Assertion::Matches);
    }

    #[test]
    fn a_non_matching_assertion_fails() {
        let controls = control(&equality("cn", "bob"), true);

        assert_eq!(evaluate(Some(&controls), &entry()), Assertion::Failed);
    }

    #[test]
    fn a_multi_valued_attribute_matches_on_any_value() {
        let controls = control(&equality("memberUid", "bob"), false);

        assert_eq!(evaluate(Some(&controls), &entry()), Assertion::Matches);
    }

    #[test]
    fn a_compound_assertion_is_evaluated_as_a_whole() {
        let filter = rasn_ldap::Filter::And(rasn::types::SetOf::from_vec(vec![
            equality("cn", "ann"),
            rasn_ldap::Filter::Not(Box::new(equality("sn", "Smith"))),
        ]));
        let controls = control(&filter, true);

        assert_eq!(evaluate(Some(&controls), &entry()), Assertion::Matches);
    }

    #[test]
    fn an_assertion_on_a_missing_attribute_fails_rather_than_erroring() {
        // `(telephoneNumber=1)` is false on an entry without the attribute, which is
        // exactly what a client asserts when it wants "only if nobody set it yet".
        let controls = control(&equality("telephoneNumber", "1"), true);

        assert_eq!(evaluate(Some(&controls), &entry()), Assertion::Failed);
    }

    #[test]
    fn other_controls_are_ignored() {
        let controls: Controls = vec![Control::new(
            "1.2.840.113556.1.4.319".as_bytes().to_vec().into(),
            true,
            None,
        )];

        assert_eq!(evaluate(Some(&controls), &entry()), Assertion::Absent);
    }

    #[test]
    fn a_critical_assertion_without_a_value_refuses() {
        let controls: Controls = vec![Control::new(
            ASSERTION_OID.as_bytes().to_vec().into(),
            true,
            None,
        )];

        assert!(matches!(
            evaluate(Some(&controls), &entry()),
            Assertion::Unusable(_)
        ));
    }

    #[test]
    fn a_non_critical_assertion_without_a_value_is_skipped() {
        let controls: Controls = vec![Control::new(
            ASSERTION_OID.as_bytes().to_vec().into(),
            false,
            None,
        )];

        assert_eq!(evaluate(Some(&controls), &entry()), Assertion::Absent);
    }

    #[test]
    fn undecodable_bytes_in_a_critical_assertion_refuse() {
        let controls: Controls = vec![Control::new(
            ASSERTION_OID.as_bytes().to_vec().into(),
            true,
            Some(vec![0xff, 0xff, 0xff].into()),
        )];

        match evaluate(Some(&controls), &entry()) {
            Assertion::Unusable(reason) => assert!(reason.contains("decode"), "{reason}"),
            other => panic!("a critical assertion that cannot be read must refuse: {other:?}"),
        }
    }

    #[test]
    fn undecodable_bytes_in_a_non_critical_assertion_are_skipped() {
        let controls: Controls = vec![Control::new(
            ASSERTION_OID.as_bytes().to_vec().into(),
            false,
            Some(vec![0xff, 0xff, 0xff].into()),
        )];

        assert_eq!(evaluate(Some(&controls), &entry()), Assertion::Absent);
    }

    #[test]
    fn a_filter_the_server_cannot_evaluate_is_reported_as_such() {
        // Approximate matching is still not implemented; a critical assertion on it must say
        // so instead of pretending it matched. `>=` used to be the example here, and stopped
        // being one when the filter learned to answer it.
        let filter = rasn_ldap::Filter::ApproxMatch(AttributeValueAssertion::new(
            AttributeDescription::from("cn"),
            rasn::types::OctetString::from("a".as_bytes()),
        ));
        let controls = control(&filter, true);

        match evaluate(Some(&controls), &entry()) {
            Assertion::Unusable(reason) => assert!(reason.contains("evaluate"), "{reason}"),
            other => panic!("expected an unusable assertion, got {other:?}"),
        }
    }

    #[test]
    fn an_ordering_filter_can_now_be_asserted_on() {
        // The counterpart: what used to be refused is answered, so an assertion on it is
        // evaluated rather than reported unusable.
        let filter = rasn_ldap::Filter::GreaterOrEqual(AttributeValueAssertion::new(
            AttributeDescription::from("cn"),
            rasn::types::OctetString::from("a".as_bytes()),
        ));
        let controls = control(&filter, true);

        match evaluate(Some(&controls), &entry()) {
            Assertion::Matches | Assertion::Failed => {}
            other => panic!("an ordering filter must be evaluated, got {other:?}"),
        }
    }
}
