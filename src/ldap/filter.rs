//! Search filter evaluation (RFC 4511 §4.5.1.7).
//!
//! Matching is case-insensitive unless the attribute is marked case sensitive
//! (`userPassword`), which is the same rule gorestldap encoded with the
//! `ldap:"case_sensitive_value"` tag. `entryDN` (RFC 5020) is answered from the
//! entry's own DN.
//!
//! Filters the server cannot evaluate are an error, not "no match": a client that
//! asked for `>=` must see `unwillingToPerform` instead of a silently empty
//! result.

use rasn_ldap::{Filter, SubstringChoice};
use thiserror::Error;

use crate::dn;
use crate::model::{Attribute, Attributes};

/// Attribute description that matches on the entry's DN instead of its values.
pub const ATTR_ENTRY_DN: &str = "entryDN";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FilterError {
    #[error("unsupported filter type '{0}'")]
    Unsupported(&'static str),
}

/// Evaluates `filter` against the entry.
pub fn matches(
    attributes: &Attributes,
    entry_dn: &str,
    filter: &Filter,
) -> Result<bool, FilterError> {
    match filter {
        Filter::And(filters) => {
            for filter in filters.iter() {
                if !matches(attributes, entry_dn, filter)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Filter::Or(filters) => {
            for filter in filters.iter() {
                if matches(attributes, entry_dn, filter)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Filter::Not(inner) => Ok(!matches(attributes, entry_dn, inner)?),
        Filter::EqualityMatch(assertion) => {
            let name = assertion.attribute_desc.0.to_lowercase();
            let value = String::from_utf8_lossy(assertion.assertion_value.as_ref()).into_owned();

            if name == "entrydn" {
                return Ok(dn::normalize(&value) == dn::normalize(entry_dn));
            }

            match attributes.get(&name) {
                Some(attribute) => Ok(attribute_matches_equality(attribute, &value)),
                None => Ok(false),
            }
        }
        Filter::Present(name) => {
            let name = name.0.to_lowercase();
            if name == "entrydn" {
                return Ok(true);
            }
            Ok(attributes.get(&name).is_some())
        }
        Filter::Substrings(substrings) => {
            let name = substrings.r#type.0.to_lowercase();
            if name == "entrydn" {
                return Ok(substring_matches(
                    &dn::normalize(entry_dn),
                    false,
                    substrings.substrings.as_slice(),
                ));
            }

            match attributes.get(&name) {
                Some(attribute) => Ok(attribute.values.iter().any(|value| {
                    substring_matches(
                        value,
                        attribute.flags.case_sensitive,
                        &substrings.substrings,
                    )
                })),
                None => Ok(false),
            }
        }
        Filter::GreaterOrEqual(_) => Err(FilterError::Unsupported("greaterOrEqual")),
        Filter::LessOrEqual(_) => Err(FilterError::Unsupported("lessOrEqual")),
        Filter::ApproxMatch(_) => Err(FilterError::Unsupported("approxMatch")),
        Filter::ExtensibleMatch(_) => Err(FilterError::Unsupported("extensibleMatch")),
        other => Err(FilterError::Unsupported(unsupported_name(other))),
    }
}

fn attribute_matches_equality(attribute: &Attribute, value: &str) -> bool {
    if attribute.flags.case_sensitive {
        return attribute.values.iter().any(|candidate| candidate == value);
    }
    let value = value.to_lowercase();
    attribute
        .values
        .iter()
        .any(|candidate| candidate.to_lowercase() == value)
}

fn substring_matches(value: &str, case_sensitive: bool, substrings: &[SubstringChoice]) -> bool {
    // Case folding happens once, on the value and on every part, so the parts are
    // compared against exactly what the client meant.
    let value = fold(value, case_sensitive);
    let mut rest: &str = &value;

    for substring in substrings {
        let (part, kind) = match substring {
            SubstringChoice::Initial(part) => (fold_bytes(part, case_sensitive), Kind::Initial),
            SubstringChoice::Any(part) => (fold_bytes(part, case_sensitive), Kind::Any),
            SubstringChoice::Final(part) => (fold_bytes(part, case_sensitive), Kind::Final),
            // Variants added by future revisions of the RFC: a part the server
            // cannot interpret must not silently match.
            _ => return false,
        };

        match kind {
            Kind::Initial => match rest.strip_prefix(part.as_str()) {
                Some(tail) => rest = tail,
                None => return false,
            },
            Kind::Any => match rest.find(part.as_str()) {
                Some(position) => rest = &rest[position + part.len()..],
                None => return false,
            },
            Kind::Final => match rest.strip_suffix(part.as_str()) {
                Some(head) => rest = head,
                None => return false,
            },
        }
    }

    true
}

#[derive(Clone, Copy)]
enum Kind {
    Initial,
    Any,
    Final,
}

fn fold(text: &str, case_sensitive: bool) -> String {
    if case_sensitive {
        text.to_string()
    } else {
        text.to_lowercase()
    }
}

fn fold_bytes(value: &rasn::types::OctetString, case_sensitive: bool) -> String {
    // Assertion values are bytes; a non-UTF-8 value simply never matches text.
    fold(&String::from_utf8_lossy(value.as_ref()), case_sensitive)
}

fn unsupported_name(filter: &Filter) -> &'static str {
    match filter {
        Filter::And(_) => "and",
        Filter::Or(_) => "or",
        Filter::Not(_) => "not",
        Filter::EqualityMatch(_) => "equalityMatch",
        Filter::Substrings(_) => "substrings",
        Filter::Present(_) => "present",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::User;

    const DN: &str = "cn=admin,ou=users,dc=example,dc=com";

    fn attributes() -> Attributes {
        let user = User {
            object_class: vec![
                "top".to_string(),
                "posixAccount".to_string(),
                "inetOrgPerson".to_string(),
            ],
            cn: "Admin".to_string(),
            uid: Some("admin".to_string()),
            mail: Some("i.petrov@example.com".to_string()),
            user_password: Some("{SSHA}rapW2TNEFWp6HxD/nfwsjcBCD8Pi3Bvj".to_string()),
            uid_number: Some(1000),
            ..User::default()
        };

        crate::mapping::gorestldap::user_entry(&user, "dc=example,dc=com", "users")
            .attributes()
            .clone()
    }

    fn equality(name: &str, value: &str) -> Filter {
        Filter::EqualityMatch(rasn_ldap::AttributeValueAssertion::new(
            rasn_ldap::AttributeDescription::from(name),
            rasn::types::OctetString::from(value.as_bytes()),
        ))
    }

    fn present(name: &str) -> Filter {
        Filter::Present(rasn_ldap::AttributeDescription::from(name))
    }

    fn substrings(name: &str, parts: Vec<SubstringChoice>) -> Filter {
        Filter::Substrings(rasn_ldap::SubstringFilter::new(
            rasn_ldap::AttributeDescription::from(name),
            parts,
        ))
    }

    fn initial(value: &str) -> SubstringChoice {
        SubstringChoice::Initial(rasn::types::OctetString::from(value.as_bytes()))
    }

    fn any(value: &str) -> SubstringChoice {
        SubstringChoice::Any(rasn::types::OctetString::from(value.as_bytes()))
    }

    fn final_part(value: &str) -> SubstringChoice {
        SubstringChoice::Final(rasn::types::OctetString::from(value.as_bytes()))
    }

    fn check(filter: &Filter) -> bool {
        matches(&attributes(), DN, filter).expect("filter must be supported")
    }

    #[test]
    fn equality_is_case_insensitive_for_names_and_values() {
        assert!(check(&equality("CN", "admin")));
        assert!(check(&equality("cn", "ADMIN")));
        assert!(!check(&equality("cn", "alice")));
    }

    #[test]
    fn equality_on_unknown_attribute_is_false() {
        assert!(!check(&equality("telephoneNumber", "123")));
    }

    #[test]
    fn equality_on_password_stays_case_sensitive() {
        assert!(check(&equality(
            "userPassword",
            "{SSHA}rapW2TNEFWp6HxD/nfwsjcBCD8Pi3Bvj"
        )));
        assert!(!check(&equality(
            "userPassword",
            "{ssha}rapw2tnefwp6hxd/nfwsjcbcd8pi3bvj"
        )));
    }

    #[test]
    fn equality_on_any_value_of_a_multi_valued_attribute() {
        assert!(check(&equality("objectClass", "inetorgperson")));
        assert!(!check(&equality("objectClass", "posixGroup")));
    }

    #[test]
    fn equality_on_entry_dn_matches_the_entry_itself() {
        assert!(check(&equality(
            "entryDN",
            "CN=Admin, OU=Users, DC=Example, DC=Com"
        )));
        assert!(!check(&equality(
            "entryDN",
            "cn=alice,ou=users,dc=example,dc=com"
        )));
    }

    #[test]
    fn present_checks_attribute_existence() {
        assert!(check(&present("mail")));
        assert!(check(&present("MAIL")));
        assert!(!check(&present("telephoneNumber")));
        assert!(check(&present("entryDN")));
    }

    #[test]
    fn object_class_present_selects_every_entry() {
        assert!(check(&present("objectClass")));
    }

    #[test]
    fn and_requires_every_part() {
        let filter = Filter::And(rasn::types::SetOf::from_vec(vec![
            present("mail"),
            equality("cn", "admin"),
        ]));
        assert!(check(&filter));

        let filter = Filter::And(rasn::types::SetOf::from_vec(vec![
            present("mail"),
            equality("cn", "alice"),
        ]));
        assert!(!check(&filter));
    }

    #[test]
    fn empty_and_is_true_and_empty_or_is_false() {
        assert!(check(&Filter::And(rasn::types::SetOf::new())));
        assert!(!check(&Filter::Or(rasn::types::SetOf::new())));
    }

    #[test]
    fn or_requires_one_part() {
        let filter = Filter::Or(rasn::types::SetOf::from_vec(vec![
            equality("cn", "alice"),
            equality("cn", "admin"),
        ]));

        assert!(check(&filter));
    }

    #[test]
    fn not_inverts_the_result() {
        assert!(check(&Filter::Not(Box::new(equality("cn", "alice")))));
        assert!(!check(&Filter::Not(Box::new(equality("cn", "admin")))));
    }

    #[test]
    fn substring_initial_final_and_any() {
        assert!(check(&substrings("cn", vec![initial("Ad")])));
        assert!(
            check(&substrings("cn", vec![initial("ad")])),
            "substring matching folds case by default"
        );
        assert!(
            !check(&substrings("cn", vec![initial("min")])),
            "initial must be a prefix"
        );
        assert!(check(&substrings("cn", vec![final_part("min")])));
        assert!(check(&substrings("cn", vec![any("dm")])));
        assert!(!check(&substrings("cn", vec![any("xx")])));
    }

    #[test]
    fn substring_initial_any_final_combination() {
        let filter = substrings(
            "mail",
            vec![initial("i."), any("petrov"), final_part(".com")],
        );

        assert!(check(&filter));
    }

    #[test]
    fn substring_final_shorter_than_value_matches_suffix() {
        assert!(check(&substrings("mail", vec![final_part("example.com")])));
        assert!(!check(&substrings("mail", vec![final_part("example.org")])));
    }

    #[test]
    fn substring_on_missing_attribute_is_false() {
        assert!(!check(&substrings("telephoneNumber", vec![any("1")])));
    }

    #[test]
    fn substring_on_entry_dn_uses_the_dn() {
        assert!(check(&substrings(
            "entryDN",
            vec![final_part("dc=example,dc=com")]
        )));
    }

    #[test]
    fn ordering_and_approximate_filters_are_reported_as_unsupported() {
        let assertion = rasn_ldap::AttributeValueAssertion::new(
            rasn_ldap::AttributeDescription::from("uidNumber"),
            rasn::types::OctetString::from(&b"999"[..]),
        );

        assert_eq!(
            matches(
                &attributes(),
                DN,
                &Filter::GreaterOrEqual(assertion.clone())
            ),
            Err(FilterError::Unsupported("greaterOrEqual"))
        );
        assert_eq!(
            matches(&attributes(), DN, &Filter::LessOrEqual(assertion.clone())),
            Err(FilterError::Unsupported("lessOrEqual"))
        );
        assert_eq!(
            matches(&attributes(), DN, &Filter::ApproxMatch(assertion)),
            Err(FilterError::Unsupported("approxMatch"))
        );
        assert_eq!(
            matches(
                &attributes(),
                DN,
                &Filter::ExtensibleMatch(rasn_ldap::MatchingRuleAssertion::new(
                    None,
                    Some(rasn_ldap::AttributeDescription::from("cn")),
                    rasn::types::OctetString::from(b"admin".as_slice()),
                    false,
                ))
            ),
            Err(FilterError::Unsupported("extensibleMatch"))
        );
    }

    #[test]
    fn numeric_values_are_compared_as_text() {
        assert!(check(&equality("uidNumber", "1000")));
        assert!(!check(&equality("uidNumber", "01000")));
    }
}
