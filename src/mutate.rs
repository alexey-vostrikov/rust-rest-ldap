//! Entry mutation: add, delete and replace, independent of the protocol.
//!
//! Kept apart from the LDAP handler on purpose: the rules below (what `delete` does to
//! a single-valued attribute, when a value already exists, what happens to operational
//! attributes) are testable without a request, and the handler stays a thin mapping
//! from BER to these calls.
//!
//! gorestldap supported `replace` only and found the target field by reflecting over a
//! Go struct, so a typo in the attribute name came back as "no such attribute" and a
//! multi-valued attribute could not be appended to. Here the entry is the model, the
//! three operations are the three operations, and the errors are the LDAP result
//! codes a client expects.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::model::{Attribute, Attributes, Entry};
use crate::schema::Schema;

/// Which modification to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Add the values, failing if any of them is already there.
    Add,
    /// Remove the values, or the whole attribute when none are given.
    Delete,
    /// Replace the values, or remove the attribute when none are given.
    Replace,
}

/// One requested modification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modification {
    pub op: Op,
    pub attribute: String,
    pub values: Vec<String>,
}

impl Modification {
    pub fn new(op: Op, attribute: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            op,
            attribute: attribute.into(),
            values,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MutateError {
    #[error("attribute '{0}' does not exist")]
    NoSuchAttribute(String),
    #[error("value of '{attribute}' already exists")]
    AttributeOrValueExists { attribute: String },
    #[error("attribute '{0}' is not defined by the schema")]
    UndefinedAttribute(String),
    #[error("attribute '{0}' is maintained by the server and cannot be modified")]
    NotUserModifiable(String),
    #[error("attribute '{attribute}' is single-valued but {count} values were given")]
    SingleValue { attribute: String, count: usize },
    #[error("attribute '{0}' cannot be modified")]
    Protected(String),
}

impl MutateError {
    /// The name of the offending attribute, for messages that must name it.
    pub fn attribute(&self) -> &str {
        match self {
            MutateError::NoSuchAttribute(name)
            | MutateError::UndefinedAttribute(name)
            | MutateError::NotUserModifiable(name)
            | MutateError::Protected(name) => name,
            MutateError::AttributeOrValueExists { attribute }
            | MutateError::SingleValue { attribute, .. } => attribute,
        }
    }
}

/// Applies `modifications` in order and returns the new entry.
///
/// The original entry is left untouched: a rejected set of changes must not leave a
/// half-modified entry. The caller persists the result, so the whole list is one
/// unit of work.
///
/// `schema` supplies `SINGLE-VALUE`; with `None` no attribute is treated as single
/// valued, which is what a running server with schema checking off must do.
pub fn apply(
    entry: &Entry,
    modifications: &[Modification],
    schema: Option<&Schema>,
) -> Result<Entry, MutateError> {
    let mut attributes = entry.attributes().clone();

    for modification in modifications {
        apply_one(&mut attributes, modification, schema)?;
    }

    Ok(Entry::new(entry.dn(), attributes))
}

fn apply_one(
    attributes: &mut Attributes,
    modification: &Modification,
    schema: Option<&Schema>,
) -> Result<(), MutateError> {
    let name = modification.attribute.to_lowercase();
    check_editable(attributes, modification)?;

    match modification.op {
        Op::Add => add(attributes, modification, &name, schema),
        Op::Delete => delete(attributes, modification, &name),
        Op::Replace => replace(attributes, modification, &name, schema),
    }
}

/// True when the schema says this attribute holds one value.
fn single_valued(schema: Option<&Schema>, name: &str) -> bool {
    schema
        .and_then(|schema| schema.resolved(name))
        .is_some_and(|attribute| attribute.single_value)
}

fn add(
    attributes: &mut Attributes,
    modification: &Modification,
    name: &str,
    schema: Option<&Schema>,
) -> Result<(), MutateError> {
    if modification.values.is_empty() {
        // RFC 4511 §4.6: an add change with no values is a protocol error, which the
        // server reports as a value already there being absent — the honest answer is
        // that nothing was added.
        return Err(MutateError::NoSuchAttribute(modification.attribute.clone()));
    }

    let existing = attributes.get(name);
    if let Some(attribute) = existing {
        let before = attribute.values.len();
        let already: Vec<&String> = modification
            .values
            .iter()
            .filter(|value| contains(attribute, value))
            .collect();
        if !already.is_empty() {
            return Err(MutateError::AttributeOrValueExists {
                attribute: modification.attribute.clone(),
            });
        }
        if single_valued(schema, name) && before + modification.values.len() > 1 {
            return Err(MutateError::SingleValue {
                attribute: modification.attribute.clone(),
                count: before + modification.values.len(),
            });
        }
    }

    let mut values: Vec<String> = existing
        .map(|attribute| attribute.values.to_vec())
        .unwrap_or_default();
    values.extend(modification.values.iter().cloned());

    let spelling = spelling(existing, modification);
    set_values(attributes, &spelling, values, mutation_flags(existing))
}

fn delete(
    attributes: &mut Attributes,
    modification: &Modification,
    name: &str,
) -> Result<(), MutateError> {
    let Some(attribute) = attributes.get(name) else {
        return Err(MutateError::NoSuchAttribute(modification.attribute.clone()));
    };

    let remaining: Vec<String> = if modification.values.is_empty() {
        // No values means the whole attribute goes.
        Vec::new()
    } else {
        for value in &modification.values {
            if !contains(attribute, value) {
                return Err(MutateError::NoSuchAttribute(modification.attribute.clone()));
            }
        }
        attribute
            .values
            .iter()
            .filter(|value| {
                !modification
                    .values
                    .iter()
                    .any(|removed| equal(value, removed, attribute))
            })
            .cloned()
            .collect()
    };

    if remaining.is_empty() {
        remove(attributes, name)
    } else {
        let spelling = spelling(Some(attribute), modification);
        set_values(
            attributes,
            &spelling,
            remaining,
            mutation_flags(Some(attribute)),
        )
    }
}

fn replace(
    attributes: &mut Attributes,
    modification: &Modification,
    name: &str,
    schema: Option<&Schema>,
) -> Result<(), MutateError> {
    if modification.values.is_empty() {
        // An empty replace removes the attribute, RFC 4511 §4.6.
        return match attributes.get(name) {
            Some(_) => remove(attributes, name),
            None => Ok(()),
        };
    }

    let existing = attributes.get(name);
    let mut seen = BTreeSet::new();
    for value in &modification.values {
        let key = fold(
            value,
            existing.map(|attribute| attribute.flags.case_sensitive),
        );
        if !seen.insert(key) {
            return Err(MutateError::AttributeOrValueExists {
                attribute: modification.attribute.clone(),
            });
        }
    }

    if single_valued(schema, name) && modification.values.len() > 1 {
        return Err(MutateError::SingleValue {
            attribute: modification.attribute.clone(),
            count: modification.values.len(),
        });
    }

    let spelling = spelling(existing, modification);
    set_values(
        attributes,
        &spelling,
        modification.values.clone(),
        mutation_flags(existing),
    )
}

/// Refuses changes to attributes the server owns or has hidden.
fn check_editable(attributes: &Attributes, modification: &Modification) -> Result<(), MutateError> {
    let name = modification.attribute.to_lowercase();

    if name == "entrydn" {
        return Err(MutateError::Protected(modification.attribute.clone()));
    }

    let Some(attribute) = attributes.get(&name) else {
        return Ok(());
    };

    // A hidden attribute must be indistinguishable from a missing one: saying "you
    // may not modify ldapAdmin" would confirm it is there.
    if attribute.flags.internal {
        return Err(MutateError::NoSuchAttribute(modification.attribute.clone()));
    }
    if attribute.flags.operational {
        return Err(MutateError::NotUserModifiable(
            modification.attribute.clone(),
        ));
    }

    Ok(())
}

/// The name to store: the entry's own spelling when the attribute exists, so a write
/// does not rename what it touches; the client's spelling for a new attribute.
fn spelling(existing: Option<&Attribute>, modification: &Modification) -> String {
    existing
        .map(|attribute| attribute.name.to_string())
        .unwrap_or_else(|| modification.attribute.clone())
}

fn mutation_flags(existing: Option<&Attribute>) -> Flags {
    existing
        .map(|attribute| Flags {
            case_sensitive: attribute.flags.case_sensitive,
            sensitive: attribute.flags.sensitive,
            operational: attribute.flags.operational,
            internal: attribute.flags.internal,
        })
        .unwrap_or_default()
}

/// The flags a modified attribute keeps: the stored ones, not the ones guessed from
/// the name.
#[derive(Clone, Copy, Default)]
struct Flags {
    case_sensitive: bool,
    sensitive: bool,
    operational: bool,
    internal: bool,
}

/// Stores `values` under `spelling`.
///
/// The lookup key is lowercased but the stored name is not: a directory that renames
/// `memberUid` to `memberuid` on every write hands the client back something it never
/// sent, and LDIF that no longer matches the schema file it came from.
fn set_values(
    attributes: &mut Attributes,
    spelling: &str,
    values: Vec<String>,
    flags: Flags,
) -> Result<(), MutateError> {
    let mut attribute = Attribute::new(spelling, values);
    attribute.flags.case_sensitive = flags.case_sensitive;
    attribute.flags.sensitive = flags.sensitive;
    attribute.flags.operational = flags.operational;
    attribute.flags.internal = flags.internal;

    *attributes = attributes.clone().replace(attribute);
    Ok(())
}

fn remove(attributes: &mut Attributes, name: &str) -> Result<(), MutateError> {
    if attributes.get(name).is_none() {
        return Err(MutateError::NoSuchAttribute(name.to_string()));
    }
    *attributes = attributes.clone().without(name);
    Ok(())
}

fn contains(attribute: &Attribute, value: &str) -> bool {
    attribute
        .values
        .iter()
        .any(|candidate| equal(candidate, value, attribute))
}

fn equal(left: &str, right: &str, attribute: &Attribute) -> bool {
    if attribute.flags.case_sensitive {
        return left == right;
    }
    left.eq_ignore_ascii_case(right) || left.to_lowercase() == right.to_lowercase()
}

fn fold(value: &str, case_sensitive: Option<bool>) -> String {
    if case_sensitive.unwrap_or(false) {
        value.to_string()
    } else {
        value.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        let attributes = Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "inetOrgPerson".to_string()],
            ))
            .push(Attribute::single("cn", "ann"))
            .push(Attribute::single("sn", "Doe"))
            .push(Attribute::new(
                "mail",
                vec!["ann@example.com".to_string(), "a@example.com".to_string()],
            ))
            .push(
                // The mapping sets both flags for a password; the fixture must match
                // it or the test proves the wrong thing.
                Attribute::new("userPassword", vec!["{SSHA}AbC".to_string()])
                    .case_sensitive()
                    .sensitive(),
            )
            // SINGLE-VALUE in the core schema, so the single-value rule has something
            // real to check against instead of a flag the model invented.
            .push(Attribute::single("uidNumber", "1000"));
        Entry::new("cn=ann,ou=users,dc=example,dc=com", attributes)
    }

    fn schema() -> crate::schema::Schema {
        crate::schema::Schema::core()
    }

    fn modify(modifications: &[Modification]) -> Result<Entry, MutateError> {
        apply(&entry(), modifications, Some(&schema()))
    }

    fn values(result: &Result<Entry, MutateError>, name: &str) -> Option<Vec<String>> {
        result
            .as_ref()
            .ok()
            .and_then(|entry| entry.attributes().get(name))
            .map(|attribute| attribute.values.to_vec())
    }

    #[test]
    fn replace_sets_the_values() {
        let result = modify(&[Modification::new(
            Op::Replace,
            "mail",
            vec!["new@example.com".to_string()],
        )]);

        assert_eq!(
            values(&result, "mail"),
            Some(vec!["new@example.com".to_string()])
        );
    }

    #[test]
    fn replace_with_no_values_removes_the_attribute() {
        let result = modify(&[Modification::new(Op::Replace, "mail", vec![])]);

        assert!(result.expect("modified").attributes().get("mail").is_none());
    }

    #[test]
    fn replace_of_a_missing_attribute_with_no_values_is_a_no_op() {
        let result = modify(&[Modification::new(Op::Replace, "telephoneNumber", vec![])]);

        assert_eq!(result.expect("modified"), entry());
    }

    #[test]
    fn add_appends_to_a_multi_valued_attribute() {
        let result = modify(&[Modification::new(
            Op::Add,
            "mail",
            vec!["third@example.com".to_string()],
        )]);

        assert_eq!(
            values(&result, "mail"),
            Some(vec![
                "ann@example.com".to_string(),
                "a@example.com".to_string(),
                "third@example.com".to_string()
            ])
        );
    }

    #[test]
    fn add_creates_a_missing_attribute() {
        let result = modify(&[Modification::new(
            Op::Add,
            "telephoneNumber",
            vec!["+7 495 000-00-00".to_string()],
        )]);

        assert_eq!(
            values(&result, "telephoneNumber"),
            Some(vec!["+7 495 000-00-00".to_string()])
        );
    }

    #[test]
    fn adding_a_value_that_exists_is_refused() {
        let error = modify(&[Modification::new(
            Op::Add,
            "mail",
            vec!["ANN@example.com".to_string()],
        )])
        .expect_err("must fail");

        assert_eq!(
            error,
            MutateError::AttributeOrValueExists {
                attribute: "mail".to_string()
            },
            "mail folds case, so ANN@example.com is already there"
        );
    }

    #[test]
    fn adding_to_a_single_valued_attribute_that_has_a_value_is_refused() {
        let error = modify(&[Modification::new(
            Op::Add,
            "uidNumber",
            vec!["1001".to_string()],
        )])
        .expect_err("must fail");

        assert!(
            matches!(error, MutateError::SingleValue { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn delete_removes_the_named_values() {
        let result = modify(&[Modification::new(
            Op::Delete,
            "mail",
            vec!["a@example.com".to_string()],
        )]);

        assert_eq!(
            values(&result, "mail"),
            Some(vec!["ann@example.com".to_string()])
        );
    }

    #[test]
    fn delete_with_no_values_removes_the_attribute() {
        let result = modify(&[Modification::new(Op::Delete, "mail", vec![])]);

        assert!(result.expect("modified").attributes().get("mail").is_none());
    }

    #[test]
    fn deleting_the_last_value_removes_the_attribute() {
        let result = modify(&[Modification::new(
            Op::Delete,
            "mail",
            vec!["ann@example.com".to_string(), "a@example.com".to_string()],
        )]);

        assert!(result.expect("modified").attributes().get("mail").is_none());
    }

    #[test]
    fn deleting_a_missing_attribute_is_no_such_attribute() {
        let error = modify(&[Modification::new(
            Op::Delete,
            "telephoneNumber",
            vec!["1".to_string()],
        )])
        .expect_err("must fail");

        assert_eq!(
            error,
            MutateError::NoSuchAttribute("telephoneNumber".to_string())
        );
    }

    #[test]
    fn deleting_a_value_that_is_not_there_is_no_such_attribute() {
        let error = modify(&[Modification::new(
            Op::Delete,
            "mail",
            vec!["nope".to_string()],
        )])
        .expect_err("must fail");

        assert_eq!(error, MutateError::NoSuchAttribute("mail".to_string()));
    }

    #[test]
    fn a_written_attribute_keeps_its_spelling() {
        // Live check found this: storing the lowercased lookup key renamed
        // `memberUid` to `memberuid`, so the client got back a name it never sent.
        let result = modify(&[Modification::new(
            Op::Add,
            "memberUid",
            vec!["bob".to_string()],
        )]);

        // The attribute is not in the fixture, so the client's spelling is used.
        assert_eq!(
            result
                .as_ref()
                .ok()
                .and_then(|entry| entry.attributes().get("memberUid"))
                .map(|attribute| attribute.name.to_string()),
            Some("memberUid".to_string())
        );

        let result = modify(&[Modification::new(
            Op::Replace,
            "memberuid",
            vec!["admin".to_string()],
        )]);
        assert!(
            result.is_ok(),
            "a differently cased request still matches: {result:?}"
        );
    }

    #[test]
    fn an_existing_attribute_keeps_the_spelling_the_entry_had() {
        let mut attributes = Attributes::new();
        attributes = attributes.push(Attribute::new("memberUid", vec!["admin".to_string()]));
        let entry = Entry::new("cn=group_a,ou=groups,dc=example,dc=com", attributes);

        let modified = apply(
            &entry,
            &[Modification::new(
                Op::Add,
                "memberuid",
                vec!["alice".to_string()],
            )],
            Some(&schema()),
        )
        .expect("modified");

        let attribute = modified.attributes().get("memberUid").expect("memberUid");
        assert_eq!(
            attribute.name.to_string(),
            "memberUid",
            "a write must not rename what it touches"
        );
        assert_eq!(
            attribute.values.to_vec(),
            vec!["admin".to_string(), "alice".to_string()]
        );
    }

    #[test]
    fn the_password_keeps_its_case_sensitive_flag() {
        let result = modify(&[Modification::new(
            Op::Replace,
            "userPassword",
            vec!["{SSHA}New".to_string()],
        )])
        .expect("modified");

        let password = result.attributes().get("userPassword").expect("password");
        assert!(
            password.flags.case_sensitive,
            "a rewritten hash stays exact"
        );
        assert!(password.flags.sensitive, "and stays hidden from *");
    }

    #[test]
    fn case_sensitive_values_are_compared_exactly() {
        let error = modify(&[Modification::new(
            Op::Delete,
            "userPassword",
            vec!["{ssha}abc".to_string()],
        )])
        .expect_err("must fail");

        assert_eq!(
            error,
            MutateError::NoSuchAttribute("userPassword".to_string()),
            "a hash is not case-insensitive"
        );
    }

    #[test]
    fn operational_attributes_cannot_be_modified() {
        let mut attributes = Attributes::new();
        attributes = attributes.push(Attribute::single("entryUUID", "1234").operational());
        let entry = Entry::new("cn=x,dc=example,dc=com", attributes);

        let error = apply(
            &entry,
            &[Modification::new(
                Op::Replace,
                "entryUUID",
                vec!["5678".to_string()],
            )],
            Some(&schema()),
        )
        .expect_err("must fail");

        assert_eq!(
            error,
            MutateError::NotUserModifiable("entryUUID".to_string())
        );
    }

    #[test]
    fn a_hidden_attribute_is_indistinguishable_from_a_missing_one() {
        let mut attributes = Attributes::new();
        attributes =
            attributes.push(Attribute::new("ldapAdmin", vec!["true".to_string()]).internal());
        let entry = Entry::new("cn=x,dc=example,dc=com", attributes);

        let error = apply(
            &entry,
            &[Modification::new(Op::Delete, "ldapAdmin", vec![])],
            Some(&schema()),
        )
        .expect_err("must fail");

        assert_eq!(error, MutateError::NoSuchAttribute("ldapAdmin".to_string()));
    }

    #[test]
    fn entry_dn_is_protected() {
        let error = modify(&[Modification::new(
            Op::Replace,
            "entryDN",
            vec!["cn=other".to_string()],
        )])
        .expect_err("must fail");

        assert_eq!(error, MutateError::Protected("entryDN".to_string()));
    }

    #[test]
    fn a_rejected_set_leaves_the_entry_untouched() {
        let original = entry();
        let result = apply(
            &original,
            &[
                Modification::new(Op::Replace, "sn", vec!["Changed".to_string()]),
                Modification::new(Op::Delete, "telephoneNumber", vec![]),
            ],
            Some(&schema()),
        );

        assert!(result.is_err(), "the second change must fail");
        assert_eq!(
            original.attributes().get("sn").map(|a| a.values.to_vec()),
            Some(vec!["Doe".to_string()]),
            "the first change must not have been applied"
        );
    }

    #[test]
    fn several_changes_apply_in_order() {
        let result = modify(&[
            Modification::new(Op::Delete, "mail", vec![]),
            Modification::new(Op::Add, "mail", vec!["fresh@example.com".to_string()]),
            Modification::new(Op::Add, "mail", vec!["second@example.com".to_string()]),
        ]);

        assert_eq!(
            values(&result, "mail"),
            Some(vec![
                "fresh@example.com".to_string(),
                "second@example.com".to_string()
            ])
        );
    }

    #[test]
    fn the_dn_is_carried_over() {
        let result = modify(&[Modification::new(
            Op::Replace,
            "sn",
            vec!["Changed".to_string()],
        )])
        .expect("modified");

        assert_eq!(result.dn(), entry().dn());
    }

    #[test]
    fn replacing_with_a_duplicate_value_is_refused() {
        let error = modify(&[Modification::new(
            Op::Replace,
            "mail",
            vec!["a@example.com".to_string(), "A@example.com".to_string()],
        )])
        .expect_err("must fail");

        assert!(matches!(error, MutateError::AttributeOrValueExists { .. }));
    }
}
