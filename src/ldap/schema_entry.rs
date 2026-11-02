//! The subschema subentry: the schema, published over the protocol (RFC 4512 §4.2).
//!
//! A client does not have to be told the schema out of band: it reads `cn=Subschema` and
//! gets the definitions this server actually enforces. That matters more than it sounds —
//! tools like Apache Directory Studio, `ldapvi` and most web panels build their forms from
//! this entry, and a server that does not answer here looks schema-less and gets treated
//! as such.
//!
//! Two names reach it, because operators type both: `cn=Subschema` (OpenLDAP) and
//! `cn=schema` (389 DS). The answer echoes the name that was asked for, so a client that
//! compares DNs does not see a surprising one.
//!
//! The values are regenerated from the parsed schema rather than stored as the original
//! text: a client reading this gets exactly what the server enforces, and a definition
//! that was accepted with unusual spacing is published in canonical form. A test
//! re-parses the published text and checks that it produces the same definitions, which
//! is the property that makes the claim true.

use rasn_ldap::{LdapMessage, MessageId, ResultCode, SearchRequest};

use super::responses::{search_done, search_result_entry};
use crate::model::{Attribute, Attributes, Entry};
use crate::schema::Schema;

/// Names this entry answers to, lowercased.
pub const NAMES: [&str; 2] = ["cn=subschema", "cn=schema"];

/// The naming attribute value RFC 4512 gives the entry.
pub const PRIMARY_DN: &str = "cn=Subschema";

/// True when `base_object` addresses the subschema subentry.
pub fn is_schema_dn(base_object: &str) -> bool {
    let normalized = crate::dn::normalize(base_object);
    NAMES.iter().any(|name| *name == normalized)
}

/// The subentry as an ordinary entry, so search, selection and the ACL work on it
/// unchanged.
///
/// The definitions are operational attributes: a `*` search of `cn=Subschema` returns the
/// entry without them, which is what RFC 4512 requires and what surprises anyone who
/// forgets to ask for `+`.
pub fn entry(schema: &Schema) -> Entry {
    let attribute_types: Vec<String> = schema
        .attribute_types()
        .into_iter()
        .map(|attribute| attribute.definition())
        .collect();
    let object_classes: Vec<String> = schema
        .object_classes()
        .into_iter()
        .map(|class| class.definition())
        .collect();

    let mut attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec!["top".to_string(), "subschema".to_string()],
        ))
        .push(Attribute::single("cn", "Subschema"))
        .push(Attribute::new("attributeTypes", attribute_types).operational())
        .push(Attribute::new("objectClasses", object_classes).operational())
        // The syntaxes the published definitions refer to. A client that wants to render
        // a value needs them, and they are part of what a subschema subentry carries.
        .push(Attribute::new("ldapSyntaxes", syntax_names()).operational());

    // `subschemaSubentry` points at itself, as RFC 4512 §4.2 describes.
    attributes = attributes.push(Attribute::single("subschemaSubentry", PRIMARY_DN).operational());

    Entry::new(PRIMARY_DN, attributes)
}

/// The LDAP syntaxes this schema uses, in the published form.
fn syntax_names() -> Vec<String> {
    use crate::schema::Syntax;

    let syntaxes = [
        Syntax::DirectoryString,
        Syntax::Ia5String,
        Syntax::Integer,
        Syntax::Boolean,
        Syntax::OctetString,
        Syntax::DistinguishedName,
        Syntax::Oid,
        Syntax::GeneralizedTime,
    ];

    syntaxes
        .iter()
        .map(|syntax| format!("( {} DESC '{}' )", syntax.oid(), describe(*syntax)))
        .collect()
}

fn describe(syntax: crate::schema::Syntax) -> &'static str {
    use crate::schema::Syntax;

    match syntax {
        Syntax::DirectoryString => "Directory String",
        Syntax::Ia5String => "IA5 String",
        Syntax::Integer => "Integer",
        Syntax::Boolean => "Boolean",
        Syntax::OctetString => "Octet String",
        Syntax::DistinguishedName => "Distinguished Name",
        Syntax::Oid => "OID",
        Syntax::GeneralizedTime => "Generalized Time",
    }
}

/// Answers a base-scoped search of the subschema subentry.
///
/// Only scope `base` makes sense: the entry has no children, and a subtree search of it is
/// the same entry. A one-level search finds nothing, which is honest.
pub fn search(
    message_id: MessageId,
    request: &SearchRequest,
    schema: &Schema,
    base_object: &str,
) -> Vec<LdapMessage> {
    let entry = entry(schema);
    let selection: Vec<String> = request
        .attributes
        .iter()
        .map(|attribute| attribute.0.clone())
        .collect();

    match super::search::scope_of(request) {
        crate::directory::Scope::OneLevel => vec![search_done(message_id, ResultCode::Success, "")],
        _ => {
            // The DN as the client wrote it, only trimmed: `cn=Subschema` must come back
            // spelled that way, because a client comparing the answer with its own base
            // sees a difference otherwise. Normalising would answer `cn=subschema`.
            let answered = match base_object.trim() {
                "" => PRIMARY_DN,
                asked => asked,
            };

            vec![
                search_result_entry(
                    message_id,
                    answered,
                    &entry.attributes().select(answered, &selection),
                ),
                search_done(message_id, ResultCode::Success, ""),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> Schema {
        Schema::core()
    }

    fn value(entry: &Entry, name: &str) -> Vec<String> {
        entry
            .attributes()
            .get(name)
            .map(|attribute| attribute.values.to_vec())
            .unwrap_or_default()
    }

    #[test]
    fn both_names_reach_the_entry() {
        assert!(is_schema_dn("cn=Subschema"));
        assert!(is_schema_dn("cn=schema"));
        assert!(is_schema_dn("CN=SCHEMA"));
        assert!(is_schema_dn(" cn=schema "));
        assert!(!is_schema_dn("cn=other"));
        assert!(!is_schema_dn(""));
    }

    #[test]
    fn the_entry_publishes_the_definitions() {
        let entry = entry(&schema());

        let types = value(&entry, "attributeTypes");
        let classes = value(&entry, "objectClasses");

        assert!(!types.is_empty(), "attributeTypes must not be empty");
        assert!(!classes.is_empty(), "objectClasses must not be empty");
        assert!(types.iter().any(|definition| definition.contains("'cn'")));
        assert!(
            classes
                .iter()
                .any(|definition| definition.contains("'inetOrgPerson'"))
        );
    }

    #[test]
    fn each_definition_appears_once() {
        let entry = entry(&schema());

        for name in ["attributeTypes", "objectClasses"] {
            let values = value(&entry, name);
            let mut sorted = values.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                values.len(),
                sorted.len(),
                "{name} must not repeat a definition"
            );
        }
    }

    #[test]
    fn the_published_text_parses_back_into_the_same_schema() {
        // The property that makes the publication trustworthy: a client that reads these
        // strings and parses them gets the schema the server enforces.
        let original = schema();
        let entry = entry(&original);

        // A schema built only from what was published, so nothing hidden can mask a loss.
        let parsed = {
            let mut fresh = Schema::default();
            for definition in value(&entry, "attributeTypes") {
                fresh
                    .extend(&format!("attributetype {definition}"))
                    .unwrap_or_else(|err| {
                        panic!("published attribute does not parse: {err}: {definition}")
                    });
            }
            for definition in value(&entry, "objectClasses") {
                fresh
                    .extend(&format!("objectclass {definition}"))
                    .unwrap_or_else(|err| {
                        panic!("published class does not parse: {err}: {definition}")
                    });
            }
            fresh
        };

        assert_eq!(
            parsed.attribute_types().len(),
            original.attribute_types().len(),
            "every attribute type must survive the round trip"
        );
        assert_eq!(
            parsed.object_classes().len(),
            original.object_classes().len()
        );

        for attribute in original.attribute_types() {
            let published = parsed
                .attribute(&attribute.oid)
                .unwrap_or_else(|| panic!("{} disappeared", attribute.oid));
            assert_eq!(
                published.definition(),
                attribute.definition(),
                "{}",
                attribute.oid
            );
        }
        for class in original.object_classes() {
            let published = parsed
                .class(&class.oid)
                .unwrap_or_else(|| panic!("{} disappeared", class.oid));
            assert_eq!(published.definition(), class.definition(), "{}", class.oid);
        }
    }

    #[test]
    fn the_definitions_are_operational() {
        let entry = entry(&schema());

        for name in [
            "attributeTypes",
            "objectClasses",
            "ldapSyntaxes",
            "subschemaSubentry",
        ] {
            assert!(
                entry
                    .attributes()
                    .get(name)
                    .is_some_and(|attribute| attribute.flags.operational),
                "{name} must be operational, or a `*` search would dump the whole schema"
            );
        }
    }

    #[test]
    fn a_star_search_does_not_return_the_definitions() {
        let entry = entry(&schema());
        let selected = entry.attributes().select(PRIMARY_DN, &["*".to_string()]);
        let names: Vec<String> = selected
            .iter()
            .map(|attribute| attribute.name.to_lowercase())
            .collect();

        assert!(names.contains(&"objectclass".to_string()));
        assert!(
            !names.contains(&"attributetypes".to_string()),
            "a client must ask for + or by name: {names:?}"
        );
    }

    #[test]
    fn a_plus_search_returns_them() {
        let entry = entry(&schema());
        let selected = entry.attributes().select(PRIMARY_DN, &["+".to_string()]);
        let names: Vec<String> = selected
            .iter()
            .map(|attribute| attribute.name.to_lowercase())
            .collect();

        assert!(names.contains(&"attributetypes".to_string()));
        assert!(names.contains(&"objectclasses".to_string()));
    }

    #[test]
    fn the_single_valued_keyword_is_published() {
        let entry = entry(&schema());
        let types = value(&entry, "attributeTypes");

        let uid_number = types
            .iter()
            .find(|definition| definition.contains("1.3.6.1.1.1.1.0"))
            .expect("uidNumber");

        assert!(
            uid_number.contains("SINGLE-VALUE"),
            "a client needs to know it holds one value: {uid_number}"
        );
    }

    #[test]
    fn an_operational_attribute_is_published_with_its_usage() {
        let entry = entry(&schema());
        let types = value(&entry, "attributeTypes");

        let csn = types
            .iter()
            .find(|definition| definition.contains("entryCSN"))
            .expect("entryCSN");

        assert!(csn.contains("USAGE directoryOperation"), "{csn}");
        assert!(csn.contains("NO-USER-MODIFICATION"), "{csn}");
    }

    #[test]
    fn the_object_class_kind_is_published() {
        let entry = entry(&schema());
        let classes = value(&entry, "objectClasses");

        let top = classes
            .iter()
            .find(|definition| definition.contains("'top'"))
            .expect("top");
        assert!(top.contains("ABSTRACT"), "{top}");

        let person = classes
            .iter()
            .find(|definition| definition.contains("'person'"))
            .expect("person");
        assert!(person.contains("STRUCTURAL"), "{person}");
        assert!(
            person.contains("MUST ( sn $ cn )") || person.contains("MUST"),
            "{person}"
        );

        let posix = classes
            .iter()
            .find(|definition| definition.contains("'posixAccount'"))
            .expect("posixAccount");
        assert!(posix.contains("AUXILIARY"), "{posix}");
    }
}
