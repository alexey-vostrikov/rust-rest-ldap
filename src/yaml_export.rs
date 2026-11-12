//! YAML export: an alternative to LDIF for people who read the dump themselves.
//!
//! LDIF is not going anywhere — `ldapadd` and `slapadd` read it and nothing else will do for
//! a migration. But LDIF is a poor format to *look at*: one record is a run of lines, long
//! values fold at 76 octets, Cyrillic goes to base64, and `dn:` repeats for every entry. A
//! diff of such a file is unreadable, which is exactly what an operator reviewing a
//! directory-as-code change needs.
//!
//! So this is a second output format, not a replacement: same entries, same selection of
//! operational and internal attributes, different shape.
//!
//! ```yaml
//! entries:
//!   - dn: "cn=ann,ou=users,dc=example,dc=com"
//!     attributes:
//!       "objectClass":
//!         - "top"
//!         - "person"
//!       "cn":
//!         - "ann"
//! ```
//!
//! Two decisions drive the shape:
//!
//! **Every scalar is quoted.** YAML types implicitly, and a directory is full of values that
//! look like something else: a login `no` becomes `false`, a room `012` becomes the number
//! 10, a version `1.10` becomes the float 1.1, `on` and `yes` become booleans, `~` and
//! `null` become nothing at all. Quoting removes that whole class of silent corruption, and
//! the round-trip test proves it by parsing the output back.
//!
//! **One value per line, always.** A flow list `[a, b]` would diff as one changed line when
//! a value is added; a block list adds a line. For a file whose point is review, that is the
//! whole difference.

use std::fmt::Write as _;

use serde::Deserialize;

use crate::model::Entry;

/// Options for one export, matching the LDIF export.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Include operational attributes (`entryUUID`, timestamps, `entryCSN`).
    pub operational: bool,
    /// Include attributes the server treats as internal (`ldapAdmin`).
    pub internal: bool,
}

/// Renders `entries` as a YAML document.
pub fn export(entries: &[Entry], options: Options) -> String {
    let mut out = String::new();
    out.push_str("# rrl-directory directory export\n");
    out.push_str(
        "# Every value is quoted on purpose: unquoted, YAML would turn \"no\" into false\n\
         # and \"012\" into the number 10.\n",
    );

    if entries.is_empty() {
        out.push_str("entries: []\n");
        return out;
    }

    out.push_str("entries:\n");
    for entry in entries {
        let _ = writeln!(out, "  - dn: {}", quote(entry.dn()));

        let attributes: Vec<_> = entry
            .attributes()
            .values()
            .iter()
            .filter(|attribute| !attribute.values.is_empty())
            .filter(|attribute| options.operational || !attribute.flags.operational)
            .filter(|attribute| options.internal || !attribute.flags.internal)
            .collect();

        if attributes.is_empty() {
            out.push_str("    attributes: {}\n");
            continue;
        }

        out.push_str("    attributes:\n");
        for attribute in attributes {
            let _ = writeln!(out, "      {}:", quote(&attribute.name));
            for value in attribute.values.iter() {
                let _ = writeln!(out, "        - {}", quote(value));
            }
        }
    }

    out
}

/// A double-quoted YAML scalar.
///
/// The JSON string dialect is a subset of what YAML allows in double quotes, so the same
/// escaping works for both — and a dump can be read by a JSON parser in a pinch, which is a
/// useful property for a format meant to be consumed by tools.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');

    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Control characters have no readable form; escaping them keeps the file valid
            // and keeps the value recoverable.
            other if (other as u32) < 0x20 || other as u32 == 0x7f => {
                let _ = write!(out, "\\u{:04x}", other as u32);
            }
            other => out.push(other),
        }
    }

    out.push('"');
    out
}

/// The document shape, for reading an export back.
///
/// Not wired to a command yet — LDIF has no import either — but a format nobody can read is a
/// format nobody can check, and the round-trip test is what keeps the quoting honest.
#[derive(Debug, Deserialize)]
struct Document {
    #[serde(default)]
    entries: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    dn: String,
    #[serde(default)]
    attributes: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("cannot parse the YAML document: {0}")]
    Yaml(String),
    #[error("the entry '{dn}' has a DN that is not valid: {dn}")]
    InvalidDn { dn: String },
    #[error("the entry '{dn}' has an attribute '{attribute}' with no values")]
    EmptyAttribute { dn: String, attribute: String },
}

/// Reads a document produced by [`export`] back into entries.
///
/// Deliberately strict about the DN: a hand-edited file with a typo would otherwise produce
/// an entry that no search can find, and the mistake would surface much later.
pub fn parse(text: &str) -> Result<Vec<Entry>, ParseError> {
    let document: Document =
        serde_saphyr::from_str(text).map_err(|err| ParseError::Yaml(err.to_string()))?;

    let mut entries = Vec::with_capacity(document.entries.len());
    for raw in document.entries {
        if !crate::dn::is_valid(&raw.dn) {
            return Err(ParseError::InvalidDn { dn: raw.dn });
        }

        let mut attributes = crate::model::Attributes::new();
        for (name, values) in raw.attributes {
            if values.is_empty() {
                return Err(ParseError::EmptyAttribute {
                    dn: raw.dn.clone(),
                    attribute: name,
                });
            }
            attributes = attributes.push(crate::model::Attribute::new(&name, values));
        }

        entries.push(Entry::new(raw.dn, attributes));
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, Attributes};

    fn entry() -> Entry {
        Entry::new(
            "cn=ann,ou=users,dc=example,dc=com",
            Attributes::new()
                .push(Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "inetOrgPerson".to_string()],
                ))
                .push(Attribute::single("cn", "ann"))
                .push(Attribute::single("mail", "ann@example.com")),
        )
    }

    #[test]
    fn a_simple_entry_is_written_as_yaml() {
        assert_eq!(
            export(&[entry()], Options::default()),
            "# rrl-directory directory export\n\
             # Every value is quoted on purpose: unquoted, YAML would turn \"no\" into false\n\
             # and \"012\" into the number 10.\n\
             entries:\n\
             \x20 - dn: \"cn=ann,ou=users,dc=example,dc=com\"\n\
             \x20   attributes:\n\
             \x20     \"objectClass\":\n\
             \x20       - \"top\"\n\
             \x20       - \"inetOrgPerson\"\n\
             \x20     \"cn\":\n\
             \x20       - \"ann\"\n\
             \x20     \"mail\":\n\
             \x20       - \"ann@example.com\"\n"
        );
    }

    #[test]
    fn the_output_parses_back_into_the_same_entries() {
        let parsed = parse(&export(&[entry()], Options::default())).expect("parse");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].dn(), entry().dn());
        assert_eq!(
            parsed[0]
                .attributes()
                .get("objectClass")
                .map(|attribute| attribute.values.to_vec()),
            Some(vec!["top".to_string(), "inetOrgPerson".to_string()])
        );
        assert_eq!(
            parsed[0]
                .attributes()
                .get("mail")
                .map(|attribute| attribute.values.to_vec()),
            Some(vec!["ann@example.com".to_string()])
        );
    }

    #[test]
    fn values_yaml_would_retype_come_back_as_text() {
        // The reason every scalar is quoted. Each of these is a value a real directory holds
        // and YAML would silently turn into something else.
        for value in [
            "no", "yes", "on", "off", "true", "false", "null", "~", "012", "0x1f", "1.10", "1e5",
            "-", "N", "Y",
        ] {
            let entry = Entry::new(
                "cn=x,dc=example,dc=com",
                Attributes::new().push(Attribute::single("description", value)),
            );

            let parsed = parse(&export(std::slice::from_ref(&entry), Options::default()))
                .unwrap_or_else(|err| panic!("'{value}' must round-trip: {err}"));

            assert_eq!(
                parsed[0]
                    .attributes()
                    .get("description")
                    .expect("description")
                    .values
                    .as_ref(),
                &[value.to_string()],
                "'{value}' must come back as the same text"
            );
        }
    }

    #[test]
    fn cyrillic_is_written_as_text_not_encoded() {
        // LDIF has to base64 a non-ASCII value; YAML is UTF-8, so a Russian display name
        // stays readable - which is most of the point of this format.
        let entry = Entry::new(
            "cn=иван,ou=users,dc=example,dc=com",
            Attributes::new().push(Attribute::single("displayName", "Иван Петров")),
        );

        let text = export(std::slice::from_ref(&entry), Options::default());

        assert!(
            text.contains("Иван Петров"),
            "the value must stay readable: {text}"
        );
        let parsed = parse(&text).expect("parse");
        assert_eq!(parsed[0].dn(), entry.dn());
        assert_eq!(
            parsed[0]
                .attributes()
                .get("displayName")
                .expect("displayName")
                .values
                .as_ref(),
            &["Иван Петров".to_string()]
        );
    }

    #[test]
    fn every_value_gets_its_own_line() {
        // A flow list would change one line when a value is added; a block list adds a line.
        let text = export(&[entry()], Options::default());

        // The list items are indented under the attribute key, one per line.
        assert!(
            text.contains("        - \"top\"\n        - \"inetOrgPerson\"\n"),
            "each value on its own line: {text}"
        );
        assert!(!text.contains('['), "no flow sequences");
    }

    #[test]
    fn special_characters_survive() {
        let value = "quote \" backslash \\ newline \n tab \t done";
        let entry = Entry::new(
            "cn=x,dc=example,dc=com",
            Attributes::new().push(Attribute::single("description", value)),
        );

        let text = export(std::slice::from_ref(&entry), Options::default());
        assert!(
            !text.contains("\n\ttab"),
            "a raw newline must be escaped: {text}"
        );

        let parsed = parse(&text).expect("parse");
        assert_eq!(
            parsed[0]
                .attributes()
                .get("description")
                .expect("description")
                .values
                .as_ref(),
            &[value.to_string()]
        );
    }

    #[test]
    fn operational_attributes_are_left_out_by_default() {
        let mut attributes = entry().attributes().clone();
        attributes = attributes.push(Attribute::single("entryUUID", "uuid-1").operational());
        let entry = Entry::new(entry().dn(), attributes);

        let plain = export(std::slice::from_ref(&entry), Options::default());
        assert!(!plain.contains("entryUUID"));

        let full = export(
            std::slice::from_ref(&entry),
            Options {
                operational: true,
                ..Options::default()
            },
        );
        assert!(full.contains("entryUUID"));
    }

    #[test]
    fn internal_attributes_need_their_own_option() {
        let mut attributes = entry().attributes().clone();
        attributes =
            attributes.push(Attribute::new("ldapAdmin", vec!["true".to_string()]).internal());
        let entry = Entry::new(entry().dn(), attributes);

        assert!(!export(std::slice::from_ref(&entry), Options::default()).contains("ldapAdmin"));
        assert!(
            export(
                std::slice::from_ref(&entry),
                Options {
                    internal: true,
                    ..Options::default()
                }
            )
            .contains("ldapAdmin")
        );
    }

    #[test]
    fn an_empty_directory_is_an_empty_list() {
        let text = export(&[], Options::default());

        assert!(text.contains("entries: []"));
        assert_eq!(parse(&text).expect("parse").len(), 0);
    }

    #[test]
    fn an_entry_without_attributes_is_written_as_an_empty_mapping() {
        let entry = Entry::new("cn=x,dc=example,dc=com", Attributes::new());
        let text = export(std::slice::from_ref(&entry), Options::default());

        assert!(text.contains("attributes: {}"));
        assert_eq!(parse(&text).expect("parse").len(), 1);
    }

    #[test]
    fn a_hand_edited_file_with_a_broken_dn_is_refused() {
        let text = "entries:\n  - dn: \"not a dn\"\n    attributes: {}\n";

        match parse(text) {
            Err(ParseError::InvalidDn { dn }) => assert_eq!(dn, "not a dn"),
            other => panic!("expected an invalid DN error, got {other:?}"),
        }
    }

    #[test]
    fn a_file_that_is_not_yaml_is_refused_with_a_reason() {
        let error = parse("entries: [\n").expect_err("must fail");

        assert!(
            matches!(error, ParseError::Yaml(_)),
            "the operator needs to know the file is malformed: {error}"
        );
    }

    #[test]
    fn the_attribute_order_of_the_entry_is_kept() {
        // Not alphabetical: the order the model holds is the order the file shows, so a dump
        // of a dump is unchanged.
        let text = export(&[entry()], Options::default());
        let object_class = text.find("objectClass").expect("objectClass");
        let mail = text.find("\"mail\"").expect("mail");

        assert!(object_class < mail);
    }
}
