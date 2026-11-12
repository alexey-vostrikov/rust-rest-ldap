//! LDIF export against the real directory, checked the way a reader would read it.
//!
//! The unit tests in `src/ldif.rs` pin the rules one at a time. This file asks the
//! question that matters for an operator: if I dump this directory and hand the file to
//! `ldapadd`, does it describe the same directory back?

use rrl_directory::directory::Directory;
use rrl_directory::ldif::{Options, export};
use rrl_directory::model::{Attribute, Attributes, Entry};

const BASE: &str = "dc=example,dc=com";

fn example_directory() -> Directory {
    let users: Vec<rrl_directory::model::User> = serde_json::from_str(
        &std::fs::read_to_string("examples/file/users.json").expect("users.json"),
    )
    .expect("parse users");
    let groups: Vec<rrl_directory::model::Group> = serde_json::from_str(
        &std::fs::read_to_string("examples/file/groups.json").expect("groups.json"),
    )
    .expect("parse groups");

    Directory::new(BASE, "users", "groups", users, groups)
}

/// Minimal reader: enough to check that the document says what it should.
///
/// Written out rather than shared with the writer on purpose — a round trip through a
/// single implementation proves only that it is self-consistent.
fn parse(text: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut records = Vec::new();
    let mut record: Option<(String, Vec<(String, String)>)> = None;

    // Unfold first: a continuation line starts with a single space.
    let mut lines: Vec<String> = Vec::new();
    for line in text.split('\n') {
        if let Some(rest) = line.strip_prefix(' ') {
            if let Some(last) = lines.last_mut() {
                last.push_str(rest);
                continue;
            }
            panic!("continuation without a line to continue: {line:?}");
        }
        lines.push(line.to_string());
    }

    for line in lines {
        if line.is_empty() {
            if let Some(finished) = record.take() {
                records.push(finished);
            }
            continue;
        }

        let (name, value) = if let Some(rest) = line.split_once(":: ") {
            (rest.0, decode_base64(rest.1))
        } else if let Some(rest) = line.strip_prefix("dn: ") {
            ("dn", rest.to_string())
        } else if let Some(rest) = line.split_once(": ") {
            (rest.0, rest.1.to_string())
        } else {
            panic!("line without a separator: {line:?}");
        };

        match record.as_mut() {
            None => {
                assert_eq!(name, "dn", "a record must start with dn: {line:?}");
                record = Some((value, Vec::new()));
            }
            Some((_, attributes)) => attributes.push((name.to_string(), value)),
        }
    }

    if let Some(finished) = record.take() {
        records.push(finished);
    }

    records
}

fn decode_base64(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut count = 0;
    let mut bytes = Vec::new();

    for byte in text.bytes() {
        if byte == b'=' {
            break;
        }
        let index = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .unwrap_or_else(|| panic!("not base64: {text}")) as u32;
        bits = (bits << 6) | index;
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push((bits >> count) as u8);
        }
    }

    String::from_utf8(bytes).expect("the encoder only ever encodes UTF-8")
}

#[test]
fn every_entry_of_the_directory_is_written_once() {
    let directory = example_directory();
    let text = export(directory.all(), Options::default());
    let records = parse(&text);

    assert_eq!(records.len(), directory.len());
    for (dn, _) in &records {
        assert!(
            directory.find(dn).is_some(),
            "{dn} came out of the export but is not in the directory"
        );
    }
}

#[test]
fn the_export_describes_the_same_values() {
    let directory = example_directory();
    let text = export(directory.all(), Options::default());

    for (dn, attributes) in parse(&text) {
        let entry = directory.find(&dn).expect("entry");

        for (name, value) in &attributes {
            let stored = entry
                .attributes()
                .get(name)
                .unwrap_or_else(|| panic!("{dn} has no {name} in the directory"));
            assert!(
                stored.values.iter().any(|candidate| candidate == value),
                "{dn}: '{value}' is not a value of {name}"
            );
        }

        for attribute in entry.attributes().values() {
            if attribute.flags.operational || attribute.flags.internal {
                continue;
            }
            let written = attributes
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case(&attribute.name))
                .count();
            assert_eq!(
                written,
                attribute.values.len(),
                "{dn}: {name} has {} values in the directory and {written} in the export",
                attribute.values.len(),
                name = attribute.name
            );
        }
    }
}

#[test]
fn a_directory_with_non_ascii_values_round_trips() {
    let entry = Entry::new(
        "cn=иван,ou=users,dc=example,dc=com",
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "person".to_string()],
            ))
            .push(Attribute::single("cn", "иван"))
            .push(Attribute::single("sn", "Петров"))
            .push(Attribute::single("displayName", &"И".repeat(120))),
    );

    let text = export(std::slice::from_ref(&entry), Options::default());
    let records = parse(&text);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, entry.dn());
    for (name, value) in &records[0].1 {
        assert!(
            entry
                .attributes()
                .get(name)
                .is_some_and(|attribute| attribute.values.iter().any(|v| v == value)),
            "{name} came back as something else"
        );
    }
}

#[test]
fn no_physical_line_exceeds_the_limit() {
    // The whole shipped directory, plus a value long enough to fold several times.
    let mut entries: Vec<Entry> = example_directory().all().to_vec();
    entries.push(Entry::new(
        "cn=long,ou=users,dc=example,dc=com",
        Attributes::new()
            .push(Attribute::single("cn", "long"))
            .push(Attribute::single("sn", &"я".repeat(300))),
    ));

    let text = export(&entries, Options::default());

    for line in text.lines() {
        assert!(line.len() <= 76, "too long ({}): {line}", line.len());
    }
}

#[test]
fn the_document_has_no_trailing_garbage() {
    let text = export(example_directory().all(), Options::default());

    assert!(
        text.ends_with("\n\n"),
        "the file must end with a blank line"
    );
    assert!(
        !text.contains("\n\n\n"),
        "records must be separated by one blank line"
    );
}

#[test]
fn operational_attributes_can_be_included() {
    let mut attributes = Attributes::new()
        .push(Attribute::single("cn", "x"))
        .push(Attribute::single("sn", "Y"))
        .push(Attribute::single("entryUUID", "uuid-1").operational())
        .push(
            Attribute::single("entryCSN", "20261102143012.000001Z#000001#000#000000").operational(),
        );
    attributes = attributes.push(Attribute::single("ldapAdmin", "true").internal());
    let entry = Entry::new("cn=x,ou=users,dc=example,dc=com", attributes);

    let plain = export(std::slice::from_ref(&entry), Options::default());
    assert!(!plain.contains("entryUUID"));
    assert!(!plain.contains("ldapAdmin"));

    let full = export(
        std::slice::from_ref(&entry),
        Options {
            operational: true,
            internal: true,
            ..Default::default()
        },
    );
    assert!(full.contains("entryUUID: uuid-1"));
    assert!(full.contains("entryCSN: "));
    assert!(full.contains("ldapAdmin: true"));
}
