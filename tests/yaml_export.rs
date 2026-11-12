//! Both export formats describe the same directory.
//!
//! LDIF and YAML are two shapes of one thing, so the property worth testing is parity: an
//! operator who picks YAML for review must not silently get a different set of entries or a
//! different set of values than one who picks LDIF. The formats differ; the data must not.

use rrl_directory::directory::Directory;
use rrl_directory::ldif;
use rrl_directory::yaml_export;

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

/// Records of an LDIF document: DN and `(attribute, value)` pairs.
fn ldif_records(text: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut records = Vec::new();
    let mut record: Option<(String, Vec<(String, String)>)> = None;

    // Unfold: a continuation is a line starting with a space.
    let mut lines: Vec<String> = Vec::new();
    for line in text.split('\n') {
        // A continuation is a line starting with a space; it belongs to the line before it.
        if let Some((rest, last)) = line
            .strip_prefix(' ')
            .and_then(|rest| lines.last_mut().map(|last| (rest, last)))
        {
            last.push_str(rest);
            continue;
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

        if let Some(dn) = line.strip_prefix("dn: ") {
            record = Some((dn.to_string(), Vec::new()));
            continue;
        }

        let (name, value) = if let Some(rest) = line.split_once(":: ") {
            (rest.0, decode_base64(rest.1))
        } else if let Some(rest) = line.split_once(": ") {
            (rest.0, rest.1.to_string())
        } else {
            // A folded line with no separator cannot occur in a well-formed dump; the
            // summary line "description:" with an empty value can.
            (line.trim_end_matches(':'), String::new())
        };

        if let Some((_, attributes)) = record.as_mut() {
            attributes.push((name.to_string(), value));
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

    String::from_utf8(bytes).expect("the encoder only encodes UTF-8")
}

#[test]
fn both_formats_carry_the_same_entries_and_values() {
    let directory = example_directory();

    let ldif_text = ldif::export(directory.all(), ldif::Options::default());
    let yaml_text = yaml_export::export(directory.all(), yaml_export::Options::default());

    let from_ldif = ldif_records(&ldif_text);
    let from_yaml = yaml_export::parse(&yaml_text).expect("the YAML export must parse");

    assert_eq!(
        from_ldif.len(),
        from_yaml.len(),
        "the two formats must describe the same number of entries"
    );

    for (index, entry) in from_yaml.iter().enumerate() {
        let (ldif_dn, ldif_attributes) = &from_ldif[index];

        assert_eq!(
            entry.dn(),
            ldif_dn,
            "entry {index}: the DN order has to match too, or a diff of the two lies"
        );

        for (name, value) in ldif_attributes {
            let ours = entry
                .attributes()
                .get(name)
                .unwrap_or_else(|| panic!("{}: missing {name}", entry.dn()));

            assert!(
                ours.values.iter().any(|candidate| candidate == value),
                "{}: {name} has '{value}' in the LDIF dump but not in the YAML one",
                entry.dn()
            );
        }

        for attribute in entry.attributes().values() {
            let count = ldif_attributes
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case(&attribute.name))
                .count();
            assert_eq!(
                count,
                attribute.values.len(),
                "{}: {name} has {count} values in the LDIF dump and {} in the YAML one",
                entry.dn(),
                attribute.values.len(),
                name = attribute.name
            );
        }
    }
}

#[test]
fn the_yaml_export_round_trips_the_shipped_directory() {
    let directory = example_directory();
    let text = yaml_export::export(directory.all(), yaml_export::Options::default());
    let parsed = yaml_export::parse(&text).expect("parse");

    assert_eq!(parsed.len(), directory.len());
    for entry in parsed {
        let original = directory
            .find(entry.dn())
            .unwrap_or_else(|| panic!("{} is not in the directory", entry.dn()));

        for attribute in entry.attributes().values() {
            let stored = original
                .attributes()
                .get(&attribute.name)
                .unwrap_or_else(|| {
                    panic!("{}: {name} vanished", entry.dn(), name = attribute.name)
                });

            assert_eq!(
                attribute.values.to_vec(),
                stored.values.to_vec(),
                "{}: {name} changed in the round trip",
                entry.dn(),
                name = attribute.name
            );
        }
    }
}

#[test]
fn yaml_does_not_fold_where_ldif_must() {
    // LDIF folds at 76 octets because RFC 2849 says so; YAML does not fold at all. For a
    // long value that is the difference between a diff that reads as one changed value and
    // one that reads as several changed lines.
    let long = "Наименование отдела продаж и маркетинга ".repeat(6);
    let entry = rrl_directory::model::Entry::new(
        "cn=long,ou=users,dc=example,dc=com",
        rrl_directory::model::Attributes::new()
            .push(rrl_directory::model::Attribute::single("cn", "long"))
            .push(rrl_directory::model::Attribute::single(
                "description",
                &long,
            )),
    );

    let ldif_text = ldif::export(std::slice::from_ref(&entry), ldif::Options::default());
    let yaml_text = yaml_export::export(
        std::slice::from_ref(&entry),
        yaml_export::Options::default(),
    );

    assert!(
        ldif_text.lines().any(|line| line.starts_with(' ')),
        "the LDIF dump must fold a value this long"
    );
    // Every YAML line is indented, so the check is not "no leading space": it is that the
    // value fits in one line, which folding would prevent.
    let value_line = yaml_text
        .lines()
        .find(|line| line.trim_start().starts_with("- \"Наименование"))
        .expect("the description on one line");
    assert_eq!(
        value_line.trim().trim_start_matches("- ").trim_matches('"'),
        long,
        "the whole value on one line"
    );
}

#[test]
fn operational_attributes_are_left_out_by_both_formats() {
    let directory = example_directory();

    let ldif_text = ldif::export(directory.all(), ldif::Options::default());
    let yaml_text = yaml_export::export(directory.all(), yaml_export::Options::default());

    for name in ["entryUUID", "createTimestamp", "entryCSN"] {
        assert!(!ldif_text.contains(name), "{name} in the LDIF dump");
        assert!(!yaml_text.contains(name), "{name} in the YAML dump");
    }

    let ldif_full = ldif::export(
        directory.all(),
        ldif::Options {
            operational: true,
            ..Default::default()
        },
    );
    let yaml_full = yaml_export::export(
        directory.all(),
        yaml_export::Options {
            operational: true,
            ..Default::default()
        },
    );
    assert!(ldif_full.contains("entryUUID"));
    assert!(yaml_full.contains("entryUUID"));
}
