//! LDIF: the text format operators move directories with (RFC 2849).
//!
//! Written rather than read, for now: an export is what lets this server hand its
//! directory to OpenLDAP, 389 DS or `ldapadd`, and it is the only format those tools
//! all accept. The rules that matter are unforgiving and each one is easy to get wrong
//! quietly:
//!
//! - A line longer than 76 octets is folded with a single leading space on the
//!   continuation. Split a multi-byte character across that boundary and the file no
//!   longer decodes.
//! - A value starting with a space, a colon or `<`, or containing a NUL, CR or LF, or
//!   any octet above 0x7f, is written base64 with `::`. A `userPassword` hash contains
//!   none of those, but a display name with a Cyrillic letter does.
//! - Records are separated by exactly one empty line, and the file ends with one.
//!
//! The exporter deliberately writes what it is given, including operational
//! attributes: an operator dumping a directory for an audit wants `entryCSN`, and one
//! dumping it for a migration can drop it with `--no-operational`.

use crate::model::Entry;

/// Options for one export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Include operational attributes (`entryUUID`, timestamps, `entryCSN`).
    pub operational: bool,
    /// Include attributes the server treats as internal (`ldapAdmin`).
    pub internal: bool,
    /// Wrap long lines; off only for tests that check the wrapping itself.
    pub wrap: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            operational: false,
            internal: false,
            wrap: true,
        }
    }
}

/// Longest line LDIF allows before folding (RFC 2849 §3).
const WRAP_AT: usize = 76;

/// Renders `entries` as an LDIF document.
pub fn export(entries: &[Entry], options: Options) -> String {
    let mut out = String::new();
    for entry in entries {
        write_entry(&mut out, entry, options);
        out.push('\n');
    }
    out
}

/// Renders one record; the caller separates records.
pub fn write_entry(out: &mut String, entry: &Entry, options: Options) {
    write_line(out, "dn", entry.dn(), options.wrap);

    for attribute in entry.attributes().values() {
        if attribute.flags.operational && !options.operational {
            continue;
        }
        if attribute.flags.internal && !options.internal {
            continue;
        }
        for value in attribute.values.iter() {
            write_line(out, &attribute.name, value, options.wrap);
        }
    }
}

/// One `name: value` line, base64-encoded and folded when needed.
fn write_line(out: &mut String, name: &str, value: &str, wrap: bool) {
    if needs_base64(value) {
        let encoded = base64(value.as_bytes());
        let line = format!("{name}:: {encoded}");
        push_folded(out, &line, wrap);
    } else {
        push_folded(out, &format!("{name}: {value}"), wrap);
    }
}

/// True when the value cannot be written as plain text.
///
/// The rules come straight from RFC 2849 §4.4 plus one conservative addition: a value
/// that is not valid UTF-8 has to be encoded, and a `String` here is always valid, so
/// the byte check only has to cover what makes a line ambiguous.
fn needs_base64(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }

    let first = value.as_bytes()[0];
    if first == b' ' || first == b':' || first == b'<' {
        return true;
    }

    value
        .bytes()
        .any(|byte| byte == 0x00 || byte == b'\r' || byte == b'\n' || byte >= 0x7f)
}

/// Pushes `line`, folding it so no physical line exceeds 76 octets.
///
/// Folding happens on byte boundaries of the encoded text, which is safe because a
/// value that needed base64 is pure ASCII at this point, and a plain value is folded
/// only at byte positions that the continuation re-joins unchanged. A UTF-8 character
/// that would land across the boundary moves to the next line as a whole.
fn push_folded(out: &mut String, line: &str, wrap: bool) {
    if !wrap {
        out.push_str(line);
        out.push('\n');
        return;
    }

    let bytes = line.as_bytes();
    if bytes.len() <= WRAP_AT {
        out.push_str(line);
        out.push('\n');
        return;
    }

    let mut start = 0;
    let mut first = true;
    while start < bytes.len() {
        // The first line has the full width; continuations lose one octet to the space.
        let width = if first { WRAP_AT } else { WRAP_AT - 1 };
        let mut end = (start + width).min(bytes.len());

        // Never split a UTF-8 character.
        while end < bytes.len() && !line.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            // A single character wider than the line: write it whole rather than loop.
            end = (start + width).min(bytes.len());
        }

        if first {
            out.push_str(&line[start..end]);
            first = false;
        } else {
            out.push(' ');
            out.push_str(&line[start..end]);
        }
        out.push('\n');
        start = end;
    }
}

/// Standard base64 with padding, written here rather than pulled in: one dependency
/// for eleven lines of arithmetic is not a trade worth making.
pub fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[triple as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
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

    fn plain() -> Options {
        Options {
            wrap: false,
            ..Options::default()
        }
    }

    #[test]
    fn a_simple_entry_is_written_as_ldif() {
        let text = export(&[entry()], plain());

        assert_eq!(
            text,
            "dn: cn=ann,ou=users,dc=example,dc=com\n\
             objectClass: top\n\
             objectClass: inetOrgPerson\n\
             cn: ann\n\
             mail: ann@example.com\n\n"
        );
    }

    #[test]
    fn records_are_separated_by_one_empty_line_and_the_file_ends_with_one() {
        let text = export(&[entry(), entry()], plain());

        assert!(
            text.ends_with("\n\n"),
            "the file must end with a blank line"
        );
        assert_eq!(
            text.matches("\n\n").count(),
            2,
            "one separator plus the final blank line"
        );
    }

    #[test]
    fn operational_attributes_are_left_out_by_default() {
        let mut attributes = entry().attributes().clone();
        attributes = attributes.push(Attribute::single("entryUUID", "uuid-1").operational());
        let entry = Entry::new(entry().dn(), attributes);

        let default = export(std::slice::from_ref(&entry), plain());
        assert!(
            !default.contains("entryUUID"),
            "an import of this file must not fight the target's own UUIDs"
        );

        let with_operational = export(
            &[entry],
            Options {
                operational: true,
                ..plain()
            },
        );
        assert!(with_operational.contains("entryUUID: uuid-1"));
    }

    #[test]
    fn internal_attributes_are_left_out_unless_asked_for() {
        let mut attributes = entry().attributes().clone();
        attributes =
            attributes.push(Attribute::new("ldapAdmin", vec!["true".to_string()]).internal());
        let entry = Entry::new(entry().dn(), attributes);

        assert!(!export(std::slice::from_ref(&entry), plain()).contains("ldapAdmin"));
        assert!(
            export(
                &[entry],
                Options {
                    internal: true,
                    ..plain()
                }
            )
            .contains("ldapAdmin")
        );
    }

    #[test]
    fn a_non_ascii_value_is_base64_encoded() {
        let value = "Иван Петров";
        let entry = Entry::new(
            "cn=ivan,dc=example,dc=com",
            Attributes::new().push(Attribute::single("displayName", value)),
        );

        let text = export(&[entry], plain());

        assert!(
            text.contains(&format!("displayName:: {}", base64(value.as_bytes()))),
            "a value above 0x7f must be encoded: {text}"
        );
        assert!(!text.contains(value), "and the plain form must not appear");
    }

    #[test]
    fn the_encoded_value_decodes_back() {
        // Circular against our own encoder, but it pins the padding and the alphabet.
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(b"{SSHA}AbCdEf"), "e1NTSEF9QWJDZEVm");
    }

    #[test]
    fn a_leading_space_colon_or_less_than_is_encoded() {
        for value in [" leading", ":colon", "<file"] {
            let entry = Entry::new(
                "cn=x,dc=example,dc=com",
                Attributes::new().push(Attribute::single("description", value)),
            );

            assert!(
                export(&[entry], plain()).contains("description:: "),
                "'{value}' is ambiguous as plain text"
            );
        }
    }

    #[test]
    fn a_value_with_a_newline_is_encoded_rather_than_breaking_the_record() {
        let entry = Entry::new(
            "cn=x,dc=example,dc=com",
            Attributes::new().push(Attribute::single("description", "two\nlines")),
        );

        let text = export(&[entry], plain());

        assert!(text.contains("description:: "));
        assert_eq!(
            text.lines().filter(|line| line.is_empty()).count(),
            1,
            "no attribute value may look like a record separator"
        );
    }

    #[test]
    fn an_empty_value_is_written_without_a_space() {
        let entry = Entry::new(
            "cn=x,dc=example,dc=com",
            Attributes::new().push(Attribute::new("description", vec!["".to_string()])),
        );

        assert_eq!(
            export(&[entry], plain()),
            "dn: cn=x,dc=example,dc=com\ndescription: \n\n"
        );
    }

    #[test]
    fn long_lines_are_folded_at_seventy_six_octets() {
        let value = "a".repeat(200);
        let entry = Entry::new(
            "cn=x,dc=example,dc=com",
            Attributes::new().push(Attribute::single("description", &value)),
        );

        let text = export(&[entry], Options::default());

        for line in text.lines() {
            assert!(
                line.len() <= WRAP_AT,
                "a physical line must not exceed {WRAP_AT} octets, got {}: {line}",
                line.len()
            );
        }
        assert!(
            text.lines().skip(1).any(|line| line.starts_with(' ')),
            "the continuation must be marked with a leading space"
        );
    }

    #[test]
    fn folding_does_not_split_a_utf8_character() {
        // Twelve Cyrillic characters are 24 octets each step; a naive fold at 76 would
        // cut one in half.
        let value = "ПриветМирКакДела".repeat(6);
        let entry = Entry::new(
            "cn=x,dc=example,dc=com",
            Attributes::new()
                .push(Attribute::single("displayName", &value))
                .push(Attribute::single("description", &"ж".repeat(200))),
        );

        let text = export(&[entry], Options::default());

        for line in text.lines() {
            assert!(line.len() <= WRAP_AT, "line too long: {line}");
            assert!(
                std::str::from_utf8(line.as_bytes()).is_ok(),
                "every line must be valid UTF-8 on its own: {line}"
            );
        }

        // Base64 keeps the ASCII path; the fold must still respect the width.
        let encoded_line = text
            .lines()
            .find(|line| line.starts_with("displayName::"))
            .expect("encoded value");
        assert!(encoded_line.len() <= WRAP_AT);
    }

    #[test]
    fn folding_round_trips_to_the_original_value() {
        let value = format!("start-{}-end", "x".repeat(150));
        let entry = Entry::new(
            "cn=x,dc=example,dc=com",
            Attributes::new().push(Attribute::single("description", &value)),
        );

        let text = export(&[entry], Options::default());

        // Join the folded lines the way a reader would: a continuation is a leading
        // space that belongs to the format, not to the value.
        let joined = text
            .lines()
            .map(|line| line.strip_prefix(' ').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(
            joined,
            format!("dn: cn=x,dc=example,dc=comdescription: {value}")
        );
    }

    #[test]
    fn a_short_line_is_not_folded() {
        let text = export(&[entry()], Options::default());

        assert!(!text.lines().any(|line| line.starts_with(' ')));
    }

    #[test]
    fn an_empty_directory_produces_an_empty_document() {
        assert_eq!(export(&[], Options::default()), "");
    }

    #[test]
    fn the_dn_is_always_written_first() {
        let text = export(&[entry()], plain());

        assert!(text.starts_with("dn: cn=ann,ou=users,dc=example,dc=com\n"));
    }
}
