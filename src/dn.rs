//! Distinguished name helpers.
//!
//! gorestldap normalizes every DN that arrives from a client or from the config
//! (`internal/ldaputils`): everything is lowercased and spaces after the commas
//! are removed, so `DC=Test, dc=EXAMPLE,  dc=com` and `dc=test,dc=example,dc=com`
//! compare equal.

/// Attribute types the server accepts in a DN it has to resolve.
const ALLOWED_ATTRIBUTES: [&str; 4] = ["cn", "uid", "ou", "dc"];

/// Returns the entry name in lowercase with spaces after commas removed.
pub fn normalize(entry: &str) -> String {
    let trimmed = entry.trim().to_lowercase();
    let mut out = String::with_capacity(trimmed.len());
    let mut prev = '\0';
    for ch in trimmed.chars() {
        if ch.is_whitespace() && prev == ',' {
            continue;
        }
        out.push(ch);
        prev = ch;
    }
    out
}

/// Splits the first RDN off the entry: `cn=admin,ou=users,dc=example,dc=com`
/// gives `("cn", "admin", "ou=users,dc=example,dc=com")`.
///
/// The input is expected to be normalized already; the suffix is empty when the
/// entry has a single RDN.
pub fn split_first_rdn(entry: &str) -> (String, String, String) {
    // The split is on an unescaped comma: RFC 4514 lets a value carry one as `\,`, and
    // `cn=Doe\, John,ou=...` is a single RDN whose value holds a comma. Splitting at the first
    // comma turned that value into `Doe\` and left the rest of the name as the parent - a
    // defect that only shows up on entries whose names have a comma in them, which is exactly
    // why it survived this long.
    let (rdn, suffix) = match split_unescaped(entry, ',') {
        Some((rdn, suffix)) => (rdn, suffix),
        None => (entry, ""),
    };
    let (attribute, value) = match rdn.split_once('=') {
        Some((attribute, value)) => (attribute, value),
        None => (rdn, ""),
    };
    (attribute.to_string(), value.to_string(), suffix.to_string())
}

/// Splits at the first occurrence of `separator` that is not escaped with a backslash.
fn split_unescaped(text: &str, separator: char) -> Option<(&str, &str)> {
    let mut escaped = false;

    for (index, character) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            _ if character == separator => return Some((&text[..index], &text[index + 1..])),
            _ => {}
        }
    }

    None
}

/// The value with its RFC 4514 escapes removed: `Doe\, John` gives `Doe, John`.
///
/// For handing a name to something outside the directory - a REST service addresses an object
/// by name, and the name it stores does not carry the directory's escapes.
pub fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut characters = value.chars();

    while let Some(character) = characters.next() {
        if character == '\\' {
            match characters.next() {
                // A hex pair is the other escape form RFC 4514 allows; both bytes are kept as
                // written, because turning them into a character could split a multibyte one.
                Some(hex) if hex.is_ascii_hexdigit() => {
                    out.push('\\');
                    out.push(hex);
                }
                Some(next) => out.push(next),
                None => out.push('\\'),
            }
        } else {
            out.push(character);
        }
    }

    out
}

/// Value of the first RDN, e.g. `dc=example,dc=com` gives `example`.
pub fn first_value(entry: &str) -> Option<String> {
    let (_, value, _) = split_first_rdn(entry);
    if value.is_empty() { None } else { Some(value) }
}

/// Checks that every RDN of the entry uses a supported attribute type and has
/// the `attribute=value` shape.
pub fn is_valid(entry: &str) -> bool {
    !entry.is_empty()
        && entry.split(',').all(|rdn| match rdn.split_once('=') {
            Some((attribute, value)) => {
                !value.is_empty() && ALLOWED_ATTRIBUTES.contains(&attribute)
            }
            None => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_escaped_comma_does_not_end_the_rdn() {
        // RFC 4514 lets a value carry a comma as `\,`. Splitting at the first comma turned
        // `cn=Doe\, John,ou=...` into the value `Doe\` and the parent ` John,ou=...` - a defect
        // that lived in every consumer of a DN and only missed entries with a comma in the name.
        let (attribute, value, parent) =
            split_first_rdn(r"cn=Doe\, John,ou=users,dc=example,dc=com");

        assert_eq!(attribute, "cn");
        assert_eq!(value, r"Doe\, John");
        assert_eq!(parent, "ou=users,dc=example,dc=com");
    }

    #[test]
    fn a_separator_after_an_escaped_one_is_a_separator() {
        // The escape ends at the character it protects. Leaving it open would make the rest of
        // the DN escaped, and the split would never happen.
        let (_, value, parent) = split_first_rdn(r"cn=a\,b,ou=users,dc=example,dc=com");

        assert_eq!(value, r"a\,b");
        assert_eq!(parent, "ou=users,dc=example,dc=com");
    }

    #[test]
    fn an_escaped_backslash_does_not_protect_the_next_character() {
        // `\\` is one literal backslash; the comma after it is a separator again.
        let (_, value, parent) = split_first_rdn(r"cn=a\\,ou=users");

        assert_eq!(value, r"a\\");
        assert_eq!(parent, "ou=users");
    }

    #[test]
    fn the_first_character_is_not_treated_as_escaped() {
        // `\,x` is an escaped comma at the very start: the escape protects it, so there is no
        // separator at all. Starting the flag as "already escaped" would consume the backslash
        // without protecting anything and split at the comma instead.
        assert_eq!(split_unescaped(r"\,x", ','), None);
        assert_eq!(split_unescaped("x,y", ','), Some(("x", "y")));
    }

    #[test]
    fn a_dn_without_a_separator_has_no_parent() {
        let (attribute, value, parent) = split_first_rdn("cn=solo");

        assert_eq!(attribute, "cn");
        assert_eq!(value, "solo");
        assert_eq!(parent, "");
    }

    #[test]
    fn unescaping_removes_the_directory_escapes_and_keeps_hex_pairs() {
        assert_eq!(unescape(r"Doe\, John"), "Doe, John");
        assert_eq!(unescape(r"a\+b"), "a+b");
        // A hex pair is a byte, and turning it into a character here could split a multibyte
        // one; it is left as written for whoever decodes it.
        assert_eq!(unescape(r"caf\c3\a9"), r"caf\c3\a9");
        // A trailing backslash alone is kept rather than swallowed.
        assert_eq!(unescape("a\\"), "a\\");
    }

    #[test]
    fn lowercases_and_removes_spaces_after_comma() {
        assert_eq!(
            normalize("DC=Test, dc=EXAMPLE,  dc=com"),
            "dc=test,dc=example,dc=com"
        );
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(normalize("  dc=example,dc=com \n"), "dc=example,dc=com");
    }

    #[test]
    fn keeps_spaces_inside_rdn_values() {
        assert_eq!(
            normalize("cn=Ivan Petrov,ou=users,dc=example,dc=com"),
            "cn=ivan petrov,ou=users,dc=example,dc=com"
        );
    }

    #[test]
    fn splits_first_rdn_of_a_multi_level_entry() {
        assert_eq!(
            split_first_rdn("cn=admin,ou=users,dc=example,dc=com"),
            (
                "cn".to_string(),
                "admin".to_string(),
                "ou=users,dc=example,dc=com".to_string()
            )
        );
    }

    #[test]
    fn splits_single_level_entry_without_suffix() {
        assert_eq!(
            split_first_rdn("dc=example"),
            ("dc".to_string(), "example".to_string(), String::new())
        );
    }

    #[test]
    fn rdn_without_equals_gives_empty_value() {
        assert_eq!(
            split_first_rdn("broken,dc=example,dc=com"),
            (
                "broken".to_string(),
                String::new(),
                "dc=example,dc=com".to_string()
            )
        );
    }

    #[test]
    fn first_value_returns_the_naming_value() {
        assert_eq!(first_value("dc=example,dc=com").as_deref(), Some("example"));
        assert_eq!(first_value("dc=").as_deref(), None);
    }

    #[test]
    fn validity_accepts_supported_attributes() {
        assert!(is_valid("cn=admin,ou=users,dc=example,dc=com"));
        assert!(is_valid("dc=example,dc=com"));
        assert!(is_valid("uid=admin,ou=users,dc=example,dc=com"));
    }

    #[test]
    fn validity_rejects_unsupported_or_malformed_entries() {
        assert!(!is_valid(""));
        assert!(!is_valid("mail=user@example.com,dc=example,dc=com"));
        assert!(!is_valid("cn=,dc=example,dc=com"));
        assert!(!is_valid("cn=admin,o=example,dc=com"));
        assert!(!is_valid("cnadmin"));
    }
}
