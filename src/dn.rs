//! Distinguished name helpers.
//!
//! gorestldap normalizes every DN that arrives from a client or from the config
//! (`internal/ldaputils`): everything is lowercased and spaces after the commas
//! are removed, so `DC=Test, dc=EXAMPLE,  dc=com` and `dc=test,dc=example,dc=com`
//! compare equal.

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

#[cfg(test)]
mod tests {
    use super::normalize;

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
}
