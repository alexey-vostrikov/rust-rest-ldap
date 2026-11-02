//! StartTLS extended operation (RFC 4511 §4.14, RFC 4513).

/// OID of the StartTLS extended request.
pub const STARTTLS_OID: &str = "1.3.6.1.4.1.1466.20037";

/// Whether the extended request asks for StartTLS.
pub fn is_starttls(request_name: &[u8]) -> bool {
    request_name == STARTTLS_OID.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rfc_oid_is_recognised() {
        assert!(is_starttls(b"1.3.6.1.4.1.1466.20037"));
    }

    #[test]
    fn other_extended_names_are_not_starttls() {
        assert!(!is_starttls(b"1.3.6.1.4.1.4203.1.11.1"));
        assert!(!is_starttls(b"1.3.6.1.4.1.1466.20036"));
        assert!(!is_starttls(b""));
    }
}
