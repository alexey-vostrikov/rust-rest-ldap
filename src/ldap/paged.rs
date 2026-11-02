//! Paged results control (RFC 2696).
//!
//! The control value is `SEQUENCE { size INTEGER, cookie OCTET STRING }`. It
//! comes from an unauthenticated client, so the parser is strict: definite
//! lengths only, a non-negative size that fits `u32`, no trailing bytes.
//!
//! `rasn` has no type for this structure and deriving one pulls the derive macro
//! into code it does not own, so the two small encodings are written out here and
//! pinned by tests against their wire form.

use thiserror::Error;

/// Control OID (the one gorestldap and Active Directory use).
pub const PAGED_RESULTS_OID: &str = "1.2.840.113556.1.4.319";

const SEQUENCE_TAG: u8 = 0x30;
const INTEGER_TAG: u8 = 0x02;
const OCTET_STRING_TAG: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Page {
    /// Page size the client asks for; zero in a response means "no fixed size".
    pub size: u32,
    /// Opaque continuation token; empty means "the search is finished".
    pub cookie: Vec<u8>,
}

impl Page {
    pub fn new(size: u32, cookie: impl Into<Vec<u8>>) -> Self {
        Self {
            size,
            cookie: cookie.into(),
        }
    }

    /// True when the client asked for paged results.
    pub fn is_requested(&self) -> bool {
        self.size > 0
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PageError {
    #[error("control value is not a BER sequence")]
    NotSequence,
    #[error("control value has no size element")]
    MissingSize,
    #[error("control value has no cookie element")]
    MissingCookie,
    #[error("control value size is negative")]
    NegativeSize,
    #[error("control value size does not fit 32 bits")]
    SizeOverflow,
    #[error("control value has trailing bytes")]
    TrailingBytes,
    #[error("unsupported BER length form in control value")]
    UnsupportedLength,
    #[error("control value is truncated")]
    Truncated,
}

/// Encodes the control value.
pub fn encode(page: &Page) -> Vec<u8> {
    let integer = encode_integer(page.size);
    let cookie = encode_octet_string(&page.cookie);

    let mut content = Vec::with_capacity(integer.len() + cookie.len());
    content.extend_from_slice(&integer);
    content.extend_from_slice(&cookie);

    let mut out = vec![SEQUENCE_TAG];
    out.extend_from_slice(&encode_length(content.len()));
    out.extend_from_slice(&content);
    out
}

/// Decodes the control value.
pub fn decode(bytes: &[u8]) -> Result<Page, PageError> {
    let (content, rest) = read_tlv(bytes, SEQUENCE_TAG)?;
    if !rest.is_empty() {
        return Err(PageError::TrailingBytes);
    }

    let (size_bytes, rest) = read_tlv(content, INTEGER_TAG)?;
    if rest.is_empty() {
        return Err(PageError::MissingCookie);
    }
    let (cookie, rest) = read_tlv(rest, OCTET_STRING_TAG)?;
    if !rest.is_empty() {
        return Err(PageError::TrailingBytes);
    }

    Ok(Page {
        size: decode_size(size_bytes)?,
        cookie: cookie.to_vec(),
    })
}

fn decode_size(bytes: &[u8]) -> Result<u32, PageError> {
    if bytes.is_empty() {
        return Err(PageError::MissingSize);
    }
    if bytes[0] & 0x80 != 0 {
        return Err(PageError::NegativeSize);
    }
    if bytes.len() > 8 {
        return Err(PageError::SizeOverflow);
    }

    let mut value: u64 = 0;
    for byte in bytes {
        value = (value << 8) | *byte as u64;
    }

    u32::try_from(value).map_err(|_| PageError::SizeOverflow)
}

fn read_tlv(bytes: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8]), PageError> {
    let tag = *bytes.first().ok_or(PageError::Truncated)?;
    if tag != expected_tag {
        return Err(match expected_tag {
            SEQUENCE_TAG => PageError::NotSequence,
            INTEGER_TAG => PageError::MissingSize,
            _ => PageError::MissingCookie,
        });
    }

    let (length, rest) = read_length(&bytes[1..])?;
    if rest.len() < length {
        return Err(PageError::Truncated);
    }
    Ok((&rest[..length], &rest[length..]))
}

fn read_length(bytes: &[u8]) -> Result<(usize, &[u8]), PageError> {
    let first = *bytes.first().ok_or(PageError::Truncated)?;
    if first == 0x80 {
        return Err(PageError::UnsupportedLength);
    }
    if first < 0x80 {
        return Ok((first as usize, &bytes[1..]));
    }

    let octets = (first & 0x7f) as usize;
    if octets > 4 || bytes.len() < 1 + octets {
        return Err(PageError::Truncated);
    }
    let length = bytes[1..1 + octets]
        .iter()
        .fold(0usize, |acc, byte| (acc << 8) | *byte as usize);
    Ok((length, &bytes[1 + octets..]))
}

fn encode_integer(value: u32) -> Vec<u8> {
    let mut content = value.to_be_bytes().to_vec();
    while content.len() > 1 && content[0] == 0 && content[1] & 0x80 == 0 {
        content.remove(0);
    }
    // A leading high bit would read as a negative number in BER.
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    let mut out = vec![INTEGER_TAG];
    out.extend_from_slice(&encode_length(content.len()));
    out.extend_from_slice(&content);
    out
}

fn encode_octet_string(value: &[u8]) -> Vec<u8> {
    let mut out = vec![OCTET_STRING_TAG];
    out.extend_from_slice(&encode_length(value.len()));
    out.extend_from_slice(value);
    out
}

fn encode_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let bytes: Vec<u8> = length
        .to_be_bytes()
        .into_iter()
        .skip_while(|byte| *byte == 0)
        .collect();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend_from_slice(&bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cookie_has_the_known_wire_form() {
        assert_eq!(
            encode(&Page::new(0, Vec::new())),
            vec![0x30, 0x05, 0x02, 0x01, 0x00, 0x04, 0x00]
        );
    }

    #[test]
    fn size_and_cookie_are_encoded_in_order() {
        assert_eq!(
            encode(&Page::new(500, b"next".to_vec())),
            vec![
                0x30, 0x0a, 0x02, 0x02, 0x01, 0xf4, 0x04, 0x04, b'n', b'e', b'x', b't'
            ]
        );
    }

    #[test]
    fn round_trip_keeps_size_and_cookie() {
        let page = Page::new(1234, b"cookie-value".to_vec());

        assert_eq!(decode(&encode(&page)), Ok(page));
    }

    #[test]
    fn large_size_uses_long_form_inside_the_sequence() {
        let page = Page::new(u32::MAX, Vec::new());
        let encoded = encode(&page);

        assert_eq!(decode(&encoded), Ok(page));
        assert_eq!(&encoded[..4], &[0x30, 0x09, 0x02, 0x05]);
    }

    #[test]
    fn large_cookie_uses_long_form_length() {
        let page = Page::new(10, vec![0x7f; 200]);
        let encoded = encode(&page);

        assert_eq!(decode(&encoded), Ok(page));
    }

    #[test]
    fn missing_sequence_tag_is_rejected() {
        assert_eq!(
            decode(&[0x31, 0x05, 0x02, 0x01, 0x00, 0x04, 0x00]),
            Err(PageError::NotSequence)
        );
    }

    #[test]
    fn missing_cookie_is_rejected() {
        assert_eq!(
            decode(&[0x30, 0x03, 0x02, 0x01, 0x00]),
            Err(PageError::MissingCookie)
        );
    }

    #[test]
    fn missing_size_is_rejected() {
        assert_eq!(
            decode(&[0x30, 0x03, 0x04, 0x01, b'x']),
            Err(PageError::MissingSize)
        );
    }

    #[test]
    fn negative_size_is_rejected() {
        assert_eq!(
            decode(&[0x30, 0x06, 0x02, 0x02, 0xff, 0xff, 0x04, 0x00]),
            Err(PageError::NegativeSize)
        );
    }

    #[test]
    fn size_over_32_bits_is_rejected() {
        assert_eq!(
            decode(&[
                0x30, 0x09, 0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00
            ]),
            Err(PageError::SizeOverflow)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert_eq!(
            decode(&[0x30, 0x07, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00]),
            Err(PageError::TrailingBytes)
        );
        assert_eq!(
            decode(&[0x30, 0x05, 0x02, 0x01, 0x00, 0x04, 0x00, 0xaa]),
            Err(PageError::TrailingBytes)
        );
    }

    #[test]
    fn truncated_value_is_rejected() {
        assert_eq!(decode(&[]), Err(PageError::Truncated));
        assert_eq!(decode(&[0x30]), Err(PageError::Truncated));
        assert_eq!(decode(&[0x30, 0x05, 0x02]), Err(PageError::Truncated));
        assert_eq!(
            decode(&[0x30, 0x06, 0x02, 0x01, 0x00, 0x04, 0x05]),
            Err(PageError::Truncated)
        );
    }

    #[test]
    fn indefinite_length_is_rejected() {
        assert_eq!(
            decode(&[0x30, 0x80, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00]),
            Err(PageError::UnsupportedLength)
        );
    }

    #[test]
    fn requested_only_when_a_positive_size_is_asked_for() {
        assert!(Page::new(1, Vec::new()).is_requested());
        assert!(!Page::new(0, Vec::new()).is_requested());
    }
}
