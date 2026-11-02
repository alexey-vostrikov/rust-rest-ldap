//! Server-side sort and virtual list view (RFC 2891, draft-ietf-ldapext-ldapv3-vlv).
//!
//! Two controls that a client sends together more often than apart: sort makes the server
//! return the entries in an order, and VLV asks for a window into that order ("show me
//! entries 41..60 starting at the one whose `cn` is closest to `M`"). A web address book
//! uses exactly that: sorted by name, scrolled thirty at a time.
//!
//! Both are controls, not operations, so they change what a search returns without a new
//! protocol exchange. The sort control may also be **critical**: a client that cannot bear
//! an unsorted answer sets that bit, and the server must then refuse rather than return
//! something the client will render in the wrong order.
//!
//! The sort key comparison follows the matching rules of the schema where they matter, but
//! only to the extent this server has them: `caseIgnoreMatch` for text, numeric order for
//! integers, byte order otherwise. A sort that ignored the schema would order `uidNumber`
//! as text, where "10" comes before "9".
//!
//! The VLV control's assertion form is deliberately not supported: RFC 2891 leaves the
//! "greater or equal" form to the same control, and answering it wrongly would be worse
//! than answering `unavailableCriticalExtension`.

use std::cmp::Ordering;

use thiserror::Error;

use crate::model::Entry;

/// Sort request control (RFC 2891).
pub const SORT_OID: &str = "1.2.840.113556.1.4.473";
/// Sort response control (RFC 2891).
pub const SORT_RESPONSE_OID: &str = "1.2.840.113556.1.4.474";
/// Virtual list view request control.
pub const VLV_OID: &str = "2.16.840.1.113730.3.4.9";
/// Virtual list view response control.
pub const VLV_RESPONSE_OID: &str = "2.16.840.1.113730.3.4.10";

const SEQUENCE_TAG: u8 = 0x30;
const SET_TAG: u8 = 0x31;
const OCTET_STRING_TAG: u8 = 0x04;
const INTEGER_TAG: u8 = 0x02;
const ENUMERATED_TAG: u8 = 0x0a;
const BOOLEAN_TAG: u8 = 0x01;
const CONTEXT_0: u8 = 0x80;
const CONTEXT_1: u8 = 0x81;
const CONTEXT_2: u8 = 0x82;

/// One sort key: an attribute and a direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortKey {
    /// Attribute description, as the client wrote it.
    pub attribute: String,
    /// `orderingRule` from the control, if any. Recognised values are applied; an
    /// unrecognised one makes the sort fail, because silently ignoring it would order the
    /// result differently from what the client asked for.
    pub ordering_rule: Option<String>,
    /// Descending when true (the control's `reverseOrder`).
    pub reverse: bool,
}

/// The parsed sort control.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SortRequest {
    pub keys: Vec<SortKey>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlError {
    #[error("control value is not a BER sequence")]
    NotSequence,
    #[error("control value is truncated")]
    Truncated,
    #[error("control value has trailing bytes")]
    TrailingBytes,
    #[error("unsupported BER length form")]
    UnsupportedLength,
    #[error("unexpected element with tag 0x{0:02x}")]
    UnexpectedTag(u8),
    #[error("the sort control is empty: at least one key is required")]
    NoKeys,
    #[error("unknown ordering rule '{0}'")]
    UnknownOrderingRule(String),
    #[error("the VLV control has no target")]
    MissingTarget,
    #[error("the VLV control has neither a count nor a context id")]
    MissingCountOrContext,
    #[error("the VLV control asserts 'greater or equal', which this server does not support")]
    AssertionForm,
}

/// A window into the sorted result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VirtualList {
    /// Offset of the window's first entry in the whole result, zero based.
    pub offset: u32,
    /// Entries the client wants before the target.
    pub before: u32,
    /// Entries the client wants after the target.
    pub after: u32,
    /// The value to start from, in the "greater or equal" form. Kept only so the parser
    /// can say precisely why it refuses it.
    pub assertion: Option<String>,
    /// Server-side context identifier from an earlier response; zero means "start here".
    pub context: Vec<u8>,
}

/// Result code the sort control may report (RFC 2891 §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortResult {
    Success = 0,
    OperationsError = 1,
    TimeLimitExceeded = 3,
    StrongerAuthRequired = 8,
    AdminLimitExceeded = 11,
    NoSuchAttribute = 16,
    InappropriateMatching = 18,
    InsufficientAccessRights = 50,
    Other = 80,
}

impl SortResult {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// The sort response control: the result code and, on failure, the offending attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortResponse {
    pub result: SortResult,
    pub attribute: Option<String>,
}

impl SortResponse {
    pub fn ok() -> Self {
        Self {
            result: SortResult::Success,
            attribute: None,
        }
    }

    pub fn failed(result: SortResult, attribute: Option<&str>) -> Self {
        Self {
            result,
            attribute: attribute.map(str::to_string),
        }
    }

    /// `SEQUENCE { sortResult ENUMERATED, attributeType [0] OPTIONAL }`.
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = vec![ENUMERATED_TAG, 0x01, self.result.as_u8()];

        if let Some(attribute) = &self.attribute {
            let bytes = attribute.as_bytes();
            inner.push(CONTEXT_0);
            push_length(&mut inner, bytes.len());
            inner.extend_from_slice(bytes);
        }

        let mut out = vec![SEQUENCE_TAG];
        push_length(&mut out, inner.len());
        out.extend_from_slice(&inner);
        out
    }
}

/// The VLV response control: where the window actually landed and how big the whole list is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualListResponse {
    pub target_position: u32,
    pub content_count: u32,
    pub result: SortResult,
    pub context: Vec<u8>,
}

impl VirtualList {
    /// Half open range `[from, to)` of the sorted list that this window asks for.
    ///
    /// The target itself is always inside the window, so a client that asks for ten
    /// before and nothing after still gets its entry.
    pub fn window(&self, len: usize) -> (usize, usize) {
        let target = (self.offset as usize).min(len);
        let from = target.saturating_sub(self.before as usize);
        let to = (target + self.after as usize + 1).min(len);
        (from, to)
    }

    /// Position of the target in the whole result, one based as RFC 2891 reports it.
    pub fn target_position(&self, len: usize) -> u32 {
        (self.offset as usize).min(len) as u32 + 1
    }
}

impl VirtualListResponse {
    /// `SEQUENCE { targetPosition INTEGER, contentCount INTEGER, virtualListViewResult
    /// ENUMERATED, contextID OCTET STRING OPTIONAL }`.
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        push_integer(&mut inner, self.target_position);
        push_integer(&mut inner, self.content_count);
        inner.extend_from_slice(&[ENUMERATED_TAG, 0x01, self.result.as_u8()]);

        if !self.context.is_empty() {
            inner.push(OCTET_STRING_TAG);
            push_length(&mut inner, self.context.len());
            inner.extend_from_slice(&self.context);
        }

        let mut out = vec![SEQUENCE_TAG];
        push_length(&mut out, inner.len());
        out.extend_from_slice(&inner);
        out
    }
}

/// Decodes the sort control value.
pub fn decode_sort(value: &[u8]) -> Result<SortRequest, ControlError> {
    let mut reader = Reader::new(value);
    let body = reader.sequence()?;
    if !reader.is_empty() {
        return Err(ControlError::TrailingBytes);
    }

    let mut inner = Reader::new(body);
    let keys_body = inner.set()?;
    if !inner.is_empty() {
        // The control has an optional `criticality`-like tail in some dialects; this
        // server does not use it, and ignoring it silently would be a guess.
        return Err(ControlError::TrailingBytes);
    }

    let mut keys = Vec::new();
    let mut keys_reader = Reader::new(keys_body);
    while !keys_reader.is_empty() {
        let key_body = keys_reader.sequence()?;
        let mut key_reader = Reader::new(key_body);

        let attribute = String::from_utf8_lossy(key_reader.octet_string()?).into_owned();
        let mut key = SortKey {
            attribute,
            ordering_rule: None,
            reverse: false,
        };

        // Optional `orderingRule` and `reverseOrder` follow, in that order.
        if !key_reader.is_empty() && key_reader.peek() == Some(OCTET_STRING_TAG) {
            let rule = String::from_utf8_lossy(key_reader.octet_string()?).into_owned();
            key.ordering_rule = Some(rule);
        }
        if !key_reader.is_empty() && key_reader.peek() == Some(BOOLEAN_TAG) {
            key.reverse = key_reader.boolean()?;
        }
        if !key_reader.is_empty() {
            return Err(ControlError::UnexpectedTag(key_reader.peek().unwrap_or(0)));
        }

        keys.push(key);
    }

    if keys.is_empty() {
        return Err(ControlError::NoKeys);
    }

    Ok(SortRequest { keys })
}

/// Decodes the VLV control value.
/// Encodes a sort control (RFC 2891 §2.4).
///
/// The mirror of `decode_sort`, and the only reason both exist: a client that can write the
/// control and a server that can read it are the two halves of the same agreement, and
/// testing the round trip catches a length that is off by one before a client meets a real
/// server.
pub fn encode_sort(request: &SortRequest) -> Vec<u8> {
    let mut keys = Vec::new();

    for key in &request.keys {
        let mut body = Vec::new();
        // The attribute is a `longName`, an OCTET STRING inside the sequence.
        body.push(OCTET_STRING_TAG);
        body.extend(encode_length(key.attribute.len()));
        body.extend_from_slice(key.attribute.as_bytes());

        if let Some(rule) = &key.ordering_rule {
            body.push(CONTEXT_0);
            body.extend(encode_length(rule.len()));
            body.extend_from_slice(rule.as_bytes());
        }

        if key.reverse {
            // `reverseOrder` is a BOOLEAN, and only `true` is ever written: absent and
            // `false` mean the same thing, and BER prefers the shorter form.
            body.push(BOOLEAN_TAG);
            body.push(1);
            body.push(0xff);
        }

        keys.push(SEQUENCE_TAG);
        keys.extend(encode_length(body.len()));
        keys.extend_from_slice(&body);
    }

    let mut set = vec![SET_TAG];
    set.extend(encode_length(keys.len()));
    set.extend_from_slice(&keys);

    let mut out = vec![SEQUENCE_TAG];
    out.extend(encode_length(set.len()));
    out.extend_from_slice(&set);

    out
}

/// BER length octets: short form below 128, long form above.
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

pub fn decode_vlv(value: &[u8]) -> Result<VirtualList, ControlError> {
    let mut reader = Reader::new(value);
    let body = reader.sequence()?;
    if !reader.is_empty() {
        return Err(ControlError::TrailingBytes);
    }

    let mut inner = Reader::new(body);
    if inner.is_empty() {
        return Err(ControlError::MissingTarget);
    }

    // `beforeCount` and `afterCount` come first, then the target.
    let before = inner.integer()?;
    let after_count = inner.integer()?;

    if inner.is_empty() {
        return Err(ControlError::MissingCountOrContext);
    }

    match inner.peek() {
        Some(CONTEXT_1) => {
            // `byOffset [1] SEQUENCE { offset INTEGER, contentCount INTEGER OPTIONAL }`.
            inner.advance();
            let target = inner.with_length()?;
            let mut target_reader = Reader::new(target);
            let offset = target_reader.integer()?;
            if !target_reader.is_empty() {
                // A content count, which this server does not need: the whole sorted list
                // is in hand, so the count is a hint rather than a requirement. It still
                // has to parse, or the control is malformed rather than merely redundant.
                let _content_count = target_reader.integer()?;
            }
            if !target_reader.is_empty() {
                return Err(ControlError::TrailingBytes);
            }

            let context = if !inner.is_empty() && inner.peek() == Some(OCTET_STRING_TAG) {
                inner.octet_string()?.to_vec()
            } else {
                Vec::new()
            };

            if !inner.is_empty() {
                return Err(ControlError::TrailingBytes);
            }

            Ok(VirtualList {
                offset: offset.max(0) as u32,
                before: before.max(0) as u32,
                after: after_count.max(0) as u32,
                assertion: None,
                context,
            })
        }
        Some(CONTEXT_2) => Err(ControlError::AssertionForm),
        Some(other) => Err(ControlError::UnexpectedTag(other)),
        None => Err(ControlError::MissingCountOrContext),
    }
}

/// Sorts `entries` in place by `request`.
///
/// An attribute that some entry does not have sorts as the empty string, which puts those
/// entries last in an ascending order: putting them first would make "entries without a
/// phone number" head the list an operator looks at.
pub fn sort_entries(entries: &mut [Entry], request: &SortRequest) -> Result<(), ControlError> {
    // Validate the ordering rules before touching the order: a rule this server does not
    // know must fail the sort rather than produce a plausible but different order.
    check_rules(request)?;

    entries.sort_by(|left, right| compare_by_keys(left, right, &request.keys));
    Ok(())
}

fn is_supported_rule(rule: &str) -> bool {
    matches!(
        rule.to_ascii_lowercase().as_str(),
        "caseignorematch"
            | "caseignoreorderingmatch"
            | "caseexactmatch"
            | "caseexactorderingmatch"
            | "integermatch"
            | "integerorderingmatch"
            | "octetstringmatch"
            | "octetstringorderingmatch"
            | "generalizedtimeorderingmatch"
    )
}

/// Orders two `(DN, attributes)` pairs, which is what a search carries.
///
/// Separate from [`sort_entries`] so the search can sort its own list without building
/// temporary `Entry` values for every comparison.
pub fn compare_attributes(
    left_dn: &str,
    left: &crate::model::Attributes,
    right_dn: &str,
    right: &crate::model::Attributes,
    keys: &[SortKey],
) -> Ordering {
    for key in keys {
        let ordering = compare_values_of(left, right, key);
        let ordering = if key.reverse {
            ordering.reverse()
        } else {
            ordering
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    left_dn.cmp(right_dn)
}

/// Validates the ordering rules of a request without sorting anything.
pub fn check_rules(request: &SortRequest) -> Result<(), ControlError> {
    for key in &request.keys {
        if let Some(rule) = key
            .ordering_rule
            .as_ref()
            .filter(|rule| !is_supported_rule(rule))
        {
            return Err(ControlError::UnknownOrderingRule(rule.clone()));
        }
    }
    Ok(())
}

fn compare_by_keys(left: &Entry, right: &Entry, keys: &[SortKey]) -> Ordering {
    for key in keys {
        let ordering = compare_attribute(left, right, key);
        let ordering = if key.reverse {
            ordering.reverse()
        } else {
            ordering
        };

        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    // A stable, total order: without a tie-break the same search could return two entries
    // in either order, and a client paging through the result would see one twice or miss
    // one entirely.
    left.dn().cmp(right.dn())
}

fn compare_attribute(left: &Entry, right: &Entry, key: &SortKey) -> Ordering {
    let left_value = first_value(left, &key.attribute);
    let right_value = first_value(right, &key.attribute);

    match (left_value, right_value) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left_value), Some(right_value)) => compare_values(&left_value, &right_value, key),
    }
}

fn first_value(entry: &Entry, attribute: &str) -> Option<String> {
    first_of(entry.attributes(), attribute)
}

fn first_of(attributes: &crate::model::Attributes, attribute: &str) -> Option<String> {
    attributes
        .get(attribute)
        .and_then(|attribute| attribute.values.first().cloned())
}

/// The same rule as [`compare_attribute`], on bare attribute sets.
fn compare_values_of(
    left: &crate::model::Attributes,
    right: &crate::model::Attributes,
    key: &SortKey,
) -> Ordering {
    let left_value = first_of(left, &key.attribute);
    let right_value = first_of(right, &key.attribute);

    match (left_value, right_value) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left_value), Some(right_value)) => compare_values(&left_value, &right_value, key),
    }
}

/// Orders two values the way the schema says, not the way bytes happen to fall.
fn compare_values(left: &str, right: &str, key: &SortKey) -> Ordering {
    let numeric = key
        .ordering_rule
        .as_deref()
        .map(|rule| {
            let rule = rule.to_ascii_lowercase();
            rule.contains("integer")
        })
        .unwrap_or_else(|| looks_numeric(left) && looks_numeric(right));

    let case_sensitive = key
        .ordering_rule
        .as_deref()
        .map(|rule| rule.to_ascii_lowercase().contains("exact"))
        .unwrap_or(false);

    order_values(left, right, numeric, case_sensitive)
}

/// The one ordering the whole server uses: numeric when both sides are numbers, folded text
/// otherwise.
///
/// Shared with the filter's `>=` and `<=` on purpose. Two implementations of "which of these
/// is greater" would agree until the day one of them gained a rule the other did not, and a
/// search would then sort one way and select another.
pub(crate) fn order_values(
    left: &str,
    right: &str,
    numeric: bool,
    case_sensitive: bool,
) -> Ordering {
    if numeric && let (Ok(left), Ok(right)) = (left.parse::<i64>(), right.parse::<i64>()) {
        return left.cmp(&right);
    }

    if case_sensitive {
        left.cmp(right)
    } else {
        // Folding for comparison only: the values themselves are untouched.
        left.to_lowercase().cmp(&right.to_lowercase())
    }
}

/// Whether a value is a plain integer, which is what makes a comparison numeric.
pub(crate) fn looks_numeric(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn push_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(length as u8);
        return;
    }

    let bytes: Vec<u8> = length
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0)
        .collect();
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(&bytes);
}

fn push_integer(out: &mut Vec<u8>, value: u32) {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let content = &bytes[first..];

    // A leading high bit would read as negative, so a zero octet goes in front.
    if content[0] & 0x80 != 0 {
        out.push(INTEGER_TAG);
        push_length(out, content.len() + 1);
        out.push(0);
        out.extend_from_slice(content);
    } else {
        out.push(INTEGER_TAG);
        push_length(out, content.len());
        out.extend_from_slice(content);
    }
}

/// Minimal BER reader for control values: definite lengths only.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.first().copied()
    }

    fn advance(&mut self) {
        self.bytes = &self.bytes[1..];
    }

    fn expect(&mut self, tag: u8) -> Result<(), ControlError> {
        match self.peek() {
            Some(found) if found == tag => {
                self.advance();
                Ok(())
            }
            Some(found) => Err(ControlError::UnexpectedTag(found)),
            None => Err(ControlError::Truncated),
        }
    }

    fn sequence(&mut self) -> Result<&'a [u8], ControlError> {
        self.expect(SEQUENCE_TAG)?;
        self.with_length()
    }

    fn set(&mut self) -> Result<&'a [u8], ControlError> {
        self.expect(SET_TAG)?;
        self.with_length()
    }

    fn octet_string(&mut self) -> Result<&'a [u8], ControlError> {
        self.expect(OCTET_STRING_TAG)?;
        self.with_length()
    }

    fn integer(&mut self) -> Result<i64, ControlError> {
        match self.peek() {
            Some(INTEGER_TAG) | Some(ENUMERATED_TAG) => self.advance(),
            Some(found) => return Err(ControlError::UnexpectedTag(found)),
            None => return Err(ControlError::Truncated),
        }

        let content = self.with_length()?;
        if content.is_empty() || content.len() > 8 {
            return Err(ControlError::Truncated);
        }

        let mut value: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
        for byte in content {
            value = (value << 8) | *byte as i64;
        }
        Ok(value)
    }

    fn boolean(&mut self) -> Result<bool, ControlError> {
        self.expect(BOOLEAN_TAG)?;
        let content = self.with_length()?;
        if content.len() != 1 {
            return Err(ControlError::Truncated);
        }
        Ok(content[0] != 0)
    }

    fn with_length(&mut self) -> Result<&'a [u8], ControlError> {
        let first = self.bytes.first().copied().ok_or(ControlError::Truncated)?;
        self.advance();

        let length = if first & 0x80 == 0 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 {
                return Err(ControlError::UnsupportedLength);
            }
            if self.bytes.len() < count {
                return Err(ControlError::Truncated);
            }

            let mut length = 0usize;
            for byte in &self.bytes[..count] {
                length = (length << 8) | *byte as usize;
            }
            self.bytes = &self.bytes[count..];
            length
        };

        if self.bytes.len() < length {
            return Err(ControlError::Truncated);
        }
        let (head, tail) = self.bytes.split_at(length);
        self.bytes = tail;
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, Attributes};

    fn entry(dn: &str, pairs: &[(&str, &str)]) -> Entry {
        let mut attributes = Attributes::new();
        for (name, value) in pairs {
            attributes = attributes.push(Attribute::single(*name, value));
        }
        Entry::new(dn, attributes)
    }

    fn sort_request(keys: &[(&str, bool)]) -> SortRequest {
        SortRequest {
            keys: keys
                .iter()
                .map(|(attribute, reverse)| SortKey {
                    attribute: (*attribute).to_string(),
                    ordering_rule: None,
                    reverse: *reverse,
                })
                .collect(),
        }
    }

    fn dns(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.dn()).collect()
    }

    #[test]
    fn a_single_key_sorts_ascending() {
        let mut entries = vec![
            entry("cn=c", &[("cn", "carol")]),
            entry("cn=a", &[("cn", "alice")]),
            entry("cn=b", &[("cn", "bob")]),
        ];

        sort_entries(&mut entries, &sort_request(&[("cn", false)])).expect("sort");

        assert_eq!(dns(&entries), vec!["cn=a", "cn=b", "cn=c"]);
    }

    #[test]
    fn reverse_order_sorts_descending() {
        let mut entries = vec![
            entry("cn=a", &[("cn", "alice")]),
            entry("cn=c", &[("cn", "carol")]),
            entry("cn=b", &[("cn", "bob")]),
        ];

        sort_entries(&mut entries, &sort_request(&[("cn", true)])).expect("sort");

        assert_eq!(dns(&entries), vec!["cn=c", "cn=b", "cn=a"]);
    }

    #[test]
    fn text_comparison_folds_case() {
        // Without folding, every upper-case name would sort before every lower-case one.
        let mut entries = vec![
            entry("cn=1", &[("cn", "beta")]),
            entry("cn=2", &[("cn", "Alpha")]),
            entry("cn=3", &[("cn", "gamma")]),
        ];

        sort_entries(&mut entries, &sort_request(&[("cn", false)])).expect("sort");

        assert_eq!(dns(&entries), vec!["cn=2", "cn=1", "cn=3"]);
    }

    #[test]
    fn numbers_sort_as_numbers_when_the_rule_says_so() {
        // Text order would put "10" before "9", which is the bug this rule prevents.
        let mut entries = vec![
            entry("cn=10", &[("uidNumber", "10")]),
            entry("cn=9", &[("uidNumber", "9")]),
            entry("cn=100", &[("uidNumber", "100")]),
        ];

        let request = SortRequest {
            keys: vec![SortKey {
                attribute: "uidNumber".to_string(),
                ordering_rule: Some("integerOrderingMatch".to_string()),
                reverse: false,
            }],
        };
        sort_entries(&mut entries, &request).expect("sort");

        assert_eq!(dns(&entries), vec!["cn=9", "cn=10", "cn=100"]);
    }

    #[test]
    fn numeric_values_sort_numerically_without_an_explicit_rule() {
        // The values parse as integers, so guessing less than the client asked for would
        // produce the surprising order for no reason.
        let mut entries = vec![
            entry("cn=10", &[("uidNumber", "10")]),
            entry("cn=9", &[("uidNumber", "9")]),
        ];

        sort_entries(&mut entries, &sort_request(&[("uidNumber", false)])).expect("sort");

        assert_eq!(dns(&entries), vec!["cn=9", "cn=10"]);
    }

    #[test]
    fn an_exact_rule_does_not_fold_case() {
        let mut entries = vec![
            entry("cn=1", &[("cn", "beta")]),
            entry("cn=2", &[("cn", "Alpha")]),
        ];

        let request = SortRequest {
            keys: vec![SortKey {
                attribute: "cn".to_string(),
                ordering_rule: Some("caseExactOrderingMatch".to_string()),
                reverse: false,
            }],
        };
        sort_entries(&mut entries, &request).expect("sort");

        assert_eq!(
            dns(&entries),
            vec!["cn=2", "cn=1"],
            "in byte order 'A' comes before 'b'"
        );
    }

    #[test]
    fn a_missing_attribute_sorts_last() {
        let mut entries = vec![
            entry("cn=1", &[("cn", "alice")]),
            entry("cn=2", &[("cn", "bob"), ("telephoneNumber", "+7")]),
            entry("cn=3", &[("cn", "carol")]),
        ];

        sort_entries(&mut entries, &sort_request(&[("telephoneNumber", false)])).expect("sort");

        assert_eq!(
            dns(&entries),
            vec!["cn=2", "cn=1", "cn=3"],
            "the entry that has the attribute comes first"
        );
    }

    #[test]
    fn several_keys_break_ties_in_order() {
        let mut entries = vec![
            entry("cn=1", &[("sn", "doe"), ("cn", "bob")]),
            entry("cn=2", &[("sn", "doe"), ("cn", "alice")]),
            entry("cn=3", &[("sn", "smith"), ("cn", "zed")]),
        ];

        sort_entries(&mut entries, &sort_request(&[("sn", false), ("cn", false)])).expect("sort");

        assert_eq!(
            dns(&entries),
            vec!["cn=2", "cn=1", "cn=3"],
            "alice before bob within doe, and smith last"
        );
    }

    #[test]
    fn the_dn_breaks_a_total_tie() {
        let mut entries = vec![
            entry("cn=b", &[("cn", "same")]),
            entry("cn=a", &[("cn", "same")]),
        ];

        sort_entries(&mut entries, &sort_request(&[("cn", false)])).expect("sort");

        assert_eq!(
            dns(&entries),
            vec!["cn=a", "cn=b"],
            "without a tie-break two identical searches could return different orders"
        );
    }

    #[test]
    fn an_unknown_ordering_rule_fails_the_sort() {
        let mut entries = vec![entry("cn=a", &[("cn", "alice")])];
        let request = SortRequest {
            keys: vec![SortKey {
                attribute: "cn".to_string(),
                ordering_rule: Some("madeUpMatch".to_string()),
                reverse: false,
            }],
        };

        assert_eq!(
            sort_entries(&mut entries, &request),
            Err(ControlError::UnknownOrderingRule("madeUpMatch".to_string())),
            "a rule the server does not know must not be silently replaced with another"
        );
    }

    #[test]
    fn an_empty_key_list_is_refused() {
        assert_eq!(
            decode_sort(&[0x30, 0x02, 0x31, 0x00]),
            Err(ControlError::NoKeys)
        );
    }

    #[test]
    fn the_sort_response_encodes_the_result_code() {
        let encoded = SortResponse::ok().encode();

        assert_eq!(encoded, vec![0x30, 0x03, 0x0a, 0x01, 0x00]);
    }

    #[test]
    fn a_failed_sort_response_names_the_attribute() {
        let encoded = SortResponse::failed(SortResult::NoSuchAttribute, Some("cn")).encode();

        assert_eq!(
            encoded,
            vec![0x30, 0x07, 0x0a, 0x01, 0x10, 0x80, 0x02, b'c', b'n'],
            "the sequence holds seven content octets"
        );
    }

    #[test]
    fn the_vlv_response_encodes_position_and_count() {
        let encoded = VirtualListResponse {
            target_position: 1,
            content_count: 100,
            result: SortResult::Success,
            context: Vec::new(),
        }
        .encode();

        assert_eq!(
            encoded,
            vec![
                0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x64, 0x0a, 0x01, 0x00
            ]
        );
    }

    #[test]
    fn a_large_integer_gets_a_leading_zero_when_needed() {
        // 0x80 as a single octet would read as -128; the encoder has to prepend a zero.
        let encoded = VirtualListResponse {
            target_position: 128,
            content_count: 0,
            result: SortResult::Success,
            context: Vec::new(),
        }
        .encode();

        assert!(
            encoded
                .windows(3)
                .any(|window| window == [0x02, 0x02, 0x00]),
            "the integer 128 must be encoded with a leading zero: {encoded:02x?}"
        );
    }

    #[test]
    fn an_assertion_form_vlv_is_refused_rather_than_guessed() {
        // SEQUENCE { before 0, after 0, byGreaterThanOrEqual [2] "M" }
        let value = vec![
            0x30, 0x09, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x82, 0x01, b'M',
        ];

        assert_eq!(decode_vlv(&value), Err(ControlError::AssertionForm));
    }

    #[test]
    fn a_by_offset_vlv_is_read_as_a_window() {
        // SEQUENCE { before 10, after 19, byOffset [1] { offset 40 } }
        let primitive = vec![
            0x30, 0x0b, 0x02, 0x01, 0x0a, 0x02, 0x01, 0x13, 0x81, 0x03, 0x02, 0x01, 0x28,
        ];

        let list = decode_vlv(&primitive).expect("decoded");

        assert_eq!(list.offset, 40);
        assert_eq!(list.before, 10);
        assert_eq!(list.after, 19);
        assert_eq!(
            list.window(100),
            (30, 60),
            "ten before the target, the target, and nineteen after"
        );
        assert_eq!(list.target_position(100), 41, "one based, as RFC 2891 says");
    }
}
