//! RFC 4533 content synchronisation: the controls, and what a state means.
//!
//! A client that holds a copy of the directory asks "what does it hold now, and what changed
//! since this cookie", and this module is the vocabulary for both answers.
//!
//! ```text
//! syncRequestValue ::= SEQUENCE {
//!      mode       ENUMERATED { refreshOnly (1), refreshAndPersist (3) },
//!      cookie     syncCookie OPTIONAL,
//!      reloadHint BOOLEAN DEFAULT FALSE }
//!
//! syncStateValue ::= SEQUENCE {
//!      state     ENUMERATED { present (0), add (1), modify (2), delete (3) },
//!      entryUUID syncUUID,
//!      cookie    syncCookie OPTIONAL }
//!
//! syncDoneValue ::= SEQUENCE {
//!      cookie         syncCookie OPTIONAL,
//!      refreshDeletes BOOLEAN DEFAULT FALSE }
//!
//! syncUUID ::= OCTET STRING (SIZE(16))
//! ```
//!
//! **What this server does not do, and says so rather than approximating it:** it answers
//! `refreshOnly`. `refreshAndPersist` needs a persistent search that keeps pushing entries as
//! they change, which is a second protocol mode living in the same connection loop; asking for it
//! is refused with `syncRefreshRequired` (RFC 4533 §2.5), which is the code that exists for
//! exactly this - "start again in a mode I can serve".
//!
//! **The cookie is a position in a walk, not a change number.** This server keeps no history of
//! deletions: the backend is read as a whole, and an entry that is gone leaves no trace. So a
//! resume cannot answer "what was removed since", and a client that needs deletions must take the
//! full refresh - which is what `refreshOnly` means and what the cookie documents.

use rasn_ldap::Control;
use rasn_ldap::LdapOid;

/// `syncRequest` / `syncState` / `syncDone` control OID (RFC 4533 §2.1).
pub const SYNC_OID: &str = "1.3.6.1.4.1.4203.1.9.1.1";

const SEQUENCE_TAG: u8 = 0x30;
const ENUMERATED_TAG: u8 = 0x0a;
const OCTET_STRING_TAG: u8 = 0x04;
/// `SET OF` - a `syncUUIDs` is a set, and its tag says so.
const SET_TAG: u8 = 0x31;

const BOOLEAN_TAG: u8 = 0x01;

/// What the client asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Answer with the state now, then finish.
    RefreshOnly,
    /// Answer with the state now, then keep sending changes on the same connection.
    RefreshAndPersist,
}

impl Mode {
    fn as_u8(self) -> u8 {
        match self {
            // RFC 4533 §2.5: 1 = refreshOnly, 3 = refreshAndPersist. Two is not skipped by
            // mistake - the numbering is the protocol's.
            Mode::RefreshOnly => 1,
            Mode::RefreshAndPersist => 3,
        }
    }
}

/// The state of one entry in the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// The entry is in the client's copy already and unchanged as far as this answer knows.
    Present,
    /// The entry is new.
    Add,
    /// The entry changed.
    Modify,
    /// The entry was removed.
    Delete,
}

impl State {
    fn as_u8(self) -> u8 {
        match self {
            State::Present => 0,
            State::Add => 1,
            State::Modify => 2,
            State::Delete => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequest {
    pub mode: Mode,
    /// The cookie the client already has, if any.
    pub cookie: Option<Vec<u8>>,
    /// The client is telling the server to re-send everything rather than trust the cookie.
    pub reload_hint: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SyncError {
    NotSequence,
    Truncated,
    TrailingBytes,
    UnsupportedMode(i64),
    UnexpectedTag(u8),
    UnknownState(i64),
    /// A `syncUUID` is sixteen octets (RFC 4533 §2.6).
    WrongUuidLength(usize),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::NotSequence => write!(formatter, "the value is not a SEQUENCE"),
            SyncError::Truncated => write!(formatter, "the value is truncated"),
            SyncError::TrailingBytes => write!(formatter, "the value has trailing bytes"),
            SyncError::UnsupportedMode(mode) => {
                write!(
                    formatter,
                    "mode {mode} is neither refreshOnly (1) nor refreshAndPersist (3)"
                )
            }
            SyncError::UnexpectedTag(tag) => {
                write!(formatter, "unexpected element with tag 0x{tag:02x}")
            }
            SyncError::UnknownState(state) => write!(formatter, "unknown sync state {state}"),
            SyncError::WrongUuidLength(length) => {
                write!(formatter, "a syncUUID is 16 octets, this one is {length}")
            }
        }
    }
}

impl std::error::Error for SyncError {}

/// A minimal BER reader, scoped to these three small structures.
///
/// Written out rather than shared with the sort codec on purpose: those two learned that a
/// decoder written against the same mistaken idea as its encoder agrees with itself and with
/// nobody else. Separate readers mean a mistake has to be made twice to hide.
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

    fn expect(&mut self, tag: u8) -> Result<(), SyncError> {
        match self.peek() {
            Some(found) if found == tag => {
                self.bytes = &self.bytes[1..];
                Ok(())
            }
            Some(found) => Err(SyncError::UnexpectedTag(found)),
            None => Err(SyncError::Truncated),
        }
    }

    fn content(&mut self) -> Result<&'a [u8], SyncError> {
        let first = self.bytes.first().copied().ok_or(SyncError::Truncated)?;
        self.bytes = &self.bytes[1..];

        let length = if first & 0x80 == 0 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 || self.bytes.len() < count {
                return Err(SyncError::Truncated);
            }
            let mut length = 0usize;
            for byte in &self.bytes[..count] {
                length = (length << 8) | *byte as usize;
            }
            self.bytes = &self.bytes[count..];
            length
        };

        if self.bytes.len() < length {
            return Err(SyncError::Truncated);
        }
        let (content, rest) = self.bytes.split_at(length);
        self.bytes = rest;
        Ok(content)
    }

    fn sequence(&mut self) -> Result<&'a [u8], SyncError> {
        self.expect(SEQUENCE_TAG)?;
        self.content()
    }

    fn enumerated(&mut self) -> Result<i64, SyncError> {
        self.expect(ENUMERATED_TAG)?;
        let content = self.content()?;
        Ok(integer_of(content))
    }

    fn octet_string(&mut self) -> Result<&'a [u8], SyncError> {
        self.expect(OCTET_STRING_TAG)?;
        self.content()
    }

    fn boolean(&mut self) -> Result<bool, SyncError> {
        self.expect(BOOLEAN_TAG)?;
        let content = self.content()?;
        if content.len() != 1 {
            return Err(SyncError::Truncated);
        }
        Ok(content[0] != 0)
    }
}

fn integer_of(content: &[u8]) -> i64 {
    if content.is_empty() || content.len() > 8 {
        return 0;
    }

    let mut value: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for byte in content {
        value = (value << 8) | *byte as i64;
    }
    value
}

/// Decodes the `syncRequest` control value.
pub fn decode_request(value: &[u8]) -> Result<SyncRequest, SyncError> {
    let mut outer = Reader::new(value);
    let body = outer.sequence()?;
    if !outer.is_empty() {
        return Err(SyncError::TrailingBytes);
    }

    let mut inner = Reader::new(body);
    let mode = match inner.enumerated()? {
        1 => Mode::RefreshOnly,
        3 => Mode::RefreshAndPersist,
        other => return Err(SyncError::UnsupportedMode(other)),
    };

    // `cookie` is an OCTET STRING; `reloadHint` a BOOLEAN. Both optional, in that order - and a
    // client that sends only the hint must still be understood, so each is checked by its tag
    // rather than by position.
    let cookie = if inner.peek() == Some(OCTET_STRING_TAG) {
        Some(inner.octet_string()?.to_vec())
    } else {
        None
    };
    let reload_hint = if inner.peek() == Some(BOOLEAN_TAG) {
        inner.boolean()?
    } else {
        false
    };
    if !inner.is_empty() {
        return Err(SyncError::TrailingBytes);
    }

    Ok(SyncRequest {
        mode,
        cookie,
        reload_hint,
    })
}

/// One entry's state, as a client reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    pub state: State,
    pub uuid: [u8; 16],
    pub cookie: Option<Vec<u8>>,
}

/// Decodes the `syncState` control value.
///
/// Here as much for the tests as for a client: an encoder nobody decodes is an encoder nobody
/// checks, which is how the sort control came to disagree with every client for months.
pub fn decode_state(value: &[u8]) -> Result<SyncState, SyncError> {
    let mut outer = Reader::new(value);
    let body = outer.sequence()?;
    if !outer.is_empty() {
        return Err(SyncError::TrailingBytes);
    }

    let mut inner = Reader::new(body);
    let state = match inner.enumerated()? {
        0 => State::Present,
        1 => State::Add,
        2 => State::Modify,
        3 => State::Delete,
        other => return Err(SyncError::UnknownState(other)),
    };

    let uuid = inner.octet_string()?;
    if uuid.len() != 16 {
        return Err(SyncError::WrongUuidLength(uuid.len()));
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(uuid);

    let cookie = if inner.peek() == Some(OCTET_STRING_TAG) {
        Some(inner.octet_string()?.to_vec())
    } else {
        None
    };
    if !inner.is_empty() {
        return Err(SyncError::TrailingBytes);
    }

    Ok(SyncState {
        state,
        uuid: bytes,
        cookie,
    })
}

/// Decodes the `syncDone` control value.
pub fn decode_done(value: &[u8]) -> Result<(Option<Vec<u8>>, bool), SyncError> {
    let mut outer = Reader::new(value);
    let body = outer.sequence()?;
    if !outer.is_empty() {
        return Err(SyncError::TrailingBytes);
    }

    let mut inner = Reader::new(body);
    let cookie = if inner.peek() == Some(OCTET_STRING_TAG) {
        Some(inner.octet_string()?.to_vec())
    } else {
        None
    };
    let refresh_deletes = if inner.peek() == Some(BOOLEAN_TAG) {
        inner.boolean()?
    } else {
        false
    };
    if !inner.is_empty() {
        return Err(SyncError::TrailingBytes);
    }

    Ok((cookie, refresh_deletes))
}

/// Encodes the `syncState` control value that accompanies one entry.
pub fn encode_state(state: State, uuid: &[u8; 16], cookie: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![ENUMERATED_TAG, 0x01, state.as_u8()];
    body.push(OCTET_STRING_TAG);
    body.push(0x10);
    body.extend_from_slice(uuid);
    if let Some(cookie) = cookie {
        body.push(OCTET_STRING_TAG);
        body.extend(encode_length(cookie.len()));
        body.extend_from_slice(cookie);
    }

    let mut out = vec![SEQUENCE_TAG];
    out.extend(encode_length(body.len()));
    out.extend_from_slice(&body);
    out
}

/// Encodes the `syncDone` control value that ends the answer.
pub fn encode_done(cookie: Option<&[u8]>, refresh_deletes: bool) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(cookie) = cookie {
        body.push(OCTET_STRING_TAG);
        body.extend(encode_length(cookie.len()));
        body.extend_from_slice(cookie);
    }
    if refresh_deletes {
        body.extend_from_slice(&[BOOLEAN_TAG, 0x01, 0xff]);
    }

    let mut out = vec![SEQUENCE_TAG];
    out.extend(encode_length(body.len()));
    out.extend_from_slice(&body);
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

/// The control that carries one entry's state.
pub fn state_control(state: State, uuid: &[u8; 16], cookie: Option<&[u8]>) -> Control {
    Control::new(
        LdapOid::from(SYNC_OID.as_bytes()),
        false,
        Some(rasn::types::OctetString::from(encode_state(
            state, uuid, cookie,
        ))),
    )
}

/// The control that ends the answer.
pub fn done_control(cookie: Option<&[u8]>, refresh_deletes: bool) -> Control {
    Control::new(
        LdapOid::from(SYNC_OID.as_bytes()),
        false,
        Some(rasn::types::OctetString::from(encode_done(
            cookie,
            refresh_deletes,
        ))),
    )
}

/// The cookie this server hands out: `<snapshot>:<csn>`.
///
/// Two numbers for the same reason paging has two: the snapshot says which directory the answer
/// was cut from, and the CSN says how far the change journal had got. The CSN is what makes a
/// resumed refresh cheap - entries whose `entryCSN` is not newer than it are unchanged, and can be
/// reported as empty `present` entries instead of being sent again.
///
/// RFC 4533 §2.4 leaves the cookie opaque, so its shape is this server's business.
pub fn encode_cookie(snapshot: u64, csn: Option<&str>) -> Vec<u8> {
    format!("{snapshot}:{}", csn.unwrap_or("")).into_bytes()
}

/// A cookie as this server issued it.
pub fn decode_cookie(value: &[u8]) -> Option<(u64, Option<String>)> {
    let text = std::str::from_utf8(value).ok()?;
    let (snapshot, csn) = text.split_once(':')?;
    let snapshot: u64 = snapshot.parse().ok()?;

    Some((snapshot, (!csn.is_empty()).then(|| csn.to_string())))
}

/// Whether `csn` is newer than `since`. Both are fixed-width `entryCSN` values, so text order is
/// chronological order - the same property the journal keys rely on.
pub fn is_newer(csn: &str, since: &str) -> bool {
    csn > since
}

/// The `syncRequest` control: the mode, and the cookie a client resumes from.
///
/// `syncRequestValue ::= SEQUENCE { mode ENUMERATED, cookie OCTET STRING OPTIONAL,
/// reloadHint BOOLEAN DEFAULT FALSE }`. Critical, because a server that ignored it would answer an
/// ordinary search and the client would take that for a synchronisation that had happened.
pub fn request_control(mode: Mode, cookie: Option<&[u8]>) -> Control {
    let mut body = vec![ENUMERATED_TAG, 0x01, mode.as_u8()];
    if let Some(cookie) = cookie {
        body.push(OCTET_STRING_TAG);
        body.extend(encode_length(cookie.len()));
        body.extend_from_slice(cookie);
    }

    let mut value = vec![SEQUENCE_TAG];
    value.extend(encode_length(body.len()));
    value.extend_from_slice(&body);

    Control::new(
        LdapOid::from(SYNC_OID.as_bytes()),
        true,
        Some(rasn::types::OctetString::from(value)),
    )
}

/// The `syncInfo` message that ends the refresh stage of a `refreshAndPersist` search.
///
/// `syncInfoValue ::= CHOICE { ... refreshPresent [2] SEQUENCE { cookie, refreshDone } }`: the
/// present phase is what this server produces, and `refreshDone TRUE` is what tells the client the
/// refresh is over and the persist stage begins. Without it the client waits for a `searchResDone`
/// that will never come.
pub fn info_refresh_present(cookie: Option<&[u8]>) -> rasn_ldap::LdapMessage {
    let mut body = Vec::new();
    if let Some(cookie) = cookie {
        body.push(OCTET_STRING_TAG);
        body.extend(encode_length(cookie.len()));
        body.extend_from_slice(cookie);
    }
    body.extend_from_slice(&[BOOLEAN_TAG, 0x01, 0xff]);

    // `refreshPresent` is `[2]`, context-tagged and constructed.
    let mut inner = vec![0xa2];
    inner.extend(encode_length(body.len()));
    inner.extend_from_slice(&body);

    rasn_ldap::LdapMessage::new(
        0,
        rasn_ldap::ProtocolOp::IntermediateResponse(rasn_ldap::IntermediateResponse {
            response_name: Some(LdapOid::from(SYNC_OID.as_bytes())),
            response_value: Some(rasn::types::OctetString::from(inner)),
        }),
    )
}

/// The `syncIdSet` message: a set of UUIDs instead of one message per entry.
///
/// RFC 4533 §1.3.1: "The server may send syncIdSet Sync Info Messages containing the set of UUIDs
/// of either unchanged present entries or deleted entries, instead of sending multiple individual
/// messages." With `refresh_deletes` FALSE the UUIDs are entries that are still present and
/// unchanged - so a resumed refresh over ten thousand untouched entries is a few messages rather
/// than ten thousand empty ones. With TRUE they are entries no longer in the content.
///
/// `syncIdSet ::= [3] SEQUENCE { cookie OPTIONAL, refreshDeletes BOOLEAN DEFAULT FALSE,
///                               syncUUIDs SET OF syncUUID }`.
pub fn info_id_set(
    uuids: &[[u8; 16]],
    refresh_deletes: bool,
    cookie: Option<&[u8]>,
) -> rasn_ldap::LdapMessage {
    let mut body = Vec::new();
    if let Some(cookie) = cookie {
        body.push(OCTET_STRING_TAG);
        body.extend(encode_length(cookie.len()));
        body.extend_from_slice(cookie);
    }
    if refresh_deletes {
        body.extend_from_slice(&[BOOLEAN_TAG, 0x01, 0xff]);
    }

    let mut uuids_body = Vec::new();
    for uuid in uuids {
        uuids_body.push(OCTET_STRING_TAG);
        uuids_body.push(0x10);
        uuids_body.extend_from_slice(uuid);
    }
    body.push(SET_TAG);
    body.extend(encode_length(uuids_body.len()));
    body.extend_from_slice(&uuids_body);

    let mut inner = vec![0xa3];
    inner.extend(encode_length(body.len()));
    inner.extend_from_slice(&body);

    rasn_ldap::LdapMessage::new(
        0,
        rasn_ldap::ProtocolOp::IntermediateResponse(rasn_ldap::IntermediateResponse {
            response_name: Some(LdapOid::from(SYNC_OID.as_bytes())),
            response_value: Some(rasn::types::OctetString::from(inner)),
        }),
    )
}

/// The sixteen octets of a `syncUUID`, from the entry's `entryUUID` text.
///
/// `None` when the attribute is missing or is not a UUID: an entry whose identity cannot be stated
/// must not be sent under a made-up one, because a replica would then file it under the wrong
/// object.
pub fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|character| *character != '-').collect();
    if hex.len() != 32 {
        return None;
    }

    let mut out = [0u8; 16];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        out[index] = u8::from_str_radix(pair, 16).ok()?;
    }

    Some(out)
}

/// One change, as a persistent search is told about it.
///
/// Deliberately the minimum a subscriber needs: what happened, to which DN, under which identity,
/// and - for anything but a deletion - the entry as it stands. A subscriber that has to re-read the
/// directory to answer a notification would be a poll wearing a push's clothes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub kind: crate::backend::redb_store::ChangeKind,
    pub dn: String,
    /// The entry's `entryUUID`, or one derived from the DN.
    pub uuid: String,
    /// `None` for a deletion.
    pub entry: Option<crate::model::Entry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [
        0x79, 0x30, 0x3a, 0xa9, 0xf7, 0x96, 0x5f, 0xe5, 0x8f, 0xbb, 0x6e, 0xd8, 0x26, 0xb2, 0xd8,
        0xbb,
    ];

    #[test]
    fn a_refresh_only_request_without_a_cookie_decodes() {
        // What a client sending only the mode puts on the wire: `30 03 0a 01 01`.
        assert_eq!(
            decode_request(&[0x30, 0x03, 0x0a, 0x01, 0x01]),
            Ok(SyncRequest {
                mode: Mode::RefreshOnly,
                cookie: None,
                reload_hint: false,
            })
        );
    }

    #[test]
    fn a_request_with_a_cookie_keeps_the_cookie_verbatim() {
        // `30 08 0a 01 01 04 03 "abc"` - the cookie is opaque, and re-encoding it as text would
        // change it.
        assert_eq!(
            decode_request(&[0x30, 0x08, 0x0a, 0x01, 0x01, 0x04, 0x03, b'a', b'b', b'c']),
            Ok(SyncRequest {
                mode: Mode::RefreshOnly,
                cookie: Some(b"abc".to_vec()),
                reload_hint: false,
            })
        );
    }

    #[test]
    fn a_request_with_only_a_reload_hint_decodes() {
        // The hint may arrive without a cookie: a client that has nothing but wants everything
        // re-sent.
        assert_eq!(
            decode_request(&[0x30, 0x06, 0x0a, 0x01, 0x01, 0x01, 0x01, 0xff]),
            Ok(SyncRequest {
                mode: Mode::RefreshOnly,
                cookie: None,
                reload_hint: true,
            })
        );
    }

    #[test]
    fn refresh_and_persist_is_recognised_even_though_it_is_refused() {
        // Recognising it is the point: "I do not do that" and "I do not know what that is" are
        // different answers, and only the first is honest.
        let request = decode_request(&[0x30, 0x03, 0x0a, 0x01, 0x03]).expect("decodes");

        assert_eq!(request.mode, Mode::RefreshAndPersist);
    }

    #[test]
    fn an_unknown_mode_is_reported_with_its_number() {
        let error = decode_request(&[0x30, 0x03, 0x0a, 0x01, 0x02]).expect_err("must refuse");

        assert_eq!(error, SyncError::UnsupportedMode(2));
        assert!(error.to_string().contains('2'), "{error}");
    }

    #[test]
    fn a_truncated_value_is_refused_rather_than_guessed() {
        assert_eq!(
            decode_request(&[0x30, 0x05, 0x0a, 0x01]),
            Err(SyncError::Truncated)
        );
    }

    #[test]
    fn a_state_value_carries_the_state_the_uuid_and_the_cookie() {
        let encoded = encode_state(State::Add, &UUID, Some(b"c1"));

        // 30 19 | 0a 01 01 | 04 10 <16 bytes> | 04 02 "c1"
        //
        // 3 + 18 + 4 = 25 = 0x19. The length was written as 0x16 in the first version of this
        // test, which is exactly the kind of arithmetic that is worth asserting: it is the one
        // thing an encoder can get wrong without breaking its own decoder's test.
        assert_eq!(encoded[0], 0x30);
        assert_eq!(encoded[1], 0x19);
        assert_eq!(&encoded[2..5], &[0x0a, 0x01, 0x01], "state add = 1");
        assert_eq!(
            &encoded[5..7],
            &[0x04, 0x10],
            "a syncUUID is sixteen octets"
        );
        assert_eq!(&encoded[7..23], &UUID);
        assert_eq!(
            &encoded[23..],
            &[0x04, 0x02, b'c', b'1'],
            "the cookie follows"
        );
    }

    #[test]
    fn a_state_value_without_a_cookie_omits_it() {
        let encoded = encode_state(State::Present, &UUID, None);

        assert_eq!(encoded.len(), 2 + 3 + 2 + 16, "no trailing element");
        assert_eq!(encoded[2 + 3], 0x04, "the uuid is the last element");
    }

    #[test]
    fn every_state_round_trips_through_its_octet() {
        // The states are numbers on the wire, and a wrong number is a replica that silently
        // treats a deletion as an addition.
        for (state, expected) in [
            (State::Present, 0u8),
            (State::Add, 1),
            (State::Modify, 2),
            (State::Delete, 3),
        ] {
            assert_eq!(encode_state(state, &UUID, None)[4], expected);
        }
    }

    #[test]
    fn a_done_value_reports_what_it_has() {
        assert_eq!(encode_done(None, false), vec![0x30, 0x00]);

        let with_cookie = encode_done(Some(b"c1"), false);
        assert_eq!(with_cookie, vec![0x30, 0x04, 0x04, 0x02, b'c', b'1']);

        let with_deletes = encode_done(None, true);
        assert_eq!(with_deletes, vec![0x30, 0x03, 0x01, 0x01, 0xff]);
    }

    #[test]
    fn a_state_value_decodes_back_to_what_was_encoded() {
        // The check the sort codec lacked: encode and decode are separate code paths, and this
        // asserts the pair against a value, not against itself.
        let encoded = encode_state(State::Modify, &UUID, Some(b"cookie-1"));

        assert_eq!(
            decode_state(&encoded),
            Ok(SyncState {
                state: State::Modify,
                uuid: UUID,
                cookie: Some(b"cookie-1".to_vec()),
            })
        );
    }

    #[test]
    fn a_state_value_naming_no_entry_is_refused() {
        // A syncUUID that is not sixteen octets names no object; accepting a short one would
        // make a replica file the entry under a truncated identity.
        // 30 07 | 0a 01 00 | 04 02 "ab" - the outer length counts what is inside it.
        let short = vec![0x30, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x02, b'a', b'b'];

        assert_eq!(decode_state(&short), Err(SyncError::WrongUuidLength(2)));
    }

    #[test]
    fn a_done_value_decodes_back_with_and_without_a_cookie() {
        assert_eq!(decode_done(&encode_done(None, false)), Ok((None, false)));
        assert_eq!(
            decode_done(&encode_done(Some(b"c9"), true)),
            Ok((Some(b"c9".to_vec()), true))
        );
    }

    #[test]
    fn a_cookie_carries_the_snapshot_and_the_csn() {
        assert_eq!(
            encode_cookie(7, Some("20261102143012.000001Z#000006#000#000000")),
            b"7:20261102143012.000001Z#000006#000#000000".to_vec()
        );
        assert_eq!(
            decode_cookie(b"7:20261102143012.000001Z#000006#000#000000"),
            Some((
                7,
                Some("20261102143012.000001Z#000006#000#000000".to_string())
            ))
        );
    }

    #[test]
    fn a_cookie_without_a_csn_says_so_rather_than_inventing_one() {
        // The case of a store with no journal: the client gets a cookie it can hand back, but the
        // server must not pretend to know how far the history had got.
        assert_eq!(decode_cookie(&encode_cookie(3, None)), Some((3, None)));
    }

    #[test]
    fn a_cookie_that_is_not_ours_is_not_guessed_at() {
        assert_eq!(decode_cookie(b"nonsense"), None);
        assert_eq!(decode_cookie(b"7"), None);
        assert_eq!(decode_cookie(b"x:"), None);
    }

    #[test]
    fn csns_compare_by_text_because_they_are_fixed_width() {
        let earlier = "20261102143012.000001Z#000001#000#000000";
        let later = "20261102143012.000002Z#000001#000#000000";

        assert!(is_newer(later, earlier));
        assert!(!is_newer(earlier, later));
        assert!(!is_newer(earlier, earlier), "equal is not newer");
    }

    #[test]
    fn a_uuid_is_sixteen_octets_from_its_text_form() {
        assert_eq!(
            uuid_bytes("79303aa9-f796-5fe5-8fbb-6ed826b2d8bb"),
            Some(UUID)
        );
    }

    #[test]
    fn a_text_that_is_not_a_uuid_gives_nothing_rather_than_zeroes() {
        // A replica would file the entry under the wrong object, and nothing would say so.
        assert_eq!(uuid_bytes(""), None);
        assert_eq!(uuid_bytes("not-a-uuid"), None);
        assert_eq!(uuid_bytes("79303aa9-f796-5fe5-8fbb"), None);
    }
}
