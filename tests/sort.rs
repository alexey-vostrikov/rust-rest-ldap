//! Sort and virtual list view over the dispatcher: what a client asks for and gets.
//!
//! The properties worth testing are not "the array got sorted": they are the ones a
//! client depends on and cannot check itself. Sort happens before the size limit and
//! before paging, so "the first twenty of the sorted list" is what comes back. VLV needs a
//! sort to mean anything, and the server says so instead of returning a window of an
//! arbitrary order. A critical sort that cannot be honoured refuses the search.

use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, Control, LdapDn, LdapMessage, LdapOid, ProtocolOp, ResultCode,
    SearchRequest, SearchRequestDerefAliases, SearchRequestScope,
};
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::ldap::search::handle_search;
use rust_rest_ldap::ldap::session::{Identity, Session};
use rust_rest_ldap::ldap::sort::{SORT_OID, SORT_RESPONSE_OID, VLV_OID, VLV_RESPONSE_OID};
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const USERS_OU: &str = "ou=users,dc=example,dc=com";

fn person(cn: &str, uid_number: &str, phone: Option<&str>) -> Entry {
    let mut attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec![
                "top".to_string(),
                "person".to_string(),
                "inetOrgPerson".to_string(),
                "posixAccount".to_string(),
            ],
        ))
        .push(Attribute::single("cn", cn))
        .push(Attribute::single("sn", "S"))
        .push(Attribute::single("uid", cn))
        .push(Attribute::single("uidNumber", uid_number))
        .push(Attribute::single("gidNumber", "100"))
        .push(Attribute::single("homeDirectory", &format!("/home/{cn}")));

    if let Some(phone) = phone {
        attributes = attributes.push(Attribute::single("telephoneNumber", phone));
    }

    Entry::new(format!("cn={cn},ou=users,{BASE}"), attributes)
}

fn directory() -> Directory {
    Directory::from_entries(
        BASE,
        "users",
        "groups",
        vec![
            person("carol", "30", None),
            person("alice", "9", Some("+7 495 000-00-03")),
            person("bob", "10", Some("+7 495 000-00-01")),
            person("dave", "100", None),
        ],
    )
}

fn admin() -> Session {
    let mut session = Session::new();
    session.set_identity(Identity::new(ADMIN_DN, true));
    session
}

/// Encodes a sort control value: `SEQUENCE { SEQUENCE OF SortKey, ... }`.
fn sort_value(keys: &[(&str, bool)]) -> Vec<u8> {
    let mut key_list = Vec::new();
    for (attribute, reverse) in keys {
        let mut key = Vec::new();
        key.push(0x04);
        key.push(attribute.len() as u8);
        key.extend_from_slice(attribute.as_bytes());

        if *reverse {
            key.extend_from_slice(&[0x01, 0x01, 0xff]);
        }

        key_list.push(0x30);
        key_list.push(key.len() as u8);
        key_list.extend_from_slice(&key);
    }

    let mut inner = vec![0x31];
    inner.push(key_list.len() as u8);
    inner.extend_from_slice(&key_list);

    let mut out = vec![0x30];
    out.push(inner.len() as u8);
    out.extend_from_slice(&inner);
    out
}

/// Encodes a VLV byOffset control value.
fn vlv_value(before: u8, after: u8, offset: u8) -> Vec<u8> {
    let mut inner = vec![0x02, 0x01, before, 0x02, 0x01, after];
    let target = [0x02, 0x01, offset];
    inner.push(0x81);
    inner.push(target.len() as u8);
    inner.extend_from_slice(&target);

    let mut out = vec![0x30];
    out.push(inner.len() as u8);
    out.extend_from_slice(&inner);
    out
}

fn control(oid: &str, critical: bool, value: Vec<u8>) -> Control {
    Control::new(
        LdapOid::from(oid.as_bytes()),
        critical,
        Some(OctetString::from(value)),
    )
}

fn search(controls: Option<Vec<Control>>, size_limit: u32) -> Vec<LdapMessage> {
    search_at(BASE, controls, size_limit)
}

fn search_at(base: &str, controls: Option<Vec<Control>>, size_limit: u32) -> Vec<LdapMessage> {
    let request = SearchRequest::new(
        LdapDn::from(base),
        SearchRequestScope::WholeSubtree,
        SearchRequestDerefAliases::NeverDerefAliases,
        size_limit,
        0,
        false,
        rasn_ldap::Filter::Present(AttributeDescription::from("objectClass")),
        vec![rasn_ldap::LdapString::from("cn")],
    );

    handle_search(
        &admin(),
        &directory(),
        1,
        &request,
        controls.as_ref(),
        &Security::default(),
    )
}

/// Common names of the returned people, in the order they arrived.
///
/// The domain entry and the two organizational units come back from a subtree search too,
/// and they have no `cn`; they are skipped so the assertions are about the people.
fn order(messages: &[LdapMessage]) -> Vec<String> {
    messages
        .iter()
        .filter_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => entry
                .attributes
                .iter()
                .find(|attribute| attribute.r#type.0.eq_ignore_ascii_case("cn"))
                .and_then(|attribute| attribute.vals.iter().next())
                .map(|value| String::from_utf8_lossy(value.as_ref()).into_owned()),
            _ => None,
        })
        .collect()
}

fn done(messages: &[LdapMessage]) -> ResultCode {
    messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResDone(result) => Some(result.0.result_code),
            _ => None,
        })
        .expect("a search always ends with a done")
}

/// The sort response control's result code, if the server sent one.
fn sort_result(messages: &[LdapMessage]) -> Option<u8> {
    messages.iter().find_map(|message| {
        let controls = message.controls.as_ref()?;
        let control = controls
            .iter()
            .find(|control| control.control_type.as_ref() == SORT_RESPONSE_OID.as_bytes())?;
        let value = control.control_value.as_ref()?;
        // SEQUENCE { ENUMERATED, ... }
        value.as_ref().get(4).copied()
    })
}

fn vlv_response(messages: &[LdapMessage]) -> Option<Vec<u8>> {
    messages.iter().find_map(|message| {
        let controls = message.controls.as_ref()?;
        controls
            .iter()
            .find(|control| control.control_type.as_ref() == VLV_RESPONSE_OID.as_bytes())
            .and_then(|control| control.control_value.as_ref())
            .map(|value| value.as_ref().to_vec())
    })
}

#[test]
fn a_sort_control_orders_the_result() {
    let messages = search(
        Some(vec![control(SORT_OID, false, sort_value(&[("cn", false)]))]),
        0,
    );

    assert_eq!(done(&messages), ResultCode::Success);
    assert_eq!(
        order(&messages),
        vec!["alice", "bob", "carol", "dave"],
        "the client asked for order and has to get it"
    );
}

#[test]
fn a_reverse_sort_orders_descending() {
    let messages = search(
        Some(vec![control(SORT_OID, false, sort_value(&[("cn", true)]))]),
        0,
    );

    assert_eq!(order(&messages), vec!["dave", "carol", "bob", "alice"]);
}

#[test]
fn the_sort_response_control_reports_success() {
    let messages = search(
        Some(vec![control(SORT_OID, false, sort_value(&[("cn", false)]))]),
        0,
    );

    assert_eq!(
        sort_result(&messages),
        Some(0),
        "RFC 2891: the client has to learn whether its order was applied"
    );
}

#[test]
fn numbers_sort_as_numbers() {
    // Text order would give 10, 100, 30, 9 - the classic sorting bug an address book shows.
    let messages = search(
        Some(vec![control(
            SORT_OID,
            false,
            sort_value(&[("uidNumber", false)]),
        )]),
        0,
    );

    assert_eq!(
        order(&messages),
        vec!["alice", "bob", "carol", "dave"],
        "9, 10, 30, 100"
    );
}

#[test]
fn sorting_happens_before_the_size_limit() {
    // With the limit applied first, the answer would be whichever entries happened to come
    // first in the directory, sorted. The client asked for the first of the sorted list.
    let messages = search(
        Some(vec![control(SORT_OID, false, sort_value(&[("cn", false)]))]),
        2,
    );

    assert_eq!(
        order(&messages),
        vec!["alice", "bob"],
        "the first two of the sorted list, not the sorted first two"
    );
}

#[test]
fn an_entry_without_the_attribute_sorts_last() {
    let messages = search(
        Some(vec![control(
            SORT_OID,
            false,
            sort_value(&[("telephoneNumber", false)]),
        )]),
        0,
    );

    let order = order(&messages);
    assert_eq!(
        order,
        vec!["bob", "alice", "carol", "dave"],
        "bob's number ends in 01 and alice's in 03, so bob comes first; the two without \
         a number come last rather than heading the list"
    );
}

#[test]
fn several_keys_are_applied_in_order() {
    let messages = search(
        Some(vec![control(
            SORT_OID,
            false,
            sort_value(&[("sn", false), ("cn", true)]),
        )]),
        0,
    );

    // Every entry has the same sn, so the second key decides: descending cn.
    assert_eq!(order(&messages), vec!["dave", "carol", "bob", "alice"]);
}

#[test]
fn vlv_returns_a_window_of_the_sorted_list() {
    let messages = search_at(
        USERS_OU,
        Some(vec![
            control(SORT_OID, false, sort_value(&[("cn", false)])),
            control(VLV_OID, false, vlv_value(1, 1, 2)),
        ]),
        0,
    );

    assert_eq!(done(&messages), ResultCode::Success);
    assert_eq!(
        order(&messages),
        vec!["bob", "carol", "dave"],
        "one before, the target, one after"
    );
}

/// Reads `SEQUENCE { INTEGER, INTEGER, ... }` into the two leading integers.
fn two_integers(value: &[u8]) -> (u32, u32) {
    let mut position = 2; // skip the SEQUENCE tag and its one-octet length
    let mut numbers = Vec::new();

    while numbers.len() < 2 && position + 2 <= value.len() {
        assert_eq!(value[position], 0x02, "expected an INTEGER at {position}");
        let length = value[position + 1] as usize;
        let content = &value[position + 2..position + 2 + length];

        let mut number: u32 = 0;
        for byte in content {
            number = (number << 8) | *byte as u32;
        }
        numbers.push(number);
        position += 2 + length;
    }

    (numbers[0], numbers[1])
}

#[test]
fn the_vlv_response_reports_position_and_total() {
    let messages = search_at(
        USERS_OU,
        Some(vec![
            control(SORT_OID, false, sort_value(&[("cn", false)])),
            control(VLV_OID, false, vlv_value(0, 1, 2)),
        ]),
        0,
    );
    let value = vlv_response(&messages).expect("a VLV response control");
    let (position, total) = two_integers(&value);

    assert_eq!(
        position, 3,
        "the third entry of the sorted list, counted from one"
    );
    assert_eq!(
        total, 5,
        "four people and the organizational unit itself, which a subtree search includes"
    );
}

#[test]
fn a_window_past_the_end_is_clamped() {
    let messages = search_at(
        USERS_OU,
        Some(vec![
            control(SORT_OID, false, sort_value(&[("cn", false)])),
            control(VLV_OID, false, vlv_value(5, 5, 2)),
        ]),
        0,
    );

    assert_eq!(done(&messages), ResultCode::Success);
    assert_eq!(
        order(&messages),
        vec!["alice", "bob", "carol", "dave"],
        "a window larger than the list returns the list, not an error"
    );
}

#[test]
fn vlv_without_a_sort_is_refused() {
    // Without an order a window would be a window of nothing in particular.
    let messages = search(Some(vec![control(VLV_OID, false, vlv_value(1, 1, 1))]), 0);

    assert_eq!(done(&messages), ResultCode::UnwillingToPerform);
}

#[test]
fn a_malformed_sort_control_is_a_protocol_error() {
    let messages = search(Some(vec![control(SORT_OID, false, vec![0x30, 0x00])]), 0);

    assert_eq!(
        done(&messages),
        ResultCode::ProtocolError,
        "an unreadable sort must not become 'unsorted but fine'"
    );
}

#[test]
fn a_malformed_vlv_control_is_a_protocol_error() {
    let messages = search(
        Some(vec![
            control(SORT_OID, false, sort_value(&[("cn", false)])),
            control(VLV_OID, false, vec![0x04, 0x01, b'x']),
        ]),
        0,
    );

    assert_eq!(done(&messages), ResultCode::ProtocolError);
}

#[test]
fn an_unknown_ordering_rule_fails_a_non_critical_sort_without_refusing_the_search() {
    // The control value carries `madeUpMatch` as the ordering rule.
    let mut key = vec![0x04, 0x02, b'c', b'n'];
    let rule = b"madeUpMatch";
    key.push(0x04);
    key.push(rule.len() as u8);
    key.extend_from_slice(rule);

    let mut key_list = vec![0x30, key.len() as u8];
    key_list.extend_from_slice(&key);

    let mut inner = vec![0x31, key_list.len() as u8];
    inner.extend_from_slice(&key_list);

    let mut value = vec![0x30, inner.len() as u8];
    value.extend_from_slice(&inner);

    let messages = search(Some(vec![control(SORT_OID, false, value)]), 0);

    assert_eq!(done(&messages), ResultCode::Success);
    assert_eq!(
        sort_result(&messages),
        Some(18),
        "inappropriateMatching tells the client its rule was not applied"
    );
}

#[test]
fn a_critical_sort_that_cannot_be_honoured_refuses_the_search() {
    // The point of the critical bit: the client cannot render an unsorted answer, so a
    // sort it cannot get must be an error, not a note.
    let mut key = vec![0x04, 0x02, b'c', b'n'];
    let rule = b"madeUpMatch";
    key.push(0x04);
    key.push(rule.len() as u8);
    key.extend_from_slice(rule);

    let mut key_list = vec![0x30, key.len() as u8];
    key_list.extend_from_slice(&key);

    let mut inner = vec![0x31, key_list.len() as u8];
    inner.extend_from_slice(&key_list);

    let mut value = vec![0x30, inner.len() as u8];
    value.extend_from_slice(&inner);

    let messages = search(Some(vec![control(SORT_OID, true, value)]), 0);

    assert_eq!(done(&messages), ResultCode::InappropriateMatching);
    assert!(
        order(&messages).is_empty(),
        "nothing may be returned when the required order cannot be produced"
    );
}

#[test]
fn without_a_sort_control_the_order_is_the_directory_order() {
    let messages = search(None, 0);

    assert_eq!(
        order(&messages),
        vec!["alice", "bob", "carol", "dave"],
        "the canonical DN order, unchanged"
    );
    assert_eq!(sort_result(&messages), None, "and no sort response control");
}
