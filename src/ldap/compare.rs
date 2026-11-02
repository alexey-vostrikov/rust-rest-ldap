//! Compare operation: does this entry hold this value, yes or no (RFC 4511 §4.10).
//!
//! The answer is a result code, not a search: `compareTrue` (6) or `compareFalse` (5),
//! and the client gets no entry back. That makes it the cheapest way to check a
//! membership or a password-style value without reading the attribute — which is also
//! why it needs the same access control as a read. A compare that answered for an
//! attribute the requester may not read would leak it one bit at a time.
//!
//! gorestldap refused `entryDN` with `unwillingToPerform` and answered
//! `noSuchAttribute` for an unknown attribute; both behaviours are kept.

use rasn_ldap::{CompareRequest, LdapMessage, MessageId, ResultCode};

use super::responses::compare_response;
use super::session::Session;
use crate::directory::Directory;
use crate::dn;
use crate::security::Security;

/// Handles a compare request.
pub fn handle_compare(
    session: &Session,
    directory: &Directory,
    message_id: MessageId,
    request: &CompareRequest,
    security: &Security,
) -> LdapMessage {
    let entry_dn = dn::normalize(&request.entry.0);
    if !dn::is_valid(&entry_dn) {
        return compare_response(message_id, ResultCode::InvalidDnSyntax, "wrong entry DN");
    }

    let attribute = request.ava.attribute_desc.0.to_lowercase();

    // The DN is not stored as an attribute; comparing it would answer about something
    // the entry does not hold.
    if attribute == "entrydn" {
        return compare_response(
            message_id,
            ResultCode::UnwillingToPerform,
            "compare over entrydn is not supported",
        );
    }

    let Some(entry) = directory.find(&entry_dn) else {
        return compare_response(
            message_id,
            ResultCode::NoSuchObject,
            "target entry not found",
        );
    };

    // A compare reads one attribute, so it needs the right a search would need to
    // return it. Checking this before the attribute exists also hides which
    // attributes are there from a requester who cannot read them.
    let requester = session.requester();
    if !security
        .acl
        .rights(&requester, directory, entry.dn(), Some(&attribute))
        .read
    {
        return compare_response(message_id, ResultCode::InsufficientAccessRights, "");
    }

    if entry.attributes().get(&attribute).is_none() {
        return compare_response(message_id, ResultCode::NoSuchAttribute, "");
    }

    // The comparison itself is the filter's equality rule: one implementation of
    // "these two values are equal", not a second one that could drift.
    let matches = super::filter::matches(
        entry.attributes(),
        entry.dn(),
        &rasn_ldap::Filter::EqualityMatch(request.ava.clone()),
    );

    match matches {
        Ok(true) => compare_response(message_id, ResultCode::CompareTrue, ""),
        Ok(false) => compare_response(message_id, ResultCode::CompareFalse, ""),
        // A comparison that cannot be evaluated must not answer `false`: that would be
        // a wrong answer where the honest one is "I cannot tell".
        Err(err) => compare_response(message_id, ResultCode::UnwillingToPerform, &err.to_string()),
    }
}
