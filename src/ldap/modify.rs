//! Modify operation: check, mutate, hand the result to the persistence layer.
//!
//! The handler does not write anything itself. It returns [`Action::Persist`] with the
//! new entry, so the socket loop performs the backend write and answers afterwards:
//! the reply must not say `success` before the change is durable, and the backend call
//! is asynchronous while this layer stays synchronous.
//!
//! Ordering of the checks is the order a client can act on: DN syntax, ACL, whether
//! the entry exists, then the changes themselves.

use rasn_ldap::{LdapMessage, MessageId, ModifyRequest, ResultCode};

use super::assertion;
use super::session::Session;
use crate::acl::Requester;
use crate::directory::Directory;
use crate::dn;
use crate::model::Entry;
use crate::mutate::{self, MutateError};
use crate::schema::{Mode as SchemaMode, Schema, ViolationCode};
use crate::security::Security;

/// Maps the protocol's change list to the model's modification list.
pub fn modifications(request: &ModifyRequest) -> Vec<mutate::Modification> {
    request
        .changes
        .iter()
        .map(|change| {
            let op = match change.operation {
                rasn_ldap::ChangeOperation::Add => mutate::Op::Add,
                rasn_ldap::ChangeOperation::Delete => mutate::Op::Delete,
                rasn_ldap::ChangeOperation::Replace => mutate::Op::Replace,
            };
            let values = change
                .modification
                .vals
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_ref()).into_owned())
                .collect();

            mutate::Modification::new(op, change.modification.r#type.0.to_string(), values)
        })
        .collect()
}

/// What the modify request turned into.
pub enum Outcome {
    /// Answer with this message and change nothing.
    Reject(LdapMessage),
    /// Persist the entry, then answer with `success`, or with an error carrying the
    /// backend's message.
    ///
    /// `extra` carries the entries whose `memberOf` follows this one: a group whose membership
    /// changed leaves every added or removed member with a value to rewrite, and that rewrite
    /// has to land in the same change set. Two change sets would leave a moment where the group
    /// lists a user who does not list the group.
    Persist {
        entry: Entry,
        extra: Vec<Entry>,
        success: LdapMessage,
    },
}

/// Checks a modify request and produces the entry to store.
pub fn handle_modify(
    session: &Session,
    directory: &Directory,
    message_id: MessageId,
    request: &ModifyRequest,
    controls: Option<&rasn_ldap::Controls>,
    security: &Security,
) -> Outcome {
    use super::responses::modify_response;

    let entry_dn = dn::normalize(&request.object.0);
    if !dn::is_valid(&entry_dn) {
        return Outcome::Reject(modify_response(
            message_id,
            ResultCode::InvalidDnSyntax,
            "wrong entry DN",
        ));
    }

    // The domain and the two organizational units are the shape of this server, not
    // data: gorestldap refused to modify them and the port keeps that.
    if entry_dn == directory.base_dn()
        || entry_dn == directory.ou_dn(directory.users_ou_name())
        || entry_dn == directory.ou_dn(directory.groups_ou_name())
    {
        return Outcome::Reject(modify_response(
            message_id,
            ResultCode::UnwillingToPerform,
            &format!("modify of '{entry_dn}' is not supported"),
        ));
    }

    let requester = session.requester();
    let rights = security.acl.rights(&requester, directory, &entry_dn, None);
    if !rights.write && !is_own_entry(&requester, &entry_dn) {
        return Outcome::Reject(modify_response(
            message_id,
            ResultCode::InsufficientAccessRights,
            "",
        ));
    }

    let Some(entry) = directory.find(&entry_dn) else {
        return Outcome::Reject(modify_response(
            message_id,
            ResultCode::NoSuchObject,
            "target entry not found",
        ));
    };

    // Assertion control (RFC 4528): the change lands only if the entry still looks
    // the way the client expects. Checked after the entry is found and before anything
    // is mutated, and a failure writes nothing.
    match assertion::evaluate(controls, entry) {
        assertion::Assertion::Matches | assertion::Assertion::Absent => {}
        assertion::Assertion::Failed => {
            return Outcome::Reject(modify_response(
                message_id,
                ResultCode::AssertionFailed,
                "assertion control: the entry does not match",
            ));
        }
        assertion::Assertion::Unusable(reason) => {
            return Outcome::Reject(modify_response(
                message_id,
                ResultCode::UnavailableCriticalExtension,
                &reason,
            ));
        }
    }

    // Schema checking decides whether SINGLE-VALUE applies, and `off` means the server
    // does not enforce what it does not publish as enforced.
    // Read once: one operation must see one schema, even if a reload lands mid-request.
    let published = crate::security::current_schema(&security.schema);
    let schema = match security.schema_mode {
        SchemaMode::Off => None,
        _ => Some(published.as_ref()),
    };

    let modified = match mutate::apply(entry, &modifications(request), schema) {
        Ok(modified) => modified,
        Err(err) => {
            return Outcome::Reject(modify_response(
                message_id,
                result_code(&err),
                &err.to_string(),
            ));
        }
    };

    // Stamped here, not in the backend: only this layer knows who is writing; the
    // clock is read once so the two timestamps of one write cannot disagree.
    let modified = stamp(&modified, session, &requester);

    // Changing `cn` or `uid` can collide with another account; the entry itself is
    // excluded, so a modify that keeps the value is not a duplicate of itself.
    //
    // `entry.dn()` and not `entry_dn`: a client may address an entry as
    // `uid=alice,ou=users,…` while the entry is stored as `cn=alice,ou=users,…`, and
    // excluding the alias would let the entry collide with itself.
    if let Err(duplicate) = crate::integrity::check_unique(
        directory,
        &modified,
        entry.dn(),
        &security.integrity.unique_attributes(),
    ) {
        return Outcome::Reject(modify_response(
            message_id,
            ResultCode::ConstraintViolation,
            &duplicate.to_string(),
        ));
    }

    // The entry as it would be stored must satisfy the schema it is published under.
    if let Err(violations) = check(&published, security.schema_mode, &modified) {
        let detail = violations
            .iter()
            .map(|violation| violation.detail.clone())
            .collect::<Vec<_>>()
            .join("; ");
        return Outcome::Reject(modify_response(
            message_id,
            violations
                .first()
                .map(|violation| code_of(violation.code))
                .unwrap_or(ResultCode::ObjectClassViolation),
            &detail,
        ));
    }

    // The group side is where `memberOf` is computed from, so a change to `member` or
    // `memberUid` is also a change to every member's entry.
    let extra = if security.integrity.referential_integrity {
        crate::integrity::member_of_changes(directory, Some(entry), Some(&modified))
            .into_iter()
            .map(|member| stamp(&member, session, &requester))
            .collect()
    } else {
        Vec::new()
    };

    Outcome::Persist {
        entry: modified,
        extra,
        success: modify_response(message_id, ResultCode::Success, ""),
    }
}

/// Adds the operational attributes that describe this write.
fn stamp(entry: &Entry, session: &Session, requester: &Requester) -> Entry {
    let actor = requester
        .dn
        .clone()
        .or_else(|| session.identity().map(|identity| identity.dn.clone()))
        .unwrap_or_default();

    crate::operational::stamp_write(entry, &actor, std::time::SystemTime::now())
}

/// True when the requester is the entry being modified.
///
/// gorestldap let a user modify their own entry without the write right; the port
/// keeps that, because changing your own password is the reason the rule exists.
fn is_own_entry(requester: &Requester, entry_dn: &str) -> bool {
    requester
        .dn
        .as_deref()
        .is_some_and(|own| dn::normalize(own) == entry_dn)
}

/// Schema verdict according to the configured mode.
fn check(
    schema: &Schema,
    mode: SchemaMode,
    entry: &Entry,
) -> Result<(), Vec<crate::schema::Violation>> {
    match mode {
        // `off` and `warn` do not refuse a write: that is the whole difference between
        // them and `strict`, and a write refused in `warn` would make the mode a lie.
        SchemaMode::Off | SchemaMode::Warn => Ok(()),
        SchemaMode::Strict => schema.check(entry),
    }
}

fn code_of(code: ViolationCode) -> ResultCode {
    match code {
        ViolationCode::ObjectClassViolation => ResultCode::ObjectClassViolation,
        ViolationCode::ConstraintViolation => ResultCode::ConstraintViolation,
        ViolationCode::UndefinedAttributeType => ResultCode::UndefinedAttributeType,
        ViolationCode::InvalidAttributeSyntax => ResultCode::InvalidAttributeSyntax,
    }
}

/// The result code the protocol answers a refused change with.
///
/// Public because the `cn=config` write path applies the same change semantics through the
/// same [`crate::mutate`] and must answer with the same codes.
pub fn result_code(error: &MutateError) -> ResultCode {
    match error {
        MutateError::NoSuchAttribute(_) => ResultCode::NoSuchAttribute,
        MutateError::AttributeOrValueExists { .. } => ResultCode::AttributeOrValueExists,
        MutateError::UndefinedAttribute(_) => ResultCode::UndefinedAttributeType,
        MutateError::NotUserModifiable(_) => ResultCode::ConstraintViolation,
        MutateError::SingleValue { .. } => ResultCode::ConstraintViolation,
        MutateError::Protected(_) => ResultCode::UnwillingToPerform,
    }
}
