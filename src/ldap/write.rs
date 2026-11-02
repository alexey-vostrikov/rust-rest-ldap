//! `add`, `delete` and `modifyDN`: giving the directory a life cycle.
//!
//! These three share one shape — check, build a change set, hand it to the persistence
//! layer — so the checks live here, together, in the order a client can act on them.
//! None of them writes anything: they return the change set and the success message,
//! and the socket loop persists before answering, exactly like `modify`.
//!
//! gorestldap had none of these: its directory was read-only, which is why the port had
//! to grow a write path at all. The result codes follow RFC 4511 rather than the old
//! server's behaviour, because there is no old behaviour to match.

use rasn_ldap::{AddRequest, DelRequest, LdapMessage, MessageId, ModifyDnRequest, ResultCode};

use super::session::Session;
use crate::backend::EntryChange;
use crate::directory::Directory;
use crate::dn;
use crate::model::{Attribute, Attributes, Entry};
use crate::schema::{Mode as SchemaMode, Schema};
use crate::security::Security;

/// What a write request turned into.
pub enum Outcome {
    Reject(LdapMessage),
    /// Persist these changes atomically, then answer with `success`.
    Persist {
        changes: Vec<EntryChange>,
        success: LdapMessage,
    },
}

fn reject(message: LdapMessage) -> Outcome {
    Outcome::Reject(message)
}

/// Whether the requester may write `entry_dn`, with the same "own entry counts" rule
/// the modify path uses.
fn may_write(
    security: &Security,
    session: &Session,
    directory: &Directory,
    entry_dn: &str,
) -> bool {
    let requester = session.requester();
    if security
        .acl
        .rights(&requester, directory, entry_dn, None)
        .write
    {
        return true;
    }

    // A user may always work on their own entry: changing your own password is the
    // reason the rule exists, and `add`/`delete` of yourself is the same right.
    requester
        .dn
        .as_deref()
        .is_some_and(|own| dn::normalize(own) == entry_dn)
}

/// Schema verdict for a write, according to the configured mode.
fn schema_verdict(
    schema: &Schema,
    mode: SchemaMode,
    entry: &Entry,
) -> Result<(), (ResultCode, String)> {
    if mode != SchemaMode::Strict {
        return Ok(());
    }

    schema.check(entry).map_err(|violations| {
        let detail = violations
            .iter()
            .map(|violation| violation.detail.clone())
            .collect::<Vec<_>>()
            .join("; ");
        let code = violations
            .first()
            .map(|violation| match violation.code {
                crate::schema::ViolationCode::ObjectClassViolation => {
                    ResultCode::ObjectClassViolation
                }
                crate::schema::ViolationCode::ConstraintViolation => {
                    ResultCode::ConstraintViolation
                }
                crate::schema::ViolationCode::UndefinedAttributeType => {
                    ResultCode::UndefinedAttributeType
                }
                crate::schema::ViolationCode::InvalidAttributeSyntax => {
                    ResultCode::InvalidAttributeSyntax
                }
            })
            .unwrap_or(ResultCode::ObjectClassViolation);
        (code, detail)
    })
}

/// Updates the naming attribute for a rename.
///
/// Three cases, and the difference between them is why this is a function:
/// - the new RDN uses the same attribute as the old one (`cn=a` → `cn=b`): the old value
///   is dropped when `delete_old_rdn` is set, and the new one is added either way. The
///   attribute keeps its flags and its other values;
/// - it uses a different attribute (`uid=a` → `cn=b`): the new attribute is added and the
///   old value removed from its own attribute, which disappears when it was the last;
/// - the same value: nothing to do.
///
/// Written with `replace`, not `push`: `push` would leave two attributes with the same
/// description, and the first one — the stale one — is what a search would return.
fn rename_naming_attribute(
    attributes: &Attributes,
    old_attribute: &str,
    old_value: &str,
    new_attribute: &str,
    new_value: &str,
    delete_old_rdn: bool,
) -> Attributes {
    let mut attributes = attributes.clone();

    if old_attribute.eq_ignore_ascii_case(new_attribute) {
        let existing = attributes.get(new_attribute);
        let mut values: Vec<String> = existing
            .map(|attribute| attribute.values.to_vec())
            .unwrap_or_default();

        if delete_old_rdn {
            values.retain(|candidate| !candidate.eq_ignore_ascii_case(old_value));
        }
        if !values
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(new_value))
        {
            values.push(new_value.to_string());
        }

        let mut rebuilt = Attribute::new(new_attribute, values);
        if let Some(existing) = existing {
            rebuilt.flags = existing.flags;
        }
        return attributes.replace(rebuilt);
    }

    // Different attributes: the new one comes first, so the rename works even when the
    // old attribute is about to be removed entirely.
    let mut rebuilt = Attribute::new(new_attribute, vec![new_value.to_string()]);
    if let Some(existing) = attributes.get(new_attribute) {
        let mut values = existing.values.to_vec();
        if !values
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(new_value))
        {
            values.push(new_value.to_string());
        }
        rebuilt = Attribute::new(new_attribute, values);
        rebuilt.flags = existing.flags;
    }
    attributes = attributes.replace(rebuilt);

    if delete_old_rdn {
        // The old attribute may be gone already when the new RDN reused its name.
        if let Some(existing) = attributes.get(old_attribute) {
            let remaining: Vec<String> = existing
                .values
                .iter()
                .filter(|candidate| !candidate.eq_ignore_ascii_case(old_value))
                .cloned()
                .collect();

            attributes = if remaining.is_empty() {
                attributes.without(old_attribute)
            } else {
                let mut rebuilt = Attribute::new(old_attribute, remaining);
                rebuilt.flags = existing.flags;
                attributes.replace(rebuilt)
            };
        }
    }

    attributes
}

/// Handles an add request.
pub fn handle_add(
    session: &Session,
    directory: &Directory,
    message_id: MessageId,
    request: &AddRequest,
    security: &Security,
) -> Outcome {
    let entry_dn = dn::normalize(&request.entry.0);
    let response = |code: ResultCode, diagnostic: &str| {
        super::responses::add_response(message_id, code, diagnostic)
    };

    if !dn::is_valid(&entry_dn) {
        return reject(response(ResultCode::InvalidDnSyntax, "wrong entry DN"));
    }

    // The parent has to exist: an entry cannot appear in a branch nobody has. Without
    // this check the directory would hold orphans that no search can reach.
    let (_, _, parent) = dn::split_first_rdn(&entry_dn);
    if parent.is_empty() || directory.find(&parent).is_none() {
        return reject(response(
            ResultCode::NoSuchObject,
            "the parent entry does not exist",
        ));
    }

    if directory.find(&entry_dn).is_some() {
        return reject(response(ResultCode::EntryAlreadyExists, ""));
    }

    if !may_write(security, session, directory, &entry_dn) {
        return reject(response(ResultCode::InsufficientAccessRights, ""));
    }

    let mut attributes = Attributes::new();
    for attribute in &request.attributes {
        let name = attribute.r#type.0.to_string();
        let values: Vec<String> = attribute
            .vals
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_ref()).into_owned())
            .collect();

        if values.is_empty() {
            return reject(response(
                ResultCode::ProtocolError,
                &format!("attribute '{name}' has no values"),
            ));
        }

        // Flags come from the name and from what the value is, the same way the
        // mapping sets them: a password hash must stay hidden and exact.
        let mut built = Attribute::new(&name, values);
        if name.eq_ignore_ascii_case("userPassword") {
            built = built.case_sensitive().sensitive();
        }
        attributes = attributes.push(built);
    }

    let entry = Entry::new(entry_dn.clone(), attributes);

    if let Err((code, detail)) = schema_verdict(&security.schema, security.schema_mode, &entry) {
        return reject(response(code, &detail));
    }

    // Two accounts called `alice` make `uid=alice,…` ambiguous: a bind picks the first
    // match and the other account cannot be used at all. The check is over the users
    // OU only, so a group may still be named after a person.
    if let Err(duplicate) = crate::integrity::check_unique(
        directory,
        &entry,
        &entry_dn,
        &security.integrity.unique_attributes(),
    ) {
        return reject(response(
            ResultCode::ConstraintViolation,
            &duplicate.to_string(),
        ));
    }

    let actor = session
        .identity()
        .map(|identity| identity.dn.clone())
        .unwrap_or_default();
    let stamped = crate::operational::stamp_write(&entry, &actor, std::time::SystemTime::now());

    Outcome::Persist {
        changes: vec![EntryChange::Upsert { entry: stamped }],
        success: response(ResultCode::Success, ""),
    }
}

/// Handles a delete request.
pub fn handle_delete(
    session: &Session,
    directory: &Directory,
    message_id: MessageId,
    request: &DelRequest,
    security: &Security,
) -> Outcome {
    let entry_dn = dn::normalize(&request.0);
    let response = |code: ResultCode, diagnostic: &str| {
        super::responses::del_response(message_id, code, diagnostic)
    };

    if !dn::is_valid(&entry_dn) {
        return reject(response(ResultCode::InvalidDnSyntax, "wrong entry DN"));
    }

    // The domain and the two OUs are the shape of this server, the same reason they
    // cannot be modified.
    if entry_dn == directory.base_dn()
        || entry_dn == directory.ou_dn(directory.users_ou_name())
        || entry_dn == directory.ou_dn(directory.groups_ou_name())
    {
        return reject(response(
            ResultCode::UnwillingToPerform,
            &format!("delete of '{entry_dn}' is not supported"),
        ));
    }

    if directory.find(&entry_dn).is_none() {
        return reject(response(ResultCode::NoSuchObject, ""));
    }

    if !may_write(security, session, directory, &entry_dn) {
        return reject(response(ResultCode::InsufficientAccessRights, ""));
    }

    // Deleting a branch would leave its children with no parent. RFC 4511 says
    // `notAllowedOnNonLeaf`, and it is the answer that stops a client from silently
    // orphaning a subtree.
    if !directory
        .entries(&entry_dn, crate::directory::Scope::OneLevel)
        .is_empty()
    {
        return reject(response(
            ResultCode::NotAllowedOnNonLeaf,
            "the entry has children",
        ));
    }

    // A group that lists this user keeps a name that no longer resolves, and nothing
    // says so: the membership looks like a person and is not one. The cleanup belongs
    // here, in the same change set, so the delete and the cleanup cannot half-happen.
    let mut changes = vec![EntryChange::Delete {
        dn: entry_dn.clone(),
    }];

    if let Some(entry) = directory
        .find(&entry_dn)
        .filter(|_| security.integrity.referential_integrity)
    {
        for group in crate::integrity::changes_for_removed(directory, entry) {
            changes.push(EntryChange::Upsert { entry: group });
        }
    }

    Outcome::Persist {
        changes,
        success: response(ResultCode::Success, ""),
    }
}

/// Handles a modifyDN (rename) request.
///
/// Renaming an entry that has children renames the whole subtree: every descendant's
/// DN has the old prefix, and leaving them behind would either orphan them or require
/// a second request that clients do not send. The change set carries every renamed
/// entry, so `redb` applies them in one transaction.
pub fn handle_modify_dn(
    session: &Session,
    directory: &Directory,
    message_id: MessageId,
    request: &ModifyDnRequest,
    security: &Security,
) -> Outcome {
    let entry_dn = dn::normalize(&request.entry.0);
    let response = |code: ResultCode, diagnostic: &str| {
        super::responses::modify_dn_response(message_id, code, diagnostic)
    };

    if !dn::is_valid(&entry_dn) {
        return reject(response(ResultCode::InvalidDnSyntax, "wrong entry DN"));
    }

    let Some(entry) = directory.find(&entry_dn) else {
        return reject(response(ResultCode::NoSuchObject, ""));
    };

    if entry_dn == directory.base_dn()
        || entry_dn == directory.ou_dn(directory.users_ou_name())
        || entry_dn == directory.ou_dn(directory.groups_ou_name())
    {
        return reject(response(
            ResultCode::UnwillingToPerform,
            &format!("rename of '{entry_dn}' is not supported"),
        ));
    }

    if !may_write(security, session, directory, &entry_dn) {
        return reject(response(ResultCode::InsufficientAccessRights, ""));
    }

    let new_rdn = dn::normalize(&request.new_rdn.0);
    if !dn::is_valid(&format!("{new_rdn},dc=example,dc=com")) || !new_rdn.contains('=') {
        return reject(response(
            ResultCode::InvalidDnSyntax,
            "the new RDN is not an attribute value pair",
        ));
    }

    let parent = match request.new_superior.as_ref() {
        Some(superior) => dn::normalize(&superior.0),
        None => dn::split_first_rdn(&entry_dn).2,
    };

    if parent.is_empty() || directory.find(&parent).is_none() {
        return reject(response(
            ResultCode::NoSuchObject,
            "the new parent entry does not exist",
        ));
    }

    let new_dn = format!("{new_rdn},{parent}");
    if new_dn == entry_dn {
        // A rename that does not rename: answer success without a write, so a client
        // retrying an idempotent request does not get `entryAlreadyExists`.
        return Outcome::Persist {
            changes: Vec::new(),
            success: response(ResultCode::Success, ""),
        };
    }

    if directory.find(&new_dn).is_some() {
        return reject(response(ResultCode::EntryAlreadyExists, ""));
    }

    let (new_attribute, new_value) = match new_rdn.split_once('=') {
        Some((attribute, value)) => (attribute.to_string(), value.to_string()),
        None => {
            return reject(response(
                ResultCode::InvalidDnSyntax,
                "the new RDN has no value",
            ));
        }
    };

    // The entry itself: new DN, naming attribute updated, old value removed when the
    // client asked for it (RFC 4511 §4.9).
    //
    // `entry.dn()` and not `entry_dn`: a client may address an entry as
    // `uid=alice,ou=users,…` while the entry is stored as `cn=alice,ou=users,…`. The
    // delete has to name the DN that exists, or the rename leaves the old entry behind
    // and creates a second one.
    let real_dn = entry.dn().to_string();
    let (old_attribute, old_value, _) = dn::split_first_rdn(&real_dn);
    let attributes = rename_naming_attribute(
        entry.attributes(),
        &old_attribute,
        &old_value,
        &new_attribute,
        &new_value,
        request.delete_old_rdn,
    );

    let renamed = Entry::new(new_dn.clone(), attributes);

    if let Err((code, detail)) = schema_verdict(&security.schema, security.schema_mode, &renamed) {
        return reject(response(code, &detail));
    }

    let mut changes = vec![EntryChange::Delete {
        dn: real_dn.clone(),
    }];

    // The subtree, if any: every descendant gets the new parent in one change set.
    //
    // A DN lists the leaf first, so a descendant's DN ENDS with the ancestor's DN:
    // `cn=carol,ou=devel,dc=…` under `ou=devel,dc=…`. The part to keep is therefore the
    // prefix, and the part to replace is the suffix — the other way round would rename
    // the child to `cn=carol,ou=engineering,…` only by accident.
    for descendant in directory.entries(&real_dn, crate::directory::Scope::Subtree) {
        if descendant.dn() == real_dn {
            continue;
        }

        let Some(head) = descendant.dn().strip_suffix(&real_dn) else {
            continue;
        };
        let moved_dn = format!("{head}{new_dn}");
        let moved = Entry::new(moved_dn, descendant.attributes().clone());

        changes.push(EntryChange::Delete {
            dn: descendant.dn().to_string(),
        });
        changes.push(EntryChange::Upsert { entry: moved });
    }

    // A group listing the old name would point at nobody; the membership follows the
    // user, in the same change set as the rename itself.
    if security.integrity.referential_integrity {
        for group in crate::integrity::retarget_members(directory, entry, &renamed) {
            changes.push(EntryChange::Upsert { entry: group });
        }
    }

    changes.push(EntryChange::Upsert { entry: renamed });

    Outcome::Persist {
        changes,
        success: super::responses::modify_dn_response(message_id, ResultCode::Success, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attributes() -> Attributes {
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "inetOrgPerson".to_string()],
            ))
            .push(Attribute::single("cn", "alice"))
            .push(Attribute::single("sn", "Surname"))
            .push(Attribute::single("uid", "alice"))
    }

    fn values(attributes: &Attributes, name: &str) -> Option<Vec<String>> {
        attributes
            .get(name)
            .map(|attribute| attribute.values.to_vec())
    }

    #[test]
    fn a_rename_on_the_same_attribute_replaces_the_value() {
        let renamed = rename_naming_attribute(&attributes(), "cn", "alice", "cn", "alicia", true);

        assert_eq!(
            values(&renamed, "cn"),
            Some(vec!["alicia".to_string()]),
            "the old value goes and the new one takes its place, in one attribute"
        );
        assert_eq!(
            renamed
                .values()
                .iter()
                .filter(|attribute| attribute.name.eq_ignore_ascii_case("cn"))
                .count(),
            1,
            "a rename must not leave two cn attributes behind"
        );
    }

    #[test]
    fn without_delete_old_rdn_both_values_are_kept() {
        let renamed = rename_naming_attribute(&attributes(), "cn", "alice", "cn", "alicia", false);

        let values = values(&renamed, "cn").expect("cn");
        assert!(values.contains(&"alice".to_string()));
        assert!(values.contains(&"alicia".to_string()));
    }

    #[test]
    fn a_rename_onto_a_new_attribute_adds_it_and_drops_the_old_one() {
        let renamed = rename_naming_attribute(&attributes(), "uid", "alice", "cn", "alicia", true);

        // `cn: alice` was NOT the old RDN — `uid=alice` was — so it stays untouched and
        // the new value is added beside it.
        assert_eq!(
            values(&renamed, "cn"),
            Some(vec!["alice".to_string(), "alicia".to_string()])
        );
        assert_eq!(
            values(&renamed, "uid"),
            None,
            "the old naming attribute disappears when its last value goes"
        );
    }

    #[test]
    fn a_rename_onto_a_new_attribute_keeps_the_old_one_when_asked() {
        let renamed = rename_naming_attribute(&attributes(), "uid", "alice", "cn", "alicia", false);

        assert!(
            values(&renamed, "cn")
                .expect("cn")
                .contains(&"alicia".to_string())
        );
        assert_eq!(
            values(&renamed, "uid"),
            Some(vec!["alice".to_string()]),
            "the client asked to keep the old RDN value"
        );
    }

    #[test]
    fn a_rename_keeps_the_other_values_of_the_attribute() {
        let attributes = Attributes::new()
            .push(Attribute::new(
                "cn",
                vec!["alice".to_string(), "alice.smith".to_string()],
            ))
            .push(Attribute::single("sn", "Surname"));

        let renamed = rename_naming_attribute(&attributes, "cn", "alice", "cn", "alicia", true);

        assert_eq!(
            values(&renamed, "cn"),
            Some(vec!["alice.smith".to_string(), "alicia".to_string()]),
            "only the old RDN value goes; the rest of the attribute survives"
        );
    }

    #[test]
    fn a_rename_preserves_the_flags_of_the_attribute() {
        let attributes = Attributes::new().push(
            Attribute::new("userPassword", vec!["{SSHA}AbC".to_string()])
                .case_sensitive()
                .sensitive()
                .operational(),
        );

        let renamed = rename_naming_attribute(
            &attributes,
            "userPassword",
            "{SSHA}AbC",
            "userPassword",
            "{SSHA}New",
            true,
        );

        let password = renamed.get("userPassword").expect("password");
        assert!(
            password.flags.case_sensitive && password.flags.sensitive && password.flags.operational,
            "a rename must not change what an attribute is, only its value"
        );
    }

    #[test]
    fn renaming_to_the_same_value_changes_nothing() {
        let renamed = rename_naming_attribute(&attributes(), "cn", "alice", "cn", "alice", true);

        assert_eq!(values(&renamed, "cn"), Some(vec!["alice".to_string()]));
    }
}
