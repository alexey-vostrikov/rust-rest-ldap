//! `cn=config`: the configuration in force, published over the protocol.
//!
//! OpenLDAP answers `ldapsearch -b cn=config` from `slapd.d`; 389 DS answers from its private
//! backend. This is the same idea with one deliberate difference: the subtree is **generated**
//! from the configuration document, never stored separately. There is then no second copy to
//! drift from the file the server actually read, and no chance of an operator editing a stored
//! copy that the process does not consult.
//!
//! The document is a YAML mapping, and the tree is that mapping, one level per mapping:
//!
//! ```text
//! cn=config                    restldap-listen-addr, restldap-backend, ...
//!  cn=backends                 restldap-url, restldap-users-path, ...
//!   cn=file                    restldap-users-path, restldap-groups-path
//!   cn=redb                    restldap-path, restldap-durability
//!  cn=indexes                  restldap-default
//!   cn=attributes              restldap-cn, restldap-uid, restldap-mail, ...
//!  cn=access                   (a list of rules)
//!   cn=1                       restldap-subject, restldap-attributes, restldap-rights
//!   cn=2                       ...
//! ```
//!
//! Four rules make the mapping reversible, which is what a writable `cn=config` will need:
//!
//! 1. every configuration key publishes as `restldap-<key>`, with `_` turned into `-`;
//! 2. a scalar becomes an attribute value;
//! 3. a list of scalars becomes a multi-valued attribute;
//! 4. a list of mappings becomes one entry per item, named by its position - the problem
//!    `slapd.d` solves with `{X}` in the RDN, solved here by an index that cannot disaggregate
//!    from the value it orders.
//!
//! The prefix is not decoration. Both reference servers namespace their configuration
//! attributes (`olc*`, `nsslapd-*`) for the same reason: the section entries are named by
//! `cn`, and a document key `cn` - an index on the `cn` attribute, say - would otherwise mean
//! two things in one entry. Two consequences follow: the mapping is reversible without a
//! translation table, and `cn`/`objectClass` can never collide with a setting.
//!
//! Two things are deliberately absent. Defaults that the document does not mention: this
//! subtree publishes what is written, like `slapd.d`, not an expansion of it - an expanded
//! default would be written back on the next edit and become a setting nobody chose. And the
//! command-line and environment overrides, which are not part of a configuration document at
//! all: `slapd.d` does not record `-h` either.

use std::collections::BTreeMap;

use rasn_ldap::{LdapMessage, MessageId, ModifyRequest, ResultCode, SearchRequest};
use serde_json::Value;

use super::responses::{search_done, search_result_entry};
use super::session::Session;
use crate::config::Document;
use crate::model::{Attribute, Attributes, Entry};

/// The subtree's own name, as an operator types it.
pub const BASE_DN: &str = "cn=config";

/// Prefix of every configuration attribute in this subtree.
pub const PREFIX: &str = "restldap-";

/// Where the document came from, as an operational attribute of the base entry.
pub const ORIGIN_ATTRIBUTE: &str = "restldap-origin";

/// The structural class every entry here carries.
///
/// Not in the published schema: like `cn=Subschema`, this subtree lives outside the naming
/// context and is served by the protocol layer rather than read from the backends, so its
/// attributes are not the directory's attributes.
const OBJECT_CLASS: [&str; 2] = ["top", "restLdapConfig"];

/// Why a document cannot be published as entries.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("the configuration document does not parse: {detail}")]
    Parse { detail: String },
    #[error("the configuration document is a list or a scalar, so it has no entries to publish")]
    NotAMapping,
    #[error(
        "'{key}' is a list of mixed values: a list is either all scalars, which is one \
         multi-valued attribute, or all mappings, which is one entry per item"
    )]
    MixedList { key: String },
    #[error("the configuration key '{key}' is not usable as part of an attribute name")]
    BadKey { key: String },
    #[error(
        "'{first}' and '{second}' would both publish as '{attribute}': `_` becomes `-` in an \
         attribute name, so the two keys cannot be told apart over the protocol"
    )]
    Collision {
        first: String,
        second: String,
        attribute: String,
    },
}

/// True when `base_object` addresses `cn=config` or anything under it.
pub fn is_config_dn(base_object: &str) -> bool {
    let normalized = crate::dn::normalize(base_object);
    normalized == BASE_DN || normalized.ends_with(&format!(",{BASE_DN}"))
}

/// The subtree as ordinary entries, so filters and selection work on it unchanged.
///
/// `None` means the server was configured by flags and defaults alone: the base entry then
/// says so through [`ORIGIN_ATTRIBUTE`] rather than leaving a client to guess whether an empty
/// subtree means "nothing is set" or "the server cannot tell".
pub fn entries(document: Option<&Document>) -> Result<Vec<Entry>, Error> {
    let mut out = Vec::new();

    let origin = match document {
        Some(document) => document.origin.clone(),
        None => "none".to_string(),
    };

    let mapping = match document {
        Some(document) => {
            let value: Value =
                serde_saphyr::from_str(&document.text).map_err(|err| Error::Parse {
                    detail: err.to_string(),
                })?;
            match value {
                Value::Object(mapping) => mapping,
                _ => return Err(Error::NotAMapping),
            }
        }
        None => serde_json::Map::new(),
    };

    render(BASE_DN, "config", &mapping, Some(&origin), &mut out)?;

    Ok(out)
}

/// What sits below an entry, waiting to be rendered.
enum Child<'a> {
    /// A mapping: one entry, named by the key.
    Section(&'a serde_json::Map<String, Value>),
    /// A list of mappings: one entry named by the key, and one entry per item under it.
    ///
    /// The intermediate entry is what keeps the mapping reversible: without it the items would
    /// hang directly off the parent, and reading the tree back could not tell which key they
    /// belonged to.
    List(Vec<&'a serde_json::Map<String, Value>>),
}

/// Renders one mapping as an entry and everything below it.
fn render(
    dn: &str,
    name: &str,
    mapping: &serde_json::Map<String, Value>,
    origin: Option<&str>,
    out: &mut Vec<Entry>,
) -> Result<(), Error> {
    let mut attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            OBJECT_CLASS.iter().map(|name| name.to_string()).collect(),
        ))
        .push(Attribute::single("cn", name));

    // Children are collected first so the entry is pushed whole and before its subtree.
    let mut children: Vec<(String, Child<'_>)> = Vec::new();

    // Two keys that differ only in `_` against `-` would publish as one attribute, and reading
    // the entry back could not say which key it was.
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    for key in mapping.keys() {
        let attribute = attribute_name(key)?;
        if let Some(first) = seen.insert(attribute.clone(), key.as_str()) {
            return Err(Error::Collision {
                first: first.to_string(),
                second: key.clone(),
                attribute,
            });
        }
    }

    for (key, value) in mapping {
        let attribute = attribute_name(key)?;

        match value {
            Value::Object(inner) => children.push((key.clone(), Child::Section(inner))),
            Value::Array(items) => {
                let scalars: Option<Vec<String>> = items.iter().map(scalar).collect();
                match scalars {
                    Some(values) if !values.is_empty() => {
                        attributes = attributes.push(Attribute::new(attribute, values));
                    }
                    Some(_) => {
                        // An empty list is not an empty attribute: LDAP has no such value, and
                        // "not set" is exactly what the absent key would mean.
                    }
                    None => {
                        let mut sections = Vec::new();
                        for item in items {
                            match item {
                                Value::Object(inner) => sections.push(inner),
                                _ => return Err(Error::MixedList { key: key.clone() }),
                            }
                        }
                        children.push((key.clone(), Child::List(sections)));
                    }
                }
            }
            other => {
                if let Some(value) = scalar(other) {
                    attributes = attributes.push(Attribute::single(attribute, &value));
                }
                // A null means "not set" - the same thing a missing key means, so publishing
                // it as an empty value would invent a distinction the document does not make.
            }
        }
    }

    if let Some(origin) = origin {
        attributes = attributes.push(Attribute::single(ORIGIN_ATTRIBUTE, origin).operational());
    }

    out.push(Entry::new(dn.to_string(), attributes));

    for (child_name, child) in children {
        let child_dn = format!("cn={child_name},{dn}");
        match child {
            Child::Section(inner) => render(&child_dn, &child_name, inner, None, out)?,
            Child::List(sections) => {
                render(&child_dn, &child_name, &serde_json::Map::new(), None, out)?;
                for (position, section) in sections.iter().enumerate() {
                    let item = (position + 1).to_string();
                    let item_dn = format!("cn={item},{child_dn}");
                    render(&item_dn, &item, section, None, out)?;
                }
            }
        }
    }

    Ok(())
}

/// The attribute name a configuration key publishes as.
fn attribute_name(key: &str) -> Result<String, Error> {
    let translated = key.replace('_', "-");
    let usable = !translated.is_empty()
        && translated
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-');

    if !usable {
        return Err(Error::BadKey {
            key: key.to_string(),
        });
    }

    Ok(format!("{PREFIX}{translated}"))
}

/// The LDAP value of a YAML scalar, or `None` when the value is not a scalar.
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        // LDAP's Boolean syntax spells these in capitals; a client that renders `true` as a
        // string is a client that showed the YAML, not the directory.
        Value::Bool(true) => Some("TRUE".to_string()),
        Value::Bool(false) => Some("FALSE".to_string()),
        _ => None,
    }
}

/// What a change did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committed {
    /// The generation the changed document was committed as.
    pub generation: u64,
    /// The document keys the change touched, named as the document names them.
    pub keys: Vec<String>,
}

/// Why a change was refused, in the terms the protocol answers with.
///
/// A struct rather than an enum because every refusal is "this code and this sentence": the
/// caller builds one response from it and has no decision left to make. The sentences name what
/// the operator has to do instead, since a refusal that only says "no" gets a second request
/// with the same shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: ResultCode,
    pub detail: String,
}

impl Refusal {
    fn new(code: ResultCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// Applies a change to the configuration and commits it as a new generation.
///
/// The change semantics are not re-invented: the target entry is an ordinary [`Entry`], so the
/// change runs through [`crate::mutate`] - the same code that answers `modify` for the directory,
/// with the same result codes for the same mistakes. What is specific here is the way back: the
/// edited entry is translated into document keys, serialised and validated as a configuration
/// before anything is committed.
///
/// Three rules make the way back exact:
///
/// 1. **Only values change.** Every attribute written must name a key that is already in the
///    document, because the attribute name alone cannot say whether `restldap-users-path` was
///    written `users_path` or `users-path`. A setting that is not in the document is refused;
///    inventing one means inventing the key spelling too.
/// 2. **A value keeps the type the document gave it.** LDAP carries strings, a document carries
///    booleans and numbers: writing `"false"` where `false` was would parse as a string on the
///    next start and be refused, so the type of the existing value decides how the new one is
///    read.
/// 3. **The result must still be a configuration.** The document is resolved before it is
///    committed, so a change that would leave the server unable to start is refused here rather
///    than discovered at the next restart.
///
/// The base of the edit is the generation in force in the store, not the text loaded at
/// startup: two changes in a row must build on each other, and a change committed by another
/// process must not be overwritten by this one.
pub fn change(
    document: &Document,
    session: &Session,
    request: &ModifyRequest,
) -> Result<Committed, Refusal> {
    if !session.requester().admin {
        return Err(Refusal::new(
            ResultCode::InsufficientAccessRights,
            "cn=config holds the server's own settings, tokens included; only an administrator \
             changes it",
        ));
    }

    let Some(store_path) = document.store.as_deref() else {
        return Err(Refusal::new(
            ResultCode::UnwillingToPerform,
            "the configuration was read from a file, so there is no generation to commit a \
             change as: start the server with `-c` pointing at a configuration store directory, \
             or edit the file and restart",
        ));
    };

    // Structure first: `cn` and `objectClass` name the entry, and the origin is written by the
    // server. Letting `mutate` take them would produce an entry that no longer describes the
    // tree it sits in.
    for change in &request.changes {
        let name = change.modification.r#type.0.to_lowercase();
        if !name.starts_with(PREFIX) {
            return Err(Refusal::new(
                ResultCode::UnwillingToPerform,
                format!(
                    "'{}' is not a setting: this subtree's entries are named by their document \
                     key, and the origin is written by the server",
                    change.modification.r#type.0
                ),
            ));
        }
    }

    let store = crate::config_store::Store::open(store_path);
    let base = store.read_current().map_err(|err| {
        Refusal::new(
            ResultCode::Other,
            format!("the configuration store cannot be read: {err}"),
        )
    })?;

    let Some(text) = base else {
        return Err(Refusal::new(
            ResultCode::UnwillingToPerform,
            "the configuration store holds no generation, so there is nothing to change",
        ));
    };

    let dn = crate::dn::normalize(&request.object.0);
    let path = path_of(&dn).ok_or_else(|| {
        Refusal::new(
            ResultCode::InvalidDnSyntax,
            format!("'{dn}' is not inside {BASE_DN}"),
        )
    })?;

    // The entries are rendered from the generation in force, not from the text the server
    // loaded at startup: the difference is not cosmetic. Rendering from the startup text and
    // editing the store's text would copy the old value of every untouched key back into the
    // new document, so the second change would undo the first.
    let current = Document::new(text.clone(), document.origin.clone());
    let entries = entries(Some(&current)).map_err(|err| {
        Refusal::new(
            ResultCode::Other,
            format!("the configuration in force cannot be published: {err}"),
        )
    })?;

    let entry = entries
        .iter()
        .find(|entry| crate::dn::normalize(entry.dn()) == dn)
        .ok_or_else(|| {
            Refusal::new(
                ResultCode::NoSuchObject,
                format!("no such object: {}", request.object.0),
            )
        })?;

    let modified = crate::mutate::apply(
        entry,
        &super::modify::modifications(request),
        // No schema: these attributes are not the directory's, and the schema mode of a
        // directory must not decide whether a server setting can be written.
        None,
    )
    .map_err(|err| Refusal::new(super::modify::result_code(&err), err.to_string()))?;

    let mut tree: Value = serde_saphyr::from_str(&text).map_err(|err| {
        Refusal::new(
            ResultCode::Other,
            format!("the configuration document does not parse: {err}"),
        )
    })?;

    let keys = rewrite(&mut tree, &path, entry, &modified)?;
    if keys.is_empty() {
        return Err(Refusal::new(
            ResultCode::UnwillingToPerform,
            "the change leaves every setting as it was, so nothing is committed",
        ));
    }

    let changed = serde_saphyr::to_string(&tree).map_err(|err| {
        Refusal::new(
            ResultCode::Other,
            format!("the changed document cannot be written: {err}"),
        )
    })?;

    // The one check that turns "a document" into "a configuration": whatever a client wrote,
    // the server must still be able to start from it.
    crate::config::resolve(crate::config::Args::default(), Some(&changed), |_| None).map_err(
        |err| {
            Refusal::new(
                ResultCode::ConstraintViolation,
                format!("the change would leave an invalid configuration: {err}"),
            )
        },
    )?;

    let actor = session
        .identity()
        .map(|identity| identity.dn.clone())
        .unwrap_or_else(|| "anonymous".to_string());
    let note = format!("cn=config: {}", keys.join(", "));

    let generation = store
        .commit(&changed, &actor, &note)
        .map_err(|err| {
            Refusal::new(
                ResultCode::Other,
                format!("the change could not be committed: {err}"),
            )
        })?
        .number;

    Ok(Committed { generation, keys })
}

/// Copies the edited entry back into the document tree, returning the keys it touched.
fn rewrite(
    tree: &mut Value,
    path: &[String],
    before: &Entry,
    after: &Entry,
) -> Result<Vec<String>, Refusal> {
    let mapping = mapping_at(tree, path).ok_or_else(|| {
        Refusal::new(
            ResultCode::NoSuchObject,
            format!("'{}' is not a section of the document", path.join(",")),
        )
    })?;

    // The keys as the document spells them, and only the ones that are settings. A key whose
    // value is a section is published as a *child entry*, not as an attribute of this one, so
    // looking it up here would find nothing and read as "the client deleted it" - which once
    // deleted every section from the document on any change to the base entry.
    let declared: Vec<String> = mapping
        .iter()
        .filter(|(_, value)| is_setting(value))
        .map(|(key, _)| key.clone())
        .collect();

    // A setting that is in the entry but not in the document would need a key invented for it.
    for attribute in after.attributes().values() {
        let name = attribute.name.to_lowercase();
        if !name.starts_with(PREFIX) {
            continue;
        }
        // The origin is the server's own attribute on the base entry, not a document key, so it
        // is expected to be there without being one.
        if name == ORIGIN_ATTRIBUTE {
            continue;
        }

        // Case-insensitively, because an LDAP attribute name is case-insensitive: the document
        // key `AllowDangerousSettings` publishes as `restldap-AllowDangerousSettings`, and a
        // client sends it back in whatever case it likes.
        let known = declared.iter().any(|key| {
            attribute_name(key)
                .map(|attribute| attribute.eq_ignore_ascii_case(&name))
                .unwrap_or(false)
        });
        if !known {
            // `noSuchAttribute`, the answer RFC 4511 gives for a replace of an attribute the
            // entry does not have. The detail says why it cannot be added either.
            return Err(Refusal::new(
                ResultCode::NoSuchAttribute,
                format!(
                    "'{name}' is not a setting of this entry: a change may alter values that \
                     are already in the document, and adding a setting is a later step because \
                     the document key it should be written as is not recoverable from the \
                     attribute name"
                ),
            ));
        }
    }

    let mut touched = Vec::new();
    for key in &declared {
        let Ok(attribute) = attribute_name(key) else {
            continue;
        };

        let listed = before
            .attributes()
            .get(&attribute)
            .map(|attribute| attribute.values.clone())
            .unwrap_or_default();

        match after.attributes().get(&attribute) {
            // The attribute is gone: the client deleted every value, or the key itself.
            None => {
                mapping.remove(key);
                if !listed.is_empty() {
                    touched.push(key.clone());
                }
            }
            Some(attribute) => {
                let value = typed(mapping.get(key), &attribute.values, key)?;
                if Some(&value) != mapping.get(key) {
                    touched.push(key.clone());
                }
                mapping.insert(key.clone(), value);
            }
        }
    }

    Ok(touched)
}

/// True when a document value is a setting of the entry, not a section below it.
///
/// The same split the renderer makes, and it has to be the same: what is published as an
/// attribute must be what is written back from one, or the two disagree about the document.
fn is_setting(value: &Value) -> bool {
    match value {
        Value::Object(_) => false,
        // A list of mappings is a section; a list of scalars is one multi-valued setting.
        Value::Array(items) => !items.iter().any(|item| matches!(item, Value::Object(_))),
        _ => true,
    }
}

/// The document value a list of LDAP values becomes, keeping the type it already had.
fn typed(existing: Option<&Value>, values: &[String], key: &str) -> Result<Value, Refusal> {
    let one = |values: &[String]| -> Result<String, Refusal> {
        match values {
            [single] => Ok(single.clone()),
            _ => Err(Refusal::new(
                ResultCode::ConstraintViolation,
                format!("'{key}' holds one value, and {} were given", values.len()),
            )),
        }
    };

    match existing {
        Some(Value::Bool(_)) => {
            let text = one(values)?;
            match text.to_lowercase().as_str() {
                "true" => Ok(Value::Bool(true)),
                "false" => Ok(Value::Bool(false)),
                _ => Err(Refusal::new(
                    ResultCode::ConstraintViolation,
                    format!("'{key}' is a yes-or-no setting, and '{text}' is neither"),
                )),
            }
        }
        Some(Value::Number(number)) => {
            let text = one(values)?;
            // The document's own kind of number decides how the text is read: a float setting
            // stays a float, an integer setting does not become one.
            let parsed: Result<Value, ()> = if number.is_f64() {
                text.parse::<f64>()
                    .map(|value| serde_json::json!(value))
                    .map_err(|_| ())
            } else {
                match text.parse::<i64>() {
                    Ok(value) => Ok(serde_json::json!(value)),
                    Err(_) => text
                        .parse::<u64>()
                        .map(|value| serde_json::json!(value))
                        .map_err(|_| ()),
                }
            };
            parsed.map_err(|()| {
                Refusal::new(
                    ResultCode::ConstraintViolation,
                    format!("'{key}' is a number, and '{text}' is not"),
                )
            })
        }
        // A list keeps the shape of the list: one element is still a list, because writing a
        // bare scalar would change what the setting means to the reader.
        Some(Value::Array(items)) => {
            let template = items.first();
            values
                .iter()
                .map(|value| typed(template, std::slice::from_ref(value), key))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        _ => Ok(match values {
            [single] => Value::String(single.clone()),
            _ => Value::Array(values.iter().cloned().map(Value::String).collect()),
        }),
    }
}

/// The document path a DN addresses: `cn=file,cn=backends,cn=config` becomes `backends, file`.
fn path_of(dn: &str) -> Option<Vec<String>> {
    let normalized = crate::dn::normalize(dn);
    if normalized == BASE_DN {
        return Some(Vec::new());
    }

    let below = normalized.strip_suffix(&format!(",{BASE_DN}"))?;
    let mut path: Vec<String> = below
        .split(',')
        .map(|rdn| {
            rdn.split_once('=')
                .map(|(_, value)| value.trim().to_string())
                .unwrap_or_default()
        })
        .collect();
    path.reverse();

    if path.iter().any(|step| step.is_empty()) {
        return None;
    }

    Some(path)
}

/// The mapping a path addresses, when it addresses one.
fn mapping_at<'a>(
    node: &'a mut Value,
    path: &[String],
) -> Option<&'a mut serde_json::Map<String, Value>> {
    match descend(node, path)? {
        Value::Object(mapping) => Some(mapping),
        _ => None,
    }
}

/// Walks a path down the tree: a key for a mapping, a position for a list of mappings.
fn descend<'a>(node: &'a mut Value, path: &[String]) -> Option<&'a mut Value> {
    let Some((head, rest)) = path.split_first() else {
        return Some(node);
    };

    match node {
        Value::Object(mapping) => descend(mapping.get_mut(head)?, rest),
        Value::Array(items) => {
            // Positions are one-based in the DN, as `slapd.d` numbers its entries, and zero-based
            // in the array: one conversion, in one place.
            let position: usize = head.parse().ok()?;
            descend(items.get_mut(position.checked_sub(1)?)?, rest)
        }
        _ => None,
    }
}

/// Handles a search in the `cn=config` subtree.
///
/// Only an administrator reads it: the document carries `auth_token`, `callback_auth_token`
/// and every other secret in the file, and an operator who can read them over the protocol can
/// read them from the file anyway. The refusal is `insufficientAccessRights` rather than a
/// pretend "no such object": `cn=config` is a standard name and its existence is not a secret,
/// so hiding it only misleads the operator whose bind did not carry the admin flag.
pub fn search(
    session: &Session,
    message_id: MessageId,
    request: &SearchRequest,
    document: Option<&Document>,
    base_object: &str,
) -> Vec<LdapMessage> {
    if !session.requester().admin {
        return vec![search_done(
            message_id,
            ResultCode::InsufficientAccessRights,
            "cn=config holds the server's own settings, tokens included; only an administrator reads it",
        )];
    }

    let entries = match entries(document) {
        Ok(entries) => entries,
        Err(err) => {
            return vec![search_done(message_id, ResultCode::Other, &err.to_string())];
        }
    };

    let base = crate::dn::normalize(base_object.trim());
    if !entries
        .iter()
        .any(|entry| crate::dn::normalize(entry.dn()) == base)
    {
        return vec![search_done(
            message_id,
            ResultCode::NoSuchObject,
            &format!("no such object: {base_object}"),
        )];
    }

    let scope = super::search::scope_of(request);
    let selection: Vec<String> = request
        .attributes
        .iter()
        .map(|attribute| attribute.0.clone())
        .collect();

    let mut out = Vec::new();
    for entry in &entries {
        let dn = crate::dn::normalize(entry.dn());
        if dn == base {
            // RFC 4511 §4.5.1.2: one-level returns the children and not the base itself;
            // base and subtree both answer it.
            if matches!(scope, crate::directory::Scope::OneLevel) {
                continue;
            }
        } else if !in_scope(&dn, &base, scope) {
            continue;
        }

        match super::filter::matches(entry.attributes(), entry.dn(), &request.filter) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => {
                return vec![search_done(
                    message_id,
                    ResultCode::Other,
                    &format!("invalid filter: {err}"),
                )];
            }
        }

        out.push(search_result_entry(
            message_id,
            entry.dn(),
            &entry.attributes().select(entry.dn(), &selection),
        ));
    }

    out.push(search_done(message_id, ResultCode::Success, ""));
    out
}

/// True when `dn` is below `base` at the depth the scope allows.
fn in_scope(dn: &str, base: &str, scope: crate::directory::Scope) -> bool {
    use crate::directory::Scope;

    match scope {
        // The base entry itself is answered by the caller, which needs it either way.
        Scope::Base => false,
        Scope::OneLevel => parent(dn).as_deref() == Some(base),
        Scope::Subtree => under(dn, base),
    }
}

/// True when `dn` is strictly below `base`.
fn under(dn: &str, base: &str) -> bool {
    dn.ends_with(&format!(",{base}"))
}

/// The parent of a DN in this subtree, or `None` at the top.
fn parent(dn: &str) -> Option<String> {
    let (_, _, rest) = crate::dn::split_first_rdn(dn);
    if rest.is_empty() {
        return None;
    }
    Some(crate::dn::normalize(&rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::types::OctetString;
    use rasn_ldap::{
        AttributeDescription, ChangeOperation, LdapDn, ModifyRequest, ModifyRequestChanges,
        PartialAttribute,
    };

    fn document(text: &str) -> Document {
        Document::new(text, "file:/etc/rust-rest-ldap/config.yaml")
    }

    fn dns(entries: &[Entry]) -> Vec<String> {
        entries.iter().map(|entry| entry.dn().to_string()).collect()
    }

    fn find<'a>(entries: &'a [Entry], dn: &str) -> &'a Entry {
        entries
            .iter()
            .find(|entry| entry.dn() == dn)
            .unwrap_or_else(|| panic!("no entry {dn} among {:?}", dns(entries)))
    }

    fn values(entry: &Entry, name: &str) -> Vec<String> {
        entry
            .attributes()
            .get(name)
            .map(|attribute| attribute.values.to_vec())
            .unwrap_or_default()
    }

    fn attribute_names(entry: &Entry) -> Vec<String> {
        let mut names: Vec<String> = entry
            .attributes()
            .values()
            .iter()
            .map(|attribute| attribute.name.to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn every_name_in_the_subtree_is_recognised() {
        assert!(is_config_dn("cn=config"));
        assert!(is_config_dn("CN=Config,cn=config"));
        assert!(is_config_dn("cn=backends,cn=config"));
        assert!(is_config_dn("cn=file,cn=backends,cn=config"));
        assert!(!is_config_dn("cn=configs"));
        assert!(!is_config_dn("dc=example,dc=com"));
    }

    #[test]
    fn a_server_configured_without_a_document_says_so() {
        let entries = entries(None).expect("entries");

        assert_eq!(dns(&entries), vec!["cn=config"]);
        assert_eq!(values(&entries[0], "cn"), vec!["config"]);
        assert_eq!(
            values(&entries[0], ORIGIN_ATTRIBUTE),
            vec!["none"],
            "an empty subtree and an unknown origin must not look alike"
        );
    }

    #[test]
    fn a_scalar_becomes_a_prefixed_attribute_and_an_underscore_becomes_a_hyphen() {
        let text =
            "base_dn: dc=example,dc=com\nbackend: redb\nuse_tls: true\nupdate_interval: 30s\n";
        let entries = entries(Some(&document(text))).expect("entries");

        assert_eq!(dns(&entries), vec!["cn=config"]);
        assert_eq!(
            values(&entries[0], "restldap-base-dn"),
            vec!["dc=example,dc=com"]
        );
        assert_eq!(values(&entries[0], "restldap-backend"), vec!["redb"]);
        assert_eq!(
            values(&entries[0], "restldap-use-tls"),
            vec!["TRUE"],
            "LDAP Boolean syntax is capitalised, not the YAML spelling"
        );
        assert_eq!(values(&entries[0], "restldap-update-interval"), vec!["30s"]);
    }

    #[test]
    fn a_mapping_becomes_a_child_entry() {
        let text = "\
backends:
  file:
    users_path: users.json
    groups_path: groups.json
  redb:
    path: ./directory.redb
";
        let entries = entries(Some(&document(text))).expect("entries");

        assert_eq!(
            dns(&entries),
            vec![
                "cn=config",
                "cn=backends,cn=config",
                "cn=file,cn=backends,cn=config",
                "cn=redb,cn=backends,cn=config",
            ],
            "one level of the document is one level of the subtree"
        );
        assert_eq!(
            values(
                find(&entries, "cn=file,cn=backends,cn=config"),
                "restldap-users-path"
            ),
            vec!["users.json"]
        );
    }

    #[test]
    fn a_list_of_scalars_becomes_one_multi_valued_attribute() {
        let text = "indexes:\n  attributes:\n    cn: [eq, pres, sub]\n";
        let entries = entries(Some(&document(text))).expect("entries");
        let cn = find(&entries, "cn=attributes,cn=indexes,cn=config");

        assert_eq!(
            values(cn, "cn"),
            vec!["attributes"],
            "the entry is named by its key"
        );
        assert_eq!(
            values(cn, "restldap-cn"),
            vec!["eq", "pres", "sub"],
            "and the setting about cn is an attribute of its own, which the prefix makes possible"
        );
    }

    #[test]
    fn a_document_key_named_cn_cannot_be_confused_with_the_entry_name() {
        // The reason for the prefix: without it this document would put two meanings into one
        // attribute, and reading the entry back could not say which value named it.
        let entries = entries(Some(&document("cn: something\n"))).expect("entries");

        assert_eq!(entries[0].dn(), "cn=config");
        assert_eq!(values(&entries[0], "cn"), vec!["config"]);
        assert_eq!(values(&entries[0], "restldap-cn"), vec!["something"]);
    }

    #[test]
    fn a_list_of_mappings_becomes_one_entry_per_item_in_order() {
        let text = "\
access:
  - subject: admin
    attributes: ['*']
    rights: [read, write]
  - subject: anonymous
    rights: []
";
        let entries = entries(Some(&document(text))).expect("entries");

        assert_eq!(
            dns(&entries),
            vec![
                "cn=config",
                "cn=access,cn=config",
                "cn=1,cn=access,cn=config",
                "cn=2,cn=access,cn=config",
            ],
            "the position in the list is the position in the subtree"
        );
        assert_eq!(
            values(
                find(&entries, "cn=1,cn=access,cn=config"),
                "restldap-subject"
            ),
            vec!["admin"]
        );
        assert_eq!(
            values(
                find(&entries, "cn=2,cn=access,cn=config"),
                "restldap-subject"
            ),
            vec!["anonymous"]
        );
        assert!(
            values(
                find(&entries, "cn=2,cn=access,cn=config"),
                "restldap-rights"
            )
            .is_empty(),
            "an empty list is not an empty attribute; it is the same as an absent key"
        );
    }

    #[test]
    fn a_null_value_publishes_nothing() {
        let entries = entries(Some(&document("http_listen_addr:\n"))).expect("entries");

        assert!(
            entries[0]
                .attributes()
                .get("restldap-http-listen-addr")
                .is_none(),
            "'not set' and 'set to nothing' are the same thing in a document"
        );
    }

    #[test]
    fn the_origin_is_carried_on_the_base_entry_only() {
        let text = "backends:\n  file:\n    users_path: users.json\n";
        let entries = entries(Some(&document(text))).expect("entries");

        assert_eq!(
            values(&entries[0], ORIGIN_ATTRIBUTE),
            vec!["file:/etc/rust-rest-ldap/config.yaml"]
        );
        assert!(
            find(&entries, "cn=file,cn=backends,cn=config")
                .attributes()
                .get(ORIGIN_ATTRIBUTE)
                .is_none(),
            "one document, one origin: repeating it on every entry is noise"
        );
    }

    #[test]
    fn a_document_that_is_not_a_mapping_is_refused_rather_than_published_as_one_entry() {
        let err = entries(Some(&document("- a\n- b\n"))).expect_err("must refuse");
        assert_eq!(err, Error::NotAMapping);

        let err = entries(Some(&document("  : :\n"))).expect_err("must refuse");
        assert!(matches!(err, Error::Parse { .. }), "{err}");
    }

    #[test]
    fn a_mixed_list_is_refused_rather_than_half_published() {
        let err = entries(Some(&document("access:\n  - subject: admin\n  - admin\n")))
            .expect_err("must refuse");
        assert_eq!(
            err,
            Error::MixedList {
                key: "access".to_string()
            }
        );
    }

    #[test]
    fn a_key_that_is_not_usable_in_an_attribute_name_is_refused() {
        let err = entries(Some(&document("\"a b\": 1\n"))).expect_err("must refuse");
        assert_eq!(
            err,
            Error::BadKey {
                key: "a b".to_string()
            }
        );
    }

    #[test]
    fn the_published_tree_is_the_document_and_not_an_expansion_of_it() {
        // The property a writable subtree will rest on: every key in the document appears, and
        // nothing appears that the document does not mention. A default expanded here would be
        // written back on the next edit and become a setting the operator never chose.
        let text = "base_dn: dc=example,dc=com\nindexes:\n  default: [pres]\n";
        let entries = entries(Some(&document(text))).expect("entries");

        assert_eq!(
            attribute_names(&entries[0]),
            vec!["cn", "objectClass", "restldap-base-dn", ORIGIN_ATTRIBUTE],
            "the document has one key, so the base entry has one setting"
        );
        assert_eq!(
            attribute_names(find(&entries, "cn=indexes,cn=config")),
            vec!["cn", "objectClass", "restldap-default"]
        );
    }

    #[test]
    fn the_shipped_example_publishes_every_shape_it_uses() {
        // The shipped `config.yaml` is the document operators copy, and it uses every shape the
        // renderer has to handle: nested maps three deep, lists of scalars, a list of maps.
        let text = include_str!("../../config.yaml");
        let entries = entries(Some(&document(text))).expect("the shipped example must publish");

        assert_eq!(
            dns(&entries),
            vec![
                "cn=config",
                "cn=backends,cn=config",
                "cn=file,cn=backends,cn=config",
                "cn=redb,cn=backends,cn=config",
                "cn=rest,cn=backends,cn=config",
                "cn=bind,cn=config",
                "cn=indexes,cn=config",
                "cn=attributes,cn=indexes,cn=config",
                "cn=integrity,cn=config",
                "cn=observability,cn=config",
                "cn=passwords,cn=config",
                "cn=schema,cn=config",
            ],
            "every section of the shipped example is published. Keys come out sorted, not in \
             the order the file was written: a YAML mapping has no order to preserve"
        );

        let rest = find(&entries, "cn=rest,cn=backends,cn=config");
        assert_eq!(
            values(rest, "restldap-url"),
            vec!["http://localhost:8000/api"]
        );

        let attributes = find(&entries, "cn=attributes,cn=indexes,cn=config");
        assert_eq!(values(attributes, "restldap-cn"), vec!["eq", "pres"]);

        // The commented-out `access:` section stays commented, so no rule entries exist: the
        // subtree must publish the document as it is, not the example the comment describes.
        assert!(
            !entries
                .iter()
                .any(|entry| entry.dn() == "cn=1,cn=access,cn=config"),
            "a commented-out section is not a setting"
        );
    }

    // ---- the way back: a change becomes a new document ----

    /// A store with `text` as its only generation.
    fn store_with(text: &str) -> (tempfile::TempDir, Document) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::config_store::Store::open(dir.path().join("config.d"));
        store.commit(text, "test", "initial").expect("commit");

        let document = Document::new(text, format!("store:{}", dir.path().display()))
            .with_store(Some(dir.path().join("config.d")));

        (dir, document)
    }

    fn change_of(pairs: &[(ChangeOperation, &str, &[&str])]) -> ModifyRequest {
        ModifyRequest {
            object: LdapDn::from("cn=config"),
            changes: pairs
                .iter()
                .map(|(operation, attribute, values)| ModifyRequestChanges {
                    operation: *operation,
                    modification: PartialAttribute::new(
                        AttributeDescription::from(*attribute),
                        rasn::types::SetOf::from_vec(
                            values
                                .iter()
                                .map(|value| OctetString::from(value.as_bytes().to_vec()))
                                .collect(),
                        ),
                    ),
                })
                .collect(),
        }
    }

    fn as_admin() -> Session {
        let mut session = Session::new();
        session.set_identity(super::super::session::Identity::new(
            "cn=admin,ou=users,dc=example,dc=com",
            true,
        ));
        session
    }

    /// The document as the store holds it after the change.
    fn in_store(document: &Document) -> String {
        let store = crate::config_store::Store::open(document.store.clone().expect("store"));
        store.read_current().expect("read").expect("generation")
    }

    #[test]
    fn a_boolean_setting_stays_a_boolean_after_a_change() {
        // The crux of the way back: LDAP carries the string "false", and a document that
        // records it as a string would be refused by the parser on the next start.
        let text = "log_timestamp: false\nuse_tls: false\n";
        let (_dir, document) = store_with(text);

        let committed = change(
            &document,
            &as_admin(),
            &change_of(&[(
                ChangeOperation::Replace,
                "restldap-log-timestamp",
                &["TRUE"],
            )]),
        )
        .expect("change");

        assert_eq!(committed.generation, 2);
        assert_eq!(
            in_store(&document).trim(),
            "log_timestamp: true\nuse_tls: false",
            "the value is written as a boolean, and the key keeps its document spelling"
        );
    }

    #[test]
    fn a_boolean_setting_refuses_a_word_that_is_neither() {
        let text = "log_timestamp: false\n";
        let (_dir, document) = store_with(text);

        let refusal = change(
            &document,
            &as_admin(),
            &change_of(&[(
                ChangeOperation::Replace,
                "restldap-log-timestamp",
                &["maybe"],
            )]),
        )
        .expect_err("must refuse");

        assert_eq!(refusal.code, ResultCode::ConstraintViolation);
        assert!(refusal.detail.contains("yes-or-no"), "{}", refusal.detail);
        let store = crate::config_store::Store::open(document.store.clone().expect("store"));
        assert_eq!(
            store.history().expect("history").len(),
            1,
            "a refused change commits nothing"
        );
    }

    #[test]
    fn a_number_setting_stays_a_number() {
        let text = "backends:\n  redb:\n    path: d.redb\n    size: 4096\n";
        let (_dir, document) = store_with(text);

        let mut request = change_of(&[(ChangeOperation::Replace, "restldap-size", &["8192"])]);
        request.object = LdapDn::from("cn=redb,cn=backends,cn=config");
        change(&document, &as_admin(), &request).expect("a number is accepted as text");

        let text = in_store(&document);
        assert!(
            text.contains("size: 8192"),
            "the number is written unquoted: {text}"
        );
    }

    #[test]
    fn a_list_keeps_its_shape() {
        let text = "indexes:\n  attributes:\n    cn: [eq, pres]\n";
        let (_dir, document) = store_with(text);

        let mut request = change_of(&[
            (ChangeOperation::Add, "restldap-cn", &["sub"]),
            (ChangeOperation::Delete, "restldap-cn", &["pres"]),
        ]);
        request.object = LdapDn::from("cn=attributes,cn=indexes,cn=config");
        let committed = change(&document, &as_admin(), &request).expect("change");

        assert_eq!(committed.keys, vec!["cn"]);
        assert_eq!(
            in_store(&document).trim(),
            "indexes:\n  attributes:\n    cn:\n    - eq\n    - sub",
            "one value added, one removed, and the list stays a list"
        );
    }

    #[test]
    fn a_setting_that_the_document_does_not_have_is_refused_rather_than_invented() {
        // The attribute name cannot say how the key was spelled: `restldap-users-path` could be
        // `users_path` or `users-path`. Writing one would guess, and the guess would be a
        // second spelling of one setting.
        let text = "listen_addr: 127.0.0.1:1389\n";
        let (_dir, document) = store_with(text);

        let refusal = change(
            &document,
            &as_admin(),
            &change_of(&[(
                ChangeOperation::Replace,
                "restldap-users-path",
                &["users.json"],
            )]),
        )
        .expect_err("must refuse");

        assert_eq!(refusal.code, ResultCode::NoSuchAttribute);
        assert!(
            refusal.detail.contains("not a setting of this entry"),
            "{}",
            refusal.detail
        );
    }

    #[test]
    fn the_entry_name_cannot_be_written() {
        // `cn` and `objectClass` name the entry: they follow from the document key, so a client
        // writing them would move the entry out from under the key it belongs to.
        for attribute in ["cn", "objectClass"] {
            let (_dir, document) = store_with("listen_addr: 127.0.0.1:1389\n");
            let refusal = change(
                &document,
                &as_admin(),
                &change_of(&[(ChangeOperation::Replace, attribute, &["x"])]),
            )
            .expect_err("must refuse");

            assert_eq!(
                refusal.code,
                ResultCode::UnwillingToPerform,
                "{attribute} must be refused"
            );
            assert!(
                refusal.detail.contains("is not a setting"),
                "{attribute}: {}",
                refusal.detail
            );
        }
    }

    #[test]
    fn the_origin_is_the_servers_own_and_cannot_be_written() {
        // It says which file or generation the server read, so a client that could write it
        // would make the answer to "what am I running" a client's opinion.
        let (_dir, document) = store_with("listen_addr: 127.0.0.1:1389\n");

        let refusal = change(
            &document,
            &as_admin(),
            &change_of(&[(ChangeOperation::Replace, "restldap-origin", &["x"])]),
        )
        .expect_err("must refuse");

        assert_eq!(refusal.code, ResultCode::ConstraintViolation);
        assert!(
            refusal.detail.to_lowercase().contains("not"),
            "the refusal says it cannot be written: {}",
            refusal.detail
        );
    }

    #[test]
    fn only_an_administrator_changes_the_document() {
        let (_dir, document) = store_with("listen_addr: 127.0.0.1:1389\n");

        let refusal = change(
            &document,
            &Session::new(),
            &change_of(&[(
                ChangeOperation::Replace,
                "restldap-listen-addr",
                &["0.0.0.0:389"],
            )]),
        )
        .expect_err("must refuse");

        assert_eq!(refusal.code, ResultCode::InsufficientAccessRights);
    }

    #[test]
    fn a_document_from_a_file_cannot_be_changed_because_there_is_no_generation_to_commit() {
        let document = Document::new("listen_addr: 127.0.0.1:1389\n", "file:/etc/config.yaml");

        let refusal = change(
            &document,
            &as_admin(),
            &change_of(&[(
                ChangeOperation::Replace,
                "restldap-listen-addr",
                &["0.0.0.0:389"],
            )]),
        )
        .expect_err("must refuse");

        assert_eq!(refusal.code, ResultCode::UnwillingToPerform);
        assert!(
            refusal
                .detail
                .contains("pointing at a configuration store directory"),
            "the refusal says what to do instead: {}",
            refusal.detail
        );
    }

    #[test]
    fn a_change_that_would_break_the_configuration_is_refused_before_it_is_committed() {
        // The one check that turns a document into a configuration: whatever a client writes,
        // the server has to be able to start from the result.
        let text = "schema:\n  mode: strict\n";
        let (_dir, document) = store_with(text);

        let mut request = change_of(&[(ChangeOperation::Replace, "restldap-mode", &["banana"])]);
        request.object = LdapDn::from("cn=schema,cn=config");
        let refusal = change(&document, &as_admin(), &request).expect_err("must refuse");

        assert_eq!(refusal.code, ResultCode::ConstraintViolation);
        assert!(
            refusal
                .detail
                .contains("would leave an invalid configuration"),
            "{}",
            refusal.detail
        );
        let store = crate::config_store::Store::open(document.store.clone().expect("store"));
        assert_eq!(
            store.history().expect("history").len(),
            1,
            "nothing committed"
        );
    }

    #[test]
    fn a_change_that_changes_nothing_commits_nothing() {
        let (_dir, document) = store_with("listen_addr: 127.0.0.1:1389\n");

        let refusal = change(
            &document,
            &as_admin(),
            &change_of(&[(
                ChangeOperation::Replace,
                "restldap-listen-addr",
                &["127.0.0.1:1389"],
            )]),
        )
        .expect_err("must refuse");

        assert!(
            refusal.detail.contains("nothing is committed"),
            "{}",
            refusal.detail
        );
    }

    #[test]
    fn two_changes_in_a_row_build_on_each_other() {
        // The base of a change is the generation in force, not the text loaded at startup:
        // otherwise the second change would silently undo the first.
        let (_dir, document) = store_with("listen_addr: 127.0.0.1:1389\nbackend: redb\n");

        change(
            &document,
            &as_admin(),
            &change_of(&[(
                ChangeOperation::Replace,
                "restldap-listen-addr",
                &["0.0.0.0:389"],
            )]),
        )
        .expect("first");

        let second = change(
            &document,
            &as_admin(),
            &change_of(&[(ChangeOperation::Replace, "restldap-backend", &["file"])]),
        )
        .expect("second");

        assert_eq!(second.generation, 3);
        let text = in_store(&document);
        assert!(text.contains("listen_addr: 0.0.0.0:389"), "{text}");
        assert!(text.contains("backend: file"), "{text}");
    }

    #[test]
    fn a_section_inside_a_list_is_addressed_by_its_position() {
        let text =
            "access:\n- subject: admin\n  rights: [read]\n- subject: anonymous\n  rights: []\n";
        let (_dir, document) = store_with(text);

        let mut request = change_of(&[(ChangeOperation::Replace, "restldap-subject", &["users"])]);
        request.object = LdapDn::from("cn=2,cn=access,cn=config");

        let committed = change(&document, &as_admin(), &request).expect("change");
        assert_eq!(committed.keys, vec!["subject"]);

        // Read the way a client reads it, not by matching the serialised text: the serialiser
        // sorts keys, so the order of `subject` and `rights` inside an item is not behaviour.
        let published =
            entries(Some(&Document::new(in_store(&document), "test"))).expect("entries");
        assert_eq!(
            values(
                find(&published, "cn=1,cn=access,cn=config"),
                "restldap-subject"
            ),
            vec!["admin"],
            "the first rule is untouched"
        );
        assert_eq!(
            values(
                find(&published, "cn=2,cn=access,cn=config"),
                "restldap-subject"
            ),
            vec!["users"],
            "the second rule changed"
        );
    }

    #[test]
    fn a_document_key_with_capitals_can_be_changed() {
        // `AllowDangerousSettings` publishes as `restldap-AllowDangerousSettings`, and a client
        // sends the name in whatever case it likes. Comparing the names case-sensitively
        // refused the whole entry - and on a live server it refused a change to an unrelated
        // setting, because the comparison runs over every attribute of the entry.
        let text = "AllowDangerousSettings: \"Yes I know this is bad idea\"\nlisten_addr: 127.0.0.1:1389\n";
        let (_dir, document) = store_with(text);

        let committed = change(
            &document,
            &as_admin(),
            &change_of(&[(
                ChangeOperation::Replace,
                "restldap-listen-addr",
                &["0.0.0.0:389"],
            )]),
        )
        .expect("change");

        assert_eq!(committed.keys, vec!["listen_addr"]);
        assert!(
            in_store(&document).contains("AllowDangerousSettings"),
            "the capitalised key is not a casualty of the change: {}",
            in_store(&document)
        );
    }

    #[test]
    fn a_change_to_the_base_entry_keeps_every_section() {
        // Regression: a section is published as a child entry, not as an attribute of its
        // parent, so a rewrite that looks sections up among the parent's attributes finds
        // nothing and reads that as "the client deleted them". The first version of this code
        // dropped every section from the document on any change to the base entry.
        let text = "\
backend: redb
listen_addr: 127.0.0.1:1389
backends:
  redb:
    path: ./directory.redb
indexes:
  default: [pres]
  attributes:
    cn: [eq]
";
        let (_dir, document) = store_with(text);

        change(
            &document,
            &as_admin(),
            &change_of(&[(ChangeOperation::Replace, "restldap-backend", &["file"])]),
        )
        .expect("change");

        let published =
            entries(Some(&Document::new(in_store(&document), "test"))).expect("entries");
        assert_eq!(
            dns(&published),
            vec![
                "cn=config",
                "cn=backends,cn=config",
                "cn=redb,cn=backends,cn=config",
                "cn=indexes,cn=config",
                "cn=attributes,cn=indexes,cn=config",
            ],
            "the change touched one value, so the tree must be the same tree"
        );
        assert_eq!(
            values(
                find(&published, "cn=redb,cn=backends,cn=config"),
                "restldap-path"
            ),
            vec!["./directory.redb"],
            "and the section's own settings are untouched"
        );
    }

    #[test]
    fn a_path_is_the_dn_read_backwards_without_the_root() {
        assert_eq!(path_of("cn=config"), Some(Vec::new()));
        assert_eq!(
            path_of("cn=file,cn=backends,cn=config"),
            Some(vec!["backends".to_string(), "file".to_string()])
        );
        assert_eq!(
            path_of("cn=1,cn=access,cn=config"),
            Some(vec!["access".to_string(), "1".to_string()])
        );
        assert_eq!(path_of("dc=example,dc=com"), None);
        assert_eq!(path_of("cn=configs"), None);
    }

    #[test]
    fn a_change_on_an_entry_that_is_not_published_is_no_such_object() {
        let (_dir, document) = store_with("listen_addr: 127.0.0.1:1389\n");

        let mut request = change_of(&[(ChangeOperation::Replace, "restldap-subject", &["x"])]);
        request.object = LdapDn::from("cn=nothing,cn=config");

        let refusal = change(&document, &as_admin(), &request).expect_err("must refuse");
        assert_eq!(refusal.code, ResultCode::NoSuchObject);
    }

    #[test]
    fn two_keys_that_would_publish_as_one_attribute_are_refused() {
        // `_` becomes `-` in an attribute name, so these two keys are one attribute, and the
        // entry could not say which setting it holds.
        let err = entries(Some(&document("users_path: a\nusers-path: b\n"))).expect_err("refuse");

        match err {
            Error::Collision {
                first,
                second,
                attribute,
            } => {
                assert_eq!(attribute, "restldap-users-path");
                // Sorted, and `-` sorts before `_`: the report names the pair, not a chosen
                // first.
                assert_eq!(first, "users-path");
                assert_eq!(second, "users_path");
            }
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn scopes_and_parents_follow_the_tree() {
        use crate::directory::Scope;

        assert!(!in_scope("cn=config", "cn=config", Scope::Base));
        assert!(in_scope(
            "cn=backends,cn=config",
            "cn=config",
            Scope::OneLevel
        ));
        assert!(!in_scope(
            "cn=file,cn=backends,cn=config",
            "cn=config",
            Scope::OneLevel
        ));
        assert!(in_scope(
            "cn=file,cn=backends,cn=config",
            "cn=config",
            Scope::Subtree
        ));
        assert!(!in_scope(
            "cn=file,cn=backends,cn=config",
            "cn=backends,cn=config",
            Scope::Base
        ));

        assert_eq!(parent("cn=config"), None);
        assert_eq!(
            parent("cn=file,cn=backends,cn=config").as_deref(),
            Some("cn=backends,cn=config")
        );
    }
}
