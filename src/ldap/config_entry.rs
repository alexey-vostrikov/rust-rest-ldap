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

use rasn_ldap::{LdapMessage, MessageId, ResultCode, SearchRequest};
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
