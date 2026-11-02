//! The directory model: an entry is a DN plus an ordered list of attributes.
//!
//! gorestldap kept the shape in Go struct tags (`json` for the backend payload,
//! `ldap:"operational"`, `ldap:"skip"`, `ldap:"case_sensitive_value"`) and read
//! attributes back through reflection. Here an entry is data: a DN and a list of
//! attributes, so anything the backend can express can be stored and returned, and
//! attribute selection, filtering and comparison work on one representation.
//!
//! [`User`] and [`Group`] remain as *parsing* shapes for the gorestldap JSON; they
//! are not the directory model any more. Turning them into entries is the job of
//! [`crate::mapping`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use serde::Deserialize;

/// Attribute description returned for every entry when `entryDN` is requested.
pub const ATTR_ENTRY_DN: &str = "entryDN";
/// Attribute description returned for every entry when `+` is requested.
pub const ATTR_HAS_SUBORDINATES: &str = "hasSubordinates";
pub const ATTR_ENTRY_UUID: &str = "entryUUID";
pub const ATTR_OBJECT_CLASS: &str = "objectClass";
/// Server-internal flag: never projected, never filterable.
pub const ATTR_LDAP_ADMIN: &str = "ldapAdmin";

/// How an attribute behaves in projection and matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct AttributeFlags {
    /// Returned only when asked for explicitly or with `+`, never with `*`.
    pub operational: bool,
    /// Compared exactly instead of case-insensitively (passwords).
    pub case_sensitive: bool,
    /// Never returned by `*` or `+`: the client has to name it, and the ACL then
    /// decides whether it may be read.
    pub sensitive: bool,
    /// Server-internal: never projected and never matched by a filter; reachable
    /// only by the server's own code.
    pub internal: bool,
}

/// Attribute descriptions repeat across every entry, so the text is interned and
/// shared: 20 000 entries with eight attributes otherwise cost 160 000 small
/// allocations for a handful of distinct names.
static NAME_CACHE: OnceLock<Mutex<HashMap<String, Arc<str>>>> = OnceLock::new();

/// Returns the shared, interned attribute description for `name`.
pub fn attribute_name(name: &str) -> Arc<str> {
    let cache = NAME_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    // A poisoned lock only means another thread panicked mid-insert; the cache is
    // still usable and the worst case is interning the same name twice.
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(existing) = cache.get(name) {
        return Arc::clone(existing);
    }
    let interned: Arc<str> = Arc::from(name);
    cache.insert(name.to_string(), Arc::clone(&interned));
    interned
}

/// One attribute of an entry: description, values and behaviour.
///
/// `values` is a boxed slice rather than a `Vec`: the list never grows after the
/// entry is built, and a `Vec` of one value carries a spare capacity of four.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: Arc<str>,
    pub values: Box<[String]>,
    pub flags: AttributeFlags,
}

impl Attribute {
    /// Attribute with explicit values.
    pub fn new(name: impl AsRef<str>, values: Vec<String>) -> Self {
        Self {
            name: attribute_name(name.as_ref()),
            values: values.into_boxed_slice(),
            flags: AttributeFlags::default(),
        }
    }

    /// Single-valued attribute with a borrowed value.
    pub fn single(name: impl AsRef<str>, value: &str) -> Self {
        Self::new(name, vec![value.to_string()])
    }

    #[must_use]
    pub fn operational(mut self) -> Self {
        self.flags.operational = true;
        self
    }

    #[must_use]
    pub fn case_sensitive(mut self) -> Self {
        self.flags.case_sensitive = true;
        self
    }

    /// Keeps the attribute out of `*` and `+`; an explicit request still returns
    /// it, so that the ACL can decide.
    #[must_use]
    pub fn sensitive(mut self) -> Self {
        self.flags.sensitive = true;
        self
    }

    /// Server-internal: invisible in every projection and in every filter.
    #[must_use]
    pub fn internal(mut self) -> Self {
        self.flags.internal = true;
        self
    }

    pub fn is_visible(&self) -> bool {
        !self.flags.internal
    }
}

/// Builder that keeps attribute order deterministic.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Attributes {
    inner: Vec<Attribute>,
}

impl Attributes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an attribute; empty value lists are dropped, so an attribute that
    /// the backend left empty is absent from the entry.
    #[must_use]
    pub fn push(mut self, attribute: Attribute) -> Self {
        if !attribute.values.is_empty() {
            self.inner.push(attribute);
        }
        self
    }

    pub fn values(&self) -> &[Attribute] {
        &self.inner
    }

    /// Case-insensitive lookup by attribute description.
    ///
    /// Internal attributes are invisible here: filtering, projection and selection
    /// all go through this method, so none of them can reach a server-only flag.
    pub fn get(&self, name: &str) -> Option<&Attribute> {
        self.inner
            .iter()
            .find(|attribute| attribute.is_visible() && attribute.name.eq_ignore_ascii_case(name))
    }

    /// Puts `attribute` in place of the one with the same description, keeping its
    /// position; appends when the entry does not have it yet.
    ///
    /// Works on the raw list, internal attributes included: this is the server's own
    /// mutation path, not a client-visible view.
    #[must_use]
    pub fn replace(mut self, attribute: Attribute) -> Self {
        if attribute.values.is_empty() {
            return self.without(&attribute.name);
        }

        match self
            .inner
            .iter()
            .position(|existing| existing.name.eq_ignore_ascii_case(&attribute.name))
        {
            Some(position) => self.inner[position] = attribute,
            None => self.inner.push(attribute),
        }
        self
    }

    /// Removes every attribute with this description.
    #[must_use]
    pub fn without(mut self, name: &str) -> Self {
        self.inner
            .retain(|attribute| !attribute.name.eq_ignore_ascii_case(name));
        self
    }

    /// Lookup that also sees internal attributes; for the server's own code.
    pub fn internal(&self, name: &str) -> Option<&Attribute> {
        self.inner
            .iter()
            .find(|attribute| attribute.name.eq_ignore_ascii_case(name))
    }

    /// True when the internal attribute holds a truthy value.
    pub fn internal_flag(&self, name: &str) -> bool {
        self.internal(name).is_some_and(|attribute| {
            attribute
                .values
                .iter()
                .any(|value| value.eq_ignore_ascii_case("true"))
        })
    }

    /// Applies an LDAP attribute selection list (`*`, `+`, `entryDN`, explicit
    /// names) to the entry named `dn`.
    ///
    /// An empty selection means `*`, as in RFC 4511 and in gorestldap.
    pub fn select(&self, dn: &str, selection: &[String]) -> Vec<Attribute> {
        let mut out: Vec<Attribute> = Vec::new();
        let mut seen: Vec<Arc<str>> = Vec::new();

        let entry_dn = || Attribute::single(ATTR_ENTRY_DN, dn).operational();

        if selection.is_empty() {
            self.push_regular(&mut out, &mut seen);
            return out;
        }

        for requested in selection {
            match requested.to_lowercase().as_str() {
                "*" => self.push_regular(&mut out, &mut seen),
                "+" => {
                    push_unique(entry_dn(), &mut out, &mut seen);
                    for attribute in &self.inner {
                        if attribute.flags.operational
                            && !attribute.flags.sensitive
                            && attribute.is_visible()
                        {
                            push_unique(attribute.clone(), &mut out, &mut seen);
                        }
                    }
                }
                _ if requested.eq_ignore_ascii_case(ATTR_ENTRY_DN) => {
                    push_unique(entry_dn(), &mut out, &mut seen);
                }
                _ => {
                    if let Some(attribute) = self.get(requested) {
                        push_unique(attribute.clone(), &mut out, &mut seen);
                    }
                }
            }
        }

        out
    }

    /// Regular (non-operational, non-sensitive, non-internal) attributes.
    fn push_regular(&self, out: &mut Vec<Attribute>, seen: &mut Vec<Arc<str>>) {
        for attribute in &self.inner {
            if !attribute.flags.operational && !attribute.flags.sensitive && attribute.is_visible()
            {
                push_unique(attribute.clone(), out, seen);
            }
        }
    }
}

/// Appends the attribute unless one with the same description is already there.
fn push_unique(attribute: Attribute, out: &mut Vec<Attribute>, seen: &mut Vec<Arc<str>>) {
    if seen
        .iter()
        .any(|name| name.eq_ignore_ascii_case(&attribute.name))
    {
        return;
    }
    seen.push(Arc::clone(&attribute.name));
    out.push(attribute);
}

/// One directory entry: its DN and its attributes.
///
/// The DN is stored normalized (lowercase, no spaces after commas), because every
/// lookup, scope test and comparison works on that form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    dn: String,
    attributes: Attributes,
}

impl Entry {
    pub fn new(dn: impl Into<String>, attributes: Attributes) -> Self {
        Self {
            dn: dn.into(),
            attributes,
        }
    }

    pub fn dn(&self) -> &str {
        &self.dn
    }

    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    pub fn into_attributes(self) -> Attributes {
        self.attributes
    }

    /// True when the entry carries the server-internal admin flag.
    pub fn is_admin(&self) -> bool {
        self.attributes.internal_flag(ATTR_LDAP_ADMIN)
    }

    /// Object classes of the entry, as the schema (and `objectClass=*`) sees them.
    pub fn object_classes(&self) -> &[String] {
        self.attributes
            .get(ATTR_OBJECT_CLASS)
            .map(|attribute| &attribute.values[..])
            .unwrap_or_default()
    }
}

/// User as it arrives from a gorestldap backend (JSON shape, not the model).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct User {
    pub ldap_admin: bool,
    #[serde(rename = "entryUUID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_subordinates: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub object_class: Vec<String>,
    pub cn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_shell: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub member_of: Vec<String>,
}

/// Group as it arrives from a gorestldap backend (JSON shape, not the model).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Group {
    #[serde(rename = "entryUUID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_subordinates: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub object_class: Vec<String>,
    pub cn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub member_uid: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Attributes {
        Attributes::new()
            .push(Attribute::new(
                ATTR_OBJECT_CLASS,
                vec!["top".to_string(), "inetOrgPerson".to_string()],
            ))
            .push(Attribute::single("cn", "admin"))
            .push(Attribute::single("mail", "i.petrov@example.com"))
            .push(
                Attribute::single("userPassword", "{SSHA}abc")
                    .case_sensitive()
                    .sensitive(),
            )
            .push(Attribute::single(ATTR_ENTRY_UUID, "8f0e4b6a").operational())
            .push(Attribute::single(ATTR_HAS_SUBORDINATES, "FALSE").operational())
            .push(Attribute::single(ATTR_LDAP_ADMIN, "true").internal())
    }

    #[test]
    fn parses_user_payload_with_camel_case_keys() {
        let json = r#"{
            "ldapAdmin": true,
            "entryUUID": "8f0e4b6a",
            "objectClass": ["top", "inetOrgPerson"],
            "cn": "admin",
            "uidNumber": 1000,
            "userPassword": "{SSHA}abc",
            "memberOf": ["group_a", "group_b"]
        }"#;

        let user: User = serde_json::from_str(json).expect("user payload");

        assert!(user.ldap_admin);
        assert_eq!(user.entry_uuid.as_deref(), Some("8f0e4b6a"));
        assert_eq!(user.uid_number, Some(1000));
        assert_eq!(user.gid_number, None);
        assert_eq!(
            user.member_of,
            vec!["group_a".to_string(), "group_b".to_string()]
        );
    }

    #[test]
    fn parses_group_payload_with_null_description() {
        let json = r#"{
            "entryUUID": "79303aa9",
            "objectClass": ["top", "posixGroup"],
            "cn": "primary_group",
            "gidNumber": 1999,
            "description": null,
            "memberUid": ["admin"]
        }"#;

        let group: Group = serde_json::from_str(json).expect("group payload");

        assert_eq!(group.description, None);
        assert_eq!(group.gid_number, Some(1999));
        assert_eq!(group.member_uid, vec!["admin".to_string()]);
    }

    #[test]
    fn lookup_never_returns_an_internal_attribute() {
        let attributes = sample();

        assert!(
            attributes.get(ATTR_LDAP_ADMIN).is_none(),
            "internal attributes must be invisible to filters and projection"
        );
        assert!(attributes.internal(ATTR_LDAP_ADMIN).is_some());
    }

    #[test]
    fn internal_flag_reads_a_truthy_value_only() {
        assert!(sample().internal_flag(ATTR_LDAP_ADMIN));

        let false_flag =
            Attributes::new().push(Attribute::single(ATTR_LDAP_ADMIN, "false").internal());
        assert!(!false_flag.internal_flag(ATTR_LDAP_ADMIN));
        assert!(!Attributes::new().internal_flag(ATTR_LDAP_ADMIN));
    }

    #[test]
    fn password_is_case_sensitive_and_sensitive() {
        let attributes = sample();
        let password = attributes.get("userPassword").expect("password");

        assert!(password.flags.case_sensitive);
        assert!(password.flags.sensitive);
    }

    #[test]
    fn wildcard_excludes_operational_sensitive_and_internal() {
        let attributes = sample();
        let selected = attributes.select("cn=admin,ou=users,dc=example,dc=com", &["*".to_string()]);

        let names: Vec<&str> = selected.iter().map(|a| &*a.name).collect();
        assert_eq!(names, vec!["objectClass", "cn", "mail"]);
    }

    #[test]
    fn plus_returns_operational_but_not_sensitive_or_internal() {
        let attributes = sample();
        let selected = attributes.select("cn=admin,ou=users,dc=example,dc=com", &["+".to_string()]);

        let names: Vec<&str> = selected.iter().map(|a| &*a.name).collect();
        assert_eq!(
            names,
            vec![ATTR_ENTRY_DN, ATTR_ENTRY_UUID, ATTR_HAS_SUBORDINATES]
        );
    }

    #[test]
    fn explicit_name_returns_a_sensitive_attribute_for_the_acl_to_judge() {
        let attributes = sample();
        let selected = attributes.select(
            "cn=admin,ou=users,dc=example,dc=com",
            &["userPassword".to_string()],
        );

        assert_eq!(selected.len(), 1);
        assert!(selected[0].flags.sensitive);
    }

    #[test]
    fn explicit_name_cannot_reach_an_internal_attribute() {
        let attributes = sample();

        assert!(
            attributes
                .select(
                    "cn=admin,ou=users,dc=example,dc=com",
                    &[ATTR_LDAP_ADMIN.to_string()]
                )
                .is_empty()
        );
    }

    #[test]
    fn selection_is_case_insensitive_and_keeps_order() {
        let attributes = sample();
        let selected = attributes.select(
            "cn=admin,ou=users,dc=example,dc=com",
            &["MAIL".to_string(), "cn".to_string(), "nosuch".to_string()],
        );

        let names: Vec<&str> = selected.iter().map(|a| &*a.name).collect();
        assert_eq!(names, vec!["mail", "cn"]);
    }

    #[test]
    fn repeated_selection_does_not_duplicate() {
        let attributes = sample();
        let selected = attributes.select(
            "cn=admin,ou=users,dc=example,dc=com",
            &["cn".to_string(), "cn".to_string(), "*".to_string()],
        );

        assert_eq!(selected.iter().filter(|a| &*a.name == "cn").count(), 1);
    }

    #[test]
    fn empty_value_list_drops_the_attribute() {
        let attributes = Attributes::new()
            .push(Attribute::new("mail", vec![]))
            .push(Attribute::single("cn", "x"));

        assert!(attributes.get("mail").is_none());
        assert_eq!(attributes.values().len(), 1);
    }

    #[test]
    fn entry_exposes_dn_classes_and_admin_flag() {
        let entry = Entry::new("cn=admin,ou=users,dc=example,dc=com", sample());

        assert_eq!(entry.dn(), "cn=admin,ou=users,dc=example,dc=com");
        assert_eq!(entry.object_classes(), ["top", "inetOrgPerson"]);
        assert!(entry.is_admin());
        assert!(entry.attributes().get("cn").is_some());
    }

    #[test]
    fn entry_without_classes_returns_an_empty_slice() {
        let entry = Entry::new("dc=example,dc=com", Attributes::new());

        assert!(entry.object_classes().is_empty());
        assert!(!entry.is_admin());
    }
}
