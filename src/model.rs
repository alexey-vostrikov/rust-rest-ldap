//! Directory model: users, groups, OUs and the domain entry.
//!
//! gorestldap kept the entry shape in Go struct tags (`json` for the backend
//! payload, `ldap:"operational"`, `ldap:"skip"`, `ldap:"case_sensitive_value"`)
//! and read attributes back through reflection. Here the same information is a
//! plain ordered attribute list built by each type, so attribute selection,
//! filtering and comparison work on one representation and no reflection is
//! involved.

use serde::Deserialize;

/// Attribute description returned for every entry when `entryDN` is requested.
pub const ATTR_ENTRY_DN: &str = "entryDN";
/// Attribute description returned for every entry when `+` is requested.
pub const ATTR_HAS_SUBORDINATES: &str = "hasSubordinates";
pub const ATTR_ENTRY_UUID: &str = "entryUUID";
pub const ATTR_OBJECT_CLASS: &str = "objectClass";

/// One attribute of an entry: description, values and matching behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: &'static str,
    pub values: Vec<String>,
    /// Operational attributes are returned only when asked for explicitly or
    /// with `+`, never with `*`.
    pub operational: bool,
    /// Values are compared exactly instead of case-insensitively (passwords).
    pub case_sensitive: bool,
}

impl Attribute {
    fn new(name: &'static str, values: Vec<String>) -> Self {
        Self {
            name,
            values,
            operational: false,
            case_sensitive: false,
        }
    }

    fn single(name: &'static str, value: &str) -> Self {
        Self::new(name, vec![value.to_string()])
    }

    fn operational(mut self) -> Self {
        self.operational = true;
        self
    }

    fn case_sensitive(mut self) -> Self {
        self.case_sensitive = true;
        self
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

    /// Appends an attribute; empty value lists are dropped, so an attribute
    /// that the backend left empty is absent from the entry.
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
    pub fn get(&self, name: &str) -> Option<&Attribute> {
        self.inner
            .iter()
            .find(|attribute| attribute.name.eq_ignore_ascii_case(name))
    }

    /// Applies an LDAP attribute selection list (`*`, `+`, `entryDN`, explicit
    /// names) to the entry named `dn`.
    ///
    /// An empty selection means `*`, as in RFC 4511 and in gorestldap.
    pub fn select(&self, dn: &str, selection: &[String]) -> Vec<Attribute> {
        let mut out: Vec<Attribute> = Vec::new();
        let mut seen: Vec<&'static str> = Vec::new();

        let entry_dn = || Attribute::single(ATTR_ENTRY_DN, dn).operational();

        if selection.is_empty() {
            for attribute in &self.inner {
                if !attribute.operational {
                    push_unique(attribute.clone(), &mut out, &mut seen);
                }
            }
            return out;
        }

        for requested in selection {
            match requested.to_lowercase().as_str() {
                "*" => {
                    for attribute in &self.inner {
                        if !attribute.operational {
                            push_unique(attribute.clone(), &mut out, &mut seen);
                        }
                    }
                }
                "+" => {
                    push_unique(entry_dn(), &mut out, &mut seen);
                    for attribute in &self.inner {
                        if attribute.operational {
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
}

/// Appends the attribute unless one with the same description is already there.
fn push_unique(attribute: Attribute, out: &mut Vec<Attribute>, seen: &mut Vec<&'static str>) {
    if seen
        .iter()
        .any(|name| name.eq_ignore_ascii_case(attribute.name))
    {
        return;
    }
    seen.push(attribute.name);
    out.push(attribute);
}

/// Domain entry: the naming context itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pub dc: String,
    pub entry_uuid: Option<String>,
    pub has_subordinates: Option<String>,
    pub object_class: Vec<String>,
}

impl Domain {
    pub fn new(dc: &str, entry_uuid: Option<String>) -> Self {
        Self {
            dc: dc.to_string(),
            entry_uuid,
            has_subordinates: None,
            object_class: vec!["top".to_string(), "domain".to_string()],
        }
    }

    pub fn attributes(&self) -> Attributes {
        let mut attributes =
            Attributes::new().push(Attribute::new(ATTR_OBJECT_CLASS, self.object_class.clone()));
        if let Some(uuid) = &self.entry_uuid {
            attributes = attributes.push(Attribute::single(ATTR_ENTRY_UUID, uuid).operational());
        }
        if let Some(has_subordinates) = &self.has_subordinates {
            attributes = attributes
                .push(Attribute::single(ATTR_HAS_SUBORDINATES, has_subordinates).operational());
        }
        attributes
    }
}

/// Organizational unit (`ou=users`, `ou=groups`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationalUnit {
    pub ou: String,
    pub entry_uuid: Option<String>,
    pub has_subordinates: Option<String>,
    pub object_class: Vec<String>,
}

impl OrganizationalUnit {
    pub fn new(ou: &str, entry_uuid: Option<String>) -> Self {
        Self {
            ou: ou.to_string(),
            entry_uuid,
            has_subordinates: None,
            object_class: vec!["top".to_string(), "organizationalUnit".to_string()],
        }
    }

    pub fn attributes(&self) -> Attributes {
        let mut attributes =
            Attributes::new().push(Attribute::new(ATTR_OBJECT_CLASS, self.object_class.clone()));
        if let Some(uuid) = &self.entry_uuid {
            attributes = attributes.push(Attribute::single(ATTR_ENTRY_UUID, uuid).operational());
        }
        if let Some(has_subordinates) = &self.has_subordinates {
            attributes = attributes
                .push(Attribute::single(ATTR_HAS_SUBORDINATES, has_subordinates).operational());
        }
        attributes
    }
}

/// User entry loaded from the backend.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct User {
    pub ldap_admin: bool,
    #[serde(rename = "entryUUID")]
    pub entry_uuid: Option<String>,
    pub has_subordinates: Option<String>,
    pub object_class: Vec<String>,
    pub cn: String,
    pub uid_number: Option<u32>,
    pub user_password: Option<String>,
    pub gid_number: Option<u32>,
    pub uid: Option<String>,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub sn: Option<String>,
    pub mail: Option<String>,
    pub home_directory: Option<String>,
    pub login_shell: Option<String>,
    pub member_of: Vec<String>,
}

impl User {
    pub fn attributes(&self) -> Attributes {
        let mut attributes = Attributes::new()
            .push(Attribute::new(ATTR_OBJECT_CLASS, self.object_class.clone()))
            .push(Attribute::single("cn", &self.cn));

        if let Some(uid) = &self.uid {
            attributes = attributes.push(Attribute::single("uid", uid));
        }
        if let Some(password) = &self.user_password {
            attributes =
                attributes.push(Attribute::single("userPassword", password).case_sensitive());
        }
        if let Some(value) = &self.display_name {
            attributes = attributes.push(Attribute::single("displayName", value));
        }
        if let Some(value) = &self.given_name {
            attributes = attributes.push(Attribute::single("givenName", value));
        }
        if let Some(value) = &self.sn {
            attributes = attributes.push(Attribute::single("sn", value));
        }
        if let Some(value) = &self.mail {
            attributes = attributes.push(Attribute::single("mail", value));
        }
        if let Some(value) = &self.home_directory {
            attributes = attributes.push(Attribute::single("homeDirectory", value));
        }
        if let Some(value) = &self.login_shell {
            attributes = attributes.push(Attribute::single("loginShell", value));
        }
        if let Some(value) = self.uid_number {
            attributes = attributes.push(Attribute::single("uidNumber", &value.to_string()));
        }
        if let Some(value) = self.gid_number {
            attributes = attributes.push(Attribute::single("gidNumber", &value.to_string()));
        }
        if !self.member_of.is_empty() {
            attributes = attributes.push(Attribute::new("memberOf", self.member_of.clone()));
        }
        if let Some(uuid) = &self.entry_uuid {
            attributes = attributes.push(Attribute::single(ATTR_ENTRY_UUID, uuid).operational());
        }
        if let Some(has_subordinates) = &self.has_subordinates {
            attributes = attributes
                .push(Attribute::single(ATTR_HAS_SUBORDINATES, has_subordinates).operational());
        }

        attributes
    }
}

/// Group entry loaded from the backend.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Group {
    #[serde(rename = "entryUUID")]
    pub entry_uuid: Option<String>,
    pub has_subordinates: Option<String>,
    pub object_class: Vec<String>,
    pub cn: String,
    pub gid_number: Option<u32>,
    pub description: Option<String>,
    pub member_uid: Vec<String>,
}

impl Group {
    pub fn attributes(&self) -> Attributes {
        let mut attributes = Attributes::new()
            .push(Attribute::new(ATTR_OBJECT_CLASS, self.object_class.clone()))
            .push(Attribute::single("cn", &self.cn));

        if let Some(value) = self.gid_number {
            attributes = attributes.push(Attribute::single("gidNumber", &value.to_string()));
        }
        if let Some(value) = &self.description {
            attributes = attributes.push(Attribute::single("description", value));
        }
        if !self.member_uid.is_empty() {
            attributes = attributes.push(Attribute::new("memberUid", self.member_uid.clone()));
        }
        if let Some(uuid) = &self.entry_uuid {
            attributes = attributes.push(Attribute::single(ATTR_ENTRY_UUID, uuid).operational());
        }
        if let Some(has_subordinates) = &self.has_subordinates {
            attributes = attributes
                .push(Attribute::single(ATTR_HAS_SUBORDINATES, has_subordinates).operational());
        }

        attributes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> User {
        User {
            ldap_admin: true,
            entry_uuid: Some("8f0e4b6a".to_string()),
            has_subordinates: Some("FALSE".to_string()),
            object_class: vec![
                "top".to_string(),
                "posixAccount".to_string(),
                "inetOrgPerson".to_string(),
            ],
            cn: "admin".to_string(),
            uid_number: Some(1000),
            user_password: Some("{SSHA}abc".to_string()),
            gid_number: Some(1999),
            uid: Some("admin".to_string()),
            display_name: Some("Ivan Petrov".to_string()),
            given_name: Some("Ivan".to_string()),
            sn: Some("Petrov".to_string()),
            mail: Some("i.petrov@example.com".to_string()),
            home_directory: Some("/home/admin".to_string()),
            login_shell: Some("/bin/bash".to_string()),
            member_of: vec!["group_a".to_string()],
        }
    }

    #[test]
    fn parses_backend_payload_with_camel_case_keys() {
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
    fn user_attributes_keep_ldap_names_and_skip_admin_flag() {
        let attributes = user().attributes();

        assert_eq!(
            attributes
                .get("cn")
                .map(|attribute| attribute.values.clone()),
            Some(vec!["admin".to_string()])
        );
        assert_eq!(
            attributes
                .get("mail")
                .map(|attribute| attribute.values.clone()),
            Some(vec!["i.petrov@example.com".to_string()])
        );
        assert_eq!(
            attributes
                .get("objectClass")
                .map(|attribute| attribute.values.len()),
            Some(3)
        );
        assert!(
            attributes.get("ldapAdmin").is_none(),
            "ldapAdmin must not leak into the directory"
        );
    }

    #[test]
    fn absent_optional_values_produce_no_attribute() {
        let attributes = User {
            cn: "minimal".to_string(),
            ..User::default()
        }
        .attributes();

        assert!(attributes.get("mail").is_none());
        assert!(attributes.get("uidNumber").is_none());
        assert!(attributes.get("memberOf").is_none());
        assert_eq!(
            attributes.values().len(),
            1,
            "only objectClass and cn remain in an empty entry"
        );
    }

    #[test]
    fn password_is_marked_case_sensitive() {
        let attributes = user().attributes();

        assert!(
            attributes
                .get("userPassword")
                .expect("password attribute")
                .case_sensitive
        );
        assert!(!attributes.get("cn").expect("cn attribute").case_sensitive);
    }

    #[test]
    fn operational_attributes_are_flagged() {
        let attributes = user().attributes();

        assert!(attributes.get(ATTR_ENTRY_UUID).expect("uuid").operational);
        assert!(
            attributes
                .get(ATTR_HAS_SUBORDINATES)
                .expect("subordinates")
                .operational
        );
        assert!(
            !attributes
                .get("objectClass")
                .expect("objectClass")
                .operational
        );
    }

    #[test]
    fn selection_star_returns_regular_attributes_only() {
        let attributes = user().attributes();
        let selected = attributes.select("cn=admin,ou=users,dc=example,dc=com", &["*".to_string()]);

        let names: Vec<&str> = selected.iter().map(|attribute| attribute.name).collect();
        assert!(names.contains(&"cn"));
        assert!(names.contains(&"objectClass"));
        assert!(!names.contains(&ATTR_ENTRY_UUID));
        assert!(!names.contains(&ATTR_ENTRY_DN));
    }

    #[test]
    fn selection_plus_returns_entry_dn_and_operational_attributes() {
        let attributes = user().attributes();
        let selected = attributes.select("cn=admin,ou=users,dc=example,dc=com", &["+".to_string()]);

        let names: Vec<&str> = selected.iter().map(|attribute| attribute.name).collect();
        assert_eq!(
            names,
            vec![ATTR_ENTRY_DN, ATTR_ENTRY_UUID, ATTR_HAS_SUBORDINATES]
        );
        assert_eq!(
            selected[0].values,
            vec!["cn=admin,ou=users,dc=example,dc=com".to_string()]
        );
    }

    #[test]
    fn selection_of_explicit_names_is_case_insensitive_and_keeps_order() {
        let attributes = user().attributes();
        let selected = attributes.select(
            "cn=admin,ou=users,dc=example,dc=com",
            &[
                "MAIL".to_string(),
                "cn".to_string(),
                "nosuchAttribute".to_string(),
            ],
        );

        let names: Vec<&str> = selected.iter().map(|attribute| attribute.name).collect();
        assert_eq!(names, vec!["mail", "cn"]);
    }

    #[test]
    fn empty_selection_means_all_regular_attributes() {
        let attributes = user().attributes();
        let selected = attributes.select("cn=admin,ou=users,dc=example,dc=com", &[]);

        assert_eq!(
            selected.len(),
            attributes.values().len() - 2,
            "operational ones are excluded"
        );
    }

    #[test]
    fn repeated_selection_does_not_duplicate_attributes() {
        let attributes = user().attributes();
        let selected = attributes.select(
            "cn=admin,ou=users,dc=example,dc=com",
            &["cn".to_string(), "cn".to_string(), "*".to_string()],
        );

        let cn_count = selected
            .iter()
            .filter(|attribute| attribute.name == "cn")
            .count();
        assert_eq!(cn_count, 1);
    }

    #[test]
    fn domain_and_ou_expose_object_class_and_skip_naming_attribute() {
        let domain = Domain::new("example", Some("uuid-d".to_string()));
        let domain_attributes = domain.attributes();
        assert_eq!(
            domain_attributes
                .get(ATTR_OBJECT_CLASS)
                .map(|a| a.values.clone()),
            Some(vec!["top".to_string(), "domain".to_string()])
        );
        assert!(domain_attributes.get("dc").is_none());

        let ou = OrganizationalUnit::new("users", Some("uuid-o".to_string()));
        let ou_attributes = ou.attributes();
        assert_eq!(
            ou_attributes
                .get(ATTR_OBJECT_CLASS)
                .map(|a| a.values.clone()),
            Some(vec!["top".to_string(), "organizationalUnit".to_string()])
        );
        assert!(ou_attributes.get("ou").is_none());
    }
}
