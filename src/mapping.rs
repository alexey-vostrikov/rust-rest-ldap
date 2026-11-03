//! Mapping: how backend JSON becomes directory entries.
//!
//! Two adapters, and the distinction matters for extensibility:
//!
//! * [`gorestldap`] understands the fixed `users.json` / `groups.json` shape of the
//!   ported server. It knows which field is the RDN (`cn`) and which flags are
//!   server-internal (`ldapAdmin`).
//! * [`direct`] takes attributes as they are, so a new attribute means new data,
//!   not new code. This is what "extensible without recompiling" means here.
//!
//! Both produce [`Entry`] values, and nothing downstream knows which adapter ran.

use serde::Deserialize;
use thiserror::Error;

use crate::dn;
use crate::model::{
    ATTR_ENTRY_UUID, ATTR_HAS_SUBORDINATES, ATTR_LDAP_ADMIN, ATTR_OBJECT_CLASS, Attribute,
    Attributes, Entry, Group, User,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MappingError {
    #[error("error parsing entry data: {0}")]
    Parse(String),
    #[error("entry has no 'dn'")]
    MissingDn,
    #[error("entry dn '{0}' is empty")]
    EmptyDn(String),
    #[error("entry has no 'cn', so the object it describes has no name")]
    MissingCn,
    #[error("'{attribute}' of '{dn}' is '{value}', which is not a number")]
    NotANumber {
        dn: String,
        attribute: String,
        value: String,
    },
    #[error("'{dn}' carries '{attribute}' more than once, and the object model has one of it")]
    Repeated { dn: String, attribute: String },
}

/// gorestldap JSON: users and groups with a fixed field list.
pub mod gorestldap {
    use super::*;

    /// Entry for one backend user, with its DN built from `cn`.
    pub fn user_entry(user: &User, base_dn: &str, users_ou_name: &str) -> Entry {
        let mut attributes = Attributes::new()
            .push(Attribute::new(ATTR_OBJECT_CLASS, user.object_class.clone()))
            .push(Attribute::single("cn", &user.cn));

        if let Some(uid) = &user.uid {
            attributes = attributes.push(Attribute::single("uid", uid));
        }
        if let Some(password) = &user.user_password {
            attributes = attributes.push(
                Attribute::single("userPassword", password)
                    .case_sensitive()
                    .sensitive(),
            );
        }
        for (name, value) in [
            ("displayName", &user.display_name),
            ("givenName", &user.given_name),
            ("sn", &user.sn),
            ("mail", &user.mail),
            ("homeDirectory", &user.home_directory),
            ("loginShell", &user.login_shell),
        ] {
            if let Some(value) = value {
                attributes = attributes.push(Attribute::single(name, value));
            }
        }
        if let Some(value) = user.uid_number {
            attributes = attributes.push(Attribute::single("uidNumber", &value.to_string()));
        }
        if let Some(value) = user.gid_number {
            attributes = attributes.push(Attribute::single("gidNumber", &value.to_string()));
        }
        if !user.member_of.is_empty() {
            attributes = attributes.push(Attribute::new("memberOf", user.member_of.clone()));
        }

        attributes = operational(
            attributes,
            user.entry_uuid.as_deref(),
            user.has_subordinates.as_deref(),
        );

        if user.ldap_admin {
            attributes = attributes.push(Attribute::single(ATTR_LDAP_ADMIN, "true").internal());
        }

        Entry::new(
            dn::normalize(&format!(
                "cn={},ou={},{}",
                user.cn.to_lowercase(),
                users_ou_name,
                base_dn
            )),
            attributes,
        )
    }

    /// Entry for one backend group.
    pub fn group_entry(group: &Group, base_dn: &str, groups_ou_name: &str) -> Entry {
        let mut attributes = Attributes::new()
            .push(Attribute::new(
                ATTR_OBJECT_CLASS,
                group.object_class.clone(),
            ))
            .push(Attribute::single("cn", &group.cn));

        if let Some(value) = group.gid_number {
            attributes = attributes.push(Attribute::single("gidNumber", &value.to_string()));
        }
        if let Some(value) = &group.description {
            attributes = attributes.push(Attribute::single("description", value));
        }
        if !group.member_uid.is_empty() {
            attributes = attributes.push(Attribute::new("memberUid", group.member_uid.clone()));
        }

        attributes = operational(
            attributes,
            group.entry_uuid.as_deref(),
            group.has_subordinates.as_deref(),
        );

        Entry::new(
            dn::normalize(&format!(
                "cn={},ou={},{}",
                group.cn.to_lowercase(),
                groups_ou_name,
                base_dn
            )),
            attributes,
        )
    }

    fn operational(
        attributes: Attributes,
        entry_uuid: Option<&str>,
        has_subordinates: Option<&str>,
    ) -> Attributes {
        let mut attributes = attributes;
        if let Some(uuid) = entry_uuid {
            attributes = attributes.push(Attribute::single(ATTR_ENTRY_UUID, uuid).operational());
        }
        if let Some(has_subordinates) = has_subordinates {
            attributes = attributes
                .push(Attribute::single(ATTR_HAS_SUBORDINATES, has_subordinates).operational());
        }
        attributes
    }
}

/// The user an entry describes.
///
/// The reverse of [`user_entry`], and it exists because the backend needs it: the REST
/// service stores users and groups as objects with fixed fields, while this server's
/// directory holds arbitrary entries. A change arrives as a whole entry, so writing it back
/// means reading the object out of it.
///
/// Fields the object model does not have are dropped, and that is the honest behaviour for
/// a backend whose model is smaller than the directory's: silently keeping them in the
/// service is impossible, and refusing every write that carries one would make the backend
/// unusable for the directory it describes.
pub fn user_from_entry(entry: &Entry) -> Result<User, MappingError> {
    let cn = single(entry, "cn")?.ok_or(MappingError::MissingCn)?;

    Ok(User {
        ldap_admin: entry
            .attributes()
            .internal(ATTR_LDAP_ADMIN)
            .is_some_and(|attribute| attribute.values.iter().any(|value| value == "true")),
        entry_uuid: single(entry, ATTR_ENTRY_UUID)?,
        has_subordinates: single(entry, ATTR_HAS_SUBORDINATES)?,
        object_class: many(entry, ATTR_OBJECT_CLASS),
        cn,
        uid_number: number(entry, "uidNumber")?,
        user_password: single(entry, "userPassword")?,
        gid_number: number(entry, "gidNumber")?,
        uid: single(entry, "uid")?,
        display_name: single(entry, "displayName")?,
        given_name: single(entry, "givenName")?,
        sn: single(entry, "sn")?,
        mail: single(entry, "mail")?,
        home_directory: single(entry, "homeDirectory")?,
        login_shell: single(entry, "loginShell")?,
        member_of: many(entry, "memberOf"),
    })
}

/// The group an entry describes; the reverse of [`group_entry`].
pub fn group_from_entry(entry: &Entry) -> Result<Group, MappingError> {
    let cn = single(entry, "cn")?.ok_or(MappingError::MissingCn)?;

    Ok(Group {
        entry_uuid: single(entry, ATTR_ENTRY_UUID)?,
        has_subordinates: single(entry, ATTR_HAS_SUBORDINATES)?,
        object_class: many(entry, ATTR_OBJECT_CLASS),
        cn,
        gid_number: number(entry, "gidNumber")?,
        description: single(entry, "description")?,
        member_uid: many(entry, "memberUid"),
    })
}

/// True when this entry describes a group rather than a user.
///
/// By object class, because that is what the directory itself uses to tell them apart: the
/// backend is not told which branch it is reading, and a DN test would need the OU names
/// that belong to the server, not to the backend.
pub fn is_group(entry: &Entry) -> bool {
    const GROUP_CLASSES: [&str; 4] = [
        "posixgroup",
        "groupofnames",
        "groupofuniquenames",
        "groupofentries",
    ];

    many(entry, ATTR_OBJECT_CLASS)
        .iter()
        .any(|class| GROUP_CLASSES.contains(&class.to_lowercase().as_str()))
}

/// One value of an attribute, or `None` when the entry does not carry it.
fn single(entry: &Entry, name: &str) -> Result<Option<String>, MappingError> {
    let Some(attribute) = entry.attributes().get(name) else {
        return Ok(None);
    };

    match attribute.values.as_ref() {
        [] => Ok(None),
        [one] => Ok(Some(one.clone())),
        // A single-valued field of the object model cannot hold two: taking the first would
        // write one of them away without saying so.
        _ => Err(MappingError::Repeated {
            dn: entry.dn().to_string(),
            attribute: name.to_string(),
        }),
    }
}

/// Every value of an attribute, in the order the entry holds them.
fn many(entry: &Entry, name: &str) -> Vec<String> {
    entry
        .attributes()
        .get(name)
        .map(|attribute| attribute.values.to_vec())
        .unwrap_or_default()
}

/// A numeric attribute, refused with the text that was not a number.
fn number(entry: &Entry, name: &str) -> Result<Option<u32>, MappingError> {
    match single(entry, name)? {
        None => Ok(None),
        Some(text) => text
            .parse::<u32>()
            .map(Some)
            .map_err(|_| MappingError::NotANumber {
                dn: entry.dn().to_string(),
                attribute: name.to_string(),
                value: text,
            }),
    }
}

/// Direct JSON: `{"dn": "...", "attributes": {"cn": ["a"], "mail": "b"}}`.
///
/// Every attribute comes from the data, so a schema addition does not need a code
/// change. Attribute names are not validated here — that is the schema's job (E2);
/// this adapter only rejects data it cannot read.
pub mod direct {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct RawEntry {
        dn: String,
        #[serde(default)]
        attributes: serde_json::Map<String, serde_json::Value>,
    }

    /// Parses a whole document of entries.
    pub fn entries(text: &str) -> Result<Vec<Entry>, MappingError> {
        let raw: Vec<RawEntry> =
            serde_json::from_str(text).map_err(|err| MappingError::Parse(err.to_string()))?;

        raw.into_iter().map(entry).collect()
    }

    fn entry(raw: RawEntry) -> Result<Entry, MappingError> {
        if raw.dn.trim().is_empty() {
            return Err(MappingError::EmptyDn(raw.dn));
        }

        // Deterministic order: the attribute list follows the names, not the order
        // the JSON happened to be written in.
        let mut pairs: Vec<(String, serde_json::Value)> = raw.attributes.into_iter().collect();
        pairs.sort_by(|left, right| {
            left.0
                .to_ascii_lowercase()
                .cmp(&right.0.to_ascii_lowercase())
        });

        let mut attributes = Attributes::new();
        for (name, value) in pairs {
            let values = values_of(&value).ok_or_else(|| {
                MappingError::Parse(format!(
                    "attribute '{name}' has a value that is not a string"
                ))
            })?;
            if values.is_empty() {
                continue;
            }
            attributes = attributes.push(attribute_for(&name, values));
        }

        Ok(Entry::new(dn::normalize(&raw.dn), attributes))
    }

    /// A JSON value as the list of attribute values it denotes.
    ///
    /// Numbers and booleans are stringified, arrays are flattened: that is how an
    /// LDAP attribute is written in JSON by people who are not thinking about LDAP.
    fn values_of(value: &serde_json::Value) -> Option<Vec<String>> {
        match value {
            serde_json::Value::String(text) => Some(vec![text.clone()]),
            serde_json::Value::Number(number) => Some(vec![number.to_string()]),
            serde_json::Value::Bool(flag) => Some(vec![flag.to_string()]),
            serde_json::Value::Null => Some(Vec::new()),
            serde_json::Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.extend(values_of(item)?);
                }
                Some(out)
            }
            serde_json::Value::Object(_) => None,
        }
    }

    /// Behaviour that follows from the attribute itself rather than the schema.
    fn attribute_for(name: &str, values: Vec<String>) -> Attribute {
        let attribute = Attribute::new(name, values);

        match name.to_ascii_lowercase().as_str() {
            "userpassword" => attribute.case_sensitive().sensitive(),
            // The admin flag is the server's own, whoever supplied the data: it is
            // never projected and never filterable.
            "ldapadmin" => attribute.internal(),
            "entryuuid" | "hassubordinates" | "createtimestamp" | "modifytimestamp"
            | "creatorsname" | "modifiersname" | "entrycsn" => attribute.operational(),
            _ => attribute,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "dc=example,dc=com";

    fn admin() -> User {
        User {
            ldap_admin: true,
            entry_uuid: Some("8f0e4b6a".to_string()),
            has_subordinates: Some("FALSE".to_string()),
            object_class: vec![
                "top".to_string(),
                "posixAccount".to_string(),
                "inetOrgPerson".to_string(),
            ],
            cn: "Admin".to_string(),
            uid_number: Some(1000),
            user_password: Some("{SSHA}abc".to_string()),
            gid_number: Some(1999),
            uid: Some("admin".to_string()),
            mail: Some("i.petrov@example.com".to_string()),
            member_of: vec!["group_a".to_string()],
            ..User::default()
        }
    }

    #[test]
    fn user_entry_dn_is_built_from_cn_and_lowercased() {
        let entry = gorestldap::user_entry(&admin(), BASE, "users");

        assert_eq!(entry.dn(), "cn=admin,ou=users,dc=example,dc=com");
    }

    #[test]
    fn user_entry_keeps_ldap_names_and_hides_the_admin_flag() {
        let entry = gorestldap::user_entry(&admin(), BASE, "users");
        let attributes = entry.attributes();

        assert_eq!(
            attributes.get("cn").map(|a| a.values.to_vec()),
            Some(vec!["Admin".to_string()])
        );
        assert_eq!(
            attributes.get("mail").map(|a| a.values.to_vec()),
            Some(vec!["i.petrov@example.com".to_string()])
        );
        assert!(
            attributes.get("ldapAdmin").is_none(),
            "the admin flag must not be projected"
        );
        assert!(entry.is_admin());
    }

    #[test]
    fn user_entry_marks_the_password_case_sensitive_and_sensitive() {
        let entry = gorestldap::user_entry(&admin(), BASE, "users");
        let password = entry.attributes().get("userPassword").expect("password");

        assert!(password.flags.case_sensitive);
        assert!(password.flags.sensitive);
    }

    #[test]
    fn absent_optional_fields_produce_no_attribute() {
        let minimal = User {
            object_class: vec!["top".to_string()],
            cn: "minimal".to_string(),
            ..User::default()
        };

        let entry = gorestldap::user_entry(&minimal, BASE, "users");

        assert!(entry.attributes().get("mail").is_none());
        assert!(entry.attributes().get("uidNumber").is_none());
        assert!(!entry.is_admin());
        assert_eq!(entry.attributes().values().len(), 2, "objectClass and cn");
    }

    #[test]
    fn operational_fields_are_flagged_operational() {
        let entry = gorestldap::user_entry(&admin(), BASE, "users");
        let attributes = entry.attributes();

        assert!(
            attributes
                .get(ATTR_ENTRY_UUID)
                .expect("uuid")
                .flags
                .operational
        );
        assert!(
            attributes
                .get(ATTR_HAS_SUBORDINATES)
                .expect("subordinates")
                .flags
                .operational
        );
    }

    #[test]
    fn group_entry_dn_and_membership() {
        let group = Group {
            object_class: vec!["top".to_string(), "posixGroup".to_string()],
            cn: "group_a".to_string(),
            gid_number: Some(2000),
            member_uid: vec!["admin".to_string()],
            ..Group::default()
        };

        let entry = gorestldap::group_entry(&group, BASE, "groups");

        assert_eq!(entry.dn(), "cn=group_a,ou=groups,dc=example,dc=com");
        assert_eq!(
            entry
                .attributes()
                .get("memberUid")
                .map(|a| a.values.to_vec()),
            Some(vec!["admin".to_string()])
        );
    }

    #[test]
    fn direct_adapter_keeps_arbitrary_attributes() {
        let text = r#"[
            {
                "dn": "cn=Jane Doe,ou=people,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["top", "inetOrgPerson"],
                    "cn": "Jane Doe",
                    "telephoneNumber": "+7 495 000-00-00",
                    "employeeNumber": 42,
                    "active": true,
                    "room": []
                }
            }
        ]"#;

        let entries = direct::entries(text).expect("parse");
        let entry = entries.first().expect("one entry");
        let attributes = entry.attributes();

        assert_eq!(entry.dn(), "cn=jane doe,ou=people,dc=example,dc=com");
        assert_eq!(
            attributes.get("telephoneNumber").map(|a| a.values.to_vec()),
            Some(vec!["+7 495 000-00-00".to_string()]),
            "an attribute the ported server never knew about must survive"
        );
        assert_eq!(
            attributes.get("employeeNumber").map(|a| a.values.to_vec()),
            Some(vec!["42".to_string()])
        );
        assert_eq!(
            attributes.get("active").map(|a| a.values.to_vec()),
            Some(vec!["true".to_string()])
        );
        assert!(attributes.get("room").is_none(), "empty list is dropped");
    }

    #[test]
    fn direct_adapter_flattens_arrays_and_marks_known_flags() {
        let text = r#"[
            {
                "dn": "cn=group,ou=groups,dc=example,dc=com",
                "attributes": {
                    "cn": "group",
                    "memberUid": ["a", "b"],
                    "userPassword": "{SSHA}abc",
                    "entryUUID": "uuid-1"
                }
            }
        ]"#;

        let entry = direct::entries(text).expect("parse").remove(0);
        let attributes = entry.attributes();

        assert_eq!(attributes.get("memberUid").map(|a| a.values.len()), Some(2));
        assert!(
            attributes
                .get("userPassword")
                .expect("password")
                .flags
                .sensitive
        );
        assert!(attributes.get("entryUUID").expect("uuid").flags.operational);
    }

    #[test]
    fn direct_adapter_rejects_an_empty_dn() {
        let text = r#"[{"dn": "  ", "attributes": {"cn": "x"}}]"#;

        assert_eq!(
            direct::entries(text),
            Err(MappingError::EmptyDn("  ".to_string()))
        );
    }

    #[test]
    fn direct_adapter_rejects_nested_objects() {
        let text = r#"[{"dn": "cn=x,dc=example,dc=com", "attributes": {"cn": {"a": 1}}}]"#;

        let err = direct::entries(text).expect_err("must fail");

        assert!(
            err.to_string()
                .contains("attribute 'cn' has a value that is not a string"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn direct_adapter_reports_broken_json() {
        let err = direct::entries("{ not json").expect_err("must fail");

        assert!(matches!(err, MappingError::Parse(_)), "unexpected: {err:?}");
    }
}
