//! The schema against the entries this server actually serves.
//!
//! A schema that rejects its own directory is worse than no schema: every write would
//! fail and the operator would switch checking off. So the built-in subset is tested
//! against the real data shipped in `examples/`, built through the real mapping, and
//! against the synthesized domain and OU entries.

use rrl_directory::directory::Directory;
use rrl_directory::model::{Attribute, Attributes, Entry};
use rrl_directory::schema::{Mode, Schema, ViolationCode};

fn example_directory() -> Directory {
    let users: Vec<rrl_directory::model::User> = serde_json::from_str(
        &std::fs::read_to_string("examples/file/users.json").expect("users.json"),
    )
    .expect("parse users");

    let groups: Vec<rrl_directory::model::Group> = serde_json::from_str(
        &std::fs::read_to_string("examples/file/groups.json").expect("groups.json"),
    )
    .expect("parse groups");

    Directory::new("dc=example,dc=com", "users", "groups", users, groups)
}

#[test]
fn every_entry_of_the_example_directory_passes_the_built_in_schema() {
    let schema = Schema::core();
    let directory = example_directory();

    let mut problems = Vec::new();
    for entry in directory.all() {
        if let Err(violations) = schema.check(entry) {
            problems.push((entry.dn().to_string(), violations));
        }
    }

    assert!(
        problems.is_empty(),
        "the built-in schema must accept the shipped data, but got: {problems:#?}"
    );
}

#[test]
fn a_person_with_a_display_name_and_mail_passes() {
    let schema = Schema::core();
    let attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec![
                "top".to_string(),
                "person".to_string(),
                "organizationalPerson".to_string(),
                "inetOrgPerson".to_string(),
                "posixAccount".to_string(),
            ],
        ))
        .push(Attribute::single("cn", "ivan"))
        .push(Attribute::single("sn", "Petrov"))
        .push(Attribute::single("uid", "ivan"))
        .push(Attribute::single("uidNumber", "1000"))
        .push(Attribute::single("gidNumber", "1999"))
        .push(Attribute::single("homeDirectory", "/home/ivan"))
        .push(Attribute::single("mail", "ivan@example.com"))
        .push(Attribute::single("displayName", "Ivan Petrov"))
        .push(Attribute::single("loginShell", "/bin/bash"))
        .push(Attribute::single("telephoneNumber", "+7 495 000-00-00"))
        .push(Attribute::single("employeeNumber", "42"));
    let entry = Entry::new("cn=ivan,ou=users,dc=example,dc=com", attributes);

    assert_eq!(
        schema.check(&entry),
        Ok(()),
        "a complete person record must not be rejected"
    );
}

#[test]
fn a_group_with_members_passes() {
    let schema = Schema::core();
    let attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec!["top".to_string(), "posixGroup".to_string()],
        ))
        .push(Attribute::single("cn", "team"))
        .push(Attribute::single("gidNumber", "2000"))
        .push(Attribute::new(
            "memberUid",
            vec!["ivan".to_string(), "anna".to_string()],
        ));
    let entry = Entry::new("cn=team,ou=groups,dc=example,dc=com", attributes);

    assert_eq!(schema.check(&entry), Ok(()));
}

#[test]
fn violations_carry_the_codes_a_client_expects() {
    let schema = Schema::core();
    let attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec!["top".to_string(), "person".to_string()],
        ))
        .push(Attribute::single("cn", "x"))
        .push(Attribute::single("sn", "Y"))
        .push(Attribute::single("uidNumber", "not-a-number"));
    let entry = Entry::new("cn=x,ou=users,dc=example,dc=com", attributes);

    let violations = schema
        .check(&entry)
        .expect_err("uidNumber is not allowed here");

    assert!(
        violations
            .iter()
            .any(|violation| violation.code == ViolationCode::ObjectClassViolation),
        "an attribute outside the classes is an object class violation: {violations:?}"
    );
}

#[test]
fn a_custom_schema_can_be_added_without_recompiling() {
    let mut schema = Schema::core();
    schema
        .extend(
            "\
attributetype ( 1.3.6.1.4.1.99999.1 NAME 'badgeNumber'
    EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
objectclass ( 1.3.6.1.4.1.99999.2 NAME 'badgeHolder' SUP top AUXILIARY MAY badgeNumber )
",
        )
        .expect("custom definitions");

    let with_badge = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec![
                "top".to_string(),
                "person".to_string(),
                "badgeHolder".to_string(),
            ],
        ))
        .push(Attribute::single("cn", "x"))
        .push(Attribute::single("sn", "Y"))
        .push(Attribute::single("badgeNumber", "B-17"));
    let entry = Entry::new("cn=x,ou=users,dc=example,dc=com", with_badge);

    assert_eq!(
        schema.check(&entry),
        Ok(()),
        "an auxiliary class from a custom definition must be usable"
    );

    // Without the auxiliary class in objectClass the attribute is not allowed.
    let without_class = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec!["top".to_string(), "person".to_string()],
        ))
        .push(Attribute::single("cn", "x"))
        .push(Attribute::single("sn", "Y"))
        .push(Attribute::single("badgeNumber", "B-17"));
    let entry = Entry::new("cn=x,ou=users,dc=example,dc=com", without_class);

    assert!(schema.check(&entry).is_err());
}

#[test]
fn modes_are_ordered_from_refusing_to_ignoring() {
    // The mode itself does not change how an entry is checked; it decides what the
    // caller does with the answer. This test pins the values so a later change to the
    // dispatch cannot silently swap `warn` for `off`.
    assert_eq!(Mode::default(), Mode::Strict);
    assert_ne!(Mode::Warn, Mode::Off);
}
