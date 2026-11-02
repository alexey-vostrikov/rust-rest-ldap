//! Bootstrap: the first administrator.
//!
//! An empty directory cannot be filled over the protocol. `add` needs a bind, a bind needs
//! an entry with a password, and the entry would have to be added first. Every real
//! deployment solves this outside the protocol - `slapadd`, an installer, a seed file - and
//! so does this one: the administrator named in the configuration is created at startup if,
//! and only if, the store holds nothing at all.
//!
//! What must never happen: a bootstrap that quietly overwrites a directory that already has
//! data, or one that resurrects an administrator somebody removed on purpose.

use std::path::Path;

use rust_rest_ldap::backend::Backend;
use rust_rest_ldap::bootstrap::{self, Error, Outcome, Spec};
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::password::verify::verify;
use rust_rest_ldap::password::{PasswordPolicy, policy::PasswordConfig};

const BASE: &str = "dc=example,dc=com";
const USERS_OU: &str = "users";
const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
const SECRET: &str = "correct horse battery staple";

fn redb(dir: &Path) -> Backend {
    Backend::from_config(
        "redb",
        Some(&serde_json::json!({
            "path": dir.join("dir.redb").to_string_lossy(),
            "durability": "immediate"
        })),
    )
    .expect("backend")
}

fn spec() -> Spec {
    Spec::new(None, BASE, USERS_OU, SECRET).expect("spec")
}

fn policy() -> PasswordPolicy {
    PasswordPolicy::from_config(None).expect("policy")
}

async fn directory(backend: &Backend) -> Directory {
    let data = backend.load().await.expect("load");
    data.into_directory(BASE, USERS_OU, "groups")
}

#[tokio::test]
async fn a_seeded_admin_binds_with_the_password_it_was_given() {
    // The whole point: after this call the directory can be administered over the
    // protocol, because somebody can bind as an administrator.
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = redb(dir.path());

    let outcome = bootstrap::seed(&backend, &spec()).await.expect("seed");
    assert_eq!(
        outcome,
        Outcome::Created {
            dn: ADMIN_DN.to_string()
        }
    );

    let directory = directory(&backend).await;
    let entry = directory.find(ADMIN_DN).expect("the admin must be there");
    assert!(entry.is_admin(), "the entry must carry the admin flag");

    let stored = entry
        .attributes()
        .internal("userPassword")
        .and_then(|attribute| attribute.values.first())
        .expect("a password must be stored");

    assert!(
        verify(SECRET, stored, &policy()).expect("verifiable"),
        "the password that was configured must be the one that works"
    );
    assert!(
        !verify("something else", stored, &policy()).expect("verifiable"),
        "and no other password may work"
    );
}

#[tokio::test]
async fn the_default_dn_is_the_admin_of_the_users_unit() {
    // The default has to be somewhere a bind can find it: inside the base DN, in the
    // users unit, under a name the naming attribute of person accepts.
    assert_eq!(spec().dn(), ADMIN_DN);
}

#[tokio::test]
async fn seeding_a_directory_that_holds_entries_does_nothing() {
    // The dangerous case: bootstrap left in the configuration of a directory that has
    // been in use for a year. It must be inert, and it must say so rather than pretend.
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = redb(dir.path());

    bootstrap::seed(&backend, &spec()).await.expect("first");
    let again = bootstrap::seed(&backend, &spec()).await.expect("second");

    assert_eq!(again, Outcome::NotEmpty { entries: 1 });

    let data = backend.load().await.expect("load");
    assert_eq!(
        data.entries.len(),
        1,
        "a second seed must not add a second entry"
    );
}

#[tokio::test]
async fn an_empty_password_is_refused_before_anything_is_written() {
    // A configured-but-empty password is the shape a broken secret mount takes. Creating
    // an administrator with it would open the directory to anybody.
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = redb(dir.path());

    let err = Spec::new(None, BASE, USERS_OU, "").expect_err("must refuse");
    assert!(matches!(err, Error::EmptyPassword), "{err}");

    let data = backend.load().await.expect("load");
    assert!(data.entries.is_empty(), "nothing may have been written");
}

#[tokio::test]
async fn a_password_of_only_whitespace_is_refused_too() {
    let err = Spec::new(None, BASE, USERS_OU, "   \n").expect_err("must refuse");
    assert!(matches!(err, Error::EmptyPassword), "{err}");
}

#[tokio::test]
async fn a_dn_outside_the_base_is_refused() {
    // A bind only searches inside the base DN, so an administrator outside it would be
    // created and then never found. That is worse than refusing: it looks like success.
    let err = Spec::new(
        Some("cn=admin,ou=users,dc=elsewhere,dc=com"),
        BASE,
        USERS_OU,
        SECRET,
    )
    .expect_err("must refuse");

    assert!(
        matches!(err, Error::OutsideBase { .. }),
        "expected OutsideBase, got {err}"
    );
}

#[tokio::test]
async fn the_password_is_not_stored_in_the_clear() {
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = redb(dir.path());
    bootstrap::seed(&backend, &spec()).await.expect("seed");

    let directory = directory(&backend).await;
    let stored = directory
        .find(ADMIN_DN)
        .expect("admin")
        .attributes()
        .internal("userPassword")
        .and_then(|attribute| attribute.values.first())
        .expect("password")
        .to_string();

    assert!(
        !stored.contains(SECRET),
        "the configured password must not appear in the store: {stored}"
    );
    // Argon2id is stored in the PHC string format ($argon2id$v=19$...), not with a
    // {SCHEME} prefix like the SHA family: the prefix form cannot carry the parameters
    // the hash was made with.
    assert!(
        stored.starts_with("$argon2id$"),
        "the default scheme must be used, got {stored}"
    );
}

#[tokio::test]
async fn the_naming_attribute_of_the_dn_is_present() {
    // `cn=admin` needs `cn: admin` in the entry, `uid=admin` needs `uid: admin`. Derived
    // from the DN rather than assumed to be cn, because the default is cn but the
    // configured DN need not be.
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = redb(dir.path());

    let spec = Spec::new(
        Some("uid=root,ou=users,dc=example,dc=com"),
        BASE,
        USERS_OU,
        SECRET,
    )
    .expect("spec");
    bootstrap::seed(&backend, &spec).await.expect("seed");

    let directory = directory(&backend).await;
    let entry = directory
        .find("uid=root,ou=users,dc=example,dc=com")
        .expect("root");

    assert_eq!(
        entry
            .attributes()
            .get("uid")
            .and_then(|attribute| attribute.values.first())
            .map(String::as_str),
        Some("root")
    );
}

#[tokio::test]
async fn a_backend_that_cannot_keep_the_write_is_refused() {
    // The JSON backends read a file that the server does not own; seeding one would
    // either be lost at the next reload or fail halfway. Refusing at startup says so
    // once, instead of leaving an administrator that disappears after a restart.
    let dir = tempfile::tempdir().expect("tempdir");
    let users = dir.path().join("users.json");
    let groups = dir.path().join("groups.json");
    std::fs::write(&users, "[]").expect("write");
    std::fs::write(&groups, "[]").expect("write");

    let backend = Backend::from_config(
        "file",
        Some(&serde_json::json!({
            "users_path": users.to_string_lossy(),
            "groups_path": groups.to_string_lossy()
        })),
    )
    .expect("backend");

    let err = bootstrap::seed(&backend, &spec())
        .await
        .expect_err("must refuse");
    assert!(
        matches!(err, Error::ReadOnlyBackend { .. }),
        "expected ReadOnlyBackend, got {err}"
    );
}

#[tokio::test]
async fn a_custom_password_scheme_is_honoured() {
    // Whoever sets up a directory should not have to re-hash the bootstrap password by
    // hand to get the scheme the policy asks for.
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = redb(dir.path());

    let policy = PasswordPolicy::from_config(Some(&PasswordConfig {
        store_scheme: Some("pbkdf2-sha512".to_string()),
        ..PasswordConfig::default()
    }))
    .expect("policy");

    bootstrap::seed_with(&backend, &spec(), &policy)
        .await
        .expect("seed");

    let directory = directory(&backend).await;
    let stored = directory
        .find(ADMIN_DN)
        .expect("admin")
        .attributes()
        .internal("userPassword")
        .and_then(|attribute| attribute.values.first())
        .expect("password")
        .to_string();

    assert!(
        stored.to_ascii_uppercase().starts_with("{PBKDF2"),
        "the configured scheme must be used, got {stored}"
    );
}
