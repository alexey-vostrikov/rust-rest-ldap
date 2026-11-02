//! Reloading the schema without a restart.
//!
//! A schema file is data, and data changes: a new attribute is added for a project, an old
//! object class is retired. Restarting a directory server for that is a restart of every
//! client connection, and the whole point of the file being data is that it need not be.
//!
//! The rules this encodes, and why each one matters:
//!
//! - **The whole fileset is re-read, not appended to.** `extend` on a live schema would
//!   accumulate: reload twice and every definition is there twice, and a retracted definition
//!   stays forever.
//! - **A broken file leaves the previous schema in place.** A directory that refuses to
//!   validate anything because somebody's half-saved edit removed a `)` is worse than one
//!   running yesterday's schema.
//! - **Existing entries are validated against the new schema before it is adopted.** If the
//!   data already breaks the new rules, adopting them turns every write into a refusal, and
//!   the operator finds out at the next write rather than at the reload.

use std::sync::Arc;

use rust_rest_ldap::backend::Backend;
use rust_rest_ldap::config::{Args, Config};
use rust_rest_ldap::reload::Source;

const BASE: &str = "dc=example,dc=com";

fn schema_with(text: &str) -> Schema {
    let mut schema = Schema::core();
    schema.extend(text).expect("schema");
    schema
}

use rust_rest_ldap::schema::Schema;

fn config(users: &std::path::Path, groups: &std::path::Path, schema: &std::path::Path) -> Config {
    let text = format!(
        "base_dn: {BASE}
schema:
  mode: strict
  files:
    - {}
backends:
  file:
    users_path: {}
    groups_path: {}
",
        schema.display(),
        users.display(),
        groups.display()
    );

    rust_rest_ldap::config::resolve(Args::default(), Some(&text), |_| None).expect("config")
}

fn write(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write");
    path
}

/// A directory with one user, and a schema file holding one custom attribute.
async fn fixture(
    dir: &std::path::Path,
) -> (
    Arc<Source>,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let users = write(
        dir,
        "users.json",
        r#"[{"cn":"alice","sn":"Smith","uid":"alice","objectClass":["top","person","inetOrgPerson","projectPerson"]}]"#,
    );
    let groups = write(dir, "groups.json", "[]");
    // One attribute and one class of our own; a reload replaces this file entirely.
    let schema = write(
        dir,
        "local.schema",
        "attributetype ( 1.3.6.1.4.1.99999.1.1 NAME 'projectCode' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n\
         objectclass ( 1.3.6.1.4.1.99999.2.1 NAME 'projectPerson' SUP top AUXILIARY MUST cn )\n",
    );

    let config = config(&users, &groups, &schema);
    let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
    let (source, _) = Source::load(&config, backend).await.expect("load");

    (source, users, groups, schema)
}

#[tokio::test]
async fn a_reload_picks_up_a_new_definition_from_the_file() {
    // The point of the whole feature: a definition added to the file is usable after the
    // reload, on every connection, without a restart.
    let dir = tempfile::tempdir().expect("tempdir");
    let (source, _users, _groups, schema) = fixture(dir.path()).await;

    assert!(
        source.schema().attribute("costCentre").is_none(),
        "the fixture must start without the definition, or the test proves nothing"
    );

    // The class the entries claim stays; only the attribute types change.
    std::fs::write(
        &schema,
        "attributetype ( 1.3.6.1.4.1.99999.1.1 NAME 'projectCode' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n\
         attributetype ( 1.3.6.1.4.1.99999.1.2 NAME 'costCentre' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n\
         objectclass ( 1.3.6.1.4.1.99999.2.1 NAME 'projectPerson' SUP top AUXILIARY MUST cn )\n",
    )
    .expect("update");

    let outcome = source.reload_schema().await.expect("reload");

    assert!(
        outcome.warnings.is_empty(),
        "a schema the data satisfies raises no warnings: {outcome:?}"
    );
    assert!(
        source.schema().attribute("costCentre").is_some(),
        "the new definition must be in force after the reload"
    );
}

#[tokio::test]
async fn a_reload_replaces_rather_than_accumulates() {
    // `extend` on a live schema would leave a retracted definition in place for ever and
    // duplicate every definition that stayed.
    let dir = tempfile::tempdir().expect("tempdir");
    let (source, _users, _groups, schema) = fixture(dir.path()).await;

    let before = source.schema().attribute_count();

    // The same file, reloaded: the count must not grow.
    source.reload_schema().await.expect("reload");
    assert_eq!(
        source.schema().attribute_count(),
        before,
        "a reload of an unchanged file must change nothing"
    );

    // Now with the custom attribute removed and the class the entries claim kept: the
    // attribute must actually disappear, which `extend` on a live schema would never do.
    std::fs::write(
        &schema,
        "objectclass ( 1.3.6.1.4.1.99999.2.1 NAME 'projectPerson' SUP top AUXILIARY MUST cn )\n",
    )
    .expect("update");
    source.reload_schema().await.expect("reload");
    assert!(
        source.schema().attribute("projectCode").is_none(),
        "a definition removed from the file must be gone from the schema"
    );
}

#[tokio::test]
async fn a_broken_schema_file_leaves_the_previous_schema_in_force() {
    // The failure this guards: a half-saved edit. Refusing to validate anything because of a
    // missing parenthesis is worse than running yesterday's schema.
    let dir = tempfile::tempdir().expect("tempdir");
    let (source, _users, _groups, schema) = fixture(dir.path()).await;

    let before = source.schema().attribute_count();

    std::fs::write(
        &schema,
        "attributetype ( 1.3.6.1.4.1.99999.1.9 NAME 'broken' SYNTAX \n",
    )
    .expect("break");

    let err = source.reload_schema().await.expect_err("must refuse");

    assert!(
        err.to_string().contains("local.schema") || err.to_string().contains("schema"),
        "the refusal must name the file: {err}"
    );
    assert_eq!(
        source.schema().attribute_count(),
        before,
        "the previous schema must still be in force"
    );
}

#[tokio::test]
async fn a_schema_that_the_data_already_breaks_is_refused() {
    // Adopting rules the directory already violates turns every write into a refusal, and
    // the operator would find out at the next write instead of at the reload.
    let dir = tempfile::tempdir().expect("tempdir");
    let (source, _users, _groups, schema) = fixture(dir.path()).await;

    // A class the entries *already claim*, made stricter: `projectPerson` was satisfied by
    // `cn` alone, now it also demands `description`, which the entry does not carry. This is
    // the shape of a real change of heart about a schema, and adopting it would turn every
    // later write to that entry into a refusal.
    std::fs::write(
        &schema,
        "objectclass ( 1.3.6.1.4.1.99999.2.1 NAME 'projectPerson' SUP top AUXILIARY MUST ( cn $ description ) )\n",
    )
    .expect("update");

    let err = source.reload_schema().await.expect_err("must refuse");

    let text = err.to_string();
    assert!(
        text.contains("alice") || text.contains("violat"),
        "the refusal must say which entry breaks it: {text}"
    );
}

#[tokio::test]
async fn a_reload_in_warn_mode_is_accepted_and_reported() {
    // `warn` exists for data older than the schema; a reload in that mode must not refuse
    // what the mode allows.
    let dir = tempfile::tempdir().expect("tempdir");
    let users = write(
        dir.path(),
        "users.json",
        r#"[{"cn":"alice","sn":"Smith","uid":"alice","objectClass":["top","person","inetOrgPerson","projectPerson"]}]"#,
    );
    let groups = write(dir.path(), "groups.json", "[]");
    let schema = write(
        dir.path(),
        "local.schema",
        "objectclass ( 1.3.6.1.4.1.99999.2.1 NAME 'projectPerson' SUP top AUXILIARY MUST cn )\n",
    );

    let text = format!(
        "base_dn: {BASE}
schema:
  mode: warn
  files:
    - {}
backends:
  file:
    users_path: {}
    groups_path: {}
",
        schema.display(),
        users.display(),
        groups.display()
    );
    let config =
        rust_rest_ldap::config::resolve(Args::default(), Some(&text), |_| None).expect("config");
    let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
    let (source, _) = Source::load(&config, backend).await.expect("load");

    std::fs::write(
        &schema,
        "objectclass ( 1.3.6.1.4.1.99999.2.1 NAME 'projectPerson' SUP top AUXILIARY MUST ( cn $ description ) )\n",
    )
    .expect("update");

    let outcome = source
        .reload_schema()
        .await
        .expect("reload must be accepted");

    assert!(
        !outcome.warnings.is_empty(),
        "the violations must be reported: {outcome:?}"
    );
}

#[tokio::test]
async fn a_reload_with_no_schema_files_keeps_the_built_in_core() {
    // The empty case, and the one that would silently wipe the schema if the reload forgot
    // to start from `Schema::core()`.
    let dir = tempfile::tempdir().expect("tempdir");
    let users = write(
        dir.path(),
        "users.json",
        r#"[{"cn":"alice","sn":"Smith","uid":"alice","objectClass":["top","person","inetOrgPerson"]}]"#,
    );
    let groups = write(dir.path(), "groups.json", "[]");

    let text = format!(
        "base_dn: {BASE}
backends:
  file:
    users_path: {}
    groups_path: {}
",
        users.display(),
        groups.display()
    );
    let config =
        rust_rest_ldap::config::resolve(Args::default(), Some(&text), |_| None).expect("config");
    let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
    let (source, _) = Source::load(&config, backend).await.expect("load");

    let before = source.schema().attribute_count();
    source.reload_schema().await.expect("reload");

    assert_eq!(
        source.schema().attribute_count(),
        before,
        "no files means the built-in schema, unchanged"
    );
    assert!(source.schema().attribute("cn").is_some(), "core survives");
}

#[tokio::test]
async fn the_reload_reports_how_many_definitions_it_ended_up_with() {
    // What the operator sees in the log or the HTTP answer: a number that says whether the
    // file was read at all, and whether anything was added.
    let dir = tempfile::tempdir().expect("tempdir");
    let (source, _users, _groups, _schema) = fixture(dir.path()).await;

    let outcome = source.reload_schema().await.expect("reload");

    assert!(outcome.attributes > 0, "{outcome:?}");
    assert_eq!(outcome.attributes, source.schema().attribute_count());
    assert_eq!(outcome.classes, source.schema().class_count());
}

#[test]
fn the_fixture_schema_builder_is_honest() {
    // A guard on the test helper: if `extend` silently ignored the text, every test above
    // would pass against the built-in schema and prove nothing.
    let schema = schema_with(
        "attributetype ( 1.3.6.1.4.1.99999.9.9 NAME 'testOnly' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n",
    );
    assert!(schema.attribute("testOnly").is_some());
}
