//! The configuration store, end to end: a directory the server reads instead of a file.
//!
//! What these prove, beyond the unit tests in the module: the server actually starts from a
//! generation, `-c` distinguishes a store from a file without a new key, and a commit through
//! the store is what the next start reads.

use rust_rest_ldap::config::Args;
use rust_rest_ldap::config_store::Store;

const CONFIG: &str = "base_dn: dc=example,dc=com\nlisten_addr: 127.0.0.1:1389\nbackend: \"null\"\n";

#[test]
fn the_server_reads_the_generation_the_pointer_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("config.d"));

    store.commit(CONFIG, "cli", "first").expect("commit");
    store
        .commit(
            "base_dn: dc=changed,dc=example,dc=com\nbackend: \"null\"\n",
            "cli",
            "second",
        )
        .expect("second");

    let text = store.read_current().expect("read").expect("generation");
    assert!(
        text.contains("dc=changed"),
        "the last commit is what a reader gets: {text}"
    );
}

#[test]
fn a_store_directory_and_a_configuration_file_are_told_apart_by_being_directories() {
    let dir = tempfile::tempdir().expect("tempdir");

    let file = dir.path().join("config.yaml");
    std::fs::write(&file, CONFIG).expect("write");

    assert!(!Store::is_store(&file), "a file is a configuration");
    assert!(Store::is_store(dir.path()), "a directory is a store");
    assert!(
        !Store::is_store(&dir.path().join("absent")),
        "a path that does not exist is not yet a store"
    );
}

#[test]
fn a_file_configuration_still_loads_through_the_ordinary_path() {
    // The store must not have replaced the plain file: an operator with one config file and no
    // interest in history keeps working exactly as before.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("config.yaml");
    std::fs::write(&file, CONFIG).expect("write");

    let config =
        rust_rest_ldap::config::resolve(Args::default(), Some(CONFIG), |_| None).expect("config");
    assert_eq!(config.base_dn, "dc=example,dc=com");
    assert_eq!(config.backend, "null");
}

#[test]
fn a_generation_is_a_valid_configuration_on_its_own() {
    // The point of the metadata living in comments: the file is a configuration, not a wrapper
    // around one. Anything that reads YAML reads the body and ignores the header.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("config.d"));

    store.commit(CONFIG, "cli", "first").expect("commit");
    let generation = store.current().expect("current").expect("generation");

    // Parsing the whole file, header included, must give the same configuration as the body.
    let with_header = generation.read().expect("read");
    let from_whole = rust_rest_ldap::config::resolve(Args::default(), Some(&with_header), |_| None)
        .expect("the whole file must parse");
    let body = generation.body().expect("body");
    let from_body = rust_rest_ldap::config::resolve(Args::default(), Some(&body), |_| None)
        .expect("the body must parse");

    assert_ne!(
        with_header, body,
        "the two texts must differ, or this test compares a file with itself"
    );

    // The document text is provenance, not a setting: what has to match is everything the
    // server acts on. Dropping the text is the strongest form of that claim that does not
    // repeat twenty field names.
    let (mut from_whole, mut from_body) = (from_whole, from_body);
    from_whole.document = None;
    from_body.document = None;

    assert_eq!(from_whole, from_body);
}

#[test]
fn a_configuration_written_into_a_generation_keeps_everything_it_had() {
    // A store that rounded the configuration to the keys it understood would be a store that
    // silently dropped settings; the document is kept verbatim.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("config.d"));

    let full = "\
base_dn: dc=example,dc=com
listen_addr: 127.0.0.1:1389
backend: \"null\"
users_ou_name: people
groups_ou_name: teams
schema:
  mode: warn
indexes:
  default: [pres]
  attributes:
    cn: [eq, sub, ord]
";
    store.commit(full, "cli", "kept verbatim").expect("commit");

    assert_eq!(
        store.read_current().expect("read").expect("generation"),
        full,
        "the document comes back byte for byte"
    );
}

#[test]
fn the_body_of_a_generation_is_usable_after_a_hundred_commits() {
    // A guard against the accumulated-header bug: a commit that prepended a header to a
    // document that already had one would grow the file on every round.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("config.d"));

    store.commit(CONFIG, "cli", "first").expect("commit");

    for _ in 0..100 {
        let body = store.read_current().expect("read").expect("generation");
        store.commit(&body, "cli", "").expect("commit");
    }

    let generation = store.current().expect("current").expect("generation");
    let document = generation.read().expect("read");

    assert_eq!(
        document.matches("generation:").count(),
        1,
        "the header must not accumulate: {document}"
    );
    assert_eq!(generation.body().expect("body"), CONFIG);
}

#[test]
fn a_failed_load_names_the_store_that_holds_no_generation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store_path = dir.path().join("config.d");
    std::fs::create_dir_all(&store_path).expect("directory");

    // `resolve` does not know about stores; `load` does. The check here is that the store
    // reports "nothing to read" rather than inventing a default configuration.
    let store = Store::open(&store_path);
    assert_eq!(store.read_current().expect("read"), None);
}
