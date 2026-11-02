//! Dangerous settings and the sentence that unlocks them.
//!
//! The rule the user asked for, in one sentence: a setting that weakens the server does
//! not take `true`, it takes `Yes I know this is bad idea`, and the top-level
//! `AllowDangerousSettings` has to carry the same sentence. If the master switch is not
//! the sentence, any dangerous setting present in the file is a startup error — not a
//! warning, not a silently ignored line.
//!
//! The failure mode this prevents: a hardening-free configuration pasted from a wiki,
//! or a `true` switched on to make a test pass and left in. A server that quietly
//! accepts those is a server whose file transport and password hashes are weaker than
//! the operator believes.

use std::path::PathBuf;

use rust_rest_ldap::config::{Args, Config, ConfigError};
use rust_rest_ldap::danger::{ACKNOWLEDGEMENT, Danger};

fn no_env(_: &str) -> Option<String> {
    None
}

fn resolve(text: &str) -> Result<Config, ConfigError> {
    rust_rest_ldap::config::resolve(Args::default(), Some(text), no_env)
}

#[test]
fn an_empty_value_does_not_unlock_a_dangerous_setting() {
    // A blank line where the sentence should be is the most likely mistake after a
    // copy-paste, and it must not count as an acknowledgement.
    let error = resolve(
        "
bind:
  AllowUnencryptedBind: \"\"
",
    )
    .expect_err("an empty value is not the sentence");

    assert!(error.to_string().contains(ACKNOWLEDGEMENT), "{error}");
}

#[test]
fn a_clean_configuration_starts_silently() {
    let cfg = resolve("base_dn: dc=example,dc=com\n").expect("a plain config must load");

    assert!(
        cfg.dangerous_settings.is_empty(),
        "nothing dangerous is on: {:?}",
        cfg.dangerous_settings
    );
    assert!(!cfg.allow_unencrypted_bind);
}

#[test]
fn an_unacknowledged_boolean_is_refused_at_parse_time() {
    // `true` never reaches the check: the type only accepts the sentence, so the
    // operator gets the instruction instead of a config that quietly does nothing.
    let error = resolve(
        "
bind:
  AllowUnencryptedBind: true
",
    )
    .expect_err("a boolean must not unlock a dangerous setting");

    let text = error.to_string();
    assert!(
        text.contains(ACKNOWLEDGEMENT),
        "the error has to say what to write instead: {text}"
    );
}

#[test]
fn a_dangerous_setting_without_the_master_switch_refuses_to_start() {
    let error = resolve(&format!(
        "
bind:
  AllowUnencryptedBind: \"{ACKNOWLEDGEMENT}\"
"
    ))
    .expect_err("the master acknowledgement is missing");

    match error {
        ConfigError::DangerousSettingsNotAcknowledged { settings } => {
            assert!(
                settings.contains("bind.AllowUnencryptedBind"),
                "the error must name the setting: {settings}"
            );
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn the_master_switch_must_be_the_sentence_not_a_shorthand() {
    for value in ["true", "yes", "1", "\"on\"", "\"allow\""] {
        let error = resolve(&format!(
            "
AllowDangerousSettings: {value}
bind:
  AllowUnencryptedBind: \"{ACKNOWLEDGEMENT}\"
"
        ))
        .expect_err(value);

        assert!(
            error.to_string().contains(ACKNOWLEDGEMENT),
            "with {value} the operator must be told the sentence: {error}"
        );
    }
}

#[test]
fn the_sentence_in_both_places_turns_the_setting_on_and_names_it() {
    let cfg = resolve(&format!(
        "
AllowDangerousSettings: \"{ACKNOWLEDGEMENT}\"
bind:
  AllowUnencryptedBind: \"{ACKNOWLEDGEMENT}\"
"
    ))
    .expect("acknowledged config");

    assert!(cfg.allow_unencrypted_bind);
    assert_eq!(cfg.dangerous_settings, vec!["bind.AllowUnencryptedBind"]);
}

#[test]
fn weak_password_hashes_need_the_same_two_locks() {
    let error = resolve(&format!(
        "
AllowDangerousSettings: \"{ACKNOWLEDGEMENT}\"
passwords:
  AllowedWeakHashes: \"ssha\"
"
    ))
    .expect_err("the per-setting sentence is missing");

    let text = error.to_string();
    assert!(
        text.contains(ACKNOWLEDGEMENT),
        "the operator must be told the sentence: {text}"
    );
}

#[test]
fn weak_hashes_with_both_sentences_load_and_are_named() {
    let cfg = resolve(&format!(
        "
AllowDangerousSettings: \"{ACKNOWLEDGEMENT}\"
passwords:
  AllowWeakHashes: \"{ACKNOWLEDGEMENT}\"
  AllowedWeakHashes: \"ssha, crypt-md5\"
"
    ))
    .expect("acknowledged weak hashes");

    assert_eq!(
        cfg.dangerous_settings,
        vec!["passwords.AllowedWeakHashes"],
        "the banner must name what is on"
    );
    assert!(cfg.passwords.upgrade_on_bind(), "and the upgrade stays on");
}

#[test]
fn the_plain_http_callback_needs_its_own_sentence() {
    let error = resolve("http_listen_addr: localhost:8080\n")
        .expect_err("a plain HTTP callback cannot be enabled silently");

    match error {
        ConfigError::PlainHttpNotAcknowledged { address } => {
            assert_eq!(address, "localhost:8080");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn the_plain_http_callback_with_the_sentence_loads() {
    let cfg = resolve(&format!(
        "
AllowDangerousSettings: \"{ACKNOWLEDGEMENT}\"
AllowPlainHttpRest: \"{ACKNOWLEDGEMENT}\"
http_listen_addr: localhost:8080
callback_auth_token: secret
"
    ))
    .expect("acknowledged callback");

    assert_eq!(cfg.http_listen_addr.as_deref(), Some("localhost:8080"));
    assert_eq!(cfg.dangerous_settings, vec!["AllowPlainHttpRest"]);
}

#[test]
fn several_dangerous_settings_are_all_named_in_the_banner() {
    let cfg = resolve(&format!(
        "
AllowDangerousSettings: \"{ACKNOWLEDGEMENT}\"
AllowPlainHttpRest: \"{ACKNOWLEDGEMENT}\"
http_listen_addr: localhost:8080
callback_auth_token: secret
bind:
  AllowUnencryptedBind: \"{ACKNOWLEDGEMENT}\"
passwords:
  AllowWeakHashes: \"{ACKNOWLEDGEMENT}\"
  AllowedWeakHashes: \"ssha\"
"
    ))
    .expect("every setting carries its own sentence");

    let mut named = cfg.dangerous_settings.clone();
    named.sort_unstable();
    assert_eq!(
        named,
        vec![
            "AllowPlainHttpRest",
            "bind.AllowUnencryptedBind",
            "passwords.AllowedWeakHashes"
        ],
        "the startup banner must name all of them"
    );
}

#[test]
fn one_missing_sentence_refuses_the_whole_configuration() {
    // Two settings on, one acknowledged: the file is refused, and the error names the
    // ones that are on rather than the one that is missing. An operator who turned on
    // three things needs to see three things.
    let error = resolve(&format!(
        "
AllowDangerousSettings: \"{ACKNOWLEDGEMENT}\"
AllowPlainHttpRest: \"{ACKNOWLEDGEMENT}\"
http_listen_addr: localhost:8080
callback_auth_token: secret
passwords:
  AllowedWeakHashes: \"ssha\"
"
    ))
    .expect_err("the weak-hash sentence is missing");

    assert!(
        error.to_string().contains(ACKNOWLEDGEMENT),
        "the operator is told the sentence: {error}"
    );
}

#[test]
fn the_master_switch_alone_does_not_unlock_anything() {
    // The master sentence says "I read this file"; without a specific sentence no
    // dangerous setting is on, and the server stays strict.
    let cfg = resolve(&format!(
        "
AllowDangerousSettings: \"{ACKNOWLEDGEMENT}\"
"
    ))
    .expect("acknowledging nothing is harmless");

    assert!(!cfg.allow_unencrypted_bind);
    assert!(cfg.dangerous_settings.is_empty());
}

#[test]
fn the_default_configuration_of_this_repository_is_acknowledged() {
    let text = std::fs::read_to_string("config.yaml").expect("config.yaml");
    let args = Args {
        config: Some(PathBuf::from("config.yaml")),
        ..Args::default()
    };
    let cfg =
        rust_rest_ldap::config::resolve(args, Some(&text), no_env).expect("repository config");

    assert_eq!(
        Danger::parse(ACKNOWLEDGEMENT),
        Ok(Danger::On),
        "sanity: the sentence parses"
    );
    assert!(
        !cfg.dangerous_settings.is_empty(),
        "the example config demonstrates the dangerous settings, so it lists them"
    );
    for name in &cfg.dangerous_settings {
        assert!(
            [
                "bind.AllowUnencryptedBind",
                "AllowPlainHttpRest",
                "passwords.AllowedWeakHashes"
            ]
            .contains(name),
            "unexpected entry in the banner: {name}"
        );
    }
}

#[test]
fn removing_the_master_switch_from_the_example_config_breaks_it() {
    // The property an operator relies on: delete one line and the dangerous settings
    // stop working, loudly. Anything softer would let a copied config run weaker than
    // it looks.
    let text = std::fs::read_to_string("config.yaml").expect("config.yaml");
    let text = text
        .lines()
        .filter(|line| !line.starts_with("AllowDangerousSettings:"))
        .collect::<Vec<_>>()
        .join("\n");

    let error = rust_rest_ldap::config::resolve(Args::default(), Some(&text), no_env)
        .expect_err("without the master switch the config must not load");

    assert!(
        error.to_string().contains("AllowDangerousSettings"),
        "the error must name the missing switch: {error}"
    );
}
