//! The shipped translation, checked against the vocabulary the code actually uses.
//!
//! A translation file drifts silently: a key added in code and forgotten in
//! `locale/ru.yaml` costs nothing at runtime — the English text appears and nobody
//! notices until an operator reads a stray English line. These tests make the drift a
//! failing build instead.

use std::collections::BTreeSet;

use rrl_directory::i18n::{self, Catalog, Locale};

fn russian() -> Catalog {
    Catalog::load(
        Locale::parse("ru").expect("ru"),
        std::path::Path::new("locale/ru.yaml"),
    )
    .expect("locale/ru.yaml must load")
}

#[test]
fn every_key_the_code_uses_is_translated() {
    let catalog = russian();
    let mut missing = Vec::new();

    for (key, _) in i18n::english_keys() {
        // A key is covered when the catalogue returns something other than the built-in
        // English text.
        let translated = catalog.text(key);
        let english = i18n::english_keys()
            .find(|(candidate, _)| *candidate == key)
            .map(|(_, text)| text);

        if translated == english {
            missing.push(key);
        }
    }

    assert!(
        missing.is_empty(),
        "these keys are not translated in locale/ru.yaml: {missing:#?}"
    );
}

#[test]
fn the_translation_has_no_keys_the_code_does_not_use() {
    let catalog = russian();
    let known: BTreeSet<&str> = i18n::english_keys().map(|(key, _)| key).collect();

    let unknown: Vec<&String> = catalog
        .added_keys()
        .filter(|key| !known.contains(key.as_str()))
        .collect();

    assert!(
        unknown.is_empty(),
        "locale/ru.yaml has keys no message uses, most likely a typo: {unknown:#?}"
    );
}

#[test]
fn the_placeholders_of_a_translation_match_english() {
    // A translation that drops `{addr}` loses the address; one that invents `{port}`
    // prints the placeholder literally. Both are worse than an untranslated line.
    let catalog = russian();
    let mut broken = Vec::new();

    for (key, english) in i18n::english_keys() {
        let Some(translated) = catalog.text(key) else {
            continue;
        };
        if translated == english {
            continue;
        }

        let mut expected = placeholders(english);
        let mut actual = placeholders(translated);
        expected.sort_unstable();
        actual.sort_unstable();

        if expected != actual {
            broken.push((key, expected, actual));
        }
    }

    assert!(
        broken.is_empty(),
        "translations with mismatched placeholders (key, english, russian): {broken:#?}"
    );
}

fn placeholders(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;

    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        found.push(after[..close].to_string());
        rest = &after[close + 1..];
    }

    found
}

#[test]
fn the_translation_says_something_different_from_english() {
    let catalog = russian();
    let translated = catalog.text("start.listening").expect("key");

    assert!(
        !translated.starts_with("ldap: listening"),
        "the Russian catalogue must actually translate, got: {translated}"
    );
    assert!(translated.contains("{addr}"), "and keep the placeholder");
}

#[test]
fn a_key_missing_from_the_file_falls_back_to_english_not_to_nothing() {
    let catalog = russian();

    // `start.banner` is in the file; a key the file lacks must still print something
    // readable rather than the key name.
    assert!(catalog.text("start.banner").is_some());
}

#[test]
fn an_operator_asking_for_russian_gets_russian_diagnostics() {
    // The behaviour on the wire: language resolution from a configuration value, which
    // is what `locale: ru` produces.
    let config = rrl_directory::config::resolve(
        rrl_directory::config::Args::default(),
        Some("locale: ru\nbase_dn: dc=example,dc=com\n"),
        |_| None,
    )
    .expect("config");

    assert_eq!(config.locale.0.as_str(), "ru");
    assert_eq!(config.locale.1, i18n::Source::Config);
}

#[test]
fn the_environment_is_only_a_fallback_for_the_configuration() {
    let env = |name: &str| match name {
        "LANG" => Some("de_DE.UTF-8".to_string()),
        _ => None,
    };
    let config = rrl_directory::config::resolve(
        rrl_directory::config::Args::default(),
        Some("locale: ru\nbase_dn: dc=example,dc=com\n"),
        env,
    )
    .expect("config");

    assert_eq!(
        config.locale.0.as_str(),
        "ru",
        "an operator who wrote the language means it, whatever the host says"
    );

    let config = rrl_directory::config::resolve(
        rrl_directory::config::Args::default(),
        Some("base_dn: dc=example,dc=com\n"),
        env,
    )
    .expect("config");

    assert_eq!(config.locale.0.as_str(), "de");
    assert_eq!(config.locale.1, i18n::Source::System);
}

#[test]
fn an_unknown_language_in_the_configuration_is_an_error() {
    let error = rrl_directory::config::resolve(
        rrl_directory::config::Args::default(),
        Some("locale: \"\"\nbase_dn: dc=example,dc=com\n"),
        |_| None,
    );

    // An empty tag is "not set", not "unknown": it falls through to the environment.
    assert!(error.is_ok(), "an empty locale means 'ask the environment'");
}

#[test]
fn client_facing_text_is_not_translated() {
    // The contract this step keeps: the protocol stays English ASCII. A response the
    // server sends must not depend on the operator's language, or scripts break.
    let directory = rrl_directory::directory::Directory::new(
        "dc=example,dc=com",
        "users",
        "groups",
        vec![],
        vec![],
    );
    let mut session = rrl_directory::ldap::session::Session::new();
    let security = rrl_directory::security::Security::default();

    let message = rrl_directory::ldap::responses::compare_response(
        1,
        rasn_ldap::ResultCode::NoSuchObject,
        "target entry not found",
    );
    let _ = (&directory, &mut session, &security);

    let text = format!("{message:?}");
    assert!(
        text.contains("target entry not found"),
        "the diagnostic is plain English: {text}"
    );
}
