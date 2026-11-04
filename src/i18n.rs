//! Operator-facing diagnostics in the operator's language.
//!
//! The split this module exists to keep: **what a client sees on the wire stays English
//! ASCII**, because `diagnosticMessage` is part of the protocol and scripts match on it;
//! **what an operator reads** — the startup banner, a configuration error, the journal —
//! is translated.
//!
//! Resolution order, most specific first:
//! 1. `locale:` in the configuration file (`ru`, `en`);
//! 2. `RUST_REST_LDAP_LOCALE`;
//! 3. `LC_ALL`, then `LANG` (so a normal server inherits the host language);
//! 4. English.
//!
//! Translations live in `locale/<tag>.yaml` as a flat `key: text` map. A key that is
//! missing from the file falls back to the built-in English text rather than printing a
//! key or failing: a half-translated catalogue must not break a server start, and an
//! operator reading one English line among Russian ones is a smaller problem than a
//! server that will not run.
//!
//! The English text is built in, so a build without any translation file is complete.
//! A language file only ever adds.

use std::collections::BTreeMap;

use thiserror::Error;

/// Language tag, normalised to its primary subtag: `ru_RU.UTF-8` becomes `ru`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Locale(String);

impl Locale {
    /// Parses a tag the way `LANG` writes one.
    pub fn parse(tag: &str) -> Option<Self> {
        let primary = tag
            .trim()
            .split(['_', '.', '-', '@'])
            .next()?
            .trim()
            .to_ascii_lowercase();

        if primary.is_empty() {
            return None;
        }
        // `C` and `POSIX` are the "no locale" spellings; they mean English.
        if primary == "c" || primary == "posix" {
            return Some(Locale("en".to_string()));
        }

        Some(Locale(primary))
    }

    pub fn english() -> Self {
        Locale("en".to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_english(&self) -> bool {
        self.0 == "en"
    }
}

/// Where the language came from, so the startup line can say it and an operator can tell
/// a configured language from an inherited one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `locale:` in the configuration file.
    Config,
    /// `RUST_REST_LDAP_LOCALE`.
    Env,
    /// `LC_ALL` or `LANG`.
    System,
    /// Nothing set.
    Default,
}

impl Source {
    pub fn name(&self) -> &'static str {
        match self {
            Source::Config => "config",
            Source::Env => "RUST_REST_LDAP_LOCALE",
            Source::System => "LANG",
            Source::Default => "default",
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum LocaleError {
    #[error("unknown language '{0}'")]
    Unknown(String),
    #[error("cannot read the translation file '{path}': {reason}")]
    Read { path: String, reason: String },
    #[error("cannot parse the translation file '{path}': {reason}")]
    Parse { path: String, reason: String },
}

/// One catalogue: the built-in English text plus whatever a file added.
#[derive(Debug, Clone)]
pub struct Catalog {
    locale: Locale,
    texts: BTreeMap<String, String>,
}

impl Catalog {
    /// The built-in English catalogue.
    pub fn builtin() -> Self {
        Self {
            locale: Locale::english(),
            texts: ENGLISH
                .iter()
                .map(|(key, text)| ((*key).to_string(), (*text).to_string()))
                .collect(),
        }
    }

    /// The built-in English catalogue with `file` layered on top.
    pub fn load(locale: Locale, path: &std::path::Path) -> Result<Self, LocaleError> {
        let text = std::fs::read_to_string(path).map_err(|err| LocaleError::Read {
            path: path.display().to_string(),
            reason: err.to_string(),
        })?;
        let overlay: BTreeMap<String, String> =
            serde_saphyr::from_str(&text).map_err(|err| LocaleError::Parse {
                path: path.display().to_string(),
                reason: err.to_string(),
            })?;

        if locale.is_english() && !overlay.is_empty() {
            // English is built in; a file for it is allowed but pointless. Layering it
            // over itself keeps the behaviour uniform rather than special-casing.
        }

        let mut catalog = Self::builtin();
        catalog.locale = locale;
        for (key, value) in overlay {
            catalog.texts.insert(key, value);
        }
        Ok(catalog)
    }

    /// The text for `key`, falling back to English when this catalogue does not have it.
    pub fn text(&self, key: &str) -> Option<&str> {
        self.texts
            .get(key)
            .map(String::as_str)
            .or_else(|| english_text(key))
    }

    pub fn locale(&self) -> &Locale {
        &self.locale
    }

    /// Keys this catalogue added on top of English, for a startup line and for tests.
    pub fn added_keys(&self) -> impl Iterator<Item = &String> {
        let english: Vec<&str> = ENGLISH.iter().map(|(key, _)| *key).collect();
        self.texts
            .keys()
            .filter(move |key| !english.contains(&key.as_str()))
    }
}

fn english_text(key: &str) -> Option<&'static str> {
    ENGLISH
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, text)| *text)
}

/// Substitutes `{name}` placeholders.
///
/// An unknown placeholder stays as it is rather than becoming empty: seeing `{entry}` in
/// a log line tells an operator that the code forgot to pass it, while an empty string
/// silently hides that.
pub fn render(text: &str, args: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];

        match after.find('}') {
            Some(close) => {
                let name = &after[..close];
                match args.iter().find(|(candidate, _)| *candidate == name) {
                    Some((_, value)) => out.push_str(value),
                    None => {
                        out.push('{');
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &after[close + 1..];
            }
            // An unclosed brace is literal text, not a reason to lose the line.
            None => {
                out.push('{');
                rest = after;
            }
        }
    }

    out.push_str(rest);
    out
}

/// The catalogue in use.
///
/// A lock rather than a `OnceLock` because the language is decided twice: the environment
/// answers before the configuration file is read (so a bad config can be reported in the
/// operator's language), and the `locale:` key in that file overrides it afterwards.
static ACTIVE: std::sync::RwLock<Option<Catalog>> = std::sync::RwLock::new(None);

/// Installs the catalogue, replacing any earlier one.
pub fn install(catalog: Catalog) {
    let mut slot = ACTIVE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = Some(catalog);
}

/// The text for `key` from the installed catalogue, or `None`.
pub fn lookup(key: &str) -> Option<String> {
    let slot = ACTIVE
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    match slot.as_ref() {
        Some(catalog) => catalog.text(key).map(str::to_string),
        None => Catalog::builtin().text(key).map(str::to_string),
    }
}

/// Shorthand: the text for `key` with `args` substituted.
pub fn t(key: &str, args: &[(&str, &str)]) -> String {
    match lookup(key) {
        Some(text) => render(&text, args),
        None => key.to_string(),
    }
}

/// Shorthand without arguments.
pub fn plain(key: &str) -> String {
    t(key, &[])
}

/// Finds a top-level `locale:` in raw configuration text.
///
/// Needed because the language has to be known *before* the file parses: an operator who
/// wrote `locale: ru` and made a typo elsewhere should read the complaint in Russian. The
/// scan is deliberately shallow — one key at column zero — because this runs on text that
/// may be malformed by definition.
pub fn prescan_locale(text: &str) -> Option<Locale> {
    for line in text.lines() {
        // A nested `locale:` (indented) belongs to a section and is not this setting.
        if line.starts_with(|character: char| character.is_whitespace()) {
            continue;
        }
        let Some(rest) = line.strip_prefix("locale:") else {
            // Allow the quoted form of the key as well.
            let Some(rest) = line.strip_prefix("\"locale\":") else {
                continue;
            };
            return Locale::parse(rest.trim().trim_matches(['\'', '"']));
        };
        return Locale::parse(rest.trim().trim_matches(['\'', '"']));
    }
    None
}

/// Every message key this build knows, with its English text.
///
/// Public so a test can check that a shipped translation covers the whole vocabulary:
/// a key added in code and forgotten in `locale/ru.yaml` would silently fall back to
/// English, which is the failure this list exists to make visible.
pub fn english_keys() -> impl Iterator<Item = (&'static str, &'static str)> {
    ENGLISH.iter().copied()
}

/// Resolves the language from the environment, and says where it came from.
pub fn from_env(env: &impl Fn(&str) -> Option<String>) -> (Locale, Source) {
    if let Some(locale) = env("RUST_REST_LDAP_LOCALE")
        .filter(|value| !value.trim().is_empty())
        .and_then(|tag| Locale::parse(&tag))
    {
        return (locale, Source::Env);
    }

    for name in ["LC_ALL", "LANG"] {
        if let Some(locale) = env(name)
            .filter(|value| !value.trim().is_empty())
            .and_then(|tag| Locale::parse(&tag))
        {
            return (locale, Source::System);
        }
    }

    (Locale::english(), Source::Default)
}

/// Picks the catalogue for `locale`, reading `file` when one is configured.
///
/// When the language came from the configuration and its file is missing, that is an
/// error: the operator asked for a language the build cannot speak, and starting in
/// English instead would hide the mistake. When it came from `LANG`, a missing file is
/// not an error — a host may well be set to a language this server does not ship, and
/// falling back to English is the reasonable answer.
/// Which language to speak, and where the answer came from.
///
/// The decision, separated from the reading it needs. `install_language` in `main` used to mix
/// the two: it read the environment, opened the configuration file, probed the filesystem for a
/// catalogue and installed the result in one function, so none of the ordering rules could be
/// tested - and they have an order.
///
/// The rules, in force order:
///
/// 1. a configuration file that already loaded decides (the operator wrote `locale:` and meant it);
/// 2. otherwise a `locale:` scanned out of the file text, before the file's own errors are
///    reported - a complaint about the file should already be in the language the file asks for;
/// 3. otherwise the environment;
/// 4. otherwise English.
///
/// `candidate` is the catalogue file for a tag, or `None` when there is none to read: the caller
/// owns the filesystem, the decision owns the order.
pub fn resolve_language(
    from_config: Option<(Locale, Source, Option<std::path::PathBuf>)>,
    config_text: Option<&str>,
    env: &impl Fn(&str) -> Option<String>,
    candidate: impl Fn(&str) -> Option<std::path::PathBuf>,
) -> (Locale, Source, Option<std::path::PathBuf>) {
    if let Some(resolved) = from_config {
        return resolved;
    }

    let (locale, source) = from_env(env);

    let scanned = config_text.and_then(prescan_locale);
    let (locale, source) = match scanned {
        Some(locale) if !locale.is_english() => (locale, Source::Config),
        _ => (locale, source),
    };

    let file = candidate(locale.as_str());
    (locale, source, file)
}

pub fn catalog_for(
    locale: Locale,
    source: Source,
    file: Option<&std::path::Path>,
) -> Result<Catalog, LocaleError> {
    if locale.is_english() {
        return match file {
            Some(path) => Catalog::load(locale, path),
            None => Ok(Catalog::builtin()),
        };
    }

    let Some(path) = file else {
        return match source {
            Source::Config => Err(LocaleError::Unknown(locale.as_str().to_string())),
            _ => Ok(Catalog::builtin()),
        };
    };

    match Catalog::load(locale.clone(), path) {
        Ok(catalog) => Ok(catalog),
        Err(err) => match source {
            Source::Config => Err(err),
            _ => Ok(Catalog::builtin()),
        },
    }
}

/// The message keys this build knows, with their English text.
///
/// One list, in the source, so a translator has the whole vocabulary in front of them and
/// a missing key is visible in review rather than at runtime.
const ENGLISH: &[(&str, &str)] = &[
    // Startup
    (
        "start.banner",
        "rust-rest-ldap {version}: backend '{backend}', base '{base}', {users} users, {groups} groups",
    ),
    (
        "start.danger",
        "DANGER: this configuration turns on {settings} - acknowledged with AllowDangerousSettings",
    ),
    (
        "start.passwords",
        "passwords: store {scheme}, {weak} weak scheme(s) allowed; acl rules {rules}; plaintext simple bind {plaintext}",
    ),
    ("start.listening", "ldap: listening on {addr}"),
    (
        "start.language",
        "diagnostics: language '{locale}' (from {source})",
    ),
    ("start.shutting_down", "shutting down"),
    ("start.export_done", "exported {entries} entries to {path}"),
    (
        "start.journal_pruned",
        "journal: dropped {removed} of the oldest change records, as replication.journal_keep says",
    ),
    (
        "start.http",
        "http: listening on {addr} (health, metrics, callback)",
    ),
    ("start.journal", "change journal: {path}"),
    ("start.journal_stdout", "change journal: standard output"),
    // Operator-facing failures
    ("error.config", "configuration error: {detail}"),
    ("error.backend", "backend error: {detail}"),
    ("error.server", "server error: {detail}"),
    ("error.http", "http server error: {detail}"),
    (
        "error.signal",
        "cannot install the SIGUSR1 handler: {detail}",
    ),
    (
        "error.reload",
        "reload failed, keeping the current directory: {detail}",
    ),
    ("error.write", "write failed: {detail}"),
    (
        "error.hash_upgrade",
        "could not persist the password hash upgrade: {detail}",
    ),
    (
        "error.password_upgrade",
        "password upgrade failed for '{dn}': {detail}",
    ),
    ("error.accept", "error accepting a connection: {detail}"),
    (
        "error.tls_handshake",
        "client {peer}: TLS handshake failed: {detail}",
    ),
    (
        "error.starttls_handshake",
        "client {peer}: StartTLS handshake failed",
    ),
    (
        "error.malformed",
        "client {peer} sent a malformed message, connection closed",
    ),
    ("error.client", "client {peer}: {detail}"),
    (
        "error.sync_lagged",
        "connection {peer} fell {missed} changes behind and its persistent searches were dropped",
    ),
    ("error.peer", "peer {url}: {detail}; retrying"),
    (
        "error.conflict_log",
        "conflict about {dn} could not be written to the conflict log: {detail}",
    ),
    (
        "error.peer_behind",
        "peer {url}: its cookie points into a part of the journal this node has already pruned, \
         so the changes in between are gone; starting a full refresh instead of a silent gap",
    ),
    (
        "error.peer_id",
        "peer {url} says it is server {actual}, but the configuration says {expected}: two nodes \
         must not share an id, and this peer is replicating under another node's name",
    ),
    (
        "error.peer_conflict",
        "peer {url} and this node disagree about {dn}: {why}; the local version was kept",
    ),
    (
        "error.panic",
        "connection {peer} ended in an internal error; the listeners are unaffected",
    ),
    ("error.journal", "cannot write the change journal: {detail}"),
    (
        "error.bootstrap",
        "cannot create the first administrator: {detail}",
    ),
    ("error.import", "cannot import: {detail}"),
    ("error.read", "cannot read the file: {detail}"),
    ("import.done", "imported {entries} entries"),
    (
        "check.schema_violation",
        "schema violation in '{dn}': {detail}",
    ),
    ("error.index", "cannot build the index: {detail}"),
    (
        "config.store_empty",
        "'{path}' is a configuration store but holds no generation yet; commit one with --config-commit, or point at a configuration file instead",
    ),
    (
        "config.store",
        "cannot read the configuration store '{path}': {detail}",
    ),
    (
        "error.store_path_missing",
        "--{command} needs the store directory: pass it with -c /etc/rust-rest-ldap/config.d",
    ),
    (
        "error.store_not_a_directory",
        "'{path}' is not a directory; the generation store is a directory, and a plain file is a configuration",
    ),
    ("error.store", "configuration store: {detail}"),
    (
        "config.committed",
        "committed; the running server adopts the new rules now",
    ),
    (
        "config.committed_needs_restart",
        "committed; the running server adopts the new rules now, but these settings take effect only after a restart: {settings}",
    ),
    (
        "config.committed_not_applied",
        "committed, but the running server could not adopt it and keeps the rules it has: {detail}",
    ),
    (
        "config.unknown_backend",
        "unknown backend '{name}'; known backends: {known}",
    ),
    (
        "error.config_apply",
        "adopting the committed configuration failed: {detail}",
    ),
    ("store.done", "committed as {what}"),
    ("store.collected", "collected generations {numbers}"),
    (
        "error.schema_reload",
        "cannot reload the schema, the previous one stays in force: {detail}",
    ),
    (
        "start.schema_reloaded",
        "schema reloaded: {attributes} attribute types, {classes} object classes",
    ),
    (
        "check.index_mismatch",
        "index disagrees with the data for {query}: missing [{lost}], unexpected [{extra}]",
    ),
    (
        "check.index_loose",
        "index on '{attribute}' narrows less than it could: {extra} extra candidates over the sample",
    ),
    (
        "check.index_sound",
        "index is sound: {checked} queries compared with a scan, {skipped} left to the scan",
    ),
    (
        "check.index_broken",
        "index is NOT sound: of {checked} queries compared with a scan, {missing} would lose entries and {wrong} disagree with it",
    ),
    (
        "check.reindex_done",
        "indexed {entries} entries, {attributes} attributes, {bytes} bytes in {millis} ms",
    ),
    (
        "check.ok",
        "configuration is usable: backend '{backend}', base '{base_dn}', {entries} entries, {broken} with schema violations",
    ),
    (
        "start.bootstrap_created",
        "created the first administrator '{dn}' with a {scheme} hash; remove the bootstrap section from the configuration",
    ),
    (
        "start.bootstrap_not_empty",
        "bootstrap skipped: the store already holds {entries} entries, and the first administrator is only created in an empty one",
    ),
    (
        "error.shutdown_timeout",
        "graceful shutdown timed out after {grace}, closing remaining connections",
    ),
    ("warn.schema", "schema warning: {detail}"),
    // Configuration diagnostics, one per variant an operator can hit
    ("config.server_id", "invalid server id: {detail}"),
    ("config.journal_keep", "invalid journal_keep: {detail}"),
    ("config.peers", "invalid peers: {detail}"),
    ("config.referral", "invalid referrals: {detail}"),
    (
        "config.tls_material",
        "use_tls is enabled, but server_cert and server_key are not both set",
    ),
    (
        "config.schema_read",
        "cannot read the schema file '{path}': {detail}",
    ),
    (
        "config.schema",
        "error loading the schema from '{path}': {detail}",
    ),
    (
        "config.schema_mode",
        "unknown schema mode '{value}'; expected strict, warn or off",
    ),
    (
        "config.locale",
        "unknown language '{value}'; the translation file '{path}' is missing or unreadable",
    ),
    (
        "config.plain_http",
        "http_listen_addr is set to '{address}' but the callback listener speaks plain HTTP, so its token travels in the clear; add AllowPlainHttpRest: 'Yes I know this is bad idea' next to it if that is acceptable",
    ),
    (
        "config.bootstrap_password_missing",
        "the 'bootstrap' section names no password: set password_file or password_env, or remove the section",
    ),
    (
        "config.bootstrap_password_ambiguous",
        "the 'bootstrap' section names both password_file and password_env; pick one, so that where the first administrator's password comes from has one answer",
    ),
    (
        "config.dangerous",
        "this configuration turns on {settings}, which weakens the server, but AllowDangerousSettings is not set; add AllowDangerousSettings: 'Yes I know this is bad idea' at the top level if that is really what you want",
    ),
    (
        "config.weak_ack",
        "weak password schemes are configured ({requested}) but AllowWeakHashes is not set; if that is really what you want, add AllowWeakHashes: 'Yes I know this is bad idea' to the passwords section",
    ),
    ("config.index", "error in the 'indexes' section: {detail}"),
    (
        "config.password",
        "error in the 'passwords' section: {detail}",
    ),
    ("config.access", "error in the 'access' section: {detail}"),
    (
        "config.unknown_backend",
        "unknown backend '{name}'; known backends: {known}",
    ),
    (
        "config.interval",
        "invalid update interval '{value}': {detail}",
    ),
    (
        "config.parse",
        "cannot parse the configuration file '{path}': {detail}",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn a_tag_is_reduced_to_its_language() {
        assert_eq!(
            Locale::parse("ru_RU.UTF-8").map(|l| l.as_str().to_string()),
            Some("ru".to_string())
        );
        assert_eq!(
            Locale::parse("ru-RU").map(|l| l.as_str().to_string()),
            Some("ru".to_string())
        );
        assert_eq!(
            Locale::parse("de_AT@euro").map(|l| l.as_str().to_string()),
            Some("de".to_string())
        );
        assert_eq!(
            Locale::parse("EN").map(|l| l.as_str().to_string()),
            Some("en".to_string())
        );
    }

    #[test]
    fn the_neutral_locales_mean_english() {
        assert_eq!(Locale::parse("C").expect("c").as_str(), "en");
        assert_eq!(Locale::parse("POSIX").expect("posix").as_str(), "en");
        assert_eq!(Locale::parse("  "), None);
        assert_eq!(Locale::parse(""), None);
    }

    // ---- the language decision, tested as a decision ----
    //
    // These were impossible while the decision lived in `main`: it read the environment, opened
    // the configuration file and probed the filesystem in one function, and a private function
    // in a binary cannot be reached by a test.

    fn no_catalogue(_: &str) -> Option<std::path::PathBuf> {
        None
    }

    #[test]
    fn a_loaded_configuration_decides_before_anything_is_scanned() {
        let decided = Locale::parse("de").expect("a tag");
        let resolved = resolve_language(
            Some((decided.clone(), Source::Config, None)),
            // The file asks for Russian and must lose: the configuration already loaded, so its
            // answer is the one that counts.
            Some("locale: ru\n"),
            &|name| (name == "RUST_REST_LDAP_LOCALE").then(|| "fr".to_string()),
            no_catalogue,
        );

        assert_eq!(resolved.0, decided);
        assert_eq!(resolved.1, Source::Config);
    }

    #[test]
    fn a_file_that_did_not_load_still_governs_the_language_of_its_own_complaint() {
        let resolved = resolve_language(
            None,
            Some("locale: ru\nbase_dn: [unclosed\n"),
            &|name| (name == "RUST_REST_LDAP_LOCALE").then(|| "fr".to_string()),
            no_catalogue,
        );

        assert_eq!(
            resolved.0,
            Locale::parse("ru").expect("a tag"),
            "the file wins over the environment for its own errors"
        );
        assert_eq!(resolved.1, Source::Config);
    }

    #[test]
    fn without_a_file_the_environment_decides() {
        let resolved = resolve_language(
            None,
            None,
            &|name| (name == "RUST_REST_LDAP_LOCALE").then(|| "ru".to_string()),
            no_catalogue,
        );

        assert_eq!(resolved.0, Locale::parse("ru").expect("a tag"));
        assert_eq!(resolved.1, Source::Env);
    }

    #[test]
    fn an_english_file_does_not_shadow_the_environment() {
        // `locale: en` says "the built-in English", which is not a decision to overrule the
        // environment: the operator asked for no translation, not for English over their locale.
        let resolved = resolve_language(
            None,
            Some("locale: en\n"),
            &|name| (name == "RUST_REST_LDAP_LOCALE").then(|| "ru".to_string()),
            no_catalogue,
        );

        assert_eq!(resolved.0, Locale::parse("ru").expect("a tag"));
        assert_eq!(resolved.1, Source::Env);
    }

    #[test]
    fn the_catalogue_is_looked_up_for_the_language_that_was_chosen() {
        let looked_for = std::cell::RefCell::new(Vec::new());
        let resolved = resolve_language(None, Some("locale: ru\n"), &|_| None, |tag| {
            looked_for.borrow_mut().push(tag.to_string());
            Some(std::path::PathBuf::from(format!("locale/{tag}.yaml")))
        });

        assert_eq!(looked_for.into_inner(), vec!["ru".to_string()]);
        assert_eq!(
            resolved.2,
            Some(std::path::PathBuf::from("locale/ru.yaml")),
            "and its path is handed back, not opened here"
        );
    }

    #[test]
    fn english_is_built_in_and_complete() {
        let catalog = Catalog::builtin();

        for (key, text) in ENGLISH {
            assert_eq!(
                catalog.text(key),
                Some(*text),
                "the built-in catalogue must contain {key}"
            );
        }
    }

    #[test]
    fn placeholders_are_substituted() {
        assert_eq!(
            render("listening on {addr}", &[("addr", "127.0.0.1:389")]),
            "listening on 127.0.0.1:389"
        );
        assert_eq!(render("{a}+{b}", &[("a", "1"), ("b", "2")]), "1+2");
    }

    #[test]
    fn an_unknown_placeholder_stays_visible() {
        assert_eq!(
            render("listening on {addr}", &[]),
            "listening on {addr}",
            "an empty string would hide the mistake"
        );
    }

    #[test]
    fn an_unclosed_brace_is_literal_text() {
        assert_eq!(render("a { b", &[]), "a { b");
        assert_eq!(render("{", &[]), "{");
    }

    #[test]
    fn the_environment_is_consulted_in_order() {
        let env = |name: &str| match name {
            "RUST_REST_LDAP_LOCALE" => Some("ru".to_string()),
            "LC_ALL" => Some("de_DE.UTF-8".to_string()),
            "LANG" => Some("fr_FR.UTF-8".to_string()),
            _ => None,
        };
        assert_eq!(
            from_env(&env),
            (Locale::parse("ru").expect("ru"), Source::Env)
        );

        let env = |name: &str| match name {
            "LC_ALL" => Some("de_DE.UTF-8".to_string()),
            "LANG" => Some("fr_FR.UTF-8".to_string()),
            _ => None,
        };
        assert_eq!(
            from_env(&env),
            (Locale::parse("de").expect("de"), Source::System)
        );

        let env = |name: &str| match name {
            "LANG" => Some("fr_FR.UTF-8".to_string()),
            _ => None,
        };
        assert_eq!(
            from_env(&env),
            (Locale::parse("fr").expect("fr"), Source::System)
        );

        assert_eq!(from_env(&no_env), (Locale::english(), Source::Default));
    }

    #[test]
    fn an_empty_environment_value_is_ignored() {
        let env = |name: &str| match name {
            "RUST_REST_LDAP_LOCALE" => Some("   ".to_string()),
            "LANG" => Some("ru_RU.UTF-8".to_string()),
            _ => None,
        };

        assert_eq!(from_env(&env).1, Source::System);
    }

    #[test]
    fn a_file_layers_over_english_and_keeps_the_rest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ru.yaml");
        std::fs::write(
            &path,
            "start.listening: \"ldap: слушает {addr}\"\nstart.custom: \"своя строка\"\n",
        )
        .expect("write");

        let catalog = Catalog::load(Locale::parse("ru").expect("ru"), &path).expect("load");

        assert_eq!(
            catalog.text("start.listening"),
            Some("ldap: слушает {addr}"),
            "the file wins"
        );
        assert_eq!(
            catalog
                .text("start.banner")
                .map(|text| text.starts_with("rust-rest-ldap")),
            Some(true),
            "a key the file does not have falls back to English"
        );
        assert!(catalog.added_keys().any(|key| key == "start.custom"));
    }

    #[test]
    fn a_locale_in_the_raw_text_is_found_before_parsing() {
        assert_eq!(
            prescan_locale("base_dn: dc=example\nlocale: ru\n").map(|l| l.as_str().to_string()),
            Some("ru".to_string())
        );
        assert_eq!(
            prescan_locale("locale: \"ru\"\n").map(|l| l.as_str().to_string()),
            Some("ru".to_string())
        );
        assert_eq!(
            prescan_locale("passwords:\n  locale: ru\n"),
            None,
            "an indented key belongs to a section, not to the server"
        );
        assert_eq!(prescan_locale("base_dn: x\n"), None);
    }

    #[test]
    fn a_missing_key_falls_back_to_english_rather_than_a_key_name() {
        let catalog = Catalog::builtin();

        assert!(catalog.text("start.banner").is_some());
        assert_eq!(catalog.text("no.such.key"), None);
    }

    #[test]
    fn a_broken_file_is_reported_with_its_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ru.yaml");
        std::fs::write(&path, "not a map: [\n").expect("write");

        let error = Catalog::load(Locale::parse("ru").expect("ru"), &path).expect_err("must fail");

        assert!(
            error.to_string().contains("ru.yaml"),
            "the operator has to see which file: {error}"
        );
    }

    #[test]
    fn a_language_asked_for_in_the_configuration_must_be_available() {
        let error = catalog_for(Locale::parse("ru").expect("ru"), Source::Config, None)
            .expect_err("the file is not configured");

        assert!(matches!(error, LocaleError::Unknown(_)));
    }

    #[test]
    fn a_language_inherited_from_the_host_falls_back_quietly() {
        // A host set to a language this build does not ship must still start.
        let catalog =
            catalog_for(Locale::parse("ja").expect("ja"), Source::System, None).expect("fallback");

        assert!(catalog.locale().is_english(), "English is the fallback");
    }

    #[test]
    fn english_needs_no_file() {
        let catalog = catalog_for(Locale::english(), Source::Default, None).expect("builtin");

        assert!(catalog.locale().is_english());
        assert!(catalog.text("start.banner").is_some());
    }
}
