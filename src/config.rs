//! Configuration: CLI flags, environment variables and the YAML file.
//!
//! Precedence (gorestldap had flags and file merged by docopt, so file values
//! silently beat the environment; here the order is explicit and testable):
//! CLI flag > environment variable > config file > built-in default.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::acl::{AccessRuleConfig, Acl, AclError};
use crate::danger::Danger;
use crate::index::{IndexConfig, IndexError};
use crate::integrity::IntegrityConfig;
use crate::password::PasswordPolicy;
use crate::password::policy::{PasswordConfig, PolicyError};
use crate::schema::{Mode as SchemaMode, Schema, SchemaError};

/// The backend a server runs when nothing says otherwise.
///
/// `null` and not `rest`: the REST backend gorestldap defaulted to is not in this build, and a
/// default that names a backend the binary does not have is a server that cannot start at all.
/// An empty read-only directory is a working server - the banner says "backend 'null'" and how
/// many users it holds - so it is the honest default for "I just want to look".
pub const DEFAULT_BACKEND: &str = "null";
pub const DEFAULT_BASE_DN: &str = "dc=example,dc=com";
pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:389";
pub const DEFAULT_UPDATE_INTERVAL: &str = "300s";
pub const DEFAULT_USERS_OU_NAME: &str = "users";
pub const DEFAULT_GROUPS_OU_NAME: &str = "groups";

pub const ENV_CONFIG_PATH: &str = "CONFIG_PATH";
pub const ENV_BACKEND: &str = "BACKEND";
pub const ENV_BASE_DN: &str = "BASE_DN";
pub const ENV_LISTEN_ADDR: &str = "LDAP_LISTEN_ADDR";
pub const ENV_UPDATE_INTERVAL: &str = "UPDATE_INTERVAL";

/// Values coming from command line flags.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Args {
    pub config: Option<PathBuf>,
    /// Present when the run is an export rather than a server.
    pub export_ldif: Option<PathBuf>,
    /// The same, in YAML instead of LDIF.
    pub export_yaml: Option<PathBuf>,
    pub export_operational: bool,
    /// Present when the run imports an LDIF file rather than serving.
    pub import_ldif: Option<PathBuf>,
    pub allow_existing_entry: bool,
    /// Present when the run only checks that the configuration would start.
    pub check_config: bool,
    /// Present when the run verifies the indexes against the data.
    pub check_index: bool,
    /// Present when the run commits the configuration as a new generation.
    pub config_commit: bool,
    /// Present when the run rolls back to a generation.
    pub config_rollback: Option<u64>,
    /// Present when the run lists the generations.
    pub config_history: bool,
    /// How many generations to keep when collecting.
    pub config_keep: Option<usize>,
    /// Why the generation was committed.
    pub note: Option<String>,
    /// The file to seed a generation from, instead of the one in force.
    pub from: Option<PathBuf>,
    /// Present when the run rebuilds the indexes and reports the cost.
    pub reindex: bool,
    pub backend: Option<String>,
    pub base_dn: Option<String>,
    pub listen_addr: Option<String>,
    pub interval: Option<String>,
    pub log_path: Option<PathBuf>,
    pub debug: bool,
}

/// The configuration document the settings were read from.
///
/// Kept verbatim, together with where it came from, because `cn=config` publishes the
/// document rather than an expansion of it: an operator reading the subtree sees the file that
/// is in force, and a later writer can change a value without inventing the 40 settings that
/// were only defaults.
///
impl ConfigError {
    /// The error as an operator should read it: in the configured language, or in English when the
    /// catalogue has no text for this variant.
    ///
    /// It lives on the error and not in `main` because it is the error's own business how it is
    /// described - and because a private function in a binary cannot be reached by a test.
    pub fn message(&self) -> String {
        let english = self.to_string();

        // The translated text borrows its arguments, so they are built first and kept alive
        // in `owned` until the call is done.
        let key: &str;
        let mut owned: Vec<(String, String)> = Vec::new();

        match self {
            Self::JournalKeep(detail) => {
                key = "config.journal_keep";
                owned.push(("detail".to_string(), detail.clone()));
            }
            Self::Sasl(detail) => {
                key = "config.sasl";
                owned.push(("detail".to_string(), detail.clone()));
            }
            Self::Peers(detail) => {
                key = "config.peers";
                owned.push(("detail".to_string(), detail.clone()));
            }
            Self::ServerId(detail) => {
                key = "config.server_id";
                owned.push(("detail".to_string(), detail.clone()));
            }
            Self::Referral(detail) => {
                key = "config.referral";
                owned.push(("detail".to_string(), detail.clone()));
            }
            Self::MissingTlsMaterial => key = "config.tls_material",
            Self::UnknownBackend { name, known } => {
                key = "config.unknown_backend";
                owned.push(("name".to_string(), name.clone()));
                owned.push(("known".to_string(), known.join(", ")));
            }
            Self::SchemaMode(value) => {
                key = "config.schema_mode";
                owned.push(("value".to_string(), value.clone()));
            }
            Self::Locale { value } => {
                key = "config.locale";
                owned.push(("value".to_string(), value.clone()));
                owned.push(("path".to_string(), format!("locale/{value}.yaml")));
            }
            Self::StoreEmpty { path } => {
                key = "config.store_empty";
                owned.push(("path".to_string(), path.display().to_string()));
            }
            Self::Store { path, detail } => {
                key = "config.store";
                owned.push(("path".to_string(), path.display().to_string()));
                owned.push(("detail".to_string(), detail.clone()));
            }
            Self::BootstrapPasswordMissing => {
                key = "config.bootstrap_password_missing";
            }
            Self::BootstrapPasswordAmbiguous => {
                key = "config.bootstrap_password_ambiguous";
            }
            Self::DangerousSettingsNotAcknowledged { settings } => {
                key = "config.dangerous";
                owned.push(("settings".to_string(), settings.clone()));
            }
            Self::PlainHttpNotAcknowledged { address } => {
                key = "config.plain_http";
                owned.push(("address".to_string(), address.clone()));
            }
            Self::SchemaRead { path, source } => {
                key = "config.schema_read";
                owned.push(("path".to_string(), path.clone()));
                owned.push(("detail".to_string(), source.to_string()));
            }
            Self::Schema { path, source } => {
                key = "config.schema";
                owned.push(("path".to_string(), path.clone()));
                owned.push(("detail".to_string(), source.to_string()));
            }
            Self::Interval { value, source } => {
                key = "config.interval";
                owned.push(("value".to_string(), value.clone()));
                owned.push(("detail".to_string(), source.to_string()));
            }
            Self::Parse { path, source } => {
                key = "config.parse";
                owned.push(("path".to_string(), path.display().to_string()));
                owned.push(("detail".to_string(), source.to_string()));
            }
            Self::Read { path, source } => {
                key = "config.parse";
                owned.push(("path".to_string(), path.display().to_string()));
                owned.push(("detail".to_string(), source.to_string()));
            }
            Self::Index(err) => {
                key = "config.index";
                owned.push(("detail".to_string(), err.to_string()));
            }
            Self::Password(err) => {
                key = "config.password";
                owned.push(("detail".to_string(), err.to_string()));
            }
            Self::Access(err) => {
                key = "config.access";
                owned.push(("detail".to_string(), err.to_string()));
            }
        }

        let args: Vec<(&str, &str)> = owned
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let translated = crate::i18n::t(key, &args);

        // `t` returns the key itself when the catalogue has no text for it. That is the one
        // case where the translated line is useless, and the English message is the answer.
        if translated == key {
            return english;
        }

        // Otherwise the translated line carries everything the English one did — including the
        // parser position or the file name, through `{detail}`. Two lines saying the same
        // thing in two languages is noise, not help.
        translated
    }
}

/// The text is attached by [`load`], the only place that knows both the text and its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// The document as written, byte for byte.
    pub text: String,
    /// Where it was read from, for the operator: `file:/etc/...` or `store:/etc/config.d`.
    pub origin: String,
    /// The generation store this document came from, when it came from one.
    ///
    /// A write through `cn=config` is a commit of a new generation, so it needs somewhere to
    /// commit to. Both facts travel together: a document read from a plain file has no store,
    /// and the write path then refuses rather than editing a file the operator owns.
    pub store: Option<PathBuf>,
}

impl Document {
    pub fn new(text: impl Into<String>, origin: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            origin: origin.into(),
            store: None,
        }
    }

    /// The same document, knowing which store it came from.
    pub fn with_store(mut self, store: Option<PathBuf>) -> Self {
        self.store = store;
        self
    }
}

/// Fully resolved server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub backend: String,
    pub base_dn: String,
    pub listen_addr: String,
    pub update_interval: Duration,
    pub log_path: Option<PathBuf>,
    pub debug: bool,
    pub log_timestamp: bool,
    pub log_caller: bool,
    pub backends: BTreeMap<String, serde_json::Value>,
    pub respect_control_criticality: bool,
    pub users_ou_name: String,
    pub groups_ou_name: String,
    pub use_tls: bool,
    pub server_cert: Option<PathBuf>,
    pub server_key: Option<PathBuf>,
    pub http_listen_addr: Option<String>,
    pub callback_auth_token: Option<String>,
    pub passwords: PasswordPolicy,
    pub schema: Schema,
    pub schema_mode: SchemaMode,
    /// The files the extra definitions were read from, kept so a reload can re-read them.
    ///
    /// The schema itself is a parsed value and cannot be re-derived from it: a reload needs
    /// the paths, not the result.
    pub schema_files: Vec<PathBuf>,
    pub indexes: IndexConfig,
    pub acl: Acl,
    /// Simple bind over an unencrypted connection.
    pub allow_unencrypted_bind: bool,
    /// Dangerous settings this configuration turned on, named for the startup banner.
    pub dangerous_settings: Vec<&'static str>,
    /// Uniqueness and referential integrity of account attributes.
    pub integrity: IntegrityConfig,
    /// Where the change journal goes, if anywhere.
    pub observability: ObservabilityConfig,
    /// The first administrator of an empty store, if the operator configured one.
    pub bootstrap: Option<BootstrapConfig>,
    /// Language for operator diagnostics, and where it came from.
    pub locale: (crate::i18n::Locale, crate::i18n::Source),
    /// Translation file, when one is configured.
    pub locale_file: Option<PathBuf>,
    /// This node's id, written into the change sequence number of every change it makes.
    ///
    /// Zero means "this node does not replicate": two nodes with the same id produce changes that
    /// cannot be told apart, and the order between them cannot be recovered afterwards. So zero is
    /// allowed only while the server has no peers.
    pub server_id: u16,
    /// Nodes this one replicates with.
    ///
    /// Empty means this node stands alone. Checked against the id at startup: a peer with this
    /// node's own id is refused, because the damage is permanent.
    pub peers: Vec<crate::peers::Peer>,
    /// How many change records this node keeps; `None` keeps everything.
    pub journal_keep: Option<usize>,
    /// Where conflicts with peers are recorded; `None` keeps them only on standard error.
    pub conflict_log: Option<PathBuf>,
    /// The `sasl:` section as written, with its realms already checked against the base.
    ///
    /// The keytab is not read here: a configuration is a value that can be compared, printed and
    /// copied, and key material is none of those things. `main` loads it once through
    /// [`crate::sasl::Gssapi::load`] and hands the acceptor to `Security`.
    pub sasl: crate::sasl::SaslConfig,
    /// Subtrees held elsewhere, and where a client is sent for them.
    ///
    /// Empty means the server answers `noSuchObject` for anything outside its own tree, which is
    /// what it did before this existed.
    pub referrals: crate::referral::Referrals,
    /// The configuration document the settings above were read from, if there was one.
    ///
    /// `cn=config` publishes this text, so a server started from flags alone has none and says
    /// so. It is the document, not the resolved settings: command-line and environment
    /// overrides are not part of it, exactly as `slapd.d` does not record `-h`.
    pub document: Option<Document>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("error reading config file '{path}': {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("error parsing config file '{path}': {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<serde_saphyr::Error>,
    },
    #[error("error parsing update interval '{value}': {source}")]
    Interval {
        value: String,
        #[source]
        source: humantime::DurationError,
    },
    #[error("invalid server id: {0}")]
    ServerId(String),
    #[error("invalid peers: {0}")]
    Peers(String),
    #[error("invalid sasl: {0}")]
    Sasl(String),
    #[error("invalid journal_keep: {0}")]
    JournalKeep(String),
    #[error("invalid referrals: {0}")]
    Referral(String),
    #[error("use_tls is enabled, but server_cert and server_key are not both set")]
    MissingTlsMaterial,
    #[error("unknown backend '{name}', known backends: {}", known.join(", "))]
    UnknownBackend {
        name: String,
        known: Vec<&'static str>,
    },
    #[error(transparent)]
    Password(#[from] PolicyError),
    #[error(transparent)]
    Access(#[from] AclError),
    #[error("error loading schema from '{path}': {source}")]
    Schema {
        path: String,
        #[source]
        source: SchemaError,
    },
    #[error("error reading schema file '{path}': {source}")]
    SchemaRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("unknown schema mode: {0}")]
    SchemaMode(String),
    #[error(
        "'{path}' is a configuration store but holds no generation yet; commit one with \
         --config-commit, or point at a configuration file instead"
    )]
    StoreEmpty { path: PathBuf },
    #[error("cannot read the configuration store '{path}': {detail}")]
    Store { path: PathBuf, detail: String },
    #[error("unknown language '{value}'")]
    Locale { value: String },
    #[error(
        "this configuration turns on {settings}, which weakens the server, but \
         AllowDangerousSettings is not set; add \
         AllowDangerousSettings: 'Yes I know this is bad idea' at the top level if that \
         is really what you want"
    )]
    DangerousSettingsNotAcknowledged { settings: String },
    #[error(
        "http_listen_addr is set to '{address}' but the callback listener speaks plain HTTP, \
         so its token travels in the clear; add AllowPlainHttpRest: \
         'Yes I know this is bad idea' next to it if that is acceptable"
    )]
    PlainHttpNotAcknowledged { address: String },
    #[error("error in the 'indexes' section: {0}")]
    Index(#[from] IndexError),
    #[error(
        "the 'bootstrap' section names no password: set password_file or password_env, \
         or remove the section"
    )]
    BootstrapPasswordMissing,
    #[error(
        "the 'bootstrap' section names both password_file and password_env; pick one, so \
         that where the first administrator's password comes from has one answer"
    )]
    BootstrapPasswordAmbiguous,
}

/// Subset of the configuration that lives in the YAML file.
#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    #[serde(default)]
    integrity: IntegrityConfig,
    /// Subtrees held elsewhere: `- dn: dc=remote,dc=com` with the URL a client should ask.
    #[serde(default)]
    referrals: Vec<ReferralConfig>,
    /// See [`Config::server_id`].
    server_id: Option<u16>,
    /// Nodes this one replicates with, if any.
    #[serde(default)]
    peers: Vec<crate::peers::PeerConfig>,
    /// How far behind a peer may fall.
    #[serde(default)]
    replication: ReplicationConfig,
    /// SASL, when this server proves identity by ticket rather than by password.
    #[serde(default)]
    sasl: crate::sasl::SaslConfig,
    #[serde(default)]
    observability: ObservabilityConfig,
    /// Language for operator-facing diagnostics: `ru`, `en`. Empty means "ask the
    /// environment". Client-visible protocol text is always English.
    locale: Option<String>,
    /// Translation file for that language; `locale/<tag>.yaml` by default.
    locale_file: Option<PathBuf>,
    /// Master acknowledgement: this configuration contains settings that weaken the
    /// server, and the operator knows it.
    ///
    /// Every dangerous setting also has to carry its own sentence, so this is a second
    /// lock, not a substitute: the master one says "I read the config", the specific one
    /// says "I meant this particular line". A config that copies a hardening list from
    /// the documentation has neither.
    #[serde(
        default,
        rename = "AllowDangerousSettings",
        alias = "allow_dangerous_settings"
    )]
    allow_dangerous_settings: Danger,
    /// How often the directory is re-read from the backend, when the file says.
    ///
    /// Accepted from the file as well as from `-i` and the environment: a setting that a
    /// configuration document publishes over `cn=config` has to be a setting the document can
    /// actually carry, or the subtree would offer a knob that does nothing.
    #[serde(default, alias = "interval")]
    update_interval: Option<String>,
    #[serde(default)]
    log_timestamp: bool,
    #[serde(default)]
    log_caller: bool,
    /// Which backend to serve from, on which address, and for which naming context.
    ///
    /// The command line and the environment come first; these are the third source, so a
    /// unit file need not repeat flag by flag what the configuration already says. A flag
    /// still wins, because a one-off run against another backend must not require editing
    /// a file.
    backend: Option<String>,
    base_dn: Option<String>,
    listen_addr: Option<String>,
    #[serde(default)]
    backends: BTreeMap<String, serde_json::Value>,
    #[serde(default = "default_respect_control_criticality")]
    respect_control_criticality: bool,
    users_ou_name: Option<String>,
    groups_ou_name: Option<String>,
    #[serde(default)]
    use_tls: bool,
    server_cert: Option<PathBuf>,
    server_key: Option<PathBuf>,
    http_listen_addr: Option<String>,
    /// The callback listener speaks plain HTTP, so its token travels in the clear.
    #[serde(
        default,
        rename = "AllowPlainHttpRest",
        alias = "allow_plain_http_rest"
    )]
    allow_plain_http_rest: Danger,
    callback_auth_token: Option<String>,
    passwords: Option<PasswordConfig>,
    #[serde(default)]
    access: Option<Vec<AccessRuleConfig>>,
    #[serde(default)]
    bind: BindConfig,
    bootstrap: Option<BootstrapConfig>,
    #[serde(default)]
    schema: SchemaConfig,
    #[serde(default)]
    indexes: IndexConfig,
}

/// `schema:` section of the configuration file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SchemaConfig {
    /// `strict` (default), `warn` or `off`.
    pub mode: Option<String>,
    /// Extra `.schema` files, read after the built-in definitions.
    pub files: Vec<PathBuf>,
}

/// One `referrals:` entry: a subtree this server does not hold, and where it lives.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReferralConfig {
    /// The DN of the subtree, for example `dc=remote,dc=com`.
    pub dn: String,
    /// An `ldap://` or `ldaps://` URL a client should ask instead.
    pub url: String,
}

/// `replication:` section of the configuration file.
///
/// Nothing here is needed to serve a directory: it bounds how far behind a peer may fall before it
/// is refused, which is a decision about storage, not about the protocol.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ReplicationConfig {
    /// How many change records to keep.
    ///
    /// The journal is the only place a deletion is remembered. Pruning it is therefore not
    /// housekeeping: a peer whose cookie points before the oldest record left has lost deletions
    /// nobody will ever send it, and the surviving records say nothing about the gap. `None` keeps
    /// everything, which is the honest default for a node whose peers have been down for a long
    /// time - and a slow leak for a node nobody reads.
    pub journal_keep: Option<usize>,
    /// Where disagreements with peers are written down, one JSON object per line.
    ///
    /// Without it a conflict is printed to standard error and forgotten: after a restart there is
    /// no record that two nodes ever disagreed, and the entry that lost is simply missing. An
    /// operator resolving a divergence needs the list, not a line in a stream.
    pub conflict_log: Option<PathBuf>,
}

/// `observability:` section of the configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ObservabilityConfig {
    /// Path of the change journal. Absent means no journal.
    ///
    /// One JSON object per line: the change, the DN, the actor and the result, so "who
    /// removed that entry" has an answer after the entry is gone.
    pub journal: Option<PathBuf>,
    /// Write the journal to standard output instead of a file, for a container that
    /// collects it.
    pub journal_stdout: bool,
    /// How large the journal may grow before it is rotated, in bytes.
    ///
    /// Absent means `JOURNAL_MAX_BYTES` (64 MiB). There was a default of *unlimited*, which is
    /// not a default but a delayed outage: a directory that is written to fills the disk at a
    /// rate nobody watches, and the first symptom is every write failing for a reason that has
    /// nothing to do with the directory.
    pub journal_max_bytes: Option<u64>,
}

/// `bootstrap:` section of the configuration file.
///
/// The first administrator, for a store no client can write to yet. It carries where the
/// password comes from, not the password: a `Config` is printed at startup and derived
/// `Debug`, and a secret that lives in it would end up in a log line the operator never
/// looks at.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct BootstrapConfig {
    /// The DN to create; `cn=admin,ou=<users unit>,<base DN>` when absent.
    pub dn: Option<String>,
    /// A file holding the password, read once at startup.
    ///
    /// The file is not the command line: arguments are visible in `ps` to every user on
    /// the machine, and a password there is a password given away.
    pub password_file: Option<PathBuf>,
    /// An environment variable holding the password, for a container secret.
    pub password_env: Option<String>,
}

/// `bind:` section of the configuration file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct BindConfig {
    /// Allow a simple bind over an unencrypted connection.
    ///
    /// Off by default: a password sent in the clear is readable by anyone on the path,
    /// and Samba refuses it for the same reason. Turning it on takes the sentence from
    /// `crate::danger`, not a boolean, because this is the setting most likely to be
    /// copied between configurations without a thought.
    #[serde(
        default,
        rename = "AllowUnencryptedBind",
        alias = "allow_unencrypted_bind",
        alias = "allow_plaintext_simple"
    )]
    pub allow_unencrypted_bind: Danger,
}

fn default_respect_control_criticality() -> bool {
    true
}

/// Reads the config file (when given) and resolves the whole configuration.
pub fn load(args: Args) -> Result<Config, ConfigError> {
    let explicit = args.config.clone();
    let from_env = std::env::var_os(ENV_CONFIG_PATH).map(PathBuf::from);
    let (text, origin, store) = match explicit.or(from_env).as_deref() {
        // A directory is a generation store: the configuration in force is the generation its
        // pointer names. A file is a configuration. The two cannot be confused, so no new key
        // is needed to say which - and pointing at the wrong one gets a message, not a parse
        // error about a directory.
        Some(path) if crate::config_store::Store::is_store(path) => {
            let store = crate::config_store::Store::open(path);
            match store.read_current() {
                Ok(Some(text)) => {
                    // The generation number belongs in the origin: "which of the ten
                    // generations am I running" is the first question after a rollback, and
                    // the directory name alone does not answer it.
                    let number = store
                        .current()
                        .ok()
                        .flatten()
                        .map(|generation| generation.number.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    (
                        Some(text),
                        format!("store:{} generation {number}", path.display()),
                        Some(path.to_path_buf()),
                    )
                }
                Ok(None) => {
                    return Err(ConfigError::StoreEmpty {
                        path: path.to_path_buf(),
                    });
                }
                Err(err) => {
                    return Err(ConfigError::Store {
                        path: path.to_path_buf(),
                        detail: err.to_string(),
                    });
                }
            }
        }
        Some(path) => (
            Some(read_file(path)?),
            format!("file:{}", path.display()),
            None,
        ),
        // Flags and defaults only: there is no document, and `cn=config` says so rather than
        // publishing an empty subtree that looks the same as a server with no settings.
        None => (None, String::new(), None),
    };

    let mut config = resolve(args, text.as_deref(), |name| std::env::var(name).ok())?;

    // The origin is known here and nowhere else: `resolve` sees the text without knowing where
    // it came from.
    if let Some(document) = config.document.as_mut() {
        document.origin = origin;
        document.store = store;
    }

    Ok(config)
}

fn read_file(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })
}

/// Resolves the configuration from the three sources; the environment is passed
/// as a closure so tests never touch the process environment.
pub fn resolve(
    args: Args,
    file_text: Option<&str>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Config, ConfigError> {
    let file: FileConfig = match file_text {
        Some(text) => serde_saphyr::from_str(text).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("<config>"),
            source: Box::new(source),
        })?,
        None => FileConfig {
            respect_control_criticality: default_respect_control_criticality(),
            ..FileConfig::default()
        },
    };

    let interval_text = pick(
        args.interval,
        env(ENV_UPDATE_INTERVAL),
        file.update_interval,
    )
    .unwrap_or_else(|| DEFAULT_UPDATE_INTERVAL.to_string());
    let update_interval =
        humantime::parse_duration(&interval_text).map_err(|source| ConfigError::Interval {
            value: interval_text.clone(),
            source,
        })?;

    let users_ou_name = file
        .users_ou_name
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_USERS_OU_NAME.to_string())
        .trim()
        .to_lowercase();
    let groups_ou_name = file
        .groups_ou_name
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_GROUPS_OU_NAME.to_string())
        .trim()
        .to_lowercase();

    let backend = pick(args.backend, env(ENV_BACKEND), file.backend)
        .unwrap_or_else(|| DEFAULT_BACKEND.to_string());

    // Known before the server opens a socket, not after: a configuration that names a backend
    // this build does not have cannot start, and a document committed through `cn=config` has
    // to be a configuration the server could start from. Without this the check happened in
    // `Backend::from_config`, which is later than the promise.
    if !crate::backend::KNOWN_BACKENDS.contains(&backend.as_str()) {
        return Err(ConfigError::UnknownBackend {
            name: backend,
            known: crate::backend::KNOWN_BACKENDS.to_vec(),
        });
    }

    let referrals = crate::referral::Referrals::new(
        file.referrals
            .iter()
            .map(|entry| crate::referral::Referral {
                dn: super::dn::normalize(&entry.dn),
                url: entry.url.clone(),
            })
            .collect(),
    )
    .map_err(|err| ConfigError::Referral(err.to_string()))?;

    // Resolved once, because the SASL realm table is checked against it: a template that points
    // outside the naming context has to be caught at startup, and it needs the same base the
    // server will serve.
    let base_dn = super::dn::normalize(
        &pick(args.base_dn, env(ENV_BASE_DN), file.base_dn)
            .unwrap_or_else(|| DEFAULT_BASE_DN.to_string()),
    );

    let config = Config {
        backend,
        base_dn: base_dn.clone(),
        listen_addr: pick(args.listen_addr, env(ENV_LISTEN_ADDR), file.listen_addr)
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string()),
        update_interval,
        log_path: args.log_path,
        debug: args.debug,
        log_timestamp: file.log_timestamp,
        log_caller: file.log_caller,
        backends: file.backends,
        respect_control_criticality: file.respect_control_criticality,
        users_ou_name,
        groups_ou_name,
        use_tls: file.use_tls,
        server_cert: file.server_cert,
        server_key: file.server_key,
        integrity: file.integrity,
        observability: file.observability,
        locale: {
            // The configuration wins over the host: an operator who wrote `locale: ru`
            // wants Russian even on an English machine.
            match file.locale.as_deref().filter(|tag| !tag.trim().is_empty()) {
                Some(tag) => {
                    let locale =
                        crate::i18n::Locale::parse(tag).ok_or_else(|| ConfigError::Locale {
                            value: tag.to_string(),
                        })?;
                    (locale, crate::i18n::Source::Config)
                }
                // The same environment the rest of the configuration reads, so a test
                // and a server resolve the language by the same rule.
                None => crate::i18n::from_env(&env),
            }
        },
        locale_file: file.locale_file,
        // The text as it was read. `load` fills in where it came from, which `resolve` cannot
        // know: it is handed the text, not the path.
        document: file_text.map(|text| Document::new(text, String::new())),
        dangerous_settings: {
            let mut enabled: Vec<&'static str> = Vec::new();
            if file.bind.allow_unencrypted_bind.is_on() {
                enabled.push("bind.AllowUnencryptedBind");
            }
            if file.allow_plain_http_rest.is_on() {
                enabled.push("AllowPlainHttpRest");
            }
            if file
                .passwords
                .as_ref()
                .is_some_and(|passwords| !passwords.requested_weak().is_empty())
            {
                enabled.push("passwords.AllowedWeakHashes");
            }

            // Both locks, and the master one is checked over the whole file: a
            // dangerous line that was pasted in without its sentence has already
            // failed to parse, and one that carries a sentence without the master
            // acknowledgement fails here.
            if !enabled.is_empty() && !file.allow_dangerous_settings.is_on() {
                return Err(ConfigError::DangerousSettingsNotAcknowledged {
                    settings: enabled.join(", "),
                });
            }

            enabled
        },
        http_listen_addr: {
            let addr = file.http_listen_addr.filter(|addr| !addr.trim().is_empty());

            // The callback listener has no TLS: the token that authorises a reload
            // would travel in the clear on every request. Enabling it is a decision
            // the operator has to write down, not a line to leave in a copied config.
            if addr.is_some() && !file.allow_plain_http_rest.is_on() {
                return Err(ConfigError::PlainHttpNotAcknowledged {
                    address: addr.clone().unwrap_or_default(),
                });
            }

            addr
        },
        callback_auth_token: file.callback_auth_token,
        passwords: PasswordPolicy::from_config(file.passwords.as_ref())?,
        schema: load_schema(&file.schema)?,
        schema_files: file.schema.files.clone(),
        schema_mode: match file.schema.mode.as_deref() {
            None => SchemaMode::Strict,
            Some(text) => text
                .parse()
                .map_err(|err: String| ConfigError::SchemaMode(err))?,
        },
        // Resolved here so a misspelled index kind fails at startup, not on the
        // first search that would have used it.
        indexes: {
            file.indexes.resolve()?;
            file.indexes
        },
        // A peer and this node must be distinguishable, or the history cannot be untangled: two
        // changes from the same id at the same microsecond look like the same change, and the
        // merge that follows is a coin toss dressed as an order. Checked at startup because the
        // damage is permanent.
        server_id: match file.server_id.unwrap_or(0) {
            0 => 0,
            value => crate::replication::ServerId::new(value)
                .map(|id| id.value())
                .map_err(|err| ConfigError::ServerId(err.to_string()))?,
        },
        peers: crate::peers::from_config(&file.peers, file.server_id.unwrap_or(0))
            .map_err(|err| ConfigError::Peers(err.to_string()))?,
        // Zero is not "keep none" - that would throw away the only record of every deletion while
        // the peers are still behind. It is a mistake in the file, and it fails here.
        journal_keep: match file.replication.journal_keep {
            Some(0) => {
                return Err(ConfigError::JournalKeep(
                    "journal_keep: 0 would discard every change record, including the only \
                     record that a deletion ever happened; omit the key to keep everything"
                        .to_string(),
                ));
            }
            other => other,
        },
        conflict_log: file.replication.conflict_log.clone(),
        sasl: {
            crate::sasl::Gssapi::validate(&file.sasl, &base_dn)
                .map_err(|err| ConfigError::Sasl(err.to_string()))?;
            file.sasl
        },
        referrals,
        acl: crate::acl::from_config(file.access.as_deref())?,
        allow_unencrypted_bind: file.bind.allow_unencrypted_bind.is_on(),
        bootstrap: match file.bootstrap {
            None => None,
            Some(section) => {
                // Exactly one source of the password. Neither is a section that does
                // nothing; both is a section whose answer depends on which line the
                // reader believes, and the two can disagree.
                match (&section.password_file, &section.password_env) {
                    (None, None) => return Err(ConfigError::BootstrapPasswordMissing),
                    (Some(_), Some(_)) => return Err(ConfigError::BootstrapPasswordAmbiguous),
                    (Some(_), None) => Some(section),
                    (None, Some(name)) if name.trim().is_empty() => {
                        return Err(ConfigError::BootstrapPasswordMissing);
                    }
                    (None, Some(_)) => Some(section),
                }
            }
        },
    };

    if config.use_tls && (config.server_cert.is_none() || config.server_key.is_none()) {
        return Err(ConfigError::MissingTlsMaterial);
    }

    Ok(config)
}

/// Builds the schema: built-in definitions first, then every configured file.
fn load_schema(config: &SchemaConfig) -> Result<Schema, ConfigError> {
    let mut schema = Schema::core();

    for path in &config.files {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::SchemaRead {
            path: path.display().to_string(),
            source,
        })?;
        schema.extend(&text).map_err(|source| ConfigError::Schema {
            path: path.display().to_string(),
            source,
        })?;
    }

    Ok(schema)
}

fn pick(cli: Option<String>, env: Option<String>, file: Option<String>) -> Option<String> {
    [cli, env, file]
        .into_iter()
        .flatten()
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn defaults_apply_without_any_source() {
        let cfg = resolve(Args::default(), None, no_env).expect("defaults");

        assert_eq!(
            cfg.backend, "null",
            "the default has to be a backend this build has"
        );
        assert_eq!(cfg.base_dn, "dc=example,dc=com");
        assert_eq!(cfg.listen_addr, "0.0.0.0:389");
        assert_eq!(cfg.update_interval, Duration::from_secs(300));
        assert_eq!(cfg.users_ou_name, "users");
        assert_eq!(cfg.groups_ou_name, "groups");
        assert!(cfg.respect_control_criticality);
        assert!(!cfg.use_tls);
        assert_eq!(cfg.http_listen_addr, None);
    }

    #[test]
    fn environment_beats_defaults() {
        let env = env_of(&[
            (ENV_BACKEND, "file"),
            (ENV_LISTEN_ADDR, "127.0.0.1:1389"),
            (ENV_UPDATE_INTERVAL, "45s"),
        ]);

        let cfg = resolve(Args::default(), None, env).expect("env config");

        assert_eq!(cfg.backend, "file");
        assert_eq!(cfg.listen_addr, "127.0.0.1:1389");
        assert_eq!(cfg.update_interval, Duration::from_secs(45));
    }

    #[test]
    fn command_line_beats_environment() {
        let args = Args {
            backend: Some("null".to_string()),
            listen_addr: Some("0.0.0.0:2389".to_string()),
            ..Args::default()
        };
        let env = env_of(&[(ENV_BACKEND, "file"), (ENV_LISTEN_ADDR, "127.0.0.1:1389")]);

        let cfg = resolve(args, None, env).expect("cli config");

        assert_eq!(cfg.backend, "null");
        assert_eq!(cfg.listen_addr, "0.0.0.0:2389");
    }

    #[test]
    fn file_values_are_used_when_no_flag_or_variable_is_set() {
        let text = r#"
users_ou_name: People
groups_ou_name: Teams
respect_control_criticality: false
AllowDangerousSettings: "Yes I know this is bad idea"
AllowPlainHttpRest: "Yes I know this is bad idea"
http_listen_addr: localhost:8080
callback_auth_token: secret
use_tls: true
server_cert: server.crt
server_key: server.key
backends:
  file:
    users_path: examples/file/users.json
"#;

        let cfg = resolve(Args::default(), Some(text), no_env).expect("file config");

        assert_eq!(cfg.users_ou_name, "people");
        assert_eq!(cfg.groups_ou_name, "teams");
        assert!(!cfg.respect_control_criticality);
        assert_eq!(cfg.http_listen_addr.as_deref(), Some("localhost:8080"));
        assert_eq!(cfg.callback_auth_token.as_deref(), Some("secret"));
        assert!(cfg.use_tls);
        assert_eq!(cfg.server_cert.as_deref(), Some(Path::new("server.crt")));
        assert!(cfg.backends.contains_key("file"));
    }

    #[test]
    fn empty_environment_value_does_not_override_defaults() {
        let env = env_of(&[(ENV_BACKEND, "   ")]);

        let cfg = resolve(Args::default(), None, env).expect("env config");

        assert_eq!(cfg.backend, "null");
    }

    #[test]
    fn the_backend_can_come_from_the_file_and_the_command_line_wins() {
        // The unit file runs the binary with no flags at all: what is served has to be
        // readable from the configuration. A flag still overrides it, because a one-off
        // run against another backend must not require editing a file.
        let text = "
backend: redb
backends:
  redb:
    path: /var/lib/rust-rest-ldap/directory.redb
";

        let cfg = resolve(Args::default(), Some(text), no_env).expect("file config");
        assert_eq!(cfg.backend, "redb");

        let args = Args {
            backend: Some("null".to_string()),
            ..Args::default()
        };
        let cfg = resolve(args, Some(text), no_env).expect("cli config");
        assert_eq!(cfg.backend, "null");
    }

    #[test]
    fn the_naming_context_and_the_address_can_come_from_the_file() {
        // Without this a unit file has to carry `-B` and `-L`, which means the same fact
        // lives in two places and drifts: the address is edited in the configuration and
        // the service keeps listening where the flag says.
        let text = "
base_dn: DC=Test, DC=Example, DC=Com
listen_addr: 127.0.0.1:1389
";

        let cfg = resolve(Args::default(), Some(text), no_env).expect("file config");
        assert_eq!(cfg.base_dn, "dc=test,dc=example,dc=com");
        assert_eq!(cfg.listen_addr, "127.0.0.1:1389");

        // The flag still decides, and it is normalized the same way.
        let args = Args {
            listen_addr: Some("127.0.0.1:2389".to_string()),
            ..Args::default()
        };
        let cfg = resolve(args, Some(text), no_env).expect("cli config");
        assert_eq!(cfg.listen_addr, "127.0.0.1:2389");
    }

    #[test]
    fn a_bootstrap_section_without_a_password_source_is_refused() {
        // A section that does nothing looks like it did something: the operator believes
        // the administrator exists and finds out at the first bind that it does not.
        let text = "
bootstrap:
  dn: cn=admin,ou=users,dc=example,dc=com
";

        let err = resolve(Args::default(), Some(text), no_env).expect_err("must reject");
        assert!(
            matches!(err, ConfigError::BootstrapPasswordMissing),
            "{err}"
        );
    }

    #[test]
    fn a_conflict_log_is_read_from_the_file() {
        let text =
            "base_dn: dc=example,dc=com\nreplication:\n  conflict_log: /var/log/conflicts.jsonl\n";
        let cfg = resolve(Args::default(), Some(text), no_env).expect("config");
        assert_eq!(
            cfg.conflict_log.as_deref(),
            Some(std::path::Path::new("/var/log/conflicts.jsonl"))
        );
    }

    #[test]
    fn without_a_conflict_log_a_conflict_is_only_printed() {
        let cfg = resolve(Args::default(), None, no_env).expect("defaults");
        assert_eq!(cfg.conflict_log, None);
    }

    #[test]
    fn a_journal_keep_is_read_from_the_file() {
        let text = "base_dn: dc=example,dc=com\nreplication:\n  journal_keep: 5000\n";
        let cfg = resolve(Args::default(), Some(text), no_env).expect("config");
        assert_eq!(cfg.journal_keep, Some(5000));
    }

    #[test]
    fn an_unconfigured_journal_keeps_everything() {
        // `None` and not a number: a node whose peers have been down for a long time needs the
        // deletions it would otherwise have thrown away, and the operator has not said otherwise.
        let cfg = resolve(Args::default(), None, no_env).expect("defaults");
        assert_eq!(cfg.journal_keep, None);
    }

    #[test]
    fn a_journal_keep_of_zero_is_refused_at_startup() {
        // Not "keep none": the journal is the only record that a deletion ever happened, so zero
        // would make every peer wrong the moment one goes down. It is a mistake in the file, and
        // it fails here rather than at the first silent divergence.
        let text = "base_dn: dc=example,dc=com\nreplication:\n  journal_keep: 0\n";
        let err = resolve(Args::default(), Some(text), no_env).expect_err("must reject");
        assert!(matches!(err, ConfigError::JournalKeep(_)), "{err}");
    }

    #[test]
    fn a_server_id_is_read_from_the_file() {
        let text = "base_dn: dc=example,dc=com\nserver_id: 4\n";
        let cfg = resolve(Args::default(), Some(text), no_env).expect("config");
        assert_eq!(cfg.server_id, 4);
    }

    #[test]
    fn an_unconfigured_server_has_no_id() {
        // Zero is not a missing value to be defaulted to one: it says "this node does not
        // replicate", and a node that invented an id would collide with a peer's.
        let cfg = resolve(Args::default(), None, no_env).expect("defaults");
        assert_eq!(cfg.server_id, 0);
    }

    #[test]
    fn a_server_id_out_of_range_fails_at_startup() {
        // The CSN carries it in three digits. A value that cannot be written is refused here
        // rather than truncated into somebody else's id later.
        let text = "base_dn: dc=example,dc=com\nserver_id: 1000\n";
        let err = resolve(Args::default(), Some(text), no_env).expect_err("must reject");
        assert!(matches!(err, ConfigError::ServerId(_)), "{err}");
    }

    #[test]
    fn a_bootstrap_section_with_two_password_sources_is_refused() {
        // Two sources that disagree have no answer, and the one the reader believes is
        // whichever line they happened to look at first.
        let text = "
bootstrap:
  password_file: /etc/rrl/password.txt
  password_env: RRL_BOOTSTRAP_PASSWORD
";

        let err = resolve(Args::default(), Some(text), no_env).expect_err("must reject");
        assert!(
            matches!(err, ConfigError::BootstrapPasswordAmbiguous),
            "{err}"
        );
    }

    #[test]
    fn an_empty_variable_name_is_not_a_password_source() {
        let text = "
bootstrap:
  password_env: '   '
";

        let err = resolve(Args::default(), Some(text), no_env).expect_err("must reject");
        assert!(
            matches!(err, ConfigError::BootstrapPasswordMissing),
            "{err}"
        );
    }

    #[test]
    fn a_bootstrap_section_with_one_source_resolves() {
        let text = "
bootstrap:
  dn: cn=root,ou=users,dc=example,dc=com
  password_env: RRL_BOOTSTRAP_PASSWORD
";

        let cfg = resolve(Args::default(), Some(text), no_env).expect("config");
        let section = cfg.bootstrap.expect("the section must survive resolution");

        assert_eq!(
            section.dn.as_deref(),
            Some("cn=root,ou=users,dc=example,dc=com")
        );
        assert_eq!(
            section.password_env.as_deref(),
            Some("RRL_BOOTSTRAP_PASSWORD")
        );
        assert!(section.password_file.is_none());
    }

    #[test]
    fn no_bootstrap_section_means_no_bootstrap() {
        let cfg = resolve(Args::default(), None, no_env).expect("defaults");
        assert!(cfg.bootstrap.is_none());
    }

    #[test]
    fn base_dn_is_normalized() {
        let args = Args {
            base_dn: Some("DC=Test, dc=EXAMPLE,  dc=com".to_string()),
            ..Args::default()
        };

        let cfg = resolve(args, None, no_env).expect("config");

        assert_eq!(cfg.base_dn, "dc=test,dc=example,dc=com");
    }

    #[test]
    fn the_file_sets_the_update_interval_too() {
        // It used to be accepted only from `-i` and the environment, and silently ignored in the
        // file - which `cn=config` then published as a setting that changed nothing.
        let cfg =
            resolve(Args::default(), Some("update_interval: 45s\n"), |_| None).expect("config");
        assert_eq!(cfg.update_interval, Duration::from_secs(45));
    }

    #[test]
    fn the_environment_still_wins_over_the_file_for_the_interval() {
        let cfg = resolve(Args::default(), Some("update_interval: 45s\n"), |name| {
            (name == ENV_UPDATE_INTERVAL).then(|| "90s".to_string())
        })
        .expect("config");
        assert_eq!(cfg.update_interval, Duration::from_secs(90));
    }

    #[test]
    fn invalid_interval_is_rejected_with_the_offending_value() {
        let args = Args {
            interval: Some("300 seconds later".to_string()),
            ..Args::default()
        };

        let err = resolve(args, None, no_env).expect_err("must reject interval");

        assert_eq!(
            err.to_string(),
            "error parsing update interval '300 seconds later': expected number at 12"
        );
    }

    #[test]
    fn tls_without_material_is_rejected() {
        let text = "
use_tls: true
server_cert: server.crt
";

        let err = resolve(Args::default(), Some(text), no_env).expect_err("must reject tls config");

        assert_eq!(
            err.to_string(),
            "use_tls is enabled, but server_cert and server_key are not both set"
        );
    }

    #[test]
    fn repository_config_file_parses() {
        let text = std::fs::read_to_string("config.yaml").expect("config.yaml");

        let cfg = resolve(
            Args {
                config: Some(PathBuf::from("config.yaml")),
                ..Args::default()
            },
            Some(&text),
            no_env,
        )
        .expect("repository config");

        assert_eq!(cfg.users_ou_name, "users");
        assert_eq!(cfg.groups_ou_name, "groups");
        assert_eq!(cfg.http_listen_addr.as_deref(), Some("localhost:8080"));
        assert!(cfg.backends.contains_key("file"));
        assert!(cfg.backends.contains_key("redb"));
        assert!(
            cfg.backends.contains_key("rest"),
            "the shipped example documents all three backends"
        );
        assert!(!cfg.use_tls);
    }

    #[test]
    fn broken_config_file_is_rejected_with_path() {
        let err = resolve(Args::default(), Some("backends: [unclosed"), no_env)
            .expect_err("must reject broken yaml");

        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "unexpected {err:?}"
        );
    }
}
