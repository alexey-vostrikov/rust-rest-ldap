//! Backends: where the directory data comes from and where changes go.
//!
//! gorestldap loaded backends as Go plugins (`-buildmode=plugin`), which tied the
//! binary to an exact toolchain and made a broken plugin a runtime surprise.
//! Here the backends are part of the binary and are selected by name from the
//! configuration; an unknown name is a startup error listing what exists.

use crate::backend::redb_store::Compaction;
use crate::directory::Directory;
use crate::model::{Entry, Group, User};
use thiserror::Error;

pub mod file;
pub mod http;
pub mod null;
pub mod redb_store;
pub mod rest;

pub use file::FileBackend;
pub use null::NullBackend;
pub use redb_store::RedbBackend;
pub use rest::RestBackend;

/// Directory payload as the backends hand it over.
///
/// Two shapes, because two kinds of backend exist: the JSON backends know about
/// users and groups as separate lists, and the entry store keeps whole entries.
/// Whichever is filled, the directory is built from it — the LDAP layer never sees
/// the difference.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectoryData {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub entries: Vec<Entry>,
}

impl DirectoryData {
    /// Builds the directory this payload describes.
    pub fn into_directory(
        self,
        base_dn: &str,
        users_ou_name: &str,
        groups_ou_name: &str,
    ) -> Directory {
        if self.entries.is_empty() {
            Directory::new(
                base_dn,
                users_ou_name,
                groups_ou_name,
                self.users,
                self.groups,
            )
        } else {
            Directory::from_entries(base_dn, users_ou_name, groups_ou_name, self.entries)
        }
    }
}

/// Whether an entry is a user or a group, for backends that keep them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    User,
    Group,
}

/// A change the server asks the backend to persist.
///
/// gorestldap passed two `interface{}` values and found the entry by deep
/// equality; the variants here make the same operation type-checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryChange {
    User {
        old: Box<User>,
        new: Box<User>,
    },
    Group {
        old: Box<Group>,
        new: Box<Group>,
    },
    /// Write the entry as it is, whatever its attributes.
    Upsert {
        entry: Entry,
    },
    Delete {
        dn: String,
        /// What kind of object the DN named, when the caller knows.
        ///
        /// The DN alone is not enough for a backend whose store has separate collections: its
        /// parent OU says "users" or "groups" in *this server's* naming, which the backend is
        /// not told. `None` means the caller did not know - the redb store does not care, and
        /// the REST backend refuses rather than guessing a collection and deleting a
        /// same-named object of the other kind.
        kind: Option<ObjectKind>,
    },
}

impl EntryChange {
    /// A delete, with the kind of object it removes.
    pub fn delete(dn: impl Into<String>, kind: Option<ObjectKind>) -> Self {
        EntryChange::Delete {
            dn: dn.into(),
            kind,
        }
    }

    /// Names the variant, for error messages that must say what was refused.
    pub fn kind(&self) -> &'static str {
        match self {
            EntryChange::User { .. } => "user change",
            EntryChange::Group { .. } => "group change",
            EntryChange::Upsert { .. } => "entry upsert",
            EntryChange::Delete { .. } => "entry delete",
        }
    }
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("unknown backend '{name}', known backends: {}", known.join(", "))]
    UnknownBackend {
        name: String,
        known: Vec<&'static str>,
    },
    #[error("backend '{name}' has no configuration section")]
    MissingConfig { name: String },
    #[error("invalid backend configuration: {0}")]
    InvalidConfig(String),
    #[error("error reading '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("error writing '{path}': {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("error parsing '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("error serializing data for '{path}': {source}")]
    Serialize {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("entry not found in backend data")]
    EntryNotFound,
    #[error("updating data is not supported by this backend")]
    UpdateNotSupported,
    #[error("redb error on '{path}': {reason}")]
    Redb { path: String, reason: String },
    #[error("the REST service at '{url}' did not answer: {detail}")]
    Rest { url: String, detail: String },
    #[error("error building indexes: {0}")]
    Index(#[from] crate::index::IndexError),
    #[error("data does not match the schema ({count} problems), first ones: {}", first.join("; "))]
    SchemaViolations { count: usize, first: Vec<String> },
    #[error("cannot read the schema file '{path}': {source}")]
    SchemaRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the schema file '{path}' is not valid: {detail}")]
    SchemaParse { path: String, detail: String },
    #[error("definition {position} added through cn=schema,cn=config is not usable: {detail}")]
    SchemaDefinition { position: usize, detail: String },
}

/// A schema that could not be built, as a backend error.
///
/// The reload rebuilds the schema from the same three sources startup reads, so it reports the
/// same three kinds of failure; only the vocabulary of the caller differs.
impl From<crate::schema::SchemaSource> for BackendError {
    fn from(err: crate::schema::SchemaSource) -> Self {
        use crate::schema::SchemaSource as Source;
        match err {
            Source::Read { path, source } => BackendError::SchemaRead { path, source },
            Source::Parse { path, source } => BackendError::SchemaParse {
                path,
                detail: source.to_string(),
            },
            Source::Definition { position, source } => BackendError::SchemaDefinition {
                position,
                detail: source.to_string(),
            },
        }
    }
}

/// Selected backend.
#[derive(Debug, Clone)]
pub enum Backend {
    File(FileBackend),
    Null(NullBackend),
    Redb(RedbBackend),
    Rest(RestBackend),
}

impl Backend {
    /// Whether this backend can store a whole entry, attributes and all.
    ///
    /// Seeding needs this and not merely durability: the administrator it writes is an entry
    /// with a password hash, and the backends with a fixed user/group model - `file` and
    /// `rest` - have nowhere to put it. The REST backend does keep what it writes, in somebody
    /// else's service; that is a different property, and asking this one is what keeps the
    /// refusal honest.
    pub fn stores_entries(&self) -> bool {
        matches!(self, Backend::Redb(_))
    }

    /// The name this backend is configured under.
    /// Journal records after `csn`, oldest first.
    ///
    /// Only the entry store keeps a journal: the JSON backends have no place to write one beside
    /// their data, and REST is somebody else's service. An empty answer from them means "no
    /// history here", which is true and is what a replica has to be told rather than a full
    /// resync it did not need.
    pub fn journal_since(
        &self,
        csn: Option<&str>,
    ) -> Result<Vec<crate::backend::redb_store::ChangeRecord>, BackendError> {
        match self {
            Backend::Redb(backend) => backend.journal_since(csn),
            _ => Ok(Vec::new()),
        }
    }

    /// Rewrites the store, dropping pages nothing points at any more.
    ///
    /// Only a store of its own can do this: a JSON document is rewritten whole on every change,
    /// and the REST backend's storage is not ours to reorganise. For those the answer is
    /// `None` - "nothing to do here" - rather than an error, because an operator running it
    /// against the wrong backend has not made a mistake worth failing on.
    pub fn compact(&mut self) -> Result<Option<Compaction>, BackendError> {
        match self {
            Backend::Redb(backend) => Ok(Some(backend.compact()?)),
            _ => Ok(None),
        }
    }

    /// The stored search index, if this backend keeps one.
    ///
    /// `None` for every backend that does not, and for a store that has never written one: the
    /// caller builds the index, which is always correct.
    pub fn load_index(&self) -> Result<Option<(Vec<u8>, u64)>, BackendError> {
        match self {
            Backend::Redb(backend) => backend.load_index(),
            _ => Ok(None),
        }
    }

    /// The store's change counter, or zero for a backend that has none.
    pub fn sequence(&self) -> Result<u64, BackendError> {
        match self {
            Backend::Redb(backend) => backend.sequence(),
            _ => Ok(0),
        }
    }

    /// Records one change set's posting changes for the next start.
    pub fn append_index_delta(&self, sequence: u64, bytes: &[u8]) -> Result<(), BackendError> {
        match self {
            Backend::Redb(backend) => backend.append_index_delta(sequence, bytes),
            _ => Ok(()),
        }
    }

    /// The deltas between two counter values, or `None` when the chain has a hole.
    pub fn index_deltas(
        &self,
        after: u64,
        until: u64,
    ) -> Result<Option<Vec<Vec<u8>>>, BackendError> {
        match self {
            Backend::Redb(backend) => backend.index_deltas(after, until),
            _ => Ok(Some(Vec::new())),
        }
    }

    /// Stores the search index, for a backend that can keep it.
    ///
    /// A backend that cannot is not an error: the index is derived, and building it is what every
    /// backend did before this existed.
    pub fn save_index(&self, bytes: &[u8], sequence: u64) -> Result<(), BackendError> {
        match self {
            Backend::Redb(backend) => backend.save_index(bytes, sequence),
            _ => Ok(()),
        }
    }

    /// Forgets the stored index after a change it cannot describe.
    pub fn clear_index(&self) -> Result<(), BackendError> {
        match self {
            Backend::Redb(backend) => backend.clear_index(),
            _ => Ok(()),
        }
    }

    /// The oldest journal CSN still remembered; a resume older than this has lost changes.
    pub fn journal_floor(&self) -> Result<Option<String>, BackendError> {
        match self {
            Backend::Redb(backend) => backend.journal_floor(),
            _ => Ok(None),
        }
    }

    /// The newest journal CSN, if this backend keeps one.
    pub fn journal_head(&self) -> Result<Option<String>, BackendError> {
        match self {
            Backend::Redb(backend) => backend.journal_head(),
            _ => Ok(None),
        }
    }

    /// Trims the journal to its newest `keep` records.
    pub fn journal_prune(&self, keep: usize) -> Result<usize, BackendError> {
        match self {
            Backend::Redb(backend) => backend.journal_prune(keep),
            _ => Ok(0),
        }
    }

    /// Drops change records stamped before `cutoff`.
    pub fn journal_prune_before(
        &self,
        cutoff: std::time::SystemTime,
    ) -> Result<usize, BackendError> {
        match self {
            Backend::Redb(backend) => backend.journal_prune_before(cutoff),
            _ => Ok(0),
        }
    }

    /// Whether this backend can store a whole entry as an upsert.
    ///
    /// Not the same question as `keeps_entries_verbatim`: the REST backend maps an entry onto
    /// its user or group object, so what it stores is not the entry - but it does accept the
    /// write. The file backend refuses an entry outright: its document has fixed fields, and a
    /// whole entry has nowhere to go.
    ///
    /// A caller that writes without a client waiting for an answer - the password-hash upgrade
    /// after a successful bind is the only one - asks this first, rather than attempting a write
    /// it already knows will be refused.
    pub fn accepts_entry_upserts(&self) -> bool {
        !matches!(self, Backend::File(_) | Backend::Null(_))
    }

    /// Whether an accepted change is in the store exactly as it was handed over.
    ///
    /// True for the redb store, which writes the entry as one key and reads it back unchanged.
    /// False for the file backend (a fixed user/group document, rewritten whole), for REST (the
    /// remote service decides what it keeps) and for null (nothing is kept).
    ///
    /// The reload path does not need this: it reads the store back, so it is right whatever the
    /// store did. The incremental write path does - it patches memory with the entry it sent,
    /// which is only honest when the store kept that entry as given.
    pub fn keeps_entries_verbatim(&self) -> bool {
        matches!(self, Backend::Redb(_))
    }

    pub fn name(&self) -> &'static str {
        match self {
            Backend::File(_) => "file",
            Backend::Null(_) => "null",
            Backend::Redb(_) => "redb",
            Backend::Rest(_) => "rest",
        }
    }

    /// Builds the backend named in the configuration.
    pub fn from_config(
        name: &str,
        config: Option<&serde_json::Value>,
    ) -> Result<Self, BackendError> {
        match name {
            "file" => {
                let config = config.ok_or_else(|| BackendError::MissingConfig {
                    name: name.to_string(),
                })?;
                Ok(Backend::File(FileBackend::from_config(config)?))
            }
            "null" => Ok(Backend::Null(NullBackend)),
            "rest" => {
                let config = config.ok_or_else(|| BackendError::MissingConfig {
                    name: name.to_string(),
                })?;
                Ok(Backend::Rest(RestBackend::from_config(config)?))
            }
            "redb" => {
                let config = config.ok_or_else(|| BackendError::MissingConfig {
                    name: name.to_string(),
                })?;
                Ok(Backend::Redb(RedbBackend::from_config(config)?))
            }
            _ => Err(BackendError::UnknownBackend {
                name: name.to_string(),
                known: KNOWN_BACKENDS.to_vec(),
            }),
        }
    }

    pub async fn load(&self) -> Result<DirectoryData, BackendError> {
        match self {
            Backend::File(backend) => backend.load(),
            Backend::Null(backend) => backend.load(),
            Backend::Redb(backend) => backend.directory_data(),
            Backend::Rest(backend) => backend.load().await,
        }
    }

    pub async fn update(&self, change: &EntryChange) -> Result<(), BackendError> {
        match self {
            Backend::File(backend) => backend.update(change),
            Backend::Null(backend) => backend.update(change),
            Backend::Redb(backend) => backend.apply(std::slice::from_ref(change)),
            Backend::Rest(backend) => backend.update(change).await,
        }
    }

    /// Applies a change set atomically where the backend can.
    ///
    /// The entry store commits all changes or none; the JSON backends apply them one
    /// by one, which is why they are not the right choice for data that matters.
    pub async fn apply(&self, changes: &[EntryChange]) -> Result<(), BackendError> {
        match self {
            Backend::File(backend) => {
                for change in changes {
                    backend.update(change)?;
                }
                Ok(())
            }
            Backend::Null(backend) => backend.update(&changes[0]),
            Backend::Redb(backend) => backend.apply(changes),
            Backend::Rest(backend) => {
                // One request per object: HTTP has no change set, and the service's own
                // transaction boundaries are the service's.
                for change in changes {
                    backend.update(change).await?;
                }
                Ok(())
            }
        }
    }
}

/// Backends compiled into the binary, in the order they are reported.
pub const KNOWN_BACKENDS: [&str; 4] = ["file", "null", "redb", "rest"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_backend_lists_the_known_ones() {
        let err = Backend::from_config("postgres", None).expect_err("must reject");

        assert_eq!(
            err.to_string(),
            "unknown backend 'postgres', known backends: file, null, redb, rest"
        );
    }

    #[test]
    fn file_backend_requires_a_config_section() {
        let err = Backend::from_config("file", None).expect_err("must reject");

        assert_eq!(
            err.to_string(),
            "backend 'file' has no configuration section"
        );
    }

    #[test]
    fn null_backend_needs_no_configuration() {
        let backend = Backend::from_config("null", None).expect("null backend");

        assert!(matches!(backend, Backend::Null(_)));
    }

    #[tokio::test]
    async fn null_backend_is_empty_and_read_only() {
        let backend = Backend::from_config("null", None).expect("null backend");

        let data = backend.load().await.expect("load");
        assert!(data.users.is_empty());
        assert!(data.groups.is_empty());

        let change = EntryChange::User {
            old: Box::default(),
            new: Box::default(),
        };
        let err = backend
            .update(&change)
            .await
            .expect_err("null backend must not update");
        assert_eq!(
            err.to_string(),
            "updating data is not supported by this backend"
        );
    }
}
