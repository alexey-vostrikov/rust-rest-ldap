//! Backends: where the directory data comes from and where changes go.
//!
//! gorestldap loaded backends as Go plugins (`-buildmode=plugin`), which tied the
//! binary to an exact toolchain and made a broken plugin a runtime surprise.
//! Here the backends are part of the binary and are selected by name from the
//! configuration; an unknown name is a startup error listing what exists.

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
    },
}

impl EntryChange {
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
