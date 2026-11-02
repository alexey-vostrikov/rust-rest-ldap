//! Backends: where the directory data comes from and where changes go.
//!
//! gorestldap loaded backends as Go plugins (`-buildmode=plugin`), which tied the
//! binary to an exact toolchain and made a broken plugin a runtime surprise.
//! Here the backends are part of the binary and are selected by name from the
//! configuration; an unknown name is a startup error listing what exists.

use crate::model::{Group, User};
use thiserror::Error;

pub mod file;
pub mod null;

pub use file::FileBackend;
pub use null::NullBackend;

/// Directory payload as the backends hand it over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectoryData {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
}

/// A change the server asks the backend to persist.
///
/// gorestldap passed two `interface{}` values and found the entry by deep
/// equality; the variants here make the same operation type-checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryChange {
    User { old: Box<User>, new: Box<User> },
    Group { old: Box<Group>, new: Box<Group> },
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
}

/// Selected backend.
#[derive(Debug, Clone)]
pub enum Backend {
    File(FileBackend),
    Null(NullBackend),
}

impl Backend {
    /// Builds the backend named in the configuration.
    pub fn from_config(
        name: &str,
        config: Option<&serde_yaml_ng::Value>,
    ) -> Result<Self, BackendError> {
        match name {
            "file" => {
                let config = config.ok_or_else(|| BackendError::MissingConfig {
                    name: name.to_string(),
                })?;
                Ok(Backend::File(FileBackend::from_config(config)?))
            }
            "null" => Ok(Backend::Null(NullBackend)),
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
        }
    }

    pub async fn update(&self, change: &EntryChange) -> Result<(), BackendError> {
        match self {
            Backend::File(backend) => backend.update(change),
            Backend::Null(backend) => backend.update(change),
        }
    }
}

/// Backends compiled into the binary, in the order they are reported.
pub const KNOWN_BACKENDS: [&str; 2] = ["file", "null"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_backend_lists_the_known_ones() {
        let err = Backend::from_config("postgres", None).expect_err("must reject");

        assert_eq!(
            err.to_string(),
            "unknown backend 'postgres', known backends: file, null"
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
