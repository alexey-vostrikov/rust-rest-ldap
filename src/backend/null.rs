//! `null` backend: an empty, read-only directory.
//!
//! Useful to bring the server up without data (health checks, protocol probes).

use super::{BackendError, DirectoryData, EntryChange};

#[derive(Debug, Clone, Default)]
pub struct NullBackend;

impl NullBackend {
    pub fn load(&self) -> Result<DirectoryData, BackendError> {
        Ok(DirectoryData::default())
    }

    pub fn update(&self, _change: &EntryChange) -> Result<(), BackendError> {
        Err(BackendError::UpdateNotSupported)
    }
}
