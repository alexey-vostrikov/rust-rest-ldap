//! The index as an artefact: the paged bitmaps written beside the store.
//!
//! Deliberately not part of [`super::store::CatalogStore`]. An index is the directory's own working
//! copy - it is rebuilt from the entries and means nothing to a store - so a storage service that
//! had to serve it would be a store that knows how searches work. Keeping the two apart is what lets
//! `rrl-domaindb` own entries and the journal while `rrl-ldap` owns what it built from them.
//!
//! The methods mirror `Backend`'s, which is the point: this step changes a type, not behaviour.

use crate::backend::{Backend, BackendError};

/// Where the index snapshot and its deltas live.
pub trait IndexStorage: Send + Sync + std::fmt::Debug {
    /// The stored snapshot and the change counter it reflects.
    fn load_index(&self) -> Result<Option<(Vec<u8>, u64)>, BackendError>;

    /// Stores the snapshot, replacing any previous one.
    fn save_index(&self, bytes: &[u8], sequence: u64) -> Result<(), BackendError>;

    /// Appends a delta since the last snapshot.
    fn append_index_delta(&self, sequence: u64, bytes: &[u8]) -> Result<(), BackendError>;

    /// How many bytes the deltas after `sequence` hold.
    fn index_delta_bytes(&self, after: u64) -> Result<u64, BackendError>;

    /// The deltas in `after..until`, oldest first; `None` when the store keeps none.
    fn index_deltas(&self, after: u64, until: u64) -> Result<Option<Vec<Vec<u8>>>, BackendError>;

    /// Drops every delta, which a fresh snapshot makes unnecessary.
    fn clear_index(&self) -> Result<(), BackendError>;
}

impl IndexStorage for Backend {
    fn load_index(&self) -> Result<Option<(Vec<u8>, u64)>, BackendError> {
        Backend::load_index(self)
    }

    fn save_index(&self, bytes: &[u8], sequence: u64) -> Result<(), BackendError> {
        Backend::save_index(self, bytes, sequence)
    }

    fn append_index_delta(&self, sequence: u64, bytes: &[u8]) -> Result<(), BackendError> {
        Backend::append_index_delta(self, sequence, bytes)
    }

    fn index_delta_bytes(&self, after: u64) -> Result<u64, BackendError> {
        Backend::index_delta_bytes(self, after)
    }

    fn index_deltas(&self, after: u64, until: u64) -> Result<Option<Vec<Vec<u8>>>, BackendError> {
        Backend::index_deltas(self, after, until)
    }

    fn clear_index(&self) -> Result<(), BackendError> {
        Backend::clear_index(self)
    }
}
