//! The change journal: what a replica asks for to catch up.
//!
//! Its own trait rather than part of [`super::store::CatalogStore`], because the two are wanted by
//! different services. `rrl-ldap` serves entries and does not care that a journal exists; `rrl-sync`
//! exists to tail it. A store that answered both would make every server carry the replication
//! machinery, which is the coupling this split is meant to remove.
//!
//! The entries themselves and the journal do belong together - a change and the record of it are one
//! transaction, or a replica can miss a write that the store acknowledges - so both traits are
//! implemented by the same object today and may be served by the same process tomorrow.

use crate::backend::{Backend, BackendError, redb_store::ChangeRecord};

/// The journal a replica reads.
pub trait Journal: Send + Sync + std::fmt::Debug {
    /// Changes after `csn`, oldest first. `None` is "from the beginning".
    fn journal_since(&self, csn: Option<&str>) -> Result<Vec<ChangeRecord>, BackendError>;

    /// The oldest change still kept, or `None` when the journal is empty.
    ///
    /// A replica resuming from before this has missed changes it cannot recover, and the floor is
    /// what lets it say so instead of silently starting from what is left.
    fn journal_floor(&self) -> Result<Option<String>, BackendError>;

    /// The newest change written.
    fn journal_head(&self) -> Result<Option<String>, BackendError>;

    /// Keeps the newest `keep` changes, and says how many were dropped.
    fn journal_prune(&self, keep: usize) -> Result<usize, BackendError>;

    /// Drops changes older than `cutoff`, and says how many were dropped.
    fn journal_prune_before(&self, cutoff: std::time::SystemTime) -> Result<usize, BackendError>;
}

impl Journal for Backend {
    fn journal_since(&self, csn: Option<&str>) -> Result<Vec<ChangeRecord>, BackendError> {
        Backend::journal_since(self, csn)
    }

    fn journal_floor(&self) -> Result<Option<String>, BackendError> {
        Backend::journal_floor(self)
    }

    fn journal_head(&self) -> Result<Option<String>, BackendError> {
        Backend::journal_head(self)
    }

    fn journal_prune(&self, keep: usize) -> Result<usize, BackendError> {
        Backend::journal_prune(self, keep)
    }

    fn journal_prune_before(&self, cutoff: std::time::SystemTime) -> Result<usize, BackendError> {
        Backend::journal_prune_before(self, cutoff)
    }
}
