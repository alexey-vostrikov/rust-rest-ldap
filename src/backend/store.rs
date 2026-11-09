//! What the directory needs from whatever stores it.
//!
//! Until now `Source` held an `Arc<Backend>` - a concrete enum with four variants - and called its
//! inherent methods. That works while the store is in the same process and stops working the moment
//! it is not: a client for another process is not a `Backend`, and every call site would have to
//! learn a second type.
//!
//! So the operations `Source` actually performs are written down here as one trait. `Backend`
//! implements it by delegating, which is what keeps this step invisible to the tests: the same
//! object, the same behaviour, one indirection. When the store moves into its own process, the only
//! new implementation is a gRPC client, and nothing above this line changes.
//!
//! # What is not here, and why
//!
//! The index and its snapshot files. `append_index_delta`, `save_index`, `open_index` are the
//! directory's own artefact - a paged bitmap it rebuilds from the entries - and they are not
//! something a *store* has an opinion about. Keeping them off this trait is what stops the boundary
//! from quietly moving into the storage service: a `CatalogStore` that had to serve an index would
//! be a store that knows how searches work.
//!
//! # Async without `async-trait`
//!
//! Two of these are async, and `dyn Trait` with `async fn` is not object safe. Rather than take a
//! dependency for the macro, they return a boxed future: one allocation per load, per apply, against
//! a call that reads a store or writes a transaction. The alternative - making everything a concrete
//! type again - is the thing this file exists to undo.

use std::pin::Pin;

use crate::backend::{Backend, BackendError, DirectoryData, EntryChange};
use crate::model::Entry;

/// A boxed future, so that the trait stays object safe.
pub type BoxFuture<'a, T> =
    Pin<Box<dyn std::future::Future<Output = Result<T, BackendError>> + Send + 'a>>;

/// The directory's storage, as the layer above it needs it.
pub trait CatalogStore: Send + Sync + std::fmt::Debug {
    /// Every entry the store holds, in the shape the backends hand over.
    fn load(&self) -> BoxFuture<'_, DirectoryData>;

    /// Applies a change set and says how many entries it touched, when the store can say so.
    ///
    /// `None` is a store that applied the change and does not count; the file and REST backends are
    /// like that, and a caller that needs a count reloads.
    fn apply<'a>(&'a self, changes: &'a [EntryChange]) -> BoxFuture<'a, Option<u64>>;

    /// One entry by DN, when the store can answer without reading all of them.
    fn entry(&self, dn: &str) -> Option<Entry>;

    /// How many entries there are, when the store knows without counting them.
    fn entry_count(&self) -> Option<u64>;

    /// The backend's name, for a diagnostic that has to say where the data came from.
    fn name(&self) -> &'static str;

    /// Whether whole entries can be written - not merely whether they persist.
    fn stores_entries(&self) -> bool;

    /// Whether an entry written is an entry read back unchanged, which is what lets a write patch the
    /// snapshot in place instead of reloading.
    fn keeps_entries_verbatim(&self) -> bool;

    /// Whether a whole-entry upsert is accepted, which is what a password upgrade needs.
    fn accepts_entry_upserts(&self) -> bool;

    /// A value the server keeps about itself, or `None`.
    fn meta_get(&self, key: &str) -> Result<Option<Vec<u8>>, BackendError>;

    /// Records a value about the server itself.
    fn meta_set(&self, key: &str, value: &[u8]) -> Result<(), BackendError>;

    /// Whether the store can keep such a value at all.
    fn keeps_meta(&self) -> bool;
}

impl CatalogStore for Backend {
    fn load(&self) -> BoxFuture<'_, DirectoryData> {
        Box::pin(async move { Backend::load(self).await })
    }

    fn apply<'a>(&'a self, changes: &'a [EntryChange]) -> BoxFuture<'a, Option<u64>> {
        Box::pin(async move { Backend::apply(self, changes).await })
    }

    fn entry(&self, dn: &str) -> Option<Entry> {
        Backend::entry(self, dn)
    }

    fn entry_count(&self) -> Option<u64> {
        Backend::entry_count(self)
    }

    fn name(&self) -> &'static str {
        Backend::name(self)
    }

    fn stores_entries(&self) -> bool {
        Backend::stores_entries(self)
    }

    fn keeps_entries_verbatim(&self) -> bool {
        Backend::keeps_entries_verbatim(self)
    }

    fn accepts_entry_upserts(&self) -> bool {
        Backend::accepts_entry_upserts(self)
    }

    fn meta_get(&self, key: &str) -> Result<Option<Vec<u8>>, BackendError> {
        Backend::meta_get(self, key)
    }

    fn meta_set(&self, key: &str, value: &[u8]) -> Result<(), BackendError> {
        Backend::meta_set(self, key, value)
    }

    fn keeps_meta(&self) -> bool {
        Backend::keeps_meta(self)
    }
}
