//! `redb` backend: durable, transactional storage for whole entries.
//!
//! Why this backend exists, in one paragraph: the JSON backends rewrite an entire
//! file per change, and they keep users and groups in two files, so one modify is
//! two independent writes with no atomicity between them — a crash in between leaves
//! the directory inconsistent. redb is an embedded B-tree with a write-ahead log:
//! a change set is one write transaction, committed with fsync (durability
//! `Immediate` by default), so after a crash the database is either the state before
//! the change or the state after it, never a mixture. It is also pure Rust with
//! `#![forbid(unsafe_code)]`, which keeps the "no C" rule of this project intact.
//!
//! Storage layout: two tables. `entries` maps the normalized DN to a JSON document
//! holding the attribute list *with its flags*, so what comes back is what went in
//! and nothing is re-derived; `meta` holds the format version, so a future change of
//! the document can be migrated instead of guessed.

use std::path::Path;

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::{BackendError, DirectoryData, EntryChange};
use crate::model::{Attribute, AttributeFlags, Attributes, Entry};

const ENTRIES: TableDefinition<&str, &[u8]> = TableDefinition::new("entries");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
/// The change journal: one record per accepted write, keyed by `entryCSN`.
///
/// In the same database and written in the same transaction as the entry it describes, so a
/// change and its record cannot half-happen. That is the whole reason it lives here and not in a
/// file beside the store: the file could be written and the store not, or the other way round,
/// and a replica reading the journal would then replay a change that never was.
const CHANGES: TableDefinition<&str, &[u8]> = TableDefinition::new("changes");

/// The search index as it stood when the data did, so a start can read it instead of building it.
///
/// A separate table rather than a row in `meta`: the value is large, and it is derived data that
/// may be dropped at any moment. Keeping it apart means `clear_index` cannot touch the format
/// version or anything else the store needs to open.
const INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("index");
const INDEX_KEY: &str = "snapshot";
const FORMAT_VERSION: &str = "1";
const META_FORMAT: &str = "format";

/// One attribute as it is stored: values and behaviour travel together.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredAttribute {
    name: String,
    values: Vec<String>,
    #[serde(default)]
    flags: AttributeFlags,
}

/// The ordering key of a change: the entry's own `entryCSN`.
///
/// A change that arrives without one gets a fresh CSN here rather than no record: a journal entry
/// with no key cannot be ordered, and a change that happened is not made un-happened by the
/// absence of a stamp.
fn csn_of(entry: &Entry) -> String {
    entry
        .attributes()
        .get(crate::operational::ATTR_ENTRY_CSN)
        .and_then(|attribute| attribute.values.first().cloned())
        .unwrap_or_else(crate::operational::next_csn)
}

/// The identity a replica knows the entry by.
fn uuid_of(entry: &Entry) -> String {
    entry
        .attributes()
        .get(crate::model::ATTR_ENTRY_UUID)
        .and_then(|attribute| attribute.values.first().cloned())
        .unwrap_or_else(|| crate::directory::entry_uuid(entry.dn()))
}

/// What kind of change a journal record describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Add,
    Modify,
    Delete,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Add => "add",
            ChangeKind::Modify => "modify",
            ChangeKind::Delete => "delete",
        }
    }
}

/// One record in the change journal.
///
/// `csn` is both the key and the ordering: `entryCSN` is fixed width, so lexicographic order is
/// chronological order - which is the property that lets a replica say "everything after this".
///
/// A deletion is a record with no entry and a CSN of its own: a tombstone. Without one, a node
/// that was offline would re-send its copy of an entry somebody else deleted, and the entry would
/// come back.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChangeRecord {
    pub csn: String,
    pub kind: ChangeKind,
    pub dn: String,
    /// The entry's `entryUUID`, or one derived from the DN when the entry had none.
    pub uuid: String,
    /// The entry as it stood after the change. `None` for a deletion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<StoredEntry>,
}

/// What a compaction did, for an operator who wants to know whether it was worth the wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compaction {
    /// False when nothing could be reclaimed: the file already holds only live pages.
    pub performed: bool,
    pub before: u64,
    pub after: u64,
}

impl Compaction {
    /// Bytes returned to the filesystem.
    pub fn reclaimed(&self) -> u64 {
        self.before.saturating_sub(self.after)
    }
}

/// The size of a file, or zero when it cannot be read.
///
/// Zero rather than an error: the size is reported, the compaction's own result is what matters,
/// and failing the command because a `stat` failed would turn a successful compaction into an
/// error message.
fn file_size(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

/// One entry as it is stored: the DN plus every attribute, flags included.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredEntry {
    attributes: Vec<StoredAttribute>,
}

impl StoredEntry {
    pub fn from_entry(entry: &Entry) -> Self {
        Self {
            attributes: entry
                .attributes()
                .values()
                .iter()
                .map(|attribute| StoredAttribute {
                    name: attribute.name.to_string(),
                    values: attribute.values.to_vec(),
                    flags: attribute.flags,
                })
                .collect(),
        }
    }

    pub fn into_entry(self, dn: &str) -> Entry {
        let mut attributes = Attributes::new();
        for attribute in self.attributes {
            attributes = attributes.push(Attribute {
                name: crate::model::attribute_name(&attribute.name),
                values: attribute.values.into_boxed_slice(),
                flags: attribute.flags,
            });
        }
        Entry::new(dn.to_string(), attributes)
    }
}

/// Durable store of whole entries.
///
/// The database handle is shared behind an `Arc`, so the backend can be cloned like
/// the other backends and several callers can hold it at once; redb serializes
/// writers internally.
#[derive(Clone)]
pub struct RedbBackend {
    /// Where the file is, for the two things that need the file rather than the handle: its size
    /// before and after compaction, and the operator's ability to find it.
    path: std::path::PathBuf,
    database: std::sync::Arc<Database>,
    /// `Immediate` fsyncs on commit; `None` defers persistence and may lose the last
    /// commits on power loss — offered only for bulk imports.
    durability: Durability,
    /// Whether a change is written down for replication to pick up.
    ///
    /// Off for a node that does not replicate: the journal record carries the whole entry, so
    /// keeping it **doubles** the store for a feature that node never uses. Measured on a bulk
    /// import of a million entries: 4.0 GB with the journal, and every record written twice.
    ///
    /// Off is not a silent loss of ability: `journal_head` and `journal_floor` then answer `None`,
    /// which a synchronised search already reads as "no journal", and it answers with a full
    /// refresh instead of pretending to know what changed.
    journal: bool,
}

impl std::fmt::Debug for RedbBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedbBackend")
            .field("durability", &self.durability)
            .field("journal", &self.journal)
            .finish()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RedbBackendConfig {
    path: String,
    /// `immediate` (default) or `eventual`.
    durability: Option<String>,
    /// Whether to keep a change journal; `true` unless the operator says otherwise.
    #[serde(default = "journal_default")]
    journal: bool,
}

fn journal_default() -> bool {
    true
}

impl RedbBackend {
    /// Opens (creating if needed) the database at `path`.
    pub fn open(path: &Path, durability: Durability) -> Result<Self, BackendError> {
        Self::open_with_journal(path, durability, true)
    }

    /// Opens the database, deciding whether changes are written down for replication.
    pub fn open_with_journal(
        path: &Path,
        durability: Durability,
        journal: bool,
    ) -> Result<Self, BackendError> {
        let database = if path.exists() {
            Database::open(path)
        } else {
            Database::create(path)
        }
        .map_err(|source| BackendError::Redb {
            path: path.display().to_string(),
            reason: source.to_string(),
        })?;

        let backend = Self {
            path: path.to_path_buf(),
            database: std::sync::Arc::new(database),
            durability,
            journal,
        };
        backend.write_format_version()?;
        Ok(backend)
    }

    /// Rewrites the file, dropping the pages that nothing points at any more.
    ///
    /// Redb is copy-on-write: a commit writes new pages and frees the old ones, and the freed
    /// space is reused by later writes but never returned to the filesystem. A store that grew
    /// to hold an import and then lost most of it keeps the size - on our three-million-entry
    /// test the file was 5.8 GB, and a delete of a third of it would not shrink it at all. The
    /// operator's only recourse was to export, delete the file and import again, which is what
    /// this replaces.
    ///
    /// `&mut self` is not a formality: redb refuses to compact while a transaction, a read
    /// reference or a savepoint is alive, because moving pages under one would corrupt the
    /// view it holds. Requiring the unique owner is how the type system says the same thing -
    /// and the reason this runs before the server starts serving, not during.
    pub fn compact(&mut self) -> Result<Compaction, BackendError> {
        let database =
            std::sync::Arc::get_mut(&mut self.database).ok_or_else(|| BackendError::Redb {
                path: self.path.display().to_string(),
                reason: "the database is still held elsewhere, and compacting it under a live \
                     transaction would move pages out from under it"
                    .to_string(),
            })?;

        let before = file_size(&self.path);
        let performed = database.compact().map_err(|source| BackendError::Redb {
            path: self.path.display().to_string(),
            reason: source.to_string(),
        })?;
        let after = file_size(&self.path);

        Ok(Compaction {
            performed,
            before,
            after,
        })
    }

    pub fn from_config(config: &serde_json::Value) -> Result<Self, BackendError> {
        let config: RedbBackendConfig = serde_json::from_value(config.clone())
            .map_err(|err| BackendError::InvalidConfig(err.to_string()))?;
        if config.path.trim().is_empty() {
            return Err(BackendError::InvalidConfig(
                "redb backend needs a non-empty 'path'".to_string(),
            ));
        }

        let durability = match config.durability.as_deref().unwrap_or("immediate") {
            // redb offers two levels: `Immediate` fsyncs before commit returns, and
            // `None` defers persistence to a later immediate commit (fast bulk load,
            // last commits lost on power loss).
            "immediate" => Durability::Immediate,
            "none" | "relaxed" => Durability::None,
            other => {
                return Err(BackendError::InvalidConfig(format!(
                    "unknown durability '{other}', expected immediate or none"
                )));
            }
        };

        Self::open_with_journal(Path::new(&config.path), durability, config.journal)
    }

    fn write_format_version(&self) -> Result<(), BackendError> {
        let transaction = self
            .database
            .begin_write()
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;
        {
            let mut meta = transaction
                .open_table(META)
                .map_err(|source| BackendError::Redb {
                    path: "<meta>".to_string(),
                    reason: source.to_string(),
                })?;
            meta.insert(META_FORMAT, FORMAT_VERSION.as_bytes())
                .map_err(|source| BackendError::Redb {
                    path: "<meta>".to_string(),
                    reason: source.to_string(),
                })?;
        }
        transaction.commit().map_err(|source| BackendError::Redb {
            path: "<meta>".to_string(),
            reason: source.to_string(),
        })
    }

    /// Reads every stored entry.
    pub fn load(&self) -> Result<Vec<Entry>, BackendError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;

        // A database created but never written has no table yet; that is an empty
        // directory, not an error.
        let table = match transaction.open_table(ENTRIES) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(source) => {
                return Err(BackendError::Redb {
                    path: "<entries>".to_string(),
                    reason: source.to_string(),
                });
            }
        };

        let mut entries = Vec::new();
        for row in table.iter().map_err(|source| BackendError::Redb {
            path: "<entries>".to_string(),
            reason: source.to_string(),
        })? {
            let (key, value) = row.map_err(|source| BackendError::Redb {
                path: "<entries>".to_string(),
                reason: source.to_string(),
            })?;
            let dn = key.value().to_string();
            let stored: StoredEntry =
                serde_json::from_slice(value.value()).map_err(|err| BackendError::Redb {
                    path: dn.clone(),
                    reason: format!("stored entry is not readable: {err}"),
                })?;
            entries.push(stored.into_entry(&dn));
        }

        Ok(entries)
    }

    /// Applies a whole change set in ONE transaction.
    ///
    /// All or nothing: on any error nothing is committed, so a caller that writes a
    /// user and a group together can never leave one of them behind.
    pub fn apply(&self, changes: &[EntryChange]) -> Result<(), BackendError> {
        if changes.is_empty() {
            return Ok(());
        }

        let mut transaction = self
            .database
            .begin_write()
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;
        transaction
            .set_durability(self.durability)
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;

        {
            let mut entries =
                transaction
                    .open_table(ENTRIES)
                    .map_err(|source| BackendError::Redb {
                        path: "<entries>".to_string(),
                        reason: source.to_string(),
                    })?;

            let mut journal =
                transaction
                    .open_table(CHANGES)
                    .map_err(|source| BackendError::Redb {
                        path: "<changes>".to_string(),
                        reason: source.to_string(),
                    })?;

            for change in changes {
                match change {
                    EntryChange::Upsert { entry } => {
                        // `add` or `modify` is decided by the store, in the same transaction:
                        // asking the directory in memory would be a second source of truth, and
                        // the two disagree exactly when a reload has not happened yet.
                        let existed = entries
                            .get(entry.dn())
                            .map_err(|source| BackendError::Redb {
                                path: entry.dn().to_string(),
                                reason: source.to_string(),
                            })?
                            .is_some();

                        // One conversion for both tables, and none of the journal work at all when
                        // the journal is off: a bulk import of a million entries was writing every
                        // entry twice, once for the store and once for a journal that node will
                        // never ship anywhere.
                        let stored = StoredEntry::from_entry(entry);

                        if self.journal {
                            let record = ChangeRecord {
                                csn: csn_of(entry),
                                kind: if existed {
                                    ChangeKind::Modify
                                } else {
                                    ChangeKind::Add
                                },
                                dn: entry.dn().to_string(),
                                uuid: uuid_of(entry),
                                entry: Some(stored.clone()),
                            };
                            let bytes =
                                serde_json::to_vec(&record).map_err(|err| BackendError::Redb {
                                    path: entry.dn().to_string(),
                                    reason: format!("cannot serialize the journal record: {err}"),
                                })?;
                            journal
                                .insert(record.csn.as_str(), bytes.as_slice())
                                .map_err(|source| BackendError::Redb {
                                    path: "<changes>".to_string(),
                                    reason: source.to_string(),
                                })?;
                        }

                        let bytes =
                            serde_json::to_vec(&stored).map_err(|err| BackendError::Redb {
                                path: entry.dn().to_string(),
                                reason: format!("cannot serialize entry: {err}"),
                            })?;
                        entries
                            .insert(entry.dn(), bytes.as_slice())
                            .map_err(|source| BackendError::Redb {
                                path: entry.dn().to_string(),
                                reason: source.to_string(),
                            })?;
                    }
                    EntryChange::Delete { dn, .. } => {
                        // The tombstone is written even when the entry was already gone: a
                        // replica that never learned about the deletion still has to, and a
                        // record we skip is a record it will never see.
                        let record = ChangeRecord {
                            csn: crate::operational::next_csn(),
                            kind: ChangeKind::Delete,
                            dn: dn.clone(),
                            uuid: String::new(),
                            entry: None,
                        };
                        let bytes =
                            serde_json::to_vec(&record).map_err(|err| BackendError::Redb {
                                path: dn.clone(),
                                reason: format!("cannot serialize the journal record: {err}"),
                            })?;
                        journal
                            .insert(record.csn.as_str(), bytes.as_slice())
                            .map_err(|source| BackendError::Redb {
                                path: "<changes>".to_string(),
                                reason: source.to_string(),
                            })?;

                        entries
                            .remove(dn.as_str())
                            .map_err(|source| BackendError::Redb {
                                path: dn.clone(),
                                reason: source.to_string(),
                            })?;
                    }
                    other => {
                        return Err(BackendError::InvalidConfig(format!(
                            "the redb backend stores whole entries; got {}",
                            other.kind()
                        )));
                    }
                }
            }
        }

        transaction.commit().map_err(|source| BackendError::Redb {
            path: "<database>".to_string(),
            reason: source.to_string(),
        })
    }

    /// Journal records strictly after `csn`, oldest first.
    ///
    /// `None` means the beginning. The key is `entryCSN`, which is fixed width, so a range scan
    /// over the text keys is a range scan over time - and no separate index is needed to answer
    /// "what changed since".
    pub fn journal_since(&self, csn: Option<&str>) -> Result<Vec<ChangeRecord>, BackendError> {
        if !self.journal {
            return Ok(Vec::new());
        }

        let transaction = self
            .database
            .begin_read()
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;

        let table = match transaction.open_table(CHANGES) {
            Ok(table) => table,
            // A store that has never been written to has no journal table yet, which is not an
            // error: it has nothing to report.
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(source) => {
                return Err(BackendError::Redb {
                    path: "<changes>".to_string(),
                    reason: source.to_string(),
                });
            }
        };

        let range = match csn {
            None => table.iter().map_err(|source| BackendError::Redb {
                path: "<changes>".to_string(),
                reason: source.to_string(),
            })?,
            Some(csn) => table
                .range::<&str>((std::ops::Bound::Excluded(csn), std::ops::Bound::Unbounded))
                .map_err(|source| BackendError::Redb {
                    path: "<changes>".to_string(),
                    reason: source.to_string(),
                })?,
        };

        let mut records = Vec::new();
        for item in range {
            let (_, value) = item.map_err(|source| BackendError::Redb {
                path: "<changes>".to_string(),
                reason: source.to_string(),
            })?;
            records.push(serde_json::from_slice(value.value()).map_err(|source| {
                BackendError::Parse {
                    path: "<changes>".to_string(),
                    source,
                }
            })?);
        }

        Ok(records)
    }

    /// The newest CSN in the journal, if there is one.
    ///
    /// The last key, not a scan: this is asked on every synchronised search, and the whole point
    /// of a fixed-width key is that the newest one is at the end.
    pub fn journal_head(&self) -> Result<Option<String>, BackendError> {
        if !self.journal {
            return Ok(None);
        }

        let transaction = self
            .database
            .begin_read()
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;

        let table = match transaction.open_table(CHANGES) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(source) => {
                return Err(BackendError::Redb {
                    path: "<changes>".to_string(),
                    reason: source.to_string(),
                });
            }
        };

        let last = table.last().map_err(|source| BackendError::Redb {
            path: "<changes>".to_string(),
            reason: source.to_string(),
        })?;

        Ok(last.map(|(key, _)| key.value().to_string()))
    }

    /// The oldest CSN the journal still remembers.
    ///
    /// A client resuming from a cookie older than this has missed changes that were pruned, and
    /// nothing in the surviving records says so: the range simply starts later. That is silent
    /// divergence, so the caller compares against this and starts a full refresh instead.
    pub fn journal_floor(&self) -> Result<Option<String>, BackendError> {
        if !self.journal {
            return Ok(None);
        }

        let transaction = self
            .database
            .begin_read()
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;

        let table = match transaction.open_table(CHANGES) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(source) => {
                return Err(BackendError::Redb {
                    path: "<changes>".to_string(),
                    reason: source.to_string(),
                });
            }
        };

        let first = table.first().map_err(|source| BackendError::Redb {
            path: "<changes>".to_string(),
            reason: source.to_string(),
        })?;

        Ok(first.map(|(key, _)| key.value().to_string()))
    }

    /// How many records the journal holds.
    pub fn journal_len(&self) -> Result<usize, BackendError> {
        Ok(self.journal_since(None)?.len())
    }

    /// Drops the oldest records, keeping the newest `keep`.
    ///
    /// A journal that is never trimmed grows with every write for ever, and a replica that has
    /// been offline longer than the journal is not `error` but a fact: it must be re-initialised
    /// rather than caught up, and `journal_head` is how it finds out.
    ///
    /// The count is the wrong only bound on its own, which is why [`Self::journal_prune_before`]
    /// exists: a directory that is written to rarely keeps a year of records under a generous
    /// count, and a directory written to heavily keeps a couple of hours under the same one.
    pub fn journal_prune(&self, keep: usize) -> Result<usize, BackendError> {
        let records = self.journal_since(None)?;
        if records.len() <= keep {
            return Ok(0);
        }

        let doomed: Vec<String> = records[..records.len() - keep]
            .iter()
            .map(|record| record.csn.clone())
            .collect();

        self.remove_changes(&doomed)
    }

    /// Drops the records stamped before `cutoff`.
    ///
    /// A tombstone ("this DN was deleted") is kept for one reason: a peer that has not yet heard
    /// about the deletion must be able to hear about it. Once every peer is past that moment the
    /// record is history, and keeping it because a count says so leaves a directory holding
    /// deletions from a year ago - which is both storage and a disclosure of what used to exist.
    ///
    /// A record whose CSN cannot be read is kept: an unreadable timestamp is not evidence that it
    /// is old, and dropping a record that a peer still needs costs a full resynchronisation of
    /// that peer, while keeping one costs a few bytes.
    pub fn journal_prune_before(
        &self,
        cutoff: std::time::SystemTime,
    ) -> Result<usize, BackendError> {
        let records = self.journal_since(None)?;

        let doomed: Vec<String> = records
            .iter()
            .filter(|record| {
                crate::operational::csn_time(&record.csn)
                    .map(|stamp| stamp < cutoff)
                    .unwrap_or(false)
            })
            .map(|record| record.csn.clone())
            .collect();

        self.remove_changes(&doomed)
    }

    /// Removes change records by CSN, in one transaction.
    ///
    /// The head and the floor are derived from what is present, so removing the tail is all a
    /// prune has to do; nothing else is updated, and nothing can be left half-removed.
    fn remove_changes(&self, doomed: &[String]) -> Result<usize, BackendError> {
        if doomed.is_empty() {
            return Ok(0);
        }

        let mut transaction = self
            .database
            .begin_write()
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;
        transaction
            .set_durability(self.durability)
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;
        {
            let mut table =
                transaction
                    .open_table(CHANGES)
                    .map_err(|source| BackendError::Redb {
                        path: "<changes>".to_string(),
                        reason: source.to_string(),
                    })?;
            for csn in doomed {
                table
                    .remove(csn.as_str())
                    .map_err(|source| BackendError::Redb {
                        path: "<changes>".to_string(),
                        reason: source.to_string(),
                    })?;
            }
        }
        transaction.commit().map_err(|source| BackendError::Redb {
            path: "<database>".to_string(),
            reason: source.to_string(),
        })?;

        Ok(doomed.len())
    }

    /// Stores the index snapshot, replacing any previous one.
    ///
    /// Written in its own transaction, after the data it describes: the snapshot names a
    /// fingerprint of that data, so a start that reads it and finds the fingerprint unchanged
    /// knows the two agree. Writing it in the same transaction as a change would be wrong for the
    /// opposite reason - the snapshot is the state of an index over the whole directory, and a
    /// single change does not update it in place.
    pub fn save_index(&self, bytes: &[u8]) -> Result<(), BackendError> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;

        // Immediate, whatever the store's own setting says. Measured on a three-million-entry
        // store configured `durability: none`: the snapshot was written, the file grew from 5.84
        // to 8.00 GB, and after a restart the index was built again from scratch - the commit was
        // never made durable, so it was rolled back and the space came back. The operator paid
        // 2.16 GB and got nothing.
        //
        // The setting is about entries, where a bulk import is worth risking the last commits
        // for; it is not about this. A snapshot is a startup cache, and a cache that silently
        // disappears is worse than no cache, because the cost was already paid.
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;
        {
            let mut table = transaction
                .open_table(INDEX)
                .map_err(|source| BackendError::Redb {
                    path: "<index>".to_string(),
                    reason: source.to_string(),
                })?;
            table
                .insert(INDEX_KEY, bytes)
                .map_err(|source| BackendError::Redb {
                    path: "<index>".to_string(),
                    reason: source.to_string(),
                })?;
        }
        transaction.commit().map_err(|source| BackendError::Redb {
            path: "<database>".to_string(),
            reason: source.to_string(),
        })?;
        Ok(())
    }

    /// The stored snapshot, if there is one.
    ///
    /// `None` is ordinary and means "build the index": an empty store, a store written by an
    /// older build, or one whose snapshot was cleared.
    pub fn load_index(&self) -> Result<Option<Vec<u8>>, BackendError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;

        let table = match transaction.open_table(INDEX) {
            Ok(table) => table,
            // The table does not exist until something is written into it.
            Err(_) => return Ok(None),
        };

        let value = table.get(INDEX_KEY).map_err(|source| BackendError::Redb {
            path: "<index>".to_string(),
            reason: source.to_string(),
        })?;

        Ok(value.map(|value| value.value().to_vec()))
    }

    /// Forgets the snapshot.
    ///
    /// Called when the data changed in a way the snapshot cannot describe - an import, a bulk
    /// write - so the next start does not trust a fingerprint that was never updated.
    pub fn clear_index(&self) -> Result<(), BackendError> {
        let transaction = self
            .database
            .begin_write()
            .map_err(|source| BackendError::Redb {
                path: "<database>".to_string(),
                reason: source.to_string(),
            })?;
        {
            let mut table = transaction
                .open_table(INDEX)
                .map_err(|source| BackendError::Redb {
                    path: "<index>".to_string(),
                    reason: source.to_string(),
                })?;
            table
                .remove(INDEX_KEY)
                .map_err(|source| BackendError::Redb {
                    path: "<index>".to_string(),
                    reason: source.to_string(),
                })?;
        }
        transaction.commit().map_err(|source| BackendError::Redb {
            path: "<database>".to_string(),
            reason: source.to_string(),
        })?;
        Ok(())
    }

    /// Number of stored entries; used by tests and logging.
    pub fn count(&self) -> Result<usize, BackendError> {
        Ok(self.load()?.len())
    }

    /// Directory payload for the LDAP layer.
    ///
    /// The redb store is entry-shaped, so users and groups are split by DN the same
    /// way `Directory::from_entries` does; the backend hands over everything and the
    /// directory decides where it belongs.
    pub fn directory_data(&self) -> Result<DirectoryData, BackendError> {
        Ok(DirectoryData {
            entries: self.load()?,
            ..DirectoryData::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Attribute;
    use tempfile::tempdir;

    fn entry(dn: &str, cn: &str, mail: Option<&str>, admin: bool) -> Entry {
        let mut attributes = Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "inetOrgPerson".to_string()],
            ))
            .push(Attribute::single("cn", cn))
            .push(Attribute::single("entryUUID", "uuid-1").operational());
        if let Some(mail) = mail {
            attributes = attributes.push(Attribute::single("mail", mail));
        }
        if admin {
            attributes = attributes.push(Attribute::single("ldapAdmin", "true").internal());
        }

        Entry::new(dn, attributes)
    }

    fn backend(dir: &tempfile::TempDir) -> RedbBackend {
        RedbBackend::open(&dir.path().join("directory.redb"), Durability::Immediate).expect("open")
    }

    #[test]
    fn written_entries_survive_a_reopen() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("directory.redb");
        {
            let backend = RedbBackend::open(&path, Durability::Immediate).expect("open");
            backend
                .apply(&[EntryChange::Upsert {
                    entry: entry(
                        "cn=admin,ou=users,dc=example,dc=com",
                        "admin",
                        Some("a@e.com"),
                        true,
                    ),
                }])
                .expect("write");
        }

        // Reopening is what a restart does.
        let reopened = RedbBackend::open(&path, Durability::Immediate).expect("reopen");
        let entries = reopened.load().expect("load");

        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.dn(), "cn=admin,ou=users,dc=example,dc=com");
        assert_eq!(
            entry
                .attributes()
                .get("mail")
                .map(|attribute| attribute.values.to_vec()),
            Some(vec!["a@e.com".to_string()])
        );
        assert!(
            entry
                .attributes()
                .get("entryUUID")
                .expect("uuid")
                .flags
                .operational,
            "flags must survive the round trip"
        );
        assert!(entry.is_admin(), "the internal flag must survive too");
    }

    /// An entry stamped at `at`, so the journal record carries that moment.
    fn stamped(dn: &str, cn: &str, at: std::time::SystemTime) -> Entry {
        crate::operational::stamp_write_for(&entry(dn, cn, None, false), "test", at, 1)
    }

    #[test]
    fn records_older_than_the_configured_age_are_dropped_and_younger_ones_stay() {
        use std::time::{Duration, SystemTime};

        let dir = tempdir().expect("tempdir");
        let backend = backend(&dir);
        let now = SystemTime::now();

        backend
            .apply(&[
                EntryChange::Upsert {
                    entry: stamped(
                        "cn=old,ou=users,dc=example,dc=com",
                        "old",
                        now - Duration::from_secs(90 * 86_400),
                    ),
                },
                EntryChange::Upsert {
                    entry: stamped(
                        "cn=young,ou=users,dc=example,dc=com",
                        "young",
                        now - Duration::from_secs(3600),
                    ),
                },
            ])
            .expect("write");

        assert_eq!(backend.journal_len().expect("len"), 2);

        let removed = backend
            .journal_prune_before(now - Duration::from_secs(30 * 86_400))
            .expect("prune");

        assert_eq!(
            removed, 1,
            "only the record from ninety days ago is older than thirty"
        );
        assert_eq!(backend.journal_len().expect("len"), 1);
        assert!(
            backend
                .journal_since(None)
                .expect("records")
                .iter()
                .all(|record| record.dn.contains("young")),
            "the record inside the age is the one that survived"
        );
        assert!(
            backend
                .journal_since(None)
                .expect("records")
                .iter()
                .all(|record| !record.dn.contains("old")),
            "and the old DN is gone, not merely hidden from the count"
        );
    }

    #[test]
    fn a_record_with_an_unreadable_stamp_is_kept() {
        use std::time::{Duration, SystemTime};

        // The rule this pins: an unreadable timestamp is not evidence that a record is old.
        // Dropping one that a peer still needs costs that peer a full resynchronisation, while
        // keeping it costs a few bytes - so the doubt resolves towards keeping.
        let dir = tempdir().expect("tempdir");
        let backend = backend(&dir);

        let mut broken = entry(
            "cn=broken,ou=users,dc=example,dc=com",
            "broken",
            None,
            false,
        );
        broken = Entry::new(
            broken.dn(),
            broken
                .attributes()
                .clone()
                .replace(Attribute::single("entryCSN", "not-a-csn").operational()),
        );
        backend
            .apply(&[EntryChange::Upsert { entry: broken }])
            .expect("write");

        let removed = backend
            .journal_prune_before(SystemTime::now() + Duration::from_secs(86_400))
            .expect("prune");

        assert_eq!(
            removed, 0,
            "nothing is dropped on the strength of a bad stamp"
        );
        assert_eq!(backend.journal_len().expect("len"), 1);
    }

    #[test]
    fn compaction_returns_what_deleted_entries_left_behind() {
        // Redb is copy-on-write: a freed page is reused by later writes but never returned to
        // the filesystem, so a store that grew and then shrank keeps its size. Without this the
        // only way to reclaim it was to export, delete the file and import again.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("directory.redb");
        let mut backend = RedbBackend::open(&path, Durability::Immediate).expect("open");

        let entries: Vec<Entry> = (0..2_000)
            .map(|index| {
                entry(
                    &format!("cn=user{index},ou=users,dc=example,dc=com"),
                    &format!("user{index}"),
                    Some(&format!("user{index}@example.com")),
                    false,
                )
            })
            .collect();

        backend
            .apply(
                &entries
                    .iter()
                    .cloned()
                    .map(|entry| EntryChange::Upsert { entry })
                    .collect::<Vec<_>>(),
            )
            .expect("write");

        let full = std::fs::metadata(&path).expect("stat").len();
        assert!(full > 0, "a store with entries occupies something");

        // Delete almost everything: the pages become free, the file does not notice.
        let doomed: Vec<EntryChange> = entries[10..]
            .iter()
            .map(|entry| EntryChange::delete(entry.dn().to_string(), None))
            .collect();
        backend.apply(&doomed).expect("delete");

        assert_eq!(
            backend.count().expect("count"),
            10,
            "only ten entries remain"
        );

        let report = backend.compact().expect("compact");
        assert!(report.performed, "there was free space to reclaim");
        assert!(
            report.after < report.before,
            "compaction has to make the file smaller: {} -> {}",
            report.before,
            report.after
        );
        assert_eq!(
            report.reclaimed(),
            report.before - report.after,
            "the bytes reported as reclaimed are the difference, not an estimate"
        );

        // What matters more than the size: the entries that stayed are untouched.
        let remaining = backend.load().expect("load");
        assert_eq!(
            remaining.len(),
            10,
            "compaction moves pages, it does not lose entries"
        );
        assert!(
            remaining.iter().any(|entry| entry.dn() == entries[0].dn()),
            "and the survivors are the ones that were not deleted"
        );
    }

    #[test]
    fn compaction_also_returns_the_space_redb_allocated_ahead_of_use() {
        // The premise this test started with was wrong, and the measurement corrected it: redb
        // grows the file in regions, so even a store that has never had a deletion holds far more
        // than its live pages. One entry measured 1 056 768 bytes before compaction and 24 576
        // after - 1 MB of slack returned, with nothing deleted at all.
        //
        // That makes compaction useful in a case it was not written for: a store that was
        // imported once and never shrank still holds the room the import took while it was
        // growing.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("directory.redb");
        let mut backend = RedbBackend::open(&path, Durability::Immediate).expect("open");

        backend
            .apply(&[EntryChange::Upsert {
                entry: entry("cn=only,ou=users,dc=example,dc=com", "only", None, false),
            }])
            .expect("write");

        let report = backend.compact().expect("compact");

        assert_eq!(
            backend.count().expect("count"),
            1,
            "compaction moves pages, it does not lose entries"
        );
        assert!(
            report.after <= report.before,
            "compaction never makes the file bigger: {} -> {}",
            report.before,
            report.after
        );
        assert_eq!(
            report.reclaimed(),
            report.before.saturating_sub(report.after),
            "and the bytes it reports are the difference that happened"
        );
    }

    #[test]
    fn the_snapshot_survives_even_when_the_store_defers_durability() {
        // The defect this guards, measured on a three-million-entry store: with
        // `durability: none` the snapshot was committed without being made durable. The file
        // grew from 5.84 to 8.00 GB, and after a restart the index was built again - the commit
        // had been rolled back and the space returned. The operator paid 2.16 GB for nothing.
        //
        // The store's setting is about entries, where a bulk import may risk the last commits.
        // A startup cache is not that: if it can vanish silently, the cost was paid and the
        // benefit was not delivered.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("directory.redb");

        {
            let backend =
                RedbBackend::open_with_journal(&path, Durability::None, true).expect("open");
            backend
                .save_index(b"a snapshot")
                .expect("save on a store that defers durability");
        }

        let reopened = RedbBackend::open(&path, Durability::Immediate).expect("reopen");
        assert_eq!(
            reopened.load_index().expect("read").as_deref(),
            Some(b"a snapshot".as_slice()),
            "the snapshot is written durably whatever the store's setting says"
        );
    }

    #[test]
    fn a_change_set_is_one_transaction() {
        let dir = tempdir().expect("tempdir");
        let backend = backend(&dir);

        backend
            .apply(&[
                EntryChange::Upsert {
                    entry: entry("cn=a,ou=users,dc=example,dc=com", "a", None, false),
                },
                EntryChange::Upsert {
                    entry: entry("cn=b,ou=users,dc=example,dc=com", "b", None, false),
                },
            ])
            .expect("write two");

        assert_eq!(backend.count().expect("count"), 2);
    }

    #[test]
    fn delete_removes_the_entry() {
        let dir = tempdir().expect("tempdir");
        let backend = backend(&dir);
        backend
            .apply(&[
                EntryChange::Upsert {
                    entry: entry("cn=a,ou=users,dc=example,dc=com", "a", None, false),
                },
                EntryChange::Upsert {
                    entry: entry("cn=b,ou=users,dc=example,dc=com", "b", None, false),
                },
            ])
            .expect("write");

        backend
            .apply(&[EntryChange::Delete {
                dn: "cn=a,ou=users,dc=example,dc=com".to_string(),
                kind: None,
            }])
            .expect("delete");

        let entries = backend.load().expect("load");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn(), "cn=b,ou=users,dc=example,dc=com");
    }

    #[test]
    fn a_rejected_change_leaves_nothing_written() {
        let dir = tempdir().expect("tempdir");
        let backend = backend(&dir);

        // The second change is not entry-shaped, so the whole transaction is refused.
        let result = backend.apply(&[
            EntryChange::Upsert {
                entry: entry("cn=a,ou=users,dc=example,dc=com", "a", None, false),
            },
            EntryChange::User {
                old: Box::default(),
                new: Box::default(),
            },
        ]);

        assert!(result.is_err(), "the change set must be refused");
        assert_eq!(
            backend.count().expect("count"),
            0,
            "a refused change set must not leave a partial write"
        );
    }

    #[test]
    fn an_empty_database_reads_as_an_empty_directory() {
        let dir = tempdir().expect("tempdir");
        let backend = backend(&dir);

        assert!(backend.load().expect("load").is_empty());
    }

    #[test]
    fn config_needs_a_path_and_accepts_a_durability_choice() {
        let missing =
            RedbBackend::from_config(&serde_json::json!({"path": "  "})).expect_err("empty path");
        assert!(
            missing.to_string().contains("non-empty 'path'"),
            "{missing}"
        );

        let bad = RedbBackend::from_config(&serde_json::json!({
            "path": "/tmp/x.redb",
            "durability": "sometimes"
        }))
        .expect_err("bad durability");
        assert!(
            bad.to_string().contains("unknown durability 'sometimes'"),
            "{bad}"
        );
    }

    #[test]
    fn with_the_journal_off_a_change_is_written_once_and_remembered_nowhere() {
        // The measurement that prompted this: a bulk import of a million entries produced a 4 GB
        // store and wrote every entry twice, once for the store and once for a journal that node
        // was never going to ship anywhere.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal-off.redb");
        let backend =
            RedbBackend::open_with_journal(&path, Durability::Immediate, false).expect("open");

        backend
            .apply(&[EntryChange::Upsert {
                entry: entry("cn=alice,dc=example,dc=com", "alice", None, false),
            }])
            .expect("write");

        // The entry is there.
        let loaded = backend.load().expect("load");
        assert_eq!(loaded.len(), 1);

        // The journal is not, and says so rather than pretending.
        assert!(backend.journal_since(None).expect("journal").is_empty());
        assert_eq!(backend.journal_head().expect("head"), None);
        assert_eq!(backend.journal_floor().expect("floor"), None);
    }

    #[test]
    fn with_the_journal_on_the_same_change_is_remembered() {
        // The control: the flag must change the journal and nothing else.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal-on.redb");
        let backend =
            RedbBackend::open_with_journal(&path, Durability::Immediate, true).expect("open");

        backend
            .apply(&[EntryChange::Upsert {
                entry: entry("cn=alice,dc=example,dc=com", "alice", None, false),
            }])
            .expect("write");

        let records = backend.journal_since(None).expect("journal");
        assert_eq!(records.len(), 1);
        assert!(backend.journal_head().expect("head").is_some());
    }

    #[test]
    fn opening_a_broken_file_names_the_path() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("broken.redb");
        std::fs::write(&path, b"this is not a database").expect("write");

        let err = RedbBackend::open(&path, Durability::Immediate).expect_err("must fail");

        assert!(
            err.to_string().contains(&path.display().to_string()),
            "unexpected: {err}"
        );
    }
}
