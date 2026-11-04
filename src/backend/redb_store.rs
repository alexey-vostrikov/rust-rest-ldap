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
            database: std::sync::Arc::new(database),
            durability,
            journal,
        };
        backend.write_format_version()?;
        Ok(backend)
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
    pub fn journal_prune(&self, keep: usize) -> Result<usize, BackendError> {
        let records = self.journal_since(None)?;
        if records.len() <= keep {
            return Ok(0);
        }

        let doomed: Vec<String> = records[..records.len() - keep]
            .iter()
            .map(|record| record.csn.clone())
            .collect();

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
            for csn in &doomed {
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
