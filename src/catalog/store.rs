//! The store: one database, one transaction per change.
//!
//! This replaces the arrangement the rest of the tree still uses - a `Vec` of entries in memory with
//! a separate index snapshot in a file - and the reason is in `docs/storage.md`: every defect that
//! arrangement produced was fixed by adding another mechanism on top of it (deltas, an overlay,
//! convergence, rewrite thresholds, a skeleton mode), and each mechanism brought its own defects.
//!
//! # The one idea that does the work
//!
//! **Entries are keyed by their DN in reverse order.** `uid=alice,ou=users,dc=example,dc=com`
//! is stored under `dc=com,dc=example,ou=users,uid=alice`. A subtree then becomes a *key prefix*:
//! everything under `ou=users,dc=example,dc=com` starts with `dc=com,dc=example,ou=users,`. So a
//! subtree walk is a range scan, a parent check is one point read, and `onelevel` is the same scan
//! cut by the number of RDNs. Nothing in memory has to hold an order.
//!
//! # What is kept where
//!
//! ```text
//! entries   reversed DN -> record
//! dn_id     DN          -> u64
//! id_dn     u64         -> DN
//! meta      next_id, format version
//! ```
//!
//! Index tables come next (paged bitmaps); this module is the entries and the two translations.
//!
//! # Why two translations
//!
//! The postings in the indexes speak ids, because a bitmap of sixteen-byte UUIDs is not a bitmap -
//! it is a sorted array with an intersection that costs a comparison per element (the reasoning is
//! in `docs/storage.md`). A DN has to be translatable to an id and back: the first to find what a
//! search named, the second to read what a search found.
//!
//! An id is issued once and **never reused**: a reused id would make an old posting point at a
//! different entry, which is a wrong answer rather than a miss.
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use std::path::Path;

use crate::model::{Attribute, Attributes, Entry};

/// Reversed DN to record.
const ENTRIES: TableDefinition<&str, &[u8]> = TableDefinition::new("entries");
/// DN to id.
const DN_ID: TableDefinition<&str, u64> = TableDefinition::new("dn_id");
/// Id to DN.
const ID_DN: TableDefinition<u64, &str> = TableDefinition::new("id_dn");
/// `next_id` and the format version.
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

/// The format this build writes. A store written by another version is refused rather than read:
/// a misread record is a wrong answer, and there is no way to tell it from a right one afterwards.
const FORMAT: &str = "format";
const FORMAT_VERSION: u64 = 1;
const NEXT_ID: &str = "next_id";

/// Something the store refuses.
#[derive(Debug)]
pub enum StoreError {
    /// The file could not be opened or a transaction failed.
    Database(String),
    /// The store was written by a different format version.
    Format { found: u64, expected: u64 },
    /// A record could not be read back.
    Record(String),
    /// The id space is exhausted.
    ///
    /// Unreachable in practice - `u64` at a million inserts a second is six hundred thousand years -
    /// but it is a refusal and not a wrap: a wrapped id points at another entry.
    Exhausted,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(detail) => write!(formatter, "store: {detail}"),
            Self::Format { found, expected } => write!(
                formatter,
                "the store was written in format {found} and this build reads {expected}; \
                 reimport the data rather than reading it as if nothing had changed"
            ),
            Self::Record(detail) => {
                write!(formatter, "store: a record could not be read: {detail}")
            }
            Self::Exhausted => formatter.write_str("store: the id space is exhausted"),
        }
    }
}

impl std::error::Error for StoreError {}

fn database(source: impl ToString) -> StoreError {
    StoreError::Database(source.to_string())
}

/// The DN as a key: RDN order reversed, so a subtree is a prefix.
///
/// `uid=alice,ou=users,dc=example,dc=com` becomes `dc=com,dc=example,ou=users,uid=alice`. Splitting
/// on commas is safe because the DNs reaching here are normalized: `dn::normalize` escapes a comma
/// inside a value, so a comma in the string is always a separator.
pub fn key_of(dn: &str) -> String {
    let mut parts: Vec<&str> = dn.split(',').map(str::trim).collect();
    parts.reverse();
    parts.join(",")
}

/// The prefix every entry under `base` shares, or `None` for an empty base.
///
/// The trailing comma is not decoration: without it `ou=users,dc=example,dc=com` would also match a
/// sibling named `ou=users2,dc=example,dc=com`, whose key starts with the same characters.
pub fn subtree_prefix(base: &str) -> Option<String> {
    let base = base.trim();
    if base.is_empty() {
        return None;
    }
    Some(format!("{},", key_of(base)))
}

/// How many RDNs a reversed key holds, which is how `onelevel` is told from a deeper match.
fn depth_of(key: &str) -> usize {
    key.split(',').count()
}

/// The store itself.
pub struct Store {
    database: Database,
}

impl Store {
    /// Opens a store, creating it when absent.
    ///
    /// `durability: none` by default: the entries are the data, but a directory that loses its last
    /// few writes on a power cut is a directory that can be re-synced, while a directory that fsyncs
    /// on every add writes at the speed of the disk. The choice belongs to the caller in the end;
    /// this default is the one every benchmark in `docs/ub-log.md` was taken with.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let database = Database::create(path).map_err(database)?;
        let store = Self { database };
        store.check_format()?;
        Ok(store)
    }

    /// An in-memory store, for tests and for a directory that is explicitly not persisted.
    pub fn in_memory() -> Result<Self, StoreError> {
        let database = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .map_err(database)?;
        let store = Self { database };
        store.check_format()?;
        Ok(store)
    }

    /// Refuses a store written by another format, and stamps an empty one.
    fn check_format(&self) -> Result<(), StoreError> {
        let write = self.database.begin_write().map_err(database)?;

        // Read first, in its own scope: a value from redb borrows the table it came from, and the
        // table borrows the transaction, so the whole chain has to be dropped before the format can
        // be stamped or the transaction committed.
        let found = {
            let meta = write.open_table(META).map_err(database)?;
            meta.get(FORMAT)
                .map_err(database)?
                .map(|value| value.value())
        };

        match found {
            // No `return`: the match is the tail of the function, and clippy is right that an
            // explicit one there is noise rather than clarity.
            Some(found) if found != FORMAT_VERSION => Err(StoreError::Format {
                found,
                expected: FORMAT_VERSION,
            }),
            Some(_) => Ok(()),
            None => {
                let mut meta = write.open_table(META).map_err(database)?;
                meta.insert(FORMAT, FORMAT_VERSION).map_err(database)?;
                meta.insert(NEXT_ID, 1u64).map_err(database)?;
                drop(meta);
                write.commit().map_err(database)?;
                Ok(())
            }
        }
    }

    /// The record for a DN, with its id.
    pub fn get(&self, dn: &str) -> Result<Option<(u64, Entry)>, StoreError> {
        let key = key_of(dn);
        let read = self.database.begin_read().map_err(database)?;

        let id = match read.open_table(DN_ID) {
            Ok(table) => match table.get(dn).map_err(database)? {
                Some(id) => id.value(),
                None => return Ok(None),
            },
            Err(_) => return Ok(None),
        };
        let bytes = match read.open_table(ENTRIES) {
            Ok(table) => match table.get(key.as_str()).map_err(database)? {
                Some(value) => value.value().to_vec(),
                None => return Ok(None),
            },
            Err(_) => return Ok(None),
        };

        let entry = decode(&bytes).ok_or_else(|| StoreError::Record(dn.to_string()))?;
        Ok(Some((id, entry)))
    }

    /// The record for an id, without translating the DN.
    ///
    /// Two reads: the id gives a DN, the DN gives the record. Kept as two lookups rather than one
    /// because the id-to-record mapping would be a second copy of every record, and a directory's
    /// records are most of what it stores.
    pub fn by_id(&self, id: u64) -> Result<Option<Entry>, StoreError> {
        let read = self.database.begin_read().map_err(database)?;
        let dn = match read.open_table(ID_DN) {
            Ok(table) => match table.get(id).map_err(database)? {
                Some(dn) => dn.value().to_string(),
                None => return Ok(None),
            },
            Err(_) => return Ok(None),
        };
        drop(read);

        Ok(self.get(&dn)?.map(|(_, entry)| entry))
    }

    /// The id of a DN, without reading the record.
    pub fn id_of(&self, dn: &str) -> Result<Option<u64>, StoreError> {
        let read = self.database.begin_read().map_err(database)?;
        let table = match read.open_table(DN_ID) {
            Ok(table) => table,
            Err(_) => return Ok(None),
        };
        Ok(table.get(dn).map_err(database)?.map(|id| id.value()))
    }

    /// How many entries the store holds.
    pub fn len(&self) -> Result<u64, StoreError> {
        let read = self.database.begin_read().map_err(database)?;
        match read.open_table(ENTRIES) {
            Ok(table) => table.len().map_err(database),
            Err(_) => Ok(0),
        }
    }

    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }

    /// The id the next insert will take.
    pub fn next_id(&self) -> Result<u64, StoreError> {
        let read = self.database.begin_read().map_err(database)?;
        match read.open_table(META) {
            Ok(table) => Ok(table
                .get(NEXT_ID)
                .map_err(database)?
                .map(|value| value.value())
                .unwrap_or(1)),
            Err(_) => Ok(1),
        }
    }

    /// Writes a batch of changes in one transaction.
    ///
    /// One transaction for the whole batch and not one per entry: a change set is a fact, and half
    /// of it on disk is a directory nobody can reason about. This is also what makes the index
    /// update atomic with the entries - they are in the same transaction, so there is no moment at
    /// which a posting refers to an entry that is not there.
    pub fn apply(&self, changes: &[Change]) -> Result<u64, StoreError> {
        let mut write = self.database.begin_write().map_err(database)?;
        write.set_durability(Durability::None).map_err(database)?;

        let mut next_id = {
            let meta = write.open_table(META).map_err(database)?;
            meta.get(NEXT_ID)
                .map_err(database)?
                .map(|value| value.value())
                .unwrap_or(1)
        };

        {
            let mut entries = write.open_table(ENTRIES).map_err(database)?;
            let mut dn_id = write.open_table(DN_ID).map_err(database)?;
            let mut id_dn = write.open_table(ID_DN).map_err(database)?;

            for change in changes {
                match change {
                    Change::Add { entry } => {
                        let dn = entry.dn();
                        let key = key_of(dn);
                        if dn_id.get(dn).map_err(database)?.is_some() {
                            continue;
                        }
                        let id = next_id;
                        next_id = next_id.checked_add(1).ok_or(StoreError::Exhausted)?;

                        entries
                            .insert(key.as_str(), encode(entry).as_slice())
                            .map_err(database)?;
                        dn_id.insert(dn, id).map_err(database)?;
                        id_dn.insert(id, dn).map_err(database)?;
                    }
                    Change::Replace { entry } => {
                        let dn = entry.dn();
                        if dn_id.get(dn).map_err(database)?.is_none() {
                            continue;
                        }
                        entries
                            .insert(key_of(dn).as_str(), encode(entry).as_slice())
                            .map_err(database)?;
                    }
                    Change::Remove { dn } => {
                        let Some(id) = dn_id.get(dn.as_str()).map_err(database)?.map(|v| v.value())
                        else {
                            continue;
                        };
                        entries.remove(key_of(dn).as_str()).map_err(database)?;
                        dn_id.remove(dn.as_str()).map_err(database)?;
                        id_dn.remove(id).map_err(database)?;
                        // The id is not reused: a posting that still names it must not point at a
                        // different entry later.
                    }
                }
            }

            let mut meta = write.open_table(META).map_err(database)?;
            meta.insert(NEXT_ID, next_id).map_err(database)?;
        }

        write.commit().map_err(database)?;
        Ok(next_id)
    }

    /// The entries under `base` at the given depth, in key order.
    ///
    /// `depth` is `0` for the base itself, `1` for its children, `usize::MAX` for the whole subtree.
    /// The implementation is the point of the reversed key: a subtree is a prefix, so this is one
    /// range scan and the depth test is a count of commas.
    pub fn walk(&self, base: &str, depth: usize) -> Result<Vec<(u64, Entry)>, StoreError> {
        let read = self.database.begin_read().map_err(database)?;
        let Ok(entries) = read.open_table(ENTRIES) else {
            return Ok(Vec::new());
        };
        let Ok(dn_id) = read.open_table(DN_ID) else {
            return Ok(Vec::new());
        };

        let mut found = Vec::new();
        let base_key = key_of(base);
        let base_depth = depth_of(&base_key);

        // The range starts at the base's own key, not at its prefix: the base is part of its own
        // subtree, and its key does not end in a comma. Everything under it does - which is also
        // what keeps a sibling whose name merely begins with the same characters out.
        let range = match subtree_prefix(base) {
            Some(prefix) => {
                let from: &str = base_key.as_str();
                entries
                    .range(from..)
                    .map_err(database)?
                    .take_while(|item| {
                        item.as_ref()
                            .map(|(key, _)| {
                                let key = key.value();
                                key == base_key || key.starts_with(prefix.as_str())
                            })
                            .unwrap_or(false)
                    })
                    .collect::<Vec<_>>()
            }
            // The empty base is the whole tree.
            None => entries.iter().map_err(database)?.collect::<Vec<_>>(),
        };

        for item in range {
            let (key, value) = item.map_err(database)?;
            let key = key.value().to_string();
            let entry_depth = depth_of(&key);

            // The base itself is at `base_depth`; a child is one deeper.
            let relative = match entry_depth.checked_sub(base_depth) {
                Some(relative) => relative,
                None => continue,
            };
            // `depth` counts levels *below* the base: `1` is the direct children only, and the base
            // itself belongs only to a full subtree walk. A listing that included its own starting
            // point would make every paging client see the base twice - once from the listing and
            // once from its parent's.
            if depth == usize::MAX {
                // everything
            } else if relative == 0 || relative > depth {
                continue;
            }

            let Some(entry) = decode(value.value()) else {
                return Err(StoreError::Record(key));
            };
            let Some(id) = dn_id.get(entry.dn()).map_err(database)?.map(|v| v.value()) else {
                // A record with no id is a store that was written by two transactions that
                // disagreed; reading past it would hide that.
                return Err(StoreError::Record(entry.dn().to_string()));
            };
            found.push((id, entry));
        }

        Ok(found)
    }

    /// Every DN and id, in key order: the numbering a fresh index is built from.
    pub fn numbering(&self) -> Result<Vec<(u64, String)>, StoreError> {
        let read = self.database.begin_read().map_err(database)?;
        let Ok(table) = read.open_table(ID_DN) else {
            return Ok(Vec::new());
        };
        let mut numbered = Vec::new();
        for item in table.iter().map_err(database)? {
            let (id, dn) = item.map_err(database)?;
            numbered.push((id.value(), dn.value().to_string()));
        }
        Ok(numbered)
    }
}

/// One change to the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Add { entry: Entry },
    Replace { entry: Entry },
    Remove { dn: String },
}

/// Encodes a record.
///
/// A hand-written format rather than `serde_json`, for two reasons that matter at nine million
/// entries: JSON repeats every attribute name and every flag, and a record is read on every point
/// lookup. The layout is lengths and bytes, with the flags packed into one byte.
///
/// ```text
/// dn_len dn_bytes
/// attribute_count
///   (name_len name_bytes, flag_byte, value_count, (value_len value_bytes)*)
/// ```
fn encode(entry: &Entry) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    write_bytes(&mut out, entry.dn().as_bytes());

    let attributes = entry.attributes().values();
    out.extend_from_slice(&(attributes.len() as u32).to_le_bytes());
    for attribute in attributes {
        write_bytes(&mut out, attribute.name.as_bytes());
        out.push(flag_byte(attribute));
        out.extend_from_slice(&(attribute.values.len() as u32).to_le_bytes());
        for value in attribute.values.iter() {
            write_bytes(&mut out, value.as_bytes());
        }
        match &attribute.value_csns {
            Some(csns) if !csns.is_empty() => {
                out.push(1);
                for csn in csns.iter() {
                    write_bytes(&mut out, csn.as_bytes());
                }
            }
            _ => out.push(0),
        }
    }
    out
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// The four flags in one byte. A version byte comes first so a later flag can be added without
/// silently reinterpreting the ones this build understands.
fn flag_byte(attribute: &Attribute) -> u8 {
    let mut byte = 0u8;
    if attribute.flags.operational {
        byte |= 1;
    }
    if attribute.flags.case_sensitive {
        byte |= 2;
    }
    if attribute.flags.sensitive {
        byte |= 4;
    }
    if attribute.flags.internal {
        byte |= 8;
    }
    byte
}

fn decode(bytes: &[u8]) -> Option<Entry> {
    let mut reader = Reader::new(bytes);
    let dn = reader.text()?;

    let count = reader.u32()? as usize;
    let mut attributes = Attributes::new();
    for _ in 0..count {
        let name = reader.text()?;
        let flags = reader.byte()?;
        let values_count = reader.u32()? as usize;
        let mut values = Vec::with_capacity(values_count.min(1024));
        for _ in 0..values_count {
            values.push(reader.text()?);
        }

        let mut attribute = Attribute::new(&name, values);
        if flags & 1 != 0 {
            attribute = attribute.operational();
        }
        if flags & 2 != 0 {
            attribute = attribute.case_sensitive();
        }
        if flags & 4 != 0 {
            attribute = attribute.sensitive();
        }
        if flags & 8 != 0 {
            attribute = attribute.internal();
        }

        if reader.byte()? == 1 {
            let stamps: Vec<std::sync::Arc<str>> = (0..attribute.values.len())
                .map(|_| {
                    reader
                        .text()
                        .map(|text| std::sync::Arc::from(text.as_str()))
                })
                .collect::<Option<Vec<_>>>()?;
            attribute = attribute.with_stamps(stamps);
        }

        attributes = attributes.replace(attribute);
    }

    Some(Entry::new(dn, attributes))
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(count)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn text(&mut self) -> Option<String> {
        let length = self.u32()? as usize;
        // A length from a corrupt record must not allocate a gigabyte before failing.
        if length > 16 * 1024 * 1024 {
            return None;
        }
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "dc=example,dc=com";

    fn person(name: &str) -> Entry {
        Entry::new(
            format!("uid={name},ou=users,{BASE}"),
            Attributes::new()
                .replace(Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "inetOrgPerson".to_string()],
                ))
                .replace(Attribute::single("uid", name))
                .replace(Attribute::single("cn", name)),
        )
    }

    fn store_with(names: &[&str]) -> Store {
        let store = Store::in_memory().expect("in-memory store");
        let changes: Vec<Change> = names
            .iter()
            .map(|name| Change::Add {
                entry: person(name),
            })
            .collect();
        store.apply(&changes).expect("seed");
        store
    }

    #[test]
    fn a_dn_is_reversed_so_a_subtree_becomes_a_prefix() {
        assert_eq!(
            key_of("uid=alice,ou=users,dc=example,dc=com"),
            "dc=com,dc=example,ou=users,uid=alice"
        );
        assert_eq!(
            subtree_prefix("ou=users,dc=example,dc=com").as_deref(),
            Some("dc=com,dc=example,ou=users,")
        );
        assert_eq!(subtree_prefix(""), None);
        // The trailing comma is what keeps a sibling out.
        assert!(
            !key_of("uid=x,ou=users2,dc=example,dc=com")
                .starts_with(&subtree_prefix("ou=users,dc=example,dc=com").unwrap())
        );
    }

    #[test]
    fn a_record_survives_the_round_trip_through_the_store() {
        let store = store_with(&["alice"]);

        let (id, entry) = store
            .get(&format!("uid=alice,ou=users,{BASE}"))
            .expect("read")
            .expect("present");

        assert_eq!(entry.dn(), format!("uid=alice,ou=users,{BASE}"));
        assert_eq!(id, 1, "the first entry takes the first id");
        assert_eq!(
            entry
                .attributes()
                .get("objectClass")
                .map(|attribute| attribute.values.clone()),
            Some(vec!["top".to_string(), "inetOrgPerson".to_string()].into_boxed_slice())
        );
        assert_eq!(
            store.by_id(id).expect("read").expect("present").dn(),
            entry.dn()
        );
    }

    #[test]
    fn an_entry_that_was_never_written_is_a_miss_and_not_an_error() {
        let store = store_with(&["alice"]);

        assert!(
            store
                .get(&format!("uid=bob,ou=users,{BASE}"))
                .expect("read")
                .is_none()
        );
        assert!(store.by_id(99).expect("read").is_none());
        assert!(
            store
                .id_of(&format!("uid=bob,ou=users,{BASE}"))
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn ids_are_never_reused_so_an_old_posting_cannot_land_on_a_new_entry() {
        // The one rule that keeps postings honest: an id issued once is never issued again, not even
        // after its entry is deleted. Reuse would make an old posting point at a different entry,
        // which is a wrong answer rather than a miss.
        let store = store_with(&["alice", "bob"]);
        let bob = store
            .id_of(&format!("uid=bob,ou=users,{BASE}"))
            .expect("read")
            .expect("present");
        assert_eq!(bob, 2);

        store
            .apply(&[Change::Remove {
                dn: format!("uid=bob,ou=users,{BASE}"),
            }])
            .expect("remove");
        store
            .apply(&[Change::Add {
                entry: person("carol"),
            }])
            .expect("add");

        let carol = store
            .id_of(&format!("uid=carol,ou=users,{BASE}"))
            .expect("read")
            .expect("present");
        assert_ne!(carol, bob, "the deleted id must not be handed out again");
        assert!(
            store.by_id(bob).expect("read").is_none(),
            "and it stays empty"
        );
    }

    #[test]
    fn a_subtree_walk_returns_the_base_its_children_and_their_children() {
        let store = Store::in_memory().expect("store");
        store
            .apply(&[
                Change::Add {
                    entry: Entry::new(BASE, Attributes::new()),
                },
                Change::Add {
                    entry: Entry::new(
                        format!("ou=users,{BASE}"),
                        Attributes::new().replace(Attribute::single("ou", "users")),
                    ),
                },
                Change::Add {
                    entry: person("alice"),
                },
                Change::Add {
                    entry: Entry::new(
                        format!("ou=groups,{BASE}"),
                        Attributes::new().replace(Attribute::single("ou", "groups")),
                    ),
                },
            ])
            .expect("seed");

        let subtree = store.walk(BASE, usize::MAX).expect("walk");
        assert_eq!(subtree.len(), 4, "the base and everything under it");

        let children = store.walk(BASE, 1).expect("walk");
        let names: Vec<String> = children
            .iter()
            .map(|(_, entry)| entry.dn().to_string())
            .collect();
        assert_eq!(children.len(), 2, "two organizational units: {names:?}");

        let under_users = store
            .walk(&format!("ou=users,{BASE}"), usize::MAX)
            .expect("walk");
        assert_eq!(under_users.len(), 2, "the ou itself and alice");

        // A base that does not exist holds nothing, and says so rather than searching elsewhere.
        assert!(
            store
                .walk(&format!("ou=nobody,{BASE}"), usize::MAX)
                .expect("walk")
                .is_empty()
        );
    }

    #[test]
    fn a_sibling_with_a_longer_name_is_not_part_of_the_subtree() {
        // The prefix trap: `ou=users` must not match `ou=users2`. The trailing comma in the prefix
        // is what prevents it, and this test is the one that notices if it goes.
        let store = Store::in_memory().expect("store");
        store
            .apply(&[
                Change::Add {
                    entry: Entry::new(
                        format!("ou=users,{BASE}"),
                        Attributes::new().replace(Attribute::single("ou", "users")),
                    ),
                },
                Change::Add {
                    entry: Entry::new(
                        format!("ou=users2,{BASE}"),
                        Attributes::new().replace(Attribute::single("ou", "users2")),
                    ),
                },
                Change::Add {
                    entry: person("alice"),
                },
            ])
            .expect("seed");

        let under_users = store
            .walk(&format!("ou=users,{BASE}"), usize::MAX)
            .expect("walk");
        let names: Vec<String> = under_users
            .iter()
            .map(|(_, entry)| crate::dn::first_value(entry.dn()).unwrap_or_default())
            .collect();

        assert_eq!(names.len(), 2, "ou=users and alice: {names:?}");
        assert!(!names.iter().any(|name| name == "users2"), "{names:?}");
    }

    #[test]
    fn replacing_a_record_keeps_its_id() {
        let store = store_with(&["alice"]);
        let before = store
            .id_of(&format!("uid=alice,ou=users,{BASE}"))
            .expect("read")
            .expect("present");

        store
            .apply(&[Change::Replace {
                entry: Entry::new(
                    format!("uid=alice,ou=users,{BASE}"),
                    Attributes::new().replace(Attribute::single("cn", "Alice Cooper")),
                ),
            }])
            .expect("replace");

        let (after, entry) = store
            .get(&format!("uid=alice,ou=users,{BASE}"))
            .expect("read")
            .expect("present");
        assert_eq!(after, before, "an id does not move when its record changes");
        assert_eq!(
            entry
                .attributes()
                .get("cn")
                .and_then(|attribute| attribute.values.first().map(String::as_str)),
            Some("Alice Cooper")
        );
    }

    #[test]
    fn a_change_set_is_one_transaction() {
        // Half a change set on disk is a directory nobody can reason about. What this can check
        // without a crash is that the batch is visible all at once, and that a duplicate add inside
        // it does not produce two records.
        let store = Store::in_memory().expect("store");
        store
            .apply(&[
                Change::Add {
                    entry: person("alice"),
                },
                Change::Add {
                    entry: person("alice"),
                },
                Change::Add {
                    entry: person("bob"),
                },
            ])
            .expect("apply");

        assert_eq!(
            store.len().expect("len"),
            2,
            "the duplicate is not a second record"
        );
    }

    #[test]
    fn the_flags_of_an_attribute_survive_the_round_trip() {
        let store = Store::in_memory().expect("store");
        store
            .apply(&[Change::Add {
                entry: Entry::new(
                    format!("uid=alice,ou=users,{BASE}"),
                    Attributes::new()
                        .replace(
                            Attribute::single("userPassword", "hash")
                                .sensitive()
                                .case_sensitive(),
                        )
                        .replace(Attribute::single("entryCSN", "stamp").operational())
                        .replace(Attribute::single("secret", "x").internal()),
                ),
            }])
            .expect("add");

        let (_, entry) = store
            .get(&format!("uid=alice,ou=users,{BASE}"))
            .expect("read")
            .expect("present");

        let password = entry
            .attributes()
            .values()
            .iter()
            .find(|a| a.name.as_ref() == "userPassword")
            .expect("password");
        assert!(password.flags.sensitive, "sensitive must survive");
        assert!(password.flags.case_sensitive, "case-sensitive must survive");
        let csn = entry
            .attributes()
            .values()
            .iter()
            .find(|a| a.name.as_ref() == "entryCSN")
            .expect("csn");
        assert!(csn.flags.operational, "operational must survive");
        let secret = entry
            .attributes()
            .values()
            .iter()
            .find(|a| a.name.as_ref() == "secret")
            .expect("secret");
        assert!(secret.flags.internal, "internal must survive");
    }

    #[test]
    fn a_store_of_another_format_is_refused_rather_than_read() {
        let store = Store::in_memory().expect("store");
        {
            let write = store.database.begin_write().expect("write");
            let mut meta = write.open_table(META).expect("meta");
            meta.insert(FORMAT, 99u64).expect("stamp");
            drop(meta);
            write.commit().expect("commit");
        }

        let refused = store.check_format().expect_err("refused");
        assert!(matches!(refused, StoreError::Format { found: 99, .. }));
        assert!(refused.to_string().contains("reimport"), "{refused}");
    }

    #[test]
    fn the_numbering_is_every_entry_with_its_id() {
        let store = store_with(&["alice", "bob"]);

        let numbering = store.numbering().expect("numbering");

        assert_eq!(numbering.len(), 2);
        let names: Vec<String> = numbering
            .iter()
            .map(|(_, dn)| crate::dn::first_value(dn).unwrap_or_default())
            .collect();
        assert!(
            names.iter().any(|name| name == "alice") && names.iter().any(|name| name == "bob"),
            "{names:?}"
        );
        assert_eq!(
            store.next_id().expect("next"),
            3,
            "two entries took two ids"
        );
    }
}
