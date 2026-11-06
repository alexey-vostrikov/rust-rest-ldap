//! Keeping the directory up to date: an interval, a signal and an HTTP callback.
//!
//! gorestldap had all three. The difference here is that a reload builds a whole
//! new [`Directory`] and swaps the `Arc`, so a request in flight finishes against
//! one consistent snapshot instead of seeing a half-updated tree.

use std::sync::Arc;

use tokio::sync::{RwLock, watch};
use tokio::time::{Duration, MissedTickBehavior};

use crate::backend::{Backend, BackendError, EntryChange};

/// How many notices a slow subscriber may fall behind before it is told it lagged.
///
/// A buffer is not a history: the number bounds memory, and the recovery from falling behind is to
/// re-read the directory, not to receive the backlog.
pub const NOTICE_BUFFER: usize = 256;
use crate::config::Config;
use crate::directory::Directory;
use crate::index::IndexConfig;
use crate::model::Entry;
use crate::schema::{Mode as SchemaMode, Schema};

/// Records fetched one at a time from the store, for a snapshot that holds identities only.
///
/// Holds the backend behind an `Arc`, the same one the `Source` holds: the store has a single
/// writer and a file lock, so a second handle would not open at all, and a clone would be a second
/// `Database` over one file.
struct BackendEntrySource {
    backend: Arc<Backend>,
}

impl crate::directory::EntrySource for BackendEntrySource {
    fn get(&self, dn: &str) -> Option<Entry> {
        self.backend.entry(dn)
    }
}

/// What the stored index snapshot is, as the process knows it: its counter and its size.
///
/// Both are written on the same three occasions - a snapshot read, built, or rewritten - and read
/// on every write, which is why they are atomics rather than a lock: a write needs the answer, not
/// exclusive access to it.
#[derive(Debug, Default)]
pub struct SnapshotKnown {
    sequence: std::sync::atomic::AtomicU64,
    bytes: std::sync::atomic::AtomicU64,
}

impl SnapshotKnown {
    /// Records a snapshot: the counter it covers and its size.
    fn remember(&self, sequence: u64, bytes: usize) {
        self.sequence
            .store(sequence, std::sync::atomic::Ordering::Release);
        self.bytes
            .store(bytes as u64, std::sync::atomic::Ordering::Release);
    }

    fn sequence(&self) -> u64 {
        self.sequence.load(std::sync::atomic::Ordering::Acquire)
    }

    fn bytes(&self) -> u64 {
        self.bytes.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Holds the current directory snapshot and knows how to rebuild it.
pub struct Source {
    backend: Arc<Backend>,
    base_dn: String,
    users_ou_name: String,
    groups_ou_name: String,
    current: RwLock<Arc<Directory>>,
    generation: RwLock<u64>,
    /// The published schema, shared with every `Security` the connections hold.
    schema: crate::security::SharedSchema,
    /// Where the schema comes from, re-read on a reload.
    ///
    /// Behind a lock because it changes at run time: a commit through `cn=schema,cn=config` adds
    /// a definition, and the next reload has to build from the document the server now holds -
    /// not from the one it started with. One holder rather than two fields, so a reload can never
    /// read the files of one moment and the definitions of another.
    schema_sources: std::sync::RwLock<SchemaSources>,
    schema_mode: SchemaMode,
    indexes: IndexConfig,
    /// Set while a snapshot rewrite is running, so two cannot encode the same index at once and
    /// delete each other's deltas.
    snapshot_rewriting: Arc<std::sync::atomic::AtomicBool>,
    /// What the store holds: the counter the snapshot covers and how many bytes it is.
    ///
    /// Kept here rather than asked of the store, because asking costs a copy of the snapshot
    /// itself: on a million entries the blob is about 700 MB, and `snapshot_rewrite_due` runs on
    /// every write - 164 ms per modify, measured, for a number that had not changed. Two words of
    /// memory instead.
    snapshot_known: Arc<SnapshotKnown>,
    /// Where writes are announced, so a persistent search can be told about them.
    ///
    /// A broadcast channel and not a queue per subscriber: the number of listeners is not known
    /// when the server starts, and one that falls behind must be told rather than silently
    /// skipped over. A lagging subscriber gets `Lagged` and re-reads the directory, which is the
    /// honest recovery - better than a stream of changes with a gap in the middle.
    notices: tokio::sync::broadcast::Sender<crate::ldap::sync::Notice>,

    /// How many times the store has been read in full.
    ///
    /// An operator number - it says what the write path costs - and the thing a test can look at
    /// to tell an incremental write from a reload, which look the same from the outside because
    /// both answer the same.
    store_reads: std::sync::atomic::AtomicU64,
}

impl Source {
    /// Loads the directory once and returns the source, failing if the backend is
    /// unusable — a server that starts with an empty directory looks healthy and
    /// is not.
    pub async fn load(
        config: &Config,
        backend: Backend,
    ) -> Result<(Arc<Self>, Arc<Directory>), BackendError> {
        let backend = Arc::new(backend);

        // Before the store is read, not after it: the whole point of the snapshot is that a start
        // on three million entries should not read three million records to answer a question about
        // one. Doing this afterwards - which is what the code did - meant the snapshot saved the
        // index build (148 s) and paid the rest of the start anyway (103 s of reading, 45 s of
        // hashing), and neither the saving nor the cost is what an operator notices.
        if backend.reads_by_key()
            && let Some(directory) = Self::from_snapshot_only(config, &backend)?
        {
            println!("{}", crate::i18n::t("start.index_skeleton", &[]));
            // Zero store reads, and the number says so rather than hiding it: an operator looking
            // at `ldap_store_reads_total` sees a start that did not walk the store.
            return Self::finish(config, backend, directory.0, directory.1, 0);
        }

        let data = backend.load().await?;
        let directory = data.into_directory(
            &config.base_dn,
            &config.users_ou_name,
            &config.groups_ou_name,
        );

        // The index first: a start that can read it skips the work that, on three million
        // entries, takes six minutes - and an operator who waits six minutes turns the index off,
        // so this is what makes the index usable at all.
        //
        // Two ways to trust what is stored, and the counter chain is the one used: the data has
        // not moved since the snapshot, or the store recorded every change since. Anything else
        // is a rebuild - a snapshot trusted by presence alone would narrow to a value that is no
        // longer in the directory, which reads as a missing entry and cannot be diagnosed from
        // outside.
        // The fingerprint is not computed here any more, and that is a measured decision rather
        // than a shortcut: hashing every entry cost 45 seconds on three million of them, on every
        // start, to answer a question the store already answers. The counter moves in the same
        // transaction as the data, the snapshot records the counter it covers, and the deltas close
        // the gap - three facts that cannot disagree without a transaction boundary in between.
        //
        // What is given up: a store restored from a backup beside a snapshot from another machine
        // whose counter happens to match. `--check-index` is the answer, and it does *not* compare
        // fingerprints - it checks that every search the index answers agrees with a full scan,
        // which is a stronger question than "did the data move". It is a check an operator runs
        // once after a restore, not on every start.
        //
        // `data_fingerprint` itself remains in `index.rs`, used by the tests that pin down what the
        // snapshot format refuses. It is not on any start path any more.
        let sequence = backend.sequence()?;
        let stored = backend.load_index()?;
        // What the store holds, as the process will remember it. The number is the one the
        // snapshot covers, not the counter's current value: the deltas after it are what a start
        // would replay, and what a rewrite measures itself against.
        let known = SnapshotKnown::default();
        if let Some((bytes, snapshot_sequence)) = &stored {
            known.remember(*snapshot_sequence, bytes.len());
        }
        let reused = match stored {
            // The counter decides, not the decode. A snapshot that decodes cleanly says only that
            // its bytes are intact - it says nothing about whether the data underneath moved, and
            // trusting it on that basis alone would answer from a snapshot of an older directory.
            // Removing the fingerprint check made that mistake visible: two tests that write
            // between starts caught it at once.
            Some((bytes, snapshot_sequence)) if snapshot_sequence == sequence => {
                // Nothing has been written since the snapshot was taken: the numbering is exactly
                // the one its postings were built under.
                crate::index::Index::decode_unchecked(&bytes).and_then(
                    |(index, numbering, next_id)| {
                        let map: std::collections::HashMap<String, u32> =
                            numbering.into_iter().collect();
                        directory
                            .clone()
                            .with_numbered_index(index, &map, next_id)
                            .map(|directory| (directory, false))
                    },
                )
            }
            Some((bytes, snapshot_sequence)) if snapshot_sequence < sequence => {
                // The data moved. Replay what the store wrote down, in the order it happened; a
                // hole in that chain means a crash wrote the data and not its delta, and the only
                // honest answer is to build again.
                match backend.index_deltas(snapshot_sequence, sequence)? {
                    Some(deltas) => {
                        replay(&directory, &bytes, &deltas, &config.indexes).map(|d| (d, true))
                    }
                    None => None,
                }
            }
            // A counter ahead of the store's means the snapshot and the store are from different
            // worlds - a store restored from a backup beside a newer snapshot, say. Build again.
            Some(_) => None,
            None => None,
        };

        let directory = match reused {
            Some((directory, replayed)) => {
                // Two different facts, and an operator reading the log deserves the right one:
                // nothing happened since the snapshot, or some change sets did and were replayed.
                let key = if replayed {
                    "start.index_replayed"
                } else {
                    "start.index_reused"
                };
                println!("{}", crate::i18n::t(key, &[]));
                directory
            }
            None => {
                let started = std::time::Instant::now();
                let directory = directory.with_indexes(&config.indexes)?;
                println!(
                    "{}",
                    crate::i18n::t(
                        "start.index_built",
                        &[("seconds", &started.elapsed().as_secs().to_string())]
                    )
                );

                // Kept for the next start. A failure to write is reported and not fatal: the
                // index works either way, and refusing to serve because a cache could not be
                // saved would be the wrong trade.
                //
                // Streamed, not encoded into a `Vec`: the postings are already in memory, and a
                // second copy of them is what made a three-million-entry start swap - 7.1 GB of
                // swap, 82 GB read off the disk, the port closed for sixteen minutes.
                let numbering = directory.numbering();
                let index = directory.index();
                let plan = crate::index::plan_hash(&config.indexes);
                // The mapped format: sorted postings and a table of offsets, so the next start
                // reads a few pages instead of parsing this in full.
                let records = index.records(numbering);
                match backend.save_records(&records, sequence, plan) {
                    Ok(bytes) => known.remember(sequence, bytes as usize),
                    Err(err) => eprintln!(
                        "{}",
                        crate::i18n::t("error.index_snapshot", &[("detail", &err.to_string())])
                    ),
                }
                directory
            }
        };

        // The journal head travels with the first snapshot for the same reason it does on every
        // reload: a synchronised search hands it to the client, and a missing head would make a
        // resumed refresh send the whole directory again.
        Self::finish(config, backend, directory, known, 1)
    }

    /// Builds the directory from the stored index alone, or says why it cannot.
    ///
    /// What is needed and what is not, settled by measurement: the postings and the numbering give
    /// every answer a filter can be narrowed by, and the records themselves are read when an entry
    /// is returned. The skeletons are therefore identities - a DN and an id - and not copies of the
    /// entries, because the postings hold their values **folded** for case-insensitive matching and
    /// a folded value is not the value the client stored.
    ///
    /// `None` means "read the store": no snapshot, a counter that disagrees, a snapshot that does
    /// not decode, or a backend that cannot fetch one record by key. Every one of those is a slower
    /// start, never a wrong one.
    /// The snapshot with its records a read away, and the cache that keeps the hot ones.
    ///
    /// One place because there are two ways to arrive here - the mapped file and the replayed dump -
    /// and a cache configured on one path but not the other is a settings that works until a store
    /// is written by a different build.
    fn skeleton(directory: Directory, backend: &Arc<Backend>, config: &Config) -> Directory {
        let source = Arc::new(BackendEntrySource {
            backend: Arc::clone(backend),
        });
        let directory = directory.with_source(source);

        // Zero means the operator asked for no cache, and the answer is to read every time rather
        // than to invent a budget they did not set.
        match config.cache.budget() {
            0 => directory,
            budget => directory.with_cache(Arc::new(crate::record_cache::RecordCache::new(budget))),
        }
    }

    fn from_snapshot_only(
        config: &Config,
        backend: &Arc<Backend>,
    ) -> Result<Option<(Directory, SnapshotKnown)>, BackendError> {
        let sequence = backend.sequence()?;
        let plan = crate::index::plan_hash(&config.indexes);

        // The mapped format first: it needs no decoding at all, and its header says which counter it
        // covers. Only if that fails does the older dump format get read, which keeps a store written
        // by the previous build starting without a rebuild.
        if let Some(file) = backend.open_index(plan) {
            let t_open = std::time::Instant::now();
            let file = Arc::new(file);
            let snapshot_sequence = file.sequence();

            let known = SnapshotKnown::default();
            known.remember(snapshot_sequence, file.length() as usize);

            let state = match snapshot_sequence.cmp(&sequence) {
                // Nothing has been written since the snapshot: the postings are the index, and the
                // numbering is the identity map. No decoding, no materialising.
                std::cmp::Ordering::Equal => file.numbering().map(|numbered| {
                    eprintln!(
                        "PHASE numbering {}ms ({} dn)",
                        t_open.elapsed().as_millis(),
                        numbered.len()
                    );
                    (
                        crate::index::Index::from_plan(&config.indexes)
                            .with_mapped(Arc::clone(&file)),
                        numbered
                            .into_iter()
                            .collect::<std::collections::HashMap<_, _>>(),
                        file.next_id(),
                    )
                }),
                // The store moved: the deltas say how. They were written by the write path, so the
                // index is materialised from the file and the changes replayed onto it - the price
                // of a start after writes, and of nothing else.
                std::cmp::Ordering::Less => backend
                    .index_deltas(snapshot_sequence, sequence)?
                    .and_then(|deltas| {
                        let numbering = file
                            .numbering()?
                            .into_iter()
                            .collect::<std::collections::HashMap<_, _>>();
                        apply_recorded(
                            crate::index::Index::from_records(file.materialize()),
                            numbering,
                            file.next_id(),
                            &deltas,
                            &config.indexes,
                        )
                    }),
                // A snapshot ahead of the store: different worlds, read the store.
                std::cmp::Ordering::Greater => None,
            };

            if let Some((index, numbering, next_id)) = state {
                let listed: Vec<(String, u32)> =
                    numbering.iter().map(|(dn, id)| (dn.clone(), *id)).collect();
                let mapped = index.is_mapped();

                let t_build = std::time::Instant::now();
                if let Some(directory) = Directory::from_skeletons(
                    &config.base_dn,
                    &config.users_ou_name,
                    &config.groups_ou_name,
                    index.skeletons(&listed),
                    index,
                    &numbering,
                    next_id,
                ) {
                    eprintln!("PHASE skeletons {}ms", t_build.elapsed().as_millis());
                    // The records are skeletons either way - the store was not read - so the
                    // source stays. What differs is only where the postings are: the file, or
                    // memory after a replay.
                    let _ = mapped;
                    let directory = Self::skeleton(directory, backend, config);
                    println!("{}", crate::i18n::t("start.index_skeleton", &[]));
                    // Said once, at start, and only when there is a cache: a budget nobody is told
                    // about is a number the operator cannot check against what the process uses.
                    if let Some(cache) = directory.cache() {
                        println!(
                            "{}",
                            crate::i18n::t(
                                "start.cache",
                                &[(
                                    "budget",
                                    &crate::limits::Size(config.cache.budget() as u64).to_string()
                                )]
                            )
                        );
                        let _ = cache;
                    }
                    return Ok(Some((directory, known)));
                }
            }
        }

        let Some((bytes, snapshot_sequence)) = backend.load_index()? else {
            return Ok(None);
        };

        let known = SnapshotKnown::default();
        known.remember(snapshot_sequence, bytes.len());

        let (index, numbering, next_id) = match snapshot_sequence.cmp(&sequence) {
            std::cmp::Ordering::Equal => match crate::index::Index::decode_unchecked(&bytes) {
                Some((index, numbering, next_id)) => (
                    index,
                    numbering
                        .into_iter()
                        .collect::<std::collections::HashMap<_, _>>(),
                    next_id,
                ),
                None => return Ok(None),
            },
            std::cmp::Ordering::Less => {
                // The store moved. The deltas were written in the same breath as the changes they
                // describe, so replaying them gives an index that matches the store - and the
                // numbering that comes out of it decides which identities the skeletons are.
                let Some(deltas) = backend.index_deltas(snapshot_sequence, sequence)? else {
                    return Ok(None);
                };
                match replay_numbering(&bytes, &deltas, &config.indexes) {
                    Some(replayed) => replayed,
                    None => return Ok(None),
                }
            }
            // A snapshot from a newer store than this one: different worlds, read the store.
            std::cmp::Ordering::Greater => return Ok(None),
        };

        let listed: Vec<(String, u32)> =
            numbering.iter().map(|(dn, id)| (dn.clone(), *id)).collect();
        let skeletons = index.skeletons(&listed);

        let Some(directory) = Directory::from_skeletons(
            &config.base_dn,
            &config.users_ou_name,
            &config.groups_ou_name,
            skeletons,
            index,
            &numbering,
            next_id,
        ) else {
            return Ok(None);
        };

        Ok(Some((Self::skeleton(directory, backend, config), known)))
    }

    /// Everything a start does once it knows what the directory holds.
    ///
    /// Split out because there are now two ways to arrive here: reading the store, which is the
    /// ordinary one, and reading the snapshot alone, which is what a large directory needs to be
    /// answering in seconds rather than minutes. The part that follows - the journal head, the
    /// schema check, the memory report, the source itself - is the same either way, and duplicating
    /// it would be the one place the two paths could start to differ.
    fn finish(
        config: &Config,
        backend: Arc<Backend>,
        directory: Directory,
        known: SnapshotKnown,
        store_reads: u64,
    ) -> Result<(Arc<Self>, Arc<Directory>), BackendError> {
        let head = backend.journal_head()?;
        let floor = backend.journal_floor()?;
        let directory = Arc::new(directory.with_csn(head).with_floor(floor));

        // A snapshot of identities has nothing to check: its entries carry a DN and no attributes,
        // and every attribute they will ever show came from a record that was checked when it was
        // written. Checking here would report three million entries missing `objectClass` and
        // refuse to start under `strict` - which is the opposite of what the mode is for.
        if !directory.is_skeleton() {
            check_schema(&directory, &config.schema, config.schema_mode)?;
        }

        // Said once, at start, against the ceiling the operator set. Not a refusal: see
        // `crate::memory` for why an unavailable server is the worse failure.
        if let Some(ceiling) = config.limits.memory_bytes
            && let Some(usage) = crate::memory::Usage::against(ceiling)
        {
            if usage.exceeded() {
                eprintln!(
                    "{}",
                    crate::i18n::t(
                        "warn.memory_over",
                        &[
                            ("usage", &usage.to_string()),
                            ("excess", &crate::limits::Size(usage.excess()).to_string()),
                        ]
                    )
                );
            } else {
                println!(
                    "{}",
                    crate::i18n::t("start.memory", &[("usage", &usage.to_string())])
                );
            }
        }

        let source = Arc::new(Self {
            base_dn: config.base_dn.clone(),
            users_ou_name: config.users_ou_name.clone(),
            groups_ou_name: config.groups_ou_name.clone(),
            current: RwLock::new(Arc::clone(&directory)),
            generation: RwLock::new(0),
            indexes: config.indexes.clone(),
            snapshot_rewriting: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            snapshot_known: Arc::new(known),
            backend,
            schema: crate::security::shared_schema(config.schema.clone()),
            schema_sources: std::sync::RwLock::new(SchemaSources::from_config(config)),
            schema_mode: config.schema_mode,
            store_reads: std::sync::atomic::AtomicU64::new(store_reads),
            notices: tokio::sync::broadcast::channel(NOTICE_BUFFER).0,
        });

        Ok((source, directory))
    }

    /// How strictly this server enforces its schema, for a decision taken outside a reload.
    pub fn schema_mode(&self) -> SchemaMode {
        self.schema_mode
    }

    /// The sources the schema in force was built from.
    pub fn schema_sources(&self) -> SchemaSources {
        match self.schema_sources.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// The schema as it stands now.
    pub fn schema(&self) -> Arc<Schema> {
        crate::security::current_schema(&self.schema)
    }

    /// The shared schema itself.
    ///
    /// For building the `Security` that serves the connections: it has to hold *this* handle
    /// rather than its own copy, or a reload through the source would never reach a write.
    pub fn shared_schema(&self) -> crate::security::SharedSchema {
        Arc::clone(&self.schema)
    }

    /// Re-reads the schema files and adopts the result.
    ///
    /// Four steps, in this order, and the order is the whole design:
    ///
    /// 1. build a **fresh** schema from `Schema::core()` and the files - never extend the live
    ///    one, or a reload would accumulate definitions and never retract one;
    /// 2. validate the entries already in the directory against it, because adopting rules
    ///    the data breaks turns every later write into a refusal;
    /// 3. swap the inner `Arc`, so every connection sees the new schema at once and one
    ///    operation still sees one schema throughout;
    /// 4. report what it ended up with, which is what tells the operator the file was read.
    ///
    /// A step that fails leaves the previous schema in force: running yesterday's rules beats
    /// refusing everything because somebody's editor saved half a line.
    pub async fn reload_schema(&self) -> Result<SchemaReloaded, BackendError> {
        let sources = match self.schema_sources.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };

        self.reload_schema_with(&sources).await
    }

    /// Adopts the sources a committed document describes, then adopts the schema they build.
    ///
    /// The order matters: storing the sources first means a failure below still leaves the next
    /// reload building from the document in force, rather than from the one that was replaced.
    pub async fn adopt_schema_sources(
        &self,
        sources: SchemaSources,
    ) -> Result<SchemaReloaded, BackendError> {
        {
            let mut guard = match self.schema_sources.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *guard = sources.clone();
        }

        self.reload_schema_with(&sources).await
    }

    /// Rebuilds the schema from `sources` and puts it in force.
    async fn reload_schema_with(
        &self,
        sources: &SchemaSources,
    ) -> Result<SchemaReloaded, BackendError> {
        // The same builder startup uses, so the two cannot drift: a source added for one is a
        // source for both, and the failure names the file or the definition rather than just
        // "the schema".
        let schema = Schema::from_sources(&sources.files, &sources.definitions)?;

        let directory = self.directory().await;
        let warnings = check_schema_collect(&directory, &schema, self.schema_mode)?;

        let attributes = schema.attribute_count();
        let classes = schema.class_count();

        // The swap: one pointer, seen by every holder at once.
        match self.schema.write() {
            Ok(mut guard) => *guard = Arc::new(schema),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(schema),
        }

        Ok(SchemaReloaded {
            attributes,
            classes,
            warnings,
        })
    }

    pub async fn directory(&self) -> Arc<Directory> {
        let directory = self.current.read().await;
        Arc::clone(&directory)
    }

    /// Listens for writes.
    ///
    /// Subscribing before the initial refresh matters: a change that lands between the refresh and
    /// the subscription would otherwise be lost for ever, and a replica would stay wrong until the
    /// next full poll.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<crate::ldap::sync::Notice> {
        self.notices.subscribe()
    }

    /// Tells every listener what was just written.
    ///
    /// A failed send means nobody is listening, which is the normal case: a server with no
    /// persistent searches has no subscribers.
    fn announce(&self, changes: &[EntryChange]) {
        for change in changes {
            let notice = match change {
                EntryChange::Upsert { entry } => crate::ldap::sync::Notice {
                    kind: crate::backend::redb_store::ChangeKind::Modify,
                    dn: entry.dn().to_string(),
                    uuid: entry
                        .attributes()
                        .get(crate::model::ATTR_ENTRY_UUID)
                        .and_then(|attribute| attribute.values.first().cloned())
                        .unwrap_or_else(|| crate::directory::entry_uuid(entry.dn())),
                    entry: Some(entry.clone()),
                },
                EntryChange::Delete { dn, .. } => crate::ldap::sync::Notice {
                    kind: crate::backend::redb_store::ChangeKind::Delete,
                    dn: dn.clone(),
                    uuid: crate::directory::entry_uuid(dn),
                    entry: None,
                },
                // A user or group change from a JSON backend: the directory re-reads it anyway, so
                // there is no entry here to describe.
                _ => continue,
            };

            let _ = self.notices.send(notice);
        }
    }

    /// Trims the journal to its newest `keep` records.
    ///
    /// Called at startup and never while serving: pruning is a decision about how far back this
    /// node can answer, and doing it mid-flight would move the floor under a peer that is reading
    /// it. A node that wants a smaller journal restarts.
    pub fn prune_journal(&self, keep: usize) -> Result<usize, BackendError> {
        self.backend.journal_prune(keep)
    }

    /// The oldest change the journal still holds.
    ///
    /// A resuming client whose cookie is older than this has missed changes nobody will send it:
    /// the journal was pruned, and the surviving records start later without saying so. The caller
    /// answers with a full refresh, which is expensive and correct - the alternative is a replica
    /// that is wrong and looks healthy.
    pub fn journal_floor(&self) -> Result<Option<String>, BackendError> {
        self.backend.journal_floor()
    }

    /// The newest deletion this store remembers for `dn`, if it remembers one.
    ///
    /// Scans the journal, because the journal is keyed by CSN and not by DN - a tombstone is a
    /// record like any other and there is one index. That is the honest cost at this size: a
    /// replication round asks about the handful of DNs a peer named, not about the directory. An
    /// index by DN is the next step if a directory makes the scan visible, and this comment is
    /// where that will be remembered.
    pub fn tombstone(&self, dn: &str) -> Result<Option<String>, BackendError> {
        let mut newest: Option<String> = None;

        for record in self.backend.journal_since(None)? {
            if record.dn != dn || record.kind != crate::backend::redb_store::ChangeKind::Delete {
                continue;
            }
            if newest
                .as_deref()
                .is_none_or(|seen| record.csn.as_str() > seen)
            {
                newest = Some(record.csn);
            }
        }

        Ok(newest)
    }

    /// Whether a password-hash upgrade could be persisted by this backend.
    ///
    /// Asked by the server once, at startup, so that a bind does not attempt a write the
    /// backend will refuse and print a line about it on every successful login.
    pub fn accepts_entry_upserts(&self) -> bool {
        self.backend.accepts_entry_upserts()
    }

    /// How many times the store has been read in full since the process started.
    ///
    /// One at startup, then one per full reload. A write that is applied in place does not move
    /// it, which is the observable difference between an incremental write and a reload.
    pub fn store_reads(&self) -> u64 {
        self.store_reads.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Number of successful reloads so far, for logging and tests.
    pub async fn generation(&self) -> u64 {
        *self.generation.read().await
    }

    /// Persists a change set and makes it visible, incrementally where that is honest.
    ///
    /// A change that replaces an entry with one the store keeps verbatim is applied to the
    /// snapshot in place: the entry takes the place of the old one, its postings are updated,
    /// and the rest of the directory is not touched. Everything else - an add, a delete, a fixed
    /// user/group change, a backend that rewrites its document whole - falls back to a full
    /// reload, because those move the ids of other entries or leave the store free to store
    /// something other than what was sent.
    ///
    /// Until this existed every write cost a store read and an index rebuild: 51 ms at ten
    /// thousand entries and growing linearly, so a hundred thousand entries would have made a
    /// single `modify` take about half a second while the directory was being read by everyone
    /// else.
    pub async fn apply(&self, changes: &[EntryChange]) -> Result<usize, BackendError> {
        if let Some(entries) = self.apply_in_place(changes).await? {
            self.announce(changes);
            return Ok(entries);
        }

        // The path that reads the store back: a backend that does not keep entries verbatim, or a
        // change this one does not describe. The store is written first so the reload sees it.
        self.backend.apply(changes).await?;
        let entries = self.reload().await?;
        self.announce(changes);

        Ok(entries)
    }

    /// Applies a change set to the snapshot without reading the store, or reports that it cannot.
    ///
    /// `None` means "not this way": the caller reloads. The order matters and is the point of
    /// this function:
    ///
    /// 1. everything that can refuse does so before anything is touched - a change set that turns
    ///    out not to fit leaves the snapshot exactly as it was;
    /// 2. the snapshot is patched in place when no reader holds it, which is what makes a write
    ///    cost the entry rather than the directory; when a reader does hold it, the snapshot is
    ///    copied first, because a reader must never watch its own view change under it.
    async fn apply_in_place(&self, changes: &[EntryChange]) -> Result<Option<usize>, BackendError> {
        if !self.backend.keeps_entries_verbatim() || changes.is_empty() {
            return Ok(None);
        }

        // Every kind of change is applied here now, because an entry's id no longer depends on
        // its position: an add takes a fresh id, a delete gives its own back to nobody, and the
        // postings of the entries between them stay where they are. Positions still move, and
        // the two maps that translate are rebuilt - that is bookkeeping in memory, against
        // re-reading a store that is gigabytes on disk.
        let mut upserts: Vec<&Entry> = Vec::new();
        let mut deletes: Vec<&str> = Vec::new();
        for change in changes {
            match change {
                EntryChange::Upsert { entry } => upserts.push(entry),
                EntryChange::Delete { dn, .. } => deletes.push(dn.as_str()),
                // A backend may describe a change this path has never heard of; it reloads.
                _ => return Ok(None),
            }
        }

        // The check a reload would make, over the entries that changed. Every other entry was
        // checked when it was read; checking them again would make a write cost the directory
        // again, which is the whole cost this path exists to remove.
        let changed: Vec<Entry> = upserts.iter().map(|entry| (*entry).clone()).collect();
        for problem in check_entries_collect(&changed, &self.schema(), self.schema_mode)? {
            eprintln!("{}", crate::i18n::t("warn.schema", &[("detail", &problem)]));
        }

        let mut current = self.current.write().await;

        // The store is written here, under the snapshot lock, and the reason is the counter:
        // written outside it, two concurrent change sets could be numbered 5 and 6 and then
        // applied to the snapshot in the other order, so the delta filed as 5 would describe a
        // snapshot that already includes 6 - and the next start would replay 6 a second time.
        // Under one lock the numbering is also the application order, which is the only order the
        // stored deltas can be replayed in. The cost is that a reader waits out one store write,
        // measured in microseconds, and not the whole reload this path exists to avoid.
        let sequence = match self.backend.apply(changes).await? {
            Some(sequence) => sequence,
            // A backend that cannot number its change sets is not one this path serves.
            None => return Ok(None),
        };

        // The snapshot moves even though the store was not read again: a paged search that is
        // half way through must notice that the directory changed under it.
        let snapshot = {
            let mut generation = self.generation.write().await;
            *generation += 1;
            *generation
        };

        // A delete of something this snapshot still holds is a change to it; a delete of
        // something it does not hold is a replica applying a change it has already applied, and
        // there is nothing to do.
        deletes.retain(|dn| current.position(dn).is_some());

        // Unique means no reader holds this snapshot, so patching it is invisible to everyone
        // else - there is nobody else. Shared means a search is running against it, and the copy
        // is then the price of not changing what that search sees.
        if Arc::get_mut(&mut current).is_none() {
            let copy = (**current).clone();
            *current = Arc::new(copy);
        }
        let directory: &mut Directory = Arc::get_mut(&mut current).expect("made unique above");

        // What the index has to be told, for the store to replay the same thing on a later
        // start. Collected as it happens rather than recomputed afterwards, because "which
        // entries changed" is exactly what this loop knows and nothing else does.
        let mut applied: Vec<crate::index::IndexChange> =
            Vec::with_capacity(deletes.len() + upserts.len());

        // Deletions first: a change set that removes one entry and adds another under the same
        // DN - an import replacing an entry - would otherwise add first and then delete what it
        // had just written.
        for dn in &deletes {
            let id = directory.id_of(dn);
            let removed = directory.remove_entry_in_place(dn, &self.indexes)?;
            if let (Some(id), Some(entry)) = (id, removed) {
                applied.push(crate::index::IndexChange::Remove { id, entry });
            }
        }

        for entry in upserts {
            // Replaced when the DN is here, added when it is not. The distinction is the
            // directory's: it holds the map that answers it.
            let before = directory.find(entry.dn()).cloned();
            if directory.replace_entry_in_place(entry.clone(), &self.indexes)? {
                if let (Some(id), Some(before)) = (directory.id_of(entry.dn()), before) {
                    applied.push(crate::index::IndexChange::Replace {
                        id,
                        before,
                        after: entry.clone(),
                    });
                }
            } else if directory.insert_entry_in_place(entry.clone(), &self.indexes)?
                && let Some(id) = directory.id_of(entry.dn())
            {
                applied.push(crate::index::IndexChange::Add {
                    id,
                    entry: entry.clone(),
                });
            }
        }

        // Recorded for the next start, so it does not have to rebuild what this just built. A
        // failure is reported and not fatal: the index in memory is right either way, and the
        // next start simply builds it again.
        if !applied.is_empty() {
            let bytes = crate::index::Index::encode_delta(&applied);
            if let Err(err) = self.backend.append_index_delta(sequence, &bytes) {
                eprintln!(
                    "{}",
                    crate::i18n::t("error.index_snapshot", &[("detail", &err.to_string())])
                );
            }
        }

        directory.set_snapshot(snapshot);
        directory.set_csn(self.backend.journal_head()?);
        directory.set_floor(self.backend.journal_floor()?);
        // Counted by the directory as it changed, not by walking it here: a pass over every entry
        // with a suffix comparison on each ran on every write, to report a number that moved by
        // one.
        let entries = directory.entry_count();

        // Taken after the last use of `directory`: what the rewriter gets is this snapshot as it
        // stands now, together with the counter this change set was given. Anything written after
        // it carries a larger counter, so its delta stays and the chain remains whole.
        // The check is cheap - two metadata reads - and it runs here rather than inside the task
        // for a reason that is not about speed: a task that exists only to discover there is
        // nothing to do still holds the store open, and a store left open cannot be reopened by
        // whoever comes next. A task is started only when there is work for it.
        let due = self.snapshot_rewrite_due(sequence);
        let retained = Arc::clone(&*current);
        drop(current);

        if due {
            self.rewrite_snapshot_soon(retained, sequence);
        }

        Ok(Some(entries))
    }

    /// Whether the recorded changes have grown past the point where replaying them costs more
    /// than the snapshot they save.
    ///
    /// A read error answers `false` rather than propagating: this decides an optimisation, and a
    /// write that already reached the store must not be reported as failed because a threshold
    /// could not be read. The next write asks again.
    fn snapshot_rewrite_due(&self, sequence: u64) -> bool {
        let snapshot_sequence = self.snapshot_known.sequence();
        let snapshot_bytes = self.snapshot_known.bytes() as usize;
        if sequence <= snapshot_sequence {
            return false;
        }
        let Ok(recorded) = self.backend.index_delta_bytes(snapshot_sequence) else {
            return false;
        };

        recorded >= delta_budget(snapshot_bytes, self.indexes.snapshot_delta_bytes)
    }

    /// Rewrites the stored snapshot once the deltas have grown past what keeping them is worth.
    ///
    /// Deltas exist so that a restart does not rebuild the index. They are only worth their space
    /// up to the point where replaying them costs more than the snapshot they save - and past that
    /// point a node that is written to but never restarted accumulates them without limit, in a
    /// table nobody reads. Measured against the snapshot's own size, so the threshold follows the
    /// directory rather than a number guessed for one of its sizes.
    ///
    /// Nothing of this is on the client's path: a write is answered before the check runs, and the
    /// encoding - seconds over a large index - happens on a blocking thread. One rewrite at a
    /// time, because two would encode the same index twice and each delete the other's deltas.
    fn rewrite_snapshot_soon(&self, directory: Arc<Directory>, sequence: u64) {
        if self
            .snapshot_rewriting
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }

        let backend = Arc::clone(&self.backend);
        let flag = Arc::clone(&self.snapshot_rewriting);
        let known = Arc::clone(&self.snapshot_known);
        let indexes = self.indexes.clone();

        tokio::spawn(async move {
            let outcome =
                tokio::task::spawn_blocking(move || -> Result<(usize, u64), BackendError> {
                    // What the rewrite replaces, for the log line: the changes the new snapshot
                    // covers. Not a size to compare - the decision was taken before the task
                    // started, from counters in memory.
                    let recorded = backend.index_delta_bytes(known.sequence())?;

                    // The same format as at start, and for the same reason: the next start reads
                    // this file in place, and a rewrite that emitted the old dump would silently
                    // cost it the whole saving. One format, one reader.
                    let numbering = directory.numbering();
                    let index = directory.index();
                    let plan = crate::index::plan_hash(&indexes);
                    let records = index.records(numbering);

                    let written = backend.save_records(&records, sequence, plan)?;
                    known.remember(sequence, written as usize);

                    Ok((written as usize, recorded))
                })
                .await;

            flag.store(false, std::sync::atomic::Ordering::Release);

            match outcome {
                Ok(Ok((written, recorded))) => println!(
                    "{}",
                    crate::i18n::t(
                        "start.index_rewritten",
                        &[
                            ("bytes", &written.to_string()),
                            ("recorded", &recorded.to_string())
                        ]
                    )
                ),
                Ok(Err(err)) => eprintln!(
                    "{}",
                    crate::i18n::t("error.index_snapshot", &[("detail", &err.to_string())])
                ),
                Err(err) => eprintln!(
                    "{}",
                    crate::i18n::t("error.index_snapshot", &[("detail", &err.to_string())])
                ),
            }
        });
    }

    /// Rebuilds the indexes over the snapshot already in memory.
    ///
    /// What this cannot do, and does not claim to: repair a stale index. Every write and
    /// every reload rebuilds the index from the store, so the index is never older than the
    /// data it describes. What it is for is the two questions an operator actually asks -
    /// how long a rebuild takes at the current size, and how much memory the configured set
    /// holds - and for applying a change of heart about which attributes deserve one without
    /// re-reading the store.
    pub async fn reindex(&self) -> Result<Reindexed, BackendError> {
        let current = self.directory().await;

        let started = std::time::Instant::now();
        let rebuilt = (*current).clone().with_indexes(&self.indexes)?;
        let elapsed = started.elapsed();

        let index = rebuilt.index();
        let reindexed = Reindexed {
            entries: rebuilt.all().len(),
            attributes: index.built_attributes().count(),
            bytes: index.size_bytes(),
            elapsed,
        };

        *self.current.write().await = Arc::new(rebuilt);

        Ok(reindexed)
    }

    /// Reloads from the backend and swaps the snapshot.
    ///
    /// On error the previous snapshot stays in place: a backend hiccup must not
    /// empty the directory that clients are using.
    pub async fn reload(&self) -> Result<usize, BackendError> {
        self.store_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let data = self.backend.load().await?;
        let directory = data
            .into_directory(&self.base_dn, &self.users_ou_name, &self.groups_ou_name)
            .with_indexes(&self.indexes)?;
        let entries = directory.entry_count();

        check_schema(&directory, &self.schema(), self.schema_mode)?;

        // The snapshot number is what a paged search uses to notice that the directory moved
        // under it; it is taken with the swap, so the number and the contents cannot disagree.
        let snapshot = {
            let mut generation = self.generation.write().await;
            *generation += 1;
            *generation
        };
        // The journal head is taken with the snapshot for the same reason the snapshot number is:
        // a head from a later write would tell a replica it has changes nobody sent it.
        let head = self.backend.journal_head()?;
        let floor = self.backend.journal_floor()?;
        let directory = directory
            .at_snapshot(snapshot)
            .with_csn(head)
            .with_floor(floor);

        *self.current.write().await = Arc::new(directory);

        Ok(entries)
    }
}

/// Validates every entry according to the configured mode.
///
/// `strict` refuses the load, so a directory that does not match its schema never comes up
/// looking healthy; `warn` reports and proceeds, which is what a migration from foreign data
/// needs; `off` skips checking and keeps the schema published.
fn check_schema(
    directory: &Directory,
    schema: &crate::schema::Schema,
    mode: SchemaMode,
) -> Result<(), BackendError> {
    // In `warn` mode the problems come back as a list and are reported here; in `strict` the
    // collect step has already refused. Either way the message is one place.
    for problem in check_schema_collect(directory, schema, mode)? {
        eprintln!("{}", crate::i18n::t("warn.schema", &[("detail", &problem)]));
    }

    Ok(())
}

/// What a schema reload ended up with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaReloaded {
    /// Attribute types in force afterwards.
    pub attributes: usize,
    /// Object classes in force afterwards.
    pub classes: usize,
    /// Entries that break the new schema, accepted because the mode is `warn`.
    pub warnings: Vec<String>,
}

/// What a rebuild of the indexes did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reindexed {
    /// Entries the indexes were built over.
    pub entries: usize,
    /// Attributes that ended up with at least one index.
    pub attributes: usize,
    /// Memory the bitmaps hold, as the index reports it.
    pub bytes: usize,
    pub elapsed: std::time::Duration,
}

/// Validates every entry, returning the problems instead of deciding what to do with them.
///
/// Split from `check_schema` because a reload needs the list: in `warn` mode the violations
/// are reported to the operator and the schema adopted anyway, and the caller has nowhere to
/// put them if the function only returns `Ok`.
fn check_schema_collect(
    directory: &Directory,
    schema: &crate::schema::Schema,
    mode: SchemaMode,
) -> Result<Vec<String>, BackendError> {
    check_entries_collect(directory.all(), schema, mode)
}

/// The same check over a set of entries rather than the whole directory.
///
/// The incremental write path needs this: the rest of the directory was validated when it was
/// read, and re-validating ten thousand entries to make sure one of them is still fine is most of
/// the cost of a write. What it must not become is a weaker check - the entry that changed is
/// checked exactly as a reload would check it.
fn check_entries_collect(
    entries: &[Entry],
    schema: &crate::schema::Schema,
    mode: SchemaMode,
) -> Result<Vec<String>, BackendError> {
    if mode == SchemaMode::Off {
        return Ok(Vec::new());
    }

    let mut problems = Vec::new();
    for entry in entries {
        if let Err(violations) = schema.check(entry) {
            for violation in violations {
                problems.push(format!(
                    "{}: {:?}: {}",
                    entry.dn(),
                    violation.code,
                    violation.detail
                ));
            }
        }
    }

    if problems.is_empty() {
        return Ok(Vec::new());
    }

    match mode {
        // `warn` reports and proceeds: it is the mode an operator picks when the data is
        // older than the schema, and a reload that refused would make the mode pointless.
        SchemaMode::Warn => Ok(problems),
        _ => Err(BackendError::SchemaViolations {
            count: problems.len(),
            first: problems.into_iter().take(10).collect(),
        }),
    }
}

/// Reloads on an interval until told to stop.
pub async fn reload_on_interval(
    source: Arc<Source>,
    interval: Duration,
    stop: watch::Receiver<bool>,
) {
    reload_on_interval_with(source, interval, stop, crate::metrics::Metrics::new()).await
}

/// The same, reporting to the shared metrics.
pub async fn reload_on_interval_with(
    source: Arc<Source>,
    interval: Duration,
    mut stop: watch::Receiver<bool>,
    metrics: std::sync::Arc<crate::metrics::Metrics>,
) {
    if interval.is_zero() {
        return;
    }

    let mut ticker = tokio::time::interval(interval);
    // A slow backend must not queue up a burst of catch-up reloads.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => match source.reload().await {
                Ok(entries) => {
                    // The gauge follows what is actually in the directory, so a scrape after
                    // a reload reports the new size rather than the startup one.
                    metrics.set_entries(entries);
                    metrics.reload_succeeded();
                    println!("reload: {entries} entries (generation {})", source.generation().await)
                }
                Err(err) => {
                    metrics.reload_failed();
                    eprintln!(
                        "{}",
                        crate::i18n::t("error.reload", &[("detail", &err.to_string())])
                    )
                }
            },
            _ = stop.changed() => {
                if *stop.borrow() {
                    return;
                }
            }
        }
    }
}

/// Rebuilds the index from a snapshot and the changes recorded since it.
///
/// `None` when the snapshot cannot be read against the deltas: the numbering has to cover every
/// entry, and an entry the snapshot never saw and no delta added means the chain is not the whole
/// story. Rebuilding is correct and costs a minute; guessing is not.
/// How many bytes of recorded changes are worth keeping before the snapshot is rewritten.
///
/// Expressed against the snapshot rather than as an absolute number, because the directory's sizes
/// differ by four orders of magnitude and a number right for one is wrong for the others: two
/// gigabytes of snapshot with a megabyte of changes is a rounding error, a megabyte of snapshot
/// with the same changes is the changes outweighing what they were meant to save.
fn delta_budget(snapshot_bytes: usize, configured: Option<u64>) -> u64 {
    if let Some(bytes) = configured {
        return bytes;
    }
    (snapshot_bytes as u64 / 4).max(1024 * 1024)
}

fn replay(
    directory: &Directory,
    snapshot: &[u8],
    deltas: &[Vec<u8>],
    config: &crate::index::IndexConfig,
) -> Option<Directory> {
    let (index, numbering, next_id) = replay_numbering(snapshot, deltas, config)?;
    directory
        .clone()
        .with_numbered_index(index, &numbering, next_id)
}

/// Replays recorded changes onto a snapshot, and reports the numbering that results.
///
/// Split from [`replay`] because the two callers need different halves of it: a directory that read
/// the store wants the index applied to its own entries, and a start that holds identities only
/// wants the numbering - which entries exist - because its skeletons are built from it.
fn replay_numbering(
    snapshot: &[u8],
    deltas: &[Vec<u8>],
    config: &crate::index::IndexConfig,
) -> Option<(
    crate::index::Index,
    std::collections::HashMap<String, u32>,
    u32,
)> {
    // The snapshot's fingerprint cannot match: the data moved, which is why a delta exists. The
    // stored value is read past rather than checked, and the deltas are what vouch for the
    // result - each one was written in the same breath as the change it describes.
    let (index, numbering, next_id) = crate::index::Index::decode_unchecked(snapshot)?;
    let numbering: std::collections::HashMap<String, u32> = numbering.into_iter().collect();

    apply_recorded(index, numbering, next_id, deltas, config)
}

/// Applies recorded change sets to an index, whatever it came from.
///
/// Two callers reach here: one that decoded the dump format, one that materialised the mapped one.
/// The loop is the same work - the deltas were written by the write path and say which entries
/// changed - so it lives once.
fn apply_recorded(
    mut index: crate::index::Index,
    mut numbering: std::collections::HashMap<String, u32>,
    mut next_id: u32,
    deltas: &[Vec<u8>],
    config: &crate::index::IndexConfig,
) -> Option<(
    crate::index::Index,
    std::collections::HashMap<String, u32>,
    u32,
)> {
    for delta in deltas {
        let changes = crate::index::Index::decode_delta(delta)?;
        index.apply_delta(&changes, config).ok()?;

        for change in &changes {
            match change {
                crate::index::IndexChange::Add { id, entry } => {
                    numbering.insert(entry.dn().to_string(), *id);
                    next_id = next_id.max(*id + 1);
                }
                crate::index::IndexChange::Remove { entry, .. } => {
                    numbering.remove(entry.dn());
                }
                crate::index::IndexChange::Replace { .. } => {}
            }
        }
    }

    Some((index, numbering, next_id))
}

/// Where the schema is built from: files on disk and definitions the protocol added.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchemaSources {
    pub files: Vec<std::path::PathBuf>,
    pub definitions: Vec<String>,
}

impl SchemaSources {
    /// What the configuration file says, before anything is added over the protocol.
    pub fn from_config(config: &Config) -> Self {
        Self {
            files: config.schema_files.clone(),
            definitions: config.schema_definitions.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Group, User};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn config(users: &str, groups: &str) -> Config {
        let mut config = Config {
            cache: crate::record_cache::CacheConfig::default(),
            backend: "file".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            listen_addr: "127.0.0.1:0".to_string(),
            update_interval: Duration::from_secs(300),
            log_path: None,
            debug: false,
            log_timestamp: false,
            log_caller: false,
            backends: Default::default(),
            respect_control_criticality: true,
            users_ou_name: "users".to_string(),
            groups_ou_name: "groups".to_string(),
            use_tls: false,
            server_cert: None,
            server_key: None,
            http_listen_addr: None,
            callback_auth_token: None,
            passwords: Default::default(),
            schema: crate::schema::Schema::core(),
            schema_mode: crate::schema::Mode::Strict,
            schema_files: Vec::new(),
            schema_definitions: Vec::new(),
            indexes: crate::index::IndexConfig::default(),
            referrals: Default::default(),
            server_id: 0,
            peers: Vec::new(),
            journal_keep: None,
            journal_max_age: None,
            conflict_log: None,
            sasl: Default::default(),
            acl: Default::default(),
            allow_unencrypted_bind: true,
            dangerous_settings: Vec::new(),
            integrity: crate::integrity::IntegrityConfig::default(),
            limits: Default::default(),
            observability: crate::config::ObservabilityConfig::default(),
            bootstrap: None,
            locale: (crate::i18n::Locale::english(), crate::i18n::Source::Default),
            locale_file: None,
            document: None,
        };
        config.backends.insert(
            "file".to_string(),
            serde_json::json!({
                "users_path": users,
                "groups_path": groups,
            }),
        );
        config
    }

    fn write(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write");
        path
    }

    /// A definition nobody has yet, in the syntax `.schema` files use.
    const FAVOURITE_DRINK: &str = "attributeType ( 1.3.6.1.4.1.59999.1.1 NAME 'favouriteDrink' \
         EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch \
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";

    #[tokio::test]
    async fn a_definition_from_the_configuration_reaches_the_schema_a_write_checks() {
        // The schema a reload builds has to include what the protocol added: a server that
        // restarted into a document carrying a definition, and then dropped it on the next
        // reload, would accept writes for a while and then start refusing them - the worst
        // shape a schema bug can take.
        let dir = tempdir().expect("tempdir");
        let users = write(
            dir.path(),
            "users.json",
            r#"[{"cn":"admin","objectClass":["top"]}]"#,
        );
        let groups = write(dir.path(), "groups.json", "[]");
        let mut config = config(
            users.to_str().expect("path"),
            groups.to_str().expect("path"),
        );
        config.schema_definitions = vec![FAVOURITE_DRINK.to_string()];

        let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
        let (source, _) = Source::load(&config, backend).await.expect("load");
        source
            .reload_schema()
            .await
            .expect("a definition from the configuration is adopted");

        let schema = source.schema();
        assert!(
            schema.attribute("favouritedrink").is_some(),
            "the definition the document carries is in force"
        );
        assert!(
            source
                .shared_schema()
                .read()
                .expect("schema")
                .attribute("favouritedrink")
                .is_some(),
            "and through the handle the connections hold, not a copy"
        );
    }

    #[tokio::test]
    async fn a_definition_that_does_not_parse_leaves_the_previous_schema_in_force() {
        let dir = tempdir().expect("tempdir");
        let users = write(
            dir.path(),
            "users.json",
            r#"[{"cn":"admin","objectClass":["top"]}]"#,
        );
        let groups = write(dir.path(), "groups.json", "[]");
        let mut config = config(
            users.to_str().expect("path"),
            groups.to_str().expect("path"),
        );
        config.schema_definitions = vec!["attributeType ( NAME 'noOid' )".to_string()];

        let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
        let (source, _) = Source::load(&config, backend).await.expect("load");

        let refusal = source
            .reload_schema()
            .await
            .expect_err("a definition without an OID is not usable");

        let text = refusal.to_string();
        assert!(
            text.contains("cn=schema,cn=config") && text.contains("definition 1"),
            "the answer says which definition and where it came from: {text}"
        );
        assert!(
            source.schema().attribute("nooid").is_none(),
            "nothing was adopted"
        );
    }

    #[tokio::test]
    async fn adopted_sources_are_what_the_next_reload_builds_from() {
        // The defect this guards: a reload that reads the sources the server started with would
        // quietly drop every definition added over the protocol, and the server would accept
        // writes against a rule it had just stopped publishing.
        let dir = tempdir().expect("tempdir");
        let users = write(
            dir.path(),
            "users.json",
            r#"[{"cn":"admin","objectClass":["top"]}]"#,
        );
        let groups = write(dir.path(), "groups.json", "[]");
        let config = config(
            users.to_str().expect("path"),
            groups.to_str().expect("path"),
        );
        let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
        let (source, _) = Source::load(&config, backend).await.expect("load");

        let adopted = SchemaSources {
            files: Vec::new(),
            definitions: vec![FAVOURITE_DRINK.to_string()],
        };
        source.adopt_schema_sources(adopted).await.expect("adopted");

        // A plain reload, as the signal and the HTTP route do it: it has to build from what was
        // adopted, not from what the process started with.
        source.reload_schema().await.expect("reload");

        assert!(
            source.schema().attribute("favouritedrink").is_some(),
            "the definition added at run time survives a reload"
        );
        assert_eq!(
            source.schema_sources().definitions,
            vec![FAVOURITE_DRINK.to_string()],
            "and the sources in force are the ones that were adopted"
        );
    }

    #[tokio::test]
    async fn reload_swaps_in_new_entries_and_keeps_the_old_snapshot_intact() {
        let dir = tempdir().expect("tempdir");
        let users = write(
            dir.path(),
            "users.json",
            r#"[{"cn":"admin","objectClass":["top"]}]"#,
        );
        let groups = write(dir.path(), "groups.json", "[]");
        let config = config(
            users.to_str().expect("path"),
            groups.to_str().expect("path"),
        );
        let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");

        let (source, first) = Source::load(&config, backend).await.expect("load");
        assert_eq!(first.users().len(), 1);

        std::fs::write(
            &users,
            r#"[{"cn":"admin","objectClass":["top"]},{"cn":"alice","objectClass":["top"]}]"#,
        )
        .expect("update fixture");

        let entries = source.reload().await.expect("reload");
        let second = source.directory().await;

        assert_eq!(second.users().len(), 2);
        assert_eq!(entries, 5, "domain, two ous and two users");
        assert_eq!(source.generation().await, 1);
        assert_eq!(
            first.users().len(),
            1,
            "the snapshot handed out earlier must not change under the caller"
        );
    }

    #[tokio::test]
    async fn failed_reload_keeps_the_previous_directory() {
        let dir = tempdir().expect("tempdir");
        let users = write(
            dir.path(),
            "users.json",
            r#"[{"cn":"admin","objectClass":["top"]}]"#,
        );
        let groups = write(dir.path(), "groups.json", "[]");
        let config = config(
            users.to_str().expect("path"),
            groups.to_str().expect("path"),
        );
        let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
        let (source, _) = Source::load(&config, backend).await.expect("load");

        std::fs::write(&users, "{ broken").expect("break fixture");
        let err = source.reload().await.expect_err("must fail");

        assert!(
            err.to_string().contains("error parsing"),
            "unexpected: {err}"
        );
        assert_eq!(source.directory().await.users().len(), 1);
        assert_eq!(source.generation().await, 0);
    }

    #[tokio::test]
    async fn reindex_rebuilds_over_the_snapshot_without_reloading_the_store() {
        // The distinction matters: `reload` re-reads the backend and bumps the generation,
        // `reindex` touches only what is already in memory.
        let dir = tempdir().expect("tempdir");
        let users = write(
            dir.path(),
            "users.json",
            r#"[{"cn":"admin","objectClass":["top","inetOrgPerson"],"sn":"Admin","mail":"root@example.com"}]"#,
        );
        let groups = write(dir.path(), "groups.json", "[]");
        let mut config = config(
            users.to_str().expect("path"),
            groups.to_str().expect("path"),
        );
        config.indexes = crate::index::IndexConfig {
            default: vec!["pres".to_string()],
            attributes: Default::default(),
            ..Default::default()
        };

        let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
        let (source, _) = Source::load(&config, backend).await.expect("load");

        let before = source.generation().await;
        let done = source.reindex().await.expect("reindex");

        assert_eq!(done.entries, source.directory().await.all().len());
        assert_eq!(
            source.generation().await,
            before,
            "a rebuild of the index is not a reload of the data"
        );
    }

    #[tokio::test]
    async fn reindex_reports_the_memory_the_index_holds() {
        let dir = tempdir().expect("tempdir");
        let users = write(
            dir.path(),
            "users.json",
            r#"[{"cn":"admin","objectClass":["top","inetOrgPerson"],"sn":"Admin","mail":"root@example.com"}]"#,
        );
        let groups = write(dir.path(), "groups.json", "[]");
        let mut config = config(
            users.to_str().expect("path"),
            groups.to_str().expect("path"),
        );
        config.indexes = crate::index::IndexConfig {
            default: vec!["pres".to_string()],
            attributes: Default::default(),
            ..Default::default()
        };

        let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
        let (source, _) = Source::load(&config, backend).await.expect("load");

        let done = source.reindex().await.expect("reindex");

        assert!(done.attributes > 0, "the fixture configures an index");
        assert!(
            done.bytes > 0,
            "an index that occupies no memory is not an index: {done:?}"
        );
    }

    #[tokio::test]
    async fn load_fails_when_the_backend_path_is_missing() {
        let dir = tempdir().expect("tempdir");
        let config = config(
            dir.path().join("absent.json").to_str().expect("path"),
            dir.path().join("groups.json").to_str().expect("path"),
        );
        let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");

        let err = Source::load(&config, backend)
            .await
            .err()
            .expect("must fail");

        assert!(
            err.to_string().contains("error reading"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn interval_reload_picks_up_changes_and_stops_on_signal() {
        let dir = tempdir().expect("tempdir");
        let users = write(
            dir.path(),
            "users.json",
            r#"[{"cn":"admin","objectClass":["top"]}]"#,
        );
        let groups = write(dir.path(), "groups.json", "[]");
        let config = config(
            users.to_str().expect("path"),
            groups.to_str().expect("path"),
        );
        let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
        let (source, _) = Source::load(&config, backend).await.expect("load");

        std::fs::write(
            &users,
            r#"[{"cn":"admin","objectClass":["top"]},{"cn":"bob","objectClass":["top"]}]"#,
        )
        .expect("update fixture");

        let (stop_tx, stop_rx) = watch::channel(false);
        let task = tokio::spawn(reload_on_interval(
            Arc::clone(&source),
            Duration::from_millis(50),
            stop_rx,
        ));

        // Wait for at least one reload without a fixed sleep race.
        let mut waited = Duration::ZERO;
        while source.generation().await == 0 && waited < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(20)).await;
            waited += Duration::from_millis(20);
        }

        assert_eq!(source.directory().await.users().len(), 2);
        stop_tx.send(true).expect("stop");
        task.await.expect("task ends after the stop signal");
    }

    #[tokio::test]
    async fn zero_interval_disables_the_timer() {
        let dir = tempdir().expect("tempdir");
        let users = write(dir.path(), "users.json", "[]");
        let groups = write(dir.path(), "groups.json", "[]");
        let config = config(
            users.to_str().expect("path"),
            groups.to_str().expect("path"),
        );
        let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");
        let (source, _) = Source::load(&config, backend).await.expect("load");
        let (_tx, rx) = watch::channel(false);

        reload_on_interval(source.clone(), Duration::ZERO, rx).await;

        assert_eq!(source.generation().await, 0);
    }

    #[test]
    fn test_fixtures_type_check() {
        // Keeps the unused imports honest: the model types are what the fixtures
        // above produce after parsing.
        let _ = std::mem::size_of::<User>();
        let _ = std::mem::size_of::<Group>();
    }
}
