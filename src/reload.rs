//! Keeping the directory up to date: an interval, a signal and an HTTP callback.
//!
//! gorestldap had all three. The difference here is that a reload builds a whole
//! new [`Directory`] and swaps the `Arc`, so a request in flight finishes against
//! one consistent snapshot instead of seeing a half-updated tree.

use std::sync::Arc;

use tokio::sync::{RwLock, watch};
use tokio::time::{Duration, MissedTickBehavior};

use crate::backend::{Backend, BackendError, EntryChange};
use crate::config::Config;
use crate::directory::Directory;
use crate::index::IndexConfig;
use crate::model::Entry;
use crate::schema::{Mode as SchemaMode, Schema};

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
    /// The files the schema was read from, re-read on a reload.
    schema_files: Vec<std::path::PathBuf>,
    schema_mode: SchemaMode,
    indexes: IndexConfig,
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
        let data = backend.load().await?;
        let directory = data
            .into_directory(
                &config.base_dn,
                &config.users_ou_name,
                &config.groups_ou_name,
            )
            .with_indexes(&config.indexes)?;
        let directory = Arc::new(directory);

        check_schema(&directory, &config.schema, config.schema_mode)?;

        let source = Arc::new(Self {
            backend: Arc::new(backend),
            base_dn: config.base_dn.clone(),
            users_ou_name: config.users_ou_name.clone(),
            groups_ou_name: config.groups_ou_name.clone(),
            current: RwLock::new(Arc::clone(&directory)),
            generation: RwLock::new(0),
            indexes: config.indexes.clone(),
            schema: crate::security::shared_schema(config.schema.clone()),
            schema_files: config.schema_files.clone(),
            schema_mode: config.schema_mode,
            store_reads: std::sync::atomic::AtomicU64::new(1),
        });

        Ok((source, directory))
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
        let mut schema = Schema::core();

        for path in &self.schema_files {
            let text =
                std::fs::read_to_string(path).map_err(|source| BackendError::SchemaRead {
                    path: path.display().to_string(),
                    source,
                })?;

            schema
                .extend(&text)
                .map_err(|source| BackendError::SchemaParse {
                    path: path.display().to_string(),
                    detail: source.to_string(),
                })?;
        }

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
        self.backend.apply(changes).await?;

        if let Some(entries) = self.apply_in_place(changes).await? {
            return Ok(entries);
        }

        self.reload().await
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

        // Only a replace keeps the ids of the other entries. An add or a delete shifts every id
        // after it, and every posting list would have to move with them.
        let mut replacements = Vec::with_capacity(changes.len());
        for change in changes {
            let EntryChange::Upsert { entry } = change else {
                return Ok(None);
            };
            replacements.push(entry);
        }

        // The check a reload would make, over the entries that changed. Every other entry was
        // checked when it was read; checking them again would make a write cost the directory
        // again, which is the whole cost this path exists to remove.
        let changed: Vec<Entry> = replacements.iter().map(|entry| (*entry).clone()).collect();
        for problem in check_entries_collect(&changed, &self.schema(), self.schema_mode)? {
            eprintln!("{}", crate::i18n::t("warn.schema", &[("detail", &problem)]));
        }

        // The snapshot moves even though the store was not read again: a paged search that is
        // half way through must notice that the directory changed under it.
        let snapshot = {
            let mut generation = self.generation.write().await;
            *generation += 1;
            *generation
        };

        let mut current = self.current.write().await;

        // Every DN must already be there before anything is touched: an upsert of a new entry is
        // an add, and an add moves the ids after it. Checking first is what lets the loop below
        // be unconditional, so a refusal cannot leave the snapshot half written.
        for entry in &replacements {
            if current.position(entry.dn()).is_none() {
                return Ok(None);
            }
        }

        // Unique means no reader holds this snapshot, so patching it is invisible to everyone
        // else - there is nobody else. Shared means a search is running against it, and the copy
        // is then the price of not changing what that search sees.
        if Arc::get_mut(&mut current).is_none() {
            let copy = (**current).clone();
            *current = Arc::new(copy);
        }
        let directory: &mut Directory = Arc::get_mut(&mut current).expect("made unique above");

        for entry in replacements {
            directory.replace_entry_in_place(entry.clone(), &self.indexes)?;
        }

        directory.set_snapshot(snapshot);
        let entries = directory
            .entries(&self.base_dn, crate::directory::Scope::Subtree)
            .len();

        Ok(Some(entries))
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
        let entries = directory
            .entries(&self.base_dn, crate::directory::Scope::Subtree)
            .len();

        check_schema(&directory, &self.schema(), self.schema_mode)?;

        // The snapshot number is what a paged search uses to notice that the directory moved
        // under it; it is taken with the swap, so the number and the contents cannot disagree.
        let snapshot = {
            let mut generation = self.generation.write().await;
            *generation += 1;
            *generation
        };
        let directory = directory.at_snapshot(snapshot);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Group, User};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn config(users: &str, groups: &str) -> Config {
        let mut config = Config {
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
            indexes: crate::index::IndexConfig::default(),
            acl: Default::default(),
            allow_unencrypted_bind: true,
            dangerous_settings: Vec::new(),
            integrity: crate::integrity::IntegrityConfig::default(),
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
