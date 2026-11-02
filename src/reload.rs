//! Keeping the directory up to date: an interval, a signal and an HTTP callback.
//!
//! gorestldap had all three. The difference here is that a reload builds a whole
//! new [`Directory`] and swaps the `Arc`, so a request in flight finishes against
//! one consistent snapshot instead of seeing a half-updated tree.

use std::sync::Arc;

use tokio::sync::{RwLock, watch};
use tokio::time::{Duration, MissedTickBehavior};

use crate::backend::{Backend, BackendError};
use crate::config::Config;
use crate::directory::Directory;
use crate::index::IndexConfig;
use crate::schema::{Mode as SchemaMode, Schema};

/// Holds the current directory snapshot and knows how to rebuild it.
pub struct Source {
    backend: Arc<Backend>,
    base_dn: String,
    users_ou_name: String,
    groups_ou_name: String,
    current: RwLock<Arc<Directory>>,
    generation: RwLock<u64>,
    schema: Schema,
    schema_mode: SchemaMode,
    indexes: IndexConfig,
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
            schema: config.schema.clone(),
            schema_mode: config.schema_mode,
        });

        Ok((source, directory))
    }

    pub async fn directory(&self) -> Arc<Directory> {
        let directory = self.current.read().await;
        Arc::clone(&directory)
    }

    /// Number of successful reloads so far, for logging and tests.
    pub async fn generation(&self) -> u64 {
        *self.generation.read().await
    }

    /// Reloads from the backend and swaps the snapshot.
    ///
    /// On error the previous snapshot stays in place: a backend hiccup must not
    /// empty the directory that clients are using.
    pub async fn reload(&self) -> Result<usize, BackendError> {
        let data = self.backend.load().await?;
        let directory = data
            .into_directory(&self.base_dn, &self.users_ou_name, &self.groups_ou_name)
            .with_indexes(&self.indexes)?;
        let entries = directory
            .entries(&self.base_dn, crate::directory::Scope::Subtree)
            .len();

        check_schema(&directory, &self.schema, self.schema_mode)?;

        *self.current.write().await = Arc::new(directory);
        *self.generation.write().await += 1;

        Ok(entries)
    }
}

/// Validates every entry according to the configured mode.
///
/// `strict` refuses the load, so a directory that does not match its schema never
/// comes up looking healthy; `warn` reports and proceeds, which is what a migration
/// from foreign data needs; `off` skips checking and keeps the schema published.
fn check_schema(
    directory: &Directory,
    schema: &crate::schema::Schema,
    mode: SchemaMode,
) -> Result<(), BackendError> {
    if mode == SchemaMode::Off {
        return Ok(());
    }

    let mut problems = Vec::new();
    for entry in directory.all() {
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
        return Ok(());
    }

    match mode {
        SchemaMode::Warn => {
            for problem in &problems {
                eprintln!("schema warning: {problem}");
            }
            Ok(())
        }
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
    mut stop: watch::Receiver<bool>,
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
                Ok(entries) => println!("reload: {entries} entries (generation {})", source.generation().await),
                Err(err) => eprintln!("reload failed, keeping the current directory: {err}"),
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
            indexes: crate::index::IndexConfig::default(),
            acl: Default::default(),
            allow_plaintext_simple_bind: true,
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
