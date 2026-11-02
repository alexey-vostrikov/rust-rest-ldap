//! Configuration generations: versioned, atomic, collected.
//!
//! OpenLDAP keeps its configuration in `slapd.d`, a directory tree of LDIF files - one entry
//! per file, the directory names spelling out the DIT, and `{X}` in an RDN to impose an order
//! that LDAP itself does not have. The documentation is explicit that those files must never
//! be edited by hand, and the reason is structural: a change spanning several files is not a
//! transaction, so a failure halfway leaves a configuration nobody wrote, and there is no way
//! back to the one that worked.
//!
//! This is the same idea with the three properties that name implies:
//!
//! - **A generation is a complete configuration**, one file. Never a diff, never a partial
//!   tree: what is in force is exactly one document, and it is readable on its own.
//! - **A commit is atomic.** The new generation is written to a temporary name, flushed to
//!   disk, renamed into place, and only then does `current` point at it. A crash before the
//!   rename leaves the previous generation in force; a crash after it leaves the new one. There
//!   is no state in between, which is what "atomic" has to mean for somebody reading the
//!   directory rather than the code.
//! - **Old generations are collected, not accumulated.** A directory that edits its
//!   configuration keeps a bounded number of past versions, and the ones that go are deleted
//!   as a whole file rather than unpicked from a tree.
//!
//! Metadata lives in comments at the top of the document, so a generation stays a valid
//! configuration for any YAML parser and still says who wrote it, when, and why. One file, one
//! rename, nothing to keep in sync.
//!
//! This is the substrate a writable `cn=config` will write through: every LDAP modification
//! becomes a generation, and the history that makes a mistake recoverable comes for free.

use std::io::Write;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// The name of the pointer that says which generation is in force.
const CURRENT: &str = "current";

/// The directory the generation files live in.
const GENERATIONS: &str = "generations";

/// The file that serialises commits.
///
/// Two commits racing would both read the history, both compute the same next number, and
/// both publish a file - different names, same number, and `current` pointing at whichever
/// renamed last. The loser is not lost, it is shadowed: the history then holds two
/// generations numbered alike, and a rollback by number becomes ambiguous. A directory with
/// `cn=config` writing through this will have concurrent writers, so the lock is not
/// defensive politeness, it is the invariant.
const LOCK: &str = ".commit.lock";

/// How long a commit waits for the lock before giving up.
///
/// A commit is a few file operations; a second is generous. Waiting for ever would turn one
/// stuck writer into a directory nobody can configure, which is the failure mode a lock is
/// supposed to prevent and not to cause.
const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// How many generations are kept by default.
///
/// Ten is enough to walk back through a working afternoon and small enough that the directory
/// does not grow without bound. `collect` takes the number as an argument, so an operator can
/// keep more.
pub const KEEP: usize = 10;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot {action} '{path}': {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "'{path}' is a generation store but holds no '{CURRENT}' pointer; run the server once to \
         create the first generation, or point at a configuration file instead"
    )]
    NoCurrent { path: PathBuf },
    #[error("generation {number} does not exist")]
    Unknown { number: u64 },
    #[error(
        "generation '{name}' is not named as a generation: expected \
         <number>-<timestamp>.yaml"
    )]
    BadName { name: String },
    #[error(
        "the configuration store was asked to keep 0 generations; the one in force would be the \
         only one left, and a rollback needs at least two"
    )]
    KeeperTooSmall,
    #[error(
        "another commit has held the lock '{path}' for more than {waited:?}; a commit takes \
         milliseconds, so this is a stuck writer - remove the file if nothing is writing"
    )]
    Locked {
        path: PathBuf,
        waited: std::time::Duration,
    },
}

/// What an operator asked the store to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Commit the configuration in force as a new generation.
    Commit,
    /// Go back to generation `n`, as a new commit.
    Rollback(u64),
    /// List the generations.
    History,
}

impl Command {
    /// The flag name, for a message that tells the operator what is missing.
    pub fn name(self) -> &'static str {
        match self {
            Command::Commit => "config-commit",
            Command::Rollback(_) => "config-rollback",
            Command::History => "config-history",
        }
    }
}

/// One configuration, as it was committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    /// Monotonic number, assigned at commit.
    pub number: u64,
    /// When it was committed, as the `createTimestamp` format.
    pub created: String,
    /// Who committed it: `cli`, `file`, or an LDAP identity once `cn=config` writes here.
    pub author: String,
    /// Why, in the operator's words. Empty when nobody said.
    pub note: String,
    /// The generation file.
    pub path: PathBuf,
}

impl Generation {
    /// The document itself, metadata comments included.
    pub fn read(&self) -> Result<String, Error> {
        std::fs::read_to_string(&self.path).map_err(|source| Error::Io {
            action: "read",
            path: self.path.clone(),
            source,
        })
    }

    /// The configuration without its metadata header, ready to be parsed.
    pub fn body(&self) -> Result<String, Error> {
        Ok(split_header(&self.read()?).1.to_string())
    }
}

/// A directory of configuration generations.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Opens the store rooted at `root`, creating nothing.
    ///
    /// A path that does not exist yet is not an error: `commit` creates the structure, and a
    /// store that has never been written to is a server whose configuration is still the file
    /// it was started with.
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Whether `path` is a generation store rather than a configuration file.
    ///
    /// The test is a directory, because that is the only thing it can be: a configuration is a
    /// file, and a directory of them is this. No new configuration key is needed to say which,
    /// and an operator who points `-c` at the wrong one gets a message instead of a parse error
    /// about a directory.
    pub fn is_store(path: &Path) -> bool {
        path.is_dir()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn generations(&self) -> PathBuf {
        self.root.join(GENERATIONS)
    }

    fn pointer(&self) -> PathBuf {
        self.root.join(CURRENT)
    }

    /// The generation in force, if the store has one.
    pub fn current(&self) -> Result<Option<Generation>, Error> {
        let pointer = self.pointer();
        let target = match std::fs::read_link(&pointer) {
            Ok(target) => target,
            // Not a symlink: either absent, or a regular file written by something that is not
            // this code. Absent is the ordinary case for a store nobody has committed to.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(Error::Io {
                    action: "read the pointer of",
                    path: pointer,
                    source,
                });
            }
        };

        // The link is stored relative to the store, so the store can be moved or copied. An
        // absolute one is still honoured, because a hand-made store may have written one.
        let path = if target.is_absolute() {
            target.clone()
        } else {
            self.root.join(&target)
        };

        self.describe(&path).map(Some)
    }

    /// The document in force, without its metadata header.
    pub fn read_current(&self) -> Result<Option<String>, Error> {
        match self.current()? {
            Some(generation) => generation.body().map(Some),
            None => Ok(None),
        }
    }

    /// Every generation, oldest first.
    pub fn history(&self) -> Result<Vec<Generation>, Error> {
        let directory = self.generations();
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(Error::Io {
                    action: "list",
                    path: directory,
                    source,
                });
            }
        };

        let mut found = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| Error::Io {
                action: "list",
                path: directory.clone(),
                source,
            })?;
            let name = entry.file_name().to_string_lossy().to_string();

            // A temporary file from an interrupted commit is not a generation and must not be
            // reported as one. It is left for `collect` to sweep.
            if name.starts_with('.') || !name.ends_with(".yaml") {
                continue;
            }

            found.push(self.describe(&entry.path())?);
        }

        found.sort_by_key(|generation| generation.number);
        Ok(found)
    }

    /// Commits `configuration` as a new generation and points `current` at it.
    ///
    /// The order is the whole guarantee:
    ///
    /// 1. write the document to a temporary name inside the store;
    /// 2. flush it, so the bytes are on disk before anything refers to them;
    /// 3. rename it to its generation name - one filesystem operation;
    /// 4. create a fresh pointer under a temporary name and rename it over `current`.
    ///
    /// Every step is atomic or comes before the step that makes it visible. A crash at any
    /// point leaves either the old generation in force or the new one, never a mixture and
    /// never a dangling pointer.
    pub fn commit(
        &self,
        configuration: &str,
        author: &str,
        note: &str,
    ) -> Result<Generation, Error> {
        self.ensure_structure()?;

        // Serialised: two commits that both read the history would both compute the same next
        // number and publish two files under it.
        let _lock = self.lock()?;

        let number = self.history()?.last().map_or(1, |last| last.number + 1);
        let created = crate::operational::generalized_time(std::time::SystemTime::now());
        let name = format!("{number:010}-{created}.yaml");
        let path = self.generations().join(&name);

        let document = with_header(configuration, number, &created, author, note);

        // Step 1 and 2: a temporary name nobody looks at, flushed. The name carries the
        // process and a counter because the lock can be taken by another process after this
        // one was killed; a shared temporary name would have two writers rename each other's
        // half-written file into place.
        let temporary =
            self.generations()
                .join(format!(".{name}.{}-{}.tmp", std::process::id(), unique()));
        write_flushed(&temporary, &document)?;

        // Step 3: one rename makes the generation exist under its real name.
        std::fs::rename(&temporary, &path).map_err(|source| Error::Io {
            action: "publish",
            path: path.clone(),
            source,
        })?;

        // Step 4: the pointer. Created fresh and renamed over, because `rename` onto a symlink
        // replaces the link itself rather than following it - a plain `write` to `current`
        // would write through the link into the generation file.
        let pointer = self.pointer();
        let pointer_temporary = self.root.join(format!(
            ".{CURRENT}.{}-{}.tmp",
            std::process::id(),
            unique()
        ));

        let relative = Path::new(GENERATIONS).join(&name);
        let _ = std::fs::remove_file(&pointer_temporary);
        write_symlink(&relative, &pointer_temporary)?;

        std::fs::rename(&pointer_temporary, &pointer).map_err(|source| Error::Io {
            action: "switch",
            path: pointer,
            source,
        })?;

        sync_directory(&self.root);

        Ok(Generation {
            number,
            created,
            author: author.to_string(),
            note: note.to_string(),
            path,
        })
    }

    /// Commits the configuration in force again, unchanged.
    ///
    /// This is how a store is created from a plain file: start with `-c config.yaml`, commit
    /// once, and from then on point `-c` at the directory. It also gives the history a point
    /// to compare against before the first change, which is what makes a diff meaningful
    /// later.
    pub fn commit_current(&self, author: &str, note: &str) -> Result<Generation, Error> {
        match self.read_current()? {
            Some(body) => self.commit(&body, author, note),
            None => Err(Error::NoCurrent {
                path: self.root.clone(),
            }),
        }
    }

    /// Points `current` back at an existing generation, as a new commit.
    ///
    /// A rollback is a commit of an older document rather than a pointer moved backwards: the
    /// history then says that somebody rolled back, and when, which a moved pointer would hide.
    pub fn rollback(&self, number: u64, author: &str) -> Result<Generation, Error> {
        let target = self
            .history()?
            .into_iter()
            .find(|generation| generation.number == number)
            .ok_or(Error::Unknown { number })?;

        let note = format!("rolled back to generation {number}");
        self.commit(&target.body()?, author, &note)
    }

    /// Deletes the oldest generations, keeping the `keep` most recent.
    ///
    /// The generation in force is never deleted, whatever the arithmetic says: a store whose
    /// pointer dangles is a directory that cannot start.
    pub fn collect(&self, keep: usize) -> Result<Vec<u64>, Error> {
        if keep == 0 {
            return Err(Error::KeeperTooSmall);
        }

        // Under the lock as well: collecting while another process commits could otherwise
        // delete a generation it is about to make current.
        let _lock = self.lock()?;

        let generations = self.history()?;
        let current = self.current()?.map(|generation| generation.number);

        let mut removed = Vec::new();

        if generations.len() <= keep {
            // Still sweep the debris of an interrupted commit: a temporary file is not a
            // generation, and leaving it means the store accumulates files nothing reads.
            self.sweep_temporaries();
            return Ok(removed);
        }

        let doomed = generations.len() - keep;
        for generation in generations.iter().take(doomed) {
            if Some(generation.number) == current {
                continue;
            }

            std::fs::remove_file(&generation.path).map_err(|source| Error::Io {
                action: "delete",
                path: generation.path.clone(),
                source,
            })?;
            removed.push(generation.number);
        }

        self.sweep_temporaries();

        Ok(removed)
    }

    /// Takes the commit lock, waiting briefly for another writer.
    ///
    /// The lock is a file created with `create_new`, which is atomic on every filesystem this
    /// runs on. It is held for the length of one commit and removed by `Drop`, so a panic
    /// releases it - and a process killed outright leaves it behind, which is why the error
    /// names the file and says what to do about it rather than waiting silently.
    fn lock(&self) -> Result<Lock, Error> {
        let path = self.root.join(LOCK);
        let deadline = std::time::Instant::now() + LOCK_TIMEOUT;

        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    // The pid is not read back by anything; it is there so an operator who
                    // finds the file knows which process to look at.
                    let _ = writeln!(file, "{}", std::process::id());
                    return Ok(Lock { path });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if std::time::Instant::now() >= deadline {
                        return Err(Error::Locked {
                            path,
                            waited: LOCK_TIMEOUT,
                        });
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(source) => {
                    return Err(Error::Io {
                        action: "lock",
                        path,
                        source,
                    });
                }
            }
        }
    }

    /// Removes temporary files left by an interrupted commit.
    fn sweep_temporaries(&self) {
        let Ok(entries) = std::fs::read_dir(self.generations()) else {
            return;
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Only files this code created and abandoned: a `.tmp` in the generations
            // directory. The lock lives in the store root and is never swept.
            if name.starts_with('.') && name.ends_with(".tmp") {
                let _ = std::fs::remove_file(entry.path());
            }
        }

        let pointer = self.root.join(format!(".{CURRENT}.tmp"));
        let _ = std::fs::remove_file(pointer);
        // The lock is deliberately not swept: it belongs to whoever holds it, and deleting it
        // would hand the next two writers the same number.
    }

    fn ensure_structure(&self) -> Result<(), Error> {
        std::fs::create_dir_all(self.generations()).map_err(|source| Error::Io {
            action: "create",
            path: self.generations(),
            source,
        })
    }

    /// Reads the metadata of one generation file.
    fn describe(&self, path: &Path) -> Result<Generation, Error> {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();

        let number = name
            .split_once('-')
            .and_then(|(number, _)| number.parse::<u64>().ok())
            .ok_or_else(|| Error::BadName {
                name: clone_string(&name),
            })?;

        let document = std::fs::read_to_string(path).map_err(|source| Error::Io {
            action: "read",
            path: path.to_path_buf(),
            source,
        })?;

        let (header, _) = split_header(&document);
        let (created, author, note) = parse_header(header);

        Ok(Generation {
            number,
            created,
            author,
            note,
            path: path.to_path_buf(),
        })
    }
}

/// A held commit lock, released when it goes out of scope.
struct Lock {
    path: PathBuf,
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn clone_string(text: &str) -> String {
    text.to_string()
}

/// Writes `body` with the metadata header in front of it.
fn with_header(body: &str, number: u64, created: &str, author: &str, note: &str) -> String {
    let mut out = String::new();
    out.push_str("# Managed by rust-rest-ldap: a configuration generation.\n");
    out.push_str("#\n");
    out.push_str(
        "# Everything above the first line that is not a comment is metadata. Editing this\n",
    );
    out.push_str(
        "# file does nothing: the server reads the generation `current` points at, and that\n",
    );
    out.push_str("# pointer only moves on a commit. Write a new generation instead.\n");
    out.push_str(&format!("# generation: {number}\n"));
    out.push_str(&format!("# created: {created}\n"));
    out.push_str(&format!("# author: {author}\n"));
    if !note.is_empty() {
        // A note with a newline in it would break the header; comments are one line each.
        let note = note.replace(['\n', '\r'], " ");
        out.push_str(&format!("# note: {note}\n"));
    }

    out.push('\n');
    out.push_str(body);
    if !body.ends_with('\n') {
        out.push('\n');
    }

    out
}

/// Splits a document into its leading comment block and the rest.
fn split_header(document: &str) -> (&str, &str) {
    let mut offset = 0;

    for line in document.split_inclusive('\n') {
        let trimmed = line.trim_end();
        // The header ends at the first line that is neither a comment nor blank; blank lines
        // between the comments and the body belong to the header, not to the body.
        if !trimmed.starts_with('#') && !trimmed.is_empty() {
            return (&document[..offset], &document[offset..]);
        }
        offset += line.len();
    }

    (document, "")
}

/// Reads `generation`, `created`, `author` and `note` out of a header.
fn parse_header(header: &str) -> (String, String, String) {
    let mut created = String::new();
    let mut author = String::new();
    let mut note = String::new();

    for line in header.lines() {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some((key, value)) = rest.trim_start().split_once(':') else {
            continue;
        };

        let value = value.trim().to_string();
        match key.trim() {
            "created" => created = value,
            "author" => author = value,
            "note" => note = value,
            _ => {}
        }
    }

    (created, author, note)
}

/// A number that is unique among the writers of one process.
///
/// Thread ids are not reused within a run on every platform, and treating them as unique
/// would be a guess; a counter is not.
fn unique() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Writes `body` to `path` and flushes it, so the bytes are on disk before the rename.
fn write_flushed(path: &Path, body: &str) -> Result<(), Error> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|source| Error::Io {
            action: "create",
            path: path.to_path_buf(),
            source,
        })?;

    file.write_all(body.as_bytes())
        .map_err(|source| Error::Io {
            action: "write",
            path: path.to_path_buf(),
            source,
        })?;

    // `sync_all` and not `flush`: the point is the disk, and a buffer flushed to the kernel is
    // still lost by a power cut.
    file.sync_all().map_err(|source| Error::Io {
        action: "flush",
        path: path.to_path_buf(),
        source,
    })?;

    Ok(())
}

#[cfg(unix)]
fn write_symlink(target: &Path, link: &Path) -> Result<(), Error> {
    std::os::unix::fs::symlink(target, link).map_err(|source| Error::Io {
        action: "create the pointer of",
        path: link.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn write_symlink(target: &Path, link: &Path) -> Result<(), Error> {
    // No symlinks: the pointer is a file holding the relative path, read by `current` through
    // the same path. The atomicity comes from the rename either way.
    std::fs::write(link, target.to_string_lossy().as_bytes()).map_err(|source| Error::Io {
        action: "create the pointer of",
        path: link.to_path_buf(),
        source,
    })
}

/// Pushes the directory's own entries to disk, so a rename survives a power cut.
fn sync_directory(path: &Path) {
    #[cfg(unix)]
    if let Ok(directory) = std::fs::File::open(path) {
        let _ = directory.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &std::path::Path) -> Store {
        Store::open(dir)
    }

    const CONFIG: &str = "base_dn: dc=example,dc=com\n";

    #[test]
    fn a_fresh_store_has_no_generation_and_no_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        assert_eq!(store.current().expect("current"), None);
        assert_eq!(store.read_current().expect("read"), None);
        assert!(store.history().expect("history").is_empty());
    }

    #[test]
    fn a_commit_becomes_the_generation_in_force() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        let committed = store.commit(CONFIG, "cli", "first").expect("commit");

        assert_eq!(committed.number, 1);
        assert_eq!(committed.author, "cli");
        assert_eq!(committed.note, "first");

        let current = store.current().expect("current").expect("a generation");
        assert_eq!(current.number, 1);
        assert_eq!(
            store.read_current().expect("read").as_deref(),
            Some(CONFIG),
            "the body comes back without the metadata header"
        );
    }

    #[test]
    fn numbers_are_monotonic_and_the_history_is_ordered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        for index in 1..=3 {
            let committed = store
                .commit(
                    &format!("base_dn: dc={index},dc=example,dc=com\n"),
                    "cli",
                    "",
                )
                .expect("commit");
            assert_eq!(committed.number, index, "numbers must not reuse or skip");
        }

        let history = store.history().expect("history");
        assert_eq!(
            history.iter().map(|g| g.number).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            store.read_current().expect("read").as_deref(),
            Some("base_dn: dc=3,dc=example,dc=com\n"),
            "the last commit is in force"
        );
    }

    #[test]
    fn a_commit_replaces_the_pointer_and_leaves_the_generations_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        store.commit(CONFIG, "cli", "first").expect("first");
        let first = store.current().expect("current").expect("generation");

        store
            .commit("base_dn: dc=other,dc=example,dc=com\n", "cli", "second")
            .expect("second");

        // The first file must still hold what it held: the pointer moved, the document did not.
        assert_eq!(
            first.body().expect("body"),
            CONFIG,
            "a committed generation is immutable"
        );
    }

    #[test]
    fn a_rollback_is_a_new_commit_of_an_old_document() {
        // Not a pointer moved backwards: the history has to say that somebody rolled back, and
        // when, which a silently moved pointer would hide.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        store.commit(CONFIG, "cli", "first").expect("first");
        store
            .commit("base_dn: dc=other,dc=example,dc=com\n", "cli", "second")
            .expect("second");

        let rolled = store.rollback(1, "cli").expect("rollback");

        assert_eq!(rolled.number, 3, "a rollback is a commit");
        assert_eq!(
            store.read_current().expect("read").as_deref(),
            Some(CONFIG),
            "the document of generation 1 is back in force"
        );
        assert!(
            rolled.note.contains("generation 1"),
            "the history must say what was rolled back to: {}",
            rolled.note
        );
        assert_eq!(store.history().expect("history").len(), 3);
    }

    #[test]
    fn a_rollback_to_a_generation_that_does_not_exist_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());
        store.commit(CONFIG, "cli", "").expect("commit");

        let err = store.rollback(99, "cli").expect_err("must refuse");
        assert!(matches!(err, Error::Unknown { number: 99 }), "{err}");
    }

    #[test]
    fn collection_keeps_the_newest_and_never_the_generation_in_force() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        for index in 1..=6 {
            store
                .commit(
                    &format!("base_dn: dc={index},dc=example,dc=com\n"),
                    "cli",
                    "",
                )
                .expect("commit");
        }

        let removed = store.collect(3).expect("collect");

        assert_eq!(removed, vec![1, 2, 3], "the oldest three go");
        let left: Vec<u64> = store
            .history()
            .expect("history")
            .iter()
            .map(|g| g.number)
            .collect();
        assert_eq!(left, vec![4, 5, 6]);
        assert_eq!(
            store.current().expect("current").map(|g| g.number),
            Some(6),
            "the generation in force survives collection"
        );
    }

    #[test]
    fn collection_with_nothing_to_do_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());
        store.commit(CONFIG, "cli", "").expect("commit");

        assert!(store.collect(KEEP).expect("collect").is_empty());
        assert_eq!(store.history().expect("history").len(), 1);
    }

    #[test]
    fn keeping_nothing_is_refused_because_a_rollback_needs_two() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());
        store.commit(CONFIG, "cli", "").expect("commit");

        let err = store.collect(0).expect_err("must refuse");
        assert!(matches!(err, Error::KeeperTooSmall), "{err}");
    }

    #[test]
    fn an_interrupted_commit_leaves_no_generation_and_is_swept() {
        // The shape of a crash between writing the temporary file and renaming it.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());
        store.commit(CONFIG, "cli", "first").expect("first");

        let debris = store
            .generations()
            .join(".0000000002-20260101T000000Z.yaml.tmp");
        std::fs::write(&debris, "base_dn: dc=half,dc=example,dc=com\n").expect("write");

        assert_eq!(
            store.history().expect("history").len(),
            1,
            "a temporary file is not a generation"
        );
        assert_eq!(
            store.current().expect("current").map(|g| g.number),
            Some(1),
            "and it certainly does not become the one in force"
        );

        store.collect(KEEP).expect("collect");
        assert!(!debris.exists(), "collection sweeps the debris");
    }

    #[test]
    fn the_pointer_is_relative_so_the_store_can_be_moved() {
        // An absolute symlink breaks the moment the directory is copied to another machine,
        // which is exactly when somebody wants the backup to work.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());
        store.commit(CONFIG, "cli", "").expect("commit");

        let target = std::fs::read_link(store.pointer()).expect("link");
        assert!(
            target.is_relative(),
            "the pointer must be relative, it is {}",
            target.display()
        );
    }

    #[test]
    fn a_generation_file_carries_who_and_why() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());
        let committed = store
            .commit(
                CONFIG,
                "cn=admin,dc=example,dc=com",
                "raised the search limit",
            )
            .expect("commit");

        let document = committed.read().expect("read");
        assert!(document.contains("# author: cn=admin,dc=example,dc=com"));
        assert!(document.contains("# note: raised the search limit"));
        assert!(document.contains("generation: 1"));

        // And the document is still a configuration: the header is comments, so any YAML
        // parser reads the body and ignores the rest.
        assert!(document.contains(CONFIG.trim()));
    }

    #[test]
    fn a_note_with_a_newline_does_not_break_the_header() {
        // A commit message typed at a prompt can be pasted with a newline in it; a header line
        // broken in two would end the comment block in the middle of the metadata.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        let committed = store
            .commit(CONFIG, "cli", "first line\nsecond line")
            .expect("commit");

        let document = committed.read().expect("read");
        for line in document
            .lines()
            .take_while(|line| line.starts_with('#') || line.is_empty())
        {
            assert!(
                !line.contains("second line") || line.starts_with("# note:"),
                "the note must stay on one line: {line}"
            );
        }

        let reread = store.current().expect("current").expect("generation");
        assert!(
            reread.note.contains("first line") && reread.note.contains("second line"),
            "the note survives, joined: {:?}",
            reread.note
        );
    }

    #[test]
    fn a_store_directory_is_recognised_and_a_file_is_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(Store::is_store(dir.path()));

        let file = dir.path().join("config.yaml");
        std::fs::write(&file, CONFIG).expect("write");
        assert!(!Store::is_store(&file));
    }

    #[test]
    fn concurrent_commits_get_distinct_numbers() {
        // The failure this prevents is quiet: two writers read the same history, compute the
        // same next number, and publish two files with different timestamps and one number.
        // The history then has two generations numbered alike and a rollback by number is
        // ambiguous.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        const WRITERS: usize = 8;
        let mut handles = Vec::new();

        for writer in 0..WRITERS {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                store
                    .commit(
                        &format!("base_dn: dc={writer},dc=example,dc=com\n"),
                        "test",
                        "",
                    )
                    .map(|generation| generation.number)
            }));
        }

        let numbers: Vec<u64> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread").expect("commit"))
            .collect();

        let mut sorted = numbers.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            WRITERS,
            "every writer must get its own number: {numbers:?}"
        );

        let history = store.history().expect("history");
        assert_eq!(history.len(), WRITERS);
        assert_eq!(
            history.last().map(|generation| generation.number),
            Some(WRITERS as u64),
            "the numbers run from one without a gap"
        );
    }

    #[test]
    fn a_lock_left_by_a_dead_process_is_reported_rather_than_waited_on_for_ever() {
        // A process killed between taking the lock and releasing it leaves the file behind.
        // Waiting for ever would turn one stuck writer into a directory nobody can configure.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());
        store.commit(CONFIG, "cli", "first").expect("first");

        std::fs::write(store.root.join(LOCK), "999999\n").expect("hold the lock");

        let started = std::time::Instant::now();
        let err = store
            .commit(CONFIG, "cli", "second")
            .expect_err("must refuse");

        assert!(matches!(err, Error::Locked { .. }), "{err}");
        assert!(
            started.elapsed() < LOCK_TIMEOUT + std::time::Duration::from_secs(1),
            "the wait must be bounded by the timeout"
        );
        assert!(
            err.to_string().contains(".commit.lock"),
            "the message must name the file to remove: {err}"
        );
        assert_eq!(
            store.history().expect("history").len(),
            1,
            "a refused commit writes nothing"
        );
    }

    #[test]
    fn the_lock_is_released_after_a_commit() {
        // Otherwise the second commit of a session would find its own lock and refuse.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        store.commit(CONFIG, "cli", "first").expect("first");
        assert!(
            !store.root.join(LOCK).exists(),
            "the lock must not outlive the commit"
        );

        store.commit(CONFIG, "cli", "second").expect("second");
    }

    #[test]
    fn a_body_is_returned_even_when_the_file_has_no_header() {
        // A generation written by an older version, or by hand: the body is the whole file.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());
        store.ensure_structure().expect("structure");

        let path = store.generations().join("0000000007-20260101T000000Z.yaml");
        std::fs::write(&path, CONFIG).expect("write");

        let generation = store.describe(&path).expect("describe");
        assert_eq!(generation.number, 7);
        assert_eq!(generation.body().expect("body"), CONFIG);
        assert!(generation.author.is_empty(), "no author, no invention");
    }

    #[test]
    fn a_file_whose_name_is_not_a_generation_is_refused_by_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());
        store.ensure_structure().expect("structure");

        let path = store.generations().join("not-a-generation.yaml");
        std::fs::write(&path, CONFIG).expect("write");

        let err = store.describe(&path).expect_err("must refuse");
        assert!(
            err.to_string().contains("not-a-generation.yaml"),
            "the refusal must quote the file: {err}"
        );
    }
}
