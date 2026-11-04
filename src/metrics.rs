//! Metrics and the change journal: what the server did, and who asked for it.
//!
//! Two things an operator needs and neither of which a directory server can reconstruct
//! afterwards:
//!
//! **Counters** answer "is it working and how fast". They are lock-free atomics, because a
//! counter on the hot path of every search must not become a contention point — the whole
//! point of the index work was to make search cheap, and a mutex here would undo it.
//!
//! **The journal** answers "who removed that entry". A directory keeps `modifiersName` on
//! the entry, which tells you who last touched it — but a delete leaves no entry to carry
//! the value, so the answer exists only if it was written down when it happened. The
//! journal is that record: one line per accepted write, with the time, the actor, the
//! operation and the DN.
//!
//! Both are deliberately simple. A metric that needs explaining is a metric nobody
//! watches, and a journal that needs a database is a journal that is not there when the
//! disk fills.

use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::operational::generalized_time;

/// Operation kinds a client can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Bind,
    Search,
    Compare,
    Modify,
    Add,
    Delete,
    ModifyDn,
    Extended,
    Abandon,
    Unbind,
}

impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Operation::Bind => "bind",
            Operation::Search => "search",
            Operation::Compare => "compare",
            Operation::Modify => "modify",
            Operation::Add => "add",
            Operation::Delete => "delete",
            Operation::ModifyDn => "modify_dn",
            Operation::Extended => "extended",
            Operation::Abandon => "abandon",
            Operation::Unbind => "unbind",
        }
    }

    /// Every operation, for the counters that have to exist before anything happens so a
    /// rate query returns zero rather than "no data".
    pub const ALL: [Operation; 10] = [
        Operation::Bind,
        Operation::Search,
        Operation::Compare,
        Operation::Modify,
        Operation::Add,
        Operation::Delete,
        Operation::ModifyDn,
        Operation::Extended,
        Operation::Abandon,
        Operation::Unbind,
    ];

    fn index(&self) -> usize {
        *self as usize
    }
}

/// One counter set per operation, plus the few global values worth watching.
///
/// `Arc` and atomics rather than a lock: every request touches at least one of these, so
/// the cost has to be a single `fetch_add`.
#[derive(Debug, Default)]
pub struct Metrics {
    requests: [AtomicU64; 10],
    failures: [AtomicU64; 10],
    connections_total: AtomicU64,
    connections_open: AtomicU64,
    entries: AtomicU64,
    reloads_total: AtomicU64,
    reload_failures: AtomicU64,
    binds_failed: AtomicU64,
    writes_total: AtomicU64,
    /// Entries a peer and this node disagreed about in a way a timestamp cannot settle.
    ///
    /// A conflict is not an error and not a dropped change: one version was kept. It is also
    /// the only event in the whole server that says a record may be missing on one node, so it
    /// is counted rather than only logged - an operator needs to be able to alert on "non-zero".
    conflicts_total: AtomicU64,
    /// Sum of entries returned by searches, for an average page size.
    entries_returned: AtomicU64,
    /// Sum of microseconds spent serving searches.
    search_micros: AtomicU64,
    started: Mutex<Option<std::time::SystemTime>>,
    /// One series group per configured peer, keyed by its URL.
    ///
    /// The only labelled metrics in this file, and the label is bounded by the configuration: a
    /// handful of peers, not a value from a client. That is the difference between a useful label
    /// and the cardinality explosion the doc comment above warns about.
    peers: Mutex<std::collections::BTreeMap<String, PeerState>>,
}

/// What is known about one peer.
#[derive(Debug, Default, Clone)]
pub struct PeerState {
    /// Whether the persistent connection to it is up right now.
    connected: bool,
    /// Changes received and written.
    applied: u64,
    /// Changes received and dropped as already known or not newer.
    ignored: u64,
    /// Attempts that failed, at connecting or at accepting a change.
    errors: u64,
    /// The newest change number applied from this peer, as `<time>#<counter>#<server>#<modifier>`.
    ///
    /// The answer to "how fresh is this replica", which no other metric can give: an entry count
    /// says nothing about whether the other node's writes have arrived.
    last_csn: Option<String>,
    /// When the last change from it was applied, as a Unix timestamp.
    last_change: Option<u64>,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        let metrics = Arc::new(Self::default());
        *metrics
            .started
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(std::time::SystemTime::now());
        metrics
    }

    /// Records one request and its result code.
    ///
    /// The result code decides success rather than the caller: a search that returned
    /// `sizeLimitExceeded` is a request that happened, and a bind that failed is the one
    /// operators actually watch.
    /// Declares a peer before it is contacted.
    ///
    /// Called at startup so every series exists with a zero value: a graph that starts the moment a
    /// node first connects hides the case that matters most - a peer that never connected at all.
    pub fn register_peer(&self, url: &str) {
        let mut peers = self.lock_peers();
        peers.entry(url.to_string()).or_default();
    }

    /// Records whether the persistent connection to a peer is up.
    pub fn peer_connected(&self, url: &str, connected: bool) {
        let mut peers = self.lock_peers();
        peers.entry(url.to_string()).or_default().connected = connected;
    }

    /// Records a failed attempt: connecting, or accepting a change.
    pub fn peer_error(&self, url: &str) {
        let mut peers = self.lock_peers();
        peers.entry(url.to_string()).or_default().errors += 1;
    }

    /// Records what happened to one change from a peer.
    pub fn peer_change(&self, url: &str, applied: bool, csn: Option<&str>) {
        let mut peers = self.lock_peers();
        let state = peers.entry(url.to_string()).or_default();

        if applied {
            state.applied += 1;
            state.last_change = Some(now_seconds());
            // The newest change number, not the last one seen: a peer's changes can arrive out of
            // order across reconnects, and a freshness gauge that went backwards would be worse
            // than none.
            if let Some(csn) = csn
                && state.last_csn.as_deref().is_none_or(|seen| csn > seen)
            {
                state.last_csn = Some(csn.to_string());
            }
        } else {
            state.ignored += 1;
        }
    }

    /// The peers this process knows about, for tests and for a shutdown summary.
    pub fn peers(&self) -> Vec<(String, PeerState)> {
        self.lock_peers()
            .iter()
            .map(|(url, state)| (url.clone(), state.clone()))
            .collect()
    }

    fn lock_peers(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<String, PeerState>> {
        self.peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Records one unresolved disagreement with a peer.
    pub fn record_conflict(&self) {
        self.conflicts_total.fetch_add(1, Ordering::Relaxed);
    }

    /// How many conflicts have been seen.
    pub fn conflicts(&self) -> u64 {
        self.conflicts_total.load(Ordering::Relaxed)
    }

    pub fn record(&self, operation: Operation, succeeded: bool) {
        self.requests[operation.index()].fetch_add(1, Ordering::Relaxed);
        if !succeeded {
            self.failures[operation.index()].fetch_add(1, Ordering::Relaxed);
        }
        if operation == Operation::Bind && !succeeded {
            self.binds_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records a search's cost and size.
    pub fn record_search(&self, elapsed: std::time::Duration, returned: usize) {
        self.search_micros
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
        self.entries_returned
            .fetch_add(returned as u64, Ordering::Relaxed);
    }

    pub fn connection_opened(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        self.connections_open.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_closed(&self) {
        // Saturating: a close without a matching open would otherwise wrap to a huge
        // number and make the gauge look like a leak.
        let _ = self
            .connections_open
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |open| {
                Some(open.saturating_sub(1))
            });
    }

    pub fn set_entries(&self, entries: usize) {
        self.entries.store(entries as u64, Ordering::Relaxed);
    }

    pub fn reload_succeeded(&self) {
        self.reloads_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn reload_failed(&self) {
        self.reload_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// A write that reached the store.
    pub fn write_stored(&self) {
        self.writes_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connections_open(&self) -> u64 {
        self.connections_open.load(Ordering::Relaxed)
    }

    pub fn requests(&self, operation: Operation) -> u64 {
        self.requests[operation.index()].load(Ordering::Relaxed)
    }

    pub fn failures(&self, operation: Operation) -> u64 {
        self.failures[operation.index()].load(Ordering::Relaxed)
    }

    /// The document, in the Prometheus text exposition format.
    ///
    /// One gauge per thing that goes up and down, one counter per thing that only goes up;
    /// the suffix says which, and Prometheus expects it. Labels are not used: this server
    /// has one directory, and a label on every metric is how metric cardinality explodes.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(2048);

        out.push_str("# HELP ldap_up Whether the process is serving.\n");
        out.push_str("# TYPE ldap_up gauge\n");
        out.push_str("ldap_up 1\n\n");

        out.push_str("# HELP ldap_uptime_seconds Seconds since the process started.\n");
        out.push_str("# TYPE ldap_uptime_seconds gauge\n");
        let uptime = self
            .started
            .lock()
            .ok()
            .and_then(|started| *started)
            .and_then(|started| std::time::SystemTime::now().duration_since(started).ok())
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        let _ = writeln!(out, "ldap_uptime_seconds {uptime}\n");

        out.push_str("# HELP ldap_entries Number of entries in the directory.\n");
        out.push_str("# TYPE ldap_entries gauge\n");
        let _ = writeln!(
            out,
            "ldap_entries {}\n",
            self.entries.load(Ordering::Relaxed)
        );

        out.push_str("# HELP ldap_connections_open Connections currently open.\n");
        out.push_str("# TYPE ldap_connections_open gauge\n");
        let _ = writeln!(
            out,
            "ldap_connections_open {}\n",
            self.connections_open.load(Ordering::Relaxed)
        );

        out.push_str("# HELP ldap_connections_total Connections accepted since start.\n");
        out.push_str("# TYPE ldap_connections_total counter\n");
        let _ = writeln!(
            out,
            "ldap_connections_total {}\n",
            self.connections_total.load(Ordering::Relaxed)
        );

        // One block per operation, with the operation as a label on the value rather than
        // in the metric name: a fixed label set here cannot explode, and the alternative is
        // nine nearly identical blocks.
        out.push_str("# HELP ldap_requests Requests received, by operation.\n");
        out.push_str("# TYPE ldap_requests counter\n");
        for operation in Operation::ALL {
            let _ = writeln!(
                out,
                "ldap_requests{{operation=\"{}\"}} {}",
                operation.name(),
                self.requests(operation)
            );
        }
        out.push('\n');

        out.push_str("# HELP ldap_request_failures Requests answered with a non-success code.\n");
        out.push_str("# TYPE ldap_request_failures counter\n");
        for operation in Operation::ALL {
            let _ = writeln!(
                out,
                "ldap_request_failures{{operation=\"{}\"}} {}",
                operation.name(),
                self.failures(operation)
            );
        }
        out.push('\n');

        out.push_str("# HELP ldap_search_entries_returned_total Entries returned by searches.\n");
        out.push_str("# TYPE ldap_search_entries_returned_total counter\n");
        let _ = writeln!(
            out,
            "ldap_search_entries_returned_total {}\n",
            self.entries_returned.load(Ordering::Relaxed)
        );

        out.push_str("# HELP ldap_search_seconds_total Time spent serving searches.\n");
        out.push_str("# TYPE ldap_search_seconds_total counter\n");
        let micros = self.search_micros.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "ldap_search_seconds_total {}.{:06}\n",
            micros / 1_000_000,
            micros % 1_000_000
        );

        out.push_str("# HELP ldap_bind_failures Binds answered with a failure code.\n");
        out.push_str("# TYPE ldap_bind_failures counter\n");
        let _ = writeln!(
            out,
            "ldap_bind_failures {}\n",
            self.binds_failed.load(Ordering::Relaxed)
        );

        out.push_str("# HELP ldap_writes_total Writes stored by the backend.\n");
        out.push_str("# TYPE ldap_writes_total counter\n");
        let _ = writeln!(
            out,
            "ldap_writes_total {}\n",
            self.writes_total.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP ldap_replication_conflicts_total Entries a peer and this node disagreed about \
             in a way a timestamp cannot settle.\n",
        );
        out.push_str("# TYPE ldap_replication_conflicts_total counter\n");
        out.push_str(&format!(
            "ldap_replication_conflicts_total {}\n",
            self.conflicts_total.load(Ordering::Relaxed)
        ));

        // Per-peer replication. Labelled, unlike everything above, because the only question
        // these answer is "which node is behind" - and a single number cannot answer it.
        let peers = self.peers();

        if !peers.is_empty() {
            out.push_str(
                "# HELP ldap_replication_peer_connected Whether the persistent connection to a \
                 peer is up.\n",
            );
            out.push_str("# TYPE ldap_replication_peer_connected gauge\n");
            for (url, state) in &peers {
                let _ = writeln!(
                    out,
                    "ldap_replication_peer_connected{{peer=\"{}\"}} {}",
                    escape_label(url),
                    u8::from(state.connected)
                );
            }
            out.push('\n');

            out.push_str(
                "# HELP ldap_replication_changes_applied_total Changes written from a peer.\n",
            );
            out.push_str("# TYPE ldap_replication_changes_applied_total counter\n");
            for (url, state) in &peers {
                let _ = writeln!(
                    out,
                    "ldap_replication_changes_applied_total{{peer=\"{}\"}} {}",
                    escape_label(url),
                    state.applied
                );
            }
            out.push('\n');

            out.push_str(
                "# HELP ldap_replication_changes_ignored_total Changes from a peer dropped as \
                 already known or not newer.\n",
            );
            out.push_str("# TYPE ldap_replication_changes_ignored_total counter\n");
            for (url, state) in &peers {
                let _ = writeln!(
                    out,
                    "ldap_replication_changes_ignored_total{{peer=\"{}\"}} {}",
                    escape_label(url),
                    state.ignored
                );
            }
            out.push('\n');

            out.push_str(
                "# HELP ldap_replication_peer_errors_total Failed attempts to reach a peer or to \
                 accept its change.\n",
            );
            out.push_str("# TYPE ldap_replication_peer_errors_total counter\n");
            for (url, state) in &peers {
                let _ = writeln!(
                    out,
                    "ldap_replication_peer_errors_total{{peer=\"{}\"}} {}",
                    escape_label(url),
                    state.errors
                );
            }
            out.push('\n');

            // A gauge that is absent until something happens is a gauge nobody can alert on: the
            // worst case is a peer that has never delivered a change, and that case must be
            // visible rather than missing.
            out.push_str(
                "# HELP ldap_replication_last_change_timestamp_seconds When the last change from \
                 this peer was written, as a Unix timestamp; 0 if none ever was.\n",
            );
            out.push_str("# TYPE ldap_replication_last_change_timestamp_seconds gauge\n");
            for (url, state) in &peers {
                let _ = writeln!(
                    out,
                    "ldap_replication_last_change_timestamp_seconds{{peer=\"{}\"}} {}",
                    escape_label(url),
                    state.last_change.unwrap_or(0)
                );
            }
            out.push('\n');

            out.push_str(
                "# HELP ldap_replication_last_csn_newest The newest change number applied from \
                 this peer, as information: absence means no change has ever arrived.\n",
            );
            out.push_str("# TYPE ldap_replication_last_csn_newest gauge\n");
            for (url, state) in &peers {
                let value = state
                    .last_csn
                    .as_deref()
                    .and_then(csn_to_number)
                    .map(|number| number.to_string())
                    .unwrap_or_else(|| "0".to_string());
                let _ = writeln!(
                    out,
                    "ldap_replication_last_csn_newest{{peer=\"{}\"}} {}",
                    escape_label(url),
                    value
                );
            }
            out.push('\n');
        }

        out.push_str("# HELP ldap_reloads_total Successful directory reloads.\n");
        out.push_str("# TYPE ldap_reloads_total counter\n");
        let _ = writeln!(
            out,
            "ldap_reloads_total {}\n",
            self.reloads_total.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP ldap_reload_failures Reloads that failed, keeping the old directory.\n",
        );
        out.push_str("# TYPE ldap_reload_failures counter\n");
        let _ = writeln!(
            out,
            "ldap_reload_failures {}\n",
            self.reload_failures.load(Ordering::Relaxed)
        );

        out
    }
}

/// What a write did, for the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Add,
    Modify,
    Delete,
    Rename,
    PasswordChange,
}

impl ChangeKind {
    pub fn name(&self) -> &'static str {
        match self {
            ChangeKind::Add => "add",
            ChangeKind::Modify => "modify",
            ChangeKind::Delete => "delete",
            ChangeKind::Rename => "rename",
            ChangeKind::PasswordChange => "password-change",
        }
    }
}

/// What the dispatcher tells the journal about a write.
///
/// The handler supplies the entry explicitly rather than letting the journal derive it from
/// the change set: one write can touch several entries (a rename moves a subtree and updates
/// the groups that list the user), and journaling each of those as "rename" would leave a
/// reader unable to tell which line is the operation and which is its side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub kind: ChangeKind,
    /// The DN the client addressed.
    pub dn: String,
    /// Where the entry went, for a rename.
    pub new_dn: Option<String>,
    pub actor: String,
}

impl Note {
    pub fn new(kind: ChangeKind, dn: impl Into<String>, actor: impl Into<String>) -> Self {
        Self {
            kind,
            dn: dn.into(),
            new_dn: None,
            actor: actor.into(),
        }
    }

    pub fn renamed(
        dn: impl Into<String>,
        new_dn: impl Into<String>,
        actor: impl Into<String>,
    ) -> Self {
        Self {
            kind: ChangeKind::Rename,
            dn: dn.into(),
            new_dn: Some(new_dn.into()),
            actor: actor.into(),
        }
    }

    /// The journal line for this note.
    pub fn change(&self, peer: &str, result: u8) -> Change {
        Change {
            kind: self.kind,
            dn: self.dn.clone(),
            new_dn: self.new_dn.clone(),
            actor: self.actor.clone(),
            peer: peer.to_string(),
            result,
        }
    }
}

/// One journal line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub kind: ChangeKind,
    /// DN the change was applied to.
    pub dn: String,
    /// New DN, for a rename.
    pub new_dn: Option<String>,
    /// Who performed it; empty for an anonymous actor, which no write allows.
    pub actor: String,
    /// The client's address, so a shared account can be traced to a place.
    pub peer: String,
    /// The result code, so a refused write is in the record too: "who tried" is a
    /// different question from "who succeeded", and both get asked.
    pub result: u8,
}

impl Change {
    /// The line as written: JSON, one object per line.
    ///
    /// JSON Lines rather than a text log because the questions asked of a journal are
    /// "show me every delete of this subtree last Tuesday", and that is a query, not a
    /// grep. It also means a log shipper does not need a parser written for this format.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');
        let _ = write!(
            out,
            "\"time\":\"{}\"",
            generalized_time(std::time::SystemTime::now())
        );
        let _ = write!(out, ",\"op\":\"{}\"", self.kind.name());
        let _ = write!(out, ",\"dn\":{}", json_string(&self.dn));
        if let Some(new_dn) = &self.new_dn {
            let _ = write!(out, ",\"newDn\":{}", json_string(new_dn));
        }
        let _ = write!(out, ",\"actor\":{}", json_string(&self.actor));
        let _ = write!(out, ",\"peer\":{}", json_string(&self.peer));
        let _ = write!(out, ",\"result\":{}", self.result);
        out.push('}');
        out
    }
}

/// A JSON string literal, escaped as JSON requires.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", other as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Where journal lines go.
enum Sink {
    /// Nowhere: the journal is off.
    Off,
    /// Standard output, for a container that collects it.
    Stdout,
    /// A file, appended to and flushed per line, rotated when it reaches its limit.
    File(Append),
}

/// An open journal file and what is needed to rotate it.
struct Append {
    file: Mutex<std::fs::File>,
    path: std::path::PathBuf,
    /// Bytes in the file as far as this process knows.
    ///
    /// Counted rather than asked of the filesystem per line: a `stat` before every write is a
    /// syscall per change for a number that only moves when this process writes.
    size: std::sync::atomic::AtomicU64,
    /// Above this the file is rotated. Zero means never.
    limit: u64,
}

impl Append {
    fn open(path: &std::path::Path, limit: u64) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let size = file.metadata().map(|meta| meta.len()).unwrap_or(0);

        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
            size: std::sync::atomic::AtomicU64::new(size),
            limit,
        })
    }

    /// Appends one line, rotating first if it would cross the limit.
    fn write(&self, line: &str) -> std::io::Result<()> {
        let needed = line.len() as u64 + 1;

        if self.limit > 0 && self.size.load(Ordering::Relaxed) + needed > self.limit {
            self.rotate()?;
        }

        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        writeln!(file, "{line}")?;
        file.flush()?;
        self.size.fetch_add(needed, Ordering::Relaxed);

        Ok(())
    }

    /// Moves the journal aside and starts a new one.
    ///
    /// One backup, `<path>.1`, replaced: the question a journal answers is "what happened
    /// around then", and a chain of ten rotated files answers it no better than one while
    /// making the disk usage harder to reason about. The rename is atomic, so a reader tailing
    /// the path loses nothing - it keeps the old inode until it reopens.
    fn rotate(&self) -> std::io::Result<()> {
        let backup = self.path.with_extension(format!(
            "{}.1",
            self.path
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or("journal")
        ));

        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        std::fs::rename(&self.path, &backup)?;
        *file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.size.store(0, Ordering::Relaxed);

        Ok(())
    }
}

/// How large the journal may grow before it rotates, when the configuration says nothing.
///
/// Sixty-four megabytes is months of a busy directory's changes and small enough that a full
/// disk is a deliberate act rather than an accident. Not unlimited: an unlimited default is an
/// outage scheduled for whenever the disk fills.
pub const JOURNAL_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The change journal.
///
/// Writes are synchronous and flushed per line: a journal that loses the last entries on a
/// crash is useless for the question it exists to answer, which is always about the change
/// that just happened.
pub struct Journal {
    sink: Sink,
    /// Count of lines written, for tests and for a shutdown summary.
    written: AtomicU64,
}

impl Journal {
    /// A journal that writes nowhere.
    pub fn off() -> Self {
        Self {
            sink: Sink::Off,
            written: AtomicU64::new(0),
        }
    }

    /// A journal on standard output.
    pub fn stdout() -> Self {
        Self {
            sink: Sink::Stdout,
            written: AtomicU64::new(0),
        }
    }

    /// A journal appending to `path`, created when absent, rotated at the default size.
    pub fn file(path: &std::path::Path) -> std::io::Result<Self> {
        Self::file_with_limit(path, JOURNAL_MAX_BYTES)
    }

    /// A journal appending to `path`, rotated when it would cross `limit` bytes.
    ///
    /// A limit of zero turns rotation off, for a journal that is collected by something else and
    /// must not be moved aside.
    pub fn file_with_limit(path: &std::path::Path, limit: u64) -> std::io::Result<Self> {
        Ok(Self {
            sink: Sink::File(Append::open(path, limit)?),
            written: AtomicU64::new(0),
        })
    }

    pub fn is_on(&self) -> bool {
        !matches!(self.sink, Sink::Off)
    }

    /// Appends one line.
    ///
    /// A failure to write is reported to the caller and *not* raised into the operation: a
    /// full disk must not make the directory refuse writes, because then the directory is
    /// down for a reason that has nothing to do with the directory.
    pub fn record(&self, change: &Change) -> std::io::Result<()> {
        self.record_line(&change.to_json())
    }

    /// Appends one already-serialised line.
    ///
    /// Here so a second journal - the replication conflicts - writes through the same sink,
    /// the same rotation and the same rule that a full disk must not fail the operation.
    pub fn record_line(&self, line: &str) -> std::io::Result<()> {
        match &self.sink {
            Sink::Off => Ok(()),
            Sink::Stdout => {
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "{line}")?;
                stdout.flush()?;
                self.written.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Sink::File(file) => {
                file.write(line)?;
                self.written.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
    }

    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Journal")
            .field("on", &self.is_on())
            .field("written", &self.written())
            .finish()
    }
}

/// Escapes a label value the way the Prometheus text format requires.
///
/// A peer URL is configuration, so it is nearly always safe - but a URL with a quote in it would
/// produce a document a scraper rejects, and rejecting the whole scrape for one bad label is a
/// harsh way to learn about a typo.
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }

    out
}

/// A change number as a number, for a gauge.
///
/// Prometheus cannot compare strings, so "is this replica behind" would be unanswerable from a
/// textual CSN. The mapping keeps the order: `<timestamp>#<counter>` becomes
/// `YYYYmmddHHMMSS.microsecond * 1000 + counter`, which climbs with every change and fits in a
/// `u64` until well past the year 9999. The server id and the modifier are dropped: they break
/// ties, they do not measure progress, and a gauge that jumped when the tie-break changed would
/// mislead exactly the person watching a replica lag.
fn csn_to_number(csn: &str) -> Option<u64> {
    let mut parts = csn.split('#');
    let timestamp = parts.next()?;
    let counter: u64 = parts.next()?.trim_start_matches('0').parse().unwrap_or(0);

    // The timestamp goes through the same parser the write path uses, rather than through
    // arithmetic on `YYYYmmddHHMMSS`: fourteen digits multiplied by a microsecond scale overflows a
    // `u64`, and the failure is silent - two different changes collapse to the same maximum, which
    // is a freshness gauge that stops moving exactly when it matters.
    let at = crate::operational::parse_generalized_time(timestamp)?;
    let micros = at
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_micros() as u64)
        .unwrap_or(0);

    Some(micros.saturating_mul(1000).saturating_add(counter))
}

/// Seconds since the Unix epoch, for a timestamp gauge.
fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_that_never_connected_is_still_in_the_document() {
        // The case a graph must show and an absent series cannot: a configured peer that has never
        // once come up. Registered at startup, so the zeroes exist before anything is attempted.
        let metrics = Metrics::new();
        metrics.register_peer("ldap://node2.example.com");

        let rendered = metrics.render();
        assert!(
            rendered
                .contains("ldap_replication_peer_connected{peer=\"ldap://node2.example.com\"} 0"),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "ldap_replication_last_change_timestamp_seconds{peer=\"ldap://node2.example.com\"} 0"
            ),
            "never having delivered a change must read as zero, not as a missing series: {rendered}"
        );
    }

    #[test]
    fn what_a_peer_delivered_is_counted_per_peer() {
        // Two peers, and the numbers must not run together: the whole point of the label is that
        // "which node is behind" has an answer.
        let metrics = Metrics::new();
        metrics.register_peer("ldap://one");
        metrics.register_peer("ldap://two");

        metrics.peer_connected("ldap://one", true);
        metrics.peer_change(
            "ldap://one",
            true,
            Some("20260101000000.000001Z#000001#002#000000"),
        );
        metrics.peer_change(
            "ldap://one",
            true,
            Some("20260101000000.000002Z#000001#002#000000"),
        );
        metrics.peer_change("ldap://one", false, None);
        metrics.peer_error("ldap://two");

        let peers = metrics.peers();
        let one = peers
            .iter()
            .find(|(url, _)| url == "ldap://one")
            .map(|(_, state)| state)
            .expect("peer one");
        let two = peers
            .iter()
            .find(|(url, _)| url == "ldap://two")
            .map(|(_, state)| state)
            .expect("peer two");

        assert!(one.connected);
        assert_eq!(one.applied, 2);
        assert_eq!(one.ignored, 1);
        assert_eq!(one.errors, 0);

        assert!(!two.connected);
        assert_eq!(two.applied, 0);
        assert_eq!(two.errors, 1);
    }

    #[test]
    fn the_freshness_csn_only_moves_forward() {
        // A peer's changes can arrive out of order across a reconnect. A freshness gauge that went
        // backwards would tell an operator a replica had regressed when it had not.
        let metrics = Metrics::new();
        metrics.peer_change(
            "ldap://one",
            true,
            Some("20260101000000.000009Z#000001#002#000000"),
        );
        metrics.peer_change(
            "ldap://one",
            true,
            Some("20260101000000.000001Z#000001#002#000000"),
        );

        let state = metrics.peers().pop().expect("one peer").1;
        assert_eq!(
            state.last_csn.as_deref(),
            Some("20260101000000.000009Z#000001#002#000000")
        );
    }

    #[test]
    fn a_change_number_becomes_a_number_that_keeps_the_order() {
        // Prometheus cannot compare strings, so "is this replica behind" needs a numeric projection
        // that climbs with every change.
        let early = csn_to_number("20260101000000.000001Z#000001#002#000000").expect("a number");
        let later = csn_to_number("20260101000000.000002Z#000001#002#000000").expect("a number");
        let same_second =
            csn_to_number("20260101000000.000001Z#000009#002#000000").expect("a number");
        let next_year =
            csn_to_number("20270101000000.000001Z#000001#002#000000").expect("a number");

        assert!(early < later, "a later microsecond");
        assert!(
            early < same_second,
            "a higher counter in the same microsecond"
        );
        assert!(later < next_year, "a later year");

        assert_eq!(csn_to_number("nonsense"), None);
        assert_eq!(csn_to_number(""), None);
    }

    #[test]
    fn a_label_is_escaped_so_one_bad_url_does_not_break_the_scrape() {
        // A URL is configuration, so it is nearly always safe - but a quote in it would produce a
        // document a scraper rejects, and rejecting the whole scrape is a harsh way to learn about
        // a typo.
        assert_eq!(escape_label("ldap://plain"), "ldap://plain");
        assert_eq!(escape_label("a\"b"), "a\\\"b");
        assert_eq!(escape_label("a\\b"), "a\\\\b");
    }

    #[test]
    fn a_conflict_is_counted_and_rendered() {
        // The counter exists so "has this node ever disagreed with a peer" is answerable without
        // reading a log file on every host. A counter that is not rendered answers nothing.
        let metrics = Metrics::new();
        assert!(
            metrics
                .render()
                .contains("ldap_replication_conflicts_total 0"),
            "the series is present before anything happens, so a graph does not start at nothing"
        );

        metrics.record_conflict();
        metrics.record_conflict();

        assert_eq!(metrics.conflicts(), 2);
        let rendered = metrics.render();
        assert!(
            rendered.contains("ldap_replication_conflicts_total 2"),
            "{rendered}"
        );
    }

    #[test]
    fn a_request_and_its_failure_are_counted() {
        let metrics = Metrics::new();

        metrics.record(Operation::Search, true);
        metrics.record(Operation::Search, false);
        metrics.record(Operation::Bind, false);

        assert_eq!(metrics.requests(Operation::Search), 2);
        assert_eq!(metrics.failures(Operation::Search), 1);
        assert_eq!(metrics.requests(Operation::Bind), 1);
        assert_eq!(metrics.failures(Operation::Bind), 1);
        assert_eq!(metrics.requests(Operation::Compare), 0);
    }

    #[test]
    fn the_rendered_document_has_one_line_per_operation() {
        let metrics = Metrics::new();
        let text = metrics.render();

        for operation in Operation::ALL {
            assert!(
                text.contains(&format!(
                    "ldap_requests{{operation=\"{}\"}}",
                    operation.name()
                )),
                "{} must be present: {text}",
                operation.name()
            );
        }
    }

    #[test]
    fn counters_only_go_up() {
        let metrics = Metrics::new();
        metrics.record(Operation::Add, true);
        metrics.record(Operation::Add, true);

        assert_eq!(metrics.requests(Operation::Add), 2);
        assert_eq!(metrics.failures(Operation::Add), 0);
    }

    #[test]
    fn a_connection_that_closes_without_opening_does_not_wrap() {
        // A saturating decrement: a bug elsewhere must not turn a gauge into 18 quintillion.
        let metrics = Metrics::new();
        metrics.connection_closed();

        assert_eq!(metrics.connections_open(), 0);
    }

    #[test]
    fn connections_are_counted_open_and_total() {
        let metrics = Metrics::new();
        metrics.connection_opened();
        metrics.connection_opened();
        metrics.connection_closed();

        assert_eq!(metrics.connections_open(), 1);
        assert!(metrics.render().contains("ldap_connections_total 2"));
    }

    #[test]
    fn search_cost_is_rendered_in_seconds_with_microseconds() {
        let metrics = Metrics::new();
        metrics.record_search(std::time::Duration::from_micros(1_500_000), 7);

        let text = metrics.render();
        assert!(
            text.contains("ldap_search_seconds_total 1.500000"),
            "the exposition format wants seconds with a decimal fraction: {text}"
        );
        assert!(text.contains("ldap_search_entries_returned_total 7"));
    }

    #[test]
    fn every_metric_has_a_type_line() {
        // Prometheus warns on an untyped metric, and a scrape that ignores the warning still
        // picks the wrong aggregation.
        let metrics = Metrics::new();
        let text = metrics.render();

        for line in text.lines() {
            if line.starts_with("ldap_") {
                let name = line.split(['{', ' ']).next().unwrap_or(line);
                let expected = if name.ends_with("_total")
                    || name.ends_with("_failures")
                    || name.ends_with("_seconds_total")
                    || name.ends_with("_micros")
                {
                    "counter"
                } else {
                    "gauge"
                };

                // `ldap_requests` and `ldap_request_failures` are counters without the
                // suffix, so they are checked by name.
                let is_counter = expected == "counter"
                    || name == "ldap_requests"
                    || name == "ldap_request_failures";

                let type_line = format!(
                    "# TYPE {name} {}",
                    if is_counter { "counter" } else { "gauge" }
                );
                assert!(
                    text.contains(&type_line),
                    "missing '{type_line}' for '{line}'"
                );
            }
        }
    }

    #[test]
    fn a_change_renders_as_one_json_line() {
        let change = Change {
            kind: ChangeKind::Delete,
            dn: "cn=ann,ou=users,dc=example,dc=com".to_string(),
            new_dn: None,
            actor: "cn=admin,ou=users,dc=example,dc=com".to_string(),
            peer: "127.0.0.1:54321".to_string(),
            result: 0,
        };

        let line = change.to_json();

        assert!(!line.contains('\n'), "one line per record: {line}");
        assert!(line.starts_with('{') && line.ends_with('}'));
        assert!(line.contains("\"op\":\"delete\""));
        assert!(line.contains("\"dn\":\"cn=ann,ou=users,dc=example,dc=com\""));
        assert!(line.contains("\"actor\":\"cn=admin,ou=users,dc=example,dc=com\""));
        assert!(line.contains("\"result\":0"));
        assert!(line.contains("\"time\":\""), "every record is timestamped");
    }

    #[test]
    fn a_rename_carries_both_dns() {
        let change = Change {
            kind: ChangeKind::Rename,
            dn: "cn=old,ou=users,dc=example,dc=com".to_string(),
            new_dn: Some("cn=new,ou=users,dc=example,dc=com".to_string()),
            actor: "cn=admin,dc=example,dc=com".to_string(),
            peer: "127.0.0.1:1".to_string(),
            result: 0,
        };

        let line = change.to_json();
        assert!(line.contains("\"newDn\":\"cn=new,ou=users,dc=example,dc=com\""));
    }

    #[test]
    fn quotes_and_backslashes_in_a_dn_are_escaped() {
        let change = Change {
            kind: ChangeKind::Add,
            dn: "cn=odd \"name\",dc=example,dc=com".to_string(),
            new_dn: None,
            actor: "cn=admin".to_string(),
            peer: "127.0.0.1:1".to_string(),
            result: 0,
        };

        let line = change.to_json();

        assert!(line.contains("\\\""), "a quote has to be escaped: {line}");
        // A line that no longer parses as JSON would break every consumer.
        let parsed: serde_json::Value =
            serde_json::from_str(&line).expect("the journal line must be valid JSON");
        assert_eq!(
            parsed["dn"],
            serde_json::json!("cn=odd \"name\",dc=example,dc=com")
        );
    }

    #[test]
    fn a_refused_write_is_recorded_with_its_code() {
        // "Who tried" is a different question from "who succeeded", and both get asked.
        let change = Change {
            kind: ChangeKind::Modify,
            dn: "cn=ann,ou=users,dc=example,dc=com".to_string(),
            new_dn: None,
            actor: "cn=ann,ou=users,dc=example,dc=com".to_string(),
            peer: "127.0.0.1:1".to_string(),
            result: 50,
        };

        let parsed: serde_json::Value =
            serde_json::from_str(&change.to_json()).expect("valid JSON");
        assert_eq!(parsed["result"], serde_json::json!(50));
    }

    #[test]
    fn a_journal_that_is_off_writes_nothing() {
        let journal = Journal::off();

        assert!(!journal.is_on());
        assert!(
            journal
                .record(&Change {
                    kind: ChangeKind::Add,
                    dn: "cn=x,dc=example,dc=com".to_string(),
                    new_dn: None,
                    actor: String::new(),
                    peer: String::new(),
                    result: 0,
                })
                .is_ok(),
            "a journal that is off accepts a record and does nothing"
        );
        assert_eq!(journal.written(), 0);
    }

    #[test]
    fn a_file_journal_appends_a_line_per_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("changes.jsonl");
        let journal = Journal::file(&path).expect("journal");

        for index in 0..3 {
            journal
                .record(&Change {
                    kind: ChangeKind::Add,
                    dn: format!("cn={index},dc=example,dc=com"),
                    new_dn: None,
                    actor: "cn=admin".to_string(),
                    peer: "127.0.0.1:1".to_string(),
                    result: 0,
                })
                .expect("record");
        }

        assert_eq!(journal.written(), 3);

        let text = std::fs::read_to_string(&path).expect("read");
        assert_eq!(text.lines().count(), 3);
        for line in text.lines() {
            serde_json::from_str::<serde_json::Value>(line).expect("each line is JSON");
        }
    }

    #[test]
    fn a_file_journal_appends_to_what_is_already_there() {
        // A restart must not truncate the record of what happened before it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("changes.jsonl");
        std::fs::write(&path, "{\"op\":\"add\"}\n").expect("seed");

        let journal = Journal::file(&path).expect("journal");
        journal
            .record(&Change {
                kind: ChangeKind::Delete,
                dn: "cn=x,dc=example,dc=com".to_string(),
                new_dn: None,
                actor: "cn=admin".to_string(),
                peer: "127.0.0.1:1".to_string(),
                result: 0,
            })
            .expect("record");

        let text = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            text.lines().count(),
            2,
            "the earlier line must still be there"
        );
    }

    #[test]
    fn a_journal_on_an_unwritable_path_reports_the_error_and_does_not_panic() {
        let journal = Journal::file(std::path::Path::new("/proc/definitely/not/writable.jsonl"));

        assert!(
            journal.is_err(),
            "the caller has to learn the journal is unusable"
        );
    }

    // ---- the journal this exists to keep bounded ----

    fn change(n: usize) -> Change {
        Change {
            kind: ChangeKind::Modify,
            dn: format!("cn=u{n},dc=example,dc=com"),
            new_dn: None,
            actor: format!("cn=a{n},dc=example,dc=com"),
            peer: "127.0.0.1:1".to_string(),
            result: 0,
        }
    }

    #[test]
    fn a_journal_rotates_instead_of_growing_without_end() {
        // The defect: an unlimited journal fills the disk, and the first symptom is every write
        // failing for a reason that has nothing to do with the directory.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("changes.jsonl");
        let journal = Journal::file_with_limit(&path, 400).expect("journal");

        for n in 0..40 {
            journal.record(&change(n)).expect("write");
        }

        let current = std::fs::read_to_string(&path).expect("the journal in force");
        let backup = std::fs::read_to_string(dir.path().join("changes.jsonl.1"))
            .expect("the rotated journal");

        assert!(
            current.len() as u64 <= 400,
            "the journal in force must stay under its limit, is {}",
            current.len()
        );
        assert!(
            backup.len() as u64 <= 400,
            "and so must the backup, is {}",
            backup.len()
        );
        assert!(
            !current.is_empty(),
            "rotation must not lose the newest lines"
        );
        assert!(
            journal.written() == 40,
            "every line was written, to one file or the other"
        );

        // One backup, so older generations are gone on purpose: the two files hold the newest
        // run of changes, and nothing is missing *inside* that run - no line dropped between the
        // rotated file and the current one, and none out of order.
        let mut together = backup;
        together.push_str(&current);
        let dns: Vec<String> = together
            .lines()
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).expect("json");
                value["dn"].as_str().expect("dn").to_string()
            })
            .collect();
        let numbers: Vec<usize> = dns
            .iter()
            .map(|dn| {
                dn.trim_start_matches("cn=u")
                    .trim_end_matches(",dc=example,dc=com")
                    .parse()
                    .expect("the number in the DN")
            })
            .collect();
        assert!(
            numbers.windows(2).all(|pair| pair[1] == pair[0] + 1),
            "the surviving lines must be contiguous and in order: {:?}",
            numbers
        );
        assert_eq!(
            *numbers.last().expect("at least one line"),
            39,
            "and the newest change is the last line of the journal in force"
        );
    }

    #[test]
    fn a_limit_of_zero_turns_rotation_off() {
        // For a journal that something else collects and must not be moved aside.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("changes.jsonl");
        let journal = Journal::file_with_limit(&path, 0).expect("journal");

        for n in 0..40 {
            journal.record(&change(n)).expect("write");
        }

        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("journal")
                .lines()
                .count(),
            40
        );
        assert!(
            !dir.path().join("changes.jsonl.1").exists(),
            "nothing is rotated when the limit is zero"
        );
    }

    #[test]
    fn a_journal_that_already_exists_is_rotated_at_its_real_size() {
        // The size is taken from the file on open, not assumed to be zero: a server restarted
        // into a full journal must rotate on the next line, not after another limit's worth.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("changes.jsonl");
        std::fs::write(&path, "x".repeat(500)).expect("a journal at its limit");

        let journal = Journal::file_with_limit(&path, 400).expect("journal");
        journal.record(&change(1)).expect("write");

        assert!(
            dir.path().join("changes.jsonl.1").exists(),
            "the file that was already too large is rotated away"
        );
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("journal")
                .lines()
                .count(),
            1,
            "and the new one holds just the new line"
        );
    }
}
