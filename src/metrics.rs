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
    /// Sum of entries returned by searches, for an average page size.
    entries_returned: AtomicU64,
    /// Sum of microseconds spent serving searches.
    search_micros: AtomicU64,
    started: Mutex<Option<std::time::SystemTime>>,
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
    /// A file, appended to and flushed per line.
    File(Mutex<std::fs::File>),
}

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

    /// A journal appending to `path`, created when absent.
    pub fn file(path: &std::path::Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Self {
            sink: Sink::File(Mutex::new(file)),
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
        let line = change.to_json();

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
                let mut file = file.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                writeln!(file, "{line}")?;
                file.flush()?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
