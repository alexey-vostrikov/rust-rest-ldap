//! The exchange half of multi-master, level 1: each node listens to its peers.
//!
//! [`crate::replication`] decides *what* to do with a peer's change; this module carries the
//! changes in and out. The transport is the one every LDAP client already has - RFC 4533
//! `refreshAndPersist` - so a peer is an ordinary LDAP server and not a bespoke protocol peer. That
//! is not a convenience: it means a node can replicate from something that is not this server, and
//! an operator can watch the whole exchange with `ldapsearch -E sync=rp`.
//!
//! # Why persist and not poll
//!
//! A poll reports what the directory holds; it cannot report what it no longer holds. In a
//! full-mesh multi-master nobody is authoritative for a subtree, so "you did not name it, so it is
//! gone" would delete entries another node created a moment ago - this node's own new record, in
//! the worst case. A persistent search reports deletions as they happen, and that is the only
//! honest source for them.
//!
//! # What is deliberately missing
//!
//! - **No re-announcement of our own writes.** An applied remote change goes to the store with the
//!   remote `entryCSN` intact, so it is the same change on every node and a peer will ignore it as
//!   not newer. A node that stamped what it received would replicate for ever.
//! - **No transaction across nodes.** A change is written here when it arrives; if this node is
//!   down, the peer's journal holds it and the next connection resumes from the cookie.
//! - **No schema or configuration replication.** Entries only. A node with a different schema will
//!   accept what it can and report the rest, which is a real limitation and is written down rather
//!   than left to be discovered.
use std::time::Duration;

use rasn_ldap::{LdapDn, LdapMessage, ProtocolOp};

use crate::backend::redb_store::ChangeKind;
use crate::model::Entry;

/// One configured peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// `ldap://host:port` or `ldaps://host:port`.
    pub url: String,
    /// The peer's server id, when the operator declared one.
    ///
    /// Optional because a peer's id is only needed to detect the one mistake that cannot be
    /// repaired - two nodes sharing an id - and an operator who has not set it on the other side
    /// yet should not be blocked from starting.
    pub server_id: Option<u16>,
    pub bind_dn: Option<String>,
    pub password: Option<String>,
}

/// A peer's change, ready for [`crate::replication::merge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pushed {
    pub dn: String,
    pub kind: ChangeKind,
    /// The change's own CSN, from the entry's `entryCSN`, or from the state control for a
    /// deletion - which is the only thing a deletion has left.
    pub csn: Option<String>,
    /// `entryUUID` in the text form the state control carries as sixteen octets.
    pub uuid: Option<String>,
    /// The entry as the peer has it. `None` for a deletion.
    pub entry: Option<Entry>,
}

/// The configuration section as written.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct PeerConfig {
    pub url: String,
    #[serde(default)]
    pub server_id: Option<u16>,
    #[serde(default)]
    pub bind_dn: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerError {
    /// A peer with the same id as this node: every later change looks like it might be the same
    /// change, and the history cannot be untangled afterwards.
    SameServerId { url: String, id: u16 },
    /// Peers configured on a node that has no id of its own.
    NoOwnServerId,
    /// A URL this server cannot open, named rather than silently skipped.
    BadUrl { url: String, why: String },
    /// The same peer twice, which would apply every change twice and double the traffic.
    Duplicate { url: String },
    /// A bind DN without a password, or the other way round: half a credential is a mistake.
    HalfCredentials { url: String },
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SameServerId { url, id } => write!(
                formatter,
                "peer {url} declares server id {id}, which is this node's own: two nodes \
                 sharing an id produce changes that cannot be told apart, and the order between \
                 them cannot be recovered afterwards"
            ),
            Self::NoOwnServerId => write!(
                formatter,
                "peers are configured but server_id is not: without an id this node cannot tell \
                 its own changes from its peers', so replication would be a loop"
            ),
            Self::BadUrl { url, why } => write!(formatter, "peer url '{url}' is unusable: {why}"),
            Self::Duplicate { url } => {
                write!(formatter, "peer {url} is configured twice")
            }
            Self::HalfCredentials { url } => write!(
                formatter,
                "peer {url} has a bind DN or a password but not both"
            ),
        }
    }
}

/// Checks the `peers:` section against this node's own id.
pub fn from_config(peers: &[PeerConfig], own: u16) -> Result<Vec<Peer>, PeerError> {
    if peers.is_empty() {
        return Ok(Vec::new());
    }
    if own == 0 {
        return Err(PeerError::NoOwnServerId);
    }

    let mut resolved: Vec<Peer> = Vec::with_capacity(peers.len());

    for peer in peers {
        let url = peer.url.trim().to_string();
        check_url(&url)?;

        if let Some(id) = peer.server_id
            && id == own
        {
            return Err(PeerError::SameServerId { url, id });
        }

        match (&peer.bind_dn, &peer.password) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(PeerError::HalfCredentials { url });
            }
            _ => {}
        }

        if resolved.iter().any(|known| known.url == url) {
            return Err(PeerError::Duplicate { url });
        }

        resolved.push(Peer {
            url,
            server_id: peer.server_id,
            bind_dn: peer.bind_dn.clone(),
            password: peer.password.clone(),
        });
    }

    Ok(resolved)
}

fn check_url(url: &str) -> Result<(), PeerError> {
    let bad = |why: &str| PeerError::BadUrl {
        url: url.to_string(),
        why: why.to_string(),
    };

    let rest = url
        .strip_prefix("ldap://")
        .or_else(|| url.strip_prefix("ldaps://"))
        .ok_or_else(|| bad("the scheme must be ldap:// or ldaps://"))?;

    // A host is required: `ldap:///` with an empty host means the client's own machine, which is
    // never what a peer is, and silently connecting to localhost would replicate a node with
    // itself.
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() || host.starts_with(':') {
        return Err(bad("a host is required"));
    }
    if host.ends_with(':') {
        return Err(bad("a port is required after ':'"));
    }

    Ok(())
}

/// Turns one message from a peer into a change.
///
/// `None` for anything that is not an entry: the persistent search's `syncInfo` and the controls
/// that end a refresh are not changes, and reporting them as such would make every connection
/// start with a spurious write.
pub fn pushed(message: &LdapMessage) -> Option<Pushed> {
    let entry = match &message.protocol_op {
        ProtocolOp::SearchResEntry(entry) => entry,
        _ => return None,
    };

    let state = message
        .controls
        .as_ref()?
        .iter()
        .find(|control| control.control_type.as_ref() == crate::ldap::sync::SYNC_OID.as_bytes())
        .and_then(|control| control.control_value.as_ref())
        .and_then(|value| crate::ldap::sync::decode_state(value.as_ref()).ok())?;

    let dn = entry.object_name.0.to_string();
    let uuid = Some(text_uuid(&state.uuid));

    match state.state {
        crate::ldap::sync::State::Delete => Some(Pushed {
            dn,
            kind: ChangeKind::Delete,
            // A deletion has no attributes left, so its CSN can only come from the cookie -
            // `<snapshot>:<csn>` as this server issues it. A peer that sends no cookie leaves the
            // deletion unordered, and `merge` will say so rather than guess.
            csn: cookie_csn(state.cookie.as_deref()),
            uuid,
            entry: None,
        }),
        // A `present` entry is one the peer did not resend because it is unchanged: there is
        // nothing to merge, and writing it would put an empty entry over a full one.
        crate::ldap::sync::State::Present => None,
        _ => {
            let model = crate::client::entry_of(message)?;
            let csn = model
                .attributes()
                .get(crate::operational::ATTR_ENTRY_CSN)
                .and_then(|attribute| attribute.values.first())
                .cloned();

            Some(Pushed {
                dn,
                kind: match state.state {
                    crate::ldap::sync::State::Add => ChangeKind::Add,
                    _ => ChangeKind::Modify,
                },
                csn,
                uuid,
                entry: Some(model),
            })
        }
    }
}

/// The CSN a sync cookie carries, if it carries one.
fn cookie_csn(cookie: Option<&[u8]>) -> Option<String> {
    let text = std::str::from_utf8(cookie?).ok()?;
    let (_, csn) = crate::ldap::sync::decode_cookie(text.as_bytes())?;
    csn
}

/// `entryUUID` text from the sixteen octets of a `syncUUID`.
fn text_uuid(bytes: &[u8; 16]) -> String {
    let hex = |slice: &[u8]| {
        slice
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&bytes[0..4]),
        hex(&bytes[4..6]),
        hex(&bytes[6..8]),
        hex(&bytes[8..10]),
        hex(&bytes[10..16])
    )
}

/// The request a peer is asked, and the control that makes it a persistent search.
///
/// `refreshAndPersist` (mode 3), resuming from `cookie` when the connection has been here before.
/// A node that reconnects therefore gets the changes it missed rather than the whole directory -
/// and, more importantly, learns about the deletions that happened while it was away.
pub fn request(
    base: &str,
    cookie: Option<&[u8]>,
) -> (rasn_ldap::SearchRequest, Vec<rasn_ldap::Control>) {
    use rasn_ldap::{LdapString, SearchRequest, SearchRequestDerefAliases, SearchRequestScope};

    let control =
        crate::ldap::sync::request_control(crate::ldap::sync::Mode::RefreshAndPersist, cookie);

    let search = SearchRequest::new(
        LdapDn::from(base),
        SearchRequestScope::WholeSubtree,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        crate::ldap::filter_parse::parse("(objectClass=*)")
            .expect("a filter that cannot fail to parse"),
        vec![LdapString::from("*"), LdapString::from("+")],
    );

    (search, vec![control])
}

/// How long to wait before trying a peer again after it failed.
///
/// A fixed interval and not exponential backoff on purpose: a peer that comes back should be
/// picked up within seconds, and a directory is not a queue of retries where backing off protects
/// anything. A storm is bounded by the number of peers, which is small.
pub const RETRY: Duration = Duration::from_secs(5);

/// Where a conflict goes: a counter for alerting, and a file for resolving.
///
/// Both, because they answer different questions. The counter says "this node has disagreed with
/// a peer, go and look"; the file says which entry, against which change, and keeps saying it
/// after a restart. A conflict that only reached standard error is a conflict nobody can act on a
/// week later.
#[derive(Clone)]
pub struct Reporter {
    metrics: std::sync::Arc<crate::metrics::Metrics>,
    journal: std::sync::Arc<crate::metrics::Journal>,
}

impl Reporter {
    pub fn new(
        metrics: std::sync::Arc<crate::metrics::Metrics>,
        journal: std::sync::Arc<crate::metrics::Journal>,
    ) -> Self {
        Self { metrics, journal }
    }

    /// A reporter that counts and records nowhere: for a node with no peers, and for tests.
    pub fn silent() -> Self {
        Self {
            metrics: crate::metrics::Metrics::new(),
            journal: std::sync::Arc::new(crate::metrics::Journal::off()),
        }
    }

    /// Declares every configured peer, so its series exist before it is contacted.
    pub fn register(&self, peers: &[Peer]) {
        for peer in peers {
            self.metrics.register_peer(&peer.url);
        }
    }

    /// The persistent connection to this peer came up or went down.
    pub fn connected(&self, peer: &Peer, up: bool) {
        self.metrics.peer_connected(&peer.url, up);
    }

    /// An attempt to reach the peer, or to accept its change, failed.
    pub fn failed(&self, peer: &Peer) {
        self.metrics.peer_error(&peer.url);
    }

    /// What the merge decided, counted per peer.
    pub fn decided(&self, peer: &Peer, decision: &crate::replication::Decision, csn: Option<&str>) {
        match decision {
            crate::replication::Decision::Apply { .. } => {
                self.metrics.peer_change(&peer.url, true, csn)
            }
            // A conflict keeps the local version, so from this peer's point of view the change was
            // not written - counting it as applied would make a diverging node look healthy.
            crate::replication::Decision::Ignore { .. }
            | crate::replication::Decision::Conflict { .. } => {
                self.metrics.peer_change(&peer.url, false, None)
            }
        }
    }

    fn conflict(
        &self,
        peer: &Peer,
        dn: &str,
        local: Option<&str>,
        incoming: Option<&str>,
        why: &str,
    ) {
        let line = serde_json::json!({
            "time": crate::operational::generalized_time(std::time::SystemTime::now()),
            "peer": peer.url,
            "dn": dn,
            "local_csn": local,
            "incoming_csn": incoming,
            "reason": why,
        })
        .to_string();

        self.metrics.record_conflict();

        // A journal that cannot be written must not stop replication: a full disk would then take
        // the replica down for a reason that has nothing to do with the replica. The counter has
        // moved either way, and standard error says why.
        if let Err(err) = self.journal.record_line(&line) {
            eprintln!(
                "{}",
                crate::i18n::t(
                    "error.conflict_log",
                    &[("detail", &err.to_string()), ("dn", dn)]
                )
            );
        }
    }
}

/// Follows one peer for as long as this server runs.
///
/// Reconnects after any failure, resuming from the last cookie seen, so a peer that restarts or a
/// network that drops out costs the changes made while it was away and not the directory.
///
/// The loop applies what the peer sends and nothing else: it does not announce its own writes, and
/// a change received keeps the peer's `entryCSN`, so the same change is the same change on every
/// node and a peer will ignore it as not newer. A node that stamped what it received would
/// replicate for ever.
pub async fn follow(
    peer: Peer,
    source: std::sync::Arc<crate::reload::Source>,
    base_dn: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    reporter: Reporter,
) {
    let mut cookie: Option<Vec<u8>> = None;

    loop {
        if *shutdown.borrow() {
            return;
        }

        match exchange(
            &peer,
            &source,
            &base_dn,
            &mut cookie,
            &mut shutdown,
            &reporter,
        )
        .await
        {
            Ok(()) => {}
            Err(err) => {
                // The connection is down and the peer is behind; both facts belong in the metrics
                // before the retry, or a silent retry loop looks like a healthy node.
                reporter.connected(&peer, false);
                reporter.failed(&peer);
                eprintln!(
                    "{}",
                    crate::i18n::t("error.peer", &[("url", &peer.url), ("detail", &err)])
                );
            }
        }

        // A peer that went away is retried, but not while the server is stopping: shutdown must
        // not wait out a retry interval.
        tokio::select! {
            _ = tokio::time::sleep(RETRY) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

/// Whether resuming from `cookie` would ask about changes this node no longer remembers.
///
/// Comparing against the floor of the journal is the only way to know: pruning leaves no marker in
/// the surviving records, so a resume from a pruned cookie is indistinguishable from a resume from
/// a current one unless the caller checks.
fn too_old_for(cookie: &[u8], source: &crate::reload::Source) -> bool {
    let Some(csn) = cookie_csn(Some(cookie)) else {
        // A cookie this server cannot read is one it cannot resume from either.
        return true;
    };
    let Some(floor) = source.journal_floor().ok().flatten() else {
        // No journal at all: nothing was pruned, so there is nothing to have missed.
        return false;
    };

    csn.as_str() < floor.as_str()
}

/// One connection's worth of exchange.
async fn exchange(
    peer: &Peer,
    source: &std::sync::Arc<crate::reload::Source>,
    base_dn: &str,
    cookie: &mut Option<Vec<u8>>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    reporter: &Reporter,
) -> Result<(), String> {
    let client = crate::client::Client::connect(&peer.url, crate::client::Options::default())
        .await
        .map_err(|err| err.to_string())?;

    if let (Some(dn), Some(password)) = (&peer.bind_dn, &peer.password) {
        client
            .bind(dn, password)
            .await
            .map_err(|err| err.to_string())?;
    }

    // A cookie older than the oldest record still kept points into a part of the journal that
    // has been pruned. Resuming from it would ask for changes since a moment nobody can answer
    // about, and the answer would look complete: the range simply starts later. Dropping the
    // cookie costs a full refresh and is the only correct answer - a replica that is wrong and
    // looks healthy is worse than a slow one.
    if let Some(old) = cookie.clone()
        && too_old_for(&old, source)
    {
        eprintln!(
            "{}",
            crate::i18n::t("error.peer_behind", &[("url", &peer.url)])
        );
        *cookie = None;
    }

    let (request, controls) = request(base_dn, cookie.as_deref());
    let (refresh, _id) = client
        .search_persist(request, controls)
        .await
        .map_err(|err| err.to_string())?;

    // The connection is up once the peer has accepted the search: a socket that opened and refused
    // the request is not a working peer, and saying so would hide the difference.
    reporter.connected(peer, true);

    // The refresh itself is merged like any other change: a node that has been away needs what
    // happened while it was away, and the cookie only orders it - it does not replace it.
    for message in &refresh {
        absorb(peer, source, message, reporter).await?;

        // The connection's cookie moves forward with the answer, so a reconnect after a failure
        // in the middle of a refresh does not start from the beginning.
        if let Some(next) = cookie_of(message) {
            *cookie = Some(next);
        }
    }

    loop {
        let message = tokio::select! {
            message = client.next_change() => message.map_err(|err| err.to_string())?,
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
        };

        match message {
            Some(message) => {
                absorb(peer, source, &message, reporter).await?;
                if let Some(next) = cookie_of(&message) {
                    *cookie = Some(next);
                }
            }
            None => return Ok(()),
        }
    }
}

/// Merges one message from a peer into this directory.
async fn absorb(
    peer: &Peer,
    source: &std::sync::Arc<crate::reload::Source>,
    message: &LdapMessage,
    reporter: &Reporter,
) -> Result<(), String> {
    match pushed(message) {
        Some(change) => apply(peer, source, &change, reporter).await.map(|_| ()),
        // Not an entry: `syncInfo`, the end of a refresh, or something this server has no
        // business turning into a write.
        None => Ok(()),
    }
}

/// Decides about one change and carries the decision out.
///
/// Separated from [`absorb`] so a conflict can be tested without a socket: the decision is what
/// is worth pinning down, and it does not need a peer to be wrong at the other end.
pub async fn apply(
    peer: &Peer,
    source: &std::sync::Arc<crate::reload::Source>,
    change: &Pushed,
    reporter: &Reporter,
) -> Result<crate::replication::Decision, String> {
    // A peer that says which node it is, when the operator expected another id, is a node
    // replicating under somebody else's name - and every change it sends would be misordered.
    if let (Some(expected), Some(csn)) = (peer.server_id, change.csn.as_deref())
        && let Some(actual) = declared_id(csn)
        && actual != expected
    {
        return Err(crate::i18n::t(
            "error.peer_id",
            &[
                ("url", &peer.url),
                ("expected", &expected.to_string()),
                ("actual", &actual.to_string()),
            ],
        ));
    }

    let directory = source.directory().await;
    // The local version itself, not only its stamp: level 2 merges values, and a stamp says
    // nothing about which values this node already holds.
    let mut local_entry: Option<crate::model::Entry> = None;
    let (local, local_csn) = match directory.find(&change.dn) {
        Some(entry) => {
            local_entry = Some(entry.clone());
            let csn = entry
                .attributes()
                .get(crate::operational::ATTR_ENTRY_CSN)
                .and_then(|attribute| attribute.values.first())
                .cloned();
            (
                crate::replication::Local::Present {
                    csn: csn.clone(),
                    uuid: entry
                        .attributes()
                        .get(crate::model::ATTR_ENTRY_UUID)
                        .and_then(|attribute| attribute.values.first())
                        .cloned(),
                },
                csn,
            )
        }
        None => match source
            .tombstone(&change.dn)
            .map_err(|err| err.to_string())?
        {
            Some(csn) => (
                crate::replication::Local::Tombstone { csn: csn.clone() },
                Some(csn),
            ),
            None => (crate::replication::Local::Absent, None),
        },
    };

    let incoming = crate::replication::Incoming {
        csn: change.csn.clone(),
        kind: change.kind,
        uuid: change.uuid.clone(),
    };

    // Let go before the change is applied: `local` is an answer about one DN, and holding the
    // snapshot while the same directory is replaced made every replicated change copy the whole
    // directory - the same defect the write path had (see `server.rs`).
    drop(directory);

    let decision = crate::replication::merge(&local, &incoming);

    // Level 2, and the reason it is here rather than in `merge`: an entry-level stamp decides which
    // *version* is newer, and that is the wrong question when the two versions edited different
    // values. An older change can still carry a value this node never had - a member added on the
    // other node while this one was adding a different member - so the content written is the merge
    // of both, not the winner of one.
    //
    // Dropped when the decision is to keep the local version *and* the merge has nothing to add:
    // then the peer really is behind, and writing would rewrite the entry on every poll for ever.
    let merged: Option<crate::model::Entry> = match (&local_entry, &change.entry) {
        (Some(here), Some(there)) => {
            let (merged, report) = crate::replication::merge_entries(here, there);
            // `None` when the merge produced nothing the local version lacks: writing it then
            // would rewrite the entry on every poll for ever, which is the defect the entry-level
            // rule already avoids.
            report.changed().then_some(merged)
        }
        _ => None,
    };

    // An older change that carries a value this node never had is not a change to drop. This is
    // the whole point of level 2: the entry-level stamp answers "which version is newer", and the
    // answer is not "which values to keep".
    let decision = match (&decision, &merged) {
        (crate::replication::Decision::Ignore { .. }, Some(_)) => {
            crate::replication::Decision::Apply {
                why: "the peer's version is older, but it holds values this node does not: they \
                      are merged rather than dropped",
            }
        }
        _ => decision,
    };

    // Counted before it is carried out: an entry that fails to write is still a change the peer
    // sent and this node tried to apply, and hiding it would make a failing write look like a
    // peer that had nothing to say.
    reporter.decided(peer, &decision, change.csn.as_deref());

    match &decision {
        crate::replication::Decision::Apply { .. } => {
            // Checked here, before the store sees it. The schema is otherwise enforced by the
            // reload that follows a change, which is too late: a peer could write an entry this
            // server's own schema refuses, the reload would then refuse the directory, and the
            // node would stop starting - a remote node deciding whether this one runs.
            //
            // `warn` keeps the older behaviour on purpose: an operator who chose to report
            // violations instead of refusing them reads the report; refusing here would enforce
            // a policy they turned off.
            let entry_change = match &change.entry {
                Some(entry) => {
                    // The merge when there was one, the peer's entry otherwise. `merged` already
                    // carries this node's operational attributes, which is why it is not passed
                    // through `without_derived`: those attributes are this node's own.
                    let entry = match &merged {
                        Some(merged) => merged.clone(),
                        None => without_derived(entry),
                    };

                    if source.schema_mode() != crate::schema::Mode::Warn
                        && let Err(violations) = source.schema().check(&entry)
                    {
                        let detail = violations
                            .iter()
                            .map(|violation| format!("{:?}: {}", violation.code, violation.detail))
                            .collect::<Vec<_>>()
                            .join("; ");

                        eprintln!(
                            "{}",
                            crate::i18n::t(
                                "error.peer_schema",
                                &[("url", &peer.url), ("dn", &change.dn), ("detail", &detail)]
                            )
                        );

                        // Skipped rather than failed: one entry this node cannot store must not
                        // stop the rest of the stream, and the next poll will try again - the
                        // log line is what an operator acts on.
                        return Ok(crate::replication::Decision::Ignore {
                            why: "the peer sent an entry this server's schema refuses",
                        });
                    }

                    crate::backend::EntryChange::Upsert { entry }
                }
                None => crate::backend::EntryChange::delete(change.dn.clone(), None),
            };

            source
                .apply(&[entry_change])
                .await
                .map_err(|err| err.to_string())?;
        }
        crate::replication::Decision::Ignore { .. } => {}
        crate::replication::Decision::Conflict { why } => {
            // Named, counted and written down. This is the one outcome that says a record may
            // exist on one node and not the other, so it is not allowed to be a line in a stream
            // that a restart erases.
            eprintln!(
                "{}",
                crate::i18n::t(
                    "error.peer_conflict",
                    &[("url", &peer.url), ("dn", &change.dn), ("why", why)]
                )
            );
            reporter.conflict(
                peer,
                &change.dn,
                local_csn.as_deref(),
                change.csn.as_deref(),
                why,
            );
        }
    }

    Ok(decision)
}

/// The entry as data, with the attributes a peer computed about it removed.
///
/// A peer that asks for `+` receives `entryDN` and `subschemaSubentry` along with the operational
/// attributes a replica actually needs (`entryCSN`, `entryUUID`). Those two describe the answering
/// server, not the entry: storing them here would fail this server's own schema check, and the
/// failure would repeat on every poll, so replication would never converge - which is exactly what
/// happened before this was here, with the peer retrying every five seconds for ever.
///
/// Stripped on receipt rather than only on sending, because the two ends are upgraded one at a
/// time: a node running an older build still sends them, and a stream that only the newest build
/// can accept is not replication.
fn without_derived(entry: &crate::model::Entry) -> crate::model::Entry {
    let mut attributes = crate::model::Attributes::new();
    for attribute in entry.attributes().values() {
        if !crate::model::is_derived(&attribute.name) {
            attributes = attributes.push(attribute.clone());
        }
    }
    crate::model::Entry::new(entry.dn(), attributes)
}

/// The cookie a message carries, if it carries one.
fn cookie_of(message: &LdapMessage) -> Option<Vec<u8>> {
    let controls = message.controls.as_ref()?;

    for control in controls {
        if control.control_type.as_ref() != crate::ldap::sync::SYNC_OID.as_bytes() {
            continue;
        }
        let value = control.control_value.as_ref()?.as_ref();

        // A `syncState` control on an entry, or a `syncDone` on the end of the answer: both carry
        // the cookie in the same first optional octet string, and either is a better starting
        // point than the one before it.
        if let Ok(state) = crate::ldap::sync::decode_state(value) {
            if let Some(cookie) = state.cookie {
                return Some(cookie);
            }
            continue;
        }
    }

    None
}

/// A peer's own id, as its CSN says, for the check that cannot wait for the operator.
///
/// Returns `None` when the peer says nothing, which is not a failure: a peer with no id is a
/// single node that someone pointed at this one.
pub fn declared_id(csn: &str) -> Option<u16> {
    crate::replication::Csn::parse(csn).map(|csn| csn.server)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(url: &str, id: Option<u16>) -> PeerConfig {
        PeerConfig {
            url: url.to_string(),
            server_id: id,
            bind_dn: None,
            password: None,
        }
    }

    #[test]
    fn a_derived_attribute_never_reaches_the_store() {
        // What a peer computes about an entry describes the peer. Storing it fails this server's
        // schema check, and the failure repeats on every poll, so replication never converges -
        // which is what a live two-node run showed before the strip existed.
        use crate::model::{Attribute, Attributes, Entry};

        let entry = Entry::new(
            "uid=alice,ou=users,dc=example,dc=com",
            Attributes::new()
                .push(Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "person".to_string()],
                ))
                .push(Attribute::single("uid", "alice"))
                .push(
                    Attribute::single("entryDN", "uid=alice,ou=users,dc=example,dc=com")
                        .operational(),
                )
                .push(Attribute::single("subschemaSubentry", "cn=Subschema").operational())
                .push(
                    Attribute::single("entryUUID", "11111111-1111-1111-1111-111111111111")
                        .operational(),
                ),
        );

        let stripped = without_derived(&entry);
        let names: Vec<String> = stripped
            .attributes()
            .values()
            .iter()
            .map(|attribute| attribute.name.to_string())
            .collect();

        assert!(
            !names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("entryDN")),
            "entryDN is the DN spelled again, not data: {names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("subschemaSubentry")),
            "subschemaSubentry names the peer's schema, not ours: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("entryUUID")),
            "and the attributes a replica does need are kept: {names:?}"
        );
        assert_eq!(
            stripped.dn(),
            entry.dn(),
            "the DN is the entry's own and survives the strip"
        );
    }

    #[test]
    fn a_peer_with_this_nodes_id_is_refused() {
        // The one mistake that cannot be repaired later: two nodes with one id produce changes
        // that look identical, and the merge that follows is a coin toss.
        let err = from_config(&[config("ldap://peer:389", Some(3))], 3).expect_err("must refuse");
        assert_eq!(
            err,
            PeerError::SameServerId {
                url: "ldap://peer:389".to_string(),
                id: 3
            }
        );
    }

    #[test]
    fn peers_without_a_node_id_are_refused() {
        let err = from_config(&[config("ldap://peer:389", None)], 0).expect_err("must refuse");
        assert_eq!(err, PeerError::NoOwnServerId);
    }

    #[test]
    fn an_empty_section_is_not_an_error() {
        // Every single-node deployment: no peers, no id, nothing to check.
        assert!(from_config(&[], 0).expect("no peers").is_empty());
    }

    #[test]
    fn a_url_that_cannot_be_opened_is_refused_with_the_reason() {
        for url in [
            "",
            "peer:389",
            "https://peer:389",
            // An empty host means the local machine, which would be this node talking to itself.
            "ldap:///:389",
            "ldap://:389",
            "ldap://peer:",
        ] {
            let result = from_config(&[config(url, Some(2))], 1);
            assert!(
                matches!(result, Err(PeerError::BadUrl { .. })),
                "{url:?} must be refused: {result:?}"
            );
        }
    }

    #[test]
    fn a_usable_url_passes_both_schemes() {
        for url in [
            "ldap://peer:389",
            "ldaps://peer:636",
            "ldap://10.0.0.5:1389",
        ] {
            let peers = from_config(&[config(url, Some(2))], 1).expect("config");
            assert_eq!(peers[0].url, url);
        }
    }

    #[test]
    fn the_same_peer_twice_is_refused() {
        // Applied twice and polled twice is not a slow node, it is a mistake in the file.
        let err = from_config(
            &[
                config("ldap://peer:389", Some(2)),
                config("ldap://peer:389", Some(2)),
            ],
            1,
        )
        .expect_err("must refuse");
        assert!(matches!(err, PeerError::Duplicate { .. }));
    }

    #[test]
    fn half_a_credential_is_refused() {
        let mut peer = config("ldap://peer:389", Some(2));
        peer.bind_dn = Some("cn=reader,dc=example,dc=com".to_string());
        let err = from_config(&[peer], 1).expect_err("must refuse");
        assert!(matches!(err, PeerError::HalfCredentials { .. }));
    }

    #[test]
    fn a_state_control_names_the_entry_it_is_about() {
        // The conversion the exchange lives or dies by: a message that is not an entry must not
        // become a change, or every connection starts by writing nonsense.
        let message = binding_message();
        let change = pushed(&message).expect("a change");

        assert_eq!(change.dn, "cn=alice,ou=users,dc=example,dc=com");
        assert_eq!(change.kind, ChangeKind::Add);
        assert_eq!(
            change.uuid.as_deref(),
            Some("00112233-4455-6677-8899-aabbccddeeff")
        );
        assert_eq!(
            change.csn.as_deref(),
            Some("20261104005712.352052Z#000012#003#000000"),
            "the entry's own entryCSN, not the connection's"
        );
    }

    #[test]
    fn a_sync_info_message_is_not_a_change() {
        let message = crate::ldap::sync::info_refresh_present(Some(b"0:csn"));
        assert_eq!(pushed(&message), None);
    }

    #[test]
    fn an_unchanged_entry_is_not_written_over() {
        // `present` means "you already have this". Writing it would put an empty entry over a full
        // one - a replica that empties itself on every poll.
        let mut message = binding_message();
        set_state(&mut message, crate::ldap::sync::State::Present);
        assert_eq!(pushed(&message), None);
    }

    #[test]
    fn a_deletion_carries_no_entry_and_its_csn_comes_from_the_cookie() {
        let mut message = binding_message();
        set_state(&mut message, crate::ldap::sync::State::Delete);
        if let ProtocolOp::SearchResEntry(entry) = &mut message.protocol_op {
            entry.attributes = Vec::new();
        }

        let change = pushed(&message).expect("a change");
        assert_eq!(change.kind, ChangeKind::Delete);
        assert_eq!(change.entry, None);
        assert!(
            change.csn.is_some(),
            "a deletion has nothing but its CSN to be ordered by"
        );
    }

    /// A source over a temporary redb store, seeded with one entry.
    async fn source_with(
        entry: Entry,
    ) -> (std::sync::Arc<crate::reload::Source>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dir.redb");
        let backend = crate::backend::Backend::from_config(
            "redb",
            Some(&serde_json::json!({"path": path.display().to_string()})),
        )
        .expect("backend");

        backend
            .apply(&[crate::backend::EntryChange::Upsert { entry }])
            .await
            .expect("seed");

        let config = crate::config::Config {
            #[cfg(feature = "kdc")]
            kerberos: crate::kerberos::KerberosConfig::default(),
            cldap: Default::default(),
            cache: crate::record_cache::CacheConfig::default(),
            backend: "redb".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            listen_addr: "127.0.0.1:0".to_string(),
            update_interval: std::time::Duration::from_secs(3600),
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
            schema_mode: crate::schema::Mode::Off,
            schema_files: Vec::new(),
            schema_definitions: Vec::new(),
            indexes: Default::default(),
            referrals: Default::default(),
            server_id: 2,
            peers: Vec::new(),
            journal_keep: None,
            journal_max_age: None,
            conflict_log: None,
            sasl: Default::default(),
            acl: Default::default(),
            allow_unencrypted_bind: true,
            dangerous_settings: Vec::new(),
            integrity: Default::default(),
            limits: Default::default(),
            observability: Default::default(),
            bootstrap: None,
            locale: (crate::i18n::Locale::english(), crate::i18n::Source::Default),
            locale_file: None,
            document: None,
        };

        let (source, _) = crate::reload::Source::load(&config, backend)
            .await
            .expect("source");
        (source, dir)
    }

    #[tokio::test]
    async fn a_disagreement_about_identity_is_recorded_where_an_operator_can_find_it() {
        // Two nodes created this DN independently, so they hold different records that happen to
        // share a name. The newer timestamp is not the answer, and the local version is kept -
        // which means the peer's record exists nowhere. That is why the conflict has to outlive
        // the connection: a line on standard error is gone after a restart, and the operator
        // learns about the missing record from its absence instead.
        let local = crate::model::Entry::new(
            "cn=clash,ou=users,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(crate::model::Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "person".to_string()],
                ))
                .push(crate::model::Attribute::single("cn", "clash"))
                .push(
                    crate::model::Attribute::single(
                        "entryUUID",
                        "11111111-1111-1111-1111-111111111111",
                    )
                    .operational(),
                )
                .push(
                    crate::model::Attribute::single(
                        "entryCSN",
                        "20260101000000.000001Z#000001#002#000000",
                    )
                    .operational(),
                ),
        );

        let (source, dir) = source_with(local).await;
        let log_path = dir.path().join("conflicts.jsonl");
        let journal = crate::metrics::Journal::file(&log_path).expect("journal");
        let metrics = crate::metrics::Metrics::new();
        let reporter = Reporter::new(
            std::sync::Arc::clone(&metrics),
            std::sync::Arc::new(journal),
        );

        let incoming = Pushed {
            dn: "cn=clash,ou=users,dc=example,dc=com".to_string(),
            kind: ChangeKind::Add,
            csn: Some("20260101000000.000009Z#000001#001#000000".to_string()),
            uuid: Some("22222222-2222-2222-2222-222222222222".to_string()),
            entry: None,
        };

        let decision = apply(&peer_of("ldap://node1:389"), &source, &incoming, &reporter)
            .await
            .expect("apply");

        assert!(
            matches!(decision, crate::replication::Decision::Conflict { .. }),
            "expected a conflict, got {decision:?}"
        );
        assert_eq!(metrics.conflicts(), 1, "the counter an operator alerts on");

        let written = std::fs::read_to_string(&log_path).expect("conflict log");
        let line: serde_json::Value =
            serde_json::from_str(written.trim()).expect("one json object per line");

        assert_eq!(line["dn"], "cn=clash,ou=users,dc=example,dc=com");
        assert_eq!(line["peer"], "ldap://node1:389");
        assert_eq!(
            line["local_csn"], "20260101000000.000001Z#000001#002#000000",
            "both sides, so the operator can tell which record was kept"
        );
        assert_eq!(
            line["incoming_csn"],
            "20260101000000.000009Z#000001#001#000000"
        );
        assert!(
            line["reason"]
                .as_str()
                .is_some_and(|why| why.contains("independently")),
            "and why the timestamp was not the answer"
        );

        // The local version survived: a conflict keeps what is here, it does not delete it.
        let directory = source.directory().await;
        let entry = directory
            .find("cn=clash,ou=users,dc=example,dc=com")
            .expect("still here");
        assert_eq!(
            entry
                .attributes()
                .get("entryUUID")
                .and_then(|attribute| attribute.values.first())
                .map(String::as_str),
            Some("11111111-1111-1111-1111-111111111111")
        );
    }

    /// A peer, as the configuration would produce one.
    fn peer_of(url: &str) -> Peer {
        Peer {
            url: url.to_string(),
            server_id: Some(1),
            bind_dn: None,
            password: None,
        }
    }

    fn set_state(message: &mut LdapMessage, state: crate::ldap::sync::State) {
        let uuid = uuid_bytes();
        let value = crate::ldap::sync::encode_state(
            state,
            &uuid,
            Some(b"0:20261104005712.352052Z#000012#003#000000"),
        );
        if let Some(controls) = &mut message.controls {
            controls[0].control_value = Some(rasn::types::OctetString::from(value));
        }
    }

    fn uuid_bytes() -> [u8; 16] {
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(0x11);
        }
        bytes
    }

    fn binding_message() -> LdapMessage {
        use rasn::types::SetOf;
        use rasn_ldap::{
            AttributeDescription, AttributeValue, PartialAttribute, SearchResultEntry,
        };

        let uuid = uuid_bytes();
        let control = rasn_ldap::Control::new(
            rasn_ldap::LdapOid::from(crate::ldap::sync::SYNC_OID.as_bytes()),
            false,
            Some(rasn::types::OctetString::from(
                crate::ldap::sync::encode_state(
                    crate::ldap::sync::State::Add,
                    &uuid,
                    Some(b"0:20261104005712.352052Z#000012#003#000000"),
                ),
            )),
        );

        let attributes = vec![
            PartialAttribute::new(
                AttributeDescription::from("objectClass"),
                SetOf::from_vec(vec![AttributeValue::from(b"top".to_vec())]),
            ),
            PartialAttribute::new(
                AttributeDescription::from("cn"),
                SetOf::from_vec(vec![AttributeValue::from(b"alice".to_vec())]),
            ),
            PartialAttribute::new(
                AttributeDescription::from("entryCSN"),
                SetOf::from_vec(vec![AttributeValue::from(
                    b"20261104005712.352052Z#000012#003#000000".to_vec(),
                )]),
            ),
        ];

        let mut message = LdapMessage::new(
            3,
            ProtocolOp::SearchResEntry(SearchResultEntry::new(
                LdapDn::from("cn=alice,ou=users,dc=example,dc=com"),
                attributes,
            )),
        );
        message.controls = Some(vec![control]);
        message
    }
}
