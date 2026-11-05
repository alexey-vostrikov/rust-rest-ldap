//! Multi-master replication, level one: one entry at a time, last writer wins.
//!
//! What this module is, and what it deliberately is not. It holds the parts of multi-master that
//! can be decided without a network: how a change sequence number is parsed and ordered, which
//! server wrote it, and - given what this directory holds for a DN and what a peer says about it -
//! whether to write the peer's version, drop it, or stop and report a conflict. The exchange itself
//! lives in [`crate::peers`], and it does nothing but carry [`ChangeRecord`]s in and
//! [`Decision`]s out.
//!
//! The split is not tidiness. Conflict resolution is the part that is wrong quietly: two nodes
//! disagree, something is written, and nobody notices until a record is missing a month later.
//! Keeping it a pure function means the cases - resurrect a deletion, ignore a stale write, refuse
//! a same-DN-with-two-UUIDs clash - are tested without sockets, timing, or a second process.
//!
//! # Why entry-level
//!
//! [`Decision`] settles a whole entry from one CSN. If two nodes edit different attributes of the
//! same entry at the same moment, one edit is lost. That is a real loss, and the answer is not
//! "someday attribute-level" but a reason: the same entry edited from two places within the time
//! it takes to replicate is rare, and nearly always two people doing the same job twice rather
//! than two different jobs. Attribute-level needs a CSN beside every value and operations in the
//! journal instead of the finished entry (level 2); version vectors need one entry per node
//! (level 3). Both are recorded in `docs/plan.md` with what would force them.
//!
//! # What a CSN has to say
//!
//! `<timestamp>#<counter>#<server>#<modifier>`, OpenLDAP's form:
//! `20261104005712.352052Z#000012#003#000000`. The timestamp orders changes across nodes; the
//! counter separates changes made in the same microsecond on one node; the server id says **which
//! node wrote it**, and without it two nodes' changes are indistinguishable and the third field is
//! decoration. The modifier field is zero: it exists for a "modify" counter this server does not
//! use.
use std::sync::atomic::{AtomicU16, Ordering};

use std::sync::Arc;

use crate::backend::redb_store::ChangeKind;
use crate::model::{Attribute, Entry};

/// The largest server id a CSN can carry: the field is three decimal digits.
pub const MAX_SERVER_ID: u16 = 999;

/// The id this process writes into its changes, or zero when it is not replicating.
///
/// A process-global with a default rather than a parameter through every write: a CSN is made
/// deep inside the write path, in `operational::stamp_write`, and threading an id through it would
/// touch every caller to say the same thing. Zero is the honest default - it is what OpenLDAP
/// writes when no server id is configured, and it means "this node does not replicate", so a
/// single-node deployment is unaffected and its stored CSNs keep their shape.
static SERVER_ID: AtomicU16 = AtomicU16::new(0);

/// Sets the id written into every change from now on.
///
/// Returns the previous one, so a caller can put it back; tests that need a particular id use
/// [`stamp_write_for`](crate::operational::stamp_write_for) instead of this.
pub fn set_server_id(id: u16) -> u16 {
    SERVER_ID.swap(id, Ordering::Relaxed)
}

/// The id written into changes right now.
pub fn server_id() -> u16 {
    SERVER_ID.load(Ordering::Relaxed)
}

/// A change sequence number, parsed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Csn {
    /// `YYYYmmddHHMMSS.microsecondsZ`, kept as text: it is fixed-width, so text order is time
    /// order, and no date arithmetic is needed to compare two of them.
    pub timestamp: String,
    pub counter: u32,
    pub server: u16,
    pub modifier: u32,
}

impl Csn {
    /// Parses `<timestamp>#<counter>#<server>#<modifier>`.
    ///
    /// `None` for anything else, and the caller must not guess: a CSN that cannot be ordered is a
    /// change whose place in history is unknown, and inventing an order for it is exactly the
    /// silent divergence this module exists to prevent.
    pub fn parse(text: &str) -> Option<Csn> {
        let mut parts = text.split('#');
        let timestamp = parts.next()?;
        let counter = parts.next()?;
        let server = parts.next()?;
        let modifier = parts.next()?;

        // Exactly four fields: a fifth means a format this server does not know, and reading the
        // first four of it would be a guess dressed as parsing.
        if parts.next().is_some() {
            return None;
        }

        if timestamp.is_empty() || !timestamp.ends_with('Z') {
            return None;
        }

        Some(Csn {
            timestamp: timestamp.to_string(),
            counter: numeric(counter)?,
            server: numeric(server)?,
            modifier: numeric(modifier)?,
        })
    }

    /// Whether this change came after `other`.
    ///
    /// Strictly after: two changes with the same CSN are the same change, and a merge that treats
    /// them as different would write the same entry for ever.
    pub fn is_newer_than(&self, other: &Csn) -> bool {
        self > other
    }
}

fn numeric<T: std::str::FromStr>(text: &str) -> Option<T> {
    // Only digits: `+3`, ` 3` and `3x` all fail to parse, and a leading zero is allowed because
    // the fields are zero-padded by construction.
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// A server id, checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServerId(u16);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIdError(pub u16);

impl std::fmt::Display for ServerIdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "server id {} is out of range: it must be between 1 and {MAX_SERVER_ID}, because a CSN \
             carries it in three decimal digits and zero means \"this node does not replicate\"",
            self.0
        )
    }
}

impl ServerId {
    pub fn new(value: u16) -> Result<ServerId, ServerIdError> {
        if value == 0 || value > MAX_SERVER_ID {
            return Err(ServerIdError(value));
        }
        Ok(ServerId(value))
    }

    pub fn value(self) -> u16 {
        self.0
    }
}

/// What this directory holds for a DN, as far as ordering a change is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Local {
    /// The entry is here. `csn` is its `entryCSN`, absent for an entry nothing has stamped -
    /// the naming context and the two units are synthesised and never stamped.
    Present {
        csn: Option<String>,
        uuid: Option<String>,
    },
    /// The entry was deleted here, and the deletion is remembered.
    Tombstone { csn: String },
    /// Neither: this directory has never seen the DN.
    Absent,
}

/// What a peer says happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    /// The change's sequence number, or `None` when the peer sent none at all.
    ///
    /// `None` and "unparseable" are different facts and are treated differently. A peer that says
    /// nothing about order has told the truth about an entry the directory synthesises - the
    /// naming context and its units carry no `entryCSN`, because nothing wrote them. A peer that
    /// sends something this server cannot read has sent a change whose place in history is
    /// unknown, and that is a conflict.
    pub csn: Option<String>,
    pub kind: ChangeKind,
    /// The entry's `entryUUID`. Two nodes that independently created the same DN have two, and
    /// that is a conflict no timestamp settles.
    pub uuid: Option<String>,
}

/// What to do with a peer's change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Write it.
    Apply { why: &'static str },
    /// Nothing to do - and the reason, so a log line says which case it was.
    Ignore { why: &'static str },
    /// Two histories that a CSN cannot reconcile. Keep the local version and report it: picking
    /// one silently is how a directory loses a record and nobody notices for a month.
    Conflict { why: &'static str },
}

/// What merging two versions of one attribute did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Merged {
    /// Values the local version did not have.
    pub added: usize,
    /// Values where the incoming change was newer and replaced the local stamp.
    pub updated: usize,
    /// Values where the local change was newer and was kept.
    pub kept: usize,
}

/// Merges two versions of one multi-valued attribute, value by value.
///
/// Level 2 of multi-master. Level 1 settles a whole entry from the entry's own `entryCSN`, so two
/// nodes editing *different attributes* of the same entry at the same moment lose one edit - and
/// that is not a rare accident, it is two administrators doing their jobs. With a change recorded
/// beside each value, the two edits are different values and both survive.
///
/// The rules, each with the reason it is not the other thing:
///
/// - **Union of values.** A value is kept if either side has it. A value that only one side has was
///   never deleted by the other, because a deletion leaves a stamp too (see `Removed`), and an
///   absent value with no stamp means "this version never knew it".
/// - **Newest stamp wins for a value both sides have.** The stamp says which change wrote it, and a
///   later change wrote the value it names.
/// - **Unstamped loses to stamped.** A value from an import, or one written before stamps existed,
///   has no history; giving it priority over a recorded change would let an old file beat a live
///   directory.
/// - **A CSN orders completely, and that is what makes the merge agree with itself.** Two changes in
///   the same microsecond are separated by the server id in the third field, so the same pair of
///   versions resolves the same way on every node - which is the property a merge needs more than
///   it needs a tie-break nobody can reproduce.
pub fn merge_attribute(local: &Attribute, incoming: &Attribute) -> (Attribute, Merged) {
    if local.values.is_empty() {
        return (incoming.clone(), Merged::default());
    }

    let local_stamps = local.stamps();
    let incoming_stamps = incoming.stamps();

    let mut values: Vec<String> = local.values.to_vec();
    let mut stamps: Vec<Arc<str>> = local_stamps.iter().map(|csn| Arc::from(*csn)).collect();
    let mut report = Merged::default();

    for (at, value) in incoming.values.iter().enumerate() {
        let incoming_stamp = incoming_stamps.get(at).copied().unwrap_or("");

        match values.iter().position(|held| held == value) {
            None => {
                values.push(value.clone());
                stamps.push(Arc::from(incoming_stamp));
                report.added += 1;
            }
            Some(position) => {
                let local_stamp = &*stamps[position];
                match compare_stamps(local_stamp, incoming_stamp) {
                    StampOrder::Incoming => {
                        stamps[position] = Arc::from(incoming_stamp);
                        report.updated += 1;
                    }
                    StampOrder::Local => report.kept += 1,
                    // The same change arriving twice, which replication does all the time. Nothing
                    // to choose: both stamps name the same write.
                    StampOrder::Same => {}
                }
            }
        }
    }

    // Flags travel with the local attribute: they describe how the attribute behaves, not which
    // change wrote it, and the schema decides them.
    let mut merged = Attribute {
        name: Arc::clone(&local.name),
        values: values.into_boxed_slice(),
        flags: local.flags,
        value_csns: None,
    };
    if stamps.iter().any(|csn| !csn.is_empty()) {
        merged.value_csns = Some(stamps.into_boxed_slice());
    }

    (merged, report)
}

/// What merging two versions of an entry did, across all its attributes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MergedEntry {
    pub attributes_added: usize,
    /// Values gained from the version that did not have them here.
    pub values_gained: usize,
    /// Values whose stamp the other version moved forward.
    pub values_updated: usize,
}

impl MergedEntry {
    /// Whether the merge produced anything the local version did not already hold.
    ///
    /// This is what decides whether a change that entry-level ordering would have dropped has to be
    /// written anyway: an older change can still carry a value this node never had, and dropping it
    /// because its timestamp is older is exactly the loss level 2 exists to prevent.
    pub fn changed(&self) -> bool {
        self.attributes_added > 0 || self.values_gained > 0 || self.values_updated > 0
    }
}

/// Merges two versions of one entry, attribute by attribute and value by value.
///
/// The result is the union of what both sides know, with the newer change owning each value it
/// wrote. Attributes present on both sides are merged with [`merge_attribute`]; an attribute only
/// one side has is taken whole.
///
/// The local entry's own operational attributes are kept: `entryCSN`, `entryUUID` and the
/// timestamps describe *this* node's record of the entry, and letting a peer's copy of them win
/// would make the two nodes disagree about who wrote what.
pub fn merge_entries(local: &Entry, incoming: &Entry) -> (Entry, MergedEntry) {
    let mut merged = local.attributes().clone();
    let mut report = MergedEntry::default();

    for attribute in incoming.attributes().values() {
        // Operational attributes belong to the node that holds the entry: `entryCSN` in particular
        // is what the caller has already decided about, and a second opinion from the peer's copy
        // would overwrite that decision.
        if attribute.flags.operational || attribute.flags.internal {
            continue;
        }

        match merged.get(&attribute.name) {
            None => {
                merged = merged.push(attribute.clone());
                report.attributes_added += 1;
                report.values_gained += attribute.values.len();
            }
            Some(existing) => {
                let existing = existing.clone();
                let (result, attribute_report) = merge_attribute(&existing, attribute);
                report.values_gained += attribute_report.added;
                report.values_updated += attribute_report.updated;
                merged = merged.replace(result);
            }
        }
    }

    (Entry::new(local.dn(), merged), report)
}

/// How two stamps order against each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StampOrder {
    Incoming,
    Local,
    /// The same change: one node's change arriving twice, which replication does all the time.
    Same,
}

fn compare_stamps(local: &str, incoming: &str) -> StampOrder {
    if local == incoming {
        return StampOrder::Same;
    }
    // An unstamped value has no history, so any recorded change is later than it.
    if local.is_empty() {
        return StampOrder::Incoming;
    }
    if incoming.is_empty() {
        return StampOrder::Local;
    }

    let (Some(local_csn), Some(incoming_csn)) = (Csn::parse(local), Csn::parse(incoming)) else {
        // A stamp that cannot be parsed is a stamp that cannot be ordered. Keeping the local value
        // is the conservative answer, and the caller reports it.
        return StampOrder::Local;
    };

    // `Csn` orders by timestamp, then counter, then server id: two changes in the same
    // microsecond are still ordered, and every node orders them the same way. Equal CSNs were
    // handled above as the same change.
    if incoming_csn > local_csn {
        StampOrder::Incoming
    } else {
        StampOrder::Local
    }
}

/// Decides what to do with `incoming`, given `local`.
///
/// Entry-level last-writer-wins, with the cases where a timestamp is the wrong tool spelled out.
pub fn merge(local: &Local, incoming: &Incoming) -> Decision {
    let incoming_csn = match &incoming.csn {
        None => {
            // Nothing to order by. An entry this directory does not hold is taken: there is
            // nothing to overwrite and writing it once is idempotent. An entry it does hold is
            // left alone - applying an unordered change to it would rewrite it on every poll, for
            // ever, because nothing could ever make it stale.
            return match local {
                Local::Absent => Decision::Apply {
                    why: "the peer sent no change sequence number, but this directory does not \
                          hold the entry at all, so writing it cannot lose anything",
                },
                _ => Decision::Ignore {
                    why: "the peer sent a change with no change sequence number: there is no \
                          order to apply it in, so the local version stays",
                },
            };
        }
        Some(text) => match Csn::parse(text) {
            Some(csn) => csn,
            None => {
                return Decision::Conflict {
                    why: "the incoming change carries a change sequence number this server \
                          cannot order, so there is no honest way to place it in history",
                };
            }
        },
    };

    match local {
        Local::Absent => match incoming.kind {
            ChangeKind::Delete => Decision::Ignore {
                // Without a tombstone there is nothing to mark deleted and nothing to remember.
                // A node that has never held the entry and is told it is gone is simply right.
                why: "the entry was never here, so a deletion for it changes nothing",
            },
            _ => Decision::Apply {
                why: "the entry is new to this directory",
            },
        },

        Local::Tombstone { csn } => {
            let tombstone = match Csn::parse(csn) {
                Some(csn) => csn,
                // A tombstone we cannot order is not a tombstone we can trust to block anything.
                None => {
                    return Decision::Conflict {
                        why: "the local deletion record carries a change sequence number this \
                              server cannot order",
                    };
                }
            };

            if !incoming_csn.is_newer_than(&tombstone) {
                return Decision::Ignore {
                    why: "this entry was deleted here at the same time or later",
                };
            }

            match incoming.kind {
                ChangeKind::Delete => Decision::Apply {
                    why: "a later deletion moves the tombstone forward, so it is remembered longer",
                },
                _ => Decision::Apply {
                    why: "a change newer than the deletion brings the entry back",
                },
            }
        }

        Local::Present { csn, uuid } => {
            let local_csn = match csn {
                Some(text) => match Csn::parse(text) {
                    Some(csn) => Some(csn),
                    None => {
                        return Decision::Conflict {
                            why: "this entry carries a change sequence number this server cannot \
                                  order, so there is no basis for comparison",
                        };
                    }
                },
                None => None,
            };

            if let Some(local_csn) = &local_csn
                && !incoming_csn.is_newer_than(local_csn)
            {
                return Decision::Ignore {
                    why: "this directory already has this change or a later one",
                };
            }

            // A deletion carries no record, so there is nothing to compare identities about;
            // refusing it would leave a dead entry here for ever.
            if incoming.kind != ChangeKind::Delete
                && let Some(local_uuid) = uuid
                && let Some(incoming_uuid) = &incoming.uuid
                && local_uuid != incoming_uuid
            {
                return Decision::Conflict {
                    why: "both nodes created this DN independently, with different identities: \
                          the newer timestamp is not the right answer, because the entries are \
                          different records that happen to share a name",
                };
            }

            match incoming.kind {
                ChangeKind::Delete => {
                    if local_csn.is_none() {
                        // An entry with no `entryCSN` cannot be older than anything, and refusing
                        // the deletion would leave it here for ever: whatever stamped it died with
                        // the old data model. Deletions are accepted, and noted.
                        return Decision::Apply {
                            why: "the local entry carries no change sequence number, so a deletion \
                                  for it cannot be placed in order and is taken as the intent",
                        };
                    }
                    Decision::Apply {
                        why: "a later deletion of an entry this directory holds",
                    }
                }
                _ => {
                    if local_csn.is_none() {
                        return Decision::Apply {
                            why: "the local entry carries no change sequence number to compare \
                                  against, so the peer's version is taken as newer",
                        };
                    }
                    Decision::Apply {
                        why: "a later change to an entry this directory holds",
                    }
                }
            }
        }
    }
}

/// Whether two nodes could be confused for one another.
///
/// Sharing an id does not degrade replication - it destroys the order irreversibly: every later
/// change from either node looks like it might be the same change, and the history cannot be
/// untangled afterwards. Hence a check at startup and at the first exchange, not a warning.
pub fn same_server(left: &Csn, right: &Csn) -> bool {
    left.server == right.server
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csn(text: &str) -> Csn {
        Csn::parse(text).expect("a parseable csn")
    }

    fn incoming(csn: &str, kind: ChangeKind) -> Incoming {
        Incoming {
            csn: Some(csn.to_string()),
            kind,
            uuid: Some("11111111-1111-1111-1111-111111111111".to_string()),
        }
    }

    #[test]
    fn a_csn_carries_the_server_that_wrote_it() {
        // Without the server id two nodes' changes at the same timestamp are indistinguishable,
        // and the third field is decoration.
        let parsed = csn("20261104005712.352052Z#000012#003#000000");
        assert_eq!(parsed.timestamp, "20261104005712.352052Z");
        assert_eq!(parsed.counter, 12);
        assert_eq!(parsed.server, 3);
        assert_eq!(parsed.modifier, 0);
    }

    #[test]
    fn a_csn_that_cannot_be_ordered_is_refused_rather_than_guessed() {
        for text in [
            "",
            "20261104005712.352052Z",
            "20261104005712.352052Z#000012",
            "20261104005712.352052Z#000012#003",
            // A fifth field is a format this server does not know.
            "20261104005712.352052Z#000012#003#000000#extra",
            // Text that is not a timestamp.
            "yesterday#000012#003#000000",
            // A field that is not a number.
            "20261104005712.352052Z#twelve#003#000000",
            "20261104005712.352052Z#-12#003#000000",
            "20261104005712.352052Z# 12#003#000000",
        ] {
            assert!(Csn::parse(text).is_none(), "{text:?} must not parse");
        }
    }

    #[test]
    fn order_is_time_then_counter_then_server() {
        let first = csn("20261104005712.352052Z#000001#003#000000");
        let same_moment_later = csn("20261104005712.352052Z#000002#003#000000");
        let later = csn("20261104005713.000000Z#000001#003#000000");

        assert!(same_moment_later.is_newer_than(&first));
        assert!(later.is_newer_than(&same_moment_later));
        assert!(
            !first.is_newer_than(&first),
            "the same change is not newer than itself"
        );
    }

    #[test]
    fn two_servers_disagreeing_within_the_same_microsecond_still_order() {
        // Not a tie-break to be proud of - it is arbitrary - but an arbitrary order that every
        // node computes the same way is what makes the nodes converge.
        let low = csn("20261104005712.352052Z#000001#002#000000");
        let high = csn("20261104005712.352052Z#000001#003#000000");
        assert!(high.is_newer_than(&low));
        assert!(!low.is_newer_than(&high));
    }

    #[test]
    fn a_server_id_out_of_range_is_refused() {
        assert_eq!(ServerId::new(0), Err(ServerIdError(0)));
        assert_eq!(ServerId::new(1000), Err(ServerIdError(1000)));
        assert_eq!(ServerId::new(1).map(ServerId::value), Ok(1));
        assert_eq!(ServerId::new(MAX_SERVER_ID).map(ServerId::value), Ok(999));
    }

    #[test]
    fn a_new_entry_is_written_and_a_deletion_for_one_that_never_was_is_not() {
        let absent = Local::Absent;
        assert!(matches!(
            merge(
                &absent,
                &incoming("20261104005712.352052Z#000001#003#000000", ChangeKind::Add)
            ),
            Decision::Apply { .. }
        ));
        assert!(matches!(
            merge(
                &absent,
                &incoming(
                    "20261104005712.352052Z#000001#003#000000",
                    ChangeKind::Delete
                )
            ),
            Decision::Ignore { .. }
        ));
    }

    #[test]
    fn a_stale_change_is_dropped_and_a_newer_one_applied() {
        let local = Local::Present {
            csn: Some("20261104005712.352052Z#000002#003#000000".to_string()),
            uuid: Some("11111111-1111-1111-1111-111111111111".to_string()),
        };

        assert!(matches!(
            merge(
                &local,
                &incoming(
                    "20261104005712.352052Z#000001#003#000000",
                    ChangeKind::Modify
                )
            ),
            Decision::Ignore { .. }
        ));
        assert!(matches!(
            merge(
                &local,
                &incoming(
                    "20261104005713.000000Z#000001#003#000000",
                    ChangeKind::Modify
                )
            ),
            Decision::Apply { .. }
        ));
    }

    #[test]
    fn the_same_change_arriving_twice_is_applied_once() {
        // Equal timestamps are the ordinary case in replication: a peer reports a change this
        // node already has. Applying it again would rewrite the entry on every poll.
        let text = "20261104005712.352052Z#000002#003#000000";
        let local = Local::Present {
            csn: Some(text.to_string()),
            uuid: Some("11111111-1111-1111-1111-111111111111".to_string()),
        };

        assert!(matches!(
            merge(&local, &incoming(text, ChangeKind::Modify)),
            Decision::Ignore { .. }
        ));
    }

    #[test]
    fn a_deletion_newer_than_the_entry_removes_it() {
        let local = Local::Present {
            csn: Some("20261104005712.352052Z#000002#003#000000".to_string()),
            uuid: None,
        };
        assert!(matches!(
            merge(
                &local,
                &incoming(
                    "20261104005713.000000Z#000001#003#000000",
                    ChangeKind::Delete
                )
            ),
            Decision::Apply { .. }
        ));
    }

    #[test]
    fn the_reason_for_accepting_a_deletion_names_which_case_it_was() {
        // Both cases write, and the difference is only in what the operator is told. A log that
        // says "this entry had no change sequence number" about an entry that had one is a log
        // that sends somebody looking for corruption that is not there.
        let staged = Local::Present {
            csn: Some("20261104005712.352052Z#000002#003#000000".to_string()),
            uuid: None,
        };
        match merge(
            &staged,
            &incoming(
                "20261104005720.000000Z#000001#003#000000",
                ChangeKind::Delete,
            ),
        ) {
            Decision::Apply { why } => assert!(
                why.contains("later deletion"),
                "an entry with a stamp is deleted as a later deletion, not as an unstamped one: {why}"
            ),
            other => panic!("expected a write, got {other:?}"),
        }

        let unstamped = Local::Present {
            csn: None,
            uuid: None,
        };
        match merge(
            &unstamped,
            &incoming(
                "20261104005720.000000Z#000001#003#000000",
                ChangeKind::Delete,
            ),
        ) {
            Decision::Apply { why } => assert!(
                why.contains("no change sequence number"),
                "an entry without a stamp says so: {why}"
            ),
            other => panic!("expected a write, got {other:?}"),
        }
    }

    #[test]
    fn a_deletion_older_than_the_entry_leaves_it_alone() {
        // The half of replication that is easy to get backwards: an entry modified after the
        // deletion elsewhere must survive, or the later edit is lost and the record disappears.
        let local = Local::Present {
            csn: Some("20261104005730.000000Z#000002#003#000000".to_string()),
            uuid: None,
        };
        assert!(matches!(
            merge(
                &local,
                &incoming(
                    "20261104005713.000000Z#000001#003#000000",
                    ChangeKind::Delete
                )
            ),
            Decision::Ignore { .. }
        ));
    }

    #[test]
    fn a_change_newer_than_the_deletion_brings_the_entry_back() {
        // Tombstones decide this. Without one the entry would simply reappear - or, worse, never
        // come back at all - and neither is a rule, both are accidents of implementation order.
        let local = Local::Tombstone {
            csn: "20261104005712.352052Z#000002#003#000000".to_string(),
        };

        assert!(matches!(
            merge(
                &local,
                &incoming("20261104005720.000000Z#000001#003#000000", ChangeKind::Add)
            ),
            Decision::Apply { .. }
        ));
        assert!(matches!(
            merge(
                &local,
                &incoming("20261104005710.000000Z#000001#003#000000", ChangeKind::Add)
            ),
            Decision::Ignore { .. }
        ));
    }

    #[test]
    fn two_nodes_that_created_one_dn_independently_are_a_conflict_not_a_race() {
        // The newer timestamp is not the right answer here: the two entries are different records
        // that happen to share a name, and picking one silently discards the other.
        let local = Local::Present {
            csn: Some("20261104005712.352052Z#000002#003#000000".to_string()),
            uuid: Some("22222222-2222-2222-2222-222222222222".to_string()),
        };

        match merge(
            &local,
            &incoming("20261104005720.000000Z#000001#003#000000", ChangeKind::Add),
        ) {
            Decision::Conflict { why } => assert!(why.contains("independently")),
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn a_deletion_is_never_a_conflict_of_identity() {
        // The UUID check exists to catch two records colliding on a name; a deletion carries no
        // record to compare, and refusing it would leave a dead entry on one node for ever.
        let local = Local::Present {
            csn: Some("20261104005712.352052Z#000002#003#000000".to_string()),
            uuid: Some("22222222-2222-2222-2222-222222222222".to_string()),
        };

        assert!(matches!(
            merge(
                &local,
                &incoming(
                    "20261104005720.000000Z#000001#003#000000",
                    ChangeKind::Delete
                )
            ),
            Decision::Apply { .. }
        ));
    }

    #[test]
    fn an_entry_without_a_csn_is_written_over_and_can_be_deleted() {
        // The naming context and the two units carry no `entryCSN`, and so does anything imported
        // before stamping existed. Refusing to touch them would mean they never change and never
        // die on a replica; the decision is named rather than hidden.
        let local = Local::Present {
            csn: None,
            uuid: None,
        };

        assert!(matches!(
            merge(
                &local,
                &incoming("20261104005712.352052Z#000001#003#000000", ChangeKind::Modify)
            ),
            Decision::Apply { why } if why.contains("no change sequence number")
        ));
        assert!(matches!(
            merge(
                &local,
                &incoming(
                    "20261104005712.352052Z#000001#003#000000",
                    ChangeKind::Delete
                )
            ),
            Decision::Apply { .. }
        ));
    }

    #[test]
    fn a_change_with_no_sequence_number_is_written_only_where_there_is_nothing_to_lose() {
        // The case a live two-node run found: the naming context and the two units are
        // synthesised, so they carry no `entryCSN`, and a peer sends them with none. Treating
        // "no number" as "an unreadable number" made every node start by recording three
        // conflicts that were not conflicts.
        let absent = Local::Absent;
        match merge(
            &absent,
            &Incoming {
                csn: None,
                kind: ChangeKind::Add,
                uuid: None,
            },
        ) {
            Decision::Apply { why } => assert!(why.contains("does not hold the entry at all")),
            other => panic!("a new entry is taken even without a number: {other:?}"),
        }

        let present = Local::Present {
            csn: None,
            uuid: None,
        };
        match merge(
            &present,
            &Incoming {
                csn: None,
                kind: ChangeKind::Modify,
                uuid: None,
            },
        ) {
            Decision::Ignore { why } => assert!(
                why.contains("no change sequence number"),
                "and it is not called a conflict: {why}"
            ),
            other => panic!("an unordered change must not be written over an entry: {other:?}"),
        }

        let tombstone = Local::Tombstone {
            csn: "20260101000000.000001Z#000001#002#000000".to_string(),
        };
        assert!(matches!(
            merge(
                &tombstone,
                &Incoming {
                    csn: None,
                    kind: ChangeKind::Add,
                    uuid: None,
                },
            ),
            Decision::Ignore { .. }
        ));
    }

    #[test]
    fn an_unorderable_incoming_change_stops_the_merge() {
        let local = Local::Present {
            csn: Some("20261104005712.352052Z#000002#003#000000".to_string()),
            uuid: None,
        };
        let mut unparseable = incoming("garbage", ChangeKind::Modify);
        unparseable.csn = Some("garbage".to_string());

        match merge(&local, &unparseable) {
            Decision::Conflict { why } => assert!(why.contains("cannot")),
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn an_unorderable_local_change_stops_the_merge_too() {
        // Symmetric on purpose: a local CSN from a format this server no longer understands is
        // exactly as unusable as a peer's, and treating only the remote one as untrustworthy
        // would let a local defect pass as a remote one.
        let local = Local::Present {
            csn: Some("garbage".to_string()),
            uuid: None,
        };
        assert!(matches!(
            merge(
                &local,
                &incoming(
                    "20261104005712.352052Z#000001#003#000000",
                    ChangeKind::Modify
                )
            ),
            Decision::Conflict { .. }
        ));
    }
    /// An attribute whose values carry the given stamps, in the same order.
    fn stamped(name: &str, values: &[(&str, &str)]) -> Attribute {
        let stamp_list: Vec<Arc<str>> = values.iter().map(|(_, csn)| Arc::from(*csn)).collect();
        Attribute {
            name: crate::model::attribute_name(name),
            values: values
                .iter()
                .map(|(value, _)| (*value).to_string())
                .collect::<Vec<String>>()
                .into_boxed_slice(),
            flags: crate::model::AttributeFlags::default(),
            value_csns: Some(stamp_list.into_boxed_slice()),
        }
    }

    /// Two nodes edit different values of one attribute at the same moment: both survive.
    ///
    /// This is the whole reason for level 2. Entry-level last-writer-wins settles a whole entry
    /// from one number and loses one of the two edits; with a change recorded beside each value,
    /// they are edits to different values.
    #[test]
    fn two_nodes_writing_different_values_both_survive() {
        let local = stamped(
            "memberUid",
            &[("alice", "20261104005712.000000Z#000001#001#000000")],
        );
        let incoming = stamped(
            "memberUid",
            &[("bob", "20261104005712.000000Z#000002#002#000000")],
        );

        let (merged, report) = merge_attribute(&local, &incoming);

        let values: Vec<&str> = merged.values.iter().map(String::as_str).collect();
        assert_eq!(values, vec!["alice", "bob"], "both edits are in the result");
        assert_eq!(report.added, 1);
        assert_eq!(report.updated, 0);
        assert_eq!(
            merged.csn_of("alice"),
            Some("20261104005712.000000Z#000001#001#000000"),
            "the stamp travels with the value it describes"
        );
        assert_eq!(
            merged.csn_of("bob"),
            Some("20261104005712.000000Z#000002#002#000000")
        );
    }

    /// The same value on both sides: the newer change takes the stamp with it.
    #[test]
    fn a_later_change_takes_the_stamp_of_a_value_both_sides_hold() {
        let local = stamped(
            "sn",
            &[("Smith", "20261104005712.000000Z#000001#001#000000")],
        );
        let incoming = stamped(
            "sn",
            &[("Smith", "20261105000000.000000Z#000001#002#000000")],
        );

        let (merged, report) = merge_attribute(&local, &incoming);

        assert_eq!(report.updated, 1, "the newer change took the stamp");
        assert_eq!(merged.values.len(), 1, "and did not duplicate the value");
        assert_eq!(
            merged.csn_of("Smith"),
            Some("20261105000000.000000Z#000001#002#000000")
        );
    }

    /// An older change cannot claim a value a newer one wrote.
    #[test]
    fn an_older_change_does_not_take_the_stamp_back() {
        let local = stamped(
            "sn",
            &[("Smith", "20261105000000.000000Z#000001#001#000000")],
        );
        let incoming = stamped(
            "sn",
            &[("Smith", "20261104005712.000000Z#000001#002#000000")],
        );

        let (merged, report) = merge_attribute(&local, &incoming);

        assert_eq!(report.updated, 0);
        assert_eq!(
            merged.csn_of("Smith"),
            Some("20261105000000.000000Z#000001#001#000000"),
            "the newer stamp stays with its value"
        );
    }

    /// A value nobody stamped belongs to no change, so a recorded change is later than it.
    ///
    /// The import case: an entry loaded from an LDIF has values but no history, and giving those
    /// priority would let a stale file beat a live directory.
    #[test]
    fn an_unstamped_value_loses_to_a_recorded_change() {
        let local = stamped("cn", &[("Ann", "")]);
        let incoming = stamped("cn", &[("Ann", "20261104005712.000000Z#000001#002#000000")]);

        let (merged, report) = merge_attribute(&local, &incoming);

        assert_eq!(report.updated, 1);
        assert_eq!(
            merged.csn_of("Ann"),
            Some("20261104005712.000000Z#000001#002#000000")
        );
    }

    /// Two nodes writing the same value in the same instant: the server id breaks the tie, and it
    /// breaks it the same way on both nodes.
    ///
    /// This is the property a replicated merge cannot do without. If the two nodes each kept their
    /// own stamp, every poll would carry a "newer" version to the other and the entry would be
    /// rewritten for ever; with the server id in the third field of the CSN, both arrive at the
    /// same answer without talking.
    #[test]
    fn a_tie_in_the_same_microsecond_is_broken_by_server_id_on_both_sides() {
        let here = stamped("cn", &[("Ann", "20261104005712.000000Z#000001#001#000000")]);
        let there = stamped("cn", &[("Ann", "20261104005712.000000Z#000001#002#000000")]);

        let (from_here, at_here) = merge_attribute(&here, &there);
        let (from_there, at_there) = merge_attribute(&there, &here);

        assert_eq!(at_here.updated, 1, "the higher server id wins at this node");
        assert_eq!(at_there.kept, 1, "and the same change wins at the other");
        assert_eq!(
            from_here.csn_of("Ann"),
            from_there.csn_of("Ann"),
            "both nodes end with one value and one stamp, and they are the same stamp"
        );
        assert_eq!(
            from_here.csn_of("Ann"),
            Some("20261104005712.000000Z#000001#002#000000")
        );
    }

    /// An attribute the local version lacks is taken whole, stamps and all.
    #[test]
    fn an_attribute_the_local_version_lacks_is_taken_whole() {
        let local = stamped("memberUid", &[]);
        let incoming = stamped(
            "memberUid",
            &[("alice", "20261104005712.000000Z#000001#002#000000")],
        );

        let (merged, report) = merge_attribute(&local, &incoming);

        assert_eq!(report, Merged::default(), "nothing to merge against");
        assert_eq!(merged.values.len(), 1);
        assert_eq!(
            merged.csn_of("alice"),
            Some("20261104005712.000000Z#000001#002#000000")
        );
    }
    /// Two nodes each adding a member to one group: both members survive, and the group is not
    /// rewritten for ever afterwards.
    #[test]
    fn entries_merge_by_value_rather_than_by_version() {
        use crate::model::Attributes;

        let entry = |members: &[(&str, &str)]| {
            Entry::new(
                "cn=team,ou=groups,dc=example,dc=com",
                Attributes::new()
                    .push(crate::model::Attribute::new(
                        "objectClass",
                        vec!["top".to_string(), "posixGroup".to_string()],
                    ))
                    .push(stamped("memberUid", members)),
            )
        };

        let local = entry(&[("alice", "20261104005712.000000Z#000001#001#000000")]);
        let incoming = entry(&[("bob", "20261104005712.000000Z#000002#002#000000")]);

        let (merged, report) = merge_entries(&local, &incoming);

        let members = merged
            .attributes()
            .get("memberUid")
            .expect("the merged entry has the attribute");
        let values: Vec<&str> = members.values.iter().map(String::as_str).collect();
        assert_eq!(
            values,
            vec!["alice", "bob"],
            "each node's edit is a different value, so neither is lost"
        );
        assert!(report.changed(), "and there is something to write");
        assert_eq!(report.values_gained, 1);
    }

    /// A peer's operational attributes do not overwrite this node's: `entryCSN` is what the caller
    /// has already decided about, and a second opinion from the other copy would undo the decision.
    #[test]
    fn operational_attributes_of_the_peer_are_not_taken() {
        use crate::model::Attributes;

        let local = Entry::new(
            "cn=team,ou=groups,dc=example,dc=com",
            Attributes::new().push(stamped("cn", &[("team", "")])).push(
                crate::model::Attribute::single(
                    crate::operational::ATTR_ENTRY_CSN,
                    "20261105000000.000000Z#000001#001#000000",
                )
                .operational(),
            ),
        );
        let incoming = Entry::new(
            "cn=team,ou=groups,dc=example,dc=com",
            Attributes::new().push(stamped("cn", &[("team", "")])).push(
                crate::model::Attribute::single(
                    crate::operational::ATTR_ENTRY_CSN,
                    "20260101000000.000000Z#000001#002#000000",
                )
                .operational(),
            ),
        );

        let (merged, _) = merge_entries(&local, &incoming);

        assert_eq!(
            merged
                .attributes()
                .get(crate::operational::ATTR_ENTRY_CSN)
                .and_then(|attribute| attribute.values.first())
                .map(String::as_str),
            Some("20261105000000.000000Z#000001#001#000000"),
            "this node keeps its own record of the change"
        );
    }
}
