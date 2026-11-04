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

use crate::backend::redb_store::ChangeKind;

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
    pub csn: String,
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

/// Decides what to do with `incoming`, given `local`.
///
/// Entry-level last-writer-wins, with the cases where a timestamp is the wrong tool spelled out.
pub fn merge(local: &Local, incoming: &Incoming) -> Decision {
    let incoming_csn = match Csn::parse(&incoming.csn) {
        Some(csn) => csn,
        None => {
            return Decision::Conflict {
                why: "the incoming change carries a change sequence number this server cannot \
                      order, so there is no honest way to place it in history",
            };
        }
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
            csn: csn.to_string(),
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
    fn an_unorderable_incoming_change_stops_the_merge() {
        let local = Local::Present {
            csn: Some("20261104005712.352052Z#000002#003#000000".to_string()),
            uuid: None,
        };
        match merge(&local, &incoming("garbage", ChangeKind::Modify)) {
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
}
