//! The domain's own identity: its SID, and the counter that issues RIDs inside it.
//!
//! Two facts, and both have to outlive a restart for reasons that are not cosmetic. A domain SID
//! that changed would leave every ACL naming the old one pointing at nothing, and every ticket
//! issued under it unverifiable. A counter that began again would hand out a RID somebody already
//! holds, and the new account would inherit the old one's rights without a word in the log.
//!
//! So both live in the store, in its `meta` table, written once and read on every start. The type
//! here is the only thing that touches those two keys: a second reader with its own spelling is a
//! second place the spelling can be wrong.
//!
//! # Why the value is not an entry in the directory
//!
//! AD keeps the domain SID in the `domainDNS` object and the allocator on
//! `CN=RID Manager$,CN=System`, and both are visible to a client. This stores them in the store's
//! own metadata instead, one step earlier than the directory proper: the SID is needed *before* the
//! first entry is written - the domain object itself has to carry one - and asking the directory for
//! a SID while building the directory is a cycle. When there is a domain object to hold it, it moves
//! there, and this becomes the cache that survives a start.

use crate::backend::{Backend, BackendError};
use crate::sid::{RidAllocator, Sid};

/// The key the domain SID is stored under.
const META_DOMAIN_SID: &str = "domain_sid";
/// The key the RID counter is stored under.
const META_NEXT_RID: &str = "domain_next_rid";

/// What went wrong establishing the domain's identity.
#[derive(Debug)]
pub enum Error {
    /// The backend has nowhere to keep it.
    NoStore(String),
    /// The store refused.
    Backend(BackendError),
    /// A stored value is not a SID, or the counter is not a number.
    Corrupt(String),
    /// The SID or the counter makes no sense - a counter inside the reserved range, a domain SID
    /// that is not `S-1-5-21-a-b-c`.
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoStore(backend) => write!(
                formatter,
                "the '{backend}' backend keeps no metadata, so a domain SID would not survive a \
                 restart; use the redb backend for a domain"
            ),
            Error::Backend(err) => write!(formatter, "{err}"),
            Error::Corrupt(detail) => write!(formatter, "stored domain identity: {detail}"),
            Error::Invalid(detail) => write!(formatter, "domain identity: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

/// The domain's identity, as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    sid: Sid,
    next_rid: u32,
}

impl Domain {
    /// Reads the domain, creating it from `entropy` if the store has never held one.
    ///
    /// `entropy` is sixteen octets from wherever the caller gets randomness; it is used **only** when
    /// there is no domain yet, so a restart cannot change an identity that already exists.
    pub fn ensure(backend: &Backend, entropy: [u8; 16]) -> Result<Domain, Error> {
        if !backend.keeps_meta() {
            return Err(Error::NoStore(backend.name().to_string()));
        }

        match Domain::load(backend)? {
            Some(domain) => Ok(domain),
            None => {
                let domain = Domain {
                    sid: Sid::domain_from_random(entropy),
                    next_rid: crate::sid::FIRST_UNRESERVED_RID,
                };
                domain.save(backend)?;
                Ok(domain)
            }
        }
    }

    /// What the store holds, or `None` if it holds nothing.
    ///
    /// Both keys have to be there or neither counts: a SID without a counter would mean a domain
    /// that has issued nothing, and a counter without a SID would be a number with no domain. Either
    /// half alone is a store somebody edited, and saying so is better than choosing one.
    pub fn load(backend: &Backend) -> Result<Option<Domain>, Error> {
        let sid = backend.meta_get(META_DOMAIN_SID).map_err(Error::Backend)?;
        let next = backend.meta_get(META_NEXT_RID).map_err(Error::Backend)?;

        let (sid, next) = match (sid, next) {
            (None, None) => return Ok(None),
            (Some(_), None) | (None, Some(_)) => {
                return Err(Error::Corrupt(
                    "one of the domain SID and the RID counter is present and the other is not; a \
                     domain needs both, and guessing the missing half would mint identities that \
                     exist nowhere"
                        .to_string(),
                ));
            }
            (Some(sid), Some(next)) => (sid, next),
        };

        let sid =
            Sid::from_bytes(&sid).map_err(|err| Error::Corrupt(format!("domain SID: {err}")))?;
        if next.len() != 4 {
            return Err(Error::Corrupt(format!(
                "the RID counter is {} octets, four were written",
                next.len()
            )));
        }
        let next = u32::from_le_bytes([next[0], next[1], next[2], next[3]]);

        // Through the allocator's own constructor, so a stored counter inside the reserved range is
        // refused here rather than handing out a built-in RID.
        RidAllocator::at(sid.clone(), next).map_err(Error::Invalid)?;

        Ok(Some(Domain {
            sid,
            next_rid: next,
        }))
    }

    /// Writes both halves.
    fn save(&self, backend: &Backend) -> Result<(), Error> {
        backend
            .meta_set(META_DOMAIN_SID, &self.sid.to_bytes())
            .map_err(Error::Backend)?;
        backend
            .meta_set(META_NEXT_RID, &self.next_rid.to_le_bytes())
            .map_err(Error::Backend)
    }

    /// The domain's SID.
    pub fn sid(&self) -> &Sid {
        &self.sid
    }

    /// An allocator standing where the store left off.
    pub fn allocator(&self) -> RidAllocator {
        RidAllocator::at(self.sid.clone(), self.next_rid)
            .expect("a stored counter was checked when it was read")
    }

    /// Takes a RID, and records the new position **before** returning the SID.
    ///
    /// In that order on purpose: a crash between the two leaves a number skipped, which nobody can
    /// tell from a number never used. The other order leaves a number issued and unrecorded, which
    /// the next start hands out again - to a different account, with the first account's rights.
    pub fn take(&mut self, backend: &Backend) -> Result<Sid, Error> {
        let mut allocator = self.allocator();
        let sid = allocator.take().map_err(Error::Invalid)?;
        self.next_rid = allocator.peek();
        self.save(backend)?;
        Ok(sid)
    }

    /// The SID of a built-in account or group, which is spoken for and takes no number.
    pub fn reserved(&self, rid: u32) -> Result<Sid, Error> {
        self.allocator().reserved(rid).map_err(Error::Invalid)
    }
}

/// The issuer a write path calls: the domain, behind a mutex, and the store that keeps it.
///
/// Behind a `Mutex` because issuing is a read-modify-write of one number: two concurrent adds that
/// both read the counter would both write the same next value, and the second account would get the
/// first one's SID. The lock is held for two store writes, which is the price of the one property
/// that matters here - a number handed out once.
#[derive(Debug)]
pub struct Issuer {
    backend: Backend,
    domain: std::sync::Mutex<Domain>,
}

impl Issuer {
    /// An issuer over `domain`, recording positions in `backend`.
    #[must_use]
    pub fn new(backend: Backend, domain: Domain) -> Self {
        Issuer {
            backend,
            domain: std::sync::Mutex::new(domain),
        }
    }

    /// Reads or creates the domain, and returns an issuer for it.
    pub fn open(backend: &Backend, entropy: [u8; 16]) -> Result<Self, Error> {
        let domain = Domain::ensure(backend, entropy)?;
        Ok(Issuer::new(backend.clone(), domain))
    }

    /// The domain's SID.
    pub fn sid(&self) -> Sid {
        self.lock().sid().clone()
    }

    /// The position the next RID will take.
    pub fn peek(&self) -> u32 {
        self.lock().allocator().peek()
    }

    /// Takes the next RID.
    ///
    /// A poisoned lock is recovered rather than propagated: the domain behind it is still a whole
    /// domain, and refusing every account creation for the rest of the process because one writer
    /// panicked is worse than the panic.
    pub fn take(&self) -> Result<Sid, Error> {
        let mut domain = self
            .domain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        domain.take(&self.backend)
    }

    /// The SID of a built-in account or group.
    pub fn reserved(&self, rid: u32) -> Result<Sid, Error> {
        self.lock().reserved(rid)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Domain> {
        self.domain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::backend::Backend;

    /// A redb store in a temporary directory, and the configuration that opens it.
    fn store(dir: &std::path::Path) -> Backend {
        let path = dir.join("directory.redb");
        let text = format!(
            "base_dn: dc=example,dc=com\n\
             backend: redb\n\
             backends:\n  redb:\n    path: {}\n\
             indexes:\n  default: [pres, eq, sub]\n",
            path.display()
        );
        let config = crate::config::resolve(crate::config::Args::default(), Some(&text), |_| None)
            .expect("config");
        Backend::from_config("redb", config.backends.get("redb")).expect("backend")
    }

    #[test]
    fn a_domain_is_created_once_and_comes_back_the_same() {
        // The property the whole module exists for. A domain SID that changed on restart would leave
        // every ACL naming the old one pointing at nothing.
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = store(dir.path());

        let first = Domain::ensure(&backend, [7u8; 16]).expect("created");
        let second = Domain::ensure(&backend, [9u8; 16]).expect("read back");

        assert_eq!(
            first.sid(),
            second.sid(),
            "a restart reads the domain it has, and the entropy it brings is not used"
        );
    }

    #[test]
    fn the_counter_continues_where_it_stopped_and_does_not_start_again() {
        // The mutation this holds against: a counter that resets on start. It would hand out a RID
        // somebody already holds, and the new account would inherit the old one's rights silently.
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = store(dir.path());

        let mut domain = Domain::ensure(&backend, [1u8; 16]).expect("created");
        let first = domain.take(&backend).expect("a SID");
        let second = domain.take(&backend).expect("a SID");
        assert_ne!(first, second);

        // A new process: the domain is read from the store, not created.
        let mut restarted = Domain::ensure(&backend, [2u8; 16]).expect("read");
        let third = restarted.take(&backend).expect("a SID");

        assert_eq!(
            third.rid(),
            Some(crate::sid::FIRST_UNRESERVED_RID + 2),
            "the third RID ever issued, not the first of a new counter"
        );
        assert_ne!(third, first);
        assert_ne!(third, second);
    }

    #[test]
    fn the_position_is_recorded_before_the_sid_is_handed_out() {
        // A crash between recording and returning skips a number, which nobody can tell from a
        // number never used. The other order would hand the same number out again after a restart.
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = store(dir.path());

        let mut domain = Domain::ensure(&backend, [3u8; 16]).expect("created");
        let sid = domain.take(&backend).expect("a SID");

        let stored = Domain::load(&backend).expect("read").expect("present");
        assert_eq!(
            stored.allocator().peek(),
            sid.rid().expect("a RID") + 1,
            "the store already knows the number was used"
        );
    }

    #[test]
    fn a_built_in_rid_takes_no_number_from_the_sequence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = store(dir.path());
        let domain = Domain::ensure(&backend, [4u8; 16]).expect("created");

        let admin = domain
            .reserved(crate::sid::reserved::ADMINISTRATOR)
            .expect("a SID");
        assert_eq!(admin.rid(), Some(500));

        let stored = Domain::load(&backend).expect("read").expect("present");
        assert_eq!(
            stored.allocator().peek(),
            crate::sid::FIRST_UNRESERVED_RID,
            "a reserved RID is spoken for before the domain exists"
        );
    }

    #[test]
    fn a_half_written_domain_is_refused_rather_than_completed() {
        // Something edited the store. Guessing the missing half would mint an identity that exists
        // nowhere, and it would look like a working domain until the first logon.
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = store(dir.path());
        Domain::ensure(&backend, [5u8; 16]).expect("created");
        backend
            .meta_set(META_NEXT_RID, &[])
            .expect("an edited store");

        match Domain::load(&backend) {
            Err(Error::Corrupt(detail)) => {
                assert!(detail.contains("counter"), "{detail}");
            }
            other => panic!("expected a corruption report, got {other:?}"),
        }
    }

    #[test]
    fn a_counter_inside_the_reserved_range_is_refused_on_read() {
        // The stored form bypasses `ensure`, so this is the only place the check can run. Handing
        // out 500 to an ordinary account would mint a domain administrator.
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = store(dir.path());
        let domain = Domain::ensure(&backend, [6u8; 16]).expect("created");
        backend
            .meta_set(META_DOMAIN_SID, &domain.sid().to_bytes())
            .expect("the SID");
        backend
            .meta_set(META_NEXT_RID, &500u32.to_le_bytes())
            .expect("an edited counter");

        match Domain::load(&backend) {
            Err(Error::Invalid(detail)) => assert!(detail.contains("reserved"), "{detail}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn two_writers_at_once_get_two_different_sids() {
        // The property the mutex is for. Two concurrent adds that both read the counter before
        // either wrote it would both record the same next value, and the two accounts would end up
        // with one SID - one account's rights, on somebody else's entry.
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = store(dir.path());
        let issuer = std::sync::Arc::new(Issuer::open(&backend, [11u8; 16]).expect("an issuer"));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let issuer = std::sync::Arc::clone(&issuer);
                std::thread::spawn(move || issuer.take().expect("a SID"))
            })
            .collect();

        let mut sids: Vec<Sid> = handles
            .into_iter()
            .map(|handle| handle.join().expect("no panic"))
            .collect();
        sids.sort();
        sids.dedup();
        assert_eq!(sids.len(), 8, "eight writers, eight distinct SIDs");

        // And the store agrees: the counter moved past everything handed out, so a restart cannot
        // hand one of them out again.
        let stored = Domain::load(&backend).expect("read").expect("present");
        assert_eq!(
            stored.allocator().peek(),
            crate::sid::FIRST_UNRESERVED_RID + 8
        );
    }

    #[test]
    fn a_backend_with_no_metadata_refuses_rather_than_pretending() {
        // The `file` backend holds a fixed user/group document. A domain SID there would live until
        // the next start, and every account would change identity.
        let dir = tempfile::tempdir().expect("tempdir");
        let users = dir.path().join("users.yaml");
        let groups = dir.path().join("groups.yaml");
        std::fs::write(&users, "{}\n").expect("written");
        std::fs::write(&groups, "{}\n").expect("written");
        let text = format!(
            "base_dn: dc=example,dc=com\nbackend: file\nbackends:\n  file:\n    \
             users_path: {}\n    groups_path: {}\n",
            users.display(),
            groups.display()
        );
        let config = crate::config::resolve(crate::config::Args::default(), Some(&text), |_| None)
            .expect("config");
        let backend = Backend::from_config("file", config.backends.get("file")).expect("backend");

        match Domain::ensure(&backend, [0u8; 16]) {
            Err(Error::NoStore(name)) => assert_eq!(name, "file"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
