//! Bounded cache of the records a skeleton snapshot does not hold.
//!
//! The point of a skeleton is that a start does not read three million records. The price is that
//! every path needing a *value* - a bind reading `userPassword`, an ACL rule reading the groups,
//! a filter on an attribute nothing indexes - reads that record back from the store. One keyed read
//! is cheap; the same keyed read on every bind of the same account is not, and a search that touches
//! every entry would read the store three million times per query.
//!
//! So the hot records are kept, and the number kept is bounded by bytes rather than by count: an
//! entry with a large `jpegPhoto` and an entry with a `uid` are not the same amount of memory, and a
//! count-based limit would answer "fits" for the first while filling the ceiling with a thousand of
//! them.
//!
//! Three rules, and each is a decision rather than an implementation detail:
//!
//! - **Least recently used goes first.** The working set of a directory server is skewed - a few
//!   accounts bind constantly, most never - so recency is the only signal that matches the load.
//! - **A record larger than the whole budget is not cached at all.** Keeping it would evict
//!   everything else to hold one entry, which is the worst trade available: the next request for
//!   anything is a miss.
//! - **A miss is not an error.** It reads the store and answers. Under the memory ceiling the server
//!   is allowed to be slower, never to refuse (`docs/plan.md`, D22).
//!
//! A search that needs every record knows it will touch almost none of them twice, so it reads
//! around the cache; filing three million entries would evict everything a client actually reuses,
//! and the cache would be a cost with no benefit. That decision lives in `Directory`, not here.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::model::Entry;

/// No node, for a list that is empty or an end that points nowhere.
const NONE: usize = usize::MAX;

/// What one cached record is charged against the budget.
///
/// An estimate, and named as one: the exact heap a record occupies depends on the allocator, and
/// measuring it would cost more than the accounting saves. What it must do is *order* records
/// correctly - a record with ten values must cost about ten times what a record with one does - and
/// that it does, because the counted parts are the strings, which are what actually takes the space.
fn cost_of(dn_key: &str, entry: &Entry) -> usize {
    // The key and the node: the same DN is stored twice, once as the map key and once in the
    // entry, and both are heap.
    let mut cost = std::mem::size_of::<Node>() + dn_key.len() + entry.dn().len();

    for attribute in entry.attributes().values() {
        cost += std::mem::size_of::<crate::model::Attribute>();
        for value in attribute.values.iter() {
            cost += value.len() + std::mem::size_of::<String>();
        }
        if let Some(csns) = attribute.value_csns.as_ref() {
            cost += csns.len() * std::mem::size_of::<String>();
        }
    }

    cost
}

struct Node {
    key: String,
    entry: Arc<Entry>,
    cost: usize,
    /// The record used more recently than this one, and the one used less recently.
    newer: usize,
    older: usize,
}

/// The list itself, behind one lock.
///
/// A `Mutex` and not something cleverer: every operation here is a hash lookup and four pointer
/// swaps, so the lock is held for nanoseconds and the alternative - sharding - would multiply the
/// bookkeeping to save contention that a directory's bind rate does not produce.
#[derive(Default)]
struct Inner {
    nodes: Vec<Node>,
    index: HashMap<String, usize>,
    free: Vec<usize>,
    /// Most recently used, and least recently used.
    newest: usize,
    oldest: usize,
    bytes: usize,
    /// What `bytes` may reach. Copied in so the trimming rule lives in one place.
    budget: usize,
}

impl Inner {
    /// Takes a node out of the recency list without freeing it or its budget.
    ///
    /// Separate from `release` on purpose: a hit has to move a node within the list, and a remove
    /// has to drop it. Folding the two together - which the first draft did - frees the slot of a
    /// record that is still in the index, and the next insert reuses that slot for another DN while
    /// the index still points at it. The symptom is not a missing record but the wrong one.
    fn detach(&mut self, slot: usize) {
        let (newer, older) = (self.nodes[slot].newer, self.nodes[slot].older);

        if newer == NONE {
            self.newest = older;
        } else {
            self.nodes[newer].older = older;
        }
        if older == NONE {
            self.oldest = newer;
        } else {
            self.nodes[older].newer = newer;
        }

        self.nodes[slot].newer = NONE;
        self.nodes[slot].older = NONE;
    }

    /// Puts a detached node at the front, where the next eviction will not reach it.
    fn promote(&mut self, slot: usize) {
        let old_newest = self.newest;
        self.nodes[slot].older = old_newest;
        self.nodes[slot].newer = NONE;
        if old_newest == NONE {
            self.oldest = slot;
        } else {
            self.nodes[old_newest].newer = slot;
        }
        self.newest = slot;
    }

    /// Drops a node entirely: out of the list, out of the index, and its budget returned.
    fn release(&mut self, slot: usize) {
        self.detach(slot);
        self.bytes -= self.nodes[slot].cost;
        let key = std::mem::take(&mut self.nodes[slot].key);
        self.index.remove(&key);
        self.free.push(slot);
    }

    /// Applies the budget, oldest first, until what is held fits.
    ///
    /// Returns how many records went, so the caller can count them: the counter lives outside the
    /// lock, and a second counter inside it would drift from this one.
    fn trim(&mut self) -> u64 {
        let mut evicted = 0;
        while self.bytes > self.budget && self.oldest != NONE {
            self.release(self.oldest);
            evicted += 1;
        }
        evicted
    }
}

/// What the `cache:` section says.
///
/// `deny_unknown_fields` for the reason every section in this project has it: a key that is
/// accepted and ignored is worse than a key that is refused, because nothing tells the operator
/// that the memory they set aside is not being used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    /// How many bytes of materialised records to keep. Zero disables the cache.
    ///
    /// Accepts the same sizes as `limits.memory_bytes` (`64M`, `1G`, plain bytes), because it is
    /// read by the same operator in the same file.
    ///
    /// The default is small on purpose. The cache is a bet on which records are read again, and a
    /// default that claims a gigabyte on a machine that has four would be the ceiling problem this
    /// whole line of work exists to stop.
    pub entries_max_bytes: crate::limits::Size,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            entries_max_bytes: crate::limits::Size(64 * 1024 * 1024),
        }
    }
}

impl CacheConfig {
    /// The budget to give `RecordCache::new`.
    pub fn budget(&self) -> usize {
        usize::try_from(self.entries_max_bytes.bytes()).unwrap_or(usize::MAX)
    }
}

/// The cache, shared by every connection.
pub struct RecordCache {
    budget: usize,
    inner: Mutex<Inner>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl std::fmt::Debug for RecordCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "<record cache {} bytes>", self.budget)
    }
}

impl RecordCache {
    /// A cache holding at most `budget` bytes of records.
    ///
    /// A budget of zero caches nothing, which is how a configuration says "do not spend memory on
    /// this" without a second key for it.
    pub fn new(budget: usize) -> Self {
        Self {
            budget,
            inner: Mutex::new(Inner {
                newest: NONE,
                oldest: NONE,
                budget,
                ..Inner::default()
            }),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// The record for `dn`, when it is here.
    ///
    /// A hit moves the record to the front: "least recently used" is measured by use, and a record
    /// that has just been read is the one most likely to be read again.
    pub fn get(&self, dn: &str) -> Option<Arc<Entry>> {
        let mut inner = self.lock();

        let Some(&slot) = inner.index.get(dn) else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        // Only a node that is not already the newest needs moving: promoting the newest one would
        // detach it and put it back, which is the same list written twice.
        if inner.newest != slot {
            inner.detach(slot);
            inner.promote(slot);
        }

        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(Arc::clone(&inner.nodes[slot].entry))
    }

    /// Files a record, evicting the least recently used ones until it fits.
    ///
    /// Silently does nothing when the record alone would exceed the budget: a cache that keeps one
    /// entry by evicting everything else answers every other request with a miss, and the budget
    /// said that record was too big for it.
    pub fn insert(&self, dn: &str, entry: Entry) {
        let cost = cost_of(dn, &entry);
        if self.budget == 0 || cost > self.budget {
            return;
        }

        let mut inner = self.lock();

        // The same DN again: the store was read a second time because the first answer was evicted
        // or invalidated. Replacing in place keeps the budget honest - two copies of one record
        // would be charged twice and evict a record that is actually in use.
        if let Some(&slot) = inner.index.get(dn) {
            let previous = inner.nodes[slot].cost;
            inner.detach(slot);
            inner.nodes[slot].cost = cost;
            inner.nodes[slot].entry = Arc::new(entry);
            inner.bytes = inner.bytes - previous + cost;
            inner.promote(slot);
            let evicted = inner.trim();
            self.evictions.fetch_add(evicted, Ordering::Relaxed);
            return;
        }

        while inner.bytes + cost > self.budget && inner.oldest != NONE {
            let victim = inner.oldest;
            inner.release(victim);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }

        let slot = match inner.free.pop() {
            Some(slot) => {
                inner.nodes[slot] = Node {
                    key: dn.to_string(),
                    entry: Arc::new(entry),
                    cost,
                    newer: NONE,
                    older: NONE,
                };
                slot
            }
            None => {
                inner.nodes.push(Node {
                    key: dn.to_string(),
                    entry: Arc::new(entry),
                    cost,
                    newer: NONE,
                    older: NONE,
                });
                inner.nodes.len() - 1
            }
        };

        inner.index.insert(dn.to_string(), slot);
        inner.bytes += cost;
        inner.promote(slot);
    }

    /// Drops a record that changed, so the next read sees the new version rather than the old.
    pub fn forget(&self, dn: &str) {
        let mut inner = self.lock();
        let Some(slot) = inner.index.get(dn).copied() else {
            return;
        };
        inner.release(slot);
    }

    /// How many bytes of records are held, as the budget counts them.
    pub fn bytes(&self) -> usize {
        self.lock().bytes
    }

    /// How many records are held.
    pub fn len(&self) -> usize {
        self.lock().index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many reads were answered without the store, and how many had to go to it.
    pub fn statistics(&self) -> (u64, u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.evictions.load(Ordering::Relaxed),
        )
    }

    /// The lock, and what to do when a previous holder panicked while holding it.
    ///
    /// Poisoning is not a reason to stop serving: the cache is an optimisation, and its worst
    /// inconsistent state costs a stale read that the store would have to answer anyway. The
    /// alternative - propagating a panic from a search thread into every later request - turns a
    /// bookkeeping slip into an outage.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Attributes;

    #[test]
    fn the_section_reads_a_size_and_defaults_to_sixty_four_mebibytes() {
        let absent: CacheConfig = serde_saphyr::from_str("{}").expect("an empty section is valid");
        assert_eq!(absent.budget(), 64 * 1024 * 1024);

        let written: CacheConfig =
            serde_saphyr::from_str("entries_max_bytes: 512M").expect("a size is accepted");
        assert_eq!(written.budget(), 512 * 1024 * 1024);

        let off: CacheConfig =
            serde_saphyr::from_str("entries_max_bytes: 0").expect("zero disables it");
        assert_eq!(off.budget(), 0);
    }

    #[test]
    fn a_misspelled_key_is_refused_rather_than_ignored() {
        let refused = serde_saphyr::from_str::<CacheConfig>("entries_max_byte: 512M");

        assert!(refused.is_err(), "an unused key must not pass silently");
    }

    /// An entry whose cost is predictable: one attribute, one value of a known length.
    fn entry(dn: &str) -> Entry {
        let attributes = Attributes::new().replace(crate::model::Attribute::single("cn", dn));
        Entry::new(dn, attributes)
    }

    fn cache_of(budget: usize) -> RecordCache {
        RecordCache::new(budget)
    }

    #[test]
    fn a_second_read_of_the_same_record_does_not_go_to_the_store() {
        let cache = cache_of(1_000_000);
        cache.insert("cn=a", entry("cn=a"));

        assert!(cache.get("cn=a").is_some());
        assert_eq!(cache.statistics(), (1, 0, 0));
    }

    #[test]
    fn a_record_that_was_never_filed_is_a_miss() {
        let cache = cache_of(1_000_000);

        assert!(cache.get("cn=absent").is_none());
        assert_eq!(cache.statistics(), (0, 1, 0));
    }

    #[test]
    fn the_record_used_longest_ago_is_the_one_that_goes() {
        // Three records, room for two: the first goes, and it goes because it was not touched.
        let one = entry("cn=one");
        let budget = cost_of("cn=one", &one) * 2 + 16;
        let cache = cache_of(budget);

        cache.insert("cn=one", entry("cn=one"));
        cache.insert("cn=two", entry("cn=two"));
        cache.insert("cn=three", entry("cn=three"));

        assert!(
            cache.get("cn=one").is_none(),
            "the oldest record must be the victim"
        );
        assert!(cache.get("cn=two").is_some());
        assert!(cache.get("cn=three").is_some());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn reading_a_record_spares_it_from_the_next_eviction() {
        // The same shape as above, except the first record is read before the third arrives. If
        // recency were not tracked, "cn=one" would still be the victim and this test would pass on
        // a cache that evicts by insertion order.
        let one = entry("cn=one");
        let budget = cost_of("cn=one", &one) * 2 + 16;
        let cache = cache_of(budget);

        cache.insert("cn=one", entry("cn=one"));
        cache.insert("cn=two", entry("cn=two"));
        assert!(cache.get("cn=one").is_some());

        cache.insert("cn=three", entry("cn=three"));

        assert!(
            cache.get("cn=one").is_some(),
            "a record just read must survive"
        );
        assert!(
            cache.get("cn=two").is_none(),
            "the untouched record is the victim"
        );
    }

    #[test]
    fn a_record_larger_than_the_whole_budget_is_not_kept() {
        let cache = cache_of(64);

        cache.insert(
            "cn=huge",
            entry("cn=huge-with-a-name-that-cannot-fit-in-sixty-four-bytes"),
        );

        assert_eq!(
            cache.len(),
            0,
            "keeping it would evict everything else for one record"
        );
        assert_eq!(cache.bytes(), 0);
    }

    #[test]
    fn the_budget_is_never_exceeded() {
        let one = entry("cn=x");
        let cache = cache_of(cost_of("cn=x", &one) * 4);

        for index in 0..100 {
            cache.insert(&format!("cn={index}"), entry(&format!("cn={index}")));
        }

        assert!(
            cache.bytes() <= cost_of("cn=x", &one) * 4,
            "held {} bytes",
            cache.bytes()
        );
        assert!(cache.len() <= 4);
    }

    #[test]
    fn filing_the_same_record_twice_does_not_charge_for_it_twice() {
        let one = entry("cn=again");
        let cache = cache_of(cost_of("cn=again", &one) * 2 + 8);

        cache.insert("cn=again", entry("cn=again"));
        let after_first = cache.bytes();
        cache.insert("cn=again", entry("cn=again"));

        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.bytes(),
            after_first,
            "the second filing replaces, it does not add"
        );
    }

    #[test]
    fn a_record_that_changed_can_be_forgotten_before_it_is_read_again() {
        let cache = cache_of(1_000_000);
        cache.insert("cn=stale", entry("cn=stale"));

        cache.forget("cn=stale");

        assert!(cache.get("cn=stale").is_none());
        assert_eq!(cache.bytes(), 0, "forgetting returns the budget it used");
    }

    #[test]
    fn forgetting_something_that_was_never_filed_changes_nothing() {
        let cache = cache_of(1_000_000);
        cache.insert("cn=kept", entry("cn=kept"));

        cache.forget("cn=absent");

        assert!(cache.get("cn=kept").is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_zero_budget_holds_nothing_and_is_not_an_error() {
        let cache = cache_of(0);

        cache.insert("cn=a", entry("cn=a"));

        assert!(cache.get("cn=a").is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn an_evicted_record_is_not_served_from_a_stale_slot() {
        // Eviction frees the slot and reuses it. A lookup that still pointed at the old slot would
        // answer a question about one DN with another DN's record - the one defect of this
        // structure that returns wrong data rather than a miss.
        let one = entry("cn=one");
        let cache = cache_of(cost_of("cn=one", &one) * 2 + 16);

        cache.insert("cn=one", entry("cn=one"));
        cache.insert("cn=two", entry("cn=two"));
        cache.insert("cn=three", entry("cn=three"));

        let record = cache.get("cn=three").expect("the newest record is here");
        assert_eq!(record.dn(), "cn=three");
        assert!(cache.get("cn=one").is_none());
    }
}
