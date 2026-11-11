//! In-memory directory: entries, their DNs, lookup and scope traversal.
//!
//! The directory is immutable: a reload builds a new one and the server swaps the
//! reference, so a request never observes a half-updated tree and no lock has to
//! guard entry mutation.
//!
//! Entries live in one flat `Vec` in the canonical order (domain, the two
//! organizational units, users, groups) with a DN index on top. That order is what
//! the server returns, and it is also the dense numbering the index of E3 will use:
//! a subtree is then a contiguous range.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

use uuid::Uuid;

use crate::dn;
use crate::index::{Index, IndexConfig, IndexError, Query};
use crate::mapping::gorestldap;
use crate::model::{
    ATTR_ENTRY_UUID, ATTR_HAS_SUBORDINATES, ATTR_OBJECT_CLASS, Attribute, Attributes, Entry, Group,
    User,
};

/// Search scope, mirroring RFC 4511 values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Base,
    OneLevel,
    Subtree,
}

/// Where a full record comes from when a snapshot holds only skeletons.
///
/// The point of the skeleton is that a start does not read three million records to answer a
/// question about one. What it cannot do is answer with attributes it never read, so the entries
/// that do match are fetched here - one keyed read each, from the store that already holds them.
///
/// `Send + Sync` because a `Directory` is shared by every connection: a search runs on any of the
/// runtime's threads, and a source that could not cross threads would make the whole snapshot
/// single-threaded.
pub trait EntrySource: Send + Sync {
    /// The record with this DN, or `None` when the store does not hold it.
    fn get(&self, dn: &str) -> Option<Entry>;
}

/// Where the records come from, in the form `Directory` can hold and compare.
///
/// A trait object cannot derive `Debug`, `PartialEq` or `Eq`, and `Directory` derives all three
/// because tests compare whole snapshots. The wrapper answers what it honestly can: no useful
/// `Debug`, and equality by identity of the source object - two directories reading from the same
/// store are the same, two reading from different stores are not, and neither claim says anything
/// about the *contents*, which is what `Directory`'s own fields compare.
#[derive(Clone)]
struct SourceSlot(Arc<dyn EntrySource>);

impl std::fmt::Debug for SourceSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<entry source>")
    }
}

impl PartialEq for SourceSlot {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for SourceSlot {}

/// The record cache, in the form `Directory` can hold and compare.
///
/// The same wrapper as `SourceSlot` and for the same reason: `Directory` derives `PartialEq` because
/// tests compare whole snapshots, and a cache has no meaningful structural equality - two directories
/// differ by what they have cached at this instant, which says nothing about the directory. Equality
/// by identity answers the question the derivation is really asking: same cache object, or not.
#[derive(Clone)]
struct CacheSlot(Arc<crate::record_cache::RecordCache>);

impl std::fmt::Debug for CacheSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<record cache>")
    }
}

impl PartialEq for CacheSlot {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for CacheSlot {}

/// Directory contents loaded from a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    base_dn: String,
    users_ou_name: String,
    groups_ou_name: String,
    /// Domain entry, the two organizational units, users, groups, everything else.
    entries: Vec<Entry>,
    /// Canonical-order ranges, so `users()` and `groups()` are slices, not filters.
    users: Range<usize>,
    groups: Range<usize>,
    /// Where each DN's entry's **id** sits, not where the entry does.
    ///
    /// An id does not move when an entry is inserted before it, so this map survives a write
    /// untouched. Storing positions here is what made every insert rebuild the whole map - a string
    /// clone per entry, per write - and the add rate fell with the size of the directory (measured:
    /// 796 adds/s at a thousand entries, 294 at thirty-one thousand).
    by_dn: HashMap<String, u32>,
    /// The stable id of each entry, indexed by position.
    ///
    /// Two different numbers, and the difference is the point. A position moves whenever an entry
    /// is added or removed before it; an id does not, once issued. The search index refers to ids,
    /// because a posting list that shifted under every insert would either have to be rewritten
    /// whole or answer about the wrong entries - and 389 DS resolves the same problem the same
    /// way, with `id2entry` and entry ids that are never reused.
    ///
    /// Ids are handed out in the order the entries are assembled, so a directory built from a
    /// store has the same ids every start: the snapshot in the store refers to them.
    ids: Vec<u32>,
    /// Where an id sits now. Rebuilt whenever the vector moves, which is what keeps add and
    /// delete from invalidating the index.
    /// Where each id sits now, built on demand.
    ///
    /// `OnceLock` because the positions move on every insert and delete, and rebuilding eagerly is
    /// the cost this exists to remove. A write drops it; the next read that needs a position builds
    /// it once. A burst of writes therefore pays nothing at all, and a burst of reads pays once -
    /// which is the right way round for a server that is either importing or serving.
    by_id: std::sync::OnceLock<HashMap<u32, usize>>,
    /// The next id to hand out. Never goes back: a reused id would make an old posting, or a
    /// record in a peer's journal, point at a different entry.
    next_id: u32,
    /// How many entries this server serves: the naming context and everything under it.
    ///
    /// Maintained rather than counted, because it is asked for on paths that move whole change
    /// sets - every write and every reload reports it - and counting it is a pass over every entry
    /// with a suffix comparison on each. On three million entries that is millions of string
    /// comparisons per write, for a number that moved by one.
    ///
    /// Not `entries.len()`: `other` also holds entries from outside the naming context, which a
    /// store may carry (an import that was not checked) and which a search under the base does not
    /// return.
    in_scope: usize,
    /// Search indexes over the same id numbering. Empty unless `with_indexes` ran.
    index: Arc<Index>,
    /// Records already read back from the store, when that is where they come from.
    ///
    /// Only ever set together with `source`: a snapshot that holds its records complete has nothing
    /// to cache, because reading one is a slice of memory it already owns.
    cache: Option<CacheSlot>,
    /// Where full records come from, when this snapshot holds skeletons instead of records.
    ///
    /// `None` in the ordinary case: the directory read the store and holds what it read. `Some`
    /// only when the start took the skeleton path, and then every entry in `entries` carries its
    /// DN and its indexed attributes and nothing else.
    source: Option<SourceSlot>,
    /// Which snapshot of the directory this is.
    ///
    /// A paged search hands the client a cookie that says where the next page starts. An offset
    /// alone is not enough to continue safely: if the directory changed between pages, the same
    /// offset points at a different entry, and the client silently skips or repeats records.
    /// The cookie carries this number too, so a page that continues a snapshot which no longer
    /// exists is refused instead of answered wrongly.
    snapshot: u64,
    /// How far the change journal had got when this snapshot was built.
    ///
    /// A synchronised search hands it to the client in a cookie, and compares it with each
    /// entry's `entryCSN` to tell "changed since you last asked" from "unchanged". It rides here
    /// because the snapshot and the journal head have to describe the same moment: a head from a
    /// later write would claim the client has changes it has not been sent.
    csn: Option<String>,
    /// The oldest change the journal still remembers when this snapshot was built.
    ///
    /// Here for the same reason as the head, and it answers a different question: the head says
    /// how far the journal has got, the floor says how far back it still reaches. A client resuming
    /// from a cookie older than the floor has missed changes that were pruned, and nothing in the
    /// surviving records says so.
    floor: Option<String>,
}

impl Directory {
    /// Builds the directory from gorestldap-shaped users and groups.
    ///
    /// The domain entry and the two organizational units are synthesized here: they
    /// belong to the shape of this server, not to the backend data.
    pub fn new(
        base_dn: &str,
        users_ou_name: &str,
        groups_ou_name: &str,
        users: Vec<User>,
        groups: Vec<Group>,
    ) -> Self {
        let base_dn = dn::normalize(base_dn);
        let users_ou_name = users_ou_name.to_lowercase();
        let groups_ou_name = groups_ou_name.to_lowercase();

        let mut entries = vec![
            domain_entry(&base_dn),
            ou_entry(&users_ou_name, &base_dn),
            ou_entry(&groups_ou_name, &base_dn),
        ];

        let users_start = entries.len();
        entries.extend(
            users
                .iter()
                .map(|user| gorestldap::user_entry(user, &base_dn, &users_ou_name)),
        );
        let users_range = users_start..entries.len();

        let groups_start = entries.len();
        entries.extend(
            groups
                .iter()
                .map(|group| gorestldap::group_entry(group, &base_dn, &groups_ou_name)),
        );
        let groups_range = groups_start..entries.len();

        Self::assemble(
            base_dn,
            users_ou_name,
            groups_ou_name,
            entries,
            users_range,
            groups_range,
        )
    }

    /// Builds the directory from entries that are already shaped — the direct JSON
    /// adapter today, any other source later.
    ///
    /// Entries below the users or groups OU are placed in the canonical position;
    /// everything else keeps DN order after them.
    /// The same directory, marked as snapshot `snapshot`.
    #[must_use]
    pub fn at_snapshot(mut self, snapshot: u64) -> Self {
        self.snapshot = snapshot;
        self
    }

    /// The snapshot this directory is.
    /// Sets the snapshot number on a directory that is being patched in place.
    pub fn set_snapshot(&mut self, snapshot: u64) {
        self.snapshot = snapshot;
    }

    /// The same directory, knowing how far the change journal had got.
    pub fn with_csn(mut self, csn: Option<String>) -> Self {
        self.csn = csn;
        self
    }

    /// Records how far the change journal has got, on a directory being patched in place.
    pub fn set_csn(&mut self, csn: Option<String>) {
        self.csn = csn;
    }

    /// How far the change journal had got when this snapshot was built.
    pub fn csn(&self) -> Option<&str> {
        self.csn.as_deref()
    }

    /// The same directory, knowing how far back the journal still reaches.
    pub fn with_floor(mut self, floor: Option<String>) -> Self {
        self.floor = floor;
        self
    }

    /// Records how far back the journal still reaches, on a directory being patched in place.
    pub fn set_floor(&mut self, floor: Option<String>) {
        self.floor = floor;
    }

    /// The oldest change the journal still remembers.
    pub fn floor(&self) -> Option<&str> {
        self.floor.as_deref()
    }

    pub fn snapshot(&self) -> u64 {
        self.snapshot
    }

    pub fn from_entries(
        base_dn: &str,
        users_ou_name: &str,
        groups_ou_name: &str,
        extra: Vec<Entry>,
    ) -> Self {
        let base_dn = dn::normalize(base_dn);
        let users_ou_name = users_ou_name.to_lowercase();
        let groups_ou_name = groups_ou_name.to_lowercase();
        let users_ou_dn = format!("ou={users_ou_name},{base_dn}");
        let groups_ou_dn = format!("ou={groups_ou_name},{base_dn}");

        let mut entries = vec![
            domain_entry(&base_dn),
            ou_entry(&users_ou_name, &base_dn),
            ou_entry(&groups_ou_name, &base_dn),
        ];

        let (mut users, mut groups, mut other): (Vec<Entry>, Vec<Entry>, Vec<Entry>) =
            (Vec::new(), Vec::new(), Vec::new());
        for entry in extra {
            // The naming context and the two units are synthesised above when the store does
            // not carry them - which is every JSON backend and every directory grown over the
            // protocol. A store that *does* carry them (an import, a migration from OpenLDAP)
            // would otherwise hold each one twice: a search would return two entries with the
            // same DN, and an export would write both.
            if entry.dn() == base_dn || entry.dn() == users_ou_dn || entry.dn() == groups_ou_dn {
                continue;
            }

            if is_descendant(entry.dn(), &users_ou_dn) {
                users.push(entry);
            } else if is_descendant(entry.dn(), &groups_ou_dn) {
                groups.push(entry);
            } else {
                other.push(entry);
            }
        }
        users.sort_by(|left, right| left.dn().cmp(right.dn()));
        groups.sort_by(|left, right| left.dn().cmp(right.dn()));
        other.sort_by(|left, right| left.dn().cmp(right.dn()));

        let users_start = entries.len();
        entries.extend(users);
        let users_range = users_start..entries.len();

        let groups_start = entries.len();
        entries.extend(groups);
        let groups_range = groups_start..entries.len();

        entries.extend(other);

        Self::assemble(
            base_dn,
            users_ou_name,
            groups_ou_name,
            entries,
            users_range,
            groups_range,
        )
    }

    fn assemble(
        base_dn: String,
        users_ou_name: String,
        groups_ou_name: String,
        entries: Vec<Entry>,
        users: Range<usize>,
        groups: Range<usize>,
    ) -> Self {
        // Ids assigned in canonical order: the same entries assembled the same way get the same
        // ids, which is what lets a snapshot taken by one start be read by the next.
        let ids: Vec<u32> = (0..entries.len() as u32).collect();

        let mut by_dn = HashMap::with_capacity(entries.len());
        for (position, entry) in entries.iter().enumerate() {
            // Normalized, because `find` normalizes what it is given: a map keyed on the raw DN
            // answers only for entries that happen to be written in lower case, and a principal
            // `alice@EXAMPLE.COM` - or any entry an import wrote with capitals - is then in the
            // directory and unfindable.
            by_dn.insert(crate::dn::normalize(entry.dn()), ids[position]);
        }

        // Built once here rather than lazily: a directory assembled by a start is about to be read,
        // and paying for the map during the assemble is one pass over data that is already in cache.
        let by_id: HashMap<u32, usize> = ids
            .iter()
            .enumerate()
            .map(|(position, id)| (*id, position))
            .collect();
        let by_id = std::sync::OnceLock::from(by_id);
        let next_id = entries.len() as u32;
        let in_scope = entries
            .iter()
            .filter(|entry| in_scope(entry.dn(), &base_dn, Scope::Subtree))
            .count();

        Self {
            base_dn,
            users_ou_name,
            groups_ou_name,
            entries,
            users,
            groups,
            by_dn,
            ids,
            by_id,
            next_id,
            in_scope,
            // Zero until the source that built it says which snapshot this is: a directory
            // built by hand in a test has no history to be inconsistent with.
            snapshot: 0,
            csn: None,
            floor: None,
            index: Arc::new(Index::default()),
            cache: None,
            source: None,
        }
    }

    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }

    pub fn users_ou_name(&self) -> &str {
        &self.users_ou_name
    }

    pub fn groups_ou_name(&self) -> &str {
        &self.groups_ou_name
    }

    /// Users, in canonical order.
    pub fn users(&self) -> &[Entry] {
        &self.entries[self.users.clone()]
    }

    /// Groups, in canonical order.
    pub fn groups(&self) -> &[Entry] {
        &self.entries[self.groups.clone()]
    }

    pub fn ou_dn(&self, ou_name: &str) -> String {
        format!("ou={},{}", ou_name.to_lowercase(), self.base_dn)
    }

    pub fn user_dn(&self, cn: &str) -> String {
        format!(
            "cn={},{}",
            cn.to_lowercase(),
            self.ou_dn(&self.users_ou_name)
        )
    }

    pub fn group_dn(&self, cn: &str) -> String {
        format!(
            "cn={},{}",
            cn.to_lowercase(),
            self.ou_dn(&self.groups_ou_name)
        )
    }

    /// Replaces one entry in this directory, in place, and returns whether it was there.
    ///
    /// Nothing is copied, so the cost of a write stops depending on the size of the directory at
    /// all - which is the whole reason this exists. The caller is responsible for knowing that no
    /// reader holds this snapshot: a reader must never watch its view change, so the source makes
    /// the snapshot unique before calling this.
    pub fn replace_entry_in_place(
        &mut self,
        entry: Entry,
        config: &crate::index::IndexConfig,
    ) -> Result<bool, crate::index::IndexError> {
        let Some(id) = self.position(entry.dn()) else {
            return Ok(false);
        };

        let stable = self.ids[id];
        let old = std::mem::replace(&mut self.entries[id], entry.clone());

        // The index is already an `Arc`: when this snapshot is unique it is patched in place, and
        // when a reader copied it earlier the copy costs microseconds rather than the directory.
        let index = Arc::make_mut(&mut self.index);
        index.replace(stable, &old, &entry, config)?;

        // After the patch, not before: a failure above leaves the directory unchanged, and a cache
        // entry dropped for a write that did not happen only costs the next read.
        self.forget_cached(entry.dn());

        Ok(true)
    }

    /// Every entry, in canonical order.
    pub fn all(&self) -> &[Entry] {
        &self.entries
    }

    /// Builds the configured indexes over this snapshot.
    ///
    /// Kept separate from the constructors so every existing caller keeps working
    /// without a configuration, and so a test can compare an indexed directory with
    /// the same directory unindexed.
    pub fn with_indexes(mut self, config: &IndexConfig) -> Result<Self, IndexError> {
        self.index = Arc::new(Index::build_for(&self.entries, &self.ids, config)?);
        Ok(self)
    }

    /// Adds an entry without reloading the directory.
    ///
    /// The entry is placed where a full rebuild would have placed it - the users range keeps DN
    /// order, the groups range its own, anything else goes after both - and the index learns it
    /// under a fresh id. What moves is positions, not ids: every posting that pointed at an entry
    /// still points at it, so the index does not have to be rewritten for the entries the
    /// insertion shifted.
    ///
    /// Returns `false` when an entry with this DN is already present, which is the case a caller
    /// has to handle as a modify rather than an add.
    pub fn insert_entry_in_place(
        &mut self,
        entry: Entry,
        config: &IndexConfig,
    ) -> Result<bool, crate::index::IndexError> {
        let entry_dn = entry.dn().to_string();
        if self.by_dn.contains_key(&crate::dn::normalize(&entry_dn)) {
            return Ok(false);
        }

        let id = self.next_id;
        let position = self.place_of(&entry_dn);

        // Before the move, and by the entry's own DN: whether it is served does not depend on
        // where it lands.
        if in_scope(&entry_dn, &self.base_dn, Scope::Subtree) {
            self.in_scope += 1;
        }

        self.entries.insert(position, entry);
        self.ids.insert(position, id);
        self.next_id += 1;

        // The three ranges are one contiguous layout, so an insertion inside one of them moves
        // the end of every range that starts at or after it.
        // `<=` and not `<`: a range that is empty sits at a single position, and inserting at that
        // position is an insert *into* it. With `<`, the first user added to a directory that had
        // none landed outside the users range - so `all()` held it and `users()` did not.
        if position < self.users.start {
            self.users = (self.users.start + 1)..(self.users.end + 1);
            self.groups = (self.groups.start + 1)..(self.groups.end + 1);
        } else if position <= self.users.end {
            self.users = self.users.start..(self.users.end + 1);
            self.groups = (self.groups.start + 1)..(self.groups.end + 1);
        } else if position <= self.groups.end {
            self.groups = self.groups.start..(self.groups.end + 1);
        }

        // The DN map is not rebuilt any more - it holds ids, which this insertion did not move - so
        // the new entry is added to it here. Missing this is not a slow path but a wrong one: the
        // entry is in `entries` and `ids` and no lookup can find it, so an add whose parent was just
        // created fails with "the parent entry does not exist".
        self.by_dn
            .insert(crate::dn::normalize(self.entries[position].dn()), id);
        self.shift_positions(position);

        // The same copy-on-write as a replace: unique here means patched in place, shared means
        // the reader keeps the view it had.
        let index = Arc::make_mut(&mut self.index);
        index.add(id, &self.entries[position], config)?;

        // A record cached under this DN was read before the entry existed - or belongs to an entry
        // this one replaced. Either way it is not this entry.
        self.forget_cached(self.entries[position].dn());
        Ok(true)
    }

    /// Removes an entry without reloading the directory.
    ///
    /// Returns the entry that was removed, or `None` when there was none - and its postings go
    /// with it, under the id it kept until now.
    pub fn remove_entry_in_place(
        &mut self,
        entry_dn: &str,
        config: &IndexConfig,
    ) -> Result<Option<Entry>, crate::index::IndexError> {
        let Some(position) = self.position(entry_dn) else {
            return Ok(None);
        };

        let id = self.ids[position];
        let removed = self.entries.remove(position);
        self.ids.remove(position);

        // The DN map is not rebuilt any more, so the entry is taken out of it here: a stale key
        // would answer `find` with a position that now holds a different entry - a wrong answer,
        // worse than a miss.
        self.by_dn.remove(&crate::dn::normalize(removed.dn()));

        if in_scope(removed.dn(), &self.base_dn, Scope::Subtree) {
            self.in_scope -= 1;
        }

        if position < self.users.end {
            self.users = self.users.start..(self.users.end - 1);
            self.groups = (self.groups.start - 1)..(self.groups.end - 1);
        } else if position < self.groups.end {
            self.groups = self.groups.start..(self.groups.end - 1);
        }

        self.shift_positions(position);

        let index = Arc::make_mut(&mut self.index);
        index.remove(id, &removed, config)?;

        // The record is gone from the directory, so serving it from the cache would answer for an
        // entry a search no longer returns.
        self.forget_cached(removed.dn());
        Ok(Some(removed))
    }

    /// Where a new entry with this DN belongs in the canonical order.
    ///
    /// The same rule [`Self::from_entries`] applies when it sorts, expressed as a position: a
    /// users entry between the other users, a group between the other groups, anything else at
    /// the end. Two implementations of one rule is a risk, so the ranges this reads are the ones
    /// that rebuild produced.
    fn place_of(&self, entry_dn: &str) -> usize {
        let users_ou = self.ou_dn(&self.users_ou_name);
        let groups_ou = self.ou_dn(&self.groups_ou_name);

        if is_descendant(entry_dn, &users_ou) {
            return self.sorted_position(self.users.clone(), entry_dn);
        }
        if is_descendant(entry_dn, &groups_ou) {
            return self.sorted_position(self.groups.clone(), entry_dn);
        }

        self.entries.len()
    }

    /// The first position in `range` whose DN is greater, which is where an insert keeps order.
    ///
    /// A binary search, because the range is in ascending DN order by construction - `from_entries`
    /// sorts it and this function is the only thing that inserts into it. The linear scan that was
    /// here compared the new DN against every entry in the range on every add: measured, that is
    /// what made the add rate fall from 752 to 357 per second between one thousand and thirty-one
    /// thousand entries, and the whole import quadratic.
    fn sorted_position(&self, range: Range<usize>, entry_dn: &str) -> usize {
        let (mut low, mut high) = (range.start, range.end);
        while low < high {
            let middle = low + (high - low) / 2;
            if self.entries[middle].dn() > entry_dn {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        low
    }

    /// Rebuilds the two maps that translate, after the vector moved.
    ///
    /// Both are derived from the vector and the id list, so they are recomputed rather than
    /// patched: a map patched in one place and not another answers about the wrong entry, and the
    /// defect shows up as a search that returns something it should not.
    /// Repairs the position map after the vector moved at `from`.
    ///
    /// Only the entries at or after `from` changed position, so only they are touched. The DN map
    /// needs no repair at all: it holds ids, and an id does not move when an entry is inserted
    /// before it.
    ///
    /// This replaces two earlier shapes, both of which cost more than the write itself: rebuilding
    /// both maps per write (a string clone per entry - 796 adds/s fell to 294 by thirty-one
    /// thousand), and dropping the position map per write so that the very next parent check
    /// rebuilt it (782/s fell to 496 by a hundred thousand). An import in ascending order inserts
    /// at the end of its range, so the tail is a handful of entries.
    fn shift_positions(&mut self, from: usize) {
        if let Some(map) = self.by_id.get_mut() {
            for position in from..self.ids.len() {
                map.insert(self.ids[position], position);
            }
        }
    }

    /// Where the entries sit, by id.
    ///
    /// Built on first use after a structural change. `&self` and a `OnceLock`, because a read must
    /// be able to build it: making it a `&mut self` method would push the cost back onto the write
    /// path, which is where it came from.
    fn positions(&self) -> &HashMap<u32, usize> {
        self.by_id.get_or_init(|| {
            self.ids
                .iter()
                .enumerate()
                .map(|(position, id)| (*id, position))
                .collect()
        })
    }

    /// The stable id of an entry, which is what its postings point at.
    pub fn id_of(&self, entry_dn: &str) -> Option<u32> {
        self.position(entry_dn).map(|position| self.ids[position])
    }

    /// The entry an id names, if it is still here.
    pub fn entry_by_id(&self, id: u32) -> Option<&Entry> {
        self.positions()
            .get(&id)
            .map(|position| &self.entries[*position])
    }

    /// The ids in canonical order: the pairing between the index's ids and the entries.
    pub fn ids(&self) -> &[u32] {
        &self.ids
    }

    /// Adopts an index built somewhere else.
    ///
    /// The only caller is a start that found a stored snapshot and checked it against this data.
    /// It is a separate entry point rather than a parameter of [`Self::with_indexes`] because the
    /// two answer different questions: one builds, the other trusts - and trusting without the
    /// fingerprint check would be a missing search result nobody could explain.
    pub fn with_index(mut self, index: Index) -> Self {
        self.index = Arc::new(index);
        self
    }

    /// Adopts an index together with the numbering it was built under.
    ///
    /// The two travel together or not at all: postings are ids, and an index taken without its
    /// numbering answers about whichever entries happen to sit at those positions now. `None`
    /// when the numbering does not describe this directory - a different number of entries, so
    /// the pairing is unknown - and the caller rebuilds.
    pub fn with_numbered_index(
        mut self,
        index: Index,
        numbering: &std::collections::HashMap<String, u32>,
        next_id: u32,
    ) -> Option<Self> {
        let mut ids = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            // Every entry has to be in the numbering. One that is not came from somewhere the
            // snapshot never saw, and guessing an id would let its postings land on another
            // entry - the caller rebuilds instead.
            ids.push(*numbering.get(entry.dn())?);
        }

        let by_id: std::collections::HashMap<u32, usize> = ids
            .iter()
            .enumerate()
            .map(|(position, id)| (*id, position))
            .collect();
        if by_id.len() != ids.len() {
            // A repeated id is a numbering that lost an entry somewhere; nothing can be trusted
            // after it.
            return None;
        }

        self.ids = ids;
        // The DN map is rebuilt, not left as `assemble` wrote it: that one numbered the ids
        // `0..n`, which is a position and not an id, and the snapshot's numbering is neither. A map
        // that still says `host/host@REALM → 8` where 8 now belongs to another principal answers a
        // lookup for one entry with the record of another - a bind against the wrong account, not a
        // miss. The check above already walked the pairs, so this is the same pass kept.
        self.by_dn = self
            .entries
            .iter()
            .zip(self.ids.iter())
            .map(|(entry, id)| (crate::dn::normalize(entry.dn()), *id))
            .collect();
        self.next_id = next_id.max(self.ids.iter().copied().max().unwrap_or(0) + 1);
        // The check above needed positions; the field is filled lazily, so the map just built is
        // dropped rather than stored. One pass over the ids on the next read is cheaper than keeping
        // a structure that a write would invalidate anyway.
        let _ = by_id;
        self.by_id = std::sync::OnceLock::new();
        self.index = Arc::new(index);
        Some(self)
    }

    /// The numbering in force, as `(dn, id)` pairs, for a snapshot to carry.
    pub fn numbering(&self) -> Vec<(String, u32)> {
        self.entries
            .iter()
            .zip(self.ids.iter())
            .map(|(entry, id)| (entry.dn().to_string(), *id))
            .collect()
    }

    /// The next id this directory would issue.
    pub fn next_id(&self) -> u32 {
        self.next_id
    }

    /// The entries in canonical order, which is the order the index ids point at.
    pub fn entries_in_order(&self) -> &[Entry] {
        &self.entries
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Position of an entry in the canonical order, which is its id in the indexes.
    pub fn position(&self, entry_dn: &str) -> Option<usize> {
        // Through the id: the DN map is stable, the position is what moved.
        let id = *self.by_dn.get(&dn::normalize(entry_dn))?;
        self.positions().get(&id).copied()
    }

    /// Entries matching `base_object` and `scope` together with their ids.
    pub fn entries_with_ids(&self, base_object: &str, scope: Scope) -> Vec<(usize, &Entry)> {
        let base_object = dn::normalize(base_object);

        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| in_scope(entry.dn(), &base_object, scope))
            .collect()
    }

    /// The entries at the given positions, in ascending order.
    ///
    /// What a search uses when the index has narrowed the answer. The alternative - walking the
    /// whole directory and testing each entry against a bitmap - costs a full pass over every entry
    /// on every search, which is what a load test of a million entries measured: 39 ms for a
    /// lookup that matches one entry, because the index skipped the filter but not the walk.
    pub fn entries_at(&self, ids: &roaring::RoaringBitmap) -> Vec<(usize, &Entry)> {
        // A bitmap from the index names **ids**, and an id is not a position once an entry has
        // been added or removed before it. Indexing the vector with an id read the wrong entry -
        // or none - and the symptom was a search that did not find an entry a write had just
        // reported as stored. The translation is the whole reason `by_id` exists.
        ids.iter()
            .filter_map(|id| {
                let position = *self.positions().get(&id)?;
                Some((position, &self.entries[position]))
            })
            .collect()
    }

    /// The record for one DN, whatever this snapshot holds.
    ///
    /// `find` answers from what is in memory, which in a skeleton snapshot is an identity with no
    /// attributes - right for a filter that only needs to know *which* entry, wrong for everything
    /// that reads a value: a bind needs `userPassword`, an ACL rule needs the groups, an integrity
    /// check needs the unique attributes. Those paths ask here, and pay one keyed read when the
    /// snapshot is a skeleton and nothing when it is not.
    ///
    /// Returns `None` when neither the snapshot nor the store has the DN.
    pub fn record(&self, dn: &str) -> Option<std::borrow::Cow<'_, Entry>> {
        // The DN as `find` would resolve it, including the `uid=alice` for `cn=alice` spelling
        // gorestldap accepted: a client that binds that way must keep working, and resolving here
        // is what makes the two paths agree.
        let normalized = dn::normalize(dn);
        let resolved = if self.by_dn.contains_key(&normalized) {
            normalized
        } else {
            self.find(&normalized)?.dn().to_string()
        };
        let position = self.position(&resolved)?;

        let Some(source) = self.source.as_ref().map(|slot| &slot.0) else {
            // The ordinary case: the entry is here, complete. Reading it is a slice of memory the
            // directory already owns, so there is nothing to cache and nothing to borrow from.
            return self.entries.get(position).map(std::borrow::Cow::Borrowed);
        };

        // A skeleton: the identity is here, the attributes are a read away - read under the DN the
        // store knows, which is the one the skeleton carries: `dn::normalize` lower-cases the value,
        // and a principal `host/HOST@AD.EXAMPLE.COM` is then a name the store has never heard of.
        // Filed afterwards, because this is the path a bind takes on every request: one account,
        // read over and over.
        let stored = self.entries[position].dn().to_string();
        if let Some(cached) = self.cache.as_ref().and_then(|slot| slot.0.get(&stored)) {
            return Some(std::borrow::Cow::Owned((*cached).clone()));
        }

        let entry = source.get(&stored)?;
        if let Some(cache) = self.cache.as_ref() {
            cache.0.insert(&stored, entry.clone());
        }
        Some(std::borrow::Cow::Owned(entry))
    }

    /// The same entries, with the record itself where this snapshot holds only a skeleton.
    ///
    /// A skeleton is enough to decide *whether* an entry matches anything the index can narrow, and
    /// not enough to answer with it: the caller needs every attribute the client asked for. So the
    /// record is fetched here, and only for the entries that got this far.
    ///
    /// A record the store no longer holds is skipped rather than answered as a skeleton: an answer
    /// with half the attributes of an entry is worse than no answer, because nothing about it says
    /// it is incomplete.
    pub fn resolved_at(
        &self,
        ids: &roaring::RoaringBitmap,
    ) -> Vec<(usize, std::borrow::Cow<'_, Entry>)> {
        let Some(source) = self.source.as_ref().map(|slot| &slot.0) else {
            // The ordinary case, and it costs nothing: the snapshot holds the records, so they are
            // borrowed and not copied. A `Cow` here is what keeps the skeleton path from making
            // every other path pay for a clone it does not need.
            return self
                .entries_at(ids)
                .into_iter()
                .map(|(position, entry)| (position, std::borrow::Cow::Borrowed(entry)))
                .collect();
        };

        let mut resolved = Vec::with_capacity(ids.len() as usize);
        for id in ids {
            let Some(position) = self.positions().get(&id) else {
                continue;
            };
            let skeleton = &self.entries[*position];

            // Consulted, never filled: a search that reaches every entry would file three million
            // records and evict exactly the few a client reuses. The cache pays on repeat reads of
            // the same record, and a bulk answer has no repeats by construction.
            if let Some(entry) = self
                .cache
                .as_ref()
                .and_then(|slot| slot.0.get(skeleton.dn()))
            {
                resolved.push((*position, std::borrow::Cow::Owned((*entry).clone())));
                continue;
            }

            // Skipped rather than answered as a skeleton: half an entry is worse than none,
            // because nothing in the answer says it is incomplete.
            if let Some(entry) = source.get(skeleton.dn()) {
                resolved.push((*position, std::borrow::Cow::Owned(entry)));
            }
        }
        resolved
    }

    /// Whether this snapshot holds skeletons rather than records.
    pub fn is_skeleton(&self) -> bool {
        self.source.is_some()
    }

    /// Throws away the record bodies, keeping the identities.
    ///
    /// The snapshot becomes a skeleton: DN, id, canonical position, and the index - everything a
    /// search needs to decide *which* entries, and nothing it needs to answer *with*. Records are
    /// read from the store when an answer needs them, which is what `with_source` provides.
    ///
    /// This is what turns `limits.memory_bytes` from a warning into a mechanism. Until it existed,
    /// a server that grew its directory by `add` never entered the skeleton mode at all: the mode
    /// was reachable only from `from_skeletons`, on the start path. So a directory built through
    /// ordinary writes held every record for ever, and the ceiling could only say "does not fit".
    ///
    /// Returns how many bytes of attribute storage it released, as a number an operator can see.
    /// The heap does not necessarily go back to the operating system - allocators keep their arenas
    /// - so this is what was *freed*, not what RSS will drop by.
    pub fn release_records(&mut self) -> u64 {
        let mut released = 0u64;

        for entry in &mut self.entries {
            for attribute in entry.attributes().values() {
                released += attribute.name.len() as u64;
                for value in attribute.values.iter() {
                    released += value.len() as u64;
                }
            }
            *entry = Entry::new(entry.dn(), crate::model::Attributes::new());
        }

        released
    }

    /// The same directory, fetching full records from `source`.
    ///
    /// Takes the entries it already holds as skeletons: their DN and their indexed attributes are
    /// what the index needs, and everything else is a read away.
    #[must_use]
    pub fn with_source(mut self, source: Arc<dyn EntrySource>) -> Self {
        self.source = Some(SourceSlot(source));
        self
    }

    /// Attaches a record source to a directory that is already in use.
    ///
    /// `with_source` consumes the directory, which is right for a builder and wrong for a snapshot
    /// that has just released its records and now has to be told where they went.
    pub fn attach_source(&mut self, source: Arc<dyn EntrySource>) {
        self.source = Some(SourceSlot(source));
    }

    /// The same directory, keeping recently read records of up to `budget` bytes.
    ///
    /// Set beside the source and only meaningful with one: without it, every record is already in
    /// memory and there is nothing to keep.
    #[must_use]
    pub fn with_cache(mut self, cache: Arc<crate::record_cache::RecordCache>) -> Self {
        self.cache = Some(CacheSlot(cache));
        self
    }

    /// Attaches a record cache to a directory that is already in use.
    pub fn attach_cache(&mut self, cache: Arc<crate::record_cache::RecordCache>) {
        self.cache = Some(CacheSlot(cache));
    }

    /// The cache this snapshot reads through, when it has one.
    pub fn cache(&self) -> Option<&Arc<crate::record_cache::RecordCache>> {
        self.cache.as_ref().map(|slot| &slot.0)
    }

    /// Drops a cached record, so the next read sees what was just written.
    ///
    /// Called by every path that changes a record in place. Without it a bind after a password
    /// change would authenticate against the password the cache read before the change - the worst
    /// kind of staleness, because it is a security answer rather than a display.
    fn forget_cached(&self, dn: &str) {
        if let Some(cache) = self.cache.as_ref() {
            cache.0.forget(&crate::dn::normalize(dn));
        }
    }

    /// Builds a snapshot from skeletons and the numbering a stored index was built under.
    ///
    /// The entries are placed canonically, and then the ids are taken from `numbering` rather than
    /// issued fresh - a posting that says "entry 42" has to name the entry the previous run called
    /// 42, or the snapshot answers about other entries entirely.
    pub fn from_skeletons(
        base_dn: &str,
        users_ou_name: &str,
        groups_ou_name: &str,
        skeletons: Vec<(String, crate::model::Attributes)>,
        index: Index,
        numbering: &std::collections::HashMap<String, u32>,
        next_id: u32,
    ) -> Option<Self> {
        let entries: Vec<Entry> = skeletons
            .into_iter()
            .map(|(dn, attributes)| Entry::new(dn, attributes))
            .collect();

        // The same placement a store read goes through, so a skeleton sits where a record would:
        // the two ranges that `users()` and `groups()` slice depend on it, and a search that walks
        // them must not see an empty half of the directory.
        Self::from_entries(base_dn, users_ou_name, groups_ou_name, entries)
            .with_numbered_index(index, numbering, next_id)
    }

    /// Ids of the entries under `base_object` for this scope, as a bitmap.
    ///
    /// Ids rather than positions, so this can be intersected with what the index answered: the
    /// index speaks ids, and two bitmaps in different numberings intersect into nonsense. A
    /// bitmap also knows numbers, not subtrees, so a search that walks candidates still has to
    /// check the scope of each one - building the set here keeps that rule in one place.
    pub fn scope_ids(&self, base_object: &str, scope: Scope) -> roaring::RoaringBitmap {
        let base_object = dn::normalize(base_object);

        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| in_scope(entry.dn(), &base_object, scope))
            // Ids, not positions: a caller intersects this with what the index answered, and a
            // bitmap of positions intersected with a bitmap of ids silently keeps the wrong
            // entries.
            .map(|(position, _)| self.ids[position])
            .collect()
    }

    /// Candidate ids for a query, or `None` when the index cannot help.
    pub fn candidates(&self, query: &Query) -> Option<roaring::RoaringBitmap> {
        self.index.candidates(query)
    }

    /// How many entries this server serves, without counting them.
    ///
    /// The naming context and everything under it. What a write and a reload report, and what the
    /// metrics show; see the field for why it is kept rather than computed.
    pub fn entry_count(&self) -> usize {
        self.in_scope
    }

    /// Entries matching `base_object` and `scope`, in canonical order.
    pub fn entries(&self, base_object: &str, scope: Scope) -> Vec<&Entry> {
        let base_object = dn::normalize(base_object);

        self.entries
            .iter()
            .filter(|entry| in_scope(entry.dn(), &base_object, scope))
            .collect()
    }

    /// Finds the entry addressed by `entry`.
    ///
    /// A DN is looked up directly. When that fails and the RDN names a user by `cn`
    /// or `uid`, the entry is looked up by that attribute inside the users OU:
    /// gorestldap accepted `uid=alice,ou=users,…` for an entry named
    /// `cn=alice,ou=users,…`, and clients rely on it.
    pub fn find(&self, entry: &str) -> Option<&Entry> {
        let entry = dn::normalize(entry);

        if let Some(id) = self.by_dn.get(&entry)
            && let Some(position) = self.positions().get(id)
        {
            return self.entries.get(*position);
        }

        let (attribute, value, suffix) = dn::split_first_rdn(&entry);
        if attribute != "cn" && attribute != "uid" {
            return None;
        }
        if suffix != self.ou_dn(&self.users_ou_name) {
            return None;
        }

        self.users().iter().find(|candidate| {
            candidate
                .attributes()
                .get(&attribute)
                .is_some_and(|attribute| {
                    attribute
                        .values
                        .iter()
                        .any(|candidate| candidate.to_lowercase() == value)
                })
        })
    }

    /// True when the entry `user_dn` is a member of the group with `cn`.
    ///
    /// Groups hold `memberUid`, which carries the user's `uid` (gorestldap
    /// semantics) or, in older data, the `cn`; both are accepted.
    pub fn is_member(&self, group_cn: &str, user_dn: &str) -> bool {
        let Some(user) = self.find(user_dn) else {
            return false;
        };
        let group_cn = group_cn.to_lowercase();
        let Some(group) = self
            .groups()
            .iter()
            .find(|group| dn::first_value(group.dn()).as_deref() == Some(group_cn.as_str()))
        else {
            return false;
        };
        let Some(members) = group.attributes().get("memberUid") else {
            return false;
        };

        let uid = first_value(user.attributes(), "uid")
            .unwrap_or_default()
            .to_lowercase();
        let cn = first_value(user.attributes(), "cn")
            .unwrap_or_default()
            .to_lowercase();

        members.values.iter().any(|member| {
            let member = member.to_lowercase();
            (!uid.is_empty() && member == uid) || (!cn.is_empty() && member == cn)
        })
    }

    /// Number of entries; used by logging and tests.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn first_value(attributes: &Attributes, name: &str) -> Option<String> {
    attributes
        .get(name)
        .and_then(|attribute| attribute.values.first().cloned())
}

fn domain_entry(base_dn: &str) -> Entry {
    let attributes = Attributes::new()
        .push(Attribute::new(
            ATTR_OBJECT_CLASS,
            vec!["top".to_string(), "domain".to_string()],
        ))
        .push(Attribute::single(ATTR_ENTRY_UUID, &entry_uuid(base_dn)).operational())
        .push(Attribute::single(ATTR_HAS_SUBORDINATES, "TRUE").operational());

    Entry::new(base_dn.to_string(), attributes)
}

fn ou_entry(ou_name: &str, base_dn: &str) -> Entry {
    let ou_dn = format!("ou={ou_name},{base_dn}");
    let attributes = Attributes::new()
        .push(Attribute::new(
            ATTR_OBJECT_CLASS,
            vec!["top".to_string(), "organizationalUnit".to_string()],
        ))
        .push(Attribute::single(ATTR_ENTRY_UUID, &entry_uuid(&ou_dn)).operational())
        .push(Attribute::single(ATTR_HAS_SUBORDINATES, "TRUE").operational());

    Entry::new(ou_dn, attributes)
}

/// Deterministic entry UUID: UUIDv5 in the OID namespace, as gorestldap does.
///
/// Public because content synchronisation has to name an entry that has never been written
/// through the protocol and therefore carries no `entryUUID` of its own. The value depends only on
/// the DN, so it is the same after a restart - which is what a replica needs from an identity.
pub fn entry_uuid(dn: &str) -> String {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, dn.as_bytes()).to_string()
}

/// Whether `entry_dn` is within `base_object` for this scope.
///
/// Public because a persistent search evaluates a change against the same rule a search used: one
/// implementation, so a pushed entry cannot be in the content when a fresh search would not have
/// returned it.
pub fn in_scope_for(entry_dn: &str, base_object: &str, scope: Scope) -> bool {
    in_scope(entry_dn, base_object, scope)
}

fn in_scope(entry_dn: &str, base_object: &str, scope: Scope) -> bool {
    match scope {
        Scope::Base => entry_dn == base_object,
        Scope::OneLevel => is_direct_child(entry_dn, base_object),
        Scope::Subtree => entry_dn == base_object || is_descendant(entry_dn, base_object),
    }
}

fn is_descendant(entry_dn: &str, base_object: &str) -> bool {
    entry_dn
        .strip_suffix(base_object)
        .and_then(|head| head.strip_suffix(','))
        .is_some()
}

fn is_direct_child(entry_dn: &str, base_object: &str) -> bool {
    match entry_dn
        .strip_suffix(base_object)
        .and_then(|head| head.strip_suffix(','))
    {
        Some(rdn) => !rdn.contains(','),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that counts reads, so "answered from the cache" is a measurable claim rather than
    /// an expectation about a field.
    struct CountingSource {
        records: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Entry>>>,
        reads: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl EntrySource for CountingSource {
        fn get(&self, dn: &str) -> Option<Entry> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let records = self
                .records
                .lock()
                .expect("the source lock is not poisoned");
            records.get(&dn::normalize(dn)).cloned()
        }
    }

    const BASE: &str = "dc=example,dc=com";
    const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
    const ALICE_DN: &str = "cn=alice cooper,ou=users,dc=example,dc=com";
    const GROUP_DN: &str = "cn=group_a,ou=groups,dc=example,dc=com";

    /// What the "store" holds, how many reads it answered, and a directory reading through it.
    ///
    /// The store is a real one in the sense that matters: when an entry changes, the store is
    /// updated too, so a cache that forgot to drop the old record answers with a value that no
    /// longer exists anywhere - which is exactly the failure the test is looking for.
    struct Stand {
        directory: Directory,
        reads: std::sync::Arc<std::sync::atomic::AtomicU64>,
        store: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Entry>>>,
    }

    impl Stand {
        fn new(budget: usize, entries: &[Entry]) -> Self {
            let mut records = std::collections::HashMap::new();
            for entry in entries {
                records.insert(dn::normalize(entry.dn()), entry.clone());
            }
            let store = std::sync::Arc::new(std::sync::Mutex::new(records));
            let reads = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

            let source = std::sync::Arc::new(CountingSource {
                records: std::sync::Arc::clone(&store),
                reads: std::sync::Arc::clone(&reads),
            });
            let directory = Directory::from_entries(BASE, "users", "groups", entries.to_vec())
                .with_source(source)
                .with_cache(std::sync::Arc::new(crate::record_cache::RecordCache::new(
                    budget,
                )));

            Self {
                directory,
                reads,
                store,
            }
        }

        /// Writes the entry to the store, as a commit would before the snapshot is patched.
        fn stored(&self, entry: &Entry) {
            self.store
                .lock()
                .expect("the store lock is not poisoned")
                .insert(dn::normalize(entry.dn()), entry.clone());
        }
    }

    fn account(dn: &str, password: &str) -> Entry {
        let attributes = crate::model::Attributes::new()
            .replace(crate::model::Attribute::single("cn", dn))
            .replace(crate::model::Attribute::single("userPassword", password));
        Entry::new(dn, attributes)
    }

    #[test]
    fn releasing_the_records_keeps_the_identities_and_returns_what_it_freed() {
        // What the ceiling does when a directory grown by `add` passes it: the bodies go, the
        // identities stay - a DN, an id, a position - and every record is read from the store when
        // an answer needs it. What must not happen is an entry losing its place: a search that
        // walks the users range must still find the account, even though its attributes are gone.
        let mut directory = Directory::from_entries(
            BASE,
            "users",
            "groups",
            vec![person("alice"), person("bob")],
        );

        let alice_id = directory
            .id_of(&format!("uid=alice,ou=users,{BASE}"))
            .expect("alice is here before the release");

        let released = directory.release_records();

        assert!(released > 0, "there were attributes to release");
        for entry in directory.all() {
            assert!(
                entry.attributes().values().is_empty(),
                "{} still holds attributes",
                entry.dn()
            );
        }
        // The identities are untouched: same DNs, same order, still findable, still in the range.
        // `all()` holds the naming context and the two organizational units as well, so the count
        // that matters here is the users range.
        assert_eq!(directory.users().len(), 2);
        assert!(
            directory
                .find(&format!("uid=alice,ou=users,{BASE}"))
                .is_some(),
            "alice cannot be found"
        );
        assert_eq!(
            directory
                .users()
                .iter()
                .map(|entry| crate::dn::first_value(entry.dn()).unwrap_or_default())
                .collect::<Vec<String>>(),
            vec!["alice".to_string(), "bob".to_string()],
            "the users range must keep both entries and their order"
        );
        // And the ids did not move, which is what the index postings mean. The number itself is a
        // position in canonical order and says nothing here; what matters is that releasing the
        // bodies did not change it - a moved id would point the index at another entry.
        assert_eq!(
            directory.id_of(&format!("uid=alice,ou=users,{BASE}")),
            Some(alice_id)
        );
    }

    #[test]
    fn inserting_out_of_order_keeps_the_canonical_order_the_search_relies_on() {
        // `sorted_position` binary-searches the range, which is only correct while the range is in
        // ascending DN order. Entries arrive in whatever order a client sends them, so the inserting
        // path is what has to keep the invariant - and if it stops, the binary search returns a
        // position that is not where the entry belongs, silently.
        let mut directory = Directory::new(BASE, "users", "groups", Vec::new(), Vec::new());
        let names = ["mira", "alice", "zoe", "bob", "yuri"];

        for name in names {
            let entry = Entry::new(
                format!("cn={name},ou=users,{BASE}"),
                crate::model::Attributes::new()
                    .replace(crate::model::Attribute::single("cn", name)),
            );
            assert!(
                directory
                    .insert_entry_in_place(entry, &crate::index::IndexConfig::default())
                    .expect("the insert is indexed"),
                "{name} was not inserted"
            );
        }

        let found: Vec<String> = directory
            .users()
            .iter()
            .map(|entry| crate::dn::first_value(entry.dn()).unwrap_or_default())
            .collect();
        assert_eq!(
            found,
            vec![
                "alice".to_string(),
                "bob".to_string(),
                "mira".to_string(),
                "yuri".to_string(),
                "zoe".to_string()
            ],
            "the users range must stay sorted whatever order they arrived in"
        );

        // And every one of them is findable, which is what the position map is for.
        for name in names {
            assert!(
                directory
                    .find(&format!("cn={name},ou=users,{BASE}"))
                    .is_some(),
                "{name} cannot be found after the insert"
            );
        }
    }

    #[test]
    fn a_record_read_twice_reaches_the_store_once() {
        let stand = Stand::new(1024 * 1024, &[account(ALICE_DN, "first")]);

        let first = stand
            .directory
            .record(ALICE_DN)
            .expect("the record is there");
        let second = stand
            .directory
            .record(ALICE_DN)
            .expect("the record is there");

        assert_eq!(
            first
                .attributes()
                .get("userPassword")
                .and_then(|attribute| attribute.values.first().map(String::as_str)),
            Some("first")
        );
        assert_eq!(second.dn(), first.dn());
        assert_eq!(
            stand.reads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the second read must come from the cache"
        );
    }

    #[test]
    fn a_cached_record_is_dropped_when_the_entry_changes() {
        // The failure this rules out is the worst kind: a bind answering with the password that was
        // current when the record was first read, while the store holds a different one.
        let changed = account(ALICE_DN, "after");
        let mut stand = Stand::new(1024 * 1024, &[account(ALICE_DN, "before")]);
        stand
            .directory
            .record(ALICE_DN)
            .expect("the record is there");

        stand.stored(&changed);
        let replaced = stand
            .directory
            .replace_entry_in_place(changed, &crate::index::IndexConfig::default())
            .expect("the replacement is indexed");
        assert!(
            replaced,
            "the entry existed, so the replacement must have happened"
        );

        let record = stand
            .directory
            .record(ALICE_DN)
            .expect("the record is there");
        assert_eq!(
            record
                .attributes()
                .get("userPassword")
                .and_then(|attribute| attribute.values.first().map(String::as_str)),
            Some("after"),
            "a stale password here would authenticate against the old one"
        );
        assert_eq!(stand.reads.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn a_search_answers_from_the_cache_but_does_not_fill_it() {
        // A bulk answer files nothing: three million records would evict every record a client
        // actually reuses, and the cache would cost memory without earning any.
        let stand = Stand::new(
            1024 * 1024,
            &[
                account(ALICE_DN, "p"),
                account("cn=bob,ou=users,dc=example,dc=com", "q"),
            ],
        );
        let cache = stand.directory.cache().expect("the cache is set");

        let ids = stand.directory.scope_ids(BASE, Scope::Subtree);
        let resolved = stand.directory.resolved_at(&ids);
        let first_search = stand.reads.load(std::sync::atomic::Ordering::SeqCst);

        // The scope also names the naming context and the two organizational units. This store
        // holds neither, so those candidates are asked for and skipped - an entry the store no
        // longer holds is never answered as a skeleton - which is why five were asked and two
        // answered.
        assert_eq!(
            resolved.len(),
            2,
            "the two accounts are the records the store holds"
        );
        assert_eq!(cache.len(), 0, "a search must not file what it read");
        assert_eq!(cache.statistics().1, ids.len(), "one miss per candidate");
        assert_eq!(first_search, ids.len(), "one keyed read per candidate");

        // The single-record path does file, and then a search is answered without the store.
        stand
            .directory
            .record(ALICE_DN)
            .expect("the record is there");
        assert_eq!(cache.len(), 1);

        let before = stand.reads.load(std::sync::atomic::Ordering::SeqCst);
        let _ = stand.directory.resolved_at(&ids);
        assert_eq!(
            stand.reads.load(std::sync::atomic::Ordering::SeqCst) - before,
            first_search - 1,
            "the cached record is not read from the store again"
        );
        assert_eq!(cache.len(), 1, "and the search still files nothing");
    }

    fn admin() -> User {
        User {
            ldap_admin: true,
            cn: "admin".to_string(),
            uid: Some("admin".to_string()),
            object_class: vec!["top".to_string()],
            ..User::default()
        }
    }

    fn alice() -> User {
        User {
            cn: "Alice Cooper".to_string(),
            uid: Some("alice".to_string()),
            object_class: vec!["top".to_string()],
            ..User::default()
        }
    }

    fn group(name: &str) -> Group {
        Group {
            cn: name.to_string(),
            member_uid: vec!["admin".to_string()],
            object_class: vec!["top".to_string()],
            ..Group::default()
        }
    }

    fn person(name: &str) -> Entry {
        Entry::new(
            format!("uid={name},ou=users,{BASE}"),
            Attributes::new()
                .push(Attribute::new("objectClass", vec!["top".to_string()]))
                .push(Attribute::single("uid", name))
                .push(Attribute::single("cn", name)),
        )
    }

    fn directory() -> Directory {
        Directory::new(
            BASE,
            "users",
            "groups",
            vec![admin(), alice()],
            vec![group("primary_group"), group("group_a")],
        )
    }

    fn dns(entries: &[&Entry]) -> Vec<String> {
        entries.iter().map(|entry| entry.dn().to_string()).collect()
    }

    #[test]
    fn candidates_narrow_but_scope_still_decides() {
        // The optimisation this guards: walking only the index's candidates is faster, and wrong if
        // the scope check is dropped - a bitmap knows positions, not subtrees, so a candidate can be
        // an entry outside the base. The speed itself is measured rather than asserted; the
        // correctness of the pairing is what a test can hold.
        let directory = Directory::from_entries(
            BASE,
            "users",
            "groups",
            vec![
                Entry::new(
                    "cn=in,ou=users,dc=example,dc=com",
                    Attributes::new().push(Attribute::single("cn", "in")),
                ),
                Entry::new(
                    "cn=out,ou=groups,dc=example,dc=com",
                    Attributes::new().push(Attribute::single("cn", "out")),
                ),
            ],
        );

        let everything: roaring::RoaringBitmap = (0..directory.len() as u32).collect();
        assert_eq!(
            directory.entries_at(&everything).len(),
            5,
            "a bitmap for every position walks every entry: base, two units, and the two added"
        );

        let scoped = directory.scope_ids("ou=users,dc=example,dc=com", Scope::Subtree);
        let inside: Vec<String> = directory
            .entries_at(&scoped)
            .into_iter()
            .map(|(_, entry)| entry.dn().to_string())
            .collect();

        assert_eq!(
            inside,
            vec![
                "ou=users,dc=example,dc=com".to_string(),
                "cn=in,ou=users,dc=example,dc=com".to_string()
            ],
            "the unit itself and what is under it, and nothing from the other unit"
        );
    }

    #[test]
    fn a_store_that_carries_the_base_and_the_units_does_not_get_them_twice() {
        // An imported or migrated store holds its own `dc=` and `ou=` entries. Synthesising
        // them on top would put two entries with the same DN in the directory: a search
        // returns both and an export writes both, which is how a round trip through
        // `--export-ldif` came to hold `dc=example,dc=com` twice.
        let base = "dc=example,dc=com";
        let users = "ou=users,dc=example,dc=com";
        let groups = "ou=groups,dc=example,dc=com";

        let stored = vec![
            Entry::new(
                base,
                Attributes::new()
                    .push(Attribute::single("objectClass", "top"))
                    .push(Attribute::single("objectClass", "domain"))
                    .push(Attribute::single("dc", "example")),
            ),
            Entry::new(
                users,
                Attributes::new()
                    .push(Attribute::single("objectClass", "organizationalUnit"))
                    .push(Attribute::single("ou", "users")),
            ),
        ];

        let directory = Directory::from_entries(base, "users", "groups", stored);

        let dns: Vec<&str> = directory.all().iter().map(|entry| entry.dn()).collect();
        assert_eq!(
            dns.iter().filter(|dn| **dn == base).count(),
            1,
            "the base appears once, whichever side supplied it: {dns:?}"
        );
        assert_eq!(
            dns.iter().filter(|dn| **dn == users).count(),
            1,
            "and so does the users unit: {dns:?}"
        );
        // The unit the store did not carry is still synthesised.
        assert!(dns.contains(&groups));
    }

    #[test]
    fn dns_follow_the_gorestldap_layout() {
        let directory = directory();

        assert_eq!(directory.base_dn(), BASE);
        assert_eq!(directory.user_dn("admin"), ADMIN_DN);
        assert_eq!(directory.user_dn("Alice Cooper"), ALICE_DN);
        assert_eq!(directory.group_dn("group_a"), GROUP_DN);
        assert_eq!(directory.ou_dn("users"), "ou=users,dc=example,dc=com");
    }

    #[test]
    fn entries_are_ordered_domain_ous_users_groups() {
        let directory = directory();
        let all: Vec<&Entry> = directory.all().iter().collect();

        assert_eq!(
            dns(&all),
            vec![
                "dc=example,dc=com",
                "ou=users,dc=example,dc=com",
                "ou=groups,dc=example,dc=com",
                ADMIN_DN,
                ALICE_DN,
                "cn=primary_group,ou=groups,dc=example,dc=com",
                GROUP_DN,
            ]
        );
        assert_eq!(directory.users().len(), 2);
        assert_eq!(directory.groups().len(), 2);
        assert_eq!(directory.len(), 7);
    }

    #[test]
    fn base_scope_returns_only_the_named_entry() {
        let directory = directory();

        let entries = directory.entries("CN=Admin, ou=USERS, dc=example, dc=com", Scope::Base);

        assert_eq!(dns(&entries), vec![ADMIN_DN]);
    }

    #[test]
    fn one_level_scope_of_the_root_returns_the_ous() {
        let directory = directory();

        assert_eq!(
            dns(&directory.entries(BASE, Scope::OneLevel)),
            vec!["ou=users,dc=example,dc=com", "ou=groups,dc=example,dc=com"]
        );
    }

    #[test]
    fn one_level_scope_of_users_ou_returns_users_only() {
        let directory = directory();

        assert_eq!(
            dns(&directory.entries("ou=users,dc=example,dc=com", Scope::OneLevel)),
            vec![ADMIN_DN, ALICE_DN]
        );
    }

    // The count is maintained, so the test that matters is the one that compares it with the
    // walk: a counter that drifts is worse than a walk, because nothing about the answer says it
    // is wrong.
    #[test]
    fn the_served_count_follows_inserts_and_deletes() {
        let mut directory = directory();
        let walked = |directory: &Directory| directory.entries(BASE, Scope::Subtree).len();
        assert_eq!(directory.entry_count(), walked(&directory));

        let config = IndexConfig::default();
        assert!(
            directory
                .insert_entry_in_place(person("bob"), &config)
                .expect("insert"),
            "a new DN is added"
        );
        assert_eq!(directory.entry_count(), walked(&directory));

        directory
            .remove_entry_in_place(&format!("uid=bob,ou=users,{BASE}"), &config)
            .expect("remove")
            .expect("there was one to remove");
        assert_eq!(directory.entry_count(), walked(&directory));
    }

    // A build has to make the same distinction as an insert: a directory assembled from a store
    // that carries an entry outside the naming context serves one fewer than it holds.
    #[test]
    fn a_build_counts_what_a_walk_would_return() {
        let outside = Entry::new(
            "ou=elsewhere,dc=other,dc=org",
            Attributes::new()
                .push(Attribute::new("objectClass", vec!["top".to_string()]))
                .push(Attribute::single("ou", "elsewhere")),
        );

        let directory = Directory::from_entries(BASE, "users", "groups", vec![outside]);

        assert_eq!(
            directory.entry_count(),
            directory.entries(BASE, Scope::Subtree).len(),
            "the count a build starts with is the one a walk would give"
        );
        assert_eq!(
            directory.entry_count(),
            3,
            "the naming context and its two organizational units"
        );
    }

    // The count is of what is served, and an entry outside the naming context is not served: a
    // store may carry one (an import nobody checked), and a walk under the base does not return it.
    #[test]
    fn an_entry_outside_the_naming_context_is_stored_but_not_counted() {
        let mut directory = directory();
        let before = directory.entry_count();

        let outside = Entry::new(
            "ou=elsewhere,dc=other,dc=org",
            Attributes::new()
                .push(Attribute::new("objectClass", vec!["top".to_string()]))
                .push(Attribute::single("ou", "elsewhere")),
        );
        assert!(
            directory
                .insert_entry_in_place(outside, &IndexConfig::default())
                .expect("insert"),
            "the entry is stored"
        );

        assert_eq!(
            directory.entry_count(),
            before,
            "and does not change what the server says it serves"
        );
        assert_eq!(
            directory.entry_count(),
            directory.entries(BASE, Scope::Subtree).len(),
            "which is what the walk says too"
        );
    }

    #[test]
    fn subtree_scope_of_the_root_returns_everything() {
        assert_eq!(directory().entries(BASE, Scope::Subtree).len(), 7);
    }

    #[test]
    fn subtree_scope_of_a_leaf_returns_the_leaf_itself() {
        let directory = directory();

        assert_eq!(
            dns(&directory.entries(ADMIN_DN, Scope::Subtree)),
            vec![ADMIN_DN]
        );
    }

    #[test]
    fn unknown_base_object_returns_nothing() {
        let directory = directory();

        assert!(
            directory
                .entries("ou=nothing,dc=example,dc=com", Scope::Subtree)
                .is_empty()
        );
    }

    #[test]
    fn find_resolves_every_entry_by_dn() {
        let directory = directory();

        for expected in [
            "dc=example,dc=com",
            "ou=groups,dc=example,dc=com",
            ADMIN_DN,
            ALICE_DN,
            GROUP_DN,
        ] {
            assert_eq!(
                directory.find(expected).map(|entry| entry.dn()),
                Some(expected),
                "expected to find {expected}"
            );
        }
    }

    #[test]
    fn an_entry_whose_dn_has_capitals_is_found() {
        // The realm's entries are named `krb5PrincipalName=krbtgt/EXAMPLE.COM@EXAMPLE.COM,...`, and
        // a DN map keyed on the raw string answered for lower-case DNs only: the entry sat in
        // `all()` and `find` returned nothing, which is how a KDC provisioned its `krbtgt` and then
        // could not read it back. Any imported entry with a capital - a `CN=Alice`, a realm - was in
        // the same state.
        let dn = "krb5PrincipalName=alice@EXAMPLE.COM,krb5RealmName=EXAMPLE.COM,dc=example,dc=com";
        let directory = Directory::from_entries(
            BASE,
            "users",
            "groups",
            vec![Entry::new(
                dn,
                Attributes::new().push(Attribute::single("objectClass", "krb5Principal")),
            )],
        );

        assert_eq!(
            directory.find(dn).map(|entry| entry.dn()),
            Some(dn),
            "an entry is found by the DN it was stored under"
        );
        // LDAP compares DNs case-insensitively, so the lower-case spelling has to answer too - and
        // answer with the entry as it was written, not with a lower-cased copy of it.
        assert_eq!(
            directory.find(&dn.to_lowercase()).map(|entry| entry.dn()),
            Some(dn)
        );
    }

    #[test]
    fn find_accepts_a_uid_rdn_for_an_entry_named_by_cn() {
        let directory = directory();

        let entry = directory
            .find("uid=alice,ou=users,dc=example,dc=com")
            .expect("user by uid");

        assert_eq!(entry.dn(), ALICE_DN);
    }

    #[test]
    fn find_is_case_insensitive_and_tolerates_spaces() {
        let directory = directory();

        assert!(
            directory
                .find("CN=ADMIN, OU=Users, DC=Example, DC=Com")
                .is_some()
        );
    }

    #[test]
    fn find_rejects_unknown_entries_and_wrong_suffix() {
        let directory = directory();

        assert!(
            directory
                .find("cn=nobody,ou=users,dc=example,dc=com")
                .is_none()
        );
        assert!(
            directory
                .find("cn=admin,ou=groups,dc=example,dc=com")
                .is_none()
        );
        assert!(directory.find("cn=admin,dc=example,dc=com").is_none());
        assert!(
            directory
                .find("uid=admin,ou=groups,dc=example,dc=com")
                .is_none()
        );
    }

    #[test]
    fn domain_ou_uuids_are_deterministic_and_distinct() {
        let uuids = |directory: &Directory| -> Vec<Option<String>> {
            directory
                .all()
                .iter()
                .take(3)
                .map(|entry| {
                    entry
                        .attributes()
                        .get(ATTR_ENTRY_UUID)
                        .map(|attribute| attribute.values.join(","))
                })
                .collect()
        };

        let first = uuids(&directory());
        let second = uuids(&directory());

        assert_eq!(first, second, "same data must give the same uuids");
        assert_ne!(first[0], first[1], "domain and users ou differ");
    }

    #[test]
    fn domain_entry_is_marked_with_subordinates() {
        let directory = directory();
        let domain = directory.find(BASE).expect("domain");

        assert_eq!(
            domain
                .attributes()
                .get(ATTR_HAS_SUBORDINATES)
                .map(|attribute| attribute.values.to_vec()),
            Some(vec!["TRUE".to_string()])
        );
    }

    #[test]
    fn empty_directory_still_exposes_domain_and_ous() {
        let directory = Directory::new(BASE, "users", "groups", vec![], vec![]);

        assert_eq!(directory.len(), 3);
        assert!(directory.users().is_empty());
    }

    #[test]
    fn membership_uses_uid_or_cn_from_member_uid() {
        let directory = directory();

        assert!(directory.is_member("group_a", ADMIN_DN));
        assert!(directory.is_member("GROUP_A", ADMIN_DN), "case insensitive");
        assert!(!directory.is_member("group_a", ALICE_DN));
        assert!(!directory.is_member("nosuchgroup", ADMIN_DN));
        assert!(
            !directory.is_member("group_a", "cn=nobody,ou=users,dc=example,dc=com"),
            "unknown member is never a member"
        );
    }

    #[test]
    fn membership_matches_member_uid_against_cn_too() {
        let directory = Directory::new(
            BASE,
            "users",
            "groups",
            vec![User {
                cn: "Alice Cooper".to_string(),
                object_class: vec!["top".to_string()],
                ..User::default()
            }],
            vec![Group {
                cn: "old_group".to_string(),
                member_uid: vec!["alice cooper".to_string()],
                object_class: vec!["top".to_string()],
                ..Group::default()
            }],
        );

        assert!(directory.is_member("old_group", ALICE_DN));
    }

    #[test]
    fn from_entries_places_entries_below_their_ou() {
        let directory = Directory::from_entries(
            BASE,
            "users",
            "groups",
            vec![
                Entry::new(
                    GROUP_DN,
                    Attributes::new().push(Attribute::single("cn", "group_a")),
                ),
                Entry::new(
                    ADMIN_DN,
                    Attributes::new().push(Attribute::single("cn", "admin")),
                ),
                Entry::new(
                    "cn=unrelated,ou=people,dc=example,dc=com",
                    Attributes::new().push(Attribute::single("cn", "unrelated")),
                ),
            ],
        );

        assert_eq!(directory.users().len(), 1);
        assert_eq!(directory.groups().len(), 1);
        assert_eq!(directory.len(), 6, "domain, two ous and three entries");
        assert_eq!(
            directory.users()[0].dn(),
            ADMIN_DN,
            "users keep their place in the canonical order"
        );
        assert!(
            directory
                .find("cn=unrelated,ou=people,dc=example,dc=com")
                .is_some()
        );
    }

    /// A store keyed by the DN exactly as written, as the redb backend is.
    ///
    /// Deliberately not `CountingSource`, which normalizes: the defect this covers is a DN map left
    /// on the wrong numbers, and a source that lower-cases its key hides half of it.
    struct ExactSource(std::collections::HashMap<String, Entry>);

    impl crate::directory::EntrySource for ExactSource {
        fn get(&self, dn: &str) -> Option<Entry> {
            self.0.get(dn).cloned()
        }
    }

    /// A restart answers a DN with that entry's record, not a neighbour's.
    ///
    /// The start path numbers entries from the snapshot, and those ids are not the positions
    /// `assemble` writes before the snapshot's numbers arrive. A DN map left on the old numbers
    /// points an id at a position that now holds another entry, and every read by DN - a bind, the
    /// KDC's own lookup - answers with somebody else's record. Measured on the AD-join stand: after
    /// a restart `kinit` said "Client not found" for every principal, and `krbtgt` resolved to
    /// `host/samba.ad.example.com`.
    #[test]
    fn a_restart_answers_a_dn_with_its_own_record() {
        // Capitals in the value, because that is what a realm's principals look like and what the
        // normalized key and the stored key disagree about.
        let dns = [
            "krb5PrincipalName=krbtgt/EXAMPLE.COM@EXAMPLE.COM,krb5RealmName=EXAMPLE.COM,dc=example,dc=com",
            "krb5PrincipalName=host/HOST@EXAMPLE.COM,krb5RealmName=EXAMPLE.COM,dc=example,dc=com",
            "krb5PrincipalName=ldap/HOST@EXAMPLE.COM,krb5RealmName=EXAMPLE.COM,dc=example,dc=com",
            ADMIN_DN,
        ];
        let skeletons: Vec<(String, crate::model::Attributes)> = dns
            .iter()
            .map(|dn| {
                (
                    dn.to_string(),
                    crate::model::Attributes::new()
                        .push(crate::model::Attribute::single("objectClass", "top")),
                )
            })
            .collect();
        // The containers come from `from_entries`, and the numbering has to cover every entry the
        // directory ends up holding - a snapshot that lost one is refused, and rightly.
        let all: Vec<String> = [
            BASE.to_string(),
            "ou=users,dc=example,dc=com".to_string(),
            "ou=groups,dc=example,dc=com".to_string(),
        ]
        .into_iter()
        .chain(dns.iter().map(|dn| dn.to_string()))
        .collect();
        // Numbers that are neither the positions nor in the same order, which is what a snapshot
        // carries after entries have been added and removed.
        let numbering: std::collections::HashMap<String, u32> = all
            .iter()
            .enumerate()
            .map(|(position, dn)| (dn.clone(), 1000 - position as u32))
            .collect();
        let store: std::collections::HashMap<String, Entry> = all
            .iter()
            .map(|dn| {
                (
                    dn.clone(),
                    Entry::new(dn.clone(), crate::model::Attributes::new()),
                )
            })
            .collect();

        let directory = Directory::from_skeletons(
            BASE,
            "users",
            "groups",
            skeletons,
            crate::index::Index::default(),
            &numbering,
            2000,
        )
        .expect("the numbering covers every entry")
        .with_source(std::sync::Arc::new(ExactSource(store)));

        for dn in dns {
            let record = directory.record(dn).expect("the store holds this DN");
            assert_eq!(record.dn(), dn, "the record under this DN is its own");
        }
    }
}
