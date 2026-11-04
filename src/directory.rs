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
    by_dn: HashMap<String, usize>,
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
    by_id: HashMap<u32, usize>,
    /// The next id to hand out. Never goes back: a reused id would make an old posting, or a
    /// record in a peer's journal, point at a different entry.
    next_id: u32,
    /// Search indexes over the same id numbering. Empty unless `with_indexes` ran.
    index: Arc<Index>,
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
        let mut by_dn = HashMap::with_capacity(entries.len());
        for (position, entry) in entries.iter().enumerate() {
            by_dn.insert(entry.dn().to_string(), position);
        }

        // Ids assigned in canonical order: the same entries assembled the same way get the same
        // ids, which is what lets a snapshot taken by one start be read by the next.
        let ids: Vec<u32> = (0..entries.len() as u32).collect();
        let by_id: HashMap<u32, usize> = ids
            .iter()
            .enumerate()
            .map(|(position, id)| (*id, position))
            .collect();
        let next_id = entries.len() as u32;

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
            // Zero until the source that built it says which snapshot this is: a directory
            // built by hand in a test has no history to be inconsistent with.
            snapshot: 0,
            csn: None,
            floor: None,
            index: Arc::new(Index::default()),
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
        if self.by_dn.contains_key(&entry_dn) {
            return Ok(false);
        }

        let id = self.next_id;
        let position = self.place_of(&entry_dn);

        self.entries.insert(position, entry);
        self.ids.insert(position, id);
        self.next_id += 1;

        // The three ranges are one contiguous layout, so an insertion inside one of them moves
        // the end of every range that starts at or after it.
        if position < self.users.start {
            self.users = (self.users.start + 1)..(self.users.end + 1);
            self.groups = (self.groups.start + 1)..(self.groups.end + 1);
        } else if position < self.users.end {
            self.users = self.users.start..(self.users.end + 1);
            self.groups = (self.groups.start + 1)..(self.groups.end + 1);
        } else if position < self.groups.end {
            self.groups = self.groups.start..(self.groups.end + 1);
        }

        self.reindex_positions();

        // The same copy-on-write as a replace: unique here means patched in place, shared means
        // the reader keeps the view it had.
        let index = Arc::make_mut(&mut self.index);
        index.add(id, &self.entries[position], config)?;
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

        if position < self.users.end {
            self.users = self.users.start..(self.users.end - 1);
            self.groups = (self.groups.start - 1)..(self.groups.end - 1);
        } else if position < self.groups.end {
            self.groups = self.groups.start..(self.groups.end - 1);
        }

        self.reindex_positions();

        let index = Arc::make_mut(&mut self.index);
        index.remove(id, &removed, config)?;
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
    fn sorted_position(&self, range: Range<usize>, entry_dn: &str) -> usize {
        range
            .clone()
            .find(|position| self.entries[*position].dn() > entry_dn)
            .unwrap_or(range.end)
    }

    /// Rebuilds the two maps that translate, after the vector moved.
    ///
    /// Both are derived from the vector and the id list, so they are recomputed rather than
    /// patched: a map patched in one place and not another answers about the wrong entry, and the
    /// defect shows up as a search that returns something it should not.
    fn reindex_positions(&mut self) {
        self.by_dn.clear();
        self.by_id.clear();
        for (position, (entry, id)) in self.entries.iter().zip(self.ids.iter()).enumerate() {
            self.by_dn.insert(entry.dn().to_string(), position);
            self.by_id.insert(*id, position);
        }
    }

    /// The stable id of an entry, which is what its postings point at.
    pub fn id_of(&self, entry_dn: &str) -> Option<u32> {
        self.position(entry_dn).map(|position| self.ids[position])
    }

    /// The entry an id names, if it is still here.
    pub fn entry_by_id(&self, id: u32) -> Option<&Entry> {
        self.by_id.get(&id).map(|position| &self.entries[*position])
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

    /// The entries in canonical order, which is the order the index ids point at.
    pub fn entries_in_order(&self) -> &[Entry] {
        &self.entries
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Position of an entry in the canonical order, which is its id in the indexes.
    pub fn position(&self, entry_dn: &str) -> Option<usize> {
        self.by_dn.get(&dn::normalize(entry_dn)).copied()
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
        ids.iter()
            .filter_map(|id| {
                self.entries
                    .get(id as usize)
                    .map(|entry| (id as usize, entry))
            })
            .collect()
    }

    /// Positions of the entries under `base_object` for this scope, as a bitmap.
    ///
    /// The bitmap knows positions, not subtrees, so a search that walks candidates must still check
    /// the scope of each one. Building the bitmap here rather than letting a caller subtract the two
    /// keeps that rule in one place.
    pub fn scope_ids(&self, base_object: &str, scope: Scope) -> roaring::RoaringBitmap {
        let base_object = dn::normalize(base_object);

        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| in_scope(entry.dn(), &base_object, scope))
            .map(|(position, _)| position as u32)
            .collect()
    }

    /// Candidate ids for a query, or `None` when the index cannot help.
    pub fn candidates(&self, query: &Query) -> Option<roaring::RoaringBitmap> {
        self.index.candidates(query)
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

        if let Some(position) = self.by_dn.get(&entry) {
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

    const BASE: &str = "dc=example,dc=com";
    const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
    const ALICE_DN: &str = "cn=alice cooper,ou=users,dc=example,dc=com";
    const GROUP_DN: &str = "cn=group_a,ou=groups,dc=example,dc=com";

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
}
