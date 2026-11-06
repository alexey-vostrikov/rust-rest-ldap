//! Indexes: narrow a search to a candidate set before the filter runs.
//!
//! The invariant that makes this safe to have: **a candidate set is a superset of the
//! answer**. The filter is still evaluated on every candidate, so an index can only
//! make a search faster or leave it unchanged — it can never return an entry the scan
//! would not have returned. The expensive direction, missing entries, is what the
//! equivalence tests hunt for.
//!
//! Entry ids are positions in the canonical order of the directory, so a subtree is a
//! contiguous range of ids and every index is a bitmap over the same numbering.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Write};
use std::sync::Arc;

use roaring::RoaringBitmap;
use serde::Deserialize;
use thiserror::Error;

use crate::index_file::Tag;
use crate::model::{Attributes, Entry};

/// What an index can answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// `(attribute=*)`.
    Pres,
    /// `(attribute=value)`.
    Eq,
    /// `(attribute=*part*)` and its anchored forms.
    ///
    /// A trigram index: every value contributes the three-character windows of itself
    /// between word boundaries, and a pattern contributes the windows of its literal parts.
    /// A pattern whose parts are all shorter than three characters narrows nothing, because
    /// there is no window to look up.
    Sub,
    /// `(attribute>=value)` and `(attribute<=value)`.
    ///
    /// The values of the attribute kept in order, each with the entries that have it, so a
    /// bound is an ordered range rather than a scan.
    Ord,
}

impl Kind {
    pub fn name(&self) -> &'static str {
        match self {
            Kind::Pres => "pres",
            Kind::Eq => "eq",
            Kind::Sub => "sub",
            Kind::Ord => "ord",
        }
    }
}

/// A filter, reduced to the parts an index can use.
///
/// Deliberately not `rasn_ldap::Filter`: the index has no business knowing the
/// protocol, and tests for it stay readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    Presence(Arc<str>),
    Equality {
        attribute: Arc<str>,
        value: String,
    },
    /// A substring pattern, split into the parts the filter gave it.
    ///
    /// The parts are kept apart rather than joined: an initial fragment can only match at the
    /// start of a value and a final one only at the end, and the boundary is what makes the
    /// index selective. Joined into one string they would match anywhere, which is still a
    /// superset and therefore still correct - and much less useful.
    Substring {
        attribute: Arc<str>,
        initial: Option<String>,
        any: Vec<String>,
        final_part: Option<String>,
    },
    /// `(attribute>=value)` or `(attribute<=value)`.
    Range {
        attribute: Arc<str>,
        bound: RangeBound,
        value: String,
    },
    And(Vec<Query>),
    Or(Vec<Query>),
    /// Never narrows: the complement of an indexable part is usually everything.
    Not(Box<Query>),
    /// A filter the index cannot help with.
    Unindexed,
}

/// How a value is ordered by the `ord` index.
///
/// Numbers sort as numbers and everything else as folded text, because that is what the
/// filter's `>=` and `<=` compare: `10` is above `9` as a number and below it as text. An
/// index that ordered `10` and `9` as text would exclude `10` from `(n>=9)` - a false
/// negative, the one answer an index must never give.
///
/// The two kinds never mix inside one attribute's map: an attribute whose values are all
/// integers gets `Num`, one with no integers gets `Text`, and a mixed attribute is left
/// unordered so that queries over it fall back to the scan.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum OrderKey {
    Num(i64),
    Text(String),
}

/// Which side of a value a range query keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeBound {
    /// `(attribute>=value)`, the bound included.
    AtLeast,
    /// `(attribute<=value)`, the bound included.
    AtMost,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IndexError {
    #[error("unknown index kind '{0}', expected pres, eq, sub or ord")]
    UnknownKind(String),
}

/// `indexes:` section of the configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IndexConfig {
    /// Kinds applied to every attribute, including ones not listed below.
    pub default: Vec<String>,
    /// Per-attribute kinds, replacing the default for that attribute.
    pub attributes: BTreeMap<String, Vec<String>>,
    /// Bytes of recorded changes kept before the stored snapshot is rewritten.
    ///
    /// The snapshot exists so a restart does not rebuild the index, and the recorded changes exist
    /// so a restart does not rebuild it either - but only up to the point where replaying them
    /// costs more than the snapshot they save. Unset means a quarter of the snapshot, never less
    /// than a megabyte: below that a small directory would rewrite on every few writes, which is
    /// dearer than the changes removed.
    pub snapshot_delta_bytes: Option<u64>,
    /// How many changed entries may be recorded on top of a mapped snapshot before the index gives
    /// up on the overlay and materialises.
    ///
    /// The overlay is what keeps a write from costing a gigabyte (ub-log §109), but it is not
    /// unbounded: every query pays one comparison per record it holds, and a server written to
    /// forever would grow it forever. At this many records the index does what it used to do on the
    /// first write - pulls the postings into maps - and from then on pays nothing per query. So the
    /// cost is "a gigabyte once, after thousands of changes", not "a gigabyte per change" and not
    /// "an overlay that never stops growing".
    ///
    /// Eight thousand and not a round ten: it is about the point where an overlay of small entries
    /// is a few megabytes, and where the per-query comparison is still cheaper than reading the
    /// snapshot back.
    pub snapshot_overlay_max: Option<usize>,
}

impl IndexConfig {
    /// Resolves the configuration into a plan: attribute -> kinds.
    pub fn resolve(&self) -> Result<BTreeMap<String, BTreeSet<Kind>>, IndexError> {
        let mut default = BTreeSet::new();
        for name in &self.default {
            default.insert(parse_kind(name)?);
        }

        let mut plan: BTreeMap<String, BTreeSet<Kind>> = BTreeMap::new();
        for (attribute, kinds) in &self.attributes {
            let mut resolved = BTreeSet::new();
            for name in kinds {
                resolved.insert(parse_kind(name)?);
            }
            plan.insert(attribute.to_lowercase(), resolved);
        }

        // The default applies to attributes nobody configured. Callers ask about
        // concrete attributes, so the default is kept separately.
        plan.insert(DEFAULT_KEY.to_string(), default);
        Ok(plan)
    }
}

/// Pseudo-attribute that carries the default kinds inside the resolved plan.
const DEFAULT_KEY: &str = "";

fn parse_kind(name: &str) -> Result<Kind, IndexError> {
    match name.trim().to_ascii_lowercase().as_str() {
        "pres" => Ok(Kind::Pres),
        "eq" => Ok(Kind::Eq),
        "sub" => Ok(Kind::Sub),
        "ord" => Ok(Kind::Ord),
        other => Err(IndexError::UnknownKind(other.to_string())),
    }
}

/// How many changed entries a mapped index records before it materialises instead.
///
/// Eight thousand and not a round ten: that is about where an overlay of small entries is a few
/// megabytes, and where one comparison per record per query is still cheaper than reading the whole
/// snapshot back into maps.
pub const DEFAULT_OVERLAY_MAX: usize = 8192;

/// One entry whose postings were changed while the index was mapped.
///
/// `before` and `after` are whole attribute sets rather than deltas of values: an entry is small,
/// the number of changed entries is bounded by the snapshot threshold, and comparing a query
/// against a set is one pass over the attributes instead of a merge of two lists.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Overlay {
    id: u32,
    before: Option<crate::model::Attributes>,
    after: Option<crate::model::Attributes>,
}

/// Built indexes for one directory snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    presence: HashMap<Arc<str>, RoaringBitmap>,
    equality: HashMap<Arc<str>, HashMap<String, RoaringBitmap>>,
    /// Trigram per attribute, with the entries whose value contains it.
    substrings: HashMap<Arc<str>, HashMap<String, RoaringBitmap>>,
    /// Value per attribute, in order, with the entries that hold it.
    ordered: HashMap<Arc<str>, BTreeMap<OrderKey, RoaringBitmap>>,
    /// Attributes whose values are all integers, which is what makes a numeric range exact.
    ordered_numeric: BTreeSet<Arc<str>>,
    /// Attributes with at least one integer value; the rest are pure text.
    ordered_mixed: BTreeSet<Arc<str>>,
    /// Attributes whose values must be matched exactly rather than case-folded.
    case_sensitive: BTreeSet<Arc<str>>,
    default_kinds: BTreeSet<Kind>,
    /// Kinds actually built, per attribute, for logging and for `--check-index`.
    built: BTreeMap<Arc<str>, BTreeSet<Kind>>,
    /// Changes made since the file was mapped, applied on top of what it holds.
    ///
    /// The file is read-only, and the maps are empty by design while it is mapped, so a write has
    /// nowhere to go. Materialising the whole index to accept one change is what this replaces:
    /// on a million entries that cost 1.14 GB per modify (measured, ub-log §108), and on three
    /// million about three times that. A change is a record of what the entry looked like before
    /// and after, and the lookup path applies it to the file's answer - tens of bytes per write,
    /// and the memory grows with the number of *changes*, not with the size of the directory.
    ///
    /// Applying it costs one comparison per overlay record per query, which is why this is not a
    /// general-purpose store: it holds the changes since the snapshot, and the snapshot rewrite
    /// (threshold `indexes.snapshot_delta_bytes`) is what empties it.
    overlay: Vec<Overlay>,

    /// The most records the overlay may hold before the index materialises instead.
    overlay_max: usize,

    /// The postings as a file, when this index was not materialised at start.
    ///
    /// Answering through the file is the whole point of the mapped format: a lookup reads a few
    /// pages, and three million postings never enter memory. The maps above stay empty in that case
    /// until something has to *change* the index, at which point `materialize` fills them.
    mapped: Option<MappedSlot>,
}

/// The mapped file, in a form `Index` can hold and compare.
///
/// `IndexFile` owns a mapping, so it is neither `Clone` nor `PartialEq`; `Index` derives all four
/// of `Debug, Clone, PartialEq, Eq` because tests compare whole indexes. The wrapper answers by
/// identity: two indexes reading the same file are the same, and the comparison says nothing about
/// the postings - which is what the maps above are for.
#[derive(Clone)]
struct MappedSlot(Arc<crate::index_file::IndexFile>);

impl std::fmt::Debug for MappedSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "<mapped index {}>", self.0.len())
    }
}

impl PartialEq for MappedSlot {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for MappedSlot {}

/// What a stored snapshot holds besides the postings: the numbering that gives them meaning, and
/// the next id to issue.
///
/// `Snapshot` is the index, `Numbering` is the pairing between an entry's DN and the number its
/// postings use. They travel together - an index taken without its numbering answers about
/// whichever entries happen to sit at those ids now.
pub type Numbering = Vec<(String, u32)>;
pub type Snapshot = (Index, Numbering, u32);

/// The per-attribute plan, without the pseudo-attribute that carries the default.
fn plan_of(config: &IndexConfig) -> Result<BTreeMap<String, BTreeSet<Kind>>, IndexError> {
    let plan = config.resolve()?;
    Ok(plan
        .into_iter()
        .filter(|(attribute, _)| !attribute.is_empty())
        .collect())
}

/// One entry's contribution to a change, as the stored index needs to hear it.
///
/// Entry-shaped rather than posting-shaped on purpose. A posting-level delta would say "remove
/// id 41 from `cn`/`ann`"; an entry-level one says "this entry changed", and the index derives the
/// postings itself through the one function that already does that for a rebuild. Two
/// implementations of the same derivation is how a persisted index starts disagreeing with a
/// built one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexChange {
    /// A new entry, under the id the directory issued.
    Add { id: u32, entry: Entry },
    /// A changed entry: the postings of `before` go, those of `after` arrive, under one id.
    Replace {
        id: u32,
        before: Entry,
        after: Entry,
    },
    /// An entry that is gone, named so its postings can be taken away.
    Remove { id: u32, entry: Entry },
}

impl IndexChange {
    /// The id this change is about, whichever shape it has.
    pub fn id(&self) -> u32 {
        match self {
            IndexChange::Add { id, .. }
            | IndexChange::Replace { id, .. }
            | IndexChange::Remove { id, .. } => *id,
        }
    }
}

/// Marks a delta written by this format., so a foreign or older blob is refused rather than
/// misread as postings.
const MAGIC: &[u8; 4] = b"RRIX";

/// Bumped whenever the layout below changes. An older blob is not upgraded: the index is derived
/// data and rebuilding it is always correct, while guessing at a layout that changed is not.
const SNAPSHOT_VERSION: u32 = 1;

/// Marks a delta written by this format.
const DELTA_MAGIC: &[u8; 4] = b"RRDL";

/// The stored shape of an entry, borrowed from the journal so a delta has no format of its own.
type StoredShape = crate::backend::redb_store::StoredEntry;

impl Index {
    /// The answer for a query the file can settle, or `None` when it cannot.
    ///
    /// Three outcomes, and the difference between them is the whole correctness argument:
    ///
    /// - the attribute has the index kind and the key is in the file: those postings;
    /// - the attribute has the index kind and the key is **not**: an empty answer, because the file
    ///   holds every posting that exists - this is the case that makes a wrong answer possible if it
    ///   were confused with the third;
    /// - the attribute has no such index, or the query is a range: `None`, and the caller scans.
    fn candidates_from_file(&self, query: &Query) -> Option<RoaringBitmap> {
        let file = self.mapped.as_ref().map(|slot| &slot.0)?;

        match query {
            Query::Equality { attribute, value } => {
                if !self.has(attribute, Kind::Eq) {
                    return None;
                }
                // The file stores the value the way the index compares it - folded for an ordinary
                // attribute - so the lookup is made with the same folding, or it finds nothing.
                let folded = fold(value, self.case_sensitive.contains(attribute));
                Some(
                    file.lookup(Tag::Equality, attribute, &folded)
                        .unwrap_or_default(),
                )
            }
            Query::Presence(attribute) => {
                if !self.has(attribute, Kind::Pres) {
                    return None;
                }
                Some(
                    file.lookup(Tag::Presence, attribute, "")
                        .unwrap_or_default(),
                )
            }
            Query::Substring { .. } => None,
            _ => None,
        }
    }

    /// Whether the plan gave this attribute this kind of index.
    fn has(&self, attribute: &str, kind: Kind) -> bool {
        self.built
            .get(attribute)
            .is_some_and(|kinds| kinds.contains(&kind))
    }

    /// An index that answers from a file: its plan, and the mapping.
    ///
    /// The plan is what makes a lookup able to say "no such index" instead of "no such value" - the
    /// file records the plan's hash, so the plan this is built from is the one the file was written
    /// with, or the file would have been refused before reaching here.
    pub fn from_plan(config: &IndexConfig) -> Self {
        let mut index = Self::default();
        if let Ok(plan) = config.resolve() {
            for (attribute, kinds) in plan {
                if !kinds.is_empty() {
                    index.built.insert(Arc::from(attribute.as_str()), kinds);
                }
            }
        }
        // The default applies to attributes nobody configured, and the file holds their postings
        // under their own names. Recording it keeps a presence lookup working for an attribute the
        // configuration never named.
        if let Ok(plan) = plan_of(config)
            && let Some(kinds) = plan.get(DEFAULT_KEY)
        {
            index.default_kinds = kinds.clone();
        }
        // The cap travels with the plan, because it is a property of how this deployment is willing
        // to spend memory rather than of any one write.
        if let Some(cap) = config.snapshot_overlay_max {
            index.overlay_max = cap;
        }
        index
    }

    /// The same index, answering from the file instead of from maps.
    ///
    /// `built` travels with it: a lookup has to be able to tell "this attribute has no index" from
    /// "this value matches nothing", and only the plan knows the first. Everything else - the
    /// postings - stays in the file until a write needs them.
    #[must_use]
    pub fn with_mapped(mut self, file: Arc<crate::index_file::IndexFile>) -> Self {
        self.mapped = Some(MappedSlot(file));
        self
    }

    /// Whether the postings are in the file rather than in memory.
    pub fn is_mapped(&self) -> bool {
        self.mapped.is_some()
    }

    /// Pulls the postings out of the file into maps a write can patch.
    ///
    /// Called once, before the first change to an index that started mapped: a mapping cannot be
    /// edited, and the alternative - writing a new file per change - is the cost this format exists
    /// to avoid.
    pub fn materialize(&mut self) {
        let Some(slot) = self.mapped.take() else {
            return;
        };
        let file = slot.0;
        let records = file.materialize();
        let pulled = Self::from_records(records);
        self.presence = pulled.presence;
        self.equality = pulled.equality;
        self.substring_map(pulled.substrings);
        self.built = pulled.built;
        // `ordered` stays empty: a range lookup falls back to the scan, which is what the search
        // path already does for an attribute without an ordered index.

        // The changes recorded since the file was written are not in it, so they go back on top of
        // the maps it was just rebuilt from. Without this a rewrite would publish a snapshot that
        // forgets the writes that triggered it.
        self.reapply_overlay();
    }

    fn substring_map(&mut self, substrings: HashMap<Arc<str>, HashMap<String, RoaringBitmap>>) {
        self.substrings = substrings;
    }

    /// Everything the mapped file format needs, flattened.
    ///
    /// The four maps are handed over as they are - presence, equality, substring, and the ordered
    /// one is left out on purpose: a range lookup needs keys whose byte order is numeric order, and
    /// that encoding does not exist yet. A start that maps the file answers `=`, `=*` and substrings
    /// from it and falls back to a scan for `>=` and `<=`, which is a slower answer and never a wrong
    /// one.
    pub fn records(&self, numbering: Vec<(String, u32)>) -> crate::index_file::Records {
        // A mapped index holds its postings in a file and its changes in the overlay, so neither is
        // in the maps below. The rewrite has to write both, and this is the one place that pays to
        // find out what they are: a copy is materialised, which is a gigabyte on a million entries
        // - in the background, once per rewrite, instead of once per write.
        if self.mapped.is_some() {
            let mut copy = self.clone();
            copy.materialize();
            return copy.records(numbering);
        }

        let presence: Vec<(&str, RoaringBitmap)> = self
            .presence
            .iter()
            .map(|(attribute, bitmap)| (attribute.as_ref(), bitmap.clone()))
            .collect();

        let mut equality: Vec<(&str, &str, RoaringBitmap)> = Vec::new();
        for (attribute, values) in &self.equality {
            for (value, bitmap) in values {
                equality.push((attribute.as_ref(), value.as_str(), bitmap.clone()));
            }
        }

        let mut substrings: Vec<(&str, &str, RoaringBitmap)> = Vec::new();
        for (attribute, values) in &self.substrings {
            for (value, bitmap) in values {
                substrings.push((attribute.as_ref(), value.as_str(), bitmap.clone()));
            }
        }

        crate::index_file::Records::new(presence, equality, substrings, numbering)
    }

    /// The index built from what a mapped file holds.
    ///
    /// The inverse of [`Self::records`], used by the first write after a mapped start: the postings
    /// are unpacked into the structures a write can patch. Ordered ranges are not in the file, so a
    /// directory materialised this way is rebuilt rather than trusted for a range lookup - see
    /// [`Self::covers`].
    pub fn from_records(records: std::collections::BTreeMap<Vec<u8>, RoaringBitmap>) -> Self {
        let mut index = Self::default();

        for (key, bitmap) in records {
            let Some((&tag, rest)) = key.split_first() else {
                continue;
            };
            let Some(separator) = rest.iter().position(|byte| *byte == 0) else {
                continue;
            };
            let attribute = String::from_utf8_lossy(&rest[..separator]).to_string();
            let value = String::from_utf8_lossy(&rest[separator + 1..]).to_string();
            let name: Arc<str> = Arc::from(attribute.as_str());

            match crate::index_file::Tag::from_byte(tag) {
                Some(crate::index_file::Tag::Presence) => {
                    index.presence.insert(name, bitmap);
                }
                Some(crate::index_file::Tag::Equality) => {
                    index
                        .equality
                        .entry(name)
                        .or_default()
                        .insert(value, bitmap);
                }
                Some(crate::index_file::Tag::Substring) => {
                    index
                        .substrings
                        .entry(name)
                        .or_default()
                        .insert(value, bitmap);
                }
                _ => {}
            }
        }

        // Which kinds exist per attribute is derived from the maps just filled - without this the
        // search path would look at an empty `built` and stand aside, which is a correct answer to
        // a different question ("this attribute has no index") and a wrong one here.
        index.fill_built();
        index
    }

    /// Whether this index can answer every kind of query the configuration asked for.
    ///
    /// A mapped file answers `=`, `=*` and substrings. Ordered ranges are not in it, so a directory
    /// materialised from a file says so rather than quietly returning `None` for `>=` - which the
    /// search path already reads as "scan", so the answer stays right and only the speed changes.
    pub fn covers(&self, plan: &BTreeMap<Arc<str>, BTreeSet<Kind>>) -> bool {
        plan.iter().all(|(attribute, kinds)| {
            self.built
                .get(attribute)
                .is_some_and(|built| kinds.iter().all(|kind| built.contains(kind)))
        })
    }

    /// Which entries the snapshot knows, by DN and id - and deliberately nothing else.
    ///
    /// The tempting version of this returned attribute values, rebuilt by inverting the postings.
    /// It cannot be done, and a test settled it: the equality map keys are **case-folded**
    /// (`ann`, not `Ann`), because that is how a case-insensitive match works. A size wouldn't even
    /// be the problem - answering a client with `ann` when the record says `Ann` is wrong, and
    /// nothing in the answer says it was folded.
    ///
    /// So a skeleton carries an identity, not a copy. That is also all a skeleton is good for: a
    /// filter has to be evaluated against real attributes, so every candidate is read from the
    /// store before it is matched, and the narrowing comes from the postings the snapshot already
    /// holds. Which means the useful structure is exactly this list of (DN, id) - three million
    /// names and numbers, not three million records.
    pub fn skeletons(&self, numbering: &[(String, u32)]) -> Vec<(String, Attributes)> {
        let _ = self;
        numbering
            .iter()
            .map(|(dn, _)| (dn.clone(), Attributes::new()))
            .collect()
    }
}

/// A hash of the *plan* - which attributes are indexed, and how.
///
/// Separate from [`data_fingerprint`], which hashes the data: this one answers "was this snapshot
/// written by a build configured the way I am", and that question has to be answerable without
/// reading a single entry. It is stored in the snapshot header and compared on open.
pub fn plan_hash(config: &IndexConfig) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut eat = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
    };

    if let Ok(plan) = config.resolve() {
        for (attribute, kinds) in plan {
            eat(attribute.as_bytes());
            eat(&[0]);
            for kind in kinds {
                eat(kind.name().as_bytes());
                eat(&[0]);
            }
        }
    }
    for name in &config.default {
        eat(name.as_bytes());
        eat(&[0]);
    }

    hash
}

/// A fingerprint of everything the index is derived from.
///
/// Two things, because either alone misses a change that matters: the entries as the index sees
/// them - DN and `entryCSN`, in the order that gives them their ids - and the resolved plan, so a
/// snapshot built with `cn: [eq]` is not reused after somebody adds `sub`.
///
/// `entryCSN` is what makes a `modify` invalidate the snapshot: the set of DNs does not change
/// when a value inside an entry does, and an index built before that change would narrow to the
/// old value.
///
/// FNV-1a: it is a dozen lines, needs no dependency, and its job here is to notice a change, not
/// to resist an adversary. A hash collision would mean a stale index, which is a wrong answer -
/// and the alternative is no persistence at all, since a cryptographic hash over three million
/// entries on every start costs what this feature was meant to save.
pub fn data_fingerprint(entries: &[Entry], config: &IndexConfig) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;

    let mut eat = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
    };

    eat(&(entries.len() as u64).to_le_bytes());

    for entry in entries {
        eat(entry.dn().as_bytes());
        // The separator keeps `ab` + `c` from hashing as `a` + `bc`.
        eat(&[0xff]);
        if let Some(csn) = entry.attributes().get(crate::operational::ATTR_ENTRY_CSN) {
            for value in &csn.values {
                eat(value.as_bytes());
            }
        }
        eat(&[0xfe]);
    }

    // The plan, in a stable order: `BTreeMap` iteration already is one.
    if let Ok(plan) = config.resolve() {
        for (attribute, kinds) in plan {
            eat(attribute.as_bytes());
            for kind in kinds {
                eat(kind.name().as_bytes());
            }
        }
    }

    // The default kinds are not in the map when the configuration left them empty.
    for name in &config.default {
        eat(name.as_bytes());
    }

    hash
}

/// The bit for a kind, for the snapshot's flag word.
fn kinds_bits(kinds: &BTreeSet<Kind>) -> u32 {
    let mut bits = 0;
    for kind in kinds {
        bits |= match kind {
            Kind::Pres => 1,
            Kind::Eq => 2,
            Kind::Sub => 4,
            Kind::Ord => 8,
        };
    }
    bits
}

/// The kinds a flag word names, or `None` when it names a bit this build does not know.
fn bits_kinds(bits: u32) -> Option<BTreeSet<Kind>> {
    if bits & !0b1111 != 0 {
        return None;
    }
    let mut kinds = BTreeSet::new();
    if bits & 1 != 0 {
        kinds.insert(Kind::Pres);
    }
    if bits & 2 != 0 {
        kinds.insert(Kind::Eq);
    }
    if bits & 4 != 0 {
        kinds.insert(Kind::Sub);
    }
    if bits & 8 != 0 {
        kinds.insert(Kind::Ord);
    }
    Some(kinds)
}

// The writers take a sink rather than a `Vec`, and that is not style: a snapshot of three million
// entries is 2.16 GB, and building it in memory meant holding the directory **and** a second copy
// of its postings at once. On a 30 GB machine that put the process into swap at start, where it
// read 82 GB off the disk and wrote almost nothing for sixteen minutes - measured. Handed a file,
// the same bytes are written once and never held.
fn write_u32(out: &mut dyn Write, value: u32) -> io::Result<()> {
    out.write_all(&value.to_le_bytes())
}

fn write_text(out: &mut dyn Write, text: &str) -> io::Result<()> {
    write_u32(out, text.len() as u32)?;
    out.write_all(text.as_bytes())
}

fn write_names<'a, I>(out: &mut dyn Write, names: I) -> io::Result<()>
where
    I: IntoIterator<Item = &'a Arc<str>>,
{
    let names: Vec<&Arc<str>> = names.into_iter().collect();
    write_u32(out, names.len() as u32)?;
    for name in names {
        write_text(out, name)?;
    }
    Ok(())
}

fn write_bitmap(out: &mut dyn Write, bitmap: &RoaringBitmap) -> io::Result<()> {
    write_u32(out, bitmap.len() as u32)?;
    // Four bytes at a time through a buffered writer is a call per id; two million of those is
    // still faster than one allocation of the whole set, and the buffer is what turns them into
    // sequential writes.
    let mut batch = Vec::with_capacity(4 * 1024);
    for id in bitmap {
        batch.extend_from_slice(&id.to_le_bytes());
        if batch.len() >= 4 * 1024 {
            out.write_all(&batch)?;
            batch.clear();
        }
    }
    out.write_all(&batch)
}

fn write_bitmaps(out: &mut dyn Write, map: &HashMap<Arc<str>, RoaringBitmap>) -> io::Result<()> {
    write_u32(out, map.len() as u32)?;
    for (name, bitmap) in map {
        write_text(out, name)?;
        write_bitmap(out, bitmap)?;
    }
    Ok(())
}

fn write_nested<F>(
    out: &mut dyn Write,
    map: &HashMap<Arc<str>, HashMap<String, RoaringBitmap>>,
    key: F,
) -> io::Result<()>
where
    F: Fn(&mut dyn Write, &str) -> io::Result<()>,
{
    write_u32(out, map.len() as u32)?;
    for (name, values) in map {
        write_text(out, name)?;
        write_u32(out, values.len() as u32)?;
        for (value, bitmap) in values {
            key(out, value)?;
            write_bitmap(out, bitmap)?;
        }
    }
    Ok(())
}

/// Reads the format [`Index::encode`] writes, refusing anything short or malformed.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn finished(&self) -> bool {
        self.at == self.bytes.len()
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(count)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i64(&mut self) -> Option<i64> {
        let bytes = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Some(i64::from_le_bytes(array))
    }

    fn u64(&mut self) -> Option<u64> {
        let bytes = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Some(u64::from_le_bytes(array))
    }

    fn text(&mut self) -> Option<Arc<str>> {
        let length = self.u32()? as usize;
        let bytes = self.take(length)?;
        Some(Arc::from(std::str::from_utf8(bytes).ok()?))
    }

    /// One entry: its DN, then the stored shape of everything else.
    fn entry(&mut self) -> Option<Entry> {
        let dn = self.text()?;
        let length = self.u32()? as usize;
        let shape: StoredShape = serde_json::from_slice(self.take(length)?).ok()?;
        Some(shape.into_entry(&dn))
    }

    fn names(&mut self) -> Option<BTreeSet<Arc<str>>> {
        let count = self.u32()? as usize;
        let mut names = BTreeSet::new();
        for _ in 0..count {
            names.insert(self.text()?);
        }
        Some(names)
    }

    fn bitmap(&mut self) -> Option<RoaringBitmap> {
        let count = self.u32()? as usize;
        let mut bitmap = RoaringBitmap::new();
        for _ in 0..count {
            bitmap.insert(self.u32()?);
        }
        Some(bitmap)
    }

    fn bitmaps(&mut self) -> Option<HashMap<Arc<str>, RoaringBitmap>> {
        let count = self.u32()? as usize;
        let mut map = HashMap::new();
        for _ in 0..count {
            let name = self.text()?;
            map.insert(name, self.bitmap()?);
        }
        Some(map)
    }

    fn nested(&mut self) -> Option<HashMap<Arc<str>, HashMap<String, RoaringBitmap>>> {
        let count = self.u32()? as usize;
        let mut map = HashMap::new();
        for _ in 0..count {
            let name = self.text()?;
            let values = self.u32()? as usize;
            let mut inner = HashMap::new();
            for _ in 0..values {
                let value = self.text()?;
                inner.insert(value.to_string(), self.bitmap()?);
            }
            map.insert(name, inner);
        }
        Some(map)
    }
}

/// Whether `touch` is adding an entry's postings or taking them away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Touch {
    Add,
    Remove,
}

/// Adds or removes one id in a posting list.
fn mark(bitmap: &mut RoaringBitmap, id: u32, how: Touch) {
    match how {
        Touch::Add => {
            bitmap.insert(id);
        }
        Touch::Remove => {
            bitmap.remove(id);
        }
    }
}

impl Index {
    /// Builds every index the configuration asks for.
    ///
    /// `entries` must be in canonical order: the position is the entry id.
    pub fn build(entries: &[Entry], config: &IndexConfig) -> Result<Self, IndexError> {
        // Ids in canonical order, which is what a directory assembled from scratch issues.
        let ids: Vec<u32> = (0..entries.len() as u32).collect();
        Self::build_for(entries, &ids, config)
    }

    /// Builds the index with the ids the directory has issued.
    ///
    /// The id is not the position. A position moves when an entry is added or removed before it,
    /// and an index built over positions would have to be rewritten whole on every insert;
    /// [`crate::directory::Directory`] keeps the two apart, and this is where the index learns
    /// which number belongs to which entry.
    pub fn build_for(
        entries: &[Entry],
        ids: &[u32],
        config: &IndexConfig,
    ) -> Result<Self, IndexError> {
        let plan = config.resolve()?;
        let default_kinds = plan.get(DEFAULT_KEY).cloned().unwrap_or_default();
        let per_attribute: BTreeMap<String, BTreeSet<Kind>> = plan
            .into_iter()
            .filter(|(attribute, _)| !attribute.is_empty())
            .collect();

        let mut index = Self {
            presence: HashMap::new(),
            equality: HashMap::new(),
            substrings: HashMap::new(),
            ordered: HashMap::new(),
            ordered_numeric: BTreeSet::new(),
            ordered_mixed: BTreeSet::new(),
            case_sensitive: BTreeSet::new(),
            default_kinds,
            built: BTreeMap::new(),
            mapped: None,
            overlay: Vec::new(),
            overlay_max: 8192,
        };

        for (position, entry) in entries.iter().enumerate() {
            let id = ids.get(position).copied().unwrap_or(position as u32);
            index.touch(id, entry, &per_attribute, Touch::Add);
        }

        Ok(index)
    }

    /// Drops the posting lists that lost their last id.
    ///
    /// A server written to for months would otherwise keep one empty bitmap per value it has ever
    /// seen, and the memory would grow with the history instead of with the data.
    fn prune_attributes(&mut self, entry: &Entry) {
        for attribute in entry.attributes().values() {
            let name: Arc<str> = crate::model::attribute_name(&attribute.name.to_lowercase());
            self.prune(&name);
        }
    }

    /// The bytes that let the next start skip building this index.
    ///
    /// A whole index in one blob rather than a key per posting list. The reason is the reader: a
    /// start wants all of it at once, and reading a hundred thousand small values to assemble
    /// something the writer already had assembled costs more than reading one large one. Redb
    /// holds the blob as a single value and writes it atomically, so a start either sees the whole
    /// snapshot or none of it - a half-written index would narrow to wrong answers, which is the
    /// one failure mode this must not have.
    ///
    /// `fingerprint` is not a checksum of the bytes: it names the data and the configuration the
    /// snapshot was built from, and the reader recomputes it before trusting anything here.
    pub fn encode(&self, fingerprint: u64, ids: &[(String, u32)], next_id: u32) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out, fingerprint, ids, next_id)
            .expect("writing to a Vec cannot fail");
        out
    }

    /// Writes the same bytes as [`Self::encode`] into any sink.
    ///
    /// This is what a start uses, so the snapshot goes from the index to the file in one pass: no
    /// second copy of the postings in memory, and no 2.16 GB allocation on top of the directory
    /// that is already resident. The format is written front to back with every count known before
    /// it is needed, so nothing has to be patched afterwards - which is what makes streaming it
    /// possible at all.
    pub fn encode_into(
        &self,
        out: &mut dyn Write,
        fingerprint: u64,
        ids: &[(String, u32)],
        next_id: u32,
    ) -> io::Result<()> {
        out.write_all(MAGIC)?;
        out.write_all(&SNAPSHOT_VERSION.to_le_bytes())?;
        out.write_all(&fingerprint.to_le_bytes())?;
        out.write_all(&kinds_bits(&self.default_kinds).to_le_bytes())?;

        // The numbering travels with the postings, by DN. A posting is a number and nothing else
        // says which entry that number names: after an insert the ids are no longer the canonical
        // positions, and a start that assumed positions would answer about other entries - the
        // defect this whole numbering exists to prevent. Positions cannot carry this, because the
        // canonical order itself changes when entries arrive or go.
        write_u32(out, next_id)?;
        write_u32(out, ids.len() as u32)?;
        for (dn, id) in ids {
            write_text(out, dn)?;
            write_u32(out, *id)?;
        }

        write_names(out, &self.case_sensitive)?;
        write_names(out, &self.ordered_numeric)?;
        write_names(out, &self.ordered_mixed)?;

        write_names(out, self.built.keys())?;

        write_bitmaps(out, &self.presence)?;

        // The three two-level maps differ only in how a key is spelled, so one pair of helpers
        // writes and reads all of them.
        write_nested(out, &self.equality, |out, value| write_text(out, value))?;
        write_nested(out, &self.substrings, |out, value| write_text(out, value))?;

        write_u32(out, self.ordered.len() as u32)?;
        for (attribute, values) in &self.ordered {
            write_text(out, attribute)?;
            write_u32(out, values.len() as u32)?;
            for (key, bitmap) in values {
                match key {
                    OrderKey::Num(number) => {
                        out.write_all(&[0])?;
                        out.write_all(&number.to_le_bytes())?;
                    }
                    OrderKey::Text(text) => {
                        out.write_all(&[1])?;
                        write_text(out, text)?;
                    }
                }
                write_bitmap(out, bitmap)?;
            }
        }

        Ok(())
    }

    /// Reads a snapshot, or reports that it cannot be trusted.
    ///
    /// Every reason to distrust the bytes answers `None` and the caller builds the index instead:
    /// a wrong magic, a version from another build, a fingerprint that no longer matches the
    /// data, or a truncated blob. Rebuilding costs a minute; answering from a snapshot that does
    /// not match the data costs a missing search result that nobody can explain.
    pub fn decode(bytes: &[u8], fingerprint: u64) -> Option<Self> {
        Self::decode_with_ids(bytes, fingerprint).map(|(index, _, _)| index)
    }

    /// The snapshot with the numbering it was built under: `(index, (dn, id) pairs, next_id)`.
    pub fn decode_with_ids(bytes: &[u8], fingerprint: u64) -> Option<Snapshot> {
        Self::decode_inner(bytes, Some(fingerprint))
    }

    /// The snapshot without the fingerprint check, for the caller that replays deltas over it.
    ///
    /// The data has moved by definition in that case, so the stored fingerprint can never match;
    /// what vouches for the result is the chain of deltas, each written with the change it
    /// describes.
    pub fn decode_unchecked(bytes: &[u8]) -> Option<Snapshot> {
        Self::decode_inner(bytes, None)
    }

    fn decode_inner(bytes: &[u8], fingerprint: Option<u64>) -> Option<Snapshot> {
        let mut reader = Reader::new(bytes);

        if reader.take(MAGIC.len())? != MAGIC {
            return None;
        }
        if reader.u32()? != SNAPSHOT_VERSION {
            return None;
        }
        let stored = reader.u64()?;
        if fingerprint.is_some_and(|expected| expected != stored) {
            return None;
        }

        let default_kinds = bits_kinds(reader.u32()?)?;

        let next_id = reader.u32()?;
        let count = reader.u32()? as usize;
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            let dn = reader.text()?;
            ids.push((dn.to_string(), reader.u32()?));
        }

        let case_sensitive = reader.names()?;
        let ordered_numeric = reader.names()?;
        let ordered_mixed = reader.names()?;
        let built_names = reader.names()?;

        let presence = reader.bitmaps()?;
        let equality = reader.nested()?;
        let substrings = reader.nested()?;

        let count = reader.u32()? as usize;
        let mut ordered: HashMap<Arc<str>, BTreeMap<OrderKey, RoaringBitmap>> = HashMap::new();
        for _ in 0..count {
            let attribute = reader.text()?;
            let values = reader.u32()? as usize;
            let mut map = BTreeMap::new();
            for _ in 0..values {
                let key = match reader.u8()? {
                    0 => OrderKey::Num(reader.i64()?),
                    1 => OrderKey::Text(reader.text()?.to_string()),
                    _ => return None,
                };
                map.insert(key, reader.bitmap()?);
            }
            ordered.insert(attribute, map);
        }

        if !reader.finished() {
            return None;
        }

        // `built` says what the index is able to answer, and it is rebuilt from the same names
        // it was written with; the kinds each attribute was built for are implied by which maps
        // hold it, so nothing else needs carrying.
        let mut built = BTreeMap::new();
        for name in built_names {
            built.insert(name, BTreeSet::new());
        }

        let mut index = Self {
            presence,
            equality,
            substrings,
            ordered,
            ordered_numeric,
            ordered_mixed,
            case_sensitive,
            default_kinds,
            built,
            mapped: None,
            overlay: Vec::new(),
            overlay_max: 8192,
        };
        index.fill_built();
        Some((index, ids, next_id))
    }

    /// Recomputes which kinds each attribute was built for, from the maps that hold it.
    ///
    /// Not carried in the snapshot because it is derivable, and a derived value that is stored
    /// can disagree with what it was derived from - which is the class of bug a snapshot is most
    /// likely to introduce.
    fn fill_built(&mut self) {
        self.built.clear();
        for name in self.presence.keys() {
            self.built
                .entry(Arc::clone(name))
                .or_default()
                .insert(Kind::Pres);
        }
        for name in self.equality.keys() {
            self.built
                .entry(Arc::clone(name))
                .or_default()
                .insert(Kind::Eq);
        }
        for name in self.substrings.keys() {
            self.built
                .entry(Arc::clone(name))
                .or_default()
                .insert(Kind::Sub);
        }
        for name in self.ordered.keys() {
            self.built
                .entry(Arc::clone(name))
                .or_default()
                .insert(Kind::Ord);
        }
    }

    /// Adds or removes one entry's ids from every posting list, without touching the rest.
    ///
    /// One function for both directions on purpose: an index that adds a value in one place and
    /// forgets it in another stops narrowing correctly and the defect shows up as a missing
    /// search result, which is the hardest kind of bug to notice. `how` is the only difference.
    ///
    /// `built` and the numeric/mixed/case flags only ever grow: they describe what the index is
    /// able to answer, and forgetting that an attribute was numeric because the last numeric
    /// entry left would silently downgrade matching for the entries that remain.
    fn touch(
        &mut self,
        id: u32,
        entry: &Entry,
        per_attribute: &BTreeMap<String, BTreeSet<Kind>>,
        how: Touch,
    ) {
        for attribute in entry.attributes().values() {
            // Keys are lowercase because the filter lowercases attribute descriptions before
            // building a query (RFC 4512 makes the name case-insensitive).
            let name: Arc<str> = crate::model::attribute_name(&attribute.name.to_lowercase());
            if attribute.flags.case_sensitive {
                self.case_sensitive.insert(Arc::clone(&name));
            }
            let kinds = self
                .kinds_for(&name, per_attribute)
                .cloned()
                .unwrap_or_default();

            if kinds.contains(&Kind::Pres) {
                mark(self.presence.entry(Arc::clone(&name)).or_default(), id, how);
                if how == Touch::Add {
                    self.built
                        .entry(Arc::clone(&name))
                        .or_default()
                        .insert(Kind::Pres);
                }
            }

            if kinds.contains(&Kind::Eq) || kinds.contains(&Kind::Ord) {
                let case_sensitive = attribute.flags.case_sensitive;
                for value in attribute.values.iter() {
                    let key = fold(value, case_sensitive);

                    if kinds.contains(&Kind::Eq) {
                        mark(
                            self.equality
                                .entry(Arc::clone(&name))
                                .or_default()
                                .entry(key.clone())
                                .or_default(),
                            id,
                            how,
                        );
                    }

                    if kinds.contains(&Kind::Ord) {
                        // The attribute's numeric-ness is decided by its values, so a mixed one
                        // is remembered as such and left to the scan.
                        match key.parse::<i64>() {
                            Ok(number) => {
                                mark(
                                    self.ordered
                                        .entry(Arc::clone(&name))
                                        .or_default()
                                        .entry(OrderKey::Num(number))
                                        .or_default(),
                                    id,
                                    how,
                                );
                                self.ordered_numeric.insert(Arc::clone(&name));
                            }
                            Err(_) => {
                                mark(
                                    self.ordered
                                        .entry(Arc::clone(&name))
                                        .or_default()
                                        .entry(OrderKey::Text(key.clone()))
                                        .or_default(),
                                    id,
                                    how,
                                );
                                self.ordered_mixed.insert(Arc::clone(&name));
                            }
                        }
                    }
                }

                if how == Touch::Add {
                    if kinds.contains(&Kind::Eq) {
                        self.built
                            .entry(Arc::clone(&name))
                            .or_default()
                            .insert(Kind::Eq);
                    }
                    if kinds.contains(&Kind::Ord) {
                        self.built
                            .entry(Arc::clone(&name))
                            .or_default()
                            .insert(Kind::Ord);
                    }
                }
            }

            if kinds.contains(&Kind::Sub) {
                let case_sensitive = attribute.flags.case_sensitive;
                for value in attribute.values.iter() {
                    // The value is indexed between its boundaries: `^` and `$` are what an
                    // anchored part of a pattern looks up.
                    let padded = format!("^{}$", fold(value, case_sensitive));
                    for trigram in trigrams(&padded) {
                        mark(
                            self.substrings
                                .entry(Arc::clone(&name))
                                .or_default()
                                .entry(trigram)
                                .or_default(),
                            id,
                            how,
                        );
                    }
                }
                if how == Touch::Add {
                    self.built.entry(name).or_default().insert(Kind::Sub);
                }
            }
        }
    }

    /// Drops the postings of one attribute that no longer hold any id.
    fn prune(&mut self, name: &Arc<str>) {
        if self
            .presence
            .get(name)
            .is_some_and(|bitmap| bitmap.is_empty())
        {
            self.presence.remove(name);
        }
        if let Some(values) = self.equality.get_mut(name) {
            values.retain(|_, bitmap| !bitmap.is_empty());
            if values.is_empty() {
                self.equality.remove(name);
            }
        }
        if let Some(trigrams_by_value) = self.substrings.get_mut(name) {
            trigrams_by_value.retain(|_, bitmap| !bitmap.is_empty());
            if trigrams_by_value.is_empty() {
                self.substrings.remove(name);
            }
        }
        if let Some(values) = self.ordered.get_mut(name) {
            values.retain(|_, bitmap| !bitmap.is_empty());
            if values.is_empty() {
                self.ordered.remove(name);
            }
        }
    }

    /// Replaces one entry in the index in place: its id stays, its postings change.
    ///
    /// This is what makes a `modify` cost the entry instead of the directory. It is correct only
    /// when the id is the same before and after, which is true for a replace: the position in
    /// canonical order depends on the DN, and a modify does not change the DN. Adding or
    /// deleting an entry moves every id after it, and that still rebuilds the whole index.
    /// A change set as bytes, for the store to keep until the snapshot is rewritten.
    ///
    /// The entries travel whole, through the same `StoredEntry` the journal uses: a format that is
    /// already written and read on every write is not a second format to get wrong. The DN rides
    /// alongside because `StoredEntry` deliberately does not carry it - the journal keys by CSN.
    pub fn encode_delta(changes: &[IndexChange]) -> Vec<u8> {
        let mut out = Vec::new();
        Self::encode_delta_into(&mut out, changes).expect("writing to a Vec cannot fail");
        out
    }

    /// The same bytes, written to a sink.
    ///
    /// A delta is small - one change set - but it goes through the same writers as the snapshot,
    /// and keeping one format is worth more than the two lines a `Vec` would save.
    pub fn encode_delta_into(out: &mut dyn Write, changes: &[IndexChange]) -> io::Result<()> {
        out.write_all(DELTA_MAGIC)?;
        out.write_all(&SNAPSHOT_VERSION.to_le_bytes())?;
        write_u32(out, changes.len() as u32)?;

        fn push_entry(out: &mut dyn Write, entry: &Entry) -> io::Result<()> {
            write_text(out, entry.dn())?;
            let json = serde_json::to_vec(&StoredShape::from_entry(entry)).unwrap_or_default();
            write_u32(out, json.len() as u32)?;
            out.write_all(&json)
        }

        for change in changes {
            match change {
                IndexChange::Add { id, entry } => {
                    out.write_all(&[0])?;
                    write_u32(out, *id)?;
                    push_entry(out, entry)?;
                }
                IndexChange::Replace { id, before, after } => {
                    out.write_all(&[1])?;
                    write_u32(out, *id)?;
                    push_entry(out, before)?;
                    push_entry(out, after)?;
                }
                IndexChange::Remove { id, entry } => {
                    out.write_all(&[2])?;
                    write_u32(out, *id)?;
                    push_entry(out, entry)?;
                }
            }
        }

        Ok(())
    }

    /// Reads a delta, or reports that it cannot be trusted.
    pub fn decode_delta(bytes: &[u8]) -> Option<Vec<IndexChange>> {
        let mut reader = Reader::new(bytes);

        if reader.take(DELTA_MAGIC.len())? != DELTA_MAGIC {
            return None;
        }
        if reader.u32()? != SNAPSHOT_VERSION {
            return None;
        }

        let count = reader.u32()? as usize;
        let mut changes = Vec::with_capacity(count);

        for _ in 0..count {
            let kind = reader.u8()?;
            let id = reader.u32()?;
            let first = reader.entry()?;

            let change = match kind {
                0 => IndexChange::Add { id, entry: first },
                1 => IndexChange::Replace {
                    id,
                    before: first,
                    after: reader.entry()?,
                },
                2 => IndexChange::Remove { id, entry: first },
                _ => return None,
            };

            changes.push(change);
        }

        if !reader.finished() {
            return None;
        }
        Some(changes)
    }

    /// Applies a stored delta, in the order the changes happened.
    pub fn apply_delta(
        &mut self,
        changes: &[IndexChange],
        config: &IndexConfig,
    ) -> Result<(), IndexError> {
        let per_attribute = plan_of(config)?;

        // A mapped index records the changes instead of pulling every posting out of the file: the
        // overlay is applied to each answer, so a write costs tens of bytes and the memory follows
        // the number of changes rather than the size of the directory (ub-log §109).
        if self.mapped.is_some() && self.overlay.len() + changes.len() <= self.overlay_cap() {
            for change in changes {
                match change {
                    IndexChange::Add { id, entry } => {
                        self.push_overlay(*id, None, Some(entry.attributes()));
                    }
                    IndexChange::Replace { id, before, after } => {
                        self.push_overlay(*id, Some(before.attributes()), Some(after.attributes()));
                    }
                    IndexChange::Remove { id, entry } => {
                        self.push_overlay(*id, Some(entry.attributes()), None);
                    }
                }
            }
            return Ok(());
        }
        if self.mapped.is_some() {
            self.materialize();
        }

        for change in changes {
            match change {
                IndexChange::Add { id, entry } => {
                    self.touch(*id, entry, &per_attribute, Touch::Add);
                }
                IndexChange::Replace { id, before, after } => {
                    self.touch(*id, before, &per_attribute, Touch::Remove);
                    self.touch(*id, after, &per_attribute, Touch::Add);
                    self.prune_attributes(before);
                }
                IndexChange::Remove { id, entry } => {
                    self.touch(*id, entry, &per_attribute, Touch::Remove);
                    self.prune_attributes(entry);
                }
            }
        }
        Ok(())
    }

    /// Adds one entry's postings under `id`, without touching any other entry.
    ///
    /// The half of [`Self::replace`] an insertion needs, and the reason a write no longer costs
    /// the directory: the entries already indexed keep their postings, because their ids did not
    /// change when the new entry took a position.
    pub fn add(&mut self, id: u32, entry: &Entry, config: &IndexConfig) -> Result<(), IndexError> {
        // The plan first, so a configuration that cannot be honoured fails here rather than later.
        let per_attribute = plan_of(config)?;

        if self.mapped.is_some() && self.overlay.len() < self.overlay_cap() {
            self.push_overlay(id, None, Some(entry.attributes()));
            return Ok(());
        }
        // The overlay reached its cap, or the index is not mapped: materialise and carry on with the
        // maps. Bounded on purpose - see `snapshot_overlay_max`.
        if self.mapped.is_some() {
            self.materialize();
        }

        self.touch(id, entry, &per_attribute, Touch::Add);
        Ok(())
    }

    /// Removes one entry's postings, pruning what is left empty.
    pub fn remove(
        &mut self,
        id: u32,
        entry: &Entry,
        config: &IndexConfig,
    ) -> Result<(), IndexError> {
        let per_attribute = plan_of(config)?;

        if self.mapped.is_some() && self.overlay.len() < self.overlay_cap() {
            self.push_overlay(id, Some(entry.attributes()), None);
            return Ok(());
        }
        if self.mapped.is_some() {
            self.materialize();
        }

        self.touch(id, entry, &per_attribute, Touch::Remove);
        self.prune_attributes(entry);
        Ok(())
    }

    pub fn replace(
        &mut self,
        id: u32,
        old: &Entry,
        new: &Entry,
        config: &IndexConfig,
    ) -> Result<(), IndexError> {
        let per_attribute = plan_of(config)?;

        if self.mapped.is_some() && self.overlay.len() < self.overlay_cap() {
            self.push_overlay(id, Some(old.attributes()), Some(new.attributes()));
            return Ok(());
        }
        if self.mapped.is_some() {
            self.materialize();
        }

        self.touch(id, old, &per_attribute, Touch::Remove);
        self.touch(id, new, &per_attribute, Touch::Add);

        self.prune_attributes(old);

        Ok(())
    }
    fn kinds_for<'a>(
        &'a self,
        name: &Arc<str>,
        per_attribute: &'a BTreeMap<String, BTreeSet<Kind>>,
    ) -> Option<&'a BTreeSet<Kind>> {
        // An attribute listed with no kinds means 'nothing special', not 'no index':
        // the default still applies, otherwise a typo in the list silently unindexes.
        match per_attribute.get(&name.to_lowercase()) {
            Some(kinds) if !kinds.is_empty() => Some(kinds),
            _ => (!self.default_kinds.is_empty()).then_some(&self.default_kinds),
        }
    }

    /// Records a change to apply on top of the mapped file.
    ///
    /// Merged with an earlier record for the same id rather than appended: two changes to one entry
    /// in a row must look like one change from the file's point of view, or the second record's
    /// `before` would describe a state the file never held and the first record's `after` would be
    /// applied twice.
    fn push_overlay(
        &mut self,
        id: u32,
        before: Option<&crate::model::Attributes>,
        after: Option<&crate::model::Attributes>,
    ) {
        if let Some(existing) = self.overlay.iter_mut().find(|record| record.id == id) {
            // The first `before` wins: it is the state the file was written in, which is what the
            // overlay has to be able to remove from an answer.
            if existing.before.is_none() {
                existing.before = before.cloned();
            }
            existing.after = after.cloned();
            return;
        }

        self.overlay.push(Overlay {
            id,
            before: before.cloned(),
            after: after.cloned(),
        });
    }

    /// Whether these attributes would have been posted under `query`.
    ///
    /// The same question the index maps answer, asked of values instead of looking a key up, so the
    /// overlay can say which of its records the file's answer is missing and which it must lose.
    ///
    /// Conservative where the index itself stands aside: `Not` and `Unindexed` never narrowed a
    /// lookup, so they match everything here and change nothing.
    fn matches(&self, query: &Query, attributes: &crate::model::Attributes) -> bool {
        match query {
            Query::Presence(name) => attributes.get(name).is_some(),
            Query::Equality { attribute, value } => {
                let case_sensitive = self.case_sensitive.contains(attribute);
                let wanted = fold(value, case_sensitive);
                attributes.get(attribute).is_some_and(|held| {
                    held.values
                        .iter()
                        .any(|candidate| fold(candidate, case_sensitive) == wanted)
                })
            }
            Query::Substring {
                attribute,
                initial,
                any,
                final_part,
            } => {
                let case_sensitive = self.case_sensitive.contains(attribute);
                attributes.get(attribute).is_some_and(|held| {
                    held.values.iter().any(|candidate| {
                        let value = fold(candidate, case_sensitive);
                        let starts = initial
                            .as_ref()
                            .is_none_or(|part| value.starts_with(&fold(part, case_sensitive)));
                        let ends = final_part
                            .as_ref()
                            .is_none_or(|part| value.ends_with(&fold(part, case_sensitive)));
                        let contains = any
                            .iter()
                            .all(|part| value.contains(&fold(part, case_sensitive)));
                        starts && ends && contains
                    })
                })
            }
            Query::Range {
                attribute,
                bound,
                value,
            } => attributes.get(attribute).is_some_and(|held| {
                let case_sensitive = self.case_sensitive.contains(attribute);
                held.values.iter().any(|candidate| {
                    // Numbers compare as numbers and everything else as folded text, which is the
                    // rule the ordered index uses; comparing `10` and `9` as text would put the
                    // bound on the wrong side.
                    match (candidate.trim().parse::<i64>(), value.trim().parse::<i64>()) {
                        (Ok(held_number), Ok(bound_number)) => match bound {
                            RangeBound::AtLeast => held_number >= bound_number,
                            RangeBound::AtMost => held_number <= bound_number,
                        },
                        _ => {
                            let held_text = fold(candidate, case_sensitive);
                            let bound_text = fold(value, case_sensitive);
                            match bound {
                                RangeBound::AtLeast => held_text >= bound_text,
                                RangeBound::AtMost => held_text <= bound_text,
                            }
                        }
                    }
                })
            }),
            Query::And(parts) => parts.iter().all(|part| self.matches(part, attributes)),
            Query::Or(parts) => parts.iter().any(|part| self.matches(part, attributes)),
            // Never narrowed a lookup, so it cannot change the file's answer here either.
            Query::Not(_) | Query::Unindexed => true,
        }
    }

    /// The file's answer with the changes since it was written applied.
    ///
    /// An entry whose `before` matched and whose `after` does not is removed from the answer; one
    /// that starts matching is added. Anything else leaves the answer alone, which keeps the common
    /// case - a change to an attribute the query does not name - free.
    fn apply_overlay(&self, query: &Query, mut answer: RoaringBitmap) -> RoaringBitmap {
        for record in &self.overlay {
            let before = record
                .before
                .as_ref()
                .is_some_and(|attributes| self.matches(query, attributes));
            let after = record
                .after
                .as_ref()
                .is_some_and(|attributes| self.matches(query, attributes));

            match (before, after) {
                (true, false) => {
                    answer.remove(record.id);
                }
                (false, true) => {
                    answer.insert(record.id);
                }
                _ => {}
            }
        }
        answer
    }

    /// Re-applies the overlay to the maps, for the one moment the file stops being the answer.
    ///
    /// Called from `materialize`, which is the snapshot rewrite and nothing else: the maps are
    /// rebuilt from the file, and without this the changes recorded since it was written would be
    /// silently lost - an index that forgets the last few thousand writes and then writes them out
    /// as the truth.
    fn reapply_overlay(&mut self) {
        if self.overlay.is_empty() {
            return;
        }

        // The plan is not passed here because the object does not hold it; `built` is what the file
        // recorded, and it is the same set of kinds - an attribute the file indexes is an attribute
        // this index indexes.
        let per_attribute: BTreeMap<String, BTreeSet<Kind>> = self
            .built
            .iter()
            .map(|(attribute, kinds)| (attribute.to_string(), kinds.clone()))
            .collect();

        let overlay = std::mem::take(&mut self.overlay);
        for record in overlay {
            if let Some(before) = &record.before {
                let entry = Entry::new("", before.clone());
                self.touch(record.id, &entry, &per_attribute, Touch::Remove);
            }
            if let Some(after) = &record.after {
                let entry = Entry::new("", after.clone());
                self.touch(record.id, &entry, &per_attribute, Touch::Add);
            }
        }
    }

    /// How many changes are waiting to be applied on top of the file.
    pub fn overlay_len(&self) -> usize {
        self.overlay.len()
    }

    /// The cap in force, with the documented default for an index built without a configuration.
    ///
    /// Zero cannot mean "no overlay": the field is a `usize` that `Default` leaves at zero, and a
    /// cap of zero would silently turn every write back into a materialisation - which is exactly
    /// the defect this default rules out. An operator who wants no overlay sets the cap to one.
    fn overlay_cap(&self) -> usize {
        if self.overlay_max == 0 {
            DEFAULT_OVERLAY_MAX
        } else {
            self.overlay_max
        }
    }

    /// Candidate ids for `query`, or `None` when the index cannot narrow it.
    /// Roughly what these postings occupy, for a start line that says how much of the ceiling this
    /// directory spends on the index alone.
    ///
    /// An estimate, and named as one: bitmaps hold variable-length containers, and walking them to
    /// count exactly would cost more than the number is worth. What it must do is order the parts
    /// correctly - keys, values and postings - so an operator can see whether the index is a
    /// fraction of the ceiling or all of it.
    pub fn heap_bytes(&self) -> u64 {
        fn bitmap(bytes: &mut u64, map: &RoaringBitmap) {
            *bytes += u64::try_from(map.serialized_size()).unwrap_or(u64::MAX);
        }

        let mut bytes = 0u64;
        for (attribute, map) in &self.presence {
            bytes += attribute.len() as u64;
            bitmap(&mut bytes, map);
        }
        for (attribute, values) in &self.equality {
            bytes += attribute.len() as u64;
            for (value, map) in values {
                bytes += value.len() as u64;
                bitmap(&mut bytes, map);
            }
        }
        for (attribute, values) in &self.substrings {
            bytes += attribute.len() as u64;
            for (value, map) in values {
                bytes += value.len() as u64;
                bitmap(&mut bytes, map);
            }
        }
        for (attribute, values) in &self.ordered {
            bytes += attribute.len() as u64;
            for map in values.values() {
                bitmap(&mut bytes, map);
            }
        }
        // What the maps cost to hold their entries: a pointer and a hash each. Counted so the
        // estimate follows the load factor instead of pretending it is free.
        let entries = self.presence.len()
            + self
                .equality
                .values()
                .map(std::collections::HashMap::len)
                .sum::<usize>()
            + self
                .substrings
                .values()
                .map(std::collections::HashMap::len)
                .sum::<usize>()
            + self
                .ordered
                .values()
                .map(std::collections::BTreeMap::len)
                .sum::<usize>();
        bytes += (entries as u64) * 16;

        bytes
    }

    pub fn candidates(&self, query: &Query) -> Option<RoaringBitmap> {
        // Everything below answers from the file or from the maps; the changes made since the file
        // was written are applied on top of whichever it was. Done here rather than in each arm, so
        // a new query kind cannot forget them.
        let answer = self.candidates_unoverlaid(query)?;
        if self.overlay.is_empty() {
            return Some(answer);
        }
        Some(self.apply_overlay(query, answer))
    }

    fn candidates_unoverlaid(&self, query: &Query) -> Option<RoaringBitmap> {
        // The file first, when the postings live there. Only the kinds it holds are asked: a range
        // is not in the format, and answering `None` for it - which the search path reads as
        // "scan" - keeps the answer right.
        if let Some(answer) = self.candidates_from_file(query) {
            return Some(answer);
        }

        match query {
            Query::Presence(name) => lookup(&self.presence, name).cloned(),
            Query::Equality { attribute, value } => {
                let case_sensitive = contains(&self.case_sensitive, attribute);
                let key = fold(value, case_sensitive);
                lookup(&self.equality, attribute)
                    .and_then(|values| values.get(&key))
                    // An indexed attribute with no such value is a real empty answer,
                    // not "unknown": the map exists for every value ever seen.
                    .cloned()
                    .or_else(|| {
                        lookup_tree(&self.built, attribute)
                            .filter(|kinds| kinds.contains(&Kind::Eq))
                            .map(|_| RoaringBitmap::new())
                    })
            }
            Query::Substring {
                attribute,
                initial,
                any,
                final_part,
            } => {
                // Every trigram the pattern implies must be present in the value, so the
                // candidates are the intersection. A part shorter than three characters
                // implies nothing and is skipped; if nothing at all is left the index stands
                // aside rather than answering with an empty set, which would be a lie.
                // Every part is folded the way the stored value was: the index holds
                // lowercase trigrams for an ordinary attribute, so a lookup for "Ann" has to
                // become "ann" or it finds nothing. Leaving the query unfolded is a false
                // negative, and the fixture that hid it held only lowercase values.
                let case_sensitive = contains(&self.case_sensitive, attribute);
                let fold_part = |part: &str| fold(part, case_sensitive);

                let mut wanted: Vec<String> = Vec::new();
                if let Some(initial) = initial {
                    // `part*` can only match at the start, so the boundary belongs in the
                    // lookup: this is what keeps an anchored fragment selective.
                    wanted.extend(trigrams(&format!("^{}", fold_part(initial))));
                }
                for part in any {
                    // Interior: the part as given, folded to match the stored trigrams.
                    wanted.extend(trigrams(&fold_part(part)));
                }
                if let Some(final_part) = final_part {
                    wanted.extend(trigrams(&format!("{}$", fold_part(final_part))));
                }

                if wanted.is_empty() {
                    // Every part was shorter than three characters; nothing to look up.
                    return None;
                }

                let buckets = lookup(&self.substrings, attribute);

                // An attribute with no substring index: stand aside and let the scan answer.
                let buckets = buckets?;

                let mut narrowed = RoaringBitmap::new();
                for (index, trigram) in wanted.iter().enumerate() {
                    let Some(bitmap) = buckets.get(trigram) else {
                        // The attribute is indexed, so a trigram nobody has cannot match:
                        // an empty answer, not "unknown".
                        return Some(RoaringBitmap::new());
                    };

                    if index == 0 {
                        narrowed = bitmap.clone();
                    } else {
                        narrowed &= bitmap;
                    }
                }

                Some(narrowed)
            }
            Query::Range {
                attribute,
                bound,
                value,
            } => {
                let case_sensitive = contains(&self.case_sensitive, attribute);
                let key = fold(value, case_sensitive);

                let buckets = lookup(&self.ordered, attribute);

                // An attribute nobody has an ordered index for: stand aside. The difference
                // from the equality case is that a map exists only for attributes that hold
                // values, so its absence here says nothing about the data.
                let buckets = buckets?;

                // The key has to be ordered the same way the filter compares, or the range
                // would leave out entries the filter would have matched. An attribute whose
                // values are all integers gets a numeric key; one with no integers gets text;
                // a mixed one and a bound of the other kind get nothing, because neither
                // ordering describes the comparison.
                let all_numeric = self.ordered_numeric.contains(attribute)
                    || self
                        .ordered_numeric
                        .contains(&attribute.to_lowercase() as &str);
                let mixed = self.ordered_mixed.contains(attribute)
                    || self
                        .ordered_mixed
                        .contains(&attribute.to_lowercase() as &str);

                let key = match key.parse::<i64>() {
                    // One kind per attribute: a numeric bound belongs in a map of numbers,
                    // and a text bound in a map of text. Anything else is a comparison the
                    // map cannot describe.
                    Ok(number) if all_numeric && !mixed => OrderKey::Num(number),
                    Err(_) if !all_numeric && !mixed => OrderKey::Text(key),
                    _ => return None,
                };

                let range: Box<dyn Iterator<Item = &RoaringBitmap>> = match bound {
                    RangeBound::AtLeast => Box::new(buckets.range(key..).map(|(_, ids)| ids)),
                    RangeBound::AtMost => Box::new(buckets.range(..=key).map(|(_, ids)| ids)),
                };

                let mut union = RoaringBitmap::new();
                for bitmap in range {
                    union |= bitmap;
                }

                Some(union)
            }
            Query::And(parts) => {
                // Every part is narrowed first, then the intersections run from the smallest
                // set outwards.
                //
                // The order the client wrote the parts in says nothing about which one is
                // selective, and intersecting in that order costs what the first part costs:
                // `(&(objectClass=person)(uid=alice))` over a million entries materialises a
                // million positions before the second part cuts them to one. Starting from the
                // smallest set means the work follows the answer rather than the request.
                //
                // An empty part ends it: a set with nothing in it cannot be intersected into
                // anything but nothing, so the remaining parts are not narrowed at all. That is
                // the case a rejected filter usually lands in.
                let mut narrowed: Vec<RoaringBitmap> = Vec::with_capacity(parts.len());
                for part in parts {
                    if let Some(bitmap) = self.candidates(part) {
                        if bitmap.is_empty() {
                            return Some(bitmap);
                        }
                        narrowed.push(bitmap);
                    }
                }

                // Fewest entries first. `sort_unstable_by_key` on the length, not on the bitmap:
                // the order of equal-sized sets does not affect the result, only the cost, and
                // the cost is the length.
                narrowed.sort_unstable_by_key(|bitmap| bitmap.len());

                let mut intersections = narrowed.into_iter();
                let Some(mut current) = intersections.next() else {
                    // Not one part was indexable, so the index stands aside and the filter
                    // evaluates every entry the scope holds.
                    return None;
                };

                for bitmap in intersections {
                    current &= bitmap;
                    if current.is_empty() {
                        break;
                    }
                }

                Some(current)
            }
            Query::Or(parts) => {
                // Every part has to be indexable: a union over the indexable ones
                // only would miss answers that live in the unindexed part.
                let mut union: Option<RoaringBitmap> = None;
                for part in parts {
                    let bitmap = self.candidates(part)?;
                    union = Some(match union {
                        Some(current) => current | bitmap,
                        None => bitmap,
                    });
                }
                union
            }
            Query::Not(_) | Query::Unindexed => None,
        }
    }

    /// Attributes that have an index, for logging.
    pub fn built_attributes(&self) -> impl Iterator<Item = (&Arc<str>, &BTreeSet<Kind>)> {
        self.built.iter()
    }

    /// Rough memory held by the bitmaps, for the startup log.
    pub fn size_bytes(&self) -> usize {
        let presence: usize = self
            .presence
            .values()
            .map(|bitmap| bitmap.serialized_size())
            .sum();
        let substrings: usize = self
            .substrings
            .values()
            .flat_map(|buckets| buckets.values())
            .map(|bitmap| bitmap.serialized_size())
            .sum();
        let ordered: usize = self
            .ordered
            .values()
            .flat_map(|buckets| buckets.values())
            .map(|bitmap| bitmap.serialized_size())
            .sum();
        let equality: usize = self
            .equality
            .values()
            .flat_map(|values| values.values())
            .map(|bitmap| bitmap.serialized_size())
            .sum();

        presence + equality + substrings + ordered
    }

    pub fn is_empty(&self) -> bool {
        self.presence.is_empty()
            && self.equality.is_empty()
            && self.substrings.is_empty()
            && self.ordered.is_empty()
    }
}

/// The value under `name`, whether the caller spelled it the way RFC 4512 allows or the way
/// the index stores it.
///
/// Attribute descriptions are case-insensitive, and the filter lowercases them before asking
/// while the index keeps its keys lowercase as well. This helper is the one place that
/// bridges the two, so a query written as `uidNumber` and one written as `uidnumber` are the
/// same question.
fn lookup<'a, V>(map: &'a HashMap<Arc<str>, V>, name: &str) -> Option<&'a V> {
    map.get(name)
        .or_else(|| map.get(name.to_lowercase().as_str()))
}

/// The same, for the one map kept in order.
fn lookup_tree<'a, V>(map: &'a BTreeMap<Arc<str>, V>, name: &str) -> Option<&'a V> {
    map.get(name)
        .or_else(|| map.get(name.to_lowercase().as_str()))
}

/// The same, for a set.
fn contains(set: &BTreeSet<Arc<str>>, name: &str) -> bool {
    set.contains(name) || set.contains(name.to_lowercase().as_str())
}

/// Every three-character window of `text`.
///
/// The padding is left to the caller, because it is what distinguishes the three parts of a
/// pattern: an initial fragment is matched against `^part`, a final one against `part$`, and
/// an interior one against the part itself. Padding all three would turn `(cn=*ob*)` into a
/// request for values beginning with `ob`, and "bob" would stop matching - a false negative,
/// which is the one direction an index must never fail in.
///
/// Fewer than three characters yield no window at all, and the index stands aside.
fn trigrams(text: &str) -> Vec<String> {
    let characters: Vec<char> = text.chars().collect();

    characters
        .windows(3)
        .map(|window| window.iter().collect())
        .collect()
}

fn fold(value: &str, case_sensitive: bool) -> String {
    if case_sensitive {
        value.to_string()
    } else {
        value.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, Attributes};

    fn entry(dn: &str, pairs: &[(&'static str, &[&str])]) -> Entry {
        let mut attributes = Attributes::new();
        for (name, values) in pairs {
            attributes = attributes.push(Attribute::new(
                *name,
                values.iter().map(|value| value.to_string()).collect(),
            ));
        }
        Entry::new(dn, attributes)
    }

    /// The numbering a directory built from these entries would issue: canonical order, from zero.
    fn numbering_of(entries: &[Entry]) -> Vec<(String, u32)> {
        entries
            .iter()
            .enumerate()
            .map(|(position, entry)| (entry.dn().to_string(), position as u32))
            .collect()
    }

    /// `count` users, each with a distinct cn and uid and a stamped `entryCSN`, which is what a
    /// write through the protocol produces and what the fingerprint tracks.
    fn people(count: usize) -> Vec<Entry> {
        (0..count)
            .map(|index| {
                let mut built = entry(
                    &format!("cn=user{index},ou=users,dc=example,dc=com"),
                    &[
                        ("objectClass", &["top", "inetOrgPerson"]),
                        ("cn", &[]),
                        ("uid", &[]),
                    ],
                );
                let mut attributes = built.attributes().clone();
                attributes =
                    attributes.replace(Attribute::new("cn", vec![format!("Person {index}")]));
                attributes =
                    attributes.replace(Attribute::new("uid", vec![format!("user{index}")]));
                attributes = attributes.replace(
                    Attribute::single(
                        crate::operational::ATTR_ENTRY_CSN,
                        "20260101000000.000000Z#000000#001#000000",
                    )
                    .operational(),
                );
                built = Entry::new(built.dn(), attributes);
                built
            })
            .collect()
    }

    fn directory() -> Vec<Entry> {
        vec![
            entry(
                "cn=ann,ou=users,dc=example,dc=com",
                &[
                    ("objectClass", &["top", "inetOrgPerson"]),
                    ("cn", &["Ann"]),
                    ("mail", &["ann@example.com"]),
                ],
            ),
            entry(
                "cn=bob,ou=users,dc=example,dc=com",
                &[
                    ("objectClass", &["top", "inetOrgPerson"]),
                    ("cn", &["Bob"]),
                    ("mail", &["bob@example.com"]),
                ],
            ),
            entry(
                "cn=team,ou=groups,dc=example,dc=com",
                &[
                    ("objectClass", &["top", "posixGroup"]),
                    ("cn", &["team"]),
                    ("memberUid", &["ann", "bob"]),
                ],
            ),
        ]
    }

    fn config(attributes: &[(&str, &[&str])], default: &[&str]) -> IndexConfig {
        IndexConfig {
            default: default.iter().map(|name| name.to_string()).collect(),
            attributes: attributes
                .iter()
                .map(|(attribute, kinds)| {
                    (
                        attribute.to_string(),
                        kinds.iter().map(|kind| kind.to_string()).collect(),
                    )
                })
                .collect(),
            ..Default::default()
        }
    }

    // The contract that matters, and the one the previous version of this function broke: a
    // skeleton is an identity. It does not carry values, because the postings hold them folded and
    // answering a client with a folded value is answering with data the client never stored.
    #[test]
    fn a_skeleton_is_an_identity_and_not_a_copy_of_the_values() {
        let numbering = vec![
            ("uid=alice,ou=users,dc=example,dc=com".to_string(), 0u32),
            ("uid=bob,ou=users,dc=example,dc=com".to_string(), 1u32),
        ];
        let index = Index::default();

        let skeletons = index.skeletons(&numbering);

        assert_eq!(skeletons.len(), 2, "one per numbered entry, none invented");
        assert_eq!(skeletons[0].0, "uid=alice,ou=users,dc=example,dc=com");
        assert!(
            skeletons
                .iter()
                .all(|(_, attributes)| attributes.values().is_empty()),
            "an identity carries no attributes: a folded value would be a lie about the record"
        );
    }

    /// `(attribute=*part*)`, the shape the filter parser produces for a bare substring.
    fn any_substring(attribute: &str, part: &str) -> Query {
        Query::Substring {
            attribute: attribute.into(),
            initial: None,
            any: vec![part.to_string()],
            final_part: None,
        }
    }

    fn ids(bitmap: Option<RoaringBitmap>) -> Vec<u32> {
        bitmap
            .map(|bitmap| bitmap.iter().collect())
            .unwrap_or_default()
    }

    #[test]
    fn presence_returns_every_entry_with_the_attribute() {
        let index =
            Index::build(&directory(), &config(&[("mail", &["pres"])], &[])).expect("index");

        assert_eq!(
            ids(index.candidates(&Query::Presence("mail".into()))),
            vec![0, 1],
            "the group has no mail"
        );
    }

    #[test]
    fn equality_is_case_insensitive_for_ordinary_attributes() {
        let entries = directory();
        let index = Index::build(&entries, &config(&[("cn", &["eq"])], &[])).expect("index");

        assert_eq!(
            ids(index.candidates(&Query::Equality {
                attribute: "cn".into(),
                value: "ann".to_string(),
            })),
            vec![0],
            "cn is folded, so 'ann' finds 'Ann'"
        );
        assert_eq!(
            ids(index.candidates(&Query::Equality {
                attribute: "cn".into(),
                value: "ANN".to_string(),
            })),
            vec![0]
        );
    }

    #[test]
    fn equality_on_a_case_sensitive_attribute_is_exact() {
        // The flag is what the index reads; the mapping sets it for passwords.
        let mut attributes = Attributes::new();
        attributes = attributes
            .push(Attribute::new("userPassword", vec!["{SSHA}AbC".to_string()]).case_sensitive());
        let entries = vec![Entry::new("cn=x,dc=example,dc=com", attributes)];
        let index =
            Index::build(&entries, &config(&[("userPassword", &["eq"])], &[])).expect("index");

        assert_eq!(
            ids(index.candidates(&Query::Equality {
                attribute: "userPassword".into(),
                value: "{SSHA}AbC".to_string(),
            })),
            vec![0]
        );
        assert!(
            ids(index.candidates(&Query::Equality {
                attribute: "userPassword".into(),
                value: "{ssha}abc".to_string(),
            }))
            .is_empty(),
            "a case-sensitive attribute must not match a folded value"
        );
        // Note on the failure mode: if a value were indexed folded while the filter
        // compares exactly, the index would still only add candidates - a superset -
        // so the answer stays correct and just costs more. That is the invariant
        // the equivalence test below relies on.
    }

    #[test]
    fn an_indexed_attribute_without_the_value_answers_empty_not_unknown() {
        let index = Index::build(&directory(), &config(&[("cn", &["eq"])], &[])).expect("index");

        let candidates = index.candidates(&Query::Equality {
            attribute: "cn".into(),
            value: "nobody".to_string(),
        });

        assert_eq!(ids(candidates.clone()), Vec::<u32>::new());
        assert!(
            candidates.is_some(),
            "a known attribute with an unknown value is an empty answer"
        );
    }

    #[test]
    fn an_unindexed_attribute_never_narrows() {
        let index = Index::build(&directory(), &config(&[("cn", &["eq"])], &[])).expect("index");

        assert_eq!(
            index.candidates(&Query::Equality {
                attribute: "telephoneNumber".into(),
                value: "1".to_string(),
            }),
            None
        );
    }

    // ---- the snapshot a start reads instead of building ----

    #[test]
    fn a_snapshot_answers_exactly_what_the_index_it_came_from_answers() {
        // The whole claim of the feature: a reused index is the same index. Checked by running
        // the same queries through both and comparing the answers, not by comparing bytes - the
        // bytes are an implementation detail, the answers are what a client sees.
        let entries = people(60);
        let config = config(&[("cn", &["eq", "pres", "sub"]), ("uid", &["eq"])], &[]);
        let index = Index::build(&entries, &config).expect("build");
        let fingerprint = data_fingerprint(&entries, &config);

        let decoded = Index::decode(
            &index.encode(fingerprint, &numbering_of(&entries), entries.len() as u32),
            fingerprint,
        )
        .expect("a snapshot of this data is readable");

        for query in [
            Query::Presence("cn".into()),
            Query::Equality {
                attribute: "uid".into(),
                value: "user7".into(),
            },
            Query::Substring {
                attribute: "cn".into(),
                initial: None,
                any: vec!["erson1".to_string()],
                final_part: None,
            },
            Query::And(vec![
                Query::Presence("cn".into()),
                Query::Equality {
                    attribute: "uid".into(),
                    value: "user9".into(),
                },
            ]),
        ] {
            assert_eq!(
                index.candidates(&query),
                decoded.candidates(&query),
                "the snapshot answers {query:?} the same way"
            );
        }
    }

    #[test]
    fn a_snapshot_of_other_data_is_refused() {
        // The one failure this must not have: answering from an index built over other data
        // narrows to a value that is no longer there, and the client sees a missing entry with
        // nothing to explain it. The fingerprint is the guard, so a changed `entryCSN` - which is
        // what a modify produces - has to make it fail.
        let entries = people(10);
        let config = config(&[("cn", &["eq"])], &[]);
        let index = Index::build(&entries, &config).expect("build");

        let built_for = data_fingerprint(&entries, &config);
        let bytes = index.encode(built_for, &numbering_of(&entries), entries.len() as u32);

        let mut changed = entries.clone();
        let mut attributes = changed[3].attributes().clone();
        attributes = attributes.replace(crate::model::Attribute::single(
            "entryCSN",
            "20260101000000.000000Z#000001#001#000000",
        ));
        changed[3] = crate::model::Entry::new(changed[3].dn(), attributes);
        let now = data_fingerprint(&changed, &config);

        assert_ne!(built_for, now, "a modify has to move the fingerprint");
        assert!(
            Index::decode(&bytes, now).is_none(),
            "a snapshot built before the change is not reused"
        );
    }

    #[test]
    fn a_snapshot_is_refused_when_the_index_section_changed() {
        // The data is the same, but the plan is not: a snapshot built with `cn: [eq]` has no
        // trigrams, and serving a `sub` query from it would narrow to nothing.
        let entries = people(10);
        let before = config(&[("cn", &["eq"])], &[]);
        let after = config(&[("cn", &["eq", "sub"])], &[]);
        let index = Index::build(&entries, &before).expect("build");

        let bytes = index.encode(
            data_fingerprint(&entries, &before),
            &numbering_of(&entries),
            entries.len() as u32,
        );

        assert!(
            Index::decode(&bytes, data_fingerprint(&entries, &after)).is_none(),
            "a changed `indexes:` section forces a rebuild"
        );
    }

    #[test]
    fn a_truncated_or_foreign_blob_is_refused_rather_than_misread() {
        let entries = people(5);
        let config = config(&[("cn", &["eq"])], &[]);
        let index = Index::build(&entries, &config).expect("build");
        let fingerprint = data_fingerprint(&entries, &config);
        let bytes = index.encode(fingerprint, &numbering_of(&entries), entries.len() as u32);

        assert!(Index::decode(&bytes[..bytes.len() / 2], fingerprint).is_none());

        let mut foreign = bytes.clone();
        foreign[0] = b'X';
        assert!(Index::decode(&foreign, fingerprint).is_none());

        let mut future = bytes.clone();
        future[4] = 99;
        assert!(
            Index::decode(&future, fingerprint).is_none(),
            "a version from another build is not guessed at"
        );
    }

    #[test]
    fn and_intersects_the_indexable_parts() {
        let index = Index::build(
            &directory(),
            &config(&[("cn", &["eq"]), ("mail", &["pres"])], &[]),
        )
        .expect("index");

        let query = Query::And(vec![
            Query::Presence("mail".into()),
            Query::Equality {
                attribute: "cn".into(),
                value: "bob".to_string(),
            },
        ]);

        assert_eq!(ids(index.candidates(&query)), vec![1]);
    }

    #[test]
    fn and_still_narrows_when_only_one_part_is_indexed() {
        let index = Index::build(&directory(), &config(&[("cn", &["eq"])], &[])).expect("index");

        let query = Query::And(vec![
            Query::Unindexed,
            Query::Equality {
                attribute: "cn".into(),
                value: "ann".to_string(),
            },
        ]);

        assert_eq!(
            ids(index.candidates(&query)),
            vec![0],
            "the indexable part is still a superset of the answer"
        );
    }

    #[test]
    fn or_unions_only_when_every_part_is_indexed() {
        let index = Index::build(&directory(), &config(&[("cn", &["eq"])], &[])).expect("index");

        let fully_indexed = Query::Or(vec![
            Query::Equality {
                attribute: "cn".into(),
                value: "ann".to_string(),
            },
            Query::Equality {
                attribute: "cn".into(),
                value: "bob".to_string(),
            },
        ]);
        assert_eq!(ids(index.candidates(&fully_indexed)), vec![0, 1]);

        let partly_indexed = Query::Or(vec![
            Query::Equality {
                attribute: "cn".into(),
                value: "ann".to_string(),
            },
            Query::Unindexed,
        ]);
        assert_eq!(
            index.candidates(&partly_indexed),
            None,
            "an unindexed branch could hold answers, so no narrowing is safe"
        );
    }

    #[test]
    fn not_never_narrows() {
        let index = Index::build(&directory(), &config(&[("cn", &["eq"])], &[])).expect("index");

        assert_eq!(
            index.candidates(&Query::Not(Box::new(Query::Equality {
                attribute: "cn".into(),
                value: "ann".to_string(),
            }))),
            None
        );
    }

    #[test]
    fn the_default_applies_to_attributes_nobody_configured() {
        let index = Index::build(&directory(), &config(&[], &["pres"])).expect("index");

        assert!(
            index
                .candidates(&Query::Presence("memberUid".into()))
                .is_some()
        );
    }

    #[test]
    fn an_attribute_configured_without_kinds_falls_back_to_the_default() {
        let index = Index::build(&directory(), &config(&[("cn", &[])], &["pres"])).expect("index");

        assert!(
            index.candidates(&Query::Presence("cn".into())).is_some(),
            "the empty list means 'nothing special', so the default still applies"
        );
    }

    #[test]
    fn an_unknown_kind_is_rejected_with_its_name() {
        // `substring` is what someone writes for `sub`, and saying so is the point of the
        // error: the configuration is read at startup, so the operator hears about the typo
        // before the server takes a request.
        let error = Index::build(&directory(), &config(&[("cn", &["substring"])], &[]))
            .expect_err("must reject");

        assert_eq!(error, IndexError::UnknownKind("substring".to_string()));
    }

    #[test]
    fn size_is_reported_and_grows_with_the_data() {
        let small =
            Index::build(&directory(), &config(&[("cn", &["eq", "pres"])], &[])).expect("index");
        let mut many = Vec::new();
        for position in 0..500 {
            many.push(entry(
                "cn=x,dc=example,dc=com",
                &[("cn", &["x"]), ("mail", &["m@example.com"])],
            ));
            let _ = position;
        }
        let large = Index::build(&many, &config(&[("cn", &["eq", "pres"])], &[])).expect("index");

        assert!(small.size_bytes() > 0);
        assert!(
            large.size_bytes() > small.size_bytes(),
            "a bigger directory must report a bigger index"
        );
    }

    #[test]
    fn an_empty_configuration_builds_nothing() {
        let index = Index::build(&directory(), &IndexConfig::default()).expect("index");

        assert!(index.is_empty());
        assert!(index.built_attributes().next().is_none());
    }

    // -----------------------------------------------------------------------------------
    // Substring and range indexes.
    // -----------------------------------------------------------------------------------

    #[test]
    fn a_pattern_with_no_trigram_stands_aside_rather_than_answering() {
        // `(cn=*n*)` is one character: no window to look up. Answering with an empty set
        // would say "nothing matches", which is a lie - "Ann" matches.
        let entries = vec![entry("cn=a,dc=example,dc=com", &[("cn", &["Ann"])])];
        let index = Index::build(&entries, &config(&[("cn", &["sub"])], &[])).expect("index");

        assert_eq!(
            index.candidates(&any_substring("cn", "n")),
            None,
            "one character cannot narrow, and standing aside is the honest answer"
        );
    }

    #[test]
    fn a_substring_query_is_folded_like_the_value_it_searches() {
        // The stored value is "Ann"; a search typed as `(cn=*Ann*)` has to find it. Building
        // the query trigrams without folding produced "^An"/"Ann", the index held
        // "^an"/"ann", the lookup missed and the answer came back empty - a false negative,
        // and invisible to any fixture whose values were already lowercase.
        let entries = vec![
            entry("cn=a,dc=example,dc=com", &[("cn", &["Ann"])]),
            entry("cn=b,dc=example,dc=com", &[("cn", &["Bob"])]),
        ];
        let index = Index::build(&entries, &config(&[("cn", &["sub"])], &[])).expect("index");

        // Three characters and up: a trigram exists, so the index must answer with Ann.
        for part in ["Ann", "ann", "ANN"] {
            let candidates = index.candidates(&Query::Substring {
                attribute: "cn".into(),
                initial: None,
                any: vec![part.to_string()],
                final_part: None,
            });

            let bitmap = candidates.expect("a trigram exists, so the index must answer");
            assert!(
                bitmap.contains(0),
                "'{part}' must find 'Ann', got {:?}",
                bitmap.iter().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_substring_query_narrows_to_the_entries_that_can_match() {
        let entries = directory();
        let index = Index::build(&entries, &config(&[("mail", &["sub"])], &[])).expect("index");

        // `*example*` is in both addresses, and also in the group's memberUid? No: memberUid
        // holds "ann" and "bob", so only the two users carry the trigram.
        assert_eq!(
            ids(index.candidates(&any_substring("mail", "example"))),
            vec![0, 1],
            "both mail values contain 'example'"
        );

        assert_eq!(
            ids(index.candidates(&any_substring("mail", "ann"))),
            vec![0],
            "only Ann's address contains 'ann'"
        );
    }

    #[test]
    fn an_anchored_substring_uses_the_boundary_and_not_only_the_interior() {
        // `ann*` is an initial fragment: it can only match a value that *starts* with it.
        // Without boundary trigrams the index would answer with every entry holding "ann"
        // anywhere, which is still a superset - correct but useless - so this checks the
        // selectivity, not the correctness.
        let entries = directory();
        let index = Index::build(&entries, &config(&[("mail", &["sub"])], &[])).expect("index");

        let initial = ids(index.candidates(&Query::Substring {
            attribute: "mail".into(),
            initial: Some("ann".to_string()),
            any: Vec::new(),
            final_part: None,
        }));
        assert_eq!(initial, vec![0]);

        // `example` is in both addresses and at neither start: as an interior part it finds
        // two entries, as an initial one it finds none. That difference *is* the boundary
        // trigrams; without them both queries would answer the same.
        assert_eq!(
            ids(index.candidates(&any_substring("mail", "example"))),
            vec![0, 1]
        );
        assert!(
            ids(index.candidates(&Query::Substring {
                attribute: "mail".into(),
                initial: Some("example".to_string()),
                any: Vec::new(),
                final_part: None,
            }))
            .is_empty(),
            "no address starts with 'example'"
        );
    }

    #[test]
    fn a_pattern_too_short_to_make_a_trigram_narrows_nothing() {
        // Two characters cannot form a trigram. Answering with an empty bitmap would be
        // wrong - `(cn=a*)` matches "Ann" - so the index has to stand aside.
        let entries = directory();
        let index = Index::build(&entries, &config(&[("cn", &["sub"])], &[])).expect("index");

        assert_eq!(
            index.candidates(&any_substring("cn", "an")),
            None,
            "no trigram, no narrowing"
        );
    }

    #[test]
    fn a_substring_on_an_unindexed_attribute_narrows_nothing() {
        let index = Index::build(&directory(), &config(&[("cn", &["sub"])], &[])).expect("index");

        assert_eq!(index.candidates(&any_substring("mail", "example")), None);
    }

    #[test]
    fn a_trigram_the_index_never_saw_is_an_empty_answer() {
        // The attribute *is* indexed, so a value nobody has cannot match: this is a real
        // empty result, not "the index cannot tell".
        let entries = directory();
        let index = Index::build(&entries, &config(&[("mail", &["sub"])], &[])).expect("index");

        assert_eq!(
            ids(index.candidates(&any_substring("mail", "zzzz"))),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn substrings_are_folded_like_equality_is() {
        let entries = directory();
        let index = Index::build(&entries, &config(&[("cn", &["sub"])], &[])).expect("index");

        // The stored value is "Ann"; the filter comes from a person typing in lowercase.
        assert_eq!(ids(index.candidates(&any_substring("cn", "ann"))), vec![0]);
    }

    #[test]
    fn a_range_query_narrows_to_the_entries_on_that_side() {
        let entries = vec![
            entry("cn=a,dc=example,dc=com", &[("uidNumber", &["100"])]),
            entry("cn=b,dc=example,dc=com", &[("uidNumber", &["200"])]),
            entry("cn=c,dc=example,dc=com", &[("uidNumber", &["300"])]),
        ];
        let index =
            Index::build(&entries, &config(&[("uidNumber", &["ord"])], &[])).expect("index");

        assert_eq!(
            ids(index.candidates(&Query::Range {
                attribute: "uidNumber".into(),
                bound: RangeBound::AtLeast,
                value: "200".to_string(),
            })),
            vec![1, 2],
            "`>= 200` includes the bound itself"
        );

        assert_eq!(
            ids(index.candidates(&Query::Range {
                attribute: "uidNumber".into(),
                bound: RangeBound::AtMost,
                value: "200".to_string(),
            })),
            vec![0, 1],
            "`<= 200` includes the bound itself"
        );
    }

    #[test]
    fn a_numeric_range_orders_by_value_and_not_by_text() {
        // The failure this guards: as text, "10" sorts before "9", so `(n>=9)` would leave
        // out 10 and 100 - entries the filter matches. A false negative is the one answer an
        // index must never give, and it is invisible unless the values differ in width.
        let entries = vec![
            entry("cn=one,dc=example,dc=com", &[("uidNumber", &["9"])]),
            entry("cn=two,dc=example,dc=com", &[("uidNumber", &["10"])]),
            entry("cn=three,dc=example,dc=com", &[("uidNumber", &["100"])]),
        ];
        let index =
            Index::build(&entries, &config(&[("uidNumber", &["ord"])], &[])).expect("index");

        assert_eq!(
            ids(index.candidates(&Query::Range {
                attribute: "uidNumber".into(),
                bound: RangeBound::AtLeast,
                value: "9".to_string(),
            })),
            vec![0, 1, 2],
            "all three are at least 9, including the wider numbers"
        );

        assert_eq!(
            ids(index.candidates(&Query::Range {
                attribute: "uidNumber".into(),
                bound: RangeBound::AtMost,
                value: "10".to_string(),
            })),
            vec![0, 1],
            "9 and 10 are at most 10; 100 is not"
        );
    }

    #[test]
    fn a_mixed_attribute_stands_aside_rather_than_guessing() {
        // One attribute holding both numbers and words has no single order that matches the
        // filter, so the index must not answer at all: the scan decides.
        let entries = vec![
            entry("cn=a,dc=example,dc=com", &[("roomNumber", &["10"])]),
            entry("cn=b,dc=example,dc=com", &[("roomNumber", &["lab"])]),
        ];
        let index =
            Index::build(&entries, &config(&[("roomNumber", &["ord"])], &[])).expect("index");

        assert_eq!(
            index.candidates(&Query::Range {
                attribute: "roomNumber".into(),
                bound: RangeBound::AtLeast,
                value: "9".to_string(),
            }),
            None
        );
    }

    #[test]
    fn a_range_beyond_the_data_is_empty_rather_than_unknown() {
        let entries = vec![entry("cn=a,dc=example,dc=com", &[("uidNumber", &["100"])])];
        let index =
            Index::build(&entries, &config(&[("uidNumber", &["ord"])], &[])).expect("index");

        assert_eq!(
            ids(index.candidates(&Query::Range {
                attribute: "uidNumber".into(),
                bound: RangeBound::AtLeast,
                value: "900".to_string(),
            })),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn a_range_on_an_unindexed_attribute_narrows_nothing() {
        let index = Index::build(&directory(), &config(&[("mail", &["ord"])], &[])).expect("index");

        assert_eq!(
            index.candidates(&Query::Range {
                attribute: "uidNumber".into(),
                bound: RangeBound::AtLeast,
                value: "1".to_string(),
            }),
            None
        );
    }

    #[test]
    fn every_attribute_with_several_values_is_in_each_of_its_buckets() {
        // `memberUid` holds two values; a search for either has to find the group.
        let entries = directory();
        let index =
            Index::build(&entries, &config(&[("memberUid", &["eq", "sub"])], &[])).expect("index");

        assert_eq!(
            ids(index.candidates(&any_substring("memberUid", "ann"))),
            vec![2]
        );
        assert_eq!(
            ids(index.candidates(&any_substring("memberUid", "bob"))),
            vec![2]
        );
    }

    #[test]
    fn an_attribute_whose_name_has_capitals_is_indexed_like_any_other() {
        // The filter lowercases every attribute description before asking the index, so the
        // index has to keep its keys lowercase too. Storing `uidNumber` meant the lookup for
        // "uidnumber" missed, the index narrowed nothing, and only a test that asserts the
        // candidate *set* rather than comparing answers could see it.
        let entries = vec![
            entry("cn=a,dc=example,dc=com", &[("uidNumber", &["100"])]),
            entry("cn=b,dc=example,dc=com", &[("uidNumber", &["200"])]),
            entry("cn=c,dc=example,dc=com", &[("uidNumber", &["300"])]),
        ];
        let index =
            Index::build(&entries, &config(&[("uidNumber", &["eq", "ord"])], &[])).expect("index");

        assert_eq!(
            ids(index.candidates(&Query::Equality {
                attribute: "uidnumber".into(),
                value: "200".to_string(),
            })),
            vec![1],
            "a lowercase query has to find a camelCase attribute"
        );

        assert_eq!(
            ids(index.candidates(&Query::Range {
                attribute: "uidnumber".into(),
                bound: RangeBound::AtLeast,
                value: "200".to_string(),
            })),
            vec![1, 2]
        );

        // Both spellings work, because the query side tries the name as written too.
        assert_eq!(
            ids(index.candidates(&Query::Equality {
                attribute: "uidNumber".into(),
                value: "200".to_string(),
            })),
            vec![1]
        );
    }

    #[test]
    fn the_new_kinds_are_named_as_the_configuration_names_them() {
        assert_eq!(Kind::Sub.name(), "sub");
        assert_eq!(Kind::Ord.name(), "ord");

        // And a typo is still a startup error that lists what exists.
        let err = parse_kind("substring").expect_err("must refuse");
        assert!(err.to_string().contains("sub"), "{err}");
    }

    // ---- an in-place replace must equal a rebuild ----
    //
    // This is the safety net for the incremental path: if `replace` and `build` can disagree,
    // the index narrows to the wrong set after a write and a search silently loses an entry.

    #[test]
    fn replacing_a_value_in_place_matches_a_full_rebuild() {
        let config = config(
            &[("cn", &["pres", "eq", "sub", "ord"]), ("mail", &["sub"])],
            &[],
        );
        let entries = directory();
        let mut index = Index::build(&entries, &config).expect("build");

        let old = &entries[0];
        let new = entry(
            "cn=ann,ou=users,dc=example,dc=com",
            &[
                ("objectClass", &["top", "inetOrgPerson"]),
                ("cn", &["Anna"]),
                ("mail", &["anna@example.org"]),
            ],
        );

        index.replace(0, old, &new, &config).expect("replace");

        let mut expected_entries = entries.clone();
        expected_entries[0] = new.clone();
        let expected = Index::build(&expected_entries, &config).expect("build");

        assert_eq!(
            index, expected,
            "an in-place replace must leave the index where a rebuild would"
        );
    }

    #[test]
    fn removing_a_value_in_place_stops_finding_the_entry_by_it() {
        // The equality posting list is the one that decides whether a filter narrows at all: a
        // stale id here answers `(mail=ann@example.com)` with an entry that no longer has it.
        let config = config(&[], &["eq", "pres"]);
        let entries = directory();
        let mut index = Index::build(&entries, &config).expect("build");

        let old = &entries[0];
        let new = entry(
            "cn=ann,ou=users,dc=example,dc=com",
            &[("objectClass", &["top", "inetOrgPerson"]), ("cn", &["Ann"])],
        );
        index.replace(0, old, &new, &config).expect("replace");

        let query = Query::Equality {
            attribute: "mail".into(),
            value: "ann@example.com".to_string(),
        };
        let candidates = index.candidates(&query).expect("the index answers this");
        assert!(
            !candidates.contains(0),
            "the entry no longer holds that mail, so the index must not name it"
        );
    }

    #[test]
    fn an_attribute_that_went_from_numeric_to_text_keeps_the_index_usable() {
        // `ordered_numeric` and `ordered_mixed` only ever grow, so a value that stops being a
        // number must not make a range query answer from the wrong structure. What must hold is
        // that the index still returns the same set a rebuild would.
        let config = config(&[("uidNumber", &["ord"])], &[]);
        let entries = vec![
            entry("cn=a,dc=example,dc=com", &[("uidNumber", &["7"])]),
            entry("cn=b,dc=example,dc=com", &[("uidNumber", &["8"])]),
        ];
        let mut index = Index::build(&entries, &config).expect("build");

        let new = entry("cn=a,dc=example,dc=com", &[("uidNumber", &["seven"])]);
        index
            .replace(0, &entries[0], &new, &config)
            .expect("replace");

        let mut expected_entries = entries.clone();
        expected_entries[0] = new;
        let expected = Index::build(&expected_entries, &config).expect("build");

        assert_eq!(index.ordered, expected.ordered);
        assert_eq!(index.ordered_mixed, expected.ordered_mixed);
        // The one difference allowed: `ordered_numeric` may stay set, because forgetting it
        // would downgrade the entries that are still numeric.
        assert!(index.ordered_numeric.is_superset(&expected.ordered_numeric));
    }
}
