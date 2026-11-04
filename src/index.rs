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
use std::sync::Arc;

use roaring::RoaringBitmap;
use serde::Deserialize;
use thiserror::Error;

use crate::model::Entry;

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
#[serde(default)]
pub struct IndexConfig {
    /// Kinds applied to every attribute, including ones not listed below.
    pub default: Vec<String>,
    /// Per-attribute kinds, replacing the default for that attribute.
    pub attributes: BTreeMap<String, Vec<String>>,
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
}

/// Marks a snapshot written by this format, so a foreign or older blob is refused rather than
/// misread as postings.
const MAGIC: &[u8; 4] = b"RRIX";

/// Bumped whenever the layout below changes. An older blob is not upgraded: the index is derived
/// data and rebuilding it is always correct, while guessing at a layout that changed is not.
const SNAPSHOT_VERSION: u32 = 1;

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

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_text(out: &mut Vec<u8>, text: &str) {
    write_u32(out, text.len() as u32);
    out.extend_from_slice(text.as_bytes());
}

fn write_names<'a, I>(out: &mut Vec<u8>, names: I)
where
    I: IntoIterator<Item = &'a Arc<str>>,
{
    let names: Vec<&Arc<str>> = names.into_iter().collect();
    write_u32(out, names.len() as u32);
    for name in names {
        write_text(out, name);
    }
}

fn write_bitmap(out: &mut Vec<u8>, bitmap: &RoaringBitmap) {
    write_u32(out, bitmap.len() as u32);
    for id in bitmap {
        write_u32(out, id);
    }
}

fn write_bitmaps(out: &mut Vec<u8>, map: &HashMap<Arc<str>, RoaringBitmap>) {
    write_u32(out, map.len() as u32);
    for (name, bitmap) in map {
        write_text(out, name);
        write_bitmap(out, bitmap);
    }
}

fn write_nested<F>(
    out: &mut Vec<u8>,
    map: &HashMap<Arc<str>, HashMap<String, RoaringBitmap>>,
    key: F,
) where
    F: Fn(&mut Vec<u8>, &str),
{
    write_u32(out, map.len() as u32);
    for (name, values) in map {
        write_text(out, name);
        write_u32(out, values.len() as u32);
        for (value, bitmap) in values {
            key(out, value);
            write_bitmap(out, bitmap);
        }
    }
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
        };

        for (position, entry) in entries.iter().enumerate() {
            let id = ids.get(position).copied().unwrap_or(position as u32);
            index.touch(id, entry, &per_attribute, Touch::Add);
        }

        Ok(index)
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
    pub fn encode(&self, fingerprint: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        out.extend_from_slice(&fingerprint.to_le_bytes());
        out.extend_from_slice(&kinds_bits(&self.default_kinds).to_le_bytes());

        write_names(&mut out, &self.case_sensitive);
        write_names(&mut out, &self.ordered_numeric);
        write_names(&mut out, &self.ordered_mixed);

        write_names(&mut out, self.built.keys());

        write_bitmaps(&mut out, &self.presence);

        // The three two-level maps differ only in how a key is spelled, so one pair of helpers
        // writes and reads all of them.
        write_nested(&mut out, &self.equality, |out, value| {
            write_text(out, value)
        });
        write_nested(&mut out, &self.substrings, |out, value| {
            write_text(out, value)
        });

        out.extend_from_slice(&(self.ordered.len() as u32).to_le_bytes());
        for (attribute, values) in &self.ordered {
            write_text(&mut out, attribute);
            out.extend_from_slice(&(values.len() as u32).to_le_bytes());
            for (key, bitmap) in values {
                match key {
                    OrderKey::Num(number) => {
                        out.push(0);
                        out.extend_from_slice(&number.to_le_bytes());
                    }
                    OrderKey::Text(text) => {
                        out.push(1);
                        write_text(&mut out, text);
                    }
                }
                write_bitmap(&mut out, bitmap);
            }
        }

        out
    }

    /// Reads a snapshot, or reports that it cannot be trusted.
    ///
    /// Every reason to distrust the bytes answers `None` and the caller builds the index instead:
    /// a wrong magic, a version from another build, a fingerprint that no longer matches the
    /// data, or a truncated blob. Rebuilding costs a minute; answering from a snapshot that does
    /// not match the data costs a missing search result that nobody can explain.
    pub fn decode(bytes: &[u8], fingerprint: u64) -> Option<Self> {
        let mut reader = Reader::new(bytes);

        if reader.take(MAGIC.len())? != MAGIC {
            return None;
        }
        if reader.u32()? != SNAPSHOT_VERSION {
            return None;
        }
        if reader.u64()? != fingerprint {
            return None;
        }

        let default_kinds = bits_kinds(reader.u32()?)?;

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
        };
        index.fill_built();
        Some(index)
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
    pub fn replace(
        &mut self,
        id: u32,
        old: &Entry,
        new: &Entry,
        config: &IndexConfig,
    ) -> Result<(), IndexError> {
        let plan = config.resolve()?;
        let per_attribute: BTreeMap<String, BTreeSet<Kind>> = plan
            .into_iter()
            .filter(|(attribute, _)| !attribute.is_empty())
            .collect();

        self.touch(id, old, &per_attribute, Touch::Remove);
        self.touch(id, new, &per_attribute, Touch::Add);

        // A posting list that lost its last id is removed rather than left empty: a server that
        // is written to for months would otherwise keep one empty bitmap per value it has ever
        // seen, and the memory would grow with the history instead of with the data.
        for attribute in old.attributes().values() {
            let name: Arc<str> = crate::model::attribute_name(&attribute.name.to_lowercase());
            self.prune(&name);
        }

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

    /// Candidate ids for `query`, or `None` when the index cannot narrow it.
    pub fn candidates(&self, query: &Query) -> Option<RoaringBitmap> {
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
        }
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

        let decoded = Index::decode(&index.encode(fingerprint), fingerprint)
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
        let bytes = index.encode(built_for);

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

        let bytes = index.encode(data_fingerprint(&entries, &before));

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
        let bytes = index.encode(fingerprint);

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
