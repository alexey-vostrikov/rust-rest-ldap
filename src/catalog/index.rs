//! Paged postings: the index, in the same transaction as the records.
//!
//! The index this replaces kept its postings in memory as `RoaringBitmap` per key, and the cost of
//! that is what `docs/storage.md` says it is: on nine million entries one posting is 1.1 MB, and a
//! write that changes one entry rewrites the pages the whole bitmap lives on. Here a posting is cut
//! into pages of [`PAGE`] ids, each page a bitmap of at most eight kilobytes, and a write touches
//! the one or two pages its ids fall on.
//!
//! # The three tables
//!
//! ```text
//! idx_eq      (attribute, value, page)     -> bitmap of ids inside that page
//! idx_pres    (attribute, page)            -> bitmap of ids inside that page
//! idx_sub     (attribute, trigram, page)   -> bitmap of ids inside that page
//! ```
//!
//! A page holds **offsets** rather than absolute ids: bit `n` of page `p` is id `p * PAGE + n`. That
//! keeps a page's meaning the same wherever it sits, so creating one is an insert and emptying one
//! is a delete, with no arithmetic in the key.
//!
//! # Why the page is deleted when it empties
//!
//! A bitmap that becomes empty is removed rather than stored as a zero. Left behind, every deleted
//! entry would leave a key naming a page that holds nothing, and a directory that is written to for
//! years would carry a shadow index of everything it ever held - which is exactly the growth the
//! old arrangement's deltas and overlay were invented to work around.
//!
//! # What is indexed, and how a value is folded
//!
//! The plan says which kinds apply to which attribute; an attribute nobody configured gets the
//! default kinds, the same rule the old index followed, so the two can be compared on the same data.
//!
//! Values are **case-folded** unless the attribute is marked case-sensitive, and the mark is
//! learned from the entries as they are written and kept in `meta` under `cs:<attribute>`. It is
//! kept there rather than in memory because a restart would otherwise forget it and answer a
//! case-insensitive match on a case-sensitive attribute - a wrong answer, not a slow one.
use redb::{ReadableTable, TableDefinition, WriteTransaction};
use roaring::{RoaringBitmap, RoaringTreemap};
use std::collections::{BTreeMap, BTreeSet};

use crate::index::{IndexConfig, IndexError, Kind};
use crate::model::Entry;
use crate::prepare::{self, Position, Rule};

use super::store::StoreError;

/// Ids per page: 65 536, which is eight kilobytes of bitmap when the page is full.
///
/// Smaller pages make a write cheaper and a range read dearer; larger ones the reverse. Eight
/// kilobytes is the size at which a single write's page rewrite is still smaller than the record it
/// accompanies, and it is the size `docs/storage.md` fixed for the first measurement.
pub const PAGE: u64 = 65_536;

/// Equality postings: attribute, folded value, page.
pub const IDX_EQ: TableDefinition<(&str, &str, u32), &[u8]> = TableDefinition::new("idx_eq");
/// Presence postings: attribute, page.
pub const IDX_PRES: TableDefinition<(&str, u32), &[u8]> = TableDefinition::new("idx_pres");
/// Trigram postings: attribute, trigram, page.
pub const IDX_SUB: TableDefinition<(&str, &str, u32), &[u8]> = TableDefinition::new("idx_sub");

/// The page an id falls on.
pub fn page_of(id: u64) -> u32 {
    (id / PAGE) as u32
}

/// The bit an id occupies inside its page.
fn bit_of(id: u64) -> u32 {
    (id % PAGE) as u32
}

/// The matching rule an attribute's flag implies.
pub fn rule_of(case_sensitive: bool) -> Rule {
    if case_sensitive {
        Rule::CaseExact
    } else {
        Rule::CaseIgnore
    }
}

/// Prepares a value for comparison: RFC 4518, not `to_lowercase`.
///
/// The difference is an answer and not a speed: `й` written as one code point and as two compare
/// equal here and unequal under a plain lowercase, and `Straße` matches `STRASSE`.
pub fn fold(value: &str, case_sensitive: bool) -> Result<String, StoreError> {
    prepare::prepare(value, rule_of(case_sensitive))
        .map_err(|refused| StoreError::Record(format!("{refused}: {value:.40}")))
}

/// The three-character windows of a string.
///
/// By characters rather than bytes: a window cut through a multibyte character is not a window
/// anything can be looked up by, and a value that is not ASCII would silently index nothing.
pub fn trigrams(text: &str) -> Vec<String> {
    let characters: Vec<char> = text.chars().collect();
    characters
        .windows(3)
        .map(|window| window.iter().collect())
        .collect()
}

/// The trigrams a substring pattern implies.
///
/// The value was indexed between `^` and `$`, so an anchored part looks up the windows that include
/// the boundary and an interior part the windows of itself. A pattern whose parts are all shorter
/// than three characters yields nothing, and the caller has to scan - there is no window to ask for.
pub fn pattern_trigrams(
    initial: Option<&str>,
    any: &[String],
    final_part: Option<&str>,
    case_sensitive: bool,
) -> Result<Vec<String>, StoreError> {
    let rule = rule_of(case_sensitive);
    let prepare_part = |part: &str, position: Position| {
        prepare::prepare_part(part, rule, position)
            .map_err(|refused| StoreError::Record(refused.to_string()))
    };

    let mut wanted = Vec::new();
    if let Some(initial) = initial {
        wanted.extend(trigrams(&format!(
            "^{}",
            prepare_part(initial, Position::Initial)?
        )));
    }
    for part in any {
        wanted.extend(trigrams(&prepare_part(part, Position::Any)?));
    }
    if let Some(final_part) = final_part {
        wanted.extend(trigrams(&format!(
            "{}$",
            prepare_part(final_part, Position::Final)?
        )));
    }
    // A part shorter than three characters yields no window: there is nothing to look up, and the
    // caller has to scan. An empty list therefore means "no narrowing", never "nothing matches".
    wanted.sort();
    wanted.dedup();
    Ok(wanted)
}

/// Which kinds of index apply to which attribute.
///
/// Mirrors `IndexConfig::resolve`, so a configuration means the same thing in both models and the
/// equivalence test compares like with like.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    kinds: BTreeMap<String, BTreeSet<Kind>>,
}

impl Plan {
    /// A plan that indexes nothing: every query has to scan, which is what an unconfigured
    /// directory does today.
    pub fn empty() -> Self {
        Self::default()
    }

    /// A plan from a configuration.
    pub fn from_config(config: &IndexConfig) -> Result<Self, IndexError> {
        let kinds = config.resolve()?;
        let mut plan = Self::default();
        for (attribute, set) in kinds {
            plan.kinds.insert(attribute, set);
        }
        Ok(plan)
    }

    /// A plan indexing one kind on some attributes - the shape most tests want.
    pub fn of(attributes: impl IntoIterator<Item = (String, Vec<Kind>)>) -> Self {
        let mut plan = Self::default();
        for (attribute, kinds) in attributes {
            plan.kinds
                .insert(attribute.to_lowercase(), kinds.into_iter().collect());
        }
        plan
    }

    /// The kinds for an attribute, falling back to the default entry (the empty name).
    pub fn kinds(&self, attribute: &str) -> BTreeSet<Kind> {
        self.kinds
            .get(attribute)
            .or_else(|| self.kinds.get(""))
            .cloned()
            .unwrap_or_default()
    }

    pub fn has(&self, attribute: &str, kind: Kind) -> bool {
        self.kinds(attribute).contains(&kind)
    }

    pub fn is_empty(&self) -> bool {
        self.kinds.values().all(BTreeSet::is_empty)
    }

    /// Every attribute the plan names, for a report.
    pub fn attributes(&self) -> impl Iterator<Item = &str> {
        self.kinds.keys().map(String::as_str)
    }
}

/// The three posting tables plus `meta`, opened once per transaction.
///
/// Opened as a group because a batch of a million entries would otherwise open three tables a
/// million times, and because the learned case-sensitivity lives in `meta` beside them.
pub(crate) struct Postings<'db> {
    eq: redb::Table<'db, (&'static str, &'static str, u32), &'static [u8]>,
    pres: redb::Table<'db, (&'static str, u32), &'static [u8]>,
    sub: redb::Table<'db, (&'static str, &'static str, u32), &'static [u8]>,
}

fn database(source: impl ToString) -> StoreError {
    StoreError::Database(source.to_string())
}

impl<'db> Postings<'db> {
    /// Opens the tables inside a write transaction.
    pub(crate) fn open(write: &'db WriteTransaction) -> Result<Self, StoreError> {
        Ok(Self {
            eq: write.open_table(IDX_EQ).map_err(database)?,
            pres: write.open_table(IDX_PRES).map_err(database)?,
            sub: write.open_table(IDX_SUB).map_err(database)?,
        })
    }

    /// Writes an entry's postings.
    pub(crate) fn add(
        &mut self,
        plan: &Plan,
        entry: &Entry,
        id: u64,
        meta: &mut redb::Table<'_, &'static str, u64>,
    ) -> Result<(), StoreError> {
        self.post(plan, entry, id, meta, true)
    }

    /// Removes an entry's postings, which are the ones its record still names.
    ///
    /// Taking the record rather than a list of keys is what makes a removal exact: the entry being
    /// replaced is read out of the store before it is overwritten, so the postings removed are the
    /// ones that were actually written, not the ones a config says should have been.
    pub(crate) fn remove(
        &mut self,
        plan: &Plan,
        entry: &Entry,
        id: u64,
        meta: &mut redb::Table<'_, &'static str, u64>,
    ) -> Result<(), StoreError> {
        self.post(plan, entry, id, meta, false)
    }

    fn post(
        &mut self,
        plan: &Plan,
        entry: &Entry,
        id: u64,
        meta: &mut redb::Table<'_, &'static str, u64>,
        present: bool,
    ) -> Result<(), StoreError> {
        let page = page_of(id);
        let bit = bit_of(id);

        for attribute in entry.attributes().values() {
            let name = attribute.name.to_lowercase();
            let kinds = plan.kinds(&name);
            if kinds.is_empty() {
                continue;
            }

            let case_sensitive = attribute.flags.case_sensitive;
            if case_sensitive {
                learn_case_sensitive(meta, &name)?;
            }

            if kinds.contains(&Kind::Pres) {
                self.touch_pres(&name, page, bit, present)?;
            }

            if kinds.contains(&Kind::Eq) {
                for value in attribute.values.iter() {
                    let folded = fold(value, case_sensitive)?;
                    Self::touch(&mut self.eq, &name, &folded, page, bit, present)?;
                }
            }

            if kinds.contains(&Kind::Sub) {
                for value in attribute.values.iter() {
                    let prepared = prepare::prepare(value, rule_of(case_sensitive))
                        .map_err(|refused| StoreError::Record(refused.to_string()))?;
                    let padded = format!("^{prepared}$");
                    for trigram in trigrams(&padded) {
                        Self::touch(&mut self.sub, &name, &trigram, page, bit, present)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn touch_pres(
        &mut self,
        attribute: &str,
        page: u32,
        bit: u32,
        present: bool,
    ) -> Result<(), StoreError> {
        let key = (attribute, page);
        let mut bitmap = match self.pres.get(key).map_err(database)? {
            Some(value) => decode(value.value())?,
            None => RoaringBitmap::new(),
        };
        if present {
            bitmap.insert(bit);
        } else if !bitmap.remove(bit) {
            // Removing a bit that is not there: the postings and the records disagree, and going on
            // would leave the disagreement in place for the next reader to find.
            return Err(StoreError::Record(format!(
                "the index of {attribute} has no page {page} bit {bit} to remove"
            )));
        }

        if bitmap.is_empty() {
            self.pres.remove(key).map_err(database)?;
        } else {
            self.pres
                .insert(key, encode(&bitmap).as_slice())
                .map_err(database)?;
        }
        Ok(())
    }

    fn touch(
        table: &mut redb::Table<'_, (&'static str, &'static str, u32), &'static [u8]>,
        attribute: &str,
        value: &str,
        page: u32,
        bit: u32,
        present: bool,
    ) -> Result<(), StoreError> {
        let key = (attribute, value, page);
        let mut bitmap = match table.get(key).map_err(database)? {
            Some(found) => decode(found.value())?,
            None => RoaringBitmap::new(),
        };
        if present {
            bitmap.insert(bit);
        } else if !bitmap.remove(bit) {
            return Err(StoreError::Record(format!(
                "the index of {attribute}={value} has no page {page} bit {bit} to remove"
            )));
        }

        if bitmap.is_empty() {
            table.remove(key).map_err(database)?;
        } else {
            table
                .insert(key, encode(&bitmap).as_slice())
                .map_err(database)?;
        }
        Ok(())
    }
}

/// Records that an attribute's values must be matched exactly.
///
/// Idempotent, and written on every such entry rather than once at start: a store restored from a
/// backup of records alone must learn it again, and a marking that lived only in memory would make
/// the first query after a restart answer a case-insensitive match on a case-sensitive attribute.
fn learn_case_sensitive(
    meta: &mut redb::Table<'_, &'static str, u64>,
    attribute: &str,
) -> Result<(), StoreError> {
    let key = format!("cs:{attribute}");
    if meta.get(key.as_str()).map_err(database)?.is_some() {
        return Ok(());
    }
    meta.insert(key.as_str(), 1u64).map_err(database)?;
    Ok(())
}

fn encode(bitmap: &RoaringBitmap) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(bitmap.serialized_size());
    // Writing into a `Vec` cannot fail: the only error `serialize_into` reports is from the writer.
    let _ = bitmap.serialize_into(&mut bytes);
    bytes
}

fn decode(bytes: &[u8]) -> Result<RoaringBitmap, StoreError> {
    RoaringBitmap::deserialize_from(bytes)
        .map_err(|error| StoreError::Record(format!("a posting page could not be read: {error}")))
}

/// Whether an attribute's values are matched exactly, as learned when they were written.
pub fn is_case_sensitive(
    meta: &redb::Table<'_, &'static str, u64>,
    attribute: &str,
) -> Result<bool, StoreError> {
    let key = format!("cs:{attribute}");
    Ok(meta.get(key.as_str()).map_err(database)?.is_some())
}

/// The ids a page bitmap names, shifted to where the page sits.
/// Moves a page's offsets into the absolute id space.
///
/// Two types, because they answer two different questions. On disk a page holds offsets, which fit
/// in `u32` by construction (`RoaringBitmap`). What a query accumulates is ids, and those are `u64`
/// - a posting must still be right past four billion entries, and `RoaringBitmap` cannot hold one.
fn collect_into(found: &mut RoaringTreemap, bitmap: &RoaringBitmap, page: u32) {
    let base = u64::from(page) * PAGE;
    for offset in bitmap.iter() {
        found.insert(base + u64::from(offset));
    }
}

/// Reads every page of an equality posting.
pub fn read_eq(
    read: &redb::ReadTransaction,
    attribute: &str,
    value: &str,
) -> Result<RoaringTreemap, StoreError> {
    // Attribute descriptions are case-insensitive (RFC 4512), and the postings key them folded. A
    // caller that passed `objectClass` would otherwise search a table that spells it `objectclass`.
    let folded_name = attribute.to_lowercase();
    let attribute: &str = folded_name.as_str();
    let Ok(table) = read.open_table(IDX_EQ) else {
        return Ok(RoaringTreemap::new());
    };
    let mut found = RoaringTreemap::new();
    let from = (attribute, value, 0u32);
    for item in table.range(from..).map_err(database)? {
        let (key, stored) = item.map_err(database)?;
        let (name, at_value, page) = key.value();
        if name != attribute || at_value != value {
            break;
        }
        collect_into(&mut found, &decode(stored.value())?, page);
    }
    Ok(found)
}

/// Reads every page of a presence posting.
pub fn read_pres(
    read: &redb::ReadTransaction,
    attribute: &str,
) -> Result<RoaringTreemap, StoreError> {
    let folded_name = attribute.to_lowercase();
    let attribute: &str = folded_name.as_str();
    let Ok(table) = read.open_table(IDX_PRES) else {
        return Ok(RoaringTreemap::new());
    };
    let mut found = RoaringTreemap::new();
    for item in table.range((attribute, 0u32)..).map_err(database)? {
        let (key, stored) = item.map_err(database)?;
        let (name, page) = key.value();
        if name != attribute {
            break;
        }
        collect_into(&mut found, &decode(stored.value())?, page);
    }
    Ok(found)
}

/// Reads the intersection of several trigram postings.
///
/// `want_all` is the whole point of a trigram index: a value that matches the pattern must contain
/// every trigram the pattern implies, so intersecting them narrows before any record is read.
pub fn read_sub(
    read: &redb::ReadTransaction,
    attribute: &str,
    trigrams: &[String],
) -> Result<RoaringTreemap, StoreError> {
    let folded_name = attribute.to_lowercase();
    let attribute: &str = folded_name.as_str();
    let Ok(table) = read.open_table(IDX_SUB) else {
        return Ok(RoaringTreemap::new());
    };

    let mut found: Option<RoaringTreemap> = None;
    for trigram in trigrams {
        let mut for_trigram = RoaringTreemap::new();
        for item in table
            .range((attribute, trigram.as_str(), 0u32)..)
            .map_err(database)?
        {
            let (key, stored) = item.map_err(database)?;
            let (name, at_trigram, page) = key.value();
            if name != attribute || at_trigram != trigram {
                break;
            }
            collect_into(&mut for_trigram, &decode(stored.value())?, page);
        }

        found = Some(match found {
            Some(accumulated) => accumulated & for_trigram,
            None => for_trigram,
        });
        // An empty intersection stays empty however many trigrams are still to be asked.
        if found.as_ref().is_some_and(RoaringTreemap::is_empty) {
            break;
        }
    }

    Ok(found.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_holds_ids_by_offset() {
        assert_eq!(page_of(0), 0);
        assert_eq!(page_of(PAGE - 1), 0);
        assert_eq!(page_of(PAGE), 1);
        assert_eq!(bit_of(PAGE), 0);
        assert_eq!(bit_of(PAGE + 7), 7);
    }

    #[test]
    fn a_value_is_prepared_by_the_matching_rule_and_not_merely_lowercased() {
        assert_eq!(fold("Ann", false).expect("prepared"), " ann ");
        assert_eq!(fold("Ann", true).expect("prepared"), " Ann ");
        // Not ASCII-only: a filter for a lowercase name has to find an uppercased one.
        assert_eq!(fold("Москва", false).expect("prepared"), " москва ");
        // And prepared, not just folded: two spellings of the same name compare equal.
        assert_eq!(
            fold("\u{0418}\u{0306}ошкар", false).expect("prepared"),
            fold("\u{0419}ошкар", false).expect("prepared")
        );
    }

    #[test]
    fn a_pattern_asks_only_for_the_windows_it_implies() {
        // `Ann` as an initial part is indexed under `^an` and `ann`; an interior `nn` is too short.
        // The windows an initial part asks for must be windows the indexed value actually carries.
        // The value is prepared as ` ann ` and indexed as `^ ann $`, so the part's windows start
        // with the space: this is what makes `(cn=ali*)` find `alice`.
        let initial = pattern_trigrams(Some("Ann"), &[], None, false).expect("prepared");
        let value = trigrams(&format!("^{}$", fold("Ann", false).expect("prepared")));
        assert!(
            initial.contains(&"^ a".to_string()) && initial.contains(&" an".to_string()),
            "{initial:?}"
        );
        assert!(
            initial.iter().all(|window| value.contains(window)),
            "every window of the part must be a window of the value: {initial:?} vs {value:?}"
        );

        let short = pattern_trigrams(None, &["nn".to_string()], None, false).expect("prepared");
        assert!(short.is_empty(), "two characters narrow nothing: {short:?}");

        let trailing = pattern_trigrams(None, &[], Some("Ann"), false).expect("prepared");
        assert!(trailing.contains(&"nn ".to_string()), "{trailing:?}");
    }

    #[test]
    fn the_plan_falls_back_to_the_default() {
        let mut plan = Plan::of([("uid".to_string(), vec![Kind::Eq])]);
        plan.kinds
            .insert("".to_string(), [Kind::Pres].into_iter().collect());

        assert!(plan.has("uid", Kind::Eq));
        assert!(!plan.has("uid", Kind::Pres));
        assert!(
            plan.has("cn", Kind::Pres),
            "an unconfigured attribute takes the default"
        );
        assert!(!plan.has("cn", Kind::Eq));
        assert!(
            !Plan::empty().has("cn", Kind::Pres),
            "and nothing, when there is no default"
        );
    }

    #[test]
    fn a_bitmap_survives_the_round_trip_through_its_encoding() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(0);
        bitmap.insert((PAGE - 1) as u32);
        bitmap.insert(4242);

        assert_eq!(decode(&encode(&bitmap)).expect("decode"), bitmap);
        assert!(
            decode(&[0xff, 0xff]).is_err(),
            "a corrupt page is an error, not a zero"
        );
    }
}
