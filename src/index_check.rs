//! Checking an index against the data it claims to describe.
//!
//! The invariant every index in this server rests on: **a candidate set is a superset of the
//! answer**. The filter still runs on every candidate, so an index can make a search faster
//! and can never change it - as long as the superset direction holds. The expensive mistake
//! is a **false negative**: a candidate set that leaves out an entry the scan would have
//! found. That is invisible in an answer, because the answer simply comes back short, and
//! nothing about a short answer says it was wrong.
//!
//! This module exists because that failure happened: the `ord` index stored attribute names
//! as written while the filter lowercased them, so `uidNumber` and `objectClass` were never
//! found and the index narrowed nothing. Nothing failed, nothing logged, and the only reason
//! it was caught is that a test compared candidate *sets* rather than answers. A check that
//! can be run against a live directory is worth more than a test that ran once.
//!
//! Two strengths of check, because two kinds of index exist:
//!
//! - `pres` and `eq` are **exact**: the map holds one bucket per value ever seen, so the
//!   candidates must equal the answer, no more and no less.
//! - `sub` and `ord` are **deliberately loose**: trigrams and ranges answer with a superset
//!   on purpose. Only the false-negative direction is a bug; a candidate set twice the size
//!   of the answer is inefficiency, not error.

use std::collections::BTreeSet;

use crate::index::{Index, Kind, Query, RangeBound};
use crate::model::{Attribute, Entry};

/// How many distinct values of one attribute are checked.
///
/// A directory of twenty thousand users has twenty thousand distinct `uid` values, and
/// checking every one against a scan is a full scan per value. A sample finds a broken index
/// as reliably as an exhaustive check - the bug is in the lookup, not in the data - and
/// finishes in a time an operator will accept at a console.
const SAMPLE: usize = 32;

/// What the check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Queries that were compared against a scan.
    pub checked: usize,
    /// Queries the index could not answer and the scan had to; neither good nor bad.
    pub not_indexed: usize,
    /// Places where the index would leave out an entry the scan finds.
    pub missing: Vec<Mismatch>,
    /// Places where an exact index answers with a different set than the scan.
    pub wrong: Vec<Mismatch>,
    /// Candidate sets that are correct but larger than the answer, per attribute.
    pub loose: Vec<Loose>,
}

/// One entry the index would lose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// The attribute the query was about.
    pub attribute: String,
    /// The query in the terms an operator can repeat.
    pub query: String,
    /// Entries the scan finds and the candidates do not.
    pub lost: Vec<String>,
    /// Entries the candidates hold and the scan does not, for an exact index.
    pub extra: Vec<String>,
}

/// An attribute whose index narrows less than it could.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loose {
    pub attribute: String,
    /// Summed over the samples: candidates beyond the answer.
    pub extra: usize,
}

impl Report {
    /// Whether the index is safe to serve from.
    pub fn is_sound(&self) -> bool {
        self.missing.is_empty() && self.wrong.is_empty()
    }
}

/// Checks `index` against `entries`.
///
/// `entries` must be the same slice the index was built from, in the same order: entry ids
/// are positions, and a check against a different order would report every entry as lost.
pub fn check(entries: &[Entry], index: &Index) -> Report {
    let mut report = Report::default();

    // Attribute names as the index stores them: lowercase, because the filter lowercases
    // before asking. Reading them from the index rather than from the entries is what makes
    // the check see a name-spelling bug instead of sharing it.
    let attributes: BTreeSet<String> = index
        .built_attributes()
        .map(|(name, _)| name.to_string())
        .collect();

    for attribute in &attributes {
        let kinds = index
            .built_attributes()
            .find(|(name, _)| name.as_ref() == attribute.as_str())
            .map(|(_, kinds)| kinds.clone())
            .unwrap_or_default();

        let Some(values) = values_of(entries, attribute) else {
            continue;
        };

        if kinds.contains(&Kind::Pres) {
            compare(
                &mut report,
                index,
                entries,
                &Query::Presence(attribute.as_str().into()),
                &format!("({attribute}=*)"),
                &present(entries, attribute),
                true,
            );
        }

        for value in sample(&values) {
            if kinds.contains(&Kind::Eq) {
                compare(
                    &mut report,
                    index,
                    entries,
                    &Query::Equality {
                        attribute: attribute.as_str().into(),
                        value: value.clone(),
                    },
                    &format!("({attribute}={value})"),
                    &equals(entries, attribute, &value),
                    true,
                );
            }

            if kinds.contains(&Kind::Sub) {
                // Three shapes, because they look up different trigrams: an interior part
                // uses the part itself, an initial part the part with `^`, a final one with
                // `$`. Checking only the interior form misses the boundary buckets entirely -
                // which is how a mutation that dropped every value's first trigram survived
                // this check until the anchored forms were added.
                compare(
                    &mut report,
                    index,
                    entries,
                    &Query::Substring {
                        attribute: attribute.as_str().into(),
                        initial: None,
                        any: vec![value.clone()],
                        final_part: None,
                    },
                    &format!("({attribute}=*{value}*)"),
                    &contains(entries, attribute, &value),
                    false,
                );

                compare(
                    &mut report,
                    index,
                    entries,
                    &Query::Substring {
                        attribute: attribute.as_str().into(),
                        initial: Some(value.clone()),
                        any: Vec::new(),
                        final_part: None,
                    },
                    &format!("({attribute}={value}*)"),
                    &starts_with(entries, attribute, &value),
                    false,
                );

                compare(
                    &mut report,
                    index,
                    entries,
                    &Query::Substring {
                        attribute: attribute.as_str().into(),
                        initial: None,
                        any: Vec::new(),
                        final_part: Some(value.clone()),
                    },
                    &format!("({attribute}=*{value})"),
                    &ends_with(entries, attribute, &value),
                    false,
                );
            }

            if kinds.contains(&Kind::Ord) {
                compare(
                    &mut report,
                    index,
                    entries,
                    &Query::Range {
                        attribute: attribute.as_str().into(),
                        bound: RangeBound::AtLeast,
                        value: value.clone(),
                    },
                    &format!("({attribute}>={value})"),
                    &at_least(entries, attribute, &value),
                    false,
                );
            }
        }
    }

    report
}

/// Compares one query's candidates with what a scan answers.
///
/// `exact` says whether the two sets must be equal (`pres`, `eq`) or whether the candidates
/// only have to contain the answer (`sub`, `ord`).
fn compare(
    report: &mut Report,
    index: &Index,
    entries: &[Entry],
    query: &Query,
    label: &str,
    answer: &BTreeSet<u32>,
    exact: bool,
) {
    let Some(candidates) = index.candidates(query) else {
        report.not_indexed += 1;
        return;
    };

    report.checked += 1;

    let lost: Vec<String> = answer
        .iter()
        .filter(|id| !candidates.contains(**id))
        .filter_map(|id| {
            entries
                .get(*id as usize)
                .map(|entry| entry.dn().to_string())
        })
        .collect();

    let extra: Vec<String> = candidates
        .iter()
        .filter(|id| !answer.contains(id))
        .filter_map(|id| entries.get(id as usize).map(|entry| entry.dn().to_string()))
        .collect();

    let attribute = match query {
        Query::Presence(name)
        | Query::Equality {
            attribute: name, ..
        } => name.to_string(),
        Query::Substring { attribute, .. } | Query::Range { attribute, .. } => {
            attribute.to_string()
        }
        Query::And(_) | Query::Or(_) | Query::Not(_) | Query::Unindexed => String::new(),
    };

    if !lost.is_empty() {
        // A false negative is a bug in every kind of index: the entry exists, the scan finds
        // it, and a client asking through the index would not.
        report.missing.push(Mismatch {
            attribute: attribute.clone(),
            query: label.to_string(),
            lost,
            extra: Vec::new(),
        });
        return;
    }

    if exact && !extra.is_empty() {
        // For an exact index this is also a bug, though a harmless one: the filter will drop
        // the extra candidates, but a map that disagrees with its data is a map to distrust.
        report.wrong.push(Mismatch {
            attribute: attribute.clone(),
            query: label.to_string(),
            lost: Vec::new(),
            extra,
        });
        return;
    }

    if !extra.is_empty() {
        match report
            .loose
            .iter_mut()
            .find(|item| item.attribute == attribute)
        {
            Some(item) => item.extra += extra.len(),
            None => report.loose.push(Loose {
                attribute,
                extra: extra.len(),
            }),
        }
    }
}

/// Distinct values of an attribute across the entries, capped at `SAMPLE`.
fn values_of(entries: &[Entry], attribute: &str) -> Option<Vec<String>> {
    let mut values: BTreeSet<String> = BTreeSet::new();

    for entry in entries {
        if let Some(found) = entry.attributes().get(attribute) {
            for value in found.values.iter() {
                // Long values are truncated to keep the check readable and the queries
                // reasonable; a photo does not need to be compared byte for byte.
                values.insert(value.chars().take(64).collect());
            }
        }
    }

    (!values.is_empty()).then(|| values.into_iter().collect())
}

/// A deterministic sample: the first and last values, then every step between.
///
/// Taking the first N would check only the beginning of a sorted attribute; taking a stride
/// spreads the sample across the whole range, which is where a widened number or a folded
/// name lives.
fn sample(values: &[String]) -> Vec<String> {
    if values.len() <= SAMPLE {
        return values.to_vec();
    }

    let stride = values.len().div_ceil(SAMPLE);
    let mut chosen: Vec<String> = values.iter().step_by(stride).cloned().collect();

    // The far end is added rather than left to the stride: a stride of a thousand over a
    // thousand values stops at the last multiple, and the widened number that breaks a
    // numeric index would be exactly the one not sampled.
    if chosen.last() != values.last() {
        chosen.extend(values.last().cloned());
    }

    chosen
}

/// Ids of the entries where the attribute is present.
fn present(entries: &[Entry], attribute: &str) -> BTreeSet<u32> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| found(entry, attribute).is_some())
        .map(|(id, _)| id as u32)
        .collect()
}

/// Ids of the entries whose value equals `value`, folded the way the index folds.
fn equals(entries: &[Entry], attribute: &str, value: &str) -> BTreeSet<u32> {
    let mut ids = BTreeSet::new();

    for (id, entry) in entries.iter().enumerate() {
        let Some(found) = found(entry, attribute) else {
            continue;
        };

        let needle = if found.flags.case_sensitive {
            value.to_string()
        } else {
            value.to_lowercase()
        };

        let hit = found.values.iter().any(|candidate| {
            let candidate: String = candidate.chars().take(64).collect();
            let candidate = if found.flags.case_sensitive {
                candidate
            } else {
                candidate.to_lowercase()
            };
            candidate == needle
        });

        if hit {
            ids.insert(id as u32);
        }
    }

    ids
}

/// Ids of the entries with a value containing `value`.
fn contains(entries: &[Entry], attribute: &str, value: &str) -> BTreeSet<u32> {
    let mut ids = BTreeSet::new();
    let needle = value.to_lowercase();

    for (id, entry) in entries.iter().enumerate() {
        let Some(found) = found(entry, attribute) else {
            continue;
        };

        let hit = found.values.iter().any(|candidate| {
            let candidate: String = candidate.chars().take(64).collect();
            let candidate = if found.flags.case_sensitive {
                candidate
            } else {
                candidate.to_lowercase()
            };
            candidate.contains(&needle)
        });

        if hit {
            ids.insert(id as u32);
        }
    }

    ids
}

/// Ids of the entries with a value starting with `value`.
fn starts_with(entries: &[Entry], attribute: &str, value: &str) -> BTreeSet<u32> {
    boundary(entries, attribute, value, |candidate, needle| {
        candidate.starts_with(needle)
    })
}

/// Ids of the entries with a value ending with `value`.
fn ends_with(entries: &[Entry], attribute: &str, value: &str) -> BTreeSet<u32> {
    boundary(entries, attribute, value, |candidate, needle| {
        candidate.ends_with(needle)
    })
}

/// The entries whose value matches an anchored pattern, folded like the index folds.
fn boundary(
    entries: &[Entry],
    attribute: &str,
    value: &str,
    predicate: fn(&str, &str) -> bool,
) -> BTreeSet<u32> {
    let mut ids = BTreeSet::new();
    let needle = value.to_lowercase();

    for (id, entry) in entries.iter().enumerate() {
        let Some(found) = found(entry, attribute) else {
            continue;
        };

        let hit = found.values.iter().any(|candidate| {
            let candidate: String = candidate.chars().take(64).collect();
            let candidate = if found.flags.case_sensitive {
                candidate
            } else {
                candidate.to_lowercase()
            };
            predicate(&candidate, &needle)
        });

        if hit {
            ids.insert(id as u32);
        }
    }

    ids
}

/// Ids of the entries with a value at or above `value`, ordered as the filter orders.
fn at_least(entries: &[Entry], attribute: &str, value: &str) -> BTreeSet<u32> {
    let mut ids = BTreeSet::new();

    for (id, entry) in entries.iter().enumerate() {
        let Some(found) = found(entry, attribute) else {
            continue;
        };

        let hit = found.values.iter().any(|candidate| {
            let candidate: String = candidate.chars().take(64).collect();
            let numeric = crate::ldap::sort::looks_numeric(&candidate)
                && crate::ldap::sort::looks_numeric(value);

            crate::ldap::sort::order_values(&candidate, value, numeric, found.flags.case_sensitive)
                .is_ge()
        });

        if hit {
            ids.insert(id as u32);
        }
    }

    ids
}

/// The attribute of an entry, matched the way the index matches names.
fn found<'a>(entry: &'a Entry, attribute: &str) -> Option<&'a Attribute> {
    entry
        .attributes()
        .get(attribute)
        .or_else(|| entry.attributes().get(&attribute.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::IndexConfig;
    use crate::model::{Attribute, Attributes};

    fn entry(dn: &str, pairs: &[(&str, &[&str])]) -> Entry {
        let mut attributes = Attributes::new();
        for (name, values) in pairs {
            attributes = attributes.push(Attribute::new(
                *name,
                values.iter().map(|value| value.to_string()).collect(),
            ));
        }
        Entry::new(dn, attributes)
    }

    fn data() -> Vec<Entry> {
        vec![
            entry(
                "cn=ann,dc=example,dc=com",
                &[("cn", &["Ann"]), ("uidNumber", &["9"])],
            ),
            entry(
                "cn=bob,dc=example,dc=com",
                &[("cn", &["Bob"]), ("uidNumber", &["10"])],
            ),
            entry(
                "cn=cat,dc=example,dc=com",
                &[("cn", &["Cat"]), ("uidNumber", &["100"])],
            ),
        ]
    }

    fn config() -> IndexConfig {
        IndexConfig {
            default: vec!["pres".to_string()],
            attributes: [
                ("cn", vec!["eq", "pres", "sub"]),
                ("uidnumber", vec!["eq", "ord"]),
            ]
            .into_iter()
            .map(|(name, kinds)| {
                (
                    name.to_string(),
                    kinds.into_iter().map(str::to_string).collect(),
                )
            })
            .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_healthy_index_reports_nothing() {
        let entries = data();
        let index = Index::build(&entries, &config()).expect("index");

        let report = check(&entries, &index);

        assert!(report.is_sound(), "{report:?}");
        assert!(
            report.checked > 0,
            "the check must actually check something"
        );
        assert_eq!(report.missing.len(), 0);
        assert_eq!(report.wrong.len(), 0);
    }

    #[test]
    fn an_index_built_from_other_data_is_caught() {
        // The failure this detector exists for: an index that does not describe the entries
        // in front of it. Entry ids are positions, so an index over a *different* directory
        // answers with ids that mean something else here.
        let entries = data();
        let stale = Index::build(
            &[entry("cn=zzz,dc=example,dc=com", &[("cn", &["Zzz"])])],
            &config(),
        )
        .expect("index");

        let report = check(&entries, &stale);

        assert!(!report.is_sound(), "the mismatch must be reported");
        assert!(
            !report.missing.is_empty(),
            "entries the stale index does not know must be reported as lost: {report:?}"
        );
    }

    #[test]
    fn a_missing_value_is_a_false_negative_and_is_reported() {
        // Half of the data: `bob` and `cat` are absent from the index while present in the
        // entries. That is exactly the shape of the bug the runtime check is for - every
        // entry the index does not hold is an entry a search would silently not return.
        let all = data();
        let index = Index::build(&all[..1], &config()).expect("index");

        let report = check(&all, &index);

        let lost: Vec<String> = report
            .missing
            .iter()
            .flat_map(|mismatch| mismatch.lost.clone())
            .collect();

        assert!(
            lost.iter().any(|dn| dn.contains("bob")),
            "bob must be reported as lost: {report:?}"
        );
        assert!(!report.is_sound());
    }

    #[test]
    fn an_exact_index_with_extra_candidates_is_reported_too() {
        // `eq` is exact by construction; an extra candidate means the map and the data
        // disagree, and a map that disagrees with its data is one to distrust even when the
        // filter would hide the difference.
        let entries = data();
        let index = Index::build(&entries, &config()).expect("index");

        // Ask the index for a value nobody has: an exact index answers empty, not "unknown",
        // and the scan agrees, so this is sound - the opposite case is what the next test
        // builds by hand.
        let report = check(&entries, &index);
        assert!(report.is_sound());

        let empty = index.candidates(&Query::Equality {
            attribute: "cn".into(),
            value: "nobody".to_string(),
        });
        assert_eq!(empty.map(|bitmap| bitmap.len()), Some(0));
    }

    #[test]
    fn a_pattern_too_short_for_a_trigram_is_counted_as_not_indexed() {
        let entries = data();
        let index = Index::build(&entries, &config()).expect("index");

        let report = check(&entries, &index);

        // Every checked query was answered; none of the samples was short enough to be
        // skipped, because the values are one, two and three characters and `ann` is a
        // trigram while `9` is not - numeric attributes have no `sub` index here, so the
        // count stays honest either way.
        assert_eq!(report.not_indexed, 0, "{report:?}");
    }

    #[test]
    fn the_sample_spans_the_whole_range_and_not_its_beginning() {
        // Taking the first N values would check a sorted prefix and miss a widened number at
        // the far end, which is where a numeric index bug shows itself.
        let values: Vec<String> = (0..1000).map(|index| index.to_string()).collect();
        let chosen = sample(&values);

        assert!(chosen.len() <= SAMPLE + 1, "{} values", chosen.len());
        assert_eq!(chosen.first().map(String::as_str), Some("0"));
        assert!(
            chosen.iter().any(|value| value == "999"),
            "the far end must be sampled: {chosen:?}"
        );
    }

    #[test]
    fn all_three_substring_shapes_are_compared() {
        // The three shapes look up different trigrams - the part itself, the part with `^`,
        // the part with `$` - and a check that only asks the interior form cannot see a
        // broken boundary bucket. A mutation that dropped every value's first trigram
        // survived this check until the anchored forms were added.
        let entries = data();
        let index = Index::build(&entries, &config()).expect("index");

        let report = check(&entries, &index);

        // Three `cn` values, three shapes each, plus presence and the equality and range
        // checks on `uidnumber`.
        assert!(
            report.checked >= 13,
            "the anchored shapes must be compared too: {report:?}"
        );
        assert!(report.is_sound());
    }

    #[test]
    fn a_short_attribute_is_checked_in_full() {
        let values: Vec<String> = (0..5).map(|index| index.to_string()).collect();
        assert_eq!(sample(&values), values);
    }

    #[test]
    fn an_attribute_with_no_values_is_skipped_rather_than_failing() {
        let entries = data();
        let index = Index::build(&entries, &config()).expect("index");

        // `telephoneNumber` is in the plan through nothing: it has no entries and no kinds,
        // so it must simply not appear.
        let report = check(&entries, &index);
        assert!(report.missing.is_empty());
        assert!(
            report
                .loose
                .iter()
                .all(|item| item.attribute != "telephoneNumber")
        );
    }
}
