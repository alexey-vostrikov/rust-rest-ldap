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
}

impl Kind {
    pub fn name(&self) -> &'static str {
        match self {
            Kind::Pres => "pres",
            Kind::Eq => "eq",
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
    And(Vec<Query>),
    Or(Vec<Query>),
    /// Never narrows: the complement of an indexable part is usually everything.
    Not(Box<Query>),
    /// A filter the index cannot help with.
    Unindexed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IndexError {
    #[error("unknown index kind '{0}', expected pres or eq")]
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
        other => Err(IndexError::UnknownKind(other.to_string())),
    }
}

/// Built indexes for one directory snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    presence: HashMap<Arc<str>, RoaringBitmap>,
    equality: HashMap<Arc<str>, HashMap<String, RoaringBitmap>>,
    /// Attributes whose values must be matched exactly rather than case-folded.
    case_sensitive: BTreeSet<Arc<str>>,
    default_kinds: BTreeSet<Kind>,
    /// Kinds actually built, per attribute, for logging and for `--check-index`.
    built: BTreeMap<Arc<str>, BTreeSet<Kind>>,
}

impl Index {
    /// Builds every index the configuration asks for.
    ///
    /// `entries` must be in canonical order: the position is the entry id.
    pub fn build(entries: &[Entry], config: &IndexConfig) -> Result<Self, IndexError> {
        let plan = config.resolve()?;
        let default_kinds = plan.get(DEFAULT_KEY).cloned().unwrap_or_default();
        let per_attribute: BTreeMap<String, BTreeSet<Kind>> = plan
            .into_iter()
            .filter(|(attribute, _)| !attribute.is_empty())
            .collect();

        let mut index = Self {
            presence: HashMap::new(),
            equality: HashMap::new(),
            case_sensitive: BTreeSet::new(),
            default_kinds,
            built: BTreeMap::new(),
        };

        for (position, entry) in entries.iter().enumerate() {
            let id = position as u32;

            for attribute in entry.attributes().values() {
                let name = Arc::clone(&attribute.name);
                if attribute.flags.case_sensitive {
                    index.case_sensitive.insert(Arc::clone(&name));
                }
                let kinds = index
                    .kinds_for(&name, &per_attribute)
                    .cloned()
                    .unwrap_or_default();

                if kinds.contains(&Kind::Pres) {
                    index
                        .presence
                        .entry(Arc::clone(&name))
                        .or_default()
                        .insert(id);
                    index
                        .built
                        .entry(Arc::clone(&name))
                        .or_default()
                        .insert(Kind::Pres);
                }

                if kinds.contains(&Kind::Eq) {
                    let case_sensitive = attribute.flags.case_sensitive;
                    for value in attribute.values.iter() {
                        let key = fold(value, case_sensitive);
                        index
                            .equality
                            .entry(Arc::clone(&name))
                            .or_default()
                            .entry(key)
                            .or_default()
                            .insert(id);
                    }
                    index.built.entry(name).or_default().insert(Kind::Eq);
                }
            }
        }

        Ok(index)
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
            Query::Presence(name) => self
                .presence
                .get(name)
                .or_else(|| self.presence.get(&name.to_lowercase() as &str))
                .cloned(),
            Query::Equality { attribute, value } => {
                let case_sensitive = self.case_sensitive.contains(attribute);
                let key = fold(value, case_sensitive);
                self.equality
                    .get(attribute)
                    .and_then(|values| values.get(&key))
                    // An indexed attribute with no such value is a real empty answer,
                    // not "unknown": the map exists for every value ever seen.
                    .cloned()
                    .or_else(|| {
                        self.built
                            .get(attribute)
                            .filter(|kinds| kinds.contains(&Kind::Eq))
                            .map(|_| RoaringBitmap::new())
                    })
            }
            Query::And(parts) => {
                let mut narrowed: Option<RoaringBitmap> = None;
                for part in parts {
                    if let Some(bitmap) = self.candidates(part) {
                        narrowed = Some(match narrowed {
                            Some(current) => current & bitmap,
                            None => bitmap,
                        });
                    }
                }
                narrowed
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
        let equality: usize = self
            .equality
            .values()
            .flat_map(|values| values.values())
            .map(|bitmap| bitmap.serialized_size())
            .sum();

        presence + equality
    }

    pub fn is_empty(&self) -> bool {
        self.presence.is_empty() && self.equality.is_empty()
    }
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
        let error =
            Index::build(&directory(), &config(&[("cn", &["sub"])], &[])).expect_err("must reject");

        assert_eq!(error, IndexError::UnknownKind("sub".to_string()));
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
}
