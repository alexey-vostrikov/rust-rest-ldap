//! Search over the catalog: a filter becomes ids, ids become records, records are re-checked.
//!
//! The shape of a search does not change from the old model - narrow, read, then verify - but each
//! step now has one meaning instead of three.
//!
//! * **Narrow.** An indexed part of the filter answers with a bitmap of ids in one posting read.
//!   `And` intersects, `Or` unites, and a part the index cannot describe returns `None`, which means
//!   "ask the scope" rather than "nothing matches". That distinction is the whole reason
//!   [`crate::catalog::index::read_ord`] returns an `Option`: an index that answered an unanswerable
//!   comparison with an empty set would silently drop entries.
//! * **Read.** Ids become records through the store, one keyed read each.
//! * **Verify.** The filter is evaluated against the records it selected. This is not a formality:
//!   the postings are a *superset* by construction (a case-insensitive posting cannot know which
//!   case a filter meant; a trigram posting cannot know the order of the windows), and the check is
//!   what turns a superset into an answer.
//!
//! # Why the scope is a range and not a filter
//!
//! A subtree is a key prefix in this store, so `(base, subtree)` is a range scan and `onelevel` is
//! the same scan cut by a count of RDNs. Neither reads a posting, and neither needs the filter to
//! mention the DN - which is what makes `(objectClass=*)` over a subtree cost a walk rather than a
//! comparison against every entry in the directory.
use std::sync::Arc;

use roaring::RoaringTreemap;

use crate::catalog::Catalog;
use crate::catalog::index::{self, fold, pattern_trigrams, read_ord};
use crate::catalog::store::StoreError;
use crate::directory::Scope;
use crate::index::Query;
use crate::model::Entry;

/// The protocol's filter, which is what the verification step evaluates.
///
/// Search carries it rather than deriving it: the index answers a *reduction* of the filter
/// (`Query`), and only the filter itself can decide whether a candidate really matches.
pub use rasn_ldap::Filter;

/// A filter, a base and a scope: the three things a search names.
#[derive(Debug, Clone)]
pub struct Request {
    pub base: String,
    pub scope: Scope,
    /// The filter as the client sent it: what the answer is checked against.
    pub filter: Filter,
    /// The same filter reduced to the parts an index can answer.
    pub query: Query,
}

impl Request {
    /// Whether a DN is inside the request's scope.
    ///
    /// The same rule the old walk applied after the fact, kept because the scope of a *record* is
    /// still the authoritative test for an entry that arrived from a posting rather than from a scan.
    pub fn covers(&self, dn: &str) -> bool {
        crate::directory::in_scope_for(dn, &self.base, self.scope)
    }
}

/// What a search produced, and what it cost.
#[derive(Debug, Default)]
pub struct Found {
    /// The entries that matched, in the store's order.
    pub entries: Vec<(u64, Entry)>,
    /// How many entries the narrowing step offered, before the filter was evaluated.
    ///
    /// Kept because it is the number that says whether an index is doing anything: as many
    /// candidates as the directory holds means the filter narrowed nothing.
    pub candidates: u64,
    /// Whether the answer came from postings rather than from a scope walk.
    pub indexed: bool,
}

/// A searcher over a catalog.
pub struct Search {
    catalog: Arc<Catalog>,
}

impl Search {
    pub fn new(catalog: Arc<Catalog>) -> Self {
        Self { catalog }
    }

    pub fn catalog(&self) -> &Arc<Catalog> {
        &self.catalog
    }

    /// The ids a query narrows to, or `None` when the index cannot answer it.
    ///
    /// `None` never means "nothing matched". It means the caller has to ask the scope instead, and
    /// every branch here that gives up says why in a comment - because each one of them is a place
    /// where answering "empty" would have been the wrong answer rather than a slow one.
    pub fn candidates(
        &self,
        read: &redb::ReadTransaction,
        query: &Query,
        case_sensitive: &dyn Fn(&str) -> bool,
    ) -> Result<Option<RoaringTreemap>, StoreError> {
        match query {
            Query::Equality { attribute, value } => {
                let folded = fold(value, case_sensitive(attribute))?;
                let found = index::read_eq(read, attribute, &folded)?;
                // An empty posting is a real answer: no entry holds that value. Unlike a range, where
                // the absence of a posting may mean the attribute was never ordered.
                Ok(Some(found))
            }
            Query::Presence(attribute) => Ok(Some(index::read_pres(read, attribute)?)),
            Query::Substring {
                attribute,
                initial,
                any,
                final_part,
            } => {
                let wanted = pattern_trigrams(
                    initial.as_deref(),
                    any.as_slice(),
                    final_part.as_deref(),
                    case_sensitive(attribute),
                )?;
                if wanted.is_empty() {
                    // Every part was shorter than one trigram: there is no window to look up, and the
                    // honest answer is "scan", not "nothing".
                    return Ok(None);
                }
                Ok(Some(index::read_sub(read, attribute, &wanted)?))
            }
            Query::Range {
                attribute,
                bound,
                value,
            } => read_ord(read, attribute, *bound, value, case_sensitive(attribute)),
            Query::And(parts) => {
                let mut narrowed: Option<RoaringTreemap> = None;
                for part in parts {
                    // One unanswerable conjunct does not spoil the others: what the rest narrow to is
                    // still a superset of the answer, and the filter check removes the difference.
                    if let Some(found) = self.candidates(read, part, case_sensitive)? {
                        narrowed = Some(match narrowed {
                            Some(accumulated) => accumulated & found,
                            None => found,
                        });
                    }
                }
                Ok(narrowed)
            }
            Query::Or(parts) => {
                let mut united = RoaringTreemap::new();
                for part in parts {
                    match self.candidates(read, part, case_sensitive)? {
                        Some(found) => united |= found,
                        // A disjunct the index cannot answer makes the union unbounded, so the whole
                        // `Or` falls back to the scope. Answering with the answerable half would drop
                        // every entry that matched only through the other.
                        None => return Ok(None),
                    }
                }
                Ok(Some(united))
            }
            // The complement of an indexed part is usually everything; intersecting with it would
            // narrow nothing and cost a pass over the directory.
            Query::Not(_) | Query::Unindexed => Ok(None),
        }
    }

    /// Runs a search: narrow when possible, walk the scope when not, then verify.
    pub fn run(
        &self,
        request: &Request,
        case_sensitive: &dyn Fn(&str) -> bool,
    ) -> Result<Found, StoreError> {
        let read = self.catalog.store().read()?;

        let narrowed = self.candidates(&read, &request.query, case_sensitive)?;
        drop(read);

        let indexed = narrowed.is_some();
        let candidates = match narrowed {
            Some(ids) => ids,
            None => self.scope_ids(&request.base, request.scope)?,
        };

        let offered = candidates.len();

        let mut entries = Vec::new();
        for id in candidates.iter() {
            let Some(entry) = self.catalog.by_id(id)? else {
                // An id with no record is a store that lost an entry without losing its postings.
                // Skipping it hides that, so it is an error.
                return Err(StoreError::Record(format!(
                    "posting names id {id}, which the store does not hold"
                )));
            };
            if !request.covers(entry.dn()) {
                continue;
            }
            // The verification step, and it is not a formality: the postings are a superset by
            // construction - a case-insensitive posting cannot know which case the filter meant, and
            // a trigram posting cannot know the order of the windows - so this check is what turns a
            // superset into an answer.
            let matched =
                crate::ldap::filter::matches(entry.attributes(), entry.dn(), &request.filter)
                    .map_err(|error| {
                        StoreError::Record(format!("the filter could not be evaluated: {error}"))
                    })?;
            if !matched {
                continue;
            }
            entries.push((id, entry));
        }

        Ok(Found {
            entries,
            candidates: offered,
            indexed,
        })
    }

    /// The ids inside a base and scope: a key-prefix range, not a posting read.
    pub fn scope_ids(&self, base: &str, scope: Scope) -> Result<RoaringTreemap, StoreError> {
        let base = crate::dn::normalize(base);

        // A base search is one point read, not a walk: `walk` counts levels *below* its base, so a
        // depth of zero there means "no children", and asking it for the base itself would come back
        // empty - which reads as "no such entry" rather than "wrong question".
        if scope == Scope::Base {
            let mut ids = RoaringTreemap::new();
            if let Some(id) = self.catalog.id_of(&base)? {
                ids.insert(id);
            }
            return Ok(ids);
        }

        let depth = match scope {
            Scope::Base => unreachable!("handled above"),
            Scope::OneLevel => 1,
            Scope::Subtree => usize::MAX,
        };

        let mut ids = RoaringTreemap::new();
        for (id, _) in self.catalog.store().walk(&base, depth)? {
            ids.insert(id);
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::index::Plan;
    use crate::catalog::store::Store;
    use crate::index::{Kind, RangeBound};
    use crate::model::{Attribute, Attributes};

    const BASE: &str = "dc=example,dc=com";

    fn plan() -> Plan {
        Plan::of([
            ("uid".to_string(), vec![Kind::Eq, Kind::Pres]),
            ("age".to_string(), vec![Kind::Ord]),
            ("cn".to_string(), vec![Kind::Sub]),
            ("objectClass".to_string(), vec![Kind::Eq]),
        ])
    }

    fn catalog() -> Arc<Catalog> {
        Arc::new(Catalog::new(
            Arc::new(Store::in_memory().expect("store").with_plan(plan())),
            BASE,
            "users",
            "groups",
        ))
    }

    fn person(name: &str, age: &str, cn: &str) -> Entry {
        Entry::new(
            format!("uid={name},ou=users,{BASE}"),
            Attributes::new()
                .replace(Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "inetOrgPerson".to_string()],
                ))
                .replace(Attribute::single("uid", name))
                .replace(Attribute::single("age", age))
                .replace(Attribute::single("cn", cn)),
        )
    }

    fn seeds() -> Arc<Catalog> {
        let catalog = catalog();
        for (name, age, cn) in [
            ("alice", "30", "Alice Cooper"),
            ("bob", "9", "Bob Marley"),
            ("carol", "10", "Carol King"),
            ("dave", "45", "Dave Bowie"),
        ] {
            catalog.insert(person(name, age, cn)).expect("insert");
        }
        catalog
    }

    fn insensitive(_: &str) -> bool {
        false
    }

    #[test]
    fn a_range_is_answered_by_the_ordered_index_and_orders_numbers_as_numbers() {
        // The defect an ordered index exists to avoid: `10` compared as text sorts before `9`, so a
        // text-ordered `(age>=9)` would leave `10` out. A false negative, and the reason a numeric
        // attribute gets a numeric key.
        let catalog = seeds();
        let search = Search::new(Arc::clone(&catalog));
        let read = catalog.store().read().expect("read");

        let found = search
            .candidates(
                &read,
                &Query::Range {
                    attribute: Arc::from("age"),
                    bound: RangeBound::AtLeast,
                    value: "10".to_string(),
                },
                &insensitive,
            )
            .expect("range")
            .expect("the index describes this comparison");

        let names: Vec<String> = found
            .iter()
            .map(|id| {
                catalog
                    .by_id(id)
                    .expect("read")
                    .expect("present")
                    .dn()
                    .to_string()
            })
            .collect();
        assert_eq!(names.len(), 3, "ages 10, 30 and 45: {names:?}");
        assert!(
            !names.iter().any(|dn| dn.contains("uid=bob")),
            "age 9 is below the bound: {names:?}"
        );
    }

    #[test]
    fn a_bound_of_the_wrong_kind_says_it_cannot_answer_rather_than_answering_nothing() {
        // The distinction that keeps a range index honest: `None` is "scan", never "no matches".
        let catalog = seeds();
        let search = Search::new(Arc::clone(&catalog));
        let read = catalog.store().read().expect("read");

        let answered = search
            .candidates(
                &read,
                &Query::Range {
                    attribute: Arc::from("age"),
                    bound: RangeBound::AtLeast,
                    value: "ten".to_string(),
                },
                &insensitive,
            )
            .expect("range");

        assert!(
            answered.is_none(),
            "a text bound on a numeric attribute cannot be indexed"
        );
    }

    #[test]
    fn a_mixed_attribute_gives_up_its_ordering() {
        // Numbers and text in one attribute: neither ordering describes the comparison, so the index
        // stands aside and the query scans. Answering from the numeric keys would silently drop the
        // text values, which a filter would have matched.
        let catalog = catalog();
        catalog
            .insert(person("alice", "30", "Alice"))
            .expect("insert");
        catalog
            .insert(Entry::new(
                format!("uid=bob,ou=users,{BASE}"),
                Attributes::new()
                    .replace(Attribute::single("objectClass", "inetOrgPerson"))
                    .replace(Attribute::single("uid", "bob"))
                    .replace(Attribute::single("age", "unknown")),
            ))
            .expect("insert");

        let search = Search::new(Arc::clone(&catalog));
        let read = catalog.store().read().expect("read");
        let answered = search
            .candidates(
                &read,
                &Query::Range {
                    attribute: Arc::from("age"),
                    bound: RangeBound::AtLeast,
                    value: "10".to_string(),
                },
                &insensitive,
            )
            .expect("range");

        assert!(answered.is_none(), "a mixed attribute is not ordered");
    }

    #[test]
    fn a_conjunction_narrows_by_what_can_be_answered_and_ignores_the_rest() {
        let catalog = seeds();
        let search = Search::new(Arc::clone(&catalog));
        let read = catalog.store().read().expect("read");

        let found = search
            .candidates(
                &read,
                &Query::And(vec![
                    Query::Presence(Arc::from("uid")),
                    Query::Equality {
                        attribute: Arc::from("objectClass"),
                        value: "inetOrgPerson".to_string(),
                    },
                    // Nothing to narrow with, and it must not empty the answer.
                    Query::Unindexed,
                ]),
                &insensitive,
            )
            .expect("and")
            .expect("the answerable conjuncts narrow");

        assert_eq!(found.len(), 4);
    }

    #[test]
    fn a_disjunction_with_one_unanswerable_part_falls_back_to_the_scope() {
        // Answering with the answerable half would drop every entry that matched through the other.
        let catalog = seeds();
        let search = Search::new(Arc::clone(&catalog));
        let read = catalog.store().read().expect("read");

        let found = search
            .candidates(
                &read,
                &Query::Or(vec![
                    Query::Equality {
                        attribute: Arc::from("uid"),
                        value: "alice".to_string(),
                    },
                    Query::Unindexed,
                ]),
                &insensitive,
            )
            .expect("or");

        assert!(
            found.is_none(),
            "the union is unbounded, so the index stands aside"
        );
    }

    #[test]
    fn the_scope_is_a_range_and_onelevel_is_cut_by_depth() {
        let catalog = seeds();
        let search = Search::new(Arc::clone(&catalog));

        assert_eq!(
            search.scope_ids(BASE, Scope::Subtree).expect("scope").len(),
            4,
            "the four accounts"
        );
        assert_eq!(
            search
                .scope_ids(&format!("ou=users,{BASE}"), Scope::OneLevel)
                .expect("scope")
                .len(),
            4,
            "one level below ou=users is the accounts"
        );
        assert_eq!(
            search
                .scope_ids("uid=alice,ou=users,dc=example,dc=com", Scope::Base)
                .expect("scope")
                .len(),
            1,
            "a base search is the entry itself"
        );
        assert!(
            search
                .scope_ids(&format!("ou=nobody,{BASE}"), Scope::Subtree)
                .expect("scope")
                .is_empty(),
            "a base that does not exist holds nothing"
        );
    }
}
