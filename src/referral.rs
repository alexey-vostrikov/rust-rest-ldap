//! Subtrees this server does not hold, and where to send a client that asks for them.
//!
//! A server that holds part of a directory and knows where the rest lives is more useful than
//! one that answers `noSuchObject`, and it is the cheap way to close a gap: nothing is copied,
//! nothing is cached, and the other server stays the authority for its own data.
//!
//! What this is **not**: the server does not forward the request itself. A `searchResRef`
//! (RFC 4511 §4.5.3) tells the client where to ask next, and the client asks. Chaining would
//! mean holding a connection, a timeout and a failure policy of our own for a question that is
//! already answerable - and a client that follows the referral gets a better answer than a proxy
//! ever gives, because it speaks to the authority directly.
//!
//! The decision lives here, apart from any socket: `covering` answers "which referral applies to
//! this DN", and the search handler decides what to send.

use std::fmt;

/// One subtree held elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Referral {
    /// The DN of the subtree, normalized the way the directory normalizes DNs.
    pub dn: String,
    /// The URI a client should ask instead: `ldap://host:port/base`.
    pub url: String,
}

impl Referral {
    /// Whether this referral covers `dn`: the same DN, or an ancestor of it.
    ///
    /// The comparison is on the parsed RDNs, not on string suffixes: `dc=example,dc=com` is not
    /// an ancestor of `dc=notexample,dc=com`, and a suffix test says it is.
    pub fn covers(&self, dn: &str) -> bool {
        crate::dn::is_descendant_or_self(&self.dn, dn)
    }
}

/// The configured referrals, longest first.
///
/// Order matters at the boundary: with `dc=example,dc=com` and `ou=remote,dc=example,dc=com`
/// both configured, a request for `cn=x,ou=remote,dc=example,dc=com` belongs to the second. The
/// most specific subtree that covers the base wins, which is what an operator writing both means.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Referrals {
    entries: Vec<Referral>,
}

impl Referrals {
    /// Builds the list, resolving overlaps by specificity and refusing what cannot work.
    pub fn new(mut entries: Vec<Referral>) -> Result<Self, ReferralError> {
        for referral in &entries {
            referral.validate()?;
        }

        // Longest DN first: the number of RDNs is the depth, and a deeper subtree is more
        // specific. Ties keep the order they were written in, so a configuration is readable.
        entries.sort_by_key(|referral| std::cmp::Reverse(crate::dn::depth(&referral.dn)));

        for pair in entries.windows(2) {
            if pair[0].dn == pair[1].dn {
                return Err(ReferralError::Duplicate {
                    dn: pair[0].dn.clone(),
                });
            }
        }

        Ok(Self { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The most specific referral covering `dn`, if any.
    pub fn covering(&self, dn: &str) -> Option<&Referral> {
        self.entries.iter().find(|referral| referral.covers(dn))
    }

    /// The referral as a `searchResRef` asks for it.
    pub fn uris(&self, dn: &str) -> Vec<String> {
        match self.covering(dn) {
            Some(referral) => vec![referral.url.clone()],
            None => Vec::new(),
        }
    }
}

impl fmt::Display for Referral {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} -> {}", self.dn, self.url)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReferralError {
    EmptyDn { url: String },
    UnsupportedUrl { url: String },
    Duplicate { dn: String },
}

impl fmt::Display for ReferralError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReferralError::EmptyDn { url } => write!(
                formatter,
                "the referral to '{url}' names no subtree: give the DN it covers"
            ),
            ReferralError::UnsupportedUrl { url } => write!(
                formatter,
                "'{url}' is not an LDAP URL: a referral must start with ldap:// or ldaps://, \
                 because that is the only scheme a client knows how to follow"
            ),
            ReferralError::Duplicate { dn } => write!(
                formatter,
                "two referrals cover '{dn}': one of them is unreachable and the operator \
                 cannot tell which"
            ),
        }
    }
}

impl std::error::Error for ReferralError {}

impl Referral {
    fn validate(&self) -> Result<(), ReferralError> {
        if self.dn.trim().is_empty() {
            return Err(ReferralError::EmptyDn {
                url: self.url.clone(),
            });
        }

        let scheme_is_ldap = self.url.starts_with("ldap://") || self.url.starts_with("ldaps://");
        if !scheme_is_ldap {
            return Err(ReferralError::UnsupportedUrl {
                url: self.url.clone(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn referral(dn: &str, url: &str) -> Referral {
        Referral {
            dn: dn.to_string(),
            url: url.to_string(),
        }
    }

    fn referrals(pairs: &[(&str, &str)]) -> Referrals {
        Referrals::new(pairs.iter().map(|(dn, url)| referral(dn, url)).collect())
            .expect("referrals")
    }

    #[test]
    fn an_exact_match_and_a_descendant_are_both_covered() {
        let list = referrals(&[("dc=remote,dc=com", "ldap://remote.example/dc=remote,dc=com")]);

        assert!(list.covering("dc=remote,dc=com").is_some());
        assert!(
            list.covering("cn=alice,ou=people,dc=remote,dc=com")
                .is_some()
        );
    }

    #[test]
    fn a_lookalike_parent_is_not_an_ancestor() {
        // The reason this is not a string suffix test: `example` ends with `ample`, and
        // `dc=notexample,dc=com` must not be answered with the referral for
        // `dc=example,dc=com`.
        let list = referrals(&[("dc=example,dc=com", "ldap://a/dc=example,dc=com")]);

        assert!(list.covering("dc=notexample,dc=com").is_none());
        assert!(list.covering("cn=x,dc=notexample,dc=com").is_none());
    }

    #[test]
    fn the_most_specific_subtree_wins() {
        let list = referrals(&[
            ("dc=example,dc=com", "ldap://wide/dc=example,dc=com"),
            (
                "ou=remote,dc=example,dc=com",
                "ldap://narrow/ou=remote,dc=example,dc=com",
            ),
        ]);

        assert_eq!(
            list.covering("cn=x,ou=remote,dc=example,dc=com")
                .expect("covered")
                .url,
            "ldap://narrow/ou=remote,dc=example,dc=com"
        );
        assert_eq!(
            list.covering("cn=y,ou=other,dc=example,dc=com")
                .expect("covered")
                .url,
            "ldap://wide/dc=example,dc=com"
        );
    }

    #[test]
    fn a_referral_with_the_wrong_scheme_is_refused_at_startup() {
        // A client following a referral has to know what to do with it. `http://` would be
        // handed to the same lookup that handles `ldap://` and produce a confusing failure,
        // so the mistake is caught where the operator can still fix it.
        let error = Referrals::new(vec![referral("dc=remote,dc=com", "http://remote.example/")])
            .expect_err("must refuse");

        assert!(
            matches!(error, ReferralError::UnsupportedUrl { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("ldap://"), "{error}");
    }

    #[test]
    fn a_referral_without_a_dn_is_refused() {
        let error = Referrals::new(vec![referral("  ", "ldap://remote.example/")])
            .expect_err("must refuse");

        assert!(matches!(error, ReferralError::EmptyDn { .. }), "{error}");
    }

    #[test]
    fn the_same_subtree_twice_is_refused() {
        let error = Referrals::new(vec![
            referral("dc=remote,dc=com", "ldap://a/"),
            referral("dc=remote,dc=com", "ldap://b/"),
        ])
        .expect_err("must refuse");

        assert!(matches!(error, ReferralError::Duplicate { .. }), "{error}");
    }

    #[test]
    fn a_normalized_configuration_dn_still_covers_a_plain_one() {
        // Config resolution normalizes the referral's DN; a search base arrives as the client
        // wrote it. The two have to meet.
        let list = referrals(&[("dc=remote,dc=test", "ldap://remote/")]);
        let normalized = crate::dn::normalize("dc=remote,dc=test");

        assert_eq!(
            normalized, "dc=remote,dc=test",
            "normalize is the identity here"
        );
        assert!(list.covering("ou=people,dc=remote,dc=test").is_some());
    }

    #[test]
    fn an_empty_configuration_referrals_nothing() {
        let list = Referrals::default();

        assert!(list.is_empty());
        assert!(list.covering("dc=example,dc=com").is_none());
        assert!(list.uris("dc=example,dc=com").is_empty());
    }
}
