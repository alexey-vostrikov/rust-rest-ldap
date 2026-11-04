//! What the server refuses to do, whatever the client asked for.
//!
//! Every limit in this module exists because a client can ask for something the server should not
//! give. `ldapsearch -z 0` is the ordinary spelling of "give me everything", and against a
//! directory of a hundred thousand entries that is one request that occupies the server, fills a
//! socket buffer, and is answered by nothing an operator configured. The client's own limit is a
//! courtesy, not a policy: a policy is the one the operator wrote down.
//!
//! # Why both a size and a time limit
//!
//! They fail differently and both are needed. A size limit bounds what is sent; a filter that
//! matches nothing still costs the scan, and on a directory large enough to matter the scan is
//! where the time goes. A time limit is therefore the only limit that bounds a search returning
//! almost nothing - which is exactly the shape of the request that hurts most: a broad filter, no
//! index, and a client that waits.
//!
//! # RFC 4511 §4.5.1.1, and where this is stricter
//!
//! The server may impose its own limit, and reports `sizeLimitExceeded` or `timeLimitExceeded`
//! when it does. What this module adds is the rule that the *smaller* of the two limits wins:
//! a client asking for ten thousand entries does not get ten thousand when the server offers a
//! thousand, and a client asking for ten does not get a thousand either.
use std::time::Duration;

/// What the `limits:` section says.
///
/// Absent means no limit, which is what every deployment had before this existed and is a
/// deliberate default rather than an oversight: a limit chosen by a library would be a limit
/// nobody measured, and refusing a legitimate bulk export is its own kind of outage.
/// `deny_unknown_fields` is the point of this attribute, not decoration: the key this section
/// documents is `time_limit`, and the field was called `time_limit_seconds`. An unknown key was
/// silently ignored, so an operator who wrote the documented limit got no limit at all - and a
/// search that should have been cut at one second ran for four minutes. A setting that is written
/// and does nothing is worse than one that is rejected, because nothing tells the operator.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// The most entries one search may return.
    ///
    /// Zero means no limit. Applied to the entries that matched, after the filter - a limit
    /// checked before the filter refuses a search that would have returned one entry, which is
    /// the defect this ordering exists to prevent.
    pub size_limit: usize,
    /// How long one search may take, in seconds.
    ///
    /// Zero means no limit. The clock covers the scan, not the writing: a search that has found
    /// its entries and is sending them is nearly done, and cutting it off mid-answer helps nobody.
    ///
    /// The name is the documented one. `time_limit_seconds` is accepted as an alias because that
    /// was the field's name in the code, and a configuration written against the source instead
    /// of the example should keep working - but the example is what an operator reads, and it
    /// says `time_limit`.
    #[serde(alias = "time_limit_seconds")]
    pub time_limit: Option<u64>,
}

/// The resolved policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Limits {
    /// Zero for no limit.
    pub size_limit: usize,
    /// `None` for no limit.
    pub time_limit: Option<Duration>,
}

impl Limits {
    pub fn from_config(config: &LimitsConfig) -> Self {
        Self {
            size_limit: config.size_limit,
            time_limit: match config.time_limit {
                // Zero is how a file says "no limit"; anything else is a real budget. A duration of
                // zero would otherwise expire before the first entry and answer every search with
                // a timeout, which is not what a forgotten key should mean.
                Some(0) | None => None,
                Some(seconds) => Some(Duration::from_secs(seconds)),
            },
        }
    }

    /// Whether nothing is limited, for a startup line that stays quiet.
    pub fn is_unlimited(&self) -> bool {
        self.size_limit == 0 && self.time_limit.is_none()
    }

    /// The size limit that decides for this request: the smaller of the two non-zero ones.
    ///
    /// Returns zero when neither applies, because that is the value the search path already uses
    /// for "no truncation".
    pub fn effective_size_limit(&self, requested: u32) -> usize {
        match (self.size_limit, requested as usize) {
            (0, 0) => 0,
            (0, requested) => requested,
            (server, 0) => server,
            (server, requested) => server.min(requested),
        }
    }

    /// Whether the server's own limit, rather than the client's, is what truncated the answer.
    ///
    /// The distinction is what the diagnostic is for: a client that asked for ten entries and got
    /// ten knows why. One that asked for everything and got ten needs to be told the server has a
    /// policy, or it will page for ever and never understand.
    pub fn server_bound(&self, requested: u32) -> bool {
        self.size_limit > 0 && (requested == 0 || self.size_limit < requested as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(size_limit: usize, time_limit_seconds: Option<u64>) -> Limits {
        Limits::from_config(&LimitsConfig {
            size_limit,
            time_limit: time_limit_seconds,
        })
    }

    #[test]
    fn an_absent_section_limits_nothing() {
        // Every deployment that existed before this: an unconfigured server must not start
        // refusing bulk exports because a library picked a number.
        let resolved = Limits::from_config(&LimitsConfig::default());
        assert!(resolved.is_unlimited());
        assert_eq!(resolved.effective_size_limit(0), 0);
        assert_eq!(resolved.effective_size_limit(5000), 5000);
    }

    #[test]
    fn the_smaller_of_the_two_limits_wins() {
        let server = limits(1000, None);

        // The client asked for everything: the server's policy applies.
        assert_eq!(server.effective_size_limit(0), 1000);
        // The client asked for more than the server offers: the server still applies.
        assert_eq!(server.effective_size_limit(10_000), 1000);
        // The client asked for less: its own limit is already stricter.
        assert_eq!(server.effective_size_limit(10), 10);
    }

    #[test]
    fn a_zero_time_limit_means_no_limit_rather_than_instant_expiry() {
        // A duration of zero would expire before the first entry and turn every search into a
        // timeout - the least useful reading of a forgotten key.
        assert_eq!(limits(0, Some(0)).time_limit, None);
        assert_eq!(limits(0, None).time_limit, None);
        assert_eq!(
            limits(0, Some(30)).time_limit,
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn the_diagnostic_only_blames_the_server_when_it_is_to_blame() {
        let server = limits(1000, None);

        assert!(
            server.server_bound(0),
            "a client that asked for everything is told the server has a policy"
        );
        assert!(
            server.server_bound(10_000),
            "and so is one that asked for more than the policy allows"
        );
        assert!(
            !server.server_bound(10),
            "a client that asked for ten and got ten knows why; blaming the server would send it \
             looking for a setting it does not need to change"
        );
    }

    #[test]
    fn an_unlimited_server_never_blames_itself() {
        let unlimited = Limits::default();
        assert!(!unlimited.server_bound(0));
        assert!(!unlimited.server_bound(10_000));
    }

    #[test]
    fn a_size_limit_alone_leaves_the_clock_alone() {
        let resolved = limits(500, None);
        assert_eq!(resolved.size_limit, 500);
        assert_eq!(resolved.time_limit, None);
        assert!(!resolved.is_unlimited());
    }
}
