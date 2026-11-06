//! What a PAC is allowed to decide.
//!
//! Kerberos proves who the client is. A PAC - the privilege attribute certificate a Windows KDC
//! puts in the ticket - also *claims* what that client may do: which SIDs it holds, when the logon
//! stops being valid. Those claims are only worth something if the signature over them verifies
//! with a key this server holds, and only useful if this server has a policy to read them with.
//!
//! Until now this server took no decision from a PAC at all (`without_pac_validation`): the
//! ticket's own signature proved the client, and authorisation came from the entry and the access
//! rules. That is still the default, and the default is deliberate - a run against MIT's KDC showed
//! that a KDC which issues a PAC this library cannot parse refuses every otherwise valid ticket, and
//! an LDAP server that suddenly stops accepting tickets is worse than one that ignores a claim it
//! was not asked to trust.
//!
//! What this module adds is the operator's choice. Three modes, named by what they trust:
//!
//! - `ignore` - the PAC is not read. Tickets verify by their own signature. The default.
//! - `verify` - the PAC is checked against the service key, and its logon expiry is honoured. A
//!   ticket without a PAC still binds: absence is not the same as a failed check.
//! - `require` - as `verify`, and a ticket without a PAC is refused. Set this when every ticket in
//!   the realm comes from a KDC that issues one, which is the AD case.
//!
//! # What is checked, and what cannot be
//!
//! The **service signature** over the PAC is verified with this service's key. The **KDC signature**
//! is not, and cannot be: it is an HMAC under the `krbtgt` key, which a service does not hold and
//! must never hold. A service that claimed to have checked it would be lying; the KDC checked it
//! when it issued the ticket, and the service trusts the ticket because it trusts the KDC that
//! signed it. This is the same boundary Samba and MIT's KDC client libraries draw.
//!
//! The **logon expiry** is honoured because it is a claim this server can act on in isolation: an
//! expired logon is a fact about the ticket, not a permission decision.
//!
//! The **account state** (`userAccountControl`) is *not* read from here. It comes from the entry,
//! which is the system of record for it, and the bind path already refuses a disabled or locked
//! account. Reading a second copy out of a PAC would create two answers to one question, and the
//! PAC's copy is the one an attacker's KDC would write.
//!
//! # Group SIDs
//!
//! `groups: true` resolves the PAC's group SIDs to entries of this directory by `objectSid`, so a
//! client from an AD world is a member of the groups the directory itself publishes, not of names
//! the ticket invented. An unknown SID is skipped and counted: a group the directory does not have
//! is a group where a search must not match, and refusing the whole bind over it would break every
//! account whose AD groups were never imported.
use std::time::SystemTime;

use crate::model::Attributes;

/// How much of a PAC this server trusts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Not read at all. Tickets verify by their own signature.
    #[default]
    Ignore,
    /// Checked when present; a ticket without a PAC still binds.
    Verify,
    /// Checked, and required.
    Require,
}

impl std::str::FromStr for Mode {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "ignore" => Ok(Self::Ignore),
            "verify" => Ok(Self::Verify),
            "require" => Ok(Self::Require),
            other => Err(format!(
                "pac mode '{other}' is not one of ignore, verify, require"
            )),
        }
    }
}

/// What the `sasl.pac` section says.
///
/// `deny_unknown_fields`, like every section in this project: a key accepted and ignored is worse
/// than a key refused, because nothing tells the operator that the trust they asked for is not
/// being given.
/// The defaults are the whole of the safe choice: `Mode::Ignore` and no groups, which is exactly
/// what every deployment had before this section existed. Derived rather than written out, so the
/// two cannot drift - a hand-written `Default` that stopped matching the field defaults would be a
/// silent change of trust, which is the last thing this setting may do quietly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PacConfig {
    /// How much of the PAC to trust. See [`Mode`], and note the default.
    pub mode: Mode,
    /// Whether the PAC's group SIDs become memberships in this directory.
    ///
    /// Off by default: it changes what a search returns for `memberOf`, and that is a decision an
    /// operator makes about their directory rather than a side effect of enabling Kerberos.
    pub groups: bool,
}

impl PacConfig {
    /// Whether the validator should check the PAC's signature.
    ///
    /// `false` maps to `ServiceValidator::without_pac_validation`, which is not a performance
    /// choice: a KDC whose PAC this library cannot parse would otherwise have every valid ticket
    /// refused.
    pub fn validates(&self) -> bool {
        !matches!(self.mode, Mode::Ignore)
    }

    /// Whether a ticket that carries no PAC is a refusal.
    pub fn requires(&self) -> bool {
        matches!(self.mode, Mode::Require)
    }
}

/// The parts of a PAC this server acts on, copied out of the library's type.
///
/// A separate struct rather than the library's `Pac`, so that the rule below is a function of plain
/// values and can be tested without building a ticket, a keytab or a KDC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The name the KDC says the client logged on as.
    pub login: String,
    /// The groups the KDC says the client holds, as SIDs.
    pub group_sids: Vec<String>,
    /// When this logon stops being valid.
    pub logoff: SystemTime,
}

impl Claim {
    /// Copies what this server reads out of a parsed PAC.
    ///
    /// `None` when the PAC carries no `KERB_VALIDATION_INFO`: a PAC without credentials says
    /// nothing about a logon, and inventing a login name from it would be worse than reading
    /// nothing.
    pub fn of(pac: &rskrb5::pac::Pac) -> Option<Self> {
        let credentials = pac.ad_credentials()?;

        Some(Self {
            login: credentials.effective_name.clone(),
            group_sids: credentials.group_membership_sids.clone(),
            logoff: credentials.logoff_time,
        })
    }

    /// Whether the logon the KDC described has run out.
    ///
    /// Taken as an absolute instant rather than compared against a raw field, because the field's
    /// "never" encoding is a sentinel rather than a date, and a comparison that treated it as a
    /// date would end every logon in the year 30828 - which is the same as never, until a clock
    /// skew or a mis-converted value makes it the past.
    ///
    /// Inclusive: a logon valid until this instant is not valid for a request that arrives at it,
    /// the same way a certificate that expires now is already expired.
    pub fn expired(&self, now: SystemTime) -> bool {
        self.logoff <= now
    }
}

/// Why a ticket was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The configuration requires a PAC and the ticket carried none.
    Missing,
    /// The KDC declared the logon over.
    Expired,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => formatter.write_str(
                "sasl.pac.mode is 'require' and the ticket carries no PAC: a ticket from a KDC \
                 that does not issue one cannot be accepted under that setting",
            ),
            Self::Expired => formatter.write_str(
                "the logon this ticket was issued for has expired (PAC logoff time is in the past)",
            ),
        }
    }
}

/// The identity a PAC declares, once the policy has accepted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    /// The logon name the KDC recorded. Used for the journal, never to address an entry: the entry
    /// comes from the principal and the realm template, which is what the client actually asked
    /// for.
    pub login: String,
    /// Group SIDs, for the caller to resolve against `objectSid`.
    pub group_sids: Vec<String>,
}

/// Applies the policy to what a ticket carried.
///
/// `claim` is `None` when the ticket had no PAC at all, which is a different fact from a PAC that
/// failed its signature - the latter never reaches here, because the validator refuses the ticket
/// before this function is called.
pub fn admit(
    claim: Option<Claim>,
    config: PacConfig,
    now: SystemTime,
) -> Result<Option<Admitted>, Refusal> {
    // `ignore` reads nothing, and says so by returning nothing: a caller that went on to use a
    // claim here would be using a value the operator said not to trust.
    if !config.validates() {
        return Ok(None);
    }

    let Some(claim) = claim else {
        return if config.requires() {
            Err(Refusal::Missing)
        } else {
            Ok(None)
        };
    };

    if claim.expired(now) {
        return Err(Refusal::Expired);
    }

    Ok(Some(Admitted {
        login: claim.login,
        group_sids: claim.group_sids,
    }))
}

/// The entries whose `objectSid` matches one of these SIDs.
///
/// Returns DN to SID for every match, and the SIDs nobody matched, so the caller can count them: a
/// group the directory does not hold is a group where a search must not match, and silence about it
/// would make a missing import look like a working group.
///
/// `objectSid` is compared as text in the form Windows prints (`S-1-5-21-...-512`), which is what
/// the schema declares it as and what an operator writes when they populate the directory by hand.
/// A directory that stores the binary form does not match here, and that is named in the
/// documentation rather than guessed at: two encodings of one value would need a rule for which
/// wins, and there is no evidence yet for which one a real deployment carries.
pub fn resolve_groups<'a>(
    entries: impl Iterator<Item = (&'a str, &'a Attributes)>,
    wanted: &[String],
) -> (Vec<(String, String)>, Vec<String>) {
    if wanted.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut found: Vec<(String, String)> = Vec::new();
    // Upper-cased, because a SID is a Windows identifier and an operator who typed it in lower case
    // made no claim about its case mattering.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (dn, attributes) in entries {
        let Some(sid) = attributes
            .get("objectSid")
            .and_then(|attribute| attribute.values.first())
        else {
            continue;
        };
        let sid = sid.trim();

        if wanted
            .iter()
            .any(|candidate| candidate.trim().eq_ignore_ascii_case(sid))
        {
            seen.insert(sid.to_ascii_uppercase());
            found.push((dn.to_string(), sid.to_string()));
        }
    }

    let unmatched = wanted
        .iter()
        .filter(|candidate| !seen.contains(&candidate.trim().to_ascii_uppercase()))
        .cloned()
        .collect();

    (found, unmatched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn claim(logoff_in: Option<Duration>) -> Claim {
        Claim {
            login: "alice@EXAMPLE.COM".to_string(),
            group_sids: vec![
                "S-1-5-21-1-2-3-513".to_string(),
                "S-1-5-21-1-2-3-512".to_string(),
            ],
            logoff: match logoff_in {
                Some(ahead) => SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000) + ahead,
                None => SystemTime::UNIX_EPOCH + Duration::from_secs(i64::MAX as u64),
            },
        }
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    #[test]
    fn the_default_reads_nothing_from_a_pac() {
        let config = PacConfig::default();
        assert_eq!(config.mode, Mode::Ignore);
        assert!(!config.validates());

        // Even a PAC that is expired, and a mode that would refuse it if it looked, returns
        // nothing: the operator said not to trust it, and a value returned here would be one the
        // caller was told to ignore.
        let admitted = admit(Some(claim(Some(Duration::from_secs(0)))), config, now());
        assert_eq!(admitted, Ok(None));
    }

    #[test]
    fn verify_accepts_a_ticket_without_a_pac_and_honours_one_that_has_it() {
        let config = PacConfig {
            mode: Mode::Verify,
            groups: false,
        };

        assert_eq!(
            admit(None, config, now()),
            Ok(None),
            "absence is not a failure"
        );

        let admitted = admit(Some(claim(Some(Duration::from_secs(60)))), config, now())
            .expect("a live logon is accepted");
        let admitted = admitted.expect("a PAC was present, so an identity comes out");
        assert_eq!(admitted.login, "alice@EXAMPLE.COM");
        assert_eq!(admitted.group_sids.len(), 2);
    }

    #[test]
    fn verify_refuses_a_logon_the_kdc_declared_over() {
        let config = PacConfig {
            mode: Mode::Verify,
            groups: false,
        };

        let refused = admit(Some(claim(Some(Duration::from_secs(0)))), config, now());
        assert_eq!(refused, Err(Refusal::Expired));
        assert!(refused.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn require_refuses_a_ticket_that_carries_no_pac() {
        let config = PacConfig {
            mode: Mode::Require,
            groups: false,
        };

        assert_eq!(admit(None, config, now()), Err(Refusal::Missing));
        // And still accepts a good one, so the refusal above is about absence and nothing else.
        assert!(admit(Some(claim(None)), config, now()).is_ok());
    }

    #[test]
    fn a_logon_that_never_expires_is_not_expired() {
        // The AD "never" encoding is a sentinel, not a date: a comparison that treated it as one
        // would be harmless today and wrong the moment a clock or a conversion disagrees.
        let forever = claim(None);
        assert!(!forever.expired(now()));
        assert!(!forever.expired(SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000)));
    }

    #[test]
    fn a_logon_expiring_exactly_now_counts_as_expired() {
        // The boundary belongs to the refusal: a logon valid until this instant is not valid for
        // the request that arrives at it.
        let ending = claim(Some(Duration::from_secs(0)));
        assert!(ending.expired(now()));
        assert!(!ending.expired(now() - Duration::from_secs(1)));
    }

    #[test]
    fn the_section_refuses_a_mode_it_does_not_know() {
        let parsed: Result<PacConfig, _> = serde_saphyr::from_str("mode: sometimes");
        assert!(
            parsed.is_err(),
            "an unknown mode must not fall back to a default"
        );

        let parsed: PacConfig = serde_saphyr::from_str("mode: require").expect("require parses");
        assert_eq!(parsed.mode, Mode::Require);
        assert!(!parsed.groups);
    }

    #[test]
    fn a_misspelled_key_in_the_section_is_refused() {
        let parsed: Result<PacConfig, _> = serde_saphyr::from_str("modes: verify");
        assert!(parsed.is_err(), "an unused key must not pass silently");
    }

    fn attributes(sid: Option<&str>) -> Attributes {
        match sid {
            Some(sid) => {
                Attributes::new().replace(crate::model::Attribute::single("objectSid", sid))
            }
            None => Attributes::new().replace(crate::model::Attribute::single("cn", "no sid")),
        }
    }

    #[test]
    fn a_group_sid_is_matched_to_the_entry_that_carries_it() {
        let domain = attributes(Some("S-1-5-21-1-2-3-512"));
        let admins = attributes(Some("S-1-5-21-1-2-3-513"));
        let nobody = attributes(None);

        let entries = vec![
            ("cn=Domain Admins,ou=groups,dc=example,dc=com", &domain),
            ("cn=Administrators,ou=groups,dc=example,dc=com", &admins),
            ("cn=alice,ou=users,dc=example,dc=com", &nobody),
        ];
        let wanted = vec!["S-1-5-21-1-2-3-513".to_string()];

        let (found, unmatched) = resolve_groups(entries.into_iter(), &wanted);

        assert_eq!(
            found,
            vec![(
                "cn=Administrators,ou=groups,dc=example,dc=com".to_string(),
                "S-1-5-21-1-2-3-513".to_string()
            )]
        );
        assert!(unmatched.is_empty());
    }

    #[test]
    fn a_sid_the_directory_does_not_hold_is_reported_rather_than_dropped() {
        let admins = attributes(Some("S-1-5-21-1-2-3-513"));
        let entries = vec![("cn=Administrators,ou=groups,dc=example,dc=com", &admins)];
        let wanted = vec![
            "S-1-5-21-1-2-3-513".to_string(),
            "S-1-5-21-9-9-9-1201".to_string(),
        ];

        let (found, unmatched) = resolve_groups(entries.into_iter(), &wanted);

        assert_eq!(found.len(), 1);
        assert_eq!(unmatched, vec!["S-1-5-21-9-9-9-1201".to_string()]);
    }

    #[test]
    fn a_sid_is_matched_without_regard_to_its_case() {
        let lower = attributes(Some("s-1-5-21-1-2-3-513"));
        let entries = vec![("cn=Administrators,ou=groups,dc=example,dc=com", &lower)];
        let wanted = vec!["S-1-5-21-1-2-3-513".to_string()];

        let (found, unmatched) = resolve_groups(entries.into_iter(), &wanted);

        assert_eq!(
            found.len(),
            1,
            "a Windows identifier has no meaningful case"
        );
        assert!(unmatched.is_empty());
    }

    #[test]
    fn with_no_sids_to_resolve_nothing_is_scanned() {
        let admins = attributes(Some("S-1-5-21-1-2-3-513"));
        let entries = vec![("cn=Administrators,ou=groups,dc=example,dc=com", &admins)];

        let (found, unmatched) = resolve_groups(entries.into_iter(), &[]);

        assert!(found.is_empty());
        assert!(unmatched.is_empty());
    }
}
