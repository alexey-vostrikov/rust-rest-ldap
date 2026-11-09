//! Security identifiers: the binary form AD stores, the text form Windows prints.
//!
//! A SID is the only identity in an AD-shaped directory that survives a rename, and three things
//! are keyed on it: an ACL, a PAC's group list, and `sIDHistory`. So the two halves of this module
//! are unequal in importance. The encoding has an existing answer - MS-DTYP §2.4.2.1 - and this
//! module follows it byte for byte. The allocation has no answer from any specification: it is a
//! policy, and the policy that matters is that a number is handed out once and never again.
//!
//! # Why both forms live here
//!
//! The directory stores the binary form, because that is what Samba and Windows read and what the
//! schema declares (`SYNTAX ...1.40`, octets). Every human who looks at the directory uses the text
//! form. Two functions in two files is how the two drift; one type that knows both is how they
//! cannot.
//!
//! # The reserved range is not an optimisation
//!
//! `500` and `512` are not "nice numbers": a domain's built-in groups are known by those numbers to
//! every client in the world, before any client has asked the directory anything. A counter that
//! began at 500 and handed them out again would produce a domain administrator nobody intended.

use std::fmt;

/// A security identifier: `S-1-5-21-a-b-c-rid`, and the octets it is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sid {
    /// Always 1. Kept as a field rather than assumed, so a value decoded from a directory that says
    /// something else is refused rather than silently read as revision 1.
    revision: u8,
    /// The identifier authority, 48 bits, big-endian in the octets. `5` is `NT Authority`, which is
    /// every SID a domain issues.
    authority: [u8; 6],
    /// The sub-authorities, each 32 bits, **little-endian** in the octets - the one place this
    /// format is not big-endian, and the one place an implementation that guessed produces a SID
    /// that looks plausible and identifies nobody.
    subauthorities: Vec<u32>,
}

/// What went wrong reading a SID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidError {
    /// The text is not `S-` followed by dash-separated numbers.
    Syntax(String),
    /// The revision is not 1.
    Revision(u8),
    /// The identifier authority does not fit in 48 bits.
    Authority(String),
    /// A sub-authority does not fit in 32 bits, or there are more than fifteen of them.
    SubAuthority(String),
    /// The octets are too short to be a SID, or say they hold more than they do.
    Truncated { want: usize, got: usize },
    /// The octets end early: the header says `count` sub-authorities and fewer arrived.
    Short { want: usize, got: usize },
}

impl fmt::Display for SidError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SidError::Syntax(detail) => write!(formatter, "not a SID: {detail}"),
            SidError::Revision(value) => {
                write!(formatter, "a SID has revision 1, this one says {value}")
            }
            SidError::Authority(detail) => write!(formatter, "identifier authority: {detail}"),
            SidError::SubAuthority(detail) => write!(formatter, "sub-authority: {detail}"),
            SidError::Truncated { want, got } => {
                write!(formatter, "a SID is at least {want} octets, got {got}")
            }
            SidError::Short { want, got } => write!(
                formatter,
                "the SID says it carries {want} octets of sub-authorities, {got} arrived"
            ),
        }
    }
}

impl std::error::Error for SidError {}

/// The most sub-authorities a SID may carry (MS-DTYP §2.4.2.1: `SubAuthorityCount` is 15 at most).
pub const MAX_SUBAUTHORITIES: usize = 15;

/// `NT Authority`, the identifier authority of every SID a domain issues.
pub const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

/// `BUILTIN`, the authority of `Administrators` and the other local groups.
pub const BUILTIN_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 2];

/// The RIDs a domain's built-in accounts and groups are known by, to every client, before the
/// client has asked anything.
pub mod reserved {
    /// The account created first and never deleted: a domain without it cannot be administered.
    pub const ADMINISTRATOR: u32 = 500;
    /// The group that holds administrators. Membership is how a domain is administered in practice.
    pub const DOMAIN_ADMINS: u32 = 512;
    /// Every account that is not a computer is a member, implicitly.
    pub const DOMAIN_USERS: u32 = 513;
    /// Every machine account.
    pub const DOMAIN_COMPUTERS: u32 = 515;
    /// The domain controllers themselves.
    pub const DOMAIN_CONTROLLERS: u32 = 516;
    /// Enterprise-wide administrators. Reserved even for a single-domain forest: a client that
    /// joins a forest asks about it, and an absent one is an answer that says the domain is odd.
    pub const ENTERPRISE_ADMINS: u32 = 519;
    /// Who may create a group policy object.
    pub const GROUP_POLICY_CREATOR_OWNERS: u32 = 520;
    /// The highest number this module treats as spoken for. Everything below it is reserved by
    /// convention, and a counter that handed one of them out would mint an account with somebody
    /// else's rights.
    pub const LAST_RESERVED: u32 = 999;
}

/// The first RID a counter may hand out.
///
/// 1000 rather than 1001: AD's own RID master starts there, and matching it means a directory that
/// later grows a second controller starts from the number the first one's blocks begin at.
pub const FIRST_UNRESERVED_RID: u32 = 1000;

impl Sid {
    /// A SID from its parts, refusing what the format cannot hold.
    pub fn new(authority: [u8; 6], subauthorities: Vec<u32>) -> Result<Self, SidError> {
        if subauthorities.len() > MAX_SUBAUTHORITIES {
            return Err(SidError::SubAuthority(format!(
                "{} sub-authorities, the format holds {MAX_SUBAUTHORITIES}",
                subauthorities.len()
            )));
        }
        Ok(Sid {
            revision: 1,
            authority,
            subauthorities,
        })
    }

    /// A domain SID: `S-1-5-21-a-b-c`.
    ///
    /// Three 32-bit numbers, which in AD are drawn at random when the domain is created. They are
    /// not a hash of the domain name: two domains deliberately created with the same name must be
    /// two different domains, or an account from one would be an account in the other.
    pub fn domain(a: u32, b: u32, c: u32) -> Self {
        Sid {
            revision: 1,
            authority: NT_AUTHORITY,
            subauthorities: vec![21, a, b, c],
        }
    }

    /// A domain SID from 16 octets of randomness, so that a caller does not have to invent one.
    ///
    /// Every octet is used, including the ones a naive implementation would leave at zero: a domain
    /// whose sub-authorities were small numbers would collide with the next domain created on the
    /// same machine, which is the case a fresh install hits first.
    pub fn domain_from_random(entropy: [u8; 16]) -> Self {
        let word = |at: usize| {
            u32::from_be_bytes([
                entropy[at],
                entropy[at + 1],
                entropy[at + 2],
                entropy[at + 3],
            ])
        };
        Sid::domain(word(0), word(4), word(8))
    }

    /// The revision, which is 1 for every SID this module produces or accepts.
    pub fn revision(&self) -> u8 {
        self.revision
    }

    /// The identifier authority.
    pub fn authority(&self) -> [u8; 6] {
        self.authority
    }

    /// The sub-authorities, in order.
    pub fn subauthorities(&self) -> &[u32] {
        &self.subauthorities
    }

    /// The RID: the last sub-authority, when this SID has one.
    ///
    /// `None` for a SID with no sub-authorities (`S-1-5`), which is a domain-level SID rather than
    /// an object in it.
    pub fn rid(&self) -> Option<u32> {
        self.subauthorities.last().copied()
    }

    /// The SID this one is an object of: `S-1-5-21-a-b-c-rid` gives `S-1-5-21-a-b-c`.
    ///
    /// `None` at the domain itself, where removing a sub-authority would produce a different
    /// authority's SID rather than a parent.
    pub fn parent(&self) -> Option<Sid> {
        if self.subauthorities.len() <= 4 {
            return None;
        }
        Some(Sid {
            revision: self.revision,
            authority: self.authority,
            subauthorities: self.subauthorities[..self.subauthorities.len() - 1].to_vec(),
        })
    }

    /// The octets AD stores: revision, count, six of authority, then each sub-authority
    /// little-endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 4 * self.subauthorities.len());
        out.push(self.revision);
        out.push(self.subauthorities.len() as u8);
        out.extend_from_slice(&self.authority);
        for value in &self.subauthorities {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }

    /// A SID from the octets a directory holds.
    ///
    /// Suspicious on purpose: these bytes come from a store other programs write, and a SID that is
    /// one octet short would otherwise be read as a slightly different SID - which is an account
    /// with somebody else's rights rather than an error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SidError> {
        if bytes.len() < 8 {
            return Err(SidError::Truncated {
                want: 8,
                got: bytes.len(),
            });
        }
        let revision = bytes[0];
        if revision != 1 {
            return Err(SidError::Revision(revision));
        }
        let count = bytes[1] as usize;
        if count > MAX_SUBAUTHORITIES {
            return Err(SidError::SubAuthority(format!(
                "the octets say {count} sub-authorities, the format holds {MAX_SUBAUTHORITIES}"
            )));
        }
        let want = 8 + 4 * count;
        if bytes.len() < want {
            return Err(SidError::Short {
                want,
                got: bytes.len(),
            });
        }
        // Trailing octets are refused rather than ignored: a value longer than its header says is a
        // value written by something that disagreed with this format, and choosing which half to
        // believe is how two implementations come to disagree about an account's identity.
        if bytes.len() > want {
            return Err(SidError::Short {
                want,
                got: bytes.len(),
            });
        }

        let mut authority = [0u8; 6];
        authority.copy_from_slice(&bytes[2..8]);
        let mut subauthorities = Vec::with_capacity(count);
        for index in 0..count {
            let at = 8 + 4 * index;
            subauthorities.push(u32::from_le_bytes([
                bytes[at],
                bytes[at + 1],
                bytes[at + 2],
                bytes[at + 3],
            ]));
        }

        Ok(Sid {
            revision,
            authority,
            subauthorities,
        })
    }

    /// Reads `S-1-5-21-a-b-c-rid`.
    pub fn parse(text: &str) -> Result<Self, SidError> {
        let text = text.trim();
        let mut parts = text.split('-');
        match parts.next() {
            Some(prefix) if prefix.eq_ignore_ascii_case("S") => {}
            _ => {
                return Err(SidError::Syntax(format!(
                    "'{text}' does not begin with 'S-'"
                )));
            }
        }

        let revision: u8 = parts
            .next()
            .ok_or_else(|| SidError::Syntax(format!("'{text}' has no revision")))?
            .parse()
            .map_err(|_| SidError::Syntax(format!("'{text}': the revision is not a number")))?;
        if revision != 1 {
            return Err(SidError::Revision(revision));
        }

        let authority_text = parts
            .next()
            .ok_or_else(|| SidError::Syntax(format!("'{text}' has no identifier authority")))?;
        let authority = if let Some(hex) = authority_text.strip_prefix("0x") {
            // MS-DTYP allows the hexadecimal spelling for an authority above 2^32, which no domain
            // uses and which a parser still has to accept rather than reject as malformed.
            u64::from_str_radix(hex, 16).map_err(|_| {
                SidError::Authority(format!("'{authority_text}' is not hexadecimal"))
            })?
        } else {
            authority_text
                .parse::<u64>()
                .map_err(|_| SidError::Authority(format!("'{authority_text}' is not a number")))?
        };
        if authority > 0xFFFF_FFFF_FFFF {
            return Err(SidError::Authority(format!(
                "'{authority_text}' does not fit in 48 bits"
            )));
        }
        let mut authority_bytes = [0u8; 6];
        authority_bytes.copy_from_slice(&authority.to_be_bytes()[2..]);

        let mut subauthorities = Vec::new();
        for part in parts {
            if subauthorities.len() == MAX_SUBAUTHORITIES {
                return Err(SidError::SubAuthority(format!(
                    "'{text}' carries more than {MAX_SUBAUTHORITIES} sub-authorities"
                )));
            }
            let value: u32 = part
                .parse()
                .map_err(|_| SidError::SubAuthority(format!("'{part}' is not a 32-bit number")))?;
            subauthorities.push(value);
        }

        Ok(Sid {
            revision,
            authority: authority_bytes,
            subauthorities,
        })
    }
}

impl fmt::Display for Sid {
    /// The text form Windows prints, which is also the form an operator writes by hand.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let authority = self
            .authority
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        write!(formatter, "S-{}-{}", self.revision, authority)?;
        for value in &self.subauthorities {
            write!(formatter, "-{value}")?;
        }
        Ok(())
    }
}

/// The name the directory gives a SID.
pub const ATTRIBUTE: &str = "objectSid";

impl Sid {
    /// The value a directory holds: base64 of the octets, because the octets are not text.
    ///
    /// One form in the store, and it is the form LDIF writes, so a value that arrived in a file
    /// needs no conversion on the way in and none on the way out.
    pub fn to_directory_value(&self) -> String {
        crate::model::encode_binary(&self.to_bytes())
    }

    /// A SID from a value a directory holds, in either form it can be in.
    ///
    /// The binary form is what this server writes. The text form is what an operator writes by
    /// hand, what `ldif` from an AD export can carry, and what a filter compares against - so it is
    /// **converted**, not refused: a directory that rejected `S-1-5-21-...` would refuse the only
    /// spelling a human can type, and the task of noticing that the value is a SID is one this
    /// function can do.
    pub fn from_directory_value(text: &str) -> Result<Self, SidError> {
        let text = text.trim();
        if text.starts_with("S-") || text.starts_with("s-") {
            return Sid::parse(text);
        }
        let bytes = crate::model::decode_binary(text).ok_or_else(|| {
            SidError::Syntax(format!(
                "'{text}' is neither a SID ({ATTRIBUTE}) nor base64 of one"
            ))
        })?;
        Sid::from_bytes(&bytes)
    }

    /// This SID as a directory attribute, in the binary form.
    #[must_use]
    pub fn attribute(&self, name: &str) -> crate::model::Attribute {
        crate::model::Attribute::new(name, vec![self.to_directory_value()]).binary()
    }
}

/// A domain SID and the counter that issues RIDs inside it.
///
/// The counter is a value, not a store: whoever owns the directory holds the number and hands it
/// here, so that a restart cannot begin again from the beginning. That is the whole reason this type
/// exists rather than a global - a counter in memory would hand out the same RID twice on the second
/// start, and the second account would inherit the first one's rights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RidAllocator {
    domain: Sid,
    next: u32,
}

impl RidAllocator {
    /// A counter positioned at `next`, refusing a position inside the reserved range.
    ///
    /// Refused rather than rounded up: a caller reading 500 from a store is a caller whose domain was
    /// initialised wrongly, and starting from 1000 would hide that for ever while the accounts that
    /// were given reserved numbers keep them.
    pub fn at(domain: Sid, next: u32) -> Result<Self, String> {
        if domain.subauthorities().len() != 4 {
            return Err(format!(
                "a domain SID is S-1-5-21-a-b-c, '{domain}' has {} sub-authorities",
                domain.subauthorities().len()
            ));
        }
        if next <= reserved::LAST_RESERVED {
            return Err(format!(
                "the counter stands at {next}, inside the reserved range (up to {})",
                reserved::LAST_RESERVED
            ));
        }
        // The last number is refused as a *position*, because a counter standing there cannot be
        // advanced after handing it out: `checked_add` has nothing to add, and a store that wrote
        // `u32::MAX` would read back a counter that hands the same number out for ever. Losing one
        // number at the end of four billion is cheaper than a state that cannot be persisted.
        if next == u32::MAX {
            return Err(format!(
                "{next} is the last RID, and a counter standing there cannot move past it"
            ));
        }
        Ok(RidAllocator { domain, next })
    }

    /// A fresh counter for a new domain.
    pub fn fresh(domain: Sid) -> Result<Self, String> {
        RidAllocator::at(domain, FIRST_UNRESERVED_RID)
    }

    /// The domain these RIDs belong to.
    pub fn domain(&self) -> &Sid {
        &self.domain
    }

    /// The number the next call to `take` will use, which is what a store persists.
    pub fn peek(&self) -> u32 {
        self.next
    }

    /// Takes the next RID.
    ///
    /// Checked addition, not wrapping: the day a counter reaches `u32::MAX` is the day a domain must
    /// stop, and wrapping would produce a SID that already exists - an account with an existing
    /// account's rights, created silently.
    pub fn take(&mut self) -> Result<Sid, String> {
        let rid = self.next;
        self.next = self.next.checked_add(1).ok_or_else(|| {
            "the RID counter is exhausted; this domain cannot issue more".to_string()
        })?;
        Sid::new(self.domain.authority, {
            let mut parts = self.domain.subauthorities.clone();
            parts.push(rid);
            parts
        })
        .map_err(|err| err.to_string())
    }

    /// The SID of a built-in account or group.
    ///
    /// Does not touch the counter: a reserved RID is spoken for before the domain exists, and taking
    /// one out of the sequence would leave a hole nobody can explain a year later.
    pub fn reserved(&self, rid: u32) -> Result<Sid, String> {
        if rid > reserved::LAST_RESERVED {
            return Err(format!(
                "{rid} is not a reserved RID; reserved ends at {}",
                reserved::LAST_RESERVED
            ));
        }
        Sid::new(self.domain.authority, {
            let mut parts = self.domain.subauthorities.clone();
            parts.push(rid);
            parts
        })
        .map_err(|err| err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_binary_form_is_the_one_windows_uses() {
        // Three vectors a reader can check by hand, which is why they are these three. Everything
        // that looks wrong about a SID implementation - and it will look wrong - is visible here:
        // the authority is big-endian, the sub-authorities are little-endian, and the count is the
        // second octet.
        let cases: [(&str, &[u8]); 3] = [
            // Everyone: S-1-1-0
            ("S-1-1-0", &[0x01, 0x01, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0]),
            // BUILTIN\Administrators: S-1-5-32-544
            (
                "S-1-5-32-544",
                &[
                    0x01, 0x02, 0, 0, 0, 0, 0, 0x05, 0x20, 0, 0, 0, 0x20, 0x02, 0, 0,
                ],
            ),
            // A domain administrator in a made-up domain: S-1-5-21-1-2-3-500
            (
                "S-1-5-21-1-2-3-500",
                &[
                    0x01, 0x05, 0, 0, 0, 0, 0, 0x05, 0x15, 0, 0, 0, 0x01, 0, 0, 0, 0x02, 0, 0, 0,
                    0x03, 0, 0, 0, 0xF4, 0x01, 0, 0,
                ],
            ),
        ];

        for (text, bytes) in cases {
            let sid = Sid::parse(text).unwrap_or_else(|err| panic!("{text}: {err}"));
            assert_eq!(sid.to_bytes(), bytes, "{text} encoded");
            assert_eq!(
                Sid::from_bytes(bytes).unwrap_or_else(|err| panic!("{text}: {err}")),
                sid,
                "{text} decoded"
            );
            assert_eq!(sid.to_string(), text, "{text} printed back");
        }
    }

    #[test]
    fn a_sid_prints_as_the_text_a_person_wrote() {
        let sid = Sid::domain(0x1122_3344, 0x5566_7788, 0x99AA_BBCC);
        assert_eq!(sid.to_string(), "S-1-5-21-287454020-1432778632-2578103244");
        assert_eq!(Sid::parse(&sid.to_string()).expect("round trip"), sid);
    }

    #[test]
    fn the_rid_is_the_last_sub_authority_and_the_parent_is_the_domain() {
        let domain = Sid::domain(1, 2, 3);
        let user = domain_with(&domain, 1500);

        assert_eq!(user.rid(), Some(1500));
        assert_eq!(user.parent(), Some(domain.clone()));
        // The domain itself has no parent: dropping a sub-authority would produce an authority's
        // SID, not a smaller domain.
        assert_eq!(domain.parent(), None);
        assert_eq!(
            domain.rid(),
            Some(3),
            "a domain has a RID: its third number"
        );
    }

    fn domain_with(domain: &Sid, rid: u32) -> Sid {
        let mut parts = domain.subauthorities().to_vec();
        parts.push(rid);
        Sid::new(domain.authority(), parts).expect("a SID")
    }

    #[test]
    fn a_sid_from_a_directory_is_read_suspiciously() {
        // Every one of these is a value a store can hold. Reading each as a slightly different SID
        // is how an account ends up with another account's rights, so each is refused by name.
        // Eight octets with a count of zero is `S-1-5`: a valid SID with no sub-authorities, which
        // is a domain-level SID rather than an object in it.
        let empty = Sid::from_bytes(&[0x01, 0x00, 0, 0, 0, 0, 0, 0x05]).expect("a valid empty SID");
        assert_eq!(empty.to_string(), "S-1-5");
        assert_eq!(empty.rid(), None);
        assert_eq!(
            Sid::from_bytes(&[0x01, 0x01, 0, 0, 0, 0, 0, 0x05]),
            Err(SidError::Short { want: 12, got: 8 })
        );
        assert_eq!(
            Sid::from_bytes(&[0x02, 0x00, 0, 0, 0, 0, 0, 0x05]),
            Err(SidError::Revision(2))
        );
        assert_eq!(
            Sid::from_bytes(&[0x01, 0x00, 0, 0, 0, 0, 0, 0x05, 0x00]),
            Err(SidError::Short { want: 8, got: 9 }),
            "a value longer than its header says is a disagreement, not padding"
        );
        match Sid::from_bytes(&[0x01, 0x02]) {
            Err(SidError::Truncated { want: 8, got: 2 }) => {}
            other => panic!("expected a truncation, got {other:?}"),
        }
    }

    #[test]
    fn text_that_is_not_a_sid_is_refused_with_the_reason() {
        for text in [
            "1-5-21",
            "S-x-5",
            "S-1-five",
            "S-2-5-32",
            "S-1-5-32-4294967296",
        ] {
            assert!(Sid::parse(text).is_err(), "'{text}' must be refused");
        }
        // The hexadecimal authority MS-DTYP allows, which no domain uses and a parser still accepts.
        let sid = Sid::parse("S-1-0x1234-0").expect("hexadecimal authority");
        assert_eq!(sid.authority(), [0, 0, 0, 0, 0x12, 0x34]);
    }

    #[test]
    fn a_domain_drawn_from_randomness_uses_all_sixteen_octets() {
        // The failure this prevents: three sub-authorities filled from four octets each and twelve
        // octets ignored, which produces the same domain SID for every domain created on a machine.
        let low = Sid::domain_from_random([0u8; 16]);
        let high = Sid::domain_from_random([0xFFu8; 16]);
        assert_ne!(low, high);
        assert_eq!(low.subauthorities(), &[21, 0, 0, 0]);
        assert_eq!(high.subauthorities(), &[21, u32::MAX, u32::MAX, u32::MAX]);

        let domain =
            Sid::domain_from_random([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(
            domain.subauthorities(),
            &[21, 0x0102_0304, 0x0506_0708, 0x090A_0B0C],
            "each group of four octets is a number, big-endian; the last four are unused by the format"
        );
    }

    #[test]
    fn the_counter_hands_each_number_out_once() {
        let domain = Sid::domain(1, 2, 3);
        let mut allocator = RidAllocator::fresh(domain.clone()).expect("a fresh counter");

        assert_eq!(allocator.peek(), FIRST_UNRESERVED_RID);
        let first = allocator.take().expect("a SID");
        let second = allocator.take().expect("a SID");

        assert_eq!(first.rid(), Some(1000));
        assert_eq!(second.rid(), Some(1001));
        assert_ne!(first, second);
        assert_eq!(
            allocator.peek(),
            1002,
            "the counter moves past what it handed out"
        );
        // Both belong to the domain they were issued in, which is what makes the SID an identity
        // and not just a number.
        assert_eq!(first.parent(), Some(domain.clone()));
    }

    #[test]
    fn the_counter_refuses_to_start_inside_the_reserved_range() {
        // Rounded up instead of refused, a wrongly initialised domain would keep the reserved
        // numbers it had already handed out and hide the mistake for ever.
        let domain = Sid::domain(1, 2, 3);
        assert!(RidAllocator::at(domain.clone(), 500).is_err());
        assert!(RidAllocator::at(domain.clone(), 999).is_err());
        assert!(RidAllocator::at(domain.clone(), 1000).is_ok());
    }

    #[test]
    fn a_reserved_rid_does_not_consume_a_number() {
        let domain = Sid::domain(1, 2, 3);
        let allocator = RidAllocator::fresh(domain).expect("a counter");

        let admin = allocator.reserved(reserved::ADMINISTRATOR).expect("a SID");
        let admins = allocator.reserved(reserved::DOMAIN_ADMINS).expect("a SID");

        assert_eq!(admin.to_string(), "S-1-5-21-1-2-3-500");
        assert_eq!(admins.to_string(), "S-1-5-21-1-2-3-512");
        assert_eq!(
            allocator.peek(),
            FIRST_UNRESERVED_RID,
            "a built-in account is spoken for before the domain exists; taking it from the \
             sequence would leave a gap nobody can explain later"
        );
        assert!(allocator.reserved(1000).is_err());
    }

    #[test]
    fn an_exhausted_counter_refuses_rather_than_wrapping() {
        // Wrapping would produce a SID that already exists, which is an account with an existing
        // account's rights - created silently, on the day of the wrap, in a domain nobody expects
        // to fail. The last position is refused at construction for the same reason: a counter
        // standing there cannot be persisted once it has handed its number out.
        let domain = Sid::domain(1, 2, 3);
        assert!(
            RidAllocator::at(domain.clone(), u32::MAX).is_err(),
            "the last position cannot be persisted after its number is issued"
        );

        let mut allocator = RidAllocator::at(domain, u32::MAX - 1).expect("the second-to-last");
        assert_eq!(allocator.take().expect("a SID").rid(), Some(u32::MAX - 1));
        assert!(
            allocator.take().is_err(),
            "and then there is no position to move to"
        );
    }

    #[test]
    fn a_counter_over_something_that_is_not_a_domain_is_refused() {
        // `S-1-5-32-544` is a built-in SID, not a domain: issuing RIDs under it would create
        // accounts inside BUILTIN, which exist in no directory and are trusted by every client.
        let builtin = Sid::parse("S-1-5-32-544").expect("a SID");
        assert!(RidAllocator::fresh(builtin).is_err());
    }
}
