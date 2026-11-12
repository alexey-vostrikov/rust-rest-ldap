//! One `dnsProperty` value: a zone setting in the shape [MS-DNSP] 2.3.2.1 gives it.
//!
//! ```text
//! DataLength  4   octets of Data; 0 means "the default for this Id"
//! NameLength  4   unused, and a reader must assume 1
//! Flag        4   reserved, zero
//! Version     4   must be 1
//! Id          4   which property this is
//! Data        n   by Id
//! Name        1   unused, ignored
//! ```
//!
//! The ids are **bit flags, not a sequence**: type is `0x01`, allow-update `0x02`, secure-time
//! `0x08`, no-refresh `0x10`, refresh `0x20`, aging `0x40`, aging-enabled-time `0x12`. A zone's blob
//! is the set of these as separate attribute values, and reading them as 1..7 is the mistake the
//! numbering invites - `0x10` is the no-refresh interval and not "the fourth property".
//!
//! A property whose `DataLength` is zero means "this zone does not set it, use the default". Kept as
//! an explicit case rather than filled in, because a server that writes today's defaults into every
//! zone makes tomorrow's default change a migration.

use thiserror::Error;

/// Octets before `Data`: the five words, and the one unused name octet after it.
const HEADER: usize = 20;

/// The zone is a primary one: the answer to [`Id::ZoneType`].
pub const ZONE_TYPE_PRIMARY: u32 = 1;

/// Dynamic updates come from any client, or only from one that signed them.
pub const UPDATE_UNSECURE: u32 = 1;
pub const UPDATE_SECURE: u32 = 2;

/// A zone property, by the id the specification gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Id(pub u32);

impl Id {
    pub const ZONE_TYPE: Self = Self(0x0000_0001);
    pub const ALLOW_UPDATE: Self = Self(0x0000_0002);
    pub const SECURE_TIME: Self = Self(0x0000_0008);
    pub const NOREFRESH_INTERVAL: Self = Self(0x0000_0010);
    pub const REFRESH_INTERVAL: Self = Self(0x0000_0020);
    pub const AGING_STATE: Self = Self(0x0000_0040);
    pub const AGING_ENABLED_TIME: Self = Self(0x0000_0012);
}

/// One property value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    pub id: Id,
    /// The data as stored. Empty means "unset, use the default".
    pub data: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("a property is at least {HEADER} octets plus one and this one is {len}")]
    TooShort { len: usize },
    #[error("the property declares {declared} octets of data and leaves {available}")]
    LengthMismatch { declared: usize, available: usize },
    #[error("version {0}, and only 1 is read")]
    Version(u32),
    #[error("{0} octets after the value, and they are not pad")]
    TrailingBytes(usize),
    #[error("a {name} property carries four octets of data and this one carries {got}")]
    NotAWord { name: &'static str, got: usize },
}

impl Property {
    /// A property carrying a 32-bit value, which is what every setting here is.
    pub fn word(id: Id, value: u32, little_endian: bool) -> Self {
        Self {
            id,
            data: if little_endian {
                value.to_le_bytes().to_vec()
            } else {
                value.to_be_bytes().to_vec()
            },
        }
    }

    /// A property this zone does not set, so a reader uses the default for its id.
    pub fn unset(id: Id) -> Self {
        Self {
            id,
            data: Vec::new(),
        }
    }

    /// The 32-bit value, when this property carries one.
    pub fn as_word(&self, little_endian: bool) -> Option<u32> {
        let octets: [u8; 4] = self.data.as_slice().try_into().ok()?;
        Some(if little_endian {
            u32::from_le_bytes(octets)
        } else {
            u32::from_be_bytes(octets)
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER + 1 {
            return Err(Error::TooShort { len: bytes.len() });
        }
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let declared = word(0) as usize;
        // 4..8 is NameLength, unused; 8..12 is Flag, reserved. Read past rather than enforced: a
        // value refused here is a whole zone whose properties will not load.
        let version = word(12);
        if version != 1 {
            return Err(Error::Version(version));
        }
        let id = Id(word(16));

        let available = bytes.len() - HEADER;
        if declared > available {
            return Err(Error::LengthMismatch {
                declared,
                available,
            });
        }
        // The last octet is the unused `Name`, which the specification fixes at one octet.
        let trailing = &bytes[HEADER + declared..];
        if trailing.len() != 1 && trailing.iter().any(|octet| *octet != 0) {
            return Err(Error::TrailingBytes(trailing.len()));
        }

        Ok(Self {
            id,
            data: bytes[HEADER..HEADER + declared].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.data.len() + 1);
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&self.id.0.to_le_bytes());
        out.extend_from_slice(&self.data);
        // The unused trailing name octet, which the reader is told to ignore and which is present in
        // every value written by every implementation.
        out.push(0);
        out
    }
}

/// The properties a zone of this server carries, in the order a reader is given them.
///
/// Deliberately the seven the specification names for a zone and nothing else: aging off, both
/// intervals at the default a week, updates allowed only when signed. Writing a value for a property
/// this server does not implement would claim a behaviour it does not have.
///
/// Every setting here is a `DWORD` in little-endian: that is the order of this attribute's own header
/// fields and of `dwSerial` in `dnsRecord`. `SecureTime` is the one value written by somebody else (a
/// client that secured the zone), and until a value from a live directory says otherwise it is read
/// the same way as its neighbours rather than as a second convention.
pub fn for_zone(updates: u32, secure_time: u32) -> Vec<Property> {
    vec![
        Property::word(Id::ZONE_TYPE, ZONE_TYPE_PRIMARY, true),
        Property::word(Id::ALLOW_UPDATE, updates, true),
        Property::word(Id::SECURE_TIME, secure_time, true),
        Property::word(Id::NOREFRESH_INTERVAL, 168, true),
        Property::word(Id::REFRESH_INTERVAL, 168, true),
        Property::word(Id::AGING_STATE, 0, true),
        Property::word(Id::AGING_ENABLED_TIME, 0, true),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ids are bit flags: reading them as "the nth property" is the mistake the numbering
    /// invites, and this pins the two that differ.
    #[test]
    fn the_ids_are_bit_flags_and_not_a_sequence() {
        assert_eq!(Id::NOREFRESH_INTERVAL.0, 0x10, "not the fourth property");
        assert_eq!(Id::REFRESH_INTERVAL.0, 0x20);
        assert_eq!(Id::AGING_STATE.0, 0x40);
        assert_eq!(Id::AGING_ENABLED_TIME.0, 0x12, "not 0x07");
        assert_eq!(Id::SECURE_TIME.0, 0x08);
        // And the ones that do look sequential do not collide with the flags above.
        assert_eq!(Id::ZONE_TYPE.0, 0x01);
        assert_eq!(Id::ALLOW_UPDATE.0, 0x02);
    }

    #[test]
    fn a_property_survives_a_round_trip() {
        for property in for_zone(UPDATE_SECURE, 1_700_000_000) {
            let octets = property.encode();
            assert_eq!(Property::decode(&octets), Ok(property.clone()));
        }
    }

    #[test]
    fn the_header_is_five_words_and_a_name_octet() {
        let property = Property::word(Id::ALLOW_UPDATE, UPDATE_SECURE, true);
        let octets = property.encode();
        assert_eq!(octets.len(), HEADER + 4 + 1);
        assert_eq!(
            &octets[0..4],
            &4u32.to_le_bytes(),
            "DataLength is the data alone"
        );
        assert_eq!(
            &octets[4..8],
            &1u32.to_le_bytes(),
            "NameLength is unused and must be 1"
        );
        assert_eq!(&octets[8..12], &0u32.to_le_bytes(), "Flag is reserved");
        assert_eq!(&octets[12..16], &1u32.to_le_bytes(), "Version is 1");
        assert_eq!(&octets[16..20], &Id::ALLOW_UPDATE.0.to_le_bytes());
        assert_eq!(octets[HEADER + 4], 0, "the unused name octet is present");
    }

    /// `DataLength` zero means "use the default for this id" - an unset property, not a missing one.
    #[test]
    fn an_unset_property_has_no_data_and_reads_back_as_unset() {
        let property = Property::unset(Id::SECURE_TIME);
        let octets = property.encode();
        assert_eq!(&octets[0..4], &0u32.to_le_bytes());
        assert_eq!(Property::decode(&octets), Ok(property));
        assert_eq!(Property::unset(Id::SECURE_TIME).as_word(true), None);
    }

    #[test]
    fn a_version_this_build_does_not_read_is_refused() {
        let mut octets = Property::word(Id::ZONE_TYPE, ZONE_TYPE_PRIMARY, true).encode();
        octets[12..16].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(Property::decode(&octets), Err(Error::Version(2)));
    }

    #[test]
    fn a_length_longer_than_the_value_is_refused() {
        let mut octets = Property::word(Id::ZONE_TYPE, ZONE_TYPE_PRIMARY, true).encode();
        octets[0..4].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(
            Property::decode(&octets),
            Err(Error::LengthMismatch {
                declared: 40,
                available: 5
            })
        );
    }
}
