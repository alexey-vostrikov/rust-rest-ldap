//! One `dnsRecord` value: a resource record in the shape [MS-DNSP] gives it in LDAP.
//!
//! The attribute is multi-valued and each value holds **one** record, header and data:
//!
//! ```text
//! DataLength  2   the length of Data, and nothing else
//! Type        2   the record type
//! Version     1   0x05, and the only version this reads
//! Rank        1   the low byte of a RANK_* flag
//! Flags       2   zero
//! Serial      4   the SOA serial of the zone holding this record
//! TtlSeconds  4   **big-endian**, unlike every other number here
//! Reserved    4   zero
//! TimeStamp   4   hours since the record was last updated
//! Data        n   by type
//! ```
//!
//! The one field with a different byte order is called out in the specification and is the reason
//! [`tests::the_ttl_is_big_endian_while_the_rest_is_not`] exists: a byte swap here reads as a record
//! that expires in 1,610,612,736 seconds, which no client reports as an error - it just never
//! expires.
//!
//! A name is stored as `DNS_COUNT_NAME`: a length, a label count, then the labels as `(length, bytes)`
//! pairs. It is not the wire format of RFC 1035 - the labels are the same, the header is not - and it
//! carries no root label at the end, so `""` is the root and `"ad.example.com"` is three labels.

use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

/// The version byte the specification fixes, and the only one this reads.
pub const VERSION: u8 = 5;

/// The rank of a record that lives in an authoritative zone (`RANK_ZONE`).
pub const RANK_ZONE: u8 = 0xF0;

/// Header octets before the data: every field in the layout above but `Data`.
const HEADER: usize = 24;

/// Record types, by their number. Named rather than spelled in place, because a zone's correctness
/// is read as `Type::Srv` and not as `33`.
pub mod kind {
    pub const ZERO: u16 = 0x0000;
    pub const A: u16 = 0x0001;
    pub const NS: u16 = 0x0002;
    pub const CNAME: u16 = 0x0005;
    pub const SOA: u16 = 0x0006;
    pub const PTR: u16 = 0x000C;
    pub const MX: u16 = 0x000F;
    pub const AAAA: u16 = 0x001C;
    pub const DNAME: u16 = 0x0027;
    pub const SRV: u16 = 0x0021;
}

/// A record read from, or to be written to, the `dnsRecord` attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The type, kept beside the data rather than inferred from it: a record of a type this build
    /// does not read is still a record of *that* type when it is written back.
    pub rtype: u16,
    /// Seconds the record stays valid for.
    pub ttl: u32,
    /// The low byte of a `RANK_*` flag; `RANK_ZONE` for a record in an authoritative zone.
    pub rank: u8,
    /// The serial of the zone holding this record, as the record remembers it.
    pub serial: u32,
    /// Hours since the record was last updated.
    pub timestamp: u32,
    pub data: Data,
}

/// The data half of a record, by the types this build reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// A single name: `NS`, `CNAME`, `PTR`, `DNAME`.
    Name(String),
    Soa(Soa),
    Mx {
        preference: u16,
        exchange: String,
    },
    Srv(Srv),
    /// A tombstoned record: `DNS_TYPE_ZERO`, the timestamp it was deleted at, in FILETIME units.
    Tombstone(u64),
    /// A type this build does not read, carried through unchanged.
    ///
    /// Not an error and not a loss: a zone is a tree other tools write to, and the DNSSEC types are
    /// on the roadmap rather than here yet. Dropping what cannot be named would turn writing one
    /// record into deleting the rest.
    Other(Vec<u8>),
}

/// The `SOA` a zone is defined by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Soa {
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    /// The primary name server, `mname`.
    pub primary: String,
    /// The mailbox of the zone's administrator, `rname`, with a dot where the address has `@`.
    pub admin: String,
}

/// A service locator, which is what a member's SRV lookups return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("a record is at least {HEADER} octets and this one is {len}")]
    TooShort { len: usize },
    #[error("the record declares {declared} octets of data and leaves {available}")]
    LengthMismatch { declared: usize, available: usize },
    #[error("record version {0}, and only {VERSION} is read")]
    Version(u8),
    #[error("a name of {len} octets does not split into the {labels} labels it declares")]
    BadName { len: usize, labels: u8 },
    #[error("{0} octets after the record, and they are not pad")]
    TrailingBytes(usize),
    #[error("type {kind} carries {expected} octets and this one carries {got}")]
    DataLength {
        kind: u16,
        expected: usize,
        got: usize,
    },
    #[error("a label of {0} octets cannot be written: a label is at most 63")]
    LongLabel(usize),
    #[error("the data does not have the shape type {kind} carries")]
    TypeMismatch { kind: u16 },
}

impl Record {
    /// A record for an authoritative zone: rank `RANK_ZONE`, no serial or timestamp of its own.
    pub fn zone(rtype: u16, ttl: u32, data: Data) -> Self {
        Self {
            rtype,
            ttl,
            rank: RANK_ZONE,
            serial: 0,
            timestamp: 0,
            data,
        }
    }

    /// Reads one attribute value.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER {
            return Err(Error::TooShort { len: bytes.len() });
        }
        let declared = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        let rtype = u16::from_le_bytes([bytes[2], bytes[3]]);
        let version = bytes[4];
        if version != VERSION {
            return Err(Error::Version(version));
        }
        let rank = bytes[5];
        // 6..8 flags and 16..20 reserved are zero in every record this has met: read past
        // rather than enforced, because a value refused here is a whole zone that will not load.
        let serial = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let ttl = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let timestamp = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);

        let available = bytes.len() - HEADER;
        if declared > available {
            return Err(Error::LengthMismatch {
                declared,
                available,
            });
        }
        // The structure is 4-byte aligned and its pad octets are not counted in `DataLength`, so a
        // value may carry up to three. Anything else after the data is a record this does not read.
        let trailing = &bytes[HEADER + declared..];
        if trailing.len() > 3 || trailing.iter().any(|octet| *octet != 0) {
            return Err(Error::TrailingBytes(trailing.len()));
        }

        let data = decode_data(rtype, &bytes[HEADER..HEADER + declared])?;
        Ok(Self {
            rtype,
            ttl,
            rank,
            serial,
            timestamp,
            data,
        })
    }

    /// Writes one attribute value.
    ///
    /// The pad octets the structure is aligned by are not written: a value is read by `DataLength`,
    /// and a reader that trusts it has no use for them.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        // A record whose data does not match its type cannot be written as itself, and writing the
        // type over data of another shape would produce a value every reader disagrees about.
        let matching = matches!(
            (&self.data, self.rtype),
            (Data::A(_), kind::A)
                | (Data::Aaaa(_), kind::AAAA)
                | (Data::Soa(_), kind::SOA)
                | (Data::Mx { .. }, kind::MX)
                | (Data::Srv(_), kind::SRV)
                | (Data::Tombstone(_), kind::ZERO)
                | (
                    Data::Name(_),
                    kind::NS | kind::CNAME | kind::PTR | kind::DNAME
                )
                | (Data::Other(_), _)
        );
        if !matching {
            return Err(Error::TypeMismatch { kind: self.rtype });
        }

        let data = encode_data(&self.data)?;
        let length = u16::try_from(data.len()).map_err(|_| Error::DataLength {
            kind: self.rtype,
            expected: usize::from(u16::MAX),
            got: data.len(),
        })?;

        let mut out = Vec::with_capacity(HEADER + data.len());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&self.rtype.to_le_bytes());
        out.push(VERSION);
        out.push(self.rank);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.serial.to_le_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&data);
        Ok(out)
    }
}

fn decode_data(rtype: u16, data: &[u8]) -> Result<Data, Error> {
    let fixed = |expected: usize| -> Result<(), Error> {
        if data.len() == expected {
            return Ok(());
        }
        Err(Error::DataLength {
            kind: rtype,
            expected,
            got: data.len(),
        })
    };
    match rtype {
        kind::A => {
            fixed(4)?;
            Ok(Data::A(Ipv4Addr::new(data[0], data[1], data[2], data[3])))
        }
        kind::AAAA => {
            fixed(16)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(data);
            Ok(Data::Aaaa(Ipv6Addr::from(octets)))
        }
        kind::NS | kind::CNAME | kind::PTR | kind::DNAME => {
            let (name, used) = read_name(data)?;
            if used != data.len() {
                return Err(Error::TrailingBytes(data.len() - used));
            }
            Ok(Data::Name(name))
        }
        kind::SOA => {
            if data.len() < 20 {
                return Err(Error::DataLength {
                    kind: rtype,
                    expected: 20,
                    got: data.len(),
                });
            }
            let number = |at: usize| {
                u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
            };
            let (primary, after_primary) = read_name(&data[20..])?;
            let (admin, after_admin) = read_name(&data[20 + after_primary..])?;
            if 20 + after_primary + after_admin != data.len() {
                return Err(Error::TrailingBytes(
                    data.len() - 20 - after_primary - after_admin,
                ));
            }
            Ok(Data::Soa(Soa {
                serial: number(0),
                refresh: number(4),
                retry: number(8),
                expire: number(12),
                minimum: number(16),
                primary,
                admin,
            }))
        }
        kind::MX => {
            if data.len() < 2 {
                return Err(Error::DataLength {
                    kind: rtype,
                    expected: 2,
                    got: data.len(),
                });
            }
            let preference = u16::from_be_bytes([data[0], data[1]]);
            let (exchange, used) = read_name(&data[2..])?;
            if 2 + used != data.len() {
                return Err(Error::TrailingBytes(data.len() - 2 - used));
            }
            Ok(Data::Mx {
                preference,
                exchange,
            })
        }
        kind::SRV => {
            if data.len() < 6 {
                return Err(Error::DataLength {
                    kind: rtype,
                    expected: 6,
                    got: data.len(),
                });
            }
            let number = |at: usize| u16::from_be_bytes([data[at], data[at + 1]]);
            let (target, used) = read_name(&data[6..])?;
            if 6 + used != data.len() {
                return Err(Error::TrailingBytes(data.len() - 6 - used));
            }
            Ok(Data::Srv(Srv {
                priority: number(0),
                weight: number(2),
                port: number(4),
                target,
            }))
        }
        kind::ZERO => {
            fixed(8)?;
            let mut octets = [0u8; 8];
            octets.copy_from_slice(data);
            Ok(Data::Tombstone(u64::from_le_bytes(octets)))
        }
        _ => Ok(Data::Other(data.to_vec())),
    }
}

fn encode_data(data: &Data) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    match data {
        Data::A(address) => out.extend_from_slice(&address.octets()),
        Data::Aaaa(address) => out.extend_from_slice(&address.octets()),
        Data::Name(name) => write_name(name, &mut out)?,
        Data::Soa(soa) => {
            for number in [soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum] {
                out.extend_from_slice(&number.to_be_bytes());
            }
            write_name(&soa.primary, &mut out)?;
            write_name(&soa.admin, &mut out)?;
        }
        Data::Mx {
            preference,
            exchange,
        } => {
            out.extend_from_slice(&preference.to_be_bytes());
            write_name(exchange, &mut out)?;
        }
        Data::Srv(srv) => {
            out.extend_from_slice(&srv.priority.to_be_bytes());
            out.extend_from_slice(&srv.weight.to_be_bytes());
            out.extend_from_slice(&srv.port.to_be_bytes());
            write_name(&srv.target, &mut out)?;
        }
        Data::Tombstone(time) => out.extend_from_slice(&time.to_le_bytes()),
        Data::Other(raw) => out.extend_from_slice(raw),
    }
    Ok(out)
}

/// Reads a `DNS_COUNT_NAME` and says how many octets it took.
fn read_name(data: &[u8]) -> Result<(String, usize), Error> {
    if data.len() < 2 {
        return Err(Error::BadName {
            len: data.len(),
            labels: 0,
        });
    }
    let length = data[0] as usize;
    let labels = data[1];
    if data.len() < 2 + length {
        return Err(Error::BadName {
            len: length,
            labels,
        });
    }

    let raw = &data[2..2 + length];
    let mut parts = Vec::with_capacity(labels as usize);
    let mut at = 0;
    for _ in 0..labels {
        let Some(&size) = raw.get(at) else {
            return Err(Error::BadName {
                len: length,
                labels,
            });
        };
        let size = size as usize;
        let Some(label) = raw.get(at + 1..at + 1 + size) else {
            return Err(Error::BadName {
                len: length,
                labels,
            });
        };
        match std::str::from_utf8(label) {
            Ok(text) => parts.push(text.to_string()),
            Err(_) => {
                return Err(Error::BadName {
                    len: length,
                    labels,
                });
            }
        }
        at += 1 + size;
    }
    // The declared length is what a reader may skip by; a name whose labels do not fill it is a
    // value the rest of the record is measured against, so the two disagreeing is an error here.
    if at != length {
        return Err(Error::BadName {
            len: length,
            labels,
        });
    }
    Ok((parts.join("."), 2 + length))
}

/// Writes a `DNS_COUNT_NAME`.
fn write_name(name: &str, out: &mut Vec<u8>) -> Result<(), Error> {
    let mut raw = Vec::with_capacity(name.len() + 2);
    let mut labels = 0u8;
    if !name.is_empty() {
        for label in name.split('.') {
            if label.len() > 63 {
                return Err(Error::LongLabel(label.len()));
            }
            raw.push(label.len() as u8);
            raw.extend_from_slice(label.as_bytes());
            labels = labels.checked_add(1).ok_or(Error::BadName {
                len: name.len(),
                labels,
            })?;
        }
    }
    let length = u8::try_from(raw.len()).map_err(|_| Error::BadName {
        len: raw.len(),
        labels,
    })?;
    out.push(length);
    out.push(labels);
    out.extend_from_slice(&raw);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record written by something other than this crate, as a zone in AD holds it.
    ///
    /// The octets are spelled out rather than built by `encode`, because a test that builds its
    /// input with the code under test agrees with that code by construction and says nothing.
    const A_RECORD: &str = "0400010005f00000010000000000025800000000000000000a000202";

    fn from_hex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|at| u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn a_record_written_by_another_tool_is_read_and_written_back_octet_for_octet() {
        let record = Record::decode(&from_hex(A_RECORD)).expect("an A record");
        assert_eq!(record.data, Data::A(Ipv4Addr::new(10, 0, 2, 2)));
        assert_eq!(record.ttl, 600);
        assert_eq!(record.rank, RANK_ZONE);
        assert_eq!(record.serial, 1);
        assert_eq!(record.encode().expect("encoded"), from_hex(A_RECORD));
    }

    /// The TTL is the one field in big-endian, and a swap is invisible: the record simply never
    /// expires. A test that only round-trips cannot catch it - both halves would agree.
    #[test]
    fn the_ttl_is_big_endian_while_the_rest_is_not() {
        let record = Record::decode(&from_hex(A_RECORD)).expect("an A record");
        assert_eq!(record.ttl, 600, "0x00000258 read as big-endian");
        assert_ne!(
            record.ttl, 0x5802_0000,
            "the little-endian reading of the same octets"
        );
        // And the serial beside it is little-endian, in the same header.
        let mut serialised = from_hex(A_RECORD);
        serialised[8..12].copy_from_slice(&258u32.to_le_bytes());
        assert_eq!(
            Record::decode(&serialised).expect("decoded").serial,
            258,
            "the serial is little-endian, and a big-endian read of these octets is 0x02010000"
        );
    }

    #[test]
    fn every_type_this_build_reads_survives_a_round_trip() {
        let records = [
            Record::zone(kind::A, 600, Data::A(Ipv4Addr::new(192, 0, 2, 53))),
            Record::zone(
                kind::AAAA,
                600,
                Data::Aaaa("2001:db8::53".parse().expect("an address")),
            ),
            Record::zone(kind::NS, 3600, Data::Name("ns1.ad.example.com".into())),
            Record::zone(kind::CNAME, 600, Data::Name("samba.ad.example.com".into())),
            Record::zone(kind::PTR, 600, Data::Name("client.ad.example.com".into())),
            Record::zone(
                kind::SOA,
                3600,
                Data::Soa(Soa {
                    serial: 12,
                    refresh: 900,
                    retry: 600,
                    expire: 86_400,
                    minimum: 300,
                    primary: "samba.ad.example.com".into(),
                    admin: "hostmaster.ad.example.com".into(),
                }),
            ),
            Record::zone(
                kind::MX,
                3600,
                Data::Mx {
                    preference: 10,
                    exchange: "mail.ad.example.com".into(),
                },
            ),
            Record::zone(
                kind::SRV,
                600,
                Data::Srv(Srv {
                    priority: 0,
                    weight: 100,
                    port: 389,
                    target: "samba.ad.example.com".into(),
                }),
            ),
            Record::zone(kind::ZERO, 0, Data::Tombstone(133_000_000_000_000_000)),
        ];
        for record in records {
            let octets = record.encode().expect("encoded");
            let read = Record::decode(&octets).expect("decoded");
            assert_eq!(read, record, "{:?} did not survive", record.data);
        }
    }

    /// The lookup a member makes on joining, spelled out: the name is what Windows asks the domain
    /// for, and the target is what it then connects to.
    #[test]
    fn a_service_locator_carries_its_own_numbers_and_target() {
        let octets = from_hex("1d00210005f0000000000000000002580000000000000000") // header, 22 octets
            .into_iter()
            .chain([0x00, 0x00, 0x00, 0x64, 0x01, 0x85]) // priority 0, weight 100, port 389
            .chain([0x15, 0x04, 0x05]) // name: 21 octets, 4 labels
            .chain(b"samba".iter().copied())
            .chain([0x02])
            .chain(b"ad".iter().copied())
            .chain([0x07])
            .chain(b"example".iter().copied())
            .chain([0x03])
            .chain(b"com".iter().copied())
            .collect::<Vec<_>>();

        let record = Record::decode(&octets).expect("an SRV record");
        assert_eq!(
            record.data,
            Data::Srv(Srv {
                priority: 0,
                weight: 100,
                port: 389,
                target: "samba.ad.example.com".into(),
            })
        );
        assert_eq!(record.encode().expect("encoded"), octets);
    }

    /// A type this build does not read is written back as it came, so that touching one record does
    /// not delete the rest of a zone - the DNSSEC types land here until they are read.
    #[test]
    fn an_unread_type_is_carried_through_unchanged() {
        const RRSIG: u16 = 0x002E;
        let payload = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x11];
        let record = Record::zone(RRSIG, 3600, Data::Other(payload.clone()));
        let octets = record.encode().expect("encoded");
        let read = Record::decode(&octets).expect("decoded");
        assert_eq!(read.rtype, RRSIG);
        assert_eq!(read.data, Data::Other(payload));
    }

    #[test]
    fn a_record_whose_data_disagrees_with_its_type_is_not_read() {
        // An A record whose data is five octets: the header is honest, the type is not.
        let mut octets = from_hex(A_RECORD);
        octets[0..2].copy_from_slice(&5u16.to_le_bytes());
        octets.push(0);
        assert_eq!(
            Record::decode(&octets),
            Err(Error::DataLength {
                kind: kind::A,
                expected: 4,
                got: 5
            })
        );
    }

    #[test]
    fn a_version_this_build_does_not_read_is_refused_rather_than_guessed() {
        let mut octets = from_hex(A_RECORD);
        octets[4] = 4;
        assert_eq!(Record::decode(&octets), Err(Error::Version(4)));
    }

    #[test]
    fn a_name_whose_labels_do_not_fill_its_length_is_refused() {
        // Declares three octets of name and one label of five: the value inside the value disagrees
        // with itself, and the octets after it are measured against the declared length.
        let octets = [
            0x05, 0x00, 0x02, 0x00, 0x05, 0xf0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x05, b'x',
            b'y',
        ];
        assert_eq!(
            Record::decode(&octets),
            Err(Error::BadName { len: 3, labels: 1 })
        );
    }

    /// Alignment padding after the data is allowed and is not part of the record; anything else is
    /// a record this does not read, and reading past it would quietly drop it.
    #[test]
    fn alignment_pad_is_allowed_and_other_trailing_octets_are_not() {
        let mut padded = from_hex(A_RECORD);
        padded.extend_from_slice(&[0, 0, 0]);
        assert_eq!(Record::decode(&padded).expect("decoded").ttl, 600);

        let mut unexpected = from_hex(A_RECORD);
        unexpected.extend_from_slice(&[0, 0, 7]);
        assert_eq!(Record::decode(&unexpected), Err(Error::TrailingBytes(3)));
    }
}
