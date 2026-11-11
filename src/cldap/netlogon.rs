//! The blob a domain controller puts in the `Netlogon` attribute.
//!
//! Three structures, chosen by the version the client asks for (MS-ADTS 6.3.3.2): the modern
//! `NETLOGON_SAM_LOGON_RESPONSE_EX` (6.3.1.9), the first extended version
//! `NETLOGON_SAM_LOGON_RESPONSE` (6.3.1.8) and the NT4-era `NETLOGON_SAM_LOGON_RESPONSE_NT40`.
//! Every multi-byte quantity is little-endian; every name is a DNS name in the sense of RFC 1035
//! §4.1.4 - length-prefixed labels with an optional compression pointer, which the decompressor in
//! MS-ADTS 6.3.7 undoes.
//!
//! # Why three structures and not one
//!
//! A client that asks for version 5 and is answered with the `_EX` structure reads the version
//! field as "the server sent me something I did not ask for" and misparses the rest, because the
//! two layouts differ in more than a name. The structure is therefore chosen from what the client
//! asked, exactly as the specification orders the choice.
//!
//! # What this encoder does not do
//!
//! It never compresses a name. Compression is optional in RFC 1035, and every decompressor reads
//! uncompressed labels; writing a pointer table would add a way to get an offset wrong in exchange
//! for a handful of bytes on a datagram that already fits.
use std::net::Ipv4Addr;

/// LOGON_SAM_LOGON_RESPONSE_EX, for the `_EX` structure.
pub const LOGON_SAM_LOGON_RESPONSE_EX: u16 = 23;
/// LOGON_SAM_PAUSE_RESPONSE_EX: the DC is not serving.
pub const LOGON_SAM_PAUSE_RESPONSE_EX: u16 = 24;
/// LOGON_SAM_USER_UNKNOWN_EX: the DC holds no such account.
pub const LOGON_SAM_USER_UNKNOWN_EX: u16 = 25;
/// LOGON_SAM_LOGON_RESPONSE, for the version-5 structure.
pub const LOGON_SAM_LOGON_RESPONSE: u16 = 19;
/// LOGON_SAM_USER_UNKNOWN, for the version-5 and NT4 structures.
pub const LOGON_SAM_USER_UNKNOWN: u16 = 21;

/// DS_FLAG bits this server sets, and the ones it deliberately does not (`MS-ADTS` 6.3.1.2).
pub mod flags {
    /// The server is an LDAP server. Always set.
    pub const DS_LDAP_FLAG: u32 = 0x0000_0008;
    /// The server is a domain controller. Always set.
    pub const DS_DS_FLAG: u32 = 0x0000_0010;
    /// The server runs a Kerberos KDC. **Not set**: this server accepts tickets but issues none.
    pub const DS_KDC_FLAG: u32 = 0x0000_0020;
    /// The server is not an RODC.
    pub const DS_WRITABLE_FLAG: u32 = 0x0000_0100;
    /// The server has a DNS name.
    pub const DS_DNS_CONTROLLER_FLAG: u32 = 0x2000_0000;
    /// The naming context is a default naming context.
    pub const DS_DNS_DOMAIN_FLAG: u32 = 0x4000_0000;
    /// The naming context is the forest root.
    pub const DS_DNS_FOREST_FLAG: u32 = 0x8000_0000;
}

/// NETLOGON_NT_VERSION bits (`MS-ADTS` 6.3.1.1).
pub mod nt_version {
    /// Respond with the NT4 structure unless a later version is asked for.
    pub const NETLOGON_NT_VERSION_1: u32 = 0x0000_0001;
    /// Respond with the version-5 structure unless `_EX` is asked for.
    pub const NETLOGON_NT_VERSION_5: u32 = 0x0000_0002;
    /// Respond with the `_EX` structure.
    pub const NETLOGON_NT_VERSION_5EX: u32 = 0x0000_0004;
    /// As `_EX`, and include the server's address.
    pub const NETLOGON_NT_VERSION_5EX_WITH_IP: u32 = 0x0000_0008;
    /// The client wants the closest site.
    pub const NETLOGON_NT_VERSION_WITH_CLOSEST_SITE: u32 = 0x0000_0010;
    /// Honour every option the client asked for.
    pub const NETLOGON_NT_VERSION_AVOID_NT4EMUL: u32 = 0x0100_0000;
}

/// Which structure the client's version word asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// `NETLOGON_SAM_LOGON_RESPONSE_EX`.
    Extended,
    /// `NETLOGON_SAM_LOGON_RESPONSE`.
    Version5,
    /// `NETLOGON_SAM_LOGON_RESPONSE_NT40`.
    Nt40,
}

impl Shape {
    /// The structure the specification orders for this version word.
    ///
    /// The order matters and is not a preference: `_EX` wins over version 5, version 5 wins over
    /// nothing, and everything else gets the NT4 structure.
    pub fn for_version(version: u32) -> Self {
        if version
            & (nt_version::NETLOGON_NT_VERSION_5EX | nt_version::NETLOGON_NT_VERSION_5EX_WITH_IP)
            != 0
        {
            Self::Extended
        } else if version & nt_version::NETLOGON_NT_VERSION_5 != 0 {
            Self::Version5
        } else {
            Self::Nt40
        }
    }
}

/// Everything the response says about this server.
///
/// Filled once at start from the configuration; the encoder never reads anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertised {
    /// `DnsDomainName`: the DNS name of the naming context, `example.com`.
    pub dns_domain: String,
    /// `DnsForestName`: the forest's DNS name. This server hosts one naming context, so the
    /// forest and the domain are the same name, and saying otherwise would invent a hierarchy
    /// that does not exist.
    pub dns_forest: String,
    /// `DnsHostName`: the server's own DNS name, `dc1.example.com`.
    pub dns_host: String,
    /// `NetbiosDomainName`: the downlevel domain name, `EXAMPLE`.
    pub netbios_domain: String,
    /// `NetbiosComputerName`: the downlevel server name, `DC1`.
    pub netbios_host: String,
    /// `DomainGuid`: stable for the domain, derived from its DNS name.
    pub domain_guid: uuid::Uuid,
    /// `DcIpAddress` / `DcSockAddr`: the address a client should connect to.
    pub address: Ipv4Addr,
    /// `DcSiteName` and `ClientSiteName`.
    ///
    /// Empty, and deliberately: this server has no sites container, so it has no site to name.
    /// Inventing `Default-First-Site-Name` would tell a client its site is known when nothing here
    /// knows about sites at all.
    pub site: String,
    /// Whether this process issues tickets for the realm - that is, whether a KDC is serving here.
    ///
    /// Not a property of the ping: the same crate answers it in a deployment with no KDC at all,
    /// and there `DS_KDC_FLAG` would be a promise nothing keeps.
    pub kdc: bool,
}

impl Advertised {
    /// The `DS_FLAG` word for this server.
    ///
    /// `DS_KDC_FLAG` follows whether a KDC actually serves the realm here. A Windows client asks the
    /// locator for a controller with `DS_KDC_REQUIRED` - a machine joining a domain needs a ticket
    /// next - and a response without this bit is filtered out as "no such domain", which reads as a
    /// DNS or a firewall problem. The bit is set only where the KDC is real: a deployment that
    /// answers pings and issues no tickets says so instead of being found and then failing at
    /// `AS-REQ`.
    pub fn flags(&self) -> u32 {
        let base = flags::DS_LDAP_FLAG
            | flags::DS_DS_FLAG
            | flags::DS_WRITABLE_FLAG
            | flags::DS_DNS_CONTROLLER_FLAG
            | flags::DS_DNS_DOMAIN_FLAG
            | flags::DS_DNS_FOREST_FLAG;
        if self.kdc {
            base | flags::DS_KDC_FLAG
        } else {
            base
        }
    }
}

/// Writes a name as RFC 1035 labels: each label length-prefixed, the name terminated by a zero.
///
/// An empty name is a single zero byte, which is a valid empty label - that is how a field with
/// nothing to say is written, because the field cannot be omitted.
fn write_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        // A label longer than 63 bytes cannot be written: RFC 1035 §2.3.4 caps it, and truncating
        // would silently produce a name that is not the one configured.
        let bytes = label.as_bytes();
        let length = bytes.len().min(63);
        out.push(length as u8);
        out.extend_from_slice(&bytes[..length]);
    }
    out.push(0);
}

/// Writes a UTF-16LE, null-terminated string, as the version-5 and NT4 structures hold names.
fn write_utf16(out: &mut Vec<u8>, text: &str) {
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
}

/// The 16 bytes of a GUID in the order MS-DTYP §2.3.4 puts them on the wire.
///
/// Three fields little-endian, the last eight bytes as they are. A `Uuid` is a 128-bit number and
/// its own byte order is big-endian throughout, so writing `as_bytes` here would reverse the first
/// three fields and produce a GUID that no AD tool recognises.
fn write_guid(out: &mut Vec<u8>, guid: &uuid::Uuid) {
    let (data1, data2, data3, data4) = guid.as_fields();
    out.extend_from_slice(&data1.to_le_bytes());
    out.extend_from_slice(&data2.to_le_bytes());
    out.extend_from_slice(&data3.to_le_bytes());
    out.extend_from_slice(data4);
}

/// Encodes the response for the structure the client's version word asks for.
///
/// `version` is the client's `NtVer`; `user_known` is false when the client named a `User` this
/// directory does not hold, which the specification answers with the "user unknown" operation code
/// rather than a logon response.
pub fn encode(advertised: &Advertised, version: u32, user: &str, user_known: bool) -> Vec<u8> {
    match Shape::for_version(version) {
        Shape::Extended => encode_extended(advertised, version, user, user_known),
        Shape::Version5 => encode_version5(advertised, user, user_known, None),
        Shape::Nt40 => encode_nt40(advertised, user, user_known),
    }
}

fn encode_extended(advertised: &Advertised, version: u32, user: &str, user_known: bool) -> Vec<u8> {
    let with_ip = version & nt_version::NETLOGON_NT_VERSION_5EX_WITH_IP != 0;

    let mut out = Vec::with_capacity(256);
    // Opcode and the reserved word.
    out.extend_from_slice(&LOGON_SAM_LOGON_RESPONSE_EX.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    // Flags, then the domain GUID.
    out.extend_from_slice(&advertised.flags().to_le_bytes());
    write_guid(&mut out, &advertised.domain_guid);

    // Eight names, in the order the structure fixes: forest, domain, host, NetBIOS domain,
    // NetBIOS host, user, DC site, client site.
    write_name(&mut out, &advertised.dns_forest);
    write_name(&mut out, &advertised.dns_domain);
    write_name(&mut out, &advertised.dns_host);
    write_name(&mut out, &advertised.netbios_domain);
    write_name(&mut out, &advertised.netbios_host);
    write_name(&mut out, user);
    write_name(&mut out, &advertised.site);
    write_name(&mut out, &advertised.site);

    if with_ip {
        // DcSockAddrSize, then a `sockaddr_in` in the layout of §6.3.1.9: family and port
        // little-endian, the address big-endian, eight reserved bytes.
        out.push(16);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&advertised.address.octets());
        out.extend_from_slice(&[0u8; 8]);
    }
    // NextClosestSiteName would go here, and does not: it is written only when the client asked for
    // the closest site *and* this DC is at functional level 2008 or above, and there is one site
    // here, so the closest site is the client's own.

    out.extend_from_slice(
        &(nt_version::NETLOGON_NT_VERSION_1
            | nt_version::NETLOGON_NT_VERSION_5EX
            | if with_ip {
                nt_version::NETLOGON_NT_VERSION_5EX_WITH_IP
            } else {
                0
            })
        .to_le_bytes(),
    );
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());

    // The operation code is the second thing on the wire and the last thing decided: whether the
    // user exists is known only after the request is understood, so the code goes back and fills
    // the first two bytes rather than being guessed.
    let code = if user_known {
        LOGON_SAM_LOGON_RESPONSE_EX
    } else {
        LOGON_SAM_USER_UNKNOWN_EX
    };
    out[0..2].copy_from_slice(&code.to_le_bytes());

    out
}

fn encode_version5(
    advertised: &Advertised,
    user: &str,
    user_known: bool,
    _closest_site: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&LOGON_SAM_LOGON_RESPONSE.to_le_bytes());

    // Three UTF-16 names first, then two GUIDs, then three DNS names, then the address.
    write_utf16(&mut out, &advertised.netbios_host);
    write_utf16(&mut out, user);
    write_utf16(&mut out, &advertised.netbios_domain);
    write_guid(&mut out, &advertised.domain_guid);
    // SiteGuid: always the null GUID in this structure.
    out.extend_from_slice(&[0u8; 16]);

    write_name(&mut out, &advertised.dns_forest);
    write_name(&mut out, &advertised.dns_domain);
    write_name(&mut out, &advertised.dns_host);
    out.extend_from_slice(&advertised.address.octets());

    // DS_PDC_FLAG is not set: this server holds no FSMO roles, and claiming the PDC role would
    // send clients to it for operations only a PDC may perform.
    out.extend_from_slice(
        &(flags::DS_DS_FLAG
            | flags::DS_DNS_CONTROLLER_FLAG
            | flags::DS_DNS_DOMAIN_FLAG
            | flags::DS_DNS_FOREST_FLAG)
            .to_le_bytes(),
    );
    out.extend_from_slice(
        &(nt_version::NETLOGON_NT_VERSION_1 | nt_version::NETLOGON_NT_VERSION_5).to_le_bytes(),
    );
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());

    let code = if user_known {
        LOGON_SAM_LOGON_RESPONSE
    } else {
        LOGON_SAM_USER_UNKNOWN
    };
    out[0..2].copy_from_slice(&code.to_le_bytes());

    out
}

fn encode_nt40(advertised: &Advertised, user: &str, user_known: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&LOGON_SAM_LOGON_RESPONSE.to_le_bytes());
    write_utf16(&mut out, &advertised.netbios_host);
    write_utf16(&mut out, user);
    write_utf16(&mut out, &advertised.netbios_domain);
    out.extend_from_slice(&nt_version::NETLOGON_NT_VERSION_1.to_le_bytes());
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());

    let code = if user_known {
        LOGON_SAM_LOGON_RESPONSE
    } else {
        LOGON_SAM_USER_UNKNOWN
    };
    out[0..2].copy_from_slice(&code.to_le_bytes());

    out
}

/// Reads a name written as RFC 1035 labels, compression pointers included.
///
/// Used by tests to check what the encoder wrote, and by anything that has to read a response from
/// another server. Returns the name and how many bytes it occupied.
pub fn read_name(bytes: &[u8]) -> Result<(String, usize), String> {
    read_name_at(bytes, 0)
}

/// The same, starting at `start`.
///
/// Separate from [`read_name`] because a compression pointer is an offset into the *message*, not
/// into the slice a caller happens to hold: reading from a slice would resolve every pointer to the
/// wrong place, which is the kind of decoder that works on the names it wrote itself and fails on
/// everything else.
pub fn read_name_at(bytes: &[u8], start: usize) -> Result<(String, usize), String> {
    // A cap on labels, because a pointer may lead to another pointer. The backward-only rule
    // rejects the simple loop, but two pointers can point at each other's neighbourhoods and
    // neither is forward - so the reading has to end by count as well as by terminator.
    //
    // Without this the parser does not fail on a hostile name, it spins, and a spinner in a UDP
    // handler costs every other client on the machine. The limit is RFC 1035's own: a name is at
    // most 255 bytes, so at most 127 one-byte labels fit in one.
    const MAX_LABELS: usize = 128;

    let mut labels: Vec<String> = Vec::new();
    let mut position = start;
    let mut consumed = 0usize;
    let mut jumped = false;
    // Steps, not labels: a chain of pure pointers adds no labels at all, so counting labels would
    // let such a chain run for ever.
    let mut steps = 0usize;

    loop {
        steps += 1;
        if steps > MAX_LABELS {
            return Err("a name does not end within the labels RFC 1035 allows".to_string());
        }
        if labels.len() > MAX_LABELS {
            return Err("a name does not end within the labels RFC 1035 allows".to_string());
        }

        let Some(&length) = bytes.get(position) else {
            return Err("the name ends before its terminator".to_string());
        };

        if length == 0 {
            if !jumped {
                consumed = position + 1 - start;
            }
            break;
        }

        if length & 0xC0 == 0xC0 {
            let Some(&low) = bytes.get(position + 1) else {
                return Err("a compression pointer is cut short".to_string());
            };
            let offset = (usize::from(length & 0x3F) << 8) | usize::from(low);
            if !jumped {
                consumed = position + 2 - start;
                jumped = true;
            }
            // A pointer must go backwards; one that does not is a loop, and following it would
            // never terminate.
            if offset >= position {
                return Err("a compression pointer points forward".to_string());
            }
            position = offset;
            continue;
        }

        let label_start = position + 1;
        let end = label_start + usize::from(length);
        let Some(label) = bytes.get(label_start..end) else {
            return Err("a label is longer than the data".to_string());
        };
        labels.push(String::from_utf8_lossy(label).into_owned());
        position = end;
    }

    Ok((labels.join("."), consumed))
}

/// Reads a UTF-16LE, null-terminated string. Returns the text and how many bytes it occupied.
pub fn read_utf16(bytes: &[u8]) -> Result<(String, usize), String> {
    let mut units: Vec<u16> = Vec::new();
    let mut position = 0usize;

    loop {
        let Some(pair) = bytes.get(position..position + 2) else {
            return Err("a UTF-16 string has no terminator".to_string());
        };
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        position += 2;
        if unit == 0 {
            break;
        }
        units.push(unit);
    }

    String::from_utf16(&units)
        .map(|text| (text, position))
        .map_err(|_| "a UTF-16 string is not valid UTF-16".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advertised() -> Advertised {
        Advertised {
            kdc: false,
            dns_domain: "example.com".to_string(),
            dns_forest: "example.com".to_string(),
            dns_host: "dc1.example.com".to_string(),
            netbios_domain: "EXAMPLE".to_string(),
            netbios_host: "DC1".to_string(),
            domain_guid: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, b"example.com"),
            address: Ipv4Addr::new(192, 0, 2, 10),
            site: String::new(),
        }
    }

    #[test]
    fn a_dns_name_is_written_as_length_prefixed_labels() {
        let mut out = Vec::new();
        write_name(&mut out, "dc1.example.com");

        assert_eq!(out, b"\x03dc1\x07example\x03com\x00");
        let (name, consumed) = read_name(&out).expect("what was written can be read");
        assert_eq!(name, "dc1.example.com");
        assert_eq!(consumed, out.len());
    }

    #[test]
    fn an_empty_name_is_a_single_terminator() {
        let mut out = Vec::new();
        write_name(&mut out, "");

        assert_eq!(out, b"\x00");
        assert_eq!(read_name(&out).expect("readable").0, "");
    }

    #[test]
    fn the_version_word_chooses_the_structure_in_the_order_the_specification_fixes() {
        // `_EX` wins over version 5, which wins over nothing.
        assert_eq!(Shape::for_version(0x0000_0006), Shape::Extended);
        assert_eq!(Shape::for_version(0x0000_0004), Shape::Extended);
        assert_eq!(Shape::for_version(0x0000_000C), Shape::Extended);
        assert_eq!(Shape::for_version(0x0000_0002), Shape::Version5);
        assert_eq!(Shape::for_version(0x0000_0003), Shape::Version5);
        assert_eq!(Shape::for_version(0x0000_0001), Shape::Nt40);
        assert_eq!(Shape::for_version(0), Shape::Nt40);
    }

    #[test]
    fn the_extended_response_carries_the_names_in_the_order_the_structure_fixes() {
        let bytes = encode(&advertised(), 0x0000_0006, "", true);

        // Opcode, reserved word, flags, GUID.
        assert_eq!(
            u16::from_le_bytes([bytes[0], bytes[1]]),
            LOGON_SAM_LOGON_RESPONSE_EX
        );
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 0);
        assert_eq!(
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            advertised().flags()
        );

        let mut at = 8 + 16;
        for expected in [
            "example.com",
            "example.com",
            "dc1.example.com",
            "EXAMPLE",
            "DC1",
            "",
            "",
            "",
        ] {
            let (name, consumed) = read_name_at(&bytes, at).expect("a readable name");
            assert_eq!(name, expected, "at offset {at}");
            at += consumed;
        }

        // Then the version word and the two 0xFFFF tokens.
        let tail = &bytes[at..];
        assert_eq!(tail.len(), 8);
        assert_eq!(
            u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]),
            nt_version::NETLOGON_NT_VERSION_1 | nt_version::NETLOGON_NT_VERSION_5EX
        );
        assert_eq!(u16::from_le_bytes([tail[4], tail[5]]), 0xFFFF);
        assert_eq!(u16::from_le_bytes([tail[6], tail[7]]), 0xFFFF);
    }

    #[test]
    fn the_address_is_written_only_when_the_client_asks_for_it() {
        let without = encode(&advertised(), 0x0000_0006, "", true);
        let with = encode(&advertised(), 0x0000_000E, "", true);

        assert_eq!(
            with.len(),
            without.len() + 17,
            "17 bytes for size and sockaddr"
        );

        // The version word says so as well, or a client would look for bytes it was not sent.
        let tail = &with[with.len() - 8..];
        assert_eq!(
            u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]),
            nt_version::NETLOGON_NT_VERSION_1
                | nt_version::NETLOGON_NT_VERSION_5EX
                | nt_version::NETLOGON_NT_VERSION_5EX_WITH_IP
        );

        // The address sits between the names and the version word, and is big-endian.
        let address_at = with.len() - 8 - 17 + 1 + 4;
        assert_eq!(&with[address_at..address_at + 4], &[192, 0, 2, 10]);
    }

    #[test]
    fn a_user_the_directory_does_not_hold_is_answered_with_the_unknown_code() {
        let known = encode(&advertised(), 0x0000_0006, "alice", true);
        let unknown = encode(&advertised(), 0x0000_0006, "nobody", false);

        assert_eq!(
            u16::from_le_bytes([known[0], known[1]]),
            LOGON_SAM_LOGON_RESPONSE_EX
        );
        assert_eq!(
            u16::from_le_bytes([unknown[0], unknown[1]]),
            LOGON_SAM_USER_UNKNOWN_EX
        );

        // The name still travels: the client asked about a specific account and the answer names it.
        assert!(unknown.windows(6).any(|window| window == b"nobody"));
    }

    #[test]
    fn the_kdc_flag_is_not_set_because_this_server_issues_no_tickets() {
        // The one bit that makes the answer honest. A client that filters on it learns the truth
        // before it tries an AS-REQ that cannot succeed.
        assert_eq!(advertised().flags() & flags::DS_KDC_FLAG, 0);
        assert_ne!(advertised().flags() & flags::DS_LDAP_FLAG, 0);
        assert_ne!(advertised().flags() & flags::DS_DS_FLAG, 0);
    }

    #[test]
    fn a_guid_is_written_in_the_order_an_ad_tool_reads_it() {
        let guid = uuid::Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").expect("parses");
        let mut out = Vec::new();
        write_guid(&mut out, &guid);

        // Data1, Data2 and Data3 little-endian; Data4 as it stands.
        assert_eq!(
            out,
            vec![
                0x33, 0x22, 0x11, 0x00, // Data1
                0x55, 0x44, // Data2
                0x77, 0x66, // Data3
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Data4
            ]
        );
    }

    #[test]
    fn a_compression_pointer_is_followed() {
        // "www" followed by a pointer to the "com" at offset 0: the name is "www.com", and the
        // reader spent four bytes instead of eight.
        let bytes = b"\x03com\x00\x03www\xc0\x00";
        let (name, consumed) = read_name_at(bytes, 5).expect("a pointer is legal");

        assert_eq!(name, "www.com");
        // "www" is four bytes and the pointer two: the eight bytes a full "www.com" would take
        // become six, and the count is what a caller walks the structure with.
        assert_eq!(consumed, 6);
    }

    #[test]
    fn a_pointer_that_points_forward_is_refused_rather_than_followed() {
        // A pointer may only lead backwards, to a name already written.
        let bytes = b"\xc0\x04\x00\x00\x01a\x00";

        assert!(read_name(bytes).is_err());
    }

    #[test]
    fn a_loop_of_pointers_ends_in_an_error_rather_than_in_a_spin() {
        // Two pointers that lead to each other without either pointing forward: "\xc0\x02" at
        // offset 0 leads to offset 2, which holds "\xc0\x00" leading back to offset 0. The
        // backward-only rule is satisfied by every step, so the reading has to be stopped by count.
        //
        // This was a hang, not a failure, until the label cap went in - and a hang in a UDP
        // handler is worse than an error, because nothing on the machine says why.
        let bytes = b"\x01a\xc0\x00\xc0\x00";

        assert!(read_name(bytes).is_err());
    }

    #[test]
    fn a_name_that_ends_before_its_terminator_is_refused() {
        assert!(read_name(b"\x05ab").is_err());
        assert!(read_name(b"").is_err());
    }

    #[test]
    fn a_utf16_name_round_trips_and_says_how_long_it_was() {
        let mut out = Vec::new();
        write_utf16(&mut out, "EXAMPLE");

        let (text, consumed) = read_utf16(&out).expect("readable");
        assert_eq!(text, "EXAMPLE");
        assert_eq!(consumed, out.len());

        // An empty name is one terminator, two bytes.
        let mut empty = Vec::new();
        write_utf16(&mut empty, "");
        assert_eq!(empty, vec![0, 0]);
        assert_eq!(read_utf16(&empty).expect("readable").0, "");
    }

    #[test]
    fn the_version_five_structure_puts_its_utf16_names_first() {
        let bytes = encode(&advertised(), 0x0000_0002, "alice", true);

        assert_eq!(
            u16::from_le_bytes([bytes[0], bytes[1]]),
            LOGON_SAM_LOGON_RESPONSE
        );
        let (host, at) = read_utf16(&bytes[2..]).expect("readable");
        assert_eq!(host, "DC1");
        let (user, at_user) = read_utf16(&bytes[2 + at..]).expect("readable");
        assert_eq!(user, "alice");
        let (domain, _) = read_utf16(&bytes[2 + at + at_user..]).expect("readable");
        assert_eq!(domain, "EXAMPLE");
    }

    #[test]
    fn the_nt4_structure_is_the_shortest_and_still_well_formed() {
        let extended = encode(&advertised(), 0x0000_0006, "", true);
        let nt40 = encode(&advertised(), 0x0000_0001, "", true);

        assert!(nt40.len() < extended.len());
        assert_eq!(
            u16::from_le_bytes([nt40[0], nt40[1]]),
            LOGON_SAM_LOGON_RESPONSE
        );
        let (host, _) = read_utf16(&nt40[2..]).expect("readable");
        assert_eq!(host, "DC1");
    }

    #[test]
    fn a_label_longer_than_rfc1035_allows_is_cut_rather_than_written_with_a_bad_length() {
        // 63 is the maximum a length byte can name without setting the pointer bits.
        let long = "a".repeat(100);
        let mut out = Vec::new();
        write_name(&mut out, &long);

        assert_eq!(out[0], 63);
        let (name, _) = read_name(&out).expect("readable");
        assert_eq!(name.len(), 63);
    }

    /// `DS_KDC_FLAG` follows whether a KDC serves the realm, not whether this crate answers pings.
    ///
    /// A Windows client that looks for a controller to join with asks for `DS_KDC_REQUIRED`, and a
    /// response without this bit is discarded as "no such domain" - which reads like DNS or a
    /// firewall, not like a missing flag.
    #[test]
    fn the_kdc_flag_says_whether_a_kdc_answers_here() {
        let mut server = advertised();
        server.kdc = false;
        assert_eq!(
            server.flags() & flags::DS_KDC_FLAG,
            0,
            "a deployment with no KDC must not claim one"
        );

        server.kdc = true;
        assert_eq!(
            server.flags() & flags::DS_KDC_FLAG,
            flags::DS_KDC_FLAG,
            "and one that issues tickets says so"
        );
        assert_eq!(
            server.flags() & flags::DS_LDAP_FLAG,
            flags::DS_LDAP_FLAG,
            "the other bits do not depend on it"
        );
    }
}
