//! The domain's own DNS: the zone a member's SRV lookups resolve against.
//!
//! A Windows client finds its controller by asking the domain's name for `_ldap._tcp.dc._msdcs.<domain>`
//! and `_kerberos._tcp.<domain>`. Until this module existed those answers came from `dnsmasq` in the
//! stand, wildcarded to one address - a name a validator would call a lie, and not something a
//! deployment could live with.
//!
//! The zone is stored the way AD stores it, because that is what makes it readable by tools that
//! already speak AD: entries of class `dnsNode` under the zone, each carrying `dnsRecord` values in
//! the binary shape of [MS-DNSP] 2.3.2.2. [`record`] reads and writes that shape for one record.
//!
//! Deliberately in this order: the value format first, then the zone in the tree, then the listener.
//! A zone that answers queries out of a blob nothing can read is a zone no other tool can check.
//!
//! Not here yet, and each for a named reason: the wire format (RFC 1035) and the listener on 53,
//! dynamic updates (RFC 2136) with their GSS-TSIG signatures, and DNSSEC. `dnsRecord` values that
//! this build does not read are carried through untouched - see [`record::Data::Other`] - so a zone
//! written by a tool with a wider type set survives a round trip through this server.

pub mod property;
pub mod record;
pub mod serve;
