//! CLDAP ping: the question a Windows machine asks over UDP before it can find a domain.
//!
//! A machine that wants to join, or to log a user on, first has to find a domain controller, and it
//! does that with a connectionless LDAP search on UDP 389 for the `Netlogon` attribute of the root
//! DSE (`MS-ADTS` 7.3.1.1.4, 6.3.3). The reply is not an entry with attributes - it is a binary
//! structure, and it is the only thing that tells Windows this address is a domain controller.
//!
//! # What this is, and what it is not
//!
//! It answers that question. It does **not** make this server a domain controller: the reply's
//! `DS_FLAG` word says so, by leaving `DS_KDC_FLAG` clear, because there is no KDC here to issue the
//! ticket a machine would ask for next. A client that checks that bit learns the truth before it
//! tries.
//!
//! The listener is off unless an operator turns it on (`cldap.enabled`). Default-on would send every
//! machine on the network to a controller that cannot complete a logon, and the failure would look
//! like a broken network rather than a half-built domain.
//!
//! # The amplification question
//!
//! A UDP service that answers a small request with a larger reply can be used to reflect traffic at
//! someone else. Here the ratio is about three to one - a ping of roughly a hundred bytes is
//! answered with roughly three hundred - and the reply is generated without touching the store, so
//! there is nothing to amplify but arithmetic. The listener additionally refuses datagrams larger
//! than a ping can be, and answers at most one message per datagram.
use std::net::Ipv4Addr;
use std::sync::Arc;

use rasn::types::SetOf;
use rasn_ldap::{
    AssertionValue, AttributeDescription, Filter, LdapDn, LdapMessage, PartialAttribute,
    ProtocolOp, SearchResultEntry,
};

pub mod netlogon;

/// The largest datagram worth parsing. A ping is well under this; anything bigger is not a ping, and
/// spending work to find that out is how a UDP service becomes a small denial of service.
pub const MAX_DATAGRAM: usize = 2048;

/// Why a datagram is not a ping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Not an LDAP message this server can read.
    Malformed(String),
    /// An LDAP message that is not a search.
    NotASearch,
    /// A search that does not ask for `Netlogon`, so it is not a ping.
    NotAPing,
    /// A ping whose filter says something this server cannot evaluate.
    BadFilter(String),
    /// A ping for a domain this server does not hold.
    ForeignDomain(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) => write!(formatter, "not an LDAP message: {detail}"),
            Self::NotASearch => formatter.write_str("an LDAP message that is not a search"),
            Self::NotAPing => formatter.write_str("a search that does not ask for Netlogon"),
            Self::BadFilter(detail) => {
                write!(formatter, "a ping filter this server cannot read: {detail}")
            }
            Self::ForeignDomain(domain) => {
                write!(
                    formatter,
                    "a ping for '{domain}', which this server does not hold"
                )
            }
        }
    }
}

/// What a ping asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    /// The message id, echoed in both reply messages: a client matches them by it.
    pub message_id: u32,
    /// `NtVer`, which decides the shape of the reply.
    pub nt_version: u32,
    /// `DnsDomain`, when the client named one.
    pub dns_domain: Option<String>,
    /// `User`, when the client asked about a specific account.
    pub user: Option<String>,
    /// `AAC`, the account-control mask the client is interested in. Read for completeness: the
    /// answer either names the user or says it is unknown, and the mask only narrows that.
    pub account_control: Option<u32>,
}

/// Reads a datagram as a ping.
pub fn parse(datagram: &[u8]) -> Result<Ping, Refused> {
    if datagram.len() > MAX_DATAGRAM {
        return Err(Refused::Malformed(format!(
            "{} bytes, more than the {MAX_DATAGRAM} a ping can be",
            datagram.len()
        )));
    }

    let message =
        crate::ldap::codec::decode(datagram).map_err(|err| Refused::Malformed(err.to_string()))?;

    let ProtocolOp::SearchRequest(request) = &message.protocol_op else {
        return Err(Refused::NotASearch);
    };

    // A ping is a search that names the attribute. Everything else on this port is somebody
    // treating UDP 389 as a general LDAP endpoint, and answering that is not this server's job.
    let wants_netlogon = request
        .attributes
        .iter()
        .any(|attribute| attribute.0.eq_ignore_ascii_case("netlogon"));
    if !wants_netlogon {
        return Err(Refused::NotAPing);
    }

    let mut clauses = Vec::new();
    collect(&request.filter, &mut clauses)?;

    let find = |name: &str| {
        clauses
            .iter()
            .find(|(attribute, _)| attribute.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };

    let nt_version = match find("NtVer") {
        None => {
            // Absent is version 1 by the specification's own fallback: the NT4 structure.
            netlogon::nt_version::NETLOGON_NT_VERSION_1
        }
        Some(raw) => {
            let bytes: Vec<u8> = raw;
            let Ok(four) = <[u8; 4]>::try_from(bytes.as_slice()) else {
                return Err(Refused::BadFilter(format!(
                    "NtVer is {} bytes, and it is a 32-bit number",
                    bytes.len()
                )));
            };
            u32::from_le_bytes(four)
        }
    };

    let dns_domain = find("DnsDomain")
        .map(|raw| String::from_utf8_lossy(&raw).into_owned())
        .filter(|domain| !domain.is_empty());

    let user = find("User").map(|raw| String::from_utf8_lossy(&raw).into_owned());

    let account_control = find("AAC").and_then(|raw| {
        let four = <[u8; 4]>::try_from(raw.as_slice()).ok()?;
        Some(u32::from_le_bytes(four))
    });

    Ok(Ping {
        message_id: message.message_id,
        nt_version,
        dns_domain,
        user,
        account_control,
    })
}

/// Collects every equality assertion in the filter, in order.
///
/// A ping's filter is a conjunction of them (`MS-ADTS` 6.3.3.1). The shape is checked only as far as
/// it matters - anything that is not a conjunction of equality assertions cannot be evaluated as a
/// ping, and is refused rather than half-read.
fn collect(filter: &Filter, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), Refused> {
    match filter {
        Filter::And(parts) | Filter::Or(parts) => {
            for part in parts.iter() {
                collect(part, out)?;
            }
            Ok(())
        }
        Filter::EqualityMatch(assertion) => {
            out.push((
                assertion.attribute_desc.0.to_string(),
                assertion.assertion_value.as_ref().to_vec(),
            ));
            Ok(())
        }
        other => Err(Refused::BadFilter(format!(
            "a {} clause is not part of a ping",
            classify(other)
        ))),
    }
}

fn classify(filter: &Filter) -> &'static str {
    match filter {
        Filter::And(_) => "conjunction",
        Filter::Or(_) => "disjunction",
        Filter::Not(_) => "negation",
        Filter::EqualityMatch(_) => "equality",
        Filter::Substrings(_) => "substring",
        Filter::GreaterOrEqual(_) => "greater-or-equal",
        Filter::LessOrEqual(_) => "less-or-equal",
        Filter::Present(_) => "presence",
        Filter::ApproxMatch(_) => "approximate",
        Filter::ExtensibleMatch(_) => "extensible",
        _ => "unrecognised",
    }
}

/// Builds the reply to a ping: a search result entry carrying the `Netlogon` structure, and the
/// search result done that closes it.
///
/// `user_exists` answers whether the directory holds an account for the `User` the client named.
/// It is asked only when the client named one.
pub fn answer(
    ping: &Ping,
    advertised: &netlogon::Advertised,
    user_exists: impl Fn(&str) -> bool,
) -> Vec<u8> {
    let user = ping.user.clone().unwrap_or_default();
    let user_known = user.is_empty() || user_exists(&user);

    let blob = netlogon::encode(advertised, ping.nt_version, &user, user_known);

    let entry = LdapMessage::new(
        ping.message_id,
        ProtocolOp::SearchResEntry(SearchResultEntry::new(
            LdapDn::from(""),
            vec![PartialAttribute::new(
                AttributeDescription::from("Netlogon".to_string()),
                SetOf::from_vec(vec![AssertionValue::from(blob.as_slice())]),
            )],
        )),
    );
    let done =
        crate::ldap::responses::search_done(ping.message_id, rasn_ldap::ResultCode::Success, "");

    let mut out = Vec::with_capacity(512);
    for message in [entry, done] {
        match crate::ldap::codec::encode(&message) {
            Ok(bytes) => out.extend_from_slice(&bytes),
            // Unreachable for a message this module builds, and the alternative - a panic in a
            // UDP handler - would take the listener down over one datagram. An empty answer is a
            // silent datagram, which is what a client already handles.
            Err(_) => return Vec::new(),
        }
    }
    out
}

/// The reply to a ping that must not be answered with a `Netlogon` structure at all.
///
/// `MS-ADTS` 6.3.3.3: an entry with no object name and no attributes, then success. Used for a
/// filter this server cannot evaluate and for a domain it does not hold. The client sees a
/// well-formed answer that names no controller and moves on, rather than a timeout it would have to
/// wait for.
pub fn refuse(message_id: u32) -> Vec<u8> {
    let entry = LdapMessage::new(
        message_id,
        ProtocolOp::SearchResEntry(SearchResultEntry::new(LdapDn::from(""), Vec::new())),
    );
    let done = crate::ldap::responses::search_done(message_id, rasn_ldap::ResultCode::Success, "");

    let mut out = Vec::with_capacity(64);
    for message in [entry, done] {
        if let Ok(bytes) = crate::ldap::codec::encode(&message) {
            out.extend_from_slice(&bytes);
        }
    }
    out
}

/// What the `cldap:` section says.
///
/// Off by default, and the default is the point: a reply to a ping is a promise that this address
/// can complete a logon, and this server cannot, because it runs no KDC. Turning it on is a
/// statement that the rest of that path exists or that the operator knows it does not.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CldapConfig {
    /// Whether to answer pings on UDP 389 at all.
    pub enabled: bool,
    /// The domain's DNS name, `example.com`.
    ///
    /// Derived from the naming context when absent (`dc=example,dc=com` is `example.com`). A value
    /// that disagrees with the naming context is refused at start: answering a ping for one domain
    /// while holding another is how a client ends up with a controller that cannot serve it.
    pub dns_domain: Option<String>,
    /// The server's own DNS name, `dc1.example.com`. Defaults to the host name under the domain.
    pub dns_host: Option<String>,
    /// The downlevel domain name, `EXAMPLE`. Defaults to the first label of the domain, upper-cased.
    pub netbios_domain: Option<String>,
    /// The downlevel server name, `DC1`. Defaults to the host name, upper-cased.
    pub netbios_host: Option<String>,
    /// The UDP port to listen on.
    ///
    /// 389 by default, which is the port a Windows client pings and the only one it tries. A
    /// different value exists for one honest reason: only root may bind below 1024, and a test or a
    /// developer without that right still has to be able to check the encoder end to end.
    pub port: Option<u16>,
    /// The address a client should connect to.
    ///
    /// Answered only when the client asks for it. Defaults to the address the listener is bound to,
    /// and to `127.0.0.1` when that is `0.0.0.0` - which is what the specification says to send when
    /// a controller has no address it can name.
    pub address: Option<Ipv4Addr>,
}

/// What the server advertises, resolved from the configuration and the naming context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub advertised: netlogon::Advertised,
}

impl Settings {
    /// Resolves the section, or says why it cannot be honoured.
    ///
    /// Every default is derived from something that already exists - the naming context, the host
    /// name, the listening address - so that an operator who turns the listener on gets a coherent
    /// answer without having to repeat what the server already knows.
    /// `kdc` says whether this process issues tickets for the realm; it reaches the answer as
    /// `DS_KDC_FLAG`, which a Windows client filters on when it looks for a controller to join
    /// with. See [`netlogon::Advertised::flags`].
    pub fn resolve(
        config: &CldapConfig,
        base_dn: &str,
        bound: std::net::SocketAddr,
        kdc: bool,
    ) -> Result<Self, String> {
        let from_base = domain_of_base(base_dn).ok_or_else(|| {
            format!("the naming context '{base_dn}' has no dc= components to make a DNS name from")
        })?;

        let dns_domain = match &config.dns_domain {
            Some(written) => {
                let written = written.trim().trim_end_matches('.').to_ascii_lowercase();
                if written.is_empty() {
                    return Err("cldap.dns_domain is empty".to_string());
                }
                if written != from_base {
                    return Err(format!(
                        "cldap.dns_domain is '{written}' but the naming context is '{base_dn}', \
                         which is '{from_base}': a controller answers for the naming context it \
                         holds, and answering for another sends clients here to be refused"
                    ));
                }
                written
            }
            None => from_base,
        };

        let host_name = default_host_name();
        let dns_host = match &config.dns_host {
            Some(written) => {
                let written = written.trim().trim_end_matches('.').to_ascii_lowercase();
                if written.is_empty() {
                    return Err("cldap.dns_host is empty".to_string());
                }
                written
            }
            None => format!("{host_name}.{dns_domain}"),
        };

        let netbios_domain = match &config.netbios_domain {
            Some(written) => written.trim().to_ascii_uppercase(),
            None => dns_domain
                .split('.')
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase(),
        };
        if netbios_domain.is_empty() {
            return Err("cldap.netbios_domain is empty".to_string());
        }

        let netbios_host = match &config.netbios_host {
            Some(written) => written.trim().to_ascii_uppercase(),
            // A NetBIOS name is 15 characters; a longer one is truncated by every Windows tool that
            // writes one, so truncating here matches what a client would compute for itself.
            None => host_name.to_ascii_uppercase().chars().take(15).collect(),
        };
        if netbios_host.is_empty() {
            return Err("cldap.netbios_host is empty".to_string());
        }

        let address = match config.address {
            Some(address) => address,
            // A wildcard bind names no address, so there is none to advertise. `127.0.0.1` is what
            // the specification says to send in that case, and it is at least not a lie about a
            // specific machine.
            None => match bound.ip() {
                std::net::IpAddr::V4(address) if !address.is_unspecified() => address,
                _ => Ipv4Addr::LOCALHOST,
            },
        };

        Ok(Self {
            advertised: netlogon::Advertised {
                // The GUID follows the DNS name, so it is the same GUID on every start and on every
                // node serving the same domain - which is the property a client relies on when it
                // caches a controller it has found.
                domain_guid: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, dns_domain.as_bytes()),
                dns_forest: dns_domain.clone(),
                dns_domain,
                dns_host,
                netbios_domain,
                netbios_host,
                kdc,
                address,
                site: String::new(),
            },
        })
    }
}

/// `dc=example,dc=com` as `example.com`.
///
/// Only the leading `dc=` components are the DNS name: a naming context with `ou=` or `cn=` in it
/// describes a subtree of a domain, and the domain is still what the `dc=` parts say.
fn domain_of_base(base_dn: &str) -> Option<String> {
    let mut labels = Vec::new();
    for part in base_dn.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, value) = part.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("dc") {
            break;
        }
        labels.push(value.trim().to_ascii_lowercase());
    }

    if labels.is_empty() || labels.iter().any(String::is_empty) {
        return None;
    }
    Some(labels.join("."))
}

/// The host's own name, without a domain part.
fn default_host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .and_then(|name| name.split('.').next().map(str::to_string))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

/// Answers pings until `shutdown` resolves.
///
/// One datagram in, one datagram out, and no state between them: a ping is a question about the
/// server, not a conversation, so there is no session to keep and nothing to time out.
///
/// A failure to reply is counted and dropped rather than logged per datagram. A machine that pings
/// every second for a month must not be able to fill a disk, and the counter is what an operator
/// reads instead.
pub async fn serve(
    socket: tokio::net::UdpSocket,
    settings: Settings,
    source: Arc<crate::reload::Source>,
    metrics: Arc<crate::metrics::Metrics>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut buffer = vec![0u8; MAX_DATAGRAM];

    loop {
        let received = tokio::select! {
            ready = socket.recv_from(&mut buffer) => ready,
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
                continue;
            }
        };

        let (length, peer) = match received {
            Ok(received) => received,
            Err(err) => {
                // A socket error on UDP is about one datagram, not about the listener: ICMP
                // unreachable from a previous reply arrives here, and exiting would stop answering
                // every other client over one machine that went away.
                metrics.cldap_failed(err.to_string().as_str());
                continue;
            }
        };

        let ping = match parse(&buffer[..length]) {
            Ok(ping) => ping,
            Err(refused) => {
                // A datagram that is not a ping is not this listener's business; the counter says
                // how often it happens, and the log stays quiet.
                metrics.cldap_refused(refused.to_string().as_str());
                continue;
            }
        };

        // A domain this server does not hold is answered with an empty result rather than with a
        // Netlogon structure: the client learns this address is not its controller and moves on,
        // instead of adopting it and failing at the next step.
        let reply = match &ping.dns_domain {
            Some(domain) if !domain.eq_ignore_ascii_case(&settings.advertised.dns_domain) => {
                metrics.cldap_refused("a domain this server does not hold");
                refuse(ping.message_id)
            }
            _ => {
                let directory = source.directory().await;
                let base = directory.base_dn().to_string();
                let reply = answer(&ping, &settings.advertised, |user| {
                    user_exists(&directory, &base, user)
                });
                metrics.cldap_answered();
                reply
            }
        };

        if reply.is_empty() {
            continue;
        }
        if let Err(err) = socket.send_to(&reply, peer).await {
            metrics.cldap_failed(err.to_string().as_str());
        }
    }
}

/// Whether the directory holds an account the ping named.
///
/// By `sAMAccountName`, which is what a ping's `User` clause carries, and then by `uid`, which is
/// what this server's own entries use. Two lookups rather than a filter, because there are two
/// candidate attributes and a scan of the store for each ping would be a denial of service with
/// extra steps.
fn user_exists(directory: &crate::directory::Directory, _base: &str, user: &str) -> bool {
    directory.find(&format!("uid={user}")).is_some()
        || directory.all().iter().any(|entry| {
            entry
                .attributes()
                .get("sAMAccountName")
                .and_then(|attribute| attribute.values.first())
                .is_some_and(|value| value.eq_ignore_ascii_case(user))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlogon::{flags, nt_version};

    fn advertised() -> netlogon::Advertised {
        netlogon::Advertised {
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

    /// Builds the datagram Windows sends, so the tests exercise the real shape of a ping.
    fn ping_datagram(message_id: u32, clauses: &[(&str, &[u8])]) -> Vec<u8> {
        let mut filter = Vec::new();
        for (attribute, value) in clauses {
            let assertion = rasn_ldap::AttributeValueAssertion::new(
                AttributeDescription::from(attribute.to_string()),
                AssertionValue::from(*value),
            );
            filter.push(Filter::EqualityMatch(assertion));
        }
        let filter = Filter::And(SetOf::from_vec(filter));

        let request = rasn_ldap::SearchRequest::new(
            LdapDn::from(""),
            rasn_ldap::SearchRequestScope::BaseObject,
            rasn_ldap::SearchRequestDerefAliases::NeverDerefAliases,
            0,
            0,
            false,
            filter,
            vec![rasn_ldap::LdapString("Netlogon".to_string())],
        );

        crate::ldap::codec::encode(&LdapMessage::new(
            message_id,
            ProtocolOp::SearchRequest(request),
        ))
        .expect("the test builds an encodable message")
    }

    fn ntver(value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }

    #[test]
    fn a_real_ping_is_understood_with_its_domain_and_version() {
        let version =
            ntver(nt_version::NETLOGON_NT_VERSION_1 | nt_version::NETLOGON_NT_VERSION_5EX);
        let datagram = ping_datagram(7, &[("DnsDomain", b"example.com"), ("NtVer", &version)]);

        let ping = parse(&datagram).expect("a ping is understood");

        assert_eq!(ping.message_id, 7);
        assert_eq!(ping.dns_domain.as_deref(), Some("example.com"));
        assert_eq!(ping.nt_version, 0x0000_0005);
        assert_eq!(ping.user, None);
    }

    #[test]
    fn a_ping_without_a_version_is_answered_as_the_oldest_structure() {
        // The specification's own fallback, and the reason it exists: a client that predates every
        // version bit still has to get an answer.
        let datagram = ping_datagram(1, &[("DnsDomain", b"example.com")]);

        let ping = parse(&datagram).expect("a ping is understood");

        assert_eq!(ping.nt_version, nt_version::NETLOGON_NT_VERSION_1);
        assert_eq!(
            netlogon::Shape::for_version(ping.nt_version),
            netlogon::Shape::Nt40
        );
    }

    #[test]
    fn a_search_that_does_not_ask_for_netlogon_is_not_a_ping() {
        let request = rasn_ldap::SearchRequest::new(
            LdapDn::from(""),
            rasn_ldap::SearchRequestScope::BaseObject,
            rasn_ldap::SearchRequestDerefAliases::NeverDerefAliases,
            0,
            0,
            false,
            Filter::Present(AttributeDescription::from("objectClass".to_string())),
            vec![rasn_ldap::LdapString("namingContexts".to_string())],
        );
        let datagram =
            crate::ldap::codec::encode(&LdapMessage::new(1, ProtocolOp::SearchRequest(request)))
                .expect("encodable");

        assert_eq!(parse(&datagram), Err(Refused::NotAPing));
    }

    #[test]
    fn something_that_is_not_a_search_is_refused() {
        let datagram = crate::ldap::codec::encode(&LdapMessage::new(
            1,
            ProtocolOp::UnbindRequest(rasn_ldap::UnbindRequest),
        ))
        .expect("encodable");

        assert_eq!(parse(&datagram), Err(Refused::NotASearch));
    }

    #[test]
    fn a_datagram_that_is_not_ldap_at_all_is_refused_without_panicking() {
        let refused = parse(b"this is not BER").expect_err("refused");
        assert!(matches!(refused, Refused::Malformed(_)));

        assert!(matches!(parse(&[]), Err(Refused::Malformed(_))));
    }

    #[test]
    fn a_datagram_larger_than_a_ping_can_be_is_refused_before_it_is_parsed() {
        let mut oversized = vec![0u8; MAX_DATAGRAM + 1];
        oversized[0] = 0x30;

        let refused = parse(&oversized).expect_err("refused");
        assert!(matches!(refused, Refused::Malformed(detail) if detail.contains("2048")));
    }

    #[test]
    fn a_version_word_that_is_not_four_bytes_is_a_bad_filter() {
        let datagram = ping_datagram(1, &[("DnsDomain", b"example.com"), ("NtVer", b"\x06\x00")]);

        let refused = parse(&datagram).expect_err("refused");
        assert!(matches!(refused, Refused::BadFilter(detail) if detail.contains("NtVer")));
    }

    #[test]
    fn a_substring_clause_is_not_part_of_a_ping() {
        let filter = Filter::Substrings(rasn_ldap::SubstringFilter::new(
            AttributeDescription::from("DnsDomain".to_string()),
            vec![rasn_ldap::SubstringChoice::Initial(AssertionValue::from(
                "example".as_bytes(),
            ))],
        ));
        let request = rasn_ldap::SearchRequest::new(
            LdapDn::from(""),
            rasn_ldap::SearchRequestScope::BaseObject,
            rasn_ldap::SearchRequestDerefAliases::NeverDerefAliases,
            0,
            0,
            false,
            filter,
            vec![rasn_ldap::LdapString("Netlogon".to_string())],
        );
        let datagram =
            crate::ldap::codec::encode(&LdapMessage::new(1, ProtocolOp::SearchRequest(request)))
                .expect("encodable");

        assert!(matches!(parse(&datagram), Err(Refused::BadFilter(_))));
    }

    #[test]
    fn the_reply_is_an_entry_with_netlogon_and_a_successful_done() {
        let version =
            ntver(nt_version::NETLOGON_NT_VERSION_1 | nt_version::NETLOGON_NT_VERSION_5EX);
        let ping = parse(&ping_datagram(
            9,
            &[("DnsDomain", b"example.com"), ("NtVer", &version)],
        ))
        .expect("understood");

        let reply = answer(&ping, &advertised(), |_| true);

        // Two LDAP messages back to back, both carrying the id of the request.
        let first = crate::ldap::codec::parse_header(&reply).expect("a header");
        let first_len = first.total_len();
        let entry = crate::ldap::codec::decode(&reply[..first_len]).expect("an entry");
        assert_eq!(entry.message_id, 9);
        let ProtocolOp::SearchResEntry(entry) = &entry.protocol_op else {
            panic!("the first reply message must be an entry");
        };
        assert_eq!(entry.object_name.0.as_str(), "");
        assert_eq!(entry.attributes.len(), 1);
        assert_eq!(entry.attributes[0].r#type.0.as_str(), "Netlogon");

        let done = crate::ldap::codec::decode(&reply[first_len..]).expect("a done");
        assert_eq!(done.message_id, 9);
        assert!(matches!(done.protocol_op, ProtocolOp::SearchResDone(_)));
    }

    #[test]
    fn the_netlogon_value_carries_the_advertised_domain() {
        let version =
            ntver(nt_version::NETLOGON_NT_VERSION_1 | nt_version::NETLOGON_NT_VERSION_5EX);
        let ping = parse(&ping_datagram(
            3,
            &[("DnsDomain", b"example.com"), ("NtVer", &version)],
        ))
        .expect("understood");

        let reply = answer(&ping, &advertised(), |_| true);
        let first_len = crate::ldap::codec::parse_header(&reply)
            .expect("a header")
            .total_len();
        let entry = crate::ldap::codec::decode(&reply[..first_len]).expect("an entry");
        let ProtocolOp::SearchResEntry(entry) = &entry.protocol_op else {
            panic!("an entry");
        };
        let values: Vec<&[u8]> = entry.attributes[0].vals.iter().map(AsRef::as_ref).collect();
        let value = *values.first().expect("one value");

        // Opcode, reserved word, flags, GUID, then the forest name.
        assert_eq!(
            u16::from_le_bytes([value[0], value[1]]),
            netlogon::LOGON_SAM_LOGON_RESPONSE_EX
        );
        assert_eq!(
            u32::from_le_bytes([value[4], value[5], value[6], value[7]]) & flags::DS_KDC_FLAG,
            0,
            "the KDC bit tells the truth: this server issues no tickets"
        );
        let (forest, _) = netlogon::read_name(&value[24..]).expect("a readable name");
        assert_eq!(forest, "example.com");
    }

    #[test]
    fn a_refusal_is_an_entry_with_no_attributes_and_a_successful_done() {
        // MS-ADTS 6.3.3.3, for a filter this server cannot evaluate and for a domain it does not
        // hold: a well-formed answer that names no controller, rather than a timeout.
        let reply = refuse(11);
        let first_len = crate::ldap::codec::parse_header(&reply)
            .expect("a header")
            .total_len();

        let entry = crate::ldap::codec::decode(&reply[..first_len]).expect("an entry");
        let ProtocolOp::SearchResEntry(entry) = &entry.protocol_op else {
            panic!("an entry");
        };
        assert_eq!(entry.attributes.len(), 0, "a refusal names no attribute");

        let done = crate::ldap::codec::decode(&reply[first_len..]).expect("a done");
        assert!(matches!(done.protocol_op, ProtocolOp::SearchResDone(_)));
    }

    #[test]
    fn the_domain_is_the_leading_dc_components_of_the_naming_context() {
        assert_eq!(
            domain_of_base("dc=example,dc=com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            domain_of_base("DC=Example,DC=ORG").as_deref(),
            Some("example.org")
        );
        // A subtree context still describes a domain; the `ou` is not part of the name.
        assert_eq!(
            domain_of_base("ou=people,dc=example,dc=com"),
            None,
            "an ou first means the leading components are not a domain"
        );
        assert_eq!(domain_of_base("o=example"), None);
        assert_eq!(domain_of_base(""), None);
    }

    #[test]
    fn the_settings_are_derived_from_what_the_server_already_knows() {
        let bound: std::net::SocketAddr = "192.0.2.10:389".parse().expect("parses");
        let settings =
            Settings::resolve(&CldapConfig::default(), "dc=example,dc=com", bound, false)
                .expect("resolves");

        assert_eq!(settings.advertised.dns_domain, "example.com");
        assert_eq!(settings.advertised.dns_forest, "example.com");
        assert_eq!(settings.advertised.netbios_domain, "EXAMPLE");
        assert_eq!(settings.advertised.address, Ipv4Addr::new(192, 0, 2, 10));
        assert!(
            settings.advertised.dns_host.ends_with(".example.com"),
            "the host name is placed under the domain: {}",
            settings.advertised.dns_host
        );
        // The same domain always yields the same GUID, which is what a client caching a controller
        // relies on.
        let again = Settings::resolve(&CldapConfig::default(), "dc=example,dc=com", bound, false)
            .expect("resolves");
        assert_eq!(
            settings.advertised.domain_guid,
            again.advertised.domain_guid
        );
    }

    #[test]
    fn a_wildcard_bind_advertises_the_loopback_address_rather_than_nothing() {
        let bound: std::net::SocketAddr = "0.0.0.0:389".parse().expect("parses");
        let settings =
            Settings::resolve(&CldapConfig::default(), "dc=example,dc=com", bound, false)
                .expect("resolves");

        assert_eq!(settings.advertised.address, Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn a_domain_that_disagrees_with_the_naming_context_is_refused_with_the_reason() {
        let bound: std::net::SocketAddr = "192.0.2.10:389".parse().expect("parses");
        let config = CldapConfig {
            enabled: true,
            dns_domain: Some("other.example".to_string()),
            ..CldapConfig::default()
        };

        let refused = Settings::resolve(&config, "dc=example,dc=com", bound, false)
            .expect_err("a controller answers for the naming context it holds");

        assert!(refused.contains("other.example"), "{refused}");
        assert!(refused.contains("example.com"), "{refused}");
    }

    #[test]
    fn an_empty_configured_name_is_refused_rather_than_defaulted() {
        let bound: std::net::SocketAddr = "192.0.2.10:389".parse().expect("parses");
        for config in [
            CldapConfig {
                dns_domain: Some("   ".to_string()),
                ..CldapConfig::default()
            },
            CldapConfig {
                dns_host: Some(String::new()),
                ..CldapConfig::default()
            },
            CldapConfig {
                netbios_host: Some(" ".to_string()),
                ..CldapConfig::default()
            },
        ] {
            assert!(Settings::resolve(&config, "dc=example,dc=com", bound, false).is_err());
        }
    }

    #[test]
    fn a_netbios_name_is_cut_to_fifteen_characters() {
        let bound: std::net::SocketAddr = "192.0.2.10:389".parse().expect("parses");
        let config = CldapConfig {
            netbios_host: Some("A-VERY-LONG-NAME-INDEED".to_string()),
            ..CldapConfig::default()
        };
        let settings =
            Settings::resolve(&config, "dc=example,dc=com", bound, false).expect("resolves");

        // Configured names are taken as written; the truncation is what a *derived* name gets, and
        // this test pins that the configured one is not silently cut.
        assert_eq!(settings.advertised.netbios_host, "A-VERY-LONG-NAME-INDEED");
    }

    #[test]
    fn the_section_refuses_a_key_it_does_not_know() {
        let parsed: Result<CldapConfig, _> = serde_saphyr::from_str("enable: true");
        assert!(parsed.is_err(), "an unused key must not pass silently");

        let parsed: CldapConfig =
            serde_saphyr::from_str("enabled: true\ndns_domain: example.com").expect("parses");
        assert!(parsed.enabled);
        assert_eq!(parsed.dns_domain.as_deref(), Some("example.com"));
    }
}
