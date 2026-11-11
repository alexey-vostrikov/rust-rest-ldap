//! The KDC, in this process, reading the same directory the LDAP side serves.
//!
//! A realm is not a second copy of the accounts: `rust-heimdal-kdc` exposes the mapping between a
//! principal and directory attributes (`hdb::ldap`), and the three operations it needs from whatever
//! holds the entries (`hdb::ldap::Directory`). This module is that implementation over this server's
//! own storage, plus the transports - the engine answers octets and nothing else, so UDP and TCP for
//! port 88 are ours.
//!
//! # Why the entries are Heimdal's attributes and not ours
//!
//! A key is DER per key version, and how it is packed beside `kvno`, enctypes and validity is a
//! detail with an existing answer. `to_attributes`/`from_attributes` are that answer, so an entry
//! written by this module can be read by an auditor with Heimdal's schema in hand, and a password
//! change made by another tool is legible here without a translation table this crate would have to
//! keep in step. The one thing this crate decides is how bytes sit in a string-valued store: they are
//! base64, which is what the protocol itself does when it carries a binary value in LDIF.
//!
//! # What is deliberately absent
//!
//! Writing through the KDC (`put`, `delete`) returns an error: principals are created and changed
//! through LDAP, where the access control, the schema and the replication already are. A second write
//! path that skipped all three would be a way to add an account nobody can audit. `kadmin` is not
//! served for the same reason, and will be when it carries an authorization story rather than a
//! second door.

pub mod bootstrap;
pub mod realm;
pub mod schema;
pub mod secrets;
pub mod serve;
pub mod unicode_pwd;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

/// What the `kerberos:` section says.
///
/// Off by default, as `cldap:` is, and for the same reason: answering on port 88 is a promise that
/// this server issues tickets, and a server that advertises a KDC it does not run sends every client
/// into a timeout that reads like a network fault.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KerberosConfig {
    /// Whether to run a KDC at all.
    pub enabled: bool,
    /// The realm, `EXAMPLE.COM`.
    ///
    /// Derived from the naming context when absent (`dc=example,dc=com` is `EXAMPLE.COM`), because a
    /// realm and a naming context that disagree describe two different domains, and a client would
    /// get a ticket for one and an entry for the other.
    pub realm: Option<String>,
    /// The port to listen on, TCP and UDP.
    ///
    /// 88 by default, the only port a client tries. A different value exists for one honest reason:
    /// only root may bind below 1024, and a test or a developer without that right still has to be
    /// able to check the exchange end to end.
    pub port: Option<u16>,
    /// A file holding the realm's master password, used once to create `krbtgt/<REALM>`.
    ///
    /// Read only when that entry is missing. The password never leaves the file, and the file is
    /// read at start rather than kept: deriving a key from it is the only thing it is for.
    pub master_key_file: Option<PathBuf>,
}

/// The resolved form: what a listener needs, and nothing that can disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The realm, upper-cased, as it appears in a principal.
    pub realm: String,
    /// Where to listen, both transports.
    pub bind: SocketAddr,
}

impl Settings {
    /// Resolves the section against the naming context and the address the LDAP listener took.
    ///
    /// Every disagreement is refused here rather than at the first ticket: a realm that cannot be
    /// derived, a name that is not a realm, a port of zero.
    pub fn resolve(
        config: &KerberosConfig,
        base_dn: &str,
        bind_ip: IpAddr,
    ) -> Result<Settings, String> {
        let realm = match &config.realm {
            Some(realm) => realm.trim().to_string(),
            None => realm_from_base_dn(base_dn).ok_or_else(|| {
                format!(
                    "no realm given and none can be derived from '{base_dn}': say `kerberos.realm`"
                )
            })?,
        };
        if realm.is_empty() {
            return Err("kerberos.realm is empty".to_string());
        }
        // A realm is a DNS name in upper case, and a Kerberos principal's realm component cannot
        // carry `@`, `/` or `\` - they would make the principal ambiguous, not merely odd.
        if realm.contains('@') || realm.contains('/') || realm.contains('\\') || realm.contains(',')
        {
            return Err(format!(
                "kerberos.realm '{realm}' contains a character a principal cannot carry (@, /, \\, ,)"
            ));
        }
        let realm = realm.to_ascii_uppercase();
        if realm.is_empty() {
            return Err("kerberos.realm is empty".to_string());
        }

        // 0 asks the kernel for a free port, and both transports then take that one. It exists for
        // tests and for a stand that cannot bind 88; an operator who sets it gets a KDC nobody has
        // been told the address of, which is their own doing and visible in the startup line.
        let port = config.port.unwrap_or(88);
        let ip = bind_ip;

        Ok(Settings {
            realm,
            bind: SocketAddr::new(ip, port),
        })
    }
}

/// `dc=example,dc=com` is the domain `example.com`, and its realm is that in upper case.
///
/// Not a general DN reader: it takes the `dc=` components from the left, stops at the first thing
/// that is not one, and gives nothing when what it found is a single label. A naming context of
/// `o=acme` has no domain name in it, and inventing `ACME` as a realm would issue tickets for a name
/// no client asks for.
fn realm_from_base_dn(base_dn: &str) -> Option<String> {
    let mut labels = Vec::new();
    for rdn in base_dn.split(',') {
        let rdn = rdn.trim();
        let (kind, value) = rdn.split_once('=')?;
        if !kind.trim().eq_ignore_ascii_case("dc") {
            break;
        }
        labels.push(value.trim().to_ascii_lowercase());
    }
    if labels.len() < 2 {
        return None;
    }
    Some(labels.join(".").to_ascii_uppercase())
}

/// The loopback address a server without a name of its own would use.
///
/// Test-only: a daemon binds the address its LDAP listener took, and only a unit test has no
/// listener to take one from.
#[cfg(test)]
pub(crate) fn localhost() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_naming_context_names_its_realm() {
        assert_eq!(
            realm_from_base_dn("dc=example,dc=com").as_deref(),
            Some("EXAMPLE.COM")
        );
        assert_eq!(
            realm_from_base_dn("dc=corp,dc=example,dc=com").as_deref(),
            Some("CORP.EXAMPLE.COM")
        );
    }

    #[test]
    fn a_naming_context_that_names_no_domain_is_refused_rather_than_guessed() {
        // `o=acme` has no domain in it. Deriving `ACME` would issue tickets for a realm no client
        // asks for, and the operator would find out at the first logon.
        assert_eq!(realm_from_base_dn("o=acme"), None);
        assert_eq!(realm_from_base_dn("dc=example"), None);
        assert_eq!(realm_from_base_dn("ou=people,dc=example,dc=com"), None);
    }

    #[test]
    fn the_section_resolves_to_a_realm_and_an_address() {
        let config = KerberosConfig {
            enabled: true,
            ..KerberosConfig::default()
        };
        let settings = Settings::resolve(&config, "dc=example,dc=com", localhost()).unwrap();
        assert_eq!(settings.realm, "EXAMPLE.COM");
        assert_eq!(settings.bind.port(), 88);
    }

    #[test]
    fn a_realm_that_disagrees_with_the_protocol_is_refused() {
        for realm in ["ex@mple.com", "exa/mple", "a,b"] {
            let config = KerberosConfig {
                enabled: true,
                realm: Some(realm.to_string()),
                ..KerberosConfig::default()
            };
            assert!(
                Settings::resolve(&config, "dc=example,dc=com", localhost()).is_err(),
                "{realm} must be refused"
            );
        }
    }

    #[test]
    fn a_realm_given_in_lower_case_is_upper_cased() {
        // The realm component of a principal is compared case-sensitively by some clients and not
        // by others; the only value that behaves the same everywhere is the conventional one.
        let config = KerberosConfig {
            enabled: true,
            realm: Some("example.com".to_string()),
            ..KerberosConfig::default()
        };
        let settings = Settings::resolve(&config, "dc=example,dc=com", localhost()).unwrap();
        assert_eq!(settings.realm, "EXAMPLE.COM");
    }
}
