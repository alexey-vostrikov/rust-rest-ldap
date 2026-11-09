//! SMB in this process: port 445, and the `IPC$` share a join talks to.
//!
//! A Samba member's first step in `net ads join` is not LDAP and not Kerberos: it is an SMB
//! connection to `\\DC\IPC$`, and everything after it - opening the `lsarpc` pipe, asking LSA who the
//! domain is - travels through that connection. Measured rather than assumed: the stand fails with
//! `transport-connection attempt was refused` from `libnet_join_connect_dc_ipc`, before any RPC is
//! spoken (`source3/libnet/libnet_join.c`).
//!
//! # What this module is
//!
//! The wiring, not the protocol. `smb-server` carries SMB2/3, the tree connect, the named pipes of
//! `IPC$` and DCE/RPC over them; this module decides the address, the name, the credentials and how
//! to stop. The same split as the KDC: an engine with no sockets, and a daemon that owns them.
//!
//! # Deliberately no file shares
//!
//! Only `IPC$`. A domain controller in this deployment is an identity service; a share with files in
//! it would be a second, unreviewed path into the same process, with its own access rules to get
//! wrong. `IPC$` is created by the library itself and is what a join needs.

pub mod serve;

use std::net::SocketAddr;
use std::path::PathBuf;

/// What the `smb:` section says.
///
/// Off by default, like `kerberos:`: a server that answers on 445 is a server claiming to be a
/// domain controller, and one that answers and then cannot complete a join sends a machine to a dead
/// end with a message about a transport.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmbConfig {
    /// Whether to serve SMB at all.
    pub enabled: bool,
    /// The port.
    ///
    /// 445 by default, the only port a client tries. A different value exists for one honest
    /// reason: only root may bind below 1024, and a test or a developer without that right still has
    /// to be able to check the handshake end to end.
    pub port: Option<u16>,
    /// The NetBIOS name this server answers to, `SAMBA`.
    ///
    /// Defaults to the host name of the DNS name the CLDAP section advertises, upper-cased, so that
    /// a client which found this server one way recognises it by the other. Two names for one server
    /// is how a machine ends up joined to a controller it cannot reach.
    pub netbios_name: Option<String>,
    /// Accounts SMB accepts a password for.
    ///
    /// NTLM only, and deliberately narrow: this is for the one path a Kerberos realm cannot carry -
    /// a client that joins with an account's password rather than a ticket. A deployment that has a
    /// keytab needs none of these, and one that has only these has no domain logon.
    ///
    /// The password is named by an environment variable rather than written here, for the same
    /// reason the bootstrap section does: a configuration file is read by whatever runs the server,
    /// and a password in it is a password in `ps` for anybody who can read one.
    #[serde(default)]
    pub users: Vec<SmbUser>,
    /// The DNS name of the domain, `ad.example.com`.
    ///
    /// Derived from the naming context when absent, by the same rule `KerberosConfig` uses, so that
    /// the realm, the CLDAP answer and this cannot disagree.
    pub dns_domain: Option<String>,
    /// A keytab for Kerberos in SESSION_SETUP.
    ///
    /// Without it the server accepts NTLM only, which a Samba member can use with an administrator's
    /// password and a Windows member will refuse. Read at start and never re-read: a keytab that
    /// changes under a running server is a keytab an operator meant to restart for.
    pub keytab: Option<PathBuf>,
}

/// One account SMB accepts a password for.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmbUser {
    /// The account name, without a domain prefix.
    pub name: String,
    /// The environment variable holding the password.
    pub password_env: String,
}

/// The resolved form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Where to listen.
    pub bind: SocketAddr,
    /// The name this server answers to.
    pub netbios_name: String,
    /// Where the keytab is, if there is one.
    pub keytab: Option<PathBuf>,
    /// The accounts resolved to their passwords.
    pub users: Vec<(String, String)>,
    /// The DNS name of the domain, `ad.example.com`.
    ///
    /// Answered by `lsarpc` when a member asks what domain it has reached. A client compares this
    /// against the realm it was told, and a wrong name sends it looking for another domain - so it
    /// comes from the same place CLDAP takes its answer from, not from a second derivation.
    pub dns_domain: Option<String>,
}

impl Settings {
    /// Resolves the section against the address the LDAP listener took.
    ///
    /// A missing `netbios_name` is refused rather than invented here: the name has to agree with
    /// what CLDAP advertises, and that is a decision the daemon makes once, in one place.
    pub fn resolve(
        config: &SmbConfig,
        bind_ip: std::net::IpAddr,
        netbios_name: Option<&str>,
    ) -> Result<Settings, String> {
        let port = config.port.unwrap_or(445);
        let netbios_name = match (&config.netbios_name, netbios_name) {
            (Some(name), _) => name.clone(),
            (None, Some(name)) => name.to_string(),
            (None, None) => {
                return Err(
                    "smb.netbios_name is not set and none can be derived: say `smb.netbios_name`"
                        .to_string(),
                );
            }
        };
        if netbios_name.is_empty() {
            return Err("smb.netbios_name is empty".to_string());
        }
        // A NetBIOS name is at most 15 octets (RFC 1001 §14.1), and a longer one is truncated by
        // every client that reads it - two servers whose names truncate to the same thing are two
        // servers a client cannot tell apart.
        if netbios_name.len() > 15 {
            return Err(format!(
                "smb.netbios_name '{netbios_name}' is {} octets, a NetBIOS name holds 15",
                netbios_name.len()
            ));
        }

        if let Some(keytab) = &config.keytab
            && !keytab.exists()
        {
            // Fail here rather than accept a bind that will refuse every Kerberos session: the
            // failure then names the file at start, once, instead of reading as a client problem.
            return Err(format!("smb.keytab '{}' does not exist", keytab.display()));
        }

        // Resolved here rather than at use: a password that is missing is a startup failure with
        // the variable's name in it, not a session setup that fails later for reasons the operator
        // has to guess at.
        let mut users = Vec::with_capacity(config.users.len());
        for user in &config.users {
            if user.name.is_empty() {
                return Err("smb.users: an account with an empty name".to_string());
            }
            let password = std::env::var(&user.password_env).map_err(|_| {
                format!(
                    "smb.users: '{}' names the password variable '{}', which is not set",
                    user.name, user.password_env
                )
            })?;
            if password.is_empty() {
                return Err(format!(
                    "smb.users: '{}' has an empty password in '{}'",
                    user.name, user.password_env
                ));
            }
            users.push((user.name.clone(), password));
        }

        Ok(Settings {
            bind: SocketAddr::new(bind_ip, port),
            netbios_name,
            keytab: config.keytab.clone(),
            users,
            dns_domain: config.dns_domain.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    fn config() -> SmbConfig {
        SmbConfig {
            enabled: true,
            ..SmbConfig::default()
        }
    }

    #[test]
    fn the_section_resolves_to_a_port_and_a_name() {
        let settings =
            Settings::resolve(&config(), Ipv4Addr::LOCALHOST.into(), Some("SAMBA")).expect("ok");
        assert_eq!(settings.bind.port(), 445);
        assert_eq!(settings.netbios_name, "SAMBA");
    }

    #[test]
    fn a_name_from_the_configuration_wins_over_the_derived_one() {
        // The configuration is the operator's decision; the derived name is a convenience for the
        // case they did not state one. A server whose two names disagree is a server a client
        // reaches by one and refuses by the other.
        let stated = SmbConfig {
            netbios_name: Some("DC1".to_string()),
            ..config()
        };
        let settings =
            Settings::resolve(&stated, Ipv4Addr::LOCALHOST.into(), Some("SAMBA")).expect("ok");
        assert_eq!(settings.netbios_name, "DC1");
    }

    #[test]
    fn a_name_nobody_stated_is_refused_rather_than_invented() {
        // Inventing one would produce a server that answers to a name CLDAP does not advertise, and
        // the client would find it by one and fail to reach it by the other.
        let error = Settings::resolve(&config(), Ipv4Addr::LOCALHOST.into(), None)
            .expect_err("a name is required");
        assert!(error.contains("netbios_name"), "{error}");
    }

    #[test]
    fn a_name_a_netbios_client_cannot_carry_is_refused() {
        let long = SmbConfig {
            netbios_name: Some("A-VERY-LONG-NETBIOS-NAME".to_string()),
            ..config()
        };
        let error = Settings::resolve(&long, Ipv4Addr::LOCALHOST.into(), None)
            .expect_err("15 octets at most");
        assert!(error.contains("15"), "{error}");
    }

    #[test]
    fn a_password_that_is_not_in_the_environment_stops_the_start() {
        // Named by a variable rather than written in the file, so this is where a missing one is
        // caught: a session setup failing later would say nothing about which variable to set.
        let configured = SmbConfig {
            users: vec![SmbUser {
                name: "administrator".to_string(),
                password_env: "RR_LDAP_TEST_MISSING_PASSWORD_VARIABLE".to_string(),
            }],
            ..config()
        };
        let error = Settings::resolve(&configured, Ipv4Addr::LOCALHOST.into(), Some("SAMBA"))
            .expect_err("the variable is not set");
        assert!(
            error.contains("RR_LDAP_TEST_MISSING_PASSWORD_VARIABLE"),
            "{error}"
        );
    }

    #[test]
    fn an_account_resolves_to_its_password() {
        // The one path a realm cannot carry: a client that joins with a password rather than a
        // ticket, which is what NTLM needs.
        //
        // `PATH` rather than a variable of its own: this crate forbids `unsafe`, so a test cannot
        // set one, and what is being checked is the reading, not the value.
        let expected = std::env::var("PATH").expect("PATH is set for any process");
        let configured = SmbConfig {
            users: vec![SmbUser {
                name: "administrator".to_string(),
                password_env: "PATH".to_string(),
            }],
            ..config()
        };

        let settings =
            Settings::resolve(&configured, Ipv4Addr::LOCALHOST.into(), Some("SAMBA")).expect("ok");
        assert_eq!(
            settings.users,
            vec![("administrator".to_string(), expected)]
        );
    }

    #[test]
    fn a_keytab_that_is_not_there_stops_the_start() {
        // Accepted silently, every Kerberos session would be refused later, and the refusal would
        // read as a client problem rather than as a missing file.
        let missing = SmbConfig {
            keytab: Some(PathBuf::from("/nonexistent/service.keytab")),
            ..config()
        };
        let error = Settings::resolve(&missing, Ipv4Addr::LOCALHOST.into(), Some("SAMBA"))
            .expect_err("the file does not exist");
        assert!(error.contains("does not exist"), "{error}");
    }
}
