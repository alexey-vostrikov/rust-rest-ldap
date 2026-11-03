//! The connection settings and the bind every command-line tool shares.
//!
//! `ldapsearch`, `ldapmodify` and `ldaputil` each had their own copy of `url_of`, `trust_of`,
//! `authenticate` and `ask_password`, and the copies had already drifted: `url_of` in
//! `ldapsearch` returned `Result<String, Failure>` with no branch that could produce an `Err`,
//! so its callers handled a failure that could not happen while the other two tools simply
//! returned the string. Three copies of a decision is three places to change it and two to
//! forget.
//!
//! The settings are a struct rather than three trait implementations: the three tools take their
//! flags through `clap`, and a trait would have meant either generics over a `Cli` each tool
//! defines or the same four accessors written three times - which is the arrangement this module
//! exists to remove.

use crate::client::{Client, Error, Trust};

/// What a tool needs to reach a server and who it claims to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// `-H`; when absent the URL is built from `-h` and `-p`.
    pub url: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub bind_dn: String,
    pub password: Option<String>,
    pub ask_password: bool,
    /// `-Z` once, `-ZZ` twice.
    pub starttls: u8,
    pub insecure: bool,
    pub ca_cert: Option<std::path::PathBuf>,
}

impl Connection {
    /// The URL to connect to.
    ///
    /// `localhost` when neither a URL nor a host was given, which is what the OpenLDAP tools do
    /// and what every example in the documentation assumes.
    pub fn url(&self) -> String {
        if let Some(url) = &self.url {
            return url.clone();
        }

        let host = self.host.clone().unwrap_or_else(|| "localhost".to_string());
        match self.port {
            Some(port) => format!("ldap://{host}:{port}"),
            None => format!("ldap://{host}"),
        }
    }

    /// How to verify the server: not at all, against a CA file, or against the web PKI.
    pub fn trust(&self) -> Trust {
        if self.insecure {
            return Trust::Insecure;
        }
        match &self.ca_cert {
            Some(path) => Trust::File(path.clone()),
            None => Trust::WebPki,
        }
    }

    /// Whether a bind was asked for at all.
    ///
    /// A DN, a password, or a request to be asked for one. An anonymous search is a legitimate
    /// question, so nothing here turns "no credentials" into "bind with an empty password".
    pub fn binds(&self) -> bool {
        !self.bind_dn.is_empty() || self.password.is_some() || self.ask_password
    }

    /// Binds if the command line asks for it, then upgrades with StartTLS if it was requested.
    ///
    /// Binding first and upgrading second is the order the OpenLDAP tools use, and it is what
    /// lets `-D`/`-w` combine with `-Z`: the password goes over the upgraded connection.
    pub async fn authenticate(&self, client: &Client) -> Result<(), Error> {
        if self.binds() {
            let password = match &self.password {
                Some(password) => password.clone(),
                None if self.ask_password => ask_password()?,
                None => String::new(),
            };
            client.bind(&self.bind_dn, &password).await?;
        }

        if self.starttls > 0 {
            client.starttls().await?;
        }

        Ok(())
    }
}

/// Reads a password from the terminal.
///
/// The prompt goes to stderr so that it does not end up in a pipeline's stdout alongside the
/// results. The input is echoed, unlike the OpenLDAP tools: turning echo off needs a terminal
/// control call, and a password echoed to the operator's own screen is a smaller problem than a
/// tool that silently reads from a closed stdin.
pub fn ask_password() -> Result<String, Error> {
    eprint!("Enter LDAP Password: ");
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .map_err(|err| Error::Io(err.to_string()))?;

    Ok(password.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn settings() -> Connection {
        Connection {
            url: None,
            host: None,
            port: None,
            bind_dn: String::new(),
            password: None,
            ask_password: false,
            starttls: 0,
            insecure: false,
            ca_cert: None,
        }
    }

    #[test]
    fn a_url_wins_over_host_and_port() {
        let mut connection = settings();
        connection.url = Some("ldaps://ldap.example.com".to_string());
        connection.host = Some("ignored".to_string());
        connection.port = Some(1);

        assert_eq!(connection.url(), "ldaps://ldap.example.com");
    }

    #[test]
    fn a_host_without_a_port_is_still_a_url() {
        let mut connection = settings();
        connection.host = Some("ldap.example.com".to_string());

        assert_eq!(connection.url(), "ldap://ldap.example.com");
    }

    #[test]
    fn nothing_at_all_means_localhost() {
        // What every OpenLDAP example assumes, and what the documentation of this project shows.
        assert_eq!(settings().url(), "ldap://localhost");
    }

    #[test]
    fn the_trust_policy_follows_the_settings_in_the_order_that_matters() {
        // `--insecure` wins over `--cacert`: an operator who asked to verify nothing gets
        // nothing, rather than a CA file that is silently ignored.
        let mut connection = settings();
        assert_eq!(connection.trust(), Trust::WebPki);

        connection.ca_cert = Some(PathBuf::from("/etc/ca.pem"));
        assert_eq!(
            connection.trust(),
            Trust::File(PathBuf::from("/etc/ca.pem"))
        );

        connection.insecure = true;
        assert_eq!(connection.trust(), Trust::Insecure);
    }

    #[test]
    fn an_empty_password_is_not_the_same_as_no_password() {
        // The distinction the three copies of this code had to agree on: a bind DN with an empty
        // password is an unauthenticated bind, which servers refuse. `authenticate` sends it
        // rather than refusing locally, so the server's answer is what the operator sees - but
        // it must not turn "no password given" into "password is the empty string" and bind
        // when the command line asked for nothing.
        let mut connection = settings();
        assert!(!connection.binds(), "nothing was asked for");

        connection.bind_dn = "cn=admin,dc=example,dc=com".to_string();
        assert!(connection.binds(), "a DN without a password still binds");
    }

    #[test]
    fn starttls_is_counted_because_one_z_and_two_mean_different_things() {
        let mut connection = settings();
        assert_eq!(connection.starttls, 0);
        connection.starttls = 1;
        assert_eq!(connection.starttls, 1, "-Z asks");
        connection.starttls = 2;
        assert_eq!(connection.starttls, 2, "-ZZ requires");
    }
}
