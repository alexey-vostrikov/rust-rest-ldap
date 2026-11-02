//! Command line interface.

use std::path::PathBuf;

use clap::Parser;

use crate::config;

#[derive(Debug, Parser)]
#[command(
    name = "rust-rest-ldap",
    version,
    about = "LDAP server with REST API & file backends"
)]
pub struct Cli {
    /// Config file path
    #[arg(short = 'c', long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Backend to use
    #[arg(short = 'b', long = "backend", value_name = "BACKEND")]
    pub backend: Option<String>,

    /// Server base dn
    #[arg(short = 'B', long = "basedn", value_name = "BASEDN")]
    pub base_dn: Option<String>,

    /// Listen addr for LDAP
    #[arg(short = 'L', long = "listen", value_name = "ADDR")]
    pub listen: Option<String>,

    /// Data update interval
    #[arg(short = 'I', long = "interval", value_name = "INTERVAL")]
    pub interval: Option<String>,

    /// Log file path
    #[arg(short = 'l', long = "log", value_name = "PATH")]
    pub log: Option<PathBuf>,

    /// Turn on debug logging
    #[arg(short = 'd', long = "debug")]
    pub debug: bool,
}

impl From<Cli> for config::Args {
    fn from(cli: Cli) -> Self {
        Self {
            config: cli.config,
            backend: cli.backend,
            base_dn: cli.base_dn,
            listen_addr: cli.listen,
            interval: cli.interval,
            log_path: cli.log,
            debug: cli.debug,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn every_flag_maps_into_config_args() {
        let cli = Cli::parse_from([
            "rust-rest-ldap",
            "-c",
            "config.yaml",
            "-b",
            "file",
            "-B",
            "dc=example,dc=org",
            "-L",
            "127.0.0.1:1389",
            "-I",
            "30s",
            "-l",
            "/tmp/rr.log",
            "-d",
        ]);

        let args: config::Args = cli.into();

        assert_eq!(
            args.config.as_deref(),
            Some(std::path::Path::new("config.yaml"))
        );
        assert_eq!(args.backend.as_deref(), Some("file"));
        assert_eq!(args.base_dn.as_deref(), Some("dc=example,dc=org"));
        assert_eq!(args.listen_addr.as_deref(), Some("127.0.0.1:1389"));
        assert_eq!(args.interval.as_deref(), Some("30s"));
        assert_eq!(
            args.log_path.as_deref(),
            Some(std::path::Path::new("/tmp/rr.log"))
        );
        assert!(args.debug);
    }

    #[test]
    fn no_flags_mean_no_overrides() {
        let cli = Cli::parse_from(["rust-rest-ldap"]);

        let args: config::Args = cli.into();

        assert_eq!(args, config::Args::default());
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
