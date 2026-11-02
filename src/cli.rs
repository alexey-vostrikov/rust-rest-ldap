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

    /// Write the directory as LDIF to PATH and exit ('-' for stdout)
    ///
    /// Loads the configured backend and dumps it; the server is not started. The
    /// output is what `ldapadd -f` expects, so it can be fed to OpenLDAP or 389 DS.
    #[arg(long = "export-ldif", value_name = "PATH", conflicts_with = "listen")]
    pub export_ldif: Option<PathBuf>,

    /// Write the directory as YAML to PATH and exit ('-' for stdout)
    ///
    /// The same entries as `--export-ldif`, in a shape meant to be read and diffed: one
    /// value per line, Cyrillic as text rather than base64. LDIF is still the format to
    /// hand to ldapadd; this one is for people and for review.
    #[arg(long = "export-yaml", value_name = "PATH", conflicts_with_all = ["export_ldif", "listen"])]
    pub export_yaml: Option<PathBuf>,

    /// Include operational attributes (entryUUID, timestamps, entryCSN) in the export
    ///
    /// Off by default: on import the target directory issues its own, and two servers
    /// would then disagree about which value wins.
    // Meaningful only together with an export; checked in `main`, where the message can
    // say that in the operator's language. clap's own conflict rules cannot express
    // "requires one of two flags" in a readable way.
    #[arg(long = "export-operational")]
    pub export_operational: bool,

    /// Load an LDIF file into the configured store and exit
    ///
    /// The offline counterpart of ldapadd, and the way an empty directory is filled: `add`
    /// over the protocol needs a bind, and a bind needs an entry that is not there yet.
    /// The whole file is written in one transaction, so a broken record leaves the store
    /// untouched. '-' reads standard input.
    #[arg(long = "import-ldif", value_name = "PATH", conflicts_with = "listen")]
    pub import_ldif: Option<PathBuf>,

    /// Import into a store that already holds entries
    ///
    /// Off by default, because a mistyped path that merges a dump into a live directory is
    /// discovered by its effects. Turns the import into an upsert of what the file holds.
    #[arg(long = "allow-existing-entry", requires = "import_ldif")]
    pub allow_existing_entry: bool,

    /// Check the configuration, the schema, the data files and the store, then exit
    ///
    /// What `slaptest` does: says whether this configuration would start, without binding a
    /// port. The exit code is the answer, so a deployment script can branch on it.
    #[arg(long = "check-config", conflicts_with_all = ["listen", "import_ldif"])]
    pub check_config: bool,
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
            export_ldif: cli.export_ldif,
            export_yaml: cli.export_yaml,
            export_operational: cli.export_operational,
            import_ldif: cli.import_ldif,
            allow_existing_entry: cli.allow_existing_entry,
            check_config: cli.check_config,
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

        assert_eq!(args.export_ldif, None, "a plain run is not an export");
        assert_eq!(args, config::Args::default());
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
