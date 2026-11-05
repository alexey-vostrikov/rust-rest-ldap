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

    /// Commit the current configuration as a new generation, then exit
    ///
    /// `-c` names the store directory. The configuration in force is read, written as a new
    /// generation, and `current` is pointed at it - atomically, so a crash leaves either the
    /// old generation or the new one. With `--note` the history says why.
    #[arg(long = "config-commit", conflicts_with_all = ["listen", "import_ldif"])]
    pub config_commit: bool,

    /// Go back to a generation by number, as a new commit
    #[arg(long = "config-rollback", value_name = "NUMBER", conflicts_with_all = ["listen", "import_ldif"])]
    pub config_rollback: Option<u64>,

    /// List the generations with their author and note, then exit
    #[arg(long = "config-history", conflicts_with_all = ["listen", "import_ldif"])]
    pub config_history: bool,

    /// Keep this many generations when collecting; the default is ten
    #[arg(long = "config-keep", value_name = "N", requires = "config_commit")]
    pub config_keep: Option<usize>,

    /// Why this generation was committed, for the history
    #[arg(long = "note", value_name = "TEXT", requires = "config_commit")]
    pub note: Option<String>,

    /// Read the configuration from this file instead of the one in force
    ///
    /// What seeds an empty store: `-c config.d --config-commit --from config.yaml` writes the
    /// first generation. Without it a commit re-commits what is already in force, which is how
    /// an operator marks a point before editing by hand.
    #[arg(long = "from", value_name = "PATH", requires = "config_commit")]
    pub from: Option<PathBuf>,

    /// Verify the search indexes against the data and exit
    ///
    /// Compares what each index answers with what a scan finds. A false negative - an entry
    /// the index would leave out - is the failure this exists to catch: the search comes
    /// back short and nothing about a short answer says it was wrong. The exit code is 1
    /// when the index would lose an entry.
    #[arg(long = "check-index", conflicts_with_all = ["listen", "import_ldif"])]
    pub check_index: bool,

    /// Rebuild the indexes and report what it cost, then exit
    ///
    /// Entries, attributes, bytes and milliseconds. The measurement is the point: it is what
    /// decides whether an attribute deserves a trigram index at the size this directory
    /// actually is.
    #[arg(long = "reindex", conflicts_with_all = ["listen", "import_ldif"])]
    pub reindex: bool,

    /// Rewrite the store, returning the space that deleted entries left behind, then exit
    ///
    /// Redb is copy-on-write: a commit writes new pages and frees the old ones, and the freed
    /// space is reused but never given back to the filesystem. A store that held an import and
    /// then lost most of it keeps its size, and this is what shrinks it. Needs room on disk for
    /// a second copy while it runs, and refuses to start while anything else has the file open.
    #[arg(long = "compact", conflicts_with_all = ["listen", "import_ldif"])]
    pub compact: bool,

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
            check_index: cli.check_index,
            compact: cli.compact,
            config_commit: cli.config_commit,
            config_rollback: cli.config_rollback,
            config_history: cli.config_history,
            config_keep: cli.config_keep,
            note: cli.note,
            from: cli.from,
            reindex: cli.reindex,
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
