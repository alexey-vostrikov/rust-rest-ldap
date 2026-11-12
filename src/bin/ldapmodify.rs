//! `ldapmodify` and `ldapadd`: LDIF applied over the protocol.
//!
//! One program for both, as OpenLDAP has it: `ldapadd` is this with `-a`, which turns every
//! content record into an add. The difference is worth keeping in one place because the
//! reading, the error handling and the exit code are identical.
//!
//! Two rules shape the failure handling:
//!
//! - **`-c` continues and reports every failure, `-c` absent stops at the first.** A file of
//!   two thousand entries imported over a slow link should not be re-run from the start
//!   because entry 812 was already there; and a file whose fourth entry is malformed should
//!   not quietly apply 1996 more after it.
//! - **Every failure names the line of the source file.** `alreadyExists` on its own sends
//!   the operator looking through a file by hand; `line 42` sends them to the line.

use std::io::Read;
use std::process::ExitCode;

use clap::Parser;
use rasn::types::SetOf;
use rasn_ldap::{
    ChangeOperation, LdapDn, LdapMessage, ModifyRequest, ModifyRequestChanges, PartialAttribute,
    ProtocolOp, ResultCode,
};
use rrl_directory::cli_connection::Connection;
use rrl_directory::client::{Client, Options};
use rrl_directory::ldif_read::{self, Change, ChangeRecord, ModOp, Record};
use rrl_directory::model::Entry;

#[derive(Debug, Parser)]
#[command(
    name = "ldapmodify",
    version,
    about = "Apply an LDIF file to a directory over the protocol",
    disable_help_flag = true
)]
struct Cli {
    /// LDAP URL: ldap://host[:port] or ldaps://host[:port]
    #[arg(short = 'H', long = "url", value_name = "URL")]
    url: Option<String>,

    #[arg(short = 'h', long = "host", value_name = "HOST")]
    host: Option<String>,

    #[arg(short = 'p', long = "port", value_name = "PORT")]
    port: Option<u16>,

    /// Bind DN
    #[arg(short = 'D', long = "binddn", value_name = "DN", default_value = "")]
    bind_dn: String,

    /// Password, on the command line
    #[arg(short = 'w', long = "bindpw", value_name = "PASSWORD")]
    password: Option<String>,

    /// Read the password from the terminal
    #[arg(short = 'W', long = "ask-password", conflicts_with = "password")]
    ask_password: bool,

    /// Use simple authentication
    #[arg(short = 'x', long = "simple-auth")]
    simple: bool,

    /// Read the changes from this file instead of standard input
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    file: Option<std::path::PathBuf>,

    /// Continue after an error, reporting every failure
    #[arg(short = 'c', long = "continue")]
    keep_going: bool,

    /// Treat every record as an addition, which is what ldapadd does
    #[arg(short = 'a', long = "add")]
    add: bool,

    /// StartTLS: -Z asks and continues on failure, -ZZ requires it
    #[arg(short = 'Z', action = clap::ArgAction::Count)]
    starttls: u8,

    /// Accept any server certificate
    #[arg(long = "insecure")]
    insecure: bool,

    /// CA certificate to verify the server against, in PEM
    #[arg(long = "cacert", value_name = "PATH")]
    ca_cert: Option<std::path::PathBuf>,

    /// Seconds to wait for one response
    #[arg(long = "timeout", value_name = "SECONDS", default_value_t = 30)]
    timeout: u64,

    /// Print this help
    #[arg(short = '?', long = "help", action = clap::ArgAction::Help)]
    help: Option<bool>,
}

impl Cli {
    /// This tool's flags as the shared connection settings.
    fn connection(&self) -> Connection {
        Connection {
            url: self.url.clone(),
            host: self.host.clone(),
            port: self.port,
            bind_dn: self.bind_dn.clone(),
            password: self.password.clone(),
            ask_password: self.ask_password,
            starttls: self.starttls,
            insecure: self.insecure,
            ca_cert: self.ca_cert.clone(),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // `ldapadd` is this program under another name, as it is in OpenLDAP: the reader, the
    // error handling and the exit code are identical, and the only difference is that a
    // change record is refused instead of applied. A symlink carries that difference.
    let cli = if invoked_as_add() {
        Cli { add: true, ..cli }
    } else {
        cli
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("ldapmodify: cannot start: {err}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(run(&cli))
}

async fn run(cli: &Cli) -> ExitCode {
    let text = match read_input(cli) {
        Ok(text) => text,
        Err(message) => {
            eprintln!("{}: {message}", program_name());
            return ExitCode::FAILURE;
        }
    };

    // Parsing the whole file before sending anything: a file that cannot be read is not a
    // file to apply halfway. A malformed record at line 900 means nothing was sent, which is
    // the one behaviour an operator can reason about.
    let records = match ldif_read::parse(&text) {
        Ok(records) => records,
        Err(err) => {
            eprintln!("{}: {err}", program_name());
            return ExitCode::FAILURE;
        }
    };

    if records.is_empty() {
        eprintln!("{}: the file holds no records", program_name());
        return ExitCode::from(0);
    }

    let connection = cli.connection();
    let options = Options {
        timeout: std::time::Duration::from_secs(cli.timeout),
        trust: connection.trust(),
        ..Options::default()
    };

    let client = match Client::connect(&connection.url(), options).await {
        Ok(client) => client,
        Err(err) => {
            eprintln!("{}: {err}", program_name());
            return ExitCode::FAILURE;
        }
    };

    if let Err(err) = connection.authenticate(&client).await {
        eprintln!("{}: {err}", program_name());
        return ExitCode::FAILURE;
    }

    let mut failed = 0usize;
    let mut first_code = ResultCode::Success;

    for record in &records {
        match apply(cli, &client, record).await {
            Ok(()) => {}
            Err(outcome) => {
                failed += 1;
                if first_code == ResultCode::Success {
                    first_code = outcome.code;
                }

                eprintln!("{}: {}", program_name(), outcome.message);

                if !cli.keep_going {
                    eprintln!(
                        "{}: stopping at the first failure; {failed} of {} records rejected, \
                         -c continues past it",
                        program_name(),
                        records.len()
                    );
                    return ExitCode::from(outcome.code as u8);
                }
            }
        }
    }

    if failed > 0 {
        eprintln!(
            "{}: {failed} of {} records rejected",
            program_name(),
            records.len()
        );
        return ExitCode::from(first_code as u8);
    }

    ExitCode::SUCCESS
}

/// What went wrong with one record.
struct Rejected {
    code: ResultCode,
    message: String,
}

/// Applies one record.
async fn apply(cli: &Cli, client: &Client, record: &Record) -> Result<(), Rejected> {
    match record {
        // A content record is an add in both programs: `ldapmodify` applies `dn` plus
        // attributes as an addition, which is what `ldapadd` does to every record. The
        // difference between the two is what `-a` forbids, below.
        Record::Entry(content) => add(client, &content.entry).await,
        Record::Change(change) => {
            if cli.add {
                return Err(Rejected {
                    code: ResultCode::ProtocolError,
                    message: format!(
                        "'{}' is a change record, and -a only applies entries; drop -a to run it",
                        change.dn
                    ),
                });
            }
            apply_change(client, change).await
        }
    }
}

/// `changetype: add | modify | delete | modrdn`.
async fn apply_change(client: &Client, change: &ChangeRecord) -> Result<(), Rejected> {
    match change.change {
        // The reader folds `changetype: add` into a content record, because RFC 2849 makes it
        // carry its attributes exactly as one does. Reaching this arm means the record came
        // from somewhere other than that reader, and adding an entry with no attributes is
        // never what was meant.
        Change::Add => Err(Rejected {
            code: ResultCode::ProtocolError,
            message: format!(
                "'{}' is an addition without attributes; write it as a plain record with \
                 'dn:' and the attributes",
                change.dn
            ),
        }),
        Change::Modify => {
            let mut changes = Vec::with_capacity(change.modifications.len());

            for modification in &change.modifications {
                let operation = match modification.op {
                    ModOp::Add => ChangeOperation::Add,
                    ModOp::Delete => ChangeOperation::Delete,
                    ModOp::Replace => ChangeOperation::Replace,
                };

                let values = SetOf::from_vec(
                    modification
                        .values
                        .iter()
                        .map(|value| rasn_ldap::AttributeValue::from(value.as_bytes()))
                        .collect(),
                );

                changes.push(ModifyRequestChanges {
                    operation,
                    modification: PartialAttribute::new(
                        rasn_ldap::AttributeDescription::from(modification.attribute.as_str()),
                        values,
                    ),
                });
            }

            let request = ModifyRequest {
                object: LdapDn::from(change.dn.as_str()),
                changes,
            };
            let response = client
                .request(ProtocolOp::ModifyRequest(request), "modify response")
                .await
                .map_err(rejected)?;

            check(&response, &change.dn).await
        }
        Change::Delete => {
            let response = client
                .request(
                    ProtocolOp::DelRequest(rasn_ldap::DelRequest(LdapDn::from(change.dn.as_str()))),
                    "delete response",
                )
                .await
                .map_err(rejected)?;

            check(&response, &change.dn).await
        }
        Change::ModDn => {
            let new_rdn = change.new_rdn.clone().unwrap_or_default();

            let request = rasn_ldap::ModifyDnRequest {
                entry: LdapDn::from(change.dn.as_str()),
                new_rdn: rasn_ldap::RelativeLdapDn::from(new_rdn.as_str()),
                delete_old_rdn: change.delete_old_rdn.unwrap_or(true),
                new_superior: change.new_superior.as_deref().map(LdapDn::from),
            };

            let response = client
                .request(ProtocolOp::ModDnRequest(request), "modify dn response")
                .await
                .map_err(rejected)?;

            check(&response, &change.dn).await
        }
    }
}

/// Adds one entry.
async fn add(client: &Client, entry: &Entry) -> Result<(), Rejected> {
    // An add request carries `Attribute`, a modify carries `PartialAttribute`: two names for
    // one shape, which is why the conversion is written out rather than shared.
    let attributes: Vec<rasn_ldap::Attribute> = entry
        .attributes()
        .values()
        .iter()
        .filter(|attribute| !attribute.values.is_empty())
        .map(|attribute| {
            rasn_ldap::Attribute::new(
                rasn_ldap::AttributeDescription::from(attribute.name.as_ref()),
                SetOf::from_vec(
                    attribute
                        .values
                        .iter()
                        .map(|value| rasn_ldap::AttributeValue::from(value.as_bytes()))
                        .collect(),
                ),
            )
        })
        .collect();

    let request = rasn_ldap::AddRequest {
        entry: LdapDn::from(entry.dn()),
        attributes,
    };

    let response = client
        .request(ProtocolOp::AddRequest(request), "add response")
        .await
        .map_err(rejected)?;

    check(&response, entry.dn()).await
}

/// Turns a client failure into a rejection that names the DN.
fn rejected(err: rrl_directory::client::Error) -> Rejected {
    match err {
        rrl_directory::client::Error::Server { code, message } => Rejected {
            code,
            message: format!("{code:?}: {message}"),
        },
        other => Rejected {
            code: ResultCode::Other,
            message: other.to_string(),
        },
    }
}

/// Checks the server's answer to one operation.
async fn check(response: &[LdapMessage], dn: &str) -> Result<(), Rejected> {
    let Some(last) = response.last() else {
        return Err(Rejected {
            code: ResultCode::Other,
            message: format!("{dn}: the server sent no response"),
        });
    };

    let code = match &last.protocol_op {
        ProtocolOp::AddResponse(response) => response.0.result_code,
        ProtocolOp::ModifyResponse(response) => response.0.result_code,
        ProtocolOp::DelResponse(response) => response.0.result_code,
        ProtocolOp::ModDnResponse(response) => response.0.result_code,
        _ => ResultCode::Other,
    };

    if code == ResultCode::Success {
        return Ok(());
    }

    Err(Rejected {
        code,
        message: format!("{dn}: {code:?}"),
    })
}

/// Whether the program was started under the name `ldapadd`.
/// The name this program was started under, for its own messages.
///
/// `ldapadd` is the same program: a message that says "ldapmodify" while the operator typed
/// `ldapadd` sends them looking for a second binary that does not exist.
fn program_name() -> &'static str {
    static NAME: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

    NAME.get_or_init(|| {
        let path = std::env::args().next().unwrap_or_default();
        let stem = std::path::Path::new(&path)
            .file_stem()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();

        if stem.eq_ignore_ascii_case("ldapadd") {
            "ldapadd"
        } else {
            "ldapmodify"
        }
    })
}

fn invoked_as_add() -> bool {
    std::env::args()
        .next()
        .map(|path| {
            std::path::Path::new(&path)
                .file_stem()
                .map(|name| name.eq_ignore_ascii_case("ldapadd"))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn read_input(cli: &Cli) -> Result<String, String> {
    match &cli.file {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|err| format!("cannot read '{}': {err}", path.display())),
        None => {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .map_err(|err| format!("cannot read standard input: {err}"))?;
            Ok(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use rrl_directory::client::Trust;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("ldapmodify").chain(args.iter().copied()))
    }

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_defaults_read_standard_input_and_stop_at_the_first_failure() {
        let cli = parse(&["-H", "ldap://host"]);
        assert!(cli.file.is_none());
        assert!(!cli.keep_going);
        assert!(!cli.add);
        assert_eq!(cli.bind_dn, "");
    }

    #[test]
    fn the_connection_settings_come_from_the_flags() {
        // The building of a URL and the choice of trust are tested once, in `cli_connection`;
        // what is this tool's own business is that its flags reach them.
        let cli = parse(&["-h", "ldap.example.com", "-p", "1389", "--insecure", "-ZZ"]);
        let connection = cli.connection();

        assert_eq!(connection.url(), "ldap://ldap.example.com:1389");
        assert_eq!(connection.trust(), Trust::Insecure);
        assert_eq!(connection.starttls, 2);
    }

    #[test]
    fn the_program_name_is_read_without_its_extension() {
        // The check is on the file stem, so a package that installs `ldapadd` and a Windows
        // build that produces `ldapadd.exe` both work; anything else keeps modify semantics.
        let stem = |path: &str| {
            std::path::Path::new(path)
                .file_stem()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default()
        };

        assert_eq!(stem("/usr/local/bin/ldapadd"), "ldapadd");
        assert_eq!(stem("/usr/local/bin/ldapmodify"), "ldapmodify");
        assert_eq!(stem("C:/bin/ldapadd.exe"), "ldapadd");
    }
}
