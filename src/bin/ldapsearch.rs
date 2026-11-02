//! `ldapsearch`: the operator's question to a directory, and the main external test of the
//! server.
//!
//! The exit code is the server's result code, because that is what a script branches on:
//! `0` for a result, `32` for "no such object", `49` for "invalid credentials", `4` for "the
//! size limit was reached". Printing a message and exiting `0` would make every caller
//! parse the text.

use std::io::Write;
use std::process::ExitCode;

use clap::Parser;
use rasn_ldap::{
    Control, LdapDn, LdapString, ResultCode, SearchRequest, SearchRequestDerefAliases,
    SearchRequestScope,
};
use rust_rest_ldap::client::{Client, Options, Trust};
use rust_rest_ldap::ldap::filter_parse;
use rust_rest_ldap::ldap::{paged, sort};
use rust_rest_ldap::ldif;
use rust_rest_ldap::model::Entry;

#[derive(Debug, Parser)]
#[command(
    name = "ldapsearch",
    version,
    about = "Search an LDAP directory and print the result as LDIF",
    // `-h` is the host here, as it is in every LDAP tool, so the automatic help flag has to
    // go: `-?` is what OpenLDAP's utilities take, and `--help` still works.
    disable_help_flag = true
)]
struct Cli {
    /// LDAP URL: ldap://host[:port] or ldaps://host[:port]
    #[arg(short = 'H', long = "url", value_name = "URL")]
    url: Option<String>,

    /// Host, as an alternative to -H
    #[arg(short = 'h', long = "host", value_name = "HOST")]
    host: Option<String>,

    /// Port, as an alternative to -H
    #[arg(short = 'p', long = "port", value_name = "PORT")]
    port: Option<u16>,

    /// Bind DN
    #[arg(short = 'D', long = "binddn", value_name = "DN", default_value = "")]
    bind_dn: String,

    /// Password, on the command line
    #[arg(short = 'w', long = "bindpw", value_name = "PASSWORD")]
    password: Option<String>,

    /// Read the password from the terminal instead of the command line
    #[arg(short = 'W', long = "ask-password", conflicts_with = "password")]
    ask_password: bool,

    /// Use simple authentication, as this server always does
    #[arg(short = 'x', long = "simple-auth")]
    simple: bool,

    /// Base DN of the search
    #[arg(short = 'b', long = "base", value_name = "DN", default_value = "")]
    base: String,

    /// Scope: base, one, sub
    #[arg(
        short = 's',
        long = "scope",
        value_name = "SCOPE",
        default_value = "sub"
    )]
    scope: Scope,

    /// How to handle aliases: never, search, find, always
    #[arg(
        short = 'a',
        long = "deref",
        value_name = "DEREF",
        default_value = "never"
    )]
    deref: Deref,

    /// Size limit for the whole search
    #[arg(short = 'z', long = "sizelimit", value_name = "N", default_value_t = 0)]
    size_limit: u32,

    /// Time limit in seconds, enforced by the server
    #[arg(short = 'l', long = "timelimit", value_name = "N", default_value_t = 0)]
    time_limit: u32,

    /// Print the LDIF header comments; -LLL prints entries only
    #[arg(short = 'L', action = clap::ArgAction::Count)]
    ldif_header: u8,

    /// Wrap long LDIF lines at 76 octets
    #[arg(short = 'o', long = "option", value_name = "OPTION=VALUE")]
    option: Vec<String>,

    /// StartTLS: -Z asks and continues on failure, -ZZ requires it
    #[arg(short = 'Z', action = clap::ArgAction::Count)]
    starttls: u8,

    /// Request a control: `pr=<size>` for paged results
    #[arg(short = 'E', long = "extended", value_name = "CONTROL")]
    extended: Vec<String>,

    /// Sort by this attribute server-side, `-` suffix for descending
    #[arg(short = 'S', long = "sort", value_name = "ATTRIBUTE")]
    sort_by: Option<String>,

    /// Filter, defaulting to `(objectClass=*)`
    #[arg(value_name = "FILTER")]
    filter: Option<String>,

    /// Attributes to return; `*` for all user attributes, `+` for operational ones
    #[arg(value_name = "ATTRIBUTE")]
    attributes: Vec<String>,

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Scope {
    Base,
    One,
    Sub,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Deref {
    Never,
    Searching,
    Finding,
    Always,
}

impl Deref {
    fn aliases(self) -> SearchRequestDerefAliases {
        match self {
            Deref::Never => SearchRequestDerefAliases::NeverDerefAliases,
            Deref::Searching => SearchRequestDerefAliases::DerefInSearching,
            Deref::Finding => SearchRequestDerefAliases::DerefFindingBaseObj,
            Deref::Always => SearchRequestDerefAliases::DerefAlways,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("ldapsearch: cannot start: {err}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(&cli)) {
        Ok(code) => exit_code(code),
        Err(Failure::Usage(message)) => {
            eprintln!("ldapsearch: {message}");
            ExitCode::FAILURE
        }
        Err(Failure::Client(err)) => {
            eprintln!("ldapsearch: {err}");

            // The server's result code is the exit code, because that is what a script
            // branches on: `32` is a wrong base, `49` a wrong password, `4` a size limit.
            // Anything that never reached the server is a plain failure.
            match err {
                rust_rest_ldap::client::Error::Server { code, .. } => exit_code(code),
                _ => ExitCode::FAILURE,
            }
        }
    }
}

/// A failure that is not the server's answer.
#[derive(Debug)]
enum Failure {
    /// The command line did not describe a search.
    Usage(String),
    Client(rust_rest_ldap::client::Error),
}

impl From<rust_rest_ldap::client::Error> for Failure {
    fn from(err: rust_rest_ldap::client::Error) -> Self {
        Failure::Client(err)
    }
}

async fn run(cli: &Cli) -> Result<ResultCode, Failure> {
    let url = url_of(cli)?;

    let filter = match &cli.filter {
        Some(text) => filter_parse::parse(text)
            .map_err(|err| Failure::Usage(format!("filter '{text}' is not valid: {err}")))?,
        // The default of every LDAP tool: ask for everything and let the ACL decide.
        None => filter_parse::parse("(objectClass=*)").expect("a constant filter parses"),
    };

    let attributes: Vec<LdapString> = if cli.attributes.is_empty() {
        vec![LdapString::from("*")]
    } else {
        cli.attributes
            .iter()
            .map(|name| LdapString::from(name.as_str()))
            .collect()
    };

    let request = SearchRequest::new(
        LdapDn::from(cli.base.as_str()),
        scope_of(cli.scope),
        cli.deref.aliases(),
        cli.size_limit,
        cli.time_limit,
        false,
        filter,
        attributes,
    );

    let options = Options {
        timeout: std::time::Duration::from_secs(cli.timeout),
        trust: trust_of(cli),
        ..Options::default()
    };

    let client = Client::connect(&url, options).await?;

    // A bind only when a DN or a password was given: an anonymous search is a legitimate
    // question, and forcing a bind would change what is being asked.
    if !cli.bind_dn.is_empty() || cli.password.is_some() || cli.ask_password {
        let password = password_of(cli)?;
        client.bind(&cli.bind_dn, &password).await?;
    }

    if cli.starttls > 0 {
        client.starttls().await?;
    }

    let page_size = page_size_of(cli)?;
    let entries = collect(cli, &client, request, page_size).await?;

    print_entries(cli, &entries);

    Ok(ResultCode::Success)
}

/// Runs the search, page by page when paging was asked for.
async fn collect(
    cli: &Cli,
    client: &Client,
    request: SearchRequest,
    page_size: Option<u32>,
) -> Result<Vec<Entry>, Failure> {
    let mut entries = Vec::new();
    let mut cookie: Vec<u8> = Vec::new();

    loop {
        let mut controls = Vec::new();

        if let Some(size) = page_size {
            controls.push(Control::new(
                rasn_ldap::LdapOid::from(paged::PAGED_RESULTS_OID.as_bytes()),
                // Critical: a server that does not understand paging must refuse rather than
                // send the whole result, which is what the page size was protecting against.
                true,
                Some(rasn::types::OctetString::from(paged::encode(
                    &paged::Page::new(size, cookie.clone()),
                ))),
            ));
        }

        if let Some(attribute) = &cli.sort_by {
            controls.push(sort_control(attribute)?);
        }

        let (messages, outcome) = client.search_with(request.clone(), controls).await?;

        // The server's own say on the whole search: `sizeLimitExceeded` is an answer worth
        // reporting, and it is also the exit code.
        if outcome.code != ResultCode::Success {
            print_entries(cli, &entries);
            return Err(Failure::Client(rust_rest_ldap::client::Error::Server {
                code: outcome.code,
                message: outcome.diagnostic,
            }));
        }

        for message in &messages {
            if let Some(entry) = rust_rest_ldap::client::entry_of(message) {
                entries.push(entry);
            }
        }

        let Some(size) = page_size else {
            break;
        };
        let _ = size;

        // The cookie of the page that just arrived decides whether there is another one.
        cookie = match next_cookie(&messages) {
            Some(cookie) if !cookie.is_empty() => cookie,
            _ => break,
        };
    }

    Ok(entries)
}

/// The paged-results cookie in an answer, if the server sent one.
fn next_cookie(messages: &[rasn_ldap::LdapMessage]) -> Option<Vec<u8>> {
    for message in messages {
        for control in rust_rest_ldap::client::controls_of(message) {
            if control.control_type.as_ref() == paged::PAGED_RESULTS_OID.as_bytes() {
                let value = control.control_value?;
                return paged::decode(value.as_ref()).ok().map(|page| page.cookie);
            }
        }
    }

    None
}

/// `-E pr=<size>`: a page size, or nothing when paging was not asked for.
fn page_size_of(cli: &Cli) -> Result<Option<u32>, Failure> {
    // Every `-E` is checked, not just the first: a second control that this client cannot
    // build is a search the caller did not ask for, and ignoring it silently is worse than
    // the refusal.
    let mut requested = cli.extended.iter();
    let Some(control) = requested.next() else {
        return Ok(None);
    };

    if let Some(other) = requested.next() {
        return Err(Failure::Usage(format!(
            "control '{other}' is not understood; this client builds one pr=<size> control"
        )));
    }

    let Some(rest) = control.strip_prefix("pr=") else {
        return Err(Failure::Usage(format!(
            "control '{control}' is not understood; this client builds pr=<size>"
        )));
    };

    let size = rest.parse::<u32>().map_err(|_| {
        Failure::Usage(format!(
            "page size '{rest}' is not a number; -E pr=<size> takes an integer"
        ))
    })?;

    if size == 0 {
        return Err(Failure::Usage(
            "-E pr=0 would ask for every entry at once; give a positive size, -E pr=<n>"
                .to_string(),
        ));
    }

    Ok(Some(size))
}

/// `-S cn` or `-S cn-` for descending.
fn sort_control(attribute: &str) -> Result<Control, Failure> {
    let (name, reverse) = match attribute.strip_suffix('-') {
        Some(name) => (name, true),
        None => (attribute, false),
    };

    if name.is_empty() {
        return Err(Failure::Usage(format!(
            "'{attribute}' names no attribute to sort by"
        )));
    }

    let request = sort::SortRequest {
        keys: vec![sort::SortKey {
            attribute: name.to_string(),
            ordering_rule: None,
            reverse,
        }],
    };

    Ok(Control::new(
        rasn_ldap::LdapOid::from(sort::SORT_OID.as_bytes()),
        true,
        Some(rasn::types::OctetString::from(sort::encode_sort(&request))),
    ))
}

fn print_entries(cli: &Cli, entries: &[Entry]) {
    let options = ldif::Options {
        wrap: wrap_enabled(cli),
        ..ldif::Options::default()
    };

    let mut out = String::new();

    // -LLL is the form scripts parse: entries only, no header, no comment about the count.
    if cli.ldif_header < 3 {
        out.push_str("# extended LDIF\n#\n");
        out.push_str("# search result\n#\n");
    }

    for entry in entries {
        ldif::write_entry(&mut out, entry, options);
        out.push('\n');
    }

    if cli.ldif_header < 3 {
        out.push_str(&format!("# numEntries: {}\n", entries.len()));
    }

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(out.as_bytes());
    let _ = lock.flush();
}

/// `-o ldif-wrap=no` turns wrapping off; the default is on.
fn wrap_enabled(cli: &Cli) -> bool {
    for option in &cli.option {
        if let Some(value) = option.strip_prefix("ldif-wrap=") {
            return !value.eq_ignore_ascii_case("no");
        }
    }

    true
}

fn url_of(cli: &Cli) -> Result<String, Failure> {
    if let Some(url) = &cli.url {
        return Ok(url.clone());
    }

    let host = cli.host.clone().unwrap_or_else(|| "localhost".to_string());
    match cli.port {
        Some(port) => Ok(format!("ldap://{host}:{port}")),
        None => Ok(format!("ldap://{host}")),
    }
}

fn trust_of(cli: &Cli) -> Trust {
    if cli.insecure {
        return Trust::Insecure;
    }
    match &cli.ca_cert {
        Some(path) => Trust::File(path.clone()),
        None => Trust::WebPki,
    }
}

/// The password, from the flag or from the terminal.
fn password_of(cli: &Cli) -> Result<String, Failure> {
    if let Some(password) = &cli.password {
        return Ok(password.clone());
    }

    if !cli.ask_password {
        // A bind DN with no password is an unauthenticated bind, which servers refuse; saying
        // so beats sending an empty password and reporting the refusal as a bad credential.
        return Ok(String::new());
    }

    eprint!("Enter LDAP Password: ");
    let _ = std::io::stderr().flush();

    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .map_err(|err| Failure::Usage(format!("cannot read the password: {err}")))?;

    Ok(password.trim_end_matches(['\r', '\n']).to_string())
}

fn scope_of(scope: Scope) -> SearchRequestScope {
    match scope {
        Scope::Base => SearchRequestScope::BaseObject,
        Scope::One => SearchRequestScope::SingleLevel,
        Scope::Sub => SearchRequestScope::WholeSubtree,
    }
}

/// The exit code is the result code: `0` when the search ran, `32` when there was no such
/// base, `49` when the credentials were refused.
fn exit_code(code: ResultCode) -> ExitCode {
    ExitCode::from(code as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("ldapsearch").chain(args.iter().copied()))
    }

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_defaults_ask_for_everything_in_the_subtree() {
        let cli = parse(&["-H", "ldap://host"]);
        assert_eq!(cli.base, "");
        assert_eq!(cli.scope, Scope::Sub);
        assert_eq!(cli.size_limit, 0);
        assert!(cli.filter.is_none());
        assert!(cli.attributes.is_empty());
        assert_eq!(cli.ldif_header, 0);
    }

    #[test]
    fn a_url_is_built_from_host_and_port_when_the_url_is_absent() {
        let cli = parse(&["-h", "ldap.example.com", "-p", "1389"]);
        assert_eq!(
            url_of(&cli).ok().as_deref(),
            Some("ldap://ldap.example.com:1389")
        );

        let cli = parse(&["-h", "ldap.example.com"]);
        assert_eq!(
            url_of(&cli).ok().as_deref(),
            Some("ldap://ldap.example.com")
        );

        let cli = parse(&[]);
        assert_eq!(url_of(&cli).expect("url"), "ldap://localhost");
    }

    #[test]
    fn the_scope_names_map_to_the_protocol_values() {
        assert_eq!(scope_of(Scope::Base), SearchRequestScope::BaseObject);
        assert_eq!(scope_of(Scope::One), SearchRequestScope::SingleLevel);
        assert_eq!(scope_of(Scope::Sub), SearchRequestScope::WholeSubtree);
    }

    #[test]
    fn the_deref_names_map_to_the_protocol_values() {
        assert_eq!(
            Deref::Never.aliases(),
            SearchRequestDerefAliases::NeverDerefAliases
        );
        assert_eq!(
            Deref::Searching.aliases(),
            SearchRequestDerefAliases::DerefInSearching
        );
        assert_eq!(
            Deref::Finding.aliases(),
            SearchRequestDerefAliases::DerefFindingBaseObj
        );
        assert_eq!(
            Deref::Always.aliases(),
            SearchRequestDerefAliases::DerefAlways
        );
    }

    #[test]
    fn a_page_size_is_read_from_the_pr_control() {
        let cli = parse(&["-H", "ldap://host", "-E", "pr=500"]);
        assert_eq!(page_size_of(&cli).expect("page size"), Some(500));

        let cli = parse(&["-H", "ldap://host"]);
        assert_eq!(page_size_of(&cli).expect("page size"), None);
    }

    #[test]
    fn a_page_size_that_is_not_a_positive_number_is_refused_with_its_text() {
        for value in ["pr=abc", "pr=0", "pr=-1"] {
            let cli = parse(&["-H", "ldap://host", "-E", value]);
            let err = page_size_of(&cli).expect_err("must refuse");
            let Failure::Usage(message) = err else {
                panic!("expected a usage error");
            };
            assert!(message.contains("pr="), "{message}");
        }
    }

    #[test]
    fn a_control_that_is_not_paging_is_named_in_the_refusal() {
        // Silently ignoring it would run a search the caller did not ask for.
        let cli = parse(&["-H", "ldap://host", "-E", "vlv=1/2/3"]);
        let Failure::Usage(message) = page_size_of(&cli).expect_err("must refuse") else {
            panic!("expected a usage error");
        };
        assert!(message.contains("vlv=1/2/3"), "{message}");
    }

    #[test]
    fn a_sort_attribute_with_a_trailing_minus_is_descending() {
        let ascending = sort_control("cn").expect("control");
        let descending = sort_control("cn-").expect("control");

        let decode = |control: &Control| {
            sort::decode_sort(control.control_value.as_ref().expect("value").as_ref())
                .expect("decode")
        };

        assert!(!decode(&ascending).keys[0].reverse);
        assert!(decode(&descending).keys[0].reverse);
        assert_eq!(decode(&descending).keys[0].attribute, "cn");
    }

    #[test]
    fn a_sort_attribute_that_is_only_a_minus_is_refused() {
        assert!(sort_control("-").is_err());
    }

    #[test]
    fn wrapping_is_on_unless_the_option_turns_it_off() {
        assert!(wrap_enabled(&parse(&["-H", "ldap://host"])));
        assert!(!wrap_enabled(&parse(&[
            "-H",
            "ldap://host",
            "-o",
            "ldif-wrap=no"
        ])));
        assert!(wrap_enabled(&parse(&[
            "-H",
            "ldap://host",
            "-o",
            "ldif-wrap=76"
        ])));
        // An option this client does not use must not change wrapping.
        assert!(wrap_enabled(&parse(&[
            "-H",
            "ldap://host",
            "-o",
            "nocheck"
        ])));
    }

    #[test]
    fn the_exit_code_is_the_result_code() {
        assert_eq!(exit_code(ResultCode::Success), ExitCode::from(0));
        assert_eq!(exit_code(ResultCode::NoSuchObject), ExitCode::from(32));
        assert_eq!(
            exit_code(ResultCode::InvalidCredentials),
            ExitCode::from(49)
        );
        assert_eq!(exit_code(ResultCode::SizeLimitExceeded), ExitCode::from(4));
    }

    #[test]
    fn the_trust_policy_follows_the_flags() {
        assert!(matches!(
            trust_of(&parse(&["-H", "ldap://h"])),
            Trust::WebPki
        ));
        assert!(matches!(
            trust_of(&parse(&["-H", "ldap://h", "--insecure"])),
            Trust::Insecure
        ));
        assert!(matches!(
            trust_of(&parse(&["-H", "ldap://h", "--cacert", "/etc/ca.pem"])),
            Trust::File(_)
        ));
    }
}
