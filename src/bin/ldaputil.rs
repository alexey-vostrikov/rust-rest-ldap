//! The small utilities: `ldapdelete`, `ldapmodrdn`, `ldapcompare`, `ldapwhoami`, `ldappasswd`.
//!
//! One program under five names, as OpenLDAP ships them. What they share is everything that
//! is easy to get wrong - connecting, binding, StartTLS, the exit code - and what they differ
//! in is one operation each, so the operation is the only thing that varies here.
//!
//! The rules these follow, and why:
//!
//! - **The exit code is the LDAP result code.** A script that deletes a subtree branches on
//!   `66` (not allowed on non-leaf) and `32` (no such object), and neither is "1".
//! - **`ldapcompare` answers TRUE, FALSE and "no such attribute" separately.** RFC 4511 gives
//!   comparison its own two success codes, and collapsing them into one exit code loses the
//!   answer the tool exists to give.
//! - **`ldapdelete -r` deletes children before parents.** Doing it in the other order is
//!   refused by the server for every entry that has a child, which is all of them except the
//!   leaves.

use std::process::ExitCode;

use clap::Parser;
use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, AttributeValueAssertion, CompareRequest, ExtendedRequest, LdapDn,
    LdapMessage, LdapOid, ProtocolOp, RelativeLdapDn, ResultCode, SearchRequest,
    SearchRequestDerefAliases, SearchRequestScope,
};
use rust_rest_ldap::cli_connection::Connection;
use rust_rest_ldap::client::{Client, Options};
use rust_rest_ldap::ldap::{extop, filter_parse};

#[derive(Debug, Parser)]
#[command(
    name = "ldaputil",
    version,
    about = "Delete, rename, compare, change a password or ask who you are",
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

    /// Say nothing; the exit code is the answer
    ///
    /// What a script wants: `if ldapcompare -z ...` branches on TRUE and FALSE without
    /// parsing the output, and `ldapdelete -z` keeps a loop quiet.
    #[arg(short = 'z', long = "quiet")]
    quiet: bool,

    /// Delete children before the entry itself (ldapdelete)
    #[arg(short = 'r', long = "recursive")]
    recursive: bool,

    /// Rename in place, keeping the old RDN as an attribute value (ldapmodrdn)
    #[arg(short = 'k', long = "keep-old-rdn")]
    keep_old_rdn: bool,

    /// Move the entry under this parent (ldapmodrdn)
    ///
    /// Long form only: `-s` is the new password in `ldappasswd`, and one program under five
    /// names cannot give the same letter two meanings. OpenLDAP has the same collision and
    /// resolves it the same way.
    #[arg(long = "newsuperior", value_name = "DN")]
    new_superior: Option<String>,

    /// The current password (ldappasswd)
    #[arg(short = 'a', long = "old-password", value_name = "PASSWORD")]
    old_password: Option<String>,

    /// The new password (ldappasswd); omitted asks the server to generate one
    #[arg(short = 's', long = "new-password", value_name = "PASSWORD")]
    new_password: Option<String>,

    /// Whose password to change (ldappasswd); default is your own
    #[arg(short = 'e', long = "user", value_name = "DN")]
    user: Option<String>,

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

    /// The entry, or the two arguments of a comparison
    #[arg(value_name = "ARG")]
    arguments: Vec<String>,
}

/// What the program was asked to do, decided by the name it was started under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tool {
    Delete,
    ModRdn,
    Compare,
    WhoAmI,
    Passwd,
}

impl Tool {
    /// The tool an invocation name belongs to, if any.
    fn of(name: &str) -> Option<Tool> {
        match name.to_ascii_lowercase().as_str() {
            "ldapdelete" => Some(Tool::Delete),
            "ldapmodrdn" | "ldapmoddn" => Some(Tool::ModRdn),
            "ldapcompare" => Some(Tool::Compare),
            "ldapwhoami" => Some(Tool::WhoAmI),
            "ldappasswd" => Some(Tool::Passwd),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Tool::Delete => "ldapdelete",
            Tool::ModRdn => "ldapmodrdn",
            Tool::Compare => "ldapcompare",
            Tool::WhoAmI => "ldapwhoami",
            Tool::Passwd => "ldappasswd",
        }
    }
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

    // The name decides the operation. A binary called anything else cannot say what to do,
    // and saying so is better than picking one.
    let Some(tool) = std::env::args().next().and_then(|path| {
        std::path::Path::new(&path)
            .file_stem()
            .map(|name| name.to_string_lossy().to_string())
            .and_then(|name| Tool::of(&name))
    }) else {
        eprintln!(
            "ldaputil: start this program as ldapdelete, ldapmodrdn, ldapcompare, ldapwhoami \
             or ldappasswd - the name is what says which operation to run"
        );
        return ExitCode::FAILURE;
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("{}: cannot start: {err}", tool.name());
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(run(tool, &cli))
}

async fn run(tool: Tool, cli: &Cli) -> ExitCode {
    let connection = cli.connection();
    let options = Options {
        timeout: std::time::Duration::from_secs(cli.timeout),
        trust: connection.trust(),
        ..Options::default()
    };

    let client = match Client::connect(&connection.url(), options).await {
        Ok(client) => client,
        Err(err) => return failure(tool, &err),
    };

    if let Err(err) = connection.authenticate(&client).await {
        return failure(tool, &err);
    }

    match tool {
        Tool::Delete => delete(cli, &client).await,
        Tool::ModRdn => rename(cli, &client).await,
        Tool::Compare => compare(cli, &client).await,
        Tool::WhoAmI => whoami(cli, &client).await,
        Tool::Passwd => passwd(cli, &client).await,
    }
}

// ---------------------------------------------------------------------------------------
// ldapdelete
// ---------------------------------------------------------------------------------------

async fn delete(cli: &Cli, client: &Client) -> ExitCode {
    let targets = match entries_of(cli) {
        Ok(targets) => targets,
        Err(code) => return code,
    };

    let mut first_failure = ResultCode::Success;

    for target in &targets {
        let mut doomed = vec![target.clone()];

        if cli.recursive {
            // Children first: the server refuses to delete an entry that still has one, so
            // deleting from the top down would refuse at the first parent and stop.
            match descendants(client, target).await {
                Ok(mut found) => {
                    // Deepest first: a DN's depth is its number of RDNs, and a child always
                    // has more than its parent.
                    found.sort_by_key(|dn| std::cmp::Reverse(dn.matches(',').count()));
                    doomed = found;
                    doomed.push(target.clone());
                }
                Err(code) => return code,
            }
        }

        for dn in doomed {
            match client
                .request(
                    ProtocolOp::DelRequest(rasn_ldap::DelRequest(LdapDn::from(dn.as_str()))),
                    "delete response",
                )
                .await
            {
                Ok(messages) => {
                    if let Some(code) = result_code(&messages)
                        && code != ResultCode::Success
                    {
                        if !cli.quiet {
                            eprintln!("ldapdelete: {dn}: {code:?}");
                        }
                        if first_failure == ResultCode::Success {
                            first_failure = code;
                        }
                    }
                }
                Err(err) => {
                    if !cli.quiet {
                        eprintln!("ldapdelete: {dn}: {err}");
                    }
                    if first_failure == ResultCode::Success {
                        first_failure = code_of(&err);
                    }
                }
            }
        }
    }

    if first_failure == ResultCode::Success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(first_failure as u8)
    }
}

/// Every entry below `base`, found by a subtree search for DNs.
async fn descendants(client: &Client, base: &str) -> Result<Vec<String>, ExitCode> {
    let request = SearchRequest::new(
        LdapDn::from(base),
        SearchRequestScope::WholeSubtree,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        true,
        filter_parse::parse("(objectClass=*)").expect("a constant filter parses"),
        vec![rasn_ldap::LdapString::from("1.1")],
    );

    let (messages, outcome) = match client.search(request).await {
        Ok(answer) => answer,
        Err(err) => {
            eprintln!("ldapdelete: cannot list the subtree of {base}: {err}");
            return Err(ExitCode::from(code_of(&err) as u8));
        }
    };

    if outcome.code != ResultCode::Success {
        eprintln!(
            "ldapdelete: cannot list the subtree of {base}: {:?}",
            outcome.code
        );
        return Err(ExitCode::from(outcome.code as u8));
    }

    let mut found: Vec<String> = messages
        .iter()
        .filter_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => Some(entry.object_name.to_string()),
            _ => None,
        })
        // The base itself is deleted last, by the caller: a subtree search includes it.
        .filter(|dn| rust_rest_ldap::dn::normalize(dn) != rust_rest_ldap::dn::normalize(base))
        .collect();

    found.dedup();
    Ok(found)
}

// ---------------------------------------------------------------------------------------
// ldapmodrdn
// ---------------------------------------------------------------------------------------

async fn rename(cli: &Cli, client: &Client) -> ExitCode {
    let arguments = match entries_of(cli) {
        Ok(arguments) => arguments,
        Err(code) => return code,
    };

    // Two spellings, both OpenLDAP's: `ldapmodrdn newrdn` reads the DN from stdin, and
    // `ldapmodrdn dn newrdn` takes both. The first is what a pipe of DNs uses.
    let pairs: Vec<(String, String)> = match arguments.len() {
        1 => {
            let mut dn = String::new();
            if std::io::stdin().read_line(&mut dn).is_err() {
                eprintln!("ldapmodrdn: cannot read the DN from standard input");
                return ExitCode::FAILURE;
            }
            vec![(dn.trim().to_string(), arguments[0].clone())]
        }
        2 => vec![(arguments[0].clone(), arguments[1].clone())],
        other => {
            eprintln!("ldapmodrdn: expected 'newrdn' or 'dn newrdn', got {other} arguments");
            return ExitCode::FAILURE;
        }
    };

    for (dn, new_rdn) in pairs {
        let request = rasn_ldap::ModifyDnRequest {
            entry: LdapDn::from(dn.as_str()),
            new_rdn: RelativeLdapDn::from(new_rdn.as_str()),
            delete_old_rdn: !cli.keep_old_rdn,
            new_superior: cli.new_superior.as_deref().map(LdapDn::from),
        };

        match client
            .request(ProtocolOp::ModDnRequest(request), "modify dn response")
            .await
        {
            Ok(messages) => {
                if let Some(code) = result_code(&messages)
                    && code != ResultCode::Success
                {
                    if !cli.quiet {
                        eprintln!("ldapmodrdn: {dn}: {code:?}");
                    }
                    return ExitCode::from(code as u8);
                }
            }
            Err(err) => return failure(Tool::ModRdn, &err),
        }
    }

    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------------------
// ldapcompare
// ---------------------------------------------------------------------------------------

async fn compare(cli: &Cli, client: &Client) -> ExitCode {
    // Three spellings, all OpenLDAP's: `attr:value dn`, `attr dn value`, and
    // `dn attr value`. The first is unambiguous and the other two are historical; all are
    // accepted because scripts in the wild use all three.
    let Some((attribute, value, dn)) = comparison_of(cli) else {
        eprintln!("ldapcompare: expected 'attr:value dn', 'attr dn value' or 'dn attr value'");
        return ExitCode::FAILURE;
    };

    let request = CompareRequest {
        entry: LdapDn::from(dn.as_str()),
        ava: AttributeValueAssertion::new(
            AttributeDescription::from(attribute.as_str()),
            OctetString::from(value.as_bytes()),
        ),
    };

    let messages = match client
        .request(ProtocolOp::CompareRequest(request), "compare response")
        .await
    {
        Ok(messages) => messages,
        Err(err) => return failure(Tool::Compare, &err),
    };

    let code = result_code(&messages).unwrap_or(ResultCode::Other);

    match code {
        // The answer the tool exists to give, and the reason it is two codes rather than
        // one: TRUE and FALSE are both successful comparisons.
        // The codes the protocol names them by, and the exit codes a shell wants: both are
        // answers, so neither is a failure.
        ResultCode::CompareTrue => {
            if !cli.quiet {
                println!("TRUE");
            }
            ExitCode::from(ResultCode::CompareTrue as u8)
        }
        ResultCode::CompareFalse => {
            if !cli.quiet {
                println!("FALSE");
            }
            ExitCode::from(ResultCode::CompareFalse as u8)
        }
        other => {
            if !cli.quiet {
                eprintln!("ldapcompare: {other:?}");
            }
            ExitCode::from(other as u8)
        }
    }
}

/// Reads the three parts of a comparison in any of the accepted spellings.
fn comparison_of(cli: &Cli) -> Option<(String, String, String)> {
    let arguments = &cli.arguments;

    if arguments.len() == 2 {
        // `attr:value dn`, and OpenLDAP's own `dn attr:value`: the argument carrying the
        // colon is the pair, and the other is the DN. Accepting only one order means a script
        // written for OpenLDAP fails on a usage error, which is the least useful kind of
        // difference between two tools with the same name.
        if let Some((attribute, value)) = arguments[0].split_once(':') {
            return Some((
                attribute.to_string(),
                value.to_string(),
                arguments[1].clone(),
            ));
        }

        if let Some((attribute, value)) = arguments[1].split_once(':') {
            return Some((
                attribute.to_string(),
                value.to_string(),
                arguments[0].clone(),
            ));
        }
    }

    if arguments.len() != 3 {
        return None;
    }

    // `attr dn value` or `dn attr value`: a DN contains an `=`, an attribute description
    // does not, so the argument with the `=` is the DN whichever position it is in.
    let has_equals = |text: &String| text.contains('=');

    if has_equals(&arguments[1]) && !has_equals(&arguments[0]) {
        return Some((
            arguments[0].clone(),
            arguments[2].clone(),
            arguments[1].clone(),
        ));
    }

    if has_equals(&arguments[0]) && !has_equals(&arguments[1]) {
        return Some((
            arguments[1].clone(),
            arguments[2].clone(),
            arguments[0].clone(),
        ));
    }

    None
}

// ---------------------------------------------------------------------------------------
// ldapwhoami
// ---------------------------------------------------------------------------------------

async fn whoami(cli: &Cli, client: &Client) -> ExitCode {
    let request = ExtendedRequest {
        request_name: LdapOid::from(extop::WHOAMI_OID.as_bytes()),
        request_value: None,
    };

    let messages = match client
        .request(ProtocolOp::ExtendedReq(request), "extended response")
        .await
    {
        Ok(messages) => messages,
        Err(err) => return failure(Tool::WhoAmI, &err),
    };

    let Some(code) = result_code(&messages) else {
        eprintln!("ldapwhoami: the server sent no response");
        return ExitCode::FAILURE;
    };

    if code != ResultCode::Success {
        eprintln!("ldapwhoami: {code:?}");
        return ExitCode::from(code as u8);
    }

    // RFC 4532: the value is the authzId, `dn:<dn>` or empty for anonymous. Printed as it
    // arrived rather than decoded: a client that compares the string wants the string.
    let value = messages
        .iter()
        .rev()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::ExtendedResp(response) => response.response_value.clone(),
            _ => None,
        });

    if !cli.quiet {
        match value {
            Some(value) => println!("{}", String::from_utf8_lossy(value.as_ref())),
            None => println!(),
        }
    }

    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------------------
// ldappasswd
// ---------------------------------------------------------------------------------------

async fn passwd(cli: &Cli, client: &Client) -> ExitCode {
    let mut parts: Vec<u8> = Vec::new();

    // The user is either `-e <dn>` or the positional argument, as OpenLDAP accepts both.
    // Ignoring the positional form does not fail cleanly: the request then means "my own
    // password", and the server dutifully changes the requester's - which is how a password
    // reset aimed at a user lands on the administrator instead.
    let user = cli.user.clone().or_else(|| cli.arguments.first().cloned());

    if let Some(user) = &user {
        push_part(&mut parts, 0, format!("dn:{user}").as_bytes());
    }
    if let Some(old) = &cli.old_password {
        push_part(&mut parts, 1, old.as_bytes());
    }
    if let Some(new) = &cli.new_password {
        push_part(&mut parts, 2, new.as_bytes());
    }

    let request = ExtendedRequest {
        request_name: LdapOid::from(extop::PASSWORD_MODIFY_OID.as_bytes()),
        request_value: Some(OctetString::from(sequence_of(parts))),
    };

    let messages = match client
        .request(ProtocolOp::ExtendedReq(request), "extended response")
        .await
    {
        Ok(messages) => messages,
        Err(err) => return failure(Tool::Passwd, &err),
    };

    let code = result_code(&messages).unwrap_or(ResultCode::Other);
    if code != ResultCode::Success {
        eprintln!("ldappasswd: {code:?}");
        return ExitCode::from(code as u8);
    }

    // RFC 3062: the response carries the generated password when the request asked the
    // server for one, and that is the only time it can be shown - the server does not know
    // it afterwards either.
    if cli.new_password.is_none() {
        let generated: Option<String> =
            messages
                .iter()
                .rev()
                .find_map(|message| match &message.protocol_op {
                    ProtocolOp::ExtendedResp(response) => response
                        .response_value
                        .as_ref()
                        .and_then(|value| generated_password(value.as_ref()))
                        .map(|password| String::from_utf8_lossy(password).to_string()),
                    _ => None,
                });

        match generated {
            Some(password) => println!("New password: {password}"),
            None => eprintln!("ldappasswd: the server generated no password to print"),
        }
    }

    ExitCode::SUCCESS
}

/// Appends a context-specific primitive part to a BER sequence body.
///
/// The tag numbers in RFC 3062 are `[0]`, `[1]`, `[2]` in a context-specific, primitive
/// class: on the wire that is `0x80 | n`, and writing the bare number produces a universal
/// INTEGER or OCTET STRING tag instead, which a server reads as a different field.
fn push_part(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(0x80 | tag);
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else {
        // Long form: the length of the length first.
        let bytes = (value.len() as u16).to_be_bytes();
        out.push(0x81);
        out.push(bytes[1]);
    }
    out.extend_from_slice(value);
}

/// Wraps the parts in a SEQUENCE.
fn sequence_of(parts: Vec<u8>) -> Vec<u8> {
    let mut out = vec![0x30];
    if parts.len() < 0x80 {
        out.push(parts.len() as u8);
    } else {
        out.push(0x81);
        out.push(parts.len() as u8);
    }
    out.extend_from_slice(&parts);
    out
}

/// Reads a BER length, returning it and how many octets it took.
fn ber_length(bytes: &[u8]) -> Option<(usize, usize)> {
    match bytes.first() {
        Some(first) if first & 0x80 == 0 => Some((*first as usize, 1)),
        Some(_) => bytes.get(1).map(|second| (*second as usize, 2)),
        None => None,
    }
}

/// The generated password out of a `PasswdModifyResponseValue` (RFC 3062 §2.2).
///
/// ```text
/// PasswdModifyResponseValue ::= SEQUENCE { genPasswd [0] OCTET STRING OPTIONAL }
/// ```
///
/// Returns `None` for anything that is not that shape, including the empty value a server
/// sends when it did not generate one: a wrong guess here would print a fragment of the
/// password as if it were the password.
fn generated_password(value: &[u8]) -> Option<&[u8]> {
    let body = value.strip_prefix(&[0x30])?;
    let (length, octets) = ber_length(body)?;
    let body = body.get(octets..)?.get(..length)?;

    let password = body.strip_prefix(&[0x80])?;
    let (inner, octets) = ber_length(password)?;
    let password = password.get(octets..)?.get(..inner)?;

    (!password.is_empty()).then_some(password)
}

// ---------------------------------------------------------------------------------------
// Shared.
// ---------------------------------------------------------------------------------------

/// The DNs on the command line, or the refusal that there are none.
fn entries_of(cli: &Cli) -> Result<Vec<String>, ExitCode> {
    if cli.arguments.is_empty() {
        eprintln!(
            "{}: no entry named",
            std::env::args().next().unwrap_or_default()
        );
        return Err(ExitCode::FAILURE);
    }

    Ok(cli.arguments.clone())
}

/// The result code of an answer, taken from whichever response it is.
fn result_code(messages: &[LdapMessage]) -> Option<ResultCode> {
    messages.last().map(|message| match &message.protocol_op {
        ProtocolOp::DelResponse(response) => response.0.result_code,
        ProtocolOp::ModDnResponse(response) => response.0.result_code,
        ProtocolOp::CompareResponse(response) => response.0.result_code,
        ProtocolOp::ExtendedResp(response) => response.result_code,
        ProtocolOp::AddResponse(response) => response.0.result_code,
        ProtocolOp::ModifyResponse(response) => response.0.result_code,
        ProtocolOp::SearchResDone(response) => response.0.result_code,
        _ => ResultCode::Other,
    })
}

/// The result code behind a client error, for the exit code.
fn code_of(err: &rust_rest_ldap::client::Error) -> ResultCode {
    match err {
        rust_rest_ldap::client::Error::Server { code, .. } => *code,
        _ => ResultCode::Other,
    }
}

fn failure(tool: Tool, err: &rust_rest_ldap::client::Error) -> ExitCode {
    eprintln!("{}: {err}", tool.name());
    ExitCode::from(code_of(err) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("ldaputil").chain(args.iter().copied()))
    }

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_name_maps_to_its_operation_and_nothing_else_does() {
        assert_eq!(Tool::of("ldapdelete"), Some(Tool::Delete));
        assert_eq!(Tool::of("ldapmodrdn"), Some(Tool::ModRdn));
        // The historical spelling of the same operation.
        assert_eq!(Tool::of("ldapmoddn"), Some(Tool::ModRdn));
        assert_eq!(Tool::of("ldapcompare"), Some(Tool::Compare));
        assert_eq!(Tool::of("ldapwhoami"), Some(Tool::WhoAmI));
        assert_eq!(Tool::of("ldappasswd"), Some(Tool::Passwd));

        // A name this program does not answer to must not pick an operation for itself.
        assert_eq!(Tool::of("ldapsearch"), None);
        assert_eq!(Tool::of("ldaputil"), None);
        assert_eq!(Tool::of(""), None);

        // Case does not decide which program this is.
        assert_eq!(Tool::of("LDAPDELETE"), Some(Tool::Delete));
    }

    #[test]
    fn a_comparison_can_be_written_in_the_colon_form() {
        let cli = parse(&["cn:alice", "cn=alice,dc=example,dc=com"]);
        assert_eq!(
            comparison_of(&cli),
            Some((
                "cn".to_string(),
                "alice".to_string(),
                "cn=alice,dc=example,dc=com".to_string()
            ))
        );
    }

    #[test]
    fn a_comparison_can_be_written_dn_first_as_openldap_writes_it() {
        // `ldapcompare DN attr:value` is the spelling OpenLDAP's own manual shows, so a
        // script copied from there must not fail on a usage error.
        let cli = parse(&["cn=alice,dc=example,dc=com", "cn:alice"]);
        assert_eq!(
            comparison_of(&cli),
            Some((
                "cn".to_string(),
                "alice".to_string(),
                "cn=alice,dc=example,dc=com".to_string()
            ))
        );
    }

    #[test]
    fn a_comparison_can_be_written_with_the_dn_in_either_position() {
        // `attr dn value` is OpenLDAP's historical order, `dn attr value` the one people
        // write first. The DN is recognised by its '=', which an attribute never has.
        let attribute_first = parse(&["cn", "cn=alice,dc=example,dc=com", "alice"]);
        let dn_first = parse(&["cn=alice,dc=example,dc=com", "cn", "alice"]);

        let expected = Some((
            "cn".to_string(),
            "alice".to_string(),
            "cn=alice,dc=example,dc=com".to_string(),
        ));
        assert_eq!(comparison_of(&attribute_first), expected);
        assert_eq!(comparison_of(&dn_first), expected);
    }

    #[test]
    fn a_comparison_with_no_dn_is_refused() {
        assert_eq!(comparison_of(&parse(&["cn:alice"])), None);
        assert_eq!(comparison_of(&parse(&["cn", "alice", "x"])), None);
        assert_eq!(comparison_of(&parse(&[])), None);
    }

    #[test]
    fn a_colon_inside_the_value_stays_in_the_value() {
        // `mail:a:b` is the attribute `mail` with the value `a:b`, not the attribute `mail:a`.
        let cli = parse(&["mail:a:b", "cn=alice,dc=example,dc=com"]);
        assert_eq!(
            comparison_of(&cli).map(|(attribute, value, _)| (attribute, value)),
            Some(("mail".to_string(), "a:b".to_string()))
        );
    }

    #[test]
    fn quiet_is_off_unless_asked_for() {
        // A tool that says nothing by default is a tool whose output nobody can read; one
        // that cannot be silenced is one a script has to filter.
        assert!(!parse(&[]).quiet);
        assert!(parse(&["-z"]).quiet);
        assert!(parse(&["--quiet"]).quiet);
    }

    #[test]
    fn the_user_of_a_password_change_is_the_flag_or_the_positional_argument() {
        // Both spellings, because both are OpenLDAP's. A missing user must not be read as
        // "somebody else's password" or as "nobody's": it means the requester's own.
        let flag = parse(&["-e", "cn=bob,dc=example,dc=com"]);
        let positional = parse(&["cn=bob,dc=example,dc=com"]);
        let neither = parse(&[]);

        let user_of = |cli: &Cli| cli.user.clone().or_else(|| cli.arguments.first().cloned());

        assert_eq!(user_of(&flag).as_deref(), Some("cn=bob,dc=example,dc=com"));
        assert_eq!(
            user_of(&positional).as_deref(),
            Some("cn=bob,dc=example,dc=com")
        );
        assert_eq!(user_of(&neither), None);
    }

    #[test]
    fn a_password_request_value_is_a_well_formed_sequence() {
        // The encoding is hand written, so the shape is checked here rather than only against
        // a server: a wrong length is invisible until a real server refuses it.
        let mut parts = Vec::new();
        push_part(&mut parts, 0, b"dn:cn=alice,dc=example,dc=com");
        push_part(&mut parts, 1, b"old");
        push_part(&mut parts, 2, b"new");

        let encoded = sequence_of(parts);
        assert_eq!(encoded[0], 0x30, "a SEQUENCE");
        assert_eq!(encoded[1] as usize, encoded.len() - 2, "the length matches");
    }

    #[test]
    fn a_long_part_uses_the_long_length_form() {
        // A new password longer than 127 octets takes two length octets; writing the short
        // form would truncate the value and change the password to a prefix of itself.
        let long = "x".repeat(200);
        let mut parts = Vec::new();
        push_part(&mut parts, 2, long.as_bytes());

        assert_eq!(parts[0], 0x82, "context tag 2, primitive");
        assert_eq!(parts[1], 0x81, "long form, one length octet");
        assert_eq!(parts[2] as usize, 200);
    }

    #[test]
    fn the_exit_code_carries_the_comparison_answer() {
        // The two codes are what makes ldapcompare useful in a shell: `if ldapcompare` has to
        // be able to tell TRUE from FALSE, and both are successful operations.
        assert_eq!(ResultCode::CompareTrue as u8, 6);
        assert_eq!(ResultCode::CompareFalse as u8, 5);
    }

    #[test]
    fn a_generated_password_is_read_out_of_the_response_value() {
        // The shape RFC 3062 §2.2 gives it, written the way the server writes it.
        let mut inner = Vec::new();
        push_part(&mut inner, 0, b"generated-secret");
        let value = sequence_of(inner);

        assert_eq!(generated_password(&value), Some(&b"generated-secret"[..]));
    }

    #[test]
    fn a_response_value_without_a_password_yields_nothing() {
        // The server sends an empty sequence when it did not generate one; printing a
        // fragment of it as the password would be worse than printing nothing.
        assert_eq!(generated_password(&sequence_of(Vec::new())), None);
        assert_eq!(generated_password(&[]), None);
        assert_eq!(generated_password(b"not a sequence"), None);
    }
}
