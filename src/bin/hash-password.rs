//! `hash-password`: print a password hash for `userPassword`.
//!
//! The equivalent of OpenLDAP's `slappasswd`: an operator needs a way to put a
//! hash into the data without running the server.

use clap::Parser;
use rrl_directory::password::{StoreScheme, hash};

#[derive(Debug, Parser)]
#[command(
    name = "hash-password",
    version,
    about = "Print an LDAP password hash for userPassword"
)]
struct Cli {
    /// Password to hash; read from stdin when omitted
    password: Option<String>,

    /// Storage scheme: argon2id (default) or pbkdf2-sha512
    #[arg(short, long, default_value = "argon2id")]
    scheme: StoreScheme,
}

fn main() {
    let cli = Cli::parse();

    let password = match cli.password {
        Some(password) => password,
        None => {
            let mut buffer = String::new();
            match std::io::stdin().read_line(&mut buffer) {
                Ok(_) => buffer.trim_end_matches(['\n', '\r']).to_string(),
                Err(err) => {
                    eprintln!(
                        "{}",
                        rrl_directory::i18n::t("error.write", &[("detail", &err.to_string())])
                    );
                    std::process::exit(1);
                }
            }
        }
    };

    match hash(&password, cli.scheme) {
        Ok(hashed) => println!("{hashed}"),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}
