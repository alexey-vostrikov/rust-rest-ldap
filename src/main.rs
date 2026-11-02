#![forbid(unsafe_code)]

use clap::Parser;
use rust_rest_ldap::{cli, config, security::Security};

fn main() {
    let args: config::Args = cli::Cli::parse().into();

    let config = match config::load(args) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    let security = Security::from_config(&config);

    println!("{config:#?}");
    println!(
        "security: passwords {:?}, acl rules {}, plaintext simple bind {}",
        security.passwords.store_scheme(),
        security.acl.rules().len(),
        security.allow_plaintext_simple_bind
    );
}
