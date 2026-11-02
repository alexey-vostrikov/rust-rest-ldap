#![forbid(unsafe_code)]

use clap::Parser;
use rust_rest_ldap::{cli, config};

fn main() {
    let args: config::Args = cli::Cli::parse().into();

    let config = match config::load(args) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    println!("{config:#?}");
}
