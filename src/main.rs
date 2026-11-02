#![forbid(unsafe_code)]

use std::sync::Arc;

use clap::Parser;
use rust_rest_ldap::backend::Backend;
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::{cli, config, security::Security};

#[tokio::main]
async fn main() {
    let args: config::Args = cli::Cli::parse().into();

    let config = match config::load(args) {
        Ok(config) => config,
        Err(err) => fatal(&err.to_string()),
    };

    // Fail fast: a backend that cannot be built or read is a startup error, not a
    // server that comes up empty and looks healthy.
    let backend = match Backend::from_config(&config.backend, config.backends.get(&config.backend))
    {
        Ok(backend) => backend,
        Err(err) => fatal(&err.to_string()),
    };
    let data = match backend.load().await {
        Ok(data) => data,
        Err(err) => fatal(&err.to_string()),
    };

    let directory = Directory::new(
        &config.base_dn,
        &config.users_ou_name,
        &config.groups_ou_name,
        data.users,
        data.groups,
    );
    let security = Security::from_config(&config);

    println!(
        "rust-rest-ldap {}: backend '{}', base '{}', {} users, {} groups",
        env!("CARGO_PKG_VERSION"),
        config.backend,
        directory.base_dn(),
        directory.users().len(),
        directory.groups().len()
    );
    println!(
        "passwords: store {}, {} weak scheme(s) allowed; acl rules {}; plaintext simple bind {}",
        security.passwords.store_scheme().name(),
        security.passwords.allowed_weak().count(),
        security.acl.rules().len(),
        security.allow_plaintext_simple_bind
    );

    let listener = match tokio::net::TcpListener::bind(&config.listen_addr).await {
        Ok(listener) => listener,
        Err(err) => fatal(&format!(
            "error listening on '{}': {err}",
            config.listen_addr
        )),
    };
    println!("ldap: listening on {}", config.listen_addr);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let serving = tokio::spawn(rust_rest_ldap::server::serve(
        listener,
        Arc::new(directory),
        Arc::new(security),
        shutdown_rx,
    ));

    wait_for_signal().await;
    println!("shutting down");
    let _ = shutdown_tx.send(true);
    match serving.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => eprintln!("server error: {err}"),
        Err(err) => eprintln!("server task failed: {err}"),
    }
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(err) => fatal(&format!("cannot install SIGTERM handler: {err}")),
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn fatal(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
