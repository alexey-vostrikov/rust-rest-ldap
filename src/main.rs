#![forbid(unsafe_code)]

use std::sync::Arc;

use clap::Parser;
use rust_rest_ldap::backend::Backend;
use rust_rest_ldap::{cli, config, security::Security};

#[tokio::main]
async fn main() {
    let args: config::Args = cli::Cli::parse().into();
    let export = args.export_ldif.clone();
    let export_operational = args.export_operational;

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
    // An export is a one-shot read of the backend, not a server: it must not bind a
    // port, and it must not rewrite data on its way out.
    if let Some(path) = export {
        let data = match backend.load().await {
            Ok(data) => data,
            Err(err) => fatal(&err.to_string()),
        };
        let directory = data.into_directory(
            &config.base_dn,
            &config.users_ou_name,
            &config.groups_ou_name,
        );

        let text = rust_rest_ldap::ldif::export(
            directory.all(),
            rust_rest_ldap::ldif::Options {
                operational: export_operational,
                ..Default::default()
            },
        );

        if path.as_os_str() == "-" {
            print!("{text}");
        } else if let Err(err) = std::fs::write(&path, text) {
            fatal(&format!("error writing '{}': {err}", path.display()));
        } else {
            eprintln!("exported {} entries to {}", directory.len(), path.display());
        }
        return;
    }

    let (source, directory) = match rust_rest_ldap::reload::Source::load(&config, backend).await {
        Ok(loaded) => loaded,
        Err(err) => fatal(&err.to_string()),
    };
    let security = Security::from_config(&config);

    println!(
        "rust-rest-ldap {}: backend '{}', base '{}', {} users, {} groups",
        env!("CARGO_PKG_VERSION"),
        config.backend,
        directory.base_dn(),
        directory.users().len(),
        directory.groups().len()
    );
    if !config.dangerous_settings.is_empty() {
        println!(
            "DANGER: this configuration turns on {} - acknowledged with AllowDangerousSettings",
            config.dangerous_settings.join(", ")
        );
    }
    println!(
        "passwords: store {}, {} weak scheme(s) allowed; acl rules {}; plaintext simple bind {}",
        security.passwords.store_scheme().name(),
        security.passwords.allowed_weak().count(),
        security.acl.rules().len(),
        security.allow_unencrypted_bind
    );

    let listener = match tokio::net::TcpListener::bind(&config.listen_addr).await {
        Ok(listener) => listener,
        Err(err) => fatal(&format!(
            "error listening on '{}': {err}",
            config.listen_addr
        )),
    };
    println!("ldap: listening on {}", config.listen_addr);

    // A certificate is shared by LDAPS and StartTLS; its presence decides whether
    // either is offered at all.
    let acceptor = match (&config.server_cert, &config.server_key) {
        (Some(cert), Some(key)) => match rust_rest_ldap::tls::acceptor(cert, key) {
            Ok(acceptor) => Some(acceptor),
            Err(err) => fatal(&err.to_string()),
        },
        _ => None,
    };
    if config.use_tls {
        println!(
            "ldaps: enabled, certificate {}",
            config
                .server_cert
                .as_ref()
                .map_or("<none>", |path| path.to_str().unwrap_or("<invalid path>"))
        );
    } else if acceptor.is_some() {
        println!("starttls: enabled");
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let reloading = tokio::spawn(rust_rest_ldap::reload::reload_on_interval(
        Arc::clone(&source),
        config.update_interval,
        shutdown_rx.clone(),
    ));

    // SIGUSR1 is the "reload now" switch gorestldap documented for systemd.
    spawn_usr1_reloader(Arc::clone(&source));

    let http_task = match &config.http_listen_addr {
        Some(addr) => {
            let state = Arc::new(rust_rest_ldap::http::HttpState {
                source: Arc::clone(&source),
                callback_token: config.callback_auth_token.clone(),
            });
            let router = rust_rest_ldap::http::router(state);
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    println!("http: listening on {addr}");
                    Some(tokio::spawn(async move {
                        if let Err(err) = axum::serve(listener, router).await {
                            eprintln!("http server error: {err}");
                        }
                    }))
                }
                Err(err) => fatal(&format!("error listening on '{addr}': {err}")),
            }
        }
        None => None,
    };

    let serving = tokio::spawn(rust_rest_ldap::server::serve(
        listener,
        acceptor,
        config.use_tls,
        Arc::clone(&source),
        Arc::new(security),
        shutdown_rx,
        // Clients get this long to finish the operation they are in the middle of.
        std::time::Duration::from_secs(10),
    ));

    wait_for_signal().await;
    println!("shutting down");
    let _ = shutdown_tx.send(true);
    match serving.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => eprintln!("server error: {err}"),
        Err(err) => eprintln!("server task failed: {err}"),
    }
    reloading.abort();
    if let Some(task) = http_task {
        task.abort();
    }
}

fn spawn_usr1_reloader(source: Arc<rust_rest_ldap::reload::Source>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut usr1 = match signal(SignalKind::user_defined1()) {
            Ok(signal) => signal,
            Err(err) => {
                eprintln!("cannot install SIGUSR1 handler: {err}");
                return;
            }
        };
        tokio::spawn(async move {
            while usr1.recv().await.is_some() {
                match source.reload().await {
                    Ok(entries) => {
                        println!("reload (SIGUSR1): {entries} entries");
                    }
                    Err(err) => eprintln!("reload failed, keeping the current directory: {err}"),
                }
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = source;
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
