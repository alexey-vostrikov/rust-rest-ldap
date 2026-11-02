#![forbid(unsafe_code)]

use std::sync::Arc;

use clap::Parser;
use rust_rest_ldap::backend::Backend;
use rust_rest_ldap::{cli, config, i18n, security::Security};

#[tokio::main]
async fn main() {
    let args: config::Args = cli::Cli::parse().into();
    let export = args.export_ldif.clone();
    let export_yaml = args.export_yaml.clone();
    let export_operational = args.export_operational;

    // The language has to be known before the configuration parses, so that a typo in a
    // Russian config is reported in Russian: the environment answers first, and the raw
    // text is scanned for `locale:` because the parsed value is not available yet.
    install_language(&args, None);

    let config = match config::load(args) {
        Ok(config) => config,
        Err(err) => fatal(&config_message(&err)),
    };

    // Now the file has spoken: its `locale:` overrides the environment.
    install_language(
        &config::Args::default(),
        Some((
            config.locale.0.clone(),
            config.locale.1,
            config.locale_file.clone(),
        )),
    );

    // Fail fast: a backend that cannot be built or read is a startup error, not a
    // server that comes up empty and looks healthy.
    let backend = match Backend::from_config(&config.backend, config.backends.get(&config.backend))
    {
        Ok(backend) => backend,
        Err(err) => fatal(&i18n::t("error.backend", &[("detail", &err.to_string())])),
    };
    // An export is a one-shot read of the backend, not a server: it must not bind a
    // port, and it must not rewrite data on its way out.
    let as_yaml = export.is_none() && export_yaml.is_some();
    if let Some(path) = export.or(export_yaml) {
        let data = match backend.load().await {
            Ok(data) => data,
            Err(err) => fatal(&i18n::t("error.backend", &[("detail", &err.to_string())])),
        };
        let directory = data.into_directory(
            &config.base_dn,
            &config.users_ou_name,
            &config.groups_ou_name,
        );

        // Both formats describe the same entries; only their shape differs, so the
        // selection of operational attributes is one option for both.
        let text = if as_yaml {
            rust_rest_ldap::yaml_export::export(
                directory.all(),
                rust_rest_ldap::yaml_export::Options {
                    operational: export_operational,
                    ..Default::default()
                },
            )
        } else {
            rust_rest_ldap::ldif::export(
                directory.all(),
                rust_rest_ldap::ldif::Options {
                    operational: export_operational,
                    ..Default::default()
                },
            )
        };

        if path.as_os_str() == "-" {
            print!("{text}");
        } else if let Err(err) = std::fs::write(&path, text) {
            fatal(&i18n::t(
                "error.write",
                &[("detail", &format!("'{}': {err}", path.display()))],
            ));
        } else {
            eprintln!(
                "{}",
                i18n::t(
                    "start.export_done",
                    &[
                        ("entries", &directory.len().to_string()),
                        ("path", &path.display().to_string()),
                    ],
                )
            );
        }
        return;
    }

    let (source, directory) = match rust_rest_ldap::reload::Source::load(&config, backend).await {
        Ok(loaded) => loaded,
        Err(err) => fatal(&i18n::t("error.backend", &[("detail", &err.to_string())])),
    };
    let security = Security::from_config(&config);

    println!(
        "{}",
        i18n::t(
            "start.banner",
            &[
                ("version", env!("CARGO_PKG_VERSION")),
                ("backend", &config.backend),
                ("base", directory.base_dn()),
                ("users", &directory.users().len().to_string()),
                ("groups", &directory.groups().len().to_string()),
            ],
        )
    );
    if !config.dangerous_settings.is_empty() {
        println!(
            "{}",
            i18n::t(
                "start.danger",
                &[("settings", &config.dangerous_settings.join(", "))]
            )
        );
    }
    println!(
        "{}",
        i18n::t(
            "start.passwords",
            &[
                ("scheme", security.passwords.store_scheme().name()),
                (
                    "weak",
                    &security.passwords.allowed_weak().count().to_string()
                ),
                ("rules", &security.acl.rules().len().to_string()),
                (
                    "plaintext",
                    if security.allow_unencrypted_bind {
                        "true"
                    } else {
                        "false"
                    }
                ),
            ],
        )
    );
    let (locale, locale_source) = &config.locale;
    if !locale.is_english() {
        println!(
            "{}",
            i18n::t(
                "start.language",
                &[
                    ("locale", locale.as_str()),
                    ("source", locale_source.name())
                ]
            )
        );
    }

    let listener = match tokio::net::TcpListener::bind(&config.listen_addr).await {
        Ok(listener) => listener,
        Err(err) => fatal(&i18n::t(
            "error.server",
            &[("detail", &format!("'{}': {err}", config.listen_addr))],
        )),
    };
    println!(
        "{}",
        i18n::t("start.listening", &[("addr", &config.listen_addr)])
    );

    // A certificate is shared by LDAPS and StartTLS; its presence decides whether
    // either is offered at all.
    let acceptor = match (&config.server_cert, &config.server_key) {
        (Some(cert), Some(key)) => match rust_rest_ldap::tls::acceptor(cert, key) {
            Ok(acceptor) => Some(acceptor),
            Err(err) => fatal(&i18n::t("error.server", &[("detail", &err.to_string())])),
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

    // One metrics registry and one journal for the process. The metrics are lock-free, so
    // the accept loop and every connection task can share this without contention.
    let metrics = rust_rest_ldap::metrics::Metrics::new();
    metrics.set_entries(directory.len());

    let journal = match (
        config.observability.journal_stdout,
        config.observability.journal.clone(),
    ) {
        (true, _) => {
            println!("{}", i18n::plain("start.journal_stdout"));
            Arc::new(rust_rest_ldap::metrics::Journal::stdout())
        }
        (false, Some(path)) => match rust_rest_ldap::metrics::Journal::file(&path) {
            Ok(journal) => {
                println!(
                    "{}",
                    i18n::t("start.journal", &[("path", &path.display().to_string())])
                );
                Arc::new(journal)
            }
            // A journal the operator asked for and the server cannot write is a startup
            // error: silently running without it would leave "who deleted it" unanswerable
            // for as long as nobody notices.
            Err(err) => fatal(&i18n::t(
                "error.journal",
                &[("detail", &format!("'{}': {err}", path.display()))],
            )),
        },
        (false, None) => Arc::new(rust_rest_ldap::metrics::Journal::off()),
    };

    let observers = rust_rest_ldap::server::Observers {
        metrics: Arc::clone(&metrics),
        journal,
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let reloading = tokio::spawn(rust_rest_ldap::reload::reload_on_interval_with(
        Arc::clone(&source),
        config.update_interval,
        shutdown_rx.clone(),
        Arc::clone(&metrics),
    ));

    // SIGUSR1 is the "reload now" switch gorestldap documented for systemd.
    spawn_usr1_reloader(Arc::clone(&source), Arc::clone(&metrics));

    let http_task = match &config.http_listen_addr {
        Some(addr) => {
            let state = Arc::new(rust_rest_ldap::http::HttpState {
                source: Arc::clone(&source),
                metrics: Arc::clone(&metrics),
                callback_token: config.callback_auth_token.clone(),
            });
            let router = rust_rest_ldap::http::router(state);
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    println!("{}", i18n::t("start.http", &[("addr", addr)]));
                    Some(tokio::spawn(async move {
                        if let Err(err) = axum::serve(listener, router).await {
                            eprintln!("{}", i18n::t("error.http", &[("detail", &err.to_string())]));
                        }
                    }))
                }
                Err(err) => fatal(&i18n::t(
                    "error.server",
                    &[("detail", &format!("'{addr}': {err}"))],
                )),
            }
        }
        None => None,
    };

    let serving = tokio::spawn(rust_rest_ldap::server::serve_with(
        listener,
        rust_rest_ldap::server::Listener {
            acceptor,
            ldaps: config.use_tls,
            // Clients get this long to finish the operation they are in the middle of.
            grace: std::time::Duration::from_secs(10),
        },
        Arc::clone(&source),
        Arc::new(security),
        shutdown_rx,
        observers,
    ));

    wait_for_signal().await;
    println!("{}", i18n::plain("start.shutting_down"));
    let _ = shutdown_tx.send(true);
    match serving.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => eprintln!(
            "{}",
            i18n::t("error.server", &[("detail", &err.to_string())])
        ),
        Err(err) => eprintln!(
            "{}",
            i18n::t("error.server", &[("detail", &err.to_string())])
        ),
    }
    reloading.abort();
    if let Some(task) = http_task {
        task.abort();
    }
}

fn spawn_usr1_reloader(
    source: Arc<rust_rest_ldap::reload::Source>,
    metrics: Arc<rust_rest_ldap::metrics::Metrics>,
) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut usr1 = match signal(SignalKind::user_defined1()) {
            Ok(signal) => signal,
            Err(err) => {
                eprintln!(
                    "{}",
                    i18n::t("error.signal", &[("detail", &err.to_string())])
                );
                return;
            }
        };
        tokio::spawn(async move {
            while usr1.recv().await.is_some() {
                match source.reload().await {
                    Ok(entries) => {
                        metrics.set_entries(entries);
                        metrics.reload_succeeded();
                        println!("reload (SIGUSR1): {entries} entries");
                    }
                    Err(err) => {
                        metrics.reload_failed();
                        eprintln!(
                            "{}",
                            i18n::t("error.reload", &[("detail", &err.to_string())])
                        )
                    }
                }
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = (source, metrics);
    }
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(err) => fatal(&i18n::t("error.signal", &[("detail", &err.to_string())])),
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

/// Chooses and installs the diagnostics language.
///
/// Two calls happen in the life of a start: one with only the environment (before the
/// configuration is readable, so its errors can be reported in the right language), one
/// with what the configuration said. The second wins.
fn install_language(
    args: &config::Args,
    from_config: Option<(i18n::Locale, i18n::Source, Option<std::path::PathBuf>)>,
) {
    let (locale, source, file) = match from_config {
        Some((locale, source, file)) => (locale, source, file),
        None => {
            // The raw text, when there is a file to read: a `locale:` inside it should
            // already govern the complaints about it.
            let env = |name: &str| std::env::var(name).ok();
            let (locale, source) = i18n::from_env(&env);

            let scanned = args
                .config
                .as_ref()
                .and_then(|path| std::fs::read_to_string(path).ok())
                .and_then(|text| i18n::prescan_locale(&text));

            match scanned {
                Some(locale) if !locale.is_english() => (locale, i18n::Source::Config, None),
                _ => (locale, source, None),
            }
        }
    };

    // `locale/<tag>.yaml` next to the working directory, then next to the executable.
    let file = file.or_else(|| {
        let name = format!("locale/{}.yaml", locale.as_str());
        let local = std::path::PathBuf::from(&name);
        if local.is_file() {
            return Some(local);
        }
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join(&name)))
            .filter(|path| path.is_file())
    });

    match i18n::catalog_for(locale, source, file.as_deref()) {
        Ok(catalog) => i18n::install(catalog),
        Err(err) => fatal(&err.to_string()),
    }
}

/// The operator-facing text for a configuration error.
///
/// The error type keeps its English `Display` (tests match on it and it is the developer's
/// view); this is the operator's view, in their language, with the English detail kept
/// where it names a file or a parser position.
fn config_message(err: &config::ConfigError) -> String {
    let english = err.to_string();

    // The translated text borrows its arguments, so they are built first and kept alive
    // in `owned` until the call is done.
    let key: &str;
    let mut owned: Vec<(String, String)> = Vec::new();

    match err {
        config::ConfigError::MissingTlsMaterial => key = "config.tls_material",
        config::ConfigError::SchemaMode(value) => {
            key = "config.schema_mode";
            owned.push(("value".to_string(), value.clone()));
        }
        config::ConfigError::Locale { value } => {
            key = "config.locale";
            owned.push(("value".to_string(), value.clone()));
            owned.push(("path".to_string(), format!("locale/{value}.yaml")));
        }
        config::ConfigError::DangerousSettingsNotAcknowledged { settings } => {
            key = "config.dangerous";
            owned.push(("settings".to_string(), settings.clone()));
        }
        config::ConfigError::PlainHttpNotAcknowledged { address } => {
            key = "config.plain_http";
            owned.push(("address".to_string(), address.clone()));
        }
        config::ConfigError::SchemaRead { path, source } => {
            key = "config.schema_read";
            owned.push(("path".to_string(), path.clone()));
            owned.push(("detail".to_string(), source.to_string()));
        }
        config::ConfigError::Schema { path, source } => {
            key = "config.schema";
            owned.push(("path".to_string(), path.clone()));
            owned.push(("detail".to_string(), source.to_string()));
        }
        config::ConfigError::Interval { value, source } => {
            key = "config.interval";
            owned.push(("value".to_string(), value.clone()));
            owned.push(("detail".to_string(), source.to_string()));
        }
        config::ConfigError::Parse { path, source } => {
            key = "config.parse";
            owned.push(("path".to_string(), path.display().to_string()));
            owned.push(("detail".to_string(), source.to_string()));
        }
        config::ConfigError::Read { path, source } => {
            key = "config.parse";
            owned.push(("path".to_string(), path.display().to_string()));
            owned.push(("detail".to_string(), source.to_string()));
        }
        config::ConfigError::Index(err) => {
            key = "config.index";
            owned.push(("detail".to_string(), err.to_string()));
        }
        config::ConfigError::Password(err) => {
            key = "config.password";
            owned.push(("detail".to_string(), err.to_string()));
        }
        config::ConfigError::Access(err) => {
            key = "config.access";
            owned.push(("detail".to_string(), err.to_string()));
        }
    }

    let args: Vec<(&str, &str)> = owned
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let translated = i18n::t(key, &args);

    // `t` returns the key itself when the catalogue has no text for it. That is the one
    // case where the translated line is useless, and the English message is the answer.
    if translated == key {
        return english;
    }

    // Otherwise the translated line carries everything the English one did — including the
    // parser position or the file name, through `{detail}`. Two lines saying the same
    // thing in two languages is noise, not help.
    translated
}
