#![forbid(unsafe_code)]

use std::sync::Arc;

use clap::Parser;
use rust_rest_ldap::backend::Backend;
use rust_rest_ldap::{cli, config, i18n, security::Security};

fn main() {
    // Built here rather than through `#[tokio::main]`: the attribute cannot name the threads, and a
    // thread called `tokio-rt-worker` in `ps -L` says nothing about which program it belongs to.
    rust_rest_ldap::runtime::multi_thread().block_on(serve());
}

/// Whether this process serves a domain, and so has a SID to issue.
///
/// Any one of the identity services is enough: a deployment may run tickets elsewhere and still be
/// the directory those tickets are about.
#[cfg(feature = "kdc")]
fn serves_a_domain(config: &config::Config) -> bool {
    if config.kerberos.enabled || config.cldap.enabled {
        return true;
    }
    #[cfg(feature = "smb")]
    if config.smb.enabled {
        return true;
    }
    false
}

async fn serve() {
    let args: config::Args = cli::Cli::parse().into();
    let export = args.export_ldif.clone();
    let export_yaml = args.export_yaml.clone();
    let export_operational = args.export_operational;
    let import_ldif = args.import_ldif.clone();
    let allow_existing_entry = args.allow_existing_entry;
    let check_config = args.check_config;
    let check_index = args.check_index;
    let config_path = args.config.clone();
    let config_commit = args.config_commit;
    let config_rollback = args.config_rollback;
    let config_history = args.config_history;
    let config_keep = args.config_keep;
    let note = args.note.clone();
    let from = args.from.clone();
    let reindex = args.reindex;
    let compact = args.compact;

    // The language has to be known before the configuration parses, so that a typo in a
    // Russian config is reported in Russian: the environment answers first, and the raw
    // text is scanned for `locale:` because the parsed value is not available yet.
    install_language(&args, None);

    // The store commands run before the configuration is parsed: they are about the
    // configuration itself, and `--config-history` on a store that holds no generation yet
    // must list nothing rather than fail to load what is not there.
    if let Some(command) = store_command(config_commit, config_rollback, config_history) {
        let store_path = match config_path
            .clone()
            .or_else(|| std::env::var_os(config::ENV_CONFIG_PATH).map(std::path::PathBuf::from))
        {
            Some(path) => path,
            None => fatal(&i18n::t(
                "error.store_path_missing",
                &[("command", command.name())],
            )),
        };

        // A store that does not exist yet is created by the first commit: refusing here would
        // mean an operator has to `mkdir` a directory whose layout is this program's business.
        // An existing *file* is refused, because that is a configuration and the operator
        // pointed at the wrong thing.
        if store_path.exists() && !rust_rest_ldap::config_store::Store::is_store(&store_path) {
            fatal(&i18n::t(
                "error.store_not_a_directory",
                &[("path", &store_path.display().to_string())],
            ));
        }

        run_store_command(
            command,
            &store_path,
            config_keep,
            note.as_deref(),
            from.as_deref(),
        );
        return;
    }

    let config = match config::load(args) {
        Ok(config) => config,
        Err(err) => fatal(&err.message()),
    };

    // Before anything else that could fail: a startup error is the one an operator most needs
    // to see reported, and until the subscriber exists every `error!` in this process is a no-op.
    if let Err(err) = rust_rest_ldap::logging::install(&config) {
        fatal(&format!("log file: {err}"));
    }

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
    let mut backend =
        match Backend::from_config(&config.backend, config.backends.get(&config.backend)) {
            Ok(backend) => backend,
            Err(err) => fatal(&i18n::t("error.backend", &[("detail", &err.to_string())])),
        };
    // Verifying the indexes is an offline read: it builds nothing the server would not have
    // built and writes nothing. The exit code is the answer.
    if check_index {
        let data = match backend.load().await {
            Ok(data) => data,
            Err(err) => fatal(&i18n::t("error.backend", &[("detail", &err.to_string())])),
        };
        let directory = data.into_directory(
            &config.base_dn,
            &config.users_ou_name,
            &config.groups_ou_name,
        );
        let directory = match directory.with_indexes(&config.indexes) {
            Ok(directory) => directory,
            Err(err) => fatal(&i18n::t("error.index", &[("detail", &err.to_string())])),
        };

        let report = rust_rest_ldap::index_check::check(directory.all(), directory.index());

        for mismatch in report.missing.iter().chain(report.wrong.iter()) {
            eprintln!(
                "{}",
                i18n::t(
                    "check.index_mismatch",
                    &[
                        ("query", &mismatch.query),
                        ("lost", &mismatch.lost.join(", ")),
                        ("extra", &mismatch.extra.join(", ")),
                    ],
                )
            );
        }

        for item in &report.loose {
            eprintln!(
                "{}",
                i18n::t(
                    "check.index_loose",
                    &[
                        ("attribute", &item.attribute),
                        ("extra", &item.extra.to_string()),
                    ],
                )
            );
        }

        // The summary says which of the two things happened rather than reporting counts
        // under a heading that calls a broken index sound.
        let key = if report.is_sound() {
            "check.index_sound"
        } else {
            "check.index_broken"
        };

        println!(
            "{}",
            i18n::t(
                key,
                &[
                    ("checked", &report.checked.to_string()),
                    ("skipped", &report.not_indexed.to_string()),
                    ("missing", &report.missing.len().to_string()),
                    ("wrong", &report.wrong.len().to_string()),
                ],
            )
        );

        if !report.is_sound() {
            std::process::exit(1);
        }
        return;
    }

    // Before anything reads the store: compaction needs the file to itself, and every read
    // reference redb sees is a transaction it refuses to move pages under.
    if compact {
        match backend.compact() {
            Ok(Some(report)) if report.performed => println!(
                "{}",
                i18n::t(
                    "check.compact_done",
                    &[
                        ("before", &report.before.to_string()),
                        ("after", &report.after.to_string()),
                        ("reclaimed", &report.reclaimed().to_string()),
                    ],
                )
            ),
            Ok(Some(_)) => println!("{}", i18n::t("check.compact_nothing", &[])),
            Ok(None) => fatal(&i18n::t("error.compact_backend", &[])),
            Err(err) => fatal(&i18n::t("error.backend", &[("detail", &err.to_string())])),
        }
        return;
    }

    if reindex {
        let data = match backend.load().await {
            Ok(data) => data,
            Err(err) => fatal(&i18n::t("error.backend", &[("detail", &err.to_string())])),
        };
        let directory = data.into_directory(
            &config.base_dn,
            &config.users_ou_name,
            &config.groups_ou_name,
        );

        let started = std::time::Instant::now();
        let directory = match directory.with_indexes(&config.indexes) {
            Ok(directory) => directory,
            Err(err) => fatal(&i18n::t("error.index", &[("detail", &err.to_string())])),
        };
        let elapsed = started.elapsed();

        println!(
            "{}",
            i18n::t(
                "check.reindex_done",
                &[
                    ("entries", &directory.all().len().to_string()),
                    (
                        "attributes",
                        &directory.index().built_attributes().count().to_string()
                    ),
                    ("bytes", &directory.index().size_bytes().to_string()),
                    ("millis", &elapsed.as_millis().to_string()),
                ],
            )
        );
        return;
    }

    // A check-only run reports whether this configuration would start, the way `slaptest`
    // does, and never binds a port. The backend open above already proved the store is
    // readable; what is left is the data itself.
    if check_config {
        let data = match backend.load().await {
            Ok(data) => data,
            Err(err) => fatal(&i18n::t("error.backend", &[("detail", &err.to_string())])),
        };

        let count = data.entries.len() + data.users.len() + data.groups.len();
        let directory = data.into_directory(
            &config.base_dn,
            &config.users_ou_name,
            &config.groups_ou_name,
        );

        // The schema is checked over the real entries, not a sample: a violation is what
        // would make the first client complain, and this run exists to find it earlier.
        let mut broken = 0;
        if config.schema_mode != rust_rest_ldap::schema::Mode::Off {
            for entry in directory.all() {
                let Err(violations) = config.schema.check(entry) else {
                    continue;
                };

                broken += 1;
                for violation in violations {
                    eprintln!(
                        "{}",
                        i18n::t(
                            "check.schema_violation",
                            &[("dn", entry.dn()), ("detail", &violation.detail)],
                        )
                    );
                }
            }
        }

        println!(
            "{}",
            i18n::t(
                "check.ok",
                &[
                    ("backend", &config.backend),
                    ("base_dn", &config.base_dn),
                    ("entries", &count.to_string()),
                    ("broken", &broken.to_string()),
                ],
            )
        );

        // The exit code is the answer, so a deployment script can branch on it without
        // parsing prose.
        if broken > 0 && config.schema_mode == rust_rest_ldap::schema::Mode::Strict {
            std::process::exit(1);
        }
        return;
    }

    // An import is a one-shot write, not a server: same shape as the export below, and for
    // the same reason.
    if let Some(path) = import_ldif {
        let text = if path.as_os_str() == "-" {
            {
                let mut text = String::new();
                match std::io::Read::read_to_string(&mut std::io::stdin(), &mut text) {
                    Ok(_) => text,
                    Err(err) => fatal(&i18n::t("error.read", &[("detail", &err.to_string())])),
                }
            }
        } else {
            match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(err) => fatal(&i18n::t(
                    "error.read",
                    &[("detail", &format!("'{}': {err}", path.display()))],
                )),
            }
        };

        match rust_rest_ldap::import::import(&backend, &config, &text, allow_existing_entry).await {
            Ok(outcome) => {
                for warning in &outcome.warnings {
                    eprintln!("{}", i18n::t("warn.schema", &[("detail", warning)]));
                }

                println!(
                    "{}",
                    i18n::t("import.done", &[("entries", &outcome.entries.to_string())],)
                );
            }
            Err(err) => fatal(&i18n::t("error.import", &[("detail", &err.to_string())])),
        }

        return;
    }

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

    // The first administrator, for a store no client can write to yet: `add` needs a bind,
    // and a bind needs an entry. Runs before the listener, so the directory is
    // administrable from the first connection rather than after a manual edit.
    if let Some(section) = config.bootstrap.clone() {
        let secret =
            match rust_rest_ldap::bootstrap::password(&section, |name| std::env::var(name).ok()) {
                Ok(secret) => secret,
                Err(err) => fatal(&i18n::t("error.bootstrap", &[("detail", &err.to_string())])),
            };
        let spec = match rust_rest_ldap::bootstrap::Spec::new(
            section.dn.as_deref(),
            &config.base_dn,
            &config.users_ou_name,
            secret.expose(),
        ) {
            Ok(spec) => spec,
            Err(err) => fatal(&i18n::t("error.bootstrap", &[("detail", &err.to_string())])),
        };

        match rust_rest_ldap::bootstrap::seed_with(&backend, &spec, &config.passwords).await {
            Ok(rust_rest_ldap::bootstrap::Outcome::Created { dn }) => eprintln!(
                "{}",
                i18n::t(
                    "start.bootstrap_created",
                    &[
                        ("dn", &dn),
                        (
                            "scheme",
                            rust_rest_ldap::bootstrap::scheme_name(&config.passwords)
                        ),
                    ],
                )
            ),
            // Said out loud rather than skipped in silence: a bootstrap section left in
            // the configuration of a directory in use is a question the operator will ask,
            // and "it did nothing" is the answer.
            Ok(rust_rest_ldap::bootstrap::Outcome::NotEmpty { entries }) => eprintln!(
                "{}",
                i18n::t(
                    "start.bootstrap_not_empty",
                    &[("entries", &entries.to_string())]
                )
            ),
            Err(err) => fatal(&i18n::t("error.bootstrap", &[("detail", &err.to_string())])),
        }
    }

    // Before the first write, because a change stamped before this point carries the id of
    // "no node" and a peer could not tell it from its own.
    rust_rest_ldap::replication::set_server_id(config.server_id);

    // Before the directory is built, so the floor the snapshot carries is the floor that is: a
    // snapshot taken before pruning would say the journal reaches further back than it does, and a
    // peer resuming from that stretch would be told nothing was missed.
    // Age first: a record that is too old is too old whatever the count says, and doing it the
    // other way round would let a generous count keep a year of tombstones in a quiet directory.
    if let Some(age) = config.journal_max_age {
        let cutoff = std::time::SystemTime::now()
            .checked_sub(age)
            .unwrap_or(std::time::UNIX_EPOCH);
        match backend.journal_prune_before(cutoff) {
            Ok(removed) if removed > 0 => println!(
                "{}",
                i18n::t(
                    "start.journal_pruned_age",
                    &[("removed", &removed.to_string())]
                )
            ),
            Ok(_) => {}
            Err(err) => fatal(&i18n::t("error.backend", &[("detail", &err.to_string())])),
        }
    }

    if let Some(keep) = config.journal_keep {
        match backend.journal_prune(keep) {
            Ok(removed) if removed > 0 => println!(
                "{}",
                i18n::t("start.journal_pruned", &[("removed", &removed.to_string())])
            ),
            Ok(_) => {}
            Err(err) => fatal(&i18n::t("error.backend", &[("detail", &err.to_string())])),
        }
    }

    // The domain's identity: its SID, and the counter that issues RIDs inside it. Opened before the
    // source takes ownership of the backend, because both live in that store, and a SID derived
    // after the fact would be a second SID.
    //
    // A domain is what a process that names identities serves - tickets, CLDAP pings, SMB sessions
    // - and not the same thing as a KDC. Tying this to `kerberos.enabled` alone was wrong and the
    // stand showed it: there the KDC is a separate process serving the same realm, so this server
    // answered a member's join with a NULL domain SID, which a join reads as an allocation failure
    // it cannot explain.
    #[cfg(feature = "kdc")]
    let domain = if serves_a_domain(&config) {
        // Sixteen octets from the OS. Used only when the store has no domain yet, so a restart
        // cannot change an identity that already exists.
        let mut entropy = [0u8; 16];
        if let Err(err) = getrandom::fill(&mut entropy) {
            fatal(&i18n::t(
                "error.server",
                &[("detail", &format!("randomness: {err}"))],
            ));
        }
        match rust_rest_ldap::sid::domain::Issuer::open(&backend, entropy) {
            Ok(issuer) => {
                println!("domain: {} (next RID {})", issuer.sid(), issuer.peek());
                Some(Arc::new(issuer))
            }
            Err(err) => fatal(&i18n::t("error.server", &[("detail", &err.to_string())])),
        }
    } else {
        None
    };

    let (source, directory) = match rust_rest_ldap::reload::Source::load(&config, backend).await {
        Ok(loaded) => loaded,
        Err(err) => fatal(&i18n::t("error.backend", &[("detail", &err.to_string())])),
    };
    // The same schema handle the source holds: a reload through the source has to reach
    // the write path, and a copy would make the two disagree after the first reload.
    // Read once, here: a keytab is a secret that belongs to root and to the service account, and
    // a failure to load it is a startup failure rather than a bind that mysteriously refuses.
    let gssapi = match rust_rest_ldap::sasl::Gssapi::load(&config.sasl, &config.base_dn) {
        Ok(gssapi) => gssapi.map(Arc::new),
        Err(err) => fatal(&i18n::t("error.sasl", &[("detail", &err.to_string())])),
    };
    if let Some(gssapi) = &gssapi {
        println!(
            "{}",
            i18n::t(
                "start.gssapi",
                &[("realms", &gssapi.realms().collect::<Vec<_>>().join(", "))]
            )
        );
    }

    #[cfg(feature = "kdc")]
    let security = match &domain {
        Some(domain) => Security::from_config(&config).with_domain(Arc::clone(domain)),
        None => Security::from_config(&config),
    };
    #[cfg(not(feature = "kdc"))]
    let security = Security::from_config(&config);

    let security = security
        .with_gssapi(gssapi)
        .with_schema(source.shared_schema())
        // The file backend stores a fixed user/group document and refuses a whole entry, so an
        // upgrade it cannot keep was attempted on every bind. Decided once, here.
        .with_password_upgrade(source.accepts_entry_upserts());

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
    // Said out loud, because a limit nobody knows about is discovered as a bug: an operator who
    // added it months ago, a client that pages for ever, and nothing on the server to explain it.
    // One line per limit that is set, so neither sentence has to say "unlimited".
    if security.limits.size_limit > 0 {
        println!(
            "{}",
            i18n::t(
                "start.limit_size",
                &[("size", &security.limits.size_limit.to_string())]
            )
        );
    }
    if let Some(budget) = security.limits.time_limit {
        println!(
            "{}",
            i18n::t(
                "start.limit_time",
                &[("seconds", &budget.as_secs().to_string())]
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
    metrics.set_entries(directory.entry_count());
    eprintln!(
        "PHASE directory rss={}MB entries={} index_bytes={}",
        rust_rest_ldap::memory::resident_bytes().unwrap_or(0) / (1024 * 1024),
        directory.entry_count(),
        directory.index().heap_bytes()
    );
    // The cache counters are the cache's own; the scrape reads them through here. Whether there is
    // a cache at all is decided by which path the load took, so this asks rather than assumes.
    if let Some(cache) = directory.cache() {
        metrics.attach_cache(Arc::clone(cache));
    }
    // Let go of the snapshot the load handed back. It is the same `Arc` the source keeps, and
    // holding one here is enough to make `Arc::get_mut` fail on every write - so every write
    // copied the whole directory instead of patching it in place. Measured on a million entries:
    // 2.8 s per modify, which is the price of a copy and not of a change.
    drop(directory);

    let journal = match (
        config.observability.journal_stdout,
        config.observability.journal.clone(),
    ) {
        (true, _) => {
            println!("{}", i18n::plain("start.journal_stdout"));
            Arc::new(rust_rest_ldap::metrics::Journal::stdout())
        }
        (false, Some(path)) => {
            let limit = config
                .observability
                .journal_max_bytes
                .unwrap_or(rust_rest_ldap::metrics::JOURNAL_MAX_BYTES);
            match rust_rest_ldap::metrics::Journal::file_with_limit(&path, limit) {
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
            }
        }
        (false, None) => Arc::new(rust_rest_ldap::metrics::Journal::off()),
    };

    let observers = rust_rest_ldap::server::Observers {
        metrics: Arc::clone(&metrics),
        journal,
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // CLDAP, when asked for: a Windows machine finds its controller by pinging UDP 389, and without
    // an answer here it reports that no controller could be found - which is routinely mistaken for
    // a Kerberos problem. The address is the same host as the TCP listener, port 389.
    let _cldap_task = if config.cldap.enabled {
        let port = config.cldap.port.unwrap_or(389);
        let bind = match listener.local_addr().map(|addr| addr.ip()) {
            Ok(std::net::IpAddr::V4(address)) => std::net::SocketAddr::from((address, port)),
            Ok(std::net::IpAddr::V6(address)) => std::net::SocketAddr::from((address, port)),
            Err(_) => std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
        };

        match rust_rest_ldap::cldap::Settings::resolve(&config.cldap, &config.base_dn, bind) {
            Err(detail) => fatal(&i18n::t("error.server", &[("detail", &detail)])),
            Ok(settings) => match tokio::net::UdpSocket::bind(bind).await {
                Ok(socket) => {
                    println!(
                        "cldap: answering pings on {bind} as {} ({}), kdc flag not set",
                        settings.advertised.dns_host, settings.advertised.netbios_host
                    );
                    Some(tokio::spawn(rust_rest_ldap::cldap::serve(
                        socket,
                        settings,
                        Arc::clone(&source),
                        Arc::clone(&metrics),
                        shutdown_rx.clone(),
                    )))
                }
                Err(err) => fatal(&i18n::t(
                    "error.server",
                    &[("detail", &format!("cldap '{bind}': {err}"))],
                )),
            },
        }
    } else {
        None
    };

    // The KDC, when asked for. It reads the realm out of the same directory this process serves, so
    // a password changed over LDAP is the key checked on the very next request; the one thing the
    // directory cannot give it is the realm's master password, and that is read once, on the first
    // start that has no `krbtgt` yet.
    #[cfg(feature = "kdc")]
    let _kdc = if config.kerberos.enabled {
        let ip = match listener.local_addr().map(|addr| addr.ip()) {
            Ok(ip) => ip,
            Err(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        };
        let settings = match rust_rest_ldap::kerberos::Settings::resolve(
            &config.kerberos,
            &config.base_dn,
            ip,
        ) {
            Ok(settings) => settings,
            Err(detail) => fatal(&i18n::t("error.server", &[("detail", &detail)])),
        };
        match rust_rest_ldap::kerberos::serve::start(
            &settings,
            Arc::clone(&source),
            config.base_dn.clone(),
            config.kerberos.master_key_file.as_deref(),
            shutdown_rx.clone(),
        )
        .await
        {
            Ok(running) => {
                // Said out loud because it is what a client is told to trust: the realm name is
                // what a machine is joined to, and a typo here costs an afternoon of "cannot
                // contact any KDC" before anybody reads this line.
                println!(
                    "kerberos: issuing tickets for {} on {} (tcp and udp)",
                    running.realm, running.bind
                );
                Some(running)
            }
            Err(detail) => fatal(&i18n::t("error.server", &[("detail", &detail)])),
        }
    } else {
        None
    };

    // SMB, when asked for. Port 445 is where a Samba member's join actually begins - an SMB
    // connection to `\\DC\IPC$` - and that was measured, not assumed: the stand fails inside
    // `libnet_join_connect_dc_ipc` before any RPC is spoken. Started after the KDC because a client
    // that reaches the share still needs the realm behind it, and before the listener accepts
    // because a machine that connects in the first moment must find it.
    #[cfg(feature = "smb")]
    let _smb = if config.smb.enabled {
        let ip = match listener.local_addr().map(|addr| addr.ip()) {
            Ok(ip) => ip,
            Err(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        };
        // The name CLDAP advertises, so that a client which found this server one way recognises it
        // by the other: two names for one server is how a machine joins a controller it cannot reach.
        let advertised = if config.cldap.enabled {
            config.cldap.netbios_host.as_deref()
        } else {
            None
        };
        // The DNS name is the naming context read as a domain, by the same rule the realm uses:
        // three answers - realm, CLDAP, lsarpc - that disagree is a client sent to a domain it
        // cannot reach.
        let mut smb_config = config.smb.clone();
        if smb_config.dns_domain.is_none() {
            smb_config.dns_domain = Some(
                config
                    .base_dn
                    .split(',')
                    .filter_map(|rdn| {
                        rdn.trim()
                            .strip_prefix("dc=")
                            .or_else(|| rdn.trim().strip_prefix("DC="))
                    })
                    .collect::<Vec<_>>()
                    .join("."),
            )
            .filter(|domain| domain.contains('.'));
        }
        match rust_rest_ldap::smb::Settings::resolve(&smb_config, ip, advertised) {
            Err(detail) => fatal(&i18n::t("error.server", &[("detail", &detail)])),
            Ok(mut settings) => {
                // The domain's SID, when this process issues one. `lsarpc` reports it beside the
                // domain's name, and a member's join stores it as the domain the machine belongs
                // to - so it comes from the issuer that already wrote the SIDs on the accounts,
                // not from the configuration.
                #[cfg(feature = "kdc")]
                if let Some(issuer) = &domain {
                    settings.domain_sid = Some(issuer.sid().to_bytes());
                }
                // The domain's NetBIOS name, by AD's own rule: the realm's first label, upper
                // case. This is the last place it can be stated explicitly; `Settings::resolve`
                // derives it from the DNS domain otherwise.
                if let Some(first) = config
                    .kerberos
                    .realm
                    .as_deref()
                    .and_then(|realm| realm.split('.').next())
                {
                    settings.domain_netbios = Some(first.to_ascii_uppercase());
                }
                match rust_rest_ldap::smb::serve::start(&settings).await {
                    Ok(running) => {
                        println!(
                            "smb: serving IPC$ as {} on {}",
                            running.netbios_name, running.bind
                        );
                        Some(running)
                    }
                    Err(detail) => fatal(&i18n::t("error.server", &[("detail", &detail)])),
                }
            }
        }
    } else {
        None
    };

    let reloading = tokio::spawn(rust_rest_ldap::reload::reload_on_interval_with(
        Arc::clone(&source),
        config.update_interval,
        shutdown_rx.clone(),
        Arc::clone(&metrics),
    ));

    // SIGUSR1 is the "reload now" switch gorestldap documented for systemd.
    spawn_usr1_reloader(Arc::clone(&source), Arc::clone(&metrics));
    spawn_usr2_schema_reloader(Arc::clone(&source));

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

    // One task per peer, each holding its own persistent connection. Spawned before the listener
    // accepts anything, so a change made here in the first moment of serving is not missed by a
    // peer that was already listening.
    let reporter = rust_rest_ldap::peers::Reporter::new(
        Arc::clone(&metrics),
        match &config.conflict_log {
            Some(path) => match rust_rest_ldap::metrics::Journal::file(path) {
                Ok(journal) => Arc::new(journal),
                Err(err) => fatal(&i18n::t(
                    "error.conflict_log",
                    &[
                        ("dn", &path.display().to_string()),
                        ("detail", &err.to_string()),
                    ],
                )),
            },
            None => Arc::new(rust_rest_ldap::metrics::Journal::off()),
        },
    );

    // Declared before anything is contacted, so a peer that never connects still has a series with
    // a zero in it - which is the case an operator most needs to see.
    reporter.register(&config.peers);

    let peer_tasks: Vec<tokio::task::JoinHandle<()>> = config
        .peers
        .iter()
        .map(|peer| {
            tokio::spawn(rust_rest_ldap::peers::follow(
                peer.clone(),
                Arc::clone(&source),
                config.base_dn.clone(),
                shutdown_tx.subscribe(),
                reporter.clone(),
            ))
        })
        .collect();

    let serving = tokio::spawn(rust_rest_ldap::server::serve_with(
        listener,
        rust_rest_ldap::server::Listener {
            acceptor,
            ldaps: config.use_tls,
            // Clients get this long to finish the operation they are in the middle of.
            grace: std::time::Duration::from_secs(10),
        },
        Arc::clone(&source),
        // The live policy remembers the configuration this process started with: that is
        // what lets a later change say which of its settings still wait for a restart.
        rust_rest_ldap::security::live(config.clone(), security),
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
    for task in peer_tasks {
        task.abort();
    }
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
                        // A full reload brings every record back into memory, so nothing is read
                        // through the cache any more and its counters would freeze at whatever they
                        // said. Reporting nothing is honest; reporting a stale number is not.
                        metrics.clear_cache();
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

/// SIGUSR2 re-reads the schema files and adopts them if the data still holds.
///
/// A separate signal from SIGUSR1 on purpose: reloading the data and reloading the rules are
/// different operations with different failure modes, and an operator debugging a schema
/// change does not want the directory reloaded underneath at the same time.
fn spawn_usr2_schema_reloader(source: Arc<rust_rest_ldap::reload::Source>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut usr2 = match signal(SignalKind::user_defined2()) {
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
            while usr2.recv().await.is_some() {
                match source.reload_schema().await {
                    Ok(done) => {
                        for warning in &done.warnings {
                            eprintln!("{}", i18n::t("warn.schema", &[("detail", warning)]));
                        }
                        println!(
                            "{}",
                            i18n::t(
                                "start.schema_reloaded",
                                &[
                                    ("attributes", &done.attributes.to_string()),
                                    ("classes", &done.classes.to_string()),
                                ],
                            )
                        );
                    }
                    // The old schema stays in force, and saying so is what stops an operator
                    // from believing the change took.
                    Err(err) => eprintln!(
                        "{}",
                        i18n::t("error.schema_reload", &[("detail", &err.to_string())])
                    ),
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
    // The file text is read here because the file is here; what to do with it is decided in
    // `i18n::resolve_language`, which takes the text and a probe instead of opening things.
    let config_text = args
        .config
        .as_ref()
        .and_then(|path| std::fs::read_to_string(path).ok());

    let (locale, source, file) = i18n::resolve_language(
        from_config,
        config_text.as_deref(),
        &|name| std::env::var(name).ok(),
        // `locale/<tag>.yaml` next to the working directory, then next to the executable.
        |tag| {
            let name = format!("locale/{tag}.yaml");
            let local = std::path::PathBuf::from(&name);
            if local.is_file() {
                return Some(local);
            }
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|dir| dir.join(&name)))
                .filter(|path| path.is_file())
        },
    );

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
/// Which store command the flags asked for, if any.
fn store_command(
    commit: bool,
    rollback: Option<u64>,
    history: bool,
) -> Option<rust_rest_ldap::config_store::Command> {
    use rust_rest_ldap::config_store::Command;

    if commit {
        return Some(Command::Commit);
    }
    if let Some(number) = rollback {
        return Some(Command::Rollback(number));
    }
    if history {
        return Some(Command::History);
    }
    None
}

/// Runs a store command and exits.
fn run_store_command(
    command: rust_rest_ldap::config_store::Command,
    path: &std::path::Path,
    keep: Option<usize>,
    note: Option<&str>,
    from: Option<&std::path::Path>,
) {
    let store = rust_rest_ldap::config_store::Store::open(path);

    let outcome = match command {
        rust_rest_ldap::config_store::Command::Commit => match from {
            // Seeding: the document comes from a file, and the store may be empty.
            Some(source) => std::fs::read_to_string(source)
                .map_err(|err| format!("'{}': {err}", source.display()))
                .and_then(|body| {
                    store
                        .commit(&body, "cli", note.unwrap_or_default())
                        .map_err(|err| err.to_string())
                }),
            None => store
                .commit_current("cli", note.unwrap_or_default())
                .map_err(|err| err.to_string()),
        }
        .map(|generation| format!("generation {}", generation.number)),
        rust_rest_ldap::config_store::Command::Rollback(number) => store
            .rollback(number, "cli")
            .map(|generation| format!("generation {}", generation.number))
            .map_err(|err| err.to_string()),
        rust_rest_ldap::config_store::Command::History => match store.history() {
            Ok(generations) => {
                let current = store.current().ok().flatten().map(|g| g.number);
                for generation in generations {
                    let mark = if Some(generation.number) == current {
                        "*"
                    } else {
                        " "
                    };
                    println!(
                        "{mark} {:>4}  {}  {:<24} {}",
                        generation.number, generation.created, generation.author, generation.note
                    );
                }
                return;
            }
            Err(err) => Err(err.to_string()),
        },
    };

    match outcome {
        Ok(what) => {
            // Collect as part of the commit: a store that only ever grew would be a store
            // somebody has to clean by hand, which is the problem this replaces.
            if let rust_rest_ldap::config_store::Command::Commit = command {
                let keep = keep.unwrap_or(rust_rest_ldap::config_store::KEEP);
                match store.collect(keep) {
                    Ok(removed) if removed.is_empty() => {}
                    Ok(removed) => println!(
                        "{}",
                        i18n::t(
                            "store.collected",
                            &[(
                                "numbers",
                                &removed
                                    .iter()
                                    .map(u64::to_string)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )]
                        )
                    ),
                    Err(err) => eprintln!(
                        "{}",
                        i18n::t("error.store", &[("detail", &err.to_string())])
                    ),
                }
            }

            println!("{}", i18n::t("store.done", &[("what", &what)]));
        }
        Err(detail) => fatal(&i18n::t("error.store", &[("detail", &detail)])),
    }
}
