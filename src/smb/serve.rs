//! Port 445, in this process.
//!
//! The library carries the protocol and this carries the lifecycle: build it, bind it, stop it when
//! the daemon stops. Small on purpose - what matters here is that a failure to bind is a failure to
//! start rather than a port that is silently absent, because a client that cannot reach 445 reports
//! it as a domain controller it cannot find.

use super::Settings;

/// What a started server is.
///
/// `Debug` by hand rather than derived: the shutdown handle is a signal, not a value, and printing
/// it says nothing an operator can use. The address and the name do, and those are printed.
pub struct Running {
    /// Where it took the port.
    pub bind: std::net::SocketAddr,
    /// The name it answers to.
    pub netbios_name: String,
    /// Where `drsuapi` answers over `ncacn_ip_tcp`, and the task serving it.
    pub drsuapi: Option<(std::net::SocketAddr, tokio::task::JoinHandle<()>)>,
    /// Stops the accept loop and closes each connection.
    shutdown: smb_server::ShutdownHandle,
    /// The task running it.
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Running")
            .field("bind", &self.bind)
            .field("netbios_name", &self.netbios_name)
            .finish_non_exhaustive()
    }
}

impl Running {
    /// Asks the server to stop and waits for the task.
    ///
    /// Awaited rather than fired and forgotten: a daemon that exits while a machine still holds a
    /// connection leaves the client waiting for a reply that will never come, which it reports as a
    /// domain controller that stopped answering.
    pub async fn stop(self) {
        self.shutdown.shutdown();
        let _ = self.task.await;
    }
}

/// Starts SMB on `settings.bind`.
///
/// Only `IPC$`, which the library provides itself, and `share_listing` on because that is what makes
/// it serve the `srvsvc` pipe. A file share here would be a second path into a process whose access
/// rules are about tickets, not about files.
///
/// An empty static user list is deliberate: this server is reached with a Kerberos ticket from a
/// machine account, or with an NTLM logon against an account the directory owns (`logon_users`).
/// SMB's own configured passwords are for the file shares this deployment does not serve.
pub async fn start(
    settings: &Settings,
    machine_secrets: Option<std::sync::Arc<dyn smb_server::MachineSecrets>>,
    machine_passwords: Option<std::sync::Arc<dyn smb_server::MachinePasswords>>,
    logon_users: Option<std::sync::Arc<dyn smb_server::LogonUsers>>,
) -> Result<Running, String> {
    let mut builder = smb_server::SmbServer::builder()
        .listen(settings.bind)
        .netbios_name(settings.netbios_name.clone())
        .share_listing(true);

    if let Some(keytab) = &settings.keytab {
        builder = builder.keytab(keytab);
    }
    if let Some(domain) = &settings.dns_domain {
        builder = builder.dns_domain(domain.clone());
    }
    if let Some(sid) = &settings.domain_sid {
        builder = builder.domain_sid(sid.clone());
    }
    if let Some(name) = &settings.domain_netbios {
        builder = builder.domain_netbios(name.clone());
    }
    // The secure channel a member establishes after its account exists: `netr_ServerAuthenticate3`
    // checks the machine password against this and nothing else.
    if let Some(secrets) = machine_secrets {
        builder = builder.machine_secrets(secrets);
    }
    if let Some(passwords) = machine_passwords {
        builder = builder.machine_passwords(passwords);
    }
    // The accounts a client logs on with before it has a ticket: `Add-Computer` sends NTLM, because
    // the domain it is joining has not issued it one yet.
    if let Some(source) = logon_users {
        builder = builder.logon_users(source);
    }
    // The DES secure channel, when the deployment asks for it: off unless `smb.netlogon_des` says
    // otherwise, because that channel's credential is two passes of a 56-bit cipher.
    builder = builder.netlogon_des(settings.netlogon_des);

    // Passwords, when any are configured. Taken from the resolved settings rather than from the
    // environment here, so that a missing variable was already a startup error.
    for (name, password) in &settings.users {
        builder = builder.user(name.clone(), password.clone());
    }

    let server = builder
        .build()
        .map_err(|err| format!("smb '{}': {err}", settings.bind))?;

    // Bound before the accept loop starts, so that a port already in use is an error here rather
    // than a task that dies a moment later and a daemon that reports itself healthy.
    let bind = server
        .bind()
        .await
        .map_err(|err| format!("smb '{}': {err}", settings.bind))?;
    let shutdown = server.shutdown_handle();

    let task = tokio::spawn(async move {
        if let Err(err) = server.serve().await {
            eprintln!("smb: {err}");
        }
    });

    // `drsuapi` over `ncacn_ip_tcp`, when a port is stated: the endpoint the mapper names and a
    // join binds before it learns where its own account goes. Taken before answering the caller, so
    // a port already in use is this function's error and not a task that dies a second later.
    let drsuapi = match settings.drsuapi_tcp {
        None => None,
        Some(addr) => {
            let endpoint = smb_server::tcp::Endpoint {
                addr,
                nb_domain: settings
                    .domain_netbios
                    .clone()
                    .unwrap_or_else(|| settings.netbios_name.clone()),
                dns_domain: settings.dns_domain.clone().unwrap_or_default(),
                nb_computer: settings.netbios_name.clone(),
                dns_computer: settings.dns_domain.as_deref().map_or_else(
                    || settings.netbios_name.clone(),
                    |domain| {
                        format!(
                            "{}.{}",
                            settings.netbios_name.to_ascii_lowercase(),
                            domain.to_ascii_lowercase()
                        )
                    },
                ),
                // The same keytab SMB uses: a client's service ticket is for a principal this
                // server already holds keys for, and a second keytab would be a second answer to
                // one question.
                keytab: settings.keytab.clone(),
            };
            // A listener that cannot be taken is a startup failure naming the address, which is what
            // an operator can act on; the port is released again immediately, because the task
            // binds it for real and two listeners for one address must not exist even for a moment.
            std::net::TcpListener::bind(endpoint.addr)
                .and_then(|probe| probe.set_nonblocking(true))
                .map_err(|err| format!("drsuapi on {}: {err}", endpoint.addr))?;
            let task = tokio::spawn(async move {
                if let Err(err) = smb_server::tcp::serve(endpoint).await {
                    eprintln!("drsuapi: {err}");
                }
            });
            Some((addr, task))
        }
    };

    Ok(Running {
        bind,
        netbios_name: settings.netbios_name.clone(),
        drsuapi,
        shutdown,
        task,
    })
}
