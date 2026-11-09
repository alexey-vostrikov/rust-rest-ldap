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
/// An empty user list is deliberate: this server is reached with a Kerberos ticket from a machine
/// account, and SMB's own password list is for the shares this deployment does not serve.
pub async fn start(settings: &Settings) -> Result<Running, String> {
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

    Ok(Running {
        bind,
        netbios_name: settings.netbios_name.clone(),
        shutdown,
        task,
    })
}
