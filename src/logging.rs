//! The subscriber that makes `tracing` events visible.
//!
//! `rust-rest-ldap` emits `tracing` events throughout, and so does `smb-server` - but `tracing`
//! without a subscriber records nothing. That combination is worse than no logging at all: the
//! call sites look instrumented, the code reads as if it reports, and an operator watching the log
//! during a failure sees silence and concludes the failure happened elsewhere.
//!
//! That is not hypothetical. `net ads join` was refused with "the procedure number is out of
//! range" while `debug!` in the RPC dispatcher named neither the interface nor the opnum, because
//! no subscriber was installed and the macro compiled to nothing.
//!
//! # What it reads from the configuration
//!
//! `-d` / `--debug` sets the level, `log_timestamp` adds a timestamp to each line, `log_caller`
//! adds the module and line, and `--log <path>` sends the lines to a file instead of stderr. Those
//! keys were in the configuration and the command line before this module existed, and nothing
//! read them; a setting that parses and does nothing is a lie told to whoever wrote it down.
//!
//! `RUST_LOG` wins over `-d` when it is set, because the reason to reach for it is always a single
//! module that is misbehaving: `RUST_LOG=smb_server::rpc=debug` says more than a flag that raises
//! the level of the whole process.

use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Registry};

use crate::config::Config;

/// Where the lines go: a file the operator named, or stderr for the service manager to collect.
#[derive(Clone)]
enum Sink {
    File(Arc<Mutex<File>>),
    Stderr,
}

impl Sink {
    fn open(path: &Path) -> io::Result<Self> {
        Ok(Self::File(Arc::new(Mutex::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?,
        ))))
    }
}

/// Writes one event to the sink.
///
/// A writer per event rather than a lock held across the process: `tracing-subscriber` asks for a
/// writer each time, and the clone here copies an `Arc`, not a file descriptor - a `try_clone` per
/// log line would be a system call per log line.
struct SinkWriter(Sink);

impl Write for SinkWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &self.0 {
            Sink::Stderr => io::stderr().write(buf),
            Sink::File(file) => match file.lock() {
                Ok(mut file) => file.write(buf),
                // Poisoned only if a writer panicked while holding the lock. A line lost there
                // is better than a process that stops serving because it cannot log.
                Err(_) => Ok(buf.len()),
            },
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &self.0 {
            Sink::Stderr => io::stderr().flush(),
            Sink::File(file) => match file.lock() {
                Ok(mut file) => file.flush(),
                Err(_) => Ok(()),
            },
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
    type Writer = SinkWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SinkWriter(self.clone())
    }
}

/// Installs the subscriber for the rest of the process.
///
/// Returns the error rather than exiting: the caller decides whether it is fatal, and for `--log`
/// it is - an operator who asked for a file and silently got stderr would learn of the difference
/// during the incident the file existed for.
pub fn install(config: &Config) -> io::Result<()> {
    let filter = match std::env::var("RUST_LOG") {
        Ok(directive) if !directive.trim().is_empty() => EnvFilter::new(directive),
        _ => EnvFilter::new(if config.debug { "debug" } else { "info" }),
    };

    let sink = match &config.log_path {
        Some(path) => Sink::open(path)?,
        None => Sink::Stderr,
    };

    // Colour only where a person is looking. A file is read by `grep` and `less`, and an escape
    // sequence around every word makes both useless; the same applies to stderr redirected into a
    // service manager, which is why the terminal itself is asked rather than assumed.
    let ansi = config.log_path.is_none() && std::io::stderr().is_terminal();

    let layer = tracing_subscriber::fmt::layer()
        .with_writer(sink)
        .with_ansi(ansi)
        .with_target(config.log_caller);
    let layer = if config.log_timestamp {
        layer.with_timer(SystemTime).boxed()
    } else {
        layer.without_time().boxed()
    };

    Registry::default().with(filter).with(layer).init();
    Ok(())
}
