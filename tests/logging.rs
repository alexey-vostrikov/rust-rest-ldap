//! The subscriber exists, so an event a call site emits reaches a file.
//!
//! A test that only asserted "install returned Ok" would pass on an installation that records
//! nothing - which is exactly the state this module was written to end: `debug!` throughout the
//! code, silence in the log, and a refusal in the RPC dispatcher that named neither the interface
//! nor the opnum.
//!
//! One test per binary: `tracing` allows a global subscriber to be installed once, and a second
//! installation in the same process fails. This file is its own test binary, so the one install
//! here cannot collide with an install elsewhere.

use std::path::PathBuf;

use rrl_directory::config::{self, Args};

/// A configuration whose only purpose is to point the log at a file at debug level.
fn config(log: &std::path::Path, timestamp: bool, caller: bool) -> rrl_directory::config::Config {
    let text =
        format!("base_dn: dc=example,dc=com\nlog_timestamp: {timestamp}\nlog_caller: {caller}\n");
    let args = Args {
        log_path: Some(PathBuf::from(log)),
        debug: true,
        ..Default::default()
    };
    config::resolve(args, Some(&text), |_| None).expect("config")
}

#[test]
fn an_event_reaches_the_file_the_configuration_named() {
    let directory = tempfile::tempdir().expect("tempdir");
    let log = directory.path().join("rrd.log");

    // `log_caller` off so the line holds the message and not a path that a test would
    // accidentally be asserting instead.
    let config = config(&log, false, false);
    rrl_directory::logging::install(&config).expect("install");

    // One event at each level a caller uses: `info!` is what an operator reads by default,
    // `debug!` is what `-d` exists for, and a subscriber that installed but filtered debug out
    // would still pass a test that only checked the first.
    tracing::info!("the store is open");
    tracing::debug!(opnum = 44u16, "rpc call");

    // The writer is flushed per event, but the file is read through a fresh handle, so this
    // also proves the bytes reached the kernel rather than a buffer in this process.
    let contents = std::fs::read_to_string(&log).expect("log file");
    assert!(
        contents.contains("the store is open"),
        "-d did not raise the level to debug, or the file writer was not reached: {contents:?}"
    );
    assert!(
        contents.contains("opnum=44"),
        "an event's fields are part of the line, and a subscriber that dropped them would \
         report what happened without saying to what: {contents:?}"
    );
    // The first version of this test failed on the assertion above with escapes between `opnum`,
    // `=` and `44`: the subscriber was colouring a file. A file is read by `grep` and `less`.
    assert!(
        !contents.contains('\u{1b}'),
        "a log file holds no escape sequences: {contents:?}"
    );
}
