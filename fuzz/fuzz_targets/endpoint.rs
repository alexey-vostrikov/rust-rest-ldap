//! Fuzz the service address parser: a URL from the configuration file.
//!
//! Not attacker-controlled the way a packet is, but it is text somebody typed, and a panic in
//! it would be a server that refuses to start with a stack trace instead of a message. The
//! interesting cases are the ones a URL grammar allows and a naive splitter does not: IPv6
//! literals, empty ports, prefixes with trailing slashes, credentials.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(endpoint) = rrl_directory::backend::http::Endpoint::parse(text) {
            // The parsed endpoint is used to build paths; a hostile address must not be able to
            // make that produce something that is not a request target.
            let _ = endpoint.target("/ldap/user");
            let _ = endpoint.target("");
            let _ = endpoint.authority();
        }
    }
});
