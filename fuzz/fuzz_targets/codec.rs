//! Fuzz the BER framing: the first thing an outside client controls.
//!
//! A frame is `tag`, `length`, body, and the length may be short-form, long-form, or plainly
//! wrong. The parser must answer `Err` for all of it - a panic here is a server that a single
//! malformed packet can stop, before any authentication has happened.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The two entry points a connection uses: how much of the buffer is one message, and what
    // that message says. Both take bytes straight off the socket.
    let _ = rust_rest_ldap::ldap::codec::parse_header(data);
    let _ = rust_rest_ldap::ldap::codec::decode(data);
});
