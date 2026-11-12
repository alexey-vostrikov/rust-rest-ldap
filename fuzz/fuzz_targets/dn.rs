//! Fuzz the DN normaliser: every operation carries a DN, including `unbind` and `abandon`.
//!
//! Multi-valued RDNs, escaped commas, quotes and bytes that are not valid UTF-8 all reach this
//! function before anything else looks at the request. It runs on every message, so a panic
//! here is the cheapest possible way to stop a server.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = rrl_directory::dn::normalize(text);
        let _ = rrl_directory::dn::is_valid(text);
        let _ = rrl_directory::dn::split_first_rdn(text);
    }
});
