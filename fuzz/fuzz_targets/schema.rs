//! Fuzz the schema reader: RFC 4512 definitions, which a schema file carries.
//!
//! Parentheses, quoted descriptions, OIDs, `$`-separated MAY lists and escapes. Every definition
//! extends a schema the server then enforces, so a parser that panics on one bad line makes a
//! schema file into a denial of service - and the reload path is reachable over HTTP.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let mut schema = rrl_directory::schema::Schema::core();
        let _ = schema.extend(text);
    }
});
