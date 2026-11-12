//! Fuzz the search filter parser: RFC 4515 text from a client's search request.
//!
//! Nesting, escapes, `&`/`|` chains and unbalanced parentheses all arrive here. The parser must
//! answer `Err`, never panic and never recurse without a bound: a filter of ten thousand nested
//! parentheses is a stack overflow in a naive recursive descent, and a stack overflow in a
//! server is an abort.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser takes text, so invalid UTF-8 is not its business: the codec already refused
    // anything that is not a string. Filtering here keeps the corpus honest about what the
    // parser really receives.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = rrl_directory::ldap::filter_parse::parse(text);
    }
});
