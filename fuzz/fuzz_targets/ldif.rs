//! Fuzz the LDIF reader: RFC 2849 text, which is a file an operator was handed.
//!
//! Line folding, base64 values, `changetype`, comments and the `-` separator all live here, and
//! an import is the one path where a stranger's file becomes the directory. A panic while
//! importing twenty thousand entries would lose the whole run at the last line.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = rrl_directory::ldif_read::parse(text);
    }
});
