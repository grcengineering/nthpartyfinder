#![no_main]
//! Fuzz the PSL pseudo-host / non-registrable classifier.
//!
//! `is_non_registrable_host` is the char-scan + PSL gate that decides whether a
//! discovered host is a real registrable vendor domain or a pseudo-host to drop
//! (e.g. `s3.amazonaws.com`, IP fragments). Fuzz it on adversarial hostnames.
use libfuzzer_sys::fuzz_target;
use nthpartyfinder::finalize;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = finalize::is_non_registrable_host(s);
    }
});
