#![no_main]
//! Fuzz DNS TXT / SPF / DKIM / DMARC record parsing.
//!
//! `extract_vendor_domains_with_source` drives the backslash-unescaping,
//! SPF-macro stripping, and `include:`/`redirect=` capture logic over
//! attacker-controlled DNS TXT strings. Each fuzz-input line becomes one TXT
//! record so libFuzzer can explore multi-record inputs.
use libfuzzer_sys::fuzz_target;
use nthpartyfinder::dns;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let records: Vec<String> = s.split('\n').map(|line| line.to_string()).collect();
        let _ = dns::extract_vendor_domains_with_source(&records);
    }
});
