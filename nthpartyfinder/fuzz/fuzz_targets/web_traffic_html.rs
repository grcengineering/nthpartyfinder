#![no_main]
//! Fuzz resource-URL extraction from third-party HTML.
//!
//! `extract_external_domains_from_html` regex-scans `src`/`href` attributes out
//! of untrusted HTML, parses each with the `url` crate, and funnels the results
//! back through `extract_base_domain` — exercising both the regex pass and URL
//! parsing on adversarial markup.
use libfuzzer_sys::fuzz_target;
use nthpartyfinder::discovery::web_traffic;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = web_traffic::extract_external_domains_from_html(s, "example.com");
    }
});
