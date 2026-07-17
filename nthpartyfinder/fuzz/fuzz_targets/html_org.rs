#![no_main]
//! Fuzz third-party HTML + JSON-LD organization extraction.
//!
//! `extract_organization_from_html` runs the `scraper`/`html5ever` parser over
//! untrusted page bodies and parses any embedded `application/ld+json`
//! Schema.org blocks as untrusted JSON — a rich adversarial-input surface.
use libfuzzer_sys::fuzz_target;
use nthpartyfinder::web_org;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = web_org::extract_organization_from_html(s, "example.com");
    }
});
