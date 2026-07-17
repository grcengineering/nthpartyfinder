#![no_main]
//! Fuzz the PSL-backed domain normalization funnel.
//!
//! `extract_base_domain` is the central registrable-domain extractor that
//! DNS/SPF discovery and web-traffic extraction both feed untrusted hostnames
//! into. A panic here is high blast-radius, so we exercise it plus the sibling
//! PSL classifiers on the same adversarial input.
use libfuzzer_sys::fuzz_target;
use nthpartyfinder::domain_utils;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = domain_utils::extract_base_domain(s);
        let _ = domain_utils::icann_suffix(s);
        let _ = domain_utils::registrable_label(s);
        let _ = domain_utils::normalize_for_dns_lookup(s);
        let _ = domain_utils::is_organizational_domain(s);
    }
});
