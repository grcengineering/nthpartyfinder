// Allow dead code for public API functions that may not be used internally
// but are part of the library's exposed interface
#![allow(dead_code)]

pub mod cli;
pub mod config;
pub mod discovery;
pub mod dns;
pub mod whois;
pub mod export;
pub mod vendor;
pub mod domain_utils;
pub mod subprocessor;
pub mod verification_logger;
pub mod logger;
pub mod known_vendors;
pub mod web_org;
pub mod ner_org;
pub mod vendor_registry;
pub mod rate_limit;
pub mod cache_commands;
pub mod batch;
pub mod org_normalizer;
pub mod checkpoint;
pub mod trust_center;

pub use vendor::VendorRelationship;
pub use checkpoint::{Checkpoint, ResumeMode};

/// Create a headless Chrome browser instance.
/// Automatically disables sandbox when running inside a container
/// (detected via /.dockerenv or NTHPARTYFINDER_CONTAINER env var).
pub fn create_browser() -> anyhow::Result<headless_chrome::Browser> {
    let is_container = std::env::var("NTHPARTYFINDER_CONTAINER").is_ok()
        || std::path::Path::new("/.dockerenv").exists();

    if is_container {
        let options = headless_chrome::LaunchOptions::default_builder()
            .sandbox(false)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build Chrome launch options: {}", e))?;
        headless_chrome::Browser::new(options)
            .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome (container mode): {}", e))
    } else {
        headless_chrome::Browser::default()
            .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))
    }
}
