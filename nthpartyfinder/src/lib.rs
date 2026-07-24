// Allow dead code for public API functions that may not be used internally
// but are part of the library's exposed interface
#![allow(dead_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

/// Test-only support shared across modules.
///
/// `cargo test` runs tests in parallel threads within a single process, and environment variables
/// are process-global — so a test that `set_var`/`remove_var`s a variable and then asserts on the
/// resulting behavior races with any sibling that mutates the same variable. [`env_guard`] returns a
/// process-wide lock: every test that touches a process-global env var acquires it for the test's
/// duration, so no two such tests ever run concurrently. One global lock (not one per variable) also
/// serializes the underlying non-thread-safe `setenv`/`getenv` calls against each other.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard};

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// Acquire the process-wide environment lock for the duration of a test. Poison-tolerant: a
    /// panic in one env-mutating test must not wedge every other env-mutating test. The returned
    /// `MutexGuard` is itself `#[must_use]`, so a caller that forgets to bind it is warned.
    pub(crate) fn env_guard() -> MutexGuard<'static, ()> {
        ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub mod analysis;
pub mod app;
pub mod batch;
pub mod browser_install;
pub mod browser_pool;
pub mod cache_commands;
pub mod checkpoint;
pub mod cli;
pub mod config;
pub mod coverage;
pub mod dep_check;
pub mod dependencies;
pub mod discovery;
pub mod dns;
pub mod domain_utils;
pub mod export;
pub mod finalize;
pub mod http_client;
pub mod interactive;
pub mod known_vendors;
pub mod logger;
pub mod memory_monitor;
#[cfg(feature = "runtime-ner")]
pub mod model_fetch;
pub mod ner_org;
pub mod org_dataset;
pub mod org_normalizer;
pub mod org_role;
pub mod perf;
pub mod prefs;
pub mod rate_limit;
pub mod result_sink;
pub mod review;
pub mod subprocessor;
pub mod trust_center;
pub mod vendor;
pub mod vendor_registry;
pub mod verification_logger;
pub mod web_org;
pub mod whois;

pub use checkpoint::{Checkpoint, ResumeMode};
pub use vendor::VendorRelationship;
