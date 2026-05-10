// Allow dead code for public API functions that may not be used internally
// but are part of the library's exposed interface
#![allow(dead_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod analysis;
pub mod app;
pub mod batch;
pub mod browser_pool;
pub mod cache_commands;
pub mod checkpoint;
pub mod cli;
pub mod config;
pub mod dep_check;
pub mod discovery;
pub mod dns;
pub mod domain_utils;
pub mod export;
pub mod interactive;
pub mod known_vendors;
pub mod logger;
pub mod memory_monitor;
pub mod ner_org;
pub mod org_normalizer;
pub mod rate_limit;
pub mod result_sink;
pub mod subprocessor;
pub mod trust_center;
pub mod vendor;
pub mod vendor_registry;
pub mod verification_logger;
pub mod web_org;
pub mod whois;

pub use checkpoint::{Checkpoint, ResumeMode};
pub use vendor::VendorRelationship;
