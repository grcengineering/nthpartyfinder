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

pub use vendor::VendorRelationship;
pub use checkpoint::{Checkpoint, ResumeMode};
