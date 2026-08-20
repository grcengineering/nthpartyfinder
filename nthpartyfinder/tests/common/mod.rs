//! Shared test-support modules for integration-test binaries that declare `mod common;`.
//!
//! Each `tests/*.rs` binary compiles this tree independently; binaries that never declare
//! `mod common;` do not pay for it. Keep every submodule hermetic (loopback-only, no live
//! network) — this tree exists to SIMULATE networks, never to touch one.

pub mod doh_farm;
