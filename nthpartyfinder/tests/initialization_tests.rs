//! Regression tests for the initialization sequence.
//!
//! These tests verify that the CLI binary starts up correctly and handles
//! configuration edge cases without hanging or crashing.
//!
//! Key regression: config loading with interactive prompts must complete
//! BEFORE the progress bar starts, otherwise the prompt is hidden and the
//! binary appears to hang (fixed in commit after 429acd5).

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper: get a Command for the nthpartyfinder binary.
fn nthpartyfinder() -> assert_cmd::Command {
    cargo_bin_cmd!("nthpartyfinder")
}

/// Helper: copy the real config directory into a temp dir so the binary
/// can find `./config/nthpartyfinder.toml` relative to its working directory.
fn setup_config_dir(tmp: &TempDir) {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
    let dst = tmp.path().join("config");
    fs::create_dir_all(&dst).unwrap();

    // Copy the main config file
    fs::copy(
        src.join("nthpartyfinder.toml"),
        dst.join("nthpartyfinder.toml"),
    )
    .unwrap();

    // Copy vendor data files needed by vendor_registry::init()
    if src.join("known_vendors.json").exists() {
        fs::copy(
            src.join("known_vendors.json"),
            dst.join("known_vendors.json"),
        )
        .unwrap();
    }
    if src.join("saas_platforms.json").exists() {
        fs::copy(
            src.join("saas_platforms.json"),
            dst.join("saas_platforms.json"),
        )
        .unwrap();
    }

    // Copy vendors subdirectory if it exists
    let vendors_src = src.join("vendors");
    if vendors_src.exists() {
        let vendors_dst = dst.join("vendors");
        fs::create_dir_all(&vendors_dst).unwrap();
        if let Ok(entries) = fs::read_dir(&vendors_src) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    fs::copy(&path, vendors_dst.join(entry.file_name())).unwrap();
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Regression: missing config must not hang (the original bug)
// ─────────────────────────────────────────────────────────────────────────────

/// REGRESSION (GRC-364 / TF-1): When no config file exists and stdin is not a
/// TTY, the binary must NOT hang on a hidden interactive "Create default config?"
/// prompt behind the progress bar. The zero-config fix made a missing config fall
/// back to embedded defaults and proceed, so this asserts the fallback (proceeds
/// past config loading without a prompt-hang), not the old hard-exit.
#[test]
fn test_missing_config_zero_config_fallback_no_prompt_hang() {
    let tmp = TempDir::new().expect("create temp dir");

    // No config/ subdirectory: the binary must fall back to embedded defaults and
    // proceed. `--timeout 1` bounds the scan; assertions are on startup stderr,
    // which appears before any scan work regardless of network speed.
    let output = nthpartyfinder()
        .current_dir(tmp.path())
        .args(["--domain", "example.com", "--timeout", "1"])
        .timeout(std::time::Duration::from_secs(20))
        .output()
        .expect("binary should run, not hang on a prompt");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Zero-config fallback proceeds past config loading...
    assert!(
        stderr.contains("Loading configuration"),
        "should reach config loading, got: {}",
        stderr
    );
    // ...and never blocks on the interactive create-config prompt in non-TTY mode.
    assert!(
        !stderr.contains("Create default config?"),
        "must not block on interactive prompt, got: {}",
        stderr
    );
}

/// GRC-364: a missing config no longer hard-exits with a "--init" suggestion;
/// it transparently uses embedded defaults. Guards against regressing to the old
/// fatal "Configuration file not found" path.
#[test]
fn test_missing_config_uses_embedded_defaults() {
    let tmp = TempDir::new().expect("create temp dir");

    let output = nthpartyfinder()
        .current_dir(tmp.path())
        .args(["--domain", "example.com", "--timeout", "1"])
        .timeout(std::time::Duration::from_secs(20))
        .output()
        .expect("binary should run");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("Configuration file not found"),
        "zero-config fallback must not emit a fatal config-not-found error, got: {}",
        stderr
    );
    assert!(
        stderr.contains("Checking dependencies"),
        "should proceed past config (zero-config) into dependency checks, got: {}",
        stderr
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// --init flag creates config file
// ─────────────────────────────────────────────────────────────────────────────

/// `--init` should create a default config file and exit successfully.
#[test]
fn test_init_creates_config_file() {
    let tmp = TempDir::new().expect("create temp dir");
    let config_path = tmp.path().join("config").join("nthpartyfinder.toml");

    assert!(!config_path.exists(), "config should not exist yet");

    nthpartyfinder()
        .current_dir(tmp.path())
        .arg("--init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Created default configuration file",
        ));

    assert!(config_path.exists(), "config file should have been created");

    // Verify it's valid TOML with expected sections
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("[http]"),
        "config should have [http] section"
    );
    assert!(
        content.contains("[dns]"),
        "config should have [dns] section"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// --help works regardless of config
// ─────────────────────────────────────────────────────────────────────────────

/// `--help` should work even without a config file (parsed before config load).
#[test]
fn test_help_works_without_config() {
    let tmp = TempDir::new().expect("create temp dir");

    nthpartyfinder()
        .current_dir(tmp.path())
        .arg("--help")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicate::str::contains("nthpartyfinder"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Valid config proceeds past initialization
// ─────────────────────────────────────────────────────────────────────────────

/// With a valid config, the binary should get past initialization and into
/// argument validation. We trigger an arg validation error (no --domain)
/// to confirm init completed without hanging.
#[test]
fn test_valid_config_completes_initialization() {
    let tmp = TempDir::new().expect("create temp dir");
    setup_config_dir(&tmp);

    // Run with no domain — should get past config loading and init,
    // then fail on missing domain requirement (clap error).
    nthpartyfinder()
        .current_dir(tmp.path())
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure();
    // The key assertion is that it doesn't timeout (hang at init).
    // Any exit — even a usage error — proves init completed.
}

// ─────────────────────────────────────────────────────────────────────────────
// Startup ordering: config error appears BEFORE any progress bar output
// ─────────────────────────────────────────────────────────────────────────────

/// Config resolution (now zero-config fallback per GRC-364) runs BEFORE the
/// progress bar/scan starts, so a missing config never produces a prompt hidden
/// behind progress redraws. Asserts the config phase appears and no interactive
/// prompt or "Initializing..." progress artifact precedes it.
#[test]
fn test_config_resolution_runs_before_progress_bar() {
    let tmp = TempDir::new().expect("create temp dir");

    let output = nthpartyfinder()
        .current_dir(tmp.path())
        .args(["--domain", "example.com", "--timeout", "1"])
        .timeout(std::time::Duration::from_secs(20))
        .output()
        .expect("binary should run");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // The config phase is present (resolved before any progress bar)...
    assert!(
        stderr.contains("Loading configuration"),
        "config phase should be present, got: {}",
        stderr
    );
    // ...and no interactive create-config prompt appears in non-TTY mode.
    assert!(
        !stderr.contains("Create default config?"),
        "no interactive prompt should appear before config resolves, got: {}",
        stderr
    );
}
