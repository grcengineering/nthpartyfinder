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
    fs::copy(src.join("nthpartyfinder.toml"), dst.join("nthpartyfinder.toml")).unwrap();

    // Copy vendor data files needed by vendor_registry::init()
    if src.join("known_vendors.json").exists() {
        fs::copy(src.join("known_vendors.json"), dst.join("known_vendors.json")).unwrap();
    }
    if src.join("saas_platforms.json").exists() {
        fs::copy(src.join("saas_platforms.json"), dst.join("saas_platforms.json")).unwrap();
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

/// REGRESSION TEST: When no config file exists and stdin is not a TTY
/// (assert_cmd pipes stdin), the binary must exit quickly with an error —
/// not block on a hidden interactive prompt behind the progress bar.
///
/// Before the fix, the progress bar started BEFORE config loading.
/// `prompt_create_config()` issued a "Create default config? [Y/n]" prompt
/// that was overwritten by the progress bar's steady-tick redraws, causing
/// the binary to appear stuck at "0% Initializing..." while silently
/// waiting on stdin.
#[test]
fn test_missing_config_exits_fast_not_hangs() {
    let tmp = TempDir::new().expect("create temp dir");

    // Run from a directory with NO config/ subdirectory.
    // The binary should detect missing config, see non-interactive stdin,
    // and exit with an error within the timeout.
    nthpartyfinder()
        .current_dir(tmp.path())
        .arg("--domain")
        .arg("example.com")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .failure()
        .stderr(predicate::str::contains("Configuration file not found").or(
            predicate::str::contains("Run with --init"),
        ));
}

/// Verify the error message includes actionable guidance.
#[test]
fn test_missing_config_suggests_init_flag() {
    let tmp = TempDir::new().expect("create temp dir");

    nthpartyfinder()
        .current_dir(tmp.path())
        .arg("--domain")
        .arg("example.com")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .failure()
        .stderr(predicate::str::contains("--init"));
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
        .stdout(predicate::str::contains("Created default configuration file"));

    assert!(config_path.exists(), "config file should have been created");

    // Verify it's valid TOML with expected sections
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("[http]"), "config should have [http] section");
    assert!(content.contains("[dns]"), "config should have [dns] section");
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

/// Verify that when config is missing, the error message appears without
/// any progress bar artifacts (no "Initializing..." in output).
/// This confirms config loading runs before the progress bar starts.
#[test]
fn test_config_error_before_progress_bar() {
    let tmp = TempDir::new().expect("create temp dir");

    let output = nthpartyfinder()
        .current_dir(tmp.path())
        .arg("--domain")
        .arg("example.com")
        .timeout(std::time::Duration::from_secs(10))
        .output()
        .expect("binary should run");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Config error should be present
    assert!(
        stderr.contains("Configuration file not found"),
        "should report missing config, got: {}",
        stderr
    );

    // Progress bar should NOT have started — no "Initializing..." in output
    assert!(
        !stderr.contains("Initializing..."),
        "progress bar should not start before config loads, got: {}",
        stderr
    );
}
