use crate::e2e::helpers::isolated_run;
use predicates::prelude::*;

#[test]
fn help_flag_shows_usage() {
    let (mut cmd, _tmp) = isolated_run();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("nthpartyfinder"));
}

#[test]
fn version_flag_shows_version() {
    let (mut cmd, _tmp) = isolated_run();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("1.0.0"));
}

#[test]
fn init_creates_default_config() {
    let (mut cmd, tmp) = isolated_run();
    cmd.arg("--init").assert().success();
    let cfg = tmp.path().join("config/nthpartyfinder.toml");
    assert!(cfg.exists(), "expected config at {:?}", cfg);
}

#[test]
#[ignore = "live-network; run with --ignored locally"]
fn dns_only_smoke_against_example_domain() {
    let (mut cmd, tmp) = isolated_run();
    cmd.args([
        "-d",
        "example.com",
        "--dns-only",
        "-r",
        "1",
        "-f",
        "json",
        "-o",
        "smoke",
    ])
    .timeout(std::time::Duration::from_secs(60))
    .assert()
    .success();
    let report = tmp.path().join("smoke.json");
    assert!(report.exists(), "expected report at {:?}", report);
}
