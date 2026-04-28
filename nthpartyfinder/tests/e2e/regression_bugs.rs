use crate::e2e::helpers::isolated_run;
use predicates::prelude::*;

#[test]
fn bug_012_dns_only_flag_documented_in_help() {
    let (mut cmd, _tmp) = isolated_run();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--dns-only"));
}

#[test]
#[ignore = "live-network; run with --ignored locally"]
fn bug_012_dns_only_disables_all_non_dns_discovery() {
    let (mut cmd, _tmp) = isolated_run();
    let output = cmd
        .args([
            "-d",
            "example.com",
            "--dns-only",
            "-r",
            "1",
            "-f",
            "json",
            "-o",
            "out",
            "-vv",
        ])
        .timeout(std::time::Duration::from_secs(45))
        .assert()
        .success()
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&output.stderr);
    for phrase in [
        "subprocessor",
        "headless",
        "subfinder",
        "ct logs",
        "saas tenant",
    ] {
        assert!(
            !stderr
                .to_lowercase()
                .contains(&format!("{phrase}: enabled"))
                && !stderr.to_lowercase().contains(&format!("running {phrase}")),
            "BUG-012 regression: {phrase} should be disabled by --dns-only"
        );
    }
}
