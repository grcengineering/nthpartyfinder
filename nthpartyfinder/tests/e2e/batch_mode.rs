use crate::e2e::helpers::isolated_run;
use std::fs;

#[test]
#[ignore = "live-network; run with --ignored locally"]
fn batch_mode_csv_input_produces_output() {
    let (mut cmd, tmp) = isolated_run();
    let csv = tmp.path().join("input.csv");
    fs::write(&csv, "domain\nexample.com\n").unwrap();
    cmd.arg("--input-file")
        .arg(&csv)
        .args(["--dns-only", "-r", "1", "--batch-parallel", "1"])
        .timeout(std::time::Duration::from_secs(120))
        .assert()
        .success();
}

#[test]
#[ignore = "live-network; run with --ignored locally"]
fn batch_combined_produces_single_report() {
    let (mut cmd, tmp) = isolated_run();
    let csv = tmp.path().join("input.csv");
    fs::write(&csv, "domain\nexample.com\n").unwrap();
    cmd.arg("--input-file")
        .arg(&csv)
        .args([
            "--dns-only",
            "-r",
            "1",
            "--batch-combined",
            "-f",
            "json",
            "-o",
            "combined",
        ])
        .timeout(std::time::Duration::from_secs(120))
        .assert()
        .success();
}
