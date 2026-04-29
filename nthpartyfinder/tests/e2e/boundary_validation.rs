use crate::e2e::helpers::isolated_run;
use predicates::prelude::*;
use std::fs;

#[test]
fn depth_zero_rejected_with_exit_2() {
    let (mut cmd, _tmp) = isolated_run();
    cmd.args(["-d", "example.com", "-r", "0"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--depth must be >= 1"));
}

#[test]
fn excess_parallelism_rejected_with_exit_2() {
    let (mut cmd, _tmp) = isolated_run();
    cmd.args(["-d", "example.com", "-j", "101"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--parallelism cannot exceed"));
}

#[test]
fn no_input_rejected_with_exit_2() {
    let (mut cmd, _tmp) = isolated_run();
    cmd.assert()
        .code(2)
        .stderr(predicate::str::contains("either -d <domain> or --input-file <file> is required"));
}

#[test]
fn batch_parallel_excess_rejected_with_exit_2() {
    let (mut cmd, tmp) = isolated_run();
    let csv = tmp.path().join("input.csv");
    fs::write(&csv, "domain\nexample.com\n").unwrap();
    cmd.arg("--input-file")
        .arg(&csv)
        .args(["--batch-parallel", "21"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--batch-parallel cannot exceed 20"));
}

#[test]
fn valid_depth_accepted() {
    let (mut cmd, _tmp) = isolated_run();
    cmd.args(["-d", "example.com", "-r", "1", "--help"])
        .assert()
        .success();
}

#[test]
fn valid_parallelism_accepted() {
    let (mut cmd, _tmp) = isolated_run();
    cmd.args(["-d", "example.com", "-j", "10", "--help"])
        .assert()
        .success();
}
