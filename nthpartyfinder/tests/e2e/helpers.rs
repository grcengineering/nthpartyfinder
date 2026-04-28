use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

#[allow(deprecated)]
pub fn cli() -> Command {
    Command::cargo_bin("nthpartyfinder").expect("binary built")
}

pub fn isolated_run() -> (Command, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let mut cmd = cli();
    cmd.current_dir(tmp.path())
        .arg("--output-dir")
        .arg(tmp.path())
        .env("NO_COLOR", "1");
    (cmd, tmp)
}

#[allow(dead_code)]
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}
