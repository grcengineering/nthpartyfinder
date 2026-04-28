use crate::e2e::helpers::isolated_run;

#[test]
fn cache_list_empty_returns_zero() {
    let (mut cmd, _tmp) = isolated_run();
    cmd.args(["cache", "list"]).assert().success();
}

#[test]
fn cache_clear_all_succeeds_on_empty() {
    let (mut cmd, _tmp) = isolated_run();
    cmd.args(["cache", "clear", "--all"]).assert().success();
}

#[test]
fn cache_validate_runs_against_empty() {
    let (mut cmd, _tmp) = isolated_run();
    cmd.args(["cache", "validate"]).assert().success();
}
