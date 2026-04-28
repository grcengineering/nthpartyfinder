use crate::e2e::helpers::isolated_run;
use rstest::rstest;

#[rstest]
#[case("csv", "out.csv")]
#[case("json", "out.json")]
#[case("markdown", "out.md")]
#[case("html", "out.html")]
#[ignore = "live-network; run with --ignored locally"]
fn output_format_produces_expected_file(#[case] fmt: &str, #[case] file: &str) {
    let (mut cmd, tmp) = isolated_run();
    cmd.args([
        "-d",
        "example.com",
        "--dns-only",
        "-r",
        "1",
        "-f",
        fmt,
        "-o",
        "out",
    ])
    .timeout(std::time::Duration::from_secs(60))
    .assert()
    .success();
    assert!(tmp.path().join(file).exists(), "missing {:?}", file);
}

#[test]
#[ignore = "live-network; run with --ignored locally"]
fn html_report_contains_required_anchors() {
    let (mut cmd, tmp) = isolated_run();
    cmd.args([
        "-d",
        "example.com",
        "--dns-only",
        "-r",
        "1",
        "-f",
        "html",
        "-o",
        "report",
    ])
    .timeout(std::time::Duration::from_secs(60))
    .assert()
    .success();
    let html = std::fs::read_to_string(tmp.path().join("report.html")).unwrap();
    for marker in ["<title>", "</html>"] {
        assert!(html.contains(marker), "missing {marker}");
    }
}
