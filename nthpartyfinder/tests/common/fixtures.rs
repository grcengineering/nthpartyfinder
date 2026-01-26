use std::path::PathBuf;
use serde::de::DeserializeOwned;

pub fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(relative)
}

pub fn load_fixture(relative: &str) -> String {
    std::fs::read_to_string(fixture_path(relative))
        .unwrap_or_else(|_| panic!("Failed to load fixture: {}", relative))
}

pub fn load_json_fixture<T: DeserializeOwned>(relative: &str) -> T {
    let content = load_fixture(relative);
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse JSON fixture {}: {}", relative, e))
}
