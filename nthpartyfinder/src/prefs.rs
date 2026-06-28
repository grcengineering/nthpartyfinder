//! User-level persisted preferences.
//!
//! Stored at the OS config dir — `~/Library/Application Support/nthpartyfinder/prefs.toml`
//! on macOS, `$XDG_CONFIG_HOME/nthpartyfinder/prefs.toml` on Linux, `%APPDATA%\nthpartyfinder\`
//! on Windows. These are opt-in settings that should survive across runs regardless of the
//! working directory (unlike `./config/nthpartyfinder.toml`, which is CWD-relative):
//!
//! - `ort_dylib_path` (#3) — absolute path to the ONNX Runtime library, persisted after a
//!   one-time download so future runs set `ORT_DYLIB_PATH` automatically without the user
//!   editing any shell profile.
//! - `analysis_timeout_secs` (#4) — a user-chosen default analysis timeout.
//! - `onboarded` (#4) — first-run marker so first-run prompts fire exactly once.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Prefs {
    /// Absolute path to the ONNX Runtime shared library. Set after a consent-gated
    /// download so subsequent runs export `ORT_DYLIB_PATH` themselves.
    pub ort_dylib_path: Option<String>,
    /// User-chosen default analysis timeout in seconds (`0` = disabled). `None` = use
    /// the built-in default (600s).
    pub analysis_timeout_secs: Option<u64>,
    /// True once the user has seen the first-run prompts, so they never re-fire.
    pub onboarded: bool,
}

impl Prefs {
    /// Path to the prefs file, or `None` if the OS exposes no config directory.
    pub fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("nthpartyfinder").join("prefs.toml"))
    }

    /// Load prefs from the default location. A missing file, an unreadable file, or a
    /// malformed file all degrade gracefully to defaults — prefs are never load-fatal.
    pub fn load() -> Prefs {
        match Self::path() {
            Some(p) => Self::load_from_path(&p),
            None => Prefs::default(),
        }
    }

    /// Load from an explicit path (testable seam). Missing/unreadable/malformed → defaults.
    pub fn load_from_path(path: &Path) -> Prefs {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
            Err(_) => Prefs::default(),
        }
    }

    /// Save prefs to the default location, creating the parent directory if needed.
    pub fn save(&self) -> Result<(), String> {
        let path = Self::path().ok_or_else(|| "no OS config directory available".to_string())?;
        self.save_to_path(&path)
    }

    /// Save to an explicit path (testable seam). Creates parent directories. Writing the
    /// whole file each time keeps it idempotent (no duplicate-append corruption).
    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {}", parent.display(), e))?;
        }
        let serialized =
            toml::to_string_pretty(self).map_err(|e| format!("serialize prefs: {}", e))?;
        // Atomic write: write a sibling temp file then rename() over the target. rename
        // is atomic on the same filesystem, so a crash/signal mid-write can never leave a
        // truncated prefs.toml that a future run would have to read.
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, serialized).map_err(|e| format!("write {}: {}", tmp.display(), e))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("rename into {}: {}", path.display(), e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_is_empty() {
        let p = Prefs::default();
        assert!(p.ort_dylib_path.is_none());
        assert!(p.analysis_timeout_secs.is_none());
        assert!(!p.onboarded);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nthpartyfinder").join("prefs.toml");
        let prefs = Prefs {
            ort_dylib_path: Some("/opt/onnx/libonnxruntime.dylib".to_string()),
            analysis_timeout_secs: Some(1800),
            onboarded: true,
        };
        prefs.save_to_path(&path).unwrap();
        assert!(path.exists(), "save must create the file (and parent dirs)");
        let loaded = Prefs::load_from_path(&path);
        assert_eq!(prefs, loaded);
    }

    #[test]
    fn load_missing_file_returns_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        assert_eq!(Prefs::load_from_path(&path), Prefs::default());
    }

    #[test]
    fn load_malformed_file_returns_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.toml");
        std::fs::write(&path, "this is not = valid = toml = [[[").unwrap();
        assert_eq!(Prefs::load_from_path(&path), Prefs::default());
    }

    #[test]
    fn save_is_idempotent_no_duplication() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.toml");
        let prefs = Prefs {
            ort_dylib_path: Some("/x/lib.dylib".to_string()),
            analysis_timeout_secs: None,
            onboarded: true,
        };
        prefs.save_to_path(&path).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        prefs.save_to_path(&path).unwrap();
        let second = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            first, second,
            "re-saving identical prefs must not grow/corrupt the file"
        );
    }

    #[test]
    fn partial_toml_fills_missing_with_defaults() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.toml");
        std::fs::write(&path, "onboarded = true\n").unwrap();
        let loaded = Prefs::load_from_path(&path);
        assert!(loaded.onboarded);
        assert!(loaded.ort_dylib_path.is_none());
        assert!(loaded.analysis_timeout_secs.is_none());
    }

    #[test]
    fn path_points_at_nthpartyfinder_prefs() {
        // On any platform with a config dir, the path ends with our app's prefs file.
        if let Some(p) = Prefs::path() {
            assert!(p.ends_with("nthpartyfinder/prefs.toml"));
        }
    }
}
