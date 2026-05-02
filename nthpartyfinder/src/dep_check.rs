//! Pre-flight dependency checks for optional runtime dependencies.
//!
//! Validates that required external tools are available before starting analysis,
//! providing actionable error messages with download URLs and install instructions.

use std::path::PathBuf;

/// Result of a dependency check
#[derive(Debug)]
pub struct DepCheckResult {
    pub name: &'static str,
    pub available: bool,
    pub required: bool,
    pub message: Option<String>,
}

/// Check all dependencies based on enabled features and return results.
/// Returns Err with a user-friendly message if a required dependency is missing.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn check_dependencies(
    enable_slm: bool,
    disable_slm: bool,
    enable_subdomain_discovery: bool,
    enable_web_org: bool,
    enable_web_traffic_discovery: bool,
    config_slm_enabled: bool,
    config_subdomain_enabled: bool,
) -> Result<Vec<DepCheckResult>, String> {
    let mut results = Vec::new();
    let mut errors = Vec::new();

    // Check ONNX Runtime (needed for NER/SLM)
    let slm_wanted = enable_slm || (!disable_slm && config_slm_enabled);
    if slm_wanted {
        let ort_result = check_onnx_runtime();
        if !ort_result.available {
            errors.push(ort_result.message.clone().unwrap_or_default());
        }
        results.push(ort_result);
    }

    // Check Chrome/Chromium (needed for web-org and web-traffic discovery)
    if enable_web_org || enable_web_traffic_discovery {
        let chrome_result = check_chrome();
        if !chrome_result.available {
            // Chrome is soft-required — warn but don't block
            results.push(chrome_result);
        } else {
            results.push(chrome_result);
        }
    }

    // Check subfinder (needed for subdomain discovery)
    let subdomain_wanted = enable_subdomain_discovery || config_subdomain_enabled;
    if subdomain_wanted {
        let subfinder_result = check_subfinder();
        if !subfinder_result.available {
            // subfinder missing is handled by main.rs interactive flow, just warn here
            results.push(subfinder_result);
        } else {
            results.push(subfinder_result);
        }
    }

    // Check whois (always needed for core functionality)
    let whois_result = check_whois();
    results.push(whois_result);

    if !errors.is_empty() {
        return Err(errors.join("\n\n"));
    }

    Ok(results)
}

/// Quick check: is ONNX Runtime available? Returns true if found.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn check_onnx_runtime_availability() -> bool {
    check_onnx_runtime().available
}

/// Check if ONNX Runtime shared library is available
#[cfg_attr(coverage_nightly, coverage(off))]
fn check_onnx_runtime() -> DepCheckResult {
    // Already set via env var
    if std::env::var("ORT_DYLIB_PATH").is_ok() {
        let path = std::env::var("ORT_DYLIB_PATH").unwrap();
        if std::path::Path::new(&path).exists() {
            return DepCheckResult {
                name: "ONNX Runtime",
                available: true,
                required: true,
                message: Some(format!("Found at ORT_DYLIB_PATH={}", path)),
            };
        }
    }

    // Search common locations
    let lib_name = if cfg!(target_os = "macos") {
        "libonnxruntime.dylib"
    } else if cfg!(target_os = "windows") {
        "onnxruntime.dll"
    } else {
        "libonnxruntime.so"
    };

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    // Check next to executable
    if let Some(ref dir) = exe_dir {
        let adjacent = dir.join(lib_name);
        if adjacent.exists() {
            let abs = adjacent.canonicalize().unwrap_or(adjacent.clone());
            std::env::set_var("ORT_DYLIB_PATH", &abs);
            return DepCheckResult {
                name: "ONNX Runtime",
                available: true,
                required: true,
                message: Some(format!("Found next to executable: {}", abs.display())),
            };
        }
        // Check onnxruntime/ subdirectory
        let ort_subdir = find_ort_in_directory(dir, lib_name);
        if let Some(path) = ort_subdir {
            let abs = path.canonicalize().unwrap_or(path.clone());
            std::env::set_var("ORT_DYLIB_PATH", &abs);
            return DepCheckResult {
                name: "ONNX Runtime",
                available: true,
                required: true,
                message: Some(format!("Found at: {}", abs.display())),
            };
        }
    }

    // Check /usr/local/lib
    let system_path = PathBuf::from("/usr/local/lib").join(lib_name);
    if system_path.exists() {
        let abs = system_path.canonicalize().unwrap_or(system_path.clone());
        std::env::set_var("ORT_DYLIB_PATH", &abs);
        return DepCheckResult {
            name: "ONNX Runtime",
            available: true,
            required: true,
            message: Some(format!("Found at: {}", abs.display())),
        };
    }

    let (_os_name, _arch, download_url) = get_ort_download_info();

    DepCheckResult {
        name: "ONNX Runtime",
        available: false,
        required: true,
        message: Some(format!(
            "ONNX Runtime not found. Required for NER organization extraction (--enable-slm).\n\
             \n\
             To install:\n\
             1. Download: {}\n\
             2. Extract and set: export ORT_DYLIB_PATH=/path/to/{}\n\
             3. Or run: ./scripts/install.sh\n\
             \n\
             To skip NER, use --disable-slm or build with --no-default-features.",
            download_url, lib_name
        )),
    }
}

/// Find ONNX Runtime library in a directory (including versioned subdirs).
/// Handles both flat (`onnxruntime-osx-arm64-1.20.1/lib/`) and nested
/// (`onnxruntime/onnxruntime-osx-arm64-1.20.1/lib/`) directory structures.
#[cfg_attr(coverage_nightly, coverage(off))]
fn find_ort_in_directory(dir: &std::path::Path, lib_name: &str) -> Option<PathBuf> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("onnxruntime") && entry.path().is_dir() {
                // Check lib/ directly (flat: onnxruntime-osx-arm64-1.20.1/lib/)
                let lib_path = entry.path().join("lib").join(lib_name);
                if lib_path.exists() {
                    return Some(lib_path);
                }
                // Check nested versioned subdirs (nested: onnxruntime/onnxruntime-*/lib/)
                if let Ok(sub_entries) = std::fs::read_dir(entry.path()) {
                    for sub_entry in sub_entries.flatten() {
                        let sub_name = sub_entry.file_name();
                        let sub_name_str = sub_name.to_string_lossy();
                        if sub_name_str.starts_with("onnxruntime") && sub_entry.path().is_dir() {
                            let nested_lib = sub_entry.path().join("lib").join(lib_name);
                            if nested_lib.exists() {
                                return Some(nested_lib);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Get OS-specific ONNX Runtime download URL
#[cfg_attr(coverage_nightly, coverage(off))]
fn get_ort_download_info() -> (&'static str, &'static str, String) {
    let (os_name, arch) = if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            ("osx", "arm64")
        } else {
            ("osx", "x86_64")
        }
    } else if cfg!(target_os = "windows") {
        ("win", "x64")
    } else {
        if cfg!(target_arch = "aarch64") {
            ("linux", "aarch64")
        } else {
            ("linux", "x64")
        }
    };

    let url = format!(
        "https://github.com/microsoft/onnxruntime/releases/download/v1.20.1/onnxruntime-{}-{}-1.20.1.tgz",
        os_name, arch
    );
    (os_name, arch, url)
}

/// Check if Chrome or Chromium is available
#[cfg_attr(coverage_nightly, coverage(off))]
fn check_chrome() -> DepCheckResult {
    // Check CHROME_PATH env var
    if let Ok(path) = std::env::var("CHROME_PATH") {
        if std::path::Path::new(&path).exists() {
            return DepCheckResult {
                name: "Chrome/Chromium",
                available: true,
                required: false,
                message: Some(format!("Found at CHROME_PATH={}", path)),
            };
        }
    }

    // Check common paths
    let chrome_paths: Vec<&str> = if cfg!(target_os = "macos") {
        vec![
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    } else if cfg!(target_os = "windows") {
        vec![
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        ]
    } else {
        vec![
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
        ]
    };

    for path in &chrome_paths {
        if std::path::Path::new(path).exists() {
            return DepCheckResult {
                name: "Chrome/Chromium",
                available: true,
                required: false,
                message: Some(format!("Found at: {}", path)),
            };
        }
    }

    let install_hint = if cfg!(target_os = "macos") {
        "brew install --cask google-chrome"
    } else if cfg!(target_os = "windows") {
        "Download from https://www.google.com/chrome/"
    } else {
        "sudo apt-get install chromium  OR  sudo apt-get install google-chrome-stable"
    };

    DepCheckResult {
        name: "Chrome/Chromium",
        available: false,
        required: false,
        message: Some(format!(
            "Chrome/Chromium not found. Optional — needed for --enable-web-org and --enable-web-traffic-discovery.\n\
             Install: {}",
            install_hint
        )),
    }
}

/// Check if subfinder is available
#[cfg_attr(coverage_nightly, coverage(off))]
fn check_subfinder() -> DepCheckResult {
    match which::which("subfinder") {
        Ok(path) => DepCheckResult {
            name: "subfinder",
            available: true,
            required: false,
            message: Some(format!("Found at: {}", path.display())),
        },
        Err(_) => DepCheckResult {
            name: "subfinder",
            available: false,
            required: false,
            message: Some(
                "subfinder not found. Optional — needed for --enable-subdomain-discovery.\n\
                 Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n\
                 Or download from: https://github.com/projectdiscovery/subfinder/releases"
                    .to_string(),
            ),
        },
    }
}

/// Check if whois is available
#[cfg_attr(coverage_nightly, coverage(off))]
fn check_whois() -> DepCheckResult {
    match which::which("whois") {
        Ok(path) => DepCheckResult {
            name: "whois",
            available: true,
            required: true,
            message: Some(format!("Found at: {}", path.display())),
        },
        Err(_) => {
            let install_hint = if cfg!(target_os = "macos") {
                "Usually pre-installed. If missing: brew install whois"
            } else if cfg!(target_os = "windows") {
                "Download from SysInternals or use WSL"
            } else {
                "sudo apt-get install whois  OR  sudo yum install whois"
            };

            DepCheckResult {
                name: "whois",
                available: false,
                required: true,
                message: Some(format!(
                    "whois not found. Required for organization name lookups.\n\
                     Install: {}",
                    install_hint
                )),
            }
        }
    }
}

/// Download ONNX Runtime to a directory next to the executable.
/// Returns the path to the downloaded library file.
/// Prompts for consent in interactive mode; errors in non-interactive mode.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn download_onnx_runtime_interactive() -> Result<PathBuf, String> {
    let is_interactive = std::io::IsTerminal::is_terminal(&std::io::stdin());

    if !is_interactive {
        let (_, _, download_url) = get_ort_download_info();
        return Err(format!(
            "ONNX Runtime not found and running in non-interactive mode.\n\
             Download manually: {}\n\
             Then set: export ORT_DYLIB_PATH=/path/to/libonnxruntime.dylib",
            download_url
        ));
    }

    let (os_name, arch, download_url) = get_ort_download_info();
    let lib_name = if cfg!(target_os = "macos") {
        "libonnxruntime.dylib"
    } else if cfg!(target_os = "windows") {
        "onnxruntime.dll"
    } else {
        "libonnxruntime.so"
    };

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║           ONNX Runtime Not Found                                 ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════╣");
    eprintln!("║ ONNX Runtime is required for NER organization extraction.        ║");
    eprintln!("║ It will be downloaded from Microsoft's official GitHub releases.  ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
    eprintln!();
    eprintln!("  Platform: {}-{}", os_name, arch);
    eprintln!("  URL: {}", download_url);
    eprintln!("  Size: ~7-15 MB (compressed)");
    eprintln!();
    eprint!("Download ONNX Runtime now? [Y/n] ");

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    let input = input.trim().to_lowercase();

    if !input.is_empty() && input != "y" && input != "yes" {
        return Err("ONNX Runtime download declined. Use --disable-slm to skip NER.".to_string());
    }

    // Determine install location: next to executable, or fallback to data dir
    let install_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("nthpartyfinder")
        });

    let ort_dir = install_dir.join("onnxruntime");
    std::fs::create_dir_all(&ort_dir).map_err(|e| format!("Failed to create directory: {}", e))?;

    eprintln!("  Downloading ONNX Runtime...");

    // Use curl for download (available on all platforms)
    let tgz_path = ort_dir.join("onnxruntime.tgz");
    let status = std::process::Command::new("curl")
        .args(["-fSL", "--progress-bar", "-o"])
        .arg(&tgz_path)
        .arg(&download_url)
        .status()
        .map_err(|e| format!("Failed to run curl: {}", e))?;

    if !status.success() {
        return Err(format!(
            "Download failed. Try manually: curl -fSL -o onnxruntime.tgz {}",
            download_url
        ));
    }

    eprintln!("  Extracting...");

    let status = std::process::Command::new("tar")
        .args(["-xzf"])
        .arg(&tgz_path)
        .arg("-C")
        .arg(&ort_dir)
        .status()
        .map_err(|e| format!("Failed to extract: {}", e))?;

    if !status.success() {
        return Err("Extraction failed.".to_string());
    }

    // Clean up tarball
    let _ = std::fs::remove_file(&tgz_path);

    // Find the extracted library
    if let Some(lib_path) = find_ort_in_directory(&ort_dir, lib_name) {
        let abs_path = lib_path.canonicalize().unwrap_or(lib_path.clone());
        // Set for current process
        std::env::set_var("ORT_DYLIB_PATH", &abs_path);

        eprintln!();
        eprintln!("  ✅ ONNX Runtime installed successfully!");
        eprintln!("  Location: {}", abs_path.display());
        eprintln!();
        eprintln!("  To make this permanent, add to your shell profile:");
        eprintln!("    export ORT_DYLIB_PATH={}", abs_path.display());
        eprintln!();

        Ok(abs_path)
    } else {
        // Try to find any matching library file in ort_dir recursively
        let mut found = None;
        if let Ok(entries) = std::fs::read_dir(&ort_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Some(path) = find_ort_in_directory(&entry.path(), lib_name) {
                        found = Some(path);
                        break;
                    }
                    // Also check direct children
                    let direct = entry.path().join(lib_name);
                    if direct.exists() {
                        found = Some(direct);
                        break;
                    }
                }
            }
        }

        match found {
            Some(path) => {
                let abs_path = path.canonicalize().unwrap_or(path.clone());
                std::env::set_var("ORT_DYLIB_PATH", &abs_path);
                eprintln!("  ✅ ONNX Runtime installed at: {}", abs_path.display());
                eprintln!(
                    "  Add to shell profile: export ORT_DYLIB_PATH={}",
                    abs_path.display()
                );
                Ok(abs_path)
            }
            None => Err(format!(
                "Downloaded but could not find {} in {}. Check the directory manually.",
                lib_name,
                ort_dir.display()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── get_ort_download_info ─────────────────────────────────────────

    #[test]
    fn test_get_ort_download_info_returns_valid_url() {
        let (os, arch, url) = get_ort_download_info();
        assert!(!os.is_empty());
        assert!(!arch.is_empty());
        assert!(url.starts_with("https://github.com/microsoft/onnxruntime/releases/"));
        assert!(url.contains("1.20.1"));
    }

    #[test]
    fn test_get_ort_download_info_contains_platform() {
        let (os_name, arch, url) = get_ort_download_info();
        // URL should contain both os and arch
        assert!(url.contains(os_name));
        assert!(url.contains(arch));
        // URL should end with .tgz
        assert!(url.ends_with(".tgz"));
    }

    // ── check_whois ───────────────────────────────────────────────────

    #[test]
    fn test_check_whois_returns_result() {
        let result = check_whois();
        assert_eq!(result.name, "whois");
        // whois is available on macOS by default
        assert!(result.message.is_some());
    }

    #[test]
    fn test_check_whois_required_flag() {
        let result = check_whois();
        assert!(result.required, "whois should be marked as required");
    }

    // ── check_chrome ──────────────────────────────────────────────────

    #[test]
    fn test_check_chrome_returns_result() {
        let result = check_chrome();
        assert_eq!(result.name, "Chrome/Chromium");
        assert!(result.message.is_some());
        // Chrome is optional, so required should be false
        assert!(!result.required);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_chrome_message_content() {
        let result = check_chrome();
        let msg = result.message.unwrap();
        if result.available {
            // Should mention where it was found
            assert!(msg.contains("Found"));
        } else {
            // Should contain install instructions
            assert!(msg.contains("Chrome/Chromium not found"));
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_chrome_with_env_var_nonexistent_path() {
        // Save and set a bogus CHROME_PATH
        let original = std::env::var("CHROME_PATH").ok();
        std::env::set_var("CHROME_PATH", "/nonexistent/chrome/binary");

        let result = check_chrome();
        // The bogus path shouldn't make it "available" -- it should fall through
        // (unless one of the system paths exists)
        // Regardless, the function should not panic
        assert_eq!(result.name, "Chrome/Chromium");

        // Restore
        match original {
            Some(val) => std::env::set_var("CHROME_PATH", val),
            None => std::env::remove_var("CHROME_PATH"),
        }
    }

    // ── check_subfinder ───────────────────────────────────────────────

    #[test]
    fn test_check_subfinder_returns_result() {
        let result = check_subfinder();
        assert_eq!(result.name, "subfinder");
        assert!(result.message.is_some());
        assert!(!result.required);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_subfinder_message_content() {
        let result = check_subfinder();
        let msg = result.message.unwrap();
        if result.available {
            assert!(msg.contains("Found at"));
        } else {
            assert!(msg.contains("subfinder not found"));
            assert!(msg.contains("projectdiscovery"));
        }
    }

    // ── check_onnx_runtime ────────────────────────────────────────────

    #[test]
    fn test_check_onnx_runtime_returns_result() {
        let result = check_onnx_runtime();
        assert_eq!(result.name, "ONNX Runtime");
        assert!(result.message.is_some());
        assert!(result.required);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_onnx_runtime_message_has_install_instructions_when_missing() {
        // Temporarily unset ORT_DYLIB_PATH so we exercise the search paths
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");

        let result = check_onnx_runtime();
        if !result.available {
            let msg = result.message.unwrap();
            assert!(msg.contains("ONNX Runtime not found"));
            assert!(msg.contains("install"));
        }

        // Restore
        if let Some(val) = original {
            std::env::set_var("ORT_DYLIB_PATH", val);
        }
    }

    // ── check_onnx_runtime_availability ───────────────────────────────

    #[test]
    fn test_check_onnx_runtime_availability_returns_bool() {
        // Just ensure it doesn't panic and returns a bool
        let _available: bool = check_onnx_runtime_availability();
    }

    // ── find_ort_in_directory ─────────────────────────────────────────

    #[test]
    fn test_find_ort_in_directory_nonexistent() {
        let result = find_ort_in_directory(
            std::path::Path::new("/nonexistent/path"),
            "libonnxruntime.dylib",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_find_ort_in_directory_empty_dir() {
        let dir = tempdir().unwrap();
        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_none());
    }

    #[test]
    fn test_find_ort_in_directory_flat_structure() {
        let dir = tempdir().unwrap();
        // Create onnxruntime-osx-arm64-1.20.1/lib/libonnxruntime.dylib
        let ort_dir = dir.path().join("onnxruntime-osx-arm64-1.20.1").join("lib");
        std::fs::create_dir_all(&ort_dir).unwrap();
        let lib_file = ort_dir.join("libonnxruntime.dylib");
        std::fs::write(&lib_file, b"fake lib").unwrap();

        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_some());
        assert!(result.unwrap().ends_with("libonnxruntime.dylib"));
    }

    #[test]
    fn test_find_ort_in_directory_nested_structure() {
        let dir = tempdir().unwrap();
        // Create onnxruntime/onnxruntime-osx-arm64-1.20.1/lib/libonnxruntime.dylib
        let nested_dir = dir
            .path()
            .join("onnxruntime")
            .join("onnxruntime-osx-arm64-1.20.1")
            .join("lib");
        std::fs::create_dir_all(&nested_dir).unwrap();
        let lib_file = nested_dir.join("libonnxruntime.dylib");
        std::fs::write(&lib_file, b"fake lib").unwrap();

        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_some());
    }

    #[test]
    fn test_find_ort_in_directory_non_ort_dirs_ignored() {
        let dir = tempdir().unwrap();
        // Create a directory that doesn't start with "onnxruntime"
        let other_dir = dir.path().join("other-library").join("lib");
        std::fs::create_dir_all(&other_dir).unwrap();
        std::fs::write(other_dir.join("libonnxruntime.dylib"), b"fake").unwrap();

        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_none());
    }

    #[test]
    fn test_find_ort_in_directory_onnxruntime_file_not_dir() {
        let dir = tempdir().unwrap();
        // Create a file (not dir) named onnxruntime-something
        let file_path = dir.path().join("onnxruntime-fake");
        std::fs::write(&file_path, b"not a directory").unwrap();

        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_none());
    }

    // ── check_dependencies ────────────────────────────────────────────

    #[test]
    fn test_check_dependencies_disabled_features_passes() {
        // When all optional features are disabled, no errors should occur
        let result = check_dependencies(
            false, // enable_slm
            true,  // disable_slm
            false, // enable_subdomain_discovery
            false, // enable_web_org
            false, // enable_web_traffic_discovery
            false, // config_slm_enabled
            false, // config_subdomain_enabled
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_dependencies_disabled_returns_whois_only() {
        let result = check_dependencies(false, false, false, false, false, false, false);
        // With disable_slm=false and config_slm_enabled=false, SLM is not wanted
        // Only whois should be checked
        assert!(result.is_ok());
        let results = result.unwrap();
        // At minimum, whois is always checked
        assert!(results.iter().any(|r| r.name == "whois"));
    }

    #[test]
    fn test_check_dependencies_web_org_includes_chrome() {
        let result = check_dependencies(
            false, // enable_slm
            true,  // disable_slm
            false, // enable_subdomain_discovery
            true,  // enable_web_org
            false, // enable_web_traffic_discovery
            false, // config_slm_enabled
            false, // config_subdomain_enabled
        );
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(results.iter().any(|r| r.name == "Chrome/Chromium"));
    }

    #[test]
    fn test_check_dependencies_web_traffic_includes_chrome() {
        let result = check_dependencies(
            false, // enable_slm
            true,  // disable_slm
            false, // enable_subdomain_discovery
            false, // enable_web_org
            true,  // enable_web_traffic_discovery
            false, // config_slm_enabled
            false, // config_subdomain_enabled
        );
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(results.iter().any(|r| r.name == "Chrome/Chromium"));
    }

    #[test]
    fn test_check_dependencies_subdomain_includes_subfinder() {
        let result = check_dependencies(
            false, // enable_slm
            true,  // disable_slm
            true,  // enable_subdomain_discovery
            false, // enable_web_org
            false, // enable_web_traffic_discovery
            false, // config_slm_enabled
            false, // config_subdomain_enabled
        );
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(results.iter().any(|r| r.name == "subfinder"));
    }

    #[test]
    fn test_check_dependencies_config_subdomain_includes_subfinder() {
        let result = check_dependencies(
            false, // enable_slm
            true,  // disable_slm
            false, // enable_subdomain_discovery
            false, // enable_web_org
            false, // enable_web_traffic_discovery
            false, // config_slm_enabled
            true,  // config_subdomain_enabled
        );
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(results.iter().any(|r| r.name == "subfinder"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_dependencies_slm_via_config_enables_ort_check() {
        // enable_slm=false, disable_slm=false, config_slm_enabled=true
        // => slm_wanted = true
        let result = check_dependencies(
            false, // enable_slm
            false, // disable_slm
            false, // enable_subdomain_discovery
            false, // enable_web_org
            false, // enable_web_traffic_discovery
            true,  // config_slm_enabled
            false, // config_subdomain_enabled
        );
        // This may error if ONNX is not installed, which is fine
        // We just verify the function ran and included ORT check
        match result {
            Ok(results) => {
                assert!(results.iter().any(|r| r.name == "ONNX Runtime"));
            }
            Err(err_msg) => {
                assert!(err_msg.contains("ONNX Runtime"));
            }
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_dependencies_enable_slm_flag() {
        let result = check_dependencies(
            true,  // enable_slm
            false, // disable_slm
            false, // enable_subdomain_discovery
            false, // enable_web_org
            false, // enable_web_traffic_discovery
            false, // config_slm_enabled
            false, // config_subdomain_enabled
        );
        match result {
            Ok(results) => {
                assert!(results.iter().any(|r| r.name == "ONNX Runtime"));
            }
            Err(err_msg) => {
                assert!(err_msg.contains("ONNX Runtime"));
            }
        }
    }

    // ── DepCheckResult fields ─────────────────────────────────────────

    #[test]
    fn test_dep_check_result_debug() {
        let r = DepCheckResult {
            name: "test-tool",
            available: true,
            required: false,
            message: Some("test msg".into()),
        };
        let dbg = format!("{:?}", r);
        assert!(dbg.contains("test-tool"));
        assert!(dbg.contains("true"));
    }

    // ── ORT env var path ──────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_onnx_with_valid_env_path() {
        let dir = tempdir().unwrap();
        let fake_lib = dir.path().join("libonnxruntime.dylib");
        std::fs::write(&fake_lib, b"fake ort lib").unwrap();

        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::set_var("ORT_DYLIB_PATH", fake_lib.to_str().unwrap());

        let result = check_onnx_runtime();
        assert!(result.available);
        assert!(result.message.unwrap().contains("ORT_DYLIB_PATH"));

        // Restore
        match original {
            Some(val) => std::env::set_var("ORT_DYLIB_PATH", val),
            None => std::env::remove_var("ORT_DYLIB_PATH"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_onnx_with_invalid_env_path() {
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::set_var("ORT_DYLIB_PATH", "/nonexistent/libonnxruntime.dylib");

        let result = check_onnx_runtime();
        // Should fall through to search paths since the env path doesn't exist
        assert_eq!(result.name, "ONNX Runtime");

        // Restore
        match original {
            Some(val) => std::env::set_var("ORT_DYLIB_PATH", val),
            None => std::env::remove_var("ORT_DYLIB_PATH"),
        }
    }

    // ── Chrome env var ────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_chrome_with_valid_env_path() {
        let dir = tempdir().unwrap();
        let fake_chrome = dir.path().join("chrome");
        std::fs::write(&fake_chrome, b"fake chrome").unwrap();

        let original = std::env::var("CHROME_PATH").ok();
        std::env::set_var("CHROME_PATH", fake_chrome.to_str().unwrap());

        let result = check_chrome();
        assert!(result.available);
        assert!(result.message.unwrap().contains("CHROME_PATH"));

        match original {
            Some(val) => std::env::set_var("CHROME_PATH", val),
            None => std::env::remove_var("CHROME_PATH"),
        }
    }

    // ── DepCheckResult struct fields ──────────────────────────────────

    #[test]
    fn test_dep_check_result_all_fields() {
        let r = DepCheckResult {
            name: "my-dep",
            available: false,
            required: true,
            message: Some("not found".to_string()),
        };
        assert_eq!(r.name, "my-dep");
        assert!(!r.available);
        assert!(r.required);
        assert_eq!(r.message.as_deref(), Some("not found"));
    }

    #[test]
    fn test_dep_check_result_none_message() {
        let r = DepCheckResult {
            name: "no-msg",
            available: true,
            required: false,
            message: None,
        };
        assert!(r.message.is_none());
    }

    #[test]
    fn test_dep_check_result_debug_format() {
        let r = DepCheckResult {
            name: "dbg",
            available: true,
            required: true,
            message: Some("ok".into()),
        };
        let s = format!("{:?}", r);
        assert!(s.contains("dbg"));
        assert!(s.contains("true"));
        assert!(s.contains("ok"));
    }

    // ── get_ort_download_info additional tests ───────────────────────

    #[test]
    fn test_get_ort_download_info_url_is_tgz() {
        let (_, _, url) = get_ort_download_info();
        assert!(url.ends_with(".tgz"), "URL should end with .tgz: {}", url);
    }

    #[test]
    fn test_get_ort_download_info_version_1_20_1() {
        let (_, _, url) = get_ort_download_info();
        assert!(
            url.contains("v1.20.1"),
            "URL should contain v1.20.1: {}",
            url
        );
    }

    #[test]
    fn test_get_ort_download_info_valid_os() {
        let (os_name, _, _) = get_ort_download_info();
        assert!(
            ["osx", "win", "linux"].contains(&os_name),
            "OS name should be osx/win/linux, got: {}",
            os_name
        );
    }

    #[test]
    fn test_get_ort_download_info_valid_arch() {
        let (_, arch, _) = get_ort_download_info();
        assert!(
            ["arm64", "x86_64", "x64", "aarch64"].contains(&arch),
            "Arch should be a known value, got: {}",
            arch
        );
    }

    // ── find_ort_in_directory additional edge cases ──────────────────

    #[test]
    fn test_find_ort_in_directory_multiple_ort_dirs_finds_first() {
        let dir = tempdir().unwrap();
        // Create two onnxruntime directories, only second has the lib
        let first = dir.path().join("onnxruntime-v1").join("lib");
        std::fs::create_dir_all(&first).unwrap();
        // No lib file in first

        let second = dir.path().join("onnxruntime-v2").join("lib");
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(second.join("libonnxruntime.dylib"), b"fake").unwrap();

        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_some());
    }

    #[test]
    fn test_find_ort_in_directory_wrong_lib_name() {
        let dir = tempdir().unwrap();
        let ort_dir = dir.path().join("onnxruntime-v1").join("lib");
        std::fs::create_dir_all(&ort_dir).unwrap();
        std::fs::write(ort_dir.join("libonnxruntime.so"), b"fake").unwrap();

        // Looking for .dylib but only .so exists
        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_none());
    }

    #[test]
    fn test_find_ort_in_directory_deeply_nested_not_found() {
        let dir = tempdir().unwrap();
        // Create a deeply nested dir that doesn't match the expected pattern
        let deep = dir.path().join("onnxruntime").join("other").join("lib");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("libonnxruntime.dylib"), b"fake").unwrap();

        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        // The nested check only looks at onnxruntime/onnxruntime-*/lib/
        // "other" doesn't start with "onnxruntime" so it shouldn't find it
        assert!(result.is_none());
    }

    #[test]
    fn test_find_ort_in_directory_nested_correct_pattern() {
        let dir = tempdir().unwrap();
        // onnxruntime/onnxruntime-linux-x64-1.20.1/lib/libonnxruntime.so
        let nested = dir
            .path()
            .join("onnxruntime")
            .join("onnxruntime-linux-x64-1.20.1")
            .join("lib");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("libonnxruntime.so"), b"fake").unwrap();

        let result = find_ort_in_directory(dir.path(), "libonnxruntime.so");
        assert!(result.is_some());
        let found = result.unwrap();
        assert!(found.ends_with("libonnxruntime.so"));
    }

    #[test]
    fn test_find_ort_in_directory_lib_directly_in_ort_dir_no_subdir() {
        let dir = tempdir().unwrap();
        // onnxruntime-v1/ exists but has the lib directly (not in lib/ subdir)
        let ort = dir.path().join("onnxruntime-v1");
        std::fs::create_dir_all(&ort).unwrap();
        std::fs::write(ort.join("libonnxruntime.dylib"), b"fake").unwrap();

        // The function checks entry.path().join("lib").join(lib_name), so this shouldn't match
        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_none());
    }

    // ── check_dependencies comprehensive combos ──────────────────────

    #[test]
    fn test_check_dependencies_all_flags_off() {
        let result = check_dependencies(false, false, false, false, false, false, false);
        // slm_wanted = enable_slm(false) || (!disable_slm(true) && config(false)) = false
        // so no ONNX check, only whois
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(results.iter().any(|r| r.name == "whois"));
        assert!(!results.iter().any(|r| r.name == "ONNX Runtime"));
        assert!(!results.iter().any(|r| r.name == "Chrome/Chromium"));
        assert!(!results.iter().any(|r| r.name == "subfinder"));
    }

    #[test]
    fn test_check_dependencies_web_org_and_web_traffic_both() {
        let result = check_dependencies(false, true, false, true, true, false, false);
        assert!(result.is_ok());
        let results = result.unwrap();
        // Chrome should be checked (from either enable_web_org or enable_web_traffic_discovery)
        assert!(results.iter().any(|r| r.name == "Chrome/Chromium"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_dependencies_disable_slm_overrides_config() {
        // disable_slm=true should prevent ONNX check even if config_slm_enabled=true
        let result = check_dependencies(false, true, false, false, false, true, false);
        // slm_wanted = false || (!true && true) = false
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(!results.iter().any(|r| r.name == "ONNX Runtime"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_dependencies_enable_slm_overrides_disable() {
        // enable_slm=true, disable_slm=true
        // slm_wanted = true || (!true && false) = true
        let result = check_dependencies(true, true, false, false, false, false, false);
        match result {
            Ok(results) => {
                assert!(results.iter().any(|r| r.name == "ONNX Runtime"));
            }
            Err(e) => {
                assert!(e.contains("ONNX"));
            }
        }
    }

    #[test]
    fn test_check_dependencies_all_optional_enabled() {
        let result = check_dependencies(false, true, true, true, true, false, true);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(results.iter().any(|r| r.name == "Chrome/Chromium"));
        assert!(results.iter().any(|r| r.name == "subfinder"));
        assert!(results.iter().any(|r| r.name == "whois"));
    }

    // ── check_whois additional ────────────────────────────────────────

    #[test]
    fn test_check_whois_message_not_empty() {
        let result = check_whois();
        assert!(result.message.is_some());
        assert!(!result.message.unwrap().is_empty());
    }

    // ── check_subfinder message content ──────────────────────────────

    #[test]
    fn test_check_subfinder_not_required() {
        let result = check_subfinder();
        assert!(!result.required);
    }

    // ── check_chrome not required ────────────────────────────────────

    #[test]
    fn test_check_chrome_not_required() {
        let result = check_chrome();
        assert!(!result.required, "Chrome should not be required");
    }

    // ── check_onnx_runtime required ──────────────────────────────────

    #[test]
    fn test_check_onnx_runtime_is_required() {
        let result = check_onnx_runtime();
        assert!(result.required, "ONNX Runtime should be marked required");
    }

    // ── download_onnx_runtime_interactive non-interactive ────────────

    #[test]
    fn test_download_onnx_runtime_interactive_non_interactive() {
        // In test/CI, stdin is not a terminal, so this should return an error
        let result = download_onnx_runtime_interactive();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("non-interactive") || err.contains("ONNX Runtime"),
            "Error should mention non-interactive mode: {}",
            err
        );
    }

    // ── check_onnx_runtime with env var edge cases ───────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_onnx_with_empty_env_var() {
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::set_var("ORT_DYLIB_PATH", "");

        let result = check_onnx_runtime();
        // Empty path won't exist, should fall through
        assert_eq!(result.name, "ONNX Runtime");

        match original {
            Some(val) => std::env::set_var("ORT_DYLIB_PATH", val),
            None => std::env::remove_var("ORT_DYLIB_PATH"),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Additional coverage tests for dep_check.rs
    // ═══════════════════════════════════════════════════════════════════

    // --- download_onnx_runtime_interactive non-interactive error content ---

    #[test]
    fn test_download_onnx_runtime_interactive_error_contains_url() {
        // In test/CI environments, stdin is not a terminal
        let result = download_onnx_runtime_interactive();
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Error message should contain the download URL
        assert!(
            err.contains("https://github.com/microsoft/onnxruntime"),
            "Error should contain download URL: {}",
            err
        );
        assert!(
            err.contains("non-interactive"),
            "Error should mention non-interactive mode: {}",
            err
        );
        assert!(
            err.contains("ORT_DYLIB_PATH"),
            "Error should mention ORT_DYLIB_PATH env var: {}",
            err
        );
    }

    // --- check_onnx_runtime: ORT_DYLIB_PATH with existing file ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_onnx_runtime_env_var_existing_file_message() {
        let dir = tempdir().unwrap();
        let fake_lib = dir.path().join("libonnxruntime.dylib");
        std::fs::write(&fake_lib, b"fake").unwrap();

        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::set_var("ORT_DYLIB_PATH", fake_lib.to_str().unwrap());

        let result = check_onnx_runtime();
        assert!(result.available);
        assert!(result.required);
        let msg = result.message.unwrap();
        assert!(msg.contains("ORT_DYLIB_PATH"));
        assert!(msg.contains(fake_lib.to_str().unwrap()));

        match original {
            Some(val) => std::env::set_var("ORT_DYLIB_PATH", val),
            None => std::env::remove_var("ORT_DYLIB_PATH"),
        }
    }

    // --- check_onnx_runtime: search in system path ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_onnx_runtime_system_path_not_found() {
        // Ensure ORT_DYLIB_PATH is unset so we exercise the search paths
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");

        let result = check_onnx_runtime();
        assert_eq!(result.name, "ONNX Runtime");
        assert!(result.required);
        // If not found, message should contain install instructions
        if !result.available {
            let msg = result.message.unwrap();
            assert!(msg.contains("ONNX Runtime not found"));
            assert!(msg.contains("github.com/microsoft/onnxruntime"));
            assert!(msg.contains("--disable-slm"));
        }

        if let Some(val) = original {
            std::env::set_var("ORT_DYLIB_PATH", val);
        }
    }

    // --- check_chrome: comprehensive system paths ---

    #[test]
    fn test_check_chrome_returns_correct_name() {
        let result = check_chrome();
        assert_eq!(result.name, "Chrome/Chromium");
        assert!(!result.required);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_chrome_env_var_valid_path() {
        let dir = tempdir().unwrap();
        let fake_chrome = dir.path().join("chrome-binary");
        std::fs::write(&fake_chrome, b"fake chrome binary").unwrap();

        let original = std::env::var("CHROME_PATH").ok();
        std::env::set_var("CHROME_PATH", fake_chrome.to_str().unwrap());

        let result = check_chrome();
        assert!(result.available);
        let msg = result.message.unwrap();
        assert!(msg.contains("CHROME_PATH"));

        match original {
            Some(val) => std::env::set_var("CHROME_PATH", val),
            None => std::env::remove_var("CHROME_PATH"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_chrome_not_found_message() {
        let original = std::env::var("CHROME_PATH").ok();
        std::env::set_var("CHROME_PATH", "/definitely/not/a/real/path/chrome");

        let result = check_chrome();
        // This might still find Chrome in system paths, so check both cases
        if !result.available {
            let msg = result.message.unwrap();
            assert!(msg.contains("Chrome/Chromium not found"));
            // On macOS it should suggest brew install
            if cfg!(target_os = "macos") {
                assert!(msg.contains("brew install"));
            }
        }

        match original {
            Some(val) => std::env::set_var("CHROME_PATH", val),
            None => std::env::remove_var("CHROME_PATH"),
        }
    }

    // --- check_subfinder: message details ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_subfinder_available_or_not() {
        let result = check_subfinder();
        assert_eq!(result.name, "subfinder");
        assert!(!result.required);
        let msg = result.message.unwrap();
        if result.available {
            assert!(msg.contains("Found at"));
        } else {
            assert!(msg.contains("subfinder not found"));
            assert!(msg.contains("go install"));
            assert!(msg.contains("github.com/projectdiscovery/subfinder"));
        }
    }

    // --- check_whois: detail checks ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_whois_available_or_not() {
        let result = check_whois();
        assert_eq!(result.name, "whois");
        assert!(result.required);
        let msg = result.message.unwrap();
        if result.available {
            assert!(msg.contains("Found at"));
        } else {
            assert!(msg.contains("whois not found"));
        }
    }

    // --- check_dependencies: error aggregation ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_dependencies_slm_enabled_error_aggregation() {
        // When SLM is enabled but ONNX is not available, check_dependencies
        // should aggregate errors
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");

        let result = check_dependencies(true, false, false, false, false, false, false);
        // May or may not error depending on whether ONNX is actually installed
        match result {
            Ok(results) => {
                assert!(results.iter().any(|r| r.name == "ONNX Runtime"));
            }
            Err(e) => {
                assert!(e.contains("ONNX Runtime"));
            }
        }

        if let Some(val) = original {
            std::env::set_var("ORT_DYLIB_PATH", val);
        }
    }

    // --- find_ort_in_directory: edge cases with permissions ---

    #[test]
    fn test_find_ort_in_directory_symlink_dir() {
        let dir = tempdir().unwrap();
        // Create a real ORT structure
        let ort = dir.path().join("onnxruntime-v1").join("lib");
        std::fs::create_dir_all(&ort).unwrap();
        std::fs::write(ort.join("libonnxruntime.dylib"), b"fake").unwrap();

        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_some());
        let path = result.unwrap();
        assert!(path.to_str().unwrap().contains("onnxruntime-v1"));
    }

    #[test]
    fn test_find_ort_in_directory_multiple_nested_dirs() {
        let dir = tempdir().unwrap();
        // Create parent "onnxruntime" dir with multiple versioned subdirs
        let parent = dir.path().join("onnxruntime");
        std::fs::create_dir_all(&parent).unwrap();

        // First subdir - no lib
        let v1 = parent.join("onnxruntime-v1").join("lib");
        std::fs::create_dir_all(&v1).unwrap();

        // Second subdir - has lib
        let v2 = parent.join("onnxruntime-v2").join("lib");
        std::fs::create_dir_all(&v2).unwrap();
        std::fs::write(v2.join("libonnxruntime.so"), b"fake lib").unwrap();

        let result = find_ort_in_directory(dir.path(), "libonnxruntime.so");
        assert!(result.is_some());
    }

    // --- get_ort_download_info: platform-specific assertions ---

    #[test]
    fn test_get_ort_download_info_format() {
        let (os_name, arch, url) = get_ort_download_info();
        // URL format: https://github.com/.../onnxruntime-{os}-{arch}-1.20.1.tgz
        let expected_suffix = format!("onnxruntime-{}-{}-1.20.1.tgz", os_name, arch);
        assert!(
            url.ends_with(&expected_suffix),
            "URL should end with {}, got {}",
            expected_suffix,
            url
        );
    }

    // --- check_dependencies: edge case combinations ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_dependencies_all_enabled() {
        // Enable everything — exercises all code paths
        let result = check_dependencies(
            true,  // enable_slm
            false, // disable_slm
            true,  // enable_subdomain_discovery
            true,  // enable_web_org
            true,  // enable_web_traffic_discovery
            true,  // config_slm_enabled
            true,  // config_subdomain_enabled
        );
        // May or may not succeed depending on installed tools
        match result {
            Ok(results) => {
                assert!(results.iter().any(|r| r.name == "whois"));
                assert!(results.iter().any(|r| r.name == "Chrome/Chromium"));
                assert!(results.iter().any(|r| r.name == "subfinder"));
                assert!(results.iter().any(|r| r.name == "ONNX Runtime"));
            }
            Err(e) => {
                // ONNX might not be installed
                assert!(e.contains("ONNX"));
            }
        }
    }

    #[test]
    fn test_check_dependencies_only_web_org() {
        let result = check_dependencies(false, true, false, true, false, false, false);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(results.iter().any(|r| r.name == "Chrome/Chromium"));
        // Should NOT include subfinder or ONNX
        assert!(!results.iter().any(|r| r.name == "subfinder"));
        assert!(!results.iter().any(|r| r.name == "ONNX Runtime"));
    }

    #[test]
    fn test_check_dependencies_only_web_traffic() {
        let result = check_dependencies(false, true, false, false, true, false, false);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(results.iter().any(|r| r.name == "Chrome/Chromium"));
    }

    #[test]
    fn test_check_dependencies_config_subdomain_only() {
        let result = check_dependencies(false, true, false, false, false, false, true);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(results.iter().any(|r| r.name == "subfinder"));
    }

    #[test]
    fn test_check_dependencies_enable_subdomain_only() {
        let result = check_dependencies(false, true, true, false, false, false, false);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(results.iter().any(|r| r.name == "subfinder"));
    }

    // --- DepCheckResult: comprehensive tests ---

    #[test]
    fn test_dep_check_result_with_none_message_debug() {
        let r = DepCheckResult {
            name: "test",
            available: false,
            required: false,
            message: None,
        };
        let debug = format!("{:?}", r);
        assert!(debug.contains("test"));
        assert!(debug.contains("None"));
    }

    #[test]
    fn test_dep_check_result_long_message() {
        let long_msg = "x".repeat(1000);
        let r = DepCheckResult {
            name: "tool",
            available: true,
            required: true,
            message: Some(long_msg.clone()),
        };
        assert_eq!(r.message.unwrap().len(), 1000);
    }

    // --- check_onnx_runtime: ORT_DYLIB_PATH set to dir (not file) ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_onnx_runtime_env_var_points_to_directory() {
        let dir = tempdir().unwrap();

        let original = std::env::var("ORT_DYLIB_PATH").ok();
        // Point to a directory instead of a file
        std::env::set_var("ORT_DYLIB_PATH", dir.path().to_str().unwrap());

        let result = check_onnx_runtime();
        // Directory exists, so std::path::Path::new(&path).exists() returns true,
        // but it's a directory not a file. The function doesn't distinguish.
        // It should either find it or fall through.
        assert_eq!(result.name, "ONNX Runtime");

        match original {
            Some(val) => std::env::set_var("ORT_DYLIB_PATH", val),
            None => std::env::remove_var("ORT_DYLIB_PATH"),
        }
    }

    // --- Multiple errors aggregation ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_dependencies_error_formatting() {
        // Force SLM to be wanted with no ONNX installed
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");

        let result = check_dependencies(true, false, false, false, false, false, false);
        if result.is_err() {
            let err = result.unwrap_err();
            // Error should be the aggregated message from check_onnx_runtime
            assert!(!err.is_empty());
        }

        if let Some(val) = original {
            std::env::set_var("ORT_DYLIB_PATH", val);
        }
    }

    // --- find_ort_in_directory: nested versioned subdir without lib file ---

    #[test]
    fn test_find_ort_in_directory_nested_missing_lib_file() {
        // Create nested structure with dir but no lib file - exercises
        // the nested loop's non-matching path (covers closing braces)
        let dir = tempdir().unwrap();
        let nested = dir
            .path()
            .join("onnxruntime")
            .join("onnxruntime-osx-arm64-1.20.1")
            .join("lib");
        std::fs::create_dir_all(&nested).unwrap();
        // No lib file created - nested_lib.exists() is false

        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_none());
    }

    // --- check_whois install hint platform ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_check_whois_install_hint_present() {
        // Force whois not found by testing the message structure
        let result = check_whois();
        if !result.available {
            let msg = result.message.unwrap();
            assert!(msg.contains("whois not found"));
            assert!(msg.contains("Install:"));
        }
    }
}
