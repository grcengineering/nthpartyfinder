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
pub fn check_onnx_runtime_availability() -> bool {
    check_onnx_runtime().available
}

/// Check if ONNX Runtime shared library is available
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

    #[test]
    fn test_get_ort_download_info_returns_valid_url() {
        let (os, arch, url) = get_ort_download_info();
        assert!(!os.is_empty());
        assert!(!arch.is_empty());
        assert!(url.starts_with("https://github.com/microsoft/onnxruntime/releases/"));
        assert!(url.contains("1.20.1"));
    }

    #[test]
    fn test_check_whois_returns_result() {
        let result = check_whois();
        assert_eq!(result.name, "whois");
        // whois is available on macOS by default
        assert!(result.message.is_some());
    }

    #[test]
    fn test_check_chrome_returns_result() {
        let result = check_chrome();
        assert_eq!(result.name, "Chrome/Chromium");
        assert!(result.message.is_some());
        // Chrome is optional, so required should be false
        assert!(!result.required);
    }

    #[test]
    fn test_check_subfinder_returns_result() {
        let result = check_subfinder();
        assert_eq!(result.name, "subfinder");
        assert!(result.message.is_some());
        assert!(!result.required);
    }

    #[test]
    fn test_check_onnx_runtime_returns_result() {
        let result = check_onnx_runtime();
        assert_eq!(result.name, "ONNX Runtime");
        assert!(result.message.is_some());
        assert!(result.required);
    }

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
    fn test_find_ort_in_directory_nonexistent() {
        let result = find_ort_in_directory(
            std::path::Path::new("/nonexistent/path"),
            "libonnxruntime.dylib",
        );
        assert!(result.is_none());
    }
}
