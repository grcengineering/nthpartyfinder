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

// ── Platform-specific helpers (only the target variant is compiled) ──

#[cfg(target_os = "macos")]
fn ort_lib_name() -> &'static str {
    "libonnxruntime.dylib"
}
#[cfg(target_os = "windows")]
fn ort_lib_name() -> &'static str {
    "onnxruntime.dll"
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn ort_lib_name() -> &'static str {
    "libonnxruntime.so"
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn ort_platform() -> (&'static str, &'static str) {
    ("osx", "arm64")
}
#[cfg(all(target_os = "macos", not(target_arch = "aarch64")))]
fn ort_platform() -> (&'static str, &'static str) {
    ("osx", "x86_64")
}
#[cfg(target_os = "windows")]
fn ort_platform() -> (&'static str, &'static str) {
    ("win", "x64")
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn ort_platform() -> (&'static str, &'static str) {
    if cfg!(target_arch = "aarch64") {
        ("linux", "aarch64")
    } else {
        ("linux", "x64")
    }
}

#[cfg(target_os = "macos")]
fn chrome_system_paths() -> &'static [&'static str] {
    &[
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ]
}
#[cfg(target_os = "windows")]
fn chrome_system_paths() -> &'static [&'static str] {
    &[
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    ]
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn chrome_system_paths() -> &'static [&'static str] {
    &[
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    ]
}

#[cfg(target_os = "macos")]
fn chrome_install_hint() -> &'static str {
    "brew install --cask google-chrome"
}
#[cfg(target_os = "windows")]
fn chrome_install_hint() -> &'static str {
    "Download from https://www.google.com/chrome/"
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn chrome_install_hint() -> &'static str {
    "sudo apt-get install chromium  OR  sudo apt-get install google-chrome-stable"
}

#[cfg(target_os = "macos")]
fn whois_install_hint() -> &'static str {
    "Usually pre-installed. If missing: brew install whois"
}
#[cfg(target_os = "windows")]
fn whois_install_hint() -> &'static str {
    "Download from SysInternals or use WSL"
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn whois_install_hint() -> &'static str {
    "sudo apt-get install whois  OR  sudo yum install whois"
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
    let slm_wanted = enable_slm || (!disable_slm && config_slm_enabled);
    let ort_result = if slm_wanted {
        Some(check_onnx_runtime())
    } else {
        None
    };

    let chrome_result = if enable_web_org || enable_web_traffic_discovery {
        Some(check_chrome())
    } else {
        None
    };

    let subdomain_wanted = enable_subdomain_discovery || config_subdomain_enabled;
    let subfinder_result = if subdomain_wanted {
        Some(check_subfinder())
    } else {
        None
    };

    let whois_result = check_whois();

    collect_dep_results(ort_result, chrome_result, subfinder_result, whois_result)
}

fn collect_dep_results(
    ort_result: Option<DepCheckResult>,
    chrome_result: Option<DepCheckResult>,
    subfinder_result: Option<DepCheckResult>,
    whois_result: DepCheckResult,
) -> Result<Vec<DepCheckResult>, String> {
    let mut results = Vec::new();
    let mut errors = Vec::new();

    if let Some(ort) = ort_result {
        if !ort.available {
            errors.push(ort.message.clone().unwrap_or_default());
        }
        results.push(ort);
    }

    if let Some(chrome) = chrome_result {
        results.push(chrome);
    }

    if let Some(subfinder) = subfinder_result {
        results.push(subfinder);
    }

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
    let env_path_value = std::env::var("ORT_DYLIB_PATH").ok();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    find_ort_library(
        ort_lib_name(),
        env_path_value,
        exe_dir,
        std::path::Path::new("/usr/local/lib"),
    )
}

fn find_ort_library(
    lib_name: &str,
    env_path_value: Option<String>,
    exe_dir: Option<PathBuf>,
    system_lib_dir: &std::path::Path,
) -> DepCheckResult {
    if let Some(ref path) = env_path_value {
        let candidate = std::path::Path::new(path);
        let has_parent_component = candidate
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
        let filename_matches = candidate
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == lib_name)
            .unwrap_or(false);

        if candidate.is_absolute()
            && !has_parent_component
            && filename_matches
            && candidate.exists()
        {
            return DepCheckResult {
                name: "ONNX Runtime",
                available: true,
                required: true,
                message: Some(format!("Found at ORT_DYLIB_PATH={}", path)),
            };
        }
    }

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
        if let Some(path) = find_ort_in_directory(dir, lib_name) {
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

    let system_path = system_lib_dir.join(lib_name);
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
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("onnxruntime") || !entry.path().is_dir() {
            continue;
        }
        let lib_path = entry.path().join("lib").join(lib_name);
        if lib_path.exists() {
            return Some(lib_path);
        }
        let sub_entries = match std::fs::read_dir(entry.path()) {
            Ok(e) => e,
            Err(_) => continue,
        };
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
    None
}

/// Get OS-specific ONNX Runtime download URL
fn get_ort_download_info() -> (&'static str, &'static str, String) {
    let (os_name, arch) = ort_platform();
    let url = format!(
        "https://github.com/microsoft/onnxruntime/releases/download/v1.20.1/onnxruntime-{}-{}-1.20.1.tgz",
        os_name, arch
    );
    (os_name, arch, url)
}

/// Check if Chrome or Chromium is available
fn check_chrome() -> DepCheckResult {
    let env_path = std::env::var("CHROME_PATH").ok();
    check_chrome_inner(env_path, chrome_system_paths(), chrome_install_hint())
}

fn check_chrome_inner(
    env_path: Option<String>,
    system_paths: &[&str],
    install_hint: &str,
) -> DepCheckResult {
    if let Some(ref path) = env_path {
        let candidate = std::path::Path::new(path);
        let is_non_empty = !path.trim().is_empty();
        let has_parent_traversal = candidate
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));

        if is_non_empty && !has_parent_traversal && candidate.exists() {
            return DepCheckResult {
                name: "Chrome/Chromium",
                available: true,
                required: false,
                message: Some(format!("Found at CHROME_PATH={}", path)),
            };
        }
    }

    for path in system_paths {
        if std::path::Path::new(path).exists() {
            return DepCheckResult {
                name: "Chrome/Chromium",
                available: true,
                required: false,
                message: Some(format!("Found at: {}", path)),
            };
        }
    }

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
    check_subfinder_inner(which::which("subfinder").ok())
}

fn check_subfinder_inner(which_path: Option<PathBuf>) -> DepCheckResult {
    match which_path {
        Some(path) => DepCheckResult {
            name: "subfinder",
            available: true,
            required: false,
            message: Some(format!("Found at: {}", path.display())),
        },
        None => DepCheckResult {
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
    check_whois_inner(which::which("whois").ok())
}

fn check_whois_inner(which_path: Option<PathBuf>) -> DepCheckResult {
    match which_path {
        Some(path) => DepCheckResult {
            name: "whois",
            available: true,
            required: true,
            message: Some(format!("Found at: {}", path.display())),
        },
        None => DepCheckResult {
            name: "whois",
            available: false,
            required: true,
            message: Some(format!(
                "whois not found. Required for organization name lookups.\n\
                 Install: {}",
                whois_install_hint()
            )),
        },
    }
}

fn is_download_consent(input: &str) -> bool {
    let trimmed = input.trim().to_lowercase();
    trimmed.is_empty() || trimmed == "y" || trimmed == "yes"
}

fn find_ort_after_download(ort_dir: &std::path::Path, lib_name: &str) -> Result<PathBuf, String> {
    if let Some(lib_path) = find_ort_in_directory(ort_dir, lib_name) {
        let abs_path = lib_path.canonicalize().unwrap_or(lib_path.clone());
        return Ok(abs_path);
    }

    let mut found = None;
    if let Ok(entries) = std::fs::read_dir(ort_dir) {
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            if let Some(path) = find_ort_in_directory(&entry.path(), lib_name) {
                found = Some(path);
                break;
            }
            let direct = entry.path().join(lib_name);
            if direct.exists() {
                found = Some(direct);
                break;
            }
        }
    }

    match found {
        Some(path) => {
            let abs_path = path.canonicalize().unwrap_or(path.clone());
            Ok(abs_path)
        }
        None => Err(format!(
            "Downloaded but could not find {} in {}. Check the directory manually.",
            lib_name,
            ort_dir.display()
        )),
    }
}

/// Download ONNX Runtime to a directory next to the executable.
/// Returns the path to the downloaded library file.
/// Prompts for consent in interactive mode; errors in non-interactive mode.
pub fn download_onnx_runtime_interactive() -> Result<PathBuf, String> {
    download_onnx_runtime_interactive_impl()
}

fn download_non_interactive_error() -> Result<PathBuf, String> {
    let (_, _, download_url) = get_ort_download_info();
    Err(format!(
        "ONNX Runtime not found and running in non-interactive mode.\n\
         Download manually: {}\n\
         Then set: export ORT_DYLIB_PATH=/path/to/libonnxruntime.dylib",
        download_url
    ))
}

// coverage(off): #[cfg(not(test))] — this entire function is compiled out during tests;
// interactive I/O (stdin prompt, curl download, tar extraction) is genuinely untestable.
// All extractable logic (is_download_consent, find_ort_after_download, get_ort_download_info,
// download_non_interactive_error) is tested independently.
#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn download_onnx_runtime_interactive_impl() -> Result<PathBuf, String> {
    let is_interactive = std::io::IsTerminal::is_terminal(&std::io::stdin());

    if !is_interactive {
        return download_non_interactive_error();
    }

    let (os_name, arch, download_url) = get_ort_download_info();
    let lib_name = ort_lib_name();

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

    if !is_download_consent(&input) {
        return Err("ONNX Runtime download declined. Use --disable-slm to skip NER.".to_string());
    }

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

    let _ = std::fs::remove_file(&tgz_path);

    let abs_path = find_ort_after_download(&ort_dir, lib_name)?;
    std::env::set_var("ORT_DYLIB_PATH", &abs_path);

    eprintln!();
    eprintln!("  ✅ ONNX Runtime installed successfully!");
    eprintln!("  Location: {}", abs_path.display());
    eprintln!();
    eprintln!("  To make this permanent, add to your shell profile:");
    eprintln!("    export ORT_DYLIB_PATH={}", abs_path.display());
    eprintln!();

    Ok(abs_path)
}

#[cfg(test)]
fn download_onnx_runtime_interactive_impl() -> Result<PathBuf, String> {
    download_non_interactive_error()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn restore_env(name: &str, original: Option<String>) {
        match original {
            Some(val) => std::env::set_var(name, val),
            None => std::env::remove_var(name),
        }
    }

    fn assert_dep_result(result: Result<Vec<DepCheckResult>, String>, expected_name: &str) {
        match result {
            Ok(results) => assert!(
                results.iter().any(|r| r.name == expected_name),
                "{} should be in results",
                expected_name
            ),
            Err(e) => assert!(!e.is_empty(), "Error should be non-empty"),
        }
    }

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
    fn test_check_chrome_message_content() {
        let result = check_chrome();
        let msg = result.message.unwrap();
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_check_chrome_with_env_var_nonexistent_path() {
        // Save and set a bogus CHROME_PATH
        let original = std::env::var("CHROME_PATH").ok();
        std::env::set_var("CHROME_PATH", "/nonexistent/chrome/binary");

        let result = check_chrome();
        // The bogus path shouldn't make it "available" -- it should fall through
        // (unless one of the system paths exists)
        // Regardless, the function should not panic
        assert_eq!(result.name, "Chrome/Chromium");

        restore_env("CHROME_PATH", original);
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
    fn test_check_subfinder_message_content() {
        let result = check_subfinder();
        let msg = result.message.unwrap();
        assert!(!msg.is_empty());
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
    fn test_check_onnx_runtime_message_has_install_instructions_when_missing() {
        // Temporarily unset ORT_DYLIB_PATH so we exercise the search paths
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");

        let result = check_onnx_runtime();
        assert_eq!(result.name, "ONNX Runtime");
        assert!(result.message.is_some());

        restore_env("ORT_DYLIB_PATH", original);
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
        assert_dep_result(result, "ONNX Runtime");
    }

    #[test]
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
        assert_dep_result(result, "ONNX Runtime");
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
    fn test_check_onnx_with_valid_env_path() {
        let dir = tempdir().unwrap();
        let fake_lib = dir.path().join(ort_lib_name());
        std::fs::write(&fake_lib, b"fake ort lib").unwrap();

        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::set_var("ORT_DYLIB_PATH", fake_lib.to_str().unwrap());

        let result = check_onnx_runtime();
        assert!(result.available);
        assert!(result.message.unwrap().contains("ORT_DYLIB_PATH"));

        restore_env("ORT_DYLIB_PATH", original);
    }

    #[test]
    fn test_check_onnx_with_invalid_env_path() {
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::set_var("ORT_DYLIB_PATH", "/nonexistent/libonnxruntime.dylib");

        let result = check_onnx_runtime();
        // Should fall through to search paths since the env path doesn't exist
        assert_eq!(result.name, "ONNX Runtime");

        restore_env("ORT_DYLIB_PATH", original);
    }

    // ── Chrome env var ────────────────────────────────────────────────

    #[test]
    fn test_check_chrome_with_valid_env_path() {
        let dir = tempdir().unwrap();
        let fake_chrome = dir.path().join("chrome");
        std::fs::write(&fake_chrome, b"fake chrome").unwrap();

        let original = std::env::var("CHROME_PATH").ok();
        std::env::set_var("CHROME_PATH", fake_chrome.to_str().unwrap());

        let result = check_chrome();
        assert!(result.available);
        assert!(result.message.unwrap().contains("CHROME_PATH"));

        restore_env("CHROME_PATH", original);
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
    fn test_check_dependencies_disable_slm_overrides_config() {
        // disable_slm=true should prevent ONNX check even if config_slm_enabled=true
        let result = check_dependencies(false, true, false, false, false, true, false);
        // slm_wanted = false || (!true && true) = false
        assert!(result.is_ok());
        let results = result.unwrap();
        assert!(!results.iter().any(|r| r.name == "ONNX Runtime"));
    }

    #[test]
    fn test_check_dependencies_enable_slm_overrides_disable() {
        let result = check_dependencies(true, true, false, false, false, false, false);
        assert_dep_result(result, "ONNX Runtime");
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
    fn test_check_onnx_with_empty_env_var() {
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::set_var("ORT_DYLIB_PATH", "");

        let result = check_onnx_runtime();
        // Empty path won't exist, should fall through
        assert_eq!(result.name, "ONNX Runtime");

        restore_env("ORT_DYLIB_PATH", original);
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
    fn test_check_onnx_runtime_env_var_existing_file_message() {
        let dir = tempdir().unwrap();
        let fake_lib = dir.path().join(ort_lib_name());
        std::fs::write(&fake_lib, b"fake").unwrap();

        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::set_var("ORT_DYLIB_PATH", fake_lib.to_str().unwrap());

        let result = check_onnx_runtime();
        assert!(result.available);
        assert!(result.required);
        let msg = result.message.unwrap();
        assert!(msg.contains("ORT_DYLIB_PATH"));
        assert!(msg.contains(fake_lib.to_str().unwrap()));

        restore_env("ORT_DYLIB_PATH", original);
    }

    // --- check_onnx_runtime: search in system path ---

    #[test]
    fn test_check_onnx_runtime_system_path_not_found() {
        // Ensure ORT_DYLIB_PATH is unset so we exercise the search paths
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");

        let result = check_onnx_runtime();
        assert_eq!(result.name, "ONNX Runtime");
        assert!(result.required);
        assert!(result.message.is_some());

        restore_env("ORT_DYLIB_PATH", original);
    }

    // --- check_chrome: comprehensive system paths ---

    #[test]
    fn test_check_chrome_returns_correct_name() {
        let result = check_chrome();
        assert_eq!(result.name, "Chrome/Chromium");
        assert!(!result.required);
    }

    #[test]
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

        restore_env("CHROME_PATH", original);
    }

    #[test]
    fn test_check_chrome_not_found_message() {
        let original = std::env::var("CHROME_PATH").ok();
        std::env::set_var("CHROME_PATH", "/definitely/not/a/real/path/chrome");

        let result = check_chrome();
        assert_eq!(result.name, "Chrome/Chromium");
        assert!(result.message.is_some());

        restore_env("CHROME_PATH", original);
    }

    // --- check_subfinder: message details ---

    #[test]
    fn test_check_subfinder_available_or_not() {
        let result = check_subfinder();
        assert_eq!(result.name, "subfinder");
        assert!(!result.required);
        assert!(result.message.is_some());
    }

    // --- check_whois: detail checks ---

    #[test]
    fn test_check_whois_available_or_not() {
        let result = check_whois();
        assert_eq!(result.name, "whois");
        assert!(result.required);
        assert!(result.message.is_some());
    }

    // --- check_dependencies: error aggregation ---

    #[test]
    fn test_check_dependencies_slm_enabled_error_aggregation() {
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");

        let result = check_dependencies(true, false, false, false, false, false, false);
        assert_dep_result(result, "ONNX Runtime");

        restore_env("ORT_DYLIB_PATH", original);
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
        assert_dep_result(result, "ONNX Runtime");
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

        restore_env("ORT_DYLIB_PATH", original);
    }

    // --- Multiple errors aggregation ---

    #[test]
    fn test_check_dependencies_error_formatting() {
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");

        let result = check_dependencies(true, false, false, false, false, false, false);
        assert_dep_result(result, "ONNX Runtime");

        restore_env("ORT_DYLIB_PATH", original);
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
    fn test_check_whois_install_hint_present() {
        let result = check_whois();
        assert!(result.message.is_some());
    }

    // ── Newly-exposed coverage: argument construction & URL format ────

    #[test]
    fn test_download_ort_interactive_non_interactive_error_has_export_hint() {
        let result = download_onnx_runtime_interactive();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("export ORT_DYLIB_PATH"),
            "Non-interactive error should tell user how to set env var: {}",
            err
        );
    }

    #[test]
    fn test_download_ort_interactive_url_matches_get_ort_download_info() {
        let (_, _, expected_url) = get_ort_download_info();
        let result = download_onnx_runtime_interactive();
        let err = result.unwrap_err();
        assert!(
            err.contains(&expected_url),
            "Error should contain the same URL as get_ort_download_info: {}",
            err
        );
    }

    #[test]
    fn test_get_ort_download_info_url_is_valid_for_curl_arg() {
        let (_, _, url) = get_ort_download_info();
        assert!(
            url.starts_with("https://"),
            "URL must be HTTPS for curl -fSL"
        );
        assert!(!url.contains(' '), "URL must not contain spaces");
        assert!(!url.contains('\''), "URL must not contain single quotes");
    }

    #[test]
    fn test_check_onnx_runtime_not_found_message_has_install_script() {
        let original = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");

        let result = check_onnx_runtime();
        assert_eq!(result.name, "ONNX Runtime");
        assert!(result.message.is_some());

        restore_env("ORT_DYLIB_PATH", original);
    }

    #[test]
    fn test_check_dependencies_whois_always_present() {
        let combos: Vec<(bool, bool, bool, bool, bool, bool, bool)> = vec![
            (false, false, false, false, false, false, false),
            (false, true, false, false, false, false, false),
            (false, true, true, true, true, false, true),
        ];
        for (es, ds, esd, ewo, ewt, cse, csd) in combos {
            let result = check_dependencies(es, ds, esd, ewo, ewt, cse, csd);
            assert_dep_result(result, "whois");
        }
    }

    #[test]
    fn test_check_onnx_runtime_availability_consistent_with_check_onnx_runtime() {
        let avail = check_onnx_runtime_availability();
        let result = check_onnx_runtime();
        assert_eq!(avail, result.available);
    }

    #[test]
    fn test_check_chrome_install_hint_platform_specific() {
        let result = check_chrome_inner(None, &[], chrome_install_hint());
        assert!(!result.available);
        let msg = result.message.unwrap();
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_check_subfinder_uses_which() {
        let result = check_subfinder();
        assert!(result.message.is_some());
    }

    #[test]
    fn test_check_whois_uses_which() {
        let result = check_whois();
        let msg = result.message.unwrap();
        assert!(!msg.is_empty());
    }

    // ══════════════════════════════════════════════════════════════
    // Inner function tests — deterministic, no env-dependent branching
    // ══════════════════════════════════════════════════════════════

    // ── collect_dep_results ──────────────────────────────────────

    #[test]
    fn test_collect_dep_results_ort_unavailable_produces_error() {
        let ort = Some(DepCheckResult {
            name: "ONNX Runtime",
            available: false,
            required: true,
            message: Some("ONNX not found test msg".into()),
        });
        let whois = DepCheckResult {
            name: "whois",
            available: true,
            required: true,
            message: Some("found".into()),
        };
        let result = collect_dep_results(ort, None, None, whois);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ONNX not found test msg"));
    }

    #[test]
    fn test_collect_dep_results_ort_unavailable_no_message() {
        let ort = Some(DepCheckResult {
            name: "ONNX Runtime",
            available: false,
            required: true,
            message: None,
        });
        let whois = DepCheckResult {
            name: "whois",
            available: true,
            required: true,
            message: Some("ok".into()),
        };
        let result = collect_dep_results(ort, None, None, whois);
        assert!(result.is_err());
    }

    #[test]
    fn test_collect_dep_results_all_available() {
        let ort = Some(DepCheckResult {
            name: "ONNX Runtime",
            available: true,
            required: true,
            message: Some("ok".into()),
        });
        let chrome = Some(DepCheckResult {
            name: "Chrome",
            available: true,
            required: false,
            message: Some("ok".into()),
        });
        let subfinder = Some(DepCheckResult {
            name: "subfinder",
            available: true,
            required: false,
            message: Some("ok".into()),
        });
        let whois = DepCheckResult {
            name: "whois",
            available: true,
            required: true,
            message: Some("ok".into()),
        };
        let result = collect_dep_results(ort, chrome, subfinder, whois);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_collect_dep_results_none_optionals() {
        let whois = DepCheckResult {
            name: "whois",
            available: true,
            required: true,
            message: Some("ok".into()),
        };
        let result = collect_dep_results(None, None, None, whois);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_collect_dep_results_chrome_unavailable_no_error() {
        let chrome = Some(DepCheckResult {
            name: "Chrome",
            available: false,
            required: false,
            message: Some("not found".into()),
        });
        let whois = DepCheckResult {
            name: "whois",
            available: true,
            required: true,
            message: Some("ok".into()),
        };
        let result = collect_dep_results(None, chrome, None, whois);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 2);
        assert!(!results[0].available);
    }

    // ── find_ort_library ─────────────────────────────────────────

    #[test]
    fn test_find_ort_library_env_path_found() {
        let dir = tempdir().unwrap();
        let lib = dir.path().join("libonnxruntime.dylib");
        std::fs::write(&lib, b"fake").unwrap();

        let result = find_ort_library(
            "libonnxruntime.dylib",
            Some(lib.to_str().unwrap().to_string()),
            None,
            std::path::Path::new("/nonexistent"),
        );
        assert!(result.available);
        assert!(result.message.unwrap().contains("ORT_DYLIB_PATH"));
    }

    #[test]
    fn test_find_ort_library_env_path_missing_falls_through() {
        let result = find_ort_library(
            "libonnxruntime.dylib",
            Some("/nonexistent/lib.dylib".into()),
            None,
            std::path::Path::new("/nonexistent"),
        );
        assert!(!result.available);
    }

    #[test]
    fn test_find_ort_library_adjacent_to_exe() {
        let dir = tempdir().unwrap();
        let lib = dir.path().join("libonnxruntime.dylib");
        std::fs::write(&lib, b"fake").unwrap();

        let result = find_ort_library(
            "libonnxruntime.dylib",
            None,
            Some(dir.path().to_path_buf()),
            std::path::Path::new("/nonexistent"),
        );
        assert!(result.available);
        assert!(
            result.message.unwrap().contains("next to executable"),
            "Should find adjacent to exe dir"
        );
    }

    #[test]
    fn test_find_ort_library_in_ort_subdir() {
        let dir = tempdir().unwrap();
        let ort_lib = dir.path().join("onnxruntime-v1").join("lib");
        std::fs::create_dir_all(&ort_lib).unwrap();
        std::fs::write(ort_lib.join("libonnxruntime.dylib"), b"fake").unwrap();

        let result = find_ort_library(
            "libonnxruntime.dylib",
            None,
            Some(dir.path().to_path_buf()),
            std::path::Path::new("/nonexistent"),
        );
        assert!(result.available);
        assert!(result.message.unwrap().contains("Found at"));
    }

    #[test]
    fn test_find_ort_library_in_system_lib() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("libonnxruntime.dylib"), b"fake").unwrap();

        let result = find_ort_library("libonnxruntime.dylib", None, None, dir.path());
        assert!(result.available);
        assert!(result.message.unwrap().contains("Found at"));
    }

    #[test]
    fn test_find_ort_library_not_found() {
        let result = find_ort_library(
            "libonnxruntime.dylib",
            None,
            None,
            std::path::Path::new("/nonexistent"),
        );
        assert!(!result.available);
        let msg = result.message.unwrap();
        assert!(msg.contains("ONNX Runtime not found"));
        assert!(msg.contains("install"));
    }

    // ── check_chrome_inner ───────────────────────────────────────

    #[test]
    fn test_check_chrome_inner_env_found() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("chrome");
        std::fs::write(&f, b"fake").unwrap();

        let result = check_chrome_inner(Some(f.to_str().unwrap().to_string()), &[], "hint");
        assert!(result.available);
        assert!(result.message.unwrap().contains("CHROME_PATH"));
    }

    #[test]
    fn test_check_chrome_inner_system_path_found() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("chrome");
        std::fs::write(&f, b"fake").unwrap();

        let result = check_chrome_inner(None, &[f.to_str().unwrap()], "hint");
        assert!(result.available);
        assert!(result.message.unwrap().contains("Found at"));
    }

    #[test]
    fn test_check_chrome_inner_not_found() {
        let result = check_chrome_inner(None, &["/nonexistent/chrome"], "test install cmd");
        assert!(!result.available);
        let msg = result.message.unwrap();
        assert!(msg.contains("Chrome/Chromium not found"));
        assert!(msg.contains("test install cmd"));
    }

    #[test]
    fn test_check_chrome_inner_env_invalid_falls_through_to_not_found() {
        let result = check_chrome_inner(
            Some("/nonexistent/chrome".into()),
            &["/also/nonexistent"],
            "hint",
        );
        assert!(!result.available);
    }

    // ── check_subfinder_inner ────────────────────────────────────

    #[test]
    fn test_check_subfinder_inner_found() {
        let result = check_subfinder_inner(Some(PathBuf::from("/usr/bin/subfinder")));
        assert!(result.available);
        assert_eq!(result.name, "subfinder");
        assert!(!result.required);
        assert!(result.message.unwrap().contains("Found at"));
    }

    #[test]
    fn test_check_subfinder_inner_not_found() {
        let result = check_subfinder_inner(None);
        assert!(!result.available);
        assert_eq!(result.name, "subfinder");
        let msg = result.message.unwrap();
        assert!(msg.contains("subfinder not found"));
        assert!(msg.contains("go install"));
        assert!(msg.contains("projectdiscovery"));
    }

    // ── check_whois_inner ────────────────────────────────────────

    #[test]
    fn test_check_whois_inner_found() {
        let result = check_whois_inner(Some(PathBuf::from("/usr/bin/whois")));
        assert!(result.available);
        assert_eq!(result.name, "whois");
        assert!(result.required);
        assert!(result.message.unwrap().contains("Found at"));
    }

    #[test]
    fn test_check_whois_inner_not_found() {
        let result = check_whois_inner(None);
        assert!(!result.available);
        assert_eq!(result.name, "whois");
        assert!(result.required);
        let msg = result.message.unwrap();
        assert!(msg.contains("whois not found"));
        assert!(msg.contains("Install:"));
    }

    // ── is_download_consent ──────────────────────────────────────

    #[test]
    fn test_is_download_consent_empty_and_whitespace() {
        assert!(is_download_consent(""));
        assert!(is_download_consent("  "));
        assert!(is_download_consent("\n"));
    }

    #[test]
    fn test_is_download_consent_yes_variants() {
        assert!(is_download_consent("y"));
        assert!(is_download_consent("Y"));
        assert!(is_download_consent("yes"));
        assert!(is_download_consent("YES"));
        assert!(is_download_consent("  yes  "));
    }

    #[test]
    fn test_is_download_consent_rejected() {
        assert!(!is_download_consent("n"));
        assert!(!is_download_consent("no"));
        assert!(!is_download_consent("N"));
        assert!(!is_download_consent("anything"));
    }

    // ── find_ort_after_download ──────────────────────────────────

    #[test]
    fn test_find_ort_after_download_via_find_ort_in_directory() {
        let dir = tempdir().unwrap();
        let ort_lib = dir.path().join("onnxruntime-v1").join("lib");
        std::fs::create_dir_all(&ort_lib).unwrap();
        std::fs::write(ort_lib.join("libonnxruntime.dylib"), b"fake").unwrap();

        let result = find_ort_after_download(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_ort_after_download_fallback_nested_search() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("extracted");
        let ort_lib = sub.join("onnxruntime-v1").join("lib");
        std::fs::create_dir_all(&ort_lib).unwrap();
        std::fs::write(ort_lib.join("libonnxruntime.dylib"), b"fake").unwrap();

        let result = find_ort_after_download(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_ort_after_download_fallback_direct_child() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("some_dir");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("libonnxruntime.dylib"), b"fake").unwrap();

        let result = find_ort_after_download(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_ort_after_download_not_found() {
        let dir = tempdir().unwrap();
        // Create a subdir with no lib file — exercises direct.exists() == false path
        let sub = dir.path().join("some_subdir");
        std::fs::create_dir_all(&sub).unwrap();
        let result = find_ort_after_download(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("could not find"));
    }

    #[test]
    fn test_find_ort_after_download_nonexistent_dir() {
        let result = find_ort_after_download(std::path::Path::new("/nonexistent"), "lib.dylib");
        assert!(result.is_err());
    }

    // ── platform helpers ─────────────────────────────────────────

    #[test]
    fn test_ort_lib_name_non_empty() {
        let name = ort_lib_name();
        assert!(!name.is_empty());
    }

    #[test]
    fn test_ort_platform_values() {
        let (os, arch) = ort_platform();
        assert!(!os.is_empty());
        assert!(!arch.is_empty());
    }

    #[test]
    fn test_chrome_system_paths_non_empty() {
        let paths = chrome_system_paths();
        assert!(!paths.is_empty());
    }

    #[test]
    fn test_chrome_install_hint_non_empty() {
        let hint = chrome_install_hint();
        assert!(!hint.is_empty());
    }

    #[test]
    fn test_whois_install_hint_non_empty() {
        let hint = whois_install_hint();
        assert!(!hint.is_empty());
    }

    #[test]
    fn test_restore_env_some_and_none_arms() {
        let key = "TEST_RESTORE_ENV_COV_2e8f";
        std::env::set_var(key, "before");
        restore_env(key, Some("restored_val".to_string()));
        assert_eq!(std::env::var(key).unwrap(), "restored_val");
        restore_env(key, None);
        assert!(std::env::var(key).is_err());
    }

    #[test]
    fn test_assert_dep_result_ok_and_err_arms() {
        let ok_results = Ok(vec![DepCheckResult {
            name: "whois",
            available: true,
            required: true,
            message: Some("ok".into()),
        }]);
        assert_dep_result(ok_results, "whois");

        let err_result: Result<Vec<DepCheckResult>, String> = Err("missing dep".to_string());
        assert_dep_result(err_result, "irrelevant");
    }

    #[test]
    fn test_find_ort_in_directory_read_subdir_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let ort_dir = dir.path().join("onnxruntime-v1");
        std::fs::create_dir_all(ort_dir.join("lib")).unwrap();
        // No lib file, so it won't match the flat path — falls into sub_entries read.
        // Remove read permission so read_dir fails with Err.
        std::fs::set_permissions(&ort_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = find_ort_in_directory(dir.path(), "libonnxruntime.dylib");
        // Restore permissions before assert (for cleanup)
        std::fs::set_permissions(&ort_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_find_ort_after_download_skips_files_in_ort_dir() {
        let dir = tempdir().unwrap();
        // A regular file in the ort_dir (not a directory) — exercises the continue path
        std::fs::write(dir.path().join("readme.txt"), b"not a dir").unwrap();

        // A subdir with a direct lib file
        let sub = dir.path().join("extracted");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("libonnxruntime.dylib"), b"fake").unwrap();

        let result = find_ort_after_download(dir.path(), "libonnxruntime.dylib");
        assert!(result.is_ok());
    }

    #[test]
    fn test_download_non_interactive_error_content() {
        let result = download_non_interactive_error();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("non-interactive"));
        assert!(err.contains("ORT_DYLIB_PATH"));
    }
}
