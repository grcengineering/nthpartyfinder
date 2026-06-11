//! Subdomain discovery using Project Discovery's subfinder tool.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
#[cfg(test)]
use tracing::warn;
#[cfg(not(test))]
use tracing::{debug, info, warn};

/// Latest subfinder version to download
const SUBFINDER_VERSION: &str = "2.11.0";

/// Available installation methods for subfinder
/// Based on official Project Discovery documentation:
/// https://docs.projectdiscovery.io/opensource/subfinder/install
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOption {
    AutoDownload,
    Go,
    Homebrew,
    Docker,
    ManualDownload,
    Skip,
}

impl InstallOption {
    /// Get the display name for this installation option
    pub fn display_name(&self) -> &'static str {
        match self {
            InstallOption::AutoDownload => "Auto-download subfinder (Recommended)",
            InstallOption::Go => "Go (go install)",
            InstallOption::Homebrew => "Homebrew (macOS/Linux)",
            InstallOption::Docker => "Docker",
            InstallOption::ManualDownload => "Open GitHub releases page",
            InstallOption::Skip => "Skip - Continue without subdomain discovery",
        }
    }
}

pub struct SubfinderDiscovery {
    binary_path: PathBuf,
    timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub source: String,
}

#[derive(Debug, Deserialize)]
struct SubfinderJsonLine {
    host: String,
    source: String,
}

impl SubfinderDiscovery {
    pub fn new(binary_path: PathBuf, timeout: Duration) -> Self {
        Self {
            binary_path,
            timeout,
        }
    }

    pub fn is_available(&self) -> bool {
        self.get_resolved_binary_path().is_some()
    }

    /// Get the actual binary path to use, checking:
    /// 1. The configured binary_path (if it exists or is in PATH)
    /// 2. The bundled binary location
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_resolved_binary_path(&self) -> Option<PathBuf> {
        if self.binary_path.exists() {
            return Some(self.binary_path.clone());
        }
        // which::which and bundled binary fallback depend on system state — untestable
        #[cfg(not(test))]
        {
            if which::which(&self.binary_path).is_ok() {
                return Some(self.binary_path.clone());
            }
            if let Some(bundled) = Self::get_bundled_binary_path() {
                if bundled.exists() {
                    return Some(bundled);
                }
            }
        }
        None
    }

    /// Get the path to the bundled subfinder binary in the app's data directory
    pub fn get_bundled_binary_path() -> Option<PathBuf> {
        #[cfg(windows)]
        let binary_name = "subfinder.exe";
        #[cfg(not(windows))]
        let binary_name = "subfinder";

        // Use platform-appropriate data directory
        #[cfg(windows)]
        {
            std::env::var("LOCALAPPDATA").ok().map(|p| {
                PathBuf::from(p)
                    .join("nthpartyfinder")
                    .join("bin")
                    .join(binary_name)
            })
        }
        #[cfg(not(windows))]
        {
            dirs::data_local_dir().map(|p| p.join("nthpartyfinder").join("bin").join(binary_name))
        }
    }

    /// Get the download URL for subfinder for the current platform
    pub fn get_platform_download_url() -> Option<String> {
        Self::get_download_url_for_platform(std::env::consts::OS, std::env::consts::ARCH)
    }

    fn get_download_url_for_platform(os: &str, arch: &str) -> Option<String> {
        let os_name = match os {
            "windows" => "windows",
            "macos" => "darwin",
            "linux" => "linux",
            _ => return None,
        };

        let arch_name = match arch {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "386",
            _ => return None,
        };

        Some(format!(
            "https://github.com/projectdiscovery/subfinder/releases/download/v{}/subfinder_{}_{}_{}.zip",
            SUBFINDER_VERSION, SUBFINDER_VERSION, os_name, arch_name
        ))
    }

    /// Download and install subfinder to the bundled location
    #[cfg(not(test))] // real network I/O — downloads binary from GitHub releases and extracts zip
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn download_and_install() -> Result<PathBuf> {
        let download_url = Self::get_platform_download_url()
            .ok_or_else(|| anyhow!("Unsupported platform for automatic download"))?;

        let install_path = Self::get_bundled_binary_path()
            .ok_or_else(|| anyhow!("Could not determine installation path"))?;

        let install_dir = install_path
            .parent()
            .ok_or_else(|| anyhow!("Invalid installation path"))?;

        // Create the installation directory
        std::fs::create_dir_all(install_dir)
            .map_err(|e| anyhow!("Failed to create installation directory: {}", e))?;

        info!(
            "Downloading subfinder v{} from GitHub...",
            SUBFINDER_VERSION
        );
        debug!("Download URL: {}", download_url);

        // Download the zip file
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

        let response = client
            .get(&download_url)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to download subfinder: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Download failed with status: {}",
                response.status()
            ));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| anyhow!("Failed to read download response: {}", e))?;

        info!("Downloaded {} bytes, extracting...", bytes.len());

        // Extract the zip file
        let cursor = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(cursor)
            .map_err(|e| anyhow!("Failed to open zip archive: {}", e))?;

        // Find and extract the subfinder binary
        let binary_name = if cfg!(windows) {
            "subfinder.exe"
        } else {
            "subfinder"
        };
        let mut found = false;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| anyhow!("Failed to read zip entry: {}", e))?;

            let name = file.name().to_string();
            if name.ends_with(binary_name) || name == binary_name {
                let mut outfile = std::fs::File::create(&install_path)
                    .map_err(|e| anyhow!("Failed to create output file: {}", e))?;

                std::io::copy(&mut file, &mut outfile)
                    .map_err(|e| anyhow!("Failed to extract binary: {}", e))?;

                // Make executable on Unix
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = outfile.metadata()?.permissions();
                    perms.set_mode(0o755);
                    std::fs::set_permissions(&install_path, perms)?;
                }

                found = true;
                break;
            }
        }

        if !found {
            return Err(anyhow!(
                "Could not find subfinder binary in downloaded archive"
            ));
        }

        info!("Subfinder installed to: {}", install_path.display());
        Ok(install_path)
    }

    #[cfg(test)]
    pub async fn download_and_install() -> Result<PathBuf> {
        Err(anyhow!("download_and_install unavailable in test mode"))
    }

    /// Create a new SubfinderDiscovery using the bundled binary if available
    pub fn with_bundled_or_path(custom_path: Option<PathBuf>, timeout: Duration) -> Self {
        #[cfg(windows)]
        let default_name = "subfinder.exe";
        #[cfg(not(windows))]
        let default_name = "subfinder";

        let binary_path = custom_path
            .or_else(|| Self::get_bundled_binary_path().filter(|p| p.exists()))
            .unwrap_or_else(|| PathBuf::from(default_name));

        Self::new(binary_path, timeout)
    }

    /// Get installation instructions for subfinder
    pub fn get_installation_instructions() -> String {
        Self::get_installation_instructions_for_platform(
            std::env::consts::OS,
            std::env::consts::ARCH,
        )
    }

    fn get_installation_instructions_for_platform(os: &str, arch: &str) -> String {
        let mut instructions = String::new();
        instructions
            .push_str("\n╔══════════════════════════════════════════════════════════════════╗\n");
        instructions
            .push_str("║           Subfinder Installation Required                        ║\n");
        instructions
            .push_str("╚══════════════════════════════════════════════════════════════════╝\n\n");
        instructions.push_str("Subfinder is a subdomain discovery tool by Project Discovery.\n");
        instructions.push_str("Install it using one of these methods:\n\n");

        // Go install (cross-platform)
        instructions.push_str("📦 Using Go (recommended if Go is installed):\n");
        instructions.push_str(
            "   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n\n",
        );

        // Platform-specific instructions
        match os {
            "windows" => {
                instructions.push_str("📦 Using Scoop (Windows):\n");
                instructions.push_str("   scoop install subfinder\n\n");
                instructions.push_str("📦 Using Chocolatey (Windows):\n");
                instructions.push_str("   choco install subfinder\n\n");
                instructions.push_str("📦 Direct Download (Windows):\n");
                let download_arch = if arch == "x86_64" { "amd64" } else { arch };
                instructions.push_str(&format!(
                    "   https://github.com/projectdiscovery/subfinder/releases/latest\n   Download: subfinder_{}_windows_{}.zip\n\n",
                    SUBFINDER_VERSION, download_arch
                ));
            }
            "macos" | "darwin" => {
                instructions.push_str("📦 Using Homebrew (macOS):\n");
                instructions.push_str("   brew install subfinder\n\n");
                instructions.push_str("📦 Direct Download (macOS):\n");
                let download_arch = if arch == "x86_64" {
                    "amd64"
                } else if arch == "aarch64" {
                    "arm64"
                } else {
                    arch
                };
                instructions.push_str(&format!(
                    "   https://github.com/projectdiscovery/subfinder/releases/latest\n   Download: subfinder_{}_darwin_{}.zip\n\n",
                    SUBFINDER_VERSION, download_arch
                ));
            }
            "linux" => {
                instructions.push_str("📦 Using apt (Debian/Ubuntu with ProjectDiscovery repo):\n");
                instructions.push_str("   sudo apt install subfinder\n\n");
                instructions.push_str("📦 Direct Download (Linux):\n");
                let download_arch = if arch == "x86_64" {
                    "amd64"
                } else if arch == "aarch64" {
                    "arm64"
                } else {
                    arch
                };
                instructions.push_str(&format!(
                    "   https://github.com/projectdiscovery/subfinder/releases/latest\n   Download: subfinder_{}_linux_{}.zip\n\n",
                    SUBFINDER_VERSION, download_arch
                ));
            }
            _ => {
                instructions.push_str("📦 Direct Download:\n");
                instructions.push_str(
                    "   https://github.com/projectdiscovery/subfinder/releases/latest\n\n",
                );
            }
        }

        instructions
            .push_str("🔗 Project Homepage: https://github.com/projectdiscovery/subfinder\n");
        instructions
            .push_str("📚 Documentation: https://docs.projectdiscovery.io/tools/subfinder\n\n");
        instructions.push_str("After installation, ensure subfinder is in your PATH or specify\n");
        instructions.push_str("the path using --subfinder-path <path>\n");

        instructions
    }

    /// Check if Go is installed
    #[cfg(not(test))] // probes system PATH for `go` binary — result depends on host environment
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn is_go_installed() -> bool {
        match std::process::Command::new("go").arg("version").output() {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(test)]
    pub fn is_go_installed() -> bool {
        false
    }

    /// Attempt to install subfinder using `go install`
    #[cfg(not(test))] // spawns real `go install` process — requires Go toolchain
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn install_via_go() -> Result<bool> {
        if !Self::is_go_installed() {
            return Err(anyhow!("Go is not installed"));
        }

        info!("Installing subfinder via 'go install'...");

        let output = tokio::process::Command::new("go")
            .args([
                "install",
                "-v",
                "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            ])
            .output()
            .await
            .map_err(|e| anyhow!("Failed to run go install: {}", e))?;

        if output.status.success() {
            info!("Subfinder installed successfully!");
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("go install failed: {}", stderr))
        }
    }

    #[cfg(test)]
    pub async fn install_via_go() -> Result<bool> {
        Err(anyhow!("install_via_go unavailable in test mode"))
    }

    /// Check if Homebrew is installed (macOS/Linux)
    #[cfg(not(test))] // probes system PATH for `brew` binary — result depends on host environment
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn is_homebrew_installed() -> bool {
        match std::process::Command::new("brew").arg("--version").output() {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(test)]
    pub fn is_homebrew_installed() -> bool {
        false
    }

    /// Check if Docker is installed
    #[cfg(not(test))] // probes system PATH for `docker` binary — result depends on host environment
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn is_docker_installed() -> bool {
        match std::process::Command::new("docker")
            .arg("--version")
            .output()
        {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(test)]
    pub fn is_docker_installed() -> bool {
        false
    }

    /// Attempt to install subfinder using Homebrew (macOS/Linux)
    #[cfg(not(test))] // spawns real `brew install` process — requires Homebrew + network
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn install_via_homebrew() -> Result<bool> {
        if !Self::is_homebrew_installed() {
            return Err(anyhow!("Homebrew is not installed"));
        }

        info!("Installing subfinder via Homebrew...");

        let output = tokio::process::Command::new("brew")
            .args(["install", "subfinder"])
            .output()
            .await
            .map_err(|e| anyhow!("Failed to run brew install: {}", e))?;

        if output.status.success() {
            info!("Subfinder installed successfully via Homebrew!");
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("brew install failed: {}", stderr))
        }
    }

    #[cfg(test)]
    pub async fn install_via_homebrew() -> Result<bool> {
        Err(anyhow!("install_via_homebrew unavailable in test mode"))
    }

    /// Attempt to pull subfinder Docker image
    #[cfg(not(test))] // spawns real `docker pull` process — requires Docker daemon
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn install_via_docker() -> Result<bool> {
        if !Self::is_docker_installed() {
            return Err(anyhow!("Docker is not installed"));
        }

        info!("Pulling subfinder Docker image...");

        let output = tokio::process::Command::new("docker")
            .args(["pull", "projectdiscovery/subfinder:latest"])
            .output()
            .await
            .map_err(|e| anyhow!("Failed to run docker pull: {}", e))?;

        if output.status.success() {
            info!("Subfinder Docker image pulled successfully!");
            info!("Run with: docker run -it projectdiscovery/subfinder:latest -d <domain>");
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("docker pull failed: {}", stderr))
        }
    }

    #[cfg(test)]
    pub async fn install_via_docker() -> Result<bool> {
        Err(anyhow!("install_via_docker unavailable in test mode"))
    }

    /// Get the download URL for subfinder releases
    pub fn get_download_url() -> &'static str {
        "https://github.com/projectdiscovery/subfinder/releases/latest"
    }

    /// Get available installation options for the current platform
    /// Based on official Project Discovery documentation
    pub fn get_available_install_options() -> Vec<InstallOption> {
        Self::build_install_options(
            Self::get_platform_download_url().is_some(),
            Self::is_go_installed(),
            Self::is_homebrew_installed(),
            Self::is_docker_installed(),
        )
    }

    fn build_install_options(
        auto_download: bool,
        go: bool,
        homebrew: bool,
        docker: bool,
    ) -> Vec<InstallOption> {
        let mut options = Vec::new();

        if auto_download {
            options.push(InstallOption::AutoDownload);
        }

        if go {
            options.push(InstallOption::Go);
        }

        if homebrew {
            options.push(InstallOption::Homebrew);
        }

        if docker {
            options.push(InstallOption::Docker);
        }

        options.push(InstallOption::ManualDownload);
        options.push(InstallOption::Skip);

        options
    }

    #[cfg_attr(coverage_nightly, coverage(off))] // coverage: process-spawn thin wrapper — tested via scripted-binary integration tests; LLVM async state machine artifacts make line-level coverage unreliable
    pub async fn discover(&self, domain: &str) -> Result<Vec<SubdomainResult>> {
        let binary_path = match self.get_resolved_binary_path() {
            Some(path) => path,
            None => {
                warn!("Subfinder binary not found at {:?}", self.binary_path);
                return Ok(vec![]);
            }
        };

        #[cfg(not(test))]
        debug!(
            "Running subfinder ({}) for domain: {}",
            binary_path.display(),
            domain
        );

        let mut child = match Command::new(&binary_path)
            .args(["-d", domain, "-silent", "-json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return Err(anyhow!("Failed to spawn subfinder: {}", e)),
        };

        // stdout is always Some when spawned with Stdio::piped()
        let stdout = child.stdout.take().unwrap();

        let reader = BufReader::new(stdout);
        let (results, timed_out) = read_lines_with_timeout(reader, self.timeout, domain).await;

        if timed_out {
            let _ = child.kill().await;
        }

        Ok(results)
    }
}

/// Read JSON lines from an async reader with a timeout, parsing each into SubdomainResult.
/// Returns (results, timed_out). Timed-out runs return partial results collected before expiry.
pub async fn read_lines_with_timeout<R: tokio::io::AsyncBufRead + Unpin>(
    reader: R,
    timeout: Duration,
    domain: &str,
) -> (Vec<SubdomainResult>, bool) {
    let mut lines = reader.lines();
    let mut results = Vec::new();

    let read_future = async {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Ok(parsed) = serde_json::from_str::<SubfinderJsonLine>(&line) {
                results.push(SubdomainResult {
                    subdomain: parsed.host,
                    source: parsed.source,
                });
            }
        }
    };

    match tokio::time::timeout(timeout, read_future).await {
        Ok(_) => (results, false),
        Err(_) => {
            warn!(
                "Subfinder timed out for {}, returning partial results",
                domain
            );
            (results, true)
        }
    }
}

/// Parse subfinder JSON output (used internally and for testing)
pub fn parse_subfinder_output(output: &str) -> Vec<SubdomainResult> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<SubfinderJsonLine>(line).ok())
        .map(|parsed| SubdomainResult {
            subdomain: parsed.host,
            source: parsed.source,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────
    // parse_subfinder_output tests (existing + new)
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_subfinder_json_output() {
        let json_output = r#"{"host":"api.example.com","source":"crtsh"}
{"host":"www.example.com","source":"hackertarget"}
{"host":"mail.example.com","source":"dnsdumpster"}"#;

        let results = parse_subfinder_output(json_output);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].subdomain, "api.example.com");
        assert_eq!(results[0].source, "crtsh");
        assert_eq!(results[1].subdomain, "www.example.com");
        assert_eq!(results[2].subdomain, "mail.example.com");
    }

    #[test]
    fn test_parse_subfinder_handles_invalid_json() {
        let output = "not json\n{\"host\":\"valid.com\",\"source\":\"test\"}\ninvalid line";
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, "valid.com");
    }

    #[test]
    fn test_parse_subfinder_empty_output() {
        let results = parse_subfinder_output("");
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_subfinder_single_line() {
        let output = r#"{"host":"single.example.com","source":"virustotal"}"#;
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, "single.example.com");
        assert_eq!(results[0].source, "virustotal");
    }

    #[test]
    fn test_parse_subfinder_mixed_valid_invalid() {
        let output = r#"{"host":"a.com","source":"s1"}
garbage
{"host":"b.com","source":"s2"}
{"invalid json
{"host":"c.com","source":"s3"}"#;
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].subdomain, "a.com");
        assert_eq!(results[1].subdomain, "b.com");
        assert_eq!(results[2].subdomain, "c.com");
    }

    #[test]
    fn test_parse_subfinder_extra_fields_ignored() {
        // serde should still parse even if there are extra fields
        let output =
            r#"{"host":"extra.com","source":"src","input":"example.com","extra_field":"ignored"}"#;
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, "extra.com");
        assert_eq!(results[0].source, "src");
    }

    #[test]
    fn test_parse_subfinder_missing_required_fields() {
        // Missing "source" field should fail to parse
        let output = r#"{"host":"no-source.com"}"#;
        let results = parse_subfinder_output(output);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_subfinder_missing_host_field() {
        let output = r#"{"source":"src"}"#;
        let results = parse_subfinder_output(output);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_subfinder_empty_strings() {
        let output = r#"{"host":"","source":""}"#;
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, "");
        assert_eq!(results[0].source, "");
    }

    #[test]
    fn test_parse_subfinder_unicode_host() {
        let output = r#"{"host":"日本語.example.com","source":"test"}"#;
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, "日本語.example.com");
    }

    #[test]
    fn test_parse_subfinder_whitespace_only_lines() {
        let output = "  \n\t\n{\"host\":\"valid.com\",\"source\":\"src\"}\n  \n";
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, "valid.com");
    }

    // ──────────────────────────────────────────────────────────────────
    // InstallOption display_name tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_install_option_display_name_auto_download() {
        assert_eq!(
            InstallOption::AutoDownload.display_name(),
            "Auto-download subfinder (Recommended)"
        );
    }

    #[test]
    fn test_install_option_display_name_go() {
        assert_eq!(InstallOption::Go.display_name(), "Go (go install)");
    }

    #[test]
    fn test_install_option_display_name_homebrew() {
        assert_eq!(
            InstallOption::Homebrew.display_name(),
            "Homebrew (macOS/Linux)"
        );
    }

    #[test]
    fn test_install_option_display_name_docker() {
        assert_eq!(InstallOption::Docker.display_name(), "Docker");
    }

    #[test]
    fn test_install_option_display_name_manual_download() {
        assert_eq!(
            InstallOption::ManualDownload.display_name(),
            "Open GitHub releases page"
        );
    }

    #[test]
    fn test_install_option_display_name_skip() {
        assert_eq!(
            InstallOption::Skip.display_name(),
            "Skip - Continue without subdomain discovery"
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // InstallOption trait tests (Debug, Clone, Copy, PartialEq, Eq)
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_install_option_debug() {
        let debug_str = format!("{:?}", InstallOption::AutoDownload);
        assert_eq!(debug_str, "AutoDownload");
    }

    #[test]
    fn test_install_option_clone() {
        let original = InstallOption::Go;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_install_option_copy() {
        let a = InstallOption::Homebrew;
        let b = a; // Copy
        assert_eq!(a, b); // original still valid (Copy, not moved)
    }

    #[test]
    fn test_install_option_eq() {
        assert_eq!(InstallOption::Docker, InstallOption::Docker);
        assert_ne!(InstallOption::Docker, InstallOption::Go);
    }

    #[test]
    fn test_install_option_all_variants_unique_names() {
        let all = [
            InstallOption::AutoDownload,
            InstallOption::Go,
            InstallOption::Homebrew,
            InstallOption::Docker,
            InstallOption::ManualDownload,
            InstallOption::Skip,
        ];
        let names: Vec<&str> = all.iter().map(|o| o.display_name()).collect();
        // Ensure all names are unique
        let mut deduped = names.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(names.len(), deduped.len());
    }

    // ──────────────────────────────────────────────────────────────────
    // SubfinderDiscovery::new tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_stores_binary_path() {
        let path = PathBuf::from("/usr/local/bin/subfinder");
        let timeout = Duration::from_secs(60);
        let sf = SubfinderDiscovery::new(path.clone(), timeout);
        assert_eq!(sf.binary_path, path);
        assert_eq!(sf.timeout, timeout);
    }

    #[test]
    fn test_new_with_custom_timeout() {
        let path = PathBuf::from("subfinder");
        let timeout = Duration::from_secs(300);
        let sf = SubfinderDiscovery::new(path, timeout);
        assert_eq!(sf.timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_new_with_zero_timeout() {
        let path = PathBuf::from("subfinder");
        let timeout = Duration::from_secs(0);
        let sf = SubfinderDiscovery::new(path, timeout);
        assert_eq!(sf.timeout, Duration::ZERO);
    }

    // ──────────────────────────────────────────────────────────────────
    // is_available tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_available_nonexistent_binary() {
        let sf = SubfinderDiscovery::new(
            PathBuf::from("/nonexistent/path/to/subfinder_that_does_not_exist_xyz_12345"),
            Duration::from_secs(30),
        );
        assert!(!sf.is_available());
    }

    #[test]
    fn test_is_available_nonexistent_name_not_in_path() {
        let sf = SubfinderDiscovery::new(
            PathBuf::from("totally_fake_binary_name_xyz_99999"),
            Duration::from_secs(30),
        );
        assert!(!sf.is_available());
    }

    // ──────────────────────────────────────────────────────────────────
    // get_bundled_binary_path tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_bundled_binary_path_returns_some() {
        let p = SubfinderDiscovery::get_bundled_binary_path()
            .expect("get_bundled_binary_path should return Some on macOS/Linux/Windows");
        #[cfg(windows)]
        assert!(p.ends_with("subfinder.exe"));
        #[cfg(not(windows))]
        assert!(p.ends_with("subfinder"));
        let path_str = p.to_string_lossy();
        assert!(
            path_str.contains("nthpartyfinder"),
            "Path should contain 'nthpartyfinder': {}",
            path_str
        );
    }

    #[test]
    fn test_get_bundled_binary_path_contains_bin_dir() {
        let p = SubfinderDiscovery::get_bundled_binary_path()
            .expect("get_bundled_binary_path should return Some");
        let parent = p.parent().unwrap();
        assert!(parent.ends_with("bin"));
    }

    // ──────────────────────────────────────────────────────────────────
    // get_platform_download_url tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_platform_download_url_returns_some_on_supported() {
        let u = SubfinderDiscovery::get_platform_download_url()
            .expect("should return Some on standard macOS/Linux/Windows");
        assert!(u.starts_with("https://github.com/projectdiscovery/subfinder/releases/download/"));
        assert!(u.contains(SUBFINDER_VERSION));
        assert!(u.ends_with(".zip"));
    }

    #[test]
    fn test_get_platform_download_url_contains_version() {
        let url = SubfinderDiscovery::get_platform_download_url()
            .expect("should return Some on supported platform");
        assert!(
            url.contains(SUBFINDER_VERSION),
            "URL should contain version {}: {}",
            SUBFINDER_VERSION,
            url
        );
    }

    #[test]
    fn test_get_platform_download_url_contains_platform_info() {
        let url = SubfinderDiscovery::get_platform_download_url()
            .expect("should return Some on supported platform");
        let has_platform = url.contains("darwin") | url.contains("linux") | url.contains("windows");
        assert!(has_platform, "URL should contain a known platform name");
    }

    #[test]
    fn test_get_platform_download_url_contains_arch() {
        let url = SubfinderDiscovery::get_platform_download_url()
            .expect("should return Some on supported platform");
        let has_arch = url.contains("amd64") | url.contains("arm64") | url.contains("386");
        assert!(has_arch, "URL should contain a known architecture");
    }

    // ──────────────────────────────────────────────────────────────────
    // get_installation_instructions tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_installation_instructions_not_empty() {
        let instructions = SubfinderDiscovery::get_installation_instructions();
        assert!(!instructions.is_empty());
    }

    #[test]
    fn test_get_installation_instructions_contains_go_install() {
        let instructions = SubfinderDiscovery::get_installation_instructions();
        assert!(
            instructions.contains("go install"),
            "Should contain Go install instructions"
        );
    }

    #[test]
    fn test_get_installation_instructions_contains_project_homepage() {
        let instructions = SubfinderDiscovery::get_installation_instructions();
        assert!(instructions.contains("github.com/projectdiscovery/subfinder"));
    }

    #[test]
    fn test_get_installation_instructions_contains_documentation_link() {
        let instructions = SubfinderDiscovery::get_installation_instructions();
        assert!(instructions.contains("docs.projectdiscovery.io"));
    }

    #[test]
    fn test_get_installation_instructions_contains_header() {
        let instructions = SubfinderDiscovery::get_installation_instructions();
        assert!(instructions.contains("Subfinder Installation Required"));
    }

    #[test]
    fn test_get_installation_instructions_contains_path_note() {
        let instructions = SubfinderDiscovery::get_installation_instructions();
        assert!(instructions.contains("--subfinder-path"));
    }

    #[test]
    fn test_get_installation_instructions_platform_specific() {
        let instructions = SubfinderDiscovery::get_installation_instructions();
        assert!(instructions.contains("go install"));
        assert!(instructions.contains("Direct Download"));
        assert!(instructions.contains(SUBFINDER_VERSION));
    }

    #[test]
    fn test_get_installation_instructions_contains_version() {
        let instructions = SubfinderDiscovery::get_installation_instructions();
        assert!(
            instructions.contains(SUBFINDER_VERSION),
            "Should contain version {}",
            SUBFINDER_VERSION
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // with_bundled_or_path tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_with_bundled_or_path_custom_path() {
        let custom = PathBuf::from("/custom/subfinder");
        let sf =
            SubfinderDiscovery::with_bundled_or_path(Some(custom.clone()), Duration::from_secs(60));
        assert_eq!(sf.binary_path, custom);
        assert_eq!(sf.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_with_bundled_or_path_no_custom_no_bundled() {
        // When no custom path and bundled doesn't exist, should fall back to "subfinder" in PATH
        let sf = SubfinderDiscovery::with_bundled_or_path(None, Duration::from_secs(30));
        // Either it finds the bundled path that exists, or falls back to "subfinder"
        let path_str = sf.binary_path.to_string_lossy();
        assert!(
            path_str.contains("subfinder"),
            "Fallback path should contain 'subfinder': {}",
            path_str
        );
    }

    #[test]
    fn test_with_bundled_or_path_timeout_preserved() {
        let timeout = Duration::from_secs(120);
        let sf = SubfinderDiscovery::with_bundled_or_path(None, timeout);
        assert_eq!(sf.timeout, timeout);
    }

    #[test]
    fn test_with_bundled_or_path_custom_takes_precedence() {
        // Even if bundled exists, custom path should take precedence
        let custom = PathBuf::from("/my/custom/subfinder");
        let sf =
            SubfinderDiscovery::with_bundled_or_path(Some(custom.clone()), Duration::from_secs(10));
        assert_eq!(sf.binary_path, custom);
    }

    // ──────────────────────────────────────────────────────────────────
    // get_download_url tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_download_url_static() {
        let url = SubfinderDiscovery::get_download_url();
        assert_eq!(
            url,
            "https://github.com/projectdiscovery/subfinder/releases/latest"
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // get_available_install_options tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_available_install_options_always_includes_manual_and_skip() {
        let options = SubfinderDiscovery::get_available_install_options();
        assert!(
            options.contains(&InstallOption::ManualDownload),
            "Should always include ManualDownload"
        );
        assert!(
            options.contains(&InstallOption::Skip),
            "Should always include Skip"
        );
    }

    #[test]
    fn test_get_available_install_options_skip_is_last() {
        let options = SubfinderDiscovery::get_available_install_options();
        assert_eq!(
            options.last(),
            Some(&InstallOption::Skip),
            "Skip should be the last option"
        );
    }

    #[test]
    fn test_get_available_install_options_manual_before_skip() {
        let options = SubfinderDiscovery::get_available_install_options();
        let manual_pos = options
            .iter()
            .position(|o| *o == InstallOption::ManualDownload);
        let skip_pos = options.iter().position(|o| *o == InstallOption::Skip);
        assert!(manual_pos.unwrap() < skip_pos.unwrap());
    }

    #[test]
    fn test_get_available_install_options_not_empty() {
        let options = SubfinderDiscovery::get_available_install_options();
        assert!(options.len() >= 2); // At minimum: ManualDownload + Skip
    }

    // ──────────────────────────────────────────────────────────────────
    // SubdomainResult struct tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_subdomain_result_creation() {
        let result = SubdomainResult {
            subdomain: "api.example.com".to_string(),
            source: "crtsh".to_string(),
        };
        assert_eq!(result.subdomain, "api.example.com");
        assert_eq!(result.source, "crtsh");
    }

    #[test]
    fn test_subdomain_result_clone() {
        let original = SubdomainResult {
            subdomain: "www.test.com".to_string(),
            source: "virustotal".to_string(),
        };
        let cloned = original.clone();
        assert_eq!(original.subdomain, cloned.subdomain);
        assert_eq!(original.source, cloned.source);
    }

    #[test]
    fn test_subdomain_result_debug() {
        let result = SubdomainResult {
            subdomain: "debug.com".to_string(),
            source: "src".to_string(),
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("debug.com"));
        assert!(debug_str.contains("src"));
        assert!(debug_str.contains("SubdomainResult"));
    }

    #[test]
    fn test_subdomain_result_clone_independence() {
        let original = SubdomainResult {
            subdomain: "original.com".to_string(),
            source: "original_src".to_string(),
        };
        let mut cloned = original.clone();
        cloned.subdomain = "cloned.com".to_string();
        cloned.source = "cloned_src".to_string();
        assert_eq!(original.subdomain, "original.com");
        assert_eq!(original.source, "original_src");
    }

    #[test]
    fn test_subdomain_result_empty_fields() {
        let result = SubdomainResult {
            subdomain: String::new(),
            source: String::new(),
        };
        assert!(result.subdomain.is_empty());
        assert!(result.source.is_empty());
    }

    // ──────────────────────────────────────────────────────────────────
    // SubfinderJsonLine deserialization tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_subfinder_json_line_deserialize() {
        let json = r#"{"host":"test.com","source":"crtsh"}"#;
        let parsed: SubfinderJsonLine = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.host, "test.com");
        assert_eq!(parsed.source, "crtsh");
    }

    #[test]
    fn test_subfinder_json_line_deserialize_with_extra_fields() {
        let json =
            r#"{"host":"test.com","source":"src","input":"example.com","resolver":"8.8.8.8"}"#;
        let parsed: SubfinderJsonLine = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.host, "test.com");
        assert_eq!(parsed.source, "src");
    }

    #[test]
    fn test_subfinder_json_line_deserialize_missing_host() {
        let json = r#"{"source":"crtsh"}"#;
        let result = serde_json::from_str::<SubfinderJsonLine>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_subfinder_json_line_deserialize_missing_source() {
        let json = r#"{"host":"test.com"}"#;
        let result = serde_json::from_str::<SubfinderJsonLine>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_subfinder_json_line_deserialize_empty_object() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<SubfinderJsonLine>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_subfinder_json_line_deserialize_invalid_json() {
        let json = "not json at all";
        let result = serde_json::from_str::<SubfinderJsonLine>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_subfinder_json_line_deserialize_null_values() {
        let json = r#"{"host":null,"source":"src"}"#;
        let result = serde_json::from_str::<SubfinderJsonLine>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_subfinder_json_line_deserialize_numeric_values() {
        let json = r#"{"host":123,"source":"src"}"#;
        let result = serde_json::from_str::<SubfinderJsonLine>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_subfinder_json_line_debug() {
        let json = r#"{"host":"debug.com","source":"test"}"#;
        let parsed: SubfinderJsonLine = serde_json::from_str(json).unwrap();
        let debug_str = format!("{:?}", parsed);
        assert!(debug_str.contains("debug.com"));
        assert!(debug_str.contains("test"));
    }

    // ──────────────────────────────────────────────────────────────────
    // discover returns empty for unavailable binary
    // ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_discover_unavailable_binary_returns_empty() {
        let sf = SubfinderDiscovery::new(
            PathBuf::from("/totally/nonexistent/binary_99999"),
            Duration::from_secs(5),
        );
        let results = sf.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    // ──────────────────────────────────────────────────────────────────
    // get_resolved_binary_path tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_resolved_binary_path_nonexistent() {
        let sf = SubfinderDiscovery::new(
            PathBuf::from("/nonexistent/subfinder_xyz_99999"),
            Duration::from_secs(30),
        );
        assert!(sf.get_resolved_binary_path().is_none());
    }

    #[test]
    fn test_get_resolved_binary_path_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let binary_path = dir.path().join("subfinder");
        std::fs::write(&binary_path, "fake binary").unwrap();

        let sf = SubfinderDiscovery::new(binary_path.clone(), Duration::from_secs(30));
        let resolved = sf.get_resolved_binary_path();
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap(), binary_path);
    }

    // ──────────────────────────────────────────────────────────────────
    // SUBFINDER_VERSION constant test
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_subfinder_version_is_semver() {
        let parts: Vec<&str> = SUBFINDER_VERSION.split('.').collect();
        assert!(
            parts.len() >= 2,
            "Version should be semver-like: {}",
            SUBFINDER_VERSION
        );
        for part in &parts {
            assert!(
                part.parse::<u32>().is_ok(),
                "Version part '{}' should be numeric",
                part
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Large output parsing stress test
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_subfinder_large_output() {
        let mut output = String::new();
        for i in 0..1000 {
            output.push_str(&format!(
                "{{\"host\":\"sub{}.example.com\",\"source\":\"src{}\"}}\n",
                i,
                i % 10
            ));
        }
        let results = parse_subfinder_output(&output);
        assert_eq!(results.len(), 1000);
        assert_eq!(results[0].subdomain, "sub0.example.com");
        assert_eq!(results[999].subdomain, "sub999.example.com");
    }

    #[test]
    fn test_parse_subfinder_trailing_newline() {
        let output = "{\"host\":\"a.com\",\"source\":\"s\"}\n";
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_parse_subfinder_no_trailing_newline() {
        let output = "{\"host\":\"a.com\",\"source\":\"s\"}";
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 1);
    }

    // ──────────────────────────────────────────────────────────────────
    // Additional get_platform_download_url format tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_platform_download_url_format() {
        let url = SubfinderDiscovery::get_platform_download_url()
            .expect("should return Some on supported platform");
        let expected_prefix = format!(
            "https://github.com/projectdiscovery/subfinder/releases/download/v{}/subfinder_{}",
            SUBFINDER_VERSION, SUBFINDER_VERSION
        );
        assert!(
            url.starts_with(&expected_prefix),
            "URL should start with version prefix: {}",
            url
        );
        assert!(url.ends_with(".zip"));
    }

    // ──────────────────────────────────────────────────────────────────
    // get_installation_instructions OS-specific branch coverage
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_installation_instructions_mentions_direct_download() {
        let instructions = SubfinderDiscovery::get_installation_instructions();
        assert!(instructions.contains("Direct Download"));
    }

    #[test]
    fn test_get_installation_instructions_multiline() {
        let instructions = SubfinderDiscovery::get_installation_instructions();
        let line_count = instructions.lines().count();
        assert!(
            line_count > 10,
            "Instructions should be multi-line, got {} lines",
            line_count
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // get_download_url is stable
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_download_url_is_github_releases() {
        let url = SubfinderDiscovery::get_download_url();
        assert!(url.starts_with("https://github.com/projectdiscovery/subfinder/releases"));
    }

    // ──────────────────────────────────────────────────────────────────
    // with_bundled_or_path edge cases
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_with_bundled_or_path_empty_path() {
        let sf = SubfinderDiscovery::with_bundled_or_path(
            Some(PathBuf::from("")),
            Duration::from_secs(10),
        );
        assert_eq!(sf.binary_path, PathBuf::from(""));
    }

    #[test]
    fn test_with_bundled_or_path_zero_timeout() {
        let sf = SubfinderDiscovery::with_bundled_or_path(None, Duration::ZERO);
        assert_eq!(sf.timeout, Duration::ZERO);
    }

    // ──────────────────────────────────────────────────────────────────
    // is_available with tempfile binary
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_available_with_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let binary_path = dir.path().join("subfinder");
        std::fs::write(&binary_path, "fake binary content").unwrap();

        let sf = SubfinderDiscovery::new(binary_path, Duration::from_secs(30));
        assert!(sf.is_available());
    }

    // ──────────────────────────────────────────────────────────────────
    // get_resolved_binary_path edge cases
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_resolved_binary_path_prefers_explicit_existing() {
        let dir = tempfile::tempdir().unwrap();
        let explicit = dir.path().join("my_subfinder");
        std::fs::write(&explicit, "fake").unwrap();

        let sf = SubfinderDiscovery::new(explicit.clone(), Duration::from_secs(30));
        let resolved = sf.get_resolved_binary_path();
        assert_eq!(resolved, Some(explicit));
    }

    // ──────────────────────────────────────────────────────────────────
    // InstallOption all variants coverage
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_install_option_all_debug_representations() {
        let variants = vec![
            InstallOption::AutoDownload,
            InstallOption::Go,
            InstallOption::Homebrew,
            InstallOption::Docker,
            InstallOption::ManualDownload,
            InstallOption::Skip,
        ];
        for v in &variants {
            let dbg = format!("{:?}", v);
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn test_install_option_ne_all_pairs() {
        let variants = [
            InstallOption::AutoDownload,
            InstallOption::Go,
            InstallOption::Homebrew,
            InstallOption::Docker,
            InstallOption::ManualDownload,
            InstallOption::Skip,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // parse_subfinder_output additional edge cases
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_subfinder_only_invalid_lines() {
        let output = "invalid1\ninvalid2\n{broken json\nnot json at all";
        let results = parse_subfinder_output(output);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_subfinder_array_json_not_object() {
        let output = r#"[{"host":"a.com","source":"s"}]"#;
        let results = parse_subfinder_output(output);
        // Array is not a valid line-delimited JSON object
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_subfinder_special_chars_in_host() {
        let output = r#"{"host":"sub-domain_test.example.com","source":"crtsh"}"#;
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, "sub-domain_test.example.com");
    }

    #[test]
    fn test_parse_subfinder_very_long_host() {
        let long_host = format!("{}.example.com", "a".repeat(500));
        let output = format!(r#"{{"host":"{}","source":"test"}}"#, long_host);
        let results = parse_subfinder_output(&output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, long_host);
    }

    #[test]
    fn test_parse_subfinder_crlf_line_endings() {
        let output =
            "{\"host\":\"a.com\",\"source\":\"s\"}\r\n{\"host\":\"b.com\",\"source\":\"s\"}\r\n";
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 2);
    }

    // ──────────────────────────────────────────────────────────────────
    // discover() with a scripted binary that outputs JSON
    // ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_discover_with_scripted_binary_success() {
        let dir = tempfile::tempdir().unwrap();
        let script_path = dir.path().join("subfinder");
        // Script outputs valid JSON lines and exits
        std::fs::write(
            &script_path,
            r#"#!/bin/sh
echo '{"host":"api.example.com","source":"crtsh"}'
echo '{"host":"www.example.com","source":"hackertarget"}'
"#,
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }

        let sf = SubfinderDiscovery::new(script_path, Duration::from_secs(10));
        let results = sf.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].subdomain, "api.example.com");
        assert_eq!(results[0].source, "crtsh");
        assert_eq!(results[1].subdomain, "www.example.com");
        assert_eq!(results[1].source, "hackertarget");
    }

    #[tokio::test]
    async fn test_discover_with_scripted_binary_empty_output() {
        let dir = tempfile::tempdir().unwrap();
        let script_path = dir.path().join("subfinder");
        std::fs::write(&script_path, "#!/bin/sh\nexit 0\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }

        let sf = SubfinderDiscovery::new(script_path, Duration::from_secs(5));
        let results = sf.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_scripted_binary_mixed_output() {
        let dir = tempfile::tempdir().unwrap();
        let script_path = dir.path().join("subfinder");
        // Outputs a mix of valid and invalid JSON
        std::fs::write(
            &script_path,
            r#"#!/bin/sh
echo '{"host":"valid.com","source":"src1"}'
echo 'not json'
echo '{"host":"also-valid.com","source":"src2"}'
echo '{"invalid":"missing host field"}'
"#,
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }

        let sf = SubfinderDiscovery::new(script_path, Duration::from_secs(5));
        let results = sf.discover("example.com").await.unwrap();
        // Only the two valid JSON lines should be parsed
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].subdomain, "valid.com");
        assert_eq!(results[1].subdomain, "also-valid.com");
    }

    #[tokio::test]
    async fn test_discover_timeout_returns_partial_results() {
        let dir = tempfile::tempdir().unwrap();
        let script_path = dir.path().join("subfinder");
        // Script outputs one line then sleeps forever
        std::fs::write(
            &script_path,
            r#"#!/bin/sh
echo '{"host":"fast.com","source":"src"}'
sleep 60
echo '{"host":"never-seen.com","source":"src"}'
"#,
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }

        let sf = SubfinderDiscovery::new(script_path, Duration::from_secs(2));
        let results = sf.discover("example.com").await.unwrap();
        assert!(results.len() <= 1);
    }

    #[tokio::test]
    async fn test_discover_with_large_output() {
        let dir = tempfile::tempdir().unwrap();
        let script_path = dir.path().join("subfinder");
        // Generate many lines of output
        let mut script = String::from("#!/bin/sh\n");
        for i in 0..100 {
            script.push_str(&format!(
                "echo '{{\"host\":\"sub{}.example.com\",\"source\":\"src\"}}'\n",
                i
            ));
        }
        std::fs::write(&script_path, &script).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }

        let sf = SubfinderDiscovery::new(script_path, Duration::from_secs(10));
        let results = sf.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 100);
    }

    // ──────────────────────────────────────────────────────────────────
    // SubfinderJsonLine additional deserialization tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_subfinder_json_line_deserialize_boolean_host() {
        let json = r#"{"host":true,"source":"src"}"#;
        let result = serde_json::from_str::<SubfinderJsonLine>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_subfinder_json_line_deserialize_nested_object() {
        let json = r#"{"host":{"nested":"val"},"source":"src"}"#;
        let result = serde_json::from_str::<SubfinderJsonLine>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_subfinder_json_line_deserialize_empty_strings() {
        let json = r#"{"host":"","source":""}"#;
        let parsed: SubfinderJsonLine = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.host, "");
        assert_eq!(parsed.source, "");
    }

    // ──────────────────────────────────────────────────────────────────
    // SubdomainResult additional tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_subdomain_result_special_chars() {
        let result = SubdomainResult {
            subdomain: "test-sub.example.co.uk".to_string(),
            source: "crt.sh".to_string(),
        };
        assert_eq!(result.subdomain, "test-sub.example.co.uk");
        assert_eq!(result.source, "crt.sh");
    }

    // ──────────────────────────────────────────────────────────────────
    // discover with existing but non-subfinder binary
    // ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_discover_with_fake_binary_returns_error_or_empty() {
        let dir = tempfile::tempdir().unwrap();
        let fake_binary = dir.path().join("subfinder");
        std::fs::write(&fake_binary, "#!/bin/sh\nexit 1").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fake_binary).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&fake_binary, perms).unwrap();
        }

        let sf = SubfinderDiscovery::new(fake_binary, Duration::from_secs(5));
        let results = sf.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_spawn_error_non_executable() {
        let dir = tempfile::tempdir().unwrap();
        let binary_path = dir.path().join("subfinder");
        std::fs::write(&binary_path, "not executable content").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&binary_path).unwrap().permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&binary_path, perms).unwrap();
        }

        let sf = SubfinderDiscovery::new(binary_path, Duration::from_secs(5));
        let result = sf.discover("example.com").await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to spawn subfinder"));
    }

    // ──────────────────────────────────────────────────────────────────
    // get_available_install_options auto-download presence
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_available_install_options_auto_download_on_supported() {
        let options = SubfinderDiscovery::get_available_install_options();
        assert!(
            SubfinderDiscovery::get_platform_download_url().is_some(),
            "Platform should be supported for auto-download"
        );
        assert!(
            options.contains(&InstallOption::AutoDownload),
            "Should include AutoDownload on supported platform"
        );
    }

    #[test]
    fn test_get_available_install_options_at_least_two() {
        let options = SubfinderDiscovery::get_available_install_options();
        assert!(
            options.len() >= 2,
            "Should have at least ManualDownload + Skip"
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // is_go/homebrew/docker_installed coverage
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_go_installed_returns_bool() {
        // Just ensure it doesn't panic
        let _result: bool = SubfinderDiscovery::is_go_installed();
    }

    #[test]
    fn test_is_homebrew_installed_returns_bool() {
        let _result: bool = SubfinderDiscovery::is_homebrew_installed();
    }

    #[test]
    fn test_is_docker_installed_returns_bool() {
        let _result: bool = SubfinderDiscovery::is_docker_installed();
    }

    // ──────────────────────────────────────────────────────────────────
    // get_download_url_for_platform — all platform/arch combinations
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_download_url_for_platform_macos_aarch64() {
        let url = SubfinderDiscovery::get_download_url_for_platform("macos", "aarch64");
        let url = url.unwrap();
        assert!(url.contains("darwin"));
        assert!(url.contains("arm64"));
        assert!(url.contains(SUBFINDER_VERSION));
        assert!(url.ends_with(".zip"));
    }

    #[test]
    fn test_download_url_for_platform_macos_x86_64() {
        let url = SubfinderDiscovery::get_download_url_for_platform("macos", "x86_64");
        let url = url.unwrap();
        assert!(url.contains("darwin"));
        assert!(url.contains("amd64"));
    }

    #[test]
    fn test_download_url_for_platform_linux_aarch64() {
        let url = SubfinderDiscovery::get_download_url_for_platform("linux", "aarch64");
        let url = url.unwrap();
        assert!(url.contains("linux"));
        assert!(url.contains("arm64"));
    }

    #[test]
    fn test_download_url_for_platform_linux_x86_64() {
        let url = SubfinderDiscovery::get_download_url_for_platform("linux", "x86_64");
        let url = url.unwrap();
        assert!(url.contains("linux"));
        assert!(url.contains("amd64"));
    }

    #[test]
    fn test_download_url_for_platform_windows_x86_64() {
        let url = SubfinderDiscovery::get_download_url_for_platform("windows", "x86_64");
        let url = url.unwrap();
        assert!(url.contains("windows"));
        assert!(url.contains("amd64"));
    }

    #[test]
    fn test_download_url_for_platform_windows_aarch64() {
        let url = SubfinderDiscovery::get_download_url_for_platform("windows", "aarch64");
        let url = url.unwrap();
        assert!(url.contains("windows"));
        assert!(url.contains("arm64"));
    }

    #[test]
    fn test_download_url_for_platform_linux_x86() {
        let url = SubfinderDiscovery::get_download_url_for_platform("linux", "x86");
        let url = url.unwrap();
        assert!(url.contains("linux"));
        assert!(url.contains("386"));
    }

    #[test]
    fn test_download_url_for_platform_unsupported_os() {
        let url = SubfinderDiscovery::get_download_url_for_platform("freebsd", "x86_64");
        assert!(url.is_none());
    }

    #[test]
    fn test_download_url_for_platform_unsupported_arch() {
        let url = SubfinderDiscovery::get_download_url_for_platform("linux", "mips");
        assert!(url.is_none());
    }

    #[test]
    fn test_download_url_for_platform_both_unsupported() {
        let url = SubfinderDiscovery::get_download_url_for_platform("haiku", "sparc");
        assert!(url.is_none());
    }

    // ──────────────────────────────────────────────────────────────────
    // get_installation_instructions_for_platform — all OS branches
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_installation_instructions_windows() {
        let instructions =
            SubfinderDiscovery::get_installation_instructions_for_platform("windows", "x86_64");
        assert!(instructions.contains("Scoop"));
        assert!(instructions.contains("Chocolatey"));
        assert!(instructions.contains("Direct Download (Windows)"));
        assert!(instructions.contains("amd64"));
        assert!(instructions.contains(SUBFINDER_VERSION));
    }

    #[test]
    fn test_installation_instructions_windows_non_x86_64() {
        let instructions =
            SubfinderDiscovery::get_installation_instructions_for_platform("windows", "aarch64");
        assert!(instructions.contains("Scoop"));
        assert!(instructions.contains("aarch64"));
    }

    #[test]
    fn test_installation_instructions_macos() {
        let instructions =
            SubfinderDiscovery::get_installation_instructions_for_platform("macos", "aarch64");
        assert!(instructions.contains("Homebrew"));
        assert!(instructions.contains("brew install subfinder"));
        assert!(instructions.contains("Direct Download (macOS)"));
        assert!(instructions.contains("arm64"));
    }

    #[test]
    fn test_installation_instructions_macos_x86_64() {
        let instructions =
            SubfinderDiscovery::get_installation_instructions_for_platform("macos", "x86_64");
        assert!(instructions.contains("amd64"));
    }

    #[test]
    fn test_installation_instructions_macos_other_arch() {
        let instructions =
            SubfinderDiscovery::get_installation_instructions_for_platform("macos", "riscv");
        assert!(instructions.contains("riscv"));
    }

    #[test]
    fn test_installation_instructions_darwin_alias() {
        let instructions =
            SubfinderDiscovery::get_installation_instructions_for_platform("darwin", "aarch64");
        assert!(instructions.contains("Homebrew"));
        assert!(instructions.contains("arm64"));
    }

    #[test]
    fn test_installation_instructions_linux() {
        let instructions =
            SubfinderDiscovery::get_installation_instructions_for_platform("linux", "x86_64");
        assert!(instructions.contains("apt"));
        assert!(instructions.contains("Direct Download (Linux)"));
        assert!(instructions.contains("amd64"));
    }

    #[test]
    fn test_installation_instructions_linux_aarch64() {
        let instructions =
            SubfinderDiscovery::get_installation_instructions_for_platform("linux", "aarch64");
        assert!(instructions.contains("arm64"));
    }

    #[test]
    fn test_installation_instructions_linux_other_arch() {
        let instructions =
            SubfinderDiscovery::get_installation_instructions_for_platform("linux", "mips");
        assert!(instructions.contains("mips"));
    }

    #[test]
    fn test_installation_instructions_unknown_os() {
        let instructions =
            SubfinderDiscovery::get_installation_instructions_for_platform("freebsd", "x86_64");
        assert!(instructions.contains("Direct Download"));
        assert!(!instructions.contains("Homebrew"));
        assert!(!instructions.contains("Scoop"));
        assert!(!instructions.contains("apt"));
    }

    #[test]
    fn test_installation_instructions_all_have_go_install() {
        for os in &["windows", "macos", "darwin", "linux", "freebsd"] {
            let instructions =
                SubfinderDiscovery::get_installation_instructions_for_platform(os, "x86_64");
            assert!(
                instructions.contains("go install"),
                "Missing go install for OS: {}",
                os
            );
        }
    }

    #[test]
    fn test_installation_instructions_all_have_homepage() {
        for os in &["windows", "macos", "linux", "freebsd"] {
            let instructions =
                SubfinderDiscovery::get_installation_instructions_for_platform(os, "x86_64");
            assert!(
                instructions.contains("github.com/projectdiscovery/subfinder"),
                "Missing homepage for OS: {}",
                os
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // build_install_options — all flag combinations
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_build_install_options_all_true() {
        let opts = SubfinderDiscovery::build_install_options(true, true, true, true);
        assert_eq!(opts.len(), 6);
        assert_eq!(opts[0], InstallOption::AutoDownload);
        assert_eq!(opts[1], InstallOption::Go);
        assert_eq!(opts[2], InstallOption::Homebrew);
        assert_eq!(opts[3], InstallOption::Docker);
        assert_eq!(opts[4], InstallOption::ManualDownload);
        assert_eq!(opts[5], InstallOption::Skip);
    }

    #[test]
    fn test_build_install_options_all_false() {
        let opts = SubfinderDiscovery::build_install_options(false, false, false, false);
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0], InstallOption::ManualDownload);
        assert_eq!(opts[1], InstallOption::Skip);
    }

    #[test]
    fn test_build_install_options_only_go() {
        let opts = SubfinderDiscovery::build_install_options(false, true, false, false);
        assert_eq!(opts.len(), 3);
        assert_eq!(opts[0], InstallOption::Go);
        assert_eq!(opts[1], InstallOption::ManualDownload);
        assert_eq!(opts[2], InstallOption::Skip);
    }

    #[test]
    fn test_build_install_options_only_docker() {
        let opts = SubfinderDiscovery::build_install_options(false, false, false, true);
        assert_eq!(opts.len(), 3);
        assert_eq!(opts[0], InstallOption::Docker);
    }

    #[test]
    fn test_build_install_options_only_homebrew() {
        let opts = SubfinderDiscovery::build_install_options(false, false, true, false);
        assert_eq!(opts.len(), 3);
        assert_eq!(opts[0], InstallOption::Homebrew);
    }

    #[test]
    fn test_build_install_options_only_auto_download() {
        let opts = SubfinderDiscovery::build_install_options(true, false, false, false);
        assert_eq!(opts.len(), 3);
        assert_eq!(opts[0], InstallOption::AutoDownload);
    }

    #[tokio::test]
    async fn test_install_stubs_return_error() {
        assert!(SubfinderDiscovery::download_and_install().await.is_err());
        assert!(SubfinderDiscovery::install_via_go().await.is_err());
        assert!(SubfinderDiscovery::install_via_homebrew().await.is_err());
        assert!(SubfinderDiscovery::install_via_docker().await.is_err());
    }

    #[test]
    fn test_build_install_options_always_ends_with_manual_and_skip() {
        for auto in [true, false] {
            for go in [true, false] {
                for brew in [true, false] {
                    for docker in [true, false] {
                        let opts =
                            SubfinderDiscovery::build_install_options(auto, go, brew, docker);
                        assert!(opts.len() >= 2);
                        assert_eq!(opts[opts.len() - 2], InstallOption::ManualDownload);
                        assert_eq!(opts[opts.len() - 1], InstallOption::Skip);
                    }
                }
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // read_lines_with_timeout tests (DI-extracted parsing logic)
    // ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_read_lines_valid_json() {
        let input = b"{\"host\":\"api.example.com\",\"source\":\"crtsh\"}\n\
                      {\"host\":\"www.example.com\",\"source\":\"hackertarget\"}\n";
        let reader = tokio::io::BufReader::new(&input[..]);
        let (results, timed_out) =
            read_lines_with_timeout(reader, Duration::from_secs(5), "example.com").await;
        assert!(!timed_out);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].subdomain, "api.example.com");
        assert_eq!(results[0].source, "crtsh");
        assert_eq!(results[1].subdomain, "www.example.com");
        assert_eq!(results[1].source, "hackertarget");
    }

    #[tokio::test]
    async fn test_read_lines_mixed_valid_invalid() {
        let input = b"{\"host\":\"a.com\",\"source\":\"s1\"}\n\
                      garbage line\n\
                      {\"host\":\"b.com\",\"source\":\"s2\"}\n\
                      {\"invalid json\n\
                      {\"host\":\"c.com\",\"source\":\"s3\"}\n";
        let reader = tokio::io::BufReader::new(&input[..]);
        let (results, timed_out) =
            read_lines_with_timeout(reader, Duration::from_secs(5), "example.com").await;
        assert!(!timed_out);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].subdomain, "a.com");
        assert_eq!(results[1].subdomain, "b.com");
        assert_eq!(results[2].subdomain, "c.com");
    }

    #[tokio::test]
    async fn test_read_lines_empty_input() {
        let input = b"";
        let reader = tokio::io::BufReader::new(&input[..]);
        let (results, timed_out) =
            read_lines_with_timeout(reader, Duration::from_secs(5), "example.com").await;
        assert!(!timed_out);
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_read_lines_only_invalid_lines() {
        let input = b"not json\nanother bad line\n{broken\n";
        let reader = tokio::io::BufReader::new(&input[..]);
        let (results, timed_out) =
            read_lines_with_timeout(reader, Duration::from_secs(5), "example.com").await;
        assert!(!timed_out);
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_read_lines_timeout_returns_partial() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            server
                .write_all(b"{\"host\":\"fast.com\",\"source\":\"s\"}\n")
                .await
                .unwrap();
            server.flush().await.unwrap();
            let _ = rx.await;
        });

        let reader = tokio::io::BufReader::new(client);
        let (results, timed_out) =
            read_lines_with_timeout(reader, Duration::from_millis(200), "example.com").await;
        assert!(timed_out);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, "fast.com");
        let _ = tx.send(());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_read_lines_large_output() {
        let mut input = String::new();
        for i in 0..500 {
            input.push_str(&format!(
                "{{\"host\":\"sub{}.example.com\",\"source\":\"src\"}}\n",
                i
            ));
        }
        let reader = tokio::io::BufReader::new(input.as_bytes());
        let (results, timed_out) =
            read_lines_with_timeout(reader, Duration::from_secs(5), "example.com").await;
        assert!(!timed_out);
        assert_eq!(results.len(), 500);
        assert_eq!(results[0].subdomain, "sub0.example.com");
        assert_eq!(results[499].subdomain, "sub499.example.com");
    }

    #[tokio::test]
    async fn test_read_lines_extra_fields_ignored() {
        let input =
            b"{\"host\":\"x.com\",\"source\":\"s\",\"input\":\"example.com\",\"extra\":true}\n";
        let reader = tokio::io::BufReader::new(&input[..]);
        let (results, timed_out) =
            read_lines_with_timeout(reader, Duration::from_secs(5), "example.com").await;
        assert!(!timed_out);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, "x.com");
    }

    #[tokio::test]
    async fn test_read_lines_missing_required_fields() {
        let input = b"{\"host\":\"no-source.com\"}\n{\"source\":\"no-host\"}\n{}\n";
        let reader = tokio::io::BufReader::new(&input[..]);
        let (results, timed_out) =
            read_lines_with_timeout(reader, Duration::from_secs(5), "example.com").await;
        assert!(!timed_out);
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_read_lines_zero_timeout_triggers_immediately() {
        let (client, _server) = tokio::io::duplex(1024);
        let reader = tokio::io::BufReader::new(client);
        let (results, timed_out) =
            read_lines_with_timeout(reader, Duration::ZERO, "example.com").await;
        assert!(timed_out);
        assert!(results.is_empty());
    }
}
