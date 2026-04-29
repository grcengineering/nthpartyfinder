//! Subdomain discovery using Project Discovery's subfinder tool.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
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
    fn get_resolved_binary_path(&self) -> Option<PathBuf> {
        // Check explicit path first
        if self.binary_path.exists() {
            return Some(self.binary_path.clone());
        }
        if which::which(&self.binary_path).is_ok() {
            return Some(self.binary_path.clone());
        }
        // Check bundled location
        if let Some(bundled) = Self::get_bundled_binary_path() {
            if bundled.exists() {
                return Some(bundled);
            }
        }
        None
    }

    /// Get the path to the bundled subfinder binary in the app's data directory
    pub fn get_bundled_binary_path() -> Option<PathBuf> {
        let binary_name = if cfg!(windows) {
            "subfinder.exe"
        } else {
            "subfinder"
        };

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
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;

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

    /// Create a new SubfinderDiscovery using the bundled binary if available
    pub fn with_bundled_or_path(custom_path: Option<PathBuf>, timeout: Duration) -> Self {
        let binary_path = custom_path
            .or_else(|| Self::get_bundled_binary_path().filter(|p| p.exists()))
            .unwrap_or_else(|| {
                PathBuf::from(if cfg!(windows) {
                    "subfinder.exe"
                } else {
                    "subfinder"
                })
            });

        Self::new(binary_path, timeout)
    }

    /// Get installation instructions for subfinder
    pub fn get_installation_instructions() -> String {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;

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
    pub fn is_go_installed() -> bool {
        std::process::Command::new("go")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Attempt to install subfinder using `go install`
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

    /// Check if Homebrew is installed (macOS/Linux)
    pub fn is_homebrew_installed() -> bool {
        std::process::Command::new("brew")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if Docker is installed
    pub fn is_docker_installed() -> bool {
        std::process::Command::new("docker")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Attempt to install subfinder using Homebrew (macOS/Linux)
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

    /// Attempt to pull subfinder Docker image
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

    /// Get the download URL for subfinder releases
    pub fn get_download_url() -> &'static str {
        "https://github.com/projectdiscovery/subfinder/releases/latest"
    }

    /// Get available installation options for the current platform
    /// Based on official Project Discovery documentation
    pub fn get_available_install_options() -> Vec<InstallOption> {
        let mut options = Vec::new();

        // Auto-download is available on supported platforms (Windows, macOS, Linux with x86_64 or arm64)
        if Self::get_platform_download_url().is_some() {
            options.push(InstallOption::AutoDownload);
        }

        // Go install is available if Go is installed (works on all platforms)
        if Self::is_go_installed() {
            options.push(InstallOption::Go);
        }

        // Homebrew is available on macOS and Linux
        if Self::is_homebrew_installed() {
            options.push(InstallOption::Homebrew);
        }

        // Docker is available on all platforms if Docker is installed
        if Self::is_docker_installed() {
            options.push(InstallOption::Docker);
        }

        // Manual binary download is always available
        options.push(InstallOption::ManualDownload);
        options.push(InstallOption::Skip);

        options
    }

    pub async fn discover(&self, domain: &str) -> Result<Vec<SubdomainResult>> {
        let binary_path = match self.get_resolved_binary_path() {
            Some(path) => path,
            None => {
                warn!("Subfinder binary not found at {:?}", self.binary_path);
                return Ok(vec![]);
            }
        };

        debug!(
            "Running subfinder ({}) for domain: {}",
            binary_path.display(),
            domain
        );

        let mut child = Command::new(&binary_path)
            .args(["-d", domain, "-silent", "-json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn subfinder: {}", e))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to capture subfinder stdout"))?;

        let mut reader = BufReader::new(stdout).lines();
        let mut results = Vec::new();

        // M017 known limitation: if the timeout fires while output is being read, the results
        // may be incomplete (partial last line is dropped by the JSON parser). This is acceptable
        // because: (1) each line is a complete JSON object, so we never get corrupt data, and
        // (2) partial results are still useful for discovery. The timeout wraps the entire read
        // loop, so all lines read before timeout are captured.
        let read_future = async {
            while let Ok(Some(line)) = reader.next_line().await {
                if let Ok(parsed) = serde_json::from_str::<SubfinderJsonLine>(&line) {
                    results.push(SubdomainResult {
                        subdomain: parsed.host,
                        source: parsed.source,
                    });
                }
            }
        };

        match tokio::time::timeout(self.timeout, read_future).await {
            Ok(_) => {
                debug!(
                    "Subfinder found {} subdomains for {}",
                    results.len(),
                    domain
                );
            }
            Err(_) => {
                warn!(
                    "Subfinder timed out for {}, returning partial results",
                    domain
                );
                let _ = child.kill().await;
            }
        }

        Ok(results)
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
        let output = r#"{"host":"extra.com","source":"src","input":"example.com","extra_field":"ignored"}"#;
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
        let cloned = original.clone();
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
        let all = vec![
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
        // On most systems, data_local_dir() should return Some
        let path = SubfinderDiscovery::get_bundled_binary_path();
        // May be None on exotic systems, but should be Some on macOS/Linux/Windows
        if let Some(p) = path {
            assert!(p.ends_with("subfinder") || p.ends_with("subfinder.exe"));
            // Should contain our app name in the path
            let path_str = p.to_string_lossy();
            assert!(
                path_str.contains("nthpartyfinder"),
                "Path should contain 'nthpartyfinder': {}",
                path_str
            );
        }
    }

    #[test]
    fn test_get_bundled_binary_path_contains_bin_dir() {
        if let Some(p) = SubfinderDiscovery::get_bundled_binary_path() {
            let parent = p.parent().unwrap();
            assert!(
                parent.ends_with("bin"),
                "Parent should be 'bin' dir, got: {}",
                parent.display()
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // get_platform_download_url tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_platform_download_url_returns_some_on_supported() {
        // This test runs on a supported platform (macOS/Linux/Windows with x86_64/arm64)
        let url = SubfinderDiscovery::get_platform_download_url();
        // Should return Some on CI/dev machines
        if let Some(u) = url {
            assert!(u.starts_with("https://github.com/projectdiscovery/subfinder/releases/download/"));
            assert!(u.contains(SUBFINDER_VERSION));
            assert!(u.ends_with(".zip"));
        }
    }

    #[test]
    fn test_get_platform_download_url_contains_version() {
        if let Some(url) = SubfinderDiscovery::get_platform_download_url() {
            assert!(
                url.contains(SUBFINDER_VERSION),
                "URL should contain version {}: {}",
                SUBFINDER_VERSION,
                url
            );
        }
    }

    #[test]
    fn test_get_platform_download_url_contains_platform_info() {
        if let Some(url) = SubfinderDiscovery::get_platform_download_url() {
            let os = std::env::consts::OS;
            match os {
                "macos" => assert!(url.contains("darwin"), "macOS URL should contain 'darwin': {}", url),
                "linux" => assert!(url.contains("linux"), "Linux URL should contain 'linux': {}", url),
                "windows" => assert!(url.contains("windows"), "Windows URL should contain 'windows': {}", url),
                _ => {} // Skip on unsupported
            }
        }
    }

    #[test]
    fn test_get_platform_download_url_contains_arch() {
        if let Some(url) = SubfinderDiscovery::get_platform_download_url() {
            let arch = std::env::consts::ARCH;
            match arch {
                "x86_64" => assert!(url.contains("amd64"), "x86_64 URL should contain 'amd64': {}", url),
                "aarch64" => assert!(url.contains("arm64"), "aarch64 URL should contain 'arm64': {}", url),
                _ => {}
            }
        }
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
        let os = std::env::consts::OS;
        match os {
            "macos" | "darwin" => {
                assert!(
                    instructions.contains("Homebrew"),
                    "macOS instructions should mention Homebrew"
                );
                assert!(instructions.contains("brew install subfinder"));
            }
            "linux" => {
                assert!(
                    instructions.contains("apt"),
                    "Linux instructions should mention apt"
                );
            }
            "windows" => {
                assert!(
                    instructions.contains("Scoop") || instructions.contains("Chocolatey"),
                    "Windows instructions should mention Scoop or Chocolatey"
                );
            }
            _ => {}
        }
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
        let sf = SubfinderDiscovery::with_bundled_or_path(Some(custom.clone()), Duration::from_secs(60));
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
        let sf = SubfinderDiscovery::with_bundled_or_path(Some(custom.clone()), Duration::from_secs(10));
        assert_eq!(sf.binary_path, custom);
    }

    // ──────────────────────────────────────────────────────────────────
    // get_download_url tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_download_url_static() {
        let url = SubfinderDiscovery::get_download_url();
        assert_eq!(url, "https://github.com/projectdiscovery/subfinder/releases/latest");
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
        let manual_pos = options.iter().position(|o| *o == InstallOption::ManualDownload);
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
        let json = r#"{"host":"test.com","source":"src","input":"example.com","resolver":"8.8.8.8"}"#;
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
        // If bundled binary also doesn't exist, should return None
        // (may return Some if bundled exists on the system)
        let resolved = sf.get_resolved_binary_path();
        if let Some(p) = &resolved {
            // If it resolved, it should be to the bundled path (not our nonexistent one)
            assert!(p.exists(), "Resolved path should exist: {}", p.display());
        }
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
                i, i % 10
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
        if let Some(url) = SubfinderDiscovery::get_platform_download_url() {
            // Should follow the pattern: .../v{VERSION}/subfinder_{VERSION}_{OS}_{ARCH}.zip
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
        let lines: Vec<&str> = instructions.lines().collect();
        assert!(lines.len() > 10, "Instructions should be multi-line, got {} lines", lines.len());
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
        let variants = vec![
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
        let output = "{\"host\":\"a.com\",\"source\":\"s\"}\r\n{\"host\":\"b.com\",\"source\":\"s\"}\r\n";
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 2);
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
        let result = sf.discover("example.com").await;
        // Either empty results or an error -- both are acceptable
        match result {
            Ok(results) => assert!(results.is_empty()),
            Err(_) => {} // spawn error is also acceptable
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // get_available_install_options auto-download presence
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_available_install_options_auto_download_on_supported() {
        let options = SubfinderDiscovery::get_available_install_options();
        // On any CI/dev machine (macOS/Linux/Windows with standard arch), AutoDownload should be present
        if SubfinderDiscovery::get_platform_download_url().is_some() {
            assert!(
                options.contains(&InstallOption::AutoDownload),
                "Should include AutoDownload on supported platform"
            );
        }
    }

    #[test]
    fn test_get_available_install_options_at_least_two() {
        let options = SubfinderDiscovery::get_available_install_options();
        assert!(options.len() >= 2, "Should have at least ManualDownload + Skip");
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
}
