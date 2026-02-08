//! Subdomain discovery using Project Discovery's subfinder tool.

use anyhow::{Result, anyhow};
use serde::Deserialize;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::io::{BufReader, AsyncBufReadExt};
use tracing::{debug, warn, info};

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
        Self { binary_path, timeout }
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
        let binary_name = if cfg!(windows) { "subfinder.exe" } else { "subfinder" };

        // Use platform-appropriate data directory
        #[cfg(windows)]
        {
            std::env::var("LOCALAPPDATA").ok()
                .map(|p| PathBuf::from(p).join("nthpartyfinder").join("bin").join(binary_name))
        }
        #[cfg(not(windows))]
        {
            dirs::data_local_dir()
                .map(|p| p.join("nthpartyfinder").join("bin").join(binary_name))
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

        let install_dir = install_path.parent()
            .ok_or_else(|| anyhow!("Invalid installation path"))?;

        // Create the installation directory
        std::fs::create_dir_all(install_dir)
            .map_err(|e| anyhow!("Failed to create installation directory: {}", e))?;

        info!("Downloading subfinder v{} from GitHub...", SUBFINDER_VERSION);
        debug!("Download URL: {}", download_url);

        // Download the zip file
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

        let response = client.get(&download_url)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to download subfinder: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("Download failed with status: {}", response.status()));
        }

        let bytes = response.bytes()
            .await
            .map_err(|e| anyhow!("Failed to read download response: {}", e))?;

        info!("Downloaded {} bytes, extracting...", bytes.len());

        // Extract the zip file
        let cursor = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(cursor)
            .map_err(|e| anyhow!("Failed to open zip archive: {}", e))?;

        // Find and extract the subfinder binary
        let binary_name = if cfg!(windows) { "subfinder.exe" } else { "subfinder" };
        let mut found = false;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)
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
            return Err(anyhow!("Could not find subfinder binary in downloaded archive"));
        }

        info!("Subfinder installed to: {}", install_path.display());
        Ok(install_path)
    }

    /// Create a new SubfinderDiscovery using the bundled binary if available
    pub fn with_bundled_or_path(custom_path: Option<PathBuf>, timeout: Duration) -> Self {
        let binary_path = custom_path
            .or_else(|| Self::get_bundled_binary_path().filter(|p| p.exists()))
            .unwrap_or_else(|| PathBuf::from(if cfg!(windows) { "subfinder.exe" } else { "subfinder" }));

        Self::new(binary_path, timeout)
    }

    /// Get installation instructions for subfinder
    pub fn get_installation_instructions() -> String {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;

        let mut instructions = String::new();
        instructions.push_str("\n╔══════════════════════════════════════════════════════════════════╗\n");
        instructions.push_str("║           Subfinder Installation Required                        ║\n");
        instructions.push_str("╚══════════════════════════════════════════════════════════════════╝\n\n");
        instructions.push_str("Subfinder is a subdomain discovery tool by Project Discovery.\n");
        instructions.push_str("Install it using one of these methods:\n\n");

        // Go install (cross-platform)
        instructions.push_str("📦 Using Go (recommended if Go is installed):\n");
        instructions.push_str("   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n\n");

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
                let download_arch = if arch == "x86_64" { "amd64" } else if arch == "aarch64" { "arm64" } else { arch };
                instructions.push_str(&format!(
                    "   https://github.com/projectdiscovery/subfinder/releases/latest\n   Download: subfinder_{}_darwin_{}.zip\n\n",
                    SUBFINDER_VERSION, download_arch
                ));
            }
            "linux" => {
                instructions.push_str("📦 Using apt (Debian/Ubuntu with ProjectDiscovery repo):\n");
                instructions.push_str("   sudo apt install subfinder\n\n");
                instructions.push_str("📦 Direct Download (Linux):\n");
                let download_arch = if arch == "x86_64" { "amd64" } else if arch == "aarch64" { "arm64" } else { arch };
                instructions.push_str(&format!(
                    "   https://github.com/projectdiscovery/subfinder/releases/latest\n   Download: subfinder_{}_linux_{}.zip\n\n",
                    SUBFINDER_VERSION, download_arch
                ));
            }
            _ => {
                instructions.push_str("📦 Direct Download:\n");
                instructions.push_str("   https://github.com/projectdiscovery/subfinder/releases/latest\n\n");
            }
        }

        instructions.push_str("🔗 Project Homepage: https://github.com/projectdiscovery/subfinder\n");
        instructions.push_str("📚 Documentation: https://docs.projectdiscovery.io/tools/subfinder\n\n");
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
            .args(["install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"])
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

        debug!("Running subfinder ({}) for domain: {}", binary_path.display(), domain);

        let mut child = Command::new(&binary_path)
            .args(["-d", domain, "-silent", "-json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn subfinder: {}", e))?;

        let stdout = child.stdout.take()
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
                debug!("Subfinder found {} subdomains for {}", results.len(), domain);
            }
            Err(_) => {
                warn!("Subfinder timed out for {}, returning partial results", domain);
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
        .filter_map(|line| {
            serde_json::from_str::<SubfinderJsonLine>(line).ok()
        })
        .map(|parsed| SubdomainResult {
            subdomain: parsed.host,
            source: parsed.source,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
