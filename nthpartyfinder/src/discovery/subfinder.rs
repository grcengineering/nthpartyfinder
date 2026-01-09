//! Subdomain discovery using Project Discovery's subfinder tool.

use anyhow::{Result, anyhow};
use serde::Deserialize;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::io::{BufReader, AsyncBufReadExt};
use tracing::{debug, warn, info};

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
        self.binary_path.exists() || which::which(&self.binary_path).is_ok()
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
                    "2.6.7", download_arch
                ));
            }
            "macos" | "darwin" => {
                instructions.push_str("📦 Using Homebrew (macOS):\n");
                instructions.push_str("   brew install subfinder\n\n");
                instructions.push_str("📦 Direct Download (macOS):\n");
                let download_arch = if arch == "x86_64" { "amd64" } else if arch == "aarch64" { "arm64" } else { arch };
                instructions.push_str(&format!(
                    "   https://github.com/projectdiscovery/subfinder/releases/latest\n   Download: subfinder_{}_darwin_{}.zip\n\n",
                    "2.6.7", download_arch
                ));
            }
            "linux" => {
                instructions.push_str("📦 Using apt (Debian/Ubuntu with ProjectDiscovery repo):\n");
                instructions.push_str("   sudo apt install subfinder\n\n");
                instructions.push_str("📦 Direct Download (Linux):\n");
                let download_arch = if arch == "x86_64" { "amd64" } else if arch == "aarch64" { "arm64" } else { arch };
                instructions.push_str(&format!(
                    "   https://github.com/projectdiscovery/subfinder/releases/latest\n   Download: subfinder_{}_linux_{}.zip\n\n",
                    "2.6.7", download_arch
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

    pub async fn discover(&self, domain: &str) -> Result<Vec<SubdomainResult>> {
        if !self.is_available() {
            warn!("Subfinder binary not found at {:?}", self.binary_path);
            return Ok(vec![]);
        }

        debug!("Running subfinder for domain: {}", domain);

        let mut child = Command::new(&self.binary_path)
            .args(["-d", domain, "-silent", "-json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn subfinder: {}", e))?;

        let stdout = child.stdout.take()
            .ok_or_else(|| anyhow!("Failed to capture subfinder stdout"))?;

        let mut reader = BufReader::new(stdout).lines();
        let mut results = Vec::new();

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
