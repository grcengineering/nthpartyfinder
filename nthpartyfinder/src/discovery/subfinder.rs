//! Subdomain discovery using Project Discovery's subfinder tool.

use anyhow::{Result, anyhow};
use serde::Deserialize;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::io::{BufReader, AsyncBufReadExt};
use tracing::{debug, warn};

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
