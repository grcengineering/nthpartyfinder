//! Subdomain discovery using Project Discovery's subfinder tool.

use anyhow::Result;
use std::path::PathBuf;
use std::time::Duration;

pub struct SubfinderDiscovery {
    binary_path: PathBuf,
    timeout: Duration,
}

impl SubfinderDiscovery {
    pub fn new(binary_path: PathBuf, timeout: Duration) -> Self {
        Self { binary_path, timeout }
    }

    pub fn is_available(&self) -> bool {
        self.binary_path.exists() || which::which(&self.binary_path).is_ok()
    }

    pub async fn discover(&self, _domain: &str) -> Result<Vec<SubdomainResult>> {
        // TODO: Implement in Task 5
        Ok(vec![])
    }
}

#[derive(Debug, Clone)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub source: String,
}
