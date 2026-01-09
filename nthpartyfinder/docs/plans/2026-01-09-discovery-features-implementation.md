# Discovery Features Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add subdomain discovery (via subfinder) and SaaS tenant probing to discover additional third-party vendor relationships.

**Architecture:** Two new discovery modules in `src/discovery/` that integrate into the existing vendor discovery pipeline. Configuration-driven with CLI overrides. Results produce `VendorRelationship` entries with new `RecordType` variants.

**Tech Stack:** Rust, tokio (async), reqwest (HTTP), serde (JSON), clap (CLI)

---

## Task 1: Add New RecordType Variants

**Files:**
- Modify: `src/vendor.rs`

**Step 1: Write the failing test**

```rust
// Add to existing tests in src/vendor.rs
#[test]
fn test_new_record_types_display() {
    assert_eq!(format!("{:?}", RecordType::SubfinderDiscovery), "SubfinderDiscovery");
    assert_eq!(format!("{:?}", RecordType::SaasTenantProbe), "SaasTenantProbe");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_new_record_types_display`
Expected: FAIL - variants don't exist

**Step 3: Add the new variants to RecordType enum**

In `src/vendor.rs`, find the `RecordType` enum and add:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RecordType {
    // ... existing variants ...
    SubfinderDiscovery,
    SaasTenantProbe,
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_new_record_types_display`
Expected: PASS

**Step 5: Commit**

```bash
git add src/vendor.rs
git commit -m "feat(vendor): add SubfinderDiscovery and SaasTenantProbe record types"
```

---

## Task 2: Add Discovery Configuration Structs

**Files:**
- Modify: `src/config.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_discovery_config_parsing() {
    let toml_str = r#"
[http]
user_agent = "test"
request_timeout_secs = 30

[dns]
servers = ["8.8.8.8"]
timeout_secs = 5

[patterns]
vendor_indicators = []
exclusions = []

[patterns.regex]
provider_verify = ".*"
domain_validation = ".*"

[analysis]
strategy = "unlimited"
concurrency_per_depth = [50]
request_delay_ms = 100
vendor_limits_per_depth = [0]
total_vendor_budget = 200

[discovery]
subdomain_enabled = true
subfinder_path = "/usr/bin/subfinder"
subfinder_timeout_secs = 300
saas_tenant_enabled = false
tenant_probe_timeout_secs = 10
tenant_probe_concurrency = 20
"#;
    let config: AppConfig = toml::from_str(toml_str).unwrap();
    assert!(config.discovery.subdomain_enabled);
    assert_eq!(config.discovery.subfinder_path, "/usr/bin/subfinder");
    assert!(!config.discovery.saas_tenant_enabled);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_discovery_config_parsing`
Expected: FAIL - `discovery` field doesn't exist

**Step 3: Add DiscoveryConfig struct and update AppConfig**

```rust
/// Discovery feature configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable subdomain discovery via subfinder
    #[serde(default)]
    pub subdomain_enabled: bool,
    /// Path to subfinder binary
    #[serde(default = "default_subfinder_path")]
    pub subfinder_path: String,
    /// Timeout for subfinder execution in seconds
    #[serde(default = "default_subfinder_timeout")]
    pub subfinder_timeout_secs: u64,
    /// Enable SaaS tenant discovery
    #[serde(default)]
    pub saas_tenant_enabled: bool,
    /// Timeout for tenant probe requests in seconds
    #[serde(default = "default_tenant_probe_timeout")]
    pub tenant_probe_timeout_secs: u64,
    /// Concurrent tenant probe requests
    #[serde(default = "default_tenant_probe_concurrency")]
    pub tenant_probe_concurrency: usize,
}

fn default_subfinder_path() -> String {
    "subfinder".to_string()
}

fn default_subfinder_timeout() -> u64 {
    300
}

fn default_tenant_probe_timeout() -> u64 {
    10
}

fn default_tenant_probe_concurrency() -> usize {
    20
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            subdomain_enabled: false,
            subfinder_path: default_subfinder_path(),
            subfinder_timeout_secs: default_subfinder_timeout(),
            saas_tenant_enabled: false,
            tenant_probe_timeout_secs: default_tenant_probe_timeout(),
            tenant_probe_concurrency: default_tenant_probe_concurrency(),
        }
    }
}

// Update AppConfig to include discovery field
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub http: HttpConfig,
    pub dns: DnsConfig,
    pub patterns: PatternsConfig,
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
}
```

**Step 4: Update DEFAULT_CONFIG constant**

Add to the DEFAULT_CONFIG string:

```toml
[discovery]
subdomain_enabled = false
subfinder_path = "subfinder"
subfinder_timeout_secs = 300
saas_tenant_enabled = false
tenant_probe_timeout_secs = 10
tenant_probe_concurrency = 20
```

**Step 5: Run test to verify it passes**

Run: `cargo test test_discovery_config_parsing`
Expected: PASS

**Step 6: Commit**

```bash
git add src/config.rs
git commit -m "feat(config): add DiscoveryConfig for subdomain and tenant discovery"
```

---

## Task 3: Add Discovery CLI Flags

**Files:**
- Modify: `src/cli.rs`

**Step 1: Add the new CLI arguments**

In `src/cli.rs`, add to the `Args` struct:

```rust
/// Enable subdomain discovery via subfinder
#[arg(long)]
pub enable_subdomain_discovery: bool,

/// Disable subdomain discovery (overrides config)
#[arg(long)]
pub disable_subdomain_discovery: bool,

/// Enable SaaS tenant discovery
#[arg(long)]
pub enable_saas_tenant_discovery: bool,

/// Disable SaaS tenant discovery (overrides config)
#[arg(long)]
pub disable_saas_tenant_discovery: bool,

/// Path to subfinder binary
#[arg(long)]
pub subfinder_path: Option<String>,

/// Run all discovery methods in parallel
#[arg(long)]
pub parallel_discovery: bool,
```

**Step 2: Run cargo check to verify compilation**

Run: `cargo check`
Expected: PASS (compiles without errors)

**Step 3: Test help output**

Run: `cargo run -- --help`
Expected: Shows new flags in help text

**Step 4: Commit**

```bash
git add src/cli.rs
git commit -m "feat(cli): add discovery feature flags"
```

---

## Task 4: Create Discovery Module Structure

**Files:**
- Create: `src/discovery/mod.rs`
- Modify: `src/main.rs`

**Step 1: Create the discovery module file**

Create `src/discovery/mod.rs`:

```rust
//! Discovery modules for finding third-party vendor relationships
//! through subdomain enumeration and SaaS tenant probing.

pub mod subfinder;
pub mod saas_tenant;

pub use subfinder::SubfinderDiscovery;
pub use saas_tenant::SaasTenantDiscovery;
```

**Step 2: Create placeholder subfinder module**

Create `src/discovery/subfinder.rs`:

```rust
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
```

**Step 3: Create placeholder saas_tenant module**

Create `src/discovery/saas_tenant.rs`:

```rust
//! SaaS tenant discovery by probing popular platforms.

use anyhow::Result;
use std::time::Duration;

pub struct SaasTenantDiscovery {
    timeout: Duration,
    concurrency: usize,
}

impl SaasTenantDiscovery {
    pub fn new(timeout: Duration, concurrency: usize) -> Self {
        Self { timeout, concurrency }
    }

    pub async fn probe(&self, _target_domain: &str) -> Result<Vec<TenantProbeResult>> {
        // TODO: Implement in Task 7
        Ok(vec![])
    }
}

#[derive(Debug, Clone)]
pub struct TenantProbeResult {
    pub platform_name: String,
    pub vendor_domain: String,
    pub tenant_url: String,
    pub status: TenantStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TenantStatus {
    Confirmed,
    Likely,
    NotFound,
    Unknown,
}
```

**Step 4: Add module to main.rs**

In `src/main.rs`, add near the top with other mod declarations:

```rust
mod discovery;
```

**Step 5: Run cargo check**

Run: `cargo check`
Expected: PASS

**Step 6: Commit**

```bash
git add src/discovery/mod.rs src/discovery/subfinder.rs src/discovery/saas_tenant.rs src/main.rs
git commit -m "feat(discovery): add module structure with placeholder implementations"
```

---

## Task 5: Implement Subfinder Integration

**Files:**
- Modify: `src/discovery/subfinder.rs`

**Step 1: Write the failing test for binary execution**

```rust
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
    }

    #[test]
    fn test_parse_subfinder_handles_invalid_json() {
        let output = "not json\n{\"host\":\"valid.com\",\"source\":\"test\"}";
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, "valid.com");
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test parse_subfinder`
Expected: FAIL - function doesn't exist

**Step 3: Implement the full subfinder module**

```rust
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
        // Check if binary exists at path or is in PATH
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

        // Read output with timeout
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

fn parse_subfinder_output(output: &str) -> Vec<SubdomainResult> {
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
    }

    #[test]
    fn test_parse_subfinder_handles_invalid_json() {
        let output = "not json\n{\"host\":\"valid.com\",\"source\":\"test\"}";
        let results = parse_subfinder_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subdomain, "valid.com");
    }
}
```

**Step 4: Add which crate to Cargo.toml**

```toml
which = "6"
```

**Step 5: Run tests**

Run: `cargo test parse_subfinder`
Expected: PASS

**Step 6: Commit**

```bash
git add src/discovery/subfinder.rs Cargo.toml
git commit -m "feat(discovery): implement subfinder integration with JSON parsing"
```

---

## Task 6: Create SaaS Platforms Database

**Files:**
- Create: `config/saas_platforms.json`

**Step 1: Create the platforms JSON file**

Create `config/saas_platforms.json` with top 100 SaaS platforms:

```json
{
  "platforms": [
    {
      "name": "Okta",
      "vendor_domain": "okta.com",
      "tenant_patterns": ["{tenant}.okta.com"],
      "detection": {
        "success_indicators": ["Sign In", "Okta"],
        "failure_indicators": ["not found", "doesn't exist", "page not found"]
      }
    },
    {
      "name": "Atlassian",
      "vendor_domain": "atlassian.com",
      "tenant_patterns": ["{tenant}.atlassian.net"],
      "detection": {
        "success_indicators": ["Atlassian", "Jira", "Confluence"],
        "failure_indicators": ["site not found", "doesn't exist"]
      }
    },
    {
      "name": "Salesforce",
      "vendor_domain": "salesforce.com",
      "tenant_patterns": ["{tenant}.my.salesforce.com", "{tenant}.lightning.force.com"],
      "detection": {
        "success_indicators": ["Salesforce", "Login"],
        "failure_indicators": ["invalid", "not found"]
      }
    },
    {
      "name": "Slack",
      "vendor_domain": "slack.com",
      "tenant_patterns": ["{tenant}.slack.com"],
      "detection": {
        "success_indicators": ["Slack", "Sign in"],
        "failure_indicators": ["workspace not found", "doesn't exist"]
      }
    },
    {
      "name": "Zendesk",
      "vendor_domain": "zendesk.com",
      "tenant_patterns": ["{tenant}.zendesk.com"],
      "detection": {
        "success_indicators": ["Zendesk", "Help Center", "Support"],
        "failure_indicators": ["not found", "doesn't exist"]
      }
    },
    {
      "name": "HubSpot",
      "vendor_domain": "hubspot.com",
      "tenant_patterns": ["{tenant}.hubspot.com"],
      "detection": {
        "success_indicators": ["HubSpot"],
        "failure_indicators": ["not found"]
      }
    },
    {
      "name": "ServiceNow",
      "vendor_domain": "servicenow.com",
      "tenant_patterns": ["{tenant}.service-now.com"],
      "detection": {
        "success_indicators": ["ServiceNow", "Login"],
        "failure_indicators": ["not found", "invalid instance"]
      }
    },
    {
      "name": "Workday",
      "vendor_domain": "workday.com",
      "tenant_patterns": ["{tenant}.myworkday.com"],
      "detection": {
        "success_indicators": ["Workday", "Sign In"],
        "failure_indicators": ["not found"]
      }
    },
    {
      "name": "Freshdesk",
      "vendor_domain": "freshdesk.com",
      "tenant_patterns": ["{tenant}.freshdesk.com"],
      "detection": {
        "success_indicators": ["Freshdesk", "Help Desk"],
        "failure_indicators": ["not found", "doesn't exist"]
      }
    },
    {
      "name": "Monday.com",
      "vendor_domain": "monday.com",
      "tenant_patterns": ["{tenant}.monday.com"],
      "detection": {
        "success_indicators": ["monday.com", "Work OS"],
        "failure_indicators": ["not found"]
      }
    },
    {
      "name": "Notion",
      "vendor_domain": "notion.so",
      "tenant_patterns": ["{tenant}.notion.site"],
      "detection": {
        "success_indicators": ["Notion"],
        "failure_indicators": ["not found", "doesn't exist"]
      }
    },
    {
      "name": "Asana",
      "vendor_domain": "asana.com",
      "tenant_patterns": ["app.asana.com/0/{tenant}"],
      "detection": {
        "success_indicators": ["Asana"],
        "failure_indicators": ["not found"]
      }
    },
    {
      "name": "Intercom",
      "vendor_domain": "intercom.com",
      "tenant_patterns": ["{tenant}.intercom.help"],
      "detection": {
        "success_indicators": ["Intercom", "Help Center"],
        "failure_indicators": ["not found"]
      }
    },
    {
      "name": "Greenhouse",
      "vendor_domain": "greenhouse.io",
      "tenant_patterns": ["boards.greenhouse.io/{tenant}"],
      "detection": {
        "success_indicators": ["Greenhouse", "Careers", "Jobs"],
        "failure_indicators": ["not found", "no jobs"]
      }
    },
    {
      "name": "Lever",
      "vendor_domain": "lever.co",
      "tenant_patterns": ["jobs.lever.co/{tenant}"],
      "detection": {
        "success_indicators": ["Lever", "Jobs"],
        "failure_indicators": ["not found"]
      }
    },
    {
      "name": "Docusign",
      "vendor_domain": "docusign.com",
      "tenant_patterns": ["{tenant}.docusign.net"],
      "detection": {
        "success_indicators": ["DocuSign"],
        "failure_indicators": ["not found"]
      }
    },
    {
      "name": "Box",
      "vendor_domain": "box.com",
      "tenant_patterns": ["{tenant}.box.com", "{tenant}.app.box.com"],
      "detection": {
        "success_indicators": ["Box", "Sign In"],
        "failure_indicators": ["not found"]
      }
    },
    {
      "name": "Dropbox Business",
      "vendor_domain": "dropbox.com",
      "tenant_patterns": ["{tenant}.dropbox.com"],
      "detection": {
        "success_indicators": ["Dropbox"],
        "failure_indicators": ["not found"]
      }
    },
    {
      "name": "GitHub Enterprise",
      "vendor_domain": "github.com",
      "tenant_patterns": ["github.com/{tenant}"],
      "detection": {
        "success_indicators": ["GitHub", "repositories"],
        "failure_indicators": ["Not Found", "404"]
      }
    },
    {
      "name": "GitLab",
      "vendor_domain": "gitlab.com",
      "tenant_patterns": ["gitlab.com/{tenant}"],
      "detection": {
        "success_indicators": ["GitLab"],
        "failure_indicators": ["not found", "404"]
      }
    }
  ]
}
```

Note: This is a representative sample. The full file should contain 100 platforms.

**Step 2: Commit**

```bash
git add config/saas_platforms.json
git commit -m "feat(discovery): add SaaS platforms database (top 20, expandable)"
```

---

## Task 7: Implement SaaS Tenant Discovery

**Files:**
- Modify: `src/discovery/saas_tenant.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_tenant_names() {
        let names = generate_tenant_names("klaviyo.com");
        assert!(names.contains(&"klaviyo".to_string()));
        assert!(names.contains(&"klaviyo-inc".to_string()));
        assert!(names.contains(&"klaviyoinc".to_string()));
    }

    #[test]
    fn test_construct_probe_url() {
        let url = construct_probe_url("{tenant}.okta.com", "klaviyo");
        assert_eq!(url, "https://klaviyo.okta.com");
    }

    #[test]
    fn test_analyze_response_confirmed() {
        let detection = DetectionConfig {
            success_indicators: vec!["Sign In".to_string(), "Okta".to_string()],
            failure_indicators: vec!["not found".to_string()],
        };
        let status = analyze_response(200, "Welcome to Okta Sign In page", &detection);
        assert_eq!(status, TenantStatus::Confirmed);
    }

    #[test]
    fn test_analyze_response_not_found() {
        let detection = DetectionConfig {
            success_indicators: vec!["Sign In".to_string()],
            failure_indicators: vec!["not found".to_string()],
        };
        let status = analyze_response(404, "Page not found", &detection);
        assert_eq!(status, TenantStatus::NotFound);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test generate_tenant`
Expected: FAIL

**Step 3: Implement full saas_tenant module**

```rust
//! SaaS tenant discovery by probing popular platforms.

use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;
use futures::{stream, StreamExt};
use reqwest::Client;
use tracing::{debug, warn};

#[derive(Debug, Clone, Deserialize)]
pub struct SaasPlatform {
    pub name: String,
    pub vendor_domain: String,
    pub tenant_patterns: Vec<String>,
    pub detection: DetectionConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DetectionConfig {
    pub success_indicators: Vec<String>,
    pub failure_indicators: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PlatformsFile {
    platforms: Vec<SaasPlatform>,
}

#[derive(Debug, Clone)]
pub struct TenantProbeResult {
    pub platform_name: String,
    pub vendor_domain: String,
    pub tenant_url: String,
    pub status: TenantStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TenantStatus {
    Confirmed,
    Likely,
    NotFound,
    Unknown,
}

pub struct SaasTenantDiscovery {
    platforms: Vec<SaasPlatform>,
    client: Client,
    timeout: Duration,
    concurrency: usize,
}

impl SaasTenantDiscovery {
    pub fn new(timeout: Duration, concurrency: usize) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .unwrap_or_default();

        Self {
            platforms: Vec::new(),
            client,
            timeout,
            concurrency,
        }
    }

    pub fn load_platforms(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        let file: PlatformsFile = serde_json::from_str(&content)?;
        self.platforms = file.platforms;
        debug!("Loaded {} SaaS platforms", self.platforms.len());
        Ok(())
    }

    pub async fn probe(&self, target_domain: &str) -> Result<Vec<TenantProbeResult>> {
        let tenant_names = generate_tenant_names(target_domain);
        debug!("Generated tenant name candidates: {:?}", tenant_names);

        let mut probe_tasks = Vec::new();
        for platform in &self.platforms {
            for tenant_name in &tenant_names {
                for pattern in &platform.tenant_patterns {
                    let url = construct_probe_url(pattern, tenant_name);
                    probe_tasks.push((
                        platform.name.clone(),
                        platform.vendor_domain.clone(),
                        url,
                        platform.detection.clone(),
                    ));
                }
            }
        }

        debug!("Probing {} URLs for tenant discovery", probe_tasks.len());

        let results: Vec<TenantProbeResult> = stream::iter(probe_tasks)
            .map(|(name, vendor, url, detection)| {
                let client = self.client.clone();
                async move {
                    let status = probe_url(&client, &url, &detection).await;
                    TenantProbeResult {
                        platform_name: name,
                        vendor_domain: vendor,
                        tenant_url: url,
                        status,
                    }
                }
            })
            .buffer_unordered(self.concurrency)
            .filter(|r| {
                let dominated = matches!(r.status, TenantStatus::Confirmed | TenantStatus::Likely);
                async move { dominated }
            })
            .collect()
            .await;

        debug!("Found {} likely/confirmed tenants", results.len());
        Ok(results)
    }
}

fn generate_tenant_names(domain: &str) -> Vec<String> {
    // Extract base name from domain (e.g., "klaviyo" from "klaviyo.com")
    let base = domain.split('.').next().unwrap_or(domain);
    let base_lower = base.to_lowercase();

    vec![
        base_lower.clone(),
        format!("{}-inc", base_lower),
        format!("{}inc", base_lower),
        format!("{}-corp", base_lower),
        format!("{}corp", base_lower),
    ]
}

fn construct_probe_url(pattern: &str, tenant: &str) -> String {
    let url = pattern.replace("{tenant}", tenant);
    if url.starts_with("http://") || url.starts_with("https://") {
        url
    } else {
        format!("https://{}", url)
    }
}

async fn probe_url(client: &Client, url: &str, detection: &DetectionConfig) -> TenantStatus {
    match client.get(url).send().await {
        Ok(response) => {
            let status_code = response.status().as_u16();
            match response.text().await {
                Ok(body) => analyze_response(status_code, &body, detection),
                Err(_) => {
                    if status_code == 200 {
                        TenantStatus::Likely
                    } else {
                        TenantStatus::NotFound
                    }
                }
            }
        }
        Err(e) => {
            if e.is_timeout() {
                TenantStatus::Unknown
            } else {
                TenantStatus::NotFound
            }
        }
    }
}

fn analyze_response(status_code: u16, body: &str, detection: &DetectionConfig) -> TenantStatus {
    let body_lower = body.to_lowercase();

    // Check for failure indicators first
    for indicator in &detection.failure_indicators {
        if body_lower.contains(&indicator.to_lowercase()) {
            return TenantStatus::NotFound;
        }
    }

    // Check for success indicators
    if status_code == 200 {
        let has_success = detection.success_indicators.iter()
            .any(|ind| body_lower.contains(&ind.to_lowercase()));

        if has_success {
            TenantStatus::Confirmed
        } else {
            TenantStatus::Likely
        }
    } else if status_code == 404 || status_code >= 400 {
        TenantStatus::NotFound
    } else {
        TenantStatus::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_tenant_names() {
        let names = generate_tenant_names("klaviyo.com");
        assert!(names.contains(&"klaviyo".to_string()));
        assert!(names.contains(&"klaviyo-inc".to_string()));
        assert!(names.contains(&"klaviyoinc".to_string()));
    }

    #[test]
    fn test_construct_probe_url() {
        let url = construct_probe_url("{tenant}.okta.com", "klaviyo");
        assert_eq!(url, "https://klaviyo.okta.com");
    }

    #[test]
    fn test_construct_probe_url_with_path() {
        let url = construct_probe_url("jobs.lever.co/{tenant}", "klaviyo");
        assert_eq!(url, "https://jobs.lever.co/klaviyo");
    }

    #[test]
    fn test_analyze_response_confirmed() {
        let detection = DetectionConfig {
            success_indicators: vec!["Sign In".to_string(), "Okta".to_string()],
            failure_indicators: vec!["not found".to_string()],
        };
        let status = analyze_response(200, "Welcome to Okta Sign In page", &detection);
        assert_eq!(status, TenantStatus::Confirmed);
    }

    #[test]
    fn test_analyze_response_not_found() {
        let detection = DetectionConfig {
            success_indicators: vec!["Sign In".to_string()],
            failure_indicators: vec!["not found".to_string()],
        };
        let status = analyze_response(404, "Page not found", &detection);
        assert_eq!(status, TenantStatus::NotFound);
    }

    #[test]
    fn test_analyze_response_likely() {
        let detection = DetectionConfig {
            success_indicators: vec!["Specific Brand".to_string()],
            failure_indicators: vec!["not found".to_string()],
        };
        // 200 status but no success indicators
        let status = analyze_response(200, "Some generic page content", &detection);
        assert_eq!(status, TenantStatus::Likely);
    }
}
```

**Step 4: Run tests**

Run: `cargo test saas_tenant`
Expected: PASS

**Step 5: Commit**

```bash
git add src/discovery/saas_tenant.rs
git commit -m "feat(discovery): implement SaaS tenant probing with response analysis"
```

---

## Task 8: Integrate Discovery into Main Pipeline

**Files:**
- Modify: `src/main.rs`

**Step 1: Import discovery modules and add initialization**

In `src/main.rs`, add the discovery initialization after subprocessor_analyzer setup:

```rust
use discovery::{SubfinderDiscovery, SaasTenantDiscovery};

// In main(), after subprocessor_analyzer initialization:

// Initialize discovery modules if enabled
let subdomain_discovery = if args.enable_subdomain_discovery
    || (!args.disable_subdomain_discovery && _app_config.discovery.subdomain_enabled) {
    let path = args.subfinder_path.clone()
        .unwrap_or_else(|| _app_config.discovery.subfinder_path.clone());
    let discovery = SubfinderDiscovery::new(
        PathBuf::from(path),
        Duration::from_secs(_app_config.discovery.subfinder_timeout_secs),
    );
    if discovery.is_available() {
        logger.info("Subdomain discovery enabled (subfinder found)");
        Some(discovery)
    } else {
        logger.warn("Subdomain discovery requested but subfinder not found");
        None
    }
} else {
    None
};

let saas_tenant_discovery = if args.enable_saas_tenant_discovery
    || (!args.disable_saas_tenant_discovery && _app_config.discovery.saas_tenant_enabled) {
    let mut discovery = SaasTenantDiscovery::new(
        Duration::from_secs(_app_config.discovery.tenant_probe_timeout_secs),
        _app_config.discovery.tenant_probe_concurrency,
    );
    let platforms_path = Path::new("config/saas_platforms.json");
    if platforms_path.exists() {
        if let Err(e) = discovery.load_platforms(platforms_path) {
            logger.warn(&format!("Failed to load SaaS platforms: {}", e));
            None
        } else {
            logger.info("SaaS tenant discovery enabled");
            Some(discovery)
        }
    } else {
        logger.warn("SaaS tenant discovery requested but platforms file not found");
        None
    }
} else {
    None
};
```

**Step 2: Add discovery calls in discover_nth_parties (simplified integration)**

At the end of `discover_nth_parties`, before returning results, add discovery calls:

```rust
// Run additional discovery methods at depth 1 only
if current_depth == 1 {
    // Subdomain discovery
    if let Some(ref subdomain_disc) = subdomain_discovery {
        logger.info("Running subdomain discovery...");
        match subdomain_disc.discover(domain).await {
            Ok(subdomains) => {
                for sub in subdomains {
                    // Filter and convert to VendorRelationship
                    let base = domain_utils::extract_base_domain(&sub.subdomain);
                    if base != domain_utils::extract_base_domain(domain) {
                        let relationship = VendorRelationship {
                            customer_domain: domain.to_string(),
                            customer_organization: root_customer_organization.to_string(),
                            nth_party_domain: base.clone(),
                            nth_party_organization: whois::get_organization(&base).await
                                .unwrap_or_else(|_| format!("{} Inc.", base)),
                            record_type: RecordType::SubfinderDiscovery,
                            depth: current_depth,
                            evidence: format!("Subdomain: {} (source: {})", sub.subdomain, sub.source),
                        };
                        results.push(relationship);
                    }
                }
            }
            Err(e) => logger.warn(&format!("Subdomain discovery failed: {}", e)),
        }
    }

    // SaaS tenant discovery
    if let Some(ref tenant_disc) = saas_tenant_discovery {
        logger.info("Running SaaS tenant discovery...");
        match tenant_disc.probe(domain).await {
            Ok(tenants) => {
                for tenant in tenants {
                    if matches!(tenant.status, TenantStatus::Confirmed | TenantStatus::Likely) {
                        let relationship = VendorRelationship {
                            customer_domain: domain.to_string(),
                            customer_organization: root_customer_organization.to_string(),
                            nth_party_domain: tenant.vendor_domain.clone(),
                            nth_party_organization: tenant.platform_name.clone(),
                            record_type: RecordType::SaasTenantProbe,
                            depth: current_depth,
                            evidence: format!("Tenant URL: {} ({:?})", tenant.tenant_url, tenant.status),
                        };
                        results.push(relationship);
                    }
                }
            }
            Err(e) => logger.warn(&format!("SaaS tenant discovery failed: {}", e)),
        }
    }
}
```

Note: This is a simplified integration. The actual implementation needs to thread the discovery objects through the function signatures.

**Step 3: Build and test**

Run: `cargo build`
Expected: PASS

**Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat(discovery): integrate subdomain and tenant discovery into main pipeline"
```

---

## Task 9: Update HTML Report Template

**Files:**
- Modify: `templates/report.html`

**Step 1: Add icons for new record types in the source column**

Find the section that renders the Source column and add cases for new types:

```html
<!-- In the RecordType display section -->
{% match relationship.record_type %}
    {% when RecordType::SubfinderDiscovery %}
        <span title="Discovered via subdomain enumeration">🔍 Subdomain</span>
    {% when RecordType::SaasTenantProbe %}
        <span title="Discovered via SaaS tenant probing">☁️ SaaS Tenant</span>
    <!-- ... existing cases ... -->
{% endmatch %}
```

**Step 2: Build and verify**

Run: `cargo build`
Expected: PASS

**Step 3: Commit**

```bash
git add templates/report.html
git commit -m "feat(report): add icons for subdomain and SaaS tenant discovery sources"
```

---

## Task 10: Update Configuration File

**Files:**
- Modify: `config/nthpartyfinder.toml`

**Step 1: Add discovery section to config file**

```toml
# =============================================================================
# Discovery Features
# =============================================================================
# Additional discovery methods for finding third-party relationships.

[discovery]
# Subdomain discovery using Project Discovery's subfinder
# Requires subfinder binary to be installed
subdomain_enabled = false
subfinder_path = "subfinder"
subfinder_timeout_secs = 300

# SaaS tenant discovery by probing popular platforms
# Probes tenant-specific URLs on 100+ SaaS platforms
saas_tenant_enabled = false
tenant_probe_timeout_secs = 10
tenant_probe_concurrency = 20
```

**Step 2: Commit**

```bash
git add config/nthpartyfinder.toml
git commit -m "feat(config): add discovery section with defaults"
```

---

## Task 11: Final Integration Test

**Step 1: Build release binary**

Run: `cargo build --release`
Expected: PASS

**Step 2: Test with subdomain discovery disabled (default)**

Run: `./target/release/nthpartyfinder.exe --domain example.com --depth 1 -v`
Expected: Normal output, no discovery messages

**Step 3: Test with flags**

Run: `./target/release/nthpartyfinder.exe --domain klaviyo.com --depth 1 --enable-saas-tenant-discovery -v`
Expected: Shows "SaaS tenant discovery enabled" and probes platforms

**Step 4: Create final commit**

```bash
git add -A
git commit -m "feat: complete discovery features implementation

- Subdomain discovery via subfinder integration
- SaaS tenant probing across 20+ platforms (expandable)
- Configuration-driven with CLI overrides
- New RecordType variants for report display

Closes: discovery-features design"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Add RecordType variants | vendor.rs |
| 2 | Add DiscoveryConfig | config.rs |
| 3 | Add CLI flags | cli.rs |
| 4 | Create module structure | discovery/*.rs, main.rs |
| 5 | Implement subfinder | discovery/subfinder.rs |
| 6 | Create platforms DB | config/saas_platforms.json |
| 7 | Implement tenant probing | discovery/saas_tenant.rs |
| 8 | Integrate into pipeline | main.rs |
| 9 | Update HTML report | templates/report.html |
| 10 | Update config file | config/nthpartyfinder.toml |
| 11 | Final integration test | - |

Total: 11 tasks, ~50 bite-sized steps
