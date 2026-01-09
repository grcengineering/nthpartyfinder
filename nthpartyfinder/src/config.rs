//! Configuration management for nthpartyfinder
//!
//! All configuration is loaded from `./config/nthpartyfinder.toml`.
//! No hardcoded defaults exist in source code - all defaults are in the config template.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::io::{self, Write};
use thiserror::Error;
use regex::Regex;

/// Configuration file path relative to working directory
pub const CONFIG_PATH: &str = "./config/nthpartyfinder.toml";

/// Default configuration file content - this is the ONLY place defaults exist
pub const DEFAULT_CONFIG: &str = include_str!("../config/nthpartyfinder.toml");

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found at {0}")]
    FileNotFound(PathBuf),

    #[error("Failed to read configuration file: {0}")]
    IoError(#[from] io::Error),

    #[error("Failed to parse configuration file: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Invalid regex pattern '{pattern_name}': {error}\n  Pattern: {pattern}")]
    InvalidRegex {
        pattern_name: String,
        pattern: String,
        error: String,
    },

    #[error("Invalid URL in '{field}': {url}")]
    InvalidUrl { field: String, url: String },

    #[error("Invalid address in '{field}': {address} (expected ip:port format)")]
    InvalidAddress { field: String, address: String },

    #[error("Configuration field '{field}' cannot be empty")]
    EmptyRequired { field: String },

    #[error("At least one DoH server or DNS server must be configured")]
    NoServersConfigured,
}

/// Root configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub http: HttpConfig,
    pub dns: DnsConfig,
    pub patterns: PatternsConfig,
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
}

/// Resource management strategy for vendor analysis
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisStrategy {
    /// Process ALL vendors at every depth (uses concurrency/rate limiting only)
    Unlimited,
    /// Apply hard vendor count limits per depth
    Limits,
    /// Stop after processing a total number of vendors across all depths
    Budget,
}

/// Analysis resource management configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisConfig {
    /// Resource management strategy
    pub strategy: AnalysisStrategy,
    /// Maximum concurrent vendor analyses at each depth level [depth_1, depth_2, depth_3, depth_4_plus]
    pub concurrency_per_depth: Vec<usize>,
    /// Delay between starting new vendor analyses (milliseconds)
    pub request_delay_ms: u64,
    /// Maximum vendors to process at each depth level (only used with "limits" strategy)
    pub vendor_limits_per_depth: Vec<usize>,
    /// Maximum total vendors across all depths (only used with "budget" strategy)
    pub total_vendor_budget: usize,
}

impl AnalysisConfig {
    /// Get concurrency limit for a given depth (1-indexed)
    pub fn get_concurrency_for_depth(&self, depth: usize) -> usize {
        if depth == 0 {
            return self.concurrency_per_depth.first().copied().unwrap_or(50);
        }
        let idx = (depth - 1).min(self.concurrency_per_depth.len().saturating_sub(1));
        self.concurrency_per_depth.get(idx).copied().unwrap_or(5)
    }

    /// Get vendor limit for a given depth (1-indexed), returns None if no limit
    pub fn get_vendor_limit_for_depth(&self, depth: usize) -> Option<usize> {
        if self.strategy != AnalysisStrategy::Limits {
            return None;
        }
        if depth == 0 {
            let limit = self.vendor_limits_per_depth.first().copied().unwrap_or(0);
            return if limit == 0 { None } else { Some(limit) };
        }
        let idx = (depth - 1).min(self.vendor_limits_per_depth.len().saturating_sub(1));
        let limit = self.vendor_limits_per_depth.get(idx).copied().unwrap_or(5);
        if limit == 0 { None } else { Some(limit) }
    }
}

/// Discovery feature configuration for subdomain and SaaS tenant discovery
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable subdomain discovery via subfinder
    #[serde(default)]
    pub subdomain_enabled: bool,
    /// Path to subfinder binary
    #[serde(default = "default_subfinder_path")]
    pub subfinder_path: String,
    /// Timeout for subfinder execution in seconds
    #[serde(default = "default_subfinder_timeout_secs")]
    pub subfinder_timeout_secs: u64,
    /// Enable SaaS tenant discovery
    #[serde(default)]
    pub saas_tenant_enabled: bool,
    /// Timeout for tenant probe requests in seconds
    #[serde(default = "default_tenant_probe_timeout_secs")]
    pub tenant_probe_timeout_secs: u64,
    /// Concurrent tenant probe requests
    #[serde(default = "default_tenant_probe_concurrency")]
    pub tenant_probe_concurrency: usize,
}

fn default_subfinder_path() -> String {
    "subfinder".to_string()
}

fn default_subfinder_timeout_secs() -> u64 {
    300
}

fn default_tenant_probe_timeout_secs() -> u64 {
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
            subfinder_timeout_secs: default_subfinder_timeout_secs(),
            saas_tenant_enabled: false,
            tenant_probe_timeout_secs: default_tenant_probe_timeout_secs(),
            tenant_probe_concurrency: default_tenant_probe_concurrency(),
        }
    }
}

/// HTTP client configuration
#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    pub user_agent: String,
    pub request_timeout_secs: u64,
}

/// DNS resolution configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    pub doh_servers: Vec<DohServerConfig>,
    pub dns_servers: Vec<DnsServerConfig>,
}

/// DNS-over-HTTPS server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DohServerConfig {
    pub name: String,
    pub url: String,
    pub timeout_secs: u64,
}

/// Traditional DNS server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DnsServerConfig {
    pub name: String,
    pub address: String,
    pub timeout_secs: u64,
}

/// Pattern configuration for DNS record parsing
#[derive(Debug, Clone, Deserialize)]
pub struct PatternsConfig {
    pub regex: RegexPatterns,
    pub verification: HashMap<String, String>,
    pub provider_mappings: HashMap<String, String>,
}

/// Regex patterns for dynamic TXT record parsing
#[derive(Debug, Clone, Deserialize)]
pub struct RegexPatterns {
    /// Strips SPF macro variables (e.g., %{ir}.%{v}.domain.com -> domain.com)
    pub spf_macro_strip: String,
    /// Matches: {provider}-domain-verification= or {provider}-verification=
    pub domain_verification: String,
    /// Matches: verification-{provider}=
    pub verification_prefix: String,
    /// Matches: {provider}-site-verification=
    pub site_verification: String,
    /// Matches: {PROVIDER}_verify_ (e.g., ZOOM_verify_)
    pub provider_verify: String,
    /// Validates extracted domain format
    pub domain_validation: String,
}

impl AppConfig {
    /// Load configuration from the default path
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from_path(Path::new(CONFIG_PATH))
    }

    /// Load configuration from a specific path
    pub fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::FileNotFound(path.to_path_buf()));
        }

        let content = fs::read_to_string(path)?;
        let config: AppConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate all configuration values
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate HTTP config
        if self.http.user_agent.is_empty() {
            return Err(ConfigError::EmptyRequired {
                field: "http.user_agent".to_string(),
            });
        }
        if self.http.request_timeout_secs == 0 {
            return Err(ConfigError::EmptyRequired {
                field: "http.request_timeout_secs".to_string(),
            });
        }

        // Validate at least one server is configured
        if self.dns.doh_servers.is_empty() && self.dns.dns_servers.is_empty() {
            return Err(ConfigError::NoServersConfigured);
        }

        // Validate DoH server URLs
        for (i, server) in self.dns.doh_servers.iter().enumerate() {
            if !server.url.starts_with("https://") {
                return Err(ConfigError::InvalidUrl {
                    field: format!("dns.doh_servers[{}].url", i),
                    url: server.url.clone(),
                });
            }
        }

        // Validate DNS server addresses (basic ip:port check)
        for (i, server) in self.dns.dns_servers.iter().enumerate() {
            if !server.address.contains(':') {
                return Err(ConfigError::InvalidAddress {
                    field: format!("dns.dns_servers[{}].address", i),
                    address: server.address.clone(),
                });
            }
        }

        // Validate regex patterns compile
        self.validate_regex("patterns.regex.spf_macro_strip", &self.patterns.regex.spf_macro_strip)?;
        self.validate_regex("patterns.regex.domain_verification", &self.patterns.regex.domain_verification)?;
        self.validate_regex("patterns.regex.verification_prefix", &self.patterns.regex.verification_prefix)?;
        self.validate_regex("patterns.regex.site_verification", &self.patterns.regex.site_verification)?;
        self.validate_regex("patterns.regex.provider_verify", &self.patterns.regex.provider_verify)?;
        self.validate_regex("patterns.regex.domain_validation", &self.patterns.regex.domain_validation)?;

        // Validate verification patterns are valid regex
        for (pattern, _domain) in &self.patterns.verification {
            self.validate_regex(&format!("patterns.verification.\"{}\"", pattern), pattern)?;
        }

        // Validate analysis config
        if self.analysis.concurrency_per_depth.is_empty() {
            return Err(ConfigError::EmptyRequired {
                field: "analysis.concurrency_per_depth".to_string(),
            });
        }
        if self.analysis.strategy == AnalysisStrategy::Limits && self.analysis.vendor_limits_per_depth.is_empty() {
            return Err(ConfigError::EmptyRequired {
                field: "analysis.vendor_limits_per_depth (required when strategy = 'limits')".to_string(),
            });
        }
        if self.analysis.strategy == AnalysisStrategy::Budget && self.analysis.total_vendor_budget == 0 {
            return Err(ConfigError::EmptyRequired {
                field: "analysis.total_vendor_budget (required when strategy = 'budget')".to_string(),
            });
        }

        Ok(())
    }

    fn validate_regex(&self, name: &str, pattern: &str) -> Result<(), ConfigError> {
        Regex::new(pattern).map_err(|e| ConfigError::InvalidRegex {
            pattern_name: name.to_string(),
            pattern: pattern.to_string(),
            error: e.to_string(),
        })?;
        Ok(())
    }

    /// Create default configuration file at the standard location
    pub fn create_default_config() -> Result<PathBuf, ConfigError> {
        let path = Path::new(CONFIG_PATH);

        // Create config directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write default config
        let mut file = fs::File::create(path)?;
        file.write_all(DEFAULT_CONFIG.as_bytes())?;

        Ok(path.to_path_buf())
    }

    /// Check if stdin is a TTY (interactive terminal)
    pub fn is_interactive() -> bool {
        atty::is(atty::Stream::Stdin)
    }

    /// Prompt user to create default config (only in interactive mode)
    pub fn prompt_create_config() -> Result<Option<PathBuf>, ConfigError> {
        if !Self::is_interactive() {
            return Ok(None);
        }

        print!("Configuration file not found. Create default config? [Y/n] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        if input.is_empty() || input == "y" || input == "yes" {
            let path = Self::create_default_config()?;
            Ok(Some(path))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_parses() {
        let config: Result<AppConfig, _> = toml::from_str(DEFAULT_CONFIG);
        assert!(config.is_ok(), "Default config should parse: {:?}", config.err());
    }

    #[test]
    fn test_default_config_validates() {
        let config: AppConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        assert!(config.validate().is_ok(), "Default config should validate");
    }

    #[test]
    fn test_discovery_config_parsing() {
        let config_str = r#"
[http]
user_agent = "test/1.0"
request_timeout_secs = 30

[dns]
[[dns.doh_servers]]
name = "Test DoH"
url = "https://test.example.com/dns-query"
timeout_secs = 3

[[dns.dns_servers]]
name = "Test DNS"
address = "1.1.1.1:53"
timeout_secs = 2

[patterns.regex]
spf_macro_strip = '%\{[a-zA-Z]+\}\.?'
domain_verification = '([a-zA-Z0-9]+)-verification='
verification_prefix = 'verification-([a-zA-Z0-9]+)='
site_verification = '([a-zA-Z0-9]+)-site-verification='
provider_verify = '([A-Z0-9]+)_verify_'
domain_validation = '^[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,62})*$'

[patterns.verification]

[patterns.provider_mappings]

[analysis]
strategy = "unlimited"
concurrency_per_depth = [50, 20, 10, 5]
request_delay_ms = 100
vendor_limits_per_depth = [0, 20, 10, 5]
total_vendor_budget = 200

[discovery]
subdomain_enabled = true
subfinder_path = "/usr/local/bin/subfinder"
subfinder_timeout_secs = 600
saas_tenant_enabled = true
tenant_probe_timeout_secs = 15
tenant_probe_concurrency = 30
"#;

        let config: AppConfig = toml::from_str(config_str).expect("Config should parse");

        // Verify discovery config values
        assert!(config.discovery.subdomain_enabled, "subdomain_enabled should be true");
        assert_eq!(config.discovery.subfinder_path, "/usr/local/bin/subfinder");
        assert_eq!(config.discovery.subfinder_timeout_secs, 600);
        assert!(config.discovery.saas_tenant_enabled, "saas_tenant_enabled should be true");
        assert_eq!(config.discovery.tenant_probe_timeout_secs, 15);
        assert_eq!(config.discovery.tenant_probe_concurrency, 30);
    }

    #[test]
    fn test_discovery_config_defaults() {
        // Test that discovery section is optional and uses defaults
        let config_str = r#"
[http]
user_agent = "test/1.0"
request_timeout_secs = 30

[dns]
[[dns.doh_servers]]
name = "Test DoH"
url = "https://test.example.com/dns-query"
timeout_secs = 3

[[dns.dns_servers]]
name = "Test DNS"
address = "1.1.1.1:53"
timeout_secs = 2

[patterns.regex]
spf_macro_strip = '%\{[a-zA-Z]+\}\.?'
domain_verification = '([a-zA-Z0-9]+)-verification='
verification_prefix = 'verification-([a-zA-Z0-9]+)='
site_verification = '([a-zA-Z0-9]+)-site-verification='
provider_verify = '([A-Z0-9]+)_verify_'
domain_validation = '^[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,62})*$'

[patterns.verification]

[patterns.provider_mappings]

[analysis]
strategy = "unlimited"
concurrency_per_depth = [50, 20, 10, 5]
request_delay_ms = 100
vendor_limits_per_depth = [0, 20, 10, 5]
total_vendor_budget = 200
"#;

        let config: AppConfig = toml::from_str(config_str).expect("Config should parse without discovery section");

        // Verify default values
        assert!(!config.discovery.subdomain_enabled, "subdomain_enabled should default to false");
        assert_eq!(config.discovery.subfinder_path, "subfinder", "subfinder_path should default to 'subfinder'");
        assert_eq!(config.discovery.subfinder_timeout_secs, 300, "subfinder_timeout_secs should default to 300");
        assert!(!config.discovery.saas_tenant_enabled, "saas_tenant_enabled should default to false");
        assert_eq!(config.discovery.tenant_probe_timeout_secs, 10, "tenant_probe_timeout_secs should default to 10");
        assert_eq!(config.discovery.tenant_probe_concurrency, 20, "tenant_probe_concurrency should default to 20");
    }
}
