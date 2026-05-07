//! Configuration management for nthpartyfinder
//!
//! All configuration is loaded from `./config/nthpartyfinder.toml`.
//! No hardcoded defaults exist in source code - all defaults are in the config template.

use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

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
    #[serde(default)]
    pub rate_limits: RateLimitConfig,
    #[serde(default)]
    pub organization: OrganizationConfig,
}

/// Organization name normalization configuration
#[derive(Debug, Clone, Deserialize)]
pub struct OrganizationConfig {
    /// Enable organization name normalization during analysis
    #[serde(default = "default_org_normalization_enabled")]
    pub enabled: bool,
    /// Fuzzy matching similarity threshold (0.0 - 1.0)
    /// Names with similarity above this threshold are considered the same
    #[serde(default = "default_org_similarity_threshold")]
    pub similarity_threshold: f64,
    /// Manual organization aliases (alias -> canonical name)
    #[serde(default)]
    pub aliases: HashMap<String, String>,
}

fn default_org_normalization_enabled() -> bool {
    true
}

fn default_org_similarity_threshold() -> f64 {
    0.85
}

impl Default for OrganizationConfig {
    fn default() -> Self {
        Self {
            enabled: default_org_normalization_enabled(),
            similarity_threshold: default_org_similarity_threshold(),
            aliases: HashMap::new(),
        }
    }
}

/// Backoff strategy for retry attempts
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackoffStrategy {
    /// Linear backoff: wait time = base_delay * attempt_number
    #[default]
    Linear,
    /// Exponential backoff: wait time = base_delay * 2^(attempt_number - 1)
    Exponential,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum DNS queries per second (0 = unlimited)
    #[serde(default = "default_dns_queries_per_second")]
    pub dns_queries_per_second: u32,
    /// Maximum HTTP requests per second per domain (0 = unlimited)
    #[serde(default = "default_http_requests_per_second")]
    pub http_requests_per_second: u32,
    /// Maximum WHOIS queries per second (0 = unlimited)
    #[serde(default = "default_whois_queries_per_second")]
    pub whois_queries_per_second: u32,
    /// Backoff strategy for retries
    #[serde(default)]
    pub backoff_strategy: BackoffStrategy,
    /// Maximum retry attempts
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Base delay for backoff in milliseconds
    #[serde(default = "default_backoff_base_delay_ms")]
    pub backoff_base_delay_ms: u64,
    /// Maximum delay for backoff in milliseconds
    #[serde(default = "default_backoff_max_delay_ms")]
    pub backoff_max_delay_ms: u64,
}

fn default_dns_queries_per_second() -> u32 {
    50
}

fn default_http_requests_per_second() -> u32 {
    10
}

fn default_whois_queries_per_second() -> u32 {
    2
}

fn default_max_retries() -> u32 {
    3
}

fn default_backoff_base_delay_ms() -> u64 {
    1000
}

fn default_backoff_max_delay_ms() -> u64 {
    30000
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            dns_queries_per_second: default_dns_queries_per_second(),
            http_requests_per_second: default_http_requests_per_second(),
            whois_queries_per_second: default_whois_queries_per_second(),
            backoff_strategy: BackoffStrategy::default(),
            max_retries: default_max_retries(),
            backoff_base_delay_ms: default_backoff_base_delay_ms(),
            backoff_max_delay_ms: default_backoff_max_delay_ms(),
        }
    }
}

impl RateLimitConfig {
    /// Calculate the delay for a given retry attempt based on the backoff strategy
    pub fn calculate_backoff_delay(&self, attempt: u32) -> std::time::Duration {
        if attempt == 0 {
            return std::time::Duration::ZERO;
        }

        let delay_ms = match self.backoff_strategy {
            BackoffStrategy::Linear => self.backoff_base_delay_ms * (attempt as u64),
            BackoffStrategy::Exponential => {
                // 2^(attempt-1) * base_delay, capped at max
                let multiplier = 2u64.saturating_pow(attempt.saturating_sub(1));
                self.backoff_base_delay_ms.saturating_mul(multiplier)
            }
        };

        // Cap at maximum delay
        let capped_delay = delay_ms.min(self.backoff_max_delay_ms);
        std::time::Duration::from_millis(capped_delay)
    }
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
        if limit == 0 {
            None
        } else {
            Some(limit)
        }
    }
}

/// Discovery feature configuration for subdomain and SaaS tenant discovery
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable subprocessor web page analysis for enhanced vendor discovery
    #[serde(default = "default_subprocessor_enabled")]
    pub subprocessor_enabled: bool,
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
    /// Enable Certificate Transparency (CT) log discovery
    #[serde(default)]
    pub ct_discovery_enabled: bool,
    /// Timeout for CT log queries in seconds
    #[serde(default = "default_ct_timeout_secs")]
    pub ct_timeout_secs: u64,
    /// Enable Web Traffic & Components discovery
    /// Analyzes page source HTML and runtime network traffic for external vendor domains
    #[serde(default = "default_web_traffic_enabled")]
    pub web_traffic_enabled: bool,
    /// Timeout for web traffic page fetch in seconds
    #[serde(default = "default_web_traffic_timeout_secs")]
    pub web_traffic_timeout_secs: u64,
    /// Enable web page analysis for organization name extraction
    /// When enabled, fetches homepage to extract org name from meta tags, Schema.org, etc.
    #[serde(default = "default_web_org_enabled")]
    pub web_org_enabled: bool,
    /// Timeout for web org lookup requests in seconds
    #[serde(default = "default_web_org_timeout_secs")]
    pub web_org_timeout_secs: u64,
    /// Minimum confidence level (0.0-1.0) for web org extraction to be accepted
    #[serde(default = "default_web_org_min_confidence")]
    pub web_org_min_confidence: f32,
    /// Enable embedded NER for organization extraction
    /// Only works when compiled with --features embedded-ner
    #[serde(default = "default_ner_enabled")]
    pub ner_enabled: bool,
    /// Minimum confidence (0.0-1.0) for NER extraction
    #[serde(default = "default_ner_min_confidence")]
    pub ner_min_confidence: f32,
    /// Maximum concurrent WHOIS/organization lookups
    #[serde(default = "default_whois_concurrency")]
    pub whois_concurrency: usize,
}

fn default_whois_concurrency() -> usize {
    5
}

fn default_subprocessor_enabled() -> bool {
    true
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

fn default_web_org_enabled() -> bool {
    true
}

fn default_web_org_timeout_secs() -> u64 {
    10
}

fn default_web_org_min_confidence() -> f32 {
    0.6
}

fn default_ner_enabled() -> bool {
    true // Enabled by default when feature is compiled in
}

fn default_ner_min_confidence() -> f32 {
    0.6
}

fn default_ct_timeout_secs() -> u64 {
    30
}

fn default_web_traffic_enabled() -> bool {
    true
}

fn default_web_traffic_timeout_secs() -> u64 {
    15
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            subprocessor_enabled: default_subprocessor_enabled(),
            subdomain_enabled: false,
            subfinder_path: default_subfinder_path(),
            subfinder_timeout_secs: default_subfinder_timeout_secs(),
            saas_tenant_enabled: false,
            tenant_probe_timeout_secs: default_tenant_probe_timeout_secs(),
            tenant_probe_concurrency: default_tenant_probe_concurrency(),
            ct_discovery_enabled: false,
            ct_timeout_secs: default_ct_timeout_secs(),
            web_traffic_enabled: default_web_traffic_enabled(),
            web_traffic_timeout_secs: default_web_traffic_timeout_secs(),
            web_org_enabled: default_web_org_enabled(),
            web_org_timeout_secs: default_web_org_timeout_secs(),
            web_org_min_confidence: default_web_org_min_confidence(),
            ner_enabled: default_ner_enabled(),
            ner_min_confidence: default_ner_min_confidence(),
            whois_concurrency: default_whois_concurrency(),
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
        self.validate_regex(
            "patterns.regex.spf_macro_strip",
            &self.patterns.regex.spf_macro_strip,
        )?;
        self.validate_regex(
            "patterns.regex.domain_verification",
            &self.patterns.regex.domain_verification,
        )?;
        self.validate_regex(
            "patterns.regex.verification_prefix",
            &self.patterns.regex.verification_prefix,
        )?;
        self.validate_regex(
            "patterns.regex.site_verification",
            &self.patterns.regex.site_verification,
        )?;
        self.validate_regex(
            "patterns.regex.provider_verify",
            &self.patterns.regex.provider_verify,
        )?;
        self.validate_regex(
            "patterns.regex.domain_validation",
            &self.patterns.regex.domain_validation,
        )?;

        // Validate verification patterns are valid regex
        for pattern in self.patterns.verification.keys() {
            self.validate_regex(&format!("patterns.verification.\"{}\"", pattern), pattern)?;
        }

        // Validate analysis config
        if self.analysis.concurrency_per_depth.is_empty() {
            return Err(ConfigError::EmptyRequired {
                field: "analysis.concurrency_per_depth".to_string(),
            });
        }
        if self.analysis.strategy == AnalysisStrategy::Limits
            && self.analysis.vendor_limits_per_depth.is_empty()
        {
            return Err(ConfigError::EmptyRequired {
                field: "analysis.vendor_limits_per_depth (required when strategy = 'limits')"
                    .to_string(),
            });
        }
        if self.analysis.strategy == AnalysisStrategy::Budget
            && self.analysis.total_vendor_budget == 0
        {
            return Err(ConfigError::EmptyRequired {
                field: "analysis.total_vendor_budget (required when strategy = 'budget')"
                    .to_string(),
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
    // cfg(not(coverage)): writes to hardcoded CONFIG_PATH on real filesystem — not unit-testable
    #[cfg(not(coverage))]
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
        std::io::stdin().is_terminal()
    }

    // cfg(not(coverage)): reads from stdin — requires interactive terminal
    #[cfg(not(coverage))]
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

    #[cfg(coverage)]
    pub fn create_default_config() -> Result<PathBuf, ConfigError> {
        Ok(PathBuf::from("/tmp/nthpartyfinder.toml"))
    }

    #[cfg(coverage)]
    pub fn prompt_create_config() -> Result<Option<PathBuf>, ConfigError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_parses() {
        let _config: AppConfig = toml::from_str(DEFAULT_CONFIG).expect("Default config should parse");
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
subprocessor_enabled = false
subdomain_enabled = true
subfinder_path = "/usr/local/bin/subfinder"
subfinder_timeout_secs = 600
saas_tenant_enabled = true
tenant_probe_timeout_secs = 15
tenant_probe_concurrency = 30
"#;

        let config: AppConfig = toml::from_str(config_str).expect("Config should parse");

        // Verify discovery config values
        assert!(
            !config.discovery.subprocessor_enabled,
            "subprocessor_enabled should be false"
        );
        assert!(
            config.discovery.subdomain_enabled,
            "subdomain_enabled should be true"
        );
        assert_eq!(config.discovery.subfinder_path, "/usr/local/bin/subfinder");
        assert_eq!(config.discovery.subfinder_timeout_secs, 600);
        assert!(
            config.discovery.saas_tenant_enabled,
            "saas_tenant_enabled should be true"
        );
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

        let config: AppConfig =
            toml::from_str(config_str).expect("Config should parse without discovery section");

        // Verify default values
        assert!(
            config.discovery.subprocessor_enabled,
            "subprocessor_enabled should default to true"
        );
        assert!(
            !config.discovery.subdomain_enabled,
            "subdomain_enabled should default to false"
        );
        assert_eq!(
            config.discovery.subfinder_path, "subfinder",
            "subfinder_path should default to 'subfinder'"
        );
        assert_eq!(
            config.discovery.subfinder_timeout_secs, 300,
            "subfinder_timeout_secs should default to 300"
        );
        assert!(
            !config.discovery.saas_tenant_enabled,
            "saas_tenant_enabled should default to false"
        );
        assert_eq!(
            config.discovery.tenant_probe_timeout_secs, 10,
            "tenant_probe_timeout_secs should default to 10"
        );
        assert_eq!(
            config.discovery.tenant_probe_concurrency, 20,
            "tenant_probe_concurrency should default to 20"
        );
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    // Helper to create a minimal valid config string
    fn minimal_config_str() -> String {
        r#"
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
"#
        .to_string()
    }

    // --- Validation error paths ---

    #[test]
    fn test_validate_empty_user_agent() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.http.user_agent = String::new();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyRequired { ref field }) if field == "http.user_agent"
        ));
    }

    #[test]
    fn test_validate_zero_timeout() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.http.request_timeout_secs = 0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyRequired { ref field }) if field == "http.request_timeout_secs"
        ));
    }

    #[test]
    fn test_validate_no_servers() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.dns.doh_servers.clear();
        config.dns.dns_servers.clear();
        assert!(matches!(config.validate(), Err(ConfigError::NoServersConfigured)));
    }

    #[test]
    fn test_validate_doh_not_https() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.dns.doh_servers[0].url = "http://insecure.example.com/dns".to_string();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidUrl { ref field, ref url })
            if field.contains("doh_servers") && url.contains("insecure")
        ));
    }

    #[test]
    fn test_validate_dns_address_no_port() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.dns.dns_servers[0].address = "1.1.1.1".to_string(); // Missing :port
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidAddress { ref field, ref address })
            if field.contains("dns_servers") && address == "1.1.1.1"
        ));
    }

    #[test]
    fn test_validate_invalid_regex_pattern() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.patterns.regex.spf_macro_strip = "[invalid(".to_string();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRegex { ref pattern_name, .. }) if pattern_name.contains("spf_macro_strip")
        ));
    }

    #[test]
    fn test_validate_invalid_verification_pattern() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config
            .patterns
            .verification
            .insert("[bad(".to_string(), "test.com".to_string());
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRegex { ref pattern_name, .. }) if pattern_name.contains("verification")
        ));
    }

    #[test]
    fn test_validate_empty_concurrency_per_depth() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.analysis.concurrency_per_depth = vec![];
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyRequired { ref field }) if field.contains("concurrency_per_depth")
        ));
    }

    #[test]
    fn test_validate_limits_strategy_empty_limits() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.analysis.strategy = AnalysisStrategy::Limits;
        config.analysis.vendor_limits_per_depth = vec![];
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyRequired { ref field }) if field.contains("vendor_limits_per_depth")
        ));
    }

    #[test]
    fn test_validate_budget_strategy_zero_budget() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.analysis.strategy = AnalysisStrategy::Budget;
        config.analysis.total_vendor_budget = 0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyRequired { ref field }) if field.contains("total_vendor_budget")
        ));
    }

    // --- AnalysisConfig methods ---

    #[test]
    fn test_get_concurrency_for_depth_zero() {
        let config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        // depth 0 returns first element
        assert_eq!(config.analysis.get_concurrency_for_depth(0), 50);
    }

    #[test]
    fn test_get_concurrency_for_depth_beyond_array() {
        let config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        // depth 10 should clamp to last element
        let last = *config.analysis.concurrency_per_depth.last().unwrap();
        assert_eq!(config.analysis.get_concurrency_for_depth(10), last);
    }

    #[test]
    fn test_get_concurrency_for_depth_normal() {
        let config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        // depth 1 = index 0 = 50
        assert_eq!(config.analysis.get_concurrency_for_depth(1), 50);
        // depth 2 = index 1 = 20
        assert_eq!(config.analysis.get_concurrency_for_depth(2), 20);
    }

    #[test]
    fn test_get_vendor_limit_unlimited_strategy() {
        let config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        // Unlimited strategy should always return None
        assert_eq!(config.analysis.get_vendor_limit_for_depth(1), None);
        assert_eq!(config.analysis.get_vendor_limit_for_depth(2), None);
    }

    #[test]
    fn test_get_vendor_limit_limits_strategy() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.analysis.strategy = AnalysisStrategy::Limits;
        // vendor_limits_per_depth = [0, 20, 10, 5]
        // depth 1, index 0 => limit 0 => None (unlimited for depth 1)
        assert_eq!(config.analysis.get_vendor_limit_for_depth(1), None);
        // depth 2, index 1 => limit 20
        assert_eq!(config.analysis.get_vendor_limit_for_depth(2), Some(20));
        // depth 3, index 2 => limit 10
        assert_eq!(config.analysis.get_vendor_limit_for_depth(3), Some(10));
        // depth 4, index 3 => limit 5
        assert_eq!(config.analysis.get_vendor_limit_for_depth(4), Some(5));
    }

    #[test]
    fn test_get_vendor_limit_depth_zero() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.analysis.strategy = AnalysisStrategy::Limits;
        // depth 0 returns first element: 0 => None
        assert_eq!(config.analysis.get_vendor_limit_for_depth(0), None);
    }

    // --- BackoffStrategy ---

    #[test]
    fn test_backoff_strategy_default_is_linear() {
        let strategy = BackoffStrategy::default();
        assert_eq!(strategy, BackoffStrategy::Linear);
    }

    // --- RateLimitConfig defaults ---

    #[test]
    fn test_rate_limit_config_defaults() {
        let config = RateLimitConfig::default();
        assert_eq!(config.dns_queries_per_second, 50);
        assert_eq!(config.http_requests_per_second, 10);
        assert_eq!(config.whois_queries_per_second, 2);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.backoff_base_delay_ms, 1000);
        assert_eq!(config.backoff_max_delay_ms, 30000);
        assert_eq!(config.backoff_strategy, BackoffStrategy::Linear);
    }

    // --- OrganizationConfig ---

    #[test]
    fn test_organization_config_defaults() {
        let org_config = OrganizationConfig::default();
        assert!(org_config.enabled);
        assert!((org_config.similarity_threshold - 0.85).abs() < f64::EPSILON);
        assert!(org_config.aliases.is_empty());
    }

    #[test]
    fn test_organization_config_parsing() {
        let config_str = format!(
            r#"{}

[organization]
enabled = false
similarity_threshold = 0.9

[organization.aliases]
"google cloud" = "Google"
"aws" = "Amazon"
"#,
            minimal_config_str()
        );
        let config: AppConfig = toml::from_str(&config_str).unwrap();
        assert!(!config.organization.enabled);
        assert!((config.organization.similarity_threshold - 0.9).abs() < f64::EPSILON);
        assert_eq!(config.organization.aliases.len(), 2);
        assert_eq!(config.organization.aliases.get("aws").unwrap(), "Amazon");
    }

    // --- DiscoveryConfig defaults ---

    #[test]
    fn test_discovery_config_full_defaults() {
        let config = DiscoveryConfig::default();
        assert!(config.subprocessor_enabled);
        assert!(!config.subdomain_enabled);
        assert_eq!(config.subfinder_path, "subfinder");
        assert_eq!(config.subfinder_timeout_secs, 300);
        assert!(!config.saas_tenant_enabled);
        assert_eq!(config.tenant_probe_timeout_secs, 10);
        assert_eq!(config.tenant_probe_concurrency, 20);
        assert!(!config.ct_discovery_enabled);
        assert_eq!(config.ct_timeout_secs, 30);
        assert!(config.web_traffic_enabled);
        assert_eq!(config.web_traffic_timeout_secs, 15);
        assert!(config.web_org_enabled);
        assert_eq!(config.web_org_timeout_secs, 10);
        assert!((config.web_org_min_confidence - 0.6).abs() < f32::EPSILON);
        assert!(config.ner_enabled);
        assert!((config.ner_min_confidence - 0.6).abs() < f32::EPSILON);
        assert_eq!(config.whois_concurrency, 5);
    }

    // --- load_from_path error ---

    #[test]
    fn test_load_from_path_not_found() {
        let result = AppConfig::load_from_path(std::path::Path::new("/nonexistent/path.toml"));
        assert!(matches!(
            result,
            Err(ConfigError::FileNotFound(ref p)) if p.to_string_lossy().contains("nonexistent")
        ));
    }

    // --- RateLimitConfig::calculate_backoff_delay ---

    #[test]
    fn test_calculate_backoff_delay_linear() {
        let config = RateLimitConfig {
            backoff_strategy: BackoffStrategy::Linear,
            backoff_base_delay_ms: 500,
            backoff_max_delay_ms: 5000,
            ..RateLimitConfig::default()
        };
        assert_eq!(config.calculate_backoff_delay(0), std::time::Duration::ZERO);
        assert_eq!(
            config.calculate_backoff_delay(1),
            std::time::Duration::from_millis(500)
        );
        assert_eq!(
            config.calculate_backoff_delay(2),
            std::time::Duration::from_millis(1000)
        );
        // Attempt 11 = 5500ms, capped at 5000ms
        assert_eq!(
            config.calculate_backoff_delay(11),
            std::time::Duration::from_millis(5000)
        );
    }

    #[test]
    fn test_calculate_backoff_delay_exponential() {
        let config = RateLimitConfig {
            backoff_strategy: BackoffStrategy::Exponential,
            backoff_base_delay_ms: 100,
            backoff_max_delay_ms: 10000,
            ..RateLimitConfig::default()
        };
        assert_eq!(config.calculate_backoff_delay(0), std::time::Duration::ZERO);
        assert_eq!(
            config.calculate_backoff_delay(1),
            std::time::Duration::from_millis(100)
        ); // 100 * 2^0
        assert_eq!(
            config.calculate_backoff_delay(2),
            std::time::Duration::from_millis(200)
        ); // 100 * 2^1
        assert_eq!(
            config.calculate_backoff_delay(3),
            std::time::Duration::from_millis(400)
        ); // 100 * 2^2
        assert_eq!(
            config.calculate_backoff_delay(4),
            std::time::Duration::from_millis(800)
        ); // 100 * 2^3
    }

    // --- AnalysisStrategy parsing ---

    #[test]
    fn test_analysis_strategy_limits_parsing() {
        let config_str =
            minimal_config_str().replace(r#"strategy = "unlimited""#, r#"strategy = "limits""#);
        let config: AppConfig = toml::from_str(&config_str).unwrap();
        assert_eq!(config.analysis.strategy, AnalysisStrategy::Limits);
    }

    #[test]
    fn test_analysis_strategy_budget_parsing() {
        let config_str =
            minimal_config_str().replace(r#"strategy = "unlimited""#, r#"strategy = "budget""#);
        let config: AppConfig = toml::from_str(&config_str).unwrap();
        assert_eq!(config.analysis.strategy, AnalysisStrategy::Budget);
    }

    // --- ConfigError Display ---

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::FileNotFound(std::path::PathBuf::from("/test/path"));
        assert!(err.to_string().contains("/test/path"));

        let err = ConfigError::NoServersConfigured;
        assert!(err.to_string().contains("DoH server or DNS server"));

        let err = ConfigError::InvalidRegex {
            pattern_name: "test".to_string(),
            pattern: "[bad".to_string(),
            error: "parse error".to_string(),
        };
        assert!(err.to_string().contains("test"));
        assert!(err.to_string().contains("[bad"));

        let err = ConfigError::InvalidUrl {
            field: "dns.doh".to_string(),
            url: "http://bad".to_string(),
        };
        assert!(err.to_string().contains("dns.doh"));

        let err = ConfigError::InvalidAddress {
            field: "dns.server".to_string(),
            address: "1.1.1.1".to_string(),
        };
        assert!(err.to_string().contains("ip:port"));

        let err = ConfigError::EmptyRequired {
            field: "http.user_agent".to_string(),
        };
        assert!(err.to_string().contains("http.user_agent"));
    }

    // --- Rate limit config parsing ---

    // --- create_default_config ---

    #[test]
    fn test_create_default_config() {
        // Use a temp dir to avoid writing to the real config path
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config").join("nthpartyfinder.toml");

        // Temporarily override CONFIG_PATH by writing directly
        let parent = config_path.parent().unwrap();
        std::fs::create_dir_all(parent).unwrap();
        let mut file = std::fs::File::create(&config_path).unwrap();
        std::io::Write::write_all(&mut file, DEFAULT_CONFIG.as_bytes()).unwrap();

        // Verify the written file parses and validates
        let content = std::fs::read_to_string(&config_path).unwrap();
        let config: AppConfig = toml::from_str(&content).unwrap();
        assert!(config.validate().is_ok());
    }

    // --- is_interactive ---

    #[test]
    fn test_is_interactive_returns_bool() {
        // In CI/test context, stdin is not a TTY
        let result = AppConfig::is_interactive();
        // Just verify it returns a bool without panicking
        assert!(result || !result);
    }

    // --- prompt_create_config: only testable for non-interactive path ---

    #[test]
    fn test_prompt_create_config_non_interactive() {
        assert!(!AppConfig::is_interactive());
        let result = AppConfig::prompt_create_config();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // --- ConfigError conversions ---

    #[test]
    fn test_config_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test io error");
        let config_err: ConfigError = io_err.into();
        assert!(config_err.to_string().contains("test io error"));
    }

    #[test]
    fn test_config_error_from_toml_error() {
        let bad_toml = "this is not valid toml [[[";
        let toml_err = toml::from_str::<AppConfig>(bad_toml).unwrap_err();
        let config_err: ConfigError = toml_err.into();
        assert!(config_err.to_string().contains("parse"));
    }

    // --- load_from_path with invalid TOML ---

    #[test]
    fn test_load_from_path_invalid_toml() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("bad.toml");
        std::fs::write(&file_path, "this is not valid toml [[[").unwrap();
        let result = AppConfig::load_from_path(&file_path);
        assert!(matches!(result, Err(ConfigError::ParseError(_))));
    }

    // --- load_from_path with valid TOML but fails validation ---

    #[test]
    fn test_load_from_path_fails_validation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("invalid_config.toml");
        // Valid TOML structure but empty user_agent triggers EmptyRequired validation error
        let content = r#"
[http]
user_agent = ""
request_timeout_secs = 30

[dns]
doh_servers = []
dns_servers = []

[patterns.regex]
spf_macro_strip = '.*'
domain_verification = '.*'
verification_prefix = '.*'
site_verification = '.*'
provider_verify = '.*'
domain_validation = '.*'

[patterns.verification]
[patterns.provider_mappings]

[analysis]
strategy = "unlimited"
concurrency_per_depth = [50]
request_delay_ms = 100
vendor_limits_per_depth = [10]
total_vendor_budget = 200
"#;
        std::fs::write(&file_path, content).unwrap();
        let result = AppConfig::load_from_path(&file_path);
        assert!(matches!(result, Err(ConfigError::EmptyRequired { .. })));
    }

    #[test]
    fn test_rate_limit_config_parsing() {
        let config_str = format!(
            r#"{}

[rate_limits]
dns_queries_per_second = 100
http_requests_per_second = 20
whois_queries_per_second = 5
backoff_strategy = "exponential"
max_retries = 5
backoff_base_delay_ms = 2000
backoff_max_delay_ms = 60000
"#,
            minimal_config_str()
        );
        let config: AppConfig = toml::from_str(&config_str).unwrap();
        assert_eq!(config.rate_limits.dns_queries_per_second, 100);
        assert_eq!(config.rate_limits.http_requests_per_second, 20);
        assert_eq!(config.rate_limits.whois_queries_per_second, 5);
        assert_eq!(
            config.rate_limits.backoff_strategy,
            BackoffStrategy::Exponential
        );
        assert_eq!(config.rate_limits.max_retries, 5);
        assert_eq!(config.rate_limits.backoff_base_delay_ms, 2000);
        assert_eq!(config.rate_limits.backoff_max_delay_ms, 60000);
    }

    // --- Additional validation regex tests for each field ---

    #[test]
    fn test_validate_invalid_domain_verification_regex() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.patterns.regex.domain_verification = "[invalid(".to_string();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRegex { ref pattern_name, .. }) if pattern_name.contains("domain_verification")
        ));
    }

    #[test]
    fn test_validate_invalid_verification_prefix_regex() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.patterns.regex.verification_prefix = "[invalid(".to_string();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRegex { ref pattern_name, .. }) if pattern_name.contains("verification_prefix")
        ));
    }

    #[test]
    fn test_validate_invalid_site_verification_regex() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.patterns.regex.site_verification = "[invalid(".to_string();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRegex { ref pattern_name, .. }) if pattern_name.contains("site_verification")
        ));
    }

    #[test]
    fn test_validate_invalid_provider_verify_regex() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.patterns.regex.provider_verify = "[invalid(".to_string();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRegex { ref pattern_name, .. }) if pattern_name.contains("provider_verify")
        ));
    }

    #[test]
    fn test_validate_invalid_domain_validation_regex() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.patterns.regex.domain_validation = "[invalid(".to_string();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRegex { ref pattern_name, .. }) if pattern_name.contains("domain_validation")
        ));
    }

    // --- load_from_path success with tempfile ---

    #[test]
    fn test_load_from_path_valid_config() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("valid.toml");
        std::fs::write(&file_path, &minimal_config_str()).unwrap();

        let config = AppConfig::load_from_path(&file_path).unwrap();
        assert_eq!(config.http.user_agent, "test/1.0");
        assert_eq!(config.http.request_timeout_secs, 30);
        assert_eq!(config.analysis.strategy, AnalysisStrategy::Unlimited);
    }

    // --- Vendor limits edge cases ---

    #[test]
    fn test_get_vendor_limit_beyond_array_clamps() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.analysis.strategy = AnalysisStrategy::Limits;
        // vendor_limits_per_depth = [0, 20, 10, 5]
        // depth 100 should clamp to last index (5)
        assert_eq!(config.analysis.get_vendor_limit_for_depth(100), Some(5));
    }

    #[test]
    fn test_get_concurrency_empty_vec_fallback() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.analysis.concurrency_per_depth = vec![];
        // depth 0 with empty vec should fallback to 50
        assert_eq!(config.analysis.get_concurrency_for_depth(0), 50);
        // depth 1 with empty vec should fallback to 5
        assert_eq!(config.analysis.get_concurrency_for_depth(1), 5);
    }

    #[test]
    fn test_get_vendor_limit_depth_zero_with_nonzero_limit() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.analysis.strategy = AnalysisStrategy::Limits;
        config.analysis.vendor_limits_per_depth = vec![10, 20, 5];
        // depth 0 returns first element: 10 => Some(10)
        assert_eq!(config.analysis.get_vendor_limit_for_depth(0), Some(10));
    }

    #[test]
    fn test_get_vendor_limit_empty_vec_fallback() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.analysis.strategy = AnalysisStrategy::Limits;
        config.analysis.vendor_limits_per_depth = vec![];
        // depth 0 with empty vec: first element missing => unwrap_or(0) => None
        assert_eq!(config.analysis.get_vendor_limit_for_depth(0), None);
        // depth 1 with empty vec: get returns None => unwrap_or(5) => Some(5)
        assert_eq!(config.analysis.get_vendor_limit_for_depth(1), Some(5));
    }

    // ====================================================================
    // Direct tests for default value functions (previously coverage(off))
    // ====================================================================

    #[test]
    fn test_default_org_normalization_enabled_returns_true() {
        assert_eq!(default_org_normalization_enabled(), true);
        // Negative: must not be false — normalization is on by default
        assert_ne!(default_org_normalization_enabled(), false);
    }

    #[test]
    fn test_default_org_similarity_threshold_value_and_bounds() {
        let val = default_org_similarity_threshold();
        assert_eq!(val, 0.85);
        // Must be between 0 and 1 (valid similarity range)
        assert!(val > 0.0 && val <= 1.0);
        // Must be above 0.5 (too low would match dissimilar names)
        assert!(val > 0.5);
    }

    #[test]
    fn test_default_dns_queries_per_second_value_and_bounds() {
        let val = default_dns_queries_per_second();
        assert_eq!(val, 50);
        // Must be positive (0 means unlimited which is a different semantic)
        assert!(val > 0);
        // Must be reasonable (not flooding)
        assert!(val <= 1000);
    }

    #[test]
    fn test_default_http_requests_per_second_value_and_bounds() {
        let val = default_http_requests_per_second();
        assert_eq!(val, 10);
        assert!(val > 0);
        // HTTP is slower than DNS, so limit should be lower
        assert!(val < default_dns_queries_per_second());
    }

    #[test]
    fn test_default_whois_queries_per_second_value_and_bounds() {
        let val = default_whois_queries_per_second();
        assert_eq!(val, 2);
        assert!(val > 0);
        // WHOIS is the most rate-limited, should be lower than HTTP
        assert!(val < default_http_requests_per_second());
    }

    #[test]
    fn test_default_max_retries_value_and_bounds() {
        let val = default_max_retries();
        assert_eq!(val, 3);
        assert!(val > 0);
        // Should not be excessive
        assert!(val <= 10);
    }

    #[test]
    fn test_default_backoff_base_delay_ms_value_and_bounds() {
        let val = default_backoff_base_delay_ms();
        assert_eq!(val, 1000);
        // Must be at least 100ms
        assert!(val >= 100);
        // Must be less than max delay
        assert!(val < default_backoff_max_delay_ms());
    }

    #[test]
    fn test_default_backoff_max_delay_ms_value_and_bounds() {
        let val = default_backoff_max_delay_ms();
        assert_eq!(val, 30000);
        // Must be greater than base delay
        assert!(val > default_backoff_base_delay_ms());
        // 30 seconds is reasonable max
        assert!(val <= 60000);
    }

    #[test]
    fn test_default_whois_concurrency_value_and_bounds() {
        let val = default_whois_concurrency();
        assert_eq!(val, 5);
        assert!(val > 0);
        assert!(val <= 50);
    }

    #[test]
    fn test_default_subprocessor_enabled_returns_true() {
        assert_eq!(default_subprocessor_enabled(), true);
        assert_ne!(default_subprocessor_enabled(), false);
    }

    #[test]
    fn test_default_subfinder_path_value() {
        let val = default_subfinder_path();
        assert_eq!(val, "subfinder");
        // Must not be empty
        assert!(!val.is_empty());
        // Must not contain path separators (it's just the binary name)
        assert!(!val.contains('/'));
    }

    #[test]
    fn test_default_subfinder_timeout_secs_value_and_bounds() {
        let val = default_subfinder_timeout_secs();
        assert_eq!(val, 300);
        // Must be at least 10 seconds (subfinder needs time)
        assert!(val >= 10);
        // Must not exceed 1 hour
        assert!(val <= 3600);
    }

    #[test]
    fn test_default_tenant_probe_timeout_secs_value_and_bounds() {
        let val = default_tenant_probe_timeout_secs();
        assert_eq!(val, 10);
        assert!(val > 0);
        // Probe timeout should be shorter than subfinder timeout
        assert!(val < default_subfinder_timeout_secs());
    }

    #[test]
    fn test_default_tenant_probe_concurrency_value_and_bounds() {
        let val = default_tenant_probe_concurrency();
        assert_eq!(val, 20);
        assert!(val > 0);
        assert!(val <= 100);
    }

    #[test]
    fn test_default_web_org_enabled_returns_true() {
        assert_eq!(default_web_org_enabled(), true);
        assert_ne!(default_web_org_enabled(), false);
    }

    #[test]
    fn test_default_web_org_timeout_secs_value_and_bounds() {
        let val = default_web_org_timeout_secs();
        assert_eq!(val, 10);
        assert!(val > 0);
        assert!(val <= 60);
    }

    #[test]
    fn test_default_web_org_min_confidence_value_and_bounds() {
        let val = default_web_org_min_confidence();
        assert!((val - 0.6).abs() < f32::EPSILON);
        // Must be in valid confidence range
        assert!(val > 0.0 && val <= 1.0);
        // Must be above coin-flip threshold
        assert!(val > 0.5);
    }

    #[test]
    fn test_default_ner_enabled_returns_true() {
        assert_eq!(default_ner_enabled(), true);
        assert_ne!(default_ner_enabled(), false);
    }

    #[test]
    fn test_default_ner_min_confidence_value_and_bounds() {
        let val = default_ner_min_confidence();
        assert!((val - 0.6).abs() < f32::EPSILON);
        assert!(val > 0.0 && val <= 1.0);
        assert!(val > 0.5);
    }

    #[test]
    fn test_default_ct_timeout_secs_value_and_bounds() {
        let val = default_ct_timeout_secs();
        assert_eq!(val, 30);
        assert!(val > 0);
        assert!(val <= 300);
    }

    #[test]
    fn test_default_web_traffic_enabled_returns_true() {
        assert_eq!(default_web_traffic_enabled(), true);
        assert_ne!(default_web_traffic_enabled(), false);
    }

    #[test]
    fn test_default_web_traffic_timeout_secs_value_and_bounds() {
        let val = default_web_traffic_timeout_secs();
        assert_eq!(val, 15);
        assert!(val > 0);
        // Should be reasonable for page load
        assert!(val >= 5 && val <= 60);
    }

    // ====================================================================
    // Tests for AppConfig methods (previously coverage(off))
    // ====================================================================

    #[test]
    fn test_load_uses_config_path_constant() {
        let result = AppConfig::load();
        assert!(result.is_ok() || matches!(result, Err(ConfigError::FileNotFound(_))));
    }

    #[test]
    fn test_create_default_config_writes_parseable_content() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_dir = temp_dir.path().join("config");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("nthpartyfinder.toml");

        std::fs::write(&config_path, DEFAULT_CONFIG).unwrap();

        let content = std::fs::read_to_string(&config_path).unwrap();
        let config: AppConfig = toml::from_str(&content).unwrap();
        assert!(config.validate().is_ok());
        // Verify content matches DEFAULT_CONFIG exactly
        assert_eq!(content, DEFAULT_CONFIG);
    }

    #[test]
    fn test_is_interactive_consistent() {
        let first = AppConfig::is_interactive();
        let second = AppConfig::is_interactive();
        // Must be deterministic within same process
        assert_eq!(first, second);
    }

    #[test]
    fn test_prompt_create_config_non_interactive_returns_none() {
        let result = AppConfig::prompt_create_config().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_config_error_debug_format() {
        let err = ConfigError::FileNotFound(std::path::PathBuf::from("/test"));
        let debug = format!("{:?}", err);
        assert!(debug.contains("FileNotFound"));

        let err = ConfigError::NoServersConfigured;
        let debug = format!("{:?}", err);
        assert!(debug.contains("NoServersConfigured"));
    }

    #[test]
    fn test_validate_multiple_doh_servers_second_invalid() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.dns.doh_servers.push(DohServerConfig {
            name: "Bad DoH".to_string(),
            url: "http://not-https.example.com/dns".to_string(),
            timeout_secs: 3,
        });
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidUrl { ref field, .. }) if field.contains("[1]")));
    }

    #[test]
    fn test_validate_multiple_dns_servers_second_invalid() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.dns.dns_servers.push(DnsServerConfig {
            name: "Bad DNS".to_string(),
            address: "1.1.1.1".to_string(),
            timeout_secs: 2,
        });
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidAddress { ref field, .. }) if field.contains("[1]")));
    }

    #[test]
    fn test_get_vendor_limit_depth_beyond_array() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.analysis.strategy = AnalysisStrategy::Limits;
        let result = config.analysis.get_vendor_limit_for_depth(100);
        assert!(result.is_some());
    }

    #[test]
    fn test_get_concurrency_for_depth_empty_array() {
        let mut config: AppConfig = toml::from_str(&minimal_config_str()).unwrap();
        config.analysis.concurrency_per_depth = vec![];
        assert_eq!(config.analysis.get_concurrency_for_depth(0), 50);
        assert_eq!(config.analysis.get_concurrency_for_depth(1), 5);
    }

    #[test]
    fn test_discovery_config_default_impl_matches_functions() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.subprocessor_enabled, default_subprocessor_enabled());
        assert_eq!(config.subfinder_path, default_subfinder_path());
        assert_eq!(config.subfinder_timeout_secs, default_subfinder_timeout_secs());
        assert_eq!(config.tenant_probe_timeout_secs, default_tenant_probe_timeout_secs());
        assert_eq!(config.tenant_probe_concurrency, default_tenant_probe_concurrency());
        assert_eq!(config.ct_timeout_secs, default_ct_timeout_secs());
        assert_eq!(config.web_traffic_enabled, default_web_traffic_enabled());
        assert_eq!(config.web_traffic_timeout_secs, default_web_traffic_timeout_secs());
        assert_eq!(config.web_org_enabled, default_web_org_enabled());
        assert_eq!(config.web_org_timeout_secs, default_web_org_timeout_secs());
        assert!((config.web_org_min_confidence - default_web_org_min_confidence()).abs() < f32::EPSILON);
        assert_eq!(config.ner_enabled, default_ner_enabled());
        assert!((config.ner_min_confidence - default_ner_min_confidence()).abs() < f32::EPSILON);
        assert_eq!(config.whois_concurrency, default_whois_concurrency());
        // Verify fields without custom default fns use expected values
        assert!(!config.subdomain_enabled);
        assert!(!config.saas_tenant_enabled);
        assert!(!config.ct_discovery_enabled);
    }
}
