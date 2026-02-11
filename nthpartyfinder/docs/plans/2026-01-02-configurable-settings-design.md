# Configurable Settings Design

**Date:** 2026-01-02
**Status:** Approved
**Goal:** Make all hardcoded settings user-customizable via TOML configuration file

## Summary

Move all hardcoded values (DoH servers, DNS servers, user agent, regex patterns, verification patterns, provider mappings) from source code to a TOML configuration file at `./config/nthpartyfinder.toml`. The source code will contain zero hardcoded defaults—all defaults live in the config file template.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Config format | TOML | Human-readable, Rust-native serde support, already used by Cargo |
| Config location | `./config/nthpartyfinder.toml` | Docker-friendly (easy volume mount), per-project customization |
| Missing config behavior | Prompt to create | Balances convenience with explicit configuration |
| Default storage | Embedded template string | No hardcoded logic, just template content |

## Configuration File Structure

```toml
# nthpartyfinder Configuration File
# Location: ./config/nthpartyfinder.toml

[http]
user_agent = "nthpartyfinder/1.0 (Security Research Tool)"
request_timeout_secs = 30

# =============================================================================
# DNS Configuration
# =============================================================================
[dns]

# DNS-over-HTTPS servers (tried in order until one succeeds)
[[dns.doh_servers]]
name = "Cloudflare DoH"
url = "https://cloudflare-dns.com/dns-query"
timeout_secs = 3

[[dns.doh_servers]]
name = "Google DoH"
url = "https://dns.google/dns-query"
timeout_secs = 3

[[dns.doh_servers]]
name = "Quad9 DoH"
url = "https://dns.quad9.net/dns-query"
timeout_secs = 4

[[dns.doh_servers]]
name = "NextDNS DoH"
url = "https://dns.nextdns.io/dns-query"
timeout_secs = 4

# Traditional DNS servers (fallback when DoH fails)
[[dns.dns_servers]]
name = "Quad9"
address = "9.9.9.9:53"
timeout_secs = 3

[[dns.dns_servers]]
name = "Cloudflare"
address = "1.1.1.1:53"
timeout_secs = 3

[[dns.dns_servers]]
name = "Google"
address = "8.8.8.8:53"
timeout_secs = 3

[[dns.dns_servers]]
name = "OpenDNS"
address = "208.67.222.222:53"
timeout_secs = 3

# =============================================================================
# Regex Patterns for Dynamic TXT Record Parsing
# These patterns extract vendor names from unknown/new verification records
# =============================================================================
[patterns.regex]

# Strips SPF macro variables (e.g., %{ir}.%{v}.domain.com -> domain.com)
spf_macro_strip = '%\{[a-zA-Z]+[0-9]*[a-zA-Z]*\}\.?'

# Matches: {provider}-domain-verification= or {provider}-verification=
# Captures: provider name (group 1)
domain_verification = '([a-zA-Z0-9]+)(?:-domain)?-verification='

# Matches: verification-{provider}=
# Captures: provider name (group 1)
verification_prefix = 'verification-([a-zA-Z0-9]+)='

# Matches: {provider}-site-verification=
# Captures: provider name (group 1)
site_verification = '([a-zA-Z0-9]+)-site-verification='

# Matches: {PROVIDER}_verify_ (e.g., ZOOM_verify_)
# Captures: provider name (group 1)
provider_verify = '([A-Z0-9]+)_verify_'

# Validates extracted domain format
domain_validation = '^[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,62}(\.[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,62})*$'

# =============================================================================
# Static Verification Patterns
# Maps known TXT record prefixes directly to vendor domains
# Used for exact-match lookups (faster than regex for known vendors)
# =============================================================================
[patterns.verification]
"google-site-verification=" = "google.com"
"MS=" = "microsoft.com"
"apple-domain-verification=" = "apple.com"
"adobe-idp-site-verification=" = "adobe.com"
"stripe-verification=" = "stripe.com"
"docusign=" = "docusign.com"
# ... (complete list in implementation)

# =============================================================================
# Provider Name to Domain Mappings
# Used by dynamic regex extraction: when a regex captures a provider name
# (e.g., "anthropic" from "anthropic-domain-verification=xyz"), this mapping
# resolves it to the vendor's actual domain (e.g., "anthropic.com")
# =============================================================================
[patterns.provider_mappings]
google = "google.com"
microsoft = "microsoft.com"
anthropic = "anthropic.com"
intacct = "sage.com"  # Special case: Sage Intacct product
aws = "amazon.com"
gcp = "google.com"
azure = "microsoft.com"
# ... (complete list in implementation)
```

## Implementation Architecture

### New File: `src/config.rs`

```rust
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub http: HttpConfig,
    pub dns: DnsConfig,
    pub patterns: PatternsConfig,
}

#[derive(Debug, Deserialize)]
pub struct HttpConfig {
    pub user_agent: String,
    pub request_timeout_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct DnsConfig {
    pub doh_servers: Vec<DohServerConfig>,
    pub dns_servers: Vec<DnsServerConfig>,
}

#[derive(Debug, Deserialize)]
pub struct DohServerConfig {
    pub name: String,
    pub url: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct DnsServerConfig {
    pub name: String,
    pub address: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct PatternsConfig {
    pub regex: RegexPatterns,
    pub verification: HashMap<String, String>,
    pub provider_mappings: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct RegexPatterns {
    pub spf_macro_strip: String,
    pub domain_verification: String,
    pub verification_prefix: String,
    pub site_verification: String,
    pub provider_verify: String,
    pub domain_validation: String,
}

impl AppConfig {
    pub const CONFIG_PATH: &'static str = "./config/nthpartyfinder.toml";

    /// Load config from ./config/nthpartyfinder.toml
    pub fn load() -> Result<Self, ConfigError>;

    /// Default config file content (embedded template)
    pub fn default_toml() -> &'static str;

    /// Create default config file
    pub fn create_default_config() -> Result<PathBuf, ConfigError>;

    /// Validate all config values (regex compilation, URL format, etc.)
    pub fn validate(&self) -> Result<(), ConfigError>;
}
```

### Error Types

```rust
pub enum ConfigError {
    FileNotFound(PathBuf),
    ParseError {
        path: PathBuf,
        line: Option<usize>,
        col: Option<usize>,
        message: String
    },
    InvalidRegex {
        pattern_name: String,
        pattern: String,
        error: String
    },
    InvalidUrl {
        field: String,
        url: String
    },
    InvalidAddress {
        field: String,
        address: String,
    },
    EmptyRequired {
        field: String
    },
    IoError(std::io::Error),
}
```

### Changes to Existing Files

**`src/main.rs`:**
- Add `--init` CLI flag
- Load config at startup
- Handle missing config with prompt
- Pass `&AppConfig` to analysis functions

**`src/dns.rs`:**
- Remove all hardcoded server lists
- Remove hardcoded regex patterns (keep `Lazy<Regex>` but initialize from config)
- Remove hardcoded verification patterns
- Remove hardcoded provider mappings
- Accept `&AppConfig` in constructor/functions
- `DnsServerPool::new()` → `DnsServerPool::from_config(&AppConfig)`

**`src/subprocessor.rs`:**
- Use `config.http.user_agent` for HTTP requests
- Use `config.http.request_timeout_secs` for timeouts

**`src/lib.rs`:**
- Export `config` module

## Startup Flow

```
1. Parse CLI arguments
2. If --init flag:
   → Create ./config/nthpartyfinder.toml
   → Print success message with path
   → Exit 0
3. Attempt to load ./config/nthpartyfinder.toml
   → Success: Continue
   → FileNotFound:
      - If TTY: Prompt "Config not found. Create default? [Y/n]"
        - Y: Create config, print path, exit 0 (user reviews before running)
        - N: Exit 1 with error
      - If not TTY: Exit 1 with "Run with --init to create config"
   → ParseError: Exit 1 with detailed error (line/col)
4. Validate config (compile regexes, check URLs)
   → Fail: Exit 1 with specific validation error
5. Proceed with analysis
```

## Validation Rules

| Field | Validation |
|-------|------------|
| `patterns.regex.*` | Must compile as valid regex |
| `dns.doh_servers[].url` | Must be valid HTTPS URL |
| `dns.dns_servers[].address` | Must be valid `ip:port` format |
| `dns.doh_servers` OR `dns.dns_servers` | At least one must have entries |
| `patterns.provider_mappings` values | Must contain `.` (look like domains) |
| `http.request_timeout_secs` | Must be > 0 |

## Docker Considerations

- Config path `./config/` maps cleanly to volume mount: `-v /host/config:/app/config`
- Non-TTY detection ensures clean failure in containers
- `--init` can be run in container to generate config to mounted volume

## Testing Strategy

1. **Unit tests for `config.rs`:**
   - Parse valid TOML
   - Detect missing required fields
   - Validate regex compilation errors
   - Validate URL format errors

2. **Integration tests:**
   - `--init` creates valid config file
   - Tool runs successfully with generated config
   - Tool fails gracefully with invalid config

## Implementation Order

1. Add `toml` dependency to `Cargo.toml`
2. Create `src/config.rs` with structs and loading logic
3. Create default TOML template with all current hardcoded values
4. Add `--init` flag to CLI
5. Update `main.rs` startup flow
6. Refactor `dns.rs` to use config
7. Refactor `subprocessor.rs` to use config
8. Remove all hardcoded values from source
9. Add tests
10. Update documentation
