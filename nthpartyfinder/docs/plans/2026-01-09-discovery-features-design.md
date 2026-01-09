# Discovery Features Design: Subdomain & SaaS Tenant Discovery

**Date:** 2026-01-09
**Status:** Approved

## Overview

This design adds two new discovery capabilities to nthpartyfinder:

1. **Subdomain Discovery** - Uses Project Discovery's subfinder to enumerate subdomains and identify third-party relationships through DNS resolution
2. **SaaS Tenant Discovery** - Probes top 100 SaaS platforms for tenant-specific subdomains to discover vendor relationships

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Subfinder integration | External binary dependency | Leverages mature, well-maintained tool; easier updates |
| Tenant detection | Response content analysis | More reliable than status codes alone |
| Feature toggle | Configuration-driven with CLI override | Flexible for different use cases |

## Architecture

### Module Structure

```
src/
├── discovery/
│   ├── mod.rs           # Module exports and shared types
│   ├── subfinder.rs     # Subdomain discovery via external subfinder binary
│   └── saas_tenant.rs   # SaaS tenant discovery via HTTP probing
```

### Configuration

New `[discovery]` section in `nthpartyfinder.toml`:

```toml
[discovery]
# Subdomain discovery settings
subdomain_enabled = false
subfinder_path = "subfinder"
subfinder_timeout_secs = 300

# SaaS tenant discovery settings
saas_tenant_enabled = false
saas_platforms_file = "saas_platforms.json"
tenant_probe_timeout_secs = 10
tenant_probe_concurrency = 20
```

### CLI Flags

```
--enable-subdomain-discovery    Enable subdomain enumeration via subfinder
--disable-subdomain-discovery   Disable subdomain enumeration
--enable-saas-tenant-discovery  Enable SaaS tenant probing
--disable-saas-tenant-discovery Disable SaaS tenant probing
--subfinder-path <PATH>         Path to subfinder binary
--parallel-discovery            Run all discovery methods in parallel
```

## Subdomain Discovery Module

### Implementation

```rust
// src/discovery/subfinder.rs

pub struct SubfinderDiscovery {
    binary_path: PathBuf,
    timeout: Duration,
}

impl SubfinderDiscovery {
    pub fn new(binary_path: PathBuf, timeout: Duration) -> Self { ... }

    pub async fn discover(&self, domain: &str) -> Result<Vec<SubdomainResult>> {
        // Execute: subfinder -d <domain> -silent -json
        // Parse JSON output
        // Return structured results
    }

    pub fn is_available(&self) -> bool {
        // Check if binary exists and is executable
    }
}

pub struct SubdomainResult {
    pub subdomain: String,
    pub source: String,  // which subfinder source found it
}
```

### Processing Pipeline

1. Run subfinder against target domain
2. Parse JSON output to extract subdomains
3. Resolve each subdomain (CNAME, A records)
4. Filter out subdomains pointing to target's own infrastructure
5. Identify third-party hosting (CDNs, cloud providers, SaaS)
6. Create `VendorRelationship` entries with `RecordType::SubfinderDiscovery`

### Error Handling

- Binary not found: Warn and skip (non-fatal)
- Timeout: Log and return partial results
- Parse errors: Log individual failures, continue with valid results

## SaaS Tenant Discovery Module

### Platform Database

`config/saas_platforms.json`:

```json
{
  "platforms": [
    {
      "name": "Okta",
      "vendor_domain": "okta.com",
      "tenant_patterns": ["{tenant}.okta.com"],
      "detection": {
        "success_indicators": ["Sign In", "Okta", "login"],
        "failure_indicators": ["not found", "doesn't exist"]
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
      "tenant_patterns": [
        "{tenant}.my.salesforce.com",
        "{tenant}.lightning.force.com"
      ],
      "detection": {
        "success_indicators": ["Salesforce", "Login"],
        "failure_indicators": ["invalid", "not found"]
      }
    }
    // ... 97 more platforms
  ]
}
```

### Tenant Name Generation

For target domain `klaviyo.com`, generate candidates:
- `klaviyo`
- `klaviyo-inc`
- `klaviyoinc`

### Implementation

```rust
// src/discovery/saas_tenant.rs

pub struct SaasTenantDiscovery {
    platforms: Vec<SaasPlatform>,
    http_client: reqwest::Client,
    timeout: Duration,
    concurrency: usize,
}

pub struct SaasPlatform {
    pub name: String,
    pub vendor_domain: String,
    pub tenant_patterns: Vec<String>,
    pub detection: DetectionConfig,
}

pub struct DetectionConfig {
    pub success_indicators: Vec<String>,
    pub failure_indicators: Vec<String>,
}

pub enum TenantStatus {
    Confirmed,    // 200 + success indicators in content
    Likely,       // 200 but no definitive indicators
    NotFound,     // 404 or failure indicators
    Unknown,      // Timeout or other error
}

impl SaasTenantDiscovery {
    pub async fn probe(&self, target_domain: &str) -> Vec<TenantProbeResult> {
        let tenant_names = self.generate_tenant_names(target_domain);

        // For each platform, for each tenant name
        // Construct probe URLs and make requests
        // Analyze responses
        // Return confirmed/likely tenants
    }

    fn generate_tenant_names(&self, domain: &str) -> Vec<String> {
        // Extract base name, generate variants
    }

    async fn probe_url(&self, url: &str, detection: &DetectionConfig) -> TenantStatus {
        // HTTP HEAD/GET with short timeout
        // Analyze status + content
    }
}
```

### Response Analysis

1. Make HTTP request (HEAD first, GET if needed for content)
2. Check status code (200, 404, 302, etc.)
3. If 200, analyze response body for indicators
4. Return `TenantStatus` based on analysis

## Integration

### Pipeline Flow

```
Target Domain (e.g., klaviyo.com)
         │
         ├─► Existing Discovery Methods
         │     ├─ DNS Records (MX, TXT, CNAME)
         │     ├─ Subprocessor Page Analysis
         │     └─ Header/Certificate Analysis
         │
         ├─► [NEW] Subdomain Discovery (if enabled)
         │     └─ subfinder → DNS resolution → filter → VendorRelationships
         │
         └─► [NEW] SaaS Tenant Discovery (if enabled)
               └─ probe platforms → analyze responses → VendorRelationships
```

### Execution Order

1. Traditional discovery (fast, low overhead)
2. Subdomain discovery (external tool dependency)
3. SaaS tenant discovery (many HTTP requests)

With `--parallel-discovery`, all three run concurrently.

### New RecordType Variants

```rust
pub enum RecordType {
    // ... existing variants ...
    SubfinderDiscovery,  // Subdomain found via subfinder
    SaasTenantProbe,     // Tenant confirmed via HTTP probe
}
```

### Report Integration

HTML reports display discovery source in "Source" column:
- Subdomain discovery: magnifying glass icon + "Subdomain"
- SaaS tenant: cloud icon + "SaaS Tenant"

## Testing Strategy

### Unit Tests

**subfinder.rs:**
- Mock binary output parsing
- Test error handling (binary not found, timeout)
- Test subdomain filtering logic

**saas_tenant.rs:**
- Mock HTTP responses
- Test detection logic with various status/content combinations
- Test tenant name generation

**config.rs:**
- Test new discovery config parsing
- Test validation rules

### Integration Tests

- End-to-end with mock subfinder binary
- HTTP response mocking for tenant probes
- Verify `VendorRelationship` output format
- Test CLI flag interactions

## Implementation Plan

### Files to Create

| File | Purpose |
|------|---------|
| `src/discovery/mod.rs` | Module exports, shared types |
| `src/discovery/subfinder.rs` | Subfinder integration |
| `src/discovery/saas_tenant.rs` | SaaS tenant probing |
| `config/saas_platforms.json` | Platform database (100 platforms) |

### Files to Modify

| File | Changes |
|------|---------|
| `src/config.rs` | Add `DiscoveryConfig` struct |
| `src/cli.rs` | Add discovery-related flags |
| `src/vendor.rs` | Add new `RecordType` variants |
| `src/main.rs` | Wire up discovery modules |
| `templates/report.html` | Add icons/labels for new sources |
| `config/nthpartyfinder.toml` | Add `[discovery]` section |

### Implementation Order

1. Config changes (schema + parsing)
2. CLI changes (new flags)
3. RecordType variants
4. Subdomain module
5. SaaS tenant module
6. Platform database
7. Pipeline integration
8. Report updates
9. Documentation

## Security Considerations

- Subfinder binary path validation (prevent command injection)
- Rate limiting for SaaS tenant probes (respect target servers)
- Timeout enforcement to prevent hanging
- No credential storage or handling

## Future Enhancements

- Custom platform definitions via config
- Subdomain wordlist support
- Historical tenant detection (wayback machine)
- Platform-specific API integrations (where available)
