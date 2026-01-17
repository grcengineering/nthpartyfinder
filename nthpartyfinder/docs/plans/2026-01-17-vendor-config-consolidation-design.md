# Vendor Configuration Consolidation Design

**Date:** 2026-01-17
**Status:** Approved

## Overview

Consolidate all domain-specific vendor configurations into a single, vendor-centric directory structure. Each vendor gets its own JSON file containing all related domains, verification patterns, SaaS tenant configurations, and risk metadata.

## Current State

Vendor data is scattered across multiple files:

| File | Contents |
|------|----------|
| `config/known_vendors.json` | 280+ domain → organization mappings |
| `config/saas_platforms.json` | 40+ SaaS tenant detection patterns |
| `config/nthpartyfinder.toml` | `[patterns.verification]` - TXT patterns → domains |
| `config/nthpartyfinder.toml` | `[patterns.provider_mappings]` - provider names → domains |
| `cache/{domain}.json` | Per-domain extraction patterns (unchanged) |

## Target State

```
config/
  vendors/
    _schema.json           # JSON Schema for validation
    google.json
    salesforce.json
    slack.json             # Cross-references salesforce as parent
    klaviyo.json
    stripe.json
    okta.json
    ... (~100-150 vendor files)
  nthpartyfinder.toml      # App config only (DNS, timeouts, analysis)
```

## Schema Design

### Vendor File Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "vendor-schema.json",
  "title": "nthpartyfinder Vendor Configuration",
  "type": "object",
  "required": ["id", "organization", "primary_domain", "domains"],

  "properties": {
    "id": {
      "type": "string",
      "description": "Unique vendor identifier (filename without .json)",
      "pattern": "^[a-z0-9-]+$"
    },
    "organization": {
      "type": "string",
      "description": "Official organization name"
    },
    "primary_domain": {
      "type": "string",
      "description": "Main domain for this vendor"
    },
    "parent_vendor": {
      "type": "string",
      "description": "ID of parent vendor if this is an acquisition"
    },
    "acquired_year": {
      "type": "integer",
      "description": "Year acquired (if subsidiary)"
    },

    "domains": {
      "type": "object",
      "description": "Map of domain -> metadata",
      "additionalProperties": {
        "type": "object",
        "properties": {
          "type": {
            "enum": ["primary", "service", "api", "cdn", "acquired", "alias", "email"]
          },
          "category": {
            "enum": [
              "platform", "infrastructure", "tracking", "advertising",
              "security", "payment", "communication", "storage",
              "development", "monitoring", "media", "support", "analytics"
            ]
          },
          "description": { "type": "string" },
          "acquired_year": { "type": "integer" },
          "vendor_ref": {
            "type": "string",
            "description": "Reference to subsidiary vendor file"
          }
        }
      }
    },

    "verification_patterns": {
      "type": "array",
      "items": { "type": "string" },
      "description": "TXT record patterns that indicate this vendor"
    },

    "provider_aliases": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Names used in dynamic TXT pattern extraction"
    },

    "saas_tenants": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "patterns"],
        "properties": {
          "name": { "type": "string" },
          "patterns": {
            "type": "array",
            "items": { "type": "string" }
          },
          "detection": {
            "type": "object",
            "properties": {
              "success_indicators": { "type": "array", "items": { "type": "string" } },
              "failure_indicators": { "type": "array", "items": { "type": "string" } },
              "notes": { "type": "string" }
            }
          }
        }
      }
    }
  }
}
```

### Domain Types

| Type | Description |
|------|-------------|
| `primary` | Main company domain |
| `service` | Product/service subdomain or domain |
| `api` | API endpoints |
| `cdn` | Content delivery |
| `acquired` | Acquired company (separate brand) |
| `alias` | Alternate/legacy domain for same service |
| `email` | Email sending domain |

### Risk Categories

| Category | Description | Risk Context |
|----------|-------------|--------------|
| `platform` | Core product | Primary vendor relationship |
| `infrastructure` | Backend/hosting | Data processing |
| `tracking` | Analytics/pixels | Privacy, data collection |
| `advertising` | Ads/marketing | Privacy, third-party data sharing |
| `security` | Auth/SSO/security tools | Critical access control |
| `payment` | Financial processing | PCI, financial data |
| `communication` | Email/chat/video | Data in transit |
| `storage` | File/data storage | Data at rest |
| `development` | Dev tools/CI/CD | Code access, supply chain |
| `monitoring` | APM/logging/errors | May contain PII in logs |
| `media` | Video/images/content | Content hosting |
| `support` | Help desk/ticketing | Customer PII |
| `analytics` | BI/reporting tools | Aggregated data access |

### Acquisition Cross-Reference Pattern

Parent vendors list acquisitions with `vendor_ref` pointing to subsidiary file:

```json
// salesforce.json
{
  "domains": {
    "slack.com": {
      "type": "acquired",
      "category": "communication",
      "acquired_year": 2021,
      "vendor_ref": "slack"
    }
  }
}
```

Subsidiary files reference parent with `parent_vendor`:

```json
// slack.json
{
  "id": "slack",
  "organization": "Slack Technologies",
  "parent_vendor": "salesforce",
  "acquired_year": 2021
}
```

## Example Vendor Files

### google.json

```json
{
  "$schema": "./_schema.json",
  "id": "google",
  "organization": "Google LLC",
  "primary_domain": "google.com",

  "domains": {
    "google.com": { "type": "primary", "category": "platform" },
    "googleapis.com": { "type": "api", "category": "infrastructure" },
    "googletagmanager.com": { "type": "service", "category": "tracking" },
    "googlesyndication.com": { "type": "service", "category": "advertising" },
    "googleads.g.doubleclick.net": { "type": "service", "category": "advertising" },
    "gstatic.com": { "type": "cdn", "category": "infrastructure" },
    "youtube.com": {
      "type": "acquired",
      "category": "media",
      "acquired_year": 2006,
      "vendor_ref": "youtube"
    },
    "looker.com": {
      "type": "acquired",
      "category": "analytics",
      "acquired_year": 2020,
      "vendor_ref": "looker"
    }
  },

  "verification_patterns": [
    "google-site-verification="
  ],

  "provider_aliases": ["google", "gcp", "googlecloud"],

  "saas_tenants": [
    {
      "name": "Looker",
      "patterns": ["{tenant}.looker.com", "{tenant}.cloud.looker.com"],
      "detection": {
        "success_indicators": ["Looker", "looker"],
        "failure_indicators": ["instance not found"]
      }
    }
  ]
}
```

### klaviyo.json

```json
{
  "$schema": "./_schema.json",
  "id": "klaviyo",
  "organization": "Klaviyo",
  "primary_domain": "klaviyo.com",

  "domains": {
    "klaviyo.com": { "type": "primary", "category": "platform" },
    "myklpages.com": { "type": "service", "category": "platform", "description": "Landing pages" }
  },

  "verification_patterns": [
    "klaviyo-site-verification="
  ],

  "provider_aliases": ["klaviyo"],

  "saas_tenants": []
}
```

### salesforce.json

```json
{
  "$schema": "./_schema.json",
  "id": "salesforce",
  "organization": "Salesforce, Inc.",
  "primary_domain": "salesforce.com",

  "domains": {
    "salesforce.com": { "type": "primary", "category": "platform" },
    "force.com": { "type": "service", "category": "platform" },
    "salesforceliveagent.com": { "type": "service", "category": "support" },
    "sfmc-marketing.com": { "type": "service", "category": "advertising" },
    "pardot.com": { "type": "service", "category": "advertising" },
    "slack.com": {
      "type": "acquired",
      "category": "communication",
      "acquired_year": 2021,
      "vendor_ref": "slack"
    },
    "heroku.com": {
      "type": "acquired",
      "category": "infrastructure",
      "acquired_year": 2010,
      "vendor_ref": "heroku"
    },
    "tableau.com": {
      "type": "acquired",
      "category": "analytics",
      "acquired_year": 2019,
      "vendor_ref": "tableau"
    },
    "mulesoft.com": {
      "type": "acquired",
      "category": "infrastructure",
      "acquired_year": 2018,
      "vendor_ref": "mulesoft"
    }
  },

  "verification_patterns": [],

  "provider_aliases": ["salesforce", "sfdc"],

  "saas_tenants": [
    {
      "name": "Salesforce CRM",
      "patterns": ["{tenant}.my.salesforce.com"],
      "detection": {
        "success_indicators": ["saml_request_id", "Salesforce", "salesforce.com"],
        "failure_indicators": [],
        "notes": "Invalid tenants fail DNS resolution"
      }
    }
  ]
}
```

### slack.json (subsidiary)

```json
{
  "$schema": "./_schema.json",
  "id": "slack",
  "organization": "Slack Technologies",
  "primary_domain": "slack.com",
  "parent_vendor": "salesforce",
  "acquired_year": 2021,

  "domains": {
    "slack.com": { "type": "primary", "category": "communication" },
    "slack-edge.com": { "type": "cdn", "category": "infrastructure" },
    "slack-imgs.com": { "type": "cdn", "category": "media" },
    "slack-files.com": { "type": "service", "category": "storage" }
  },

  "verification_patterns": [
    "slack-domain-verification="
  ],

  "provider_aliases": ["slack"],

  "saas_tenants": [
    {
      "name": "Slack Workspace",
      "patterns": ["{tenant}.slack.com"],
      "detection": {
        "success_indicators": ["enterprise.slack.com", "Slack", "workspace"],
        "failure_indicators": [],
        "notes": "Invalid tenants return HTTP 404 - detected by status code"
      }
    }
  ]
}
```

## Implementation Plan

### Phase 1: Create New Structure

1. Create `config/vendors/` directory
2. Create `config/vendors/_schema.json` with the JSON Schema
3. Write migration script to:
   - Parse `known_vendors.json` and group domains by organization
   - Parse `saas_platforms.json` and merge tenant configs
   - Parse `nthpartyfinder.toml` verification patterns and provider mappings
   - Generate individual vendor JSON files
4. Manual review and enrichment of generated files (add types, categories, cross-refs)

### Phase 2: Rust Code Changes

1. Create new `src/vendor_registry.rs` module:
   - `VendorRegistry` struct that loads all vendor files
   - Domain → Vendor lookup (reverse index)
   - Provider alias → Vendor lookup
   - Verification pattern → Vendor lookup
   - SaaS tenant pattern access

2. Update existing modules to use `VendorRegistry`:
   - `src/known_vendors.rs` → delegate to VendorRegistry or deprecate
   - `src/discovery/saas_tenant.rs` → load tenants from VendorRegistry
   - `src/dns.rs` → use VendorRegistry for verification pattern matching
   - `src/config.rs` → remove `[patterns.verification]` and `[patterns.provider_mappings]`

3. Update `src/main.rs` to initialize VendorRegistry at startup

### Phase 3: Cleanup

1. Remove deprecated config sections from `nthpartyfinder.toml`:
   - `[patterns.verification]`
   - `[patterns.provider_mappings]`

2. Archive old config files:
   - `config/known_vendors.json` → `config/archive/known_vendors.json.bak`
   - `config/saas_platforms.json` → `config/archive/saas_platforms.json.bak`

3. Update documentation and README

### Phase 4: Enrichment (Ongoing)

1. Add missing domain types and categories
2. Research and add acquisition dates
3. Add cross-references for all subsidiaries
4. Expand vendor coverage

## File Changes Summary

### New Files
- `config/vendors/_schema.json`
- `config/vendors/*.json` (~100-150 vendor files)
- `src/vendor_registry.rs`

### Modified Files
- `src/main.rs` - Initialize VendorRegistry
- `src/known_vendors.rs` - Deprecate or wrap VendorRegistry
- `src/discovery/saas_tenant.rs` - Load from VendorRegistry
- `src/dns.rs` - Use VendorRegistry for patterns
- `src/config.rs` - Remove vendor-specific sections
- `config/nthpartyfinder.toml` - Remove `[patterns.verification]` and `[patterns.provider_mappings]`

### Archived Files
- `config/known_vendors.json`
- `config/saas_platforms.json`

## Migration Strategy

The migration script should:

1. **Group domains by organization** from `known_vendors.json`
2. **Match SaaS platforms** to their parent organizations
3. **Map verification patterns** to vendors
4. **Generate skeleton vendor files** with:
   - All known domains (type: TBD, category: TBD)
   - Verification patterns
   - Provider aliases
   - SaaS tenant configs
5. **Flag items needing manual review**:
   - Domains without clear organization grouping
   - Potential acquisition relationships
   - Missing type/category metadata

## Backward Compatibility

During migration, support both old and new config formats:

1. VendorRegistry checks for `config/vendors/` directory first
2. Falls back to old files if vendor directory doesn't exist
3. Logs deprecation warning when using old format

This allows gradual migration and testing.

## Success Criteria

- [ ] All 280+ domains from `known_vendors.json` migrated
- [ ] All 40+ SaaS platforms from `saas_platforms.json` migrated
- [ ] All verification patterns from TOML migrated
- [ ] All provider mappings from TOML migrated
- [ ] Existing tests pass
- [ ] Lookups work: domain → vendor, provider → vendor, pattern → vendor
- [ ] No duplicate data across files
- [ ] Schema validation passes for all vendor files
