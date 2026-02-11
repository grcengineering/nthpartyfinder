# Scan Results Fixes Design

**Date:** 2026-01-19
**Status:** Approved

## Overview

This document covers fixes for 4 issues identified in scan results:

1. SaaS tenant discovery false positives (Auth0, Duo)
2. Subprocessor page duplicate results (Google multiple times)
3. Domain verification evidence display bug
4. Domain→org name mapping improvements + El Camino bug fix

---

## Issue 1: SaaS Tenant Discovery False Positives

### Root Cause
Auth0 and Duo redirect ALL tenant URLs (valid AND invalid) to their main websites with HTTP 200. The code follows redirects and finds success indicators on the main company site, causing false positives.

### Files Affected
- `src/discovery/saas_tenant.rs` - `analyze_response` function (lines 240-265)

### Solution
Detect when final URL domain differs from probed URL domain:

```rust
// In probe_tenant or analyze_response
if final_url_domain != probed_url_domain && is_main_company_domain(final_url_domain) {
    return TenantStatus::NotFound; // Redirected to main site = tenant doesn't exist
}
```

### Testing
- Test Auth0: `nonexistent12345.auth0.com` should return NotFound (redirects to auth0.com)
- Test Duo: `nonexistent12345.duosecurity.com` should return NotFound (redirects to duo.com)
- Test Slack: Valid tenant detection should still work

---

## Issue 2: Subprocessor Page Duplicate Results

### Root Cause
Organization names extracted from navigation menu elements (e.g., "Google Cloud's Vertex AI" link) in addition to actual subprocessor content.

### Files Affected
- `src/subprocessor.rs` - extraction functions

### Solution
Filter navigation elements before extraction:
- Exclude `<nav>`, `<header>`, `<footer>`, `<aside>` elements
- Exclude elements with nav/menu/header/footer classes
- Prefer content from `<main>`, `<article>`, `.content` selectors

### Testing
- Test claude.ai subprocessor page: Google should appear only once
- Verify legitimate subprocessors still extracted

---

## Issue 3: Domain Verification Evidence Display Bug

### Root Cause
For Domain Verification records, `nth_party_record` is set to vendor domain (`gc-ai.com`) instead of raw TXT record.

### Files Affected
- `src/main.rs` - lines 1160-1164

### Solution
Change record_value assignment to use raw_record for DNS TXT types:

```rust
let record_value = match source_type {
    RecordType::DnsSubdomain => format!("{} (base of {})", base_domain, customer_domain),
    RecordType::DnsTxtVerification | RecordType::DnsTxtSpf |
    RecordType::DnsTxtDmarc | RecordType::DnsTxtDkim => raw_record.clone(),
    _ => vendor_domain.clone(),
};
```

### Testing
- Verify gc-ai.com shows `gc-ai-domain-verification-pc2v6s=...` in Record column
- Verify SPF records show full SPF string
- Verify subdomains still show `domain.com (base of subdomain.domain.com)` format

---

## Issue 4: Domain→Org Mapping & El Camino Bug

### Root Cause (El Camino)
In `subprocessor.rs:2719-2732`, `.zip()` incorrectly pairs company names with domains positionally without verifying correspondence. This caused "El Camino Technologies" to be mapped to "elcamino.tech" instead of "ectusa.net".

### Files Affected
- `src/subprocessor.rs` - `analyze_table_patterns` function
- `cache/klaviyo.com.json` - incorrect cached mapping

### Solution

**Immediate fix:** Correct the mapping in `cache/klaviyo.com.json`:
```json
"el camino technologies": "ectusa.net"
```

**Prevent future:** Change mapping generation to verify domain-org correspondence:
```rust
for extraction in successful_extractions.iter() {
    if let Some(company_name) = extract_company_from_raw_record(&extraction.raw_record) {
        if cell_text.to_lowercase().contains(&company_name.to_lowercase()) {
            custom_mappings.insert(company_name.to_lowercase(), extraction.domain.clone());
        }
    }
}
```

### Additional Improvements
- Add known vendors: ceros.com→Ceros, seismic.com→Seismic, swoogo.com→Swoogo, outrch.com→Outreach
- Consider enabling web_org extraction by default

### Testing
- Verify El Camino Technologies maps to ectusa.net
- Verify new extractions don't create mismatched mappings
- Verify known vendors resolve correctly

---

## Implementation Order

1. **Issue 3** (Evidence display) - Simplest, isolated change
2. **Issue 4** (El Camino cache fix) - Quick data fix
3. **Issue 1** (SaaS redirect detection) - Moderate complexity
4. **Issue 2** (Navigation filtering) - Most complex, needs careful testing
5. **Issue 4** (Mapping generation fix) - Prevent future bugs
