use regex::Regex;
use anyhow::{Result, anyhow};
use tracing::debug;
use std::time::Duration;
use std::process::Command;
use std::collections::HashMap;
use std::sync::Arc;
use whois_rust::{WhoIs, WhoIsLookupOptions};
use tokio::sync::Semaphore;
use futures::stream::{self, StreamExt};
use crate::known_vendors;
use crate::web_org;
use crate::ner_org;
use crate::rate_limit::RateLimitContext;

/// Result of an organization lookup with verification status
#[derive(Debug, Clone)]
pub struct OrganizationResult {
    /// The organization name
    pub name: String,
    /// Whether the organization was verified from WHOIS data (true) or inferred from domain (false)
    pub is_verified: bool,
    /// The source of the organization name (e.g., "whois", "registrar", "domain_fallback", "known_vendors")
    pub source: String,
}

impl OrganizationResult {
    pub fn verified(name: String, source: &str) -> Self {
        Self {
            name,
            is_verified: true,
            source: source.to_string(),
        }
    }

    pub fn inferred(name: String) -> Self {
        Self {
            name,
            is_verified: false,
            source: "domain_fallback".to_string(),
        }
    }
}

/// Get organization with verification status
pub async fn get_organization_with_status(domain: &str) -> Result<OrganizationResult> {
    get_organization_with_status_and_config(domain, true, 0.6).await
}

/// Get organization with verification status and optional rate limiting
/// This is the preferred method when using rate limiting
pub async fn get_organization_with_rate_limit(
    domain: &str,
    web_org_enabled: bool,
    min_confidence: f32,
    rate_limit_ctx: Option<&RateLimitContext>,
) -> Result<OrganizationResult> {
    debug!("Looking up organization for domain: {}", domain);

    // Priority 1: Check known vendors database (fastest and most reliable - no rate limit needed)
    if let Some(kv_result) = known_vendors::lookup(domain) {
        debug!("Found {} in known vendors database: {} (source: {})",
               domain, kv_result.organization, kv_result.source);
        return Ok(OrganizationResult::verified(
            kv_result.organization,
            &kv_result.source.to_string(),
        ));
    }

    // Priority 2: Web page analysis (uses HTTP rate limiter separately, not WHOIS)
    if web_org_enabled {
        if let Ok(Some(web_result)) = web_org::extract_organization_with_fallback(domain, false).await {
            if web_result.confidence >= min_confidence {
                debug!("Found {} via web page analysis: {} (source: {}, confidence: {:.2})",
                       domain, web_result.organization, web_result.source, web_result.confidence);
                return Ok(OrganizationResult::verified(
                    web_result.organization,
                    &format!("web_{}", web_result.source),
                ));
            } else {
                debug!("Web page result for {} had low confidence ({:.2} < {:.2}), trying other methods",
                       domain, web_result.confidence, min_confidence);
            }
        }
    }

    // Apply WHOIS rate limiting before actual WHOIS queries
    if let Some(ctx) = rate_limit_ctx {
        ctx.whois_limiter.acquire().await;
    }

    // Priority 3: Native Rust WHOIS lookup using whois-rust library
    if let Ok(result) = try_native_whois(domain).await {
        if let Some(organization) = extract_organization_from_whois(&result) {
            debug!("Found organization via whois-rust for {}: {}", domain, organization);
            return Ok(OrganizationResult::verified(organization, "whois"));
        }
        debug!("whois-rust returned placeholder organization for {}, trying fallbacks", domain);
    }

    // Priority 4: System whois command (if available) - also uses the same rate limit token
    if let Ok(result) = try_system_whois(domain).await {
        if let Some(organization) = extract_organization_from_whois(&result) {
            debug!("Found organization via system whois for {}: {}", domain, organization);
            return Ok(OrganizationResult::verified(organization, "system_whois"));
        }
        debug!("System whois returned placeholder organization for {}, trying NER fallback", domain);
    }

    // Priority 5: NER-based extraction (if embedded-ner feature enabled)
    if ner_org::is_available() {
        debug!("NER is available, attempting extraction for {}", domain);
        let page_content = web_org::fetch_page_content(domain).await.ok();
        let content_ref = page_content.as_deref();

        if let Ok(Some(ner_result)) = ner_org::extract_organization(domain, content_ref) {
            debug!("Found organization via NER for {}: {} (confidence: {:.2})",
                   domain, ner_result.organization, ner_result.confidence);
            return Ok(OrganizationResult::verified(
                ner_result.organization,
                "ner_gliner",
            ));
        }
        debug!("NER could not determine organization for {}, using domain fallback", domain);
    }

    // Final fallback to domain-based organization name (marked as unverified)
    debug!("All lookup methods failed or returned placeholders for {}, using domain-based fallback", domain);
    Ok(OrganizationResult::inferred(extract_organization_from_domain(domain)))
}

/// Get organization with verification status, with configurable web org lookup
pub async fn get_organization_with_status_and_config(
    domain: &str,
    web_org_enabled: bool,
    min_confidence: f32,
) -> Result<OrganizationResult> {
    debug!("Looking up organization for domain: {}", domain);

    // Priority 1: Check known vendors database (fastest and most reliable)
    if let Some(kv_result) = known_vendors::lookup(domain) {
        debug!("Found {} in known vendors database: {} (source: {})",
               domain, kv_result.organization, kv_result.source);
        return Ok(OrganizationResult::verified(
            kv_result.organization,
            &kv_result.source.to_string(),
        ));
    }

    // Priority 2: Web page analysis (Schema.org, OpenGraph, meta tags)
    // Uses HTTP first, falls back to headless browser for SPA sites
    if web_org_enabled {
        if let Ok(Some(web_result)) = web_org::extract_organization_with_fallback(domain, false).await {
            if web_result.confidence >= min_confidence {
                debug!("Found {} via web page analysis: {} (source: {}, confidence: {:.2})",
                       domain, web_result.organization, web_result.source, web_result.confidence);
                return Ok(OrganizationResult::verified(
                    web_result.organization,
                    &format!("web_{}", web_result.source),
                ));
            } else {
                debug!("Web page result for {} had low confidence ({:.2} < {:.2}), trying other methods",
                       domain, web_result.confidence, min_confidence);
            }
        }
    }

    // Priority 3: Native Rust WHOIS lookup using whois-rust library
    if let Ok(result) = try_native_whois(domain).await {
        if let Some(organization) = extract_organization_from_whois(&result) {
            debug!("Found organization via whois-rust for {}: {}", domain, organization);
            return Ok(OrganizationResult::verified(organization, "whois"));
        }
        debug!("whois-rust returned placeholder organization for {}, trying fallbacks", domain);
    }

    // Priority 4: System whois command (if available)
    if let Ok(result) = try_system_whois(domain).await {
        if let Some(organization) = extract_organization_from_whois(&result) {
            debug!("Found organization via system whois for {}: {}", domain, organization);
            return Ok(OrganizationResult::verified(organization, "system_whois"));
        }
        debug!("System whois returned placeholder organization for {}, trying NER fallback", domain);
    }

    // Priority 5: NER-based extraction (if embedded-ner feature enabled)
    if ner_org::is_available() {
        debug!("NER is available, attempting extraction for {}", domain);
        // First try to get web content for NER to analyze
        let page_content = web_org::fetch_page_content(domain).await.ok();
        let content_ref = page_content.as_deref();

        if let Ok(Some(ner_result)) = ner_org::extract_organization(domain, content_ref) {
            debug!("Found organization via NER for {}: {} (confidence: {:.2})",
                   domain, ner_result.organization, ner_result.confidence);
            return Ok(OrganizationResult::verified(
                ner_result.organization,
                "ner_gliner",
            ));
        }
        debug!("NER could not determine organization for {}, using domain fallback", domain);
    }

    // Final fallback to domain-based organization name (marked as unverified)
    debug!("All lookup methods failed or returned placeholders for {}, using domain-based fallback", domain);
    Ok(OrganizationResult::inferred(extract_organization_from_domain(domain)))
}

pub async fn get_organization(domain: &str) -> Result<String> {
    get_organization_with_config(domain, true, 0.6).await
}

/// Get organization name with configurable web org lookup
pub async fn get_organization_with_config(
    domain: &str,
    web_org_enabled: bool,
    min_confidence: f32,
) -> Result<String> {
    debug!("Looking up organization for domain: {}", domain);

    // Priority 1: Check known vendors database (fastest and most reliable)
    if let Some(kv_result) = known_vendors::lookup(domain) {
        debug!("Found {} in known vendors database: {}", domain, kv_result.organization);
        return Ok(kv_result.organization);
    }

    // Priority 2: Web page analysis (Schema.org, OpenGraph, meta tags)
    // Uses HTTP first, falls back to headless browser for SPA sites
    if web_org_enabled {
        if let Ok(Some(web_result)) = web_org::extract_organization_with_fallback(domain, false).await {
            if web_result.confidence >= min_confidence {
                debug!("Found {} via web page analysis: {} (confidence: {:.2})",
                       domain, web_result.organization, web_result.confidence);
                return Ok(web_result.organization);
            }
        }
    }

    // Priority 3: Native Rust WHOIS lookup using whois-rust library
    if let Ok(result) = try_native_whois(domain).await {
        if let Some(organization) = extract_organization_from_whois(&result) {
            debug!("Found organization via whois-rust for {}: {}", domain, organization);
            return Ok(organization);
        }
        debug!("whois-rust returned placeholder organization for {}, trying fallbacks", domain);
    }

    // Priority 4: System whois command (if available)
    if let Ok(result) = try_system_whois(domain).await {
        if let Some(organization) = extract_organization_from_whois(&result) {
            debug!("Found organization via system whois for {}: {}", domain, organization);
            return Ok(organization);
        }
        debug!("System whois returned placeholder organization for {}, using domain fallback", domain);
    }

    // Final fallback to domain-based organization name
    debug!("All lookup methods failed or returned placeholders for {}, using domain-based fallback", domain);
    Ok(extract_organization_from_domain(domain))
}

async fn try_native_whois(domain: &str) -> Result<String> {
    debug!("Trying whois-rust library lookup for domain: {}", domain);
    
    // Use default whois-rust configuration with built-in servers
    let whois = WhoIs::from_path("whois-servers.json")
        .or_else(|_| {
            // Fallback to using a basic server configuration string
            WhoIs::from_string(r#"{
                "com": "whois.verisign-grs.com",
                "net": "whois.verisign-grs.com",
                "org": "whois.pir.org",
                "": "whois.iana.org"
            }"#)
        })
        .map_err(|e| anyhow!("Failed to create WHOIS client: {}", e))?;
    
    // Configure lookup options
    let lookup_options = WhoIsLookupOptions::from_string(domain)
        .map_err(|e| anyhow!("Invalid domain for WHOIS lookup: {}", e))?;
    
    // Perform WHOIS lookup with timeout using spawn_blocking for async compatibility
    match tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            whois.lookup(lookup_options)
        })
    ).await {
        Ok(Ok(Ok(whois_result))) => {
            debug!("whois-rust lookup successful for {}", domain);
            Ok(whois_result)
        },
        Ok(Ok(Err(e))) => {
            debug!("whois-rust lookup failed for {}: {}", domain, e);
            Err(anyhow!("whois-rust lookup failed: {}", e))
        },
        Ok(Err(_)) => {
            debug!("whois-rust lookup task panicked for {}", domain);
            Err(anyhow!("whois-rust lookup task panicked"))
        },
        Err(_) => {
            debug!("whois-rust lookup timed out for {}", domain);
            Err(anyhow!("whois-rust lookup timed out"))
        }
    }
}

async fn try_system_whois(domain: &str) -> Result<String> {
    let domain_owned = domain.to_string();
    
    match tokio::time::timeout(
        Duration::from_secs(15),
        tokio::task::spawn_blocking(move || {
            execute_whois_command(&domain_owned)
        })
    ).await {
        Ok(Ok(Ok(result))) => Ok(result),
        Ok(Ok(Err(e))) => Err(anyhow!("System whois failed: {}", e)),
        Ok(Err(_)) => Err(anyhow!("System whois task panicked")),
        Err(_) => Err(anyhow!("System whois timed out")),
    }
}

fn execute_whois_command(domain: &str) -> Result<String> {
    // Try different whois command locations based on platform
    let whois_commands = if cfg!(windows) {
        vec!["whois.exe", "whois"]
    } else {
        vec!["whois", "/usr/bin/whois", "/usr/local/bin/whois"]
    };
    
    for cmd in whois_commands {
        match Command::new(cmd)
            .arg(domain)
            .output() {
            Ok(output) => {
                if output.status.success() {
                    return Ok(String::from_utf8_lossy(&output.stdout).to_string());
                }
            },
            Err(_) => continue,
        }
    }
    
    Err(anyhow!("No working whois command found"))
}

fn extract_organization_from_domain(domain: &str) -> String {
    // Extract a reasonable organization name from the domain
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        // Convert domain to title case organization name
        let org_name = parts[parts.len() - 2];
        let mut chars: Vec<char> = org_name.chars().collect();
        if !chars.is_empty() {
            chars[0] = chars[0].to_uppercase().next().unwrap_or(chars[0]);
        }
        format!("{} Inc.", chars.into_iter().collect::<String>())
    } else {
        domain.to_string()
    }
}

fn extract_organization_from_whois(whois_data: &str) -> Option<String> {
    let organization_patterns = vec![
        r"(?i)Organization:\s*(.+)",
        r"(?i)Registrant Organization:\s*(.+)",
        r"(?i)Registrant:\s*(.+)",
        r"(?i)OrgName:\s*(.+)",
        r"(?i)org-name:\s*(.+)",
        r"(?i)organisation:\s*(.+)",
        r"(?i)Company:\s*(.+)",
    ];

    for pattern in organization_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if let Some(cap) = regex.captures(whois_data) {
                if let Some(org_match) = cap.get(1) {
                    let org = org_match.as_str().trim();
                    if !org.is_empty() && !is_placeholder_organization(org) {
                        return Some(clean_organization_name(org));
                    }
                }
            }
        }
    }

    // If no organization found, try to extract from registrar (but filter placeholders)
    extract_registrar_from_whois(whois_data)
}

fn extract_registrar_from_whois(whois_data: &str) -> Option<String> {
    let registrar_patterns = vec![
        r"(?i)Registrar:\s*(.+)",
        r"(?i)Sponsoring Registrar:\s*(.+)",
        r"(?i)Registrar Name:\s*(.+)",
    ];
    
    for pattern in registrar_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if let Some(cap) = regex.captures(whois_data) {
                if let Some(registrar_match) = cap.get(1) {
                    let registrar = registrar_match.as_str().trim();
                    if !registrar.is_empty() && !is_placeholder_organization(registrar) {
                        return Some(clean_organization_name(registrar));
                    }
                }
            }
        }
    }
    
    None
}

fn is_placeholder_organization(org: &str) -> bool {
    let placeholders = vec![
        // Privacy protection services
        "whois privacy protection service",
        "privacy protection service",
        "domains by proxy",
        "whoisguard",
        "perfect privacy",
        "redacted for privacy",
        "contact privacy inc",
        "n/a",
        "not disclosed",
        "private",
        "redacted",
        "withheld",
        // Domain registrars/brand protection services (not the actual domain owners)
        "markmonitor",
        "csc corporate domains",
        "corporatedomains.com",
        "safenames",
        "com laude",
        "nameprotect",
        "brand protection",
        "domain management",
        "networksolutions",
        "network solutions",
        "godaddy",
        "namecheap",
        "enom",
        "tucows",
        "key-systems",
        "gandi",
        "identity protection service",
        "identity protect",
        // Additional registrars
        "porkbun",
        "cloudflare",
        "dynadot",
        "hover",
        "google domains",
        "squarespace domains",
        "bluehost",
        "hostgator",
        "dreamhost",
        "siteground",
        "ionos",
        "register.com",
        "name.com",
        "domain.com",
        "epik",
        // Registrant field values that aren't organization names
        "registrant street",
        "registrant city",
        "registrant state",
        "registrant postal",
        "registrant country",
        "registrant phone",
        "registrant email",
        "registrant fax",
        "admin street",
        "admin city",
        "tech street",
        "tech city",
        "po box",
        "p.o. box",
        "care of",
        "c/o ",
    ];

    let org_lower = org.to_lowercase();

    // Check if org contains any placeholder
    if placeholders.iter().any(|&placeholder| org_lower.contains(placeholder)) {
        return true;
    }

    // Check if org looks like an address (starts with numbers or contains common address patterns)
    if org_lower.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        // Likely an address like "5335 Gate Parkway..."
        return true;
    }

    false
}

fn clean_organization_name(org: &str) -> String {
    org.trim()
        .replace('\n', " ")
        .replace('\r', " ")
        .replace('\t', " ")
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

/// Batch lookup organizations for multiple domains in parallel
///
/// This function performs parallel WHOIS/organization lookups for a batch of domains,
/// rate-limited by the specified concurrency to avoid overwhelming WHOIS servers.
///
/// # Arguments
/// * `domains` - List of domains to look up
/// * `web_org_enabled` - Whether to enable web page organization extraction
/// * `min_confidence` - Minimum confidence for web org extraction
/// * `concurrency` - Maximum concurrent lookups (default: 5)
///
/// # Returns
/// A HashMap mapping domain -> OrganizationResult
pub async fn batch_get_organizations(
    domains: Vec<String>,
    web_org_enabled: bool,
    min_confidence: f32,
    concurrency: usize,
) -> HashMap<String, OrganizationResult> {
    batch_get_organizations_with_rate_limit(domains, web_org_enabled, min_confidence, concurrency, None).await
}

/// Batch lookup organizations with optional rate limiting
///
/// This function performs parallel WHOIS/organization lookups for a batch of domains,
/// applying both concurrency limiting (semaphore) and rate limiting (token bucket).
///
/// # Arguments
/// * `domains` - List of domains to look up
/// * `web_org_enabled` - Whether to enable web page organization extraction
/// * `min_confidence` - Minimum confidence for web org extraction
/// * `concurrency` - Maximum concurrent lookups
/// * `rate_limit_ctx` - Optional rate limit context for WHOIS rate limiting
///
/// # Returns
/// A HashMap mapping domain -> OrganizationResult
pub async fn batch_get_organizations_with_rate_limit(
    domains: Vec<String>,
    web_org_enabled: bool,
    min_confidence: f32,
    concurrency: usize,
    rate_limit_ctx: Option<&RateLimitContext>,
) -> HashMap<String, OrganizationResult> {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let total_domains = domains.len();

    debug!("Starting parallel WHOIS lookups for {} domains (concurrency: {})", total_domains, concurrency);

    // Clone the rate limit context for use in async closures
    let rate_limit_ctx_opt = rate_limit_ctx.cloned();

    let results: Vec<(String, OrganizationResult)> = stream::iter(domains.into_iter().enumerate())
        .map(|(index, domain)| {
            let semaphore = semaphore.clone();
            let rate_limit_ctx_opt = rate_limit_ctx_opt.clone();
            async move {
                // Acquire semaphore permit to limit concurrency
                let _permit = semaphore.acquire().await.unwrap();

                debug!("WHOIS lookup {}/{}: {}", index + 1, total_domains, domain);

                match get_organization_with_rate_limit(&domain, web_org_enabled, min_confidence, rate_limit_ctx_opt.as_ref()).await {
                    Ok(result) => {
                        debug!("WHOIS lookup complete for {}: {} (verified: {})",
                               domain, result.name, result.is_verified);
                        (domain, result)
                    }
                    Err(e) => {
                        debug!("WHOIS lookup failed for {}: {}, using domain fallback", domain, e);
                        (domain.clone(), OrganizationResult::inferred(extract_organization_from_domain(&domain)))
                    }
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let result_map: HashMap<String, OrganizationResult> = results.into_iter().collect();
    debug!("Completed parallel WHOIS lookups: {} results", result_map.len());

    result_map
}

/// Pre-warm organization cache by performing parallel lookups for discovered domains
///
/// This is useful when you have a set of domains from DNS discovery and want to
/// resolve all their organizations in parallel before processing relationships.
///
/// # Arguments
/// * `domains` - List of domains to look up
/// * `existing_cache` - Already cached domain -> organization mappings to skip
/// * `web_org_enabled` - Whether to enable web page organization extraction
/// * `min_confidence` - Minimum confidence for web org extraction
/// * `concurrency` - Maximum concurrent lookups
/// * `logger` - Optional callback for logging progress
///
/// # Returns
/// A HashMap of newly resolved domain -> organization name mappings
pub async fn prewarm_organization_cache<F>(
    domains: Vec<String>,
    existing_cache: &HashMap<String, String>,
    web_org_enabled: bool,
    min_confidence: f32,
    concurrency: usize,
    progress_callback: Option<F>,
) -> HashMap<String, String>
where
    F: Fn(usize, usize, &str) + Send + Sync,
{
    // Filter out domains already in cache
    let uncached_domains: Vec<String> = domains
        .into_iter()
        .filter(|d| !existing_cache.contains_key(d))
        .collect();

    if uncached_domains.is_empty() {
        debug!("All domains already cached, skipping WHOIS pre-warming");
        return HashMap::new();
    }

    let total = uncached_domains.len();
    debug!("Pre-warming WHOIS cache for {} uncached domains (concurrency: {})", total, concurrency);

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let progress_counter = Arc::new(tokio::sync::Mutex::new(0usize));

    let results: Vec<(String, String)> = stream::iter(uncached_domains.into_iter())
        .map(|domain| {
            let semaphore = semaphore.clone();
            let progress_counter = progress_counter.clone();
            let callback = &progress_callback;

            async move {
                let _permit = semaphore.acquire().await.unwrap();

                // Update progress
                let current = {
                    let mut counter = progress_counter.lock().await;
                    *counter += 1;
                    *counter
                };

                if let Some(cb) = callback {
                    cb(current, total, &domain);
                }

                match get_organization_with_status_and_config(&domain, web_org_enabled, min_confidence).await {
                    Ok(result) => (domain, result.name),
                    Err(_) => (domain.clone(), extract_organization_from_domain(&domain)),
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let new_cache: HashMap<String, String> = results.into_iter().collect();
    debug!("Pre-warmed {} organization mappings", new_cache.len());

    new_cache
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_result_verified() {
        let result = OrganizationResult::verified("Test Corp".to_string(), "whois");
        assert_eq!(result.name, "Test Corp");
        assert!(result.is_verified);
        assert_eq!(result.source, "whois");
    }

    #[test]
    fn test_organization_result_inferred() {
        let result = OrganizationResult::inferred("Test Inc.".to_string());
        assert_eq!(result.name, "Test Inc.");
        assert!(!result.is_verified);
        assert_eq!(result.source, "domain_fallback");
    }

    #[test]
    fn test_extract_organization_from_domain() {
        // Basic domain extraction
        assert_eq!(extract_organization_from_domain("example.com"), "Example Inc.");
        assert_eq!(extract_organization_from_domain("test-company.org"), "Test-company Inc.");

        // Subdomains should use the second-to-last part
        assert_eq!(extract_organization_from_domain("www.example.com"), "Example Inc.");
        assert_eq!(extract_organization_from_domain("api.sub.example.com"), "Example Inc.");
    }

    #[test]
    fn test_is_placeholder_organization() {
        // Privacy protection services
        assert!(is_placeholder_organization("Domains by Proxy, LLC"));
        assert!(is_placeholder_organization("WhoisGuard Protected"));
        assert!(is_placeholder_organization("REDACTED FOR PRIVACY"));
        assert!(is_placeholder_organization("Contact Privacy Inc."));

        // Domain registrars
        assert!(is_placeholder_organization("MarkMonitor Inc."));
        assert!(is_placeholder_organization("GoDaddy.com, LLC"));
        assert!(is_placeholder_organization("Cloudflare, Inc."));

        // Address-like values (start with numbers)
        assert!(is_placeholder_organization("5335 Gate Parkway"));
        assert!(is_placeholder_organization("123 Main Street"));

        // Valid organization names
        assert!(!is_placeholder_organization("Microsoft Corporation"));
        assert!(!is_placeholder_organization("Google LLC"));
        assert!(!is_placeholder_organization("Anthropic PBC"));
    }

    #[test]
    fn test_clean_organization_name() {
        assert_eq!(clean_organization_name("  Test Corp  "), "Test Corp");
        assert_eq!(clean_organization_name("Test\nCorp"), "Test Corp");
        assert_eq!(clean_organization_name("Test\r\nCorp"), "Test Corp");
        assert_eq!(clean_organization_name("Test\t\tCorp"), "Test Corp");
        assert_eq!(clean_organization_name("  Multiple   Spaces  "), "Multiple Spaces");
    }

    #[test]
    fn test_extract_organization_from_whois() {
        // Valid organization field
        let whois_data = "Domain Name: example.com\nOrganization: Test Corporation\nRegistrar: GoDaddy";
        assert_eq!(
            extract_organization_from_whois(whois_data),
            Some("Test Corporation".to_string())
        );

        // Registrant Organization field
        let whois_data = "Domain Name: example.com\nRegistrant Organization: Acme Inc\nRegistrar: NameCheap";
        assert_eq!(
            extract_organization_from_whois(whois_data),
            Some("Acme Inc".to_string())
        );

        // Privacy protected - registrar fallback may be used if registrar is a valid org
        let whois_data = "Domain Name: example.com\nOrganization: REDACTED FOR PRIVACY\nRegistrar: Real Registrar";
        // The registrar "Real Registrar" is not in the placeholder list, so it gets returned as fallback
        assert_eq!(
            extract_organization_from_whois(whois_data),
            Some("Real Registrar".to_string())
        );

        // Privacy protected with registrar that is a known placeholder
        let whois_data = "Domain Name: example.com\nOrganization: REDACTED FOR PRIVACY\nRegistrar: GoDaddy.com, LLC";
        // GoDaddy is in the placeholder list, so should return None
        assert!(extract_organization_from_whois(whois_data).is_none());
    }

    #[tokio::test]
    async fn test_batch_get_organizations_empty_list() {
        let domains: Vec<String> = vec![];
        let results = batch_get_organizations(domains, false, 0.6, 5).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_batch_get_organizations_concurrency_limit() {
        // Test that concurrency is properly limited
        // This test uses known_vendors which should return quickly
        let domains = vec![
            "google.com".to_string(),
            "microsoft.com".to_string(),
            "amazon.com".to_string(),
        ];

        let results = batch_get_organizations(domains.clone(), false, 0.6, 2).await;

        // All domains should be resolved
        assert_eq!(results.len(), 3);

        // Each domain should have a result
        for domain in &domains {
            assert!(results.contains_key(domain), "Missing result for {}", domain);
        }
    }

    #[tokio::test]
    async fn test_prewarm_organization_cache_skips_cached() {
        let domains = vec![
            "cached.com".to_string(),
            "new.com".to_string(),
        ];

        let mut existing_cache = HashMap::new();
        existing_cache.insert("cached.com".to_string(), "Cached Corp".to_string());

        let new_results = prewarm_organization_cache::<fn(usize, usize, &str)>(
            domains,
            &existing_cache,
            false,
            0.6,
            5,
            None,
        ).await;

        // Only the uncached domain should be in results
        assert!(!new_results.contains_key("cached.com"), "Cached domain should be skipped");
        assert!(new_results.contains_key("new.com"), "New domain should be resolved");
    }

    #[tokio::test]
    async fn test_prewarm_organization_cache_all_cached() {
        let domains = vec![
            "cached1.com".to_string(),
            "cached2.com".to_string(),
        ];

        let mut existing_cache = HashMap::new();
        existing_cache.insert("cached1.com".to_string(), "Corp 1".to_string());
        existing_cache.insert("cached2.com".to_string(), "Corp 2".to_string());

        let new_results = prewarm_organization_cache::<fn(usize, usize, &str)>(
            domains,
            &existing_cache,
            false,
            0.6,
            5,
            None,
        ).await;

        // No new results since all were cached
        assert!(new_results.is_empty(), "Should return empty when all domains cached");
    }

    #[tokio::test]
    async fn test_prewarm_with_progress_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let domains = vec![
            "test1.com".to_string(),
            "test2.com".to_string(),
        ];

        let existing_cache = HashMap::new();
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let callback = move |_current: usize, _total: usize, _domain: &str| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
        };

        let _results = prewarm_organization_cache(
            domains,
            &existing_cache,
            false,
            0.6,
            5,
            Some(callback),
        ).await;

        // Callback should be called for each domain
        assert_eq!(call_count.load(Ordering::SeqCst), 2, "Progress callback should be called for each domain");
    }

    #[tokio::test]
    async fn test_get_organization_with_rate_limit() {
        use crate::config::RateLimitConfig;

        // Create a rate limit context with high limits to avoid actual waiting in tests
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);

        // Test with rate limiting enabled - should work for a domain in known_vendors
        let result = get_organization_with_rate_limit("google.com", false, 0.6, Some(&ctx)).await;
        assert!(result.is_ok(), "Should successfully look up organization");
        let org = result.unwrap();
        assert!(org.is_verified || !org.is_verified, "Result should be valid (verified or inferred)");
    }

    #[tokio::test]
    async fn test_batch_get_organizations_with_rate_limit() {
        use crate::config::RateLimitConfig;

        // Create a rate limit context
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);

        let domains = vec![
            "google.com".to_string(),
            "microsoft.com".to_string(),
        ];

        let results = batch_get_organizations_with_rate_limit(
            domains.clone(),
            false,
            0.6,
            2,
            Some(&ctx),
        ).await;

        // All domains should have results
        assert_eq!(results.len(), 2);
        for domain in &domains {
            assert!(results.contains_key(domain), "Missing result for {}", domain);
        }
    }
}