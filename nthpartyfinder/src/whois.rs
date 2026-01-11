use regex::Regex;
use anyhow::{Result, anyhow};
use tracing::debug;
use std::time::Duration;
use std::process::Command;
use whois_rust::{WhoIs, WhoIsLookupOptions};
use crate::known_vendors;
use crate::web_org;
use crate::ner_org;

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
    if web_org_enabled {
        if let Ok(Some(web_result)) = web_org::extract_organization_from_web(domain).await {
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
    if web_org_enabled {
        if let Ok(Some(web_result)) = web_org::extract_organization_from_web(domain).await {
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