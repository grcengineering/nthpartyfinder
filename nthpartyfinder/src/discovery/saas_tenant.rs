//! SaaS tenant discovery by probing popular platforms.
//!
//! Supports loading platform definitions from:
//! - VendorRegistry (consolidated vendor JSON files) - preferred
//! - Legacy saas_platforms.json file - fallback

use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;
use futures::{stream, StreamExt};
use reqwest::Client;
use tracing::{debug, info};

use crate::vendor_registry;

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
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
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
    #[allow(dead_code)]
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

    /// Returns the number of platforms loaded
    pub fn platform_count(&self) -> usize {
        self.platforms.len()
    }

    /// Load platforms from legacy saas_platforms.json file
    pub fn load_platforms(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        let file: PlatformsFile = serde_json::from_str(&content)?;
        self.platforms = file.platforms;
        debug!("Loaded {} SaaS platforms from file", self.platforms.len());
        Ok(())
    }

    /// Load platforms from VendorRegistry (preferred source)
    /// Falls back to empty list if registry not initialized
    pub fn load_from_vendor_registry(&mut self) {
        let tenants = vendor_registry::get_all_saas_tenants();
        if tenants.is_empty() {
            debug!("No SaaS tenants found in VendorRegistry");
            return;
        }

        for (vendor_id, tenant) in tenants {
            // Get vendor info for the vendor_domain
            let vendor_domain = if let Some(vendor) = vendor_registry::get() {
                vendor.get_vendor(&vendor_id)
                    .map(|v| v.primary_domain.clone())
                    .unwrap_or_else(|| format!("{}.com", vendor_id))
            } else {
                format!("{}.com", vendor_id)
            };

            let detection = if let Some(det) = tenant.detection {
                DetectionConfig {
                    success_indicators: det.success_indicators.unwrap_or_default(),
                    failure_indicators: det.failure_indicators.unwrap_or_default(),
                    notes: det.notes,
                }
            } else {
                DetectionConfig {
                    success_indicators: Vec::new(),
                    failure_indicators: Vec::new(),
                    notes: None,
                }
            };

            self.platforms.push(SaasPlatform {
                name: tenant.name,
                vendor_domain,
                tenant_patterns: tenant.patterns,
                detection,
            });
        }

        info!("Loaded {} SaaS platforms from VendorRegistry", self.platforms.len());
    }

    /// Load platforms from VendorRegistry first, then fallback to file if empty
    pub fn load_platforms_with_fallback(&mut self, fallback_path: &Path) -> Result<()> {
        self.load_from_vendor_registry();

        if self.platforms.is_empty() {
            debug!("VendorRegistry empty, falling back to file");
            self.load_platforms(fallback_path)?;
        }

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

        // Deduplicate by vendor_domain - multiple patterns for the same vendor
        // can produce duplicate entries (R002 fix). Keep first (highest confidence) match.
        let mut seen_vendors = std::collections::HashSet::new();
        let deduped_results: Vec<TenantProbeResult> = results.into_iter()
            .filter(|r| seen_vendors.insert(r.vendor_domain.clone()))
            .collect();

        debug!("Found {} unique likely/confirmed tenants (after dedup)", deduped_results.len());
        Ok(deduped_results)
    }
}

/// Generate tenant name candidates from a domain
pub fn generate_tenant_names(domain: &str) -> Vec<String> {
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

/// Construct a probe URL from a pattern and tenant name
pub fn construct_probe_url(pattern: &str, tenant: &str) -> String {
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
            let final_url = response.url().to_string();

            // Check if we were redirected to the main company site
            // This indicates the tenant doesn't exist (e.g., auth0.com/duo.com redirect invalid tenants)
            if was_redirected_to_main_site(url, &final_url) {
                debug!("Tenant URL {} redirected to main site {}, marking as NotFound", url, final_url);
                return TenantStatus::NotFound;
            }

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

/// Check if a URL was redirected to the main company site
/// This detects cases like klaviyo.auth0.com -> auth0.com
fn was_redirected_to_main_site(original_url: &str, final_url: &str) -> bool {
    // Parse URLs to extract domains
    let original_host = extract_host_from_url(original_url);
    let final_host = extract_host_from_url(final_url);

    if original_host.is_none() || final_host.is_none() {
        return false;
    }

    let original_host = original_host.unwrap();
    let final_host = final_host.unwrap();

    // If hosts are the same, no redirect to main site
    if original_host == final_host {
        return false;
    }

    // Check if the final host is the "base" domain of the original
    // e.g., klaviyo.auth0.com -> auth0.com
    // e.g., klaviyo.duosecurity.com -> duo.com
    let original_parts: Vec<&str> = original_host.split('.').collect();
    let final_parts: Vec<&str> = final_host.split('.').collect();

    // Main sites usually have 2 parts (domain.tld) or www.domain.tld
    // Check if final URL looks like a main company site
    let is_main_site = final_parts.len() <= 3 &&
        (final_parts.first() == Some(&"www") || final_parts.len() == 2);

    if !is_main_site {
        return false;
    }

    // Check if the original URL's subdomain was the tenant identifier
    // e.g., if original is "tenant.auth0.com" and final is "auth0.com"
    if original_parts.len() > final_parts.len() {
        // Check if the "core" domain matches
        let original_core = if original_parts.len() >= 2 {
            format!("{}.{}", original_parts[original_parts.len()-2], original_parts[original_parts.len()-1])
        } else {
            original_host.clone()
        };

        let final_core = if final_parts.len() >= 2 {
            let last = final_parts.len();
            format!("{}.{}", final_parts[last-2], final_parts[last-1])
        } else {
            final_host.clone()
        };

        // Known redirect patterns: some services redirect to different domains
        // e.g., duosecurity.com -> duo.com
        let known_redirects = [
            ("duosecurity.com", "duo.com"),
            ("auth0.com", "auth0.com"),
        ];

        for (from_domain, to_domain) in known_redirects {
            if original_core.ends_with(from_domain) && final_core.ends_with(to_domain) {
                return true;
            }
        }

        // If core domains match, it's likely a redirect to main site
        if original_core == final_core {
            return true;
        }
    }

    false
}

/// Extract host from URL string
fn extract_host_from_url(url: &str) -> Option<String> {
    // Simple URL parsing - handle both http:// and https://
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Get just the host part (before any path/query)
    let host = without_scheme.split('/').next()?;
    let host = host.split('?').next()?;
    let host = host.split(':').next()?; // Remove port if present

    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// Analyze HTTP response to determine tenant status
pub fn analyze_response(status_code: u16, body: &str, detection: &DetectionConfig) -> TenantStatus {
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
            notes: None,
        };
        let status = analyze_response(200, "Welcome to Okta Sign In page", &detection);
        assert_eq!(status, TenantStatus::Confirmed);
    }

    #[test]
    fn test_analyze_response_not_found() {
        let detection = DetectionConfig {
            success_indicators: vec!["Sign In".to_string()],
            failure_indicators: vec!["not found".to_string()],
            notes: None,
        };
        let status = analyze_response(404, "Page not found", &detection);
        assert_eq!(status, TenantStatus::NotFound);
    }

    #[test]
    fn test_analyze_response_likely() {
        let detection = DetectionConfig {
            success_indicators: vec!["Specific Brand".to_string()],
            failure_indicators: vec!["not found".to_string()],
            notes: None,
        };
        let status = analyze_response(200, "Some generic page content", &detection);
        assert_eq!(status, TenantStatus::Likely);
    }

    #[test]
    fn test_analyze_response_failure_indicator_takes_priority() {
        let detection = DetectionConfig {
            success_indicators: vec!["Okta".to_string()],
            failure_indicators: vec!["not found".to_string()],
            notes: None,
        };
        // Even with Okta in the body, "not found" should trigger NotFound
        let status = analyze_response(200, "Okta tenant not found", &detection);
        assert_eq!(status, TenantStatus::NotFound);
    }
}
