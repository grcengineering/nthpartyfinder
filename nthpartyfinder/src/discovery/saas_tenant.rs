//! SaaS tenant discovery by probing popular platforms.
//!
//! Supports loading platform definitions from:
//! - VendorRegistry (consolidated vendor JSON files) - preferred
//! - Legacy saas_platforms.json file - fallback

use anyhow::Result;
use futures::{stream, StreamExt};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tracing::{debug, info};

use crate::logger::AnalysisLogger;
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
    pub evidence: String,
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
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
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
                vendor
                    .get_vendor(&vendor_id)
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

        info!(
            "Loaded {} SaaS platforms from VendorRegistry",
            self.platforms.len()
        );
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
        self.probe_with_logger(target_domain, None).await
    }

    pub async fn probe_with_logger(
        &self,
        target_domain: &str,
        logger: Option<&AnalysisLogger>,
    ) -> Result<Vec<TenantProbeResult>> {
        let tenant_names = generate_tenant_names(target_domain);
        debug!("Generated tenant name candidates: {:?}", tenant_names);

        // Phase 1: Baseline canary probes — one per unique pattern
        // Detects wildcard platforms that return identical responses for any tenant
        let mut baselines: HashMap<String, BaselineResponse> = HashMap::new();
        let unique_patterns: Vec<String> = self
            .platforms
            .iter()
            .flat_map(|p| p.tenant_patterns.iter().cloned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if let Some(log) = logger {
            log.show_sub_progress(&format!(
                "Probing SaaS platforms for {} (baselining {} patterns)",
                target_domain,
                unique_patterns.len()
            ))
            .await;
        }

        let baseline_results: Vec<(String, Option<BaselineResponse>)> =
            stream::iter(unique_patterns)
                .map(|pattern| {
                    let client = self.client.clone();
                    async move {
                        let baseline = probe_baseline(&client, &pattern).await;
                        (pattern, baseline)
                    }
                })
                .buffer_unordered(self.concurrency)
                .collect()
                .await;

        for (pattern, baseline) in baseline_results {
            if let Some(b) = baseline {
                debug!(
                    "Baseline established for pattern {}: HTTP {} | {} bytes",
                    pattern, b.status_code, b.body_length
                );
                baselines.insert(pattern, b);
            }
        }
        debug!(
            "Established {} baselines from {} patterns",
            baselines.len(),
            self.platforms
                .iter()
                .flat_map(|p| &p.tenant_patterns)
                .count()
        );

        // Phase 2: Real tenant probes with baseline comparison
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
                        pattern.clone(),
                    ));
                }
            }
        }

        let total_probes = probe_tasks.len();
        let platform_count = self.platforms.len();
        debug!("Probing {} URLs for tenant discovery", total_probes);

        if let Some(log) = logger {
            log.show_sub_progress(&format!(
                "Probing SaaS platforms for {} (0/{} probes across {} platforms)",
                target_domain, total_probes, platform_count
            ))
            .await;
        }

        let baselines_ref = &baselines;
        let completed = AtomicUsize::new(0);
        let target_domain_owned = target_domain.to_string();
        let results: Vec<TenantProbeResult> = stream::iter(probe_tasks)
            .map(|(name, vendor, url, detection, pattern)| {
                let client = self.client.clone();
                let vendor_domain = vendor.clone();
                let baseline = baselines_ref.get(&pattern).cloned();
                let completed_ref = &completed;
                let logger_clone = logger.cloned();
                let target_ref = &target_domain_owned;
                async move {
                    let (status, evidence) = probe_url_with_baseline(
                        &client,
                        &url,
                        &detection,
                        &vendor_domain,
                        baseline.as_ref(),
                    )
                    .await;
                    let done = completed_ref.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Some(ref log) = logger_clone {
                        log.show_sub_progress(&format!(
                            "Probing SaaS platforms for {} ({}/{} probes: {})",
                            target_ref, done, total_probes, name
                        ))
                        .await;
                    }
                    TenantProbeResult {
                        platform_name: name,
                        vendor_domain: vendor,
                        tenant_url: url,
                        status,
                        evidence,
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
        let deduped_results: Vec<TenantProbeResult> = results
            .into_iter()
            .filter(|r| seen_vendors.insert(r.vendor_domain.clone()))
            .collect();

        debug!(
            "Found {} unique likely/confirmed tenants (after dedup)",
            deduped_results.len()
        );
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

/// Probe a URL with optional baseline comparison for wildcard detection.
/// If a baseline exists and the response matches it, the probe is downgraded to NotFound.
async fn probe_url_with_baseline(
    client: &Client,
    url: &str,
    detection: &DetectionConfig,
    vendor_domain: &str,
    baseline: Option<&BaselineResponse>,
) -> (TenantStatus, String) {
    match client.get(url).send().await {
        Ok(response) => {
            let status_code = response.status().as_u16();
            let final_url = response.url().to_string();
            let was_redirected = extract_host_from_url(url) != extract_host_from_url(&final_url);

            // Check if we were redirected to the main company site
            if was_redirected_to_main_site(url, &final_url) {
                let evidence = format!(
                    "HTTP {} | Redirected to {} (vendor main site)",
                    status_code, final_url
                );
                debug!(
                    "Tenant URL {} redirected to main site {}, marking as NotFound",
                    url, final_url
                );
                return (TenantStatus::NotFound, evidence);
            }

            // Defense-in-depth: detect wildcard DNS where final URL host is the vendor's main domain
            let final_host = extract_host_from_url(&final_url).unwrap_or_default();
            let vendor_bare = vendor_domain.to_lowercase();
            let final_stripped = final_host.strip_prefix("www.").unwrap_or(&final_host);
            if final_stripped == vendor_bare
                && final_host != extract_host_from_url(url).unwrap_or_default()
            {
                let evidence = format!(
                    "HTTP {} | Resolved to vendor main site {} (wildcard DNS)",
                    status_code, final_url
                );
                debug!("Tenant URL {} resolved to vendor main site {}, likely wildcard DNS - marking NotFound", url, final_url);
                return (TenantStatus::NotFound, evidence);
            }

            match response.text().await {
                Ok(body) => {
                    // Wildcard detection: compare against baseline canary response
                    if let Some(baseline) = baseline {
                        if matches_baseline(status_code, &body, &final_url, baseline) {
                            let evidence = format!(
                                "HTTP {} | {} bytes | Wildcard: response matches baseline canary (baseline: {} bytes, hash match={})",
                                status_code, body.len(), baseline.body_length,
                                compute_body_hash(&body) == baseline.body_hash
                            );
                            debug!("Tenant URL {} matches baseline canary — wildcard platform, marking NotFound", url);
                            return (TenantStatus::NotFound, evidence);
                        }
                    }

                    let (status, matched) =
                        analyze_response_with_evidence(status_code, &body, detection);
                    let redirect_info = if was_redirected {
                        format!(" | Redirected to {}", final_url)
                    } else {
                        String::new()
                    };
                    let match_info = if matched.is_empty() {
                        String::new()
                    } else {
                        format!(" | Matched: [{}]", matched.join(", "))
                    };
                    let evidence = format!(
                        "HTTP {}{} | {:?}{}",
                        status_code, redirect_info, status, match_info
                    );
                    (status, evidence)
                }
                Err(e) => {
                    let evidence = format!("HTTP {} | Body read error: {}", status_code, e);
                    if status_code == 200 {
                        (TenantStatus::Likely, evidence)
                    } else {
                        (TenantStatus::NotFound, evidence)
                    }
                }
            }
        }
        Err(e) => {
            let evidence = format!("Request failed: {}", e);
            if e.is_timeout() {
                (TenantStatus::Unknown, evidence)
            } else {
                (TenantStatus::NotFound, evidence)
            }
        }
    }
}

/// Check if a URL was redirected to the main company site.
/// Detects cases like:
/// - klaviyo.bamboohr.com -> www.bamboohr.com (www prefix replacement)
/// - klaviyo.auth0.com -> auth0.com (subdomain stripped)
/// - klaviyo.duosecurity.com -> duo.com (cross-domain redirect)
/// - jobs.lever.co/klaviyo -> jobs.lever.co/ (path-based redirect)
fn was_redirected_to_main_site(original_url: &str, final_url: &str) -> bool {
    let original_host = match extract_host_from_url(original_url) {
        Some(h) => h,
        None => return false,
    };
    let final_host = match extract_host_from_url(final_url) {
        Some(h) => h,
        None => return false,
    };

    let core_domain = |host: &str| -> String {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            host.to_string()
        }
    };

    // Same host: check for path-based redirect (e.g., /klaviyo -> /)
    if original_host == final_host {
        let original_path = extract_path_from_url(original_url);
        let final_path = extract_path_from_url(final_url);
        // Original had a meaningful path but final is just root
        if original_path.len() > 1 && (final_path == "/" || final_path.is_empty()) {
            return true;
        }
        return false;
    }

    let original_core = core_domain(&original_host);
    let final_core = core_domain(&final_host);

    // Same core domain: final host is the bare domain or www.domain
    // e.g., klaviyo.bamboohr.com -> www.bamboohr.com (both core: bamboohr.com)
    // e.g., klaviyo.auth0.com -> auth0.com (both core: auth0.com)
    if original_core == final_core {
        let final_stripped = final_host.strip_prefix("www.").unwrap_or(&final_host);
        if final_stripped == original_core {
            return true;
        }
    }

    // Known cross-domain redirects (e.g., duosecurity.com -> duo.com)
    let known_redirects = [("duosecurity.com", "duo.com")];
    for (from_domain, to_domain) in known_redirects {
        if original_core == from_domain && final_core == to_domain {
            return true;
        }
    }

    false
}

/// Extract path from URL string
fn extract_path_from_url(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    if let Some(slash_pos) = without_scheme.find('/') {
        let path = &without_scheme[slash_pos..];
        path.split('?').next().unwrap_or(path).to_string()
    } else {
        "/".to_string()
    }
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
        let has_success = detection
            .success_indicators
            .iter()
            .any(|ind| body_lower.contains(&ind.to_lowercase()));

        if has_success {
            TenantStatus::Confirmed
        } else if detection.success_indicators.is_empty() {
            // No success indicators defined — HTTP 200 alone is a signal
            TenantStatus::Likely
        } else {
            // Success indicators defined but none matched — insufficient evidence
            TenantStatus::Unknown
        }
    } else if status_code == 404 || status_code >= 400 {
        TenantStatus::NotFound
    } else {
        TenantStatus::Unknown
    }
}

/// Analyze HTTP response and return matched indicator names for evidence
fn analyze_response_with_evidence(
    status_code: u16,
    body: &str,
    detection: &DetectionConfig,
) -> (TenantStatus, Vec<String>) {
    let body_lower = body.to_lowercase();

    // Check for failure indicators first
    for indicator in &detection.failure_indicators {
        if body_lower.contains(&indicator.to_lowercase()) {
            return (
                TenantStatus::NotFound,
                vec![format!("failure:{}", indicator)],
            );
        }
    }

    if status_code == 200 {
        let matched: Vec<String> = detection
            .success_indicators
            .iter()
            .filter(|ind| body_lower.contains(&ind.to_lowercase()))
            .cloned()
            .collect();

        if !matched.is_empty() {
            (TenantStatus::Confirmed, matched)
        } else if detection.success_indicators.is_empty() {
            (TenantStatus::Likely, vec![])
        } else {
            (TenantStatus::Unknown, vec![])
        }
    } else if status_code == 404 || status_code >= 400 {
        (
            TenantStatus::NotFound,
            vec![format!("http_status:{}", status_code)],
        )
    } else {
        (
            TenantStatus::Unknown,
            vec![format!("http_status:{}", status_code)],
        )
    }
}

/// Baseline response captured from a canary probe (known-nonexistent tenant)
#[derive(Debug, Clone)]
struct BaselineResponse {
    status_code: u16,
    body_hash: u64,
    body_length: usize,
    final_url: String,
}

/// Compute a fast hash of response body using Rust's built-in DefaultHasher
fn compute_body_hash(body: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut hasher);
    hasher.finish()
}

/// Probe a platform pattern with a canary tenant name to establish baseline response
async fn probe_baseline(client: &Client, pattern: &str) -> Option<BaselineResponse> {
    let canary_name = "nthparty-canary-8f3a2b";
    let url = construct_probe_url(pattern, canary_name);

    match client.get(&url).send().await {
        Ok(response) => {
            let status_code = response.status().as_u16();
            let final_url = response.url().to_string();
            match response.text().await {
                Ok(body) => {
                    let body_hash = compute_body_hash(&body);
                    let body_length = body.len();
                    debug!(
                        "Baseline for pattern {}: HTTP {} | {} bytes | hash {} | final_url {}",
                        pattern, status_code, body_length, body_hash, final_url
                    );
                    Some(BaselineResponse {
                        status_code,
                        body_hash,
                        body_length,
                        final_url,
                    })
                }
                Err(_) => None,
            }
        }
        Err(e) => {
            debug!("Baseline probe failed for pattern {}: {} (platform likely rejects invalid tenants)", pattern, e);
            None
        }
    }
}

/// Check if a probe response matches the baseline (wildcard detection)
fn matches_baseline(
    status_code: u16,
    body: &str,
    final_url: &str,
    baseline: &BaselineResponse,
) -> bool {
    // Exact body hash match — same content as canary
    let body_hash = compute_body_hash(body);
    if body_hash == baseline.body_hash {
        return true;
    }

    // Body length within 5% tolerance (handles dynamic CSRF tokens, timestamps)
    // Only if status codes also match
    if status_code == baseline.status_code && baseline.body_length > 0 {
        let length_ratio = body.len() as f64 / baseline.body_length as f64;
        if (0.95..=1.05).contains(&length_ratio) {
            return true;
        }
    }

    // Same final redirect URL (both redirected to identical login page)
    if !final_url.is_empty() && final_url == baseline.final_url {
        let original_different = true; // We're comparing a real probe vs canary — URLs started different
        if original_different {
            return true;
        }
    }

    false
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
    fn test_analyze_response_indicators_defined_but_unmatched_is_unknown() {
        // When success indicators are defined but none match, should be Unknown (not Likely)
        let detection = DetectionConfig {
            success_indicators: vec!["Specific Brand".to_string()],
            failure_indicators: vec!["not found".to_string()],
            notes: None,
        };
        let status = analyze_response(200, "Some generic page content", &detection);
        assert_eq!(status, TenantStatus::Unknown);
    }

    #[test]
    fn test_analyze_response_no_indicators_defined_is_likely() {
        // When no success indicators are defined, HTTP 200 alone is a signal -> Likely
        let detection = DetectionConfig {
            success_indicators: vec![],
            failure_indicators: vec![],
            notes: None,
        };
        let status = analyze_response(200, "Some page content", &detection);
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

    // --- Redirect detection tests ---

    #[test]
    fn test_redirect_www_prefix_replaces_tenant_subdomain() {
        // Bug 1: klaviyo.bamboohr.com -> www.bamboohr.com (same part count)
        assert!(was_redirected_to_main_site(
            "https://klaviyo.bamboohr.com",
            "https://www.bamboohr.com"
        ));
    }

    #[test]
    fn test_redirect_subdomain_stripped_to_bare_domain() {
        // klaviyo.auth0.com -> auth0.com
        assert!(was_redirected_to_main_site(
            "https://klaviyo.auth0.com",
            "https://auth0.com"
        ));
    }

    #[test]
    fn test_redirect_cross_domain() {
        // Known redirect: duosecurity.com -> duo.com
        assert!(was_redirected_to_main_site(
            "https://klaviyo.duosecurity.com",
            "https://duo.com"
        ));
    }

    #[test]
    fn test_no_redirect_same_host() {
        // Same host, no redirect
        assert!(!was_redirected_to_main_site(
            "https://klaviyo.okta.com",
            "https://klaviyo.okta.com"
        ));
    }

    #[test]
    fn test_redirect_path_based_to_root() {
        // Same host but path changed from tenant-specific to root
        assert!(was_redirected_to_main_site(
            "https://jobs.lever.co/klaviyo",
            "https://jobs.lever.co/"
        ));
    }

    #[test]
    fn test_no_redirect_app_subdomain() {
        // Redirect to app.platform.com is NOT a main-site redirect
        assert!(!was_redirected_to_main_site(
            "https://klaviyo.platform.com",
            "https://app.platform.com/login"
        ));
    }

    #[test]
    fn test_redirect_www_with_path() {
        // Redirect to www.bamboohr.com/ (with trailing slash)
        assert!(was_redirected_to_main_site(
            "https://klaviyo.bamboohr.com/home/",
            "https://www.bamboohr.com/"
        ));
    }

    #[test]
    fn test_no_redirect_same_host_with_path() {
        // Same host, different paths — not a main-site redirect
        assert!(!was_redirected_to_main_site(
            "https://klaviyo.okta.com",
            "https://klaviyo.okta.com/login"
        ));
    }

    // --- Wildcard / baseline detection tests ---

    #[test]
    fn test_baseline_exact_hash_match_is_wildcard() {
        // Box-like: canary and real probe return identical content
        let body = "<html><head><title>Box Login</title></head><body>Log in to Box</body></html>";
        let baseline = BaselineResponse {
            status_code: 200,
            body_hash: compute_body_hash(body),
            body_length: body.len(),
            final_url: "https://account.box.com/login".to_string(),
        };
        assert!(matches_baseline(
            200,
            body,
            "https://account.box.com/login",
            &baseline
        ));
    }

    #[test]
    fn test_baseline_length_tolerance_is_wildcard() {
        // Platform with dynamic CSRF tokens: body differs slightly but length is ~same
        let canary_body = "x".repeat(10000);
        let real_body = "y".repeat(10200); // 2% larger — within 5% tolerance
        let baseline = BaselineResponse {
            status_code: 200,
            body_hash: compute_body_hash(&canary_body),
            body_length: canary_body.len(),
            final_url: "https://app.example.com/login".to_string(),
        };
        // Hash won't match, but length is within tolerance
        assert!(matches_baseline(
            200,
            &real_body,
            "https://app.example.com/other",
            &baseline
        ));
    }

    #[test]
    fn test_baseline_length_outside_tolerance_is_not_wildcard() {
        // Real tenant returns significantly different response size
        let canary_body = "x".repeat(1000);
        let real_body = "y".repeat(5000); // 5x larger — way outside tolerance
        let baseline = BaselineResponse {
            status_code: 200,
            body_hash: compute_body_hash(&canary_body),
            body_length: canary_body.len(),
            final_url: "https://app.example.com/login".to_string(),
        };
        assert!(!matches_baseline(
            200,
            &real_body,
            "https://app.example.com/dashboard",
            &baseline
        ));
    }

    #[test]
    fn test_baseline_same_redirect_url_is_wildcard() {
        // Both canary and real probe redirect to same login page
        let baseline = BaselineResponse {
            status_code: 302,
            body_hash: 12345,
            body_length: 100,
            final_url: "https://account.box.com/login".to_string(),
        };
        // Different body but same final redirect URL
        assert!(matches_baseline(
            200,
            "different content entirely",
            "https://account.box.com/login",
            &baseline
        ));
    }

    #[test]
    fn test_baseline_different_response_is_not_wildcard() {
        // Canary fails (404 page) but real tenant gets unique content
        let canary_body = "Page not found";
        let real_body = "Welcome to Klaviyo's Okta portal - Sign In";
        let baseline = BaselineResponse {
            status_code: 404,
            body_hash: compute_body_hash(canary_body),
            body_length: canary_body.len(),
            final_url: "https://klaviyo.okta.com/404".to_string(),
        };
        assert!(!matches_baseline(
            200,
            real_body,
            "https://klaviyo.okta.com/login",
            &baseline
        ));
    }

    #[test]
    fn test_compute_body_hash_deterministic() {
        let body = "Hello, World!";
        assert_eq!(compute_body_hash(body), compute_body_hash(body));
    }

    #[test]
    fn test_compute_body_hash_different_content() {
        assert_ne!(
            compute_body_hash("content A"),
            compute_body_hash("content B")
        );
    }

    #[test]
    fn test_baseline_status_code_mismatch_skips_length_check() {
        // Same body length but different status codes — should NOT match on length alone
        let baseline = BaselineResponse {
            status_code: 302,
            body_hash: 99999, // different hash
            body_length: 100,
            final_url: "https://example.com/a".to_string(),
        };
        // Status 200 vs baseline 302, same length, different hash, different URL
        assert!(!matches_baseline(
            200,
            &"x".repeat(100),
            "https://example.com/b",
            &baseline
        ));
    }

    // ───────────────────────────────────────────────────────────────
    // Additional coverage tests below
    // ───────────────────────────────────────────────────────────────

    // --- SaasTenantDiscovery construction and platform_count ---

    #[test]
    fn test_new_discovery_has_no_platforms() {
        let disc = SaasTenantDiscovery::new(Duration::from_secs(5), 4);
        assert_eq!(disc.platform_count(), 0);
        assert_eq!(disc.concurrency, 4);
    }

    #[test]
    fn test_platform_count_after_manual_push() {
        let mut disc = SaasTenantDiscovery::new(Duration::from_secs(5), 2);
        disc.platforms.push(SaasPlatform {
            name: "TestPlatform".into(),
            vendor_domain: "test.com".into(),
            tenant_patterns: vec!["{tenant}.test.com".into()],
            detection: DetectionConfig {
                success_indicators: vec![],
                failure_indicators: vec![],
                notes: None,
            },
        });
        assert_eq!(disc.platform_count(), 1);
    }

    // --- load_platforms from file ---

    #[test]
    fn test_load_platforms_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("saas_platforms.json");
        let content = r#"{
            "platforms": [
                {
                    "name": "Okta",
                    "vendor_domain": "okta.com",
                    "tenant_patterns": ["{tenant}.okta.com"],
                    "detection": {
                        "success_indicators": ["Sign In"],
                        "failure_indicators": ["not found"]
                    }
                },
                {
                    "name": "Slack",
                    "vendor_domain": "slack.com",
                    "tenant_patterns": ["{tenant}.slack.com"],
                    "detection": {
                        "success_indicators": ["Slack"],
                        "failure_indicators": ["This workspace was not found"],
                        "notes": "Enterprise only"
                    }
                }
            ]
        }"#;
        std::fs::write(&file_path, content).unwrap();

        let mut disc = SaasTenantDiscovery::new(Duration::from_secs(5), 2);
        disc.load_platforms(&file_path).unwrap();
        assert_eq!(disc.platform_count(), 2);
        assert_eq!(disc.platforms[0].name, "Okta");
        assert_eq!(disc.platforms[1].name, "Slack");
        assert_eq!(
            disc.platforms[1].detection.notes,
            Some("Enterprise only".to_string())
        );
    }

    #[test]
    fn test_load_platforms_missing_file() {
        let mut disc = SaasTenantDiscovery::new(Duration::from_secs(5), 2);
        let result = disc.load_platforms(Path::new("/nonexistent/path.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_platforms_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("bad.json");
        std::fs::write(&file_path, "not json at all").unwrap();

        let mut disc = SaasTenantDiscovery::new(Duration::from_secs(5), 2);
        let result = disc.load_platforms(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_platforms_empty_platforms_array() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("empty.json");
        std::fs::write(&file_path, r#"{"platforms": []}"#).unwrap();

        let mut disc = SaasTenantDiscovery::new(Duration::from_secs(5), 2);
        disc.load_platforms(&file_path).unwrap();
        assert_eq!(disc.platform_count(), 0);
    }

    // --- generate_tenant_names ---

    #[test]
    fn test_generate_tenant_names_subdomain() {
        let names = generate_tenant_names("mail.example.org");
        assert_eq!(names[0], "mail");
        assert!(names.contains(&"mail-inc".to_string()));
        assert!(names.contains(&"mail-corp".to_string()));
    }

    #[test]
    fn test_generate_tenant_names_uppercase() {
        let names = generate_tenant_names("ACME.com");
        assert!(names.contains(&"acme".to_string()));
        assert!(names.contains(&"acme-inc".to_string()));
        assert!(names.contains(&"acmecorp".to_string()));
    }

    #[test]
    fn test_generate_tenant_names_no_dot() {
        // Domain with no dots uses the full string
        let names = generate_tenant_names("localhost");
        assert_eq!(names[0], "localhost");
        assert_eq!(names.len(), 5);
    }

    #[test]
    fn test_generate_tenant_names_count() {
        let names = generate_tenant_names("test.com");
        assert_eq!(names.len(), 5);
        assert_eq!(names[0], "test");
        assert_eq!(names[1], "test-inc");
        assert_eq!(names[2], "testinc");
        assert_eq!(names[3], "test-corp");
        assert_eq!(names[4], "testcorp");
    }

    // --- construct_probe_url ---

    #[test]
    fn test_construct_probe_url_already_has_https() {
        let url = construct_probe_url("https://{tenant}.okta.com", "acme");
        assert_eq!(url, "https://acme.okta.com");
    }

    #[test]
    fn test_construct_probe_url_already_has_http() {
        let url = construct_probe_url("http://{tenant}.example.com", "acme");
        assert_eq!(url, "http://acme.example.com");
    }

    #[test]
    fn test_construct_probe_url_no_scheme() {
        let url = construct_probe_url("{tenant}.zendesk.com", "acme");
        assert_eq!(url, "https://acme.zendesk.com");
    }

    #[test]
    fn test_construct_probe_url_multiple_tenant_placeholders() {
        let url = construct_probe_url("{tenant}.example.com/{tenant}/login", "acme");
        assert_eq!(url, "https://acme.example.com/acme/login");
    }

    #[test]
    fn test_construct_probe_url_no_placeholder() {
        // Pattern without {tenant} — URL remains as-is
        let url = construct_probe_url("static.example.com/login", "acme");
        assert_eq!(url, "https://static.example.com/login");
    }

    // --- extract_host_from_url ---

    #[test]
    fn test_extract_host_https() {
        assert_eq!(
            extract_host_from_url("https://foo.bar.com/path"),
            Some("foo.bar.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_http() {
        assert_eq!(
            extract_host_from_url("http://example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_no_scheme() {
        assert_eq!(
            extract_host_from_url("example.com/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_with_port() {
        assert_eq!(
            extract_host_from_url("https://example.com:8080/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_with_query() {
        assert_eq!(
            extract_host_from_url("https://example.com?q=1"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_uppercase_normalized() {
        assert_eq!(
            extract_host_from_url("https://EXAMPLE.COM/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_empty_after_scheme() {
        // Edge case: "https://" with nothing after
        assert_eq!(extract_host_from_url("https://"), None);
    }

    #[test]
    fn test_extract_host_empty_string() {
        assert_eq!(extract_host_from_url(""), None);
    }

    // --- extract_path_from_url ---

    #[test]
    fn test_extract_path_with_path() {
        assert_eq!(
            extract_path_from_url("https://example.com/foo/bar"),
            "/foo/bar"
        );
    }

    #[test]
    fn test_extract_path_no_path() {
        assert_eq!(extract_path_from_url("https://example.com"), "/");
    }

    #[test]
    fn test_extract_path_root_only() {
        assert_eq!(extract_path_from_url("https://example.com/"), "/");
    }

    #[test]
    fn test_extract_path_with_query_string() {
        assert_eq!(
            extract_path_from_url("https://example.com/path?q=1&r=2"),
            "/path"
        );
    }

    #[test]
    fn test_extract_path_http_scheme() {
        assert_eq!(extract_path_from_url("http://example.com/hello"), "/hello");
    }

    #[test]
    fn test_extract_path_no_scheme() {
        assert_eq!(extract_path_from_url("example.com/test"), "/test");
    }

    // --- analyze_response edge cases ---

    #[test]
    fn test_analyze_response_400_status() {
        let detection = DetectionConfig {
            success_indicators: vec!["OK".into()],
            failure_indicators: vec![],
            notes: None,
        };
        assert_eq!(
            analyze_response(400, "Bad Request", &detection),
            TenantStatus::NotFound
        );
    }

    #[test]
    fn test_analyze_response_500_status() {
        let detection = DetectionConfig {
            success_indicators: vec![],
            failure_indicators: vec![],
            notes: None,
        };
        assert_eq!(
            analyze_response(500, "Internal Server Error", &detection),
            TenantStatus::NotFound
        );
    }

    #[test]
    fn test_analyze_response_301_redirect_unknown() {
        let detection = DetectionConfig {
            success_indicators: vec![],
            failure_indicators: vec![],
            notes: None,
        };
        assert_eq!(
            analyze_response(301, "Moved Permanently", &detection),
            TenantStatus::Unknown
        );
    }

    #[test]
    fn test_analyze_response_case_insensitive_success() {
        let detection = DetectionConfig {
            success_indicators: vec!["sign in".into()],
            failure_indicators: vec![],
            notes: None,
        };
        assert_eq!(
            analyze_response(200, "Please SIGN IN to continue", &detection),
            TenantStatus::Confirmed
        );
    }

    #[test]
    fn test_analyze_response_case_insensitive_failure() {
        let detection = DetectionConfig {
            success_indicators: vec!["Okta".into()],
            failure_indicators: vec!["NOT FOUND".into()],
            notes: None,
        };
        assert_eq!(
            analyze_response(200, "page not found here", &detection),
            TenantStatus::NotFound
        );
    }

    // --- analyze_response_with_evidence ---

    #[test]
    fn test_analyze_response_with_evidence_confirmed() {
        let detection = DetectionConfig {
            success_indicators: vec!["Sign In".into(), "Okta".into()],
            failure_indicators: vec![],
            notes: None,
        };
        let (status, matched) =
            analyze_response_with_evidence(200, "Welcome to Okta Sign In page", &detection);
        assert_eq!(status, TenantStatus::Confirmed);
        assert!(matched.contains(&"Sign In".to_string()));
        assert!(matched.contains(&"Okta".to_string()));
    }

    #[test]
    fn test_analyze_response_with_evidence_partial_match() {
        let detection = DetectionConfig {
            success_indicators: vec!["Sign In".into(), "BrandX".into()],
            failure_indicators: vec![],
            notes: None,
        };
        let (status, matched) = analyze_response_with_evidence(200, "Please Sign In", &detection);
        assert_eq!(status, TenantStatus::Confirmed);
        assert_eq!(matched, vec!["Sign In".to_string()]);
    }

    #[test]
    fn test_analyze_response_with_evidence_failure_indicator() {
        let detection = DetectionConfig {
            success_indicators: vec!["Okta".into()],
            failure_indicators: vec!["not found".into()],
            notes: None,
        };
        let (status, matched) =
            analyze_response_with_evidence(200, "Okta tenant not found", &detection);
        assert_eq!(status, TenantStatus::NotFound);
        assert_eq!(matched, vec!["failure:not found".to_string()]);
    }

    #[test]
    fn test_analyze_response_with_evidence_no_indicators_likely() {
        let detection = DetectionConfig {
            success_indicators: vec![],
            failure_indicators: vec![],
            notes: None,
        };
        let (status, matched) = analyze_response_with_evidence(200, "Some page", &detection);
        assert_eq!(status, TenantStatus::Likely);
        assert!(matched.is_empty());
    }

    #[test]
    fn test_analyze_response_with_evidence_indicators_defined_but_none_matched() {
        let detection = DetectionConfig {
            success_indicators: vec!["SpecificBrand".into()],
            failure_indicators: vec![],
            notes: None,
        };
        let (status, matched) =
            analyze_response_with_evidence(200, "Generic page content", &detection);
        assert_eq!(status, TenantStatus::Unknown);
        assert!(matched.is_empty());
    }

    #[test]
    fn test_analyze_response_with_evidence_404() {
        let detection = DetectionConfig {
            success_indicators: vec![],
            failure_indicators: vec![],
            notes: None,
        };
        let (status, matched) = analyze_response_with_evidence(404, "Not Found", &detection);
        assert_eq!(status, TenantStatus::NotFound);
        assert_eq!(matched, vec!["http_status:404".to_string()]);
    }

    #[test]
    fn test_analyze_response_with_evidence_500() {
        let detection = DetectionConfig {
            success_indicators: vec![],
            failure_indicators: vec![],
            notes: None,
        };
        let (status, matched) = analyze_response_with_evidence(500, "Server Error", &detection);
        assert_eq!(status, TenantStatus::NotFound);
        assert_eq!(matched, vec!["http_status:500".to_string()]);
    }

    #[test]
    fn test_analyze_response_with_evidence_302_redirect() {
        let detection = DetectionConfig {
            success_indicators: vec![],
            failure_indicators: vec![],
            notes: None,
        };
        let (status, matched) = analyze_response_with_evidence(302, "Redirecting...", &detection);
        assert_eq!(status, TenantStatus::Unknown);
        assert_eq!(matched, vec!["http_status:302".to_string()]);
    }

    // --- was_redirected_to_main_site additional edge cases ---

    #[test]
    fn test_redirect_no_host_in_original() {
        // Malformed URL with no host
        assert!(!was_redirected_to_main_site("", "https://example.com"));
    }

    #[test]
    fn test_redirect_no_host_in_final() {
        assert!(!was_redirected_to_main_site("https://example.com", ""));
    }

    #[test]
    fn test_redirect_same_host_path_not_root() {
        // Same host, both have meaningful paths — not a main-site redirect
        assert!(!was_redirected_to_main_site(
            "https://jobs.lever.co/klaviyo",
            "https://jobs.lever.co/other-company"
        ));
    }

    #[test]
    fn test_redirect_same_host_path_root_empty() {
        // Same host, path changes from meaningful to empty (no trailing slash)
        assert!(was_redirected_to_main_site(
            "https://jobs.lever.co/klaviyo",
            "https://jobs.lever.co"
        ));
    }

    #[test]
    fn test_redirect_different_core_domain_not_known() {
        // Different core domains not in known redirect list
        assert!(!was_redirected_to_main_site(
            "https://tenant.oldplatform.com",
            "https://newplatform.io"
        ));
    }

    #[test]
    fn test_redirect_same_core_but_different_subdomain() {
        // Same core domain but final is not bare/www — not a main site redirect
        assert!(!was_redirected_to_main_site(
            "https://tenant.platform.com",
            "https://login.platform.com"
        ));
    }

    #[test]
    fn test_redirect_single_part_host_path_to_root() {
        // Single-part hosts (like "localhost") — same host, path went from /tenant to /
        // This IS a main-site redirect (path-based)
        assert!(was_redirected_to_main_site(
            "https://localhost/tenant",
            "https://localhost/"
        ));
    }

    #[test]
    fn test_redirect_single_part_host_same_path() {
        // Single-part host, same path — NOT a redirect
        assert!(!was_redirected_to_main_site(
            "https://localhost/tenant",
            "https://localhost/tenant"
        ));
    }

    // --- matches_baseline additional cases ---

    #[test]
    fn test_baseline_empty_final_url_no_redirect_match() {
        let baseline = BaselineResponse {
            status_code: 200,
            body_hash: 99999,   // different hash
            body_length: 50000, // very different length
            final_url: "".to_string(),
        };
        // Empty baseline final_url should not match
        assert!(!matches_baseline(
            200,
            "totally different content",
            "",
            &baseline
        ));
    }

    #[test]
    fn test_baseline_zero_body_length_no_length_match() {
        let baseline = BaselineResponse {
            status_code: 200,
            body_hash: 99999,
            body_length: 0, // zero-length baseline
            final_url: "https://different.com".to_string(),
        };
        // Even with zero-length probe body, body_length=0 guard should prevent division issue
        assert!(!matches_baseline(
            200,
            "some content",
            "https://other.com",
            &baseline
        ));
    }

    #[test]
    fn test_baseline_boundary_tolerance_just_within() {
        // 5% tolerance boundary: ratio of 1.05 exactly
        let canary_body = "x".repeat(1000);
        let real_body = "y".repeat(1050); // exactly 5% larger
        let baseline = BaselineResponse {
            status_code: 200,
            body_hash: compute_body_hash(&canary_body),
            body_length: canary_body.len(),
            final_url: "https://different.com/a".to_string(),
        };
        assert!(matches_baseline(
            200,
            &real_body,
            "https://different.com/b",
            &baseline
        ));
    }

    #[test]
    fn test_baseline_boundary_tolerance_just_outside() {
        // 5% tolerance boundary: ratio of 1.06 (outside)
        let canary_body = "x".repeat(1000);
        let real_body = "y".repeat(1060); // 6% larger — outside tolerance
        let baseline = BaselineResponse {
            status_code: 200,
            body_hash: compute_body_hash(&canary_body),
            body_length: canary_body.len(),
            final_url: "https://different.com/a".to_string(),
        };
        assert!(!matches_baseline(
            200,
            &real_body,
            "https://different.com/b",
            &baseline
        ));
    }

    #[test]
    fn test_baseline_boundary_tolerance_just_below() {
        // 5% tolerance: 0.95 exactly
        let canary_body = "x".repeat(1000);
        let real_body = "y".repeat(950); // exactly 5% smaller
        let baseline = BaselineResponse {
            status_code: 200,
            body_hash: compute_body_hash(&canary_body),
            body_length: canary_body.len(),
            final_url: "https://different.com/a".to_string(),
        };
        assert!(matches_baseline(
            200,
            &real_body,
            "https://different.com/b",
            &baseline
        ));
    }

    #[test]
    fn test_baseline_boundary_tolerance_below_range() {
        // ratio of 0.94 — outside lower bound
        let canary_body = "x".repeat(1000);
        let real_body = "y".repeat(940);
        let baseline = BaselineResponse {
            status_code: 200,
            body_hash: compute_body_hash(&canary_body),
            body_length: canary_body.len(),
            final_url: "https://different.com/a".to_string(),
        };
        assert!(!matches_baseline(
            200,
            &real_body,
            "https://different.com/b",
            &baseline
        ));
    }

    // --- compute_body_hash ---

    #[test]
    fn test_compute_body_hash_empty_string() {
        // Empty string should still produce a deterministic hash
        let h1 = compute_body_hash("");
        let h2 = compute_body_hash("");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_body_hash_very_long_body() {
        let long = "a".repeat(100_000);
        let h1 = compute_body_hash(&long);
        let h2 = compute_body_hash(&long);
        assert_eq!(h1, h2);
        // Different content should differ
        let long2 = "b".repeat(100_000);
        assert_ne!(compute_body_hash(&long), compute_body_hash(&long2));
    }

    // --- TenantStatus / TenantProbeResult coverage ---

    #[test]
    fn test_tenant_status_equality() {
        assert_eq!(TenantStatus::Confirmed, TenantStatus::Confirmed);
        assert_eq!(TenantStatus::Likely, TenantStatus::Likely);
        assert_eq!(TenantStatus::NotFound, TenantStatus::NotFound);
        assert_eq!(TenantStatus::Unknown, TenantStatus::Unknown);
        assert_ne!(TenantStatus::Confirmed, TenantStatus::Likely);
    }

    #[test]
    fn test_tenant_status_debug() {
        // Ensure Debug is implemented (compile-time check + format coverage)
        let s = format!("{:?}", TenantStatus::Confirmed);
        assert!(s.contains("Confirmed"));
    }

    #[test]
    fn test_tenant_probe_result_debug_and_clone() {
        let result = TenantProbeResult {
            platform_name: "Okta".into(),
            vendor_domain: "okta.com".into(),
            tenant_url: "https://acme.okta.com".into(),
            status: TenantStatus::Confirmed,
            evidence: "HTTP 200 | Sign In".into(),
        };
        let cloned = result.clone();
        assert_eq!(cloned.platform_name, "Okta");
        assert_eq!(cloned.status, TenantStatus::Confirmed);
        let debug = format!("{:?}", result);
        assert!(debug.contains("Okta"));
    }

    // --- SaasPlatform / DetectionConfig deserialization ---

    #[test]
    fn test_detection_config_default_notes() {
        let json = r#"{"success_indicators": ["test"], "failure_indicators": []}"#;
        let config: DetectionConfig = serde_json::from_str(json).unwrap();
        assert!(config.notes.is_none());
        assert_eq!(config.success_indicators, vec!["test"]);
    }

    #[test]
    fn test_saas_platform_deserialization() {
        let json = r#"{
            "name": "Jira",
            "vendor_domain": "atlassian.com",
            "tenant_patterns": ["{tenant}.atlassian.net"],
            "detection": {
                "success_indicators": ["Atlassian"],
                "failure_indicators": ["This site can't be reached"],
                "notes": "Cloud only"
            }
        }"#;
        let platform: SaasPlatform = serde_json::from_str(json).unwrap();
        assert_eq!(platform.name, "Jira");
        assert_eq!(platform.vendor_domain, "atlassian.com");
        assert_eq!(platform.tenant_patterns, vec!["{tenant}.atlassian.net"]);
        assert_eq!(platform.detection.notes, Some("Cloud only".to_string()));
    }

    #[test]
    fn test_detection_config_clone() {
        let config = DetectionConfig {
            success_indicators: vec!["A".into(), "B".into()],
            failure_indicators: vec!["C".into()],
            notes: Some("note".into()),
        };
        let cloned = config.clone();
        assert_eq!(cloned.success_indicators, config.success_indicators);
        assert_eq!(cloned.notes, config.notes);
    }

    // --- Parameterized tests using rstest ---

    use rstest::rstest;

    #[rstest]
    #[case("{tenant}.okta.com", "acme", "https://acme.okta.com")]
    #[case("jobs.lever.co/{tenant}", "acme", "https://jobs.lever.co/acme")]
    #[case("https://{tenant}.zendesk.com", "acme", "https://acme.zendesk.com")]
    #[case("http://{tenant}.test.com", "acme", "http://acme.test.com")]
    #[case("{tenant}.my.salesforce.com", "acme", "https://acme.my.salesforce.com")]
    fn test_construct_probe_url_parametrized(
        #[case] pattern: &str,
        #[case] tenant: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(construct_probe_url(pattern, tenant), expected);
    }

    #[rstest]
    #[case("https://example.com/path", Some("example.com".to_string()))]
    #[case("http://foo.bar.com:443/x", Some("foo.bar.com".to_string()))]
    #[case("no-scheme.com/path", Some("no-scheme.com".to_string()))]
    #[case("https://", None)]
    #[case("", None)]
    fn test_extract_host_parametrized(#[case] url: &str, #[case] expected: Option<String>) {
        assert_eq!(extract_host_from_url(url), expected);
    }

    #[rstest]
    #[case("https://example.com/foo", "/foo")]
    #[case("https://example.com", "/")]
    #[case("https://example.com/", "/")]
    #[case("https://example.com/a?b=c", "/a")]
    #[case("http://x.com/p/q", "/p/q")]
    fn test_extract_path_parametrized(#[case] url: &str, #[case] expected: &str) {
        assert_eq!(extract_path_from_url(url), expected);
    }

    #[rstest]
    // Status code edge values
    #[case(200, "body", vec![], vec![], TenantStatus::Likely)]
    #[case(200, "has brand", vec!["brand".to_string()], vec![], TenantStatus::Confirmed)]
    #[case(200, "generic", vec!["brand".to_string()], vec![], TenantStatus::Unknown)]
    #[case(403, "forbidden", vec![], vec![], TenantStatus::NotFound)]
    #[case(404, "not found", vec![], vec![], TenantStatus::NotFound)]
    #[case(301, "moved", vec![], vec![], TenantStatus::Unknown)]
    #[case(204, "no content", vec![], vec![], TenantStatus::Unknown)]
    fn test_analyze_response_parametrized(
        #[case] status_code: u16,
        #[case] body: &str,
        #[case] success: Vec<String>,
        #[case] failure: Vec<String>,
        #[case] expected: TenantStatus,
    ) {
        let detection = DetectionConfig {
            success_indicators: success,
            failure_indicators: failure,
            notes: None,
        };
        assert_eq!(analyze_response(status_code, body, &detection), expected);
    }

    // --- was_redirected_to_main_site parametrized ---

    #[rstest]
    #[case("https://tenant.bamboohr.com", "https://www.bamboohr.com", true)]
    #[case("https://tenant.auth0.com", "https://auth0.com", true)]
    #[case("https://tenant.duosecurity.com", "https://duo.com", true)]
    #[case("https://tenant.okta.com", "https://tenant.okta.com", false)]
    #[case("https://jobs.lever.co/tenant", "https://jobs.lever.co/", true)]
    #[case("https://jobs.lever.co/tenant", "https://jobs.lever.co/other", false)]
    #[case("https://tenant.platform.com", "https://app.platform.com/login", false)]
    fn test_was_redirected_to_main_site_parametrized(
        #[case] original: &str,
        #[case] final_url: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(was_redirected_to_main_site(original, final_url), expected);
    }

    // --- Async probe test (mock HTTP with wiremock) ---

    #[tokio::test]
    async fn test_probe_with_no_platforms_returns_empty() {
        let disc = SaasTenantDiscovery::new(Duration::from_secs(5), 4);
        let results = disc.probe("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_probe_with_logger_no_platforms() {
        let disc = SaasTenantDiscovery::new(Duration::from_secs(5), 4);
        let results = disc.probe_with_logger("example.com", None).await.unwrap();
        assert!(results.is_empty());
    }

    // --- BaselineResponse clone/debug coverage ---

    #[test]
    fn test_baseline_response_clone_and_debug() {
        let baseline = BaselineResponse {
            status_code: 200,
            body_hash: 12345,
            body_length: 100,
            final_url: "https://example.com".into(),
        };
        let cloned = baseline.clone();
        assert_eq!(cloned.status_code, 200);
        assert_eq!(cloned.body_hash, 12345);
        let debug = format!("{:?}", baseline);
        assert!(debug.contains("200"));
    }
}
