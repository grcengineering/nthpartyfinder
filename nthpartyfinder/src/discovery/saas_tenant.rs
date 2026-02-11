//! SaaS tenant discovery by probing popular platforms.
//!
//! Supports loading platform definitions from:
//! - VendorRegistry (consolidated vendor JSON files) - preferred
//! - Legacy saas_platforms.json file - fallback

use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use futures::{stream, StreamExt};
use reqwest::Client;
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
        self.probe_with_logger(target_domain, None).await
    }

    pub async fn probe_with_logger(&self, target_domain: &str, logger: Option<&AnalysisLogger>) -> Result<Vec<TenantProbeResult>> {
        let tenant_names = generate_tenant_names(target_domain);
        debug!("Generated tenant name candidates: {:?}", tenant_names);

        // Phase 1: Baseline canary probes — one per unique pattern
        // Detects wildcard platforms that return identical responses for any tenant
        let mut baselines: HashMap<String, BaselineResponse> = HashMap::new();
        let unique_patterns: Vec<String> = self.platforms.iter()
            .flat_map(|p| p.tenant_patterns.iter().cloned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if let Some(log) = logger {
            log.show_sub_progress(&format!(
                "Probing SaaS platforms for {} (baselining {} patterns)",
                target_domain, unique_patterns.len()
            )).await;
        }

        let baseline_results: Vec<(String, Option<BaselineResponse>)> = stream::iter(unique_patterns)
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
                debug!("Baseline established for pattern {}: HTTP {} | {} bytes", pattern, b.status_code, b.body_length);
                baselines.insert(pattern, b);
            }
        }
        debug!("Established {} baselines from {} patterns", baselines.len(), self.platforms.iter().flat_map(|p| &p.tenant_patterns).count());

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
            )).await;
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
                        &client, &url, &detection, &vendor_domain, baseline.as_ref()
                    ).await;
                    let done = completed_ref.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Some(ref log) = logger_clone {
                        log.show_sub_progress(&format!(
                            "Probing SaaS platforms for {} ({}/{} probes: {})",
                            target_ref, done, total_probes, name
                        )).await;
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
                debug!("Tenant URL {} redirected to main site {}, marking as NotFound", url, final_url);
                return (TenantStatus::NotFound, evidence);
            }

            // Defense-in-depth: detect wildcard DNS where final URL host is the vendor's main domain
            let final_host = extract_host_from_url(&final_url).unwrap_or_default();
            let vendor_bare = vendor_domain.to_lowercase();
            let final_stripped = final_host.strip_prefix("www.").unwrap_or(&final_host);
            if final_stripped == vendor_bare && final_host != extract_host_from_url(url).unwrap_or_default() {
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

                    let (status, matched) = analyze_response_with_evidence(status_code, &body, detection);
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
                    let evidence = format!("HTTP {}{} | {:?}{}", status_code, redirect_info, status, match_info);
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
    let known_redirects = [
        ("duosecurity.com", "duo.com"),
    ];
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
        let has_success = detection.success_indicators.iter()
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
fn analyze_response_with_evidence(status_code: u16, body: &str, detection: &DetectionConfig) -> (TenantStatus, Vec<String>) {
    let body_lower = body.to_lowercase();

    // Check for failure indicators first
    for indicator in &detection.failure_indicators {
        if body_lower.contains(&indicator.to_lowercase()) {
            return (TenantStatus::NotFound, vec![format!("failure:{}", indicator)]);
        }
    }

    if status_code == 200 {
        let matched: Vec<String> = detection.success_indicators.iter()
            .filter(|ind| body_lower.contains(&ind.to_lowercase()))
            .map(|ind| ind.clone())
            .collect();

        if !matched.is_empty() {
            (TenantStatus::Confirmed, matched)
        } else if detection.success_indicators.is_empty() {
            (TenantStatus::Likely, vec![])
        } else {
            (TenantStatus::Unknown, vec![])
        }
    } else if status_code == 404 || status_code >= 400 {
        (TenantStatus::NotFound, vec![format!("http_status:{}", status_code)])
    } else {
        (TenantStatus::Unknown, vec![format!("http_status:{}", status_code)])
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
        assert!(matches_baseline(200, body, "https://account.box.com/login", &baseline));
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
        assert!(matches_baseline(200, &real_body, "https://app.example.com/other", &baseline));
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
        assert!(!matches_baseline(200, &real_body, "https://app.example.com/dashboard", &baseline));
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
        assert!(matches_baseline(200, "different content entirely", "https://account.box.com/login", &baseline));
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
        assert!(!matches_baseline(200, real_body, "https://klaviyo.okta.com/login", &baseline));
    }

    #[test]
    fn test_compute_body_hash_deterministic() {
        let body = "Hello, World!";
        assert_eq!(compute_body_hash(body), compute_body_hash(body));
    }

    #[test]
    fn test_compute_body_hash_different_content() {
        assert_ne!(compute_body_hash("content A"), compute_body_hash("content B"));
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
        assert!(!matches_baseline(200, &"x".repeat(100), "https://example.com/b", &baseline));
    }
}
