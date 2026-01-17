//! SaaS tenant discovery by probing popular platforms.

use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;
use futures::{stream, StreamExt};
use reqwest::Client;
use tracing::{debug, warn};

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

    pub fn load_platforms(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        let file: PlatformsFile = serde_json::from_str(&content)?;
        self.platforms = file.platforms;
        debug!("Loaded {} SaaS platforms", self.platforms.len());
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

        debug!("Found {} likely/confirmed tenants", results.len());
        Ok(results)
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
