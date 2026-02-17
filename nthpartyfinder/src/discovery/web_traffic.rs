//! Webpage source & network request discovery module.
//!
//! Discovers nth-party vendor relationships by analyzing:
//! 1. **Page source** (static HTML): External domains in `<script>`, `<link>`, `<img>`,
//!    `<iframe>`, and other resource-loading elements.
//! 2. **Runtime network traffic**: XHR, fetch, WebSocket, and other network requests
//!    made when the page loads and executes JavaScript. This catches self-hosted SDKs
//!    that phone home to vendor servers (e.g., a first-party `/js/pendo.js` that sends
//!    data to `app.pendo.io`).

use anyhow::Result;
use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::debug;
use url::Url;

use crate::domain_utils;

/// Result of web traffic analysis for a single domain.
#[derive(Debug, Clone)]
pub struct WebTrafficResult {
    /// Domain of the discovered vendor (base domain, e.g., "pendo.io")
    pub vendor_domain: String,
    /// How this vendor was discovered
    pub source: WebTrafficSource,
    /// Evidence string (the URL or HTML element that revealed the vendor)
    pub evidence: String,
}

/// How a vendor was discovered via web traffic analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum WebTrafficSource {
    /// Found in static HTML page source (e.g., `<script src="https://cdn.pendo.io/...">`)
    PageSource,
    /// Found in runtime network traffic (e.g., XHR to `https://api.segment.io/...`)
    NetworkTraffic,
}

/// Regex patterns for extracting external resource URLs from HTML.
static SCRIPT_SRC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<script[^>]+src\s*=\s*["']([^"']+)["']"#).unwrap()
});
static LINK_HREF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<link[^>]+href\s*=\s*["']([^"']+)["']"#).unwrap()
});
static IMG_SRC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<img[^>]+src\s*=\s*["']([^"']+)["']"#).unwrap()
});
static IFRAME_SRC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<iframe[^>]+src\s*=\s*["']([^"']+)["']"#).unwrap()
});
// Catch data-src, data-href, and other lazy-loading attributes
static DATA_SRC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"data-(?:src|href)\s*=\s*["'](https?://[^"']+)["']"#).unwrap()
});
// Inline JavaScript URL patterns (e.g., fetch("https://..."), new Image().src = "https://...")
static INLINE_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"["'](https?://[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}[^"']*?)["']"#).unwrap()
});

/// The main web traffic discovery struct.
pub struct WebTrafficDiscovery {
    client: reqwest::Client,
    timeout: Duration,
    /// Maximum time to wait for runtime network activity after page load
    network_wait_ms: u64,
}

impl WebTrafficDiscovery {
    pub fn new(timeout_secs: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
            .redirect(reqwest::redirect::Policy::limited(5))
            .danger_accept_invalid_certs(false)
            .build()
            .expect("Failed to create HTTP client for web traffic discovery");

        Self {
            client,
            timeout: Duration::from_secs(timeout_secs),
            network_wait_ms: 5000,
        }
    }

    /// Analyze a domain for external vendor relationships via web traffic.
    /// Returns a list of discovered vendor domains with evidence.
    pub async fn analyze_domain(&self, domain: &str) -> Vec<WebTrafficResult> {
        let url = format!("https://{}", domain);
        let target_base_domain = domain_utils::extract_base_domain(domain);
        let mut all_results: HashMap<String, WebTrafficResult> = HashMap::new();

        // Phase 1: Static HTML analysis (fast, no browser needed)
        match self.analyze_page_source(&url, &target_base_domain).await {
            Ok(results) => {
                debug!("Web traffic: static analysis of {} found {} external domains", domain, results.len());
                for r in results {
                    all_results.entry(r.vendor_domain.clone()).or_insert(r);
                }
            }
            Err(e) => {
                debug!("Web traffic: static analysis failed for {}: {}", domain, e);
            }
        }

        // Phase 2: Runtime network traffic analysis (browser-based, catches self-hosted SDKs)
        match self.analyze_network_traffic(&url, &target_base_domain).await {
            Ok(results) => {
                debug!("Web traffic: network analysis of {} found {} external domains", domain, results.len());
                for r in results {
                    // Network traffic evidence is stronger — overwrite page source if same domain
                    all_results.insert(r.vendor_domain.clone(), r);
                }
            }
            Err(e) => {
                debug!("Web traffic: network analysis failed for {}: {}", domain, e);
            }
        }

        all_results.into_values().collect()
    }

    /// Phase 1: Parse static HTML for external resource references.
    async fn analyze_page_source(&self, url: &str, target_base_domain: &str) -> Result<Vec<WebTrafficResult>> {
        let response = self.client.get(url).send().await?;
        let html = response.text().await?;
        Ok(extract_external_domains_from_html(&html, target_base_domain))
    }

    /// Phase 2: Load page in headless browser and capture all network requests.
    async fn analyze_network_traffic(&self, url: &str, target_base_domain: &str) -> Result<Vec<WebTrafficResult>> {
        let captured_urls = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured_clone = captured_urls.clone();
        let url_owned = url.to_string();
        let wait_ms = self.network_wait_ms;

        let handle = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let guard = crate::browser_pool::create_browser()?;
            let tab = guard.browser.new_tab()
                .map_err(|e| anyhow::anyhow!("Failed to create tab: {}", e))?;

            // Intercept ALL network responses (not just JSON like trust_center does)
            tab.register_response_handling("web_traffic_discovery",
                Box::new(move |event_params, _fetch_body| {
                    let resp = &event_params.response;
                    let resp_url = &resp.url;
                    // Capture the URL of every network request
                    if let Ok(mut urls) = captured_clone.lock() {
                        urls.push(resp_url.clone());
                    }
                })
            ).map_err(|e| anyhow::anyhow!("Failed to register response handler: {}", e))?;

            // Navigate to page
            tab.navigate_to(&url_owned)
                .map_err(|e| anyhow::anyhow!("Navigation failed: {}", e))?;

            tab.wait_until_navigated()
                .map_err(|e| anyhow::anyhow!("Page load failed: {}", e))?;

            // Wait for runtime JavaScript to make its network calls
            // (self-hosted SDKs like Pendo, DataDog init and phone home during this period)
            std::thread::sleep(Duration::from_millis(wait_ms));

            // Deregister and collect
            let _ = tab.deregister_response_handling("web_traffic_discovery");
            let urls = captured_urls.lock().unwrap().clone();
            Ok(urls)
        });

        let network_urls = handle.await
            .map_err(|e| anyhow::anyhow!("Browser task panicked: {}", e))??;

        debug!("Web traffic: captured {} network requests", network_urls.len());

        let mut results = Vec::new();
        let mut seen_domains = HashSet::new();

        for url_str in &network_urls {
            if let Ok(parsed) = Url::parse(url_str) {
                if let Some(host) = parsed.host_str() {
                    let base_domain = domain_utils::extract_base_domain(host);

                    // Skip self-references and already-seen domains
                    if base_domain == target_base_domain || !seen_domains.insert(base_domain.clone()) {
                        continue;
                    }

                    // Skip common browser/infrastructure noise
                    if is_infrastructure_noise(&base_domain) {
                        continue;
                    }

                    results.push(WebTrafficResult {
                        vendor_domain: base_domain,
                        source: WebTrafficSource::NetworkTraffic,
                        evidence: format!("Runtime network request to {}", url_str),
                    });
                }
            }
        }

        Ok(results)
    }
}

/// Extract external domains from HTML content by parsing resource-loading elements.
fn extract_external_domains_from_html(html: &str, target_base_domain: &str) -> Vec<WebTrafficResult> {
    let mut results = Vec::new();
    let mut seen_domains = HashSet::new();

    let resource_patterns: &[(&Lazy<Regex>, &str)] = &[
        (&SCRIPT_SRC_RE, "script src"),
        (&LINK_HREF_RE, "link href"),
        (&IMG_SRC_RE, "img src"),
        (&IFRAME_SRC_RE, "iframe src"),
        (&DATA_SRC_RE, "data-src"),
        (&INLINE_URL_RE, "inline URL"),
    ];

    for (regex, element_type) in resource_patterns {
        for cap in regex.captures_iter(html) {
            if let Some(url_match) = cap.get(1) {
                let url_str = url_match.as_str();

                // Only process absolute URLs with external domains
                if let Ok(parsed) = Url::parse(url_str) {
                    if let Some(host) = parsed.host_str() {
                        let base_domain = domain_utils::extract_base_domain(host);

                        // Skip self-references, already-seen, and infrastructure noise
                        if base_domain == target_base_domain
                            || !seen_domains.insert(base_domain.clone())
                            || is_infrastructure_noise(&base_domain)
                        {
                            continue;
                        }

                        results.push(WebTrafficResult {
                            vendor_domain: base_domain,
                            source: WebTrafficSource::PageSource,
                            evidence: format!("HTML {} reference: {}", element_type, truncate_url(url_str, 200)),
                        });
                    }
                }
            }
        }
    }

    results
}

/// Check if a domain is generic infrastructure/browser noise that shouldn't be reported
/// as a vendor relationship (e.g., Chrome DevTools, localhost, browser internals).
fn is_infrastructure_noise(domain: &str) -> bool {
    matches!(domain,
        "localhost" | "127.0.0.1" | "0.0.0.0" | "[::1]"
        | "chromium.org" | "gstatic.com" | "googleapis.com"
        // W3C/standards bodies
        | "w3.org" | "schema.org" | "ogp.me"
    )
}

/// Truncate a URL for evidence display (char boundary safe for non-ASCII URLs).
fn truncate_url(url: &str, max_len: usize) -> String {
    if url.len() <= max_len {
        url.to_string()
    } else {
        let mut end = max_len;
        while end > 0 && !url.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &url[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_script_src() {
        let html = r#"<html><head><script src="https://cdn.pendo.io/agent/static/abc.js"></script></head></html>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "pendo.io");
        assert_eq!(results[0].source, WebTrafficSource::PageSource);
    }

    #[test]
    fn test_extract_multiple_resources() {
        let html = r#"
            <script src="https://cdn.segment.io/analytics.js"></script>
            <link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">
            <img src="https://pixel.facebook.com/tr?id=123">
            <iframe src="https://www.youtube.com/embed/abc123"></iframe>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(domains.contains(&"segment.io"), "Should find segment.io");
        // googleapis.com is filtered as infrastructure noise
        assert!(!domains.contains(&"googleapis.com"), "Should filter googleapis.com");
        assert!(domains.contains(&"facebook.com"), "Should find facebook.com");
        assert!(domains.contains(&"youtube.com"), "Should find youtube.com");
    }

    #[test]
    fn test_skip_self_references() {
        let html = r#"<script src="https://cdn.example.com/app.js"></script>
                       <script src="https://api.example.com/v1/init"></script>
                       <script src="https://cdn.pendo.io/agent.js"></script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        // Only pendo.io should be found; example.com subdomains are self-references
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "pendo.io");
    }

    #[test]
    fn test_dedup_same_domain() {
        let html = r#"
            <script src="https://cdn.pendo.io/agent.js"></script>
            <script src="https://cdn.pendo.io/init.js"></script>
            <script src="https://app.pendo.io/data.js"></script>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        // pendo.io appears 3 times but should be deduped to 1
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "pendo.io");
    }

    #[test]
    fn test_inline_url_extraction() {
        let html = r#"<script>
            var config = {
                endpoint: "https://api.amplitude.com/v2/httpapi",
                beacon: "https://rum.datadoghq.com/api/v2"
            };
        </script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(domains.contains(&"amplitude.com"), "Should find amplitude.com in inline JS");
        assert!(domains.contains(&"datadoghq.com"), "Should find datadoghq.com in inline JS");
    }

    #[test]
    fn test_infrastructure_noise_filtered() {
        let html = r#"
            <script src="https://www.w3.org/2000/svg"></script>
            <link href="https://schema.org/Organization" rel="stylesheet">
            <script src="https://cdn.segment.io/analytics.js"></script>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "segment.io");
    }

    #[test]
    fn test_relative_urls_ignored() {
        let html = r#"
            <script src="/js/app.js"></script>
            <script src="./vendor/bundle.js"></script>
            <script src="https://cdn.pendo.io/agent.js"></script>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        // Only the absolute external URL should be captured
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "pendo.io");
    }
}
