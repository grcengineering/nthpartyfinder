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
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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
    Regex::new(r#"<script[^>]+src\s*=\s*["']([^"']+)["']"#)
        .expect("SCRIPT_SRC_RE is a valid compile-time regex literal")
});
static LINK_HREF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<link[^>]+href\s*=\s*["']([^"']+)["']"#)
        .expect("LINK_HREF_RE is a valid compile-time regex literal")
});
static IMG_SRC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<img[^>]+src\s*=\s*["']([^"']+)["']"#)
        .expect("IMG_SRC_RE is a valid compile-time regex literal")
});
static IFRAME_SRC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<iframe[^>]+src\s*=\s*["']([^"']+)["']"#)
        .expect("IFRAME_SRC_RE is a valid compile-time regex literal")
});
// Catch data-src, data-href, and other lazy-loading attributes
static DATA_SRC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"data-(?:src|href)\s*=\s*["'](https?://[^"']+)["']"#)
        .expect("DATA_SRC_RE is a valid compile-time regex literal")
});
// Inline JavaScript URL patterns (e.g., fetch("https://..."), new Image().src = "https://...")
static INLINE_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"["'](https?://[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}[^"']*?)["']"#)
        .expect("INLINE_URL_RE is a valid compile-time regex literal")
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
        let client = crate::http_client::hardened_builder()
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
        self.analyze_domain_url(&url, domain, &target_base_domain)
            .await
    }

    /// Internal: run both analysis phases against a pre-built URL.
    async fn analyze_domain_url(
        &self,
        url: &str,
        domain: &str,
        target_base_domain: &str,
    ) -> Vec<WebTrafficResult> {
        let mut all_results: HashMap<String, WebTrafficResult> = HashMap::new();

        // Phase 1: Static HTML analysis (fast, no browser needed)
        match self.analyze_page_source(url, target_base_domain).await {
            Ok(results) => {
                debug!(
                    "Web traffic: static analysis of {} found {} external domains",
                    domain,
                    results.len()
                );
                for r in results {
                    all_results.entry(r.vendor_domain.clone()).or_insert(r);
                }
            }
            Err(e) => {
                debug!("Web traffic: static analysis failed for {}: {}", domain, e);
            }
        }

        // Phase 2: Runtime network traffic analysis (browser-based, catches self-hosted SDKs)
        match self.analyze_network_traffic(url, target_base_domain).await {
            Ok(results) => {
                debug!(
                    "Web traffic: network analysis of {} found {} external domains",
                    domain,
                    results.len()
                );
                for r in results {
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
    async fn analyze_page_source(
        &self,
        url: &str,
        target_base_domain: &str,
    ) -> Result<Vec<WebTrafficResult>> {
        let response = self.client.get(url).send().await?;
        let html = response.text().await?;
        Ok(extract_external_domains_from_html(
            &html,
            target_base_domain,
        ))
    }

    /// Phase 2: Load page in headless browser and capture all network requests.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn analyze_network_traffic(
        &self,
        url: &str,
        target_base_domain: &str,
    ) -> Result<Vec<WebTrafficResult>> {
        let captured_urls = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured_clone = captured_urls.clone();
        // Network-idle bookkeeping, updated from the browser's event thread. `in_flight`
        // counts requests that have started but not yet finished/failed; `last_activity`
        // is the instant of the most recent request start or completion. The wait loop
        // uses them to release the scarce render permit as soon as the page has genuinely
        // settled instead of always sleeping the full cap. Capture is unchanged (still via
        // register_response_handling on loadingFinished), and we never exit while a request
        // is in flight, so this shortens the idle tail without dropping any captured URL.
        let in_flight = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let in_flight_evt = in_flight.clone();
        let last_activity_evt = last_activity.clone();
        let url_owned = url.to_string();
        let wait_ms = self.network_wait_ms;

        let handle = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            use std::sync::atomic::Ordering;
            // Declared before the guard so tab close and Chrome recycling are measured.
            let mut render_timer = crate::perf::RenderTimer::start()
                .with_source(&crate::perf::METRICS.render_webtraffic);
            let guard = crate::browser_pool::acquire_tab()?;
            render_timer.exclude(guard.permit_wait());
            let tab = guard.tab();

            // Intercept ALL network responses (not just JSON like trust_center does).
            // This is the capture path and also calls Network.enable, so the activity
            // listener registered next receives Network.* events.
            tab.register_response_handling(
                "web_traffic_discovery",
                Box::new(move |event_params, _fetch_body| {
                    // Capture the URL of every network response
                    if let Ok(mut urls) = captured_clone.lock() {
                        urls.push(event_params.response.url.clone());
                    }
                }),
            )
            .map_err(|e| anyhow::anyhow!("Failed to register response handler: {}", e))?;

            // Activity listener: a request start (+1) or a finish/failure (-1) both mark
            // activity, so late-firing beacons keep the page "active" and are still waited
            // out. It only reads the counter/clock — capture stays on the response handler.
            let activity_listener = tab
                .add_event_listener(std::sync::Arc::new(
                    move |event: &headless_chrome::protocol::cdp::types::Event| {
                        use headless_chrome::protocol::cdp::types::Event;
                        match event {
                            Event::NetworkRequestWillBeSent(_) => {
                                in_flight_evt.fetch_add(1, Ordering::SeqCst);
                                if let Ok(mut t) = last_activity_evt.lock() {
                                    *t = Instant::now();
                                }
                            }
                            Event::NetworkLoadingFinished(_) | Event::NetworkLoadingFailed(_) => {
                                in_flight_evt.fetch_sub(1, Ordering::SeqCst);
                                if let Ok(mut t) = last_activity_evt.lock() {
                                    *t = Instant::now();
                                }
                            }
                            _ => {}
                        }
                    },
                ))
                .map_err(|e| anyhow::anyhow!("Failed to add network activity listener: {}", e))?;

            // Navigate to page
            tab.navigate_to(&url_owned)
                .map_err(|e| anyhow::anyhow!("Navigation failed: {}", e))?;

            tab.wait_until_navigated()
                .map_err(|e| anyhow::anyhow!("Page load failed: {}", e))?;

            // Adaptive network-idle wait. Previously a fixed `sleep(wait_ms)`; now `wait_ms`
            // is only the hard cap. Exit as soon as no request is in flight and the network
            // has been quiet for `idle_window`. `stall_window` forces an exit under total
            // silence even if the in-flight counter is left non-zero by redirect chains or
            // WebSockets (which need not emit a matching loadingFinished) — nothing is
            // happening then, so no capture is lost. The hard cap preserves the previous
            // worst-case wait exactly, and because we never exit while a request is pending,
            // recall on any page still doing work is identical to the old fixed wait.
            let hard_cap = Duration::from_millis(wait_ms);
            let idle_window = hard_cap.min(Duration::from_millis(800));
            let stall_window = hard_cap.min(Duration::from_millis(2500));
            let min_wait = hard_cap.min(Duration::from_millis(600));
            let poll = Duration::from_millis(50);
            let started = Instant::now();
            loop {
                std::thread::sleep(poll);
                let elapsed = started.elapsed();
                if elapsed >= hard_cap {
                    break;
                }
                if elapsed < min_wait {
                    continue;
                }
                let quiet = last_activity
                    .lock()
                    .map(|t| t.elapsed())
                    .unwrap_or(Duration::ZERO);
                let pending = in_flight.load(Ordering::SeqCst) > 0;
                if (!pending && quiet >= idle_window) || quiet >= stall_window {
                    break;
                }
            }
            let _ = tab.remove_event_listener(&activity_listener);

            // Deregister and collect. Recover from a poisoned mutex rather than
            // panicking: the guarded Vec<String> is a plain URL accumulator, so
            // its contents stay valid even if a peer thread panicked while holding
            // the lock. A GRC tool must not abort a scan over a poisoned lock.
            let _ = tab.deregister_response_handling("web_traffic_discovery");
            let urls = captured_urls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            Ok(urls)
        });

        let network_urls = handle
            .await
            .map_err(|e| anyhow::anyhow!("Browser task panicked: {}", e))??;

        debug!(
            "Web traffic: captured {} network requests",
            network_urls.len()
        );

        Ok(filter_network_urls(&network_urls, target_base_domain))
    }
}

/// Extract external domains from HTML content by parsing resource-loading elements.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn extract_external_domains_from_html(
    html: &str,
    target_base_domain: &str,
) -> Vec<WebTrafficResult> {
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

                        // Social media domains are only vendor signals when their
                        // SDK/script is loaded, not from simple hyperlinks or embeds
                        if is_social_media_domain(&base_domain)
                            && !is_active_resource_load(element_type)
                        {
                            debug!(
                                "Web traffic: skipping social media link {} (element: {})",
                                base_domain, element_type
                            );
                            continue;
                        }

                        results.push(WebTrafficResult {
                            vendor_domain: base_domain,
                            source: WebTrafficSource::PageSource,
                            evidence: format!(
                                "HTML {} reference: {}",
                                element_type,
                                truncate_url(url_str, 200)
                            ),
                        });
                    }
                }
            }
        }
    }

    results
}

/// Filter raw network URLs into vendor results, deduplicating, skipping self-references
/// and infrastructure noise.
pub fn filter_network_urls(
    network_urls: &[String],
    target_base_domain: &str,
) -> Vec<WebTrafficResult> {
    let mut results = Vec::new();
    let mut seen_domains = HashSet::new();

    for url_str in network_urls {
        if let Ok(parsed) = Url::parse(url_str) {
            if let Some(host) = parsed.host_str() {
                let base_domain = domain_utils::extract_base_domain(host);

                if base_domain == target_base_domain || !seen_domains.insert(base_domain.clone()) {
                    continue;
                }

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

    results
}

/// Check if a domain is generic infrastructure/browser noise that shouldn't be reported
/// as a vendor relationship (e.g., Chrome DevTools, localhost, browser internals).
fn is_infrastructure_noise(domain: &str) -> bool {
    // An IP address is not a vendor. A page fetching `https://44.238.122.172/...` is talking to a
    // host with no organization behind it — and the address used to be chopped into "122.172" by
    // the base-domain extractor, which is not merely a junk row: "122.172" is inet_aton shorthand
    // for 122.0.0.172, so the scanner would then aim DNS and a real browser at an arbitrary,
    // unrelated live host. Whole or fragmented, an IP must never become a vendor.
    if is_ip_host(domain) {
        return true;
    }

    matches!(
        domain,
        "localhost" | "127.0.0.1" | "0.0.0.0" | "[::1]"
        | "chromium.org" | "gstatic.com" | "googleapis.com"
        // W3C/standards bodies
        | "w3.org" | "schema.org" | "ogp.me"
    )
}

/// An IP literal (bracketed or bare), or the numeric fragment of one — never a hostname.
fn is_ip_host(host: &str) -> bool {
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    if unbracketed.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !unbracketed.is_empty()
        && unbracketed
            .split('.')
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
}

/// Check if a domain is a social media platform. Social media domains should only be
/// treated as vendor relationships when their SDK/scripts are actively loaded (e.g.,
/// `<script src="https://connect.facebook.net/sdk.js">`), NOT when they appear as
/// simple hyperlinks (e.g., `<a href="https://facebook.com/company">`).
fn is_social_media_domain(domain: &str) -> bool {
    matches!(
        domain,
        "facebook.com"
            | "facebook.net"
            | "linkedin.com"
            | "twitter.com"
            | "x.com"
            | "youtube.com"
            | "instagram.com"
            | "tiktok.com"
            | "pinterest.com"
            | "reddit.com"
            | "threads.net"
            | "mastodon.social"
            | "discord.com"
            | "discord.gg"
    )
}

/// Whether the given HTML element type represents an active resource load (script/SDK)
/// vs. a passive reference (hyperlink, meta tag).
fn is_active_resource_load(element_type: &str) -> bool {
    matches!(element_type, "script src" | "img src")
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
        assert!(
            !domains.contains(&"googleapis.com"),
            "Should filter googleapis.com"
        );
        // facebook.com from <img> (tracking pixel) IS a vendor signal
        assert!(
            domains.contains(&"facebook.com"),
            "Should find facebook.com tracking pixel"
        );
        // youtube.com from <iframe> (embed) is NOT a vendor signal — social media filter
        assert!(
            !domains.contains(&"youtube.com"),
            "Should filter youtube.com iframe embed"
        );
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
        assert!(
            domains.contains(&"amplitude.com"),
            "Should find amplitude.com in inline JS"
        );
        assert!(
            domains.contains(&"datadoghq.com"),
            "Should find datadoghq.com in inline JS"
        );
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
    fn test_social_media_links_filtered() {
        // Simple hyperlinks to social media profiles should NOT be vendor relationships
        let html = r#"
            <a href="https://www.facebook.com/ourcompany">Follow us on Facebook</a>
            <a href="https://twitter.com/ourcompany">Follow us on Twitter</a>
            <a href="https://www.linkedin.com/company/ourcompany">LinkedIn</a>
            <a href="https://www.youtube.com/c/ourcompany">YouTube</a>
            <a href="https://www.instagram.com/ourcompany">Instagram</a>
            <script src="https://cdn.segment.io/analytics.js"></script>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        // Social media profile links should be filtered
        assert!(
            !domains.contains(&"facebook.com"),
            "Should filter facebook.com profile link"
        );
        assert!(
            !domains.contains(&"twitter.com"),
            "Should filter twitter.com profile link"
        );
        assert!(
            !domains.contains(&"linkedin.com"),
            "Should filter linkedin.com profile link"
        );
        assert!(
            !domains.contains(&"youtube.com"),
            "Should filter youtube.com profile link"
        );
        assert!(
            !domains.contains(&"instagram.com"),
            "Should filter instagram.com profile link"
        );
        // Real vendor SDKs should still be found
        assert!(
            domains.contains(&"segment.io"),
            "Should find segment.io SDK"
        );
    }

    #[test]
    fn test_social_media_sdk_not_filtered() {
        // Social media SDKs loaded via <script> ARE vendor relationships
        let html = r#"
            <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
            <img src="https://pixel.facebook.com/tr?id=123456">
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        // Facebook SDK via script = vendor signal
        assert!(
            domains.contains(&"facebook.net"),
            "Should find facebook.net SDK script"
        );
        // Facebook tracking pixel via img = vendor signal
        assert!(
            domains.contains(&"facebook.com"),
            "Should find facebook.com tracking pixel"
        );
    }

    #[test]
    fn test_discord_links_filtered() {
        let html = r#"
            <a href="https://discord.com/invite/ourserver">Join Discord</a>
            <a href="https://discord.gg/abc123">Discord</a>
            <script src="https://cdn.segment.io/analytics.js"></script>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(
            !domains.contains(&"discord.com"),
            "Should filter discord.com profile link"
        );
        assert!(
            !domains.contains(&"discord.gg"),
            "Should filter discord.gg invite link"
        );
        assert!(
            domains.contains(&"segment.io"),
            "Should still find real vendor SDKs"
        );
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

    // ───────────────────────────────────────────────────────────────
    // Additional coverage tests below
    // ───────────────────────────────────────────────────────────────

    use rstest::rstest;

    // --- WebTrafficDiscovery construction ---

    #[test]
    fn test_web_traffic_discovery_new() {
        let disc = WebTrafficDiscovery::new(30);
        assert_eq!(disc.timeout, Duration::from_secs(30));
        assert_eq!(disc.network_wait_ms, 5000);
    }

    #[test]
    fn test_web_traffic_discovery_new_short_timeout() {
        let disc = WebTrafficDiscovery::new(1);
        assert_eq!(disc.timeout, Duration::from_secs(1));
    }

    // --- WebTrafficResult / WebTrafficSource ---

    #[test]
    fn test_web_traffic_result_clone_and_debug() {
        let result = WebTrafficResult {
            vendor_domain: "pendo.io".to_string(),
            source: WebTrafficSource::PageSource,
            evidence: "HTML script src reference: https://cdn.pendo.io/agent.js".to_string(),
        };
        let cloned = result.clone();
        assert_eq!(cloned.vendor_domain, "pendo.io");
        assert_eq!(cloned.source, WebTrafficSource::PageSource);
        let debug = format!("{:?}", result);
        assert!(debug.contains("pendo.io"));
    }

    #[test]
    fn test_web_traffic_source_equality() {
        assert_eq!(WebTrafficSource::PageSource, WebTrafficSource::PageSource);
        assert_eq!(
            WebTrafficSource::NetworkTraffic,
            WebTrafficSource::NetworkTraffic
        );
        assert_ne!(
            WebTrafficSource::PageSource,
            WebTrafficSource::NetworkTraffic
        );
    }

    #[test]
    fn test_web_traffic_source_debug() {
        let s = format!("{:?}", WebTrafficSource::NetworkTraffic);
        assert!(s.contains("NetworkTraffic"));
    }

    // --- truncate_url ---

    #[test]
    fn test_truncate_url_short() {
        let url = "https://example.com";
        assert_eq!(truncate_url(url, 200), url);
    }

    #[test]
    fn test_truncate_url_exact_limit() {
        let url = "x".repeat(200);
        assert_eq!(truncate_url(&url, 200), url);
    }

    #[test]
    fn test_truncate_url_over_limit() {
        let url = "x".repeat(300);
        let result = truncate_url(&url, 200);
        assert_eq!(result.len(), 203); // 200 chars + "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_url_non_ascii() {
        // Test char boundary safety with multi-byte characters
        let url = "https://example.com/data/日本語テスト";
        let result = truncate_url(url, 30);
        assert!(result.ends_with("..."));
        // Must not panic — the point is char boundary safety
    }

    #[test]
    fn test_truncate_url_empty() {
        assert_eq!(truncate_url("", 100), "");
    }

    #[test]
    fn test_truncate_url_single_char() {
        assert_eq!(truncate_url("x", 100), "x");
    }

    // --- is_infrastructure_noise ---

    #[rstest]
    #[case("localhost", true)]
    #[case("127.0.0.1", true)]
    #[case("0.0.0.0", true)]
    #[case("[::1]", true)]
    #[case("chromium.org", true)]
    #[case("gstatic.com", true)]
    #[case("googleapis.com", true)]
    #[case("w3.org", true)]
    #[case("schema.org", true)]
    #[case("ogp.me", true)]
    // NOT noise
    #[case("pendo.io", false)]
    #[case("segment.io", false)]
    #[case("stripe.com", false)]
    #[case("google.com", false)]
    #[case("example.com", false)] // example.com is not infrastructure noise (different from CT logs)
    fn test_is_infrastructure_noise_parametrized(#[case] domain: &str, #[case] expected: bool) {
        assert_eq!(
            is_infrastructure_noise(domain),
            expected,
            "Domain '{}' should be noise={}",
            domain,
            expected
        );
    }

    // --- is_social_media_domain ---

    #[rstest]
    #[case("facebook.com", true)]
    #[case("facebook.net", true)]
    #[case("linkedin.com", true)]
    #[case("twitter.com", true)]
    #[case("x.com", true)]
    #[case("youtube.com", true)]
    #[case("instagram.com", true)]
    #[case("tiktok.com", true)]
    #[case("pinterest.com", true)]
    #[case("reddit.com", true)]
    #[case("threads.net", true)]
    #[case("mastodon.social", true)]
    #[case("discord.com", true)]
    #[case("discord.gg", true)]
    // NOT social media
    #[case("pendo.io", false)]
    #[case("stripe.com", false)]
    #[case("facebooks.com", false)] // typo/lookalike should not match
    #[case("mylinkedin.com", false)]
    fn test_is_social_media_domain_parametrized(#[case] domain: &str, #[case] expected: bool) {
        assert_eq!(
            is_social_media_domain(domain),
            expected,
            "Domain '{}' should be social={}",
            domain,
            expected
        );
    }

    // --- is_active_resource_load ---

    #[rstest]
    #[case("script src", true)]
    #[case("img src", true)]
    #[case("link href", false)]
    #[case("iframe src", false)]
    #[case("data-src", false)]
    #[case("inline URL", false)]
    fn test_is_active_resource_load_parametrized(
        #[case] element_type: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            is_active_resource_load(element_type),
            expected,
            "Element type '{}' should be active={}",
            element_type,
            expected
        );
    }

    // --- extract_external_domains_from_html edge cases ---

    #[test]
    fn test_extract_empty_html() {
        let results = extract_external_domains_from_html("", "example.com");
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_html_no_external_resources() {
        let html = r#"<html><head><title>Test</title></head><body><p>Hello</p></body></html>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_data_src_attribute() {
        let html = r#"<div data-src="https://cdn.launchdarkly.com/sdk.js"></div>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(
            domains.contains(&"launchdarkly.com"),
            "Should find launchdarkly.com from data-src, got: {:?}",
            domains
        );
    }

    #[test]
    fn test_extract_data_href_attribute() {
        let html = r#"<div data-href="https://api.intercom.io/widget"></div>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(
            domains.contains(&"intercom.io"),
            "Should find intercom.io from data-href, got: {:?}",
            domains
        );
    }

    #[test]
    fn test_extract_iframe_src() {
        let html =
            r#"<iframe src="https://app.hubspot.com/embed/form/12345" width="100%"></iframe>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "hubspot.com");
        assert_eq!(results[0].source, WebTrafficSource::PageSource);
    }

    #[test]
    fn test_extract_link_href() {
        let html = r#"<link href="https://cdn.jsdelivr.net/npm/bootstrap@5/dist/css/bootstrap.min.css" rel="stylesheet">"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "jsdelivr.net");
    }

    #[test]
    fn test_extract_img_src() {
        let html = r#"<img src="https://pixel.quantserve.com/pixel/123.gif" width="1" height="1">"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "quantserve.com");
    }

    #[test]
    fn test_social_media_script_passes_but_iframe_blocked() {
        // Twitter script SDK (active load) — should pass
        // Twitter iframe embed — social media from iframe should be blocked
        let html = r#"
            <script src="https://platform.twitter.com/widgets.js"></script>
            <iframe src="https://twitter.com/user/status/12345"></iframe>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        // twitter.com from script src — is_active_resource_load("script src") = true
        assert!(
            domains.contains(&"twitter.com"),
            "Should find twitter.com SDK from script src, got: {:?}",
            domains
        );
        // The dedup means twitter.com only appears once (from the script, which is processed first)
        assert_eq!(domains.iter().filter(|&&d| d == "twitter.com").count(), 1);
    }

    #[test]
    fn test_inline_url_in_json_config() {
        let html = r#"<script>
            window.analytics_config = {
                "api_host": "https://api.mixpanel.com",
                "proxy": "https://events.customer.io/v1/track"
            };
        </script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(
            domains.contains(&"mixpanel.com"),
            "Should find mixpanel.com, got: {:?}",
            domains
        );
        assert!(
            domains.contains(&"customer.io"),
            "Should find customer.io, got: {:?}",
            domains
        );
    }

    #[test]
    fn test_inline_url_with_single_quotes() {
        let html = r#"<script>
            var url = 'https://api.clearbit.com/v1/identify';
        </script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(
            domains.contains(&"clearbit.com"),
            "Should find clearbit.com from single-quoted inline URL, got: {:?}",
            domains
        );
    }

    #[test]
    fn test_mixed_case_urls() {
        let html = r#"<script src="HTTPS://CDN.PENDO.IO/Agent.JS"></script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        // SCRIPT_SRC_RE captures the URL regardless of case; Url::parse is case-insensitive
        // for the scheme. The inline URL regex also matches. Either path finds pendo.io.
        assert!(
            !results.is_empty(),
            "Uppercase URLs should still be matched by at least the inline URL regex"
        );
        assert_eq!(results[0].vendor_domain, "pendo.io");
    }

    #[test]
    fn test_evidence_format_page_source() {
        let html = r#"<script src="https://cdn.segment.io/analytics.js"></script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 1);
        assert!(results[0].evidence.contains("script src"));
        assert!(results[0].evidence.contains("segment.io"));
    }

    #[test]
    fn test_evidence_format_inline_url() {
        let html = r#"<script>fetch("https://api.amplitude.com/2/httpapi")</script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        let amp = results.iter().find(|r| r.vendor_domain == "amplitude.com");
        assert!(amp.is_some(), "Should find amplitude.com");
        assert!(amp.unwrap().evidence.contains("inline URL"));
    }

    #[test]
    fn test_multiple_resource_types_same_domain() {
        // Same vendor from script AND img — should be deduped
        let html = r#"
            <script src="https://cdn.newrelic.com/nr.js"></script>
            <img src="https://bam.nr-data.net/pixel.gif">
            <link href="https://cdn.newrelic.com/style.css" rel="stylesheet">
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let nr_count = results
            .iter()
            .filter(|r| r.vendor_domain == "newrelic.com")
            .count();
        assert_eq!(nr_count, 1, "newrelic.com should appear exactly once");
    }

    #[test]
    fn test_protocol_relative_urls_not_matched() {
        // Protocol-relative URLs (//cdn.example.com/...) won't be parsed by Url::parse
        // because the regex patterns require absolute URLs starting with http(s)://.
        let html = r#"<script src="//cdn.vendor.com/sdk.js"></script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(
            results.len(),
            0,
            "Protocol-relative URLs should not be captured"
        );
    }

    #[test]
    fn test_malformed_url_in_src_ignored() {
        let html = r#"<script src="not-a-valid-url"></script>
                       <script src="https://cdn.pendo.io/agent.js"></script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        // Only valid URL should be captured
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "pendo.io");
    }

    #[test]
    fn test_url_with_long_path_truncated_in_evidence() {
        let long_path = "x".repeat(300);
        let html = format!(
            r#"<script src="https://cdn.vendor.com/{}"></script>"#,
            long_path
        );
        let results = extract_external_domains_from_html(&html, "example.com");
        assert_eq!(results.len(), 1);
        // Evidence should be truncated
        assert!(results[0].evidence.len() < 500);
    }

    #[test]
    fn test_social_media_in_link_href_filtered() {
        // Social media in <link> tag (like canonical links) should be filtered
        let html = r#"
            <link href="https://www.facebook.com/ourpage" rel="canonical">
            <link href="https://www.linkedin.com/company/us" rel="alternate">
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        // link href is not an active resource load, so social media should be filtered
        assert_eq!(
            results.len(),
            0,
            "Social media link hrefs should be fully filtered"
        );
    }

    #[test]
    fn test_non_social_media_in_link_href_kept() {
        let html = r#"<link href="https://fonts.gstatic.com/font.woff2" rel="preload" as="font">"#;
        let results = extract_external_domains_from_html(html, "example.com");
        // gstatic.com is infrastructure noise, so filtered
        assert!(results.is_empty());
    }

    #[test]
    fn test_data_src_with_relative_url_ignored() {
        // data-src with relative URL (no http/https) should not match the data-src regex
        let html = r#"<img data-src="/images/logo.png" data-href="./page.html">"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert!(results.is_empty());
    }

    #[test]
    fn test_complex_real_world_page() {
        let html = r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Test Page</title>
                <link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">
                <link href="https://cdn.jsdelivr.net/npm/bootstrap.css" rel="stylesheet">
                <script src="https://cdn.segment.io/analytics.js/v1/abc/analytics.min.js"></script>
                <script src="https://js.stripe.com/v3/"></script>
            </head>
            <body>
                <img src="https://pixel.facebook.com/tr?id=123" width="1" height="1">
                <iframe src="https://www.youtube.com/embed/abc123"></iframe>
                <a href="https://twitter.com/company">Twitter</a>
                <a href="https://www.linkedin.com/company/test">LinkedIn</a>
                <script>
                    window.intercomSettings = {
                        app_id: "abc123",
                        api_base: "https://api-iam.intercom.io"
                    };
                    !function(){var w="https://widget.intercom.io/widget/abc123";}();
                </script>
                <div data-src="https://cdn.cookiebot.com/consent.js"></div>
            </body>
            </html>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();

        // Should find real vendors
        assert!(
            domains.contains(&"segment.io"),
            "Missing segment.io, got: {:?}",
            domains
        );
        assert!(
            domains.contains(&"stripe.com"),
            "Missing stripe.com, got: {:?}",
            domains
        );
        assert!(
            domains.contains(&"facebook.com"),
            "Missing facebook.com (tracking pixel), got: {:?}",
            domains
        );
        assert!(
            domains.contains(&"intercom.io"),
            "Missing intercom.io, got: {:?}",
            domains
        );
        assert!(
            domains.contains(&"jsdelivr.net"),
            "Missing jsdelivr.net, got: {:?}",
            domains
        );
        assert!(
            domains.contains(&"cookiebot.com"),
            "Missing cookiebot.com, got: {:?}",
            domains
        );

        // Should filter infrastructure noise
        assert!(
            !domains.contains(&"googleapis.com"),
            "Should filter googleapis.com"
        );

        // Should filter social media links (non-active)
        assert!(
            !domains.contains(&"youtube.com"),
            "Should filter youtube.com iframe"
        );
        assert!(
            !domains.contains(&"linkedin.com"),
            "Should filter linkedin.com link"
        );
        // twitter.com from <a> tag is inline URL — depends on regex
    }

    // --- Regex pattern tests ---

    #[test]
    fn test_script_src_regex() {
        let html = r#"<script type="text/javascript" src="https://cdn.example.com/app.js" async></script>"#;
        let caps: Vec<_> = SCRIPT_SRC_RE.captures_iter(html).collect();
        assert_eq!(caps.len(), 1);
        assert_eq!(
            caps[0].get(1).unwrap().as_str(),
            "https://cdn.example.com/app.js"
        );
    }

    #[test]
    fn test_script_src_regex_single_quotes() {
        let html = r#"<script src='https://cdn.example.com/app.js'></script>"#;
        let caps: Vec<_> = SCRIPT_SRC_RE.captures_iter(html).collect();
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn test_link_href_regex() {
        let html =
            r#"<link rel="stylesheet" href="https://fonts.example.com/font.css" type="text/css">"#;
        let caps: Vec<_> = LINK_HREF_RE.captures_iter(html).collect();
        assert_eq!(caps.len(), 1);
        assert_eq!(
            caps[0].get(1).unwrap().as_str(),
            "https://fonts.example.com/font.css"
        );
    }

    #[test]
    fn test_img_src_regex() {
        let html = r#"<img src="https://pixel.example.com/track.gif" width="1" height="1">"#;
        let caps: Vec<_> = IMG_SRC_RE.captures_iter(html).collect();
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn test_iframe_src_regex() {
        let html = r#"<iframe src="https://embed.example.com/widget" frameborder="0"></iframe>"#;
        let caps: Vec<_> = IFRAME_SRC_RE.captures_iter(html).collect();
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn test_data_src_regex() {
        let html = r#"<div data-src="https://cdn.example.com/lazy.js" class="lazy"></div>"#;
        let caps: Vec<_> = DATA_SRC_RE.captures_iter(html).collect();
        assert_eq!(caps.len(), 1);
        assert_eq!(
            caps[0].get(1).unwrap().as_str(),
            "https://cdn.example.com/lazy.js"
        );
    }

    #[test]
    fn test_data_href_regex() {
        let html = r#"<a data-href="https://api.vendor.com/track" class="track"></a>"#;
        let caps: Vec<_> = DATA_SRC_RE.captures_iter(html).collect();
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn test_inline_url_regex_double_quotes() {
        let html = r#"var endpoint = "https://api.segment.io/v1/track";"#;
        let caps: Vec<_> = INLINE_URL_RE.captures_iter(html).collect();
        assert_eq!(caps.len(), 1);
        assert_eq!(
            caps[0].get(1).unwrap().as_str(),
            "https://api.segment.io/v1/track"
        );
    }

    #[test]
    fn test_inline_url_regex_single_quotes() {
        let html = r#"var endpoint = 'https://api.segment.io/v1/track';"#;
        let caps: Vec<_> = INLINE_URL_RE.captures_iter(html).collect();
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn test_inline_url_regex_http() {
        let html = r#"var endpoint = "http://api.oldvendor.com/v1";"#;
        let caps: Vec<_> = INLINE_URL_RE.captures_iter(html).collect();
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn test_no_match_non_http_url() {
        let html = r#"var endpoint = "ftp://files.example.com/data";"#;
        let caps: Vec<_> = INLINE_URL_RE.captures_iter(html).collect();
        assert_eq!(caps.len(), 0);
    }

    // ───────────────────────────────────────────────────────────────
    // analyze_page_source with wiremock
    // ───────────────────────────────────────────────────────────────

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_analyze_page_source_with_mock_server() {
        let mock_server = MockServer::start().await;

        let html_body = r#"<html><head>
            <script src="https://cdn.segment.io/analytics.js"></script>
            <script src="https://cdn.pendo.io/agent.js"></script>
        </head><body><p>Hello</p></body></html>"#;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html_body))
            .mount(&mock_server)
            .await;

        let disc = WebTrafficDiscovery::new(10);
        let result = disc
            .analyze_page_source(&mock_server.uri(), "example.com")
            .await;
        assert!(result.is_ok());
        let results = result.unwrap();
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(domains.contains(&"segment.io"));
        assert!(domains.contains(&"pendo.io"));
    }

    #[tokio::test]
    async fn test_analyze_page_source_http_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string("error"))
            .mount(&mock_server)
            .await;

        let disc = WebTrafficDiscovery::new(10);
        let result = disc
            .analyze_page_source(&mock_server.uri(), "example.com")
            .await;
        // Should return an error for non-success status since reqwest doesn't error on 5xx by default
        // Actually reqwest returns Ok for any HTTP response, so we'd get an Ok with the error body parsed
        assert!(result.is_ok());
        let results = result.unwrap();
        // Error page body won't have vendor references
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_page_source_connection_refused() {
        let disc = WebTrafficDiscovery::new(2);
        // Port that's not listening
        let result = disc
            .analyze_page_source("http://127.0.0.1:1", "example.com")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_analyze_page_source_empty_html() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&mock_server)
            .await;

        let disc = WebTrafficDiscovery::new(10);
        let result = disc
            .analyze_page_source(&mock_server.uri(), "example.com")
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // ───────────────────────────────────────────────────────────────
    // analyze_domain with wiremock (page source only, browser path skipped)
    // ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_analyze_domain_static_only() {
        // analyze_domain tries both static and browser analysis
        // Browser analysis will fail in test env (no Chrome), but static should work
        let mock_server = MockServer::start().await;

        let html_body = r#"<html><head>
            <script src="https://cdn.segment.io/analytics.js"></script>
        </head><body></body></html>"#;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html_body))
            .mount(&mock_server)
            .await;

        // We can't easily use analyze_domain because it constructs its own URL from domain
        // Instead we test the static extraction function directly with more patterns
        let results = extract_external_domains_from_html(html_body, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "segment.io");
    }

    // ───────────────────────────────────────────────────────────────
    // truncate_url edge cases
    // ───────────────────────────────────────────────────────────────

    #[test]
    fn test_truncate_url_zero_limit() {
        let result = truncate_url("abc", 0);
        assert_eq!(result, "...");
    }

    #[test]
    fn test_truncate_url_limit_one() {
        let result = truncate_url("abc", 1);
        assert_eq!(result, "a...");
    }

    #[test]
    fn test_truncate_url_multi_byte_boundary() {
        // 3-byte UTF-8 char, truncate in the middle
        let url = "\u{1F600}rest"; // emoji (4 bytes) + "rest"
        let result = truncate_url(url, 2);
        // Should back up to a char boundary (position 0)
        assert!(result.ends_with("..."));
    }

    // ───────────────────────────────────────────────────────────────
    // HTML extraction additional edge cases
    // ───────────────────────────────────────────────────────────────

    #[test]
    fn test_extract_html_only_self_references() {
        let html = r#"
            <script src="https://cdn.example.com/app.js"></script>
            <link href="https://static.example.com/style.css" rel="stylesheet">
            <img src="https://images.example.com/logo.png">
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_html_tiktok_pinterest_reddit() {
        // More social media domains that should be filtered from non-active loads
        let html = r#"
            <a href="https://www.tiktok.com/@company">TikTok</a>
            <a href="https://www.pinterest.com/company">Pinterest</a>
            <a href="https://www.reddit.com/r/company">Reddit</a>
            <a href="https://threads.net/@company">Threads</a>
            <a href="https://mastodon.social/@company">Mastodon</a>
            <script src="https://cdn.segment.io/analytics.js"></script>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(!domains.contains(&"tiktok.com"));
        assert!(!domains.contains(&"pinterest.com"));
        assert!(!domains.contains(&"reddit.com"));
        assert!(!domains.contains(&"threads.net"));
        assert!(!domains.contains(&"mastodon.social"));
        assert!(domains.contains(&"segment.io"));
    }

    #[test]
    fn test_extract_html_x_com_filtered() {
        let html = r#"
            <a href="https://x.com/company">Follow us</a>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(
            results.len(),
            0,
            "x.com social media link should be filtered"
        );
    }

    #[test]
    fn test_extract_ogp_me_filtered() {
        let html = r#"<link href="https://ogp.me/ns#" rel="stylesheet"><script src="https://cdn.vendor.com/sdk.js"></script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(!domains.contains(&"ogp.me"));
        assert!(domains.contains(&"vendor.com"));
    }

    #[test]
    fn test_extract_multiple_inline_urls_same_domain_deduped() {
        let html = r#"<script>
            var a = "https://api.vendor.com/v1";
            var b = "https://api.vendor.com/v2";
            var c = "https://cdn.vendor.com/sdk.js";
        </script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        let vendor_count = results
            .iter()
            .filter(|r| r.vendor_domain == "vendor.com")
            .count();
        assert_eq!(vendor_count, 1, "vendor.com should be deduped to 1");
    }

    #[test]
    fn test_web_traffic_result_network_traffic_source() {
        let result = WebTrafficResult {
            vendor_domain: "pendo.io".to_string(),
            source: WebTrafficSource::NetworkTraffic,
            evidence: "Runtime network request to https://app.pendo.io/init".to_string(),
        };
        assert_eq!(result.source, WebTrafficSource::NetworkTraffic);
        assert!(result.evidence.contains("Runtime"));
    }

    // ───────────────────────────────────────────────────────────────
    // Additional coverage tests — round 2
    // ───────────────────────────────────────────────────────────────

    #[test]
    fn test_web_traffic_source_clone() {
        let src = WebTrafficSource::PageSource;
        let cloned = src.clone();
        assert_eq!(cloned, WebTrafficSource::PageSource);

        let src2 = WebTrafficSource::NetworkTraffic;
        let cloned2 = src2.clone();
        assert_eq!(cloned2, WebTrafficSource::NetworkTraffic);
    }

    #[test]
    fn test_web_traffic_result_all_fields() {
        let result = WebTrafficResult {
            vendor_domain: "segment.io".to_string(),
            source: WebTrafficSource::PageSource,
            evidence: "HTML script src reference: https://cdn.segment.io/analytics.js".to_string(),
        };
        assert_eq!(result.vendor_domain, "segment.io");
        assert_eq!(result.source, WebTrafficSource::PageSource);
        assert!(result.evidence.starts_with("HTML"));
        // Test Debug
        let dbg = format!("{:?}", result);
        assert!(dbg.contains("segment.io"));
        assert!(dbg.contains("PageSource"));
    }

    #[test]
    fn test_extract_html_with_all_six_regex_patterns() {
        // Ensure all 6 regex patterns are exercised in one HTML document
        let html = r#"
            <script src="https://cdn.vendor1.com/script.js"></script>
            <link href="https://cdn.vendor2.com/style.css" rel="stylesheet">
            <img src="https://pixel.vendor3.com/track.gif">
            <iframe src="https://embed.vendor4.com/widget"></iframe>
            <div data-src="https://cdn.vendor5.com/lazy.js"></div>
            <script>var x = "https://api.vendor6.com/init";</script>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(
            domains.contains(&"vendor1.com"),
            "Missing vendor1.com (script src)"
        );
        assert!(
            domains.contains(&"vendor2.com"),
            "Missing vendor2.com (link href)"
        );
        assert!(
            domains.contains(&"vendor3.com"),
            "Missing vendor3.com (img src)"
        );
        assert!(
            domains.contains(&"vendor4.com"),
            "Missing vendor4.com (iframe src)"
        );
        assert!(
            domains.contains(&"vendor5.com"),
            "Missing vendor5.com (data-src)"
        );
        assert!(
            domains.contains(&"vendor6.com"),
            "Missing vendor6.com (inline URL)"
        );
    }

    #[test]
    fn test_extract_html_infrastructure_noise_all_domains() {
        // Test that all infrastructure noise domains are actually filtered
        // Note: [::1] is not included because it's not a valid URL host in HTML attributes
        let html = r#"
            <script src="https://localhost/app.js"></script>
            <script src="https://127.0.0.1/app.js"></script>
            <script src="https://0.0.0.0/app.js"></script>
            <script src="https://chromium.org/app.js"></script>
            <script src="https://gstatic.com/app.js"></script>
            <script src="https://googleapis.com/app.js"></script>
            <script src="https://w3.org/app.js"></script>
            <script src="https://schema.org/app.js"></script>
            <script src="https://ogp.me/app.js"></script>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        // localhost, 127.0.0.1, and 0.0.0.0 won't have a base domain that passes Url::parse host check
        // The others are filtered by is_infrastructure_noise
        let non_infra: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        for domain in &non_infra {
            assert!(
                !is_infrastructure_noise(domain),
                "Domain '{}' should have been filtered as infrastructure noise",
                domain
            );
        }
    }

    #[test]
    fn test_extract_html_social_media_script_src_passes() {
        // Social media domains loaded via <script src> should be kept
        let html = r#"
            <script src="https://platform.linkedin.com/badges/js/profile.js"></script>
            <script src="https://connect.facebook.net/en_US/sdk.js"></script>
            <script src="https://platform.twitter.com/widgets.js"></script>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(
            domains.contains(&"linkedin.com"),
            "LinkedIn SDK script should pass"
        );
        assert!(
            domains.contains(&"facebook.net"),
            "Facebook SDK script should pass"
        );
        assert!(
            domains.contains(&"twitter.com"),
            "Twitter SDK script should pass"
        );
    }

    #[test]
    fn test_extract_html_social_media_img_src_passes() {
        // Social media domains loaded via <img src> (tracking pixels) should be kept
        let html = r#"
            <img src="https://pixel.facebook.com/tr?id=123" width="1" height="1">
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(
            domains.contains(&"facebook.com"),
            "Facebook tracking pixel should pass"
        );
    }

    #[test]
    fn test_extract_html_social_media_data_src_blocked() {
        // Social media in data-src (not active load) should be filtered
        let html = r#"
            <div data-src="https://www.instagram.com/embed/123"></div>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 0, "Instagram data-src should be filtered");
    }

    #[test]
    fn test_extract_html_social_media_inline_url_blocked() {
        // Social media in inline JS URLs (not active load) should be filtered
        let html = r#"<script>var share = "https://www.tiktok.com/@company";</script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 0, "TikTok inline URL should be filtered");
    }

    #[test]
    fn test_truncate_url_exactly_at_char_boundary() {
        // ASCII-only URL at exact boundary
        let url = "abcde";
        assert_eq!(truncate_url(url, 3), "abc...");
        assert_eq!(truncate_url(url, 5), "abcde"); // exact length, no truncation
    }

    #[test]
    fn test_truncate_url_two_byte_utf8() {
        // 2-byte UTF-8 chars (e.g., accented letters)
        let url = "\u{00E9}\u{00E9}\u{00E9}rest"; // e-acute (2 bytes each) + "rest"
        let result = truncate_url(url, 3);
        // Position 3 is in the middle of the 2nd 2-byte char; should back up
        assert!(result.ends_with("..."));
    }

    #[tokio::test]
    async fn test_analyze_page_source_with_mixed_content() {
        let mock_server = MockServer::start().await;

        let html_body = r#"<html>
            <head>
                <script src="https://cdn.segment.io/analytics.js"></script>
                <script src="/local/app.js"></script>
                <link href="https://fonts.googleapis.com/css" rel="stylesheet">
            </head>
            <body>
                <img src="https://pixel.facebook.com/tr?id=1">
                <script>var x = "https://api.amplitude.com/v2";</script>
            </body>
        </html>"#;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html_body))
            .mount(&mock_server)
            .await;

        let disc = WebTrafficDiscovery::new(10);
        let result = disc
            .analyze_page_source(&mock_server.uri(), "example.com")
            .await;
        assert!(result.is_ok());
        let results = result.unwrap();
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(domains.contains(&"segment.io"));
        assert!(domains.contains(&"facebook.com"));
        assert!(domains.contains(&"amplitude.com"));
        // googleapis.com is infrastructure noise
        assert!(!domains.contains(&"googleapis.com"));
    }

    #[tokio::test]
    async fn test_analyze_page_source_large_html() {
        let mock_server = MockServer::start().await;

        // Large HTML with many vendor references
        let html_body = format!(
            r#"<html><head>
            <script src="https://cdn.vendor-a.com/sdk.js"></script>
            <script src="https://cdn.vendor-b.com/sdk.js"></script>
            <script src="https://cdn.vendor-c.com/sdk.js"></script>
            {}</head></html>"#,
            "<!-- padding -->".repeat(1000)
        );

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&html_body))
            .mount(&mock_server)
            .await;

        let disc = WebTrafficDiscovery::new(10);
        let result = disc
            .analyze_page_source(&mock_server.uri(), "example.com")
            .await;
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_extract_html_url_with_query_params() {
        let html = r#"<script src="https://cdn.vendor.com/sdk.js?v=2&key=abc"></script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "vendor.com");
    }

    #[test]
    fn test_extract_html_url_with_fragment() {
        let html = r#"<link href="https://cdn.vendor.com/style.css#section" rel="stylesheet">"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "vendor.com");
    }

    #[test]
    fn test_extract_html_url_with_port() {
        let html = r#"<script src="https://cdn.vendor.com:8443/sdk.js"></script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "vendor.com");
    }

    #[test]
    fn test_extract_html_multiple_scripts_same_line() {
        let html = r#"<script src="https://cdn.vendor-a.com/a.js"></script><script src="https://cdn.vendor-b.com/b.js"></script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_web_traffic_discovery_different_timeouts() {
        let disc1 = WebTrafficDiscovery::new(5);
        assert_eq!(disc1.timeout, Duration::from_secs(5));
        assert_eq!(disc1.network_wait_ms, 5000);

        let disc2 = WebTrafficDiscovery::new(60);
        assert_eq!(disc2.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_is_infrastructure_noise_ipv6_loopback() {
        assert!(is_infrastructure_noise("[::1]"));
    }

    #[test]
    fn test_is_active_resource_load_all_variants() {
        // Active loads
        assert!(is_active_resource_load("script src"));
        assert!(is_active_resource_load("img src"));
        // Not active loads
        assert!(!is_active_resource_load("link href"));
        assert!(!is_active_resource_load("iframe src"));
        assert!(!is_active_resource_load("data-src"));
        assert!(!is_active_resource_load("inline URL"));
        assert!(!is_active_resource_load("unknown"));
    }

    #[test]
    fn test_extract_html_evidence_contains_truncated_long_url() {
        let long_path = "a".repeat(250);
        let html = format!(
            r#"<script src="https://cdn.vendor.com/{}"></script>"#,
            long_path
        );
        let results = extract_external_domains_from_html(&html, "example.com");
        assert_eq!(results.len(), 1);
        assert!(
            results[0].evidence.contains("..."),
            "Long URL evidence should be truncated"
        );
    }

    #[test]
    fn test_extract_relative_url_skip() {
        // Relative URL that the regex captures but Url::parse rejects
        let html = r#"<script src="/local/path/script.js"></script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        // Should produce no results — relative URL doesn't parse as absolute
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_html_dedup_across_different_element_types() {
        // Same vendor domain appearing in script and link — should be deduped
        let html = r#"
            <script src="https://cdn.vendor.com/sdk.js"></script>
            <link href="https://cdn.vendor.com/style.css" rel="stylesheet">
            <img src="https://cdn.vendor.com/pixel.gif">
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "vendor.com");
        // First match (script src) should be kept
        assert!(results[0].evidence.contains("script src"));
    }

    #[tokio::test]
    async fn test_analyze_domain_static_html_with_vendors() {
        let server = wiremock::MockServer::start().await;
        let html = r#"<html><head>
            <script src="https://cdn.pendo.io/agent/static/abc.js"></script>
            <script src="https://cdn.segment.io/analytics.js"></script>
        </head><body>Hello</body></html>"#;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;

        let addr = server.address();
        let host = format!("{}:{}", addr.ip(), addr.port());
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(5),
            network_wait_ms: 100,
        };
        let results = discovery
            .analyze_page_source(&format!("http://{}", host), &host)
            .await
            .unwrap();
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(
            domains.contains(&"pendo.io"),
            "Should find pendo.io, got: {:?}",
            domains
        );
        assert!(
            domains.contains(&"segment.io"),
            "Should find segment.io, got: {:?}",
            domains
        );
        assert!(results
            .iter()
            .all(|r| r.source == WebTrafficSource::PageSource));
    }

    #[tokio::test]
    async fn test_analyze_domain_empty_page_returns_empty() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string("<html><body></body></html>"),
            )
            .mount(&server)
            .await;

        let addr = server.address();
        let host = format!("{}:{}", addr.ip(), addr.port());
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(5),
            network_wait_ms: 100,
        };
        let results = discovery
            .analyze_page_source(&format!("http://{}", host), &host)
            .await
            .unwrap();
        assert!(results.is_empty(), "Empty page should yield no vendors");
    }

    #[test]
    fn test_extract_external_domains_filters_infrastructure_noise() {
        let html = r#"
            <script src="https://cdn.pendo.io/agent.js"></script>
            <script src="https://fonts.googleapis.com/css2"></script>
            <link href="https://www.w3.org/1999/xhtml" rel="stylesheet">
            <img src="https://schema.org/logo.png">
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(domains.contains(&"pendo.io"), "Should keep pendo.io");
        assert!(
            !domains.contains(&"googleapis.com"),
            "Should filter googleapis.com"
        );
        assert!(!domains.contains(&"w3.org"), "Should filter w3.org");
        assert!(!domains.contains(&"schema.org"), "Should filter schema.org");
    }

    #[test]
    fn test_extract_external_domains_social_media_script_vs_link() {
        let html_script = r#"<script src="https://connect.facebook.net/sdk.js"></script>"#;
        let results_script = extract_external_domains_from_html(html_script, "example.com");
        assert_eq!(
            results_script.len(),
            1,
            "Facebook SDK script should be captured"
        );
        assert_eq!(results_script[0].vendor_domain, "facebook.net");

        let html_iframe = r#"<iframe src="https://www.youtube.com/embed/abc123"></iframe>"#;
        let results_iframe = extract_external_domains_from_html(html_iframe, "example.com");
        assert!(
            results_iframe.is_empty(),
            "YouTube iframe embed should be filtered"
        );
    }

    #[test]
    fn test_truncate_url_short_minimal() {
        assert_eq!(truncate_url("https://x.com", 200), "https://x.com");
    }

    #[test]
    fn test_truncate_url_long() {
        let long = format!("https://example.com/{}", "a".repeat(300));
        let truncated = truncate_url(&long, 100);
        assert!(truncated.len() <= 103); // 100 chars + "..."
        assert!(truncated.ends_with("..."));
    }

    // ───────────────────────────────────────────────────────────────
    // filter_network_urls tests
    // ───────────────────────────────────────────────────────────────

    #[test]
    fn test_filter_network_urls_basic() {
        let urls = vec![
            "https://api.segment.io/v1/track".to_string(),
            "https://cdn.pendo.io/agent.js".to_string(),
        ];
        let results = filter_network_urls(&urls, "example.com");
        assert_eq!(results.len(), 2);
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(domains.contains(&"segment.io"));
        assert!(domains.contains(&"pendo.io"));
        assert!(results
            .iter()
            .all(|r| r.source == WebTrafficSource::NetworkTraffic));
    }

    #[test]
    fn test_filter_network_urls_skips_self_references() {
        let urls = vec![
            "https://cdn.example.com/app.js".to_string(),
            "https://api.example.com/data".to_string(),
            "https://cdn.pendo.io/agent.js".to_string(),
        ];
        let results = filter_network_urls(&urls, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "pendo.io");
    }

    #[test]
    fn test_filter_network_urls_dedup() {
        let urls = vec![
            "https://api.segment.io/v1/track".to_string(),
            "https://cdn.segment.io/analytics.js".to_string(),
            "https://api.segment.io/v1/identify".to_string(),
        ];
        let results = filter_network_urls(&urls, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "segment.io");
    }

    #[test]
    fn test_filter_network_urls_infrastructure_noise() {
        let urls = vec![
            "https://gstatic.com/recaptcha.js".to_string(),
            "https://googleapis.com/api/v1".to_string(),
            "https://w3.org/2000/svg".to_string(),
            "https://schema.org/Organization".to_string(),
            "https://ogp.me/ns".to_string(),
            "https://chromium.org/updates".to_string(),
            "https://cdn.pendo.io/agent.js".to_string(),
        ];
        let results = filter_network_urls(&urls, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "pendo.io");
    }

    #[test]
    fn test_filter_network_urls_invalid_urls_skipped() {
        let urls = vec![
            "not-a-url".to_string(),
            "://broken".to_string(),
            "".to_string(),
            "https://cdn.pendo.io/agent.js".to_string(),
        ];
        let results = filter_network_urls(&urls, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "pendo.io");
    }

    #[test]
    fn test_filter_network_urls_empty() {
        let results = filter_network_urls(&[], "example.com");
        assert!(results.is_empty());
    }

    #[test]
    fn test_filter_network_urls_evidence_format() {
        let urls = vec!["https://api.stripe.com/v1/charges".to_string()];
        let results = filter_network_urls(&urls, "example.com");
        assert_eq!(results.len(), 1);
        assert!(results[0].evidence.contains("Runtime network request to"));
        assert!(results[0]
            .evidence
            .contains("https://api.stripe.com/v1/charges"));
    }

    #[test]
    fn test_filter_network_urls_all_self_refs() {
        let urls = vec![
            "https://cdn.example.com/app.js".to_string(),
            "https://api.example.com/data".to_string(),
            "https://static.example.com/img.png".to_string(),
        ];
        let results = filter_network_urls(&urls, "example.com");
        assert!(results.is_empty());
    }

    #[test]
    fn test_filter_network_urls_url_without_host() {
        let urls = vec![
            "data:text/html,<h1>Hi</h1>".to_string(),
            "javascript:void(0)".to_string(),
            "mailto:test@example.com".to_string(),
            "https://cdn.pendo.io/agent.js".to_string(),
        ];
        let results = filter_network_urls(&urls, "example.com");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vendor_domain, "pendo.io");
    }

    #[test]
    fn test_filter_network_urls_mixed_scenario() {
        let urls = vec![
            "https://cdn.example.com/self.js".to_string(),
            "https://api.segment.io/v1/track".to_string(),
            "https://cdn.segment.io/analytics.js".to_string(),
            "https://localhost/debug".to_string(),
            "not-a-url".to_string(),
            "https://api.stripe.com/v1/charges".to_string(),
            "https://w3.org/2000/svg".to_string(),
            "https://cdn.stripe.com/js/v3".to_string(),
            "https://app.pendo.io/init".to_string(),
        ];
        let results = filter_network_urls(&urls, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert_eq!(domains.len(), 3);
        assert!(domains.contains(&"segment.io"));
        assert!(domains.contains(&"stripe.com"));
        assert!(domains.contains(&"pendo.io"));
    }

    // ───────────────────────────────────────────────────────────────
    // analyze_domain_url tests (via wiremock)
    // ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_analyze_domain_url_page_source_success_network_error() {
        let server = MockServer::start().await;
        let html = r#"<html><head>
            <script src="https://cdn.segment.io/analytics.js"></script>
            <script src="https://cdn.pendo.io/agent.js"></script>
        </head><body></body></html>"#;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;

        let addr = server.address();
        let host = format!("{}:{}", addr.ip(), addr.port());
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(5),
            network_wait_ms: 100,
        };
        let results = discovery
            .analyze_domain_url(&format!("http://{}", host), &host, &host)
            .await;
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(
            domains.contains(&"segment.io"),
            "Should find segment.io from page source, got: {:?}",
            domains
        );
        assert!(
            domains.contains(&"pendo.io"),
            "Should find pendo.io from page source, got: {:?}",
            domains
        );
    }

    #[tokio::test]
    async fn test_analyze_domain_url_both_phases_fail() {
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(1),
            network_wait_ms: 100,
        };
        let results = discovery
            .analyze_domain_url("http://127.0.0.1:1", "nonexistent.test", "nonexistent.test")
            .await;
        assert!(
            results.is_empty(),
            "Both phases failing should return empty results"
        );
    }

    #[tokio::test]
    async fn test_analyze_domain_url_merges_and_deduplicates() {
        let server = MockServer::start().await;
        let html = r#"<html><head>
            <script src="https://cdn.segment.io/analytics.js"></script>
            <script src="https://cdn.pendo.io/agent.js"></script>
            <script src="https://js.stripe.com/v3"></script>
        </head><body></body></html>"#;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;

        let addr = server.address();
        let host = format!("{}:{}", addr.ip(), addr.port());
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(5),
            network_wait_ms: 100,
        };
        let results = discovery
            .analyze_domain_url(&format!("http://{}", host), &host, &host)
            .await;
        assert!(results.len() >= 3, "Should find at least 3 vendors");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(domains.contains(&"segment.io"));
        assert!(domains.contains(&"pendo.io"));
        assert!(domains.contains(&"stripe.com"));
    }

    #[tokio::test]
    async fn test_analyze_domain_url_page_source_error_returns_empty() {
        let server = MockServer::start().await;
        // No mock routes → 404
        let addr = server.address();
        let host = format!("{}:{}", addr.ip(), addr.port());
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(5),
            network_wait_ms: 100,
        };
        let results = discovery
            .analyze_domain_url(&format!("http://{}", host), &host, &host)
            .await;
        // wiremock returns 404 with empty body → reqwest returns Ok, empty body → no vendors
        assert!(results.is_empty());
    }

    // ───────────────────────────────────────────────────────────────
    // analyze_domain tests
    // ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_analyze_domain_unreachable_host() {
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(1),
            network_wait_ms: 100,
        };
        let results = discovery.analyze_domain("unreachable.invalid.test").await;
        assert!(
            results.is_empty(),
            "Unreachable domain should return empty results"
        );
    }

    // ───────────────────────────────────────────────────────────────
    // analyze_network_traffic tests
    // ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_analyze_network_traffic_browser_fails() {
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(1),
            network_wait_ms: 100,
        };
        let result = discovery
            .analyze_network_traffic("http://127.0.0.1:1", "example.com")
            .await;
        // Browser creation or navigation should fail in test environment
        assert!(
            result.is_err(),
            "analyze_network_traffic should fail without a browser"
        );
    }

    // ───────────────────────────────────────────────────────────────
    // Social media debug branch (ensure the skip path is exercised)
    // ───────────────────────────────────────────────────────────────

    #[test]
    fn test_social_media_link_href_exercises_debug_skip() {
        let html = r#"
            <link href="https://www.facebook.com/ourpage" rel="canonical">
            <link href="https://www.twitter.com/ourpage" rel="alternate">
            <link href="https://www.instagram.com/ourpage" rel="me">
            <link href="https://www.tiktok.com/@ourpage" rel="me">
            <link href="https://www.pinterest.com/ourpage" rel="me">
            <link href="https://www.reddit.com/r/ourcommunity" rel="me">
            <link href="https://threads.net/@ourpage" rel="me">
            <link href="https://mastodon.social/@ourpage" rel="me">
            <link href="https://discord.com/invite/abc" rel="me">
            <link href="https://discord.gg/abc" rel="me">
            <link href="https://www.x.com/ourpage" rel="me">
            <link href="https://www.youtube.com/c/ourpage" rel="me">
            <link href="https://www.linkedin.com/company/us" rel="me">
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert!(results.is_empty());
    }

    #[test]
    fn test_social_media_iframe_exercises_debug_skip() {
        let html = r#"
            <iframe src="https://www.facebook.com/plugins/post.php?href=123"></iframe>
            <iframe src="https://www.instagram.com/p/abc/embed/"></iframe>
            <iframe src="https://www.tiktok.com/embed/123"></iframe>
            <iframe src="https://www.youtube.com/embed/abc123"></iframe>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert!(
            results.is_empty(),
            "Social media iframes should all be filtered"
        );
    }

    #[test]
    fn test_social_media_data_src_exercises_debug_skip() {
        let html = r#"
            <div data-src="https://www.facebook.com/embed/post/123"></div>
            <div data-src="https://www.linkedin.com/embed/feed/123"></div>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert!(
            results.is_empty(),
            "Social media data-src should be filtered"
        );
    }

    #[test]
    fn test_social_media_inline_url_exercises_debug_skip() {
        let html = r#"<script>
            var fb = "https://www.facebook.com/share?url=test";
            var tw = "https://twitter.com/intent/tweet?text=hello";
            var li = "https://www.linkedin.com/shareArticle?mini=true";
            var yt = "https://www.youtube.com/watch?v=abc123";
            var ig = "https://www.instagram.com/p/abc123/";
            var tt = "https://www.tiktok.com/@user/video/123";
            var pi = "https://pinterest.com/pin/create/button/";
            var rd = "https://reddit.com/submit?url=test";
        </script>"#;
        let results = extract_external_domains_from_html(html, "example.com");
        assert!(results.is_empty());
    }

    // ───────────────────────────────────────────────────────────────
    // Tests with tracing enabled (covers debug!() macro branches)
    // ───────────────────────────────────────────────────────────────

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[test]
    fn test_extract_with_tracing_social_media_skip_debug() {
        init_tracing();
        let html = r#"
            <link href="https://www.facebook.com/page" rel="canonical">
            <iframe src="https://www.youtube.com/embed/abc"></iframe>
            <div data-src="https://www.instagram.com/p/123"></div>
            <script>var tw = "https://twitter.com/intent/tweet";</script>
            <script src="https://cdn.segment.io/analytics.js"></script>
        "#;
        let results = extract_external_domains_from_html(html, "example.com");
        let domains: Vec<&str> = results.iter().map(|r| r.vendor_domain.as_str()).collect();
        assert!(domains.contains(&"segment.io"));
    }

    #[tokio::test]
    async fn test_analyze_domain_url_with_tracing_page_source_ok() {
        init_tracing();
        let server = MockServer::start().await;
        let html = r#"<html><head>
            <script src="https://cdn.segment.io/analytics.js"></script>
        </head></html>"#;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;

        let addr = server.address();
        let host = format!("{}:{}", addr.ip(), addr.port());
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(5),
            network_wait_ms: 100,
        };
        let results = discovery
            .analyze_domain_url(&format!("http://{}", host), "test.com", &host)
            .await;
        assert!(!results.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_domain_url_with_tracing_both_fail() {
        init_tracing();
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(1),
            network_wait_ms: 100,
        };
        let results = discovery
            .analyze_domain_url("http://127.0.0.1:1", "fail.test", "fail.test")
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_network_traffic_with_real_browser() {
        let server = MockServer::start().await;
        let html = r#"<html><body><h1>Test Page</h1></body></html>"#;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;

        let addr = server.address();
        let url = format!("http://{}:{}", addr.ip(), addr.port());
        let host = format!("{}:{}", addr.ip(), addr.port());
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(10),
            network_wait_ms: 500,
        };
        // Browser may or may not be available; exercise the path regardless
        let _ = discovery.analyze_network_traffic(&url, &host).await;
    }

    #[tokio::test]
    async fn test_analyze_domain_url_with_browser_ok_path() {
        let server = MockServer::start().await;
        let html = r#"<html><head>
            <script src="https://cdn.segment.io/analytics.js"></script>
        </head><body><h1>Test</h1></body></html>"#;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;

        let addr = server.address();
        let url = format!("http://{}:{}", addr.ip(), addr.port());
        let host = format!("{}:{}", addr.ip(), addr.port());
        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            timeout: Duration::from_secs(10),
            network_wait_ms: 500,
        };
        let results = discovery
            .analyze_domain_url(&url, "test.local", &host)
            .await;
        assert!(results.iter().any(|r| r.vendor_domain == "segment.io"));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_analyze_page_source_body_read_timeout() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Send HTTP headers with large Content-Length but no body
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let discovery = WebTrafficDiscovery {
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(500))
                .build()
                .unwrap(),
            timeout: Duration::from_millis(500),
            network_wait_ms: 100,
        };
        let result = discovery
            .analyze_page_source(&format!("http://{}", addr), "example.com")
            .await;
        assert!(result.is_err(), "Body read should time out");
    }
}
