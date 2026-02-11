//! Auto-discovery engine for trust center extraction strategies.
//!
//! When a domain has no cached strategy and the HTML looks like an SPA,
//! this module runs generic probes to discover the extraction strategy.

use anyhow::Result;

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::debug;

use super::{
    CandidateStrategy, DiscoveryMetadata, DiscoveryMethod, EndpointConfig,
    ResponseMapping, StrategyType, TrustCenterStrategy,
    find_entity_arrays, score_subprocessor_array, detect_field_mapping,
};

/// Collected network response during page load.
#[derive(Debug, Clone)]
struct InterceptedResponse {
    url: String,
    status: u16,
    content_type: String,
    body: String,
    request_url: String,
    request_method: String,
    request_body: Option<String>,
}

/// Check if HTML content looks like a JavaScript SPA that needs special handling.
pub fn is_likely_spa(html: &str) -> bool {
    // Strip HTML tags to get approximate text content length
    let text_len = html.chars()
        .fold((0usize, false), |(count, in_tag), ch| {
            match ch {
                '<' => (count, true),
                '>' => (count, false),
                _ if !in_tag => (count + 1, false),
                _ => (count, in_tag),
            }
        }).0;

    let html_len = html.len();
    if html_len == 0 {
        return false;
    }

    // SPA indicator 1: Very little text content relative to HTML size
    let text_ratio = text_len as f64 / html_len as f64;
    if text_ratio < 0.05 && html_len > 1000 {
        debug!("SPA detected: text/HTML ratio {:.3} < 0.05", text_ratio);
        return true;
    }

    // SPA indicator 2: Contains framework markers
    let html_lower = html.to_lowercase();
    let spa_markers = [
        "id=\"__next\"",
        "id=\"root\"",
        "__next_data__",
        "data-reactroot",
        "window.__nuxt__",
        "ng-app",
        "id=\"app\"",
    ];

    for marker in &spa_markers {
        if html_lower.contains(marker) {
            debug!("SPA detected: found framework marker '{}'", marker);
            return true;
        }
    }

    false
}

/// Run auto-discovery probes to find the best extraction strategy for a URL.
///
/// Probes are run in order of reliability:
/// 1. Network interception (captures actual API calls)
/// 2. HTML pattern scanning (finds embedded data)
///
/// Returns the best candidate strategy, or None if no strategy was found.
pub async fn discover_strategy(
    url: &str,
    static_html: &str,
) -> Result<Option<TrustCenterStrategy>> {
    let mut all_candidates: Vec<CandidateStrategy> = Vec::new();

    // Probe 1: Scan static HTML for embedded data patterns first (cheapest)
    debug!("Running HTML pattern scan probe on static HTML for {}", url);
    match discover_via_html_patterns(static_html) {
        Ok(candidates) => {
            debug!("HTML pattern scan found {} candidates", candidates.len());
            all_candidates.extend(candidates);
        }
        Err(e) => debug!("HTML pattern scan failed: {}", e),
    }

    // If HTML patterns found strong candidates, use them (no need for browser)
    if let Some(best) = all_candidates.iter().max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal)) {
        if best.score >= 0.7 {
            debug!("Strong candidate found via HTML patterns (score: {:.2}), skipping browser probes", best.score);
            return Ok(Some(best.strategy.clone()));
        }
    }

    // Probe 2: Network interception (requires headless browser)
    debug!("Running network interception probe for {}", url);
    match discover_via_network_interception(url).await {
        Ok(candidates) => {
            debug!("Network interception found {} candidates", candidates.len());
            all_candidates.extend(candidates);
        }
        Err(e) => debug!("Network interception failed: {}", e),
    }

    // Select the best candidate
    all_candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    if let Some(best) = all_candidates.into_iter().next() {
        if best.score >= 0.4 {
            debug!("Selected strategy with score {:.2}, {} items", best.score, best.item_count);
            return Ok(Some(best.strategy));
        }
        debug!("Best candidate score {:.2} below threshold 0.4", best.score);
    }

    Ok(None)
}

/// Probe 1: Discover strategies by intercepting network traffic during headless page load.
async fn discover_via_network_interception(url: &str) -> Result<Vec<CandidateStrategy>> {
    let responses = Arc::new(Mutex::new(Vec::<InterceptedResponse>::new()));
    let responses_clone = responses.clone();
    let url_owned = url.to_string();

    // headless_chrome operations are blocking, run in a blocking thread
    let handle = tokio::task::spawn_blocking(move || -> Result<Vec<InterceptedResponse>> {
        let browser = crate::create_browser()?;

        let tab = browser.new_tab()
            .map_err(|e| anyhow::anyhow!("Failed to create tab: {}", e))?;

        // Register response handler to capture JSON API responses.
        // Handler signature: (ResponseReceivedEventParams, &dyn Fn() -> Result<GetResponseBodyReturnObject>)
        tab.register_response_handling("trust_center_discovery",
            Box::new(move |event_params, fetch_body| {
                let resp = &event_params.response;
                let mime = &resp.mime_type;
                let resp_url = &resp.url;
                let status = resp.status;

                let is_json = mime.contains("json")
                    || resp_url.contains("graphql")
                    || resp_url.contains("/api/");

                if is_json && status >= 200 && status < 300 {
                    // Small delay for body to become available
                    std::thread::sleep(Duration::from_millis(100));
                    if let Ok(body_obj) = fetch_body() {
                        let body_str = &body_obj.body;
                        if body_str.len() > 50 && body_str.len() < 5_000_000 {
                            let mut collected = responses_clone.lock().unwrap();
                            collected.push(InterceptedResponse {
                                url: resp_url.clone(),
                                status: status as u16,
                                content_type: mime.clone(),
                                body: body_str.clone(),
                                request_url: resp_url.clone(),
                                request_method: "GET".to_string(),
                                request_body: None,
                            });
                        }
                    }
                }
            })
        ).map_err(|e| anyhow::anyhow!("Failed to register response handler: {}", e))?;

        // Navigate and wait for page + API calls to complete
        tab.navigate_to(&url_owned)
            .map_err(|e| anyhow::anyhow!("Navigation failed: {}", e))?;

        tab.wait_until_navigated()
            .map_err(|e| anyhow::anyhow!("Page load failed: {}", e))?;

        // Wait for async API calls to complete
        std::thread::sleep(Duration::from_millis(3000));

        // Deregister and collect results
        let _ = tab.deregister_response_handling("trust_center_discovery");
        let collected = responses.lock().unwrap().clone();
        Ok(collected)
    });

    let collected_responses = handle.await
        .map_err(|e| anyhow::anyhow!("Blocking task panicked: {}", e))??;

    debug!("Intercepted {} JSON responses", collected_responses.len());
    analyze_intercepted_responses(&collected_responses, url)
}

/// Analyze intercepted API responses to find subprocessor data arrays.
fn analyze_intercepted_responses(
    responses: &[InterceptedResponse],
    page_url: &str,
) -> Result<Vec<CandidateStrategy>> {
    let mut candidates = Vec::new();

    for response in responses {
        let json: serde_json::Value = match serde_json::from_str(&response.body) {
            Ok(j) => j,
            Err(_) => continue,
        };

        // Search the JSON tree for arrays that look like subprocessor lists
        let arrays = find_entity_arrays(&json, "");

        for (path, items) in &arrays {
            let score = score_subprocessor_array(items, path);

            if score >= 0.4 {
                let field_mapping = detect_field_mapping(items);

                let name_field = match field_mapping.name_field {
                    Some(f) => f,
                    None => continue, // Must have a name field
                };

                // Determine strategy type from the response URL
                let strategy_type = if response.url.contains("graphql") {
                    // For GraphQL, we'd need the query from the request body
                    // For now, create a placeholder that can be refined
                    StrategyType::GraphqlApi {
                        query_template: String::new(), // Will need to be captured from request
                        variables: std::collections::HashMap::new(),
                        operation_name: extract_graphql_operation(&response.url),
                    }
                } else {
                    StrategyType::RestApi {
                        method: response.request_method.clone(),
                        body_template: response.request_body.clone(),
                        headers: std::collections::HashMap::new(),
                    }
                };

                let strategy = TrustCenterStrategy {
                    strategy_type,
                    endpoint: EndpointConfig {
                        url: response.url.clone(),
                        slug: extract_slug_from_url(page_url),
                        requires_browser: false,
                    },
                    response_mapping: ResponseMapping {
                        subprocessors_path: path.clone(),
                        name_field,
                        url_field: field_mapping.url_field,
                        purpose_field: field_mapping.purpose_field,
                        location_field: field_mapping.location_field,
                        evidence_fields: Vec::new(),
                    },
                    discovery_metadata: DiscoveryMetadata::new(
                        DiscoveryMethod::NetworkInterception,
                        items.len() as u32,
                        score,
                    ),
                };

                candidates.push(CandidateStrategy {
                    strategy,
                    score,
                    item_count: items.len(),
                });
            }
        }
    }

    Ok(candidates)
}

/// Probe 2: Discover strategies by scanning HTML for embedded data patterns.
fn discover_via_html_patterns(html: &str) -> Result<Vec<CandidateStrategy>> {
    let mut candidates = Vec::new();

    // Probe 2a: __NEXT_DATA__ hydration blob (Next.js apps)
    if let Some(candidate) = probe_next_data(html) {
        candidates.push(candidate);
    }

    // Probe 2b: <script type="application/json"> tags
    probe_json_script_tags(html, &mut candidates);

    // Probe 2c: Base64 encoded JSON blobs
    probe_base64_blobs(html, &mut candidates);

    // Probe 2d: JavaScript object assignments (window.X = {...})
    probe_js_object_assignments(html, &mut candidates);

    Ok(candidates)
}

/// Search for Next.js __NEXT_DATA__ hydration blob.
fn probe_next_data(html: &str) -> Option<CandidateStrategy> {
    // Look for <script id="__NEXT_DATA__" type="application/json">...</script>
    let pattern = r#"<script\s+id="__NEXT_DATA__"[^>]*>([\s\S]*?)</script>"#;
    let regex = fancy_regex::Regex::new(pattern).ok()?;

    let captures = regex.captures(html).ok()??;
    let json_str = captures.get(1)?.as_str();

    let json: serde_json::Value = serde_json::from_str(json_str).ok()?;

    // Search for subprocessor arrays in the hydration data
    let arrays = find_entity_arrays(&json, "");

    for (path, items) in &arrays {
        let score = score_subprocessor_array(items, path);
        if score >= 0.4 {
            let field_mapping = detect_field_mapping(items);
            let name_field = field_mapping.name_field?;

            return Some(CandidateStrategy {
                strategy: TrustCenterStrategy {
                    strategy_type: StrategyType::HydrationData {
                        script_selector: "script#__NEXT_DATA__".to_string(),
                        data_path: path.clone(),
                    },
                    endpoint: EndpointConfig {
                        url: String::new(), // Filled by caller
                        slug: None,
                        requires_browser: false,
                    },
                    response_mapping: ResponseMapping {
                        subprocessors_path: String::new(), // Not needed for HydrationData
                        name_field,
                        url_field: field_mapping.url_field,
                        purpose_field: field_mapping.purpose_field,
                        location_field: field_mapping.location_field,
                        evidence_fields: Vec::new(),
                    },
                    discovery_metadata: DiscoveryMetadata::new(
                        DiscoveryMethod::HtmlPatternScan,
                        items.len() as u32,
                        score,
                    ),
                },
                score,
                item_count: items.len(),
            });
        }
    }

    None
}

/// Search for <script type="application/json"> tags containing subprocessor data.
fn probe_json_script_tags(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    let document = scraper::Html::parse_document(html);
    let selector = match scraper::Selector::parse(r#"script[type="application/json"]"#) {
        Ok(s) => s,
        Err(_) => return,
    };

    for (idx, script) in document.select(&selector).enumerate() {
        let text: String = script.text().collect();
        let trimmed = text.trim();

        if trimmed.len() < 50 {
            continue;
        }

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let arrays = find_entity_arrays(&json, "");
            for (path, items) in &arrays {
                let score = score_subprocessor_array(items, path);
                if score >= 0.4 {
                    let field_mapping = detect_field_mapping(items);
                    if let Some(name_field) = field_mapping.name_field {
                        candidates.push(CandidateStrategy {
                            strategy: TrustCenterStrategy {
                                strategy_type: StrategyType::HydrationData {
                                    script_selector: format!(
                                        r#"script[type="application/json"]:nth-of-type({})"#,
                                        idx + 1
                                    ),
                                    data_path: path.clone(),
                                },
                                endpoint: EndpointConfig {
                                    url: String::new(),
                                    slug: None,
                                    requires_browser: false,
                                },
                                response_mapping: ResponseMapping {
                                    subprocessors_path: String::new(),
                                    name_field,
                                    url_field: field_mapping.url_field,
                                    purpose_field: field_mapping.purpose_field,
                                    location_field: field_mapping.location_field,
                                    evidence_fields: Vec::new(),
                                },
                                discovery_metadata: DiscoveryMetadata::new(
                                    DiscoveryMethod::HtmlPatternScan,
                                    items.len() as u32,
                                    score,
                                ),
                            },
                            score,
                            item_count: items.len(),
                        });
                    }
                }
            }
        }
    }
}

/// Search for base64-encoded JSON blobs in HTML.
fn probe_base64_blobs(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    let patterns = [
        // data attribute with base64 content
        r#"data-[a-z-]+="([A-Za-z0-9+/=]{200,})""#,
        // atob() call with base64 string
        r#"atob\s*\(\s*["']([A-Za-z0-9+/=]{200,})["']\s*\)"#,
        // Variable assignment with base64 string
        r#"(?:var|let|const)\s+\w+\s*=\s*["']([A-Za-z0-9+/=]{200,})["']"#,
    ];

    for pattern in &patterns {
        if let Ok(regex) = fancy_regex::Regex::new(pattern) {
            let mut search_start = 0;
            while search_start < html.len() {
                let search_slice = &html[search_start..];
                match regex.captures(search_slice) {
                    Ok(Some(captures)) => {
                        if let Some(b64_match) = captures.get(1) {
                            let b64_str = b64_match.as_str();

                            use base64::Engine;
                            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64_str) {
                                if let Ok(json_str) = String::from_utf8(decoded) {
                                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                                        let arrays = find_entity_arrays(&json, "");
                                        for (path, items) in &arrays {
                                            let score = score_subprocessor_array(items, path);
                                            if score >= 0.4 {
                                                let field_mapping = detect_field_mapping(items);
                                                if let Some(name_field) = field_mapping.name_field {
                                                    candidates.push(CandidateStrategy {
                                                        strategy: TrustCenterStrategy {
                                                            strategy_type: StrategyType::EmbeddedBase64Json {
                                                                locator_pattern: pattern.to_string(),
                                                            },
                                                            endpoint: EndpointConfig {
                                                                url: String::new(),
                                                                slug: None,
                                                                requires_browser: false,
                                                            },
                                                            response_mapping: ResponseMapping {
                                                                subprocessors_path: path.clone(),
                                                                name_field,
                                                                url_field: field_mapping.url_field,
                                                                purpose_field: field_mapping.purpose_field,
                                                                location_field: field_mapping.location_field,
                                                                evidence_fields: Vec::new(),
                                                            },
                                                            discovery_metadata: DiscoveryMetadata::new(
                                                                DiscoveryMethod::HtmlPatternScan,
                                                                items.len() as u32,
                                                                score,
                                                            ),
                                                        },
                                                        score,
                                                        item_count: items.len(),
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Move past this match
                            search_start += b64_match.end();
                        } else {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }
    }
}

/// Search for JavaScript object assignments like `window.VENDOR_REPORT = {...}`.
fn probe_js_object_assignments(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    // Match window.VARIABLE = { ... large JSON ... }
    let pattern = r#"window\.([A-Z_][A-Z_0-9]*)\s*=\s*(\{[\s\S]{200,}?\})(?:\s*;|\s*<)"#;

    if let Ok(regex) = fancy_regex::Regex::new(pattern) {
        let mut search_start = 0;
        while search_start < html.len() {
            let search_slice = &html[search_start..];
            match regex.captures(search_slice) {
                Ok(Some(captures)) => {
                    let var_name = captures.get(1).map(|m| m.as_str()).unwrap_or("UNKNOWN");

                    if let Some(json_match) = captures.get(2) {
                        let json_str = json_match.as_str();

                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
                            let arrays = find_entity_arrays(&json, "");
                            for (path, items) in &arrays {
                                let score = score_subprocessor_array(items, path);
                                if score >= 0.4 {
                                    let field_mapping = detect_field_mapping(items);
                                    if let Some(name_field) = field_mapping.name_field {
                                        let locator = format!(
                                            r#"window\.{}\s*=\s*(\{{[\s\S]*?\}})(?:\s*;|\s*<)"#,
                                            regex::escape(var_name)
                                        );
                                        candidates.push(CandidateStrategy {
                                            strategy: TrustCenterStrategy {
                                                strategy_type: StrategyType::EmbeddedJsObject {
                                                    locator_pattern: locator,
                                                },
                                                endpoint: EndpointConfig {
                                                    url: String::new(),
                                                    slug: None,
                                                    requires_browser: false,
                                                },
                                                response_mapping: ResponseMapping {
                                                    subprocessors_path: path.clone(),
                                                    name_field,
                                                    url_field: field_mapping.url_field,
                                                    purpose_field: field_mapping.purpose_field,
                                                    location_field: field_mapping.location_field,
                                                    evidence_fields: Vec::new(),
                                                },
                                                discovery_metadata: DiscoveryMetadata::new(
                                                    DiscoveryMethod::HtmlPatternScan,
                                                    items.len() as u32,
                                                    score,
                                                ),
                                            },
                                            score,
                                            item_count: items.len(),
                                        });
                                    }
                                }
                            }
                        }

                        search_start += json_match.end();
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
    }
}

/// Extract a GraphQL operation name from a URL query parameter.
fn extract_graphql_operation(url: &str) -> Option<String> {
    if let Ok(parsed) = url::Url::parse(url) {
        for (key, value) in parsed.query_pairs() {
            if key == "operation" || key == "operationName" {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Extract a potential slug from a trust center URL.
/// For example: `https://trust.vanta.com/acme/subprocessors` -> `Some("acme")`
fn extract_slug_from_url(url: &str) -> Option<String> {
    if let Ok(parsed) = url::Url::parse(url) {
        let segments: Vec<&str> = parsed.path_segments()
            .map(|s| s.collect())
            .unwrap_or_default();

        // Common pattern: /slug/subprocessors or /slug/trust/subprocessors
        if segments.len() >= 2 {
            let first = segments[0];
            // Skip if it's a common non-slug path
            let non_slugs = ["api", "graphql", "trust", "security", "legal", "privacy", "subprocessors"];
            if !non_slugs.contains(&first) && !first.is_empty() {
                return Some(first.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_likely_spa_minimal_html() {
        let spa_html = r#"<!DOCTYPE html><html><head><meta charset="utf-8">
            <script src="/_next/static/chunks/main.js"></script>
            </head><body><div id="__next"></div>
            <script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
            </body></html>"#;
        assert!(is_likely_spa(spa_html));
    }

    #[test]
    fn test_is_likely_spa_regular_html() {
        let regular_html = r#"<!DOCTYPE html><html><head><title>Subprocessors</title></head>
            <body><h1>Our Subprocessors</h1><table><tr><td>AWS</td><td>Cloud hosting</td></tr>
            <tr><td>Cloudflare</td><td>CDN</td></tr></table></body></html>"#;
        assert!(!is_likely_spa(regular_html));
    }

    #[test]
    fn test_extract_slug_from_url() {
        assert_eq!(extract_slug_from_url("https://trust.vanta.com/acme/subprocessors"),
                   Some("acme".to_string()));
        assert_eq!(extract_slug_from_url("https://trust.vanta.com/subprocessors"), None);
    }

    #[test]
    fn test_probe_next_data() {
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"subprocessors":[
                {"name":"AWS","url":"https://aws.amazon.com","purpose":"Cloud"},
                {"name":"Cloudflare","url":"https://cloudflare.com","purpose":"CDN"},
                {"name":"Datadog","url":"https://datadoghq.com","purpose":"Monitoring"},
                {"name":"Anthropic","url":"https://anthropic.com","purpose":"AI"},
                {"name":"Google","url":"https://google.com","purpose":"Analytics"}
            ]}}}
            </script></body></html>"#;

        let result = probe_next_data(html);
        assert!(result.is_some());
        let candidate = result.unwrap();
        assert_eq!(candidate.item_count, 5);
        assert!(candidate.score >= 0.4);
    }
}
