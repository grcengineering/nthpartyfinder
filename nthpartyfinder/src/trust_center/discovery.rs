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

    // SPA indicator 3: Body element has no visible content elements — only scripts.
    // Some SPAs (e.g., Vanta trust center) use <body id="body"> with only <script> children
    // and rely entirely on JavaScript to render content. The text ratio check above may be
    // fooled by long meta descriptions that inflate text content counts.
    if let Some(body_start) = html_lower.find("<body") {
        if let Some(body_tag_end) = html_lower[body_start..].find('>') {
            let body_content_start = body_start + body_tag_end + 1;
            let body_content = if let Some(body_end) = html_lower[body_content_start..].find("</body") {
                &html_lower[body_content_start..body_content_start + body_end]
            } else {
                &html_lower[body_content_start..]
            };

            // Check if body has any visible content elements (not just script/noscript)
            let visible_tags = ["<div", "<p", "<table", "<section", "<article", "<main",
                                "<h1", "<h2", "<h3", "<span", "<ul", "<ol", "<form"];
            let has_visible_content = visible_tags.iter().any(|tag| body_content.contains(tag));

            if !has_visible_content && body_content.contains("<script") {
                debug!("SPA detected: body has no visible content elements, only scripts");
                return true;
            }
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
        let guard = crate::browser_pool::create_browser()?;

        let tab = guard.browser.new_tab()
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

    // Probe 2a: SafeBase trust center (detected by __SB_CONFIG__)
    // Must run before generic __NEXT_DATA__ probe since SafeBase uses Next.js
    // but has a specific structure that the generic probe might score poorly.
    probe_safebase(html, &mut candidates);

    // Probe 2b: Conveyor trust center (detected by window.VENDOR_REPORT)
    // Must run before generic JS object probe since Conveyor uses a relational
    // model (canonical_asset_id → canonical_assets) that the generic probe can't handle.
    probe_conveyor(html, &mut candidates);

    // Probe 2c: __NEXT_DATA__ hydration blob (Next.js apps)
    if let Some(candidate) = probe_next_data(html) {
        candidates.push(candidate);
    }

    // Probe 2d: <script type="application/json"> tags
    probe_json_script_tags(html, &mut candidates);

    // Probe 2e: Base64 encoded JSON blobs
    probe_base64_blobs(html, &mut candidates);

    // Probe 2f: JavaScript object assignments (window.X = {...})
    probe_js_object_assignments(html, &mut candidates);

    Ok(candidates)
}

/// SafeBase trust center probe.
///
/// SafeBase (safebase.io) powers trust centers for many companies. It uses Next.js
/// and embeds subprocessor data in the __NEXT_DATA__ hydration blob at:
///   props.pageProps.orgInfo.sp.products.{productId}.raw.spData.items.{itemUid}.listEntries
///
/// Each entry has: { company: { name, domain, logo }, purpose, location, additionalDetails }
///
/// SafeBase also supports multi-product trust centers where multiple products
/// (e.g., "Drata" and "SafeBase") share a single trust center domain.
/// Product info is at: props.pageProps.orgInfo.sp.products (map of productId → product).
fn probe_safebase(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    // Quick check: SafeBase pages contain __SB_CONFIG__
    if !html.contains("__SB_CONFIG__") {
        return;
    }
    debug!("SafeBase trust center detected (found __SB_CONFIG__)");

    // Parse __NEXT_DATA__ to extract the SafeBase structure
    let pattern = r#"<script\s+id="__NEXT_DATA__"[^>]*>([\s\S]*?)</script>"#;
    let regex = match fancy_regex::Regex::new(pattern) {
        Ok(r) => r,
        Err(_) => return,
    };

    let json_str = match regex.captures(html).ok().flatten().and_then(|c| c.get(1)) {
        Some(m) => m.as_str(),
        None => {
            debug!("SafeBase: __NEXT_DATA__ not found despite __SB_CONFIG__ presence");
            return;
        }
    };

    let json: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(j) => j,
        Err(e) => {
            debug!("SafeBase: Failed to parse __NEXT_DATA__: {}", e);
            return;
        }
    };

    // Navigate to the products structure
    let products = match super::navigate_json_path(&json, "props.pageProps.orgInfo.sp.products") {
        Some(p) if p.is_object() => p,
        _ => {
            debug!("SafeBase: products structure not found in __NEXT_DATA__");
            return;
        }
    };

    let products_map = match products.as_object() {
        Some(m) => m,
        None => return,
    };

    debug!("SafeBase: found {} products", products_map.len());

    // Iterate through all products to find subprocessor list items
    for (product_id, product_data) in products_map {
        let slug = product_data.get("slug").and_then(|v| v.as_str()).unwrap_or(product_id);
        let product_name = product_data.get("name").and_then(|v| v.as_str()).unwrap_or(slug);
        let show = product_data.get("show").and_then(|v| v.as_bool()).unwrap_or(true);

        if !show {
            debug!("SafeBase: skipping hidden product '{}' (slug: {})", product_name, slug);
            continue;
        }

        debug!("SafeBase: scanning product '{}' (id: {}, slug: {})", product_name, product_id, slug);

        // Look for subprocessor items in raw.spData.items
        let items = match super::navigate_json_path(product_data, "raw.spData.items") {
            Some(i) if i.is_object() => i,
            _ => continue,
        };

        let items_map = match items.as_object() {
            Some(m) => m,
            None => continue,
        };

        for (item_uid, item_data) in items_map {
            let list_entries = match item_data.get("listEntries").and_then(|v| v.as_array()) {
                Some(arr) if arr.len() >= 3 => arr,
                _ => continue,
            };

            // Verify entries look like subprocessor data (have company.name or name)
            let has_company = list_entries.iter().take(5).any(|entry| {
                entry.get("company").and_then(|c| c.get("name")).and_then(|n| n.as_str())
                    .map_or(false, |s| !s.is_empty())
            });

            if !has_company {
                continue;
            }

            debug!("SafeBase: found {} subprocessor entries in product '{}', item {}",
                   list_entries.len(), product_name, item_uid);

            // Build the full data path for this subprocessor list
            let data_path = format!(
                "props.pageProps.orgInfo.sp.products.{}.raw.spData.items.{}.listEntries",
                product_id, item_uid
            );

            // Score higher since we've positively identified SafeBase structure
            let score = 0.95;

            candidates.push(CandidateStrategy {
                strategy: TrustCenterStrategy {
                    strategy_type: StrategyType::HydrationData {
                        script_selector: "script#__NEXT_DATA__".to_string(),
                        data_path: data_path.clone(),
                    },
                    endpoint: EndpointConfig {
                        url: String::new(), // Filled by caller
                        slug: Some(slug.to_string()),
                        requires_browser: false,
                    },
                    response_mapping: ResponseMapping {
                        subprocessors_path: String::new(), // Not needed for HydrationData
                        name_field: "company.name".to_string(),
                        url_field: Some("company.domain".to_string()),
                        purpose_field: Some("purpose".to_string()),
                        location_field: Some("location".to_string()),
                        evidence_fields: vec![
                            "company.name".to_string(),
                            "purpose".to_string(),
                            "location".to_string(),
                        ],
                    },
                    discovery_metadata: DiscoveryMetadata::new(
                        DiscoveryMethod::HtmlPatternScan,
                        list_entries.len() as u32,
                        score,
                    ),
                },
                score,
                item_count: list_entries.len(),
            });
        }
    }
}

/// Conveyor trust center probe.
///
/// Conveyor (conveyor.com) powers trust centers embedded as `window.VENDOR_REPORT = {...}`.
/// The data uses a relational model:
///   - `_embedded.subprocessors[]` has `canonical_asset_id`, `description`, `data_locations`
///   - `_embedded.canonical_assets[]` has `id`, `name`, `website`
/// Subprocessor names/domains are resolved by joining on `canonical_asset_id` → `id`.
///
/// Conveyor also has a public REST API that returns the same data:
///   GET https://api.conveyor.com/public/public_vendor_reports/by_slug?slug={slug}&embed_canonical_assets=true
/// The slug is found in `window.CANONICAL_ASSET = { slug: "company" }`.
///
/// This probe creates a RestApi strategy pointing to the public API.
fn probe_conveyor(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    // Quick check: Conveyor pages contain window.VENDOR_REPORT
    if !html.contains("window.VENDOR_REPORT") {
        return;
    }
    debug!("Conveyor trust center detected (found window.VENDOR_REPORT)");

    // Extract the slug from window.CANONICAL_ASSET
    let slug = extract_conveyor_slug(html);

    if slug.is_none() {
        debug!("Conveyor: could not extract slug from CANONICAL_ASSET");
    }

    // Try to parse window.VENDOR_REPORT to count subprocessors for validation
    let subprocessor_count = count_conveyor_subprocessors(html);

    if subprocessor_count < 3 {
        debug!("Conveyor: found {} subprocessors, below threshold of 3", subprocessor_count);
        return;
    }

    debug!("Conveyor: found {} subprocessors, slug={:?}", subprocessor_count, slug);

    let score = 0.95;
    let api_url = match &slug {
        Some(s) => format!(
            "https://api.conveyor.com/public/public_vendor_reports/by_slug?slug={}&embed_canonical_assets=true",
            s
        ),
        None => String::new(),
    };

    candidates.push(CandidateStrategy {
        strategy: TrustCenterStrategy {
            strategy_type: StrategyType::RestApi {
                method: "GET".to_string(),
                body_template: None,
                headers: std::collections::HashMap::new(),
            },
            endpoint: EndpointConfig {
                url: api_url,
                slug,
                requires_browser: false,
            },
            response_mapping: ResponseMapping {
                subprocessors_path: "_embedded.subprocessors".to_string(),
                name_field: "name".to_string(),
                url_field: Some("website".to_string()),
                purpose_field: Some("description".to_string()),
                location_field: Some("data_locations".to_string()),
                evidence_fields: vec![
                    "name".to_string(),
                    "description".to_string(),
                ],
            },
            discovery_metadata: DiscoveryMetadata::new(
                DiscoveryMethod::HtmlPatternScan,
                subprocessor_count as u32,
                score,
            ),
        },
        score,
        item_count: subprocessor_count,
    });
}

/// Extract the Conveyor slug from window.CANONICAL_ASSET assignment.
fn extract_conveyor_slug(html: &str) -> Option<String> {
    let json = extract_js_object_assignment(html, "CANONICAL_ASSET")?;
    json.get("slug").and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Count the number of subprocessors in a Conveyor VENDOR_REPORT.
fn count_conveyor_subprocessors(html: &str) -> usize {
    let json = extract_js_object_assignment(html, "VENDOR_REPORT");
    match json {
        Some(j) => {
            j.get("_embedded")
                .and_then(|e| e.get("subprocessors"))
                .and_then(|s| s.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        }
        None => 0,
    }
}

/// Extract a JSON object from a `window.VAR_NAME = {...};` assignment using bracket-matching.
/// This handles nested braces correctly unlike regex-based approaches.
fn extract_js_object_assignment(html: &str, var_name: &str) -> Option<serde_json::Value> {
    let marker = format!("window.{}", var_name);
    let marker_pos = html.find(&marker)?;
    let after_marker = &html[marker_pos + marker.len()..];

    // Skip whitespace and '='
    let trimmed = after_marker.trim_start();
    if !trimmed.starts_with('=') {
        return None;
    }
    let after_eq = trimmed[1..].trim_start();

    if !after_eq.starts_with('{') {
        return None;
    }

    // Bracket-match to find the balanced closing brace
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape_next = false;
    let mut end_pos = None;

    for (i, ch) in after_eq.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if in_string => { escape_next = true; }
            '"' => { in_string = !in_string; }
            '{' if !in_string => { depth += 1; }
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    end_pos = Some(i + 1);
                    break;
                }
            }
            _ => {}
        }
    }

    let json_str = &after_eq[..end_pos?];
    serde_json::from_str(json_str).ok()
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

    #[test]
    fn test_probe_safebase_detects_trust_center() {
        // Minimal SafeBase trust center HTML with __SB_CONFIG__ and __NEXT_DATA__
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {"NEXT_PUBLIC_SITE":"https://app.safebase.io"};</script>
            <div id="__next"></div>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme Corp","show":true,"order":1,
                    "raw":{"spData":{"items":{
                        "abc-123":{"listEntries":[
                            {"company":{"name":"Algolia","domain":"algolia.com"},"purpose":"Search","location":"US"},
                            {"company":{"name":"AWS","domain":"amazonaws.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"Datadog","domain":"datadoghq.com"},"purpose":"Monitoring","location":"US"},
                            {"company":{"name":"Stripe","domain":"stripe.com"},"purpose":"Payments","location":"US"}
                        ],"text":{"title":"Subprocessors"}}
                    }}}
                }
            }}}}}}
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);

        assert_eq!(candidates.len(), 1, "Should find exactly one subprocessor list");
        let candidate = &candidates[0];
        assert_eq!(candidate.item_count, 4);
        assert!(candidate.score >= 0.9, "SafeBase probe should have high confidence");

        // Verify field mapping
        assert_eq!(candidate.strategy.response_mapping.name_field, "company.name");
        assert_eq!(candidate.strategy.response_mapping.url_field, Some("company.domain".to_string()));
        assert_eq!(candidate.strategy.response_mapping.purpose_field, Some("purpose".to_string()));
        assert_eq!(candidate.strategy.response_mapping.location_field, Some("location".to_string()));

        // Verify slug extraction
        assert_eq!(candidate.strategy.endpoint.slug, Some("acme".to_string()));
    }

    #[test]
    fn test_probe_safebase_multi_product() {
        // Multi-product SafeBase trust center
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme","show":true,"order":1,
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"AWS","domain":"amazonaws.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"GCP","domain":"cloud.google.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"Stripe","domain":"stripe.com"},"purpose":"Pay","location":"US"}
                        ]}
                    }}}
                },
                "product1":{
                    "id":"product1","slug":"safebase","name":"SafeBase","show":true,"order":2,
                    "raw":{"spData":{"items":{
                        "uid-2":{"listEntries":[
                            {"company":{"name":"Okta","domain":"okta.com"},"purpose":"Auth","location":"US"},
                            {"company":{"name":"Snowflake","domain":"snowflake.com"},"purpose":"Data","location":"US"},
                            {"company":{"name":"Twilio","domain":"twilio.com"},"purpose":"Comms","location":"US"}
                        ]}
                    }}}
                },
                "hidden_product":{
                    "id":"hidden","slug":"internal","name":"Internal","show":false,"order":3,
                    "raw":{"spData":{"items":{
                        "uid-3":{"listEntries":[
                            {"company":{"name":"Secret","domain":"secret.com"},"purpose":"Internal","location":"US"},
                            {"company":{"name":"Hidden","domain":"hidden.com"},"purpose":"Internal","location":"US"},
                            {"company":{"name":"Private","domain":"private.com"},"purpose":"Internal","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);

        // Should find 2 products (not the hidden one)
        assert_eq!(candidates.len(), 2, "Should find subprocessors from 2 visible products");
        assert_eq!(candidates[0].item_count, 3);
        assert_eq!(candidates[1].item_count, 3);
    }

    #[test]
    fn test_probe_safebase_skips_non_safebase() {
        // Regular Next.js page without __SB_CONFIG__
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"data":[
                {"name":"AWS","url":"https://aws.amazon.com"}
            ]}}}
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty(), "Should not detect SafeBase on non-SafeBase pages");
    }

    #[test]
    fn test_probe_safebase_skips_entries_without_company() {
        // SafeBase page with non-subprocessor list entries (no company.name)
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme","show":true,"order":1,
                    "raw":{"spData":{"items":{
                        "trusted-by":{"listEntries":[
                            {"name":"Customer A","logo":"a.png"},
                            {"name":"Customer B","logo":"b.png"},
                            {"name":"Customer C","logo":"c.png"},
                            {"name":"Customer D","logo":"d.png"}
                        ]}
                    }}}
                }
            }}}}}}
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty(), "Should not detect entries without company.name as subprocessors");
    }

    #[test]
    fn test_probe_conveyor_detects_trust_center() {
        let html = r#"<html><body>
            <script>
            window.CANONICAL_ASSET = {"id":"abc-123","slug":"acme","name":"Acme Inc."};
            window.VENDOR_REPORT = {"_embedded":{"subprocessors":[
                {"id":"s1","canonical_asset_id":"ca1","description":"Cloud","data_locations":["US"]},
                {"id":"s2","canonical_asset_id":"ca2","description":"CDN","data_locations":["US"]},
                {"id":"s3","canonical_asset_id":"ca3","description":"Monitoring","data_locations":["US"]},
                {"id":"s4","canonical_asset_id":"ca4","description":"Auth","data_locations":["US"]}
            ],"canonical_assets":[
                {"id":"ca1","name":"AWS","website":"https://aws.amazon.com"},
                {"id":"ca2","name":"Cloudflare","website":"https://cloudflare.com"},
                {"id":"ca3","name":"Datadog","website":"https://datadoghq.com"},
                {"id":"ca4","name":"Okta","website":"https://okta.com"}
            ]}};
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_conveyor(html, &mut candidates);

        assert_eq!(candidates.len(), 1, "Should find one Conveyor trust center");
        let candidate = &candidates[0];
        assert_eq!(candidate.item_count, 4);
        assert!(candidate.score >= 0.9, "Conveyor probe should have high confidence");

        // Verify slug extraction
        assert_eq!(candidate.strategy.endpoint.slug, Some("acme".to_string()));

        // Verify API URL contains slug
        assert!(candidate.strategy.endpoint.url.contains("slug=acme"));

        // Verify it's a RestApi strategy
        match &candidate.strategy.strategy_type {
            StrategyType::RestApi { method, .. } => assert_eq!(method, "GET"),
            _ => panic!("Expected RestApi strategy"),
        }
    }

    #[test]
    fn test_probe_conveyor_skips_non_conveyor() {
        let html = r#"<html><body>
            <script>
            window.APP_CONFIG = {"key": "value"};
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_conveyor(html, &mut candidates);
        assert!(candidates.is_empty(), "Should not detect Conveyor on non-Conveyor pages");
    }

    #[test]
    fn test_probe_conveyor_handles_missing_slug() {
        // Conveyor page without CANONICAL_ASSET (should still detect but with empty URL)
        let html = r#"<html><body>
            <script>
            window.VENDOR_REPORT = {"_embedded":{"subprocessors":[
                {"id":"s1","canonical_asset_id":"ca1","description":"Cloud","data_locations":["US"]},
                {"id":"s2","canonical_asset_id":"ca2","description":"CDN","data_locations":["US"]},
                {"id":"s3","canonical_asset_id":"ca3","description":"Monitoring","data_locations":["US"]}
            ],"canonical_assets":[
                {"id":"ca1","name":"AWS","website":"https://aws.amazon.com"},
                {"id":"ca2","name":"Cloudflare","website":"https://cloudflare.com"},
                {"id":"ca3","name":"Datadog","website":"https://datadoghq.com"}
            ]}};
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_conveyor(html, &mut candidates);

        assert_eq!(candidates.len(), 1, "Should detect Conveyor even without slug");
        assert_eq!(candidates[0].strategy.endpoint.slug, None);
        assert!(candidates[0].strategy.endpoint.url.is_empty(), "URL should be empty without slug");
    }

    #[test]
    fn test_probe_conveyor_skips_few_subprocessors() {
        // Conveyor page with too few subprocessors
        let html = r#"<html><body>
            <script>
            window.VENDOR_REPORT = {"_embedded":{"subprocessors":[
                {"id":"s1","canonical_asset_id":"ca1","description":"Cloud","data_locations":["US"]}
            ],"canonical_assets":[
                {"id":"ca1","name":"AWS","website":"https://aws.amazon.com"}
            ]}};
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_conveyor(html, &mut candidates);
        assert!(candidates.is_empty(), "Should skip Conveyor with < 3 subprocessors");
    }

    #[test]
    fn test_extract_conveyor_slug() {
        let html = r#"window.CANONICAL_ASSET = {"id":"abc","slug":"conveyor","name":"Conveyor Inc."};"#;
        assert_eq!(extract_conveyor_slug(html), Some("conveyor".to_string()));

        let html_no_slug = r#"window.APP_CONFIG = {"key":"value"};"#;
        assert_eq!(extract_conveyor_slug(html_no_slug), None);
    }
}
