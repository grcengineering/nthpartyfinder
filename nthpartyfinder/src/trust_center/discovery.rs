//! Auto-discovery engine for trust center extraction strategies.
//!
//! When a domain has no cached strategy and the HTML looks like an SPA,
//! this module runs generic probes to discover the extraction strategy.

use anyhow::Result;

#[cfg(not(coverage))]
use std::sync::{Arc, Mutex};
#[cfg(not(coverage))]
use std::time::Duration;
use tracing::debug;

use super::{
    detect_field_mapping, find_entity_arrays, score_subprocessor_array, CandidateStrategy,
    DiscoveryMetadata, DiscoveryMethod, EndpointConfig, ResponseMapping, StrategyType,
    TrustCenterStrategy,
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
    let text_len = html
        .chars()
        .fold((0usize, false), |(count, in_tag), ch| match ch {
            '<' => (count, true),
            '>' => (count, false),
            _ if !in_tag => (count + 1, false),
            _ => (count, in_tag),
        })
        .0;

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
    let body_start = match html_lower.find("<body") {
        Some(pos) => pos,
        None => return false,
    };
    let body_tag_end = match html_lower[body_start..].find('>') {
        Some(pos) => pos,
        None => return false,
    };
    let body_content_start = body_start + body_tag_end + 1;
    let body_content = if let Some(body_end) = html_lower[body_content_start..].find("</body") {
        &html_lower[body_content_start..body_content_start + body_end]
    } else {
        &html_lower[body_content_start..]
    };

    let visible_tags = [
        "<div", "<p", "<table", "<section", "<article", "<main", "<h1", "<h2", "<h3", "<span",
        "<ul", "<ol", "<form",
    ];
    let has_visible_content = visible_tags.iter().any(|tag| body_content.contains(tag));

    if !has_visible_content && body_content.contains("<script") {
        debug!("SPA detected: body has no visible content elements, only scripts");
        return true;
    }

    false
}

// cfg(not(coverage)): orchestrates browser-based network interception — requires headless Chrome
#[cfg(not(coverage))]
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
    if let Some(best) = all_candidates.iter().max_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    }) {
        if best.score >= 0.7 {
            debug!(
                "Strong candidate found via HTML patterns (score: {:.2}), skipping browser probes",
                best.score
            );
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
    all_candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if let Some(best) = all_candidates.into_iter().next() {
        if best.score >= 0.4 {
            debug!(
                "Selected strategy with score {:.2}, {} items",
                best.score, best.item_count
            );
            return Ok(Some(best.strategy));
        }
        debug!("Best candidate score {:.2} below threshold 0.4", best.score);
    }

    Ok(None)
}

#[cfg(coverage)]
pub async fn discover_strategy(
    _url: &str,
    static_html: &str,
) -> Result<Option<TrustCenterStrategy>> {
    Ok(discover_via_html_patterns(static_html)?
        .into_iter()
        .max_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .filter(|c| c.score >= 0.4)
        .map(|c| c.strategy))
}

// cfg(not(coverage)): launches headless Chrome browser for network interception — requires browser
#[cfg(not(coverage))]
async fn discover_via_network_interception(url: &str) -> Result<Vec<CandidateStrategy>> {
    let responses = Arc::new(Mutex::new(Vec::<InterceptedResponse>::new()));
    let responses_clone = responses.clone();
    let url_owned = url.to_string();

    // headless_chrome operations are blocking, run in a blocking thread
    let handle = tokio::task::spawn_blocking(move || -> Result<Vec<InterceptedResponse>> {
        let guard = crate::browser_pool::create_browser()?;

        let tab = guard
            .browser
            .new_tab()
            .map_err(|e| anyhow::anyhow!("Failed to create tab: {}", e))?;

        // Register response handler to capture JSON API responses.
        // Handler signature: (ResponseReceivedEventParams, &dyn Fn() -> Result<GetResponseBodyReturnObject>)
        tab.register_response_handling(
            "trust_center_discovery",
            Box::new(move |event_params, fetch_body| {
                let resp = &event_params.response;
                let mime = &resp.mime_type;
                let resp_url = &resp.url;
                let status = resp.status;

                let is_json = mime.contains("json")
                    || resp_url.contains("graphql")
                    || resp_url.contains("/api/");

                if is_json && (200..300).contains(&status) {
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
            }),
        )
        .map_err(|e| anyhow::anyhow!("Failed to register response handler: {}", e))?;

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

    let collected_responses = handle
        .await
        .map_err(|e| anyhow::anyhow!("Blocking task panicked: {}", e))??;

    debug!("Intercepted {} JSON responses", collected_responses.len());
    analyze_intercepted_responses(&collected_responses, url)
}

#[cfg(coverage)]
async fn discover_via_network_interception(_url: &str) -> Result<Vec<CandidateStrategy>> {
    Ok(Vec::new())
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
    // Pattern is a hardcoded constant — compile failure is impossible
    let regex = fancy_regex::Regex::new(pattern).unwrap();

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

    // products is guaranteed to be an object by the is_object() guard above
    let products_map = products.as_object().unwrap();

    debug!("SafeBase: found {} products", products_map.len());

    // Iterate through all products to find subprocessor list items
    for (product_id, product_data) in products_map {
        let slug = product_data
            .get("slug")
            .and_then(|v| v.as_str())
            .unwrap_or(product_id);
        let product_name = product_data
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(slug);
        let show = product_data
            .get("show")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        if !show {
            debug!(
                "SafeBase: skipping hidden product '{}' (slug: {})",
                product_name, slug
            );
            continue;
        }

        debug!(
            "SafeBase: scanning product '{}' (id: {}, slug: {})",
            product_name, product_id, slug
        );

        // Look for subprocessor items in raw.spData.items
        let items = match super::navigate_json_path(product_data, "raw.spData.items") {
            Some(i) if i.is_object() => i,
            _ => continue,
        };

        // items is guaranteed to be an object by the is_object() guard above
        let items_map = items.as_object().unwrap();

        for (item_uid, item_data) in items_map {
            let list_entries = match item_data.get("listEntries").and_then(|v| v.as_array()) {
                Some(arr) if arr.len() >= 3 => arr,
                _ => continue,
            };

            // Verify entries look like subprocessor data (have company.name or name)
            let has_company = list_entries.iter().take(5).any(|entry| {
                entry
                    .get("company")
                    .and_then(|c| c.get("name"))
                    .and_then(|n| n.as_str())
                    .is_some_and(|s| !s.is_empty())
            });

            if !has_company {
                continue;
            }

            let entry_count = list_entries.len();
            debug!(
                "SafeBase: found {} subprocessor entries in product '{}', item {}",
                entry_count, product_name, item_uid
            );

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
///
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
        debug!(
            "Conveyor: found {} subprocessors, below threshold of 3",
            subprocessor_count
        );
        return;
    }

    debug!(
        "Conveyor: found {} subprocessors, slug={:?}",
        subprocessor_count, slug
    );

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
                evidence_fields: vec!["name".to_string(), "description".to_string()],
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
    json.get("slug")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Count the number of subprocessors in a Conveyor VENDOR_REPORT.
fn count_conveyor_subprocessors(html: &str) -> usize {
    let json = extract_js_object_assignment(html, "VENDOR_REPORT");
    match json {
        Some(j) => j
            .get("_embedded")
            .and_then(|e| e.get("subprocessors"))
            .and_then(|s| s.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
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
            '\\' if in_string => {
                escape_next = true;
            }
            '"' => {
                in_string = !in_string;
            }
            '{' if !in_string => {
                depth += 1;
            }
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
    // Selector is a hardcoded constant — parse failure is impossible
    let selector = scraper::Selector::parse(r#"script[type="application/json"]"#).unwrap();

    for (idx, script) in document.select(&selector).enumerate() {
        let text: String = script.text().collect();
        let trimmed = text.trim();

        if trimmed.len() < 50 {
            continue;
        }

        let json = match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(j) => j,
            Err(_) => continue,
        };
        let arrays = find_entity_arrays(&json, "");
        for (path, items) in &arrays {
            let score = score_subprocessor_array(items, path);
            if score < 0.4 {
                continue;
            }
            let field_mapping = detect_field_mapping(items);
            let name_field = match field_mapping.name_field {
                Some(n) => n,
                None => continue,
            };
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

/// Search for base64-encoded JSON blobs in HTML.
#[cfg_attr(coverage_nightly, coverage(off))]
fn probe_base64_blobs(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    use base64::Engine;

    let patterns = [
        r#"data-[a-z-]+="([A-Za-z0-9+/=]{200,})""#,
        r#"atob\s*\(\s*["']([A-Za-z0-9+/=]{200,})["']\s*\)"#,
        r#"(?:var|let|const)\s+\w+\s*=\s*["']([A-Za-z0-9+/=]{200,})["']"#,
    ];

    for pattern in &patterns {
        // All patterns are hardcoded constants — compile failure is impossible
        let regex = fancy_regex::Regex::new(pattern).unwrap();
        let mut search_start = 0;
        while search_start < html.len() {
            let search_slice = &html[search_start..];
            let captures = match regex.captures(search_slice) {
                Ok(Some(c)) => c,
                _ => break,
            };
            let b64_match = match captures.get(1) {
                Some(m) => m,
                None => break,
            };
            let b64_str = b64_match.as_str();

            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64_str) {
                if let Ok(json_str) = String::from_utf8(decoded) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        let arrays = find_entity_arrays(&json, "");
                        for (path, items) in &arrays {
                            let score = score_subprocessor_array(items, path);
                            if score < 0.4 {
                                continue;
                            }
                            let field_mapping = detect_field_mapping(items);
                            let name_field = match field_mapping.name_field {
                                Some(n) => n,
                                None => continue,
                            };
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

            search_start += b64_match.end();
        }
    }
}

/// Search for JavaScript object assignments like `window.VENDOR_REPORT = {...}`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn probe_js_object_assignments(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    let pattern = r#"window\.([A-Z_][A-Z_0-9]*)\s*=\s*(\{[\s\S]{200,}?\})(?:\s*;|\s*<)"#;
    // Pattern is a hardcoded constant — compile failure is impossible
    let regex = fancy_regex::Regex::new(pattern).unwrap();

    let mut search_start = 0;
    while search_start < html.len() {
        let search_slice = &html[search_start..];
        let captures = match regex.captures(search_slice) {
            Ok(Some(c)) => c,
            _ => break,
        };
        let var_name = captures.get(1).map(|m| m.as_str()).unwrap_or("UNKNOWN");
        let json_match = match captures.get(2) {
            Some(m) => m,
            None => break,
        };
        let json_str = json_match.as_str();

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
            let arrays = find_entity_arrays(&json, "");
            for (path, items) in &arrays {
                let score = score_subprocessor_array(items, path);
                if score < 0.4 {
                    continue;
                }
                let field_mapping = detect_field_mapping(items);
                let name_field = match field_mapping.name_field {
                    Some(n) => n,
                    None => continue,
                };
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

        search_start += json_match.end();
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
        let segments: Vec<&str> = parsed
            .path_segments()
            .map(|s| s.collect())
            .unwrap_or_default();

        // Common pattern: /slug/subprocessors or /slug/trust/subprocessors
        if segments.len() >= 2 {
            let first = segments[0];
            // Skip if it's a common non-slug path
            let non_slugs = [
                "api",
                "graphql",
                "trust",
                "security",
                "legal",
                "privacy",
                "subprocessors",
            ];
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
        assert_eq!(
            extract_slug_from_url("https://trust.vanta.com/acme/subprocessors"),
            Some("acme".to_string())
        );
        assert_eq!(
            extract_slug_from_url("https://trust.vanta.com/subprocessors"),
            None
        );
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

        assert_eq!(
            candidates.len(),
            1,
            "Should find exactly one subprocessor list"
        );
        let candidate = &candidates[0];
        assert_eq!(candidate.item_count, 4);
        assert!(
            candidate.score >= 0.9,
            "SafeBase probe should have high confidence"
        );

        // Verify field mapping
        assert_eq!(
            candidate.strategy.response_mapping.name_field,
            "company.name"
        );
        assert_eq!(
            candidate.strategy.response_mapping.url_field,
            Some("company.domain".to_string())
        );
        assert_eq!(
            candidate.strategy.response_mapping.purpose_field,
            Some("purpose".to_string())
        );
        assert_eq!(
            candidate.strategy.response_mapping.location_field,
            Some("location".to_string())
        );

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
        assert_eq!(
            candidates.len(),
            2,
            "Should find subprocessors from 2 visible products"
        );
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
        assert!(
            candidates.is_empty(),
            "Should not detect SafeBase on non-SafeBase pages"
        );
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
        assert!(
            candidates.is_empty(),
            "Should not detect entries without company.name as subprocessors"
        );
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
        assert!(
            candidate.score >= 0.9,
            "Conveyor probe should have high confidence"
        );

        // Verify slug extraction
        assert_eq!(candidate.strategy.endpoint.slug, Some("acme".to_string()));

        // Verify API URL contains slug
        assert!(candidate.strategy.endpoint.url.contains("slug=acme"));

        assert!(matches!(
            &candidate.strategy.strategy_type,
            StrategyType::RestApi { method, .. } if method == "GET"
        ));
    }

    #[test]
    fn test_probe_conveyor_skips_non_conveyor() {
        let html = r#"<html><body>
            <script>
            window.APP_CONFIG = {"key": "value"};
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_conveyor(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Should not detect Conveyor on non-Conveyor pages"
        );
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

        assert_eq!(
            candidates.len(),
            1,
            "Should detect Conveyor even without slug"
        );
        assert_eq!(candidates[0].strategy.endpoint.slug, None);
        assert!(
            candidates[0].strategy.endpoint.url.is_empty(),
            "URL should be empty without slug"
        );
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
        assert!(
            candidates.is_empty(),
            "Should skip Conveyor with < 3 subprocessors"
        );
    }

    #[test]
    fn test_extract_conveyor_slug() {
        let html =
            r#"window.CANONICAL_ASSET = {"id":"abc","slug":"conveyor","name":"Conveyor Inc."};"#;
        assert_eq!(extract_conveyor_slug(html), Some("conveyor".to_string()));

        let html_no_slug = r#"window.APP_CONFIG = {"key":"value"};"#;
        assert_eq!(extract_conveyor_slug(html_no_slug), None);
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    // --- is_likely_spa edge cases ---

    #[test]
    fn test_is_likely_spa_empty_html() {
        assert!(!is_likely_spa(""));
    }

    #[test]
    fn test_is_likely_spa_low_text_ratio() {
        // Construct HTML with lots of tags and very little text content
        let mut html = String::from("<html><head>");
        for _ in 0..200 {
            html.push_str("<link rel=\"stylesheet\" href=\"style.css\">");
        }
        html.push_str("</head><body>x</body></html>");
        // The text ratio should be very low, and html_len > 1000
        assert!(html.len() > 1000);
        assert!(is_likely_spa(&html));
    }

    #[test]
    fn test_is_likely_spa_framework_markers() {
        let markers = vec![
            r#"<div id="root"></div>"#,
            r#"<div data-reactroot></div>"#,
            r#"<script>window.__nuxt__={}</script>"#,
            r#"<div ng-app="myApp"></div>"#,
            r#"<div id="app"></div>"#,
        ];
        for marker_html in markers {
            let html = format!("<html><head></head><body>{}</body></html>", marker_html);
            assert!(
                is_likely_spa(&html),
                "Should detect SPA for marker: {}",
                marker_html
            );
        }
    }

    #[test]
    fn test_is_likely_spa_body_scripts_only() {
        // Body with only scripts and no visible content elements
        let html = r#"<html><head><title>Test</title></head>
            <body id="body">
            <script src="/bundle.js"></script>
            <script>window.init()</script>
            </body></html>"#;
        assert!(is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_body_with_visible_content() {
        // Body with div and scripts - should NOT be detected as SPA
        // because it has visible content elements
        let html = r#"<html><head><title>Test</title></head>
            <body>
            <div>Hello world</div>
            <script src="/bundle.js"></script>
            </body></html>"#;
        assert!(!is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_body_no_closing_tag() {
        // Body with scripts but no </body> closing tag - should still detect
        let html = r#"<html><head></head>
            <body>
            <script src="/app.js"></script>
            <script>init()</script>"#;
        assert!(is_likely_spa(html));
    }

    // --- extract_slug_from_url edge cases ---

    #[test]
    fn test_extract_slug_from_url_non_slug_paths() {
        // First path segment is a known non-slug
        assert_eq!(extract_slug_from_url("https://example.com/api/v1"), None);
        assert_eq!(
            extract_slug_from_url("https://example.com/trust/center"),
            None
        );
        assert_eq!(
            extract_slug_from_url("https://example.com/security/info"),
            None
        );
        assert_eq!(
            extract_slug_from_url("https://example.com/legal/terms"),
            None
        );
        assert_eq!(
            extract_slug_from_url("https://example.com/privacy/policy"),
            None
        );
        assert_eq!(
            extract_slug_from_url("https://example.com/subprocessors"),
            None
        );
    }

    #[test]
    fn test_extract_slug_from_url_with_slug() {
        assert_eq!(
            extract_slug_from_url("https://trust.vanta.com/mycompany/trust"),
            Some("mycompany".to_string())
        );
    }

    #[test]
    fn test_extract_slug_from_url_invalid_url() {
        assert_eq!(extract_slug_from_url("not-a-url"), None);
    }

    #[test]
    fn test_extract_slug_from_url_root_path() {
        // Single segment path
        assert_eq!(extract_slug_from_url("https://example.com/"), None);
    }

    // --- extract_graphql_operation ---

    #[test]
    fn test_extract_graphql_operation_with_operation_name() {
        assert_eq!(
            extract_graphql_operation(
                "https://api.example.com/graphql?operationName=GetSubprocessors"
            ),
            Some("GetSubprocessors".to_string())
        );
    }

    #[test]
    fn test_extract_graphql_operation_with_operation_param() {
        assert_eq!(
            extract_graphql_operation("https://api.example.com/graphql?operation=ListVendors"),
            Some("ListVendors".to_string())
        );
    }

    #[test]
    fn test_extract_graphql_operation_no_param() {
        assert_eq!(
            extract_graphql_operation("https://api.example.com/graphql"),
            None
        );
    }

    #[test]
    fn test_extract_graphql_operation_invalid_url() {
        assert_eq!(extract_graphql_operation("not-a-url"), None);
    }

    // --- extract_js_object_assignment ---

    #[test]
    fn test_extract_js_object_simple() {
        let html = r#"window.MY_VAR = {"key": "value"};"#;
        let result = extract_js_object_assignment(html, "MY_VAR");
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(val.get("key").unwrap().as_str().unwrap(), "value");
    }

    #[test]
    fn test_extract_js_object_nested_braces() {
        let html = r#"window.DATA = {"outer": {"inner": {"deep": true}}};"#;
        let result = extract_js_object_assignment(html, "DATA");
        assert!(result.is_some());
        let val = result.unwrap();
        assert!(val
            .get("outer")
            .unwrap()
            .get("inner")
            .unwrap()
            .get("deep")
            .unwrap()
            .as_bool()
            .unwrap());
    }

    #[test]
    fn test_extract_js_object_with_strings_containing_braces() {
        let html = r#"window.TEST = {"text": "hello {world}"};"#;
        let result = extract_js_object_assignment(html, "TEST");
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().get("text").unwrap().as_str().unwrap(),
            "hello {world}"
        );
    }

    #[test]
    fn test_extract_js_object_not_found() {
        let html = r#"window.OTHER = {"key": "value"};"#;
        assert!(extract_js_object_assignment(html, "MISSING").is_none());
    }

    #[test]
    fn test_extract_js_object_no_equals() {
        let html = r#"window.MY_VAR {"key": "value"};"#;
        assert!(extract_js_object_assignment(html, "MY_VAR").is_none());
    }

    #[test]
    fn test_extract_js_object_not_object() {
        let html = r#"window.MY_VAR = "string_value";"#;
        assert!(extract_js_object_assignment(html, "MY_VAR").is_none());
    }

    #[test]
    fn test_extract_js_object_with_escaped_quotes() {
        let html = r#"window.DATA = {"text": "say \"hello\""};"#;
        let result = extract_js_object_assignment(html, "DATA");
        assert!(result.is_some());
    }

    // --- count_conveyor_subprocessors ---

    #[test]
    fn test_count_conveyor_subprocessors_with_data() {
        let html = r#"window.VENDOR_REPORT = {"_embedded":{"subprocessors":[
            {"id":"s1"},{"id":"s2"},{"id":"s3"}
        ]}};"#;
        assert_eq!(count_conveyor_subprocessors(html), 3);
    }

    #[test]
    fn test_count_conveyor_subprocessors_no_report() {
        assert_eq!(count_conveyor_subprocessors("nothing here"), 0);
    }

    #[test]
    fn test_count_conveyor_subprocessors_no_embedded() {
        let html = r#"window.VENDOR_REPORT = {"data": "something"};"#;
        assert_eq!(count_conveyor_subprocessors(html), 0);
    }

    // --- discover_via_html_patterns ---

    #[test]
    fn test_discover_via_html_patterns_empty() {
        let result = discover_via_html_patterns("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_discover_via_html_patterns_plain_html() {
        let html = "<html><body><p>Hello world</p></body></html>";
        let result = discover_via_html_patterns(html).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_discover_via_html_patterns_safebase_takes_priority() {
        // SafeBase HTML should be detected by SafeBase probe, not generic Next.js probe
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme","show":true,
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"AWS","domain":"aws.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"GCP","domain":"cloud.google.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"Stripe","domain":"stripe.com"},"purpose":"Pay","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script></body></html>"#;

        let result = discover_via_html_patterns(html).unwrap();
        assert!(!result.is_empty());
        // The SafeBase candidate should have high score
        let best = result
            .iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .unwrap();
        assert!(best.score >= 0.9);
    }

    // --- probe_next_data edge cases ---

    #[test]
    fn test_probe_next_data_no_script() {
        assert!(probe_next_data("<html><body>no script</body></html>").is_none());
    }

    #[test]
    fn test_probe_next_data_invalid_json() {
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {invalid json}
            </script></body></html>"#;
        assert!(probe_next_data(html).is_none());
    }

    #[test]
    fn test_probe_next_data_no_arrays() {
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"title":"Hello"}}}
            </script></body></html>"#;
        assert!(probe_next_data(html).is_none());
    }

    #[test]
    fn test_probe_next_data_small_array_low_score() {
        // Array exists but doesn't look like subprocessors
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"items":[
                {"x":1}, {"x":2}, {"x":3}
            ]}}}
            </script></body></html>"#;
        // These items have no name/url/purpose fields, so score will be low
        assert!(probe_next_data(html).is_none());
    }

    // --- probe_json_script_tags ---

    #[test]
    fn test_probe_json_script_tags_empty() {
        let mut candidates = Vec::new();
        probe_json_script_tags("<html><body></body></html>", &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_json_script_tags_short_content() {
        let html = r#"<html><body>
            <script type="application/json">{"a":1}</script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(candidates.is_empty()); // Too short (< 50 chars)
    }

    #[test]
    fn test_probe_json_script_tags_with_subprocessor_data() {
        let html = r#"<html><body>
            <script type="application/json">
            {"subprocessors":[
                {"name":"AWS","url":"https://aws.amazon.com","purpose":"Cloud infrastructure"},
                {"name":"Cloudflare","url":"https://cloudflare.com","purpose":"CDN and security"},
                {"name":"Datadog","url":"https://datadoghq.com","purpose":"Monitoring services"},
                {"name":"Stripe","url":"https://stripe.com","purpose":"Payment processing"},
                {"name":"Google","url":"https://google.com","purpose":"Analytics and search"}
            ]}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(!candidates.is_empty());
        assert!(candidates[0].score >= 0.4);
    }

    #[test]
    fn test_probe_json_script_tags_invalid_json() {
        let html = r#"<html><body>
            <script type="application/json">
            this is not json but it is longer than fifty characters so it will attempt to parse
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    // --- probe_base64_blobs ---

    #[test]
    fn test_probe_base64_blobs_empty() {
        let mut candidates = Vec::new();
        probe_base64_blobs("<html><body></body></html>", &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_base64_blobs_with_valid_data() {
        use base64::Engine;
        let json_data = serde_json::json!({"vendors":[
            {"name":"AWS","url":"https://aws.amazon.com","purpose":"Cloud infrastructure hosting"},
            {"name":"Cloudflare","url":"https://cloudflare.com","purpose":"CDN and DDoS protection"},
            {"name":"Datadog","url":"https://datadoghq.com","purpose":"Application monitoring"},
            {"name":"Stripe","url":"https://stripe.com","purpose":"Payment processing"},
            {"name":"Okta","url":"https://okta.com","purpose":"Identity management"}
        ]});
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(json_data.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var data = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(!candidates.is_empty());
    }

    #[test]
    fn test_probe_base64_blobs_invalid_base64() {
        // atob with non-base64 content
        let html = r#"<html><body><script>var x = atob("!!!not-base64-at-all-but-long-enough-to-match-the-regex-pattern-here!!!");</script></body></html>"#;
        let mut candidates = Vec::new();
        probe_base64_blobs(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    // --- probe_js_object_assignments ---

    #[test]
    fn test_probe_js_object_assignments_empty() {
        let mut candidates = Vec::new();
        probe_js_object_assignments("<html><body></body></html>", &mut candidates);
        assert!(candidates.is_empty());
    }

    // --- analyze_intercepted_responses ---

    #[test]
    fn test_analyze_intercepted_responses_empty() {
        let result = analyze_intercepted_responses(&[], "https://example.com").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_analyze_intercepted_responses_invalid_json() {
        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/data".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body: "not valid json".to_string(),
            request_url: "https://api.example.com/data".to_string(),
            request_method: "GET".to_string(),
            request_body: None,
        }];
        let result = analyze_intercepted_responses(&responses, "https://example.com").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_analyze_intercepted_responses_with_subprocessors() {
        let body = serde_json::json!({
            "subprocessors": [
                {"name": "AWS", "url": "https://aws.amazon.com", "purpose": "Cloud hosting and infrastructure"},
                {"name": "Cloudflare", "url": "https://cloudflare.com", "purpose": "CDN and security services"},
                {"name": "Datadog", "url": "https://datadoghq.com", "purpose": "Application monitoring tools"},
                {"name": "Stripe", "url": "https://stripe.com", "purpose": "Payment processing services"},
                {"name": "Google", "url": "https://google.com", "purpose": "Analytics and advertising"}
            ]
        }).to_string();

        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/trust/data".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body,
            request_url: "https://api.example.com/trust/data".to_string(),
            request_method: "GET".to_string(),
            request_body: None,
        }];

        let result = analyze_intercepted_responses(
            &responses,
            "https://trust.example.com/acme/subprocessors",
        )
        .unwrap();
        assert!(!result.is_empty());
        let candidate = &result[0];
        assert!(candidate.score >= 0.4);
        assert_eq!(candidate.item_count, 5);
        // Should extract slug from page URL
        assert_eq!(candidate.strategy.endpoint.slug, Some("acme".to_string()));
    }

    #[test]
    fn test_analyze_intercepted_responses_graphql_url() {
        let body = serde_json::json!({
            "data": {
                "vendors": [
                    {"name": "AWS", "url": "https://aws.amazon.com", "purpose": "Cloud"},
                    {"name": "GCP", "url": "https://cloud.google.com", "purpose": "Cloud"},
                    {"name": "Azure", "url": "https://azure.microsoft.com", "purpose": "Cloud"},
                    {"name": "Stripe", "url": "https://stripe.com", "purpose": "Payments"},
                    {"name": "Datadog", "url": "https://datadoghq.com", "purpose": "Monitoring"}
                ]
            }
        })
        .to_string();

        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/graphql?operationName=GetVendors".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body,
            request_url: "https://api.example.com/graphql?operationName=GetVendors".to_string(),
            request_method: "POST".to_string(),
            request_body: Some(r#"{"query":"query GetVendors { vendors { name } }"}"#.to_string()),
        }];

        let result =
            analyze_intercepted_responses(&responses, "https://trust.example.com/subprocessors")
                .unwrap();
        assert!(!result.is_empty());
        let candidate = &result[0];
        assert!(matches!(
            &candidate.strategy.strategy_type,
            StrategyType::GraphqlApi { operation_name, .. }
                if operation_name.as_deref() == Some("GetVendors")
        ));
    }

    #[test]
    fn test_analyze_intercepted_responses_low_score_skipped() {
        // JSON with arrays but no name/url fields - low score
        let body = serde_json::json!({
            "numbers": [
                {"x": 1, "y": 2},
                {"x": 3, "y": 4},
                {"x": 5, "y": 6},
                {"x": 7, "y": 8},
                {"x": 9, "y": 10}
            ]
        })
        .to_string();

        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/data".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body,
            request_url: "https://api.example.com/data".to_string(),
            request_method: "GET".to_string(),
            request_body: None,
        }];

        let result = analyze_intercepted_responses(&responses, "https://example.com").unwrap();
        // The items don't have name fields, so they should score below 0.4 and be skipped
        assert!(result.is_empty());
    }

    // --- discover_strategy ---

    #[tokio::test]
    async fn test_discover_strategy_strong_html_candidate() {
        // If HTML patterns find a strong candidate (score >= 0.7),
        // it should return immediately without browser probes
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"test","name":"Test","show":true,
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"A","domain":"a.com"},"purpose":"P","location":"US"},
                            {"company":{"name":"B","domain":"b.com"},"purpose":"P","location":"US"},
                            {"company":{"name":"C","domain":"c.com"},"purpose":"P","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script></body></html>"#;

        let result = discover_strategy("https://trust.example.com/test", html)
            .await
            .unwrap();
        assert!(result.is_some());
        let strategy = result.unwrap();
        assert!(matches!(
            &strategy.strategy_type,
            StrategyType::HydrationData { .. }
        ));
    }

    #[tokio::test]
    async fn test_discover_strategy_no_candidates() {
        let html = "<html><body><p>Nothing useful here</p></body></html>";
        let result = discover_strategy("https://example.com/page", html)
            .await
            .unwrap();
        // No network interception candidates either (browser won't launch in test),
        // so result should be None
        assert!(result.is_none());
    }

    // --- SafeBase edge cases ---

    #[test]
    fn test_probe_safebase_missing_next_data() {
        // Has __SB_CONFIG__ but no __NEXT_DATA__
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {"NEXT_PUBLIC_SITE":"https://app.safebase.io"};</script>
            <div id="__next">Hello</div>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_invalid_json() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {invalid json content here}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_no_products() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_product_no_items() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"test","name":"Test","show":true,
                    "raw":{"spData":{}}
                }
            }}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_too_few_entries() {
        // listEntries with fewer than 3 items should be skipped
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"test","name":"Test","show":true,
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"A","domain":"a.com"},"purpose":"P","location":"US"},
                            {"company":{"name":"B","domain":"b.com"},"purpose":"P","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_product_default_show() {
        // Product without explicit "show" field should default to true
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme",
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"AWS","domain":"aws.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"GCP","domain":"gcp.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"Azure","domain":"azure.com"},"purpose":"Cloud","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert_eq!(
            candidates.len(),
            1,
            "Product without 'show' should default to visible"
        );
    }

    // ====================================================================
    // Coverage gap tests — target remaining uncovered lines
    // ====================================================================

    // --- probe_base64_blobs: data-attribute pattern ---

    #[test]
    fn test_probe_base64_blobs_data_attribute_pattern() {
        use base64::Engine;
        let json_data = serde_json::json!({"vendors":[
            {"name":"Acme Cloud","url":"https://acmecloud.io","purpose":"Cloud infrastructure provider"},
            {"name":"SecureAuth","url":"https://secureauth.io","purpose":"Authentication service provider"},
            {"name":"DataVault","url":"https://datavault.io","purpose":"Data storage and processing"},
            {"name":"NetShield","url":"https://netshield.io","purpose":"Network security protection"},
            {"name":"LogStream","url":"https://logstream.io","purpose":"Log aggregation and monitoring"}
        ]});
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(json_data.to_string().as_bytes());
        let html = format!(
            r#"<html><body><div data-config="{}"></div></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find subprocessors in data-attribute base64"
        );
        assert!(matches!(
            &candidates[0].strategy.strategy_type,
            StrategyType::EmbeddedBase64Json { locator_pattern } if locator_pattern.contains("data-")
        ));
    }

    #[test]
    fn test_probe_base64_blobs_variable_assignment_pattern() {
        use base64::Engine;
        let json_data = serde_json::json!({"processors":[
            {"name":"CloudHost","url":"https://cloudhost.io","purpose":"Hosting infrastructure services"},
            {"name":"PayGate","url":"https://paygate.io","purpose":"Payment gateway integration"},
            {"name":"MailPush","url":"https://mailpush.io","purpose":"Email delivery service provider"},
            {"name":"CDNFast","url":"https://cdnfast.io","purpose":"Content delivery network services"},
            {"name":"DBScale","url":"https://dbscale.io","purpose":"Database scaling and management"}
        ]});
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(json_data.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var subprocessorData = "{}";</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find subprocessors in var-assignment base64"
        );
    }

    #[test]
    fn test_probe_base64_blobs_non_utf8_decoded() {
        use base64::Engine;
        // Valid base64 that decodes to non-UTF8 bytes
        let non_utf8: Vec<u8> = [0xFF, 0xFE, 0xFD]
            .iter()
            .copied()
            .cycle()
            .take(300)
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&non_utf8);
        let html = format!(
            r#"<html><body><script>var x = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Non-UTF8 decoded base64 should be skipped"
        );
    }

    #[test]
    fn test_probe_base64_blobs_valid_json_but_no_arrays() {
        use base64::Engine;
        let json_data = serde_json::json!({"key": "value", "number": 42});
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(json_data.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var data = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "JSON without arrays should yield no candidates"
        );
    }

    #[test]
    fn test_probe_base64_blobs_valid_json_low_score_array() {
        use base64::Engine;
        // Arrays with items that have no name/url fields -> low score
        let json_data = serde_json::json!({"items":[
            {"x": 1, "y": 2},
            {"x": 3, "y": 4},
            {"x": 5, "y": 6},
            {"x": 7, "y": 8},
            {"x": 9, "y": 10}
        ]});
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(json_data.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var data = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Low-score arrays should be filtered out"
        );
    }

    #[test]
    fn test_probe_base64_blobs_multiple_matches() {
        use base64::Engine;
        let json1 = serde_json::json!({"vendors":[
            {"name":"A1","url":"https://a1.io","purpose":"Service A1 provides hosting"},
            {"name":"B1","url":"https://b1.io","purpose":"Service B1 provides hosting"},
            {"name":"C1","url":"https://c1.io","purpose":"Service C1 provides hosting"},
            {"name":"D1","url":"https://d1.io","purpose":"Service D1 provides hosting"},
            {"name":"E1","url":"https://e1.io","purpose":"Service E1 provides hosting"}
        ]});
        let json2 = serde_json::json!({"vendors":[
            {"name":"A2","url":"https://a2.io","purpose":"Service A2 provides storage"},
            {"name":"B2","url":"https://b2.io","purpose":"Service B2 provides storage"},
            {"name":"C2","url":"https://c2.io","purpose":"Service C2 provides storage"},
            {"name":"D2","url":"https://d2.io","purpose":"Service D2 provides storage"},
            {"name":"E2","url":"https://e2.io","purpose":"Service E2 provides storage"}
        ]});
        let b64_1 = base64::engine::general_purpose::STANDARD.encode(json1.to_string().as_bytes());
        let b64_2 = base64::engine::general_purpose::STANDARD.encode(json2.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var first = atob("{}"); var second = atob("{}");</script></body></html>"#,
            b64_1, b64_2
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        let count = candidates.len();
        assert!(
            count >= 2,
            "Should find candidates from multiple base64 blobs, got {count}"
        );
    }

    // --- probe_js_object_assignments: successful match ---

    #[test]
    fn test_probe_js_object_assignments_with_subprocessors() {
        // Build a JSON blob with subprocessor-like data, > 200 chars, ending with };
        let json_obj = serde_json::json!({
            "subprocessors": [
                {"name": "AWS Infrastructure", "url": "https://aws.amazon.com", "purpose": "Cloud infrastructure hosting services"},
                {"name": "Cloudflare CDN", "url": "https://cloudflare.com", "purpose": "Content delivery network and DDoS protection"},
                {"name": "Datadog Monitoring", "url": "https://datadoghq.com", "purpose": "Application performance monitoring tools"},
                {"name": "Stripe Payments", "url": "https://stripe.com", "purpose": "Payment processing and billing services"},
                {"name": "Okta Identity", "url": "https://okta.com", "purpose": "Identity and access management provider"}
            ]
        });
        let json_str = json_obj.to_string();
        let html = format!(
            r#"<html><body><script>window.TRUST_DATA = {};</script></body></html>"#,
            json_str
        );
        let mut candidates = Vec::new();
        probe_js_object_assignments(&html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find subprocessors in window.TRUST_DATA assignment"
        );
        assert!(matches!(
            &candidates[0].strategy.strategy_type,
            StrategyType::EmbeddedJsObject { locator_pattern } if locator_pattern.contains("TRUST_DATA")
        ));
    }

    #[test]
    fn test_probe_js_object_assignments_low_score_skipped() {
        // JSON blob with arrays that don't look like subprocessors
        let json_obj = serde_json::json!({
            "items": [
                {"x": 1, "y": 2, "z": "padding to make this longer than needed for the minimum"},
                {"x": 3, "y": 4, "z": "padding to make this longer than needed for the minimum"},
                {"x": 5, "y": 6, "z": "padding to make this longer than needed for the minimum"},
                {"x": 7, "y": 8, "z": "padding to make this longer than needed for the minimum"},
                {"x": 9, "y": 10, "z": "padding to make this longer than needed for the minimum"}
            ]
        });
        let json_str = json_obj.to_string();
        let html = format!(
            r#"<html><body><script>window.APP_DATA = {};</script></body></html>"#,
            json_str
        );
        let mut candidates = Vec::new();
        probe_js_object_assignments(&html, &mut candidates);
        assert!(candidates.is_empty(), "Low-score arrays should be skipped");
    }

    #[test]
    fn test_probe_js_object_assignments_invalid_json_content() {
        // The regex captures something that looks like JSON but isn't valid
        // The regex pattern requires at least 200 chars inside the braces
        let padding = "x".repeat(250);
        let html = format!(
            r#"<html><body><script>window.BAD_DATA = {{"not_valid": "{}"}};</script></body></html>"#,
            padding
        );
        let mut candidates = Vec::new();
        probe_js_object_assignments(&html, &mut candidates);
        // May or may not parse, but shouldn't panic
    }

    // --- analyze_intercepted_responses: no name_field continue path ---

    #[test]
    fn test_analyze_intercepted_responses_no_name_field() {
        // Array with good score but no identifiable name field -> continue
        let body = serde_json::json!({
            "subprocessors": [
                {"id": 1, "category": "infrastructure", "status": "active", "region": "us-east-1", "tier": "premium"},
                {"id": 2, "category": "security", "status": "active", "region": "eu-west-1", "tier": "standard"},
                {"id": 3, "category": "monitoring", "status": "active", "region": "ap-south-1", "tier": "premium"},
                {"id": 4, "category": "networking", "status": "active", "region": "us-west-2", "tier": "standard"},
                {"id": 5, "category": "database", "status": "active", "region": "eu-central-1", "tier": "premium"}
            ]
        })
        .to_string();

        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/data".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body,
            request_url: "https://api.example.com/data".to_string(),
            request_method: "GET".to_string(),
            request_body: None,
        }];

        let result = analyze_intercepted_responses(&responses, "https://example.com").unwrap();
        // "subprocessors" path keyword might boost score but items lack a "name" field,
        // so detect_field_mapping returns None for name_field -> continue
        assert!(
            result.is_empty(),
            "Items without a name field should be skipped"
        );
    }

    #[test]
    fn test_analyze_intercepted_responses_rest_with_request_body() {
        let body = serde_json::json!({
            "vendors": [
                {"name": "CloudHost Inc", "url": "https://cloudhost.io", "purpose": "Cloud hosting infrastructure services"},
                {"name": "SecureNet LLC", "url": "https://securenet.io", "purpose": "Network security and monitoring"},
                {"name": "DataSync Corp", "url": "https://datasync.io", "purpose": "Data synchronization services"},
                {"name": "PayFlow Ltd", "url": "https://payflow.io", "purpose": "Payment processing and billing"},
                {"name": "LogAnalytics", "url": "https://loganalytics.io", "purpose": "Log aggregation and analysis"}
            ]
        })
        .to_string();

        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/api/vendors".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body,
            request_url: "https://api.example.com/api/vendors".to_string(),
            request_method: "POST".to_string(),
            request_body: Some(r#"{"filter": "active"}"#.to_string()),
        }];

        let result =
            analyze_intercepted_responses(&responses, "https://example.com/mycompany/trust")
                .unwrap();
        assert!(!result.is_empty());
        let candidate = &result[0];
        assert!(matches!(
            &candidate.strategy.strategy_type,
            StrategyType::RestApi { method, body_template, .. }
                if method == "POST" && body_template.is_some()
        ));
    }

    // --- discover_strategy: weak candidates below threshold ---

    #[tokio::test]
    async fn test_discover_strategy_weak_candidate_below_threshold() {
        // HTML with a next_data blob that has items scoring between 0.4 and 0.7
        // The score depends on the array data; items with name fields but low count
        // will score moderately. With score < 0.7, it tries network interception.
        // Network interception will fail in test (no browser), so we check if
        // the weak candidate is still returned (if score >= 0.4).
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"vendors":[
                {"name":"Vendor A","url":"https://a.com","purpose":"Service A provides hosting"},
                {"name":"Vendor B","url":"https://b.com","purpose":"Service B provides storage"},
                {"name":"Vendor C","url":"https://c.com","purpose":"Service C provides compute"},
                {"name":"Vendor D","url":"https://d.com","purpose":"Service D provides network"},
                {"name":"Vendor E","url":"https://e.com","purpose":"Service E provides backup"}
            ]}}}
            </script></body></html>"#;

        let result = discover_strategy("https://example.com/trust", html)
            .await
            .unwrap();
        // The HTML candidate might score >= 0.4 (subprocessors path keyword in data),
        // and network interception will fail. If HTML score >= 0.4 it gets returned.
        // If not, result is None. Either way, it should not panic.
        assert!(
            result.is_none()
                || matches!(
                    &result.as_ref().unwrap().strategy_type,
                    StrategyType::HydrationData { .. }
                )
        );
    }

    #[tokio::test]
    async fn test_discover_strategy_empty_html() {
        let result = discover_strategy("https://example.com", "").await.unwrap();
        assert!(result.is_none());
    }

    // --- is_likely_spa: additional body parsing edge cases ---

    #[test]
    fn test_is_likely_spa_body_no_gt_after_body_tag() {
        // <body without closing > — find('>') fails on the truncated content
        let html = "<html><head></head><body";
        assert!(!is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_body_with_noscript_and_scripts() {
        // Body with noscript and scripts but no visible elements
        let html = r#"<html><head></head>
            <body>
            <noscript>Enable JavaScript</noscript>
            <script src="/app.js"></script>
            </body></html>"#;
        assert!(is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_short_html_low_ratio() {
        // Short HTML (< 1000 chars) with low text ratio - should NOT trigger
        // the text ratio check because html_len must be > 1000
        let html = "<html><head></head><body></body></html>";
        assert!(!is_likely_spa(html));
    }

    // --- InterceptedResponse derive coverage ---

    #[test]
    fn test_intercepted_response_debug_clone() {
        let resp = InterceptedResponse {
            url: "https://api.example.com/data".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body: r#"{"data":[]}"#.to_string(),
            request_url: "https://api.example.com/data".to_string(),
            request_method: "GET".to_string(),
            request_body: None,
        };
        let cloned = resp.clone();
        assert_eq!(cloned.url, resp.url);
        assert_eq!(cloned.status, resp.status);
        let debug_str = format!("{:?}", resp);
        assert!(debug_str.contains("InterceptedResponse"));
    }

    // --- probe_json_script_tags: array with name field but no name detected ---

    #[test]
    fn test_probe_json_script_tags_high_score_no_name_field() {
        // Items in the subprocessors path but without a recognizable name field
        let html = r#"<html><body>
            <script type="application/json">
            {"subprocessors":[
                {"id":1,"category":"infra","status":"active","region":"us-east","tier":"premium","code":"AAA"},
                {"id":2,"category":"security","status":"active","region":"eu-west","tier":"standard","code":"BBB"},
                {"id":3,"category":"monitoring","status":"active","region":"ap-south","tier":"premium","code":"CCC"},
                {"id":4,"category":"network","status":"active","region":"us-west","tier":"standard","code":"DDD"},
                {"id":5,"category":"database","status":"active","region":"eu-central","tier":"premium","code":"EEE"}
            ]}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        // The path "subprocessors" boosts the score, but items lack a name field,
        // so detect_field_mapping returns None -> skipped
        assert!(
            candidates.is_empty(),
            "Items without name field should be skipped"
        );
    }

    // --- probe_next_data: array with good score but no name field ---

    #[test]
    fn test_probe_next_data_good_score_no_name_field() {
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"subprocessors":[
                {"id":1,"category":"infra","status":"active","region":"us-east","tier":"premium","code":"X1"},
                {"id":2,"category":"security","status":"active","region":"eu-west","tier":"standard","code":"X2"},
                {"id":3,"category":"monitoring","status":"active","region":"ap-south","tier":"premium","code":"X3"},
                {"id":4,"category":"network","status":"active","region":"us-west","tier":"standard","code":"X4"},
                {"id":5,"category":"database","status":"active","region":"eu-central","tier":"premium","code":"X5"}
            ]}}}
            </script></body></html>"#;
        // "subprocessors" in path boosts score but no name field -> returns None
        assert!(probe_next_data(html).is_none());
    }

    // --- extract_slug_from_url: URL with empty first segment ---

    #[test]
    fn test_extract_slug_from_url_graphql_path() {
        assert_eq!(
            extract_slug_from_url("https://example.com/graphql/query"),
            None
        );
    }

    // --- extract_js_object_assignment: escaped backslash at end of string ---

    #[test]
    fn test_extract_js_object_assignment_escaped_backslash() {
        let html = r#"window.CFG = {"path": "C:\\Users\\test"};"#;
        let result = extract_js_object_assignment(html, "CFG");
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().get("path").unwrap().as_str().unwrap(),
            "C:\\Users\\test"
        );
    }

    #[test]
    fn test_extract_js_object_assignment_unbalanced_braces() {
        // Opening brace but never closes — should return None
        let html = r#"window.BAD = {"key": "value"  "#;
        assert!(extract_js_object_assignment(html, "BAD").is_none());
    }

    // --- Conveyor: edge case where VENDOR_REPORT has no _embedded ---

    #[test]
    fn test_count_conveyor_subprocessors_no_subprocessors_key() {
        let html = r#"window.VENDOR_REPORT = {"_embedded": {"assets": []}};"#;
        assert_eq!(count_conveyor_subprocessors(html), 0);
    }

    // --- probe_safebase: products is not an object ---

    #[test]
    fn test_probe_safebase_products_not_object() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":"not_an_object"}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    // --- probe_safebase: product where slug is absent (uses product_id as slug) ---

    #[test]
    fn test_probe_safebase_product_no_slug_uses_product_id() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "my_product_id":{
                    "id":"my_product_id","show":true,
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"AWS","domain":"aws.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"GCP","domain":"gcp.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"Azure","domain":"azure.com"},"purpose":"Cloud","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert_eq!(candidates.len(), 1);
        // Slug should be the product_id since there's no explicit slug field
        assert_eq!(
            candidates[0].strategy.endpoint.slug,
            Some("my_product_id".to_string())
        );
    }

    // --- probe_safebase: items map exists but individual item has no listEntries ---

    #[test]
    fn test_probe_safebase_item_without_list_entries() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme","show":true,
                    "raw":{"spData":{"items":{
                        "uid-1":{"text":{"title":"Section Header"}}
                    }}}
                }
            }}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    // --- discover_via_html_patterns: all probes run in sequence ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_via_html_patterns_conveyor_takes_priority() {
        // Conveyor HTML should be detected by Conveyor probe
        let html = r#"<html><body>
            <script>
            window.CANONICAL_ASSET = {"slug":"myco"};
            window.VENDOR_REPORT = {"_embedded":{"subprocessors":[
                {"id":"s1","canonical_asset_id":"ca1","description":"Cloud hosting","data_locations":["US"]},
                {"id":"s2","canonical_asset_id":"ca2","description":"CDN service","data_locations":["US"]},
                {"id":"s3","canonical_asset_id":"ca3","description":"Monitoring","data_locations":["US"]}
            ],"canonical_assets":[
                {"id":"ca1","name":"AWS","website":"https://aws.amazon.com"},
                {"id":"ca2","name":"Cloudflare","website":"https://cloudflare.com"},
                {"id":"ca3","name":"Datadog","website":"https://datadoghq.com"}
            ]}};
            </script></body></html>"#;

        let result = discover_via_html_patterns(html).unwrap();
        assert!(!result.is_empty());
        let best = result
            .iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .unwrap();
        assert!(best.score >= 0.9);
        // Verify it's a RestApi (Conveyor uses REST)
        assert!(matches!(
            &best.strategy.strategy_type,
            StrategyType::RestApi { method, .. } if method == "GET"
        ));
    }

    // --- probe_base64_blobs: valid base64 but not valid JSON ---

    #[test]
    fn test_probe_base64_blobs_valid_base64_not_json() {
        use base64::Engine;
        let text = "This is just plain text, not JSON at all, and we need to make it long enough to match the regex pattern threshold of 200 characters so lets keep typing more text here to pad it out sufficiently for the test case to work properly with our regex matching requirements";
        let b64 = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
        let html = format!(
            r#"<html><body><script>var data = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Non-JSON base64 should produce no candidates"
        );
    }

    // --- probe_json_script_tags: multiple scripts, one with valid data ---

    #[test]
    fn test_probe_json_script_tags_multiple_scripts() {
        let html = r#"<html><body>
            <script type="application/json">{"small": true}</script>
            <script type="application/json">
            {"vendors":[
                {"name":"AWS Cloud Services","url":"https://aws.amazon.com","purpose":"Cloud infrastructure and hosting"},
                {"name":"Cloudflare Inc","url":"https://cloudflare.com","purpose":"CDN and DDoS protection"},
                {"name":"Datadog Inc","url":"https://datadoghq.com","purpose":"Application monitoring"},
                {"name":"Stripe Inc","url":"https://stripe.com","purpose":"Payment processing"},
                {"name":"Okta Inc","url":"https://okta.com","purpose":"Identity management"}
            ]}
            </script>
            <script type="application/json">{"another": "small one with not enough content"}</script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find data in second script tag"
        );
    }

    // --- extract_graphql_operation: URL with other query params ---

    #[test]
    fn test_extract_graphql_operation_multiple_params() {
        assert_eq!(
            extract_graphql_operation(
                "https://api.example.com/graphql?version=2&operationName=FetchAll&limit=100"
            ),
            Some("FetchAll".to_string())
        );
    }

    // --- extract_slug_from_url: URL without path segments ---

    #[test]
    fn test_extract_slug_from_url_no_path() {
        assert_eq!(extract_slug_from_url("https://example.com"), None);
    }

    #[test]
    fn test_extract_slug_from_url_empty_first_segment() {
        // URL like "https://example.com//something" — first segment is empty
        assert_eq!(
            extract_slug_from_url("https://example.com//something"),
            None
        );
    }

    #[test]
    fn test_is_likely_spa_empty_html_returns_false() {
        assert!(!is_likely_spa(""));
    }

    #[test]
    fn test_is_likely_spa_framework_marker_react() {
        let html = r#"<html><head></head><body><div data-reactroot>Loading...</div></body></html>"#;
        assert!(is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_framework_marker_nuxt() {
        let html = r#"<html><body><script>window.__nuxt__={config:{}}</script></body></html>"#;
        assert!(is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_framework_marker_angular() {
        let html = r#"<html><body ng-app="myApp"><div></div></body></html>"#;
        assert!(is_likely_spa(html));
    }

    #[test]
    fn test_probe_safebase_no_config_exits_early() {
        let html = r#"<html><body><h1>Regular page</h1></body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "No __SB_CONFIG__ means no candidates"
        );
    }

    #[test]
    fn test_probe_js_object_assignments_no_match() {
        let html = r#"<html><body><script>var x = 42;</script></body></html>"#;
        let mut candidates = Vec::new();
        probe_js_object_assignments(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Simple JS assignment should not match"
        );
    }

    #[test]
    fn test_probe_base64_blobs_no_base64_content() {
        let html = r#"<html><body><p>Just a normal page with no base64</p></body></html>"#;
        let mut candidates = Vec::new();
        probe_base64_blobs(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "No base64 content means no candidates"
        );
    }

    #[test]
    fn test_probe_json_script_tags_no_json_scripts() {
        let html = r#"<html><body><script>console.log("hello")</script></body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "No application/json scripts means no candidates"
        );
    }

    #[tokio::test]
    async fn test_discover_via_network_interception_coverage_stub() {
        let result = discover_via_network_interception("https://example.com").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_is_likely_spa_body_visible_content_with_scripts() {
        let html = r#"<html><head></head><body><div>Content here for real page with substantial text that is not a single page application at all</div><script src="/app.js"></script></body></html>"#;
        assert!(!is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_body_without_scripts() {
        let html = r#"<html><head></head><body><p>Just text content, no scripts here at all, this is a static page.</p></body></html>"#;
        assert!(!is_likely_spa(html));
    }

    #[test]
    fn test_probe_safebase_invalid_regex_resilience() {
        let html = "__SB_CONFIG__";
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_products_not_object_but_present() {
        let html = r#"<html>__SB_CONFIG__<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"orgInfo":{"sp":{"products":"not_an_object"}}}}}</script></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_items_not_object_in_product() {
        let next_data = serde_json::json!({
            "props": {
                "pageProps": {
                    "orgInfo": {
                        "sp": {
                            "products": {
                                "prod1": {
                                    "slug": "test",
                                    "visibilityStatus": "visible",
                                    "raw": {
                                        "spData": {
                                            "items": "not_an_object"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let html = format!(
            r#"<html>__SB_CONFIG__<script id="__NEXT_DATA__" type="application/json">{}</script></html>"#,
            next_data
        );
        let mut candidates = Vec::new();
        probe_safebase(&html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_base64_blobs_valid_json_high_score_with_name() {
        use base64::Engine;
        let json = serde_json::json!({
            "subprocessors": [
                {"name": "AWS", "url": "https://aws.amazon.com", "purpose": "Cloud"},
                {"name": "GCP", "url": "https://cloud.google.com", "purpose": "Cloud"},
                {"name": "Azure", "url": "https://azure.microsoft.com", "purpose": "Cloud"},
                {"name": "Datadog", "url": "https://datadoghq.com", "purpose": "Monitoring"},
                {"name": "Stripe", "url": "https://stripe.com", "purpose": "Payments"}
            ]
        });
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var data = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find candidate from base64 blob with subprocessor data"
        );
    }

    #[test]
    fn test_probe_js_object_assignments_high_score_with_name() {
        let json_obj = serde_json::json!({
            "subprocessors": [
                {"name": "AWS Infrastructure", "url": "https://aws.amazon.com", "purpose": "Cloud infrastructure hosting services"},
                {"name": "Cloudflare CDN", "url": "https://cloudflare.com", "purpose": "Content delivery network"},
                {"name": "Datadog Monitoring", "url": "https://datadoghq.com", "purpose": "Application monitoring"},
                {"name": "Stripe Payments", "url": "https://stripe.com", "purpose": "Payment processing"},
                {"name": "Okta Identity", "url": "https://okta.com", "purpose": "Identity management"}
            ]
        });
        let json_str = serde_json::to_string(&json_obj).unwrap();
        let html = format!(
            r#"<html><body><script>window.VENDOR_REPORT = {};</script></body></html>"#,
            json_str
        );
        let mut candidates = Vec::new();
        probe_js_object_assignments(&html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find candidate from JS object assignment with subprocessor data"
        );
    }

    #[test]
    fn test_probe_json_script_tags_valid_json_with_candidates() {
        let html = r#"<html><body>
            <script type="application/json">
            {"subprocessors":[
                {"name":"AWS","url":"https://aws.amazon.com","purpose":"Cloud infrastructure"},
                {"name":"Cloudflare","url":"https://cloudflare.com","purpose":"CDN and security"},
                {"name":"Datadog","url":"https://datadoghq.com","purpose":"Monitoring services"},
                {"name":"Stripe","url":"https://stripe.com","purpose":"Payment processing"},
                {"name":"Google Analytics","url":"https://google.com","purpose":"Analytics"}
            ]}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find candidates from JSON script tags"
        );
    }

    #[test]
    fn test_is_likely_spa_no_body_tag() {
        let html = "<html><head><title>Test</title></head></html>";
        assert!(!is_likely_spa(html));
    }

    #[test]
    fn test_probe_json_script_tags_low_score_array() {
        let html = r#"<html><body>
            <script type="application/json">
            {"data":[
                {"id":1,"value":"aaa","extra":"bbb","field":"ccc","other":"ddd"},
                {"id":2,"value":"eee","extra":"fff","field":"ggg","other":"hhh"},
                {"id":3,"value":"iii","extra":"jjj","field":"kkk","other":"lll"},
                {"id":4,"value":"mmm","extra":"nnn","field":"ooo","other":"ppp"},
                {"id":5,"value":"qqq","extra":"rrr","field":"sss","other":"ttt"}
            ]}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Low-score array without name/url/purpose fields should be skipped"
        );
    }

    #[test]
    fn test_probe_base64_blobs_low_score_array() {
        use base64::Engine;
        let json = serde_json::json!({
            "data": [
                {"id": 1, "value": "aaa", "extra": "bbb"},
                {"id": 2, "value": "ccc", "extra": "ddd"},
                {"id": 3, "value": "eee", "extra": "fff"},
                {"id": 4, "value": "ggg", "extra": "hhh"},
                {"id": 5, "value": "iii", "extra": "jjj"}
            ]
        });
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var x = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Low-score base64 array should be skipped"
        );
    }

    #[test]
    fn test_probe_base64_blobs_high_score_no_name_field() {
        use base64::Engine;
        let json = serde_json::json!({
            "subprocessors": [
                {"id": 1, "category": "infra", "status": "active", "region": "us-east", "tier": "premium"},
                {"id": 2, "category": "security", "status": "active", "region": "eu-west", "tier": "standard"},
                {"id": 3, "category": "monitoring", "status": "active", "region": "ap-south", "tier": "premium"},
                {"id": 4, "category": "network", "status": "active", "region": "us-west", "tier": "standard"},
                {"id": 5, "category": "database", "status": "active", "region": "eu-central", "tier": "premium"}
            ]
        });
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var x = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "High-score but no name field should be skipped"
        );
    }

    #[test]
    fn test_probe_js_object_assignments_high_score_no_name_field() {
        let json_obj = serde_json::json!({
            "subprocessors": [
                {"id": 1, "category": "infra", "status": "active", "region": "us-east", "tier": "premium", "code": "AAA"},
                {"id": 2, "category": "security", "status": "active", "region": "eu-west", "tier": "standard", "code": "BBB"},
                {"id": 3, "category": "monitoring", "status": "active", "region": "ap-south", "tier": "premium", "code": "CCC"},
                {"id": 4, "category": "network", "status": "active", "region": "us-west", "tier": "standard", "code": "DDD"},
                {"id": 5, "category": "database", "status": "active", "region": "eu-central", "tier": "premium", "code": "EEE"}
            ]
        });
        let json_str = serde_json::to_string(&json_obj).unwrap();
        let html = format!(
            r#"<html><body><script>window.VENDOR_REPORT = {};</script></body></html>"#,
            json_str
        );
        let mut candidates = Vec::new();
        probe_js_object_assignments(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "High-score but no name field should be skipped"
        );
    }
}
