//! Generic Trust Center extraction engine
//!
//! Provides a data-driven approach to extracting subprocessor data from
//! Trust Center products (Vanta, SecureFrame, Conveyor, etc.).
//!
//! Extraction strategies are stored as configuration in domain-specific
//! cache JSON files, not as hard-coded per-product logic. The engine
//! supports auto-discovery of strategies for unknown trust centers.

pub mod discovery;
pub mod executor;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// A discovered or manually-configured strategy for extracting subprocessors
/// from a trust center page. Stored in the domain's cache JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCenterStrategy {
    /// What kind of data source this trust center exposes
    pub strategy_type: StrategyType,

    /// How to reach the data (URL, endpoint, etc.)
    pub endpoint: EndpointConfig,

    /// How to parse the response into subprocessor records
    pub response_mapping: ResponseMapping,

    /// When this strategy was discovered and how reliable it is
    pub discovery_metadata: DiscoveryMetadata,
}

/// Strategy types for extracting structured data from trust centers.
/// Each variant stores only its type-specific parameters; the executor
/// dispatches on the variant and uses shared JSON extraction utilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StrategyType {
    /// POST to a GraphQL endpoint with a query that returns subprocessors.
    /// Used by: Vanta, Sprinto, and other GraphQL-based trust centers.
    GraphqlApi {
        /// The GraphQL query string. Use `{{slug}}` as placeholder for the slug value.
        query_template: String,
        /// Variables to send with the query. Values may contain `{{slug}}` placeholder.
        variables: HashMap<String, serde_json::Value>,
        /// The GraphQL operation name (some endpoints require it).
        #[serde(skip_serializing_if = "Option::is_none")]
        operation_name: Option<String>,
    },

    /// GET/POST to a REST API endpoint that returns JSON.
    RestApi {
        /// HTTP method: "GET" or "POST".
        method: String,
        /// Request body template (for POST), may contain `{{slug}}` placeholder.
        #[serde(skip_serializing_if = "Option::is_none")]
        body_template: Option<String>,
        /// Additional headers required for the request.
        #[serde(default)]
        headers: HashMap<String, String>,
    },

    /// Data is embedded in the HTML as a base64-encoded JSON blob.
    /// Used by: SecureFrame trust centers.
    EmbeddedBase64Json {
        /// Regex pattern to locate the base64 string in HTML.
        /// Must have exactly one capture group for the base64 content.
        locator_pattern: String,
    },

    /// Data is embedded as a JavaScript object assignment in the HTML.
    /// Used by: Conveyor trust centers (`window.VENDOR_REPORT = {...}`).
    EmbeddedJsObject {
        /// Regex pattern to locate the JSON object in HTML.
        /// Must have exactly one capture group for the JSON content.
        locator_pattern: String,
    },

    /// Data is available in a JSON hydration blob (e.g., Next.js `__NEXT_DATA__`).
    HydrationData {
        /// CSS selector for the script tag (e.g., `script#__NEXT_DATA__`).
        script_selector: String,
        /// Dot-notation path to the subprocessors array within the blob.
        data_path: String,
    },
}

/// Configuration for how to reach the trust center's data source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    /// The full URL to the API or page. May contain `{{slug}}` placeholder.
    pub url: String,

    /// The slug or identifier extracted from the original trust center URL.
    /// For Vanta: the slugId for the GraphQL query.
    /// For others: the company identifier from the URL path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,

    /// Whether this endpoint requires headless browser rendering first.
    /// True for strategies that extract data from rendered HTML (EmbeddedBase64Json,
    /// EmbeddedJsObject) when the data is injected by JavaScript.
    #[serde(default)]
    pub requires_browser: bool,
}

/// Mapping from JSON response structure to subprocessor fields.
/// Uses dot-notation paths to navigate nested JSON objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMapping {
    /// Dot-notation path to the array of subprocessor objects.
    /// Example: `"data.trust.trustReportBySlugId.subprocessors"`
    pub subprocessors_path: String,

    /// Field name within each subprocessor object for the company name.
    /// Example: `"name"` or `"companyName"` or `"vendor.name"`
    pub name_field: String,

    /// Field name for the subprocessor's website/domain URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_field: Option<String>,

    /// Field name for the purpose/service description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose_field: Option<String>,

    /// Field name for location/country information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_field: Option<String>,

    /// List of field names to concatenate for the evidence/raw_record string.
    #[serde(default)]
    pub evidence_fields: Vec<String>,
}

/// Metadata about how and when a strategy was discovered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryMetadata {
    /// How this strategy was discovered.
    pub discovery_method: DiscoveryMethod,
    /// Timestamp of discovery (Unix epoch seconds).
    pub discovered_at: u64,
    /// Number of subprocessors found when the strategy was first validated.
    pub validated_count: u32,
    /// Confidence in the strategy (0.0-1.0).
    pub confidence: f32,
    /// Number of successful uses since discovery.
    #[serde(default)]
    pub success_count: u32,
    /// Number of failures since discovery.
    #[serde(default)]
    pub failure_count: u32,
}

/// How a trust center strategy was discovered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Discovered by intercepting network traffic during headless browse.
    NetworkInterception,
    /// Discovered by scanning HTML for embedded data patterns.
    HtmlPatternScan,
    /// Discovered by probing known API endpoint patterns.
    ApiProbe,
    /// Manually configured by user in cache JSON.
    Manual,
}

impl DiscoveryMetadata {
    /// Create new discovery metadata with current timestamp.
    pub fn new(method: DiscoveryMethod, validated_count: u32, confidence: f32) -> Self {
        Self {
            discovery_method: method,
            discovered_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            validated_count,
            confidence,
            success_count: 0,
            failure_count: 0,
        }
    }

    /// Check if the strategy is stale (older than max_age_days).
    pub fn is_stale(&self, max_age_days: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age_secs = now.saturating_sub(self.discovered_at);
        age_secs > max_age_days * 86400
    }

    /// Check if the strategy has too many failures.
    pub fn is_unreliable(&self, max_failures: u32) -> bool {
        self.failure_count >= max_failures
    }
}

/// A candidate strategy found during auto-discovery, with a confidence score.
#[derive(Debug, Clone)]
pub struct CandidateStrategy {
    /// The discovered strategy.
    pub strategy: TrustCenterStrategy,
    /// Confidence score for this candidate (0.0-1.0).
    pub score: f32,
    /// Number of subprocessor items found.
    pub item_count: usize,
}

/// Result of analyzing a JSON array to detect if it contains subprocessor-like data.
#[derive(Debug, Clone)]
pub struct ArrayAnalysis {
    /// Dot-notation path to the array in the JSON structure.
    pub path: String,
    /// The array items.
    pub items: Vec<serde_json::Value>,
    /// Score indicating how likely this is a subprocessor array (0.0-1.0).
    pub score: f32,
    /// Detected field mapping.
    pub field_mapping: DetectedFieldMapping,
}

/// Auto-detected mapping of JSON fields to subprocessor data.
#[derive(Debug, Clone)]
pub struct DetectedFieldMapping {
    pub name_field: Option<String>,
    pub url_field: Option<String>,
    pub purpose_field: Option<String>,
    pub location_field: Option<String>,
}

// ============================================================================
// JSON utility functions shared across executor and discovery
// ============================================================================

/// Navigate a dot-separated path through a JSON value.
/// Example: `navigate_json_path(json, "data.trust.subprocessors")`
/// navigates `json["data"]["trust"]["subprocessors"]`.
pub fn navigate_json_path<'a>(
    json: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    if path.is_empty() {
        return Some(json);
    }
    let mut current = json;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Get a string value from a potentially nested field path.
pub fn get_nested_str<'a>(json: &'a serde_json::Value, field_path: &str) -> Option<&'a str> {
    navigate_json_path(json, field_path)?.as_str()
}

/// Recursively search a JSON value for arrays of objects that could be
/// subprocessor lists. Returns all arrays found with their dot-notation paths.
pub fn find_entity_arrays(
    json: &serde_json::Value,
    current_path: &str,
) -> Vec<(String, Vec<serde_json::Value>)> {
    let mut results = Vec::new();

    match json {
        serde_json::Value::Array(arr) if arr.len() >= 3 => {
            // Check if this looks like an array of entity objects
            let obj_count = arr.iter().filter(|v| v.is_object()).count();
            if obj_count as f64 / arr.len() as f64 > 0.8 {
                results.push((current_path.to_string(), arr.clone()));
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                let child_path = if current_path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", current_path, key)
                };
                results.extend(find_entity_arrays(value, &child_path));
            }
        }
        _ => {}
    }

    results
}

/// Score how likely a JSON array contains subprocessor data.
/// Returns a score between 0.0 and 1.0.
pub fn score_subprocessor_array(items: &[serde_json::Value], path: &str) -> f32 {
    if items.is_empty() {
        return 0.0;
    }

    let mut score: f32 = 0.0;

    // Score based on array size (subprocessor lists typically have 5-100 items)
    if items.len() >= 5 {
        score += 0.15;
    }
    if items.len() >= 10 {
        score += 0.1;
    }

    // Score based on path containing relevant keywords
    let path_lower = path.to_lowercase();
    let path_keywords = [
        "subprocessor",
        "vendor",
        "processor",
        "provider",
        "supplier",
        "partner",
    ];
    for keyword in &path_keywords {
        if path_lower.contains(keyword) {
            score += 0.25;
            break;
        }
    }

    // Analyze object fields from the first few items
    let sample_size = std::cmp::min(items.len(), 5);
    let sample = &items[..sample_size];

    let name_fields = [
        "name",
        "companyName",
        "company_name",
        "vendor_name",
        "vendorName",
        "organization",
        "entity",
        "entityName",
        "entity_name",
        "company.name",
    ]; // SafeBase: nested company object
    let url_fields = [
        "url",
        "website",
        "domain",
        "link",
        "href",
        "websiteUrl",
        "website_url",
        "company.domain",
    ]; // SafeBase: nested company object
    let purpose_fields = [
        "purpose",
        "service",
        "description",
        "category",
        "type",
        "serviceDescription",
        "service_description",
    ];
    let location_fields = ["location", "country", "region", "geography"];

    /// Check if a field path (possibly dot-separated) resolves to a non-empty string.
    fn has_field_value(item: &serde_json::Value, field_path: &str) -> bool {
        get_nested_str(item, field_path).is_some_and(|s| !s.is_empty())
    }

    let has_name_field = sample
        .iter()
        .any(|item| name_fields.iter().any(|f| has_field_value(item, f)));
    let has_url_field = sample
        .iter()
        .any(|item| url_fields.iter().any(|f| has_field_value(item, f)));
    let has_purpose_field = sample
        .iter()
        .any(|item| purpose_fields.iter().any(|f| has_field_value(item, f)));
    let has_location_field = sample
        .iter()
        .any(|item| location_fields.iter().any(|f| has_field_value(item, f)));

    if has_name_field {
        score += 0.25;
    }
    if has_url_field {
        score += 0.15;
    }
    if has_purpose_field {
        score += 0.05;
    }
    if has_location_field {
        score += 0.05;
    }

    score.min(1.0)
}

/// Detect which fields in a JSON array map to subprocessor name, URL, purpose, location.
/// Supports nested dot-notation fields (e.g., "company.name" for SafeBase).
pub fn detect_field_mapping(items: &[serde_json::Value]) -> DetectedFieldMapping {
    let sample = if items.len() > 5 { &items[..5] } else { items };

    let name_candidates = [
        "name",
        "companyName",
        "company_name",
        "vendor_name",
        "vendorName",
        "organization",
        "entity",
        "entityName",
        "entity_name",
        "company.name",
    ]; // SafeBase
    let url_candidates = [
        "url",
        "website",
        "domain",
        "link",
        "href",
        "websiteUrl",
        "website_url",
        "company.domain",
    ]; // SafeBase
    let purpose_candidates = [
        "purpose",
        "service",
        "description",
        "category",
        "type",
        "serviceDescription",
        "service_description",
    ];
    let location_candidates = ["location", "country", "region", "geography"];

    let find_field = |candidates: &[&str]| -> Option<String> {
        for field in candidates {
            let match_count = sample
                .iter()
                .filter(|item| get_nested_str(item, field).is_some_and(|s| !s.is_empty()))
                .count();
            if match_count as f64 / sample.len() as f64 > 0.5 {
                return Some(field.to_string());
            }
        }
        None
    };

    DetectedFieldMapping {
        name_field: find_field(&name_candidates),
        url_field: find_field(&url_candidates),
        purpose_field: find_field(&purpose_candidates),
        location_field: find_field(&location_candidates),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_subprocessor_array_with_nested_fields() {
        // SafeBase-style entries with nested company.name and company.domain
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"company": {"name": "Algolia", "domain": "algolia.com"}, "purpose": "Search", "location": "US"}),
            serde_json::json!({"company": {"name": "AWS", "domain": "amazonaws.com"}, "purpose": "Cloud", "location": "US"}),
            serde_json::json!({"company": {"name": "Datadog", "domain": "datadoghq.com"}, "purpose": "Monitoring", "location": "US"}),
            serde_json::json!({"company": {"name": "Stripe", "domain": "stripe.com"}, "purpose": "Payments", "location": "US"}),
            serde_json::json!({"company": {"name": "Okta", "domain": "okta.com"}, "purpose": "Auth", "location": "US"}),
        ];

        let score = score_subprocessor_array(&items, "items.listEntries");
        // Should score >= 0.4 thanks to nested company.name detection
        assert!(
            score >= 0.4,
            "Score {:.2} should be >= 0.4 for SafeBase-style entries",
            score
        );
    }

    #[test]
    fn test_detect_field_mapping_nested() {
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"company": {"name": "Algolia", "domain": "algolia.com"}, "purpose": "Search", "location": "US"}),
            serde_json::json!({"company": {"name": "AWS", "domain": "amazonaws.com"}, "purpose": "Cloud", "location": "US"}),
            serde_json::json!({"company": {"name": "Datadog", "domain": "datadoghq.com"}, "purpose": "Monitoring", "location": "US"}),
        ];

        let mapping = detect_field_mapping(&items);
        assert_eq!(
            mapping.name_field,
            Some("company.name".to_string()),
            "Should detect nested company.name"
        );
        assert_eq!(
            mapping.url_field,
            Some("company.domain".to_string()),
            "Should detect nested company.domain"
        );
        assert_eq!(mapping.purpose_field, Some("purpose".to_string()));
        assert_eq!(mapping.location_field, Some("location".to_string()));
    }

    #[test]
    fn test_navigate_json_path_nested() {
        let json = serde_json::json!({"company": {"name": "Algolia", "domain": "algolia.com"}});
        assert_eq!(get_nested_str(&json, "company.name"), Some("Algolia"));
        assert_eq!(get_nested_str(&json, "company.domain"), Some("algolia.com"));
        assert_eq!(get_nested_str(&json, "company.missing"), None);
    }

    // ──────────────────────────────────────────────────────────────────
    // DiscoveryMetadata tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_discovery_metadata_new() {
        let meta = DiscoveryMetadata::new(DiscoveryMethod::NetworkInterception, 10, 0.95);
        assert_eq!(meta.validated_count, 10);
        assert!((meta.confidence - 0.95).abs() < f32::EPSILON);
        assert_eq!(meta.success_count, 0);
        assert_eq!(meta.failure_count, 0);
        // discovered_at should be recent (within the last 5 seconds)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(meta.discovered_at <= now);
        assert!(meta.discovered_at >= now - 5);
    }

    #[test]
    fn test_discovery_metadata_new_all_methods() {
        let methods = vec![
            DiscoveryMethod::NetworkInterception,
            DiscoveryMethod::HtmlPatternScan,
            DiscoveryMethod::ApiProbe,
            DiscoveryMethod::Manual,
        ];
        for method in methods {
            let meta = DiscoveryMetadata::new(method, 5, 0.8);
            assert_eq!(meta.validated_count, 5);
        }
    }

    #[test]
    fn test_discovery_metadata_is_stale_fresh() {
        let meta = DiscoveryMetadata::new(DiscoveryMethod::Manual, 10, 0.9);
        // Just created, should not be stale even with 0-day max age
        // (it's within the same second)
        assert!(!meta.is_stale(1));
        assert!(!meta.is_stale(30));
        assert!(!meta.is_stale(365));
    }

    #[test]
    fn test_discovery_metadata_is_stale_old() {
        let mut meta = DiscoveryMetadata::new(DiscoveryMethod::Manual, 10, 0.9);
        // Set discovered_at to 31 days ago
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        meta.discovered_at = now - (31 * 86400);
        assert!(meta.is_stale(30)); // 30-day max_age, 31 days old -> stale
        assert!(!meta.is_stale(60)); // 60-day max_age, 31 days old -> not stale
    }

    #[test]
    fn test_discovery_metadata_is_stale_zero_days() {
        let mut meta = DiscoveryMetadata::new(DiscoveryMethod::Manual, 10, 0.9);
        // Set discovered_at to 1 second ago
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        meta.discovered_at = now - 1;
        assert!(meta.is_stale(0)); // 0-day max_age, any age -> stale
    }

    #[test]
    fn test_discovery_metadata_is_unreliable() {
        let mut meta = DiscoveryMetadata::new(DiscoveryMethod::Manual, 10, 0.9);
        assert!(!meta.is_unreliable(3)); // 0 failures < 3
        meta.failure_count = 2;
        assert!(!meta.is_unreliable(3)); // 2 failures < 3
        meta.failure_count = 3;
        assert!(meta.is_unreliable(3)); // 3 failures >= 3
        meta.failure_count = 10;
        assert!(meta.is_unreliable(3)); // 10 failures >= 3
    }

    #[test]
    fn test_discovery_metadata_is_unreliable_zero_threshold() {
        let meta = DiscoveryMetadata::new(DiscoveryMethod::Manual, 10, 0.9);
        assert!(meta.is_unreliable(0)); // 0 failures >= 0 threshold
    }

    // ──────────────────────────────────────────────────────────────────
    // DiscoveryMethod Debug/Clone
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_discovery_method_debug() {
        let dbg = format!("{:?}", DiscoveryMethod::NetworkInterception);
        assert!(dbg.contains("NetworkInterception"));
        let dbg = format!("{:?}", DiscoveryMethod::HtmlPatternScan);
        assert!(dbg.contains("HtmlPatternScan"));
        let dbg = format!("{:?}", DiscoveryMethod::ApiProbe);
        assert!(dbg.contains("ApiProbe"));
        let dbg = format!("{:?}", DiscoveryMethod::Manual);
        assert!(dbg.contains("Manual"));
    }

    #[test]
    fn test_discovery_method_clone() {
        let method = DiscoveryMethod::NetworkInterception;
        let cloned = method.clone();
        assert_eq!(format!("{:?}", method), format!("{:?}", cloned));
    }

    // ──────────────────────────────────────────────────────────────────
    // Serialization / Deserialization round-trip tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_discovery_metadata_serde_roundtrip() {
        let meta = DiscoveryMetadata::new(DiscoveryMethod::HtmlPatternScan, 25, 0.85);
        let json_str = serde_json::to_string(&meta).unwrap();
        let deserialized: DiscoveryMetadata = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.validated_count, 25);
        assert!((deserialized.confidence - 0.85).abs() < f32::EPSILON);
    }

    #[test]
    fn test_strategy_type_graphql_serde_roundtrip() {
        let st = StrategyType::GraphqlApi {
            query_template: "query { vendors { name } }".to_string(),
            variables: {
                let mut m = HashMap::new();
                m.insert("slug".to_string(), serde_json::json!("test-slug"));
                m
            },
            operation_name: Some("GetVendors".to_string()),
        };
        let json_str = serde_json::to_string(&st).unwrap();
        let deserialized: StrategyType = serde_json::from_str(&json_str).unwrap();
        match deserialized {
            StrategyType::GraphqlApi {
                query_template,
                operation_name,
                ..
            } => {
                assert_eq!(query_template, "query { vendors { name } }");
                assert_eq!(operation_name, Some("GetVendors".to_string()));
            }
            _ => panic!("Expected GraphqlApi"),
        }
    }

    #[test]
    fn test_strategy_type_rest_api_serde_roundtrip() {
        let st = StrategyType::RestApi {
            method: "GET".to_string(),
            body_template: None,
            headers: HashMap::new(),
        };
        let json_str = serde_json::to_string(&st).unwrap();
        let deserialized: StrategyType = serde_json::from_str(&json_str).unwrap();
        match deserialized {
            StrategyType::RestApi { method, .. } => assert_eq!(method, "GET"),
            _ => panic!("Expected RestApi"),
        }
    }

    #[test]
    fn test_strategy_type_rest_api_with_body_serde_roundtrip() {
        let st = StrategyType::RestApi {
            method: "POST".to_string(),
            body_template: Some(r#"{"query":"test"}"#.to_string()),
            headers: {
                let mut m = HashMap::new();
                m.insert("X-Api-Key".to_string(), "secret".to_string());
                m
            },
        };
        let json_str = serde_json::to_string(&st).unwrap();
        let deserialized: StrategyType = serde_json::from_str(&json_str).unwrap();
        match deserialized {
            StrategyType::RestApi {
                method,
                body_template,
                headers,
            } => {
                assert_eq!(method, "POST");
                assert!(body_template.is_some());
                assert!(headers.contains_key("X-Api-Key"));
            }
            _ => panic!("Expected RestApi"),
        }
    }

    #[test]
    fn test_strategy_type_embedded_base64_serde_roundtrip() {
        let st = StrategyType::EmbeddedBase64Json {
            locator_pattern: r#"data-payload="([A-Za-z0-9+/=]+)""#.to_string(),
        };
        let json_str = serde_json::to_string(&st).unwrap();
        let deserialized: StrategyType = serde_json::from_str(&json_str).unwrap();
        match deserialized {
            StrategyType::EmbeddedBase64Json { locator_pattern } => {
                assert!(locator_pattern.contains("data-payload"));
            }
            _ => panic!("Expected EmbeddedBase64Json"),
        }
    }

    #[test]
    fn test_strategy_type_embedded_js_object_serde_roundtrip() {
        let st = StrategyType::EmbeddedJsObject {
            locator_pattern: r#"window\.DATA\s*=\s*(\{.*\})"#.to_string(),
        };
        let json_str = serde_json::to_string(&st).unwrap();
        let deserialized: StrategyType = serde_json::from_str(&json_str).unwrap();
        match deserialized {
            StrategyType::EmbeddedJsObject { locator_pattern } => {
                assert!(locator_pattern.contains("window"));
            }
            _ => panic!("Expected EmbeddedJsObject"),
        }
    }

    #[test]
    fn test_strategy_type_hydration_data_serde_roundtrip() {
        let st = StrategyType::HydrationData {
            script_selector: "script#__NEXT_DATA__".to_string(),
            data_path: "props.pageProps.vendors".to_string(),
        };
        let json_str = serde_json::to_string(&st).unwrap();
        let deserialized: StrategyType = serde_json::from_str(&json_str).unwrap();
        match deserialized {
            StrategyType::HydrationData {
                script_selector,
                data_path,
            } => {
                assert_eq!(script_selector, "script#__NEXT_DATA__");
                assert_eq!(data_path, "props.pageProps.vendors");
            }
            _ => panic!("Expected HydrationData"),
        }
    }

    #[test]
    fn test_endpoint_config_serde_roundtrip() {
        let ec = EndpointConfig {
            url: "https://api.example.com/data".to_string(),
            slug: Some("acme".to_string()),
            requires_browser: true,
        };
        let json_str = serde_json::to_string(&ec).unwrap();
        let deserialized: EndpointConfig = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.url, "https://api.example.com/data");
        assert_eq!(deserialized.slug, Some("acme".to_string()));
        assert!(deserialized.requires_browser);
    }

    #[test]
    fn test_endpoint_config_no_slug_no_browser() {
        let ec = EndpointConfig {
            url: "https://api.example.com".to_string(),
            slug: None,
            requires_browser: false,
        };
        let json_str = serde_json::to_string(&ec).unwrap();
        // slug should be omitted from JSON (skip_serializing_if)
        assert!(!json_str.contains("slug"));
        let deserialized: EndpointConfig = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.slug, None);
        assert!(!deserialized.requires_browser);
    }

    #[test]
    fn test_response_mapping_serde_roundtrip() {
        let rm = ResponseMapping {
            subprocessors_path: "data.vendors".to_string(),
            name_field: "name".to_string(),
            url_field: Some("url".to_string()),
            purpose_field: Some("purpose".to_string()),
            location_field: Some("location".to_string()),
            evidence_fields: vec!["name".to_string(), "purpose".to_string()],
        };
        let json_str = serde_json::to_string(&rm).unwrap();
        let deserialized: ResponseMapping = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.subprocessors_path, "data.vendors");
        assert_eq!(deserialized.evidence_fields.len(), 2);
    }

    #[test]
    fn test_response_mapping_minimal() {
        let rm = ResponseMapping {
            subprocessors_path: "data".to_string(),
            name_field: "name".to_string(),
            url_field: None,
            purpose_field: None,
            location_field: None,
            evidence_fields: vec![],
        };
        let json_str = serde_json::to_string(&rm).unwrap();
        // Optional fields should be omitted
        assert!(!json_str.contains("url_field"));
        assert!(!json_str.contains("purpose_field"));
        assert!(!json_str.contains("location_field"));
    }

    #[test]
    fn test_trust_center_strategy_full_serde_roundtrip() {
        let strategy = TrustCenterStrategy {
            strategy_type: StrategyType::RestApi {
                method: "GET".to_string(),
                body_template: None,
                headers: HashMap::new(),
            },
            endpoint: EndpointConfig {
                url: "https://api.example.com/vendors".to_string(),
                slug: Some("test".to_string()),
                requires_browser: false,
            },
            response_mapping: ResponseMapping {
                subprocessors_path: "data".to_string(),
                name_field: "name".to_string(),
                url_field: Some("url".to_string()),
                purpose_field: None,
                location_field: None,
                evidence_fields: vec![],
            },
            discovery_metadata: DiscoveryMetadata::new(DiscoveryMethod::ApiProbe, 15, 0.92),
        };
        let json_str = serde_json::to_string(&strategy).unwrap();
        let deserialized: TrustCenterStrategy = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.endpoint.url, "https://api.example.com/vendors");
        assert_eq!(deserialized.response_mapping.name_field, "name");
    }

    // ──────────────────────────────────────────────────────────────────
    // navigate_json_path additional tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_navigate_json_path_empty_returns_root() {
        let json = serde_json::json!({"a": 1});
        let result = navigate_json_path(&json, "");
        assert!(result.is_some());
        assert!(result.unwrap().is_object());
    }

    #[test]
    fn test_navigate_json_path_single_key() {
        let json = serde_json::json!({"name": "test"});
        let result = navigate_json_path(&json, "name");
        assert_eq!(result.unwrap().as_str().unwrap(), "test");
    }

    #[test]
    fn test_navigate_json_path_deep_nested() {
        let json = serde_json::json!({"a": {"b": {"c": {"d": 42}}}});
        let result = navigate_json_path(&json, "a.b.c.d");
        assert_eq!(result.unwrap().as_i64().unwrap(), 42);
    }

    #[test]
    fn test_navigate_json_path_missing_key() {
        let json = serde_json::json!({"a": {"b": 1}});
        assert!(navigate_json_path(&json, "a.c").is_none());
    }

    #[test]
    fn test_navigate_json_path_into_array_element() {
        // Cannot index into arrays with dot notation
        let json = serde_json::json!({"arr": [1, 2, 3]});
        assert!(navigate_json_path(&json, "arr.0").is_none());
    }

    // ──────────────────────────────────────────────────────────────────
    // get_nested_str additional tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_nested_str_non_string_value() {
        let json = serde_json::json!({"count": 42});
        assert!(get_nested_str(&json, "count").is_none());
    }

    #[test]
    fn test_get_nested_str_null_value() {
        let json = serde_json::json!({"name": null});
        assert!(get_nested_str(&json, "name").is_none());
    }

    #[test]
    fn test_get_nested_str_boolean_value() {
        let json = serde_json::json!({"active": true});
        assert!(get_nested_str(&json, "active").is_none());
    }

    // ──────────────────────────────────────────────────────────────────
    // find_entity_arrays additional tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_find_entity_arrays_empty_object() {
        let json = serde_json::json!({});
        let results = find_entity_arrays(&json, "");
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_entity_arrays_small_array_skipped() {
        // Arrays with fewer than 3 items should be skipped
        let json = serde_json::json!({"items": [{"name": "A"}, {"name": "B"}]});
        let results = find_entity_arrays(&json, "");
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_entity_arrays_non_object_array_skipped() {
        // Arrays of non-objects (primitives) should be skipped
        let json = serde_json::json!({"ids": [1, 2, 3, 4, 5]});
        let results = find_entity_arrays(&json, "");
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_entity_arrays_mixed_array_skipped() {
        // Arrays where less than 80% of items are objects
        let json = serde_json::json!({"items": [{"name": "A"}, 2, 3, 4, 5]});
        let results = find_entity_arrays(&json, "");
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_entity_arrays_valid_nested() {
        let json = serde_json::json!({
            "data": {
                "vendors": [
                    {"name": "A"},
                    {"name": "B"},
                    {"name": "C"}
                ]
            }
        });
        let results = find_entity_arrays(&json, "");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "data.vendors");
        assert_eq!(results[0].1.len(), 3);
    }

    #[test]
    fn test_find_entity_arrays_multiple_arrays() {
        let json = serde_json::json!({
            "vendors": [{"name": "A"}, {"name": "B"}, {"name": "C"}],
            "users": [{"name": "X"}, {"name": "Y"}, {"name": "Z"}]
        });
        let results = find_entity_arrays(&json, "");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_entity_arrays_root_array() {
        let json = serde_json::json!([
            {"name": "A"},
            {"name": "B"},
            {"name": "C"}
        ]);
        let results = find_entity_arrays(&json, "");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "");
    }

    #[test]
    fn test_find_entity_arrays_primitive_value() {
        let json = serde_json::json!("just a string");
        let results = find_entity_arrays(&json, "");
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_entity_arrays_null_value() {
        let json = serde_json::json!(null);
        let results = find_entity_arrays(&json, "");
        assert!(results.is_empty());
    }

    // ──────────────────────────────────────────────────────────────────
    // score_subprocessor_array additional tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_score_subprocessor_array_empty() {
        let items: Vec<serde_json::Value> = vec![];
        assert_eq!(score_subprocessor_array(&items, "data"), 0.0);
    }

    #[test]
    fn test_score_subprocessor_array_small_no_fields() {
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"x": 1}),
            serde_json::json!({"x": 2}),
            serde_json::json!({"x": 3}),
        ];
        let score = score_subprocessor_array(&items, "data");
        // No name/url/purpose fields, no path keywords, < 5 items => very low score
        assert!(score < 0.4);
    }

    #[test]
    fn test_score_subprocessor_array_path_keyword_boost() {
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"x": 1}),
            serde_json::json!({"x": 2}),
            serde_json::json!({"x": 3}),
        ];
        let score_subprocessor = score_subprocessor_array(&items, "data.subprocessors");
        let score_generic = score_subprocessor_array(&items, "data.items");
        // "subprocessors" path keyword should boost score
        assert!(score_subprocessor > score_generic);
    }

    #[test]
    fn test_score_subprocessor_array_path_keywords() {
        let items = vec![serde_json::json!({"x": 1}); 3];
        for keyword in &[
            "vendor",
            "processor",
            "provider",
            "supplier",
            "partner",
            "subprocessor",
        ] {
            let path = format!("data.{}", keyword);
            let score = score_subprocessor_array(&items, &path);
            assert!(
                score >= 0.25,
                "Path keyword '{}' should boost score, got {}",
                keyword,
                score
            );
        }
    }

    #[test]
    fn test_score_subprocessor_array_size_boost() {
        let items_3: Vec<serde_json::Value> = vec![serde_json::json!({"name": "A"}); 3];
        let items_5: Vec<serde_json::Value> = vec![serde_json::json!({"name": "A"}); 5];
        let items_10: Vec<serde_json::Value> = vec![serde_json::json!({"name": "A"}); 10];

        let score_3 = score_subprocessor_array(&items_3, "data");
        let score_5 = score_subprocessor_array(&items_5, "data");
        let score_10 = score_subprocessor_array(&items_10, "data");

        // More items should score higher
        assert!(score_5 > score_3);
        assert!(score_10 > score_5);
    }

    #[test]
    fn test_score_subprocessor_array_name_field_boost() {
        let with_name: Vec<serde_json::Value> =
            vec![serde_json::json!({"name": "Vendor", "url": "https://v.com"}); 5];
        let without_name: Vec<serde_json::Value> =
            vec![serde_json::json!({"id": 1, "value": "test"}); 5];

        let score_with = score_subprocessor_array(&with_name, "data");
        let score_without = score_subprocessor_array(&without_name, "data");
        assert!(score_with > score_without);
    }

    #[test]
    fn test_score_capped_at_one() {
        // Create items with all possible field types and path keyword
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"name":"A","url":"https://a.com","purpose":"P","location":"US"});
            20
        ];
        let score = score_subprocessor_array(&items, "data.subprocessors.vendor");
        assert!(score <= 1.0);
    }

    // ──────────────────────────────────────────────────────────────────
    // detect_field_mapping additional tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_detect_field_mapping_flat_fields() {
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"name": "AWS", "url": "https://aws.com", "purpose": "Cloud", "location": "US"}),
            serde_json::json!({"name": "GCP", "url": "https://cloud.google.com", "purpose": "Cloud", "location": "US"}),
            serde_json::json!({"name": "Azure", "url": "https://azure.com", "purpose": "Cloud", "location": "US"}),
        ];
        let mapping = detect_field_mapping(&items);
        assert_eq!(mapping.name_field, Some("name".to_string()));
        assert_eq!(mapping.url_field, Some("url".to_string()));
        assert_eq!(mapping.purpose_field, Some("purpose".to_string()));
        assert_eq!(mapping.location_field, Some("location".to_string()));
    }

    #[test]
    fn test_detect_field_mapping_no_matching_fields() {
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"id": 1, "value": "x"}),
            serde_json::json!({"id": 2, "value": "y"}),
            serde_json::json!({"id": 3, "value": "z"}),
        ];
        let mapping = detect_field_mapping(&items);
        assert!(mapping.name_field.is_none());
        assert!(mapping.url_field.is_none());
        assert!(mapping.purpose_field.is_none());
        assert!(mapping.location_field.is_none());
    }

    #[test]
    fn test_detect_field_mapping_alternative_field_names() {
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"companyName": "AWS", "website": "https://aws.com", "service": "Cloud", "country": "US"}),
            serde_json::json!({"companyName": "GCP", "website": "https://cloud.google.com", "service": "Cloud", "country": "US"}),
            serde_json::json!({"companyName": "Azure", "website": "https://azure.com", "service": "Cloud", "country": "US"}),
        ];
        let mapping = detect_field_mapping(&items);
        assert_eq!(mapping.name_field, Some("companyName".to_string()));
        assert_eq!(mapping.url_field, Some("website".to_string()));
        assert_eq!(mapping.purpose_field, Some("service".to_string()));
        assert_eq!(mapping.location_field, Some("country".to_string()));
    }

    #[test]
    fn test_detect_field_mapping_with_empty_values() {
        // If most items have empty string values for a field, it should not match
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"name": "AWS", "url": ""}),
            serde_json::json!({"name": "GCP", "url": ""}),
            serde_json::json!({"name": "Azure", "url": ""}),
        ];
        let mapping = detect_field_mapping(&items);
        assert_eq!(mapping.name_field, Some("name".to_string()));
        // url field has empty values, so it should not match (empty strings fail is_some_and check)
        assert!(mapping.url_field.is_none());
    }

    #[test]
    fn test_detect_field_mapping_large_sample() {
        // More than 5 items - should only sample first 5
        let items: Vec<serde_json::Value> = (0..20)
            .map(|i| serde_json::json!({"name": format!("Vendor {}", i)}))
            .collect();
        let mapping = detect_field_mapping(&items);
        assert_eq!(mapping.name_field, Some("name".to_string()));
    }

    // ──────────────────────────────────────────────────────────────────
    // CandidateStrategy / ArrayAnalysis struct coverage
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_candidate_strategy_debug_and_clone() {
        let cs = CandidateStrategy {
            strategy: TrustCenterStrategy {
                strategy_type: StrategyType::RestApi {
                    method: "GET".to_string(),
                    body_template: None,
                    headers: HashMap::new(),
                },
                endpoint: EndpointConfig {
                    url: "https://example.com".to_string(),
                    slug: None,
                    requires_browser: false,
                },
                response_mapping: ResponseMapping {
                    subprocessors_path: "data".to_string(),
                    name_field: "name".to_string(),
                    url_field: None,
                    purpose_field: None,
                    location_field: None,
                    evidence_fields: vec![],
                },
                discovery_metadata: DiscoveryMetadata::new(DiscoveryMethod::Manual, 5, 0.8),
            },
            score: 0.85,
            item_count: 10,
        };
        let cloned = cs.clone();
        assert_eq!(cloned.score, 0.85);
        assert_eq!(cloned.item_count, 10);
        let dbg = format!("{:?}", cs);
        assert!(dbg.contains("0.85"));
    }

    #[test]
    fn test_array_analysis_debug_and_clone() {
        let aa = ArrayAnalysis {
            path: "data.vendors".to_string(),
            items: vec![serde_json::json!({"name": "test"})],
            score: 0.75,
            field_mapping: DetectedFieldMapping {
                name_field: Some("name".to_string()),
                url_field: None,
                purpose_field: None,
                location_field: None,
            },
        };
        let cloned = aa.clone();
        assert_eq!(cloned.path, "data.vendors");
        assert_eq!(cloned.items.len(), 1);
        let dbg = format!("{:?}", aa);
        assert!(dbg.contains("data.vendors"));
    }

    #[test]
    fn test_detected_field_mapping_debug_and_clone() {
        let dfm = DetectedFieldMapping {
            name_field: Some("name".to_string()),
            url_field: Some("url".to_string()),
            purpose_field: None,
            location_field: None,
        };
        let cloned = dfm.clone();
        assert_eq!(cloned.name_field, Some("name".to_string()));
        let dbg = format!("{:?}", dfm);
        assert!(dbg.contains("name"));
    }

    #[test]
    fn test_detect_field_mapping_empty_items() {
        let items: Vec<serde_json::Value> = vec![];
        let mapping = detect_field_mapping(&items);
        assert!(mapping.name_field.is_none());
        assert!(mapping.url_field.is_none());
        assert!(mapping.purpose_field.is_none());
        assert!(mapping.location_field.is_none());
    }

    #[test]
    fn test_score_subprocessor_array_purpose_without_name() {
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"description": "Cloud hosting"}),
            serde_json::json!({"description": "CDN services"}),
            serde_json::json!({"description": "Database hosting"}),
            serde_json::json!({"description": "Email delivery"}),
            serde_json::json!({"description": "Analytics"}),
        ];
        let score = score_subprocessor_array(&items, "services");
        // Has purpose field (description) but no name field, 5+ items
        assert!(score > 0.0);
    }

    #[test]
    fn test_score_subprocessor_array_location_without_name() {
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"country": "US", "id": 1}),
            serde_json::json!({"country": "EU", "id": 2}),
            serde_json::json!({"country": "AP", "id": 3}),
            serde_json::json!({"country": "US", "id": 4}),
            serde_json::json!({"country": "EU", "id": 5}),
        ];
        let score = score_subprocessor_array(&items, "regions");
        // Has location field but no name, 5+ items
        assert!(score > 0.0);
    }

    #[test]
    fn test_discovery_metadata_is_stale_future_timestamp() {
        let mut meta = DiscoveryMetadata::new(DiscoveryMethod::Manual, 10, 0.9);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        meta.discovered_at = now + 3600; // Future timestamp
                                         // saturating_sub produces 0, so never stale even with 0-day threshold
        assert!(!meta.is_stale(0));
    }

    #[test]
    fn test_find_entity_arrays_deeply_nested() {
        let json = serde_json::json!({
            "response": {
                "data": {
                    "level3": {
                        "items": [
                            {"name": "A"},
                            {"name": "B"},
                            {"name": "C"}
                        ]
                    }
                }
            }
        });
        let results = find_entity_arrays(&json, "");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "response.data.level3.items");
    }

    #[test]
    fn test_score_subprocessor_array_url_only() {
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"url": "https://a.com", "id": 1}),
            serde_json::json!({"url": "https://b.com", "id": 2}),
            serde_json::json!({"url": "https://c.com", "id": 3}),
            serde_json::json!({"url": "https://d.com", "id": 4}),
            serde_json::json!({"url": "https://e.com", "id": 5}),
        ];
        let score = score_subprocessor_array(&items, "links");
        // Has url field but no name, 5+ items
        assert!(score > 0.0);
    }
}
