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
pub fn navigate_json_path<'a>(json: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
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
pub fn find_entity_arrays(json: &serde_json::Value, current_path: &str) -> Vec<(String, Vec<serde_json::Value>)> {
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
    let path_keywords = ["subprocessor", "vendor", "processor", "provider", "supplier", "partner"];
    for keyword in &path_keywords {
        if path_lower.contains(keyword) {
            score += 0.25;
            break;
        }
    }

    // Analyze object fields from the first few items
    let sample_size = std::cmp::min(items.len(), 5);
    let sample = &items[..sample_size];

    let name_fields = ["name", "companyName", "company_name", "vendor_name", "vendorName",
                        "organization", "entity", "entityName", "entity_name",
                        "company.name"]; // SafeBase: nested company object
    let url_fields = ["url", "website", "domain", "link", "href", "websiteUrl", "website_url",
                       "company.domain"]; // SafeBase: nested company object
    let purpose_fields = ["purpose", "service", "description", "category", "type",
                          "serviceDescription", "service_description"];
    let location_fields = ["location", "country", "region", "geography"];

    /// Check if a field path (possibly dot-separated) resolves to a non-empty string.
    fn has_field_value(item: &serde_json::Value, field_path: &str) -> bool {
        get_nested_str(item, field_path).map_or(false, |s| !s.is_empty())
    }

    let has_name_field = sample.iter().any(|item| {
        name_fields.iter().any(|f| has_field_value(item, f))
    });
    let has_url_field = sample.iter().any(|item| {
        url_fields.iter().any(|f| has_field_value(item, f))
    });
    let has_purpose_field = sample.iter().any(|item| {
        purpose_fields.iter().any(|f| has_field_value(item, f))
    });
    let has_location_field = sample.iter().any(|item| {
        location_fields.iter().any(|f| has_field_value(item, f))
    });

    if has_name_field { score += 0.25; }
    if has_url_field { score += 0.15; }
    if has_purpose_field { score += 0.05; }
    if has_location_field { score += 0.05; }

    score.min(1.0)
}

/// Detect which fields in a JSON array map to subprocessor name, URL, purpose, location.
/// Supports nested dot-notation fields (e.g., "company.name" for SafeBase).
pub fn detect_field_mapping(items: &[serde_json::Value]) -> DetectedFieldMapping {
    let sample = if items.len() > 5 { &items[..5] } else { items };

    let name_candidates = ["name", "companyName", "company_name", "vendor_name", "vendorName",
                            "organization", "entity", "entityName", "entity_name",
                            "company.name"]; // SafeBase
    let url_candidates = ["url", "website", "domain", "link", "href", "websiteUrl", "website_url",
                           "company.domain"]; // SafeBase
    let purpose_candidates = ["purpose", "service", "description", "category", "type",
                               "serviceDescription", "service_description"];
    let location_candidates = ["location", "country", "region", "geography"];

    let find_field = |candidates: &[&str]| -> Option<String> {
        for field in candidates {
            let match_count = sample.iter()
                .filter(|item| get_nested_str(item, field).map_or(false, |s| !s.is_empty()))
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
        assert!(score >= 0.4, "Score {:.2} should be >= 0.4 for SafeBase-style entries", score);
    }

    #[test]
    fn test_detect_field_mapping_nested() {
        let items: Vec<serde_json::Value> = vec![
            serde_json::json!({"company": {"name": "Algolia", "domain": "algolia.com"}, "purpose": "Search", "location": "US"}),
            serde_json::json!({"company": {"name": "AWS", "domain": "amazonaws.com"}, "purpose": "Cloud", "location": "US"}),
            serde_json::json!({"company": {"name": "Datadog", "domain": "datadoghq.com"}, "purpose": "Monitoring", "location": "US"}),
        ];

        let mapping = detect_field_mapping(&items);
        assert_eq!(mapping.name_field, Some("company.name".to_string()), "Should detect nested company.name");
        assert_eq!(mapping.url_field, Some("company.domain".to_string()), "Should detect nested company.domain");
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
}
