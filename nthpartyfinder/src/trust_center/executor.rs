//! Generic trust center strategy executor.
//!
//! Provides a single entry point (`execute_strategy`) that dispatches
//! on the `StrategyType` variant and uses shared JSON extraction utilities.

use anyhow::Result;
use reqwest;
use scraper::{Html, Selector};
use tracing::debug;

use super::{
    EndpointConfig, ResponseMapping, StrategyType, TrustCenterStrategy,
    get_nested_str, navigate_json_path,
};
use crate::subprocessor::SubprocessorDomain;
use crate::vendor::RecordType;

/// Execute a trust center extraction strategy and return discovered subprocessors.
///
/// This is the single generic entry point. It dispatches on `strategy.strategy_type`
/// and uses shared JSON navigation/extraction utilities for all strategy types.
pub async fn execute_strategy(
    strategy: &TrustCenterStrategy,
    client: &reqwest::Client,
    html_content: Option<&str>,
    source_domain: &str,
) -> Result<Vec<SubprocessorDomain>> {
    let endpoint_url = resolve_slug(&strategy.endpoint.url, strategy.endpoint.slug.as_deref());

    debug!("Executing trust center strategy for {}: {:?}", source_domain, strategy.strategy_type);

    let json = match &strategy.strategy_type {
        StrategyType::GraphqlApi { query_template, variables, operation_name } => {
            execute_graphql(client, &endpoint_url, query_template, variables, operation_name.as_deref(),
                            strategy.endpoint.slug.as_deref()).await?
        }
        StrategyType::RestApi { method, body_template, headers } => {
            execute_rest(client, &endpoint_url, method, body_template.as_deref(), headers,
                         strategy.endpoint.slug.as_deref()).await?
        }
        StrategyType::EmbeddedBase64Json { locator_pattern } => {
            let html = require_html(html_content, &strategy.endpoint)?;
            extract_embedded_base64(&html, locator_pattern)?
        }
        StrategyType::EmbeddedJsObject { locator_pattern } => {
            let html = require_html(html_content, &strategy.endpoint)?;
            extract_embedded_js_object(&html, locator_pattern)?
        }
        StrategyType::HydrationData { script_selector, data_path } => {
            let html = require_html(html_content, &strategy.endpoint)?;
            extract_hydration_data(&html, script_selector, data_path)?
        }
    };

    extract_subprocessors_from_json(&json, &strategy.response_mapping, source_domain)
}

// ============================================================================
// Strategy type executors
// ============================================================================

async fn execute_graphql(
    client: &reqwest::Client,
    endpoint_url: &str,
    query_template: &str,
    variables: &std::collections::HashMap<String, serde_json::Value>,
    operation_name: Option<&str>,
    slug: Option<&str>,
) -> Result<serde_json::Value> {
    let query = resolve_slug(query_template, slug);

    // Resolve slug placeholders in variables
    let resolved_vars: std::collections::HashMap<String, serde_json::Value> = variables
        .iter()
        .map(|(k, v)| {
            let resolved = match v {
                serde_json::Value::String(s) => {
                    serde_json::Value::String(resolve_slug(s, slug))
                }
                other => other.clone(),
            };
            (k.clone(), resolved)
        })
        .collect();

    let mut body = serde_json::json!({
        "query": query,
        "variables": resolved_vars,
    });

    if let Some(op_name) = operation_name {
        body["operationName"] = serde_json::Value::String(op_name.to_string());
    }

    debug!("GraphQL request to {}: operation={:?}", endpoint_url, operation_name);

    let response = client
        .post(endpoint_url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("GraphQL request failed: HTTP {}", response.status()));
    }

    let json: serde_json::Value = response.json().await?;

    // Check for GraphQL errors
    if let Some(errors) = json.get("errors") {
        if let Some(arr) = errors.as_array() {
            if !arr.is_empty() {
                let msg = arr.first()
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown GraphQL error");
                return Err(anyhow::anyhow!("GraphQL error: {}", msg));
            }
        }
    }

    Ok(json)
}

async fn execute_rest(
    client: &reqwest::Client,
    endpoint_url: &str,
    method: &str,
    body_template: Option<&str>,
    headers: &std::collections::HashMap<String, String>,
    slug: Option<&str>,
) -> Result<serde_json::Value> {
    debug!("REST {} request to {}", method, endpoint_url);

    let mut request = match method.to_uppercase().as_str() {
        "POST" => {
            let mut req = client.post(endpoint_url);
            if let Some(body) = body_template {
                let resolved = resolve_slug(body, slug);
                req = req.body(resolved).header("Content-Type", "application/json");
            }
            req
        }
        _ => client.get(endpoint_url),
    };

    request = request.header("Accept", "application/json");
    for (key, value) in headers {
        request = request.header(key, value);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("REST request failed: HTTP {}", response.status()));
    }

    Ok(response.json().await?)
}

fn extract_embedded_base64(html: &str, locator_pattern: &str) -> Result<serde_json::Value> {
    debug!("Extracting embedded base64 JSON with pattern: {}", locator_pattern);

    let regex = fancy_regex::Regex::new(locator_pattern)
        .map_err(|e| anyhow::anyhow!("Invalid base64 locator pattern: {}", e))?;

    let captures = regex.captures(html)
        .map_err(|e| anyhow::anyhow!("Regex error: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("Base64 pattern not found in HTML"))?;

    let b64_str = captures.get(1)
        .ok_or_else(|| anyhow::anyhow!("No capture group in base64 pattern"))?
        .as_str();

    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64_str)
        .map_err(|e| anyhow::anyhow!("Base64 decode failed: {}", e))?;

    let json_str = String::from_utf8(decoded)
        .map_err(|e| anyhow::anyhow!("Base64 decoded content is not valid UTF-8: {}", e))?;

    serde_json::from_str(&json_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse decoded JSON: {}", e))
}

fn extract_embedded_js_object(html: &str, locator_pattern: &str) -> Result<serde_json::Value> {
    debug!("Extracting embedded JS object with pattern: {}", locator_pattern);

    let regex = fancy_regex::Regex::new(locator_pattern)
        .map_err(|e| anyhow::anyhow!("Invalid JS object locator pattern: {}", e))?;

    let captures = regex.captures(html)
        .map_err(|e| anyhow::anyhow!("Regex error: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("JS object pattern not found in HTML"))?;

    let json_str = captures.get(1)
        .ok_or_else(|| anyhow::anyhow!("No capture group in JS object pattern"))?
        .as_str();

    serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse embedded JS object as JSON: {}", e))
}

fn extract_hydration_data(
    html: &str,
    script_selector: &str,
    data_path: &str,
) -> Result<serde_json::Value> {
    debug!("Extracting hydration data: selector={}, path={}", script_selector, data_path);

    let document = Html::parse_document(html);
    let selector = Selector::parse(script_selector)
        .map_err(|_| anyhow::anyhow!("Invalid CSS selector: {}", script_selector))?;

    let script_element = document.select(&selector)
        .next()
        .ok_or_else(|| anyhow::anyhow!("Script element not found: {}", script_selector))?;

    let text: String = script_element.text().collect();

    let json: serde_json::Value = serde_json::from_str(text.trim())
        .map_err(|e| anyhow::anyhow!("Failed to parse hydration data as JSON: {}", e))?;

    // Navigate to the specific data path
    let target = navigate_json_path(&json, data_path)
        .ok_or_else(|| anyhow::anyhow!("Data path '{}' not found in hydration data", data_path))?;

    Ok(target.clone())
}

// ============================================================================
// Shared extraction utilities
// ============================================================================

/// Extract subprocessor records from a JSON value using the response mapping.
fn extract_subprocessors_from_json(
    json: &serde_json::Value,
    mapping: &ResponseMapping,
    source_domain: &str,
) -> Result<Vec<SubprocessorDomain>> {
    // Navigate to the subprocessors array
    let target = navigate_json_path(json, &mapping.subprocessors_path)
        .ok_or_else(|| anyhow::anyhow!(
            "Path '{}' not found in response JSON", mapping.subprocessors_path
        ))?;

    let items = target.as_array()
        .ok_or_else(|| anyhow::anyhow!(
            "Path '{}' is not an array (got {:?})",
            mapping.subprocessors_path,
            target
        ))?;

    debug!("Found {} items at path '{}'", items.len(), mapping.subprocessors_path);

    let mut vendors = Vec::new();
    for item in items {
        // Extract the company name
        let name = match get_nested_str(item, &mapping.name_field) {
            Some(n) => n.trim().to_string(),
            None => continue,
        };

        if name.is_empty() || name.len() < 2 {
            continue;
        }

        // Try to extract domain from the URL field
        let domain = if let Some(ref url_field) = mapping.url_field {
            get_nested_str(item, url_field)
                .and_then(|url_text| extract_domain_from_url_text(url_text))
        } else {
            None
        };

        // If no domain from URL, the caller's pipeline will handle org-to-domain resolution.
        // Store the org name as the domain for now (prefixed to indicate it needs resolution).
        let domain = domain.unwrap_or_else(|| {
            format!("_org:{}", name)
        });

        // Build evidence string from configured fields
        let evidence = if mapping.evidence_fields.is_empty() {
            name.clone()
        } else {
            mapping.evidence_fields.iter()
                .filter_map(|f| get_nested_str(item, f))
                .collect::<Vec<_>>()
                .join(" | ")
        };

        vendors.push(SubprocessorDomain {
            domain,
            source_type: RecordType::TrustCenterApi,
            raw_record: evidence,
        });
    }

    debug!("Extracted {} subprocessor records for {}", vendors.len(), source_domain);
    Ok(vendors)
}

/// Extract a domain from URL text like "https://aws.amazon.com" or "cloudflare.com".
fn extract_domain_from_url_text(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    // Try parsing as URL first
    if let Ok(url) = url::Url::parse(text) {
        if let Some(host) = url.host_str() {
            let domain = host.trim_start_matches("www.").to_lowercase();
            if domain.contains('.') && !domain.starts_with('.') {
                return Some(domain);
            }
        }
    }

    // Try adding a scheme and parsing
    let with_scheme = if !text.contains("://") {
        format!("https://{}", text)
    } else {
        text.to_string()
    };

    if let Ok(url) = url::Url::parse(&with_scheme) {
        if let Some(host) = url.host_str() {
            let domain = host.trim_start_matches("www.").to_lowercase();
            if domain.contains('.') && !domain.starts_with('.') {
                return Some(domain);
            }
        }
    }

    // Last resort: check if the text itself looks like a domain
    let text_lower = text.to_lowercase();
    if text_lower.contains('.') && !text_lower.contains(' ')
        && text_lower.len() > 3 && text_lower.len() < 100
    {
        return Some(text_lower.trim_start_matches("www.").to_string());
    }

    None
}

/// Replace `{{slug}}` placeholders in a string with the actual slug value.
fn resolve_slug(template: &str, slug: Option<&str>) -> String {
    match slug {
        Some(s) => template.replace("{{slug}}", s),
        None => template.to_string(),
    }
}

/// Get HTML content, either from provided content or by indicating browser is needed.
fn require_html<'a>(html_content: Option<&'a str>, endpoint: &EndpointConfig) -> Result<String> {
    match html_content {
        Some(content) => Ok(content.to_string()),
        None => {
            if endpoint.requires_browser {
                Err(anyhow::anyhow!("Strategy requires browser-rendered HTML but none was provided"))
            } else {
                Err(anyhow::anyhow!("No HTML content provided for embedded data extraction"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_from_url_text() {
        assert_eq!(extract_domain_from_url_text("https://aws.amazon.com"), Some("aws.amazon.com".to_string()));
        assert_eq!(extract_domain_from_url_text("https://www.cloudflare.com/"), Some("cloudflare.com".to_string()));
        assert_eq!(extract_domain_from_url_text("cloudflare.com"), Some("cloudflare.com".to_string()));
        assert_eq!(extract_domain_from_url_text("https://cloud.mongodb.com/"), Some("cloud.mongodb.com".to_string()));
        assert_eq!(extract_domain_from_url_text(""), None);
        assert_eq!(extract_domain_from_url_text("just a name"), None);
    }

    #[test]
    fn test_resolve_slug() {
        assert_eq!(resolve_slug("https://api.com/{{slug}}/data", Some("acme")),
                   "https://api.com/acme/data");
        assert_eq!(resolve_slug("https://api.com/data", None),
                   "https://api.com/data");
    }

    #[test]
    fn test_navigate_json_path() {
        let json = serde_json::json!({
            "data": {
                "trust": {
                    "subprocessors": [
                        {"name": "AWS", "url": "aws.amazon.com"}
                    ]
                }
            }
        });

        let result = navigate_json_path(&json, "data.trust.subprocessors");
        assert!(result.is_some());
        assert!(result.unwrap().is_array());

        assert!(navigate_json_path(&json, "data.nonexistent").is_none());
        assert!(navigate_json_path(&json, "").unwrap().is_object());
    }

    #[test]
    fn test_extract_subprocessors_from_json() {
        let json = serde_json::json!({
            "data": {
                "subprocessors": [
                    {"name": "Cloudflare", "url": "https://cloudflare.com", "purpose": "CDN"},
                    {"name": "Datadog", "url": "https://datadoghq.com", "purpose": "Monitoring"},
                    {"name": "Anthropic", "url": "https://anthropic.com", "purpose": "AI"}
                ]
            }
        });

        let mapping = ResponseMapping {
            subprocessors_path: "data.subprocessors".to_string(),
            name_field: "name".to_string(),
            url_field: Some("url".to_string()),
            purpose_field: Some("purpose".to_string()),
            location_field: None,
            evidence_fields: vec!["name".to_string(), "purpose".to_string()],
        };

        let result = extract_subprocessors_from_json(&json, &mapping, "example.com").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].domain, "cloudflare.com");
        assert_eq!(result[1].domain, "datadoghq.com");
        assert_eq!(result[2].domain, "anthropic.com");
        assert_eq!(result[0].source_type, RecordType::TrustCenterApi);
    }
}
