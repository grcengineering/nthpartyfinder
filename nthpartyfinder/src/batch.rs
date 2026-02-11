//! Batch domain analysis module for processing multiple domains from CSV/JSON files
//!
//! Supports:
//! - CSV files with one domain per line or a "domain" column
//! - JSON files with array of domain strings or objects with "domain" field
//! - Parallel processing of multiple domains
//! - Individual and combined output options
//! - Error resilience (continue processing if individual domains fail)

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;
use chrono::Utc;

/// Represents a domain entry from a batch input file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DomainEntry {
    /// The domain to analyze
    pub domain: String,
    /// Optional label/identifier for the domain (e.g., company name)
    #[serde(default)]
    pub label: Option<String>,
}

impl DomainEntry {
    /// Create a new domain entry with just a domain
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            label: None,
        }
    }

    /// Create a new domain entry with domain and label
    pub fn with_label(domain: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            label: Some(label.into()),
        }
    }
}

/// Result of analyzing a single domain in a batch
#[derive(Debug, Clone, Serialize)]
pub struct DomainAnalysisResult {
    /// The domain that was analyzed
    pub domain: String,
    /// Optional label for the domain
    pub label: Option<String>,
    /// Whether the analysis was successful
    pub success: bool,
    /// Error message if analysis failed
    pub error: Option<String>,
    /// Number of vendor relationships found
    pub relationship_count: usize,
    /// Path to the individual output file (if generated)
    pub output_file: Option<String>,
    /// Duration of analysis in seconds
    pub duration_secs: f64,
}

/// Summary of a batch analysis run
#[derive(Debug, Clone, Serialize)]
pub struct BatchSummary {
    /// Total number of domains processed
    pub total_domains: usize,
    /// Number of successful analyses
    pub successful: usize,
    /// Number of failed analyses
    pub failed: usize,
    /// Total vendor relationships found across all domains
    pub total_relationships: usize,
    /// Results for each domain
    pub domain_results: Vec<DomainAnalysisResult>,
    /// Total batch duration in seconds
    pub total_duration_secs: f64,
    /// Timestamp when batch started
    pub started_at: String,
    /// Timestamp when batch completed
    pub completed_at: String,
}

/// Input format for batch domain files
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputFormat {
    /// CSV file
    Csv,
    /// JSON file
    Json,
}

impl InputFormat {
    /// Detect format from file extension
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()).as_deref() {
            Some("csv") => Some(Self::Csv),
            Some("json") => Some(Self::Json),
            _ => None,
        }
    }
}

/// Parse domain list from a file (auto-detects format from extension)
pub fn parse_domain_file(path: &Path) -> Result<Vec<DomainEntry>> {
    let format = InputFormat::from_path(path)
        .context(format!("Cannot determine input format from file extension. Expected .csv or .json: {}", path.display()))?;

    let content = fs::read_to_string(path)
        .context(format!("Failed to read input file: {}", path.display()))?;

    match format {
        InputFormat::Csv => parse_csv_domains(&content),
        InputFormat::Json => parse_json_domains(&content),
    }
}

/// Parse domains from CSV content
///
/// Supports two formats:
/// 1. One domain per line (no header)
/// 2. CSV with "domain" column header (and optional "label" column)
pub fn parse_csv_domains(content: &str) -> Result<Vec<DomainEntry>> {
    let mut domains = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    if lines.is_empty() {
        return Ok(domains);
    }

    // Check if first line looks like a header
    let first_line = lines[0].to_lowercase();
    let has_header = first_line.contains("domain");

    if has_header {
        // Parse as CSV with headers
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(content.as_bytes());

        let headers = reader.headers()
            .context("Failed to read CSV headers")?
            .clone();

        // Find column indices
        let domain_idx = headers.iter().position(|h| h.to_lowercase() == "domain")
            .context("CSV must have a 'domain' column when using headers")?;
        let label_idx = headers.iter().position(|h| h.to_lowercase() == "label");

        for result in reader.records() {
            let record = result.context("Failed to parse CSV record")?;

            let domain = record.get(domain_idx)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            if let Some(domain) = domain {
                // Validate domain format
                if !is_valid_domain(&domain) {
                    continue;
                }

                let label = label_idx
                    .and_then(|idx| record.get(idx))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());

                domains.push(DomainEntry { domain, label });
            }
        }
    } else {
        // Parse as simple one-domain-per-line format
        for line in lines {
            // Handle CSV with comma-separated values (take first column as domain)
            let domain = line.split(',').next().unwrap_or(line).trim();

            if domain.is_empty() || domain.starts_with('#') {
                continue;
            }

            // Validate domain format
            if !is_valid_domain(domain) {
                continue;
            }

            domains.push(DomainEntry::new(domain));
        }
    }

    Ok(domains)
}

/// Parse domains from JSON content
///
/// Supports three formats:
/// 1. Array of domain strings: ["example.com", "test.org"]
/// 2. Array of objects with "domain" field: [{"domain": "example.com"}, {"domain": "test.org"}]
/// 3. Object with "domains" array: {"domains": ["example.com", "test.org"]}
pub fn parse_json_domains(content: &str) -> Result<Vec<DomainEntry>> {
    let value: serde_json::Value = serde_json::from_str(content)
        .context("Failed to parse JSON content")?;

    // Try to extract domains from various JSON structures
    let entries = match &value {
        // Direct array at root
        serde_json::Value::Array(arr) => parse_json_array(arr)?,

        // Object with "domains" key
        serde_json::Value::Object(obj) => {
            if let Some(domains_value) = obj.get("domains") {
                if let serde_json::Value::Array(arr) = domains_value {
                    parse_json_array(arr)?
                } else {
                    bail!("'domains' field must be an array");
                }
            } else {
                bail!("JSON object must have a 'domains' array field");
            }
        }

        _ => bail!("JSON must be an array of domains or an object with 'domains' field"),
    };

    Ok(entries)
}

/// Parse a JSON array into domain entries
fn parse_json_array(arr: &[serde_json::Value]) -> Result<Vec<DomainEntry>> {
    let mut entries = Vec::new();

    for item in arr {
        match item {
            // String element: just a domain
            serde_json::Value::String(domain) => {
                let domain = domain.trim();
                if !domain.is_empty() && is_valid_domain(domain) {
                    entries.push(DomainEntry::new(domain));
                }
            }

            // Object element: {domain: "...", label: "..."}
            serde_json::Value::Object(obj) => {
                if let Some(serde_json::Value::String(domain)) = obj.get("domain") {
                    let domain = domain.trim();
                    if !domain.is_empty() && is_valid_domain(domain) {
                        let label = obj.get("label")
                            .and_then(|v| v.as_str())
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty());

                        entries.push(DomainEntry { domain: domain.to_string(), label });
                    }
                }
            }

            _ => {
                // Skip invalid entries
            }
        }
    }

    Ok(entries)
}

/// Basic domain validation
fn is_valid_domain(domain: &str) -> bool {
    // Must contain at least one dot
    if !domain.contains('.') {
        return false;
    }

    // Must not contain protocols or paths
    if domain.contains("://") || domain.contains('/') {
        return false;
    }

    // Must not start or end with dot or hyphen
    if domain.starts_with('.') || domain.ends_with('.')
        || domain.starts_with('-') || domain.ends_with('-') {
        return false;
    }

    // Must not contain consecutive dots
    if domain.contains("..") {
        return false;
    }

    // Check for valid characters
    domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Generate a unique output filename for a domain
pub fn domain_output_filename(domain: &str, format: &str) -> String {
    let domain_clean = domain.replace('.', "_").replace(':', "_");
    format!("Nth Party Analysis for {}.{}", domain_clean, format)
}

/// Export batch summary to JSON file
pub fn export_batch_summary(summary: &BatchSummary, output_path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(summary)
        .context("Failed to serialize batch summary")?;

    fs::write(output_path, json)
        .context(format!("Failed to write batch summary to: {}", output_path.display()))?;

    Ok(())
}

/// Create a new batch summary
pub fn new_batch_summary() -> BatchSummary {
    BatchSummary {
        total_domains: 0,
        successful: 0,
        failed: 0,
        total_relationships: 0,
        domain_results: Vec::new(),
        total_duration_secs: 0.0,
        started_at: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        completed_at: String::new(),
    }
}

/// Finalize a batch summary with end time
pub fn finalize_batch_summary(summary: &mut BatchSummary) {
    summary.completed_at = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    summary.total_domains = summary.domain_results.len();
    summary.successful = summary.domain_results.iter().filter(|r| r.success).count();
    summary.failed = summary.domain_results.iter().filter(|r| !r.success).count();
    summary.total_relationships = summary.domain_results.iter().map(|r| r.relationship_count).sum();
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============ CSV Parsing Tests ============

    #[test]
    fn test_parse_csv_simple_domains() {
        let content = "example.com\ntest.org\nfoo.bar.com";
        let result = parse_csv_domains(content).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[1].domain, "test.org");
        assert_eq!(result[2].domain, "foo.bar.com");
        assert!(result.iter().all(|e| e.label.is_none()));
    }

    #[test]
    fn test_parse_csv_with_header() {
        let content = "domain,label\nexample.com,Example Inc\ntest.org,Test Corp";
        let result = parse_csv_domains(content).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[0].label, Some("Example Inc".to_string()));
        assert_eq!(result[1].domain, "test.org");
        assert_eq!(result[1].label, Some("Test Corp".to_string()));
    }

    #[test]
    fn test_parse_csv_domain_only_header() {
        let content = "domain\nexample.com\ntest.org";
        let result = parse_csv_domains(content).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "example.com");
        assert!(result[0].label.is_none());
    }

    #[test]
    fn test_parse_csv_skip_comments_and_empty() {
        let content = "example.com\n# this is a comment\n\ntest.org";
        let result = parse_csv_domains(content).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[1].domain, "test.org");
    }

    #[test]
    fn test_parse_csv_skip_invalid_domains() {
        let content = "example.com\ninvalid\ntest.org\nno-dot";
        let result = parse_csv_domains(content).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[1].domain, "test.org");
    }

    #[test]
    fn test_parse_csv_empty() {
        let content = "";
        let result = parse_csv_domains(content).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_csv_whitespace_trimming() {
        let content = "  example.com  \n  test.org  ";
        let result = parse_csv_domains(content).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[1].domain, "test.org");
    }

    // ============ JSON Parsing Tests ============

    #[test]
    fn test_parse_json_string_array() {
        let content = r#"["example.com", "test.org", "foo.bar.com"]"#;
        let result = parse_json_domains(content).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[1].domain, "test.org");
        assert_eq!(result[2].domain, "foo.bar.com");
    }

    #[test]
    fn test_parse_json_object_array() {
        let content = r#"[
            {"domain": "example.com"},
            {"domain": "test.org", "label": "Test Corp"}
        ]"#;
        let result = parse_json_domains(content).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "example.com");
        assert!(result[0].label.is_none());
        assert_eq!(result[1].domain, "test.org");
        assert_eq!(result[1].label, Some("Test Corp".to_string()));
    }

    #[test]
    fn test_parse_json_domains_field() {
        let content = r#"{"domains": ["example.com", "test.org"]}"#;
        let result = parse_json_domains(content).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[1].domain, "test.org");
    }

    #[test]
    fn test_parse_json_mixed_array() {
        let content = r#"[
            "example.com",
            {"domain": "test.org", "label": "Test Corp"}
        ]"#;
        let result = parse_json_domains(content).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[1].domain, "test.org");
        assert_eq!(result[1].label, Some("Test Corp".to_string()));
    }

    #[test]
    fn test_parse_json_skip_invalid() {
        let content = r#"["example.com", "invalid", "test.org", 123, null]"#;
        let result = parse_json_domains(content).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[1].domain, "test.org");
    }

    #[test]
    fn test_parse_json_empty_array() {
        let content = "[]";
        let result = parse_json_domains(content).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_json_invalid() {
        let content = "not valid json";
        let result = parse_json_domains(content);
        assert!(result.is_err());
    }

    // ============ Domain Validation Tests ============

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("my-site.example.com"));
        assert!(is_valid_domain("test123.org"));

        assert!(!is_valid_domain("invalid"));
        assert!(!is_valid_domain("http://example.com"));
        assert!(!is_valid_domain("example.com/path"));
        assert!(!is_valid_domain(".example.com"));
        assert!(!is_valid_domain("example.com."));
        assert!(!is_valid_domain("-example.com"));
        assert!(!is_valid_domain("example.com-"));
        assert!(!is_valid_domain("example..com"));
    }

    // ============ Input Format Detection Tests ============

    #[test]
    fn test_input_format_detection() {
        assert_eq!(InputFormat::from_path(Path::new("domains.csv")), Some(InputFormat::Csv));
        assert_eq!(InputFormat::from_path(Path::new("domains.CSV")), Some(InputFormat::Csv));
        assert_eq!(InputFormat::from_path(Path::new("domains.json")), Some(InputFormat::Json));
        assert_eq!(InputFormat::from_path(Path::new("domains.JSON")), Some(InputFormat::Json));
        assert_eq!(InputFormat::from_path(Path::new("domains.txt")), None);
        assert_eq!(InputFormat::from_path(Path::new("domains")), None);
    }

    // ============ Utility Function Tests ============

    #[test]
    fn test_domain_output_filename() {
        assert_eq!(
            domain_output_filename("example.com", "csv"),
            "Nth Party Analysis for example_com.csv"
        );
        assert_eq!(
            domain_output_filename("sub.example.com", "json"),
            "Nth Party Analysis for sub_example_com.json"
        );
    }

    #[test]
    fn test_batch_summary_finalize() {
        let mut summary = new_batch_summary();
        summary.domain_results.push(DomainAnalysisResult {
            domain: "example.com".to_string(),
            label: None,
            success: true,
            error: None,
            relationship_count: 10,
            output_file: Some("output.csv".to_string()),
            duration_secs: 5.0,
        });
        summary.domain_results.push(DomainAnalysisResult {
            domain: "test.org".to_string(),
            label: None,
            success: false,
            error: Some("DNS lookup failed".to_string()),
            relationship_count: 0,
            output_file: None,
            duration_secs: 1.0,
        });

        finalize_batch_summary(&mut summary);

        assert_eq!(summary.total_domains, 2);
        assert_eq!(summary.successful, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.total_relationships, 10);
        assert!(!summary.completed_at.is_empty());
    }
}
