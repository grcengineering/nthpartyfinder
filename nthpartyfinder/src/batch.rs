//! Batch domain analysis module for processing multiple domains from CSV/JSON files
//!
//! Supports:
//! - CSV files with one domain per line or a "domain" column
//! - JSON files with array of domain strings or objects with "domain" field
//! - Parallel processing of multiple domains
//! - Individual and combined output options
//! - Error resilience (continue processing if individual domains fail)

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

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
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .as_deref()
        {
            Some("csv") => Some(Self::Csv),
            Some("json") => Some(Self::Json),
            _ => None,
        }
    }
}

/// Parse domain list from a file (auto-detects format from extension)
pub fn parse_domain_file(path: &Path) -> Result<Vec<DomainEntry>> {
    let format = InputFormat::from_path(path).context(format!(
        "Cannot determine input format from file extension. Expected .csv or .json: {}",
        path.display()
    ))?;

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
#[cfg_attr(coverage_nightly, coverage(off))]
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

        let headers = reader
            .headers()
            .context("Failed to read CSV headers")?
            .clone();

        // Find column indices
        let domain_idx = headers
            .iter()
            .position(|h| h.to_lowercase() == "domain")
            .context("CSV must have a 'domain' column when using headers")?;
        let label_idx = headers.iter().position(|h| h.to_lowercase() == "label");

        for result in reader.records() {
            let record = result.context("Failed to parse CSV record")?;

            let domain = record
                .get(domain_idx)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            if let Some(domain) = domain {
                // Validate domain format — loudly. A silently dropped input row
                // means the batch summary under-reports scope with no signal.
                if !is_valid_domain(&domain) {
                    tracing::warn!(
                        "Skipping invalid domain '{}' from batch input (not a valid hostname)",
                        domain
                    );
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

            // Validate domain format — loudly (see CSV path above).
            if !is_valid_domain(domain) {
                tracing::warn!(
                    "Skipping invalid domain '{}' from batch input (not a valid hostname)",
                    domain
                );
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
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn parse_json_domains(content: &str) -> Result<Vec<DomainEntry>> {
    let value: serde_json::Value =
        serde_json::from_str(content).context("Failed to parse JSON content")?;

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
                } else {
                    tracing::warn!(
                        "Skipping invalid domain '{}' from JSON batch input (not a valid hostname)",
                        domain
                    );
                }
            }

            // Object element: {domain: "...", label: "..."}
            serde_json::Value::Object(obj) => {
                if let Some(serde_json::Value::String(domain)) = obj.get("domain") {
                    let domain = domain.trim();
                    if !domain.is_empty() && is_valid_domain(domain) {
                        let label = obj
                            .get("label")
                            .and_then(|v| v.as_str())
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty());

                        entries.push(DomainEntry {
                            domain: domain.to_string(),
                            label,
                        });
                    } else {
                        tracing::warn!(
                            "Skipping invalid domain '{}' from JSON batch input (not a valid hostname)",
                            domain
                        );
                    }
                } else {
                    tracing::warn!(
                        "Skipping JSON batch entry without a string 'domain' field: {}",
                        item
                    );
                }
            }

            _ => {
                tracing::warn!("Skipping non-string, non-object JSON batch entry: {}", item);
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
    if domain.starts_with('.')
        || domain.ends_with('.')
        || domain.starts_with('-')
        || domain.ends_with('-')
    {
        return false;
    }

    // Must not contain consecutive dots
    if domain.contains("..") {
        return false;
    }

    // Check for valid characters
    domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Generate a unique output filename for a domain
pub fn domain_output_filename(domain: &str, format: &str) -> String {
    let domain_clean = domain.replace(['.', ':'], "_");
    format!("Nth Party Analysis for {}.{}", domain_clean, format)
}

/// Export batch summary to JSON file
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn export_batch_summary(summary: &BatchSummary, output_path: &Path) -> Result<()> {
    let json =
        serde_json::to_string_pretty(summary).context("Failed to serialize batch summary")?;

    fs::write(output_path, json).context(format!(
        "Failed to write batch summary to: {}",
        output_path.display()
    ))?;

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
    summary.total_relationships = summary
        .domain_results
        .iter()
        .map(|r| r.relationship_count)
        .sum();
}

// ============================================================================
// P2.15: cross-root dedup sharing
//
// `--input-file` runs N roots back to back, and today every root gets a fresh
// `discovered_vendors` map, a fresh `processed_domains` gate and a fresh `dns_pool`. Any vendor
// that two roots share — which is most of them, since the popular SaaS/CDN vendors sit under
// nearly every parent — is resolved from scratch N times. That is the depth-2+ dedup mandate
// applied across roots instead of within one.
//
// The catch is that "dedup structure" covers two categories that must NOT be treated alike, and
// getting that wrong silently deletes findings from a report rather than merely slowing things
// down. See `sharing_scope` for the classification and the concrete failure mode behind it.
// ============================================================================

/// A scan-lifetime structure the batch loop currently rebuilds for every root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DedupLayer {
    /// domain → normalized organization name.
    OrgResolution,
    /// The DoH resolver pool and its per-name answer memo.
    DnsAnswers,
    /// The recursion gate (`processed_domains`): "this domain has already been expanded".
    RecursionGate,
    /// `ScanDedup`'s claim-to-run gate for subfinder enumeration of a registrable base.
    SubfinderApexClaim,
    /// `ScanDedup`'s claim-to-run gate for the CT-log query of a registrable base.
    CtApexClaim,
    /// `ScanDedup`'s claim-to-run gate for the SaaS-tenant probe of a registrable base.
    SaasApexClaim,
    /// The per-root relationship set that becomes that root's report.
    EdgeSink,
}

/// Whether a layer may be held across roots in a batch run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingScope {
    /// The value is a fact about the domain itself, identical no matter which root asked. Holding
    /// it across roots saves the lookup and changes no report.
    SharedAcrossRoots,
    /// Reusing this across roots would suppress work whose *output* the later root still needs.
    PerRoot,
}

/// Which layers may be shared across batch roots, and which must be rebuilt per root.
///
/// The dividing line is not "is it expensive" but **what a hit means**. An answer memo hit means
/// "here is the answer, again" — free to share. A claim-gate hit means "somebody else is doing
/// this, so you skip it", and the results land in *that* caller's edge set, not yours. Share a
/// claim gate across roots and the second root's report quietly loses every edge the first root
/// claimed — a silent recall loss dressed up as a cache hit, which is the same failure mode as
/// memoizing an outage as absence.
///
/// The sharpest instance is [`DedupLayer::RecursionGate`]: `analysis::discover_nth_parties_minimal`
/// opens by checking `processed_domains` for its own root domain and returning `Ok(vec![])` on a
/// hit. Sharing that gate across roots means any root whose domain was already touched as a vendor
/// of an earlier root returns an **empty report** — success, zero relationships, no error.
pub fn sharing_scope(layer: DedupLayer) -> SharingScope {
    match layer {
        DedupLayer::OrgResolution | DedupLayer::DnsAnswers => SharingScope::SharedAcrossRoots,
        DedupLayer::RecursionGate
        | DedupLayer::SubfinderApexClaim
        | DedupLayer::CtApexClaim
        | DedupLayer::SaasApexClaim
        | DedupLayer::EdgeSink => SharingScope::PerRoot,
    }
}

/// Write gate for the cross-root org memo: may this resolution be handed to later roots?
///
/// Only when it is a *fact* we actually established. A transport failure means "we could not
/// look", never "this domain has no organization" — and the cost of getting that wrong is far
/// higher here than in a single scan, because a shared memo freezes the bad value for every
/// remaining root in the batch. A domain-derived echo (`analysis::is_likely_inferred_org`) is the
/// same hazard wearing a name: it is the fallback we emit when resolution did not land, so
/// sharing it would pin the echo across the whole run and cost the batch exactly the attribution
/// accuracy the org-resolution work exists to produce. Both cases fall through and let the next
/// root resolve the domain properly, which is the pre-P2.15 behaviour and therefore never worse.
///
/// This is the cross-root twin of `subprocessor::may_record_subprocessor_absence`.
pub fn may_share_org_resolution(
    resolved: &str,
    is_domain_echo: bool,
    transport_failed: bool,
) -> bool {
    !transport_failed && !is_domain_echo && !resolved.trim().is_empty()
}

/// Scan-lifetime state a batch run holds across roots.
///
/// Holds only the layers `sharing_scope` marks [`SharingScope::SharedAcrossRoots`]. Per-root
/// structures are handed out fresh by [`BatchDedupContext::new_root_recursion_gate`] and
/// [`BatchDedupContext::seed_root_org_map`] so edge isolation is structural rather than a rule
/// somebody has to remember at the call site.
///
/// The org memo is deliberately *copied into* each root rather than shared by handle. Roots write
/// their raw resolutions — echoes and all — into the map they are given, and only the entries that
/// clear [`may_share_org_resolution`] are folded back in. Sharing the handle directly would make
/// every root's fallback visible to every later root with no gate in between.
pub struct BatchDedupContext {
    /// domain → organization, accumulated across roots. Gated on write, never on read.
    org_memo: Mutex<HashMap<String, String>>,
    dns_pool: Arc<crate::dns::DnsServerPool>,
    roots_served: AtomicUsize,
    /// Entries this batch reused instead of re-resolving. Reported so the sharing is measurable
    /// rather than merely asserted.
    org_memo_hits: AtomicUsize,
}

impl BatchDedupContext {
    /// Build the shared context for a batch run. The DNS pool is constructed once and handed to
    /// every root, so its answer memo and failure counters span the batch.
    pub fn new(dns_pool: Arc<crate::dns::DnsServerPool>) -> Self {
        Self {
            org_memo: Mutex::new(HashMap::new()),
            dns_pool,
            roots_served: AtomicUsize::new(0),
            org_memo_hits: AtomicUsize::new(0),
        }
    }

    /// The batch-wide DNS pool.
    pub fn dns_pool(&self) -> Arc<crate::dns::DnsServerPool> {
        Arc::clone(&self.dns_pool)
    }

    /// A fresh recursion gate for one root. Never shared — see [`sharing_scope`].
    pub fn new_root_recursion_gate(&self) -> Arc<Mutex<HashSet<String>>> {
        Arc::new(Mutex::new(HashSet::new()))
    }

    /// A root's own org map, pre-seeded with everything earlier roots established.
    ///
    /// The root owns this map outright: mutating it cannot affect the shared memo or any other
    /// root until [`Self::absorb_root_org_map`] folds the gated subset back.
    pub async fn seed_root_org_map(&self) -> Arc<Mutex<HashMap<String, String>>> {
        self.roots_served.fetch_add(1, Ordering::Relaxed);
        let seeded = self.org_memo.lock().await.clone();
        crate::perf::METRICS.batch_org_memo_seeded.hit();
        self.org_memo_hits
            .fetch_add(seeded.len(), Ordering::Relaxed);
        Arc::new(Mutex::new(seeded))
    }

    /// Fold a finished root's resolutions back into the shared memo.
    ///
    /// `is_domain_echo` is the caller's echo predicate (`analysis::is_likely_inferred_org`), taken
    /// as a parameter so this stays pure of the attribution heuristics and cannot drift from them.
    /// First good value wins: a later root never overwrites an org an earlier root established,
    /// so the memo cannot degrade as the batch runs.
    ///
    /// Returns how many entries were newly shared.
    pub async fn absorb_root_org_map(
        &self,
        root_map: &Mutex<HashMap<String, String>>,
        is_domain_echo: impl Fn(&str, &str) -> bool,
    ) -> usize {
        let root = root_map.lock().await;
        let mut memo = self.org_memo.lock().await;
        let mut added = 0;
        for (domain, org) in root.iter() {
            if memo.contains_key(domain) {
                continue;
            }
            if !may_share_org_resolution(org, is_domain_echo(domain, org), false) {
                continue;
            }
            memo.insert(domain.clone(), org.clone());
            added += 1;
        }
        crate::perf::METRICS.batch_org_memo_absorbed.hit();
        added
    }

    /// Entries currently held for later roots.
    pub async fn shared_org_count(&self) -> usize {
        self.org_memo.lock().await.len()
    }

    /// Roots that have been handed a seeded map.
    pub fn roots_served(&self) -> usize {
        self.roots_served.load(Ordering::Relaxed)
    }

    /// Total org entries handed to roots instead of being re-resolved.
    pub fn org_memo_hits(&self) -> usize {
        self.org_memo_hits.load(Ordering::Relaxed)
    }
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
        assert_eq!(
            InputFormat::from_path(Path::new("domains.csv")),
            Some(InputFormat::Csv)
        );
        assert_eq!(
            InputFormat::from_path(Path::new("domains.CSV")),
            Some(InputFormat::Csv)
        );
        assert_eq!(
            InputFormat::from_path(Path::new("domains.json")),
            Some(InputFormat::Json)
        );
        assert_eq!(
            InputFormat::from_path(Path::new("domains.JSON")),
            Some(InputFormat::Json)
        );
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

    // ============ Additional Coverage Tests ============

    #[test]
    fn test_parse_domain_file_csv() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("domains.csv");
        std::fs::write(&csv_path, "example.com\ntest.org\n").unwrap();
        let result = parse_domain_file(&csv_path).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[1].domain, "test.org");
    }

    #[test]
    fn test_parse_domain_file_json() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("domains.json");
        std::fs::write(&json_path, r#"["example.com", "test.org"]"#).unwrap();
        let result = parse_domain_file(&json_path).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_domain_file_unknown_extension() {
        let dir = tempfile::tempdir().unwrap();
        let txt_path = dir.path().join("domains.txt");
        std::fs::write(&txt_path, "example.com\n").unwrap();
        let result = parse_domain_file(&txt_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cannot determine"));
    }

    #[test]
    fn test_parse_domain_file_not_found() {
        let result = parse_domain_file(Path::new("/nonexistent/file.csv"));
        assert!(result.is_err());
    }

    #[test]
    fn test_domain_entry_new() {
        let entry = DomainEntry::new("example.com");
        assert_eq!(entry.domain, "example.com");
        assert!(entry.label.is_none());
    }

    #[test]
    fn test_domain_entry_with_label() {
        let entry = DomainEntry::with_label("example.com", "Example Inc");
        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.label, Some("Example Inc".to_string()));
    }

    #[test]
    fn test_parse_json_domains_field_not_array() {
        let content = r#"{"domains": "not-an-array"}"#;
        let result = parse_json_domains(content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be an array"));
    }

    #[test]
    fn test_parse_json_object_no_domains_key() {
        let content = r#"{"other": "value"}"#;
        let result = parse_json_domains(content);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must have a 'domains'"));
    }

    #[test]
    fn test_parse_json_bare_value() {
        let content = r#""just a string""#;
        let result = parse_json_domains(content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be an array"));
    }

    #[test]
    fn test_parse_json_array_with_object_missing_domain_key() {
        let content = r#"[{"name": "not-domain"}]"#;
        let result = parse_json_domains(content).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_json_array_with_empty_domain_in_object() {
        let content = r#"[{"domain": ""}]"#;
        let result = parse_json_domains(content).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_json_array_with_empty_string() {
        let content = r#"["", "  "]"#;
        let result = parse_json_domains(content).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_json_object_with_label_empty() {
        let content = r#"[{"domain": "example.com", "label": ""}]"#;
        let result = parse_json_domains(content).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].label.is_none()); // empty label filtered
    }

    #[test]
    fn test_parse_csv_with_header_empty_domain() {
        let content = "domain,label\n,Some Label\nexample.com,Good";
        let result = parse_csv_domains(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].domain, "example.com");
    }

    #[test]
    fn test_parse_csv_with_header_invalid_domain() {
        let content = "domain,label\ninvalid,No Dot\nexample.com,Good";
        let result = parse_csv_domains(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].domain, "example.com");
    }

    #[test]
    fn test_parse_csv_with_header_label_empty() {
        let content = "domain,label\nexample.com,";
        let result = parse_csv_domains(content).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].label.is_none());
    }

    #[test]
    fn test_parse_csv_simple_comma_separated() {
        let content = "example.com,some extra data\ntest.org,more data";
        let result = parse_csv_domains(content).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[1].domain, "test.org");
    }

    #[test]
    fn test_is_valid_domain_special_chars() {
        assert!(!is_valid_domain("example .com"));
        assert!(!is_valid_domain("exam$ple.com"));
    }

    #[test]
    fn test_export_batch_summary() {
        let dir = tempfile::tempdir().unwrap();
        let output_path = dir.path().join("summary.json");
        let mut summary = new_batch_summary();
        finalize_batch_summary(&mut summary);
        export_batch_summary(&summary, &output_path).unwrap();
        let content = std::fs::read_to_string(&output_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["total_domains"], 0);
    }

    #[test]
    fn test_new_batch_summary() {
        let summary = new_batch_summary();
        assert_eq!(summary.total_domains, 0);
        assert_eq!(summary.successful, 0);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.total_relationships, 0);
        assert!(summary.domain_results.is_empty());
        assert!(!summary.started_at.is_empty());
        assert!(summary.completed_at.is_empty());
    }

    #[test]
    fn test_domain_entry_serde_roundtrip() {
        let entry = DomainEntry::with_label("test.org", "Test Corp");
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: DomainEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, entry);
    }

    #[test]
    fn test_domain_output_filename_with_colon() {
        let result = domain_output_filename("example.com:8080", "csv");
        assert_eq!(result, "Nth Party Analysis for example_com_8080.csv");
    }

    // ============ P2.15: cross-root dedup sharing ============

    /// Stand-in for `analysis::is_likely_inferred_org`: the org is an echo when it is just the
    /// domain's first label. Keeps these tests pinned to the sharing contract rather than to the
    /// attribution heuristic, which has its own tests.
    fn echo_stub(domain: &str, org: &str) -> bool {
        domain
            .split('.')
            .next()
            .is_some_and(|label| label.eq_ignore_ascii_case(org))
    }

    #[test]
    fn test_sharing_scope_classification() {
        // Answer memos: a hit means "here is the answer again".
        assert_eq!(
            sharing_scope(DedupLayer::OrgResolution),
            SharingScope::SharedAcrossRoots
        );
        assert_eq!(
            sharing_scope(DedupLayer::DnsAnswers),
            SharingScope::SharedAcrossRoots
        );

        // Claim gates and edge state: a hit means "somebody else did it, and kept the output".
        // Sharing any of these across roots costs the later root its findings.
        for layer in [
            DedupLayer::RecursionGate,
            DedupLayer::SubfinderApexClaim,
            DedupLayer::CtApexClaim,
            DedupLayer::SaasApexClaim,
            DedupLayer::EdgeSink,
        ] {
            assert_eq!(
                sharing_scope(layer),
                SharingScope::PerRoot,
                "{:?} suppresses work whose output a later root still needs",
                layer
            );
        }
    }

    #[test]
    fn test_may_share_org_resolution_truth_table() {
        // The only shareable case: a real name, resolved cleanly.
        assert!(may_share_org_resolution("Twilio SendGrid", false, false));

        // A transport failure means "we could not look" — never shared as a fact.
        assert!(!may_share_org_resolution("Twilio SendGrid", false, true));
        assert!(!may_share_org_resolution("sendgrid", true, true));

        // A domain-derived echo is the fallback we emit when resolution did not land. Sharing it
        // would pin the echo for every remaining root in the batch.
        assert!(!may_share_org_resolution("sendgrid", true, false));

        // Empty and whitespace-only are non-answers.
        assert!(!may_share_org_resolution("", false, false));
        assert!(!may_share_org_resolution("   ", false, false));
        assert!(!may_share_org_resolution("\t\n", false, false));
    }

    #[tokio::test]
    async fn test_seeded_root_map_is_isolated_until_absorbed() {
        let ctx = BatchDedupContext::new(Arc::new(crate::dns::DnsServerPool::new()));

        let root_a = ctx.seed_root_org_map().await;
        root_a
            .lock()
            .await
            .insert("sendgrid.net".to_string(), "Twilio SendGrid".to_string());

        // Root A's own map moved; the shared memo has not, so a concurrently-seeded root cannot
        // see a half-finished root's work.
        assert_eq!(ctx.shared_org_count().await, 0);
        let root_b = ctx.seed_root_org_map().await;
        assert!(root_b.lock().await.is_empty());

        assert_eq!(ctx.absorb_root_org_map(&root_a, echo_stub).await, 1);
        assert_eq!(ctx.shared_org_count().await, 1);

        // Only a root seeded *after* the absorb inherits it.
        let root_c = ctx.seed_root_org_map().await;
        assert_eq!(
            root_c.lock().await.get("sendgrid.net").map(String::as_str),
            Some("Twilio SendGrid")
        );
        assert_eq!(ctx.roots_served(), 3);
        assert_eq!(ctx.org_memo_hits(), 1, "only root C inherited an entry");
    }

    #[tokio::test]
    async fn test_absorb_drops_domain_echoes_so_a_later_root_re_resolves() {
        let ctx = BatchDedupContext::new(Arc::new(crate::dns::DnsServerPool::new()));

        let root_a = ctx.seed_root_org_map().await;
        {
            let mut m = root_a.lock().await;
            m.insert("stripe.com".to_string(), "Stripe, Inc.".to_string());
            // The unresolved fallback: the org is just the domain's own label.
            m.insert("okta.com".to_string(), "okta".to_string());
        }

        assert_eq!(ctx.absorb_root_org_map(&root_a, echo_stub).await, 1);

        let root_b = ctx.seed_root_org_map().await;
        let seeded = root_b.lock().await;
        assert_eq!(
            seeded.get("stripe.com").map(String::as_str),
            Some("Stripe, Inc.")
        );
        assert!(
            !seeded.contains_key("okta.com"),
            "an echo must not be frozen into the batch — root B has to resolve it itself"
        );
    }

    #[tokio::test]
    async fn test_absorb_never_downgrades_an_established_org() {
        let ctx = BatchDedupContext::new(Arc::new(crate::dns::DnsServerPool::new()));

        let root_a = ctx.seed_root_org_map().await;
        root_a
            .lock()
            .await
            .insert("cloudflare.com".to_string(), "Cloudflare, Inc.".to_string());
        ctx.absorb_root_org_map(&root_a, echo_stub).await;

        // A later root resolved the same domain to something weaker. First good value wins, so the
        // memo cannot degrade as the batch runs.
        let root_b = ctx.seed_root_org_map().await;
        root_b
            .lock()
            .await
            .insert("cloudflare.com".to_string(), "Cloudflare".to_string());
        assert_eq!(
            ctx.absorb_root_org_map(&root_b, echo_stub).await,
            0,
            "already established — nothing new to share"
        );

        let root_c = ctx.seed_root_org_map().await;
        assert_eq!(
            root_c
                .lock()
                .await
                .get("cloudflare.com")
                .map(String::as_str),
            Some("Cloudflare, Inc.")
        );
    }

    #[tokio::test]
    async fn test_recursion_gates_are_never_shared_between_roots() {
        // The isolation guarantee that keeps a root's report attributable: two roots must never
        // receive the same gate, or the second returns Ok(vec![]) for anything the first touched.
        let ctx = BatchDedupContext::new(Arc::new(crate::dns::DnsServerPool::new()));

        let gate_a = ctx.new_root_recursion_gate();
        let gate_b = ctx.new_root_recursion_gate();
        assert!(
            !Arc::ptr_eq(&gate_a, &gate_b),
            "each root must own its recursion gate"
        );

        gate_a.lock().await.insert("vanta.com".to_string());
        assert!(
            !gate_b.lock().await.contains("vanta.com"),
            "root B must still be free to expand a domain root A already walked"
        );
    }

    #[tokio::test]
    async fn test_dns_pool_is_the_same_handle_for_every_root() {
        let pool = Arc::new(crate::dns::DnsServerPool::new());
        let ctx = BatchDedupContext::new(Arc::clone(&pool));
        assert!(Arc::ptr_eq(&ctx.dns_pool(), &pool));
        assert!(Arc::ptr_eq(&ctx.dns_pool(), &ctx.dns_pool()));
    }

    #[test]
    fn test_export_batch_summary_write_error() {
        let summary = new_batch_summary();
        let result = export_batch_summary(&summary, Path::new("/nonexistent/dir/summary.json"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to write batch summary"));
    }
}
