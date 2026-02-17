use anyhow::Result;
use reqwest;
use scraper::{Html, Selector};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use serde::{Deserialize, Serialize};
use crate::dns::LogFailure;
use crate::vendor::RecordType;
use crate::rate_limit::RateLimitContext;

use fancy_regex::Regex;
// rayon available if needed for parallel processing
use std::collections::BTreeMap;
use once_cell::sync::Lazy;

/// Maximum allowed length for regex patterns loaded from cache files.
/// Patterns exceeding this limit are rejected to mitigate ReDoS attacks (H006 fix).
const MAX_REGEX_PATTERN_LENGTH: usize = 500;

/// Maximum HTTP response body size (10 MB).
/// Bodies exceeding this limit are truncated during streaming reads
/// rather than rejected after full download, preventing memory exhaustion
/// from adversarial or unexpectedly large responses.
const MAX_HTTP_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Read an HTTP response body with streaming truncation.
/// Reads the body in chunks, stopping at `max_bytes` to prevent
/// memory exhaustion. Returns the body as a String (lossy UTF-8 conversion
/// for truncated multi-byte boundaries).
async fn read_response_body_capped(response: reqwest::Response, max_bytes: usize) -> Result<String> {
    use futures::StreamExt;

    let mut body = Vec::with_capacity(max_bytes.min(256 * 1024)); // Pre-alloc up to 256KB
    let mut stream = response.bytes_stream();
    let mut total = 0usize;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow::anyhow!("Stream read error: {}", e))?;
        let remaining = max_bytes.saturating_sub(total);
        if remaining == 0 {
            debug!("HTTP response truncated at {} bytes (limit: {})", total, max_bytes);
            break;
        }
        let take = chunk.len().min(remaining);
        body.extend_from_slice(&chunk[..take]);
        total += take;
    }

    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Validate and compile a regex pattern from cache, rejecting patterns that are
/// too long (potential ReDoS vectors). Returns None for rejected patterns.
/// Uses fancy_regex which has built-in backtracking limits for additional safety.
fn validate_and_compile_regex(pattern: &str) -> Option<regex::Regex> {
    if pattern.len() > MAX_REGEX_PATTERN_LENGTH {
        tracing::warn!(
            "Rejected regex pattern from cache: length {} exceeds limit of {} characters (potential ReDoS). Pattern prefix: '{}'",
            pattern.len(),
            MAX_REGEX_PATTERN_LENGTH,
            &pattern[..pattern.len().min(80)]
        );
        return None;
    }
    match regex::Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(e) => {
            tracing::warn!("Failed to compile regex pattern from cache: {}", e);
            None
        }
    }
}

// Compile CSS selectors once at startup for performance (fixes B015).
// Safety (L006): All .unwrap() calls below are safe because the selector strings are
// compile-time constants containing valid CSS selectors. Selector::parse() only fails
// on malformed CSS selector syntax, which cannot occur with these hardcoded values.
static DIV_SELECTOR: Lazy<Selector> = Lazy::new(|| {
    Selector::parse("div").unwrap()
});

static ALL_ELEMENTS_SELECTOR: Lazy<Selector> = Lazy::new(|| {
    Selector::parse("*").unwrap()
});

static PARAGRAPH_SELECTOR: Lazy<Selector> = Lazy::new(|| {
    Selector::parse("p").unwrap()
});

static HEADER_ROW_SELECTOR: Lazy<Selector> = Lazy::new(|| {
    Selector::parse("thead tr, tr:first-child").unwrap()
});

static HEADER_CELL_SELECTOR: Lazy<Selector> = Lazy::new(|| {
    Selector::parse("th, td").unwrap()
});

static DATA_ROW_SELECTOR: Lazy<Selector> = Lazy::new(|| {
    Selector::parse("tbody tr, tr").unwrap()
});

static CELL_SELECTOR: Lazy<Selector> = Lazy::new(|| {
    Selector::parse("td, th").unwrap()
});

static TH_SELECTOR: Lazy<Selector> = Lazy::new(|| {
    Selector::parse("th").unwrap()
});

static PARAGRAPH_DIV_SELECTOR: Lazy<Selector> = Lazy::new(|| {
    Selector::parse("p, div").unwrap()
});

static TR_SELECTOR: Lazy<Selector> = Lazy::new(|| {
    Selector::parse("tr").unwrap()
});

/// Represents a discovered subprocessor from web page analysis
#[derive(Debug, Clone)]
pub struct SubprocessorDomain {
    pub domain: String,
    pub source_type: RecordType,
    pub raw_record: String, // Full HTML content or specific section where domain was found
}

/// Represents a pending org-to-domain mapping that was inferred via generic fallback
/// and needs user confirmation before being cached
#[derive(Debug, Clone)]
pub struct PendingOrgMapping {
    /// The organization name as found in the HTML (e.g., "Acme Corp, Inc.")
    pub org_name: String,
    /// The inferred domain from generic fallback logic (e.g., "acmecorp.com")
    pub inferred_domain: String,
    /// The source domain whose subprocessor page contained this org
    pub source_domain: String,
}

/// Result of subprocessor extraction including any pending mappings that need confirmation
#[derive(Debug, Clone, Default)]
pub struct SubprocessorExtractionResult {
    /// Successfully extracted subprocessor domains
    pub subprocessors: Vec<SubprocessorDomain>,
    /// Mappings that were inferred via generic fallback and need user confirmation
    pub pending_mappings: Vec<PendingOrgMapping>,
}

/// Result of domain extraction indicating whether it came from cache or fallback
#[derive(Debug, Clone)]
pub struct DomainExtractionResult {
    pub domain: String,
    /// True if the mapping came from generic fallback (needs user confirmation)
    pub is_fallback: bool,
}

/// Extraction patterns for parsing subprocessor entities from HTML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionPatterns {
    /// CSS selectors for finding entity name columns (e.g., "th:contains('Entity Name')", ".entity-column")
    pub entity_column_selectors: Vec<String>,
    /// Text patterns to identify entity name headers (e.g., "entity name", "company name", "vendor")
    pub entity_header_patterns: Vec<String>,
    /// CSS selectors for table containers (e.g., "table.subprocessors", ".vendor-table")
    pub table_selectors: Vec<String>,
    /// CSS selectors for list containers (e.g., "ul.vendors", ".processor-list li")
    pub list_selectors: Vec<String>,
    /// Context patterns to confirm this is a subprocessor page (e.g., "third party", "subprocessors")
    pub context_patterns: Vec<String>,
    /// Regex patterns to extract domains from entity names (e.g., r"\(([^)]+\.(com|org|io))\)")
    pub domain_extraction_patterns: Vec<String>,
    /// Domain-specific custom extraction rules that override generic methods
    #[serde(default)]
    pub custom_extraction_rules: Option<CustomExtractionRules>,
    /// Whether this pattern set is domain-specific (contributed by users) vs generic fallback
    #[serde(default)]
    pub is_domain_specific: bool,
}

/// Domain-specific custom extraction rules for precise subprocessor extraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomExtractionRules {
    /// Custom CSS selectors that directly target subprocessor elements for this specific domain
    #[serde(default)]
    pub direct_selectors: Vec<DirectSelector>,
    /// Custom regex patterns specific to this domain's formatting
    #[serde(default)]
    pub custom_regex_patterns: Vec<CustomRegexPattern>,
    /// Instructions for handling domain-specific edge cases
    pub special_handling: Option<SpecialHandling>,
}

/// A direct CSS selector that targets subprocessor elements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectSelector {
    /// CSS selector that directly finds subprocessor names (e.g., ".vendor-name", "td:nth-child(2)")
    pub selector: String,
    /// Optional attribute to extract from (e.g., "data-company", "title")
    pub attribute: Option<String>,
    /// Optional transformation to apply to the text (e.g., "trim", "lowercase", "remove_suffix")
    pub transform: Option<String>,
    /// Description of what this selector targets for maintainability
    pub description: String,
}

/// A custom regex pattern for domain-specific text extraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRegexPattern {
    /// Regex pattern with capture groups (e.g., r"Company:\s*([^,\n]+)")
    pub pattern: String,
    /// Which capture group contains the organization name (usually 1)
    pub capture_group: usize,
    /// Description of what this pattern matches
    pub description: String,
}

/// Special handling instructions for domain-specific edge cases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialHandling {
    /// Skip standard extraction methods and only use custom rules
    #[serde(default)]
    pub skip_generic_methods: bool,
    /// Custom organization name to domain mapping overrides
    pub custom_org_to_domain_mapping: Option<std::collections::HashMap<String, String>>,
    /// Patterns to explicitly exclude from results (false positives specific to this domain)
    #[serde(default)]
    pub exclusion_patterns: Vec<String>,
}

impl Default for ExtractionPatterns {
    fn default() -> Self {
        Self {
            entity_column_selectors: vec![
                "th:contains('Entity Name')".to_string(),
                "th:contains('Company Name')".to_string(),
                "th:contains('Vendor')".to_string(),
                "th:contains('Name')".to_string(),
            ],
            entity_header_patterns: vec![
                "entity name".to_string(),
                "company name".to_string(),
                "vendor".to_string(),
                "processor".to_string(),
                "sub-processor".to_string(),
                "subprocessor".to_string(),
                "company".to_string(),
                "organization".to_string(),
                "service provider".to_string(),
                "name".to_string(),
            ],
            table_selectors: vec![
                "table".to_string(),
                ".subprocessors-table".to_string(),
                ".vendor-table".to_string(),
            ],
            list_selectors: vec![
                "ul li".to_string(),
                "ol li".to_string(),
                ".vendor-list li".to_string(),
            ],
            context_patterns: vec![
                "third-party sub-processors".to_string(),
                "subprocessors".to_string(),
                "sub-processors".to_string(),
                "processors".to_string(),
                "third party".to_string(),
                "service providers".to_string(),
                "hosting and infrastructure".to_string(),
                "communications technology".to_string(),
                "cloud infrastructure".to_string(),
                "data processing".to_string(),
            ],
            domain_extraction_patterns: vec![
                r"\(([^)]+\.(com|org|io|net|co))\)".to_string(),
                r"(https?://)?([a-zA-Z0-9.-]+\.(com|org|io|net|co))".to_string(),
            ],
            custom_extraction_rules: None,
            is_domain_specific: false,
        }
    }
}

/// Cached subprocessor URL information for a specific domain with extraction patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubprocessorUrlCacheEntry {
    pub domain: String,
    pub working_subprocessor_url: String,
    pub last_successful_access: u64,
    pub cache_version: u32,
    /// Extraction patterns specific to this domain's subprocessor page structure
    pub extraction_patterns: Option<ExtractionPatterns>,
    /// Metadata about successful extractions to help optimize patterns
    pub extraction_metadata: Option<ExtractionMetadata>,
    /// Trust center extraction strategy (auto-discovered or manually configured)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_center_strategy: Option<crate::trust_center::TrustCenterStrategy>,
}

/// Metadata about extraction success to help optimize patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionMetadata {
    /// Number of entities successfully extracted with current patterns
    pub successful_extractions: u32,
    /// Column index that contained entity names (for table parsing)
    pub successful_entity_column_index: Option<usize>,
    /// Which pattern successfully identified the entity column
    pub successful_header_pattern: Option<String>,
    /// Last extraction timestamp
    pub last_extraction_time: u64,
    /// AI-derived adaptive patterns discovered through content analysis
    pub adaptive_patterns: Option<AdaptivePatterns>,
}

/// AI-derived patterns discovered through content analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptivePatterns {
    pub discovered_selectors: Vec<DomSelector>,
    pub confidence_score: f64,
    pub discovery_timestamp: u64,
    pub validation_count: u32,
}

/// A DOM selector with context and confidence
#[derive(Debug, Clone, Serialize, Deserialize)]  
pub struct DomSelector {
    pub selector: String,
    pub selector_type: SelectorType,
    pub confidence: f64,
    pub sample_matches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelectorType {
    Table,
    List, 
    Container,
    DirectText,
}

/// Detected organization with context
#[derive(Debug, Clone)]
pub struct DetectedOrganization {
    pub name: String,
    pub confidence: f64,
    pub dom_context: DomContext,
}

/// DOM context around detected organization
#[derive(Debug, Clone)]
pub struct DomContext {
    pub parent_tags: Vec<String>,
    pub sibling_count: usize, 
    pub css_classes: Vec<String>,
    pub text_content: String,
    pub xpath_like: String,
}

/// Modular cache manager that stores working subprocessor URLs
/// 
/// This cache only stores URLs that were successfully found to contain subprocessor data.
/// The actual content is scraped fresh every time to detect changes.
/// Each vendor domain gets its own JSON file in the cache/ directory.
///
/// Cache behavior:
/// - Only successful subprocessor URL discoveries are cached
/// - Each vendor domain has its own cache file: cache/{domain}.json
/// - Cache files contain only the working URL and access timestamp
/// - Content is always scraped fresh from cached URLs
///
/// Manual management:
/// - Delete specific cache files to refresh URL discovery for domains
/// - Delete the entire cache/ directory to clear all URL cache
///
/// ## Concurrency (M006)
///
/// The `SubprocessorCache` is wrapped in `Arc<RwLock<SubprocessorCache>>` in
/// `SubprocessorAnalyzer`, which provides in-process synchronization for concurrent
/// access. However, the individual cache file I/O operations (read/write via
/// `tokio::fs`) are not protected by file-level locks. This is an architectural
/// limitation, but the actual risk of collision is low because:
///
/// 1. The cache is domain-specific (one file per domain), and parallel processing
///    typically processes different domains concurrently.
/// 2. Write operations are non-atomic at the filesystem level, but cache corruption
///    would only affect a single domain's cached URL and is self-healing (the cache
///    entry would fail to deserialize and be treated as a cache miss).
#[derive(Debug, Default)]
pub struct SubprocessorCache {
    cache_dir: PathBuf,
    cache_version: u32,
}

impl SubprocessorCache {
    const CACHE_VERSION: u32 = 2;  // Updated for extraction patterns support
    const CACHE_DIR: &'static str = "cache";
    
    pub fn new() -> Self {
        Self {
            cache_dir: PathBuf::from(Self::CACHE_DIR),
            cache_version: Self::CACHE_VERSION,
        }
    }
    
    /// Load cache (just initialize the cache directory)
    pub async fn load() -> Self {
        let cache = Self::new();
        
        // Create cache directory if it doesn't exist
        if let Err(e) = tokio::fs::create_dir_all(&cache.cache_dir).await {
            debug!("Failed to create cache directory: {}", e);
        } else {
            debug!("Initialized modular cache system in directory: {:?}", cache.cache_dir);
        }
        
        cache
    }
    
    /// Check if a vendor domain has a cached working subprocessor URL
    pub async fn get_cached_subprocessor_url(&self, domain: &str) -> Option<String> {
        let cache_file = self.get_cache_file_path(domain);
        
        if let Ok(content) = tokio::fs::read_to_string(&cache_file).await {
            if let Ok(entry) = serde_json::from_str::<SubprocessorUrlCacheEntry>(&content) {
                if entry.cache_version == Self::CACHE_VERSION {
                    debug!("Cache hit for domain {}: working URL {}", domain, entry.working_subprocessor_url);
                    return Some(entry.working_subprocessor_url);
                } else {
                    debug!("Cache version mismatch for {}, ignoring cached URL", domain);
                }
            }
        }
        
        None
    }
    
    /// Get cached extraction patterns for a domain, or default patterns if not cached
    pub async fn get_extraction_patterns(&self, domain: &str) -> ExtractionPatterns {
        let cache_file = self.get_cache_file_path(domain);
        
        if let Ok(content) = tokio::fs::read_to_string(&cache_file).await {
            if let Ok(entry) = serde_json::from_str::<SubprocessorUrlCacheEntry>(&content) {
                if entry.cache_version == Self::CACHE_VERSION {
                    if let Some(patterns) = entry.extraction_patterns {
                        debug!("Using cached extraction patterns for domain {}", domain);
                        return patterns;
                    }
                }
            }
        }
        
        debug!("No domain-specific extraction patterns found for domain {}, returning empty patterns", domain);
        // Return empty patterns instead of generic defaults - forces initial extraction with minimal patterns
        ExtractionPatterns {
            entity_column_selectors: vec!["th:contains('Entity Name')".to_string()], // Minimal bootstrap selector
            entity_header_patterns: Vec::new(),
            table_selectors: vec!["table".to_string()], // Minimal bootstrap selector
            list_selectors: Vec::new(),
            context_patterns: vec!["subprocessor".to_string(), "third party".to_string()], // Minimal context
            domain_extraction_patterns: Vec::new(),
            custom_extraction_rules: None,
            is_domain_specific: false,
        }
    }
    
    /// Get cached entry with all metadata for a domain
    pub async fn get_cached_entry(&self, domain: &str) -> Option<SubprocessorUrlCacheEntry> {
        let cache_file = self.get_cache_file_path(domain);
        
        if let Ok(content) = tokio::fs::read_to_string(&cache_file).await {
            if let Ok(entry) = serde_json::from_str::<SubprocessorUrlCacheEntry>(&content) {
                if entry.cache_version == Self::CACHE_VERSION {
                    return Some(entry);
                }
            }
        }
        
        None
    }
    
    /// Cache a working subprocessor URL for a domain
    pub async fn cache_working_url(&self, domain: &str, subprocessor_url: &str) -> Result<()> {
        let cache_file = self.get_cache_file_path(domain);
        
        // Load existing entry to preserve extraction patterns and metadata
        let mut entry = self.get_cached_entry(domain).await.unwrap_or_else(|| {
            SubprocessorUrlCacheEntry {
                domain: domain.to_string(),
                working_subprocessor_url: String::new(),
                last_successful_access: 0,
                cache_version: Self::CACHE_VERSION,
                extraction_patterns: Some(ExtractionPatterns::default()),
                extraction_metadata: None,
                trust_center_strategy: None,
            }
        });

        // Update URL and timestamp while preserving patterns and metadata
        entry.working_subprocessor_url = subprocessor_url.to_string();
        entry.last_successful_access = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        entry.cache_version = Self::CACHE_VERSION;
        
        let content = serde_json::to_string_pretty(&entry)?;
        tokio::fs::write(&cache_file, content).await?;
        
        debug!("Cached working subprocessor URL for domain {} while preserving extraction patterns: {}", domain, subprocessor_url);
        Ok(())
    }
    
    /// Update extraction patterns and metadata for a cached domain
    pub async fn update_extraction_info(&self, domain: &str, patterns: ExtractionPatterns, metadata: ExtractionMetadata) -> Result<()> {
        let cache_file = self.get_cache_file_path(domain);
        
        // Load existing entry or create new one
        let mut entry = self.get_cached_entry(domain).await.unwrap_or_else(|| {
            SubprocessorUrlCacheEntry {
                domain: domain.to_string(),
                working_subprocessor_url: String::new(),
                last_successful_access: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                cache_version: Self::CACHE_VERSION,
                extraction_patterns: None,
                extraction_metadata: None,
                trust_center_strategy: None,
            }
        });

        entry.extraction_patterns = Some(patterns);
        entry.extraction_metadata = Some(metadata);
        entry.last_successful_access = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let content = serde_json::to_string_pretty(&entry)?;
        tokio::fs::write(&cache_file, content).await?;
        
        debug!("Updated extraction patterns and metadata for domain {}", domain);
        Ok(())
    }
    
    /// Get cache file path for a specific domain
    pub fn get_cache_file_path(&self, domain: &str) -> PathBuf {
        // Sanitize domain for filesystem - prevent path traversal (M005 fix)
        let safe_domain: String = domain.chars()
            .map(|c| match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => c,
                _ => '_',
            })
            .collect();
        // Ensure no path traversal via ".." sequences
        let safe_domain = safe_domain.replace("..", "_");
        // Validate that the sanitized domain doesn't produce an empty filename
        if safe_domain.is_empty() || safe_domain == "." {
            return self.cache_dir.join("_invalid_domain_.json");
        }
        self.cache_dir.join(format!("{}.json", safe_domain))
    }
    
    /// Clear cache for a specific domain
    pub async fn clear_domain_cache(&self, domain: &str) -> Result<bool> {
        let cache_file = self.get_cache_file_path(domain);
        
        if cache_file.exists() {
            tokio::fs::remove_file(&cache_file).await?;
            debug!("Cleared cache for domain: {}", domain);
            Ok(true)
        } else {
            debug!("No cache file found for domain: {}", domain);
            Ok(false)
        }
    }
    
    /// Clear all cached data
    pub async fn clear_all_cache(&self) -> Result<usize> {
        let mut count = 0;
        
        if let Ok(mut entries) = tokio::fs::read_dir(&self.cache_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Err(e) = tokio::fs::remove_file(entry.path()).await {
                        debug!("Failed to remove cache file {:?}: {}", entry.path(), e);
                    } else {
                        count += 1;
                    }
                }
            }
        }
        
        debug!("Cleared {} cache files", count);
        Ok(count)
    }

    /// Add confirmed org-to-domain mappings to a domain's cache
    /// This saves user-confirmed mappings so they're used in future extractions
    pub async fn add_confirmed_mappings(&self, domain: &str, mappings: &[(String, String)]) -> Result<()> {
        if mappings.is_empty() {
            return Ok(());
        }

        let cache_file = self.get_cache_file_path(domain);

        // Load existing entry or create new one
        let mut entry = if let Ok(content) = tokio::fs::read_to_string(&cache_file).await {
            serde_json::from_str::<SubprocessorUrlCacheEntry>(&content).unwrap_or_else(|_| SubprocessorUrlCacheEntry {
                domain: domain.to_string(),
                working_subprocessor_url: String::new(),
                last_successful_access: 0,
                cache_version: Self::CACHE_VERSION,
                extraction_patterns: None,
                extraction_metadata: None,
                trust_center_strategy: None,
            })
        } else {
            SubprocessorUrlCacheEntry {
                domain: domain.to_string(),
                working_subprocessor_url: String::new(),
                last_successful_access: 0,
                cache_version: Self::CACHE_VERSION,
                extraction_patterns: None,
                extraction_metadata: None,
                trust_center_strategy: None,
            }
        };

        // Ensure extraction_patterns and custom_extraction_rules exist
        let patterns = entry.extraction_patterns.get_or_insert_with(|| ExtractionPatterns {
            entity_column_selectors: Vec::new(),
            entity_header_patterns: Vec::new(),
            table_selectors: Vec::new(),
            list_selectors: Vec::new(),
            context_patterns: Vec::new(),
            domain_extraction_patterns: Vec::new(),
            custom_extraction_rules: None,
            is_domain_specific: true,
        });

        let custom_rules = patterns.custom_extraction_rules.get_or_insert_with(|| CustomExtractionRules {
            direct_selectors: Vec::new(),
            custom_regex_patterns: Vec::new(),
            special_handling: None,
        });

        let special_handling = custom_rules.special_handling.get_or_insert_with(|| SpecialHandling {
            skip_generic_methods: true,
            custom_org_to_domain_mapping: Some(std::collections::HashMap::new()),
            exclusion_patterns: Vec::new(),
        });

        let org_mapping = special_handling.custom_org_to_domain_mapping.get_or_insert_with(std::collections::HashMap::new);

        // Add confirmed mappings with multiple variations of the org name
        for (org_name, domain_name) in mappings {
            let org_lower = org_name.trim().to_lowercase();
            org_mapping.insert(org_lower.clone(), domain_name.clone());

            // Add variations to improve matching
            // Remove trailing comma variation
            if org_lower.ends_with(',') {
                org_mapping.insert(org_lower.trim_end_matches(',').to_string(), domain_name.clone());
            } else {
                org_mapping.insert(format!("{},", org_lower), domain_name.clone());
            }

            // Remove business suffixes for base name
            let suffixes = [", inc.", ", llc", ", corp.", ", ltd.", " inc.", " llc", " corp.", " ltd.", ", inc", ", pbc"];
            for suffix in &suffixes {
                if let Some(base) = org_lower.strip_suffix(suffix) {
                    org_mapping.insert(base.trim().to_string(), domain_name.clone());
                }
            }
        }

        patterns.is_domain_specific = true;

        // Save updated cache
        let content = serde_json::to_string_pretty(&entry)?;
        tokio::fs::write(&cache_file, content).await?;

        debug!("Added {} confirmed mappings to cache for domain {}", mappings.len(), domain);
        Ok(())
    }
}

/// HTTP client for subprocessor page scraping
pub struct SubprocessorAnalyzer {
    client: reqwest::Client,
    cache: Arc<RwLock<SubprocessorCache>>,
    /// Pending org-to-domain mappings discovered via generic fallback that need user confirmation
    pending_mappings: Arc<RwLock<Vec<PendingOrgMapping>>>,
}

impl SubprocessorAnalyzer {
    /// Create HTTP client with production-ready configuration
    fn create_http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))  // Increased timeout for slower servers
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")  // Realistic browser user agent
            .redirect(reqwest::redirect::Policy::limited(5))
            .danger_accept_invalid_certs(false)  // Security: reject invalid certificates
            .https_only(true)                    // Security: force HTTPS
            .build()
            .expect("Failed to create HTTP client")
    }

    /// Create a new subprocessor analyzer with production-ready defaults
    pub async fn new() -> Self {
        let cache = SubprocessorCache::load().await;

        Self {
            client: Self::create_http_client(),
            cache: Arc::new(RwLock::new(cache)),
            pending_mappings: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create analyzer with existing cache (for sharing across instances)
    pub fn with_cache(cache: Arc<RwLock<SubprocessorCache>>) -> Self {
        Self {
            client: Self::create_http_client(),
            cache,
            pending_mappings: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get all pending org-to-domain mappings that need user confirmation
    /// These are mappings discovered via generic fallback during extraction
    pub async fn get_pending_mappings(&self) -> Vec<PendingOrgMapping> {
        self.pending_mappings.read().await.clone()
    }

    /// Clear all pending mappings (after user has confirmed or rejected them)
    pub async fn clear_pending_mappings(&self) {
        self.pending_mappings.write().await.clear();
    }

    /// Add a pending mapping that needs confirmation
    async fn add_pending_mapping(&self, mapping: PendingOrgMapping) {
        self.pending_mappings.write().await.push(mapping);
    }

    /// Add confirmed mappings to the cache for a specific domain
    pub async fn save_confirmed_mappings(&self, source_domain: &str, confirmed_mappings: &[(String, String)]) -> Result<()> {
        let cache = self.cache.write().await;
        cache.add_confirmed_mappings(source_domain, confirmed_mappings).await
    }

    /// Analyze a domain for subprocessor pages and extract vendor relationships
    pub async fn analyze_domain(&self, domain: &str, logger: Option<&dyn LogFailure>) -> Result<Vec<SubprocessorDomain>> {
        self.analyze_domain_with_logging(domain, logger, None).await
    }

    /// Analyze a domain with rate limiting support
    pub async fn analyze_domain_with_rate_limit(
        &self,
        domain: &str,
        logger: Option<&dyn LogFailure>,
        rate_limit_ctx: Option<&RateLimitContext>,
    ) -> Result<Vec<SubprocessorDomain>> {
        self.analyze_domain_with_full_options(domain, logger, None, rate_limit_ctx).await
    }

    /// Analyze a domain with additional debug logging for cache operations
    pub async fn analyze_domain_with_logging(&self, domain: &str, logger: Option<&dyn LogFailure>, debug_logger: Option<&crate::logger::AnalysisLogger>) -> Result<Vec<SubprocessorDomain>> {
        self.analyze_domain_with_full_options(domain, logger, debug_logger, None).await
    }

    /// Analyze a domain with all options including rate limiting
    pub async fn analyze_domain_with_full_options(
        &self,
        domain: &str,
        logger: Option<&dyn LogFailure>,
        debug_logger: Option<&crate::logger::AnalysisLogger>,
        rate_limit_ctx: Option<&RateLimitContext>,
    ) -> Result<Vec<SubprocessorDomain>> {
        if let Some(debug_logger) = &debug_logger {
            debug_logger.debug(&format!("🔍 Starting detailed subprocessor analysis for {}", domain));
        }
        
        // Check if we have a cached working URL for this domain
        let cached_url = {
            let cache = self.cache.read().await;
            cache.get_cached_subprocessor_url(domain).await
        };

        if let Some(url) = cached_url {
            debug!("Cache hit for domain {}: using cached URL {}", domain, url);
            debug!("📋 CACHE HIT PATH: Using cached URL for {}: {}", domain, url);
            if let Some(debug_logger) = &debug_logger {
                debug_logger.log_cache_hit_organization(domain, 1); // Just indicating cache hit
                debug_logger.debug(&format!("🔗 Using cached URL: {}", url));
                debug_logger.debug(&format!("🚀 Making HTTP request to cached URL: {}", url));
            }
            
            // Always scrape fresh content from cached URL
            // Apply HTTP rate limiting before the request
            if let Some(ctx) = rate_limit_ctx {
                ctx.http_limiter.acquire(domain).await;
            }
            let request_start = std::time::Instant::now();
            debug!("🔥🔥🔥 CACHED PATH: ABOUT TO CALL scrape_subprocessor_page for: {}", url);
            match self.scrape_subprocessor_page(&url, logger, domain).await {
                Ok(subprocessors) => {
                    let elapsed = request_start.elapsed();
                    debug!("Scraped {} subprocessors from cached URL: {}", subprocessors.len(), url);
                    if let Some(debug_logger) = &debug_logger {
                        debug_logger.debug(&format!("✅ HTTP request to cached URL {} completed in {:.2}s (found {} subprocessors)", 
                            url, elapsed.as_secs_f64(), subprocessors.len()));
                    }
                    
                    // Update the cache access time regardless of whether results are empty
                    let cache = self.cache.read().await;
                    if let Err(e) = cache.cache_working_url(domain, &url).await {
                        debug!("Failed to update cache timestamp for {}: {}", domain, e);
                    }
                    
                    // Return results even if empty - empty results are valid and should be cached
                    if !subprocessors.is_empty() {
                        debug!("Cached URL {} returned {} subprocessors for {}", url, subprocessors.len(), domain);
                    } else {
                        debug!("Cached URL {} returned no subprocessors for {} (this is valid and cached)", url, domain);
                    }
                    return Ok(subprocessors);
                }
                Err(e) => {
                    debug!("Cached URL {} failed for {}: {}, will try other URLs", url, domain, e);
                    if let Some(debug_logger) = &debug_logger {
                        debug_logger.debug(&format!("❌ Cached URL {} failed: {}", url, e));
                    }
                    // Clear the cache for this domain and fall through to URL discovery
                    let cache = self.cache.read().await;
                    if let Err(e) = cache.clear_domain_cache(domain).await {
                        debug!("Failed to clear stale cache for {}: {}", domain, e);
                    }
                }
            }
        } else {
            debug!("🆕 NO CACHE: Starting URL discovery for {}", domain);
            if let Some(debug_logger) = debug_logger {
                debug_logger.log_cache_miss_organization(domain);
            }
        }

        // URL discovery phase - try a limited number of most promising URLs
        let subprocessor_urls = self.generate_subprocessor_urls(domain);
        
        // Limit URL testing to prevent performance degradation
        const MAX_URLS_TO_TEST: usize = 25;
        const MAX_ANALYSIS_TIME: std::time::Duration = std::time::Duration::from_secs(15);
        
        let urls_to_test = if subprocessor_urls.len() > MAX_URLS_TO_TEST {
            debug!("Limiting URL testing to first {} URLs out of {} generated for performance", MAX_URLS_TO_TEST, subprocessor_urls.len());
            &subprocessor_urls[0..MAX_URLS_TO_TEST]
        } else {
            &subprocessor_urls
        };
        
        if let Some(debug_logger) = &debug_logger {
            debug_logger.debug(&format!("🌐 Testing {} subprocessor URLs for {} (limited from {})", 
                urls_to_test.len(), domain, subprocessor_urls.len()));
        }
        debug!("Analyzing {} potential subprocessor URLs for domain: {}", urls_to_test.len(), domain);

        let analysis_start = std::time::Instant::now();
        for (url_index, url) in urls_to_test.iter().enumerate() {
            // Check if we've exceeded our time budget
            if analysis_start.elapsed() > MAX_ANALYSIS_TIME {
                debug!("Subprocessor analysis time limit exceeded for {}, stopping URL discovery", domain);
                if let Some(debug_logger) = &debug_logger {
                    debug_logger.debug(&format!("⏰ Time limit exceeded after {:.2}s, stopping URL discovery", analysis_start.elapsed().as_secs_f64()));
                }
                break;
            }
            if let Some(debug_logger) = &debug_logger {
                debug_logger.debug(&format!("🔗 Checking URL {}/{}: {}",
                    url_index + 1, urls_to_test.len(), url));
                debug_logger.debug(&format!("🚀 Making HTTP request to: {}", url));
            }

            // Apply HTTP rate limiting before each request
            if let Some(ctx) = rate_limit_ctx {
                ctx.http_limiter.acquire(domain).await;
            }
            let request_start = std::time::Instant::now();
            debug!("🔥🔥🔥 ABOUT TO CALL scrape_subprocessor_page for: {}", url);
            match self.scrape_subprocessor_page(&url, logger, domain).await {
                Ok(subprocessors) => {
                    let elapsed = request_start.elapsed();
                    debug!("Found {} subprocessors from URL: {}", subprocessors.len(), url);
                    if let Some(debug_logger) = &debug_logger {
                        debug_logger.debug(&format!("✅ HTTP request to {} completed in {:.2}s (found {} subprocessors)",
                            url, elapsed.as_secs_f64(), subprocessors.len()));
                    }

                    // Cache successful URLs regardless of whether they return subprocessors
                    {
                        let cache = self.cache.read().await;
                        if let Err(e) = cache.cache_working_url(domain, &url).await {
                            debug!("Failed to cache working URL for {}: {}", domain, e);
                        } else {
                            debug!("Successfully cached URL for {}: {} (found {} subprocessors)", domain, url, subprocessors.len());
                        }
                    }

                    if !subprocessors.is_empty() {
                        debug!("Found working subprocessor URL for {}: {} - stopping URL discovery", domain, url);
                        if let Some(debug_logger) = &debug_logger {
                            debug_logger.debug(&format!("🎯 SUCCESS: Found {} subprocessors, stopping URL discovery", subprocessors.len()));
                        }
                        return Ok(subprocessors);
                    } else {
                        // HTTP succeeded but no subprocessors found - continue trying other URLs
                        debug!("HTTP request to {} succeeded but found 0 subprocessors - continuing to test other URLs", url);
                        if let Some(debug_logger) = &debug_logger {
                            debug_logger.debug(&format!("✅ No subprocessors found on {} (continuing to next URL)", url));
                        }
                        
                        // Continue to the next URL instead of returning
                        continue;
                    }
                }
                Err(e) => {
                    let elapsed = request_start.elapsed();
                    let error_msg = e.to_string();
                    debug!("Failed to scrape {}: {}", url, error_msg);
                    if let Some(debug_logger) = &debug_logger {
                        debug_logger.debug(&format!("❌ HTTP request to {} failed in {:.2}s: {}", 
                            url, elapsed.as_secs_f64(), error_msg));
                    }
                    
                    if let Some(logger) = logger {
                        logger.log_failure(domain, "HTTP::SUBPROCESSOR", &url, None, &format!("Failed to scrape: {}", e));
                    }
                }
            }
        }

        // No working subprocessor page found
        debug!("No subprocessor pages found for domain: {}", domain);
        Ok(Vec::new())
    }
    
    /// Get a reference to the cache for external access
    pub fn get_cache(&self) -> Arc<RwLock<SubprocessorCache>> {
        self.cache.clone()
    }
    
    /// Clear cache for a specific domain (removes their cache file)
    pub async fn clear_organization_cache(&self, domain: &str) -> bool {
        let cache = self.cache.read().await;
        match cache.clear_domain_cache(domain).await {
            Ok(cleared) => cleared,
            Err(e) => {
                debug!("Failed to clear cache for domain {}: {}", domain, e);
                false
            }
        }
    }
    
    /// Clear all cache files (force fresh analysis for all domains)
    pub async fn clear_all_cache(&self) {
        let cache = self.cache.read().await;
        match cache.clear_all_cache().await {
            Ok(count) => debug!("Cleared {} cache files", count),
            Err(e) => debug!("Failed to clear cache: {}", e),
        }
    }

    /// Generate common subprocessor page URLs based on research findings
    pub fn generate_subprocessor_urls(&self, domain: &str) -> Vec<String> {
        let base_domain = domain.trim_start_matches("www.");
        
        // Known working URLs from Perplexity analysis - test these first
        let mut urls = vec![];
        
        // High-priority patterns based on successful discoveries
        match base_domain {
            "apple.com" => urls.push("https://www.apple.com/legal/enterprise/data-transfer-agreements/subprocessors_us.pdf".to_string()),
            "google.com" => urls.push("https://workspace.google.com/terms/subprocessors/".to_string()),
            "microsoft.com" => urls.push("https://go.microsoft.com/fwlink/p/?linkid=2096306".to_string()),
            "atlassian.com" => urls.push("https://www.atlassian.com/legal/sub-processors".to_string()),
            "dropbox.com" => urls.push("https://subprocessor.dropbox-legal.com/subprocessorlist.html".to_string()),
            "hubspot.com" => urls.push("https://legal.hubspot.com/sub-processors-page".to_string()),
            "canva.com" => urls.push("https://www.canva.com/policies/subprocessors/".to_string()),
            "docusign.com" => urls.push("https://www.docusign.com/trust/privacy/subprocessors-list".to_string()),
            "jamf.com" => urls.push("https://www.jamf.com/jamf-subprocessors/".to_string()),
            "browserstack.com" => urls.push("https://www.browserstack.com/sub-processors".to_string()),
            "sage.com" => urls.push("https://www.sage.com/en-gb/trust-security/privacy/customer-due-diligence/".to_string()),
            "heroku.com" => urls.push("https://compliance.salesforce.com/en/services/heroku".to_string()),
            // Trust Center product companies - their own subprocessor pages
            "vanta.com" => urls.push("https://trust.vanta.com/subprocessors".to_string()),
            "drata.com" => urls.push("https://drata.com/trust/subprocessors".to_string()),
            "secureframe.com" => urls.push("https://secureframe.com/trust/subprocessors".to_string()),
            "thoropass.com" => urls.push("https://thoropass.com/trust/subprocessors".to_string()),
            "safebase.io" => urls.push("https://safebase.io/trust/subprocessors".to_string()),
            "onetrust.com" => urls.push("https://www.onetrust.com/trust-center/subprocessors".to_string()),
            "sprinto.com" => urls.push("https://sprinto.com/trust/subprocessors".to_string()),
            "scrut.io" => urls.push("https://scrut.io/trust/subprocessors".to_string()),
            "conveyor.com" => urls.push("https://trust.conveyor.com".to_string()),
            _ => {}
        }
        
        // Add high-priority patterns discovered through research first
        urls.extend(vec![
            // HIGHEST PRIORITY: Trust subdomain pattern — extremely common for trust center products
            // (SafeBase, Conveyor, Vanta, Drata, Secureframe all use trust.{domain})
            format!("https://trust.{}/subprocessors", domain),
            format!("https://trust.{}", domain),  // Root trust page may contain subprocessors (Conveyor)

            // WORKING PATTERNS: Discovered through research and web searches
            format!("https://{}/legal/subprocessors", domain),         // Klaviyo: https://klaviyo.com/legal/subprocessors
            format!("https://{}/legal/service-providers", domain),      // Stripe: https://stripe.com/legal/service-providers
            format!("https://www.{}/legal/service-providers", domain),  // Stripe variant
            format!("https://www.{}/en/trust/subprocessors/", domain),  // Zoom: redirects but pattern seen
            
            // Direct subprocessor pages (keep early for common patterns)
            format!("https://{}/subprocessors", domain),
            format!("https://{}/sub-processors", domain),
            format!("https://www.{}/subprocessors", domain),
            format!("https://www.{}/sub-processors", domain),
            // HTML file extensions (e.g., adobe.com/privacy/sub-processors.html)
            format!("https://{}/subprocessors.html", domain),
            format!("https://{}/sub-processors.html", domain),
            format!("https://www.{}/subprocessors.html", domain),
            format!("https://www.{}/sub-processors.html", domain),
            
            // Legal/Privacy section patterns
            format!("https://{}/legal/subprocessors", domain),
            format!("https://www.{}/legal/subprocessors", domain),
            format!("https://{}/legal/sub-processors", domain),
            format!("https://www.{}/legal/sub-processors", domain),
            format!("https://{}/privacy/subprocessors", domain),
            format!("https://www.{}/privacy/subprocessors", domain),
            // HTML file extensions for legal/privacy sections (e.g., adobe.com/privacy/sub-processors.html)
            format!("https://{}/legal/subprocessors.html", domain),
            format!("https://www.{}/legal/subprocessors.html", domain),
            format!("https://{}/privacy/sub-processors.html", domain),  // Adobe pattern
            format!("https://www.{}/privacy/sub-processors.html", domain),
            format!("https://{}/privacy/subprocessors.html", domain),
            format!("https://www.{}/privacy/subprocessors.html", domain),
            
            // Policy section patterns  
            format!("https://{}/policies/subprocessors", domain),
            format!("https://www.{}/policies/subprocessors", domain),
            format!("https://{}/policies/subprocessors/", domain),  // Canva pattern with trailing slash
            format!("https://www.{}/policies/subprocessors/", domain),
            format!("https://{}/policies/sub-processor-list", domain),  // OpenAI pattern
            format!("https://www.{}/policies/sub-processor-list", domain),
            format!("https://{}/policy/subprocessors", domain),
            format!("https://www.{}/policy/subprocessors", domain),
            
            // Trust/Security center patterns
            format!("https://{}/trust/subprocessors", domain),
            format!("https://www.{}/trust/subprocessors", domain),
            // trust.{domain}/subprocessors already added as high-priority pattern above
            format!("https://{}/security/subprocessors", domain),
            format!("https://www.{}/security/subprocessors", domain),
            format!("https://{}/trust-center/subprocessors", domain),
            format!("https://www.{}/trust-center/subprocessors", domain),
            
            // NEW: Combined trust/privacy patterns (DocuSign)
            format!("https://{}/trust/privacy/subprocessors-list", domain),
            format!("https://www.{}/trust/privacy/subprocessors-list", domain),
            
            // NEW: Subdomain patterns found in Perplexity data
            format!("https://workspace.{}/terms/subprocessors/", domain),  // Google Workspace
            format!("https://legal.{}/sub-processors-page", domain),  // HubSpot
            format!("https://go.{}/fwlink/p/?linkid=2096306", domain),  // Microsoft redirect
            format!("https://compliance.{}/en/services/{}", base_domain, base_domain),  // Heroku/Salesforce
            format!("https://subprocessor.{}-legal.com/subprocessorlist.html", base_domain),  // Dropbox
            
            // NEW: Company-specific patterns
            format!("https://www.{}/{}-subprocessors/", domain, base_domain),  // JAMF pattern
            
            // NEW: Enterprise/business section patterns (Apple)
            format!("https://www.{}/legal/enterprise/data-transfer-agreements/subprocessors_us.pdf", domain),
            format!("https://{}/legal/enterprise/data-transfer-agreements/subprocessors_us.pdf", domain),
            
            // NEW: Localized patterns (Sage)
            format!("https://www.{}/en-gb/trust-security/privacy/customer-due-diligence/", domain),
            format!("https://{}/en-gb/trust-security/privacy/customer-due-diligence/", domain),
            format!("https://www.{}/en-us/trust-security/privacy/customer-due-diligence/", domain),
            
            // Company/About section patterns
            format!("https://{}/company/subprocessors", domain),
            format!("https://www.{}/company/subprocessors", domain),
            format!("https://{}/about/subprocessors", domain),
            format!("https://www.{}/about/subprocessors", domain),
            
            // GDPR-specific patterns
            format!("https://{}/gdpr/subprocessors", domain),
            format!("https://www.{}/gdpr/subprocessors", domain),
            format!("https://{}/data-protection/subprocessors", domain),
            format!("https://www.{}/data-protection/subprocessors", domain),
            
            // DPA (Data Processing Agreement) patterns
            format!("https://{}/dpa/subprocessors", domain),
            format!("https://www.{}/dpa/subprocessors", domain),
            
            // Vendor/Third-party patterns
            format!("https://{}/vendors", domain),
            format!("https://www.{}/vendors", domain),
            format!("https://{}/third-party-vendors", domain),
            format!("https://www.{}/third-party-vendors", domain),

            // F001: Third-party/services patterns
            format!("https://{}/third-party/subprocessors", domain),
            format!("https://www.{}/third-party/subprocessors", domain),
            format!("https://{}/third-party-services", domain),
            format!("https://www.{}/third-party-services", domain),

            // F001: Compliance section patterns
            format!("https://{}/compliance/subprocessors", domain),
            format!("https://www.{}/compliance/subprocessors", domain),

            // F001: Data processing/security patterns
            format!("https://{}/data-processing/subprocessors", domain),
            format!("https://www.{}/data-processing/subprocessors", domain),
            format!("https://{}/data-security/subprocessors", domain),
            format!("https://www.{}/data-security/subprocessors", domain),
            format!("https://{}/data-sub-processors", domain),
            format!("https://www.{}/data-sub-processors", domain),

            // F001: Domain-specific patterns (e.g., /slack-subprocessors for slack.com)
            format!("https://{}/{}-subprocessors", domain, base_domain.split('.').next().unwrap_or(base_domain)),
            format!("https://www.{}/{}-subprocessors", domain, base_domain.split('.').next().unwrap_or(base_domain)),

            // NEW: Terms section patterns
            format!("https://{}/terms/subprocessors", domain),
            format!("https://www.{}/terms/subprocessors", domain),
            format!("https://{}/terms/subprocessors/", domain),
            format!("https://www.{}/terms/subprocessors/", domain),

            // NEW: CDN and asset-based patterns (for companies that host subprocessor lists on CDNs)
            format!("https://content-management-files.{}/assets/subprocessors", base_domain),
            format!("https://assets.{}/subprocessors/list", base_domain),
            format!("https://cdn.{}/legal/subprocessors", base_domain),

            // NEW: PDF document patterns (many companies use PDFs)
            format!("https://www.{}/content/dam/legal/documents/Subprocessor-List-2024.pdf", base_domain),
            format!("https://www.{}/content/dam/legal/documents/Subprocessor-List-2023.pdf", base_domain),
            format!("https://www.{}/content/dam/cc/en/legal/documents/Subprocessor-List-2024-December.pdf", base_domain),
            format!("https://www.{}/content/dam/cc/en/legal/documents/Subprocessor-List-2023-December.pdf", base_domain),
            format!("https://{}/legal/documents/subprocessors.pdf", base_domain),
            format!("https://www.{}/legal/documents/subprocessors.pdf", base_domain),
            format!("https://{}/assets/legal/subprocessor-list.pdf", base_domain),
            format!("https://www.{}/assets/legal/subprocessor-list.pdf", base_domain),

            // (Legal subdomain patterns moved to front)
            format!("https://www.{}/en/trust/subprocessors/", base_domain),

            // F001: Additional security and compliance URL patterns
            format!("https://{}/security/sub-processors", domain),
            format!("https://www.{}/security/sub-processors", domain),
            format!("https://{}/security/vendors", domain),
            format!("https://www.{}/security/vendors", domain),
            format!("https://{}/security/third-party", domain),
            format!("https://www.{}/security/third-party", domain),

            // F001: Trust center with various path variations
            format!("https://{}/trust-center/sub-processors", domain),
            format!("https://www.{}/trust-center/sub-processors", domain),
            format!("https://{}/trust-center/vendors", domain),
            format!("https://www.{}/trust-center/vendors", domain),
            format!("https://{}/trust-center/third-party", domain),
            format!("https://www.{}/trust-center/third-party", domain),
            format!("https://{}/trustcenter/subprocessors", domain),
            format!("https://www.{}/trustcenter/subprocessors", domain),

            // F001: Trust subdomain patterns (popular pattern)
            format!("https://trust.{}/sub-processors", base_domain),
            format!("https://trust.{}/vendors", base_domain),
            format!("https://trust.{}/third-party", base_domain),
            format!("https://trust.{}/data-processors", base_domain),
            format!("https://trust.{}/security/subprocessors", base_domain),
            format!("https://trust.{}/compliance/subprocessors", base_domain),

            // F001: Compliance page variations
            format!("https://{}/compliance/sub-processors", domain),
            format!("https://www.{}/compliance/sub-processors", domain),
            format!("https://{}/compliance/vendors", domain),
            format!("https://www.{}/compliance/vendors", domain),
            format!("https://{}/compliance/third-party-vendors", domain),
            format!("https://www.{}/compliance/third-party-vendors", domain),
            format!("https://{}/compliance/data-processors", domain),
            format!("https://www.{}/compliance/data-processors", domain),

            // F001: GDPR-specific page variations
            format!("https://{}/gdpr/sub-processors", domain),
            format!("https://www.{}/gdpr/sub-processors", domain),
            format!("https://{}/gdpr/vendors", domain),
            format!("https://www.{}/gdpr/vendors", domain),
            format!("https://{}/gdpr/third-party", domain),
            format!("https://www.{}/gdpr/third-party", domain),
            format!("https://{}/gdpr/data-processors", domain),
            format!("https://www.{}/gdpr/data-processors", domain),

            // F001: Privacy section variations
            format!("https://{}/privacy/sub-processors", domain),
            format!("https://www.{}/privacy/sub-processors", domain),
            format!("https://{}/privacy/vendors", domain),
            format!("https://www.{}/privacy/vendors", domain),
            format!("https://{}/privacy/third-party", domain),
            format!("https://www.{}/privacy/third-party", domain),
            format!("https://{}/privacy/data-processors", domain),
            format!("https://www.{}/privacy/data-processors", domain),
            format!("https://{}/privacy-policy/subprocessors", domain),
            format!("https://www.{}/privacy-policy/subprocessors", domain),

            // F001: Legal section variations (sub-processors with hyphen)
            format!("https://{}/legal/third-party", domain),
            format!("https://www.{}/legal/third-party", domain),
            format!("https://{}/legal/vendors", domain),
            format!("https://www.{}/legal/vendors", domain),
            format!("https://{}/legal/data-processors", domain),
            format!("https://www.{}/legal/data-processors", domain),
            format!("https://{}/legal/third-party-vendors", domain),
            format!("https://www.{}/legal/third-party-vendors", domain),

            // F001: About section variations
            format!("https://{}/about/security", domain),
            format!("https://www.{}/about/security", domain),
            format!("https://{}/about/security/subprocessors", domain),
            format!("https://www.{}/about/security/subprocessors", domain),
            format!("https://{}/about/compliance", domain),
            format!("https://www.{}/about/compliance", domain),
            format!("https://{}/about/privacy", domain),
            format!("https://www.{}/about/privacy", domain),

            // F001: DPA/Agreement section variations
            format!("https://{}/dpa/sub-processors", domain),
            format!("https://www.{}/dpa/sub-processors", domain),
            format!("https://{}/data-processing-agreement/subprocessors", domain),
            format!("https://www.{}/data-processing-agreement/subprocessors", domain),
            format!("https://{}/dpa", domain),  // Sometimes DPA page lists subprocessors inline
            format!("https://www.{}/dpa", domain),

            // F001: Resources/docs section patterns
            format!("https://{}/resources/subprocessors", domain),
            format!("https://www.{}/resources/subprocessors", domain),
            format!("https://{}/docs/subprocessors", domain),
            format!("https://www.{}/docs/subprocessors", domain),
            format!("https://{}/documentation/subprocessors", domain),
            format!("https://www.{}/documentation/subprocessors", domain),
            format!("https://docs.{}/subprocessors", base_domain),  // docs subdomain
            format!("https://docs.{}/legal/subprocessors", base_domain),

            // F001: Help center patterns
            format!("https://help.{}/subprocessors", base_domain),
            format!("https://help.{}/legal/subprocessors", base_domain),
            format!("https://support.{}/subprocessors", base_domain),
            format!("https://support.{}/legal/subprocessors", base_domain),

            // F001: Info/information section patterns
            format!("https://{}/info/subprocessors", domain),
            format!("https://www.{}/info/subprocessors", domain),
            format!("https://{}/information/subprocessors", domain),
            format!("https://www.{}/information/subprocessors", domain),

            // F001: Service providers variations (like Stripe uses)
            format!("https://{}/service-providers", domain),
            format!("https://www.{}/service-providers", domain),
            format!("https://{}/legal/service-providers", domain),  // Already exists but adding www
            format!("https://{}/privacy/service-providers", domain),
            format!("https://www.{}/privacy/service-providers", domain),

            // F001: Partners/vendors pages that may list subprocessors
            format!("https://{}/partners/subprocessors", domain),
            format!("https://www.{}/partners/subprocessors", domain),
            format!("https://{}/technology-partners", domain),
            format!("https://www.{}/technology-partners", domain),

            // F001: Enterprise section patterns
            format!("https://{}/enterprise/subprocessors", domain),
            format!("https://www.{}/enterprise/subprocessors", domain),
            format!("https://{}/enterprise/security", domain),
            format!("https://www.{}/enterprise/security", domain),
            format!("https://{}/enterprise/compliance", domain),
            format!("https://www.{}/enterprise/compliance", domain),

            // F001: Processor list variations
            format!("https://{}/processor-list", domain),
            format!("https://www.{}/processor-list", domain),
            format!("https://{}/processors", domain),
            format!("https://www.{}/processors", domain),
            format!("https://{}/data-processor-list", domain),
            format!("https://www.{}/data-processor-list", domain),

            // F001: Additional PDF patterns with more year/date variations
            format!("https://{}/legal/subprocessors.pdf", domain),
            format!("https://www.{}/legal/subprocessors.pdf", domain),
            format!("https://{}/subprocessors.pdf", domain),
            format!("https://www.{}/subprocessors.pdf", domain),
            format!("https://{}/legal/sub-processors.pdf", domain),
            format!("https://www.{}/legal/sub-processors.pdf", domain),
            format!("https://{}/content/dam/legal/subprocessors.pdf", domain),
            format!("https://www.{}/content/dam/legal/subprocessors.pdf", domain),

            // F001: Sitemap and robots patterns for discovery
            format!("https://{}/sitemap.xml", domain),
            format!("https://www.{}/sitemap.xml", domain),

            // F001: Trailing slash variations for existing patterns
            format!("https://{}/legal/subprocessors/", domain),
            format!("https://www.{}/legal/subprocessors/", domain),
            format!("https://{}/privacy/subprocessors/", domain),
            format!("https://www.{}/privacy/subprocessors/", domain),
            format!("https://{}/trust/subprocessors/", domain),
            format!("https://www.{}/trust/subprocessors/", domain),
            format!("https://{}/security/subprocessors/", domain),
            format!("https://www.{}/security/subprocessors/", domain),
            format!("https://{}/compliance/subprocessors/", domain),
            format!("https://www.{}/compliance/subprocessors/", domain),
            format!("https://{}/gdpr/subprocessors/", domain),
            format!("https://www.{}/gdpr/subprocessors/", domain),
        ]);

        // ========================================================================
        // TRUST CENTER PRODUCTS (Vanta, Drata, SecureFrame, Thoropass, SafeBase, etc.)
        // These products provide hosted trust centers for companies to publish their
        // security documentation and subprocessor lists.
        // ========================================================================

        // Extract company name from domain (e.g., "acme" from "acme.com", "acme-corp" from "acme-corp.io")
        let company_name = base_domain.split('.').next().unwrap_or(base_domain);

        // Vanta Trust Center patterns
        // Vanta's own trust center: https://trust.vanta.com/subprocessors
        // Customer trust centers: https://trust.vanta.com/[company]/subprocessors
        //                        https://[company].vanta.com/trust/subprocessors
        urls.extend(vec![
            // Vanta-hosted trust centers
            format!("https://trust.vanta.com/{}/subprocessors", company_name),
            format!("https://trust.vanta.com/{}/sub-processors", company_name),
            format!("https://trust.vanta.com/{}", company_name), // Main trust page may list subprocessors
            format!("https://{}.vanta.com/subprocessors", company_name),
            format!("https://{}.vanta.com/trust/subprocessors", company_name),
            // Vanta app-hosted (some companies use app subdomain)
            format!("https://app.vanta.com/{}/trust/subprocessors", company_name),
            format!("https://app.vanta.com/{}/trust-center/subprocessors", company_name),
        ]);

        // Drata Trust Center patterns
        // Drata trust centers: https://[company].drata.com/trust-center/subprocessors
        //                     https://trust.drata.com/[company]/subprocessors
        urls.extend(vec![
            format!("https://{}.drata.com/trust-center/subprocessors", company_name),
            format!("https://{}.drata.com/trust-center/sub-processors", company_name),
            format!("https://{}.drata.com/trust-center/vendors", company_name),
            format!("https://{}.drata.com/trust-center", company_name), // Main page may list
            format!("https://{}.drata.com/subprocessors", company_name),
            format!("https://trust.drata.com/{}/subprocessors", company_name),
            format!("https://app.drata.com/{}/trust-center/subprocessors", company_name),
        ]);

        // SecureFrame Trust Center patterns
        // SecureFrame trust centers: https://[company].secureframe.com/trust/subprocessors
        //                           https://trust.secureframe.com/[company]/subprocessors
        urls.extend(vec![
            format!("https://{}.secureframe.com/trust/subprocessors", company_name),
            format!("https://{}.secureframe.com/trust/sub-processors", company_name),
            format!("https://{}.secureframe.com/trust/vendors", company_name),
            format!("https://{}.secureframe.com/trust", company_name),
            format!("https://{}.secureframe.com/subprocessors", company_name),
            format!("https://trust.secureframe.com/{}/subprocessors", company_name),
            format!("https://app.secureframe.com/{}/trust/subprocessors", company_name),
        ]);

        // Thoropass (formerly Laika) Trust Center patterns
        // Thoropass trust centers: https://[company].thoropass.com/trust/subprocessors
        urls.extend(vec![
            format!("https://{}.thoropass.com/trust/subprocessors", company_name),
            format!("https://{}.thoropass.com/trust/sub-processors", company_name),
            format!("https://{}.thoropass.com/trust/vendors", company_name),
            format!("https://{}.thoropass.com/trust", company_name),
            format!("https://{}.thoropass.com/subprocessors", company_name),
            format!("https://trust.thoropass.com/{}/subprocessors", company_name),
            // Legacy Laika patterns (Thoropass was formerly Laika)
            format!("https://{}.heylaika.com/trust/subprocessors", company_name),
            format!("https://{}.laika.com/trust/subprocessors", company_name),
        ]);

        // SafeBase Trust Center patterns
        // SafeBase trust centers: https://[company].safebase.io/subprocessors
        //                        https://security.[company].com (hosted by SafeBase)
        //                        https://trust.[company].com/product/[company]/subprocessors (custom domain)
        urls.extend(vec![
            format!("https://{}.safebase.io/subprocessors", company_name),
            format!("https://{}.safebase.io/sub-processors", company_name),
            format!("https://{}.safebase.io/vendors", company_name),
            format!("https://{}.safebase.io/", company_name), // Main page may list
            format!("https://security.{}/subprocessors", base_domain), // SafeBase often powers security.* subdomains
            format!("https://security.{}/sub-processors", base_domain),
            format!("https://security.{}/vendors", base_domain),
            // SafeBase custom-domain patterns (e.g., trust.drata.com/product/drata/subprocessors)
            format!("https://trust.{}/product/{}/subprocessors", base_domain, company_name),
            format!("https://trust.{}/product/{}/sub-processors", base_domain, company_name),
            format!("https://trust.{}/product/{}/vendors", base_domain, company_name),
        ]);

        // OneTrust Trust Center patterns
        // OneTrust provides various trust center solutions
        urls.extend(vec![
            format!("https://{}.onetrust.com/trust/subprocessors", company_name),
            format!("https://{}.onetrust.com/trust-center/subprocessors", company_name),
            format!("https://{}.onetrust.com/subprocessors", company_name),
            format!("https://privacyportal.{}.com/subprocessors", company_name), // OneTrust privacy portal pattern
            format!("https://privacyportal-{}.onetrust.com/subprocessors", company_name),
        ]);

        // Conveyor Trust Center patterns
        // Conveyor trust hubs: https://[company].trusthub.io (defunct, redirects to conveyor.com)
        // Custom domains: trust.{domain} is already covered by generic URL patterns above
        // Conveyor detection happens via probe_conveyor() when window.VENDOR_REPORT is found
        urls.extend(vec![
            format!("https://{}.trusthub.io/subprocessors", company_name),
            format!("https://{}.trusthub.io/sub-processors", company_name),
            format!("https://{}.trusthub.io/vendors", company_name),
            format!("https://{}.conveyor.com/trust/subprocessors", company_name),
        ]);

        // Scytale Trust Center patterns
        urls.extend(vec![
            format!("https://{}.scytale.ai/trust/subprocessors", company_name),
            format!("https://{}.scytale.ai/trust-center/subprocessors", company_name),
            format!("https://trust.scytale.ai/{}/subprocessors", company_name),
        ]);

        // Sprinto Trust Center patterns
        urls.extend(vec![
            format!("https://{}.sprinto.com/trust/subprocessors", company_name),
            format!("https://{}.sprinto.com/trust-center/subprocessors", company_name),
            format!("https://trust.sprinto.com/{}/subprocessors", company_name),
        ]);

        // Scrut Trust Center patterns
        urls.extend(vec![
            format!("https://{}.scrut.io/trust/subprocessors", company_name),
            format!("https://{}.scrut.io/trust-center/subprocessors", company_name),
            format!("https://trust.scrut.io/{}/subprocessors", company_name),
        ]);

        // Strike Graph Trust Center patterns
        urls.extend(vec![
            format!("https://{}.strikegraph.com/trust/subprocessors", company_name),
            format!("https://{}.strikegraph.com/trust-center/subprocessors", company_name),
        ]);

        // Anecdotes Trust Center patterns
        urls.extend(vec![
            format!("https://{}.anecdotes.ai/trust/subprocessors", company_name),
            format!("https://{}.anecdotes.ai/trust-center/subprocessors", company_name),
        ]);

        // Delve (now part of OneTrust) patterns
        urls.extend(vec![
            format!("https://{}.delve.com/trust/subprocessors", company_name),
            format!("https://trust.delve.com/{}/subprocessors", company_name),
        ]);
        
        urls
    }

    /// Scrape a single subprocessor page and extract vendor domains
    pub async fn scrape_subprocessor_page(&self, url: &str, logger: Option<&dyn LogFailure>, source_domain: &str) -> Result<Vec<SubprocessorDomain>> {
        self.scrape_subprocessor_page_with_retry(url, logger, source_domain, None).await
    }

    /// Scrape a single subprocessor page with configurable retry and backoff
    pub async fn scrape_subprocessor_page_with_retry(
        &self,
        url: &str,
        logger: Option<&dyn LogFailure>,
        source_domain: &str,
        rate_limit_ctx: Option<&RateLimitContext>,
    ) -> Result<Vec<SubprocessorDomain>> {
        debug!("🔥🔥🔥 SCRAPE_SUBPROCESSOR_PAGE CALLED: {}", url);
        debug!("🚀🚀🚀 STARTING DETAILED SCRAPE of subprocessor page: {}", url);

        // Get retry configuration from rate_limit_ctx or use defaults
        let (max_retries, backoff_config) = if let Some(ctx) = rate_limit_ctx {
            (ctx.config.max_retries, Some(&ctx.config))
        } else {
            (3, None) // Default: 3 retries
        };

        // Fetch the webpage with configurable retry mechanism
        let mut last_error = None;
        let mut response = None;

        for attempt in 1..=max_retries {
            debug!("HTTP request attempt {}/{} for URL: {}", attempt, max_retries, url);
            match self.client.get(url)
                .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
                .header("Accept-Language", "en-US,en;q=0.9")
                .header("Cache-Control", "no-cache")
                .header("Sec-Fetch-Dest", "document")
                .header("Sec-Fetch-Mode", "navigate")
                .header("Sec-Fetch-Site", "none")
                .header("Upgrade-Insecure-Requests", "1")
                .send().await {
                Ok(resp) => {
                    response = Some(resp);
                    break;
                },
                Err(e) => {
                    debug!("HTTP request attempt {}/{} failed for URL {}: {}", attempt, max_retries, url, e);
                    last_error = Some(e);
                    if attempt < max_retries {
                        // Calculate backoff delay using config or default
                        let delay = if let Some(config) = backoff_config {
                            config.calculate_backoff_delay(attempt)
                        } else {
                            // Default: linear backoff starting at 100ms
                            Duration::from_millis(100 * attempt as u64)
                        };
                        debug!("Waiting {:?} before retry attempt {}", delay, attempt + 1);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        let response = response.ok_or_else(|| {
            anyhow::anyhow!("All {} HTTP attempts failed for URL {}: {}", max_retries, url, last_error.unwrap())
        })?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
        }

        // Security: Check content type before processing
        let content_type = response.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        
        debug!("🔥🔥🔥 CONTENT-TYPE: {}", content_type);
        
        // Accept HTML, XHTML, and PDF documents
        let is_html = content_type.starts_with("text/html") || content_type.starts_with("application/xhtml");
        let is_pdf = content_type.starts_with("application/pdf");
        
        debug!("🔥🔥🔥 IS_HTML: {}, IS_PDF: {}", is_html, is_pdf);
        
        if !is_html && !is_pdf {
            return Err(anyhow::anyhow!("Invalid content type: {} (expected HTML or PDF)", content_type));
        }

        // Stream the response body with size cap to prevent memory exhaustion
        let content = read_response_body_capped(response, MAX_HTTP_BODY_BYTES).await?;

        // Handle PDF documents differently than HTML
        if is_pdf {
            debug!("Processing PDF document from URL: {}", url);
            return self.extract_from_pdf_content(&content, url, source_domain).await;
        }

        // ================================================================
        // Trust Center Strategy: Check cached strategy or auto-discover
        // ================================================================
        {
            // Check for a cached trust center strategy first
            let cached_strategy = {
                let cache = self.cache.read().await;
                let entry = cache.get_cached_entry(source_domain).await;
                entry.and_then(|e| e.trust_center_strategy.clone())
            };

            if let Some(ref strategy) = cached_strategy {
                // Check if strategy is not stale or unreliable
                let is_stale = strategy.discovery_metadata.is_stale(30);
                let is_unreliable = strategy.discovery_metadata.is_unreliable(3);
                if !is_stale && !is_unreliable {
                    debug!("Found cached trust center strategy for {}, executing", source_domain);
                    match crate::trust_center::executor::execute_strategy(
                        strategy, &self.client, Some(&content), source_domain
                    ).await {
                        Ok(vendors) if !vendors.is_empty() => {
                            debug!("Trust center strategy returned {} vendors for {}", vendors.len(), source_domain);
                            return Ok(vendors);
                        }
                        Ok(_) => {
                            debug!("Trust center strategy returned no vendors for {}", source_domain);
                        }
                        Err(e) => {
                            debug!("Trust center strategy failed for {}: {}", source_domain, e);
                        }
                    }
                }
            }

            // If no cached strategy and HTML looks like an SPA, try auto-discovery
            if cached_strategy.is_none() && crate::trust_center::discovery::is_likely_spa(&content) {
                debug!("SPA detected for {}, running trust center auto-discovery", source_domain);
                match crate::trust_center::discovery::discover_strategy(url, &content).await {
                    Ok(Some(strategy)) => {
                        debug!("Auto-discovered trust center strategy for {}", source_domain);
                        match crate::trust_center::executor::execute_strategy(
                            &strategy, &self.client, Some(&content), source_domain
                        ).await {
                            Ok(vendors) if !vendors.is_empty() => {
                                debug!("Auto-discovered strategy returned {} vendors for {}", vendors.len(), source_domain);
                                // Cache the strategy for future use
                                let cache = self.cache.write().await;
                                if let Ok(mut entry) = cache.get_cached_entry(source_domain).await
                                    .ok_or_else(|| anyhow::anyhow!("no cache entry"))
                                {
                                    entry.trust_center_strategy = Some(strategy);
                                    let cache_file = cache.get_cache_file_path(source_domain);
                                    let _ = tokio::fs::write(
                                        &cache_file,
                                        serde_json::to_string_pretty(&entry).unwrap_or_default(),
                                    ).await;
                                }
                                return Ok(vendors);
                            }
                            Ok(_) => {
                                debug!("Auto-discovered strategy returned no vendors for {}", source_domain);
                            }
                            Err(e) => {
                                debug!("Auto-discovered strategy execution failed: {}", e);
                            }
                        }
                    }
                    Ok(None) => {
                        debug!("No trust center strategy discovered for {}", source_domain);
                    }
                    Err(e) => {
                        debug!("Trust center auto-discovery failed for {}: {}", source_domain, e);
                    }
                }
            }
        }

        // SPA fallback: If the static HTML looks like a SPA (minimal text content),
        // use a headless browser to render the page and get the full DOM content.
        // This catches trust center pages (like Vanta's) where static HTML is just a
        // skeleton and all content is rendered by JavaScript.
        let content = if crate::trust_center::discovery::is_likely_spa(&content) {
            debug!("SPA content detected for {} — attempting headless browser rendering for subprocessor extraction", source_domain);
            let url_for_browser = url.to_string();
            match tokio::task::spawn_blocking(move || -> Result<String> {
                let guard = crate::browser_pool::create_browser()?;
                let tab = guard.browser.new_tab()
                    .map_err(|e| anyhow::anyhow!("Failed to create tab: {}", e))?;
                tab.navigate_to(&url_for_browser)
                    .map_err(|e| anyhow::anyhow!("Navigation failed: {}", e))?;
                tab.wait_until_navigated()
                    .map_err(|e| anyhow::anyhow!("Page load failed: {}", e))?;
                // Wait for JavaScript to render content
                std::thread::sleep(Duration::from_millis(5000));
                let rendered = tab.get_content()
                    .map_err(|e| anyhow::anyhow!("Failed to get rendered content: {}", e))?;
                Ok(rendered)
            }).await {
                Ok(Ok(rendered)) if rendered.len() > content.len() => {
                    debug!("Browser rendered {} chars (was {} static) for {}", rendered.len(), content.len(), source_domain);
                    rendered
                }
                Ok(Ok(_rendered)) => {
                    debug!("Browser rendering didn't produce larger content for {}, using static HTML", source_domain);
                    content
                }
                Ok(Err(e)) => {
                    debug!("Browser rendering failed for {}: {}, using static HTML", source_domain, e);
                    content
                }
                Err(e) => {
                    debug!("Browser task panicked for {}: {}, using static HTML", source_domain, e);
                    content
                }
            }
        } else {
            content
        };

        // Process HTML content
        let document = Html::parse_document(&content);
        debug!("🚀🚀🚀 HTML PARSED successfully, content length: {} chars", content.len());
        debug!("🔥🔥🔥 HTML CONTENT PREVIEW: {}", &content[..std::cmp::min(content.len(), 1000)]);
        
        // Debug: Check for div elements that might contain subprocessor info
        let divs: Vec<_> = document.select(&DIV_SELECTOR).collect();
        debug!("🔥🔥🔥 Found {} div elements total", divs.len());
        
        // Check for specific div patterns that might contain subprocessors
        let common_selectors = [
            "div[class*='subprocessor']",
            "div[class*='vendor']", 
            "div[class*='partner']",
            "div[class*='processor']",
            "div[class*='supplier']"
        ];
        
        for selector_str in &common_selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                let elements: Vec<_> = document.select(&selector).collect();
                debug!("🔥🔥🔥 Found {} elements with selector: {}", elements.len(), selector_str);
            }
        }

        // Load extraction patterns from cache (use default if not cached)  
        let patterns = {
            let cache = self.cache.read().await;
            cache.get_extraction_patterns(source_domain).await
        };
        debug!("🚀🚀🚀 LOADED EXTRACTION PATTERNS for domain: {}", source_domain);
        debug!("🔥🔥🔥 EXTRACTION PATTERNS: entity_column_selectors={:?}, table_selectors={:?}", patterns.entity_column_selectors, patterns.table_selectors);

        // Extract vendors using pattern-based strategies
        let mut vendors = Vec::new();
        let mut extraction_metadata = ExtractionMetadata {
            successful_extractions: 0,
            successful_entity_column_index: None,
            successful_header_pattern: None,
            last_extraction_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            adaptive_patterns: None,
        };
        
        // Use cache-derived patterns exclusively - either domain-specific or minimal bootstrap
        if patterns.is_domain_specific {
            if let Some(custom_rules) = &patterns.custom_extraction_rules {
                debug!("🔥🔥🔥 USING DOMAIN-SPECIFIC CACHE PATTERNS for {}", source_domain);
                let extraction_result = self.extract_with_custom_rules(&document, &content, url, custom_rules, source_domain)?;
                debug!("🔥🔥🔥 DOMAIN-SPECIFIC EXTRACTION FOUND {} vendors ({} pending confirmations)",
                       extraction_result.subprocessors.len(), extraction_result.pending_mappings.len());

                // Warn if extraction count is lower than what was previously successful
                // This helps detect when page content changes break extraction patterns
                {
                    let cache = self.cache.read().await;
                    if let Some(entry) = cache.get_cached_entry(source_domain).await {
                        if let Some(ref metadata) = entry.extraction_metadata {
                            if extraction_result.subprocessors.len() < metadata.successful_extractions as usize
                                && metadata.successful_extractions > 0
                            {
                                warn!("Subprocessor extraction for {} found {} vendors, but cache records {} successful extractions. \
                                       Page content may have changed or extraction patterns may need updating.",
                                      source_domain, extraction_result.subprocessors.len(), metadata.successful_extractions);
                                // Log which vendors were found to help debug
                                let found_domains: Vec<&str> = extraction_result.subprocessors.iter()
                                    .map(|s| s.domain.as_str())
                                    .collect();
                                debug!("Extracted domains for {}: {:?}", source_domain, found_domains);
                            }
                        }
                    }
                }

                // Store pending mappings for later confirmation
                for mapping in extraction_result.pending_mappings {
                    self.add_pending_mapping(mapping).await;
                }

                vendors.extend(extraction_result.subprocessors);

                // Decide whether to return domain-specific results or fall through to generic.
                let should_skip_generic = custom_rules.special_handling.as_ref()
                    .map(|sh| sh.skip_generic_methods)
                    .unwrap_or(true);

                if should_skip_generic {
                    return Ok(vendors);
                }

                // When skip_generic_methods is false, check if we found a reasonable number
                // of vendors compared to what was previously successful. If extraction count
                // dropped significantly, fall through to generic methods which may do better
                // (e.g., when page structure changed and regex patterns became stale).
                let prev_count = {
                    let cache = self.cache.read().await;
                    cache.get_cached_entry(source_domain).await
                        .and_then(|e| e.extraction_metadata.as_ref().map(|m| m.successful_extractions))
                        .unwrap_or(0) as usize
                };
                let found_enough = prev_count == 0 || vendors.len() >= prev_count / 2;
                if !vendors.is_empty() && found_enough {
                    return Ok(vendors);
                }
                debug!("Domain-specific extraction found {} vendors (prev: {}), falling through to generic extraction", vendors.len(), prev_count);
            }
        } else {
            debug!("🔥🔥🔥 NO DOMAIN-SPECIFIC PATTERNS - Using minimal bootstrap extraction for {}", source_domain);
        }

        // Strategy 1: Look for table-based layouts using cached patterns (PRIORITY METHOD)
        debug!("🔥🔥🔥 STARTING TABLE EXTRACTION");
        let table_results = self.extract_from_tables_with_patterns(&document, &content, url, &patterns)?;
        debug!("🔥🔥🔥 TABLE EXTRACTION FOUND {} vendors", table_results.0.len());
        
        // If table extraction found results, prioritize it over other methods to avoid false positives
        if !table_results.0.is_empty() {
            debug!("🔥🔥🔥 TABLE EXTRACTION SUCCESS - using table results only to avoid false positives");
            vendors.extend(table_results.0);
            if let Some(metadata) = table_results.1 {
                extraction_metadata.successful_entity_column_index = metadata.successful_entity_column_index;
                extraction_metadata.successful_header_pattern = metadata.successful_header_pattern;
            }
            
            // Generate and cache domain-specific patterns based on successful extractions
            debug!("🔥🔥🔥 PATTERN GENERATION: Creating domain-specific patterns from {} successful extractions", vendors.len());
            debug!("Generating domain-specific extraction patterns from {} successful extractions", vendors.len());
            
            // Generate intelligent domain-specific patterns
            let custom_rules = self.generate_domain_specific_patterns(&document, &content, &vendors, url);
            
            // Create domain-specific patterns (no generic fallbacks)
            let domain_specific_patterns = ExtractionPatterns {
                entity_column_selectors: Vec::new(), // Remove generic patterns
                entity_header_patterns: Vec::new(),  // Remove generic patterns
                table_selectors: Vec::new(),         // Remove generic patterns  
                list_selectors: Vec::new(),          // Remove generic patterns
                context_patterns: Vec::new(),        // Remove generic patterns
                domain_extraction_patterns: Vec::new(), // Remove generic patterns
                custom_extraction_rules: Some(custom_rules),
                is_domain_specific: true,
            };
            
            // Create fresh extraction metadata for domain-specific patterns
            let domain_metadata = ExtractionMetadata {
                successful_extractions: vendors.len() as u32,
                successful_entity_column_index: extraction_metadata.successful_entity_column_index,
                successful_header_pattern: extraction_metadata.successful_header_pattern.clone(),
                last_extraction_time: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                adaptive_patterns: None,
            };
            
            let cache = self.cache.write().await;
            if let Err(e) = cache.update_extraction_info(source_domain, domain_specific_patterns, domain_metadata).await {
                debug!("🔥🔥🔥 CACHE ERROR: Failed to update extraction patterns cache for {}: {}", source_domain, e);
                debug!("Failed to update extraction patterns cache for {}: {}", source_domain, e);
            } else {
                debug!("🔥🔥🔥 CACHE SUCCESS: Successfully cached domain-specific patterns for {}", source_domain);
                debug!("Successfully cached domain-specific patterns for {}", source_domain);
            }
        } else {
            // Only use fallback methods if table extraction failed
            debug!("🔥🔥🔥 TABLE EXTRACTION FAILED - trying fallback methods");
            
            // Strategy 2: Look for list-based layouts using cached patterns
            debug!("🔥🔥🔥 STARTING LIST EXTRACTION");
            let list_results = self.extract_from_lists_with_patterns(&document, &content, url, &patterns)?;
            debug!("🔥🔥🔥 LIST EXTRACTION FOUND {} vendors", list_results.len());
            vendors.extend(list_results);
            
            // Strategy 3: Look for paragraph-based content (for text-based tables)
            debug!("🔥🔥🔥 STARTING PARAGRAPH EXTRACTION");
            let paragraph_results = self.extract_from_paragraphs(&document, &content, url, &patterns)?;
            debug!("🔥🔥🔥 PARAGRAPH EXTRACTION FOUND {} vendors", paragraph_results.len());
            vendors.extend(paragraph_results);
            
            // Strategy 4: Look for structured data with company indicators (kept as fallback)
            debug!("🔥🔥🔥 STARTING STRUCTURED CONTENT EXTRACTION");
            let structured_results = self.extract_from_structured_content(&document, &content)?;
            debug!("🔥🔥🔥 STRUCTURED CONTENT EXTRACTION FOUND {} vendors", structured_results.len());
            vendors.extend(structured_results);
        }

        // Update extraction metadata
        extraction_metadata.successful_extractions = vendors.len() as u32;

        // If static HTML parsing found no vendors, try intelligent analysis and then headless browser
        if vendors.is_empty() {
            debug!("🔥🔥🔥 STATIC HTML PARSING FAILED - trying AI-powered analysis");
            debug!("Static HTML parsing returned no vendors, attempting intelligent analysis");
            
            // Try AI-powered content analysis first
            match self.scrape_with_intelligent_analysis(url, &content, source_domain).await {
                Ok(ai_vendors) => {
                    if !ai_vendors.is_empty() {
                        debug!("🧠 AI ANALYSIS SUCCESS - found {} vendors", ai_vendors.len());
                        debug!("AI analysis successful, found {} vendors", ai_vendors.len());
                        return Ok(ai_vendors);
                    } else {
                        debug!("🧠 AI ANALYSIS - no vendors detected, falling back to headless browser");
                        debug!("AI analysis returned no vendors, attempting headless browser fallback");
                    }
                }
                Err(e) => {
                    debug!("🧠 AI ANALYSIS ERROR: {}", e);
                    debug!("AI analysis failed: {}", e);
                }
            }
            
            // Try headless browser scraping as final fallback
            match self.scrape_with_headless_browser(url, logger, source_domain).await {
                Ok(headless_vendors) => {
                    if !headless_vendors.is_empty() {
                        debug!("🔥🔥🔥 HEADLESS BROWSER SUCCESS - found {} vendors", headless_vendors.len());
                        debug!("Headless browser fallback successful, found {} vendors", headless_vendors.len());
                        
                        // Try AI analysis on the rendered content for pattern discovery
                        let rendered_content = self.get_rendered_content_from_browser(url).await.unwrap_or_default();
                        if !rendered_content.is_empty() {
                            let _ = self.scrape_with_intelligent_analysis(url, &rendered_content, source_domain).await;
                        }
                        
                        return Ok(headless_vendors);
                    } else {
                        debug!("🔥🔥🔥 ALL METHODS FAILED - no vendors found with any approach");
                        debug!("All extraction methods returned no vendors");
                    }
                }
                Err(e) => {
                    debug!("🔥🔥🔥 HEADLESS BROWSER ERROR: {}", e);
                    debug!("Headless browser fallback failed: {}", e);
                }
            }

            // NER fallback: extract organization names from rendered/static HTML as last resort
            if vendors.is_empty() && crate::ner_org::is_available() {
                debug!("Attempting NER-based org extraction as final fallback for {}", source_domain);
                // Extract text content from HTML for NER processing
                let text_content = extract_text_from_html(&content);
                if text_content.len() >= 100 {
                    match crate::ner_org::extract_all_organizations(&text_content, Some(0.7)) {
                        Ok(ner_results) if !ner_results.is_empty() => {
                            debug!("NER fallback found {} organizations for {}", ner_results.len(), source_domain);
                            for org in &ner_results {
                                // Skip if the org name matches the source domain's own org
                                let org_lower = org.organization.to_lowercase();
                                let domain_parts: Vec<&str> = source_domain.split('.').collect();
                                let domain_name = domain_parts.first().unwrap_or(&"");
                                if org_lower == domain_name.to_lowercase() {
                                    continue;
                                }
                                // Skip NER false positives: language codes, locale identifiers,
                                // snake_case field names, and other non-organization patterns
                                if is_ner_false_positive(&org.organization) {
                                    debug!("Skipping NER false positive: '{}'", org.organization);
                                    continue;
                                }
                                vendors.push(SubprocessorDomain {
                                    domain: format!("_org:{}", org.organization),
                                    source_type: crate::vendor::RecordType::HttpSubprocessor,
                                    raw_record: format!("NER:{:.2}:{}", org.confidence, org.organization),
                                });
                            }
                            if !vendors.is_empty() {
                                debug!("NER fallback returning {} vendors for {}", vendors.len(), source_domain);
                                return Ok(vendors);
                            }
                        }
                        Ok(_) => debug!("NER found no organizations for {}", source_domain),
                        Err(e) => debug!("NER extraction failed for {}: {}", source_domain, e),
                    }
                }
            }
        } else {
            debug!("🔥🔥🔥 STATIC HTML PARSING SUCCESS - found {} vendors", vendors.len());
        }

        Ok(vendors)
    }

    /// Intelligent content-first extraction using AI-powered pattern discovery
    pub async fn scrape_with_intelligent_analysis(&self, url: &str, html_content: &str, source_domain: &str) -> Result<Vec<SubprocessorDomain>> {
        debug!("🧠 INTELLIGENT ANALYSIS: Starting AI-powered content analysis for: {}", url);
        debug!("Starting intelligent content analysis for: {}", url);

        let document = Html::parse_document(html_content);
        
        // Step 1: Content-first detection - find organization names using NLP patterns
        let detected_orgs = self.detect_organizations_in_content(&document, html_content).await;
        debug!("🧠 DETECTED {} potential organizations", detected_orgs.len());
        
        if detected_orgs.is_empty() {
            debug!("🧠 No organizations detected - falling back to static patterns");
            return Ok(vec![]);
        }

        // Step 2: Analyze DOM context of detected organizations to derive patterns
        let adaptive_patterns = self.derive_extraction_patterns(&detected_orgs, &document).await;
        debug!("🧠 DERIVED {} adaptive patterns with confidence {:.2}", 
            adaptive_patterns.discovered_selectors.len(), adaptive_patterns.confidence_score);

        // Step 3: Extract organizations using derived patterns with confidence scoring
        let mut extracted_vendors = Vec::new();
        for selector in &adaptive_patterns.discovered_selectors {
            if selector.confidence > 0.7 { // High confidence threshold
                let vendors = self.extract_using_adaptive_selector(&document, selector, url);
                extracted_vendors.extend(vendors);
            }
        }

        // Step 4: Cache successful adaptive patterns for future use
        if !extracted_vendors.is_empty() && adaptive_patterns.confidence_score > 0.8 {
            self.cache_adaptive_patterns(source_domain, adaptive_patterns).await;
        }

        debug!("🧠 INTELLIGENT ANALYSIS: Extracted {} vendors with AI patterns", extracted_vendors.len());
        Ok(extracted_vendors)
    }

    /// Detect organizations in content using NLP-like pattern recognition.
    ///
    /// Known limitation (L007): Generic org detection patterns (e.g., matching
    /// `[A-Z][a-zA-Z]+ Services`) may produce false positives for non-organization
    /// strings that happen to match the pattern (e.g., "Customer Services", "Privacy
    /// Platform"). This is an inherent trade-off of regex-based heuristic extraction.
    /// Improving these heuristics is out of scope for a bug fix; downstream consumers
    /// should treat results as candidates requiring validation (e.g., via VendorRegistry
    /// lookup or user confirmation through the pending mappings workflow).
    async fn detect_organizations_in_content(&self, document: &Html, _html_content: &str) -> Vec<DetectedOrganization> {
        debug!("🔍 ORGANIZATION DETECTION: Scanning content for company patterns");

        let mut detected_orgs = Vec::new();

        // High-confidence patterns for organization names
        let org_patterns = vec![
            // Common company suffixes
            r"(?i)\b([A-Z][a-zA-Z\s&\.]{2,30})\s+(Inc\.?|LLC\.?|Corp\.?|Corporation|Ltd\.?|Limited|Co\.?|Company|Group|Technologies?|Tech|Systems?|Solutions?)\b",
            // Cloud/tech companies
            r"(?i)\b(Amazon|Google|Microsoft|Apple|IBM|Oracle|Salesforce|Adobe|Atlassian|Dropbox|GitHub|Slack|Zoom|Stripe|HubSpot|Klaviyo|Canva|Notion|DocuSign|Twilio|SendGrid|Mailgun|Zendesk|Freshworks?|Intercom|Segment|Mixpanel|Amplitude|Datadog|New Relic|PagerDuty|Auth0|Okta|OneLogin)\b",
            // Generic company patterns
            r"(?i)\b([A-Z][a-zA-Z]{3,20})\s+(Services?|Analytics?|Platform|Network|Software|SaaS|Cloud|Data|Security|Infrastructure)\b",
        ];

        // Prefer content-focused elements over generic * selector to avoid navigation noise
        // Priority: main content areas first, then fall back to all elements
        let content_selectors = [
            "main *",           // Main content area
            "article *",        // Article content
            ".content *",       // Common content class
            "[role='main'] *",  // ARIA main role
            "table *",          // Table cells (subprocessor lists are often in tables)
            "ul li, ol li",     // List items
            "p",                // Paragraphs
        ];

        for pattern_str in &org_patterns {
            if let Ok(pattern) = Regex::new(pattern_str) {
                // Try content-focused selectors first
                let mut found_in_content = false;
                for selector_str in &content_selectors {
                    if let Ok(selector) = Selector::parse(selector_str) {
                        for text_element in document.select(&selector) {
                            // Skip if element is inside navigation containers
                            if self.is_in_navigation_container(&text_element) {
                                continue;
                            }

                            let text = text_element.text().collect::<String>();
                            if let Ok(Some(captures)) = pattern.captures(&text) {
                                if let Some(full_match) = captures.get(0) {
                                    let org_name = full_match.as_str().trim().to_string();
                                    let confidence = self.calculate_organization_confidence(&org_name, &text);

                                    if confidence > 0.6 {
                                        let dom_context = self.extract_dom_context(&text_element);
                                        detected_orgs.push(DetectedOrganization {
                                            name: org_name.clone(),
                                            confidence,
                                            dom_context,
                                        });
                                        debug!("🔍 FOUND: {} (confidence: {:.2})", org_name, confidence);
                                        found_in_content = true;
                                    }
                                }
                            }
                        }
                    }
                }

                // Only fall back to generic * selector if no content found in focused areas
                if !found_in_content {
                    for text_element in document.select(&ALL_ELEMENTS_SELECTOR) {
                        // Skip navigation containers
                        if self.is_in_navigation_container(&text_element) {
                            continue;
                        }

                        let text = text_element.text().collect::<String>();
                        if let Ok(Some(captures)) = pattern.captures(&text) {
                            if let Some(full_match) = captures.get(0) {
                                let org_name = full_match.as_str().trim().to_string();
                                let confidence = self.calculate_organization_confidence(&org_name, &text);

                                if confidence > 0.6 {
                                    let dom_context = self.extract_dom_context(&text_element);
                                    detected_orgs.push(DetectedOrganization {
                                        name: org_name.clone(),
                                        confidence,
                                        dom_context,
                                    });
                                    debug!("🔍 FOUND (fallback): {} (confidence: {:.2})", org_name, confidence);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Deduplicate by organization name and take highest confidence
        let mut unique_orgs: BTreeMap<String, DetectedOrganization> = BTreeMap::new();
        for org in detected_orgs {
            let key = org.name.to_lowercase();
            match unique_orgs.get(&key) {
                Some(existing) if existing.confidence >= org.confidence => {},
                _ => { unique_orgs.insert(key, org); }
            }
        }

        unique_orgs.into_values().collect()
    }

    /// Calculate confidence score for detected organization name
    fn calculate_organization_confidence(&self, org_name: &str, context: &str) -> f64 {
        let mut confidence: f64 = 0.5; // Base confidence

        // Boost confidence for well-known tech companies
        let known_companies = ["Google", "Microsoft", "Amazon", "Apple", "IBM", "Oracle", 
                              "Salesforce", "Adobe", "Atlassian", "Stripe", "Zoom"];
        if known_companies.iter().any(|&company| org_name.contains(company)) {
            confidence += 0.3;
        }

        // Boost for proper company suffixes
        if org_name.contains("Inc") || org_name.contains("Corp") || org_name.contains("LLC") {
            confidence += 0.2;
        }

        // Context analysis - boost if in table/list structure
        if context.contains("<td>") || context.contains("<li>") {
            confidence += 0.1;
        }

        // Penalize very short or very long names
        match org_name.len() {
            3..=50 => {},
            _ => confidence -= 0.2,
        }

        confidence.min(1.0).max(0.0)
    }

    /// Extract DOM context information around an element
    fn extract_dom_context(&self, element: &scraper::ElementRef) -> DomContext {
        let mut parent_tags = Vec::new();
        let mut current = element.parent();
        
        // Traverse up the DOM to capture parent structure
        while let Some(parent_element) = current {
            if let Some(element_ref) = scraper::ElementRef::wrap(parent_element) {
                parent_tags.push(element_ref.value().name().to_string());
                if parent_tags.len() >= 5 { break; } // Limit depth
            }
            current = parent_element.parent();
        }

        // Get CSS classes
        let css_classes = element.value().classes()
            .map(|c| c.to_string())
            .collect();

        // Build xpath-like selector
        let xpath_like = format!("{} > {}", 
            parent_tags.join(" > "), 
            element.value().name());

        DomContext {
            parent_tags,
            sibling_count: element.parent()
                .map(|p| p.children().count())
                .unwrap_or(0),
            css_classes,
            text_content: element.text().collect::<String>().trim().to_string(),
            xpath_like,
        }
    }

    /// Check if an element is inside a navigation container (nav, header, footer, sidebar)
    /// These elements typically contain navigation links, not subprocessor content
    fn is_in_navigation_container(&self, element: &scraper::ElementRef) -> bool {
        // Navigation-related tag names to exclude
        let nav_tags = ["nav", "header", "footer", "aside"];

        // Navigation-related class/id patterns
        let nav_patterns = [
            "nav", "menu", "header", "footer", "sidebar", "navigation",
            "topbar", "navbar", "menubar", "breadcrumb", "sitemap",
        ];

        // Check the element itself
        let tag_name = element.value().name().to_lowercase();
        if nav_tags.contains(&tag_name.as_str()) {
            return true;
        }

        // Check element's classes and id
        let classes: Vec<String> = element.value().classes().map(|c| c.to_lowercase()).collect();
        let id = element.value().id().map(|i| i.to_lowercase()).unwrap_or_default();

        for pattern in &nav_patterns {
            if classes.iter().any(|c| c.contains(pattern)) || id.contains(pattern) {
                return true;
            }
        }

        // Check parent elements up the DOM tree
        let mut current = element.parent();
        let mut depth = 0;
        while let Some(parent_node) = current {
            if depth > 10 {
                break; // Limit traversal depth
            }

            if let Some(parent_ref) = scraper::ElementRef::wrap(parent_node) {
                let parent_tag = parent_ref.value().name().to_lowercase();

                // Check if parent is a nav container tag
                if nav_tags.contains(&parent_tag.as_str()) {
                    return true;
                }

                // Check parent's classes and id
                let parent_classes: Vec<String> = parent_ref.value().classes()
                    .map(|c| c.to_lowercase())
                    .collect();
                let parent_id = parent_ref.value().id()
                    .map(|i| i.to_lowercase())
                    .unwrap_or_default();

                for pattern in &nav_patterns {
                    if parent_classes.iter().any(|c| c.contains(pattern)) || parent_id.contains(pattern) {
                        return true;
                    }
                }
            }

            current = parent_node.parent();
            depth += 1;
        }

        false
    }

    /// Derive extraction patterns from detected organizations' DOM contexts
    async fn derive_extraction_patterns(&self, detected_orgs: &[DetectedOrganization], document: &Html) -> AdaptivePatterns {
        debug!("🧠 PATTERN DERIVATION: Analyzing DOM patterns from {} organizations", detected_orgs.len());
        
        let mut discovered_selectors = Vec::new();
        let mut confidence_scores = Vec::new();
        
        // Group organizations by similar DOM patterns
        let pattern_groups = self.group_by_dom_patterns(detected_orgs);
        
        for (pattern_signature, orgs) in pattern_groups {
            if orgs.len() >= 2 { // Require at least 2 similar patterns for confidence
                let selector = self.generate_selector_from_pattern(&pattern_signature, &orgs);
                let confidence = self.calculate_pattern_confidence(&orgs, document, &selector);
                
                if confidence > 0.6 {
                    debug!("🧠 DERIVED PATTERN: {} (confidence: {:.2}, matches: {})", 
                        selector.selector, selector.confidence, orgs.len());
                    confidence_scores.push(confidence);
                    discovered_selectors.push(selector);
                }
            }
        }
        
        let overall_confidence = if confidence_scores.is_empty() { 
            0.0 
        } else { 
            confidence_scores.iter().sum::<f64>() / confidence_scores.len() as f64 
        };

        AdaptivePatterns {
            discovered_selectors,
            confidence_score: overall_confidence,
            discovery_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            validation_count: 0,
        }
    }

    /// Group detected organizations by similar DOM patterns
    fn group_by_dom_patterns<'a>(&self, orgs: &'a [DetectedOrganization]) -> BTreeMap<String, Vec<&'a DetectedOrganization>> {
        let mut groups = BTreeMap::new();
        
        for org in orgs {
            // Create a pattern signature from DOM context
            let signature = format!("{}_{}_{}", 
                org.dom_context.parent_tags.join(">"),
                org.dom_context.css_classes.join("."),
                org.dom_context.sibling_count
            );
            
            groups.entry(signature).or_insert_with(Vec::new).push(org);
        }
        
        groups
    }

    /// Generate CSS selector from DOM pattern analysis
    fn generate_selector_from_pattern(&self, _pattern_signature: &str, orgs: &[&DetectedOrganization]) -> DomSelector {
        // Analyze common DOM structure
        let first_org = &orgs[0];
        let parent_tags = &first_org.dom_context.parent_tags;
        
        // Determine selector type based on DOM structure
        let selector_type = if parent_tags.contains(&"table".to_string()) {
            SelectorType::Table
        } else if parent_tags.contains(&"ul".to_string()) || parent_tags.contains(&"ol".to_string()) {
            SelectorType::List
        } else if !first_org.dom_context.css_classes.is_empty() {
            SelectorType::Container
        } else {
            SelectorType::DirectText
        };

        // Build CSS selector based on pattern analysis
        let selector = match selector_type {
            SelectorType::Table => {
                if parent_tags.contains(&"td".to_string()) {
                    "table td".to_string()
                } else {
                    "table".to_string()
                }
            },
            SelectorType::List => {
                "ul li, ol li".to_string()
            },
            SelectorType::Container => {
                if !first_org.dom_context.css_classes.is_empty() {
                    format!(".{}", first_org.dom_context.css_classes[0])
                } else {
                    "div".to_string()
                }
            },
            SelectorType::DirectText => {
                parent_tags.last().unwrap_or(&"*".to_string()).clone()
            },
        };

        // Calculate confidence based on consistency across detected orgs
        let confidence = self.calculate_selector_consistency(orgs);
        
        // Sample matches for validation
        let sample_matches = orgs.iter()
            .take(3)
            .map(|org| org.name.clone())
            .collect();

        DomSelector {
            selector,
            selector_type,
            confidence,
            sample_matches,
        }
    }

    /// Calculate confidence score for pattern consistency
    fn calculate_selector_consistency(&self, orgs: &[&DetectedOrganization]) -> f64 {
        if orgs.len() < 2 { return 0.5; }
        
        let first_context = &orgs[0].dom_context;
        let mut similarity_scores = Vec::new();
        
        for org in &orgs[1..] {
            let mut score = 0.0;
            
            // Parent tag similarity
            let common_parents = first_context.parent_tags.iter()
                .filter(|tag| org.dom_context.parent_tags.contains(tag))
                .count();
            score += (common_parents as f64) / first_context.parent_tags.len().max(1) as f64;
            
            // CSS class similarity  
            let common_classes = first_context.css_classes.iter()
                .filter(|class| org.dom_context.css_classes.contains(class))
                .count();
            if !first_context.css_classes.is_empty() || !org.dom_context.css_classes.is_empty() {
                score += (common_classes as f64) / first_context.css_classes.len().max(org.dom_context.css_classes.len()).max(1) as f64;
            }
            
            similarity_scores.push(score / 2.0); // Average of the two metrics
        }
        
        let avg_similarity = similarity_scores.iter().sum::<f64>() / similarity_scores.len() as f64;
        (avg_similarity + 0.3).min(1.0) // Boost base confidence
    }

    /// Calculate pattern confidence based on document analysis
    fn calculate_pattern_confidence(&self, orgs: &[&DetectedOrganization], document: &Html, selector: &DomSelector) -> f64 {
        // Test selector against document to see how many matches it produces
        if let Ok(css_selector) = Selector::parse(&selector.selector) {
            let matches = document.select(&css_selector).count();
            let org_count = orgs.len();
            
            // Good patterns should match close to the number of detected orgs
            let match_ratio = if matches > 0 {
                (org_count as f64) / (matches as f64)
            } else {
                0.0
            };
            
            // Ideal ratio is between 0.3 and 1.0 (not too many extra matches, not too few)
            let ratio_score = if (0.3..=1.0).contains(&match_ratio) {
                match_ratio
            } else if match_ratio > 1.0 {
                1.0 / match_ratio
            } else {
                match_ratio * 0.5
            };
            
            (ratio_score + selector.confidence) / 2.0
        } else {
            0.2 // Invalid selector gets low confidence
        }
    }

    /// Extract organizations using an adaptive selector
    fn extract_using_adaptive_selector(&self, document: &Html, selector: &DomSelector, url: &str) -> Vec<SubprocessorDomain> {
        let mut vendors = Vec::new();
        
        if let Ok(css_selector) = Selector::parse(&selector.selector) {
            for element in document.select(&css_selector) {
                let text = element.text().collect::<String>();
                if let Some(domain) = self.extract_domain_from_text(&text) {
                    if self.looks_like_vendor_content(&text) {
                        vendors.push(SubprocessorDomain {
                            domain,
                            source_type: RecordType::HttpSubprocessor,
                            raw_record: self.create_evidence_excerpt(&text, url),
                        });
                    }
                }
            }
        }
        
        vendors
    }

    /// Cache adaptive patterns for future use
    async fn cache_adaptive_patterns(&self, source_domain: &str, patterns: AdaptivePatterns) {
        let cache = self.cache.write().await;
        
        // Get existing cache entry to preserve domain-specific patterns
        let existing_patterns = if let Some(existing) = cache.get_cached_entry(source_domain).await {
            existing.extraction_patterns.unwrap_or_default()
        } else {
            ExtractionPatterns::default()
        };
        
        let metadata = ExtractionMetadata {
            successful_extractions: 0, // Will be updated when patterns are used
            successful_entity_column_index: None,
            successful_header_pattern: None,
            last_extraction_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            adaptive_patterns: Some(patterns),
        };
        
        // Preserve existing domain-specific patterns instead of using default
        if let Err(e) = cache.update_extraction_info(source_domain, existing_patterns, metadata).await {
            debug!("Failed to cache adaptive patterns for {}: {}", source_domain, e);
        } else {
            debug!("🧠 CACHED adaptive patterns for {}", source_domain);
        }
    }

    /// Scrape subprocessor page using headless browser for JavaScript-generated content
    pub async fn scrape_with_headless_browser(&self, url: &str, _logger: Option<&dyn LogFailure>, source_domain: &str) -> Result<Vec<SubprocessorDomain>> {
        debug!("🔥🔥🔥 HEADLESS BROWSER: Starting JavaScript rendering for: {}", url);
        debug!("Starting headless browser scraping for: {}", url);

        // Launch headless Chrome (auto-detects container for sandbox config)
        let guard = crate::browser_pool::create_browser()?;

        let tab = guard.browser.new_tab().map_err(|e| {
            anyhow::anyhow!("Failed to create new browser tab: {}", e)
        })?;

        // Navigate to the page and wait for JavaScript to render
        debug!("🔥🔥🔥 HEADLESS BROWSER: Navigating to {}", url);
        tab.navigate_to(url).map_err(|e| {
            anyhow::anyhow!("Failed to navigate to {}: {}", url, e)
        })?;

        // Wait for the page to load completely
        tab.wait_until_navigated().map_err(|e| {
            anyhow::anyhow!("Page failed to load: {}", e)
        })?;

        // Wait a bit more for JavaScript content to render
        std::thread::sleep(Duration::from_millis(2000));
        debug!("🔥🔥🔥 HEADLESS BROWSER: Page loaded, extracting content");

        // Get the fully rendered HTML
        let html_content = tab.get_content().map_err(|e| {
            anyhow::anyhow!("Failed to get page content: {}", e)
        })?;

        debug!("🔥🔥🔥 HEADLESS BROWSER: Got rendered HTML, length: {} chars", html_content.len());
        debug!("🔥🔥🔥 HEADLESS BROWSER: HTML preview: {}", &html_content[..std::cmp::min(html_content.len(), 500)]);

        // Parse the rendered HTML and extract vendors
        let document = Html::parse_document(&html_content);
        
        // Load extraction patterns from cache
        let patterns = {
            let cache = self.cache.read().await;
            cache.get_extraction_patterns(source_domain).await
        };

        debug!("🔥🔥🔥 HEADLESS BROWSER: Starting extraction with patterns");

        // Use the same extraction logic as static HTML parsing
        let mut vendors = Vec::new();
        let mut extraction_metadata = ExtractionMetadata {
            successful_extractions: 0,
            successful_entity_column_index: None,
            successful_header_pattern: None,
            last_extraction_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            adaptive_patterns: None,
        };

        // Use cache-derived patterns exclusively - either domain-specific or minimal bootstrap
        if patterns.is_domain_specific {
            if let Some(custom_rules) = &patterns.custom_extraction_rules {
                debug!("🔥🔥🔥 HEADLESS BROWSER: USING DOMAIN-SPECIFIC CACHE PATTERNS for {}", source_domain);
                let extraction_result = self.extract_with_custom_rules(&document, &html_content, url, custom_rules, source_domain)?;
                debug!("🔥🔥🔥 HEADLESS BROWSER: DOMAIN-SPECIFIC EXTRACTION FOUND {} vendors ({} pending confirmations)",
                       extraction_result.subprocessors.len(), extraction_result.pending_mappings.len());

                // Store pending mappings for later confirmation
                for mapping in extraction_result.pending_mappings {
                    self.add_pending_mapping(mapping).await;
                }

                vendors.extend(extraction_result.subprocessors);
                return Ok(vendors); // Always return early for domain-specific patterns
            }
        } else {
            debug!("🔥🔥🔥 HEADLESS BROWSER: NO DOMAIN-SPECIFIC PATTERNS - Using minimal bootstrap extraction for {}", source_domain);
        }

        // Strategy 1: Look for table-based layouts (PRIORITY METHOD)
        let table_results = self.extract_from_tables_with_patterns(&document, &html_content, url, &patterns)?;
        
        // If table extraction found results, prioritize it over other methods to avoid false positives
        if !table_results.0.is_empty() {
            debug!("🔥🔥🔥 HEADLESS BROWSER: TABLE EXTRACTION SUCCESS - using table results only to avoid false positives");
            vendors.extend(table_results.0);
            if let Some(metadata) = table_results.1 {
                extraction_metadata.successful_entity_column_index = metadata.successful_entity_column_index;
                extraction_metadata.successful_header_pattern = metadata.successful_header_pattern;
            }
        } else {
            // Only use fallback methods if table extraction failed
            debug!("🔥🔥🔥 HEADLESS BROWSER: TABLE EXTRACTION FAILED - trying fallback methods");
            
            // Strategy 2: Look for list-based layouts
            vendors.extend(self.extract_from_lists_with_patterns(&document, &html_content, url, &patterns)?);
            
            // Strategy 3: Look for paragraph-based content
            vendors.extend(self.extract_from_paragraphs(&document, &html_content, url, &patterns)?);
            
            // Strategy 4: Look for structured data with company indicators
            vendors.extend(self.extract_from_structured_content(&document, &html_content)?);
        }

        // Update extraction metadata
        extraction_metadata.successful_extractions = vendors.len() as u32;

        debug!("🔥🔥🔥 HEADLESS BROWSER: Extraction complete, found {} vendors", vendors.len());

        // Generate and cache domain-specific patterns based on successful extractions
        if !vendors.is_empty() {
            debug!("Generating domain-specific extraction patterns from {} successful extractions", vendors.len());
            
            // Generate intelligent domain-specific patterns
            let custom_rules = self.generate_domain_specific_patterns(&document, &html_content, &vendors, url);
            
            // Create domain-specific patterns (no generic fallbacks)
            let domain_specific_patterns = ExtractionPatterns {
                entity_column_selectors: Vec::new(), // Remove generic patterns
                entity_header_patterns: Vec::new(),  // Remove generic patterns
                table_selectors: Vec::new(),         // Remove generic patterns  
                list_selectors: Vec::new(),          // Remove generic patterns
                context_patterns: Vec::new(),        // Remove generic patterns
                domain_extraction_patterns: Vec::new(), // Remove generic patterns
                custom_extraction_rules: Some(custom_rules),
                is_domain_specific: true,
            };
            
            let cache = self.cache.write().await;
            // Create fresh extraction metadata for domain-specific patterns
            let domain_metadata = ExtractionMetadata {
                successful_extractions: vendors.len() as u32,
                successful_entity_column_index: None,
                successful_header_pattern: None,
                last_extraction_time: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                adaptive_patterns: None,
            };

            if let Err(e) = cache.update_extraction_info(source_domain, domain_specific_patterns, domain_metadata).await {
                debug!("🔥🔥🔥 CACHE ERROR: Failed to update extraction patterns cache for {}: {}", source_domain, e);
                debug!("Failed to update extraction patterns cache for {}: {}", source_domain, e);
            } else {
                debug!("🔥🔥🔥 CACHE SUCCESS: Successfully cached domain-specific patterns for {}", source_domain);
                debug!("Successfully cached domain-specific patterns for {}", source_domain);
            }
        }

        Ok(vendors)
    }

    /// Extract vendor domains from HTML tables using cached extraction patterns
    pub fn extract_from_tables_with_patterns(&self, document: &Html, _html_content: &str, base_url: &str, patterns: &ExtractionPatterns) -> Result<(Vec<SubprocessorDomain>, Option<ExtractionMetadata>)> {
        let mut vendors = Vec::new();
        let mut metadata = ExtractionMetadata {
            successful_extractions: 0,
            successful_entity_column_index: None,
            successful_header_pattern: None,
            last_extraction_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            adaptive_patterns: None,
        };
        
        // Check for subprocessor context using cached patterns
        debug!("🚀🚀🚀 STARTING CONTEXT DETECTION");
        debug!("🔥🔥🔥 STARTING CONTEXT DETECTION - looking for subprocessor indicators");
        let mut found_subprocessor_context = false;

        let paragraphs: Vec<_> = document.select(&PARAGRAPH_SELECTOR).collect();
        debug!("🚀🚀🚀 Found {} paragraph elements for context detection", paragraphs.len());
        debug!("🔥🔥🔥 Found {} paragraph elements to search for context", paragraphs.len());
        
        for (p_index, paragraph) in paragraphs.iter().enumerate() {
            let text = paragraph.text().collect::<String>().to_lowercase();
            debug!("🚀🚀🚀 Paragraph {}: '{}'", p_index, text.trim());
            for context_pattern in &patterns.context_patterns {
                if text.contains(context_pattern) {
                    found_subprocessor_context = true;
                    debug!("Found subprocessor context with pattern: {}", context_pattern);
                    break;
                }
            }
            if found_subprocessor_context {
                break;
            }
        }
        
        // Fallback: Check if this is likely a subprocessor page based on URL
        if !found_subprocessor_context {
            let is_likely_subprocessor_page = base_url.contains("subprocessor") || 
                                               base_url.contains("sub-processor") ||
                                               base_url.contains("legal/subprocessor") ||
                                               (base_url.contains("legal/") && base_url.contains("processor"));
            
            if is_likely_subprocessor_page {
                debug!("No explicit subprocessor context found, but URL suggests subprocessor page - proceeding anyway");
            } else {
                debug!("No subprocessor context found on page and URL doesn't suggest subprocessor content");
                return Ok((vendors, None));
            }
        }
        
        // Extract domains from tables using cached patterns
        debug!("🔥🔥🔥 SEARCHING FOR TABLES - {} table selectors to try", patterns.table_selectors.len());
        for table_selector_pattern in &patterns.table_selectors {
            debug!("🔍 Trying table selector: {}", table_selector_pattern);
            debug!("🔥🔥🔥 Trying table selector: {}", table_selector_pattern);
            if let Ok(table_selector) = Selector::parse(table_selector_pattern) {
                let tables: Vec<_> = document.select(&table_selector).collect();
                debug!("📊 Found {} table(s) with selector: {}", tables.len(), table_selector_pattern);
                debug!("🔥🔥🔥 Found {} table(s) with selector: {}", tables.len(), table_selector_pattern);
                
                for (table_index, table) in tables.iter().enumerate() {
                    debug!("🔍 Processing table {}/{}", table_index + 1, tables.len());
                    let mut entity_name_column = 0; // Default to first column
                    
                    // Look for table headers to identify the correct column for entity names
                    let header_rows: Vec<_> = table.select(&HEADER_ROW_SELECTOR).collect();
                    debug!("🔍 Found {} header row(s)", header_rows.len());

                    if !header_rows.is_empty() {
                        let first_header_row = header_rows[0];
                        // Handle both <th> and <td> headers (some sites use <td> for headers)
                        let headers: Vec<_> = first_header_row.select(&HEADER_CELL_SELECTOR).collect();
                        debug!("📋 Found {} header cell(s) in first row", headers.len());
                        
                        // Log all header texts for debugging
                        for (index, header) in headers.iter().enumerate() {
                            let header_text = header.text().collect::<String>();
                            let header_html = header.html();
                            debug!("📋 Header {}: text='{}' html='{}'", index, header_text.trim(), header_html.trim());
                        }
                        
                        // Look for entity column using cached header patterns
                        for (index, header) in headers.iter().enumerate() {
                            let header_text = header.text().collect::<String>().to_lowercase();
                            debug!("🔍 Checking header {} text: '{}' against patterns", index, header_text.trim());
                            
                            for header_pattern in &patterns.entity_header_patterns {
                                debug!("🔍 Testing pattern: '{}'", header_pattern);
                                if header_text.contains(header_pattern) {
                                    entity_name_column = index;
                                    metadata.successful_header_pattern = Some(header_pattern.clone());
                                    metadata.successful_entity_column_index = Some(index);
                                    debug!("✅ Found entity name column at index {} with header pattern: '{}'", index, header_pattern);
                                    break;
                                }
                            }
                            if metadata.successful_header_pattern.is_some() {
                                break;
                            }
                        }
                        
                        if metadata.successful_header_pattern.is_none() {
                            debug!("❌ No header pattern matched, using default column 0");
                        }
                    } else {
                        debug!("❌ No header rows found, using default column 0");
                    }
                    
                    // Process data rows
                    let all_rows: Vec<_> = table.select(&DATA_ROW_SELECTOR).collect();
                    debug!("🔍 Found {} total rows in table", all_rows.len());

                    for (row_index, row) in all_rows.iter().enumerate() {
                        let cells: Vec<_> = row.select(&CELL_SELECTOR).collect();
                        let has_th_elements = row.select(&TH_SELECTOR).next().is_some();
                        
                        debug!("🔍 Row {}: {} cells, has_th_elements={}", row_index, cells.len(), has_th_elements);
                        
                        // Log cell contents for debugging
                        for (cell_index, cell) in cells.iter().enumerate() {
                            let cell_text = cell.text().collect::<String>().trim().to_string();
                            if !cell_text.is_empty() {
                                debug!("📋 Row {} Cell {}: '{}'", row_index, cell_index, cell_text);
                            } else {
                                debug!("📋 Row {} Cell {}: (empty)", row_index, cell_index);
                            }
                        }
                        
                        // Skip empty rows or header rows
                        if cells.is_empty() || has_th_elements {
                            debug!("⏭️ Skipping row {} (empty={}, has_th={})", row_index, cells.is_empty(), has_th_elements);
                            continue;
                        }
                        
                        // Get the entity name from the identified column
                        if let Some(entity_cell) = cells.get(entity_name_column) {
                            let cell_text = entity_cell.text().collect::<String>();
                            debug!("🔍 Processing entity cell from column {}: '{}'", entity_name_column, cell_text.trim());
                            
                            // Handle complex cells that might contain multiple lines or additional info
                            let lines: Vec<&str> = cell_text.lines().collect();
                            let mut found_company = false;
                            
                            // Try to extract from the first line first (most likely company name)
                            for (i, line) in lines.iter().enumerate() {
                                let line_text = line.trim();
                                
                                // Skip empty lines or lines that are too short
                                if line_text.is_empty() || line_text.len() < 3 {
                                    continue;
                                }
                                
                                // For complex cells, first line is usually the company name
                                // Additional lines might be addresses, etc.
                                let entity_name = if i == 0 {
                                    line_text.to_string()
                                } else {
                                    // For subsequent lines, check if they might be company names
                                    // Skip lines that look like addresses or other info
                                    if line_text.contains("Avenue") || 
                                       line_text.contains("Street") || 
                                       line_text.contains("Suite") ||
                                       line_text.chars().any(|c| c.is_digit(10)) &&
                                       (line_text.contains("WA ") || line_text.contains("NY ") || line_text.contains("CA ") || 
                                        line_text.len() < 20) {
                                        continue; // Skip address-like lines
                                    }
                                    line_text.to_string()
                                };
                                
                                debug!("Processing entity name from column {} line {}: {}", entity_name_column, i, entity_name);
                                
                                // Try to extract domain using cached patterns
                                if let Some(domain) = self.extract_domain_from_entity_name_with_patterns(&entity_name, patterns) {
                                    let evidence = self.create_enhanced_evidence(entity_cell, &entity_name, base_url);
                                    debug!("Extracted domain: {} from entity: {}", domain, entity_name);
                                    vendors.push(SubprocessorDomain {
                                        domain,
                                        source_type: RecordType::HttpSubprocessor,
                                        raw_record: evidence,
                                    });
                                    found_company = true;
                                    break; // Found a company in this cell, move to next cell
                                }
                            }
                            
                            if !found_company {
                                debug!("Could not extract domain from cell content: {}", cell_text.replace('\n', " | "));
                            }
                        }
                    }
                }
            }
        }
        
        metadata.successful_extractions = vendors.len() as u32;
        debug!("Extracted {} domains from subprocessor tables using patterns", vendors.len());
        
        let has_vendors = !vendors.is_empty();
        Ok((vendors, if has_vendors { Some(metadata) } else { None }))
    }
    
    /// Legacy method for backward compatibility
    pub fn extract_from_tables(&self, document: &Html, _html_content: &str, base_url: &str) -> Result<Vec<SubprocessorDomain>> {
        let patterns = ExtractionPatterns::default();
        let (vendors, _) = self.extract_from_tables_with_patterns(document, _html_content, base_url, &patterns)?;
        Ok(vendors)
    }

    /// Extract vendor domains from HTML lists using cached extraction patterns
    pub fn extract_from_lists_with_patterns(&self, document: &Html, _html_content: &str, base_url: &str, patterns: &ExtractionPatterns) -> Result<Vec<SubprocessorDomain>> {
        let mut vendors = Vec::new();
        
        // Check for subprocessor context using cached patterns
        let mut found_subprocessor_context = false;

        for paragraph in document.select(&PARAGRAPH_SELECTOR) {
            let text = paragraph.text().collect::<String>().to_lowercase();
            for context_pattern in &patterns.context_patterns {
                if text.contains(context_pattern) {
                    found_subprocessor_context = true;
                    debug!("Found subprocessor context in lists with pattern: {}", context_pattern);
                    break;
                }
            }
            if found_subprocessor_context {
                break;
            }
        }
        
        if !found_subprocessor_context {
            debug!("No subprocessor context found for list extraction");
            return Ok(vendors);
        }
        
        // Extract from lists using cached patterns
        for list_selector_pattern in &patterns.list_selectors {
            if let Ok(list_selector) = Selector::parse(list_selector_pattern) {
                for list_element in document.select(&list_selector) {
                    let text = list_element.text().collect::<String>().trim().to_string();
                    
                    if text.len() < 3 || text.chars().all(|c| c.is_whitespace()) {
                        continue;
                    }
                    
                    // Only process text that looks like an organization name
                    if self.looks_like_organization_name(&text) {
                        // Try to extract domain using cached patterns
                        if let Some(domain) = self.extract_domain_from_entity_name_with_patterns(&text, patterns) {
                            let evidence = self.create_enhanced_evidence(&list_element, &text, base_url);
                            debug!("Extracted domain from list: {} from text: {}", domain, text);
                            vendors.push(SubprocessorDomain {
                                domain,
                                source_type: RecordType::HttpSubprocessor,
                                raw_record: evidence,
                            });
                        }
                    }
                }
            }
        }
        
        debug!("Extracted {} domains from subprocessor lists using patterns", vendors.len());
        Ok(vendors)
    }

    /// Check if text looks like an organization name (has proper business suffixes or patterns)
    fn looks_like_organization_name(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase().trim().to_string();
        
        // Skip very short text or navigation-like terms
        if text_lower.len() < 4 {
            return false;
        }
        
        // Skip common navigation/UI terms that aren't organizations
        let navigation_terms = [
            "home", "about", "contact", "login", "signup", "search", "menu",
            "products", "services", "solutions", "platform", "pricing", "features",
            "enterprise", "business", "developers", "partners", "support", "help",
            "blog", "news", "events", "careers", "company", "legal", "privacy",
            "terms", "policy", "cookie", "security", "trust", "compliance",
            "documentation", "docs", "api", "integration", "marketplace",
            "community", "forum", "resources", "downloads", "training",
            "academy", "certification", "overview", "getting started",
            "dashboard", "account", "profile", "settings", "preferences",
            "notifications", "inbox", "messages", "calendar", "reports",
            "analytics", "insights", "metrics", "performance", "monitoring",
            "automation", "workflow", "templates", "campaigns", "segments",
            "lists", "forms", "surveys", "reviews", "feedback", "ratings",
            "shipping", "billing", "payment", "subscription", "upgrade",
            "downgrade", "cancel", "pause", "resume", "archive", "delete",
            "import", "export", "sync", "backup", "restore", "migrate",
            "integration", "webhook", "api", "sdk", "library", "plugin"
        ];
        
        for term in &navigation_terms {
            if text_lower == *term {
                return false;
            }
        }
        
        // Look for organization indicators (company suffixes or patterns)
        let organization_patterns = [
            // Company suffixes
            "inc.", "inc", "corporation", "corp.", "corp", "limited", "ltd.", "ltd",
            "llc", "llp", "pllc", "company", "co.", "co", "group", "holdings",
            "enterprises", "industries", "solutions", "technologies", "tech",
            "systems", "software", "services", "consulting", "partners",
            // Other business indicators
            "& co", "and company", "and co", " gmbh", " ag", " sa", " bv", " ltd",
            // Service/Tech company patterns
            "technologies", "software", "systems", "solutions", "consulting",
            "services", "ventures", "capital", "investments", "partners",
            // Name + descriptive patterns
            " web services", " cloud", " platform", " network", " digital",
            " media", " communications", " financial", " security", " analytics"
        ];
        
        for pattern in &organization_patterns {
            if text_lower.contains(pattern) {
                return true;
            }
        }
        
        // Additional check: multi-word capitalized names (like "Amazon Web Services")
        // that might be company names even without explicit suffixes
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.len() >= 2 && words.len() <= 6 {  // Reasonable company name length
            let has_proper_capitalization = words.iter().all(|word| {
                word.chars().next().map_or(false, |c| c.is_uppercase()) &&
                word.len() > 2  // Skip short words like "a", "of", "the"
            });
            
            if has_proper_capitalization {
                // Additional filter: avoid generic phrases that might be capitalized
                let generic_phrases = [
                    "Terms Of Service", "Privacy Policy", "Cookie Policy",
                    "End User License", "Service Level Agreement",
                    "Data Processing Agreement", "Master Service Agreement",
                    "Software License Agreement", "Terms And Conditions"
                ];
                
                let text_title_case = words.join(" ");
                for phrase in &generic_phrases {
                    if text_title_case.to_lowercase() == phrase.to_lowercase() {
                        return false;
                    }
                }
                
                return true;
            }
        }
        
        false
    }
    
    /// Legacy method for backward compatibility 
    pub fn extract_from_lists(&self, document: &Html, _html_content: &str, base_url: &str) -> Result<Vec<SubprocessorDomain>> {
        let patterns = ExtractionPatterns::default();
        self.extract_from_lists_with_patterns(document, _html_content, base_url, &patterns)
    }
    
    /// Extract domain from company entity name using cached patterns with enhanced matching
    pub fn extract_domain_from_entity_name_with_patterns(&self, entity_name: &str, patterns: &ExtractionPatterns) -> Option<String> {
        let entity_lower = entity_name.to_lowercase().trim().to_string();
        
        // First, try direct domain extraction patterns (validated against ReDoS - H006)
        for pattern_str in &patterns.domain_extraction_patterns {
            if let Some(regex) = validate_and_compile_regex(pattern_str) {
                for cap in regex.captures_iter(&entity_lower) {
                    if let Some(domain_match) = cap.get(1).or_else(|| cap.get(2)) {
                        let domain = domain_match.as_str().to_lowercase();
                        if self.is_valid_domain(&domain) {
                            debug!("Extracted domain '{}' using pattern: {}", domain, pattern_str);
                            return Some(domain);
                        }
                    }
                }
            }
        }
        
        // Enhanced organization name to domain mapping for subprocessor entities
        let domain = self.map_organization_to_domain(&entity_lower);
        if let Some(mapped_domain) = domain {
            debug!("Mapped organization '{}' to domain: {}", entity_name, mapped_domain);
            return Some(mapped_domain);
        }
        
        // Fallback to legacy method
        self.extract_domain_from_entity_name(entity_name)
    }
    
    /// Map organization names to their likely domain names for subprocessor extraction
    fn map_organization_to_domain(&self, org_name: &str) -> Option<String> {
        let cleaned = org_name
            .replace(",", "")
            .replace(".", "")
            .replace(" inc", "")
            .replace(" llc", "")
            .replace(" ltd", "")
            .replace(" corp", "")
            .replace(" corporation", "")
            .replace(" company", "")
            .replace(" co", "")
            .trim()
            .to_lowercase();
        
        // Common organization to domain mappings for tech/SaaS companies
        let mappings = [
            // From Klaviyo samples
            ("ada support", "ada.cx"),
            ("amazon web services", "aws.amazon.com"), 
            ("chronosphere", "chronosphere.io"),
            ("cloudflare", "cloudflare.com"),
            
            // Common subprocessors
            ("google", "google.com"),
            ("microsoft", "microsoft.com"),
            ("stripe", "stripe.com"),
            ("twilio", "twilio.com"),
            ("sendgrid", "sendgrid.com"),
            ("mailgun", "mailgun.com"),
            ("hubspot", "hubspot.com"),
            ("salesforce", "salesforce.com"),
            ("zendesk", "zendesk.com"),
            ("slack", "slack.com"),
            ("zoom", "zoom.us"),
            ("atlassian", "atlassian.com"),
            ("github", "github.com"),
            ("gitlab", "gitlab.com"),
            ("docker", "docker.com"),
            ("kubernetes", "kubernetes.io"),
            ("databricks", "databricks.com"),
            ("snowflake", "snowflake.com"),
            ("mongodb", "mongodb.com"),
            ("redis", "redis.io"),
            ("elastic", "elastic.co"),
            ("elasticsearch", "elastic.co"),
            ("datadog", "datadoghq.com"),
            ("new relic", "newrelic.com"),
            ("splunk", "splunk.com"),
            ("pagerduty", "pagerduty.com"),
            ("okta", "okta.com"),
            ("auth0", "auth0.com"),
            ("onelogin", "onelogin.com"),
            ("duo security", "duo.com"),
            ("crowdstrike", "crowdstrike.com"),
            ("notion", "notion.so"),
            ("airtable", "airtable.com"),
            ("zapier", "zapier.com"),
            ("segment", "segment.com"),
            ("amplitude", "amplitude.com"),
            ("mixpanel", "mixpanel.com"),
            ("intercom", "intercom.com"),
            ("braze", "braze.com"),
            ("iterable", "iterable.com"),
            ("mailchimp", "mailchimp.com"),
            ("constant contact", "constantcontact.com"),
            ("campaign monitor", "campaignmonitor.com"),
        ];
        
        // Check for direct matches
        for (org, domain) in &mappings {
            if cleaned.contains(org) {
                return Some(domain.to_string());
            }
        }
        
        // Only try to infer domains for well-known organization names
        // Removed automatic domain inference to prevent false positives from navigation links
        if cleaned.len() > 2 && !cleaned.contains(" ") {
            // Only infer domains for organization names that are likely actual companies
            // and not navigation terms like "home", "community", "enterprise", etc.
            let navigation_terms = [
                "home", "about", "contact", "privacy", "terms", "help", "support",
                "community", "forum", "blog", "news", "events", "careers", "jobs",
                "login", "signup", "register", "account", "profile", "settings",
                "dashboard", "admin", "search", "browse", "explore", "discover",
                "features", "products", "services", "solutions", "pricing", "plans",
                "enterprise", "business", "commercial", "professional", "personal",
                "free", "premium", "pro", "basic", "standard", "advanced",
                "developers", "api", "docs", "documentation", "guides", "tutorials",
                "resources", "tools", "downloads", "software", "platform", "app",
                "mobile", "desktop", "web", "online", "cloud", "saas",
                "academy", "education", "training", "learning", "courses", "certification",
                "partners", "integrations", "marketplace", "store", "shop", "cart",
                "checkout", "payment", "billing", "invoice", "subscription", "license",
                "reviews", "testimonials", "case", "studies", "success", "stories",
                "newsletter", "updates", "announcements", "releases", "changelog",
                "legal", "compliance", "security", "privacy", "cookies", "gdpr",
                "feedback", "survey", "contact", "sales", "demo", "trial", "quote",
                "templates", "themes", "design", "customize", "builder", "editor",
                "analytics", "reports", "statistics", "metrics", "insights", "data",
                "integration", "workflow", "automation", "marketing", "advertising",
                "social", "media", "content", "publishing", "campaign", "email",
                "notifications", "alerts", "messages", "chat", "communication",
                "collaboration", "team", "workspace", "project", "management",
                "portfolio", "gallery", "showcase", "examples", "samples", "demos",
                // Generic business/company terms that aren't specific vendors
                "technologies", "technology", "solutions", "services", "systems",
                "consulting", "group", "partners", "international", "global",
                "corporation", "limited", "holdings", "ventures", "capital",
                "enterprises", "associates", "industries", "incorporated",
                // Country/region names that shouldn't be converted to domains
                "japan", "ireland", "israel", "korea", "canada", "australia",
                "germany", "france", "spain", "italy", "netherlands", "belgium",
                "sweden", "norway", "denmark", "finland", "switzerland", "austria",
                "poland", "portugal", "brazil", "mexico", "argentina", "chile",
                "india", "china", "singapore", "malaysia", "indonesia", "thailand",
                "philippines", "vietnam", "taiwan", "hongkong", "uk", "usa", "eu",
                "emea", "apac", "latam", "americas", "europe", "asia", "africa",
                // Common location descriptors
                "north", "south", "east", "west", "central", "pacific", "atlantic",
                // Generic corporate structure terms
                "pty", "superholdco", "holdco", "subco", "dados", "communications",
                "affiliate", "subsidiary", "parent", "branch", "division", "unit"
            ];
            
            if !navigation_terms.contains(&cleaned.as_str()) {
                let candidate = format!("{}.com", cleaned);
                // Validate the inferred domain to prevent garbage like short-name FPs
                if self.is_valid_vendor_domain(&candidate) {
                    return Some(candidate);
                }
            }
        }
        
        None
    }
    
    /// Validate if a string is a reasonable domain name
    fn is_valid_domain(&self, domain: &str) -> bool {
        // Basic validation: must contain a dot and valid characters
        domain.contains('.') && 
        domain.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') &&
        !domain.starts_with('.') &&
        !domain.ends_with('.') &&
        domain.len() >= 4 // minimum like "a.co"
    }

    /// Extract vendor domains from paragraph-based content (for text-based tables and lists)
    pub fn extract_from_paragraphs(&self, document: &Html, html_content: &str, base_url: &str, patterns: &ExtractionPatterns) -> Result<Vec<SubprocessorDomain>> {
        let mut vendors = Vec::new();

        // Look for strong subprocessor context first
        let has_subprocessor_context = patterns.context_patterns.iter()
            .any(|pattern| html_content.to_lowercase().contains(pattern));
        
        if !has_subprocessor_context {
            debug!("No subprocessor context found in paragraphs, skipping paragraph extraction");
            return Ok(vendors);
        }

        // Strategy 1: Extract from paragraph text containing common company patterns
        for paragraph in document.select(&PARAGRAPH_DIV_SELECTOR) {
            let text = paragraph.text().collect::<String>();

            // More precise company name patterns that include proper business suffixes
            let company_patterns = vec![
                // Standard business suffixes with more specific patterns
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Inc\.?",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+LLC",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Corp(?:oration)?\.?",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Ltd\.?",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Limited",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Company",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Co\.?",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Group",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Holdings",
                // Technology company patterns
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Technologies",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Software",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Systems",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*),?\s+Solutions",
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*)\s+(?:Web\s+)?Services",
                // Patterns that include descriptive terms
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*)\s+(?:Cloud|Platform|Network|Digital|Media|Communications|Financial|Security|Analytics)",
                // Pattern for "Company Name (d/b/a Other Name)" format common in subprocessor lists
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*(?:,\s*Inc\.?|,\s*LLC|,\s*Corp\.?|,\s*Ltd\.?)?)\s*\([^)]*d/b/a[^)]*\)",
                // Pattern for company names with parenthetical domain references
                r"([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*(?:,\s*Inc\.?|,\s*LLC|,\s*Corp\.?|,\s*Ltd\.?)?)\s*\([^)]*\.(?:com|org|io|net|co)[^)]*\)",
            ];

            for pattern_str in &company_patterns {
                if let Ok(regex) = regex::Regex::new(pattern_str) {
                    for capture in regex.captures_iter(&text) {
                        if let Some(company_match) = capture.get(1) {
                            let company_name = company_match.as_str();
                            
                            // Skip very generic terms and apply organization name validation
                            if company_name.len() < 3 || 
                               company_name.to_lowercase().contains("service") ||
                               company_name.to_lowercase().contains("provider") ||
                               !self.looks_like_organization_name(company_name) {
                                continue;
                            }

                            // Try to extract domain from company name
                            if let Some(domain) = self.extract_domain_from_entity_name_with_patterns(company_name, patterns) {
                                let evidence = self.create_enhanced_evidence(&paragraph, &text, base_url);
                                debug!("Extracted domain from paragraph: {} from company: {}", domain, company_name);
                                vendors.push(SubprocessorDomain {
                                    domain,
                                    source_type: RecordType::HttpSubprocessor,
                                    raw_record: evidence,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Strategy 2: Look for structured text blocks that might be formatted as tables
        let text_content = document.root_element().text().collect::<String>();
        let lines: Vec<&str> = text_content.lines().collect();
        
        // Look for lines that might contain company information
        for line in lines {
            let line = line.trim();
            if line.len() < 5 || line.len() > 200 {
                continue; // Skip very short or very long lines
            }

            // Check if line looks like it contains a company name and additional info
            let company_line_patterns = vec![
                r"^([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*(?:,\s*(?:Inc\.?|LLC|Corp\.?|Ltd\.?))?)\s+[-–]\s*(.+)$",
                r"^([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]*)*(?:,\s*(?:Inc\.?|LLC|Corp\.?|Ltd\.?))?)\s+(.+services?|.+platform|.+solutions?)$",
            ];

            for pattern_str in &company_line_patterns {
                if let Ok(regex) = regex::Regex::new(pattern_str) {
                    if let Some(capture) = regex.captures(line) {
                        if let Some(company_match) = capture.get(1) {
                            let company_name = company_match.as_str();
                            
                            if let Some(domain) = self.extract_domain_from_entity_name_with_patterns(company_name, patterns) {
                                let evidence = format!("Text line: {}", line);
                                debug!("Extracted domain from text line: {} from company: {}", domain, company_name);
                                vendors.push(SubprocessorDomain {
                                    domain,
                                    source_type: RecordType::HttpSubprocessor,
                                    raw_record: evidence,
                                });
                            }
                        }
                    }
                }
            }
        }

        debug!("Paragraph extraction found {} vendors", vendors.len());
        Ok(vendors)
    }

    /// Extract vendor domains using domain-specific custom extraction rules
    /// This method takes precedence over generic extraction methods for domains with user-contributed patterns
    /// Returns both extracted vendors and any pending mappings that need user confirmation
    pub fn extract_with_custom_rules(&self, document: &Html, html_content: &str, base_url: &str, custom_rules: &CustomExtractionRules, source_domain: &str) -> Result<SubprocessorExtractionResult> {
        let mut vendors = Vec::new();
        let mut pending_mappings = Vec::new();
        debug!("Starting domain-specific custom extraction with {} direct selectors and {} regex patterns",
               custom_rules.direct_selectors.len(), custom_rules.custom_regex_patterns.len());

        // Apply exclusion patterns if specified (validated against ReDoS - H006)
        let exclusion_regexes: Vec<regex::Regex> = if let Some(special_handling) = &custom_rules.special_handling {
            special_handling.exclusion_patterns.iter()
                .filter_map(|pattern| validate_and_compile_regex(pattern))
                .collect()
        } else {
            Vec::new()
        };

        // Extract using direct CSS selectors
        for selector_rule in &custom_rules.direct_selectors {
            if let Ok(selector) = scraper::Selector::parse(&selector_rule.selector) {
                let matched_elements: Vec<_> = document.select(&selector).collect();
                debug!("Applying custom selector: {} - {} (matched {} elements)",
                       selector_rule.selector, selector_rule.description, matched_elements.len());

                for element in matched_elements {
                    let mut text = if let Some(attr) = &selector_rule.attribute {
                        element.value().attr(attr).unwrap_or("").to_string()
                    } else {
                        element.text().collect::<String>()
                    };

                    // Apply transformations if specified
                    if let Some(transform) = &selector_rule.transform {
                        text = match transform.as_str() {
                            "trim" => text.trim().to_string(),
                            "lowercase" => text.to_lowercase(),
                            "remove_suffix" => {
                                // Remove common business suffixes
                                text.replace(" Inc", "").replace(" LLC", "").replace(" Corp", "").trim().to_string()
                            },
                            _ => text,
                        };
                    }

                    if !text.is_empty() && text.len() > 2 {
                        // Check against exclusion patterns
                        let should_exclude = exclusion_regexes.iter().any(|regex| regex.is_match(&text));
                        if should_exclude {
                            debug!("Excluding '{}' due to exclusion pattern", text);
                            continue;
                        }

                        // Try to extract domain from the organization name
                        if let Some(result) = self.extract_domain_from_organization_name(&text, custom_rules) {
                            let evidence = self.create_enhanced_evidence(&element, &text, base_url);
                            debug!("Custom extraction found: {} -> {} (fallback: {})", text, result.domain, result.is_fallback);

                            // Track pending mappings that came from generic fallback
                            if result.is_fallback {
                                pending_mappings.push(PendingOrgMapping {
                                    org_name: text.clone(),
                                    inferred_domain: result.domain.clone(),
                                    source_domain: source_domain.to_string(),
                                });
                            }

                            vendors.push(SubprocessorDomain {
                                domain: result.domain,
                                source_type: RecordType::HttpSubprocessor,
                                raw_record: evidence,
                            });
                        } else {
                            debug!("Custom extraction: no domain mapping found for '{}' (skipped)", text);
                        }
                    }
                }
            } else {
                debug!("Invalid CSS selector in custom rules: {}", selector_rule.selector);
            }
        }

        // Extract plain text from the document for regex matching.
        // SPA-rendered pages have company names in separate DOM elements (e.g. <div>Name</div><div>•</div>)
        // which become contiguous in plain text ("Name • ...") but NOT in raw HTML.
        let plain_text: String = document.root_element()
            .text()
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        // Extract using custom regex patterns (validated against ReDoS - H006)
        // Run against both raw HTML and plain text to handle SPA-rendered content
        for regex_rule in &custom_rules.custom_regex_patterns {
            if let Some(regex) = validate_and_compile_regex(&regex_rule.pattern) {
                debug!("Applying custom regex: {} - {}", regex_rule.pattern, regex_rule.description);

                // Run regex against both raw HTML and plain text
                let sources: [&str; 2] = [html_content, &plain_text];
                for source in &sources {
                    for capture in regex.captures_iter(source) {
                        if let Some(org_match) = capture.get(regex_rule.capture_group) {
                            let org_name = org_match.as_str().trim();

                            if !org_name.is_empty() && org_name.len() > 2 {
                                // Check against exclusion patterns
                                let should_exclude = exclusion_regexes.iter().any(|regex| regex.is_match(org_name));
                                if should_exclude {
                                    debug!("Excluding '{}' due to exclusion pattern", org_name);
                                    continue;
                                }

                                if let Some(result) = self.extract_domain_from_organization_name(org_name, custom_rules) {
                                    // Deduplicate: skip if we already found this domain
                                    if vendors.iter().any(|v| v.domain == result.domain) {
                                        continue;
                                    }

                                    let evidence = format!("Custom regex match: '{}' from pattern: {}", org_name, regex_rule.description);
                                    debug!("Custom regex extraction found: {} -> {} (fallback: {})", org_name, result.domain, result.is_fallback);

                                    // Track pending mappings that came from generic fallback
                                    if result.is_fallback {
                                        pending_mappings.push(PendingOrgMapping {
                                            org_name: org_name.to_string(),
                                            inferred_domain: result.domain.clone(),
                                            source_domain: source_domain.to_string(),
                                        });
                                    }

                                    vendors.push(SubprocessorDomain {
                                        domain: result.domain,
                                        source_type: RecordType::HttpSubprocessor,
                                        raw_record: evidence,
                                    });
                                }
                            }
                        }
                    }
                }
            } else {
                debug!("Invalid regex pattern in custom rules: {}", regex_rule.pattern);
            }
        }

        debug!("Custom extraction completed, found {} vendors ({} pending confirmations)", vendors.len(), pending_mappings.len());
        Ok(SubprocessorExtractionResult {
            subprocessors: vendors,
            pending_mappings,
        })
    }

    /// Extract domain from organization name using custom mapping rules if available
    /// Returns the domain and whether it was resolved via generic fallback (needs confirmation)
    fn extract_domain_from_organization_name(&self, org_name: &str, custom_rules: &CustomExtractionRules) -> Option<DomainExtractionResult> {
        let cleaned_org = org_name.trim().to_lowercase();

        // First, check custom organization-to-domain mappings
        // Use earliest-position matching to handle ambiguous names like "Loom, Inc. (Atlassian)"
        // where both "loom" and "atlassian" are valid patterns. The primary entity appears first
        // in the organization name, so we prefer the match closest to the start of the string.
        // Ties are broken by preferring the longest (most specific) pattern.
        if let Some(special_handling) = &custom_rules.special_handling {
            if let Some(custom_mappings) = &special_handling.custom_org_to_domain_mapping {
                let mut best_match: Option<(usize, usize, &str)> = None; // (position, pattern_len, domain)
                for (org_pattern, domain) in custom_mappings {
                    let pattern_lower = org_pattern.to_lowercase();
                    if let Some(pos) = cleaned_org.find(&pattern_lower) {
                        let is_better = match best_match {
                            None => true,
                            Some((best_pos, best_len, _)) => {
                                pos < best_pos || (pos == best_pos && pattern_lower.len() > best_len)
                            }
                        };
                        if is_better {
                            best_match = Some((pos, pattern_lower.len(), domain.as_str()));
                        }
                    }
                }
                if let Some((pos, _, domain)) = best_match {
                    debug!("Used custom mapping: '{}' -> '{}' (matched at position {})", org_name, domain, pos);
                    return Some(DomainExtractionResult {
                        domain: domain.to_string(),
                        is_fallback: false,
                    });
                }
            }
        }

        // Fall back to standard domain extraction
        self.map_organization_to_domain(&cleaned_org).map(|domain| {
            debug!("Used generic fallback mapping: '{}' -> '{}' (needs confirmation)", org_name, domain);
            DomainExtractionResult {
                domain,
                is_fallback: true,
            }
        })
    }

    /// Generate intelligent domain-specific extraction patterns from successful extraction results
    /// This analyzes what worked and creates patterns that can be cached for future use
    pub fn generate_domain_specific_patterns(&self, document: &Html, html_content: &str, successful_extractions: &[SubprocessorDomain], base_url: &str) -> CustomExtractionRules {
        let mut direct_selectors = Vec::new();
        let mut custom_regex_patterns = Vec::new();
        let mut custom_org_to_domain_mapping = std::collections::HashMap::new();

        debug!("Generating domain-specific patterns from {} successful extractions", successful_extractions.len());

        // Analyze successful table-based extractions
        self.analyze_table_patterns(document, successful_extractions, &mut direct_selectors, &mut custom_org_to_domain_mapping);

        // Analyze HTML structure for regex patterns
        self.analyze_html_patterns(html_content, successful_extractions, &mut custom_regex_patterns);

        // Generate exclusion patterns to avoid common false positives
        let exclusion_patterns = self.generate_exclusion_patterns(base_url);

        CustomExtractionRules {
            direct_selectors,
            custom_regex_patterns,
            special_handling: Some(SpecialHandling {
                skip_generic_methods: true, // Use only domain-specific patterns
                custom_org_to_domain_mapping: if custom_org_to_domain_mapping.is_empty() { None } else { Some(custom_org_to_domain_mapping) },
                exclusion_patterns,
            }),
        }
    }

    /// Analyze successful table extractions to create targeted CSS selectors
    fn analyze_table_patterns(&self, document: &Html, successful_extractions: &[SubprocessorDomain], 
                             direct_selectors: &mut Vec<DirectSelector>, 
                             custom_mappings: &mut std::collections::HashMap<String, String>) {
        
        // Find tables that contain subprocessor data
        if let Ok(table_selector) = scraper::Selector::parse("table") {
            for table in document.select(&table_selector) {
                let table_text = table.text().collect::<String>().to_lowercase();
                
                // Extract company names from raw records for pattern matching
                let company_names: Vec<String> = successful_extractions.iter()
                    .filter_map(|extraction| {
                        // Extract company name from raw_record which contains HTML like "<td>Amazon Web Services, Inc.</td>"
                        if let Some(start) = extraction.raw_record.find(">") {
                            if let Some(end) = extraction.raw_record.rfind("<") {
                                let company_name = extraction.raw_record[start + 1..end].trim();
                                if !company_name.is_empty() && company_name.len() > 3 {
                                    return Some(company_name.to_string());
                                }
                            }
                        }
                        None
                    })
                    .collect();

                // Check if this table contains our successful extractions (look for company names, not domains)
                let matches_found = company_names.iter()
                    .filter(|company_name| table_text.contains(&company_name.to_lowercase()))
                    .count();

                debug!("Table contains {} company name matches out of {} extracted companies", matches_found, company_names.len());

                if matches_found >= 3 { // Table must contain multiple successful matches
                    debug!("Found productive table with {} matches", matches_found);
                    
                    // Analyze table structure
                    if let Ok(td_selector) = scraper::Selector::parse("td") {
                        let mut column_analysis = std::collections::HashMap::new();

                        for (_row_idx, row) in table.select(&TR_SELECTOR).enumerate() {
                            for (col_idx, cell) in row.select(&td_selector).enumerate() {
                                let cell_text = cell.text().collect::<String>().trim().to_string();
                                
                                // Check if this cell contains organization names
                                for (extraction_idx, company_name) in company_names.iter().enumerate() {
                                    if cell_text.to_lowercase().contains(&company_name.to_lowercase()) {
                                        column_analysis.entry(col_idx).or_insert(Vec::new()).push(format!("{}:{}", extraction_idx, company_name));
                                        debug!("Found company '{}' in column {} cell: '{}'", company_name, col_idx, cell_text);
                                    }
                                }
                            }
                        }

                        // Find the most productive column for organization names
                        if let Some((best_col, _)) = column_analysis.iter().max_by_key(|(_, domains)| domains.len()) {
                            let selector = format!("td:nth-child({})", best_col + 1);
                            direct_selectors.push(DirectSelector {
                                selector: selector.clone(),
                                attribute: None,
                                transform: Some("trim".to_string()),
                                description: format!("Extract organization names from column {} of subprocessor table", best_col + 1),
                            });
                            debug!("Generated column-specific selector: {}", selector);
                        }
                    }

                    // Extract organization name to domain mappings from table content
                    // IMPORTANT: Each extraction must be matched with its OWN company name from its raw_record
                    // to prevent mismatched mappings (e.g., "El Camino" -> wrong domain)
                    if let Ok(td_selector) = scraper::Selector::parse("td") {
                        for cell in table.select(&td_selector) {
                            let cell_text = cell.text().collect::<String>().trim().to_string();

                            // For each extraction, extract its company name from its own raw_record
                            // and only create a mapping if THAT company name matches the cell
                            for extraction in successful_extractions.iter() {
                                // Extract this extraction's company name from its raw_record
                                let extraction_company_name = if let Some(start) = extraction.raw_record.find(">") {
                                    if let Some(end) = extraction.raw_record.rfind("<") {
                                        let name = extraction.raw_record[start + 1..end].trim();
                                        if !name.is_empty() && name.len() > 3 {
                                            Some(name.to_string())
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                                if let Some(company_name) = extraction_company_name {
                                    // Only create mapping if THIS extraction's company name matches the cell
                                    if cell_text.to_lowercase().contains(&company_name.to_lowercase()) {
                                        // Add direct mapping from company name to domain
                                        custom_mappings.insert(company_name.to_lowercase(), extraction.domain.clone());

                                        // Also add variations of the company name
                                        let org_variations = self.extract_organization_variations(&company_name);
                                        for org_name in org_variations {
                                            if !org_name.is_empty() && org_name.len() > 3 {
                                                custom_mappings.insert(org_name.to_lowercase(), extraction.domain.clone());
                                            }
                                        }

                                        debug!("Added verified domain mapping: '{}' -> '{}'", company_name, extraction.domain);
                                    }
                                }
                            }
                        }
                    }
                    break; // Use first productive table
                }
            }
        }
    }

    /// Extract organization name variations for mapping (handles "Company Name, Inc.", "Company (Brand)", etc.)
    fn extract_organization_variations(&self, cell_text: &str) -> Vec<String> {
        let mut variations = Vec::new();
        let cleaned = cell_text.trim();
        
        if cleaned.is_empty() || cleaned.len() < 3 {
            return variations;
        }

        // Add the full text
        variations.push(cleaned.to_string());

        // Extract text before common business suffixes
        let suffixes = [", Inc.", ", LLC", ", Corp.", ", Ltd.", " Inc.", " LLC", " Corp.", " Ltd."];
        for suffix in &suffixes {
            if let Some(pos) = cleaned.find(suffix) {
                let base_name = cleaned[..pos].trim();
                if !base_name.is_empty() && base_name.len() > 2 {
                    variations.push(base_name.to_string());
                }
            }
        }

        // Extract text before parentheses (handles "Company (Brand)")
        if let Some(pos) = cleaned.find('(') {
            let base_name = cleaned[..pos].trim();
            if !base_name.is_empty() && base_name.len() > 2 {
                variations.push(base_name.to_string());
            }
        }

        variations
    }

    /// Analyze HTML patterns to create targeted regex patterns
    fn analyze_html_patterns(&self, html_content: &str, successful_extractions: &[SubprocessorDomain], 
                            custom_regex_patterns: &mut Vec<CustomRegexPattern>) {
        
        // Look for consistent HTML patterns around successful extractions
        for extraction in successful_extractions {
            // Find HTML contexts where this domain appears
            let domain = &extraction.domain;
            let domain_lower = domain.to_lowercase();
            
            // Look for table cell patterns
            if html_content.to_lowercase().contains(&format!("<td>{}", domain_lower)) {
                custom_regex_patterns.push(CustomRegexPattern {
                    pattern: r"<td>([^<,]+(?:,\s*(?:Inc|LLC|Corp|Ltd)\.?)?)</td>".to_string(),
                    capture_group: 1,
                    description: "Extract company names from table cells with business suffixes".to_string(),
                });
                break; // Only add this pattern once
            }
        }

        // Add pattern for extracting company names with various formats
        if successful_extractions.len() > 5 {
            custom_regex_patterns.push(CustomRegexPattern {
                pattern: r"(?:^|\s)([A-Z][a-zA-Z\s]+(?:,?\s*(?:Inc|LLC|Corp|Ltd)\.?))".to_string(),
                capture_group: 1,
                description: "Extract properly capitalized company names with business suffixes".to_string(),
            });
        }
    }

    /// Generate exclusion patterns to avoid common false positives for this domain
    fn generate_exclusion_patterns(&self, base_url: &str) -> Vec<String> {
        let mut exclusions = vec![
            // Common navigation and UI elements
            r"^(?i:home|about|contact|privacy|terms|help|support|login|signup|register)$".to_string(),
            r"^(?i:dashboard|admin|search|browse|explore|discover|features|products|services)$".to_string(),
            r"^(?i:pricing|plans|enterprise|business|professional|free|premium|pro|basic)$".to_string(),
            r"^(?i:developers|api|docs|documentation|guides|tutorials|resources|tools)$".to_string(),
            r"^(?i:partners|integrations|marketplace|academy|education|training|careers)$".to_string(),
            r"^(?i:community|forum|blog|news|events|newsletter|updates|legal|security)$".to_string(),
        ];

        // Add domain-specific exclusions based on the URL
        if base_url.contains("klaviyo") {
            exclusions.push(r"^(?i:klaviyo|email|marketing|ecommerce|automation)$".to_string());
        } else if base_url.contains("stripe") {
            exclusions.push(r"^(?i:stripe|payments|billing|checkout|terminal)$".to_string());
        }

        exclusions
    }

    /// Extract vendor domains from structured content - DISABLED to prevent false positives
    /// The generic structured content extraction is too broad and causes false positives
    /// All legitimate subprocessor extraction should happen via tables and lists with proper context
    pub fn extract_from_structured_content(&self, _document: &Html, _html_content: &str) -> Result<Vec<SubprocessorDomain>> {
        debug!("Structured content extraction disabled to prevent false positives");
        Ok(Vec::new())
    }

    /// Extract domain from company entity name with intelligent parsing
    pub fn extract_domain_from_entity_name(&self, entity_name: &str) -> Option<String> {
        // First, look for explicit domains in parentheses like "(Sentry.io)" or "(d/b/a Sinch Email)"
        let parentheses_regex = regex::Regex::new(r"\(([^)]+)\)").ok()?;
        
        for capture in parentheses_regex.captures_iter(entity_name) {
            if let Some(parentheses_content) = capture.get(1) {
                let content = parentheses_content.as_str();
                
                // Look for domain patterns within parentheses
                if let Some(domain) = self.extract_direct_domain_from_text(content) {
                    return Some(domain);
                }
                
                // Handle "d/b/a Company Name" format
                if content.to_lowercase().contains("d/b/a") {
                    if let Some(dba_name) = content.splitn(2, "d/b/a").nth(1) {
                        if let Some(domain) = self.company_name_to_domain(dba_name.trim()) {
                            return Some(domain);
                        }
                    }
                }
            }
        }
        
        // Try to infer domain from company name directly
        self.company_name_to_domain(entity_name)
    }
    
    /// Extract domain from text using strict domain detection patterns
    pub fn extract_direct_domain_from_text(&self, text: &str) -> Option<String> {
        // Strict domain regex pattern - must have valid TLD
        let domain_regex = regex::Regex::new(r"(?i)\b([a-zA-Z]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,10}\b").ok()?;
        
        for capture in domain_regex.captures_iter(text) {
            if let Some(domain_match) = capture.get(0) {
                let domain = domain_match.as_str().to_lowercase();
                
                // Additional validation: reject IP addresses that might match
                if self.is_ip_address(&domain) {
                    continue;
                }
                
                // Filter out common false positives and validate domain
                if self.is_valid_vendor_domain(&domain) {
                    return Some(domain);
                }
            }
        }
        
        None
    }
    
    /// Convert company name to likely domain using intelligent mapping
    pub fn company_name_to_domain(&self, company_name: &str) -> Option<String> {
        let clean_name = company_name.to_lowercase();
        
        // Known mappings for common cases
        let known_mappings = [
            ("ada support, inc", "ada.cx"),
            ("amazon web services", "aws.amazon.com"), 
            ("cloudflare", "cloudflare.com"),
            ("functional software", "sentry.io"),
            ("mailgun technologies", "mailgun.com"),
            ("sendgrid", "sendgrid.com"),
            ("snowflake", "snowflake.com"),
            ("sparkpost", "sparkpost.com"),
            ("splunk", "splunk.com"),
            ("statsig", "statsig.com"),
            ("twilio", "twilio.com"),
            ("zendesk", "zendesk.com"),
            ("concentrix", "concentrix.com"),
            ("dropbox", "dropbox.com"),
            ("fivetran", "fivetran.com"),
            ("infobip", "infobip.com"),
            ("chronosphere", "chronosphere.io"),
        ];
        
        // Check for exact or partial matches
        for (company_key, domain) in &known_mappings {
            if clean_name.contains(company_key) {
                return Some(domain.to_string());
            }
        }
        
        // Try to extract from company name patterns like "Company, Inc." -> "company.com"
        let company_patterns = [
            r"^([a-zA-Z]+),?\s+(inc\.?|llc\.?|corp\.?|ltd\.?).*$",
            r"^([a-zA-Z]+)\s+technologies.*$",
            r"^([a-zA-Z]+)\s+(inc\.?|llc\.?|corp\.?|ltd\.?).*$",
        ];
        
        for pattern in &company_patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if let Some(capture) = regex.captures(&clean_name) {
                    if let Some(company_match) = capture.get(1) {
                        let base_name = company_match.as_str().to_lowercase();
                        if base_name.len() > 2 && base_name.chars().all(|c| c.is_ascii_alphabetic()) {
                            let potential_domain = format!("{}.com", base_name);
                            if self.is_valid_vendor_domain(&potential_domain) {
                                return Some(potential_domain);
                            }
                        }
                    }
                }
            }
        }
        
        None
    }
    
    /// Legacy method for backward compatibility 
    pub fn extract_domain_from_text(&self, text: &str) -> Option<String> {
        self.extract_direct_domain_from_text(text)
    }

    /// Check if a string looks like an IP address
    fn is_ip_address(&self, text: &str) -> bool {
        // Simple check for IP address patterns
        text.chars().all(|c| c.is_ascii_digit() || c == '.')
    }

    /// Check if text looks like it contains vendor/company information
    pub fn looks_like_vendor_content(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase();
        
        // Keywords that suggest vendor/company content
        let vendor_keywords = [
            "inc", "ltd", "llc", "corp", "corporation", "company", "technologies",
            "systems", "solutions", "services", "platform", "software", "cloud",
            "api", "hosting", "analytics", "security", "payment", "email",
        ];
        
        // Must contain at least one vendor keyword and a domain-like pattern
        vendor_keywords.iter().any(|&keyword| text_lower.contains(keyword)) &&
        (text_lower.contains(".com") || text_lower.contains(".io") || 
        text_lower.contains(".org") || text_lower.contains(".net"))
    }

    /// Validate if a domain is likely a legitimate vendor domain
    pub fn is_valid_vendor_domain(&self, domain: &str) -> bool {
        // Filter out common false positives and invalid domains
        let invalid_patterns = [
            "example.com", "example.org", "localhost", "127.0.0.1",
            "test.com", "domain.com", "yoursite.com", "website.com",
            "email.com", "mail.com", // Common placeholders
            "n/a.com", "none.com", "na.com", // Placeholder text parsed as domains
        ];

        // Check if domain is in invalid patterns
        if invalid_patterns.iter().any(|&pattern| domain == pattern) {
            return false;
        }

        // Domain should have at least one dot and reasonable length
        // Also check that it has a valid TLD (at least 2 characters after the last dot)
        if !domain.contains('.') || domain.len() < 4 || domain.len() > 100 {
            return false;
        }

        // Validate TLD exists and is reasonable
        if let Some(last_dot_pos) = domain.rfind('.') {
            let tld = &domain[last_dot_pos + 1..];
            if tld.len() < 2 || tld.len() > 10 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
                return false;
            }

            // Validate the domain label (part before TLD) is at least 3 characters
            // This catches PDF extraction artifacts like b.mz, e.zz, n.ik, j.os, f.ff, v.rr
            // from garbled PDF text (e.g., Apple's subprocessor PDF table formatting)
            // Note: legitimate 2-char domains like hp.com or fb.com are handled via known
            // vendor mappings which bypass this validation path
            let label = &domain[..last_dot_pos];
            let last_label = label.rsplit('.').next().unwrap_or(label);
            if last_label.len() < 3 {
                return false;
            }
        }

        true
    }
    
    /// Create enhanced evidence with text content (stripped HTML) and highlight URL (H005 fix)
    pub fn create_enhanced_evidence(&self, element: &scraper::ElementRef, entity_name: &str, base_url: &str) -> String {
        // Get text content from the element instead of raw HTML to prevent stored XSS
        let text = element.text().collect::<String>();
        let text = text.trim();

        // Truncate to reasonable length (find valid char boundary to avoid panic on multi-byte UTF-8)
        let evidence_text = if text.len() > 200 {
            let mut truncate_at = 200;
            while truncate_at > 0 && !text.is_char_boundary(truncate_at) {
                truncate_at -= 1;
            }
            format!("{}...", &text[..truncate_at])
        } else {
            text.to_string()
        };

        // Create URL with text highlight
        let highlight_url = self.create_highlight_url(base_url, entity_name);

        format!("Found '{}' in: {}; URL: {}", entity_name, evidence_text, highlight_url)
    }
    
    /// Create focused HTML evidence showing just the organization name and its immediate surrounding elements
    fn create_focused_html_evidence(&self, element: &scraper::ElementRef, entity_name: &str) -> String {
        let element_html = element.html();
        
        // If the element is small (likely a td, span, etc), just return it
        if element_html.len() <= 200 {
            return element_html;
        }
        
        // For larger elements, try to extract just the part containing the entity name
        let text_content = element.text().collect::<String>();
        if text_content.to_lowercase().contains(&entity_name.to_lowercase()) {
            // Look for the tag name of the element
            let tag_name = element.value().name();
            
            // Try to find the specific inner element containing the entity name
            if let Ok(selector) = scraper::Selector::parse(&format!("{} td, {} span, {} div, {} p", tag_name, tag_name, tag_name, tag_name)) {
                for inner_element in element.select(&selector) {
                    let inner_text = inner_element.text().collect::<String>();
                    if inner_text.to_lowercase().contains(&entity_name.to_lowercase()) {
                        let inner_html = inner_element.html();
                        // Return the inner element if it's focused enough
                        if inner_html.len() <= 300 {
                            return inner_html;
                        }
                    }
                }
            }
        }
        
        // Fallback: return just the tag with the entity name visible
        format!("<{}>{}...</{}>", element.value().name(), entity_name, element.value().name())
    }
    
    /// Create a URL with text highlighting for easy navigation to the subprocessor entry
    pub fn create_highlight_url(&self, base_url: &str, entity_name: &str) -> String {
        // URL encode the entity name for the highlight parameter
        let encoded_text = urlencoding::encode(entity_name);
        
        // Create the highlight URL using the :~:text= syntax
        format!("{}#:~:text={}", base_url, encoded_text)
    }
    
    /// Create a concise evidence excerpt instead of storing full HTML content
    pub fn create_evidence_excerpt(&self, text: &str, domain: &str) -> String {
        const MAX_EXCERPT_LENGTH: usize = 500;
        
        let text = text.trim();
        
        // Find the position of the domain in the text
        if let Some(domain_pos) = text.to_lowercase().find(&domain.to_lowercase()) {
            // Create an excerpt around the domain
            let start = domain_pos.saturating_sub(100);
            let end = std::cmp::min(domain_pos + domain.len() + 100, text.len());
            
            let excerpt = &text[start..end];
            
            // If the excerpt is too long, truncate it
            if excerpt.len() > MAX_EXCERPT_LENGTH {
                let truncated = &excerpt[..MAX_EXCERPT_LENGTH];
                format!("...{}...", truncated)
            } else {
                // Add ellipsis if we truncated from beginning or end
                let prefix = if start > 0 { "..." } else { "" };
                let suffix = if end < text.len() { "..." } else { "" };
                format!("{}{}{}", prefix, excerpt, suffix)
            }
        } else {
            // Fallback: just take the first part of the text
            if text.len() > MAX_EXCERPT_LENGTH {
                format!("{}...", &text[..MAX_EXCERPT_LENGTH])
            } else {
                text.to_string()
            }
        }
    }

    /// Extract vendor domains from PDF content
    /// For now, this is a basic text-based extraction from PDF content
    /// In the future, this could be enhanced with a proper PDF parser
    pub async fn extract_from_pdf_content(&self, pdf_content: &str, base_url: &str, source_domain: &str) -> Result<Vec<SubprocessorDomain>> {
        debug!("Extracting subprocessors from PDF content for domain: {}", source_domain);
        
        let mut vendors = Vec::new();
        
        // PDF content when fetched as text often contains readable text mixed with PDF formatting
        // Look for patterns that suggest company names in the text
        let company_patterns = vec![
            // Look for lines that contain "Inc.", "LLC", "Corp", etc.
            r"([A-Z][a-zA-Z\s&,\.]+(?:Inc\.?|LLC|Corp\.?|Corporation|Ltd\.?|Limited))",
            // Look for lines with ".com", ".org", etc. domains
            r"([A-Z][a-zA-Z\s&,\.]+)\s+([a-zA-Z0-9.-]+\.(com|org|io|net|co))",
            // Look for capitalized company names (at least 2 words)
            r"([A-Z][a-zA-Z]+\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*)",
        ];

        // Load extraction patterns from cache
        let patterns = {
            let cache = self.cache.read().await;
            cache.get_extraction_patterns(source_domain).await
        };

        for pattern_str in &company_patterns {
            if let Ok(regex) = regex::Regex::new(pattern_str) {
                for capture in regex.captures_iter(pdf_content) {
                    if let Some(company_match) = capture.get(1) {
                        let company_name = company_match.as_str().trim();
                        
                        // Skip very short matches or common false positives
                        if company_name.len() < 5 || 
                           company_name.to_lowercase().contains("pdf") ||
                           company_name.to_lowercase().contains("page") ||
                           company_name.to_lowercase().contains("document") {
                            continue;
                        }

                        // Try to extract domain from company name using patterns
                        if let Some(domain) = self.extract_domain_from_entity_name_with_patterns(company_name, &patterns) {
                            debug!("Extracted domain from PDF: {} from company: {}", domain, company_name);
                            vendors.push(SubprocessorDomain {
                                domain,
                                source_type: RecordType::HttpSubprocessor,
                                raw_record: format!("PDF content: {} (URL: {})", company_name, base_url),
                            });
                        }
                    }
                }
            }
        }

        // Also look for explicit domain mentions in the PDF content
        // Require labels to be at least 3 chars to avoid PDF artifacts like b.mz, e.zz, n.ik
        let domain_regex = regex::Regex::new(r"\b([a-zA-Z][a-zA-Z0-9\-]{2,61}\.)+[a-zA-Z]{2,10}\b").ok();
        if let Some(regex) = domain_regex {
            for capture in regex.captures_iter(pdf_content) {
                if let Some(domain_match) = capture.get(0) {
                    let domain = domain_match.as_str().to_lowercase();
                    
                    // Filter out common false positives and validate domain
                    if self.is_valid_vendor_domain(&domain) {
                        debug!("Extracted explicit domain from PDF: {}", domain);
                        vendors.push(SubprocessorDomain {
                            domain: domain.clone(),
                            source_type: RecordType::HttpSubprocessor,
                            raw_record: format!("PDF explicit domain: {} (URL: {})", domain, base_url),
                        });
                    }
                }
            }
        }

        // Deduplicate vendors by domain name
        let mut seen_domains = std::collections::HashSet::new();
        vendors.retain(|vendor| seen_domains.insert(vendor.domain.clone()));

        debug!("Extracted {} unique domains from PDF for domain: {}", vendors.len(), source_domain);
        Ok(vendors)
    }

    /// Helper method to get rendered content from headless browser
    async fn get_rendered_content_from_browser(&self, url: &str) -> Result<String> {
        let guard = crate::browser_pool::create_browser()?;

        let tab = guard.browser.new_tab().map_err(|e| {
            anyhow::anyhow!("Failed to create new browser tab: {}", e)
        })?;
        
        tab.navigate_to(url).map_err(|e| {
            anyhow::anyhow!("Failed to navigate to {}: {}", url, e)
        })?;
        
        tab.wait_until_navigated().map_err(|e| {
            anyhow::anyhow!("Page failed to load: {}", e)
        })?;
        
        // Wait for JavaScript to render content
        std::thread::sleep(Duration::from_millis(2000));
        
        let html_content = tab.get_content().map_err(|e| {
            anyhow::anyhow!("Failed to get page content: {}", e)
        })?;
        
        debug!("Retrieved {} characters of rendered HTML content", html_content.len());
        Ok(html_content)
    }
}

/// Extract vendor domains from subprocessor pages with logging support
pub async fn extract_vendor_domains_from_subprocessors(
    domain: &str, 
    logger: Option<&dyn LogFailure>
) -> Result<Vec<SubprocessorDomain>> {
    let analyzer = SubprocessorAnalyzer::new().await;
    // Cache is automatically saved when successful results are found
    analyzer.analyze_domain(domain, logger).await
}

/// Extract vendor domains with shared analyzer instance (for performance)
pub async fn extract_vendor_domains_with_analyzer(
    analyzer: &SubprocessorAnalyzer,
    domain: &str,
    logger: Option<&dyn LogFailure>
) -> Result<Vec<SubprocessorDomain>> {
    analyzer.analyze_domain(domain, logger).await
}

/// Extract vendor domains with shared analyzer instance and debug logging
pub async fn extract_vendor_domains_with_analyzer_and_logging(
    analyzer: &SubprocessorAnalyzer,
    domain: &str,
    logger: Option<&dyn LogFailure>,
    debug_logger: &crate::logger::AnalysisLogger,
) -> Result<Vec<SubprocessorDomain>> {
    analyzer.analyze_domain_with_logging(domain, logger, Some(debug_logger)).await
}

/// Check if a NER-extracted organization name is a false positive.
/// Returns true for patterns that are clearly not real organization names:
/// - ISO 639 language codes (ar, cs, da, de, es, fi, fr, he, hu, id, it, ja, ko, ms, nl, pl, ru, sv, th, tr)
/// - Locale identifiers (en-us, zh-hans, pt-br, nb-no)
/// - Snake_case field/feature names (soc2_report, penetration_testing, encrypt_data)
/// - Very short strings (< 3 chars)
pub fn is_ner_false_positive(org_name: &str) -> bool {
    let name = org_name.trim();
    let lower = name.to_lowercase();

    // Too short to be a real organization name
    if name.len() < 3 {
        return true;
    }

    // Snake_case identifiers are code/config field names, not organizations
    if lower.contains('_') && lower.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return true;
    }

    // Locale/language identifiers (en-us, zh-hans, pt-br, nb-no)
    if lower.len() <= 7 && lower.contains('-') && lower.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return true;
    }

    // ISO 639-1 language codes that NER misidentifies as organizations
    // (commonly found on internationalized Microsoft/Salesforce pages)
    let language_codes = [
        "ar", "bg", "bn", "ca", "cs", "cy", "da", "de", "el", "en", "es", "et",
        "eu", "fa", "fi", "fr", "ga", "gl", "gu", "he", "hi", "hr", "hu", "hy",
        "id", "is", "it", "ja", "ka", "kk", "km", "kn", "ko", "lb", "lo", "lt",
        "lv", "mk", "ml", "mn", "mr", "ms", "mt", "my", "ne", "nl", "no", "pa",
        "pl", "ps", "pt", "ro", "ru", "si", "sk", "sl", "so", "sq", "sr", "sv",
        "sw", "ta", "te", "th", "tl", "tr", "uk", "ur", "uz", "vi", "zh",
    ];
    if language_codes.contains(&lower.as_str()) {
        return true;
    }

    false
}

/// Extract visible text content from HTML, stripping tags and scripts.
/// Used for NER-based organization extraction from subprocessor pages.
fn extract_text_from_html(html: &str) -> String {
    let document = Html::parse_document(html);

    // Try to select main content areas first for better signal
    let content_selectors = ["main", "article", "[role='main']", ".content", "#content"];
    for sel_str in &content_selectors {
        if let Ok(sel) = Selector::parse(sel_str) {
            let texts: Vec<String> = document.select(&sel)
                .flat_map(|el| el.text())
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
            if texts.join(" ").len() > 200 {
                return texts.join(" ");
            }
        }
    }

    // Fallback: extract all text from body
    if let Ok(body_sel) = Selector::parse("body") {
        let texts: Vec<String> = document.select(&body_sel)
            .flat_map(|el| el.text())
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        return texts.join(" ");
    }

    String::new()
}