//! Cache management commands for the nthpartyfinder CLI
//!
//! This module provides functionality to list, show, clear, and validate
//! the subprocessor URL cache stored in the /cache directory.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use crate::subprocessor::{SubprocessorCache, SubprocessorUrlCacheEntry};

/// Cache directory relative to current working directory
const CACHE_DIR: &str = "cache";

/// List all cached domains
pub async fn list_cached_domains() -> Result<()> {
    let cache_dir = PathBuf::from(CACHE_DIR);

    if !cache_dir.exists() {
        println!("No cache directory found. Run an analysis with --enable-subprocessor-analysis to create cache entries.");
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(&cache_dir)
        .await
        .context("Failed to read cache directory")?;

    let mut domains: Vec<(String, u64, String)> = Vec::new();

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Some(domain) = path.file_stem().and_then(|s| s.to_str()) {
                // Try to read the cache entry to get details
                if let Ok(content) = tokio::fs::read_to_string(&path).await {
                    if let Ok(cache_entry) =
                        serde_json::from_str::<SubprocessorUrlCacheEntry>(&content)
                    {
                        domains.push((
                            domain.to_string(),
                            cache_entry.last_successful_access,
                            cache_entry.working_subprocessor_url.clone(),
                        ));
                    } else {
                        domains.push((domain.to_string(), 0, "Invalid cache entry".to_string()));
                    }
                } else {
                    domains.push((domain.to_string(), 0, "Unable to read".to_string()));
                }
            }
        }
    }

    if domains.is_empty() {
        println!("No cached domains found.");
        return Ok(());
    }

    // Sort by last access time (most recent first)
    domains.sort_by_key(|b| std::cmp::Reverse(b.1));

    println!("Cached Domains ({} total):", domains.len());
    println!("{}", "=".repeat(80));
    println!("{:<40} {:<25} URL", "Domain", "Last Accessed");
    println!("{}", "-".repeat(80));

    for (domain, timestamp, url) in domains {
        let last_accessed = if timestamp > 0 {
            format_timestamp(timestamp)
        } else {
            "Unknown".to_string()
        };

        // Truncate URL if too long (char boundary safe for non-ASCII URLs)
        let url_display = if url.len() > 40 {
            let mut end = 37;
            while end > 0 && !url.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &url[..end])
        } else {
            url
        };

        println!("{:<40} {:<25} {}", domain, last_accessed, url_display);
    }

    Ok(())
}

/// Show detailed cache entry for a specific domain
pub async fn show_cache_entry(domain: &str) -> Result<()> {
    let cache = SubprocessorCache::load().await;

    match cache.get_cached_entry(domain).await {
        Some(entry) => {
            println!("Cache Entry for: {}", entry.domain);
            println!("{}", "=".repeat(60));
            println!();
            println!("Working URL: {}", entry.working_subprocessor_url);
            println!(
                "Last Accessed: {}",
                format_timestamp(entry.last_successful_access)
            );
            println!("Cache Version: {}", entry.cache_version);
            println!();

            if let Some(ref patterns) = entry.extraction_patterns {
                println!("Extraction Patterns:");
                println!("  Domain-specific: {}", patterns.is_domain_specific);

                if !patterns.table_selectors.is_empty() {
                    println!("  Table Selectors: {:?}", patterns.table_selectors);
                }
                if !patterns.list_selectors.is_empty() {
                    println!("  List Selectors: {:?}", patterns.list_selectors);
                }
                if !patterns.context_patterns.is_empty() {
                    println!("  Context Patterns: {:?}", patterns.context_patterns);
                }
                if !patterns.entity_header_patterns.is_empty() {
                    println!(
                        "  Entity Header Patterns: {:?}",
                        patterns.entity_header_patterns
                    );
                }
                if let Some(ref rules) = patterns.custom_extraction_rules {
                    println!("  Custom Extraction Rules:");
                    if !rules.direct_selectors.is_empty() {
                        println!("    Direct Selectors: {:?}", rules.direct_selectors);
                    }
                    if !rules.custom_regex_patterns.is_empty() {
                        println!(
                            "    Custom Regex Patterns: {} patterns",
                            rules.custom_regex_patterns.len()
                        );
                        for pattern in &rules.custom_regex_patterns {
                            println!(
                                "      - {} (capture group: {})",
                                &pattern.description, pattern.capture_group
                            );
                        }
                    }
                    if let Some(ref handling) = rules.special_handling {
                        if handling.skip_generic_methods {
                            println!("    Skip Generic Methods: true");
                        }
                        if !handling.exclusion_patterns.is_empty() {
                            println!(
                                "    Exclusion Patterns: {} patterns",
                                handling.exclusion_patterns.len()
                            );
                        }
                    }
                }
                println!();
            }

            if let Some(ref metadata) = entry.extraction_metadata {
                println!("Extraction Metadata:");
                println!(
                    "  Successful Extractions: {}",
                    metadata.successful_extractions
                );
                if let Some(col_idx) = metadata.successful_entity_column_index {
                    println!("  Entity Column Index: {}", col_idx);
                }
                if let Some(ref pattern) = metadata.successful_header_pattern {
                    println!("  Successful Header Pattern: {}", pattern);
                }
                println!(
                    "  Last Extraction Time: {}",
                    format_timestamp(metadata.last_extraction_time)
                );

                if let Some(ref adaptive) = metadata.adaptive_patterns {
                    println!("  Adaptive Patterns:");
                    println!("    Confidence Score: {:.2}", adaptive.confidence_score);
                    println!("    Validation Count: {}", adaptive.validation_count);
                    println!(
                        "    Discovery Time: {}",
                        format_timestamp(adaptive.discovery_timestamp)
                    );
                    println!(
                        "    Discovered Selectors: {} selectors",
                        adaptive.discovered_selectors.len()
                    );
                }
            }

            Ok(())
        }
        None => {
            // Try to find similar domains
            let cache_dir = PathBuf::from(CACHE_DIR);
            if cache_dir.exists() {
                let mut similar: Vec<String> = Vec::new();
                let mut entries = tokio::fs::read_dir(&cache_dir).await?;

                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("json") {
                        if let Some(cached_domain) = path.file_stem().and_then(|s| s.to_str()) {
                            if cached_domain.contains(domain) || domain.contains(cached_domain) {
                                similar.push(cached_domain.to_string());
                            }
                        }
                    }
                }

                if !similar.is_empty() {
                    eprintln!("No cache entry found for: {}", domain);
                    eprintln!("Did you mean one of these?");
                    for s in similar {
                        eprintln!("  - {}", s);
                    }
                } else {
                    eprintln!("No cache entry found for: {}", domain);
                }
            } else {
                eprintln!("No cache directory found.");
            }

            std::process::exit(1);
        }
    }
}

/// Clear cache for a specific domain
pub async fn clear_domain_cache(domain: &str) -> Result<()> {
    let cache = SubprocessorCache::load().await;

    match cache.clear_domain_cache(domain).await {
        Ok(true) => {
            println!("Successfully cleared cache for: {}", domain);
            Ok(())
        }
        Ok(false) => {
            eprintln!("No cache entry found for: {}", domain);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to clear cache for {}: {}", domain, e);
            std::process::exit(1);
        }
    }
}

/// Clear all cached data
pub async fn clear_all_cache() -> Result<()> {
    let cache = SubprocessorCache::load().await;

    match cache.clear_all_cache().await {
        Ok(count) => {
            if count > 0 {
                println!("Successfully cleared {} cache entries.", count);
            } else {
                println!("No cache entries to clear.");
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to clear cache: {}", e);
            std::process::exit(1);
        }
    }
}

/// Validation result for a single cache entry
#[derive(Debug)]
pub struct ValidationResult {
    pub domain: String,
    pub url: String,
    pub status: ValidationStatus,
    pub response_time_ms: Option<u64>,
    pub error_message: Option<String>,
}

#[derive(Debug)]
pub enum ValidationStatus {
    Ok,
    Redirect(String),
    NotFound,
    ServerError(u16),
    Timeout,
    NetworkError,
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationStatus::Ok => write!(f, "OK"),
            ValidationStatus::Redirect(url) => write!(f, "Redirect -> {}", url),
            ValidationStatus::NotFound => write!(f, "Not Found (404)"),
            ValidationStatus::ServerError(code) => write!(f, "Server Error ({})", code),
            ValidationStatus::Timeout => write!(f, "Timeout"),
            ValidationStatus::NetworkError => write!(f, "Network Error"),
        }
    }
}

/// Validate all cached URLs still work
pub async fn validate_cache(verbose: bool, specific_domain: Option<&str>) -> Result<()> {
    let cache_dir = PathBuf::from(CACHE_DIR);

    if !cache_dir.exists() {
        println!("No cache directory found.");
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(&cache_dir)
        .await
        .context("Failed to read cache directory")?;

    let mut urls_to_validate: Vec<(String, String)> = Vec::new();

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Some(domain) = path.file_stem().and_then(|s| s.to_str()) {
                // Skip if we're validating a specific domain and this isn't it
                if let Some(specific) = specific_domain {
                    if domain != specific {
                        continue;
                    }
                }

                if let Ok(content) = tokio::fs::read_to_string(&path).await {
                    if let Ok(cache_entry) =
                        serde_json::from_str::<SubprocessorUrlCacheEntry>(&content)
                    {
                        if !cache_entry.working_subprocessor_url.is_empty() {
                            urls_to_validate
                                .push((domain.to_string(), cache_entry.working_subprocessor_url));
                        }
                    }
                }
            }
        }
    }

    if urls_to_validate.is_empty() {
        if specific_domain.is_some() {
            println!("No cache entry found for specified domain.");
        } else {
            println!("No cached URLs to validate.");
        }
        return Ok(());
    }

    println!("Validating {} cached URLs...", urls_to_validate.len());
    println!();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none()) // Don't follow redirects to detect them
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .context("Failed to create HTTP client")?;

    let mut ok_count = 0;
    let mut redirect_count = 0;
    let mut error_count = 0;
    let mut results: Vec<ValidationResult> = Vec::new();

    for (domain, url) in urls_to_validate {
        let start = std::time::Instant::now();

        let result = match client.get(&url).send().await {
            Ok(response) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let status = response.status();

                if status.is_success() {
                    ok_count += 1;
                    ValidationResult {
                        domain,
                        url,
                        status: ValidationStatus::Ok,
                        response_time_ms: Some(elapsed),
                        error_message: None,
                    }
                } else if status.is_redirection() {
                    redirect_count += 1;
                    let redirect_url = response
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("unknown")
                        .to_string();
                    ValidationResult {
                        domain,
                        url,
                        status: ValidationStatus::Redirect(redirect_url),
                        response_time_ms: Some(elapsed),
                        error_message: None,
                    }
                } else if status == reqwest::StatusCode::NOT_FOUND {
                    error_count += 1;
                    ValidationResult {
                        domain,
                        url,
                        status: ValidationStatus::NotFound,
                        response_time_ms: Some(elapsed),
                        error_message: None,
                    }
                } else {
                    error_count += 1;
                    ValidationResult {
                        domain,
                        url,
                        status: ValidationStatus::ServerError(status.as_u16()),
                        response_time_ms: Some(elapsed),
                        error_message: Some(format!("HTTP {}", status)),
                    }
                }
            }
            Err(e) => {
                error_count += 1;
                if e.is_timeout() {
                    ValidationResult {
                        domain,
                        url,
                        status: ValidationStatus::Timeout,
                        response_time_ms: None,
                        error_message: Some("Request timed out".to_string()),
                    }
                } else {
                    ValidationResult {
                        domain,
                        url,
                        status: ValidationStatus::NetworkError,
                        response_time_ms: None,
                        error_message: Some(e.to_string()),
                    }
                }
            }
        };

        // Print progress
        let status_indicator = match &result.status {
            ValidationStatus::Ok => "[OK]",
            ValidationStatus::Redirect(_) => "[REDIRECT]",
            ValidationStatus::NotFound => "[NOT FOUND]",
            ValidationStatus::ServerError(_) => "[ERROR]",
            ValidationStatus::Timeout => "[TIMEOUT]",
            ValidationStatus::NetworkError => "[NET ERROR]",
        };

        if verbose {
            println!(
                "{:<12} {:<40} {} ({}ms)",
                status_indicator,
                result.domain,
                result.url,
                result.response_time_ms.unwrap_or(0)
            );

            if let Some(ref err) = result.error_message {
                println!("             Error: {}", err);
            }
            if let ValidationStatus::Redirect(ref redirect_url) = result.status {
                println!("             -> {}", redirect_url);
            }
        } else {
            print!(".");
            // Flush stdout to show progress
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        results.push(result);
    }

    if !verbose {
        println!(); // New line after progress dots
    }

    println!();
    println!("Validation Summary:");
    println!("{}", "=".repeat(40));
    println!("OK:        {} URLs", ok_count);
    println!("Redirects: {} URLs", redirect_count);
    println!("Errors:    {} URLs", error_count);
    println!();

    // Show problematic URLs
    let problems: Vec<&ValidationResult> = results
        .iter()
        .filter(|r| !matches!(r.status, ValidationStatus::Ok))
        .collect();

    if !problems.is_empty() && !verbose {
        println!("Problematic URLs:");
        println!("{}", "-".repeat(40));
        for result in problems {
            println!("{}: {} - {}", result.domain, result.url, result.status);
        }
        println!();
        println!("Run with -v/--verbose for more details.");
    }

    if error_count > 0 {
        println!();
        println!("Tip: Use 'nthpartyfinder cache clear <domain>' to remove stale cache entries.");
    }

    Ok(())
}

/// Format a Unix timestamp as a human-readable date string
fn format_timestamp(timestamp: u64) -> String {
    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);
    if let Ok(system_time) = datetime.duration_since(UNIX_EPOCH) {
        let dt: DateTime<Utc> = DateTime::from(UNIX_EPOCH + system_time);
        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        "Invalid timestamp".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timestamp() {
        let ts = 1704067200; // 2024-01-01 00:00:00 UTC
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2024"));
    }

    #[test]
    fn test_format_timestamp_zero() {
        // Timestamp of 0 should still format correctly (1970-01-01)
        let ts = 0;
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("1970"));
    }

    #[test]
    fn test_validation_status_display() {
        assert_eq!(format!("{}", ValidationStatus::Ok), "OK");
        assert_eq!(format!("{}", ValidationStatus::NotFound), "Not Found (404)");
        assert_eq!(format!("{}", ValidationStatus::Timeout), "Timeout");
        assert_eq!(
            format!("{}", ValidationStatus::NetworkError),
            "Network Error"
        );
        assert_eq!(
            format!("{}", ValidationStatus::ServerError(500)),
            "Server Error (500)"
        );
        assert_eq!(
            format!("{}", ValidationStatus::ServerError(503)),
            "Server Error (503)"
        );
    }

    #[test]
    fn test_validation_status_redirect_display() {
        let status = ValidationStatus::Redirect("https://example.com/new-location".to_string());
        let formatted = format!("{}", status);
        assert!(formatted.contains("Redirect"));
        assert!(formatted.contains("https://example.com/new-location"));
    }

    #[test]
    fn test_validation_result_fields() {
        let result = ValidationResult {
            domain: "example.com".to_string(),
            url: "https://example.com/subprocessors".to_string(),
            status: ValidationStatus::Ok,
            response_time_ms: Some(150),
            error_message: None,
        };

        assert_eq!(result.domain, "example.com");
        assert_eq!(result.url, "https://example.com/subprocessors");
        assert!(matches!(result.status, ValidationStatus::Ok));
        assert_eq!(result.response_time_ms, Some(150));
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_validation_result_with_error() {
        let result = ValidationResult {
            domain: "failed.com".to_string(),
            url: "https://failed.com/subprocessors".to_string(),
            status: ValidationStatus::NetworkError,
            response_time_ms: None,
            error_message: Some("Connection refused".to_string()),
        };

        assert!(result.error_message.is_some());
        assert_eq!(result.error_message.unwrap(), "Connection refused");
    }

    #[test]
    fn test_cache_dir_constant() {
        // Verify the cache directory constant is correctly set
        assert_eq!(CACHE_DIR, "cache");
    }

    // ── format_timestamp additional tests ──────────────────────────────

    #[test]
    fn test_format_timestamp_specific_date() {
        // 2024-06-15 12:30:00 UTC = 1718451000
        let ts = 1718451000;
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2024"));
        assert!(formatted.contains("UTC"));
    }

    #[test]
    fn test_format_timestamp_epoch_start() {
        let formatted = format_timestamp(0);
        assert_eq!(formatted, "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn test_format_timestamp_new_years_2024() {
        let ts = 1704067200; // 2024-01-01 00:00:00 UTC
        let formatted = format_timestamp(ts);
        assert_eq!(formatted, "2024-01-01 00:00:00 UTC");
    }

    #[test]
    fn test_format_timestamp_large_value() {
        // Far future: 2100-01-01 roughly
        let ts = 4102444800;
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2100"));
        assert!(formatted.contains("UTC"));
    }

    #[test]
    fn test_format_timestamp_format_consistency() {
        let formatted = format_timestamp(1000000000);
        // Should match YYYY-MM-DD HH:MM:SS UTC format
        assert_eq!(formatted.len(), "YYYY-MM-DD HH:MM:SS UTC".len());
        assert!(formatted.ends_with("UTC"));
    }

    // ── ValidationStatus Display tests ─────────────────────────────────

    #[test]
    fn test_validation_status_display_all_variants() {
        assert_eq!(format!("{}", ValidationStatus::Ok), "OK");
        assert_eq!(format!("{}", ValidationStatus::NotFound), "Not Found (404)");
        assert_eq!(format!("{}", ValidationStatus::Timeout), "Timeout");
        assert_eq!(format!("{}", ValidationStatus::NetworkError), "Network Error");
    }

    #[test]
    fn test_validation_status_server_error_various_codes() {
        assert_eq!(format!("{}", ValidationStatus::ServerError(500)), "Server Error (500)");
        assert_eq!(format!("{}", ValidationStatus::ServerError(502)), "Server Error (502)");
        assert_eq!(format!("{}", ValidationStatus::ServerError(503)), "Server Error (503)");
        assert_eq!(format!("{}", ValidationStatus::ServerError(504)), "Server Error (504)");
        assert_eq!(format!("{}", ValidationStatus::ServerError(429)), "Server Error (429)");
    }

    #[test]
    fn test_validation_status_redirect_various_urls() {
        let s1 = ValidationStatus::Redirect("https://new.example.com".to_string());
        assert_eq!(format!("{}", s1), "Redirect -> https://new.example.com");

        let s2 = ValidationStatus::Redirect("".to_string());
        assert_eq!(format!("{}", s2), "Redirect -> ");

        let s3 = ValidationStatus::Redirect("/relative/path".to_string());
        assert!(format!("{}", s3).contains("/relative/path"));
    }

    // ── ValidationResult construction tests ────────────────────────────

    #[test]
    fn test_validation_result_ok_status() {
        let result = ValidationResult {
            domain: "test.com".to_string(),
            url: "https://test.com/subs".to_string(),
            status: ValidationStatus::Ok,
            response_time_ms: Some(42),
            error_message: None,
        };
        assert_eq!(result.domain, "test.com");
        assert_eq!(result.response_time_ms, Some(42));
        assert!(result.error_message.is_none());
        assert!(matches!(result.status, ValidationStatus::Ok));
    }

    #[test]
    fn test_validation_result_timeout_status() {
        let result = ValidationResult {
            domain: "slow.com".to_string(),
            url: "https://slow.com/page".to_string(),
            status: ValidationStatus::Timeout,
            response_time_ms: None,
            error_message: Some("Request timed out".to_string()),
        };
        assert!(matches!(result.status, ValidationStatus::Timeout));
        assert!(result.response_time_ms.is_none());
        assert_eq!(result.error_message.as_deref(), Some("Request timed out"));
    }

    #[test]
    fn test_validation_result_redirect_status() {
        let result = ValidationResult {
            domain: "old.com".to_string(),
            url: "https://old.com/subs".to_string(),
            status: ValidationStatus::Redirect("https://new.com/subs".to_string()),
            response_time_ms: Some(200),
            error_message: None,
        };
        if let ValidationStatus::Redirect(ref target) = result.status {
            assert_eq!(target, "https://new.com/subs");
        } else {
            panic!("Expected redirect status");
        }
    }

    #[test]
    fn test_validation_result_not_found_status() {
        let result = ValidationResult {
            domain: "gone.com".to_string(),
            url: "https://gone.com/page".to_string(),
            status: ValidationStatus::NotFound,
            response_time_ms: Some(50),
            error_message: None,
        };
        assert!(matches!(result.status, ValidationStatus::NotFound));
    }

    #[test]
    fn test_validation_result_server_error_status() {
        let result = ValidationResult {
            domain: "broken.com".to_string(),
            url: "https://broken.com/api".to_string(),
            status: ValidationStatus::ServerError(500),
            response_time_ms: Some(100),
            error_message: Some("Internal Server Error".to_string()),
        };
        if let ValidationStatus::ServerError(code) = result.status {
            assert_eq!(code, 500);
        } else {
            panic!("Expected server error status");
        }
    }

    #[test]
    fn test_validation_result_network_error_status() {
        let result = ValidationResult {
            domain: "unreachable.com".to_string(),
            url: "https://unreachable.com/subs".to_string(),
            status: ValidationStatus::NetworkError,
            response_time_ms: None,
            error_message: Some("Connection refused".to_string()),
        };
        assert!(matches!(result.status, ValidationStatus::NetworkError));
        assert!(result.response_time_ms.is_none());
    }

    // ── ValidationStatus Debug ─────────────────────────────────────────

    #[test]
    fn test_validation_status_debug() {
        let s = ValidationStatus::Ok;
        let debug_str = format!("{:?}", s);
        assert_eq!(debug_str, "Ok");

        let s2 = ValidationStatus::ServerError(503);
        let debug_str2 = format!("{:?}", s2);
        assert!(debug_str2.contains("503"));
    }

    #[test]
    fn test_validation_result_debug() {
        let result = ValidationResult {
            domain: "test.com".to_string(),
            url: "https://test.com".to_string(),
            status: ValidationStatus::Ok,
            response_time_ms: Some(100),
            error_message: None,
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("test.com"));
        assert!(debug_str.contains("100"));
    }

    // ── Async tests using tempdir for filesystem operations ────────────

    #[tokio::test]
    async fn test_list_cached_domains_with_temp_cache() {
        let tmpdir = tempfile::tempdir().unwrap();
        let cache_dir = tmpdir.path().join("cache");
        tokio::fs::create_dir_all(&cache_dir).await.unwrap();

        // Write a valid cache entry
        let entry = SubprocessorUrlCacheEntry {
            domain: "example.com".to_string(),
            working_subprocessor_url: "https://example.com/subprocessors".to_string(),
            last_successful_access: 1704067200,
            cache_version: 1,
            extraction_patterns: None,
            extraction_metadata: None,
            trust_center_strategy: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let cache_file = cache_dir.join("example.com.json");
        tokio::fs::write(&cache_file, &json).await.unwrap();

        // Verify the file was written correctly
        let content = tokio::fs::read_to_string(&cache_file).await.unwrap();
        let parsed: SubprocessorUrlCacheEntry = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.working_subprocessor_url, "https://example.com/subprocessors");
        assert_eq!(parsed.last_successful_access, 1704067200);
        assert_eq!(parsed.cache_version, 1);
    }

    #[tokio::test]
    async fn test_cache_entry_serialization_roundtrip() {
        let entry = SubprocessorUrlCacheEntry {
            domain: "test.org".to_string(),
            working_subprocessor_url: "https://test.org/vendors".to_string(),
            last_successful_access: 1718451000,
            cache_version: 2,
            extraction_patterns: None,
            extraction_metadata: None,
            trust_center_strategy: None,
        };

        let json = serde_json::to_string_pretty(&entry).unwrap();
        let deserialized: SubprocessorUrlCacheEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.domain, entry.domain);
        assert_eq!(deserialized.working_subprocessor_url, entry.working_subprocessor_url);
        assert_eq!(deserialized.last_successful_access, entry.last_successful_access);
        assert_eq!(deserialized.cache_version, entry.cache_version);
    }

    #[tokio::test]
    async fn test_cache_entry_invalid_json() {
        let result = serde_json::from_str::<SubprocessorUrlCacheEntry>("not json at all");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cache_entry_missing_fields() {
        let partial = r#"{"domain": "test.com"}"#;
        let result = serde_json::from_str::<SubprocessorUrlCacheEntry>(partial);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cache_dir_reading_empty_directory() {
        let tmpdir = tempfile::tempdir().unwrap();
        let cache_dir = tmpdir.path().join("cache");
        tokio::fs::create_dir_all(&cache_dir).await.unwrap();

        // Reading an empty cache directory should yield no entries
        let mut entries = tokio::fs::read_dir(&cache_dir).await.unwrap();
        let mut count = 0;
        while let Some(_) = entries.next_entry().await.unwrap() {
            count += 1;
        }
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_cache_dir_ignores_non_json_files() {
        let tmpdir = tempfile::tempdir().unwrap();
        let cache_dir = tmpdir.path().join("cache");
        tokio::fs::create_dir_all(&cache_dir).await.unwrap();

        // Write a non-JSON file
        tokio::fs::write(cache_dir.join("readme.txt"), "not a cache entry").await.unwrap();
        // Write a JSON file
        let entry = SubprocessorUrlCacheEntry {
            domain: "valid.com".to_string(),
            working_subprocessor_url: "https://valid.com/subs".to_string(),
            last_successful_access: 1000,
            cache_version: 1,
            extraction_patterns: None,
            extraction_metadata: None,
            trust_center_strategy: None,
        };
        tokio::fs::write(
            cache_dir.join("valid.com.json"),
            serde_json::to_string(&entry).unwrap(),
        ).await.unwrap();

        // Count JSON files only
        let mut entries = tokio::fs::read_dir(&cache_dir).await.unwrap();
        let mut json_count = 0;
        while let Some(e) = entries.next_entry().await.unwrap() {
            if e.path().extension().and_then(|s| s.to_str()) == Some("json") {
                json_count += 1;
            }
        }
        assert_eq!(json_count, 1);
    }

    #[tokio::test]
    async fn test_cache_multiple_entries_sorting() {
        // Verify that entries can be sorted by timestamp
        let entries = vec![
            ("b.com".to_string(), 100u64, "url-b".to_string()),
            ("a.com".to_string(), 300u64, "url-a".to_string()),
            ("c.com".to_string(), 200u64, "url-c".to_string()),
        ];

        let mut sorted = entries.clone();
        sorted.sort_by_key(|e| std::cmp::Reverse(e.1));

        assert_eq!(sorted[0].0, "a.com");  // 300 - most recent
        assert_eq!(sorted[1].0, "c.com");  // 200
        assert_eq!(sorted[2].0, "b.com");  // 100 - oldest
    }

    #[test]
    fn test_url_truncation_logic() {
        // Test the URL truncation logic from list_cached_domains
        let short_url = "https://short.com";
        let long_url = "https://very-long-domain-name-that-exceeds-forty-characters.com/subprocessors/list";

        let short_display = if short_url.len() > 40 {
            let mut end = 37;
            while end > 0 && !short_url.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &short_url[..end])
        } else {
            short_url.to_string()
        };
        assert_eq!(short_display, short_url);

        let long_display = if long_url.len() > 40 {
            let mut end = 37;
            while end > 0 && !long_url.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &long_url[..end])
        } else {
            long_url.to_string()
        };
        assert!(long_display.ends_with("..."));
        assert!(long_display.len() <= 40);
    }

    #[test]
    fn test_url_truncation_with_unicode() {
        // Ensure char boundary safety with non-ASCII URLs
        let unicode_url = "https://example.com/sub/\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}extra";
        if unicode_url.len() > 40 {
            let mut end = 37;
            while end > 0 && !unicode_url.is_char_boundary(end) {
                end -= 1;
            }
            let truncated = format!("{}...", &unicode_url[..end]);
            // Should not panic and should end with "..."
            assert!(truncated.ends_with("..."));
        }
    }

    #[test]
    fn test_domain_similarity_matching() {
        // Test the "similar domain" matching logic from show_cache_entry
        let search = "example";
        let cached_domains = vec!["example.com", "my-example.org", "test.com", "other.com"];

        let similar: Vec<_> = cached_domains
            .iter()
            .filter(|d| d.contains(search) || search.contains(*d))
            .collect();

        assert_eq!(similar.len(), 2);
        assert!(similar.contains(&&"example.com"));
        assert!(similar.contains(&&"my-example.org"));
    }

    #[test]
    fn test_domain_similarity_no_matches() {
        let search = "zzz-unknown";
        let cached_domains = vec!["example.com", "test.org"];

        let similar: Vec<_> = cached_domains
            .iter()
            .filter(|d| d.contains(search) || search.contains(*d))
            .collect();

        assert!(similar.is_empty());
    }

    #[test]
    fn test_domain_similarity_exact_match() {
        let search = "example.com";
        let cached_domains = vec!["example.com", "other.com"];

        let similar: Vec<_> = cached_domains
            .iter()
            .filter(|d| d.contains(search) || search.contains(*d))
            .collect();

        assert_eq!(similar.len(), 1);
        assert!(similar.contains(&&"example.com"));
    }
}
