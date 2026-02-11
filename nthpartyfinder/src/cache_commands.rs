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
                    if let Ok(cache_entry) = serde_json::from_str::<SubprocessorUrlCacheEntry>(&content) {
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
    domains.sort_by(|a, b| b.1.cmp(&a.1));

    println!("Cached Domains ({} total):", domains.len());
    println!("{}", "=".repeat(80));
    println!("{:<40} {:<25} {}", "Domain", "Last Accessed", "URL");
    println!("{}", "-".repeat(80));

    for (domain, timestamp, url) in domains {
        let last_accessed = if timestamp > 0 {
            format_timestamp(timestamp)
        } else {
            "Unknown".to_string()
        };

        // Truncate URL if too long
        let url_display = if url.len() > 40 {
            format!("{}...", &url[..37])
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
            println!("Last Accessed: {}", format_timestamp(entry.last_successful_access));
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
                    println!("  Entity Header Patterns: {:?}", patterns.entity_header_patterns);
                }
                if let Some(ref rules) = patterns.custom_extraction_rules {
                    println!("  Custom Extraction Rules:");
                    if !rules.direct_selectors.is_empty() {
                        println!("    Direct Selectors: {:?}", rules.direct_selectors);
                    }
                    if !rules.custom_regex_patterns.is_empty() {
                        println!("    Custom Regex Patterns: {} patterns", rules.custom_regex_patterns.len());
                        for pattern in &rules.custom_regex_patterns {
                            println!("      - {} (capture group: {})",
                                &pattern.description,
                                pattern.capture_group);
                        }
                    }
                    if let Some(ref handling) = rules.special_handling {
                        if handling.skip_generic_methods {
                            println!("    Skip Generic Methods: true");
                        }
                        if !handling.exclusion_patterns.is_empty() {
                            println!("    Exclusion Patterns: {} patterns", handling.exclusion_patterns.len());
                        }
                    }
                }
                println!();
            }

            if let Some(ref metadata) = entry.extraction_metadata {
                println!("Extraction Metadata:");
                println!("  Successful Extractions: {}", metadata.successful_extractions);
                if let Some(col_idx) = metadata.successful_entity_column_index {
                    println!("  Entity Column Index: {}", col_idx);
                }
                if let Some(ref pattern) = metadata.successful_header_pattern {
                    println!("  Successful Header Pattern: {}", pattern);
                }
                println!("  Last Extraction Time: {}", format_timestamp(metadata.last_extraction_time));

                if let Some(ref adaptive) = metadata.adaptive_patterns {
                    println!("  Adaptive Patterns:");
                    println!("    Confidence Score: {:.2}", adaptive.confidence_score);
                    println!("    Validation Count: {}", adaptive.validation_count);
                    println!("    Discovery Time: {}", format_timestamp(adaptive.discovery_timestamp));
                    println!("    Discovered Selectors: {} selectors", adaptive.discovered_selectors.len());
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
                    if let Ok(cache_entry) = serde_json::from_str::<SubprocessorUrlCacheEntry>(&content) {
                        if !cache_entry.working_subprocessor_url.is_empty() {
                            urls_to_validate.push((domain.to_string(), cache_entry.working_subprocessor_url));
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
            println!("{:<12} {:<40} {} ({}ms)",
                status_indicator,
                result.domain,
                result.url,
                result.response_time_ms.unwrap_or(0));

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
        assert_eq!(format!("{}", ValidationStatus::NetworkError), "Network Error");
        assert_eq!(format!("{}", ValidationStatus::ServerError(500)), "Server Error (500)");
        assert_eq!(format!("{}", ValidationStatus::ServerError(503)), "Server Error (503)");
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
}
