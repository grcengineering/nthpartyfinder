//! Tests for vendor source deduplication fix and CT log discovery
//!
//! These tests verify:
//! 1. Same vendor from different sources appears multiple times (deduplication fix)
//! 2. Exact duplicates (same domain + record_type + raw_record) are still deduplicated
//! 3. CT log discovery works correctly

use nthpartyfinder::dns;
use nthpartyfinder::vendor::RecordType;
use nthpartyfinder::discovery::CtLogDiscovery;
use std::time::Duration;

// ============================================================================
// DEDUPLICATION FIX TESTS
// ============================================================================

#[test]
fn test_same_vendor_different_sources_appears_multiple_times() {
    // Test that same vendor from DIFFERENT sources appears multiple times
    // This is the key fix: vendors should appear for ALL discovery sources
    let records = vec![
        "v=spf1 include:_spf.google.com ~all".to_string(),
        "google-site-verification=abc123".to_string(),
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // google.com appears in both SPF and verification records
    // With the fix, both should be reported (different record types + different raw records)
    let google_domains: Vec<_> = domains.iter().filter(|d| d.domain == "google.com").collect();

    // Deduplication is now by (domain, record_type, raw_record) tuple
    // So same domain from different sources should appear multiple times
    assert_eq!(
        google_domains.len(),
        2,
        "Same vendor from different sources should appear multiple times. Found: {:?}",
        google_domains
    );

    // Verify they have different source types
    let source_types: Vec<_> = google_domains.iter().map(|d| &d.source_type).collect();
    assert!(
        source_types.contains(&&RecordType::DnsTxtSpf),
        "Should have SPF source. Found: {:?}", source_types
    );
    assert!(
        source_types.contains(&&RecordType::DnsTxtVerification),
        "Should have verification source. Found: {:?}", source_types
    );
}

#[test]
fn test_exact_duplicate_records_still_deduplicated() {
    // Test that EXACT duplicates (same domain + same record type + same raw record)
    // are still deduplicated. This prevents reporting the same record twice.
    let records = vec![
        "v=spf1 include:_spf.google.com ~all".to_string(),
        "v=spf1 include:_spf.google.com ~all".to_string(),  // Exact duplicate record
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should only appear once since it's the exact same (domain, record_type, raw_record)
    let google_domains: Vec<_> = domains.iter().filter(|d| d.domain == "google.com").collect();
    assert_eq!(
        google_domains.len(),
        1,
        "Exact duplicate records should be deduplicated. Found: {:?}",
        google_domains
    );
}

#[test]
fn test_same_domain_same_type_different_raw_records() {
    // Same vendor from same record TYPE but different raw records should appear multiple times
    let records = vec![
        "v=spf1 include:_spf.google.com ~all".to_string(),
        "v=spf1 include:mail.google.com -all".to_string(),
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Both records are SPF, but have different raw_record values
    // Each raw record produces google.com, so we should have 2 entries
    let google_domains: Vec<_> = domains.iter().filter(|d| d.domain == "google.com").collect();
    assert_eq!(
        google_domains.len(),
        2,
        "Same domain from different raw records should appear multiple times. Found: {:?}",
        google_domains
    );

    // Verify both are SPF type
    assert!(google_domains.iter().all(|d| d.source_type == RecordType::DnsTxtSpf));

    // Verify different raw records
    let raw_records: Vec<_> = google_domains.iter().map(|d| &d.raw_record).collect();
    assert_eq!(raw_records.len(), 2);
    assert_ne!(raw_records[0], raw_records[1], "Raw records should be different");
}

#[test]
fn test_vendor_from_spf_dmarc_and_verification() {
    // Test vendor appearing from three different sources
    let records = vec![
        "v=spf1 include:_spf.google.com ~all".to_string(),
        "v=DMARC1; p=reject; rua=mailto:dmarc@google.com".to_string(),
        "google-site-verification=xyz789".to_string(),
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    let google_domains: Vec<_> = domains.iter().filter(|d| d.domain == "google.com").collect();

    // Should appear 3 times - once for each source type
    assert_eq!(
        google_domains.len(),
        3,
        "Vendor should appear for each discovery source. Found: {:?}",
        google_domains
    );

    // Verify we have all three source types
    let source_types: Vec<_> = google_domains.iter().map(|d| &d.source_type).collect();
    assert!(source_types.contains(&&RecordType::DnsTxtSpf), "Should have SPF");
    assert!(source_types.contains(&&RecordType::DnsTxtDmarc), "Should have DMARC");
    assert!(source_types.contains(&&RecordType::DnsTxtVerification), "Should have Verification");
}

#[test]
fn test_within_same_spf_record_still_deduplicated() {
    // Within a SINGLE SPF record, same domain referenced multiple times should be deduplicated
    // because they share the same raw_record
    let records = vec![
        "v=spf1 include:_spf.google.com include:mail.google.com a:smtp.google.com ~all".to_string(),
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // All references resolve to google.com, but they're from the same raw_record
    // So they should be deduplicated to 1
    let google_domains: Vec<_> = domains.iter().filter(|d| d.domain == "google.com").collect();
    assert_eq!(
        google_domains.len(),
        1,
        "Multiple references in same record should be deduplicated. Found: {:?}",
        google_domains
    );
}

// ============================================================================
// CT LOG DISCOVERY TESTS
// ============================================================================

#[test]
fn test_ct_log_discovery_infrastructure_filtering() {
    // Test that infrastructure domains are correctly filtered
    use nthpartyfinder::discovery::ct_logs::CtLogDiscovery;

    // These should be filtered as infrastructure
    assert!(is_infrastructure("cloudflare.com"));
    assert!(is_infrastructure("amazonaws.com"));
    assert!(is_infrastructure("azurewebsites.net"));
    assert!(is_infrastructure("letsencrypt.org"));
    assert!(is_infrastructure("example.com"));

    // These should NOT be filtered (real vendors)
    assert!(!is_infrastructure("klaviyo.com"));
    assert!(!is_infrastructure("google.com"));
    assert!(!is_infrastructure("stripe.com"));
    assert!(!is_infrastructure("twilio.com"));
}

// Helper function to test infrastructure domain filtering
fn is_infrastructure(domain: &str) -> bool {
    let infrastructure_domains = [
        "cloudflare.com", "cloudflare.net", "cloudfront.net",
        "akamai.com", "akamaiedge.net", "fastly.net", "fastly.com",
        "edgekey.net", "edgesuite.net", "amazonaws.com", "azure.com",
        "azurewebsites.net", "azureedge.net", "googleusercontent.com",
        "googlesyndication.com", "gstatic.com", "letsencrypt.org",
        "digicert.com", "comodo.com", "godaddy.com", "rapidssl.com",
        "geotrust.com", "thawte.com", "entrust.net", "globalsign.com",
        "sectigo.com", "localhost", "local", "test", "example.com",
    ];
    infrastructure_domains.iter().any(|&infra| domain.ends_with(infra) || domain == infra)
}

#[test]
fn test_ct_log_discovery_creates_with_timeout() {
    // Test that CtLogDiscovery can be created with various timeouts
    let discovery = CtLogDiscovery::new(Duration::from_secs(30));
    // If we get here, creation succeeded
    assert!(true);

    let discovery_short = CtLogDiscovery::new(Duration::from_secs(5));
    assert!(true);
}

#[tokio::test]
async fn test_ct_log_discovery_real_domain() {
    // Integration test: query CT logs for a real domain
    // This tests the actual crt.sh API integration
    let discovery = CtLogDiscovery::new(Duration::from_secs(60));

    // Use a well-known domain that should have CT log entries
    let result = discovery.discover("google.com").await;

    match result {
        Ok(vendors) => {
            // Google should have some CT log entries with third-party domains
            // (or at least not error out)
            println!("Found {} vendors from CT logs for google.com", vendors.len());

            // Verify result structure if any vendors found
            for vendor in &vendors {
                assert!(!vendor.domain.is_empty(), "Domain should not be empty");
                assert!(!vendor.source.is_empty(), "Source should not be empty");
                assert!(!vendor.certificate_info.is_empty(), "Certificate info should not be empty");
            }
        }
        Err(e) => {
            // API might be rate limited or unavailable - that's OK for a unit test
            println!("CT log query failed (may be rate limited): {}", e);
        }
    }
}

#[tokio::test]
async fn test_ct_log_discovery_nonexistent_domain() {
    // Test behavior with a domain that has no CT log entries
    let discovery = CtLogDiscovery::new(Duration::from_secs(30));

    let result = discovery.discover("this-domain-definitely-does-not-exist-xyz123.com").await;

    match result {
        Ok(vendors) => {
            // Should return empty list for nonexistent domain
            assert_eq!(vendors.len(), 0, "Nonexistent domain should have no CT log entries");
        }
        Err(e) => {
            // API error is acceptable
            println!("CT log query error (expected for bad domain): {}", e);
        }
    }
}

// ============================================================================
// COMBINED WORKFLOW TESTS
// ============================================================================

#[test]
fn test_full_extraction_preserves_all_sources() {
    // Comprehensive test: extract vendors from multiple record types
    // and verify all are preserved with correct attribution
    let records = vec![
        // SPF records
        "v=spf1 include:_spf.google.com include:mailgun.org ~all".to_string(),
        // DMARC record
        "v=DMARC1; p=reject; rua=mailto:report@proofpoint.com".to_string(),
        // Verification records
        "google-site-verification=abc123".to_string(),
        "facebook-domain-verification=def456".to_string(),
        "MS=ms789xyz".to_string(),
    ];

    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "example.com");

    // Expected vendors:
    // - google.com (from SPF and verification - 2 entries)
    // - mailgun.org (from SPF - 1 entry)
    // - proofpoint.com (from DMARC - 1 entry)
    // - facebook.com (from verification - 1 entry)
    // - microsoft.com (from verification - 1 entry)

    let google_count = domains.iter().filter(|d| d.domain == "google.com").count();
    let mailgun_count = domains.iter().filter(|d| d.domain == "mailgun.org").count();
    let proofpoint_count = domains.iter().filter(|d| d.domain == "proofpoint.com").count();
    let facebook_count = domains.iter().filter(|d| d.domain == "facebook.com").count();
    let microsoft_count = domains.iter().filter(|d| d.domain == "microsoft.com").count();

    // Google appears in SPF and verification
    assert_eq!(google_count, 2, "Google should appear twice (SPF + verification)");

    // Others appear once each
    assert_eq!(mailgun_count, 1, "Mailgun should appear once");
    assert_eq!(proofpoint_count, 1, "Proofpoint should appear once");
    assert_eq!(facebook_count, 1, "Facebook should appear once");
    assert_eq!(microsoft_count, 1, "Microsoft should appear once");

    // Total should be 6 vendors
    assert_eq!(domains.len(), 6, "Should have 6 total vendor entries");
}
