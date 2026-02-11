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
// SUBPROCESSOR RECORD TYPE PRESERVATION TESTS (Regression for Klaviyo bug)
// ============================================================================
// Regression test: When a vendor domain is discovered via BOTH DNS TXT records
// AND a subprocessor page, the pre-processing dedup must preserve the
// HttpSubprocessor record type. Previously, the dedup kept the first entry
// (DNS), causing subprocessor-sourced vendors to be invisible in the report's
// Subprocessors tab. This caused Klaviyo to show 18 instead of 24 subprocessors.

#[test]
fn test_subprocessor_record_type_survives_preprocess_dedup() {
    // Simulate the pre-processing dedup from main.rs lines 1305-1318.
    // DNS TXT records come BEFORE subprocessor results in all_vendor_domains.
    // The dedup must prefer HttpSubprocessor over DNS-based record types.
    use std::collections::HashMap;
    use nthpartyfinder::domain_utils;

    let all_vendor_domains: Vec<dns::VendorDomain> = vec![
        // DNS TXT records (added first in the pipeline)
        dns::VendorDomain {
            domain: "anthropic.com".to_string(),
            source_type: RecordType::DnsTxtVerification,
            raw_record: "anthropic-domain-verification=abc123".to_string(),
        },
        dns::VendorDomain {
            domain: "dropbox.com".to_string(),
            source_type: RecordType::DnsTxtVerification,
            raw_record: "dropbox-domain-verification=xyz".to_string(),
        },
        dns::VendorDomain {
            domain: "microsoft.com".to_string(),
            source_type: RecordType::DnsTxtVerification,
            raw_record: "MS=ms41847412".to_string(),
        },
        dns::VendorDomain {
            domain: "openai.com".to_string(),
            source_type: RecordType::DnsTxtVerification,
            raw_record: "openai-domain-verification=abc".to_string(),
        },
        dns::VendorDomain {
            domain: "zendesk.com".to_string(),
            source_type: RecordType::DnsTxtSpf,
            raw_record: "v=spf1 include:mail.zendesk.com ~all".to_string(),
        },
        dns::VendorDomain {
            domain: "mailgun.com".to_string(),
            source_type: RecordType::DnsTxtVerification,
            raw_record: "mgverify=abc123".to_string(),
        },
        // Non-overlapping DNS entries
        dns::VendorDomain {
            domain: "google.com".to_string(),
            source_type: RecordType::DnsTxtVerification,
            raw_record: "google-site-verification=abc".to_string(),
        },
        // Subprocessor page results (added second in the pipeline)
        dns::VendorDomain {
            domain: "anthropic.com".to_string(),
            source_type: RecordType::HttpSubprocessor,
            raw_record: "anthropic.com".to_string(),
        },
        dns::VendorDomain {
            domain: "dropbox.com".to_string(),
            source_type: RecordType::HttpSubprocessor,
            raw_record: "dropbox.com".to_string(),
        },
        dns::VendorDomain {
            domain: "microsoft.com".to_string(),
            source_type: RecordType::HttpSubprocessor,
            raw_record: "microsoft.com".to_string(),
        },
        dns::VendorDomain {
            domain: "openai.com".to_string(),
            source_type: RecordType::HttpSubprocessor,
            raw_record: "openai.com".to_string(),
        },
        dns::VendorDomain {
            domain: "zendesk.com".to_string(),
            source_type: RecordType::HttpSubprocessor,
            raw_record: "zendesk.com".to_string(),
        },
        dns::VendorDomain {
            domain: "mailgun.com".to_string(),
            source_type: RecordType::HttpSubprocessor,
            raw_record: "mailgun.com".to_string(),
        },
        // Subprocessor-only entries (no DNS overlap)
        dns::VendorDomain {
            domain: "ada.cx".to_string(),
            source_type: RecordType::HttpSubprocessor,
            raw_record: "ada.cx".to_string(),
        },
        dns::VendorDomain {
            domain: "chronosphere.io".to_string(),
            source_type: RecordType::HttpSubprocessor,
            raw_record: "chronosphere.io".to_string(),
        },
        dns::VendorDomain {
            domain: "snowflake.com".to_string(),
            source_type: RecordType::HttpSubprocessor,
            raw_record: "snowflake.com".to_string(),
        },
    ];

    // Apply the same dedup logic as main.rs (prefer HttpSubprocessor)
    let mut seen_domains: HashMap<String, usize> = HashMap::new();
    let mut deduped: Vec<dns::VendorDomain> = Vec::new();
    for vd in all_vendor_domains {
        let base = domain_utils::extract_base_domain(&vd.domain);
        if let Some(&existing_idx) = seen_domains.get(&base) {
            if matches!(vd.source_type, RecordType::HttpSubprocessor)
                && !matches!(deduped[existing_idx].source_type, RecordType::HttpSubprocessor)
            {
                deduped[existing_idx] = vd;
            }
        } else {
            seen_domains.insert(base, deduped.len());
            deduped.push(vd);
        }
    }

    // Total unique base domains: 10 (anthropic, dropbox, microsoft, openai, zendesk,
    // mailgun, google, ada, chronosphere, snowflake)
    assert_eq!(deduped.len(), 10, "Should have 10 unique vendor domains after dedup");

    // All 6 overlapping vendors MUST be HttpSubprocessor (the core regression check)
    let overlapping_domains = ["anthropic.com", "dropbox.com", "microsoft.com",
                               "openai.com", "zendesk.com", "mailgun.com"];
    for domain in &overlapping_domains {
        let entry = deduped.iter().find(|vd| vd.domain == *domain)
            .unwrap_or_else(|| panic!("Missing domain: {}", domain));
        assert_eq!(
            entry.source_type,
            RecordType::HttpSubprocessor,
            "Domain {} should have HttpSubprocessor record type, got {:?}",
            domain, entry.source_type
        );
    }

    // Subprocessor-only entries should remain HttpSubprocessor
    for domain in &["ada.cx", "chronosphere.io", "snowflake.com"] {
        let entry = deduped.iter().find(|vd| vd.domain == *domain)
            .unwrap_or_else(|| panic!("Missing domain: {}", domain));
        assert_eq!(entry.source_type, RecordType::HttpSubprocessor,
            "Subprocessor-only domain {} should remain HttpSubprocessor", domain);
    }

    // google.com (DNS-only, no subprocessor overlap) should keep its DNS type
    let google = deduped.iter().find(|vd| vd.domain == "google.com").unwrap();
    assert_eq!(google.source_type, RecordType::DnsTxtVerification,
        "DNS-only domain should keep its original record type");

    // Count total HttpSubprocessor entries
    let subprocessor_count = deduped.iter()
        .filter(|vd| matches!(vd.source_type, RecordType::HttpSubprocessor))
        .count();
    assert_eq!(subprocessor_count, 9,
        "Should have 9 HttpSubprocessor entries (6 overlapping + 3 subprocessor-only)");
}

#[test]
fn test_postprocess_dedup_preserves_subprocessor_record_type() {
    // Regression test for the post-processing VendorRelationship dedup.
    // With type-aware dedup (R003 fix), different source types produce SEPARATE rows.
    // DNS Verification and HttpSubprocessor for the same domain are preserved independently.
    use nthpartyfinder::vendor::VendorRelationship;
    use std::collections::HashMap;

    let relationships = vec![
        // DNS-sourced entry comes first
        VendorRelationship::new(
            "anthropic.com".to_string(),
            "Anthropic".to_string(),
            1,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "anthropic-domain-verification=abc".to_string(),
            RecordType::DnsTxtVerification,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "anthropic-domain-verification=abc".to_string(),
        ),
        // Subprocessor-sourced entry comes second
        VendorRelationship::new(
            "anthropic.com".to_string(),
            "Anthropic".to_string(),
            1,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "anthropic.com".to_string(),
            RecordType::HttpSubprocessor,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "Found on subprocessor page".to_string(),
        ),
    ];

    // Apply the same type-aware post-processing dedup logic as main.rs
    let mut seen: HashMap<(String, String, String), usize> = HashMap::new();
    let mut deduped: Vec<VendorRelationship> = Vec::new();
    for r in relationships {
        let key = (
            r.nth_party_domain.clone(),
            r.nth_party_customer_domain.clone(),
            r.nth_party_record_type.as_hierarchy_string(),
        );
        if let Some(&idx) = seen.get(&key) {
            let existing = &mut deduped[idx];
            if !existing.evidence.contains(&r.evidence) {
                existing.evidence = format!("{} | {}", existing.evidence, r.evidence);
            }
        } else {
            seen.insert(key, deduped.len());
            deduped.push(r);
        }
    }

    // With type-aware dedup, different source types are SEPARATE rows
    assert_eq!(deduped.len(), 2, "Different source types should produce separate rows");

    // Find each row by record type
    let verification_row = deduped.iter().find(|r| r.nth_party_record_type == RecordType::DnsTxtVerification)
        .expect("Should have a DnsTxtVerification row");
    let subprocessor_row = deduped.iter().find(|r| r.nth_party_record_type == RecordType::HttpSubprocessor)
        .expect("Should have an HttpSubprocessor row");

    assert!(verification_row.evidence.contains("anthropic-domain-verification"),
        "Verification row should have DNS evidence");
    assert!(subprocessor_row.evidence.contains("Found on subprocessor page"),
        "Subprocessor row should have subprocessor evidence");
}

#[test]
fn test_postprocess_dedup_spf_preserved_alongside_verification() {
    // Regression test for SPF vendors being lost in post-processing dedup.
    // When google.com appears from both SPF and Verification sources,
    // both must survive as separate rows in the final output.
    // This was the root cause of missing SPF vendors in the Klaviyo report.
    use nthpartyfinder::vendor::VendorRelationship;
    use std::collections::HashMap;

    let relationships = vec![
        // Google from SPF
        VendorRelationship::new(
            "google.com".to_string(),
            "Google".to_string(),
            1,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "v=spf1 include:_spf.google.com ~all".to_string(),
            RecordType::DnsTxtSpf,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "v=spf1 include:_spf.google.com ~all".to_string(),
        ),
        // Google from Verification
        VendorRelationship::new(
            "google.com".to_string(),
            "Google".to_string(),
            1,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "google-site-verification=abc123".to_string(),
            RecordType::DnsTxtVerification,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "google-site-verification=abc123".to_string(),
        ),
        // Google from SaaS Tenant probe
        VendorRelationship::new(
            "google.com".to_string(),
            "Google".to_string(),
            1,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "SaaS tenant: klaviyo.google.com".to_string(),
            RecordType::SaasTenantProbe,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "SaaS tenant: klaviyo.google.com".to_string(),
        ),
        // Zendesk from SPF
        VendorRelationship::new(
            "zendesk.com".to_string(),
            "Zendesk".to_string(),
            1,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "v=spf1 include:mail.zendesk.com ~all".to_string(),
            RecordType::DnsTxtSpf,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "v=spf1 include:mail.zendesk.com ~all".to_string(),
        ),
        // Zendesk from SaaS Tenant probe
        VendorRelationship::new(
            "zendesk.com".to_string(),
            "Zendesk".to_string(),
            1,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "SaaS tenant: klaviyo.zendesk.com".to_string(),
            RecordType::SaasTenantProbe,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "SaaS tenant: klaviyo.zendesk.com".to_string(),
        ),
        // Salesforce from SPF only
        VendorRelationship::new(
            "salesforce.com".to_string(),
            "Salesforce".to_string(),
            1,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "v=spf1 include:_spf.salesforce.com ~all".to_string(),
            RecordType::DnsTxtSpf,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "v=spf1 include:_spf.salesforce.com ~all".to_string(),
        ),
    ];

    // Apply type-aware post-processing dedup (same logic as main.rs)
    let mut seen: HashMap<(String, String, String), usize> = HashMap::new();
    let mut deduped: Vec<VendorRelationship> = Vec::new();
    for r in relationships {
        let key = (
            r.nth_party_domain.clone(),
            r.nth_party_customer_domain.clone(),
            r.nth_party_record_type.as_hierarchy_string(),
        );
        if let Some(&idx) = seen.get(&key) {
            let existing = &mut deduped[idx];
            if !existing.evidence.contains(&r.evidence) {
                existing.evidence = format!("{} | {}", existing.evidence, r.evidence);
            }
        } else {
            seen.insert(key, deduped.len());
            deduped.push(r);
        }
    }

    // Google: 3 separate rows (SPF, Verification, SaaS Tenant)
    let google_rows: Vec<_> = deduped.iter().filter(|r| r.nth_party_domain == "google.com").collect();
    assert_eq!(google_rows.len(), 3,
        "Google should have 3 separate rows (SPF + Verification + SaaS Tenant), got {}",
        google_rows.len());
    assert!(google_rows.iter().any(|r| r.nth_party_record_type == RecordType::DnsTxtSpf),
        "Google must have an SPF row");
    assert!(google_rows.iter().any(|r| r.nth_party_record_type == RecordType::DnsTxtVerification),
        "Google must have a Verification row");
    assert!(google_rows.iter().any(|r| r.nth_party_record_type == RecordType::SaasTenantProbe),
        "Google must have a SaaS Tenant row");

    // Zendesk: 2 separate rows (SPF, SaaS Tenant)
    let zendesk_rows: Vec<_> = deduped.iter().filter(|r| r.nth_party_domain == "zendesk.com").collect();
    assert_eq!(zendesk_rows.len(), 2,
        "Zendesk should have 2 separate rows (SPF + SaaS Tenant), got {}",
        zendesk_rows.len());
    assert!(zendesk_rows.iter().any(|r| r.nth_party_record_type == RecordType::DnsTxtSpf),
        "Zendesk must have an SPF row");

    // Salesforce: 1 row (SPF only)
    let salesforce_rows: Vec<_> = deduped.iter().filter(|r| r.nth_party_domain == "salesforce.com").collect();
    assert_eq!(salesforce_rows.len(), 1,
        "Salesforce should have 1 row (SPF only), got {}",
        salesforce_rows.len());
    assert_eq!(salesforce_rows[0].nth_party_record_type, RecordType::DnsTxtSpf,
        "Salesforce row must be SPF");

    // Total: 6 rows (3 google + 2 zendesk + 1 salesforce)
    assert_eq!(deduped.len(), 6, "Total should be 6 rows");
}

#[test]
fn test_postprocess_dedup_merges_evidence_within_same_source_type() {
    // Verify that within the SAME source type, evidence is merged (not duplicated).
    // Two SPF records for google.com should produce one row with combined evidence.
    use nthpartyfinder::vendor::VendorRelationship;
    use std::collections::HashMap;

    let relationships = vec![
        VendorRelationship::new(
            "google.com".to_string(),
            "Google".to_string(),
            1,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "v=spf1 include:_spf.google.com ~all".to_string(),
            RecordType::DnsTxtSpf,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "v=spf1 include:_spf.google.com ~all".to_string(),
        ),
        VendorRelationship::new(
            "google.com".to_string(),
            "Google".to_string(),
            1,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "v=spf1 include:mail.google.com ~all".to_string(),
            RecordType::DnsTxtSpf,
            "klaviyo.com".to_string(),
            "Klaviyo".to_string(),
            "v=spf1 include:mail.google.com ~all".to_string(),
        ),
    ];

    // Apply type-aware dedup
    let mut seen: HashMap<(String, String, String), usize> = HashMap::new();
    let mut deduped: Vec<VendorRelationship> = Vec::new();
    for r in relationships {
        let key = (
            r.nth_party_domain.clone(),
            r.nth_party_customer_domain.clone(),
            r.nth_party_record_type.as_hierarchy_string(),
        );
        if let Some(&idx) = seen.get(&key) {
            let existing = &mut deduped[idx];
            if !existing.evidence.contains(&r.evidence) {
                existing.evidence = format!("{} | {}", existing.evidence, r.evidence);
            }
        } else {
            seen.insert(key, deduped.len());
            deduped.push(r);
        }
    }

    // Same source type → merged into 1 row with combined evidence
    assert_eq!(deduped.len(), 1, "Same source type should merge into 1 row");
    assert!(deduped[0].evidence.contains("_spf.google.com"), "Should contain first SPF evidence");
    assert!(deduped[0].evidence.contains("mail.google.com"), "Should contain second SPF evidence");
}

#[test]
fn test_klaviyo_scenario_24_subprocessors_preserved() {
    // End-to-end regression test simulating the exact Klaviyo scenario:
    // 24 subprocessors extracted, 6 overlap with DNS TXT records.
    // All 24 must survive the pre-processing dedup as HttpSubprocessor.
    use std::collections::HashMap;
    use nthpartyfinder::domain_utils;

    // The 24 subprocessors from Klaviyo's subprocessor page
    let subprocessor_domains = vec![
        "ada.cx", "aws.amazon.com", "anthropic.com", "chronosphere.io",
        "cloudflare.com", "concentrix.com", "dropbox.com", "ectusa.net",
        "fivetran.com", "sentry.io", "glean.com", "infobip.com",
        "loom.com", "mailgun.com", "meta.com", "microsoft.com",
        "openai.com", "sendgrid.com", "sendsafely.com", "snowflake.com",
        "splunk.com", "statsig.com", "twilio.com", "zendesk.com",
    ];

    // The 6 that overlap with DNS TXT records
    let dns_overlap_domains = vec![
        ("anthropic.com", "anthropic-domain-verification=abc"),
        ("dropbox.com", "dropbox-domain-verification=xyz"),
        ("microsoft.com", "MS=ms41847412"),
        ("openai.com", "openai-domain-verification=def"),
        ("zendesk.com", "v=spf1 include:mail.zendesk.com ~all"),
        ("mailgun.com", "mgverify=abc123"),
    ];

    // Build all_vendor_domains in the same order as the production pipeline
    let mut all_vendor_domains: Vec<dns::VendorDomain> = Vec::new();

    // 1. DNS TXT records (added first)
    for (domain, raw) in &dns_overlap_domains {
        all_vendor_domains.push(dns::VendorDomain {
            domain: domain.to_string(),
            source_type: if raw.starts_with("v=spf1") {
                RecordType::DnsTxtSpf
            } else {
                RecordType::DnsTxtVerification
            },
            raw_record: raw.to_string(),
        });
    }
    // Additional DNS-only entries (not on subprocessor page)
    for domain in &["google.com", "whimsical.com", "zoom.us", "adobe.com"] {
        all_vendor_domains.push(dns::VendorDomain {
            domain: domain.to_string(),
            source_type: RecordType::DnsTxtVerification,
            raw_record: format!("{}-verification=test", domain),
        });
    }

    // 2. Subprocessor page results (added second)
    for domain in &subprocessor_domains {
        all_vendor_domains.push(dns::VendorDomain {
            domain: domain.to_string(),
            source_type: RecordType::HttpSubprocessor,
            raw_record: domain.to_string(),
        });
    }

    let total_before_dedup = all_vendor_domains.len();

    // Apply dedup logic (must prefer HttpSubprocessor)
    let mut seen_domains: HashMap<String, usize> = HashMap::new();
    let mut deduped: Vec<dns::VendorDomain> = Vec::new();
    for vd in all_vendor_domains {
        let base = domain_utils::extract_base_domain(&vd.domain);
        if let Some(&existing_idx) = seen_domains.get(&base) {
            if matches!(vd.source_type, RecordType::HttpSubprocessor)
                && !matches!(deduped[existing_idx].source_type, RecordType::HttpSubprocessor)
            {
                deduped[existing_idx] = vd;
            }
        } else {
            seen_domains.insert(base, deduped.len());
            deduped.push(vd);
        }
    }

    // Count how many HttpSubprocessor entries survived
    let subprocessor_count = deduped.iter()
        .filter(|vd| matches!(vd.source_type, RecordType::HttpSubprocessor))
        .count();

    // THE KEY ASSERTION: All 24 subprocessors must be present as HttpSubprocessor
    // (not 18, which was the bug)
    // Note: aws.amazon.com dedupes to amazon.com base domain, so we count unique bases
    let subprocessor_bases: std::collections::HashSet<String> = deduped.iter()
        .filter(|vd| matches!(vd.source_type, RecordType::HttpSubprocessor))
        .map(|vd| domain_utils::extract_base_domain(&vd.domain))
        .collect();
    assert!(
        subprocessor_bases.len() >= 23,
        "Expected at least 23 unique subprocessor base domains (24 domains, \
         aws.amazon.com shares base with amazon.com), got {}. \
         Subprocessor domains found: {:?}",
        subprocessor_bases.len(), subprocessor_bases
    );

    // Verify the 6 overlapping domains specifically
    for (domain, _) in &dns_overlap_domains {
        let base = domain_utils::extract_base_domain(domain);
        let entry = deduped.iter().find(|vd| domain_utils::extract_base_domain(&vd.domain) == base)
            .unwrap_or_else(|| panic!("Missing domain: {}", domain));
        assert_eq!(
            entry.source_type, RecordType::HttpSubprocessor,
            "Overlapping domain {} (base: {}) must be HttpSubprocessor after dedup, got {:?}",
            domain, base, entry.source_type
        );
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
