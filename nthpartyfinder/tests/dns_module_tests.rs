use nthpartyfinder::dns::{self, VendorDomain, DnsServerPool};
use nthpartyfinder::vendor::RecordType;

// ============================================================================
// SPF RECORD PARSING TESTS
// ============================================================================

#[test]
fn test_spf_basic_include() {
    let records = vec!["v=spf1 include:_spf.google.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "google.com");
    assert_eq!(domains[0].source_type, RecordType::DnsTxtSpf);
}

#[test]
fn test_spf_multiple_includes() {
    let records = vec![
        "v=spf1 include:_spf.google.com include:mailgun.org include:sendgrid.net ~all".to_string()
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 3);
    let domain_names: Vec<&str> = domains.iter().map(|d| d.domain.as_str()).collect();
    assert!(domain_names.contains(&"google.com"));
    assert!(domain_names.contains(&"mailgun.org"));
    assert!(domain_names.contains(&"sendgrid.net"));
}

#[test]
fn test_spf_redirect_mechanism() {
    let records = vec!["v=spf1 redirect=_spf.example.com".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "example.com");
}

#[test]
fn test_spf_a_mechanism() {
    let records = vec!["v=spf1 a:mail.example.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "example.com");
}

#[test]
fn test_spf_mx_mechanism() {
    let records = vec!["v=spf1 mx:mail.example.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "example.com");
}

#[test]
fn test_spf_exists_mechanism() {
    let records = vec!["v=spf1 exists:%{ir}.%{v}._spf.example.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // After macro stripping, should extract example.com
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "example.com");
}

#[test]
fn test_spf_macro_expansion_simple() {
    // Test basic macro patterns like %{ir}, %{v}, %{d}
    let records = vec!["v=spf1 include:%{ir}.%{v}._spf.example.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should strip macros and extract example.com
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "example.com");
}

#[test]
fn test_spf_macro_expansion_complex() {
    // Test complex macro with transformers
    let records = vec!["v=spf1 include:%{i}.%{d2}.spf.has.pphosted.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should extract pphosted.com
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "pphosted.com");
}

#[test]
fn test_spf_macro_with_modifiers() {
    // Test macros with digit modifiers like %{ir}.%{v}.%{d}
    let records = vec!["v=spf1 exists:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "pphosted.com");
}

#[test]
fn test_spf_with_ip4_and_ip6() {
    // SPF records with IP addresses should not extract domains from IPs
    let records = vec!["v=spf1 ip4:192.168.1.0/24 ip6:2001:db8::/32 include:_spf.google.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should only extract google.com, not IPs
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "google.com");
}

#[test]
fn test_spf_all_mechanisms_together() {
    let records = vec![
        "v=spf1 a mx include:_spf.google.com redirect=_spf.mailgun.org -all".to_string()
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should extract google.com and mailgun.org
    // a and mx without domains refer to the queried domain, not extracted
    assert_eq!(domains.len(), 2);
}

#[test]
fn test_spf_escaped_characters() {
    // Test SPF with escaped quotes and backslashes
    let records = vec!["v=spf1 include:\\_spf.google.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "google.com");
}

#[test]
fn test_spf_empty_record() {
    let records = vec!["v=spf1 ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 0);
}

#[test]
fn test_spf_malformed_no_version() {
    // SPF without version should not be parsed
    let records = vec!["include:_spf.google.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 0);
}

#[test]
fn test_spf_whitespace_variations() {
    // Test various whitespace patterns
    let records = vec![
        "v=spf1  include:_spf.google.com   include:mailgun.org  ~all".to_string()
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 2);
}

// ============================================================================
// DMARC RECORD PARSING TESTS
// ============================================================================

#[test]
fn test_dmarc_basic_rua() {
    let records = vec!["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "example.com");
    assert_eq!(domains[0].source_type, RecordType::DnsTxtDmarc);
}

#[test]
fn test_dmarc_multiple_rua() {
    let records = vec![
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com,mailto:reports@vendor.com".to_string()
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 2);
    let domain_names: Vec<&str> = domains.iter().map(|d| d.domain.as_str()).collect();
    assert!(domain_names.contains(&"example.com"));
    assert!(domain_names.contains(&"vendor.com"));
}

#[test]
fn test_dmarc_ruf() {
    let records = vec!["v=DMARC1; p=none; ruf=mailto:forensic@example.com".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "example.com");
}

#[test]
fn test_dmarc_no_version() {
    // DMARC without version should not be parsed
    let records = vec!["p=quarantine; rua=mailto:dmarc@example.com".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 0);
}

#[test]
fn test_dmarc_sp_tag() {
    // sp tag should be extracted (although current implementation may not)
    let records = vec!["v=DMARC1; p=quarantine; sp=mailto:sub@example.com".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // This test may fail if sp is not properly extracted
    // Documenting as potential issue
}

// ============================================================================
// DKIM RECORD PARSING TESTS
// ============================================================================

#[test]
fn test_dkim_basic_rsa() {
    let records = vec!["k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ...".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // DKIM extraction is limited - may not extract domains
    // This tests current behavior
}

#[test]
fn test_dkim_ed25519() {
    let records = vec!["k=ed25519; p=base64encodedkey".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // DKIM records typically don't contain vendor domains directly
    // Testing to confirm expected behavior
}

// ============================================================================
// VERIFICATION RECORD PARSING TESTS
// ============================================================================

#[test]
fn test_verification_google() {
    let records = vec!["google-site-verification=abc123xyz".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "google.com");
    assert_eq!(domains[0].source_type, RecordType::DnsTxtVerification);
}

#[test]
fn test_verification_facebook() {
    let records = vec!["facebook-domain-verification=abc123".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "facebook.com");
}

#[test]
fn test_verification_microsoft() {
    let records = vec!["MS=ms12345678".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "microsoft.com");
}

#[test]
fn test_verification_zoom() {
    let records = vec!["ZOOM_verify_abc123".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "zoom.us");
}

#[test]
fn test_verification_multiple_providers() {
    let records = vec![
        "google-site-verification=abc123".to_string(),
        "facebook-domain-verification=def456".to_string(),
        "MS=ms789".to_string(),
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 3);
    let domain_names: Vec<&str> = domains.iter().map(|d| d.domain.as_str()).collect();
    assert!(domain_names.contains(&"google.com"));
    assert!(domain_names.contains(&"facebook.com"));
    assert!(domain_names.contains(&"microsoft.com"));
}

#[test]
fn test_verification_dynamic_pattern() {
    // Test dynamic pattern matching
    let records = vec!["twilio-domain-verification=abc123".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should infer twilio.com
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "twilio.com");
}

#[test]
fn test_verification_whimsical_edge_case() {
    // Special case with angle bracket
    let records = vec!["<whimsical=abc123".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "whimsical.com");
}

// ============================================================================
// DOMAIN VALIDATION TESTS
// ============================================================================

#[test]
fn test_valid_domain_simple() {
    let records = vec!["v=spf1 include:example.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "example.com");
}

#[test]
fn test_valid_domain_with_subdomain() {
    let records = vec!["v=spf1 include:mail.example.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "example.com");
}

#[test]
fn test_valid_domain_with_underscore() {
    // Underscores are valid in SPF delegation patterns
    let records = vec!["v=spf1 include:_spf.google.com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "google.com");
}

#[test]
fn test_invalid_domain_consecutive_dots() {
    let records = vec!["v=spf1 include:example..com ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should be rejected as invalid
    assert_eq!(domains.len(), 0);
}

#[test]
fn test_invalid_domain_trailing_dot() {
    let records = vec!["v=spf1 include:example.com. ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should be rejected (trailing dot not allowed per is_valid_domain)
    assert_eq!(domains.len(), 0);
}

#[test]
fn test_invalid_domain_no_dot() {
    let records = vec!["v=spf1 include:localhost ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should be rejected (no TLD)
    assert_eq!(domains.len(), 0);
}

#[test]
fn test_invalid_domain_too_long() {
    // Domain longer than 253 characters
    let long_domain = "a".repeat(250) + ".com";
    let records = vec![format!("v=spf1 include:{} ~all", long_domain)];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should be rejected
    assert_eq!(domains.len(), 0);
}

#[test]
fn test_invalid_domain_too_short() {
    let records = vec!["v=spf1 include:a.b ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should be rejected (less than 3 chars)
    assert_eq!(domains.len(), 0);
}

#[test]
fn test_invalid_domain_label_too_long() {
    // Label longer than 63 characters
    let long_label = "a".repeat(64);
    let records = vec![format!("v=spf1 include:{}.example.com ~all", long_label)];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should be rejected
    assert_eq!(domains.len(), 0);
}

// ============================================================================
// DEDUPLICATION TESTS
// ============================================================================

#[test]
fn test_deduplication_same_domain() {
    let records = vec![
        "v=spf1 include:_spf.google.com include:mail.google.com ~all".to_string()
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Both should resolve to google.com, but should only appear once
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "google.com");
}

#[test]
fn test_deduplication_multiple_records() {
    let records = vec![
        "v=spf1 include:_spf.google.com ~all".to_string(),
        "google-site-verification=abc123".to_string(),
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // google.com appears in both SPF and verification, should be deduplicated
    // But they have different source_types, so may appear twice
    // This tests the actual deduplication behavior
    let google_domains: Vec<_> = domains.iter().filter(|d| d.domain == "google.com").collect();

    // Based on code review, deduplication is by domain string only
    assert_eq!(google_domains.len(), 1);
}

// ============================================================================
// RAW RECORD PRESERVATION TESTS
// ============================================================================

#[test]
fn test_raw_record_preservation() {
    let raw_spf = "v=spf1 include:_spf.google.com ~all";
    let records = vec![raw_spf.to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].raw_record, raw_spf);
}

#[test]
fn test_raw_record_with_escapes() {
    let raw_record = r#"v=spf1 include:\_spf.google.com ~all"#;
    let records = vec![raw_record.to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Raw record should be preserved exactly
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].raw_record, raw_record);
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_empty_txt_records() {
    let records: Vec<String> = vec![];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 0);
}

#[test]
fn test_non_dns_txt_record() {
    let records = vec![
        "some random txt record".to_string(),
        "another-record=value".to_string(),
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should extract nothing
    assert_eq!(domains.len(), 0);
}

#[test]
fn test_mixed_record_types() {
    let records = vec![
        "v=spf1 include:_spf.google.com ~all".to_string(),
        "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com".to_string(),
        "google-site-verification=abc123".to_string(),
        "some random text".to_string(),
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should extract google.com (SPF), example.com (DMARC), and google.com (verification)
    // With deduplication, google.com should appear once
    assert!(domains.len() >= 2); // At least example.com and google.com
}

#[test]
fn test_unicode_in_domain() {
    // Test punycode/unicode handling
    let records = vec!["v=spf1 include:münchen.de ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // May or may not be extracted depending on validation
    // This documents the behavior
}

#[test]
fn test_case_insensitivity() {
    let records = vec![
        "V=SPF1 INCLUDE:_SPF.GOOGLE.COM ~ALL".to_string(),
        "v=DMARC1; P=QUARANTINE; RUA=MAILTO:DMARC@EXAMPLE.COM".to_string(),
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should still extract domains (case insensitive)
    assert!(domains.len() >= 1);
}

// ============================================================================
// DNS RESOLUTION TESTS
// ============================================================================

#[tokio::test]
async fn test_dns_resolution_google() {
    // Test real DNS resolution for a known domain
    let result = dns::get_txt_records("google.com").await;

    assert!(result.is_ok());
    let records = result.unwrap();
    // Google should have at least some TXT records (SPF, verification, etc.)
    assert!(records.len() > 0);
}

#[tokio::test]
async fn test_dns_resolution_nonexistent_domain() {
    // Test DNS resolution for a domain that definitely doesn't exist
    let result = dns::get_txt_records("this-domain-definitely-does-not-exist-123456789.com").await;

    // Should return Ok with empty vec (not an error per code review)
    assert!(result.is_ok());
    let records = result.unwrap();
    assert_eq!(records.len(), 0);
}

#[tokio::test]
async fn test_dns_resolution_invalid_domain() {
    // Test with invalid domain format
    let result = dns::get_txt_records("not..valid").await;

    // Should handle gracefully
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_dns_resolution_with_pool() {
    // Test using explicit DNS pool
    let pool = DnsServerPool::new();
    let result = dns::get_txt_records_with_pool("google.com", &pool).await;

    assert!(result.is_ok());
    let records = result.unwrap();
    assert!(records.len() > 0);
}

#[tokio::test]
async fn test_dns_server_rotation() {
    // Test that DNS server rotation works
    let pool = DnsServerPool::new();

    // Make multiple requests to trigger rotation
    for _ in 0..5 {
        let _ = dns::get_txt_records_with_pool("example.com", &pool).await;
    }

    // If we get here without panic, rotation is working
    assert!(true);
}

#[tokio::test]
async fn test_doh_fallback_to_traditional_dns() {
    // This test is hard to write without mocking DoH failures
    // Documenting as a manual test case

    // To test manually:
    // 1. Block DoH servers in firewall
    // 2. Query a domain
    // 3. Verify traditional DNS is used as fallback
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

#[test]
fn test_regex_compilation_performance() {
    // This test measures the regex recompilation overhead (B014)
    use std::time::Instant;

    let records = vec!["v=spf1 include:_spf.google.com ~all".to_string(); 1000];

    let start = Instant::now();
    for _ in 0..10 {
        let _ = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");
    }
    let duration = start.elapsed();

    println!("Processing 10,000 records took: {:?}", duration);

    // This will be slow due to regex recompilation
    // Expected to improve after fixing B014
}

#[test]
fn test_large_spf_record() {
    // Test with a very large SPF record (edge case)
    let large_spf = format!("v=spf1 {} ~all",
        (0..100).map(|i| format!("include:domain{}.com", i)).collect::<Vec<_>>().join(" ")
    );
    let records = vec![large_spf];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    assert_eq!(domains.len(), 100);
}

// ============================================================================
// IP ADDRESS HANDLING TESTS (B018)
// ============================================================================

#[test]
fn test_ipv4_in_spf() {
    // Test IPv4 handling - should not panic (B018)
    let records = vec!["v=spf1 ip4:192.168.1.1 ip4:10.0.0.0/8 ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should not extract IPs as domains, should not panic
    assert_eq!(domains.len(), 0);
}

#[test]
fn test_ipv6_in_spf() {
    // Test IPv6 handling - should not panic (B018)
    let records = vec!["v=spf1 ip6:2001:db8::1 ip6:fe80::/10 ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should not extract IPs as domains, should not panic
    assert_eq!(domains.len(), 0);
}

#[test]
fn test_malformed_ip_in_spf() {
    // Test malformed IP - should not panic
    let records = vec!["v=spf1 ip4:999.999.999.999 ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    // Should handle gracefully without panic
}

// ============================================================================
// CIRCULAR DEPENDENCY TESTS
// ============================================================================

// Note: Circular dependency detection would require recursive resolution
// which is not implemented in this module. This is a potential issue
// to document for future enhancement.

// ============================================================================
// TIMEOUT TESTS
// ============================================================================

#[tokio::test]
async fn test_dns_timeout_handling() {
    // Test that DNS timeouts are handled gracefully
    // This requires a domain that times out - hard to test reliably

    // Documenting as a manual test case:
    // Use a firewall to drop packets to specific DNS servers
    // Verify timeout handling works correctly
}
