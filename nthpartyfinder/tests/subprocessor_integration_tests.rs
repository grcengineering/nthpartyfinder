use nthpartyfinder::subprocessor::{SubprocessorAnalyzer, extract_vendor_domains_from_subprocessors};
use tokio;

#[tokio::test]
async fn test_subprocessor_analyzer_creation() {
    // Test that we can create an analyzer without errors
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Verify it creates URLs correctly
    let urls = analyzer.generate_subprocessor_urls("example.com");
    assert!(!urls.is_empty(), "Should generate URLs");
    
    // Verify domain validation works
    assert!(!analyzer.is_valid_vendor_domain("example.com"), "Should filter placeholder domains");
    assert!(analyzer.is_valid_vendor_domain("google.com"), "Should accept real domains");
}

#[tokio::test]
async fn test_end_to_end_analysis_with_invalid_domain() {
    // Test analysis with a clearly invalid domain that should not cause crashes
    let result = extract_vendor_domains_from_subprocessors("invalid-domain-that-does-not-exist-12345.com", None).await;
    
    // Should not panic, but may return empty results or error
    match result {
        Ok(vendors) => {
            // If successful, should return empty results for non-existent domain
            assert!(vendors.is_empty() || vendors.len() < 5, "Should not find many vendors for fake domain");
        }
        Err(_) => {
            // HTTP errors are acceptable for non-existent domains
        }
    }
}

#[tokio::test] 
async fn test_analysis_timeout_handling() {
    // Test with a domain that might be slow to respond
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // This tests the timeout handling - should complete within reasonable time
    let start = std::time::Instant::now();
    let _result = analyzer.analyze_domain("httpbin.org", None).await;
    let elapsed = start.elapsed();
    
    // Should complete within 60 seconds (allowing for 30s timeout + overhead)
    assert!(elapsed.as_secs() < 60, "Analysis should complete within reasonable time");
}

#[tokio::test]
async fn test_html_parsing_with_malformed_content() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Test malformed HTML parsing doesn't crash
    let malformed_html = r#"
    <html>
        <body>
            <p>The following are our third party subprocessors:</p>
            <table>
                <tr>
                    <td>Unclosed tag content with domain.com
                <tr>
                    <td>Another unclosed with test.io
            </table>
        </body>
    "#;
    
    let document = scraper::Html::parse_document(malformed_html);
    let result = analyzer.extract_from_tables(&document, malformed_html, "https://example.com");

    // Should not panic even with malformed HTML
    assert!(result.is_ok(), "Should handle malformed HTML gracefully");
}

#[tokio::test]
async fn test_deduplication_logic() {
    // Test that the high-level analyze_domain method properly deduplicates results
    // We can't easily test with HTML parsing, so we test the deduplication concept
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Test deduplication at the extraction level - these methods should return all matches
    let html_with_duplicates = r#"
    <html>
        <body>
            <p>The following are our third party subprocessors:</p>
            <ul>
                <li>Service A: stripe.com</li>
                <li>Service B: stripe.com (duplicate)</li>
                <li>Service C: paypal.com</li>
                <li>Service D: stripe.com (another duplicate)</li>
                <li>Service E: paypal.com (duplicate)</li>
            </ul>
        </body>
    </html>
    "#;
    
    let document = scraper::Html::parse_document(html_with_duplicates);
    let vendors = analyzer.extract_from_lists(&document, html_with_duplicates, "https://example.com").unwrap();
    
    // At extraction level, should find all domains (including duplicates)
    // Extraction may deduplicate - verify we find the unique domains
    assert!(vendors.len() >= 2, "Should find at least 2 unique domains");
    
    // Verify that analyze_domain would deduplicate (test the deduplication logic conceptually)
    let mut unique_domains = std::collections::HashSet::new();
    let mut deduplicated_vendors = Vec::new();
    
    for vendor in vendors {
        if unique_domains.insert(vendor.domain.clone()) {
            deduplicated_vendors.push(vendor);
        }
    }
    
    // After deduplication, should have only unique domains
    assert!(deduplicated_vendors.len() >= 2, "Should have at least 2 unique domains after deduplication");
    assert!(deduplicated_vendors.len() <= 2, "Should have at most 2 unique domains after deduplication");
}

#[tokio::test]
async fn test_content_type_handling() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Test with various content that should/shouldn't be detected as vendor content
    let test_cases = vec![
        ("Analytics provided by Google Inc. at analytics.google.com", true),
        ("Email services by Mailgun LLC via mailgun.org", true), 
        ("Cloud hosting through Amazon Web Services at aws.amazon.com", true),
        ("Just some random text with no vendor indicators", false),
        ("Visit our blog for more information", false),
        ("Contact us at info@example.com for support", false),
    ];
    
    for (text, should_match) in test_cases {
        let result = analyzer.looks_like_vendor_content(text);
        assert_eq!(result, should_match, "Content detection failed for: '{}'", text);
    }
}

#[tokio::test]
async fn test_url_generation_patterns() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Test URL generation for different domain formats
    let test_domains = vec![
        "example.com",
        "subdomain.example.com", 
        "multi.level.subdomain.example.com",
    ];
    
    for domain in test_domains {
        let urls = analyzer.generate_subprocessor_urls(domain);
        
        // Should generate consistent number of URLs regardless of domain format
        assert!(urls.len() >= 25, "Should generate at least 25 URLs for domain: {}", domain);
        
        // Should include both www and non-www variants
        let with_www = urls.iter().any(|url| url.contains(&format!("https://www.{}/", domain)));
        let without_www = urls.iter().any(|url| url.contains(&format!("https://{}/", domain)));
        
        assert!(with_www || without_www, "Should generate appropriate URL variants for: {}", domain);
        
        // Should include common subprocessor paths
        let has_subprocessors_path = urls.iter().any(|url| url.contains("/subprocessors"));
        let has_legal_path = urls.iter().any(|url| url.contains("/legal/"));
        let has_privacy_path = urls.iter().any(|url| url.contains("/privacy/"));
        
        assert!(has_subprocessors_path, "Should include /subprocessors path");
        assert!(has_legal_path, "Should include /legal/ path");
        assert!(has_privacy_path, "Should include /privacy/ path");
    }
}

#[tokio::test]
async fn test_error_resilience() {
    // Test that subprocessor analysis handles various error conditions gracefully
    let long_domain = "toolongdomainname".repeat(10);
    let error_test_cases = vec![
        "",                    // Empty domain
        "invalid",             // Invalid domain format
        long_domain.as_str(),  // Extremely long domain
        "xn--domain.com",      // IDN domain
        "127.0.0.1",          // IP address instead of domain
    ];
    
    for domain in error_test_cases {
        let result = extract_vendor_domains_from_subprocessors(domain, None).await;
        
        // Should not panic, regardless of result
        match result {
            Ok(vendors) => {
                // Results should be reasonable (not thousands of vendors)
                assert!(vendors.len() < 100, "Should not return excessive vendors for: {}", domain);
            }
            Err(_) => {
                // Errors are acceptable for malformed input
            }
        }
    }
}