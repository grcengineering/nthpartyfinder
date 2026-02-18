use nthpartyfinder::subprocessor::{SubprocessorAnalyzer, extract_vendor_domains_from_subprocessors};

#[tokio::test]
async fn test_subprocessor_url_generation() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("testdomain.com");
    
    // Should generate 25+ URLs based on common patterns
    assert!(urls.len() >= 25, "Should generate at least 25 URLs, got {}", urls.len());
    
    // Test specific patterns exist
    let expected_patterns = vec![
        "https://testdomain.com/subprocessors",
        "https://www.testdomain.com/subprocessors", 
        "https://testdomain.com/legal/subprocessors",
        "https://testdomain.com/privacy/subprocessors",
        "https://testdomain.com/trust/subprocessors",
        "https://testdomain.com/gdpr/subprocessors",
        "https://testdomain.com/vendors",
    ];
    
    for pattern in expected_patterns {
        assert!(urls.contains(&pattern.to_string()), 
                "Missing expected URL pattern: {}", pattern);
    }
}

#[tokio::test]
async fn test_domain_validation() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Valid domains
    let valid_domains = vec![
        "google.com",
        "sub.domain.io",
        "test-site.org",
        "cdn.assets.vendor.com",
        "valid-domain123.net",
    ];
    
    for domain in valid_domains {
        assert!(analyzer.is_valid_vendor_domain(domain), 
                "Should be valid: {}", domain);
    }
    
    // Invalid domains
    let invalid_domains = vec![
        "example.com",    // Placeholder
        "localhost",      // Local
        "test.com",       // Placeholder  
        "a",              // Too short
        "nodot",          // No dot
    ];
    
    for domain in invalid_domains {
        assert!(!analyzer.is_valid_vendor_domain(domain), 
                "Should be invalid: {}", domain);
    }
}

#[tokio::test]
async fn test_vendor_content_detection() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Should match vendor content
    let vendor_texts = vec![
        "Acme Inc. provides analytics services via acme.com",
        "XYZ Technologies LLC hosts our data at xyz-tech.io", 
        "Payment processing by Stripe Corporation at stripe.com",
        "Email services company sends via mailsender.net",
        "Cloud hosting platform available at cloudhost.org",
    ];
    
    for text in vendor_texts {
        assert!(analyzer.looks_like_vendor_content(text), 
                "Should detect vendor content: '{}'", text);
    }
    
    // Should not match non-vendor content
    let non_vendor_texts = vec![
        "This is just regular text without indicators",
        "Visit our blog for updates and news",
        "Contact us for more information about pricing",
        "Follow us on social media platforms",
    ];
    
    for text in non_vendor_texts {
        assert!(!analyzer.looks_like_vendor_content(text), 
                "Should not detect vendor content: '{}'", text);
    }
}

#[tokio::test]
async fn test_domain_extraction_valid_domains() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Test valid domains that should pass both extraction and validation
    let test_cases = vec![
        ("Visit our partner at stripe.com for more info", Some("stripe.com")),
        ("Contact support@sendgrid.io for help", Some("sendgrid.io")),
        ("Check out analytics-provider.net", Some("analytics-provider.net")),
        ("Our payment processor is paypal.com", Some("paypal.com")),
        ("Email services by mailgun.org", Some("mailgun.org")),
    ];
    
    for (text, expected) in test_cases {
        let result = analyzer.extract_domain_from_text(text);
        if let Some(ref expected_domain) = expected {
            if let Some(ref found_domain) = result {
                assert_eq!(found_domain, expected_domain, "Failed for text: '{}'", text);
            } else {
                panic!("Expected to find '{}' in text: '{}'", expected_domain, text);
            }
        }
    }
}

#[tokio::test]
async fn test_domain_extraction_filters_placeholders() {
    let analyzer = SubprocessorAnalyzer::new().await;

    // Test that placeholder domains are filtered out
    let test_cases = vec![
        "Visit example.com for testing",  // Should be filtered as placeholder
        "Email us at test@localhost",     // localhost should be filtered
        "Our site is yoursite.com",      // Generic placeholder
        "Contact domain.com support",    // Generic placeholder
    ];

    for text in test_cases {
        let result = analyzer.extract_domain_from_text(text);
        if let Some(domain) = result {
            assert!(!analyzer.is_valid_vendor_domain(&domain),
                    "Should have filtered out placeholder domain '{}' from text: '{}'", domain, text);
        }
    }
}

// =============================================================================
// F001: Enhanced URL Generation Tests
// =============================================================================

#[tokio::test]
async fn test_url_generation_includes_new_security_patterns() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("acme.com");

    // New security/compliance paths from F001 feature spec
    let security_patterns = vec![
        "https://acme.com/security/subprocessors",
        "https://www.acme.com/security/subprocessors",
        "https://acme.com/compliance/subprocessors",
        "https://www.acme.com/compliance/subprocessors",
        "https://acme.com/trust-center/subprocessors",
        "https://www.acme.com/trust-center/subprocessors",
    ];

    for pattern in security_patterns {
        assert!(urls.contains(&pattern.to_string()),
                "Missing security pattern: {}", pattern);
    }
}

#[tokio::test]
async fn test_url_generation_includes_legal_variations() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("acme.com");

    // Legal path variations from F001 feature spec
    let legal_patterns = vec![
        "https://acme.com/legal/subprocessors",
        "https://acme.com/legal/sub-processors",
        "https://www.acme.com/legal/subprocessors",
        "https://www.acme.com/legal/sub-processors",
        "https://acme.com/privacy/subprocessors",
        "https://www.acme.com/privacy/subprocessors",
    ];

    for pattern in legal_patterns {
        assert!(urls.contains(&pattern.to_string()),
                "Missing legal pattern: {}", pattern);
    }
}

#[tokio::test]
async fn test_url_generation_includes_data_processing_patterns() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("acme.com");

    // Data processing/GDPR paths from F001 feature spec
    let data_patterns = vec![
        "https://acme.com/data-processing/subprocessors",
        "https://www.acme.com/data-processing/subprocessors",
        "https://acme.com/gdpr/subprocessors",
        "https://www.acme.com/gdpr/subprocessors",
        "https://acme.com/data-security/subprocessors",
        "https://www.acme.com/data-security/subprocessors",
    ];

    for pattern in data_patterns {
        assert!(urls.contains(&pattern.to_string()),
                "Missing data processing pattern: {}", pattern);
    }
}

#[tokio::test]
async fn test_url_generation_includes_third_party_patterns() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("acme.com");

    // Third-party/vendor paths from F001 feature spec
    let third_party_patterns = vec![
        "https://acme.com/third-party/subprocessors",
        "https://www.acme.com/third-party/subprocessors",
        "https://acme.com/vendors",
        "https://www.acme.com/vendors",
        "https://acme.com/third-party-services",
        "https://www.acme.com/third-party-services",
    ];

    for pattern in third_party_patterns {
        assert!(urls.contains(&pattern.to_string()),
                "Missing third-party pattern: {}", pattern);
    }
}

#[tokio::test]
async fn test_url_generation_includes_html_suffixes() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("acme.com");

    // HTML file suffixes from F001 feature spec
    let html_patterns = vec![
        "https://acme.com/subprocessors.html",
        "https://www.acme.com/subprocessors.html",
        "https://acme.com/sub-processors.html",
        "https://www.acme.com/sub-processors.html",
    ];

    for pattern in html_patterns {
        assert!(urls.contains(&pattern.to_string()),
                "Missing HTML suffix pattern: {}", pattern);
    }
}

#[tokio::test]
async fn test_url_generation_includes_domain_specific_patterns() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("slack.com");

    // Domain-specific pattern: /{domain}-subprocessors
    // For slack.com, should generate /slack-subprocessors
    let domain_specific_patterns = vec![
        "https://slack.com/slack-subprocessors",
        "https://www.slack.com/slack-subprocessors",
    ];

    for pattern in domain_specific_patterns {
        assert!(urls.contains(&pattern.to_string()),
                "Missing domain-specific pattern: {}", pattern);
    }
}

#[tokio::test]
async fn test_url_generation_includes_data_sub_processors_pattern() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("acme.com");

    // data-sub-processors pattern from F001 feature spec
    let data_sub_patterns = vec![
        "https://acme.com/data-sub-processors",
        "https://www.acme.com/data-sub-processors",
    ];

    for pattern in data_sub_patterns {
        assert!(urls.contains(&pattern.to_string()),
                "Missing data-sub-processors pattern: {}", pattern);
    }
}

#[tokio::test]
async fn test_url_generation_trailing_slash_variations() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("acme.com");

    // Both with and without trailing slashes should be present for key patterns
    // Check that we have at least some trailing slash variants
    let trailing_slash_patterns = vec![
        "https://acme.com/policies/subprocessors/",
        "https://www.acme.com/policies/subprocessors/",
    ];

    for pattern in trailing_slash_patterns {
        assert!(urls.contains(&pattern.to_string()),
                "Missing trailing slash pattern: {}", pattern);
    }
}

#[tokio::test]
async fn test_url_generation_trust_subdomain_pattern() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("cursor.com");

    // Trust subdomain pattern (e.g., trust.cursor.com)
    assert!(urls.contains(&"https://trust.cursor.com/subprocessors".to_string()),
            "Missing trust subdomain pattern: https://trust.cursor.com/subprocessors");
}

#[tokio::test]
async fn test_url_generation_prioritizes_successful_patterns() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("testcompany.com");

    // High-priority patterns should appear early in the list
    // Based on successful cache hits, these patterns work most often:
    // - /legal/subprocessors
    // - /subprocessors
    // - /legal/service-providers

    // Find the index of known successful patterns
    let legal_subprocessors_idx = urls.iter().position(|u| u == "https://testcompany.com/legal/subprocessors");
    let root_subprocessors_idx = urls.iter().position(|u| u == "https://testcompany.com/subprocessors");

    // Both should exist
    assert!(legal_subprocessors_idx.is_some(), "Missing /legal/subprocessors pattern");
    assert!(root_subprocessors_idx.is_some(), "Missing /subprocessors pattern");

    // They should be in the first 15 URLs (high priority)
    assert!(legal_subprocessors_idx.unwrap() < 15,
            "/legal/subprocessors should be in first 15 URLs, but was at index {}",
            legal_subprocessors_idx.unwrap());
    assert!(root_subprocessors_idx.unwrap() < 15,
            "/subprocessors should be in first 15 URLs, but was at index {}",
            root_subprocessors_idx.unwrap());
}

#[tokio::test]
async fn test_url_generation_count_increased() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("testdomain.com");

    // With all the new patterns, we should generate significantly more URLs
    // Previous was ~70, new should be ~100+
    assert!(urls.len() >= 80,
            "Should generate at least 80 URLs for comprehensive coverage, got {}", urls.len());
}