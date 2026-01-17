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
        "a.b.c.d.com",
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