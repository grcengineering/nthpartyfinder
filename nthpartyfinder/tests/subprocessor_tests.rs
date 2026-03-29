use nthpartyfinder::subprocessor::{SubprocessorAnalyzer, extract_vendor_domains_from_subprocessors, is_valid_tld, is_valid_org_name};

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

#[tokio::test]
async fn test_trust_subdomain_url_generation() {
    let analyzer = SubprocessorAnalyzer::new().await;

    // When domain IS a trust subdomain, should NOT generate trust.trust.{domain} URLs
    let urls = analyzer.generate_subprocessor_urls("trust.vanta.com");
    let has_double_trust = urls.iter().any(|u| u.contains("trust.trust."));
    assert!(!has_double_trust,
            "Should NOT generate double-trust URLs, but found: {:?}",
            urls.iter().filter(|u| u.contains("trust.trust.")).collect::<Vec<_>>());

    // Should have the correct URL as one of the first entries
    assert!(urls.iter().any(|u| u == "https://trust.vanta.com/subprocessors"),
            "Should include https://trust.vanta.com/subprocessors in URL list");

    // First URL should be the trust center's own subprocessor page
    assert!(urls[0] == "https://trust.vanta.com/subprocessors",
            "First URL should be the trust subdomain's subprocessor page, got: {}", urls[0]);
}

#[tokio::test]
async fn test_vanta_com_still_generates_correct_urls() {
    let analyzer = SubprocessorAnalyzer::new().await;
    let urls = analyzer.generate_subprocessor_urls("vanta.com");

    // vanta.com should still get the hardcoded trust.vanta.com URL
    assert!(urls.iter().any(|u| u == "https://trust.vanta.com/subprocessors"),
            "vanta.com should include trust.vanta.com/subprocessors");

    // Should also include trust.vanta.com pattern from generic trust subdomain patterns
    assert!(urls.iter().any(|u| u.starts_with("https://trust.vanta.com")),
            "vanta.com should include trust.vanta.com patterns");
}

#[test]
fn test_is_valid_tld_rejects_fake_tlds() {
    // These are false positive TLDs from extraction garbage
    assert!(!is_valid_tld("truncated"), "Should reject 'truncated' TLD");
    assert!(!is_valid_tld("xm"), "Should reject 'xm' TLD");
    assert!(!is_valid_tld("yfc"), "Should reject 'yfc' TLD");
    assert!(!is_valid_tld("mui"), "Should reject 'mui' TLD");
}

#[test]
fn test_is_valid_tld_accepts_real_tlds() {
    // Common valid TLDs
    assert!(is_valid_tld("com"), "Should accept 'com'");
    assert!(is_valid_tld("org"), "Should accept 'org'");
    assert!(is_valid_tld("net"), "Should accept 'net'");
    assert!(is_valid_tld("io"), "Should accept 'io'");
    assert!(is_valid_tld("co"), "Should accept 'co'");
    assert!(is_valid_tld("ai"), "Should accept 'ai'");
    assert!(is_valid_tld("dev"), "Should accept 'dev'");
    assert!(is_valid_tld("app"), "Should accept 'app'");

    // Country code TLDs
    assert!(is_valid_tld("uk"), "Should accept 'uk'");
    assert!(is_valid_tld("de"), "Should accept 'de'");
    assert!(is_valid_tld("jp"), "Should accept 'jp'");
    assert!(is_valid_tld("us"), "Should accept 'us'");

    // Less common but valid
    assert!(is_valid_tld("email"), "Should accept 'email'");
    assert!(is_valid_tld("cloud"), "Should accept 'cloud'");
}
#[tokio::test]
#[ignore] // Requires network access to Vanta API; run with: cargo test -- --ignored
async fn test_vanta_graphql_from_html() {
    // Minimal Vanta trust center HTML with required data attributes
    let vanta_html = r#"<!doctype html>
<html data-signature-manifest-url="https://assets.vanta.com/static/signature-manifest.a48acf2deafa086b8892d65f28bd1a9c0ecb5223.json">
<head data-slugid="jr8w9ljcrpzfh88hb34qo"></head>
<body><script src="https://assets.vanta.com/static/index.fcb463e0.js"></script></body>
</html>"#;

    let analyzer = SubprocessorAnalyzer::new().await;
    let results = analyzer.try_vanta_graphql_from_html(vanta_html).await;
    assert!(results.is_some(), "Vanta GraphQL strategy should return results for Vanta trust center HTML");
    let results = results.unwrap();
    assert!(results.len() > 10, "Should find at least 10 Vanta subprocessors, found {}", results.len());

    // Verify no false positives like _org:encrypt_data
    for r in &results {
        if r.domain.starts_with("_org:") {
            let org_name = r.domain.strip_prefix("_org:").unwrap();
            assert!(!org_name.contains("encrypt"), "Should not have false positive org: {}", r.domain);
            assert!(!org_name.contains("penetration"), "Should not have false positive org: {}", r.domain);
        } else {
            // Domain results should not have fake TLDs
            if let Some(tld) = r.domain.rsplit('.').next() {
                assert!(is_valid_tld(tld), "Invalid TLD in domain {}", r.domain);
            }
        }
    }

    // Verify we get well-known Vanta subprocessors
    let domains: Vec<&str> = results.iter().map(|r| r.domain.as_str()).collect();
    assert!(domains.iter().any(|d| d.contains("amazon")), "Should find AWS: {:?}", domains);
}

#[test]
fn test_org_name_validation() {
    // Valid org names
    assert!(is_valid_org_name("GitHub, Inc."));
    assert!(is_valid_org_name("Amazon Web Services, Inc."));
    assert!(is_valid_org_name("Cloudflare"));
    assert!(is_valid_org_name("Elasticsearch, Inc."));
    assert!(is_valid_org_name("New Relic"));
    assert!(is_valid_org_name("Anthropic PBC"));

    // Invalid: too long (concatenated table rows)
    assert!(!is_valid_org_name(
        "AI Inference and AI Services United States United States Anthropic PBC AI Inference and AI Services United States United States Cloudflare Content delivery service United States United States Elasticsearch, Inc."
    ));

    // Invalid: contains location/country markers
    assert!(!is_valid_org_name("Factor Authentication United States United States xAI"));
    assert!(!is_valid_org_name("Some Company United Kingdom Processing"));

    // Invalid: contains table header phrases
    assert!(!is_valid_org_name("Third Party Subprocessors Name of Subprocessor Description of Processing"));
    assert!(!is_valid_org_name("Location of Processing Corporate Location GitHub"));

    // Invalid: too many words
    assert!(!is_valid_org_name("This Is Way Too Many Words For A Real Organization Name To Have In Practice"));

    // Invalid: too short
    assert!(!is_valid_org_name("AB"));
    assert!(!is_valid_org_name(""));

    // Edge cases: valid short names
    assert!(is_valid_org_name("IBM"));
    assert!(is_valid_org_name("xAI"));
    assert!(is_valid_org_name("Duo Security"));

    // "America, Inc." is structurally valid as an org name (13 chars, 2 words).
    // The regex fix prevents it from being extracted in the first place — the old
    // greedy regex matched "...America, Inc." from mid-table-row, but the fixed
    // regex with [a-zA-Z ]{2,50} won't cross row boundaries.
    assert!(is_valid_org_name("America, Inc."), "Structurally valid org name format");
}

#[test]
fn test_org_regex_prevents_table_row_gobbling() {
    // The fixed regex should NOT match across table row boundaries
    let fixed_regex = regex::Regex::new(
        r"(?:^|[\s>])([A-Z][a-zA-Z ]{2,50}(?:,?\s*(?:Inc|LLC|Corp|Ltd)\.?))"
    ).unwrap();

    // Simulated plain text from github.com subprocessor page (table rows joined by spaces)
    let table_text = "AI Inference and AI Services United States United States Anthropic PBC AI Inference and AI Services United States United States Cloudflare Content delivery service United States United States Elasticsearch, Inc.";

    let matches: Vec<&str> = fixed_regex.captures_iter(table_text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim()))
        .collect();

    // Should NOT produce a 200+ char match spanning the whole text
    for m in &matches {
        assert!(m.len() <= 60, "Regex match too long ({}): '{}'", m.len(), m);
    }

    // Should extract individual company names, not concatenated rows
    let good_text = "GitHub, Inc. provides hosting services. Amazon Web Services, Inc. provides cloud.";
    let good_matches: Vec<&str> = fixed_regex.captures_iter(good_text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim()))
        .collect();

    // Should find reasonable individual matches
    for m in &good_matches {
        assert!(m.len() <= 60, "Good match too long: '{}'", m);
        assert!(m.len() >= 3, "Good match too short: '{}'", m);
    }
}
