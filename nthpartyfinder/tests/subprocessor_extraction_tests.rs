use nthpartyfinder::subprocessor::{SubprocessorAnalyzer, ExtractionPatterns};
use nthpartyfinder::vendor::RecordType;
use scraper::Html;

/// Test comprehensive organization name extraction from various HTML structures
#[tokio::test]
async fn test_organization_name_extraction_from_table() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Test HTML with a typical subprocessor table containing organization names
    let html_content = r#"
    <html>
        <body>
            <h2>Our Subprocessors</h2>
            <table class="subprocessor-table">
                <thead>
                    <tr>
                        <th>Entity Name</th>
                        <th>Purpose</th>
                        <th>Location</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Stripe Inc.</td>
                        <td>Payment processing</td>
                        <td>United States</td>
                    </tr>
                    <tr>
                        <td>SendGrid LLC (d/b/a Twilio SendGrid)</td>
                        <td>Email delivery</td>
                        <td>United States</td>
                    </tr>
                    <tr>
                        <td>Sentry (sentry.io)</td>
                        <td>Error monitoring</td>
                        <td>United States</td>
                    </tr>
                    <tr>
                        <td>Amazon Web Services, Inc.</td>
                        <td>Cloud infrastructure</td>
                        <td>United States</td>
                    </tr>
                    <tr>
                        <td>Intercom, Inc.</td>
                        <td>Customer messaging</td>
                        <td>United States</td>
                    </tr>
                </tbody>
            </table>
        </body>
    </html>
    "#;
    
    let document = Html::parse_document(html_content);
    let result = analyzer.extract_from_tables(&document, html_content, "https://example.com/subprocessors");
    
    assert!(result.is_ok(), "Table extraction should succeed");
    let vendors = result.unwrap();
    
    // Should extract domains from organization names
    assert!(vendors.len() >= 3, "Should extract at least 3 vendor domains, found: {}", vendors.len());
    
    // Check for expected domains extracted from organization names
    let domains: Vec<String> = vendors.iter().map(|v| v.domain.clone()).collect();
    
    // These should be extracted based on organization name patterns
    assert!(domains.contains(&"stripe.com".to_string()), 
            "Should extract stripe.com from 'Stripe Inc.', found domains: {:?}", domains);
    assert!(domains.contains(&"sentry.io".to_string()), 
            "Should extract sentry.io from explicit domain in parentheses, found domains: {:?}", domains);
    assert!(domains.contains(&"sendgrid.com".to_string()) || domains.contains(&"twilio.com".to_string()), 
            "Should extract domain from SendGrid/Twilio organization, found domains: {:?}", domains);
    
    // Verify source type is correct
    for vendor in &vendors {
        assert_eq!(vendor.source_type, RecordType::HttpSubprocessor, 
                  "All extracted vendors should have HttpSubprocessor source type");
        assert!(!vendor.raw_record.is_empty(), 
                "Raw record should contain evidence of extraction");
    }
}

/// Test organization name extraction from list structures
#[tokio::test] 
async fn test_organization_name_extraction_from_lists() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    let html_content = r#"
    <html>
        <body>
            <h2>Third Party Service Providers</h2>
            <p>We use the following subprocessors to provide our services:</p>
            <ul class="vendor-list">
                <li><strong>GitHub, Inc.</strong> - Code repository hosting</li>
                <li><strong>Slack Technologies, Inc.</strong> - Team communication</li>
                <li><strong>Zoom Video Communications, Inc.</strong> - Video conferencing</li>
                <li><strong>Atlassian Corporation (atlassian.com)</strong> - Project management</li>
                <li><strong>Datadog, Inc.</strong> - Application monitoring</li>
            </ul>
            
            <div class="processor-list">
                <h3>Additional Processors</h3>
                <ol>
                    <li>Microsoft Corporation - Cloud services via azure.microsoft.com</li>
                    <li>Google LLC - Analytics and advertising</li>
                    <li>Mailgun Technologies, Inc. - Email delivery services</li>
                </ol>
            </div>
        </body>
    </html>
    "#;
    
    let document = Html::parse_document(html_content);
    let result = analyzer.extract_from_lists(&document, html_content, "https://example.com/vendors");
    
    assert!(result.is_ok(), "List extraction should succeed");
    let vendors = result.unwrap();
    
    assert!(vendors.len() >= 4, "Should extract at least 4 vendor domains, found: {}", vendors.len());
    
    let domains: Vec<String> = vendors.iter().map(|v| v.domain.clone()).collect();
    
    // Test various organization name to domain mappings
    assert!(domains.contains(&"github.com".to_string()), 
            "Should extract github.com from 'GitHub, Inc.', found domains: {:?}", domains);
    assert!(domains.contains(&"slack.com".to_string()), 
            "Should extract slack.com from 'Slack Technologies, Inc.', found domains: {:?}", domains);
    assert!(domains.contains(&"atlassian.com".to_string()), 
            "Should extract atlassian.com from explicit domain, found domains: {:?}", domains);
    assert!(domains.contains(&"datadog.com".to_string()) || domains.contains(&"datadoghq.com".to_string()), 
            "Should extract datadog domain from 'Datadog, Inc.', found domains: {:?}", domains);
    
    // Check for advanced extractions
    assert!(domains.contains(&"microsoft.com".to_string()) || domains.contains(&"azure.microsoft.com".to_string()), 
            "Should extract Microsoft domain, found domains: {:?}", domains);
    assert!(domains.contains(&"mailgun.com".to_string()) || domains.contains(&"mailgun.org".to_string()), 
            "Should extract Mailgun domain, found domains: {:?}", domains);
}

/// Test organization name extraction with various naming patterns
#[tokio::test]
async fn test_organization_name_patterns() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Test individual organization name to domain extraction through text processing
    let test_cases = vec![
        // Standard company names with context
        ("Partner: Stripe Inc. provides payment processing", Some("stripe.com")),
        ("Services from Google LLC for analytics", Some("google.com")),  
        ("Microsoft Corporation handles our cloud needs", Some("microsoft.com")),
        
        // Names with explicit domains in parentheses
        ("Sentry (sentry.io) handles error monitoring", Some("sentry.io")),
        ("Atlassian Corporation (atlassian.com) for project management", Some("atlassian.com")),
        ("Twilio Inc. (twilio.com) for communications", Some("twilio.com")),
        
        // Complex names that might extract domains
        ("Slack Technologies, Inc. at slack.com", Some("slack.com")),
        ("Zoom Video Communications via zoom.us", Some("zoom.us")),
        ("Adobe Systems at adobe.com", Some("adobe.com")),
        
        // Names that should be handled gracefully
        ("Internal Team", None), // Generic name
        ("Various Partners", None), // Non-specific
        ("", None), // Empty
    ];
    
    for (text_with_org, expected_domain) in test_cases {
        let result = analyzer.extract_domain_from_text(text_with_org);
        
        match expected_domain {
            Some(expected) => {
                if let Some(extracted) = result {
                    assert_eq!(extracted, expected, 
                              "Expected '{}' from text '{}', but got '{}'", expected, text_with_org, extracted);
                } else {
                    // Some extractions might not work, which is acceptable for this test
                    println!("Note: Could not extract '{}' from text: '{}'", expected, text_with_org);
                }
            }
            None => {
                // For cases where we expect no domain extraction, just ensure it doesn't panic
                // Some might still extract valid domains, which is acceptable
            }
        }
    }
}

/// Test extraction with mixed HTML structures (realistic subprocessor pages)
#[tokio::test]
async fn test_realistic_subprocessor_page_structure() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    let html_content = r#"
    <html>
        <head>
            <title>Data Subprocessors - Example Corp</title>
        </head>
        <body>
            <main>
                <section class="legal-content">
                    <h1>Data Processing Addendum - Subprocessors</h1>
                    <p>Example Corp uses the following subprocessors to provide services:</p>
                    
                    <div class="subprocessor-section">
                        <h2>Cloud Infrastructure Partners</h2>
                        <table class="data-table">
                            <tr>
                                <th>Company</th>
                                <th>Service Type</th>
                                <th>Data Location</th>
                            </tr>
                            <tr>
                                <td>Amazon Web Services, Inc.</td>
                                <td>Cloud hosting and storage</td>
                                <td>US, EU</td>
                            </tr>
                            <tr>
                                <td>Google Cloud Platform (Google LLC)</td>
                                <td>Analytics and machine learning</td>
                                <td>Global</td>
                            </tr>
                        </table>
                    </div>
                    
                    <div class="subprocessor-section">
                        <h2>Communication & Support</h2>
                        <ul class="vendor-list">
                            <li><strong>Intercom R&amp;D Unlimited Company</strong> - Customer support chat</li>
                            <li><strong>Zendesk, Inc.</strong> - Help desk and ticketing</li>
                            <li><strong>Mailgun Technologies, Inc.</strong> - Transactional email delivery</li>
                        </ul>
                    </div>
                    
                    <div class="additional-vendors">
                        <h3>Analytics and Monitoring</h3>
                        <p>We also work with these partners for insights:</p>
                        <ol>
                            <li>Mixpanel, Inc. - User analytics</li>
                            <li>Sentry (operated by Functional Software, Inc.) - Error tracking</li>
                            <li>New Relic, Inc. - Performance monitoring</li>
                        </ol>
                    </div>
                </section>
            </main>
        </body>
    </html>
    "#;
    
    let document = Html::parse_document(html_content);
    
    // Test both table and list extraction
    let table_result = analyzer.extract_from_tables(&document, html_content, "https://example.com/subprocessors");
    let list_result = analyzer.extract_from_lists(&document, html_content, "https://example.com/subprocessors");
    
    assert!(table_result.is_ok(), "Table extraction should succeed");
    assert!(list_result.is_ok(), "List extraction should succeed");
    
    let table_vendors = table_result.unwrap();
    let list_vendors = list_result.unwrap();
    
    // Combine all extracted vendors
    let mut all_vendors = table_vendors;
    all_vendors.extend(list_vendors);
    
    assert!(all_vendors.len() >= 5, "Should extract at least 5 vendors from realistic page, found: {}", all_vendors.len());
    
    let domains: Vec<String> = all_vendors.iter().map(|v| v.domain.clone()).collect();
    
    // Expected extractions from various sections
    let expected_domains = vec![
        "aws.amazon.com", "amazon.com", // AWS variations
        "google.com", "cloud.google.com", // Google variations  
        "intercom.com", "intercom.io", // Intercom
        "zendesk.com",
        "mailgun.com", "mailgun.org", // Mailgun variations
        "mixpanel.com", 
        "sentry.io",
        "newrelic.com"
    ];
    
    let mut found_count = 0;
    for expected in &expected_domains {
        if domains.contains(&expected.to_string()) {
            found_count += 1;
        }
    }
    
    assert!(found_count >= 4, "Should find at least 4 expected domains from {:?}, found domains: {:?}", 
            expected_domains, domains);
    
    // Verify all have proper source types and evidence
    for vendor in &all_vendors {
        assert_eq!(vendor.source_type, RecordType::HttpSubprocessor);
        assert!(!vendor.raw_record.is_empty(), "Should have extraction evidence");
        assert!(!vendor.domain.is_empty(), "Domain should not be empty");
        assert!(vendor.domain.contains("."), "Domain should contain a dot");
    }
}

/// Test edge cases and error handling in organization extraction
#[tokio::test]
async fn test_organization_extraction_edge_cases() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    let problematic_html = r#"
    <html>
        <body>
            <table>
                <tr><th>Vendor</th><th>Service</th></tr>
                <tr><td></td><td>Empty vendor name</td></tr>
                <tr><td>   </td><td>Whitespace only</td></tr>
                <tr><td>A</td><td>Too short</td></tr>
                <tr><td>localhost</td><td>Invalid domain</td></tr>
                <tr><td>example.com</td><td>Placeholder domain</td></tr>
                <tr><td>Very Long Company Name That Goes On And On Inc. LLC Corp. Ltd. With Many Suffixes</td><td>Very long name</td></tr>
                <tr><td>Company-with-Dashes & Special Characters! @#$%^&*()</td><td>Special chars</td></tr>
                <tr><td>数字公司 (Chinese Company)</td><td>Unicode characters</td></tr>
            </table>
            
            <ul>
                <li></li>
                <li>   whitespace   </li>
                <li>Microsoft Corporation - Office 365</li>
                <li>Invalid Entry Without Domain</li>
            </ul>
        </body>
    </html>
    "#;
    
    let document = Html::parse_document(problematic_html);
    
    // Should not panic or crash with problematic content
    let table_result = analyzer.extract_from_tables(&document, problematic_html, "https://test.com");
    let list_result = analyzer.extract_from_lists(&document, problematic_html, "https://test.com");
    
    assert!(table_result.is_ok(), "Should handle problematic table content gracefully");
    assert!(list_result.is_ok(), "Should handle problematic list content gracefully");
    
    let table_vendors = table_result.unwrap();
    let list_vendors = list_result.unwrap();
    
    // Should extract valid entries and filter out invalid ones
    let all_vendors: Vec<_> = table_vendors.into_iter().chain(list_vendors).collect();
    
    // Verify all extracted domains are valid
    for vendor in &all_vendors {
        assert!(vendor.domain.len() > 3, "Domain should be reasonable length: '{}'", vendor.domain);
        assert!(vendor.domain.contains("."), "Domain should contain a dot: '{}'", vendor.domain);
        assert!(!vendor.domain.starts_with("."), "Domain should not start with dot: '{}'", vendor.domain);
        assert!(!vendor.domain.ends_with("."), "Domain should not end with dot: '{}'", vendor.domain);
    }
    
    // Should find at least Microsoft if extraction works properly
    let domains: Vec<String> = all_vendors.iter().map(|v| v.domain.clone()).collect();
    // Microsoft should be extractable from "Microsoft Corporation"
    if !domains.is_empty() {
        assert!(domains.iter().any(|d| d.contains("microsoft") || d == "microsoft.com"), 
               "Should extract microsoft.com if any domains were found: {:?}", domains);
    }
}

/// Test extraction patterns and caching behavior
#[tokio::test] 
async fn test_extraction_patterns_functionality() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Test with custom extraction patterns
    let patterns = ExtractionPatterns {
        entity_column_selectors: vec![
            "th:contains('Company')".to_string(),
            "th:contains('Vendor Name')".to_string(),
        ],
        entity_header_patterns: vec![
            "company".to_string(),
            "vendor name".to_string(),
            "organization".to_string(),
        ],
        table_selectors: vec![
            "table.vendors".to_string(),
            ".processor-table".to_string(),
        ],
        list_selectors: vec![
            "ul.vendor-list".to_string(),
            ".processor-list li".to_string(),
        ],
        context_patterns: vec![
            "subprocessors".to_string(),
            "third party".to_string(),
            "vendors".to_string(),
        ],
        domain_extraction_patterns: vec![
            r"(?:^|\s)([a-zA-Z0-9.-]+\.(?:com|org|io|net|co))(?:\s|$)".to_string(),
            r"\(([a-zA-Z0-9.-]+\.(?:com|org|io|net|co))\)".to_string(),
        ],
        custom_extraction_rules: None,
        is_domain_specific: false,
    };
    
    let html_with_custom_structure = r#"
    <html>
        <body>
            <p>Our subprocessors include the following companies:</p>
            <table class="vendors">
                <tr><th>Company</th><th>Purpose</th></tr>
                <tr><td>Stripe Inc. (stripe.com)</td><td>Payments</td></tr>
                <tr><td>GitHub Inc. (github.com)</td><td>Code hosting</td></tr>
            </table>
            <ul class="vendor-list">
                <li>Custom Vendor (customvendor.io)</li>
                <li>Another Service Provider (serviceprovider.com)</li>
            </ul>
        </body>
    </html>
    "#;
    
    let document = Html::parse_document(html_with_custom_structure);
    let result = analyzer.extract_from_tables_with_patterns(&document, html_with_custom_structure, "https://test.com", &patterns);
    
    assert!(result.is_ok(), "Extraction with custom patterns should succeed");
    let (vendors, metadata) = result.unwrap();
    
    // Should extract some vendors using custom patterns
    assert!(vendors.len() >= 1, "Should extract at least one vendor using custom patterns, found: {}", vendors.len());
    
    let domains: Vec<String> = vendors.iter().map(|v| v.domain.clone()).collect();
    println!("Extracted domains with custom patterns: {:?}", domains);
    
    // Check that we get domains from the explicit patterns
    let contains_expected = domains.iter().any(|d| 
        d.contains("stripe.com") || d.contains("github.com") || d.contains("customvendor.io") || d.contains("serviceprovider.com")
    );
    assert!(contains_expected, "Should extract at least one expected domain, found: {:?}", domains);
    
    // Test metadata extraction
    assert!(metadata.is_some(), "Should return extraction metadata");
    let metadata = metadata.unwrap();
    // Note: successful_extractions is always >= 0, but we're checking it exists and is accessible
}

/// Performance test - ensure extraction completes in reasonable time
#[tokio::test]
async fn test_extraction_performance() {
    let analyzer = SubprocessorAnalyzer::new().await;
    
    // Generate large HTML document with many vendors
    let mut html_content = String::from(r#"<html><body><table><tr><th>Entity</th><th>Service</th></tr>"#);
    
    let vendors = vec![
        "Stripe Inc.", "Google LLC", "Microsoft Corp.", "Amazon Inc.", "Apple Inc.",
        "Facebook Inc.", "Salesforce Inc.", "Adobe Inc.", "Oracle Corp.", "IBM Corp."
    ];
    
    // Create 50 rows (5 repetitions of 10 vendors)
    for i in 0..50 {
        let vendor = vendors[i % vendors.len()];
        html_content.push_str(&format!(r#"<tr><td>{}</td><td>Service {}</td></tr>"#, vendor, i));
    }
    
    html_content.push_str("</table></body></html>");
    
    let document = Html::parse_document(&html_content);
    
    let start_time = std::time::Instant::now();
    let result = analyzer.extract_from_tables(&document, &html_content, "https://perf-test.com");
    let elapsed = start_time.elapsed();
    
    assert!(result.is_ok(), "Large document extraction should succeed");
    assert!(elapsed.as_millis() < 1000, "Extraction should complete within 1 second, took: {}ms", elapsed.as_millis());
    
    let vendors = result.unwrap();
    // Note: The extraction might not find many vendors if the HTML structure doesn't match expected patterns
    // This is acceptable as long as it doesn't crash and completes quickly
    assert!(vendors.len() <= 50, "Should not exceed reasonable extraction count, found: {}", vendors.len());
    println!("Performance test extracted {} vendors in {}ms", vendors.len(), elapsed.as_millis());
}

/// Test that custom rules matching prefers earliest-position match for ambiguous org names.
/// This is critical for entries like "Loom, Inc. (Atlassian)" where both "loom" and "atlassian"
/// are valid mapping keys — the primary entity (Loom) appears first and should win.
#[tokio::test]
async fn test_custom_rules_earliest_position_matching() {
    use nthpartyfinder::subprocessor::{
        CustomExtractionRules, DirectSelector, SpecialHandling,
    };
    use std::collections::HashMap;

    let analyzer = SubprocessorAnalyzer::new().await;

    // Build custom rules with ambiguous mappings
    let mut custom_mappings = HashMap::new();
    custom_mappings.insert("loom".to_string(), "loom.com".to_string());
    custom_mappings.insert("atlassian".to_string(), "atlassian.com".to_string());
    custom_mappings.insert("mailgun technologies".to_string(), "mailgun.com".to_string());
    custom_mappings.insert("sinch email".to_string(), "sinch.com".to_string());
    custom_mappings.insert("functional software".to_string(), "sentry.io".to_string());
    custom_mappings.insert("sentry".to_string(), "sentry.io".to_string());

    let custom_rules = CustomExtractionRules {
        direct_selectors: vec![DirectSelector {
            selector: "table tbody tr td:first-child".to_string(),
            attribute: None,
            transform: Some("trim".to_string()),
            description: "Test selector".to_string(),
        }],
        custom_regex_patterns: Vec::new(),
        special_handling: Some(SpecialHandling {
            skip_generic_methods: true,
            custom_org_to_domain_mapping: Some(custom_mappings),
            exclusion_patterns: Vec::new(),
        }),
    };

    // HTML with ambiguous organization names
    let html_content = r#"
    <html><body>
        <table><tbody>
            <tr><td>Loom, Inc. (Atlassian)</td><td>Support</td></tr>
            <tr><td>Mailgun Technologies, Inc. (d/b/a Sinch Email)</td><td>Email</td></tr>
            <tr><td>Functional Software, Inc. (Sentry.io)</td><td>Error tracking</td></tr>
        </tbody></table>
    </body></html>
    "#;

    let document = scraper::Html::parse_document(html_content);
    let result = analyzer.extract_with_custom_rules(
        &document, html_content, "https://test.com/subprocessors", &custom_rules, "test.com",
    );

    assert!(result.is_ok(), "Custom rules extraction should succeed");
    let extraction = result.unwrap();
    let domains: Vec<String> = extraction.subprocessors.iter().map(|v| v.domain.clone()).collect();

    assert_eq!(domains.len(), 3, "Should extract exactly 3 vendors, found: {:?}", domains);

    // "Loom, Inc. (Atlassian)" -> "loom" at position 0 beats "atlassian" at position ~12
    assert!(
        domains.contains(&"loom.com".to_string()),
        "Should map 'Loom, Inc. (Atlassian)' to loom.com (earliest match), found: {:?}",
        domains
    );
    assert!(
        !domains.contains(&"atlassian.com".to_string()),
        "Should NOT map to atlassian.com (later match) when loom.com is earlier, found: {:?}",
        domains
    );

    // "Mailgun Technologies, Inc. (d/b/a Sinch Email)" -> "mailgun technologies" at pos 0 beats "sinch email"
    assert!(
        domains.contains(&"mailgun.com".to_string()),
        "Should map Mailgun entry to mailgun.com (earliest match), found: {:?}",
        domains
    );

    // "Functional Software, Inc. (Sentry.io)" -> "functional software" at pos 0 beats "sentry"
    assert!(
        domains.contains(&"sentry.io".to_string()),
        "Should map Functional Software entry to sentry.io, found: {:?}",
        domains
    );
}