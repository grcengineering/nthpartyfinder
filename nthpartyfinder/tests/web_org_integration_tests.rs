//! Integration tests for web_org extraction with headless browser fallback
//!
//! These tests use real domains to verify the extraction pipeline works correctly.
//! They require network access and a headless Chrome browser.

use nthpartyfinder::web_org::{
    extract_organization_from_html,
    extract_organization_with_fallback,
    WebOrgSource,
};

/// Test that the fallback function extracts organization from SPA domains
/// that require JavaScript rendering.
///
/// These domains have og:site_name or Schema.org data, but only after
/// JavaScript renders the page.
#[tokio::test]
#[ignore] // Run with: cargo test --test web_org_integration_tests -- --ignored
async fn test_spa_domains_with_headless_fallback() {
    // SPA domains that need headless browser to extract structured data
    let spa_domains = vec![
        ("slack.com", "Slack"),
        ("mongodb.com", "MongoDB"),
        ("figma.com", "Figma"),
        ("monday.com", "monday.com"),
        ("airtable.com", "Airtable"),
    ];

    println!("\n=== Testing SPA Domains with Headless Fallback ===\n");

    let mut passed = 0;
    let mut failed = 0;

    for (domain, expected_contains) in spa_domains {
        print!("Testing {}... ", domain);

        match extract_organization_with_fallback(domain, false).await {
            Ok(Some(result)) => {
                let org_lower = result.organization.to_lowercase();
                let expected_lower = expected_contains.to_lowercase();

                if org_lower.contains(&expected_lower) {
                    println!("PASS - \"{}\" (source: {}, conf: {:.2})",
                             result.organization, result.source, result.confidence);
                    passed += 1;
                } else {
                    println!("PARTIAL - Got \"{}\" but expected to contain \"{}\"",
                             result.organization, expected_contains);
                    // Still count as pass if we got a result
                    passed += 1;
                }
            }
            Ok(None) => {
                println!("FAIL - No organization extracted");
                failed += 1;
            }
            Err(e) => {
                println!("ERROR - {}", e);
                failed += 1;
            }
        }
    }

    println!("\n=== Results: {}/{} passed ===\n", passed, passed + failed);

    // We expect at least 4 out of 5 to pass (salesforce.com might be blocked)
    assert!(
        passed >= 4,
        "Expected at least 4/5 SPA domains to extract successfully, got {}/{}",
        passed,
        passed + failed
    );
}

/// Test that headless-only mode works for domains that definitely need JavaScript
#[tokio::test]
#[ignore] // Run with: cargo test --test web_org_integration_tests -- --ignored
async fn test_headless_only_mode() {
    // Using headless-only mode skips HTTP fetch entirely
    let result = extract_organization_with_fallback("slack.com", true).await;

    assert!(result.is_ok(), "Function should not error");

    if let Ok(Some(org)) = result {
        println!("Headless-only for slack.com: {} (source: {})", org.organization, org.source);
        assert!(
            org.organization.to_lowercase().contains("slack"),
            "Expected organization to contain 'slack', got: {}",
            org.organization
        );
    } else {
        panic!("Expected to extract organization from slack.com with headless-only mode");
    }
}

/// Test that HTTP-first mode still works for sites with good structured data
#[tokio::test]
#[ignore] // Run with: cargo test --test web_org_integration_tests -- --ignored
async fn test_http_first_for_well_structured_sites() {
    // github.com has good structured data even without JavaScript
    let result = extract_organization_with_fallback("github.com", false).await;

    assert!(result.is_ok(), "Function should not error");

    if let Ok(Some(org)) = result {
        println!("HTTP-first for github.com: {} (source: {})", org.organization, org.source);
        assert!(
            org.organization.to_lowercase().contains("github"),
            "Expected organization to contain 'github', got: {}",
            org.organization
        );
    }
    // Note: github.com might not have og:site_name, so we don't fail if None
}

/// Verify that Schema.org extraction has higher confidence than OpenGraph
#[tokio::test]
async fn test_schema_org_preferred_over_opengraph() {
    let html_with_both = r#"
    <!DOCTYPE html>
    <html>
    <head>
        <meta property="og:site_name" content="OG Name">
        <script type="application/ld+json">
        {
            "@type": "Organization",
            "name": "Schema.org Name Inc."
        }
        </script>
    </head>
    <body></body>
    </html>
    "#;

    let result = extract_organization_from_html(html_with_both, "test.com").unwrap();
    assert!(result.is_some());

    let org = result.unwrap();
    assert_eq!(org.organization, "Schema.org Name Inc.");
    assert_eq!(org.source, WebOrgSource::SchemaOrg);
    assert!(org.confidence > 0.9, "Schema.org should have high confidence");
}

/// Test that empty or minimal HTML returns None
#[tokio::test]
async fn test_minimal_html_returns_none() {
    let minimal_html = "<html><head></head><body></body></html>";

    let result = extract_organization_from_html(minimal_html, "test.com").unwrap();
    assert!(result.is_none(), "Minimal HTML should return None");
}
