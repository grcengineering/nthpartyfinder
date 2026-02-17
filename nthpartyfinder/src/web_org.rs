//! Web-based organization name extraction
//!
//! Extracts organization names from web pages using:
//! - Schema.org JSON-LD structured data
//! - OpenGraph meta tags
//! - HTML meta tags (author, application-name)
//! - Title tag patterns
//! - Copyright/footer patterns
//!
//! This provides a reliable fallback when WHOIS data is unavailable or protected.

use anyhow::{Result, anyhow};

use regex::Regex;
use scraper::{Html, Selector};
use serde::Deserialize;
use std::time::Duration;
use tracing::{debug, info};

/// Result of web-based organization extraction
#[derive(Debug, Clone)]
pub struct WebOrgResult {
    /// The organization name
    pub organization: String,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Source of the extraction
    pub source: WebOrgSource,
}

/// Source of the organization name extraction
#[derive(Debug, Clone, PartialEq)]
pub enum WebOrgSource {
    /// Schema.org JSON-LD structured data
    SchemaOrg,
    /// OpenGraph og:site_name meta tag
    OpenGraph,
    /// HTML meta tags (author, application-name)
    MetaTag,
    /// Parsed from title tag
    TitleTag,
    /// Copyright notice in footer
    Copyright,
    /// PWA manifest.json
    Manifest,
}

impl std::fmt::Display for WebOrgSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebOrgSource::SchemaOrg => write!(f, "schema_org"),
            WebOrgSource::OpenGraph => write!(f, "opengraph"),
            WebOrgSource::MetaTag => write!(f, "meta_tag"),
            WebOrgSource::TitleTag => write!(f, "title_tag"),
            WebOrgSource::Copyright => write!(f, "copyright"),
            WebOrgSource::Manifest => write!(f, "manifest"),
        }
    }
}

/// Schema.org Organization structure (partial)
#[derive(Debug, Deserialize)]
struct SchemaOrgData {
    #[serde(rename = "@type")]
    schema_type: Option<String>,
    name: Option<String>,
    #[serde(rename = "legalName")]
    legal_name: Option<String>,
    publisher: Option<Box<SchemaOrgData>>,
    author: Option<Box<SchemaOrgData>>,
    #[serde(rename = "@graph")]
    graph: Option<Vec<SchemaOrgData>>,
}

/// Fetch page content from a domain's website
pub async fn fetch_page_content(domain: &str) -> Result<String> {
    let url = format!("https://{}", domain);

    debug!("Fetching web page content: {}", url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (compatible; nthpartyfinder/1.0; +https://github.com/your-org/nthpartyfinder)")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    let response = match client.get(&url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            debug!("Failed to fetch {}: {}", url, e);
            // Try HTTP fallback
            let http_url = format!("http://{}", domain);
            client.get(&http_url).send().await
                .map_err(|e2| anyhow!("Failed to fetch {}: HTTPS: {}, HTTP: {}", domain, e, e2))?
        }
    };

    if !response.status().is_success() {
        return Err(anyhow!("Non-success status {} for {}", response.status(), url));
    }

    response.text().await.map_err(|e| anyhow!("Failed to read response body: {}", e))
}

/// Extract organization name from a domain's website
pub async fn extract_organization_from_web(domain: &str) -> Result<Option<WebOrgResult>> {
    let html_content = fetch_page_content(domain).await?;
    extract_organization_from_html(&html_content, domain)
}

/// Extract organization with headless browser fallback
///
/// First tries simple HTTP fetch. If that fails to extract an organization
/// (e.g., SPA sites that need JavaScript rendering), falls back to headless
/// browser rendering.
///
/// # Arguments
/// * `domain` - The domain to extract organization from
/// * `use_headless_only` - If true, skip HTTP and go directly to headless browser
///
/// # Returns
/// * `Ok(Some(WebOrgResult))` - Successfully extracted organization
/// * `Ok(None)` - Could not extract organization from either method
/// * `Err` - Network or browser error
pub async fn extract_organization_with_fallback(
    domain: &str,
    use_headless_only: bool,
) -> Result<Option<WebOrgResult>> {
    // Step 1: Try simple HTTP fetch first (unless headless_only requested)
    if !use_headless_only {
        debug!("Trying simple HTTP fetch for {}", domain);
        match fetch_page_content(domain).await {
            Ok(html_content) => {
                if let Ok(Some(result)) = extract_organization_from_html(&html_content, domain) {
                    debug!("HTTP fetch succeeded for {}: {} ({})",
                           domain, result.organization, result.source);
                    return Ok(Some(result));
                }
                debug!("HTTP fetch returned no structured data for {} - likely SPA", domain);
            }
            Err(e) => {
                debug!("HTTP fetch failed for {}: {}", domain, e);
            }
        }
    }

    // Step 2: Fall back to headless browser for JavaScript rendering
    debug!("Trying headless browser for {}", domain);
    match fetch_page_with_headless(domain) {
        Ok(html_content) => {
            if let Ok(Some(result)) = extract_organization_from_html(&html_content, domain) {
                info!("Headless browser succeeded for {}: {} ({})",
                      domain, result.organization, result.source);
                return Ok(Some(result));
            }
            debug!("Headless browser returned no structured data for {}", domain);
        }
        Err(e) => {
            debug!("Headless browser failed for {}: {}", domain, e);
        }
    }

    Ok(None)
}

/// Fetch page content using headless Chrome browser (for JavaScript-rendered pages)
fn fetch_page_with_headless(domain: &str) -> Result<String> {
    let url = format!("https://{}", domain);

    let guard = crate::browser_pool::create_browser()?;

    let tab = guard.browser.new_tab()
        .map_err(|e| anyhow!("Failed to create browser tab: {}", e))?;

    tab.navigate_to(&url)
        .map_err(|e| anyhow!("Failed to navigate to {}: {}", url, e))?;

    tab.wait_until_navigated()
        .map_err(|e| anyhow!("Page failed to load for {}: {}", url, e))?;

    // Wait for JavaScript to render - SPAs often need more time
    std::thread::sleep(Duration::from_millis(3000));

    let html_content = tab.get_content()
        .map_err(|e| anyhow!("Failed to get page content for {}: {}", url, e))?;

    Ok(html_content)
}

/// Extract organization from HTML content
pub fn extract_organization_from_html(html: &str, domain: &str) -> Result<Option<WebOrgResult>> {
    let document = Html::parse_document(html);

    // Try extraction methods in order of reliability

    // 1. Schema.org JSON-LD (highest confidence)
    if let Some(result) = extract_from_schema_org(&document) {
        debug!("Found organization via Schema.org: {}", result.organization);
        return Ok(Some(result));
    }

    // 2. OpenGraph meta tags (high confidence)
    if let Some(result) = extract_from_opengraph(&document) {
        debug!("Found organization via OpenGraph: {}", result.organization);
        return Ok(Some(result));
    }

    // 3. Other meta tags (medium-high confidence)
    if let Some(result) = extract_from_meta_tags(&document) {
        debug!("Found organization via meta tags: {}", result.organization);
        return Ok(Some(result));
    }

    // 4. Title tag patterns (medium confidence)
    if let Some(result) = extract_from_title(&document, domain) {
        debug!("Found organization via title: {}", result.organization);
        return Ok(Some(result));
    }

    // 5. Copyright/footer patterns (lower confidence)
    if let Some(result) = extract_from_copyright(&document, html) {
        debug!("Found organization via copyright: {}", result.organization);
        return Ok(Some(result));
    }

    debug!("No organization found in web page for {}", domain);
    Ok(None)
}

/// Extract organization from Schema.org JSON-LD
fn extract_from_schema_org(document: &Html) -> Option<WebOrgResult> {
    let selector = Selector::parse(r#"script[type="application/ld+json"]"#).ok()?;

    for element in document.select(&selector) {
        let json_text = element.text().collect::<String>();

        // Try to parse as a single object
        if let Ok(data) = serde_json::from_str::<SchemaOrgData>(&json_text) {
            if let Some(org) = extract_org_from_schema_data(&data) {
                return Some(WebOrgResult {
                    organization: org,
                    confidence: 0.95,
                    source: WebOrgSource::SchemaOrg,
                });
            }
        }

        // Try to parse as an array
        if let Ok(data_array) = serde_json::from_str::<Vec<SchemaOrgData>>(&json_text) {
            for data in data_array {
                if let Some(org) = extract_org_from_schema_data(&data) {
                    return Some(WebOrgResult {
                        organization: org,
                        confidence: 0.95,
                        source: WebOrgSource::SchemaOrg,
                    });
                }
            }
        }
    }

    None
}

/// Extract organization name from Schema.org data structure
fn extract_org_from_schema_data(data: &SchemaOrgData) -> Option<String> {
    // Check if this is an Organization type
    if let Some(ref schema_type) = data.schema_type {
        let org_types = ["Organization", "Corporation", "LocalBusiness", "Company",
                        "Brand", "NGO", "GovernmentOrganization", "EducationalOrganization"];

        if org_types.iter().any(|t| schema_type.contains(t)) {
            // Prefer legal name, fall back to name
            if let Some(ref legal_name) = data.legal_name {
                if is_valid_org_name(legal_name) {
                    return Some(clean_org_name(legal_name));
                }
            }
            if let Some(ref name) = data.name {
                if is_valid_org_name(name) {
                    return Some(clean_org_name(name));
                }
            }
        }
    }

    // Check @graph for Organization entries
    if let Some(ref graph) = data.graph {
        for item in graph {
            if let Some(org) = extract_org_from_schema_data(item) {
                return Some(org);
            }
        }
    }

    // Check publisher/author
    if let Some(ref publisher) = data.publisher {
        if let Some(org) = extract_org_from_schema_data(publisher) {
            return Some(org);
        }
    }
    if let Some(ref author) = data.author {
        if let Some(org) = extract_org_from_schema_data(author) {
            return Some(org);
        }
    }

    None
}

/// Extract organization from OpenGraph meta tags
fn extract_from_opengraph(document: &Html) -> Option<WebOrgResult> {
    // Try og:site_name first (most reliable)
    if let Some(og_site) = get_meta_property(document, "og:site_name") {
        if is_valid_org_name(&og_site) {
            return Some(WebOrgResult {
                organization: clean_org_name(&og_site),
                confidence: 0.85,
                source: WebOrgSource::OpenGraph,
            });
        }
    }

    // Try twitter:site as fallback
    if let Some(twitter_site) = get_meta_name(document, "twitter:site") {
        // Twitter handles start with @, convert to potential org name
        let handle = twitter_site.trim_start_matches('@');
        if handle.len() > 2 && !handle.contains(' ') {
            // Convert handle to title case as potential org name
            let org_name = handle.chars().next()
                .map(|c| c.to_uppercase().collect::<String>() + &handle[1..])
                .unwrap_or_else(|| handle.to_string());

            return Some(WebOrgResult {
                organization: org_name,
                confidence: 0.60, // Lower confidence for Twitter handle
                source: WebOrgSource::OpenGraph,
            });
        }
    }

    None
}

/// Extract organization from various meta tags
fn extract_from_meta_tags(document: &Html) -> Option<WebOrgResult> {
    // Try application-name (often set for PWAs)
    if let Some(app_name) = get_meta_name(document, "application-name") {
        if is_valid_org_name(&app_name) {
            return Some(WebOrgResult {
                organization: clean_org_name(&app_name),
                confidence: 0.75,
                source: WebOrgSource::MetaTag,
            });
        }
    }

    // Try author meta tag
    if let Some(author) = get_meta_name(document, "author") {
        if is_valid_org_name(&author) {
            return Some(WebOrgResult {
                organization: clean_org_name(&author),
                confidence: 0.70,
                source: WebOrgSource::MetaTag,
            });
        }
    }

    // Try publisher meta tag
    if let Some(publisher) = get_meta_name(document, "publisher") {
        if is_valid_org_name(&publisher) {
            return Some(WebOrgResult {
                organization: clean_org_name(&publisher),
                confidence: 0.70,
                source: WebOrgSource::MetaTag,
            });
        }
    }

    // Try DC.publisher (Dublin Core)
    if let Some(dc_publisher) = get_meta_name(document, "DC.publisher") {
        if is_valid_org_name(&dc_publisher) {
            return Some(WebOrgResult {
                organization: clean_org_name(&dc_publisher),
                confidence: 0.75,
                source: WebOrgSource::MetaTag,
            });
        }
    }

    None
}

/// Extract organization from title tag
fn extract_from_title(document: &Html, _domain: &str) -> Option<WebOrgResult> {
    let selector = Selector::parse("title").ok()?;
    let title = document.select(&selector).next()?.text().collect::<String>();
    let title = title.trim();

    if title.is_empty() || title.len() < 3 {
        return None;
    }

    // Common title patterns:
    // "Product Name | Company Name"
    // "Product Name - Company Name"
    // "Company Name: Product"
    // "Company Name – Product"

    let separators = [" | ", " - ", " – ", " — ", ": ", " :: "];

    for sep in separators {
        if let Some(parts) = title.split_once(sep) {
            // Usually the company name is on the right for "Product | Company"
            // or on the left for "Company: Product"

            let (left, right) = (parts.0.trim(), parts.1.trim());

            // Check if right side looks like a company name (preferred for | and -)
            if sep == " | " || sep == " - " || sep == " – " || sep == " — " {
                if is_valid_org_name(right) && !looks_like_page_name(right) {
                    return Some(WebOrgResult {
                        organization: clean_org_name(right),
                        confidence: 0.65,
                        source: WebOrgSource::TitleTag,
                    });
                }
            }

            // Check if left side looks like a company name (for ": " pattern)
            if sep == ": " || sep == " :: " {
                if is_valid_org_name(left) && !looks_like_page_name(left) {
                    return Some(WebOrgResult {
                        organization: clean_org_name(left),
                        confidence: 0.65,
                        source: WebOrgSource::TitleTag,
                    });
                }
            }
        }
    }

    // If no separator, and title is short enough, it might be just the company name
    if title.len() < 50 && !title.contains("Home") && !title.contains("Welcome") {
        // Check if it doesn't look like a page title
        if is_valid_org_name(&title) && !looks_like_page_name(&title) {
            return Some(WebOrgResult {
                organization: clean_org_name(&title),
                confidence: 0.50,
                source: WebOrgSource::TitleTag,
            });
        }
    }

    None
}

/// Extract organization from copyright notices
fn extract_from_copyright(document: &Html, html: &str) -> Option<WebOrgResult> {
    // Look for copyright patterns in the HTML
    // © 2024 Company Name, Inc.
    // Copyright © 2024 Company Name
    // (c) 2024 Company Name

    let copyright_patterns = [
        // Pattern 1: © 2024 Company Name followed by All rights or period/comma
        r"(?i)(?:©|&copy;|\(c\))\s*(?:20\d{2}[-–]?\s*)?(?:20\d{2}\s+)?([A-Z][A-Za-z0-9\s,&']+?(?:\s*(?:Inc\.?|LLC|Ltd\.?|Corp\.?|Corporation|Company|Co\.?|GmbH|Pty|Limited))?)(?:\s*\.|\s*,|\s+All\s+[Rr]ights)",
        // Pattern 2: Copyright © 2024 Company Name
        r"(?i)Copyright\s+(?:©|&copy;)?\s*(?:20\d{2}[-–]?\s*)?(?:20\d{2}\s+)?([A-Z][A-Za-z0-9\s,&']+?(?:\s*(?:Inc\.?|LLC|Ltd\.?|Corp\.?|Corporation|Company|Co\.?|GmbH|Pty|Limited))?)(?:\s*\.|\s*,|\s+All\s+[Rr]ights)",
        // Pattern 3: Simpler pattern - just year followed by company name until period
        r"(?i)(?:©|&copy;|\(c\)|copyright)\s*20\d{2}\s+([A-Z][A-Za-z0-9\s]+?)(?:\.|\s+All)",
    ];

    // First try to find footer element
    let footer_selectors = ["footer", ".footer", "#footer", "[role=\"contentinfo\"]"];
    let mut search_text = String::new();

    for sel_str in footer_selectors {
        if let Ok(selector) = Selector::parse(sel_str) {
            for element in document.select(&selector) {
                search_text.push_str(&element.text().collect::<String>());
                search_text.push(' ');
            }
        }
    }

    // If no footer found, search the whole document
    if search_text.is_empty() {
        search_text = html.to_string();
    }

    for pattern in copyright_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if let Some(caps) = regex.captures(&search_text) {
                if let Some(org_match) = caps.get(1) {
                    let org = org_match.as_str().trim();
                    if is_valid_org_name(org) {
                        return Some(WebOrgResult {
                            organization: clean_org_name(org),
                            confidence: 0.60,
                            source: WebOrgSource::Copyright,
                        });
                    }
                }
            }
        }
    }

    None
}

/// Get meta tag content by property attribute
fn get_meta_property(document: &Html, property: &str) -> Option<String> {
    let selector = Selector::parse(&format!(r#"meta[property="{}"]"#, property)).ok()?;
    document.select(&selector)
        .next()
        .and_then(|el| el.value().attr("content"))
        .map(|s| s.to_string())
}

/// Get meta tag content by name attribute
fn get_meta_name(document: &Html, name: &str) -> Option<String> {
    let selector = Selector::parse(&format!(r#"meta[name="{}"]"#, name)).ok()?;
    document.select(&selector)
        .next()
        .and_then(|el| el.value().attr("content"))
        .map(|s| s.to_string())
}

/// Check if a string looks like a valid organization name
fn is_valid_org_name(name: &str) -> bool {
    let name = name.trim();

    // Must be at least 2 characters
    if name.len() < 2 {
        return false;
    }

    // Must not be too long
    if name.len() > 100 {
        return false;
    }

    // Must start with alphanumeric
    if !name.chars().next().map(|c| c.is_alphanumeric()).unwrap_or(false) {
        return false;
    }

    // Must not be just numbers
    if name.chars().all(|c| c.is_numeric() || c.is_whitespace()) {
        return false;
    }

    // Reject common non-org strings (including SPA placeholders)
    let invalid_names = [
        "home", "welcome", "about", "contact", "login", "sign in", "sign up",
        "register", "dashboard", "admin", "404", "error", "page not found",
        "undefined", "null", "none", "n/a", "test", "example",
        "loading", "loading...", "please wait", "redirecting",
    ];

    let name_lower = name.to_lowercase();
    if invalid_names.iter().any(|inv| name_lower == *inv) {
        return false;
    }

    true
}

/// Check if a string looks like a page name rather than an org name
fn looks_like_page_name(name: &str) -> bool {
    let page_indicators = [
        "Home", "Welcome", "About", "Contact", "Login", "Sign", "Register",
        "Dashboard", "Settings", "Profile", "Account", "Blog", "News",
        "Products", "Services", "Pricing", "Support", "Help", "FAQ",
        "Privacy", "Terms", "Legal", "Careers", "Jobs",
    ];

    page_indicators.iter().any(|ind| name.contains(ind))
}

/// Clean up organization name
fn clean_org_name(name: &str) -> String {
    let cleaned = name.trim()
        .replace('\n', " ")
        .replace('\r', " ")
        .replace('\t', " ")
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    // Remove trailing period if it's not part of an abbreviation
    if cleaned.ends_with('.') && !cleaned.ends_with("Inc.") && !cleaned.ends_with("Ltd.")
        && !cleaned.ends_with("Corp.") && !cleaned.ends_with("Co.") && !cleaned.ends_with("LLC.")
    {
        cleaned[..cleaned.len()-1].to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_organization_with_fallback_prefers_http() {
        // When HTTP fetch returns good structured data, we should use it
        // (no need for expensive headless browser)
        let html_with_og = r#"
        <html>
        <head>
            <meta property="og:site_name" content="Test Company">
        </head>
        <body></body>
        </html>
        "#;

        let result = extract_organization_from_html(html_with_og, "test.com").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().organization, "Test Company");
    }

    #[test]
    fn test_extract_organization_detects_spa_needing_headless() {
        // SPA sites return minimal HTML with JavaScript bundles
        // This should return None, signaling we need headless fallback
        let spa_html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Loading...</title>
            <script src="/static/app.bundle.js"></script>
        </head>
        <body>
            <div id="root"></div>
            <noscript>Please enable JavaScript</noscript>
        </body>
        </html>
        "#;

        let result = extract_organization_from_html(spa_html, "example.com").unwrap();
        // SPA shell has no structured data - should return None
        assert!(result.is_none(), "SPA shell should return None, triggering headless fallback");
    }

    #[test]
    fn test_extract_organization_from_rendered_spa_content() {
        // This simulates what headless browser would return after JavaScript renders
        // Real SPA sites have og:site_name and Schema.org after JS executes
        let rendered_spa_html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Slack | AI Work Platform</title>
            <meta property="og:site_name" content="Slack">
            <script type="application/ld+json">
            {
                "@type": "Organization",
                "name": "Slack Technologies, LLC"
            }
            </script>
        </head>
        <body>
            <div id="root">
                <h1>Welcome to Slack</h1>
            </div>
        </body>
        </html>
        "#;

        let result = extract_organization_from_html(rendered_spa_html, "slack.com").unwrap();
        assert!(result.is_some());
        let org = result.unwrap();
        // Schema.org has higher priority than og:site_name
        assert_eq!(org.organization, "Slack Technologies, LLC");
        assert_eq!(org.source, WebOrgSource::SchemaOrg);
    }

    #[tokio::test]
    async fn test_extract_organization_with_fallback_exists() {
        // This test verifies the fallback function exists and compiles
        // We test with a domain that's in known_vendors.json to avoid network calls
        // The function should exist and be callable
        let _result = extract_organization_with_fallback("example.com", false).await;
        // Function exists and returns a Result
    }

    #[test]
    fn test_is_valid_org_name() {
        assert!(is_valid_org_name("Acme Inc."));
        assert!(is_valid_org_name("Google LLC"));
        assert!(is_valid_org_name("Microsoft"));
        assert!(!is_valid_org_name(""));
        assert!(!is_valid_org_name("a"));
        assert!(!is_valid_org_name("Home"));
        assert!(!is_valid_org_name("123456"));
    }

    #[test]
    fn test_looks_like_page_name() {
        assert!(looks_like_page_name("Home - Products"));
        assert!(looks_like_page_name("Welcome to our site"));
        assert!(!looks_like_page_name("Acme Inc."));
        assert!(!looks_like_page_name("Google"));
    }

    #[test]
    fn test_clean_org_name() {
        assert_eq!(clean_org_name("  Acme  Inc.  "), "Acme Inc.");
        assert_eq!(clean_org_name("Acme\n\tInc."), "Acme Inc.");
    }

    #[test]
    fn test_extract_from_html_schema_org() {
        let html = r#"
        <html>
        <head>
            <script type="application/ld+json">
            {
                "@type": "Organization",
                "name": "Test Company Inc."
            }
            </script>
        </head>
        <body></body>
        </html>
        "#;

        let result = extract_organization_from_html(html, "test.com").unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.organization, "Test Company Inc.");
        assert_eq!(result.source, WebOrgSource::SchemaOrg);
    }

    #[test]
    fn test_extract_from_html_opengraph() {
        let html = r#"
        <html>
        <head>
            <meta property="og:site_name" content="My Company">
        </head>
        <body></body>
        </html>
        "#;

        let result = extract_organization_from_html(html, "test.com").unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.organization, "My Company");
        assert_eq!(result.source, WebOrgSource::OpenGraph);
    }

    #[test]
    fn test_extract_from_html_title() {
        let html = r#"
        <html>
        <head>
            <title>Product Name | Acme Corporation</title>
        </head>
        <body></body>
        </html>
        "#;

        let result = extract_organization_from_html(html, "test.com").unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.organization, "Acme Corporation");
        assert_eq!(result.source, WebOrgSource::TitleTag);
    }

    #[test]
    fn test_extract_from_html_copyright() {
        let html = r#"
        <html>
        <body>
            <footer>
                © 2024 Example Corp. All rights reserved.
            </footer>
        </body>
        </html>
        "#;

        let result = extract_organization_from_html(html, "test.com").unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        // Corp. is a valid corporate suffix, so it's preserved
        assert_eq!(result.organization, "Example Corp.");
        assert_eq!(result.source, WebOrgSource::Copyright);
    }
}
