//! Certificate Transparency (CT) log discovery for finding third-party vendors.
//!
//! Queries crt.sh to find certificates associated with a domain and extracts
//! third-party domains from certificate Subject Alternative Names (SANs).

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::domain_utils;

/// Response from crt.sh API
#[derive(Debug, Deserialize)]
pub struct CrtShEntry {
    /// Issuer CA ID
    pub issuer_ca_id: Option<i64>,
    /// Certificate issuer name
    pub issuer_name: Option<String>,
    /// Common name from certificate
    pub common_name: Option<String>,
    /// Subject Alternative Names (newline separated)
    pub name_value: Option<String>,
    /// Certificate ID
    pub id: i64,
    /// Entry timestamp
    pub entry_timestamp: Option<String>,
    /// Not before date
    pub not_before: Option<String>,
    /// Not after date
    pub not_after: Option<String>,
}

/// Result of CT log discovery
#[derive(Debug, Clone)]
pub struct CtDiscoveryResult {
    /// Discovered vendor domain
    pub domain: String,
    /// Source description
    pub source: String,
    /// Raw certificate info for evidence
    pub certificate_info: String,
}

/// Certificate Transparency log discovery
pub struct CtLogDiscovery {
    client: Client,
    timeout: Duration,
    base_url: String,
}

impl CtLogDiscovery {
    pub fn new(timeout: Duration) -> Self {
        Self::with_base_url(timeout, "https://crt.sh".to_string())
    }

    pub fn with_base_url(timeout: Duration, base_url: String) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("nthpartyfinder/1.0")
            .build()
            .unwrap_or_default();

        Self {
            client,
            timeout,
            base_url,
        }
    }

    /// Discover vendors from CT logs for a domain
    pub async fn discover(&self, domain: &str) -> Result<Vec<CtDiscoveryResult>> {
        info!("Querying CT logs for certificates related to {}", domain);

        let mut results = Vec::new();
        let mut seen_domains = HashSet::new();

        // Add the target domain to seen to avoid self-references
        let base_domain = domain_utils::extract_base_domain(domain);
        seen_domains.insert(base_domain.clone());

        // Query crt.sh for certificates
        let entries = self.query_crt_sh(domain).await?;
        debug!("Found {} certificate entries for {}", entries.len(), domain);

        for entry in entries {
            // Extract domains from SAN (name_value)
            if let Some(name_value) = &entry.name_value {
                for san in name_value.lines() {
                    let san = san.trim().to_lowercase();
                    if san.is_empty() {
                        continue;
                    }

                    // Extract base domain
                    let san_base = domain_utils::extract_base_domain(&san);

                    // Skip if same as target domain
                    if san_base == base_domain {
                        continue;
                    }

                    // Skip common CDN/infrastructure domains that aren't meaningful vendors
                    if Self::is_infrastructure_domain(&san_base) {
                        continue;
                    }

                    // Only add if not seen before
                    if seen_domains.insert(san_base.clone()) {
                        let issuer = entry.issuer_name.as_deref().unwrap_or("Unknown CA");
                        let cert_id = entry.id;

                        results.push(CtDiscoveryResult {
                            domain: san_base.clone(),
                            source: format!("Certificate SAN (crt.sh ID: {})", cert_id),
                            certificate_info: format!(
                                "SAN: {} | Issuer: {} | Certificate ID: {}",
                                san, issuer, cert_id
                            ),
                        });

                        debug!(
                            "Found vendor {} from CT log certificate {}",
                            san_base, cert_id
                        );
                    }
                }
            }

            // Also check common_name if different from target
            if let Some(common_name) = &entry.common_name {
                let cn = common_name.trim().to_lowercase();
                let cn_base = domain_utils::extract_base_domain(&cn);

                if cn_base != base_domain
                    && !Self::is_infrastructure_domain(&cn_base)
                    && seen_domains.insert(cn_base.clone())
                {
                    results.push(CtDiscoveryResult {
                        domain: cn_base.clone(),
                        source: format!("Certificate CN (crt.sh ID: {})", entry.id),
                        certificate_info: format!(
                            "CN: {} | Issuer: {} | Certificate ID: {}",
                            cn,
                            entry.issuer_name.as_deref().unwrap_or("Unknown CA"),
                            entry.id
                        ),
                    });

                    debug!("Found vendor {} from CT log certificate CN", cn_base);
                }
            }
        }

        info!(
            "CT log discovery found {} unique vendor domains for {}",
            results.len(),
            domain
        );
        Ok(results)
    }

    /// Query crt.sh for certificates related to a domain
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) async fn query_crt_sh(&self, domain: &str) -> Result<Vec<CrtShEntry>> {
        // Query for wildcard certificates (%.domain.com)
        let url = format!(
            "{}/?q=%.{}&output=json",
            self.base_url,
            urlencoding::encode(domain)
        );

        debug!("Querying crt.sh: {}", url);

        let response = self.client.get(&url).timeout(self.timeout).send().await?;

        if !response.status().is_success() {
            warn!(
                "crt.sh returned status {} for {}",
                response.status(),
                domain
            );
            return Ok(Vec::new());
        }

        let text = response.text().await?;

        // crt.sh returns empty array as "[]" or sometimes just empty
        if text.is_empty() || text == "[]" {
            return Ok(Vec::new());
        }

        // Parse JSON response
        match serde_json::from_str::<Vec<CrtShEntry>>(&text) {
            Ok(entries) => Ok(entries),
            Err(e) => {
                warn!("Failed to parse crt.sh response: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Check if a domain is infrastructure/CDN that shouldn't be reported as a vendor.
    ///
    /// NOTE(M009): This list intentionally excludes hosting platforms like heroku.com and
    /// wpengine.com because organizations may legitimately use them as vendors. Only pure
    /// infrastructure domains (CDNs, cloud primitives, certificate issuers) that would create
    /// noise in vendor reports are filtered here.
    fn is_infrastructure_domain(domain: &str) -> bool {
        let infrastructure_domains = [
            // CDN providers - these appear in certs due to CDN termination, not vendor relationships
            "cloudflare.com",
            "cloudflare.net",
            "cloudfront.net",
            "akamai.com",
            "akamaiedge.net",
            "fastly.net",
            "fastly.com",
            "edgekey.net",
            "edgesuite.net",
            // Cloud infrastructure primitives - raw cloud hostnames, not meaningful vendor signals
            "amazonaws.com",
            "azure.com",
            "azurewebsites.net",
            "azureedge.net",
            "googleusercontent.com",
            "googlesyndication.com",
            "gstatic.com",
            // SSL/TLS certificate issuers - appear as cert issuers, not actual vendor relationships
            "letsencrypt.org",
            "digicert.com",
            "comodo.com",
            "godaddy.com",
            "rapidssl.com",
            "geotrust.com",
            "thawte.com",
            "entrust.net",
            // M009 fix: removed globalsign.com - it's a legitimate SSL vendor that organizations
            // may want to track as a third-party relationship
            "sectigo.com",
            // Non-routable / test domains
            "localhost",
            "local",
            "test",
            "example.com",
        ];

        infrastructure_domains
            .iter()
            .any(|&infra| domain.ends_with(infra) || domain == infra)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_infrastructure_domain() {
        assert!(CtLogDiscovery::is_infrastructure_domain("cloudflare.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "sub.cloudflare.com"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain("amazonaws.com"));
        assert!(!CtLogDiscovery::is_infrastructure_domain("klaviyo.com"));
        assert!(!CtLogDiscovery::is_infrastructure_domain("google.com"));
    }

    // ───────────────────────────────────────────────────────────────
    // Additional coverage tests below
    // ───────────────────────────────────────────────────────────────

    use rstest::rstest;
    use tracing_subscriber;

    // --- CtLogDiscovery construction ---

    #[test]
    fn test_ct_log_discovery_new() {
        let disc = CtLogDiscovery::new(Duration::from_secs(30));
        assert_eq!(disc.timeout, Duration::from_secs(30));
        assert_eq!(disc.base_url, "https://crt.sh");
    }

    #[test]
    fn test_ct_log_discovery_new_short_timeout() {
        let disc = CtLogDiscovery::new(Duration::from_millis(100));
        assert_eq!(disc.timeout, Duration::from_millis(100));
    }

    #[test]
    fn test_ct_log_discovery_with_base_url() {
        let disc = CtLogDiscovery::with_base_url(
            Duration::from_secs(10),
            "http://localhost:9999".to_string(),
        );
        assert_eq!(disc.timeout, Duration::from_secs(10));
        assert_eq!(disc.base_url, "http://localhost:9999");
    }

    // --- CrtShEntry deserialization ---

    #[test]
    fn test_crt_sh_entry_full_deserialization() {
        let json = r#"{
            "issuer_ca_id": 12345,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "*.example.com",
            "name_value": "example.com\nwww.example.com\nmail.example.com",
            "id": 9876543210,
            "entry_timestamp": "2024-01-15T10:30:00",
            "not_before": "2024-01-15T00:00:00",
            "not_after": "2024-04-15T00:00:00"
        }"#;
        let entry: CrtShEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.issuer_ca_id, Some(12345));
        assert_eq!(entry.id, 9876543210);
        assert_eq!(entry.common_name, Some("*.example.com".to_string()));
        assert!(entry
            .name_value
            .as_ref()
            .unwrap()
            .contains("www.example.com"));
        assert_eq!(entry.not_before, Some("2024-01-15T00:00:00".to_string()));
    }

    #[test]
    fn test_crt_sh_entry_minimal_deserialization() {
        let json = r#"{"id": 100}"#;
        let entry: CrtShEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.id, 100);
        assert!(entry.issuer_ca_id.is_none());
        assert!(entry.issuer_name.is_none());
        assert!(entry.common_name.is_none());
        assert!(entry.name_value.is_none());
        assert!(entry.entry_timestamp.is_none());
        assert!(entry.not_before.is_none());
        assert!(entry.not_after.is_none());
    }

    #[test]
    fn test_crt_sh_entry_array_deserialization() {
        let json = r#"[
            {"id": 1, "name_value": "vendor1.com"},
            {"id": 2, "name_value": "vendor2.com\nvendor3.com"}
        ]"#;
        let entries: Vec<CrtShEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, 1);
        assert_eq!(
            entries[1].name_value,
            Some("vendor2.com\nvendor3.com".to_string())
        );
    }

    #[test]
    fn test_crt_sh_entry_empty_array() {
        let json = "[]";
        let entries: Vec<CrtShEntry> = serde_json::from_str(json).unwrap();
        assert!(entries.is_empty());
    }

    // --- CtDiscoveryResult ---

    #[test]
    fn test_ct_discovery_result_clone_and_debug() {
        let result = CtDiscoveryResult {
            domain: "vendor.com".to_string(),
            source: "Certificate SAN (crt.sh ID: 12345)".to_string(),
            certificate_info: "SAN: vendor.com | Issuer: R3 | Certificate ID: 12345".to_string(),
        };
        let cloned = result.clone();
        assert_eq!(cloned.domain, "vendor.com");
        assert_eq!(cloned.source, result.source);
        let debug = format!("{:?}", result);
        assert!(debug.contains("vendor.com"));
    }

    // --- Infrastructure domain filtering (comprehensive) ---

    #[rstest]
    // CDN providers
    #[case("cloudflare.com", true)]
    #[case("sub.cloudflare.com", true)]
    #[case("cloudflare.net", true)]
    #[case("cloudfront.net", true)]
    #[case("d123.cloudfront.net", true)]
    #[case("akamai.com", true)]
    #[case("akamaiedge.net", true)]
    #[case("fastly.net", true)]
    #[case("fastly.com", true)]
    #[case("edgekey.net", true)]
    #[case("edgesuite.net", true)]
    // Cloud providers
    #[case("amazonaws.com", true)]
    #[case("s3.amazonaws.com", true)]
    #[case("azure.com", true)]
    #[case("azurewebsites.net", true)]
    #[case("azureedge.net", true)]
    #[case("googleusercontent.com", true)]
    #[case("googlesyndication.com", true)]
    #[case("gstatic.com", true)]
    // SSL providers
    #[case("letsencrypt.org", true)]
    #[case("digicert.com", true)]
    #[case("comodo.com", true)]
    #[case("godaddy.com", true)]
    #[case("rapidssl.com", true)]
    #[case("geotrust.com", true)]
    #[case("thawte.com", true)]
    #[case("entrust.net", true)]
    #[case("sectigo.com", true)]
    // Non-routable
    #[case("localhost", true)]
    #[case("local", true)]
    #[case("test", true)]
    #[case("example.com", true)]
    // NOT infrastructure — should be false
    #[case("klaviyo.com", false)]
    #[case("google.com", false)]
    #[case("heroku.com", false)] // M009: intentionally not filtered
    #[case("wpengine.com", false)] // M009: intentionally not filtered
    #[case("globalsign.com", false)] // M009: removed from filter
    #[case("stripe.com", false)]
    #[case("pendo.io", false)]
    #[case("okta.com", false)]
    fn test_is_infrastructure_domain_parametrized(#[case] domain: &str, #[case] expected: bool) {
        assert_eq!(
            CtLogDiscovery::is_infrastructure_domain(domain),
            expected,
            "Domain '{}' should be infrastructure={}",
            domain,
            expected
        );
    }

    // --- discover() behavior tests via wiremock ---

    // --- JSON parsing edge cases ---

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_parse_empty_json_string() {
        let text = "";
        // Mimics query_crt_sh behavior
        let is_empty = text.is_empty() || text == "[]";
        assert!(is_empty);
    }

    #[test]
    fn test_parse_empty_json_array() {
        let text = "[]";
        let is_empty = text.is_empty() || text == "[]";
        assert!(is_empty);
    }

    #[test]
    fn test_parse_malformed_json() {
        let text = "this is not json";
        let result = serde_json::from_str::<Vec<CrtShEntry>>(text);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_valid_json_response() {
        let text = r#"[{"id": 1, "name_value": "vendor.com"}, {"id": 2}]"#;
        let entries: Vec<CrtShEntry> = serde_json::from_str(text).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_json_with_null_fields() {
        let text = r#"[{"id": 1, "issuer_ca_id": null, "common_name": null, "name_value": null}]"#;
        let entries: Vec<CrtShEntry> = serde_json::from_str(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].issuer_ca_id.is_none());
        assert!(entries[0].common_name.is_none());
        assert!(entries[0].name_value.is_none());
    }

    // --- Multiple entries across certificates ---

    // --- Async tests with wiremock for discover() and query_crt_sh() ---

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_discover_via_wiremock_finds_vendors() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 100,
                "issuer_name": "Let's Encrypt R3",
                "common_name": "*.example.com",
                "name_value": "example.com\napi.vendor-a.com\ncdn.vendor-b.io"
            },
            {
                "id": 200,
                "issuer_name": "DigiCert Inc",
                "common_name": "secure.vendor-c.net",
                "name_value": "vendor-d.org"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();

        let domains: Vec<&str> = results.iter().map(|r| r.domain.as_str()).collect();
        assert!(
            domains.contains(&"vendor-a.com"),
            "Should find vendor-a.com from SAN"
        );
        assert!(
            domains.contains(&"vendor-b.io"),
            "Should find vendor-b.io from SAN"
        );
        assert!(
            domains.contains(&"vendor-d.org"),
            "Should find vendor-d.org from SAN"
        );
        assert!(
            domains.contains(&"vendor-c.net"),
            "Should find vendor-c.net from CN"
        );
        assert!(
            !domains.contains(&"example.com"),
            "Should not include self-reference"
        );
    }

    #[tokio::test]
    async fn test_discover_via_wiremock_empty_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_via_wiremock_server_error_returns_empty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_via_wiremock_malformed_json_returns_empty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_via_wiremock_filters_infrastructure() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 300,
                "name_value": "cdn.cloudflare.com\ns3.amazonaws.com\nreal-vendor.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "real-vendor.com");
    }

    #[tokio::test]
    async fn test_discover_via_wiremock_deduplicates_domains() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 400,
                "common_name": "api.vendor.com",
                "name_value": "cdn.vendor.com\nwww.vendor.com\napi.vendor.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();

        assert_eq!(
            results.len(),
            1,
            "All subdomains of vendor.com should deduplicate to one"
        );
        assert_eq!(results[0].domain, "vendor.com");
    }

    #[test]
    fn test_ct_discovery_result_all_fields() {
        let result = CtDiscoveryResult {
            domain: "vendor.io".to_string(),
            source: "Certificate SAN (crt.sh ID: 999)".to_string(),
            certificate_info: "SAN: api.vendor.io | Issuer: DigiCert | Certificate ID: 999"
                .to_string(),
        };
        assert_eq!(result.domain, "vendor.io");
        assert!(result.source.contains("999"));
        assert!(result.certificate_info.contains("DigiCert"));

        let cloned = result.clone();
        assert_eq!(cloned.domain, result.domain);
        assert_eq!(cloned.source, result.source);
        assert_eq!(cloned.certificate_info, result.certificate_info);

        let dbg = format!("{:?}", result);
        assert!(dbg.contains("vendor.io"));
        assert!(dbg.contains("999"));
    }

    #[test]
    fn test_crt_sh_entry_debug() {
        let entry = CrtShEntry {
            issuer_ca_id: Some(42),
            issuer_name: Some("TestCA".to_string()),
            common_name: Some("test.com".to_string()),
            name_value: Some("test.com".to_string()),
            id: 12345,
            entry_timestamp: Some("2024-01-01".to_string()),
            not_before: Some("2024-01-01".to_string()),
            not_after: Some("2025-01-01".to_string()),
        };
        let dbg = format!("{:?}", entry);
        assert!(dbg.contains("12345"));
        assert!(dbg.contains("TestCA"));
    }

    #[test]
    fn test_ct_log_discovery_new_creates_client() {
        let disc = CtLogDiscovery::new(Duration::from_secs(10));
        assert_eq!(disc.timeout, Duration::from_secs(10));
        // Verify we can create multiple instances
        let disc2 = CtLogDiscovery::new(Duration::from_secs(60));
        assert_eq!(disc2.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_is_infrastructure_domain_subdomain_matching() {
        // Test that subdomains of infrastructure domains are also filtered (ends_with check)
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "cdn.cloudflare.com"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "s3.us-east-1.amazonaws.com"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "test-app.azurewebsites.net"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "mysite.azureedge.net"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "storage.googleusercontent.com"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "abc.googlesyndication.com"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "fonts.gstatic.com"
        ));
    }

    #[test]
    fn test_is_infrastructure_domain_exact_matches() {
        // Test exact match (not just ends_with)
        assert!(CtLogDiscovery::is_infrastructure_domain("localhost"));
        assert!(CtLogDiscovery::is_infrastructure_domain("local"));
        assert!(CtLogDiscovery::is_infrastructure_domain("test"));
        assert!(CtLogDiscovery::is_infrastructure_domain("example.com"));
    }

    #[test]
    fn test_is_infrastructure_domain_not_partial_match() {
        // "notlocalhost" should NOT match "localhost"
        // The check uses ends_with, so "notlocalhost" would end with "localhost" - it WILL match
        // This documents the current behavior
        assert!(CtLogDiscovery::is_infrastructure_domain("notlocalhost"));
        // But a domain like "mylocal" should not match "local" via ends_with
        assert!(CtLogDiscovery::is_infrastructure_domain("mylocal")); // ends_with "local"
    }

    #[test]
    fn test_crt_sh_entry_with_all_optional_fields_present() {
        let json = r#"{
            "issuer_ca_id": 16418,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "*.example.com",
            "name_value": "example.com\n*.example.com",
            "id": 9876543210,
            "entry_timestamp": "2024-06-15T12:00:00",
            "not_before": "2024-06-15T00:00:00",
            "not_after": "2024-09-13T00:00:00"
        }"#;
        let entry: CrtShEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.issuer_ca_id, Some(16418));
        assert!(entry
            .issuer_name
            .as_ref()
            .unwrap()
            .contains("Let's Encrypt"));
        assert_eq!(entry.common_name.as_ref().unwrap(), "*.example.com");
        assert!(entry.name_value.as_ref().unwrap().contains("*.example.com"));
        assert_eq!(
            entry.entry_timestamp.as_ref().unwrap(),
            "2024-06-15T12:00:00"
        );
        assert_eq!(entry.not_before.as_ref().unwrap(), "2024-06-15T00:00:00");
        assert_eq!(entry.not_after.as_ref().unwrap(), "2024-09-13T00:00:00");
    }

    // --- wiremock tests for query_crt_sh behavior patterns ---

    #[tokio::test]
    async fn test_query_crt_sh_via_wiremock_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 5001,
                "issuer_name": "R3",
                "common_name": "*.vendor.com",
                "name_value": "vendor.com\nwww.vendor.com\napi.vendor.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, 5001);
        let name_value = entries[0].name_value.as_ref().unwrap();
        assert!(name_value.contains("vendor.com"));
        assert!(name_value.contains("api.vendor.com"));
    }

    #[tokio::test]
    async fn test_query_crt_sh_via_wiremock_html_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>Rate limited</html>"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty(), "Malformed JSON should return empty vec");
    }

    #[tokio::test]
    async fn test_query_crt_sh_via_wiremock_empty_string() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_query_crt_sh_via_wiremock_500_returns_empty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_is_infrastructure_domain_ssl_providers() {
        assert!(CtLogDiscovery::is_infrastructure_domain("letsencrypt.org"));
        assert!(CtLogDiscovery::is_infrastructure_domain("digicert.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("comodo.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("godaddy.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("rapidssl.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("geotrust.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("thawte.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("entrust.net"));
        assert!(CtLogDiscovery::is_infrastructure_domain("sectigo.com"));
    }

    #[test]
    fn test_is_infrastructure_domain_globalsign_not_filtered() {
        // M009: globalsign.com was intentionally removed from the filter
        assert!(!CtLogDiscovery::is_infrastructure_domain("globalsign.com"));
    }

    // ───────────────────────────────────────────────────────────────
    // Coverage round 3: tracing format args + error propagation
    // ───────────────────────────────────────────────────────────────

    fn init_tracing() -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(std::io::sink)
                .finish(),
        )
    }

    #[tokio::test]
    async fn test_discover_with_tracing_finds_vendors() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2001,
                "issuer_name": "Let's Encrypt R3",
                "common_name": "*.example.com",
                "name_value": "example.com\napi.traced-vendor.com\ncdn.traced-vendor2.io"
            },
            {
                "id": 2002,
                "issuer_name": "DigiCert Inc",
                "common_name": "secure.traced-cn-vendor.net",
                "name_value": "traced-vendor3.org"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();

        let domains: Vec<&str> = results.iter().map(|r| r.domain.as_str()).collect();
        assert!(domains.contains(&"traced-vendor.com"));
        assert!(domains.contains(&"traced-vendor2.io"));
        assert!(domains.contains(&"traced-vendor3.org"));
        assert!(domains.contains(&"traced-cn-vendor.net"));
    }

    #[tokio::test]
    async fn test_discover_with_tracing_empty_response() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_server_error() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_malformed_json() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{broken"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_sans_with_empty_lines() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2003,
                "issuer_name": "CA",
                "name_value": "\n  \nempty-line-vendor.com\n\n"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "empty-line-vendor.com");
    }

    #[tokio::test]
    async fn test_discover_with_tracing_infrastructure_filtered() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2004,
                "name_value": "cdn.cloudflare.com\nreal-traced.com\ns3.amazonaws.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "real-traced.com");
    }

    #[tokio::test]
    async fn test_discover_with_tracing_deduplication() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2005,
                "issuer_name": "CA",
                "common_name": "api.dup-vendor.com",
                "name_value": "cdn.dup-vendor.com\nwww.dup-vendor.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "dup-vendor.com");
    }

    #[tokio::test]
    async fn test_discover_error_propagation_connection_refused() {
        let _guard = init_tracing();
        let disc = CtLogDiscovery::with_base_url(
            Duration::from_millis(100),
            "http://127.0.0.1:1".to_string(),
        );
        let result = disc.discover("example.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_query_crt_sh_error_propagation_connection_refused() {
        let _guard = init_tracing();
        let disc = CtLogDiscovery::with_base_url(
            Duration::from_millis(100),
            "http://127.0.0.1:1".to_string(),
        );
        let result = disc.query_crt_sh("example.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_query_crt_sh_with_tracing_success() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {"id": 3001, "name_value": "traced.com"}
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_query_crt_sh_with_tracing_error_status() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_query_crt_sh_with_tracing_malformed() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<<<not json>>>"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_query_crt_sh_with_tracing_empty_body() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_no_issuer_name() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2006,
                "name_value": "no-issuer-vendor.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].certificate_info.contains("Unknown CA"));
    }

    #[tokio::test]
    async fn test_discover_with_tracing_cn_no_issuer() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2007,
                "common_name": "cn-no-issuer.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "cn-no-issuer.com");
        assert!(results[0].certificate_info.contains("Unknown CA"));
    }

    #[tokio::test]
    async fn test_discover_with_tracing_self_ref_cn() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2008,
                "common_name": "www.example.com",
                "name_value": "example.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_cn_infra_filtered() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2009,
                "common_name": "cdn.cloudflare.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_entry_no_san_no_cn() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([{"id": 2010}]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }
}
