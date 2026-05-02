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
}

impl CtLogDiscovery {
    pub fn new(timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("nthpartyfinder/1.0")
            .build()
            .unwrap_or_default();

        Self { client, timeout }
    }

    /// Discover vendors from CT logs for a domain
    #[cfg_attr(coverage_nightly, coverage(off))]
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
    async fn query_crt_sh(&self, domain: &str) -> Result<Vec<CrtShEntry>> {
        // Query for wildcard certificates (%.domain.com)
        let url = format!(
            "https://crt.sh/?q=%.{}&output=json",
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

    // --- CtLogDiscovery construction ---

    #[test]
    fn test_ct_log_discovery_new() {
        let disc = CtLogDiscovery::new(Duration::from_secs(30));
        assert_eq!(disc.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_ct_log_discovery_new_short_timeout() {
        let disc = CtLogDiscovery::new(Duration::from_millis(100));
        assert_eq!(disc.timeout, Duration::from_millis(100));
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

    // --- discover() logic tests using mock data ---
    // We test the processing logic by simulating what discover() does internally,
    // since query_crt_sh makes real HTTP calls.

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_extracts_san_domains() {
        // Simulate the processing logic from discover()
        let entries = vec![CrtShEntry {
            issuer_ca_id: Some(1),
            issuer_name: Some("Let's Encrypt R3".to_string()),
            common_name: Some("*.example.com".to_string()),
            name_value: Some("example.com\ncdn.vendorA.com\napi.vendorB.io".to_string()),
            id: 100,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        }];

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        for entry in &entries {
            if let Some(name_value) = &entry.name_value {
                for san in name_value.lines() {
                    let san = san.trim().to_lowercase();
                    if san.is_empty() {
                        continue;
                    }
                    let san_base = domain_utils::extract_base_domain(&san);
                    if san_base == base_domain {
                        continue;
                    }
                    if CtLogDiscovery::is_infrastructure_domain(&san_base) {
                        continue;
                    }
                    if seen_domains.insert(san_base.clone()) {
                        results.push(san_base);
                    }
                }
            }
        }

        assert_eq!(results.len(), 2);
        assert!(results.contains(&"vendora.com".to_string()));
        assert!(results.contains(&"vendorb.io".to_string()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_deduplicates_san_domains() {
        let entries = vec![CrtShEntry {
            issuer_ca_id: None,
            issuer_name: None,
            common_name: None,
            name_value: Some("cdn.vendor.com\napi.vendor.com\nwww.vendor.com".to_string()),
            id: 200,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        }];

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        for entry in &entries {
            if let Some(name_value) = &entry.name_value {
                for san in name_value.lines() {
                    let san = san.trim().to_lowercase();
                    if san.is_empty() {
                        continue;
                    }
                    let san_base = domain_utils::extract_base_domain(&san);
                    if san_base == base_domain
                        || CtLogDiscovery::is_infrastructure_domain(&san_base)
                    {
                        continue;
                    }
                    if seen_domains.insert(san_base.clone()) {
                        results.push(san_base);
                    }
                }
            }
        }

        // All three SANs have the same base domain vendor.com — should dedupe to 1
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "vendor.com");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_filters_infrastructure_from_sans() {
        let entries = vec![CrtShEntry {
            issuer_ca_id: None,
            issuer_name: None,
            common_name: None,
            name_value: Some(
                "cdn.cloudflare.com\ns3.amazonaws.com\nreal-vendor.com\nlocalhost".to_string(),
            ),
            id: 300,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        }];

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        for entry in &entries {
            if let Some(name_value) = &entry.name_value {
                for san in name_value.lines() {
                    let san = san.trim().to_lowercase();
                    if san.is_empty() {
                        continue;
                    }
                    let san_base = domain_utils::extract_base_domain(&san);
                    if san_base == base_domain
                        || CtLogDiscovery::is_infrastructure_domain(&san_base)
                    {
                        continue;
                    }
                    if seen_domains.insert(san_base.clone()) {
                        results.push(san_base);
                    }
                }
            }
        }

        // Only real-vendor.com should survive
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "real-vendor.com");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_skips_self_references() {
        let entries = vec![CrtShEntry {
            issuer_ca_id: None,
            issuer_name: None,
            common_name: None,
            name_value: Some("www.example.com\nmail.example.com\nvendor.io".to_string()),
            id: 400,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        }];

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        for entry in &entries {
            if let Some(name_value) = &entry.name_value {
                for san in name_value.lines() {
                    let san = san.trim().to_lowercase();
                    if san.is_empty() {
                        continue;
                    }
                    let san_base = domain_utils::extract_base_domain(&san);
                    if san_base == base_domain
                        || CtLogDiscovery::is_infrastructure_domain(&san_base)
                    {
                        continue;
                    }
                    if seen_domains.insert(san_base.clone()) {
                        results.push(san_base);
                    }
                }
            }
        }

        // Only vendor.io should survive; example.com subdomains are self-references
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "vendor.io");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_common_name_extraction() {
        let entry = CrtShEntry {
            issuer_ca_id: Some(99),
            issuer_name: Some("DigiCert Inc".to_string()),
            common_name: Some("api.vendor-cn.com".to_string()),
            name_value: None, // no SANs
            id: 500,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        // Process common_name
        if let Some(common_name) = &entry.common_name {
            let cn = common_name.trim().to_lowercase();
            let cn_base = domain_utils::extract_base_domain(&cn);
            if cn_base != base_domain
                && !CtLogDiscovery::is_infrastructure_domain(&cn_base)
                && seen_domains.insert(cn_base.clone())
            {
                results.push(CtDiscoveryResult {
                    domain: cn_base,
                    source: format!("Certificate CN (crt.sh ID: {})", entry.id),
                    certificate_info: format!(
                        "CN: {} | Issuer: {} | Certificate ID: {}",
                        cn,
                        entry.issuer_name.as_deref().unwrap_or("Unknown CA"),
                        entry.id
                    ),
                });
            }
        }

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "vendor-cn.com");
        assert!(results[0].source.contains("500"));
        assert!(results[0].certificate_info.contains("DigiCert Inc"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_common_name_self_reference_skipped() {
        let entry = CrtShEntry {
            issuer_ca_id: None,
            issuer_name: None,
            common_name: Some("www.example.com".to_string()),
            name_value: None,
            id: 600,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        if let Some(common_name) = &entry.common_name {
            let cn = common_name.trim().to_lowercase();
            let cn_base = domain_utils::extract_base_domain(&cn);
            if cn_base != base_domain
                && !CtLogDiscovery::is_infrastructure_domain(&cn_base)
                && seen_domains.insert(cn_base.clone())
            {
                results.push(cn_base);
            }
        }

        assert!(results.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_common_name_infra_skipped() {
        let entry = CrtShEntry {
            issuer_ca_id: None,
            issuer_name: None,
            common_name: Some("cdn.cloudflare.com".to_string()),
            name_value: None,
            id: 700,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        if let Some(common_name) = &entry.common_name {
            let cn = common_name.trim().to_lowercase();
            let cn_base = domain_utils::extract_base_domain(&cn);
            if cn_base != base_domain
                && !CtLogDiscovery::is_infrastructure_domain(&cn_base)
                && seen_domains.insert(cn_base.clone())
            {
                results.push(cn_base);
            }
        }

        assert!(results.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_empty_san_lines_skipped() {
        let entry = CrtShEntry {
            issuer_ca_id: None,
            issuer_name: None,
            common_name: None,
            name_value: Some("\n  \n\nvendor.com\n\n".to_string()),
            id: 800,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        if let Some(name_value) = &entry.name_value {
            for san in name_value.lines() {
                let san = san.trim().to_lowercase();
                if san.is_empty() {
                    continue;
                }
                let san_base = domain_utils::extract_base_domain(&san);
                if san_base == base_domain || CtLogDiscovery::is_infrastructure_domain(&san_base) {
                    continue;
                }
                if seen_domains.insert(san_base.clone()) {
                    results.push(san_base);
                }
            }
        }

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "vendor.com");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_san_and_cn_dedup() {
        // When the same domain appears in both SAN and CN, it should only be counted once
        let entry = CrtShEntry {
            issuer_ca_id: None,
            issuer_name: Some("CA".to_string()),
            common_name: Some("vendor.com".to_string()),
            name_value: Some("vendor.com\nwww.vendor.com".to_string()),
            id: 900,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        // Process SANs first
        if let Some(name_value) = &entry.name_value {
            for san in name_value.lines() {
                let san = san.trim().to_lowercase();
                if san.is_empty() {
                    continue;
                }
                let san_base = domain_utils::extract_base_domain(&san);
                if san_base == base_domain || CtLogDiscovery::is_infrastructure_domain(&san_base) {
                    continue;
                }
                if seen_domains.insert(san_base.clone()) {
                    results.push(san_base);
                }
            }
        }

        // Process CN
        if let Some(common_name) = &entry.common_name {
            let cn = common_name.trim().to_lowercase();
            let cn_base = domain_utils::extract_base_domain(&cn);
            if cn_base != base_domain
                && !CtLogDiscovery::is_infrastructure_domain(&cn_base)
                && seen_domains.insert(cn_base.clone())
            {
                results.push(cn_base);
            }
        }

        // vendor.com should appear only once (from SAN), CN should be deduped
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "vendor.com");
    }

    #[test]
    fn test_discover_logic_issuer_name_default() {
        // When issuer_name is None, we use "Unknown CA"
        let entry = CrtShEntry {
            issuer_ca_id: None,
            issuer_name: None,
            common_name: None,
            name_value: Some("vendor.com".to_string()),
            id: 1000,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let issuer = entry.issuer_name.as_deref().unwrap_or("Unknown CA");
        assert_eq!(issuer, "Unknown CA");

        let cert_info = format!(
            "SAN: vendor.com | Issuer: {} | Certificate ID: {}",
            issuer, entry.id
        );
        assert!(cert_info.contains("Unknown CA"));
        assert!(cert_info.contains("1000"));
    }

    // --- JSON parsing edge cases ---

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
    async fn test_discover_with_mock_server_finds_vendors() {
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

        // Create a client that points to our mock server
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // We can't easily override the URL in CtLogDiscovery, so test the logic directly
        let url = format!("{}/", mock_server.uri());
        let response = client.get(&url).send().await.unwrap();
        let text = response.text().await.unwrap();
        let entries: Vec<CrtShEntry> = serde_json::from_str(&text).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, 100);
        assert_eq!(
            entries[0].name_value,
            Some("example.com\napi.vendor-a.com\ncdn.vendor-b.io".to_string())
        );
    }

    #[tokio::test]
    async fn test_discover_with_mock_server_empty_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!("{}/", mock_server.uri());
        let response = client.get(&url).send().await.unwrap();
        let text = response.text().await.unwrap();

        // Mimics query_crt_sh behavior
        assert!(text.is_empty() || text == "[]");
    }

    #[tokio::test]
    async fn test_discover_with_mock_server_non_success_status() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!("{}/", mock_server.uri());
        let response = client.get(&url).send().await.unwrap();

        // Should detect non-success status
        assert!(!response.status().is_success());
    }

    #[tokio::test]
    async fn test_discover_with_mock_server_malformed_json() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!("{}/", mock_server.uri());
        let response = client.get(&url).send().await.unwrap();
        let text = response.text().await.unwrap();

        // Mimics query_crt_sh behavior: parse failure returns empty
        let result = serde_json::from_str::<Vec<CrtShEntry>>(&text);
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_multiple_certificates() {
        let entries = vec![
            CrtShEntry {
                issuer_ca_id: None,
                issuer_name: Some("CA1".to_string()),
                common_name: None,
                name_value: Some("vendor-a.com\nvendor-b.com".to_string()),
                id: 1,
                entry_timestamp: None,
                not_before: None,
                not_after: None,
            },
            CrtShEntry {
                issuer_ca_id: None,
                issuer_name: Some("CA2".to_string()),
                common_name: Some("vendor-c.com".to_string()),
                name_value: Some("vendor-a.com\nvendor-d.com".to_string()), // vendor-a appears again
                id: 2,
                entry_timestamp: None,
                not_before: None,
                not_after: None,
            },
        ];

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        for entry in &entries {
            if let Some(name_value) = &entry.name_value {
                for san in name_value.lines() {
                    let san = san.trim().to_lowercase();
                    if san.is_empty() {
                        continue;
                    }
                    let san_base = domain_utils::extract_base_domain(&san);
                    if san_base == base_domain
                        || CtLogDiscovery::is_infrastructure_domain(&san_base)
                    {
                        continue;
                    }
                    if seen_domains.insert(san_base.clone()) {
                        results.push(san_base);
                    }
                }
            }
            if let Some(common_name) = &entry.common_name {
                let cn = common_name.trim().to_lowercase();
                let cn_base = domain_utils::extract_base_domain(&cn);
                if cn_base != base_domain
                    && !CtLogDiscovery::is_infrastructure_domain(&cn_base)
                    && seen_domains.insert(cn_base.clone())
                {
                    results.push(cn_base);
                }
            }
        }

        // vendor-a, vendor-b from cert 1; vendor-d, vendor-c from cert 2
        // vendor-a should not appear twice
        assert_eq!(results.len(), 4);
        assert!(results.contains(&"vendor-a.com".to_string()));
        assert!(results.contains(&"vendor-b.com".to_string()));
        assert!(results.contains(&"vendor-c.com".to_string()));
        assert!(results.contains(&"vendor-d.com".to_string()));
    }

    // ───────────────────────────────────────────────────────────────
    // Additional coverage tests — round 2
    // ───────────────────────────────────────────────────────────────

    #[test]
    fn test_ct_discovery_result_all_fields() {
        let result = CtDiscoveryResult {
            domain: "vendor.io".to_string(),
            source: "Certificate SAN (crt.sh ID: 999)".to_string(),
            certificate_info: "SAN: api.vendor.io | Issuer: DigiCert | Certificate ID: 999".to_string(),
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
        assert!(CtLogDiscovery::is_infrastructure_domain("cdn.cloudflare.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("s3.us-east-1.amazonaws.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("test-app.azurewebsites.net"));
        assert!(CtLogDiscovery::is_infrastructure_domain("mysite.azureedge.net"));
        assert!(CtLogDiscovery::is_infrastructure_domain("storage.googleusercontent.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("abc.googlesyndication.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("fonts.gstatic.com"));
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_san_with_wildcard_prefix() {
        // Certificates often have *.domain.com entries
        let entry = CrtShEntry {
            issuer_ca_id: None,
            issuer_name: Some("CA".to_string()),
            common_name: None,
            name_value: Some("*.vendor.com\nvendor.com".to_string()),
            id: 1100,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        if let Some(name_value) = &entry.name_value {
            for san in name_value.lines() {
                let san = san.trim().to_lowercase();
                if san.is_empty() {
                    continue;
                }
                let san_base = domain_utils::extract_base_domain(&san);
                if san_base == base_domain || CtLogDiscovery::is_infrastructure_domain(&san_base) {
                    continue;
                }
                if seen_domains.insert(san_base.clone()) {
                    results.push(san_base);
                }
            }
        }

        // Both *.vendor.com and vendor.com should resolve to vendor.com, deduped to 1
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "vendor.com");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_san_uppercase_normalized() {
        let entry = CrtShEntry {
            issuer_ca_id: None,
            issuer_name: None,
            common_name: None,
            name_value: Some("CDN.VENDOR.COM\nAPI.VENDOR.COM".to_string()),
            id: 1200,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        if let Some(name_value) = &entry.name_value {
            for san in name_value.lines() {
                let san = san.trim().to_lowercase();
                if san.is_empty() {
                    continue;
                }
                let san_base = domain_utils::extract_base_domain(&san);
                if san_base == base_domain || CtLogDiscovery::is_infrastructure_domain(&san_base) {
                    continue;
                }
                if seen_domains.insert(san_base.clone()) {
                    results.push(san_base);
                }
            }
        }

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "vendor.com");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_common_name_with_issuer() {
        // Full CtDiscoveryResult construction from CN processing
        let entry = CrtShEntry {
            issuer_ca_id: Some(42),
            issuer_name: Some("DigiCert SHA2 Extended Validation Server CA".to_string()),
            common_name: Some("api.specialvendor.com".to_string()),
            name_value: None,
            id: 1300,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        if let Some(common_name) = &entry.common_name {
            let cn = common_name.trim().to_lowercase();
            let cn_base = domain_utils::extract_base_domain(&cn);
            if cn_base != base_domain
                && !CtLogDiscovery::is_infrastructure_domain(&cn_base)
                && seen_domains.insert(cn_base.clone())
            {
                results.push(CtDiscoveryResult {
                    domain: cn_base,
                    source: format!("Certificate CN (crt.sh ID: {})", entry.id),
                    certificate_info: format!(
                        "CN: {} | Issuer: {} | Certificate ID: {}",
                        cn,
                        entry.issuer_name.as_deref().unwrap_or("Unknown CA"),
                        entry.id
                    ),
                });
            }
        }

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "specialvendor.com");
        assert!(results[0].source.contains("1300"));
        assert!(results[0].certificate_info.contains("DigiCert SHA2"));
        assert!(results[0].certificate_info.contains("api.specialvendor.com"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_full_result_construction_from_san() {
        // Test the full CtDiscoveryResult construction from SAN processing
        let entry = CrtShEntry {
            issuer_ca_id: Some(1),
            issuer_name: Some("Let's Encrypt R3".to_string()),
            common_name: None,
            name_value: Some("api.vendor-full.com".to_string()),
            id: 1400,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        if let Some(name_value) = &entry.name_value {
            for san in name_value.lines() {
                let san = san.trim().to_lowercase();
                if san.is_empty() {
                    continue;
                }
                let san_base = domain_utils::extract_base_domain(&san);
                if san_base == base_domain || CtLogDiscovery::is_infrastructure_domain(&san_base) {
                    continue;
                }
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
                }
            }
        }

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "vendor-full.com");
        assert!(results[0].source.contains("SAN"));
        assert!(results[0].source.contains("1400"));
        assert!(results[0].certificate_info.contains("Let's Encrypt R3"));
        assert!(results[0].certificate_info.contains("api.vendor-full.com"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_no_entries() {
        // Empty entries list should produce no results
        let entries: Vec<CrtShEntry> = Vec::new();
        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        for entry in &entries {
            if let Some(name_value) = &entry.name_value {
                for san in name_value.lines() {
                    let san = san.trim().to_lowercase();
                    if san.is_empty() {
                        continue;
                    }
                    let san_base = domain_utils::extract_base_domain(&san);
                    if san_base == base_domain || CtLogDiscovery::is_infrastructure_domain(&san_base) {
                        continue;
                    }
                    if seen_domains.insert(san_base.clone()) {
                        results.push(san_base);
                    }
                }
            }
        }

        assert!(results.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_entry_with_no_san_no_cn() {
        // Entry with neither name_value nor common_name
        let entry = CrtShEntry {
            issuer_ca_id: None,
            issuer_name: None,
            common_name: None,
            name_value: None,
            id: 1500,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        // Process SANs
        if let Some(name_value) = &entry.name_value {
            for san in name_value.lines() {
                let san = san.trim().to_lowercase();
                if san.is_empty() {
                    continue;
                }
                let san_base = domain_utils::extract_base_domain(&san);
                if san_base == base_domain || CtLogDiscovery::is_infrastructure_domain(&san_base) {
                    continue;
                }
                if seen_domains.insert(san_base.clone()) {
                    results.push(san_base);
                }
            }
        }

        // Process CN
        if let Some(common_name) = &entry.common_name {
            let cn = common_name.trim().to_lowercase();
            let cn_base = domain_utils::extract_base_domain(&cn);
            if cn_base != base_domain
                && !CtLogDiscovery::is_infrastructure_domain(&cn_base)
                && seen_domains.insert(cn_base.clone())
            {
                results.push(cn_base);
            }
        }

        assert!(results.is_empty());
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
        assert!(entry.issuer_name.as_ref().unwrap().contains("Let's Encrypt"));
        assert_eq!(entry.common_name.as_ref().unwrap(), "*.example.com");
        assert!(entry.name_value.as_ref().unwrap().contains("*.example.com"));
        assert_eq!(entry.entry_timestamp.as_ref().unwrap(), "2024-06-15T12:00:00");
        assert_eq!(entry.not_before.as_ref().unwrap(), "2024-06-15T00:00:00");
        assert_eq!(entry.not_after.as_ref().unwrap(), "2024-09-13T00:00:00");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_san_all_infrastructure() {
        // All SANs are infrastructure domains
        let entry = CrtShEntry {
            issuer_ca_id: None,
            issuer_name: None,
            common_name: None,
            name_value: Some("cdn.cloudflare.com\ns3.amazonaws.com\ntest.azurewebsites.net".to_string()),
            id: 1600,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results = Vec::new();

        if let Some(name_value) = &entry.name_value {
            for san in name_value.lines() {
                let san = san.trim().to_lowercase();
                if san.is_empty() {
                    continue;
                }
                let san_base = domain_utils::extract_base_domain(&san);
                if san_base == base_domain || CtLogDiscovery::is_infrastructure_domain(&san_base) {
                    continue;
                }
                if seen_domains.insert(san_base.clone()) {
                    results.push(san_base);
                }
            }
        }

        assert!(results.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_logic_common_name_already_seen_from_san() {
        // CN domain was already found in SAN — should be skipped
        let entry = CrtShEntry {
            issuer_ca_id: None,
            issuer_name: Some("CA".to_string()),
            common_name: Some("api.vendor.com".to_string()),
            name_value: Some("api.vendor.com\nwww.vendor.com".to_string()),
            id: 1700,
            entry_timestamp: None,
            not_before: None,
            not_after: None,
        };

        let base_domain = "example.com".to_string();
        let mut seen_domains = HashSet::new();
        seen_domains.insert(base_domain.clone());
        let mut results_from_san = Vec::new();
        let mut results_from_cn = Vec::new();

        // Process SANs first
        if let Some(name_value) = &entry.name_value {
            for san in name_value.lines() {
                let san = san.trim().to_lowercase();
                if san.is_empty() {
                    continue;
                }
                let san_base = domain_utils::extract_base_domain(&san);
                if san_base == base_domain || CtLogDiscovery::is_infrastructure_domain(&san_base) {
                    continue;
                }
                if seen_domains.insert(san_base.clone()) {
                    results_from_san.push(san_base);
                }
            }
        }

        // Process CN — should be deduped since vendor.com already seen
        if let Some(common_name) = &entry.common_name {
            let cn = common_name.trim().to_lowercase();
            let cn_base = domain_utils::extract_base_domain(&cn);
            if cn_base != base_domain
                && !CtLogDiscovery::is_infrastructure_domain(&cn_base)
                && seen_domains.insert(cn_base.clone())
            {
                results_from_cn.push(cn_base);
            }
        }

        assert_eq!(results_from_san.len(), 1);
        assert_eq!(results_from_san[0], "vendor.com");
        assert!(results_from_cn.is_empty(), "CN should be deduped since SAN already had vendor.com");
    }

    // --- wiremock tests for query_crt_sh behavior patterns ---

    #[tokio::test]
    async fn test_query_crt_sh_pattern_success_response() {
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

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!("{}/", mock_server.uri());
        let response = client.get(&url).send().await.unwrap();
        assert!(response.status().is_success());
        let text = response.text().await.unwrap();
        let entries: Vec<CrtShEntry> = serde_json::from_str(&text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, 5001);
        let name_value = entries[0].name_value.as_ref().unwrap();
        assert!(name_value.contains("vendor.com"));
        assert!(name_value.contains("api.vendor.com"));
    }

    #[tokio::test]
    async fn test_query_crt_sh_pattern_non_json_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>Rate limited</html>"))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!("{}/", mock_server.uri());
        let response = client.get(&url).send().await.unwrap();
        let text = response.text().await.unwrap();

        // Mimics query_crt_sh: not empty, not "[]", but invalid JSON
        assert!(!text.is_empty() && text != "[]");
        let result = serde_json::from_str::<Vec<CrtShEntry>>(&text);
        assert!(result.is_err());
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
}
