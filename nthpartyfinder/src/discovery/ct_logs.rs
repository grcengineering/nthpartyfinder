//! Certificate Transparency (CT) log discovery for finding third-party vendors.
//!
//! Queries crt.sh to find certificates associated with a domain and extracts
//! third-party domains from certificate Subject Alternative Names (SANs).

use anyhow::Result;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use reqwest::Client;
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

                        debug!("Found vendor {} from CT log certificate {}", san_base, cert_id);
                    }
                }
            }

            // Also check common_name if different from target
            if let Some(common_name) = &entry.common_name {
                let cn = common_name.trim().to_lowercase();
                let cn_base = domain_utils::extract_base_domain(&cn);

                if cn_base != base_domain && !Self::is_infrastructure_domain(&cn_base) {
                    if seen_domains.insert(cn_base.clone()) {
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
        }

        info!("CT log discovery found {} unique vendor domains for {}", results.len(), domain);
        Ok(results)
    }

    /// Query crt.sh for certificates related to a domain
    async fn query_crt_sh(&self, domain: &str) -> Result<Vec<CrtShEntry>> {
        // Query for wildcard certificates (%.domain.com)
        let url = format!(
            "https://crt.sh/?q=%.{}&output=json",
            urlencoding::encode(domain)
        );

        debug!("Querying crt.sh: {}", url);

        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await?;

        if !response.status().is_success() {
            warn!("crt.sh returned status {} for {}", response.status(), domain);
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

    /// Check if a domain is infrastructure/CDN that shouldn't be reported as a vendor
    fn is_infrastructure_domain(domain: &str) -> bool {
        let infrastructure_domains = [
            // CDN providers
            "cloudflare.com",
            "cloudflare.net",
            "cloudfront.net",
            "akamai.com",
            "akamaiedge.net",
            "fastly.net",
            "fastly.com",
            "edgekey.net",
            "edgesuite.net",
            // Cloud providers (as infrastructure)
            "amazonaws.com",
            "azure.com",
            "azurewebsites.net",
            "azureedge.net",
            "googleusercontent.com",
            "googlesyndication.com",
            "gstatic.com",
            // SSL/TLS providers (issuers)
            "letsencrypt.org",
            "digicert.com",
            "comodo.com",
            "godaddy.com",
            "rapidssl.com",
            "geotrust.com",
            "thawte.com",
            "entrust.net",
            "globalsign.com",
            "sectigo.com",
            // Other infrastructure
            "localhost",
            "local",
            "test",
            "example.com",
        ];

        infrastructure_domains.iter().any(|&infra| domain.ends_with(infra) || domain == infra)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_infrastructure_domain() {
        assert!(CtLogDiscovery::is_infrastructure_domain("cloudflare.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("sub.cloudflare.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("amazonaws.com"));
        assert!(!CtLogDiscovery::is_infrastructure_domain("klaviyo.com"));
        assert!(!CtLogDiscovery::is_infrastructure_domain("google.com"));
    }
}
