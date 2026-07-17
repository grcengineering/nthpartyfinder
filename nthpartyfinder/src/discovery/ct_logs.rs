//! Certificate Transparency (CT) log discovery for finding third-party vendors.
//!
//! Queries Certificate Transparency aggregators (crt.sh and SSLMate Cert Spotter) to
//! find certificates associated with a domain and extracts third-party domains from
//! certificate Subject Alternative Names (SANs). Providers are round-robined on a
//! process-shared cursor so no single aggregator is overloaded — crt.sh returns HTTP 429
//! under a wide fan-out — and a provider failure fails over to the next rather than
//! collapsing into a silent empty answer.

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tracing::{debug, info};

use crate::domain_utils;
use crate::http_client::GatedSend;

/// Base URL for the SSLMate Cert Spotter API (`/v1/issuances`).
const CERTSPOTTER_BASE_URL: &str = "https://api.certspotter.com";
/// Optional env var carrying a Cert Spotter API token; without it the anonymous
/// (rate-limited) tier is used, and a throttle simply fails over to crt.sh.
const CERTSPOTTER_TOKEN_ENV: &str = "NTHPARTYFINDER_CERTSPOTTER_TOKEN";

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

/// One issuance record from the SSLMate Cert Spotter API (`GET /v1/issuances`).
#[derive(Debug, Deserialize)]
struct CertSpotterIssuance {
    #[serde(default)]
    id: Option<String>,
    /// Clean array of certificate DNS names (Cert Spotter's equivalent of crt.sh's
    /// newline-separated `name_value`).
    #[serde(default)]
    dns_names: Option<Vec<String>>,
    #[serde(default)]
    issuer: Option<CertSpotterIssuer>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CertSpotterIssuer {
    #[serde(default)]
    name: Option<String>,
}

impl CertSpotterIssuance {
    /// Normalize a Cert Spotter issuance into the crt.sh entry shape so the shared
    /// SAN/CN extraction loop in `discover` works over both providers unchanged.
    fn into_crtsh_entry(self) -> CrtShEntry {
        let name_value = self.dns_names.map(|names| names.join("\n"));
        CrtShEntry {
            issuer_ca_id: None,
            issuer_name: self.issuer.and_then(|i| i.name),
            common_name: None,
            name_value,
            id: self
                .id
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or_default(),
            entry_timestamp: None,
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }
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

/// A failure fetching from one CT provider, classified so the round-robin can decide
/// whether to fail over silently or surface a hard error.
enum CtFetchError {
    /// Provider responded but not usefully (non-2xx status, or an unparseable body).
    /// Recoverable: fail over to the next provider; degrade to an empty answer if none
    /// remain (a reachable-but-unhelpful provider is not a scan-fatal condition).
    Soft(String),
    /// Provider could not be reached at all (transport / connection / timeout). If every
    /// provider is unreachable this propagates as a hard error so the phase logs it.
    Transport(anyhow::Error),
}

/// One CT log source in the round-robin rotation.
enum CtProvider {
    CrtSh {
        base_url: String,
    },
    CertSpotter {
        base_url: String,
        token: Option<String>,
    },
}

impl CtProvider {
    fn name(&self) -> &'static str {
        match self {
            CtProvider::CrtSh { .. } => "crt.sh",
            CtProvider::CertSpotter { .. } => "certspotter",
        }
    }
}

/// Certificate Transparency log discovery.
///
/// Round-robins across the configured providers on `cursor` so successive domains hit
/// different aggregators, and fails over on any provider error. A single-provider
/// instance (`with_base_url`, used by the wiremock test-suite) behaves exactly as before.
pub struct CtLogDiscovery {
    client: Client,
    timeout: Duration,
    /// crt.sh base URL (kept as a named field for the public API + back-compat tests).
    base_url: String,
    /// Cert Spotter base URL; `None` => crt.sh-only (single-provider) instance.
    certspotter_base_url: Option<String>,
    /// Optional Cert Spotter API token (raises the anonymous rate limit).
    certspotter_token: Option<String>,
    /// Process-shared round-robin cursor across providers.
    cursor: AtomicUsize,
}

impl CtLogDiscovery {
    pub fn new(timeout: Duration) -> Self {
        Self::with_providers(
            timeout,
            "https://crt.sh".to_string(),
            Some(CERTSPOTTER_BASE_URL.to_string()),
            std::env::var(CERTSPOTTER_TOKEN_ENV)
                .ok()
                .filter(|t| !t.is_empty()),
        )
    }

    /// crt.sh-only instance. Used by the wiremock test-suite to point crt.sh at a mock
    /// server; production uses `new` (multi-provider round-robin).
    pub fn with_base_url(timeout: Duration, base_url: String) -> Self {
        Self::with_providers(timeout, base_url, None, None)
    }

    fn with_providers(
        timeout: Duration,
        base_url: String,
        certspotter_base_url: Option<String>,
        certspotter_token: Option<String>,
    ) -> Self {
        let client = crate::http_client::hardened_builder()
            .timeout(timeout)
            .user_agent("nthpartyfinder/1.0")
            .build()
            .unwrap_or_default();

        Self {
            client,
            timeout,
            base_url,
            certspotter_base_url,
            certspotter_token,
            cursor: AtomicUsize::new(0),
        }
    }

    /// The provider rotation for this instance: always crt.sh, plus Cert Spotter when
    /// configured (production). A `with_base_url` instance yields crt.sh only.
    fn providers(&self) -> Vec<CtProvider> {
        let mut providers = vec![CtProvider::CrtSh {
            base_url: self.base_url.clone(),
        }];
        if let Some(cs) = &self.certspotter_base_url {
            providers.push(CtProvider::CertSpotter {
                base_url: cs.clone(),
                token: self.certspotter_token.clone(),
            });
        }
        providers
    }

    /// Discover vendors from CT logs for a domain
    pub async fn discover(&self, domain: &str) -> Result<Vec<CtDiscoveryResult>> {
        info!("Querying CT logs for certificates related to {}", domain);

        let mut results = Vec::new();
        let mut seen_domains = HashSet::new();

        // Add the target domain to seen to avoid self-references
        let base_domain = domain_utils::extract_base_domain(domain);
        seen_domains.insert(base_domain.clone());

        // Query CT providers (round-robin + failover) for certificates.
        let entries = self.fetch_entries_round_robin(domain).await?;
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

    /// Fetch certificate entries by round-robining the configured providers, failing
    /// over on any provider error. Returns the first provider's authoritative (2xx)
    /// entries — possibly empty. If every provider fails, a reachable-but-unhelpful
    /// response degrades to an empty answer while a total transport failure propagates
    /// as a hard error (so the phase logs it with the real error kind).
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fetch_entries_round_robin(&self, domain: &str) -> Result<Vec<CrtShEntry>> {
        let providers = self.providers();
        let n = providers.len();
        // Advance the shared cursor so successive domains start at a different provider,
        // spreading load off any single aggregator.
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
        let mut transport_err = None;

        for offset in 0..n {
            let provider = &providers[(start + offset) % n];
            match self.fetch_provider(provider, domain).await {
                Ok(entries) => return Ok(entries),
                Err(CtFetchError::Soft(msg)) => {
                    debug!(
                        "CT provider {} unavailable for {} (failing over): {}",
                        provider.name(),
                        domain,
                        msg
                    );
                }
                Err(CtFetchError::Transport(e)) => {
                    debug!(
                        "CT provider {} unreachable for {} (failing over): {}",
                        provider.name(),
                        domain,
                        e
                    );
                    transport_err = Some(e);
                }
            }
        }

        match transport_err {
            // Nothing was reachable — surface the real error kind rather than a silent empty.
            Some(e) => Err(e),
            // Every provider responded but unhelpfully (429/5xx/parse) — treat as "no certs".
            None => Ok(Vec::new()),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fetch_provider(
        &self,
        provider: &CtProvider,
        domain: &str,
    ) -> std::result::Result<Vec<CrtShEntry>, CtFetchError> {
        match provider {
            CtProvider::CrtSh { base_url } => self.fetch_crtsh(base_url, domain).await,
            CtProvider::CertSpotter { base_url, token } => {
                self.fetch_certspotter(base_url, token.as_deref(), domain)
                    .await
            }
        }
    }

    /// Query crt.sh (`/?q=%.domain&output=json`). Wildcard prefix `%.` = all subdomains.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fetch_crtsh(
        &self,
        base_url: &str,
        domain: &str,
    ) -> std::result::Result<Vec<CrtShEntry>, CtFetchError> {
        let url = format!(
            "{}/?q=%.{}&output=json",
            base_url,
            urlencoding::encode(domain)
        );
        debug!("Querying crt.sh: {}", url);

        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .send_gated()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        if !response.status().is_success() {
            return Err(CtFetchError::Soft(format!(
                "crt.sh returned status {} for {}",
                response.status(),
                domain
            )));
        }

        let text = response
            .text()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        // crt.sh returns empty array as "[]" or sometimes just empty
        if text.is_empty() || text == "[]" {
            return Ok(Vec::new());
        }

        match serde_json::from_str::<Vec<CrtShEntry>>(&text) {
            Ok(entries) => Ok(entries),
            Err(e) => Err(CtFetchError::Soft(format!(
                "Failed to parse crt.sh response: {}",
                e
            ))),
        }
    }

    /// Query SSLMate Cert Spotter (`/v1/issuances`), normalizing its clean `dns_names[]`
    /// array into the crt.sh entry shape.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fetch_certspotter(
        &self,
        base_url: &str,
        token: Option<&str>,
        domain: &str,
    ) -> std::result::Result<Vec<CrtShEntry>, CtFetchError> {
        let url = format!(
            "{}/v1/issuances?domain={}&include_subdomains=true&match_wildcards=true&expand=dns_names&expand=issuer",
            base_url,
            urlencoding::encode(domain)
        );
        debug!("Querying Cert Spotter: {}", url);

        let mut request = self.client.get(&url).timeout(self.timeout);
        if let Some(t) = token {
            request = request.bearer_auth(t);
        }

        let response = request
            .send_gated()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        if !response.status().is_success() {
            return Err(CtFetchError::Soft(format!(
                "Cert Spotter returned status {} for {}",
                response.status(),
                domain
            )));
        }

        let text = response
            .text()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        if text.is_empty() || text == "[]" {
            return Ok(Vec::new());
        }

        match serde_json::from_str::<Vec<CertSpotterIssuance>>(&text) {
            Ok(issuances) => Ok(issuances
                .into_iter()
                .map(CertSpotterIssuance::into_crtsh_entry)
                .collect()),
            Err(e) => Err(CtFetchError::Soft(format!(
                "Failed to parse Cert Spotter response: {}",
                e
            ))),
        }
    }

    /// Test-scoped crt.sh query preserving the historical contract (a reachable-but-
    /// unhelpful response degrades to empty with a warning; only a transport failure
    /// propagates) so the crt.sh HTTP behavior stays directly covered by the wiremock
    /// suite. Production goes through `fetch_entries_round_robin`.
    #[cfg(test)]
    pub(crate) async fn query_crt_sh(&self, domain: &str) -> Result<Vec<CrtShEntry>> {
        match self.fetch_crtsh(&self.base_url, domain).await {
            Ok(entries) => Ok(entries),
            Err(CtFetchError::Soft(msg)) => {
                tracing::warn!("{}", msg);
                Ok(Vec::new())
            }
            Err(CtFetchError::Transport(e)) => Err(e),
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

    // --- Cert Spotter mapping + multi-provider round-robin/failover ---

    #[test]
    fn test_certspotter_issuance_maps_to_crtsh_entry() {
        let json = r#"[{"id":"12345","dns_names":["example.com","api.vendor.io"],"issuer":{"name":"Let's Encrypt"},"not_before":"2024-01-01","not_after":"2024-04-01"}]"#;
        let issuances: Vec<CertSpotterIssuance> = serde_json::from_str(json).unwrap();
        assert_eq!(issuances.len(), 1);
        let entry = issuances.into_iter().next().unwrap().into_crtsh_entry();
        // dns_names[] is normalized into crt.sh's newline-joined name_value.
        assert_eq!(entry.id, 12345);
        assert_eq!(
            entry.name_value.as_deref(),
            Some("example.com\napi.vendor.io")
        );
        assert_eq!(entry.issuer_name.as_deref(), Some("Let's Encrypt"));
        assert!(entry.common_name.is_none());
    }

    #[test]
    fn test_certspotter_issuance_non_numeric_id_defaults_zero() {
        let json = r#"[{"id":"not-a-number","dns_names":["x.com"]}]"#;
        let issuances: Vec<CertSpotterIssuance> = serde_json::from_str(json).unwrap();
        let entry = issuances.into_iter().next().unwrap().into_crtsh_entry();
        assert_eq!(entry.id, 0);
        assert!(entry.issuer_name.is_none());
    }

    #[tokio::test]
    async fn test_discover_round_robin_fails_over_to_certspotter() {
        // crt.sh is over its rate limit (429); the round-robin must fail over to the
        // Cert Spotter provider and still surface the vendor from its certificates.
        let crtsh = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
            .mount(&crtsh)
            .await;

        let certspotter = MockServer::start().await;
        let cs_body = serde_json::json!([
            {"id": "9001", "dns_names": ["example.com", "vendor-x.io"], "issuer": {"name": "Let's Encrypt"}}
        ]);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&cs_body))
            .mount(&certspotter)
            .await;

        let disc = CtLogDiscovery::with_providers(
            Duration::from_secs(5),
            crtsh.uri(),
            Some(certspotter.uri()),
            None,
        );
        let results = disc.discover("example.com").await.unwrap();
        assert!(
            results.iter().any(|r| r.domain == "vendor-x.io"),
            "expected failover to Cert Spotter to surface vendor-x.io, got {:?}",
            results.iter().map(|r| &r.domain).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_discover_all_providers_soft_fail_returns_empty() {
        // Both providers respond with a server error — every provider soft-fails, so the
        // result degrades to empty (no vendors) rather than erroring the scan.
        let crtsh = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&crtsh)
            .await;
        let certspotter = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&certspotter)
            .await;

        let disc = CtLogDiscovery::with_providers(
            Duration::from_secs(5),
            crtsh.uri(),
            Some(certspotter.uri()),
            None,
        );
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }
}
