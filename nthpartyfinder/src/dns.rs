use crate::config::AppConfig;
use crate::domain_utils;
use crate::rate_limit::RateLimitContext;
use crate::vendor::RecordType;
use anyhow::Result;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::TokioResolver;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, info, warn};

// Compile regex patterns once at startup for performance (fixes B020)
static MACRO_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%\{[a-zA-Z]+[0-9]*[a-zA-Z]*\}\.?").unwrap());

static DOMAIN_VERIFICATION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([a-zA-Z0-9]+)(?:-domain)?-verification=").unwrap());

static VERIFICATION_PREFIX_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"verification-([a-zA-Z0-9]+)=").unwrap());

static SITE_VERIFICATION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([a-zA-Z0-9]+)-site-verification=").unwrap());

static PROVIDER_VERIFY_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([A-Z0-9]+)_verify_").unwrap());

// M016: Underscores are intentionally allowed at the start of labels to support
// SPF/DMARC/DKIM underscore-prefixed subdomains (e.g., _spf.google.com, _dmarc.domain.com,
// _domainkey.domain.com). This is correct per RFC 7208 and RFC 6376.
static DOMAIN_VALIDATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,62}(\.[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,62})*$").unwrap()
});

// DMARC mailto: extraction regex (fixes B020)
static MAILTO_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"mailto:([^@,\s]+@)?([^,;\s]+)").unwrap());

// SP_TAG_REGEX removed - sp= contains policy values, not domains (C001 fix)

// Pre-compiled SPF mechanism regexes to avoid recompilation in loops (H001 fix)
static SPF_INCLUDE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"include:\s*([^\s]+)").unwrap());
static SPF_REDIRECT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"redirect=\s*([^\s]+)").unwrap());
static SPF_A_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"a:\s*([^\s]+)").unwrap());
static SPF_MX_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"mx:\s*([^\s]+)").unwrap());
static SPF_EXISTS_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"exists:\s*([^\s]+)").unwrap());
// M003: ptr: mechanism contains a domain (unlike ip4:/ip6: which contain IP addresses)
static SPF_PTR_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"ptr:\s*([^\s]+)").unwrap());

// Pre-compiled DKIM pattern regexes (H002 fix)
static DKIM_P_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"p=([A-Za-z0-9+/=]+)").unwrap());
static DKIM_H_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"h=([^;]+)").unwrap());
static DKIM_S_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"s=([^;]+)").unwrap());

pub trait LogFailure {
    fn log_failure(
        &self,
        source_domain: &str,
        record_type: &str,
        raw_record: &str,
        extracted_service: Option<&str>,
        failure_reason: &str,
    );
}

/// DNS over HTTPS server configuration (runtime loaded from config)
#[derive(Debug, Clone)]
struct DohServerConfig {
    url: String,
    name: String,
    timeout_secs: u64,
}

/// Traditional DNS Server configuration for fallback (runtime loaded from config)
#[derive(Debug, Clone)]
struct DnsServerConfig {
    address: String,
    name: String,
    timeout_secs: u64,
}

/// Enhanced DNS server pool with DoH support
pub struct DnsServerPool {
    doh_servers: Vec<DohServerConfig>,
    dns_servers: Vec<DnsServerConfig>,
    current_doh_index: AtomicUsize,
    current_dns_index: AtomicUsize,
    client: reqwest::Client,
}

impl DnsServerPool {
    /// Create a new DNS server pool from configuration
    pub fn from_config(config: &AppConfig) -> Self {
        let doh_servers: Vec<DohServerConfig> = config
            .dns
            .doh_servers
            .iter()
            .map(|s| DohServerConfig {
                url: s.url.clone(),
                name: s.name.clone(),
                timeout_secs: s.timeout_secs,
            })
            .collect();

        let dns_servers: Vec<DnsServerConfig> = config
            .dns
            .dns_servers
            .iter()
            .map(|s| DnsServerConfig {
                address: s.address.clone(),
                name: s.name.clone(),
                timeout_secs: s.timeout_secs,
            })
            .collect();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(
                config.http.request_timeout_secs,
            ))
            .user_agent(&config.http.user_agent)
            .build()
            .expect("Failed to create HTTP client for DoH");

        Self {
            doh_servers,
            dns_servers,
            current_doh_index: AtomicUsize::new(0),
            current_dns_index: AtomicUsize::new(0),
            client,
        }
    }

    /// Create a new DNS server pool with embedded defaults (for backwards compatibility)
    pub fn new() -> Self {
        let doh_servers = vec![
            DohServerConfig {
                url: "https://cloudflare-dns.com/dns-query".to_string(),
                name: "Cloudflare DoH".to_string(),
                timeout_secs: 3,
            },
            DohServerConfig {
                url: "https://dns.google/dns-query".to_string(),
                name: "Google DoH".to_string(),
                timeout_secs: 3,
            },
            DohServerConfig {
                url: "https://dns.quad9.net/dns-query".to_string(),
                name: "Quad9 DoH".to_string(),
                timeout_secs: 4,
            },
            DohServerConfig {
                url: "https://doh.opendns.com/dns-query".to_string(),
                name: "OpenDNS DoH".to_string(),
                timeout_secs: 4,
            },
        ];

        let dns_servers = vec![
            DnsServerConfig {
                address: "1.1.1.1:53".to_string(),
                name: "Cloudflare".to_string(),
                timeout_secs: 2,
            },
            DnsServerConfig {
                address: "8.8.8.8:53".to_string(),
                name: "Google".to_string(),
                timeout_secs: 2,
            },
            DnsServerConfig {
                address: "9.9.9.9:53".to_string(),
                name: "Quad9".to_string(),
                timeout_secs: 3,
            },
            DnsServerConfig {
                address: "208.67.222.222:53".to_string(),
                name: "OpenDNS".to_string(),
                timeout_secs: 3,
            },
        ];

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .user_agent("nthpartyfinder/1.0")
            .build()
            .expect("Failed to create HTTP client for DoH");

        Self {
            doh_servers,
            dns_servers,
            current_doh_index: AtomicUsize::new(0),
            current_dns_index: AtomicUsize::new(0),
            client,
        }
    }
}

impl Default for DnsServerPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl DnsServerPool {
    /// Create a DnsServerPool with custom DoH URLs for testing.
    /// Allows injecting wiremock server addresses for mocked DNS responses.
    ///
    /// # Arguments
    /// * `urls` - A vector of DoH endpoint URLs (e.g., wiremock server addresses)
    ///
    /// # Example
    /// ```ignore
    /// let mock_server = wiremock::MockServer::start().await;
    /// let pool = DnsServerPool::with_test_urls(vec![mock_server.uri()]);
    /// ```
    pub fn with_test_urls(urls: Vec<String>) -> Self {
        let doh_servers: Vec<DohServerConfig> = urls
            .into_iter()
            .enumerate()
            .map(|(i, url)| DohServerConfig {
                url,
                name: format!("Test DoH Server {}", i + 1),
                timeout_secs: 5,
            })
            .collect();

        // Provide minimal DNS fallback servers for tests (won't be used if DoH succeeds)
        let dns_servers = vec![DnsServerConfig {
            address: "127.0.0.1:53".to_string(),
            name: "Test DNS Fallback".to_string(),
            timeout_secs: 2,
        }];

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("nthpartyfinder-test/1.0")
            .build()
            .expect("Failed to create HTTP client for test DoH");

        Self {
            doh_servers,
            dns_servers,
            current_doh_index: AtomicUsize::new(0),
            current_dns_index: AtomicUsize::new(0),
            client,
        }
    }
}

impl DnsServerPool {
    /// Get the next DoH server in rotation
    fn next_doh_server(&self) -> &DohServerConfig {
        let index = self.current_doh_index.fetch_add(1, Ordering::Relaxed) % self.doh_servers.len();
        &self.doh_servers[index]
    }

    /// Get the next DNS server in rotation (for fallback)
    fn next_dns_server(&self) -> &DnsServerConfig {
        let index = self.current_dns_index.fetch_add(1, Ordering::Relaxed) % self.dns_servers.len();
        &self.dns_servers[index]
    }

    // coverage(off): performs live HTTPS request to DoH provider — requires network
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn doh_txt_lookup(&self, domain: &str, server: &DohServerConfig) -> Result<Vec<String>> {
        debug!("DoH lookup for {} using {}", domain, server.name);

        // Create DNS query in wire format
        let query_params = [("name", domain), ("type", "TXT")];

        let response = self
            .client
            .get(&server.url)
            .query(&query_params)
            .header("Accept", "application/dns-json")
            .timeout(std::time::Duration::from_secs(server.timeout_secs))
            .send()
            .await?
            .json::<Value>()
            .await?;

        let mut records = Vec::new();

        if let Some(answers) = response["Answer"].as_array() {
            for answer in answers {
                if answer["type"].as_u64() == Some(16) {
                    // TXT record type
                    if let Some(data) = answer["data"].as_str() {
                        // Remove quotes and handle escaped characters
                        let cleaned = unescape_dns_txt(data.trim_matches('"'));
                        records.push(cleaned);
                    }
                }
            }
        }

        debug!(
            "DoH found {} TXT records for {} via {}",
            records.len(),
            domain,
            server.name
        );
        Ok(records)
    }

    // coverage(off): performs live HTTPS request to DoH provider — requires network
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn doh_cname_lookup(
        &self,
        domain: &str,
        server: &DohServerConfig,
    ) -> Result<Vec<String>> {
        debug!("DoH CNAME lookup for {} using {}", domain, server.name);

        let query_params = [("name", domain), ("type", "CNAME")];

        let response = self
            .client
            .get(&server.url)
            .query(&query_params)
            .header("Accept", "application/dns-json")
            .timeout(std::time::Duration::from_secs(server.timeout_secs))
            .send()
            .await?
            .json::<Value>()
            .await?;

        let mut records = Vec::new();

        if let Some(answers) = response["Answer"].as_array() {
            for answer in answers {
                if answer["type"].as_u64() == Some(5) {
                    // CNAME record type
                    if let Some(data) = answer["data"].as_str() {
                        // Remove trailing dot from CNAME targets
                        let cleaned = data.trim_end_matches('.').to_string();
                        records.push(cleaned);
                    }
                }
            }
        }

        debug!(
            "DoH found {} CNAME records for {} via {}",
            records.len(),
            domain,
            server.name
        );
        Ok(records)
    }

    /// Create a traditional DNS resolver for the given server config (C002 fix: returns Result)
    fn create_dns_resolver(
        &self,
        server: &DnsServerConfig,
        use_tcp: bool,
    ) -> Result<TokioResolver> {
        let mut config = ResolverConfig::new();

        let socket_addr = server.address.parse().map_err(|e| {
            anyhow::anyhow!(
                "Invalid DNS server address '{}' for server '{}': {}",
                server.address,
                server.name,
                e
            )
        })?;

        config.add_name_server(NameServerConfig {
            socket_addr,
            protocol: if use_tcp {
                Protocol::Tcp
            } else {
                Protocol::Udp
            },
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
            http_endpoint: None,
        });

        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(server.timeout_secs);
        opts.attempts = 1; // Single attempt for speed
        opts.edns0 = true;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6; // Prefer IPv4 for speed
        opts.validate = false;
        opts.num_concurrent_reqs = 4; // Increased concurrency

        Ok(
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
                .with_options(opts)
                .build(),
        )
    }

    // coverage(off): performs live DNS lookups via DoH and traditional DNS — requires network
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn get_txt_and_cname_fast(&self, domain: &str) -> (Vec<String>, Vec<String>) {
        let (txt_result, cname_result) =
            tokio::join!(self.fast_txt_lookup(domain), self.fast_cname_lookup(domain),);
        (
            txt_result.unwrap_or_default(),
            cname_result.unwrap_or_default(),
        )
    }

    // coverage(off): performs live DNS lookup — requires network
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fast_txt_lookup(&self, domain: &str) -> Result<Vec<String>> {
        // Try DoH first with a single attempt
        let doh_server = self.next_doh_server();
        match tokio::time::timeout(
            std::time::Duration::from_millis(2000),
            self.doh_txt_lookup(domain, doh_server),
        )
        .await
        {
            Ok(Ok(records)) if !records.is_empty() => return Ok(records),
            _ => {}
        }

        // Fallback to traditional DNS (single attempt, UDP only)
        let dns_server = self.next_dns_server();
        if let Ok(resolver) = self.create_dns_resolver(dns_server, false) {
            if let Ok(Ok(txt_lookup)) = tokio::time::timeout(
                std::time::Duration::from_millis(2000),
                resolver.txt_lookup(domain),
            )
            .await
            {
                let records: Vec<String> = txt_lookup.iter().map(|r| r.to_string()).collect();
                return Ok(records);
            }
        }

        Ok(vec![])
    }

    // coverage(off): performs live DNS lookup — requires network
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fast_cname_lookup(&self, domain: &str) -> Result<Vec<String>> {
        let doh_server = self.next_doh_server();
        match tokio::time::timeout(
            std::time::Duration::from_millis(2000),
            self.doh_cname_lookup(domain, doh_server),
        )
        .await
        {
            Ok(Ok(records)) if !records.is_empty() => return Ok(records),
            _ => {}
        }

        // Fallback to traditional DNS
        let dns_server = self.next_dns_server();
        if let Ok(resolver) = self.create_dns_resolver(dns_server, false) {
            if let Ok(Ok(lookup)) = tokio::time::timeout(
                std::time::Duration::from_millis(2000),
                resolver.lookup(domain, hickory_resolver::proto::rr::RecordType::CNAME),
            )
            .await
            {
                use hickory_resolver::proto::rr::RData;
                let records: Vec<String> = lookup
                    .record_iter()
                    .filter_map(|r| match r.data() {
                        RData::CNAME(ref cname) => {
                            Some(cname.to_string().trim_end_matches('.').to_string())
                        }
                        _ => None,
                    })
                    .collect();
                return Ok(records);
            }
        }

        Ok(vec![])
    }
}

pub async fn get_txt_records(domain: &str) -> Result<Vec<String>> {
    get_txt_records_with_pool(domain, &DnsServerPool::new()).await
}

pub async fn get_txt_records_with_pool(
    domain: &str,
    dns_pool: &DnsServerPool,
) -> Result<Vec<String>> {
    get_txt_records_with_rate_limit(domain, dns_pool, None).await
}

// coverage(off): performs live DNS lookups racing DoH and traditional DNS — requires network
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn get_txt_records_with_rate_limit(
    domain: &str,
    dns_pool: &DnsServerPool,
    rate_limit_ctx: Option<&RateLimitContext>,
) -> Result<Vec<String>> {
    // Apply rate limiting if configured
    if let Some(ctx) = rate_limit_ctx {
        ctx.dns_limiter.acquire().await;
    }

    debug!("Querying TXT records for domain: {}", domain);

    // Race DoH and traditional DNS concurrently — first successful result wins.
    // This replaces the old sequential fallback (DoH×2 → DNS×2 → system) which
    // could take 20+ seconds on failure. Now worst-case is ~3s (single timeout).
    let doh_server = dns_pool.next_doh_server();
    let dns_server = dns_pool.next_dns_server();

    // Spawn DoH lookup
    let doh_fut = async {
        match dns_pool.doh_txt_lookup(domain, doh_server).await {
            Ok(records) if !records.is_empty() => Some(records),
            Ok(_) => None,
            Err(_) => None,
        }
    };

    // Spawn traditional DNS lookup (UDP)
    let dns_fut = async {
        let resolver = match dns_pool.create_dns_resolver(dns_server, false) {
            Ok(r) => r,
            Err(_) => return None,
        };
        match resolver.txt_lookup(domain).await {
            Ok(txt_lookup) => {
                let records: Vec<String> = txt_lookup.iter().map(|r| r.to_string()).collect();
                if records.is_empty() {
                    None
                } else {
                    Some(records)
                }
            }
            Err(_) => None,
        }
    };

    // Race both with a 3s overall timeout
    let race_result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        async {
            tokio::pin!(doh_fut);
            tokio::pin!(dns_fut);

            // Use select to return whichever finishes first with results
            tokio::select! {
                biased;
                result = &mut doh_fut => {
                    if let Some(records) = result {
                        info!("DoH successful: Found {} TXT records for {} via {}", records.len(), domain, doh_server.name);
                        return Some(records);
                    }
                    // DoH failed — wait for DNS
                    if let Some(records) = (&mut dns_fut).await {
                        debug!("DNS successful: Found {} TXT records for {} via {} (UDP)", records.len(), domain, dns_server.name);
                        return Some(records);
                    }
                    None
                }
                result = &mut dns_fut => {
                    if let Some(records) = result {
                        debug!("DNS successful: Found {} TXT records for {} via {} (UDP)", records.len(), domain, dns_server.name);
                        return Some(records);
                    }
                    // DNS failed — wait for DoH
                    if let Some(records) = (&mut doh_fut).await {
                        info!("DoH successful: Found {} TXT records for {} via {}", records.len(), domain, doh_server.name);
                        return Some(records);
                    }
                    None
                }
            }
        }
    ).await;

    if let Ok(Some(records)) = race_result {
        return Ok(records);
    }

    // Final fallback: system resolver (only if both racing attempts failed)
    debug!("DNS race failed for {}, trying system resolver", domain);
    match try_system_dns_resolver(domain).await {
        Ok(records) => {
            debug!(
                "Found {} TXT records for {} via system resolver",
                records.len(),
                domain
            );
            Ok(records)
        }
        Err(e) => {
            warn!("All DNS resolution failed for {} — returning empty results to continue analysis. Last error: {}", domain, e);
            Ok(vec![])
        }
    }
}

// coverage(off): performs live DNS lookup via system resolver — requires network
#[cfg_attr(coverage_nightly, coverage(off))]
async fn try_system_dns_resolver(domain: &str) -> Result<Vec<String>> {
    let resolver = TokioResolver::builder_tokio()?.build();

    let txt_lookup = resolver.txt_lookup(domain).await?;
    let records: Vec<String> = txt_lookup.iter().map(|record| record.to_string()).collect();

    Ok(records)
}

// coverage(off): delegates to get_cname_records_with_rate_limit which performs live DNS
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn get_cname_records_with_pool(
    domain: &str,
    dns_pool: &DnsServerPool,
) -> Result<Vec<String>> {
    get_cname_records_with_rate_limit(domain, dns_pool, None).await
}

// coverage(off): performs live DNS lookup via DoH — requires network
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn get_cname_records_with_rate_limit(
    domain: &str,
    dns_pool: &DnsServerPool,
    rate_limit_ctx: Option<&RateLimitContext>,
) -> Result<Vec<String>> {
    // Apply rate limiting if configured
    if let Some(ctx) = rate_limit_ctx {
        ctx.dns_limiter.acquire().await;
    }

    debug!("Querying CNAME records for domain: {}", domain);

    // Single DoH attempt with short timeout — CNAME absence is normal
    let doh_server = dns_pool.next_doh_server();
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        dns_pool.doh_cname_lookup(domain, doh_server),
    )
    .await
    {
        Ok(Ok(records)) if !records.is_empty() => {
            debug!(
                "DoH successful: Found {} CNAME records for {} via {}",
                records.len(),
                domain,
                doh_server.name
            );
            return Ok(records);
        }
        _ => {}
    }

    // No CNAME found is normal for most domains
    Ok(vec![])
}

#[derive(Debug)]
pub struct VendorDomain {
    pub domain: String,
    pub source_type: RecordType,
    pub raw_record: String,
}

/// Simple extraction without logging - used for subdomain analysis
pub fn extract_vendor_domains_with_source(txt_records: &[String]) -> Vec<VendorDomain> {
    extract_vendor_domains_with_source_and_logger(txt_records, None, "")
}

pub fn extract_vendor_domains_with_source_and_logger(
    txt_records: &[String],
    logger: Option<&dyn LogFailure>,
    source_domain: &str,
) -> Vec<VendorDomain> {
    let mut vendor_domains = Vec::new();
    // Deduplicate by (domain, record_type, raw_record) to allow same vendor from different sources
    // but prevent exact duplicates (same domain + same record type + same raw record)
    let mut seen_entries: HashSet<(String, String, String)> = HashSet::new();

    for record in txt_records {
        // Strip wrapping quotes, then unescape DNS TXT backslash sequences (H004 fix)
        // DNS TXT records use backslash-escaping: \X -> X for any char X
        // Process in one pass to handle all escape sequences correctly
        let record_trimmed = record.trim_matches('"');
        let record_clean = unescape_dns_txt(record_trimmed);
        let mut record_matched = false;

        // Extract vendor domains based on record patterns
        if let Some(domains) = extract_from_spf_record(&record_clean, logger, source_domain, record)
        {
            record_matched = true;
            for domain_info in domains {
                let key = (
                    domain_info.domain.clone(),
                    domain_info.source_type.as_hierarchy_string(),
                    domain_info.raw_record.clone(),
                );
                if seen_entries.insert(key) {
                    vendor_domains.push(domain_info);
                }
            }
        }

        if let Some(domains) =
            extract_from_dkim_record(&record_clean, logger, source_domain, record)
        {
            record_matched = true;
            for domain_info in domains {
                let key = (
                    domain_info.domain.clone(),
                    domain_info.source_type.as_hierarchy_string(),
                    domain_info.raw_record.clone(),
                );
                if seen_entries.insert(key) {
                    vendor_domains.push(domain_info);
                }
            }
        }

        if let Some(domains) =
            extract_from_dmarc_record(&record_clean, logger, source_domain, record)
        {
            record_matched = true;
            for domain_info in domains {
                let key = (
                    domain_info.domain.clone(),
                    domain_info.source_type.as_hierarchy_string(),
                    domain_info.raw_record.clone(),
                );
                if seen_entries.insert(key) {
                    vendor_domains.push(domain_info);
                }
            }
        }

        if let Some(domains) =
            extract_from_verification_record(&record_clean, logger, source_domain, record)
        {
            record_matched = true;
            for domain_info in domains {
                let key = (
                    domain_info.domain.clone(),
                    domain_info.source_type.as_hierarchy_string(),
                    domain_info.raw_record.clone(),
                );
                if seen_entries.insert(key) {
                    vendor_domains.push(domain_info);
                }
            }
        }

        // Log unmatched TXT records for debugging and pattern discovery (M004 fix: use if-let)
        if !record_matched {
            if let Some(logger) = logger {
                // Skip very short records (likely not vendor verification records)
                if record_clean.len() > 5 {
                    logger.log_failure(
                        source_domain,
                        "UNMATCHED_TXT",
                        record,
                        None,
                        "No pattern matched this TXT record",
                    );
                }
            }
        }
    }

    vendor_domains
}

/// Unescape DNS TXT record backslash sequences: \X -> X for any char X.
/// This handles \\, \", \_, and any other backslash-escaped character.
fn unescape_dns_txt(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // Consume the next char as-is (unescaped)
            if let Some(next) = chars.next() {
                result.push(next);
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn strip_spf_macros(domain: &str) -> String {
    // Remove SPF macro variables like %{ir}, %{v}, %{d}, etc.
    // Pattern: %{<macro>} where <macro> can be letters with optional modifiers
    // Use pre-compiled regex for performance (B020 fix)
    MACRO_REGEX.replace_all(domain, "").to_string()
}

fn extract_from_spf_record(
    record: &str,
    logger: Option<&dyn LogFailure>,
    source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    // Case-insensitive check (fixes DNS-001 - RFC compliance)
    let record_lower = record.to_lowercase();
    if !record_lower.starts_with("v=spf1") {
        return None;
    }

    let mut domains = Vec::new();
    // Use pre-compiled regexes instead of compiling in loop (H001 fix)
    // Note: ip4:/ip6: mechanisms are intentionally excluded — they contain IP addresses,
    // not domains, so they are not relevant to vendor domain extraction.
    // L009: RFC 7208 limits SPF to 10 DNS-querying mechanisms (include, a, mx, ptr, exists,
    // redirect). This tool does not recursively resolve SPF chains, it only extracts domains
    // from a single record, so the 10-lookup limit is not enforced here. A future recursive
    // SPF resolver would need to track and enforce this limit.
    let spf_regexes: &[&Lazy<Regex>] = &[
        &SPF_INCLUDE_REGEX,
        &SPF_REDIRECT_REGEX,
        &SPF_A_REGEX,
        &SPF_MX_REGEX,
        &SPF_EXISTS_REGEX,
        &SPF_PTR_REGEX,
    ];

    for re in spf_regexes {
        for domain_match in re.captures_iter(&record_lower).filter_map(|c| c.get(1)) {
            let raw_domain = domain_match.as_str();

            // Strip SPF macros to get the actual domain (e.g., %{ir}.%{v}.%{d}.spf.has.pphosted.com -> spf.has.pphosted.com)
            let cleaned_domain = strip_spf_macros(raw_domain);

            if is_valid_domain(&cleaned_domain) {
                // Extract base domain from SPF subdomains (e.g., _spf.google.com -> google.com)
                let base_domain = domain_utils::extract_base_domain(&cleaned_domain);

                domains.push(VendorDomain {
                    domain: base_domain,
                    source_type: RecordType::DnsTxtSpf,
                    raw_record: raw_record.to_string(),
                });
            } else if let Some(logger) = logger {
                logger.log_failure(
                    source_domain,
                    "SPF",
                    raw_record,
                    Some(raw_domain),
                    "Invalid domain format",
                );
            }
        }
    }

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

// coverage(off): performs live DNS lookups to resolve SPF include chains — requires network
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn resolve_spf_includes_recursive(
    txt_records: &[String],
    dns_pool: &DnsServerPool,
    source_domain: &str,
) -> Vec<VendorDomain> {
    let mut all_domains = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut to_resolve: Vec<String> = Vec::new();
    let mut lookup_count: usize = 0;
    const MAX_SPF_LOOKUPS: usize = 10;

    // Find SPF records in the initial TXT records and extract include/redirect/exists targets
    for record in txt_records {
        let record_clean = unescape_dns_txt(record.trim_matches('"'));
        let record_lower = record_clean.to_lowercase();
        if !record_lower.starts_with("v=spf1") {
            continue;
        }
        collect_spf_targets(&record_lower, &mut to_resolve, &mut visited);
    }

    // Iteratively resolve include targets (BFS to stay within lookup limit)
    while let Some(target) = to_resolve.pop() {
        if lookup_count >= MAX_SPF_LOOKUPS {
            debug!(
                "SPF recursive resolution hit {}-lookup limit for {}",
                MAX_SPF_LOOKUPS, source_domain
            );
            break;
        }
        lookup_count += 1;

        match get_txt_records_with_pool(&target, dns_pool).await {
            Ok(nested_records) => {
                for record in &nested_records {
                    let record_clean = unescape_dns_txt(record.trim_matches('"'));
                    let record_lower = record_clean.to_lowercase();
                    if !record_lower.starts_with("v=spf1") {
                        continue;
                    }

                    // Extract vendor domains from this nested SPF record
                    if let Some(domains) =
                        extract_from_spf_record(&record_clean, None, source_domain, record)
                    {
                        all_domains.extend(domains);
                    }

                    // Collect more targets to resolve
                    collect_spf_targets(&record_lower, &mut to_resolve, &mut visited);
                }
            }
            Err(e) => {
                debug!("SPF recursive resolution failed for {}: {}", target, e);
            }
        }
    }

    if !all_domains.is_empty() {
        debug!(
            "SPF recursive resolution for {} found {} additional vendor domains across {} lookups",
            source_domain,
            all_domains.len(),
            lookup_count
        );
    }

    all_domains
}

/// Extract SPF include/redirect targets from a lowercased SPF record for recursive resolution.
/// Note: `exists:` targets are NOT included here because they are macro-expanded IP-check
/// mechanisms, not SPF delegation. Domain extraction from `exists:` is already handled by
/// `extract_from_spf_record`.
fn collect_spf_targets(
    record_lower: &str,
    to_resolve: &mut Vec<String>,
    visited: &mut HashSet<String>,
) {
    let target_regexes: &[&Lazy<Regex>] = &[&SPF_INCLUDE_REGEX, &SPF_REDIRECT_REGEX];
    for re in target_regexes {
        for m in re.captures_iter(record_lower).filter_map(|c| c.get(1)) {
            let raw_target = m.as_str();
            // Strip SPF macros (e.g., %{i}._spf.mta.salesforce.com -> _spf.mta.salesforce.com)
            let cleaned = strip_spf_macros(raw_target);
            if is_valid_domain(&cleaned) && visited.insert(cleaned.clone()) {
                to_resolve.push(cleaned);
            }
        }
    }
}

fn extract_from_dkim_record(
    record: &str,
    _logger: Option<&dyn LogFailure>,
    _source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    if !record.contains("k=rsa") && !record.contains("k=ed25519") {
        return None;
    }

    let mut domains = Vec::new();

    // Use pre-compiled DKIM regexes instead of compiling in loop (H002 fix)
    let dkim_regexes: &[&Lazy<Regex>] = &[&DKIM_P_REGEX, &DKIM_H_REGEX, &DKIM_S_REGEX];

    for re in dkim_regexes {
        for value_match in re.captures_iter(record).filter_map(|c| c.get(1)) {
            let value = value_match.as_str();
            if value.contains('.') && is_valid_domain(value) {
                domains.push(VendorDomain {
                    domain: value.to_string(),
                    source_type: RecordType::DnsTxtDkim,
                    raw_record: raw_record.to_string(),
                });
            }
        }
    }

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

fn extract_from_dmarc_record(
    record: &str,
    logger: Option<&dyn LogFailure>,
    source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    // Case-insensitive check (fixes DNS-001 - RFC compliance)
    if !record.to_lowercase().starts_with("v=dmarc1") {
        return None;
    }

    let mut domains = Vec::new();

    // Extract domains from rua and ruf tags (which can have comma-separated mailto addresses)
    // e.g., rua=mailto:a@domain1.com,mailto:b@domain2.com
    // Use lowercase copy consistently to avoid byte index mismatch on mixed-case records (H003 fix)
    // and to prevent UTF-8 boundary panics on multi-byte chars (C004 fix)
    let record_lower = record.to_lowercase();
    for tag in &["rua=", "ruf="] {
        // Find the tag value (case-insensitive search on lowercase copy)
        if let Some(tag_pos) = record_lower.find(*tag) {
            let value_start = tag_pos + tag.len();
            // Find end of value (next semicolon or end of string) - search lowercase copy
            let value_end = record_lower[value_start..]
                .find(';')
                .map(|p| value_start + p)
                .unwrap_or(record_lower.len());
            let tag_value = &record_lower[value_start..value_end];

            // Extract all mailto: addresses (comma-separated)
            // Pattern: mailto:localpart@domain or mailto:domain
            for domain_match in MAILTO_REGEX.captures_iter(tag_value).filter_map(|c| c.get(2)) {
                let domain = domain_match.as_str();
                if is_valid_domain(domain) {
                    domains.push(VendorDomain {
                        domain: domain.to_string(),
                        source_type: RecordType::DnsTxtDmarc,
                        raw_record: raw_record.to_string(),
                    });
                } else if let Some(logger) = logger {
                    logger.log_failure(
                        source_domain,
                        "DMARC",
                        raw_record,
                        Some(tag),
                        "Invalid domain format",
                    );
                }
            }
        }
    }

    // Note: sp= tag contains policy values ("none", "quarantine", "reject"), not domains.
    // Removed dead code that attempted to extract domains from sp= (C001 fix).

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

fn extract_from_verification_record(
    record: &str,
    logger: Option<&dyn LogFailure>,
    source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    let mut domains = Vec::new();

    // First, try comprehensive static provider mappings
    if let Some(static_domains) =
        try_static_verification_patterns(record, logger, source_domain, raw_record)
    {
        domains.extend(static_domains);
    }

    // Then try dynamic pattern matching for unknown verification records
    if let Some(dynamic_domains) =
        try_dynamic_verification_patterns(record, logger, source_domain, raw_record)
    {
        domains.extend(dynamic_domains);
    }

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

fn try_static_verification_patterns(
    record: &str,
    _logger: Option<&dyn LogFailure>,
    _source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    // Comprehensive static provider mappings based on research
    let verification_patterns = vec![
        // Common verification patterns
        (
            r"google-site-verification=",
            "google.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"facebook-domain-verification=",
            "facebook.com",
            RecordType::DnsTxtVerification,
        ),
        (r"MS=", "microsoft.com", RecordType::DnsTxtVerification),
        (
            r"apple-domain-verification=",
            "apple.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"adobe-idp-site-verification=",
            "adobe.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"stripe-verification=",
            "stripe.com",
            RecordType::DnsTxtVerification,
        ),
        (r"docusign=", "docusign.com", RecordType::DnsTxtVerification),
        (
            r"globalsign-domain-verification=",
            "globalsign.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"dropbox-domain-verification=",
            "dropbox.com",
            RecordType::DnsTxtVerification,
        ),
        // Extended patterns from research and klaviyo analysis
        (r"ZOOM_verify_", "zoom.us", RecordType::DnsTxtVerification),
        (
            r"atlassian-domain-verification=",
            "atlassian.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"browserstack-domain-verification=",
            "browserstack.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"canva-site-verification=",
            "canva.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"cursor-domain-verification",
            "cursor.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"datadome-domain-verify=",
            "datadome.co",
            RecordType::DnsTxtVerification,
        ),
        (
            r"drift-domain-verification=",
            "drift.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"hubspot-domain-verification=",
            "hubspot.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"klaviyo-site-verification=",
            "klaviyo.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"notion-domain-verification=",
            "notion.so",
            RecordType::DnsTxtVerification,
        ),
        (
            r"onetrust-domain-verification=",
            "onetrust.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"openai-domain-verification=",
            "openai.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"postman-domain-verification=",
            "postman.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"slack-domain-verification=",
            "slack.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"teamviewer-sso-verification=",
            "teamviewer.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"wework-site-verification=",
            "wework.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"heroku-domain-verification=",
            "heroku.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"jamf-site-verification=",
            "jamf.com",
            RecordType::DnsTxtVerification,
        ),
        // Additional patterns found in klaviyo.com analysis
        (
            r"anthropic-domain-verification",
            "anthropic.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"jetbrains-domain-verification=",
            "jetbrains.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"gc-ai-domain-verification",
            "gc-ai.com",
            RecordType::DnsTxtVerification,
        ), // Unverified vendor - kept for completeness
        // Special mappings discovered from research
        (r"intacct-esk=", "sage.com", RecordType::DnsTxtVerification), // Sage Intacct
        (r"mgverify=", "mailgun.com", RecordType::DnsTxtVerification), // Mailgun verification
        // L002: neat.co is correct — Neat's actual domain is neat.co (not .com)
        (
            r"neat-pulse-domain-verification",
            "neat.co",
            RecordType::DnsTxtVerification,
        ),
        // Pattern variations
        (
            r"webex-domain-verification=",
            "webex.com",
            RecordType::DnsTxtVerification,
        ),
        (
            r"zoom-domain-verification=",
            "zoom.us",
            RecordType::DnsTxtVerification,
        ),
        (
            r"have-i-been-pwned-verification=",
            "haveibeenpwned.com",
            RecordType::DnsTxtVerification,
        ),
        // L001: Whimsical uses angle bracket format in TXT records — this is an actual
        // record format observed in the wild (e.g., klaviyo.com DNS), not a parsing error.
        (
            r"<whimsical=",
            "whimsical.com",
            RecordType::DnsTxtVerification,
        ),
    ];

    let mut domains = Vec::new();

    // These patterns are all literal strings, use contains() instead of regex for speed
    for (pattern, domain, record_type) in &verification_patterns {
        if record.contains(pattern) {
            domains.push(VendorDomain {
                domain: domain.to_string(),
                source_type: record_type.clone(),
                raw_record: raw_record.to_string(),
            });
        }
    }

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

fn try_dynamic_verification_patterns(
    record: &str,
    _logger: Option<&dyn LogFailure>,
    _source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    let mut domains = Vec::new();

    let verification_regexes: &[&Lazy<Regex>] = &[
        &DOMAIN_VERIFICATION_REGEX,
        &VERIFICATION_PREFIX_REGEX,
        &SITE_VERIFICATION_REGEX,
        &PROVIDER_VERIFY_REGEX,
    ];
    for re in verification_regexes {
        for provider_match in re.captures_iter(record).filter_map(|c| c.get(1)) {
            let provider_name = provider_match.as_str().to_lowercase();
            if let Some(domain) = infer_provider_domain(&provider_name) {
                domains.push(VendorDomain {
                    domain,
                    source_type: RecordType::DnsTxtVerification,
                    raw_record: raw_record.to_string(),
                });
            }
        }
    }

    // Dynamic pattern 5: "letters=" (preceded by letters, like EU5VQe53KTDQgPby023o4w)
    // This is more challenging as it requires heuristic analysis - skip for now to avoid false positives

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

fn infer_provider_domain(provider_name: &str) -> Option<String> {
    // Provider name to domain mapping for dynamic inference
    let provider_mappings = vec![
        ("google", "google.com"),
        ("microsoft", "microsoft.com"),
        ("apple", "apple.com"),
        ("adobe", "adobe.com"),
        ("stripe", "stripe.com"),
        ("docusign", "docusign.com"),
        ("globalsign", "globalsign.com"),
        ("dropbox", "dropbox.com"),
        ("zoom", "zoom.us"),
        ("atlassian", "atlassian.com"),
        ("browserstack", "browserstack.com"),
        ("canva", "canva.com"),
        ("cursor", "cursor.com"),
        ("datadome", "datadome.co"),
        ("drift", "drift.com"),
        ("hubspot", "hubspot.com"),
        ("klaviyo", "klaviyo.com"),
        ("notion", "notion.so"),
        ("onetrust", "onetrust.com"),
        ("openai", "openai.com"),
        ("postman", "postman.com"),
        ("slack", "slack.com"),
        ("teamviewer", "teamviewer.com"),
        ("wework", "wework.com"),
        ("heroku", "heroku.com"),
        ("jamf", "jamf.com"),
        ("intacct", "sage.com"), // Special case: Sage Intacct
        ("mailgun", "mailgun.com"),
        ("neat", "neat.co"),
        ("webex", "webex.com"),
        ("whimsical", "whimsical.com"),
        ("facebook", "facebook.com"),
        ("anthropic", "anthropic.com"),
        ("jetbrains", "jetbrains.com"),
        ("github", "github.com"),
        ("gitlab", "gitlab.com"),
        ("bitbucket", "bitbucket.org"),
        ("okta", "okta.com"),
        ("auth0", "auth0.com"),
        ("twilio", "twilio.com"),
        ("segment", "segment.com"),
        ("sentry", "sentry.io"),
        ("pagerduty", "pagerduty.com"),
        // Common generic mappings
        ("aws", "amazon.com"),
        ("gcp", "google.com"),
        ("azure", "microsoft.com"),
        ("salesforce", "salesforce.com"),
        ("shopify", "shopify.com"),
        ("zendesk", "zendesk.com"),
    ];

    for (name, domain) in &provider_mappings {
        if provider_name == *name {
            return Some(domain.to_string());
        }
    }

    // If no exact match, try appending .com as a fallback for common patterns
    if provider_name.len() > 2 && provider_name.chars().all(|c| c.is_alphanumeric()) {
        // Only do this for well-formed provider names to avoid false positives
        match provider_name {
            // Known cases where .com works
            "sendgrid" | "mailchimp" | "constantcontact" | "pardot" | "marketo" | "hubspot"
            | "intercom" | "freshdesk" | "typeform" => Some(format!("{}.com", provider_name)),
            _ => None,
        }
    } else {
        None
    }
}

fn is_valid_domain(domain: &str) -> bool {
    // Allow domains with underscores for SPF delegation patterns (e.g., _spf.google.com, _spf1.canva.com)
    // This matches RFC requirements for service records and SPF patterns
    // Each label can be 1-63 characters, starting with alphanumeric or underscore
    // Use pre-compiled regex for performance (B020 fix)

    // Additional validation: ensure no consecutive dots, no trailing dot (for our purposes)
    if domain.contains("..") || domain.ends_with('.') {
        return false;
    }

    // Check overall length and that it contains at least one dot
    DOMAIN_VALIDATION_REGEX.is_match(domain)
        && domain.contains('.')
        && domain.len() <= 253
        && domain.len() >= 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn test_extract_spf_records() {
        let records = vec!["v=spf1 include:_spf.google.com include:sendgrid.net ~all".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        assert!(!results.is_empty());
        let domains: Vec<&str> = results.iter().map(|r| r.domain.as_str()).collect();
        assert!(domains.iter().any(|d| d.contains("google")));
        assert!(domains.iter().any(|d| d.contains("sendgrid")));
    }

    #[test]
    fn test_extract_verification_records() {
        let records = vec![
            "google-site-verification=abc123".to_string(),
            "MS=ms12345678".to_string(),
            "docusign=abcdef-1234-5678".to_string(),
            "atlassian-domain-verification=abc123".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_extract_dmarc_record() {
        let records = vec![
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com"
                .to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        let _ = results;
    }

    #[test]
    fn test_extract_dkim_record() {
        let records =
            vec!["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ...".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        let _ = results;
    }

    #[test]
    fn test_extract_empty_records() {
        let results = extract_vendor_domains_with_source(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_no_match_records() {
        let records = vec!["just some random text".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_with_logger() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "random-unmatched-record".to_string(),
        ];
        let results = extract_vendor_domains_with_source_and_logger(&records, None, "example.com");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_extract_dedup() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "v=spf1 include:_spf.google.com ~all".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        let google_count = results
            .iter()
            .filter(|r| r.domain.contains("google"))
            .count();
        assert_eq!(google_count, 1);
    }

    #[test]
    fn test_extract_spf_multiple_includes() {
        let records = vec![
            "v=spf1 include:_spf.google.com include:amazonses.com include:mailgun.org -all"
                .to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        assert!(results.len() >= 3);
    }

    #[test]
    fn test_unescape_dns_txt() {
        assert_eq!(unescape_dns_txt("hello"), "hello");
        assert_eq!(unescape_dns_txt("he\\llo"), "hello");
        assert_eq!(unescape_dns_txt("test\\\\value"), "test\\value");
    }

    #[rstest]
    #[case("google.com", true)]
    #[case("sub.domain.co.uk", true)]
    #[case("_spf.google.com", true)]
    #[case("", false)]
    #[case("x", false)]
    #[case("no-dot", false)]
    #[case("a..b.com", false)]
    fn test_is_valid_domain(#[case] domain: &str, #[case] expected: bool) {
        assert_eq!(is_valid_domain(domain), expected, "domain: {}", domain);
    }

    #[test]
    fn test_dns_server_pool_new() {
        let pool = DnsServerPool::new();
        let _ = pool;
    }

    #[test]
    fn test_vendor_domain_source_types() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "google-site-verification=abc123".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        let spf_results: Vec<_> = results
            .iter()
            .filter(|r| r.source_type == RecordType::DnsTxtSpf)
            .collect();
        let verification_results: Vec<_> = results
            .iter()
            .filter(|r| r.source_type == RecordType::DnsTxtVerification)
            .collect();
        assert!(!spf_results.is_empty());
        assert!(!verification_results.is_empty());
    }

    // ====================================================================
    // Additional inline tests for private helper functions
    // ====================================================================

    // --- unescape_dns_txt edge cases ---

    #[test]
    fn test_unescape_dns_txt_empty() {
        assert_eq!(unescape_dns_txt(""), "");
    }

    #[test]
    fn test_unescape_dns_txt_trailing_backslash() {
        // Trailing backslash with nothing after it
        assert_eq!(unescape_dns_txt("test\\"), "test");
    }

    #[test]
    fn test_unescape_dns_txt_escaped_quote() {
        assert_eq!(unescape_dns_txt(r#"say \"hello\""#), r#"say "hello""#);
    }

    #[test]
    fn test_unescape_dns_txt_escaped_underscore() {
        assert_eq!(unescape_dns_txt("test\\_value"), "test_value");
    }

    // --- strip_spf_macros ---

    #[test]
    fn test_strip_spf_macros_simple() {
        assert_eq!(strip_spf_macros("%{ir}.%{v}.domain.com"), "domain.com");
    }

    #[test]
    fn test_strip_spf_macros_no_macros() {
        assert_eq!(strip_spf_macros("_spf.google.com"), "_spf.google.com");
    }

    #[test]
    fn test_strip_spf_macros_with_numbers() {
        // SPF macros can have optional digit modifiers
        assert_eq!(strip_spf_macros("%{d4r}.example.com"), "example.com");
    }

    // --- is_valid_domain edge cases ---

    #[test]
    fn test_is_valid_domain_trailing_dot() {
        assert!(!is_valid_domain("example.com."));
    }

    #[test]
    fn test_is_valid_domain_consecutive_dots() {
        assert!(!is_valid_domain("example..com"));
    }

    #[test]
    fn test_is_valid_domain_too_long() {
        let long_domain = format!("{}.com", "a".repeat(250));
        assert!(!is_valid_domain(&long_domain));
    }

    #[test]
    fn test_is_valid_domain_underscore_prefix() {
        assert!(is_valid_domain("_spf.google.com"));
        assert!(is_valid_domain("_dmarc.example.com"));
    }

    #[test]
    fn test_is_valid_domain_minimum_length() {
        // 4 chars minimum: a.co
        assert!(is_valid_domain("a.co"));
        // 3 chars: too short
        assert!(!is_valid_domain("a.c"));
    }

    // --- extract_from_spf_record ---

    #[test]
    fn test_extract_from_spf_non_spf_record() {
        assert!(extract_from_spf_record("not an spf record", None, "", "").is_none());
    }

    #[test]
    fn test_extract_from_spf_case_insensitive() {
        // RFC compliance: V=SPF1 should also match
        let result = extract_from_spf_record(
            "V=SPF1 include:_spf.google.com ~all",
            None,
            "test.com",
            "V=SPF1 include:_spf.google.com ~all",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_spf_redirect() {
        let result = extract_from_spf_record(
            "v=spf1 redirect=_spf.example.com",
            None,
            "test.com",
            "v=spf1 redirect=_spf.example.com",
        );
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain.contains("example")));
    }

    #[test]
    fn test_extract_from_spf_a_mechanism() {
        let result = extract_from_spf_record(
            "v=spf1 a:mail.example.com ~all",
            None,
            "test.com",
            "v=spf1 a:mail.example.com ~all",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_spf_mx_mechanism() {
        let result = extract_from_spf_record(
            "v=spf1 mx:mx.example.com ~all",
            None,
            "test.com",
            "v=spf1 mx:mx.example.com ~all",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_spf_exists_mechanism() {
        let result = extract_from_spf_record(
            "v=spf1 exists:example.com ~all",
            None,
            "test.com",
            "v=spf1 exists:example.com ~all",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_spf_ptr_mechanism() {
        let result = extract_from_spf_record(
            "v=spf1 ptr:example.com ~all",
            None,
            "test.com",
            "v=spf1 ptr:example.com ~all",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_spf_with_macros() {
        let result = extract_from_spf_record(
            "v=spf1 exists:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
            None,
            "test.com",
            "v=spf1 exists:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
        );
        assert!(result.is_some());
        let domains = result.unwrap();
        // After macro stripping, should extract pphosted.com base domain
        assert!(domains.iter().any(|d| d.domain.contains("pphosted")));
    }

    #[test]
    fn test_extract_from_spf_no_domains() {
        // SPF record with only ip4/ip6 mechanisms - no domains to extract
        let result = extract_from_spf_record(
            "v=spf1 ip4:192.168.1.0/24 ip6:::1 ~all",
            None,
            "test.com",
            "v=spf1 ip4:192.168.1.0/24 ~all",
        );
        assert!(result.is_none());
    }

    // --- extract_from_dkim_record ---

    #[test]
    fn test_extract_from_dkim_non_dkim() {
        assert!(extract_from_dkim_record("not a dkim record", None, "", "").is_none());
    }

    #[test]
    fn test_extract_from_dkim_no_domains() {
        // DKIM record with public key but no domain references
        let result = extract_from_dkim_record(
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBA; h=sha256; s=email",
            None,
            "test.com",
            "DKIM record",
        );
        // h=sha256 and s=email don't contain dots, so no domains extracted
        assert!(result.is_none());
    }

    // --- extract_from_dmarc_record ---

    #[test]
    fn test_extract_from_dmarc_non_dmarc() {
        assert!(extract_from_dmarc_record("not a dmarc record", None, "", "").is_none());
    }

    #[test]
    fn test_extract_from_dmarc_case_insensitive() {
        let result = extract_from_dmarc_record(
            "V=DMARC1; p=reject; rua=mailto:reports@example.com",
            None,
            "test.com",
            "V=DMARC1; p=reject; rua=mailto:reports@example.com",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_dmarc_multiple_mailto() {
        let result = extract_from_dmarc_record(
            "v=DMARC1; p=reject; rua=mailto:a@domain1.com,mailto:b@domain2.com; ruf=mailto:c@domain3.com",
            None,
            "test.com",
            "dmarc record",
        );
        assert!(result.is_some());
        let domains = result.unwrap();
        let domain_strs: Vec<&str> = domains.iter().map(|d| d.domain.as_str()).collect();
        assert!(domain_strs.contains(&"domain1.com"));
        assert!(domain_strs.contains(&"domain2.com"));
        assert!(domain_strs.contains(&"domain3.com"));
    }

    #[test]
    fn test_extract_from_dmarc_no_mailto() {
        let result = extract_from_dmarc_record(
            "v=DMARC1; p=none; sp=none",
            None,
            "test.com",
            "v=DMARC1; p=none",
        );
        assert!(result.is_none());
    }

    // --- extract_from_verification_record ---

    #[test]
    fn test_extract_from_verification_record_no_match() {
        assert!(extract_from_verification_record("random text", None, "", "").is_none());
    }

    // --- try_static_verification_patterns ---

    #[rstest]
    #[case("facebook-domain-verification=abc123", "facebook.com")]
    #[case("apple-domain-verification=abc123", "apple.com")]
    #[case("adobe-idp-site-verification=abc123", "adobe.com")]
    #[case("stripe-verification=abc123", "stripe.com")]
    #[case("docusign=abc123", "docusign.com")]
    #[case("dropbox-domain-verification=abc123", "dropbox.com")]
    #[case("ZOOM_verify_abc123", "zoom.us")]
    #[case("atlassian-domain-verification=abc123", "atlassian.com")]
    #[case("slack-domain-verification=abc123", "slack.com")]
    #[case("hubspot-domain-verification=abc123", "hubspot.com")]
    #[case("openai-domain-verification=abc123", "openai.com")]
    #[case("notion-domain-verification=abc123", "notion.so")]
    #[case("anthropic-domain-verification=abc123", "anthropic.com")]
    #[case("jetbrains-domain-verification=abc123", "jetbrains.com")]
    #[case("heroku-domain-verification=abc123", "heroku.com")]
    #[case("jamf-site-verification=abc123", "jamf.com")]
    #[case("intacct-esk=abc123", "sage.com")]
    #[case("mgverify=abc123", "mailgun.com")]
    #[case("have-i-been-pwned-verification=abc123", "haveibeenpwned.com")]
    fn test_static_verification_patterns(#[case] record: &str, #[case] expected_domain: &str) {
        let result = try_static_verification_patterns(record, None, "", record);
        assert!(result.is_some(), "Should match pattern: {}", record);
        let domains = result.unwrap();
        assert!(
            domains.iter().any(|d| d.domain == expected_domain),
            "Expected {} for record {}, got {:?}",
            expected_domain,
            record,
            domains.iter().map(|d| &d.domain).collect::<Vec<_>>()
        );
    }

    // --- infer_provider_domain ---

    #[rstest]
    #[case("google", Some("google.com"))]
    #[case("zoom", Some("zoom.us"))]
    #[case("notion", Some("notion.so"))]
    #[case("datadome", Some("datadome.co"))]
    #[case("aws", Some("amazon.com"))]
    #[case("azure", Some("microsoft.com"))]
    #[case("sendgrid", Some("sendgrid.com"))]
    #[case("mailchimp", Some("mailchimp.com"))]
    #[case("intercom", Some("intercom.com"))]
    fn test_infer_provider_domain(#[case] provider: &str, #[case] expected: Option<&str>) {
        assert_eq!(
            infer_provider_domain(provider),
            expected.map(|s| s.to_string()),
            "provider: {}",
            provider
        );
    }

    #[test]
    fn test_infer_provider_domain_unknown() {
        // Short names or unknown providers
        assert_eq!(infer_provider_domain("ab"), None);
        assert_eq!(infer_provider_domain("unknown_xyz"), None);
    }

    #[test]
    fn test_infer_provider_domain_known_fallback() {
        // Providers that get .com appended as fallback
        assert_eq!(
            infer_provider_domain("freshdesk"),
            Some("freshdesk.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("typeform"),
            Some("typeform.com".to_string())
        );
    }

    // --- try_dynamic_verification_patterns ---

    #[test]
    fn test_dynamic_verification_known_provider() {
        let result = try_dynamic_verification_patterns(
            "github-domain-verification=abc123",
            None,
            "",
            "github-domain-verification=abc123",
        );
        assert!(result.is_some());
        assert!(result.unwrap().iter().any(|d| d.domain == "github.com"));
    }

    #[test]
    fn test_dynamic_verification_site_verification_pattern() {
        let result = try_dynamic_verification_patterns(
            "okta-site-verification=abc123",
            None,
            "",
            "okta-site-verification=abc123",
        );
        assert!(result.is_some());
        assert!(result.unwrap().iter().any(|d| d.domain == "okta.com"));
    }

    #[test]
    fn test_dynamic_verification_prefix_pattern() {
        let result = try_dynamic_verification_patterns(
            "verification-sentry=abc123",
            None,
            "",
            "verification-sentry=abc123",
        );
        assert!(result.is_some());
        assert!(result.unwrap().iter().any(|d| d.domain == "sentry.io"));
    }

    // --- collect_spf_targets ---

    #[test]
    fn test_collect_spf_targets_basic() {
        let mut targets = Vec::new();
        let mut visited = std::collections::HashSet::new();
        collect_spf_targets(
            "v=spf1 include:spf.protection.outlook.com redirect=_spf.example.com ~all",
            &mut targets,
            &mut visited,
        );
        assert!(targets.contains(&"spf.protection.outlook.com".to_string()));
        assert!(targets.contains(&"_spf.example.com".to_string()));
    }

    #[test]
    fn test_collect_spf_targets_dedup() {
        let mut targets = Vec::new();
        let mut visited = std::collections::HashSet::new();
        collect_spf_targets(
            "v=spf1 include:spf.google.com include:spf.google.com ~all",
            &mut targets,
            &mut visited,
        );
        // Should only appear once
        assert_eq!(targets.iter().filter(|t| t.contains("google")).count(), 1);
    }

    // --- LogFailure trait with logger ---

    struct TestLogger {
        failures: std::sync::Mutex<Vec<String>>,
    }

    impl TestLogger {
        fn new() -> Self {
            Self {
                failures: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl LogFailure for TestLogger {
        fn log_failure(
            &self,
            source_domain: &str,
            record_type: &str,
            raw_record: &str,
            extracted_service: Option<&str>,
            failure_reason: &str,
        ) {
            self.failures.lock().unwrap().push(format!(
                "{}:{}:{}:{}:{}",
                source_domain,
                record_type,
                raw_record,
                extracted_service.unwrap_or("none"),
                failure_reason
            ));
        }
    }

    #[test]
    fn test_extract_with_logger_logs_unmatched() {
        let logger = TestLogger::new();
        let records = vec!["some-unmatched-but-long-enough-record".to_string()];
        let _ =
            extract_vendor_domains_with_source_and_logger(&records, Some(&logger), "example.com");
        let failures = logger.failures.lock().unwrap();
        assert!(!failures.is_empty(), "Should log unmatched records");
        assert!(failures[0].contains("UNMATCHED_TXT"));
    }

    #[test]
    fn test_extract_with_logger_skips_short_unmatched() {
        let logger = TestLogger::new();
        let records = vec!["short".to_string()];
        let _ =
            extract_vendor_domains_with_source_and_logger(&records, Some(&logger), "example.com");
        let failures = logger.failures.lock().unwrap();
        assert!(
            failures.is_empty(),
            "Should not log short unmatched records"
        );
    }

    // --- DnsServerPool default ---

    #[test]
    fn test_dns_server_pool_default() {
        let pool = DnsServerPool::default();
        assert!(!pool.doh_servers.is_empty());
        assert!(!pool.dns_servers.is_empty());
    }

    #[test]
    fn test_dns_server_pool_with_test_urls() {
        let pool = DnsServerPool::with_test_urls(vec![
            "http://localhost:8080/dns".to_string(),
            "http://localhost:8081/dns".to_string(),
        ]);
        assert_eq!(pool.doh_servers.len(), 2);
        assert_eq!(pool.doh_servers[0].name, "Test DoH Server 1");
        assert_eq!(pool.doh_servers[1].name, "Test DoH Server 2");
    }

    // --- DnsServerPool rotation ---

    #[test]
    fn test_dns_server_pool_rotation() {
        let pool = DnsServerPool::new();
        let first = pool.next_doh_server().name.clone();
        let second = pool.next_doh_server().name.clone();
        // Should rotate to different servers
        assert_ne!(first, second, "Should rotate between servers");
    }

    #[test]
    fn test_dns_server_pool_dns_rotation() {
        let pool = DnsServerPool::new();
        let first = pool.next_dns_server().name.clone();
        let second = pool.next_dns_server().name.clone();
        assert_ne!(first, second, "DNS servers should rotate");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // is_valid_domain — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_is_valid_domain_empty() {
        assert!(!is_valid_domain(""));
    }

    #[test]
    fn test_is_valid_domain_single_label() {
        assert!(!is_valid_domain("localhost"));
    }

    #[test]
    fn test_is_valid_domain_length_253() {
        let label = "a".repeat(60);
        let domain = format!("{}.{}.{}.{}.com", label, label, label, label);
        assert!(domain.len() <= 253, "60*4 + separators = 247, within 253 limit");
        assert!(is_valid_domain(&domain));
    }

    #[test]
    fn test_is_valid_domain_length_too_long() {
        let label = "a".repeat(63);
        let domain = format!("{}.{}.{}.{}.com", label, label, label, label);
        assert!(domain.len() > 253, "63*4 + separators = 259, exceeds 253 limit");
        assert!(!is_valid_domain(&domain));
    }

    #[test]
    fn test_is_valid_domain_spf_underscore_prefix() {
        // SPF delegation domains use underscore prefixes
        assert!(is_valid_domain("_spf.google.com"));
        assert!(is_valid_domain("_dmarc.example.com"));
        assert!(is_valid_domain("_domainkey.example.com"));
    }

    #[test]
    fn test_is_valid_domain_three_char_minimum() {
        assert!(!is_valid_domain("a.b")); // len < 4
        assert!(is_valid_domain("ab.cd")); // len == 5
    }

    #[test]
    fn test_is_valid_domain_hyphen_in_label() {
        assert!(is_valid_domain("my-domain.com"));
        assert!(is_valid_domain("sub-domain.example.com"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // unescape_dns_txt — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_unescape_dns_txt_no_escapes() {
        assert_eq!(unescape_dns_txt("hello world"), "hello world");
    }

    #[test]
    fn test_unescape_dns_txt_double_backslash() {
        assert_eq!(unescape_dns_txt("path\\\\file"), "path\\file");
    }

    #[test]
    fn test_unescape_dns_txt_mixed_escapes() {
        assert_eq!(
            unescape_dns_txt(r#"v=spf1 include:\_spf.google.com"#),
            "v=spf1 include:_spf.google.com"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // strip_spf_macros — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_strip_spf_macros_multiple_macros() {
        let input = "%{ir}.%{v}.%{d}.spf.has.pphosted.com";
        let result = strip_spf_macros(input);
        assert_eq!(result, "spf.has.pphosted.com");
    }

    #[test]
    fn test_strip_spf_macros_empty() {
        assert_eq!(strip_spf_macros(""), "");
    }

    #[test]
    fn test_strip_spf_macros_only_macros() {
        let result = strip_spf_macros("%{ir}.%{v}.");
        assert!(result.is_empty() || result == ".");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_from_spf_record — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_from_spf_record_with_macros() {
        let record = "v=spf1 exists:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all";
        let result = extract_from_spf_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain.contains("pphosted.com")));
    }

    #[test]
    fn test_extract_from_spf_all_mechanism_types() {
        let record = "v=spf1 include:spf.protection.outlook.com a:mail.example.com mx:mx.example.com ptr:ptr.example.com redirect=redirect.example.com ~all";
        let result = extract_from_spf_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        // Should have extracted from include, a, mx, ptr, and redirect
        assert!(domains.len() >= 4);
    }

    #[test]
    fn test_extract_from_spf_empty_record() {
        let record = "v=spf1 ~all";
        let result = extract_from_spf_record(record, None, "test.com", record);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_from_spf_with_ip4_mechanisms() {
        // ip4 mechanisms should be ignored (they're IPs, not domains)
        let record = "v=spf1 ip4:192.168.1.0/24 include:_spf.google.com ~all";
        let result = extract_from_spf_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        // Should only extract from include, not from ip4
        assert!(domains.iter().all(|d| !d.domain.contains("192.168")));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_from_dkim_record — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_from_dkim_record_rsa_only() {
        let record = "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        // The p= value is a base64 key, not a domain, so should be None
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_from_dkim_record_ed25519() {
        let record = "k=ed25519; p=dGVzdA==";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        assert!(result.is_none()); // No valid domains in key material
    }

    #[test]
    fn test_extract_from_dkim_record_not_dkim() {
        let record = "This is not a DKIM record at all";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        assert!(result.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_from_dmarc_record — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_from_dmarc_record_rua_and_ruf() {
        let record = "v=DMARC1; p=quarantine; rua=mailto:dmarc@agari.com; ruf=mailto:forensics@proofpoint.com";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "agari.com"));
        assert!(domains.iter().any(|d| d.domain == "proofpoint.com"));
    }

    #[test]
    fn test_extract_from_dmarc_record_sp_tag_not_extracted() {
        // sp= contains policy values, not domains
        let record = "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        // sp=quarantine should NOT produce a domain
        assert!(domains.iter().all(|d| d.domain != "quarantine"));
    }

    #[test]
    fn test_extract_from_dmarc_record_mixed_case() {
        let record = "V=DMARC1; p=reject; RUA=mailto:report@dmarcian.com";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "dmarcian.com"));
    }

    #[test]
    fn test_extract_from_dmarc_record_no_mailto() {
        let record = "v=DMARC1; p=none";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_from_verification_record — static patterns
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verification_record_stripe() {
        let record = "stripe-verification=abc123def";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "stripe.com"));
    }

    #[test]
    fn test_verification_record_zoom() {
        let record = "ZOOM_verify_abc123";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "zoom.us"));
    }

    #[test]
    fn test_verification_record_anthropic() {
        let record = "anthropic-domain-verification=xyz789";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "anthropic.com"));
    }

    #[test]
    fn test_verification_record_whimsical_angle_bracket() {
        let record = "<whimsical=abc123>";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "whimsical.com"));
    }

    #[test]
    fn test_verification_record_mailgun() {
        let record = "mgverify=abc123";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "mailgun.com"));
    }

    #[test]
    fn test_verification_record_sage_intacct() {
        let record = "intacct-esk=abc123";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "sage.com"));
    }

    #[test]
    fn test_verification_record_no_match() {
        let record = "some-random-text-not-a-verification-record";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // infer_provider_domain — additional cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_infer_provider_domain_cloud_providers() {
        assert_eq!(infer_provider_domain("aws"), Some("amazon.com".to_string()));
        assert_eq!(infer_provider_domain("gcp"), Some("google.com".to_string()));
        assert_eq!(
            infer_provider_domain("azure"),
            Some("microsoft.com".to_string())
        );
    }

    #[test]
    fn test_infer_provider_domain_common_saas() {
        assert_eq!(
            infer_provider_domain("salesforce"),
            Some("salesforce.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("shopify"),
            Some("shopify.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("zendesk"),
            Some("zendesk.com".to_string())
        );
    }

    #[test]
    fn test_infer_provider_domain_known_fallback_com_providers() {
        assert_eq!(
            infer_provider_domain("sendgrid"),
            Some("sendgrid.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("mailchimp"),
            Some("mailchimp.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("intercom"),
            Some("intercom.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("typeform"),
            Some("typeform.com".to_string())
        );
    }

    #[test]
    fn test_infer_provider_domain_returns_none_for_unknown() {
        assert_eq!(infer_provider_domain("xyzunknownprovider"), None);
        assert_eq!(infer_provider_domain("ab"), None); // too short
    }

    #[test]
    fn test_infer_provider_domain_security_vendors() {
        assert_eq!(
            infer_provider_domain("sentry"),
            Some("sentry.io".to_string())
        );
        assert_eq!(infer_provider_domain("okta"), Some("okta.com".to_string()));
        assert_eq!(
            infer_provider_domain("auth0"),
            Some("auth0.com".to_string())
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // try_dynamic_verification_patterns — edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_dynamic_verification_domain_verification_pattern() {
        let record = "hubspot-domain-verification=abc123";
        let result = try_dynamic_verification_patterns(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "hubspot.com"));
    }

    #[test]
    fn test_dynamic_verification_verification_prefix() {
        let record = "verification-sentry=abc123";
        let result = try_dynamic_verification_patterns(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "sentry.io"));
    }

    #[test]
    fn test_dynamic_verification_provider_verify_uppercase() {
        let record = "TWILIO_verify_abc123";
        let result = try_dynamic_verification_patterns(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "twilio.com"));
    }

    #[test]
    fn test_dynamic_verification_unknown_provider() {
        let record = "unknownxyz-domain-verification=abc123";
        let result = try_dynamic_verification_patterns(record, None, "test.com", record);
        // Unknown provider should not produce results
        assert!(result.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // collect_spf_targets — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_collect_spf_targets_with_macros() {
        let record = "v=spf1 include:%{ir}._spf.google.com redirect=_spf.salesforce.com ~all";
        let mut to_resolve = Vec::new();
        let mut visited = HashSet::new();
        collect_spf_targets(record, &mut to_resolve, &mut visited);
        // Should strip macros and collect valid targets
        assert!(to_resolve.iter().any(|t| t.contains("google.com")));
        assert!(to_resolve.iter().any(|t| t.contains("salesforce.com")));
    }

    #[test]
    fn test_collect_spf_targets_no_targets() {
        let record = "v=spf1 ip4:192.168.1.0/24 ~all";
        let mut to_resolve = Vec::new();
        let mut visited = HashSet::new();
        collect_spf_targets(record, &mut to_resolve, &mut visited);
        assert!(to_resolve.is_empty());
    }

    #[test]
    fn test_collect_spf_targets_visited_dedup() {
        let record = "v=spf1 include:_spf.google.com include:_spf.google.com ~all";
        let mut to_resolve = Vec::new();
        let mut visited = HashSet::new();
        collect_spf_targets(record, &mut to_resolve, &mut visited);
        // Should only have one entry despite duplicate includes
        let google_count = to_resolve.iter().filter(|t| t.contains("google")).count();
        assert_eq!(google_count, 1);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_vendor_domains_with_source — integration edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_vendor_domains_multiple_record_types() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "google-site-verification=abc123".to_string(),
            "v=DMARC1; p=reject; rua=mailto:report@proofpoint.com".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        assert!(results.len() >= 3); // At least one from each record type
        let source_types: Vec<String> = results
            .iter()
            .map(|r| r.source_type.as_hierarchy_string())
            .collect();
        assert!(source_types.iter().any(|t| t.contains("SPF")));
        assert!(source_types.iter().any(|t| t.contains("VERIFICATION")));
        assert!(source_types.iter().any(|t| t.contains("DMARC")));
    }

    #[test]
    fn test_extract_vendor_domains_empty_records() {
        let records: Vec<String> = vec![];
        let results = extract_vendor_domains_with_source(&records);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_vendor_domains_quoted_records() {
        // DNS TXT records are often wrapped in quotes
        let records = vec!["\"v=spf1 include:_spf.google.com ~all\"".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_extract_vendor_domains_dedup_same_entry() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "v=spf1 include:_spf.google.com ~all".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        // Should deduplicate identical entries
        let google_count = results
            .iter()
            .filter(|r| r.domain.contains("google"))
            .count();
        assert_eq!(google_count, 1);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VendorDomain struct and RecordType coverage
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_vendor_domain_debug() {
        let vd = VendorDomain {
            domain: "stripe.com".to_string(),
            source_type: RecordType::DnsTxtSpf,
            raw_record: "v=spf1 include:stripe.com".to_string(),
        };
        let debug_str = format!("{:?}", vd);
        assert!(debug_str.contains("stripe.com"));
    }

    #[test]
    fn test_vendor_domain_fields() {
        let vd = VendorDomain {
            domain: "stripe.com".to_string(),
            source_type: RecordType::DnsTxtSpf,
            raw_record: "v=spf1 include:stripe.com".to_string(),
        };
        assert_eq!(vd.domain, "stripe.com");
        assert_eq!(vd.raw_record, "v=spf1 include:stripe.com");
        assert_eq!(
            vd.source_type.as_hierarchy_string(),
            RecordType::DnsTxtSpf.as_hierarchy_string()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DnsServerPool — additional coverage
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_dns_server_pool_wraps_around() {
        let pool = DnsServerPool::new();
        let server_count = pool.doh_servers.len();
        // Access one more than the total to trigger wrap-around
        let mut names: Vec<String> = Vec::new();
        for _ in 0..=server_count {
            names.push(pool.next_doh_server().name.clone());
        }
        // The (server_count+1)th should wrap back to the first
        assert_eq!(names[0], names[server_count]);
    }

    #[test]
    fn test_dns_server_pool_dns_wraps_around() {
        let pool = DnsServerPool::new();
        let server_count = pool.dns_servers.len();
        let mut names: Vec<String> = Vec::new();
        for _ in 0..=server_count {
            names.push(pool.next_dns_server().name.clone());
        }
        assert_eq!(names[0], names[server_count]);
    }

    #[test]
    fn test_dns_server_pool_test_urls_empty() {
        let pool = DnsServerPool::with_test_urls(vec![]);
        assert!(pool.doh_servers.is_empty());
    }

    #[test]
    fn test_doh_server_config_fields() {
        let config = DohServerConfig {
            url: "https://dns.google/dns-query".to_string(),
            name: "Google DoH".to_string(),
            timeout_secs: 3,
        };
        assert_eq!(config.url, "https://dns.google/dns-query");
        assert_eq!(config.name, "Google DoH");
        assert_eq!(config.timeout_secs, 3);
    }

    #[test]
    fn test_dns_server_config_fields() {
        let config = DnsServerConfig {
            address: "1.1.1.1:53".to_string(),
            name: "Cloudflare".to_string(),
            timeout_secs: 2,
        };
        assert_eq!(config.address, "1.1.1.1:53");
        assert_eq!(config.name, "Cloudflare");
        assert_eq!(config.timeout_secs, 2);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Async DNS tests using wiremock for DoH mocking
    // ═══════════════════════════════════════════════════════════════════════════

    /// Helper: build a DoH JSON response for TXT records
    fn build_doh_txt_response(domain: &str, txt_records: &[&str]) -> serde_json::Value {
        let answers: Vec<serde_json::Value> = txt_records
            .iter()
            .map(|txt| {
                serde_json::json!({
                    "name": domain,
                    "type": 16,
                    "TTL": 300,
                    "data": format!("\"{}\"", txt)
                })
            })
            .collect();
        serde_json::json!({
            "Status": 0,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [{"name": domain, "type": 16}],
            "Answer": answers
        })
    }

    /// Helper: build a DoH JSON response for CNAME records
    fn build_doh_cname_response(domain: &str, cnames: &[&str]) -> serde_json::Value {
        let answers: Vec<serde_json::Value> = cnames
            .iter()
            .map(|cname| {
                serde_json::json!({
                    "name": domain,
                    "type": 5,
                    "TTL": 300,
                    "data": format!("{}.", cname)
                })
            })
            .collect();
        serde_json::json!({
            "Status": 0,
            "Question": [{"name": domain, "type": 5}],
            "Answer": answers
        })
    }

    /// Helper: build an empty DoH response (no answers)
    fn build_doh_empty_response(domain: &str) -> serde_json::Value {
        serde_json::json!({
            "Status": 0,
            "Question": [{"name": domain, "type": 16}],
            "Answer": []
        })
    }

    // --- doh_txt_lookup tests ---

    #[tokio::test]
    async fn test_doh_txt_lookup_success() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = build_doh_txt_response(
            "example.com",
            &["v=spf1 include:_spf.google.com ~all"],
        );

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "example.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool.doh_txt_lookup("example.com", doh_server).await.unwrap();

        assert_eq!(records.len(), 1);
        assert!(records[0].contains("spf1"));
    }

    #[tokio::test]
    async fn test_doh_txt_lookup_multiple_records() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = build_doh_txt_response(
            "multi.com",
            &[
                "v=spf1 include:sendgrid.net ~all",
                "google-site-verification=abc123",
                "v=DMARC1; p=reject; rua=mailto:dmarc@multi.com",
            ],
        );

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "multi.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool.doh_txt_lookup("multi.com", doh_server).await.unwrap();

        assert_eq!(records.len(), 3);
    }

    #[tokio::test]
    async fn test_doh_txt_lookup_empty_response() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = build_doh_empty_response("empty.com");

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "empty.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool.doh_txt_lookup("empty.com", doh_server).await.unwrap();

        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn test_doh_txt_lookup_non_txt_type_ignored() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        // Answer with type=1 (A record) instead of type=16 (TXT)
        let response = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "mix.com", "type": 16}],
            "Answer": [
                {"name": "mix.com", "type": 1, "TTL": 300, "data": "1.2.3.4"},
                {"name": "mix.com", "type": 16, "TTL": 300, "data": "\"v=spf1 ~all\""}
            ]
        });

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "mix.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool.doh_txt_lookup("mix.com", doh_server).await.unwrap();

        // Should only have the TXT record, not the A record
        assert_eq!(records.len(), 1);
        assert!(records[0].contains("spf1"));
    }

    // --- doh_cname_lookup tests ---

    #[tokio::test]
    async fn test_doh_cname_lookup_success() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = build_doh_cname_response("alias.com", &["target.example.com"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "alias.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool.doh_cname_lookup("alias.com", doh_server).await.unwrap();

        assert_eq!(records.len(), 1);
        // Trailing dot should be removed
        assert_eq!(records[0], "target.example.com");
    }

    #[tokio::test]
    async fn test_doh_cname_lookup_empty() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "nocname.com", "type": 5}],
            "Answer": []
        });

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "nocname.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool.doh_cname_lookup("nocname.com", doh_server).await.unwrap();

        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn test_doh_cname_lookup_non_cname_type_ignored() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        // Answer has type=1 (A record) but not type=5 (CNAME)
        let response = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "nocname.com", "type": 5}],
            "Answer": [
                {"name": "nocname.com", "type": 1, "TTL": 300, "data": "1.2.3.4"}
            ]
        });

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "nocname.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool.doh_cname_lookup("nocname.com", doh_server).await.unwrap();

        assert!(records.is_empty());
    }

    // --- get_txt_records_with_pool tests ---

    #[tokio::test]
    async fn test_get_txt_records_with_pool_via_doh() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = build_doh_txt_response(
            "test.com",
            &["v=spf1 include:_spf.google.com ~all"],
        );

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "test.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_txt_records_with_pool("test.com", &pool).await.unwrap();

        assert!(!records.is_empty());
        assert!(records[0].contains("spf1"));
    }

    #[tokio::test]
    async fn test_get_txt_records_with_pool_doh_failure_fallback() {
        // DoH server returns error, should fall back to traditional DNS then system
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::method;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        // This will fail DoH, try DNS fallback (which will also likely fail on 127.0.0.1:53),
        // then try system resolver. End result: either records or empty vec.
        let records = get_txt_records_with_pool("nonexistent-domain-xyz.invalid", &pool)
            .await
            .unwrap();
        // Just verify it doesn't panic and returns a result
        let _ = records;
    }

    // --- get_cname_records_with_pool tests ---

    #[tokio::test]
    async fn test_get_cname_records_with_pool_via_doh() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = build_doh_cname_response("alias.example.com", &["target.cdn.com"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "alias.example.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_cname_records_with_pool("alias.example.com", &pool)
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0], "target.cdn.com");
    }

    #[tokio::test]
    async fn test_get_cname_records_with_pool_empty() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "nocname.test", "type": 5}],
            "Answer": []
        });

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "nocname.test"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_cname_records_with_pool("nocname.test", &pool)
            .await
            .unwrap();

        assert!(records.is_empty());
    }

    // --- get_txt_and_cname_fast tests ---

    #[tokio::test]
    async fn test_get_txt_and_cname_fast() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;

        // TXT response
        let txt_response = build_doh_txt_response("fast.com", &["v=spf1 ~all"]);
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "fast.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(txt_response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        // CNAME response
        let cname_response = build_doh_cname_response("fast.com", &["cdn.fast.com"]);
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "fast.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(cname_response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let (txt_records, cname_records) = pool.get_txt_and_cname_fast("fast.com").await;

        assert!(!txt_records.is_empty());
        assert!(!cname_records.is_empty());
    }

    #[tokio::test]
    async fn test_get_txt_and_cname_fast_doh_failure() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::method;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let (txt_records, cname_records) = pool.get_txt_and_cname_fast("failing.invalid").await;

        // Both should return empty vec on failure (unwrap_or_default)
        // They may or may not be empty depending on DNS fallback
        let _ = txt_records;
        let _ = cname_records;
    }

    // --- get_txt_records_with_rate_limit tests ---

    #[tokio::test]
    async fn test_get_txt_records_with_rate_limit_no_limiter() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("ratelimit.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "ratelimit.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_txt_records_with_rate_limit("ratelimit.com", &pool, None)
            .await
            .unwrap();

        assert!(!records.is_empty());
    }

    #[tokio::test]
    async fn test_get_txt_records_with_rate_limit_with_limiter() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};
        use crate::rate_limit::RateLimitContext;
        use crate::config::RateLimitConfig;

        let server = MockServer::start().await;
        let response = build_doh_txt_response("limited.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "limited.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let rate_config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 10,
            whois_queries_per_second: 2,
            backoff_strategy: Default::default(),
            max_retries: 3,
            backoff_base_delay_ms: 100,
            backoff_max_delay_ms: 1000,
        };
        let ctx = RateLimitContext::from_config(&rate_config);
        let records = get_txt_records_with_rate_limit("limited.com", &pool, Some(&ctx))
            .await
            .unwrap();

        assert!(!records.is_empty());
    }

    // --- get_cname_records_with_rate_limit tests ---

    #[tokio::test]
    async fn test_get_cname_records_with_rate_limit_no_limiter() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = build_doh_cname_response("cname-rl.com", &["target.cdn.com"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "cname-rl.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_cname_records_with_rate_limit("cname-rl.com", &pool, None)
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0], "target.cdn.com");
    }

    #[tokio::test]
    async fn test_get_cname_records_with_rate_limit_with_limiter() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};
        use crate::rate_limit::RateLimitContext;
        use crate::config::RateLimitConfig;

        let server = MockServer::start().await;
        let response = build_doh_cname_response("cname-limited.com", &["target.example.com"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "cname-limited.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let rate_config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 10,
            whois_queries_per_second: 2,
            backoff_strategy: Default::default(),
            max_retries: 3,
            backoff_base_delay_ms: 100,
            backoff_max_delay_ms: 1000,
        };
        let ctx = RateLimitContext::from_config(&rate_config);
        let records = get_cname_records_with_rate_limit("cname-limited.com", &pool, Some(&ctx))
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
    }

    // --- create_dns_resolver tests ---

    #[test]
    fn test_create_dns_resolver_valid_address() {
        let pool = DnsServerPool::new();
        let server = &pool.dns_servers[0];
        let resolver = pool.create_dns_resolver(server, false);
        assert!(resolver.is_ok());
    }

    #[test]
    fn test_create_dns_resolver_tcp() {
        let pool = DnsServerPool::new();
        let server = &pool.dns_servers[0];
        let resolver = pool.create_dns_resolver(server, true);
        assert!(resolver.is_ok());
    }

    #[test]
    fn test_create_dns_resolver_invalid_address() {
        let pool = DnsServerPool::new();
        let bad_server = DnsServerConfig {
            address: "not-an-ip-address".to_string(),
            name: "Bad Server".to_string(),
            timeout_secs: 2,
        };
        let resolver = pool.create_dns_resolver(&bad_server, false);
        assert!(resolver.is_err());
        let err = resolver.unwrap_err().to_string();
        assert!(err.contains("Invalid DNS server address"));
        assert!(err.contains("Bad Server"));
    }

    // --- resolve_spf_includes_recursive tests ---

    #[tokio::test]
    async fn test_resolve_spf_includes_recursive_no_spf() {
        let pool = DnsServerPool::new();
        let records = vec!["not an spf record".to_string()];
        let result = resolve_spf_includes_recursive(&records, &pool, "test.com").await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_spf_includes_recursive_no_includes() {
        let pool = DnsServerPool::new();
        let records = vec!["v=spf1 ip4:192.168.1.0/24 ~all".to_string()];
        let result = resolve_spf_includes_recursive(&records, &pool, "test.com").await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_spf_includes_recursive_with_mock() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;

        // First level: initial SPF includes _spf.nested.com
        // When we resolve _spf.nested.com, it returns another SPF with a vendor
        let nested_response = build_doh_txt_response(
            "_spf.nested.com",
            &["v=spf1 include:spf.vendor.com ~all"],
        );

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "_spf.nested.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(nested_response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        // Second level: spf.vendor.com has a simple SPF
        let vendor_response = build_doh_txt_response(
            "spf.vendor.com",
            &["v=spf1 ip4:10.0.0.0/8 ~all"],
        );

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "spf.vendor.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(vendor_response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let initial_records = vec!["v=spf1 include:_spf.nested.com ~all".to_string()];
        let result = resolve_spf_includes_recursive(&initial_records, &pool, "test.com").await;

        // Should have found vendor.com from the nested SPF
        assert!(result.iter().any(|d| d.domain.contains("vendor")));
    }

    #[tokio::test]
    async fn test_resolve_spf_includes_recursive_failed_lookup() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::method;

        let server = MockServer::start().await;
        // DoH server always returns 500
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let initial_records = vec!["v=spf1 include:_spf.fails.com ~all".to_string()];
        let result = resolve_spf_includes_recursive(&initial_records, &pool, "test.com").await;

        // Should handle failures gracefully
        let _ = result;
    }

    // --- DnsServerPool from_config test ---

    #[test]
    fn test_dns_server_pool_from_config() {
        use crate::config::AppConfig;

        // Try config-based pool; fall back to default if config unavailable.
        // Both paths must produce non-empty server lists.
        let pool = AppConfig::load()
            .map(|c| DnsServerPool::from_config(&c))
            .unwrap_or_else(|_| DnsServerPool::new());
        assert!(!pool.doh_servers.is_empty());
        assert!(!pool.dns_servers.is_empty());
    }

    // --- fast_txt_lookup and fast_cname_lookup tests ---

    #[tokio::test]
    async fn test_fast_txt_lookup_doh_success() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("fast-txt.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "fast-txt.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let result = pool.fast_txt_lookup("fast-txt.com").await.unwrap();

        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn test_fast_txt_lookup_doh_failure_dns_fallback() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::method;

        let server = MockServer::start().await;
        // DoH returns empty/error
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let result = pool.fast_txt_lookup("nonexistent.invalid").await.unwrap();
        // Will fall back to DNS then return empty
        let _ = result;
    }

    #[tokio::test]
    async fn test_fast_cname_lookup_doh_success() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        let response = build_doh_cname_response("fast-cname.com", &["target.cdn.com"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "fast-cname.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let result = pool.fast_cname_lookup("fast-cname.com").await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "target.cdn.com");
    }

    #[tokio::test]
    async fn test_fast_cname_lookup_doh_failure_dns_fallback() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::method;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let result = pool.fast_cname_lookup("nonexistent.invalid").await.unwrap();
        let _ = result;
    }

    // --- get_txt_records (without pool) ---

    #[tokio::test]
    async fn test_get_txt_records_creates_default_pool() {
        // This will use the real DNS pool and make actual DNS queries
        // Test with a domain that definitely won't have TXT records
        let result = get_txt_records("this-domain-does-not-exist-xyz.invalid").await;
        // Should not panic, should return Ok (possibly empty)
        assert!(result.is_ok());
    }

    // --- DoH with escaped TXT records ---

    #[tokio::test]
    async fn test_doh_txt_lookup_with_escaped_data() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path, query_param};

        let server = MockServer::start().await;
        // Response with escaped characters in TXT data
        let response = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "escaped.com", "type": 16}],
            "Answer": [
                {
                    "name": "escaped.com",
                    "type": 16,
                    "TTL": 300,
                    "data": "\"v=spf1 include:\\_spf.google.com ~all\""
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "escaped.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool.doh_txt_lookup("escaped.com", doh_server).await.unwrap();

        assert_eq!(records.len(), 1);
        // The unescape function should handle \_ -> _
        assert!(records[0].contains("_spf.google.com"));
    }

    // --- DMARC with logger for invalid domain ---

    #[test]
    fn test_extract_from_dmarc_record_with_logger_invalid_domain() {
        let logger = TestLogger::new();
        let record = "v=DMARC1; p=reject; rua=mailto:x@a";
        let result = extract_from_dmarc_record(record, Some(&logger), "test.com", record);
        // "a" is not a valid domain (too short, no dot), so logger should capture failure
        let _failures = logger.failures.lock().unwrap();
        assert!(result.is_none(), "invalid domain should yield no results");
    }

    // --- SPF with logger for invalid domain ---

    #[test]
    fn test_extract_from_spf_with_logger_invalid_domain() {
        let logger = TestLogger::new();
        let record = "v=spf1 include:x ~all";
        let result = extract_from_spf_record(record, Some(&logger), "test.com", record);
        // "x" is not a valid domain, so logger should be called
        assert!(result.is_none());
        let failures = logger.failures.lock().unwrap();
        assert!(
            !failures.is_empty(),
            "Should log failure for invalid SPF domain"
        );
        assert!(failures[0].contains("SPF"));
    }

    // --- Comprehensive vendor domain extraction with all record types ---

    #[test]
    fn test_extract_vendor_domains_comprehensive() {
        let records = vec![
            // SPF with multiple mechanisms using unique domains to avoid dedup
            "v=spf1 include:_spf.google.com a:mail.sendgrid.net mx:mx.outlook.com ptr:ptr.mailgun.org ~all".to_string(),
            // DMARC with rua and ruf
            "v=DMARC1; p=reject; rua=mailto:dmarc@proofpoint.com; ruf=mailto:forensics@agari.com".to_string(),
            // Multiple verification records
            "google-site-verification=abc123".to_string(),
            "facebook-domain-verification=xyz789".to_string(),
            "apple-domain-verification=def456".to_string(),
            "MS=msxxxxxxxx".to_string(),
            "stripe-verification=stripe123".to_string(),
            "slack-domain-verification=slack456".to_string(),
            // DKIM record
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        // Should have extracted from SPF, DMARC, and verification records
        assert!(results.len() >= 8);

        // Check record types are correct
        let spf_count = results.iter().filter(|r| r.source_type == RecordType::DnsTxtSpf).count();
        let dmarc_count = results.iter().filter(|r| r.source_type == RecordType::DnsTxtDmarc).count();
        let verif_count = results.iter().filter(|r| r.source_type == RecordType::DnsTxtVerification).count();
        assert!(spf_count >= 3, "Should have at least 3 SPF domains, got {}", spf_count);
        assert!(dmarc_count >= 2, "Should have at least 2 DMARC domains, got {}", dmarc_count);
        assert!(verif_count >= 4, "Should have at least 4 verification domains, got {}", verif_count);
    }

    // --- Additional static verification patterns ---

    #[rstest]
    #[case("globalsign-domain-verification=abc", "globalsign.com")]
    #[case("browserstack-domain-verification=abc", "browserstack.com")]
    #[case("canva-site-verification=abc", "canva.com")]
    #[case("cursor-domain-verification=abc", "cursor.com")]
    #[case("datadome-domain-verify=abc", "datadome.co")]
    #[case("drift-domain-verification=abc", "drift.com")]
    #[case("klaviyo-site-verification=abc", "klaviyo.com")]
    #[case("onetrust-domain-verification=abc", "onetrust.com")]
    #[case("postman-domain-verification=abc", "postman.com")]
    #[case("teamviewer-sso-verification=abc", "teamviewer.com")]
    #[case("wework-site-verification=abc", "wework.com")]
    #[case("webex-domain-verification=abc", "webex.com")]
    #[case("zoom-domain-verification=abc", "zoom.us")]
    #[case("neat-pulse-domain-verification=abc", "neat.co")]
    #[case("gc-ai-domain-verification=abc", "gc-ai.com")]
    fn test_additional_static_verification_patterns(
        #[case] record: &str,
        #[case] expected_domain: &str,
    ) {
        let result = try_static_verification_patterns(record, None, "", record);
        assert!(result.is_some(), "Should match pattern: {}", record);
        let domains = result.unwrap();
        assert!(
            domains.iter().any(|d| d.domain == expected_domain),
            "Expected {} for record {}, got {:?}",
            expected_domain,
            record,
            domains.iter().map(|d| &d.domain).collect::<Vec<_>>()
        );
    }

    // --- infer_provider_domain: additional providers ---

    #[rstest]
    #[case("constantcontact", Some("constantcontact.com"))]
    #[case("pardot", Some("pardot.com"))]
    #[case("marketo", Some("marketo.com"))]
    #[case("github", Some("github.com"))]
    #[case("gitlab", Some("gitlab.com"))]
    #[case("bitbucket", Some("bitbucket.org"))]
    #[case("twilio", Some("twilio.com"))]
    #[case("segment", Some("segment.com"))]
    #[case("pagerduty", Some("pagerduty.com"))]
    fn test_infer_provider_domain_additional(
        #[case] provider: &str,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(
            infer_provider_domain(provider),
            expected.map(|s| s.to_string()),
            "provider: {}",
            provider
        );
    }

    // --- infer_provider_domain: special cases ---

    #[test]
    fn test_infer_provider_domain_special_char_in_name() {
        // Provider with non-alphanumeric chars - should return None
        assert_eq!(infer_provider_domain("test-provider"), None);
        assert_eq!(infer_provider_domain("test_provider"), None);
    }

    #[test]
    fn test_infer_provider_domain_single_char() {
        assert_eq!(infer_provider_domain("a"), None);
    }

    // --- DMARC edge cases ---

    #[test]
    fn test_extract_from_dmarc_record_ruf_only() {
        let record = "v=DMARC1; p=reject; ruf=mailto:forensics@mimecast.com";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "mimecast.com"));
    }

    #[test]
    fn test_extract_from_dmarc_record_rua_without_at_sign() {
        // mailto:domain (without user@)
        let record = "v=DMARC1; p=reject; rua=mailto:reporting.example.com";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "reporting.example.com"));
    }

    // --- extract_vendor_domains with quoted and escaped records ---

    #[test]
    fn test_extract_vendor_domains_backslash_escaped() {
        let records = vec!["v=spf1 include:\\_spf.google.com ~all".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_extract_vendor_domains_double_quoted() {
        let records =
            vec!["\"v=spf1 include:_spf.google.com ~all\"".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        assert!(!results.is_empty());
    }

    // --- DnsServerPool with single server ---

    #[test]
    fn test_dns_server_pool_with_single_test_url() {
        let pool = DnsServerPool::with_test_urls(vec!["http://localhost:1234/dns-query".to_string()]);
        assert_eq!(pool.doh_servers.len(), 1);
        assert_eq!(pool.dns_servers.len(), 1);
        // Rotation with single server should always return the same
        let first = pool.next_doh_server().name.clone();
        let second = pool.next_doh_server().name.clone();
        assert_eq!(first, second);
    }

    // --- DohServerConfig and DnsServerConfig debug ---

    #[test]
    fn test_doh_server_config_debug() {
        let config = DohServerConfig {
            url: "https://dns.example.com/dns-query".to_string(),
            name: "Test".to_string(),
            timeout_secs: 5,
        };
        let debug = format!("{:?}", config);
        assert!(debug.contains("Test"));
        assert!(debug.contains("dns.example.com"));
    }

    #[test]
    fn test_dns_server_config_debug() {
        let config = DnsServerConfig {
            address: "8.8.8.8:53".to_string(),
            name: "Google".to_string(),
            timeout_secs: 2,
        };
        let debug = format!("{:?}", config);
        assert!(debug.contains("Google"));
        assert!(debug.contains("8.8.8.8"));
    }

    // --- DohServerConfig and DnsServerConfig clone ---

    #[test]
    fn test_doh_server_config_clone() {
        let config = DohServerConfig {
            url: "https://dns.test.com/dns-query".to_string(),
            name: "Clone Test".to_string(),
            timeout_secs: 3,
        };
        let cloned = config.clone();
        assert_eq!(config.url, cloned.url);
        assert_eq!(config.name, cloned.name);
        assert_eq!(config.timeout_secs, cloned.timeout_secs);
    }

    #[test]
    fn test_dns_server_config_clone() {
        let config = DnsServerConfig {
            address: "1.1.1.1:53".to_string(),
            name: "Clone Test".to_string(),
            timeout_secs: 2,
        };
        let cloned = config.clone();
        assert_eq!(config.address, cloned.address);
        assert_eq!(config.name, cloned.name);
        assert_eq!(config.timeout_secs, cloned.timeout_secs);
    }

    // ═══════════════════════════════════════════════════════════════════
    // DKIM record extraction with domain references
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_from_dkim_record_with_domain_in_s_tag() {
        // DKIM record where s= tag contains a valid domain
        let record = "v=DKIM1; k=rsa; s=mail.vendor.com; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "mail.vendor.com"));
        assert!(domains.iter().all(|d| d.source_type == RecordType::DnsTxtDkim));
    }

    #[test]
    fn test_extract_from_dkim_record_with_domain_in_h_tag() {
        // DKIM record where h= tag contains a valid domain (unusual but possible)
        let record = "v=DKIM1; k=rsa; h=hash.provider.org; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "hash.provider.org"));
    }

    #[test]
    fn test_dkim_record_through_full_extraction_pipeline() {
        // Test that DKIM records with domain references flow through the full pipeline
        let records = vec![
            "v=DKIM1; k=rsa; s=selector.mailservice.com; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ"
                .to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        assert!(results.iter().any(|d| d.domain == "selector.mailservice.com"));
    }

    #[test]
    fn test_dkim_record_ed25519_with_domain() {
        let record = "v=DKIM1; k=ed25519; s=dkim.thirdparty.net; p=abcdef1234567890";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "dkim.thirdparty.net"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Dynamic verification patterns — cover all 4 pattern branches
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_dynamic_verification_all_four_patterns_in_one() {
        // Pattern 1: *-domain-verification=
        let r1 = "stripe-domain-verification=abc123";
        let res1 = try_dynamic_verification_patterns(r1, None, "test.com", r1);
        assert!(res1.is_some());
        assert!(res1.unwrap().iter().any(|d| d.domain == "stripe.com"));

        // Pattern 2: verification-*=
        let r2 = "verification-okta=abc123";
        let res2 = try_dynamic_verification_patterns(r2, None, "test.com", r2);
        assert!(res2.is_some());
        assert!(res2.unwrap().iter().any(|d| d.domain == "okta.com"));

        // Pattern 3: *-site-verification=
        let r3 = "adobe-site-verification=abc123";
        let res3 = try_dynamic_verification_patterns(r3, None, "test.com", r3);
        assert!(res3.is_some());
        assert!(res3.unwrap().iter().any(|d| d.domain == "adobe.com"));

        // Pattern 4: PROVIDER_verify_
        let r4 = "ZOOM_verify_abc123";
        let res4 = try_dynamic_verification_patterns(r4, None, "test.com", r4);
        assert!(res4.is_some());
        assert!(res4.unwrap().iter().any(|d| d.domain == "zoom.us"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // try_system_dns_resolver — previously coverage(off)
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_try_system_dns_resolver_valid_domain() {
        let result = try_system_dns_resolver("google.com").await;
        match result {
            Ok(records) => {
                // google.com has TXT records (SPF, verification, etc.)
                assert!(!records.is_empty(), "google.com should have TXT records");
                let has_spf = records.iter().any(|r| r.contains("spf"));
                assert!(has_spf, "google.com TXT records should include SPF: {:?}", records);
            }
            Err(e) => {
                // DNS resolution may fail in sandboxed/offline environments
                let msg = e.to_string();
                assert!(!msg.is_empty(), "Error message should be descriptive: {}", msg);
            }
        }
    }

    #[tokio::test]
    async fn test_try_system_dns_resolver_nonexistent_domain() {
        let result = try_system_dns_resolver("zzz-nonexistent.invalid").await;
        // .invalid TLD should fail DNS resolution
        assert!(result.is_err(), "Nonexistent domain should fail DNS resolution");
    }

    #[tokio::test]
    // coverage(off): network-dependent — result varies by DNS availability
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn test_try_system_dns_resolver_no_txt_records() {
        let result = try_system_dns_resolver("zzz-no-txt-records-test.com").await;
        match result {
            Ok(records) => {
                let _ = records;
            }
            Err(_) => {}
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Coverage gap tests — exercise untested production code paths
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_spf_logger_invalid_domain() {
        let logger = TestLogger::new();
        let record = "v=spf1 include:a ~all";
        let result = extract_from_spf_record(record, Some(&logger), "example.com", record);
        assert!(result.is_none());
        let failures = logger.failures.lock().unwrap();
        assert!(!failures.is_empty(), "Logger should capture invalid SPF domain 'a'");
        assert!(failures[0].contains("Invalid domain format"));
    }

    #[test]
    fn test_collect_spf_targets_include() {
        let mut to_resolve = Vec::new();
        let mut visited = std::collections::HashSet::new();
        collect_spf_targets(
            "v=spf1 include:_spf.google.com redirect=_spf.example.com ~all",
            &mut to_resolve,
            &mut visited,
        );
        assert!(!to_resolve.is_empty(), "Should collect SPF include/redirect targets");
        assert!(to_resolve.iter().any(|d| d.contains("google.com")));
        assert!(to_resolve.iter().any(|d| d.contains("example.com")));
    }

    #[test]
    fn test_dkim_record_with_domain_value() {
        let record = "v=DKIM1; k=rsa; h=mail.sendgrid.net; s=selector; p=MIGfMA0";
        let result = extract_from_dkim_record(record, None, "example.com", record);
        assert!(result.is_some(), "DKIM h= with a domain-like value should extract");
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain.contains("sendgrid")));
    }

    #[test]
    fn test_dmarc_logger_invalid_domain() {
        let logger = TestLogger::new();
        let record = "v=DMARC1; rua=mailto:report@x";
        let result = extract_from_dmarc_record(record, Some(&logger), "example.com", record);
        assert!(result.is_none());
        let failures = logger.failures.lock().unwrap();
        assert!(!failures.is_empty(), "Logger should capture invalid DMARC domain 'x'");
        assert!(failures[0].contains("DMARC"));
    }

    #[test]
    fn test_verification_record_prefix_pattern() {
        let record = "verification-google=abc123";
        let result = extract_from_verification_record(record, None, "example.com", record);
        assert!(result.is_some(), "verification-google= should infer google.com");
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "google.com"));
    }

    #[test]
    fn test_verification_record_site_pattern() {
        let record = "hubspot-site-verification=def456";
        let result = extract_from_verification_record(record, None, "example.com", record);
        assert!(result.is_some(), "hubspot-site-verification= should infer hubspot.com");
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "hubspot.com"));
    }

    #[test]
    fn test_verification_record_provider_verify_pattern() {
        let record = "ZOOM_verify_xyz789";
        let result = extract_from_verification_record(record, None, "example.com", record);
        assert!(result.is_some(), "ZOOM_verify_ should infer zoom.us");
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "zoom.us"));
    }

    #[test]
    fn test_verification_record_domain_equals_pattern() {
        let record = "atlassian-domain-verification=abc";
        let result = extract_from_verification_record(record, None, "example.com", record);
        assert!(result.is_some(), "atlassian-domain-verification should infer atlassian.com");
    }
}
