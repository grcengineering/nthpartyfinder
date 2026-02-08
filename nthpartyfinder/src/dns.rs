use hickory_resolver::{TokioAsyncResolver, config::*};
use hickory_resolver::config::LookupIpStrategy;
use regex::Regex;
use once_cell::sync::Lazy;
use anyhow::Result;
use tracing::{debug, warn, info};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use reqwest;
use serde_json::Value;
use crate::vendor::RecordType;
use crate::domain_utils;
use crate::config::AppConfig;
use crate::rate_limit::RateLimitContext;

// Compile regex patterns once at startup for performance (fixes B020)
static MACRO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"%\{[a-zA-Z]+[0-9]*[a-zA-Z]*\}\.?").unwrap()
});

static DOMAIN_VERIFICATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([a-zA-Z0-9]+)(?:-domain)?-verification=").unwrap()
});

static VERIFICATION_PREFIX_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"verification-([a-zA-Z0-9]+)=").unwrap()
});

static SITE_VERIFICATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([a-zA-Z0-9]+)-site-verification=").unwrap()
});

static PROVIDER_VERIFY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([A-Z0-9]+)_verify_").unwrap()
});

// M016: Underscores are intentionally allowed at the start of labels to support
// SPF/DMARC/DKIM underscore-prefixed subdomains (e.g., _spf.google.com, _dmarc.domain.com,
// _domainkey.domain.com). This is correct per RFC 7208 and RFC 6376.
static DOMAIN_VALIDATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,62}(\.[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,62})*$").unwrap()
});

// DMARC mailto: extraction regex (fixes B020)
static MAILTO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"mailto:([^@,\s]+@)?([^,;\s]+)").unwrap()
});

// SP_TAG_REGEX removed - sp= contains policy values, not domains (C001 fix)

// Pre-compiled SPF mechanism regexes to avoid recompilation in loops (H001 fix)
static SPF_INCLUDE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"include:\s*([^\s]+)").unwrap()
});
static SPF_REDIRECT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"redirect=\s*([^\s]+)").unwrap()
});
static SPF_A_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"a:\s*([^\s]+)").unwrap()
});
static SPF_MX_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"mx:\s*([^\s]+)").unwrap()
});
static SPF_EXISTS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"exists:\s*([^\s]+)").unwrap()
});
// M003: ptr: mechanism contains a domain (unlike ip4:/ip6: which contain IP addresses)
static SPF_PTR_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"ptr:\s*([^\s]+)").unwrap()
});

// Pre-compiled DKIM pattern regexes (H002 fix)
static DKIM_P_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"p=([A-Za-z0-9+/=]+)").unwrap()
});
static DKIM_H_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"h=([^;]+)").unwrap()
});
static DKIM_S_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"s=([^;]+)").unwrap()
});

pub trait LogFailure {
    fn log_failure(&self, source_domain: &str, record_type: &str, raw_record: &str, extracted_service: Option<&str>, failure_reason: &str);
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
        let doh_servers: Vec<DohServerConfig> = config.dns.doh_servers.iter()
            .map(|s| DohServerConfig {
                url: s.url.clone(),
                name: s.name.clone(),
                timeout_secs: s.timeout_secs,
            })
            .collect();

        let dns_servers: Vec<DnsServerConfig> = config.dns.dns_servers.iter()
            .map(|s| DnsServerConfig {
                address: s.address.clone(),
                name: s.name.clone(),
                timeout_secs: s.timeout_secs,
            })
            .collect();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.http.request_timeout_secs))
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
            DohServerConfig { url: "https://cloudflare-dns.com/dns-query".to_string(), name: "Cloudflare DoH".to_string(), timeout_secs: 3 },
            DohServerConfig { url: "https://dns.google/dns-query".to_string(), name: "Google DoH".to_string(), timeout_secs: 3 },
            DohServerConfig { url: "https://dns.quad9.net/dns-query".to_string(), name: "Quad9 DoH".to_string(), timeout_secs: 4 },
            DohServerConfig { url: "https://doh.opendns.com/dns-query".to_string(), name: "OpenDNS DoH".to_string(), timeout_secs: 4 },
        ];

        let dns_servers = vec![
            DnsServerConfig { address: "1.1.1.1:53".to_string(), name: "Cloudflare".to_string(), timeout_secs: 2 },
            DnsServerConfig { address: "8.8.8.8:53".to_string(), name: "Google".to_string(), timeout_secs: 2 },
            DnsServerConfig { address: "9.9.9.9:53".to_string(), name: "Quad9".to_string(), timeout_secs: 3 },
            DnsServerConfig { address: "208.67.222.222:53".to_string(), name: "OpenDNS".to_string(), timeout_secs: 3 },
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
        let dns_servers = vec![
            DnsServerConfig {
                address: "127.0.0.1:53".to_string(),
                name: "Test DNS Fallback".to_string(),
                timeout_secs: 2,
            },
        ];

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
    
    /// Perform DNS over HTTPS lookup for TXT records
    async fn doh_txt_lookup(&self, domain: &str, server: &DohServerConfig) -> Result<Vec<String>> {
        debug!("DoH lookup for {} using {}", domain, server.name);
        
        // Create DNS query in wire format
        let query_params = [
            ("name", domain),
            ("type", "TXT"),
        ];
        
        let response = self.client
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
                if answer["type"].as_u64() == Some(16) { // TXT record type
                    if let Some(data) = answer["data"].as_str() {
                        // Remove quotes and handle escaped characters
                        let cleaned = unescape_dns_txt(data.trim_matches('"'));
                        records.push(cleaned);
                    }
                }
            }
        }
        
        debug!("DoH found {} TXT records for {} via {}", records.len(), domain, server.name);
        Ok(records)
    }

    /// Perform DNS over HTTPS lookup for CNAME records
    async fn doh_cname_lookup(&self, domain: &str, server: &DohServerConfig) -> Result<Vec<String>> {
        debug!("DoH CNAME lookup for {} using {}", domain, server.name);

        let query_params = [
            ("name", domain),
            ("type", "CNAME"),
        ];

        let response = self.client
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
                if answer["type"].as_u64() == Some(5) { // CNAME record type
                    if let Some(data) = answer["data"].as_str() {
                        // Remove trailing dot from CNAME targets
                        let cleaned = data.trim_end_matches('.').to_string();
                        records.push(cleaned);
                    }
                }
            }
        }

        debug!("DoH found {} CNAME records for {} via {}", records.len(), domain, server.name);
        Ok(records)
    }

    /// Create a traditional DNS resolver for the given server config (C002 fix: returns Result)
    fn create_dns_resolver(&self, server: &DnsServerConfig, use_tcp: bool) -> Result<TokioAsyncResolver> {
        let mut config = ResolverConfig::new();

        let socket_addr = server.address.parse()
            .map_err(|e| anyhow::anyhow!("Invalid DNS server address '{}' for server '{}': {}",
                server.address, server.name, e))?;

        config.add_name_server(NameServerConfig {
            socket_addr,
            protocol: if use_tcp { Protocol::Tcp } else { Protocol::Udp },
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
            tls_config: None,
        });

        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(server.timeout_secs);
        opts.attempts = 1; // Single attempt for speed
        opts.edns0 = true;
        opts.use_hosts_file = false;
        opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6; // Prefer IPv4 for speed
        opts.validate = false;
        opts.num_concurrent_reqs = 4; // Increased concurrency
        opts.rotate = true; // Enable rotation for better load distribution

        Ok(TokioAsyncResolver::tokio(config, opts))
    }
}

pub async fn get_txt_records(domain: &str) -> Result<Vec<String>> {
    get_txt_records_with_pool(domain, &DnsServerPool::new()).await
}

pub async fn get_txt_records_with_pool(domain: &str, dns_pool: &DnsServerPool) -> Result<Vec<String>> {
    get_txt_records_with_rate_limit(domain, dns_pool, None).await
}

/// Get TXT records with optional rate limiting support
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
    
    // First, try DNS over HTTPS (primary method)
    info!("Attempting DoH lookup for {}", domain);
    for attempt in 0..2 {
        let doh_server = dns_pool.next_doh_server();
        debug!("DoH attempt {} for {}: using {}", attempt + 1, domain, doh_server.name);
        
        match dns_pool.doh_txt_lookup(domain, doh_server).await {
            Ok(records) if !records.is_empty() => {
                info!("DoH successful: Found {} TXT records for {} via {}", records.len(), domain, doh_server.name);
                return Ok(records);
            },
            Ok(_) => {
                debug!("DoH returned empty results for {} via {}", domain, doh_server.name);
            },
            Err(e) => {
                debug!("DoH lookup failed for {} via {}: {}", domain, doh_server.name, e);
            }
        }
    }
    
    // Fallback to traditional DNS queries
    info!("DoH failed, falling back to traditional DNS for {}", domain);
    for attempt in 0..2 {
        let dns_server = dns_pool.next_dns_server();
        debug!("DNS attempt {} for {}: using {}", attempt + 1, domain, dns_server.name);
        
        // Try UDP first (faster) - handle resolver creation failure gracefully (C002 fix)
        let resolver = match dns_pool.create_dns_resolver(dns_server, false) {
            Ok(r) => r,
            Err(e) => {
                debug!("Failed to create UDP resolver for {}: {}", dns_server.name, e);
                continue;
            }
        };
        match resolver.txt_lookup(domain).await {
            Ok(txt_lookup) => {
                let records: Vec<String> = txt_lookup
                    .iter()
                    .map(|record| record.to_string())
                    .collect();

                debug!("Found {} TXT records for {} via {} (UDP)", records.len(), domain, dns_server.name);
                return Ok(records);
            },
            Err(e) => {
                debug!("UDP lookup failed for {} via {}: {}", domain, dns_server.name, e);

                // Try TCP fallback for this server
                let tcp_resolver = match dns_pool.create_dns_resolver(dns_server, true) {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("Failed to create TCP resolver for {}: {}", dns_server.name, e);
                        continue;
                    }
                };
                match tcp_resolver.txt_lookup(domain).await {
                    Ok(txt_lookup) => {
                        let records: Vec<String> = txt_lookup
                            .iter()
                            .map(|record| record.to_string())
                            .collect();

                        debug!("Found {} TXT records for {} via {} (TCP)", records.len(), domain, dns_server.name);
                        return Ok(records);
                    },
                    Err(tcp_e) => {
                        debug!("TCP lookup also failed for {} via {}: {}", domain, dns_server.name, tcp_e);
                    }
                }
            }
        }
    }
    
    // Final fallback: try system resolver
    debug!("All custom DNS failed for {}, trying system resolver", domain);
    match try_system_dns_resolver(domain).await {
        Ok(records) => {
            debug!("Found {} TXT records for {} via system resolver", records.len(), domain);
            Ok(records)
        },
        Err(e) => {
            // M001: Distinguish "all DNS resolution failed" from "no records found" (which
            // returns Ok(vec![]) via a successful lookup with zero results above).
            warn!("All DNS resolution failed for {} (DoH, UDP, TCP, system resolver all errored) — returning empty results to continue analysis. Last error: {}", domain, e);
            Ok(vec![]) // Return empty instead of error to continue analysis
        }
    }
}

async fn try_system_dns_resolver(domain: &str) -> Result<Vec<String>> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;

    let txt_lookup = resolver.txt_lookup(domain).await?;
    let records: Vec<String> = txt_lookup
        .iter()
        .map(|record| record.to_string())
        .collect();

    Ok(records)
}

/// Get CNAME records for a domain using the DNS pool
pub async fn get_cname_records_with_pool(domain: &str, dns_pool: &DnsServerPool) -> Result<Vec<String>> {
    get_cname_records_with_rate_limit(domain, dns_pool, None).await
}

/// Get CNAME records with optional rate limiting support
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

    // Try DNS over HTTPS first
    for attempt in 0..2 {
        let doh_server = dns_pool.next_doh_server();
        debug!("DoH CNAME attempt {} for {}: using {}", attempt + 1, domain, doh_server.name);

        match dns_pool.doh_cname_lookup(domain, doh_server).await {
            Ok(records) if !records.is_empty() => {
                debug!("DoH successful: Found {} CNAME records for {} via {}", records.len(), domain, doh_server.name);
                return Ok(records);
            },
            Ok(_) => {
                debug!("DoH returned empty CNAME results for {} via {}", domain, doh_server.name);
            },
            Err(e) => {
                debug!("DoH CNAME lookup failed for {} via {}: {}", domain, doh_server.name, e);
            }
        }
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

pub fn extract_vendor_domains_with_source_and_logger(txt_records: &[String], logger: Option<&dyn LogFailure>, source_domain: &str) -> Vec<VendorDomain> {
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
        if let Some(domains) = extract_from_spf_record(&record_clean, logger, source_domain, &record) {
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

        if let Some(domains) = extract_from_dkim_record(&record_clean, logger, source_domain, &record) {
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

        if let Some(domains) = extract_from_dmarc_record(&record_clean, logger, source_domain, &record) {
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

        if let Some(domains) = extract_from_verification_record(&record_clean, logger, source_domain, &record) {
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
                    logger.log_failure(source_domain, "UNMATCHED_TXT", &record, None, "No pattern matched this TXT record");
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

fn extract_from_spf_record(record: &str, logger: Option<&dyn LogFailure>, source_domain: &str, raw_record: &str) -> Option<Vec<VendorDomain>> {
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
        &SPF_INCLUDE_REGEX, &SPF_REDIRECT_REGEX, &SPF_A_REGEX, &SPF_MX_REGEX, &SPF_EXISTS_REGEX,
        &SPF_PTR_REGEX,
    ];

    for re in spf_regexes {
        for cap in re.captures_iter(&record_lower) {
            if let Some(domain_match) = cap.get(1) {
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
                    logger.log_failure(source_domain, "SPF", raw_record, Some(raw_domain), "Invalid domain format");
                }
            }
        }
    }

    if domains.is_empty() { None } else { Some(domains) }
}

fn extract_from_dkim_record(record: &str, _logger: Option<&dyn LogFailure>, _source_domain: &str, raw_record: &str) -> Option<Vec<VendorDomain>> {
    if !record.contains("k=rsa") && !record.contains("k=ed25519") {
        return None;
    }

    let mut domains = Vec::new();

    // Use pre-compiled DKIM regexes instead of compiling in loop (H002 fix)
    let dkim_regexes: &[&Lazy<Regex>] = &[&DKIM_P_REGEX, &DKIM_H_REGEX, &DKIM_S_REGEX];

    for re in dkim_regexes {
        for cap in re.captures_iter(record) {
            if let Some(value_match) = cap.get(1) {
                let value = value_match.as_str();
                // DKIM records usually don't contain direct domain references
                // This is a simplified extraction that may need refinement
                if value.contains('.') && is_valid_domain(value) {
                    domains.push(VendorDomain {
                        domain: value.to_string(),
                        source_type: RecordType::DnsTxtDkim,
                        raw_record: raw_record.to_string(),
                    });
                }
            }
        }
    }

    if domains.is_empty() { None } else { Some(domains) }
}

fn extract_from_dmarc_record(record: &str, logger: Option<&dyn LogFailure>, source_domain: &str, raw_record: &str) -> Option<Vec<VendorDomain>> {
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
            let value_end = record_lower[value_start..].find(';')
                .map(|p| value_start + p)
                .unwrap_or(record_lower.len());
            let tag_value = &record_lower[value_start..value_end];

            // Extract all mailto: addresses (comma-separated)
            // Pattern: mailto:localpart@domain or mailto:domain
            for cap in MAILTO_REGEX.captures_iter(tag_value) {
                if let Some(domain_match) = cap.get(2) {
                    let domain = domain_match.as_str();
                    if is_valid_domain(domain) {
                        domains.push(VendorDomain {
                            domain: domain.to_string(),
                            source_type: RecordType::DnsTxtDmarc,
                            raw_record: raw_record.to_string(),
                        });
                    } else if let Some(logger) = logger {
                        logger.log_failure(source_domain, "DMARC", raw_record, Some(tag), "Invalid domain format");
                    }
                }
            }
        }
    }

    // Note: sp= tag contains policy values ("none", "quarantine", "reject"), not domains.
    // Removed dead code that attempted to extract domains from sp= (C001 fix).

    if domains.is_empty() { None } else { Some(domains) }
}

fn extract_from_verification_record(record: &str, logger: Option<&dyn LogFailure>, source_domain: &str, raw_record: &str) -> Option<Vec<VendorDomain>> {
    let mut domains = Vec::new();

    // First, try comprehensive static provider mappings
    if let Some(static_domains) = try_static_verification_patterns(record, logger, source_domain, raw_record) {
        domains.extend(static_domains);
    }

    // Then try dynamic pattern matching for unknown verification records
    if let Some(dynamic_domains) = try_dynamic_verification_patterns(record, logger, source_domain, raw_record) {
        domains.extend(dynamic_domains);
    }

    if domains.is_empty() { None } else { Some(domains) }
}

fn try_static_verification_patterns(record: &str, _logger: Option<&dyn LogFailure>, _source_domain: &str, raw_record: &str) -> Option<Vec<VendorDomain>> {
    // Comprehensive static provider mappings based on research
    let verification_patterns = vec![
        // Common verification patterns
        (r"google-site-verification=", "google.com", RecordType::DnsTxtVerification),
        (r"facebook-domain-verification=", "facebook.com", RecordType::DnsTxtVerification),
        (r"MS=", "microsoft.com", RecordType::DnsTxtVerification),
        (r"apple-domain-verification=", "apple.com", RecordType::DnsTxtVerification),
        (r"adobe-idp-site-verification=", "adobe.com", RecordType::DnsTxtVerification),
        (r"stripe-verification=", "stripe.com", RecordType::DnsTxtVerification),
        (r"docusign=", "docusign.com", RecordType::DnsTxtVerification),
        (r"globalsign-domain-verification=", "globalsign.com", RecordType::DnsTxtVerification),
        (r"dropbox-domain-verification=", "dropbox.com", RecordType::DnsTxtVerification),
        
        // Extended patterns from research and klaviyo analysis
        (r"ZOOM_verify_", "zoom.us", RecordType::DnsTxtVerification),
        (r"atlassian-domain-verification=", "atlassian.com", RecordType::DnsTxtVerification),
        (r"browserstack-domain-verification=", "browserstack.com", RecordType::DnsTxtVerification),
        (r"canva-site-verification=", "canva.com", RecordType::DnsTxtVerification),
        (r"cursor-domain-verification", "cursor.com", RecordType::DnsTxtVerification),
        (r"datadome-domain-verify=", "datadome.co", RecordType::DnsTxtVerification),
        (r"drift-domain-verification=", "drift.com", RecordType::DnsTxtVerification),
        (r"hubspot-domain-verification=", "hubspot.com", RecordType::DnsTxtVerification),
        (r"klaviyo-site-verification=", "klaviyo.com", RecordType::DnsTxtVerification),
        (r"notion-domain-verification=", "notion.so", RecordType::DnsTxtVerification),
        (r"onetrust-domain-verification=", "onetrust.com", RecordType::DnsTxtVerification),
        (r"openai-domain-verification=", "openai.com", RecordType::DnsTxtVerification),
        (r"postman-domain-verification=", "postman.com", RecordType::DnsTxtVerification),
        (r"slack-domain-verification=", "slack.com", RecordType::DnsTxtVerification),
        (r"teamviewer-sso-verification=", "teamviewer.com", RecordType::DnsTxtVerification),
        (r"wework-site-verification=", "wework.com", RecordType::DnsTxtVerification),
        (r"heroku-domain-verification=", "heroku.com", RecordType::DnsTxtVerification),
        (r"jamf-site-verification=", "jamf.com", RecordType::DnsTxtVerification),

        // Additional patterns found in klaviyo.com analysis
        (r"anthropic-domain-verification", "anthropic.com", RecordType::DnsTxtVerification),
        (r"jetbrains-domain-verification=", "jetbrains.com", RecordType::DnsTxtVerification),
        (r"gc-ai-domain-verification", "gc-ai.com", RecordType::DnsTxtVerification), // Unverified vendor - kept for completeness

        // Special mappings discovered from research
        (r"intacct-esk=", "sage.com", RecordType::DnsTxtVerification), // Sage Intacct
        (r"mgverify=", "mailgun.com", RecordType::DnsTxtVerification), // Mailgun verification
        // L002: neat.co is correct — Neat's actual domain is neat.co (not .com)
        (r"neat-pulse-domain-verification", "neat.co", RecordType::DnsTxtVerification),
        
        // Pattern variations
        (r"webex-domain-verification=", "webex.com", RecordType::DnsTxtVerification),
        (r"zoom-domain-verification=", "zoom.us", RecordType::DnsTxtVerification),
        (r"have-i-been-pwned-verification=", "haveibeenpwned.com", RecordType::DnsTxtVerification),
        
        // L001: Whimsical uses angle bracket format in TXT records — this is an actual
        // record format observed in the wild (e.g., klaviyo.com DNS), not a parsing error.
        (r"<whimsical=", "whimsical.com", RecordType::DnsTxtVerification),
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

    if domains.is_empty() { None } else { Some(domains) }
}

fn try_dynamic_verification_patterns(record: &str, _logger: Option<&dyn LogFailure>, _source_domain: &str, raw_record: &str) -> Option<Vec<VendorDomain>> {
    let mut domains = Vec::new();

    // Dynamic pattern 1: "*-verification=" or "*-domain-verification="
    // Use pre-compiled regex for performance (B020 fix)
    for cap in DOMAIN_VERIFICATION_REGEX.captures_iter(record) {
        if let Some(provider_match) = cap.get(1) {
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

    // Dynamic pattern 2: "verification-*="
    // Use pre-compiled regex for performance (B020 fix)
    for cap in VERIFICATION_PREFIX_REGEX.captures_iter(record) {
        if let Some(provider_match) = cap.get(1) {
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

    // Dynamic pattern 3: "*-site-verification="
    // Use pre-compiled regex for performance (B020 fix)
    for cap in SITE_VERIFICATION_REGEX.captures_iter(record) {
        if let Some(provider_match) = cap.get(1) {
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

    // Dynamic pattern 4: "PROVIDER_verify_" (like ZOOM_verify_)
    // Use pre-compiled regex for performance (B020 fix)
    for cap in PROVIDER_VERIFY_REGEX.captures_iter(record) {
        if let Some(provider_match) = cap.get(1) {
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

    if domains.is_empty() { None } else { Some(domains) }
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
            "sendgrid" | "mailchimp" | "constantcontact" | "pardot" |
            "marketo" | "hubspot" | "intercom" | "freshdesk" | "typeform" => {
                Some(format!("{}.com", provider_name))
            },
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
    DOMAIN_VALIDATION_REGEX.is_match(domain) && domain.contains('.') && domain.len() <= 253 && domain.len() >= 4
}