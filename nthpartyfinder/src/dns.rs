use crate::config::AppConfig;
use crate::domain_utils;
// All send_gated() sites in this file live in #[cfg(not(coverage))] DoH paths,
// so the trait import is only referenced outside the coverage build.
#[cfg(not(coverage))]
use crate::http_client::GatedSend;
use crate::rate_limit::{RateLimitContext, SharedRateLimiter};
use crate::vendor::RecordType;
use anyhow::Result;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use once_cell::sync::Lazy;
use regex::Regex;
#[cfg(not(coverage))]
use serde_json::Value;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(not(coverage))]
use tracing::{debug, info, warn};

// Compile regex patterns once at startup for performance (fixes B020)
static MACRO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"%\{[a-zA-Z]+[0-9]*[a-zA-Z]*\}\.?")
        .expect("MACRO_REGEX is a valid compile-time regex literal")
});

static DOMAIN_VERIFICATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([a-zA-Z0-9]+)(?:-domain)?-verification=")
        .expect("DOMAIN_VERIFICATION_REGEX is a valid compile-time regex literal")
});

static VERIFICATION_PREFIX_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"verification-([a-zA-Z0-9]+)=")
        .expect("VERIFICATION_PREFIX_REGEX is a valid compile-time regex literal")
});

static SITE_VERIFICATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([a-zA-Z0-9]+)-site-verification=")
        .expect("SITE_VERIFICATION_REGEX is a valid compile-time regex literal")
});

static PROVIDER_VERIFY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([A-Z0-9]+)_verify_")
        .expect("PROVIDER_VERIFY_REGEX is a valid compile-time regex literal")
});

// M016: Underscores are intentionally allowed at the start of labels to support
// SPF/DMARC/DKIM underscore-prefixed subdomains (e.g., _spf.google.com, _dmarc.domain.com,
// _domainkey.domain.com). This is correct per RFC 7208 and RFC 6376.
static DOMAIN_VALIDATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,62}(\.[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,62})*$")
        .expect("DOMAIN_VALIDATION_REGEX is a valid compile-time regex literal")
});

// DMARC mailto: extraction regex (fixes B020)
static MAILTO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"mailto:([^@,\s]+@)?([^,;\s]+)")
        .expect("MAILTO_REGEX is a valid compile-time regex literal")
});

// SP_TAG_REGEX removed - sp= contains policy values, not domains (C001 fix)

// Pre-compiled SPF mechanism regexes to avoid recompilation in loops (H001 fix)
static SPF_INCLUDE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"include:\s*([^\s]+)")
        .expect("SPF_INCLUDE_REGEX is a valid compile-time regex literal")
});
static SPF_REDIRECT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"redirect=\s*([^\s]+)")
        .expect("SPF_REDIRECT_REGEX is a valid compile-time regex literal")
});
static SPF_A_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"a:\s*([^\s]+)").expect("SPF_A_REGEX is a valid compile-time regex literal")
});
static SPF_MX_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"mx:\s*([^\s]+)").expect("SPF_MX_REGEX is a valid compile-time regex literal")
});
static SPF_EXISTS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"exists:\s*([^\s]+)")
        .expect("SPF_EXISTS_REGEX is a valid compile-time regex literal")
});
// M003: ptr: mechanism contains a domain (unlike ip4:/ip6: which contain IP addresses)
static SPF_PTR_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"ptr:\s*([^\s]+)").expect("SPF_PTR_REGEX is a valid compile-time regex literal")
});

// Pre-compiled DKIM pattern regexes (H002 fix)
static DKIM_P_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"p=([A-Za-z0-9+/=]+)").expect("DKIM_P_REGEX is a valid compile-time regex literal")
});
static DKIM_H_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"h=([^;]+)").expect("DKIM_H_REGEX is a valid compile-time regex literal")
});
static DKIM_S_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"s=([^;]+)").expect("DKIM_S_REGEX is a valid compile-time regex literal")
});

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
    /// Per-process DNS rate limiter (GRC-367): acquired before every outbound DoH/DNS
    /// request so the configured `dns_queries_per_second` is actually enforced. Previously
    /// the limiter was dead code (callers always passed `None`), letting sustained
    /// concurrency trip DoH-provider 429s that were then mis-read as empty answers.
    dns_limiter: SharedRateLimiter,
    /// Max DoH provider rotations on a throttle (429/5xx) before giving up.
    max_dns_retries: u32,
    /// Base backoff (ms) between throttled DoH retries.
    backoff_base_ms: u64,
    /// GRC-367 (fix 1): the SINGLE choke-point throttle counter. When wired up via
    /// `with_failure_counter` (production: to `logger.dns_failure_counter_arc()`), every DoH
    /// throttle on EVERY path — TXT root, subdomain fast, CNAME, and the SPF include-chain
    /// recursion (`resolve_spf_includes_recursive` → `get_txt_records_with_pool` →
    /// `doh_txt_lookup`) — increments the same atomic the exit-3 guard reads. `None` in tests
    /// that don't opt in. This is the authoritative source of truth for throttle visibility;
    /// the older per-path increments are a harmless redundant signal (the guard is `> 0`).
    failure_counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    /// Per-provider failure-log counts backing `log_doh_failure`'s warn-once-then-debug
    /// behavior. Mutex (not atomics) because failures are rare and the critical section
    /// is a HashMap bump with no await inside.
    #[cfg(not(coverage))]
    doh_failure_log: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    /// Scan-lifetime memo of DNS answers, keyed by `(record kind, domain)`.
    ///
    /// The same names are looked up many times in one scan: SPF include chains converge on
    /// a handful of shared targets (`_spf.google.com`, `sendgrid.net`, …), and a vendor seen
    /// at one depth is commonly re-analyzed as a customer at the next. Each repeat used to
    /// re-issue the query, spend a rate-limit token, and wait a full round trip.
    ///
    /// **Only authoritative answers are stored** — see `remember_answer`. A record set that
    /// came back from a real resolver (including a genuinely empty one) is a fact about the
    /// zone and is safe to reuse for the seconds-to-minutes a scan lasts. An empty vector
    /// produced because every resolver failed is NOT such a fact: caching it would silently
    /// convert one transient outage into a scan-wide false negative and would bypass the
    /// `note_throttle` counting that the exit-3 guard depends on (GRC-367).
    #[cfg(not(coverage))]
    answer_memo: tokio::sync::Mutex<std::collections::HashMap<(RecordKind, String), Vec<String>>>,
}

/// Record kinds the answer memo distinguishes. Keying on the name alone would let a TXT
/// answer satisfy a CNAME query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(coverage, allow(dead_code))]
pub(crate) enum RecordKind {
    Txt,
    Cname,
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

        let client = crate::http_client::hardened_builder()
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
            dns_limiter: SharedRateLimiter::new(config.rate_limits.dns_queries_per_second),
            max_dns_retries: config.rate_limits.max_retries,
            backoff_base_ms: config.rate_limits.backoff_base_delay_ms,
            failure_counter: None,
            #[cfg(not(coverage))]
            doh_failure_log: std::sync::Mutex::new(std::collections::HashMap::new()),
            #[cfg(not(coverage))]
            answer_memo: tokio::sync::Mutex::new(std::collections::HashMap::new()),
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
            // Google's JSON DoH API is at /resolve, NOT /dns-query (the latter is
            // RFC-8484 wire-format and 400s for application/dns-json).
            DohServerConfig {
                url: "https://dns.google/resolve".to_string(),
                name: "Google DoH".to_string(),
                timeout_secs: 3,
            },
            // IP-literal endpoints avoid a DNS-bootstrap dependency when UDP/53 is
            // blocked. Quad9 + OpenDNS were dropped: their DoH does not serve the
            // JSON GET API, so they returned 0 records and caused false negatives.
            DohServerConfig {
                url: "https://1.1.1.1/dns-query".to_string(),
                name: "Cloudflare DoH (IP)".to_string(),
                timeout_secs: 3,
            },
            DohServerConfig {
                url: "https://8.8.8.8/resolve".to_string(),
                name: "Google DoH (IP)".to_string(),
                timeout_secs: 3,
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

        let client = crate::http_client::hardened_builder()
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
            dns_limiter: SharedRateLimiter::new(50), // matches config default_dns_queries_per_second
            max_dns_retries: 3,
            backoff_base_ms: 500,
            failure_counter: None,
            #[cfg(not(coverage))]
            doh_failure_log: std::sync::Mutex::new(std::collections::HashMap::new()),
            #[cfg(not(coverage))]
            answer_memo: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// GRC-367 (fix 1): wire the pool's choke-point throttle counter to a shared atomic
    /// (production: `logger.dns_failure_counter_arc()`). After this, `note_throttle()` — called
    /// inside `doh_txt_lookup`/`doh_cname_lookup` on a 429/5xx — increments this atomic on every
    /// DoH path, including the previously-untracked SPF include-chain recursion. Builder-style so
    /// the production construction sites stay one expression: `from_config(&cfg).with_failure_counter(..)`.
    pub fn with_failure_counter(
        mut self,
        c: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.failure_counter = Some(c);
        self
    }

    /// GRC-367 (fix 1): the choke-point increment. A no-op until `with_failure_counter` has been
    /// called, so tests that don't opt in are unaffected. Called from both DoH lookups the instant
    /// a throttle (429/5xx) is detected — making throttle visibility path-independent.
    fn note_throttle(&self) {
        if let Some(c) = &self.failure_counter {
            c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Per-provider failure visibility: the FIRST failure from a given provider warns
    /// (actionable signal — a configured provider is misconfigured, down, or speaking the
    /// wrong API); repeats from the same provider log at debug so a long scan against a
    /// dead provider doesn't drown the output in duplicate warnings.
    // cfg(not(coverage)): only the live resilient lookups call this — gated identically
    // to them so it is not dead code under the coverage profile.
    #[cfg(not(coverage))]
    fn log_doh_failure(&self, server_name: &str, err: &str) {
        let mut counts = match self.doh_failure_log.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let n = counts.entry(server_name.to_string()).or_insert(0);
        *n += 1;
        if *n == 1 {
            warn!(
                "DoH provider '{}' failed: {} (subsequent failures from this provider log at debug)",
                server_name, err
            );
        } else {
            debug!("DoH provider '{}' failure #{}: {}", server_name, *n, err);
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
            dns_limiter: SharedRateLimiter::new(1000), // effectively unthrottled for tests
            max_dns_retries: 3,
            backoff_base_ms: 1, // fast backoff so rotation tests run quickly
            failure_counter: None,
            #[cfg(not(coverage))]
            doh_failure_log: std::sync::Mutex::new(std::collections::HashMap::new()),
            #[cfg(not(coverage))]
            answer_memo: tokio::sync::Mutex::new(std::collections::HashMap::new()),
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

    /// Empty-pool-safe rotation. `next_doh_server`/`next_dns_server` index with
    /// `% len`, which panics on an empty list — and a config with only one of
    /// the two server kinds is legal (validation requires "at least one DoH OR
    /// DNS server"). Production lookup paths must rotate through these instead.
    #[cfg(not(coverage))]
    fn next_doh_server_opt(&self) -> Option<&DohServerConfig> {
        if self.doh_servers.is_empty() {
            None
        } else {
            Some(self.next_doh_server())
        }
    }

    #[cfg(not(coverage))]
    fn next_dns_server_opt(&self) -> Option<&DnsServerConfig> {
        if self.dns_servers.is_empty() {
            None
        } else {
            Some(self.next_dns_server())
        }
    }

    // cfg(not(coverage)): performs live HTTPS request to DoH provider — requires network
    #[cfg(not(coverage))]
    async fn doh_txt_lookup(&self, domain: &str, server: &DohServerConfig) -> Result<Vec<String>> {
        debug!("DoH lookup for {} using {}", domain, server.name);

        // Create DNS query in wire format
        let query_params = [("name", domain), ("type", "TXT")];

        let http_response = self
            .client
            .get(&server.url)
            .query(&query_params)
            .header("Accept", "application/dns-json")
            .timeout(std::time::Duration::from_secs(server.timeout_secs))
            .send_gated()
            .await?;
        // GRC-367: a throttle (429) or provider 5xx MUST surface as a distinct error —
        // never be parsed into an empty answer, which the caller would otherwise mistake
        // for "this domain has no records" and report as a false-negative 0-vendor result.
        let status = http_response.status();
        if status.as_u16() == 429 || status.is_server_error() {
            // GRC-367 (fix 1): count the throttle at the choke-point BEFORE returning, so every
            // path that reaches a DoH TXT lookup (incl. SPF include recursion) is tracked once
            // and for all against the exit-3 counter.
            self.note_throttle();
            return Err(anyhow::anyhow!(
                "DNS_THROTTLE: DoH provider {} returned HTTP {} for {}",
                server.name,
                status,
                domain
            ));
        }
        // Any other non-2xx (400/403/404…) means the endpoint cannot serve this query at
        // all — wrong API path, wrong protocol, misconfiguration. Never parse it into an
        // empty answer: that is the exact silent-false-negative class of the
        // /dns-query-vs-/resolve incident (3 of 4 default providers returned HTTP 400 and
        // were read as "0 TXT records"). Count it for the exit-3 guard and surface a
        // distinct DNS_ENDPOINT class so the resilient loop rotates WITHOUT backoff.
        if !status.is_success() {
            self.note_throttle();
            return Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider {} returned HTTP {} for {} — endpoint does not serve the JSON DoH API or rejected the query",
                server.name,
                status,
                domain
            ));
        }
        let response = http_response.json::<Value>().await?;
        // dns-json `Status` is the DNS RCODE: 0 = NOERROR and 3 = NXDOMAIN are genuine
        // answers (records present / genuinely absent). Anything else (2 = SERVFAIL,
        // 5 = REFUSED, …) is a resolver-side failure that must never read as "this domain
        // has no records". A missing `Status` field is tolerated (lenient providers/fixtures).
        if let Some(rcode) = response["Status"].as_u64() {
            if rcode != 0 && rcode != 3 {
                self.note_throttle();
                return Err(anyhow::anyhow!(
                    "DNS_ENDPOINT: DoH provider {} returned DNS RCODE {} for {}",
                    server.name,
                    rcode,
                    domain
                ));
            }
        } else if response["Answer"].as_array().is_none() {
            // A 2xx JSON body with NO Status and NO Answer is not a dns-json
            // answer at all (captive portal, proxy error page, middlebox `{}`)
            // — treating it as authoritative-empty would re-arm the silent
            // 0-record incident behind an HTTP 200. Only a body carrying the
            // RCODE (or actual records) earns authoritative-empty trust.
            self.note_throttle();
            return Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider {} returned a 2xx body without Status or Answer for {} — not a DNS JSON answer",
                server.name,
                domain
            ));
        }

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

    #[cfg(coverage)]
    async fn doh_txt_lookup(
        &self,
        _domain: &str,
        _server: &DohServerConfig,
    ) -> Result<Vec<String>> {
        Ok(vec![])
    }

    // cfg(not(coverage)): performs live HTTPS request to DoH provider — requires network
    #[cfg(not(coverage))]
    async fn doh_cname_lookup(
        &self,
        domain: &str,
        server: &DohServerConfig,
    ) -> Result<Vec<String>> {
        debug!("DoH CNAME lookup for {} using {}", domain, server.name);

        let query_params = [("name", domain), ("type", "CNAME")];

        let http_response = self
            .client
            .get(&server.url)
            .query(&query_params)
            .header("Accept", "application/dns-json")
            .timeout(std::time::Duration::from_secs(server.timeout_secs))
            .send_gated()
            .await?;
        // GRC-367: surface DoH throttle/5xx as a distinct error, never an empty answer.
        let status = http_response.status();
        if status.as_u16() == 429 || status.is_server_error() {
            // GRC-367 (fix 1): choke-point throttle count for the CNAME path (mirrors the TXT
            // path) — increment before returning so it is visible to the exit-3 guard.
            self.note_throttle();
            return Err(anyhow::anyhow!(
                "DNS_THROTTLE: DoH provider {} returned HTTP {} for {}",
                server.name,
                status,
                domain
            ));
        }
        // Any other non-2xx is a broken/misconfigured endpoint — surface DNS_ENDPOINT,
        // never an empty answer (mirrors the TXT path; see comment there).
        if !status.is_success() {
            self.note_throttle();
            return Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider {} returned HTTP {} for {} — endpoint does not serve the JSON DoH API or rejected the query",
                server.name,
                status,
                domain
            ));
        }
        let response = http_response.json::<Value>().await?;
        // RCODE gate mirroring the TXT path: only NOERROR (0) and NXDOMAIN (3) are genuine
        // answers; SERVFAIL/REFUSED/… must never read as "no CNAME".
        if let Some(rcode) = response["Status"].as_u64() {
            if rcode != 0 && rcode != 3 {
                self.note_throttle();
                return Err(anyhow::anyhow!(
                    "DNS_ENDPOINT: DoH provider {} returned DNS RCODE {} for {}",
                    server.name,
                    rcode,
                    domain
                ));
            }
        } else if response["Answer"].as_array().is_none() {
            // No Status and no Answer: not a dns-json answer (see TXT path).
            self.note_throttle();
            return Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider {} returned a 2xx body without Status or Answer for {} — not a DNS JSON answer",
                server.name,
                domain
            ));
        }

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

    #[cfg(coverage)]
    async fn doh_cname_lookup(
        &self,
        _domain: &str,
        _server: &DohServerConfig,
    ) -> Result<Vec<String>> {
        Ok(vec![])
    }

    /// GRC-367: number of provider attempts a resilient lookup may make (1 + retries,
    /// bounded by the number of DoH providers actually configured).
    ///
    /// GRC-367 (fix 4): only the `#[cfg(not(coverage))]` resilient lookups call this, so it
    /// is gated identically — otherwise it is a dead-code warning under the coverage profile.
    #[cfg(not(coverage))]
    fn resilient_attempts(&self) -> usize {
        ((self.max_dns_retries as usize) + 1)
            .min(self.doh_servers.len().max(1))
            .max(1)
    }

    /// GRC-367 (fix 5): in-race backoff between throttled DoH rotations.
    ///
    /// The TXT/CNAME race wraps the resilient lookup in a 3-second `tokio::time::timeout`.
    /// The original `backoff_base_ms << i` used the production base of 1000ms, so the very
    /// first 1000ms + second 2000ms sleep blew the 3s budget and only ~1 rotation could fit
    /// — defeating the whole point of rotation under throttle. Here we derive a short in-race
    /// base (the configured base, capped at 200ms); use an OVERFLOW-SAFE shift (`checked_shl`
    /// saturating to `u64::MAX`) so a provider count >= 64 can never panic/wrap; and cap each
    /// individual sleep at 500ms. With a 200ms base this yields 200ms, 400ms, 500ms(cap)…,
    /// letting 2-3 rotations comfortably complete inside the 3s race window.
    #[cfg(not(coverage))]
    fn in_race_backoff(&self, attempt_index: usize) -> std::time::Duration {
        const IN_RACE_BASE_CAP_MS: u64 = 200;
        const IN_RACE_DELAY_CAP_MS: u64 = 500;
        let base = self.backoff_base_ms.min(IN_RACE_BASE_CAP_MS);
        // Overflow-safe: shl that would overflow saturates to u64::MAX, then saturating_mul
        // keeps the multiply in-range; finally clamp to the per-sleep cap.
        let multiplier = 1u64.checked_shl(attempt_index as u32).unwrap_or(u64::MAX);
        let delay = base.saturating_mul(multiplier).min(IN_RACE_DELAY_CAP_MS);
        std::time::Duration::from_millis(delay)
    }

    /// GRC-367: DoH TXT lookup with throttle-aware retry + provider rotation.
    /// On a throttle (429/5xx) it backs off and rotates to the next DoH provider, up to
    /// `max_dns_retries` times, instead of giving up after a single provider. A non-throttle
    /// error (parse/transport) stops retrying immediately. This is what makes a 429 recover
    /// (rotate to a healthy provider) instead of collapsing into a false-negative empty result.
    #[cfg(not(coverage))]
    async fn doh_txt_lookup_resilient(&self, domain: &str) -> Result<Vec<String>> {
        let attempts = self.resilient_attempts();
        let mut last_err: Option<anyhow::Error> = None;
        for i in 0..attempts {
            // DoH-only configs are legal; so are DNS-only ones — never index an
            // empty pool (panic), surface a plain error the callers treat as a
            // non-class failure and fall back from.
            let Some(server) = self.next_doh_server_opt().cloned() else {
                return Err(anyhow::anyhow!(
                    "no DoH servers configured for TXT lookup of {}",
                    domain
                ));
            };
            match self.doh_txt_lookup(domain, &server).await {
                Ok(records) => return Ok(records),
                Err(e) => {
                    let msg = e.to_string();
                    let throttled = msg.contains("DNS_THROTTLE");
                    let endpoint_broken = msg.contains("DNS_ENDPOINT");
                    self.log_doh_failure(&server.name, &msg);
                    if !throttled && !endpoint_broken {
                        // Transport/parse failures (connect refused, TLS error,
                        // 200-with-HTML body) are provider failures too — count
                        // them for the exit-3 guard. Classed errors were already
                        // counted at the doh_*_lookup choke point.
                        self.note_throttle();
                    }
                    last_err = Some(e);
                    if i + 1 < attempts {
                        if throttled {
                            // fix 5: short, overflow-safe backoff so 2-3 rotations fit the 3s race.
                            tokio::time::sleep(self.in_race_backoff(i)).await;
                        }
                        // Rotate past ANY failing provider — broken (4xx/RCODE),
                        // unreachable (transport), or misbehaving (parse) endpoints
                        // are not busy; only a throttle earns a backoff first.
                        continue;
                    }
                    break;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DoH TXT lookup failed for {}", domain)))
    }

    #[cfg(coverage)]
    async fn doh_txt_lookup_resilient(&self, _domain: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }

    /// GRC-367 (fix 2): DoH CNAME lookup with throttle-aware retry + provider rotation,
    /// mirroring `doh_txt_lookup_resilient`. On a throttle (429/5xx) it backs off (using the
    /// same short, overflow-safe `in_race_backoff`) and rotates to the next DoH provider,
    /// up to `max_dns_retries` times. A non-throttle error stops retrying immediately.
    ///
    /// This lets the CNAME path RECOVER from a single throttling provider instead of the old
    /// `get_cname_records_with_rate_limit` behavior of collapsing any failure into `Ok(empty)`
    /// — which made a throttle indistinguishable from a genuine "this domain has no CNAME".
    /// On a genuine no-CNAME the inner lookup returns `Ok(vec![])`, which we propagate as-is;
    /// only an all-providers-throttle surfaces as a `DNS_THROTTLE` error.
    #[cfg(not(coverage))]
    async fn doh_cname_lookup_resilient(&self, domain: &str) -> Result<Vec<String>> {
        let attempts = self.resilient_attempts();
        let mut last_err: Option<anyhow::Error> = None;
        for i in 0..attempts {
            // Mirror the TXT path: never index an empty DoH pool.
            let Some(server) = self.next_doh_server_opt().cloned() else {
                return Err(anyhow::anyhow!(
                    "no DoH servers configured for CNAME lookup of {}",
                    domain
                ));
            };
            match self.doh_cname_lookup(domain, &server).await {
                Ok(records) => return Ok(records),
                Err(e) => {
                    let msg = e.to_string();
                    let throttled = msg.contains("DNS_THROTTLE");
                    let endpoint_broken = msg.contains("DNS_ENDPOINT");
                    self.log_doh_failure(&server.name, &msg);
                    if !throttled && !endpoint_broken {
                        // Count transport/parse provider failures (see TXT path).
                        self.note_throttle();
                    }
                    last_err = Some(e);
                    if i + 1 < attempts {
                        if throttled {
                            // fix 5: same short, overflow-safe backoff as the TXT path.
                            tokio::time::sleep(self.in_race_backoff(i)).await;
                        }
                        // Rotate past ANY failing provider (see TXT path).
                        continue;
                    }
                    break;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DoH CNAME lookup failed for {}", domain)))
    }

    #[cfg(coverage)]
    async fn doh_cname_lookup_resilient(&self, _domain: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }

    /// GRC-367: acquire a permit from the pool's per-process DNS rate limiter. Called on the
    /// production hot path so `dns_queries_per_second` is enforced even when no explicit
    /// RateLimitContext is threaded through (the limiter was previously dead code).
    pub async fn acquire_dns_permit(&self) {
        self.dns_limiter.acquire().await;
    }

    /// Create a traditional DNS resolver for the given server config (C002 fix: returns Result)
    fn create_dns_resolver(
        &self,
        server: &DnsServerConfig,
        use_tcp: bool,
    ) -> Result<TokioResolver> {
        // 0.26: NameServerConfig takes an IpAddr (port 53 is the resolver default).
        // The configured address is "ip:53"; parse to SocketAddr and take the IP to
        // preserve the prior behavior (always resolving against the standard DNS port).
        let socket_addr: std::net::SocketAddr = server.address.parse().map_err(|e| {
            anyhow::anyhow!(
                "Invalid DNS server address '{}' for server '{}': {}",
                server.address,
                server.name,
                e
            )
        })?;
        let ns_ip = socket_addr.ip();

        // 0.26: protocol is chosen via the NameServerConfig constructor instead of a
        // separate Protocol field. udp() / tcp() match the prior UDP/TCP selection.
        let name_server = if use_tcp {
            NameServerConfig::tcp(ns_ip)
        } else {
            NameServerConfig::udp(ns_ip)
        };

        // 0.26: ResolverConfig::new() is gone — build via from_parts(domain, search, servers).
        let config = ResolverConfig::from_parts(None, vec![], vec![name_server]);

        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(server.timeout_secs);
        opts.attempts = 1; // Single attempt for speed
        opts.edns0 = true;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6; // Prefer IPv4 for speed
        opts.num_concurrent_reqs = 4; // Increased concurrency

        // 0.26: the builder now returns Result (build() can fail constructing the
        // runtime), so propagate with `?`.
        Ok(
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                .with_options(opts)
                .build()?,
        )
    }

    /// GRC-367 (fix 1): subdomain fast path — the highest-concurrency DNS path
    /// (`buffer_unordered(50)` over every discovered subdomain in analysis.rs).
    ///
    /// Previously this path (a) never acquired a DNS permit, so it bypassed the limiter
    /// entirely; (b) called the non-resilient `doh_*_lookup` directly so a single throttling
    /// provider was never rotated past; and (c) collapsed `DNS_THROTTLE` into an empty answer
    /// via `_ => {}` + `unwrap_or_default()`, threading no failure counter — making throttles
    /// invisible to the exit-3 guard (`has_dns_failures() && unique_vendors == 0`).
    ///
    /// Now it acquires a permit before any DoH call, uses the resilient (rotate + backoff)
    /// lookups, and threads `dns_failure_counter` so a throttle that survives ALL providers
    /// increments it. A genuine empty answer (no records) still returns empty without
    /// touching the counter.
    // cfg(not(coverage)): performs live DNS lookups via DoH and traditional DNS — requires network
    #[cfg(not(coverage))]
    pub async fn get_txt_and_cname_fast(
        &self,
        domain: &str,
        dns_failure_counter: &AtomicUsize,
    ) -> (Vec<String>, Vec<String>) {
        // fix 1: enforce the per-process DNS limiter on this hot path (was bypassed entirely).
        self.acquire_dns_permit().await;

        let (txt_result, cname_result) =
            tokio::join!(self.fast_txt_lookup(domain), self.fast_cname_lookup(domain),);

        // fix 1: a surviving throttle on EITHER record type increments the failure counter
        // so the exit-3 guard can distinguish "throttled into emptiness" from "genuinely empty".
        let txt = match txt_result {
            Ok(records) => records,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("DNS_THROTTLE") || msg.contains("DNS_ENDPOINT") {
                    dns_failure_counter.fetch_add(1, Ordering::Relaxed);
                }
                Vec::new()
            }
        };
        let cname = match cname_result {
            Ok(records) => records,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("DNS_THROTTLE") || msg.contains("DNS_ENDPOINT") {
                    dns_failure_counter.fetch_add(1, Ordering::Relaxed);
                }
                Vec::new()
            }
        };
        (txt, cname)
    }

    #[cfg(coverage)]
    pub async fn get_txt_and_cname_fast(
        &self,
        _domain: &str,
        _dns_failure_counter: &AtomicUsize,
    ) -> (Vec<String>, Vec<String>) {
        (vec![], vec![])
    }

    // cfg(not(coverage)): performs live DNS lookup — requires network
    #[cfg(not(coverage))]
    async fn fast_txt_lookup(&self, domain: &str) -> Result<Vec<String>> {
        // fix 1: resilient lookup rotates/backs off past a throttling provider instead of
        // letting a single 429 collapse into a false-negative empty. A surviving throttle
        // propagates as a DNS_THROTTLE error so the caller can count it.
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.doh_txt_lookup_resilient(domain),
        )
        .await
        {
            // Any authoritative answer — including a genuine empty (NOERROR/NXDOMAIN with
            // no records) — is final: skip the traditional-DNS fallback entirely. On the
            // high-volume subdomain fan-out this saves a UDP lookup per recordless name.
            Ok(Ok(records)) => return Ok(records),
            // All providers failed (throttled or broken endpoint) — try DNS fallback, but if
            // that also yields nothing, surface the failure rather than a silent empty.
            Ok(Err(e))
                if e.to_string().contains("DNS_THROTTLE")
                    || e.to_string().contains("DNS_ENDPOINT") =>
            {
                if let Some(records) = self.fast_dns_txt_fallback(domain).await {
                    return Ok(records);
                }
                return Err(e);
            }
            _ => {}
        }

        // Fallback to traditional DNS (single attempt, UDP only)
        if let Some(records) = self.fast_dns_txt_fallback(domain).await {
            return Ok(records);
        }

        Ok(vec![])
    }

    // cfg(not(coverage)): performs live DNS lookup — requires network
    #[cfg(not(coverage))]
    async fn fast_dns_txt_fallback(&self, domain: &str) -> Option<Vec<String>> {
        let dns_server = self.next_dns_server_opt()?;
        if let Ok(resolver) = self.create_dns_resolver(dns_server, false) {
            if let Ok(Ok(txt_lookup)) = tokio::time::timeout(
                std::time::Duration::from_millis(2000),
                crate::http_client::with_connection_permit(resolver.txt_lookup(domain)),
            )
            .await
            {
                // 0.26: Lookup no longer exposes .iter() over RData — iterate the
                // answer Records and render each record's RData (record.data()) to
                // preserve the previous per-RData string output.
                let records: Vec<String> = txt_lookup
                    .answers()
                    .iter()
                    .map(|r| r.data.to_string())
                    .collect();
                if !records.is_empty() {
                    return Some(records);
                }
            }
        }
        None
    }

    #[cfg(coverage)]
    async fn fast_txt_lookup(&self, _domain: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }

    // cfg(not(coverage)): performs live DNS lookup — requires network
    #[cfg(not(coverage))]
    async fn fast_cname_lookup(&self, domain: &str) -> Result<Vec<String>> {
        // fix 1: resilient CNAME lookup (rotate + backoff) instead of a single direct call.
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.doh_cname_lookup_resilient(domain),
        )
        .await
        {
            // Authoritative answer (including genuine no-CNAME) is final — skip fallback.
            Ok(Ok(records)) => return Ok(records),
            Ok(Err(e))
                if e.to_string().contains("DNS_THROTTLE")
                    || e.to_string().contains("DNS_ENDPOINT") =>
            {
                if let Some(records) = self.fast_dns_cname_fallback(domain).await {
                    return Ok(records);
                }
                return Err(e);
            }
            _ => {}
        }

        // Fallback to traditional DNS
        if let Some(records) = self.fast_dns_cname_fallback(domain).await {
            return Ok(records);
        }

        Ok(vec![])
    }

    // cfg(not(coverage)): performs live DNS lookup — requires network
    #[cfg(not(coverage))]
    async fn fast_dns_cname_fallback(&self, domain: &str) -> Option<Vec<String>> {
        let dns_server = self.next_dns_server_opt()?;
        if let Ok(resolver) = self.create_dns_resolver(dns_server, false) {
            if let Ok(Ok(lookup)) = tokio::time::timeout(
                std::time::Duration::from_millis(2000),
                crate::http_client::with_connection_permit(
                    resolver.lookup(domain, hickory_resolver::proto::rr::RecordType::CNAME),
                ),
            )
            .await
            {
                use hickory_resolver::proto::rr::RData;
                // 0.26: Lookup::record_iter() is gone — iterate answers() (&[Record])
                // and match on each record's RData via record.data().
                let records: Vec<String> = lookup
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::CNAME(ref cname) => {
                            Some(cname.to_string().trim_end_matches('.').to_string())
                        }
                        _ => None,
                    })
                    .collect();
                if !records.is_empty() {
                    return Some(records);
                }
            }
        }
        None
    }

    #[cfg(coverage)]
    async fn fast_cname_lookup(&self, _domain: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

// cfg(not(coverage)): the memo only serves the live-network lookup paths, which are
// themselves compiled out under coverage.
#[cfg(not(coverage))]
impl DnsServerPool {
    /// A previously-seen authoritative answer for `(kind, domain)`, if any.
    async fn recall_answer(&self, kind: RecordKind, domain: &str) -> Option<Vec<String>> {
        let memo = self.answer_memo.lock().await;
        let hit = memo.get(&(kind, domain.to_string())).cloned();
        if hit.is_some() {
            crate::perf::METRICS.dns_memo_hit.hit();
        }
        hit
    }

    /// Record an answer that a resolver actually returned.
    ///
    /// Callers MUST NOT pass a vector manufactured after every resolution path failed:
    /// that value is a degradation marker, not a fact about the zone, and its caller is
    /// obliged to count it toward the DNS-failure guard rather than memoize it.
    async fn remember_answer(&self, kind: RecordKind, domain: &str, records: &[String]) {
        let mut memo = self.answer_memo.lock().await;
        memo.insert((kind, domain.to_string()), records.to_vec());
    }
}

pub async fn get_txt_records(domain: &str) -> Result<Vec<String>> {
    get_txt_records_with_pool(domain, &DnsServerPool::new()).await
}

pub async fn get_txt_records_with_pool(
    domain: &str,
    dns_pool: &DnsServerPool,
) -> Result<Vec<String>> {
    get_txt_records_with_rate_limit(domain, dns_pool, None, None).await
}

pub async fn get_txt_records_with_pool_tracked(
    domain: &str,
    dns_pool: &DnsServerPool,
    dns_failure_counter: &AtomicUsize,
) -> Result<Vec<String>> {
    get_txt_records_with_rate_limit(domain, dns_pool, None, Some(dns_failure_counter)).await
}

// cfg(not(coverage)): performs live DNS lookups racing DoH and traditional DNS — requires network
#[cfg(not(coverage))]
pub async fn get_txt_records_with_rate_limit(
    domain: &str,
    dns_pool: &DnsServerPool,
    rate_limit_ctx: Option<&RateLimitContext>,
    dns_failure_counter: Option<&AtomicUsize>,
) -> Result<Vec<String>> {
    // A memo hit sends no packet, so it is checked before any permit is taken: rate limits
    // exist to pace outbound queries, and charging a token for a query we don't make would
    // throttle the scan against nothing.
    if let Some(records) = dns_pool.recall_answer(RecordKind::Txt, domain).await {
        debug!(
            "TXT memo hit for {}: {} records (no query issued)",
            domain,
            records.len()
        );
        return Ok(records);
    }

    // Past the memo: this call will put a packet on the wire. Time the whole resolution,
    // including the rate-limit permit wait, since that is wall clock the scan actually spends.
    let _query_timer = crate::perf::scoped(&crate::perf::METRICS.dns_query);

    // Apply rate limiting if configured
    if let Some(ctx) = rate_limit_ctx {
        ctx.dns_limiter.acquire().await;
    } else {
        // GRC-367: no explicit context → use the pool's own per-process limiter so the
        // configured dns_queries_per_second is actually enforced on the production hot path.
        dns_pool.acquire_dns_permit().await;
    }

    debug!("Querying TXT records for domain: {}", domain);

    // Race DoH and traditional DNS concurrently — first successful result wins.
    // This replaces the old sequential fallback (DoH×2 → DNS×2 → system) which
    // could take 20+ seconds on failure. Now worst-case is ~3s (single timeout).
    // Spawn DoH lookup
    let doh_fut = async {
        // GRC-367: resilient lookup retries/rotates DoH providers on throttle (429/5xx)
        // instead of collapsing a throttle into an empty (false-negative) answer.
        // An authoritative empty answer (HTTP 2xx, RCODE NOERROR/NXDOMAIN, no records) is
        // a REAL answer: return Some(vec![]) so the caller doesn't fall through to the
        // system resolver and emit a spurious "All DNS resolution failed" warning for
        // every domain that genuinely has no TXT records.
        dns_pool.doh_txt_lookup_resilient(domain).await.ok()
    };

    // Spawn traditional DNS lookup (UDP). DNS-only/DoH-only configs are legal —
    // an empty traditional pool just means this race arm yields nothing.
    let dns_fut = async {
        let dns_server = dns_pool.next_dns_server_opt()?;
        let resolver = match dns_pool.create_dns_resolver(dns_server, false) {
            Ok(r) => r,
            Err(_) => return None,
        };
        match crate::http_client::with_connection_permit(resolver.txt_lookup(domain)).await {
            Ok(txt_lookup) => {
                // 0.26: iterate answer Records and render each record's RData.
                let records: Vec<String> = txt_lookup
                    .answers()
                    .iter()
                    .map(|r| r.data.to_string())
                    .collect();
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
                        info!("DoH successful: Found {} TXT records for {}", records.len(), domain);
                        return Some(records);
                    }
                    // DoH failed — wait for DNS
                    if let Some(records) = (&mut dns_fut).await {
                        debug!("DNS successful: Found {} TXT records for {} (UDP)", records.len(), domain);
                        return Some(records);
                    }
                    None
                }
                result = &mut dns_fut => {
                    if let Some(records) = result {
                        debug!("DNS successful: Found {} TXT records for {} (UDP)", records.len(), domain);
                        return Some(records);
                    }
                    // DNS failed — wait for DoH
                    if let Some(records) = (&mut doh_fut).await {
                        info!("DoH successful: Found {} TXT records for {}", records.len(), domain);
                        return Some(records);
                    }
                    None
                }
            }
        }
    ).await;

    if let Ok(Some(records)) = race_result {
        // A resolver answered. Empty counts: "this name has no TXT records" is an answer.
        dns_pool
            .remember_answer(RecordKind::Txt, domain, &records)
            .await;
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
            dns_pool
                .remember_answer(RecordKind::Txt, domain, &records)
                .await;
            Ok(records)
        }
        Err(e) => {
            warn!("All DNS resolution failed for {} — returning empty results to continue analysis. Last error: {}", domain, e);
            if let Some(counter) = dns_failure_counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            // Deliberately NOT memoized: no resolver answered, so this empty vector is a
            // degradation marker. Memoizing it would turn a transient failure into a
            // scan-wide false negative and would suppress the counting above on retries.
            Ok(vec![])
        }
    }
}

#[cfg(coverage)]
pub async fn get_txt_records_with_rate_limit(
    _domain: &str,
    _dns_pool: &DnsServerPool,
    _rate_limit_ctx: Option<&RateLimitContext>,
    _dns_failure_counter: Option<&AtomicUsize>,
) -> Result<Vec<String>> {
    Ok(vec![])
}

// cfg(not(coverage)): performs live DNS lookup via system resolver — requires network
#[cfg(not(coverage))]
async fn try_system_dns_resolver(domain: &str) -> Result<Vec<String>> {
    // 0.26: builder_tokio() returns Result and build() now also returns Result.
    let resolver = TokioResolver::builder_tokio()?.build()?;

    // Query as an absolute (FQDN) name — trailing dot — so the system resolver's
    // search list from /etc/resolv.conf (e.g. OrbStack/Docker's `search localdomain`)
    // is never appended. Without this, a failed lookup of `_x._spf.vali.email` was
    // retried as `_x._spf.vali.email.localdomain` and surfaced as a confusing error.
    let fqdn = if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{}.", domain)
    };
    let txt_lookup = crate::http_client::with_connection_permit(resolver.txt_lookup(fqdn)).await?;
    // 0.26: iterate answer Records and render each record's RData.
    let records: Vec<String> = txt_lookup
        .answers()
        .iter()
        .map(|record| record.data.to_string())
        .collect();

    Ok(records)
}

#[cfg(coverage)]
async fn try_system_dns_resolver(_domain: &str) -> Result<Vec<String>> {
    Ok(vec![])
}

// cfg(not(coverage)): delegates to get_cname_records_with_rate_limit which performs live DNS
#[cfg(not(coverage))]
pub async fn get_cname_records_with_pool(
    domain: &str,
    dns_pool: &DnsServerPool,
) -> Result<Vec<String>> {
    get_cname_records_with_rate_limit(domain, dns_pool, None, None).await
}

#[cfg(coverage)]
pub async fn get_cname_records_with_pool(
    _domain: &str,
    _dns_pool: &DnsServerPool,
) -> Result<Vec<String>> {
    Ok(vec![])
}

// GRC-367 (fix 4): `get_cname_records_with_pool_tracked` removed — it had zero callers in src,
// tests, examples, and benches. The CNAME throttle is now tracked at the pool choke-point
// (`note_throttle` in `doh_cname_lookup`); a separate threaded-counter CNAME wrapper is dead.

// cfg(not(coverage)): performs live DNS lookup via DoH — requires network
#[cfg(not(coverage))]
pub async fn get_cname_records_with_rate_limit(
    domain: &str,
    dns_pool: &DnsServerPool,
    rate_limit_ctx: Option<&RateLimitContext>,
    dns_failure_counter: Option<&AtomicUsize>,
) -> Result<Vec<String>> {
    // Checked before the permit for the same reason as the TXT path: a memo hit issues no
    // query, so it must not consume rate-limit budget.
    if let Some(records) = dns_pool.recall_answer(RecordKind::Cname, domain).await {
        debug!(
            "CNAME memo hit for {}: {} records (no query issued)",
            domain,
            records.len()
        );
        return Ok(records);
    }

    // Apply rate limiting if configured
    if let Some(ctx) = rate_limit_ctx {
        ctx.dns_limiter.acquire().await;
    } else {
        // GRC-367: enforce the pool's per-process DNS limiter on the production path.
        dns_pool.acquire_dns_permit().await;
    }

    debug!("Querying CNAME records for domain: {}", domain);

    // GRC-367 (fix 2): use the resilient (rotate + backoff) CNAME lookup so a single
    // throttling provider is rotated past instead of collapsing every failure into
    // `Ok(empty)`. The race is bounded by a 3s timeout — matching the TXT path — which the
    // short in-race backoff (fix 5) is sized to allow 2-3 rotations within.
    match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        dns_pool.doh_cname_lookup_resilient(domain),
    )
    .await
    {
        // Genuine answer: records present.
        Ok(Ok(records)) if !records.is_empty() => {
            debug!(
                "DoH successful: Found {} CNAME records for {}",
                records.len(),
                domain
            );
            dns_pool
                .remember_answer(RecordKind::Cname, domain, &records)
                .await;
            Ok(records)
        }
        // Genuine no-CNAME (NoData/NXDOMAIN): the resilient lookup succeeded but returned
        // no records. This is the normal "CNAME absence is normal" case — return empty WITHOUT
        // touching the failure counter. It is an authoritative answer, so it is memoized.
        Ok(Ok(_)) => {
            dns_pool
                .remember_answer(RecordKind::Cname, domain, &[])
                .await;
            Ok(vec![])
        }
        // All providers throttled (429/5xx surviving rotation). This is a FALSE-NEGATIVE risk,
        // NOT a genuine absence — count it so the exit-3 guard can see it, then return empty so
        // analysis continues (consistent with the TXT path's degrade-but-record behavior).
        Ok(Err(e))
            if e.to_string().contains("DNS_THROTTLE") || e.to_string().contains("DNS_ENDPOINT") =>
        {
            warn!(
                "CNAME lookup for {} failed across all DoH providers (throttled or broken endpoint) — recording failure: {}",
                domain, e
            );
            if let Some(counter) = dns_failure_counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            Ok(vec![])
        }
        // Non-throttle error (parse/transport) or overall timeout: not a throttle, treat as a
        // normal no-CNAME outcome (unchanged from prior behavior for these cases).
        _ => Ok(vec![]),
    }
}

#[cfg(coverage)]
pub async fn get_cname_records_with_rate_limit(
    _domain: &str,
    _dns_pool: &DnsServerPool,
    _rate_limit_ctx: Option<&RateLimitContext>,
    _dns_failure_counter: Option<&AtomicUsize>,
) -> Result<Vec<String>> {
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

#[cfg_attr(coverage_nightly, coverage(off))]
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

#[cfg_attr(coverage_nightly, coverage(off))]
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

// cfg(not(coverage)): performs live DNS lookups to resolve SPF include chains — requires network
#[cfg(not(coverage))]
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

#[cfg(coverage)]
pub async fn resolve_spf_includes_recursive(
    _txt_records: &[String],
    _dns_pool: &DnsServerPool,
    _source_domain: &str,
) -> Vec<VendorDomain> {
    vec![]
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
            // RFC 7208 §7 (macros): an include:/redirect= target bearing a macro
            // (e.g. Valimail's `%{ir}._ip.%{v}._ehlo.%{d}._spf.vali.email`) is a
            // sender-dependent, evaluation-time construct — it is NOT a static SPF
            // delegation. Stripping the `%{...}` leaves a non-resolvable residual
            // like `_ip._ehlo._spf.vali.email`; recursing into it yields RCODE 2 and
            // noisy DoH-failure warnings. Skip it here. The provider's registrable
            // base domain (vali.email) is still surfaced as a vendor by
            // extract_from_spf_record, so we lose no vendor signal.
            // Key off the raw token containing any `%` (macro variables `%{...}` and the
            // macro-literal escapes `%%`/`%_`/`%-`); `%` is never valid in a real
            // hostname, so this is RFC 7208 §7-complete and never false-positives.
            if raw_target.contains('%') {
                continue;
            }
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

#[cfg_attr(coverage_nightly, coverage(off))]
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
            for domain_match in MAILTO_REGEX
                .captures_iter(tag_value)
                .filter_map(|c| c.get(2))
            {
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

/// Literal TXT-record markers that identify a SaaS vendor, mapped to that vendor's domain.
///
/// A static slice rather than a `vec!` rebuilt inside the function: this table is
/// consulted for every TXT record of every domain and subdomain a scan touches, and the
/// entries are compile-time constants.
static VERIFICATION_PATTERNS: &[(&str, &str, RecordType)] = &[
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

fn try_static_verification_patterns(
    record: &str,
    _logger: Option<&dyn LogFailure>,
    _source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    // Comprehensive static provider mappings based on research

    let mut domains = Vec::new();

    // These patterns are all literal strings, use contains() instead of regex for speed
    for (pattern, domain, record_type) in VERIFICATION_PATTERNS {
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

pub(crate) fn is_valid_domain(domain: &str) -> bool {
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
        assert!(
            domain.len() <= 253,
            "60*4 + separators = 247, within 253 limit"
        );
        assert!(is_valid_domain(&domain));
    }

    #[test]
    fn test_is_valid_domain_length_too_long() {
        let label = "a".repeat(63);
        let domain = format!("{}.{}.{}.{}.com", label, label, label, label);
        assert!(
            domain.len() > 253,
            "63*4 + separators = 259, exceeds 253 limit"
        );
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

    #[cfg_attr(coverage_nightly, coverage(off))]
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
        // RFC 7208 §7: a macro-bearing include:/redirect= target is a runtime
        // construct, not a static delegation. It must NOT be recursed into (the
        // stripped residual is non-resolvable). A static target alongside it is
        // still collected.
        let record = "v=spf1 include:%{ir}._spf.google.com redirect=_spf.salesforce.com ~all";
        let mut to_resolve = Vec::new();
        let mut visited = HashSet::new();
        collect_spf_targets(record, &mut to_resolve, &mut visited);
        // The macro-bearing include is skipped...
        assert!(
            !to_resolve.iter().any(|t| t.contains("google.com")),
            "macro-bearing include must not be enqueued, got {:?}",
            to_resolve
        );
        // ...but the static redirect is still collected.
        assert!(to_resolve.iter().any(|t| t.contains("salesforce.com")));
    }

    #[test]
    fn test_collect_spf_targets_skips_valimail_agari_macro_artifacts() {
        // Regression for the vanta.com run: Valimail/Agari publish macro-based
        // exists/include mechanisms. Their stripped residuals (_ip._ehlo._spf.vali.email,
        // 55.spf-protect.agari.com) previously got DNS-queried -> RCODE 2 noise.
        let record = "v=spf1 include:%{ir}._ip.%{v}._ehlo._spf.vali.email redirect=%{ir}.55.spf-protect.agari.com ~all";
        let mut to_resolve = Vec::new();
        let mut visited = HashSet::new();
        collect_spf_targets(record, &mut to_resolve, &mut visited);
        assert!(
            to_resolve.is_empty(),
            "no macro-bearing targets should be enqueued, got {:?}",
            to_resolve
        );
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
    #[cfg(not(coverage))]
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
    #[cfg(not(coverage))]
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
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_success() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response =
            build_doh_txt_response("example.com", &["v=spf1 include:_spf.google.com ~all"]);

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
        let records = pool
            .doh_txt_lookup("example.com", doh_server)
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert!(records[0].contains("spf1"));
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_multiple_records() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_non_txt_type_ignored() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
    #[cfg(not(coverage))]
    async fn test_doh_cname_lookup_success() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let records = pool
            .doh_cname_lookup("alias.com", doh_server)
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        // Trailing dot should be removed
        assert_eq!(records[0], "target.example.com");
    }

    #[tokio::test]
    async fn test_doh_cname_lookup_empty() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let records = pool
            .doh_cname_lookup("nocname.com", doh_server)
            .await
            .unwrap();

        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn test_doh_cname_lookup_non_cname_type_ignored() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let records = pool
            .doh_cname_lookup("nocname.com", doh_server)
            .await
            .unwrap();

        assert!(records.is_empty());
    }

    // --- get_txt_records_with_pool tests ---

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_pool_via_doh() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("test.com", &["v=spf1 include:_spf.google.com ~all"]);

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
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
    #[cfg(not(coverage))]
    async fn test_get_cname_records_with_pool_via_doh() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
    #[cfg(not(coverage))]
    async fn test_get_txt_and_cname_fast() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let counter = AtomicUsize::new(0);
        let (txt_records, cname_records) = pool.get_txt_and_cname_fast("fast.com", &counter).await;

        assert!(!txt_records.is_empty());
        assert!(!cname_records.is_empty());
        // A successful lookup must NOT register a DNS failure.
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "successful fast lookup must not increment the failure counter"
        );
    }

    // GRC-367 (fix 6): the old assertion-free `test_get_txt_and_cname_fast_doh_failure`
    // mounted a 500 and asserted NOTHING (`let _ = …`) — it locked in the very bug the audit
    // found (a throttle silently collapsing to empty on the subdomain fast path). Rewritten to
    // assert the POST-FIX behavior: a 429/5xx that survives all DoH providers (and the dead
    // 127.0.0.1 DNS fallback in tests) is SURFACED via the failure counter, never silently empty.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_and_cname_fast_throttle_increments_failure_counter() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Single DoH provider that always 5xx-throttles (a DNS_THROTTLE per the doh_*_lookup
        // contract). The test DNS fallback target (127.0.0.1:53) won't answer, so the throttle
        // cannot be masked by a fallback success.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);
        let (txt_records, cname_records) = pool
            .get_txt_and_cname_fast("failing.invalid", &counter)
            .await;

        // Records are empty (analysis still continues), but the throttle is NOT silent: the
        // shared counter is incremented so the exit-3 guard can see it. One increment per
        // record type (TXT + CNAME) that was throttled across all providers.
        assert!(txt_records.is_empty());
        assert!(cname_records.is_empty());
        assert!(
            counter.load(Ordering::Relaxed) >= 1,
            "a throttle surviving all providers on the subdomain fast path MUST increment the \
             DNS failure counter, not collapse silently into an empty result"
        );
    }

    // --- get_txt_records_with_rate_limit tests ---

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_rate_limit_no_limiter() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let records = get_txt_records_with_rate_limit("ratelimit.com", &pool, None, None)
            .await
            .unwrap();

        assert!(!records.is_empty());
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_rate_limit_with_limiter() {
        use crate::config::RateLimitConfig;
        use crate::rate_limit::RateLimitContext;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let records = get_txt_records_with_rate_limit("limited.com", &pool, Some(&ctx), None)
            .await
            .unwrap();

        assert!(!records.is_empty());
    }

    // --- get_cname_records_with_rate_limit tests ---

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_cname_records_with_rate_limit_no_limiter() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let records = get_cname_records_with_rate_limit("cname-rl.com", &pool, None, None)
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0], "target.cdn.com");
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_cname_records_with_rate_limit_with_limiter() {
        use crate::config::RateLimitConfig;
        use crate::rate_limit::RateLimitContext;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let records =
            get_cname_records_with_rate_limit("cname-limited.com", &pool, Some(&ctx), None)
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
    #[cfg(not(coverage))]
    async fn test_resolve_spf_includes_recursive_with_mock() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // First level: initial SPF includes _spf.nested.com
        // When we resolve _spf.nested.com, it returns another SPF with a vendor
        let nested_response =
            build_doh_txt_response("_spf.nested.com", &["v=spf1 include:spf.vendor.com ~all"]);

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
        let vendor_response =
            build_doh_txt_response("spf.vendor.com", &["v=spf1 ip4:10.0.0.0/8 ~all"]);

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
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
    #[cfg_attr(coverage_nightly, coverage(off))]
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
    #[cfg(not(coverage))]
    async fn test_fast_txt_lookup_doh_success() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
    #[cfg(not(coverage))]
    async fn test_fast_txt_lookup_doh_failure_dns_fallback() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Only DoH provider returns 500 (a throttle/5xx); no healthy provider to rotate to and
        // the test UDP fallback (127.0.0.1:53) is unreachable.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        // GRC-367 fix 1: a surviving throttle on the subdomain fast path MUST surface as a
        // DNS_THROTTLE error (so get_txt_and_cname_fast counts it toward the exit-3 guard),
        // never be silently swallowed into an empty answer.
        let result = pool.fast_txt_lookup("nonexistent.invalid").await;
        assert!(
            result.is_err(),
            "5xx throttle must surface, not be swallowed into Ok(empty)"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_THROTTLE"),
            "surfaced error must be tagged DNS_THROTTLE"
        );
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_fast_cname_lookup_doh_success() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
    #[cfg(not(coverage))]
    async fn test_fast_cname_lookup_doh_failure_dns_fallback() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        // GRC-367 fix 2: a CNAME-path throttle must surface as DNS_THROTTLE, not Ok(empty).
        let result = pool.fast_cname_lookup("nonexistent.invalid").await;
        assert!(
            result.is_err(),
            "5xx throttle must surface, not be swallowed into Ok(empty)"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_THROTTLE"),
            "surfaced error must be tagged DNS_THROTTLE"
        );
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
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_with_escaped_data() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let records = pool
            .doh_txt_lookup("escaped.com", doh_server)
            .await
            .unwrap();

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
        let spf_count = results
            .iter()
            .filter(|r| r.source_type == RecordType::DnsTxtSpf)
            .count();
        let dmarc_count = results
            .iter()
            .filter(|r| r.source_type == RecordType::DnsTxtDmarc)
            .count();
        let verif_count = results
            .iter()
            .filter(|r| r.source_type == RecordType::DnsTxtVerification)
            .count();
        assert!(
            spf_count >= 3,
            "Should have at least 3 SPF domains, got {}",
            spf_count
        );
        assert!(
            dmarc_count >= 2,
            "Should have at least 2 DMARC domains, got {}",
            dmarc_count
        );
        assert!(
            verif_count >= 4,
            "Should have at least 4 verification domains, got {}",
            verif_count
        );
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
        let records = vec!["\"v=spf1 include:_spf.google.com ~all\"".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        assert!(!results.is_empty());
    }

    // --- DnsServerPool with single server ---

    #[test]
    fn test_dns_server_pool_with_single_test_url() {
        let pool =
            DnsServerPool::with_test_urls(vec!["http://localhost:1234/dns-query".to_string()]);
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
        assert!(domains
            .iter()
            .all(|d| d.source_type == RecordType::DnsTxtDkim));
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
        assert!(results
            .iter()
            .any(|d| d.domain == "selector.mailservice.com"));
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
    #[cfg(not(coverage))]
    async fn test_try_system_dns_resolver_valid_domain() {
        let result = try_system_dns_resolver("google.com").await;
        match result {
            Ok(records) => {
                // google.com has TXT records (SPF, verification, etc.)
                assert!(!records.is_empty(), "google.com should have TXT records");
                let has_spf = records.iter().any(|r| r.contains("spf"));
                assert!(
                    has_spf,
                    "google.com TXT records should include SPF: {:?}",
                    records
                );
            }
            Err(e) => {
                // DNS resolution may fail in sandboxed/offline environments
                let msg = e.to_string();
                assert!(
                    !msg.is_empty(),
                    "Error message should be descriptive: {}",
                    msg
                );
            }
        }
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_try_system_dns_resolver_nonexistent_domain() {
        let result = try_system_dns_resolver("zzz-nonexistent.invalid").await;
        // .invalid TLD should fail DNS resolution
        assert!(
            result.is_err(),
            "Nonexistent domain should fail DNS resolution"
        );
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_try_system_dns_resolver_no_txt_records() {
        let result = try_system_dns_resolver("zzz-no-txt-records-test.com").await;
        if let Ok(records) = result {
            let _ = records;
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
        assert!(
            !failures.is_empty(),
            "Logger should capture invalid SPF domain 'a'"
        );
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
        assert!(
            !to_resolve.is_empty(),
            "Should collect SPF include/redirect targets"
        );
        assert!(to_resolve.iter().any(|d| d.contains("google.com")));
        assert!(to_resolve.iter().any(|d| d.contains("example.com")));
    }

    #[test]
    fn test_dkim_record_with_domain_value() {
        let record = "v=DKIM1; k=rsa; h=mail.sendgrid.net; s=selector; p=MIGfMA0";
        let result = extract_from_dkim_record(record, None, "example.com", record);
        assert!(
            result.is_some(),
            "DKIM h= with a domain-like value should extract"
        );
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
        assert!(
            !failures.is_empty(),
            "Logger should capture invalid DMARC domain 'x'"
        );
        assert!(failures[0].contains("DMARC"));
    }

    #[test]
    fn test_verification_record_prefix_pattern() {
        let record = "verification-google=abc123";
        let result = extract_from_verification_record(record, None, "example.com", record);
        assert!(
            result.is_some(),
            "verification-google= should infer google.com"
        );
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "google.com"));
    }

    #[test]
    fn test_verification_record_site_pattern() {
        let record = "hubspot-site-verification=def456";
        let result = extract_from_verification_record(record, None, "example.com", record);
        assert!(
            result.is_some(),
            "hubspot-site-verification= should infer hubspot.com"
        );
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
        assert!(
            result.is_some(),
            "atlassian-domain-verification should infer atlassian.com"
        );
    }

    #[tokio::test]
    #[cfg(coverage)]
    async fn test_try_system_dns_resolver_coverage_stub() {
        let result = try_system_dns_resolver("example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[cfg(coverage)]
    async fn test_get_cname_records_with_rate_limit_coverage_stub() {
        let pool = DnsServerPool::default();
        let result = get_cname_records_with_rate_limit("example.com", &pool, None, None).await;
        assert!(result.is_ok());
    }

    // ── DNS failure counter tracking (wiremock, no live DNS) ─────────

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_pool_tracked_no_failures() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("tracked.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "tracked.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);
        let result = get_txt_records_with_pool_tracked("tracked.com", &pool, &counter).await;
        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_rate_limit_counter_none() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("counter-none.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "counter-none.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let result = get_txt_records_with_rate_limit("counter-none.com", &pool, None, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_rate_limit_counter_some() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("counter-some.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "counter-some.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);
        let result =
            get_txt_records_with_rate_limit("counter-some.com", &pool, None, Some(&counter)).await;
        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    // ── GRC-367: throttle (429) must never masquerade as an empty answer ──────────

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_throttle_returns_error_not_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // DoH provider is throttling (HTTP 429) — must surface as an error, NOT Ok(empty).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = pool.next_doh_server().clone();
        let result = pool.doh_txt_lookup("throttled.example", &doh_server).await;
        assert!(
            result.is_err(),
            "a 429 throttle must surface as an error, never a silent Ok(empty)"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_THROTTLE"),
            "throttle error must be tagged DNS_THROTTLE so the caller can retry/rotate"
        );
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_resilient_rotates_past_throttle() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Provider 1 always throttles (429); provider 2 returns a valid TXT answer.
        let throttling = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&throttling)
            .await;

        let healthy = MockServer::start().await;
        let body = build_doh_txt_response(
            "rotated.example",
            &["v=spf1 include:mail.rotated.example ~all"],
        );
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&healthy)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", throttling.uri()),
            format!("{}/dns-query", healthy.uri()),
        ]);
        // First provider 429s; resilient lookup must back off and rotate to the healthy one.
        let result = pool.doh_txt_lookup_resilient("rotated.example").await;
        assert!(
            result.is_ok(),
            "resilient lookup must rotate past the 429 provider to a healthy one"
        );
        assert!(
            !result.unwrap().is_empty(),
            "rotation to the healthy provider must return TXT records, not a false-negative empty"
        );
    }

    // ── GRC-367 (fix 2 + fix 6): CNAME throttle handling ──────────────────────────

    // doh_cname_lookup must surface a 429 throttle as a DNS_THROTTLE error (mirroring the
    // TXT path), never silently as Ok(empty) — that's the distinction the resilient layer
    // and the failure counter depend on.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_cname_lookup_throttle_429_returns_error_not_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = pool.next_doh_server().clone();
        let result = pool
            .doh_cname_lookup("throttled.example", &doh_server)
            .await;
        assert!(
            result.is_err(),
            "a 429 CNAME throttle must surface as an error, never a silent Ok(empty)"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_THROTTLE"),
            "CNAME throttle error must be tagged DNS_THROTTLE so the caller can rotate/count"
        );
    }

    // Same contract for a provider 5xx (server error).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_cname_lookup_throttle_5xx_returns_error_not_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = pool.next_doh_server().clone();
        let result = pool.doh_cname_lookup("err5xx.example", &doh_server).await;
        assert!(
            result.is_err(),
            "a 5xx CNAME response must surface as an error, never a silent Ok(empty)"
        );
        assert!(result.unwrap_err().to_string().contains("DNS_THROTTLE"));
    }

    // doh_cname_lookup_resilient must rotate past a throttling provider to a healthy one,
    // mirroring the TXT resilient path.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_cname_lookup_resilient_rotates_past_throttle() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let throttling = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&throttling)
            .await;

        let healthy = MockServer::start().await;
        let body = build_doh_cname_response("rotated.example", &["cdn.rotated.example"]);
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&healthy)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", throttling.uri()),
            format!("{}/dns-query", healthy.uri()),
        ]);
        let result = pool.doh_cname_lookup_resilient("rotated.example").await;
        assert!(
            result.is_ok(),
            "resilient CNAME lookup must rotate past the 429 provider"
        );
        let records = result.unwrap();
        assert_eq!(
            records,
            vec!["cdn.rotated.example".to_string()],
            "rotation must return the healthy provider's CNAME, not a false-negative empty"
        );
    }

    // get_cname_records_with_rate_limit must NOT return Ok(empty) "CNAME absent" on an
    // all-providers-throttle — it must record the failure via the counter (the core fix 2 bug).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_cname_records_with_rate_limit_throttle_counts_not_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Both providers 429 → throttle survives rotation.
        let p1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p1)
            .await;
        let p2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p2)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", p1.uri()),
            format!("{}/dns-query", p2.uri()),
        ]);
        let counter = AtomicUsize::new(0);
        let result =
            get_cname_records_with_rate_limit("throttled.example", &pool, None, Some(&counter))
                .await;
        // It still returns Ok(empty) so analysis continues, but the throttle is NOT silent.
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "an all-providers-throttle on the CNAME root path must increment the failure \
             counter, NOT be mistaken for a genuine 'CNAME absent' (Ok(empty)) result"
        );
    }

    // A GENUINE no-CNAME (provider answers 200 with an empty Answer) must map to Ok(empty)
    // WITHOUT touching the counter — "CNAME absence is normal".
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_cname_records_with_rate_limit_genuine_absence_no_count() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = build_doh_empty_response("no-cname.example");
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);
        let result =
            get_cname_records_with_rate_limit("no-cname.example", &pool, None, Some(&counter))
                .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "a genuine no-CNAME answer is normal and must NOT increment the failure counter"
        );
    }

    // GRC-367 (fix 2): a throttle that survives ALL DoH providers must (a) surface as a
    // DNS_THROTTLE error and (b) increment the pool's choke-point counter — verified WITHOUT
    // touching the system resolver. The previous version of this test drove the outer
    // `get_txt_records_with_rate_limit`, which on an all-throttle falls through to
    // `try_system_dns_resolver("throttled.invalid")` — a REAL network query that violated the
    // no-live-DNS invariant. We now drive `doh_txt_lookup_resilient` directly against a
    // wiremock 429, so the only DNS traffic is to the in-process mock and the choke-point count
    // is observed at its source.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_rate_limit_all_throttled_counts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let p1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p1)
            .await;
        let p2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p2)
            .await;

        let test_counter = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", p1.uri()),
            format!("{}/dns-query", p2.uri()),
        ])
        .with_failure_counter(std::sync::Arc::clone(&test_counter));

        // Drive the resilient DoH lookup directly: both providers 429, so the throttle survives
        // rotation and surfaces as a DNS_THROTTLE error. No DNS/system fallback is reached.
        let result = pool.doh_txt_lookup_resilient("throttled.invalid").await;
        assert!(
            result.is_err(),
            "an all-providers 429 must surface as an error"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("DNS_THROTTLE"),
            "the surfaced error must be a DNS_THROTTLE, got: {err}"
        );
        // Both providers 429'd, so the choke-point fired once per provider attempt; the exit-3
        // guard only needs `> 0`, so we assert it was reached at least once.
        assert!(
            test_counter.load(Ordering::Relaxed) >= 1,
            "a throttle defeating every DoH provider must increment the pool's choke-point \
             counter so the exit-3 guard sees it — without any live system-resolver query"
        );
    }

    // ── GRC-500: non-throttle endpoint failures (4xx / bad RCODE) must surface as ──
    // ── DNS_ENDPOINT, never a silent Ok(empty). These pin THE incident: 3 of 4    ──
    // ── default providers returned HTTP 400 (wrong /dns-query-vs-/resolve path)   ──
    // ── and were read as "0 TXT records", producing false-negative 0-vendor scans.──

    // THE incident regression: a 400 with a *valid JSON error body* (so it is NOT a
    // JSON-parse failure that could mask the bug) must (a) surface as a DNS_ENDPOINT
    // error — never Ok(empty) — and (b) increment the pool's choke-point counter.
    // Previously this exact case returned Ok(vec![]) and silently dropped every vendor.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_400_valid_json_body_returns_dns_endpoint_and_counts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // A 400 with a well-formed JSON body — if the guard relied on a parse failure it
        // would slip through; the status check must reject it BEFORE parsing.
        let error_body = serde_json::json!({
            "error": "Invalid request: this endpoint does not serve application/dns-json"
        });
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(error_body)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let test_counter = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())])
            .with_failure_counter(std::sync::Arc::clone(&test_counter));
        let doh_server = pool.next_doh_server().clone();
        let result = pool.doh_txt_lookup("incident.example", &doh_server).await;

        assert!(
            result.is_err(),
            "a 400 (wrong endpoint) must surface as an error, never the false-negative Ok(empty) \
             that dropped every vendor in the incident"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_ENDPOINT"),
            "a non-throttle 4xx must be tagged DNS_ENDPOINT so the resilient loop rotates without backoff"
        );
        assert_eq!(
            test_counter.load(Ordering::Relaxed),
            1,
            "a DNS_ENDPOINT failure must increment the choke-point counter exactly once so the \
             exit-3 guard can see the broken endpoint"
        );
    }

    // The CNAME path mirrors the TXT path: a 400 must surface as DNS_ENDPOINT, not Ok(empty).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_cname_lookup_400_returns_dns_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;

        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())])
            .with_failure_counter(counter.clone());
        let doh_server = pool.next_doh_server().clone();
        let result = pool.doh_cname_lookup("incident.example", &doh_server).await;

        assert!(
            result.is_err(),
            "a 400 on the CNAME path must surface as an error, never a silent Ok(empty)"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_ENDPOINT"),
            "a non-throttle 4xx on the CNAME path must be tagged DNS_ENDPOINT (mirrors the TXT path)"
        );
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the CNAME 4xx must be counted at the choke point for the exit-3 guard, like the TXT path"
        );
    }

    // dns-json `Status` (RCODE) 2 = SERVFAIL with no Answer is a resolver-side failure, NOT a
    // genuine "no records". It must surface as DNS_ENDPOINT and increment the counter — never
    // be parsed into an empty answer that reads as "this domain has no TXT records".
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_rcode_servfail_returns_dns_endpoint_and_counts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // HTTP 200 but DNS RCODE 2 (SERVFAIL), no Answer — the subtle case the status check
        // alone would miss; the RCODE gate must catch it.
        let body = serde_json::json!({
            "Status": 2,
            "Question": [{"name": "servfail.example", "type": 16}],
            "Answer": []
        });
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let test_counter = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())])
            .with_failure_counter(std::sync::Arc::clone(&test_counter));
        let doh_server = pool.next_doh_server().clone();
        let result = pool.doh_txt_lookup("servfail.example", &doh_server).await;

        assert!(
            result.is_err(),
            "RCODE 2 (SERVFAIL) is a resolver failure, not a genuine empty — must surface as an error"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_ENDPOINT"),
            "a non-0/3 RCODE must be tagged DNS_ENDPOINT"
        );
        assert_eq!(
            test_counter.load(Ordering::Relaxed),
            1,
            "a SERVFAIL RCODE must increment the choke-point counter exactly once"
        );
    }

    // RCODE 3 = NXDOMAIN with no Answer is a GENUINE absence (the domain truly has no records).
    // It must map to Ok(vec![]) WITHOUT touching the counter — the boundary case that proves the
    // RCODE gate distinguishes "resolver failed" (count) from "genuinely absent" (don't count).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_rcode_nxdomain_returns_ok_empty_no_count() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // HTTP 200, RCODE 3 (NXDOMAIN), no Answer — a real "this domain has no TXT records".
        let body = serde_json::json!({
            "Status": 3,
            "Question": [{"name": "nxdomain.example", "type": 16}],
            "Answer": []
        });
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let test_counter = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())])
            .with_failure_counter(std::sync::Arc::clone(&test_counter));
        let doh_server = pool.next_doh_server().clone();
        let records = pool
            .doh_txt_lookup("nxdomain.example", &doh_server)
            .await
            .expect("NXDOMAIN (RCODE 3) is a genuine absence and must be Ok, not an error");

        assert!(
            records.is_empty(),
            "NXDOMAIN must return an empty record set"
        );
        assert_eq!(
            test_counter.load(Ordering::Relaxed),
            0,
            "a genuine NXDOMAIN absence must NOT increment the failure counter"
        );
    }

    // The resilient loop must rotate to the next provider on a DNS_ENDPOINT failure (the
    // incident scenario: one provider 400s, the next serves real records). This pins the
    // "rotate immediately, no backoff" behavior for the DNS_ENDPOINT class specifically.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_resilient_rotates_past_400_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Provider 1 always 400s (DNS_ENDPOINT); provider 2 serves a valid TXT answer.
        let broken = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&broken)
            .await;

        let healthy = MockServer::start().await;
        let body = build_doh_txt_response(
            "rotated.example",
            &["v=spf1 include:mail.rotated.example ~all"],
        );
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&healthy)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", broken.uri()),
            format!("{}/dns-query", healthy.uri()),
        ]);
        let result = pool.doh_txt_lookup_resilient("rotated.example").await;
        assert!(
            result.is_ok(),
            "resilient lookup must rotate past the 400 (DNS_ENDPOINT) provider to a healthy one"
        );
        let records = result.unwrap();
        assert_eq!(
            records.len(),
            1,
            "rotation must return the healthy provider's TXT records, not a false-negative empty"
        );
        assert!(
            records[0].contains("spf1"),
            "the rotated-to record must be the healthy provider's real answer"
        );
    }

    // get_txt_records_with_pool on a single DoH server answering 200 / RCODE 0 / no Answer
    // must treat the authoritative empty as FINAL: Ok(vec![]) with no system-resolver
    // fallthrough (the recordless subdomain skips the extra UDP/system lookup entirely).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_pool_authoritative_empty_is_final() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 200, Status 0 (NOERROR), empty Answer — an authoritative "no TXT records".
        let body = build_doh_empty_response("authoritative-empty.example");
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "authoritative-empty.example"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_txt_records_with_pool("authoritative-empty.example", &pool)
            .await
            .expect("an authoritative empty (2xx / RCODE 0 / no Answer) must be Ok, not an error");

        assert!(
            records.is_empty(),
            "an authoritative empty answer is final and must return Ok(vec![]) — no records, \
             and (the DoH future resolving first) no system-resolver fallthrough"
        );
        // Prove the mock actually served this lookup: the total-failure fallback
        // path also yields Ok(vec![]), so without this assertion the test passes
        // even when the mock is never reached (demonstrated under a MITM proxy).
        let hits = server
            .received_requests()
            .await
            .expect("wiremock request recording enabled");
        assert!(
            !hits.is_empty(),
            "the DoH mock must have served the lookup — otherwise this exercised the \
             total-failure fallback, not the authoritative-empty short-circuit"
        );
    }

    // Config validation accepts "at least one DoH OR DNS server", so single-kind
    // pools are legal — the rotation helpers index with `% len` and previously
    // panicked (div-by-zero) on the empty side. These pin the no-panic guarantee.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_only_pool_no_dns_servers_does_not_panic() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = build_doh_txt_response("doh-only.example", &["v=spf1 include:vendor.test ~all"]);
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "doh-only.example"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let mut pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        pool.dns_servers.clear(); // legal DoH-only configuration

        let records = get_txt_records_with_pool("doh-only.example", &pool)
            .await
            .expect("a DoH-only pool must resolve without touching the (empty) DNS pool");
        assert_eq!(records.len(), 1, "the DoH answer must come through intact");
        assert!(records[0].contains("spf1"));
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_dns_only_pool_no_doh_servers_does_not_panic() {
        // DNS-only configuration: empty DoH pool, only the (unreachable) test
        // DNS fallback. The lookup must complete without panicking — result
        // content is environment-dependent (system resolver final fallback),
        // so the assertion is the absence of a panic plus a well-formed Ok.
        let mut pool = DnsServerPool::with_test_urls(vec!["http://127.0.0.1:1/dns-query".into()]);
        pool.doh_servers.clear(); // legal DNS-only configuration

        let result = get_txt_records_with_pool("dns-only-nonexistent.invalid", &pool).await;
        assert!(
            result.is_ok(),
            "an empty DoH pool must degrade gracefully, never index-panic: {result:?}"
        );
    }

    // ── Answer memo (scan-lifetime DNS deduplication) ────────────────────────────
    //
    // The memo's whole safety story is *what it refuses to remember*. A resolver's answer —
    // including an authoritative "no records" — is a fact about the zone and may be reused.
    // An empty vector produced because every resolution path failed is not; caching it would
    // convert one transient outage into a scan-wide false negative and would suppress the
    // `dns_failure_counter` increments that the exit-3 guard reads (GRC-367).

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn memo_serves_repeat_txt_query_without_a_second_request() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // `expect(1)` is the assertion: a second outbound request fails the test on drop.
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "memo.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(build_doh_txt_response("memo.com", &["v=spf1 -all"]))
                    .insert_header("content-type", "application/dns-json"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);

        let first = get_txt_records_with_rate_limit("memo.com", &pool, None, None)
            .await
            .expect("first lookup succeeds");
        let second = get_txt_records_with_rate_limit("memo.com", &pool, None, None)
            .await
            .expect("second lookup served from memo");

        assert_eq!(
            first, second,
            "memo must return the recorded answer verbatim"
        );
        assert_eq!(first.len(), 1);
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn memo_remembers_authoritative_empty_txt_answer() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // RCODE 0 with no Answer section: the name exists and genuinely has no TXT records.
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "norecords.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(build_doh_empty_response("norecords.com"))
                    .insert_header("content-type", "application/dns-json"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);

        let first = get_txt_records_with_rate_limit("norecords.com", &pool, None, None)
            .await
            .expect("authoritative empty is a successful lookup");
        assert!(first.is_empty());

        let second = get_txt_records_with_rate_limit("norecords.com", &pool, None, None)
            .await
            .expect("second lookup served from memo");
        assert!(second.is_empty(), "authoritative empty is reusable");
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn memo_never_caches_an_empty_result_produced_by_total_dns_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Every DoH attempt is a hard endpoint error, and the traditional/system resolvers
        // cannot answer this reserved-for-testing name either. The lookup therefore degrades
        // to `Ok(vec![])` while incrementing the failure counter.
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);

        let first =
            get_txt_records_with_rate_limit("invalid.invalid", &pool, None, Some(&counter)).await;
        let second =
            get_txt_records_with_rate_limit("invalid.invalid", &pool, None, Some(&counter)).await;

        assert!(
            first.is_ok() && second.is_ok(),
            "failures degrade, never panic"
        );
        assert!(first.unwrap().is_empty() && second.unwrap().is_empty());

        // The load-bearing assertion: the second call re-attempted resolution and re-counted
        // the failure. Had the degraded empty been memoized, this counter would read 1 and the
        // exit-3 guard would under-report DNS failures for every later lookup of this name.
        assert_eq!(
            counter.load(Ordering::Relaxed),
            2,
            "a failure-produced empty must not be memoized: each attempt must re-count"
        );
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn memo_keys_on_record_kind_so_txt_and_cname_do_not_collide() {
        let pool = DnsServerPool::with_test_urls(vec![]);

        pool.remember_answer(RecordKind::Txt, "collide.com", &["txt-answer".to_string()])
            .await;

        assert_eq!(
            pool.recall_answer(RecordKind::Txt, "collide.com").await,
            Some(vec!["txt-answer".to_string()])
        );
        assert_eq!(
            pool.recall_answer(RecordKind::Cname, "collide.com").await,
            None,
            "a TXT answer must never satisfy a CNAME query"
        );
    }
}
