use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

use crate::checkpoint;
use crate::cli::Args;
use crate::config::{AnalysisConfig, AnalysisStrategy};
use crate::discovery::ct_logs::CtDiscoveryResult;
use crate::discovery::saas_tenant::TenantProbeResult;
use crate::discovery::web_traffic::{WebTrafficResult, WebTrafficSource};
use crate::discovery::{
    CtLogDiscovery, SaasTenantDiscovery, SubfinderDiscovery, TenantStatus, WebTrafficDiscovery,
};
use crate::dns;
use crate::domain_utils;
use crate::logger::AnalysisLogger;
use crate::org_normalizer;
use crate::result_sink::ResultSink;
use crate::subprocessor;
use crate::vendor::{RecordType, VendorRelationship};
use crate::verification_logger;
use crate::whois;

use crate::checkpoint::Checkpoint;

/// Global flag for interrupt signaling - used to gracefully save checkpoint on Ctrl+C
static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_interrupted() {
    INTERRUPTED.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub fn is_interrupted() -> bool {
    INTERRUPTED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Scan-lifetime dedup memos for apex-scoped discovery methods (P1.5) and dispatch
/// singleflight (P1.1). Constructed once per scan and shared by reference through the
/// recursion, exactly like `subprocessor_attempted_orgs`. Every method is apex-scoped —
/// enumerating a registrable base's subdomains, or querying `%.<apex>` on a CT log, or
/// probing SaaS tenants named after the apex — so running it once per apex covers every
/// subdomain and every parent that reaches into that apex.
#[derive(Default)]
pub struct ScanDedup {
    /// Registrable bases whose subfinder enumeration has been claimed this scan.
    subfinder_apexes: Mutex<HashSet<String>>,
    /// Registrable bases whose CT-log query has been claimed this scan.
    ct_apexes: Mutex<HashSet<String>>,
    /// Registrable bases whose SaaS-tenant probe has been claimed this scan.
    saas_apexes: Mutex<HashSet<String>>,
    /// P1.4: per-base org-resolution singleflight. Concurrent discoverers of the same
    /// registrable base (the popular SaaS/CDN vendors appear under most parents at depth 2+)
    /// used to each run the full multi-second WHOIS→web→NER chain within the check-then-act
    /// window. A keyed OnceCell coalesces them: the first runs the chain, the rest await its
    /// result. The value is the FINAL normalized org string, so the coalesced result is
    /// byte-identical to a fresh resolution.
    org_cells: Mutex<HashMap<String, Arc<tokio::sync::OnceCell<String>>>>,
}

impl ScanDedup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim `apex` for `set`, returning true iff this is the first claim (so the caller
    /// should RUN the method). Later claims return false (skip — already covered).
    async fn claim(set: &Mutex<HashSet<String>>, apex: &str) -> bool {
        set.lock().await.insert(apex.to_string())
    }

    async fn claim_subfinder(&self, apex: &str) -> bool {
        Self::claim(&self.subfinder_apexes, apex).await
    }
    async fn claim_ct(&self, apex: &str) -> bool {
        Self::claim(&self.ct_apexes, apex).await
    }
    async fn claim_saas(&self, apex: &str) -> bool {
        Self::claim(&self.saas_apexes, apex).await
    }

    /// P1.4: resolve a base domain's org through `compute` exactly once per scan, coalescing
    /// concurrent callers. Returns the shared normalized org string. Counts a `whois.cache_hit`
    /// when the value was already resolved (the compute is not run).
    async fn resolve_org_once<F, Fut>(&self, base: &str, compute: F) -> String
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = String>,
    {
        let cell = {
            let mut cells = self.org_cells.lock().await;
            cells
                .entry(base.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::OnceCell::new()))
                .clone()
        };
        if cell.get().is_some() {
            crate::perf::METRICS.whois_cache_hit.hit();
        }
        cell.get_or_init(compute).await.clone()
    }
}

/// The absolute maximum recursion depth, regardless of user configuration.
pub const ABSOLUTE_MAX_DEPTH: u32 = 10;

/// The outcome of the depth-aware processed-domain gate (P1.3).
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessedGate {
    /// Already claimed at a shallower-or-equal depth — skip (a true duplicate reach).
    Skip,
    /// New, or reached strictly shallower than before — claim at this depth and proceed
    /// (re-expansion: the deeper first-crawl truncated the subtree and mislabeled layers).
    Claim,
    /// Not yet claimed but this depth exceeds the budget — do not claim, do not proceed
    /// (it may still be reached within budget via a shallower path later).
    DepthRefused,
}

/// Pure decision for the recursion gate. `existing_depth` is the min depth a domain was
/// previously claimed at (None if never). Depth-aware: a strictly shallower reach re-expands.
pub fn processed_gate_decision(
    existing_depth: Option<u32>,
    current_depth: u32,
    depth_allowed: bool,
) -> ProcessedGate {
    if let Some(claimed) = existing_depth {
        if current_depth >= claimed {
            return ProcessedGate::Skip;
        }
    }
    if depth_allowed {
        ProcessedGate::Claim
    } else {
        ProcessedGate::DepthRefused
    }
}

/// Check whether the current depth exceeds the allowed limits.
/// Returns `true` if analysis should proceed, `false` if it should be skipped.
pub fn is_depth_allowed(current_depth: u32, max_depth: Option<u32>) -> bool {
    if current_depth > ABSOLUTE_MAX_DEPTH {
        return false;
    }
    if let Some(max) = max_depth {
        if current_depth > max {
            return false;
        }
    }
    true
}

/// Deduplicate a list of `VendorDomain` entries by (base_domain, source_type, raw_record).
/// Returns (deduplicated list, number of duplicates removed).
pub fn dedup_vendor_domains(
    vendor_domains: Vec<dns::VendorDomain>,
) -> (Vec<dns::VendorDomain>, usize) {
    let pre_dedup_count = vendor_domains.len();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut deduped: Vec<dns::VendorDomain> = Vec::new();
    for vd in vendor_domains {
        let base = domain_utils::extract_base_domain(&vd.domain);
        let source_key = format!("{:?}", vd.source_type);
        let key = (base, source_key, vd.raw_record.clone());
        if seen.insert(key) {
            deduped.push(vd);
        }
    }
    let removed = pre_dedup_count - deduped.len();
    (deduped, removed)
}

/// Build the record_value string for a vendor relationship based on source type.
pub fn build_record_value(
    source_type: &RecordType,
    base_domain: &str,
    customer_domain: &str,
    raw_record: &str,
    vendor_domain: &str,
) -> String {
    match source_type {
        RecordType::DnsSubdomain => format!("{} (base of {})", base_domain, customer_domain),
        RecordType::DnsTxtVerification
        | RecordType::DnsTxtSpf
        | RecordType::DnsTxtDmarc
        | RecordType::DnsTxtDkim => raw_record.to_string(),
        _ => vendor_domain.to_string(),
    }
}

/// Map a RecordType to a short human-readable source label for progress display.
pub fn source_type_label(source_type: &RecordType) -> &'static str {
    match source_type {
        RecordType::HttpSubprocessor => "subprocessor",
        RecordType::DnsTxtSpf => "SPF",
        RecordType::DnsTxtVerification => "DNS verification",
        RecordType::DnsTxtDmarc => "DMARC",
        RecordType::SubfinderDiscovery => "subfinder",
        RecordType::SaasTenantProbe => "SaaS tenant",
        RecordType::CtLogDiscovery => "CT log",
        _ => "discovery",
    }
}

/// Truncate a string to at most `max_len` bytes, respecting UTF-8 char boundaries.
/// Appends "..." if truncation occurred.
pub fn truncate_utf8(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// Apply strategy-based vendor limits to a list of vendor domains.
/// Returns the (possibly truncated) list and the number of vendors removed.
pub fn apply_vendor_limits(
    mut vendor_domains: Vec<dns::VendorDomain>,
    strategy: &AnalysisStrategy,
    analysis_config: &AnalysisConfig,
    current_depth: u32,
) -> (Vec<dns::VendorDomain>, usize) {
    let original_count = vendor_domains.len();
    match strategy {
        AnalysisStrategy::Limits => {
            if let Some(max_vendors) =
                analysis_config.get_vendor_limit_for_depth(current_depth as usize)
            {
                if vendor_domains.len() > max_vendors {
                    vendor_domains.truncate(max_vendors);
                }
            }
        }
        AnalysisStrategy::Unlimited | AnalysisStrategy::Budget => {
            // No truncation for these strategies
        }
    }
    let removed = original_count - vendor_domains.len();
    (vendor_domains, removed)
}

pub fn is_common_denominator(domain: &str) -> bool {
    let common_denominators = vec![
        "amazon.com",
        "amazonaws.com",
        "microsoft.com",
        "google.com",
        "googletagmanager.com",
        "googlehosted.com",
        "googlesyndication.com",
        "googleadservices.com",
        "googleusercontent.com",
        "googleapis.com",
        "cloudflare.com",
        "cloudflare-dns.com",
        "fastly.com",
        "akamai.com",
        "azure.com",
        "office365.com",
        "outlook.com",
        "googlemail.com",
        "gmail.com",
    ];

    common_denominators
        .iter()
        .any(|&cd| domain == cd || domain.ends_with(&format!(".{}", cd)))
}

/// Social / ad-network / marketing-pixel domains that are the dominant
/// false-positive class when discovered via passive web-traffic scanning
/// (GRC-501). These are tracking/marketing endpoints, not data subprocessors,
/// so when they surface only because a page loads a pixel or SDK they should be
/// suppressed rather than counted.
///
/// NOTE: this classifier is intentionally source-agnostic. Callers MUST gate
/// suppression on the discovery source (web-traffic only) — a domain like
/// `facebook.com` that appears on a company's *published subprocessor page*
/// (`RecordType::HttpSubprocessor`) is a legitimately-disclosed relationship and
/// must NOT be suppressed. See `app::filter_marketing_tracking`.
pub fn is_marketing_tracking_domain(domain: &str) -> bool {
    let marketing_tracking = [
        // Meta / Facebook
        "facebook.com",
        "facebook.net",
        "fbcdn.net",
        "fbsbx.com",
        // LinkedIn
        "licdn.com",
        // Twitter / X advertising + click tracking
        "ads-twitter.com",
        "analytics.twitter.com",
        "t.co",
        // TikTok
        "tiktok.com",
        "tiktokcdn.com",
        "ttwstatic.com",
        // Reddit advertising / static
        "redditstatic.com",
        "redditmedia.com",
        // Snap
        "snapchat.com",
        "sc-static.net",
        // Google Marketing Platform / DoubleClick
        "doubleclick.net",
    ];

    marketing_tracking
        .iter()
        .any(|&m| domain == m || domain.ends_with(&format!(".{}", m)))
}

/// Groups of base domains that belong to the same organization. When a scan of
/// one member surfaces another member as a "vendor", it is really a
/// self-reference (alternate landing / marketing / registrar-of-record domain),
/// not a third party (GRC-501). Each inner slice is one organization's domain
/// family; membership is symmetric.
const KNOWN_SELF_ALIAS_GROUPS: &[&[&str]] = &[
    // Klaviyo: primary domain + hosted landing-page / alt domains
    &["klaviyo.com", "myklpages.com", "klaviyomail.com"],
    // MarkMonitor: corporate registrar + its registrar-of-record landing domain
    &["markmonitor.com", "saasbee.com"],
];

/// Whether `vendor_domain` and `customer_domain` resolve to the same
/// organization via a known alias group (GRC-501). Compared on base domains so
/// subdomains (e.g. `www.myklpages.com`) are handled. Returns false for an
/// exact base-domain match, which is already covered by the plain base check.
pub fn is_known_self_alias(vendor_domain: &str, customer_domain: &str) -> bool {
    let vendor_base = domain_utils::extract_base_domain(vendor_domain);
    let customer_base = domain_utils::extract_base_domain(customer_domain);
    if vendor_base == customer_base {
        return false;
    }
    KNOWN_SELF_ALIAS_GROUPS.iter().any(|group| {
        group.iter().any(|&d| d == vendor_base) && group.iter().any(|&d| d == customer_base)
    })
}

pub fn is_likely_inferred_org(domain: &str, org: &str) -> bool {
    let base = domain.split('.').next().unwrap_or(domain).to_lowercase();
    let org_lower = org.to_lowercase();

    if org_lower == format!("{} inc.", base) {
        return true;
    }
    if org_lower == base {
        return true;
    }
    if org_lower == domain.to_lowercase() {
        return true;
    }

    let common_inferred_patterns = [
        format!("{} inc", base),
        format!("{} inc.", base),
        format!("{}, inc", base),
        format!("{}, inc.", base),
        format!("{} llc", base),
        format!("{} corp", base),
        format!("{} corporation", base),
        format!("{} company", base),
        format!("{} co", base),
        format!("{} ltd", base),
    ];

    common_inferred_patterns.contains(&org_lower)
}

/// If domain is a subdomain (different from its base), return a VendorDomain entry for the base.
pub fn add_base_domain_if_subdomain(
    domain: &str,
    current_base_domain: &str,
) -> Option<dns::VendorDomain> {
    if current_base_domain != domain {
        Some(dns::VendorDomain {
            domain: current_base_domain.to_string(),
            source_type: RecordType::DnsSubdomain,
            raw_record: format!("Subdomain analysis: {} -> {}", domain, current_base_domain),
        })
    } else {
        None
    }
}

/// Convert SubprocessorDomain entries into VendorDomain entries (field mapping).
pub fn convert_subprocessor_domains(
    subprocessor_domains: Vec<subprocessor::SubprocessorDomain>,
) -> Vec<dns::VendorDomain> {
    subprocessor_domains
        .into_iter()
        .map(|sub_domain| dns::VendorDomain {
            domain: sub_domain.domain,
            source_type: sub_domain.source_type,
            raw_record: sub_domain.raw_record,
        })
        .collect()
}

/// Filter subfinder subdomain results: keep only vendors whose base domain differs from
/// the target domain_base. Returns (new vendor domains, txt_count, cname_count).
#[allow(clippy::type_complexity)]
pub fn filter_subfinder_results(
    subdomain_results: Vec<(
        String,
        String,
        Vec<dns::VendorDomain>,
        Vec<(String, String)>,
    )>,
    domain_base: &str,
) -> (Vec<dns::VendorDomain>, usize, usize) {
    let mut vendor_domains = Vec::new();
    let mut txt_count = 0;
    let mut cname_count = 0;

    for (subdomain, source, txt_vendors, cname_vendors) in subdomain_results {
        for vd in txt_vendors {
            let vd_base = domain_utils::extract_base_domain(&vd.domain);
            if vd_base != domain_base {
                txt_count += 1;
                vendor_domains.push(dns::VendorDomain {
                    domain: vd.domain,
                    source_type: vd.source_type,
                    raw_record: format!(
                        "Via subdomain {} (subfinder:{}): {}",
                        subdomain, source, vd.raw_record
                    ),
                });
            }
        }
        for (cname_target, cname_base) in cname_vendors {
            cname_count += 1;
            vendor_domains.push(dns::VendorDomain {
                domain: cname_base,
                source_type: RecordType::SubfinderDiscovery,
                raw_record: format!(
                    "Subdomain {} CNAMEs to {} (subfinder:{})",
                    subdomain, cname_target, source
                ),
            });
        }
    }

    (vendor_domains, txt_count, cname_count)
}

/// Filter tenant probe results to only Confirmed/Likely, converting to VendorDomain entries.
pub fn filter_confirmed_tenants(tenants: &[TenantProbeResult]) -> Vec<dns::VendorDomain> {
    tenants
        .iter()
        .filter(|t| matches!(t.status, TenantStatus::Confirmed | TenantStatus::Likely))
        .map(|tenant| dns::VendorDomain {
            domain: tenant.vendor_domain.clone(),
            source_type: RecordType::SaasTenantProbe,
            raw_record: format!(
                "Tenant URL: {} ({:?}) | {}",
                tenant.tenant_url, tenant.status, tenant.evidence
            ),
        })
        .collect()
}

/// Convert CT log discovery results into VendorDomain entries.
pub fn convert_ct_results(ct_results: Vec<CtDiscoveryResult>) -> Vec<dns::VendorDomain> {
    ct_results
        .into_iter()
        .map(|result| dns::VendorDomain {
            domain: result.domain,
            source_type: RecordType::CtLogDiscovery,
            raw_record: result.certificate_info,
        })
        .collect()
}

/// Convert web traffic analysis results into VendorDomain entries with source-type mapping.
pub fn convert_web_traffic_results(results: Vec<WebTrafficResult>) -> Vec<dns::VendorDomain> {
    results
        .into_iter()
        .map(|result| {
            let record_type = match result.source {
                WebTrafficSource::PageSource => RecordType::WebTrafficSource,
                WebTrafficSource::NetworkTraffic => RecordType::WebTrafficNetwork,
            };
            dns::VendorDomain {
                domain: result.vendor_domain,
                source_type: record_type,
                raw_record: result.evidence,
            }
        })
        .collect()
}

/// Compute stream buffer size from the depth's configured concurrency, optionally capped by
/// an operator-supplied `--parallel-jobs`, floored at 2.
///
/// `parallel_jobs == 0` means "no operator cap". Previously this argument defaulted to 10 and
/// was always min'd in, so `analysis.concurrency_per_depth` (50/20/10/5) could never take
/// effect unless the operator also passed a matching `-j` — every depth ran 10 wide. The
/// configured values are the intended widths; `-j` now only narrows them.
pub fn compute_buffer_size(configured_concurrency: usize, parallel_jobs: usize) -> usize {
    let capped = if parallel_jobs == 0 {
        configured_concurrency
    } else {
        configured_concurrency.min(parallel_jobs)
    };
    capped.max(2)
}

/// Compute progress bar position (30-100 range) given current index and total vendors.
pub fn compute_progress_position(index: usize, total_vendors: usize) -> u64 {
    30 + ((index as u64 + 1) * 70) / total_vendors as u64
}

/// Determine whether a periodic checkpoint should be saved.
pub fn should_checkpoint(processed_count: usize, vendor_count: usize) -> bool {
    processed_count.is_multiple_of(5) || processed_count == vendor_count
}

/// P3.4: minimum wall-clock gap between periodic checkpoint saves.
///
/// The every-5-completions cadence was chosen when a scan meant tens of domains. At depth 3 the
/// driver completes thousands, so "every 5" fired constantly — and each firing serializes the whole
/// depth-1 pipeline behind an fsync (see [`should_checkpoint_now`]). Thirty seconds bounds the
/// re-work a crash can cost to one interval while making the save rare enough that its cost stops
/// mattering.
pub const CHECKPOINT_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// P3.4: whether to save a periodic checkpoint *now*, given how long it has been since the last one.
///
/// Debouncing by TIME rather than by completion count is what makes the save affordable: a
/// checkpoint clones the entire `discovered_vendors` + `processed_domains` maps under their mutexes
/// and then fsyncs, and those are the same mutexes every concurrent org resolution needs. Firing
/// that every 5 completions turned a durability mechanism into the pipeline's own contention source.
///
/// The final completion (`processed_count == vendor_count`) always saves regardless of the interval:
/// that is the checkpoint a resumed scan actually reads, so skipping it to honour a debounce would
/// trade real resume fidelity for nothing.
pub fn should_checkpoint_now(
    processed_count: usize,
    vendor_count: usize,
    since_last_save: Duration,
    min_interval: Duration,
) -> bool {
    if vendor_count > 0 && processed_count == vendor_count {
        return true;
    }
    since_last_save >= min_interval
}

/// Map memory pressure level to a delay in milliseconds.
pub fn compute_pressure_delay_ms(pressure_level: u8) -> u64 {
    if pressure_level >= 2 {
        250
    } else if pressure_level >= 1 {
        25
    } else {
        0
    }
}

/// Check whether a vendor domain is a self-reference to the customer domain.
pub fn should_skip_self_reference(vendor_domain: &str, customer_domain: &str) -> bool {
    let base_domain = domain_utils::extract_base_domain(vendor_domain);
    let customer_base_domain = domain_utils::extract_base_domain(customer_domain);
    base_domain == customer_base_domain || is_known_self_alias(vendor_domain, customer_domain)
}

/// Resolve organization names from the discovered vendors map with domain fallback.
pub fn resolve_orgs_from_vendors(
    discovered_vendors: &HashMap<String, String>,
    customer_base_domain: &str,
    base_domain: &str,
) -> (String, String) {
    let customer_org = discovered_vendors
        .get(customer_base_domain)
        .cloned()
        .unwrap_or_else(|| customer_base_domain.to_string());
    let vendor_org = discovered_vendors
        .get(base_domain)
        .cloned()
        .unwrap_or_else(|| base_domain.to_string());
    (customer_org, vendor_org)
}

/// Check whether recursion should stop at a common denominator domain.
pub fn should_stop_at_common_denominator(max_depth: Option<u32>, base_domain: &str) -> bool {
    max_depth.is_none() && is_common_denominator(base_domain)
}

/// P4.8: whether to GATE (skip) subdomain/CT *enumeration* for a domain at this recursion depth
/// because it is a common-denominator infrastructure/CMS root (AWS, Cloudflare, wordpress.org-
/// class). Such a root's thousands of subdomains are the platform's own sprawl, not the customer's
/// nth-parties — enumerating them is the dominant deep-scan cost (single infra apexes fanned out to
/// 5,000–10,000 subdomains in the 2026-08-15 validation scan; 279k subdomains, 9.15h wall) for
/// near-zero attribution value.
///
/// This gates only the ENUMERATION fan-out, not the relationship: the parent→infra edge was
/// already recorded before this domain is processed, so the infra root stays a leaf edge (recall of
/// the relationship preserved). Only going *deeper through* the infra root is stopped — exactly
/// what `should_stop_at_common_denominator` does for unbounded scans, extended to bounded (max-
/// depth-set) scans where it currently does nothing. Never gates depth 1 (the scan root itself is
/// always fully enumerated); the roadmap scopes the gate to depth ≥2, where a discovered vendor
/// that happens to be infra would otherwise explode the frontier.
pub fn should_gate_infra_enumeration(current_depth: u32, base_domain: &str) -> bool {
    current_depth >= 2 && is_common_denominator(base_domain)
}

/// P3.6: the whole-domain working-time ceiling.
///
/// Every discovery method already carries its own budget (subprocessor 20s of working time,
/// CT 30s, web traffic 15s, SaaS 10s per probe, subfinder 300s), but none of them compose: a
/// domain that is slow on *several* methods pays their sum, and the serial preamble — TXT, the
/// `_dmarc` probe, the recursive SPF chain — and the org-resolution chain sit on top of that
/// sum. The 2026-08-15 depth-3 validation scan measured a 93s worst case for a single origin
/// this way, with no mechanism anywhere that could see the total.
///
/// **The 90s value this started at was falsified in the field and must not be restored without new
/// measurement.** The reasoning behind it — "a healthy-but-slow domain spends ~45s, so 90s clips
/// only the 93s-class tail" — modelled the ceiling against per-method budgets in isolation. The
/// 2026-08-17 depth-3 validation scan measured what actually happens: **1,608 cuts across 559
/// domains** (the ceiling wraps each phase of the join, so it fires per phase, not per domain),
/// which starved web-traffic on 509 of 559 domains and collapsed the scan from 22,482 relationships
/// to 2,564. It was not clipping a tail; it had become the primary control.
///
/// The gap between model and reality is queueing the clock cannot see: `permit_wait` averaged 155s
/// per browser acquisition on that same scan, and only the waits this clock is told about are
/// subtracted. So "working time" as measured here still contains queueing, and a 90s bound trips on
/// the body of the distribution rather than its tail.
///
/// 600s restores this to what it was always meant to be: a backstop against the genuinely unbounded
/// case (before P3.6 there was no whole-domain ceiling at all), sitting far enough above legitimate
/// per-domain work that tripping it is evidence of a pathology rather than of a deep scan. Re-tuning
/// it downward is a measurement exercise — watch `domain.budget_cut` against the relationship count
/// on a full depth-3 scan — not a judgement call (TF-DOMAIN-CEILING-SIZING).
pub const DOMAIN_WORK_CEILING: Duration = Duration::from_secs(600);

/// P3.6: how long the [`await_work_deadline`] watchdog waits before re-reading the clock when
/// the remaining budget rounds to almost nothing. Without a floor, a domain whose queue time is
/// growing at wall-clock rate (every permit taken, nothing progressing) would re-arm a
/// zero-length timer in a tight loop.
const WORK_DEADLINE_MIN_TICK: Duration = Duration::from_millis(50);

/// P3.6: a single domain's working-time clock — wall time minus the time it spent *queued*.
///
/// The distinction is the whole point. `browser.permit_wait` averaged 201.6s across 1,113
/// acquisitions on the 2026-08-15 depth-3 scan, so a budget measured on the wall clock reports
/// how contended the scan is, not how much work the domain did: recall would quietly collapse
/// on exactly the busy scans where it matters, and identically-configured runs would diverge.
/// `subprocessor::analyze_domain_with_full_options` already subtracts its `browser_wait_nanos`
/// for this reason; this is the same contract raised from one method to the whole domain.
///
/// What it credits today is the P3.1 admission permit — the one queue this layer can see and
/// measure. A render blocked on `browser_pool`'s permits is invisible from here, so the ceiling is
/// deliberately set far above any single method's own budget rather than pretending to a precision
/// it does not have; each render-using method already subtracts its own browser wait one layer
/// down. Any further queue this file learns to observe is one `credit_queue` call away, and
/// [`await_work_deadline`] re-reads the clock so a late credit extends the deadline rather than
/// being spent by it.
pub struct DomainWorkClock {
    started: std::time::Instant,
    queued_nanos: std::sync::atomic::AtomicU64,
}

impl DomainWorkClock {
    /// Start a clock for one domain's unit of work.
    pub fn start() -> Self {
        Self {
            started: std::time::Instant::now(),
            queued_nanos: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Credit time this domain spent waiting in a queue rather than working. Mirrors
    /// `subprocessor::credit_browser_wait`.
    ///
    /// Saturating, not wrapping: a wrapped total would read as *near-zero* queue time and
    /// would therefore make the ceiling fire early on precisely the most-starved domain — the
    /// opposite of what the subtraction exists to do.
    pub fn credit_queue(&self, waited: Duration) {
        let nanos = u64::try_from(waited.as_nanos()).unwrap_or(u64::MAX);
        let _ = self.queued_nanos.fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |current| Some(current.saturating_add(nanos)),
        );
    }

    /// Wall time since the unit started.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Queue time credited so far, which the ceiling subtracts from [`Self::elapsed`].
    pub fn queued(&self) -> Duration {
        Duration::from_nanos(self.queued_nanos.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn decide(&self, current_depth: u32, ceiling: Duration) -> DomainCeiling {
        domain_ceiling_decision(current_depth, self.elapsed(), self.queued(), ceiling)
    }
}

/// P3.6: the outcome of the whole-domain ceiling.
#[derive(Debug, PartialEq, Eq)]
pub enum DomainCeiling {
    /// The ceiling does not apply to this unit — the scan root's own layer, or a ceiling the
    /// operator has disabled. Nothing is ever cut.
    Exempt,
    /// Inside the budget; the wrapped value is the working time still available.
    Within(Duration),
    /// The budget is spent. Methods still running are cut, classified and counted; methods that
    /// already answered keep everything they returned.
    Exhausted,
}

/// P3.6: pure decision for the whole-domain ceiling.
///
/// Depth 1 is exempt for the same reason `should_gate_infra_enumeration` never gates it and
/// `subprocessor_skip_decision` never skips it: the scan root is the one domain whose
/// enumeration the entire report is built on, and it is also the run that most legitimately
/// takes minutes (subfinder against a large apex). Truncating it to save time on the tail would
/// trade the headline result for the thing the ceiling exists to protect.
pub fn domain_ceiling_decision(
    current_depth: u32,
    elapsed: Duration,
    queued: Duration,
    ceiling: Duration,
) -> DomainCeiling {
    if ceiling.is_zero() || current_depth <= 1 {
        return DomainCeiling::Exempt;
    }
    // Saturating: a clock can be credited more queue time than has elapsed (two waits recorded
    // from concurrent sub-steps), and that must read as "all of it was queue", never as a
    // negative that panics or wraps into a huge budget.
    let working = elapsed.saturating_sub(queued);
    match ceiling.checked_sub(working) {
        Some(remaining) if !remaining.is_zero() => DomainCeiling::Within(remaining),
        _ => DomainCeiling::Exhausted,
    }
}

// coverage(off): thin logging wrapper over SubprocessorAnalyzer::analyze_domain_with_logging
// which performs real HTTP requests and browser scraping; branch outcomes depend on external
// service responses. Branches: non-empty result (lines 221-228), empty result (229-235),
// error (238-247) — all determined by network I/O.
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn subprocessor_analysis_with_logging(
    domain: &str,
    verification_logger: &verification_logger::VerificationFailureLogger,
    logger: Arc<AnalysisLogger>,
    analyzer: &subprocessor::SubprocessorAnalyzer,
) -> Result<Vec<subprocessor::SubprocessorDomain>> {
    logger.debug(&format!(
        "🌐 Starting subprocessor analysis for domain: {}",
        domain
    ));
    let start_time = std::time::Instant::now();

    match analyzer
        .analyze_domain_with_logging(domain, Some(verification_logger), Some(&logger))
        .await
    {
        Ok(subprocessors) => {
            let elapsed = start_time.elapsed();
            if !subprocessors.is_empty() {
                logger.debug(&format!(
                    "✅ Subprocessor analysis for {} found {} unique vendors in {:.2}s: {:?}",
                    domain,
                    subprocessors.len(),
                    elapsed.as_secs_f64(),
                    subprocessors.iter().map(|s| &s.domain).collect::<Vec<_>>()
                ));
            } else {
                logger.debug(&format!(
                    "✅ Subprocessor analysis for {} completed in {:.2}s (no vendors found)",
                    domain,
                    elapsed.as_secs_f64()
                ));
            }
            Ok(subprocessors)
        }
        Err(e) => {
            let elapsed = start_time.elapsed();
            logger.debug(&format!(
                "❌ Subprocessor analysis failed for {} in {:.2}s: {}",
                domain,
                elapsed.as_secs_f64(),
                e
            ));
            // Record the failure so the scan summary can tell "ran but errored" apart from "ran and
            // found nothing" — the analyzer's Err would otherwise be laundered into an empty Vec and
            // vanish (the RC-5 silent-failure hole). The Vec stays empty (nothing to merge); the
            // degradation now lives in SCAN_COVERAGE instead of being lost.
            crate::coverage::SCAN_COVERAGE.subprocessor.record_failure();
            Ok(Vec::new())
        }
    }
}

// ── Independent discovery phases (run concurrently at depth 1) ──
// Each returns the vendor domains it found. They hit different sources (subprocessor
// pages, subfinder, SaaS tenants, CT logs, live page traffic) and share no mutable
// state, so they are safe to run together with tokio::join! — collapsing the previously
// serial ~70s root-discovery chain to roughly its slowest single phase. Discovery logic
// is byte-for-byte the same as the old sequential code (same inputs, same outputs), so
// recall is unchanged; only the orchestration is parallel.

/// Decide whether to skip the (expensive, browser-rendered) subprocessor phase for a
/// domain because another domain of the same organization has already been analyzed.
///
/// `org` is the domain's resolved organization (from `discovered_vendors`); `None` means
/// we don't know it yet. In order:
/// - unknown org, or an implausible one (a placeholder / privacy redaction / domain echo,
///   per `is_plausible_org_name`) → never skip (fail toward recall; this also prevents a
///   shared placeholder like "Redacted for Privacy" from mass-colliding real vendors).
/// - first time this normalized org is seen → claim it (insert) and run.
/// - already claimed, and this is not a depth-1 direct vendor → skip.
/// - already claimed but `current_depth == 1` → still run (direct vendors always get full
///   recall; the root layer is never skipped).
///
/// The reported waste (slack.design/slack.dev/… discovered *below* slack.com) is caught
/// because the primary is processed at a shallower depth and claims the org first.
fn subprocessor_skip_decision(
    org: Option<&str>,
    current_depth: u32,
    attempted_orgs: &mut HashMap<String, u32>,
) -> bool {
    let Some(org) = org else {
        return false;
    };
    if !org_normalizer::is_plausible_org_name(org) {
        return false;
    }
    // Lowercase the normalized name so case-variants (PostHog / Posthog) share one key,
    // independent of whether the org normalizer singleton is initialized.
    let key = org_normalizer::normalize(org).trim().to_lowercase();
    // Never dedup on an empty key or a generic placeholder — those are shared by many
    // unrelated domains and would mass-collide real vendors into a single skip.
    if key.is_empty()
        || matches!(
            key.as_str(),
            "unknown" | "n/a" | "none" | "private" | "redacted" | "redacted for privacy"
        )
    {
        return false;
    }
    // P4.7: the claim carries the depth it was made at. Because the traversal is a concurrent
    // DFS, a deep satellite (slack.design at depth 3) could claim an org before its shallower
    // PRIMARY (slack.com at depth 2), suppressing the primary's subprocessor page — the tool's
    // highest-evidence source. A strictly shallower reach therefore re-claims and RUNS.
    match attempted_orgs.get(&key).copied() {
        None => {
            attempted_orgs.insert(key, current_depth);
            false
        }
        Some(claimed_depth) => {
            if current_depth < claimed_depth {
                // Shallower than the existing claim (includes a depth-1 primary arriving after
                // a deep satellite) → the shallower domain is authoritative; re-claim and run.
                attempted_orgs.insert(key, current_depth);
                false
            } else if current_depth == 1 {
                // Depth-1 direct vendors always run — the root layer is never suppressed.
                false
            } else {
                // Already covered at a shallower-or-equal depth → skip the redundant lookup.
                true
            }
        }
    }
}

// coverage(off): live subprocessor-page I/O — orchestration only.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_subprocessor_phase(
    domain: &str,
    analyzer: Option<&Arc<subprocessor::SubprocessorAnalyzer>>,
    enabled: bool,
    verification_logger: &verification_logger::VerificationFailureLogger,
    logger: &Arc<AnalysisLogger>,
) -> Vec<dns::VendorDomain> {
    let Some(analyzer) = analyzer.filter(|_| enabled) else {
        return Vec::new();
    };
    logger.debug(&format!(
        "Starting subprocessor web page analysis for {}",
        domain
    ));
    match subprocessor_analysis_with_logging(domain, verification_logger, logger.clone(), analyzer)
        .await
    {
        Ok(subprocessor_domains) if !subprocessor_domains.is_empty() => {
            logger.log_subprocessor_analysis(domain, subprocessor_domains.len());
            crate::coverage::SCAN_COVERAGE
                .subprocessor
                .record_found(subprocessor_domains.len());
            convert_subprocessor_domains(subprocessor_domains)
        }
        Ok(_) => {
            logger.log_subprocessor_analysis(domain, 0);
            Vec::new()
        }
        Err(e) => {
            logger.warn(&format!(
                "Subprocessor analysis failed for {}: {}",
                domain, e
            ));
            crate::coverage::SCAN_COVERAGE.subprocessor.record_failure();
            Vec::new()
        }
    }
}

// coverage(off): subfinder subprocess + DNS I/O — orchestration only.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_subfinder_phase(
    domain: &str,
    subdomain_discovery: Option<&SubfinderDiscovery>,
    dns_pool: &Arc<dns::DnsServerPool>,
    logger: &Arc<AnalysisLogger>,
) -> Vec<dns::VendorDomain> {
    let Some(subfinder) = subdomain_discovery else {
        return Vec::new();
    };
    logger.info(&format!(
        "Running subdomain discovery via subfinder for {}...",
        domain
    ));
    let sf_start = std::time::Instant::now();
    let subdomains = match subfinder.discover(domain).await {
        Ok(s) => s,
        Err(e) => {
            logger.warn(&format!("Subdomain discovery failed for {}: {}", domain, e));
            crate::coverage::SCAN_COVERAGE.subfinder.record_failure();
            return Vec::new();
        }
    };
    let sf_subprocess_elapsed = sf_start.elapsed();
    if subdomains.is_empty() {
        logger.debug(&format!("Subfinder found no subdomains for {}", domain));
        return Vec::new();
    }
    logger.info(&format!(
        "Subfinder found {} subdomains for {}",
        subdomains.len(),
        domain
    ));

    use futures::{stream, StreamExt};
    let subdomain_concurrency = 50;
    let dns_fanout_start = std::time::Instant::now();
    let domain_base = domain_utils::extract_base_domain(domain);
    let subdomain_results: Vec<_> = stream::iter(subdomains.iter().map(|sub| {
        let subdomain = sub.subdomain.clone();
        let source = sub.source.clone();
        let dns_pool = dns_pool.clone();
        let domain_base = domain_base.clone();
        let logger_sub = logger.clone();
        async move {
            let (txt_records, cname_records) = dns_pool
                .get_txt_and_cname_fast(&subdomain, logger_sub.dns_failure_counter())
                .await;
            let mut txt_vendors = Vec::new();
            let mut cname_vendors = Vec::new();
            if !txt_records.is_empty() {
                txt_vendors = dns::extract_vendor_domains_with_source(&txt_records);
            }
            for cname in &cname_records {
                let cname_base = domain_utils::extract_base_domain(cname);
                if cname_base != domain_base {
                    cname_vendors.push((cname.clone(), cname_base));
                }
            }
            (subdomain, source, txt_vendors, cname_vendors)
        }
    }))
    .buffer_unordered(subdomain_concurrency)
    .collect()
    .await;
    // PERF: decompose the subfinder phase into its two sequential halves so the bottleneck is
    // legible — the subfinder subprocess vs the per-subdomain DNS fan-out (both candidates for
    // pipelining if each is large). INFO-level, so only `-v` surfaces it.
    tracing::info!(
        "subfinder phase split for {}: subprocess {:.1}s, subdomain-DNS fan-out {:.1}s ({} subdomains)",
        domain,
        sf_subprocess_elapsed.as_secs_f64(),
        dns_fanout_start.elapsed().as_secs_f64(),
        subdomains.len()
    );

    let (new_vendor_domains, txt_found, cname_found) =
        filter_subfinder_results(subdomain_results, &domain_base);
    if txt_found > 0 || cname_found > 0 {
        logger.info(&format!(
            "Found {} vendors from subdomain TXT records, {} from CNAME infrastructure for {}",
            txt_found, cname_found, domain
        ));
    }
    crate::coverage::SCAN_COVERAGE
        .subfinder
        .record_found(new_vendor_domains.len());
    new_vendor_domains
}

// coverage(off): SaaS-tenant probe I/O — orchestration only.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_saas_phase(
    domain: &str,
    saas_tenant_discovery: Option<&SaasTenantDiscovery>,
    logger: &Arc<AnalysisLogger>,
) -> Vec<dns::VendorDomain> {
    let Some(tenant_disc) = saas_tenant_discovery else {
        return Vec::new();
    };
    // P1.8: gate SaaS probing to apex inputs. Tenant names derive from the registrable
    // base, so probing a subdomain (`www.vanta.com`) issues the identical ~245-probe matrix
    // as its apex (`vanta.com`), which is ALWAYS separately queued for subdomains
    // (add_base_domain_if_subdomain). Skipping the subdomain removes the duplicate matrix
    // at zero recall cost — the apex runs the full pass.
    let base_domain = crate::domain_utils::extract_base_domain(domain);
    if base_domain != domain {
        crate::perf::METRICS.saas_apex_skip.hit();
        logger.debug(&format!(
            "Skipping SaaS phase for subdomain {} — apex {} carries the probe",
            domain, base_domain
        ));
        return Vec::new();
    }
    logger.info(&format!("Running SaaS tenant discovery for {}...", domain));
    match tenant_disc.probe_with_logger(domain, Some(logger)).await {
        Ok(tenants) => {
            let tenant_vendors = filter_confirmed_tenants(&tenants);
            if !tenant_vendors.is_empty() {
                logger.info(&format!(
                    "Found {} likely/confirmed SaaS tenants for {}",
                    tenant_vendors.len(),
                    domain
                ));
            }
            crate::coverage::SCAN_COVERAGE
                .saas
                .record_found(tenant_vendors.len());
            tenant_vendors
        }
        Err(e) => {
            logger.warn(&format!(
                "SaaS tenant discovery failed for {}: {}",
                domain, e
            ));
            crate::coverage::SCAN_COVERAGE.saas.record_failure();
            Vec::new()
        }
    }
}

// coverage(off): CT-log HTTP I/O — orchestration only.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_ct_phase(
    domain: &str,
    ct_discovery: Option<&CtLogDiscovery>,
    logger: &Arc<AnalysisLogger>,
) -> Vec<dns::VendorDomain> {
    let Some(ct_disc) = ct_discovery else {
        return Vec::new();
    };
    logger.info(&format!(
        "Running Certificate Transparency log discovery for {}...",
        domain
    ));
    match ct_disc.discover(domain).await {
        Ok(ct_results) if !ct_results.is_empty() => {
            logger.info(&format!(
                "Found {} vendors from CT logs for {}",
                ct_results.len(),
                domain
            ));
            crate::coverage::SCAN_COVERAGE
                .ct
                .record_found(ct_results.len());
            convert_ct_results(ct_results)
        }
        Ok(_) => Vec::new(),
        Err(e) => {
            logger.warn(&format!("CT log discovery failed for {}: {}", domain, e));
            crate::coverage::SCAN_COVERAGE.ct.record_failure();
            Vec::new()
        }
    }
}

// coverage(off): headless-browser web-traffic I/O — orchestration only.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_webtraffic_phase(
    domain: &str,
    web_traffic_discovery: Option<&WebTrafficDiscovery>,
    logger: &Arc<AnalysisLogger>,
) -> Vec<dns::VendorDomain> {
    let Some(web_traffic_disc) = web_traffic_discovery else {
        return Vec::new();
    };
    logger.info(&format!(
        "Running webpage source & network request discovery for {}...",
        domain
    ));
    let web_traffic_results = web_traffic_disc.analyze_domain(domain).await;
    if web_traffic_results.is_empty() {
        logger.debug(&format!(
            "No vendors discovered from webpage analysis for {}",
            domain
        ));
        return Vec::new();
    }
    logger.info(&format!(
        "Found {} vendors from webpage analysis for {}",
        web_traffic_results.len(),
        domain
    ));
    crate::coverage::SCAN_COVERAGE
        .webtraffic
        .record_found(web_traffic_results.len());
    convert_web_traffic_results(web_traffic_results)
}

/// P3.6: resolve once the domain's *working* budget is spent.
///
/// Re-reads the clock each pass rather than arming one absolute deadline, so queue time credited
/// while the watchdog waits pushes the deadline out instead of being spent by it. That is what
/// keeps the ceiling a measure of work: an absolute deadline computed up front would degrade back
/// into a wall clock the moment the domain started queueing. Nothing credits the clock mid-join
/// today, so this normally costs exactly one sleep — the loop is what makes it stay correct when
/// something does.
async fn await_work_deadline(clock: &DomainWorkClock, current_depth: u32, ceiling: Duration) {
    loop {
        match clock.decide(current_depth, ceiling) {
            DomainCeiling::Within(remaining) => {
                tokio::time::sleep(remaining.max(WORK_DEADLINE_MIN_TICK)).await;
            }
            // Unreachable from the join (an exempt unit is given no budget at all), but resolve
            // to "never fire" rather than "fire now" so a future caller that hands this an exempt
            // depth cannot silently truncate the scan root.
            DomainCeiling::Exempt => std::future::pending::<()>().await,
            DomainCeiling::Exhausted => return,
        }
    }
}

/// P3.6: run one discovery phase under the domain's shared ceiling.
///
/// All five arms of the join race the SAME clock, so this is one whole-domain ceiling rather than
/// five per-method ones — but each arm is cut independently, so a method that already answered
/// keeps every vendor it found. Cutting the join as a unit (a `timeout` around `tokio::join!`)
/// would have discarded the finished arms' results too, converting a slow domain into an empty one.
///
/// `biased` is load-bearing: the phase is polled first, so a disabled method (which returns an
/// empty Vec on its first poll) always wins the race and is never reported as starved, and a phase
/// that completes in the same wakeup as the deadline is counted as a result rather than a cut.
///
/// A cut drops the phase future, which cancels it. That is safe for every arm: the subfinder child
/// is spawned with `kill_on_drop(true)` and deregistered from the PID registry on drop, and the
/// render sites move their browser permit *into* `spawn_blocking`, so the blocking task runs to
/// completion and drops its `TabGuard` normally rather than orphaning Chrome.
async fn phase_within_domain_budget<F>(
    phase: F,
    budget: Option<(&DomainWorkClock, u32, Duration)>,
    coverage: &crate::coverage::PhaseCoverage,
    method: &str,
    domain: &str,
    logger: &Arc<AnalysisLogger>,
) -> Vec<dns::VendorDomain>
where
    F: std::future::Future<Output = Vec<dns::VendorDomain>>,
{
    let Some((clock, current_depth, ceiling)) = budget else {
        return phase.await;
    };
    tokio::select! {
        biased;
        found = phase => found,
        _ = await_work_deadline(clock, current_depth, ceiling) => {
            crate::perf::METRICS.domain_budget_cut.hit();
            // Classified, not silently truncated. `record_failure` is the same call every phase
            // error path makes, and it is the difference that matters here: an empty Vec from a
            // cut phase is byte-identical to "this domain genuinely has nothing", and without
            // this the scan summary would print SUCCESS over the loss — the RC-1 collapse that
            // cost chargify.com all 28 of its rows while the scan-wide total went UP.
            coverage.record_failure();
            let queued = clock.queued();
            logger.warn(&format!(
                "DOMAIN_BUDGET_EXHAUSTED: cut {} discovery for {} after {:.1}s of working time \
                 ({:.1}s queued for permits, excluded) — this method was starved, not empty. \
                 The domain's other methods keep everything they already returned.",
                method,
                domain,
                clock.elapsed().saturating_sub(queued).as_secs_f64(),
                queued.as_secs_f64(),
            ));
            Vec::new()
        }
    }
}

// coverage(off): argument-forwarding shell — starts the scan root's P3.6 clock and delegates.
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::too_many_arguments)]
pub async fn discover_nth_parties(
    domain: &str,
    max_depth: Option<u32>,
    discovered_vendors: Arc<Mutex<HashMap<String, String>>>,
    processed_domains: Arc<Mutex<HashMap<String, u32>>>,
    subprocessor_attempted_orgs: Arc<Mutex<HashMap<String, u32>>>,
    scan_dedup: Arc<ScanDedup>,
    semaphore: Arc<Semaphore>,
    current_depth: u32,
    root_customer_domain: &str,
    root_customer_organization: &str,
    verification_logger: &verification_logger::VerificationFailureLogger,
    dns_pool: Arc<dns::DnsServerPool>,
    recursive_semaphore: Arc<Semaphore>,
    args: &Args,
    logger: Arc<AnalysisLogger>,
    subprocessor_analyzer: Option<&Arc<subprocessor::SubprocessorAnalyzer>>,
    subprocessor_enabled: bool,
    web_org_enabled: bool,
    web_org_min_confidence: f32,
    analysis_config: &AnalysisConfig,
    subdomain_discovery: Option<&SubfinderDiscovery>,
    saas_tenant_discovery: Option<&SaasTenantDiscovery>,
    ct_discovery: Option<&CtLogDiscovery>,
    web_traffic_discovery: Option<&WebTrafficDiscovery>,
    checkpoint: Arc<Mutex<Checkpoint>>,
    checkpoint_output_dir: &str,
    result_sink: Arc<Mutex<ResultSink>>,
    memory_pressure_level: Arc<std::sync::atomic::AtomicU8>,
) -> Result<()> {
    // P3.6: the scan entry point owns a fresh clock. Every other caller reaches the body through
    // `process_vendor_domain`, which starts its clock *before* acquiring the admission permit so
    // the wait for that permit is credited as queue rather than charged as work.
    let clock = DomainWorkClock::start();
    discover_nth_parties_with_clock(
        &clock,
        domain,
        max_depth,
        discovered_vendors,
        processed_domains,
        subprocessor_attempted_orgs,
        scan_dedup,
        semaphore,
        current_depth,
        root_customer_domain,
        root_customer_organization,
        verification_logger,
        dns_pool,
        recursive_semaphore,
        args,
        logger,
        subprocessor_analyzer,
        subprocessor_enabled,
        web_org_enabled,
        web_org_min_confidence,
        analysis_config,
        subdomain_discovery,
        saas_tenant_discovery,
        ct_discovery,
        web_traffic_discovery,
        checkpoint,
        checkpoint_output_dir,
        result_sink,
        memory_pressure_level,
    )
    .await
}

/// The body of [`discover_nth_parties`], carrying the caller's P3.6 work clock.
///
/// Split out rather than adding a parameter to the public entry point so the whole-domain ceiling
/// can span BOTH halves of one vendor unit — the org resolution in `process_vendor_domain` and the
/// discovery join here — without a signature change rippling into `app.rs`. The clock stops being
/// consulted once the per-vendor fan-out starts: each child begins its own unit, so the ceiling
/// bounds one domain's own methods and never the subtree beneath it.
// coverage(off): I/O-only orchestration shell after DI extraction. All pure logic extracted to:
// add_base_domain_if_subdomain, convert_subprocessor_domains, filter_subfinder_results,
// filter_confirmed_tenants, convert_ct_results, convert_web_traffic_results,
// compute_buffer_size, compute_progress_position, should_checkpoint, compute_pressure_delay_ms,
// domain_ceiling_decision. Remaining code is: DNS-over-HTTPS calls, subfinder/SaaS/CT/web I/O,
// checkpoint file writes, tokio mutex locks, and progress logger calls — no testable branching.
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::too_many_arguments)]
async fn discover_nth_parties_with_clock(
    clock: &DomainWorkClock,
    domain: &str,
    max_depth: Option<u32>,
    discovered_vendors: Arc<Mutex<HashMap<String, String>>>,
    // P1.3: domain -> the MINIMUM recursion depth at which it has been claimed. A depth-aware
    // gate: a domain first reached deep is re-expanded when later reached shallower (else its
    // subtree keeps inflated layers and its within-budget grandchildren are never discovered).
    processed_domains: Arc<Mutex<HashMap<String, u32>>>,
    // Normalized org names whose subprocessor page has already been sought, so we don't
    // re-run the expensive browser-rendered subprocessor lookup on secondary/tertiary
    // domains of an org we already analyzed (slack.com then slack.design/slack.dev/…).
    subprocessor_attempted_orgs: Arc<Mutex<HashMap<String, u32>>>,
    // Scan-lifetime apex memos for subfinder/CT/SaaS dedup (P1.5).
    scan_dedup: Arc<ScanDedup>,
    semaphore: Arc<Semaphore>,
    current_depth: u32,
    root_customer_domain: &str,
    root_customer_organization: &str,
    verification_logger: &verification_logger::VerificationFailureLogger,
    dns_pool: Arc<dns::DnsServerPool>,
    recursive_semaphore: Arc<Semaphore>,
    args: &Args,
    logger: Arc<AnalysisLogger>,
    subprocessor_analyzer: Option<&Arc<subprocessor::SubprocessorAnalyzer>>,
    subprocessor_enabled: bool,
    web_org_enabled: bool,
    web_org_min_confidence: f32,
    analysis_config: &AnalysisConfig,
    subdomain_discovery: Option<&SubfinderDiscovery>,
    saas_tenant_discovery: Option<&SaasTenantDiscovery>,
    ct_discovery: Option<&CtLogDiscovery>,
    web_traffic_discovery: Option<&WebTrafficDiscovery>,
    checkpoint: Arc<Mutex<Checkpoint>>,
    checkpoint_output_dir: &str,
    result_sink: Arc<Mutex<ResultSink>>,
    memory_pressure_level: Arc<std::sync::atomic::AtomicU8>,
) -> Result<()> {
    if is_interrupted() {
        let cp = checkpoint.lock().await;
        let checkpoint_path = Path::new(checkpoint_output_dir);
        if let Err(e) = cp.save(checkpoint_path) {
            eprintln!("Warning: Failed to save checkpoint on interrupt: {}", e);
        } else {
            eprintln!(
                "Checkpoint saved to: {}",
                checkpoint_path
                    .join(checkpoint::CHECKPOINT_FILENAME)
                    .display()
            );
        }
        return Ok(());
    }

    // P1.3: one atomic, depth-aware test-and-set. Holding the lock across the read, the
    // (pure, cheap) depth check, and the insert closes the check-then-insert race that let
    // two parents run the FULL discovery suite for the same domain concurrently. The gate is
    // depth-aware: a domain already claimed at a shallower-or-equal depth is skipped; a
    // strictly shallower reach re-expands (re-claims at the lower depth and proceeds), which
    // output dedup absorbs. Depth-refused domains are NOT inserted — they may still be reached
    // within budget via a shallower path later.
    let depth_refused = {
        let mut processed = processed_domains.lock().await;
        match processed_gate_decision(
            processed.get(domain).copied(),
            current_depth,
            is_depth_allowed(current_depth, max_depth),
        ) {
            ProcessedGate::Skip => {
                crate::perf::METRICS.dedup_domain_hit.hit();
                logger.debug(&format!(
                    "Domain {} already processed at depth <= {} — skipping",
                    domain, current_depth
                ));
                return Ok(());
            }
            ProcessedGate::Claim => {
                processed.insert(domain.to_string(), current_depth);
                false
            }
            ProcessedGate::DepthRefused => true,
        }
    };
    if depth_refused {
        if current_depth > ABSOLUTE_MAX_DEPTH {
            logger.warn(&format!(
                "Hit absolute depth cap ({}) for domain {}",
                ABSOLUTE_MAX_DEPTH, domain
            ));
        } else {
            logger.debug(&format!(
                "Reached max depth {:?} for domain {}",
                max_depth, domain
            ));
        }
        return Ok(());
    }

    logger.record_domain_processed();
    logger.record_depth_reached(current_depth);
    logger.debug(&format!(
        "Analyzing domain: {} at depth {}",
        domain, current_depth
    ));

    if current_depth == 1 {
        logger.update_progress("DNS record analysis").await;
        logger
            .show_sub_progress(&format!(
                "Querying TXT/SPF/DMARC/DKIM records for {} via DNS-over-HTTPS",
                domain
            ))
            .await;
        logger.set_progress_position(12).await;
    }
    logger.log_dns_lookup_start(domain);

    let dns_counter = logger.dns_failure_counter();
    let txt_records = match dns::get_txt_records_with_pool_tracked(domain, &dns_pool, dns_counter)
        .await
    {
        Ok(records) if !records.is_empty() => records,
        first_result => {
            if current_depth == 1 {
                logger.debug(&format!(
                    "Root domain {} returned 0 TXT records on first attempt, retrying...",
                    domain
                ));
                match dns::get_txt_records_with_pool_tracked(domain, &dns_pool, dns_counter).await {
                    Ok(retry_records) if !retry_records.is_empty() => {
                        logger.info(&format!(
                            "DNS retry succeeded: found {} TXT records for {} on second attempt",
                            retry_records.len(),
                            domain
                        ));
                        retry_records
                    }
                    _ => {
                        logger.warn(&format!(
                            "DNS returned 0 TXT records for root domain {} after 2 attempts. \
                             This is unusual — most domains have SPF/DMARC/verification records. \
                             Possible causes: transient DNS failure, network issues, or DNS blocking.",
                            domain
                        ));
                        first_result.unwrap_or_default()
                    }
                }
            } else {
                first_result.unwrap_or_default()
            }
        }
    };

    {
        if !txt_records.is_empty() {
            logger.log_dns_lookup_success(domain, "DoH/DNS", txt_records.len());
            logger.debug(&format!(
                "Raw TXT records for {}: {:?}",
                domain, txt_records
            ));
            if current_depth == 1 {
                logger
                    .show_sub_progress(&format!(
                        "Found {} TXT records for {}",
                        txt_records.len(),
                        domain
                    ))
                    .await;
            }
        } else {
            logger.log_dns_lookup_success(domain, "DoH/DNS", 0);
        }

        let vendor_domains_with_source = dns::extract_vendor_domains_with_source_and_logger(
            &txt_records,
            Some(verification_logger),
            domain,
        );

        // DMARC records live at `_dmarc.<domain>`, not the apex, so the apex TXT query
        // above never sees them — which is why the "Email Security (DMARC)" source was
        // effectively dead. Probe `_dmarc.<domain>` explicitly and run it through the same
        // extractor: its rua=/ruf= reporting addresses point to report-processing vendors
        // (dmarcian, Agari, Proofpoint, …) that are typically absent from SPF, so this is
        // additive, non-redundant recall. Only the DMARC extractor matches a v=DMARC1
        // record; the SPF/DKIM/verification extractors no-op on it.
        let dmarc_host = format!("_dmarc.{}", domain);
        let dmarc_records =
            dns::get_txt_records_with_pool_tracked(&dmarc_host, &dns_pool, dns_counter)
                .await
                .unwrap_or_default();
        let dmarc_vendor_domains = if dmarc_records.is_empty() {
            Vec::new()
        } else {
            logger.debug(&format!(
                "Found {} _dmarc TXT record(s) for {}",
                dmarc_records.len(),
                domain
            ));
            dns::extract_vendor_domains_with_source_and_logger(
                &dmarc_records,
                Some(verification_logger),
                domain,
            )
        };

        let spf_recursive_domains =
            dns::resolve_spf_includes_recursive(&txt_records, &dns_pool, domain).await;
        if !spf_recursive_domains.is_empty() {
            logger.debug(&format!(
                "SPF recursive resolution found {} additional domains for {}",
                spf_recursive_domains.len(),
                domain
            ));
        }

        let current_base_domain = domain_utils::extract_base_domain(domain);
        let mut all_vendor_domains = vendor_domains_with_source;
        all_vendor_domains.extend(dmarc_vendor_domains);
        all_vendor_domains.extend(spf_recursive_domains);
        if let Some(base_vd) = add_base_domain_if_subdomain(domain, &current_base_domain) {
            logger.debug(&format!(
                "Added base domain {} for subdomain analysis of {}",
                current_base_domain, domain
            ));
            all_vendor_domains.push(base_vd);
        }

        // Discovery phases. The five independent scanners run concurrently (each hits
        // a different source and shares no mutable state) via tokio::join!, collapsing
        // the serial chain to ~its slowest single phase. The full suite now runs at
        // EVERY depth (previously depth 1 only): deeper layers get subprocessor +
        // subfinder + SaaS + CT + web traffic, so an Nth-party org's subprocessors and
        // subdomains are discovered instead of DNS records alone. The number of vendors
        // processed at each depth is bounded by the per-depth vendor limits, and the
        // browser-based web-traffic phase waits on adaptive network-idle rather than a
        // fixed sleep, so the added deep renders stay affordable. Each phase Option-gates
        // internally (a disabled/None method is a no-op), so this respects the operator's
        // enabled-methods configuration at every depth.
        if current_depth == 1 {
            logger
                .update_progress("Discovery: subprocessor + subfinder + SaaS + CT + web traffic")
                .await;
            logger.set_progress_position(16).await;
        }
        // Each arm is timed independently. They run concurrently, so these do not sum to the
        // discovery wall time — the join costs roughly its slowest arm, and the point of the
        // per-phase counters is to name which arm that is. The whole join is timed into the
        // depth bucket, which is the term that actually adds up across the recursion.
        // Per-organization subprocessor dedup: skip the browser-rendered subprocessor
        // lookup for a domain whose org another domain already claimed (see
        // subprocessor_skip_decision). Only gates the subprocessor arm — the other four
        // phases genuinely differ per domain and stay enabled.
        let subprocessor_enabled = subprocessor_enabled
            && {
                let base = domain_utils::extract_base_domain(domain);
                let org = discovered_vendors.lock().await.get(&base).cloned();
                let mut attempted = subprocessor_attempted_orgs.lock().await;
                let skip =
                    subprocessor_skip_decision(org.as_deref(), current_depth, &mut attempted);
                if skip {
                    crate::perf::METRICS.dedup_org_subproc_skip.hit();
                    logger.debug(&format!(
                    "Skipping subprocessor lookup for {} — org already analyzed at a shallower layer",
                    domain
                ));
                }
                !skip
            };

        // P1.5: apex-scoped dedup for subfinder / CT / SaaS. Each enumerates a registrable
        // base (subfinder: the base's subdomains; CT: `%.<apex>`; SaaS: tenants named after
        // the apex), so one run per apex per scan covers every subdomain of that apex and
        // every parent that reaches into it. A subdomain input skips these entirely — its
        // apex is always separately queued (add_base_domain_if_subdomain) and carries the
        // superset. Claim-before-run (like subprocessor_attempted_orgs) so racing reaches of
        // the same apex can't double-run.
        // NOTE: these gated bindings are JOIN-LOCAL — they must NOT shadow the discovery
        // parameters, which are still handed to every child recursion below (each child does
        // its own apex claim). Disabling a method here for the whole subtree would be a recall
        // regression.
        let apex = domain_utils::extract_base_domain(domain);
        let is_apex = apex == domain;
        // P4.8: gate subdomain/CT enumeration for common-denominator infra roots at depth >=2.
        // Their subdomain sprawl is the platform's, not the customer's nth-parties — the edge to
        // the infra root is already recorded (leaf preserved), only the fan-out is skipped. Counted
        // once per gated domain that actually had enumeration to skip; distinct from the apex-dedup
        // skips below (which fire when the apex was already enumerated this scan).
        let infra_gated = should_gate_infra_enumeration(current_depth, &apex);
        if infra_gated && (subdomain_discovery.is_some() || ct_discovery.is_some()) {
            crate::perf::METRICS.fanout_gate_skip.hit();
        }
        let subfinder_for_join =
            if !infra_gated && is_apex && scan_dedup.claim_subfinder(&apex).await {
                subdomain_discovery
            } else {
                if subdomain_discovery.is_some() && !infra_gated {
                    crate::perf::METRICS.subfinder_apex_skip.hit();
                }
                None
            };
        let ct_for_join = if !infra_gated && is_apex && scan_dedup.claim_ct(&apex).await {
            ct_discovery
        } else {
            if ct_discovery.is_some() && !infra_gated {
                crate::perf::METRICS.ct_apex_skip.hit();
            }
            None
        };
        // SaaS: run_saas_phase already skips subdomains internally (P1.8). Add the
        // cross-parent apex dedup here: an apex reached via a second parent skips re-probing.
        let saas_for_join = if !is_apex || scan_dedup.claim_saas(&apex).await {
            saas_tenant_discovery
        } else {
            if saas_tenant_discovery.is_some() {
                crate::perf::METRICS.saas_apex_skip.hit();
            }
            None
        };

        // P3.6: the whole-domain ceiling. Every per-method budget already shipped, but none of them
        // compose — a domain slow on several methods pays their sum on top of the serial DNS
        // preamble and the org resolution the caller already spent out of this same clock. One
        // ceiling now spans all of it. `None` means exempt (the scan root), in which case the arms
        // run exactly as they did before, with no timer and no select.
        let domain_budget = match clock.decide(current_depth, DOMAIN_WORK_CEILING) {
            DomainCeiling::Exempt => None,
            DomainCeiling::Within(_) | DomainCeiling::Exhausted => {
                Some((clock, current_depth, DOMAIN_WORK_CEILING))
            }
        };
        // The budget wrapper sits INSIDE `timed_async` so a cut phase still records the time it
        // burned before being cut. Excluding it would quietly shrink the phase metric that names
        // the slow arm — the one number a reader needs to understand why the ceiling fired.
        let discovery_started = std::time::Instant::now();
        let (sp, sf, st, ct_v, wt) = tokio::join!(
            crate::perf::timed_async(
                &crate::perf::METRICS.phase_subproc,
                phase_within_domain_budget(
                    run_subprocessor_phase(
                        domain,
                        subprocessor_analyzer,
                        subprocessor_enabled,
                        verification_logger,
                        &logger,
                    ),
                    domain_budget,
                    &crate::coverage::SCAN_COVERAGE.subprocessor,
                    "subprocessor",
                    domain,
                    &logger,
                ),
            ),
            crate::perf::timed_async(
                &crate::perf::METRICS.phase_subfinder,
                phase_within_domain_budget(
                    run_subfinder_phase(domain, subfinder_for_join, &dns_pool, &logger),
                    domain_budget,
                    &crate::coverage::SCAN_COVERAGE.subfinder,
                    "subfinder",
                    domain,
                    &logger,
                ),
            ),
            crate::perf::timed_async(
                &crate::perf::METRICS.phase_saas,
                phase_within_domain_budget(
                    run_saas_phase(domain, saas_for_join, &logger),
                    domain_budget,
                    &crate::coverage::SCAN_COVERAGE.saas,
                    "SaaS tenant",
                    domain,
                    &logger,
                ),
            ),
            crate::perf::timed_async(
                &crate::perf::METRICS.phase_ct,
                phase_within_domain_budget(
                    run_ct_phase(domain, ct_for_join, &logger),
                    domain_budget,
                    &crate::coverage::SCAN_COVERAGE.ct,
                    "CT log",
                    domain,
                    &logger,
                ),
            ),
            crate::perf::timed_async(
                &crate::perf::METRICS.phase_webtraffic,
                phase_within_domain_budget(
                    run_webtraffic_phase(domain, web_traffic_discovery, &logger),
                    domain_budget,
                    &crate::coverage::SCAN_COVERAGE.webtraffic,
                    "web traffic",
                    domain,
                    &logger,
                ),
            ),
        );
        crate::perf::METRICS
            .depth_bucket(current_depth)
            .record(discovery_started.elapsed());
        all_vendor_domains.extend(sp);
        all_vendor_domains.extend(sf);
        all_vendor_domains.extend(st);
        all_vendor_domains.extend(ct_v);
        all_vendor_domains.extend(wt);
        if current_depth == 1 {
            logger.clear_sub_progress().await;
            logger.set_progress_position(30).await;
        }

        {
            let pre_dedup_count = all_vendor_domains.len();
            let (deduped, removed) = dedup_vendor_domains(all_vendor_domains);
            all_vendor_domains = deduped;
            if removed > 0 {
                logger.debug(&format!(
                    "Deduplicated vendor domains: {} -> {} (removed {} exact duplicates)",
                    pre_dedup_count,
                    all_vendor_domains.len(),
                    removed
                ));
            }
        }

        if current_depth == 1 {
            let vendor_count = all_vendor_domains.len() as u64;
            if vendor_count > 0 {
                logger
                    .update_progress(&format!(
                        "Analyzing {} vendor domains (WHOIS + org lookup)",
                        vendor_count
                    ))
                    .await;
                logger
                    .show_sub_progress(&format!(
                        "Processing vendor 0/{} — resolving organizations",
                        vendor_count
                    ))
                    .await;
            } else {
                logger.warn(
                    "No vendor domains found for root domain after all discovery methods. \
                                 This likely indicates a DNS resolution failure or network issue. \
                                 Try re-running the scan.",
                );
                logger
                    .update_progress("No vendor domains found to analyze")
                    .await;
                logger.set_progress_position(100).await;
                logger
                    .finish_progress("Analysis completed — 0 vendors found (possible DNS failure)")
                    .await;
            }
        }

        {
            let before_count = all_vendor_domains.len();
            let (limited, removed) = apply_vendor_limits(
                all_vendor_domains,
                &analysis_config.strategy,
                analysis_config,
                current_depth,
            );
            all_vendor_domains = limited;
            match analysis_config.strategy {
                AnalysisStrategy::Unlimited => {
                    logger.debug(&format!(
                        "Strategy 'unlimited': processing all {} vendors at depth {}",
                        all_vendor_domains.len(),
                        current_depth
                    ));
                }
                AnalysisStrategy::Limits => {
                    if removed > 0 {
                        logger.info(&format!("Strategy 'limits': limiting vendor processing at depth {} from {} to {} vendors",
                                               current_depth, before_count, all_vendor_domains.len()));
                    }
                }
                AnalysisStrategy::Budget => {
                    logger.debug(&format!(
                        "Strategy 'budget': processing vendors at depth {} (budget tracking enabled)",
                        current_depth
                    ));
                }
            }
        }

        let vendor_count = all_vendor_domains.len();
        logger.log_vendor_discovery(domain, vendor_count);

        if vendor_count > 0 {
            logger.log_parallel_processing_start(vendor_count, current_depth);

            use futures::{stream, StreamExt};

            let request_delay_ms = analysis_config.request_delay_ms;
            let analysis_config_clone = analysis_config.clone();
            let checkpoint_output_dir_owned = checkpoint_output_dir.to_string();
            let vendor_stream = stream::iter(all_vendor_domains.into_iter().enumerate().map(|(index, vendor_domain_info)| {
                    let discovered_vendors = discovered_vendors.clone();
                    let processed_domains = processed_domains.clone();
                    let subprocessor_attempted_orgs = subprocessor_attempted_orgs.clone();
                    let scan_dedup = scan_dedup.clone();
                    let semaphore = semaphore.clone();
                    let recursive_semaphore = recursive_semaphore.clone();
                    let domain = domain.to_string();
                    let root_customer_domain = root_customer_domain.to_string();
                    let root_customer_organization = root_customer_organization.to_string();
                    let dns_pool = dns_pool.clone();
                    let args_ref = args;
                    let logger_clone = logger.clone();
                    let vendor_domain_clone = vendor_domain_info.domain.clone();
                    let total_vendors = vendor_count;
                    let analysis_config_inner = analysis_config_clone.clone();
                    let checkpoint_clone = checkpoint.clone();
                    let checkpoint_output_dir_clone = checkpoint_output_dir_owned.clone();
                    let result_sink_clone = result_sink.clone();
                    let pressure_level = memory_pressure_level.clone();

                    async move {
                        let pressure = pressure_level.load(std::sync::atomic::Ordering::Relaxed);
                        let delay = compute_pressure_delay_ms(pressure);
                        if delay > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        }

                        if request_delay_ms > 0 && index > 0 && current_depth == 1 {
                            tokio::time::sleep(std::time::Duration::from_millis(request_delay_ms)).await;
                        }

                        let start_time = std::time::Instant::now();
                        if current_depth == 1 {
                            let source_label = source_type_label(&vendor_domain_info.source_type);
                            let record_hint = truncate_utf8(&vendor_domain_info.raw_record, 50);
                            logger_clone.show_sub_progress(&format!("WHOIS + org lookup {}/{}: {} (via {}: {})",
                                index + 1, total_vendors, vendor_domain_clone, source_label, record_hint)).await;
                        }
                        logger_clone.debug(&format!("🔍 Starting analysis for vendor {}/{}: {} (depth {}, source: {:?})",
                            index + 1, total_vendors, vendor_domain_clone, current_depth, vendor_domain_info.source_type));

                        let count_before = {
                            let sink = result_sink_clone.lock().await;
                            sink.count()
                        };

                        process_vendor_domain(
                            vendor_domain_info.domain,
                            vendor_domain_info.source_type,
                            domain,
                            current_depth,
                            max_depth,
                            discovered_vendors,
                            processed_domains,
                            subprocessor_attempted_orgs,
                            scan_dedup,
                            semaphore.clone(),
                            root_customer_domain,
                            root_customer_organization,
                            verification_logger,
                            dns_pool,
                            recursive_semaphore,
                            vendor_domain_info.raw_record,
                            args_ref,
                            logger_clone.clone(),
                            subprocessor_analyzer,
                            subprocessor_enabled,
                            web_org_enabled,
                            web_org_min_confidence,
                            &analysis_config_inner,
                            subdomain_discovery,
                            saas_tenant_discovery,
                            ct_discovery,
                            web_traffic_discovery,
                            checkpoint_clone,
                            checkpoint_output_dir_clone,
                            result_sink_clone.clone(),
                            pressure_level.clone(),
                        ).await;

                        let count_after = {
                            let sink = result_sink_clone.lock().await;
                            sink.count()
                        };
                        let new_relationships = count_after - count_before;

                        let elapsed = start_time.elapsed();
                        logger_clone.debug(&format!("✅ Completed analysis for vendor {}/{}: {} in {:.2}s (found {} relationships)",
                            index + 1, total_vendors, vendor_domain_clone, elapsed.as_secs_f64(), new_relationships));

                        if current_depth == 1 && total_vendors > 0 {
                            let position = compute_progress_position(index, total_vendors);
                            logger_clone.set_progress_position(position).await;
                        }

                        new_relationships
                    }
                }));

            let configured_concurrency =
                analysis_config.get_concurrency_for_depth(current_depth as usize);
            let buffer_size = compute_buffer_size(configured_concurrency, args.parallel_jobs);

            let mut vendor_stream = vendor_stream.buffer_unordered(buffer_size);

            logger.debug(&format!(
                "Starting parallel processing for {} vendors at depth {} (disk-backed results)",
                vendor_count, current_depth
            ));

            let mut processed_count = 0;
            let mut total_relationships_found = 0usize;
            // P3.4: debounce clock for periodic checkpoint saves. Starts now so the first save waits
            // out a full interval rather than firing on the first few completions.
            let mut last_checkpoint_at = std::time::Instant::now();
            let checkpoint_path = Path::new(checkpoint_output_dir);
            while let Some(new_count) = vendor_stream.next().await {
                if is_interrupted() {
                    {
                        let mut sink = result_sink.lock().await;
                        if let Err(e) = sink.flush() {
                            // Unflushed rows exist only in memory — the checkpoint
                            // about to be saved will silently lose them on resume.
                            logger.warn(&format!(
                                "Failed to flush results to disk on interrupt: {} — \
                                 the checkpoint may be missing the most recent results.",
                                e
                            ));
                        }
                    }
                    let mut cp = checkpoint.lock().await;
                    let vendors = discovered_vendors.lock().await;
                    cp.discovered_vendors = vendors.clone();
                    drop(vendors);
                    let processed = processed_domains.lock().await;
                    cp.completed_domains = processed.keys().cloned().collect();
                    drop(processed);
                    let sink = result_sink.lock().await;
                    cp.results_count = sink.count();
                    cp.results_file = sink.path().to_string_lossy().to_string();
                    drop(sink);
                    // Record how deep the scan actually got. Outside tests this was never
                    // assigned, so every checkpoint on disk reported depth 0 and the resume
                    // banner under-reported progress on every deep scan.
                    cp.current_depth_reached = cp.current_depth_reached.max(current_depth);
                    if let Err(e) = cp.save(checkpoint_path) {
                        eprintln!("Warning: Failed to save checkpoint on interrupt: {}", e);
                    } else {
                        eprintln!(
                            "Checkpoint saved to: {}",
                            checkpoint_path
                                .join(checkpoint::CHECKPOINT_FILENAME)
                                .display()
                        );
                    }
                    return Ok(());
                }

                processed_count += 1;
                total_relationships_found += new_count;
                if current_depth == 1 {
                    logger
                        .update_progress(&format!(
                            "Analyzing vendors ({}/{}) — {} relationships found",
                            processed_count, vendor_count, total_relationships_found
                        ))
                        .await;
                }
                if should_checkpoint(processed_count, vendor_count) {
                    logger.debug(&format!(
                        "📊 Progress: {}/{} vendors processed, {} relationships found",
                        processed_count, vendor_count, total_relationships_found
                    ));
                }
                // P3.4: the periodic save is debounced by TIME, not by completion count, and its
                // serialize+fsync runs on a blocking thread with every mutex already released.
                // Previously this fired every 5 completions and held the checkpoint lock across an
                // fsync while the vendor/processed maps were cloned under theirs — so a durability
                // mechanism became the depth-1 pipeline's own contention source, spiking exactly the
                // locks every concurrent org resolution needs.
                if current_depth == 1
                    && should_checkpoint_now(
                        processed_count,
                        vendor_count,
                        last_checkpoint_at.elapsed(),
                        CHECKPOINT_MIN_INTERVAL,
                    )
                {
                    let snapshot = {
                        let mut cp = checkpoint.lock().await;
                        let vendors = discovered_vendors.lock().await;
                        cp.discovered_vendors = vendors.clone();
                        drop(vendors);
                        let processed = processed_domains.lock().await;
                        cp.completed_domains = processed.keys().cloned().collect();
                        drop(processed);
                        let sink = result_sink.lock().await;
                        cp.results_count = sink.count();
                        cp.results_file = sink.path().to_string_lossy().to_string();
                        drop(sink);
                        cp.current_depth_reached = cp.current_depth_reached.max(current_depth);
                        cp.clone()
                    };
                    let completed = snapshot.completed_domains.len();
                    let save_path = checkpoint_path.to_path_buf();
                    // Awaited rather than fire-and-forget: the caller must still learn whether the
                    // save failed (silent checkpoint loss is what a resume discovers too late), and
                    // awaiting keeps two saves from ever racing the same temp file. The win is that
                    // no mutex is held for the duration, so the rest of the pipeline runs through it.
                    let saved =
                        tokio::task::spawn_blocking(move || snapshot.save(&save_path)).await;
                    last_checkpoint_at = std::time::Instant::now();
                    match saved {
                        Ok(Ok(())) => logger.debug(&format!(
                            "Checkpoint saved: {} domains completed",
                            completed
                        )),
                        Ok(Err(e)) => logger.debug(&format!("Failed to save checkpoint: {}", e)),
                        Err(e) => logger.debug(&format!("Checkpoint save task failed: {}", e)),
                    }
                }
            }

            logger.debug(&format!("All {} vendor domains processed at depth {} ({} raw relationships to disk, pending dedup)",
                    processed_count, current_depth, total_relationships_found));

            logger.log_parallel_processing_complete(total_relationships_found);

            if current_depth == 1 {
                // Report the actual number of relationships written to the sink (the
                // flattened count, == app.rs's raw_count), NOT `total_relationships_found`:
                // that per-level accumulator re-counts every descendant edge at each
                // recursion level and over-reports the headline by ~25x on a deep scan
                // (718412 vs the true 28216 fed to dedup). By this point the depth-1
                // buffer has awaited all descendants, so every edge is already in the sink.
                let written = result_sink.lock().await.count();
                logger.finish_progress(&format!("Vendor analysis completed — {} raw relationships from {} vendors (deduplicating...)",
                        written, vendor_count)).await;
            }
        }
    }

    Ok(())
}

// coverage(off): I/O-only orchestration shell after DI extraction. Pure logic extracted to:
// should_skip_self_reference, resolve_orgs_from_vendors, build_record_value,
// should_stop_at_common_denominator. Remaining code is: WHOIS network lookups via
// get_organization_with_status_and_config, result_sink file I/O, recursive discover_nth_parties
// call — no testable branching logic remains.
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::too_many_arguments)]
pub async fn process_vendor_domain(
    vendor_domain: String,
    source_type: RecordType,
    customer_domain: String,
    current_depth: u32,
    max_depth: Option<u32>,
    discovered_vendors: Arc<Mutex<HashMap<String, String>>>,
    processed_domains: Arc<Mutex<HashMap<String, u32>>>,
    subprocessor_attempted_orgs: Arc<Mutex<HashMap<String, u32>>>,
    scan_dedup: Arc<ScanDedup>,
    semaphore: Arc<Semaphore>,
    root_customer_domain: String,
    root_customer_organization: String,
    verification_logger: &verification_logger::VerificationFailureLogger,
    dns_pool: Arc<dns::DnsServerPool>,
    recursive_semaphore: Arc<Semaphore>,
    raw_record: String,
    args: &Args,
    logger: Arc<AnalysisLogger>,
    subprocessor_analyzer: Option<&Arc<subprocessor::SubprocessorAnalyzer>>,
    subprocessor_enabled: bool,
    web_org_enabled: bool,
    web_org_min_confidence: f32,
    analysis_config: &AnalysisConfig,
    // Threaded through so the recursive discover_nth_parties call runs the full
    // discovery suite at deeper layers (previously these were passed as None,
    // restricting subdomain/SaaS/CT/web-traffic discovery to depth 1).
    subdomain_discovery: Option<&SubfinderDiscovery>,
    saas_tenant_discovery: Option<&SaasTenantDiscovery>,
    ct_discovery: Option<&CtLogDiscovery>,
    web_traffic_discovery: Option<&WebTrafficDiscovery>,
    checkpoint: Arc<Mutex<Checkpoint>>,
    checkpoint_output_dir: String,
    result_sink: Arc<Mutex<ResultSink>>,
    memory_pressure_level: Arc<std::sync::atomic::AtomicU8>,
) {
    if should_skip_self_reference(&vendor_domain, &customer_domain) {
        logger.debug(&format!(
            "Skipping self-reference: {} -> {}",
            customer_domain, vendor_domain
        ));
        return;
    }

    // P3.1: real admission control. `semaphore` was constructed, threaded through every signature in
    // this module, and then never acquired — `rg acquire src/analysis.rs` returned zero hits. Actual
    // concurrency was therefore the PRODUCT of the nested `buffer_unordered` widths (50 x 30 x 15…),
    // i.e. thousands of simultaneously-live vendor tasks. That is what drove `browser.permit_wait` to
    // a 201.6s mean over 1,113 acquisitions on the 2026-08-15 depth-3 scan, and it is why every
    // per-vendor time budget was really measuring queue depth instead of work.
    //
    // The permit is held for this vendor's LOCAL work only and released before the recursive descent
    // below (the leaf-held-only doctrine already articulated in http_client.rs). Holding it across
    // the subtree would deadlock: a parent would occupy a permit while waiting on children that need
    // permits of their own. Released-before-descent makes that impossible by construction.
    //
    // Fail-open on a closed semaphore: a scan that has begun shutting down must not wedge here.
    //
    // P3.6: the whole-domain clock starts BEFORE the acquire, and the wait is then credited back as
    // queue time. That ordering is the point — this is the queue the P3.1 comment above measured at
    // a 201.6s mean, so a ceiling that charged it as work would fire on every domain of a busy scan
    // and cut recall in proportion to how loaded the machine was. The clock spans this vendor's org
    // resolution and, via `discover_nth_parties_with_clock`, its five discovery methods.
    let clock = DomainWorkClock::start();
    let _local_work_permit = semaphore.clone().acquire_owned().await.ok();
    clock.credit_queue(clock.elapsed());

    // Input guard (mirrors the output-time gate in finalize::finalize_report). A non-registrable
    // host — an org name, an email, a wayback-wrapped URL, an IP fragment — must never enter the
    // per-vendor WHOIS/org lookups or the recursive discovery fan-out. Discovery occasionally emits
    // these ("anysphere, inc.", "hostmaster@slack.com", "org/web/20250601085143/https://cursor.com/");
    // left unguarded they burn WHOIS/DNS/CT/subfinder budget and recurse. `is_non_registrable_host`
    // is the exact PSL-based predicate finalize already uses to drop them at output, so applying it
    // earlier can only remove work that would have been discarded anyway — recall is unchanged and
    // speed strictly improves. Platform-tenancy vendors (github.io, s3.amazonaws.com) are PSL
    // PRIVATE entries and are correctly NOT matched.
    if crate::finalize::is_non_registrable_host(&vendor_domain) {
        logger.debug(&format!(
            "Skipping non-registrable vendor input: {}",
            vendor_domain
        ));
        return;
    }

    let base_domain = domain_utils::extract_base_domain(&vendor_domain);
    let customer_base_domain = domain_utils::extract_base_domain(&customer_domain);

    // The vendor's org and the customer's org are independent lookups against different
    // map keys, and each can cost seconds (web fetch → WHOIS → NER). Awaiting them in
    // sequence, as this used to, put both on every vendor's critical path. Resolving them
    // concurrently makes the pair cost `max` rather than `sum`; when either is already
    // cached the join costs nothing. Politeness is unaffected — the DNS, HTTP, and WHOIS
    // token buckets are global and still pace every outbound request.
    //
    // The insert-after-lookup shape is preserved exactly, including its check-then-act
    // window: a domain resolved twice by racing vendors yields the same value from the same
    // priority chain, so last-write-wins is a no-op rather than a correctness hazard.
    let vendor_needed = !discovered_vendors.lock().await.contains_key(&base_domain);
    let customer_needed = base_domain != customer_base_domain
        && !discovered_vendors
            .lock()
            .await
            .contains_key(&customer_base_domain);

    // P1.4: resolve a base's org through the scan-global singleflight. The whole
    // whois→web→NER chain plus the plausibility-gated normalization runs inside the once-cell
    // compute, so the value is the FINAL normalized string and coalesced callers receive a
    // byte-identical result. The plausibility backstop, verified-flag handling, and per-domain
    // logging are unchanged — only who runs them (once per base, not once per racing vendor).
    let resolve_org = |domain: String, needed: bool| {
        let scan_dedup = scan_dedup.clone();
        let logger = logger.clone();
        async move {
            if !needed {
                return None;
            }
            let org = scan_dedup
                .resolve_org_once(&domain, || async {
                    match whois::get_organization_with_status_and_config(
                        &domain,
                        web_org_enabled,
                        web_org_min_confidence,
                    )
                    .await
                    {
                        Ok(org_result) => {
                            // Backstop against extracted taglines reaching the report. Applies
                            // to INFERRED names only; a curated/verified source is never
                            // overruled by the plausibility heuristic (real legal names are odd
                            // enough that the heuristic is the thing more likely to be wrong).
                            let resolved = if org_result.is_verified
                                || org_normalizer::is_plausible_org_name(&org_result.name)
                            {
                                org_normalizer::normalize(&org_result.name)
                            } else {
                                org_normalizer::normalize(&domain)
                            };
                            logger.log_whois_lookup(&domain, org_result.is_verified);
                            resolved
                        }
                        Err(e) => {
                            logger.debug(&format!(
                                "Failed to get organization for {}: {}",
                                domain, e
                            ));
                            logger.log_whois_lookup(&domain, false);
                            org_normalizer::normalize(&domain)
                        }
                    }
                })
                .await;
            Some((domain, org))
        }
    };

    let (vendor_lookup, customer_lookup) = tokio::join!(
        resolve_org(base_domain.clone(), vendor_needed),
        resolve_org(customer_base_domain.clone(), customer_needed),
    );

    for (domain, org) in [vendor_lookup, customer_lookup].into_iter().flatten() {
        discovered_vendors.lock().await.insert(domain, org);
    }

    let (customer_org, vendor_org) = {
        let vendors = discovered_vendors.lock().await;
        resolve_orgs_from_vendors(&vendors, &customer_base_domain, &base_domain)
    };

    let record_value = build_record_value(
        &source_type,
        &base_domain,
        &customer_domain,
        &raw_record,
        &vendor_domain,
    );

    let relationship = VendorRelationship::new(
        base_domain.clone(),
        vendor_org.clone(),
        current_depth,
        customer_base_domain.clone(),
        customer_org.clone(),
        record_value.clone(),
        source_type.clone(),
        root_customer_domain.clone(),
        root_customer_organization.clone(),
        raw_record.clone(),
    );

    logger.debug(&format!(
        "Established {} relationship: {} ({}) -> {} ({})",
        relationship.layer_description(),
        customer_base_domain,
        customer_org,
        base_domain,
        vendor_org
    ));

    {
        let mut sink = result_sink.lock().await;
        if let Err(e) = sink.append_one(&relationship) {
            logger.warn(&format!("Failed to write result to sink: {}", e));
        }
    }

    if should_stop_at_common_denominator(max_depth, &base_domain) {
        logger.debug(&format!("Reached common denominator: {}", base_domain));
        return;
    }

    let lookup_domain = domain_utils::normalize_for_dns_lookup(&vendor_domain);

    // P3.1: local work is done — release the admission permit BEFORE descending. This is the half of
    // the leaf-held-only doctrine that prevents deadlock: every parent below is now waiting on
    // children without occupying a slot those children need.
    drop(_local_work_permit);

    if let Err(e) = discover_nth_parties_with_clock(
        // P3.6: the SAME clock the org resolution above ran under, so the ceiling covers this
        // vendor's whole unit rather than restarting per half.
        &clock,
        &lookup_domain,
        max_depth,
        discovered_vendors.clone(),
        processed_domains.clone(),
        subprocessor_attempted_orgs.clone(),
        scan_dedup.clone(),
        semaphore.clone(),
        current_depth + 1,
        &root_customer_domain,
        &root_customer_organization,
        verification_logger,
        dns_pool,
        recursive_semaphore.clone(),
        args,
        logger.clone(),
        subprocessor_analyzer,
        subprocessor_enabled,
        web_org_enabled,
        web_org_min_confidence,
        analysis_config,
        // Full discovery suite at every depth (previously restricted to depth 1 by
        // passing None here). Deeper layers now get subdomain/SaaS/CT/web-traffic
        // discovery too — bounded by the per-depth vendor limits, and the
        // browser-based web-traffic phase uses adaptive network-idle so the added
        // renders stay affordable.
        subdomain_discovery,
        saas_tenant_discovery,
        ct_discovery,
        web_traffic_discovery,
        checkpoint,
        &checkpoint_output_dir,
        result_sink,
        memory_pressure_level,
    )
    .await
    {
        logger.warn(&format!(
            "Recursive analysis failed for {}: {}",
            lookup_domain, e
        ));
    }
}

// coverage(off): I/O-only orchestration shell — calls DNS (get_txt_records_with_pool,
// resolve_spf_includes_recursive) and WHOIS (get_organization_with_status_and_config).
// All pure logic (self-reference check, org resolution, record building, common-denominator stop)
// tested via extracted functions. Remaining code is network I/O and recursion plumbing.
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::too_many_arguments)]
pub async fn discover_nth_parties_minimal(
    domain: &str,
    max_depth: Option<u32>,
    discovered_vendors: Arc<Mutex<HashMap<String, String>>>,
    processed_domains: Arc<Mutex<HashSet<String>>>,
    semaphore: Arc<Semaphore>,
    current_depth: u32,
    root_customer_domain: &str,
    root_customer_organization: &str,
    verification_logger: &verification_logger::VerificationFailureLogger,
    dns_pool: Arc<dns::DnsServerPool>,
    recursive_semaphore: Arc<Semaphore>,
    parallel_jobs: usize,
    logger: Arc<AnalysisLogger>,
    analysis_config: &AnalysisConfig,
) -> Result<Vec<VendorRelationship>> {
    {
        let processed = processed_domains.lock().await;
        if processed.contains(domain) {
            return Ok(vec![]);
        }
    }

    if let Some(max) = max_depth {
        if current_depth > max {
            return Ok(vec![]);
        }
    }

    {
        let mut processed = processed_domains.lock().await;
        processed.insert(domain.to_string());
    }

    let mut results = Vec::new();

    if let Ok(txt_records) =
        dns::get_txt_records_with_pool_tracked(domain, &dns_pool, logger.dns_failure_counter())
            .await
    {
        let mut vendor_domains_with_source = dns::extract_vendor_domains_with_source_and_logger(
            &txt_records,
            Some(verification_logger),
            domain,
        );

        let spf_recursive =
            dns::resolve_spf_includes_recursive(&txt_records, &dns_pool, domain).await;
        vendor_domains_with_source.extend(spf_recursive);

        for vendor_domain_info in vendor_domains_with_source {
            let base_domain = domain_utils::extract_base_domain(&vendor_domain_info.domain);
            let customer_base_domain = domain_utils::extract_base_domain(domain);

            if base_domain == customer_base_domain {
                continue;
            }

            if !{
                let vendors = discovered_vendors.lock().await;
                vendors.contains_key(&base_domain)
            } {
                match whois::get_organization_with_status_and_config(&base_domain, false, 0.5).await
                {
                    Ok(org_result) => {
                        let mut vendors = discovered_vendors.lock().await;
                        vendors.insert(
                            base_domain.clone(),
                            org_normalizer::normalize(&org_result.name),
                        );
                    }
                    Err(_) => {
                        let mut vendors = discovered_vendors.lock().await;
                        vendors
                            .insert(base_domain.clone(), org_normalizer::normalize(&base_domain));
                    }
                }
            }

            let (customer_org, vendor_org) = {
                let vendors = discovered_vendors.lock().await;
                let customer_org = vendors
                    .get(&customer_base_domain)
                    .unwrap_or(&customer_base_domain.to_string())
                    .clone();
                let vendor_org = vendors.get(&base_domain).unwrap_or(&base_domain).clone();
                (customer_org, vendor_org)
            };

            let record_value = build_record_value(
                &vendor_domain_info.source_type,
                &base_domain,
                domain,
                &vendor_domain_info.raw_record,
                &vendor_domain_info.domain,
            );

            let relationship = VendorRelationship::new(
                base_domain.clone(),
                vendor_org,
                current_depth,
                customer_base_domain.clone(),
                customer_org,
                record_value,
                vendor_domain_info.source_type.clone(),
                root_customer_domain.to_string(),
                root_customer_organization.to_string(),
                vendor_domain_info.raw_record.clone(),
            );

            results.push(relationship);

            if !is_common_denominator(&base_domain) {
                let lookup_domain =
                    domain_utils::normalize_for_dns_lookup(&vendor_domain_info.domain);

                if let Ok(sub_results) = Box::pin(discover_nth_parties_minimal(
                    &lookup_domain,
                    max_depth,
                    discovered_vendors.clone(),
                    processed_domains.clone(),
                    semaphore.clone(),
                    current_depth + 1,
                    root_customer_domain,
                    root_customer_organization,
                    verification_logger,
                    dns_pool.clone(),
                    recursive_semaphore.clone(),
                    parallel_jobs,
                    logger.clone(),
                    analysis_config,
                ))
                .await
                {
                    results.extend(sub_results);
                }
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    // P1.3: depth-aware processed gate — the correctness-critical decision.
    #[test]
    fn test_processed_gate_new_domain_claims() {
        assert_eq!(processed_gate_decision(None, 2, true), ProcessedGate::Claim);
    }

    #[test]
    fn test_processed_gate_reached_deeper_or_equal_skips() {
        // Already claimed at depth 2; a reach at depth 2 or 3 is a true duplicate → skip.
        assert_eq!(
            processed_gate_decision(Some(2), 2, true),
            ProcessedGate::Skip
        );
        assert_eq!(
            processed_gate_decision(Some(2), 3, true),
            ProcessedGate::Skip
        );
    }

    #[test]
    fn test_processed_gate_reached_shallower_re_expands() {
        // Claimed deep (3), now reached shallow (1) → re-expand (Claim), not skip.
        // This is the fix for inflated layers + never-discovered grandchildren.
        assert_eq!(
            processed_gate_decision(Some(3), 1, true),
            ProcessedGate::Claim
        );
    }

    #[test]
    fn test_processed_gate_depth_refused_does_not_claim() {
        // New domain but over budget → DepthRefused (not inserted, may return within budget).
        assert_eq!(
            processed_gate_decision(None, 4, false),
            ProcessedGate::DepthRefused
        );
        // But an already-claimed domain still Skips even when over budget (the claim wins).
        assert_eq!(
            processed_gate_decision(Some(2), 4, false),
            ProcessedGate::Skip
        );
    }

    // P1.4: org-resolution singleflight — the compute runs once per base; later callers get
    // the same value without re-running it.
    #[tokio::test]
    async fn test_resolve_org_once_coalesces() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let d = ScanDedup::new();
        let runs = AtomicUsize::new(0);

        let first = d
            .resolve_org_once("stripe.com", || async {
                runs.fetch_add(1, Ordering::SeqCst);
                "Stripe".to_string()
            })
            .await;
        assert_eq!(first, "Stripe");
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        // Second call for the same base must NOT run compute — returns the cached value.
        let second = d
            .resolve_org_once("stripe.com", || async {
                runs.fetch_add(1, Ordering::SeqCst);
                "SHOULD-NOT-RUN".to_string()
            })
            .await;
        assert_eq!(second, "Stripe", "coalesced value must equal the first");
        assert_eq!(runs.load(Ordering::SeqCst), 1, "compute ran only once");

        // A different base runs its own compute.
        let other = d
            .resolve_org_once("vanta.com", || async {
                runs.fetch_add(1, Ordering::SeqCst);
                "Vanta".to_string()
            })
            .await;
        assert_eq!(other, "Vanta");
        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    // P1.5: apex-scoped dedup claims — first claim runs, later claims skip; per-method
    // independent; per-apex independent.
    #[tokio::test]
    async fn test_scan_dedup_claim_semantics() {
        let d = ScanDedup::new();
        // First claim of an apex for a method returns true (run); second returns false (skip).
        assert!(d.claim_subfinder("vanta.com").await, "first claim runs");
        assert!(!d.claim_subfinder("vanta.com").await, "second claim skips");
        // A different apex is independent.
        assert!(d.claim_subfinder("stripe.com").await);
        // A different method for the same apex is independent.
        assert!(d.claim_ct("vanta.com").await, "ct is a separate memo");
        assert!(d.claim_saas("vanta.com").await, "saas is a separate memo");
        assert!(!d.claim_ct("vanta.com").await);
        assert!(!d.claim_saas("vanta.com").await);
    }

    #[test]
    fn test_is_common_denominator_new_google_domains() {
        assert!(is_common_denominator("googletagmanager.com"));
        assert!(is_common_denominator("googlehosted.com"));
        assert!(is_common_denominator("googlesyndication.com"));
        assert!(is_common_denominator("googleadservices.com"));
        assert!(is_common_denominator("googleusercontent.com"));
        assert!(is_common_denominator("googleapis.com"));
    }

    #[test]
    fn test_is_common_denominator_cloudflare_dns() {
        assert!(is_common_denominator("cloudflare-dns.com"));
        assert!(is_common_denominator("sub.cloudflare-dns.com"));
    }

    #[test]
    fn test_is_common_denominator_subdomains() {
        assert!(is_common_denominator("tag.googletagmanager.com"));
        assert!(is_common_denominator("storage.googleapis.com"));
        assert!(is_common_denominator("cdn.cloudflare-dns.com"));
    }

    #[test]
    fn test_is_common_denominator_non_matches() {
        assert!(!is_common_denominator("stripe.com"));
        assert!(!is_common_denominator("pendo.io"));
        assert!(!is_common_denominator("notgoogletagmanager.com"));
    }

    #[test]
    fn test_is_common_denominator_all_entries() {
        let all = vec![
            "amazon.com",
            "amazonaws.com",
            "microsoft.com",
            "google.com",
            "cloudflare.com",
            "fastly.com",
            "akamai.com",
            "azure.com",
            "office365.com",
            "outlook.com",
            "googlemail.com",
            "gmail.com",
        ];
        for domain in all {
            assert!(
                is_common_denominator(domain),
                "Expected {} to be common denominator",
                domain
            );
        }
    }

    #[test]
    fn test_is_common_denominator_deep_subdomains() {
        assert!(is_common_denominator("a.b.c.amazonaws.com"));
        assert!(is_common_denominator("deep.nested.google.com"));
    }

    #[test]
    fn test_is_likely_inferred_org_basic() {
        assert!(is_likely_inferred_org("myklpages.com", "Myklpages Inc."));
        assert!(is_likely_inferred_org("example.com", "example"));
        assert!(is_likely_inferred_org("test.com", "test.com"));
    }

    #[test]
    fn test_subprocessor_skip_decision() {
        let mut attempted = HashMap::new();

        // Unknown org → never skip (fail toward recall), nothing claimed.
        assert!(!subprocessor_skip_decision(None, 3, &mut attempted));
        assert!(attempted.is_empty());

        // Implausible org (a tagline / redaction) → never skip.
        assert!(!subprocessor_skip_decision(
            Some("Redacted for Privacy"),
            3,
            &mut attempted
        ));
        assert!(attempted.is_empty());

        // Generic placeholder → never skip (would mass-collide unrelated domains).
        assert!(!subprocessor_skip_decision(
            Some("Unknown"),
            3,
            &mut attempted
        ));
        assert!(attempted.is_empty());

        // First real org (slack.com's "Slack") → claim it and run.
        assert!(!subprocessor_skip_decision(
            Some("Slack"),
            1,
            &mut attempted
        ));
        // A secondary domain of the same org below the root → skip (the reported waste).
        assert!(subprocessor_skip_decision(Some("Slack"), 2, &mut attempted));
        assert!(subprocessor_skip_decision(Some("Slack"), 3, &mut attempted));
        // Case-variant of the same org still dedups to the same key.
        assert!(subprocessor_skip_decision(Some("SLACK"), 2, &mut attempted));

        // Same org at depth 1 (a direct vendor) always runs — the root layer is never skipped.
        assert!(!subprocessor_skip_decision(
            Some("Slack"),
            1,
            &mut attempted
        ));

        // A different real org → claimed independently and runs.
        assert!(!subprocessor_skip_decision(
            Some("Stripe"),
            2,
            &mut attempted
        ));
    }

    // P4.7: a deep satellite claiming an org first must NOT suppress the shallower primary —
    // a strictly shallower reach re-claims and runs.
    #[test]
    fn test_subprocessor_skip_decision_shallower_primary_re_runs() {
        let mut attempted = HashMap::new();
        // Deep satellite (slack.design at depth 3) claims "Slack" first → runs.
        assert!(!subprocessor_skip_decision(
            Some("Slack"),
            3,
            &mut attempted
        ));
        // The shallower PRIMARY (slack.com at depth 2) must RUN, not be skipped — it re-claims.
        assert!(
            !subprocessor_skip_decision(Some("Slack"), 2, &mut attempted),
            "shallower primary must run, not be suppressed by the deep satellite"
        );
        // Now a depth-3 reach is redundant (claimed at 2) → skip.
        assert!(subprocessor_skip_decision(Some("Slack"), 3, &mut attempted));
        // And an even shallower depth-1 direct vendor still runs.
        assert!(!subprocessor_skip_decision(
            Some("Slack"),
            1,
            &mut attempted
        ));
    }

    #[test]
    fn test_is_likely_inferred_org_suffixes() {
        assert!(is_likely_inferred_org("acme.com", "acme llc"));
        assert!(is_likely_inferred_org("acme.com", "acme corp"));
        assert!(is_likely_inferred_org("acme.com", "acme corporation"));
        assert!(is_likely_inferred_org("acme.com", "acme company"));
        assert!(is_likely_inferred_org("acme.com", "acme co"));
        assert!(is_likely_inferred_org("acme.com", "acme ltd"));
        assert!(is_likely_inferred_org("acme.com", "acme, inc"));
        assert!(is_likely_inferred_org("acme.com", "acme, inc."));
    }

    #[test]
    fn test_is_likely_inferred_org_not_inferred() {
        assert!(!is_likely_inferred_org("google.com", "Alphabet Inc."));
        assert!(!is_likely_inferred_org(
            "aws.amazon.com",
            "Amazon Web Services"
        ));
        assert!(!is_likely_inferred_org(
            "stripe.com",
            "Payment Processing Corp"
        ));
    }

    #[test]
    fn test_is_likely_inferred_org_case_insensitive() {
        assert!(is_likely_inferred_org("TestDomain.com", "testdomain inc."));
        assert!(is_likely_inferred_org("UPPER.com", "upper"));
    }

    #[test]
    fn test_set_and_check_interrupted() {
        // Reset first in case a previous test left it set
        INTERRUPTED.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(!is_interrupted());
        set_interrupted();
        assert!(is_interrupted());
        // Reset for other tests
        INTERRUPTED.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    // ── Additional is_common_denominator tests ─────────────────────────

    #[test]
    fn test_is_common_denominator_empty_string() {
        assert!(!is_common_denominator(""));
    }

    #[test]
    fn test_is_common_denominator_exact_match_only() {
        // "amazonfake.com" should NOT match "amazon.com"
        assert!(!is_common_denominator("amazonfake.com"));
        assert!(!is_common_denominator("notamazon.com"));
        assert!(!is_common_denominator("myamazon.com"));
    }

    #[test]
    fn test_is_common_denominator_prefix_not_subdomain() {
        // "prefixgoogle.com" is not a subdomain of "google.com"
        assert!(!is_common_denominator("prefixgoogle.com"));
        assert!(!is_common_denominator("mycloudflare.com"));
        assert!(!is_common_denominator("notmicrosoft.com"));
    }

    #[test]
    fn test_is_common_denominator_microsoft_and_azure() {
        assert!(is_common_denominator("microsoft.com"));
        assert!(is_common_denominator("azure.com"));
        assert!(is_common_denominator("login.microsoft.com"));
        assert!(is_common_denominator("portal.azure.com"));
    }

    #[test]
    fn test_is_common_denominator_email_services() {
        assert!(is_common_denominator("office365.com"));
        assert!(is_common_denominator("outlook.com"));
        assert!(is_common_denominator("googlemail.com"));
        assert!(is_common_denominator("gmail.com"));
        assert!(is_common_denominator("mail.gmail.com"));
    }

    #[test]
    fn test_is_common_denominator_cdn_providers() {
        assert!(is_common_denominator("fastly.com"));
        assert!(is_common_denominator("akamai.com"));
        assert!(is_common_denominator("cdn.fastly.com"));
        assert!(is_common_denominator("edge.akamai.com"));
    }

    #[test]
    fn test_is_common_denominator_cloud_providers_subdomains() {
        assert!(is_common_denominator("s3.amazonaws.com"));
        assert!(is_common_denominator("ec2.amazonaws.com"));
        assert!(is_common_denominator("us-east-1.amazonaws.com"));
    }

    #[test]
    fn test_is_common_denominator_non_infra_vendors() {
        assert!(!is_common_denominator("stripe.com"));
        assert!(!is_common_denominator("slack.com"));
        assert!(!is_common_denominator("salesforce.com"));
        assert!(!is_common_denominator("zendesk.com"));
        assert!(!is_common_denominator("datadog.com"));
        assert!(!is_common_denominator("twilio.com"));
        assert!(!is_common_denominator("sendgrid.net"));
        assert!(!is_common_denominator("pendo.io"));
        assert!(!is_common_denominator("segment.io"));
    }

    #[test]
    fn test_is_common_denominator_tld_only() {
        assert!(!is_common_denominator("com"));
        assert!(!is_common_denominator(".com"));
    }

    #[test]
    fn test_is_common_denominator_single_label() {
        assert!(!is_common_denominator("localhost"));
        assert!(!is_common_denominator("amazon"));
    }

    // ── Additional is_likely_inferred_org tests ────────────────────────

    #[test]
    fn test_is_likely_inferred_org_empty_org() {
        assert!(!is_likely_inferred_org("example.com", ""));
    }

    #[test]
    fn test_is_likely_inferred_org_domain_equals_org() {
        // Domain itself as org name
        assert!(is_likely_inferred_org("mysite.com", "mysite.com"));
        assert!(is_likely_inferred_org("MYSITE.COM", "mysite.com"));
    }

    #[test]
    fn test_is_likely_inferred_org_base_equals_org() {
        // Just the base domain part matches the org
        assert!(is_likely_inferred_org("acme.com", "acme"));
        assert!(is_likely_inferred_org("acme.co.uk", "acme"));
    }

    #[test]
    fn test_is_likely_inferred_org_inc_variations() {
        assert!(is_likely_inferred_org("acme.com", "Acme Inc."));
        assert!(is_likely_inferred_org("acme.com", "acme inc"));
        assert!(is_likely_inferred_org("acme.com", "ACME INC."));
    }

    #[test]
    fn test_is_likely_inferred_org_real_companies_not_inferred() {
        // Real company names that differ from domain
        assert!(!is_likely_inferred_org("google.com", "Alphabet Inc."));
        assert!(!is_likely_inferred_org(
            "github.com",
            "Microsoft Corporation"
        ));
        assert!(!is_likely_inferred_org(
            "aws.amazon.com",
            "Amazon Web Services, Inc."
        ));
        assert!(!is_likely_inferred_org(
            "azure.com",
            "Microsoft Corporation"
        ));
    }

    #[test]
    fn test_is_likely_inferred_org_unrelated_org() {
        assert!(!is_likely_inferred_org(
            "example.com",
            "Totally Different Company"
        ));
        assert!(!is_likely_inferred_org(
            "test.com",
            "Unrelated Organization LLC"
        ));
    }

    #[test]
    fn test_is_likely_inferred_org_subdomain() {
        // Subdomain: base is the first label
        assert!(is_likely_inferred_org("app.mycompany.com", "app inc."));
        assert!(!is_likely_inferred_org(
            "app.mycompany.com",
            "mycompany inc."
        ));
    }

    #[test]
    fn test_is_likely_inferred_org_hyphenated_domain() {
        // Hyphenated domain: base part is "my-company"
        assert!(is_likely_inferred_org("my-company.com", "my-company inc."));
        assert!(is_likely_inferred_org("my-company.com", "my-company"));
    }

    #[test]
    fn test_is_likely_inferred_org_numeric_domain() {
        assert!(is_likely_inferred_org("123.com", "123"));
        assert!(is_likely_inferred_org("123.com", "123 inc."));
    }

    #[test]
    fn test_is_likely_inferred_org_all_suffix_patterns() {
        // Patterns that use space separator: "base suffix"
        let space_suffixes = vec![
            "inc",
            "inc.",
            "llc",
            "corp",
            "corporation",
            "company",
            "co",
            "ltd",
        ];
        for suffix in space_suffixes {
            let org = format!("testdomain {}", suffix);
            assert!(
                is_likely_inferred_org("testdomain.com", &org),
                "Expected '{}' to be inferred for testdomain.com",
                org
            );
        }
        // Patterns that use comma separator: "base, suffix"
        let comma_suffixes = vec!["inc", "inc."];
        for suffix in comma_suffixes {
            let org = format!("testdomain, {}", suffix);
            assert!(
                is_likely_inferred_org("testdomain.com", &org),
                "Expected '{}' to be inferred for testdomain.com",
                org
            );
        }
    }

    // ── Interrupt flag additional tests ────────────────────────────────

    #[test]
    fn test_interrupted_default_is_false_after_reset() {
        INTERRUPTED.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(!is_interrupted());
    }

    #[test]
    fn test_interrupted_set_and_check() {
        INTERRUPTED.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(!is_interrupted());
        set_interrupted();
        assert!(is_interrupted());
        set_interrupted();
        assert!(is_interrupted());
        INTERRUPTED.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(!is_interrupted());
    }

    // ── is_depth_allowed tests ────────────────────────────────────────

    #[test]
    fn test_depth_allowed_within_limits() {
        assert!(is_depth_allowed(1, Some(5)));
        assert!(is_depth_allowed(5, Some(5)));
        assert!(is_depth_allowed(1, None));
        assert!(is_depth_allowed(10, None));
    }

    #[test]
    fn test_depth_allowed_exceeds_max_depth() {
        assert!(!is_depth_allowed(6, Some(5)));
        assert!(!is_depth_allowed(100, Some(3)));
    }

    #[test]
    fn test_depth_allowed_exceeds_absolute_max() {
        assert!(!is_depth_allowed(11, None));
        assert!(!is_depth_allowed(11, Some(20)));
        assert!(!is_depth_allowed(ABSOLUTE_MAX_DEPTH + 1, None));
    }

    #[test]
    fn test_depth_allowed_at_absolute_max() {
        assert!(is_depth_allowed(ABSOLUTE_MAX_DEPTH, None));
        assert!(is_depth_allowed(
            ABSOLUTE_MAX_DEPTH,
            Some(ABSOLUTE_MAX_DEPTH)
        ));
    }

    #[test]
    fn test_depth_allowed_zero() {
        assert!(is_depth_allowed(0, Some(5)));
        assert!(is_depth_allowed(0, None));
        // max_depth=0 means only depth 0 is allowed
        assert!(is_depth_allowed(0, Some(0)));
        assert!(!is_depth_allowed(1, Some(0)));
    }

    // ── dedup_vendor_domains tests ────────────────────────────────────

    #[test]
    fn test_dedup_vendor_domains_empty() {
        let (deduped, removed) = dedup_vendor_domains(vec![]);
        assert_eq!(deduped.len(), 0);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_dedup_vendor_domains_no_duplicates() {
        let domains = vec![
            dns::VendorDomain {
                domain: "stripe.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "v=spf1 include:stripe.com".to_string(),
            },
            dns::VendorDomain {
                domain: "google.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "v=spf1 include:google.com".to_string(),
            },
        ];
        let (deduped, removed) = dedup_vendor_domains(domains);
        assert_eq!(deduped.len(), 2);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_dedup_vendor_domains_removes_exact_duplicates() {
        let domains = vec![
            dns::VendorDomain {
                domain: "stripe.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "v=spf1 include:stripe.com".to_string(),
            },
            dns::VendorDomain {
                domain: "stripe.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "v=spf1 include:stripe.com".to_string(),
            },
        ];
        let (deduped, removed) = dedup_vendor_domains(domains);
        assert_eq!(deduped.len(), 1);
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_dedup_vendor_domains_different_source_types_kept() {
        let domains = vec![
            dns::VendorDomain {
                domain: "stripe.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "same record".to_string(),
            },
            dns::VendorDomain {
                domain: "stripe.com".to_string(),
                source_type: RecordType::HttpSubprocessor,
                raw_record: "same record".to_string(),
            },
        ];
        let (deduped, removed) = dedup_vendor_domains(domains);
        assert_eq!(deduped.len(), 2);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_dedup_vendor_domains_different_records_kept() {
        let domains = vec![
            dns::VendorDomain {
                domain: "stripe.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "record A".to_string(),
            },
            dns::VendorDomain {
                domain: "stripe.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "record B".to_string(),
            },
        ];
        let (deduped, removed) = dedup_vendor_domains(domains);
        assert_eq!(deduped.len(), 2);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_dedup_vendor_domains_subdomain_dedupes_to_same_base() {
        // sub.stripe.com and stripe.com should dedup to same base
        let domains = vec![
            dns::VendorDomain {
                domain: "sub.stripe.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "same".to_string(),
            },
            dns::VendorDomain {
                domain: "stripe.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "same".to_string(),
            },
        ];
        let (deduped, removed) = dedup_vendor_domains(domains);
        assert_eq!(deduped.len(), 1);
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_dedup_vendor_domains_preserves_first_occurrence() {
        let domains = vec![
            dns::VendorDomain {
                domain: "aaa.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "rec".to_string(),
            },
            dns::VendorDomain {
                domain: "bbb.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "rec".to_string(),
            },
            dns::VendorDomain {
                domain: "aaa.com".to_string(),
                source_type: RecordType::DnsTxtSpf,
                raw_record: "rec".to_string(),
            },
        ];
        let (deduped, removed) = dedup_vendor_domains(domains);
        assert_eq!(deduped.len(), 2);
        assert_eq!(removed, 1);
        assert_eq!(deduped[0].domain, "aaa.com");
        assert_eq!(deduped[1].domain, "bbb.com");
    }

    // ── build_record_value tests ──────────────────────────────────────

    #[test]
    fn test_build_record_value_dns_subdomain() {
        let val = build_record_value(
            &RecordType::DnsSubdomain,
            "example.com",
            "customer.com",
            "raw",
            "vendor.example.com",
        );
        assert_eq!(val, "example.com (base of customer.com)");
    }

    #[test]
    fn test_build_record_value_spf() {
        let val = build_record_value(
            &RecordType::DnsTxtSpf,
            "example.com",
            "customer.com",
            "v=spf1 include:example.com ~all",
            "example.com",
        );
        assert_eq!(val, "v=spf1 include:example.com ~all");
    }

    #[test]
    fn test_build_record_value_dmarc() {
        let val = build_record_value(
            &RecordType::DnsTxtDmarc,
            "example.com",
            "customer.com",
            "v=DMARC1; p=none",
            "example.com",
        );
        assert_eq!(val, "v=DMARC1; p=none");
    }

    #[test]
    fn test_build_record_value_verification() {
        let val = build_record_value(
            &RecordType::DnsTxtVerification,
            "example.com",
            "customer.com",
            "google-site-verification=abc123",
            "example.com",
        );
        assert_eq!(val, "google-site-verification=abc123");
    }

    #[test]
    fn test_build_record_value_dkim() {
        let val = build_record_value(
            &RecordType::DnsTxtDkim,
            "example.com",
            "customer.com",
            "v=DKIM1; k=rsa; p=abc",
            "example.com",
        );
        assert_eq!(val, "v=DKIM1; k=rsa; p=abc");
    }

    #[test]
    fn test_build_record_value_subprocessor() {
        let val = build_record_value(
            &RecordType::HttpSubprocessor,
            "example.com",
            "customer.com",
            "raw record data",
            "vendor.example.com",
        );
        assert_eq!(val, "vendor.example.com");
    }

    #[test]
    fn test_build_record_value_ct_log() {
        let val = build_record_value(
            &RecordType::CtLogDiscovery,
            "example.com",
            "customer.com",
            "cert info",
            "ct.example.com",
        );
        assert_eq!(val, "ct.example.com");
    }

    #[test]
    fn test_build_record_value_saas_tenant() {
        let val = build_record_value(
            &RecordType::SaasTenantProbe,
            "slack.com",
            "customer.com",
            "tenant probe",
            "slack.com",
        );
        assert_eq!(val, "slack.com");
    }

    #[test]
    fn test_build_record_value_subfinder() {
        let val = build_record_value(
            &RecordType::SubfinderDiscovery,
            "cdn.example.com",
            "customer.com",
            "subfinder raw",
            "cdn.example.com",
        );
        assert_eq!(val, "cdn.example.com");
    }

    // ── source_type_label tests ───────────────────────────────────────

    #[test]
    fn test_source_type_label_all_known() {
        assert_eq!(
            source_type_label(&RecordType::HttpSubprocessor),
            "subprocessor"
        );
        assert_eq!(source_type_label(&RecordType::DnsTxtSpf), "SPF");
        assert_eq!(
            source_type_label(&RecordType::DnsTxtVerification),
            "DNS verification"
        );
        assert_eq!(source_type_label(&RecordType::DnsTxtDmarc), "DMARC");
        assert_eq!(
            source_type_label(&RecordType::SubfinderDiscovery),
            "subfinder"
        );
        assert_eq!(
            source_type_label(&RecordType::SaasTenantProbe),
            "SaaS tenant"
        );
        assert_eq!(source_type_label(&RecordType::CtLogDiscovery), "CT log");
    }

    #[test]
    fn test_source_type_label_fallback() {
        assert_eq!(source_type_label(&RecordType::DnsTxtDkim), "discovery");
        assert_eq!(source_type_label(&RecordType::DnsSubdomain), "discovery");
        assert_eq!(source_type_label(&RecordType::Unknown), "discovery");
        assert_eq!(
            source_type_label(&RecordType::WebTrafficSource),
            "discovery"
        );
        assert_eq!(
            source_type_label(&RecordType::WebTrafficNetwork),
            "discovery"
        );
        assert_eq!(source_type_label(&RecordType::TrustCenterApi), "discovery");
    }

    // ── truncate_utf8 tests ───────────────────────────────────────────

    #[test]
    fn test_truncate_utf8_short_string() {
        assert_eq!(truncate_utf8("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_utf8_exact_length() {
        assert_eq!(truncate_utf8("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_utf8_truncates_with_ellipsis() {
        assert_eq!(truncate_utf8("hello world", 5), "hello...");
    }

    #[test]
    fn test_truncate_utf8_empty_string() {
        assert_eq!(truncate_utf8("", 10), "");
    }

    #[test]
    fn test_truncate_utf8_zero_max() {
        assert_eq!(truncate_utf8("hello", 0), "...");
    }

    #[test]
    fn test_truncate_utf8_multibyte_char_boundary() {
        // "café" has a multi-byte é (2 bytes in UTF-8)
        let s = "caf\u{00e9}!"; // "café!"
                                // Truncating at 4 bytes: "caf" + first byte of é is not a boundary
                                // Should back up to 3 bytes: "caf"
        let result = truncate_utf8(s, 4);
        assert!(result.ends_with("..."));
        // The result should be valid UTF-8
        assert!(!result.is_empty());
    }

    // --- ABSOLUTE_MAX_DEPTH constant ---

    #[test]
    fn test_absolute_max_depth_constant() {
        assert_eq!(ABSOLUTE_MAX_DEPTH, 10);
    }

    #[test]
    fn test_truncate_utf8_emoji() {
        let s = "hello 🌍 world";
        let result = truncate_utf8(s, 8);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_utf8_long_raw_record() {
        let long = "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all";
        let result = truncate_utf8(long, 50);
        assert!(result.ends_with("..."));
        // Without the "...", should be at most 50 bytes
        let without_dots = result.trim_end_matches("...");
        assert!(without_dots.len() <= 50);
    }

    // ── apply_vendor_limits tests ─────────────────────────────────────

    fn make_vendor_domains(count: usize) -> Vec<dns::VendorDomain> {
        (0..count)
            .map(|i| dns::VendorDomain {
                domain: format!("vendor{}.com", i),
                source_type: RecordType::DnsTxtSpf,
                raw_record: format!("record {}", i),
            })
            .collect()
    }

    fn make_analysis_config_with_limits(limits: Vec<usize>) -> AnalysisConfig {
        AnalysisConfig {
            strategy: AnalysisStrategy::Limits,
            concurrency_per_depth: vec![50, 20, 10, 5],
            request_delay_ms: 0,
            vendor_limits_per_depth: limits,
            total_vendor_budget: 1000,
        }
    }

    #[test]
    fn test_apply_vendor_limits_unlimited_no_truncation() {
        let domains = make_vendor_domains(100);
        let config = AnalysisConfig {
            strategy: AnalysisStrategy::Unlimited,
            concurrency_per_depth: vec![50],
            request_delay_ms: 0,
            vendor_limits_per_depth: vec![10],
            total_vendor_budget: 1000,
        };
        let (result, removed) =
            apply_vendor_limits(domains, &AnalysisStrategy::Unlimited, &config, 1);
        assert_eq!(result.len(), 100);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_apply_vendor_limits_budget_no_truncation() {
        let domains = make_vendor_domains(100);
        let config = AnalysisConfig {
            strategy: AnalysisStrategy::Budget,
            concurrency_per_depth: vec![50],
            request_delay_ms: 0,
            vendor_limits_per_depth: vec![10],
            total_vendor_budget: 1000,
        };
        let (result, removed) = apply_vendor_limits(domains, &AnalysisStrategy::Budget, &config, 1);
        assert_eq!(result.len(), 100);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_apply_vendor_limits_limits_truncates() {
        let domains = make_vendor_domains(50);
        let config = make_analysis_config_with_limits(vec![20, 10, 5]);
        let (result, removed) = apply_vendor_limits(domains, &AnalysisStrategy::Limits, &config, 1);
        assert_eq!(result.len(), 20);
        assert_eq!(removed, 30);
    }

    #[test]
    fn test_apply_vendor_limits_limits_depth2() {
        let domains = make_vendor_domains(50);
        let config = make_analysis_config_with_limits(vec![20, 10, 5]);
        let (result, removed) = apply_vendor_limits(domains, &AnalysisStrategy::Limits, &config, 2);
        assert_eq!(result.len(), 10);
        assert_eq!(removed, 40);
    }

    #[test]
    fn test_apply_vendor_limits_limits_no_truncation_needed() {
        let domains = make_vendor_domains(5);
        let config = make_analysis_config_with_limits(vec![20, 10, 5]);
        let (result, removed) = apply_vendor_limits(domains, &AnalysisStrategy::Limits, &config, 1);
        assert_eq!(result.len(), 5);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_apply_vendor_limits_empty_input() {
        let domains = vec![];
        let config = make_analysis_config_with_limits(vec![20]);
        let (result, removed) = apply_vendor_limits(domains, &AnalysisStrategy::Limits, &config, 1);
        assert_eq!(result.len(), 0);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_apply_vendor_limits_preserves_order() {
        let domains = make_vendor_domains(10);
        let config = make_analysis_config_with_limits(vec![5]);
        let (result, _) = apply_vendor_limits(domains, &AnalysisStrategy::Limits, &config, 1);
        assert_eq!(result[0].domain, "vendor0.com");
        assert_eq!(result[4].domain, "vendor4.com");
    }

    #[test]
    fn test_apply_vendor_limits_limits_zero_limit_returns_none() {
        // When get_vendor_limit_for_depth returns None (limit is 0), no truncation occurs
        let domains = make_vendor_domains(10);
        let config = make_analysis_config_with_limits(vec![0]);
        let (result, removed) = apply_vendor_limits(domains, &AnalysisStrategy::Limits, &config, 0);
        assert_eq!(result.len(), 10);
        assert_eq!(removed, 0);
    }

    // ── discover_nth_parties_minimal early-return paths ───────────────

    #[tokio::test]
    async fn test_discover_nth_parties_minimal_already_processed() {
        let mut processed = HashSet::new();
        processed.insert("example.com".to_string());
        let processed_domains = Arc::new(tokio::sync::Mutex::new(processed));
        let discovered_vendors = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let semaphore = Arc::new(Semaphore::new(10));
        let recursive_semaphore = Arc::new(Semaphore::new(10));
        let dns_pool = Arc::new(dns::DnsServerPool::new());
        let logger = Arc::new(AnalysisLogger::new(crate::logger::VerbosityLevel::Silent));
        let vl = verification_logger::VerificationFailureLogger::new("/tmp", "test.com", false);
        let config = make_analysis_config_with_limits(vec![20]);

        let result = discover_nth_parties_minimal(
            "example.com",
            Some(3),
            discovered_vendors,
            processed_domains,
            semaphore,
            1,
            "root.com",
            "Root Org",
            &vl,
            dns_pool,
            recursive_semaphore,
            4,
            logger,
            &config,
        )
        .await
        .unwrap();

        assert!(
            result.is_empty(),
            "already-processed domain should return empty"
        );
    }

    #[tokio::test]
    async fn test_discover_nth_parties_minimal_depth_exceeded() {
        let processed_domains = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let discovered_vendors = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let semaphore = Arc::new(Semaphore::new(10));
        let recursive_semaphore = Arc::new(Semaphore::new(10));
        let dns_pool = Arc::new(dns::DnsServerPool::new());
        let logger = Arc::new(AnalysisLogger::new(crate::logger::VerbosityLevel::Silent));
        let vl = verification_logger::VerificationFailureLogger::new("/tmp", "test.com", false);
        let config = make_analysis_config_with_limits(vec![20]);

        let result = discover_nth_parties_minimal(
            "new-domain.com",
            Some(2),
            discovered_vendors,
            processed_domains,
            semaphore,
            5, // current_depth > max_depth (2)
            "root.com",
            "Root Org",
            &vl,
            dns_pool,
            recursive_semaphore,
            4,
            logger,
            &config,
        )
        .await
        .unwrap();

        assert!(result.is_empty(), "depth-exceeded should return empty");
    }

    // ── subprocessor_analysis_with_logging ────────────────────────────

    #[tokio::test]
    #[ignore = "live network: resolves a nonexistent name; kills the sfw cargo wrapper (CLAUDE.md)"]
    async fn test_subprocessor_analysis_with_logging_invalid_domain() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = Arc::new(AnalysisLogger::new(crate::logger::VerbosityLevel::Silent));
        let vl = verification_logger::VerificationFailureLogger::new("/tmp", "test.com", false);

        let result = subprocessor_analysis_with_logging(
            "nonexistent.invalid.domain.test",
            &vl,
            logger,
            &analyzer,
        )
        .await;

        // Should return Ok (errors are swallowed) with empty or populated vec
        assert!(result.is_ok());
    }

    // ── Phase-function extraction tests ──────────────────────────────

    #[test]
    fn test_add_base_domain_if_subdomain_returns_some() {
        let result = add_base_domain_if_subdomain("mail.example.com", "example.com");
        assert!(result.is_some());
        let vd = result.unwrap();
        assert_eq!(vd.domain, "example.com");
        assert_eq!(vd.source_type, RecordType::DnsSubdomain);
        assert!(vd.raw_record.contains("mail.example.com"));
        assert!(vd.raw_record.contains("example.com"));
    }

    #[test]
    fn test_add_base_domain_if_subdomain_returns_none_when_same() {
        let result = add_base_domain_if_subdomain("example.com", "example.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_convert_subprocessor_domains_field_mapping() {
        let input = vec![
            subprocessor::SubprocessorDomain {
                domain: "stripe.com".to_string(),
                source_type: RecordType::HttpSubprocessor,
                raw_record: "Found on /subprocessors page".to_string(),
            },
            subprocessor::SubprocessorDomain {
                domain: "twilio.com".to_string(),
                source_type: RecordType::HttpSubprocessor,
                raw_record: "Found on /privacy page".to_string(),
            },
        ];
        let result = convert_subprocessor_domains(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "stripe.com");
        assert_eq!(result[0].source_type, RecordType::HttpSubprocessor);
        assert_eq!(result[0].raw_record, "Found on /subprocessors page");
        assert_eq!(result[1].domain, "twilio.com");
    }

    #[test]
    fn test_convert_subprocessor_domains_empty() {
        let result = convert_subprocessor_domains(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_subfinder_results_filters_same_base() {
        let subdomain_results = vec![(
            "mail.example.com".to_string(),
            "certspotter".to_string(),
            vec![
                dns::VendorDomain {
                    domain: "example.com".to_string(), // same base — should be filtered
                    source_type: RecordType::DnsTxtSpf,
                    raw_record: "v=spf1".to_string(),
                },
                dns::VendorDomain {
                    domain: "sendgrid.net".to_string(), // different base — kept
                    source_type: RecordType::DnsTxtSpf,
                    raw_record: "v=spf1 include:sendgrid.net".to_string(),
                },
            ],
            vec![],
        )];
        let (result, txt_count, cname_count) =
            filter_subfinder_results(subdomain_results, "example.com");
        assert_eq!(result.len(), 1);
        assert_eq!(txt_count, 1);
        assert_eq!(cname_count, 0);
        assert_eq!(result[0].domain, "sendgrid.net");
        assert!(result[0].raw_record.contains("mail.example.com"));
        assert!(result[0].raw_record.contains("certspotter"));
    }

    #[test]
    fn test_filter_subfinder_results_includes_cname_cross_domain() {
        let subdomain_results = vec![(
            "app.example.com".to_string(),
            "subfinder".to_string(),
            vec![],
            vec![
                (
                    "app.example.com.cdn.cloudfront.net".to_string(),
                    "cloudfront.net".to_string(),
                ),
                (
                    "app.example.com.example.com".to_string(),
                    "example.com".to_string(),
                ),
            ],
        )];
        let (result, txt_count, cname_count) =
            filter_subfinder_results(subdomain_results, "example.com");
        // Both CNAMEs are counted (the function doesn't filter by base for CNAMEs)
        assert_eq!(cname_count, 2);
        assert_eq!(txt_count, 0);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "cloudfront.net");
        assert_eq!(result[0].source_type, RecordType::SubfinderDiscovery);
        assert!(result[0].raw_record.contains("CNAMEs to"));
    }

    #[test]
    fn test_filter_subfinder_results_empty_input() {
        let (result, txt, cname) = filter_subfinder_results(vec![], "example.com");
        assert!(result.is_empty());
        assert_eq!(txt, 0);
        assert_eq!(cname, 0);
    }

    #[test]
    fn test_filter_confirmed_tenants_only_confirmed_and_likely() {
        use crate::discovery::saas_tenant::TenantProbeResult;
        let tenants = vec![
            TenantProbeResult {
                platform_name: "Slack".to_string(),
                vendor_domain: "slack.com".to_string(),
                tenant_url: "https://example.slack.com".to_string(),
                status: TenantStatus::Confirmed,
                evidence: "HTTP 200".to_string(),
            },
            TenantProbeResult {
                platform_name: "Jira".to_string(),
                vendor_domain: "atlassian.com".to_string(),
                tenant_url: "https://example.atlassian.net".to_string(),
                status: TenantStatus::Likely,
                evidence: "redirect".to_string(),
            },
            TenantProbeResult {
                platform_name: "Notion".to_string(),
                vendor_domain: "notion.so".to_string(),
                tenant_url: "https://example.notion.site".to_string(),
                status: TenantStatus::NotFound,
                evidence: "HTTP 404".to_string(),
            },
            TenantProbeResult {
                platform_name: "Linear".to_string(),
                vendor_domain: "linear.app".to_string(),
                tenant_url: "https://linear.app/example".to_string(),
                status: TenantStatus::Unknown,
                evidence: "timeout".to_string(),
            },
        ];
        let result = filter_confirmed_tenants(&tenants);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "slack.com");
        assert_eq!(result[0].source_type, RecordType::SaasTenantProbe);
        assert!(result[0].raw_record.contains("Confirmed"));
        assert_eq!(result[1].domain, "atlassian.com");
        assert!(result[1].raw_record.contains("Likely"));
    }

    #[test]
    fn test_filter_confirmed_tenants_empty_when_all_not_found() {
        use crate::discovery::saas_tenant::TenantProbeResult;
        let tenants = vec![TenantProbeResult {
            platform_name: "Notion".to_string(),
            vendor_domain: "notion.so".to_string(),
            tenant_url: "https://example.notion.site".to_string(),
            status: TenantStatus::NotFound,
            evidence: "404".to_string(),
        }];
        let result = filter_confirmed_tenants(&tenants);
        assert!(result.is_empty());
    }

    #[test]
    fn test_convert_ct_results_maps_fields() {
        use crate::discovery::ct_logs::CtDiscoveryResult;
        let input = vec![
            CtDiscoveryResult {
                domain: "cdn.vendor.com".to_string(),
                source: "crt.sh".to_string(),
                certificate_info: "CN=*.vendor.com, Issuer=Let's Encrypt".to_string(),
            },
            CtDiscoveryResult {
                domain: "api.other.io".to_string(),
                source: "crt.sh".to_string(),
                certificate_info: "CN=api.other.io".to_string(),
            },
        ];
        let result = convert_ct_results(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "cdn.vendor.com");
        assert_eq!(result[0].source_type, RecordType::CtLogDiscovery);
        assert_eq!(
            result[0].raw_record,
            "CN=*.vendor.com, Issuer=Let's Encrypt"
        );
        assert_eq!(result[1].domain, "api.other.io");
    }

    #[test]
    fn test_convert_web_traffic_results_maps_source_types() {
        let input = vec![
            WebTrafficResult {
                vendor_domain: "pendo.io".to_string(),
                source: WebTrafficSource::PageSource,
                evidence: "<script src=\"https://cdn.pendo.io/agent.js\">".to_string(),
            },
            WebTrafficResult {
                vendor_domain: "segment.io".to_string(),
                source: WebTrafficSource::NetworkTraffic,
                evidence: "XHR to https://api.segment.io/v1/track".to_string(),
            },
        ];
        let result = convert_web_traffic_results(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "pendo.io");
        assert_eq!(result[0].source_type, RecordType::WebTrafficSource);
        assert!(result[0].raw_record.contains("pendo.io"));
        assert_eq!(result[1].domain, "segment.io");
        assert_eq!(result[1].source_type, RecordType::WebTrafficNetwork);
    }

    #[test]
    fn test_compute_buffer_size_minimum_is_two() {
        assert_eq!(compute_buffer_size(1, 1), 2);
        assert_eq!(compute_buffer_size(0, 0), 2);
        assert_eq!(compute_buffer_size(1, 100), 2);
    }

    #[test]
    fn test_compute_buffer_size_takes_min_of_inputs() {
        assert_eq!(compute_buffer_size(10, 5), 5);
        assert_eq!(compute_buffer_size(5, 10), 5);
        assert_eq!(compute_buffer_size(50, 50), 50);
    }

    /// `--parallel-jobs 0` is the default and means "no operator cap": the configured
    /// per-depth concurrency must reach the stream unchanged. Before this, the flag's
    /// default of 10 was always min'd in, so `concurrency_per_depth = [50, 20, 10, 5]`
    /// silently ran 10/10/10/5.
    #[test]
    fn test_compute_buffer_size_zero_jobs_means_no_operator_cap() {
        assert_eq!(compute_buffer_size(50, 0), 50, "depth-1 configured width");
        assert_eq!(compute_buffer_size(20, 0), 20, "depth-2 configured width");
        assert_eq!(compute_buffer_size(5, 0), 5, "depth-4 configured width");
        // The floor still applies when the configured value is degenerate.
        assert_eq!(compute_buffer_size(1, 0), 2);
    }

    /// An explicit `-j N` still narrows the configured width, and never widens it.
    #[test]
    fn test_compute_buffer_size_explicit_jobs_only_narrows() {
        assert_eq!(
            compute_buffer_size(50, 4),
            4,
            "operator cap wins when lower"
        );
        assert_eq!(
            compute_buffer_size(5, 100),
            5,
            "operator cap never widens beyond the configured value"
        );
    }

    #[test]
    fn test_compute_progress_position_boundaries() {
        // First vendor (index 0) of 10: 30 + (1*70)/10 = 37
        assert_eq!(compute_progress_position(0, 10), 37);
        // Last vendor (index 9) of 10: 30 + (10*70)/10 = 100
        assert_eq!(compute_progress_position(9, 10), 100);
        // Single vendor: 30 + (1*70)/1 = 100
        assert_eq!(compute_progress_position(0, 1), 100);
        // Middle vendor (index 4) of 10: 30 + (5*70)/10 = 65
        assert_eq!(compute_progress_position(4, 10), 65);
    }

    #[test]
    fn test_should_checkpoint_every_5_and_final() {
        assert!(should_checkpoint(5, 100));
        assert!(should_checkpoint(10, 100));
        assert!(should_checkpoint(15, 100));
        assert!(!should_checkpoint(1, 100));
        assert!(!should_checkpoint(3, 100));
        assert!(!should_checkpoint(7, 100));
        // Final vendor always checkpoints
        assert!(should_checkpoint(13, 13));
        assert!(should_checkpoint(1, 1));
    }

    #[test]
    fn test_compute_pressure_delay_ms_tiers() {
        assert_eq!(compute_pressure_delay_ms(0), 0);
        assert_eq!(compute_pressure_delay_ms(1), 25);
        assert_eq!(compute_pressure_delay_ms(2), 250);
        assert_eq!(compute_pressure_delay_ms(3), 250);
        assert_eq!(compute_pressure_delay_ms(255), 250);
    }

    #[test]
    fn test_should_skip_self_reference_same_base() {
        assert!(should_skip_self_reference(
            "mail.example.com",
            "example.com"
        ));
        assert!(should_skip_self_reference("example.com", "www.example.com"));
        assert!(should_skip_self_reference("example.com", "example.com"));
    }

    #[test]
    fn test_should_skip_self_reference_different_base() {
        assert!(!should_skip_self_reference("stripe.com", "example.com"));
        assert!(!should_skip_self_reference(
            "mail.google.com",
            "example.com"
        ));
    }

    // ── GRC-501: marketing/tracking + self-alias classifiers ────────

    #[test]
    fn test_is_marketing_tracking_domain_positive() {
        for d in [
            "facebook.com",
            "connect.facebook.net",
            "licdn.com",
            "ads-twitter.com",
            "tiktok.com",
            "redditstatic.com",
            "snapchat.com",
            "sc-static.net",
            "doubleclick.net",
            "stats.g.doubleclick.net",
        ] {
            assert!(is_marketing_tracking_domain(d), "expected marketing: {d}");
        }
    }

    #[test]
    fn test_is_marketing_tracking_domain_negative() {
        // Real subprocessors / unrelated domains must not match.
        for d in ["stripe.com", "github.com", "notfacebook.com", "example.com"] {
            assert!(!is_marketing_tracking_domain(d), "unexpected match: {d}");
        }
    }

    #[test]
    fn test_is_known_self_alias_matches_group() {
        // Klaviyo landing/alt domains resolve to the same org.
        assert!(is_known_self_alias("myklpages.com", "klaviyo.com"));
        assert!(is_known_self_alias("www.myklpages.com", "klaviyo.com"));
        assert!(is_known_self_alias("klaviyomail.com", "klaviyo.com"));
        // MarkMonitor registrar landing domain.
        assert!(is_known_self_alias("saasbee.com", "markmonitor.com"));
    }

    #[test]
    fn test_is_known_self_alias_non_matches() {
        // Different orgs, and exact base matches (handled elsewhere), are false.
        assert!(!is_known_self_alias("stripe.com", "klaviyo.com"));
        assert!(!is_known_self_alias("klaviyo.com", "klaviyo.com"));
        assert!(!is_known_self_alias("myklpages.com", "markmonitor.com"));
    }

    #[test]
    fn test_should_skip_self_reference_known_alias() {
        // The alias map extends self-reference suppression beyond exact base.
        assert!(should_skip_self_reference("myklpages.com", "klaviyo.com"));
        assert!(should_skip_self_reference("saasbee.com", "markmonitor.com"));
        // A genuine third party is still kept.
        assert!(!should_skip_self_reference("pendo.io", "klaviyo.com"));
    }

    #[test]
    fn test_resolve_orgs_from_vendors_with_entries() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), "Example Inc.".to_string());
        map.insert("stripe.com".to_string(), "Stripe, Inc.".to_string());
        let (customer_org, vendor_org) =
            resolve_orgs_from_vendors(&map, "example.com", "stripe.com");
        assert_eq!(customer_org, "Example Inc.");
        assert_eq!(vendor_org, "Stripe, Inc.");
    }

    #[test]
    fn test_resolve_orgs_from_vendors_with_fallback() {
        let map = HashMap::new(); // empty
        let (customer_org, vendor_org) =
            resolve_orgs_from_vendors(&map, "example.com", "stripe.com");
        assert_eq!(customer_org, "example.com");
        assert_eq!(vendor_org, "stripe.com");
    }

    #[test]
    fn test_resolve_orgs_from_vendors_partial_entries() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), "Example Corp".to_string());
        let (customer_org, vendor_org) =
            resolve_orgs_from_vendors(&map, "example.com", "unknown.io");
        assert_eq!(customer_org, "Example Corp");
        assert_eq!(vendor_org, "unknown.io"); // fallback
    }

    #[test]
    fn test_should_stop_at_common_denominator_combinations() {
        // No max_depth + common denominator → stop
        assert!(should_stop_at_common_denominator(None, "google.com"));
        assert!(should_stop_at_common_denominator(None, "amazonaws.com"));
        // No max_depth + NOT common denominator → don't stop
        assert!(!should_stop_at_common_denominator(None, "stripe.com"));
        // With max_depth (even if common denominator) → don't stop (depth controls recursion)
        assert!(!should_stop_at_common_denominator(Some(3), "google.com"));
        assert!(!should_stop_at_common_denominator(Some(5), "stripe.com"));
    }

    // ── P3.4 time-debounced checkpointing ──────────────────────────────

    #[test]
    fn test_should_checkpoint_now_debounces_by_time_but_never_skips_the_final_save() {
        let iv = Duration::from_secs(30);

        // The save a resumed scan actually reads is the LAST one. It must happen even if the
        // previous save was moments ago, or a debounce would trade real resume fidelity for nothing.
        assert!(should_checkpoint_now(10, 10, Duration::ZERO, iv));
        assert!(should_checkpoint_now(1, 1, Duration::from_millis(1), iv));

        // Mid-scan, inside the interval: skip. This is the whole point — the old every-5-completions
        // cadence fired constantly at depth 3 and serialized the pipeline behind an fsync.
        assert!(!should_checkpoint_now(5, 100, Duration::ZERO, iv));
        assert!(!should_checkpoint_now(50, 100, Duration::from_secs(29), iv));

        // Interval elapsed: save.
        assert!(should_checkpoint_now(50, 100, Duration::from_secs(30), iv));
        assert!(should_checkpoint_now(7, 100, Duration::from_secs(120), iv));

        // vendor_count == 0 must not read as "final completion" for a 0-progress scan; only the
        // elapsed interval can trigger it.
        assert!(!should_checkpoint_now(0, 0, Duration::ZERO, iv));
        assert!(should_checkpoint_now(0, 0, Duration::from_secs(31), iv));
    }

    // ── P4.8 infra-enumeration gate ────────────────────────────────────

    #[test]
    fn test_should_gate_infra_enumeration_depth_and_classification() {
        // Depth >=2 AND infra → gate the enumeration fan-out.
        assert!(should_gate_infra_enumeration(2, "amazonaws.com"));
        assert!(should_gate_infra_enumeration(3, "cloudflare.com"));
        assert!(should_gate_infra_enumeration(4, "akamai.com"));

        // Depth 1 (the scan root and, per this codebase's 1-indexing, the root pass) is NEVER
        // gated — the root is always fully enumerated even if it were infra.
        assert!(!should_gate_infra_enumeration(1, "amazonaws.com"));
        assert!(!should_gate_infra_enumeration(0, "cloudflare.com"));

        // A real vendor (non-infra) is never gated at any depth — its subdomains ARE candidate
        // nth-parties, so recall must be preserved.
        assert!(!should_gate_infra_enumeration(2, "stripe.com"));
        assert!(!should_gate_infra_enumeration(3, "datadog.com"));
        assert!(!should_gate_infra_enumeration(5, "sendgrid.net"));
    }

    #[test]
    fn test_should_gate_infra_enumeration_is_depth_gated_not_blanket() {
        // The same infra root: gated at depth 2+, fully enumerated at depth 1. This is the exact
        // difference from should_stop_at_common_denominator, which only fires for unbounded scans.
        assert!(!should_gate_infra_enumeration(1, "googleapis.com"));
        assert!(should_gate_infra_enumeration(2, "googleapis.com"));
    }

    // ── P3.6 whole-domain working-time ceiling ─────────────────────────

    #[test]
    fn test_domain_ceiling_never_truncates_the_scan_root() {
        // The root's own enumeration is what the whole report is built on, and it is also the run
        // that most legitimately takes minutes. No amount of elapsed time may cut it.
        assert_eq!(
            domain_ceiling_decision(
                1,
                Duration::from_secs(3600),
                Duration::ZERO,
                DOMAIN_WORK_CEILING
            ),
            DomainCeiling::Exempt
        );
        assert_eq!(
            domain_ceiling_decision(
                0,
                Duration::from_secs(3600),
                Duration::ZERO,
                DOMAIN_WORK_CEILING
            ),
            DomainCeiling::Exempt
        );
    }

    #[test]
    fn test_domain_ceiling_zero_disables_enforcement() {
        // A zero ceiling is the off switch, and it must be off at every depth — not "expires
        // immediately", which would truncate every method of every domain in the scan.
        assert_eq!(
            domain_ceiling_decision(7, Duration::from_secs(600), Duration::ZERO, Duration::ZERO),
            DomainCeiling::Exempt
        );
    }

    #[test]
    fn test_domain_ceiling_measures_work_not_queue_depth() {
        // The load-bearing property: identical wall-clock, opposite verdicts, decided purely by
        // how much of that wall clock was spent queued. Without the subtraction the ceiling would
        // fire in proportion to how busy the machine is and recall would depend on scan
        // concurrency — the failure mode `browser_wait_nanos` exists to prevent one layer down.
        let elapsed = Duration::from_secs(200);
        assert_eq!(
            domain_ceiling_decision(
                2,
                elapsed,
                Duration::from_secs(190),
                Duration::from_secs(90)
            ),
            DomainCeiling::Within(Duration::from_secs(80))
        );
        assert_eq!(
            domain_ceiling_decision(2, elapsed, Duration::ZERO, Duration::from_secs(90)),
            DomainCeiling::Exhausted
        );
    }

    #[test]
    fn test_domain_ceiling_boundary_is_exhausted_exactly_at_the_ceiling() {
        let ceiling = Duration::from_secs(90);
        // One nanosecond of budget left is still budget — the phase gets polled.
        assert_eq!(
            domain_ceiling_decision(
                2,
                ceiling - Duration::from_nanos(1),
                Duration::ZERO,
                ceiling
            ),
            DomainCeiling::Within(Duration::from_nanos(1))
        );
        // Exactly spent is spent; a zero-length remaining budget must not be reported as Within,
        // or the watchdog would arm a zero timer and busy-loop instead of cutting.
        assert_eq!(
            domain_ceiling_decision(2, ceiling, Duration::ZERO, ceiling),
            DomainCeiling::Exhausted
        );
        assert_eq!(
            domain_ceiling_decision(2, ceiling + Duration::from_secs(1), Duration::ZERO, ceiling),
            DomainCeiling::Exhausted
        );
    }

    #[test]
    fn test_domain_ceiling_saturates_when_credited_queue_exceeds_elapsed() {
        // Two concurrent sub-steps can each credit their own wait, so credited queue time can
        // exceed the unit's wall clock. That must read as "all of it was queue" and leave the full
        // budget, never underflow.
        assert_eq!(
            domain_ceiling_decision(
                3,
                Duration::from_secs(10),
                Duration::from_secs(45),
                Duration::from_secs(90)
            ),
            DomainCeiling::Within(Duration::from_secs(90))
        );
    }

    #[test]
    fn test_domain_ceiling_enforced_from_depth_two_onwards() {
        // Depth 2 is the first layer the ceiling applies to — the same boundary P4.8's
        // enumeration gate uses, so the two mechanisms carve the root out identically.
        //
        // `spent` is derived from the ceiling rather than hard-coded: DOMAIN_WORK_CEILING is an
        // explicitly tunable value (it was re-sized once already, after field measurement showed
        // the original figure was clipping the body of the distribution instead of its tail). A
        // literal here would make a legitimate re-tune look like a broken test, which is exactly
        // the kind of false signal that trains people to edit assertions to make them pass.
        let spent = DOMAIN_WORK_CEILING + Duration::from_secs(30);
        assert_eq!(
            domain_ceiling_decision(1, spent, Duration::ZERO, DOMAIN_WORK_CEILING),
            DomainCeiling::Exempt
        );
        for depth in 2..=6 {
            assert_eq!(
                domain_ceiling_decision(depth, spent, Duration::ZERO, DOMAIN_WORK_CEILING),
                DomainCeiling::Exhausted,
                "depth {} must be enforced",
                depth
            );
        }
    }

    #[test]
    fn test_work_clock_credit_is_subtracted_from_the_budget() {
        let clock = DomainWorkClock::start();
        clock.credit_queue(Duration::from_secs(3600));
        assert_eq!(clock.queued(), Duration::from_secs(3600));
        // The clock has been alive for microseconds of test time, all of it covered by the
        // credited hour, so the domain must still hold every bit of its budget.
        assert_eq!(
            clock.decide(3, DOMAIN_WORK_CEILING),
            DomainCeiling::Within(DOMAIN_WORK_CEILING)
        );
    }

    #[test]
    fn test_work_clock_queue_credit_saturates_instead_of_wrapping() {
        let clock = DomainWorkClock::start();
        clock.credit_queue(Duration::MAX);
        clock.credit_queue(Duration::MAX);
        // A wrapped total would read as near-zero queue time, so the ceiling would fire earliest
        // on the most-starved domain — the exact inversion of what the subtraction is for.
        assert_eq!(clock.queued(), Duration::from_nanos(u64::MAX));
    }

    #[tokio::test]
    async fn test_phase_within_domain_budget_cuts_a_starved_phase_but_keeps_a_ready_one() {
        let clock = DomainWorkClock::start();
        let coverage = crate::coverage::PhaseCoverage::default();
        let logger = Arc::new(AnalysisLogger::new(crate::logger::VerbosityLevel::Silent));
        let tiny = Duration::from_millis(20);

        // A method that cannot answer inside the budget yields nothing rather than blocking the
        // domain forever.
        let cut = phase_within_domain_budget(
            async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                make_vendor_domains(3)
            },
            Some((&clock, 3, tiny)),
            &coverage,
            "test",
            "example.com",
            &logger,
        )
        .await;
        assert!(
            cut.is_empty(),
            "a starved phase must not return partial results"
        );

        // The budget is now spent, yet a method that is already ready still wins: `biased` polls
        // the phase first, which is what keeps a disabled method (an instant empty Vec) from being
        // reported as starved, and keeps a phase that lands on the deadline's own wakeup.
        let kept = phase_within_domain_budget(
            async { make_vendor_domains(2) },
            Some((&clock, 3, tiny)),
            &coverage,
            "test",
            "example.com",
            &logger,
        )
        .await;
        assert_eq!(kept.len(), 2, "a ready phase must keep everything it found");
    }

    #[tokio::test]
    async fn test_phase_within_domain_budget_never_truncates_the_scan_root() {
        // Even handed an already-blown budget, depth 1 waits for the real answer. The exemption
        // has to hold at the enforcement site, not only in the pure decision.
        let clock = DomainWorkClock::start();
        let coverage = crate::coverage::PhaseCoverage::default();
        let logger = Arc::new(AnalysisLogger::new(crate::logger::VerbosityLevel::Silent));

        let kept = phase_within_domain_budget(
            async {
                tokio::time::sleep(Duration::from_millis(40)).await;
                make_vendor_domains(4)
            },
            Some((&clock, 1, Duration::from_nanos(1))),
            &coverage,
            "test",
            "root.example.com",
            &logger,
        )
        .await;
        assert_eq!(kept.len(), 4, "the scan root's own layer must never be cut");
    }

    #[tokio::test]
    async fn test_phase_within_domain_budget_without_a_budget_runs_to_completion() {
        // The exempt path takes no timer and no select at all, so this pins the behaviour the
        // depth-1 hot path relies on: identical to calling the phase directly.
        let coverage = crate::coverage::PhaseCoverage::default();
        let logger = Arc::new(AnalysisLogger::new(crate::logger::VerbosityLevel::Silent));

        let kept = phase_within_domain_budget(
            async {
                tokio::time::sleep(Duration::from_millis(30)).await;
                make_vendor_domains(5)
            },
            None,
            &coverage,
            "test",
            "example.com",
            &logger,
        )
        .await;
        assert_eq!(kept.len(), 5);
    }
}
