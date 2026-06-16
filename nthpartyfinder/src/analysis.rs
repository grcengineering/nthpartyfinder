use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
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

/// The absolute maximum recursion depth, regardless of user configuration.
pub const ABSOLUTE_MAX_DEPTH: u32 = 10;

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

/// Compute stream buffer size: min of configured concurrency and parallel_jobs, floored at 2.
pub fn compute_buffer_size(configured_concurrency: usize, parallel_jobs: usize) -> usize {
    configured_concurrency.min(parallel_jobs).max(2)
}

/// Compute progress bar position (30-100 range) given current index and total vendors.
pub fn compute_progress_position(index: usize, total_vendors: usize) -> u64 {
    30 + ((index as u64 + 1) * 70) / total_vendors as u64
}

/// Determine whether a periodic checkpoint should be saved.
pub fn should_checkpoint(processed_count: usize, vendor_count: usize) -> bool {
    processed_count.is_multiple_of(5) || processed_count == vendor_count
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
            Ok(Vec::new())
        }
    }
}

// coverage(off): I/O-only orchestration shell after DI extraction. All pure logic extracted to:
// add_base_domain_if_subdomain, convert_subprocessor_domains, filter_subfinder_results,
// filter_confirmed_tenants, convert_ct_results, convert_web_traffic_results,
// compute_buffer_size, compute_progress_position, should_checkpoint, compute_pressure_delay_ms.
// Remaining code is: DNS-over-HTTPS calls, subfinder/SaaS/CT/web I/O, checkpoint file writes,
// tokio mutex locks, and progress logger calls — no testable branching logic.
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::too_many_arguments)]
pub async fn discover_nth_parties(
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

    {
        let processed = processed_domains.lock().await;
        if processed.contains(domain) {
            logger.debug(&format!("Domain {} already processed, skipping", domain));
            return Ok(());
        }
    }

    if !is_depth_allowed(current_depth, max_depth) {
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

    {
        let mut processed = processed_domains.lock().await;
        processed.insert(domain.to_string());
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
        all_vendor_domains.extend(spf_recursive_domains);
        if let Some(base_vd) = add_base_domain_if_subdomain(domain, &current_base_domain) {
            logger.debug(&format!(
                "Added base domain {} for subdomain analysis of {}",
                current_base_domain, domain
            ));
            all_vendor_domains.push(base_vd);
        }

        if let Some(analyzer) = subprocessor_analyzer.filter(|_| subprocessor_enabled) {
            if current_depth == 1 {
                let dns_vendor_count = all_vendor_domains.len();
                logger.update_progress("Subprocessor page analysis").await;
                logger
                    .show_sub_progress(&format!(
                        "Scraping subprocessor pages for {} ({} DNS vendors found so far)",
                        domain, dns_vendor_count
                    ))
                    .await;
                logger.set_progress_position(16).await;
            }
            logger.debug(&format!(
                "Starting subprocessor web page analysis for {}",
                domain
            ));

            match subprocessor_analysis_with_logging(
                domain,
                verification_logger,
                logger.clone(),
                analyzer,
            )
            .await
            {
                Ok(subprocessor_domains) => {
                    if !subprocessor_domains.is_empty() {
                        logger.log_subprocessor_analysis(domain, subprocessor_domains.len());
                        if current_depth == 1 {
                            logger
                                .show_sub_progress(&format!(
                                    "Found {} subprocessors for {}",
                                    subprocessor_domains.len(),
                                    domain
                                ))
                                .await;
                        }
                        logger.debug(&format!(
                            "Subprocessor domains discovered: {:?}",
                            subprocessor_domains
                                .iter()
                                .map(|d| &d.domain)
                                .collect::<Vec<_>>()
                        ));

                        let converted_domains = convert_subprocessor_domains(subprocessor_domains);
                        all_vendor_domains.extend(converted_domains);
                    } else {
                        logger.log_subprocessor_analysis(domain, 0);
                        if current_depth == 1 {
                            logger
                                .show_sub_progress(&format!(
                                    "No subprocessors found on {} pages",
                                    domain
                                ))
                                .await;
                        }
                        logger.debug("Subprocessor analysis completed: No vendor domains found in any subprocessor pages");
                    }
                }
                Err(e) => {
                    logger.warn(&format!(
                        "Subprocessor analysis failed for {}: {}",
                        domain, e
                    ));
                    logger.debug(&format!("Subprocessor analysis error details: {:?}", e));
                }
            }
        }

        if current_depth == 1 {
            if let Some(subfinder) = subdomain_discovery {
                logger.update_progress("Subdomain discovery").await;
                logger
                    .show_sub_progress(&format!("Running subfinder for {}", domain))
                    .await;
                logger.info("Running subdomain discovery via subfinder...");
                match subfinder.discover(domain).await {
                    Ok(subdomains) => {
                        if !subdomains.is_empty() {
                            logger
                                .info(&format!("Subfinder found {} subdomains", subdomains.len()));

                            use futures::{stream, StreamExt};

                            let subdomain_concurrency = 50;
                            let domain_base = domain_utils::extract_base_domain(domain);

                            let total_subdomains = subdomains.len();
                            logger
                                .show_sub_progress(&format!(
                                    "Running subfinder for {} (0/{} subdomains)",
                                    domain, total_subdomains
                                ))
                                .await;
                            let domain_for_closure = domain.to_string();

                            let subdomain_results: Vec<_> = stream::iter(subdomains.iter().enumerate().map(|(i, sub)| {
                                    let subdomain = sub.subdomain.clone();
                                    let source = sub.source.clone();
                                    let dns_pool = dns_pool.clone();
                                    let domain_base = domain_base.clone();
                                    let logger_sub = logger.clone();
                                    let total = total_subdomains;
                                    let root_domain = domain_for_closure.clone();
                                    async move {
                                        logger_sub.show_sub_progress(&format!(
                                            "Running subfinder for {} ({}/{} subdomains: {})",
                                            root_domain, i + 1, total, subdomain
                                        )).await;
                                        // GRC-367 (fix 1): thread the shared DNS failure counter
                                        // (same source as the root path) so a throttle on this
                                        // high-concurrency subdomain path is visible to the
                                        // exit-3 guard instead of silently producing empty results.
                                        let (txt_records, cname_records) = dns_pool
                                            .get_txt_and_cname_fast(
                                                &subdomain,
                                                logger_sub.dns_failure_counter(),
                                            )
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

                                        if let Some(first_vendor) = txt_vendors.first() {
                                            logger_sub.show_sub_progress(&format!(
                                                "Running subfinder for {} ({}/{} subdomains: {} --> {})",
                                                root_domain, i + 1, total, subdomain, first_vendor.domain
                                            )).await;
                                        } else if let Some((cname_target, _)) = cname_vendors.first() {
                                            logger_sub.show_sub_progress(&format!(
                                                "Running subfinder for {} ({}/{} subdomains: {} --> {})",
                                                root_domain, i + 1, total, subdomain, cname_target
                                            )).await;
                                        }

                                        (subdomain, source, txt_vendors, cname_vendors)
                                    }
                                }))
                                .buffer_unordered(subdomain_concurrency)
                                .collect()
                                .await;

                            let (
                                new_vendor_domains,
                                subdomain_txt_vendors_found,
                                subdomain_cname_vendors_found,
                            ) = filter_subfinder_results(subdomain_results, &domain_base);
                            all_vendor_domains.extend(new_vendor_domains);

                            if subdomain_txt_vendors_found > 0 || subdomain_cname_vendors_found > 0
                            {
                                logger.info(&format!("Found {} vendors from subdomain TXT records, {} from CNAME infrastructure",
                                        subdomain_txt_vendors_found, subdomain_cname_vendors_found));
                            }
                        } else {
                            logger.debug("Subfinder found no subdomains");
                        }
                    }
                    Err(e) => {
                        logger.warn(&format!("Subdomain discovery failed: {}", e));
                    }
                }
                logger.clear_sub_progress().await;
                logger.set_progress_position(22).await;
            }

            if let Some(tenant_disc) = saas_tenant_discovery {
                logger.update_progress("SaaS tenant discovery").await;
                logger
                    .show_sub_progress(&format!("Probing SaaS platforms for {}", domain))
                    .await;
                logger.info("Running SaaS tenant discovery...");
                match tenant_disc.probe_with_logger(domain, Some(&logger)).await {
                    Ok(tenants) => {
                        let tenant_vendors = filter_confirmed_tenants(&tenants);
                        if !tenant_vendors.is_empty() {
                            logger.info(&format!(
                                "Found {} likely/confirmed SaaS tenants",
                                tenant_vendors.len()
                            ));
                            all_vendor_domains.extend(tenant_vendors);
                        } else {
                            logger.debug("No SaaS tenants discovered");
                        }
                    }
                    Err(e) => {
                        logger.warn(&format!("SaaS tenant discovery failed: {}", e));
                    }
                }
                logger.clear_sub_progress().await;
                logger.set_progress_position(26).await;
            }

            if let Some(ct_disc) = ct_discovery {
                logger
                    .update_progress("Certificate Transparency discovery")
                    .await;
                logger
                    .show_sub_progress(&format!("Querying crt.sh for {} certificates", domain))
                    .await;
                logger.info("Running Certificate Transparency log discovery...");
                match ct_disc.discover(domain).await {
                    Ok(ct_results) => {
                        if !ct_results.is_empty() {
                            logger
                                .info(&format!("Found {} vendors from CT logs", ct_results.len()));
                            let ct_vendors = convert_ct_results(ct_results);
                            all_vendor_domains.extend(ct_vendors);
                        } else {
                            logger.debug("No vendors discovered from CT logs");
                        }
                    }
                    Err(e) => {
                        logger.warn(&format!("CT log discovery failed: {}", e));
                    }
                }
                logger.clear_sub_progress().await;
                logger.set_progress_position(28).await;
            }

            if let Some(web_traffic_disc) = web_traffic_discovery {
                logger
                    .update_progress("Webpage source & network request discovery")
                    .await;
                logger
                    .show_sub_progress(&format!(
                        "Analyzing webpage source and network requests for {}",
                        domain
                    ))
                    .await;
                logger.info("Running webpage source & network request discovery...");
                let web_traffic_results = web_traffic_disc.analyze_domain(domain).await;
                if !web_traffic_results.is_empty() {
                    logger.info(&format!(
                        "Found {} vendors from webpage analysis",
                        web_traffic_results.len()
                    ));
                    let web_vendors = convert_web_traffic_results(web_traffic_results);
                    all_vendor_domains.extend(web_vendors);
                } else {
                    logger.debug("No vendors discovered from webpage analysis");
                }
                logger.clear_sub_progress().await;
                logger.set_progress_position(30).await;
            }
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
                    cp.completed_domains = processed.clone();
                    drop(processed);
                    let sink = result_sink.lock().await;
                    cp.results_count = sink.count();
                    cp.results_file = sink.path().to_string_lossy().to_string();
                    drop(sink);
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
                    if current_depth == 1 {
                        let mut cp = checkpoint.lock().await;
                        let vendors = discovered_vendors.lock().await;
                        cp.discovered_vendors = vendors.clone();
                        drop(vendors);
                        let processed = processed_domains.lock().await;
                        cp.completed_domains = processed.clone();
                        drop(processed);
                        let sink = result_sink.lock().await;
                        cp.results_count = sink.count();
                        cp.results_file = sink.path().to_string_lossy().to_string();
                        drop(sink);
                        if let Err(e) = cp.save(checkpoint_path) {
                            logger.debug(&format!("Failed to save checkpoint: {}", e));
                        } else {
                            logger.debug(&format!(
                                "Checkpoint saved: {} domains completed",
                                cp.completed_domains.len()
                            ));
                        }
                    }
                }
            }

            logger.debug(&format!("All {} vendor domains processed at depth {} ({} raw relationships to disk, pending dedup)",
                    processed_count, current_depth, total_relationships_found));

            logger.log_parallel_processing_complete(total_relationships_found);

            if current_depth == 1 {
                logger.finish_progress(&format!("Vendor analysis completed — {} raw relationships from {} vendors (deduplicating...)",
                        total_relationships_found, vendor_count)).await;
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
    processed_domains: Arc<Mutex<HashSet<String>>>,
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

    let base_domain = domain_utils::extract_base_domain(&vendor_domain);
    let customer_base_domain = domain_utils::extract_base_domain(&customer_domain);

    {
        let vendors = discovered_vendors.lock().await;
        if !vendors.contains_key(&base_domain) {
            drop(vendors);
            match whois::get_organization_with_status_and_config(
                &base_domain,
                web_org_enabled,
                web_org_min_confidence,
            )
            .await
            {
                Ok(org_result) => {
                    let mut vendors = discovered_vendors.lock().await;
                    vendors.insert(
                        base_domain.clone(),
                        org_normalizer::normalize(&org_result.name),
                    );
                    logger.log_whois_lookup(&base_domain, org_result.is_verified);
                }
                Err(e) => {
                    logger.debug(&format!(
                        "Failed to get organization for {}: {}",
                        base_domain, e
                    ));
                    let mut vendors = discovered_vendors.lock().await;
                    vendors.insert(base_domain.clone(), org_normalizer::normalize(&base_domain));
                    logger.log_whois_lookup(&base_domain, false);
                }
            }
        }
    }

    {
        let vendors = discovered_vendors.lock().await;
        if !vendors.contains_key(&customer_base_domain) {
            drop(vendors);
            match whois::get_organization_with_status_and_config(
                &customer_base_domain,
                web_org_enabled,
                web_org_min_confidence,
            )
            .await
            {
                Ok(org_result) => {
                    let mut vendors = discovered_vendors.lock().await;
                    vendors.insert(
                        customer_base_domain.clone(),
                        org_normalizer::normalize(&org_result.name),
                    );
                    logger.log_whois_lookup(&customer_base_domain, org_result.is_verified);
                }
                Err(e) => {
                    logger.debug(&format!(
                        "Failed to get organization for customer {}: {}",
                        customer_base_domain, e
                    ));
                    let mut vendors = discovered_vendors.lock().await;
                    vendors.insert(
                        customer_base_domain.clone(),
                        org_normalizer::normalize(&customer_base_domain),
                    );
                    logger.log_whois_lookup(&customer_base_domain, false);
                }
            }
        }
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

    if let Err(e) = discover_nth_parties(
        &lookup_domain,
        max_depth,
        discovered_vendors.clone(),
        processed_domains.clone(),
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
        None,
        None,
        None,
        None,
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
}
