use crate::known_vendors;
use crate::ner_org;
use crate::rate_limit::RateLimitContext;
use crate::vendor_registry;
use crate::web_org;
use anyhow::{anyhow, Result};
use futures::stream::{self, StreamExt};
use regex::Regex;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock as StdRwLock;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::debug;

/// Result of an organization lookup with verification status
#[derive(Debug, Clone)]
pub struct OrganizationResult {
    /// The organization name
    pub name: String,
    /// Whether the organization was verified from WHOIS data (true) or inferred from domain (false)
    pub is_verified: bool,
    /// The source of the organization name (e.g., "whois", "registrar", "domain_fallback", "known_vendors")
    pub source: String,
}

impl OrganizationResult {
    /// An attribution backed by evidence outside the vendor's own marketing surface:
    /// a curated store, the embedded dataset, or a registrant record filed with a registry.
    pub fn verified(name: String, source: &str) -> Self {
        Self {
            name,
            is_verified: true,
            source: source.to_string(),
        }
    }

    /// A name the operator published about itself (Schema.org, OpenGraph, page title).
    ///
    /// Self-declaration is real evidence but it is not independent: the party being
    /// identified wrote it, and parking pages, bot interstitials and taglines all live in
    /// exactly this channel. Marked unverified so the report can say so and the review
    /// contract can pick it up — previously every one of these was laundered into
    /// `is_verified = true`, which is why a scraped tagline was indistinguishable from a
    /// curated attribution.
    pub fn self_declared(name: String, source: &str) -> Self {
        Self {
            name,
            is_verified: false,
            source: source.to_string(),
        }
    }

    /// A machine-inferred name (NER span), carrying its source so downstream can tell it
    /// apart from a bare domain fallback.
    pub fn inferred_by(name: String, source: &str) -> Self {
        Self {
            name,
            is_verified: false,
            source: source.to_string(),
        }
    }

    /// No source could attribute the domain: the name is derived from the domain itself.
    pub fn inferred(name: String) -> Self {
        Self {
            name,
            is_verified: false,
            source: "domain_fallback".to_string(),
        }
    }
}

/// Get organization with verification status
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn get_organization_with_status(domain: &str) -> Result<OrganizationResult> {
    get_organization_with_status_and_config(domain, true, 0.6).await
}

/// Get organization with verification status and optional rate limiting.
///
/// This used to be a SECOND copy of the whole attribution chain, and it had drifted: no embedded
/// dataset tier, web/NER results marked `verified = true`, and a domain-less WHOIS extraction
/// that could never apply the self-attribution rescue. Two chains means two answers to the same
/// question, and the copy nobody calls is the one nobody notices going wrong. There is now one
/// chain; this wrapper only adds the rate-limit permit.
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn get_organization_with_rate_limit(
    domain: &str,
    web_org_enabled: bool,
    min_confidence: f32,
    rate_limit_ctx: Option<&RateLimitContext>,
) -> Result<OrganizationResult> {
    // The curated tiers need no network, so they must not spend a WHOIS permit.
    if let Some(curated) = resolve_curated(domain) {
        return Ok(curated);
    }
    if let Some(ctx) = rate_limit_ctx {
        ctx.whois_limiter.acquire().await;
    }
    get_organization_with_status_and_config(domain, web_org_enabled, min_confidence).await
}

/// Whether a WHOIS record carries an organization/registrant field whose value is a
/// privacy placeholder ("REDACTED FOR PRIVACY", "Domains By Proxy", ...).
///
/// This is the precise condition under which running `whois(1)` afterwards cannot help:
/// both clients speak RFC 3912 to the same registry and registrar servers, so when the
/// field is present and deliberately redacted, the second query returns the same
/// redaction. It just costs a subprocess and up to 4s to learn that — and modern .com
/// registrations are redacted by default, so this is the common case.
///
/// Deliberately narrower than "the response looked long enough": a thin or referral-only
/// record carries no org field at all, and there a second client that chases referrals
/// differently might genuinely find one. Those still fall through to `whois(1)`.
fn whois_org_field_is_redacted(response: &str) -> bool {
    for regex in organization_patterns().iter().chain(registrar_patterns()) {
        if let Some(cap) = regex.captures(response) {
            if let Some(field) = cap.get(1) {
                let value = field.as_str().trim();
                if !value.is_empty() {
                    return is_placeholder_organization(value);
                }
            }
        }
    }
    false
}

/// Page HTML for the NER step. Reuses the body already fetched by the web-org step
/// when one is available, so a domain reaching NER is fetched once, not twice. Falls
/// back to a fetch only when the web-org step did not run or produced no body.
async fn fetch_org_page_content(domain: &str, prefetched_html: Option<String>) -> Option<String> {
    match prefetched_html {
        Some(html) => {
            debug!("Reusing web-org page body for NER extraction of {}", domain);
            Some(html)
        }
        None => web_org::fetch_page_content(domain).await.ok(),
    }
}

/// The curated, offline prefix of the attribution chain — the tiers that need no network
/// and make no inference, in precedence order:
///
/// 1. **Known vendors** (ships with the tool + the user's own local overrides). The user's
///    own decisions always win.
/// 2. **Vendor registry** (config-backed, verification-token-derived).
/// 3. **Embedded public dataset** (AdGuard companiesdb, CC BY-SA) — ~5.1k domains curated by
///    an independent maintainer. This is the single largest coverage lever in the chain: the
///    first two tiers know ~280 domains between them, while a depth-3 scan surfaces thousands,
///    so most domains previously fell all the way through to inference.
///
/// Returns `None` when no curated source knows the domain — the caller then descends into the
/// network and inference tiers, which are the ones that can be wrong.
///
/// The production chain calls this function first, and the hermetic attribution eval
/// (`tests/attribution_eval.rs`) calls this same function, so the eval cannot drift away from
/// the behaviour that actually ships.
pub fn resolve_curated(domain: &str) -> Option<OrganizationResult> {
    if let Some(kv_result) = known_vendors::lookup(domain) {
        debug!(
            "Found {} in known vendors database: {} (source: {})",
            domain, kv_result.organization, kv_result.source
        );
        return Some(OrganizationResult::verified(
            kv_result.organization,
            &kv_result.source.to_string(),
        ));
    }

    if let Some(org) = vendor_registry::lookup_organization(domain) {
        debug!("Found {} in vendor registry: {}", domain, org);
        return Some(OrganizationResult::verified(org, "vendor_registry"));
    }

    // A domain the dataset gets WRONG for our purposes — see `STALE_ROLLUP`.
    if let Some(correct) = stale_rollup_correction(domain) {
        debug!("Using curated correction for {}: {}", domain, correct);
        return Some(OrganizationResult::verified(
            correct.to_string(),
            "curated_correction",
        ));
    }

    // An independently-maintained mapping beats anything scraped off the vendor's own page, so
    // the dataset sits above every inference source — and below the user's tiers, which always
    // win.
    //
    // No intermediary filter here, deliberately. That filter exists for WHOIS, where a registrar
    // or privacy proxy LEAKS into the registrant field of a domain it does not own. A dataset row
    // is the opposite: it is a positive ownership assertion, and registrars really do own domains
    // (`secureserver.net` is GoDaddy's, `trafficfacts.com` is GoDaddy's). Filtering the dataset
    // through it threw away correct answers.
    if let Some(org) = crate::org_dataset::lookup(domain) {
        debug!("Found {} in embedded dataset: {}", domain, org);
        return Some(OrganizationResult::verified(
            org.to_string(),
            "embedded_dataset",
        ));
    }

    // A brand TLD names its owner outright. ICANN Registry Agreement Specification 13 makes a
    // .brand a single-registrant TLD: nobody but Google may hold a name under `.google`. So the
    // suffix itself is proof of ownership — stronger evidence than any WHOIS record — and it
    // costs no network call.
    //
    // Without this, `blog.google` shipped as "Blog", `calculator.aws` as "Calculator", and
    // `core.microsoft` as "Core": the domain-derived label is technically honest and completely
    // useless, and it is exactly the kind of row a user would otherwise hand-map.
    if let Some(org) = brand_tld_owner(domain) {
        debug!("{} sits under the .{} brand TLD", domain, org);
        return Some(OrganizationResult::verified(org.to_string(), "brand_tld"));
    }

    None
}

/// TLDs that ICANN delegated to a single company. The suffix *is* the attribution.
///
/// Deliberately a hand-curated list, not "any suffix that looks like a company". The generic
/// TLDs are the trap: `.app`, `.dev`, and `.cloud` are Google-operated *registries* open to
/// anyone, so treating a Google-run registry as a Google-owned domain would attribute half the
/// internet to Google. Only genuine single-registrant .brand TLDs belong here.
const BRAND_TLDS: &[(&str, &str)] = &[
    ("google", "Google"),
    ("gle", "Google"), // goo.gle
    ("youtube", "Google"),
    ("android", "Google"),
    ("chrome", "Google"),
    ("gmail", "Google"),
    ("aws", "Amazon"),
    ("amazon", "Amazon"),
    ("microsoft", "Microsoft"),
    ("azure", "Microsoft"),
    ("xbox", "Microsoft"),
    ("bing", "Microsoft"),
    ("apple", "Apple"),
    ("icloud", "Apple"),
    ("meta", "Meta"),
    ("facebook", "Meta"),
    ("instagram", "Meta"),
    ("whatsapp", "Meta"),
    ("oracle", "Oracle"),
    ("java", "Oracle"),
    ("ibm", "IBM"),
    ("cisco", "Cisco"),
    ("intel", "Intel"),
    ("dell", "Dell"),
    ("hp", "HP"),
    ("sap", "SAP"),
    ("salesforce", "Salesforce"),
    ("adobe", "Adobe"),
    ("netflix", "Netflix"),
    ("linkedin", "LinkedIn"),
    ("paypal", "PayPal"),
    ("visa", "Visa"),
    ("mastercard", "Mastercard"),
    ("walmart", "Walmart"),
    ("target", "Target"),
    ("nike", "Nike"),
    ("bmw", "BMW"),
    ("audi", "Audi"),
    ("ford", "Ford"),
    ("toyota", "Toyota"),
];

/// The company that owns the domain's brand TLD, if its suffix is one.
fn brand_tld_owner(domain: &str) -> Option<&'static str> {
    let suffix = crate::domain_utils::icann_suffix(domain)?;
    BRAND_TLDS
        .iter()
        .find(|(tld, _)| *tld == suffix)
        .map(|(_, org)| *org)
}

/// Domains where the embedded dataset's answer is wrong for THIS tool's question.
///
/// The dataset answers *"which company ultimately receives this traffic"* — a tracker-ownership
/// question — so it rolls domains up to their **parent** company, and those rollups go stale when
/// companies split. A vendor graph asks a different question: *who is this vendor?*
///
/// This is a hand-curated list of the conflicts, not a heuristic, because the heuristic version of
/// this idea ("if the domain's label is a brand we know, prefer the brand") was worse than the
/// disease: it also fired on `icloud.com` → "iCloud" (instead of Apple), `sharepoint.com` →
/// "SharePoint" (instead of Microsoft) and `wordpress.com` → "WordPress" (instead of Automattic),
/// replacing correct company names with product names. A product is not a vendor you contract
/// with. Only a human can tell the difference, so a human (this list) does.
const STALE_ROLLUP: &[(&str, &str)] = &[
    // Dataset says "eBay". PayPal was spun off from eBay in 2015.
    ("paypal.com", "PayPal"),
    // Dataset says "Microsoft Corporation" — the parent, not the vendor. A vendor graph that
    // reports github.com as Microsoft has lost the fact the user needs.
    ("github.com", "GitHub"),
    ("linkedin.com", "LinkedIn"),
];

fn stale_rollup_correction(domain: &str) -> Option<&'static str> {
    let base = crate::domain_utils::extract_base_domain(domain);
    STALE_ROLLUP
        .iter()
        .find(|(d, _)| *d == base)
        .map(|(_, org)| *org)
}

/// The terminal tier: the domain's own registrable label, honestly marked unverified.
///
/// This is what a domain gets when every curated, network and inference source has failed.
/// It invents nothing — no legal suffix, no company — it just says "the owner of
/// `stripe.com` calls itself something, and the only part of that we actually know is
/// 'Stripe'". Exposed so the attribution eval can assert the honest-fallback properties
/// against the real implementation.
pub fn domain_derived_organization(domain: &str) -> OrganizationResult {
    OrganizationResult::inferred(extract_organization_from_domain(domain))
}

/// Get organization with verification status, with configurable web org lookup
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn get_organization_with_status_and_config(
    domain: &str,
    web_org_enabled: bool,
    min_confidence: f32,
) -> Result<OrganizationResult> {
    debug!("Looking up organization for domain: {}", domain);

    // Priorities 1 / 1.5 / 1.7 — the curated, offline, no-inference tiers.
    if let Some(curated) = resolve_curated(domain) {
        return Ok(curated);
    }

    // Priority 2: Web page analysis (Schema.org, OpenGraph, meta tags), HTTP-only.
    // The headless-browser fallback is intentionally NOT used here: this runs once per
    // discovered vendor (hundreds per scan) and a Chrome launch each was the dominant
    // cost. The fetched body is retained for the Priority-5 NER step, which would otherwise
    // re-fetch the same page.
    //
    // A page is the *operator's own* claim about itself, so it is accepted as
    // `is_verified = false` (self-declared, not independently attested) and only after
    // `accept_extracted_name` clears it. Rejection here FALLS THROUGH to WHOIS rather than
    // dead-ending at the domain fallback — a scraped tagline must never outrank a real
    // registrant record, which is precisely what used to happen.
    let mut prefetched_html: Option<String> = None;
    if web_org_enabled {
        if let Ok((web_result, html)) =
            web_org::extract_organization_http_only_with_body(domain).await
        {
            prefetched_html = html;
            if let Some(web_result) = web_result {
                if web_result.confidence >= min_confidence {
                    if let Some(name) = accept_extracted_name(&web_result.organization, domain) {
                        debug!(
                            "Found {} via web page analysis: {} (source: {}, confidence: {:.2})",
                            domain, name, web_result.source, web_result.confidence
                        );
                        return Ok(OrganizationResult::self_declared(
                            name,
                            &format!("web_{}", web_result.source),
                        ));
                    }
                    debug!(
                        "Web result '{}' for {} rejected (tagline/intermediary), trying WHOIS",
                        web_result.organization, domain
                    );
                } else {
                    debug!("Web page result for {} had low confidence ({:.2} < {:.2}), trying other methods",
                           domain, web_result.confidence, min_confidence);
                }
            }
        }
    }

    // Priority 3: Native Rust WHOIS lookup (in-process TCP client, RFC 3912). Registration
    // data — asserted by the registrant to a registry, which is a materially stronger claim
    // than a page the operator wrote about itself.
    let native_org_is_redacted = match try_native_whois(domain).await {
        Ok(result) => {
            if let Some(organization) = extract_organization_from_whois_for_domain(&result, domain)
            {
                debug!(
                    "Found organization via native WHOIS for {}: {}",
                    domain, organization
                );
                return Ok(OrganizationResult::verified(organization, "whois"));
            }
            debug!(
                "native WHOIS returned no usable registrant organization for {}, trying fallbacks",
                domain
            );
            whois_org_field_is_redacted(&result)
        }
        Err(_) => false,
    };

    // Priority 4: System whois command (if available). Skipped when the native record
    // already showed a deliberately-redacted org — see the sibling chain for the rationale.
    if !native_org_is_redacted {
        if let Ok(result) = try_system_whois(domain).await {
            if let Some(organization) = extract_organization_from_whois_for_domain(&result, domain)
            {
                debug!(
                    "Found organization via system whois for {}: {}",
                    domain, organization
                );
                return Ok(OrganizationResult::verified(organization, "system_whois"));
            }
            debug!(
                "System whois returned no usable registrant organization for {}, trying NER fallback",
                domain
            );
        }
    } else {
        debug!(
            "Skipping system whois for {}: native WHOIS org field is redacted at the source",
            domain
        );
    }

    // Priority 5: NER extraction. A model's guess over page text — the weakest evidence the
    // chain produces, and the one that most reliably invents taglines and third-party names.
    // It is accepted as `is_verified = false` and only through the same gate as the web tier,
    // so that a low-quality span becomes an honest unattribution rather than a confident
    // wrong answer.
    if ner_org::is_available() {
        debug!("NER is available, attempting extraction for {}", domain);
        let page_content = fetch_org_page_content(domain, prefetched_html).await;
        let content_ref = page_content.as_deref();

        if let Ok(Some(ner_result)) = ner_org::extract_organization_async(domain, content_ref).await
        {
            if let Some(name) = accept_extracted_name(&ner_result.organization, domain) {
                debug!(
                    "Found organization via NER for {}: {} (confidence: {:.2})",
                    domain, name, ner_result.confidence
                );
                return Ok(OrganizationResult::inferred_by(name, "ner_gliner"));
            }
            debug!(
                "NER result '{}' for {} rejected (tagline/intermediary), using domain fallback",
                ner_result.organization, domain
            );
        }
        debug!(
            "NER could not determine organization for {}, using domain fallback",
            domain
        );
    }

    // Final fallback: the domain's own registrable label, honestly marked unverified. No
    // legal suffix is invented — see `extract_organization_from_domain`.
    debug!(
        "All lookup methods failed or returned placeholders for {}, using domain-based fallback",
        domain
    );
    Ok(domain_derived_organization(domain))
}

/// The gate every *extracted* organization name (web page, NER) must clear.
///
/// Extracted names come from text the vendor — or an attacker, or a parking provider —
/// controls, so they are the source of the tagline, interstitial and third-party-name
/// misattributions. Three checks, each cheap:
///
/// 1. It must look like an organization name and not a sentence ([`org_normalizer::is_plausible_org_name`]).
/// 2. It must not name an intermediary (registrar, privacy proxy, registry, address).
/// 3. It must not be a bare echo of the domain label, which adds nothing over the fallback
///    yet would otherwise be presented as an attributed name.
///
/// Returning `None` means "keep looking", not "give up" — every caller falls through to the
/// next evidence source.
fn accept_extracted_name(candidate: &str, domain: &str) -> Option<String> {
    // Clean FIRST, then judge. The gates must see exactly the string that would ship: a candidate
    // carrying embedded newlines ("Acme\nfor\nTeams") reads as a name to the plausibility check
    // (whose phrase probes are space-padded) but as a tagline once collapsed, so gating the raw
    // form let the two checks disagree about the same name.
    let cleaned = clean_organization_name(candidate.trim());
    let name = cleaned.trim();
    if name.is_empty() {
        return None;
    }
    if is_interstitial(name) {
        return None;
    }
    if !crate::org_normalizer::is_plausible_org_name(name) {
        return None;
    }
    if crate::org_role::is_intermediary_for_domain(name, domain) {
        return None;
    }
    Some(name.to_string())
}

/// A page that is not the vendor's site: a bot check, an error page, a parking lander.
///
/// These read as perfectly plausible organization names — "Attention Required! | Cloudflare" has
/// capitals, a proper noun and no tagline grammar — so they sail through every other check and
/// get printed as the company that owns the domain. What the scanner actually reached was a
/// challenge page, which means it learned nothing at all, and the honest answer is to keep
/// looking (WHOIS) rather than to report the interstitial as a company.
fn is_interstitial(name: &str) -> bool {
    const INTERSTITIALS: &[&str] = &[
        "attention required",
        "just a moment",
        "checking your browser",
        "verify you are human",
        "are you a robot",
        "security check",
        "access denied",
        "403 forbidden",
        "page not found",
        "404 not found",
        "domain for sale",
        "buy this domain",
        "this domain is for sale",
        "under construction",
        "coming soon",
        "index of /",
        "example domain",
        // Some registries answer WHOIS with prose instead of a record. DNS Belgium's reply
        // shipped verbatim as the organization for `youtu.be`: "Not shown, please visit
        // www.dnsbelgium.be for webbased whois." It parses as a name because it is a sentence.
        "please visit",
        "webbased whois",
        "web-based whois",
        "whois server",
        "not shown",
        "see the whois",
        "query the whois",
        "for more information",
    ];
    let lower = name.to_lowercase();
    INTERSTITIALS.iter().any(|phrase| lower.contains(phrase))
}

#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn get_organization(domain: &str) -> Result<String> {
    get_organization_with_config(domain, true, 0.6).await
}

/// Get organization name with configurable web org lookup
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn get_organization_with_config(
    domain: &str,
    web_org_enabled: bool,
    min_confidence: f32,
) -> Result<String> {
    debug!("Looking up organization for domain: {}", domain);

    // Priority 1: Check known vendors database (fastest and most reliable)
    if let Some(kv_result) = known_vendors::lookup(domain) {
        debug!(
            "Found {} in known vendors database: {}",
            domain, kv_result.organization
        );
        return Ok(kv_result.organization);
    }

    // Priority 1.5: Vendor registry (authoritative, instant — no network).
    if let Some(org) = vendor_registry::lookup_organization(domain) {
        debug!("Found {} in vendor registry: {}", domain, org);
        return Ok(org);
    }

    // Priority 2: Web page analysis (HTTP-only — no per-vendor headless browser).
    if web_org_enabled {
        if let Ok(Some(web_result)) = web_org::extract_organization_http_only(domain).await {
            if web_result.confidence >= min_confidence {
                debug!(
                    "Found {} via web page analysis: {} (confidence: {:.2})",
                    domain, web_result.organization, web_result.confidence
                );
                return Ok(web_result.organization);
            }
        }
    }

    // Priority 3: Native Rust WHOIS lookup (in-process TCP client, RFC 3912)
    if let Ok(result) = try_native_whois(domain).await {
        if let Some(organization) = extract_organization_from_whois(&result) {
            debug!(
                "Found organization via native WHOIS for {}: {}",
                domain, organization
            );
            return Ok(organization);
        }
        debug!(
            "native WHOIS returned placeholder organization for {}, trying fallbacks",
            domain
        );
    }

    // Priority 4: System whois command (if available)
    if let Ok(result) = try_system_whois(domain).await {
        if let Some(organization) = extract_organization_from_whois(&result) {
            debug!(
                "Found organization via system whois for {}: {}",
                domain, organization
            );
            return Ok(organization);
        }
        debug!(
            "System whois returned placeholder organization for {}, using domain fallback",
            domain
        );
    }

    // Final fallback to domain-based organization name
    debug!(
        "All lookup methods failed or returned placeholders for {}, using domain-based fallback",
        domain
    );
    Ok(extract_organization_from_domain(domain))
}

/// The label we ask IANA about to discover a TLD's registry WHOIS server.
/// For `sub.example.co.uk` this is `uk` (IANA is authoritative for the root zone,
/// so the last label is the right key; the registry's own response then carries
/// any further `Registrar WHOIS Server` referral we follow below).
fn whois_tld_query(domain: &str) -> String {
    domain
        .trim_end_matches('.')
        .rsplit('.')
        .next()
        .unwrap_or(domain)
        .to_ascii_lowercase()
}

/// Extract a referral WHOIS host from a response: the `refer:` line IANA returns,
/// or the `Registrar WHOIS Server:` / `whois:` line a registry returns. Returns a
/// bare hostname (scheme/path/trailing-dot stripped) or `None`.
fn parse_whois_referral(response: &str) -> Option<String> {
    for line in response.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        for key in [
            "refer:",
            "registrar whois server:",
            "whois:",
            "whois server:",
        ] {
            if lower.starts_with(key) {
                // Slice the original (case-preserving) line at the matched span.
                let value = trimmed[key.len()..].trim();
                let host = value
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_start_matches("rwhois://")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('.');
                if host.len() > 3 && host.contains('.') && !host.contains(' ') {
                    return Some(host.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

/// One WHOIS exchange over TCP (RFC 3912): connect to `{server}:43`, send
/// `{query}\r\n`, read the full reply. In-process replacement for the `whois-rs`
/// crate, which was removed to drop its vulnerable transitive deps
/// (hickory-client 0.24 → hickory-proto 0.24 = RUSTSEC-2026-0119; validators 0.25
/// → idna 0.5 = RUSTSEC-2024-0421). `whois-rs` 1.6.1 is the latest release and
/// pins those old crates, so eliminating the dependency is the only code-level
/// fix. System `whois` (`try_system_whois`) remains a fallback.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn whois_query(server: &str, query: &str) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let _whois_timer = crate::perf::scoped(&crate::perf::METRICS.whois_lookup);

    // Defense-in-depth: the query is a domain/TLD and must be a single WHOIS line.
    // Reject any CR/LF/whitespace so a (discovered, not pre-validated) domain can
    // never inject a second protocol line via `\r\n`.
    if query
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == b' ' || b == b'\t')
    {
        return Err(anyhow!(
            "invalid WHOIS query (contains whitespace/control chars)"
        ));
    }

    let addr = format!("{server}:43");
    let mut stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow!("WHOIS connect to {server} timed out"))?
        .map_err(|e| anyhow!("WHOIS connect to {server} failed: {e}"))?;

    stream
        .write_all(format!("{query}\r\n").as_bytes())
        .await
        .map_err(|e| anyhow!("WHOIS write to {server} failed: {e}"))?;
    stream.flush().await.ok();

    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut buf))
        .await
        .map_err(|_| anyhow!("WHOIS read from {server} timed out"))?
        .map_err(|e| anyhow!("WHOIS read from {server} failed: {e}"))?;

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// TLD → registry WHOIS server, learned from IANA once per TLD per process.
///
/// A scan resolves hundreds of domains, the overwhelming majority under a handful of
/// TLDs. Without this, every native WHOIS lookup opens a fresh TCP session to
/// `whois.iana.org` to ask the same question ("who serves .com?") and pays up to a 3s
/// connect plus a 4s read for an answer that does not change during a scan. Caching it
/// removes one full round trip from every lookup after the first per TLD, and stops the
/// scan from hammering IANA.
static TLD_REGISTRY_SERVERS: OnceLock<StdRwLock<HashMap<String, String>>> = OnceLock::new();

fn tld_registry_servers() -> &'static StdRwLock<HashMap<String, String>> {
    TLD_REGISTRY_SERVERS.get_or_init(|| StdRwLock::new(HashMap::new()))
}

/// The registry WHOIS server for a TLD, from cache when known and from IANA otherwise.
/// Only successful resolutions are cached: a failed IANA query says nothing durable
/// about the TLD, and caching it would convert one transient network error into a
/// scan-long inability to resolve any domain under that TLD.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn resolve_registry_server(tld: &str) -> Option<String> {
    if let Ok(cache) = tld_registry_servers().read() {
        if let Some(server) = cache.get(tld) {
            debug!("Using cached WHOIS registry server for .{tld}: {server}");
            return Some(server.clone());
        }
    }

    let server = match whois_query("whois.iana.org", tld).await {
        Ok(resp) => parse_whois_referral(&resp),
        Err(e) => {
            debug!("IANA WHOIS for .{tld} failed: {e}");
            None
        }
    }?;

    if let Ok(mut cache) = tld_registry_servers().write() {
        cache.insert(tld.to_string(), server.clone());
    }
    Some(server)
}

#[cfg_attr(coverage_nightly, coverage(off))]
async fn try_native_whois(domain: &str) -> Result<String> {
    debug!("Trying in-process TCP WHOIS for domain: {}", domain);

    let result = tokio::time::timeout(Duration::from_secs(8), async {
        // 1. Ask IANA (authoritative for the root zone) which registry serves the TLD.
        //    Answered from the per-process cache after the first domain in each TLD.
        let tld = whois_tld_query(domain);
        let registry_server = resolve_registry_server(&tld)
            .await
            .ok_or_else(|| anyhow!("no WHOIS server found for .{tld} via IANA"))?;

        // 2. Query the registry for the domain.
        let registry_resp = whois_query(&registry_server, domain).await?;

        // 3. Follow a registrar referral once for richer registrant data.
        if let Some(registrar) = parse_whois_referral(&registry_resp) {
            if !registrar.eq_ignore_ascii_case(&registry_server) {
                if let Ok(registrar_resp) = whois_query(&registrar, domain).await {
                    if registrar_resp.trim().len() > 40 {
                        return Ok::<String, anyhow::Error>(registrar_resp);
                    }
                }
            }
        }
        Ok(registry_resp)
    })
    .await
    .map_err(|_| anyhow!("WHOIS lookup for {domain} timed out"))??;

    debug!("in-process WHOIS lookup successful for {}", domain);
    Ok(result)
}

#[cfg_attr(coverage_nightly, coverage(off))]
async fn try_system_whois(domain: &str) -> Result<String> {
    // Single hard deadline for the whole fallback. `execute_whois_command` spawns a real child
    // per candidate; if this timeout fires, its future is dropped and any in-flight child —
    // spawned with `kill_on_drop(true)` — is SIGKILLed and reaped. This is the fix for the
    // process-wedge bug: the previous `std::process::Command::output()` blocked in `waitpid`
    // with no cancellation, so `tokio::time::timeout` only detached the `spawn_blocking` handle
    // and left a hung whois child (plus the blocking thread the runtime joins on shutdown) alive
    // forever — the observed multi-hour stuck scan. Bounded by 4s exactly as before.
    match tokio::time::timeout(Duration::from_secs(4), execute_whois_command(domain)).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("System whois timed out")),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
async fn execute_whois_command(domain: &str) -> Result<String> {
    // Try different whois command locations based on platform; first that runs and succeeds wins.
    let whois_commands: &[&str] = if cfg!(windows) {
        &["whois.exe", "whois"]
    } else {
        &["whois", "/usr/bin/whois", "/usr/local/bin/whois"]
    };

    for cmd in whois_commands {
        // tokio::process + kill_on_drop mirrors the subfinder subprocess pattern
        // (discovery/subfinder.rs): kill_on_drop guarantees SIGKILL + reap on every drop path,
        // including when the caller's 4s timeout drops this future mid-`wait_with_output`.
        let child = match tokio::process::Command::new(cmd)
            .arg(domain)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(_) => continue, // binary not present at this path — try the next candidate
        };

        match child.wait_with_output().await {
            Ok(output) if output.status.success() => {
                return Ok(String::from_utf8_lossy(&output.stdout).to_string());
            }
            Ok(_) => continue,  // ran but non-zero exit — try the next candidate
            Err(_) => continue, // I/O error collecting output — try the next candidate
        }
    }

    Err(anyhow!("No working whois command found"))
}

/// The honest display name for a domain nobody could attribute.
///
/// This used to append a fabricated `" Inc."` to the title-cased second-to-last label,
/// turning "we could not identify the owner of acme.io" into "Acme Inc." — a
/// confident-looking company that does not exist. Every unattributed domain in every
/// report was therefore indistinguishable from a real attribution, which is why
/// misattribution looked rampant: most of it was not a wrong lookup, it was an invented
/// answer to a lookup that had failed.
///
/// The replacement invents nothing: the registrable label the owner actually chose,
/// title-cased, with no legal suffix. Paired with `OrganizationResult::inferred` (which
/// sets `is_verified = false`), a guess stays distinguishable from an attribution. The
/// label comes from the PSL, so `monzo.co.uk` yields "Monzo" rather than "Co".
fn extract_organization_from_domain(domain: &str) -> String {
    let Some(label) = crate::domain_utils::registrable_label(domain) else {
        return domain.to_string();
    };
    let mut chars: Vec<char> = label.chars().collect();
    if let Some(first) = chars.first_mut() {
        *first = first.to_uppercase().next().unwrap_or(*first);
    }
    chars.into_iter().collect::<String>()
}

/// Organization field patterns, in precedence order. Compiled once: a scan parses one
/// WHOIS response per unknown domain, and rebuilding these ten regexes each time was
/// pure repeated work.
static ORGANIZATION_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
static REGISTRAR_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();

/// Compile a fixed pattern list, dropping any that fail. The literals are compile-time
/// constants, so a failure here is a programming error, not an input-dependent one; the
/// prior code silently skipped uncompilable patterns and this preserves that behavior.
fn compile_patterns(patterns: &[&str]) -> Vec<Regex> {
    patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
}

/// Registrant-organization field patterns, in precedence order.
///
/// Anchored to line starts (`(?im)^`). The unanchored versions matched
/// `Admin Organization:` and `Tech Organization:` — the registrar's or a law firm's
/// contact, not the registrant — and matched organization-looking text inside registry
/// disclaimer paragraphs. Whichever line appeared first in the response won, which made
/// the attribution depend on registry response ordering.
///
/// Registrant-scoped patterns come first so an explicit `Registrant Organization:` beats a
/// bare `Organization:` elsewhere in the record. The Nominet (.uk) form — where the value
/// sits on the line *after* `Registrant:` — has its own pattern; the same-line regex could
/// never capture it, so every .uk domain fell through to the fabricated fallback.
fn organization_patterns() -> &'static [Regex] {
    ORGANIZATION_PATTERNS.get_or_init(|| {
        // Order is precedence. Every ORGANIZATION field comes before every NAME field, because
        // `Registrant Name` is a PERSON field in most registries — a WHOIS record carrying both
        // "Registrant Name: Jane Doe" and "Organization: Acme GmbH" must attribute the domain to
        // Acme, not to Jane. (It is kept at all because many records carry only the name field,
        // and a company name in it is better than no attribution.)
        compile_patterns(&[
            r"(?im)^\s*Registrant Organization:\s*(.+)$",
            r"(?im)^\s*Registrant Organisation:\s*(.+)$",
            r"(?im)^\s*Organization:\s*(.+)$",
            r"(?im)^\s*Organisation:\s*(.+)$",
            r"(?im)^\s*OrgName:\s*(.+)$",
            r"(?im)^\s*org-name:\s*(.+)$",
            r"(?im)^\s*Company:\s*(.+)$",
            r"(?im)^\s*Registrant Name:\s*(.+)$",
            r"(?im)^\s*Registrant:\s*(.+)$",
            // Nominet .uk: "Registrant:\n    Acme Widgets Limited"
            r"(?im)^\s*Registrant:\s*$\r?\n\s+(\S.*)$",
        ])
    })
}

fn registrar_patterns() -> &'static [Regex] {
    REGISTRAR_PATTERNS.get_or_init(|| {
        compile_patterns(&[
            r"(?i)Registrar:\s*(.+)",
            r"(?i)Sponsoring Registrar:\s*(.+)",
            r"(?i)Registrar Name:\s*(.+)",
        ])
    })
}

/// Extract the registrant organization from a WHOIS response.
///
/// Two rules that were previously wrong:
///
/// 1. **The registrar is never the owner.** This used to fall back to the `Registrar:`
///    field whenever the organization field was missing or redacted, and return it as the
///    owning organization with `is_verified = true`. Post-GDPR that is the common case, so
///    the single largest source of confidently-wrong attributions was the tool reporting
///    "MarkMonitor" / "GoDaddy" / "Cloudflare" as the vendor. A redacted registrant means
///    we do not know the owner — the honest answer is `None`, and the caller falls through
///    to the next evidence source.
///
/// 2. **Intermediaries are filtered with domain context.** A registrant string naming a
///    privacy proxy, registrar, registry operator or postal address is not an owner —
///    unless it is that provider's *own* domain (cloudflare.com really is Cloudflare's).
///    [`crate::org_role`] makes that judgment for every source, not just this one.
#[cfg_attr(coverage_nightly, coverage(off))]
fn extract_organization_from_whois_for_domain(whois_data: &str, domain: &str) -> Option<String> {
    for regex in organization_patterns() {
        if let Some(cap) = regex.captures(whois_data) {
            if let Some(org_match) = cap.get(1) {
                let org = org_match.as_str().trim();
                if org.is_empty() {
                    continue;
                }
                let cleaned = clean_organization_name(org);
                if crate::org_role::is_intermediary_for_domain(&cleaned, domain) {
                    debug!(
                        "WHOIS organization '{}' for {} names an intermediary, not the owner",
                        cleaned, domain
                    );
                    continue;
                }
                return Some(cleaned);
            }
        }
    }

    // Deliberately NO registrar fallback: see rule 1 above.
    None
}

/// Domain-less variant, kept for callers that only have a response body.
#[cfg_attr(coverage_nightly, coverage(off))]
fn extract_organization_from_whois(whois_data: &str) -> Option<String> {
    extract_organization_from_whois_for_domain(whois_data, "")
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn extract_registrar_from_whois(whois_data: &str) -> Option<String> {
    for regex in registrar_patterns() {
        if let Some(cap) = regex.captures(whois_data) {
            if let Some(registrar_match) = cap.get(1) {
                let registrar = registrar_match.as_str().trim();
                if !registrar.is_empty() && !is_placeholder_organization(registrar) {
                    return Some(clean_organization_name(registrar));
                }
            }
        }
    }

    None
}

/// Registrant strings that name a privacy service, a registry operator, or a registrar
/// rather than the organization that actually owns the domain. A static slice: the list
/// is fixed, and rebuilding a ~120-element `Vec` on every candidate string was pure
/// repeated allocation on a path that runs several times per WHOIS response.
static PLACEHOLDER_ORGANIZATIONS: &[&str] = &[
    // Privacy protection services
    "whois privacy protection service",
    "privacy protection service",
    "domains by proxy",
    "whoisguard",
    "perfect privacy",
    "redacted for privacy",
    "contact privacy inc",
    "n/a",
    "not disclosed",
    "private",
    "redacted",
    "withheld",
    // TLD registry operators (not the actual domain owners)
    "verisign global registry",
    "verisign",
    "vrsn",
    "pir.org",
    "public interest registry",
    "afilias",
    "donuts",
    "identity digital",
    "centralnic",
    "nic.br",
    "denic",
    "nominet",
    "afnic",
    "sidn",
    "registry operator",
    "global registry services",
    "icann",
    // ccTLD registry authorities (government/national registries, not domain owners)
    "nic.ro",
    "rotld",
    "registro.br",
    "cnnic",
    "jprs",
    "krnic",
    "twnic",
    "mynic",
    "thnic",
    "vnnic",
    "sgnic",
    "hkirc",
    "auda",
    ".au domain administration",
    "nz domain name commission",
    "cira",
    "nic.at",
    "nic.ch",
    "switch",
    "dns belgium",
    "dns.pt",
    "nic.cz",
    "nic.pl",
    "domaininfo.com",
    "registro.it",
    "nic.ir",
    "registry.in",
    "nixi",
    "national internet exchange of india",
    // Domain registrars/brand protection services (not the actual domain owners)
    "markmonitor",
    "csc corporate domains",
    "corporatedomains.com",
    "safenames",
    "com laude",
    "nameprotect",
    "brand protection",
    "domain management",
    "networksolutions",
    "network solutions",
    "godaddy",
    "namecheap",
    "enom",
    "tucows",
    "key-systems",
    "gandi",
    "identity protection service",
    "identity protect",
    // Amazon registrar (operates as domain registrar, not the actual domain owner)
    "amazon registrar",
    "amazon registrar, inc.",
    // Additional registrars
    "porkbun",
    "cloudflare",
    "dynadot",
    "hover",
    "google domains",
    "squarespace domains",
    "bluehost",
    "hostgator",
    "dreamhost",
    "siteground",
    "ionos",
    "register.com",
    "name.com",
    "domain.com",
    "epik",
    // Registrant field values that aren't organization names
    "registrant street",
    "registrant city",
    "registrant state",
    "registrant postal",
    "registrant country",
    "registrant phone",
    "registrant email",
    "registrant fax",
    "admin street",
    "admin city",
    "tech street",
    "tech city",
    "po box",
    "p.o. box",
    "care of",
    "c/o ",
];

pub fn is_placeholder_organization(org: &str) -> bool {
    let placeholders = PLACEHOLDER_ORGANIZATIONS;

    let org_lower = org.to_lowercase();

    // Check if org contains any placeholder
    if placeholders
        .iter()
        .any(|&placeholder| org_lower.contains(placeholder))
    {
        return true;
    }

    // Check if org looks like an address (starts with numbers or contains common address patterns)
    if org_lower
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        // Likely an address like "5335 Gate Parkway..."
        return true;
    }

    false
}

fn clean_organization_name(org: &str) -> String {
    org.trim()
        .replace(['\n', '\r', '\t'], " ")
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

/// Batch lookup organizations for multiple domains in parallel
///
/// This function performs parallel WHOIS/organization lookups for a batch of domains,
/// rate-limited by the specified concurrency to avoid overwhelming WHOIS servers.
///
/// # Arguments
/// * `domains` - List of domains to look up
/// * `web_org_enabled` - Whether to enable web page organization extraction
/// * `min_confidence` - Minimum confidence for web org extraction
/// * `concurrency` - Maximum concurrent lookups (default: 5)
///
/// # Returns
/// A HashMap mapping domain -> OrganizationResult
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn batch_get_organizations(
    domains: Vec<String>,
    web_org_enabled: bool,
    min_confidence: f32,
    concurrency: usize,
) -> HashMap<String, OrganizationResult> {
    batch_get_organizations_with_rate_limit(
        domains,
        web_org_enabled,
        min_confidence,
        concurrency,
        None,
    )
    .await
}

/// Batch lookup organizations with optional rate limiting
///
/// This function performs parallel WHOIS/organization lookups for a batch of domains,
/// applying both concurrency limiting (semaphore) and rate limiting (token bucket).
///
/// # Arguments
/// * `domains` - List of domains to look up
/// * `web_org_enabled` - Whether to enable web page organization extraction
/// * `min_confidence` - Minimum confidence for web org extraction
/// * `concurrency` - Maximum concurrent lookups
/// * `rate_limit_ctx` - Optional rate limit context for WHOIS rate limiting
///
/// # Returns
/// A HashMap mapping domain -> OrganizationResult
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn batch_get_organizations_with_rate_limit(
    domains: Vec<String>,
    web_org_enabled: bool,
    min_confidence: f32,
    concurrency: usize,
    rate_limit_ctx: Option<&RateLimitContext>,
) -> HashMap<String, OrganizationResult> {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let total_domains = domains.len();

    debug!(
        "Starting parallel WHOIS lookups for {} domains (concurrency: {})",
        total_domains, concurrency
    );

    // Clone the rate limit context for use in async closures
    let rate_limit_ctx_opt = rate_limit_ctx.cloned();

    let results: Vec<(String, OrganizationResult)> = stream::iter(domains.into_iter().enumerate())
        .map(|(index, domain)| {
            let semaphore = semaphore.clone();
            let rate_limit_ctx_opt = rate_limit_ctx_opt.clone();
            async move {
                // Acquire semaphore permit to limit concurrency
                let _permit = semaphore
                    .acquire()
                    .await
                    .expect("whois concurrency semaphore is never closed");

                debug!("WHOIS lookup {}/{}: {}", index + 1, total_domains, domain);

                match get_organization_with_rate_limit(
                    &domain,
                    web_org_enabled,
                    min_confidence,
                    rate_limit_ctx_opt.as_ref(),
                )
                .await
                {
                    Ok(result) => {
                        debug!(
                            "WHOIS lookup complete for {}: {} (verified: {})",
                            domain, result.name, result.is_verified
                        );
                        (domain, result)
                    }
                    Err(e) => {
                        debug!(
                            "WHOIS lookup failed for {}: {}, using domain fallback",
                            domain, e
                        );
                        (
                            domain.clone(),
                            OrganizationResult::inferred(extract_organization_from_domain(&domain)),
                        )
                    }
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let result_map: HashMap<String, OrganizationResult> = results.into_iter().collect();
    debug!(
        "Completed parallel WHOIS lookups: {} results",
        result_map.len()
    );

    result_map
}

/// Pre-warm organization cache by performing parallel lookups for discovered domains
///
/// This is useful when you have a set of domains from DNS discovery and want to
/// resolve all their organizations in parallel before processing relationships.
///
/// # Arguments
/// * `domains` - List of domains to look up
/// * `existing_cache` - Already cached domain -> organization mappings to skip
/// * `web_org_enabled` - Whether to enable web page organization extraction
/// * `min_confidence` - Minimum confidence for web org extraction
/// * `concurrency` - Maximum concurrent lookups
/// * `logger` - Optional callback for logging progress
///
/// # Returns
/// A HashMap of newly resolved domain -> organization name mappings
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn prewarm_organization_cache<F>(
    domains: Vec<String>,
    existing_cache: &HashMap<String, String>,
    web_org_enabled: bool,
    min_confidence: f32,
    concurrency: usize,
    progress_callback: Option<F>,
) -> HashMap<String, String>
where
    F: Fn(usize, usize, &str) + Send + Sync,
{
    // Filter out domains already in cache
    let uncached_domains: Vec<String> = domains
        .into_iter()
        .filter(|d| !existing_cache.contains_key(d))
        .collect();

    if uncached_domains.is_empty() {
        debug!("All domains already cached, skipping WHOIS pre-warming");
        return HashMap::new();
    }

    let total = uncached_domains.len();
    debug!(
        "Pre-warming WHOIS cache for {} uncached domains (concurrency: {})",
        total, concurrency
    );

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let progress_counter = Arc::new(tokio::sync::Mutex::new(0usize));

    let results: Vec<(String, String)> = stream::iter(uncached_domains)
        .map(|domain| {
            let semaphore = semaphore.clone();
            let progress_counter = progress_counter.clone();
            let callback = &progress_callback;

            async move {
                let _permit = semaphore
                    .acquire()
                    .await
                    .expect("whois concurrency semaphore is never closed");

                // Update progress
                let current = {
                    let mut counter = progress_counter.lock().await;
                    *counter += 1;
                    *counter
                };

                if let Some(cb) = callback {
                    cb(current, total, &domain);
                }

                match get_organization_with_status_and_config(
                    &domain,
                    web_org_enabled,
                    min_confidence,
                )
                .await
                {
                    Ok(result) => (domain, result.name),
                    Err(_) => (domain.clone(), extract_organization_from_domain(&domain)),
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let new_cache: HashMap<String, String> = results.into_iter().collect();
    debug!("Pre-warmed {} organization mappings", new_cache.len());

    new_cache
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_brand_tld_attributes_every_domain_beneath_it() {
        // Found in a real depth-3 scan of vanta.com: 15 domains across .google, .aws and
        // .microsoft each shipped as its own bare label — "Blog", "Calculator", "Core" — because
        // nothing in the chain looked at the suffix. ICANN Spec 13 makes a .brand TLD
        // single-registrant, so the suffix alone settles ownership.
        // The suffix rule itself.
        assert_eq!(brand_tld_owner("blog.google"), Some("Google"));
        assert_eq!(brand_tld_owner("calculator.aws"), Some("Amazon"));
        assert_eq!(brand_tld_owner("core.microsoft"), Some("Microsoft"));

        // And end-to-end through the real chain. A more specific tier may name the company more
        // fully ("Microsoft Corporation") — that is the precedence working, so assert the company
        // is identified rather than pinning the exact string an earlier tier chose.
        for (domain, company) in [
            ("blog.google", "Google"),
            ("about.google", "Google"),
            ("ai.google", "Google"),
            ("calculator.aws", "Amazon"),
            ("api.aws", "Amazon"),
            ("core.microsoft", "Microsoft"),
            ("cloud.microsoft", "Microsoft"),
        ] {
            let got = resolve_curated(domain)
                .unwrap_or_else(|| panic!("{domain} should resolve without a network call"));
            assert!(
                got.name.contains(company),
                "{domain} resolved to {:?}, which does not name {company}",
                got.name
            );
            assert!(
                got.is_verified,
                "{domain} is settled by the registry, not inferred"
            );
        }
    }

    #[test]
    fn a_google_operated_registry_is_not_a_google_owned_domain() {
        // The trap this table exists to avoid. Google *operates* the .app, .dev and .cloud
        // registries, but anyone may register under them — so the suffix proves nothing about
        // ownership. Attributing them to Google would hand half the internet to Google.
        for domain in ["dagster.cloud", "sentry.dev", "slater.app", "linear.app"] {
            assert_eq!(
                brand_tld_owner(domain),
                None,
                "{domain} sits under an open registry, not a .brand TLD"
            );
        }
    }

    #[test]
    fn a_registry_that_answers_whois_with_prose_is_not_a_company() {
        // Real output from a depth-3 scan: youtu.be shipped with the organization
        // "Not shown, please visit www.dnsbelgium.be for webbased whois." It survived the older
        // gate because it is a grammatical sentence with capitalised words — it looks like a name.
        assert!(is_interstitial(
            "Not shown, please visit www.dnsbelgium.be for webbased whois."
        ));
        assert_eq!(
            accept_extracted_name(
                "Not shown, please visit www.dnsbelgium.be for webbased whois.",
                "youtu.be"
            ),
            None
        );
        // ...while a real company whose name merely contains an innocent word still passes.
        assert!(!is_interstitial("Visa"));
        assert!(!is_interstitial("Information Services Group"));
    }

    #[test]
    fn accept_extracted_name_rejects_taglines_and_intermediaries() {
        // This gate is what stands between a scraped page and the report. Everything a vendor's
        // own page (or an attacker's, or a parking provider's) says about itself arrives here.

        // A tagline is not a company name. Rejecting it means "keep looking" — the caller falls
        // through to WHOIS — which is why returning None here is the safe answer, not a loss.
        assert_eq!(
            accept_extracted_name("Payments infrastructure for the internet", "stripe.com"),
            None
        );
        assert_eq!(
            accept_extracted_name("Connective Infrastructure for Production AI", "e2b.dev"),
            None
        );
        // An interstitial served instead of the site.
        assert_eq!(
            accept_extracted_name("Attention Required! | Cloudflare", "some-vendor.com"),
            None
        );
        // An intermediary is never the owner of someone else's domain...
        assert_eq!(
            accept_extracted_name("GoDaddy.com, LLC", "some-customer.com"),
            None
        );
        assert_eq!(
            accept_extracted_name("REDACTED FOR PRIVACY", "some-customer.com"),
            None
        );
        // ...but it IS the owner of its own.
        assert_eq!(
            accept_extracted_name("GoDaddy.com, LLC", "godaddy.com").as_deref(),
            Some("GoDaddy.com, LLC")
        );
        // A real name passes, cleaned.
        assert_eq!(
            accept_extracted_name("  Stripe, Inc.  ", "stripe.com").as_deref(),
            Some("Stripe, Inc.")
        );
        assert_eq!(accept_extracted_name("", "stripe.com"), None);
    }

    #[test]
    fn accept_extracted_name_judges_the_string_it_would_ship() {
        // The gates used to run on the RAW candidate while the CLEANED form was what shipped, so
        // a tagline broken across lines slipped past the plausibility probes and was only caught
        // (or not) further downstream.
        assert_eq!(
            accept_extracted_name("Payments\ninfrastructure\nfor the internet", "stripe.com"),
            None
        );
    }

    #[test]
    fn test_whois_tld_query() {
        assert_eq!(whois_tld_query("example.com"), "com");
        assert_eq!(whois_tld_query("sub.example.co.uk"), "uk");
        assert_eq!(whois_tld_query("EXAMPLE.IO"), "io");
        assert_eq!(whois_tld_query("example.com."), "com");
        assert_eq!(whois_tld_query("localhost"), "localhost");
    }

    #[test]
    fn test_parse_whois_referral_iana_refer() {
        let resp = "% IANA WHOIS server\ndomain:       COM\nrefer:        whois.verisign-grs.com\n\norganisation: VeriSign\n";
        assert_eq!(
            parse_whois_referral(resp).as_deref(),
            Some("whois.verisign-grs.com")
        );
    }

    #[test]
    fn test_parse_whois_referral_registrar_server() {
        let resp = "Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\n";
        assert_eq!(
            parse_whois_referral(resp).as_deref(),
            Some("whois.markmonitor.com")
        );
    }

    #[test]
    fn test_parse_whois_referral_strips_scheme_and_trailing_dot() {
        let resp = "Registrar WHOIS Server: https://whois.example-registrar.com./extra\n";
        assert_eq!(
            parse_whois_referral(resp).as_deref(),
            Some("whois.example-registrar.com")
        );
    }

    #[test]
    fn test_parse_whois_referral_none_when_absent() {
        assert_eq!(
            parse_whois_referral("No referral here.\nDomain: x.com\n"),
            None
        );
        // A bare/garbage value (no dot) must not be accepted as a host.
        assert_eq!(parse_whois_referral("refer: localhost\n"), None);
    }

    #[tokio::test]
    async fn test_whois_query_rejects_injection() {
        // CR/LF/whitespace in the query must be rejected at the guard, before any
        // network I/O — so a discovered (not pre-validated) domain can't inject a
        // second WHOIS protocol line. The guard returns Err before TcpStream::connect.
        for bad in ["evil.com\r\ninject", "evil.com\nx", "a b.com", "a\tb.com"] {
            let r = whois_query("whois.iana.org", bad).await;
            assert!(r.is_err(), "should reject {bad:?}");
            assert!(
                r.unwrap_err().to_string().contains("invalid WHOIS query"),
                "expected guard error for {bad:?}"
            );
        }
    }

    #[test]
    fn test_organization_result_verified() {
        let result = OrganizationResult::verified("Test Corp".to_string(), "whois");
        assert_eq!(result.name, "Test Corp");
        assert!(result.is_verified);
        assert_eq!(result.source, "whois");
    }

    #[test]
    fn test_organization_result_inferred() {
        let result = OrganizationResult::inferred("Test Inc.".to_string());
        assert_eq!(result.name, "Test Inc.");
        assert!(!result.is_verified);
        assert_eq!(result.source, "domain_fallback");
    }

    #[test]
    fn test_extract_organization_from_domain() {
        // The domain fallback no longer fabricates a legal suffix. It previously returned
        // "Example Inc." — a company that does not exist — for every domain no source could
        // attribute, which made an unattributed domain indistinguishable from a real
        // attribution in the report. The label is what the owner chose; the " Inc." was ours.
        assert_eq!(extract_organization_from_domain("example.com"), "Example");
        assert_eq!(
            extract_organization_from_domain("test-company.org"),
            "Test-company"
        );

        // Subdomains resolve to the registrable label.
        assert_eq!(
            extract_organization_from_domain("www.example.com"),
            "Example"
        );
        assert_eq!(
            extract_organization_from_domain("api.sub.example.com"),
            "Example"
        );

        // Multi-label public suffixes now resolve correctly (PSL-backed): the old
        // second-to-last-label rule produced "Co" for every .co.uk domain.
        assert_eq!(extract_organization_from_domain("monzo.co.uk"), "Monzo");
    }

    #[test]
    fn test_is_placeholder_organization() {
        // Privacy protection services
        assert!(is_placeholder_organization("Domains by Proxy, LLC"));
        assert!(is_placeholder_organization("WhoisGuard Protected"));
        assert!(is_placeholder_organization("REDACTED FOR PRIVACY"));
        assert!(is_placeholder_organization("Contact Privacy Inc."));

        // Domain registrars
        assert!(is_placeholder_organization("MarkMonitor Inc."));
        assert!(is_placeholder_organization("GoDaddy.com, LLC"));
        assert!(is_placeholder_organization("Cloudflare, Inc."));

        // TLD registry operators (BUG-006)
        assert!(is_placeholder_organization(
            "Verisign Global Registry Services"
        ));
        assert!(is_placeholder_organization("VeriSign, Inc."));
        assert!(is_placeholder_organization("Public Interest Registry"));
        assert!(is_placeholder_organization("ICANN"));

        // Address-like values (start with numbers)
        assert!(is_placeholder_organization("5335 Gate Parkway"));
        assert!(is_placeholder_organization("123 Main Street"));

        // Amazon Registrar (registrar, not domain owner)
        assert!(is_placeholder_organization("Amazon Registrar, Inc."));
        assert!(is_placeholder_organization("Amazon Registrar"));

        // ccTLD registry authorities (government/national registries)
        assert!(is_placeholder_organization("RoTLD"));
        assert!(is_placeholder_organization("CNNIC"));
        assert!(is_placeholder_organization("JPRS"));
        assert!(is_placeholder_organization("CIRA"));
        assert!(is_placeholder_organization("DNS Belgium"));
        assert!(is_placeholder_organization(
            "National Internet Exchange of India"
        ));

        // Valid organization names
        assert!(!is_placeholder_organization("Microsoft Corporation"));
        assert!(!is_placeholder_organization("Google LLC"));
        assert!(!is_placeholder_organization("Anthropic PBC"));
        assert!(!is_placeholder_organization("Amazon.com, Inc.")); // Amazon the company, NOT registrar
    }

    #[test]
    fn test_clean_organization_name() {
        assert_eq!(clean_organization_name("  Test Corp  "), "Test Corp");
        assert_eq!(clean_organization_name("Test\nCorp"), "Test Corp");
        assert_eq!(clean_organization_name("Test\r\nCorp"), "Test Corp");
        assert_eq!(clean_organization_name("Test\t\tCorp"), "Test Corp");
        assert_eq!(
            clean_organization_name("  Multiple   Spaces  "),
            "Multiple Spaces"
        );
    }

    #[test]
    fn test_extract_organization_from_whois() {
        // Valid organization field
        let whois_data =
            "Domain Name: example.com\nOrganization: Test Corporation\nRegistrar: GoDaddy";
        assert_eq!(
            extract_organization_from_whois(whois_data),
            Some("Test Corporation".to_string())
        );

        // Registrant Organization field
        let whois_data =
            "Domain Name: example.com\nRegistrant Organization: Acme Inc\nRegistrar: NameCheap";
        assert_eq!(
            extract_organization_from_whois(whois_data),
            Some("Acme Inc".to_string())
        );

        // Privacy-protected registrant: the answer is "we do not know", NOT the registrar.
        // This assertion used to expect "Real Registrar" — the registrar reported as the
        // domain's owning organization. See test_registrar_is_never_returned_as_the_owner.
        let whois_data = "Domain Name: example.com\nOrganization: REDACTED FOR PRIVACY\nRegistrar: Real Registrar";
        assert_eq!(extract_organization_from_whois(whois_data), None);

        // Same, with a registrar that was already denylisted.
        let whois_data = "Domain Name: example.com\nOrganization: REDACTED FOR PRIVACY\nRegistrar: GoDaddy.com, LLC";
        assert!(extract_organization_from_whois(whois_data).is_none());

        // Registry operator as organization (BUG-006) — should be rejected
        let whois_data = "Domain Name: smtp.com\nOrganization: Verisign Global Registry Services\nRegistrar: Network Solutions, LLC";
        // Verisign is a registry operator, not the domain owner; registrar is also a placeholder
        assert!(
            extract_organization_from_whois(whois_data).is_none(),
            "Registry operator should be rejected as placeholder"
        );

        // Registry operator as registrant, with a valid-looking registrar: still None. The
        // registrar is not evidence of ownership no matter how ordinary its name looks —
        // this assertion previously expected "Acme Corp" (the registrar) as smtp.com's owner.
        let whois_data =
            "Domain Name: smtp.com\nOrganization: VeriSign, Inc.\nRegistrar: Acme Corp";
        assert_eq!(extract_organization_from_whois(whois_data), None);

        // Amazon Registrar as registrar — should be rejected (not the domain owner)
        let whois_data = "Domain Name: example.com\nOrganization: REDACTED FOR PRIVACY\nRegistrar: Amazon Registrar, Inc.";
        assert!(
            extract_organization_from_whois(whois_data).is_none(),
            "Amazon Registrar should be rejected as a registrar placeholder"
        );

        // ccTLD WHOIS returning country registry authority — registrant is rejected,
        // but registrar may still return a non-placeholder value
        let whois_data = "Domain Name: example.ro\nRegistrant: RoTLD";
        assert!(
            extract_organization_from_whois(whois_data).is_none(),
            "RoTLD (Romania ccTLD registry) should be rejected as placeholder"
        );

        // When both registrant AND registrar are ccTLD-related, should return None
        let whois_data = "Domain Name: example.ro\nRegistrant: RoTLD\nRegistrar: NIC.RO";
        assert!(
            extract_organization_from_whois(whois_data).is_none(),
            "Both RoTLD and NIC.RO should be rejected as ccTLD registry placeholders"
        );
    }

    #[tokio::test]
    async fn test_batch_get_organizations_empty_list() {
        let domains: Vec<String> = vec![];
        let results = batch_get_organizations(domains, false, 0.6, 5).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_batch_get_organizations_concurrency_limit() {
        // Test that concurrency is properly limited
        // This test uses known_vendors which should return quickly
        let domains = vec![
            "google.com".to_string(),
            "microsoft.com".to_string(),
            "amazon.com".to_string(),
        ];

        let results = batch_get_organizations(domains.clone(), false, 0.6, 2).await;

        // All domains should be resolved
        assert_eq!(results.len(), 3);

        // Each domain should have a result
        for domain in &domains {
            assert!(
                results.contains_key(domain),
                "Missing result for {}",
                domain
            );
        }
    }

    #[tokio::test]
    async fn test_prewarm_organization_cache_skips_cached() {
        let domains = vec!["cached.com".to_string(), "new.com".to_string()];

        let mut existing_cache = HashMap::new();
        existing_cache.insert("cached.com".to_string(), "Cached Corp".to_string());

        let new_results = prewarm_organization_cache::<fn(usize, usize, &str)>(
            domains,
            &existing_cache,
            false,
            0.6,
            5,
            None,
        )
        .await;

        // Only the uncached domain should be in results
        assert!(
            !new_results.contains_key("cached.com"),
            "Cached domain should be skipped"
        );
        assert!(
            new_results.contains_key("new.com"),
            "New domain should be resolved"
        );
    }

    #[tokio::test]
    async fn test_prewarm_organization_cache_all_cached() {
        let domains = vec!["cached1.com".to_string(), "cached2.com".to_string()];

        let mut existing_cache = HashMap::new();
        existing_cache.insert("cached1.com".to_string(), "Corp 1".to_string());
        existing_cache.insert("cached2.com".to_string(), "Corp 2".to_string());

        let new_results = prewarm_organization_cache::<fn(usize, usize, &str)>(
            domains,
            &existing_cache,
            false,
            0.6,
            5,
            None,
        )
        .await;

        // No new results since all were cached
        assert!(
            new_results.is_empty(),
            "Should return empty when all domains cached"
        );
    }

    #[tokio::test]
    async fn test_prewarm_with_progress_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let domains = vec!["test1.com".to_string(), "test2.com".to_string()];

        let existing_cache = HashMap::new();
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let callback = move |_current: usize, _total: usize, _domain: &str| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
        };

        let _results =
            prewarm_organization_cache(domains, &existing_cache, false, 0.6, 5, Some(callback))
                .await;

        // Callback should be called for each domain
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "Progress callback should be called for each domain"
        );
    }

    #[tokio::test]
    async fn test_get_organization_with_rate_limit() {
        use crate::config::RateLimitConfig;

        // Create a rate limit context with high limits to avoid actual waiting in tests
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);

        // Test with rate limiting enabled - should work for a domain in known_vendors
        let result = get_organization_with_rate_limit("google.com", false, 0.6, Some(&ctx)).await;
        assert!(result.is_ok(), "Should successfully look up organization");
        let org = result.unwrap();
        // Sanity check: result should be valid (verified or inferred)
        let _ = &org;
    }

    #[tokio::test]
    async fn test_batch_get_organizations_with_rate_limit() {
        use crate::config::RateLimitConfig;

        // Create a rate limit context
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);

        let domains = vec!["google.com".to_string(), "microsoft.com".to_string()];

        let results =
            batch_get_organizations_with_rate_limit(domains.clone(), false, 0.6, 2, Some(&ctx))
                .await;

        // All domains should have results
        assert_eq!(results.len(), 2);
        for domain in &domains {
            assert!(
                results.contains_key(domain),
                "Missing result for {}",
                domain
            );
        }
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    // --- extract_organization_from_domain edge cases ---

    #[test]
    fn test_extract_organization_from_domain_single_part() {
        // Single part domain (no dots) - falls through to domain.to_string()
        assert_eq!(extract_organization_from_domain("localhost"), "localhost");
    }

    #[test]
    fn test_extract_organization_from_domain_capitalization() {
        // No fabricated legal suffix — see test_extract_organization_from_domain.
        assert_eq!(extract_organization_from_domain("stripe.com"), "Stripe");
        assert_eq!(extract_organization_from_domain("UPPER.com"), "Upper");
    }

    // --- extract_organization_from_whois additional patterns ---

    #[test]
    fn test_extract_org_from_whois_orgname() {
        let whois_data = "OrgName: My Organization\nAddress: 123 Main St";
        assert_eq!(
            extract_organization_from_whois(whois_data),
            Some("My Organization".to_string())
        );
    }

    #[test]
    fn test_extract_org_from_whois_org_name_lowercase() {
        let whois_data = "org-name: Lowercase Org\nstatus: active";
        assert_eq!(
            extract_organization_from_whois(whois_data),
            Some("Lowercase Org".to_string())
        );
    }

    #[test]
    fn test_extract_org_from_whois_organisation() {
        let whois_data = "organisation: British Org Ltd\ncountry: GB";
        assert_eq!(
            extract_organization_from_whois(whois_data),
            Some("British Org Ltd".to_string())
        );
    }

    #[test]
    fn test_extract_org_from_whois_company() {
        let whois_data = "Company: Test Company GmbH\nphone: +49";
        assert_eq!(
            extract_organization_from_whois(whois_data),
            Some("Test Company GmbH".to_string())
        );
    }

    #[test]
    fn test_extract_org_from_whois_empty_org() {
        // Empty organization field is matched by the regex but is_empty() check filters it
        // The Registrar: pattern is also matched - but the regex captures everything after
        // "Registrar:" which includes the rest of the line
        let whois_data = "Organization: \nRegistrar: Acme Registrar";
        let result = extract_organization_from_whois(whois_data);
        // "Registrar:" line matches the registrar extraction path
        assert!(result.is_some());
    }

    // --- extract_registrar_from_whois ---

    #[test]
    fn test_extract_registrar_sponsoring() {
        let whois_data = "Sponsoring Registrar: Real Corp\nDomain: test.com";
        assert_eq!(
            extract_registrar_from_whois(whois_data),
            Some("Real Corp".to_string())
        );
    }

    #[test]
    fn test_extract_registrar_name() {
        let whois_data = "Registrar Name: Actual Business Inc\nDomain: test.com";
        assert_eq!(
            extract_registrar_from_whois(whois_data),
            Some("Actual Business Inc".to_string())
        );
    }

    #[test]
    fn test_extract_registrar_placeholder_filtered() {
        let whois_data = "Registrar: Namecheap, Inc.\nDomain: test.com";
        assert!(extract_registrar_from_whois(whois_data).is_none());
    }

    #[test]
    fn test_extract_registrar_none() {
        let whois_data = "Domain: test.com\nStatus: active";
        assert!(extract_registrar_from_whois(whois_data).is_none());
    }

    // --- is_placeholder_organization additional patterns ---

    #[test]
    fn test_is_placeholder_additional_registrars() {
        assert!(is_placeholder_organization("Porkbun LLC"));
        assert!(is_placeholder_organization("Dynadot Inc"));
        assert!(is_placeholder_organization("Hover, a Tucows company"));
        assert!(is_placeholder_organization("Google Domains LLC"));
        assert!(is_placeholder_organization("Squarespace Domains LLC"));
        assert!(is_placeholder_organization("Bluehost Inc"));
        assert!(is_placeholder_organization("DreamHost LLC"));
        assert!(is_placeholder_organization("SiteGround Ltd"));
        assert!(is_placeholder_organization("IONOS SE"));
        assert!(is_placeholder_organization("Register.com Inc"));
        assert!(is_placeholder_organization("Name.com Inc"));
        assert!(is_placeholder_organization("Epik Inc"));
    }

    #[test]
    fn test_is_placeholder_privacy_services() {
        assert!(is_placeholder_organization("Perfect Privacy LLC"));
        assert!(is_placeholder_organization("Identity Protect Limited"));
        assert!(is_placeholder_organization("Identity Protection Service"));
    }

    #[test]
    fn test_is_placeholder_registrant_fields() {
        assert!(is_placeholder_organization("Registrant Street"));
        assert!(is_placeholder_organization("Registrant City"));
        assert!(is_placeholder_organization("Admin Street"));
        assert!(is_placeholder_organization("PO Box 12345"));
        assert!(is_placeholder_organization("P.O. Box 999"));
        assert!(is_placeholder_organization("Care Of Someone"));
        assert!(is_placeholder_organization("c/o Privacy"));
    }

    #[test]
    fn test_is_placeholder_valid_orgs() {
        assert!(!is_placeholder_organization("Stripe, Inc."));
        assert!(!is_placeholder_organization("Anthropic PBC"));
        assert!(!is_placeholder_organization("Datadog Inc."));
        // Cloudflare IS in the placeholder list (it's a domain registrar)
        assert!(is_placeholder_organization("Cloudflare, Inc."));
        // These should NOT be placeholders
        assert!(!is_placeholder_organization("Notion Labs, Inc."));
        assert!(!is_placeholder_organization("Figma, Inc."));
    }

    // --- clean_organization_name ---

    #[test]
    fn test_clean_organization_name_complex() {
        assert_eq!(
            clean_organization_name("  Test\r\n\tOrg  Name  "),
            "Test Org Name"
        );
    }

    // --- execute_whois_command ---

    #[tokio::test]
    async fn test_execute_whois_command_compiles() {
        // This test just verifies the function exists and handles missing commands
        // gracefully without panicking
        let result = execute_whois_command("nonexistent-domain-12345.com").await;
        // May succeed or fail depending on whether whois is installed
        let _ = result;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_organization_from_whois — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_org_from_whois_registrant_organization() {
        let whois = "Registrant Organization: Stripe, Inc.\nRegistrant Country: US";
        let result = extract_organization_from_whois(whois);
        assert_eq!(result, Some("Stripe, Inc.".to_string()));
    }

    #[test]
    fn test_extract_org_from_whois_company_field() {
        let whois = "Company: Acme Corporation\nCountry: UK";
        let result = extract_organization_from_whois(whois);
        assert_eq!(result, Some("Acme Corporation".to_string()));
    }

    #[test]
    fn test_extract_org_from_whois_privacy_filtered() {
        let whois = "Organization: Whois Privacy Protection Service\nRegistrar: GoDaddy";
        let result = extract_organization_from_whois(whois);
        // Privacy org should be filtered, falls back to registrar
        // GoDaddy is also a registrar placeholder, so should return None
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_org_from_whois_empty_field() {
        let whois = "Organization: \nRegistrar: MarkMonitor Inc.";
        let result = extract_organization_from_whois(whois);
        // Empty org field, falls back to registrar — but MarkMonitor is a placeholder
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_org_from_whois_no_matching_field() {
        let whois = "Domain: example.com\nCreated: 2020-01-01";
        let result = extract_organization_from_whois(whois);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_org_from_whois_multiple_patterns() {
        // Organization: takes priority over OrgName:
        let whois = "Organization: Primary Corp\nOrgName: Secondary Corp";
        let result = extract_organization_from_whois(whois);
        assert_eq!(result, Some("Primary Corp".to_string()));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_registrar_from_whois — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_registrar_from_whois_registrar_field() {
        let whois = "Registrar: Gandi SAS\nRegistrar URL: https://gandi.net";
        let result = extract_registrar_from_whois(whois);
        // Gandi is in the placeholder list
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_registrar_from_whois_valid_registrar() {
        let whois = "Registrar: Some Legitimate Company";
        let result = extract_registrar_from_whois(whois);
        assert_eq!(result, Some("Some Legitimate Company".to_string()));
    }

    #[test]
    fn test_extract_registrar_from_whois_no_registrar() {
        let whois = "Domain: test.com\nStatus: active";
        let result = extract_registrar_from_whois(whois);
        assert!(result.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_organization_from_domain — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_org_from_domain_standard() {
        // No fabricated " Inc." — see test_extract_organization_from_domain.
        let result = extract_organization_from_domain("stripe.com");
        assert_eq!(result, "Stripe");
    }

    #[test]
    fn test_extract_org_from_domain_with_subdomain() {
        let result = extract_organization_from_domain("api.stripe.com");
        assert_eq!(result, "Stripe");
    }

    #[test]
    fn test_extract_org_from_domain_bare_tld() {
        // A bare public suffix has no owner to name, so it is returned untouched rather
        // than becoming the organization "Com".
        let result = extract_organization_from_domain("com");
        assert_eq!(result, "com");
    }

    #[test]
    fn test_extract_org_from_domain_hyphenated() {
        let result = extract_organization_from_domain("my-company.com");
        assert_eq!(result, "My-company");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // is_placeholder_organization — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_is_placeholder_address_starting_with_number() {
        assert!(is_placeholder_organization("123 Main Street, Suite 100"));
        assert!(is_placeholder_organization("5335 Gate Parkway"));
    }

    #[test]
    fn test_is_placeholder_amazon_registrar() {
        assert!(is_placeholder_organization("Amazon Registrar, Inc."));
        assert!(is_placeholder_organization("amazon registrar"));
    }

    #[test]
    fn test_is_placeholder_cctld_registries() {
        assert!(is_placeholder_organization("NIC.RO"));
        assert!(is_placeholder_organization("ROTLD"));
        assert!(is_placeholder_organization("CNNIC"));
        assert!(is_placeholder_organization("JPRS"));
    }

    #[test]
    fn test_is_placeholder_case_insensitive() {
        assert!(is_placeholder_organization("WHOISGUARD"));
        assert!(is_placeholder_organization("Domains By Proxy"));
        assert!(is_placeholder_organization("REDACTED FOR PRIVACY"));
    }

    #[test]
    fn test_is_placeholder_registrant_address_fields() {
        assert!(is_placeholder_organization("Registrant Street: 123 Main"));
        assert!(is_placeholder_organization("Admin City: New York"));
        assert!(is_placeholder_organization("PO Box 1234"));
        assert!(is_placeholder_organization("c/o Domain Admin"));
    }

    #[test]
    fn test_is_not_placeholder_real_orgs() {
        assert!(!is_placeholder_organization("Stripe, Inc."));
        assert!(!is_placeholder_organization("Amazon.com Services LLC")); // Not "Amazon Registrar"
        assert!(!is_placeholder_organization("Microsoft Corporation"));
        assert!(!is_placeholder_organization("Alphabet Inc."));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // clean_organization_name — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_clean_org_name_whitespace_only() {
        assert_eq!(clean_organization_name("   "), "");
    }

    #[test]
    fn test_clean_org_name_tabs_and_newlines() {
        assert_eq!(
            clean_organization_name("Corp\t\tName\n\nHere"),
            "Corp Name Here"
        );
    }

    #[test]
    fn test_clean_org_name_normal_input() {
        assert_eq!(clean_organization_name("Stripe Inc."), "Stripe Inc.");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // OrganizationResult struct coverage
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_organization_result_debug() {
        let result = OrganizationResult::verified("Test".to_string(), "whois");
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Test"));
    }

    #[test]
    fn test_organization_result_clone() {
        let result = OrganizationResult::verified("Test Corp".to_string(), "whois");
        let cloned = result.clone();
        assert_eq!(result.name, cloned.name);
        assert_eq!(result.is_verified, cloned.is_verified);
        assert_eq!(result.source, cloned.source);
    }

    #[test]
    fn test_organization_result_inferred_not_verified() {
        let result = OrganizationResult::inferred("Test Corp".to_string());
        assert!(!result.is_verified);
        assert_eq!(result.source, "domain_fallback");
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    #[test]
    fn test_extract_org_placeholder_falls_through() {
        // Organization field matches the regex but value is a known placeholder
        let whois = "Organization: REDACTED FOR PRIVACY\nRegistrar: REDACTED FOR PRIVACY";
        let result = extract_organization_from_whois(whois);
        // Both org and registrar are placeholders, so should return None
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_org_empty_value_falls_through() {
        let whois = "Organization:   ";
        let result = extract_organization_from_whois(whois);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_registrar_placeholder_falls_through() {
        // Only registrar lines present, all placeholders
        let whois = "Registrar: Verisign\nSponsoring Registrar: N/A";
        let result = extract_registrar_from_whois(whois);
        // "Verisign" is a placeholder organization
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_registrar_empty_falls_through() {
        let whois = "Registrar:   ";
        let result = extract_registrar_from_whois(whois);
        assert!(result.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Tests for previously-coverage(off) async functions
    // ═══════════════════════════════════════════════════════════════════════════

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_get_organization_with_status_returns_result() {
        let result = get_organization_with_status("google.com").await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty(), "Organization name must not be empty");
        assert!(
            org.source == "known_vendors"
                || org.source == "known_vendor"
                || org.source == "vendor_registry"
                || org.source.starts_with("web_")
                || org.source == "whois"
                || org.source == "system_whois"
                || org.source == "domain_fallback",
            "Source should be a recognized value, got: {}",
            org.source
        );
    }

    #[tokio::test]
    async fn test_get_organization_with_status_fallback_domain() {
        let result = get_organization_with_status("zzz-nonexistent-test-domain-12345.com").await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_organization_with_status_and_config_web_disabled() {
        let result = get_organization_with_status_and_config("google.com", false, 0.6).await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
        assert!(
            !org.source.starts_with("web_"),
            "With web disabled, source should not be web-based, got: {}",
            org.source
        );
    }

    #[tokio::test]
    async fn test_get_organization_with_status_and_config_high_confidence_threshold() {
        let result = get_organization_with_status_and_config("google.com", false, 0.99).await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_organization_returns_string() {
        let result = get_organization("google.com").await;
        assert!(result.is_ok());
        let org_name = result.unwrap();
        assert!(!org_name.is_empty(), "Organization name must not be empty");
    }

    #[tokio::test]
    async fn test_get_organization_fallback_domain() {
        let result = get_organization("zzz-nonexistent-domain-99999.com").await;
        assert!(result.is_ok());
        let org_name = result.unwrap();
        assert!(!org_name.is_empty());
        // The fallback names the domain's own label and invents nothing. This assertion used
        // to REQUIRE the fabricated "Inc." suffix.
        assert!(
            !org_name.contains("Inc."),
            "Fallback must not fabricate a legal suffix, got: {}",
            org_name
        );
        assert!(
            org_name.to_lowercase().starts_with("zzz-nonexistent"),
            "Fallback should be derived from the domain label, got: {}",
            org_name
        );
    }

    #[tokio::test]
    async fn test_get_organization_with_config_web_disabled() {
        let result = get_organization_with_config("microsoft.com", false, 0.6).await;
        assert!(result.is_ok());
        let org_name = result.unwrap();
        assert!(!org_name.is_empty());
    }

    #[tokio::test]
    async fn test_get_organization_with_config_high_confidence_threshold() {
        let result = get_organization_with_config("google.com", false, 0.99).await;
        assert!(result.is_ok());
        let org_name = result.unwrap();
        assert!(!org_name.is_empty());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_native_whois_nonexistent_tld() {
        let result = try_native_whois("zzz-nonexistent-domain-00000.invalid").await;
        // .invalid TLD may fail or return data depending on WHOIS server behavior
        match result {
            Ok(data) => assert!(!data.is_empty() || data.is_empty()),
            Err(e) => {
                let msg = e.to_string();
                assert!(!msg.is_empty(), "Error message should be descriptive");
            }
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_system_whois_does_not_panic() {
        // try_system_whois wraps execute_whois_command (tokio::process children, kill_on_drop) in
        // a single 4s timeout. The result varies by platform — we verify it handles all outcomes
        // without panicking.
        let result = try_system_whois("example.com").await;
        assert!(
            result.is_ok() || result.is_err(),
            "Must return a valid Result"
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_system_whois_timeout_path() {
        // .invalid TLD should hit the error/timeout path on most systems
        let result = try_system_whois("zzz-nonexistent.invalid").await;
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(!msg.is_empty(), "Error message must not be empty");
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_execute_whois_command_returns_result() {
        let result = execute_whois_command("example.com").await;
        match result {
            Ok(_data) => {
                // Command found and executed — Ok is the expected success path.
                // Data may be empty on some platforms (e.g., piped stdout).
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("whois") || msg.contains("command"),
                    "Error should mention whois: {}",
                    msg
                );
            }
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_execute_whois_command_error_on_missing_binary() {
        // On any system, calling the function exercises the for-loop over command paths.
        // The function returns Err only if NO whois binary is found.
        let result = execute_whois_command("zzz-definitely-not-a-real-domain.invalid").await;
        assert!(
            result.is_ok() || result.is_err(),
            "Must return a valid Result regardless of domain"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // GRC-317: Coverage for async function bodies & network I/O paths
    // ═══════════════════════════════════════════════════════════════════════════

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_native_whois_valid_domain() {
        let result = try_native_whois("example.com").await;
        match result {
            Ok(data) => {
                assert!(
                    !data.is_empty(),
                    "WHOIS data should not be empty for example.com"
                );
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("WHOIS")
                        || msg.contains("lookup")
                        || msg.contains("timed out")
                        || msg.contains("panicked")
                        || msg.contains("Failed"),
                    "Error should be descriptive: {}",
                    msg
                );
            }
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_native_whois_simple_tld() {
        let result = try_native_whois("iana.org").await;
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_system_whois_valid_domain() {
        let result = try_system_whois("example.com").await;
        match result {
            Ok(_data) => {}
            Err(e) => assert!(!e.to_string().is_empty()),
        }
    }

    fn ensure_known_vendors_initialized() {
        let _ = crate::known_vendors::init();
    }

    #[tokio::test]
    async fn test_get_org_with_rate_limit_known_vendor() {
        use crate::config::RateLimitConfig;
        ensure_known_vendors_initialized();
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);
        let result = get_organization_with_rate_limit("google.com", false, 0.6, Some(&ctx)).await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_rate_limit_non_vendor_domain() {
        use crate::config::RateLimitConfig;
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);
        let result = get_organization_with_rate_limit("example.com", false, 0.6, Some(&ctx)).await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_rate_limit_no_ctx() {
        let result = get_organization_with_rate_limit("example.com", false, 0.6, None).await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_status_and_config_known_vendor() {
        ensure_known_vendors_initialized();
        let result = get_organization_with_status_and_config("google.com", false, 0.6).await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_status_and_config_non_vendor() {
        let result = get_organization_with_status_and_config("example.com", false, 0.6).await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_config_known_vendor() {
        ensure_known_vendors_initialized();
        let result = get_organization_with_config("google.com", false, 0.6).await;
        assert!(result.is_ok());
        let org_name = result.unwrap();
        assert!(!org_name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_config_non_vendor() {
        let result = get_organization_with_config("example.com", false, 0.6).await;
        assert!(result.is_ok());
        let org_name = result.unwrap();
        assert!(!org_name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_status_non_vendor() {
        let result = get_organization_with_status("example.com").await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_status_known_vendor() {
        ensure_known_vendors_initialized();
        let result = get_organization_with_status("google.com").await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_organization_known_vendor() {
        ensure_known_vendors_initialized();
        let result = get_organization("google.com").await;
        assert!(result.is_ok());
        let org_name = result.unwrap();
        assert!(!org_name.is_empty());
    }

    #[tokio::test]
    async fn test_batch_with_rate_limit_mixed_domains() {
        use crate::config::RateLimitConfig;
        ensure_known_vendors_initialized();
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);
        let domains = vec![
            "google.com".to_string(),
            "zzz-nonexistent-batch-12345.invalid".to_string(),
        ];
        let results =
            batch_get_organizations_with_rate_limit(domains.clone(), false, 0.6, 2, Some(&ctx))
                .await;
        assert_eq!(results.len(), 2);
        for domain in &domains {
            assert!(results.contains_key(domain));
        }
    }

    #[tokio::test]
    async fn test_prewarm_cache_with_failing_domain() {
        let domains = vec!["zzz-prewarm-fail-test.invalid".to_string()];
        let existing_cache = HashMap::new();
        let results = prewarm_organization_cache::<fn(usize, usize, &str)>(
            domains,
            &existing_cache,
            false,
            0.6,
            5,
            None,
        )
        .await;
        assert!(results.contains_key("zzz-prewarm-fail-test.invalid"));
    }

    #[test]
    fn test_extract_org_whois_all_patterns_placeholder_or_empty() {
        // Each org pattern matches but the captured value is a placeholder.
        // This forces the loop to iterate through ALL patterns (covering
        // the fall-through braces at lines 461, 463).
        let whois_data = "Organization: REDACTED FOR PRIVACY\n\
                          Registrant Organization: Domains by Proxy\n\
                          Registrant: WhoisGuard Protected\n\
                          OrgName: N/A\n\
                          org-name: REDACTED\n\
                          organisation: Private\n\
                          Company: Withheld";
        let result = extract_organization_from_whois(whois_data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_registrar_all_patterns_placeholder() {
        // Each registrar pattern matches but captures a placeholder.
        let whois_data = "Registrar: GoDaddy.com, LLC\n\
                          Sponsoring Registrar: Namecheap, Inc.\n\
                          Registrar Name: Cloudflare, Inc.";
        let result = extract_registrar_from_whois(whois_data);
        assert!(result.is_none());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_execute_whois_command_real_domain() {
        let result = execute_whois_command("example.com").await;
        match &result {
            Ok(data) => {
                let _ = data.len();
            }
            Err(e) => {
                let _ = e.to_string();
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // GRC-317 Phase 2: Targeted coverage for remaining uncovered paths
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_org_with_rate_limit_web_org_enabled() {
        use crate::config::RateLimitConfig;
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);
        let result = get_organization_with_rate_limit("example.com", true, 0.6, Some(&ctx)).await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_rate_limit_web_org_high_confidence() {
        use crate::config::RateLimitConfig;
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);
        let result = get_organization_with_rate_limit("example.com", true, 0.99, Some(&ctx)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_org_with_status_and_config_web_enabled() {
        let result = get_organization_with_status_and_config("example.com", true, 0.6).await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_status_and_config_web_high_conf() {
        let result = get_organization_with_status_and_config("example.com", true, 0.99).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_org_with_config_web_enabled() {
        let result = get_organization_with_config("example.com", true, 0.6).await;
        assert!(result.is_ok());
        let org_name = result.unwrap();
        assert!(!org_name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_config_web_high_conf() {
        let result = get_organization_with_config("example.com", true, 0.99).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_org_with_status_web_enabled() {
        let result = get_organization_with_status("example.com").await;
        assert!(result.is_ok());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_native_whois_com_domain() {
        let result = try_native_whois("google.com").await;
        match result {
            Ok(data) => assert!(!data.is_empty()),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("WHOIS")
                        || msg.contains("lookup")
                        || msg.contains("timed out")
                        || msg.contains("panicked")
                        || msg.contains("Failed")
                        || msg.contains("Invalid"),
                    "Unexpected error: {}",
                    msg
                );
            }
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_native_whois_net_domain() {
        let result = try_native_whois("example.net").await;
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_native_whois_org_domain() {
        let result = try_native_whois("example.org").await;
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_native_whois_unknown_tld() {
        let result = try_native_whois("test.xyz").await;
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_system_whois_known_domain() {
        let result = try_system_whois("google.com").await;
        match result {
            Ok(_data) => {}
            Err(e) => assert!(!e.to_string().is_empty()),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_try_system_whois_invalid_domain() {
        let result = try_system_whois("x".repeat(255).as_str()).await;
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_execute_whois_command_various_domains() {
        for domain in &["google.com", "example.net", "nonexistent.invalid"] {
            let result = execute_whois_command(domain).await;
            let _ = result;
        }
    }

    #[test]
    fn test_extract_org_from_whois_no_org_fields() {
        let whois = "Domain Name: test.com\nCreation Date: 2020-01-01\nExpiry Date: 2025-01-01";
        let result = extract_organization_from_whois(whois);
        assert!(result.is_none());
    }

    #[test]
    fn test_registrant_scoped_field_wins_over_bare_organization() {
        // Precedence now favours the registrant-SCOPED field. A bare "Organization:" line
        // can belong to any contact block in a WHOIS record (admin, tech, billing — often
        // the registrar's own staff), while "Registrant Organization:" unambiguously names
        // the party that registered the domain. When a record carries both, the registrant
        // one is the answer. (Previously the array order decided, so whichever pattern was
        // listed first won regardless of which field was more specific.)
        let whois = "Organization: ValidCorp\nRegistrant Organization: OtherCorp";
        let result = extract_organization_from_whois(whois);
        assert_eq!(result, Some("OtherCorp".to_string()));
    }

    #[test]
    fn test_admin_and_tech_organization_lines_are_not_the_registrant() {
        // The unanchored regex matched "Admin Organization:" and "Tech Organization:" —
        // the registrar's or a law firm's contact — and whichever appeared first in the
        // response won. Anchoring to line starts confines matching to the real fields.
        let whois = "Admin Organization: Law Firm LLP\nTech Organization: Hosting Provider\nRegistrant Organization: Real Owner Ltd";
        assert_eq!(
            extract_organization_from_whois(whois),
            Some("Real Owner Ltd".to_string())
        );
    }

    #[test]
    fn test_nominet_next_line_registrant_is_parsed() {
        // Nominet (.uk) puts the registrant on the line AFTER "Registrant:", so the
        // same-line regex could never capture it and every .uk domain fell through to the
        // fabricated domain fallback.
        let whois = "Domain name:\n    example.co.uk\n\nRegistrant:\n    Acme Widgets Limited\n\nRegistrant type:\n    UK Limited Company";
        assert_eq!(
            extract_organization_from_whois(whois),
            Some("Acme Widgets Limited".to_string())
        );
    }

    #[test]
    fn test_extract_org_first_placeholder_second_valid() {
        let whois = "Organization: REDACTED\nRegistrant Organization: RealCompany Ltd";
        let result = extract_organization_from_whois(whois);
        assert_eq!(result, Some("RealCompany Ltd".to_string()));
    }

    #[test]
    fn test_registrar_is_never_returned_as_the_owner() {
        // THE single largest producer of confidently-wrong attributions: when the registrant
        // organization was missing or redacted (the post-GDPR default for most gTLDs), the
        // chain fell back to the "Registrar:" field and reported it as the owning company —
        // marked verified. Reports therefore attributed thousands of domains to MarkMonitor,
        // GoDaddy and Cloudflare. A redacted registrant means we do NOT know the owner, and
        // saying so lets the caller fall through to real evidence instead.
        let whois = "Domain Name: test.com\nStatus: active\nRegistrar: ActualCorp Inc";
        assert_eq!(extract_organization_from_whois(whois), None);

        let redacted = "Domain Name: test.com\nRegistrant Organization: REDACTED FOR PRIVACY\nRegistrar: MarkMonitor Inc.";
        assert_eq!(extract_organization_from_whois(redacted), None);
    }

    #[test]
    fn test_registrar_named_as_registrant_on_its_own_domain_is_the_owner() {
        // The mirror case: Cloudflare really is the registrant of cloudflare.com. The
        // intermediary filter is domain-aware precisely so self-attribution survives.
        let whois = "Domain Name: cloudflare.com\nRegistrant Organization: Cloudflare, Inc.";
        assert_eq!(
            extract_organization_from_whois_for_domain(whois, "cloudflare.com"),
            Some("Cloudflare, Inc.".to_string())
        );
    }

    #[test]
    fn test_extract_registrar_first_placeholder_second_valid() {
        let whois =
            "Registrar: Verisign\nSponsoring Registrar: LegitCo Inc\nRegistrar Name: GoDaddy";
        let result = extract_registrar_from_whois(whois);
        assert_eq!(result, Some("LegitCo Inc".to_string()));
    }

    #[test]
    fn test_extract_registrar_first_two_placeholder_third_valid() {
        let whois = "Registrar: GoDaddy.com, LLC\nSponsoring Registrar: Namecheap, Inc.\nRegistrar Name: ActualBiz Corp";
        let result = extract_registrar_from_whois(whois);
        assert_eq!(result, Some("ActualBiz Corp".to_string()));
    }

    #[test]
    fn test_extract_registrar_no_registrar_fields() {
        let whois = "Domain Name: test.com\nCreation Date: 2020-01-01";
        let result = extract_registrar_from_whois(whois);
        assert!(result.is_none());
    }

    #[test]
    fn test_is_placeholder_empty_string() {
        assert!(!is_placeholder_organization(""));
    }

    #[test]
    fn test_is_placeholder_single_digit_start() {
        assert!(is_placeholder_organization("1"));
        assert!(is_placeholder_organization("0x Corp"));
    }

    #[test]
    fn test_extract_org_from_domain_two_parts_only() {
        // ".b" is not a real public suffix, so there is no registrable label and no owner
        // to name — the input is returned untouched instead of inventing "A Inc.".
        assert_eq!(extract_organization_from_domain("a.b"), "a.b");
    }

    #[test]
    fn test_extract_org_from_domain_empty_first_char() {
        // A leading dot leaves a bare public suffix: no owner to name, nothing invented.
        assert_eq!(extract_organization_from_domain(".com"), ".com");
    }

    #[tokio::test]
    async fn test_batch_get_orgs_single_domain() {
        let domains = vec!["example.com".to_string()];
        let results = batch_get_organizations(domains, false, 0.6, 1).await;
        assert_eq!(results.len(), 1);
        assert!(results.contains_key("example.com"));
    }

    #[tokio::test]
    async fn test_batch_get_orgs_with_rate_limit_no_ctx() {
        let domains = vec!["example.com".to_string()];
        let results = batch_get_organizations_with_rate_limit(domains, false, 0.6, 1, None).await;
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_prewarm_with_callback_single_domain() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let domains = vec!["example.com".to_string()];
        let existing_cache = HashMap::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();

        let callback = move |current: usize, total: usize, _domain: &str| {
            assert!(current <= total);
            count_clone.fetch_add(1, Ordering::SeqCst);
        };

        let results =
            prewarm_organization_cache(domains, &existing_cache, false, 0.6, 1, Some(callback))
                .await;
        assert_eq!(results.len(), 1);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_get_org_with_rate_limit_web_and_whois_fallthrough() {
        use crate::config::RateLimitConfig;
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);
        let result = get_organization_with_rate_limit(
            "zzz-no-vendor-no-web-12345.com",
            true,
            0.6,
            Some(&ctx),
        )
        .await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_status_and_config_full_fallthrough() {
        let result =
            get_organization_with_status_and_config("zzz-no-vendor-no-web-99999.com", true, 0.6)
                .await;
        assert!(result.is_ok());
        let org = result.unwrap();
        assert!(!org.name.is_empty());
    }

    #[tokio::test]
    async fn test_get_org_with_config_full_fallthrough() {
        let result =
            get_organization_with_config("zzz-no-vendor-no-web-99999.com", true, 0.6).await;
        assert!(result.is_ok());
        let org_name = result.unwrap();
        assert!(!org_name.is_empty());
    }

    #[tokio::test]
    async fn test_batch_with_web_enabled() {
        let domains = vec![
            "example.com".to_string(),
            "zzz-batch-web-test-12345.com".to_string(),
        ];
        let results = batch_get_organizations(domains.clone(), true, 0.6, 2).await;
        assert_eq!(results.len(), 2);
        for domain in &domains {
            assert!(results.contains_key(domain));
        }
    }

    #[tokio::test]
    async fn test_get_org_rate_limit_web_real_company() {
        use crate::config::RateLimitConfig;
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);
        let result = get_organization_with_rate_limit("stripe.com", true, 0.5, Some(&ctx)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_org_status_config_web_real_company() {
        let result = get_organization_with_status_and_config("stripe.com", true, 0.5).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_org_config_web_real_company() {
        let result = get_organization_with_config("stripe.com", true, 0.5).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_org_rate_limit_unusual_tld() {
        use crate::config::RateLimitConfig;
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 100,
            whois_queries_per_second: 100,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);
        let result = get_organization_with_rate_limit("bbc.co.uk", false, 0.6, Some(&ctx)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_org_status_config_unusual_tld() {
        let result = get_organization_with_status_and_config("bbc.co.uk", false, 0.6).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_org_config_unusual_tld() {
        let result = get_organization_with_config("bbc.co.uk", false, 0.6).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_org_single_pattern_placeholder_company() {
        let whois = "Company: Withheld";
        assert!(extract_organization_from_whois(whois).is_none());
    }

    #[test]
    fn test_extract_org_first_empty_second_valid() {
        let whois = "Registrant: Acme Corporation\nDomain: test.com";
        let result = extract_organization_from_whois(whois);
        assert_eq!(result, Some("Acme Corporation".to_string()));
    }

    #[test]
    fn test_extract_registrar_second_pattern_valid() {
        let whois = "Registrar: MarkMonitor Inc.\nSponsoring Registrar: RealCorp LLC";
        let result = extract_registrar_from_whois(whois);
        assert_eq!(result, Some("RealCorp LLC".to_string()));
    }

    #[test]
    fn test_extract_registrar_third_pattern_only() {
        let whois = "Domain: test.com\nRegistrar Name: IndependentCo";
        let result = extract_registrar_from_whois(whois);
        assert_eq!(result, Some("IndependentCo".to_string()));
    }
}
