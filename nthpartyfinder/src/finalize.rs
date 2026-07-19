//! Report finalization — the last gate every relationship crosses before export.
//!
//! Attribution happens per-lookup, deep inside the discovery paths, and each path resolves a
//! domain independently. That is fine for throughput and fatal for coherence: a real depth-3 scan
//! shipped `mcsv.net` as "Intuit" on two edges and "Mailchimp" on twenty-four, `siteforce.com` as
//! "Salesforce" on two and "Siteforce" on ten, and `cursor.sh` as "Government of St. Helena" on
//! one edge and "Cursor" on another. The same company had two names in one report, and one of
//! those names was a national registry.
//!
//! The lesson from that last example is the important one. `cursor.sh` proves an emit path exists
//! that never consulted [`crate::org_role`] — the gate is called at the WHOIS resolver's two call
//! sites, so any source that reaches the vendor map another way (a warm cache entry written before
//! the gate existed, a path added later) bypasses it silently, with no test failing. A gate that
//! must be remembered at each new call site is a convention, and conventions rot.
//!
//! So these passes run once, over the assembled report, where every relationship from every source
//! is finally in one place:
//!
//! 1. [`reject_non_registrable`] — a truncated internal hostname is not a vendor.
//! 2. [`gate_intermediary_orgs`] — no registrar, registry, privacy proxy or state authority
//!    survives as an owner, whichever source produced it.
//! 3. [`reconcile_org_per_domain`] — one domain, one organization, everywhere in the report.
//!
//! Each is a pure function over the assembled results, so each is directly testable and the
//! ordering is explicit rather than emergent.

use crate::vendor::VendorRelationship;
use crate::{org_normalizer, org_role, whois};
use std::collections::{BTreeMap, HashMap};

/// What finalization changed, so the run can report it rather than silently rewriting the report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FinalizeStats {
    /// Relationships dropped because the "domain" was not a registrable host.
    pub non_registrable_dropped: usize,
    /// Organization names replaced because they named an intermediary, not an owner.
    pub intermediary_orgs_gated: usize,
    /// Domains that carried more than one organization name and were reconciled to one.
    pub domains_reconciled: usize,
}

/// A hostname that could never be a third-party vendor.
///
/// Two shapes, both seen in a real scan:
///
/// **Truncated internal hostnames.** `telemetry.eu-central-1` and `event-track.us-west-2` are AWS
/// internal names cut short by a base-domain extractor; `cluster.local` is Kubernetes. None is a
/// registrable domain, and each was title-cased into a fake company ("Telemetry.Eu-Central-1").
///
/// **The test is whether the Public Suffix List has ever heard of the suffix — not whether the
/// suffix is ICANN.** This distinction is the whole point and it is easy to get backwards. The PSL
/// has two sections, and the private one lists platform tenancy boundaries: `github.io`,
/// `s3.amazonaws.com`, `vercel.app`, `pages.dev`, `web.app`. Those are real vendors. Rejecting
/// every domain whose suffix is not ICANN-listed would delete all of them from the report. What
/// separates a pseudo-host is that its suffix is in NEITHER section — the PSL falls back to its
/// implicit `*` rule and reports `eu-central-1` as a "suffix" purely because it has no entry for
/// it. An unlisted suffix (`typ() == None`) is the signature; a listed one, of either kind, is a
/// real public name.
///
/// **Non-hostnames.** `org/web/20250601085143/https://cursor.com/` reached the report as a vendor
/// domain — a URL fragment from an archive link. A hostname has no slashes, colons, spaces or
/// query marks.
///
/// Note the residual risk, because it is real and not silent: a gTLD delegated after the `psl`
/// crate's bundled snapshot would read as unlisted, and a vendor under it would be dropped. The
/// count is reported, never swallowed, and the crate's snapshot travels with its releases.
pub fn is_non_registrable_host(host: &str) -> bool {
    let host = host.trim();
    if host.is_empty() {
        return true;
    }
    // A hostname, not a URL, not a path fragment.
    if host
        .chars()
        .any(|c| matches!(c, '/' | ':' | '?' | '#' | ' ' | '\t' | '@'))
    {
        return true;
    }
    // A bare label with no dot at all is not a public domain.
    if !host.contains('.') {
        return true;
    }
    let lower = host.trim_end_matches('.').to_lowercase();
    match psl::suffix(lower.as_bytes()) {
        // Listed in EITHER section — a real public name (`stripe.com`, `github.io`).
        Some(suffix) => suffix.typ().is_none(),
        None => true,
    }
}

/// Drop relationships whose vendor domain is not a registrable host.
pub fn reject_non_registrable(
    results: Vec<VendorRelationship>,
) -> (Vec<VendorRelationship>, usize) {
    let before = results.len();
    // Symmetric across positions. A row whose CUSTOMER is a pseudo-host ("cluster.local uses
    // vendor X") is exactly as meaningless as one whose vendor is, and leaving it in gave the
    // pseudo-host a name and a vote in the passes below. The root customer domain is the
    // user's own scan target and is never filtered.
    let kept: Vec<VendorRelationship> = results
        .into_iter()
        .filter(|r| {
            let customer_ok = r.nth_party_customer_domain.is_empty()
                || !is_non_registrable_host(&r.nth_party_customer_domain);
            !is_non_registrable_host(&r.nth_party_domain) && customer_ok
        })
        .collect();
    let dropped = before - kept.len();
    (kept, dropped)
}

/// The honest name for a domain when nothing has legitimately named its owner.
fn honest_label(domain: &str) -> String {
    org_normalizer::normalize(&whois::domain_derived_organization(domain).name)
}

/// Whether this name is a curated tier's positive assertion that this company owns this domain.
///
/// **The intermediary filter must never be applied to one.** That filter exists for WHOIS, where a
/// registrar or privacy proxy LEAKS into the registrant field of a domain it does not own. A
/// curated row makes the opposite claim — this company DOES own this domain — and registrars
/// really do own domains. Cloudflare owns `cloudflareinsights.com`, `cloudflarestream.com` and
/// `videodelivery.net`; GoDaddy owns `trafficfacts.com`; Neustar owns `agkn.com`. Each is a row in
/// this crate's own dataset, and each names a company on the registrar denylist under a domain it
/// is not eponymous with — so the self-attribution rescue cannot save them either. Filtering them
/// yields "Cloudflareinsights", "Cloudflarestream", "Videodelivery", "Trafficfacts", "Agkn": five
/// fake organizations in place of three real ones, which is precisely the incoherence this module
/// exists to remove.
///
/// `whois.rs` already learned this and says so at its dataset tier: *"No intermediary filter here,
/// deliberately... registrars really do own domains (`trafficfacts.com` is GoDaddy's). Filtering
/// the dataset through it threw away correct answers."* This function is how that hard-won rule
/// survives the introduction of a second gate.
fn is_curated_assertion(org: &str, domain: &str) -> bool {
    whois::resolve_curated(domain)
        .map(|curated| org_normalizer::normalize(&curated.name) == org_normalizer::normalize(org))
        .unwrap_or(false)
}

/// Replace every organization name that names an intermediary rather than an owner.
///
/// This is the invariant the per-source gate could only promise. Whatever produced the name —
/// WHOIS, a scraped page, a certificate, a cache entry written months ago by a build that had no
/// gate at all — it does not reach the report if it names a registrar, a registry operator, a
/// privacy proxy, an address, or a state authority standing in for a ccTLD.
pub fn gate_intermediary_orgs(
    mut results: Vec<VendorRelationship>,
) -> (Vec<VendorRelationship>, usize) {
    let mut gated = 0usize;
    // One domain is resolved many times across a report; memoize the honest label per domain.
    let mut labels: HashMap<String, String> = HashMap::new();

    for r in &mut results {
        for (domain, org) in [
            (r.nth_party_domain.clone(), &mut r.nth_party_organization),
            (
                r.nth_party_customer_domain.clone(),
                &mut r.nth_party_customer_organization,
            ),
            (
                r.root_customer_domain.clone(),
                &mut r.root_customer_organization,
            ),
        ] {
            if domain.is_empty() || org.is_empty() {
                continue;
            }
            // A curated tier already asserted this ownership. The leak filter has no business
            // second-guessing a positive claim — see `is_curated_assertion`.
            if is_curated_assertion(org, &domain) {
                continue;
            }
            if org_role::classify_for_domain(org, &domain).is_intermediary() {
                let honest = labels
                    .entry(domain.clone())
                    .or_insert_with(|| honest_label(&domain))
                    .clone();
                if *org != honest {
                    *org = honest;
                    gated += 1;
                }
            }
        }
    }
    (results, gated)
}

/// Choose the one organization name a domain will carry throughout the report.
///
/// Precedence, strongest first:
///
/// 1. **An offline curated source.** [`whois::resolve_curated`] is the tool's own authority — the
///    user's overrides, the vendor registry, the embedded dataset, the brand-TLD rule — and it is
///    deterministic and network-free. If it names the domain, that name is the answer and the
///    disagreement between edges is simply which tier each edge happened to reach.
/// 2. **The most-supported real name among the edges.** A name that is not merely the domain label
///    echoed back carries information; the one carried by the most relationships wins. Ties break
///    on the more specific (longer) name, then lexically, so the result never depends on hash
///    iteration order.
/// 3. **The honest domain-derived label**, when no edge ever named the owner.
fn canonical_org(domain: &str, votes: &BTreeMap<String, usize>) -> String {
    // The curated tier is a positive ownership assertion and outranks everything. It is NOT
    // re-filtered through the intermediary heuristic: doing so discarded Cloudflare on every
    // Cloudflare-owned domain that is not literally cloudflare.com, and left the vote tally to
    // pick from names the gate had already degraded. See `is_curated_assertion`.
    if let Some(curated) = whois::resolve_curated(domain) {
        return org_normalizer::normalize(&curated.name);
    }

    let honest = honest_label(domain);
    let mut real: Vec<(&String, usize)> = votes
        .iter()
        .filter(|(name, _)| {
            // The honest label is what the tool says when it does not know; it is never a vote
            // FOR a name. But a name only outranks it if it is plausibly a company at all —
            // otherwise a single scraped tagline on one edge beats fifty honest labels.
            !name.is_empty()
                && **name != honest
                && org_normalizer::is_plausible_org_name(name)
                && !org_role::classify_for_domain(name, domain).is_intermediary()
        })
        .map(|(name, count)| (name, *count))
        .collect();

    if real.is_empty() {
        return honest;
    }
    // Most-supported, then most-specific, then lexical — total and deterministic.
    real.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| b.0.len().cmp(&a.0.len()))
            .then_with(|| a.0.cmp(b.0))
    });
    real[0].0.clone()
}

/// Give every domain a single organization name across the whole report.
///
/// Returns the number of domains that had disagreed and were reconciled.
pub fn reconcile_org_per_domain(
    mut results: Vec<VendorRelationship>,
) -> (Vec<VendorRelationship>, usize) {
    // Tally every (domain, organization) pair the report asserts, in any position. A domain's
    // name should not depend on whether it happened to appear as a vendor or as a customer.
    let mut votes: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for r in &results {
        for (domain, org) in [
            (&r.nth_party_domain, &r.nth_party_organization),
            (
                &r.nth_party_customer_domain,
                &r.nth_party_customer_organization,
            ),
            (&r.root_customer_domain, &r.root_customer_organization),
        ] {
            if domain.is_empty() || org.is_empty() {
                continue;
            }
            *votes
                .entry(domain.clone())
                .or_default()
                .entry(org.clone())
                .or_insert(0) += 1;
        }
    }

    let canonical: HashMap<String, String> = votes
        .iter()
        .map(|(domain, names)| (domain.clone(), canonical_org(domain, names)))
        .collect();

    // Count the domains whose name this pass actually CHANGES — not merely the ones that
    // disagreed with themselves. A report can be unanimously wrong: every edge naming a domain
    // identically, all of them superseded by the curated tier. Reporting "0 reconciled" while
    // rewriting forty rows would be a lie of exactly the kind this module exists to prevent.
    let mut rewritten: std::collections::HashSet<String> = std::collections::HashSet::new();

    for r in &mut results {
        for (domain, org) in [
            (r.nth_party_domain.clone(), &mut r.nth_party_organization),
            (
                r.nth_party_customer_domain.clone(),
                &mut r.nth_party_customer_organization,
            ),
            (
                r.root_customer_domain.clone(),
                &mut r.root_customer_organization,
            ),
        ] {
            if let Some(name) = canonical.get(&domain) {
                if org != name {
                    *org = name.clone();
                    rewritten.insert(domain);
                }
            }
        }
    }

    (results, rewritten.len())
}

/// Run every finalization pass, in the only order that makes sense.
///
/// Rejection first: a pseudo-host should not get a vote on anything. Gating second: an
/// intermediary name must not be a candidate when the report picks a domain's canonical name.
/// Reconciliation last, on names that have already been cleaned.
pub fn finalize_report(
    results: Vec<VendorRelationship>,
) -> (Vec<VendorRelationship>, FinalizeStats) {
    let (results, non_registrable_dropped) = reject_non_registrable(results);
    let (results, intermediary_orgs_gated) = gate_intermediary_orgs(results);
    let (results, domains_reconciled) = reconcile_org_per_domain(results);
    (
        results,
        FinalizeStats {
            non_registrable_dropped,
            intermediary_orgs_gated,
            domains_reconciled,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::RecordType;

    fn rel(vendor_domain: &str, vendor_org: &str, customer_domain: &str) -> VendorRelationship {
        VendorRelationship::new(
            vendor_domain.to_string(),
            vendor_org.to_string(),
            2,
            customer_domain.to_string(),
            "Vanta".to_string(),
            "CNAME".to_string(),
            RecordType::DnsSubdomain,
            "vanta.com".to_string(),
            "Vanta".to_string(),
            "evidence".to_string(),
        )
    }

    // --- is_non_registrable_host: the recall side is the one that must not break ---

    #[test]
    fn platform_tenancy_domains_are_registrable() {
        // The PSL's PRIVATE section lists these. They are real vendors, and an ICANN-only test
        // would delete every one of them from the report.
        for host in [
            "github.io",
            "myapp.github.io",
            "s3.amazonaws.com",
            "vercel.app",
            "pages.dev",
            "web.app",
        ] {
            assert!(
                !is_non_registrable_host(host),
                "{host} is a real domain and must survive"
            );
        }
    }

    #[test]
    fn ordinary_domains_are_registrable() {
        for host in [
            "stripe.com",
            "monzo.co.uk",
            "sentry.io",
            "blog.google",
            "calculator.aws",
            "cursor.sh",
            "dev.to",
            "lu.ma",
        ] {
            assert!(!is_non_registrable_host(host), "{host} must survive");
        }
    }

    #[test]
    fn truncated_internal_hostnames_are_not_vendors() {
        // Each shipped as a fake company on a real depth-3 scan.
        for host in [
            "telemetry.eu-central-1",
            "event-track.us-west-2",
            "event-track.eu-central-1",
            "cluster.local",
            "typeform-scripts.local",
        ] {
            assert!(is_non_registrable_host(host), "{host} is not a domain");
        }
    }

    #[test]
    fn url_fragments_and_malformed_hosts_are_not_vendors() {
        // A real scan emitted this archive-link fragment as a vendor domain.
        assert!(is_non_registrable_host(
            "org/web/20250601085143/https://cursor.com/"
        ));
        assert!(is_non_registrable_host("host with space.com"));
        assert!(is_non_registrable_host("example.com:8080"));
        assert!(is_non_registrable_host("localhost"));
        assert!(is_non_registrable_host(""));
    }

    #[test]
    fn scan_emitted_non_domains_are_blocked_at_input() {
        // The exact non-domain shapes a real depth-3 scan fed into network lookups. The same
        // predicate now guards the discovery→recursion INPUT boundary (analysis::process_vendor_domain),
        // so these never reach WHOIS/DNS/CT/subfinder or recurse — not merely dropped at output.
        for host in [
            "anysphere, inc.",                            // an org name (comma + space)
            "hostmaster@slack.com",                       // a registrant email ('@')
            "org/web/20250601085143/https://cursor.com/", // a wayback-wrapped URL
        ] {
            assert!(
                is_non_registrable_host(host),
                "{host} is a non-domain and must be blocked at input"
            );
        }
    }

    #[test]
    fn reject_non_registrable_drops_only_the_garbage() {
        let results = vec![
            rel("stripe.com", "Stripe", "vanta.com"),
            rel(
                "telemetry.eu-central-1",
                "Telemetry.Eu-Central-1",
                "vanta.com",
            ),
            rel("github.io", "GitHub", "vanta.com"),
            rel("cluster.local", "Cluster.Local", "vanta.com"),
        ];
        let (kept, dropped) = reject_non_registrable(results);
        assert_eq!(dropped, 2);
        let domains: Vec<&str> = kept.iter().map(|r| r.nth_party_domain.as_str()).collect();
        assert_eq!(domains, vec!["stripe.com", "github.io"]);
    }

    // --- gate_intermediary_orgs: the invariant a per-call-site gate cannot promise ---

    #[test]
    fn an_intermediary_name_never_survives_whatever_source_produced_it() {
        // cursor.sh really shipped with this name, which proves some emit path skipped the gate.
        let results = vec![
            rel("cursor.sh", "Government of St. Helena", "vanta.com"),
            rel("merge.dev", "Charleston Road Registry", "vanta.com"),
            rel(
                "terminal.com",
                "Jewella Privacy LLC Privacy ID# 14492117",
                "vanta.com",
            ),
        ];
        let (gated, count) = gate_intermediary_orgs(results);
        assert_eq!(
            count, 3,
            "every intermediary name should have been replaced"
        );
        for r in &gated {
            assert!(
                !org_role::classify_for_domain(&r.nth_party_organization, &r.nth_party_domain)
                    .is_intermediary(),
                "{} still names an intermediary: {}",
                r.nth_party_domain,
                r.nth_party_organization
            );
        }
        // And the replacement is the honest label, not a fabrication.
        assert_eq!(gated[0].nth_party_organization, "Cursor");
    }

    #[test]
    fn a_real_owner_is_left_alone() {
        let results = vec![
            rel("stripe.com", "Stripe", "vanta.com"),
            rel("godaddy.com", "GoDaddy", "vanta.com"), // owns its own domain
        ];
        let (gated, count) = gate_intermediary_orgs(results);
        assert_eq!(count, 0);
        assert_eq!(gated[1].nth_party_organization, "GoDaddy");
    }

    // --- reconcile_org_per_domain: one domain, one name ---

    #[test]
    fn a_domain_carries_one_organization_across_the_whole_report() {
        // mcsv.net really shipped as "Intuit" twice and "Mailchimp" 24 times in one report.
        let mut results = vec![rel("mcsv.net", "Intuit", "vanta.com")];
        for _ in 0..24 {
            results.push(rel("mcsv.net", "Mailchimp", "example.com"));
        }
        let (reconciled, contested) = reconcile_org_per_domain(results);
        assert_eq!(contested, 1, "one domain disagreed with itself");
        let names: std::collections::HashSet<&str> = reconciled
            .iter()
            .map(|r| r.nth_party_organization.as_str())
            .collect();
        assert_eq!(names.len(), 1, "the report must settle on exactly one name");
    }

    #[test]
    fn a_real_name_beats_the_domain_echo() {
        // siteforce.com: "Salesforce" on 2 edges, the bare echo on 10. The echo is what the tool
        // says when it does not know; it must never outvote a name.
        let mut results = vec![
            rel("siteforce.com", "Salesforce", "vanta.com"),
            rel("siteforce.com", "Salesforce", "acme.com"),
        ];
        for _ in 0..10 {
            results.push(rel("siteforce.com", "Siteforce", "other.com"));
        }
        let (reconciled, _) = reconcile_org_per_domain(results);
        for r in &reconciled {
            assert_eq!(r.nth_party_organization, "Salesforce");
        }
    }

    #[test]
    fn a_curated_source_outranks_any_number_of_scraped_names() {
        // github.com is named by a curated tier. Even a landslide of scraped nonsense loses.
        let mut results = vec![];
        for _ in 0..50 {
            results.push(rel("github.com", "Some Scraped Tagline Ltd", "vanta.com"));
        }
        let (reconciled, _) = reconcile_org_per_domain(results);
        let curated = whois::resolve_curated("github.com").expect("github.com is curated");
        let expected = org_normalizer::normalize(&curated.name);
        for r in &reconciled {
            assert_eq!(r.nth_party_organization, expected);
        }
    }

    #[test]
    fn reconciliation_is_deterministic_under_a_perfect_tie() {
        // Two names, one vote each: the result must not depend on map iteration order.
        let build = || {
            vec![
                rel("tied-example-domain.com", "Alpha Corp", "vanta.com"),
                rel("tied-example-domain.com", "Beta Corporation", "acme.com"),
            ]
        };
        let (first, _) = reconcile_org_per_domain(build());
        for _ in 0..5 {
            let (again, _) = reconcile_org_per_domain(build());
            assert_eq!(
                first[0].nth_party_organization,
                again[0].nth_party_organization
            );
        }
    }

    #[test]
    fn an_unnamed_domain_keeps_its_honest_label() {
        let results = vec![rel(
            "some-unknown-vendor-xyz.com",
            "Some-Unknown-Vendor-Xyz",
            "vanta.com",
        )];
        let (reconciled, contested) = reconcile_org_per_domain(results);
        assert_eq!(contested, 0);
        assert_eq!(
            reconciled[0].nth_party_organization,
            "Some-Unknown-Vendor-Xyz"
        );
    }

    // --- the composed pipeline ---

    #[test]
    fn finalize_report_runs_every_pass_in_order() {
        let results = vec![
            rel(
                "telemetry.eu-central-1",
                "Telemetry.Eu-Central-1",
                "vanta.com",
            ),
            rel("cursor.sh", "Government of St. Helena", "vanta.com"),
            rel("cursor.sh", "Cursor", "acme.com"),
            rel("stripe.com", "Stripe", "vanta.com"),
        ];
        let (finalized, stats) = finalize_report(results);

        assert_eq!(stats.non_registrable_dropped, 1);
        assert_eq!(stats.intermediary_orgs_gated, 1);

        // The pseudo-host is gone.
        assert!(finalized
            .iter()
            .all(|r| r.nth_party_domain != "telemetry.eu-central-1"));
        // cursor.sh is one company everywhere, and it is not a government.
        let cursor: Vec<&str> = finalized
            .iter()
            .filter(|r| r.nth_party_domain == "cursor.sh")
            .map(|r| r.nth_party_organization.as_str())
            .collect();
        assert_eq!(cursor, vec!["Cursor", "Cursor"]);
    }

    #[test]
    fn finalize_is_idempotent() {
        // Running the report through finalization twice must change nothing the second time —
        // otherwise a resumed scan (which re-finalizes) would drift.
        let results = vec![
            rel("cursor.sh", "Government of St. Helena", "vanta.com"),
            rel("mcsv.net", "Intuit", "vanta.com"),
            rel("mcsv.net", "Mailchimp", "acme.com"),
            rel("stripe.com", "Stripe", "vanta.com"),
        ];
        let (once, _) = finalize_report(results);
        let snapshot: Vec<(String, String)> = once
            .iter()
            .map(|r| (r.nth_party_domain.clone(), r.nth_party_organization.clone()))
            .collect();

        let (twice, stats) = finalize_report(once);
        let after: Vec<(String, String)> = twice
            .iter()
            .map(|r| (r.nth_party_domain.clone(), r.nth_party_organization.clone()))
            .collect();

        assert_eq!(snapshot, after);
        assert_eq!(stats.non_registrable_dropped, 0);
        assert_eq!(stats.intermediary_orgs_gated, 0);
        assert_eq!(stats.domains_reconciled, 0);
    }

    // --- Regressions found by adversarial review. Each reproduced against the real code. ---

    #[test]
    fn a_registrar_keeps_the_domains_it_actually_owns() {
        // THE bug this module nearly shipped. Cloudflare is on the registrar denylist and really
        // does own cloudflareinsights.com — the dataset says so. The gate classified the curated
        // name as an intermediary and replaced it with "Cloudflareinsights", turning one company
        // into five. whois.rs:192 documents this exact mistake being made and reverted once
        // before; the filter is for names LEAKED from a registrant field, never for a curated
        // ownership assertion.
        let owned = [
            ("cloudflareinsights.com", "Cloudflare"),
            ("cloudflarestream.com", "Cloudflare"),
            ("videodelivery.net", "Cloudflare"),
            ("trafficfacts.com", "GoDaddy"),
            ("agkn.com", "Neustar"),
        ];
        let results: Vec<VendorRelationship> = owned
            .iter()
            .map(|(domain, _)| {
                let curated = whois::resolve_curated(domain)
                    .unwrap_or_else(|| panic!("{domain} is a curated row"));
                rel(
                    domain,
                    &org_normalizer::normalize(&curated.name),
                    "vanta.com",
                )
            })
            .collect();

        let (finalized, stats) = finalize_report(results);
        assert_eq!(
            stats.intermediary_orgs_gated, 0,
            "a curated row is not a leak"
        );
        for (r, (domain, company)) in finalized.iter().zip(owned.iter()) {
            assert!(
                r.nth_party_organization.contains(company),
                "{domain} lost its real owner: got {:?}, expected it to name {company}",
                r.nth_party_organization
            );
        }
    }

    #[test]
    fn a_company_named_like_a_state_still_owns_its_own_domain() {
        // "Ministry of Supply" is a clothing company; "Ministry of Testing" is a software
        // community. The state-authority shape ran before the self-attribution rescue and
        // disowned both, shipping the bare domain label instead.
        assert_eq!(
            org_role::classify_for_domain("Ministry of Supply", "ministryofsupply.com"),
            org_role::OrgRole::Valid
        );
        assert_eq!(
            org_role::classify_for_domain("Ministry of Testing", "ministryoftesting.com"),
            org_role::OrgRole::Valid
        );
        // And the registry answering for a domain it does NOT own is still caught.
        assert_eq!(
            org_role::classify_for_domain("Government of St. Helena", "cursor.sh"),
            org_role::OrgRole::RegistryOperator
        );
    }

    #[test]
    fn one_scraped_tagline_does_not_outvote_the_honest_label() {
        // The echo filter removes the honest label from the tally, so ANY non-echo name used to
        // win with a single vote — including a page tagline scraped once off one edge.
        let mut results = vec![rel(
            "some-unknown-vendor-xyz.com",
            "Connective Infrastructure for Production AI Workloads and More",
            "vanta.com",
        )];
        for _ in 0..20 {
            results.push(rel(
                "some-unknown-vendor-xyz.com",
                "Some-Unknown-Vendor-Xyz",
                "acme.com",
            ));
        }
        let (finalized, _) = reconcile_org_per_domain(results);
        for r in &finalized {
            assert_eq!(
                r.nth_party_organization, "Some-Unknown-Vendor-Xyz",
                "an implausible scraped sentence must not become the company name"
            );
        }
    }

    #[test]
    fn a_pseudo_host_in_the_customer_position_is_dropped_too() {
        let results = vec![
            rel("stripe.com", "Stripe", "vanta.com"),
            rel("stripe.com", "Stripe", "cluster.local"),
        ];
        let (kept, dropped) = reject_non_registrable(results);
        assert_eq!(dropped, 1);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].nth_party_customer_domain, "vanta.com");
    }

    #[test]
    fn a_unanimous_rewrite_is_counted_honestly() {
        // Every edge agreed, so nothing was "contested" — but the curated tier still supersedes
        // all of them. Reporting 0 while rewriting every row would be a silent rewrite.
        let domain = "cloudflareinsights.com";
        let results: Vec<VendorRelationship> = (0..10)
            .map(|_| rel(domain, "Something Else Entirely", "vanta.com"))
            .collect();
        let (finalized, reconciled) = reconcile_org_per_domain(results);
        assert_eq!(reconciled, 1, "a rewritten domain must be counted");
        assert!(finalized[0].nth_party_organization.contains("Cloudflare"));
    }

    #[test]
    fn finalize_never_drops_a_real_relationship() {
        // ISC-437: the anti-criterion. Only non-registrable garbage may be removed.
        let real = [
            "stripe.com",
            "github.io",
            "s3.amazonaws.com",
            "vercel.app",
            "monzo.co.uk",
            "blog.google",
            "sentry.io",
            "pages.dev",
        ];
        let results: Vec<VendorRelationship> = real
            .iter()
            .map(|d| rel(d, "Some Org", "vanta.com"))
            .collect();
        let (finalized, stats) = finalize_report(results);
        assert_eq!(stats.non_registrable_dropped, 0);
        assert_eq!(finalized.len(), real.len(), "no real vendor may be dropped");
    }
}
