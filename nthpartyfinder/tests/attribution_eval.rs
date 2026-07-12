//! Attribution eval — the hermetic regression harness for domain→organization accuracy.
//!
//! The tool's core promise is that a domain in the report names the organization that
//! actually owns it. Two things can break that promise, and they break it in opposite
//! directions:
//!
//! * **Wrong**: the report confidently names an organization that does not own the domain —
//!   a registrar, a privacy proxy, a CDN, a truncated brand, an invented legal entity.
//! * **Missing**: the report names nothing, and the user has to go and map the domain by hand.
//!   (The user's whole ask: "avoid users needing to customize domain↔organization attribution
//!   as much as possible.")
//!
//! This file guards both. It runs against the REAL chain functions — `whois::resolve_curated`
//! and `whois::domain_derived_organization` are the same functions production calls, not a
//! reimplementation — so the eval cannot quietly drift away from what ships.
//!
//! It is deliberately hermetic: no DNS, no WHOIS, no HTTP, no model. Every assertion here is
//! about the offline part of the chain (curated tiers + honest fallback), which is exactly the
//! part that must be right without the network's help. The network tiers are exercised by the
//! integration suite; the *coverage* number they produce is measured on real scans, not here.

use nthpartyfinder::whois::{domain_derived_organization, resolve_curated, OrganizationResult};

/// Resolve a domain the way production does when no network source answers: curated tiers
/// first, honest domain-derived label last — and then through `normalize`, because that is what
/// production inserts into the vendor map (`analysis.rs`). Stopping short of the normalizer left
/// the eval blind to the exact class of bug it was written to catch: reintroducing the historical
/// suffix-truncation ("Cisco" -> "Cis") left every ground-truth row green.
fn resolve_offline(domain: &str) -> OrganizationResult {
    let mut result = resolve_curated(domain).unwrap_or_else(|| domain_derived_organization(domain));
    result.name = nthpartyfinder::org_normalizer::normalize(&result.name);
    result
}

/// Comparison key: case- and punctuation-insensitive, so "Amazon.com, Inc." and "Amazon"
/// are not compared on their punctuation.
fn key(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// The registrable label of a domain ("stripe" for api.stripe.com).
fn label_of(domain: &str) -> String {
    nthpartyfinder::domain_utils::registrable_label(domain).unwrap_or_default()
}

// ---------------------------------------------------------------------------------------
// Ground truth — domains whose owner is a matter of public record.
//
// Every row here is resolvable OFFLINE (curated tier or honest label). Rows that would need a
// live WHOIS/page fetch to get right do not belong in a hermetic eval; they are measured on
// real scans instead.
// ---------------------------------------------------------------------------------------

/// What kind of domain this is. Reported per-category, because an aggregate score hides the
/// case that matters: a tool can look excellent overall while getting every long-tail domain
/// wrong, and the long tail is precisely where the user would otherwise be forced to write
/// their own mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    /// Ad/analytics domains whose name says nothing about their operator.
    Tracker,
    /// CDN, cloud and edge infrastructure.
    Infra,
    /// A SaaS vendor on its own domain.
    Saas,
    /// A domain nobody has curated — the honest-label path.
    LongTail,
    /// Non-`.com` registries, where a naive TLD list produces a vendor called "Co".
    CcTld,
}

/// A labelled domain. `aliases` are other renderings that are also *correct* — the grader must
/// not fail a run for saying "Meta Platforms, Inc." where the label says "Meta". Getting the
/// entity right is the thing being measured; the exact string is not.
struct Row {
    domain: &'static str,
    canonical: &'static str,
    aliases: &'static [&'static str],
    category: Category,
}

const fn row(
    domain: &'static str,
    canonical: &'static str,
    aliases: &'static [&'static str],
    category: Category,
) -> Row {
    Row {
        domain,
        canonical,
        aliases,
        category,
    }
}

use Category::{CcTld, Infra, LongTail, Saas, Tracker};

const GROUND_TRUTH: &[Row] = &[
    // Trackers: the operator's name is nowhere in the domain. Nothing but a curated mapping can
    // resolve these — they are the reason the embedded dataset earns its place in the chain.
    row("doubleclick.net", "Google", &[], Tracker),
    row("google-analytics.com", "Google", &[], Tracker),
    row("googletagmanager.com", "Google", &[], Tracker),
    row("googlesyndication.com", "Google", &[], Tracker),
    row(
        "facebook.net",
        "Meta Platforms, Inc.",
        &["Meta", "Facebook"],
        Tracker,
    ),
    row("hotjar.com", "Hotjar", &[], Tracker),
    row("segment.com", "Segment", &["Twilio"], Tracker),
    row("scorecardresearch.com", "Comscore", &[], Tracker),
    // Infra: the vendor is the platform operator, not the tenant using it.
    row(
        "cloudfront.net",
        "Amazon",
        &["Amazon.com, Inc.", "AWS"],
        Infra,
    ),
    row(
        "amazonaws.com",
        "Amazon",
        &["Amazon.com, Inc.", "AWS"],
        Infra,
    ),
    row("akamaiedge.net", "Akamai Technologies", &["Akamai"], Infra),
    row("fastly.net", "Fastly", &[], Infra),
    row("cloudflare.com", "Cloudflare", &[], Infra),
    // SaaS on its own domain. The correct spelling is not what naive title-casing produces
    // ("Openai", "Mongodb", "Github"), and for three of these the embedded dataset wants to answer
    // with a stale parent company instead (see `STALE_ROLLUP` in whois.rs).
    row("openai.com", "OpenAI", &[], Saas),
    row("mongodb.com", "MongoDB", &[], Saas),
    row("github.com", "GitHub", &[], Saas),
    row("hubspot.com", "HubSpot", &[], Saas),
    row("paypal.com", "PayPal", &[], Saas),
    row("linkedin.com", "LinkedIn", &[], Saas),
    row("newrelic.com", "New Relic", &[], Saas),
    row("stripe.com", "Stripe", &["Stripe, Inc."], Saas),
    row("datadoghq.com", "Datadog", &[], Saas),
    row("okta.com", "Okta", &[], Saas),
    // Long tail: no curated source knows these, so they exercise the honest-label path. Each
    // name here is one a suffix-stripper mangles if it matches inside a word rather than on a
    // word boundary: "Cisco" -> "Cis" (lost "co"), "Zinc" -> "Z" (lost "inc").
    row("cisco.com", "Cisco", &["Cisco Systems"], LongTail),
    row("geico.com", "Geico", &[], LongTail),
    row("capco.com", "Capco", &[], LongTail),
    row("zinc.com", "Zinc", &[], LongTail),
    row("maytag.com", "Maytag", &[], LongTail),
    row("sysco.com", "Sysco", &[], LongTail),
    row("vanta.com", "Vanta", &["Vanta Inc."], LongTail),
    // ccTLDs and multi-label suffixes. The old hand-maintained TLD list collapsed these to the
    // bare public suffix, which then became a vendor organization called "Co" or "Com".
    row("monzo.co.uk", "Monzo", &[], CcTld),
    row("bbc.co.uk", "BBC", &[], CcTld),
    row("beispiel.de", "Beispiel", &[], CcTld),
    row("example.com.au", "Example", &[], CcTld),
];

/// Does the produced name identify the same entity the label names?
///
/// Containment is allowed in both directions, so "Amazon" and "Amazon.com, Inc." are the same
/// answer — the legal-suffix rendering is not what this eval grades. But a SHORTER answer only
/// counts when it is still substantially the name: without that floor, "Cisc" contains-matches
/// "Cisco" and the truncation bugs this file exists to catch grade as correct.
fn names_match(got: &str, r: &Row) -> bool {
    let g = key(got);
    if g.is_empty() {
        return false;
    }

    let matches_one = |expected: &str| -> bool {
        let e = key(expected);
        if e.is_empty() {
            return false;
        }
        // The produced name contains the expected entity (e.g. "Cisco Systems" for "Cisco").
        if g.contains(&e) {
            return true;
        }
        // The produced name is a PREFIX-or-substring of the expected one: allowed only if it did
        // not lose a meaningful piece of it. "Amazon" of "Amazon.com, Inc." keeps 6 of 15 chars
        // but is the whole first word; "Cisc" of "Cisco" drops a character off a single word.
        if e.contains(&g) {
            let whole_word = e.split(|c: char| !c.is_alphanumeric()).next().unwrap_or("");
            return g == key(whole_word);
        }
        false
    };

    matches_one(r.canonical) || r.aliases.iter().any(|a| matches_one(a))
}

#[test]
fn ground_truth_domains_resolve_to_their_real_owner() {
    let mut wrong: Vec<String> = Vec::new();

    for r in GROUND_TRUTH {
        let got = resolve_offline(r.domain);
        if !names_match(&got.name, r) {
            wrong.push(format!(
                "[{:?}] {}: expected {:?}, got {:?} (source: {})",
                r.category, r.domain, r.canonical, got.name, got.source
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} ground-truth domains attributed to the wrong organization:\n  {}",
        wrong.len(),
        GROUND_TRUTH.len(),
        wrong.join("\n  ")
    );
}

#[test]
fn a_product_name_never_replaces_the_company_that_owns_it() {
    // The first version of the stale-rollup fix was a heuristic: "if the domain's label is a
    // brand we can spell, prefer the brand over the dataset". It fixed github.com and broke more
    // than it fixed — iCloud, SharePoint, WordPress and YouTube are PRODUCTS, and the dataset's
    // company answer was right. You cannot contract with iCloud; you contract with Apple.
    for (domain, company) in [
        ("icloud.com", "Apple"),
        ("sharepoint.com", "Microsoft"),
        ("wordpress.com", "Automattic"),
        ("youtube.com", "Google"),
    ] {
        let got = resolve_offline(domain);
        assert!(
            key(&got.name).contains(&key(company)),
            "{domain}: expected the owning company ({company}), got the product name {:?}",
            got.name
        );
    }
}

#[test]
fn a_registrar_still_owns_the_domains_it_actually_owns() {
    // The intermediary filter belongs on WHOIS, where a registrar LEAKS into the registrant
    // field of a domain it does not own. Applying it to the embedded dataset — which asserts
    // ownership — threw away correct answers, because registrars really do own domains.
    let got = resolve_offline("secureserver.net");
    assert!(
        !got.name.trim().is_empty(),
        "secureserver.net (GoDaddy's own infrastructure domain) lost its attribution entirely"
    );
}

#[test]
fn every_category_is_fully_attributed() {
    // The regression gate is the WORST category, not the average. A tool that resolves every
    // tracker and no long-tail domain has not solved the user's problem — it has moved it.
    for category in [Tracker, Infra, Saas, LongTail, CcTld] {
        let rows: Vec<&Row> = GROUND_TRUTH
            .iter()
            .filter(|r| r.category == category)
            .collect();
        let correct = rows
            .iter()
            .filter(|r| names_match(&resolve_offline(r.domain).name, r))
            .count();

        assert_eq!(
            correct,
            rows.len(),
            "category {category:?}: only {correct}/{} domains attributed correctly",
            rows.len()
        );
    }
}

// ---------------------------------------------------------------------------------------
// Property corpus — invariants that must hold for EVERY domain, known or unknown.
//
// A ground-truth table can only test the domains someone thought to label. The properties
// below are what protect the thousands of domains nobody labelled: whatever name the tool
// prints, it must not be a registrar, a truncation, or an invented company.
// ---------------------------------------------------------------------------------------

const PROPERTY_CORPUS: &[&str] = &[
    // Known to a curated tier.
    "doubleclick.net",
    "google-analytics.com",
    "cloudfront.net",
    "stripe.com",
    "github.com",
    "openai.com",
    "segment.com",
    // Not known to any curated tier — these fall to the honest label, which is where a
    // fabricated name used to be invented.
    "vanta.com",
    "capco.com",
    "zinc.com",
    "maytag.com",
    "some-startup-nobody-has-heard-of.com",
    "acme-widgets-ltd.co.uk",
    "xn--80ak6aa92e.com",
    // Registrar / privacy-proxy / registry-operator domains. Each is a legitimate vendor ON
    // ITS OWN domain, and must never be named as the owner of anyone else's.
    "godaddy.com",
    "markmonitor.com",
    "namecheap.com",
    "cloudflare.com",
    // Platform tenancy boundaries: the PSL's PRIVATE section calls each of these a public
    // suffix. Treating them as such would make every tenant its own vendor.
    "s3.amazonaws.com",
    "my-bucket.s3.amazonaws.com",
    "d25ka488dfqyj6.cloudfront.net",
    "nagios-842216103.us-east-1.elb.amazonaws.com",
    "someone.github.io",
    // Deep/technical FQDNs.
    "api.stripe.com",
    "eu.mailgun.org",
    "_spf.google.com",
    "mail.protection.outlook.com",
];

/// Legal suffixes the tool must never append to a name it does not have evidence for.
const FABRICATED_SUFFIXES: &[&str] = &[" inc", " inc.", " llc", " ltd", " ltd.", " corp", " corp."];

/// Corporate-suffix fragments. A name that is its own domain label with one of these bitten
/// off the end is a truncation bug ("cisco" -> "Cis"), not an abbreviation.
const SUFFIX_FRAGMENTS: &[&str] = &[
    "co", "inc", "llc", "ltd", "corp", "sa", "ag", "bv", "nv", "plc", "lp",
];

#[test]
fn no_domain_is_attributed_to_a_fabricated_legal_entity() {
    // The domain fallback used to emit `format!("{label} Inc.")` — a company that does not
    // exist, printed with the same confidence as a real one. An honest "Stripe" is a label;
    // a dishonest "Stripe Inc." is a claim about a legal entity we never verified.
    //
    // Scoped to INFERRED results on purpose: a curated source that says "Vanta Inc." is
    // reporting an attested legal name, which is exactly what we want it to do. The bug is
    // the tool *inventing* the suffix when no source supplied one.
    for domain in PROPERTY_CORPUS {
        let got = resolve_offline(domain);
        if got.is_verified {
            continue;
        }
        let lower = got.name.to_lowercase();

        for suffix in FABRICATED_SUFFIXES {
            if let Some(stem) = lower.strip_suffix(suffix) {
                assert!(
                    key(stem) != key(&label_of(domain)),
                    "{domain}: '{}' invents a legal entity — it is the domain label with '{}' \
                     appended, which no source attested",
                    got.name,
                    suffix.trim()
                );
            }
        }
    }
}

#[test]
fn no_domain_is_attributed_to_an_intermediary() {
    // Registrars, privacy proxies, registry operators and hosting providers appear in WHOIS for
    // domains they do not own. Naming them as the owner is the most confidently wrong answer the
    // tool can give: "who owns evil-phish.com?" -> "GoDaddy".
    //
    // The oracle is this INDEPENDENT literal list, not `org_role::is_intermediary_for_domain`.
    // Asking the classifier whether its own output is an intermediary is a tautology: mutate the
    // classifier to return Valid for everything and a test written that way still passes, while
    // production ships GoDaddy as the owner of every domain it registered.
    const NEVER_AN_OWNER: &[&str] = &[
        "godaddy",
        "markmonitor",
        "namecheap",
        "namesilo",
        "domains by proxy",
        "domain protection services",
        "dnstination",
        "redacted for privacy",
        "withheld for privacy",
        "whoisguard",
        "privacyguardian",
        "verisign",
        "nominet",
        "rotld",
    ];

    for domain in PROPERTY_CORPUS {
        let got = resolve_offline(domain);
        let name = got.name.to_lowercase();
        let label = label_of(domain);

        for bad in NEVER_AN_OWNER {
            // ...unless it IS that provider's own domain, where it is the rightful owner.
            if key(bad).contains(&key(&label)) && !label.is_empty() {
                continue;
            }
            assert!(
                !name.contains(bad),
                "{domain}: attributed to intermediary '{}' (source: {})",
                got.name,
                got.source
            );
        }
    }
}

#[test]
fn no_name_is_a_truncation_of_its_own_domain_label() {
    for domain in PROPERTY_CORPUS {
        let got = resolve_offline(domain);
        let (name, label) = (key(&got.name), key(&label_of(domain)));

        if name.is_empty() || label.is_empty() || !label.starts_with(&name) || name == label {
            continue;
        }
        let remainder = &label[name.len()..];
        assert!(
            !SUFFIX_FRAGMENTS.contains(&remainder),
            "{domain}: '{}' is the domain label with the corporate-suffix fragment '{remainder}' \
             stripped out of the middle of a word",
            got.name
        );
    }
}

#[test]
fn no_domain_is_attributed_to_an_empty_organization() {
    // A blank name renders as a vendor row with no company — strictly worse than the honest
    // label, because the user cannot even tell what they are looking at.
    for domain in PROPERTY_CORPUS {
        let got = resolve_offline(domain);
        assert!(
            !got.name.trim().is_empty(),
            "{domain}: resolved to an empty organization (source: {})",
            got.source
        );
    }
}

#[test]
fn verified_is_reserved_for_curated_sources() {
    // `is_verified` is a claim to the user that a source we trust attested this name. Only the
    // curated tiers can make that claim; a domain-derived label is a guess and says so.
    for domain in PROPERTY_CORPUS {
        let curated = resolve_curated(domain);
        let fallback = domain_derived_organization(domain);

        assert!(
            !fallback.is_verified,
            "{domain}: domain-derived label '{}' claims to be verified",
            fallback.name
        );
        if let Some(result) = curated {
            assert!(
                result.is_verified,
                "{domain}: curated source '{}' produced an unverified result",
                result.source
            );
        }
    }
}

#[test]
fn tenant_fqdns_collapse_to_the_platform_operator() {
    // A bucket, a load balancer and a CloudFront distribution are not three vendors — they are
    // Amazon. Collapsing them is what keeps a scan's vendor list a list of ORGANIZATIONS rather
    // than a list of hostnames the user then has to map by hand.
    for (fqdn, expected) in [
        ("my-bucket.s3.amazonaws.com", "Amazon"),
        ("nagios-842216103.us-east-1.elb.amazonaws.com", "Amazon"),
        ("d25ka488dfqyj6.cloudfront.net", "Amazon"),
    ] {
        let got = resolve_offline(fqdn);
        assert_eq!(
            key(&got.name),
            key(expected),
            "{fqdn}: expected {expected}, got '{}'",
            got.name
        );
    }
}

#[test]
fn a_provider_is_still_the_owner_of_its_own_domain() {
    // The intermediary filter must not be so eager that GoDaddy stops being the owner of
    // godaddy.com. "Never name a registrar" means "never name it as someone ELSE's owner".
    for (domain, expected) in [
        ("godaddy.com", "godaddy"),
        ("markmonitor.com", "markmonitor"),
        ("cloudflare.com", "cloudflare"),
    ] {
        let got = resolve_offline(domain);
        assert!(
            key(&got.name).contains(expected),
            "{domain}: provider's own domain resolved to '{}', losing its identity",
            got.name
        );
    }
}
