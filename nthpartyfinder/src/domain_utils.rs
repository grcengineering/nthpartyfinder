#[cfg_attr(coverage_nightly, coverage(off))]
fn bug004_single_label_fallback(
    result: &str,
    cleaned_domain: &str,
    original_domain: &str,
) -> Option<String> {
    if result.split('.').count() < 2 {
        if cleaned_domain.split('.').count() >= 2 {
            Some(cleaned_domain.to_string())
        } else {
            Some(original_domain.to_lowercase())
        }
    } else {
        None
    }
}

/// Extract the base domain from SPF subdomains and other technical subdomains
pub fn extract_base_domain(domain: &str) -> String {
    // Remove common SPF and technical prefixes
    let spf_prefixes = vec![
        "_spf.",
        "spf.",
        "_dmarc.",
        "dmarc.",
        "_domainkey.",
        "selector1._domainkey.",
        "selector2._domainkey.",
        "_smtp.",
        "smtp.",
        "mail.",
        "email.",
    ];

    let mut cleaned_domain = domain.to_lowercase();

    // Remove SPF-specific prefixes
    for prefix in spf_prefixes {
        if cleaned_domain.starts_with(prefix) {
            cleaned_domain = cleaned_domain
                .strip_prefix(prefix)
                .unwrap_or(&cleaned_domain)
                .to_string();
            break;
        }
    }

    // Remove subdomain prefixes that are clearly technical (but keep meaningful subdomains)
    // Fall back to the cleaned input if org-domain extraction yields nothing,
    // rather than panicking on malformed/unusual domain input.
    let result =
        extract_organizational_domain(&cleaned_domain).unwrap_or_else(|| cleaned_domain.clone());

    if let Some(fallback) = bug004_single_label_fallback(&result, &cleaned_domain, domain) {
        return fallback;
    }

    // Reject results that are only a public suffix (e.g. "co.uk", "com.au"). The PSL knows
    // every one of these, so this no longer depends on a hand-maintained list.
    //
    // ICANN-only, for the same reason `icann_registrable_domain` is: the PSL's PRIVATE
    // section lists platform tenancy boundaries (`cloudfront.net`, `github.io`), so the
    // default private-inclusive answer calls `cloudfront.net` a bare public suffix. That
    // would reject the correct collapse and hand the full distribution FQDN back as the
    // vendor domain — one distribution per vendor row instead of one Amazon.
    if is_bare_icann_suffix(&result) {
        return cleaned_domain;
    }

    result
}

/// True when `candidate` is *itself* an ICANN public suffix ("com", "co.uk") — i.e. a
/// string with no registrable owner beneath it. Private-section suffixes are deliberately
/// not treated as bare suffixes; see `icann_registrable_domain`.
fn is_bare_icann_suffix(candidate: &str) -> bool {
    psl::suffix(candidate.as_bytes()).is_some_and(|suffix| {
        suffix.typ() == Some(psl::Type::Icann)
            && std::str::from_utf8(suffix.as_bytes()).is_ok_and(|s| s == candidate)
    })
}

/// Extract the organizational domain (e.g. mailgun.org from eu.mailgun.org).
///
/// Backed by the Public Suffix List (`psl` crate) rather than a hand-maintained list of
/// compound TLDs. The hardcoded list got the common cases right and every other case
/// wrong: `foo.com.sg`, `foo.gov.uk`, `foo.co.id` and hundreds more collapsed to the bare
/// public suffix, which then became a "vendor domain" and, downstream, a fabricated
/// organization name. The PSL is the registry-published answer to exactly this question.
///
/// FQDNs like `s3.amazonaws.com` normalize to `amazonaws.com` — the vendor is the platform
/// provider; the full FQDN is preserved in the record value / evidence fields.
fn extract_organizational_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return None;
    }

    if let Some(registrable) = icann_registrable_domain(domain) {
        return Some(registrable);
    }

    // An IP address has no registrable domain. It must come back WHOLE, because the
    // last-two-labels fallback below would otherwise chop "192.168.1.1" into a vendor domain
    // called "1.1" — and a caller can reject an IP, but it cannot recognise "1.1" as one.
    if is_ip_literal(domain) {
        return Some(domain.to_string());
    }

    // Unknown/invalid suffix (private TLDs, malformed input, single labels): fall back to
    // the last two labels, preserving the previous behaviour rather than dropping the
    // domain entirely.
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() <= 2 {
        return Some(domain.to_string());
    }
    Some(format!(
        "{}.{}",
        parts[parts.len() - 2],
        parts[parts.len() - 1]
    ))
}

/// Every label is numeric — an IPv4 address (or a fragment of one), not a hostname.
fn is_ip_literal(domain: &str) -> bool {
    !domain.is_empty()
        && domain
            .split('.')
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
}

/// The registrable domain under the PSL's **ICANN** section only.
///
/// The PSL has two sections and they answer different questions. The ICANN section lists
/// registry-operated suffixes (`com`, `co.uk`, `com.sg`); the PRIVATE section additionally
/// lists platform-operated tenancy boundaries (`s3.amazonaws.com`, `github.io`,
/// `elb.amazonaws.com`).
///
/// For *this* tool the vendor is the platform provider: an `…elb.amazonaws.com` load
/// balancer is Amazon's, and collapsing it to `amazonaws.com` is the whole point — the
/// tenant is the customer being scanned, not a new nth party. Using the PSL's default
/// (private-inclusive) answer would treat every S3 bucket and GitHub Pages site as its own
/// registrable vendor domain, which is precisely the tenant/operator confusion this tool
/// exists to untangle. So we deliberately ask the ICANN-only question here.
///
/// (The tenant *is* interesting — it just belongs in a tenant field, not in the vendor's
/// identity. That distinction is a follow-up; see the ISA.)
fn icann_registrable_domain(domain: &str) -> Option<String> {
    // The PSL is case-sensitive: `psl::suffix("STRIPE.COM")` carries no `typ()` at all, so an
    // uppercase FQDN (DNS is case-insensitive, and real records arrive mixed-case) would fall
    // out of every check below and be handed back raw as an organization name.
    let domain = domain.to_lowercase();

    // An IP address is not a domain and has no registrable owner. (`extract_organizational_domain`
    // returns the literal whole, so a caller can still recognise and reject it.)
    if is_ip_literal(&domain) {
        return None;
    }

    // A bare public suffix ("co.uk", "com.au") has no owner beneath it. Returning it as the
    // registrable domain makes `registrable_label` invent an organization called "Co".
    if is_bare_icann_suffix(&domain) {
        return None;
    }

    let labels: Vec<&str> = domain.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }

    // Walk left-to-right looking for the longest trailing run of labels that is itself an
    // ICANN public suffix; the registrable domain is that run plus the label before it.
    for i in 1..labels.len() {
        let candidate = labels[i..].join(".");
        let Some(suffix) = psl::suffix(candidate.as_bytes()) else {
            continue;
        };
        let Ok(suffix_str) = std::str::from_utf8(suffix.as_bytes()) else {
            continue;
        };
        if suffix.typ() == Some(psl::Type::Icann) && suffix_str == candidate {
            return Some(labels[i - 1..].join("."));
        }
    }

    None
}

/// The ICANN-listed public suffix of a domain ("com", "co.uk", "google"), or `None` when the
/// domain has no listed suffix at all.
///
/// The `None` case is the load-bearing one. The PSL has an implicit `*` rule, so
/// `psl::suffix_str("telemetry.eu-central-1")` happily answers `eu-central-1` — an unknown
/// single label is *treated as* a suffix even though nobody listed it. Only a suffix whose
/// `typ()` is `Icann` was actually listed, so that check is what separates a real TLD from a
/// truncated internal hostname.
pub fn icann_suffix(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    if is_ip_literal(&domain) {
        return None;
    }
    let suffix = psl::suffix(domain.as_bytes())?;
    if suffix.typ() != Some(psl::Type::Icann) {
        return None;
    }
    std::str::from_utf8(suffix.as_bytes())
        .ok()
        .map(str::to_string)
}

/// The registrable label of a domain — the eTLD+1's first label ("stripe" for
/// `api.stripe.com`, "monzo" for `monzo.co.uk`).
///
/// This is the only honest raw material for a domain-derived display name: it is the part
/// of the hostname the owner actually chose. Everything else in the hostname belongs to
/// the registry or is a technical prefix.
pub fn registrable_label(domain: &str) -> Option<String> {
    // A bare public suffix ("com", "co.uk") has no registrable label — there is no owner to
    // name. Returning None keeps callers from inventing "Com" as an organization.
    let trimmed = domain.trim().trim_end_matches('.');
    icann_registrable_domain(trimmed)?;
    let base = extract_base_domain(trimmed);
    let label = base.split('.').next()?.trim();
    if label.is_empty() {
        None
    } else {
        Some(label.to_string())
    }
}

/// Normalize domain for DNS lookups (remove _spf prefixes but keep domain structure)
pub fn normalize_for_dns_lookup(domain: &str) -> String {
    let mut normalized = domain.to_lowercase();

    // Remove underscore prefixes that are SPF-specific
    if normalized.starts_with("_spf.") {
        normalized = normalized
            .strip_prefix("_spf.")
            .unwrap_or(&normalized)
            .to_string();
    } else if normalized.starts_with("_dmarc.") {
        normalized = normalized
            .strip_prefix("_dmarc.")
            .unwrap_or(&normalized)
            .to_string();
    }

    normalized
}

/// Check if a domain is likely an organizational domain vs technical subdomain
pub fn is_organizational_domain(domain: &str) -> bool {
    let technical_subdomains = vec![
        "_spf",
        "spf",
        "_dmarc",
        "dmarc",
        "_domainkey",
        "selector1",
        "selector2",
        "mail",
        "smtp",
        "email",
    ];

    let parts: Vec<&str> = domain.split('.').collect();
    parts
        .first()
        .is_none_or(|first_part| !technical_subdomains.contains(first_part))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("_spf.mailgun.org"), "mailgun.org");
        assert_eq!(extract_base_domain("spf.eu.mailgun.org"), "mailgun.org");
        assert_eq!(extract_base_domain("_spf.eu.mailgun.org"), "mailgun.org");
        assert_eq!(extract_base_domain("google.com"), "google.com");
        assert_eq!(extract_base_domain("mail.google.com"), "google.com");
        assert_eq!(extract_base_domain("api.stripe.com"), "stripe.com");
    }

    #[test]
    fn ip_addresses_are_never_chopped_into_vendor_domains() {
        // The last-two-labels fallback turned an IP into a "domain": 192.168.1.1 -> "1.1".
        // That is how "122.172" and "2.105" ended up in a real scan's vendor list. An IP must
        // come back whole, so the caller can recognise it for what it is and reject it.
        assert_eq!(extract_base_domain("192.168.1.1"), "192.168.1.1");
        assert_eq!(extract_base_domain("8.8.8.8"), "8.8.8.8");
        assert_eq!(registrable_label("192.168.1.1"), None);
    }

    #[test]
    fn a_bare_public_suffix_has_no_registrable_label() {
        // Returning "co" for "co.uk" makes the fallback invent an organization called "Co".
        assert_eq!(registrable_label("co.uk"), None);
        assert_eq!(registrable_label("com.au"), None);
        assert_eq!(registrable_label("com"), None);
        assert_eq!(registrable_label("stripe.com").as_deref(), Some("stripe"));
    }

    #[test]
    fn uppercase_domains_resolve_the_same_as_lowercase() {
        // The PSL is case-sensitive, so an uppercase FQDN silently fell out of every check and
        // was handed back raw as an organization name. DNS records arrive mixed-case routinely.
        assert_eq!(extract_base_domain("STRIPE.COM"), "stripe.com");
        assert_eq!(
            registrable_label("API.Stripe.COM").as_deref(),
            Some("stripe")
        );
    }

    /// Regression test: FQDNs from subdomain discovery (e.g. CNAME targets)
    /// must normalize to the apex domain for the Vendor Domain field.
    /// The full FQDN is preserved in Record Value / Evidence.
    #[test]
    fn test_fqdn_normalizes_to_apex_domain() {
        // AWS ELB FQDN → amazonaws.com
        assert_eq!(
            extract_base_domain("Nagios-842216103.us-east-1.elb.amazonaws.com"),
            "amazonaws.com"
        );
        // S3 bucket FQDN → amazonaws.com
        assert_eq!(extract_base_domain("s3.amazonaws.com"), "amazonaws.com");
        // Deep AWS FQDN
        assert_eq!(
            extract_base_domain("my-app-1234.us-west-2.elb.amazonaws.com"),
            "amazonaws.com"
        );
        // CloudFront distribution → cloudfront.net
        assert_eq!(
            extract_base_domain("d25ka488dfqyj6.cloudfront.net"),
            "cloudfront.net"
        );
        // Azure Web Apps → azurewebsites.net
        assert_eq!(
            extract_base_domain("myapp.azurewebsites.net"),
            "azurewebsites.net"
        );
        // GitHub Pages → github.io
        assert_eq!(extract_base_domain("myproject.github.io"), "github.io");
        // Heroku → herokuapp.com
        assert_eq!(extract_base_domain("myapp.herokuapp.com"), "herokuapp.com");
        // Already apex → unchanged
        assert_eq!(extract_base_domain("amazonaws.com"), "amazonaws.com");
        assert_eq!(extract_base_domain("cloudfront.net"), "cloudfront.net");
    }

    /// Regression test: compound TLDs are handled correctly
    #[test]
    fn test_compound_tld_handling() {
        assert_eq!(extract_base_domain("mail.example.co.uk"), "example.co.uk");
        assert_eq!(extract_base_domain("api.company.com.au"), "company.com.au");
        // Already at apex with compound TLD
        assert_eq!(extract_base_domain("example.co.uk"), "example.co.uk");
    }

    #[test]
    fn test_new_regional_compound_tlds() {
        // India
        assert_eq!(extract_base_domain("app.tcs.co.in"), "tcs.co.in");
        assert_eq!(extract_base_domain("mail.infosys.org.in"), "infosys.org.in");
        // South Africa
        assert_eq!(extract_base_domain("api.company.co.za"), "company.co.za");
        // Israel
        assert_eq!(extract_base_domain("cdn.startup.co.il"), "startup.co.il");
        // Singapore
        assert_eq!(extract_base_domain("api.firm.com.sg"), "firm.com.sg");
        // Hong Kong
        assert_eq!(extract_base_domain("mail.corp.com.hk"), "corp.com.hk");
        // Indonesia
        assert_eq!(extract_base_domain("api.company.co.id"), "company.co.id");
        // Turkey
        assert_eq!(extract_base_domain("app.firma.com.tr"), "firma.com.tr");
        // Argentina
        assert_eq!(extract_base_domain("cdn.empresa.com.ar"), "empresa.com.ar");
        // Thailand
        assert_eq!(extract_base_domain("api.company.co.th"), "company.co.th");
        assert_eq!(extract_base_domain("uni.example.ac.th"), "example.ac.th");
        // Bare compound TLDs should return unchanged (2-label safety)
        assert_eq!(extract_base_domain("co.in"), "co.in");
        assert_eq!(extract_base_domain("co.za"), "co.za");
        assert_eq!(extract_base_domain("co.th"), "co.th");
    }

    /// BUG-004 regression: SPF include domains must never be over-stripped to a bare TLD.
    /// e.g., include:theaccessgroupSPF.smtp.com must not extract just "com".
    #[test]
    fn test_never_returns_bare_tld() {
        // smtp. prefix stripped → theaccessgroupspf.com (valid 2-label domain)
        let result = extract_base_domain("theaccessgroupSPF.smtp.com");
        assert!(result.contains('.'), "Must not return bare TLD");
        let label_count = result.split('.').count();
        assert!(
            label_count >= 2,
            "Must have at least 2 labels, got: {}",
            result
        );

        // Edge case: "smtp.com" — stripping smtp. prefix leaves bare "com",
        // but safety check falls back to the original "smtp.com"
        let result2 = extract_base_domain("smtp.com");
        assert_eq!(
            result2, "smtp.com",
            "Must fall back to original when over-stripped"
        );
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    #[test]
    fn test_normalize_for_dns_lookup_dmarc_prefix() {
        assert_eq!(
            normalize_for_dns_lookup("_dmarc.example.com"),
            "example.com"
        );
    }

    #[test]
    fn test_normalize_for_dns_lookup_no_prefix() {
        assert_eq!(
            normalize_for_dns_lookup("mail.example.com"),
            "mail.example.com"
        );
    }

    #[test]
    fn test_normalize_for_dns_lookup_case_insensitive() {
        assert_eq!(normalize_for_dns_lookup("_SPF.Example.COM"), "example.com");
    }

    #[test]
    fn test_is_organizational_domain_email_prefix() {
        assert!(!is_organizational_domain("email.example.com"));
    }

    #[test]
    fn test_is_organizational_domain_domainkey_prefix() {
        assert!(!is_organizational_domain("_domainkey.example.com"));
    }

    #[test]
    fn test_is_organizational_domain_selector_prefix() {
        assert!(!is_organizational_domain("selector1.example.com"));
        assert!(!is_organizational_domain("selector2.example.com"));
    }

    #[test]
    fn test_is_organizational_domain_dmarc_prefix() {
        assert!(!is_organizational_domain("dmarc.example.com"));
        assert!(!is_organizational_domain("_dmarc.example.com"));
    }

    #[test]
    fn test_is_organizational_domain_smtp_prefix() {
        assert!(!is_organizational_domain("smtp.example.com"));
    }

    #[test]
    fn test_is_organizational_domain_empty() {
        // empty string has no parts, first returns None -> true
        assert!(is_organizational_domain(""));
    }

    #[test]
    fn test_extract_base_domain_dmarc_prefix() {
        assert_eq!(extract_base_domain("_dmarc.example.com"), "example.com");
    }

    #[test]
    fn test_extract_base_domain_domainkey_prefix() {
        assert_eq!(
            extract_base_domain("selector1._domainkey.example.com"),
            "example.com"
        );
        assert_eq!(
            extract_base_domain("selector2._domainkey.example.com"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_base_domain_email_prefix() {
        assert_eq!(extract_base_domain("email.example.com"), "example.com");
    }

    #[test]
    fn test_extract_base_domain_single_label() {
        // Single label domain falls back to original
        assert_eq!(extract_base_domain("localhost"), "localhost");
    }

    #[test]
    fn test_normalize_for_dns_lookup() {
        assert_eq!(normalize_for_dns_lookup("_spf.mailgun.org"), "mailgun.org");
        assert_eq!(
            normalize_for_dns_lookup("spf.eu.mailgun.org"),
            "spf.eu.mailgun.org"
        );
        assert_eq!(normalize_for_dns_lookup("google.com"), "google.com");
    }

    #[test]
    fn test_is_organizational_domain() {
        assert!(is_organizational_domain("google.com"));
        assert!(is_organizational_domain("mailgun.org"));
        assert!(!is_organizational_domain("_spf.mailgun.org"));
        assert!(!is_organizational_domain("spf.mailgun.org"));
    }

    #[test]
    fn test_extract_base_domain_smtp_underscore_prefix() {
        assert_eq!(extract_base_domain("_smtp.example.com"), "example.com");
    }

    #[test]
    fn test_extract_base_domain_dmarc_no_underscore_prefix() {
        assert_eq!(extract_base_domain("dmarc.example.com"), "example.com");
    }

    #[test]
    fn test_extract_base_domain_compound_tld_only_two_labels() {
        // "ac.uk" is a compound TLD with only 2 labels — exercises compound_tlds guard at end
        assert_eq!(extract_base_domain("ac.uk"), "ac.uk");
        assert_eq!(extract_base_domain("org.uk"), "org.uk");
        assert_eq!(extract_base_domain("com.au"), "com.au");
    }

    #[test]
    fn test_extract_organizational_domain_exactly_three_parts_compound_tld() {
        // "bbc.co.uk" — exactly 3 parts with compound TLD returns full domain
        assert_eq!(extract_base_domain("bbc.co.uk"), "bbc.co.uk");
    }
}
