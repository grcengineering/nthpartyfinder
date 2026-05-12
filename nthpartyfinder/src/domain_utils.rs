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
    let result = extract_organizational_domain(&cleaned_domain)
        .unwrap_or_else(|| cleaned_domain.clone());

    if let Some(fallback) = bug004_single_label_fallback(&result, &cleaned_domain, domain) {
        return fallback;
    }

    // Reject results that are only a public suffix (e.g., "co.uk", "com.au")
    let compound_tlds = [
        "co.uk", "ac.uk", "org.uk", "gov.uk", "net.uk", "me.uk", "co.au", "com.au", "net.au",
        "org.au", "edu.au", "co.nz", "org.nz", "co.jp", "or.jp", "ac.jp", "ne.jp", "co.kr",
        "or.kr", "ac.kr", "com.br", "org.br", "net.br", "com.mx", "org.mx", "com.cn", "org.cn",
        "net.cn", "co.in", "org.in", "ac.in", "co.za", "org.za", "co.il", "org.il", "ac.il",
        "com.sg", "edu.sg", "com.hk", "edu.hk", "co.id", "or.id", "com.tr", "org.tr", "com.ar",
        "org.ar", "co.th", "or.th", "ac.th",
    ];
    if compound_tlds.contains(&result.as_str()) {
        return cleaned_domain;
    }

    result
}

/// Extract the organizational domain (e.g. mailgun.org from eu.mailgun.org)
fn extract_organizational_domain(domain: &str) -> Option<String> {
    let parts: Vec<&str> = domain.split('.').collect();

    // If it's already a base domain (2 parts), return as-is
    if parts.len() <= 2 {
        return Some(domain.to_string());
    }

    // For domains with more than 2 parts, try to identify the organizational domain
    // Common patterns:
    // - eu.mailgun.org -> mailgun.org
    // - mail.google.com -> google.com
    // - subdomain.company.com -> company.com

    // Get the organizational/apex domain.
    // FQDNs like s3.amazonaws.com or Nagios-842216103.us-east-1.elb.amazonaws.com
    // normalize to amazonaws.com — the vendor is the platform provider.
    // The full FQDN is preserved in the record value / evidence fields.
    let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);

    // Handle compound TLDs (e.g., .co.uk, .com.au) — need 3 parts for the apex
    let compound_tlds = [
        "co.uk", "ac.uk", "org.uk", "gov.uk", "net.uk", "me.uk", "co.au", "com.au", "net.au",
        "org.au", "edu.au", "co.nz", "org.nz", "co.jp", "or.jp", "ac.jp", "ne.jp", "co.kr",
        "or.kr", "ac.kr", "com.br", "org.br", "net.br", "com.mx", "org.mx", "com.cn", "org.cn",
        "net.cn", "co.in", "org.in", "ac.in", "co.za", "org.za", "co.il", "org.il", "ac.il",
        "com.sg", "edu.sg", "com.hk", "edu.hk", "co.id", "or.id", "com.tr", "org.tr", "com.ar",
        "org.ar", "co.th", "or.th", "ac.th",
    ];
    if compound_tlds.contains(&last_two.as_str()) {
        if parts.len() > 3 {
            Some(format!("{}.{}", parts[parts.len() - 3], last_two))
        } else {
            // e.g., "example.co.uk" — already the apex with compound TLD
            Some(domain.to_string())
        }
    } else {
        Some(last_two)
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
        .map_or(true, |first_part| !technical_subdomains.contains(first_part))
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
