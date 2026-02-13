/// Extract the base domain from SPF subdomains and other technical subdomains
pub fn extract_base_domain(domain: &str) -> String {
    // Remove common SPF and technical prefixes
    let spf_prefixes = vec![
        "_spf.", "spf.", "_dmarc.", "dmarc.", "_domainkey.", 
        "selector1._domainkey.", "selector2._domainkey.",
        "_smtp.", "smtp.", "mail.", "email."
    ];
    
    let mut cleaned_domain = domain.to_lowercase();
    
    // Remove SPF-specific prefixes
    for prefix in spf_prefixes {
        if cleaned_domain.starts_with(prefix) {
            cleaned_domain = cleaned_domain.strip_prefix(prefix).unwrap_or(&cleaned_domain).to_string();
            break;
        }
    }
    
    // Remove subdomain prefixes that are clearly technical (but keep meaningful subdomains)
    if let Some(base) = extract_organizational_domain(&cleaned_domain) {
        base
    } else {
        cleaned_domain
    }
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
    let compound_tlds = ["co.uk", "co.au", "com.au", "co.nz", "co.jp", "co.kr",
                         "com.br", "com.mx", "com.cn", "org.uk", "net.au"];
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
        normalized = normalized.strip_prefix("_spf.").unwrap_or(&normalized).to_string();
    } else if normalized.starts_with("_dmarc.") {
        normalized = normalized.strip_prefix("_dmarc.").unwrap_or(&normalized).to_string();
    }
    
    normalized
}

/// Check if a domain is likely an organizational domain vs technical subdomain
pub fn is_organizational_domain(domain: &str) -> bool {
    let technical_subdomains = vec![
        "_spf", "spf", "_dmarc", "dmarc", "_domainkey", 
        "selector1", "selector2", "mail", "smtp", "email"
    ];
    
    let parts: Vec<&str> = domain.split('.').collect();
    if let Some(first_part) = parts.first() {
        !technical_subdomains.contains(first_part)
    } else {
        true
    }
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
        assert_eq!(
            extract_base_domain("myapp.herokuapp.com"),
            "herokuapp.com"
        );
        // Already apex → unchanged
        assert_eq!(extract_base_domain("amazonaws.com"), "amazonaws.com");
        assert_eq!(extract_base_domain("cloudfront.net"), "cloudfront.net");
    }

    /// Regression test: compound TLDs are handled correctly
    #[test]
    fn test_compound_tld_handling() {
        assert_eq!(
            extract_base_domain("mail.example.co.uk"),
            "example.co.uk"
        );
        assert_eq!(
            extract_base_domain("api.company.com.au"),
            "company.com.au"
        );
        // Already at apex with compound TLD
        assert_eq!(extract_base_domain("example.co.uk"), "example.co.uk");
    }

    #[test]
    fn test_normalize_for_dns_lookup() {
        assert_eq!(normalize_for_dns_lookup("_spf.mailgun.org"), "mailgun.org");
        assert_eq!(normalize_for_dns_lookup("spf.eu.mailgun.org"), "spf.eu.mailgun.org");
        assert_eq!(normalize_for_dns_lookup("google.com"), "google.com");
    }

    #[test]
    fn test_is_organizational_domain() {
        assert!(is_organizational_domain("google.com"));
        assert!(is_organizational_domain("mailgun.org"));
        assert!(!is_organizational_domain("_spf.mailgun.org"));
        assert!(!is_organizational_domain("spf.mailgun.org"));
    }
}