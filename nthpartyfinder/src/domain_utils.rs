use regex::Regex;

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
    
    // Get the last 2 parts (assumed to be the org domain)
    if parts.len() >= 2 {
        let org_domain = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        
        // Don't flatten if the subdomain indicates a different organization
        // (e.g., github.io, herokuapp.com)
        let keep_subdomain_patterns = vec![
            r"\.github\.io$",
            r"\.herokuapp\.com$", 
            r"\.amazonaws\.com$",
            r"\.cloudfront\.net$",
            r"\.azurewebsites\.net$"
        ];
        
        for pattern in keep_subdomain_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(domain) {
                    return Some(domain.to_string());
                }
            }
        }
        
        Some(org_domain)
    } else {
        Some(domain.to_string())
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