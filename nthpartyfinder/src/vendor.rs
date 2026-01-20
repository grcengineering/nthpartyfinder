use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecordType {
    // DNS TXT Record types
    DnsTxtSpf,           // DNS::TXT::SPF
    DnsTxtVerification,  // DNS::TXT::VERIFICATION  
    DnsTxtDmarc,         // DNS::TXT::DMARC
    DnsTxtDkim,          // DNS::TXT::DKIM
    
    // DNS other record types
    DnsCname,            // DNS::CNAME
    DnsSubdomain,        // DNS::SUBDOMAIN
    DnsMx,               // DNS::MX
    DnsA,                // DNS::A
    DnsAaaa,             // DNS::AAAA
    
    // HTTP-based verifications
    HttpWellKnown,       // HTTP::.well-known
    HttpMeta,            // HTTP::META
    HttpFile,            // HTTP::FILE
    
    // Certificate-based
    CertDomain,          // CERT::DOMAIN
    CertSan,             // CERT::SAN
    
    // API-based discovery
    ApiEndpoint,         // API::ENDPOINT
    ApiWebhook,          // API::WEBHOOK
    
    // HTTP-based discovery
    HttpSubprocessor,    // HTTP::SUBPROCESSOR

    // Discovery-based
    SubfinderDiscovery,  // DISCOVERY::SUBFINDER
    SaasTenantProbe,     // DISCOVERY::SAAS_TENANT
    CtLogDiscovery,      // DISCOVERY::CT_LOG

    // Unknown/Other
    Unknown,             // UNKNOWN
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_hierarchy_string())
    }
}

impl RecordType {
    pub fn as_hierarchy_string(&self) -> String {
        match self {
            RecordType::DnsTxtSpf => "DNS::TXT::SPF".to_string(),
            RecordType::DnsTxtVerification => "DNS::TXT::VERIFICATION".to_string(),
            RecordType::DnsTxtDmarc => "DNS::TXT::DMARC".to_string(),
            RecordType::DnsTxtDkim => "DNS::TXT::DKIM".to_string(),
            RecordType::DnsCname => "DNS::CNAME".to_string(),
            RecordType::DnsSubdomain => "DNS::SUBDOMAIN".to_string(),
            RecordType::DnsMx => "DNS::MX".to_string(),
            RecordType::DnsA => "DNS::A".to_string(),
            RecordType::DnsAaaa => "DNS::AAAA".to_string(),
            RecordType::HttpWellKnown => "HTTP::.well-known".to_string(),
            RecordType::HttpMeta => "HTTP::META".to_string(),
            RecordType::HttpFile => "HTTP::FILE".to_string(),
            RecordType::CertDomain => "CERT::DOMAIN".to_string(),
            RecordType::CertSan => "CERT::SAN".to_string(),
            RecordType::ApiEndpoint => "API::ENDPOINT".to_string(),
            RecordType::ApiWebhook => "API::WEBHOOK".to_string(),
            RecordType::HttpSubprocessor => "HTTP::SUBPROCESSOR".to_string(),
            RecordType::SubfinderDiscovery => "DISCOVERY::SUBFINDER".to_string(),
            RecordType::SaasTenantProbe => "DISCOVERY::SAAS_TENANT".to_string(),
            RecordType::CtLogDiscovery => "DISCOVERY::CT_LOG".to_string(),
            RecordType::Unknown => "UNKNOWN".to_string(),
        }
    }
    
    pub fn from_legacy_string(legacy_type: &str) -> Self {
        match legacy_type {
            "SPF" => RecordType::DnsTxtSpf,
            "VERIFICATION" => RecordType::DnsTxtVerification,
            "SUBDOMAIN" => RecordType::DnsSubdomain,
            _ => RecordType::Unknown,
        }
    }
    
    pub fn get_category(&self) -> &'static str {
        match self {
            RecordType::DnsTxtSpf | RecordType::DnsTxtVerification | RecordType::DnsTxtDmarc | RecordType::DnsTxtDkim => "Email & Authentication",
            RecordType::DnsCname | RecordType::DnsSubdomain | RecordType::DnsMx | RecordType::DnsA | RecordType::DnsAaaa => "DNS Infrastructure",
            RecordType::HttpWellKnown | RecordType::HttpMeta | RecordType::HttpFile | RecordType::HttpSubprocessor => "HTTP Verification",
            RecordType::CertDomain | RecordType::CertSan => "Certificate Authority",
            RecordType::ApiEndpoint | RecordType::ApiWebhook => "API Integration",
            RecordType::SubfinderDiscovery | RecordType::SaasTenantProbe | RecordType::CtLogDiscovery => "Discovery",
            RecordType::Unknown => "Other",
        }
    }
    
    pub fn get_description(&self) -> &'static str {
        match self {
            RecordType::DnsTxtSpf => "Email sending authorization record",
            RecordType::DnsTxtVerification => "Domain ownership verification record",
            RecordType::DnsTxtDmarc => "Email authentication policy record",
            RecordType::DnsTxtDkim => "Email signature verification record",
            RecordType::DnsCname => "Canonical name record",
            RecordType::DnsSubdomain => "Subdomain delegation",
            RecordType::DnsMx => "Mail exchange record",
            RecordType::DnsA => "IPv4 address record",
            RecordType::DnsAaaa => "IPv6 address record",
            RecordType::HttpWellKnown => "HTTP well-known URI verification",
            RecordType::HttpMeta => "HTML meta tag verification",
            RecordType::HttpFile => "HTTP file-based verification",
            RecordType::HttpSubprocessor => "HTTP subprocessor page listing",
            RecordType::CertDomain => "SSL certificate domain verification",
            RecordType::CertSan => "SSL certificate subject alternative name",
            RecordType::ApiEndpoint => "API endpoint discovery",
            RecordType::ApiWebhook => "Webhook endpoint registration",
            RecordType::SubfinderDiscovery => "Subdomain discovered via subfinder",
            RecordType::SaasTenantProbe => "SaaS tenant probe discovery",
            RecordType::CtLogDiscovery => "Certificate Transparency log discovery",
            RecordType::Unknown => "Unknown or unclassified record type",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorRelationship {
    pub nth_party_domain: String,
    pub nth_party_organization: String,
    pub nth_party_layer: u32,
    pub nth_party_customer_domain: String,
    pub nth_party_customer_organization: String,
    pub nth_party_record: String,
    pub nth_party_record_type: RecordType,
    pub root_customer_domain: String,
    pub root_customer_organization: String,
    pub evidence: String, // Raw evidence used for domain inference
}

impl VendorRelationship {
    pub fn new(
        nth_party_domain: String,
        nth_party_organization: String,
        nth_party_layer: u32,
        nth_party_customer_domain: String,
        nth_party_customer_organization: String,
        nth_party_record: String,
        nth_party_record_type: RecordType,
        root_customer_domain: String,
        root_customer_organization: String,
        evidence: String,
    ) -> Self {
        VendorRelationship {
            nth_party_domain,
            nth_party_organization,
            nth_party_layer,
            nth_party_customer_domain,
            nth_party_customer_organization,
            nth_party_record,
            nth_party_record_type,
            root_customer_domain,
            root_customer_organization,
            evidence,
        }
    }
    
    pub fn layer_description(&self) -> String {
        match self.nth_party_layer {
            1 => "1st party".to_string(),
            2 => "2nd party".to_string(),
            3 => "3rd party".to_string(),
            n => format!("{}th party", n),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub total_vendors: usize,
    pub max_depth_reached: u32,
    pub vendor_relationships: Vec<VendorRelationship>,
    pub unique_organizations: Vec<String>,
}

impl AnalysisResult {
    pub fn new(vendor_relationships: Vec<VendorRelationship>) -> Self {
        let total_vendors = vendor_relationships.len();
        let max_depth_reached = vendor_relationships
            .iter()
            .map(|v| v.nth_party_layer)
            .max()
            .unwrap_or(0);
        
        let mut unique_organizations: Vec<String> = vendor_relationships
            .iter()
            .map(|v| v.nth_party_organization.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        
        unique_organizations.sort();
        
        AnalysisResult {
            total_vendors,
            max_depth_reached,
            vendor_relationships,
            unique_organizations,
        }
    }
    
    pub fn get_vendors_by_layer(&self, layer: u32) -> Vec<&VendorRelationship> {
        self.vendor_relationships
            .iter()
            .filter(|v| v.nth_party_layer == layer)
            .collect()
    }
    
    pub fn get_common_denominators(&self) -> Vec<String> {
        // Identify vendors that appear at the deepest layers (likely common denominators)
        let max_depth = self.max_depth_reached;

        self.vendor_relationships
            .iter()
            .filter(|v| v.nth_party_layer >= max_depth.saturating_sub(1))
            .map(|v| v.nth_party_organization.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_record_types_display() {
        // Test SubfinderDiscovery
        assert_eq!(RecordType::SubfinderDiscovery.as_hierarchy_string(), "DISCOVERY::SUBFINDER");
        assert_eq!(RecordType::SubfinderDiscovery.get_category(), "Discovery");
        assert_eq!(RecordType::SubfinderDiscovery.get_description(), "Subdomain discovered via subfinder");

        // Test SaasTenantProbe
        assert_eq!(RecordType::SaasTenantProbe.as_hierarchy_string(), "DISCOVERY::SAAS_TENANT");
        assert_eq!(RecordType::SaasTenantProbe.get_category(), "Discovery");
        assert_eq!(RecordType::SaasTenantProbe.get_description(), "SaaS tenant probe discovery");
    }
}