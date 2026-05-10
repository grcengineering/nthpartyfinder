use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecordType {
    // DNS TXT Record types
    DnsTxtSpf,          // DNS::TXT::SPF
    DnsTxtVerification, // DNS::TXT::VERIFICATION
    DnsTxtDmarc,        // DNS::TXT::DMARC
    DnsTxtDkim,         // DNS::TXT::DKIM

    // DNS other record types
    DnsSubdomain, // DNS::SUBDOMAIN
    DnsMx,        // DNS::MX
    DnsA,         // DNS::A
    DnsAaaa,      // DNS::AAAA

    // HTTP-based verifications
    HttpWellKnown, // HTTP::WELL_KNOWN
    HttpMeta,      // HTTP::META
    HttpFile,      // HTTP::FILE

    // Certificate-based
    CertDomain, // CERT::DOMAIN
    CertSan,    // CERT::SAN

    // API-based discovery
    ApiEndpoint, // API::ENDPOINT
    ApiWebhook,  // API::WEBHOOK

    // HTTP-based discovery
    HttpSubprocessor, // HTTP::SUBPROCESSOR

    // Discovery-based
    SubfinderDiscovery, // DISCOVERY::SUBFINDER
    SaasTenantProbe,    // DISCOVERY::SAAS_TENANT
    CtLogDiscovery,     // DISCOVERY::CT_LOG

    // Trust Center API extraction
    TrustCenterApi, // TRUST_CENTER::API

    // Webpage discovery
    WebTrafficSource,  // DISCOVERY::WEBPAGE_SOURCE (static HTML analysis)
    WebTrafficNetwork, // DISCOVERY::WEBPAGE_NETWORK (runtime network requests)

    // Unknown/Other
    Unknown, // UNKNOWN
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
            RecordType::DnsSubdomain => "DNS::SUBDOMAIN".to_string(),
            RecordType::DnsMx => "DNS::MX".to_string(),
            RecordType::DnsA => "DNS::A".to_string(),
            RecordType::DnsAaaa => "DNS::AAAA".to_string(),
            RecordType::HttpWellKnown => "HTTP::WELL_KNOWN".to_string(),
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
            RecordType::TrustCenterApi => "TRUST_CENTER::API".to_string(),
            RecordType::WebTrafficSource => "DISCOVERY::WEBPAGE_SOURCE".to_string(),
            RecordType::WebTrafficNetwork => "DISCOVERY::WEBPAGE_NETWORK".to_string(),
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
            RecordType::DnsTxtSpf
            | RecordType::DnsTxtVerification
            | RecordType::DnsTxtDmarc
            | RecordType::DnsTxtDkim => "Email & Authentication",
            RecordType::DnsSubdomain
            | RecordType::DnsMx
            | RecordType::DnsA
            | RecordType::DnsAaaa => "DNS Infrastructure",
            RecordType::HttpWellKnown
            | RecordType::HttpMeta
            | RecordType::HttpFile
            | RecordType::HttpSubprocessor => "HTTP Verification",
            RecordType::CertDomain | RecordType::CertSan => "Certificate Authority",
            RecordType::ApiEndpoint | RecordType::ApiWebhook => "API Integration",
            RecordType::SubfinderDiscovery
            | RecordType::SaasTenantProbe
            | RecordType::CtLogDiscovery
            | RecordType::WebTrafficSource
            | RecordType::WebTrafficNetwork => "Discovery",
            RecordType::TrustCenterApi => "Trust Center",
            RecordType::Unknown => "Other",
        }
    }

    /// Evidence strength priority for dedup merging. Higher = stronger evidence.
    /// HttpSubprocessor is strongest because it's a direct listing on the company's
    /// own subprocessor page. TrustCenterApi is next, then SaaS tenant, etc.
    pub fn evidence_priority(&self) -> u8 {
        match self {
            RecordType::HttpSubprocessor => 10,
            RecordType::TrustCenterApi => 9,
            RecordType::DnsTxtVerification => 8,
            RecordType::SaasTenantProbe => 7,
            RecordType::DnsTxtSpf => 6,
            RecordType::DnsTxtDmarc => 5,
            RecordType::DnsTxtDkim => 5,
            RecordType::WebTrafficNetwork => 5, // Runtime network request is strong evidence
            RecordType::WebTrafficSource => 4,  // Static webpage source reference
            RecordType::SubfinderDiscovery => 4,
            RecordType::CtLogDiscovery => 3,
            RecordType::DnsSubdomain
            | RecordType::DnsMx
            | RecordType::DnsA
            | RecordType::DnsAaaa => 2,
            RecordType::HttpWellKnown | RecordType::HttpMeta | RecordType::HttpFile => 2,
            RecordType::CertDomain | RecordType::CertSan => 2,
            RecordType::ApiEndpoint | RecordType::ApiWebhook => 2,
            RecordType::Unknown => 0,
        }
    }

    pub fn get_description(&self) -> &'static str {
        match self {
            RecordType::DnsTxtSpf => "Email sending authorization record",
            RecordType::DnsTxtVerification => "Domain ownership verification record",
            RecordType::DnsTxtDmarc => "Email authentication policy record",
            RecordType::DnsTxtDkim => "Email signature verification record",
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
            RecordType::TrustCenterApi => "Trust center API extraction",
            RecordType::WebTrafficSource => "External resource referenced in webpage source",
            RecordType::WebTrafficNetwork => {
                "Runtime network request from webpage to external domain"
            }
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
    #[allow(clippy::too_many_arguments)]
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
        // BUG-001/002: Strip any leaked _org: sentinel prefix from output fields.
        // This is a safety net — the primary fix is in filter_subprocessor_results().
        let nth_party_domain = nth_party_domain
            .strip_prefix("_org:")
            .map(|s| s.to_string())
            .unwrap_or(nth_party_domain);
        let nth_party_organization = nth_party_organization
            .strip_prefix("_org:")
            .map(|s| s.to_string())
            .unwrap_or(nth_party_organization);

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
    use rstest::rstest;

    #[rstest]
    #[case(RecordType::DnsTxtSpf, "DNS::TXT::SPF")]
    #[case(RecordType::DnsTxtVerification, "DNS::TXT::VERIFICATION")]
    #[case(RecordType::DnsTxtDmarc, "DNS::TXT::DMARC")]
    #[case(RecordType::DnsTxtDkim, "DNS::TXT::DKIM")]
    #[case(RecordType::DnsSubdomain, "DNS::SUBDOMAIN")]
    #[case(RecordType::DnsMx, "DNS::MX")]
    #[case(RecordType::DnsA, "DNS::A")]
    #[case(RecordType::DnsAaaa, "DNS::AAAA")]
    #[case(RecordType::HttpWellKnown, "HTTP::WELL_KNOWN")]
    #[case(RecordType::HttpMeta, "HTTP::META")]
    #[case(RecordType::HttpFile, "HTTP::FILE")]
    #[case(RecordType::CertDomain, "CERT::DOMAIN")]
    #[case(RecordType::CertSan, "CERT::SAN")]
    #[case(RecordType::ApiEndpoint, "API::ENDPOINT")]
    #[case(RecordType::ApiWebhook, "API::WEBHOOK")]
    #[case(RecordType::HttpSubprocessor, "HTTP::SUBPROCESSOR")]
    #[case(RecordType::SubfinderDiscovery, "DISCOVERY::SUBFINDER")]
    #[case(RecordType::SaasTenantProbe, "DISCOVERY::SAAS_TENANT")]
    #[case(RecordType::CtLogDiscovery, "DISCOVERY::CT_LOG")]
    #[case(RecordType::TrustCenterApi, "TRUST_CENTER::API")]
    #[case(RecordType::WebTrafficSource, "DISCOVERY::WEBPAGE_SOURCE")]
    #[case(RecordType::WebTrafficNetwork, "DISCOVERY::WEBPAGE_NETWORK")]
    #[case(RecordType::Unknown, "UNKNOWN")]
    fn test_as_hierarchy_string(#[case] record_type: RecordType, #[case] expected: &str) {
        assert_eq!(record_type.as_hierarchy_string(), expected);
    }

    #[rstest]
    #[case(RecordType::DnsTxtSpf, "DNS::TXT::SPF")]
    #[case(RecordType::Unknown, "UNKNOWN")]
    fn test_display_matches_hierarchy(#[case] record_type: RecordType, #[case] expected: &str) {
        assert_eq!(format!("{}", record_type), expected);
    }

    #[rstest]
    #[case("SPF", RecordType::DnsTxtSpf)]
    #[case("VERIFICATION", RecordType::DnsTxtVerification)]
    #[case("SUBDOMAIN", RecordType::DnsSubdomain)]
    #[case("unknown_value", RecordType::Unknown)]
    #[case("", RecordType::Unknown)]
    fn test_from_legacy_string(#[case] input: &str, #[case] expected: RecordType) {
        assert_eq!(RecordType::from_legacy_string(input), expected);
    }

    #[rstest]
    #[case(RecordType::DnsTxtSpf, "Email & Authentication")]
    #[case(RecordType::DnsTxtVerification, "Email & Authentication")]
    #[case(RecordType::DnsTxtDmarc, "Email & Authentication")]
    #[case(RecordType::DnsTxtDkim, "Email & Authentication")]
    #[case(RecordType::DnsSubdomain, "DNS Infrastructure")]
    #[case(RecordType::DnsMx, "DNS Infrastructure")]
    #[case(RecordType::DnsA, "DNS Infrastructure")]
    #[case(RecordType::DnsAaaa, "DNS Infrastructure")]
    #[case(RecordType::HttpWellKnown, "HTTP Verification")]
    #[case(RecordType::HttpMeta, "HTTP Verification")]
    #[case(RecordType::HttpFile, "HTTP Verification")]
    #[case(RecordType::HttpSubprocessor, "HTTP Verification")]
    #[case(RecordType::CertDomain, "Certificate Authority")]
    #[case(RecordType::CertSan, "Certificate Authority")]
    #[case(RecordType::ApiEndpoint, "API Integration")]
    #[case(RecordType::ApiWebhook, "API Integration")]
    #[case(RecordType::SubfinderDiscovery, "Discovery")]
    #[case(RecordType::SaasTenantProbe, "Discovery")]
    #[case(RecordType::CtLogDiscovery, "Discovery")]
    #[case(RecordType::WebTrafficSource, "Discovery")]
    #[case(RecordType::WebTrafficNetwork, "Discovery")]
    #[case(RecordType::TrustCenterApi, "Trust Center")]
    #[case(RecordType::Unknown, "Other")]
    fn test_get_category(#[case] record_type: RecordType, #[case] expected: &str) {
        assert_eq!(record_type.get_category(), expected);
    }

    #[test]
    fn test_evidence_priority_ordering() {
        assert_eq!(RecordType::HttpSubprocessor.evidence_priority(), 10);
        assert_eq!(RecordType::TrustCenterApi.evidence_priority(), 9);
        assert_eq!(RecordType::DnsTxtVerification.evidence_priority(), 8);
        assert_eq!(RecordType::Unknown.evidence_priority(), 0);
        assert!(
            RecordType::HttpSubprocessor.evidence_priority()
                > RecordType::TrustCenterApi.evidence_priority()
        );
        assert!(
            RecordType::TrustCenterApi.evidence_priority()
                > RecordType::DnsTxtSpf.evidence_priority()
        );
    }

    #[rstest]
    #[case(RecordType::DnsTxtSpf, "Email sending authorization record")]
    #[case(RecordType::HttpSubprocessor, "HTTP subprocessor page listing")]
    #[case(RecordType::TrustCenterApi, "Trust center API extraction")]
    #[case(
        RecordType::WebTrafficNetwork,
        "Runtime network request from webpage to external domain"
    )]
    #[case(RecordType::Unknown, "Unknown or unclassified record type")]
    fn test_get_description(#[case] record_type: RecordType, #[case] expected: &str) {
        assert_eq!(record_type.get_description(), expected);
    }

    fn make_vendor(
        domain: &str,
        org: &str,
        layer: u32,
        record_type: RecordType,
    ) -> VendorRelationship {
        VendorRelationship::new(
            domain.to_string(),
            org.to_string(),
            layer,
            "customer.com".to_string(),
            "Customer Inc".to_string(),
            format!("v=spf1 include:{}", domain),
            record_type,
            "root.com".to_string(),
            "Root Inc".to_string(),
            "test evidence".to_string(),
        )
    }

    #[test]
    fn test_vendor_relationship_new() {
        let vr = make_vendor("google.com", "Google", 3, RecordType::DnsTxtSpf);
        assert_eq!(vr.nth_party_domain, "google.com");
        assert_eq!(vr.nth_party_organization, "Google");
        assert_eq!(vr.nth_party_layer, 3);
        assert_eq!(vr.nth_party_record_type, RecordType::DnsTxtSpf);
    }

    #[test]
    fn test_vendor_relationship_strips_org_prefix() {
        let vr = VendorRelationship::new(
            "_org:example.com".to_string(),
            "_org:Example Inc".to_string(),
            1,
            "c.com".to_string(),
            "C".to_string(),
            "record".to_string(),
            RecordType::Unknown,
            "r.com".to_string(),
            "R".to_string(),
            "ev".to_string(),
        );
        assert_eq!(vr.nth_party_domain, "example.com");
        assert_eq!(vr.nth_party_organization, "Example Inc");
    }

    #[rstest]
    #[case(1, "1st party")]
    #[case(2, "2nd party")]
    #[case(3, "3rd party")]
    #[case(4, "4th party")]
    #[case(5, "5th party")]
    #[case(10, "10th party")]
    fn test_layer_description(#[case] layer: u32, #[case] expected: &str) {
        let vr = make_vendor("test.com", "Test", layer, RecordType::Unknown);
        assert_eq!(vr.layer_description(), expected);
    }

    #[test]
    fn test_analysis_result_empty() {
        let result = AnalysisResult::new(vec![]);
        assert_eq!(result.total_vendors, 0);
        assert_eq!(result.max_depth_reached, 0);
        assert!(result.unique_organizations.is_empty());
    }

    #[test]
    fn test_analysis_result_basic() {
        let vendors = vec![
            make_vendor("google.com", "Google", 3, RecordType::DnsTxtSpf),
            make_vendor("sendgrid.net", "SendGrid", 3, RecordType::DnsTxtSpf),
            make_vendor("cloudflare.com", "Cloudflare", 4, RecordType::DnsSubdomain),
        ];
        let result = AnalysisResult::new(vendors);
        assert_eq!(result.total_vendors, 3);
        assert_eq!(result.max_depth_reached, 4);
        assert_eq!(result.unique_organizations.len(), 3);
    }

    #[test]
    fn test_analysis_result_dedup_orgs() {
        let vendors = vec![
            make_vendor("google.com", "Google", 3, RecordType::DnsTxtSpf),
            make_vendor("google.com", "Google", 4, RecordType::DnsTxtVerification),
        ];
        let result = AnalysisResult::new(vendors);
        assert_eq!(result.total_vendors, 2);
        assert_eq!(result.unique_organizations.len(), 1);
        assert_eq!(result.unique_organizations[0], "Google");
    }

    #[test]
    fn test_get_vendors_by_layer() {
        let vendors = vec![
            make_vendor("a.com", "A", 3, RecordType::DnsTxtSpf),
            make_vendor("b.com", "B", 4, RecordType::DnsTxtSpf),
            make_vendor("c.com", "C", 3, RecordType::DnsTxtSpf),
        ];
        let result = AnalysisResult::new(vendors);
        assert_eq!(result.get_vendors_by_layer(3).len(), 2);
        assert_eq!(result.get_vendors_by_layer(4).len(), 1);
        assert_eq!(result.get_vendors_by_layer(5).len(), 0);
    }

    #[test]
    fn test_get_common_denominators() {
        let vendors = vec![
            make_vendor("a.com", "A", 3, RecordType::DnsTxtSpf),
            make_vendor("b.com", "B", 4, RecordType::DnsTxtSpf),
            make_vendor("c.com", "C", 5, RecordType::DnsTxtSpf),
        ];
        let result = AnalysisResult::new(vendors);
        let denominators = result.get_common_denominators();
        assert!(denominators.contains(&"B".to_string()));
        assert!(denominators.contains(&"C".to_string()));
        assert!(!denominators.contains(&"A".to_string()));
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    // --- RecordType serde roundtrip ---

    #[test]
    fn test_record_type_serde_roundtrip() {
        let types = vec![
            RecordType::DnsTxtSpf,
            RecordType::DnsTxtVerification,
            RecordType::DnsTxtDmarc,
            RecordType::DnsTxtDkim,
            RecordType::DnsSubdomain,
            RecordType::DnsMx,
            RecordType::DnsA,
            RecordType::DnsAaaa,
            RecordType::HttpWellKnown,
            RecordType::HttpMeta,
            RecordType::HttpFile,
            RecordType::CertDomain,
            RecordType::CertSan,
            RecordType::ApiEndpoint,
            RecordType::ApiWebhook,
            RecordType::HttpSubprocessor,
            RecordType::SubfinderDiscovery,
            RecordType::SaasTenantProbe,
            RecordType::CtLogDiscovery,
            RecordType::TrustCenterApi,
            RecordType::WebTrafficSource,
            RecordType::WebTrafficNetwork,
            RecordType::Unknown,
        ];
        for rt in &types {
            let json = serde_json::to_string(rt).unwrap();
            let deserialized: RecordType = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, rt, "Serde roundtrip failed for {:?}", rt);
        }
    }

    // --- All evidence_priority values ---

    #[test]
    fn test_evidence_priority_all_variants() {
        assert_eq!(RecordType::SaasTenantProbe.evidence_priority(), 7);
        assert_eq!(RecordType::DnsTxtDmarc.evidence_priority(), 5);
        assert_eq!(RecordType::DnsTxtDkim.evidence_priority(), 5);
        assert_eq!(RecordType::WebTrafficNetwork.evidence_priority(), 5);
        assert_eq!(RecordType::WebTrafficSource.evidence_priority(), 4);
        assert_eq!(RecordType::SubfinderDiscovery.evidence_priority(), 4);
        assert_eq!(RecordType::CtLogDiscovery.evidence_priority(), 3);
        assert_eq!(RecordType::DnsSubdomain.evidence_priority(), 2);
        assert_eq!(RecordType::DnsMx.evidence_priority(), 2);
        assert_eq!(RecordType::DnsA.evidence_priority(), 2);
        assert_eq!(RecordType::DnsAaaa.evidence_priority(), 2);
        assert_eq!(RecordType::HttpWellKnown.evidence_priority(), 2);
        assert_eq!(RecordType::HttpMeta.evidence_priority(), 2);
        assert_eq!(RecordType::HttpFile.evidence_priority(), 2);
        assert_eq!(RecordType::CertDomain.evidence_priority(), 2);
        assert_eq!(RecordType::CertSan.evidence_priority(), 2);
        assert_eq!(RecordType::ApiEndpoint.evidence_priority(), 2);
        assert_eq!(RecordType::ApiWebhook.evidence_priority(), 2);
    }

    // --- All get_description variants ---

    #[rstest]
    #[case(RecordType::DnsTxtVerification, "Domain ownership verification record")]
    #[case(RecordType::DnsTxtDmarc, "Email authentication policy record")]
    #[case(RecordType::DnsTxtDkim, "Email signature verification record")]
    #[case(RecordType::DnsSubdomain, "Subdomain delegation")]
    #[case(RecordType::DnsMx, "Mail exchange record")]
    #[case(RecordType::DnsA, "IPv4 address record")]
    #[case(RecordType::DnsAaaa, "IPv6 address record")]
    #[case(RecordType::HttpWellKnown, "HTTP well-known URI verification")]
    #[case(RecordType::HttpMeta, "HTML meta tag verification")]
    #[case(RecordType::HttpFile, "HTTP file-based verification")]
    #[case(RecordType::CertDomain, "SSL certificate domain verification")]
    #[case(RecordType::CertSan, "SSL certificate subject alternative name")]
    #[case(RecordType::ApiEndpoint, "API endpoint discovery")]
    #[case(RecordType::ApiWebhook, "Webhook endpoint registration")]
    #[case(RecordType::SubfinderDiscovery, "Subdomain discovered via subfinder")]
    #[case(RecordType::SaasTenantProbe, "SaaS tenant probe discovery")]
    #[case(RecordType::CtLogDiscovery, "Certificate Transparency log discovery")]
    #[case(
        RecordType::WebTrafficSource,
        "External resource referenced in webpage source"
    )]
    fn test_get_description_all(#[case] record_type: RecordType, #[case] expected: &str) {
        assert_eq!(record_type.get_description(), expected);
    }

    // --- VendorRelationship without _org: prefix ---

    #[test]
    fn test_vendor_relationship_no_org_prefix() {
        let vr = VendorRelationship::new(
            "normal.com".to_string(),
            "Normal Inc".to_string(),
            1,
            "c.com".to_string(),
            "C".to_string(),
            "record".to_string(),
            RecordType::DnsTxtSpf,
            "r.com".to_string(),
            "R".to_string(),
            "evidence".to_string(),
        );
        assert_eq!(vr.nth_party_domain, "normal.com");
        assert_eq!(vr.nth_party_organization, "Normal Inc");
    }

    // --- VendorRelationship serde ---

    #[test]
    fn test_vendor_relationship_serde() {
        let vr = make_vendor("test.com", "Test Inc", 2, RecordType::DnsTxtSpf);
        let json = serde_json::to_string(&vr).unwrap();
        let deserialized: VendorRelationship = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.nth_party_domain, "test.com");
        assert_eq!(deserialized.nth_party_organization, "Test Inc");
        assert_eq!(deserialized.nth_party_layer, 2);
    }

    // --- AnalysisResult get_common_denominators edge cases ---

    #[test]
    fn test_get_common_denominators_single_depth() {
        let vendors = vec![
            make_vendor("a.com", "A", 1, RecordType::DnsTxtSpf),
            make_vendor("b.com", "B", 1, RecordType::DnsTxtSpf),
        ];
        let result = AnalysisResult::new(vendors);
        let denominators = result.get_common_denominators();
        // All at depth 1, max_depth=1, saturating_sub(1)=0, so all at depth >= 0 are included
        assert!(denominators.contains(&"A".to_string()));
        assert!(denominators.contains(&"B".to_string()));
    }

    #[test]
    fn test_unique_organizations_sorted() {
        let vendors = vec![
            make_vendor("z.com", "Zebra", 3, RecordType::DnsTxtSpf),
            make_vendor("a.com", "Alpha", 3, RecordType::DnsTxtSpf),
            make_vendor("m.com", "Maple", 3, RecordType::DnsTxtSpf),
        ];
        let result = AnalysisResult::new(vendors);
        assert_eq!(result.unique_organizations, vec!["Alpha", "Maple", "Zebra"]);
    }
}
