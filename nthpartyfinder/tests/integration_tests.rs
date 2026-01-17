use nthpartyfinder::dns;
use nthpartyfinder::vendor::{VendorRelationship, RecordType};

#[tokio::test]
async fn test_extract_vendor_domains_from_spf() {
    let txt_records = vec![
        "v=spf1 include:_spf.google.com include:mailgun.org ~all".to_string(),
        "v=spf1 include:servers.mcsv.net ?all".to_string(),
    ];
    
    let vendor_domains = dns::extract_vendor_domains_with_source_and_logger(&txt_records, None, "test.com");

    // Check that the vendor domains were found
    let domains: Vec<String> = vendor_domains.iter().map(|v| v.domain.clone()).collect();
    assert!(domains.contains(&"_spf.google.com".to_string()));
    assert!(domains.contains(&"mailgun.org".to_string()));
    assert!(domains.contains(&"servers.mcsv.net".to_string()));
}

#[test]
fn test_vendor_relationship_creation() {
    let relationship = VendorRelationship::new(
        "vendor.com".to_string(),
        "Vendor Inc.".to_string(),
        1,
        "customer.com".to_string(),
        "Customer Corp".to_string(),
        "vendor.com".to_string(),
        RecordType::DnsTxtSpf,
        "root.com".to_string(),
        "Root Corp".to_string(),
        "evidence".to_string(),
    );
    
    assert_eq!(relationship.nth_party_domain, "vendor.com");
    assert_eq!(relationship.nth_party_organization, "Vendor Inc.");
    assert_eq!(relationship.nth_party_layer, 1);
    assert_eq!(relationship.layer_description(), "1st party");
}

#[test]
fn test_layer_descriptions() {
    let relationship1 = VendorRelationship::new(
        "test.com".to_string(),
        "Test".to_string(),
        1,
        "customer.com".to_string(),
        "Customer".to_string(),
        "test.com".to_string(),
        RecordType::DnsTxtSpf,
        "root.com".to_string(),
        "Root".to_string(),
        "evidence".to_string(),
    );
    
    let relationship3 = VendorRelationship::new(
        "test.com".to_string(),
        "Test".to_string(),
        3,
        "customer.com".to_string(),
        "Customer".to_string(),
        "test.com".to_string(),
        RecordType::DnsTxtSpf,
        "root.com".to_string(),
        "Root".to_string(),
        "evidence".to_string(),
    );
    
    let relationship5 = VendorRelationship::new(
        "test.com".to_string(),
        "Test".to_string(),
        5,
        "customer.com".to_string(),
        "Customer".to_string(),
        "test.com".to_string(),
        RecordType::DnsTxtSpf,
        "root.com".to_string(),
        "Root".to_string(),
        "evidence".to_string(),
    );
    
    assert_eq!(relationship1.layer_description(), "1st party");
    assert_eq!(relationship3.layer_description(), "3rd party");
    assert_eq!(relationship5.layer_description(), "5th party");
}