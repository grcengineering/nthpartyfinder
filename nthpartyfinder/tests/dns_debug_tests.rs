use nthpartyfinder::dns;

#[test]
fn debug_case_insensitivity() {
    let records = vec![
        "V=SPF1 INCLUDE:_SPF.GOOGLE.COM ~ALL".to_string(),
        "v=DMARC1; P=QUARANTINE; RUA=MAILTO:DMARC@EXAMPLE.COM".to_string(),
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    println!("Case insensitivity test results:");
    println!("  Number of domains extracted: {}", domains.len());
    for (i, domain) in domains.iter().enumerate() {
        println!("  Domain {}: {} (type: {:?})", i+1, domain.domain, domain.source_type);
    }
}

#[test]
fn debug_invalid_domain_too_short() {
    let records = vec!["v=spf1 include:a.b ~all".to_string()];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    println!("Short domain test results:");
    println!("  Number of domains extracted: {}", domains.len());
    for (i, domain) in domains.iter().enumerate() {
        println!("  Domain {}: {} (type: {:?})", i+1, domain.domain, domain.source_type);
    }
}

#[test]
fn debug_dmarc_multiple_rua() {
    let records = vec![
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com,mailto:reports@vendor.com".to_string()
    ];
    let domains = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");

    println!("Multiple RUA test results:");
    println!("  Number of domains extracted: {}", domains.len());
    for (i, domain) in domains.iter().enumerate() {
        println!("  Domain {}: {} (type: {:?}, raw: {})", i+1, domain.domain, domain.source_type, domain.raw_record);
    }
}
