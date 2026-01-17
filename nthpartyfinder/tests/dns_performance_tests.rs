use nthpartyfinder::dns;
use std::time::Instant;

#[test]
fn measure_regex_overhead_detailed() {
    // Test with varying record counts to establish performance baseline

    println!("\n=== Regex Compilation Performance Analysis ===\n");

    // Test 1: Small batch (100 records)
    let records_100: Vec<String> = vec!["v=spf1 include:_spf.google.com ~all".to_string(); 100];
    let start = Instant::now();
    for _ in 0..10 {
        let _ = dns::extract_vendor_domains_with_source_and_logger(&records_100, None, "test.com");
    }
    let duration_100 = start.elapsed();
    println!("100 records × 10 iterations (1,000 total):");
    println!("  Total time: {:?}", duration_100);
    println!("  Per record: {:?}", duration_100 / 1000);
    println!("  Per second: ~{} records\n", 1000 * 1000 / duration_100.as_millis().max(1));

    // Test 2: Medium batch (500 records)
    let records_500: Vec<String> = vec!["v=spf1 include:_spf.google.com ~all".to_string(); 500];
    let start = Instant::now();
    for _ in 0..5 {
        let _ = dns::extract_vendor_domains_with_source_and_logger(&records_500, None, "test.com");
    }
    let duration_500 = start.elapsed();
    println!("500 records × 5 iterations (2,500 total):");
    println!("  Total time: {:?}", duration_500);
    println!("  Per record: {:?}", duration_500 / 2500);
    println!("  Per second: ~{} records\n", 2500 * 1000 / duration_500.as_millis().max(1));

    // Test 3: Complex records (multiple patterns)
    let complex_records: Vec<String> = vec![
        "v=spf1 include:_spf.google.com include:mailgun.org redirect=_spf.sendgrid.net ~all".to_string();
        100
    ];
    let start = Instant::now();
    for _ in 0..10 {
        let _ = dns::extract_vendor_domains_with_source_and_logger(&complex_records, None, "test.com");
    }
    let duration_complex = start.elapsed();
    println!("100 complex records × 10 iterations (1,000 total):");
    println!("  Total time: {:?}", duration_complex);
    println!("  Per record: {:?}", duration_complex / 1000);
    println!("  Overhead vs simple: {:?}\n", duration_complex.saturating_sub(duration_100));

    // Test 4: Single record repeated extraction (measures pure regex overhead)
    let single_record = vec!["v=spf1 include:_spf.google.com ~all".to_string()];
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = dns::extract_vendor_domains_with_source_and_logger(&single_record, None, "test.com");
    }
    let duration_single = start.elapsed();
    println!("1 record × 1,000 iterations:");
    println!("  Total time: {:?}", duration_single);
    println!("  Per extraction: {:?}", duration_single / 1000);
    println!("  Estimated regex compilation overhead: ~{:?} per call\n", duration_single / 1000);

    // Performance expectations
    println!("=== Performance Expectations ===");
    println!("Current (with regex recompilation):");
    println!("  - Per record: ~{:?}", duration_100 / 1000);
    println!("  - Throughput: ~{} records/sec", 1000 * 1000 / duration_100.as_millis().max(1));
    println!("\nExpected after optimization (static regex):");
    println!("  - Per record: <100μs (100x improvement)");
    println!("  - Throughput: >10,000 records/sec");
    println!("\nOptimization Impact:");
    println!("  - Processing 100,000 records:");
    println!("    Current: ~{} seconds", (duration_100.as_secs() * 100));
    println!("    After fix: <10 seconds");
    println!("    Time saved: ~{} seconds per 100k records", (duration_100.as_secs() * 100).saturating_sub(10));
}

#[test]
fn measure_domain_validation_overhead() {
    // Measure is_valid_domain regex compilation overhead
    println!("\n=== Domain Validation Performance ===\n");

    let test_domains = vec![
        "google.com",
        "_spf.mailgun.org",
        "mail.server.example.com",
        "subdomain.with.many.parts.example.org",
        "a.b", // edge case
    ];

    let records: Vec<String> = test_domains.iter()
        .map(|d| format!("v=spf1 include:{} ~all", d))
        .collect();

    let start = Instant::now();
    for _ in 0..100 {
        let _ = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");
    }
    let duration = start.elapsed();

    println!("{} domains × 100 iterations ({} validations):", records.len(), records.len() * 100);
    println!("  Total time: {:?}", duration);
    println!("  Per validation: {:?}", duration / (records.len() as u32 * 100));
    println!("  Validations/sec: ~{}\n", (records.len() as u128 * 100 * 1000) / duration.as_millis().max(1));

    println!("Note: Each validation compiles a new regex (line 657)");
    println!("Expected improvement: 50-100x after using static regex");
}

#[test]
fn measure_spf_macro_stripping_overhead() {
    // Measure strip_spf_macros regex compilation overhead
    println!("\n=== SPF Macro Stripping Performance ===\n");

    let macro_domains = vec![
        "v=spf1 include:%{ir}.%{v}._spf.example.com ~all",
        "v=spf1 exists:%{i}.%{d2}.spf.has.pphosted.com ~all",
        "v=spf1 include:%{ir}.%{v}.%{d}.spf.example.org ~all",
    ];

    let records: Vec<String> = macro_domains.iter()
        .map(|s| s.to_string())
        .collect();

    let start = Instant::now();
    for _ in 0..100 {
        let _ = dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");
    }
    let duration = start.elapsed();

    println!("{} macro records × 100 iterations ({} total):", records.len(), records.len() * 100);
    println!("  Total time: {:?}", duration);
    println!("  Per record: {:?}", duration / (records.len() as u32 * 100));
    println!("  Records/sec: ~{}\n", (records.len() as u128 * 100 * 1000) / duration.as_millis().max(1));

    println!("Note: strip_spf_macros() compiles regex on every call (line 299)");
    println!("This is called for EVERY SPF include/redirect/a/mx/exists domain");
    println!("Expected improvement: 100x after using static regex");
}

#[test]
fn estimate_total_optimization_gain() {
    println!("\n=== Total Optimization Impact Estimate ===\n");

    // Simulate realistic workload: 1000 domains with mixed record types
    let mixed_records: Vec<String> = vec![
        "v=spf1 include:_spf.google.com include:mailgun.org ~all".to_string(),
        "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com".to_string(),
        "google-site-verification=abc123xyz".to_string(),
        "v=spf1 include:%{ir}.%{v}._spf.example.com ~all".to_string(),
    ].into_iter().cycle().take(1000).collect();

    let start = Instant::now();
    let domains = dns::extract_vendor_domains_with_source_and_logger(&mixed_records, None, "test.com");
    let duration = start.elapsed();

    println!("Realistic workload: 1,000 mixed DNS records");
    println!("  Time taken: {:?}", duration);
    println!("  Domains extracted: {}", domains.len());
    println!("  Per record: {:?}", duration / 1000);
    println!("  Throughput: ~{} records/sec\n", 1000 * 1000 / duration.as_millis().max(1));

    println!("Estimated regex compilations per record:");
    println!("  - is_valid_domain: 1-3 calls");
    println!("  - strip_spf_macros: 0-2 calls (for SPF)");
    println!("  - Pattern matching: 4-10 calls");
    println!("  - Total: ~5-15 regex compilations per record\n");

    println!("Expected after optimization:");
    println!("  - Time for 1,000 records: <100ms");
    println!("  - Speedup: ~{}x", (duration.as_millis() / 100).max(1));
    println!("  - Throughput: >10,000 records/sec\n");

    println!("Impact on real-world usage:");
    println!("  - Analyzing 10,000 domains: {}s → <10s", duration.as_secs() * 10);
    println!("  - Analyzing 100,000 domains: {}s → <100s", duration.as_secs() * 100);
    println!("  - CI/CD pipeline: From unusable to instant");
}
