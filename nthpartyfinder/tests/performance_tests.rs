use std::time::Instant;
use std::path::Path;

/// Benchmark vendor registry loading (filesystem-based, no network)
#[test]
fn bench_vendor_registry_loading() {
    println!("\n=== Vendor Registry Loading Performance ===\n");

    let config_dir = Path::new("config");
    if !config_dir.exists() {
        println!("SKIP: config/ directory not found (run from project root)");
        return;
    }

    // Warm up filesystem cache
    let _ = nthpartyfinder::vendor_registry::VendorRegistry::load_from_directory(config_dir);

    // Measure 5 runs
    let mut times = Vec::new();
    for i in 0..5 {
        let start = Instant::now();
        let registry = nthpartyfinder::vendor_registry::VendorRegistry::load_from_directory(config_dir)
            .expect("Failed to load vendor registry");
        let elapsed = start.elapsed();
        println!("  Run {}: {:?} ({} vendors, {} domains)",
            i + 1, elapsed, registry.vendor_count(), registry.domain_count());
        times.push(elapsed);
    }

    let avg = times.iter().sum::<std::time::Duration>() / times.len() as u32;
    println!("\n  Average: {:?}", avg);
    println!("  Target: <100ms");

    assert!(avg.as_millis() < 500, "Vendor registry loading took {:?} on average (target <500ms)", avg);
}

/// Benchmark DNS record extraction (CPU-bound, no network)
#[test]
fn bench_dns_extraction_throughput() {
    println!("\n=== DNS Record Extraction Throughput ===\n");

    // Realistic mix of records
    let records: Vec<String> = vec![
        "v=spf1 include:_spf.google.com include:mailgun.org redirect=_spf.sendgrid.net ~all".to_string(),
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com".to_string(),
        "google-site-verification=abc123".to_string(),
        "MS=ms12345678".to_string(),
        "v=spf1 include:spf.protection.outlook.com include:_spf.salesforce.com ~all".to_string(),
    ];

    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = nthpartyfinder::dns::extract_vendor_domains_with_source_and_logger(&records, None, "test.com");
    }
    let elapsed = start.elapsed();

    let total_records = records.len() * iterations;
    let per_record = elapsed / total_records as u32;
    let throughput = total_records as f64 / elapsed.as_secs_f64();

    println!("  {} records processed in {:?}", total_records, elapsed);
    println!("  Per record: {:?}", per_record);
    println!("  Throughput: {:.0} records/sec", throughput);

    // Debug builds are ~10x slower than release for CPU-bound regex work.
    // Use a conservative threshold that works in both modes.
    let is_debug = cfg!(debug_assertions);
    let threshold = if is_debug { 500.0 } else { 10000.0 };
    println!("  Target: >{:.0} records/sec ({})", threshold, if is_debug { "debug build" } else { "release build" });

    assert!(throughput > threshold,
        "DNS extraction throughput {:.0} records/sec is below {:.0} ({})",
        throughput, threshold, if is_debug { "debug" } else { "release" });
}
