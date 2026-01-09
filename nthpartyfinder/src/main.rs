use clap::Parser;
use anyhow::Result;
use ctrlc;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::io;
use std::path::Path;
use tokio::sync::{Mutex, Semaphore};

mod cli;
mod config;
mod discovery;
mod dns;
mod whois;
mod export;
mod vendor;
mod domain_utils;
mod verification_logger;
mod subprocessor;
mod logger;

use cli::Args;
use config::{AppConfig, AnalysisConfig, AnalysisStrategy};
use vendor::{VendorRelationship, RecordType};
use logger::{AnalysisLogger, VerbosityLevel};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle --init flag first (before any other processing)
    if args.init {
        match AppConfig::create_default_config() {
            Ok(path) => {
                println!("✅ Created default configuration file at: {}", path.display());
                println!("   Edit this file to customize settings, then run nthpartyfinder again.");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("❌ Failed to create configuration file: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Load configuration
    let _app_config = match AppConfig::load() {
        Ok(cfg) => cfg,
        Err(config::ConfigError::FileNotFound(path)) => {
            // Config not found - prompt to create if interactive
            match AppConfig::prompt_create_config() {
                Ok(Some(created_path)) => {
                    println!("✅ Created default configuration file at: {}", created_path.display());
                    println!("   Edit this file to customize settings, then run nthpartyfinder again.");
                    std::process::exit(0);
                }
                Ok(None) => {
                    eprintln!("❌ Configuration file not found at: {}", path.display());
                    eprintln!("   Run with --init to create a default configuration file.");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("❌ Failed to create configuration file: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize new logging system
    let verbosity = VerbosityLevel::from_verbose_count(args.verbose);
    let logger = Arc::new(match &args.log_file {
        Some(log_file_path) => AnalysisLogger::with_log_file(verbosity, log_file_path.clone()),
        None => AnalysisLogger::new(verbosity),
    });

    // Set up Ctrl-C handler for clean exit
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\n⚠️  Received interrupt signal, cleaning up...");
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    // Validate arguments
    if let Err(e) = args.validate() {
        logger.error(&format!("Invalid arguments: {}", e));
        std::process::exit(1);
    }

    // Get domain (required at this point since --init was not used)
    let domain = args.domain.as_ref().expect("Domain is required when not using --init");
    
    // Get domain-specific output directory
    let output_dir = match args.get_domain_output_dir() {
        Ok(dir) => dir,
        Err(e) => {
            logger.error(&format!("Failed to determine output directory: {}", e));
            std::process::exit(1);
        }
    };

    // Create the directory structure if it doesn't exist
    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        logger.error(&format!("Failed to create output directory '{}': {}", output_dir, e));
        std::process::exit(1);
    }
    
    let output_filename = if args.output.contains('.') {
        args.output.clone()
    } else if args.output == "nth_parties" {
        match args.output_format.as_str() {
            "html" => format!("Nth Party Analysis for {}.html", domain),
            "json" => format!("Nth Party Analysis for {}.json", domain),
            "markdown" => format!("Nth Party Analysis for {}.md", domain),
            "csv" | _ => format!("Nth Party Analysis for {}.csv", domain),
        }
    } else {
        format!("{}.{}", args.output, args.output_format)
    };
    let output_path = Path::new(&output_dir).join(&output_filename);
    let output_path_str = output_path.to_string_lossy();

    // Prompt user for directory confirmation (no progress bar during user input)
    println!("📁 Output file will be saved to: {}", output_path_str);
    print!("Press Enter to continue or type a different directory path: ");
    io::Write::flush(&mut io::stdout()).unwrap();

    let mut user_input = String::new();
    io::stdin().read_line(&mut user_input).unwrap();
    let user_input = user_input.trim();

    let final_output_path = if user_input.is_empty() {
        output_path_str.to_string()
    } else {
        let custom_path = Path::new(user_input).join(&output_filename);
        custom_path.to_string_lossy().to_string()
    };

    println!("✅ Results will be saved to: {}", final_output_path);

    logger.log_initialization(domain);

    // Initialize verification failure logger if enabled
    let verification_logger = verification_logger::VerificationFailureLogger::new(
        &output_dir,
        domain,
        args.log_verification_failures
    );
    
    if args.log_verification_failures {
        if let Err(e) = verification_logger.initialize() {
            logger.warn(&format!("Failed to initialize verification failure logger: {}", e));
        } else {
            logger.debug(&format!("Verification failure logging enabled: {}", verification_logger.get_file_path()));
        }
    }
    
    let mut discovered_vendors = HashMap::new();

    // Get initial organization for the root domain
    if let Ok(root_org) = whois::get_organization(domain).await {
        discovered_vendors.insert(domain.clone(), root_org);
        logger.log_whois_lookup(domain, true);
    } else {
        logger.log_whois_lookup(domain, false);
    }

    let root_customer_domain = domain.clone();
    let root_customer_org = discovered_vendors.get(domain)
        .unwrap_or(domain)
        .clone();
    
    let discovered_vendors = Arc::new(Mutex::new(discovered_vendors));
    let processed_domains = Arc::new(Mutex::new(HashSet::new()));
    let semaphore = Arc::new(Semaphore::new(args.parallel_jobs));
    
    // Create shared DNS server pool from configuration
    let dns_pool = Arc::new(dns::DnsServerPool::from_config(&_app_config));
    logger.debug(&format!("Initialized DNS server pool with {} DoH servers and {} DNS servers",
        _app_config.dns.doh_servers.len(), _app_config.dns.dns_servers.len()));
    
    // Create shared SubprocessorAnalyzer with persistent cache
    let subprocessor_analyzer = if args.enable_subprocessor_analysis {
        Some(Arc::new(subprocessor::SubprocessorAnalyzer::new().await))
    } else {
        None
    };
    if subprocessor_analyzer.is_some() {
        logger.debug("Initialized subprocessor analyzer with persistent cache");
    }
    
    // Configure concurrency based on analysis config
    // For recursive processing, use depth-1 concurrency as initial limit (CLI --parallel-jobs can override)
    let recursive_limit = _app_config.analysis.get_concurrency_for_depth(1).min(args.parallel_jobs);
    let recursive_semaphore = Arc::new(Semaphore::new(recursive_limit));
    logger.debug(&format!("Configured concurrency: {} main jobs, {} initial recursive jobs (strategy: {:?})",
                          args.parallel_jobs, recursive_limit, _app_config.analysis.strategy));
    logger.debug(&format!("Concurrency per depth: {:?}, request delay: {}ms",
                          _app_config.analysis.concurrency_per_depth, _app_config.analysis.request_delay_ms));
    
    let results = discover_nth_parties(
        domain,
        args.depth,
        discovered_vendors.clone(),
        processed_domains.clone(),
        semaphore.clone(),
        1,
        &root_customer_domain,
        &root_customer_org,
        &verification_logger,
        dns_pool.clone(),
        recursive_semaphore.clone(),
        &args,
        logger.clone(),
        subprocessor_analyzer.as_ref(),
        &_app_config.analysis,
    ).await?;
    
    let unique_vendors = results.iter()
        .map(|r| &r.nth_party_organization)
        .collect::<HashSet<_>>()
        .len();
    
    logger.record_vendor_relationships(results.len());
    logger.record_unique_vendors(unique_vendors);
    
    logger.log_export_start(&args.output_format);
    
    // Export results
    match args.output_format.as_str() {
        "json" => export::export_json(&results, &final_output_path)?,
        "markdown" => export::export_markdown(&results, &final_output_path)?,
        "html" => export::export_html(&results, &final_output_path)?,
        "csv" | _ => export::export_csv(&results, &final_output_path)?,
    }
    
    logger.log_export_success(&final_output_path);

    // Prompt user to confirm any pending org-to-domain mappings discovered via generic fallback
    if let Some(analyzer) = &subprocessor_analyzer {
        let pending = analyzer.get_pending_mappings().await;
        if !pending.is_empty() {
            confirm_pending_mappings(&pending, analyzer, &logger).await?;
        }
    }

    // Close verification logger if it was enabled
    if args.log_verification_failures {
        verification_logger.close();
        logger.debug(&format!("Verification failure log closed: {}", verification_logger.get_file_path()));
    }

    // Print final comprehensive summary
    logger.print_final_summary();

    // Export logs to file if enabled
    if logger.is_log_export_enabled() {
        match logger.export_logs() {
            Ok(()) => {
                if let Some(ref log_file) = args.log_file {
                    println!("📄 Execution logs exported to: {}", log_file);
                    println!("   Total log entries: {}", logger.get_log_count());
                }
            }
            Err(e) => {
                eprintln!("⚠️ Warning: Failed to export logs: {}", e);
            }
        }
    }

    Ok(())
}

async fn subprocessor_analysis_with_logging(
    domain: &str,
    verification_logger: &verification_logger::VerificationFailureLogger,
    logger: Arc<AnalysisLogger>,
    analyzer: &subprocessor::SubprocessorAnalyzer,
) -> Result<Vec<subprocessor::SubprocessorDomain>> {
    logger.debug(&format!("🌐 Starting subprocessor analysis for domain: {}", domain));
    let start_time = std::time::Instant::now();
    
    // Use the cached analyzer which handles URL caching, organization caching, and early termination
    match analyzer.analyze_domain_with_logging(domain, Some(verification_logger), Some(&logger)).await {
        Ok(subprocessors) => {
            let elapsed = start_time.elapsed();
            if !subprocessors.is_empty() {
                logger.debug(&format!("✅ Subprocessor analysis for {} found {} unique vendors in {:.2}s: {:?}", 
                    domain, subprocessors.len(), elapsed.as_secs_f64(),
                    subprocessors.iter().map(|s| &s.domain).collect::<Vec<_>>()));
            } else {
                logger.debug(&format!("✅ Subprocessor analysis for {} completed in {:.2}s (no vendors found)", domain, elapsed.as_secs_f64()));
            }
            Ok(subprocessors)
        }
        Err(e) => {
            let elapsed = start_time.elapsed();
            logger.debug(&format!("❌ Subprocessor analysis failed for {} in {:.2}s: {}", domain, elapsed.as_secs_f64(), e));
            Ok(Vec::new()) // Return empty vec instead of failing the entire analysis
        }
    }
}

async fn discover_nth_parties(
    domain: &str,
    max_depth: Option<u32>,
    discovered_vendors: Arc<Mutex<HashMap<String, String>>>,
    processed_domains: Arc<Mutex<HashSet<String>>>,
    semaphore: Arc<Semaphore>,
    current_depth: u32,
    root_customer_domain: &str,
    root_customer_organization: &str,
    verification_logger: &verification_logger::VerificationFailureLogger,
    dns_pool: Arc<dns::DnsServerPool>,
    recursive_semaphore: Arc<Semaphore>,
    args: &Args,
    logger: Arc<AnalysisLogger>,
    subprocessor_analyzer: Option<&Arc<subprocessor::SubprocessorAnalyzer>>,
    analysis_config: &AnalysisConfig,
) -> Result<Vec<VendorRelationship>> {
    // Check if we've already processed this domain
    {
        let processed = processed_domains.lock().await;
        if processed.contains(domain) {
            logger.debug(&format!("Domain {} already processed, skipping", domain));
            return Ok(vec![]);
        }
    }
    
    // Check if we've exceeded max depth
    if let Some(max) = max_depth {
        if current_depth > max {
            logger.debug(&format!("Reached max depth {} for domain {}", max, domain));
            return Ok(vec![]);
        }
    }
    
    {
        let mut processed = processed_domains.lock().await;
        processed.insert(domain.to_string());
    }
    
    logger.record_domain_processed();
    logger.record_depth_reached(current_depth);
    logger.debug(&format!("Analyzing domain: {} at depth {}", domain, current_depth));
    
    let mut results = Vec::new();
    
    // Analyze DNS TXT records using the DNS server pool
    logger.log_dns_lookup_start(domain);
    
    match dns::get_txt_records_with_pool(domain, &dns_pool).await {
        Ok(txt_records) => {
            if !txt_records.is_empty() {
                logger.log_dns_lookup_success(domain, "DoH/DNS", txt_records.len());
                logger.debug(&format!("Raw TXT records for {}: {:?}", domain, txt_records));
            } else {
                logger.log_dns_lookup_success(domain, "DoH/DNS", 0);
            }
            
            let vendor_domains_with_source = dns::extract_vendor_domains_with_source_and_logger(&txt_records, Some(verification_logger), domain);
            
            // Also include base domain if we're analyzing a subdomain
            let current_base_domain = domain_utils::extract_base_domain(domain);
            let mut all_vendor_domains = vendor_domains_with_source;
            if current_base_domain != domain {
                all_vendor_domains.push(dns::VendorDomain {
                    domain: current_base_domain.clone(),
                    source_type: RecordType::DnsSubdomain,
                    raw_record: format!("Subdomain analysis: {} -> {}", domain, current_base_domain),
                });
                logger.debug(&format!("Added base domain {} for subdomain analysis of {}", current_base_domain, domain));
            }
            
            // Subprocessor web page analysis (if enabled)
            if args.enable_subprocessor_analysis && subprocessor_analyzer.is_some() {
                logger.debug(&format!("Starting subprocessor web page analysis for {}", domain));
                
                match subprocessor_analysis_with_logging(domain, verification_logger, logger.clone(), subprocessor_analyzer.unwrap()).await {
                    Ok(subprocessor_domains) => {
                        if !subprocessor_domains.is_empty() {
                            logger.log_subprocessor_analysis(domain, subprocessor_domains.len());
                            logger.debug(&format!("Subprocessor domains discovered: {:?}", 
                                subprocessor_domains.iter().map(|d| &d.domain).collect::<Vec<_>>()));
                            
                            let converted_domains: Vec<dns::VendorDomain> = subprocessor_domains.into_iter()
                                .map(|sub_domain| {
                                    logger.debug(&format!("Converting subprocessor domain: {} ({})", 
                                        sub_domain.domain, sub_domain.source_type));
                                    dns::VendorDomain {
                                        domain: sub_domain.domain,
                                        source_type: sub_domain.source_type,
                                        raw_record: sub_domain.raw_record,
                                    }
                                })
                                .collect();
                            all_vendor_domains.extend(converted_domains);
                        } else {
                            logger.log_subprocessor_analysis(domain, 0);
                            logger.debug(&format!("Subprocessor analysis completed: No vendor domains found in any subprocessor pages"));
                        }
                    }
                    Err(e) => {
                        logger.warn(&format!("Subprocessor analysis failed for {}: {}", domain, e));
                        logger.debug(&format!("Subprocessor analysis error details: {:?}", e));
                    }
                }
            }
            
            // Initialize progress bar based on total work units found (only for root domain at depth 1)
            if current_depth == 1 {
                let total_work_units = all_vendor_domains.len() as u64;
                if total_work_units > 0 {
                    logger.start_progress(total_work_units).await;
                    logger.update_progress(&format!("🔍 Analyzing {} vendor domains...", total_work_units)).await;
                } else {
                    logger.start_progress(1).await;
                    logger.update_progress("🔍 No vendor domains found to analyze").await;
                    logger.advance_progress(1).await;
                    logger.finish_progress("Analysis completed").await;
                }
            }
            
            // Resource management based on configured strategy
            match analysis_config.strategy {
                AnalysisStrategy::Unlimited => {
                    // No vendor limiting - process all vendors (resource control via concurrency/rate limiting)
                    logger.debug(&format!("Strategy 'unlimited': processing all {} vendors at depth {}",
                                         all_vendor_domains.len(), current_depth));
                }
                AnalysisStrategy::Limits => {
                    // Apply per-depth vendor limits from configuration
                    if let Some(max_vendors) = analysis_config.get_vendor_limit_for_depth(current_depth as usize) {
                        if all_vendor_domains.len() > max_vendors {
                            logger.info(&format!("Strategy 'limits': limiting vendor processing at depth {} from {} to {} vendors",
                                               current_depth, all_vendor_domains.len(), max_vendors));
                            all_vendor_domains.truncate(max_vendors);
                        }
                    }
                }
                AnalysisStrategy::Budget => {
                    // Budget strategy uses a global counter (tracked elsewhere)
                    // Here we just log that we're using budget mode
                    logger.debug(&format!("Strategy 'budget': processing vendors at depth {} (budget tracking enabled)", current_depth));
                }
            }
            
            let vendor_count = all_vendor_domains.len();
            logger.log_vendor_discovery(domain, vendor_count);
            
            if vendor_count > 0 {
                logger.log_parallel_processing_start(vendor_count, current_depth);
                
                // Process vendor domains with controlled concurrency using stream
                use futures::{stream, StreamExt};
                
                let request_delay_ms = analysis_config.request_delay_ms;
                let analysis_config_clone = analysis_config.clone();
                let vendor_stream = stream::iter(all_vendor_domains.into_iter().enumerate().map(|(index, vendor_domain_info)| {
                    let discovered_vendors = discovered_vendors.clone();
                    let processed_domains = processed_domains.clone();
                    let semaphore = semaphore.clone();
                    let recursive_semaphore = recursive_semaphore.clone();
                    let domain = domain.to_string();
                    let root_customer_domain = root_customer_domain.to_string();
                    let root_customer_organization = root_customer_organization.to_string();
                    let dns_pool = dns_pool.clone();
                    let args_ref = args;
                    let logger_clone = logger.clone();
                    let vendor_domain_clone = vendor_domain_info.domain.clone();
                    let total_vendors = vendor_count;
                    let analysis_config_inner = analysis_config_clone.clone();

                    async move {
                        // Apply rate limiting delay if configured (helps prevent server/resource overwhelming)
                        if request_delay_ms > 0 && index > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(request_delay_ms)).await;
                        }

                        let start_time = std::time::Instant::now();
                        logger_clone.debug(&format!("🔍 Starting analysis for vendor {}/{}: {} (depth {}, source: {:?})", 
                            index + 1, total_vendors, vendor_domain_clone, current_depth, vendor_domain_info.source_type));
                        
                        let result = process_vendor_domain(
                            vendor_domain_info.domain,
                            vendor_domain_info.source_type,
                            domain,
                            current_depth,
                            max_depth,
                            discovered_vendors,
                            processed_domains,
                            semaphore.clone(),
                            root_customer_domain,
                            root_customer_organization,
                            verification_logger,
                            dns_pool,
                            recursive_semaphore,
                            vendor_domain_info.raw_record,
                            args_ref,
                            logger_clone.clone(),
                            subprocessor_analyzer,
                            &analysis_config_inner,
                        ).await;
                        
                        let elapsed = start_time.elapsed();
                        logger_clone.debug(&format!("✅ Completed analysis for vendor {}/{}: {} in {:.2}s (found {} relationships)", 
                            index + 1, total_vendors, vendor_domain_clone, elapsed.as_secs_f64(), result.len()));
                        
                        // Advance progress for root-level analysis only
                        if current_depth == 1 {
                            logger_clone.advance_progress(1).await;
                        }

                        result
                    }
                }));
                
                // Configure buffer size based on analysis config concurrency settings
                let configured_concurrency = analysis_config.get_concurrency_for_depth(current_depth as usize);
                let buffer_size = configured_concurrency.min(args.parallel_jobs).max(2);
                
                // Process all vendors without timeout restrictions
                let mut vendor_results: Vec<Vec<VendorRelationship>> = Vec::new();
                let mut vendor_stream = vendor_stream.buffer_unordered(buffer_size);
                
                logger.debug(&format!("Starting parallel processing for {} vendors at depth {} (no timeout limit)", vendor_count, current_depth));
                
                // Process all vendors to completion without timeout
                let mut processed_count = 0;
                while let Some(result) = vendor_stream.next().await {
                    processed_count += 1;
                    vendor_results.push(result);
                    if processed_count % 5 == 0 || processed_count == vendor_count {
                        logger.debug(&format!("📊 Progress: {}/{} vendors processed", processed_count, vendor_count));
                    }
                }
                
                logger.debug(&format!("All {} vendor domains processed successfully at depth {}", vendor_results.len(), current_depth));
                
                // Collect results from parallel processing
                let mut total_relationships = 0;
                for vendor_result in vendor_results {
                    total_relationships += vendor_result.len();
                    results.extend(vendor_result);
                }

                logger.log_parallel_processing_complete(total_relationships);
                
                // Finish progress bar for root-level analysis
                if current_depth == 1 {
                    logger.finish_progress("Vendor analysis completed").await;
                }
            }
        },
        Err(e) => {
            logger.log_dns_lookup_failed(domain, &e.to_string());
            
            // Finish progress bar even if DNS lookup failed (for root-level analysis)
            if current_depth == 1 {
                logger.finish_progress("Analysis completed with DNS errors").await;
            }
        }
    }
    
    Ok(results)
}

async fn process_vendor_domain(
    vendor_domain: String,
    source_type: RecordType,
    customer_domain: String,
    current_depth: u32,
    max_depth: Option<u32>,
    discovered_vendors: Arc<Mutex<HashMap<String, String>>>,
    processed_domains: Arc<Mutex<HashSet<String>>>,
    semaphore: Arc<Semaphore>,
    root_customer_domain: String,
    root_customer_organization: String,
    verification_logger: &verification_logger::VerificationFailureLogger,
    dns_pool: Arc<dns::DnsServerPool>,
    recursive_semaphore: Arc<Semaphore>,
    raw_record: String,
    args: &Args,
    logger: Arc<AnalysisLogger>,
    subprocessor_analyzer: Option<&Arc<subprocessor::SubprocessorAnalyzer>>,
    analysis_config: &AnalysisConfig,
) -> Vec<VendorRelationship> {
    let mut results = Vec::new();
    
    // Extract base domain for organization identification
    let base_domain = domain_utils::extract_base_domain(&vendor_domain);
    let customer_base_domain = domain_utils::extract_base_domain(&customer_domain);
    
    // Skip self-references (same organization)
    if base_domain == customer_base_domain {
        logger.debug(&format!("Skipping self-reference: {} -> {}", customer_domain, base_domain));
        return results;
    }
    
    // Get organization info via WHOIS if not already cached
    {
        let vendors = discovered_vendors.lock().await;
        if !vendors.contains_key(&base_domain) {
            drop(vendors);
            match whois::get_organization(&base_domain).await {
                Ok(org_name) => {
                    let mut vendors = discovered_vendors.lock().await;
                    vendors.insert(base_domain.clone(), org_name);
                    logger.log_whois_lookup(&base_domain, true);
                },
                Err(e) => {
                    logger.debug(&format!("Failed to get organization for {}: {}", base_domain, e));
                    let mut vendors = discovered_vendors.lock().await;
                    vendors.insert(base_domain.clone(), base_domain.clone());
                    logger.log_whois_lookup(&base_domain, false);
                }
            }
        }
    }
    
    // Ensure we have organization info for the customer domain
    {
        let vendors = discovered_vendors.lock().await;
        if !vendors.contains_key(&customer_base_domain) {
            drop(vendors);
            match whois::get_organization(&customer_base_domain).await {
                Ok(org_name) => {
                    let mut vendors = discovered_vendors.lock().await;
                    vendors.insert(customer_base_domain.clone(), org_name);
                    logger.log_whois_lookup(&customer_base_domain, true);
                },
                Err(e) => {
                    logger.debug(&format!("Failed to get organization for customer {}: {}", customer_base_domain, e));
                    let mut vendors = discovered_vendors.lock().await;
                    vendors.insert(customer_base_domain.clone(), customer_base_domain.clone());
                    logger.log_whois_lookup(&customer_base_domain, false);
                }
            }
        }
    }
    
    // Create vendor relationship record using proper organization names
    let (customer_org, vendor_org) = {
        let vendors = discovered_vendors.lock().await;
        let customer_org = vendors.get(&customer_base_domain)
            .unwrap_or(&customer_base_domain.to_string())
            .clone();
        let vendor_org = vendors.get(&base_domain)
            .unwrap_or(&base_domain)
            .clone();
        (customer_org, vendor_org)
    };
    
    // Determine record value based on source
    let record_value = if source_type == RecordType::DnsSubdomain {
        format!("{} (base of {})", base_domain, customer_domain)
    } else {
        vendor_domain.clone()
    };
    
    let relationship = VendorRelationship::new(
        base_domain.clone(),
        vendor_org.clone(),
        current_depth,
        customer_base_domain.clone(),
        customer_org.clone(),
        record_value.clone(),
        source_type.clone(),
        root_customer_domain.clone(),
        root_customer_organization.clone(),
        raw_record.clone(),
    );
    
    logger.debug(&format!("Established {} relationship: {} ({}) -> {} ({})", 
                          relationship.layer_description(),
                          customer_base_domain, customer_org,
                          base_domain, vendor_org));
    
    results.push(relationship);
    
    // Check for termination condition (common denominators)
    if max_depth.is_none() && is_common_denominator(&base_domain) {
        logger.debug(&format!("Reached common denominator: {}", base_domain));
        return results;
    }
    
    // Normalize domain for DNS lookup
    let lookup_domain = domain_utils::normalize_for_dns_lookup(&vendor_domain);
    
    // Recursive analysis for deeper levels
    match discover_nth_parties(
        &lookup_domain,
        max_depth,
        discovered_vendors.clone(),
        processed_domains.clone(),
        semaphore.clone(),
        current_depth + 1,
        &root_customer_domain,
        &root_customer_organization,
        verification_logger,
        dns_pool,
        recursive_semaphore.clone(),
        args,
        logger.clone(),
        subprocessor_analyzer,
        analysis_config,
    ).await {
        Ok(sub_results) => {
            results.extend(sub_results);
        },
        Err(e) => {
            logger.warn(&format!("Failed to analyze vendor domain {}: {}", lookup_domain, e));
        }
    }

    results
}

fn is_common_denominator(domain: &str) -> bool {
    let common_denominators = vec![
        "amazon.com",
        "amazonaws.com",
        "microsoft.com",
        "google.com",
        "cloudflare.com",
        "fastly.com",
        "akamai.com",
        "azure.com",
        "office365.com",
        "outlook.com",
        "googlemail.com",
        "gmail.com",
    ];
    
    common_denominators.iter().any(|&cd| {
        domain == cd || domain.ends_with(&format!(".{}", cd))
    })
}

/// Layer-by-layer processing approach for better resource management and deduplication
/// This processes all vendors at layer N before moving to layer N+1
async fn discover_nth_parties_by_layers(
    domain: &str,
    max_depth: Option<u32>,
    discovered_vendors: Arc<Mutex<HashMap<String, String>>>,
    processed_domains: Arc<Mutex<HashSet<String>>>,
    _semaphore: Arc<Semaphore>,
    root_customer_domain: &str,
    root_customer_organization: &str,
    verification_logger: &verification_logger::VerificationFailureLogger,
    dns_pool: Arc<dns::DnsServerPool>,
    args: &Args,
    logger: Arc<AnalysisLogger>,
    subprocessor_analyzer: Option<&Arc<subprocessor::SubprocessorAnalyzer>>,
) -> Result<Vec<VendorRelationship>> {
    let mut all_results = Vec::new();
    let mut current_layer_domains = vec![domain.to_string()];
    let global_processed_vendors = Arc::new(Mutex::new(HashSet::<String>::new())); // Track processed vendors globally
    
    // Process each layer sequentially
    for current_depth in 1..=max_depth.unwrap_or(1) {
        if current_layer_domains.is_empty() {
            logger.info(&format!("No more domains to process at depth {}, stopping", current_depth));
            break;
        }
        
        logger.info(&format!("🏗️  Processing Layer {} with {} domains", current_depth, current_layer_domains.len()));
        
        // Adjust concurrency based on depth
        let layer_concurrency = match current_depth {
            1 => args.parallel_jobs,
            2 => args.parallel_jobs.min(20),
            3 => args.parallel_jobs.min(10),
            _ => args.parallel_jobs.min(5)
        };
        
        let layer_semaphore = Arc::new(Semaphore::new(layer_concurrency));
        let mut layer_results = Vec::new();
        let mut next_layer_domains = Vec::new();
        
        logger.debug(&format!("Layer {} concurrency: {} jobs", current_depth, layer_concurrency));
        
        // Process all domains in this layer in parallel
        use futures::{stream, StreamExt};
        
        let domain_stream = stream::iter(current_layer_domains.into_iter().enumerate().map(|(index, layer_domain)| {
            let discovered_vendors = discovered_vendors.clone();
            let processed_domains = processed_domains.clone();
            let layer_semaphore = layer_semaphore.clone();
            let root_customer_domain = root_customer_domain.to_string();
            let root_customer_organization = root_customer_organization.to_string();
            let dns_pool = dns_pool.clone();
            let logger = logger.clone();
            let domain_clone = layer_domain.clone();
            let global_processed_vendors = global_processed_vendors.clone();
            
            async move {
                let _permit = layer_semaphore.acquire().await.unwrap();
                
                logger.debug(&format!("🔍 Layer {} - Processing domain {}: {}", current_depth, index + 1, domain_clone));
                
                // Check if we've already processed this vendor globally (deduplication)
                let base_domain = domain_utils::extract_base_domain(&domain_clone);
                {
                    let processed_vendors = global_processed_vendors.lock().await;
                    if processed_vendors.contains(&base_domain) {
                        logger.debug(&format!("⭕ Skipping {} - already processed in earlier layer", base_domain));
                        return (Vec::new(), Vec::new());
                    }
                }
                
                match discover_single_domain(
                    &domain_clone,
                    current_depth,
                    discovered_vendors,
                    processed_domains,
                    &root_customer_domain,
                    &root_customer_organization,
                    verification_logger,
                    dns_pool,
                    args,
                    logger.clone(),
                    subprocessor_analyzer,
                ).await {
                    Ok((domain_results, next_domains)) => {
                        logger.debug(&format!("✅ Layer {} - Domain {} produced {} results, {} next domains", 
                                            current_depth, domain_clone, domain_results.len(), next_domains.len()));
                        (domain_results, next_domains)
                    }
                    Err(e) => {
                        logger.warn(&format!("❌ Layer {} - Failed to process domain {}: {}", current_depth, domain_clone, e));
                        (Vec::new(), Vec::new())
                    }
                }
            }
        }));
        
        let buffer_size = layer_concurrency.min(10).max(3);
        let mut domain_stream = domain_stream.buffer_unordered(buffer_size);
        
        logger.info(&format!("⏳ Processing Layer {} (no timeout limit)", current_depth));
        
        // Process all domains in this layer to completion without timeout
        while let Some((domain_results, next_domains)) = domain_stream.next().await {
            // Track processed vendors for deduplication
            {
                let mut processed_vendors = global_processed_vendors.lock().await;
                for result in &domain_results {
                    processed_vendors.insert(result.nth_party_domain.clone());
                }
            }
            
            layer_results.extend(domain_results);
            next_layer_domains.extend(next_domains);
        }
        
        logger.info(&format!("✅ Layer {} completed successfully - {} results, {} domains for next layer", 
                           current_depth, layer_results.len(), next_layer_domains.len()));
        
        // Remove duplicates from next layer domains
        next_layer_domains.sort();
        next_layer_domains.dedup();
        
        // Filter out already processed domains
        {
            let processed_vendors = global_processed_vendors.lock().await;
            next_layer_domains.retain(|domain| {
                let base_domain = domain_utils::extract_base_domain(domain);
                !processed_vendors.contains(&base_domain)
            });
        }
        
        // Limit next layer domains to prevent exponential growth
        let max_next_domains = match current_depth {
            1 => next_layer_domains.len(),
            2 => next_layer_domains.len().min(50),
            3 => next_layer_domains.len().min(20),
            _ => next_layer_domains.len().min(10)
        };
        
        if next_layer_domains.len() > max_next_domains {
            logger.warn(&format!("🔒 Limiting next layer domains from {} to {} to prevent exponential growth", 
                               next_layer_domains.len(), max_next_domains));
            next_layer_domains.truncate(max_next_domains);
        }
        
        all_results.extend(layer_results);
        current_layer_domains = next_layer_domains;
        
        let processed_count = {
            let processed_vendors = global_processed_vendors.lock().await;
            processed_vendors.len()
        };
        logger.info(&format!("📊 Layer {} Summary: {} total results so far, {} vendors processed globally", 
                           current_depth, all_results.len(), processed_count));
    }
    
    logger.info(&format!("🏁 Layer-by-layer processing completed: {} total results across all layers", all_results.len()));
    Ok(all_results)
}

/// Process a single domain and return both results and next domains to process
async fn discover_single_domain(
    domain: &str,
    current_depth: u32,
    discovered_vendors: Arc<Mutex<HashMap<String, String>>>,
    processed_domains: Arc<Mutex<HashSet<String>>>,
    root_customer_domain: &str,
    root_customer_organization: &str,
    verification_logger: &verification_logger::VerificationFailureLogger,
    dns_pool: Arc<dns::DnsServerPool>,
    args: &Args,
    logger: Arc<AnalysisLogger>,
    subprocessor_analyzer: Option<&Arc<subprocessor::SubprocessorAnalyzer>>,
) -> Result<(Vec<VendorRelationship>, Vec<String>)> {
    // Check if we've already processed this domain
    {
        let processed = processed_domains.lock().await;
        if processed.contains(domain) {
            logger.debug(&format!("Domain {} already processed, skipping", domain));
            return Ok((vec![], vec![]));
        }
    }
    
    // Mark as processed
    {
        let mut processed = processed_domains.lock().await;
        processed.insert(domain.to_string());
    }
    
    logger.record_domain_processed();
    logger.record_depth_reached(current_depth);
    logger.debug(&format!("Analyzing domain: {} at depth {}", domain, current_depth));
    
    let mut results = Vec::new();
    let mut next_domains = Vec::new();
    
    // DNS TXT record analysis
    match dns::get_txt_records_with_pool(domain, &dns_pool).await {
        Ok(txt_records) => {
            if !txt_records.is_empty() {
                logger.log_dns_lookup_success(domain, "DoH/DNS", txt_records.len());
                logger.debug(&format!("Raw TXT records for {}: {:?}", domain, txt_records));
            }
            
            let vendor_domains_with_source = dns::extract_vendor_domains_with_source_and_logger(&txt_records, Some(verification_logger), domain);
            
            // Include base domain for subdomain analysis
            let current_base_domain = domain_utils::extract_base_domain(domain);
            let mut all_vendor_domains = vendor_domains_with_source;
            if current_base_domain != domain {
                all_vendor_domains.push(dns::VendorDomain {
                    domain: current_base_domain.clone(),
                    source_type: RecordType::DnsSubdomain,
                    raw_record: format!("Subdomain analysis: {} -> {}", domain, current_base_domain),
                });
            }
            
            // Subprocessor analysis (if enabled)
            if args.enable_subprocessor_analysis && subprocessor_analyzer.is_some() {
                match subprocessor_analysis_with_logging(domain, verification_logger, logger.clone(), subprocessor_analyzer.unwrap()).await {
                    Ok(subprocessor_domains) => {
                        let converted_domains: Vec<dns::VendorDomain> = subprocessor_domains.into_iter()
                            .map(|sub_domain| dns::VendorDomain {
                                domain: sub_domain.domain,
                                source_type: sub_domain.source_type,
                                raw_record: sub_domain.raw_record,
                            })
                            .collect();
                        all_vendor_domains.extend(converted_domains);
                    }
                    Err(e) => {
                        logger.warn(&format!("Subprocessor analysis failed for {}: {}", domain, e));
                    }
                }
            }
            
            // Process vendor domains and collect results and next domains
            for vendor_domain_info in all_vendor_domains {
                let base_domain = domain_utils::extract_base_domain(&vendor_domain_info.domain);
                let customer_base_domain = domain_utils::extract_base_domain(domain);
                
                // Skip self-references
                if base_domain == customer_base_domain {
                    continue;
                }
                
                // Get organization info
                if !{
                    let vendors = discovered_vendors.lock().await;
                    vendors.contains_key(&base_domain)
                } {
                    match whois::get_organization(&base_domain).await {
                        Ok(org_name) => {
                            let mut vendors = discovered_vendors.lock().await;
                            vendors.insert(base_domain.clone(), org_name);
                            logger.log_whois_lookup(&base_domain, true);
                        }
                        Err(_) => {
                            let mut vendors = discovered_vendors.lock().await;
                            vendors.insert(base_domain.clone(), base_domain.clone());
                            logger.log_whois_lookup(&base_domain, false);
                        }
                    }
                }
                
                // Create vendor relationship
                let (customer_org, vendor_org) = {
                    let vendors = discovered_vendors.lock().await;
                    let customer_org = vendors.get(&customer_base_domain).unwrap_or(&customer_base_domain.to_string()).clone();
                    let vendor_org = vendors.get(&base_domain).unwrap_or(&base_domain).clone();
                    (customer_org, vendor_org)
                };
                
                let record_value = if vendor_domain_info.source_type == RecordType::DnsSubdomain {
                    format!("{} (base of {})", base_domain, domain)
                } else {
                    vendor_domain_info.domain.clone()
                };
                
                let relationship = VendorRelationship::new(
                    base_domain.clone(),
                    vendor_org.clone(),
                    current_depth,
                    customer_base_domain.clone(),
                    customer_org.clone(),
                    record_value.clone(),
                    vendor_domain_info.source_type.clone(),
                    root_customer_domain.to_string(),
                    root_customer_organization.to_string(),
                    vendor_domain_info.raw_record.clone(),
                );
                
                results.push(relationship);
                
                // Add to next layer if not a common denominator and within depth limits
                if !is_common_denominator(&base_domain) {
                    let lookup_domain = domain_utils::normalize_for_dns_lookup(&vendor_domain_info.domain);
                    next_domains.push(lookup_domain);
                }
            }
        }
        Err(e) => {
            logger.log_dns_lookup_failed(domain, &e.to_string());
        }
    }
    
    Ok((results, next_domains))
}

/// Prompt the user to confirm pending org-to-domain mappings discovered via generic fallback
/// These are mappings that were inferred but not verified - user confirmation ensures accuracy
async fn confirm_pending_mappings(
    pending: &[subprocessor::PendingOrgMapping],
    analyzer: &subprocessor::SubprocessorAnalyzer,
    logger: &AnalysisLogger,
) -> Result<()> {
    use std::collections::HashMap;
    use std::io::Write;

    // Group pending mappings by source domain
    let mut grouped: HashMap<&str, Vec<&subprocessor::PendingOrgMapping>> = HashMap::new();
    for mapping in pending {
        grouped.entry(&mapping.source_domain).or_default().push(mapping);
    }

    // Deduplicate mappings per source domain (same org_name -> same domain)
    let mut unique_mappings: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();
    for (source, mappings) in &grouped {
        let mut seen: HashMap<&str, &str> = HashMap::new();
        for m in mappings {
            seen.entry(&m.org_name).or_insert(&m.inferred_domain);
        }
        unique_mappings.insert(source, seen.into_iter().collect());
    }

    let total_count: usize = unique_mappings.values().map(|v| v.len()).sum();
    if total_count == 0 {
        return Ok(());
    }

    println!();
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║         UNCONFIRMED ORG-TO-DOMAIN MAPPINGS DETECTED            ║");
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║ The following mappings were inferred via generic fallback.     ║");
    println!("║ Please review and confirm to improve future extraction.        ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    for (source_domain, mappings) in &unique_mappings {
        println!("📋 Source: {} ({} mapping{})", source_domain, mappings.len(), if mappings.len() == 1 { "" } else { "s" });
        println!("─────────────────────────────────────────────────────────────────");

        for (idx, (org_name, domain)) in mappings.iter().enumerate() {
            println!("  [{}] \"{}\" → {}", idx + 1, org_name, domain);
        }
        println!();
    }

    // Ask user what to do
    println!("Options:");
    println!("  [A] Accept ALL mappings and save to cache");
    println!("  [R] Review each mapping individually");
    println!("  [S] Skip - don't save any mappings (analysis results are already exported)");
    println!();
    print!("Your choice (A/R/S): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim().to_uppercase();

    match choice.as_str() {
        "A" => {
            // Accept all mappings
            for (source_domain, mappings) in &unique_mappings {
                let confirmed: Vec<(String, String)> = mappings
                    .iter()
                    .map(|(org, dom)| (org.to_string(), dom.to_string()))
                    .collect();

                if let Err(e) = analyzer.save_confirmed_mappings(source_domain, &confirmed).await {
                    logger.warn(&format!("Failed to save mappings for {}: {}", source_domain, e));
                } else {
                    println!("✅ Saved {} mapping{} for {}", confirmed.len(), if confirmed.len() == 1 { "" } else { "s" }, source_domain);
                }
            }
        }
        "R" => {
            // Review each mapping individually
            for (source_domain, mappings) in &unique_mappings {
                println!();
                println!("📋 Reviewing mappings for: {}", source_domain);
                println!("─────────────────────────────────────────────────────────────────");

                let mut confirmed: Vec<(String, String)> = Vec::new();

                for (org_name, inferred_domain) in mappings {
                    println!();
                    println!("  Organization: \"{}\"", org_name);
                    println!("  Inferred domain: {}", inferred_domain);
                    print!("  [Y] Accept  [N] Reject  [C] Custom domain: ");
                    io::stdout().flush()?;

                    let mut response = String::new();
                    io::stdin().read_line(&mut response)?;
                    let resp = response.trim().to_uppercase();

                    match resp.as_str() {
                        "Y" => {
                            confirmed.push((org_name.to_string(), inferred_domain.to_string()));
                            println!("    ✅ Accepted: \"{}\" → {}", org_name, inferred_domain);
                        }
                        "C" => {
                            print!("    Enter correct domain: ");
                            io::stdout().flush()?;
                            let mut custom = String::new();
                            io::stdin().read_line(&mut custom)?;
                            let custom_domain = custom.trim().to_lowercase();
                            if !custom_domain.is_empty() {
                                confirmed.push((org_name.to_string(), custom_domain.clone()));
                                println!("    ✅ Custom: \"{}\" → {}", org_name, custom_domain);
                            } else {
                                println!("    ⏭️  Skipped (empty input)");
                            }
                        }
                        _ => {
                            println!("    ⏭️  Rejected");
                        }
                    }
                }

                if !confirmed.is_empty() {
                    if let Err(e) = analyzer.save_confirmed_mappings(source_domain, &confirmed).await {
                        logger.warn(&format!("Failed to save mappings for {}: {}", source_domain, e));
                    } else {
                        println!();
                        println!("✅ Saved {} mapping{} for {}", confirmed.len(), if confirmed.len() == 1 { "" } else { "s" }, source_domain);
                    }
                }
            }
        }
        _ => {
            println!("⏭️  Skipped - no mappings saved");
            println!("   (Your analysis results have already been exported)");
        }
    }

    // Clear pending mappings
    analyzer.clear_pending_mappings().await;

    println!();
    Ok(())
}