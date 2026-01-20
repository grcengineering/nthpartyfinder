use clap::Parser;
use anyhow::Result;
use ctrlc;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
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
mod vendor_registry;
mod known_vendors;
mod web_org;
mod ner_org;

use cli::Args;
use config::{AppConfig, AnalysisConfig, AnalysisStrategy};
use vendor::{VendorRelationship, RecordType};
use logger::{AnalysisLogger, VerbosityLevel};
use discovery::{SubfinderDiscovery, SaasTenantDiscovery, TenantStatus, InstallOption, CtLogDiscovery};
use std::path::PathBuf;

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

    // Initialize vendor registry (consolidated vendor JSON files)
    let vendor_registry_loaded = match vendor_registry::init() {
        Ok(()) => {
            if let Some(reg) = vendor_registry::get() {
                reg.vendor_count() > 0
            } else {
                false
            }
        }
        Err(_) => false,
    };

    // Initialize known vendors database for reliable org lookups
    // (now uses vendor_registry as primary source with JSON fallback)
    let known_vendors_loaded = match known_vendors::init() {
        Ok(()) => {
            if let Some(kv) = known_vendors::get() {
                let stats = kv.stats();
                stats.base_count > 0 || vendor_registry_loaded
            } else {
                vendor_registry_loaded
            }
        }
        Err(_) => vendor_registry_loaded,
    };

    // Initialize embedded NER for organization extraction (if feature enabled)
    let ner_enabled: bool;
    #[cfg(feature = "embedded-ner")]
    {
        ner_enabled = if !args.disable_slm {
            match ner_org::init_with_config(0.6) {
                Ok(()) => true,
                Err(_) => false,
            }
        } else {
            false
        };
    }

    #[cfg(not(feature = "embedded-ner"))]
    {
        ner_enabled = false;
    }

    // Determine feature enablement status for display
    // (actual initialization happens later, but we show status to user first)
    let web_org_will_be_enabled = args.enable_web_org
        || (!args.disable_web_org && _app_config.discovery.web_org_enabled);
    let subprocessor_will_be_enabled = args.enable_subprocessor_analysis
        || (!args.disable_subprocessor_analysis && _app_config.discovery.subprocessor_enabled);
    let subdomain_will_be_enabled = args.enable_subdomain_discovery
        || (!args.disable_subdomain_discovery && _app_config.discovery.subdomain_enabled);
    let saas_tenant_will_be_enabled = args.enable_saas_tenant_discovery
        || (!args.disable_saas_tenant_discovery && _app_config.discovery.saas_tenant_enabled);

    // Print consolidated initialization status block
    eprintln!();
    if vendor_registry_loaded {
        if let Some(reg) = vendor_registry::get() {
            eprintln!("✅ ENABLED: Vendor registry ({} vendors, {} domains)", reg.vendor_count(), reg.domain_count());
        }
    } else {
        eprintln!("⚠️  Vendor registry not loaded (using legacy known_vendors.json)");
    }
    if known_vendors_loaded {
        if let Some(kv) = known_vendors::get() {
            let stats = kv.stats();
            if vendor_registry_loaded {
                eprintln!("✅ ENABLED: Known vendors fallback ({} vendors in legacy JSON)", stats.base_count);
            } else {
                eprintln!("✅ ENABLED: Known vendors database ({} vendors)", stats.base_count);
            }
        }
    } else {
        eprintln!("❌ DISABLED: Known vendors database (will use WHOIS/domain inference)");
    }
    if ner_enabled {
        eprintln!("✅ ENABLED: NER-based organization name extraction (via embedded GLiNER model)");
    } else {
        #[cfg(feature = "embedded-ner")]
        {
            if args.disable_slm {
                eprintln!("❌ DISABLED: NER-based organization name extraction (via --disable-slm)");
            } else {
                eprintln!("❌ DISABLED: NER-based organization name extraction (initialization failed)");
            }
        }
        #[cfg(not(feature = "embedded-ner"))]
        {
            eprintln!("❌ DISABLED: NER-based organization name extraction (not compiled in)");
        }
    }
    if web_org_will_be_enabled {
        eprintln!("✅ ENABLED: Deterministic organization name extraction (via HTTP & headless browser)");
    } else {
        eprintln!("❌ DISABLED: Deterministic organization name extraction (via --disable-web-org)");
    }
    if subprocessor_will_be_enabled {
        eprintln!("✅ ENABLED: Subprocessor web page analysis");
    } else {
        eprintln!("❌ DISABLED: Subprocessor web page analysis");
    }
    if subdomain_will_be_enabled {
        eprintln!("✅ ENABLED: Subdomain discovery (via subfinder)");
    } else {
        eprintln!("❌ DISABLED: Subdomain discovery");
    }
    if saas_tenant_will_be_enabled {
        eprintln!("✅ ENABLED: SaaS tenant discovery");
    } else {
        eprintln!("❌ DISABLED: SaaS tenant discovery");
    }
    eprintln!();

    // Initialize new logging system
    let verbosity = VerbosityLevel::from_verbose_count(args.verbose);
    let logger = Arc::new(match &args.log_file {
        Some(log_file_path) => AnalysisLogger::with_log_file(verbosity, log_file_path.clone()),
        None => AnalysisLogger::new(verbosity),
    });

    // Set up Ctrl-C handler for clean exit
    ctrlc::set_handler(move || {
        eprintln!("\n⚠️  Received interrupt signal, exiting...");
        std::process::exit(130); // 130 = 128 + SIGINT(2), standard exit code for Ctrl-C
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

    // Determine web org extraction settings (headless browser fallback for org name extraction)
    // Must be set before any org lookups occur
    let web_org_enabled = web_org_will_be_enabled;
    let web_org_min_confidence = _app_config.discovery.web_org_min_confidence;

    let mut discovered_vendors = HashMap::new();
    let mut unverified_orgs: Vec<UnverifiedOrgMapping> = Vec::new();

    // Get initial organization for the root domain
    if let Ok(org_result) = whois::get_organization_with_status_and_config(domain, web_org_enabled, web_org_min_confidence).await {
        discovered_vendors.insert(domain.clone(), org_result.name.clone());
        logger.log_whois_lookup(domain, true);
        if !org_result.is_verified {
            unverified_orgs.push(UnverifiedOrgMapping {
                domain: domain.clone(),
                inferred_org: org_result.name,
            });
        }
    } else {
        logger.log_whois_lookup(domain, false);
    }

    let root_customer_domain = domain.clone();
    let root_customer_org = discovered_vendors.get(domain)
        .unwrap_or(domain)
        .clone();

    let discovered_vendors = Arc::new(Mutex::new(discovered_vendors));
    let unverified_orgs = Arc::new(Mutex::new(unverified_orgs));
    let processed_domains = Arc::new(Mutex::new(HashSet::new()));
    let semaphore = Arc::new(Semaphore::new(args.parallel_jobs));
    
    // Create shared DNS server pool from configuration
    let dns_pool = Arc::new(dns::DnsServerPool::from_config(&_app_config));
    logger.debug(&format!("Initialized DNS server pool with {} DoH servers and {} DNS servers",
        _app_config.dns.doh_servers.len(), _app_config.dns.dns_servers.len()));
    
    // Create shared SubprocessorAnalyzer with persistent cache
    let subprocessor_enabled = subprocessor_will_be_enabled;
    let subprocessor_analyzer = if subprocessor_enabled {
        Some(Arc::new(subprocessor::SubprocessorAnalyzer::new().await))
    } else {
        None
    };

    // Initialize discovery modules if enabled
    let subdomain_discovery = if args.enable_subdomain_discovery
        || (!args.disable_subdomain_discovery && _app_config.discovery.subdomain_enabled) {
        let path = args.subfinder_path.clone()
            .unwrap_or_else(|| _app_config.discovery.subfinder_path.clone());
        let mut discovery = SubfinderDiscovery::new(
            PathBuf::from(path.clone()),
            std::time::Duration::from_secs(_app_config.discovery.subfinder_timeout_secs),
        );
        if discovery.is_available() {
            Some(discovery)
        } else {
            // Subfinder not found - show interactive installation menu
            eprintln!();
            eprintln!("╔══════════════════════════════════════════════════════════════════╗");
            eprintln!("║           Subfinder Not Found                                    ║");
            eprintln!("╚══════════════════════════════════════════════════════════════════╝");
            eprintln!();
            eprintln!("Subfinder is required for subdomain discovery.");
            eprintln!("It's a subdomain enumeration tool by Project Discovery.");
            eprintln!();

            // Get available installation options for this platform
            let options = SubfinderDiscovery::get_available_install_options();

            eprintln!("Would you like to install subfinder now?");
            eprintln!();
            for (i, option) in options.iter().enumerate() {
                eprintln!("  [{}] {}", i + 1, option.display_name());
            }
            eprintln!();
            eprint!("Select option [1-{}]: ", options.len());

            let mut input = String::new();
            let selected_option = if io::stdin().read_line(&mut input).is_ok() {
                input.trim().parse::<usize>()
                    .ok()
                    .and_then(|n| if n >= 1 && n <= options.len() { Some(options[n - 1]) } else { None })
            } else {
                None
            };

            match selected_option {
                Some(InstallOption::AutoDownload) => {
                    eprintln!();
                    eprintln!("Downloading subfinder...");
                    match SubfinderDiscovery::download_and_install().await {
                        Ok(install_path) => {
                            logger.info(&format!("Subfinder installed to: {}", install_path.display()));
                            discovery = SubfinderDiscovery::new(
                                install_path,
                                std::time::Duration::from_secs(_app_config.discovery.subfinder_timeout_secs),
                            );
                            if discovery.is_available() {
                                Some(discovery)
                            } else {
                                logger.warn("Subfinder was downloaded but failed verification");
                                None
                            }
                        }
                        Err(e) => {
                            logger.warn(&format!("Failed to download subfinder: {}", e));
                            eprintln!("Download failed: {}", e);
                            eprintln!("You can try one of the other installation methods.");
                            None
                        }
                    }
                }
                Some(InstallOption::Skip) => {
                    None
                }
                Some(InstallOption::ManualDownload) => {
                    let url = SubfinderDiscovery::get_download_url();
                    eprintln!();
                    eprintln!("Opening download page: {}", url);
                    // Try to open the URL in the default browser
                    #[cfg(target_os = "windows")]
                    let _ = std::process::Command::new("cmd").args(["/C", "start", url]).spawn();
                    #[cfg(target_os = "macos")]
                    let _ = std::process::Command::new("open").arg(url).spawn();
                    #[cfg(target_os = "linux")]
                    let _ = std::process::Command::new("xdg-open").arg(url).spawn();

                    eprintln!("After installing, run nthpartyfinder again.");
                    None
                }
                Some(InstallOption::Go) => {
                    eprintln!();
                    eprintln!("Installing subfinder via 'go install'...");
                    match SubfinderDiscovery::install_via_go().await {
                        Ok(true) => {
                            logger.info("Subfinder installed successfully!");
                            // Re-check availability after installation
                            let subfinder_name = if cfg!(windows) { "subfinder.exe" } else { "subfinder" };
                            let go_bin = dirs::home_dir()
                                .map(|h| h.join("go").join("bin").join(subfinder_name))
                                .unwrap_or_else(|| PathBuf::from(subfinder_name));
                            discovery = SubfinderDiscovery::new(
                                go_bin,
                                std::time::Duration::from_secs(_app_config.discovery.subfinder_timeout_secs),
                            );
                            if discovery.is_available() {
                                Some(discovery)
                            } else {
                                logger.warn("Subfinder was installed but not found in PATH. You may need to add ~/go/bin to your PATH.");
                                None
                            }
                        }
                        Ok(false) => {
                            logger.warn("Failed to install subfinder");
                            None
                        }
                        Err(e) => {
                            logger.warn(&format!("Failed to install subfinder: {}", e));
                            None
                        }
                    }
                }
                Some(InstallOption::Docker) => {
                    eprintln!();
                    eprintln!("Pulling subfinder Docker image...");
                    match SubfinderDiscovery::install_via_docker().await {
                        Ok(true) => {
                            eprintln!();
                            eprintln!("Docker image pulled successfully!");
                            eprintln!();
                            eprintln!("Note: Docker-based subfinder requires running via docker command.");
                            eprintln!("nthpartyfinder cannot use Docker-based subfinder directly.");
                            eprintln!();
                            eprintln!("To use subfinder with Docker, run manually:");
                            eprintln!("  docker run -it projectdiscovery/subfinder:latest -d <domain>");
                            eprintln!();
                            eprintln!("For native integration, install subfinder via Go or download the binary.");
                            None
                        }
                        Ok(false) => {
                            logger.warn("Failed to pull subfinder Docker image");
                            None
                        }
                        Err(e) => {
                            logger.warn(&format!("Failed to pull subfinder Docker image: {}", e));
                            None
                        }
                    }
                }
                Some(InstallOption::Homebrew) => {
                    eprintln!();
                    eprintln!("Installing subfinder via Homebrew...");
                    match SubfinderDiscovery::install_via_homebrew().await {
                        Ok(true) => {
                            logger.info("Subfinder installed successfully via Homebrew!");
                            discovery = SubfinderDiscovery::new(
                                PathBuf::from("subfinder"),
                                std::time::Duration::from_secs(_app_config.discovery.subfinder_timeout_secs),
                            );
                            if discovery.is_available() {
                                Some(discovery)
                            } else {
                                logger.warn("Subfinder was installed but not found. You may need to restart your terminal.");
                                None
                            }
                        }
                        Ok(false) => {
                            logger.warn("Failed to install subfinder via Homebrew");
                            None
                        }
                        Err(e) => {
                            logger.warn(&format!("Failed to install subfinder via Homebrew: {}", e));
                            None
                        }
                    }
                }
                None => {
                    eprintln!("Invalid selection. Continuing without subdomain discovery.");
                    None
                }
            }
        }
    } else {
        None
    };

    let saas_tenant_discovery = if args.enable_saas_tenant_discovery
        || (!args.disable_saas_tenant_discovery && _app_config.discovery.saas_tenant_enabled) {
        let mut discovery = SaasTenantDiscovery::new(
            std::time::Duration::from_secs(_app_config.discovery.tenant_probe_timeout_secs),
            _app_config.discovery.tenant_probe_concurrency,
        );
        let platforms_path = Path::new("config/saas_platforms.json");
        if platforms_path.exists() {
            if let Err(e) = discovery.load_platforms(platforms_path) {
                logger.warn(&format!("Failed to load SaaS platforms: {}", e));
                None
            } else {
                Some(discovery)
            }
        } else {
            logger.warn("SaaS tenant discovery requested but platforms file not found");
            None
        }
    } else {
        None
    };

    // Set up CT log discovery
    let ct_discovery = if args.enable_ct_discovery
        || (!args.disable_ct_discovery && _app_config.discovery.ct_discovery_enabled) {
        Some(CtLogDiscovery::new(
            std::time::Duration::from_secs(_app_config.discovery.ct_timeout_secs),
        ))
    } else {
        None
    };

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
        subprocessor_enabled,
        web_org_enabled,
        web_org_min_confidence,
        &_app_config.analysis,
        subdomain_discovery.as_ref(),
        saas_tenant_discovery.as_ref(),
        ct_discovery.as_ref(),
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

    // Prompt user to confirm any organizations that were inferred from domain names
    // Also detect additional inferred orgs by checking for the " Inc." pattern
    {
        let vendors = discovered_vendors.lock().await;
        let mut all_unverified = unverified_orgs.lock().await.clone();

        // Detect additional inferred organizations by pattern matching
        for (domain, org) in vendors.iter() {
            // Skip domains that are in the known vendors database (they're verified)
            if known_vendors::lookup(domain).is_some() {
                continue;
            }
            // Check if org looks like it was inferred from domain (e.g., "Myklpages Inc." from myklpages.com)
            if is_likely_inferred_org(domain, org) {
                // Check if not already tracked
                if !all_unverified.iter().any(|u| u.domain == *domain) {
                    all_unverified.push(UnverifiedOrgMapping {
                        domain: domain.clone(),
                        inferred_org: org.clone(),
                    });
                }
            }
        }
        drop(vendors);

        if !all_unverified.is_empty() {
            confirm_unverified_organizations(&all_unverified, &discovered_vendors, &logger).await?;
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
    subprocessor_enabled: bool,
    web_org_enabled: bool,
    web_org_min_confidence: f32,
    analysis_config: &AnalysisConfig,
    subdomain_discovery: Option<&SubfinderDiscovery>,
    saas_tenant_discovery: Option<&SaasTenantDiscovery>,
    ct_discovery: Option<&CtLogDiscovery>,
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
            if subprocessor_enabled && subprocessor_analyzer.is_some() {
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

            // Run discovery methods at depth 1 only (for the root domain)
            if current_depth == 1 {
                // Subdomain discovery via subfinder
                if let Some(subfinder) = subdomain_discovery {
                    logger.info("Running subdomain discovery via subfinder...");
                    match subfinder.discover(domain).await {
                        Ok(subdomains) => {
                            if !subdomains.is_empty() {
                                logger.info(&format!("Subfinder found {} subdomains", subdomains.len()));

                                // Analyze TXT and CNAME records for each subdomain with concurrency limiting
                                let subdomain_concurrency = 10; // Limit concurrent DNS queries
                                let subdomain_chunks: Vec<_> = subdomains.chunks(subdomain_concurrency).collect();
                                let mut subdomain_txt_vendors_found = 0;
                                let mut subdomain_cname_vendors_found = 0;
                                let domain_base = domain_utils::extract_base_domain(domain);

                                for chunk in subdomain_chunks {
                                    let chunk_futures: Vec<_> = chunk.iter().map(|sub| {
                                        let subdomain = sub.subdomain.clone();
                                        let source = sub.source.clone();
                                        let dns_pool = dns_pool.clone();
                                        let domain_base = domain_base.clone();
                                        async move {
                                            let mut txt_vendors = Vec::new();
                                            let mut cname_vendors = Vec::new();

                                            // Query TXT records for this subdomain
                                            if let Ok(txt_records) = dns::get_txt_records_with_pool(&subdomain, &dns_pool).await {
                                                if !txt_records.is_empty() {
                                                    txt_vendors = dns::extract_vendor_domains_with_source(&txt_records);
                                                }
                                            }

                                            // Query CNAME records to find third-party infrastructure
                                            if let Ok(cname_records) = dns::get_cname_records_with_pool(&subdomain, &dns_pool).await {
                                                for cname in cname_records {
                                                    let cname_base = domain_utils::extract_base_domain(&cname);
                                                    // Only add if CNAME points to different infrastructure
                                                    if cname_base != domain_base {
                                                        cname_vendors.push((cname.clone(), cname_base));
                                                    }
                                                }
                                            }

                                            (subdomain, source, txt_vendors, cname_vendors)
                                        }
                                    }).collect();

                                    let chunk_results = futures::future::join_all(chunk_futures).await;

                                    for (subdomain, source, txt_vendors, cname_vendors) in chunk_results {
                                        // Add TXT-derived vendors
                                        for vd in txt_vendors {
                                            let vd_base = domain_utils::extract_base_domain(&vd.domain);
                                            if vd_base != domain_base {
                                                subdomain_txt_vendors_found += 1;
                                                all_vendor_domains.push(dns::VendorDomain {
                                                    domain: vd.domain,
                                                    source_type: vd.source_type,
                                                    raw_record: format!("Via subdomain {} (subfinder:{}): {}", subdomain, source, vd.raw_record),
                                                });
                                            }
                                        }

                                        // Add CNAME-derived vendors (third-party infrastructure)
                                        // Use SubfinderDiscovery type to indicate these were found via subfinder
                                        for (cname_target, cname_base) in cname_vendors {
                                            subdomain_cname_vendors_found += 1;
                                            all_vendor_domains.push(dns::VendorDomain {
                                                domain: cname_base,
                                                source_type: RecordType::SubfinderDiscovery,
                                                raw_record: format!("Subdomain {} CNAMEs to {} (subfinder:{})", subdomain, cname_target, source),
                                            });
                                        }
                                    }
                                }

                                if subdomain_txt_vendors_found > 0 || subdomain_cname_vendors_found > 0 {
                                    logger.info(&format!("Found {} vendors from subdomain TXT records, {} from CNAME infrastructure",
                                        subdomain_txt_vendors_found, subdomain_cname_vendors_found));
                                }
                            } else {
                                logger.debug("Subfinder found no subdomains");
                            }
                        }
                        Err(e) => {
                            logger.warn(&format!("Subdomain discovery failed: {}", e));
                        }
                    }
                }

                // SaaS tenant discovery
                if let Some(tenant_disc) = saas_tenant_discovery {
                    logger.info("Running SaaS tenant discovery...");
                    match tenant_disc.probe(domain).await {
                        Ok(tenants) => {
                            let confirmed_tenants: Vec<_> = tenants.iter()
                                .filter(|t| matches!(t.status, TenantStatus::Confirmed | TenantStatus::Likely))
                                .collect();
                            if !confirmed_tenants.is_empty() {
                                logger.info(&format!("Found {} likely/confirmed SaaS tenants", confirmed_tenants.len()));
                                for tenant in confirmed_tenants {
                                    all_vendor_domains.push(dns::VendorDomain {
                                        domain: tenant.vendor_domain.clone(),
                                        source_type: RecordType::SaasTenantProbe,
                                        raw_record: format!("Tenant URL: {} ({:?})", tenant.tenant_url, tenant.status),
                                    });
                                }
                            } else {
                                logger.debug("No SaaS tenants discovered");
                            }
                        }
                        Err(e) => {
                            logger.warn(&format!("SaaS tenant discovery failed: {}", e));
                        }
                    }
                }

                // Certificate Transparency log discovery
                if let Some(ct_disc) = ct_discovery {
                    logger.info("Running Certificate Transparency log discovery...");
                    match ct_disc.discover(domain).await {
                        Ok(ct_results) => {
                            if !ct_results.is_empty() {
                                logger.info(&format!("Found {} vendors from CT logs", ct_results.len()));
                                for result in ct_results {
                                    all_vendor_domains.push(dns::VendorDomain {
                                        domain: result.domain,
                                        source_type: RecordType::CtLogDiscovery,
                                        raw_record: result.certificate_info,
                                    });
                                }
                            } else {
                                logger.debug("No vendors discovered from CT logs");
                            }
                        }
                        Err(e) => {
                            logger.warn(&format!("CT log discovery failed: {}", e));
                        }
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
                            subprocessor_enabled,
                            web_org_enabled,
                            web_org_min_confidence,
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
    subprocessor_enabled: bool,
    web_org_enabled: bool,
    web_org_min_confidence: f32,
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
            match whois::get_organization_with_status_and_config(&base_domain, web_org_enabled, web_org_min_confidence).await {
                Ok(org_result) => {
                    let mut vendors = discovered_vendors.lock().await;
                    vendors.insert(base_domain.clone(), org_result.name);
                    logger.log_whois_lookup(&base_domain, org_result.is_verified);
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
            match whois::get_organization_with_status_and_config(&customer_base_domain, web_org_enabled, web_org_min_confidence).await {
                Ok(org_result) => {
                    let mut vendors = discovered_vendors.lock().await;
                    vendors.insert(customer_base_domain.clone(), org_result.name);
                    logger.log_whois_lookup(&customer_base_domain, org_result.is_verified);
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
    // For DNS TXT records, use the raw record so users can see the actual TXT content
    // For subdomains, show the base domain with context
    // For other types, use the vendor domain
    let record_value = match source_type {
        RecordType::DnsSubdomain => format!("{} (base of {})", base_domain, customer_domain),
        RecordType::DnsTxtVerification | RecordType::DnsTxtSpf |
        RecordType::DnsTxtDmarc | RecordType::DnsTxtDkim => raw_record.clone(),
        _ => vendor_domain.clone(),
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
    // Note: Discovery methods (subdomain/SaaS tenant) only run at depth 1, so we pass None here
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
        subprocessor_enabled,
        web_org_enabled,
        web_org_min_confidence,
        analysis_config,
        None,  // subdomain_discovery - only runs at depth 1
        None,  // saas_tenant_discovery - only runs at depth 1
        None,  // ct_discovery - only runs at depth 1
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
    subprocessor_enabled: bool,
    web_org_enabled: bool,
    web_org_min_confidence: f32,
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
                    subprocessor_enabled,
                    web_org_enabled,
                    web_org_min_confidence,
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
    subprocessor_enabled: bool,
    web_org_enabled: bool,
    web_org_min_confidence: f32,
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
            if subprocessor_enabled && subprocessor_analyzer.is_some() {
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
                    match whois::get_organization_with_status_and_config(&base_domain, web_org_enabled, web_org_min_confidence).await {
                        Ok(org_result) => {
                            let mut vendors = discovered_vendors.lock().await;
                            vendors.insert(base_domain.clone(), org_result.name);
                            logger.log_whois_lookup(&base_domain, org_result.is_verified);
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

/// Represents an organization that was inferred from domain name (not verified via WHOIS)
#[derive(Debug, Clone)]
pub struct UnverifiedOrgMapping {
    /// The vendor domain
    pub domain: String,
    /// The inferred organization name (e.g., "Myklpages Inc." from myklpages.com)
    pub inferred_org: String,
}

/// Check if an organization name was likely inferred from the domain name
/// Returns true for patterns like "Myklpages Inc." from myklpages.com
fn is_likely_inferred_org(domain: &str, org: &str) -> bool {
    // Extract the base domain name (without TLD)
    let base = domain.split('.').next().unwrap_or(domain).to_lowercase();

    // Check if org matches the pattern "{Base} Inc." where Base is the domain name with first letter capitalized
    let org_lower = org.to_lowercase();

    // Pattern 1: "{domain} inc." (e.g., "myklpages inc." from myklpages.com)
    if org_lower == format!("{} inc.", base) {
        return true;
    }

    // Pattern 2: Just the domain name (no " Inc." suffix) - also inferred
    if org_lower == base {
        return true;
    }

    // Pattern 3: Org is the domain itself (fallback when everything fails)
    if org_lower == domain.to_lowercase() {
        return true;
    }

    // Check if org contains only the domain base with common suffixes
    let common_inferred_patterns = [
        format!("{} inc", base),
        format!("{} inc.", base),
        format!("{}, inc", base),
        format!("{}, inc.", base),
        format!("{} llc", base),
        format!("{} corp", base),
        format!("{} corporation", base),
        format!("{} company", base),
        format!("{} co", base),
        format!("{} ltd", base),
    ];

    common_inferred_patterns.iter().any(|pattern| org_lower == *pattern)
}

/// Prompt the user to confirm organizations that were inferred from domain names
/// These organizations couldn't be verified via WHOIS (due to privacy, errors, etc.)
async fn confirm_unverified_organizations(
    unverified: &[UnverifiedOrgMapping],
    discovered_vendors: &Arc<Mutex<HashMap<String, String>>>,
    logger: &AnalysisLogger,
) -> Result<()> {
    use std::io::Write;

    if unverified.is_empty() {
        return Ok(());
    }

    // Deduplicate by domain
    let mut unique: HashMap<String, String> = HashMap::new();
    for mapping in unverified {
        unique.entry(mapping.domain.clone()).or_insert(mapping.inferred_org.clone());
    }

    if unique.is_empty() {
        return Ok(());
    }

    println!();
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║         UNVERIFIED ORGANIZATION NAMES DETECTED                 ║");
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║ The following organizations were inferred from domain names    ║");
    println!("║ because WHOIS data was unavailable or protected by privacy.    ║");
    println!("║ You may specify correct organization names to improve accuracy.║");
    println!("║                                                                ║");
    println!("║ Confirmed names are saved locally for future runs.             ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    let mut domains: Vec<_> = unique.iter().collect();
    domains.sort_by(|a, b| a.0.cmp(b.0));

    for (idx, (domain, inferred_org)) in domains.iter().enumerate() {
        println!("  [{}] {} → \"{}\"", idx + 1, domain, inferred_org);
    }
    println!();

    println!("Options:");
    println!("  [A] Accept ALL inferred names and save for future runs");
    println!("  [R] Review each domain and specify correct organization names");
    println!("  [S] Skip - use inferred names without saving");
    println!();
    print!("Your choice (A/R/S): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim().to_uppercase();

    match choice.as_str() {
        "A" => {
            // Save all inferred names as local overrides for future runs
            let mut saved_count = 0;
            if let Some(kv) = known_vendors::get() {
                for (domain, inferred_org) in &domains {
                    if let Err(e) = kv.add_override(domain, inferred_org) {
                        logger.warn(&format!("Failed to save override for {}: {}", domain, e));
                    } else {
                        saved_count += 1;
                    }
                }
            }
            println!("✅ Accepted all {} inferred organization names", unique.len());
            if saved_count > 0 {
                println!("   💾 Saved {} names to local database for future runs", saved_count);
            }
        }
        "R" => {
            println!();
            println!("📋 Reviewing inferred organizations:");
            println!("─────────────────────────────────────────────────────────────────");

            let mut vendors = discovered_vendors.lock().await;
            let mut updated_count = 0;
            let mut saved_count = 0;

            for (domain, inferred_org) in &domains {
                println!();
                println!("  Domain: {}", domain);
                println!("  Inferred: \"{}\"", inferred_org);
                print!("  [Y] Accept  [C] Custom name  [S] Skip: ");
                io::stdout().flush()?;

                let mut response = String::new();
                io::stdin().read_line(&mut response)?;
                let resp = response.trim().to_uppercase();

                match resp.as_str() {
                    "C" => {
                        print!("    Enter correct organization name: ");
                        io::stdout().flush()?;
                        let mut custom = String::new();
                        io::stdin().read_line(&mut custom)?;
                        let custom_org = custom.trim();
                        if !custom_org.is_empty() {
                            vendors.insert(domain.to_string(), custom_org.to_string());

                            // Save to local overrides for future runs
                            if let Some(kv) = known_vendors::get() {
                                if let Err(e) = kv.add_override(domain, custom_org) {
                                    logger.warn(&format!("Failed to save override for {}: {}", domain, e));
                                } else {
                                    saved_count += 1;
                                }
                            }

                            logger.info(&format!("Updated organization for {}: {} -> {}", domain, inferred_org, custom_org));
                            println!("    ✅ Updated: {} → \"{}\" (saved for future runs)", domain, custom_org);
                            updated_count += 1;
                        } else {
                            println!("    ⏭️  Kept inferred name (empty input)");
                        }
                    }
                    "Y" | "" => {
                        // Accept inferred name and save for future runs
                        if let Some(kv) = known_vendors::get() {
                            if let Err(e) = kv.add_override(domain, inferred_org) {
                                logger.warn(&format!("Failed to save override for {}: {}", domain, e));
                            } else {
                                saved_count += 1;
                            }
                        }
                        println!("    ✅ Accepted: \"{}\" (saved for future runs)", inferred_org);
                    }
                    _ => {
                        println!("    ⏭️  Skipped (not saved)");
                    }
                }
            }

            if updated_count > 0 || saved_count > 0 {
                println!();
                if updated_count > 0 {
                    println!("✅ Updated {} organization name{}", updated_count, if updated_count == 1 { "" } else { "s" });
                }
                if saved_count > 0 {
                    println!("💾 Saved {} name{} to local database for future runs",
                             saved_count, if saved_count == 1 { "" } else { "s" });
                }
                if updated_count > 0 {
                    println!("   Note: Re-run analysis to regenerate reports with corrected names");
                }
            }
        }
        _ => {
            println!("⏭️  Skipped - using inferred organization names (not saved)");
        }
    }

    println!();
    Ok(())
}