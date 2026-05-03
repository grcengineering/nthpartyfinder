use anyhow::{bail, Result};
use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, IsTerminal};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

use crate::analysis;
use crate::batch;
use crate::cache_commands;
use crate::checkpoint::{generate_settings_hash, Checkpoint, ResumeMode};
use crate::cli::{Args, CacheCommands, Cli, Commands};
use crate::config::{AppConfig, ConfigError};
use crate::dep_check;
use crate::discovery::{
    CtLogDiscovery, InstallOption, SaasTenantDiscovery, SubfinderDiscovery, WebTrafficDiscovery,
};
use crate::dns;
use crate::export;
use crate::interactive::{self, UnverifiedOrgMapping};
use crate::known_vendors;
use crate::logger::{AnalysisLogger, VerbosityLevel};
use crate::memory_monitor::{self, MemoryMonitor};
use crate::org_normalizer;
use crate::result_sink::ResultSink;
use crate::subprocessor;
use crate::vendor::VendorRelationship;
use crate::vendor_registry;
use crate::verification_logger;
use crate::whois;

use std::path::PathBuf;

#[derive(Debug)]
pub struct AppExitCode(pub i32);

impl std::fmt::Display for AppExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exit code {}", self.0)
    }
}

impl std::error::Error for AppExitCode {}

pub trait InputSource: Send + Sync {
    fn is_terminal(&self) -> bool;
    fn read_line(&self, buf: &mut String) -> io::Result<usize>;
}

pub struct StdioInput;

impl InputSource for StdioInput {
    fn is_terminal(&self) -> bool {
        std::io::stdin().is_terminal()
    }

    fn read_line(&self, buf: &mut String) -> io::Result<usize> {
        io::stdin().lock().read_line(buf)
    }
}

/// Feature flags computed from CLI args + config, used to decide which discovery methods run.
#[derive(Debug, Clone, PartialEq)]
pub struct FeatureFlags {
    pub web_org: bool,
    pub subprocessor: bool,
    pub subdomain: bool,
    pub saas_tenant: bool,
    pub web_traffic: bool,
    pub ct_discovery: bool,
}

/// Compute which discovery features are enabled based on CLI args and config.
pub fn compute_feature_flags(args: &Args, config: &AppConfig) -> FeatureFlags {
    FeatureFlags {
        web_org: !args.dns_only
            && (args.enable_web_org || (!args.disable_web_org && config.discovery.web_org_enabled)),
        subprocessor: !args.dns_only
            && (args.enable_subprocessor_analysis
                || (!args.disable_subprocessor_analysis && config.discovery.subprocessor_enabled)),
        subdomain: !args.dns_only
            && (args.enable_subdomain_discovery
                || (!args.disable_subdomain_discovery && config.discovery.subdomain_enabled)),
        saas_tenant: !args.dns_only
            && (args.enable_saas_tenant_discovery
                || (!args.disable_saas_tenant_discovery && config.discovery.saas_tenant_enabled)),
        web_traffic: !args.dns_only
            && (args.enable_web_traffic_discovery
                || (!args.disable_web_traffic_discovery && config.discovery.web_traffic_enabled)),
        ct_discovery: !args.dns_only
            && (args.enable_ct_discovery
                || (!args.disable_ct_discovery && config.discovery.ct_discovery_enabled)),
    }
}

/// Build the output filename from the output base name, format, and domain.
pub fn build_output_filename(output: &str, output_format: &str, domain: &str) -> String {
    if output.contains('.') {
        output.to_string()
    } else if output == "nth_parties" {
        match output_format {
            "html" => format!("Nth Party Analysis for {}.html", domain),
            "json" => format!("Nth Party Analysis for {}.json", domain),
            "markdown" => format!("Nth Party Analysis for {}.md", domain),
            _ => format!("Nth Party Analysis for {}.csv", domain),
        }
    } else {
        format!("{}.{}", output, output_format)
    }
}

/// Deduplicate vendor relationships, merging evidence for duplicate keys.
/// Returns (deduplicated results, raw count before dedup).
pub fn deduplicate_results(results: Vec<VendorRelationship>) -> (Vec<VendorRelationship>, usize) {
    let raw_count = results.len();
    let mut seen: HashMap<(String, String, String), usize> = HashMap::new();
    let mut deduped: Vec<VendorRelationship> = Vec::new();
    for r in results {
        let key = (
            r.nth_party_domain.clone(),
            r.nth_party_customer_domain.clone(),
            r.nth_party_record_type.as_hierarchy_string(),
        );
        if let Some(&idx) = seen.get(&key) {
            let existing = &mut deduped[idx];
            if !existing.evidence.contains(&r.evidence) {
                existing.evidence = format!("{} | {}", existing.evidence, r.evidence);
            }
        } else {
            seen.insert(key, deduped.len());
            deduped.push(r);
        }
    }
    (deduped, raw_count)
}

/// Filter out common infrastructure providers unless include_infra is true.
/// Returns (filtered results, number removed).
pub fn filter_infra_providers(
    results: Vec<VendorRelationship>,
    include_infra: bool,
) -> (Vec<VendorRelationship>, usize) {
    if include_infra {
        (results, 0)
    } else {
        let before = results.len();
        let filtered: Vec<VendorRelationship> = results
            .into_iter()
            .filter(|r| !analysis::is_common_denominator(&r.nth_party_domain))
            .collect();
        let removed = before - filtered.len();
        (filtered, removed)
    }
}

/// Compute the analysis timeout from CLI args and environment variable.
/// Returns None if timeout is disabled (0), otherwise the Duration.
pub fn compute_analysis_timeout(cli_timeout: Option<u64>) -> Option<std::time::Duration> {
    compute_analysis_timeout_with_env(
        cli_timeout,
        std::env::var("NTHPARTY_ANALYSIS_TIMEOUT_SECS").ok(),
    )
}

/// Inner function for testability: compute timeout from CLI arg and env value.
pub fn compute_analysis_timeout_with_env(
    cli_timeout: Option<u64>,
    env_value: Option<String>,
) -> Option<std::time::Duration> {
    let timeout_secs: u64 =
        cli_timeout.unwrap_or_else(|| env_value.and_then(|v| v.parse().ok()).unwrap_or(600));
    if timeout_secs == 0 {
        None
    } else {
        Some(std::time::Duration::from_secs(timeout_secs))
    }
}

/// Construct the full output path from output_dir and filename.
pub fn build_full_output_path(output_dir: &str, output_filename: &str) -> PathBuf {
    Path::new(output_dir).join(output_filename)
}

/// Determine whether a checkpoint is compatible and should be resumed,
/// based on the resume mode and compatibility check.
///
/// Returns:
/// - `Some(true)` if the checkpoint should be resumed
/// - `Some(false)` if it should be deleted and fresh start
/// - `None` if user chose not to proceed (e.g. incompatible + no delete)
pub fn resolve_checkpoint_resume(
    resume_mode: &ResumeMode,
    is_compatible: bool,
    is_interactive: bool,
) -> Option<bool> {
    match resume_mode {
        ResumeMode::AutoResume => {
            if is_compatible {
                Some(true)
            } else {
                Some(false) // delete and start fresh
            }
        }
        ResumeMode::Fresh => Some(false),
        ResumeMode::Prompt => {
            if !is_interactive {
                if is_compatible {
                    Some(true)
                } else {
                    Some(false)
                }
            } else {
                // Interactive prompt needed - caller handles this
                None
            }
        }
    }
}

/// Collect unverified organization mappings from discovered vendors.
/// Returns domains whose org name appears to be inferred from the domain itself.
pub fn collect_unverified_orgs(
    vendors: &HashMap<String, String>,
) -> Vec<interactive::UnverifiedOrgMapping> {
    let mut unverified = Vec::new();
    for (domain, org) in vendors.iter() {
        if known_vendors::lookup(domain).is_some() {
            continue;
        }
        if analysis::is_likely_inferred_org(domain, org) {
            unverified.push(interactive::UnverifiedOrgMapping {
                domain: domain.clone(),
                inferred_org: org.clone(),
            });
        }
    }
    unverified
}

pub async fn run() -> Result<()> {
    eprintln!("nthpartyfinder v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  Parsing arguments...");

    let cli = Cli::parse();
    if let Some(Commands::Cache { action }) = &cli.command {
        match action {
            CacheCommands::List => {
                return cache_commands::list_cached_domains().await;
            }
            CacheCommands::Show { domain } => {
                return cache_commands::show_cache_entry(domain).await;
            }
            CacheCommands::Clear { domain, all } => {
                if *all {
                    return cache_commands::clear_all_cache().await;
                } else if let Some(d) = domain {
                    return cache_commands::clear_domain_cache(d).await;
                } else {
                    eprintln!(
                        "Error: Either specify a domain or use --all to clear all cache entries."
                    );
                    eprintln!("Usage: nthpartyfinder cache clear <domain>");
                    eprintln!("       nthpartyfinder cache clear --all");
                    std::process::exit(1);
                }
            }
            CacheCommands::Validate { detailed, domain } => {
                return cache_commands::validate_cache(*detailed, domain.as_deref()).await;
            }
        }
    }

    let args = Args::from(&cli);
    let input = StdioInput;
    match run_inner(args, &input).await {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Some(code) = e.downcast_ref::<AppExitCode>() {
                std::process::exit(code.0);
            }
            Err(e)
        }
    }
}

pub async fn run_inner(args: Args, input: &dyn InputSource) -> Result<()> {
    if args.init {
        match AppConfig::create_default_config() {
            Ok(path) => {
                println!(
                    "✅ Created default configuration file at: {}",
                    path.display()
                );
                println!("   Edit this file to customize settings, then run nthpartyfinder again.");
                return Ok(());
            }
            Err(e) => {
                eprintln!("❌ Failed to create configuration file: {}", e);
                bail!(AppExitCode(1));
            }
        }
    }

    if let Err(e) = args.validate() {
        eprintln!("error: {}", e);
        bail!(AppExitCode(2));
    }

    eprintln!("  Loading configuration...");
    let _app_config = match AppConfig::load() {
        Ok(cfg) => cfg,
        Err(ConfigError::FileNotFound(path)) => match AppConfig::prompt_create_config() {
            Ok(Some(created_path)) => {
                println!(
                    "✅ Created default configuration file at: {}",
                    created_path.display()
                );
                println!("   Edit this file to customize settings, then run nthpartyfinder again.");
                return Ok(());
            }
            Ok(None) => {
                eprintln!("❌ Configuration file not found at: {}", path.display());
                eprintln!("   Run with --init to create a default configuration file.");
                bail!(AppExitCode(1));
            }
            Err(e) => {
                eprintln!("❌ Failed to create configuration file: {}", e);
                bail!(AppExitCode(1));
            }
        },
        Err(e) => {
            eprintln!("❌ Configuration error: {}", e);
            bail!(AppExitCode(1));
        }
    };

    eprintln!("  Checking dependencies...");
    #[cfg(feature = "embedded-ner")]
    {
        let slm_wanted =
            args.enable_slm || (!args.disable_slm && _app_config.discovery.ner_enabled);
        if slm_wanted {
            let ort_check = dep_check::check_onnx_runtime_availability();
            if !ort_check {
                match dep_check::download_onnx_runtime_interactive() {
                    Ok(_path) => {}
                    Err(e) => {
                        eprintln!("⚠️  {}", e);
                        eprintln!("   Continuing without NER (--disable-slm implied).");
                    }
                }
            }
        }
    }

    match dep_check::check_dependencies(
        args.enable_slm,
        args.disable_slm,
        args.enable_subdomain_discovery,
        args.enable_web_org,
        args.enable_web_traffic_discovery,
        _app_config.discovery.ner_enabled,
        _app_config.discovery.subdomain_enabled,
    ) {
        Ok(results) => {
            for result in &results {
                if !result.available {
                    if let Some(msg) = &result.message {
                        eprintln!("⚠️  {}", msg);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Missing required dependency:\n{}", e);
            bail!(AppExitCode(1));
        }
    }

    eprintln!("  Starting logger...");
    let verbosity = VerbosityLevel::from_verbose_count(args.verbose);
    let logger = Arc::new(match &args.log_file {
        Some(log_file_path) => AnalysisLogger::with_log_file(verbosity, log_file_path.clone()),
        None => AnalysisLogger::new(verbosity),
    });

    logger.start_init_progress(5).await;

    #[cfg(feature = "embedded-ner")]
    let ner_bg_handle = if !args.disable_slm {
        Some(tokio::task::spawn_blocking(|| {
            crate::ner_org::init_with_config(0.6)
        }))
    } else {
        None
    };

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
    if vendor_registry_loaded {
        if let Some(reg) = vendor_registry::get() {
            logger
                .complete_init_step(&format!(
                    "Vendor registry ({} vendors, {} domains)",
                    reg.vendor_count(),
                    reg.domain_count()
                ))
                .await;
        } else {
            logger.complete_init_step("Vendor registry loaded").await;
        }
    } else {
        logger
            .complete_init_step("Vendor registry (fallback mode)")
            .await;
    }

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
    if known_vendors_loaded {
        if let Some(kv) = known_vendors::get() {
            let stats = kv.stats();
            logger
                .complete_init_step(&format!(
                    "Known vendors database ({} vendors)",
                    stats.base_count
                ))
                .await;
        } else {
            logger
                .complete_init_step("Known vendors database loaded")
                .await;
        }
    } else {
        logger
            .complete_init_step("Known vendors database (not available)")
            .await;
    }

    org_normalizer::init(&_app_config.organization);
    if org_normalizer::is_enabled() {
        logger
            .complete_init_step(&format!(
                "Organization normalizer (threshold: {:.0}%)",
                _app_config.organization.similarity_threshold * 100.0
            ))
            .await;
    } else {
        logger
            .complete_init_step("Organization normalizer (disabled)")
            .await;
    }

    let flags = compute_feature_flags(&args, &_app_config);
    let web_org_will_be_enabled = flags.web_org;
    let subprocessor_will_be_enabled = flags.subprocessor;
    let subdomain_will_be_enabled = flags.subdomain;
    let saas_tenant_will_be_enabled = flags.saas_tenant;
    let web_traffic_will_be_enabled = flags.web_traffic;
    let ct_will_be_enabled = flags.ct_discovery;
    if args.dns_only {
        logger.info("DNS-only mode: all non-DNS discovery methods disabled");
    }
    logger
        .complete_init_step("Feature detection complete")
        .await;

    #[cfg(feature = "embedded-ner")]
    {
        if let Some(handle) = ner_bg_handle {
            match handle.await {
                Ok(Ok(())) => {
                    logger
                        .complete_init_step("NER model loaded (GLiNER ready)")
                        .await;
                }
                Ok(Err(e)) => {
                    logger
                        .complete_init_step(&format!("NER initialization failed: {}", e))
                        .await;
                }
                Err(e) => {
                    logger
                        .complete_init_step(&format!("NER task panicked: {}", e))
                        .await;
                }
            }
        } else {
            logger
                .complete_init_step("NER disabled (--disable-slm)")
                .await;
        }
    }
    #[cfg(not(feature = "embedded-ner"))]
    {
        logger.complete_init_step("NER not compiled in").await;
    }

    logger.finish_init().await;

    if vendor_registry_loaded {
        if let Some(reg) = vendor_registry::get() {
            logger.info(&format!(
                "Vendor registry: {} vendors, {} domains",
                reg.vendor_count(),
                reg.domain_count()
            ));
        }
    }
    if web_org_will_be_enabled {
        logger.info("Web organization extraction enabled");
    }
    if subprocessor_will_be_enabled {
        logger.info("Subprocessor web page analysis enabled");
    }
    if subdomain_will_be_enabled {
        logger.info("Subdomain discovery enabled");
    }
    if saas_tenant_will_be_enabled {
        logger.info("SaaS tenant discovery enabled");
    }
    if web_traffic_will_be_enabled {
        logger.info("Webpage source & network request discovery enabled");
    }

    ctrlc::set_handler(
        move || {
        analysis::set_interrupted();
        eprintln!("\n⚠️  Interrupt received. Saving checkpoint and exiting...");
        std::thread::sleep(std::time::Duration::from_secs(2));
        eprintln!("⚠️  Force exiting (checkpoint may be incomplete).");
        std::process::exit(130);
    }).unwrap_or_else(|e| {
        eprintln!("⚠️  Warning: Failed to set Ctrl-C handler: {}. Interrupt signals may not be handled gracefully.", e);
    });

    if args.is_batch_mode() {
        let input_path = std::path::Path::new(args.input_file.as_ref().unwrap());
        let domains = match batch::parse_domain_file(input_path) {
            Ok(d) if d.is_empty() => {
                eprintln!("error: no valid domains found in {}", input_path.display());
                bail!(AppExitCode(2));
            }
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: failed to read input file: {}", e);
                bail!(AppExitCode(2));
            }
        };

        let output_dir = args
            .batch_output_dir
            .clone()
            .or_else(|| args.output_dir.clone())
            .unwrap_or_else(|| Args::get_default_output_dir().unwrap_or_else(|_| ".".into()));
        let output_base = std::path::Path::new(&output_dir);
        if let Err(e) = std::fs::create_dir_all(output_base) {
            eprintln!("error: failed to create output directory: {}", e);
            bail!(AppExitCode(1));
        }

        let batch_start = std::time::Instant::now();
        let mut summary = batch::new_batch_summary();

        let parallelism = args.batch_parallel;
        let semaphore = Arc::new(Semaphore::new(parallelism));

        let domains_total = domains.len();
        logger.info(&format!(
            "Batch mode: {} domains, parallelism={}",
            domains_total, parallelism
        ));

        let results: Arc<Mutex<Vec<batch::DomainAnalysisResult>>> =
            Arc::new(Mutex::new(Vec::new()));

        let mut handles = Vec::new();
        for entry in &domains {
            let sem = semaphore.clone();
            let domain = entry.domain.clone();
            let label = entry.label.clone();
            let format = args.output_format.clone();
            let depth = args.depth;
            let dns_only = args.dns_only;
            let output_base = output_base.to_path_buf();
            let batch_combined = args.batch_combined;
            let results = results.clone();
            let logger = logger.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let domain_start = std::time::Instant::now();

                logger.info(&format!("Batch: starting analysis of {}", domain));

                let mut cmd_args = vec![
                    "nthpartyfinder".to_string(),
                    "-d".to_string(),
                    domain.clone(),
                    "-f".to_string(),
                    format.clone(),
                ];
                if let Some(d) = depth {
                    cmd_args.push("-r".to_string());
                    cmd_args.push(d.to_string());
                }
                if dns_only {
                    cmd_args.push("--dns-only".to_string());
                }
                if !batch_combined {
                    let domain_dir = output_base.join(domain.replace('.', "_"));
                    let _ = std::fs::create_dir_all(&domain_dir);
                    cmd_args.push("--output-dir".to_string());
                    cmd_args.push(domain_dir.to_string_lossy().to_string());
                }

                let output = tokio::process::Command::new(std::env::current_exe().unwrap())
                    .args(&cmd_args[1..])
                    .env("NO_COLOR", "1")
                    .output()
                    .await;

                let duration = domain_start.elapsed().as_secs_f64();

                let result = match output {
                    Ok(out) if out.status.success() => {
                        let output_file = if !batch_combined {
                            Some(
                                output_base
                                    .join(domain.replace('.', "_"))
                                    .join(batch::domain_output_filename(&domain, &format))
                                    .to_string_lossy()
                                    .to_string(),
                            )
                        } else {
                            None
                        };
                        batch::DomainAnalysisResult {
                            domain: domain.clone(),
                            label,
                            success: true,
                            error: None,
                            relationship_count: 0,
                            output_file,
                            duration_secs: duration,
                        }
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        batch::DomainAnalysisResult {
                            domain: domain.clone(),
                            label,
                            success: false,
                            error: Some(stderr),
                            relationship_count: 0,
                            output_file: None,
                            duration_secs: duration,
                        }
                    }
                    Err(e) => batch::DomainAnalysisResult {
                        domain: domain.clone(),
                        label,
                        success: false,
                        error: Some(format!("Failed to spawn: {}", e)),
                        relationship_count: 0,
                        output_file: None,
                        duration_secs: duration,
                    },
                };

                results.lock().await.push(result);
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        summary.domain_results = Arc::try_unwrap(results)
            .unwrap_or_else(|arc| {
                let guard = arc.try_lock().unwrap();
                Mutex::new(guard.clone())
            })
            .into_inner();

        summary.total_duration_secs = batch_start.elapsed().as_secs_f64();
        batch::finalize_batch_summary(&mut summary);

        if args.batch_combined {
            let combined_path = output_base.join(format!("{}.{}", args.output, args.output_format));
            if let Err(e) = batch::export_batch_summary(&summary, &combined_path) {
                eprintln!("error: failed to write combined report: {}", e);
                bail!(AppExitCode(1));
            }
            logger.info(&format!("Combined report: {}", combined_path.display()));
        }

        let summary_path = output_base.join("batch_summary.json");
        if let Err(e) = batch::export_batch_summary(&summary, &summary_path) {
            eprintln!("error: failed to write batch summary: {}", e);
            bail!(AppExitCode(1));
        }

        logger.info(&format!(
            "Batch complete: {}/{} succeeded in {:.1}s",
            summary.successful, summary.total_domains, summary.total_duration_secs
        ));

        if summary.failed > 0 {
            bail!(AppExitCode(1));
        }
        return Ok(());
    }

    let domain = args
        .domain
        .as_ref()
        .expect("Domain is required when not using --init or --input-file");

    let output_dir = match args.get_domain_output_dir() {
        Ok(dir) => dir,
        Err(e) => {
            logger.error(&format!("Failed to determine output directory: {}", e));
            bail!(AppExitCode(1));
        }
    };

    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        logger.error(&format!(
            "Failed to create output directory '{}': {}",
            output_dir, e
        ));
        bail!(AppExitCode(1));
    }

    let output_filename = build_output_filename(&args.output, &args.output_format, domain);
    let output_path = build_full_output_path(&output_dir, &output_filename);
    let output_path_str = output_path.to_string_lossy();

    let is_interactive = input.is_terminal();
    let final_output_path = if is_interactive {
        logger.suspend_for_io(|| {
            println!("📁 Output file will be saved to: {}", output_path_str);
            println!();
            print!("Press Enter to continue or type a different directory path: ");
            io::Write::flush(&mut io::stdout()).unwrap();

            let mut user_input = String::new();
            if let Err(e) = input.read_line(&mut user_input) {
                eprintln!(
                    "Warning: Failed to read stdin: {}, using default output path",
                    e
                );
            }
            let user_input = user_input.trim();

            if user_input.is_empty() {
                output_path_str.to_string()
            } else {
                let custom_path = Path::new(user_input).join(&output_filename);
                custom_path.to_string_lossy().to_string()
            }
        })
    } else {
        logger.info(&format!("Output file: {}", output_path_str));
        output_path_str.to_string()
    };

    logger.info(&format!("Results will be saved to: {}", final_output_path));

    logger.log_initialization(domain);

    let settings_hash = generate_settings_hash(
        args.depth,
        subprocessor_will_be_enabled,
        subdomain_will_be_enabled,
        saas_tenant_will_be_enabled,
        ct_will_be_enabled,
        web_org_will_be_enabled,
        web_traffic_will_be_enabled,
    );

    let output_dir_path = Path::new(&output_dir);
    let resume_mode = args.get_resume_mode();
    let mut checkpoint: Option<Checkpoint> = None;

    if Checkpoint::exists(output_dir_path) {
        match Checkpoint::load(output_dir_path) {
            Ok(existing_checkpoint) => {
                let summary = existing_checkpoint.summary();
                let is_compatible = existing_checkpoint.is_compatible(domain, &settings_hash);

                match resume_mode {
                    ResumeMode::AutoResume => {
                        if is_compatible {
                            logger.info(&format!("Resuming from checkpoint: {}", summary));
                            checkpoint = Some(existing_checkpoint);
                        } else {
                            logger.info("Existing checkpoint is incompatible (different domain or settings). Starting fresh.");
                            let _ = Checkpoint::delete(output_dir_path);
                        }
                    }
                    ResumeMode::Fresh => {
                        logger.info("Starting fresh analysis (--no-resume specified).");
                        let _ = Checkpoint::delete(output_dir_path);
                    }
                    ResumeMode::Prompt => {
                        if !input.is_terminal() {
                            if is_compatible {
                                logger.info("Auto-resuming from compatible checkpoint (non-interactive mode)");
                                checkpoint = Some(existing_checkpoint);
                            } else {
                                logger
                                    .info("Incompatible checkpoint deleted (non-interactive mode)");
                                let _ = Checkpoint::delete(output_dir_path);
                            }
                        } else {
                            let created_at = existing_checkpoint
                                .created_at
                                .format("%Y-%m-%d %H:%M:%S UTC")
                                .to_string();
                            let resume_result = logger.suspend_for_io(|| -> Result<Option<bool>> {
                                println!();
                                println!("╔════════════════════════════════════════════════════════════════╗");
                                println!("║         INCOMPLETE ANALYSIS CHECKPOINT FOUND                  ║");
                                println!("╚════════════════════════════════════════════════════════════════╝");
                                println!();
                                println!("   {}", summary);
                                println!("   Created: {}", created_at);
                                println!();

                                if is_compatible {
                                    print!("Resume from checkpoint? [Y/n]: ");
                                    io::Write::flush(&mut io::stdout()).unwrap();

                                    let mut resume_input = String::new();
                                    let _ = input.read_line(&mut resume_input);
                                    let resume_input = resume_input.trim().to_lowercase();

                                    if resume_input.is_empty() || resume_input == "y" || resume_input == "yes" {
                                        println!("Resuming from checkpoint...");
                                        Ok(Some(true))
                                    } else {
                                        println!("Starting fresh analysis...");
                                        Ok(Some(false))
                                    }
                                } else {
                                    println!("Checkpoint is incompatible with current settings.");
                                    println!("   (Different domain or analysis options)");
                                    print!("Delete checkpoint and start fresh? [Y/n]: ");
                                    io::Write::flush(&mut io::stdout()).unwrap();

                                    let mut delete_input = String::new();
                                    let _ = input.read_line(&mut delete_input);
                                    let delete_input = delete_input.trim().to_lowercase();

                                    if delete_input.is_empty() || delete_input == "y" || delete_input == "yes" {
                                        println!("Starting fresh analysis...");
                                        Ok(None)
                                    } else {
                                        println!("Cannot proceed with incompatible checkpoint. Exiting.");
                                        bail!(AppExitCode(1));
                                    }
                                }
                            })?;

                            match resume_result {
                                Some(true) => checkpoint = Some(existing_checkpoint),
                                Some(false) => {
                                    let _ = Checkpoint::delete(output_dir_path);
                                }
                                None => {
                                    let _ = Checkpoint::delete(output_dir_path);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                logger.warn(&format!(
                    "Failed to load existing checkpoint: {}. Starting fresh.",
                    e
                ));
                let _ = Checkpoint::delete(output_dir_path);
            }
        }
    }

    let checkpoint = Arc::new(Mutex::new(checkpoint.unwrap_or_else(|| {
        Checkpoint::new(domain.clone(), None, args.depth, settings_hash.clone())
    })));

    let verification_logger = verification_logger::VerificationFailureLogger::new(
        &output_dir,
        domain,
        args.log_verification_failures,
    );

    if args.log_verification_failures {
        if let Err(e) = verification_logger.initialize() {
            logger.warn(&format!(
                "Failed to initialize verification failure logger: {}",
                e
            ));
        } else {
            logger.debug(&format!(
                "Verification failure logging enabled: {}",
                verification_logger.get_file_path()
            ));
        }
    }

    let web_org_enabled = web_org_will_be_enabled;
    let web_org_min_confidence = _app_config.discovery.web_org_min_confidence;

    let (mut discovered_vendors, processed_domains_set, resumed_results_file) = {
        let cp = checkpoint.lock().await;
        if !cp.completed_domains.is_empty() {
            let results_file = if !cp.results_file.is_empty() {
                Some(cp.results_file.clone())
            } else {
                None
            };
            logger.info(&format!(
                "Restoring state: {} completed domains, {} pending, {} results on disk",
                cp.completed_domains.len(),
                cp.pending_domains.len(),
                cp.results_count
            ));
            (
                cp.discovered_vendors.clone(),
                cp.completed_domains.clone(),
                results_file,
            )
        } else {
            (HashMap::new(), HashSet::new(), None)
        }
    };

    let mut unverified_orgs: Vec<UnverifiedOrgMapping> = Vec::new();

    let whois_handle = if !discovered_vendors.contains_key(domain) {
        let whois_domain = domain.clone();
        Some(tokio::spawn(async move {
            whois::get_organization_with_status_and_config(
                &whois_domain,
                web_org_enabled,
                web_org_min_confidence,
            )
            .await
        }))
    } else {
        None
    };

    if let Some(handle) = whois_handle {
        match handle.await {
            Ok(Ok(org_result)) => {
                let normalized_name = org_normalizer::normalize(&org_result.name);
                discovered_vendors.insert(domain.clone(), normalized_name.clone());
                logger.log_whois_lookup(domain, true);
                if !org_result.is_verified {
                    unverified_orgs.push(UnverifiedOrgMapping {
                        domain: domain.clone(),
                        inferred_org: normalized_name,
                    });
                }
                {
                    let mut cp = checkpoint.lock().await;
                    cp.root_organization = discovered_vendors.get(domain).cloned();
                }
            }
            Ok(Err(_)) => {
                logger.log_whois_lookup(domain, false);
            }
            Err(e) => {
                logger.warn(&format!("WHOIS lookup task failed: {}", e));
                logger.log_whois_lookup(domain, false);
            }
        }
    }

    let root_customer_domain = domain.clone();
    let root_customer_org = discovered_vendors.get(domain).unwrap_or(domain).clone();

    let discovered_vendors = Arc::new(Mutex::new(discovered_vendors));
    let unverified_orgs = Arc::new(Mutex::new(unverified_orgs));
    let processed_domains = Arc::new(Mutex::new(processed_domains_set));
    let semaphore = Arc::new(Semaphore::new(args.parallel_jobs));

    let dns_pool = Arc::new(dns::DnsServerPool::from_config(&_app_config));
    logger.debug(&format!(
        "Initialized DNS server pool with {} DoH servers and {} DNS servers",
        _app_config.dns.doh_servers.len(),
        _app_config.dns.dns_servers.len()
    ));

    let subprocessor_enabled = subprocessor_will_be_enabled;
    let subprocessor_analyzer = if subprocessor_enabled {
        Some(Arc::new(subprocessor::SubprocessorAnalyzer::new().await))
    } else {
        None
    };

    let subdomain_discovery = if subdomain_will_be_enabled {
        let path = args
            .subfinder_path
            .clone()
            .unwrap_or_else(|| _app_config.discovery.subfinder_path.clone());
        let mut discovery = SubfinderDiscovery::new(
            PathBuf::from(path.clone()),
            std::time::Duration::from_secs(_app_config.discovery.subfinder_timeout_secs),
        );
        if discovery.is_available() {
            Some(discovery)
        } else if !input.is_terminal() {
            logger.warn("Subfinder binary not found — subdomain discovery disabled (non-interactive mode, cannot prompt for installation)");
            None
        } else {
            let options = SubfinderDiscovery::get_available_install_options();
            let selected_option = logger.suspend_for_io(|| {
                eprintln!();
                eprintln!("╔══════════════════════════════════════════════════════════════════╗");
                eprintln!("║           Subfinder Not Found                                    ║");
                eprintln!("╚══════════════════════════════════════════════════════════════════╝");
                eprintln!();
                eprintln!("Subfinder is required for subdomain discovery.");
                eprintln!("It's a subdomain enumeration tool by Project Discovery.");
                eprintln!();
                eprintln!("Would you like to install subfinder now?");
                eprintln!();
                for (i, option) in options.iter().enumerate() {
                    eprintln!("  [{}] {}", i + 1, option.display_name());
                }
                eprintln!();
                eprint!("Select option [1-{}]: ", options.len());

                let mut line_buf = String::new();
                if input.read_line(&mut line_buf).is_ok() {
                    line_buf.trim().parse::<usize>().ok().and_then(|n| {
                        if n >= 1 && n <= options.len() {
                            Some(options[n - 1])
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            });

            match selected_option {
                Some(InstallOption::AutoDownload) => {
                    eprintln!();
                    eprintln!("Downloading subfinder...");
                    match SubfinderDiscovery::download_and_install().await {
                        Ok(install_path) => {
                            logger.info(&format!(
                                "Subfinder installed to: {}",
                                install_path.display()
                            ));
                            discovery = SubfinderDiscovery::new(
                                install_path,
                                std::time::Duration::from_secs(
                                    _app_config.discovery.subfinder_timeout_secs,
                                ),
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
                Some(InstallOption::Skip) => None,
                Some(InstallOption::ManualDownload) => {
                    let url = SubfinderDiscovery::get_download_url();
                    eprintln!();
                    eprintln!("Opening download page: {}", url);
                    #[cfg(target_os = "windows")]
                    let _ = std::process::Command::new("cmd")
                        .args(["/C", "start", url])
                        .spawn();
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
                            let subfinder_name = if cfg!(windows) {
                                "subfinder.exe"
                            } else {
                                "subfinder"
                            };
                            let go_bin = dirs::home_dir()
                                .map(|h| h.join("go").join("bin").join(subfinder_name))
                                .unwrap_or_else(|| PathBuf::from(subfinder_name));
                            discovery = SubfinderDiscovery::new(
                                go_bin,
                                std::time::Duration::from_secs(
                                    _app_config.discovery.subfinder_timeout_secs,
                                ),
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
                            eprintln!(
                                "Note: Docker-based subfinder requires running via docker command."
                            );
                            eprintln!("nthpartyfinder cannot use Docker-based subfinder directly.");
                            eprintln!();
                            eprintln!("To use subfinder with Docker, run manually:");
                            eprintln!(
                                "  docker run -it projectdiscovery/subfinder:latest -d <domain>"
                            );
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
                                std::time::Duration::from_secs(
                                    _app_config.discovery.subfinder_timeout_secs,
                                ),
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
                            logger
                                .warn(&format!("Failed to install subfinder via Homebrew: {}", e));
                            None
                        }
                    }
                }
                None => {
                    eprintln!("Invalid selection. Continuing without subdomain discovery.");
                    eprintln!("❌ DISABLED: Subdomain discovery (subfinder not installed)");
                    None
                }
            }
        }
    } else {
        None
    };

    let saas_tenant_discovery = if saas_tenant_will_be_enabled {
        let mut discovery = SaasTenantDiscovery::new(
            std::time::Duration::from_secs(_app_config.discovery.tenant_probe_timeout_secs),
            _app_config.discovery.tenant_probe_concurrency,
        );
        let platforms_path = Path::new("config/saas_platforms.json");
        if let Err(e) = discovery.load_platforms_with_fallback(platforms_path) {
            logger.warn(&format!("Failed to load SaaS platforms: {}", e));
            None
        } else if discovery.platform_count() == 0 {
            logger.warn("SaaS tenant discovery enabled but no platforms loaded");
            None
        } else {
            Some(discovery)
        }
    } else {
        None
    };

    let ct_discovery = if ct_will_be_enabled {
        Some(CtLogDiscovery::new(std::time::Duration::from_secs(
            _app_config.discovery.ct_timeout_secs,
        )))
    } else {
        None
    };

    let web_traffic_discovery = if web_traffic_will_be_enabled {
        Some(WebTrafficDiscovery::new(
            _app_config.discovery.web_traffic_timeout_secs,
        ))
    } else {
        None
    };

    let recursive_limit = _app_config
        .analysis
        .get_concurrency_for_depth(1)
        .min(args.parallel_jobs);
    let recursive_semaphore = Arc::new(Semaphore::new(recursive_limit));
    logger.debug(&format!(
        "Configured concurrency: {} main jobs, {} initial recursive jobs (strategy: {:?})",
        args.parallel_jobs, recursive_limit, _app_config.analysis.strategy
    ));
    logger.debug(&format!(
        "Concurrency per depth: {:?}, request delay: {}ms",
        _app_config.analysis.concurrency_per_depth, _app_config.analysis.request_delay_ms
    ));

    let checkpoint_for_analysis = checkpoint.clone();
    let output_dir_for_checkpoint = output_dir.clone();

    let sink_dir = std::path::PathBuf::from("/tmp");
    match ResultSink::cleanup_orphans(&sink_dir) {
        Ok(0) => {}
        Ok(n) => logger.debug(&format!("Cleaned up {} orphaned result files", n)),
        Err(e) => logger.debug(&format!("Orphan cleanup failed (non-critical): {}", e)),
    }
    let result_sink = Arc::new(Mutex::new(
        ResultSink::new(&sink_dir).expect("Failed to create result sink — check /tmp disk space"),
    ));
    logger.debug(&format!(
        "Result sink created: {}",
        result_sink.lock().await.path().display()
    ));

    let memory_pressure_level = Arc::new(std::sync::atomic::AtomicU8::new(0));
    {
        let pressure = memory_pressure_level.clone();
        let logger_mem = logger.clone();
        tokio::spawn(async move {
            let mut monitor = MemoryMonitor::new(10);
            loop {
                let (level, _) = monitor.check();
                let level_num = match level {
                    memory_monitor::PressureLevel::Normal => 0u8,
                    memory_monitor::PressureLevel::Warning => 1u8,
                    memory_monitor::PressureLevel::Critical => 2u8,
                };
                let prev = pressure.swap(level_num, std::sync::atomic::Ordering::Relaxed);
                if level_num != prev {
                    let status = monitor.status_string();
                    match level_num {
                        2 => logger_mem.warn(&format!(
                            "Memory CRITICAL — throttling concurrency. {}",
                            status
                        )),
                        1 => logger_mem.warn(&format!(
                            "Memory WARNING — reducing concurrency. {}",
                            status
                        )),
                        0 if prev > 0 => logger_mem.info(&format!(
                            "Memory pressure relieved — resuming normal concurrency. {}",
                            status
                        )),
                        _ => {}
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }
    logger.debug("Memory pressure monitor started (5s interval)");

    logger.start_scan_progress(100).await;

    let analysis_timeout = compute_analysis_timeout(args.timeout);
    let analysis_timeout_secs = analysis_timeout.map(|d| d.as_secs()).unwrap_or(0);

    let analysis_future = analysis::discover_nth_parties(
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
        web_traffic_discovery.as_ref(),
        checkpoint_for_analysis.clone(),
        &output_dir_for_checkpoint,
        result_sink.clone(),
        memory_pressure_level.clone(),
    );

    if let Some(timeout_duration) = analysis_timeout {
        match tokio::time::timeout(timeout_duration, analysis_future).await {
            Ok(result) => result?,
            Err(_) => {
                logger.warn(&format!(
                    "Analysis timed out after {} seconds. Saving checkpoint with partial results.",
                    analysis_timeout_secs
                ));
                {
                    let mut sink = result_sink.lock().await;
                    let _ = sink.flush();
                }
                {
                    let mut cp = checkpoint.lock().await;
                    let sink = result_sink.lock().await;
                    cp.results_count = sink.count();
                    cp.results_file = sink.path().to_string_lossy().to_string();
                    drop(sink);
                    if let Err(e) = cp.save(Path::new(&output_dir)) {
                        logger.warn(&format!("Failed to save checkpoint on timeout: {}", e));
                    }
                }
                logger
                    .finish_progress("Analysis timed out - partial results saved")
                    .await;
                eprintln!();
                eprintln!(
                    "Analysis exceeded the {} second timeout.",
                    analysis_timeout_secs
                );
                eprintln!("Partial progress has been saved as a checkpoint. Re-run to resume.");
                eprintln!("To increase the timeout: use --timeout <seconds> or export NTHPARTY_ANALYSIS_TIMEOUT_SECS=<seconds>");
                bail!(AppExitCode(1));
            }
        }
    } else {
        analysis_future.await?
    };

    if analysis::is_interrupted() {
        logger.warn("Analysis interrupted by user.");
        bail!(AppExitCode(130));
    }

    let new_results = {
        let sink_path;
        {
            let mut sink = result_sink.lock().await;
            let _ = sink.flush();
            sink_path = sink.path().to_path_buf();
        }
        match Arc::try_unwrap(result_sink) {
            Ok(mutex) => {
                let sink = mutex.into_inner();
                sink.drain_all()
                    .expect("Failed to read results from disk sink")
            }
            Err(_arc) => {
                logger.debug("ResultSink has outstanding references, reading from file path");
                ResultSink::read_results(&sink_path)
                    .expect("Failed to read results from disk sink file")
            }
        }
    };
    logger.debug(&format!(
        "Read {} results from disk sink",
        new_results.len()
    ));

    let resumed_results = if let Some(ref results_file) = resumed_results_file {
        let path = std::path::Path::new(results_file);
        if path.exists() {
            match ResultSink::read_results(path) {
                Ok(results) => {
                    logger.info(&format!(
                        "Loaded {} resumed results from {}",
                        results.len(),
                        results_file
                    ));
                    results
                }
                Err(e) => {
                    logger.warn(&format!(
                        "Failed to read resumed results from {}: {}",
                        results_file, e
                    ));
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let results: Vec<VendorRelationship> = {
        let mut all_results = resumed_results;
        all_results.extend(new_results);
        let (deduped, raw_count) = deduplicate_results(all_results);
        if deduped.len() < raw_count {
            logger.info(&format!(
                "{} raw relationships deduplicated to {} unique",
                raw_count,
                deduped.len()
            ));
        }
        deduped
    };

    let results: Vec<VendorRelationship> = {
        let (filtered, removed) = filter_infra_providers(results, args.include_infra);
        if removed > 0 {
            logger.info(&format!(
                "Filtered {} common infra provider entries (use --include-infra to include)",
                removed
            ));
        }
        filtered
    };

    let unique_vendors = results
        .iter()
        .map(|r| &r.nth_party_organization)
        .collect::<HashSet<_>>()
        .len();

    logger.record_vendor_relationships(results.len());
    logger.record_unique_vendors(unique_vendors);

    if let Err(e) = Checkpoint::delete(output_dir_path) {
        logger.debug(&format!(
            "Failed to delete checkpoint (non-critical): {}",
            e
        ));
    } else {
        logger.debug("Checkpoint deleted after successful completion.");
    }

    logger.log_export_start(&args.output_format);

    match args.output_format.as_str() {
        "json" => export::export_json(&results, &final_output_path)?,
        "markdown" => export::export_markdown(&results, &final_output_path)?,
        "html" => export::export_html(&results, &final_output_path)?,
        _ => export::export_csv(&results, &final_output_path)?,
    }

    logger.log_export_success(&final_output_path);

    let is_interactive_post = input.is_terminal();
    if is_interactive_post {
        if let Some(analyzer) = &subprocessor_analyzer {
            let pending = analyzer.get_pending_mappings().await;
            if !pending.is_empty() {
                interactive::confirm_pending_mappings(&pending, analyzer, &logger).await?;
            }
        }
    }

    {
        let vendors = discovered_vendors.lock().await;
        let mut all_unverified = unverified_orgs.lock().await.clone();

        let newly_found = collect_unverified_orgs(&vendors);
        for mapping in newly_found {
            if !all_unverified.iter().any(|u| u.domain == mapping.domain) {
                all_unverified.push(mapping);
            }
        }
        drop(vendors);

        if !all_unverified.is_empty() && is_interactive_post {
            interactive::confirm_unverified_organizations(
                &all_unverified,
                &discovered_vendors,
                &logger,
            )
            .await?;
        }
    }

    if args.log_verification_failures {
        verification_logger.close();
        logger.debug(&format!(
            "Verification failure log closed: {}",
            verification_logger.get_file_path()
        ));
    }

    logger.print_final_summary();

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

pub async fn run_batch_analysis(
    args: &Args,
    app_config: &AppConfig,
    logger: Arc<AnalysisLogger>,
    input: &dyn InputSource,
) -> Result<()> {
    use batch::{
        export_batch_summary, finalize_batch_summary, new_batch_summary, parse_domain_file,
        DomainAnalysisResult,
    };
    use futures::{stream, StreamExt};

    let input_file = args
        .input_file
        .as_ref()
        .expect("input_file required in batch mode");
    let input_path = Path::new(input_file);

    println!();
    println!("========================================================================");
    println!("                     BATCH ANALYSIS MODE                                ");
    println!("========================================================================");
    println!();

    logger.info(&format!("Loading domains from: {}", input_file));

    let domains = match parse_domain_file(input_path) {
        Ok(domains) => {
            if domains.is_empty() {
                logger.error("No valid domains found in input file");
                bail!(AppExitCode(1));
            }
            domains
        }
        Err(e) => {
            logger.error(&format!("Failed to parse input file: {}", e));
            bail!(AppExitCode(1));
        }
    };

    println!("Loaded {} domains from input file", domains.len());
    println!();

    let batch_output_dir = match &args.batch_output_dir {
        Some(dir) => PathBuf::from(dir),
        None => {
            let base = Args::get_default_output_dir().unwrap_or_else(|_| ".".to_string());
            PathBuf::from(base).join("batch_reports")
        }
    };

    if let Err(e) = std::fs::create_dir_all(&batch_output_dir) {
        logger.error(&format!("Failed to create batch output directory: {}", e));
        bail!(AppExitCode(1));
    }

    println!("Batch output directory: {}", batch_output_dir.display());
    println!("Parallel domains: {}", args.batch_parallel);
    println!("Output format: {}", args.output_format);
    if args.batch_combined {
        println!("Mode: Combined report");
    } else {
        println!("Mode: Individual reports per domain");
    }
    println!();

    print!("Press Enter to start batch analysis or Ctrl+C to cancel: ");
    io::Write::flush(&mut io::stdout()).unwrap();
    let mut line_buf = String::new();
    let _ = input.read_line(&mut line_buf);
    println!();

    let mut summary = new_batch_summary();
    let batch_start = std::time::Instant::now();

    let all_results: Arc<Mutex<Vec<VendorRelationship>>> = Arc::new(Mutex::new(Vec::new()));

    println!("Starting batch analysis of {} domains...", domains.len());
    println!();

    let batch_semaphore = Arc::new(Semaphore::new(args.batch_parallel));
    let domains_arc = Arc::new(domains);
    let total_domains = domains_arc.len();

    let domain_stream = stream::iter(domains_arc.iter().enumerate().map(|(index, entry)| {
        let batch_sem = batch_semaphore.clone();
        let output_dir = batch_output_dir.clone();
        let output_format = args.output_format.clone();
        let logger = logger.clone();
        let all_results = all_results.clone();
        let batch_combined = args.batch_combined;
        let app_config = app_config.clone();
        let args_depth = args.depth;
        let args_parallel_jobs = args.parallel_jobs;
        let entry = entry.clone();

        async move {
            let _permit = batch_sem.acquire().await.unwrap();
            let domain_start = std::time::Instant::now();

            println!(
                "[{}/{}] Starting analysis: {} {}",
                index + 1,
                total_domains,
                entry.domain,
                entry
                    .label
                    .as_ref()
                    .map(|l| format!("({})", l))
                    .unwrap_or_default()
            );

            let result = analyze_single_domain_for_batch(
                &entry,
                &output_dir,
                &output_format,
                batch_combined,
                &app_config,
                args_depth,
                args_parallel_jobs,
                logger.clone(),
            )
            .await;

            let duration = domain_start.elapsed().as_secs_f64();

            match result {
                Ok((relationships, output_file)) => {
                    let count = relationships.len();

                    if batch_combined {
                        let mut all = all_results.lock().await;
                        all.extend(relationships);
                    }

                    println!(
                        "[{}/{}] Completed: {} - {} relationships in {:.1}s",
                        index + 1,
                        total_domains,
                        entry.domain,
                        count,
                        duration
                    );

                    DomainAnalysisResult {
                        domain: entry.domain.clone(),
                        label: entry.label.clone(),
                        success: true,
                        error: None,
                        relationship_count: count,
                        output_file,
                        duration_secs: duration,
                    }
                }
                Err(e) => {
                    println!(
                        "[{}/{}] Failed: {} - {} ({:.1}s)",
                        index + 1,
                        total_domains,
                        entry.domain,
                        e,
                        duration
                    );

                    DomainAnalysisResult {
                        domain: entry.domain.clone(),
                        label: entry.label.clone(),
                        success: false,
                        error: Some(e.to_string()),
                        relationship_count: 0,
                        output_file: None,
                        duration_secs: duration,
                    }
                }
            }
        }
    }));

    let results: Vec<DomainAnalysisResult> = domain_stream
        .buffer_unordered(args.batch_parallel)
        .collect()
        .await;

    summary.domain_results = results;
    summary.total_duration_secs = batch_start.elapsed().as_secs_f64();
    finalize_batch_summary(&mut summary);

    println!();
    println!("========================================================================");
    println!("                       BATCH ANALYSIS COMPLETE                          ");
    println!("========================================================================");
    println!();
    println!("Summary:");
    println!("   Total domains:       {}", summary.total_domains);
    println!("   Successful:          {}", summary.successful);
    println!("   Failed:              {}", summary.failed);
    println!("   Total relationships: {}", summary.total_relationships);
    println!(
        "   Total duration:      {:.1}s",
        summary.total_duration_secs
    );
    println!();

    if args.batch_combined {
        let combined_filename = format!("Combined_Nth_Party_Analysis.{}", args.output_format);
        let combined_path = batch_output_dir.join(&combined_filename);

        let all_relationships = all_results.lock().await;

        let export_relationships: Vec<VendorRelationship> = if args.include_infra {
            all_relationships.clone()
        } else {
            all_relationships
                .iter()
                .filter(|r| !analysis::is_common_denominator(&r.nth_party_domain))
                .cloned()
                .collect()
        };

        match args.output_format.as_str() {
            "json" => export::export_json(&export_relationships, &combined_path.to_string_lossy())?,
            "markdown" => {
                export::export_markdown(&export_relationships, &combined_path.to_string_lossy())?
            }
            "html" => export::export_html(&export_relationships, &combined_path.to_string_lossy())?,
            _ => export::export_csv(&export_relationships, &combined_path.to_string_lossy())?,
        }

        println!("Combined report: {}", combined_path.display());
    }

    let summary_path = batch_output_dir.join("batch_summary.json");
    export_batch_summary(&summary, &summary_path)?;
    println!("Batch summary:   {}", summary_path.display());

    let failed: Vec<_> = summary
        .domain_results
        .iter()
        .filter(|r| !r.success)
        .collect();
    if !failed.is_empty() {
        println!();
        println!("Failed domains:");
        for result in failed {
            println!(
                "   - {}: {}",
                result.domain,
                result.error.as_deref().unwrap_or("Unknown error")
            );
        }
    }

    println!();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn analyze_single_domain_for_batch(
    entry: &batch::DomainEntry,
    output_dir: &Path,
    output_format: &str,
    skip_individual_export: bool,
    app_config: &AppConfig,
    depth: Option<u32>,
    parallel_jobs: usize,
    _logger: Arc<AnalysisLogger>,
) -> Result<(Vec<VendorRelationship>, Option<String>)> {
    let logger = Arc::new(AnalysisLogger::new_with_color_setting(
        VerbosityLevel::Silent,
        false,
    ));

    let discovered_vendors = Arc::new(Mutex::new(HashMap::new()));
    let processed_domains = Arc::new(Mutex::new(HashSet::new()));
    let semaphore = Arc::new(Semaphore::new(parallel_jobs));
    let dns_pool = Arc::new(dns::DnsServerPool::from_config(app_config));
    let recursive_semaphore = Arc::new(Semaphore::new(parallel_jobs.min(10)));

    let root_customer_domain = entry.domain.clone();
    let root_customer_org =
        match whois::get_organization_with_status_and_config(&entry.domain, false, 0.5).await {
            Ok(org_result) => {
                discovered_vendors
                    .lock()
                    .await
                    .insert(entry.domain.clone(), org_result.name.clone());
                org_result.name
            }
            Err(_) => entry.domain.clone(),
        };

    let verification_logger = verification_logger::VerificationFailureLogger::new(
        &output_dir.to_string_lossy(),
        &entry.domain,
        false,
    );

    let results = analysis::discover_nth_parties_minimal(
        &entry.domain,
        depth,
        discovered_vendors,
        processed_domains,
        semaphore,
        1,
        &root_customer_domain,
        &root_customer_org,
        &verification_logger,
        dns_pool,
        recursive_semaphore,
        parallel_jobs,
        logger.clone(),
        &app_config.analysis,
    )
    .await?;

    let output_file = if !skip_individual_export && !results.is_empty() {
        let filename = batch::domain_output_filename(&entry.domain, output_format);
        let domain_dir = output_dir.join(entry.domain.replace('.', "_"));
        std::fs::create_dir_all(&domain_dir)?;
        let output_path = domain_dir.join(&filename);

        match output_format {
            "json" => export::export_json(&results, &output_path.to_string_lossy())?,
            "markdown" => export::export_markdown(&results, &output_path.to_string_lossy())?,
            "html" => export::export_html(&results, &output_path.to_string_lossy())?,
            _ => export::export_csv(&results, &output_path.to_string_lossy())?,
        }

        Some(output_path.to_string_lossy().to_string())
    } else {
        None
    };

    Ok((results, output_file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_CONFIG;
    use crate::vendor::RecordType;

    /// Helper: build a default Args with all fields zeroed/false.
    fn default_args() -> Args {
        Args {
            init: false,
            domain: None,
            depth: None,
            output_format: "csv".to_string(),
            output_dir: None,
            output: "nth_parties".to_string(),
            verbose: 0,
            parallel_jobs: 4,
            log_verification_failures: false,
            enable_subprocessor_analysis: false,
            disable_subprocessor_analysis: false,
            enable_subdomain_discovery: false,
            disable_subdomain_discovery: false,
            enable_saas_tenant_discovery: false,
            disable_saas_tenant_discovery: false,
            enable_ct_discovery: false,
            disable_ct_discovery: false,
            enable_web_traffic_discovery: false,
            disable_web_traffic_discovery: false,
            subfinder_path: None,
            parallel_discovery: false,
            log_file: None,
            enable_slm: false,
            disable_slm: false,
            enable_web_org: false,
            disable_web_org: false,
            no_color: false,
            dns_rate_limit: None,
            http_rate_limit: None,
            backoff_strategy: None,
            max_retries: None,
            whois_concurrency: None,
            timeout: None,
            resume: false,
            no_resume: false,
            include_infra: false,
            dns_only: false,
            input_file: None,
            batch_output_dir: None,
            batch_parallel: 1,
            batch_combined: false,
        }
    }

    /// Helper: build a default AppConfig from the embedded TOML.
    fn default_config() -> AppConfig {
        toml::from_str(DEFAULT_CONFIG).expect("DEFAULT_CONFIG should parse")
    }

    /// Helper: create a VendorRelationship with the given fields.
    fn make_relationship(
        domain: &str,
        org: &str,
        customer_domain: &str,
        record_type: RecordType,
        evidence: &str,
    ) -> VendorRelationship {
        VendorRelationship::new(
            domain.to_string(),
            org.to_string(),
            1,
            customer_domain.to_string(),
            "Customer Org".to_string(),
            "record".to_string(),
            record_type,
            "root.com".to_string(),
            "Root Org".to_string(),
            evidence.to_string(),
        )
    }

    // ── build_output_filename ──────────────────────────────────────────

    #[test]
    fn test_build_output_filename_default_csv() {
        let name = build_output_filename("nth_parties", "csv", "example.com");
        assert_eq!(name, "Nth Party Analysis for example.com.csv");
    }

    #[test]
    fn test_build_output_filename_default_json() {
        let name = build_output_filename("nth_parties", "json", "example.com");
        assert_eq!(name, "Nth Party Analysis for example.com.json");
    }

    #[test]
    fn test_build_output_filename_default_html() {
        let name = build_output_filename("nth_parties", "html", "example.com");
        assert_eq!(name, "Nth Party Analysis for example.com.html");
    }

    #[test]
    fn test_build_output_filename_default_markdown() {
        let name = build_output_filename("nth_parties", "markdown", "example.com");
        assert_eq!(name, "Nth Party Analysis for example.com.md");
    }

    #[test]
    fn test_build_output_filename_custom_name_no_extension() {
        let name = build_output_filename("my_report", "json", "example.com");
        assert_eq!(name, "my_report.json");
    }

    #[test]
    fn test_build_output_filename_custom_name_with_extension() {
        let name = build_output_filename("report.xlsx", "json", "example.com");
        assert_eq!(name, "report.xlsx");
    }

    #[test]
    fn test_build_output_filename_unknown_format_falls_to_csv() {
        let name = build_output_filename("nth_parties", "xml", "test.org");
        assert_eq!(name, "Nth Party Analysis for test.org.csv");
    }

    // ── compute_feature_flags ──────────────────────────────────────────

    #[test]
    fn test_feature_flags_all_default() {
        let args = default_args();
        let config = default_config();
        let flags = compute_feature_flags(&args, &config);

        // With default config, subprocessor is enabled but most others are not
        assert_eq!(flags.subprocessor, config.discovery.subprocessor_enabled);
        assert_eq!(flags.subdomain, config.discovery.subdomain_enabled);
        assert_eq!(flags.saas_tenant, config.discovery.saas_tenant_enabled);
        assert_eq!(flags.ct_discovery, config.discovery.ct_discovery_enabled);
        assert_eq!(flags.web_org, config.discovery.web_org_enabled);
        assert_eq!(flags.web_traffic, config.discovery.web_traffic_enabled);
    }

    #[test]
    fn test_feature_flags_dns_only_disables_all() {
        let mut args = default_args();
        args.dns_only = true;
        // Even if config enables them all
        let config = default_config();
        let flags = compute_feature_flags(&args, &config);

        assert!(!flags.web_org);
        assert!(!flags.subprocessor);
        assert!(!flags.subdomain);
        assert!(!flags.saas_tenant);
        assert!(!flags.web_traffic);
        assert!(!flags.ct_discovery);
    }

    #[test]
    fn test_feature_flags_explicit_enable_overrides_config() {
        let mut args = default_args();
        args.enable_subdomain_discovery = true;
        args.enable_saas_tenant_discovery = true;
        args.enable_ct_discovery = true;
        args.enable_web_traffic_discovery = true;
        args.enable_web_org = true;
        args.enable_subprocessor_analysis = true;
        let config = default_config();
        let flags = compute_feature_flags(&args, &config);

        assert!(flags.web_org);
        assert!(flags.subprocessor);
        assert!(flags.subdomain);
        assert!(flags.saas_tenant);
        assert!(flags.web_traffic);
        assert!(flags.ct_discovery);
    }

    #[test]
    fn test_feature_flags_explicit_disable_overrides_config() {
        let mut args = default_args();
        args.disable_subprocessor_analysis = true;
        args.disable_web_org = true;
        let config = default_config();
        let flags = compute_feature_flags(&args, &config);

        assert!(!flags.subprocessor);
        assert!(!flags.web_org);
    }

    #[test]
    fn test_feature_flags_dns_only_trumps_explicit_enable() {
        let mut args = default_args();
        args.dns_only = true;
        args.enable_subdomain_discovery = true;
        args.enable_web_org = true;
        let config = default_config();
        let flags = compute_feature_flags(&args, &config);

        assert!(!flags.subdomain);
        assert!(!flags.web_org);
    }

    // ── deduplicate_results ────────────────────────────────────────────

    #[test]
    fn test_deduplicate_empty() {
        let (deduped, raw) = deduplicate_results(vec![]);
        assert_eq!(deduped.len(), 0);
        assert_eq!(raw, 0);
    }

    #[test]
    fn test_deduplicate_no_duplicates() {
        let results = vec![
            make_relationship(
                "stripe.com",
                "Stripe",
                "example.com",
                RecordType::DnsTxtSpf,
                "spf record",
            ),
            make_relationship(
                "google.com",
                "Google",
                "example.com",
                RecordType::DnsTxtSpf,
                "spf include",
            ),
        ];
        let (deduped, raw) = deduplicate_results(results);
        assert_eq!(deduped.len(), 2);
        assert_eq!(raw, 2);
    }

    #[test]
    fn test_deduplicate_merges_evidence() {
        let results = vec![
            make_relationship(
                "stripe.com",
                "Stripe",
                "example.com",
                RecordType::DnsTxtSpf,
                "evidence-A",
            ),
            make_relationship(
                "stripe.com",
                "Stripe",
                "example.com",
                RecordType::DnsTxtSpf,
                "evidence-B",
            ),
        ];
        let (deduped, raw) = deduplicate_results(results);
        assert_eq!(deduped.len(), 1);
        assert_eq!(raw, 2);
        assert!(deduped[0].evidence.contains("evidence-A"));
        assert!(deduped[0].evidence.contains("evidence-B"));
    }

    #[test]
    fn test_deduplicate_does_not_merge_duplicate_evidence() {
        let results = vec![
            make_relationship(
                "stripe.com",
                "Stripe",
                "example.com",
                RecordType::DnsTxtSpf,
                "same-evidence",
            ),
            make_relationship(
                "stripe.com",
                "Stripe",
                "example.com",
                RecordType::DnsTxtSpf,
                "same-evidence",
            ),
        ];
        let (deduped, _raw) = deduplicate_results(results);
        assert_eq!(deduped.len(), 1);
        // Evidence should NOT be duplicated
        assert_eq!(deduped[0].evidence.matches("same-evidence").count(), 1);
    }

    #[test]
    fn test_deduplicate_different_record_types_not_merged() {
        let results = vec![
            make_relationship(
                "stripe.com",
                "Stripe",
                "example.com",
                RecordType::DnsTxtSpf,
                "ev1",
            ),
            make_relationship(
                "stripe.com",
                "Stripe",
                "example.com",
                RecordType::HttpSubprocessor,
                "ev2",
            ),
        ];
        let (deduped, _raw) = deduplicate_results(results);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_deduplicate_different_customers_not_merged() {
        let results = vec![
            make_relationship(
                "stripe.com",
                "Stripe",
                "customer-a.com",
                RecordType::DnsTxtSpf,
                "ev1",
            ),
            make_relationship(
                "stripe.com",
                "Stripe",
                "customer-b.com",
                RecordType::DnsTxtSpf,
                "ev2",
            ),
        ];
        let (deduped, _raw) = deduplicate_results(results);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_deduplicate_preserves_order_of_first_occurrence() {
        let results = vec![
            make_relationship(
                "aaa.com",
                "AAA",
                "example.com",
                RecordType::DnsTxtSpf,
                "first",
            ),
            make_relationship(
                "bbb.com",
                "BBB",
                "example.com",
                RecordType::DnsTxtSpf,
                "second",
            ),
            make_relationship(
                "aaa.com",
                "AAA",
                "example.com",
                RecordType::DnsTxtSpf,
                "third",
            ),
        ];
        let (deduped, _raw) = deduplicate_results(results);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].nth_party_domain, "aaa.com");
        assert_eq!(deduped[1].nth_party_domain, "bbb.com");
    }

    // ── filter_infra_providers ─────────────────────────────────────────

    #[test]
    fn test_filter_infra_include_infra_returns_all() {
        let results = vec![
            make_relationship(
                "amazonaws.com",
                "Amazon",
                "example.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
            make_relationship(
                "stripe.com",
                "Stripe",
                "example.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
        ];
        let (filtered, removed) = filter_infra_providers(results, true);
        assert_eq!(filtered.len(), 2);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_filter_infra_removes_common_providers() {
        let results = vec![
            make_relationship(
                "amazonaws.com",
                "Amazon",
                "example.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
            make_relationship(
                "google.com",
                "Google",
                "example.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
            make_relationship(
                "stripe.com",
                "Stripe",
                "example.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
        ];
        let (filtered, removed) = filter_infra_providers(results, false);
        assert_eq!(filtered.len(), 1);
        assert_eq!(removed, 2);
        assert_eq!(filtered[0].nth_party_domain, "stripe.com");
    }

    #[test]
    fn test_filter_infra_empty_input() {
        let (filtered, removed) = filter_infra_providers(vec![], false);
        assert_eq!(filtered.len(), 0);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_filter_infra_all_infra() {
        let results = vec![
            make_relationship(
                "amazonaws.com",
                "Amazon",
                "example.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
            make_relationship(
                "cloudflare.com",
                "Cloudflare",
                "example.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
        ];
        let (filtered, removed) = filter_infra_providers(results, false);
        assert_eq!(filtered.len(), 0);
        assert_eq!(removed, 2);
    }

    #[test]
    fn test_filter_infra_no_infra() {
        let results = vec![
            make_relationship(
                "stripe.com",
                "Stripe",
                "example.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
            make_relationship(
                "pendo.io",
                "Pendo",
                "example.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
        ];
        let (filtered, removed) = filter_infra_providers(results, false);
        assert_eq!(filtered.len(), 2);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_filter_infra_subdomain_of_infra() {
        let results = vec![make_relationship(
            "s3.amazonaws.com",
            "Amazon",
            "example.com",
            RecordType::DnsTxtSpf,
            "ev",
        )];
        let (filtered, removed) = filter_infra_providers(results, false);
        assert_eq!(filtered.len(), 0);
        assert_eq!(removed, 1);
    }

    // ── FeatureFlags struct ────────────────────────────────────────────

    #[test]
    fn test_feature_flags_equality() {
        let a = FeatureFlags {
            web_org: true,
            subprocessor: false,
            subdomain: true,
            saas_tenant: false,
            web_traffic: true,
            ct_discovery: false,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_feature_flags_debug() {
        let flags = FeatureFlags {
            web_org: true,
            subprocessor: false,
            subdomain: false,
            saas_tenant: false,
            web_traffic: false,
            ct_discovery: false,
        };
        let debug_str = format!("{:?}", flags);
        assert!(debug_str.contains("web_org: true"));
        assert!(debug_str.contains("subprocessor: false"));
    }

    // ── compute_analysis_timeout ──────────────────────────────────────

    #[test]
    fn test_compute_analysis_timeout_with_cli_value() {
        let timeout = compute_analysis_timeout_with_env(Some(120), None);
        assert_eq!(timeout, Some(std::time::Duration::from_secs(120)));
    }

    #[test]
    fn test_compute_analysis_timeout_zero_disables() {
        let timeout = compute_analysis_timeout_with_env(Some(0), None);
        assert_eq!(timeout, None);
    }

    #[test]
    fn test_compute_analysis_timeout_none_uses_default() {
        // Without env var, defaults to 600
        let timeout = compute_analysis_timeout_with_env(None, None);
        assert_eq!(timeout, Some(std::time::Duration::from_secs(600)));
    }

    #[test]
    fn test_compute_analysis_timeout_env_override() {
        let timeout = compute_analysis_timeout_with_env(None, Some("300".to_string()));
        assert_eq!(timeout, Some(std::time::Duration::from_secs(300)));
    }

    #[test]
    fn test_compute_analysis_timeout_env_invalid_uses_default() {
        let timeout = compute_analysis_timeout_with_env(None, Some("notanumber".to_string()));
        assert_eq!(timeout, Some(std::time::Duration::from_secs(600)));
    }

    #[test]
    fn test_compute_analysis_timeout_cli_overrides_env() {
        let timeout = compute_analysis_timeout_with_env(Some(42), Some("999".to_string()));
        assert_eq!(timeout, Some(std::time::Duration::from_secs(42)));
    }

    #[test]
    fn test_compute_analysis_timeout_env_zero_disables() {
        let timeout = compute_analysis_timeout_with_env(None, Some("0".to_string()));
        assert_eq!(timeout, None);
    }

    #[test]
    fn test_compute_analysis_timeout_env_empty_string_uses_default() {
        let timeout = compute_analysis_timeout_with_env(None, Some("".to_string()));
        assert_eq!(timeout, Some(std::time::Duration::from_secs(600)));
    }

    // ── build_full_output_path ────────────────────────────────────────

    #[test]
    fn test_build_full_output_path_simple() {
        let path = build_full_output_path("/tmp/output", "report.csv");
        assert_eq!(path, PathBuf::from("/tmp/output/report.csv"));
    }

    #[test]
    fn test_build_full_output_path_with_spaces() {
        let path = build_full_output_path(
            "/home/user/My Documents",
            "Nth Party Analysis for test.com.html",
        );
        assert_eq!(
            path,
            PathBuf::from("/home/user/My Documents/Nth Party Analysis for test.com.html")
        );
    }

    #[test]
    fn test_build_full_output_path_current_dir() {
        let path = build_full_output_path(".", "report.json");
        assert_eq!(path, PathBuf::from("./report.json"));
    }

    #[test]
    fn test_build_full_output_path_nested_dir() {
        let path = build_full_output_path("/var/output/nthparty/scans", "result.csv");
        assert_eq!(path, PathBuf::from("/var/output/nthparty/scans/result.csv"));
    }

    // ── resolve_checkpoint_resume ─────────────────────────────────────

    #[test]
    fn test_resolve_checkpoint_auto_resume_compatible() {
        let result = resolve_checkpoint_resume(&ResumeMode::AutoResume, true, true);
        assert_eq!(result, Some(true));
    }

    #[test]
    fn test_resolve_checkpoint_auto_resume_incompatible() {
        let result = resolve_checkpoint_resume(&ResumeMode::AutoResume, false, true);
        assert_eq!(result, Some(false));
    }

    #[test]
    fn test_resolve_checkpoint_fresh_always_false() {
        assert_eq!(
            resolve_checkpoint_resume(&ResumeMode::Fresh, true, true),
            Some(false)
        );
        assert_eq!(
            resolve_checkpoint_resume(&ResumeMode::Fresh, false, true),
            Some(false)
        );
        assert_eq!(
            resolve_checkpoint_resume(&ResumeMode::Fresh, true, false),
            Some(false)
        );
    }

    #[test]
    fn test_resolve_checkpoint_prompt_non_interactive_compatible() {
        let result = resolve_checkpoint_resume(&ResumeMode::Prompt, true, false);
        assert_eq!(result, Some(true));
    }

    #[test]
    fn test_resolve_checkpoint_prompt_non_interactive_incompatible() {
        let result = resolve_checkpoint_resume(&ResumeMode::Prompt, false, false);
        assert_eq!(result, Some(false));
    }

    #[test]
    fn test_resolve_checkpoint_prompt_interactive_returns_none() {
        // Interactive mode returns None to signal that caller needs to prompt user
        let result = resolve_checkpoint_resume(&ResumeMode::Prompt, true, true);
        assert_eq!(result, None);
        let result = resolve_checkpoint_resume(&ResumeMode::Prompt, false, true);
        assert_eq!(result, None);
    }

    // ── collect_unverified_orgs ───────────────────────────────────────

    #[test]
    fn test_collect_unverified_orgs_empty() {
        let vendors: HashMap<String, String> = HashMap::new();
        let result = collect_unverified_orgs(&vendors);
        assert!(result.is_empty());
    }

    #[test]
    fn test_collect_unverified_orgs_inferred() {
        let mut vendors = HashMap::new();
        vendors.insert("acme.com".to_string(), "acme inc.".to_string());
        vendors.insert("test.org".to_string(), "test".to_string());
        let result = collect_unverified_orgs(&vendors);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_collect_unverified_orgs_real_company_not_inferred() {
        let mut vendors = HashMap::new();
        vendors.insert("google.com".to_string(), "Alphabet Inc.".to_string());
        vendors.insert(
            "github.com".to_string(),
            "Microsoft Corporation".to_string(),
        );
        let result = collect_unverified_orgs(&vendors);
        assert!(result.is_empty());
    }

    #[test]
    fn test_collect_unverified_orgs_mixed() {
        let mut vendors = HashMap::new();
        vendors.insert("acme.com".to_string(), "acme inc.".to_string()); // inferred
        vendors.insert("google.com".to_string(), "Alphabet Inc.".to_string()); // not inferred
        let result = collect_unverified_orgs(&vendors);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].domain, "acme.com");
    }

    #[test]
    fn test_collect_unverified_orgs_domain_as_org() {
        let mut vendors = HashMap::new();
        vendors.insert("example.com".to_string(), "example.com".to_string());
        let result = collect_unverified_orgs(&vendors);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].domain, "example.com");
        assert_eq!(result[0].inferred_org, "example.com");
    }

    // ── AppExitCode ──────────────────────────────────────────────────

    #[test]
    fn test_app_exit_code_display() {
        let code = AppExitCode(42);
        assert_eq!(format!("{}", code), "exit code 42");
    }

    #[test]
    fn test_app_exit_code_display_zero() {
        let code = AppExitCode(0);
        assert_eq!(format!("{}", code), "exit code 0");
    }

    #[test]
    fn test_app_exit_code_is_error() {
        let code = AppExitCode(1);
        let err: &dyn std::error::Error = &code;
        assert_eq!(err.to_string(), "exit code 1");
    }

    // ── compute_analysis_timeout (outer function) ────────────────────

    #[test]
    fn test_compute_analysis_timeout_outer_returns_some() {
        // The outer function reads env var; without it set, defaults to 600s
        let timeout = compute_analysis_timeout(Some(300));
        assert_eq!(timeout, Some(std::time::Duration::from_secs(300)));
    }

    #[test]
    fn test_compute_analysis_timeout_outer_zero_disables() {
        let timeout = compute_analysis_timeout(Some(0));
        assert_eq!(timeout, None);
    }

    #[test]
    fn test_compute_analysis_timeout_outer_none_uses_default() {
        // Without env var set, defaults to 600
        let timeout = compute_analysis_timeout(None);
        // Will be 600 unless NTHPARTY_ANALYSIS_TIMEOUT_SECS is set in env
        assert!(timeout.is_some());
    }
}
