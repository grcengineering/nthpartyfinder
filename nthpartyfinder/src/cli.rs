use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "nthpartyfinder")]
#[command(
    about = "Discover Nth-party vendor relationships via DNS analysis and optional extended discovery methods"
)]
#[command(
    long_about = "Discover Nth-party vendor relationships via DNS analysis and optional extended discovery methods.\n\n\
Discovery methods:\n  \
DNS (always on)      SPF/DMARC/DKIM/MX/NS/CNAME/verification TXT records\n  \
Subprocessor         Scrapes vendor/subprocessor pages linked from trust centers\n  \
Web Traffic          Analyzes page source and runtime network requests for 3rd-party SDKs\n  \
SaaS Tenant          Probes for SaaS tenant subdomains (e.g., company.slack.com)\n  \
Subfinder            Subdomain enumeration via CNAME discovery\n  \
CT Logs              Certificate Transparency log analysis\n\n\
Non-DNS methods are controlled by config or --enable/--disable flags.\n\
Use --dns-only to disable all non-DNS discovery methods."
)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    // Global flags that work without subcommand (for backward compatibility)
    /// Create default configuration file at ./config/nthpartyfinder.toml
    #[arg(long, global = true)]
    pub init: bool,

    /// Domain name to analyze for Nth party relationships (shorthand for 'analyze' subcommand)
    #[arg(short, long)]
    pub domain: Option<String>,

    /// Maximum recursion depth (if not specified, will recurse until no more vendors found)
    #[arg(short = 'r', long, value_name = "DEPTH")]
    pub depth: Option<u32>,

    /// Output format: 'csv' (default), 'json', 'markdown', or 'html'
    #[arg(short = 'f', long, default_value = "csv")]
    pub output_format: String,

    /// Output directory for results file (defaults to Desktop)
    #[arg(long)]
    pub output_dir: Option<String>,

    /// Output filename (extension will be set based on format if not provided)
    #[arg(short, long, default_value = "nth_parties")]
    pub output: String,

    /// Verbose logging (use -v for INFO, -vv for DEBUG with record details)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Maximum vendor analyses in flight, as a cap on the per-depth concurrency configured
    /// in `analysis.concurrency_per_depth`. `0` (the default) means "no extra cap" — the
    /// configured per-depth values apply as written.
    ///
    /// Request pacing is NOT controlled by this flag: the DNS, HTTP-per-domain, and WHOIS
    /// token buckets are global and enforce politeness regardless of how many analyses are
    /// in flight. Lower this only to bound local CPU/memory use.
    #[arg(short = 'j', long, default_value = "0")]
    pub parallel_jobs: usize,

    /// Log failed verification record inferences to a separate file
    #[arg(long, default_value = "false")]
    pub log_verification_failures: bool,

    /// Enable subprocessor web page analysis for enhanced vendor discovery
    #[arg(long)]
    pub enable_subprocessor_analysis: bool,

    /// Disable subprocessor analysis (overrides config)
    #[arg(long)]
    pub disable_subprocessor_analysis: bool,

    /// Enable subdomain discovery via subfinder
    #[arg(long)]
    pub enable_subdomain_discovery: bool,

    /// Disable subdomain discovery (overrides config)
    #[arg(long)]
    pub disable_subdomain_discovery: bool,

    /// Enable SaaS tenant discovery
    #[arg(long)]
    pub enable_saas_tenant_discovery: bool,

    /// Disable SaaS tenant discovery (overrides config)
    #[arg(long)]
    pub disable_saas_tenant_discovery: bool,

    /// Enable Certificate Transparency (CT) log discovery
    #[arg(long)]
    pub enable_ct_discovery: bool,

    /// Disable CT log discovery (overrides config)
    #[arg(long)]
    pub disable_ct_discovery: bool,

    /// Enable Web Traffic & Components discovery (analyzes page source and runtime network traffic)
    #[arg(long)]
    pub enable_web_traffic_discovery: bool,

    /// Disable Web Traffic & Components discovery (overrides config)
    #[arg(long)]
    pub disable_web_traffic_discovery: bool,

    /// Path to subfinder binary
    #[arg(long)]
    pub subfinder_path: Option<String>,

    /// Run all discovery methods in parallel
    #[arg(long)]
    pub parallel_discovery: bool,

    /// Export execution logs to a file (specify file path)
    #[arg(long)]
    pub log_file: Option<String>,

    /// Enable NER (Named Entity Recognition) for organization name extraction
    /// Requires compilation with --features embedded-ner
    #[arg(long)]
    pub enable_slm: bool,

    /// Disable NER organization extraction (overrides config).
    /// Opts out of NER entirely — no model is fetched and no prompt is shown.
    #[arg(long)]
    pub disable_slm: bool,

    /// Consent to download the runtime NER model (~183 MB) without prompting.
    /// For non-interactive/CI/headless use with the default `runtime-ner` build:
    /// the model is fetched from grcengineering/nthpartyfinder and SHA-256
    /// verified before use. Without this flag, an interactive terminal is
    /// prompted; a non-interactive session skips NER (use --disable-slm to opt
    /// out entirely). No effect on `embedded-ner` builds (model is bundled).
    #[arg(long)]
    pub download_ner_model: bool,

    /// Enable web page analysis for organization name extraction
    /// Uses Schema.org, OpenGraph, and meta tags with headless browser fallback for SPAs
    #[arg(long)]
    pub enable_web_org: bool,

    /// Disable web page analysis for organization extraction (overrides config)
    #[arg(long)]
    pub disable_web_org: bool,

    /// Disable colored output (also respects NO_COLOR environment variable)
    #[arg(long)]
    pub no_color: bool,

    /// Maximum DNS queries per second (0 = unlimited, overrides config)
    #[arg(long, value_name = "QPS")]
    pub dns_rate_limit: Option<u32>,

    /// Maximum HTTP requests per second per domain (0 = unlimited, overrides config)
    #[arg(long, value_name = "RPS")]
    pub http_rate_limit: Option<u32>,

    /// Backoff strategy for retries: "linear" or "exponential" (overrides config)
    #[arg(long, value_name = "STRATEGY")]
    pub backoff_strategy: Option<String>,

    /// Maximum retry attempts for failed requests (overrides config)
    #[arg(long, value_name = "COUNT")]
    pub max_retries: Option<u32>,

    /// Maximum concurrent WHOIS/organization lookups (default: 5)
    /// Higher values speed up organization resolution but may overwhelm WHOIS servers
    #[arg(long, value_name = "CONCURRENCY")]
    pub whois_concurrency: Option<usize>,

    /// Analysis timeout in seconds (default: 600). Use 0 for no timeout.
    /// Overrides NTHPARTY_ANALYSIS_TIMEOUT_SECS environment variable.
    /// The default suits a depth-1 scan; depth 3+ or cold-cache runs routinely
    /// exceed 600s (e.g. ~1500-3000s), so raise this (e.g. --timeout 1800) or
    /// disable it (--timeout 0) for deep scans. The output format does not
    /// change discovery time. On timeout the scan exits non-zero with a
    /// checkpoint rather than emitting an empty report.
    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<u64>,

    /// Auto-resume from checkpoint if one exists (skip resume prompt)
    #[arg(long, conflicts_with = "no_resume")]
    pub resume: bool,

    /// Start fresh analysis, ignore any existing checkpoint
    #[arg(long, conflicts_with = "resume")]
    pub no_resume: bool,

    /// Include common infrastructure providers (AWS, Google, Cloudflare, etc.) in results.
    /// By default, these are filtered from output to reduce noise.
    #[arg(long)]
    pub include_infra: bool,

    /// DNS-only mode: disable all non-DNS discovery methods (subprocessor, web traffic,
    /// SaaS tenant, subfinder, CT logs). Equivalent to passing all --disable-* flags.
    #[arg(long)]
    pub dns_only: bool,

    // ============ Batch Analysis Options ============
    /// Path to CSV or JSON file containing multiple domains to analyze
    /// CSV: One domain per line, or column named "domain" (with optional "label" column)
    /// JSON: Array of domain strings, or array of objects with "domain" field
    #[arg(long, value_name = "FILE")]
    pub input_file: Option<String>,

    /// Output directory for batch analysis results
    /// Each domain gets its own output file, plus a summary file
    #[arg(long, value_name = "DIR")]
    pub batch_output_dir: Option<String>,

    /// Number of domains to analyze in parallel during batch processing (default: 1)
    /// Higher values speed up batch analysis but increase resource usage
    #[arg(long, value_name = "N", default_value = "1")]
    pub batch_parallel: usize,

    /// Generate a single combined report with all domains instead of individual files
    #[arg(long)]
    pub batch_combined: bool,

    /// Emit the scan's uncertain domain↔org mappings (the set normally shown in the
    /// interactive review prompt) to this JSON file, non-interactively — enabling the
    /// Claude plugin / automation to validate and apply corrections. Does not change
    /// the normal scan output.
    #[arg(long, value_name = "FILE", global = true)]
    pub review_json: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage the subprocessor URL cache
    Cache {
        #[command(subcommand)]
        action: CacheCommands,
    },

    /// Validate and apply domain→org mapping decisions non-interactively
    /// (the Claude plugin contract: the sole safe writer of local overrides).
    Review {
        #[command(subcommand)]
        action: ReviewCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum CacheCommands {
    /// List all cached domains
    List,

    /// Show cache entry details for a specific domain
    Show {
        /// Domain to show cache details for
        domain: String,
    },

    /// Clear cache for a specific domain or all domains
    Clear {
        /// Domain to clear cache for (omit to use --all)
        domain: Option<String>,

        /// Clear cache for all domains
        #[arg(long)]
        all: bool,
    },

    /// Validate all cached URLs still work
    Validate {
        /// Show detailed validation results
        #[arg(long)]
        detailed: bool,

        /// Only validate specific domain
        #[arg(short, long)]
        domain: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ReviewCommands {
    /// Apply a validated decisions JSON — the SOLE writer of local overrides.
    Apply {
        /// Path to the decisions JSON (produced after independent validation)
        #[arg(long, visible_alias = "in", value_name = "FILE")]
        input: String,

        /// Show what would change without writing anything
        #[arg(long)]
        dry_run: bool,
    },

    /// Print the resolved local-overrides store path (where the next scan reads)
    Path,

    /// List local overrides, optionally filtered to a single provenance source
    List {
        /// Only show overrides whose source matches (e.g. claude_verified)
        #[arg(long)]
        source: Option<String>,
    },

    /// Remove a local override (revert an accepted mapping)
    Revert {
        /// Domain whose override should be removed
        domain: String,
    },
}

// Keep Args as a compatibility layer for existing code
#[derive(Debug)]
pub struct Args {
    pub init: bool,
    pub domain: Option<String>,
    pub depth: Option<u32>,
    pub output_format: String,
    pub output_dir: Option<String>,
    pub output: String,
    pub verbose: u8,
    pub parallel_jobs: usize,
    pub log_verification_failures: bool,
    pub enable_subprocessor_analysis: bool,
    pub disable_subprocessor_analysis: bool,
    pub enable_subdomain_discovery: bool,
    pub disable_subdomain_discovery: bool,
    pub enable_saas_tenant_discovery: bool,
    pub disable_saas_tenant_discovery: bool,
    pub enable_ct_discovery: bool,
    pub disable_ct_discovery: bool,
    pub enable_web_traffic_discovery: bool,
    pub disable_web_traffic_discovery: bool,
    pub subfinder_path: Option<String>,
    pub parallel_discovery: bool,
    pub log_file: Option<String>,
    pub enable_slm: bool,
    pub disable_slm: bool,
    pub download_ner_model: bool,
    pub enable_web_org: bool,
    pub disable_web_org: bool,
    pub no_color: bool,
    pub dns_rate_limit: Option<u32>,
    pub http_rate_limit: Option<u32>,
    pub backoff_strategy: Option<String>,
    pub max_retries: Option<u32>,
    pub whois_concurrency: Option<usize>,
    pub timeout: Option<u64>,
    pub resume: bool,
    pub no_resume: bool,
    pub include_infra: bool,
    pub dns_only: bool,
    // Batch options
    pub input_file: Option<String>,
    pub batch_output_dir: Option<String>,
    pub batch_parallel: usize,
    pub batch_combined: bool,
    pub review_json: Option<String>,
}

impl From<&Cli> for Args {
    fn from(cli: &Cli) -> Self {
        Args {
            init: cli.init,
            domain: cli.domain.clone(),
            depth: cli.depth,
            output_format: cli.output_format.clone(),
            output_dir: cli.output_dir.clone(),
            output: cli.output.clone(),
            verbose: cli.verbose,
            parallel_jobs: cli.parallel_jobs,
            log_verification_failures: cli.log_verification_failures,
            enable_subprocessor_analysis: cli.enable_subprocessor_analysis,
            disable_subprocessor_analysis: cli.disable_subprocessor_analysis,
            enable_subdomain_discovery: cli.enable_subdomain_discovery,
            disable_subdomain_discovery: cli.disable_subdomain_discovery,
            enable_saas_tenant_discovery: cli.enable_saas_tenant_discovery,
            disable_saas_tenant_discovery: cli.disable_saas_tenant_discovery,
            enable_ct_discovery: cli.enable_ct_discovery,
            disable_ct_discovery: cli.disable_ct_discovery,
            enable_web_traffic_discovery: cli.enable_web_traffic_discovery,
            disable_web_traffic_discovery: cli.disable_web_traffic_discovery,
            subfinder_path: cli.subfinder_path.clone(),
            parallel_discovery: cli.parallel_discovery,
            log_file: cli.log_file.clone(),
            enable_slm: cli.enable_slm,
            disable_slm: cli.disable_slm,
            download_ner_model: cli.download_ner_model,
            enable_web_org: cli.enable_web_org,
            disable_web_org: cli.disable_web_org,
            no_color: cli.no_color,
            dns_rate_limit: cli.dns_rate_limit,
            http_rate_limit: cli.http_rate_limit,
            backoff_strategy: cli.backoff_strategy.clone(),
            max_retries: cli.max_retries,
            whois_concurrency: cli.whois_concurrency,
            timeout: cli.timeout,
            resume: cli.resume,
            no_resume: cli.no_resume,
            include_infra: cli.include_infra,
            dns_only: cli.dns_only,
            input_file: cli.input_file.clone(),
            batch_output_dir: cli.batch_output_dir.clone(),
            batch_parallel: cli.batch_parallel,
            batch_combined: cli.batch_combined,
            review_json: cli.review_json.clone(),
        }
    }
}

impl Args {
    /// Check if running in batch mode (--input-file provided)
    pub fn is_batch_mode(&self) -> bool {
        self.input_file.is_some()
    }

    pub fn validate(&self) -> Result<(), String> {
        // Domain validation only applies when not using --init, not in batch mode,
        // and no subcommand is active
        if !self.init && !self.is_batch_mode() {
            match &self.domain {
                None => {
                    return Err(
                        "either -d <domain> or --input-file <file> is required. Run with --help for usage."
                            .to_string(),
                    )
                }
                Some(d) if d.is_empty() => return Err("domain cannot be empty".to_string()),
                // Fail fast on malformed domains. Previously `bad..domain!!`
                // sailed through parsing, produced nothing, and burned the full
                // analysis timeout (exit 142) with no message — looking hung.
                Some(d) if !crate::dns::is_valid_domain(d) => {
                    return Err(format!(
                        "'{}' is not a valid domain name (expected a hostname like example.com)",
                        d
                    ))
                }
                _ => {}
            }
        }

        // Batch mode validation
        if self.is_batch_mode() {
            if self.batch_parallel == 0 {
                return Err("--batch-parallel must be >= 1".to_string());
            }
            if self.batch_parallel > 20 {
                return Err(
                    "--batch-parallel cannot exceed 20 to avoid overwhelming target systems"
                        .to_string(),
                );
            }
        }

        if !["csv", "json", "markdown", "html"].contains(&self.output_format.as_str()) {
            return Err("output format must be 'csv', 'json', 'markdown', or 'html'".to_string());
        }

        if let Some(depth) = self.depth {
            if depth == 0 {
                return Err("--depth must be >= 1".to_string());
            }
        }

        // `0` is the default and means "no operator cap" — the configured
        // `analysis.concurrency_per_depth` applies as written. Any positive value narrows it.
        let max_parallel = std::cmp::min(64, Self::num_cpus() * 8);
        if self.parallel_jobs > max_parallel {
            return Err(format!(
                "--parallelism cannot exceed {} (min of 64, num_cpus*8) to avoid overwhelming DNS servers",
                max_parallel
            ));
        }

        Ok(())
    }

    fn num_cpus() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn get_default_output_dir() -> Result<String, String> {
        if let Some(desktop_dir) = dirs::desktop_dir() {
            Ok(desktop_dir.to_string_lossy().to_string())
        } else {
            // Fallback to current directory if Desktop can't be found
            Ok(".".to_string())
        }
    }

    pub fn get_output_dir(&self) -> Result<String, String> {
        match &self.output_dir {
            Some(dir) => Ok(dir.clone()),
            None => Self::get_default_output_dir(),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn get_domain_output_dir(&self) -> Result<String, String> {
        let base_dir = self.get_output_dir()?;
        let domain = self
            .domain
            .as_ref()
            .ok_or("Domain is required for output directory")?;
        let domain_clean = domain.replace(".", "_").replace(":", "_");
        let reports_dir = std::path::Path::new(&base_dir)
            .join("reports")
            .join(&domain_clean);
        Ok(reports_dir.to_string_lossy().to_string())
    }

    /// Get the resume mode based on CLI flags
    pub fn get_resume_mode(&self) -> crate::checkpoint::ResumeMode {
        if self.resume {
            crate::checkpoint::ResumeMode::AutoResume
        } else if self.no_resume {
            crate::checkpoint::ResumeMode::Fresh
        } else {
            crate::checkpoint::ResumeMode::Prompt
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Helper to create a default Args for testing, with a domain set
    fn default_args() -> Args {
        Args {
            init: false,
            domain: Some("example.com".to_string()),
            depth: None,
            output_format: "csv".to_string(),
            output_dir: None,
            output: "nth_parties".to_string(),
            verbose: 0,
            parallel_jobs: 10,
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
            download_ner_model: false,
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
            review_json: None,
        }
    }

    // ---- Cli parsing ----

    #[test]
    fn cli_parse_minimal() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "example.com"]);
        assert_eq!(cli.domain, Some("example.com".to_string()));
        assert_eq!(cli.output_format, "csv");
        // 0 = "no operator cap": the configured `analysis.concurrency_per_depth` applies as
        // written. Before this became the default, `-j` silently clamped every depth to 10 and
        // the shipped per-depth widths were unreachable.
        assert_eq!(cli.parallel_jobs, 0);
        assert!(!cli.init);
    }

    #[test]
    fn cli_parse_all_flags() {
        let cli = Cli::parse_from([
            "nthpartyfinder",
            "-d",
            "test.com",
            "-r",
            "3",
            "-f",
            "json",
            "-o",
            "output_name",
            "-v",
            "-j",
            "5",
            "--log-verification-failures",
            "--enable-subprocessor-analysis",
            "--enable-subdomain-discovery",
            "--enable-saas-tenant-discovery",
            "--enable-ct-discovery",
            "--enable-web-traffic-discovery",
            "--parallel-discovery",
            "--enable-slm",
            "--enable-web-org",
            "--no-color",
            "--dns-rate-limit",
            "100",
            "--http-rate-limit",
            "50",
            "--backoff-strategy",
            "exponential",
            "--max-retries",
            "3",
            "--whois-concurrency",
            "8",
            "--timeout",
            "300",
            "--include-infra",
            "--dns-only",
            "--batch-parallel",
            "5",
            "--batch-combined",
        ]);
        assert_eq!(cli.domain, Some("test.com".to_string()));
        assert_eq!(cli.depth, Some(3));
        assert_eq!(cli.output_format, "json");
        assert_eq!(cli.output, "output_name");
        assert_eq!(cli.verbose, 1);
        assert_eq!(cli.parallel_jobs, 5);
        assert!(cli.log_verification_failures);
        assert!(cli.enable_subprocessor_analysis);
        assert!(cli.enable_subdomain_discovery);
        assert!(cli.enable_saas_tenant_discovery);
        assert!(cli.enable_ct_discovery);
        assert!(cli.enable_web_traffic_discovery);
        assert!(cli.parallel_discovery);
        assert!(cli.enable_slm);
        assert!(cli.enable_web_org);
        assert!(cli.no_color);
        assert_eq!(cli.dns_rate_limit, Some(100));
        assert_eq!(cli.http_rate_limit, Some(50));
        assert_eq!(cli.backoff_strategy, Some("exponential".to_string()));
        assert_eq!(cli.max_retries, Some(3));
        assert_eq!(cli.whois_concurrency, Some(8));
        assert_eq!(cli.timeout, Some(300));
        assert!(cli.include_infra);
        assert!(cli.dns_only);
        assert_eq!(cli.batch_parallel, 5);
        assert!(cli.batch_combined);
    }

    #[test]
    fn cli_parse_verbose_count() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "x.com", "-vv"]);
        assert_eq!(cli.verbose, 2);
    }

    #[test]
    fn cli_parse_init_flag() {
        let cli = Cli::parse_from(["nthpartyfinder", "--init"]);
        assert!(cli.init);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cli_parse_cache_list_subcommand() {
        let cli = Cli::parse_from(["nthpartyfinder", "cache", "list"]);
        match cli.command {
            Some(Commands::Cache {
                action: CacheCommands::List,
            }) => {}
            _ => panic!("Expected Cache List subcommand"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cli_parse_cache_show_subcommand() {
        let cli = Cli::parse_from(["nthpartyfinder", "cache", "show", "example.com"]);
        match cli.command {
            Some(Commands::Cache {
                action: CacheCommands::Show { domain },
            }) => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Expected Cache Show subcommand"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cli_parse_cache_clear_domain() {
        let cli = Cli::parse_from(["nthpartyfinder", "cache", "clear", "example.com"]);
        match cli.command {
            Some(Commands::Cache {
                action: CacheCommands::Clear { domain, all },
            }) => {
                assert_eq!(domain, Some("example.com".to_string()));
                assert!(!all);
            }
            _ => panic!("Expected Cache Clear subcommand"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cli_parse_cache_clear_all() {
        let cli = Cli::parse_from(["nthpartyfinder", "cache", "clear", "--all"]);
        match cli.command {
            Some(Commands::Cache {
                action: CacheCommands::Clear { domain, all },
            }) => {
                assert!(domain.is_none());
                assert!(all);
            }
            _ => panic!("Expected Cache Clear --all"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cli_parse_cache_validate() {
        let cli = Cli::parse_from([
            "nthpartyfinder",
            "cache",
            "validate",
            "--detailed",
            "--domain",
            "x.com",
        ]);
        match cli.command {
            Some(Commands::Cache {
                action: CacheCommands::Validate { detailed, domain },
            }) => {
                assert!(detailed);
                assert_eq!(domain, Some("x.com".to_string()));
            }
            _ => panic!("Expected Cache Validate subcommand"),
        }
    }

    #[test]
    fn cli_parse_input_file() {
        let cli = Cli::parse_from(["nthpartyfinder", "--input-file", "domains.csv"]);
        assert_eq!(cli.input_file, Some("domains.csv".to_string()));
    }

    #[test]
    fn cli_parse_resume_flag() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "x.com", "--resume"]);
        assert!(cli.resume);
        assert!(!cli.no_resume);
    }

    #[test]
    fn cli_parse_no_resume_flag() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "x.com", "--no-resume"]);
        assert!(!cli.resume);
        assert!(cli.no_resume);
    }

    // ---- From<&Cli> for Args ----

    #[test]
    fn args_from_cli_maps_all_fields() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "test.com", "-r", "5", "-f", "json"]);
        let args = Args::from(&cli);
        assert_eq!(args.domain, Some("test.com".to_string()));
        assert_eq!(args.depth, Some(5));
        assert_eq!(args.output_format, "json");
        assert_eq!(args.output, "nth_parties");
        assert!(!args.init);
    }

    // ---- Args::is_batch_mode ----

    #[test]
    fn is_batch_mode_true_when_input_file_set() {
        let mut args = default_args();
        args.input_file = Some("file.csv".to_string());
        assert!(args.is_batch_mode());
    }

    #[test]
    fn is_batch_mode_false_when_no_input_file() {
        let args = default_args();
        assert!(!args.is_batch_mode());
    }

    // ---- Args::validate ----

    #[test]
    fn validate_ok_with_domain() {
        let args = default_args();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn validate_ok_with_init() {
        let mut args = default_args();
        args.init = true;
        args.domain = None;
        assert!(args.validate().is_ok());
    }

    #[test]
    fn validate_ok_with_batch_mode() {
        let mut args = default_args();
        args.domain = None;
        args.input_file = Some("domains.csv".to_string());
        assert!(args.validate().is_ok());
    }

    #[test]
    fn validate_error_no_domain_no_init_no_batch() {
        let mut args = default_args();
        args.domain = None;
        let err = args.validate().unwrap_err();
        assert!(err.contains("either -d <domain> or --input-file"));
    }

    #[test]
    fn validate_error_empty_domain() {
        let mut args = default_args();
        args.domain = Some("".to_string());
        let err = args.validate().unwrap_err();
        assert_eq!(err, "domain cannot be empty");
    }

    #[test]
    fn validate_error_batch_parallel_zero() {
        let mut args = default_args();
        args.domain = None;
        args.input_file = Some("file.csv".to_string());
        args.batch_parallel = 0;
        let err = args.validate().unwrap_err();
        assert!(err.contains("--batch-parallel must be >= 1"));
    }

    #[test]
    fn validate_error_batch_parallel_too_high() {
        let mut args = default_args();
        args.domain = None;
        args.input_file = Some("file.csv".to_string());
        args.batch_parallel = 21;
        let err = args.validate().unwrap_err();
        assert!(err.contains("--batch-parallel cannot exceed 20"));
    }

    #[test]
    fn validate_error_invalid_output_format() {
        let mut args = default_args();
        args.output_format = "xml".to_string();
        let err = args.validate().unwrap_err();
        assert!(err.contains("output format must be"));
    }

    #[test]
    fn validate_all_valid_output_formats() {
        for fmt in &["csv", "json", "markdown", "html"] {
            let mut args = default_args();
            args.output_format = fmt.to_string();
            assert!(args.validate().is_ok(), "format '{}' should be valid", fmt);
        }
    }

    #[test]
    fn validate_error_depth_zero() {
        let mut args = default_args();
        args.depth = Some(0);
        let err = args.validate().unwrap_err();
        assert!(err.contains("--depth must be >= 1"));
    }

    #[test]
    fn validate_ok_depth_nonzero() {
        let mut args = default_args();
        args.depth = Some(1);
        assert!(args.validate().is_ok());

        args.depth = Some(100);
        assert!(args.validate().is_ok());
    }

    /// `0` is the default and means "no operator cap"; it must validate, not error.
    /// It previously errored because the flag defaulted to 10 and was always min'd into the
    /// stream width, which made `analysis.concurrency_per_depth` unreachable.
    #[test]
    fn validate_parallel_jobs_zero_is_auto_not_an_error() {
        let mut args = default_args();
        args.parallel_jobs = 0;
        assert!(
            args.validate().is_ok(),
            "-j 0 means 'use the configured per-depth concurrency', not an invalid input"
        );
    }

    #[test]
    fn validate_error_parallel_jobs_too_high() {
        let mut args = default_args();
        args.parallel_jobs = 1000;
        let err = args.validate().unwrap_err();
        assert!(err.contains("--parallelism cannot exceed"));
    }

    #[test]
    fn validate_ok_parallel_jobs_within_range() {
        let mut args = default_args();
        args.parallel_jobs = 1;
        assert!(args.validate().is_ok());

        args.parallel_jobs = 10;
        assert!(args.validate().is_ok());
    }

    // ---- Args::get_output_dir ----

    #[test]
    fn get_output_dir_uses_custom_when_set() {
        let mut args = default_args();
        args.output_dir = Some("/custom/path".to_string());
        assert_eq!(args.get_output_dir().unwrap(), "/custom/path");
    }

    #[test]
    fn get_output_dir_uses_default_when_none() {
        let args = default_args();
        let dir = args.get_output_dir().unwrap();
        // Should return either Desktop path or "."
        assert!(!dir.is_empty());
    }

    #[test]
    fn get_default_output_dir_returns_string() {
        let dir = Args::get_default_output_dir().unwrap();
        assert!(!dir.is_empty());
    }

    // ---- Args::get_domain_output_dir ----

    #[test]
    fn get_domain_output_dir_creates_path() {
        let mut args = default_args();
        args.output_dir = Some("/base".to_string());
        args.domain = Some("test.example.com".to_string());
        let dir = args.get_domain_output_dir().unwrap();
        assert!(dir.contains("reports"));
        assert!(dir.contains("test_example_com"));
        assert!(!dir.contains("test.example.com"));
    }

    #[test]
    fn get_domain_output_dir_error_when_no_domain() {
        let mut args = default_args();
        args.domain = None;
        let err = args.get_domain_output_dir().unwrap_err();
        assert!(err.contains("Domain is required"));
    }

    // ---- Args::get_resume_mode ----

    #[test]
    fn get_resume_mode_auto_resume() {
        let mut args = default_args();
        args.resume = true;
        assert_eq!(
            args.get_resume_mode(),
            crate::checkpoint::ResumeMode::AutoResume
        );
    }

    #[test]
    fn get_resume_mode_fresh() {
        let mut args = default_args();
        args.no_resume = true;
        assert_eq!(args.get_resume_mode(), crate::checkpoint::ResumeMode::Fresh);
    }

    #[test]
    fn get_resume_mode_prompt_default() {
        let args = default_args();
        assert_eq!(
            args.get_resume_mode(),
            crate::checkpoint::ResumeMode::Prompt
        );
    }

    // ---- Cli disable flags ----

    #[test]
    fn cli_parse_disable_flags() {
        let cli = Cli::parse_from([
            "nthpartyfinder",
            "-d",
            "x.com",
            "--disable-subprocessor-analysis",
            "--disable-subdomain-discovery",
            "--disable-saas-tenant-discovery",
            "--disable-ct-discovery",
            "--disable-web-traffic-discovery",
            "--disable-slm",
            "--disable-web-org",
        ]);
        let args = Args::from(&cli);
        assert!(args.disable_subprocessor_analysis);
        assert!(args.disable_subdomain_discovery);
        assert!(args.disable_saas_tenant_discovery);
        assert!(args.disable_ct_discovery);
        assert!(args.disable_web_traffic_discovery);
        assert!(args.disable_slm);
        assert!(args.disable_web_org);
    }

    #[test]
    fn cli_parse_download_ner_model_flag() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "x.com", "--download-ner-model"]);
        assert!(cli.download_ner_model);
        let args = Args::from(&cli);
        assert!(args.download_ner_model);
    }

    #[test]
    fn cli_download_ner_model_defaults_false() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "x.com"]);
        assert!(!cli.download_ner_model);
        let args = Args::from(&cli);
        assert!(!args.download_ner_model);
    }

    #[test]
    fn cli_parse_output_dir() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "x.com", "--output-dir", "/tmp/out"]);
        let args = Args::from(&cli);
        assert_eq!(args.output_dir, Some("/tmp/out".to_string()));
    }

    #[test]
    fn cli_parse_log_file() {
        let cli = Cli::parse_from([
            "nthpartyfinder",
            "-d",
            "x.com",
            "--log-file",
            "/tmp/log.txt",
        ]);
        let args = Args::from(&cli);
        assert_eq!(args.log_file, Some("/tmp/log.txt".to_string()));
    }

    #[test]
    fn cli_parse_subfinder_path() {
        let cli = Cli::parse_from([
            "nthpartyfinder",
            "-d",
            "x.com",
            "--subfinder-path",
            "/usr/bin/subfinder",
        ]);
        let args = Args::from(&cli);
        assert_eq!(args.subfinder_path, Some("/usr/bin/subfinder".to_string()));
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    #[test]
    fn test_num_cpus_returns_positive() {
        // Test the private num_cpus helper indirectly through validate
        // with a parallel_jobs value that's exactly at the limit
        let mut args = default_args();
        let max_parallel = std::cmp::min(64, Args::num_cpus() * 8);
        args.parallel_jobs = max_parallel;
        assert!(args.validate().is_ok());

        // One above the limit should fail
        args.parallel_jobs = max_parallel + 1;
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_get_domain_output_dir_with_colons() {
        let mut args = default_args();
        args.output_dir = Some("/base".to_string());
        args.domain = Some("test:8080".to_string());
        let dir = args.get_domain_output_dir().unwrap();
        assert!(dir.contains("test_8080"));
        assert!(!dir.contains(":"));
    }

    #[test]
    fn test_args_dns_only_flag() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "x.com", "--dns-only"]);
        let args = Args::from(&cli);
        assert!(args.dns_only);
    }

    #[test]
    fn test_args_include_infra_flag() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "x.com", "--include-infra"]);
        let args = Args::from(&cli);
        assert!(args.include_infra);
    }

    #[test]
    fn test_args_whois_concurrency() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "x.com", "--whois-concurrency", "15"]);
        let args = Args::from(&cli);
        assert_eq!(args.whois_concurrency, Some(15));
    }

    #[test]
    fn test_args_timeout() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "x.com", "--timeout", "0"]);
        let args = Args::from(&cli);
        assert_eq!(args.timeout, Some(0));
    }

    #[test]
    fn cli_parse_batch_output_dir() {
        let cli = Cli::parse_from([
            "nthpartyfinder",
            "--input-file",
            "f.csv",
            "--batch-output-dir",
            "/out",
        ]);
        let args = Args::from(&cli);
        assert_eq!(args.batch_output_dir, Some("/out".to_string()));
    }

    #[test]
    fn cli_default_batch_values() {
        let cli = Cli::parse_from(["nthpartyfinder", "-d", "x.com"]);
        assert_eq!(cli.batch_parallel, 1);
        assert!(!cli.batch_combined);
        assert!(cli.input_file.is_none());
        assert!(cli.batch_output_dir.is_none());
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_args_debug_format() {
        let args = default_args();
        let debug_str = format!("{:?}", args);
        assert!(debug_str.contains("example.com"));
        assert!(debug_str.contains("csv"));
        assert!(debug_str.contains("nth_parties"));
    }

    #[test]
    fn test_validate_batch_parallel_boundary_values() {
        let mut args = default_args();
        args.domain = None;
        args.input_file = Some("file.csv".to_string());

        args.batch_parallel = 1;
        assert!(args.validate().is_ok());

        args.batch_parallel = 20;
        assert!(args.validate().is_ok());

        args.batch_parallel = 21;
        assert!(args.validate().is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cli_parse_cache_validate_minimal() {
        let cli = Cli::parse_from(["nthpartyfinder", "cache", "validate"]);
        match cli.command {
            Some(Commands::Cache {
                action: CacheCommands::Validate { detailed, domain },
            }) => {
                assert!(!detailed);
                assert!(domain.is_none());
            }
            _ => panic!("Expected Cache Validate subcommand"),
        }
    }

    #[test]
    fn test_get_domain_output_dir_default_output_dir() {
        let mut args = default_args();
        args.output_dir = None;
        args.domain = Some("test.com".to_string());
        let dir = args.get_domain_output_dir().unwrap();
        assert!(dir.contains("reports"));
        assert!(dir.contains("test_com"));
    }

    #[test]
    fn test_args_from_cli_batch_fields() {
        let cli = Cli::parse_from([
            "nthpartyfinder",
            "--input-file",
            "domains.json",
            "--batch-output-dir",
            "/output",
            "--batch-parallel",
            "10",
            "--batch-combined",
        ]);
        let args = Args::from(&cli);
        assert_eq!(args.input_file, Some("domains.json".to_string()));
        assert_eq!(args.batch_output_dir, Some("/output".to_string()));
        assert_eq!(args.batch_parallel, 10);
        assert!(args.batch_combined);
    }
}
