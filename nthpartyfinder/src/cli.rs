use clap::{Parser, Subcommand};
use dirs;

#[derive(Parser, Debug)]
#[command(name = "nthpartyfinder")]
#[command(about = "A tool for identifying Nth party vendor relationships through DNS analysis")]
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

    /// Number of parallel jobs for domain analysis (default: 10)
    #[arg(short = 'j', long, default_value = "10")]
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

    /// Disable NER organization extraction (overrides config)
    #[arg(long)]
    pub disable_slm: bool,

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

    /// Auto-resume from checkpoint if one exists (skip resume prompt)
    #[arg(long, conflicts_with = "no_resume")]
    pub resume: bool,

    /// Start fresh analysis, ignore any existing checkpoint
    #[arg(long, conflicts_with = "resume")]
    pub no_resume: bool,

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
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage the subprocessor URL cache
    Cache {
        #[command(subcommand)]
        action: CacheCommands,
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
    pub enable_web_org: bool,
    pub disable_web_org: bool,
    pub no_color: bool,
    pub dns_rate_limit: Option<u32>,
    pub http_rate_limit: Option<u32>,
    pub backoff_strategy: Option<String>,
    pub max_retries: Option<u32>,
    pub whois_concurrency: Option<usize>,
    pub resume: bool,
    pub no_resume: bool,
    // Batch options
    pub input_file: Option<String>,
    pub batch_output_dir: Option<String>,
    pub batch_parallel: usize,
    pub batch_combined: bool,
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
            enable_web_org: cli.enable_web_org,
            disable_web_org: cli.disable_web_org,
            no_color: cli.no_color,
            dns_rate_limit: cli.dns_rate_limit,
            http_rate_limit: cli.http_rate_limit,
            backoff_strategy: cli.backoff_strategy.clone(),
            max_retries: cli.max_retries,
            whois_concurrency: cli.whois_concurrency,
            resume: cli.resume,
            no_resume: cli.no_resume,
            input_file: cli.input_file.clone(),
            batch_output_dir: cli.batch_output_dir.clone(),
            batch_parallel: cli.batch_parallel,
            batch_combined: cli.batch_combined,
        }
    }
}

impl Args {
    /// Check if running in batch mode (--input-file provided)
    pub fn is_batch_mode(&self) -> bool {
        self.input_file.is_some()
    }

    pub fn validate(&self) -> Result<(), String> {
        // Domain validation only applies when not using --init and not in batch mode
        if !self.init && !self.is_batch_mode() {
            match &self.domain {
                None => return Err("Domain is required (use --domain or --input-file for batch mode)".to_string()),
                Some(d) if d.is_empty() => return Err("Domain cannot be empty".to_string()),
                _ => {}
            }
        }

        // Batch mode validation
        if self.is_batch_mode() {
            if self.batch_parallel == 0 {
                return Err("Batch parallel must be greater than 0".to_string());
            }
            if self.batch_parallel > 20 {
                return Err("Batch parallel cannot exceed 20 to avoid overwhelming systems".to_string());
            }
        }

        if !["csv", "json", "markdown", "html"].contains(&self.output_format.as_str()) {
            return Err("Output format must be 'csv', 'json', 'markdown', or 'html'".to_string());
        }

        if let Some(depth) = self.depth {
            if depth == 0 {
                return Err("Depth must be greater than 0".to_string());
            }
        }

        if self.parallel_jobs == 0 {
            return Err("Parallel jobs must be greater than 0".to_string());
        }

        if self.parallel_jobs > 100 {
            return Err("Parallel jobs cannot exceed 100 to avoid overwhelming DNS servers".to_string());
        }

        Ok(())
    }

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

    pub fn get_domain_output_dir(&self) -> Result<String, String> {
        let base_dir = self.get_output_dir()?;
        let domain = self.domain.as_ref().ok_or("Domain is required for output directory")?;
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
