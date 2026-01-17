use clap::Parser;
use dirs;

#[derive(Parser, Debug)]
#[command(name = "nthpartyfinder")]
#[command(about = "A tool for identifying Nth party vendor relationships through DNS analysis")]
#[command(version)]
pub struct Args {
    /// Create default configuration file at ./config/nthpartyfinder.toml
    #[arg(long)]
    pub init: bool,

    /// Domain name to analyze for Nth party relationships
    #[arg(short, long, required_unless_present = "init")]
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
    #[arg(short, long, action = clap::ArgAction::Count)]
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
}

impl Args {
    pub fn validate(&self) -> Result<(), String> {
        // Domain validation only applies when not using --init
        if !self.init {
            match &self.domain {
                None => return Err("Domain is required".to_string()),
                Some(d) if d.is_empty() => return Err("Domain cannot be empty".to_string()),
                _ => {}
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
}