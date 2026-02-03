use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::RwLock;
use std::io::{self, IsTerminal, Write};
use std::fs::OpenOptions;
use std::path::Path;
use colored::{Colorize, control};

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum VerbosityLevel {
    Silent = 0,    // Only show progress bar and final summary
    Summary = 1,   // High-level analysis progress (default)
    Detailed = 2,  // Detailed steps, results, warnings
    Debug = 3,     // All messages including debug info and errors
}

impl VerbosityLevel {
    pub fn from_verbose_count(count: u8) -> Self {
        match count {
            0 => VerbosityLevel::Summary,
            1 => VerbosityLevel::Detailed,
            2.. => VerbosityLevel::Debug,
        }
    }
}

#[derive(Clone)]
pub struct AnalysisLogger {
    verbosity: VerbosityLevel,
    progress_bar: Arc<RwLock<Option<ProgressBar>>>,
    analysis_metadata: Arc<Mutex<AnalysisMetadata>>,
    log_buffer: Arc<Mutex<Vec<String>>>,
    log_file_path: Option<String>,
    color_enabled: bool,
}

#[derive(Default, Clone)]
struct AnalysisMetadata {
    start_time: Option<SystemTime>,
    end_time: Option<SystemTime>,
    total_domains_processed: usize,
    total_txt_records_found: usize,
    total_vendor_relationships: usize,
    max_depth_reached: u32,
    unique_vendors: usize,
    dns_method_used: String,
    output_file: String,
}

impl AnalysisLogger {
    /// Check if colors should be enabled based on environment and settings
    fn should_enable_colors(no_color_flag: bool) -> bool {
        // Respect NO_COLOR environment variable (standard convention)
        if std::env::var("NO_COLOR").is_ok() {
            return false;
        }

        // Respect --no-color CLI flag
        if no_color_flag {
            return false;
        }

        // Disable colors when stdout is not a tty
        if !std::io::stdout().is_terminal() {
            return false;
        }

        true
    }

    /// Configure the colored crate based on our color settings
    fn configure_colored(enabled: bool) {
        if enabled {
            control::set_override(true);
        } else {
            control::set_override(false);
        }
    }

    pub fn new(verbosity: VerbosityLevel) -> Self {
        let color_enabled = Self::should_enable_colors(false);
        Self::configure_colored(color_enabled);

        Self {
            verbosity,
            progress_bar: Arc::new(RwLock::new(None)),
            analysis_metadata: Arc::new(Mutex::new(AnalysisMetadata::default())),
            log_buffer: Arc::new(Mutex::new(Vec::new())),
            log_file_path: None,
            color_enabled,
        }
    }

    pub fn new_with_color_setting(verbosity: VerbosityLevel, no_color: bool) -> Self {
        let color_enabled = Self::should_enable_colors(no_color);
        Self::configure_colored(color_enabled);

        Self {
            verbosity,
            progress_bar: Arc::new(RwLock::new(None)),
            analysis_metadata: Arc::new(Mutex::new(AnalysisMetadata::default())),
            log_buffer: Arc::new(Mutex::new(Vec::new())),
            log_file_path: None,
            color_enabled,
        }
    }

    pub fn with_log_file(verbosity: VerbosityLevel, log_file_path: String) -> Self {
        let color_enabled = Self::should_enable_colors(false);
        Self::configure_colored(color_enabled);

        Self {
            verbosity,
            progress_bar: Arc::new(RwLock::new(None)),
            analysis_metadata: Arc::new(Mutex::new(AnalysisMetadata::default())),
            log_buffer: Arc::new(Mutex::new(Vec::new())),
            log_file_path: Some(log_file_path),
            color_enabled,
        }
    }

    pub fn with_log_file_and_color(verbosity: VerbosityLevel, log_file_path: String, no_color: bool) -> Self {
        let color_enabled = Self::should_enable_colors(no_color);
        Self::configure_colored(color_enabled);

        Self {
            verbosity,
            progress_bar: Arc::new(RwLock::new(None)),
            analysis_metadata: Arc::new(Mutex::new(AnalysisMetadata::default())),
            log_buffer: Arc::new(Mutex::new(Vec::new())),
            log_file_path: Some(log_file_path),
            color_enabled,
        }
    }

    /// Check if colors are enabled
    pub fn is_color_enabled(&self) -> bool {
        self.color_enabled
    }

    // Core logging functions with consistent timestamp formatting
    pub fn info(&self, message: &str) {
        if self.verbosity >= VerbosityLevel::Summary {
            self.print_message("INFO", message);
        }
    }

    pub fn warn(&self, message: &str) {
        if self.verbosity >= VerbosityLevel::Detailed {
            self.print_message("WARN", message);
        }
    }

    pub fn error(&self, message: &str) {
        // ALWAYS show errors regardless of verbosity (fixes B021)
        // Critical errors should never be hidden from users
        self.print_message("ERROR", message);
    }

    pub fn debug(&self, message: &str) {
        if self.verbosity >= VerbosityLevel::Debug {
            self.print_message("DEBUG", message);
        }
    }

    pub fn success(&self, message: &str) {
        // Always show success messages (they are important user feedback)
        self.print_message("SUCCESS", message);
    }

    fn print_message(&self, level: &str, message: &str) {
        let timestamp = self.get_timestamp();

        // Plain message for log file (no ANSI codes)
        let plain_msg = format!("[{}] {}: {}", timestamp, level, message);

        // Store in log buffer if log file export is enabled (without colors)
        if self.log_file_path.is_some() {
            if let Ok(mut buffer) = self.log_buffer.lock() {
                buffer.push(plain_msg.clone());
            }
        }

        // Colored message for terminal output
        let display_msg = if self.color_enabled {
            let timestamp_colored = timestamp.dimmed();
            let (level_colored, message_colored) = match level {
                "INFO" => (level.cyan().bold(), message.cyan()),
                "WARN" => (level.yellow().bold(), message.yellow()),
                "ERROR" => (level.red().bold(), message.red()),
                "DEBUG" => (level.dimmed().bold(), message.dimmed()),
                "SUCCESS" => (level.bright_green().bold(), message.bright_green()),
                _ => (level.normal().bold(), message.normal()),
            };
            format!("[{}] {}: {}", timestamp_colored, level_colored, message_colored)
        } else {
            plain_msg.clone()
        };

        // Check if we have an active progress bar and use its println method
        if let Ok(guard) = self.progress_bar.try_read() {
            if let Some(pb) = guard.as_ref() {
                pb.println(&display_msg);
                return;
            }
        }

        // Fallback if no progress bar
        eprintln!("{}", display_msg);
    }

    fn get_timestamp(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        let millis = now.subsec_millis();
        
        let hours = (secs / 3600) % 24;
        let minutes = (secs % 3600) / 60;
        let seconds = secs % 60;
        
        format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
    }

    // Progress bar management with visual completion tracking
    pub async fn start_progress(&self, total_steps: u64) {        
        // Create a proper horizontal progress bar with total steps
        let pb = ProgressBar::new(total_steps);
        
        // Set a clear progress bar style showing percentage and bar
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                .unwrap_or_else(|_| {
                    // Fallback to a simpler template if the complex one fails
                    ProgressStyle::default_bar()
                        .template("{bar:40} {pos}/{len} {msg}")
                        .unwrap_or_else(|_| ProgressStyle::default_bar())
                })
                .progress_chars("##-")
        );
        
        pb.set_message("Initializing...");
        
        let mut progress_guard = self.progress_bar.write().await;
        *progress_guard = Some(pb);
        
        // Record start time
        let mut metadata = self.analysis_metadata.lock()
            .expect("analysis_metadata mutex poisoned during start_progress");
        metadata.start_time = Some(SystemTime::now());
    }

    pub async fn update_progress(&self, message: &str) {
        if let Some(pb) = self.progress_bar.read().await.as_ref() {
            pb.set_message(message.to_string());
        }
    }

    pub async fn advance_progress(&self, steps: u64) {
        if let Some(pb) = self.progress_bar.read().await.as_ref() {
            pb.inc(steps);
            // Small delay to ensure progress bar is visible
            tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
        }
    }

    pub async fn set_progress_position(&self, position: u64) {
        if let Some(pb) = self.progress_bar.read().await.as_ref() {
            pb.set_position(position);
        }
    }

    pub async fn finish_progress(&self, final_message: &str) {
        let mut progress_guard = self.progress_bar.write().await;
        if let Some(pb) = progress_guard.take() {
            pb.finish_and_clear();
        }

        // Record end time
        let mut metadata = self.analysis_metadata.lock()
            .expect("analysis_metadata mutex poisoned during finish_progress");
        metadata.end_time = Some(SystemTime::now());

        if self.verbosity >= VerbosityLevel::Summary {
            self.print_message("INFO", final_message);
        }
    }

    /// Start an indeterminate spinner for early scan phases before we know the total work
    pub async fn start_spinner(&self, message: &str) {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("[{elapsed_precise}] {spinner:.cyan} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner())
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        let mut progress_guard = self.progress_bar.write().await;
        *progress_guard = Some(pb);

        // Record start time
        let mut metadata = self.analysis_metadata.lock()
            .expect("analysis_metadata mutex poisoned during start_spinner");
        metadata.start_time = Some(SystemTime::now());
    }

    /// Convert spinner to a determinate progress bar when we know the total work
    pub async fn convert_to_progress(&self, total_steps: u64) {
        let mut progress_guard = self.progress_bar.write().await;

        // Clear existing spinner if any
        if let Some(pb) = progress_guard.take() {
            pb.finish_and_clear();
        }

        // Create new determinate progress bar
        let pb = ProgressBar::new(total_steps);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                .unwrap_or_else(|_| {
                    ProgressStyle::default_bar()
                        .template("{bar:40} {pos}/{len} {msg}")
                        .unwrap_or_else(|_| ProgressStyle::default_bar())
                })
                .progress_chars("##-")
        );
        pb.set_message("Processing...");

        *progress_guard = Some(pb);
    }

    // Metadata recording functions
    pub fn record_dns_method(&self, method: &str) {
        let mut metadata = self.analysis_metadata.lock()
            .expect("analysis_metadata mutex poisoned during record_dns_method");
        metadata.dns_method_used = method.to_string();
    }

    pub fn record_txt_records_found(&self, count: usize) {
        let mut metadata = self.analysis_metadata.lock()
            .expect("analysis_metadata mutex poisoned during record_txt_records_found");
        metadata.total_txt_records_found += count;
    }

    pub fn record_domain_processed(&self) {
        let mut metadata = self.analysis_metadata.lock()
            .expect("analysis_metadata mutex poisoned during record_domain_processed");
        metadata.total_domains_processed += 1;
    }

    pub fn record_vendor_relationships(&self, count: usize) {
        let mut metadata = self.analysis_metadata.lock()
            .expect("analysis_metadata mutex poisoned during record_vendor_relationships");
        metadata.total_vendor_relationships = count;
    }

    pub fn record_depth_reached(&self, depth: u32) {
        let mut metadata = self.analysis_metadata.lock()
            .expect("analysis_metadata mutex poisoned during record_depth_reached");
        if depth > metadata.max_depth_reached {
            metadata.max_depth_reached = depth;
        }
    }

    pub fn record_unique_vendors(&self, count: usize) {
        let mut metadata = self.analysis_metadata.lock()
            .expect("analysis_metadata mutex poisoned during record_unique_vendors");
        metadata.unique_vendors = count;
    }

    pub fn record_output_file(&self, path: &str) {
        let mut metadata = self.analysis_metadata.lock()
            .expect("analysis_metadata mutex poisoned during record_output_file");
        metadata.output_file = path.to_string();
    }

    // Final summary message
    pub fn print_final_summary(&self) {
        let metadata = self.analysis_metadata.lock()
            .expect("analysis_metadata mutex poisoned during print_final_summary");

        // Ensure clean output after progress bar
        print!("\x1b[2K\r"); // Clear any remaining progress bar artifacts
        io::stdout().flush().unwrap();

        // Always print summary regardless of verbosity level
        if self.color_enabled {
            println!("\n{}", "=== ANALYSIS SUMMARY ===".bold().cyan());

            if let (Some(start), Some(end)) = (metadata.start_time, metadata.end_time) {
                let duration = end.duration_since(start).unwrap_or_default();
                println!("{}: {:.2}s", "Analysis Duration".bold(), duration.as_secs_f64());
            }

            println!("{}: {}", "DNS Resolution Method".bold(), metadata.dns_method_used);
            println!("{}: {}", "Domains Processed".bold(), metadata.total_domains_processed);
            println!("{}: {}", "TXT Records Found".bold(), metadata.total_txt_records_found);
            println!("{}: {}", "Vendor Relationships".bold(), metadata.total_vendor_relationships);
            println!("{}: {}", "Unique Vendors".bold(), metadata.unique_vendors);
            println!("{}: {}", "Maximum Depth".bold(), metadata.max_depth_reached);

            if !metadata.output_file.is_empty() {
                println!("{}: {}", "Results Exported".bold(), metadata.output_file.green());
            }

            println!("{}\n", "========================".bold().cyan());

            // Success message
            if metadata.total_vendor_relationships > 0 {
                println!("{} Analysis completed successfully! Found {} vendor relationships.",
                    "SUCCESS:".bright_green().bold(),
                    metadata.total_vendor_relationships.to_string().bright_green().bold());
            } else {
                println!("{} Analysis completed. No vendor relationships found.",
                    "SUCCESS:".bright_green().bold());
            }
        } else {
            println!("\n=== ANALYSIS SUMMARY ===");

            if let (Some(start), Some(end)) = (metadata.start_time, metadata.end_time) {
                let duration = end.duration_since(start).unwrap_or_default();
                println!("Analysis Duration: {:.2}s", duration.as_secs_f64());
            }

            println!("DNS Resolution Method: {}", metadata.dns_method_used);
            println!("Domains Processed: {}", metadata.total_domains_processed);
            println!("TXT Records Found: {}", metadata.total_txt_records_found);
            println!("Vendor Relationships: {}", metadata.total_vendor_relationships);
            println!("Unique Vendors: {}", metadata.unique_vendors);
            println!("Maximum Depth: {}", metadata.max_depth_reached);

            if !metadata.output_file.is_empty() {
                println!("Results Exported: {}", metadata.output_file);
            }

            println!("========================\n");

            // Success message
            if metadata.total_vendor_relationships > 0 {
                println!("SUCCESS: Analysis completed successfully! Found {} vendor relationships.", metadata.total_vendor_relationships);
            } else {
                println!("SUCCESS: Analysis completed. No vendor relationships found.");
            }
        }
    }

    // Specialized logging methods for different analysis phases
    pub fn log_initialization(&self, domain: &str) {
        self.info(&format!("Starting Nth Party Analysis for domain: {}", domain));
    }

    pub fn log_dns_lookup_start(&self, domain: &str) {
        self.debug(&format!("Beginning DNS lookup for: {}", domain));
    }

    pub fn log_dns_lookup_success(&self, domain: &str, method: &str, record_count: usize) {
        self.record_txt_records_found(record_count);
        self.record_dns_method(method);
        
        if record_count > 0 {
            self.info(&format!("DNS lookup successful: {} TXT records found for {} (via {})", record_count, domain, method));
        } else {
            self.debug(&format!("DNS lookup completed: No TXT records found for {} (via {})", domain, method));
        }
    }

    pub fn log_dns_lookup_failed(&self, domain: &str, error: &str) {
        self.warn(&format!("DNS lookup failed for {}: {}", domain, error));
    }

    pub fn log_vendor_discovery(&self, domain: &str, vendor_count: usize) {
        if vendor_count > 0 {
            self.info(&format!("Vendor discovery: {} vendors identified for {}", vendor_count, domain));
        } else {
            self.debug(&format!("Vendor discovery: No vendors found for {}", domain));
        }
    }

    pub fn log_parallel_processing_start(&self, domain_count: usize, depth: u32) {
        self.info(&format!("Processing {} domains at depth {} (parallel execution)", domain_count, depth));
    }

    pub fn log_parallel_processing_complete(&self, relationship_count: usize) {
        self.info(&format!("Parallel processing completed: {} relationships established", relationship_count));
    }

    pub fn log_export_start(&self, format: &str) {
        self.info(&format!("Exporting results in {} format", format));
    }

    pub fn log_export_success(&self, path: &str) {
        self.record_output_file(path);
        self.info(&format!("Export completed: {}", path));
    }

    pub fn log_whois_lookup(&self, domain: &str, success: bool) {
        if success {
            self.debug(&format!("WHOIS lookup successful for: {}", domain));
        } else {
            self.debug(&format!("WHOIS lookup failed for: {}", domain));
        }
    }

    pub fn log_subprocessor_analysis(&self, domain: &str, vendor_count: usize) {
        if vendor_count > 0 {
            self.info(&format!("Subprocessor analysis: {} additional vendors found for {}", vendor_count, domain));
        } else {
            self.debug(&format!("Subprocessor analysis: No additional vendors found for {}", domain));
        }
    }
    
    pub fn log_subprocessor_url_attempt(&self, url: &str) {
        self.debug(&format!("Attempting to scrape subprocessor URL: {}", url));
    }
    
    pub fn log_subprocessor_url_success(&self, url: &str, vendor_count: usize) {
        if vendor_count > 0 {
            self.debug(&format!("Successfully scraped {}: {} vendors found", url, vendor_count));
        } else {
            self.debug(&format!("Successfully scraped {}: no vendors found", url));
        }
    }
    
    pub fn log_subprocessor_url_failed(&self, url: &str, error: &str) {
        self.debug(&format!("Failed to scrape {}: {}", url, error));
    }
    
    pub fn log_cache_hit_organization(&self, domain: &str, vendor_count: usize) {
        self.debug(&format!("Cache hit - organization {}: {} vendors from cache", domain, vendor_count));
    }
    
    pub fn log_cache_miss_organization(&self, domain: &str) {
        self.debug(&format!("Cache miss - organization {}: performing fresh analysis", domain));
    }
    
    pub fn log_cache_hit_url(&self, url: &str, status: &str) {
        if status.contains("(retrying)") {
            self.debug(&format!("Cache hit - URL {}: {} - retrying to check if fixed", url, status));
        } else {
            self.debug(&format!("Cache hit - URL {}: {} - verifying still works", url, status));
        }
    }
    
    pub fn log_cache_miss_url(&self, url: &str) {
        self.debug(&format!("Cache miss - URL {}: attempting fresh request", url));
    }
    
    pub fn log_cache_save(&self, url_count: usize, org_count: usize) {
        self.debug(&format!("Saved subprocessor cache: {} URLs, {} organizations", url_count, org_count));
    }

    /// Export all collected logs to the specified file
    pub fn export_logs(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref log_file_path) = self.log_file_path {
            if let Ok(buffer) = self.log_buffer.lock() {
                // Create parent directories if they don't exist
                if let Some(parent) = Path::new(log_file_path).parent() {
                    std::fs::create_dir_all(parent)?;
                }

                // Write all logs to the file
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(log_file_path)?;

                for log_entry in buffer.iter() {
                    writeln!(file, "{}", log_entry)?;
                }

                file.flush()?;
                return Ok(());
            }
        }
        Ok(())
    }

    /// Check if log export is enabled
    pub fn is_log_export_enabled(&self) -> bool {
        self.log_file_path.is_some()
    }

    /// Get the current number of logged messages
    pub fn get_log_count(&self) -> usize {
        if let Ok(buffer) = self.log_buffer.lock() {
            buffer.len()
        } else {
            0
        }
    }
}