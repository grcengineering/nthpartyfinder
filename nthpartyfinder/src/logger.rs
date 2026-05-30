use colored::{control, Colorize};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum VerbosityLevel {
    Silent = 0,   // Only show progress bar and final summary
    Summary = 1,  // High-level analysis progress (default)
    Detailed = 2, // Detailed steps, results, warnings
    Debug = 3,    // All messages including debug info and errors
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

/// UI phase state machine for tracking progress bar lifecycle
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UiPhase {
    PreInit,      // Before any bars are created
    Initializing, // Init progress bar active
    Scanning,     // Scan progress bar active with sub-progress
    Complete,     // All bars finished
}

#[derive(Clone)]
pub struct AnalysisLogger {
    verbosity: VerbosityLevel,
    multi_progress: Arc<MultiProgress>,
    main_bar: Arc<RwLock<Option<ProgressBar>>>,
    detail_bar: Arc<RwLock<Option<ProgressBar>>>,
    phase: Arc<RwLock<UiPhase>>,
    analysis_metadata: Arc<Mutex<AnalysisMetadata>>,
    dns_failures: Arc<AtomicUsize>,
    log_buffer: Arc<Mutex<Vec<String>>>,
    log_file_path: Option<String>,
    color_enabled: bool,
    /// Timestamp when the logger was created (used to maintain continuous timer across phases)
    app_start: Instant,
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

        Self::stdout_is_interactive()
    }

    // coverage(off): returns true only when stdout is a real terminal;
    // automated tests always have piped stdout so the true-path is unreachable.
    // Colored-output behaviour is tested via new_forced_color() constructors.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stdout_is_interactive() -> bool {
        std::io::stdout().is_terminal()
    }

    /// Configure the colored crate based on our color settings
    fn configure_colored(enabled: bool) {
        if enabled {
            control::set_override(true);
        } else {
            control::set_override(false);
        }
    }

    /// Create the shared MultiProgress draw target
    fn create_multi_progress() -> MultiProgress {
        MultiProgress::with_draw_target(ProgressDrawTarget::stderr_with_hz(12))
    }

    pub fn new(verbosity: VerbosityLevel) -> Self {
        let color_enabled = Self::should_enable_colors(false);
        Self::configure_colored(color_enabled);

        Self {
            verbosity,
            multi_progress: Arc::new(Self::create_multi_progress()),
            main_bar: Arc::new(RwLock::new(None)),
            detail_bar: Arc::new(RwLock::new(None)),
            phase: Arc::new(RwLock::new(UiPhase::PreInit)),
            analysis_metadata: Arc::new(Mutex::new(AnalysisMetadata::default())),
            dns_failures: Arc::new(AtomicUsize::new(0)),
            log_buffer: Arc::new(Mutex::new(Vec::new())),
            log_file_path: None,
            color_enabled,
            app_start: Instant::now(),
        }
    }

    pub fn new_with_color_setting(verbosity: VerbosityLevel, no_color: bool) -> Self {
        let color_enabled = Self::should_enable_colors(no_color);
        Self::configure_colored(color_enabled);

        Self {
            verbosity,
            multi_progress: Arc::new(Self::create_multi_progress()),
            main_bar: Arc::new(RwLock::new(None)),
            detail_bar: Arc::new(RwLock::new(None)),
            phase: Arc::new(RwLock::new(UiPhase::PreInit)),
            analysis_metadata: Arc::new(Mutex::new(AnalysisMetadata::default())),
            dns_failures: Arc::new(AtomicUsize::new(0)),
            log_buffer: Arc::new(Mutex::new(Vec::new())),
            log_file_path: None,
            color_enabled,
            app_start: Instant::now(),
        }
    }

    pub fn with_log_file(verbosity: VerbosityLevel, log_file_path: String) -> Self {
        let color_enabled = Self::should_enable_colors(false);
        Self::configure_colored(color_enabled);

        Self {
            verbosity,
            multi_progress: Arc::new(Self::create_multi_progress()),
            main_bar: Arc::new(RwLock::new(None)),
            detail_bar: Arc::new(RwLock::new(None)),
            phase: Arc::new(RwLock::new(UiPhase::PreInit)),
            analysis_metadata: Arc::new(Mutex::new(AnalysisMetadata::default())),
            dns_failures: Arc::new(AtomicUsize::new(0)),
            log_buffer: Arc::new(Mutex::new(Vec::new())),
            log_file_path: Some(log_file_path),
            color_enabled,
            app_start: Instant::now(),
        }
    }

    pub fn with_log_file_and_color(
        verbosity: VerbosityLevel,
        log_file_path: String,
        no_color: bool,
    ) -> Self {
        let color_enabled = Self::should_enable_colors(no_color);
        Self::configure_colored(color_enabled);

        Self {
            verbosity,
            multi_progress: Arc::new(Self::create_multi_progress()),
            main_bar: Arc::new(RwLock::new(None)),
            detail_bar: Arc::new(RwLock::new(None)),
            phase: Arc::new(RwLock::new(UiPhase::PreInit)),
            analysis_metadata: Arc::new(Mutex::new(AnalysisMetadata::default())),
            dns_failures: Arc::new(AtomicUsize::new(0)),
            log_buffer: Arc::new(Mutex::new(Vec::new())),
            log_file_path: Some(log_file_path),
            color_enabled,
            app_start: Instant::now(),
        }
    }

    /// Check if colors are enabled
    pub fn is_color_enabled(&self) -> bool {
        self.color_enabled
    }

    // ═══════════════════════════════════════════════════════════════════
    // Unified progress bar (single bar from init through scan completion)
    // ═══════════════════════════════════════════════════════════════════

    /// Start the unified progress bar that runs from initialization through scan completion.
    /// Uses a single 0→100 percentage bar with elapsed timer throughout.
    /// Init steps occupy positions 0→10, scan phases occupy 10→100.
    pub async fn start_init_progress(&self, _total_steps: u64) {
        if self.verbosity == VerbosityLevel::Silent {
            return;
        }

        let template = if self.color_enabled {
            "[{elapsed_precise}] {spinner:.cyan} [{bar:40.cyan/blue}] {percent}% {msg}"
        } else {
            "[{elapsed_precise}] {spinner} [{bar:40}] {percent}% {msg}"
        };

        let pb = self.multi_progress.add(ProgressBar::new(100));
        pb.set_style(
            ProgressStyle::default_bar()
                .template(template)
                .expect("valid progress bar template")
                .progress_chars("##-")
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
        );
        pb.set_position(0);
        pb.set_message("Initializing...");
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        let mut bar_guard = self.main_bar.write().await;
        *bar_guard = Some(pb);

        let mut phase_guard = self.phase.write().await;
        *phase_guard = UiPhase::Initializing;

        // Record start time at the very beginning
        let mut metadata = self
            .analysis_metadata
            .lock()
            .expect("analysis_metadata mutex poisoned during start_init_progress");
        metadata.start_time = Some(SystemTime::now());
    }

    /// Complete one initialization step. Prints a ✓ checklist line above the bar
    /// and advances within the 0→10 range (each of 6 steps ≈ 1-2 positions).
    /// Includes a brief yield so the terminal can render each step progressively
    /// instead of batching all steps into a single frame.
    pub async fn complete_init_step(&self, step_name: &str) {
        if self.verbosity == VerbosityLevel::Silent {
            return;
        }

        let bar_guard = self.main_bar.read().await;
        if let Some(pb) = bar_guard.as_ref() {
            // Print checklist line above the progress bar
            let check_line = if self.color_enabled {
                format!("  {} {}", "✓".green(), step_name)
            } else {
                format!("  ✓ {}", step_name)
            };
            pb.println(check_line);

            // Advance within 0→10 range (cap at 10)
            let new_pos = (pb.position() + 2).min(10);
            pb.set_position(new_pos);
            pb.set_message("Initializing...");
        }
        // Drop the read guard before sleeping
        drop(bar_guard);

        // Brief pause so the progress bar's steady tick renders each step visually.
        // Without this, all init steps complete within a single render frame (~83ms at 12Hz)
        // and appear as a batch dump instead of progressive updates.
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }

    /// Finish the initialization phase. Prints completion message and transitions
    /// to scanning phase. The bar continues running — no style change or reset.
    pub async fn finish_init(&self) {
        if self.verbosity == VerbosityLevel::Silent {
            return;
        }

        let bar_guard = self.main_bar.read().await;
        if let Some(pb) = bar_guard.as_ref() {
            let done_line = if self.color_enabled {
                format!(
                    "  {} {}",
                    "✓".green().bold(),
                    "Initialization complete".bold()
                )
            } else {
                "  ✓ Initialization complete".to_string()
            };
            pb.println(done_line);
            pb.set_position(10);
            pb.set_message("Preparing analysis...");
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Scanning progress (continues the unified bar + adds detail sub-progress)
    // ═══════════════════════════════════════════════════════════════════

    /// Transition to the scanning phase. The unified bar continues running
    /// (no reset, no style change). Adds a detail bar for sub-progress messages.
    pub async fn start_scan_progress(&self, _total: u64) {
        if self.verbosity == VerbosityLevel::Silent {
            return;
        }

        // Bar is already running from init — just update message and ensure tick is active
        {
            let bar_guard = self.main_bar.read().await;
            if let Some(pb) = bar_guard.as_ref() {
                pb.set_message("Starting vendor discovery...");
                pb.enable_steady_tick(std::time::Duration::from_millis(250));
            } else {
                // Fallback: create bar if somehow missing (shouldn't happen in normal flow)
                drop(bar_guard);
                let mut bar_guard = self.main_bar.write().await;
                let template = if self.color_enabled {
                    "[{elapsed_precise}] {spinner:.cyan} [{bar:40.cyan/blue}] {percent}% {msg}"
                } else {
                    "[{elapsed_precise}] {spinner} [{bar:40}] {percent}% {msg}"
                };
                let main_pb = self
                    .multi_progress
                    .add(ProgressBar::new(100).with_elapsed(self.app_start.elapsed()));
                main_pb.set_style(
                    ProgressStyle::default_bar()
                        .template(template)
                        .expect("valid progress bar template")
                        .progress_chars("##-")
                        .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
                );
                main_pb.set_position(10);
                main_pb.set_message("Starting vendor discovery...");
                main_pb.enable_steady_tick(std::time::Duration::from_millis(250));
                *bar_guard = Some(main_pb);
            }
        }

        // Create detail bar for sub-progress (↳ lines)
        let detail_template = "  {msg}";

        let detail_pb = self.multi_progress.add(ProgressBar::new_spinner());
        detail_pb.set_style(
            ProgressStyle::default_spinner()
                .template(detail_template)
                .expect("valid spinner template")
                .tick_chars("   "), // invisible spinner — just shows message
        );
        detail_pb.set_message(""); // hidden initially

        {
            let mut detail_guard = self.detail_bar.write().await;
            *detail_guard = Some(detail_pb);
        }
        {
            let mut phase_guard = self.phase.write().await;
            *phase_guard = UiPhase::Scanning;
        }
    }

    /// Show a sub-progress detail line below the main scan bar.
    /// Displayed as: "  ↳ {message}"
    pub async fn show_sub_progress(&self, message: &str) {
        if self.verbosity == VerbosityLevel::Silent {
            return;
        }

        let detail_guard = self.detail_bar.read().await;
        if let Some(pb) = detail_guard.as_ref() {
            let formatted = if self.color_enabled {
                format!("{} {}", "↳".dimmed(), message.dimmed())
            } else {
                format!("↳ {}", message)
            };
            pb.set_message(formatted);
        }
    }

    /// Clear the sub-progress detail line.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn clear_sub_progress(&self) {
        let detail_guard = self.detail_bar.read().await;
        if let Some(pb) = detail_guard.as_ref() {
            pb.set_message("".to_string());
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Core logging (works with any active bar via MultiProgress)
    // ═══════════════════════════════════════════════════════════════════

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

    #[cfg_attr(coverage_nightly, coverage(off))]
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
            format!(
                "[{}] {}: {}",
                timestamp_colored, level_colored, message_colored
            )
        } else {
            plain_msg.clone()
        };

        // Use main_bar's println to print above all progress bars managed by MultiProgress.
        // Falls back to eprintln when no bar exists or the lock is write-held.
        let printed = self
            .main_bar
            .try_read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|pb| pb.println(&display_msg)))
            .is_some();

        if !printed {
            eprintln!("{}", display_msg);
        }
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

    // ═══════════════════════════════════════════════════════════════════
    // Backward-compatible progress bar methods (used by scanning phase)
    // ═══════════════════════════════════════════════════════════════════

    /// Start a progress bar (backward compat — delegates to start_scan_progress)
    pub async fn start_progress(&self, total_steps: u64) {
        self.start_scan_progress(total_steps).await;
    }

    pub async fn update_progress(&self, message: &str) {
        if let Some(pb) = self.main_bar.read().await.as_ref() {
            pb.set_message(message.to_string());
        }
    }

    pub async fn advance_progress(&self, steps: u64) {
        if let Some(pb) = self.main_bar.read().await.as_ref() {
            pb.inc(steps);
            // Small delay to ensure progress bar is visible
            tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn set_progress_position(&self, position: u64) {
        if let Some(pb) = self.main_bar.read().await.as_ref() {
            pb.set_position(position);
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn finish_progress(&self, final_message: &str) {
        // Clear detail bar first
        {
            let mut detail_guard = self.detail_bar.write().await;
            if let Some(pb) = detail_guard.take() {
                pb.finish_and_clear();
            }
        }

        // Clear main bar
        {
            let mut bar_guard = self.main_bar.write().await;
            if let Some(pb) = bar_guard.take() {
                pb.finish_and_clear();
            }
        }

        // Set phase to complete
        {
            let mut phase_guard = self.phase.write().await;
            *phase_guard = UiPhase::Complete;
        }

        // Record end time
        let mut metadata = self
            .analysis_metadata
            .lock()
            .expect("analysis_metadata mutex poisoned during finish_progress");
        metadata.end_time = Some(SystemTime::now());

        if self.verbosity >= VerbosityLevel::Summary {
            self.print_message("INFO", final_message);
        }
    }

    /// Start an indeterminate spinner for early scan phases before we know the total work
    pub async fn start_spinner(&self, message: &str) {
        let template = if self.color_enabled {
            "[{elapsed_precise}] {spinner:.cyan} {msg}"
        } else {
            "[{elapsed_precise}] {spinner} {msg}"
        };

        let pb = self.multi_progress.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .template(template)
                .expect("valid spinner template")
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        let mut bar_guard = self.main_bar.write().await;
        *bar_guard = Some(pb);

        // Record start time
        let mut metadata = self
            .analysis_metadata
            .lock()
            .expect("analysis_metadata mutex poisoned during start_spinner");
        metadata.start_time = Some(SystemTime::now());
    }

    /// Convert spinner to a determinate progress bar when we know the total work
    pub async fn convert_to_progress(&self, total_steps: u64) {
        let mut bar_guard = self.main_bar.write().await;

        // Clear existing spinner if any
        if let Some(pb) = bar_guard.take() {
            pb.finish_and_clear();
        }

        let template = if self.color_enabled {
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}"
        } else {
            "[{elapsed_precise}] [{bar:40}] {pos}/{len} ({percent}%) {msg}"
        };

        // Create new determinate progress bar
        let pb = self.multi_progress.add(ProgressBar::new(total_steps));
        pb.set_style(
            ProgressStyle::default_bar()
                .template(template)
                .expect("valid progress bar template")
                .progress_chars("##-"),
        );
        pb.set_message("Processing...");

        *bar_guard = Some(pb);
    }

    /// Update the progress bar's total length while preserving current position
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn set_progress_total(&self, new_total: u64) {
        if let Some(pb) = self.main_bar.read().await.as_ref() {
            pb.set_length(new_total);
        }
    }

    /// Get the current progress bar position
    pub async fn get_progress_position(&self) -> u64 {
        if let Some(pb) = self.main_bar.read().await.as_ref() {
            pb.position()
        } else {
            0
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Metadata recording
    // ═══════════════════════════════════════════════════════════════════

    pub fn record_dns_method(&self, method: &str) {
        let mut metadata = self
            .analysis_metadata
            .lock()
            .expect("analysis_metadata mutex poisoned during record_dns_method");
        metadata.dns_method_used = method.to_string();
    }

    pub fn record_txt_records_found(&self, count: usize) {
        let mut metadata = self
            .analysis_metadata
            .lock()
            .expect("analysis_metadata mutex poisoned during record_txt_records_found");
        metadata.total_txt_records_found += count;
    }

    pub fn record_domain_processed(&self) {
        let mut metadata = self
            .analysis_metadata
            .lock()
            .expect("analysis_metadata mutex poisoned during record_domain_processed");
        metadata.total_domains_processed += 1;
    }

    pub fn record_vendor_relationships(&self, count: usize) {
        let mut metadata = self
            .analysis_metadata
            .lock()
            .expect("analysis_metadata mutex poisoned during record_vendor_relationships");
        metadata.total_vendor_relationships = count;
    }

    pub fn record_depth_reached(&self, depth: u32) {
        let mut metadata = self
            .analysis_metadata
            .lock()
            .expect("analysis_metadata mutex poisoned during record_depth_reached");
        if depth > metadata.max_depth_reached {
            metadata.max_depth_reached = depth;
        }
    }

    pub fn record_unique_vendors(&self, count: usize) {
        let mut metadata = self
            .analysis_metadata
            .lock()
            .expect("analysis_metadata mutex poisoned during record_unique_vendors");
        metadata.unique_vendors = count;
    }

    pub fn record_dns_failure(&self) {
        self.dns_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn has_dns_failures(&self) -> bool {
        self.dns_failures.load(Ordering::Relaxed) > 0
    }

    pub fn dns_failure_count(&self) -> usize {
        self.dns_failures.load(Ordering::Relaxed)
    }

    pub fn dns_failure_counter(&self) -> &AtomicUsize {
        &self.dns_failures
    }

    /// GRC-367 (fix 1): hand the *shared* `Arc` over the DNS-failure counter to the
    /// `DnsServerPool` via `with_failure_counter`, so a DoH throttle counted at the pool
    /// choke-point (`note_throttle` inside `doh_*_lookup`) increments the SAME atomic this
    /// logger reads for `has_dns_failures()` — the value the exit-3 false-negative guard checks.
    pub fn dns_failure_counter_arc(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.dns_failures)
    }

    pub fn record_output_file(&self, path: &str) {
        let mut metadata = self
            .analysis_metadata
            .lock()
            .expect("analysis_metadata mutex poisoned during record_output_file");
        metadata.output_file = path.to_string();
    }

    // Final summary message
    pub fn print_final_summary(&self) {
        let metadata = self
            .analysis_metadata
            .lock()
            .expect("analysis_metadata mutex poisoned during print_final_summary");

        // Ensure clean output after progress bar
        print!("\x1b[2K\r"); // Clear any remaining progress bar artifacts
        io::stdout().flush().unwrap();

        // Always print summary regardless of verbosity level
        if self.color_enabled {
            println!("\n{}", "=== ANALYSIS SUMMARY ===".bold().cyan());

            if let (Some(start), Some(end)) = (metadata.start_time, metadata.end_time) {
                let duration = end.duration_since(start).unwrap_or_default();
                println!(
                    "{}: {:.2}s",
                    "Analysis Duration".bold(),
                    duration.as_secs_f64()
                );
            }

            println!(
                "{}: {}",
                "DNS Resolution Method".bold(),
                metadata.dns_method_used
            );
            println!(
                "{}: {}",
                "Domains Processed".bold(),
                metadata.total_domains_processed
            );
            println!(
                "{}: {}",
                "TXT Records Found".bold(),
                metadata.total_txt_records_found
            );
            println!(
                "{}: {}",
                "Vendor Relationships".bold(),
                metadata.total_vendor_relationships
            );
            println!("{}: {}", "Unique Vendors".bold(), metadata.unique_vendors);
            println!("{}: {}", "Maximum Depth".bold(), metadata.max_depth_reached);

            if !metadata.output_file.is_empty() {
                println!(
                    "{}: {}",
                    "Results Exported".bold(),
                    metadata.output_file.green()
                );
            }

            let dns_fail_count = self.dns_failure_count();
            if dns_fail_count > 0 {
                println!(
                    "{}: {}",
                    "DNS Failures".bold(),
                    dns_fail_count.to_string().bright_yellow().bold()
                );
            }

            println!("{}\n", "========================".bold().cyan());

            if dns_fail_count > 0 && metadata.total_vendor_relationships == 0 {
                println!(
                    "{} Results may be unreliable — {} DNS resolution failure(s) occurred and no vendors were found.",
                    "WARNING:".bright_yellow().bold(),
                    dns_fail_count
                );
                println!(
                    "   This likely means DNS queries were blocked or failed. Retry with a different network or DNS provider."
                );
            } else if dns_fail_count > 0 {
                println!(
                    "{} Analysis completed with {} vendor relationships, but {} DNS resolution failure(s) occurred. Some vendors may be missing.",
                    "SUCCESS:".bright_green().bold(),
                    metadata.total_vendor_relationships.to_string().bright_green().bold(),
                    dns_fail_count
                );
            } else if metadata.total_vendor_relationships > 0 {
                println!(
                    "{} Analysis completed successfully! Found {} vendor relationships.",
                    "SUCCESS:".bright_green().bold(),
                    metadata
                        .total_vendor_relationships
                        .to_string()
                        .bright_green()
                        .bold()
                );
            } else {
                println!(
                    "{} Analysis completed. No vendor relationships found.",
                    "SUCCESS:".bright_green().bold()
                );
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
            println!(
                "Vendor Relationships: {}",
                metadata.total_vendor_relationships
            );
            println!("Unique Vendors: {}", metadata.unique_vendors);
            println!("Maximum Depth: {}", metadata.max_depth_reached);

            if !metadata.output_file.is_empty() {
                println!("Results Exported: {}", metadata.output_file);
            }

            let dns_fail_count = self.dns_failure_count();
            if dns_fail_count > 0 {
                println!("DNS Failures: {}", dns_fail_count);
            }

            println!("========================\n");

            if dns_fail_count > 0 && metadata.total_vendor_relationships == 0 {
                println!(
                    "WARNING: Results may be unreliable — {} DNS resolution failure(s) occurred and no vendors were found.",
                    dns_fail_count
                );
                println!(
                    "   This likely means DNS queries were blocked or failed. Retry with a different network or DNS provider."
                );
            } else if dns_fail_count > 0 {
                println!(
                    "SUCCESS: Analysis completed with {} vendor relationships, but {} DNS resolution failure(s) occurred. Some vendors may be missing.",
                    metadata.total_vendor_relationships, dns_fail_count
                );
            } else if metadata.total_vendor_relationships > 0 {
                println!(
                    "SUCCESS: Analysis completed successfully! Found {} vendor relationships.",
                    metadata.total_vendor_relationships
                );
            } else {
                println!("SUCCESS: Analysis completed. No vendor relationships found.");
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Specialized logging methods for different analysis phases
    // ═══════════════════════════════════════════════════════════════════

    pub fn log_initialization(&self, domain: &str) {
        self.info(&format!(
            "Starting Nth Party Analysis for domain: {}",
            domain
        ));
    }

    pub fn log_dns_lookup_start(&self, domain: &str) {
        self.debug(&format!("Beginning DNS lookup for: {}", domain));
    }

    pub fn log_dns_lookup_success(&self, domain: &str, method: &str, record_count: usize) {
        self.record_txt_records_found(record_count);
        self.record_dns_method(method);

        if record_count > 0 {
            self.info(&format!(
                "DNS lookup successful: {} TXT records found for {} (via {})",
                record_count, domain, method
            ));
        } else {
            self.debug(&format!(
                "DNS lookup completed: No TXT records found for {} (via {})",
                domain, method
            ));
        }
    }

    pub fn log_dns_lookup_failed(&self, domain: &str, error: &str) {
        self.warn(&format!("DNS lookup failed for {}: {}", domain, error));
    }

    pub fn log_vendor_discovery(&self, domain: &str, vendor_count: usize) {
        if vendor_count > 0 {
            self.info(&format!(
                "Vendor discovery: {} vendors identified for {}",
                vendor_count, domain
            ));
        } else {
            self.debug(&format!(
                "Vendor discovery: No vendors found for {}",
                domain
            ));
        }
    }

    pub fn log_parallel_processing_start(&self, domain_count: usize, depth: u32) {
        self.info(&format!(
            "Processing {} domains at depth {} (parallel execution)",
            domain_count, depth
        ));
    }

    pub fn log_parallel_processing_complete(&self, relationship_count: usize) {
        self.info(&format!(
            "Parallel processing completed: {} relationships established",
            relationship_count
        ));
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
            self.info(&format!(
                "Subprocessor analysis: {} additional vendors found for {}",
                vendor_count, domain
            ));
        } else {
            self.debug(&format!(
                "Subprocessor analysis: No additional vendors found for {}",
                domain
            ));
        }
    }

    pub fn log_subprocessor_url_attempt(&self, url: &str) {
        self.debug(&format!("Attempting to scrape subprocessor URL: {}", url));
    }

    pub fn log_subprocessor_url_success(&self, url: &str, vendor_count: usize) {
        if vendor_count > 0 {
            self.debug(&format!(
                "Successfully scraped {}: {} vendors found",
                url, vendor_count
            ));
        } else {
            self.debug(&format!("Successfully scraped {}: no vendors found", url));
        }
    }

    pub fn log_subprocessor_url_failed(&self, url: &str, error: &str) {
        self.debug(&format!("Failed to scrape {}: {}", url, error));
    }

    pub fn log_cache_hit_organization(&self, domain: &str, vendor_count: usize) {
        self.debug(&format!(
            "Cache hit - organization {}: {} vendors from cache",
            domain, vendor_count
        ));
    }

    pub fn log_cache_miss_organization(&self, domain: &str) {
        self.debug(&format!(
            "Cache miss - organization {}: performing fresh analysis",
            domain
        ));
    }

    pub fn log_cache_hit_url(&self, url: &str, status: &str) {
        if status.contains("(retrying)") {
            self.debug(&format!(
                "Cache hit - URL {}: {} - retrying to check if fixed",
                url, status
            ));
        } else {
            self.debug(&format!(
                "Cache hit - URL {}: {} - verifying still works",
                url, status
            ));
        }
    }

    pub fn log_cache_miss_url(&self, url: &str) {
        self.debug(&format!(
            "Cache miss - URL {}: attempting fresh request",
            url
        ));
    }

    pub fn log_cache_save(&self, url_count: usize, org_count: usize) {
        self.debug(&format!(
            "Saved subprocessor cache: {} URLs, {} organizations",
            url_count, org_count
        ));
    }

    /// Export all collected logs to the specified file
    #[cfg_attr(coverage_nightly, coverage(off))]
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

    /// Temporarily suspend progress bars for interactive I/O (prompts, user input).
    /// All direct stdout/stderr output MUST go through this method while bars are active,
    /// otherwise ghost bars will appear due to terminal rendering conflicts with indicatif.
    pub fn suspend_for_io<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        self.multi_progress.suspend(f)
    }

    #[cfg(test)]
    fn new_forced_color(verbosity: VerbosityLevel) -> Self {
        Self::configure_colored(true);
        Self {
            verbosity,
            multi_progress: Arc::new(Self::create_multi_progress()),
            main_bar: Arc::new(RwLock::new(None)),
            detail_bar: Arc::new(RwLock::new(None)),
            phase: Arc::new(RwLock::new(UiPhase::PreInit)),
            analysis_metadata: Arc::new(Mutex::new(AnalysisMetadata::default())),
            dns_failures: Arc::new(AtomicUsize::new(0)),
            log_buffer: Arc::new(Mutex::new(Vec::new())),
            log_file_path: None,
            color_enabled: true,
            app_start: Instant::now(),
        }
    }

    #[cfg(test)]
    fn with_log_file_forced_color(verbosity: VerbosityLevel, log_file_path: String) -> Self {
        Self::configure_colored(true);
        Self {
            verbosity,
            multi_progress: Arc::new(Self::create_multi_progress()),
            main_bar: Arc::new(RwLock::new(None)),
            detail_bar: Arc::new(RwLock::new(None)),
            phase: Arc::new(RwLock::new(UiPhase::PreInit)),
            analysis_metadata: Arc::new(Mutex::new(AnalysisMetadata::default())),
            dns_failures: Arc::new(AtomicUsize::new(0)),
            log_buffer: Arc::new(Mutex::new(Vec::new())),
            log_file_path: Some(log_file_path),
            color_enabled: true,
            app_start: Instant::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tempfile::TempDir;

    #[rstest]
    #[case(0, VerbosityLevel::Summary)]
    #[case(1, VerbosityLevel::Detailed)]
    #[case(2, VerbosityLevel::Debug)]
    #[case(3, VerbosityLevel::Debug)]
    #[case(255, VerbosityLevel::Debug)]
    fn test_verbosity_from_verbose_count(#[case] count: u8, #[case] expected: VerbosityLevel) {
        assert_eq!(VerbosityLevel::from_verbose_count(count), expected);
    }

    #[test]
    fn test_verbosity_ordering() {
        assert!(VerbosityLevel::Silent < VerbosityLevel::Summary);
        assert!(VerbosityLevel::Summary < VerbosityLevel::Detailed);
        assert!(VerbosityLevel::Detailed < VerbosityLevel::Debug);
    }

    #[test]
    fn test_new_logger() {
        let logger = AnalysisLogger::new(VerbosityLevel::Summary);
        assert!(!logger.is_log_export_enabled());
        assert_eq!(logger.get_log_count(), 0);
    }

    #[test]
    fn test_new_with_color_setting() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        assert!(!logger.is_color_enabled());

        let logger2 = AnalysisLogger::new_with_color_setting(VerbosityLevel::Silent, false);
        let _ = logger2.is_color_enabled();
    }

    #[test]
    fn test_with_log_file() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");
        let logger = AnalysisLogger::with_log_file(
            VerbosityLevel::Debug,
            log_path.to_str().unwrap().to_string(),
        );
        assert!(logger.is_log_export_enabled());
    }

    #[test]
    fn test_with_log_file_and_color() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");
        let logger = AnalysisLogger::with_log_file_and_color(
            VerbosityLevel::Detailed,
            log_path.to_str().unwrap().to_string(),
            true,
        );
        assert!(logger.is_log_export_enabled());
        assert!(!logger.is_color_enabled());
    }

    #[test]
    fn test_metadata_recording() {
        let logger = AnalysisLogger::new(VerbosityLevel::Debug);

        logger.record_dns_method("system");
        logger.record_txt_records_found(5);
        logger.record_txt_records_found(3);
        logger.record_domain_processed();
        logger.record_domain_processed();
        logger.record_vendor_relationships(10);
        logger.record_depth_reached(3);
        logger.record_depth_reached(2);
        logger.record_unique_vendors(7);
        logger.record_output_file("output.csv");

        let metadata = logger.analysis_metadata.lock().unwrap();
        assert_eq!(metadata.dns_method_used, "system");
        assert_eq!(metadata.total_txt_records_found, 8);
        assert_eq!(metadata.total_domains_processed, 2);
        assert_eq!(metadata.total_vendor_relationships, 10);
        assert_eq!(metadata.max_depth_reached, 3);
        assert_eq!(metadata.unique_vendors, 7);
        assert_eq!(metadata.output_file, "output.csv");
    }

    #[test]
    fn test_log_methods_with_file() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("messages.log");
        let logger = AnalysisLogger::with_log_file(
            VerbosityLevel::Debug,
            log_path.to_str().unwrap().to_string(),
        );

        logger.info("info message");
        logger.warn("warn message");
        logger.error("error message");
        logger.debug("debug message");
        logger.success("success message");

        assert!(logger.get_log_count() > 0);

        logger.export_logs().unwrap();
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("info message"));
        assert!(content.contains("error message"));
        assert!(content.contains("success message"));
    }

    #[test]
    fn test_log_verbosity_filtering() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("filter.log");
        let logger = AnalysisLogger::with_log_file(
            VerbosityLevel::Silent,
            log_path.to_str().unwrap().to_string(),
        );

        logger.info("should not appear");
        logger.warn("should not appear");
        logger.debug("should not appear");
        logger.error("errors always appear");
        logger.success("success always appears");

        logger.export_logs().unwrap();
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("errors always appear"));
        assert!(content.contains("success always appears"));
    }

    #[test]
    fn test_specialized_log_methods() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("specialized.log");
        let logger = AnalysisLogger::with_log_file(
            VerbosityLevel::Debug,
            log_path.to_str().unwrap().to_string(),
        );

        logger.log_initialization("example.com");
        logger.log_dns_lookup_start("example.com");
        logger.log_dns_lookup_success("example.com", "system", 5);
        logger.log_dns_lookup_failed("bad.com", "timeout");
        logger.log_vendor_discovery("example.com", 3);
        logger.log_vendor_discovery("empty.com", 0);
        logger.log_parallel_processing_start(10, 3);
        logger.log_parallel_processing_complete(25);
        logger.log_export_start("csv");
        logger.log_export_success("output.csv");
        logger.log_whois_lookup("example.com", true);
        logger.log_whois_lookup("bad.com", false);
        logger.log_subprocessor_analysis("example.com", 5);
        logger.log_subprocessor_analysis("empty.com", 0);
        logger.log_subprocessor_url_attempt("https://example.com/sub");
        logger.log_subprocessor_url_success("https://example.com/sub", 3);
        logger.log_subprocessor_url_success("https://example.com/sub", 0);
        logger.log_subprocessor_url_failed("https://bad.com/sub", "404");
        logger.log_cache_hit_organization("example.com", 5);
        logger.log_cache_miss_organization("example.com");
        logger.log_cache_hit_url("https://example.com", "working");
        logger.log_cache_hit_url("https://example.com", "(retrying)");
        logger.log_cache_miss_url("https://new.com");
        logger.log_cache_save(10, 5);

        assert!(logger.get_log_count() > 20);
    }

    #[test]
    fn test_print_final_summary_no_color() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        logger.record_dns_method("system");
        logger.record_vendor_relationships(5);
        {
            let mut metadata = logger.analysis_metadata.lock().unwrap();
            metadata.start_time = Some(SystemTime::now());
            metadata.end_time = Some(SystemTime::now());
        }
        logger.print_final_summary();
    }

    #[test]
    fn test_print_final_summary_zero_vendors() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        logger.record_vendor_relationships(0);
        {
            let mut metadata = logger.analysis_metadata.lock().unwrap();
            metadata.start_time = Some(SystemTime::now());
            metadata.end_time = Some(SystemTime::now());
        }
        logger.print_final_summary();
    }

    #[test]
    fn test_export_logs_no_file() {
        let logger = AnalysisLogger::new(VerbosityLevel::Debug);
        logger.info("test");
        logger.export_logs().unwrap();
    }

    #[test]
    fn test_suspend_for_io() {
        let logger = AnalysisLogger::new(VerbosityLevel::Summary);
        let result = logger.suspend_for_io(|| 42);
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_async_progress_lifecycle() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);

        logger.start_init_progress(5).await;
        logger.complete_init_step("Step 1").await;
        logger.complete_init_step("Step 2").await;
        logger.finish_init().await;

        logger.start_scan_progress(100).await;
        logger.show_sub_progress("Processing...").await;
        logger.clear_sub_progress().await;

        logger.start_progress(50).await;
        logger.update_progress("working...").await;
        logger.advance_progress(10).await;
        logger.set_progress_position(25).await;
        logger.set_progress_total(100).await;
        let pos = logger.get_progress_position().await;
        assert!(pos <= 100);
        logger.finish_progress("Done!").await;
    }

    #[tokio::test]
    async fn test_silent_mode_skips_progress() {
        let logger = AnalysisLogger::new(VerbosityLevel::Silent);
        logger.start_init_progress(5).await;
        logger.complete_init_step("Step").await;
        logger.finish_init().await;
        logger.start_scan_progress(10).await;
    }

    #[tokio::test]
    async fn test_spinner_lifecycle() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        logger.start_spinner("Scanning...").await;
        logger.convert_to_progress(50).await;
        logger.finish_progress("Done").await;
    }

    #[test]
    fn test_ui_phase_enum() {
        assert_eq!(UiPhase::PreInit, UiPhase::PreInit);
        assert_ne!(UiPhase::PreInit, UiPhase::Scanning);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // print_final_summary — colored path
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_print_final_summary_colored_with_vendors() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, false);
        logger.record_dns_method("doh");
        logger.record_vendor_relationships(15);
        logger.record_unique_vendors(10);
        logger.record_output_file("results.json");
        {
            let mut metadata = logger.analysis_metadata.lock().unwrap();
            metadata.start_time = Some(SystemTime::now());
            metadata.end_time = Some(SystemTime::now());
            metadata.total_domains_processed = 5;
            metadata.total_txt_records_found = 20;
            metadata.max_depth_reached = 3;
        }
        // Should exercise the colored branch
        logger.print_final_summary();
    }

    #[test]
    fn test_print_final_summary_colored_zero_vendors() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, false);
        logger.record_vendor_relationships(0);
        {
            let mut metadata = logger.analysis_metadata.lock().unwrap();
            metadata.start_time = Some(SystemTime::now());
            metadata.end_time = Some(SystemTime::now());
        }
        logger.print_final_summary();
    }

    #[test]
    fn test_print_final_summary_no_output_file() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        // Don't set output_file - should skip the "Results Exported" line
        {
            let mut metadata = logger.analysis_metadata.lock().unwrap();
            metadata.start_time = Some(SystemTime::now());
            metadata.end_time = Some(SystemTime::now());
        }
        logger.print_final_summary();
    }

    #[test]
    fn test_print_final_summary_no_timing() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        // Don't set start/end time - should skip duration
        logger.print_final_summary();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // print_message — branch coverage
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_print_message_all_levels_colored() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("colored.log");
        let logger = AnalysisLogger::with_log_file_and_color(
            VerbosityLevel::Debug,
            log_path.to_str().unwrap().to_string(),
            false,
        );
        // Exercise all color branches
        logger.info("info test");
        logger.warn("warn test");
        logger.error("error test");
        logger.debug("debug test");
        logger.success("success test");

        logger.export_logs().unwrap();
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("info test"));
        assert!(content.contains("warn test"));
        assert!(content.contains("error test"));
        assert!(content.contains("debug test"));
        assert!(content.contains("success test"));
    }

    #[test]
    fn test_print_message_no_log_file() {
        let logger = AnalysisLogger::new(VerbosityLevel::Debug);
        // Without a log file, messages go to stderr only
        logger.info("ephemeral message");
        assert_eq!(logger.get_log_count(), 0); // No buffer without log file
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // metadata edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_depth_reached_keeps_max() {
        let logger = AnalysisLogger::new(VerbosityLevel::Debug);
        logger.record_depth_reached(5);
        logger.record_depth_reached(3);
        logger.record_depth_reached(7);
        logger.record_depth_reached(2);
        let metadata = logger.analysis_metadata.lock().unwrap();
        assert_eq!(metadata.max_depth_reached, 7);
    }

    #[test]
    fn test_txt_records_accumulate() {
        let logger = AnalysisLogger::new(VerbosityLevel::Debug);
        logger.record_txt_records_found(10);
        logger.record_txt_records_found(5);
        logger.record_txt_records_found(3);
        let metadata = logger.analysis_metadata.lock().unwrap();
        assert_eq!(metadata.total_txt_records_found, 18);
    }

    #[test]
    fn test_domains_processed_accumulate() {
        let logger = AnalysisLogger::new(VerbosityLevel::Debug);
        logger.record_domain_processed();
        logger.record_domain_processed();
        logger.record_domain_processed();
        let metadata = logger.analysis_metadata.lock().unwrap();
        assert_eq!(metadata.total_domains_processed, 3);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // export_logs edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_export_logs_empty_buffer() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("empty.log");
        let logger = AnalysisLogger::with_log_file(
            VerbosityLevel::Debug,
            log_path.to_str().unwrap().to_string(),
        );
        // No messages logged
        logger.export_logs().unwrap();
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.is_empty());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // specialized log methods — more branch coverage
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_log_cache_hit_url_retrying() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("cache.log");
        let logger = AnalysisLogger::with_log_file(
            VerbosityLevel::Debug,
            log_path.to_str().unwrap().to_string(),
        );
        // Test the "(retrying)" branch
        logger.log_cache_hit_url("https://example.com", "(retrying)");
        logger.export_logs().unwrap();
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("retrying"));
    }

    #[test]
    fn test_log_dns_lookup_success_zero_records() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("dns.log");
        let logger = AnalysisLogger::with_log_file(
            VerbosityLevel::Debug,
            log_path.to_str().unwrap().to_string(),
        );
        logger.log_dns_lookup_success("example.com", "doh", 0);
        logger.export_logs().unwrap();
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("example.com"));
    }

    #[test]
    fn test_verbosity_level_debug() {
        let debug_str = format!("{:?}", VerbosityLevel::Debug);
        assert_eq!(debug_str, "Debug");
    }

    #[test]
    fn test_verbosity_level_clone() {
        let level = VerbosityLevel::Detailed;
        let cloned = level;
        assert_eq!(level, cloned);
    }

    #[tokio::test]
    async fn test_progress_without_start() {
        let logger = AnalysisLogger::new(VerbosityLevel::Debug);
        // Calling update/advance without starting should not panic
        logger.update_progress("no-op").await;
        logger.advance_progress(5).await;
        let pos = logger.get_progress_position().await;
        assert_eq!(pos, 0);
    }

    #[tokio::test]
    async fn test_convert_spinner_to_progress_without_spinner() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        // Convert without starting spinner first
        logger.convert_to_progress(100).await;
        logger.finish_progress("done").await;
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    #[test]
    fn test_export_logs_with_log_file() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("test.log");
        let logger = AnalysisLogger::with_log_file(
            VerbosityLevel::Summary,
            log_path.to_string_lossy().into(),
        );

        // Add some log entries via the buffer
        {
            let mut buffer = logger.log_buffer.lock().unwrap();
            buffer.push("Log entry 1".to_string());
            buffer.push("Log entry 2".to_string());
        }

        logger.export_logs().unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("Log entry 1"));
        assert!(content.contains("Log entry 2"));
    }

    #[test]
    fn test_export_logs_without_log_file() {
        let logger = AnalysisLogger::new(VerbosityLevel::Summary);
        // Should be a no-op and not error
        logger.export_logs().unwrap();
    }

    #[test]
    fn test_export_logs_root_path_no_parent() {
        // Path "/" has parent() == None, exercising the implicit else branch
        let logger = AnalysisLogger::with_log_file(VerbosityLevel::Summary, "/".to_string());
        {
            let mut buffer = logger.log_buffer.lock().unwrap();
            buffer.push("test entry".to_string());
        }
        // This will fail because we can't write to "/" but we want to exercise
        // the path where parent() returns None
        let _ = logger.export_logs();
    }

    #[test]
    fn test_is_log_export_enabled() {
        let logger_no_file = AnalysisLogger::new(VerbosityLevel::Summary);
        assert!(!logger_no_file.is_log_export_enabled());

        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("test.log");
        let logger_with_file = AnalysisLogger::with_log_file(
            VerbosityLevel::Summary,
            log_path.to_string_lossy().into(),
        );
        assert!(logger_with_file.is_log_export_enabled());
    }

    #[test]
    fn test_get_log_count() {
        let logger = AnalysisLogger::new(VerbosityLevel::Summary);
        assert_eq!(logger.get_log_count(), 0);

        {
            let mut buffer = logger.log_buffer.lock().unwrap();
            buffer.push("entry 1".to_string());
            buffer.push("entry 2".to_string());
            buffer.push("entry 3".to_string());
        }

        assert_eq!(logger.get_log_count(), 3);
    }

    #[test]
    fn test_get_log_count_poisoned_mutex() {
        let logger = AnalysisLogger::new(VerbosityLevel::Summary);
        let log_buffer = logger.log_buffer.clone();

        // Poison the mutex by panicking while holding the lock
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = log_buffer.lock().unwrap();
            panic!("intentional panic to poison mutex");
        }));

        // Now log_buffer mutex is poisoned, get_log_count should return 0
        assert_eq!(logger.get_log_count(), 0);
    }

    #[test]
    fn test_export_logs_poisoned_mutex() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("poisoned.log");
        let logger = AnalysisLogger::with_log_file(
            VerbosityLevel::Summary,
            log_path.to_string_lossy().into(),
        );
        let log_buffer = logger.log_buffer.clone();

        // Poison the mutex
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = log_buffer.lock().unwrap();
            panic!("intentional panic to poison mutex");
        }));

        // export_logs should handle the poisoned mutex gracefully (skip to Ok(()))
        let result = logger.export_logs();
        assert!(result.is_ok());
        // File should not be created since we couldn't lock the buffer
        assert!(!log_path.exists());
    }

    // ====================================================================
    // Tests for functions that previously had coverage(off)
    // ====================================================================

    #[test]
    fn test_should_enable_colors_no_color_flag() {
        assert!(!AnalysisLogger::should_enable_colors(true));
    }

    #[test]
    fn test_should_enable_colors_no_color_env() {
        std::env::set_var("NO_COLOR", "1");
        let result = AnalysisLogger::should_enable_colors(false);
        std::env::remove_var("NO_COLOR");
        assert!(!result);
    }

    #[test]
    fn test_should_enable_colors_non_terminal_returns_false() {
        std::env::remove_var("NO_COLOR");
        let result = AnalysisLogger::should_enable_colors(false);
        // In test environments stdout is typically not a terminal
        assert!(!result);
    }

    #[test]
    fn test_configure_colored_both_paths() {
        AnalysisLogger::configure_colored(true);
        AnalysisLogger::configure_colored(false);
    }

    #[tokio::test]
    async fn test_start_init_progress_sets_phase() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        assert_eq!(*logger.phase.read().await, UiPhase::PreInit);

        logger.start_init_progress(5).await;
        assert_eq!(*logger.phase.read().await, UiPhase::Initializing);

        let metadata = logger.analysis_metadata.lock().unwrap();
        assert!(metadata.start_time.is_some());
    }

    #[tokio::test]
    async fn test_complete_init_step_advances_position() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        logger.start_init_progress(5).await;

        let pos_before = logger.main_bar.read().await.as_ref().unwrap().position();
        logger.complete_init_step("Test step").await;
        let pos_after = logger.main_bar.read().await.as_ref().unwrap().position();

        assert!(pos_after > pos_before);
        assert!(pos_after <= 10);
    }

    #[tokio::test]
    async fn test_finish_init_sets_position_to_10() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        logger.start_init_progress(5).await;
        logger.finish_init().await;

        let pos = logger.main_bar.read().await.as_ref().unwrap().position();
        assert_eq!(pos, 10);
    }

    #[tokio::test]
    async fn test_start_scan_progress_sets_scanning_phase() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        logger.start_init_progress(5).await;
        logger.finish_init().await;
        logger.start_scan_progress(100).await;

        assert_eq!(*logger.phase.read().await, UiPhase::Scanning);
        assert!(logger.detail_bar.read().await.is_some());
    }

    #[tokio::test]
    async fn test_show_sub_progress_updates_detail_bar() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        logger.start_init_progress(5).await;
        logger.finish_init().await;
        logger.start_scan_progress(100).await;

        // Should not panic and the detail bar should exist
        logger.show_sub_progress("Processing domain X").await;
        assert!(logger.detail_bar.read().await.is_some());
    }

    #[test]
    fn test_print_message_formats_timestamp_and_level() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("format.log");
        let logger = AnalysisLogger::with_log_file(
            VerbosityLevel::Debug,
            log_path.to_str().unwrap().to_string(),
        );

        logger.info("hello world");
        logger.export_logs().unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        // Verify timestamp format [HH:MM:SS.mmm]
        assert!(content.contains("INFO"));
        assert!(content.contains("hello world"));
        // Verify the line matches expected pattern: [timestamp] LEVEL: message
        let line = content.lines().next().unwrap();
        assert!(line.starts_with("["));
        assert!(line.contains("] INFO: hello world"));
    }

    #[tokio::test]
    async fn test_start_spinner_creates_bar() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        assert!(logger.main_bar.read().await.is_none());

        logger.start_spinner("Scanning...").await;
        assert!(logger.main_bar.read().await.is_some());

        let metadata = logger.analysis_metadata.lock().unwrap();
        assert!(metadata.start_time.is_some());
    }

    #[tokio::test]
    async fn test_convert_to_progress_replaces_spinner() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        logger.start_spinner("Scanning...").await;

        logger.convert_to_progress(50).await;
        let bar = logger.main_bar.read().await;
        let bar = bar.as_ref().unwrap();
        assert_eq!(bar.length(), Some(50));
    }

    #[test]
    fn test_print_final_summary_records_expected_fields() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        logger.record_dns_method("doh");
        logger.record_vendor_relationships(5);
        logger.record_unique_vendors(3);
        logger.record_output_file("out.csv");
        {
            let mut metadata = logger.analysis_metadata.lock().unwrap();
            metadata.start_time = Some(SystemTime::now());
            metadata.end_time = Some(SystemTime::now());
            metadata.total_domains_processed = 10;
            metadata.total_txt_records_found = 25;
            metadata.max_depth_reached = 4;
        }
        // Verify metadata is consistent before summary
        let metadata = logger.analysis_metadata.lock().unwrap();
        assert_eq!(metadata.dns_method_used, "doh");
        assert_eq!(metadata.total_vendor_relationships, 5);
        assert_eq!(metadata.unique_vendors, 3);
        assert_eq!(metadata.output_file, "out.csv");
        assert_eq!(metadata.total_domains_processed, 10);
        assert_eq!(metadata.total_txt_records_found, 25);
        assert_eq!(metadata.max_depth_reached, 4);
        drop(metadata);
        // Should not panic in either colored or non-colored path
        logger.print_final_summary();
    }

    // ====================================================================
    // Forced-color tests — exercise color_enabled=true paths that are
    // unreachable via public constructors in test (stdout is never a tty)
    // ====================================================================

    #[test]
    fn test_print_message_forced_color_all_levels() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("fc_all.log");
        let logger = AnalysisLogger::with_log_file_forced_color(
            VerbosityLevel::Debug,
            log_path.to_str().unwrap().to_string(),
        );
        logger.info("info fc");
        logger.warn("warn fc");
        logger.error("error fc");
        logger.debug("debug fc");
        logger.success("success fc");
        // Hit the default match arm in the color branch
        logger.print_message("CUSTOM", "custom fc");

        logger.export_logs().unwrap();
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("info fc"));
        assert!(content.contains("custom fc"));
    }

    #[tokio::test]
    async fn test_print_message_forced_color_with_active_bar() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        logger.start_init_progress(5).await;
        logger.info("msg with bar");
        logger.warn("warn with bar");
        logger.error("error with bar");
        logger.debug("debug with bar");
        logger.success("success with bar");
        logger.finish_progress("done").await;
    }

    #[tokio::test]
    async fn test_start_init_progress_forced_color() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        logger.start_init_progress(5).await;
        assert_eq!(*logger.phase.read().await, UiPhase::Initializing);
    }

    #[tokio::test]
    async fn test_complete_init_step_forced_color() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        logger.start_init_progress(5).await;
        logger.complete_init_step("Colored step").await;
        let pos = logger.main_bar.read().await.as_ref().unwrap().position();
        assert!(pos > 0);
    }

    #[tokio::test]
    async fn test_finish_init_forced_color() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        logger.start_init_progress(5).await;
        logger.finish_init().await;
        let pos = logger.main_bar.read().await.as_ref().unwrap().position();
        assert_eq!(pos, 10);
    }

    #[tokio::test]
    async fn test_show_sub_progress_forced_color() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        logger.start_init_progress(5).await;
        logger.finish_init().await;
        logger.start_scan_progress(100).await;
        logger.show_sub_progress("Colored sub-progress").await;
        assert!(logger.detail_bar.read().await.is_some());
    }

    #[tokio::test]
    async fn test_start_scan_progress_fallback_no_init_plain() {
        let logger = AnalysisLogger::new_with_color_setting(VerbosityLevel::Debug, true);
        // No start_init_progress — main_bar is None, triggers fallback creation
        logger.start_scan_progress(100).await;
        assert!(logger.main_bar.read().await.is_some());
        assert_eq!(*logger.phase.read().await, UiPhase::Scanning);
    }

    #[tokio::test]
    async fn test_start_scan_progress_fallback_no_init_colored() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        // No start_init_progress — main_bar is None, triggers fallback + colored template
        logger.start_scan_progress(100).await;
        assert!(logger.main_bar.read().await.is_some());
        assert_eq!(*logger.phase.read().await, UiPhase::Scanning);
    }

    #[tokio::test]
    async fn test_start_spinner_forced_color() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        logger.start_spinner("Colored spinner").await;
        assert!(logger.main_bar.read().await.is_some());
    }

    #[tokio::test]
    async fn test_convert_to_progress_forced_color() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        logger.start_spinner("Colored spinner").await;
        logger.convert_to_progress(100).await;
        let bar = logger.main_bar.read().await;
        assert_eq!(bar.as_ref().unwrap().length(), Some(100));
    }

    #[test]
    fn test_print_final_summary_forced_color_with_vendors_and_output() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        logger.record_dns_method("doh");
        logger.record_vendor_relationships(10);
        logger.record_unique_vendors(7);
        logger.record_output_file("results.json");
        {
            let mut metadata = logger.analysis_metadata.lock().unwrap();
            metadata.start_time = Some(SystemTime::now());
            metadata.end_time = Some(SystemTime::now());
            metadata.total_domains_processed = 5;
            metadata.total_txt_records_found = 20;
            metadata.max_depth_reached = 3;
        }
        logger.print_final_summary();
    }

    #[test]
    fn test_print_final_summary_forced_color_zero_vendors() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        logger.record_vendor_relationships(0);
        {
            let mut metadata = logger.analysis_metadata.lock().unwrap();
            metadata.start_time = Some(SystemTime::now());
            metadata.end_time = Some(SystemTime::now());
        }
        logger.print_final_summary();
    }

    #[test]
    fn test_print_final_summary_forced_color_no_timing() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        logger.record_vendor_relationships(3);
        logger.print_final_summary();
    }

    #[test]
    fn test_print_final_summary_forced_color_no_output_file() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        logger.record_vendor_relationships(5);
        {
            let mut metadata = logger.analysis_metadata.lock().unwrap();
            metadata.start_time = Some(SystemTime::now());
            metadata.end_time = Some(SystemTime::now());
        }
        logger.print_final_summary();
    }

    #[test]
    fn test_should_enable_colors_delegates_to_stdout_is_interactive() {
        std::env::remove_var("NO_COLOR");
        let result = AnalysisLogger::should_enable_colors(false);
        assert!(!result);
    }

    #[tokio::test]
    async fn test_complete_init_step_without_bar() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        // Don't start init progress — main_bar is None
        logger.complete_init_step("no-op step").await;
    }

    #[tokio::test]
    async fn test_finish_init_without_bar() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        // Don't start init progress — main_bar is None
        logger.finish_init().await;
    }

    #[tokio::test]
    async fn test_show_sub_progress_silent() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Silent);
        logger.show_sub_progress("should be skipped").await;
    }

    #[tokio::test]
    async fn test_show_sub_progress_without_detail_bar() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Debug);
        // Don't start scan progress — detail_bar is None
        logger.show_sub_progress("no-op sub-progress").await;
    }

    // ====================================================================
    // Derived trait coverage — exercise generated Clone/Debug/Copy impls
    // ====================================================================

    #[test]
    fn test_analysis_logger_clone() {
        let logger = AnalysisLogger::new(VerbosityLevel::Summary);
        let cloned = logger.clone();
        assert_eq!(cloned.is_color_enabled(), logger.is_color_enabled());
    }

    #[test]
    fn test_ui_phase_debug_and_clone() {
        let phase = UiPhase::Complete;
        let cloned = phase;
        assert_eq!(cloned, UiPhase::Complete);
        let debug_str = format!("{:?}", phase);
        assert_eq!(debug_str, "Complete");
    }

    #[test]
    fn test_verbosity_level_copy() {
        let level = VerbosityLevel::Detailed;
        let copied = level;
        assert_eq!(level, copied);
    }

    #[test]
    fn test_ui_phase_copy() {
        let phase = UiPhase::Scanning;
        let copied = phase;
        assert_eq!(phase, copied);
    }

    // ── DNS failure tracking ─────────────────────────────────────────

    #[test]
    fn test_dns_failure_tracking_initial_state() {
        let logger = AnalysisLogger::new(VerbosityLevel::Silent);
        assert!(!logger.has_dns_failures());
        assert_eq!(logger.dns_failure_count(), 0);
    }

    #[test]
    fn test_dns_failure_tracking_single() {
        let logger = AnalysisLogger::new(VerbosityLevel::Silent);
        logger.record_dns_failure();
        assert!(logger.has_dns_failures());
        assert_eq!(logger.dns_failure_count(), 1);
    }

    #[test]
    fn test_dns_failure_tracking_multiple() {
        let logger = AnalysisLogger::new(VerbosityLevel::Silent);
        logger.record_dns_failure();
        logger.record_dns_failure();
        logger.record_dns_failure();
        assert_eq!(logger.dns_failure_count(), 3);
    }

    #[test]
    fn test_dns_failure_counter_is_shared() {
        let logger = AnalysisLogger::new(VerbosityLevel::Silent);
        let counter = logger.dns_failure_counter();
        counter.fetch_add(1, Ordering::Relaxed);
        assert!(logger.has_dns_failures());
        assert_eq!(logger.dns_failure_count(), 1);
    }

    #[test]
    fn test_dns_failure_warning_banner_no_color() {
        let logger = AnalysisLogger::new(VerbosityLevel::Silent);
        logger.record_dns_failure();
        logger.record_vendor_relationships(0);
        logger.record_unique_vendors(0);
        // end_time is set inside finish_progress; summary works without it
        // This exercises the WARNING banner path (dns_failures > 0, vendors == 0)
        logger.print_final_summary();
    }

    #[test]
    fn test_dns_failure_success_with_note_no_color() {
        let logger = AnalysisLogger::new(VerbosityLevel::Silent);
        logger.record_dns_failure();
        logger.record_vendor_relationships(5);
        logger.record_unique_vendors(3);
        // end_time is set inside finish_progress; summary works without it
        // This exercises the SUCCESS-with-DNS-note path (dns_failures > 0, vendors > 0)
        logger.print_final_summary();
    }

    #[test]
    fn test_dns_failure_warning_banner_colored() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Silent);
        logger.record_dns_failure();
        logger.record_dns_failure();
        logger.record_vendor_relationships(0);
        logger.record_unique_vendors(0);
        // end_time is set inside finish_progress; summary works without it
        logger.print_final_summary();
    }

    #[test]
    fn test_dns_failure_success_with_note_colored() {
        let logger = AnalysisLogger::new_forced_color(VerbosityLevel::Silent);
        logger.record_dns_failure();
        logger.record_vendor_relationships(5);
        logger.record_unique_vendors(3);
        // end_time is set inside finish_progress; summary works without it
        logger.print_final_summary();
    }

    #[test]
    fn test_no_dns_failure_success_unchanged() {
        let logger = AnalysisLogger::new(VerbosityLevel::Silent);
        logger.record_vendor_relationships(5);
        logger.record_unique_vendors(3);
        // end_time is set inside finish_progress; summary works without it
        // No DNS failures — should print normal SUCCESS message
        logger.print_final_summary();
    }
}
