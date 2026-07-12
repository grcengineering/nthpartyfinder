use anyhow::{bail, Context, Result};
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
use crate::cli::{Args, CacheCommands, Cli, Commands, ReviewCommands};
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
use crate::review;
use crate::subprocessor;
use crate::vendor::VendorRelationship;
use crate::vendor_registry;
use crate::verification_logger;
use crate::whois;

use std::path::PathBuf;

/// Process exit code carried as an error so `run_inner` can bubble it up to
/// `main` for a clean `std::process::exit`.
///
/// Known codes:
/// - `1` — generic failure (config error, analysis timeout, batch failure)
/// - `2` — invalid CLI arguments
/// - `4` — analysis results could not be read back from the disk sink
/// - `130` — interrupted by the user (SIGINT)
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

    // coverage(off): thin stdin wrapper — delegates to io::stdin().lock().read_line();
    // cannot redirect process stdin in unit tests
    #[cfg_attr(coverage_nightly, coverage(off))]
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
            .filter(|r| {
                // A company that EXPLICITLY discloses a vendor on its own
                // subprocessor/legal page is naming an intentional relationship —
                // keep it even when the vendor is a common infrastructure provider
                // (AWS, Cloudflare, Microsoft). Infra suppression targets incidental
                // providers surfaced by DNS/web-traffic scanning, not disclosed
                // subprocessor listings (mirrors the GRC-501 marketing-filter scope).
                is_explicit_subprocessor_disclosure(&r.nth_party_record_type)
                    || !analysis::is_common_denominator(&r.nth_party_domain)
            })
            .collect();
        let removed = before - filtered.len();
        (filtered, removed)
    }
}

/// Whether a discovery source is passive web-traffic scanning (page source or
/// runtime network requests). Marketing/tracking suppression is scoped to these
/// sources so disclosed subprocessor-page listings are never dropped (GRC-501).
fn is_web_traffic_source(record_type: &crate::vendor::RecordType) -> bool {
    use crate::vendor::RecordType;
    matches!(
        record_type,
        RecordType::WebTrafficSource | RecordType::WebTrafficNetwork
    )
}

/// Whether a discovery source is an explicit subprocessor disclosure — a vendor a
/// company named on its own subprocessor/legal page (or hosted trust center). Such
/// relationships are intentional and exempt from common-infra suppression, so a
/// disclosed subprocessor list stays complete even when it names AWS/Cloudflare/etc.
fn is_explicit_subprocessor_disclosure(record_type: &crate::vendor::RecordType) -> bool {
    use crate::vendor::RecordType;
    matches!(
        record_type,
        RecordType::HttpSubprocessor | RecordType::TrustCenterApi
    )
}

/// Suppress social / ad-network / marketing-pixel domains that were discovered
/// *only* via passive web-traffic scanning (GRC-501). These are tracking
/// endpoints, not data subprocessors, and are the dominant false-positive class
/// after TF5 triage. Suppression is gated on `include_infra` (the same flag that
/// keeps common-denominator noise) so `--include-infra` shows the full picture,
/// and is scoped by discovery source so a domain disclosed on an actual
/// subprocessor page (`HttpSubprocessor`) is retained.
/// Returns (filtered results, number removed).
pub fn filter_marketing_tracking(
    results: Vec<VendorRelationship>,
    include_infra: bool,
) -> (Vec<VendorRelationship>, usize) {
    if include_infra {
        (results, 0)
    } else {
        let before = results.len();
        let filtered: Vec<VendorRelationship> = results
            .into_iter()
            .filter(|r| {
                !(analysis::is_marketing_tracking_domain(&r.nth_party_domain)
                    && is_web_traffic_source(&r.nth_party_record_type))
            })
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
    compute_analysis_timeout_with_env_and_default(cli_timeout, env_value, None)
}

/// Resolve `--parallel-jobs` against the configured concurrency.
///
/// `0` means the operator supplied no cap, so the configured value stands. Any positive
/// value narrows it. The result is floored at 1 so semaphores built from it always have a
/// permit to hand out.
pub fn effective_parallel_jobs(parallel_jobs: usize, configured: usize) -> usize {
    let resolved = if parallel_jobs == 0 {
        configured
    } else {
        configured.min(parallel_jobs)
    };
    resolved.max(1)
}

/// Resolve the analysis timeout with full precedence (#4): explicit `--timeout` CLI value
/// wins, then `NTHPARTY_ANALYSIS_TIMEOUT_SECS`, then the user's persisted default, then the
/// built-in 600s. `0` at any layer disables the timeout (returns None).
pub fn compute_analysis_timeout_with_env_and_default(
    cli_timeout: Option<u64>,
    env_value: Option<String>,
    prefs_default: Option<u64>,
) -> Option<std::time::Duration> {
    let timeout_secs: u64 = cli_timeout
        .or_else(|| env_value.and_then(|v| v.parse().ok()))
        .or(prefs_default)
        .unwrap_or(600);
    if timeout_secs == 0 {
        None
    } else {
        Some(std::time::Duration::from_secs(timeout_secs))
    }
}

/// The user's response to the first-run timeout prompt (#4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutChoice {
    /// Keep the built-in default for this run; persist nothing.
    KeepDefault,
    /// Use this value (seconds; 0 = disabled) for this run only.
    ThisRun(u64),
    /// Use this value for this run AND persist it as the new default.
    SetDefault(u64),
}

/// Parse the first-run timeout prompt input (pure, testable).
///
/// - empty / whitespace            → KeepDefault
/// - `<n>`                         → ThisRun(n)   (0 = disable for this run)
/// - `<n> d` / `<n> default` / `<n> save` / `<n>!` → SetDefault(n)
/// - anything else                 → None (caller re-prompts or keeps default)
pub fn parse_timeout_choice(input: &str) -> Option<TimeoutChoice> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Some(TimeoutChoice::KeepDefault);
    }
    // "<n>!" shorthand for set-default.
    if let Some(num) = trimmed.strip_suffix('!') {
        return num
            .trim()
            .parse::<u64>()
            .ok()
            .map(TimeoutChoice::SetDefault);
    }
    let mut parts = trimmed.split_whitespace();
    let first = parts.next()?;
    match (first.parse::<u64>(), parts.next()) {
        (Ok(n), None) => Some(TimeoutChoice::ThisRun(n)),
        (Ok(n), Some(kw)) if matches!(kw.to_lowercase().as_str(), "d" | "default" | "save") => {
            Some(TimeoutChoice::SetDefault(n))
        }
        _ => None,
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
    collect_unverified_orgs_with_lookup(vendors, |d| known_vendors::lookup(d).is_some())
}

/// Inner testable function: accepts a lookup predicate for known vendor checking.
pub fn collect_unverified_orgs_with_lookup(
    vendors: &HashMap<String, String>,
    is_known_vendor: impl Fn(&str) -> bool,
) -> Vec<interactive::UnverifiedOrgMapping> {
    let mut unverified = Vec::new();
    for (domain, org) in vendors.iter() {
        if is_known_vendor(domain) {
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

/// Outcome of config loading decision logic.
#[derive(Debug)]
pub enum ConfigOutcome {
    Ready(Box<AppConfig>),
    CreatedNew(PathBuf),
    Exit { message: String, code: i32 },
}

/// Process the result of AppConfig::load() and optional interactive prompt.
/// Separates config-loading decision logic from the I/O calls themselves.
///
/// `prompt_result` should be `Some(...)` only when `load_result` was
/// `Err(ConfigError::FileNotFound(_))` and the caller ran the interactive prompt.
pub fn process_config_result(
    load_result: Result<AppConfig, ConfigError>,
    prompt_result: Option<Result<Option<PathBuf>, String>>,
) -> ConfigOutcome {
    match load_result {
        Ok(cfg) => ConfigOutcome::Ready(Box::new(cfg)),
        Err(ConfigError::FileNotFound(_path)) => match prompt_result {
            Some(Ok(Some(created_path))) => ConfigOutcome::CreatedNew(created_path),
            _ => match AppConfig::load_default() {
                Ok(cfg) => ConfigOutcome::Ready(Box::new(cfg)),
                Err(e) => ConfigOutcome::Exit {
                    message: format!("Failed to load embedded default configuration: {}", e),
                    code: 1,
                },
            },
        },
        Err(e) => ConfigOutcome::Exit {
            message: format!("Configuration error: {}", e),
            code: 1,
        },
    }
}

/// Extract warning messages from dependency check results.
/// Returns the message string for each unavailable dependency.
pub fn format_dep_check_warnings(results: &[dep_check::DepCheckResult]) -> Vec<String> {
    results
        .iter()
        .filter(|r| !r.available)
        .filter_map(|r| r.message.clone())
        .collect()
}

/// What to do about the runtime-fetched NER model before NER init. Pure routing
/// so the decision is unit-testable without stdin, the network, or the filesystem.
#[cfg(all(feature = "runtime-ner", not(feature = "embedded-ner")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelFetchAction {
    /// NER is not wanted — do nothing.
    Skip,
    /// Model is already cached and SHA-256-verified — do nothing.
    AlreadyCached,
    /// Wanted + not cached, running non-interactively with no consent flag: warn
    /// and disable NER rather than hang on a hidden prompt (GRC-364 discipline).
    SkipNonInteractive,
    /// Wanted + not cached: fetch it. `assume_yes` skips the interactive prompt
    /// (set by `--download-ner-model`); otherwise the fetch path prompts `[y/N]`.
    Fetch { assume_yes: bool },
}

/// Decide what to do about the runtime NER model. Pure function of: whether NER is
/// wanted, whether the model is already cached+valid, whether the operator passed
/// `--download-ner-model`, and whether stdin is an interactive terminal. The
/// precedence (not-wanted → cached → explicit-flag → interactive → non-interactive)
/// guarantees we never prompt when unwanted/cached and never hang when headless.
#[cfg(all(feature = "runtime-ner", not(feature = "embedded-ner")))]
pub fn decide_model_action(
    slm_wanted: bool,
    cached_and_valid: bool,
    download_flag: bool,
    is_terminal: bool,
) -> ModelFetchAction {
    if !slm_wanted {
        ModelFetchAction::Skip
    } else if cached_and_valid {
        ModelFetchAction::AlreadyCached
    } else if download_flag {
        ModelFetchAction::Fetch { assume_yes: true }
    } else if is_terminal {
        ModelFetchAction::Fetch { assume_yes: false }
    } else {
        ModelFetchAction::SkipNonInteractive
    }
}

#[cfg(all(test, feature = "runtime-ner", not(feature = "embedded-ner")))]
mod model_action_tests {
    use super::{decide_model_action, ModelFetchAction};

    #[test]
    fn ner_not_wanted_is_skip() {
        // slm_wanted=false short-circuits regardless of the other inputs.
        assert_eq!(
            decide_model_action(false, false, false, false),
            ModelFetchAction::Skip
        );
        assert_eq!(
            decide_model_action(false, true, true, true),
            ModelFetchAction::Skip
        );
    }

    #[test]
    fn cached_valid_is_already_cached() {
        assert_eq!(
            decide_model_action(true, true, false, false),
            ModelFetchAction::AlreadyCached
        );
        // A cached+valid model wins over both the download flag and a TTY.
        assert_eq!(
            decide_model_action(true, true, true, true),
            ModelFetchAction::AlreadyCached
        );
    }

    #[test]
    fn download_flag_fetches_without_prompt() {
        assert_eq!(
            decide_model_action(true, false, true, false),
            ModelFetchAction::Fetch { assume_yes: true }
        );
        // The explicit flag wins even on a TTY — no prompt.
        assert_eq!(
            decide_model_action(true, false, true, true),
            ModelFetchAction::Fetch { assume_yes: true }
        );
    }

    #[test]
    fn interactive_no_flag_fetches_with_prompt() {
        assert_eq!(
            decide_model_action(true, false, false, true),
            ModelFetchAction::Fetch { assume_yes: false }
        );
    }

    #[test]
    fn noninteractive_no_flag_skips_without_hanging() {
        assert_eq!(
            decide_model_action(true, false, false, false),
            ModelFetchAction::SkipNonInteractive
        );
    }
}

/// Build CLI argument vector for a batch-mode subprocess invocation.
///
/// GRC-367 (fix 4): `dns_rate_limit` is forwarded as `--dns-rate-limit <n>` when set.
/// Previously this argument was dropped entirely, so every batch child reverted to the
/// config-default DNS qps — silently ignoring an operator's explicit `--dns-rate-limit`
/// (the throttle they set precisely to avoid the 429s GRC-367 is about).
pub fn build_batch_domain_args(
    domain: &str,
    format: &str,
    depth: Option<u32>,
    dns_only: bool,
    batch_combined: bool,
    output_base: &Path,
    dns_rate_limit: Option<u32>,
) -> Vec<String> {
    let mut cmd_args = vec![
        "nthpartyfinder".to_string(),
        "-d".to_string(),
        domain.to_string(),
        "-f".to_string(),
        format.to_string(),
    ];
    if let Some(d) = depth {
        cmd_args.push("-r".to_string());
        cmd_args.push(d.to_string());
    }
    if dns_only {
        cmd_args.push("--dns-only".to_string());
    }
    // fix 4: propagate the operator-supplied DNS rate limit to each batch child.
    if let Some(rl) = dns_rate_limit {
        cmd_args.push("--dns-rate-limit".to_string());
        cmd_args.push(rl.to_string());
    }
    if !batch_combined {
        let domain_dir = output_base.join(domain.replace('.', "_"));
        cmd_args.push("--output-dir".to_string());
        cmd_args.push(domain_dir.to_string_lossy().to_string());
    }
    cmd_args
}

/// Resolve the final output path from a computed default and optional user
/// override. If `user_input` (trimmed) is empty, use `computed_path`. Otherwise,
/// treat `user_input` as a directory and join with `output_filename`.
///
/// Returns `Err` if the user-provided path contains traversal sequences (`..`).
pub fn resolve_final_output_path(
    computed_path: &str,
    output_filename: &str,
    user_input: &str,
) -> Result<String, String> {
    if user_input.is_empty() {
        return Ok(computed_path.to_string());
    }

    let input_path = Path::new(user_input);
    for component in input_path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(format!(
                "Path traversal detected: '{}' contains '..' components",
                user_input
            ));
        }
    }

    let custom_path = input_path.join(output_filename);
    Ok(custom_path.to_string_lossy().to_string())
}

/// Combined results from new + resumed analysis, deduplicated and filtered.
#[derive(Debug)]
pub struct AssembledResults {
    pub results: Vec<VendorRelationship>,
    pub raw_count: usize,
    pub dedup_count: usize,
    pub infra_removed: usize,
    pub marketing_removed: usize,
    /// What report finalization changed. See [`crate::finalize`].
    pub finalize: crate::finalize::FinalizeStats,
}

/// Combine new and resumed results, deduplicate, and optionally filter infra
/// and web-traffic-sourced marketing/tracking false positives (GRC-501).
pub fn assemble_and_filter_results(
    new_results: Vec<VendorRelationship>,
    resumed_results: Vec<VendorRelationship>,
    include_infra: bool,
) -> AssembledResults {
    let mut all_results = resumed_results;
    all_results.extend(new_results);
    let (deduped, raw_count) = deduplicate_results(all_results);
    let dedup_count = deduped.len();
    let (filtered, infra_removed) = filter_infra_providers(deduped, include_infra);
    let (filtered, marketing_removed) = filter_marketing_tracking(filtered, include_infra);
    // The single choke point. Every relationship from every source, every run mode (fresh,
    // resumed, batch) passes through here, so this is the only place an attribution invariant
    // can be enforced once instead of remembered at each new emit site.
    let (filtered, finalize) = crate::finalize::finalize_report(filtered);
    AssembledResults {
        results: filtered,
        raw_count,
        dedup_count,
        infra_removed,
        marketing_removed,
        finalize,
    }
}

/// Dispatch export to the appropriate format handler.
pub fn dispatch_export(
    results: &[VendorRelationship],
    format: &str,
    output_path: &str,
) -> Result<()> {
    match format {
        "json" => export::export_json(results, output_path),
        "markdown" => export::export_markdown(results, output_path),
        "html" => export::export_html(results, output_path),
        _ => export::export_csv(results, output_path),
    }
}

/// State restored from a checkpoint for resuming an analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct RestoredCheckpointState {
    pub discovered_vendors: HashMap<String, String>,
    pub completed_domains: HashSet<String>,
    pub results_file: Option<String>,
    pub results_count: usize,
    pub pending_count: usize,
}

/// Extract resumable state from a checkpoint. Returns None if the checkpoint
/// has no completed work (fresh checkpoint).
pub fn extract_checkpoint_state(
    checkpoint: &crate::checkpoint::Checkpoint,
) -> Option<RestoredCheckpointState> {
    if checkpoint.completed_domains.is_empty() {
        None
    } else {
        let results_file = if !checkpoint.results_file.is_empty() {
            Some(checkpoint.results_file.clone())
        } else {
            None
        };
        Some(RestoredCheckpointState {
            discovered_vendors: checkpoint.discovered_vendors.clone(),
            completed_domains: checkpoint.completed_domains.clone(),
            results_file,
            results_count: checkpoint.results_count,
            pending_count: checkpoint.pending_domains.len(),
        })
    }
}

/// Count unique vendor organizations in a results set.
pub fn count_unique_vendors(results: &[VendorRelationship]) -> usize {
    results
        .iter()
        .map(|r| &r.nth_party_organization)
        .collect::<HashSet<_>>()
        .len()
}

// coverage(off): CLI entry point — calls Cli::parse() (reads process args via std::env::args)
// and std::process::exit(); both are process-level operations untestable in unit tests.
// Delegates to run_inner() which has all pure logic extracted and tested.
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn run() -> Result<()> {
    eprintln!("nthpartyfinder v{}", env!("CARGO_PKG_VERSION"));

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

    if let Some(Commands::Review { action }) = &cli.command {
        return run_review(action).await;
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

/// Handle the non-interactive `review` subcommands — the Claude plugin contract.
/// Thin I/O orchestrator over the individually-tested `review` / `known_vendors`
/// logic; coverage-off because it only sequences stdin/stdout/filesystem calls.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_review(action: &ReviewCommands) -> Result<()> {
    match action {
        ReviewCommands::Path => {
            println!("{}", known_vendors::resolved_overrides_path().display());
            Ok(())
        }
        ReviewCommands::Apply { input, dry_run } => {
            let json = std::fs::read_to_string(input)
                .with_context(|| format!("read decisions file {}", input))?;
            let decisions = review::parse_decisions(&json)?;
            let kv = known_vendors::KnownVendors::load()?;
            // Log the resolved store path so the operator can confirm this run
            // writes exactly where the next scan reads (no silent path mismatch).
            println!(
                "Store: {}",
                known_vendors::resolved_overrides_path().display()
            );
            let report = review::apply_decisions(&kv, &decisions, *dry_run)?;
            if *dry_run {
                println!("DRY RUN — no changes written");
            }
            for (d, o) in &report.written {
                println!("  wrote     {} -> {}", d, o);
            }
            for (d, o) in &report.would_write {
                println!("  would     {} -> {}", d, o);
            }
            for d in &report.unchanged {
                println!("  unchanged {}", d);
            }
            for d in &report.abstained {
                println!("  abstained {}", d);
            }
            for d in &report.skipped_precedence {
                println!("  skipped   {} (higher-trust entry exists)", d);
            }
            for (d, reason) in &report.rejected {
                eprintln!("  REJECTED  {}: {}", d, reason);
            }
            println!("{}", report.summary());
            // Persist an audit trail of WHY each mapping was accepted (the cited
            // signals), co-located with the store so it survives the transient
            // decisions file — the durable answer to "how do I know this is right?".
            // A written override without a recoverable audit line is a failure.
            let mut audit_failed = false;
            if !*dry_run && !report.written.is_empty() {
                use std::io::Write as _;
                let audit_path =
                    known_vendors::resolved_overrides_path().with_extension("audit.jsonl");
                let ts = chrono::Utc::now().to_rfc3339();
                let written: std::collections::HashSet<String> =
                    report.written.iter().map(|(d, _)| d.clone()).collect();
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&audit_path)
                {
                    Ok(mut f) => {
                        for d in &decisions.decisions {
                            if written.contains(&d.domain.trim().to_lowercase()) {
                                match review::audit_line(d, &ts) {
                                    Ok(line) => {
                                        if writeln!(f, "{}", line).is_err() {
                                            audit_failed = true;
                                        }
                                    }
                                    Err(_) => audit_failed = true,
                                }
                            }
                        }
                        if audit_failed {
                            eprintln!(
                                "ERROR: failed to write one or more audit-trail lines to {}",
                                audit_path.display()
                            );
                        } else {
                            println!("Audit trail appended to {}", audit_path.display());
                        }
                    }
                    Err(e) => {
                        audit_failed = true;
                        eprintln!(
                            "ERROR: could not open audit trail {}: {}",
                            audit_path.display(),
                            e
                        );
                    }
                }
            }
            // Non-zero exit if any decision was rejected OR a written decision's
            // audit line could not be recorded — automation must notice both.
            if !report.rejected.is_empty() || audit_failed {
                std::process::exit(3);
            }
            Ok(())
        }
        ReviewCommands::List { source } => {
            let kv = known_vendors::KnownVendors::load()?;
            let mut count = 0usize;
            for (domain, entry) in kv.list_overrides() {
                if let Some(s) = source {
                    if &entry.source != s {
                        continue;
                    }
                }
                println!(
                    "{}\t{}\t[{}]\t{}",
                    domain, entry.organization, entry.source, entry.added
                );
                count += 1;
            }
            eprintln!("{} override(s)", count);
            Ok(())
        }
        ReviewCommands::Revert { domain } => {
            let kv = known_vendors::KnownVendors::load()?;
            if kv.remove_override(domain)? {
                println!("Removed override for {}", domain);
            } else {
                println!("No override found for {}", domain);
            }
            Ok(())
        }
    }
}

// coverage(off): integration orchestrator — sequences I/O operations (filesystem, network,
// stdin/stdout, system binaries, signal handlers, ONNX runtime, sysinfo). All branching/decision
// logic extracted into individually-tested phase functions: process_config_result,
// format_dep_check_warnings, compute_feature_flags, build_output_filename, build_batch_domain_args,
// resolve_final_output_path, resolve_checkpoint_resume, extract_checkpoint_state,
// assemble_and_filter_results, dispatch_export, count_unique_vendors, deduplicate_results,
// filter_infra_providers, compute_analysis_timeout, build_full_output_path,
// collect_unverified_orgs.
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn run_inner(mut args: Args, input: &dyn InputSource) -> Result<()> {
    // Chrome processes are now pooled and reused across renders rather than killed after each
    // one. The pool is a `Lazy` static, and statics never run `Drop`, so this guard is what
    // reaps them — on every return path out of the scan, including `?` and `bail!`.
    let _browser_pool = crate::browser_pool::PoolShutdownGuard;
    if args.init {
        // --init previously overwrote an existing (possibly customized) config
        // while printing "Created" — silent data loss. Refuse and instruct.
        let existing = std::path::Path::new(crate::config::CONFIG_PATH);
        if existing.exists() {
            eprintln!(
                "❌ {} already exists — refusing to overwrite it.",
                existing.display()
            );
            eprintln!(
                "   Move or delete the file first if you want a fresh default configuration."
            );
            bail!(AppExitCode(2));
        }
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

    // Initialize the tracing subscriber + AnalysisLogger up-front so the first status
    // lines ("Parsing arguments…", "Loading configuration…", "Checking dependencies…")
    // flow through the timestamped logger ([HH:MM:SS.mmm] LEVEL:) instead of raw
    // eprintln (#1). The subscriber also silences headless_chrome's benign CDP-teardown
    // logs (#5) and maps -v levels: default WARN, -v INFO, -vv DEBUG.
    // try_init: tests/embedders may already have a subscriber installed.
    let trace_level = match args.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        _ => tracing::Level::DEBUG,
    };
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(trace_level.into())
        .from_env_lossy()
        // headless_chrome's CDP transport logs benign teardown races at WARN/ERROR
        // ("Couldn't send browser an event", "Transport loop got a timeout") when the
        // throwaway headless instance is killed with events still in flight. Not a
        // nthpartyfinder error, not the user's Chrome — silence the dependency target.
        .add_directive(
            "headless_chrome=off"
                .parse()
                .expect("static tracing directive is valid"),
        );
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        // Bar-safe writer: routes through the active MultiProgress so warn lines don't
        // splice into in-place progress redraws.
        .with_writer(crate::logger::ProgressAwareWriter::default)
        .with_target(false)
        .compact()
        .try_init();
    let verbosity = VerbosityLevel::from_verbose_count(args.verbose);
    let logger = Arc::new(match &args.log_file {
        Some(log_file_path) => AnalysisLogger::with_log_file(verbosity, log_file_path.clone()),
        None => AnalysisLogger::new(verbosity),
    });

    logger.info("Parsing arguments...");
    logger.info("Loading configuration...");
    let load_result = AppConfig::load();
    let prompt_result = match &load_result {
        Err(ConfigError::FileNotFound(_)) => {
            Some(AppConfig::prompt_create_config().map_err(|e| e.to_string()))
        }
        _ => None,
    };
    let mut _app_config = match process_config_result(load_result, prompt_result) {
        ConfigOutcome::Ready(cfg) => *cfg,
        ConfigOutcome::CreatedNew(path) => {
            println!(
                "✅ Created default configuration file at: {}",
                path.display()
            );
            println!("   Edit this file to customize settings, then run nthpartyfinder again.");
            return Ok(());
        }
        ConfigOutcome::Exit { message, code } => {
            eprintln!("❌ {}", message);
            bail!(AppExitCode(code));
        }
    };

    // GRC-367: honor --dns-rate-limit by overriding the configured DNS qps before any
    // DnsServerPool is built (every pool-construction site reads from this config), so the
    // now-live per-process limiter is actually controllable from the CLI.
    if let Some(rl) = args.dns_rate_limit {
        _app_config.rate_limits.dns_queries_per_second = rl;
    }

    // Load user-level prefs (#3/#4). If a prior run persisted the ONNX Runtime path,
    // export it before the dependency check so NER works without re-download or manual
    // shell setup — unless the environment already provides one.
    let mut prefs = crate::prefs::Prefs::load();
    if std::env::var_os("ORT_DYLIB_PATH").is_none() {
        if let Some(ort) = prefs.ort_dylib_path.as_deref() {
            std::env::set_var("ORT_DYLIB_PATH", ort);
        }
    }

    logger.info("Checking dependencies...");
    #[cfg(any(feature = "embedded-ner", feature = "runtime-ner"))]
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

    // runtime-ner only: the NER model is not embedded, so ensure it is present
    // (consent-gated, SHA-256-verified) before NER init. embedded-ner builds skip
    // this entirely — the model is baked into the binary. If both features are on,
    // embedded-ner wins and this block is compiled out.
    #[cfg(all(feature = "runtime-ner", not(feature = "embedded-ner")))]
    {
        let slm_wanted =
            args.enable_slm || (!args.disable_slm && _app_config.discovery.ner_enabled);
        let action = decide_model_action(
            slm_wanted,
            crate::model_fetch::is_model_cached_and_valid(),
            args.download_ner_model,
            std::io::stdin().is_terminal(),
        );
        match action {
            ModelFetchAction::Skip => {}
            ModelFetchAction::AlreadyCached => {}
            ModelFetchAction::SkipNonInteractive => {
                eprintln!(
                    "⚠️  NER model (~183 MB) not installed and running non-interactively. \
                     Re-run with --download-ner-model to fetch it, or --disable-slm to silence \
                     this. Continuing without NER."
                );
                args.disable_slm = true;
            }
            ModelFetchAction::Fetch { assume_yes } => {
                match crate::model_fetch::ensure_model_available(assume_yes).await {
                    Ok(_path) => {}
                    Err(e) => {
                        eprintln!("⚠️  {}", e);
                        eprintln!("   Continuing without NER (--disable-slm implied).");
                        args.disable_slm = true;
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
            for msg in format_dep_check_warnings(&results) {
                eprintln!("⚠️  {}", msg);
            }
            let ort_unavailable = results
                .iter()
                .any(|r| r.name == "ONNX Runtime" && !r.available);
            if ort_unavailable {
                eprintln!("⚠️  ONNX Runtime not available — continuing without NER (--disable-slm implied).");
                args.disable_slm = true;
            }
        }
        Err(e) => {
            eprintln!("⚠️  Dependency issue: {}", e);
            eprintln!("   Continuing with reduced functionality.");
        }
    }

    logger.start_init_progress(5).await;

    #[cfg(any(feature = "embedded-ner", feature = "runtime-ner"))]
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

    #[cfg(any(feature = "embedded-ner", feature = "runtime-ner"))]
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
    #[cfg(not(any(feature = "embedded-ner", feature = "runtime-ner")))]
    {
        logger.complete_init_step("NER not compiled in").await;
    }

    logger.finish_init().await;

    // (#2) The vendor-registry count is already reported once by complete_init_step
    // above; the previously-duplicated logger.info line here was removed. Only the
    // enabled-discovery-method lines (not covered by the init steps) remain.
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
        // `std::process::exit` runs no destructors, so the `PoolShutdownGuard` in `run_inner`
        // never fires here. Browsers are pooled now, so up to MAX_RENDER_PERMITS idle Chrome
        // processes would outlive the scanner on every Ctrl-C. Reap them explicitly; `shutdown`
        // is idempotent and recovers from a poisoned pool lock.
        //
        // Not unit-tested: this path ends in `process::exit`. Verified empirically instead —
        // SIGINT a live depth-3 scan and assert zero surviving Chrome processes.
        crate::browser_pool::shutdown();
        eprintln!("⚠️  Force exiting (checkpoint may be incomplete).");
        std::process::exit(130);
    }).unwrap_or_else(|e| {
        eprintln!("⚠️  Warning: Failed to set Ctrl-C handler: {}. Interrupt signals may not be handled gracefully.", e);
    });

    if args.is_batch_mode() {
        let input_path = std::path::Path::new(
            args.input_file
                .as_ref()
                .expect("is_batch_mode() guarantees input_file is Some"),
        );
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
            // fix 4: capture the operator's DNS rate limit so it is forwarded to the child.
            let dns_rate_limit = args.dns_rate_limit;
            let results = results.clone();
            let logger = logger.clone();

            // A panicked task pushes nothing into `results`; keep its identity
            // alongside the handle so the join loop records it as a failed row
            // instead of letting the domain silently vanish from the summary.
            let domain_for_join = domain.clone();
            let label_for_join = label.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem
                    .acquire()
                    .await
                    .expect("batch concurrency semaphore is never closed");
                let domain_start = std::time::Instant::now();

                logger.info(&format!("Batch: starting analysis of {}", domain));

                let cmd_args = build_batch_domain_args(
                    &domain,
                    &format,
                    depth,
                    dns_only,
                    batch_combined,
                    &output_base,
                    dns_rate_limit,
                );
                if !batch_combined {
                    let domain_dir = output_base.join(domain.replace('.', "_"));
                    let _ = std::fs::create_dir_all(&domain_dir);
                }

                let output = tokio::process::Command::new(
                    std::env::current_exe()
                        .expect("current_exe must be resolvable to spawn batch workers"),
                )
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
            handles.push((domain_for_join, label_for_join, handle));
        }

        for (domain, label, handle) in handles {
            if let Err(e) = handle.await {
                // The task panicked before pushing its row — without this, the
                // domain is counted as neither success nor failure, the summary
                // exit-code gate never trips, and the run exits 0 incomplete.
                logger.error(&format!("Batch: task for {} panicked: {}", domain, e));
                results.lock().await.push(batch::DomainAnalysisResult {
                    domain,
                    label,
                    success: false,
                    error: Some(format!("internal task failure: {}", e)),
                    relationship_count: 0,
                    output_file: None,
                    duration_secs: 0.0,
                });
            }
        }

        summary.domain_results = Arc::try_unwrap(results)
            .unwrap_or_else(|arc| {
                // All worker tasks have completed above, so the lock is uncontended.
                // (tokio's Mutex has no poisoning; try_lock cannot WouldBlock here.)
                let guard = arc
                    .try_lock()
                    .expect("uncontended: all batch worker tasks have completed");
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
            let _ = io::Write::flush(&mut io::stdout());

            let mut user_input = String::new();
            if let Err(e) = input.read_line(&mut user_input) {
                eprintln!(
                    "Warning: Failed to read stdin: {}, using default output path",
                    e
                );
            }
            let user_input = user_input.trim();
            match resolve_final_output_path(&output_path_str, &output_filename, user_input) {
                Ok(path) => path,
                Err(msg) => {
                    eprintln!("⚠️  {}", msg);
                    eprintln!("Using default output path instead.");
                    output_path_str.to_string()
                }
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
                                    let _ = io::Write::flush(&mut io::stdout());

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
                                    let _ = io::Write::flush(&mut io::stdout());

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
        match extract_checkpoint_state(&cp) {
            Some(state) => {
                logger.info(&format!(
                    "Restoring state: {} completed domains, {} pending, {} results on disk",
                    state.completed_domains.len(),
                    state.pending_count,
                    state.results_count
                ));
                (
                    state.discovered_vendors,
                    state.completed_domains,
                    state.results_file,
                )
            }
            None => (HashMap::new(), HashSet::new(), None),
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
                // Ask the user to confirm a name only when the tool does not actually KNOW it —
                // when the name is a domain-derived echo. `is_verified` alone is the wrong
                // trigger: it means "a CURATED source attested this", so gating on it would
                // prompt for every organization whose name came from its own web page or WHOIS
                // record — most of them. Prompting on a name we extracted correctly is exactly
                // the hand-mapping burden this work exists to remove.
                if !org_result.is_verified
                    && analysis::is_likely_inferred_org(domain, &normalized_name)
                {
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
    // `--parallel-jobs 0` means "no operator cap", so the semaphore falls back to the
    // depth-1 configured concurrency. A zero-permit semaphore would deadlock any future
    // caller that acquires it.
    let semaphore = Arc::new(Semaphore::new(effective_parallel_jobs(
        args.parallel_jobs,
        _app_config.analysis.get_concurrency_for_depth(1),
    )));

    // GRC-367 (fix 1): wire the pool's choke-point throttle counter to the SAME atomic the
    // exit-3 guard reads (`logger.has_dns_failures()`), so a DoH throttle on any path — incl.
    // the SPF include-chain recursion — is counted once at the source.
    let dns_pool = Arc::new(
        dns::DnsServerPool::from_config(&_app_config)
            .with_failure_counter(logger.dns_failure_counter_arc()),
    );
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

    let depth_one_concurrency = _app_config.analysis.get_concurrency_for_depth(1);
    let recursive_limit = effective_parallel_jobs(args.parallel_jobs, depth_one_concurrency);
    let recursive_semaphore = Arc::new(Semaphore::new(recursive_limit));
    logger.debug(&format!(
        "Configured concurrency: {} main jobs, {} initial recursive jobs (strategy: {:?})",
        recursive_limit, recursive_limit, _app_config.analysis.strategy
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

    // (#4) First-run timeout onboarding. Fires at most once, and only when interactive,
    // with no explicit --timeout, no env override, and not yet onboarded — so it never
    // breaks non-interactive/CI runs. Lets the user keep 600s, override for this run, or
    // persist a new default.
    let env_timeout = std::env::var("NTHPARTY_ANALYSIS_TIMEOUT_SECS").ok();
    if args.timeout.is_none()
        && env_timeout.is_none()
        && !prefs.onboarded
        && std::io::stdin().is_terminal()
    {
        eprintln!();
        eprintln!("  ⏱  Analysis timeout (first-run setup)");
        eprintln!("     Default is 600s. Depth-3 / cold-cache scans often need more.");
        eprintln!("       [Enter]   keep 600s for this run");
        eprintln!("       <n>       use <n> seconds for this run (0 = no timeout)");
        eprintln!("       <n> d     use <n> seconds AND save it as your default");
        eprint!("     > ");
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_ok() {
            match parse_timeout_choice(&line) {
                Some(TimeoutChoice::ThisRun(n)) => args.timeout = Some(n),
                Some(TimeoutChoice::SetDefault(n)) => {
                    args.timeout = Some(n);
                    prefs.analysis_timeout_secs = Some(n);
                }
                // KeepDefault or unparseable → leave precedence to fall through to default.
                Some(TimeoutChoice::KeepDefault) | None => {}
            }
        }
        prefs.onboarded = true;
        if let Err(e) = prefs.save() {
            logger.debug(&format!("Could not persist timeout preference: {}", e));
        }
        eprintln!();
    }

    let analysis_timeout = compute_analysis_timeout_with_env_and_default(
        args.timeout,
        env_timeout,
        prefs.analysis_timeout_secs,
    );
    let analysis_timeout_secs = analysis_timeout.map(|d| d.as_secs()).unwrap_or(0);

    if let Some(duration) = analysis_timeout {
        logger.warn(&format!(
            "Analysis timeout active: {}s. Use --timeout 0 to disable.",
            duration.as_secs()
        ));
    }

    let scan_started = std::time::Instant::now();

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
                    if let Err(e) = sink.flush() {
                        // An unflushed buffer means the checkpoint will claim more
                        // results than the file holds — the tail rows are lost on
                        // resume. Say so instead of promising safe progress.
                        logger.warn(&format!(
                            "Failed to flush results to disk before checkpointing: {} — \
                             the checkpoint may be missing the most recent results.",
                            e
                        ));
                    }
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
                eprintln!("Partial progress has been saved as a checkpoint. Re-run with --resume to continue.");
                eprintln!("To increase the timeout: use --timeout <seconds> or export NTHPARTY_ANALYSIS_TIMEOUT_SECS=<seconds>");
                eprintln!("To disable the timeout entirely: --timeout 0");
                bail!(AppExitCode(142));
            }
        }
    } else {
        analysis_future.await?
    };

    // Attribution table for the scan that just finished. INFO-level, so a default run's
    // stdout stays clean and only `-v` surfaces it.
    if tracing::enabled!(tracing::Level::INFO) {
        tracing::info!(
            "\n{}",
            crate::perf::format_report(
                &crate::perf::METRICS.snapshot(),
                scan_started.elapsed(),
                crate::browser_pool::permits(),
            )
        );
    }

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
        let drained = match Arc::try_unwrap(result_sink) {
            Ok(mutex) => mutex.into_inner().drain_all(),
            Err(_arc) => {
                logger.debug("ResultSink has outstanding references, reading from file path");
                ResultSink::read_results(&sink_path)
            }
        };
        match drained {
            Ok(results) => results,
            // Fail loudly instead of panicking. A genuinely empty scan returns an
            // intact (zero-row) file here, so reaching this arm means the sink
            // file was unreadable or missing — historically because a concurrent
            // run deleted the shared /tmp sink (GRC-500). Never silently emit an
            // empty report in that case.
            Err(e) => {
                logger.error(&format!(
                    "Failed to read analysis results from disk sink {}: {}",
                    sink_path.display(),
                    e
                ));
                eprintln!();
                eprintln!(
                    "Failed to read analysis results from the disk sink at {}.",
                    sink_path.display()
                );
                eprintln!("The result file was missing or unreadable, so no report was written.");
                eprintln!(
                    "This can happen when a concurrent nthpartyfinder run removes the shared \
                     /tmp sink file. Re-run the scan, and when running scans in parallel give \
                     each its own --output-dir."
                );
                bail!(AppExitCode(4));
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
            // The checkpoint says prior results exist on disk, the file is gone,
            // and the completed domains will be SKIPPED on this resume — silently
            // returning empty here writes a "complete" report that is missing
            // every previously discovered relationship. Same failure class as the
            // GRC-500 fresh-sink arm above: never silently emit an empty report.
            eprintln!(
                "The checkpoint references prior results at {} but that file no longer exists.",
                results_file
            );
            eprintln!(
                "Resuming would skip the already-completed domains while losing all of their \
                 results, producing a silently incomplete report."
            );
            eprintln!("Re-run without --resume to regenerate the full scan.");
            bail!(AppExitCode(4));
        }
    } else {
        Vec::new()
    };

    let assembled = assemble_and_filter_results(new_results, resumed_results, args.include_infra);
    if assembled.dedup_count < assembled.raw_count {
        logger.info(&format!(
            "{} raw relationships deduplicated to {} unique",
            assembled.raw_count, assembled.dedup_count
        ));
    }
    if assembled.infra_removed > 0 {
        logger.info(&format!(
            "Filtered {} common infra provider entries (use --include-infra to include)",
            assembled.infra_removed
        ));
    }
    if assembled.marketing_removed > 0 {
        logger.info(&format!(
            "Suppressed {} social/ad-network marketing-tracking entries from web traffic (use --include-infra to include)",
            assembled.marketing_removed
        ));
    }
    // Finalization rewrites the report; say so. A silently-corrected name is indistinguishable
    // from one that was right all along, and the counts are how a stale PSL snapshot or an
    // over-eager gate would first show itself.
    if assembled.finalize.non_registrable_dropped > 0 {
        logger.info(&format!(
            "Dropped {} entries whose host is not a registrable domain (truncated internal hostnames, URL fragments)",
            assembled.finalize.non_registrable_dropped
        ));
    }
    if assembled.finalize.intermediary_orgs_gated > 0 {
        logger.info(&format!(
            "Replaced {} organization names that identified a registrar, registry, privacy proxy or address rather than the domain's owner",
            assembled.finalize.intermediary_orgs_gated
        ));
    }
    if assembled.finalize.domains_reconciled > 0 {
        logger.info(&format!(
            "Reconciled {} domains that carried conflicting organization names into a single name each",
            assembled.finalize.domains_reconciled
        ));
    }
    let results = assembled.results;

    let unique_vendors = count_unique_vendors(&results);

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

    dispatch_export(&results, &args.output_format, &final_output_path)?;

    logger.log_export_success(&final_output_path);

    // Compute the two uncertain sets ONCE — consumed by the non-interactive
    // `--review-json` machine contract and/or the interactive human prompts.
    let pending_for_review = match &subprocessor_analyzer {
        Some(analyzer) => analyzer.get_pending_mappings().await,
        None => Vec::new(),
    };
    let all_unverified = {
        let vendors = discovered_vendors.lock().await;
        let mut au = unverified_orgs.lock().await.clone();
        let newly_found = collect_unverified_orgs(&vendors);
        for mapping in newly_found {
            if !au.iter().any(|u| u.domain == mapping.domain) {
                au.push(mapping);
            }
        }
        au
    };

    // Non-interactive machine contract (additive, opt-in): emit the uncertain
    // set as JSON so an automated reviewer (the Claude plugin) can validate the
    // true company↔domain relationship and apply corrections via `review apply`.
    // Does not alter the normal scan output.
    if let Some(review_path) = &args.review_json {
        let ov_path = known_vendors::resolved_overrides_path()
            .to_string_lossy()
            .into_owned();
        let export = review::build_review_export(
            args.domain.as_deref().unwrap_or(""),
            &pending_for_review,
            &all_unverified,
            &ov_path,
            &chrono::Utc::now().to_rfc3339(),
        );
        match review::export_to_json(&export) {
            Ok(json) => match std::fs::write(review_path, json) {
                Ok(()) => logger.info(&format!(
                    "Wrote {} unverified org(s) and {} pending mapping(s) to {}",
                    export.unverified_orgs.len(),
                    export.pending_mappings.len(),
                    review_path
                )),
                Err(e) => logger.warn(&format!(
                    "Failed to write --review-json {}: {}",
                    review_path, e
                )),
            },
            Err(e) => logger.warn(&format!("Failed to serialize review export: {}", e)),
        }
    }

    let is_interactive_post = input.is_terminal();
    if is_interactive_post {
        if let Some(analyzer) = &subprocessor_analyzer {
            if !pending_for_review.is_empty() {
                interactive::confirm_pending_mappings(&pending_for_review, analyzer, &logger)
                    .await?;
            }
        }
        if !all_unverified.is_empty() {
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

    if logger.has_dns_failures() && unique_vendors == 0 {
        bail!(AppExitCode(3));
    }

    Ok(())
}

// coverage(off): batch-mode I/O orchestrator — spawns concurrent domain analyses via subprocess,
// reads stdin, writes batch summaries to filesystem. Export dispatch delegated to tested
// dispatch_export(). Component logic tested in batch module.
#[cfg_attr(coverage_nightly, coverage(off))]
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
    let _ = io::Write::flush(&mut io::stdout());
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
            let _permit = batch_sem
                .acquire()
                .await
                .expect("batch concurrency semaphore is never closed");
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

        dispatch_export(
            &export_relationships,
            &args.output_format,
            &combined_path.to_string_lossy(),
        )?;

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

// coverage(off): per-domain I/O helper — calls real WHOIS (network), DNS analysis (network), and
// dispatch_export (tested). Each component tested individually in its own module.
#[cfg_attr(coverage_nightly, coverage(off))]
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
    // GRC-367 (fix 1): same choke-point wiring as the primary path — the locally constructed
    // `logger` owns the DNS-failure counter this pool increments on throttle.
    let dns_pool = Arc::new(
        dns::DnsServerPool::from_config(app_config)
            .with_failure_counter(logger.dns_failure_counter_arc()),
    );
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

        dispatch_export(&results, output_format, &output_path.to_string_lossy())?;
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

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn unwrap_config_exit(outcome: ConfigOutcome) -> (String, i32) {
        match outcome {
            ConfigOutcome::Exit { message, code } => (message, code),
            other => panic!("Expected Exit, got {:?}", other),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn unwrap_config_created(outcome: ConfigOutcome) -> PathBuf {
        match outcome {
            ConfigOutcome::CreatedNew(p) => p,
            other => panic!("Expected CreatedNew, got {:?}", other),
        }
    }

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
    fn test_filter_infra_keeps_explicitly_disclosed_subprocessors() {
        // A company that names AWS/Cloudflare/Microsoft on its OWN subprocessor page
        // is disclosing an intentional relationship — these must NOT be filtered as
        // common infra. Incidentally-discovered infra (DNS/web traffic) still is.
        let results = vec![
            make_relationship(
                "cloudflare.com",
                "Cloudflare",
                "klaviyo.com",
                RecordType::HttpSubprocessor,
                "Listed on klaviyo.com/legal/subprocessors",
            ),
            make_relationship(
                "amazonaws.com",
                "AWS",
                "klaviyo.com",
                RecordType::HttpSubprocessor,
                "Listed on klaviyo.com/legal/subprocessors",
            ),
            // Same infra provider but only seen incidentally via DNS → still filtered.
            make_relationship(
                "google.com",
                "Google",
                "klaviyo.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
        ];
        let (filtered, removed) = filter_infra_providers(results, false);
        assert_eq!(removed, 1, "only the DNS-sourced infra entry is removed");
        let domains: Vec<&str> = filtered
            .iter()
            .map(|r| r.nth_party_domain.as_str())
            .collect();
        assert!(domains.contains(&"cloudflare.com"));
        assert!(domains.contains(&"amazonaws.com"));
        assert!(!domains.contains(&"google.com"));
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

    // ── compute_analysis_timeout_with_env_and_default (#4 precedence) ──
    #[test]
    fn test_timeout_default_precedence_cli_wins() {
        let t = compute_analysis_timeout_with_env_and_default(
            Some(120),
            Some("300".to_string()),
            Some(900),
        );
        assert_eq!(t, Some(std::time::Duration::from_secs(120)));
    }

    #[test]
    fn test_timeout_default_precedence_env_over_prefs() {
        let t =
            compute_analysis_timeout_with_env_and_default(None, Some("300".to_string()), Some(900));
        assert_eq!(t, Some(std::time::Duration::from_secs(300)));
    }

    #[test]
    fn test_timeout_default_precedence_prefs_over_builtin() {
        let t = compute_analysis_timeout_with_env_and_default(None, None, Some(900));
        assert_eq!(t, Some(std::time::Duration::from_secs(900)));
    }

    #[test]
    fn test_timeout_default_precedence_falls_back_to_600() {
        let t = compute_analysis_timeout_with_env_and_default(None, None, None);
        assert_eq!(t, Some(std::time::Duration::from_secs(600)));
    }

    #[test]
    fn test_timeout_default_prefs_zero_disables() {
        let t = compute_analysis_timeout_with_env_and_default(None, None, Some(0));
        assert_eq!(t, None);
    }

    // ── effective_parallel_jobs (`-j 0` = use configured per-depth concurrency) ────────
    #[test]
    fn test_effective_parallel_jobs_zero_uses_configured() {
        assert_eq!(effective_parallel_jobs(0, 50), 50);
        assert_eq!(effective_parallel_jobs(0, 8), 8);
    }

    #[test]
    fn test_effective_parallel_jobs_explicit_value_narrows_only() {
        assert_eq!(effective_parallel_jobs(4, 50), 4);
        assert_eq!(effective_parallel_jobs(100, 8), 8);
    }

    /// A semaphore built from this value must always have at least one permit, or every
    /// acquirer deadlocks. A zero config must still floor to 1.
    #[test]
    fn test_effective_parallel_jobs_floors_at_one() {
        assert_eq!(effective_parallel_jobs(0, 0), 1);
        assert_eq!(effective_parallel_jobs(1, 0), 1);
    }

    // ── parse_timeout_choice (#4 first-run prompt) ────────────────────
    #[test]
    fn test_parse_timeout_choice_empty_keeps_default() {
        assert_eq!(parse_timeout_choice(""), Some(TimeoutChoice::KeepDefault));
        assert_eq!(
            parse_timeout_choice("   \n"),
            Some(TimeoutChoice::KeepDefault)
        );
    }

    #[test]
    fn test_parse_timeout_choice_number_is_this_run() {
        assert_eq!(
            parse_timeout_choice("1800"),
            Some(TimeoutChoice::ThisRun(1800))
        );
        assert_eq!(parse_timeout_choice(" 0 "), Some(TimeoutChoice::ThisRun(0)));
    }

    #[test]
    fn test_parse_timeout_choice_set_default_variants() {
        assert_eq!(
            parse_timeout_choice("1800 d"),
            Some(TimeoutChoice::SetDefault(1800))
        );
        assert_eq!(
            parse_timeout_choice("1800 default"),
            Some(TimeoutChoice::SetDefault(1800))
        );
        assert_eq!(
            parse_timeout_choice("1800 save"),
            Some(TimeoutChoice::SetDefault(1800))
        );
        assert_eq!(
            parse_timeout_choice("1800!"),
            Some(TimeoutChoice::SetDefault(1800))
        );
    }

    #[test]
    fn test_parse_timeout_choice_invalid_is_none() {
        assert_eq!(parse_timeout_choice("abc"), None);
        assert_eq!(parse_timeout_choice("1800 bogus"), None);
        assert_eq!(parse_timeout_choice("twelve!"), None);
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

    // ── collect_unverified_orgs_with_lookup ─────────────────────────

    #[test]
    fn test_collect_unverified_orgs_skips_known_vendors() {
        let mut vendors = HashMap::new();
        vendors.insert("acme.com".to_string(), "acme".to_string());
        vendors.insert("known.com".to_string(), "known".to_string());

        let result = collect_unverified_orgs_with_lookup(&vendors, |d| d == "known.com");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].domain, "acme.com");
    }

    #[test]
    fn test_collect_unverified_orgs_all_known() {
        let mut vendors = HashMap::new();
        vendors.insert("a.com".to_string(), "a".to_string());
        vendors.insert("b.com".to_string(), "b".to_string());

        let result = collect_unverified_orgs_with_lookup(&vendors, |_| true);
        assert!(result.is_empty());
    }

    #[test]
    fn test_collect_unverified_orgs_none_known() {
        let mut vendors = HashMap::new();
        vendors.insert("acme.com".to_string(), "acme".to_string());

        let result = collect_unverified_orgs_with_lookup(&vendors, |_| false);
        assert_eq!(result.len(), 1);
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

    // ── StdioInput ───────────────────────────────────────────────────

    #[test]
    fn test_stdio_input_is_not_terminal_in_tests() {
        let input = StdioInput;
        assert!(!input.is_terminal());
    }

    #[test]
    fn test_stdio_input_implements_input_source() {
        fn assert_input_source<T: InputSource>(_: &T) {}
        let input = StdioInput;
        assert_input_source(&input);
    }

    // ── process_config_result ────────────────────────────────────────

    #[test]
    fn test_process_config_result_ok() {
        let config: AppConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        let result = process_config_result(Ok(config), None);
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn is_ready(o: &ConfigOutcome) -> bool {
            matches!(o, ConfigOutcome::Ready(_))
        }
        assert!(is_ready(&result));
    }

    #[test]
    fn test_process_config_result_file_not_found_created() {
        let path = PathBuf::from("/tmp/created.toml");
        let result = process_config_result(
            Err(ConfigError::FileNotFound(PathBuf::from("/missing"))),
            Some(Ok(Some(path.clone()))),
        );
        assert_eq!(unwrap_config_created(result), path);
    }

    #[test]
    fn test_process_config_result_file_not_found_declined() {
        let result = process_config_result(
            Err(ConfigError::FileNotFound(PathBuf::from("/etc/config.toml"))),
            Some(Ok(None)),
        );
        assert!(matches!(result, ConfigOutcome::Ready(_)));
    }

    #[test]
    fn test_process_config_result_file_not_found_prompt_error() {
        let result = process_config_result(
            Err(ConfigError::FileNotFound(PathBuf::from("/missing"))),
            Some(Err("permission denied".to_string())),
        );
        assert!(matches!(result, ConfigOutcome::Ready(_)));
    }

    #[test]
    fn test_process_config_result_file_not_found_no_prompt() {
        let result =
            process_config_result(Err(ConfigError::FileNotFound(PathBuf::from("/conf"))), None);
        assert!(matches!(result, ConfigOutcome::Ready(_)));
    }

    #[test]
    fn test_zero_config_fallback_uses_valid_defaults() {
        let result = process_config_result(
            Err(ConfigError::FileNotFound(PathBuf::from(
                "./config/nthpartyfinder.toml",
            ))),
            None,
        );
        match result {
            ConfigOutcome::Ready(cfg) => {
                assert!(cfg.validate().is_ok(), "Fallback defaults must validate");
                assert!(!cfg.http.user_agent.is_empty());
                assert!(!cfg.dns.doh_servers.is_empty() || !cfg.dns.dns_servers.is_empty());
            }
            other => panic!("Expected Ready with defaults, got {:?}", other),
        }
    }

    #[test]
    fn test_process_config_result_other_error() {
        let result = process_config_result(
            Err(ConfigError::EmptyRequired {
                field: "http.user_agent".to_string(),
            }),
            None,
        );
        let (message, code) = unwrap_config_exit(result);
        assert_eq!(code, 1);
        assert!(message.contains("Configuration error"));
    }

    // ── format_dep_check_warnings ────────────────────────────────────

    #[test]
    fn test_format_dep_check_warnings_all_available() {
        let results = vec![
            dep_check::DepCheckResult {
                name: "curl",
                available: true,
                required: true,
                message: None,
            },
            dep_check::DepCheckResult {
                name: "subfinder",
                available: true,
                required: false,
                message: None,
            },
        ];
        assert!(format_dep_check_warnings(&results).is_empty());
    }

    #[test]
    fn test_format_dep_check_warnings_some_unavailable() {
        let results = vec![
            dep_check::DepCheckResult {
                name: "curl",
                available: true,
                required: true,
                message: None,
            },
            dep_check::DepCheckResult {
                name: "subfinder",
                available: false,
                required: false,
                message: Some("subfinder not found in PATH".to_string()),
            },
            dep_check::DepCheckResult {
                name: "go",
                available: false,
                required: false,
                message: None,
            },
        ];
        let warnings = format_dep_check_warnings(&results);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0], "subfinder not found in PATH");
    }

    #[test]
    fn test_format_dep_check_warnings_empty() {
        let results: Vec<dep_check::DepCheckResult> = vec![];
        assert!(format_dep_check_warnings(&results).is_empty());
    }

    // ── build_batch_domain_args ──────────────────────────────────────

    #[test]
    fn test_build_batch_domain_args_basic() {
        let args = build_batch_domain_args(
            "example.com",
            "csv",
            None,
            false,
            true, // batch_combined = true → no --output-dir
            Path::new("/tmp/output"),
            None, // no dns rate limit
        );
        assert_eq!(
            args,
            vec!["nthpartyfinder", "-d", "example.com", "-f", "csv"]
        );
    }

    #[test]
    fn test_build_batch_domain_args_with_depth_and_dns_only() {
        let args = build_batch_domain_args(
            "test.org",
            "json",
            Some(3),
            true,
            true,
            Path::new("/out"),
            None,
        );
        assert_eq!(
            args,
            vec![
                "nthpartyfinder",
                "-d",
                "test.org",
                "-f",
                "json",
                "-r",
                "3",
                "--dns-only"
            ]
        );
    }

    #[test]
    fn test_build_batch_domain_args_not_combined_adds_output_dir() {
        let args = build_batch_domain_args(
            "sub.example.com",
            "html",
            None,
            false,
            false, // not combined → adds --output-dir
            Path::new("/reports"),
            None,
        );
        assert!(args.contains(&"--output-dir".to_string()));
        let idx = args.iter().position(|a| a == "--output-dir").unwrap();
        assert!(args[idx + 1].contains("sub_example_com"));
    }

    // GRC-367 (fix 4): an operator-supplied --dns-rate-limit MUST be forwarded to each batch
    // child; previously it was dropped and the child reverted to the config default.
    #[test]
    fn test_build_batch_domain_args_forwards_dns_rate_limit() {
        let args = build_batch_domain_args(
            "example.com",
            "csv",
            None,
            false,
            true,
            Path::new("/tmp/output"),
            Some(7), // operator pinned DNS to 7 qps
        );
        assert!(
            args.contains(&"--dns-rate-limit".to_string()),
            "the --dns-rate-limit flag must be forwarded to the batch child"
        );
        let idx = args
            .iter()
            .position(|a| a == "--dns-rate-limit")
            .expect("flag present");
        assert_eq!(
            args[idx + 1],
            "7",
            "the forwarded value must match the operator-supplied qps"
        );
    }

    // The flag must be ABSENT when no rate limit was supplied (so the child uses its config
    // default rather than a spurious 0/override).
    #[test]
    fn test_build_batch_domain_args_omits_dns_rate_limit_when_none() {
        let args = build_batch_domain_args(
            "example.com",
            "csv",
            None,
            false,
            true,
            Path::new("/tmp/output"),
            None,
        );
        assert!(
            !args.contains(&"--dns-rate-limit".to_string()),
            "no --dns-rate-limit flag should be emitted when the operator did not set one"
        );
    }

    // ── resolve_final_output_path ────────────────────────────────────

    #[test]
    fn test_resolve_final_output_path_empty_uses_default() {
        let result = resolve_final_output_path("/tmp/default.csv", "report.csv", "").unwrap();
        assert_eq!(result, "/tmp/default.csv");
    }

    #[test]
    fn test_resolve_final_output_path_custom_dir() {
        let result =
            resolve_final_output_path("/tmp/default.csv", "report.csv", "/home/user/reports")
                .unwrap();
        assert_eq!(result, "/home/user/reports/report.csv");
    }

    #[test]
    fn test_resolve_final_output_path_whitespace_only_uses_default() {
        let result = resolve_final_output_path("/tmp/out.json", "out.json", "").unwrap();
        assert_eq!(result, "/tmp/out.json");
    }

    #[test]
    fn test_resolve_final_output_path_rejects_traversal() {
        let result = resolve_final_output_path("/tmp/out.csv", "report.csv", "../../../etc");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Path traversal"));
    }

    #[test]
    fn test_resolve_final_output_path_rejects_embedded_traversal() {
        let result =
            resolve_final_output_path("/tmp/out.csv", "report.csv", "/home/user/../../etc");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_final_output_path_allows_absolute() {
        let result =
            resolve_final_output_path("/tmp/out.csv", "report.csv", "/var/reports").unwrap();
        assert_eq!(result, "/var/reports/report.csv");
    }

    // ── assemble_and_filter_results ──────────────────────────────────

    #[test]
    fn test_assemble_and_filter_results_new_only() {
        let new = vec![make_relationship(
            "stripe.com",
            "Stripe",
            "e.com",
            RecordType::DnsTxtSpf,
            "ev",
        )];
        let assembled = assemble_and_filter_results(new, vec![], false);
        assert_eq!(assembled.results.len(), 1);
        assert_eq!(assembled.raw_count, 1);
        assert_eq!(assembled.dedup_count, 1);
        assert_eq!(assembled.infra_removed, 0);
    }

    #[test]
    fn test_assemble_and_filter_results_with_resumed_and_dedup() {
        let resumed = vec![make_relationship(
            "stripe.com",
            "Stripe",
            "e.com",
            RecordType::DnsTxtSpf,
            "ev-old",
        )];
        let new = vec![
            make_relationship(
                "stripe.com",
                "Stripe",
                "e.com",
                RecordType::DnsTxtSpf,
                "ev-new",
            ),
            make_relationship("pendo.io", "Pendo", "e.com", RecordType::DnsTxtSpf, "ev2"),
        ];
        let assembled = assemble_and_filter_results(new, resumed, false);
        assert_eq!(assembled.raw_count, 3);
        assert_eq!(assembled.dedup_count, 2);
        assert_eq!(assembled.results.len(), 2);
    }

    #[test]
    fn test_assemble_and_filter_results_filters_infra() {
        let new = vec![
            make_relationship("amazonaws.com", "AWS", "e.com", RecordType::DnsTxtSpf, "ev"),
            make_relationship("stripe.com", "Stripe", "e.com", RecordType::DnsTxtSpf, "ev"),
        ];
        let assembled = assemble_and_filter_results(new, vec![], false);
        assert_eq!(assembled.results.len(), 1);
        assert_eq!(assembled.infra_removed, 1);
        assert_eq!(assembled.results[0].nth_party_domain, "stripe.com");
    }

    #[test]
    fn test_assemble_and_filter_results_include_infra() {
        let new = vec![
            make_relationship("amazonaws.com", "AWS", "e.com", RecordType::DnsTxtSpf, "ev"),
            make_relationship("stripe.com", "Stripe", "e.com", RecordType::DnsTxtSpf, "ev"),
        ];
        let assembled = assemble_and_filter_results(new, vec![], true);
        assert_eq!(assembled.results.len(), 2);
        assert_eq!(assembled.infra_removed, 0);
    }

    // ── filter_marketing_tracking (GRC-501) ─────────────────────────

    #[test]
    fn test_filter_marketing_tracking_suppresses_web_traffic_social() {
        // facebook.com discovered via web traffic is a tracking pixel, not a
        // subprocessor — it must be suppressed.
        let results = vec![
            make_relationship(
                "facebook.com",
                "Meta",
                "shop.com",
                RecordType::WebTrafficNetwork,
                "https://connect.facebook.net/en_US/fbevents.js",
            ),
            make_relationship(
                "stripe.com",
                "Stripe",
                "shop.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
        ];
        let (filtered, removed) = filter_marketing_tracking(results, false);
        assert_eq!(removed, 1);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].nth_party_domain, "stripe.com");
    }

    #[test]
    fn test_filter_marketing_tracking_keeps_disclosed_subprocessor() {
        // facebook.com listed on a real subprocessor page is a legitimately
        // disclosed relationship and must be retained.
        let results = vec![make_relationship(
            "facebook.com",
            "Meta",
            "shop.com",
            RecordType::HttpSubprocessor,
            "listed on /subprocessors",
        )];
        let (filtered, removed) = filter_marketing_tracking(results, false);
        assert_eq!(removed, 0);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_filter_marketing_tracking_respects_include_infra() {
        let results = vec![make_relationship(
            "doubleclick.net",
            "Google",
            "shop.com",
            RecordType::WebTrafficSource,
            "ad pixel",
        )];
        let (filtered, removed) = filter_marketing_tracking(results, true);
        assert_eq!(removed, 0);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_assemble_and_filter_results_suppresses_marketing() {
        let new = vec![
            make_relationship(
                "licdn.com",
                "LinkedIn",
                "shop.com",
                RecordType::WebTrafficNetwork,
                "insight tag",
            ),
            make_relationship(
                "stripe.com",
                "Stripe",
                "shop.com",
                RecordType::DnsTxtSpf,
                "ev",
            ),
        ];
        let assembled = assemble_and_filter_results(new, vec![], false);
        assert_eq!(assembled.marketing_removed, 1);
        assert_eq!(assembled.results.len(), 1);
        assert_eq!(assembled.results[0].nth_party_domain, "stripe.com");
    }

    // ── dispatch_export ──────────────────────────────────────────────

    #[test]
    fn test_dispatch_export_csv() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.csv");
        let results = vec![make_relationship(
            "s.com",
            "S",
            "e.com",
            RecordType::DnsTxtSpf,
            "ev",
        )];
        dispatch_export(&results, "csv", &path.to_string_lossy()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_dispatch_export_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");
        let results = vec![make_relationship(
            "s.com",
            "S",
            "e.com",
            RecordType::DnsTxtSpf,
            "ev",
        )];
        dispatch_export(&results, "json", &path.to_string_lossy()).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("s.com"));
    }

    #[test]
    fn test_dispatch_export_markdown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.md");
        dispatch_export(&[], "markdown", &path.to_string_lossy()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_dispatch_export_html() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.html");
        dispatch_export(&[], "html", &path.to_string_lossy()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_dispatch_export_unknown_falls_to_csv() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.xml");
        dispatch_export(&[], "xml", &path.to_string_lossy()).unwrap();
        assert!(path.exists());
    }

    // ── extract_checkpoint_state ─────────────────────────────────────

    #[test]
    fn test_extract_checkpoint_state_fresh() {
        let cp = Checkpoint::new("example.com".to_string(), None, Some(2), "hash".to_string());
        let state = extract_checkpoint_state(&cp);
        assert!(state.is_none());
    }

    #[test]
    fn test_extract_checkpoint_state_with_progress() {
        let mut cp = Checkpoint::new("test.com".to_string(), None, Some(1), "h".to_string());
        cp.completed_domains.insert("a.com".to_string());
        cp.completed_domains.insert("b.com".to_string());
        cp.discovered_vendors
            .insert("a.com".to_string(), "Acme".to_string());
        cp.results_count = 5;
        cp.results_file = "/tmp/sink.zst".to_string();

        let state = extract_checkpoint_state(&cp).unwrap();
        assert_eq!(state.completed_domains.len(), 2);
        assert_eq!(state.discovered_vendors.get("a.com").unwrap(), "Acme");
        assert_eq!(state.results_count, 5);
        assert_eq!(state.results_file, Some("/tmp/sink.zst".to_string()));
        assert_eq!(state.pending_count, 0);
    }

    #[test]
    fn test_extract_checkpoint_state_empty_results_file() {
        let mut cp = Checkpoint::new("x.com".to_string(), None, None, "h".to_string());
        cp.completed_domains.insert("y.com".to_string());
        // results_file is empty string by default
        let state = extract_checkpoint_state(&cp).unwrap();
        assert_eq!(state.results_file, None);
    }

    // ── count_unique_vendors ─────────────────────────────────────────

    #[test]
    fn test_count_unique_vendors_empty() {
        assert_eq!(count_unique_vendors(&[]), 0);
    }

    #[test]
    fn test_count_unique_vendors_with_duplicates() {
        let results = vec![
            make_relationship("a.com", "Acme", "e.com", RecordType::DnsTxtSpf, "ev1"),
            make_relationship("b.com", "Acme", "e.com", RecordType::DnsTxtSpf, "ev2"),
            make_relationship("c.com", "Beta Corp", "e.com", RecordType::DnsTxtSpf, "ev3"),
        ];
        assert_eq!(count_unique_vendors(&results), 2);
    }

    #[test]
    fn test_count_unique_vendors_all_unique() {
        let results = vec![
            make_relationship("a.com", "Alpha", "e.com", RecordType::DnsTxtSpf, "ev1"),
            make_relationship("b.com", "Beta", "e.com", RecordType::DnsTxtSpf, "ev2"),
            make_relationship("c.com", "Gamma", "e.com", RecordType::DnsTxtSpf, "ev3"),
        ];
        assert_eq!(count_unique_vendors(&results), 3);
    }

    // ── DNS failure exit code ───────────────────────────────────────

    #[test]
    fn test_app_exit_code_3_display() {
        let code = AppExitCode(3);
        assert_eq!(format!("{}", code), "exit code 3");
    }

    // ── Timeout exit code ────────────────────────────────────────────

    #[test]
    fn test_app_exit_code_142_timeout_display() {
        let code = AppExitCode(142);
        assert_eq!(format!("{}", code), "exit code 142");
    }
}
