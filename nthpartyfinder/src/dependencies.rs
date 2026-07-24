//! Unified runtime dependency UX.
//!
//! nthpartyfinder has three optional external dependencies — a browser (Chrome/Chromium/Edge),
//! subfinder, and whois — each unlocking part of its analysis. This module gives them ONE
//! runtime experience, identical no matter how nthpartyfinder was installed (Homebrew, WinGet,
//! a direct macOS/Windows package, cargo, a raw tarball): when a run needs optional tools it
//! lacks, the user sees a SINGLE prompt that lists every missing dependency, states in plain
//! language what each unlocks and how the scan degrades without it, and installs all of them
//! from one keystroke — or lets the user pick a subset. Declining is remembered per
//! dependency: remind next run, or never again (persisted to [`crate::prefs`]).
//!
//! Hang-safety (inherited from the browser-install work): the decision of what to do is a
//! pure function ([`decide_dep_action`]), unit-tested across every combination. A
//! non-interactive session with missing deps and no install flag warns and continues with
//! reduced coverage, never reading stdin. Unattended installs use `sudo -n` + a subprocess
//! timeout (see [`crate::browser_install`]) so nothing blocks.
//!
//! Install mechanisms differ per dependency and that is fine: the browser and whois install
//! via per-OS package managers; subfinder via its own universal direct-binary download (no
//! package manager required) — the most install-method-agnostic path.

use crate::app::InputSource;
#[cfg(not(test))]
use crate::browser_install;
use crate::browser_install::{InstallCommand, InstallPlan, ToolAvailability};
use crate::logger::AnalysisLogger;
use crate::prefs::Prefs;

/// An optional external dependency nthpartyfinder can detect and install at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dependency {
    Browser,
    Subfinder,
    Whois,
}

impl Dependency {
    /// Stable id used in `prefs.never_remind` and on the CLI. NEVER change these strings —
    /// a change would silently forget a user's "never remind" choices.
    pub fn id(self) -> &'static str {
        match self {
            Dependency::Browser => "browser",
            Dependency::Subfinder => "subfinder",
            Dependency::Whois => "whois",
        }
    }

    /// Name shown in the prompt.
    pub fn display_name(self) -> &'static str {
        match self {
            Dependency::Browser => "A browser (Google Chrome / Chromium)",
            Dependency::Subfinder => "subfinder",
            Dependency::Whois => "whois",
        }
    }

    /// Plain-language statement of what this dependency unlocks and, explicitly, which
    /// capabilities are DISABLED or DEGRADED without it — shown next to it in the prompt.
    pub fn capability_impact(self) -> &'static str {
        match self {
            Dependency::Browser => {
                "Web-content, web-traffic, and subprocessor-render discovery (whichever you have \
                 enabled) run DEGRADED without it — HTTP / static-HTML only, with no browser \
                 rendering or runtime network-request capture (the richest web-traffic signal, and \
                 SPA-rendered content, are lost)."
            }
            Dependency::Subfinder => {
                "Subdomain discovery — a major source of vendor relationships — is DISABLED \
                 without it."
            }
            Dependency::Whois => {
                "Adds a secondary WHOIS lookup that can improve organization-name accuracy on some \
                 TLDs. Without it, nthpartyfinder uses only its built-in WHOIS, so a few names may \
                 be DEGRADED."
            }
        }
    }
}

/// Which optional dependencies this run cares about, derived from the enabled phases. The
/// browser matters when any browser-using phase is on; subfinder when subdomain discovery is
/// on; whois on essentially every run (organization-name lookups are near-universal).
pub fn relevant_dependencies(
    browser_phase_enabled: bool,
    subdomain_enabled: bool,
) -> Vec<Dependency> {
    let mut deps = Vec::new();
    if browser_phase_enabled {
        deps.push(Dependency::Browser);
    }
    if subdomain_enabled {
        deps.push(Dependency::Subfinder);
    }
    deps.push(Dependency::Whois);
    deps
}

/// From the relevant dependencies, the ones to actually put in front of the user: those that
/// are MISSING and NOT on the user's never-remind list. Pure — takes the present set and the
/// never-remind ids as data so it is exhaustively testable.
pub fn dependencies_to_prompt(
    relevant: &[Dependency],
    present: &[Dependency],
    never_remind: &[String],
) -> Vec<Dependency> {
    relevant
        .iter()
        .copied()
        .filter(|dep| !present.contains(dep))
        .filter(|dep| !never_remind.iter().any(|id| id == dep.id()))
        .collect()
}

/// The never-hang decision for the prompt set (the deps not already auto-installed via a
/// flag). Mirrors the browser-install decision, generalized: nothing to prompt ⇒ do nothing;
/// otherwise an interactive terminal is prompted and a non-interactive session is skipped
/// WITHOUT touching stdin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepAction {
    NothingToPrompt,
    SkipNonInteractive,
    Prompt,
}

pub fn decide_dep_action(any_to_prompt: bool, interactive: bool) -> DepAction {
    if !any_to_prompt {
        DepAction::NothingToPrompt
    } else if interactive {
        DepAction::Prompt
    } else {
        DepAction::SkipNonInteractive
    }
}

/// Which dependencies a `--install-deps` / `--install-browser` flag auto-installs (no prompt),
/// out of the missing set. `--install-deps` covers ALL missing; `--install-browser` covers
/// only the browser (back-compat). Deps not covered here fall through to the interactive
/// prompt (or a non-interactive skip).
pub fn flag_selected_dependencies(
    to_prompt: &[Dependency],
    install_all: bool,
    install_browser: bool,
) -> Vec<Dependency> {
    if install_all {
        to_prompt.to_vec()
    } else if install_browser {
        to_prompt
            .iter()
            .copied()
            .filter(|dep| *dep == Dependency::Browser)
            .collect()
    } else {
        Vec::new()
    }
}

/// The user's answer to the consolidated prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptResponse {
    /// Install every listed dependency (the one-keystroke "yes to all").
    All,
    /// Install none.
    None,
    /// Install the listed dependencies at these 1-based positions.
    Subset(Vec<usize>),
}

/// Parse the typed answer against a prompt listing `count` dependencies. Installing runs
/// package managers (often via sudo) and downloads/executes a binary, so — matching the
/// sibling reminder prompt — the conservative default wins: an EMPTY line (bare Enter) is a
/// DECLINE, not an install. An explicit `y`/`yes`/`a`/`all` installs everything (one keystroke);
/// `n`/`no`/`s`/`skip` declines; a list of numbers (comma- or space-separated) ⇒ that subset,
/// with out-of-range and unparseable entries dropped. Anything that yields nothing valid is a
/// decline (None) — never install something the user didn't clearly ask for.
pub fn parse_prompt_response(input: &str, count: usize) -> PromptResponse {
    let trimmed = input.trim().to_lowercase();
    if trimmed == "y" || trimmed == "yes" || trimmed == "a" || trimmed == "all" {
        return PromptResponse::All;
    }
    if trimmed.is_empty()
        || trimmed == "n"
        || trimmed == "no"
        || trimmed == "s"
        || trimmed == "skip"
    {
        return PromptResponse::None;
    }
    let mut indices: Vec<usize> = trimmed
        .split([',', ' '])
        .filter_map(|part| part.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1 && n <= count)
        .collect();
    indices.sort_unstable();
    indices.dedup();
    if indices.is_empty() {
        PromptResponse::None
    } else {
        PromptResponse::Subset(indices)
    }
}

/// Interpret the OUTCOME of reading the prompt line. EOF (`Ok(0)`, e.g. Ctrl-D or a closed
/// pipe) and a read error both mean install NOTHING. A real line defers to
/// [`parse_prompt_response`] (whose empty-line default is also decline).
pub fn response_from_read(read: std::io::Result<usize>, buf: &str, count: usize) -> PromptResponse {
    match read {
        Ok(0) | Err(_) => PromptResponse::None,
        Ok(_) => parse_prompt_response(buf, count),
    }
}

/// The dependencies a response selects out of the prompted list (1-based indices).
pub fn selected_dependencies(
    response: &PromptResponse,
    prompted: &[Dependency],
) -> Vec<Dependency> {
    match response {
        PromptResponse::All => prompted.to_vec(),
        PromptResponse::None => Vec::new(),
        PromptResponse::Subset(indices) => indices
            .iter()
            .filter_map(|&i| i.checked_sub(1).and_then(|idx| prompted.get(idx).copied()))
            .collect(),
    }
}

/// Which declined dependencies to silence forever, from ONE consolidated reminder answer. Keeps
/// the "as simple as possible" UX: a single question over all declined deps, one keystroke to
/// keep being reminded about all, one to silence all, or numbers to silence specific ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReminderSelection {
    /// Keep reminding about every declined dependency (silence none).
    RemindAll,
    /// Never remind about any of them again (silence all).
    NeverAll,
    /// Silence only these 1-based positions in the declined list.
    NeverSubset(Vec<usize>),
}

/// Parse the consolidated reminder answer over `count` declined dependencies. Empty / `r` /
/// `remind` ⇒ keep reminding about all (the safe default — a permanent "never" is only set on an
/// explicit choice); `n` / `never` ⇒ silence all; a list of numbers ⇒ silence just those
/// (out-of-range/garbage dropped; nothing valid ⇒ remind all).
pub fn parse_reminder_selection(input: &str, count: usize) -> ReminderSelection {
    let trimmed = input.trim().to_lowercase();
    if trimmed.is_empty() || trimmed == "r" || trimmed == "remind" {
        return ReminderSelection::RemindAll;
    }
    if trimmed == "n" || trimmed == "never" {
        return ReminderSelection::NeverAll;
    }
    let mut indices: Vec<usize> = trimmed
        .split([',', ' '])
        .filter_map(|part| part.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1 && n <= count)
        .collect();
    indices.sort_unstable();
    indices.dedup();
    if indices.is_empty() {
        ReminderSelection::RemindAll
    } else {
        ReminderSelection::NeverSubset(indices)
    }
}

/// EOF / read error ⇒ keep reminding about all (safe default). A real line defers to the parser.
pub fn reminder_selection_from_read(
    read: std::io::Result<usize>,
    buf: &str,
    count: usize,
) -> ReminderSelection {
    match read {
        Ok(0) | Err(_) => ReminderSelection::RemindAll,
        Ok(_) => parse_reminder_selection(buf, count),
    }
}

/// The declined dependencies a reminder selection silences (marks never-remind).
pub fn silenced_dependencies(
    selection: &ReminderSelection,
    declined: &[Dependency],
) -> Vec<Dependency> {
    match selection {
        ReminderSelection::RemindAll => Vec::new(),
        ReminderSelection::NeverAll => declined.to_vec(),
        ReminderSelection::NeverSubset(indices) => indices
            .iter()
            .filter_map(|&i| i.checked_sub(1).and_then(|idx| declined.get(idx).copied()))
            .collect(),
    }
}

/// Per-OS install plan for `whois` (the browser has its own in [`browser_install`], and
/// subfinder uses a direct download). macOS via Homebrew; Linux via the system package
/// manager; Windows has no standard `whois` package (it ships with WSL / Sysinternals), so it
/// is manual-only there.
pub fn whois_install_plan(os: &str, tools: &ToolAvailability) -> InstallPlan {
    let sudo = |args: &[&str]| InstallCommand {
        program: "sudo".to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
    };
    match os {
        "macos" => {
            let mut commands = Vec::new();
            if tools.brew {
                commands.push(InstallCommand {
                    program: "brew".to_string(),
                    args: vec!["install".to_string(), "whois".to_string()],
                });
            }
            InstallPlan {
                target_label: "whois",
                commands,
                manual_url: "https://formulae.brew.sh/formula/whois",
            }
        }
        "windows" => InstallPlan {
            target_label: "whois",
            commands: Vec::new(),
            manual_url: "https://learn.microsoft.com/sysinternals/downloads/whois",
        },
        _ => {
            let mut commands = Vec::new();
            if tools.apt_get {
                commands.push(sudo(&["apt-get", "install", "-y", "whois"]));
            }
            if tools.dnf {
                commands.push(sudo(&["dnf", "install", "-y", "whois"]));
            }
            if tools.pacman {
                commands.push(sudo(&["pacman", "-S", "--noconfirm", "whois"]));
            }
            if tools.zypper {
                commands.push(sudo(&["zypper", "--non-interactive", "install", "whois"]));
            }
            InstallPlan {
                target_label: "whois",
                commands,
                manual_url: "https://github.com/rfc1036/whois",
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestration (coverage(off) + cfg(not(test))): reads stdin, spawns installers,
// persists prefs. Every decision it makes is a pure function tested above.
// ─────────────────────────────────────────────────────────────────────────────

/// Ensure the optional dependencies this run needs are present — with one consolidated,
/// install-method-agnostic prompt. Never hangs a non-interactive session. Always-compiled thin
/// wrapper: the real IO orchestration is `cfg(not(test))`; the test build is a no-op (the pure
/// decision logic it drives is unit-tested directly), so `run_inner` compiles under test.
///
/// `prefs` is the run's single owning [`Prefs`] (loaded once by the caller): this mutates and
/// persists it in place, so the caller's later save cannot clobber a "never remind" choice
/// recorded here. `subfinder_path` is the effective configured subfinder path, used so detection
/// agrees with how the scan actually resolves subfinder.
#[allow(clippy::too_many_arguments)]
pub async fn ensure_dependencies(
    input: &dyn InputSource,
    logger: &AnalysisLogger,
    prefs: &mut Prefs,
    browser_phase_enabled: bool,
    subdomain_enabled: bool,
    subfinder_path: Option<&str>,
    install_all_flag: bool,
    install_browser_flag: bool,
) {
    #[cfg(not(test))]
    ensure_dependencies_impl(
        input,
        logger,
        prefs,
        browser_phase_enabled,
        subdomain_enabled,
        subfinder_path,
        install_all_flag,
        install_browser_flag,
    )
    .await;
    #[cfg(test)]
    {
        // No-op in tests — real IO/install/prefs cannot run here.
        let _ = (
            input.is_terminal(),
            logger,
            &prefs.never_remind,
            browser_phase_enabled,
            subdomain_enabled,
            subfinder_path,
            install_all_flag,
            install_browser_flag,
        );
    }
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::too_many_arguments)]
async fn ensure_dependencies_impl(
    input: &dyn InputSource,
    logger: &AnalysisLogger,
    prefs: &mut Prefs,
    browser_phase_enabled: bool,
    subdomain_enabled: bool,
    subfinder_path: Option<&str>,
    install_all_flag: bool,
    install_browser_flag: bool,
) {
    let relevant = relevant_dependencies(browser_phase_enabled, subdomain_enabled);
    let missing: Vec<Dependency> = relevant
        .iter()
        .copied()
        .filter(|dep| !is_present(*dep, subfinder_path))
        .collect();
    if missing.is_empty() {
        return;
    }

    let interactive = input.is_terminal();
    let mut prefs_changed = false;

    // An explicit --install-deps / --install-browser is a deliberate action that OVERRIDES a
    // stored "never remind" preference: it installs from the whole MISSING set, and clears the
    // never-remind flag for anything it installs (that dependency is now present).
    let flag_selected =
        flag_selected_dependencies(&missing, install_all_flag, install_browser_flag);
    for dep in &flag_selected {
        if install_dependency(*dep, !interactive, logger).await && prefs.is_never_remind(dep.id()) {
            prefs.never_remind.retain(|id| id != dep.id());
            prefs_changed = true;
        }
    }

    // The interactive prompt covers what a flag didn't, minus anything the user muted.
    let to_prompt: Vec<Dependency> = missing
        .iter()
        .copied()
        .filter(|dep| !flag_selected.contains(dep))
        .filter(|dep| !prefs.is_never_remind(dep.id()))
        .collect();

    match decide_dep_action(!to_prompt.is_empty(), interactive) {
        DepAction::NothingToPrompt => {}
        DepAction::SkipNonInteractive => {
            let names: Vec<&str> = to_prompt.iter().map(|d| d.id()).collect();
            logger.warn(&format!(
                "Optional dependencies not installed ({}) — the scan will run with reduced \
                 coverage. Install them, or pass --install-deps, to enable those capabilities.",
                names.join(", ")
            ));
        }
        DepAction::Prompt => {
            let response = prompt_for_dependencies(input, &to_prompt);
            let selected = selected_dependencies(&response, &to_prompt);
            for dep in &selected {
                install_dependency(*dep, false, logger).await;
            }
            // ONE consolidated reminder question over everything the user declined.
            let declined: Vec<Dependency> = to_prompt
                .iter()
                .copied()
                .filter(|dep| !selected.contains(dep))
                .collect();
            for dep in prompt_reminder_choice(input, &declined) {
                prefs.mark_never_remind(dep.id());
                prefs_changed = true;
            }
        }
    }

    if prefs_changed {
        if let Err(e) = prefs.save() {
            logger.warn(&format!("Could not save dependency preference: {e}"));
        }
    }
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn is_present(dep: Dependency, subfinder_path: Option<&str>) -> bool {
    match dep {
        Dependency::Browser => browser_install::detect_browser().is_some(),
        Dependency::Subfinder => {
            // Use the SAME resolution the scan uses, so "prompt to install" and "actually use it"
            // never disagree — including a custom configured subfinder path.
            let path = subfinder_path.unwrap_or("subfinder");
            crate::discovery::subfinder::SubfinderDiscovery::new(
                std::path::PathBuf::from(path),
                std::time::Duration::from_secs(30),
            )
            .is_available()
        }
        Dependency::Whois => which::which("whois").is_ok(),
    }
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn prompt_for_dependencies(input: &dyn InputSource, deps: &[Dependency]) -> PromptResponse {
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║   Optional dependencies — install to unlock more analysis        ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
    eprintln!();
    eprintln!("These are missing. nthpartyfinder can install them for you:");
    eprintln!();
    for (i, dep) in deps.iter().enumerate() {
        eprintln!("  [{}] {}", i + 1, dep.display_name());
        eprintln!("      {}", dep.capability_impact());
        eprintln!();
    }
    eprintln!("Install all of them? [y]es / [N]o / or type numbers to pick (e.g. 1,3)");
    eprint!("> ");
    let _ = std::io::Write::flush(&mut std::io::stderr());

    let mut buf = String::new();
    let read = input.read_line(&mut buf);
    response_from_read(read, &buf, deps.len())
}

/// Ask ONCE about everything the user declined, and return the deps to silence forever.
#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn prompt_reminder_choice(input: &dyn InputSource, declined: &[Dependency]) -> Vec<Dependency> {
    if declined.is_empty() {
        return Vec::new();
    }
    let names: Vec<&str> = declined.iter().map(|d| d.display_name()).collect();
    eprintln!();
    eprintln!("You skipped: {}.", names.join(", "));
    if declined.len() == 1 {
        eprint!("Remind you next run [R], or never again [n]? > ");
    } else {
        eprint!("[R]emind next run (all) / [n]ever again (all) / numbers to silence just those > ");
    }
    let _ = std::io::Write::flush(&mut std::io::stderr());

    let mut buf = String::new();
    let read = input.read_line(&mut buf);
    let selection = reminder_selection_from_read(read, &buf, declined.len());
    let silenced = silenced_dependencies(&selection, declined);
    if silenced.is_empty() {
        eprintln!("  OK — will remind you next run.");
    } else {
        let ids: Vec<&str> = silenced.iter().map(|d| d.id()).collect();
        eprintln!("  OK — won't ask about {} again.", ids.join(", "));
    }
    silenced
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn install_dependency(
    dep: Dependency,
    non_interactive: bool,
    logger: &AnalysisLogger,
) -> bool {
    match dep {
        Dependency::Browser => {
            let plan = browser_install::resolve_install_plan(
                std::env::consts::OS,
                &ToolAvailability::detect(),
            );
            run_package_manager_plan(
                plan,
                non_interactive,
                || browser_install::detect_browser().is_some(),
                logger,
            )
        }
        Dependency::Whois => {
            let plan = whois_install_plan(std::env::consts::OS, &ToolAvailability::detect());
            run_package_manager_plan(
                plan,
                non_interactive,
                || which::which("whois").is_ok(),
                logger,
            )
        }
        Dependency::Subfinder => {
            eprintln!();
            eprintln!("Downloading subfinder…");
            match crate::discovery::subfinder::SubfinderDiscovery::download_and_install().await {
                Ok(path) => {
                    eprintln!("✅ subfinder installed.");
                    logger.info(&format!("subfinder installed ({}).", path.display()));
                    true
                }
                Err(e) => {
                    logger.warn(&format!(
                        "subfinder install did not complete ({e}). Subdomain discovery will be \
                         skipped. Install manually: https://github.com/projectdiscovery/subfinder"
                    ));
                    false
                }
            }
        }
    }
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn run_package_manager_plan(
    plan: InstallPlan,
    non_interactive: bool,
    detect: impl Fn() -> bool,
    logger: &AnalysisLogger,
) -> bool {
    if plan.commands.is_empty() {
        eprintln!();
        eprintln!(
            "No supported installer for {} on this system. Install it manually: {}",
            plan.target_label, plan.manual_url
        );
        return false;
    }
    let plan = if non_interactive {
        browser_install::non_interactive_plan(plan)
    } else {
        plan
    };
    browser_install::execute_install_plan(&plan, detect, logger)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Dependency metadata ───────────────────────────────────────────

    #[test]
    fn ids_are_stable_and_distinct() {
        assert_eq!(Dependency::Browser.id(), "browser");
        assert_eq!(Dependency::Subfinder.id(), "subfinder");
        assert_eq!(Dependency::Whois.id(), "whois");
    }

    #[test]
    fn every_dependency_states_disabled_or_degraded_impact() {
        for dep in [
            Dependency::Browser,
            Dependency::Subfinder,
            Dependency::Whois,
        ] {
            let impact = dep.capability_impact();
            assert!(!impact.is_empty());
            assert!(
                impact.contains("DISABLED") || impact.contains("DEGRADED"),
                "{} impact must name DISABLED/DEGRADED: {impact}",
                dep.id()
            );
            assert!(!dep.display_name().is_empty());
        }
    }

    // ── relevance ─────────────────────────────────────────────────────

    #[test]
    fn relevance_tracks_enabled_phases_and_always_includes_whois() {
        assert_eq!(relevant_dependencies(false, false), vec![Dependency::Whois]);
        assert_eq!(
            relevant_dependencies(true, false),
            vec![Dependency::Browser, Dependency::Whois]
        );
        assert_eq!(
            relevant_dependencies(false, true),
            vec![Dependency::Subfinder, Dependency::Whois]
        );
        assert_eq!(
            relevant_dependencies(true, true),
            vec![
                Dependency::Browser,
                Dependency::Subfinder,
                Dependency::Whois
            ]
        );
    }

    // ── dependencies_to_prompt: missing AND not never-remind ──────────

    #[test]
    fn to_prompt_excludes_present_and_never_remind() {
        let relevant = vec![
            Dependency::Browser,
            Dependency::Subfinder,
            Dependency::Whois,
        ];
        // Browser present, whois on never-remind → only subfinder should be prompted.
        let present = vec![Dependency::Browser];
        let never = vec!["whois".to_string()];
        assert_eq!(
            dependencies_to_prompt(&relevant, &present, &never),
            vec![Dependency::Subfinder]
        );
    }

    #[test]
    fn to_prompt_empty_when_all_present() {
        let relevant = vec![Dependency::Whois];
        assert_eq!(
            dependencies_to_prompt(&relevant, &[Dependency::Whois], &[]),
            Vec::<Dependency>::new()
        );
    }

    #[test]
    fn never_remind_alone_can_empty_the_prompt() {
        let relevant = vec![Dependency::Subfinder];
        let never = vec!["subfinder".to_string()];
        assert!(dependencies_to_prompt(&relevant, &[], &never).is_empty());
    }

    // ── decide_dep_action: never-hang invariant ───────────────────────

    #[test]
    fn decide_nothing_to_prompt() {
        assert_eq!(decide_dep_action(false, true), DepAction::NothingToPrompt);
        assert_eq!(decide_dep_action(false, false), DepAction::NothingToPrompt);
    }

    #[test]
    fn decide_non_interactive_with_missing_skips_never_prompts() {
        // THE hard requirement: missing deps + not a terminal ⇒ skip, never read stdin.
        assert_eq!(
            decide_dep_action(true, false),
            DepAction::SkipNonInteractive
        );
    }

    #[test]
    fn decide_interactive_with_missing_prompts() {
        assert_eq!(decide_dep_action(true, true), DepAction::Prompt);
    }

    // ── flag_selected_dependencies ────────────────────────────────────

    #[test]
    fn install_all_flag_selects_everything() {
        let to_prompt = vec![
            Dependency::Browser,
            Dependency::Subfinder,
            Dependency::Whois,
        ];
        assert_eq!(
            flag_selected_dependencies(&to_prompt, true, false),
            to_prompt
        );
    }

    #[test]
    fn install_browser_flag_selects_only_browser_when_present_in_set() {
        let to_prompt = vec![Dependency::Subfinder, Dependency::Browser];
        assert_eq!(
            flag_selected_dependencies(&to_prompt, false, true),
            vec![Dependency::Browser]
        );
        // No browser in the set ⇒ nothing selected.
        assert!(flag_selected_dependencies(&[Dependency::Whois], false, true).is_empty());
    }

    #[test]
    fn no_flags_selects_nothing() {
        let to_prompt = vec![Dependency::Browser, Dependency::Whois];
        assert!(flag_selected_dependencies(&to_prompt, false, false).is_empty());
    }

    #[test]
    fn install_all_takes_precedence_over_install_browser() {
        // Both flags set → install-all wins (covers everything, not just the browser).
        let to_prompt = vec![
            Dependency::Browser,
            Dependency::Subfinder,
            Dependency::Whois,
        ];
        assert_eq!(
            flag_selected_dependencies(&to_prompt, true, true),
            to_prompt
        );
    }

    // ── parse_prompt_response ──────────────────────────────────────────

    #[test]
    fn parse_response_only_explicit_yes_installs_all() {
        for yes in ["y", "Y", "yes", "YES", "a", "all", "  all  "] {
            assert_eq!(
                parse_prompt_response(yes, 3),
                PromptResponse::All,
                "{yes:?}"
            );
        }
    }

    #[test]
    fn parse_response_empty_is_decline_not_install() {
        // Consent safety: a bare Enter must NOT install (installing runs sudo + downloads a binary).
        for none in ["", "\n", "   ", "n", "N", "no", "s", "skip", "SKIP"] {
            assert_eq!(
                parse_prompt_response(none, 3),
                PromptResponse::None,
                "{none:?}"
            );
        }
    }

    #[test]
    fn parse_response_numbers_select_subset() {
        assert_eq!(
            parse_prompt_response("1,3", 3),
            PromptResponse::Subset(vec![1, 3])
        );
        assert_eq!(
            parse_prompt_response("2 1", 3),
            PromptResponse::Subset(vec![1, 2]) // sorted + dedup
        );
        assert_eq!(
            parse_prompt_response("2,2,2", 3),
            PromptResponse::Subset(vec![2])
        );
    }

    #[test]
    fn parse_response_out_of_range_and_garbage_are_dropped_then_declined() {
        // Out of range, zero, negative, garbage → nothing valid → None (never install by accident).
        assert_eq!(parse_prompt_response("5", 3), PromptResponse::None);
        assert_eq!(parse_prompt_response("0", 3), PromptResponse::None);
        assert_eq!(parse_prompt_response("-1", 3), PromptResponse::None);
        assert_eq!(parse_prompt_response("banana", 3), PromptResponse::None);
        // A mix keeps only the in-range number.
        assert_eq!(
            parse_prompt_response("2, banana, 9", 3),
            PromptResponse::Subset(vec![2])
        );
    }

    // ── response_from_read: EOF-is-decline ────────────────────────────

    #[test]
    fn response_from_read_eof_and_error_install_nothing() {
        assert_eq!(response_from_read(Ok(0), "", 3), PromptResponse::None);
        let err = Err(std::io::Error::other("boom"));
        assert_eq!(response_from_read(err, "", 3), PromptResponse::None);
    }

    #[test]
    fn response_from_read_real_line_defers_to_parse() {
        assert_eq!(response_from_read(Ok(2), "y\n", 3), PromptResponse::All);
        assert_eq!(response_from_read(Ok(1), "\n", 3), PromptResponse::None); // bare Enter declines
        assert_eq!(
            response_from_read(Ok(3), "1,2", 3),
            PromptResponse::Subset(vec![1, 2])
        );
    }

    // ── selected_dependencies (guarded index math) ─────────────────────

    #[test]
    fn selected_maps_response_to_deps() {
        let prompted = vec![
            Dependency::Browser,
            Dependency::Subfinder,
            Dependency::Whois,
        ];
        assert_eq!(
            selected_dependencies(&PromptResponse::All, &prompted),
            prompted
        );
        assert!(selected_dependencies(&PromptResponse::None, &prompted).is_empty());
        assert_eq!(
            selected_dependencies(&PromptResponse::Subset(vec![1, 3]), &prompted),
            vec![Dependency::Browser, Dependency::Whois]
        );
        // Out-of-range and 0 indices are filtered — the 0 must not underflow/panic.
        assert!(selected_dependencies(&PromptResponse::Subset(vec![9]), &prompted).is_empty());
        assert!(selected_dependencies(&PromptResponse::Subset(vec![0]), &prompted).is_empty());
    }

    // ── consolidated reminder (one question over all declined) ─────────

    #[test]
    fn reminder_selection_defaults_and_never_all() {
        for remind in ["", "r", "remind", "later", "x"] {
            assert_eq!(
                parse_reminder_selection(remind, 3),
                ReminderSelection::RemindAll,
                "{remind:?}"
            );
        }
        assert_eq!(
            parse_reminder_selection("n", 3),
            ReminderSelection::NeverAll
        );
        assert_eq!(
            parse_reminder_selection("never", 3),
            ReminderSelection::NeverAll
        );
        assert_eq!(
            parse_reminder_selection("1,3", 3),
            ReminderSelection::NeverSubset(vec![1, 3])
        );
        // Out-of-range/garbage → remind all (safe default).
        assert_eq!(
            parse_reminder_selection("9, foo", 3),
            ReminderSelection::RemindAll
        );
    }

    #[test]
    fn reminder_selection_from_read_eof_keeps_reminding() {
        assert_eq!(
            reminder_selection_from_read(Ok(0), "", 3),
            ReminderSelection::RemindAll
        );
        let err = Err(std::io::Error::other("boom"));
        assert_eq!(
            reminder_selection_from_read(err, "", 3),
            ReminderSelection::RemindAll
        );
        assert_eq!(
            reminder_selection_from_read(Ok(6), "never\n", 3),
            ReminderSelection::NeverAll
        );
    }

    #[test]
    fn silenced_maps_selection_to_declined_deps() {
        let declined = vec![Dependency::Subfinder, Dependency::Whois];
        assert!(silenced_dependencies(&ReminderSelection::RemindAll, &declined).is_empty());
        assert_eq!(
            silenced_dependencies(&ReminderSelection::NeverAll, &declined),
            declined
        );
        assert_eq!(
            silenced_dependencies(&ReminderSelection::NeverSubset(vec![2]), &declined),
            vec![Dependency::Whois]
        );
        // 0 and out-of-range are guarded.
        assert!(
            silenced_dependencies(&ReminderSelection::NeverSubset(vec![0, 9]), &declined)
                .is_empty()
        );
    }

    // ── whois_install_plan ─────────────────────────────────────────────

    fn tools_with_apt() -> ToolAvailability {
        ToolAvailability {
            apt_get: true,
            ..ToolAvailability::default()
        }
    }

    #[test]
    fn whois_plan_macos_uses_brew() {
        let plan = whois_install_plan(
            "macos",
            &ToolAvailability {
                brew: true,
                ..ToolAvailability::default()
            },
        );
        assert_eq!(plan.target_label, "whois");
        assert_eq!(plan.commands.len(), 1);
        assert_eq!(plan.commands[0].display(), "brew install whois");
    }

    #[test]
    fn whois_plan_macos_without_brew_is_manual_only() {
        let plan = whois_install_plan("macos", &ToolAvailability::default());
        assert!(plan.commands.is_empty());
    }

    #[test]
    fn whois_plan_windows_is_manual_only() {
        let plan = whois_install_plan("windows", &tools_with_apt());
        assert!(plan.commands.is_empty(), "no apt on windows path");
        assert!(plan.manual_url.contains("sysinternals"));
    }

    #[test]
    fn whois_plan_linux_apt() {
        let plan = whois_install_plan("linux", &tools_with_apt());
        assert_eq!(plan.commands.len(), 1);
        assert_eq!(plan.commands[0].display(), "sudo apt-get install -y whois");
    }

    #[test]
    fn whois_plan_linux_multiple_managers_ordered() {
        let plan = whois_install_plan(
            "linux",
            &ToolAvailability {
                dnf: true,
                zypper: true,
                ..ToolAvailability::default()
            },
        );
        assert_eq!(plan.commands.len(), 2);
        assert_eq!(plan.commands[0].display(), "sudo dnf install -y whois");
        assert_eq!(
            plan.commands[1].display(),
            "sudo zypper --non-interactive install whois"
        );
    }

    #[test]
    fn whois_plan_linux_pacman() {
        let plan = whois_install_plan(
            "linux",
            &ToolAvailability {
                pacman: true,
                ..ToolAvailability::default()
            },
        );
        assert_eq!(plan.commands.len(), 1);
        assert_eq!(
            plan.commands[0].display(),
            "sudo pacman -S --noconfirm whois"
        );
    }

    #[test]
    fn whois_plan_linux_no_manager_is_manual_only() {
        let plan = whois_install_plan("linux", &ToolAvailability::default());
        assert!(plan.commands.is_empty());
        assert!(plan.manual_url.contains("rfc1036/whois"));
    }

    #[test]
    fn whois_plan_commands_are_shell_free() {
        let plan = whois_install_plan("linux", &tools_with_apt());
        for command in &plan.commands {
            assert_ne!(command.program, "sh");
            assert_ne!(command.program, "bash");
            for arg in &command.args {
                assert!(!arg.contains([';', '|', '&', '$', '`']));
            }
        }
    }
}
