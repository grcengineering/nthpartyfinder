//! Runtime browser detection and optional guided install.
//!
//! nthpartyfinder's browser-based discovery phases — web-org extraction, web-traffic
//! discovery, and subprocessor page rendering — need a Chromium-family browser (Chrome,
//! Chromium, or Edge). Rather than make a browser a hard install-time dependency (which
//! would force `brew install --cask …`, break on machines that already have Chrome, and
//! not work on Linux at all), the tool detects a browser at runtime and, when none is
//! found AND a browser-using phase is enabled, offers to install one for the user's
//! platform. This keeps `brew install nthpartyfinder` (and every other install path) a
//! single step.
//!
//! This module provides browser-specific detection ([`detect_browser`], faithful to
//! `headless_chrome`'s own probe set) and the shared per-OS install machinery
//! ([`resolve_install_plan`], [`non_interactive_plan`], [`execute_install_plan`]) reused by
//! the unified dependency prompt in [`crate::dependencies`]. The user-facing decision,
//! consent, and prompt flow lives there, not here.
//!
//! SECURITY: every install command is built from constant program names and constant
//! argument arrays via [`std::process::Command`] (never a shell string), so the domain
//! under scan — or any other external input — can never influence what runs. When an install
//! runs unattended (`--install-deps`/`--install-browser` on a non-tty), sudo runs with `-n`
//! so it fails fast instead of blocking on a password prompt, and every installer subprocess
//! is bounded by a wall-clock timeout — so no path can hang the tool indefinitely.

// Only referenced by the coverage(off), cfg(not(test)) install executor below.
#[cfg(not(test))]
use crate::logger::AnalysisLogger;
use std::path::PathBuf;

/// Browser executables to look for on `PATH`, in preference order. This is the exact set
/// `headless_chrome` 1.0.22 probes in `default_executable()`, so "detected here" implies
/// "launchable there" — we never prompt to install a browser the scanner could have used,
/// nor report one present that the launcher can't find. A test pins this to catch drift on
/// a `headless_chrome` bump.
fn browser_path_names() -> &'static [&'static str] {
    &[
        "google-chrome-stable",
        "google-chrome-beta",
        "google-chrome-dev",
        "google-chrome-unstable",
        "chromium",
        "chromium-browser",
        "microsoft-edge-stable",
        "microsoft-edge-beta",
        "microsoft-edge-dev",
        "chrome",
        "chrome-browser",
        "msedge",
        "microsoft-edge",
    ]
}

/// Well-known filesystem locations for an installed browser, per OS. Parameterised on the
/// OS string (rather than `cfg`) so the mapping is unit-testable on any host. The macOS list
/// mirrors `headless_chrome`'s app-bundle probes; the Windows list covers the common Chrome
/// and Edge install paths (`headless_chrome` additionally consults the registry, which the
/// PATH-name lookup above already covers for a normally-installed browser).
fn browser_system_paths_for(os: &str) -> &'static [&'static str] {
    match os {
        "macos" => &[
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta",
            "/Applications/Google Chrome Dev.app/Contents/MacOS/Google Chrome Dev",
            "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Microsoft Edge Beta.app/Contents/MacOS/Microsoft Edge Beta",
            "/Applications/Microsoft Edge Dev.app/Contents/MacOS/Microsoft Edge Dev",
            "/Applications/Microsoft Edge Canary.app/Contents/MacOS/Microsoft Edge Canary",
        ],
        "windows" => &[
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        ],
        // Linux and other unixes.
        _ => &[
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/snap/bin/chromium",
            "/usr/bin/microsoft-edge",
        ],
    }
}

/// A single installer invocation. Program + argument array only — never a shell string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl InstallCommand {
    /// Human-readable rendering of the command, e.g. `sudo apt-get install -y chromium`.
    pub fn display(&self) -> String {
        if self.args.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
        }
    }
}

/// The platform-appropriate way to install a browser: an ordered list of candidate
/// commands (tried until one produces a detectable browser) plus a manual-download URL
/// used when no supported installer is present or every command fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    /// Display name of the browser this plan installs (e.g. `Google Chrome`, `Chromium`).
    pub target_label: &'static str,
    /// Installer commands, tried in order until one succeeds. Empty ⇒ manual-only.
    pub commands: Vec<InstallCommand>,
    /// Where to point the user when we cannot install for them.
    pub manual_url: &'static str,
}

/// Which package managers / installers are present on this machine. Kept as data so the
/// plan resolver is pure and exhaustively testable across combinations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ToolAvailability {
    pub brew: bool,
    pub apt_get: bool,
    pub dnf: bool,
    pub pacman: bool,
    pub zypper: bool,
    pub snap: bool,
    pub winget: bool,
    pub choco: bool,
}

impl ToolAvailability {
    /// Probe `PATH` for each supported installer. `coverage(off)`: thin `which` wrapper —
    /// the decision logic that consumes this lives in the pure [`resolve_install_plan`].
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn detect() -> Self {
        let has = |tool: &str| which::which(tool).is_ok();
        ToolAvailability {
            brew: has("brew"),
            apt_get: has("apt-get"),
            dnf: has("dnf"),
            pacman: has("pacman"),
            zypper: has("zypper"),
            snap: has("snap"),
            winget: has("winget"),
            choco: has("choco"),
        }
    }
}

fn cmd(program: &str, args: &[&str]) -> InstallCommand {
    InstallCommand {
        program: program.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
    }
}

/// Resolve how to install a browser on `os` given the installers available in `tools`.
///
/// Smart per-OS target (chosen for install reliability, all fully supported by the
/// scanner): Google Chrome on macOS (Homebrew cask) and Windows (winget/choco); Chromium
/// on Linux via the system package manager (distro-native — no Google apt/yum repo or
/// signing-key setup required), with snap as a last-resort fallback.
pub fn resolve_install_plan(os: &str, tools: &ToolAvailability) -> InstallPlan {
    match os {
        "macos" => {
            let mut commands = Vec::new();
            if tools.brew {
                commands.push(cmd("brew", &["install", "--cask", "google-chrome"]));
            }
            InstallPlan {
                target_label: "Google Chrome",
                commands,
                manual_url: "https://www.google.com/chrome/",
            }
        }
        "windows" => {
            let mut commands = Vec::new();
            if tools.winget {
                commands.push(cmd(
                    "winget",
                    &[
                        "install",
                        "--id",
                        "Google.Chrome",
                        "-e",
                        "--accept-package-agreements",
                        "--accept-source-agreements",
                    ],
                ));
            }
            if tools.choco {
                commands.push(cmd("choco", &["install", "googlechrome", "-y"]));
            }
            InstallPlan {
                target_label: "Google Chrome",
                commands,
                manual_url: "https://www.google.com/chrome/",
            }
        }
        // Linux and other unixes: Chromium via the system package manager.
        _ => {
            let mut commands = Vec::new();
            if tools.apt_get {
                // Debian ships `chromium`; Ubuntu ships `chromium-browser` — try both so a
                // single "yes" works across the two dominant apt families.
                commands.push(cmd("sudo", &["apt-get", "install", "-y", "chromium"]));
                commands.push(cmd(
                    "sudo",
                    &["apt-get", "install", "-y", "chromium-browser"],
                ));
            }
            if tools.dnf {
                commands.push(cmd("sudo", &["dnf", "install", "-y", "chromium"]));
            }
            if tools.pacman {
                commands.push(cmd("sudo", &["pacman", "-S", "--noconfirm", "chromium"]));
            }
            if tools.zypper {
                commands.push(cmd(
                    "sudo",
                    &["zypper", "--non-interactive", "install", "chromium"],
                ));
            }
            if tools.snap {
                commands.push(cmd("sudo", &["snap", "install", "chromium"]));
            }
            InstallPlan {
                target_label: "Chromium",
                commands,
                manual_url: "https://www.chromium.org/getting-involved/download-chromium/",
            }
        }
    }
}

/// Rewrite a plan for unattended use: every `sudo` invocation gets `-n` (non-interactive)
/// inserted first, so sudo returns an error immediately when credentials aren't cached
/// instead of blocking forever on a `/dev/tty` password prompt. Non-sudo installers
/// (brew/winget/choco) are left unchanged. Idempotent — a `sudo -n …` is not re-prefixed.
pub fn non_interactive_plan(mut plan: InstallPlan) -> InstallPlan {
    for command in &mut plan.commands {
        if command.program == "sudo" && command.args.first().map(String::as_str) != Some("-n") {
            command.args.insert(0, "-n".to_string());
        }
    }
    plan
}

/// Outcome of running one installer command.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RunOutcome {
    Succeeded,
    Failed(String),
}

/// Pure sequencing over the plan's commands: run each until one succeeds AND a browser is
/// then detectable. `run` executes a command; `detect` reports whether a browser is now
/// present (a command can "succeed" without producing a launchable browser — e.g. apt
/// installs `chromium-browser` as a snap stub — so detection is the real success test).
/// Returns `Ok(())` once a browser is present, or `Err(last_error)` if every command was
/// exhausted. Structured this way so the fallback design is asserted by tests with fakes,
/// while production wires real subprocess spawning + [`detect_browser`].
fn install_sequence<R, D>(commands: &[InstallCommand], run: R, detect: D) -> Result<(), String>
where
    R: Fn(&InstallCommand) -> RunOutcome,
    D: Fn() -> bool,
{
    let mut last_error: Option<String> = None;
    for command in commands {
        match run(command) {
            RunOutcome::Succeeded => {
                if detect() {
                    return Ok(());
                }
                last_error = Some(format!(
                    "`{}` succeeded but no browser was detected afterward",
                    command.display()
                ));
            }
            RunOutcome::Failed(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| "no installer commands to run".to_string()))
}

/// Detect an installed browser the scanner could launch. Returns its path if found.
pub fn detect_browser() -> Option<PathBuf> {
    detect_browser_impl()
}

// coverage(off): performs real `which`/filesystem probes. The pure inputs it consults —
// [`browser_path_names`], [`browser_system_paths_for`] — are unit-tested directly.
#[cfg_attr(coverage_nightly, coverage(off))]
fn detect_browser_impl() -> Option<PathBuf> {
    // Explicit overrides first — both env conventions the codebase and headless_chrome honor.
    for var in ["CHROME_PATH", "CHROME"] {
        if let Ok(value) = std::env::var(var) {
            let path = std::path::Path::new(&value);
            if !value.trim().is_empty() && path.exists() {
                return Some(path.to_path_buf());
            }
        }
    }
    // Anything on PATH.
    for name in browser_path_names() {
        if let Ok(path) = which::which(name) {
            return Some(path);
        }
    }
    // OS well-known install locations.
    for candidate in browser_system_paths_for(std::env::consts::OS) {
        let path = std::path::Path::new(candidate);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    None
}

/// Backstop wall-clock timeout for any single installer subprocess. Generous — a browser
/// download can be large — but bounded, so a stalled installer (a `dpkg` conffile prompt, a
/// wedged `snap` download, an elevation dialog) can never hang the tool forever. The common
/// sudo-password hang is handled earlier by `-n` on the unattended path.
#[cfg(not(test))]
const INSTALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

// coverage(off) + cfg(not(test)): spawns installer subprocesses.
#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn run_one_command(command: &InstallCommand, timeout: std::time::Duration) -> RunOutcome {
    eprintln!();
    eprintln!("Running: {}", command.display());

    let mut child = match std::process::Command::new(&command.program)
        .args(&command.args)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return RunOutcome::Failed(format!("could not run `{}`: {}", command.display(), e))
        }
    };

    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return RunOutcome::Succeeded,
            Ok(Some(status)) => {
                return RunOutcome::Failed(format!(
                    "`{}` exited with {}",
                    command.display(),
                    status
                ))
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return RunOutcome::Failed(format!(
                        "`{}` timed out after {}s",
                        command.display(),
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => {
                return RunOutcome::Failed(format!(
                    "error waiting on `{}`: {}",
                    command.display(),
                    e
                ))
            }
        }
    }
}

/// Run an install plan's commands until one succeeds AND `detect` reports the target present.
/// Generic over the dependency being installed (browser, whois, …): the caller supplies the
/// post-install detection probe and frames any capability consequence. Returns whether the
/// target is present afterward. coverage(off) + cfg(not(test)): spawns real subprocesses.
#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn execute_install_plan(
    plan: &InstallPlan,
    detect: impl Fn() -> bool,
    logger: &AnalysisLogger,
) -> bool {
    match install_sequence(
        &plan.commands,
        |command| run_one_command(command, INSTALL_TIMEOUT),
        &detect,
    ) {
        Ok(()) => {
            eprintln!("✅ {} installed.", plan.target_label);
            logger.info(&format!("{} installed.", plan.target_label));
            true
        }
        Err(reason) => {
            logger.warn(&format!(
                "{} install did not complete ({reason}). Install manually: {}",
                plan.target_label, plan.manual_url,
            ));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn all_false() -> ToolAvailability {
        ToolAvailability::default()
    }

    // ── non_interactive_plan: sudo -n hang fix ────────────────────────────

    #[test]
    fn non_interactive_plan_inserts_dash_n_after_sudo() {
        let plan = resolve_install_plan(
            "linux",
            &ToolAvailability {
                apt_get: true,
                snap: true,
                ..all_false()
            },
        );
        let hardened = non_interactive_plan(plan);
        for command in &hardened.commands {
            assert_eq!(command.program, "sudo");
            assert_eq!(command.args.first().map(String::as_str), Some("-n"));
        }
        assert_eq!(
            hardened.commands[0].display(),
            "sudo -n apt-get install -y chromium"
        );
    }

    #[test]
    fn non_interactive_plan_leaves_non_sudo_installers_untouched() {
        // macOS brew and Windows winget are not sudo — they must not be rewritten.
        let mac = non_interactive_plan(resolve_install_plan(
            "macos",
            &ToolAvailability {
                brew: true,
                ..all_false()
            },
        ));
        assert_eq!(
            mac.commands[0].display(),
            "brew install --cask google-chrome"
        );

        let win = non_interactive_plan(resolve_install_plan(
            "windows",
            &ToolAvailability {
                winget: true,
                ..all_false()
            },
        ));
        assert!(win.commands[0].args.first().map(String::as_str) != Some("-n"));
        assert_eq!(win.commands[0].program, "winget");
    }

    #[test]
    fn non_interactive_plan_is_idempotent() {
        let once = non_interactive_plan(resolve_install_plan(
            "linux",
            &ToolAvailability {
                dnf: true,
                ..all_false()
            },
        ));
        let twice = non_interactive_plan(once.clone());
        assert_eq!(once, twice);
        assert_eq!(
            twice.commands[0].display(),
            "sudo -n dnf install -y chromium"
        );
    }

    // ── install_sequence: fallback sequencing (finding #8) ────────────────

    fn c(display_program: &str) -> InstallCommand {
        cmd(display_program, &["x"])
    }

    #[test]
    fn install_sequence_first_success_with_detection_stops() {
        let runs = Cell::new(0);
        let out = install_sequence(
            &[c("a"), c("b")],
            |_| {
                runs.set(runs.get() + 1);
                RunOutcome::Succeeded
            },
            || true,
        );
        assert_eq!(out, Ok(()));
        assert_eq!(
            runs.get(),
            1,
            "should stop after the first success that detects"
        );
    }

    #[test]
    fn install_sequence_success_but_no_browser_tries_next() {
        // apt "succeeds" installing a snap stub that produces no launchable browser ⇒ next.
        let runs = Cell::new(0);
        let out = install_sequence(
            &[c("chromium"), c("chromium-browser")],
            |_| {
                runs.set(runs.get() + 1);
                RunOutcome::Succeeded
            },
            // Only "detect" a browser after the SECOND command has run.
            || runs.get() >= 2,
        );
        assert_eq!(out, Ok(()));
        assert_eq!(runs.get(), 2);
    }

    #[test]
    fn install_sequence_all_fail_returns_last_error() {
        let out = install_sequence(
            &[c("a"), c("b")],
            |command| RunOutcome::Failed(format!("{} boom", command.program)),
            || false,
        );
        assert_eq!(out, Err("b boom".to_string()));
    }

    #[test]
    fn install_sequence_empty_commands_errors() {
        let out = install_sequence(&[], |_| RunOutcome::Succeeded, || true);
        assert!(out.is_err());
    }

    // ── resolve_install_plan: macOS ───────────────────────────────────

    #[test]
    fn macos_with_brew_installs_chrome_via_cask() {
        let tools = ToolAvailability {
            brew: true,
            ..all_false()
        };
        let plan = resolve_install_plan("macos", &tools);
        assert_eq!(plan.target_label, "Google Chrome");
        assert_eq!(plan.commands.len(), 1);
        assert_eq!(
            plan.commands[0].display(),
            "brew install --cask google-chrome"
        );
        assert_eq!(plan.manual_url, "https://www.google.com/chrome/");
    }

    #[test]
    fn macos_without_brew_is_manual_only() {
        let plan = resolve_install_plan("macos", &all_false());
        assert_eq!(plan.target_label, "Google Chrome");
        assert!(plan.commands.is_empty());
        assert_eq!(plan.manual_url, "https://www.google.com/chrome/");
    }

    // ── resolve_install_plan: Windows ─────────────────────────────────

    #[test]
    fn windows_prefers_winget_over_choco() {
        let tools = ToolAvailability {
            winget: true,
            choco: true,
            ..all_false()
        };
        let plan = resolve_install_plan("windows", &tools);
        assert_eq!(plan.target_label, "Google Chrome");
        assert_eq!(plan.commands.len(), 2);
        assert_eq!(plan.commands[0].program, "winget");
        assert!(plan.commands[0].args.contains(&"Google.Chrome".to_string()));
        assert_eq!(plan.commands[1].program, "choco");
    }

    #[test]
    fn windows_choco_only() {
        let tools = ToolAvailability {
            choco: true,
            ..all_false()
        };
        let plan = resolve_install_plan("windows", &tools);
        assert_eq!(plan.commands.len(), 1);
        assert_eq!(plan.commands[0].display(), "choco install googlechrome -y");
    }

    #[test]
    fn windows_without_installers_is_manual_only() {
        let plan = resolve_install_plan("windows", &all_false());
        assert!(plan.commands.is_empty());
        assert_eq!(plan.manual_url, "https://www.google.com/chrome/");
    }

    // ── resolve_install_plan: Linux ───────────────────────────────────

    #[test]
    fn linux_apt_tries_both_chromium_package_names() {
        let tools = ToolAvailability {
            apt_get: true,
            ..all_false()
        };
        let plan = resolve_install_plan("linux", &tools);
        assert_eq!(plan.target_label, "Chromium");
        assert_eq!(plan.commands.len(), 2);
        assert_eq!(
            plan.commands[0].display(),
            "sudo apt-get install -y chromium"
        );
        assert_eq!(
            plan.commands[1].display(),
            "sudo apt-get install -y chromium-browser"
        );
    }

    #[test]
    fn linux_dnf_pacman_zypper_each_single_command() {
        for (tools, expected) in [
            (
                ToolAvailability {
                    dnf: true,
                    ..all_false()
                },
                "sudo dnf install -y chromium",
            ),
            (
                ToolAvailability {
                    pacman: true,
                    ..all_false()
                },
                "sudo pacman -S --noconfirm chromium",
            ),
            (
                ToolAvailability {
                    zypper: true,
                    ..all_false()
                },
                "sudo zypper --non-interactive install chromium",
            ),
        ] {
            let plan = resolve_install_plan("linux", &tools);
            assert_eq!(plan.commands.len(), 1);
            assert_eq!(plan.commands[0].display(), expected);
        }
    }

    #[test]
    fn linux_snap_is_fallback_after_system_pm() {
        let tools = ToolAvailability {
            dnf: true,
            snap: true,
            ..all_false()
        };
        let plan = resolve_install_plan("linux", &tools);
        assert_eq!(plan.commands.len(), 2);
        assert_eq!(plan.commands[0].program, "sudo");
        assert!(plan.commands[0].args.contains(&"dnf".to_string()));
        assert_eq!(plan.commands[1].display(), "sudo snap install chromium");
    }

    #[test]
    fn linux_without_any_pm_is_manual_only() {
        let plan = resolve_install_plan("linux", &all_false());
        assert_eq!(plan.target_label, "Chromium");
        assert!(plan.commands.is_empty());
        assert!(plan.manual_url.contains("chromium.org"));
    }

    #[test]
    fn unknown_os_falls_through_to_linux_style_plan() {
        let tools = ToolAvailability {
            apt_get: true,
            ..all_false()
        };
        let plan = resolve_install_plan("freebsd", &tools);
        assert_eq!(plan.target_label, "Chromium");
        assert!(!plan.commands.is_empty());
    }

    // ── install command construction is shell-free ────────────────────

    #[test]
    fn install_commands_never_use_a_shell() {
        let tools = ToolAvailability {
            brew: true,
            winget: true,
            apt_get: true,
            dnf: true,
            pacman: true,
            zypper: true,
            snap: true,
            choco: true,
        };
        for os in ["macos", "windows", "linux"] {
            // Check both the raw plan and the unattended-hardened variant.
            let plans = [
                resolve_install_plan(os, &tools),
                non_interactive_plan(resolve_install_plan(os, &tools)),
            ];
            for plan in plans {
                for command in plan.commands {
                    assert!(
                        !["sh", "bash", "zsh", "cmd", "powershell", "pwsh"]
                            .contains(&command.program.as_str()),
                        "{} must not shell out",
                        command.program
                    );
                    for arg in &command.args {
                        assert!(
                            !arg.contains([';', '|', '&', '$', '`']),
                            "arg {arg:?} contains a shell metacharacter"
                        );
                    }
                }
            }
        }
    }

    // ── InstallCommand::display ───────────────────────────────────────

    #[test]
    fn display_with_and_without_args() {
        assert_eq!(cmd("brew", &["install"]).display(), "brew install");
        assert_eq!(
            InstallCommand {
                program: "lone".into(),
                args: vec![]
            }
            .display(),
            "lone"
        );
    }

    // ── detection lists (pure) — pinned to headless_chrome 1.0.22 ─────

    #[test]
    fn browser_path_names_exactly_mirror_headless_chrome_1_0_22() {
        // The exact `default_executable()` PATH probe set in headless_chrome 1.0.22. If a
        // dependency bump changes this, update both together (and detect_browser stays faithful).
        let expected = [
            "google-chrome-stable",
            "google-chrome-beta",
            "google-chrome-dev",
            "google-chrome-unstable",
            "chromium",
            "chromium-browser",
            "microsoft-edge-stable",
            "microsoft-edge-beta",
            "microsoft-edge-dev",
            "chrome",
            "chrome-browser",
            "msedge",
            "microsoft-edge",
        ];
        assert_eq!(browser_path_names(), &expected[..]);
        // Guard against the specific false-positive the review caught: bare `google-chrome`
        // is NOT a name headless_chrome probes, so we must not either.
        assert!(!browser_path_names().contains(&"google-chrome"));
    }

    #[test]
    fn system_paths_are_platform_appropriate() {
        let mac = browser_system_paths_for("macos");
        assert!(mac
            .iter()
            .any(|p| p.contains("/Applications/Google Chrome.app")));
        // macOS list includes the Edge channels headless_chrome probes.
        assert!(mac.iter().any(|p| p.contains("Microsoft Edge Beta")));
        assert!(mac.iter().any(|p| p.contains("Microsoft Edge Canary")));
        assert!(browser_system_paths_for("windows")
            .iter()
            .any(|p| p.ends_with("chrome.exe")));
        let linux = browser_system_paths_for("linux");
        assert!(linux.iter().any(|p| p.contains("chromium")));
        // Unknown OS uses the same (unix) fallback list as Linux.
        assert_eq!(browser_system_paths_for("plan9"), linux);
    }

    // ── ToolAvailability ──────────────────────────────────────────────

    #[test]
    fn tool_availability_default_is_all_false() {
        let t = ToolAvailability::default();
        assert!(!t.brew && !t.apt_get && !t.dnf && !t.pacman);
        assert!(!t.zypper && !t.snap && !t.winget && !t.choco);
    }

    #[test]
    fn tool_availability_detect_does_not_panic() {
        let _ = ToolAvailability::detect();
    }

    // ── detect_browser smoke (host-dependent, must not panic) ─────────

    #[test]
    fn detect_browser_does_not_panic() {
        let _ = detect_browser();
    }
}
