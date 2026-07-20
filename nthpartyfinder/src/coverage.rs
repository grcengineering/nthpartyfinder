//! Per-phase discovery coverage — the scan-health visibility layer.
//!
//! Every discovery phase can fail, time out, or be starved of its budget and still return an
//! empty result that is byte-for-byte indistinguishable from "this domain genuinely has nothing."
//! That lets two identically-configured scans diverge silently: a transient network blip collapses
//! recall while the summary still prints SUCCESS. This module records, per phase, whether the phase
//! actually returned what it should have, so the final summary can tell "ran and found nothing"
//! apart from "ran but failed" — extending the DNS failure-visibility contract (GRC-367) to every
//! discovery phase.
//!
//! The live counters are a process-wide `static` (`SCAN_COVERAGE`), mirroring `perf::METRICS`: one
//! scan runs per process invocation, so a global is the natural home and avoids threading a report
//! object through the recursive `discover_nth_parties` fan-out. Reporting reads a `snapshot()` and
//! all formatting is pure over that snapshot, so it is testable without touching the global.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// One discovery phase's observed coverage across the whole scan (summed over every depth).
#[derive(Debug, Default)]
pub struct PhaseCoverage {
    found: AtomicU64,
    failed: AtomicU64,
    degraded: AtomicBool,
}

impl PhaseCoverage {
    const fn new() -> Self {
        Self {
            found: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            degraded: AtomicBool::new(false),
        }
    }

    /// Record a successful phase run that yielded `n` vendor domains.
    pub fn record_found(&self, n: usize) {
        self.found.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Record that the phase failed / timed out / was starved for one unit of work — it did not
    /// return what it should have. Marks the phase degraded so the summary flags it, and counts the
    /// failed unit. A failure is NOT the same as an authoritative empty; only real degradation
    /// (an error, a timeout, a budget starvation) calls this.
    pub fn record_failure(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        self.degraded.store(true, Ordering::Relaxed);
    }

    fn snapshot(&self) -> PhaseSnapshot {
        PhaseSnapshot {
            found: self.found.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            degraded: self.degraded.load(Ordering::Relaxed),
        }
    }

    /// Zero the counters. Test-support only; a scan never resets mid-flight.
    #[cfg(test)]
    pub fn reset(&self) {
        self.found.store(0, Ordering::Relaxed);
        self.failed.store(0, Ordering::Relaxed);
        self.degraded.store(false, Ordering::Relaxed);
    }
}

/// Every discovery phase's coverage for one scan.
#[derive(Debug)]
pub struct CoverageReport {
    pub subprocessor: PhaseCoverage,
    pub subfinder: PhaseCoverage,
    pub saas: PhaseCoverage,
    pub ct: PhaseCoverage,
    pub webtraffic: PhaseCoverage,
}

impl CoverageReport {
    const fn new() -> Self {
        Self {
            subprocessor: PhaseCoverage::new(),
            subfinder: PhaseCoverage::new(),
            saas: PhaseCoverage::new(),
            ct: PhaseCoverage::new(),
            webtraffic: PhaseCoverage::new(),
        }
    }

    /// Take a snapshot of every phase for reporting. Not atomic across phases — the scan has
    /// finished when this runs, so there are no concurrent writers.
    pub fn snapshot(&self) -> CoverageSnapshot {
        CoverageSnapshot {
            subprocessor: self.subprocessor.snapshot(),
            subfinder: self.subfinder.snapshot(),
            saas: self.saas.snapshot(),
            ct: self.ct.snapshot(),
            webtraffic: self.webtraffic.snapshot(),
        }
    }

    /// Zero every phase. Test-support only.
    #[cfg(test)]
    pub fn reset(&self) {
        self.subprocessor.reset();
        self.subfinder.reset();
        self.saas.reset();
        self.ct.reset();
        self.webtraffic.reset();
    }
}

/// Process-wide discovery coverage for the current scan (one scan per process invocation).
pub static SCAN_COVERAGE: CoverageReport = CoverageReport::new();

/// One phase's counts at reporting time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PhaseSnapshot {
    pub found: u64,
    pub failed: u64,
    pub degraded: bool,
}

/// Every phase's counts at reporting time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CoverageSnapshot {
    pub subprocessor: PhaseSnapshot,
    pub subfinder: PhaseSnapshot,
    pub saas: PhaseSnapshot,
    pub ct: PhaseSnapshot,
    pub webtraffic: PhaseSnapshot,
}

impl CoverageSnapshot {
    /// True if any phase failed / was degraded this scan.
    pub fn any_degraded(&self) -> bool {
        self.subprocessor.degraded
            || self.subfinder.degraded
            || self.saas.degraded
            || self.ct.degraded
            || self.webtraffic.degraded
    }

    /// The phase snapshot for a manifest feature name, if that feature maps to a discovery phase.
    /// (`web-org` is per-vendor org resolution, not a discovery phase, so it has no counts.)
    fn phase_for(&self, feature: &str) -> Option<PhaseSnapshot> {
        match feature {
            "subprocessor" => Some(self.subprocessor),
            "subdomain" => Some(self.subfinder),
            "saas-tenant" => Some(self.saas),
            "ct-logs" => Some(self.ct),
            "web-traffic" => Some(self.webtraffic),
            _ => None,
        }
    }
}

/// A discovery feature's enabled state and the reason, for the coverage manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureStatus {
    pub name: &'static str,
    pub enabled: bool,
    pub reason: String,
}

/// Explain why one discovery feature is on or off, mirroring `app::compute_feature_flags` exactly.
///
/// This is what lets the manifest say e.g. "ct-logs: disabled (default — enable with
/// --enable-ct-discovery)", so an intended, flag-driven difference between two scans is instantly
/// distinguishable from an unintended one. `config_default` is the shipped config value;
/// `enable_flag_name` is the flag to suggest when the feature is off-by-default.
pub fn feature_status(
    name: &'static str,
    dns_only: bool,
    enable_flag: bool,
    disable_flag: bool,
    config_default: bool,
    enable_flag_name: &str,
) -> FeatureStatus {
    if dns_only {
        return FeatureStatus {
            name,
            enabled: false,
            reason: "disabled (--dns-only mode)".to_string(),
        };
    }
    let enabled = enable_flag || (!disable_flag && config_default);
    let reason = if enable_flag {
        format!("enabled via {enable_flag_name}")
    } else if disable_flag {
        "disabled via flag".to_string()
    } else if config_default {
        "on by default".to_string()
    } else {
        format!("disabled (default — enable with {enable_flag_name})")
    };
    FeatureStatus {
        name,
        enabled,
        reason,
    }
}

/// A one-line human summary of how (and how badly) coverage was degraded, or `None` if the scan ran
/// clean. `subproc_starved` is `perf::METRICS.subproc_budget_exhausted` (vendors whose subprocessor
/// work overran the per-vendor time budget — a silent recall loss the phase's own return value
/// hides); `dns_failures` is the classified DNS failure count.
pub fn degradation_summary(
    snap: &CoverageSnapshot,
    subproc_starved: u64,
    dns_failures: u64,
) -> Option<String> {
    let mut parts = Vec::new();
    if subproc_starved > 0 {
        parts.push(format!(
            "subprocessor starved on {subproc_starved} vendor(s)"
        ));
    } else if snap.subprocessor.degraded {
        parts.push(format!(
            "subprocessor failed on {} domain(s)",
            snap.subprocessor.failed
        ));
    }
    if snap.webtraffic.degraded {
        parts.push(format!(
            "web-traffic capture failed on {} domain(s)",
            snap.webtraffic.failed
        ));
    }
    if snap.subfinder.degraded {
        parts.push(format!(
            "subdomain discovery failed on {} domain(s)",
            snap.subfinder.failed
        ));
    }
    if snap.saas.degraded {
        parts.push(format!(
            "SaaS-tenant discovery failed on {} domain(s)",
            snap.saas.failed
        ));
    }
    if snap.ct.degraded {
        parts.push(format!(
            "CT-log discovery failed on {} domain(s)",
            snap.ct.failed
        ));
    }
    if dns_failures > 0 {
        parts.push(format!("DNS degraded on {dns_failures} lookup(s)"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

/// Render the per-scan discovery-coverage manifest for the summary block. Pure over its inputs, so
/// the summary reads a live `SCAN_COVERAGE.snapshot()` but the formatting is testable directly.
///
/// One row per feature: why it is on/off, and — for the five discovery phases — how many vendors it
/// found and how many units failed. This is the surface that makes "CT was off" vs "subprocessor
/// collapsed" legible at a glance.
pub fn render_manifest(features: &[FeatureStatus], snap: &CoverageSnapshot) -> String {
    let mut out = String::from("── discovery coverage ──\n");
    for f in features {
        // The reason already carries the on/off state ("on by default", "disabled (--dns-only
        // mode)", …), so it stands alone — a separate state word would read as "disabled (disabled …)".
        match snap.phase_for(f.name).filter(|_| f.enabled) {
            Some(p) => {
                let flag = if p.degraded { "  ⚠ degraded" } else { "" };
                out.push_str(&format!(
                    "{:<13} {} — {} found, {} failed{}\n",
                    f.name, f.reason, p.found, p.failed, flag
                ));
            }
            None => {
                out.push_str(&format!("{:<13} {}\n", f.name, f.reason));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_records_found_and_failure_and_snapshots() {
        let p = PhaseCoverage::new();
        assert_eq!(p.snapshot(), PhaseSnapshot::default());
        p.record_found(5);
        p.record_found(3);
        assert_eq!(
            p.snapshot(),
            PhaseSnapshot {
                found: 8,
                failed: 0,
                degraded: false
            }
        );
        p.record_failure();
        let s = p.snapshot();
        assert_eq!(s.found, 8);
        assert_eq!(s.failed, 1);
        assert!(s.degraded);
        p.reset();
        assert_eq!(p.snapshot(), PhaseSnapshot::default());
    }

    #[test]
    fn report_snapshot_and_any_degraded() {
        let r = CoverageReport::new();
        assert!(!r.snapshot().any_degraded());
        r.ct.record_found(34);
        assert!(!r.snapshot().any_degraded());
        r.subprocessor.record_failure();
        assert!(r.snapshot().any_degraded());
        r.reset();
        assert!(!r.snapshot().any_degraded());
    }

    #[test]
    fn feature_status_dns_only_forces_disabled() {
        let f = feature_status("subprocessor", true, true, false, true, "--enable-x");
        assert!(!f.enabled);
        assert!(f.reason.contains("dns-only"));
    }

    #[test]
    fn feature_status_enable_flag_wins() {
        let f = feature_status(
            "ct-logs",
            false,
            true,
            false,
            false,
            "--enable-ct-discovery",
        );
        assert!(f.enabled);
        assert_eq!(f.reason, "enabled via --enable-ct-discovery");
    }

    #[test]
    fn feature_status_disable_flag() {
        let f = feature_status("web-org", false, false, true, true, "--enable-web-org");
        assert!(!f.enabled);
        assert_eq!(f.reason, "disabled via flag");
    }

    #[test]
    fn feature_status_on_by_default() {
        let f = feature_status("subprocessor", false, false, false, true, "--enable-x");
        assert!(f.enabled);
        assert_eq!(f.reason, "on by default");
    }

    #[test]
    fn feature_status_off_by_default_suggests_flag() {
        // The CT case: default-off, no flag → disabled, but the manifest tells you how to enable it.
        let f = feature_status(
            "ct-logs",
            false,
            false,
            false,
            false,
            "--enable-ct-discovery",
        );
        assert!(!f.enabled);
        assert_eq!(
            f.reason,
            "disabled (default — enable with --enable-ct-discovery)"
        );
    }

    #[test]
    fn degradation_summary_is_none_when_clean() {
        assert_eq!(
            degradation_summary(&CoverageSnapshot::default(), 0, 0),
            None
        );
    }

    #[test]
    fn degradation_summary_prefers_starvation_wording_for_subprocessor() {
        let mut snap = CoverageSnapshot::default();
        snap.subprocessor.degraded = true;
        snap.subprocessor.failed = 4;
        // With starvation present, the wording names the starved vendor count, not the failure count.
        let s = degradation_summary(&snap, 12, 0).unwrap();
        assert!(s.contains("subprocessor starved on 12 vendor(s)"));
        assert!(!s.contains("failed on 4"));
    }

    #[test]
    fn degradation_summary_reports_each_degraded_phase_and_dns() {
        let mut snap = CoverageSnapshot::default();
        snap.webtraffic.degraded = true;
        snap.webtraffic.failed = 3;
        snap.ct.degraded = true;
        snap.ct.failed = 1;
        let s = degradation_summary(&snap, 0, 16).unwrap();
        assert!(s.contains("web-traffic capture failed on 3 domain(s)"));
        assert!(s.contains("CT-log discovery failed on 1 domain(s)"));
        assert!(s.contains("DNS degraded on 16 lookup(s)"));
    }

    #[test]
    fn render_manifest_shows_reason_counts_and_degraded_flag() {
        let features = vec![
            feature_status("subprocessor", false, false, false, true, "--x"),
            feature_status(
                "ct-logs",
                false,
                false,
                false,
                false,
                "--enable-ct-discovery",
            ),
            feature_status("web-org", false, false, false, true, "--enable-web-org"),
        ];
        let mut snap = CoverageSnapshot::default();
        snap.subprocessor.found = 37;
        snap.subprocessor.failed = 2;
        snap.subprocessor.degraded = true;
        let out = render_manifest(&features, &snap);
        assert!(out.contains("discovery coverage"));
        assert!(out.contains("subprocessor"));
        assert!(out.contains("37 found, 2 failed"));
        assert!(out.contains("⚠ degraded"));
        // CT off-by-default: disabled row with the enable hint, no counts.
        assert!(out.contains("disabled (default — enable with --enable-ct-discovery)"));
        // web-org has no phase counts.
        assert!(out.contains("web-org"));
    }

    #[test]
    fn degradation_summary_subprocessor_failed_without_starvation() {
        // starved == 0 but the phase errored → the failure-count wording, not the starvation wording.
        let mut snap = CoverageSnapshot::default();
        snap.subprocessor.degraded = true;
        snap.subprocessor.failed = 2;
        let s = degradation_summary(&snap, 0, 0).unwrap();
        assert!(s.contains("subprocessor failed on 2 domain(s)"));
        assert!(!s.contains("starved"));
    }

    #[test]
    fn render_manifest_covers_every_phase_mapping_and_enabled_nondegraded_row() {
        // Exercises the enabled + non-degraded counts row (no ⚠) and every feature→phase mapping.
        let features = vec![
            feature_status("subprocessor", false, false, false, true, "--a"),
            feature_status("subdomain", false, false, false, true, "--b"),
            feature_status("saas-tenant", false, false, false, true, "--c"),
            feature_status(
                "ct-logs",
                false,
                true,
                false,
                false,
                "--enable-ct-discovery",
            ),
            feature_status("web-traffic", false, false, false, true, "--d"),
            feature_status("web-org", false, false, false, true, "--e"),
        ];
        let mut snap = CoverageSnapshot::default();
        snap.subprocessor.found = 37;
        snap.subfinder.found = 70; // subdomain feature maps to the subfinder phase
        snap.saas.found = 14;
        snap.ct.found = 34;
        snap.webtraffic.found = 13;
        let out = render_manifest(&features, &snap);
        assert!(out.contains("subprocessor") && out.contains("37 found, 0 failed"));
        assert!(out.contains("saas-tenant") && out.contains("14 found, 0 failed"));
        assert!(out.contains("web-traffic") && out.contains("13 found, 0 failed"));
        assert!(out.contains("ct-logs")); // enabled via flag → shows a phase counts row
        assert!(!out.contains("⚠ degraded"));
    }
}
