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
use std::sync::{Mutex, PoisonError};

/// Who is responsible for a discovery phase not returning full results for one unit of work.
///
/// The two `Target*` origins are NOT failures: they state, with recorded evidence, that the scan
/// target itself either has nothing to find (`TargetNoop`) or capped coverage itself
/// (`TargetLimited`). Only `Upstream`/`Tool`/`Policy` mark the phase degraded — those are the
/// classes a fix, a re-run, or a budget change on OUR side could improve. Ambiguity never lands in
/// a `Target*` class: the conservative default is the failure side, so target attribution always
/// rests on evidence the sidecar records (the anti-laundering invariant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// The target has nothing to find here, and every probe that establishes that answered
    /// definitively (completeness is part of the evidence, never assumed).
    TargetNoop,
    /// The target exists but limited coverage itself — refused connections, blocked or throttled
    /// the scan, served errors — while the scan's own transport was demonstrably healthy.
    TargetLimited,
    /// An intermediary the scan depends on failed: subfinder's passive sources, a DoH provider,
    /// the CT-log API, WHOIS.
    Upstream,
    /// nthpartyfinder itself or its local environment: browser crash/panic, subprocess spawn
    /// failure, a missing binary.
    Tool,
    /// A designed budget or ceiling stopped genuine work early.
    Policy,
}

impl Origin {
    /// The snake_case code used in log lines (matches the serde rename), so a grep over the log
    /// and a jq over the sidecar see the same vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::TargetNoop => "target_noop",
            Origin::TargetLimited => "target_limited",
            Origin::Upstream => "upstream",
            Origin::Tool => "tool",
            Origin::Policy => "policy",
        }
    }
}

/// Which remote party a phase's failed operation was talking to, for `classify_fetch_error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteParty {
    /// The scan target's own infrastructure (its web site, its trust center).
    Target,
    /// An intermediary service (crt.sh, a DoH provider, subfinder's sources, WHOIS).
    Intermediary,
}

/// Best-effort origin classification of a discovery-phase error chain.
///
/// Conservative by construction (the anti-laundering invariant): only evidence in which the remote
/// demonstrably ANSWERED — a TCP reset/refusal, an HTTP error status — may classify a `Target`
/// remote as `TargetLimited`; silence (timeouts) and anything unrecognized stay on the failure
/// side. For `Intermediary` remotes there is no laundering risk (both candidate classes are
/// failures), so transport-shaped errors attribute to the intermediary.
pub fn classify_fetch_error(e: &anyhow::Error, remote: RemoteParty) -> (Origin, &'static str) {
    let mut saw_timeout = false;
    let mut saw_connect = false;
    let mut saw_status = false;
    for cause in e.chain() {
        if let Some(re) = cause.downcast_ref::<reqwest::Error>() {
            saw_timeout |= re.is_timeout();
            saw_connect |= re.is_connect();
            saw_status |= re.is_status();
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            match io.kind() {
                std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted => {
                    // The remote host itself answered (refused/reset the connection): that is the
                    // remote speaking, not this machine's link failing.
                    return match remote {
                        RemoteParty::Target => (Origin::TargetLimited, "connect_refused"),
                        RemoteParty::Intermediary => (Origin::Upstream, "provider_refused"),
                    };
                }
                std::io::ErrorKind::TimedOut => saw_timeout = true,
                _ => {}
            }
        }
    }
    if saw_status {
        return match remote {
            RemoteParty::Target => (Origin::TargetLimited, "http_error_status"),
            RemoteParty::Intermediary => (Origin::Upstream, "provider_error_status"),
        };
    }
    if saw_timeout {
        return match remote {
            // Silence is not target evidence: without a differential health signal this stays on
            // the failure side rather than being laundered into "the target was just slow".
            RemoteParty::Target => (Origin::Tool, "unattributed_timeout"),
            RemoteParty::Intermediary => (Origin::Upstream, "provider_timeout"),
        };
    }
    if saw_connect {
        return match remote {
            RemoteParty::Target => (Origin::Tool, "connect_failed"),
            RemoteParty::Intermediary => (Origin::Upstream, "provider_unreachable"),
        };
    }
    match remote {
        RemoteParty::Target => (Origin::Tool, "unclassified"),
        RemoteParty::Intermediary => (Origin::Upstream, "provider_error"),
    }
}

/// Per-origin event counts for one phase. `Copy` so `PhaseSnapshot` stays cheap to pass around.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct OriginCounts {
    pub target_noop: u64,
    pub target_limited: u64,
    pub upstream: u64,
    pub tool: u64,
    pub policy: u64,
}

/// One recorded attribution event: which domain, whose fault, the machine-readable reason code,
/// and optional human detail. Samples are bounded (`SAMPLE_CAP`); the counters stay exact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AttributionSample {
    pub domain: String,
    pub origin: Origin,
    pub reason: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// Cap on retained per-phase attribution samples. Counts above the cap are still exact; only the
/// per-event evidence list stops growing, so a pathological scan cannot balloon the sidecar.
const SAMPLE_CAP: usize = 50;

/// One discovery phase's observed coverage across the whole scan (summed over every depth).
#[derive(Debug, Default)]
pub struct PhaseCoverage {
    found: AtomicU64,
    failed: AtomicU64,
    degraded: AtomicBool,
    target_noop: AtomicU64,
    target_limited: AtomicU64,
    upstream: AtomicU64,
    tool: AtomicU64,
    policy: AtomicU64,
    samples: Mutex<Vec<AttributionSample>>,
}

impl PhaseCoverage {
    const fn new() -> Self {
        Self {
            found: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            degraded: AtomicBool::new(false),
            target_noop: AtomicU64::new(0),
            target_limited: AtomicU64::new(0),
            upstream: AtomicU64::new(0),
            tool: AtomicU64::new(0),
            policy: AtomicU64::new(0),
            samples: Mutex::new(Vec::new()),
        }
    }

    /// Record a successful phase run that yielded `n` vendor domains.
    pub fn record_found(&self, n: usize) {
        self.found.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Record one attributed outcome for one unit of work. `Upstream`/`Tool`/`Policy` count as
    /// failures and mark the phase degraded — the phase did not return what it should have and the
    /// cause is on our side of the line. `TargetNoop`/`TargetLimited` count separately and do NOT
    /// degrade the phase: the target itself had nothing to find or capped coverage itself, which is
    /// a property of the target, not of this scan.
    pub fn record_attributed(&self, origin: Origin, domain: &str, reason: &str) {
        self.record_attributed_detail(origin, domain, reason, String::new());
    }

    /// `record_attributed` with human-readable evidence detail carried into the sample.
    pub fn record_attributed_detail(
        &self,
        origin: Origin,
        domain: &str,
        reason: &str,
        detail: String,
    ) {
        match origin {
            Origin::TargetNoop => {
                self.target_noop.fetch_add(1, Ordering::Relaxed);
            }
            Origin::TargetLimited => {
                self.target_limited.fetch_add(1, Ordering::Relaxed);
            }
            Origin::Upstream => {
                self.upstream.fetch_add(1, Ordering::Relaxed);
                self.failed.fetch_add(1, Ordering::Relaxed);
                self.degraded.store(true, Ordering::Relaxed);
            }
            Origin::Tool => {
                self.tool.fetch_add(1, Ordering::Relaxed);
                self.failed.fetch_add(1, Ordering::Relaxed);
                self.degraded.store(true, Ordering::Relaxed);
            }
            Origin::Policy => {
                self.policy.fetch_add(1, Ordering::Relaxed);
                self.failed.fetch_add(1, Ordering::Relaxed);
                self.degraded.store(true, Ordering::Relaxed);
            }
        }
        let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        if samples.len() < SAMPLE_CAP {
            samples.push(AttributionSample {
                domain: domain.to_string(),
                origin,
                reason: reason.to_string(),
                detail,
            });
        }
    }

    fn snapshot(&self) -> PhaseSnapshot {
        PhaseSnapshot {
            found: self.found.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            degraded: self.degraded.load(Ordering::Relaxed),
            origins: OriginCounts {
                target_noop: self.target_noop.load(Ordering::Relaxed),
                target_limited: self.target_limited.load(Ordering::Relaxed),
                upstream: self.upstream.load(Ordering::Relaxed),
                tool: self.tool.load(Ordering::Relaxed),
                policy: self.policy.load(Ordering::Relaxed),
            },
        }
    }

    /// The retained attribution samples (bounded by `SAMPLE_CAP`).
    pub fn samples(&self) -> Vec<AttributionSample> {
        self.samples
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Zero the counters. Test-support only; a scan never resets mid-flight.
    #[cfg(test)]
    pub fn reset(&self) {
        self.found.store(0, Ordering::Relaxed);
        self.failed.store(0, Ordering::Relaxed);
        self.degraded.store(false, Ordering::Relaxed);
        self.target_noop.store(0, Ordering::Relaxed);
        self.target_limited.store(0, Ordering::Relaxed);
        self.upstream.store(0, Ordering::Relaxed);
        self.tool.store(0, Ordering::Relaxed);
        self.policy.store(0, Ordering::Relaxed);
        self.samples
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
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

    /// Every phase's retained attribution samples, for the sidecar's evidence section.
    pub fn samples_snapshot(&self) -> CoverageSamples {
        CoverageSamples {
            subprocessor: self.subprocessor.samples(),
            subfinder: self.subfinder.samples(),
            saas: self.saas.samples(),
            ct: self.ct.samples(),
            webtraffic: self.webtraffic.samples(),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct PhaseSnapshot {
    pub found: u64,
    pub failed: u64,
    pub degraded: bool,
    /// Per-origin decomposition: `upstream + tool + policy == failed`; the `target_*` counts sit
    /// outside `failed` because a target-attributed outcome is not a failure of this scan.
    pub origins: OriginCounts,
}

/// Every phase's retained attribution samples at reporting time.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct CoverageSamples {
    pub subprocessor: Vec<AttributionSample>,
    pub subfinder: Vec<AttributionSample>,
    pub saas: Vec<AttributionSample>,
    pub ct: Vec<AttributionSample>,
    pub webtraffic: Vec<AttributionSample>,
}

/// Every phase's counts at reporting time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
/// clean. `subproc_starved` is `perf::METRICS.subproc_zero_yield` (vendors whose subprocessor work
/// overran the per-vendor time budget having found NOTHING — a silent recall loss the phase's own
/// return value hides; a budget stop *after* a source was found is normal early exit, not
/// starvation). `dns_failures` is the classified DNS failure count and `dns_name_failures` the
/// subset caused by the queried name's own authoritative servers rather than by this machine's link.
pub fn degradation_summary(
    snap: &CoverageSnapshot,
    subproc_starved: u64,
    dns_failures: u64,
    dns_name_failures: u64,
) -> Option<String> {
    let mut parts = Vec::new();
    if subproc_starved > 0 {
        parts.push(format!(
            "subprocessor starved on {subproc_starved} vendor(s)"
        ));
    } else if snap.subprocessor.degraded {
        parts.push(format!(
            "subprocessor failed on {} domain(s){}",
            snap.subprocessor.failed,
            origin_suffix(&snap.subprocessor.origins)
        ));
    }
    if snap.webtraffic.degraded {
        parts.push(format!(
            "web-traffic capture failed on {} domain(s){}",
            snap.webtraffic.failed,
            origin_suffix(&snap.webtraffic.origins)
        ));
    }
    if snap.subfinder.degraded {
        parts.push(format!(
            "subdomain discovery failed on {} domain(s){}",
            snap.subfinder.failed,
            origin_suffix(&snap.subfinder.origins)
        ));
    }
    if snap.saas.degraded {
        parts.push(format!(
            "SaaS-tenant discovery failed on {} domain(s){}",
            snap.saas.failed,
            origin_suffix(&snap.saas.origins)
        ));
    }
    if snap.ct.degraded {
        parts.push(format!(
            "CT-log discovery failed on {} domain(s){}",
            snap.ct.failed,
            origin_suffix(&snap.ct.origins)
        ));
    }
    // Split by who is actually at fault. A name that answers SERVFAIL/REFUSED from its own
    // authoritative servers fails identically on every resolver and on a perfect link — reporting
    // it under the same "re-run on a stable network" advice as a real transport problem is a
    // warning whose remedy cannot work, and it drowns the transport failures that the advice does
    // fit. (Observed 2026-07-31: klaviyo.com's `buywithprime.klaviyo.com` delegation SERVFAILs from
    // 1.1.1.1 and 8.8.8.8 alike, and produced 29 "DNS degraded" lookups on an otherwise clean scan.)
    let transport_failures = dns_failures.saturating_sub(dns_name_failures);
    if transport_failures > 0 {
        parts.push(format!("DNS degraded on {transport_failures} lookup(s)"));
    }
    if dns_name_failures > 0 {
        parts.push(format!(
            "{dns_name_failures} name(s) failed at their own authoritative DNS (not a local network fault)"
        ));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

/// The bracketed per-origin decomposition appended to a degraded phase's sentence, e.g.
/// `" [tool 2, upstream 1]"`. Empty when the phase recorded no decomposable failures (a phase
/// degraded through a legacy path with zero origin counts stays readable rather than showing an
/// empty bracket). Only the failure origins appear here — `target_*` outcomes are not failures and
/// render through `target_outcomes_summary` instead.
fn origin_suffix(o: &OriginCounts) -> String {
    let mut sub = Vec::new();
    if o.tool > 0 {
        sub.push(format!("tool {}", o.tool));
    }
    if o.upstream > 0 {
        sub.push(format!("upstream {}", o.upstream));
    }
    if o.policy > 0 {
        sub.push(format!("budget/policy {}", o.policy));
    }
    if sub.is_empty() {
        String::new()
    } else {
        format!(" [{}]", sub.join(", "))
    }
}

/// The target-side story — outcomes that are NOT failures of this scan. `None` when no
/// target-attributed events were recorded. Rendered under SUCCESS too: a verified no-op is a
/// result ("this vendor publishes no subprocessor disclosure"), not an absence of one, and hiding
/// it is exactly the ambiguity that makes an honest empty result read like a silent failure.
pub fn target_outcomes_summary(snap: &CoverageSnapshot) -> Option<String> {
    let phases: [(&str, &PhaseSnapshot); 5] = [
        ("subprocessor", &snap.subprocessor),
        ("web-traffic", &snap.webtraffic),
        ("subdomain discovery", &snap.subfinder),
        ("SaaS-tenant discovery", &snap.saas),
        ("CT-log discovery", &snap.ct),
    ];
    let mut parts = Vec::new();
    for (name, p) in phases {
        let mut sub = Vec::new();
        if p.origins.target_noop > 0 {
            sub.push(format!("{} verified no-op(s)", p.origins.target_noop));
        }
        if p.origins.target_limited > 0 {
            sub.push(format!("{} target-limited", p.origins.target_limited));
        }
        if !sub.is_empty() {
            parts.push(format!("{name}: {}", sub.join(", ")));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!(
            "Target-side outcomes (not failures — the target itself had nothing to find, or capped \
             coverage itself): {}.",
            parts.join("; ")
        ))
    }
}

/// The closing sentence of the DEGRADED banner: what, if anything, the reader should actually do.
///
/// "Re-run on a stable network" is only advice when something on the path to a resolver failed. A
/// scan degraded solely by a target's own broken authoritative DNS, or by a per-vendor time budget,
/// reproduces identically on a perfect link — telling that reader to change networks sends them
/// after a fault that is not theirs and teaches them to discount the banner when it is real.
pub fn degradation_advice(dns_failures: u64, dns_name_failures: u64) -> &'static str {
    if dns_failures > dns_name_failures {
        " Results may undercount; see the discovery-coverage section above and re-run on a stable \
         network for full recall."
    } else {
        " Results may undercount; see the discovery-coverage section above."
    }
}

/// The scan's final verdict — decision AND wording — single-sourced so the colored console path,
/// the plain console path, the `--log-file` mirror, and the persisted `scan-summary.json` can
/// never disagree about how the scan ended.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Verdict {
    /// `SUCCESS` | `DEGRADED` | `WARNING`.
    pub kind: String,
    /// The full plain sentence that follows the `KIND:` label on the console.
    pub detail: String,
    /// Follow-up guidance sentence; empty for `SUCCESS`.
    pub advice: String,
}

/// Decide the scan verdict. Extracted verbatim from the branch logic that used to live three times in
/// `logger::print_final_summary` (colored, plain, file mirror); every string here is byte-for-byte
/// the pre-refactor console wording, pinned by tests in `logger`.
///
/// `degradation` is `degradation_summary(..)`'s output for this scan (`None` = ran clean).
/// Precedence mirrors the original: WARNING (DNS failed and nothing was found) over DEGRADED
/// (something completed but coverage suffered) over SUCCESS.
pub fn verdict(
    total_relationships: usize,
    dns_failures: u64,
    dns_name_failures: u64,
    degradation: Option<&str>,
) -> Verdict {
    if dns_failures > 0 && total_relationships == 0 {
        let advice = if dns_name_failures >= dns_failures {
            "Every failure was the queried name's own authoritative DNS answering SERVFAIL/REFUSED — the fault is in that domain's DNS, not on this network, and retrying will not change it."
        } else {
            "This likely means DNS queries were blocked or failed. Retry with a different network or DNS provider."
        };
        Verdict {
            kind: "WARNING".to_string(),
            detail: format!(
                "Results may be unreliable — {dns_failures} DNS resolution failure(s) occurred and no vendors were found."
            ),
            advice: advice.to_string(),
        }
    } else if let Some(detail) = degradation {
        Verdict {
            kind: "DEGRADED".to_string(),
            detail: format!(
                "Completed with {total_relationships} vendor relationships, but coverage was DEGRADED — {detail}."
            ),
            // `degradation_advice` returns a leading space (it was appended directly after the
            // detail's period); trim it here — renderers re-insert the single joining space.
            advice: degradation_advice(dns_failures, dns_name_failures)
                .trim_start()
                .to_string(),
        }
    } else if total_relationships > 0 {
        Verdict {
            kind: "SUCCESS".to_string(),
            detail: format!(
                "Analysis completed successfully! Found {total_relationships} vendor relationships."
            ),
            advice: String::new(),
        }
    } else {
        Verdict {
            kind: "SUCCESS".to_string(),
            detail: "Analysis completed. No vendor relationships found.".to_string(),
            advice: String::new(),
        }
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
                let noop = if p.origins.target_noop > 0 {
                    format!(", {} no-op", p.origins.target_noop)
                } else {
                    String::new()
                };
                let limited = if p.origins.target_limited > 0 {
                    format!(", {} target-limited", p.origins.target_limited)
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "{:<13} {} — {} found, {} failed{}{}{}\n",
                    f.name, f.reason, p.found, p.failed, noop, limited, flag
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
                degraded: false,
                origins: OriginCounts::default()
            }
        );
        p.record_attributed(Origin::Tool, "x.example", "browser_crash");
        let s = p.snapshot();
        assert_eq!(s.found, 8);
        assert_eq!(s.failed, 1);
        assert!(s.degraded);
        assert_eq!(s.origins.tool, 1);
        p.reset();
        assert_eq!(p.snapshot(), PhaseSnapshot::default());
        assert!(p.samples().is_empty());
    }

    #[test]
    fn report_snapshot_and_any_degraded() {
        let r = CoverageReport::new();
        assert!(!r.snapshot().any_degraded());
        r.ct.record_found(34);
        assert!(!r.snapshot().any_degraded());
        r.subprocessor
            .record_attributed(Origin::Tool, "x.example", "browser_crash");
        assert!(r.snapshot().any_degraded());
        r.reset();
        assert!(!r.snapshot().any_degraded());
    }

    #[test]
    fn target_attribution_is_not_a_failure_and_never_degrades() {
        // The whole point of the taxonomy: a target-attributed outcome must not trip the
        // degradation machinery — it is a property of the target, not of this scan. If either
        // Target* variant set `degraded` or counted into `failed`, every verified no-op would
        // resurrect the exact false "DEGRADED" verdict this layer exists to kill.
        let p = PhaseCoverage::new();
        p.record_attributed(Origin::TargetNoop, "empty.example", "no_disclosure_found");
        p.record_attributed(Origin::TargetLimited, "blocked.example", "connect_refused");
        let s = p.snapshot();
        assert_eq!(s.failed, 0);
        assert!(!s.degraded);
        assert_eq!(s.origins.target_noop, 1);
        assert_eq!(s.origins.target_limited, 1);
        // And the failure origins each count into `failed` + degrade.
        p.record_attributed(Origin::Upstream, "u.example", "provider_throttled");
        p.record_attributed(Origin::Policy, "p.example", "budget_exhausted");
        let s = p.snapshot();
        assert_eq!(s.failed, 2);
        assert!(s.degraded);
        assert_eq!(
            s.origins.upstream + s.origins.tool + s.origins.policy,
            s.failed
        );
        p.reset();
    }

    #[test]
    fn attribution_samples_are_capped_but_counts_stay_exact() {
        let p = PhaseCoverage::new();
        for i in 0..(SAMPLE_CAP + 10) {
            p.record_attributed(Origin::Tool, &format!("d{i}.example"), "browser_crash");
        }
        assert_eq!(p.samples().len(), SAMPLE_CAP);
        assert_eq!(p.snapshot().origins.tool, (SAMPLE_CAP + 10) as u64);
        p.reset();
    }

    #[test]
    fn attribution_sample_carries_detail_and_serializes_snake_case() {
        let p = PhaseCoverage::new();
        p.record_attributed_detail(
            Origin::TargetNoop,
            "empty.example",
            "no_disclosure_found",
            "25 candidates, all definitive misses".to_string(),
        );
        let s = p.samples();
        assert_eq!(s.len(), 1);
        let json = serde_json::to_string(&s[0]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["origin"], "target_noop");
        assert_eq!(v["reason"], "no_disclosure_found");
        assert!(v["detail"].as_str().unwrap().contains("25 candidates"));
        p.reset();
    }

    #[test]
    fn degradation_summary_decomposes_failures_by_origin() {
        let mut snap = CoverageSnapshot::default();
        snap.webtraffic.degraded = true;
        snap.webtraffic.failed = 3;
        snap.webtraffic.origins.tool = 2;
        snap.webtraffic.origins.upstream = 1;
        let s = degradation_summary(&snap, 0, 0, 0).unwrap();
        assert!(
            s.contains("web-traffic capture failed on 3 domain(s) [tool 2, upstream 1]"),
            "{s}"
        );
        // A legacy-shaped snapshot with zero origin counts renders without an empty bracket.
        let mut legacy = CoverageSnapshot::default();
        legacy.ct.degraded = true;
        legacy.ct.failed = 1;
        let s = degradation_summary(&legacy, 0, 0, 0).unwrap();
        assert!(s.contains("CT-log discovery failed on 1 domain(s)"), "{s}");
        assert!(!s.contains('['), "{s}");
    }

    #[test]
    fn target_outcomes_summary_renders_noops_and_limited_or_none() {
        assert_eq!(target_outcomes_summary(&CoverageSnapshot::default()), None);
        let mut snap = CoverageSnapshot::default();
        snap.subprocessor.origins.target_noop = 12;
        snap.webtraffic.origins.target_limited = 3;
        let s = target_outcomes_summary(&snap).unwrap();
        assert!(s.contains("not failures"), "{s}");
        assert!(s.contains("subprocessor: 12 verified no-op(s)"), "{s}");
        assert!(s.contains("web-traffic: 3 target-limited"), "{s}");
        // Target outcomes alone must never produce a degradation summary (→ verdict stays SUCCESS).
        assert_eq!(degradation_summary(&snap, 0, 0, 0), None);
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
    fn the_closing_advice_only_blames_the_network_when_the_network_actually_failed() {
        // Some failures were transport-side: retrying elsewhere genuinely can help.
        assert!(degradation_advice(20, 6).contains("re-run on a stable network"));
        assert!(degradation_advice(16, 0).contains("re-run on a stable network"));

        // Every failure was the target's own authoritative DNS — a different network resolves it
        // exactly the same way, so the advice would send the reader after a fault that is not
        // theirs (optro.com, 2026-07-31: 154 name failures, zero transport failures).
        assert!(!degradation_advice(154, 154).contains("stable network"));

        // Degraded with no DNS failures at all (e.g. a starved subprocessor budget) — likewise
        // nothing about the network to act on.
        assert!(!degradation_advice(0, 0).contains("stable network"));

        // Whatever the case, the reader is always pointed at the manifest that explains it.
        for (a, b) in [(20, 6), (16, 0), (154, 154), (0, 0)] {
            assert!(degradation_advice(a, b).contains("discovery-coverage section"));
        }
    }

    #[test]
    fn dns_summary_separates_a_broken_target_zone_from_a_broken_local_link() {
        let snap = CoverageSnapshot::default();

        // The reported case: every DNS failure was the queried name answering SERVFAIL from its own
        // authority (klaviyo.com's `buywithprime` delegation). Blaming the local link here sends the
        // reader chasing a network problem that does not exist.
        let name_only = degradation_summary(&snap, 0, 29, 29).unwrap();
        assert!(
            name_only.contains("29 name(s) failed at their own authoritative DNS"),
            "name failures must be named as such: {name_only}"
        );
        assert!(
            !name_only.contains("DNS degraded on"),
            "no transport failures occurred, so nothing may be reported as a degraded link: \
             {name_only}"
        );

        // A genuine transport problem still reads exactly as before.
        let transport_only = degradation_summary(&snap, 0, 16, 0).unwrap();
        assert!(transport_only.contains("DNS degraded on 16 lookup(s)"));
        assert!(!transport_only.contains("authoritative DNS"));

        // Mixed: the transport count is the remainder, so the two never double-count.
        let mixed = degradation_summary(&snap, 0, 20, 6).unwrap();
        assert!(mixed.contains("DNS degraded on 14 lookup(s)"), "{mixed}");
        assert!(
            mixed.contains("6 name(s) failed at their own authoritative DNS"),
            "{mixed}"
        );
    }

    #[test]
    fn degradation_summary_is_none_when_clean() {
        assert_eq!(
            degradation_summary(&CoverageSnapshot::default(), 0, 0, 0),
            None
        );
    }

    #[test]
    fn degradation_summary_prefers_starvation_wording_for_subprocessor() {
        let mut snap = CoverageSnapshot::default();
        snap.subprocessor.degraded = true;
        snap.subprocessor.failed = 4;
        // With starvation present, the wording names the starved vendor count, not the failure count.
        let s = degradation_summary(&snap, 12, 0, 0).unwrap();
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
        let s = degradation_summary(&snap, 0, 16, 0).unwrap();
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
        let s = degradation_summary(&snap, 0, 0, 0).unwrap();
        assert!(s.contains("subprocessor failed on 2 domain(s)"));
        assert!(!s.contains("starved"));
    }

    #[test]
    fn verdict_warning_when_dns_failed_and_nothing_found() {
        // Transport failures present → the retry-elsewhere advice.
        let v = verdict(0, 5, 1, Some("DNS degraded on 4 lookup(s)"));
        assert_eq!(v.kind, "WARNING");
        assert_eq!(
            v.detail,
            "Results may be unreliable — 5 DNS resolution failure(s) occurred and no vendors were found."
        );
        assert_eq!(
            v.advice,
            "This likely means DNS queries were blocked or failed. Retry with a different network or DNS provider."
        );
        // Every failure was the name's own authority → the don't-blame-the-network advice.
        let v = verdict(0, 5, 5, Some("x"));
        assert_eq!(v.kind, "WARNING");
        assert!(v.advice.contains("own authoritative DNS"));
        assert!(!v.advice.contains("Retry with a different network"));
    }

    #[test]
    fn verdict_degraded_wraps_detail_and_trims_advice() {
        let v = verdict(42, 0, 0, Some("subprocessor failed on 2 domain(s)"));
        assert_eq!(v.kind, "DEGRADED");
        assert_eq!(
            v.detail,
            "Completed with 42 vendor relationships, but coverage was DEGRADED — subprocessor failed on 2 domain(s)."
        );
        // Trimmed of `degradation_advice`'s leading space; renderers re-insert the join space.
        assert_eq!(
            v.advice,
            "Results may undercount; see the discovery-coverage section above."
        );
        assert!(!v.advice.starts_with(' '));
        // With transport failures, the advice adds the stable-network clause.
        let v = verdict(42, 6, 1, Some("DNS degraded on 5 lookup(s)"));
        assert_eq!(
            v.advice,
            "Results may undercount; see the discovery-coverage section above and re-run on a stable network for full recall."
        );
    }

    #[test]
    fn verdict_success_with_and_without_relationships() {
        let v = verdict(17, 0, 0, None);
        assert_eq!(v.kind, "SUCCESS");
        assert_eq!(
            v.detail,
            "Analysis completed successfully! Found 17 vendor relationships."
        );
        assert_eq!(v.advice, "");
        let v = verdict(0, 0, 0, None);
        assert_eq!(v.kind, "SUCCESS");
        assert_eq!(
            v.detail,
            "Analysis completed. No vendor relationships found."
        );
        assert_eq!(v.advice, "");
    }

    #[test]
    fn verdict_precedence_warning_beats_degraded_beats_success() {
        // DNS failures + zero relationships wins over a degradation detail.
        assert_eq!(verdict(0, 3, 0, Some("deg")).kind, "WARNING");
        // Relationships present demote the same inputs to DEGRADED.
        assert_eq!(verdict(1, 3, 0, Some("deg")).kind, "DEGRADED");
        // DNS failures with relationships and no degradation summary → SUCCESS. (Unreachable in
        // practice — dns_failures>0 makes degradation_summary Some — but the precedence must not
        // invent a warning the console never printed.)
        assert_eq!(verdict(1, 0, 0, None).kind, "SUCCESS");
    }

    #[test]
    fn verdict_serializes_for_the_sidecar() {
        let v = verdict(42, 0, 0, Some("subprocessor failed on 2 domain(s)"));
        let json = serde_json::to_string(&v).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["kind"], "DEGRADED");
        assert!(parsed["detail"].as_str().unwrap().contains("42"));
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
