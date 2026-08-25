//! Persisted scan-summary sidecar (`scan-summary.json`) — Phase 0 of the DNS attribution plan.
//!
//! Every scan writes a machine-readable summary of what happened — args, the ANALYSIS SUMMARY
//! numbers, the full DNS story (failure counts, governor state, provider telemetry), per-phase
//! discovery coverage, all perf counters, HTTP ceiling state, and the same verdict the console
//! prints — **unconditionally** (not `-v`-gated, not `--log-file`-gated) to
//! `<output_dir>/reports/<domain>/scan-summary.json`.
//!
//! While the scan runs, the existing 5 s sampler task rewrites `scan-summary.partial.json`
//! (atomic temp+rename, same pattern as `Checkpoint::save`) so a Ctrl-C/SIGKILL/timeout/panic
//! still leaves a record. The partial is deleted once the final write succeeds.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

/// Bump when a field is renamed/removed or its meaning changes; additive fields do not require it.
///
/// v2 (2026-08-25, failure-vs-no-op attribution): `coverage.phases.*.failed` narrowed its meaning
/// — it now counts only upstream/tool/policy-attributed failures; target-attributed outcomes
/// (verified no-ops, target-limited coverage) moved to the new `origins` counts and are not
/// failures. Additive: `coverage.phases.*.origins`, `coverage.target_outcomes`,
/// `coverage.samples`.
pub const SCHEMA_VERSION: u32 = 2;

const FINAL_FILENAME: &str = "scan-summary.json";
const PARTIAL_FILENAME: &str = "scan-summary.partial.json";

/// The subset of CLI arguments worth persisting for run-to-run comparison. All fields are
/// optional/defaultable so a partially-known context still serializes.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ArgsSummary {
    pub domain: Option<String>,
    pub depth: Option<u32>,
    pub dns_only: bool,
    pub dns_max_concurrency: Option<u32>,
    pub max_connections: Option<usize>,
    pub output_format: String,
    /// Discovery methods explicitly disabled via `--disable-*` flags.
    pub disabled_methods: Vec<String>,
}

impl ArgsSummary {
    /// Extract the persisted subset from the full CLI args.
    pub fn from_args(args: &crate::cli::Args) -> Self {
        let mut disabled_methods = Vec::new();
        for (flag, name) in [
            (args.disable_subprocessor_analysis, "subprocessor"),
            (args.disable_subdomain_discovery, "subdomain"),
            (args.disable_saas_tenant_discovery, "saas-tenant"),
            (args.disable_ct_discovery, "ct-logs"),
            (args.disable_web_traffic_discovery, "web-traffic"),
            (args.disable_web_org, "web-org"),
            (args.disable_slm, "slm"),
        ] {
            if flag {
                disabled_methods.push(name.to_string());
            }
        }
        Self {
            domain: args.domain.clone(),
            depth: args.depth,
            dns_only: args.dns_only,
            dns_max_concurrency: args.dns_max_concurrency,
            max_connections: args.max_connections,
            output_format: args.output_format.clone(),
            disabled_methods,
        }
    }
}

/// Run identity: what binary, when, how long, how it ended.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Meta {
    /// `env!("CARGO_PKG_VERSION")` of the binary that wrote this file.
    pub version: String,
    /// RFC3339 wall-clock scan start.
    pub started_at: Option<String>,
    /// RFC3339 wall-clock write time of the final summary; `None` while `status == "running"`.
    pub ended_at: Option<String>,
    /// Monotonic seconds since scan start at write time.
    pub wall_secs: f64,
    /// One of `running | success | timeout | interrupted | error`.
    pub status: String,
    pub args: ArgsSummary,
}

/// Mirror of the console ANALYSIS SUMMARY block.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AnalysisSummarySection {
    /// `end_time - start_time` when both were recorded (set by `finish_progress`), else `None`
    /// — a partial written mid-scan has no end time yet.
    pub duration_secs: Option<f64>,
    pub domains_processed: usize,
    pub txt_records_found: usize,
    pub vendor_relationships: usize,
    pub unique_vendors: usize,
    pub max_depth: u32,
}

/// The full DNS story: classified failure counts, adaptive-governor state, provider telemetry.
#[derive(Debug, Clone, Serialize)]
pub struct DnsSection {
    /// All classified DNS failures (the exit-3 guard's counter).
    pub failures: u64,
    /// Subset attributable to the queried name's own authoritative servers.
    pub name_failures: u64,
    /// `failures - name_failures` (saturating): failures on this machine's path to a resolver.
    pub transport_failures: u64,
    pub governor: crate::dns_governor::GovernorStats,
    pub telemetry: crate::dns_telemetry::Snapshot,
}

/// Per-phase discovery coverage plus each feature's enabled state and why.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CoverageSection {
    pub features: Vec<crate::coverage::FeatureStatus>,
    pub phases: crate::coverage::CoverageSnapshot,
    pub any_degraded: bool,
    /// `coverage::target_outcomes_summary` for this scan — the target-side outcomes (verified
    /// no-ops, target-limited coverage) that are NOT failures; `None` when none were recorded.
    pub target_outcomes: Option<String>,
    /// Bounded per-phase attribution evidence: which domain, whose fault, what reason code.
    pub samples: crate::coverage::CoverageSamples,
}

/// One perf counter row (`perf::METRICS`), duration flattened to seconds for JSON consumers.
#[derive(Debug, Clone, Serialize)]
pub struct PerfRow {
    pub name: String,
    pub count: u64,
    pub total_secs: f64,
}

/// HTTP-layer ceilings at write time.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct HttpSection {
    pub getaddrinfo_distinct_hosts: usize,
    pub conn_cap: usize,
    pub conn_available_at_close: usize,
}

/// The whole persisted artifact. Field order is the on-disk section order.
#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub schema_version: u32,
    pub meta: Meta,
    pub analysis_summary: AnalysisSummarySection,
    pub dns: DnsSection,
    pub coverage: CoverageSection,
    pub perf: Vec<PerfRow>,
    pub http: HttpSection,
    /// Same decision + strings the console prints (`coverage::verdict`), so stdout and JSON
    /// cannot disagree.
    pub verdict: crate::coverage::Verdict,
}

impl ScanSummary {
    /// Serialize (pretty) and write atomically: `<path>.tmp` + fsync + rename, the same pattern
    /// as `Checkpoint::save`, so an interrupt mid-write can never leave a torn final file.
    pub fn write_atomic(&self, path: &Path) -> std::io::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        let mut tmp_os = path.as_os_str().to_os_string();
        tmp_os.push(".tmp");
        let tmp = PathBuf::from(tmp_os);
        {
            let mut file = std::fs::File::create(&tmp)?;
            std::io::Write::write_all(&mut file, content.as_bytes())?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Compact JSON safe to inline inside a `<script>` element: `</` is emitted as `<\/` so a
    /// detail string containing `</script>` cannot terminate the embedding script block. (`<\/`
    /// is valid JSON — `\/` is an escaped solidus — so `JSON.parse` of the element text is
    /// unaffected.)
    pub fn to_embed_json(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|_| "{}".to_string())
            .replace("</", "<\\/")
    }
}

fn rfc3339(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()
}

/// Everything the collector needs that is fixed for the life of one scan, plus the live handles
/// it samples. Built once in `run_inner` after the DNS pool exists; shared (Arc) with the 5 s
/// sampler task.
pub struct ScanSummaryContext {
    started_at: SystemTime,
    started: Instant,
    args: ArgsSummary,
    features: Vec<crate::coverage::FeatureStatus>,
    logger: crate::logger::AnalysisLogger,
    dns_pool: Arc<crate::dns::DnsServerPool>,
    dir: PathBuf,
    /// Serializes partial writes against finalization and latches once final, so the sampler
    /// can never recreate `scan-summary.partial.json` after the final write deleted it.
    finalized: std::sync::Mutex<bool>,
}

impl ScanSummaryContext {
    pub fn new(
        args: ArgsSummary,
        features: Vec<crate::coverage::FeatureStatus>,
        logger: crate::logger::AnalysisLogger,
        dns_pool: Arc<crate::dns::DnsServerPool>,
        dir: PathBuf,
    ) -> Self {
        Self {
            started_at: SystemTime::now(),
            started: Instant::now(),
            args,
            features,
            logger,
            dns_pool,
            dir,
            finalized: std::sync::Mutex::new(false),
        }
    }

    /// Where the final artifact lands: `<reports dir>/scan-summary.json`.
    pub fn summary_path(&self) -> PathBuf {
        self.dir.join(FINAL_FILENAME)
    }

    /// Where in-flight partials land: `<reports dir>/scan-summary.partial.json`.
    pub fn partial_path(&self) -> PathBuf {
        self.dir.join(PARTIAL_FILENAME)
    }

    /// Read every live source and assemble the artifact with the given status.
    pub fn collect(&self, status: &str) -> ScanSummary {
        let meta_snap = self.logger.analysis_summary_snapshot();
        let failures = self.logger.dns_failure_count() as u64;
        let name_failures = self.logger.dns_name_failure_count() as u64;

        let cov = crate::coverage::SCAN_COVERAGE.snapshot();
        let subproc_starved = crate::perf::METRICS.subproc_zero_yield.snapshot().0;
        let degradation =
            crate::coverage::degradation_summary(&cov, subproc_starved, failures, name_failures);
        let verdict = crate::coverage::verdict(
            meta_snap.vendor_relationships,
            failures,
            name_failures,
            degradation.as_deref(),
        );

        let perf = crate::perf::METRICS
            .snapshot()
            .rows
            .into_iter()
            .map(|r| PerfRow {
                name: r.name.to_string(),
                count: r.count,
                total_secs: r.total.as_secs_f64(),
            })
            .collect();

        let (conn_cap, conn_available_at_close) = crate::http_client::connection_ceiling_state();

        let running = status == "running";
        ScanSummary {
            schema_version: SCHEMA_VERSION,
            meta: Meta {
                version: env!("CARGO_PKG_VERSION").to_string(),
                started_at: Some(rfc3339(self.started_at)),
                ended_at: if running {
                    None
                } else {
                    Some(rfc3339(SystemTime::now()))
                },
                wall_secs: self.started.elapsed().as_secs_f64(),
                status: status.to_string(),
                args: self.args.clone(),
            },
            analysis_summary: AnalysisSummarySection {
                duration_secs: meta_snap.duration_secs,
                domains_processed: meta_snap.domains_processed,
                txt_records_found: meta_snap.txt_records_found,
                vendor_relationships: meta_snap.vendor_relationships,
                unique_vendors: meta_snap.unique_vendors,
                max_depth: meta_snap.max_depth,
            },
            dns: DnsSection {
                failures,
                name_failures,
                transport_failures: failures.saturating_sub(name_failures),
                governor: self.dns_pool.governor_stats(),
                telemetry: crate::dns_telemetry::DNS_TELEMETRY
                    .snapshot(&self.dns_pool.doh_provider_names()),
            },
            coverage: CoverageSection {
                features: self.features.clone(),
                phases: cov,
                any_degraded: cov.any_degraded(),
                target_outcomes: crate::coverage::target_outcomes_summary(&cov),
                samples: crate::coverage::SCAN_COVERAGE.samples_snapshot(),
            },
            perf,
            http: HttpSection {
                getaddrinfo_distinct_hosts: crate::http_client::getaddrinfo_distinct_hosts(),
                conn_cap,
                conn_available_at_close,
            },
            verdict,
        }
    }

    /// Rewrite `scan-summary.partial.json` (status `running`). No-op once finalized — the gate
    /// mutex means a sampler tick can never race the final write into resurrecting the partial.
    pub fn write_partial(&self) -> std::io::Result<()> {
        let guard = self
            .finalized
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *guard {
            return Ok(());
        }
        self.collect("running").write_atomic(&self.partial_path())
    }

    /// Write the final `scan-summary.json` with the given terminal status and delete the
    /// partial. Idempotent-ish: a second call overwrites the first's file (last status wins),
    /// which never happens on the current call sites (each exit path finalizes exactly once).
    pub fn finalize(&self, status: &str) -> std::io::Result<()> {
        let mut guard = self
            .finalized
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = true;
        self.collect(status).write_atomic(&self.summary_path())?;
        // Best-effort: the final artifact exists, so a stale partial is only clutter.
        let _ = std::fs::remove_file(self.partial_path());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fully-populated summary with a hand-built governor (all fields pub) and a real (empty)
    /// telemetry snapshot from the process-wide static — no network, no pool construction.
    fn sample_summary(detail: &str) -> ScanSummary {
        let governor = crate::dns_governor::GovernorStats {
            current_limit: 8,
            max_limit: 24,
            peak_limit: 12,
            min_limit_seen: 4,
            in_flight: 0,
            backoff_events: 2,
            total_queries: 100,
            congestion_signals: 3,
            user_pinned: false,
            timeouts: 1,
            rejections: 2,
            step_ups: 4,
            step_downs: 3,
            holds_app_limited: 5,
            holds_cooldown: 1,
            floor_ms: 0,
            ceiling_ms: 0,
            rtt_recent_us: 1200.0,
            rtt_baseline_us: 900.0,
            rtt_var_us: 300.0,
            in_cooldown: false,
            in_slow_start: true,
        };
        let telemetry = crate::dns_telemetry::DNS_TELEMETRY.snapshot(&[]);
        ScanSummary {
            schema_version: SCHEMA_VERSION,
            meta: Meta {
                version: env!("CARGO_PKG_VERSION").to_string(),
                started_at: Some("2026-08-19T00:00:00+00:00".to_string()),
                ended_at: Some("2026-08-19T00:05:00+00:00".to_string()),
                wall_secs: 300.0,
                status: "success".to_string(),
                args: ArgsSummary {
                    domain: Some("example.com".to_string()),
                    depth: Some(2),
                    output_format: "html".to_string(),
                    ..Default::default()
                },
            },
            analysis_summary: AnalysisSummarySection {
                duration_secs: Some(299.5),
                domains_processed: 10,
                txt_records_found: 42,
                vendor_relationships: 37,
                unique_vendors: 20,
                max_depth: 2,
            },
            dns: DnsSection {
                failures: 3,
                name_failures: 1,
                transport_failures: 2,
                governor,
                telemetry,
            },
            coverage: CoverageSection::default(),
            perf: vec![PerfRow {
                name: "report.export".to_string(),
                count: 1,
                total_secs: 0.25,
            }],
            http: HttpSection {
                getaddrinfo_distinct_hosts: 7,
                conn_cap: 64,
                conn_available_at_close: 64,
            },
            verdict: crate::coverage::Verdict {
                kind: "SUCCESS".to_string(),
                detail: detail.to_string(),
                advice: String::new(),
            },
        }
    }

    #[test]
    fn schema_serializes_with_every_section_present() {
        let s = sample_summary("Analysis completed successfully! Found 37 vendor relationships.");
        let json = serde_json::to_string_pretty(&s).expect("summary serializes");
        let v: serde_json::Value = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(v["schema_version"], 2);
        // Every top-level section the schema promises is present.
        for key in [
            "meta",
            "analysis_summary",
            "dns",
            "coverage",
            "perf",
            "http",
            "verdict",
        ] {
            assert!(v.get(key).is_some(), "missing section {key}: {json}");
        }
        assert_eq!(v["meta"]["status"], "success");
        assert_eq!(v["meta"]["args"]["domain"], "example.com");
        assert_eq!(v["dns"]["transport_failures"], 2);
        assert_eq!(v["dns"]["governor"]["current_limit"], 8);
        assert!(v["dns"]["telemetry"]["providers"].is_array());
        assert_eq!(v["perf"][0]["name"], "report.export");
        assert_eq!(v["verdict"]["kind"], "SUCCESS");
    }

    #[test]
    fn write_atomic_writes_valid_json_and_leaves_no_tmp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan-summary.json");
        let s = sample_summary("Analysis completed. No vendor relationships found.");
        s.write_atomic(&path).expect("write_atomic succeeds");

        let content = std::fs::read_to_string(&path).expect("final file readable");
        let v: serde_json::Value = serde_json::from_str(&content).expect("file is valid JSON");
        assert_eq!(v["schema_version"], 2);

        let tmp = dir.path().join("scan-summary.json.tmp");
        assert!(!tmp.exists(), "temp file must be renamed away");
        // Rewrite over an existing file works too (the 5 s partial rewrite path).
        s.write_atomic(&path).expect("second write_atomic succeeds");
        assert!(!tmp.exists());
    }

    #[test]
    fn embed_json_escapes_script_terminators() {
        let s = sample_summary("bad detail with </script><script>alert(1)</script> inside");
        let embed = s.to_embed_json();
        assert!(
            !embed.contains("</"),
            "raw </ must never appear in embeddable JSON: {embed}"
        );
        assert!(embed.contains("<\\/script>"), "escaped form present");
        // The escaping is JSON-transparent: parsing recovers the original detail string.
        let v: serde_json::Value = serde_json::from_str(&embed).expect("embed JSON parses");
        assert_eq!(
            v["verdict"]["detail"],
            "bad detail with </script><script>alert(1)</script> inside"
        );
    }

    #[test]
    fn args_summary_collects_disabled_methods() {
        use clap::Parser;
        let cli = crate::cli::Cli::parse_from([
            "nthpartyfinder",
            "-d",
            "example.com",
            "--disable-ct-discovery",
            "--disable-web-org",
        ]);
        let args = crate::cli::Args::from(&cli);
        let s = ArgsSummary::from_args(&args);
        assert_eq!(s.domain.as_deref(), Some("example.com"));
        assert_eq!(s.disabled_methods, vec!["ct-logs", "web-org"]);
        assert!(!s.dns_only);
    }
}
