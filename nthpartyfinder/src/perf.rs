//! Scan-lifetime performance counters.
//!
//! A depth-3 scan spends its wall clock across DNS, WHOIS, HTTP, NER inference and
//! headless-Chrome renders. Which of those dominates has, historically, been guessed at
//! from profiles and guessed wrong: `sample` attributes wall time to *blocked* threads, so
//! a thread parked in a semaphore looks identical to a thread doing work. These counters
//! measure the terms directly.
//!
//! Everything here is `Relaxed` atomics on the hot path — `dns_query` fires ~10^4 times per
//! scan, which at a few nanoseconds per increment is immaterial against a 600s+ budget. No
//! counter influences control flow; the module is observation only.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// A `(count, total_duration)` pair updated from many threads.
#[derive(Debug, Default)]
pub struct Metric {
    count: AtomicU64,
    nanos: AtomicU64,
}

impl Metric {
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            nanos: AtomicU64::new(0),
        }
    }

    /// Record one occurrence that took `d`.
    pub fn record(&self, d: Duration) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.nanos.fetch_add(
            u64::try_from(d.as_nanos()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Record one occurrence with no meaningful duration (e.g. a cache hit).
    pub fn hit(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Current `(count, total)`.
    pub fn snapshot(&self) -> (u64, Duration) {
        (
            self.count.load(Ordering::Relaxed),
            Duration::from_nanos(self.nanos.load(Ordering::Relaxed)),
        )
    }

    /// Zero the counter. Test-support only; a scan never resets mid-flight.
    pub fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
        self.nanos.store(0, Ordering::Relaxed);
    }
}

/// Every counter the attribution table reports on.
#[derive(Debug)]
pub struct Metrics {
    /// Time inside `Browser::new` — the Chrome process launch itself.
    pub browser_launch: Metric,
    /// Time blocked waiting for a browser-pool permit, before any launch.
    pub browser_permit_wait: Metric,
    /// Chrome processes reused from the pool rather than launched.
    pub browser_reuse: Metric,
    /// `navigate_to` + `wait_until_navigated`.
    pub render_navigate: Metric,
    /// The post-navigation settle wait.
    pub render_settle: Metric,
    /// `get_content`.
    pub render_capture: Metric,
    /// Whole render, permit wait excluded: launch + navigate + settle + capture + teardown.
    pub render_total: Metric,
    /// GLiNER ONNX inference.
    pub ner_infer: Metric,
    /// Outbound HTTP page fetches from the web-org enrichment path.
    pub http_fetch: Metric,
    /// Candidate subprocessor-URL probes. Most 404 — a vendor generates up to 25 guesses.
    /// This is the work the per-vendor time budget is actually spending.
    pub subproc_probe: Metric,
    /// WHOIS lookups (native + system `whois(1)`).
    pub whois_lookup: Metric,
    /// DNS queries that reached the network.
    pub dns_query: Metric,
    /// DNS queries served from the scan-lifetime memo.
    pub dns_memo_hit: Metric,
    /// Vendors whose subprocessor analysis hit its working-time budget.
    pub subproc_budget_exhausted: Metric,
    /// Vendors that hit the budget having found *nothing* — starved, not empty. Any non-zero
    /// value means the scan under-reports, and the aggregate row count will not show it.
    pub subproc_zero_yield: Metric,
    /// Renders attributed to the subprocessor path (per-source split of `render.total`).
    pub render_subproc: Metric,
    /// Renders attributed to the web-org enrichment path.
    pub render_weborg: Metric,
    /// Renders attributed to the web-traffic discovery path.
    pub render_webtraffic: Metric,
    /// Renders attributed to the trust-center discovery path.
    pub render_trustcenter: Metric,
    /// Subprocessor renders that fired the SPA fallback (static HTML looked like a skeleton).
    /// On a warm-cache repeat scan, where every probed URL comes from cache, this equals the
    /// count of renders spent on already-known cached URLs — the quantity B3 measures.
    pub subproc_spa_render: Metric,
}

impl Metrics {
    const fn new() -> Self {
        Self {
            browser_launch: Metric::new(),
            browser_permit_wait: Metric::new(),
            browser_reuse: Metric::new(),
            render_navigate: Metric::new(),
            render_settle: Metric::new(),
            render_capture: Metric::new(),
            render_total: Metric::new(),
            ner_infer: Metric::new(),
            http_fetch: Metric::new(),
            subproc_probe: Metric::new(),
            whois_lookup: Metric::new(),
            dns_query: Metric::new(),
            dns_memo_hit: Metric::new(),
            subproc_budget_exhausted: Metric::new(),
            subproc_zero_yield: Metric::new(),
            render_subproc: Metric::new(),
            render_weborg: Metric::new(),
            render_webtraffic: Metric::new(),
            render_trustcenter: Metric::new(),
            subproc_spa_render: Metric::new(),
        }
    }

    /// Zero every counter. Test-support only.
    pub fn reset(&self) {
        for m in self.all() {
            m.1.reset();
        }
    }

    fn all(&self) -> [(&'static str, &Metric); 20] {
        [
            ("browser.permit_wait", &self.browser_permit_wait),
            ("browser.launch", &self.browser_launch),
            ("browser.reuse", &self.browser_reuse),
            ("render.navigate", &self.render_navigate),
            ("render.settle", &self.render_settle),
            ("render.capture", &self.render_capture),
            ("render.total", &self.render_total),
            ("render.subproc", &self.render_subproc),
            ("render.weborg", &self.render_weborg),
            ("render.webtraffic", &self.render_webtraffic),
            ("render.trustcenter", &self.render_trustcenter),
            ("ner.infer", &self.ner_infer),
            ("http.fetch", &self.http_fetch),
            ("subproc.probe", &self.subproc_probe),
            ("subproc.spa_render", &self.subproc_spa_render),
            ("whois.lookup", &self.whois_lookup),
            ("dns.query", &self.dns_query),
            ("dns.memo_hit", &self.dns_memo_hit),
            ("subproc.budget_exhausted", &self.subproc_budget_exhausted),
            ("subproc.zero_yield", &self.subproc_zero_yield),
        ]
    }

    /// Take a consistent-enough snapshot of every counter for reporting.
    ///
    /// Not atomic across counters: the scan is finished when this runs, so no writer races.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            rows: self
                .all()
                .into_iter()
                .map(|(name, m)| {
                    let (count, total) = m.snapshot();
                    Row { name, count, total }
                })
                .collect(),
        }
    }
}

/// One counter's observed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: &'static str,
    pub count: u64,
    pub total: Duration,
}

/// All counters at one instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub rows: Vec<Row>,
}

impl Snapshot {
    /// Look up one counter by name.
    pub fn get(&self, name: &str) -> Option<&Row> {
        self.rows.iter().find(|r| r.name == name)
    }

    fn total_of(&self, name: &str) -> Duration {
        self.get(name).map(|r| r.total).unwrap_or_default()
    }

    fn count_of(&self, name: &str) -> u64 {
        self.get(name).map(|r| r.count).unwrap_or_default()
    }

    /// Serialized render time divided across the pool — the floor the render path imposes on
    /// the scan's wall clock. If this is a small fraction of `wall`, renders are not the
    /// critical path no matter how many threads are parked in the permit queue.
    pub fn render_critical_path(&self, permits: usize) -> Duration {
        let permits = permits.max(1) as u32;
        self.total_of("render.total") / permits
    }
}

/// The process-wide counters.
pub static METRICS: Metrics = Metrics::new();

fn pct(part: Duration, whole: Duration) -> f64 {
    if whole.is_zero() {
        return 0.0;
    }
    part.as_secs_f64() / whole.as_secs_f64() * 100.0
}

/// Render the attribution table.
///
/// Pure over its inputs so the formatting is testable without touching the global counters.
pub fn format_report(snap: &Snapshot, wall: Duration, permits: usize) -> String {
    let mut out = String::from("── scan performance attribution ──\n");
    out.push_str(&format!(
        "{:<22} {:>8} {:>12} {:>10} {:>8}\n",
        "counter", "count", "total", "mean", "%wall"
    ));

    for row in &snap.rows {
        let mean = if row.count == 0 {
            Duration::ZERO
        } else {
            row.total / u32::try_from(row.count).unwrap_or(u32::MAX)
        };
        out.push_str(&format!(
            "{:<22} {:>8} {:>11.1}s {:>9.3}s {:>7.1}%\n",
            row.name,
            row.count,
            row.total.as_secs_f64(),
            mean.as_secs_f64(),
            pct(row.total, wall),
        ));
    }

    let crit = snap.render_critical_path(permits);
    out.push_str(&format!(
        "\nwall {:.1}s | browser permits {} | render critical path {:.1}s ({:.1}% of wall)\n",
        wall.as_secs_f64(),
        permits,
        crit.as_secs_f64(),
        pct(crit, wall),
    ));

    let render_total = snap.total_of("render.total");
    if !render_total.is_zero() {
        out.push_str(&format!(
            "render breakdown: launch {:.1}% | navigate {:.1}% | settle {:.1}% | capture {:.1}%\n",
            pct(snap.total_of("browser.launch"), render_total),
            pct(snap.total_of("render.navigate"), render_total),
            pct(snap.total_of("render.settle"), render_total),
            pct(snap.total_of("render.capture"), render_total),
        ));

        // Not every render site reports sub-timings: the trust-center and web-traffic paths
        // record only `render.total`. Say so, rather than letting the breakdown read as if it
        // accounted for all of `render.total` — an under-reported settle share would point the
        // next optimization at the wrong term.
        let all = snap.count_of("render.total");
        let broken_down = snap.count_of("render.settle");
        if broken_down < all {
            out.push_str(&format!(
                "  (sub-timings cover {broken_down} of {all} renders; \
                 trust-center + web-traffic report total only)\n"
            ));
        }
    }

    // Starvation is an accuracy fact, not a performance one, so it is stated outright rather
    // than left for a reader to infer from a row in the table above.
    let starved = snap.count_of("subproc.zero_yield");
    if starved > 0 {
        out.push_str(&format!(
            "WARNING: {starved} vendor(s) exhausted the subprocessor budget having found nothing \
             — those vendors are under-reported (see SUBPROC_BUDGET_EXHAUSTED warnings).\n"
        ));
    }
    out
}

/// Time `f`, recording the elapsed duration into `metric`. Returns `f`'s value.
pub fn timed<T>(metric: &Metric, f: impl FnOnce() -> T) -> T {
    let started = std::time::Instant::now();
    let out = f();
    metric.record(started.elapsed());
    out
}

/// Records elapsed time into `metric` when dropped.
///
/// Useful where a function has several early returns, or where the thing being measured is a
/// value's whole lifetime rather than a call. Rust drops locals in reverse declaration order,
/// so declaring a `ScopedTimer` *before* another local measures that local's teardown too.
pub struct ScopedTimer {
    metric: &'static Metric,
    started: std::time::Instant,
}

impl Drop for ScopedTimer {
    fn drop(&mut self) {
        self.metric.record(self.started.elapsed());
    }
}

/// Start a timer that records into `metric` on drop.
pub fn scoped(metric: &'static Metric) -> ScopedTimer {
    ScopedTimer {
        metric,
        started: std::time::Instant::now(),
    }
}

/// Records into `render.total` when dropped, minus any excluded time.
///
/// Declare it *before* the render's `TabGuard` so that guard — and therefore tab close and
/// Chrome recycling — drops first and is counted.
///
/// **`render.total` must measure a render's own work, not the queue it waited in.** Acquiring a
/// permit blocks, so the timer would otherwise include `permit_wait`; a scan with 272 renders
/// each queued ~54s produced `render.total` = 18473s against a 576s wall, and a "critical path"
/// of 400% of wall. Call [`RenderTimer::exclude`] with the guard's `permit_wait` to subtract it.
pub struct RenderTimer {
    metric: &'static Metric,
    source: Option<&'static Metric>,
    started: std::time::Instant,
    excluded: Duration,
}

impl RenderTimer {
    pub fn start() -> Self {
        Self::into_metric(&METRICS.render_total)
    }

    /// Record into `metric` instead of the global `render.total`.
    ///
    /// Every render site declares its timer before `acquire_tab()`, so a site that fails to get
    /// a browser still drops a timer and increments the global counter. Tests that assert on an
    /// absolute render count must therefore own their own [`Metric`], or an unrelated test in the
    /// same binary can make them fail — which is exactly what happened.
    pub fn into_metric(metric: &'static Metric) -> Self {
        Self {
            metric,
            source: None,
            started: std::time::Instant::now(),
            excluded: Duration::ZERO,
        }
    }

    /// Also record this render's net duration into `source` — the per-call-site split of
    /// `render.total`.
    ///
    /// The aggregate stays the denominator; the source counters partition it. Both receive the
    /// identical exclusion-subtracted duration on drop, so `Σ render.<source> ≈ render.total` and
    /// a source's share is directly readable. A render that fails still records into both, for
    /// the same reason `render.total` counts failures: the slow failures are the ones worth
    /// seeing.
    pub fn with_source(mut self, source: &'static Metric) -> Self {
        self.source = Some(source);
        self
    }

    /// Subtract `d` from what this timer will record — the time spent queued, not working.
    pub fn exclude(&mut self, d: Duration) {
        self.excluded = self.excluded.saturating_add(d);
    }

    #[cfg(test)]
    fn metric(&self) -> &'static Metric {
        self.metric
    }
}

impl Default for RenderTimer {
    fn default() -> Self {
        Self::start()
    }
}

impl Drop for RenderTimer {
    fn drop(&mut self) {
        let net = self.started.elapsed().saturating_sub(self.excluded);
        self.metric.record(net);
        if let Some(source) = self.source {
            source.record(net);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `METRICS` is process-global and `cargo test` runs tests on parallel threads. Any test
    /// that reads or resets the global counters must hold this lock, or a sibling test's
    /// increments race it.
    static GLOBAL_METRICS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_globals() -> std::sync::MutexGuard<'static, ()> {
        GLOBAL_METRICS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn metric_record_accumulates_count_and_duration() {
        let m = Metric::new();
        m.record(Duration::from_millis(10));
        m.record(Duration::from_millis(30));
        let (count, total) = m.snapshot();
        assert_eq!(count, 2);
        assert_eq!(total, Duration::from_millis(40));
    }

    #[test]
    fn metric_hit_counts_without_duration() {
        let m = Metric::new();
        m.hit();
        m.hit();
        let (count, total) = m.snapshot();
        assert_eq!(count, 2);
        assert_eq!(total, Duration::ZERO, "hit() records no time");
    }

    #[test]
    fn metric_reset_zeroes_both_fields() {
        let m = Metric::new();
        m.record(Duration::from_secs(5));
        m.reset();
        assert_eq!(m.snapshot(), (0, Duration::ZERO));
    }

    #[test]
    fn metric_is_shared_across_threads() {
        let m = std::sync::Arc::new(Metric::new());
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let m = std::sync::Arc::clone(&m);
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        m.record(Duration::from_micros(1));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("counter thread panicked");
        }
        let (count, total) = m.snapshot();
        assert_eq!(count, 800, "every increment from every thread must land");
        assert_eq!(total, Duration::from_micros(800));
    }

    #[test]
    fn timed_records_elapsed_and_returns_value() {
        let m = Metric::new();
        let v = timed(&m, || {
            std::thread::sleep(Duration::from_millis(20));
            41 + 1
        });
        assert_eq!(v, 42, "timed() must return the closure's value");
        let (count, total) = m.snapshot();
        assert_eq!(count, 1);
        assert!(
            total >= Duration::from_millis(20),
            "timed() must record at least the slept duration, got {total:?}"
        );
    }

    fn snap_with(pairs: &[(&'static str, u64, Duration)]) -> Snapshot {
        Snapshot {
            rows: pairs
                .iter()
                .map(|(name, count, total)| Row {
                    name,
                    count: *count,
                    total: *total,
                })
                .collect(),
        }
    }

    #[test]
    fn render_critical_path_divides_serialized_time_by_permits() {
        let s = snap_with(&[("render.total", 40, Duration::from_secs(400))]);
        assert_eq!(s.render_critical_path(8), Duration::from_secs(50));
    }

    #[test]
    fn render_critical_path_treats_zero_permits_as_one() {
        // A zero-permit pool cannot exist, but the formatter must not divide by zero.
        let s = snap_with(&[("render.total", 1, Duration::from_secs(10))]);
        assert_eq!(s.render_critical_path(0), Duration::from_secs(10));
    }

    #[test]
    fn render_critical_path_is_zero_when_no_renders_happened() {
        let s = snap_with(&[("dns.query", 5, Duration::from_secs(1))]);
        assert_eq!(s.render_critical_path(8), Duration::ZERO);
    }

    #[test]
    fn pct_of_zero_wall_is_zero_not_nan() {
        assert_eq!(pct(Duration::from_secs(1), Duration::ZERO), 0.0);
    }

    #[test]
    fn pct_computes_share() {
        assert!((pct(Duration::from_secs(25), Duration::from_secs(100)) - 25.0).abs() < 1e-9);
    }

    #[test]
    fn format_report_shows_counts_means_and_critical_path() {
        let s = snap_with(&[
            ("render.total", 100, Duration::from_secs(800)),
            ("browser.launch", 100, Duration::from_secs(200)),
            ("render.settle", 100, Duration::from_secs(400)),
        ]);
        let out = format_report(&s, Duration::from_secs(1000), 8);
        assert!(out.contains("render.total"), "counter name must appear");
        // 800s over 100 renders = 8.000s mean.
        assert!(out.contains("8.000s"), "mean must be rendered: {out}");
        // 800s / 8 permits = 100.0s critical path, 10% of a 1000s wall.
        assert!(
            out.contains("render critical path 100.0s (10.0% of wall)"),
            "critical path line must be present and correct: {out}"
        );
        // settle is 400/800 of render.total.
        assert!(
            out.contains("settle 50.0%"),
            "render breakdown must attribute settle: {out}"
        );
    }

    /// The trust-center and web-traffic render sites record only `render.total`. If the report
    /// implied the breakdown covered every render, a reader would conclude settle was a smaller
    /// share than it is — and optimize the wrong term.
    #[test]
    fn format_report_discloses_partial_sub_timing_coverage() {
        let s = snap_with(&[
            ("render.total", 100, Duration::from_secs(800)),
            ("render.settle", 60, Duration::from_secs(400)),
        ]);
        let out = format_report(&s, Duration::from_secs(1000), 8);
        assert!(
            out.contains("sub-timings cover 60 of 100 renders"),
            "partial coverage must be disclosed: {out}"
        );
    }

    #[test]
    fn format_report_omits_coverage_note_when_all_renders_broken_down() {
        let s = snap_with(&[
            ("render.total", 42, Duration::from_secs(80)),
            ("render.settle", 42, Duration::from_secs(40)),
        ]);
        let out = format_report(&s, Duration::from_secs(100), 8);
        assert!(
            !out.contains("sub-timings cover"),
            "full coverage needs no caveat: {out}"
        );
    }

    #[test]
    fn format_report_omits_breakdown_when_no_renders() {
        let s = snap_with(&[("dns.query", 10, Duration::from_secs(2))]);
        let out = format_report(&s, Duration::from_secs(100), 8);
        assert!(
            !out.contains("render breakdown"),
            "a scan with zero renders must not print a render breakdown: {out}"
        );
        assert!(out.contains("dns.query"));
    }

    #[test]
    fn format_report_handles_zero_count_row_without_dividing_by_zero() {
        let s = snap_with(&[("ner.infer", 0, Duration::ZERO)]);
        let out = format_report(&s, Duration::from_secs(10), 8);
        assert!(out.contains("ner.infer"));
        assert!(out.contains("0.000s"), "zero-count mean is zero: {out}");
    }

    #[test]
    fn snapshot_exposes_every_counter_by_name() {
        let _guard = lock_globals();
        METRICS.reset();
        let snap = METRICS.snapshot();
        for expected in [
            "browser.permit_wait",
            "browser.launch",
            "browser.reuse",
            "render.navigate",
            "render.settle",
            "render.capture",
            "render.total",
            "render.subproc",
            "render.weborg",
            "render.webtraffic",
            "render.trustcenter",
            "ner.infer",
            "http.fetch",
            "whois.lookup",
            "dns.query",
            "dns.memo_hit",
            "subproc.probe",
            "subproc.spa_render",
            "subproc.budget_exhausted",
            "subproc.zero_yield",
        ] {
            assert!(
                snap.get(expected).is_some(),
                "counter {expected} missing from snapshot"
            );
        }
        assert_eq!(snap.rows.len(), 20);
    }

    /// A starved vendor under-reports its subprocessors while the scan-wide total can still
    /// rise. The table must say so in words — this is the signal that a performance change has
    /// quietly cost recall.
    #[test]
    fn format_report_warns_when_vendors_were_starved() {
        let s = snap_with(&[
            ("render.total", 10, Duration::from_secs(80)),
            ("subproc.zero_yield", 3, Duration::ZERO),
        ]);
        let out = format_report(&s, Duration::from_secs(100), 8);
        assert!(
            out.contains("WARNING: 3 vendor(s) exhausted the subprocessor budget"),
            "starvation must be stated outright: {out}"
        );
    }

    #[test]
    fn format_report_is_silent_when_no_vendor_starved() {
        let s = snap_with(&[
            ("render.total", 10, Duration::from_secs(80)),
            ("subproc.zero_yield", 0, Duration::ZERO),
        ]);
        let out = format_report(&s, Duration::from_secs(100), 8);
        assert!(
            !out.contains("WARNING"),
            "a clean scan must not cry wolf: {out}"
        );
    }

    #[test]
    fn snapshot_get_returns_none_for_unknown_counter() {
        let s = snap_with(&[("dns.query", 1, Duration::ZERO)]);
        assert!(s.get("nope").is_none());
    }

    /// `RenderTimer::start()` must target the global `render.total`, or every production render
    /// site would silently measure into a counter the report never prints. Asserted by identity
    /// rather than by counting: any other test in this binary may drop a timer into the global
    /// counter at any moment, so a count-delta assertion here would be racy.
    #[test]
    fn render_timer_start_targets_the_global_render_total() {
        let t = RenderTimer::start();
        assert!(
            std::ptr::eq(t.metric(), &METRICS.render_total),
            "start() must record into METRICS.render_total"
        );
    }

    /// The drop-guard is how two of the five render sites are measured. If it silently failed
    /// to record, those renders would vanish from `N_renders` and the critical-path figure
    /// would understate the render path — the exact error the table exists to prevent.
    #[test]
    fn render_timer_records_into_its_metric_on_drop() {
        static M: Metric = Metric::new();
        {
            let _t = RenderTimer::into_metric(&M);
            std::thread::sleep(Duration::from_millis(15));
        }
        let (count, total) = M.snapshot();
        assert_eq!(count, 1, "drop must record exactly one render");
        assert!(
            total >= Duration::from_millis(15),
            "drop must record the elapsed time, got {total:?}"
        );
    }

    /// The per-source split must partition the aggregate, not shadow it: one render records the
    /// *same* duration into both, so `Σ render.<source>` reconciles against `render.total`.
    #[test]
    fn with_source_records_the_same_duration_into_both_metrics() {
        static AGGREGATE: Metric = Metric::new();
        static SOURCE: Metric = Metric::new();
        {
            let _t = RenderTimer::into_metric(&AGGREGATE).with_source(&SOURCE);
            std::thread::sleep(Duration::from_millis(15));
        }
        let (agg_count, agg_total) = AGGREGATE.snapshot();
        let (src_count, src_total) = SOURCE.snapshot();
        assert_eq!(agg_count, 1, "aggregate must still count the render");
        assert_eq!(src_count, 1, "source must count the render");
        assert_eq!(
            agg_total, src_total,
            "both counters must receive the identical duration, got {agg_total:?} vs {src_total:?}"
        );
        assert!(agg_total >= Duration::from_millis(15));
    }

    /// The exclusion is queue time, not render work — it must be subtracted from the per-source
    /// counter too, or a source's share of `render.total` would be inflated by the queue it
    /// happened to wait in.
    #[test]
    fn with_source_subtracts_the_exclusion_from_both_metrics() {
        static AGGREGATE: Metric = Metric::new();
        static SOURCE: Metric = Metric::new();
        {
            let mut t = RenderTimer::into_metric(&AGGREGATE).with_source(&SOURCE);
            std::thread::sleep(Duration::from_millis(30));
            t.exclude(Duration::from_millis(25));
        }
        let (_, agg_total) = AGGREGATE.snapshot();
        let (_, src_total) = SOURCE.snapshot();
        assert_eq!(agg_total, src_total, "exclusion must apply to both");
        assert!(
            agg_total < Duration::from_millis(30),
            "the excluded queue time must not be recorded, got {agg_total:?}"
        );
    }

    /// A timer with no source declared must leave every other counter alone — the four
    /// per-source counters exist to partition renders, not to collect stray ones.
    #[test]
    fn render_timer_without_source_records_only_its_own_metric() {
        static AGGREGATE: Metric = Metric::new();
        static UNTOUCHED: Metric = Metric::new();
        {
            let _t = RenderTimer::into_metric(&AGGREGATE);
            std::thread::sleep(Duration::from_millis(5));
        }
        let (agg_count, _) = AGGREGATE.snapshot();
        let (untouched_count, untouched_total) = UNTOUCHED.snapshot();
        assert_eq!(agg_count, 1);
        assert_eq!(untouched_count, 0, "no source declared, none recorded");
        assert_eq!(untouched_total, Duration::ZERO);
    }

    /// The permit wait is queue time, not render work. Recording it inside `render.total`
    /// produced a "critical path" of 400% of wall — an impossible figure that only surfaced
    /// because the report printed it. Excluding it is the whole point of the timer.
    #[test]
    fn render_timer_excludes_queue_time_from_render_total() {
        static M: Metric = Metric::new();
        {
            let mut t = RenderTimer::into_metric(&M);
            std::thread::sleep(Duration::from_millis(60));
            // Pretend 50ms of that was spent queued for a permit.
            t.exclude(Duration::from_millis(50));
        }
        let (count, total) = M.snapshot();
        assert_eq!(count, 1);
        assert!(
            total < Duration::from_millis(50),
            "queue time must be subtracted from render work, got {total:?}"
        );
    }

    /// Excluding more than elapsed must saturate at zero, never wrap a `Duration`.
    #[test]
    fn render_timer_exclusion_larger_than_elapsed_saturates_to_zero() {
        static M: Metric = Metric::new();
        {
            let mut t = RenderTimer::into_metric(&M);
            t.exclude(Duration::from_secs(3600));
        }
        let (count, total) = M.snapshot();
        assert_eq!(count, 1);
        assert_eq!(total, Duration::ZERO);
    }

    /// Locals drop in reverse declaration order, so a `RenderTimer` declared first outlives
    /// (and therefore measures) anything declared after it — such as the Chrome guard.
    #[test]
    fn render_timer_declared_first_outlives_later_locals() {
        static M: Metric = Metric::new();
        struct DropsFirst(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropsFirst {
            fn drop(&mut self) {
                // If the timer had already recorded, count would be 1 here.
                let (count, _) = M.snapshot();
                self.0
                    .store(count == 0, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let observed_timer_still_open =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let _timer = RenderTimer::into_metric(&M);
            let _teardown = DropsFirst(std::sync::Arc::clone(&observed_timer_still_open));
        }
        assert!(
            observed_timer_still_open.load(std::sync::atomic::Ordering::SeqCst),
            "the later-declared value must drop while the timer is still running, \
             otherwise Chrome teardown is excluded from render.total"
        );
    }
}
