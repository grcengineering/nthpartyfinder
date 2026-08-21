//! Adaptive DNS congestion control.
//!
//! # Why this exists
//!
//! nthpartyfinder used to pace DNS with a fixed `dns_queries_per_second` (default 100). A deep
//! scan issues tens of thousands of lookups — one measured depth-3 run fanned out 45,398 subdomain
//! resolutions — and a fixed rate cannot be safe, because the safe rate is a property of whichever
//! router and resolver path the user happens to be on. 100 QPS is nothing on a datacenter link and
//! fatal behind a consumer access point, whose DNS forwarder and NAT table are small. In the
//! incident that motivated this module, port 53 went dark to *every* destination — public
//! resolvers and the LAN gateway alike — while ICMP and TCP/443 stayed perfectly healthy: the
//! resolver path had been driven into collapse while the rest of the network was fine.
//!
//! # The idea
//!
//! Bound **concurrency**, not rate, and discover the bound the way TCP discovers a path's
//! bandwidth: probe upward while the network looks healthy, back off quickly when it doesn't.
//!
//! Controlling concurrency is the load-bearing choice. By Little's Law the emitted rate is
//! `concurrency / latency`, so a *fixed* concurrency limit already self-throttles: when the network
//! slows, latency rises and the rate we emit falls out automatically. A fixed *rate* limiter has
//! the opposite behavior — as the network slows it keeps pushing queries at the same rate and the
//! number outstanding grows without bound, which is exactly the state that exhausts a forwarder or
//! conntrack table. Concurrency is also the quantity the intermediary actually runs out of.
//!
//! # The controller
//!
//! Two signals, because they arrive at different times:
//!
//! * **Latency gradient** (early). Queueing inflates round-trip time long before anything drops.
//!   Modeled on TCP Vegas and Netflix's `Gradient2Limit`: compare a slow-moving baseline RTT
//!   against a fast-moving recent RTT. When recent latency inflates relative to baseline the
//!   gradient falls below 1 and the limit is pulled down proportionally.
//! * **Hard failure** (late). Timeouts, refusals and SERVFAIL mean we are already over the edge, so
//!   they trigger an immediate multiplicative decrease independent of the latency path.
//!
//! Both baselines are exponentially-weighted averages rather than an absolute minimum. An absolute
//! minimum is tempting but wrong for a ~70-minute scan: one cache-hit answer returning in
//! microseconds early in the run would pin the baseline near zero forever, making the gradient
//! permanently pessimistic and collapsing the limit to the floor for the rest of the scan.
//!
//! # Invariants
//!
//! * In-flight DNS operations never exceed [`DnsGovernor::limit`].
//! * The limit is always within `[MIN_LIMIT, max_limit]` and can never reach zero, so the scan can
//!   never deadlock itself into making no progress.
//! * A timeout's duration is **never** fed into the latency baselines. A timeout is a congestion
//!   signal, not a latency sample; feeding it in would inflate measured RTT, which would force more
//!   backoff, which would inflate it further — a death spiral.
//! * The control path never blocks on in-flight work. Shrinking withholds only the permits that are
//!   free right now and defers the remainder to the next tick.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

/// Never go below this many concurrent lookups. A floor of 1 would serialize the scan and, on a
/// flaky network, could stall it entirely; 2 keeps forward progress with minimal load.
pub const MIN_LIMIT: u32 = 2;

/// Default ceiling on adaptive concurrency. Deliberately modest: this is the value in force during
/// slow-start before the controller has learned anything, so it must be survivable by a consumer
/// router on its own. Healthy networks climb to it within a few seconds.
pub const DEFAULT_MAX_LIMIT: u32 = 64;

/// Where slow-start begins. Low enough that the opening burst cannot hurt a weak network, high
/// enough that a healthy one is not held back for long (it doubles per healthy window).
const INITIAL_LIMIT: u32 = 8;

/// Smoothing for the fast-moving RTT average — reacts within a handful of samples.
const ALPHA_RECENT: f64 = 0.20;

/// Smoothing for the slow-moving RTT baseline. Deliberately ~20x slower than `ALPHA_RECENT` so the
/// two averages can actually diverge under load; if the baseline tracked recent latency closely the
/// gradient would always read ~1.0 and the controller would be blind to queueing.
const ALPHA_BASELINE: f64 = 0.01;

/// Clamp on the gradient. Bounding below at 0.5 caps how violently one bad window can cut the
/// limit; bounding above at 1.0 means the gradient can only ever *reduce* — growth is the job of
/// the additive probe term, which keeps the controller conservative by construction.
const GRADIENT_MIN: f64 = 0.5;

/// How much latency inflation to tolerate before braking at all.
///
/// This constant is load-bearing, and omitting it is a subtle disaster. The controller's fixed
/// point is `limit = 1/(1 - gradient)^2`, so the *steady-state* concurrency is decided by the
/// average gradient rather than by network capacity — and the mapping is violently nonlinear
/// (g=0.95 → 400, g=0.90 → 100, g=0.50 → 4). Without tolerance, ordinary RTT jitter drives the
/// gradient below 1.0 in roughly half of all windows, so the limit settles somewhere far below
/// what the network can actually carry and the scan silently crawls with no error ever logged.
///
/// Both production limiters do this: Netflix's `Gradient2Limit` uses `rttTolerance = 1.5`, Envoy's
/// adaptive concurrency filter an additive 25% buffer. 1.25 is Envoy's — the more conservative of
/// the two, which suits a bottleneck that is a consumer router rather than a datacenter service.
const RTT_TOLERANCE: f64 = 1.25;

/// Multiplicative decrease applied on a hard failure.
const BACKOFF_FACTOR: f64 = 0.7;

/// How much of the newly-computed target to adopt per control tick. Damps oscillation.
const LIMIT_SMOOTHING: f64 = 0.2;

/// Minimum spacing between control updates. Without this, a burst of fast cached answers would
/// drive many updates in a few milliseconds and amplify noise.
const CONTROL_INTERVAL: Duration = Duration::from_millis(250);

/// After a hard failure, ignore *upward* pressure for this long so a collapsing network is not
/// immediately re-probed. Downward moves still apply.
const BACKOFF_COOLDOWN: Duration = Duration::from_millis(1500);

/// Samples required before the gradient is trusted. Below this the baseline is too noisy to act on
/// and slow-start governs instead.
const MIN_SAMPLES_FOR_GRADIENT: u64 = 20;

/// Latency below this is treated as a cache hit / local answer and excluded from the baselines.
/// Such samples do not reflect network capacity and would otherwise drag the baseline toward zero,
/// permanently biasing the gradient.
const MIN_MEANINGFUL_RTT: Duration = Duration::from_millis(1);

/// Jacobson/Karels smoothing for the RTT variance (RFC 6298 β). An estimator parameter, not a
/// sized ceiling: it shapes how fast the deviation estimate tracks, and the budgets computed from
/// it are observable per attempt via `perf::METRICS.dns_doh_attempt_budget`.
const RTT_VAR_BETA: f64 = 0.25;

/// RFC 6298 K: the retransmission-timeout multiplier on the deviation term.
const RTO_K: f64 = 4.0;

/// Leaf-RTT samples required before [`DnsGovernor::rto`] has an opinion. Below this the variance
/// estimate is seeded noise and the caller's fair-slice budget governs instead.
const MIN_SAMPLES_FOR_RTO: u64 = 8;

/// RFC 6298 §2.4, verbatim: "Whenever RTO is computed, if it is less than 1 second, then the RTO
/// SHOULD be rounded up to 1 second." A standards constant, not a model-sized one — and the r2
/// validation A/B measured why it matters here: with steady ~100 ms RTTs the raw estimator gave
/// per-attempt budgets a few hundred ms wide, ordinary DNS tail latency blew them chronically
/// (dns.sb alone: 562 attempt timeouts in one truncated scan), and at 64 in-flight those bursts
/// filled the breaker's all-providers mask in under five seconds.
const MIN_RTO: Duration = Duration::from_secs(1);

/// How a single DNS lookup ended, from the controller's point of view.
///
/// The distinction that matters is not success-vs-failure but *does this carry usable latency
/// information* and *is this evidence of congestion*. An authoritative empty answer is a perfectly
/// good latency sample; a timeout is not a latency sample at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOutcome {
    /// The resolver answered — including an authoritative empty answer. Carries a usable RTT.
    Answered,
    /// The query timed out. Congestion evidence; the elapsed time is the timeout, not a latency.
    TimedOut,
    /// The resolver actively rejected or failed the query (refused, SERVFAIL, throttled).
    /// Congestion evidence, and its RTT is not representative of a healthy path.
    Rejected,
    /// The lookup failed for a reason unrelated to load (malformed name, unsupported record type,
    /// a decode error). Neither a latency sample nor congestion evidence — the controller ignores
    /// it entirely so that data-dependent failures cannot throttle a healthy network.
    Unrelated,
}

impl DnsOutcome {
    /// Is this outcome evidence that we are pushing the network too hard?
    pub fn is_congestion_signal(self) -> bool {
        matches!(self, DnsOutcome::TimedOut | DnsOutcome::Rejected)
    }
}

/// Point-in-time view of the controller, for reporting to the user.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct GovernorStats {
    pub current_limit: u32,
    pub max_limit: u32,
    pub peak_limit: u32,
    pub min_limit_seen: u32,
    pub in_flight: u32,
    pub backoff_events: u32,
    pub total_queries: u64,
    pub congestion_signals: u64,
    /// True when the user pinned the limit with an explicit override.
    pub user_pinned: bool,
    /// Congestion split: permits that ended `TimedOut` (no response — ambiguous) vs `Rejected`
    /// (explicit refusal — the real over-rate signal). Phase-0 attribution.
    pub timeouts: u64,
    pub rejections: u64,
    /// `apply_limit` transitions by direction — actual controller movement, distinct from
    /// `backoff_events` (congestion-outcome permits, which fire even at an immovable floor).
    pub step_ups: u32,
    pub step_downs: u32,
    /// Control ticks that held still (app-limited workload / cooldown clamp).
    pub holds_app_limited: u64,
    pub holds_cooldown: u64,
    /// Wall time parked at the floor / at the ceiling, open intervals folded in.
    pub floor_ms: u64,
    pub ceiling_ms: u64,
    /// Current EWMA state, microseconds (0.0 until the first sample).
    pub rtt_recent_us: f64,
    pub rtt_baseline_us: f64,
    /// Jacobson mean-deviation estimate, microseconds (0.0 until the first sample). Together with
    /// `rtt_recent_us` this is the RTO the per-attempt DoH budgets are computed from.
    pub rtt_var_us: f64,
    pub in_cooldown: bool,
    pub in_slow_start: bool,
}

/// A compact, copyable governor snapshot for telemetry events (demotions, 5 s samples).
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct GovernorSample {
    pub limit: u32,
    pub max_limit: u32,
    pub in_flight: u32,
    pub is_backing_off: bool,
    pub in_cooldown: bool,
    pub in_slow_start: bool,
    pub cooldown_left_ms: u64,
    pub rtt_recent_us: f64,
    pub rtt_baseline_us: f64,
    pub backoff_events: u32,
    pub congestion_signals: u64,
    pub total_queries: u64,
}

impl GovernorStats {
    /// One line describing what the controller did, for the scan summary. Returns `None` when the
    /// governor never saw enough traffic to have an opinion worth reporting.
    pub fn summary_line(&self) -> Option<String> {
        if self.total_queries == 0 {
            return None;
        }
        if self.user_pinned {
            return Some(format!(
                "DNS concurrency pinned to {} by --dns-max-concurrency ({} queries)",
                self.max_limit, self.total_queries
            ));
        }
        Some(format!(
            "DNS concurrency adapted between {} and {} (ended at {}); {} backoff event(s) across {} queries",
            self.min_limit_seen,
            self.peak_limit,
            self.current_limit,
            self.backoff_events,
            self.total_queries
        ))
    }
}

/// A held slot to perform exactly one DNS lookup.
///
/// The permit is released when this guard drops, so an early `?` or a panic can never leak
/// capacity. Report the result with [`DnsPermit::complete`]; a guard dropped without it still
/// releases its slot but contributes no measurement (the correct behavior for a cancelled task,
/// whose elapsed time says nothing about the network).
pub struct DnsPermit {
    governor: Arc<DnsGovernor>,
    _permit: OwnedSemaphorePermit,
    started: Instant,
    recorded: bool,
}

impl DnsPermit {
    /// Record how the lookup ended. Consumes the guard, releasing the slot.
    ///
    /// Deliberately carries NO latency: the permit's elapsed time contains every queue the lookup
    /// waited in (rate-bucket, memo lock, provider rotation), so feeding it into the RTT baselines
    /// let our own queueing read as network congestion — the Wave-1 fix for the 07-29 flapping.
    /// Latency reaches the controller only through [`DnsGovernor::record_rtt`], fed by the leaf
    /// exchange that actually put one query on the wire.
    pub fn complete(mut self, outcome: DnsOutcome) {
        self.recorded = true;
        self.governor.record(outcome, self.started);
    }

    /// Elapsed time since the permit was granted.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

impl Drop for DnsPermit {
    fn drop(&mut self) {
        self.governor.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Adaptive concurrency controller for DNS egress.
///
/// Construct once per process and share via [`Arc`]. Every DNS lookup acquires a [`DnsPermit`]
/// first and reports its outcome, which is the only input the controller needs.
#[derive(Debug)]
pub struct DnsGovernor {
    /// Created with `max_limit` permits. Concurrency is reduced by *withholding* permits (the
    /// `ballast`) rather than by destroying the semaphore, because tokio semaphores can only grow.
    semaphore: Arc<Semaphore>,
    /// Permits currently withheld to enforce a limit below `max_limit`. Only the control path
    /// touches this, under the mutex, so resizes cannot race each other.
    ballast: Mutex<u32>,

    limit: AtomicU32,
    max_limit: u32,
    in_flight: AtomicU32,

    /// Fast- and slow-moving RTT averages, in microseconds, stored as bit-cast `f64`.
    rtt_recent_us: AtomicU64,
    rtt_baseline_us: AtomicU64,
    /// Jacobson mean deviation of the RTT, microseconds, bit-cast `f64` (RFC 6298 RTTVAR).
    rtt_var_us: AtomicU64,
    latency_samples: AtomicU64,

    /// Millis since construction; avoids wall-clock dependence.
    epoch: Instant,
    next_control_at_ms: AtomicU64,
    cooldown_until_ms: AtomicU64,
    /// Epoch-relative ms of the last multiplicative decrease (0 = never) — the congestion-epoch
    /// marker (Wave 2, 7a). Written by CAS so one wave of correlated signals decreases once.
    last_decrease_at_ms: AtomicU64,

    /// Slow-start ends at the first congestion signal and never resumes.
    in_slow_start: AtomicBool,

    peak_limit: AtomicU32,
    min_limit_seen: AtomicU32,
    backoff_events: AtomicU32,
    total_queries: AtomicU64,
    congestion_signals: AtomicU64,

    // ── Phase-0 attribution counters (observation only; none influences control flow) ──
    /// Congestion signals that were timeouts vs explicit rejections — the split the summary
    /// needs to tell "no response" (ambiguous) from "server said no" (real 429-class signal).
    timeouts: AtomicU64,
    rejections: AtomicU64,
    /// `apply_limit` transitions, split by direction. Distinct from `backoff_events`, which
    /// counts congestion-outcome permits even when the limit was already at the floor and
    /// could not move — the conflation that made "34,506 backoff events" unreadable.
    step_ups: AtomicU32,
    step_downs: AtomicU32,
    /// Control ticks held still because the workload was app-limited / in cooldown.
    holds_app_limited: AtomicU64,
    holds_cooldown: AtomicU64,
    /// Accumulated wall time spent parked at the floor / at the ceiling (open intervals are
    /// folded in by `stats()`); `*_since_ms` of 0 means "not currently there".
    floor_since_ms: AtomicU64,
    floor_ms_total: AtomicU64,
    ceiling_since_ms: AtomicU64,
    ceiling_ms_total: AtomicU64,

    /// When set, the limit is pinned and adaptation is disabled.
    user_pinned: bool,
}

impl DnsGovernor {
    /// Adaptive governor with the given ceiling. `max_limit` is clamped to at least [`MIN_LIMIT`].
    pub fn new(max_limit: u32) -> Arc<Self> {
        Self::build(max_limit.max(MIN_LIMIT), false)
    }

    /// Governor pinned to a fixed concurrency, for `--dns-max-concurrency`. Adaptation is off; the
    /// bound is still enforced.
    pub fn pinned(limit: u32) -> Arc<Self> {
        Self::build(limit.max(MIN_LIMIT), true)
    }

    fn build(max_limit: u32, user_pinned: bool) -> Arc<Self> {
        let start = if user_pinned {
            max_limit
        } else {
            INITIAL_LIMIT.min(max_limit)
        };
        let governor = Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(max_limit as usize)),
            ballast: Mutex::new(max_limit - start),
            limit: AtomicU32::new(start),
            max_limit,
            in_flight: AtomicU32::new(0),
            rtt_recent_us: AtomicU64::new(0),
            rtt_baseline_us: AtomicU64::new(0),
            rtt_var_us: AtomicU64::new(0),
            latency_samples: AtomicU64::new(0),
            epoch: Instant::now(),
            next_control_at_ms: AtomicU64::new(0),
            cooldown_until_ms: AtomicU64::new(0),
            last_decrease_at_ms: AtomicU64::new(0),
            in_slow_start: AtomicBool::new(!user_pinned),
            peak_limit: AtomicU32::new(start),
            min_limit_seen: AtomicU32::new(start),
            backoff_events: AtomicU32::new(0),
            total_queries: AtomicU64::new(0),
            congestion_signals: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            rejections: AtomicU64::new(0),
            step_ups: AtomicU32::new(0),
            step_downs: AtomicU32::new(0),
            holds_app_limited: AtomicU64::new(0),
            holds_cooldown: AtomicU64::new(0),
            floor_since_ms: AtomicU64::new(0),
            floor_ms_total: AtomicU64::new(0),
            ceiling_since_ms: AtomicU64::new(0),
            ceiling_ms_total: AtomicU64::new(0),
            user_pinned,
        });
        // Withhold the difference between the ceiling and the starting limit. These permits are
        // free at construction, so this cannot block.
        let withhold = max_limit - start;
        if withhold > 0 {
            if let Ok(permits) = governor.semaphore.clone().try_acquire_many_owned(withhold) {
                permits.forget();
            }
        }
        governor
    }

    /// Wait for a slot. The returned guard bounds one DNS lookup.
    pub async fn acquire(self: &Arc<Self>) -> DnsPermit {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("DNS governor semaphore is never closed");
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        DnsPermit {
            governor: Arc::clone(self),
            _permit: permit,
            started: Instant::now(),
            recorded: false,
        }
    }

    /// Current concurrency limit.
    pub fn limit(&self) -> u32 {
        self.limit.load(Ordering::Relaxed)
    }

    /// Lookups currently in flight.
    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Is the controller currently pulling back because the network is struggling?
    ///
    /// True when the limit sits below its ceiling *and* we are inside the post-failure cooldown —
    /// i.e. a hard failure happened recently and we responded to it. Callers use this to tell
    /// self-inflicted congestion apart from a genuinely broken transport, so that a circuit
    /// breaker does not disable a working path just because we were pushing it too hard.
    pub fn is_backing_off(&self) -> bool {
        if self.user_pinned {
            return false;
        }
        self.limit.load(Ordering::Relaxed) < self.max_limit
            && self.now_ms() < self.cooldown_until_ms.load(Ordering::Relaxed)
    }

    /// Snapshot for reporting.
    pub fn stats(&self) -> GovernorStats {
        let now = self.now_ms();
        let fold_open = |since: &AtomicU64, total: &AtomicU64| -> u64 {
            let open = match since.load(Ordering::Relaxed) {
                0 => 0,
                s => now.saturating_sub(s),
            };
            total.load(Ordering::Relaxed) + open
        };
        GovernorStats {
            current_limit: self.limit(),
            max_limit: self.max_limit,
            peak_limit: self.peak_limit.load(Ordering::Relaxed),
            min_limit_seen: self.min_limit_seen.load(Ordering::Relaxed),
            in_flight: self.in_flight(),
            backoff_events: self.backoff_events.load(Ordering::Relaxed),
            total_queries: self.total_queries.load(Ordering::Relaxed),
            congestion_signals: self.congestion_signals.load(Ordering::Relaxed),
            user_pinned: self.user_pinned,
            timeouts: self.timeouts.load(Ordering::Relaxed),
            rejections: self.rejections.load(Ordering::Relaxed),
            step_ups: self.step_ups.load(Ordering::Relaxed),
            step_downs: self.step_downs.load(Ordering::Relaxed),
            holds_app_limited: self.holds_app_limited.load(Ordering::Relaxed),
            holds_cooldown: self.holds_cooldown.load(Ordering::Relaxed),
            floor_ms: fold_open(&self.floor_since_ms, &self.floor_ms_total),
            ceiling_ms: fold_open(&self.ceiling_since_ms, &self.ceiling_ms_total),
            rtt_recent_us: f64::from_bits(self.rtt_recent_us.load(Ordering::Relaxed)),
            rtt_baseline_us: f64::from_bits(self.rtt_baseline_us.load(Ordering::Relaxed)),
            rtt_var_us: f64::from_bits(self.rtt_var_us.load(Ordering::Relaxed)),
            in_cooldown: now < self.cooldown_until_ms.load(Ordering::Relaxed),
            in_slow_start: self.in_slow_start.load(Ordering::Relaxed),
        }
    }

    /// Compact snapshot for telemetry events — cheap enough to take on every demotion/sample.
    pub fn sample(&self) -> GovernorSample {
        let now = self.now_ms();
        let cooldown_until = self.cooldown_until_ms.load(Ordering::Relaxed);
        GovernorSample {
            limit: self.limit(),
            max_limit: self.max_limit,
            in_flight: self.in_flight(),
            is_backing_off: self.is_backing_off(),
            in_cooldown: now < cooldown_until,
            in_slow_start: self.in_slow_start.load(Ordering::Relaxed),
            cooldown_left_ms: cooldown_until.saturating_sub(now),
            rtt_recent_us: f64::from_bits(self.rtt_recent_us.load(Ordering::Relaxed)),
            rtt_baseline_us: f64::from_bits(self.rtt_baseline_us.load(Ordering::Relaxed)),
            backoff_events: self.backoff_events.load(Ordering::Relaxed),
            congestion_signals: self.congestion_signals.load(Ordering::Relaxed),
            total_queries: self.total_queries.load(Ordering::Relaxed),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Fold one completed lookup's OUTCOME into the controller. Latency arrives separately via
    /// [`Self::record_rtt`] — see [`DnsPermit::complete`] for why the split is load-bearing.
    /// `started` is when the lookup's permit was granted — the congestion-epoch discriminator
    /// (see [`Self::on_congestion`]).
    fn record(self: &Arc<Self>, outcome: DnsOutcome, started: Instant) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);

        if outcome == DnsOutcome::Unrelated {
            // Data-dependent failure: says nothing about the network, so it must not move the
            // limit in either direction.
            return;
        }

        if outcome.is_congestion_signal() {
            self.congestion_signals.fetch_add(1, Ordering::Relaxed);
            match outcome {
                DnsOutcome::TimedOut => self.timeouts.fetch_add(1, Ordering::Relaxed),
                DnsOutcome::Rejected => self.rejections.fetch_add(1, Ordering::Relaxed),
                _ => unreachable!("is_congestion_signal admits only TimedOut | Rejected"),
            };
            self.on_congestion(started);
            return;
        }

        self.maybe_run_control();
    }

    /// Fold one LEAF-EXCHANGE latency sample into the averages: the elapsed time of exactly one
    /// query put on the wire and answered, measured at the site that sent it. Never a permit's
    /// lifetime (that contains our own queues), never a timeout's duration (that is the timeout).
    /// Sub-[`MIN_MEANINGFUL_RTT`] samples are cache hits and are ignored here, exactly as before.
    pub fn record_rtt(&self, elapsed: Duration) {
        if elapsed < MIN_MEANINGFUL_RTT {
            return;
        }
        let sample = elapsed.as_micros() as f64;
        let n = self.latency_samples.fetch_add(1, Ordering::Relaxed);
        if n == 0 {
            // Seed both averages from the first real sample so the gradient starts at exactly 1.0
            // rather than at an arbitrary ratio against zero. RFC 6298: RTTVAR seeds at R/2.
            self.rtt_recent_us
                .store(sample.to_bits(), Ordering::Relaxed);
            self.rtt_baseline_us
                .store(sample.to_bits(), Ordering::Relaxed);
            self.rtt_var_us
                .store((sample / 2.0).to_bits(), Ordering::Relaxed);
            return;
        }
        // Deviation against the pre-update smoothed RTT (Jacobson's ordering), then the means.
        let recent_before = f64::from_bits(self.rtt_recent_us.load(Ordering::Relaxed));
        ewma_update(
            &self.rtt_var_us,
            (sample - recent_before).abs(),
            RTT_VAR_BETA,
        );
        ewma_update(&self.rtt_recent_us, sample, ALPHA_RECENT);
        ewma_update(&self.rtt_baseline_us, sample, ALPHA_BASELINE);
    }

    /// The measured retransmission timeout — `rtt_recent + 4·rtt_var` (RFC 6298) — or `None`
    /// until enough leaf samples exist to trust it. Callers use it as a per-attempt DoH budget
    /// floor: an attempt gets at least the time a real answer plausibly takes on THIS network,
    /// instead of a model-sized constant. Field-measured by construction (CLAUDE.md rule 17).
    pub fn rto(&self) -> Option<Duration> {
        if self.latency_samples.load(Ordering::Relaxed) < MIN_SAMPLES_FOR_RTO {
            return None;
        }
        let recent = f64::from_bits(self.rtt_recent_us.load(Ordering::Relaxed));
        let var = f64::from_bits(self.rtt_var_us.load(Ordering::Relaxed));
        let rto_us = recent + RTO_K * var;
        if !rto_us.is_finite() || rto_us <= 0.0 {
            return None;
        }
        Some(Duration::from_micros(rto_us as u64).max(MIN_RTO))
    }

    /// Has the adaptive controller retreated all the way to its floor?
    ///
    /// This is the discriminator the breaker uses for NO-RESPONSE evidence (attempt-budget
    /// timeouts): "the controller has already given the network every concession it can make and
    /// the transport still does not answer" — which by construction is not our load. A pinned
    /// governor never retreats, so under `--dns-max-concurrency` timeout evidence stays ambiguous
    /// forever and can never trip a breaker (unreachable-class evidence still can) — the latch
    /// that made every pinned Phase-1 arm a zero-relationship scan cannot re-arm this way.
    /// Time remaining in the post-failure cooldown (zero when none). The deferred-retry rescue
    /// (Wave 2, 7d) sleeps exactly this long before its one retry, so the retry runs after the
    /// controller's reduction has taken effect — bounded by `BACKOFF_COOLDOWN` by construction.
    pub fn cooldown_left(&self) -> Duration {
        Duration::from_millis(
            self.cooldown_until_ms
                .load(Ordering::Relaxed)
                .saturating_sub(self.now_ms()),
        )
    }

    pub fn has_retreated_to_floor(&self) -> bool {
        !self.user_pinned && self.limit.load(Ordering::Relaxed) <= MIN_LIMIT
    }

    /// Hard failure: at most ONE multiplicative decrease per congestion EPOCH — TCP's rule
    /// (Wave 2, 7a). A signal whose permit started BEFORE the last decrease was already in
    /// flight when the controller reacted: it corroborates that epoch rather than opening a new
    /// one. Without this, one correlated wave of 64 timeouts applied 0.7^k in a single burst and
    /// collapsed the limit 64 → 2 instantly — the cliff the Phase-1 baseline spent 61% of its
    /// scan at the bottom of. Every signal still refreshes the cooldown (upward pressure stays
    /// suppressed while failures continue) and still counts in `congestion_signals`;
    /// `backoff_events` now counts actual decreases (epochs).
    fn on_congestion(self: &Arc<Self>, started: Instant) {
        if self.user_pinned {
            return;
        }
        self.in_slow_start.store(false, Ordering::Relaxed);
        let now = self.now_ms();
        self.cooldown_until_ms
            .store(now + BACKOFF_COOLDOWN.as_millis() as u64, Ordering::Relaxed);

        let started_ms = started.saturating_duration_since(self.epoch).as_millis() as u64;
        let last = self.last_decrease_at_ms.load(Ordering::Relaxed);
        if started_ms < last {
            return; // in flight when the epoch's decrease was applied — corroboration only
        }
        // Exactly one concurrent fresh signal wins the epoch's decrease; the CAS losers were
        // part of the same wave.
        if self
            .last_decrease_at_ms
            .compare_exchange(last, now.max(1), Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.backoff_events.fetch_add(1, Ordering::Relaxed);

        let current = self.limit.load(Ordering::Relaxed);
        let target = ((current as f64) * BACKOFF_FACTOR).floor() as u32;
        self.apply_limit(target.max(MIN_LIMIT));
    }

    /// Run the gradient controller if the control interval has elapsed. Exactly one caller wins the
    /// CAS; the rest return immediately, so this stays cheap on the hot path.
    fn maybe_run_control(self: &Arc<Self>) {
        if self.user_pinned {
            return;
        }
        let now = self.now_ms();
        let due = self.next_control_at_ms.load(Ordering::Relaxed);
        if now < due {
            return;
        }
        if self
            .next_control_at_ms
            .compare_exchange(
                due,
                now + CONTROL_INTERVAL.as_millis() as u64,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return; // another task is running this tick
        }

        let current = self.limit.load(Ordering::Relaxed);
        let in_cooldown = now < self.cooldown_until_ms.load(Ordering::Relaxed);

        // Only probe upward when we are actually using the capacity we already have. Growing while
        // half-idle would chase a limit the workload never exercises, and the number would be
        // meaningless the moment load arrived.
        let saturated = self.in_flight.load(Ordering::Relaxed) * 2 >= current;

        let target = if self.in_slow_start.load(Ordering::Relaxed) {
            if in_cooldown || !saturated {
                current
            } else {
                current.saturating_mul(2)
            }
        } else {
            let samples = self.latency_samples.load(Ordering::Relaxed);
            if samples < MIN_SAMPLES_FOR_GRADIENT {
                current
            } else {
                let recent = f64::from_bits(self.rtt_recent_us.load(Ordering::Relaxed));
                let baseline = f64::from_bits(self.rtt_baseline_us.load(Ordering::Relaxed));
                let gradient = compute_gradient(baseline, recent);
                // Additive probe headroom, sub-linear in the limit so growth slows as we climb.
                let headroom = (current as f64).sqrt();
                let raw = (current as f64) * gradient + headroom;
                let smoothed = (current as f64) * (1.0 - LIMIT_SMOOTHING) + raw * LIMIT_SMOOTHING;
                // Round *away* from the current limit. Rounding to nearest would strand the
                // controller at small limits, where a whole tick's smoothed movement is less than
                // one whole permit: at limit 2 the target computes to 2.28, rounds back to 2, and
                // the limit can never recover from a backoff.
                let next = if smoothed > current as f64 {
                    smoothed.ceil()
                } else {
                    smoothed.floor()
                }
                .max(MIN_LIMIT as f64) as u32;
                if !saturated {
                    // App-limited: we are not using the capacity we already have, so the latency
                    // we measured says nothing about the network's limit. Hold still. Accepting
                    // *downward* moves here (and only downward, since growth is already gated on
                    // saturation) would ratchet the limit down to roughly twice the offered load
                    // and keep it there — the controller would end up tracking our own token
                    // bucket rather than the network. Netflix's Gradient2 does the same thing:
                    // `if (inflight < estimatedLimit / 2) return estimatedLimit;`
                    self.holds_app_limited.fetch_add(1, Ordering::Relaxed);
                    current
                } else if in_cooldown {
                    // Recovering from a hard failure: corrections may only reduce.
                    if next > current {
                        self.holds_cooldown.fetch_add(1, Ordering::Relaxed);
                    }
                    next.min(current)
                } else {
                    next
                }
            }
        };

        if target != current {
            self.apply_limit(target);
        }
    }

    /// Move the limit to `target`, clamped, and resize the semaphore to match.
    fn apply_limit(self: &Arc<Self>, target: u32) {
        let target = target.clamp(MIN_LIMIT, self.max_limit);
        let previous = self.limit.swap(target, Ordering::AcqRel);
        if previous == target {
            return;
        }
        self.peak_limit.fetch_max(target, Ordering::Relaxed);
        self.min_limit_seen.fetch_min(target, Ordering::Relaxed);
        if target > previous {
            self.step_ups.fetch_add(1, Ordering::Relaxed);
        } else {
            self.step_downs.fetch_add(1, Ordering::Relaxed);
        }
        self.note_extreme_transition(previous, target);
        self.resize(target);
    }

    /// Track wall time spent parked at the floor / ceiling (Phase-0 attribution). Open intervals
    /// are folded in by [`DnsGovernor::stats`]; a `*_since_ms` of 0 means "not currently there".
    fn note_extreme_transition(&self, previous: u32, target: u32) {
        let now = self.now_ms().max(1); // 0 is the "not there" sentinel
        if target == MIN_LIMIT && previous != MIN_LIMIT {
            self.floor_since_ms.store(now, Ordering::Relaxed);
        } else if previous == MIN_LIMIT && target != MIN_LIMIT {
            let since = self.floor_since_ms.swap(0, Ordering::Relaxed);
            if since != 0 {
                self.floor_ms_total
                    .fetch_add(now.saturating_sub(since), Ordering::Relaxed);
            }
        }
        if target == self.max_limit && previous != self.max_limit {
            self.ceiling_since_ms.store(now, Ordering::Relaxed);
        } else if previous == self.max_limit && target != self.max_limit {
            let since = self.ceiling_since_ms.swap(0, Ordering::Relaxed);
            if since != 0 {
                self.ceiling_ms_total
                    .fetch_add(now.saturating_sub(since), Ordering::Relaxed);
            }
        }
    }

    /// Reconcile withheld permits with the current limit.
    ///
    /// Growing hands permits back immediately. Shrinking withholds only what is free right now —
    /// a permit held by an in-flight lookup cannot be revoked, and blocking here would stall the
    /// caller behind network I/O. The shortfall is simply retried on the next tick, so the limit
    /// converges as lookups complete.
    fn resize(self: &Arc<Self>, target: u32) {
        let governor = Arc::clone(self);
        let Ok(mut ballast) = governor.ballast.try_lock() else {
            // Another resize is in flight; it will observe the newer limit when it reconciles.
            return;
        };
        let want = governor.max_limit - target;
        let have = *ballast;
        if want > have {
            let deficit = want - have;
            if let Ok(permits) = governor
                .semaphore
                .clone()
                .try_acquire_many_owned(deficit.min(governor.semaphore.available_permits() as u32))
            {
                let got = permits.num_permits() as u32;
                permits.forget();
                *ballast = have + got;
            }
        } else if want < have {
            let surplus = have - want;
            governor.semaphore.add_permits(surplus as usize);
            *ballast = want;
        }
    }
}

/// Fold `sample` into the EWMA stored as bit-cast `f64` in `slot`.
///
/// Uses compare-and-swap so a concurrent update cannot be lost. On contention we retry with the
/// value the winner wrote, which keeps the average consistent rather than merely approximate.
fn ewma_update(slot: &AtomicU64, sample: f64, alpha: f64) {
    let mut current = slot.load(Ordering::Relaxed);
    loop {
        let previous = f64::from_bits(current);
        let next = previous * (1.0 - alpha) + sample * alpha;
        match slot.compare_exchange_weak(
            current,
            next.to_bits(),
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

/// Tolerated ratio of baseline to recent latency, clamped to `[GRADIENT_MIN, 1.0]`.
///
/// 1.0 means no braking. Below 1.0 means recent latency has inflated past what
/// [`RTT_TOLERANCE`] permits, and the limit is scaled by that ratio. Clamping at 1.0 makes the
/// gradient purely a brake: growth comes only from the explicit probe term.
fn compute_gradient(baseline: f64, recent: f64) -> f64 {
    if !baseline.is_finite() || !recent.is_finite() || recent <= 0.0 || baseline <= 0.0 {
        return 1.0;
    }
    (RTT_TOLERANCE * baseline / recent).clamp(GRADIENT_MIN, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn drive(governor: &Arc<DnsGovernor>, outcome: DnsOutcome, rtt: Duration, times: usize) {
        for _ in 0..times {
            // Mirror production wiring: only an answered exchange feeds a leaf-RTT sample; a
            // timeout/rejection carries no latency information at all (its elapsed IS the budget).
            if outcome == DnsOutcome::Answered {
                governor.record_rtt(rtt);
            }
            governor.record(outcome, Instant::now());
        }
    }

    /// Advance past the control interval so the next `record` runs a control tick.
    fn allow_control_tick(governor: &Arc<DnsGovernor>) {
        governor.next_control_at_ms.store(0, Ordering::Relaxed);
    }

    #[test]
    fn starts_in_slow_start_below_the_ceiling() {
        let g = DnsGovernor::new(64);
        assert_eq!(g.limit(), INITIAL_LIMIT);
        assert!(g.limit() < 64, "must not open at the ceiling");
    }

    #[test]
    fn ceiling_is_never_exceeded() {
        let g = DnsGovernor::new(16);
        for _ in 0..50 {
            allow_control_tick(&g);
            g.in_flight.store(g.limit(), Ordering::Relaxed);
            drive(&g, DnsOutcome::Answered, Duration::from_millis(10), 30);
        }
        assert!(g.limit() <= 16, "limit {} exceeded ceiling", g.limit());
    }

    #[test]
    fn limit_never_falls_below_the_floor() {
        let g = DnsGovernor::new(64);
        drive(&g, DnsOutcome::TimedOut, Duration::from_secs(5), 200);
        assert!(g.limit() >= MIN_LIMIT, "limit fell to {}", g.limit());
    }

    #[test]
    fn timeouts_do_not_pollute_the_latency_baseline() {
        let g = DnsGovernor::new(64);
        drive(&g, DnsOutcome::Answered, Duration::from_millis(20), 30);
        let baseline_before = g.rtt_baseline_us.load(Ordering::Relaxed);
        let recent_before = g.rtt_recent_us.load(Ordering::Relaxed);

        // A timeout's elapsed time is enormous; it must be ignored as a latency sample.
        drive(&g, DnsOutcome::TimedOut, Duration::from_secs(30), 10);

        assert_eq!(
            baseline_before,
            g.rtt_baseline_us.load(Ordering::Relaxed),
            "timeout moved the RTT baseline"
        );
        assert_eq!(
            recent_before,
            g.rtt_recent_us.load(Ordering::Relaxed),
            "timeout moved the recent RTT"
        );
    }

    #[test]
    fn hard_failure_reduces_the_limit_immediately() {
        let g = DnsGovernor::new(64);
        // Climb first so there is room to fall.
        for _ in 0..4 {
            allow_control_tick(&g);
            g.in_flight.store(g.limit(), Ordering::Relaxed);
            drive(&g, DnsOutcome::Answered, Duration::from_millis(5), 5);
        }
        let climbed = g.limit();
        assert!(climbed > INITIAL_LIMIT, "slow start did not climb");

        g.record(DnsOutcome::TimedOut, Instant::now());
        assert!(
            g.limit() < climbed,
            "limit {} did not drop from {climbed}",
            g.limit()
        );
        assert_eq!(g.stats().backoff_events, 1);
    }

    #[test]
    fn rejected_is_treated_as_congestion_and_unrelated_is_not() {
        assert!(DnsOutcome::Rejected.is_congestion_signal());
        assert!(DnsOutcome::TimedOut.is_congestion_signal());
        assert!(!DnsOutcome::Answered.is_congestion_signal());
        assert!(!DnsOutcome::Unrelated.is_congestion_signal());

        let g = DnsGovernor::new(64);
        let before = g.limit();
        drive(&g, DnsOutcome::Unrelated, Duration::from_millis(3), 100);
        assert_eq!(
            g.limit(),
            before,
            "a data-dependent failure must not move the limit"
        );
        assert_eq!(g.stats().backoff_events, 0);
    }

    #[test]
    fn slow_start_climbs_quickly_on_a_healthy_network() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        for _ in 0..6 {
            allow_control_tick(&g);
            g.in_flight.store(g.limit(), Ordering::Relaxed);
            drive(&g, DnsOutcome::Answered, Duration::from_millis(8), 5);
        }
        assert_eq!(
            g.limit(),
            DEFAULT_MAX_LIMIT,
            "healthy network should reach the ceiling within a few windows"
        );
    }

    #[test]
    fn inflating_latency_pulls_the_limit_down_without_any_failure() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        // Establish a healthy baseline and climb out of slow start.
        for _ in 0..6 {
            allow_control_tick(&g);
            g.in_flight.store(g.limit(), Ordering::Relaxed);
            drive(&g, DnsOutcome::Answered, Duration::from_millis(8), 10);
        }
        g.in_slow_start.store(false, Ordering::Relaxed);
        let healthy = g.limit();

        // Latency inflates 10x — pure queueing, zero failures.
        for _ in 0..12 {
            allow_control_tick(&g);
            g.in_flight.store(g.limit(), Ordering::Relaxed);
            drive(&g, DnsOutcome::Answered, Duration::from_millis(80), 10);
        }

        assert!(
            g.limit() < healthy,
            "limit {} did not fall from {healthy} despite 10x latency inflation",
            g.limit()
        );
    }

    #[test]
    fn gradient_is_a_brake_only() {
        // Recent faster than baseline still yields 1.0 — never above.
        assert_eq!(compute_gradient(100.0, 10.0), 1.0);
        // Severe inflation bottoms out at the clamp.
        assert_eq!(compute_gradient(100.0, 400.0), GRADIENT_MIN);
        // Past the tolerance, braking is proportional: 1.25 * 100/200 = 0.625.
        assert!((compute_gradient(100.0, 200.0) - 0.625).abs() < 1e-9);
    }

    /// Ordinary jitter must not brake at all. Without the tolerance term the controller's fixed
    /// point (`limit = 1/(1-gradient)^2`) is set by noise rather than capacity, and a healthy
    /// network silently settles at a fraction of what it can carry.
    #[test]
    fn latency_jitter_within_tolerance_does_not_brake() {
        for inflation in [1.0, 1.05, 1.10, 1.20, 1.25] {
            assert_eq!(
                compute_gradient(100.0, 100.0 * inflation),
                1.0,
                "{inflation}x inflation should be tolerated, not braked"
            );
        }
        // Just past tolerance, braking begins.
        assert!(compute_gradient(100.0, 130.0) < 1.0);
    }

    /// The controller's equilibrium is `1/(1-g)^2`. Pin that down so a future constant change
    /// cannot silently move the steady-state concurrency by two orders of magnitude.
    #[test]
    fn healthy_network_equilibrium_is_the_ceiling_not_a_low_fixed_point() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        g.in_slow_start.store(false, Ordering::Relaxed);
        // Steady 20ms with +-10% jitter: comfortably inside tolerance.
        let mut tick = 0u64;
        for _ in 0..400 {
            allow_control_tick(&g);
            g.in_flight.store(g.limit(), Ordering::Relaxed);
            tick += 1;
            let jitter = if tick.is_multiple_of(2) { 22 } else { 18 };
            drive(&g, DnsOutcome::Answered, Duration::from_millis(jitter), 5);
        }
        assert_eq!(
            g.limit(),
            DEFAULT_MAX_LIMIT,
            "a healthy jittery network must reach the ceiling, not settle at a jitter-determined \
             fixed point"
        );
    }

    #[test]
    fn gradient_is_defensive_against_degenerate_inputs() {
        assert_eq!(compute_gradient(0.0, 10.0), 1.0);
        assert_eq!(compute_gradient(10.0, 0.0), 1.0);
        assert_eq!(compute_gradient(f64::NAN, 10.0), 1.0);
        assert_eq!(compute_gradient(10.0, f64::INFINITY), 1.0);
    }

    #[test]
    fn sub_millisecond_answers_do_not_drag_the_baseline_down() {
        let g = DnsGovernor::new(64);
        drive(&g, DnsOutcome::Answered, Duration::from_millis(20), 10);
        let baseline = g.rtt_baseline_us.load(Ordering::Relaxed);
        // A burst of cache hits returning in microseconds must be ignored.
        drive(&g, DnsOutcome::Answered, Duration::from_micros(50), 200);
        assert_eq!(
            baseline,
            g.rtt_baseline_us.load(Ordering::Relaxed),
            "cache-hit latencies polluted the baseline"
        );
    }

    #[test]
    fn ewma_converges_toward_the_sample() {
        let slot = AtomicU64::new(100.0f64.to_bits());
        for _ in 0..500 {
            ewma_update(&slot, 200.0, 0.2);
        }
        let value = f64::from_bits(slot.load(Ordering::Relaxed));
        assert!((value - 200.0).abs() < 1e-6, "converged to {value}");
    }

    /// The circuit-breaker discriminator. A governor that has just backed off is reporting
    /// self-inflicted congestion; a healthy one is not.
    #[test]
    fn is_backing_off_distinguishes_congestion_from_a_broken_transport() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        assert!(
            !g.is_backing_off(),
            "a fresh governor is not backing off, so failures mean a broken transport"
        );

        g.record(DnsOutcome::TimedOut, Instant::now());
        assert!(
            g.is_backing_off(),
            "after a hard failure the governor is visibly backing off"
        );

        // Once the cooldown lapses we are no longer attributing failures to our own load.
        g.cooldown_until_ms.store(0, Ordering::Relaxed);
        assert!(!g.is_backing_off(), "cooldown expiry ends the attribution");

        // A pinned governor never claims congestion — the user chose the limit.
        let pinned = DnsGovernor::pinned(4);
        pinned.record(DnsOutcome::TimedOut, Instant::now());
        assert!(!pinned.is_backing_off());
    }

    #[test]
    fn pinned_governor_does_not_adapt() {
        let g = DnsGovernor::pinned(12);
        assert_eq!(g.limit(), 12);
        drive(&g, DnsOutcome::TimedOut, Duration::from_secs(5), 100);
        assert_eq!(g.limit(), 12, "pinned limit must not move");
        assert_eq!(g.stats().backoff_events, 0);
        assert!(g.stats().user_pinned);
    }

    #[test]
    fn stats_summary_reports_pinned_and_adaptive_modes() {
        let pinned = DnsGovernor::pinned(9);
        pinned.record(DnsOutcome::Answered, Instant::now());
        let line = pinned.stats().summary_line().expect("pinned summary");
        assert!(line.contains("pinned to 9"), "got: {line}");

        let adaptive = DnsGovernor::new(32);
        adaptive.record(DnsOutcome::Answered, Instant::now());
        let line = adaptive.stats().summary_line().expect("adaptive summary");
        assert!(line.contains("adapted between"), "got: {line}");

        // No traffic → nothing worth saying.
        assert!(DnsGovernor::new(32).stats().summary_line().is_none());
    }

    #[tokio::test]
    async fn in_flight_never_exceeds_the_limit_under_concurrency() {
        let g = DnsGovernor::pinned(5);
        let peak = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..64 {
            let g = Arc::clone(&g);
            let peak = Arc::clone(&peak);
            handles.push(tokio::spawn(async move {
                let permit = g.acquire().await;
                let now = g.in_flight() as usize;
                peak.fetch_max(now, Ordering::AcqRel);
                tokio::time::sleep(Duration::from_millis(2)).await;
                permit.complete(DnsOutcome::Answered);
            }));
        }
        for h in handles {
            h.await.expect("task panicked");
        }

        assert!(
            peak.load(Ordering::Relaxed) <= 5,
            "peak in-flight {} exceeded limit 5",
            peak.load(Ordering::Relaxed)
        );
        assert_eq!(g.in_flight(), 0, "permits leaked");
    }

    #[tokio::test]
    async fn dropping_a_permit_without_completing_it_releases_the_slot() {
        let g = DnsGovernor::pinned(2);
        {
            let _a = g.acquire().await;
            let _b = g.acquire().await;
            assert_eq!(g.in_flight(), 2);
        }
        assert_eq!(g.in_flight(), 0, "dropped permits did not release");
        // And the slots are genuinely reusable.
        let _c = g.acquire().await;
        assert_eq!(g.in_flight(), 1);
    }

    #[tokio::test]
    async fn shrinking_under_load_converges_and_never_wedges() {
        let g = DnsGovernor::new(32);
        // Occupy several slots, then demand a much smaller limit.
        let held: Vec<DnsPermit> = {
            let mut v = Vec::new();
            for _ in 0..8 {
                v.push(g.acquire().await);
            }
            v
        };
        g.apply_limit(MIN_LIMIT);
        assert_eq!(g.limit(), MIN_LIMIT);

        // Releasing the in-flight work lets the deferred shrink complete on later ticks.
        drop(held);
        for _ in 0..10 {
            g.resize(g.limit());
        }
        let available = g.semaphore.available_permits() as u32;
        assert!(
            available <= MIN_LIMIT,
            "after shrink, {available} permits remain available for a limit of {}",
            MIN_LIMIT
        );

        // Still functional: a permit can be acquired.
        let permit = g.acquire().await;
        permit.complete(DnsOutcome::Answered);
    }

    #[tokio::test]
    async fn growing_returns_capacity() {
        let g = DnsGovernor::new(32);
        assert_eq!(g.limit(), INITIAL_LIMIT);
        g.apply_limit(24);
        assert_eq!(g.limit(), 24);
        // 24 concurrent acquisitions must now succeed.
        let mut permits = Vec::new();
        for _ in 0..24 {
            permits.push(g.acquire().await);
        }
        assert_eq!(g.in_flight(), 24);
    }

    #[tokio::test]
    async fn recovers_after_a_collapse_and_climbs_again() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        for _ in 0..6 {
            allow_control_tick(&g);
            g.in_flight.store(g.limit(), Ordering::Relaxed);
            drive(&g, DnsOutcome::Answered, Duration::from_millis(5), 10);
        }
        let peak = g.limit();

        // Total collapse.
        drive(&g, DnsOutcome::TimedOut, Duration::from_secs(5), 40);
        let floor = g.limit();
        assert!(floor < peak, "did not back off: {floor} vs {peak}");
        assert!(floor >= MIN_LIMIT);

        // Network heals. Clear the cooldown and feed healthy samples.
        g.cooldown_until_ms.store(0, Ordering::Relaxed);
        for _ in 0..40 {
            allow_control_tick(&g);
            g.in_flight.store(g.limit(), Ordering::Relaxed);
            drive(&g, DnsOutcome::Answered, Duration::from_millis(5), 20);
        }
        assert!(
            g.limit() > floor,
            "did not recover: still at {} after healing",
            g.limit()
        );
    }

    /// Regression: an app-limited workload must not ratchet the limit *down* either. Accepting
    /// only downward moves while idle drives the limit to ~2x offered load, where it then sticks.
    #[test]
    fn app_limited_workload_does_not_ratchet_the_limit_down() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        g.in_slow_start.store(false, Ordering::Relaxed);
        g.apply_limit(40);
        let start = g.limit();

        // Steady healthy latency with jitter, but only a trickle of concurrency.
        let mut tick = 0u64;
        for _ in 0..200 {
            allow_control_tick(&g);
            g.in_flight.store(2, Ordering::Relaxed);
            tick += 1;
            let jitter = if tick.is_multiple_of(3) { 26 } else { 18 };
            drive(&g, DnsOutcome::Answered, Duration::from_millis(jitter), 5);
        }
        assert_eq!(
            g.limit(),
            start,
            "app-limited load ratcheted the limit from {start} to {}",
            g.limit()
        );
    }

    /// Wave-1 falsifier (defects C/G): a permit's lifetime — which contains every queue the
    /// lookup waited in — must contribute NOTHING to the RTT baselines. Only an explicit leaf
    /// sample moves them. Red on the old code, where `complete()` fed `started.elapsed()` into
    /// the averages and our own queueing read as network congestion.
    #[tokio::test]
    async fn permit_lifetime_is_excluded_from_the_governor_rtt_sample() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        let permit = g.acquire().await;
        // Hold the permit long enough that its lifetime would be an unmistakable sample.
        tokio::time::sleep(Duration::from_millis(30)).await;
        permit.complete(DnsOutcome::Answered);
        assert_eq!(
            g.latency_samples.load(Ordering::Relaxed),
            0,
            "completing a permit must not create a latency sample"
        );

        // The leaf exchange is the only latency source.
        g.record_rtt(Duration::from_millis(50));
        let recent = f64::from_bits(g.rtt_recent_us.load(Ordering::Relaxed));
        assert!(
            (recent - 50_000.0).abs() < 1.0,
            "the first leaf sample seeds the baseline exactly; got {recent}µs"
        );
    }

    /// The RTO abstains until it has enough leaf samples to mean something.
    #[test]
    fn rto_is_none_until_enough_leaf_samples() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        assert!(g.rto().is_none());
        for _ in 0..(MIN_SAMPLES_FOR_RTO - 1) {
            g.record_rtt(Duration::from_millis(40));
        }
        assert!(
            g.rto().is_none(),
            "one short of the floor must still abstain"
        );
        g.record_rtt(Duration::from_millis(40));
        assert!(g.rto().is_some());
    }

    /// RFC 6298 shape above the floor: steady samples give an RTO just above the RTT; jitter
    /// widens it. This is what floors the per-attempt DoH budget at "what a real answer
    /// plausibly takes here".
    #[test]
    fn rto_tracks_recent_rtt_plus_deviation() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        for _ in 0..40 {
            g.record_rtt(Duration::from_millis(1200));
        }
        let steady = g.rto().expect("enough samples");
        assert!(
            steady >= Duration::from_millis(1200) && steady < Duration::from_millis(4000),
            "steady 1.2s samples must yield an RTO near-but-above 1.2s, got {steady:?}"
        );

        for i in 0..40u64 {
            let jitter = if i % 2 == 0 { 600 } else { 2400 };
            g.record_rtt(Duration::from_millis(jitter));
        }
        let jittery = g.rto().expect("still enough samples");
        assert!(
            jittery > steady,
            "jitter must widen the RTO ({steady:?} → {jittery:?}), or slow-but-real answers get \
             cancelled by their own budget"
        );
    }

    /// RFC 6298 §2.4: the RTO never computes below one second, however fast the network — a
    /// sub-second budget turns ordinary DNS tail latency into chronic attempt timeouts (the r2
    /// validation A/B measured 10 false DoH demotions born exactly this way).
    #[test]
    fn rto_is_floored_at_one_second() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        for _ in 0..40 {
            g.record_rtt(Duration::from_millis(50));
        }
        assert_eq!(g.rto(), Some(MIN_RTO));
    }

    /// Wave-2 falsifier (7a): one correlated wave of congestion signals applies exactly ONE
    /// multiplicative decrease. 64 permits that all started before any reaction, all failing
    /// together, must move the limit 64 → 44 — never 0.7^64 → the floor.
    #[test]
    fn a_correlated_wave_of_signals_decreases_the_limit_exactly_once() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        g.apply_limit(DEFAULT_MAX_LIMIT);
        let wave_start = Instant::now();
        for _ in 0..64 {
            g.record(DnsOutcome::TimedOut, wave_start);
        }
        let stats = g.stats();
        assert_eq!(
            stats.backoff_events, 1,
            "one epoch, one decrease — got {} decreases",
            stats.backoff_events
        );
        assert_eq!(stats.congestion_signals, 64, "every signal still counts");
        assert_eq!(
            g.limit(),
            (DEFAULT_MAX_LIMIT as f64 * 0.7).floor() as u32,
            "one multiplicative step from the ceiling, not a collapse to the floor"
        );

        // A signal from a permit granted AFTER the decrease opens a new epoch. The epoch marker
        // is millisecond-granular, so step past the decrease's millisecond first.
        std::thread::sleep(Duration::from_millis(3));
        let fresh = Instant::now();
        g.record(DnsOutcome::TimedOut, fresh);
        assert_eq!(
            g.stats().backoff_events,
            2,
            "a fresh permit's failure opens a new epoch"
        );
    }

    /// Wave-2 test (7c): the sqrt-headroom probe climbs the governor from the floor back to the
    /// ceiling within ~15 s of clean, saturated ticks — "dead at 2" must be a transient, never a
    /// resting state. Ticks are forced (allow_control_tick) so the test measures the climb's
    /// TICK COUNT, the deterministic analogue of the wall-clock claim (a tick fires at most
    /// every 250 ms, so <= 60 ticks == <= 15 s).
    #[test]
    fn a_governor_at_the_floor_climbs_back_to_the_ceiling_in_bounded_clean_ticks() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        g.in_slow_start.store(false, Ordering::Relaxed);
        g.apply_limit(MIN_LIMIT);
        g.cooldown_until_ms.store(0, Ordering::Relaxed);
        // Establish a healthy baseline so the gradient reads 1.0.
        for _ in 0..30 {
            g.record_rtt(Duration::from_millis(20));
        }
        let mut ticks = 0;
        while g.limit() < DEFAULT_MAX_LIMIT && ticks < 60 {
            allow_control_tick(&g);
            g.in_flight.store(g.limit(), Ordering::Relaxed);
            drive(&g, DnsOutcome::Answered, Duration::from_millis(20), 3);
            ticks += 1;
        }
        assert_eq!(
            g.limit(),
            DEFAULT_MAX_LIMIT,
            "still at {} after {ticks} clean saturated ticks (~{}s wall)",
            g.limit(),
            ticks / 4
        );
    }

    /// The breaker's no-response discriminator: only an un-pinned governor parked at its floor
    /// counts as "retreated" — a pinned governor never does, so timeout evidence can never latch
    /// a breaker under --dns-max-concurrency (defect H's mechanism).
    #[test]
    fn floor_retreat_is_only_claimed_by_an_adaptive_governor_at_the_floor() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        assert!(!g.has_retreated_to_floor(), "fresh governor is above floor");
        g.apply_limit(MIN_LIMIT);
        assert!(g.has_retreated_to_floor());

        let pinned = DnsGovernor::pinned(MIN_LIMIT);
        assert!(
            !pinned.has_retreated_to_floor(),
            "a pinned governor never 'retreats' — the user chose the limit"
        );
    }

    #[tokio::test]
    async fn idle_workload_does_not_inflate_the_limit() {
        let g = DnsGovernor::new(DEFAULT_MAX_LIMIT);
        let start = g.limit();
        // Plenty of healthy samples, but nothing in flight — the limit must not chase a load that
        // is not there.
        for _ in 0..20 {
            allow_control_tick(&g);
            g.in_flight.store(0, Ordering::Relaxed);
            drive(&g, DnsOutcome::Answered, Duration::from_millis(5), 10);
        }
        assert_eq!(g.limit(), start, "limit grew while the scan was idle");
    }
}
