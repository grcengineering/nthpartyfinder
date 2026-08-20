//! Scan-lifetime DNS attribution telemetry (Phase 0 of the DNS-flapping investigation).
//!
//! `perf::METRICS` answers "how much"; this module answers "which provider / which tier / which
//! stage / why". It exists because four DNS-reliability incidents in a row ended with the same
//! sentence — "not yet localized" — and the counters needed to localize them did not exist: the
//! per-provider failure log was write-only, the highest-volume lookup path had no timer, a
//! wrapper-cancelled attempt vanished without a trace, and a transport demotion recorded neither
//! the governor's state nor which providers were implicated at the moment it fired.
//!
//! Everything here is observation only: fixed-size `Relaxed` atomics on the hot paths, a small
//! mutex-guarded ring for rare events (demotions, recoveries, sampled failures), and nothing that
//! influences control flow. The whole struct serializes into the `scan-summary.json` sidecar so
//! every scan leaves its diagnosis on disk (`Plans/zesty-tinkering-falcon.md` §Phase 0).

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::dns_governor::GovernorSample;

/// Histogram bucket upper edges in milliseconds; the last bucket is open-ended.
///
/// Chosen to resolve the timescales the investigation cares about: sub-100ms healthy DoH RTT,
/// the 200/400/500ms backoff sleeps, the 3s per-attempt and wrapper timeouts, and the 4s/5s
/// DoT/connect budgets. p50/p95 estimates interpolate within a bucket — ±one bucket of
/// precision, which is adequate against 3s-class thresholds.
pub const HIST_EDGES_MS: [u64; 21] = [
    5, 10, 20, 35, 50, 75, 100, 150, 200, 300, 400, 500, 750, 1000, 1500, 2000, 2500, 3000, 4000,
    5000, 8000,
];

/// Bucket count: one per edge plus the open-ended tail.
pub const HIST_BUCKETS: usize = HIST_EDGES_MS.len() + 1;

/// A fixed-bucket latency histogram updated from many threads.
#[derive(Debug)]
pub struct Hist {
    buckets: [AtomicU64; HIST_BUCKETS],
}

impl Hist {
    const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; HIST_BUCKETS],
        }
    }

    fn bucket_for(ms: u64) -> usize {
        HIST_EDGES_MS
            .iter()
            .position(|&edge| ms <= edge)
            .unwrap_or(HIST_BUCKETS - 1)
    }

    /// Record one observation.
    pub fn record(&self, d: Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        self.buckets[Self::bucket_for(ms)].fetch_add(1, Ordering::Relaxed);
    }

    /// Raw bucket counts.
    pub fn counts(&self) -> [u64; HIST_BUCKETS] {
        std::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed))
    }

    /// Approximate percentile in ms (upper edge of the bucket containing it); `None` when empty.
    pub fn percentile_ms(&self, p: f64) -> Option<u64> {
        let counts = self.counts();
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return None;
        }
        let rank = ((total as f64) * p).ceil().max(1.0) as u64;
        let mut seen = 0u64;
        for (i, &c) in counts.iter().enumerate() {
            seen += c;
            if seen >= rank {
                return Some(HIST_EDGES_MS.get(i).copied().unwrap_or(u64::MAX));
            }
        }
        Some(u64::MAX)
    }
}

/// Per-DoH-provider attempt outcomes. Indexed by the pool's `server_index`; slot 7 saturates so
/// a mis-sized config can never write out of bounds.
#[derive(Debug)]
pub struct ProviderStats {
    pub attempts: AtomicU64,
    pub ok: AtomicU64,
    pub http_429: AtomicU64,
    pub http_5xx: AtomicU64,
    pub http_4xx_other: AtomicU64,
    pub non_dnsjson_2xx: AtomicU64,
    /// 2xx dns-json with RCODE ∉ {0,3} — the DNS_NAME class (a working transport).
    pub rcode_fail: AtomicU64,
    /// The attempt's own timeout fired while it was still queued for the connection permit —
    /// no packet was ever sent. Hypothesis C in a single counter.
    pub timeout_before_send: AtomicU64,
    /// The attempt's timeout fired after the send started — a genuine slow/no answer.
    pub timeout_after_send: AtomicU64,
    pub connect_err: AtomicU64,
    pub other_err: AtomicU64,
    /// EMFILE/ENFILE — local FD exhaustion misclassified as provider failure in a prior incident.
    pub local_resource_err: AtomicU64,
    /// Time this provider's attempts spent waiting for the global connection permit.
    pub permit_wait: Hist,
    /// Time from send actually starting to the response (permit wait excluded).
    pub rtt: Hist,
}

impl ProviderStats {
    const fn new() -> Self {
        Self {
            attempts: AtomicU64::new(0),
            ok: AtomicU64::new(0),
            http_429: AtomicU64::new(0),
            http_5xx: AtomicU64::new(0),
            http_4xx_other: AtomicU64::new(0),
            non_dnsjson_2xx: AtomicU64::new(0),
            rcode_fail: AtomicU64::new(0),
            timeout_before_send: AtomicU64::new(0),
            timeout_after_send: AtomicU64::new(0),
            connect_err: AtomicU64::new(0),
            other_err: AtomicU64::new(0),
            local_resource_err: AtomicU64::new(0),
            permit_wait: Hist::new(),
            rtt: Hist::new(),
        }
    }
}

/// The three transport tiers of the fallback ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Doh,
    Dot,
    Udp53,
}

impl Tier {
    pub const fn name(self) -> &'static str {
        match self {
            Tier::Doh => "doh",
            Tier::Dot => "dot",
            Tier::Udp53 => "udp53",
        }
    }
    const fn idx(self) -> usize {
        self as usize
    }
}

/// Per-transport-tier outcomes and ladder events.
#[derive(Debug)]
pub struct TierStats {
    pub attempts: AtomicU64,
    pub answered: AtomicU64,
    pub empty: AtomicU64,
    pub transport_failed: AtomicU64,
    /// The tier's budget expired while still queued for the connection permit — the failure was
    /// manufactured by our own semaphore, not the network (hypothesis C, ladder half).
    pub permit_starved: AtomicU64,
    pub skipped_breaker: AtomicU64,
    /// UDP/53 only: admission shed by the hard token budget.
    pub skipped_budget: AtomicU64,
    pub demotions: AtomicU64,
    pub recoveries: AtomicU64,
    pub reprobes: AtomicU64,
    pub permit_wait: Hist,
    pub rtt: Hist,
}

impl TierStats {
    const fn new() -> Self {
        Self {
            attempts: AtomicU64::new(0),
            answered: AtomicU64::new(0),
            empty: AtomicU64::new(0),
            transport_failed: AtomicU64::new(0),
            permit_starved: AtomicU64::new(0),
            skipped_breaker: AtomicU64::new(0),
            skipped_budget: AtomicU64::new(0),
            demotions: AtomicU64::new(0),
            recoveries: AtomicU64::new(0),
            reprobes: AtomicU64::new(0),
            permit_wait: Hist::new(),
            rtt: Hist::new(),
        }
    }
}

/// The four logical lookup paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupPath {
    RootTxt,
    RootCname,
    FastTxt,
    FastCname,
}

impl LookupPath {
    pub const ALL: [LookupPath; 4] = [
        LookupPath::RootTxt,
        LookupPath::RootCname,
        LookupPath::FastTxt,
        LookupPath::FastCname,
    ];
    pub const fn name(self) -> &'static str {
        match self {
            LookupPath::RootTxt => "root_txt",
            LookupPath::RootCname => "root_cname",
            LookupPath::FastTxt => "fast_txt",
            LookupPath::FastCname => "fast_cname",
        }
    }
    const fn idx(self) -> usize {
        self as usize
    }
}

/// How a logical lookup ended — exactly one terminal stage per lookup arm.
///
/// The Σ-stages-equals-lookups invariant is what makes "TimedOut" diagnosable: every wrapper
/// timeout, ladder descent, memo replay and silent-empty path lands in a named bucket instead of
/// disappearing into an undifferentiated failure count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalStage {
    MemoHit,
    MemoNegHit,
    DohOkA1,
    DohOkA2,
    DohOkA3Plus,
    DohNameFail,
    DohExhaustedLadderOk,
    DohExhaustedLadderEmpty,
    DohExhaustedLadderFail,
    WrapperTimeoutLadderOk,
    WrapperTimeoutLadderEmpty,
    WrapperTimeoutLadderFail,
    /// The root-CNAME wrapper-timeout arm that returns `Ok(vec![])` uncounted today — named so
    /// the visibility-contract violation is measurable before Wave 1 fixes it.
    WrapperTimeoutSilentEmpty,
    DohSkippedLadder,
    RootUdpArmWon,
    SystemOk,
    SystemFail,
}

impl TerminalStage {
    pub const ALL: [TerminalStage; 17] = [
        TerminalStage::MemoHit,
        TerminalStage::MemoNegHit,
        TerminalStage::DohOkA1,
        TerminalStage::DohOkA2,
        TerminalStage::DohOkA3Plus,
        TerminalStage::DohNameFail,
        TerminalStage::DohExhaustedLadderOk,
        TerminalStage::DohExhaustedLadderEmpty,
        TerminalStage::DohExhaustedLadderFail,
        TerminalStage::WrapperTimeoutLadderOk,
        TerminalStage::WrapperTimeoutLadderEmpty,
        TerminalStage::WrapperTimeoutLadderFail,
        TerminalStage::WrapperTimeoutSilentEmpty,
        TerminalStage::DohSkippedLadder,
        TerminalStage::RootUdpArmWon,
        TerminalStage::SystemOk,
        TerminalStage::SystemFail,
    ];
    pub const fn name(self) -> &'static str {
        match self {
            TerminalStage::MemoHit => "memo_hit",
            TerminalStage::MemoNegHit => "memo_neg_hit",
            TerminalStage::DohOkA1 => "doh_ok_a1",
            TerminalStage::DohOkA2 => "doh_ok_a2",
            TerminalStage::DohOkA3Plus => "doh_ok_a3plus",
            TerminalStage::DohNameFail => "doh_name_fail",
            TerminalStage::DohExhaustedLadderOk => "doh_exhausted_ladder_ok",
            TerminalStage::DohExhaustedLadderEmpty => "doh_exhausted_ladder_empty",
            TerminalStage::DohExhaustedLadderFail => "doh_exhausted_ladder_fail",
            TerminalStage::WrapperTimeoutLadderOk => "wrapper_timeout_ladder_ok",
            TerminalStage::WrapperTimeoutLadderEmpty => "wrapper_timeout_ladder_empty",
            TerminalStage::WrapperTimeoutLadderFail => "wrapper_timeout_ladder_fail",
            TerminalStage::WrapperTimeoutSilentEmpty => "wrapper_timeout_silent_empty",
            TerminalStage::DohSkippedLadder => "doh_skipped_ladder",
            TerminalStage::RootUdpArmWon => "root_udp_arm_won",
            TerminalStage::SystemOk => "system_ok",
            TerminalStage::SystemFail => "system_fail",
        }
    }
    const fn idx(self) -> usize {
        self as usize
    }
}

/// Where a `dns_failures` increment came from — one slot per increment site, so the summary can
/// derive `inflation = dns_failures / distinct terminal failures` and the double-increment on the
/// root negative-memo path is directly visible (defect E).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureSite {
    DohTxtThrottle,
    DohTxtEndpoint,
    DohTxtNonJson,
    DohTxtName,
    DohCnameThrottle,
    DohCnameEndpoint,
    DohCnameNonJson,
    DohCnameName,
    ResilientTransport,
    ResilientLocalResource,
    SettleArm,
    RootNegativeMemoExtra,
    RootAllFailed,
    CnameAllThrottled,
}

impl FailureSite {
    pub const ALL: [FailureSite; 14] = [
        FailureSite::DohTxtThrottle,
        FailureSite::DohTxtEndpoint,
        FailureSite::DohTxtNonJson,
        FailureSite::DohTxtName,
        FailureSite::DohCnameThrottle,
        FailureSite::DohCnameEndpoint,
        FailureSite::DohCnameNonJson,
        FailureSite::DohCnameName,
        FailureSite::ResilientTransport,
        FailureSite::ResilientLocalResource,
        FailureSite::SettleArm,
        FailureSite::RootNegativeMemoExtra,
        FailureSite::RootAllFailed,
        FailureSite::CnameAllThrottled,
    ];
    pub const fn name(self) -> &'static str {
        match self {
            FailureSite::DohTxtThrottle => "doh_txt_throttle",
            FailureSite::DohTxtEndpoint => "doh_txt_endpoint",
            FailureSite::DohTxtNonJson => "doh_txt_non_json",
            FailureSite::DohTxtName => "doh_txt_name",
            FailureSite::DohCnameThrottle => "doh_cname_throttle",
            FailureSite::DohCnameEndpoint => "doh_cname_endpoint",
            FailureSite::DohCnameNonJson => "doh_cname_non_json",
            FailureSite::DohCnameName => "doh_cname_name",
            FailureSite::ResilientTransport => "resilient_transport",
            FailureSite::ResilientLocalResource => "resilient_local_resource",
            FailureSite::SettleArm => "settle_arm",
            FailureSite::RootNegativeMemoExtra => "root_negative_memo_extra",
            FailureSite::RootAllFailed => "root_all_failed",
            FailureSite::CnameAllThrottled => "cname_all_throttled",
        }
    }
    const fn idx(self) -> usize {
        self as usize
    }
}

/// Which phase of an attempt a wrapper cancellation caught it in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptPhase {
    PermitWait,
    InFlight,
    BackoffSleep,
}

impl AttemptPhase {
    pub const ALL: [AttemptPhase; 3] = [
        AttemptPhase::PermitWait,
        AttemptPhase::InFlight,
        AttemptPhase::BackoffSleep,
    ];
    pub const fn name(self) -> &'static str {
        match self {
            AttemptPhase::PermitWait => "permit_wait",
            AttemptPhase::InFlight => "in_flight",
            AttemptPhase::BackoffSleep => "backoff_sleep",
        }
    }
    const fn idx(self) -> usize {
        self as usize
    }
}

/// A stack guard armed around one DoH rotation attempt: if the enclosing future is cancelled
/// (the outer lookup wrapper timing out) before [`AttemptProbe::disarm`] is called, the drop
/// records WHERE the cancellation caught the attempt — the observation defect A's "cancelled
/// attempts vanish uncounted" made impossible before.
#[derive(Debug)]
pub struct AttemptProbe {
    pub idx: usize,
    pub phase: AttemptPhase,
    done: bool,
}

impl AttemptProbe {
    pub fn new(idx: usize) -> Self {
        Self {
            idx,
            phase: AttemptPhase::InFlight,
            done: false,
        }
    }
    /// The attempt reached a real outcome (success or classified failure) — not a cancellation.
    pub fn disarm(&mut self) {
        self.done = true;
    }
}

impl Drop for AttemptProbe {
    fn drop(&mut self) {
        if !self.done {
            DNS_TELEMETRY.attempt_cancelled(self.phase, self.idx);
        }
    }
}

/// A rare, cause-bearing event kept in the bounded ring (and, when a sink is installed, streamed
/// to `scan-events.jsonl`).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Demotion {
        t_ms: u64,
        tier: Tier,
        cause: &'static str,
        consecutive_failures: u32,
        streak_ms: u64,
        implicated_mask: u64,
        governor: GovernorSample,
        conn_cap: usize,
        conn_available: usize,
    },
    Recovery {
        t_ms: u64,
        tier: Tier,
    },
    LookupFailed {
        t_ms: u64,
        name: String,
        path: LookupPath,
        stage: TerminalStage,
        elapsed_ms: u64,
        governor_limit: u32,
        conn_available: usize,
    },
}

/// Cap on the event ring — demotions and recoveries are rare; sampled failures are bounded below.
const EVENT_RING_CAP: usize = 512;
/// Keep the first N failed-lookup events, then 1-in-64 thereafter.
const FAILED_SAMPLE_HEAD: u64 = 200;
const FAILED_SAMPLE_STRIDE: u64 = 64;
/// Cap on the distinct all-failed-name set.
const FAILED_NAME_SET_CAP: usize = 1000;

/// The process-wide DNS attribution state. One scan per process (batch mode builds a fresh pool
/// but shares this — acceptable: batch entries are sequential and the summary is per-process).
#[derive(Debug)]
pub struct DnsTelemetry {
    pub providers: [ProviderStats; 8],
    tiers: [TierStats; 3],
    terminal: [[AtomicU64; 17]; 4],
    pub doh_ok_at_attempt: [AtomicU64; 4],
    doh_cancelled_at: [[AtomicU64; 4]; 3],
    pub answered_with_sleep: AtomicU64,
    failure_sites: [AtomicU64; 14],
    events: Mutex<Vec<Event>>,
    failed_lookup_seen: AtomicU64,
    failed_names: Mutex<BTreeSet<String>>,
    /// Epoch for event `t_ms` stamps; installed once at scan start (0 = uninstalled, stamps are 0).
    epoch_ms: AtomicU64,
}

impl DnsTelemetry {
    const fn new() -> Self {
        Self {
            providers: [const { ProviderStats::new() }; 8],
            tiers: [const { TierStats::new() }; 3],
            terminal: [const { [const { AtomicU64::new(0) }; 17] }; 4],
            doh_ok_at_attempt: [const { AtomicU64::new(0) }; 4],
            doh_cancelled_at: [const { [const { AtomicU64::new(0) }; 4] }; 3],
            answered_with_sleep: AtomicU64::new(0),
            failure_sites: [const { AtomicU64::new(0) }; 14],
            events: Mutex::new(Vec::new()),
            failed_lookup_seen: AtomicU64::new(0),
            failed_names: Mutex::new(BTreeSet::new()),
            epoch_ms: AtomicU64::new(0),
        }
    }

    /// Install the scan-start epoch so event `t_ms` stamps are scan-relative. Idempotent-enough:
    /// last writer wins, which for one scan per process is the only writer.
    pub fn install_epoch(&self, unix_ms: u64) {
        self.epoch_ms.store(unix_ms, Ordering::Relaxed);
    }

    fn t_ms(&self) -> u64 {
        let epoch = self.epoch_ms.load(Ordering::Relaxed);
        if epoch == 0 {
            return 0;
        }
        now_unix_ms().saturating_sub(epoch)
    }

    /// The provider slot for `server_index` (slot 7 saturates).
    pub fn provider(&self, server_index: usize) -> &ProviderStats {
        &self.providers[server_index.min(7)]
    }

    pub fn tier(&self, tier: Tier) -> &TierStats {
        &self.tiers[tier.idx()]
    }

    /// Record a lookup arm's terminal stage.
    pub fn terminal(&self, path: LookupPath, stage: TerminalStage) {
        self.terminal[path.idx()][stage.idx()].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a wrapper-cancelled attempt (from the `AttemptProbe` drop guard in the resilient
    /// loops): which phase it was in, at which rotation index.
    pub fn attempt_cancelled(&self, phase: AttemptPhase, attempt_idx: usize) {
        self.doh_cancelled_at[phase.idx()][attempt_idx.min(3)].fetch_add(1, Ordering::Relaxed);
        crate::perf::METRICS.dns_attempt_cancelled.hit();
    }

    /// Record a DoH success at rotation index `attempt_idx`.
    pub fn ok_at_attempt(&self, attempt_idx: usize) {
        self.doh_ok_at_attempt[attempt_idx.min(3)].fetch_add(1, Ordering::Relaxed);
    }

    /// Mirror one `dns_failures` increment with its site, so inflation is decomposable.
    pub fn failure_site(&self, site: FailureSite) {
        self.failure_sites[site.idx()].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rare event into the bounded ring.
    pub fn event(&self, event: Event) {
        if let Ok(mut ring) = self.events.lock() {
            if ring.len() < EVENT_RING_CAP {
                ring.push(event);
            }
        }
    }

    /// Convenience stamps for event constructors.
    pub fn now_t_ms(&self) -> u64 {
        self.t_ms()
    }

    /// Sampled record of a lookup that ended in failure: first 200, then 1/64. Also folds the
    /// name into the bounded distinct-failure set that `recheck-names.sh` re-resolves.
    pub fn lookup_failed(
        &self,
        name: &str,
        path: LookupPath,
        stage: TerminalStage,
        elapsed: Duration,
        governor_limit: u32,
        conn_available: usize,
    ) {
        if let Ok(mut set) = self.failed_names.lock() {
            if set.len() < FAILED_NAME_SET_CAP {
                set.insert(name.to_ascii_lowercase());
            }
        }
        let n = self.failed_lookup_seen.fetch_add(1, Ordering::Relaxed);
        if n >= FAILED_SAMPLE_HEAD && !n.is_multiple_of(FAILED_SAMPLE_STRIDE) {
            return;
        }
        self.event(Event::LookupFailed {
            t_ms: self.t_ms(),
            name: name.to_string(),
            path,
            stage,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            governor_limit,
            conn_available,
        });
    }

    /// Serialize the whole state for the scan summary. `provider_names` maps `server_index` to a
    /// display name; missing entries render as `provider-N`.
    pub fn snapshot(&self, provider_names: &[String]) -> Snapshot {
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let providers = self
            .providers
            .iter()
            .enumerate()
            .filter(|(_, p)| load(&p.attempts) > 0)
            .map(|(i, p)| ProviderRow {
                name: provider_names
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| format!("provider-{i}")),
                attempts: load(&p.attempts),
                ok: load(&p.ok),
                http_429: load(&p.http_429),
                http_5xx: load(&p.http_5xx),
                http_4xx_other: load(&p.http_4xx_other),
                non_dnsjson_2xx: load(&p.non_dnsjson_2xx),
                rcode_fail: load(&p.rcode_fail),
                timeout_before_send: load(&p.timeout_before_send),
                timeout_after_send: load(&p.timeout_after_send),
                connect_err: load(&p.connect_err),
                other_err: load(&p.other_err),
                local_resource_err: load(&p.local_resource_err),
                permit_wait_p50_ms: p.permit_wait.percentile_ms(0.50),
                permit_wait_p95_ms: p.permit_wait.percentile_ms(0.95),
                rtt_p50_ms: p.rtt.percentile_ms(0.50),
                rtt_p95_ms: p.rtt.percentile_ms(0.95),
                permit_wait_hist: p.permit_wait.counts().to_vec(),
                rtt_hist: p.rtt.counts().to_vec(),
            })
            .collect();
        let tiers = [Tier::Doh, Tier::Dot, Tier::Udp53]
            .into_iter()
            .map(|t| {
                let s = self.tier(t);
                TierRow {
                    name: t.name(),
                    attempts: load(&s.attempts),
                    answered: load(&s.answered),
                    empty: load(&s.empty),
                    transport_failed: load(&s.transport_failed),
                    permit_starved: load(&s.permit_starved),
                    skipped_breaker: load(&s.skipped_breaker),
                    skipped_budget: load(&s.skipped_budget),
                    demotions: load(&s.demotions),
                    recoveries: load(&s.recoveries),
                    reprobes: load(&s.reprobes),
                    permit_wait_p95_ms: s.permit_wait.percentile_ms(0.95),
                    rtt_p95_ms: s.rtt.percentile_ms(0.95),
                }
            })
            .collect();
        let terminal = LookupPath::ALL
            .iter()
            .map(|&path| {
                let stages = TerminalStage::ALL
                    .iter()
                    .filter_map(|&stage| {
                        let n = self.terminal[path.idx()][stage.idx()].load(Ordering::Relaxed);
                        (n > 0).then(|| (stage.name().to_string(), n))
                    })
                    .collect();
                (path.name().to_string(), stages)
            })
            .collect();
        let failure_sites = FailureSite::ALL
            .iter()
            .filter_map(|&site| {
                let n = self.failure_sites[site.idx()].load(Ordering::Relaxed);
                (n > 0).then(|| (site.name().to_string(), n))
            })
            .collect();
        Snapshot {
            providers,
            tiers,
            terminal,
            doh_ok_at_attempt: std::array::from_fn(|i| load(&self.doh_ok_at_attempt[i])),
            doh_cancelled_at: AttemptPhase::ALL
                .iter()
                .map(|&ph| {
                    (
                        ph.name().to_string(),
                        std::array::from_fn(|i| load(&self.doh_cancelled_at[ph.idx()][i])),
                    )
                })
                .collect(),
            answered_with_sleep: load(&self.answered_with_sleep),
            failure_sites,
            events: self.events.lock().map(|e| e.clone()).unwrap_or_default(),
            failed_names_sample: self
                .failed_names
                .lock()
                .map(|s| {
                    let mut v: Vec<String> = s.iter().cloned().collect();
                    v.sort();
                    v.truncate(FAILED_SAMPLE_HEAD as usize);
                    v
                })
                .unwrap_or_default(),
        }
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// One provider's serialized row (histograms included raw; percentiles precomputed).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderRow {
    pub name: String,
    pub attempts: u64,
    pub ok: u64,
    pub http_429: u64,
    pub http_5xx: u64,
    pub http_4xx_other: u64,
    pub non_dnsjson_2xx: u64,
    pub rcode_fail: u64,
    pub timeout_before_send: u64,
    pub timeout_after_send: u64,
    pub connect_err: u64,
    pub other_err: u64,
    pub local_resource_err: u64,
    pub permit_wait_p50_ms: Option<u64>,
    pub permit_wait_p95_ms: Option<u64>,
    pub rtt_p50_ms: Option<u64>,
    pub rtt_p95_ms: Option<u64>,
    pub permit_wait_hist: Vec<u64>,
    pub rtt_hist: Vec<u64>,
}

/// One tier's serialized row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TierRow {
    pub name: &'static str,
    pub attempts: u64,
    pub answered: u64,
    pub empty: u64,
    pub transport_failed: u64,
    pub permit_starved: u64,
    pub skipped_breaker: u64,
    pub skipped_budget: u64,
    pub demotions: u64,
    pub recoveries: u64,
    pub reprobes: u64,
    pub permit_wait_p95_ms: Option<u64>,
    pub rtt_p95_ms: Option<u64>,
}

/// The full serialized telemetry state for `scan-summary.json`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Snapshot {
    pub providers: Vec<ProviderRow>,
    pub tiers: Vec<TierRow>,
    /// path name → (stage name → count), zero stages omitted.
    pub terminal: Vec<(String, Vec<(String, u64)>)>,
    pub doh_ok_at_attempt: [u64; 4],
    /// phase name → per-attempt-index cancellations.
    pub doh_cancelled_at: Vec<(String, [u64; 4])>,
    pub answered_with_sleep: u64,
    pub failure_sites: Vec<(String, u64)>,
    pub events: Vec<Event>,
    pub failed_names_sample: Vec<String>,
}

/// The process-wide instance.
pub static DNS_TELEMETRY: DnsTelemetry = DnsTelemetry::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_buckets_cover_the_edges_and_the_open_tail() {
        assert_eq!(Hist::bucket_for(0), 0);
        assert_eq!(Hist::bucket_for(5), 0);
        assert_eq!(Hist::bucket_for(6), 1);
        assert_eq!(Hist::bucket_for(8000), HIST_BUCKETS - 2);
        assert_eq!(Hist::bucket_for(8001), HIST_BUCKETS - 1);
        assert_eq!(Hist::bucket_for(u64::MAX), HIST_BUCKETS - 1);
    }

    #[test]
    fn histogram_percentile_lands_in_the_right_bucket() {
        let h = Hist::new();
        for _ in 0..90 {
            h.record(Duration::from_millis(40)); // bucket edge 50
        }
        for _ in 0..10 {
            h.record(Duration::from_millis(2900)); // bucket edge 3000
        }
        assert_eq!(h.percentile_ms(0.50), Some(50));
        assert_eq!(h.percentile_ms(0.95), Some(3000));
        let empty = Hist::new();
        assert_eq!(empty.percentile_ms(0.95), None);
    }

    #[test]
    fn every_terminal_stage_and_failure_site_has_a_distinct_index_and_name() {
        let mut stage_names: Vec<&str> = TerminalStage::ALL.iter().map(|s| s.name()).collect();
        stage_names.sort();
        stage_names.dedup();
        assert_eq!(stage_names.len(), TerminalStage::ALL.len());
        let mut site_names: Vec<&str> = FailureSite::ALL.iter().map(|s| s.name()).collect();
        site_names.sort();
        site_names.dedup();
        assert_eq!(site_names.len(), FailureSite::ALL.len());
    }

    #[test]
    fn provider_slot_saturates_instead_of_indexing_out_of_bounds() {
        let t = DnsTelemetry::new();
        t.provider(200).attempts.fetch_add(1, Ordering::Relaxed);
        assert_eq!(t.providers[7].attempts.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn failed_lookup_sampling_keeps_the_head_and_strides_the_tail() {
        let t = DnsTelemetry::new();
        for i in 0..(FAILED_SAMPLE_HEAD + FAILED_SAMPLE_STRIDE * 3) {
            t.lookup_failed(
                &format!("host{i}.example"),
                LookupPath::FastTxt,
                TerminalStage::SystemFail,
                Duration::from_millis(10),
                8,
                100,
            );
        }
        let snap = t.snapshot(&[]);
        let sampled = snap
            .events
            .iter()
            .filter(|e| matches!(e, Event::LookupFailed { .. }))
            .count() as u64;
        // Head fully kept, tail sampled 1/64.
        assert_eq!(sampled, FAILED_SAMPLE_HEAD + 3);
        // The distinct-name set holds everything up to its cap regardless of sampling.
        assert_eq!(
            snap.failed_names_sample.len() as u64,
            FAILED_SAMPLE_HEAD.min(FAILED_NAME_SET_CAP as u64)
        );
    }

    #[test]
    fn snapshot_omits_untouched_providers_and_zero_stages() {
        let t = DnsTelemetry::new();
        t.provider(2).attempts.fetch_add(3, Ordering::Relaxed);
        t.terminal(LookupPath::RootTxt, TerminalStage::MemoHit);
        let snap = t.snapshot(&["a".into(), "b".into(), "c".into()]);
        assert_eq!(snap.providers.len(), 1);
        assert_eq!(snap.providers[0].name, "c");
        let root = snap
            .terminal
            .iter()
            .find(|(p, _)| p == "root_txt")
            .expect("root_txt path present");
        assert_eq!(root.1, vec![("memo_hit".to_string(), 1)]);
    }

    #[test]
    fn the_whole_snapshot_serializes_to_json() {
        let t = DnsTelemetry::new();
        t.provider(0).attempts.fetch_add(1, Ordering::Relaxed);
        t.event(Event::Recovery {
            t_ms: 5,
            tier: Tier::Doh,
        });
        let json = serde_json::to_string(&t.snapshot(&["cloudflare".into()]))
            .expect("telemetry snapshot must serialize");
        assert!(json.contains("cloudflare"));
        assert!(json.contains("recovery"));
    }
}
