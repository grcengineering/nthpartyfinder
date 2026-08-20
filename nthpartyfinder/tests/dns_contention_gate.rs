//! Hermetic DNS contention gate (Plan Phase 3, L1 — lands with PR-0).
//!
//! Drives a PRODUCTION-SHAPED `DnsServerPool` (built via `DnsServerPool::from_config` from
//! the embedded default config) against a simulated 6-provider DoH farm
//! (`tests/common/doh_farm.rs`) under real 64-worker contention, and records every run's
//! measurements to `target/dns-contention/<profile>.json`.
//!
//! ## What is asserted in this PR
//!
//! Only invariants that must already hold on today's master (P0, P2, P5, P8). The other
//! profiles (P1, P3, P4, P6) RECORD their measurements and assert nothing numeric yet —
//! their current numbers are the honest baseline of today's defects, committed to
//! `tests/dns_contention/baseline.json`, and the post-fix ratchet tightens each profile in
//! the PR that fixes it (asserts become `<= baseline * 1.15`).
//!
//! ## Hermeticity contract (ZERO real-network traffic)
//!
//! * Every DoH URL is a wiremock loopback IP literal (or a bound-then-dropped loopback
//!   port for dead providers) — no bootstrap DNS lookup is ever needed to reach one.
//! * `cfg.dns.dns_servers = []` — the UDP/53 arm has no server to talk to and stays silent
//!   (`next_dns_server_indexed()` yields `None`).
//! * `.disable_dot()` — the DoT (853) tier is off, so a simulated DoH failure can never
//!   escalate into a real :853 connection to the hardcoded public `DOT_SERVERS`.
//! * The root path's LAST fallback, `try_system_dns_resolver` (src/dns.rs), IS a real
//!   network path with no test seam — so every gate lookup name carries a mid-label
//!   underscore (`nameNNN_h.gate.example`). `hickory_resolvable()` rejects such labels,
//!   which makes the root path return `Ok(vec![])` at its "Skipping hickory
//!   system-resolver fallback" guard BEFORE the system resolver is ever constructed
//!   (src/dns.rs:3178). The DoH JSON arm has no such limitation and resolves these names
//!   against the farm normally. Structural, not probabilistic: even a profile where every
//!   race fails (P5) cannot emit a system-resolver query.
//!
//! ## Serialization
//!
//! Profiles run strictly serially behind a tokio mutex: the farm, the governor, and the
//! transport breakers are per-profile, but the process shares the global connection-ceiling
//! semaphore (`http_client`) and the `DNS_TELEMETRY` static, and overlapping profiles would
//! contend for CPU and skew each other's latency measurements. For the same reason this
//! gate asserts only pool-local state (governor stats, transport snapshot, its own
//! counters, farm request counts) — never absolute process-global telemetry.
//!
//! ## Deliberately skipped in this PR
//!
//! * **P7 permit-starvation**: needs to manipulate the process-global connection-ceiling
//!   semaphore, which races every other test binary sharing it (and any in-process test in
//!   this binary). Follow-up: land with the Wave-2 fixes once the ceiling has an injectable
//!   seam.
//! * **P9 pinned-control** (`DnsGovernor::pinned`): a control profile for A/B-ing the
//!   adaptive governor; deferred with P7 so both arrive with the profiles they exist to
//!   compare against.
//!
//! `#[ignore]` is forbidden in this binary (the profiles ARE the gate).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::doh_farm::{Behavior, Farm, Profile, ProviderSpec};
use nthpartyfinder::config::{AppConfig, DohServerConfig};
use nthpartyfinder::dns::{self, DnsServerPool, TransportSnapshot};
use nthpartyfinder::dns_governor::{DnsGovernor, GovernorStats};

/// Serializes the profiles — see the module docs. tokio's mutex (not std's) so the guard is
/// held across `.await` without clippy's `await_holding_lock`, and so a panicking profile
/// releases (rather than poisons) the gate for the profiles after it.
static GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const LOGICAL_LOOKUPS: usize = 600;
const WORKERS: usize = 64;
const DISTINCT_NAMES: usize = 100;
const PER_PROFILE_TIMEOUT: Duration = Duration::from_secs(90);
/// Arbitrary but FIXED farm seed — determinism, not entropy, is the point.
const FARM_SEED: u64 = 0x0DDB_A5E5_EED5_EED5;

/// One profile run's recorded evidence — serialized to `target/dns-contention/<profile>.json`
/// (uploaded as a CI artifact by the Integration Tests job) and the source of
/// `tests/dns_contention/baseline.json`.
#[derive(serde::Serialize)]
struct Measurement {
    schema: u32,
    profile: String,
    wall_ms: u64,
    /// Driver shape, recorded so a future reader can interpret the numbers.
    logical_lookups: u64,
    distinct_names: u64,
    workers: u64,
    config_dns_qps: u32,
    /// Lookups whose TXT answer came back non-empty vs empty (600 total).
    lookups_with_records: u64,
    lookups_empty: u64,
    /// The pool's choke-point failure counters (fresh per profile; the general counter is
    /// wired BOTH as the pool's `with_failure_counter` sink and as every call's explicit
    /// `dns_failure_counter`, exactly as app.rs wires both to the logger's one atomic —
    /// including production's known double-count of negative-memo root hits (defect E)).
    dns_failures: u64,
    name_failures: u64,
    /// Requests each farm provider actually served, in provider order (dead providers: 0).
    provider_requests: Vec<u64>,
    governor: GovernorStats,
    transport: TransportSnapshot,
}

/// Distinct lookup names for one profile. Every label set carries a MID-LABEL UNDERSCORE
/// (`_h` suffix inside the first label) — the hermeticity keystone: `hickory_resolvable()`
/// is false for such names, so the root path's real-network system-resolver fallback is
/// structurally unreachable (see the module docs). The DoH farm answers them normally.
fn gate_names(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| format!("name{i:03}_h.gate.example"))
        .collect()
}

/// Production-shaped config pointed at the farm: embedded defaults, farm DoH URLs
/// (timeout_secs: 3, matching production's per-attempt budget), no UDP/53 servers, and a
/// governor-BINDING rate limit — 1000 qps means the token bucket (which starts full, so the
/// whole 600-lookup profile is never paced by it) can never be the constraint a profile
/// measures. The adaptive governor, breakers, rotation, and memo are the objects under
/// test; the production default of 50 qps would cap in-flight at ~2-3 and hide all of them
/// behind the token bucket (the plan's "50 qps vs 1000 qps" split — this gate runs the
/// governor-binding arm; the paced arm arrives with P9's pinned control).
fn farm_config(farm: &Farm) -> AppConfig {
    let mut cfg = AppConfig::load_default().expect("embedded default config parses");
    cfg.dns.doh_servers = farm
        .urls()
        .into_iter()
        .enumerate()
        .map(|(i, url)| DohServerConfig {
            name: format!("farm-{i}"),
            url,
            timeout_secs: 3,
        })
        .collect();
    cfg.dns.dns_servers = Vec::new();
    cfg.rate_limits.dns_queries_per_second = GATE_DNS_QPS;
    cfg
}

const GATE_DNS_QPS: u32 = 1000;

struct DriveOutcome {
    wall_ms: u64,
    with_records: u64,
    empty: u64,
}

/// 64 workers over a shared queue of 600 lookups: 80% subdomain fast path
/// (`get_txt_and_cname_fast`), 20% root path (`get_txt_records_with_pool_tracked`). The
/// root/fast assignment rotates phase each pass over the name list
/// (`(i + i / names) % 5 == 4`) so most names are eventually touched by BOTH paths and the
/// cross-path memo interactions are exercised, while the 80/20 split stays exact.
async fn drive(
    pool: Arc<DnsServerPool>,
    names: Arc<Vec<String>>,
    failures: Arc<AtomicUsize>,
) -> DriveOutcome {
    let next = Arc::new(AtomicUsize::new(0));
    let with_records = Arc::new(AtomicUsize::new(0));
    let t0 = Instant::now();

    let mut handles = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let pool = Arc::clone(&pool);
        let names = Arc::clone(&names);
        let failures = Arc::clone(&failures);
        let next = Arc::clone(&next);
        let with_records = Arc::clone(&with_records);
        handles.push(tokio::spawn(async move {
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= LOGICAL_LOOKUPS {
                    break;
                }
                let name = &names[i % names.len()];
                let is_root = (i + i / names.len()) % 5 == 4;
                let got_records = if is_root {
                    dns::get_txt_records_with_pool_tracked(name, &pool, &failures)
                        .await
                        .map(|records| !records.is_empty())
                        .unwrap_or(false)
                } else {
                    let (txt, _cname) = pool.get_txt_and_cname_fast(name, &failures).await;
                    !txt.is_empty()
                };
                if got_records {
                    with_records.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for handle in handles {
        handle.await.expect("gate worker panicked");
    }

    let with_records = with_records.load(Ordering::Relaxed) as u64;
    DriveOutcome {
        wall_ms: t0.elapsed().as_millis() as u64,
        with_records,
        empty: LOGICAL_LOOKUPS as u64 - with_records,
    }
}

/// Build the farm + a production-shaped pool, run the driver under the hard per-profile
/// timeout, snapshot everything, and persist the measurement.
async fn run_profile(
    profile_name: &str,
    profile_index: u64,
    specs: Vec<ProviderSpec>,
    distinct_names: usize,
) -> Measurement {
    let farm = Farm::start(
        common::doh_farm::splitmix64(FARM_SEED ^ profile_index),
        specs,
    )
    .await;
    let cfg = farm_config(&farm);

    let governor = DnsGovernor::new(64);
    let failures = Arc::new(AtomicUsize::new(0));
    let name_failures = Arc::new(AtomicUsize::new(0));
    let pool = Arc::new(
        DnsServerPool::from_config(&cfg)
            .disable_dot()
            .with_governor(Arc::clone(&governor))
            .with_failure_counter(Arc::clone(&failures))
            .with_name_failure_counter(Arc::clone(&name_failures)),
    );
    let names = Arc::new(gate_names(distinct_names));

    let outcome = tokio::time::timeout(
        PER_PROFILE_TIMEOUT,
        drive(Arc::clone(&pool), names, Arc::clone(&failures)),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "profile {profile_name} exceeded the {}s hard timeout",
            PER_PROFILE_TIMEOUT.as_secs()
        )
    });

    let measurement = Measurement {
        schema: 1,
        profile: profile_name.to_string(),
        wall_ms: outcome.wall_ms,
        logical_lookups: LOGICAL_LOOKUPS as u64,
        distinct_names: distinct_names as u64,
        workers: WORKERS as u64,
        config_dns_qps: GATE_DNS_QPS,
        lookups_with_records: outcome.with_records,
        lookups_empty: outcome.empty,
        dns_failures: failures.load(Ordering::Relaxed) as u64,
        name_failures: name_failures.load(Ordering::Relaxed) as u64,
        provider_requests: farm.request_counts(),
        governor: pool.governor_stats(),
        transport: pool.transport_snapshot(),
    };
    persist(&measurement);
    measurement
}

fn persist(measurement: &Measurement) {
    let dir = std::path::Path::new("target/dns-contention");
    std::fs::create_dir_all(dir).expect("create target/dns-contention");
    let path = dir.join(format!("{}.json", measurement.profile));
    std::fs::write(
        &path,
        serde_json::to_string_pretty(measurement).expect("measurement serializes"),
    )
    .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn six<F: Fn(usize) -> ProviderSpec>(f: F) -> Vec<ProviderSpec> {
    (0..6).map(f).collect()
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// Profiles
// ─────────────────────────────────────────────────────────────────────────────────────────

/// P0 — six healthy providers (20-60 ms band). Everything the pool promises on a healthy
/// network must already hold: no backoff, no breaker movement, no counted failures, real
/// rotation across all providers, and slow-start actually opening the governor up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p0_healthy() {
    let _gate = GATE.lock().await;
    let specs = six(|i| {
        ProviderSpec::Mock(Profile::uniform(Behavior::Ok {
            delay_ms: 50 + 2 * i as u64,
        }))
    });
    let m = run_profile("p0_healthy", 0, specs, DISTINCT_NAMES).await;

    assert_eq!(
        m.governor.backoff_events, 0,
        "healthy farm must not back off"
    );
    assert_eq!(m.transport.doh.down_transitions, 0);
    assert_eq!(m.transport.dot.down_transitions, 0);
    assert_eq!(m.transport.do53.down_transitions, 0);
    assert_eq!(
        m.dns_failures, 0,
        "healthy farm must count zero DNS failures"
    );
    assert!(
        m.governor.peak_limit >= 32,
        "slow-start never opened up: peak_limit {} < 32",
        m.governor.peak_limit
    );
    let total: u64 = m.provider_requests.iter().sum();
    assert!(total > 0, "farm served no requests at all");
    for (i, &count) in m.provider_requests.iter().enumerate() {
        assert!(
            count * 20 >= total,
            "provider {i} got {count} of {total} requests (<5%) — rotation is broken"
        );
    }
}

/// P1 — six providers answering slowly (900-1500 ms). RECORD ONLY in this PR: the current
/// code's handling of slow-but-healthy (3 s per-attempt budget vs ~1.2 s answers under
/// contention) is one of the suspected defects; whatever it does is the baseline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p1_slow_but_healthy() {
    let _gate = GATE.lock().await;
    let specs = six(|i| {
        ProviderSpec::Mock(Profile::uniform(Behavior::Ok {
            delay_ms: 900 + 120 * i as u64,
        }))
    });
    let _m = run_profile("p1_slow_but_healthy", 1, specs, DISTINCT_NAMES).await;
    // Deliberately no numeric asserts: the ratchet arrives with the baseline (see module docs).
}

/// P2 — provider 0 is a dead loopback port, five healthy. Rotation must carry every lookup
/// past the corpse, and the per-provider implication mask must keep the DoH breaker closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2_one_provider_dead() {
    let _gate = GATE.lock().await;
    let specs = six(|i| {
        if i == 0 {
            ProviderSpec::Dead
        } else {
            ProviderSpec::Mock(Profile::uniform(Behavior::Ok { delay_ms: 50 }))
        }
    });
    let m = run_profile("p2_one_provider_dead", 2, specs, DISTINCT_NAMES).await;

    assert_eq!(
        m.lookups_with_records, m.logical_lookups,
        "every lookup must resolve by rotating past the dead provider"
    );
    assert_eq!(
        m.transport.doh.down_transitions, 0,
        "one dead provider must never trip the whole-transport breaker (implication mask)"
    );
    assert!(
        m.dns_failures < m.logical_lookups,
        "failures ({}) reached the logical lookup count ({}) — rotation is not recovering",
        m.dns_failures,
        m.logical_lookups
    );
}

/// P3 — provider 0 hangs past the per-attempt timeout, five healthy. RECORD ONLY: the
/// 3 s-vs-3 s budget interaction (per-attempt vs whole-rotation) is a suspected defect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p3_one_provider_slow() {
    let _gate = GATE.lock().await;
    let specs = six(|i| {
        if i == 0 {
            ProviderSpec::Mock(Profile::uniform(Behavior::Hang { delay_ms: 3500 }))
        } else {
            ProviderSpec::Mock(Profile::uniform(Behavior::Ok { delay_ms: 50 }))
        }
    });
    let _m = run_profile("p3_one_provider_slow", 3, specs, DISTINCT_NAMES).await;
}

/// P4 — all six providers 429 during a 2-second flap window, healthy either side. RECORD
/// ONLY: the plan predicts the baseline will show the breaker demoting DoH on a transient
/// burst (down_transitions >= 1) — that number IS the finding.
///
/// Window note: the plan sketches 1000-3000 ms, but at this gate's throughput (memo hits
/// are instant and the wire volume is ~100-150 requests) the healthy run is OVER before
/// t=1000 ms — a 1000-3000 ms window would throttle nothing and record a P0 clone. The
/// window here opens at 250 ms (mid-first-wave under contention) and holds the same 2 s
/// width, which is the behavior the profile exists to measure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p4_transient_throttle_burst() {
    let _gate = GATE.lock().await;
    let specs = six(|_| {
        ProviderSpec::Mock(Profile::uniform(Behavior::Ok { delay_ms: 50 }).with_flap(
            250,
            2250,
            Behavior::Throttle429,
        ))
    });
    let _m = run_profile("p4_transient_throttle_burst", 4, specs, DISTINCT_NAMES).await;
}

/// P5 — all six providers dead: a genuine DoH outage. The breaker MUST trip (that is its
/// one job), the run must fail fast rather than grind, and every lookup must come back
/// empty (never fabricated, never hung).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p5_genuine_outage() {
    let _gate = GATE.lock().await;
    let specs = six(|_| ProviderSpec::Dead);
    let m = run_profile("p5_genuine_outage", 5, specs, DISTINCT_NAMES).await;

    assert!(
        m.transport.doh.down_transitions >= 1,
        "a genuine all-provider outage must trip the DoH breaker"
    );
    assert!(
        m.wall_ms < 60_000,
        "an outage must fail fast, not grind: wall {} ms",
        m.wall_ms
    );
    assert_eq!(
        m.lookups_with_records, 0,
        "no provider existed, so no lookup may claim records"
    );
    assert_eq!(m.lookups_empty, m.logical_lookups);
}

/// P6 — every provider intermittently flaps (8% hang, 4% 5xx, 2% 429, 1% SERVFAIL, rest
/// healthy 30-300 ms). RECORD ONLY: the messy-real-network profile the ratchet will hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p6_intermittent_flap() {
    let _gate = GATE.lock().await;
    let specs = six(|i| {
        ProviderSpec::Mock(Profile::weighted(vec![
            (Behavior::Hang { delay_ms: 3500 }, 8),
            (Behavior::Http5xx, 4),
            (Behavior::Throttle429, 2),
            (Behavior::Rcode(2), 1),
            (
                Behavior::Ok {
                    delay_ms: 30 + 54 * i as u64,
                },
                85,
            ),
        ]))
    });
    let _m = run_profile("p6_intermittent_flap", 6, specs, DISTINCT_NAMES).await;
}

/// P8 — P0's healthy farm, but 600 lookups over only 20 distinct names: the scan-lifetime
/// memo must absorb the repeats. Bound: 20 names x 2 record kinds x 3 margin (the margin
/// covers the contention window where same-name lookups are already past their memo check
/// before the first answer lands, plus any rotation).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p8_memo_dedupe() {
    let _gate = GATE.lock().await;
    let specs = six(|i| {
        ProviderSpec::Mock(Profile::uniform(Behavior::Ok {
            delay_ms: 50 + 2 * i as u64,
        }))
    });
    let m = run_profile("p8_memo_dedupe", 8, specs, 20).await;

    let total: u64 = m.provider_requests.iter().sum();
    assert!(
        total <= 20 * 2 * 3,
        "memo is not deduplicating: {total} farm requests for 600 lookups over 20 names \
         (bound: 120)"
    );
}
