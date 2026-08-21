use crate::config::AppConfig;
use crate::domain_utils;
use crate::rate_limit::{RateLimitContext, SharedRateLimiter};
use crate::vendor::RecordType;
use anyhow::Result;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::TokioResolver;
use once_cell::sync::Lazy;
use regex::Regex;
#[cfg(not(coverage))]
use serde_json::Value;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
#[cfg(not(coverage))]
use tracing::{debug, info, warn};

// Compile regex patterns once at startup for performance (fixes B020)
static MACRO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"%\{[a-zA-Z]+[0-9]*[a-zA-Z]*\}\.?")
        .expect("MACRO_REGEX is a valid compile-time regex literal")
});

static DOMAIN_VERIFICATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([a-zA-Z0-9]+)(?:-domain)?-verification=")
        .expect("DOMAIN_VERIFICATION_REGEX is a valid compile-time regex literal")
});

static VERIFICATION_PREFIX_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"verification-([a-zA-Z0-9]+)=")
        .expect("VERIFICATION_PREFIX_REGEX is a valid compile-time regex literal")
});

static SITE_VERIFICATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([a-zA-Z0-9]+)-site-verification=")
        .expect("SITE_VERIFICATION_REGEX is a valid compile-time regex literal")
});

static PROVIDER_VERIFY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([A-Z0-9]+)_verify_")
        .expect("PROVIDER_VERIFY_REGEX is a valid compile-time regex literal")
});

// M016: Underscores are intentionally allowed at the start of labels to support
// SPF/DMARC/DKIM underscore-prefixed subdomains (e.g., _spf.google.com, _dmarc.domain.com,
// _domainkey.domain.com). This is correct per RFC 7208 and RFC 6376.
static DOMAIN_VALIDATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,62}(\.[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,62})*$")
        .expect("DOMAIN_VALIDATION_REGEX is a valid compile-time regex literal")
});

// DMARC mailto: extraction regex (fixes B020)
static MAILTO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"mailto:([^@,\s]+@)?([^,;\s]+)")
        .expect("MAILTO_REGEX is a valid compile-time regex literal")
});

// SP_TAG_REGEX removed - sp= contains policy values, not domains (C001 fix)

// Pre-compiled SPF mechanism regexes to avoid recompilation in loops (H001 fix)
static SPF_INCLUDE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"include:\s*([^\s]+)")
        .expect("SPF_INCLUDE_REGEX is a valid compile-time regex literal")
});
static SPF_REDIRECT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"redirect=\s*([^\s]+)")
        .expect("SPF_REDIRECT_REGEX is a valid compile-time regex literal")
});
static SPF_A_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"a:\s*([^\s]+)").expect("SPF_A_REGEX is a valid compile-time regex literal")
});
static SPF_MX_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"mx:\s*([^\s]+)").expect("SPF_MX_REGEX is a valid compile-time regex literal")
});
static SPF_EXISTS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"exists:\s*([^\s]+)")
        .expect("SPF_EXISTS_REGEX is a valid compile-time regex literal")
});
// M003: ptr: mechanism contains a domain (unlike ip4:/ip6: which contain IP addresses)
static SPF_PTR_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"ptr:\s*([^\s]+)").expect("SPF_PTR_REGEX is a valid compile-time regex literal")
});

// Pre-compiled DKIM pattern regexes (H002 fix)
static DKIM_P_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"p=([A-Za-z0-9+/=]+)").expect("DKIM_P_REGEX is a valid compile-time regex literal")
});
static DKIM_H_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"h=([^;]+)").expect("DKIM_H_REGEX is a valid compile-time regex literal")
});
static DKIM_S_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"s=([^;]+)").expect("DKIM_S_REGEX is a valid compile-time regex literal")
});

pub trait LogFailure {
    fn log_failure(
        &self,
        source_domain: &str,
        record_type: &str,
        raw_record: &str,
        extracted_service: Option<&str>,
        failure_reason: &str,
    );
}

/// DNS over HTTPS server configuration (runtime loaded from config)
#[derive(Debug, Clone)]
struct DohServerConfig {
    url: String,
    name: String,
    timeout_secs: u64,
}

/// Traditional DNS Server configuration for fallback (runtime loaded from config)
#[derive(Debug, Clone)]
struct DnsServerConfig {
    address: String,
    name: String,
    timeout_secs: u64,
}

/// Enhanced DNS server pool with DoH support
pub struct DnsServerPool {
    doh_servers: Vec<DohServerConfig>,
    dns_servers: Vec<DnsServerConfig>,
    current_doh_index: AtomicUsize,
    current_dns_index: AtomicUsize,
    client: reqwest::Client,
    /// Per-process DNS rate limiter (GRC-367): acquired before every outbound DoH/DNS
    /// request so the configured `dns_queries_per_second` is actually enforced. Previously
    /// the limiter was dead code (callers always passed `None`), letting sustained
    /// concurrency trip DoH-provider 429s that were then mis-read as empty answers.
    dns_limiter: SharedRateLimiter,
    /// Adaptive concurrency governor. The rate limiter above paces *how often* we may start a
    /// lookup; this bounds *how many* may be outstanding, and learns that bound from observed
    /// latency and failures. A fixed rate cannot be safe on an unknown network — see
    /// [`crate::dns_governor`] — so this is the control that actually protects the resolver path.
    governor: Arc<crate::dns_governor::DnsGovernor>,
    /// Max DoH provider rotations on a throttle (429/5xx) before giving up.
    max_dns_retries: u32,
    /// GRC-367 (fix 1): the SINGLE choke-point throttle counter. When wired up via
    /// `with_failure_counter` (production: to `logger.dns_failure_counter_arc()`), every DoH
    /// throttle on EVERY path — TXT root, subdomain fast, CNAME, and the SPF include-chain
    /// recursion (`resolve_spf_includes_recursive` → `get_txt_records_with_pool` →
    /// `doh_txt_lookup`) — increments the same atomic the exit-3 guard reads. `None` in tests
    /// that don't opt in. This is the authoritative source of truth for throttle visibility;
    /// the older per-path increments are a harmless redundant signal (the guard is `> 0`).
    failure_counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    /// Parallel counter for failures attributable to the queried NAME rather than the transport.
    /// Incremented *in addition to* `failure_counter`, so the exit-3 guard is unchanged while the
    /// scan summary can separate "this domain's DNS is broken" from "your link is unstable".
    name_failure_counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    /// Per-transport availability trackers (circuit breakers), shared across TXT and CNAME so one
    /// detection covers the whole scan. The lookup ladder tries them in network-footprint order —
    /// DoH (443) → DoT (853) → direct UDP/53 — skipping any transport whose breaker is down and
    /// re-probing it periodically.
    #[cfg_attr(coverage, allow(dead_code))]
    doh_health: TransportHealth,
    /// DNS-over-TLS (853) availability — an encrypted, TCP-pooled fallback tried BEFORE raw UDP/53,
    /// so a DoH-blocked network degrades to a low-conntrack-footprint transport, not the flood-prone
    /// one.
    #[cfg_attr(coverage, allow(dead_code))]
    dot_health: TransportHealth,
    /// Direct UDP/53 availability — the flood-prone tier, health-gated so a router that
    /// rate-limits/blocks port 53 (the DNS-flood-protection collapse) is skipped after
    /// `TRANSPORT_DOWN_THRESHOLD` consecutive timeouts instead of being hammered into a worse outage.
    #[cfg_attr(coverage, allow(dead_code))]
    do53_health: TransportHealth,
    /// Hard emission ceiling on the raw UDP/53 tier — the transport that can damage the network.
    /// See `Do53Budget`.
    #[cfg_attr(coverage, allow(dead_code))]
    do53_budget: Do53Budget,
    /// Whether the DoT (853) tier is attempted at all. Real DoT queries hit hardcoded public 853
    /// resolvers (`DOT_SERVERS`), so hermetic tests (mock-DoH pools from `with_test_urls`) disable
    /// it while production constructors enable it. DoT still only runs when DoH is unavailable.
    #[cfg_attr(coverage, allow(dead_code))]
    dot_enabled: bool,
    /// Lazily-built-then-reused DoT (853) resolver, so hickory actually POOLS its TLS connections
    /// across lookups instead of opening a fresh handshake per lookup — which, during a DoH outage
    /// (when the DoT tier carries the scan), would storm :853 with short-lived connections, the very
    /// conntrack churn this ladder exists to avoid. Built once on first DoT use; `None` if it fails.
    #[cfg_attr(coverage, allow(dead_code))]
    dot_resolver: tokio::sync::OnceCell<Option<TokioResolver>>,
    /// The UDP/53 analogue of `dot_resolver`, one slot per configured server so each keeps its own.
    ///
    /// Every raw-DNS site in this file used to build a fresh `TokioResolver` — and with it a fresh
    /// socket and a fresh hickory runtime handle — for a single lookup and then drop it. On the
    /// root TXT race that happened on essentially every non-memoized lookup, so a deep scan churned
    /// one short-lived UDP socket per root domain at the consumer forwarder this ladder exists to
    /// protect. A `None` in a slot means that server's configured address did not parse and the
    /// tier is skipped for it, exactly as the per-call construction did.
    #[cfg_attr(coverage, allow(dead_code))]
    do53_resolvers: Vec<tokio::sync::OnceCell<Option<TokioResolver>>>,
    /// Per-provider failure-log counts backing `log_doh_failure`'s warn-once-then-debug
    /// behavior. Mutex (not atomics) because failures are rare and the critical section
    /// is a HashMap bump with no await inside.
    #[cfg(not(coverage))]
    doh_failure_log: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    /// Scan-lifetime memo of DNS lookups, keyed by `(record kind, domain)`.
    ///
    /// The same names are looked up many times in one scan: SPF include chains converge on
    /// a handful of shared targets (`_spf.google.com`, `sendgrid.net`, …), and a vendor seen
    /// at one depth is commonly re-analyzed as a customer at the next. Each repeat used to
    /// re-issue the query, spend a rate-limit token, and wait a full round trip.
    ///
    /// **Only facts about the zone are stored** — see [`MemoEntry`] and [`may_memoize_failure`].
    /// A record set that came back from a real resolver (including a genuinely empty one) is such
    /// a fact. So is a `DNS_NAME` verdict: the name's own authoritative servers reporting
    /// SERVFAIL/REFUSED over a transport that demonstrably worked. An empty vector produced
    /// because every resolver failed is NOT: caching it would silently convert one transient
    /// outage into a scan-wide false negative and would bypass the `note_throttle` counting that
    /// the exit-3 guard depends on (GRC-367).
    ///
    /// One mutex rather than a shard array, deliberately. The critical section is a single
    /// `HashMap` probe plus a small `Vec` clone, and every caller that takes it is either about
    /// to spend milliseconds on the network or has just come back from doing so — so the lock is
    /// nowhere near the throughput limit even at the subdomain fan-out's concurrency. Sharding
    /// would buy nothing measurable and would leave the memo with two shapes to keep in step.
    #[cfg(not(coverage))]
    answer_memo: tokio::sync::Mutex<std::collections::HashMap<(RecordKind, String), MemoEntry>>,
}

/// What the scan-lifetime memo remembers about one `(kind, name)`.
///
/// The split is the memo's safety story on the read side: serving a remembered failure must not
/// look like serving a remembered absence. A `DNS_NAME` verdict still has to be counted every time
/// it is served, or the exit-3 guard and the end-of-scan coverage summary quietly lose sight of a
/// name the scan never resolved — the memo is allowed to remove the *query*, never the failure's
/// visibility.
#[cfg(not(coverage))]
#[derive(Debug, Clone)]
enum MemoEntry {
    /// A resolver answered. An empty vector here is a real answer: the name has no records of
    /// this kind.
    Answer(Vec<String>),
    /// Every provider answered over a working transport and reported SERVFAIL/REFUSED for this
    /// NAME (`DNS_NAME`). Carries the classified message verbatim so a hit is counted and
    /// classified exactly as a fresh attempt would have been.
    NameFailure(String),
}

/// A TXT lookup's records, plus the CNAME chain the SAME dns-json response already carried.
///
/// A resolver cannot answer a TXT query for an aliased name without following the alias, so it
/// returns the type-5 chain in the answer section alongside the target's type-16 records. The
/// subdomain fast path used to discard those and then issue a second, separate CNAME query for the
/// very name it had just resolved — doubling the DNS volume of the highest-volume path in the
/// program to re-learn something it was already holding.
#[cfg_attr(coverage, allow(dead_code))]
#[derive(Debug, Clone, Default)]
pub(crate) struct TxtAnswer {
    /// The name's TXT records.
    pub(crate) txt: Vec<String>,
    /// `Some` when the records came from a dns-json response, which settles the chain
    /// authoritatively — an empty vector then *proves* the name is not aliased, because an alias
    /// would have had to appear in the answer section for the TXT records to be there at all.
    /// `None` when they came from the DoT/UDP-53 ladder, whose extractors read only TXT rdata: the
    /// chain is then simply unknown and the caller must still ask for it.
    pub(crate) cname: Option<Vec<String>>,
}

/// Record kinds the answer memo distinguishes. Keying on the name alone would let a TXT
/// answer satisfy a CNAME query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(coverage, allow(dead_code))]
pub(crate) enum RecordKind {
    Txt,
    Cname,
    /// Address records (A/AAAA), for the governed reqwest resolver (Wave 3, 6b). Stored in the
    /// same answer memo as strings; `POOL_MAX_IDLE_PER_HOST = 0` means reqwest resolves per
    /// request, so the memo is what makes governed resolution affordable.
    Addr,
}

/// Total wall-clock budget one DoH lookup (all provider rotations together) may spend. The
/// RESILIENT LOOP owns this deadline — it slices the remainder across the attempts it has left
/// (floored by the governor's measured RTO) — so rotation always completes inside it. The old
/// shape, an outer `timeout(3s, …)` wrapping attempts that each carried their own 3 s, meant the
/// wrapper fired while attempt 0 was still in flight and providers 2–4 never ran: Phase 1 measured
/// 7,032 of 7,988 cancellations at attempt-0-in-flight (defect A). Same total budget as before.
#[cfg_attr(coverage, allow(dead_code))]
const DOH_LOOKUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

/// Hang backstop on the callers of the resilient loops. The loop self-terminates at
/// [`DOH_LOOKUP_DEADLINE`]; this outer guard exists only to catch a runaway future and is expected
/// to NEVER fire — `perf::METRICS.dns_deadline_backstop_fired` counts it, and any nonzero reading
/// is a defect. 4× the deadline, comfortably above every legitimate completion.
#[cfg_attr(coverage, allow(dead_code))]
const DOH_WRAPPER_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(12);

/// Compile-time guard (Wave 1, defect C): DNS left the shared connection semaphore — the governor
/// is now the only DNS concurrency ceiling — so its ceiling must stay small against the process-wide
/// connection ceiling, or DNS could reclaim through sockets the contention the decoupling removed.
const _: () = assert!(
    crate::dns_governor::DEFAULT_MAX_LIMIT as usize
        <= crate::http_client::DEFAULT_MAX_CONNECTIONS / 2,
    "DNS governor ceiling must stay at or under half the connection ceiling"
);

/// Consecutive failures on a single DNS transport before it is treated as unavailable (a blocked
/// network, a rate-limiting router, or a provider outage). High enough that a transient
/// throttle/timeout won't trip it; low enough that a genuinely blocked transport stops paying a
/// per-lookup timeout — or hammering a rate-limited port — quickly.
#[cfg_attr(coverage, allow(dead_code))]
const TRANSPORT_DOWN_THRESHOLD: u32 = 8;
/// While a transport is marked down, permit one re-probe this often to detect recovery.
#[cfg_attr(coverage, allow(dead_code))]
const TRANSPORT_REPROBE_INTERVAL_MS: u64 = 30_000;

/// Sustained queries per second the raw UDP/53 tier may emit, process-wide.
///
/// This is a *hard* ceiling, not a pacing target: when the budget is spent the tier is skipped for
/// that lookup rather than queued behind it. It exists because the UDP/53 tier is the one that can
/// damage the network it runs on, and the breaker alone is not enough to bound it — the breaker
/// reacts to failures, so it only engages *after* a flood has already been emitted, and on
/// 2026-07-29 the flood was itself what caused the failures.
///
/// The value is chosen to sit inside what an ordinary browsing device emits: a few queries a
/// second sustained, with a small burst allowance for the natural clustering of a lookup batch.
/// A depth-3 scan can want thousands of lookups per minute; on plain port 53 from a residential
/// line, that is the traffic pattern that gets an IP throttled upstream. Recall lost to this
/// ceiling is recoverable — the scan reports reduced coverage — whereas a throttled WAN link takes
/// hours to clear and takes every other device on the LAN with it.
#[cfg_attr(coverage, allow(dead_code))]
const DO53_MAX_QPS: u64 = 5;

/// Burst allowance for [`DO53_MAX_QPS`], so a small cluster of lookups is not needlessly serialized
/// while the sustained rate stays bounded.
#[cfg_attr(coverage, allow(dead_code))]
const DO53_BURST: u64 = 10;

/// Build-time guard on the UDP/53 ceiling. This is a *compile* error rather than a test failure on
/// purpose: the whole point of the ceiling is that it cannot quietly drift upward, and a value
/// raised in a hurry should not be able to reach a release even if the suite is skipped.
const _: () = {
    assert!(
        DO53_MAX_QPS <= 10,
        "UDP/53 is the transport that gets a residential IP throttled upstream — keep it low"
    );
    assert!(
        DO53_BURST <= DO53_MAX_QPS * 4,
        "burst must stay a small multiple of the sustained rate, or it IS the sustained rate"
    );
};

/// A shedding token bucket bounding how fast the raw UDP/53 tier may emit queries.
///
/// **Sheds rather than queues.** A waiting limiter would convert a flood into a backlog: the same
/// number of queries still leave the machine, just later, and every caller blocks holding its
/// resources. Skipping the tier instead keeps the emission rate genuinely bounded and degrades the
/// way the scanner already knows how to report — as reduced coverage on names it could not resolve.
///
/// A plain `Mutex` is right here: the critical section is a compare-and-subtract with no `await`
/// inside, and by construction this path runs at single-digit QPS.
#[cfg_attr(coverage, allow(dead_code))]
#[derive(Debug)]
struct Do53Budget {
    state: std::sync::Mutex<Do53BudgetState>,
}

#[cfg_attr(coverage, allow(dead_code))]
#[derive(Debug)]
struct Do53BudgetState {
    tokens: f64,
    last_refill_ms: u64,
}

#[cfg_attr(coverage, allow(dead_code))]
impl Do53Budget {
    fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(Do53BudgetState {
                tokens: DO53_BURST as f64,
                last_refill_ms: now_epoch_millis(),
            }),
        }
    }

    /// Take one token if the budget allows. Returns false when the caller must skip the UDP/53
    /// tier for this lookup.
    ///
    /// A poisoned mutex denies the request: failing closed on the flood-prone transport is the safe
    /// direction, and it cannot deadlock the scan because every caller treats `false` as "skip".
    fn try_take(&self) -> bool {
        let Ok(mut st) = self.state.lock() else {
            return false;
        };
        let now = now_epoch_millis();
        // Saturating: a clock that steps backwards must not manufacture tokens.
        let elapsed_ms = now.saturating_sub(st.last_refill_ms);
        if elapsed_ms > 0 {
            st.tokens = (st.tokens + (elapsed_ms as f64) * (DO53_MAX_QPS as f64) / 1000.0)
                .min(DO53_BURST as f64);
            st.last_refill_ms = now;
        }
        if st.tokens >= 1.0 {
            st.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Well-known DNS-over-TLS (853) resolvers, as `(ip, tls_server_name)`. One DoT resolver is built
/// over all of them so hickory gets resolver-level provider diversity (Cloudflare + Quad9 + Google)
/// and connection pooling for free. IP literals avoid a DNS-bootstrap dependency when UDP/53 — the
/// path DoT is stepping in for — is the very thing that's blocked.
#[cfg_attr(coverage, allow(dead_code))]
const DOT_SERVERS: &[(&str, &str)] = &[
    ("1.1.1.1", "cloudflare-dns.com"),
    ("9.9.9.9", "dns.quad9.net"),
    ("8.8.8.8", "dns.google"),
];

/// Milliseconds since the Unix epoch (best-effort; 0 if the clock is before the epoch).
#[cfg_attr(coverage, allow(dead_code))]
fn now_epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Tracks whether a single DNS transport (DoH, DoT, or direct UDP/53) looks usable, so a blocked or
/// rate-limited transport doesn't cost a full timeout — or keep hammering a router's DNS-flood
/// protection — on EVERY lookup before the ladder moves on.
///
/// When the transport is healthy this is two atomic loads and changes nothing. After
/// `TRANSPORT_DOWN_THRESHOLD` consecutive failures it flips to "skip this transport"; a single
/// re-probe every `TRANSPORT_REPROBE_INTERVAL_MS` (single-flight via CAS) resumes it the instant it
/// recovers, and any success resets the streak (a flaky-but-working transport keeps being used). One
/// instance per transport lets the lookup ladder degrade from network-kind transports (DoH/DoT,
/// pooled + encrypted) toward the flood-prone raw UDP/53 path only as each higher tier proves
/// unavailable — and stop firing UDP/53 entirely once it, too, is being dropped.
#[cfg_attr(coverage, allow(dead_code))]
#[derive(Debug, Default)]
struct TransportHealth {
    consecutive_failures: AtomicU32,
    /// Unix-epoch millis after which one re-probe is permitted while the transport is marked down.
    reprobe_after_ms: AtomicU64,
    /// Bitmask of the distinct upstreams that have failed during the *current* streak, one bit per
    /// provider index — cleared by any success, alongside the streak.
    ///
    /// A transport with several independent providers (DoH) must not be declared unavailable on the
    /// strength of one sick endpoint. `consecutive_failures` alone cannot tell "Cloudflare is
    /// rate-limiting us" from "port 443 is blocked", because rotation means eight consecutive
    /// failures can all belong to a single provider. On 2026-07-29 that distinction was the whole
    /// incident: DoH was declared blocked six times in fourteen minutes while DoH was demonstrably
    /// answering — a live probe mid-outage returned HTTP 200 in 35ms — and each false demotion moved
    /// the scan's DNS onto raw UDP/53, which is what got the WAN IP throttled upstream for ~2h08m.
    ///
    /// Requiring every configured provider to have failed makes the breaker mean what its name
    /// says: the *transport* is unusable, not one endpoint on it. It also self-heals — a provider
    /// that is permanently broken cannot force a demotion on its own, because any success from a
    /// working sibling clears the streak.
    ///
    /// A `u64` bitmask covers 64 providers, far past any sane configuration; indices at or beyond
    /// that saturate into the top bit, which is conservative (it can only delay a demotion).
    failed_sources: AtomicU64,
    /// Whether the "transport is down" warning has already been emitted for the current outage, so
    /// `just_went_down` fires once rather than on every lookup while the breaker is open. Reset by
    /// `record_success` along with the streak.
    warned_down: std::sync::atomic::AtomicBool,
    /// Total transitions into "down" this scan (Phase-0 attribution) — the observable the
    /// contention gate and demotion events key on. Never reset.
    down_transitions: AtomicU32,
    /// Re-probe admissions while down (each CAS winner in `should_attempt_with_sources`).
    reprobes: AtomicU64,
    /// Epoch-millis when the current failure streak started (0 = no streak) — lets a demotion
    /// event report how fast the threshold was reached, which separates a burst trip from a
    /// genuine outage.
    streak_started_ms: AtomicU64,
}

#[cfg_attr(coverage, allow(dead_code))]
impl TransportHealth {
    /// Attempt this transport for the current lookup? True when healthy, or — when marked down — for
    /// the single lookup that wins the periodic re-probe (the CAS ensures exactly one concurrent
    /// probe; the rest skip straight to the next tier).
    fn should_attempt(&self) -> bool {
        self.should_attempt_with_sources(1)
    }

    /// As [`Self::should_attempt`], but for a transport with `source_count` independent upstreams:
    /// it is only skippable once every one of them has failed in the current streak.
    fn should_attempt_with_sources(&self, source_count: usize) -> bool {
        if !self.is_down(source_count) {
            return true;
        }
        let now = now_epoch_millis();
        let due = self.reprobe_after_ms.load(Ordering::Relaxed);
        let admitted = now >= due
            && self
                .reprobe_after_ms
                .compare_exchange(
                    due,
                    now + TRANSPORT_REPROBE_INTERVAL_MS,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok();
        if admitted {
            self.reprobes.fetch_add(1, Ordering::Relaxed);
        }
        admitted
    }

    /// The transport answered (any authoritative result, including an empty one) — it works. Clear
    /// the failure streak, and with it the set of providers implicated in that streak.
    ///
    /// Returns true when this success ended a warned outage (the transport was down and is now
    /// recovered) so the caller can record the recovery — callers that don't care ignore it.
    fn record_success(&self) -> bool {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.failed_sources.store(0, Ordering::Relaxed);
        self.streak_started_ms.store(0, Ordering::Relaxed);
        self.warned_down.swap(false, Ordering::Relaxed)
    }

    /// How long the current failure streak has been running (0 when healthy).
    fn streak_ms(&self) -> u64 {
        match self.streak_started_ms.load(Ordering::Relaxed) {
            0 => 0,
            start => now_epoch_millis().saturating_sub(start),
        }
    }

    /// The current streak's implicated-provider bitmask (Phase-0 attribution).
    fn failed_mask(&self) -> u64 {
        self.failed_sources.load(Ordering::Relaxed)
    }

    /// The current consecutive-failure count.
    fn consecutive(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Total transitions into "down" this scan.
    fn transitions(&self) -> u32 {
        self.down_transitions.load(Ordering::Relaxed)
    }

    // (Wave 2) The old `record_congestion` / `record_*_unless_congested` suppression trio is
    // gone: "is the governor backing off?" was a bimodal discriminator — it disabled the breaker
    // entirely while a cooldown kept refreshing (a genuine outage at the floor could never trip)
    // and hair-triggered at the ceiling (a burst of 8 concurrent failures filled the mask before
    // the controller could react). The discriminator is now the EVIDENCE at each call site:
    // unreachable-class failures always advance the streak, no-response-class failures advance it
    // only once the governor has retreated to its floor.

    /// The transport failed at the transport layer (timeout / connection / sustained throttle).
    /// Advance the streak; returns true exactly once, on the transition into "down", so the caller
    /// warns a single time per outage.
    fn record_failure(&self) -> bool {
        self.record_failure_from(0, 1)
    }

    /// Advance the streak and mark `source_index` as implicated.
    ///
    /// The transport flips to "down" only when BOTH conditions hold: the streak has reached
    /// `TRANSPORT_DOWN_THRESHOLD`, and every one of the `source_count` configured upstreams has
    /// failed at least once during it. The second condition is what stops one sick provider from
    /// demoting a working transport — see the `failed_sources` field docs for the incident that
    /// made it necessary.
    ///
    /// Returns true exactly once, on the transition into "down", so the caller warns a single time.
    fn record_failure_from(&self, source_index: usize, source_count: usize) -> bool {
        let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n == 1 {
            self.streak_started_ms
                .store(now_epoch_millis(), Ordering::Relaxed);
        }

        // Saturate out-of-range indices into the top bit rather than wrapping: a wrapped index
        // would alias onto a different provider's bit and could fake full coverage.
        let bit = 1u64 << source_index.min(63);
        let prev = self.failed_sources.fetch_or(bit, Ordering::Relaxed);
        let seen = prev | bit;

        // `source_count` is clamped the same way so the "all providers failed" mask is reachable.
        let needed = match source_count.clamp(1, 64) {
            64 => u64::MAX,
            k => (1u64 << k) - 1,
        };
        let all_sources_failed = seen & needed == needed;

        if n >= TRANSPORT_DOWN_THRESHOLD && all_sources_failed {
            // Warn (and start the re-probe clock) only on the transition, not on every subsequent
            // failure once down. `should_attempt` treats any streak at/above the threshold as down,
            // so the transition is the first call where both conditions hold.
            let was_down = n > TRANSPORT_DOWN_THRESHOLD && prev & needed == needed;
            if !was_down {
                self.down_transitions.fetch_add(1, Ordering::Relaxed);
                self.reprobe_after_ms.store(
                    now_epoch_millis() + TRANSPORT_REPROBE_INTERVAL_MS,
                    Ordering::Relaxed,
                );
            }
            !was_down
        } else {
            false
        }
    }

    /// Report the down-transition exactly once, for callers that record failures elsewhere.
    ///
    /// The DoH tier attributes failures per-provider deep inside the rotation loop (the only layer
    /// that knows which upstream failed), so its outer call site must not record again — that would
    /// double-count and could trip the breaker on one provider's streak. It still needs to warn on
    /// the transition, which this provides: true the first time the transport is observed down.
    fn just_went_down(&self, source_count: usize) -> bool {
        self.is_down(source_count) && !self.warned_down.swap(true, Ordering::Relaxed)
    }

    /// Is this transport currently considered down? Mirrors the condition in
    /// [`Self::record_failure_from`] so `should_attempt` cannot drift from it.
    fn is_down(&self, source_count: usize) -> bool {
        if self.consecutive_failures.load(Ordering::Relaxed) < TRANSPORT_DOWN_THRESHOLD {
            return false;
        }
        let needed = match source_count.clamp(1, 64) {
            64 => u64::MAX,
            k => (1u64 << k) - 1,
        };
        self.failed_sources.load(Ordering::Relaxed) & needed == needed
    }
}

/// One transport breaker's observable state (Phase-0; see `DnsServerPool::transport_snapshot`).
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct TransportView {
    pub down_transitions: u32,
    pub is_down: bool,
    pub consecutive_failures: u32,
    pub implicated_mask: u64,
    pub reprobes: u64,
}

/// The three tiers' breaker state at one instant.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct TransportSnapshot {
    pub doh: TransportView,
    pub dot: TransportView,
    pub do53: TransportView,
}

/// Classify a paired TXT + CNAME lookup for the adaptive DNS controller.
///
/// The pair is a single unit of network work, so it yields a single verdict. Either arm answering
/// proves the resolver path is alive, and CNAME absence is the norm — so only a failure of *both*
/// is evidence of anything. Even then, a name the resolver could not parse is a property of the
/// name, not of the network, and must never be allowed to throttle a healthy link.
fn classify_pair<T, U, E: std::fmt::Display, F: std::fmt::Display>(
    txt: &std::result::Result<T, E>,
    cname: &std::result::Result<U, F>,
) -> crate::dns_governor::DnsOutcome {
    use crate::dns_governor::DnsOutcome;
    if txt.is_ok() || cname.is_ok() {
        return DnsOutcome::Answered;
    }
    let msgs: Vec<String> = [
        txt.as_ref().err().map(|e| e.to_string()),
        cname.as_ref().err().map(|e| e.to_string()),
    ]
    .into_iter()
    .flatten()
    .collect();
    // Classified on the class MARKERS the lookup layer stamps, never on free-text substrings.
    // The old `contains("timeout")` match was defect F twice over: reqwest's plain `Display`
    // ("error sending request for url (…)") carries no such text, so real timeouts read as
    // `Unrelated` — while any queried NAME containing "timeout" read as congestion.
    //
    // DNS_NAME is deliberately absent: the resolver answered over a working link and simply
    // reported SERVFAIL/REFUSED for this name. DNS_ENDPOINT is now absent too — it means a
    // provider answered with the wrong API shape, or that NO transport was available (the dead
    // ladder). Neither is evidence of congestion, and reading the dead ladder's failures as
    // explicit refusals is what parked the governor at its floor for 61% of the Phase-1 baseline
    // scan (21,139 "rejections" against zero observed 429s).
    if msgs.iter().any(|m| m.contains("DNS_THROTTLE")) {
        DnsOutcome::Rejected
    } else if msgs.iter().any(|m| m.contains("DNS_TIMEOUT")) {
        DnsOutcome::TimedOut
    } else {
        DnsOutcome::Unrelated
    }
}

/// How a lookup failure whose class we still know should be reported to the adaptive governor.
///
/// `DNS_NAME` is the case this exists for. That class is emitted only when a provider returned an
/// HTTPS response carrying a well-formed dns-json body whose RCODE reports SERVFAIL/REFUSED: the
/// link is demonstrably healthy and the name's own servers are what failed, so there is nothing
/// for the controller to back off from. Reading it as congestion costs the whole scan 30% of its
/// concurrency plus a cooldown — once per broken name — and the root TXT race did exactly that,
/// because `.ok()` erased the class before anyone could look at it.
///
/// The mapping is the single-error twin of [`classify_pair`]'s judgement on a TXT+CNAME pair:
/// only an explicit provider refusal (`DNS_THROTTLE`, a real 429/5xx) is `Rejected`; a lookup that
/// ran out of its measured deadline is `TimedOut`; everything else — `DNS_NAME`, `DNS_ENDPOINT`
/// (wrong API shape or dead ladder), local-resource failures, unclassified decode errors — says
/// nothing about network load and is `Unrelated`.
fn failure_outcome_for_governor(err: Option<&str>) -> crate::dns_governor::DnsOutcome {
    match err {
        Some(msg) if msg.contains("DNS_THROTTLE") => crate::dns_governor::DnsOutcome::Rejected,
        Some(msg) if msg.contains("DNS_TIMEOUT") => crate::dns_governor::DnsOutcome::TimedOut,
        _ => crate::dns_governor::DnsOutcome::Unrelated,
    }
}

/// One arm of a paired lookup, reduced to what it is entitled to tell the adaptive governor.
///
/// An arm served from the memo issued no query, so it may not vouch for the network in either
/// direction. A remembered *success* masking a live throttle would stop the controller backing off
/// while the one query we did issue was being rejected; a remembered *failure* would have it back
/// off over a name we never asked about. `Err("")` is the neutral value: [`classify_pair`] reads it
/// as neither an answer nor any of the congestion classes, so the live arm decides alone.
fn governor_view(
    served_from_memo: bool,
    result: &Result<Vec<String>>,
) -> std::result::Result<(), String> {
    if served_from_memo {
        return Err(String::new());
    }
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// May a failed lookup be remembered as a *negative* memo entry — is this failure a durable fact
/// about the NAME, or a statement about our own reach?
///
/// Only `DNS_NAME` qualifies, and the rule it enforces is that an outage must never memoize as
/// absence. A throttle, a broken endpoint, a timeout or an exhausted FD table all mean "we could
/// not look"; remembering any of them would convert one transient outage into a scan-wide false
/// negative and would suppress the per-attempt counting the exit-3 guard reads (GRC-367) — the
/// exact hazard `answer_memo` was built to refuse. A `DNS_NAME` verdict is the opposite: the
/// transport worked, we did look, and the answer was that this name's authoritative servers are
/// broken. That stays true for the seconds-to-minutes a scan lasts, which is why one broken SPF
/// include referenced by thousands of domains need only be discovered once instead of costing a
/// full four-provider rotation per referencing domain.
///
/// `DNS_NAME` must be the ONLY class present: a message that also carries `DNS_THROTTLE` or
/// `DNS_ENDPOINT` is not a clean verdict about the name, so it is refused rather than guessed at.
fn may_memoize_failure(msg: &str) -> bool {
    msg.contains("DNS_NAME")
        && !msg.contains("DNS_THROTTLE")
        && !msg.contains("DNS_ENDPOINT")
        && !msg.contains("DNS_TIMEOUT")
        && !msg.contains("DNS_LOCAL")
}

/// The CNAME chain a dns-json answer section already carries, as cleaned target names.
///
/// Type-5 answers appear in a TXT (or any other type's) response whenever the queried name is an
/// alias, because the resolver had to follow the chain to answer at all. Reading them here is what
/// makes the paired CNAME query on the subdomain fast path unnecessary. An empty result is
/// meaningful — it says the name is not aliased — but only for a response that already passed the
/// RCODE gate, which is why extraction is separate from the trust decision.
///
/// Note this can return a LONGER chain than a dedicated CNAME query would: a CNAME query returns
/// only the RRset at the queried name (one hop), whereas the followed chain shows every hop to the
/// final target. For a scanner whose job is naming third parties, more hops is more of the
/// infrastructure actually in the path, so the extra entries are kept.
fn cname_chain_from_dns_json(response: &serde_json::Value) -> Vec<String> {
    response["Answer"]
        .as_array()
        .map(|answers| {
            answers
                .iter()
                .filter_map(|answer| {
                    if answer["type"].as_u64() != Some(5) {
                        return None;
                    }
                    // Same cleaning as `doh_cname_lookup`: dns-json renders targets fully
                    // qualified, and a non-string `data` is dropped rather than coerced.
                    Some(answer["data"].as_str()?.trim_end_matches('.').to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Outcome of one direct (hickory) lookup, classified so the shared per-transport breaker counts
/// only genuine transport failures — never an authoritative empty answer (which is the NORM for
/// CNAME and must not disable the transport for TXT).
#[cfg_attr(coverage, allow(dead_code))]
enum DirectOutcome {
    /// The resolver returned one or more records.
    Answered(Vec<String>),
    /// The resolver responded, authoritatively, with no records of this type (NXDOMAIN / NODATA).
    /// The transport works; this is a fact about the zone, not a failure.
    Empty,
    /// No usable answer — carries WHAT KIND of silence, because the two kinds mean opposite
    /// things to the breaker (see [`TransportEvidence`]).
    TransportFailed(TransportEvidence),
}

/// What a transport-level failure actually proved (Wave 1, defect B's evidence typing).
///
/// The breaker's one job is "route around a transport that is genuinely unusable", and the two
/// failure shapes are OPPOSITE evidence for that: a refused/reset connection or a TLS failure is
/// the transport itself saying no (always breaker-relevant), while a TIMEOUT is silence measured
/// against OUR OWN budget — under load it is overwhelmingly self-inflicted. The r2 validation A/B
/// measured 10 DoH demotions, every one born from attempt-budget timeouts bursting at 64
/// in-flight on a healthy network with ZERO connect errors. Timeout evidence therefore advances a
/// breaker only when the adaptive governor has already retreated to its floor
/// ([`crate::dns_governor::DnsGovernor::has_retreated_to_floor`]) — the network has been given
/// every concession and still does not answer, which by construction is not our load.
#[cfg_attr(coverage, allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportEvidence {
    /// The transport actively refused: connection refused/reset, unreachable, TLS failure.
    Unreachable,
    /// No response inside the budget we chose. Ambiguous unless the governor is at its floor.
    NoResponse,
}

/// Classify a hickory resolver error into breaker evidence. `NetError::Io`/`RustlsError` are the
/// transport actively failing; `Timeout`/`NoConnections`/`Busy`/`Proto` and everything else are
/// no-response shapes. (`Dns(_)` never reaches this — it is authoritative and handled first.)
#[cfg_attr(coverage, allow(dead_code))]
fn net_error_evidence(err: &NetError) -> TransportEvidence {
    match err {
        NetError::Io(_) | NetError::RustlsError(_) => TransportEvidence::Unreachable,
        _ => TransportEvidence::NoResponse,
    }
}

/// Does a resolver error represent an *authoritative DNS answer* (the server spoke DNS: NoRecordsFound
/// / NXDOMAIN / NODATA / a response code / an NSEC proof) rather than a transport-level failure?
///
/// Classified on the TYPED error, deliberately NOT on its `Display`: hickory renders a no-records
/// error as `no records found for Query { name: Name("mtls.example.com."), .. }`, so a string match
/// would false-classify any queried name containing a substring like "tls"/"connection"/"timeout"
/// (exactly the subdomains a fan-out enumerates) as a transport failure — false-tripping the shared
/// per-transport breaker on an authoritative empty. `NetError::Dns(_)` means the transport delivered
/// a DNS-level response (it works); every other variant (`Timeout`, `NoConnections`, `Io`,
/// `RustlsError`, `Proto`, …) is a genuine transport failure.
#[cfg_attr(coverage, allow(dead_code))]
fn net_error_is_authoritative_negative(err: &NetError) -> bool {
    matches!(err, NetError::Dns(_))
}

/// One-line, once-per-outage notice that a DNS transport is unavailable and the ladder has moved
/// on — plus the Phase-0 demotion record: tier counter and a cause-bearing event carrying the
/// governor's state, the implicated-provider mask, and the connection-ceiling occupancy at the
/// moment the breaker fired. Those are exactly the facts every prior "appears blocked" incident
/// was missing when it came time to decide whether the transport was down or we were.
///
/// `transport_label` is the human name in the warning (unchanged text); `tier`/`cause` feed the
/// telemetry; `health`/`governor` supply the state snapshot.
#[cfg_attr(coverage, allow(dead_code))]
fn warn_transport_unavailable(
    tier: crate::dns_telemetry::Tier,
    transport_label: &str,
    fallback: &str,
    cause: &'static str,
    health: &TransportHealth,
    governor: &std::sync::Arc<crate::dns_governor::DnsGovernor>,
) {
    // Deliberately does NOT promise "results are unaffected". It used to, and that was wrong in
    // the case that matters: when a transport goes down mid-scan, the lookups that failed on the
    // way to the threshold have already returned empty, and empty is indistinguishable from
    // "this name genuinely has no records". Recall really can drop, and the 2026-07-24 incident
    // produced 76,293 failed lookups while the log calmly reported no impact. Failures are
    // counted through `note_throttle` and surfaced in the end-of-scan coverage summary, so the
    // honest thing here is to point at that rather than to reassure.
    tracing::warn!(
        "{} appears blocked or unavailable after {} consecutive failures — {}. Lookups that \
         failed before the fallback engaged may have returned empty, so recall for those names \
         can be incomplete; see the discovery-coverage summary at the end of the scan. It is \
         re-probed every {}s and resumes automatically when it recovers.",
        transport_label,
        TRANSPORT_DOWN_THRESHOLD,
        fallback,
        TRANSPORT_REPROBE_INTERVAL_MS / 1000
    );
    let telemetry = &crate::dns_telemetry::DNS_TELEMETRY;
    telemetry
        .tier(tier)
        .demotions
        .fetch_add(1, Ordering::Relaxed);
    let (conn_cap, conn_available) = crate::http_client::connection_ceiling_state();
    telemetry.event(crate::dns_telemetry::Event::Demotion {
        t_ms: telemetry.now_t_ms(),
        tier,
        cause,
        consecutive_failures: health.consecutive(),
        streak_ms: health.streak_ms(),
        implicated_mask: health.failed_mask(),
        governor: governor.sample(),
        conn_cap,
        conn_available,
    });
}

/// Record a transport recovery (Phase-0): tier counter + event, called when a
/// `record_success()` return says a warned outage just ended.
#[cfg_attr(coverage, allow(dead_code))]
fn note_transport_recovered(tier: crate::dns_telemetry::Tier) {
    let telemetry = &crate::dns_telemetry::DNS_TELEMETRY;
    telemetry
        .tier(tier)
        .recoveries
        .fetch_add(1, Ordering::Relaxed);
    telemetry.event(crate::dns_telemetry::Event::Recovery {
        t_ms: telemetry.now_t_ms(),
        tier,
    });
}

/// Build a single DNS-over-TLS (853) resolver spanning every well-known DoT endpoint in
/// `DOT_SERVERS`, so hickory load-balances across Cloudflare/Quad9/Google and pools connections.
/// No network I/O happens here (connections are lazy); returns `None` only if the static table is
/// somehow unparseable.
#[cfg_attr(coverage, allow(dead_code))]
fn build_dot_resolver() -> Option<TokioResolver> {
    let servers: Vec<NameServerConfig> = DOT_SERVERS
        .iter()
        .filter_map(|(ip, name)| {
            ip.parse::<std::net::IpAddr>()
                .ok()
                .map(|addr| NameServerConfig::tls(addr, std::sync::Arc::from(*name)))
        })
        .collect();
    if servers.is_empty() {
        return None;
    }
    let config = ResolverConfig::from_parts(None, vec![], servers);
    let mut opts = ResolverOpts::default();
    // A generous inner timeout; each caller also bounds the lookup with an outer
    // `tokio::time::timeout`. Whichever fires, the result is typed as a transport failure
    // (NetError::Timeout or tokio Elapsed), never a false empty — see `direct_txt_outcome`.
    opts.timeout = std::time::Duration::from_secs(6);
    opts.attempts = 1;
    opts.edns0 = true;
    opts.use_hosts_file = ResolveHosts::Never;
    opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .ok()
}

/// Run one TXT lookup and classify it for the shared per-transport breaker. `TransportFailed` means
/// "no response within the outer budget" (a blocked/rate-limited transport); an authoritative empty
/// is `Empty`, not a failure. Works for any transport's resolver (DoT or direct UDP/53).
#[cfg(not(coverage))]
async fn direct_txt_outcome(
    resolver: &TokioResolver,
    domain: &str,
    outer_ms: u64,
) -> DirectOutcome {
    // Wave 1 (defect C): no shared connection permit — DNS transports are bounded by the
    // governor alone, so a DoT/UDP exchange can no longer queue behind 30 s subprocessor
    // fetches inside its own budget and read as a "blocked transport".
    match tokio::time::timeout(
        std::time::Duration::from_millis(outer_ms),
        resolver.txt_lookup(domain),
    )
    .await
    {
        // Outer budget exceeded: silence against our own budget — ambiguous evidence.
        Err(_) => DirectOutcome::TransportFailed(TransportEvidence::NoResponse),
        Ok(Ok(lookup)) => {
            let records: Vec<String> = lookup
                .answers()
                .iter()
                .map(|r| r.data.to_string())
                .collect();
            if records.is_empty() {
                DirectOutcome::Empty
            } else {
                DirectOutcome::Answered(records)
            }
        }
        Ok(Err(e)) => {
            // Typed classification (NOT the error's Display): a DNS-level response proves the
            // transport works → authoritative Empty; anything else is a real transport failure. See
            // net_error_is_authoritative_negative for why Display-matching would be a bug here.
            if net_error_is_authoritative_negative(&e) {
                DirectOutcome::Empty
            } else {
                DirectOutcome::TransportFailed(net_error_evidence(&e))
            }
        }
    }
}

/// CNAME analogue of `direct_txt_outcome`. An authoritative "no CNAME" (the common case) is `Empty`,
/// never a transport failure — critical because `do53_health` is shared with TXT lookups.
#[cfg(not(coverage))]
async fn direct_cname_outcome(
    resolver: &TokioResolver,
    domain: &str,
    outer_ms: u64,
) -> DirectOutcome {
    // Wave 1 (defect C): no shared connection permit — see `direct_txt_outcome`.
    match tokio::time::timeout(
        std::time::Duration::from_millis(outer_ms),
        resolver.lookup(domain, hickory_resolver::proto::rr::RecordType::CNAME),
    )
    .await
    {
        Err(_) => DirectOutcome::TransportFailed(TransportEvidence::NoResponse),
        Ok(Ok(lookup)) => {
            use hickory_resolver::proto::rr::RData;
            let records: Vec<String> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::CNAME(ref cname) => {
                        Some(cname.to_string().trim_end_matches('.').to_string())
                    }
                    _ => None,
                })
                .collect();
            if records.is_empty() {
                DirectOutcome::Empty
            } else {
                DirectOutcome::Answered(records)
            }
        }
        Ok(Err(e)) => {
            // Typed classification (NOT the error's Display): a DNS-level response proves the
            // transport works → authoritative Empty; anything else is a real transport failure. See
            // net_error_is_authoritative_negative for why Display-matching would be a bug here.
            if net_error_is_authoritative_negative(&e) {
                DirectOutcome::Empty
            } else {
                DirectOutcome::TransportFailed(net_error_evidence(&e))
            }
        }
    }
}

impl DnsServerPool {
    /// Create a new DNS server pool from configuration
    pub fn from_config(config: &AppConfig) -> Self {
        let doh_servers: Vec<DohServerConfig> = config
            .dns
            .doh_servers
            .iter()
            .map(|s| DohServerConfig {
                url: s.url.clone(),
                name: s.name.clone(),
                timeout_secs: s.timeout_secs,
            })
            .collect();

        let dns_servers: Vec<DnsServerConfig> = config
            .dns
            .dns_servers
            .iter()
            .map(|s| DnsServerConfig {
                address: s.address.clone(),
                name: s.name.clone(),
                timeout_secs: s.timeout_secs,
            })
            .collect();

        // `doh_builder`, not `hardened_builder`: the DoH endpoint list is fixed and tiny, so
        // keep-alive reuse here has a hard ceiling, whereas disabling it makes every query pay a
        // fresh TLS handshake — the storm that tripped the DoH breaker and demoted the scan onto
        // UDP/53 on 2026-07-29. See `http_client::DOH_POOL_MAX_IDLE_PER_HOST`.
        let client = crate::http_client::doh_builder()
            .timeout(std::time::Duration::from_secs(
                config.http.request_timeout_secs,
            ))
            .user_agent(&config.http.user_agent)
            .build()
            .expect("Failed to create HTTP client for DoH");

        // One resolver slot per configured UDP/53 server; see the field docs.
        let do53_resolvers: Vec<tokio::sync::OnceCell<Option<TokioResolver>>> = dns_servers
            .iter()
            .map(|_| tokio::sync::OnceCell::new())
            .collect();

        Self {
            doh_servers,
            dns_servers,
            current_doh_index: AtomicUsize::new(0),
            current_dns_index: AtomicUsize::new(0),
            client,
            dns_limiter: SharedRateLimiter::new(config.rate_limits.dns_queries_per_second),
            governor: config
                .rate_limits
                .dns_max_concurrency
                .map(crate::dns_governor::DnsGovernor::pinned)
                .unwrap_or_else(|| {
                    crate::dns_governor::DnsGovernor::new(crate::dns_governor::DEFAULT_MAX_LIMIT)
                }),
            dot_enabled: true,
            max_dns_retries: config.rate_limits.max_retries,
            failure_counter: None,
            name_failure_counter: None,
            doh_health: TransportHealth::default(),
            dot_health: TransportHealth::default(),
            do53_health: TransportHealth::default(),
            do53_budget: Do53Budget::new(),
            dot_resolver: tokio::sync::OnceCell::new(),
            do53_resolvers,
            #[cfg(not(coverage))]
            doh_failure_log: std::sync::Mutex::new(std::collections::HashMap::new()),
            #[cfg(not(coverage))]
            answer_memo: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Create a new DNS server pool with embedded defaults (for backwards compatibility)
    pub fn new() -> Self {
        let doh_servers = vec![
            // EVERY endpoint is an IP literal, deliberately, and this is load-bearing for
            // network safety rather than a style choice.
            //
            // These clients run with `POOL_MAX_IDLE_PER_HOST == 0` (http_client.rs:62), so every
            // DoH request opens a fresh TCP+TLS connection. reqwest is built without the
            // `hickory-dns` feature and sets no custom resolver, so establishing that connection
            // to a *hostname* goes through hyper's `GaiResolver` — plain `getaddrinfo`, which
            // reads /etc/resolv.conf and asks the LAN router, and which hyper does not cache.
            //
            // The list used to alternate hostname and IP forms of the same three providers under
            // strict round-robin, so roughly half of all DoH requests silently emitted an A+AAAA
            // pair to the router *before* the encrypted query even left the machine. On a depth-3
            // scan (45,398 subdomain lookups × 2 record types) that is order 10^5 unbudgeted
            // UDP/53 queries aimed at exactly the consumer DNS forwarder we are trying to
            // protect — the single largest contributor to the 2026-07-24 incident in which port
            // 53 went dark to every destination while ICMP and TCP/443 stayed healthy.
            //
            // Each provider below is the same operator as the hostname form it replaces, so
            // provider diversity is unchanged; only the bootstrap lookup is gone. These are
            // long-lived anycast addresses whose TLS certificates carry the IP in a SAN, so
            // certificate validation still succeeds. Quad9 + OpenDNS remain excluded: their DoH
            // does not serve the JSON GET API, so they returned 0 records and caused false
            // negatives.
            DohServerConfig {
                url: "https://1.1.1.1/dns-query".to_string(),
                name: "Cloudflare DoH (IP)".to_string(),
                timeout_secs: 3,
            },
            // Google's JSON DoH API is at /resolve, NOT /dns-query (the latter is
            // RFC-8484 wire-format and 400s for application/dns-json).
            DohServerConfig {
                url: "https://8.8.8.8/resolve".to_string(),
                name: "Google DoH (IP)".to_string(),
                timeout_secs: 3,
            },
            // dns.sb: a third independent operator so a deep scan's DNS load spreads
            // across three providers, not two — cutting per-provider throttle risk by a
            // third. Live-verified to serve the JSON GET API with TXT answer counts
            // identical to Cloudflare (unfiltered, no truncation; recall unaffected).
            DohServerConfig {
                url: "https://185.222.222.222/dns-query".to_string(),
                name: "dns.sb DoH (IP)".to_string(),
                timeout_secs: 3,
            },
            // Each operator's SECOND anycast address. These add endpoint capacity — spreading the
            // per-IP rate limits that public resolvers apply — without adding a fourth party to
            // trust or a new filtering policy to audit: same operator, same service, same answers.
            //
            // Live-verified 2026-07-29 against the project's JSON-GET-API rule, identical TXT
            // answer counts to their primaries (google.com 15, stripe.com 31, vanta.com 39), and
            // confirmed NOT to filter the ad/tracker domains this scanner exists to discover
            // (doubleclick.net, google-analytics.com, scorecardresearch.com all resolve). A
            // filtering resolver is the silent hazard here: it returns NXDOMAIN rather than an
            // error, which the scanner would read as "this vendor does not exist".
            //
            // Note this is depth, not a fix: more endpoints delay the DoH breaker, they do not stop
            // it tripping. The reason a deep scan stopped exhausting DoH is connection reuse
            // (`http_client::DOH_POOL_MAX_IDLE_PER_HOST`) plus the per-provider breaker above.
            DohServerConfig {
                url: "https://1.0.0.1/dns-query".to_string(),
                name: "Cloudflare DoH (IP, secondary)".to_string(),
                timeout_secs: 3,
            },
            DohServerConfig {
                url: "https://8.8.4.4/resolve".to_string(),
                name: "Google DoH (IP, secondary)".to_string(),
                timeout_secs: 3,
            },
            DohServerConfig {
                url: "https://45.11.45.11/dns-query".to_string(),
                name: "dns.sb DoH (IP, secondary)".to_string(),
                timeout_secs: 3,
            },
        ];

        let dns_servers = vec![
            DnsServerConfig {
                address: "1.1.1.1:53".to_string(),
                name: "Cloudflare".to_string(),
                timeout_secs: 2,
            },
            DnsServerConfig {
                address: "8.8.8.8:53".to_string(),
                name: "Google".to_string(),
                timeout_secs: 2,
            },
            DnsServerConfig {
                address: "9.9.9.9:53".to_string(),
                name: "Quad9".to_string(),
                timeout_secs: 3,
            },
            DnsServerConfig {
                address: "208.67.222.222:53".to_string(),
                name: "OpenDNS".to_string(),
                timeout_secs: 3,
            },
        ];

        // See the note in `from_config`: DoH gets keep-alive reuse because its endpoint list is
        // fixed and tiny. `http_client::DOH_POOL_MAX_IDLE_PER_HOST`.
        let client = crate::http_client::doh_builder()
            .timeout(std::time::Duration::from_secs(5))
            .user_agent(crate::http_client::USER_AGENT)
            .build()
            .expect("Failed to create HTTP client for DoH");

        // One resolver slot per configured UDP/53 server; see the field docs.
        let do53_resolvers: Vec<tokio::sync::OnceCell<Option<TokioResolver>>> = dns_servers
            .iter()
            .map(|_| tokio::sync::OnceCell::new())
            .collect();

        Self {
            doh_servers,
            dns_servers,
            current_doh_index: AtomicUsize::new(0),
            current_dns_index: AtomicUsize::new(0),
            client,
            dns_limiter: SharedRateLimiter::new(50), // matches config default_dns_queries_per_second
            governor: crate::dns_governor::DnsGovernor::new(crate::dns_governor::DEFAULT_MAX_LIMIT),
            dot_enabled: true,
            max_dns_retries: 3,
            failure_counter: None,
            name_failure_counter: None,
            doh_health: TransportHealth::default(),
            dot_health: TransportHealth::default(),
            do53_health: TransportHealth::default(),
            do53_budget: Do53Budget::new(),
            dot_resolver: tokio::sync::OnceCell::new(),
            do53_resolvers,
            #[cfg(not(coverage))]
            doh_failure_log: std::sync::Mutex::new(std::collections::HashMap::new()),
            #[cfg(not(coverage))]
            answer_memo: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// GRC-367 (fix 1): wire the pool's choke-point throttle counter to a shared atomic
    /// (production: `logger.dns_failure_counter_arc()`). After this, `note_throttle()` — called
    /// inside `doh_txt_lookup`/`doh_cname_lookup` on a 429/5xx — increments this atomic on every
    /// DoH path, including the previously-untracked SPF include-chain recursion. Builder-style so
    /// the production construction sites stay one expression: `from_config(&cfg).with_failure_counter(..)`.
    pub fn with_failure_counter(
        mut self,
        c: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.failure_counter = Some(c);
        self
    }

    /// Companion to [`Self::with_failure_counter`] for the name-attributable subset.
    pub fn with_name_failure_counter(
        mut self,
        c: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.name_failure_counter = Some(c);
        self
    }

    /// Disable the DoT tier (test-support for the hermetic contention gate: a farm-driven pool
    /// must never escalate a simulated DoH failure into a real :853 connection).
    #[doc(hidden)]
    pub fn disable_dot(mut self) -> Self {
        self.dot_enabled = false;
        self
    }

    /// Replace the governor (test-support: lets the contention gate pin or resize the controller
    /// while keeping every other production default from `from_config`).
    #[doc(hidden)]
    pub fn with_governor(
        mut self,
        governor: std::sync::Arc<crate::dns_governor::DnsGovernor>,
    ) -> Self {
        self.governor = governor;
        self
    }

    /// Point-in-time state of the three transport breakers (Phase-0 observability; the contention
    /// gate's primary assertion surface).
    pub fn transport_snapshot(&self) -> TransportSnapshot {
        let view = |h: &TransportHealth, sources: usize| TransportView {
            down_transitions: h.transitions(),
            is_down: h.is_down(sources),
            consecutive_failures: h.consecutive(),
            implicated_mask: h.failed_mask(),
            reprobes: h.reprobes.load(Ordering::Relaxed),
        };
        TransportSnapshot {
            doh: view(&self.doh_health, self.doh_servers.len().max(1)),
            dot: view(&self.dot_health, 1),
            do53: view(&self.do53_health, 1),
        }
    }

    /// Count ONE logical failure that the queried NAME caused: the resolver answered over a
    /// working transport with SERVFAIL/REFUSED, so the name's own authoritative servers are at
    /// fault. Increments the general counter too — it is still a DNS failure for the exit-3
    /// guard — but the separate tally lets the summary avoid telling the user to fix a network
    /// that is fine. Wave 1: called only at negative-memo terminals (a memo hit IS the lookup's
    /// terminal); live lookups count at their own terminal sites instead.
    fn note_name_failure(&self) {
        crate::dns_telemetry::DNS_TELEMETRY
            .failure_site(crate::dns_telemetry::FailureSite::NegativeMemoHit);
        self.note_throttle();
        self.note_name_attribution();
    }

    /// Add to the name-attributed tally *only* — for callers that have already counted the failure
    /// in the general counter themselves.
    fn note_name_attribution(&self) {
        if let Some(c) = &self.name_failure_counter {
            c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Count one LOGICAL lookup arm that ended unresolved, at its terminal (Wave 1, defect E).
    ///
    /// This is the scan-level `dns_failures` semantic: one increment per lookup arm that the scan
    /// could not resolve — never one per provider attempt (those live in the per-provider tallies)
    /// and never a re-count of the same arm at two layers. Every error counts, classified or not:
    /// under logical counting an unclassified decode failure is still an arm the scan lost. The
    /// name-attributed subset keeps the summary honest about whose fault the failures were —
    /// `transport_failures = general - name` — so a broken domain is not reported as a degraded
    /// local link.
    fn note_classified_failure(&self, msg: &str, general: &AtomicUsize) {
        general.fetch_add(1, Ordering::Relaxed);
        crate::dns_telemetry::DNS_TELEMETRY
            .failure_site(crate::dns_telemetry::FailureSite::SettleArm);
        if msg.contains("DNS_NAME") {
            self.note_name_attribution();
        }
    }

    /// GRC-367 (fix 1): the choke-point increment. A no-op until `with_failure_counter` has been
    /// called, so tests that don't opt in are unaffected. Called from both DoH lookups the instant
    /// a throttle (429/5xx) is detected — making throttle visibility path-independent.
    fn note_throttle(&self) {
        if let Some(c) = &self.failure_counter {
            c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Per-provider failure visibility: the FIRST failure from a given provider warns
    /// (actionable signal — a configured provider is misconfigured, down, or speaking the
    /// wrong API); repeats from the same provider log at debug so a long scan against a
    /// dead provider doesn't drown the output in duplicate warnings.
    // cfg(not(coverage)): only the live resilient lookups call this — gated identically
    // to them so it is not dead code under the coverage profile.
    #[cfg(not(coverage))]
    fn log_doh_failure(&self, server_name: &str, err: &str) {
        let mut counts = match self.doh_failure_log.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let n = counts.entry(server_name.to_string()).or_insert(0);
        *n += 1;
        if *n == 1 {
            warn!(
                "DoH provider '{}' failed: {} (subsequent failures from this provider log at debug)",
                server_name, err
            );
        } else {
            debug!("DoH provider '{}' failure #{}: {}", server_name, *n, err);
        }
    }
}

impl Default for DnsServerPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl DnsServerPool {
    /// Create a DnsServerPool with custom DoH URLs for testing.
    /// Allows injecting wiremock server addresses for mocked DNS responses.
    ///
    /// # Arguments
    /// * `urls` - A vector of DoH endpoint URLs (e.g., wiremock server addresses)
    ///
    /// # Example
    /// ```ignore
    /// let mock_server = wiremock::MockServer::start().await;
    /// let pool = DnsServerPool::with_test_urls(vec![mock_server.uri()]);
    /// ```
    pub fn with_test_urls(urls: Vec<String>) -> Self {
        let doh_servers: Vec<DohServerConfig> = urls
            .into_iter()
            .enumerate()
            .map(|(i, url)| DohServerConfig {
                url,
                name: format!("Test DoH Server {}", i + 1),
                timeout_secs: 5,
            })
            .collect();

        // Provide minimal DNS fallback servers for tests (won't be used if DoH succeeds)
        let dns_servers = vec![DnsServerConfig {
            address: "127.0.0.1:53".to_string(),
            name: "Test DNS Fallback".to_string(),
            timeout_secs: 2,
        }];

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("nthpartyfinder-test/1.0")
            .build()
            .expect("Failed to create HTTP client for test DoH");

        let do53_resolvers: Vec<tokio::sync::OnceCell<Option<TokioResolver>>> = dns_servers
            .iter()
            .map(|_| tokio::sync::OnceCell::new())
            .collect();

        Self {
            doh_servers,
            dns_servers,
            current_doh_index: AtomicUsize::new(0),
            current_dns_index: AtomicUsize::new(0),
            client,
            dns_limiter: SharedRateLimiter::new(1000), // effectively unthrottled for tests
            // Hermetic tests must not be paced by adaptation; pin wide open.
            governor: crate::dns_governor::DnsGovernor::pinned(1000),
            dot_enabled: false, // hermetic tests must not hit real DoT (853) servers
            max_dns_retries: 3,
            failure_counter: None,
            name_failure_counter: None,
            doh_health: TransportHealth::default(),
            dot_health: TransportHealth::default(),
            do53_health: TransportHealth::default(),
            do53_budget: Do53Budget::new(),
            dot_resolver: tokio::sync::OnceCell::new(),
            do53_resolvers,
            #[cfg(not(coverage))]
            doh_failure_log: std::sync::Mutex::new(std::collections::HashMap::new()),
            #[cfg(not(coverage))]
            answer_memo: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl DnsServerPool {
    /// Get the next DoH server in rotation
    fn next_doh_server(&self) -> &DohServerConfig {
        let index = self.current_doh_index.fetch_add(1, Ordering::Relaxed) % self.doh_servers.len();
        &self.doh_servers[index]
    }

    /// Get the next DNS server in rotation (for fallback)
    fn next_dns_server(&self) -> &DnsServerConfig {
        let index = self.current_dns_index.fetch_add(1, Ordering::Relaxed) % self.dns_servers.len();
        &self.dns_servers[index]
    }

    /// Empty-pool-safe rotation. `next_doh_server`/`next_dns_server` index with
    /// `% len`, which panics on an empty list — and a config with only one of
    /// the two server kinds is legal (validation requires "at least one DoH OR
    /// DNS server"). Production lookup paths must rotate through these instead.
    #[cfg(not(coverage))]
    fn next_doh_server_opt(&self) -> Option<&DohServerConfig> {
        self.next_doh_server_indexed().map(|(_, s)| s)
    }

    /// May the raw UDP/53 tier issue one query right now?
    ///
    /// Both gates, in one place so a test can exercise the real admission decision rather than the
    /// budget in isolation — the wiring is the part that matters, and a unit test of `Do53Budget`
    /// alone stays green if this call site drops it.
    ///
    /// Order matters: the budget is a ceiling on what we are willing to emit, checked before the
    /// breaker's opinion about what is failing. Note `try_take` consumes a token, so this is not a
    /// predicate — call it exactly once per intended query.
    fn admit_do53_query(&self) -> bool {
        // Split for observability (Phase-0): a breaker skip and a budget shed are different
        // stories — one says "port 53 looked broken", the other "we chose not to emit". The
        // short-circuit order is unchanged: the budget token is only consumed when the breaker
        // admits, preserving the single-flight reprobe CAS semantics.
        let tier = crate::dns_telemetry::DNS_TELEMETRY.tier(crate::dns_telemetry::Tier::Udp53);
        if !self.do53_health.should_attempt() {
            tier.skipped_breaker.fetch_add(1, Ordering::Relaxed);
            crate::perf::METRICS.dns_udp53_skipped_breaker.hit();
            return false;
        }
        if !self.do53_budget.try_take() {
            tier.skipped_budget.fetch_add(1, Ordering::Relaxed);
            crate::perf::METRICS.dns_udp53_shed.hit();
            return false;
        }
        true
    }

    /// Rotation that also yields the provider's index, so a failure can be attributed to the
    /// specific upstream that produced it. The DoH breaker needs this: it may only declare the
    /// transport down once *every* configured provider has failed, which is impossible to tell
    /// from an unattributed failure count (see `TransportHealth::failed_sources`).
    #[cfg(not(coverage))]
    fn next_doh_server_indexed(&self) -> Option<(usize, &DohServerConfig)> {
        if self.doh_servers.is_empty() {
            return None;
        }
        let index = self.current_doh_index.fetch_add(1, Ordering::Relaxed) % self.doh_servers.len();
        Some((index, &self.doh_servers[index]))
    }

    /// Empty-pool-safe UDP/53 rotation that also yields the server's index, because the cached
    /// resolver for that server lives at the same index (`do53_resolvers`).
    #[cfg(not(coverage))]
    fn next_dns_server_indexed(&self) -> Option<(usize, &DnsServerConfig)> {
        if self.dns_servers.is_empty() {
            return None;
        }
        let index = self.current_dns_index.fetch_add(1, Ordering::Relaxed) % self.dns_servers.len();
        Some((index, &self.dns_servers[index]))
    }

    /// The reused UDP/53 resolver for `index`, building it on first use.
    ///
    /// `None` means this server cannot be used at all — its configured address did not parse — so
    /// the caller skips the tier for it, exactly as the previous per-call construction did on a
    /// build failure. The build is memoized either way: a server with a malformed address must not
    /// re-attempt (and re-log) construction on every lookup.
    #[cfg(not(coverage))]
    async fn do53_resolver(
        &self,
        index: usize,
        server: &DnsServerConfig,
    ) -> Option<&TokioResolver> {
        self.do53_resolvers
            .get(index)?
            .get_or_init(|| async { self.create_dns_resolver(server, false).ok() })
            .await
            .as_ref()
    }

    // cfg(not(coverage)): performs live HTTPS request to DoH provider — requires network
    #[cfg(not(coverage))]
    async fn doh_txt_lookup(
        &self,
        domain: &str,
        server_index: usize,
        server: &DohServerConfig,
        attempt_budget: std::time::Duration,
    ) -> Result<TxtAnswer> {
        debug!("DoH lookup for {} using {}", domain, server.name);
        let provider = crate::dns_telemetry::DNS_TELEMETRY.provider(server_index);
        provider.attempts.fetch_add(1, Ordering::Relaxed);
        let _attempt_timer = crate::perf::scoped(&crate::perf::METRICS.dns_doh_attempt);
        let attempt_t0 = std::time::Instant::now();

        // Create DNS query in wire format
        let query_params = [("name", domain), ("type", "TXT")];

        // Wave 1 (defect C): sent WITHOUT the shared connection semaphore. DNS egress is bounded
        // by the governor's permit alone; queueing DoH behind 30 s subprocessor fetches inside its
        // own budget is exactly what Phase 1 measured as S_wait = 0.228 with half the timeouts
        // firing before a byte was sent.
        let sent = self
            .client
            .get(&server.url)
            .query(&query_params)
            .header("Accept", "application/dns-json")
            .timeout(attempt_budget)
            .send()
            .await;
        let http_response = match sent {
            Ok(response) => {
                // Send-to-headers latency of this one exchange: the provider-attributable RTT and
                // the governor's leaf sample (defect G: never a permit lifetime, never a sleep).
                let rtt = attempt_t0.elapsed();
                provider.rtt.record(rtt);
                self.governor.record_rtt(rtt);
                response
            }
            Err(e) => {
                if e.is_timeout() {
                    // Typed classification at the source (defect F): the class travels in the
                    // message like every other DNS_* class, so no downstream layer ever has to
                    // substring-match reqwest's free text again.
                    provider.timeout_after_send.fetch_add(1, Ordering::Relaxed);
                    return Err(anyhow::anyhow!(
                        "DNS_TIMEOUT: DoH provider {} exceeded its {}ms attempt budget for {}",
                        server.name,
                        attempt_budget.as_millis(),
                        domain
                    ));
                } else if e.is_connect() {
                    provider.connect_err.fetch_add(1, Ordering::Relaxed);
                } else {
                    let wrapped = anyhow::Error::from(e);
                    if Self::is_local_resource_error(&wrapped) {
                        provider.local_resource_err.fetch_add(1, Ordering::Relaxed);
                    } else {
                        provider.other_err.fetch_add(1, Ordering::Relaxed);
                    }
                    return Err(wrapped);
                }
                return Err(e.into());
            }
        };
        // GRC-367: a throttle (429) or provider 5xx MUST surface as a distinct error —
        // never be parsed into an empty answer, which the caller would otherwise mistake
        // for "this domain has no records" and report as a false-negative 0-vendor result.
        //
        // Wave 1 (defect E): per-ATTEMPT failures live in the per-provider tallies only; the
        // scan-level `dns_failures` counter now counts LOGICAL lookups that end unresolved, at
        // their terminal sites. Counting here made 4 rotations read as 4 scan failures.
        let status = http_response.status();
        if status.as_u16() == 429 || status.is_server_error() {
            if status.as_u16() == 429 {
                provider.http_429.fetch_add(1, Ordering::Relaxed);
            } else {
                provider.http_5xx.fetch_add(1, Ordering::Relaxed);
            }
            return Err(anyhow::anyhow!(
                "DNS_THROTTLE: DoH provider {} returned HTTP {} for {}",
                server.name,
                status,
                domain
            ));
        }
        // Any other non-2xx (400/403/404…) means the endpoint cannot serve this query at
        // all — wrong API path, wrong protocol, misconfiguration. Never parse it into an
        // empty answer: that is the exact silent-false-negative class of the
        // /dns-query-vs-/resolve incident (3 of 4 default providers returned HTTP 400 and
        // were read as "0 TXT records"). Count it for the exit-3 guard and surface a
        // distinct DNS_ENDPOINT class so the resilient loop rotates WITHOUT backoff.
        if !status.is_success() {
            provider.http_4xx_other.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider {} returned HTTP {} for {} — endpoint does not serve the JSON DoH API or rejected the query",
                server.name,
                status,
                domain
            ));
        }
        let response = http_response.json::<Value>().await?;
        // dns-json `Status` is the DNS RCODE: 0 = NOERROR and 3 = NXDOMAIN are genuine
        // answers (records present / genuinely absent). Anything else (2 = SERVFAIL,
        // 5 = REFUSED, …) is a resolver-side failure that must never read as "this domain
        // has no records". A missing `Status` field is tolerated (lenient providers/fixtures).
        //
        // Classed `DNS_NAME`, NOT `DNS_ENDPOINT`: we received an HTTPS response carrying a
        // well-formed dns-json body, so the TRANSPORT demonstrably works — what failed is this
        // NAME, at its own authoritative servers. Conflating the two was a real bug (2026-07-29):
        // a pathological name SERVFAILs identically on every provider, which trivially satisfies
        // the DoH breaker's "all providers failed" condition and demoted a perfectly healthy
        // transport onto UDP/53. One broken domain must never take the transport down.
        if let Some(rcode) = response["Status"].as_u64() {
            if rcode != 0 && rcode != 3 {
                provider.rcode_fail.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow::anyhow!(
                    "DNS_NAME: DoH provider {} returned DNS RCODE {} for {}",
                    server.name,
                    rcode,
                    domain
                ));
            }
        } else if response["Answer"].as_array().is_none() {
            // A 2xx JSON body with NO Status and NO Answer is not a dns-json
            // answer at all (captive portal, proxy error page, middlebox `{}`)
            // — treating it as authoritative-empty would re-arm the silent
            // 0-record incident behind an HTTP 200. Only a body carrying the
            // RCODE (or actual records) earns authoritative-empty trust.
            provider.non_dnsjson_2xx.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider {} returned a 2xx body without Status or Answer for {} — not a DNS JSON answer",
                server.name,
                domain
            ));
        }

        let mut records = Vec::new();

        if let Some(answers) = response["Answer"].as_array() {
            for answer in answers {
                if answer["type"].as_u64() == Some(16) {
                    // TXT record type
                    if let Some(data) = answer["data"].as_str() {
                        // Remove quotes and handle escaped characters
                        let cleaned = unescape_dns_txt(data.trim_matches('"'));
                        records.push(cleaned);
                    }
                }
            }
        }

        // The alias chain the resolver had to follow to answer at all. Past the RCODE gate above
        // this response is authoritative, so an EMPTY chain is a positive fact — the name is not
        // aliased — and the caller may skip the separate CNAME query entirely. See `TxtAnswer`.
        let cname = cname_chain_from_dns_json(&response);

        debug!(
            "DoH found {} TXT records ({} CNAME hops) for {} via {}",
            records.len(),
            cname.len(),
            domain,
            server.name
        );
        provider.ok.fetch_add(1, Ordering::Relaxed);
        Ok(TxtAnswer {
            txt: records,
            cname: Some(cname),
        })
    }

    #[cfg(coverage)]
    async fn doh_txt_lookup(
        &self,
        _domain: &str,
        _server_index: usize,
        _server: &DohServerConfig,
        _attempt_budget: std::time::Duration,
    ) -> Result<TxtAnswer> {
        Ok(TxtAnswer::default())
    }

    // cfg(not(coverage)): performs live HTTPS request to DoH provider — requires network
    #[cfg(not(coverage))]
    async fn doh_cname_lookup(
        &self,
        domain: &str,
        server_index: usize,
        server: &DohServerConfig,
        attempt_budget: std::time::Duration,
    ) -> Result<Vec<String>> {
        debug!("DoH CNAME lookup for {} using {}", domain, server.name);
        let provider = crate::dns_telemetry::DNS_TELEMETRY.provider(server_index);
        provider.attempts.fetch_add(1, Ordering::Relaxed);
        let _attempt_timer = crate::perf::scoped(&crate::perf::METRICS.dns_doh_attempt);
        let attempt_t0 = std::time::Instant::now();

        let query_params = [("name", domain), ("type", "CNAME")];

        // Wave 1 (defect C): no shared connection semaphore — see the TXT twin.
        let sent = self
            .client
            .get(&server.url)
            .query(&query_params)
            .header("Accept", "application/dns-json")
            .timeout(attempt_budget)
            .send()
            .await;
        let http_response = match sent {
            Ok(response) => {
                let rtt = attempt_t0.elapsed();
                provider.rtt.record(rtt);
                self.governor.record_rtt(rtt);
                response
            }
            Err(e) => {
                if e.is_timeout() {
                    // Typed classification at the source (defect F) — see the TXT twin.
                    provider.timeout_after_send.fetch_add(1, Ordering::Relaxed);
                    return Err(anyhow::anyhow!(
                        "DNS_TIMEOUT: DoH provider {} exceeded its {}ms attempt budget for {}",
                        server.name,
                        attempt_budget.as_millis(),
                        domain
                    ));
                } else if e.is_connect() {
                    provider.connect_err.fetch_add(1, Ordering::Relaxed);
                } else {
                    let wrapped = anyhow::Error::from(e);
                    if Self::is_local_resource_error(&wrapped) {
                        provider.local_resource_err.fetch_add(1, Ordering::Relaxed);
                    } else {
                        provider.other_err.fetch_add(1, Ordering::Relaxed);
                    }
                    return Err(wrapped);
                }
                return Err(e.into());
            }
        };
        // GRC-367: surface DoH throttle/5xx as a distinct error, never an empty answer.
        // Wave 1 (defect E): per-attempt tallies only here — see the TXT twin.
        let status = http_response.status();
        if status.as_u16() == 429 || status.is_server_error() {
            if status.as_u16() == 429 {
                provider.http_429.fetch_add(1, Ordering::Relaxed);
            } else {
                provider.http_5xx.fetch_add(1, Ordering::Relaxed);
            }
            return Err(anyhow::anyhow!(
                "DNS_THROTTLE: DoH provider {} returned HTTP {} for {}",
                server.name,
                status,
                domain
            ));
        }
        // Any other non-2xx is a broken/misconfigured endpoint — surface DNS_ENDPOINT,
        // never an empty answer (mirrors the TXT path; see comment there).
        if !status.is_success() {
            provider.http_4xx_other.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider {} returned HTTP {} for {} — endpoint does not serve the JSON DoH API or rejected the query",
                server.name,
                status,
                domain
            ));
        }
        let response = http_response.json::<Value>().await?;
        // RCODE gate mirroring the TXT path: only NOERROR (0) and NXDOMAIN (3) are genuine
        // answers; SERVFAIL/REFUSED/… must never read as "no CNAME".
        //
        // Classed `DNS_NAME`, NOT `DNS_ENDPOINT`: we received an HTTPS response carrying a
        // well-formed dns-json body, so the TRANSPORT demonstrably works — what failed is this
        // NAME, at its own authoritative servers. Conflating the two was a real bug (2026-07-29):
        // a pathological name SERVFAILs identically on every provider, which trivially satisfies
        // the DoH breaker's "all providers failed" condition and demoted a perfectly healthy
        // transport onto UDP/53. One broken domain must never take the transport down.
        if let Some(rcode) = response["Status"].as_u64() {
            if rcode != 0 && rcode != 3 {
                provider.rcode_fail.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow::anyhow!(
                    "DNS_NAME: DoH provider {} returned DNS RCODE {} for {}",
                    server.name,
                    rcode,
                    domain
                ));
            }
        } else if response["Answer"].as_array().is_none() {
            // No Status and no Answer: not a dns-json answer (see TXT path).
            provider.non_dnsjson_2xx.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider {} returned a 2xx body without Status or Answer for {} — not a DNS JSON answer",
                server.name,
                domain
            ));
        }

        let mut records = Vec::new();

        if let Some(answers) = response["Answer"].as_array() {
            for answer in answers {
                if answer["type"].as_u64() == Some(5) {
                    // CNAME record type
                    if let Some(data) = answer["data"].as_str() {
                        // Remove trailing dot from CNAME targets
                        let cleaned = data.trim_end_matches('.').to_string();
                        records.push(cleaned);
                    }
                }
            }
        }

        debug!(
            "DoH found {} CNAME records for {} via {}",
            records.len(),
            domain,
            server.name
        );
        provider.ok.fetch_add(1, Ordering::Relaxed);
        Ok(records)
    }

    #[cfg(coverage)]
    async fn doh_cname_lookup(
        &self,
        _domain: &str,
        _server_index: usize,
        _server: &DohServerConfig,
        _attempt_budget: std::time::Duration,
    ) -> Result<Vec<String>> {
        Ok(vec![])
    }

    /// GRC-367: number of provider attempts a resilient lookup may make (1 + retries,
    /// bounded by the number of DoH providers actually configured).
    ///
    /// GRC-367 (fix 4): only the `#[cfg(not(coverage))]` resilient lookups call this, so it
    /// is gated identically — otherwise it is a dead-code warning under the coverage profile.
    #[cfg(not(coverage))]
    fn resilient_attempts(&self) -> usize {
        ((self.max_dns_retries as usize) + 1)
            .min(self.doh_servers.len().max(1))
            .max(1)
    }

    /// The per-attempt budget for attempt `i` of `attempts`, given the rotation's `deadline`.
    ///
    /// The loop owns its deadline (Wave 1, defect A): each attempt gets a fair slice of what
    /// REMAINS, floored by the governor's measured RTO — so an attempt is never granted less time
    /// than a real answer plausibly takes on this network, and rotation always completes inside
    /// [`DOH_LOOKUP_DEADLINE`]. Returns `None` when the deadline is exhausted (stop rotating).
    /// The per-server configured timeout stays as an upper cap, preserving config semantics.
    ///
    /// COLD START: until the governor has a measured RTO, the attempt gets the FULL remaining
    /// deadline, not a slice. Slicing before any RTT evidence exists locks a slow-but-healthy
    /// network out permanently: with a 3 s deadline over 4 attempts every attempt gets 750 ms, a
    /// network whose real answers take ~1.2 s never completes one, and — because no success ever
    /// lands a sample — the RTO that would widen the budget can never be learned. The contention
    /// gate's P1 profile (all providers healthy at 0.9–1.5 s) measured exactly that: 100% loss,
    /// a false DoH demotion, and 42 s parked at the governor floor. Not cancelling an in-flight
    /// attempt before the path's RTT is known is RFC 6298's own §2.1 posture (a deliberately
    /// generous pre-measurement RTO); rotation-past-a-hang begins once evidence exists, which on
    /// a concurrent scan is within the first wave of lookups.
    #[cfg(not(coverage))]
    fn attempt_budget(
        &self,
        deadline: std::time::Instant,
        i: usize,
        attempts: usize,
        server_cap_secs: u64,
    ) -> Option<std::time::Duration> {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let attempts_left = (attempts.saturating_sub(i)).max(1) as u32;
        let fair = remaining / attempts_left;
        let budget = self
            .governor
            .rto()
            .map_or(remaining, |rto| rto.max(fair))
            .min(remaining)
            .min(std::time::Duration::from_secs(server_cap_secs.max(1)));
        crate::perf::METRICS.dns_doh_attempt_budget.record(budget);
        Some(budget)
    }

    /// GRC-367 + Wave 1: DoH TXT lookup with deadline-owned provider rotation. The loop slices
    /// [`DOH_LOOKUP_DEADLINE`] across its remaining attempts (see [`Self::attempt_budget`]) and
    /// rotates immediately past ANY failing provider — no sleeps: a 429 from provider N says
    /// nothing about provider N+1, and Phase 1 observed zero real 429s while rotation-killing
    /// timeouts were epidemic. A surviving failure propagates with its class intact.
    #[cfg(not(coverage))]
    async fn doh_txt_lookup_resilient(&self, domain: &str) -> Result<TxtAnswer> {
        let attempts = self.resilient_attempts();
        let deadline = std::time::Instant::now() + DOH_LOOKUP_DEADLINE;
        let mut last_err: Option<anyhow::Error> = None;
        for i in 0..attempts {
            // DoH-only configs are legal; so are DNS-only ones — never index an
            // empty pool (panic), surface a plain error the callers treat as a
            // non-class failure and fall back from.
            let Some((server_index, server)) =
                self.next_doh_server_indexed().map(|(i, s)| (i, s.clone()))
            else {
                return Err(anyhow::anyhow!(
                    "no DoH servers configured for TXT lookup of {}",
                    domain
                ));
            };
            let Some(budget) = self.attempt_budget(deadline, i, attempts, server.timeout_secs)
            else {
                break; // deadline exhausted — surface the last classified failure below
            };
            let mut probe = crate::dns_telemetry::AttemptProbe::new(i);
            match self
                .doh_txt_lookup(domain, server_index, &server, budget)
                .await
            {
                Ok(records) => {
                    probe.disarm();
                    crate::dns_telemetry::DNS_TELEMETRY.ok_at_attempt(i);
                    return Ok(records);
                }
                Err(e) => {
                    probe.disarm();
                    let msg = e.to_string();
                    self.log_doh_failure(&server.name, &msg);
                    if Self::is_local_resource_error(&e) {
                        // EMFILE / local FD exhaustion is not a provider fault: the next provider,
                        // opened from this same exhausted process, would fail identically, and each
                        // rotation burns another descriptor against the same wall. Stop rotating;
                        // the class marker keeps the terminal counting honest about whose fault
                        // this was (ours, locally — not the network's and not the name's). The
                        // per-provider `local_resource_err` tally at the choke point is the
                        // occurrence record; `failure_sites` tracks only counter increments.
                        last_err = Some(anyhow::anyhow!("DNS_LOCAL: {:#}", e));
                        break;
                    }
                    // A DNS_NAME error means the provider ANSWERED — an HTTPS response carrying a
                    // well-formed dns-json body that happens to report SERVFAIL/REFUSED for this
                    // name. A DNS_THROTTLE (429/5xx) is equally positive transport evidence: the
                    // provider delivered an HTTP response over a working path and chose to shed
                    // the query. Both clear the streak (Wave 1, defect B — Phase 1 measured 100%
                    // of demotions false while every probe was healthy).
                    //
                    // A DNS_TIMEOUT is silence against OUR OWN measured budget — ambiguous
                    // evidence that advances the breaker only once the governor has retreated to
                    // its floor (see `TransportEvidence`; the r2 validation A/B measured 10 false
                    // DoH demotions from timeout bursts at 64 in-flight with zero connect
                    // errors). Everything else — connect refused, TLS failure, wrong-API
                    // endpoints, undecodable bodies — is direct transport/endpoint evidence and
                    // always advances the streak.
                    if msg.contains("DNS_NAME") || msg.contains("DNS_THROTTLE") {
                        if self.doh_health.record_success() {
                            note_transport_recovered(crate::dns_telemetry::Tier::Doh);
                        }
                    } else if !msg.contains("DNS_TIMEOUT") || self.governor.has_retreated_to_floor()
                    {
                        // Attribute a genuine transport failure to the provider that produced it.
                        // The DoH breaker may only trip once EVERY configured provider has failed
                        // in the current streak, so an unattributed count would let one sick
                        // endpoint demote a working transport.
                        // Wave 2: the EVIDENCE gate above is the whole discriminator —
                        // `is_backing_off` no longer suppresses, so a genuine outage at the
                        // governor floor trips reliably instead of hiding behind a
                        // perpetually-refreshed cooldown.
                        self.doh_health
                            .record_failure_from(server_index, self.doh_servers.len());
                    }
                    last_err = Some(e);
                    // Rotate past ANY failing provider — broken (4xx/RCODE), unreachable
                    // (transport), throttling (429), or misbehaving (parse) endpoints: the next
                    // provider is independent, and the deadline is the only budget that matters.
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!(
                "DNS_TIMEOUT: DoH TXT rotation deadline ({}ms) exhausted for {}",
                DOH_LOOKUP_DEADLINE.as_millis(),
                domain
            )
        }))
    }

    #[cfg(coverage)]
    async fn doh_txt_lookup_resilient(&self, _domain: &str) -> Result<TxtAnswer> {
        Ok(TxtAnswer::default())
    }

    /// True when a DoH send failed because *this process* ran out of a local resource — chiefly
    /// file descriptors (EMFILE, per-process errno 24; or ENFILE, system-wide errno 23) — not
    /// because a DoH provider misbehaved. Rotating to the next provider on such a failure is futile
    /// (it opens another socket against the same exhausted process) and counts one logical lookup
    /// as several failures, so the resilient loops stop rotating on it.
    ///
    /// Classifies on the *typed* error first — walking the chain for an `io::Error` and matching its
    /// raw OS errno — so it is robust to how reqwest/hyper render the message (errno 23/24 are the
    /// same on Linux and macOS). Falls back to a text match for wrappers that stringify the OS error
    /// instead of preserving a downcastable `io::Error`. Takes the error (not a pre-rendered string)
    /// precisely so the typed path is available; unit-testable by constructing an `io::Error`.
    fn is_local_resource_error(err: &anyhow::Error) -> bool {
        for cause in err.chain() {
            if let Some(io) = cause.downcast_ref::<std::io::Error>() {
                if matches!(io.raw_os_error(), Some(23) | Some(24)) {
                    return true;
                }
            }
        }
        // Fallback for wrappers that stringify the OS error instead of preserving a downcastable
        // `io::Error`. MUST use the alternate `{:#}` form: a reqwest error's plain `Display`
        // (== `to_string()`) prints only "error sending request for url (…)" and omits its io
        // source — where the "os error 24" text actually lives — so a plain-Display match would
        // silently miss every real EMFILE (verified against reqwest 0.13.4). `{:#}` walks the chain.
        let msg = format!("{err:#}");
        msg.contains("Too many open files") || msg.contains("os error 24")
    }

    /// GRC-367 (fix 2) + Wave 1: DoH CNAME lookup with deadline-owned provider rotation,
    /// mirroring [`Self::doh_txt_lookup_resilient`] — same deadline slicing, same no-sleep
    /// rotation, same class-marker propagation. On a genuine no-CNAME the inner lookup returns
    /// `Ok(vec![])`, which we propagate as-is.
    #[cfg(not(coverage))]
    async fn doh_cname_lookup_resilient(&self, domain: &str) -> Result<Vec<String>> {
        let attempts = self.resilient_attempts();
        let deadline = std::time::Instant::now() + DOH_LOOKUP_DEADLINE;
        let mut last_err: Option<anyhow::Error> = None;
        for i in 0..attempts {
            // Mirror the TXT path: never index an empty DoH pool.
            let Some((server_index, server)) =
                self.next_doh_server_indexed().map(|(i, s)| (i, s.clone()))
            else {
                return Err(anyhow::anyhow!(
                    "no DoH servers configured for CNAME lookup of {}",
                    domain
                ));
            };
            let Some(budget) = self.attempt_budget(deadline, i, attempts, server.timeout_secs)
            else {
                break; // deadline exhausted — surface the last classified failure below
            };
            let mut probe = crate::dns_telemetry::AttemptProbe::new(i);
            match self
                .doh_cname_lookup(domain, server_index, &server, budget)
                .await
            {
                Ok(records) => {
                    probe.disarm();
                    crate::dns_telemetry::DNS_TELEMETRY.ok_at_attempt(i);
                    return Ok(records);
                }
                Err(e) => {
                    probe.disarm();
                    let msg = e.to_string();
                    self.log_doh_failure(&server.name, &msg);
                    if Self::is_local_resource_error(&e) {
                        // Local FD exhaustion, not a provider fault — stop rotating, classify
                        // (see the TXT path for the full rationale).
                        last_err = Some(anyhow::anyhow!("DNS_LOCAL: {:#}", e));
                        break;
                    }
                    // DNS_NAME and DNS_THROTTLE are both positive transport evidence — the
                    // provider delivered an HTTP response — so both clear the breaker streak;
                    // DNS_TIMEOUT is ambiguous and advances it only at the governor floor
                    // (Wave 1, defect B; see the TXT twin for the full rationale).
                    if msg.contains("DNS_NAME") || msg.contains("DNS_THROTTLE") {
                        if self.doh_health.record_success() {
                            note_transport_recovered(crate::dns_telemetry::Tier::Doh);
                        }
                    } else if !msg.contains("DNS_TIMEOUT") || self.governor.has_retreated_to_floor()
                    {
                        // Attribute a genuine transport failure to the provider that produced it.
                        // The DoH breaker may only trip once EVERY configured provider has failed
                        // in the current streak, so an unattributed count would let one sick
                        // endpoint demote a working transport.
                        // Wave 2: the EVIDENCE gate above is the whole discriminator —
                        // `is_backing_off` no longer suppresses, so a genuine outage at the
                        // governor floor trips reliably instead of hiding behind a
                        // perpetually-refreshed cooldown.
                        self.doh_health
                            .record_failure_from(server_index, self.doh_servers.len());
                    }
                    last_err = Some(e);
                    // Rotate past ANY failing provider (see TXT path) — no sleeps.
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!(
                "DNS_TIMEOUT: DoH CNAME rotation deadline ({}ms) exhausted for {}",
                DOH_LOOKUP_DEADLINE.as_millis(),
                domain
            )
        }))
    }

    #[cfg(coverage)]
    async fn doh_cname_lookup_resilient(&self, _domain: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }

    /// GRC-367: acquire a permit from the pool's per-process DNS rate limiter. Called on the
    /// production hot path so `dns_queries_per_second` is enforced even when no explicit
    /// RateLimitContext is threaded through (the limiter was previously dead code).
    ///
    /// Also acquires an adaptive-concurrency permit from the governor, which is what actually
    /// bounds simultaneous DNS egress. Report the lookup's fate with
    /// [`crate::dns_governor::DnsPermit::complete`]; simply dropping the returned permit releases
    /// the slot without recording a measurement, which is the right behavior for a cancelled task.
    #[must_use = "the returned permit bounds one DNS lookup; dropping it immediately frees the slot"]
    pub async fn acquire_dns_permit(&self) -> crate::dns_governor::DnsPermit {
        // Rate first, then concurrency: pacing the *start* of a lookup before occupying a slot
        // keeps the governor's in-flight count a true measure of network work, not of queueing
        // behind our own token bucket.
        let _wait_timer = crate::perf::scoped(&crate::perf::METRICS.dns_governor_acquire_wait);
        self.dns_limiter.acquire().await;
        self.governor.acquire().await
    }

    /// Snapshot of the adaptive DNS controller, for the end-of-scan summary.
    pub fn governor_stats(&self) -> crate::dns_governor::GovernorStats {
        self.governor.stats()
    }

    /// Display names of the configured DoH providers, indexed by `server_index` — the key the
    /// per-provider telemetry table is reported under (Phase-0 attribution).
    pub fn doh_provider_names(&self) -> Vec<String> {
        self.doh_servers.iter().map(|s| s.name.clone()).collect()
    }

    /// Shared handle to the governor, so lookup paths that acquire their own permits can report
    /// outcomes against the same controller.
    pub fn governor(&self) -> &Arc<crate::dns_governor::DnsGovernor> {
        &self.governor
    }

    /// Create a traditional DNS resolver for the given server config (C002 fix: returns Result)
    fn create_dns_resolver(
        &self,
        server: &DnsServerConfig,
        use_tcp: bool,
    ) -> Result<TokioResolver> {
        // 0.26: NameServerConfig takes an IpAddr (port 53 is the resolver default).
        // The configured address is "ip:53"; parse to SocketAddr and take the IP to
        // preserve the prior behavior (always resolving against the standard DNS port).
        let socket_addr: std::net::SocketAddr = server.address.parse().map_err(|e| {
            anyhow::anyhow!(
                "Invalid DNS server address '{}' for server '{}': {}",
                server.address,
                server.name,
                e
            )
        })?;
        let ns_ip = socket_addr.ip();

        // 0.26: protocol is chosen via the NameServerConfig constructor instead of a
        // separate Protocol field. udp() / tcp() match the prior UDP/TCP selection.
        let name_server = if use_tcp {
            NameServerConfig::tcp(ns_ip)
        } else {
            NameServerConfig::udp(ns_ip)
        };

        // 0.26: ResolverConfig::new() is gone — build via from_parts(domain, search, servers).
        let config = ResolverConfig::from_parts(None, vec![], vec![name_server]);

        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(server.timeout_secs);
        opts.attempts = 1; // Single attempt for speed
        opts.edns0 = true;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6; // Prefer IPv4 for speed
        opts.num_concurrent_reqs = 4; // Increased concurrency

        // 0.26: the builder now returns Result (build() can fail constructing the
        // runtime), so propagate with `?`.
        Ok(
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                .with_options(opts)
                .build()?,
        )
    }

    /// GRC-367 (fix 1): subdomain fast path — the highest-concurrency DNS path
    /// (`buffer_unordered(50)` over every discovered subdomain in analysis.rs).
    ///
    /// Previously this path (a) never acquired a DNS permit, so it bypassed the limiter
    /// entirely; (b) called the non-resilient `doh_*_lookup` directly so a single throttling
    /// provider was never rotated past; and (c) collapsed `DNS_THROTTLE` into an empty answer
    /// via `_ => {}` + `unwrap_or_default()`, threading no failure counter — making throttles
    /// invisible to the exit-3 guard (`has_dns_failures() && unique_vendors == 0`).
    ///
    /// Now it acquires a permit before any DoH call, uses the resilient (rotate + backoff)
    /// lookups, and threads `dns_failure_counter` so a throttle that survives ALL providers
    /// increments it. A genuine empty answer (no records) still returns empty without
    /// touching the counter.
    ///
    /// It also stopped bypassing the scan-lifetime memo, which for the busiest DNS caller in the
    /// program meant no reuse, no negative caching and no visibility; and it stopped paying a
    /// separate CNAME query per subdomain, because a dns-json TXT answer already carries the alias
    /// chain the second query was asking for. The two arms are therefore sequenced rather than
    /// joined: TXT decides whether CNAME needs a packet at all.
    // cfg(not(coverage)): performs live DNS lookups via DoH and traditional DNS — requires network
    #[cfg(not(coverage))]
    pub async fn get_txt_and_cname_fast(
        &self,
        domain: &str,
        dns_failure_counter: &AtomicUsize,
    ) -> (Vec<String>, Vec<String>) {
        // Memo before permit, for the reason the root path already states: a remembered verdict
        // puts no packet on the wire, and spending a rate-limit token on a query we never make
        // throttles the scan against nothing. This path — `buffer_unordered` over every discovered
        // subdomain — is the program's highest-volume DNS caller and was the ONLY one that
        // bypassed the memo entirely, so it neither reused answers nor benefited from the negative
        // memo that stops one broken shared name costing a four-provider rotation per referrer.
        let txt_memo = self.recall_memo(RecordKind::Txt, domain).await;
        let cname_memo = self.recall_memo(RecordKind::Cname, domain).await;
        if let (Some(txt), Some(cname)) = (&txt_memo, &cname_memo) {
            // Nothing goes on the wire, so there is no concurrency slot to occupy and no latency
            // measurement to feed the governor. A remembered failure is still counted, though —
            // `settle_arm` does that — because the scan really did fail to resolve this name.
            for (kind, entry) in [
                (crate::dns_telemetry::LookupPath::FastTxt, txt),
                (crate::dns_telemetry::LookupPath::FastCname, cname),
            ] {
                let stage = match entry {
                    MemoEntry::NameFailure(_) => crate::dns_telemetry::TerminalStage::MemoNegHit,
                    MemoEntry::Answer(_) => crate::dns_telemetry::TerminalStage::MemoHit,
                };
                crate::dns_telemetry::DNS_TELEMETRY.terminal(kind, stage);
            }
            return (
                self.settle_arm(Self::memo_as_result(txt), dns_failure_counter),
                self.settle_arm(Self::memo_as_result(cname), dns_failure_counter),
            );
        }

        // Phase-0: the program's highest-volume DNS path finally gets its own timer (dnsLayer.7).
        let _fast_timer = crate::perf::scoped(&crate::perf::METRICS.dns_fast_lookup);
        // fix 1: enforce the per-process DNS limiter on this hot path (was bypassed entirely).
        let permit = self.acquire_dns_permit().await;

        // TXT first, because its answer decides whether a CNAME query is needed at all. This is
        // the P2.10b trade: the common case drops from two queries to one, and the cost is that
        // the rarer both-arms case is sequential rather than concurrent.
        let txt_answer = match &txt_memo {
            Some(entry) => Self::memo_as_result(entry).map(|txt| TxtAnswer { txt, cname: None }),
            None => self.fast_txt_lookup(domain).await,
        };

        let cname_result = match &cname_memo {
            Some(entry) => Self::memo_as_result(entry),
            // P2.10b: a dns-json TXT answer already carried the alias chain — the resolver had to
            // follow it to answer — and an empty chain there PROVES the name is not aliased. Only
            // when that is unavailable (the TXT arm failed, or answered over the DoT/UDP-53 ladder
            // which reads TXT rdata only) is a second query worth its packet.
            None => match txt_answer
                .as_ref()
                .ok()
                .and_then(|answer| answer.cname.clone())
            {
                Some(chain) => Ok(chain),
                None => self.fast_cname_lookup(domain).await,
            },
        };

        let mut txt_result = txt_answer.map(|answer| answer.txt);
        let mut cname_result = cname_result;

        // Feed the adaptive controller. Either arm answering means the resolver path is alive;
        // only when BOTH fail do we have evidence of congestion, and even then a name the
        // resolver simply cannot parse is not the network's fault. Arms served from the memo are
        // neutralised first — see `governor_view` — because they issued no query and must not
        // testify about a network they never touched.
        crate::perf::METRICS
            .dns_permit_held
            .record(permit.elapsed());
        permit.complete(classify_pair(
            &governor_view(txt_memo.is_some(), &txt_result),
            &governor_view(cname_memo.is_some(), &cname_result),
        ));

        // Wave 2 (7d): deferred single retry for load-class failures. A DNS_TIMEOUT/DNS_THROTTLE
        // while the governor is backing off is overwhelmingly OUR congestion; the old rescue was
        // to descend the plain-port ladder immediately — more pressure at the worst moment, on
        // transports that answer no better. Instead: report the signal (permit completed above),
        // wait out the controller's cooldown, and retry ONCE on the transport known to work,
        // paced by the reduced limit. Memo writes happen after, so only the final verdict lands.
        let is_load_class = |r: &Result<Vec<String>>| {
            r.as_ref().err().is_some_and(|e| {
                let m = e.to_string();
                m.contains("DNS_TIMEOUT") || m.contains("DNS_THROTTLE")
            })
        };
        let txt_retry = txt_memo.is_none() && is_load_class(&txt_result);
        let cname_retry = cname_memo.is_none() && is_load_class(&cname_result);
        if (txt_retry || cname_retry) && self.governor.is_backing_off() {
            crate::perf::METRICS.dns_deferred_retry.hit();
            tokio::time::sleep(self.governor.cooldown_left()).await;
            let permit = self.acquire_dns_permit().await;
            if txt_retry {
                txt_result = self.fast_txt_lookup(domain).await.map(|answer| answer.txt);
            }
            if cname_retry {
                cname_result = self.fast_cname_lookup(domain).await;
            }
            let rescued =
                (!txt_retry || txt_result.is_ok()) && (!cname_retry || cname_result.is_ok());
            if rescued {
                crate::perf::METRICS.dns_deferred_retry_rescued.hit();
            }
            crate::perf::METRICS
                .dns_permit_held
                .record(permit.elapsed());
            permit.complete(classify_pair(
                &governor_view(!txt_retry, &txt_result),
                &governor_view(!cname_retry, &cname_result),
            ));
        }

        // Remember only what this call actually settled — an answer, or a `DNS_NAME` verdict.
        // Arms served from the memo are skipped rather than rewritten with their own value.
        if txt_memo.is_none() {
            self.remember_arm(RecordKind::Txt, domain, &txt_result)
                .await;
        }
        if cname_memo.is_none() {
            self.remember_arm(RecordKind::Cname, domain, &cname_result)
                .await;
        }

        // fix 1: a surviving throttle on EITHER record type increments the failure counter
        // so the exit-3 guard can distinguish "throttled into emptiness" from "genuinely empty".
        (
            self.settle_arm(txt_result, dns_failure_counter),
            self.settle_arm(cname_result, dns_failure_counter),
        )
    }

    #[cfg(coverage)]
    pub async fn get_txt_and_cname_fast(
        &self,
        _domain: &str,
        _dns_failure_counter: &AtomicUsize,
    ) -> (Vec<String>, Vec<String>) {
        (vec![], vec![])
    }

    // cfg(not(coverage)): performs live DNS lookup — requires network
    #[cfg(not(coverage))]
    async fn fast_txt_lookup(&self, domain: &str) -> Result<TxtAnswer> {
        // The DoH arm's failure class, kept for the bottom of the function. A `DNS_NAME` verdict
        // means a provider ANSWERED and reported SERVFAIL/REFUSED for this name; the ladder
        // failing afterwards does not turn that into a transport fault, and re-labelling it
        // `DNS_ENDPOINT` (which is what used to happen) both told the governor a healthy link was
        // congested and made the name ineligible for the negative memo.
        let mut doh_failure: Option<String> = None;

        // fix 1: resilient lookup rotates/backs off past a throttling provider instead of
        // letting a single 429 collapse into a false-negative empty. A surviving throttle
        // propagates as a DNS_THROTTLE error so the caller can count it.
        //
        // Tier 1 — DoH (443): network-kind, multiplexed. Health-gated — on a DoH-blocking network (or
        // provider outage) `should_attempt` returns false after TRANSPORT_DOWN_THRESHOLD consecutive
        // failures, so we skip the 3s DoH round-trip and descend the encrypted-then-plain ladder
        // below, re-probing DoH periodically to resume it the moment it recovers.
        if !self
            .doh_health
            .should_attempt_with_sources(self.doh_servers.len())
        {
            crate::dns_telemetry::DNS_TELEMETRY
                .tier(crate::dns_telemetry::Tier::Doh)
                .skipped_breaker
                .fetch_add(1, Ordering::Relaxed);
            crate::perf::METRICS.dns_doh_skipped_breaker.hit();
        } else {
            // The resilient loop OWNS its 3 s deadline (Wave 1, defect A); this outer guard is a
            // hang backstop only and is expected never to fire.
            match tokio::time::timeout(DOH_WRAPPER_BACKSTOP, self.doh_txt_lookup_resilient(domain))
                .await
            {
                // Any authoritative answer — including a genuine empty (NOERROR/NXDOMAIN with
                // no records) — is final: skip the fallback ladder entirely. On the high-volume
                // subdomain fan-out this saves a lookup per recordless name.
                Ok(Ok(answer)) => {
                    if self.doh_health.record_success() {
                        note_transport_recovered(crate::dns_telemetry::Tier::Doh);
                    }
                    return Ok(answer);
                }
                // Broken endpoints (wrong API shape, or every provider unusable) — descend the
                // ladder: another transport may genuinely serve what DoH's endpoints cannot. If
                // it yields no authoritative result either, surface the classified failure
                // rather than a silent empty.
                Ok(Err(e)) if e.to_string().contains("DNS_ENDPOINT") => {
                    // The per-provider failures were already recorded inside the resilient
                    // rotation, which is the only layer that knows WHICH upstream failed. Recording
                    // again here would double-count and could trip the breaker on a single
                    // provider's streak. Just report the transition if this failure completed it.
                    if self.doh_health.just_went_down(self.doh_servers.len()) {
                        warn_transport_unavailable(
                            crate::dns_telemetry::Tier::Doh,
                            "DoH",
                            "trying DNS-over-TLS (853), then direct DNS",
                            "doh_exhausted_throttle_or_endpoint",
                            &self.doh_health,
                            &self.governor,
                        );
                    }
                    match self.laddered_direct(domain, RecordKind::Txt).await {
                        // A ladder answer settles the records but NOT the alias chain: the
                        // DoT/UDP-53 extractors read TXT rdata only. `cname: None` is what tells
                        // the caller it still has to ask.
                        DirectOutcome::Answered(records) => {
                            return Ok(TxtAnswer {
                                txt: records,
                                cname: None,
                            })
                        }
                        // Empty or TransportFailed: surface the DoH failure `e` (already
                        // classified) instead of masking it with a fallback empty.
                        _ => return Err(e),
                    }
                }
                // Wave 2 ladder policy: load-class failures (DNS_THROTTLE — the providers are
                // shedding; DNS_TIMEOUT — our own measured deadline expired) and verdicts that no
                // other transport can improve (DNS_NAME — the name's own servers are broken;
                // DNS_LOCAL — this process is out of descriptors) return classified immediately.
                // Descending the DoT/UDP ladder for them was pure pressure: it multiplied plain-
                // port traffic exactly when the network was struggling, and a SERVFAILing name
                // SERVFAILs identically on every transport. Load-class failures are the deferred
                // single retry's input at the permit-owning caller (7d).
                Ok(Err(e))
                    if e.to_string().contains("DNS_THROTTLE")
                        || e.to_string().contains("DNS_TIMEOUT")
                        || e.to_string().contains("DNS_NAME")
                        || e.to_string().contains("DNS_LOCAL") =>
                {
                    if self.doh_health.just_went_down(self.doh_servers.len()) {
                        warn_transport_unavailable(
                            crate::dns_telemetry::Tier::Doh,
                            "DoH",
                            "trying DNS-over-TLS (853), then direct DNS",
                            "doh_load_class_or_name",
                            &self.doh_health,
                            &self.governor,
                        );
                    }
                    return Err(e);
                }
                Ok(Err(e)) => {
                    // Unclassified transport failures (connect refused, TLS, undecodable body) —
                    // unreachable-class evidence: keep the message and descend the ladder below.
                    doh_failure = Some(e.to_string());
                    if self.doh_health.just_went_down(self.doh_servers.len()) {
                        warn_transport_unavailable(
                            crate::dns_telemetry::Tier::Doh,
                            "DoH",
                            "trying DNS-over-TLS (853), then direct DNS",
                            "doh_other_err",
                            &self.doh_health,
                            &self.governor,
                        );
                    }
                }
                Err(_elapsed) => {
                    // The backstop fired: the self-deadlining loop hung, which is a defect by
                    // definition — count it loudly. (Per-provider failures were already recorded
                    // inside the rotation; recording here would double-count the breaker.)
                    crate::perf::METRICS.dns_wrapper_timeout.hit();
                    crate::perf::METRICS.dns_deadline_backstop_fired.hit();
                    if self.doh_health.just_went_down(self.doh_servers.len()) {
                        warn_transport_unavailable(
                            crate::dns_telemetry::Tier::Doh,
                            "DoH",
                            "trying DNS-over-TLS (853), then direct DNS",
                            "doh_wrapper_timeout",
                            &self.doh_health,
                            &self.governor,
                        );
                    }
                }
            }
        }

        // Tiers 2 (DoT/853) then 3 (direct UDP/53), each health-gated — see `laddered_direct`.
        // Reached when DoH was skipped (breaker tripped) or failed non-throttle. If NO transport
        // could resolve the name, surface a classified failure so the caller counts it — otherwise a
        // tripped breaker turns every unresolved lookup into a silent, uncounted empty (RC-3).
        match self.laddered_direct(domain, RecordKind::Txt).await {
            DirectOutcome::Answered(records) => Ok(TxtAnswer {
                txt: records,
                cname: None,
            }),
            // A DoH provider's authoritative NAME verdict outranks a records-less ladder result.
            // Preserving it only on `TransportFailed` left this hole: when the ladder produced no
            // records, the SERVFAIL verdict was dropped and the caller received a clean empty —
            // the name was never counted and never entered the negative memo, so every referencing
            // domain re-paid the full four-provider rotation. That is the silent-absence failure
            // this module exists to prevent, so the verdict is re-emitted here too. An authoritative
            // ladder answer that carries actual RECORDS still wins (the `Answered` arm above).
            DirectOutcome::Empty => match doh_failure {
                Some(msg) if may_memoize_failure(&msg) => Err(anyhow::anyhow!("{}", msg)),
                _ => Ok(TxtAnswer {
                    txt: vec![],
                    cname: None,
                }),
            },
            DirectOutcome::TransportFailed(_) => Err(match doh_failure {
                // A DoH provider already told us this NAME is broken. The ladder failing after it
                // does not make that a transport problem, and mislabelling it would make the
                // governor throttle a healthy link once per broken name — and would keep the name
                // out of the negative memo, so every referencing domain re-pays the rotation.
                Some(msg) if may_memoize_failure(&msg) => anyhow::anyhow!("{}", msg),
                _ => anyhow::anyhow!(
                    "DNS_ENDPOINT: no DNS transport could resolve TXT for {}",
                    domain
                ),
            }),
        }
    }

    // cfg(not(coverage)): performs live DNS lookups (DoT/853 then UDP/53) — requires network.
    /// Tiers 2 (DoT) and 3 (direct UDP/53) of the resolution ladder, reached only when DoH has not
    /// answered. Each transport is health-gated: a down transport is skipped; a transport failure
    /// (never an authoritative empty) advances its breaker so a blocked/rate-limited path is
    /// abandoned rather than hammered.
    ///
    /// Returns a `DirectOutcome`: `Answered` for a non-empty answer; `Empty` when some tier
    /// authoritatively resolved the name to no records (the transport worked — not a failure); and
    /// `TransportFailed` when NO tier could resolve it (every tier failed or was skipped). The
    /// caller uses that distinction to count a genuinely-unresolvable lookup as a classified DNS
    /// failure instead of returning it as a silent, uncounted empty — the hole that let a tripped
    /// DoH breaker collapse recall invisibly (RC-3). An authoritative `Empty` still descends (a
    /// lower transport may hold records) and never advances a breaker.
    #[cfg(not(coverage))]
    async fn laddered_direct(&self, domain: &str, kind: RecordKind) -> DirectOutcome {
        crate::perf::METRICS.dns_ladder_entered.hit();
        // Did any lower tier authoritatively answer "no records"? That is a working transport, not a
        // failure — so if every tier is empty-or-skipped we return `Empty`, and only a true "no
        // transport could resolve this" returns `TransportFailed` (which the caller counts).
        let mut saw_empty = false;

        // Tier 2 — DoT (853): encrypted, TCP-pooled. Tried before raw UDP/53 so a DoH-blocked
        // network resolves over a low-conntrack-footprint transport.
        if self.dot_enabled && !self.dot_health.should_attempt() {
            crate::dns_telemetry::DNS_TELEMETRY
                .tier(crate::dns_telemetry::Tier::Dot)
                .skipped_breaker
                .fetch_add(1, Ordering::Relaxed);
            crate::perf::METRICS.dns_dot_skipped_breaker.hit();
        }
        if self.dot_enabled && self.dot_health.should_attempt() {
            // Build the DoT resolver ONCE and reuse it, so hickory pools its :853 TLS connections
            // across the whole outage instead of handshaking per lookup.
            if let Some(resolver) = self
                .dot_resolver
                .get_or_init(|| async { build_dot_resolver() })
                .await
            {
                let tier =
                    crate::dns_telemetry::DNS_TELEMETRY.tier(crate::dns_telemetry::Tier::Dot);
                tier.attempts.fetch_add(1, Ordering::Relaxed);
                let t0 = std::time::Instant::now();
                let outcome = match kind {
                    RecordKind::Txt => direct_txt_outcome(resolver, domain, 4000).await,
                    RecordKind::Cname => direct_cname_outcome(resolver, domain, 4000).await,
                    // The governed addr path never descends the ladder (its fallback is
                    // getaddrinfo, counted); reaching here would be a wiring bug.
                    RecordKind::Addr => {
                        debug_assert!(false, "addr lookups never descend the ladder");
                        DirectOutcome::TransportFailed(TransportEvidence::NoResponse)
                    }
                };
                crate::perf::METRICS.dns_dot_attempt.record(t0.elapsed());
                match outcome {
                    DirectOutcome::Answered(records) => {
                        tier.answered.fetch_add(1, Ordering::Relaxed);
                        tier.rtt.record(t0.elapsed());
                        if self.dot_health.record_success() {
                            note_transport_recovered(crate::dns_telemetry::Tier::Dot);
                        }
                        return DirectOutcome::Answered(records);
                    }
                    DirectOutcome::Empty => {
                        // Transport works (authoritative no-records) — reset the breaker but keep
                        // descending: a lower transport can still report records.
                        tier.empty.fetch_add(1, Ordering::Relaxed);
                        if self.dot_health.record_success() {
                            note_transport_recovered(crate::dns_telemetry::Tier::Dot);
                        }
                        saw_empty = true;
                    }
                    DirectOutcome::TransportFailed(evidence) => {
                        tier.transport_failed.fetch_add(1, Ordering::Relaxed);
                        // Timeout evidence is breaker-relevant only once the governor has
                        // retreated to its floor — see `TransportEvidence`.
                        let breaker_relevant = evidence == TransportEvidence::Unreachable
                            || self.governor.has_retreated_to_floor();
                        if breaker_relevant && self.dot_health.record_failure() {
                            warn_transport_unavailable(
                                crate::dns_telemetry::Tier::Dot,
                                "DoT (DNS-over-TLS, 853)",
                                "falling back to direct DNS (UDP/53, rate-limited)",
                                "dot_transport_failed",
                                &self.dot_health,
                                &self.governor,
                            );
                        }
                    }
                }
            }
        }
        // Tier 3 — direct UDP/53: the flood-prone tier, health-gated so a router that blocks or
        // rate-limits port 53 is skipped after TRANSPORT_DOWN_THRESHOLD consecutive timeouts instead
        // of being hammered into a worse outage (the DNS-flood-protection collapse).
        // The budget check comes BEFORE the health check on purpose: it is a ceiling on what we are
        // willing to emit, not a reaction to what failed. Skipping here costs one name's recall;
        // not skipping is what got the WAN IP throttled for ~2h08m on 2026-07-29.
        if self.admit_do53_query() {
            if let Some((index, server)) = self.next_dns_server_indexed() {
                // Reused, not rebuilt: a fresh resolver per lookup means a fresh socket per lookup
                // at the very forwarder this tier is trying not to overwhelm.
                if let Some(resolver) = self.do53_resolver(index, server).await {
                    let tier =
                        crate::dns_telemetry::DNS_TELEMETRY.tier(crate::dns_telemetry::Tier::Udp53);
                    tier.attempts.fetch_add(1, Ordering::Relaxed);
                    let t0 = std::time::Instant::now();
                    let outcome = match kind {
                        RecordKind::Txt => direct_txt_outcome(resolver, domain, 2000).await,
                        RecordKind::Cname => direct_cname_outcome(resolver, domain, 2000).await,
                        // See the DoT arm: the governed addr path never reaches the ladder.
                        RecordKind::Addr => {
                            debug_assert!(false, "addr lookups never descend the ladder");
                            DirectOutcome::TransportFailed(TransportEvidence::NoResponse)
                        }
                    };
                    crate::perf::METRICS.dns_udp53_attempt.record(t0.elapsed());
                    match outcome {
                        DirectOutcome::Answered(records) => {
                            tier.answered.fetch_add(1, Ordering::Relaxed);
                            tier.rtt.record(t0.elapsed());
                            if self.do53_health.record_success() {
                                note_transport_recovered(crate::dns_telemetry::Tier::Udp53);
                            }
                            return DirectOutcome::Answered(records);
                        }
                        DirectOutcome::Empty => {
                            // Authoritative no-records: reset the breaker and note it; a DoH throttle
                            // (if any) still surfaces at the caller.
                            tier.empty.fetch_add(1, Ordering::Relaxed);
                            if self.do53_health.record_success() {
                                note_transport_recovered(crate::dns_telemetry::Tier::Udp53);
                            }
                            saw_empty = true;
                        }
                        DirectOutcome::TransportFailed(evidence) => {
                            tier.transport_failed.fetch_add(1, Ordering::Relaxed);
                            let breaker_relevant = evidence == TransportEvidence::Unreachable
                                || self.governor.has_retreated_to_floor();
                            if breaker_relevant && self.do53_health.record_failure() {
                                warn_transport_unavailable(
                                    crate::dns_telemetry::Tier::Udp53,
                                    "Direct DNS (UDP/53)",
                                    "no DNS transport currently reachable — some lookups may be unresolved",
                                    "udp53_transport_failed",
                                    &self.do53_health,
                                    &self.governor,
                                );
                            }
                        }
                    }
                }
            }
        }
        // No tier returned records. If a tier authoritatively said "empty" the name genuinely has no
        // records; otherwise no transport could resolve it at all — a countable failure. The
        // aggregate is reported as NoResponse: each tier already fed its own typed evidence to its
        // own breaker above, and the caller only turns this into a counted classified failure.
        if saw_empty {
            DirectOutcome::Empty
        } else {
            DirectOutcome::TransportFailed(TransportEvidence::NoResponse)
        }
    }

    #[cfg(coverage)]
    async fn fast_txt_lookup(&self, _domain: &str) -> Result<TxtAnswer> {
        Ok(TxtAnswer::default())
    }

    // cfg(not(coverage)): performs live DNS lookup — requires network
    #[cfg(not(coverage))]
    async fn fast_cname_lookup(&self, domain: &str) -> Result<Vec<String>> {
        // Mirrors `fast_txt_lookup`: keep the DoH arm's failure class so a `DNS_NAME` verdict is
        // not re-emitted as a transport failure at the bottom of the ladder.
        let mut doh_failure: Option<String> = None;

        // fix 1: resilient CNAME lookup (rotate + backoff) instead of a single direct call.
        // Tier 1 — DoH (443), health-gated and shared with TXT via self.doh_health: skip DoH and
        // descend the DoT→UDP/53 ladder when DoH is blocked/unavailable, re-probing periodically.
        // See fast_txt_lookup.
        if !self
            .doh_health
            .should_attempt_with_sources(self.doh_servers.len())
        {
            crate::dns_telemetry::DNS_TELEMETRY
                .tier(crate::dns_telemetry::Tier::Doh)
                .skipped_breaker
                .fetch_add(1, Ordering::Relaxed);
            crate::perf::METRICS.dns_doh_skipped_breaker.hit();
        } else {
            // Hang backstop only — the resilient loop owns its deadline (see fast_txt_lookup).
            match tokio::time::timeout(
                DOH_WRAPPER_BACKSTOP,
                self.doh_cname_lookup_resilient(domain),
            )
            .await
            {
                // Authoritative answer (including genuine no-CNAME) is final — skip the ladder.
                Ok(Ok(records)) => {
                    if self.doh_health.record_success() {
                        note_transport_recovered(crate::dns_telemetry::Tier::Doh);
                    }
                    return Ok(records);
                }
                Ok(Err(e)) if e.to_string().contains("DNS_ENDPOINT") => {
                    // Broken endpoints — descend; another transport may serve what DoH's
                    // endpoints cannot (mirrors the TXT twin).
                    if self.doh_health.just_went_down(self.doh_servers.len()) {
                        warn_transport_unavailable(
                            crate::dns_telemetry::Tier::Doh,
                            "DoH",
                            "trying DNS-over-TLS (853), then direct DNS",
                            "doh_exhausted_throttle_or_endpoint",
                            &self.doh_health,
                            &self.governor,
                        );
                    }
                    match self.laddered_direct(domain, RecordKind::Cname).await {
                        DirectOutcome::Answered(records) => return Ok(records),
                        // Empty or TransportFailed: surface the DoH failure `e` (already
                        // classified) instead of masking it with a fallback empty.
                        _ => return Err(e),
                    }
                }
                // Wave 2 ladder policy — load-class and name/local verdicts return classified
                // without descending; see the TXT twin for the full rationale.
                Ok(Err(e))
                    if e.to_string().contains("DNS_THROTTLE")
                        || e.to_string().contains("DNS_TIMEOUT")
                        || e.to_string().contains("DNS_NAME")
                        || e.to_string().contains("DNS_LOCAL") =>
                {
                    if self.doh_health.just_went_down(self.doh_servers.len()) {
                        warn_transport_unavailable(
                            crate::dns_telemetry::Tier::Doh,
                            "DoH",
                            "trying DNS-over-TLS (853), then direct DNS",
                            "doh_load_class_or_name",
                            &self.doh_health,
                            &self.governor,
                        );
                    }
                    return Err(e);
                }
                Ok(Err(e)) => {
                    // Unclassified transport failures — unreachable-class; descend below.
                    doh_failure = Some(e.to_string());
                    if self.doh_health.just_went_down(self.doh_servers.len()) {
                        warn_transport_unavailable(
                            crate::dns_telemetry::Tier::Doh,
                            "DoH",
                            "trying DNS-over-TLS (853), then direct DNS",
                            "doh_other_err",
                            &self.doh_health,
                            &self.governor,
                        );
                    }
                }
                Err(_elapsed) => {
                    // Backstop fired — a self-deadlining loop hung; count it loudly (see the
                    // TXT twin for why nothing else is recorded here).
                    crate::perf::METRICS.dns_wrapper_timeout.hit();
                    crate::perf::METRICS.dns_deadline_backstop_fired.hit();
                    if self.doh_health.just_went_down(self.doh_servers.len()) {
                        warn_transport_unavailable(
                            crate::dns_telemetry::Tier::Doh,
                            "DoH",
                            "trying DNS-over-TLS (853), then direct DNS",
                            "doh_wrapper_timeout",
                            &self.doh_health,
                            &self.governor,
                        );
                    }
                }
            }
        }

        // Tiers 2 (DoT/853) then 3 (direct UDP/53), each health-gated — see `laddered_direct`.
        // Reached when DoH was skipped (breaker tripped) or failed non-throttle. If NO transport
        // could resolve the name, surface a classified failure so the caller counts it — otherwise a
        // tripped breaker turns every unresolved lookup into a silent, uncounted empty (RC-3).
        match self.laddered_direct(domain, RecordKind::Cname).await {
            DirectOutcome::Answered(records) => Ok(records),
            // Same reasoning as the TXT path: a records-less ladder result must not erase a DoH
            // provider's authoritative NAME verdict, or the failure goes uncounted and unmemoized.
            DirectOutcome::Empty => match doh_failure {
                Some(msg) if may_memoize_failure(&msg) => Err(anyhow::anyhow!("{}", msg)),
                _ => Ok(vec![]),
            },
            DirectOutcome::TransportFailed(_) => Err(match doh_failure {
                // A DoH provider already answered "this NAME is broken" over a working transport;
                // the ladder failing afterwards does not reclassify that as our network's fault.
                Some(msg) if may_memoize_failure(&msg) => anyhow::anyhow!("{}", msg),
                _ => anyhow::anyhow!(
                    "DNS_ENDPOINT: no DNS transport could resolve CNAME for {}",
                    domain
                ),
            }),
        }
    }

    #[cfg(coverage)]
    async fn fast_cname_lookup(&self, _domain: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

#[cfg(not(coverage))]
impl DnsServerPool {
    /// One DoH address (A) lookup against one provider (Wave 3, 6b). Mirrors the TXT/CNAME
    /// leaf twins: same class markers, same per-provider attribution, same RCODE gate. AAAA is
    /// deliberately not queried — the discovery clients dial IPv4-first everywhere else, and
    /// one query per resolution keeps the governed path's cost at parity with getaddrinfo.
    async fn doh_addr_lookup(
        &self,
        domain: &str,
        server_index: usize,
        server: &DohServerConfig,
        attempt_budget: std::time::Duration,
    ) -> Result<Vec<String>> {
        let provider = crate::dns_telemetry::DNS_TELEMETRY.provider(server_index);
        provider.attempts.fetch_add(1, Ordering::Relaxed);
        let attempt_t0 = std::time::Instant::now();
        let query_params = [("name", domain), ("type", "A")];
        let sent = self
            .client
            .get(&server.url)
            .query(&query_params)
            .header("Accept", "application/dns-json")
            .timeout(attempt_budget)
            .send()
            .await;
        let http_response = match sent {
            Ok(response) => {
                let rtt = attempt_t0.elapsed();
                provider.rtt.record(rtt);
                self.governor.record_rtt(rtt);
                response
            }
            Err(e) => {
                if e.is_timeout() {
                    provider.timeout_after_send.fetch_add(1, Ordering::Relaxed);
                    return Err(anyhow::anyhow!(
                        "DNS_TIMEOUT: DoH provider {} exceeded its {}ms attempt budget for {}",
                        server.name,
                        attempt_budget.as_millis(),
                        domain
                    ));
                } else if e.is_connect() {
                    provider.connect_err.fetch_add(1, Ordering::Relaxed);
                } else {
                    let wrapped = anyhow::Error::from(e);
                    if Self::is_local_resource_error(&wrapped) {
                        provider.local_resource_err.fetch_add(1, Ordering::Relaxed);
                    } else {
                        provider.other_err.fetch_add(1, Ordering::Relaxed);
                    }
                    return Err(wrapped);
                }
                return Err(e.into());
            }
        };
        let status = http_response.status();
        if status.as_u16() == 429 || status.is_server_error() {
            if status.as_u16() == 429 {
                provider.http_429.fetch_add(1, Ordering::Relaxed);
            } else {
                provider.http_5xx.fetch_add(1, Ordering::Relaxed);
            }
            return Err(anyhow::anyhow!(
                "DNS_THROTTLE: DoH provider {} returned HTTP {} for {}",
                server.name,
                status,
                domain
            ));
        }
        if !status.is_success() {
            provider.http_4xx_other.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider {} returned HTTP {} for {} — endpoint does not serve the JSON DoH API or rejected the query",
                server.name,
                status,
                domain
            ));
        }
        let response = http_response.json::<Value>().await?;
        if let Some(rcode) = response["Status"].as_u64() {
            if rcode != 0 && rcode != 3 {
                provider.rcode_fail.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow::anyhow!(
                    "DNS_NAME: DoH provider {} returned DNS RCODE {} for {}",
                    server.name,
                    rcode,
                    domain
                ));
            }
        } else if response["Answer"].as_array().is_none() {
            provider.non_dnsjson_2xx.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider {} returned a 2xx body without Status or Answer for {} — not a DNS JSON answer",
                server.name,
                domain
            ));
        }
        let mut records = Vec::new();
        if let Some(answers) = response["Answer"].as_array() {
            for answer in answers {
                // Type 1 = A. The resolver follows CNAME chains itself, so the terminal
                // A records are present in the same answer section.
                if answer["type"].as_u64() == Some(1) {
                    if let Some(data) = answer["data"].as_str() {
                        records.push(data.to_string());
                    }
                }
            }
        }
        provider.ok.fetch_add(1, Ordering::Relaxed);
        Ok(records)
    }

    /// Deadline-owned rotation for address lookups — same shape as the TXT/CNAME twins.
    async fn doh_addr_lookup_resilient(&self, domain: &str) -> Result<Vec<String>> {
        let attempts = self.resilient_attempts();
        let deadline = std::time::Instant::now() + DOH_LOOKUP_DEADLINE;
        let mut last_err: Option<anyhow::Error> = None;
        for i in 0..attempts {
            let Some((server_index, server)) =
                self.next_doh_server_indexed().map(|(i, s)| (i, s.clone()))
            else {
                return Err(anyhow::anyhow!(
                    "no DoH servers configured for A lookup of {}",
                    domain
                ));
            };
            let Some(budget) = self.attempt_budget(deadline, i, attempts, server.timeout_secs)
            else {
                break;
            };
            match self
                .doh_addr_lookup(domain, server_index, &server, budget)
                .await
            {
                Ok(records) => return Ok(records),
                Err(e) => {
                    let msg = e.to_string();
                    if Self::is_local_resource_error(&e) {
                        last_err = Some(anyhow::anyhow!("DNS_LOCAL: {:#}", e));
                        break;
                    }
                    if msg.contains("DNS_NAME") || msg.contains("DNS_THROTTLE") {
                        if self.doh_health.record_success() {
                            note_transport_recovered(crate::dns_telemetry::Tier::Doh);
                        }
                    } else if !msg.contains("DNS_TIMEOUT") || self.governor.has_retreated_to_floor()
                    {
                        self.doh_health
                            .record_failure_from(server_index, self.doh_servers.len());
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!(
                "DNS_TIMEOUT: DoH A rotation deadline ({}ms) exhausted for {}",
                DOH_LOOKUP_DEADLINE.as_millis(),
                domain
            )
        }))
    }

    /// Governed address resolution for the discovery HTTP clients (Wave 3, 6b): memo → governor
    /// permit → DoH A lookup. Every packet this path emits is DoH under a governor permit; the
    /// process-wide invariant is that getaddrinfo remains only as a COUNTED fallback on transport
    /// failure. Deadlock-safe by construction since Wave 1: connection-permit holders may wait on
    /// the governor here, but governor holders never wait on connection permits.
    ///
    /// An authoritative empty (NXDOMAIN/NODATA — the dominant shape for guessed SaaS tenant
    /// hosts) memoizes and returns empty WITHOUT a getaddrinfo fallback: the recursive resolver
    /// already answered, and GAI would re-ask the same question of the same resolvers through
    /// the LAN forwarder — the exact ungoverned load this resolver exists to remove.
    pub async fn addr_lookup_governed(&self, domain: &str) -> Result<Vec<std::net::IpAddr>> {
        let parse = |records: &[String]| -> Vec<std::net::IpAddr> {
            records.iter().filter_map(|r| r.parse().ok()).collect()
        };
        if let Some(entry) = self.recall_memo(RecordKind::Addr, domain).await {
            crate::perf::METRICS.dns_addr_memo.hit();
            return match entry {
                MemoEntry::Answer(records) => Ok(parse(&records)),
                // A remembered DNS_NAME verdict is an authoritative negative for this scan.
                MemoEntry::NameFailure(_) => Ok(Vec::new()),
            };
        }
        let _timer = crate::perf::scoped(&crate::perf::METRICS.dns_addr_lookup);
        let permit = self.acquire_dns_permit().await;
        let result = self.doh_addr_lookup_resilient(domain).await;
        permit.complete(match &result {
            Ok(_) => crate::dns_governor::DnsOutcome::Answered,
            Err(e) => failure_outcome_for_governor(Some(&e.to_string())),
        });
        match &result {
            Ok(records) => {
                self.remember_answer(RecordKind::Addr, domain, records)
                    .await;
                Ok(parse(records))
            }
            Err(e) => {
                self.remember_name_failure(RecordKind::Addr, domain, &e.to_string())
                    .await;
                Err(anyhow::anyhow!("{}", e))
            }
        }
    }
}

/// A `reqwest` DNS resolver that routes the discovery clients' address lookups through the
/// governed DoH path (Wave 3, 6b) — memoized, permit-bounded, breaker-aware — with getaddrinfo
/// kept only as a COUNTED fallback on transport failure. Installed by app startup via
/// [`crate::http_client::install_governed_resolver`]; never used by the DoH client itself
/// (its endpoints are IP literals — resolving DoH via DoH would be circular).
#[cfg(not(coverage))]
pub struct GovernedResolver {
    pool: std::sync::Arc<DnsServerPool>,
}

#[cfg(not(coverage))]
impl GovernedResolver {
    pub fn new(pool: std::sync::Arc<DnsServerPool>) -> Self {
        Self { pool }
    }
}

#[cfg(not(coverage))]
impl reqwest::dns::Resolve for GovernedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let pool = std::sync::Arc::clone(&self.pool);
        Box::pin(async move {
            match pool.addr_lookup_governed(name.as_str()).await {
                Ok(ips) => {
                    let addrs: Box<dyn Iterator<Item = std::net::SocketAddr> + Send> = Box::new(
                        ips.into_iter()
                            .map(|ip| std::net::SocketAddr::new(ip, 0))
                            .collect::<Vec<_>>()
                            .into_iter(),
                    );
                    Ok(addrs)
                }
                Err(_) => {
                    // Transport failure — fall back to the system path so recall cannot regress
                    // below today's behaviour, and COUNT it (the canary's gai_fallback signal).
                    crate::perf::METRICS.dns_addr_gai_fallback.hit();
                    let host = name.as_str().to_string();
                    let t0 = std::time::Instant::now();
                    let looked = tokio::net::lookup_host((host.as_str(), 0)).await;
                    crate::perf::METRICS.http_getaddrinfo.record(t0.elapsed());
                    let addrs = looked?;
                    Ok(Box::new(addrs.collect::<Vec<_>>().into_iter())
                        as Box<dyn Iterator<Item = std::net::SocketAddr> + Send>)
                }
            }
        })
    }
}

// cfg(not(coverage)): the memo only serves the live-network lookup paths, which are
// themselves compiled out under coverage.
#[cfg(not(coverage))]
impl DnsServerPool {
    /// A previously-settled verdict for `(kind, domain)`, if any — an answer or a remembered
    /// `DNS_NAME` failure.
    async fn recall_memo(&self, kind: RecordKind, domain: &str) -> Option<MemoEntry> {
        let memo = self.answer_memo.lock().await;
        let hit = memo.get(&(kind, domain.to_string())).cloned();
        if hit.is_some() {
            // A negative hit is counted on its OWN counter as well as the shared memo counter:
            // folding it into `dns.memo_hit` alone understated how much of the saving comes from
            // not re-rotating four providers over a name that is simply broken.
            if matches!(hit, Some(MemoEntry::NameFailure(_))) {
                crate::perf::METRICS.dns_memo_negative_hit.hit();
            }
            crate::perf::METRICS.dns_memo_hit.hit();
        }
        hit
    }

    /// Record an answer that a resolver actually returned.
    ///
    /// Callers MUST NOT pass a vector manufactured after every resolution path failed:
    /// that value is a degradation marker, not a fact about the zone, and its caller is
    /// obliged to count it toward the DNS-failure guard rather than memoize it.
    async fn remember_answer(&self, kind: RecordKind, domain: &str, records: &[String]) {
        let mut memo = self.answer_memo.lock().await;
        memo.insert(
            (kind, domain.to_string()),
            MemoEntry::Answer(records.to_vec()),
        );
    }

    /// Record that this NAME's own authoritative servers failed it, so the rest of the scan can
    /// stop paying a full provider rotation to rediscover the same broken name.
    ///
    /// The write is gated on [`may_memoize_failure`], not on the caller's judgement: any class
    /// other than a clean `DNS_NAME` is silently ignored here rather than trusted, because the
    /// cost of getting this wrong is a scan-wide false negative rather than a slow scan.
    async fn remember_name_failure(&self, kind: RecordKind, domain: &str, msg: &str) {
        if !may_memoize_failure(msg) {
            return;
        }
        let mut memo = self.answer_memo.lock().await;
        memo.insert(
            (kind, domain.to_string()),
            MemoEntry::NameFailure(msg.to_string()),
        );
    }

    /// A memo entry as the lookup result it stands in for.
    ///
    /// Returning the remembered *error* rather than an empty vector is what keeps a memo hit
    /// indistinguishable from a fresh attempt to everything downstream: it is still counted by
    /// `note_classified_failure`, and `classify_pair` still reads it as `Unrelated` — never as
    /// congestion — so a shared broken name cannot throttle a healthy scan just because it is now
    /// cheap to look up.
    fn memo_as_result(entry: &MemoEntry) -> Result<Vec<String>> {
        match entry {
            MemoEntry::Answer(records) => Ok(records.clone()),
            MemoEntry::NameFailure(msg) => Err(anyhow::anyhow!("{}", msg)),
        }
    }

    /// Remember whatever one arm of a lookup proved, if anything durable. An answer is a fact
    /// about the zone; a `DNS_NAME` verdict is a fact about the zone's own servers; everything
    /// else is a statement about our reach and is deliberately forgotten.
    async fn remember_arm(&self, kind: RecordKind, domain: &str, result: &Result<Vec<String>>) {
        match result {
            Ok(records) => self.remember_answer(kind, domain, records).await,
            Err(e) => {
                self.remember_name_failure(kind, domain, &e.to_string())
                    .await
            }
        }
    }

    /// Reduce one arm's result to the records it should report, counting a classified failure on
    /// the way. Factored out so the memoized and live paths cannot drift apart on the "a surviving
    /// failure must never become a silent empty" contract (GRC-367).
    fn settle_arm(&self, result: Result<Vec<String>>, counter: &AtomicUsize) -> Vec<String> {
        match result {
            Ok(records) => records,
            Err(e) => {
                self.note_classified_failure(&e.to_string(), counter);
                Vec::new()
            }
        }
    }
}

pub async fn get_txt_records(domain: &str) -> Result<Vec<String>> {
    get_txt_records_with_pool(domain, &DnsServerPool::new()).await
}

pub async fn get_txt_records_with_pool(
    domain: &str,
    dns_pool: &DnsServerPool,
) -> Result<Vec<String>> {
    get_txt_records_with_rate_limit(domain, dns_pool, None, None).await
}

pub async fn get_txt_records_with_pool_tracked(
    domain: &str,
    dns_pool: &DnsServerPool,
    dns_failure_counter: &AtomicUsize,
) -> Result<Vec<String>> {
    get_txt_records_with_rate_limit(domain, dns_pool, None, Some(dns_failure_counter)).await
}

/// Outcome of the root TXT race, carrying the DoH arm's failure CLASS when neither arm answered.
///
/// The class is the whole point of the type. `.ok()` used to erase it before anything downstream
/// could look, so a name whose own servers SERVFAIL — not the network's problem at all — was
/// reported to the adaptive governor as congestion and to the memo as unmemoizable, once per
/// referencing domain. See [`failure_outcome_for_governor`] and [`may_memoize_failure`].
#[cfg(not(coverage))]
enum RootRaceOutcome {
    /// A resolver answered. An empty vector is a real answer.
    Records(Vec<String>),
    /// Neither arm produced records; carries the DoH arm's classified message when it had one.
    Failed(Option<String>),
}

// cfg(not(coverage)): performs live DNS lookups racing DoH and traditional DNS — requires network
#[cfg(not(coverage))]
pub async fn get_txt_records_with_rate_limit(
    domain: &str,
    dns_pool: &DnsServerPool,
    rate_limit_ctx: Option<&RateLimitContext>,
    dns_failure_counter: Option<&AtomicUsize>,
) -> Result<Vec<String>> {
    // A memo hit sends no packet, so it is checked before any permit is taken: rate limits
    // exist to pace outbound queries, and charging a token for a query we don't make would
    // throttle the scan against nothing.
    match dns_pool.recall_memo(RecordKind::Txt, domain).await {
        Some(MemoEntry::Answer(records)) => {
            debug!(
                "TXT memo hit for {}: {} records (no query issued)",
                domain,
                records.len()
            );
            crate::dns_telemetry::DNS_TELEMETRY.terminal(
                crate::dns_telemetry::LookupPath::RootTxt,
                crate::dns_telemetry::TerminalStage::MemoHit,
            );
            return Ok(records);
        }
        // This name's own authoritative servers already failed it over a working transport, and
        // that verdict does not change inside one scan. Report it exactly as a fresh attempt
        // would have — the choke-point counters fire, the caller still gets an empty set and
        // continues — but without re-rotating every DoH provider. An SPF include referenced by
        // thousands of domains is discovered broken once, not once per referrer.
        Some(MemoEntry::NameFailure(msg)) => {
            debug!(
                "TXT negative memo hit for {}: {} (no query issued)",
                domain, msg
            );
            crate::dns_telemetry::DNS_TELEMETRY.terminal(
                crate::dns_telemetry::LookupPath::RootTxt,
                crate::dns_telemetry::TerminalStage::MemoNegHit,
            );
            // ONE logical name failure — `note_name_failure` bumps the general counter (in
            // production the same atomic as `dns_failure_counter`) plus the name-attributed
            // tally. The second `counter.fetch_add` that used to sit here double-counted every
            // negative-memo hit as an additional TRANSPORT failure (Wave 1, defect E — measured
            // by the now-retired RootNegativeMemoExtra site before it was removed).
            dns_pool.note_name_failure();
            return Ok(vec![]);
        }
        None => {}
    }

    // Past the memo: this call will put a packet on the wire. Time the whole resolution,
    // including the rate-limit permit wait, since that is wall clock the scan actually spends.
    let _query_timer = crate::perf::scoped(&crate::perf::METRICS.dns_query);

    // Apply rate limiting if configured
    // Pace with whichever rate limiter applies, then take an adaptive-concurrency slot. Only one
    // rate limiter is used so an explicit context does not double-throttle.
    let permit = if let Some(ctx) = rate_limit_ctx {
        ctx.dns_limiter.acquire().await;
        dns_pool.governor().acquire().await
    } else {
        // GRC-367: no explicit context → use the pool's own per-process limiter so the
        // configured dns_queries_per_second is actually enforced on the production hot path.
        dns_pool.acquire_dns_permit().await
    };

    debug!("Querying TXT records for domain: {}", domain);

    // Race DoH and traditional DNS concurrently — first successful result wins.
    // This replaces the old sequential fallback (DoH×2 → DNS×2 → system) which
    // could take 20+ seconds on failure. Now worst-case is ~3s (single timeout).
    // Spawn DoH lookup
    let doh_fut = async {
        // GRC-367: resilient lookup retries/rotates DoH providers on throttle (429/5xx)
        // instead of collapsing a throttle into an empty (false-negative) answer.
        // An authoritative empty answer (HTTP 2xx, RCODE NOERROR/NXDOMAIN, no records) is
        // a REAL answer: return Ok(vec![]) so the caller doesn't fall through to the
        // system resolver and emit a spurious "All DNS resolution failed" warning for
        // every domain that genuinely has no TXT records.
        //
        // The failure MESSAGE is carried out of the race rather than dropped by `.ok()`. Without
        // the class, a SERVFAIL name is indistinguishable from a throttle, and every one of them
        // told the governor the network was congested — see `failure_outcome_for_governor`.
        dns_pool
            .doh_txt_lookup_resilient(domain)
            .await
            .map(|answer| answer.txt)
            .map_err(|e| e.to_string())
    };

    // Spawn traditional DNS lookup (UDP). DNS-only/DoH-only configs are legal —
    // an empty traditional pool just means this race arm yields nothing.
    let dns_fut = async {
        // hickory's IDNA parser rejects mid-label underscores (e.g. `spf_s2.oraclecloud.com`),
        // so this UDP arm can only fail for such names — skip it and let the DoH arm answer.
        if !hickory_resolvable(domain) {
            return None;
        }
        // This arm was the last raw UDP/53 emission point in the program that consulted neither
        // the budget nor the breaker, and it fired on essentially every non-memoized root lookup —
        // exactly the unbudgeted plain-port traffic shape that got the WAN IP throttled upstream
        // for ~2h08m on 2026-07-29. Admission is now the same single decision the ladder's tier-3
        // uses (`admit_do53_query` consumes a token, so it is called once per intended query);
        // a refusal simply leaves this arm of the race silent, which the DoH arm already covers.
        if !dns_pool.admit_do53_query() {
            return None;
        }
        let (index, dns_server) = dns_pool.next_dns_server_indexed()?;
        let resolver = dns_pool.do53_resolver(index, dns_server).await?;
        // Classified rather than collapsed: `direct_txt_outcome` separates an authoritative empty
        // (the transport works) from a timeout/connection failure (it does not), so this arm can
        // finally feed the shared UDP/53 breaker instead of leaving it blind to the busiest
        // plain-port path in the scan. The 2000ms inner budget matches the ladder's tier 3.
        {
            let tier = crate::dns_telemetry::DNS_TELEMETRY.tier(crate::dns_telemetry::Tier::Udp53);
            tier.attempts.fetch_add(1, Ordering::Relaxed);
            let t0 = std::time::Instant::now();
            let outcome = direct_txt_outcome(resolver, domain, 2000).await;
            crate::perf::METRICS.dns_udp53_attempt.record(t0.elapsed());
            match outcome {
                DirectOutcome::Answered(records) => {
                    tier.answered.fetch_add(1, Ordering::Relaxed);
                    tier.rtt.record(t0.elapsed());
                    if dns_pool.do53_health.record_success() {
                        note_transport_recovered(crate::dns_telemetry::Tier::Udp53);
                    }
                    Some(records)
                }
                // An authoritative "no TXT here" proves the transport works, but it must not win the
                // race: the DoH arm can still answer, and the old behavior of declining on empty is
                // what lets a slower-but-answering DoH provider supply the memoized record set.
                DirectOutcome::Empty => {
                    tier.empty.fetch_add(1, Ordering::Relaxed);
                    if dns_pool.do53_health.record_success() {
                        note_transport_recovered(crate::dns_telemetry::Tier::Udp53);
                    }
                    None
                }
                DirectOutcome::TransportFailed(evidence) => {
                    tier.transport_failed.fetch_add(1, Ordering::Relaxed);
                    // Timeout evidence only counts at the governor floor — see TransportEvidence.
                    let breaker_relevant = evidence == TransportEvidence::Unreachable
                        || dns_pool.governor().has_retreated_to_floor();
                    if breaker_relevant && dns_pool.do53_health.record_failure() {
                        warn_transport_unavailable(
                            crate::dns_telemetry::Tier::Udp53,
                            "Direct DNS (UDP/53)",
                            "the DoH arm of the root lookup race carries these names",
                            "root_udp_arm_failed",
                            &dns_pool.do53_health,
                            dns_pool.governor(),
                        );
                    }
                    None
                }
            }
        }
    };

    // Race both arms. Each arm is self-bounding (the DoH rotation owns its 3 s deadline; the UDP
    // arm carries a 2 s budget), so the outer guard is a hang backstop only (Wave 1, defect A).
    let race_result = tokio::time::timeout(
        DOH_WRAPPER_BACKSTOP,
        async {
            tokio::pin!(doh_fut);
            tokio::pin!(dns_fut);

            // Use select to return whichever finishes first with results
            tokio::select! {
                biased;
                result = &mut doh_fut => {
                    match result {
                        Ok(records) => {
                            info!("DoH successful: Found {} TXT records for {}", records.len(), domain);
                            RootRaceOutcome::Records(records)
                        }
                        Err(msg) => {
                            // DoH failed — wait for DNS
                            if let Some(records) = (&mut dns_fut).await {
                                debug!("DNS successful: Found {} TXT records for {} (UDP)", records.len(), domain);
                                return RootRaceOutcome::Records(records);
                            }
                            RootRaceOutcome::Failed(Some(msg))
                        }
                    }
                }
                result = &mut dns_fut => {
                    if let Some(records) = result {
                        debug!("DNS successful: Found {} TXT records for {} (UDP)", records.len(), domain);
                        return RootRaceOutcome::Records(records);
                    }
                    // DNS declined — wait for DoH
                    match (&mut doh_fut).await {
                        Ok(records) => {
                            info!("DoH successful: Found {} TXT records for {}", records.len(), domain);
                            RootRaceOutcome::Records(records)
                        }
                        Err(msg) => RootRaceOutcome::Failed(Some(msg)),
                    }
                }
            }
        }
    ).await;

    // Tell the adaptive controller how the network behaved. A resolver answering — even with an
    // empty answer — is a healthy latency sample; the overall timeout firing is congestion
    // evidence; both arms declining without a timeout is a resolver-level failure whose CLASS
    // decides whether it was the network's fault at all.
    crate::perf::METRICS
        .dns_permit_held
        .record(permit.elapsed());
    if race_result.is_err() {
        crate::perf::METRICS.dns_deadline_backstop_fired.hit();
    }
    permit.complete(match &race_result {
        Ok(RootRaceOutcome::Records(_)) => crate::dns_governor::DnsOutcome::Answered,
        Ok(RootRaceOutcome::Failed(msg)) => failure_outcome_for_governor(msg.as_deref()),
        Err(_) => crate::dns_governor::DnsOutcome::TimedOut,
    });

    // Kept past the race so the total-failure branch below can decide whether what went wrong is
    // a durable fact about this NAME (memoizable) or about our reach (never memoizable).
    let doh_failure = match race_result {
        Ok(RootRaceOutcome::Records(records)) => {
            // A resolver answered. Empty counts: "this name has no TXT records" is an answer.
            // (Which arm won is visible in the tier/provider tables; the terminal stage records
            // that the root lookup ended in an answer without descending to the system resolver.)
            crate::dns_telemetry::DNS_TELEMETRY.terminal(
                crate::dns_telemetry::LookupPath::RootTxt,
                crate::dns_telemetry::TerminalStage::DohOkA1,
            );
            dns_pool
                .remember_answer(RecordKind::Txt, domain, &records)
                .await;
            return Ok(records);
        }
        Ok(RootRaceOutcome::Failed(msg)) => msg,
        // The overall timeout fired, so no arm ever reported a class.
        Err(_) => None,
    };
    let mut doh_failure = doh_failure;

    // Wave 2 (7d): deferred single retry for load-class root failures — wait out the cooldown
    // the controller just started, then retry the DoH rotation once, paced by the reduced limit,
    // on the transport known to work. See `get_txt_and_cname_fast` for the full rationale.
    if doh_failure
        .as_deref()
        .is_some_and(|m| m.contains("DNS_TIMEOUT") || m.contains("DNS_THROTTLE"))
        && dns_pool.governor().is_backing_off()
    {
        crate::perf::METRICS.dns_deferred_retry.hit();
        tokio::time::sleep(dns_pool.governor().cooldown_left()).await;
        let permit = dns_pool.acquire_dns_permit().await;
        let retried = tokio::time::timeout(
            DOH_WRAPPER_BACKSTOP,
            dns_pool.doh_txt_lookup_resilient(domain),
        )
        .await;
        crate::perf::METRICS
            .dns_permit_held
            .record(permit.elapsed());
        match retried {
            Ok(Ok(answer)) => {
                permit.complete(crate::dns_governor::DnsOutcome::Answered);
                crate::perf::METRICS.dns_deferred_retry_rescued.hit();
                crate::dns_telemetry::DNS_TELEMETRY.terminal(
                    crate::dns_telemetry::LookupPath::RootTxt,
                    crate::dns_telemetry::TerminalStage::DohOkA1,
                );
                dns_pool
                    .remember_answer(RecordKind::Txt, domain, &answer.txt)
                    .await;
                return Ok(answer.txt);
            }
            Ok(Err(e)) => {
                let msg = e.to_string();
                permit.complete(failure_outcome_for_governor(Some(&msg)));
                doh_failure = Some(msg);
            }
            Err(_elapsed) => {
                crate::perf::METRICS.dns_deadline_backstop_fired.hit();
                permit.complete(crate::dns_governor::DnsOutcome::TimedOut);
            }
        }
    }

    // Names hickory cannot parse (mid-label underscore, e.g. `spf_s2.oraclecloud.com`)
    // would fail the system resolver with a misleading "Label contains invalid characters"
    // error that surfaces as the headline failure. The DoH arm — which has no such
    // limitation — already had its turn in the race above, so skip the doomed hickory
    // fallback and its scary warning rather than attempt a lookup guaranteed to fail.
    // The lookup still ended UNRESOLVED, so it is counted at this terminal (Wave 1,
    // defect E — this used to be a silent, uncounted empty), and a clean DNS_NAME
    // verdict is still memoized so referencing domains stop re-paying the rotation.
    if !hickory_resolvable(domain) {
        debug!(
            "Skipping hickory system-resolver fallback for {} (label not IDNA-parseable); DoH arm already attempted",
            domain
        );
        if let Some(counter) = dns_failure_counter {
            crate::dns_telemetry::DNS_TELEMETRY
                .failure_site(crate::dns_telemetry::FailureSite::RootAllFailed);
            counter.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(msg) = doh_failure.as_deref() {
            if msg.contains("DNS_NAME") {
                dns_pool.note_name_attribution();
            }
            dns_pool
                .remember_name_failure(RecordKind::Txt, domain, msg)
                .await;
        }
        return Ok(vec![]);
    }

    // Final fallback: system resolver (only if both racing attempts failed). Wave 3 (6a):
    // this emits a UDP/53 query at the LAN forwarder via getaddrinfo's own path, so it is
    // admitted through the SAME gate as every other plain-port emission — the DO53 budget and
    // the UDP/53 breaker. A shed here costs one name's recall; an ungated storm is what got
    // the WAN IP throttled upstream for ~2h08m on 2026-07-29.
    if !dns_pool.admit_do53_query() {
        debug!(
            "System-resolver fallback for {} not admitted (UDP/53 budget/breaker) — unresolved",
            domain
        );
        crate::dns_telemetry::DNS_TELEMETRY.terminal(
            crate::dns_telemetry::LookupPath::RootTxt,
            crate::dns_telemetry::TerminalStage::SystemFail,
        );
        if let Some(counter) = dns_failure_counter {
            crate::dns_telemetry::DNS_TELEMETRY
                .failure_site(crate::dns_telemetry::FailureSite::RootAllFailed);
            counter.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(msg) = doh_failure.as_deref() {
            if msg.contains("DNS_NAME") {
                dns_pool.note_name_attribution();
            }
            dns_pool
                .remember_name_failure(RecordKind::Txt, domain, msg)
                .await;
        }
        return Ok(vec![]);
    }
    debug!("DNS race failed for {}, trying system resolver", domain);
    let system_t0 = std::time::Instant::now();
    let system_result = try_system_dns_resolver(domain).await;
    crate::perf::METRICS
        .dns_system_resolver
        .record(system_t0.elapsed());
    match system_result {
        Ok(records) => {
            debug!(
                "Found {} TXT records for {} via system resolver",
                records.len(),
                domain
            );
            crate::dns_telemetry::DNS_TELEMETRY.terminal(
                crate::dns_telemetry::LookupPath::RootTxt,
                crate::dns_telemetry::TerminalStage::SystemOk,
            );
            dns_pool
                .remember_answer(RecordKind::Txt, domain, &records)
                .await;
            Ok(records)
        }
        Err(e) => {
            warn!("All DNS resolution failed for {} — returning empty results to continue analysis. Last error: {}", domain, e);
            crate::perf::METRICS.dns_all_failed.hit();
            let telemetry = &crate::dns_telemetry::DNS_TELEMETRY;
            telemetry.terminal(
                crate::dns_telemetry::LookupPath::RootTxt,
                crate::dns_telemetry::TerminalStage::SystemFail,
            );
            let (_, conn_available) = crate::http_client::connection_ceiling_state();
            telemetry.lookup_failed(
                domain,
                crate::dns_telemetry::LookupPath::RootTxt,
                crate::dns_telemetry::TerminalStage::SystemFail,
                system_t0.elapsed(),
                dns_pool.governor().limit(),
                conn_available,
            );
            if let Some(counter) = dns_failure_counter {
                telemetry.failure_site(crate::dns_telemetry::FailureSite::RootAllFailed);
                counter.fetch_add(1, Ordering::Relaxed);
            }
            // The empty vector is deliberately NOT memoized: no resolver answered, so it is a
            // degradation marker. Memoizing it would turn a transient failure into a scan-wide
            // false negative and would suppress the counting above on retries.
            //
            // The DoH arm's VERDICT can still be memoized, but only if it was a clean `DNS_NAME`
            // — the name's own servers answering "broken" over a transport that worked. The gate
            // lives in `remember_name_failure`, so a throttle, a broken endpoint or a timeout
            // reaching here writes nothing: an outage must never memoize as absence.
            if let Some(msg) = doh_failure.as_deref() {
                if msg.contains("DNS_NAME") {
                    dns_pool.note_name_attribution();
                }
                dns_pool
                    .remember_name_failure(RecordKind::Txt, domain, msg)
                    .await;
            }
            Ok(vec![])
        }
    }
}

#[cfg(coverage)]
pub async fn get_txt_records_with_rate_limit(
    _domain: &str,
    _dns_pool: &DnsServerPool,
    _rate_limit_ctx: Option<&RateLimitContext>,
    _dns_failure_counter: Option<&AtomicUsize>,
) -> Result<Vec<String>> {
    Ok(vec![])
}

/// The system-config resolver, built ONCE per process (Wave 3, 6a — mirrors `dot_resolver`).
/// A fresh resolver per rescue meant a fresh socket per rescue at the very forwarder the
/// rescue path is trying not to overwhelm.
#[cfg(not(coverage))]
static SYSTEM_RESOLVER: tokio::sync::OnceCell<Option<TokioResolver>> =
    tokio::sync::OnceCell::const_new();

// cfg(not(coverage)): performs live DNS lookup via system resolver — requires network
#[cfg(not(coverage))]
async fn try_system_dns_resolver(domain: &str) -> Result<Vec<String>> {
    let resolver = SYSTEM_RESOLVER
        .get_or_init(|| async {
            // 0.26: builder_tokio() and build() both return Result; a system config that cannot
            // be read memoizes as None so every rescue does not re-attempt (and re-log) it.
            TokioResolver::builder_tokio()
                .ok()
                .map(|b| b.build())
                .and_then(Result::ok)
        })
        .await
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("system resolver unavailable (resolv.conf unreadable)"))?;

    // Query as an absolute (FQDN) name — trailing dot — so the system resolver's
    // search list from /etc/resolv.conf (e.g. OrbStack/Docker's `search localdomain`)
    // is never appended. Without this, a failed lookup of `_x._spf.vali.email` was
    // retried as `_x._spf.vali.email.localdomain` and surfaced as a confusing error.
    let fqdn = if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{}.", domain)
    };
    // Wave 1 (defect C): no shared connection permit — the system-resolver rescue must not
    // queue behind unrelated HTTP work; its own outer budget bounds it.
    let txt_lookup = resolver.txt_lookup(fqdn).await?;
    // 0.26: iterate answer Records and render each record's RData.
    let records: Vec<String> = txt_lookup
        .answers()
        .iter()
        .map(|record| record.data.to_string())
        .collect();

    Ok(records)
}

#[cfg(coverage)]
async fn try_system_dns_resolver(_domain: &str) -> Result<Vec<String>> {
    Ok(vec![])
}

// cfg(not(coverage)): delegates to get_cname_records_with_rate_limit which performs live DNS
#[cfg(not(coverage))]
pub async fn get_cname_records_with_pool(
    domain: &str,
    dns_pool: &DnsServerPool,
) -> Result<Vec<String>> {
    get_cname_records_with_rate_limit(domain, dns_pool, None, None).await
}

#[cfg(coverage)]
pub async fn get_cname_records_with_pool(
    _domain: &str,
    _dns_pool: &DnsServerPool,
) -> Result<Vec<String>> {
    Ok(vec![])
}

// GRC-367 (fix 4): `get_cname_records_with_pool_tracked` removed — it had zero callers in src,
// tests, examples, and benches. The CNAME throttle is now tracked at the pool choke-point
// (`note_throttle` in `doh_cname_lookup`); a separate threaded-counter CNAME wrapper is dead.

// cfg(not(coverage)): performs live DNS lookup via DoH — requires network
#[cfg(not(coverage))]
pub async fn get_cname_records_with_rate_limit(
    domain: &str,
    dns_pool: &DnsServerPool,
    rate_limit_ctx: Option<&RateLimitContext>,
    dns_failure_counter: Option<&AtomicUsize>,
) -> Result<Vec<String>> {
    // Checked before the permit for the same reason as the TXT path: a memo hit issues no
    // query, so it must not consume rate-limit budget. The subdomain fast path now writes the
    // chain it derives from a TXT answer here too, so a later explicit CNAME lookup of a name
    // that path already resolved is free.
    match dns_pool.recall_memo(RecordKind::Cname, domain).await {
        Some(MemoEntry::Answer(records)) => {
            debug!(
                "CNAME memo hit for {}: {} records (no query issued)",
                domain,
                records.len()
            );
            crate::dns_telemetry::DNS_TELEMETRY.terminal(
                crate::dns_telemetry::LookupPath::RootCname,
                crate::dns_telemetry::TerminalStage::MemoHit,
            );
            return Ok(records);
        }
        // The memo removes the query, never the failure's visibility: `note_name_failure` is
        // exactly what a fresh rotation would have hit at the choke point. The explicit
        // `dns_failure_counter` is deliberately NOT bumped here, because the live CNAME path
        // below only bumps it for throttles/broken endpoints — a memo hit must account for a
        // name failure the same way an attempt does, not more.
        Some(MemoEntry::NameFailure(msg)) => {
            debug!(
                "CNAME negative memo hit for {}: {} (no query issued)",
                domain, msg
            );
            crate::dns_telemetry::DNS_TELEMETRY.terminal(
                crate::dns_telemetry::LookupPath::RootCname,
                crate::dns_telemetry::TerminalStage::MemoNegHit,
            );
            dns_pool.note_name_failure();
            return Ok(vec![]);
        }
        None => {}
    }

    // Apply rate limiting if configured
    // See the TXT path: one rate limiter, then an adaptive-concurrency slot.
    let permit = if let Some(ctx) = rate_limit_ctx {
        ctx.dns_limiter.acquire().await;
        dns_pool.governor().acquire().await
    } else {
        // GRC-367: enforce the pool's per-process DNS limiter on the production path.
        dns_pool.acquire_dns_permit().await
    };

    debug!("Querying CNAME records for domain: {}", domain);

    // GRC-367 (fix 2) + Wave 1: the resilient CNAME lookup owns its 3 s rotation deadline; the
    // outer guard is a hang backstop only, expected never to fire.
    let outcome = tokio::time::timeout(
        DOH_WRAPPER_BACKSTOP,
        dns_pool.doh_cname_lookup_resilient(domain),
    )
    .await;

    // Report to the adaptive controller before interpreting the result, using the same class →
    // outcome mapping as every other path: only a real provider refusal is `Rejected`, a deadline
    // exhaustion is `TimedOut`, and name/endpoint/local failures say nothing about load.
    crate::perf::METRICS
        .dns_permit_held
        .record(permit.elapsed());
    permit.complete(match &outcome {
        Ok(Ok(_)) => crate::dns_governor::DnsOutcome::Answered,
        Ok(Err(e)) => failure_outcome_for_governor(Some(&e.to_string())),
        Err(_) => crate::dns_governor::DnsOutcome::TimedOut,
    });

    // Wave 2 (7d): deferred single retry for load-class failures — mirrors the root TXT path.
    let mut outcome = outcome;
    if outcome.as_ref().is_ok_and(|r| {
        r.as_ref().is_err_and(|e| {
            let m = e.to_string();
            m.contains("DNS_TIMEOUT") || m.contains("DNS_THROTTLE")
        })
    }) && dns_pool.governor().is_backing_off()
    {
        crate::perf::METRICS.dns_deferred_retry.hit();
        tokio::time::sleep(dns_pool.governor().cooldown_left()).await;
        let permit = dns_pool.acquire_dns_permit().await;
        let retried = tokio::time::timeout(
            DOH_WRAPPER_BACKSTOP,
            dns_pool.doh_cname_lookup_resilient(domain),
        )
        .await;
        crate::perf::METRICS
            .dns_permit_held
            .record(permit.elapsed());
        permit.complete(match &retried {
            Ok(Ok(_)) => {
                crate::perf::METRICS.dns_deferred_retry_rescued.hit();
                crate::dns_governor::DnsOutcome::Answered
            }
            Ok(Err(e)) => failure_outcome_for_governor(Some(&e.to_string())),
            Err(_) => {
                crate::perf::METRICS.dns_deadline_backstop_fired.hit();
                crate::dns_governor::DnsOutcome::TimedOut
            }
        });
        outcome = retried;
    }

    match outcome {
        // Genuine answer: records present.
        Ok(Ok(records)) if !records.is_empty() => {
            debug!(
                "DoH successful: Found {} CNAME records for {}",
                records.len(),
                domain
            );
            dns_pool
                .remember_answer(RecordKind::Cname, domain, &records)
                .await;
            Ok(records)
        }
        // Genuine no-CNAME (NoData/NXDOMAIN): the resilient lookup succeeded but returned
        // no records. This is the normal "CNAME absence is normal" case — return empty WITHOUT
        // touching the failure counter. It is an authoritative answer, so it is memoized.
        Ok(Ok(_)) => {
            dns_pool
                .remember_answer(RecordKind::Cname, domain, &[])
                .await;
            Ok(vec![])
        }
        // All providers throttled (429/5xx surviving rotation). This is a FALSE-NEGATIVE risk,
        // NOT a genuine absence — count it so the exit-3 guard can see it, then return empty so
        // analysis continues (consistent with the TXT path's degrade-but-record behavior).
        Ok(Err(e))
            if e.to_string().contains("DNS_THROTTLE") || e.to_string().contains("DNS_ENDPOINT") =>
        {
            warn!(
                "CNAME lookup for {} failed across all DoH providers (throttled or broken endpoint) — recording failure: {}",
                domain, e
            );
            if let Some(counter) = dns_failure_counter {
                crate::dns_telemetry::DNS_TELEMETRY
                    .failure_site(crate::dns_telemetry::FailureSite::CnameAllThrottled);
                counter.fetch_add(1, Ordering::Relaxed);
            }
            Ok(vec![])
        }
        // Non-throttle failure (DNS_NAME / DNS_TIMEOUT / DNS_LOCAL / parse) or the hang backstop:
        // the lookup ended UNRESOLVED, so it is counted — exactly once, at this terminal — before
        // degrading to an empty result so analysis continues. This closes the last silent-empty in
        // the DNS layer (Wave 1, defect E: the old arm returned `Ok(vec![])` with no failure
        // counted anywhere).
        other => {
            if other.is_err() {
                crate::perf::METRICS.dns_wrapper_timeout.hit();
                crate::perf::METRICS.dns_deadline_backstop_fired.hit();
                crate::dns_telemetry::DNS_TELEMETRY.terminal(
                    crate::dns_telemetry::LookupPath::RootCname,
                    crate::dns_telemetry::TerminalStage::WrapperTimeoutSilentEmpty,
                );
            }
            if let Some(counter) = dns_failure_counter {
                crate::dns_telemetry::DNS_TELEMETRY
                    .failure_site(crate::dns_telemetry::FailureSite::CnameUnresolvedOther);
                counter.fetch_add(1, Ordering::Relaxed);
            }
            // A clean `DNS_NAME` verdict is the one failure here that is a durable fact about the
            // NAME rather than about our reach, so it is worth remembering — the same broken name
            // referenced by many domains then costs one rotation instead of one per referrer. The
            // gate in `remember_name_failure` refuses every other class, timeouts included.
            if let Ok(Err(e)) = &other {
                let msg = e.to_string();
                if msg.contains("DNS_NAME") {
                    dns_pool.note_name_attribution();
                }
                dns_pool
                    .remember_name_failure(RecordKind::Cname, domain, &msg)
                    .await;
            }
            Ok(vec![])
        }
    }
}

#[cfg(coverage)]
pub async fn get_cname_records_with_rate_limit(
    _domain: &str,
    _dns_pool: &DnsServerPool,
    _rate_limit_ctx: Option<&RateLimitContext>,
    _dns_failure_counter: Option<&AtomicUsize>,
) -> Result<Vec<String>> {
    Ok(vec![])
}

#[derive(Debug)]
pub struct VendorDomain {
    pub domain: String,
    pub source_type: RecordType,
    pub raw_record: String,
}

/// Simple extraction without logging - used for subdomain analysis
pub fn extract_vendor_domains_with_source(txt_records: &[String]) -> Vec<VendorDomain> {
    extract_vendor_domains_with_source_and_logger(txt_records, None, "")
}

#[cfg_attr(coverage_nightly, coverage(off))]
pub fn extract_vendor_domains_with_source_and_logger(
    txt_records: &[String],
    logger: Option<&dyn LogFailure>,
    source_domain: &str,
) -> Vec<VendorDomain> {
    let mut vendor_domains = Vec::new();
    // Deduplicate by (domain, record_type, raw_record) to allow same vendor from different sources
    // but prevent exact duplicates (same domain + same record type + same raw record)
    let mut seen_entries: HashSet<(String, String, String)> = HashSet::new();

    for record in txt_records {
        // Strip wrapping quotes, then unescape DNS TXT backslash sequences (H004 fix)
        // DNS TXT records use backslash-escaping: \X -> X for any char X
        // Process in one pass to handle all escape sequences correctly
        let record_trimmed = record.trim_matches('"');
        let record_clean = unescape_dns_txt(record_trimmed);
        let mut record_matched = false;

        // Extract vendor domains based on record patterns
        if let Some(domains) = extract_from_spf_record(&record_clean, logger, source_domain, record)
        {
            record_matched = true;
            for domain_info in domains {
                let key = (
                    domain_info.domain.clone(),
                    domain_info.source_type.as_hierarchy_string(),
                    domain_info.raw_record.clone(),
                );
                if seen_entries.insert(key) {
                    vendor_domains.push(domain_info);
                }
            }
        }

        if let Some(domains) =
            extract_from_dkim_record(&record_clean, logger, source_domain, record)
        {
            record_matched = true;
            for domain_info in domains {
                let key = (
                    domain_info.domain.clone(),
                    domain_info.source_type.as_hierarchy_string(),
                    domain_info.raw_record.clone(),
                );
                if seen_entries.insert(key) {
                    vendor_domains.push(domain_info);
                }
            }
        }

        if let Some(domains) =
            extract_from_dmarc_record(&record_clean, logger, source_domain, record)
        {
            record_matched = true;
            for domain_info in domains {
                let key = (
                    domain_info.domain.clone(),
                    domain_info.source_type.as_hierarchy_string(),
                    domain_info.raw_record.clone(),
                );
                if seen_entries.insert(key) {
                    vendor_domains.push(domain_info);
                }
            }
        }

        if let Some(domains) =
            extract_from_verification_record(&record_clean, logger, source_domain, record)
        {
            record_matched = true;
            for domain_info in domains {
                let key = (
                    domain_info.domain.clone(),
                    domain_info.source_type.as_hierarchy_string(),
                    domain_info.raw_record.clone(),
                );
                if seen_entries.insert(key) {
                    vendor_domains.push(domain_info);
                }
            }
        }

        // Log unmatched TXT records for debugging and pattern discovery (M004 fix: use if-let)
        if !record_matched {
            if let Some(logger) = logger {
                // Skip very short records (likely not vendor verification records)
                if record_clean.len() > 5 {
                    logger.log_failure(
                        source_domain,
                        "UNMATCHED_TXT",
                        record,
                        None,
                        "No pattern matched this TXT record",
                    );
                }
            }
        }
    }

    vendor_domains
}

/// Unescape DNS TXT record backslash sequences: \X -> X for any char X.
/// This handles \\, \", \_, and any other backslash-escaped character.
fn unescape_dns_txt(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // Consume the next char as-is (unescaped)
            if let Some(next) = chars.next() {
                result.push(next);
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn strip_spf_macros(domain: &str) -> String {
    // Remove SPF macro variables like %{ir}, %{v}, %{d}, etc.
    // Pattern: %{<macro>} where <macro> can be letters with optional modifiers
    // Use pre-compiled regex for performance (B020 fix)
    MACRO_REGEX.replace_all(domain, "").to_string()
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn extract_from_spf_record(
    record: &str,
    logger: Option<&dyn LogFailure>,
    source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    // Case-insensitive check (fixes DNS-001 - RFC compliance)
    let record_lower = record.to_lowercase();
    if !record_lower.starts_with("v=spf1") {
        return None;
    }

    let mut domains = Vec::new();
    // Use pre-compiled regexes instead of compiling in loop (H001 fix)
    // Note: ip4:/ip6: mechanisms are intentionally excluded — they contain IP addresses,
    // not domains, so they are not relevant to vendor domain extraction.
    // L009: RFC 7208 limits SPF to 10 DNS-querying mechanisms (include, a, mx, ptr, exists,
    // redirect). This tool does not recursively resolve SPF chains, it only extracts domains
    // from a single record, so the 10-lookup limit is not enforced here. A future recursive
    // SPF resolver would need to track and enforce this limit.
    let spf_regexes: &[&Lazy<Regex>] = &[
        &SPF_INCLUDE_REGEX,
        &SPF_REDIRECT_REGEX,
        &SPF_A_REGEX,
        &SPF_MX_REGEX,
        &SPF_EXISTS_REGEX,
        &SPF_PTR_REGEX,
    ];

    for re in spf_regexes {
        for domain_match in re.captures_iter(&record_lower).filter_map(|c| c.get(1)) {
            let raw_domain = domain_match.as_str();

            // Strip SPF macros to get the actual domain (e.g., %{ir}.%{v}.%{d}.spf.has.pphosted.com -> spf.has.pphosted.com)
            let cleaned_domain = strip_spf_macros(raw_domain);

            if is_valid_domain(&cleaned_domain) {
                // Extract base domain from SPF subdomains (e.g., _spf.google.com -> google.com)
                let base_domain = domain_utils::extract_base_domain(&cleaned_domain);

                domains.push(VendorDomain {
                    domain: base_domain,
                    source_type: RecordType::DnsTxtSpf,
                    raw_record: raw_record.to_string(),
                });
            } else if let Some(logger) = logger {
                logger.log_failure(
                    source_domain,
                    "SPF",
                    raw_record,
                    Some(raw_domain),
                    "Invalid domain format",
                );
            }
        }
    }

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

// cfg(not(coverage)): performs live DNS lookups to resolve SPF include chains — requires network
#[cfg(not(coverage))]
pub async fn resolve_spf_includes_recursive(
    txt_records: &[String],
    dns_pool: &DnsServerPool,
    source_domain: &str,
) -> Vec<VendorDomain> {
    let mut all_domains = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut to_resolve: Vec<String> = Vec::new();
    let mut lookup_count: usize = 0;
    const MAX_SPF_LOOKUPS: usize = 10;

    // Find SPF records in the initial TXT records and extract include/redirect/exists targets
    for record in txt_records {
        let record_clean = unescape_dns_txt(record.trim_matches('"'));
        let record_lower = record_clean.to_lowercase();
        if !record_lower.starts_with("v=spf1") {
            continue;
        }
        collect_spf_targets(&record_lower, &mut to_resolve, &mut visited);
    }

    // Iteratively resolve include targets (BFS to stay within lookup limit)
    while let Some(target) = to_resolve.pop() {
        if lookup_count >= MAX_SPF_LOOKUPS {
            debug!(
                "SPF recursive resolution hit {}-lookup limit for {}",
                MAX_SPF_LOOKUPS, source_domain
            );
            break;
        }
        lookup_count += 1;

        match get_txt_records_with_pool(&target, dns_pool).await {
            Ok(nested_records) => {
                for record in &nested_records {
                    let record_clean = unescape_dns_txt(record.trim_matches('"'));
                    let record_lower = record_clean.to_lowercase();
                    if !record_lower.starts_with("v=spf1") {
                        continue;
                    }

                    // Extract vendor domains from this nested SPF record
                    if let Some(domains) =
                        extract_from_spf_record(&record_clean, None, source_domain, record)
                    {
                        all_domains.extend(domains);
                    }

                    // Collect more targets to resolve
                    collect_spf_targets(&record_lower, &mut to_resolve, &mut visited);
                }
            }
            Err(e) => {
                debug!("SPF recursive resolution failed for {}: {}", target, e);
            }
        }
    }

    if !all_domains.is_empty() {
        debug!(
            "SPF recursive resolution for {} found {} additional vendor domains across {} lookups",
            source_domain,
            all_domains.len(),
            lookup_count
        );
    }

    all_domains
}

#[cfg(coverage)]
pub async fn resolve_spf_includes_recursive(
    _txt_records: &[String],
    _dns_pool: &DnsServerPool,
    _source_domain: &str,
) -> Vec<VendorDomain> {
    vec![]
}

/// Extract SPF include/redirect targets from a lowercased SPF record for recursive resolution.
/// Note: `exists:` targets are NOT included here because they are macro-expanded IP-check
/// mechanisms, not SPF delegation. Domain extraction from `exists:` is already handled by
/// `extract_from_spf_record`.
fn collect_spf_targets(
    record_lower: &str,
    to_resolve: &mut Vec<String>,
    visited: &mut HashSet<String>,
) {
    let target_regexes: &[&Lazy<Regex>] = &[&SPF_INCLUDE_REGEX, &SPF_REDIRECT_REGEX];
    for re in target_regexes {
        for m in re.captures_iter(record_lower).filter_map(|c| c.get(1)) {
            let raw_target = m.as_str();
            // RFC 7208 §7 (macros): an include:/redirect= target bearing a macro
            // (e.g. Valimail's `%{ir}._ip.%{v}._ehlo.%{d}._spf.vali.email`) is a
            // sender-dependent, evaluation-time construct — it is NOT a static SPF
            // delegation. Stripping the `%{...}` leaves a non-resolvable residual
            // like `_ip._ehlo._spf.vali.email`; recursing into it yields RCODE 2 and
            // noisy DoH-failure warnings. Skip it here. The provider's registrable
            // base domain (vali.email) is still surfaced as a vendor by
            // extract_from_spf_record, so we lose no vendor signal.
            // Key off the raw token containing any `%` (macro variables `%{...}` and the
            // macro-literal escapes `%%`/`%_`/`%-`); `%` is never valid in a real
            // hostname, so this is RFC 7208 §7-complete and never false-positives.
            if raw_target.contains('%') {
                continue;
            }
            // Strip SPF macros (e.g., %{i}._spf.mta.salesforce.com -> _spf.mta.salesforce.com)
            let cleaned = strip_spf_macros(raw_target);
            if is_valid_domain(&cleaned) && visited.insert(cleaned.clone()) {
                to_resolve.push(cleaned);
            }
        }
    }
}

fn extract_from_dkim_record(
    record: &str,
    _logger: Option<&dyn LogFailure>,
    _source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    if !record.contains("k=rsa") && !record.contains("k=ed25519") {
        return None;
    }

    let mut domains = Vec::new();

    // Use pre-compiled DKIM regexes instead of compiling in loop (H002 fix)
    let dkim_regexes: &[&Lazy<Regex>] = &[&DKIM_P_REGEX, &DKIM_H_REGEX, &DKIM_S_REGEX];

    for re in dkim_regexes {
        for value_match in re.captures_iter(record).filter_map(|c| c.get(1)) {
            let value = value_match.as_str();
            if value.contains('.') && is_valid_domain(value) {
                domains.push(VendorDomain {
                    domain: value.to_string(),
                    source_type: RecordType::DnsTxtDkim,
                    raw_record: raw_record.to_string(),
                });
            }
        }
    }

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn extract_from_dmarc_record(
    record: &str,
    logger: Option<&dyn LogFailure>,
    source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    // Case-insensitive check (fixes DNS-001 - RFC compliance)
    if !record.to_lowercase().starts_with("v=dmarc1") {
        return None;
    }

    let mut domains = Vec::new();

    // Extract domains from rua and ruf tags (which can have comma-separated mailto addresses)
    // e.g., rua=mailto:a@domain1.com,mailto:b@domain2.com
    // Use lowercase copy consistently to avoid byte index mismatch on mixed-case records (H003 fix)
    // and to prevent UTF-8 boundary panics on multi-byte chars (C004 fix)
    let record_lower = record.to_lowercase();
    for tag in &["rua=", "ruf="] {
        // Find the tag value (case-insensitive search on lowercase copy)
        if let Some(tag_pos) = record_lower.find(*tag) {
            let value_start = tag_pos + tag.len();
            // Find end of value (next semicolon or end of string) - search lowercase copy
            let value_end = record_lower[value_start..]
                .find(';')
                .map(|p| value_start + p)
                .unwrap_or(record_lower.len());
            let tag_value = &record_lower[value_start..value_end];

            // Extract all mailto: addresses (comma-separated)
            // Pattern: mailto:localpart@domain or mailto:domain
            for domain_match in MAILTO_REGEX
                .captures_iter(tag_value)
                .filter_map(|c| c.get(2))
            {
                let domain = domain_match.as_str();
                if is_valid_domain(domain) {
                    domains.push(VendorDomain {
                        domain: domain.to_string(),
                        source_type: RecordType::DnsTxtDmarc,
                        raw_record: raw_record.to_string(),
                    });
                } else if let Some(logger) = logger {
                    logger.log_failure(
                        source_domain,
                        "DMARC",
                        raw_record,
                        Some(tag),
                        "Invalid domain format",
                    );
                }
            }
        }
    }

    // Note: sp= tag contains policy values ("none", "quarantine", "reject"), not domains.
    // Removed dead code that attempted to extract domains from sp= (C001 fix).

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

fn extract_from_verification_record(
    record: &str,
    logger: Option<&dyn LogFailure>,
    source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    let mut domains = Vec::new();

    // First, try comprehensive static provider mappings
    if let Some(static_domains) =
        try_static_verification_patterns(record, logger, source_domain, raw_record)
    {
        domains.extend(static_domains);
    }

    // Then try dynamic pattern matching for unknown verification records
    if let Some(dynamic_domains) =
        try_dynamic_verification_patterns(record, logger, source_domain, raw_record)
    {
        domains.extend(dynamic_domains);
    }

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

/// Literal TXT-record markers that identify a SaaS vendor, mapped to that vendor's domain.
///
/// A static slice rather than a `vec!` rebuilt inside the function: this table is
/// consulted for every TXT record of every domain and subdomain a scan touches, and the
/// entries are compile-time constants.
static VERIFICATION_PATTERNS: &[(&str, &str, RecordType)] = &[
    // Common verification patterns
    (
        r"google-site-verification=",
        "google.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"facebook-domain-verification=",
        "facebook.com",
        RecordType::DnsTxtVerification,
    ),
    (r"MS=", "microsoft.com", RecordType::DnsTxtVerification),
    (
        r"apple-domain-verification=",
        "apple.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"adobe-idp-site-verification=",
        "adobe.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"stripe-verification=",
        "stripe.com",
        RecordType::DnsTxtVerification,
    ),
    (r"docusign=", "docusign.com", RecordType::DnsTxtVerification),
    (
        r"globalsign-domain-verification=",
        "globalsign.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"dropbox-domain-verification=",
        "dropbox.com",
        RecordType::DnsTxtVerification,
    ),
    // Extended patterns from research and klaviyo analysis
    (r"ZOOM_verify_", "zoom.us", RecordType::DnsTxtVerification),
    (
        r"atlassian-domain-verification=",
        "atlassian.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"browserstack-domain-verification=",
        "browserstack.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"canva-site-verification=",
        "canva.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"cursor-domain-verification",
        "cursor.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"datadome-domain-verify=",
        "datadome.co",
        RecordType::DnsTxtVerification,
    ),
    (
        r"drift-domain-verification=",
        "drift.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"hubspot-domain-verification=",
        "hubspot.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"klaviyo-site-verification=",
        "klaviyo.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"notion-domain-verification=",
        "notion.so",
        RecordType::DnsTxtVerification,
    ),
    (
        r"onetrust-domain-verification=",
        "onetrust.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"openai-domain-verification=",
        "openai.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"postman-domain-verification=",
        "postman.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"slack-domain-verification=",
        "slack.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"teamviewer-sso-verification=",
        "teamviewer.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"wework-site-verification=",
        "wework.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"heroku-domain-verification=",
        "heroku.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"jamf-site-verification=",
        "jamf.com",
        RecordType::DnsTxtVerification,
    ),
    // Additional patterns found in klaviyo.com analysis
    (
        r"anthropic-domain-verification",
        "anthropic.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"jetbrains-domain-verification=",
        "jetbrains.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"gc-ai-domain-verification",
        "gc-ai.com",
        RecordType::DnsTxtVerification,
    ), // Unverified vendor - kept for completeness
    // Special mappings discovered from research
    (r"intacct-esk=", "sage.com", RecordType::DnsTxtVerification), // Sage Intacct
    (r"mgverify=", "mailgun.com", RecordType::DnsTxtVerification), // Mailgun verification
    // L002: neat.co is correct — Neat's actual domain is neat.co (not .com)
    (
        r"neat-pulse-domain-verification",
        "neat.co",
        RecordType::DnsTxtVerification,
    ),
    // Pattern variations
    (
        r"webex-domain-verification=",
        "webex.com",
        RecordType::DnsTxtVerification,
    ),
    (
        r"zoom-domain-verification=",
        "zoom.us",
        RecordType::DnsTxtVerification,
    ),
    (
        r"have-i-been-pwned-verification=",
        "haveibeenpwned.com",
        RecordType::DnsTxtVerification,
    ),
    // L001: Whimsical uses angle bracket format in TXT records — this is an actual
    // record format observed in the wild (e.g., klaviyo.com DNS), not a parsing error.
    (
        r"<whimsical=",
        "whimsical.com",
        RecordType::DnsTxtVerification,
    ),
];

fn try_static_verification_patterns(
    record: &str,
    _logger: Option<&dyn LogFailure>,
    _source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    // Comprehensive static provider mappings based on research

    let mut domains = Vec::new();

    // These patterns are all literal strings, use contains() instead of regex for speed
    for (pattern, domain, record_type) in VERIFICATION_PATTERNS {
        if record.contains(pattern) {
            domains.push(VendorDomain {
                domain: domain.to_string(),
                source_type: record_type.clone(),
                raw_record: raw_record.to_string(),
            });
        }
    }

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

fn try_dynamic_verification_patterns(
    record: &str,
    _logger: Option<&dyn LogFailure>,
    _source_domain: &str,
    raw_record: &str,
) -> Option<Vec<VendorDomain>> {
    let mut domains = Vec::new();

    let verification_regexes: &[&Lazy<Regex>] = &[
        &DOMAIN_VERIFICATION_REGEX,
        &VERIFICATION_PREFIX_REGEX,
        &SITE_VERIFICATION_REGEX,
        &PROVIDER_VERIFY_REGEX,
    ];
    for re in verification_regexes {
        for provider_match in re.captures_iter(record).filter_map(|c| c.get(1)) {
            let provider_name = provider_match.as_str().to_lowercase();
            if let Some(domain) = infer_provider_domain(&provider_name) {
                domains.push(VendorDomain {
                    domain,
                    source_type: RecordType::DnsTxtVerification,
                    raw_record: raw_record.to_string(),
                });
            }
        }
    }

    // Dynamic pattern 5: "letters=" (preceded by letters, like EU5VQe53KTDQgPby023o4w)
    // This is more challenging as it requires heuristic analysis - skip for now to avoid false positives

    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

fn infer_provider_domain(provider_name: &str) -> Option<String> {
    // Provider name to domain mapping for dynamic inference
    let provider_mappings = vec![
        ("google", "google.com"),
        ("microsoft", "microsoft.com"),
        ("apple", "apple.com"),
        ("adobe", "adobe.com"),
        ("stripe", "stripe.com"),
        ("docusign", "docusign.com"),
        ("globalsign", "globalsign.com"),
        ("dropbox", "dropbox.com"),
        ("zoom", "zoom.us"),
        ("atlassian", "atlassian.com"),
        ("browserstack", "browserstack.com"),
        ("canva", "canva.com"),
        ("cursor", "cursor.com"),
        ("datadome", "datadome.co"),
        ("drift", "drift.com"),
        ("hubspot", "hubspot.com"),
        ("klaviyo", "klaviyo.com"),
        ("notion", "notion.so"),
        ("onetrust", "onetrust.com"),
        ("openai", "openai.com"),
        ("postman", "postman.com"),
        ("slack", "slack.com"),
        ("teamviewer", "teamviewer.com"),
        ("wework", "wework.com"),
        ("heroku", "heroku.com"),
        ("jamf", "jamf.com"),
        ("intacct", "sage.com"), // Special case: Sage Intacct
        ("mailgun", "mailgun.com"),
        ("neat", "neat.co"),
        ("webex", "webex.com"),
        ("whimsical", "whimsical.com"),
        ("facebook", "facebook.com"),
        ("anthropic", "anthropic.com"),
        ("jetbrains", "jetbrains.com"),
        ("github", "github.com"),
        ("gitlab", "gitlab.com"),
        ("bitbucket", "bitbucket.org"),
        ("okta", "okta.com"),
        ("auth0", "auth0.com"),
        ("twilio", "twilio.com"),
        ("segment", "segment.com"),
        ("sentry", "sentry.io"),
        ("pagerduty", "pagerduty.com"),
        // Common generic mappings
        ("aws", "amazon.com"),
        ("gcp", "google.com"),
        ("azure", "microsoft.com"),
        ("salesforce", "salesforce.com"),
        ("shopify", "shopify.com"),
        ("zendesk", "zendesk.com"),
    ];

    for (name, domain) in &provider_mappings {
        if provider_name == *name {
            return Some(domain.to_string());
        }
    }

    // If no exact match, try appending .com as a fallback for common patterns
    if provider_name.len() > 2 && provider_name.chars().all(|c| c.is_alphanumeric()) {
        // Only do this for well-formed provider names to avoid false positives
        match provider_name {
            // Known cases where .com works
            "sendgrid" | "mailchimp" | "constantcontact" | "pardot" | "marketo" | "hubspot"
            | "intercom" | "freshdesk" | "typeform" => Some(format!("{}.com", provider_name)),
            _ => None,
        }
    } else {
        None
    }
}

pub(crate) fn is_valid_domain(domain: &str) -> bool {
    // Allow domains with underscores for SPF delegation patterns (e.g., _spf.google.com, _spf1.canva.com)
    // This matches RFC requirements for service records and SPF patterns
    // Each label can be 1-63 characters, starting with alphanumeric or underscore
    // Use pre-compiled regex for performance (B020 fix)

    // Additional validation: ensure no consecutive dots, no trailing dot (for our purposes)
    if domain.contains("..") || domain.ends_with('.') {
        return false;
    }

    // Check overall length and that it contains at least one dot
    DOMAIN_VALIDATION_REGEX.is_match(domain)
        && domain.contains('.')
        && domain.len() <= 253
        && domain.len() >= 4
}

/// Returns `true` iff every dot-separated label of `domain` is one hickory-resolver's
/// name parser will accept.
///
/// hickory parses a label beginning with `_` via `from_ascii` (bypassing IDNA), so
/// leading-underscore service labels — `_spf`, `_dmarc`, `_domainkey` — are accepted.
/// Any other label goes through IDNA (UTS-46 + STD3 ASCII), which **rejects** an
/// underscore anywhere in it: `spf_s2.oraclecloud.com` fails with
/// "Label contains invalid characters". A name like that is still a legitimate SPF
/// `include:` target and the DoH JSON arm (a plain URL query param, no hickory parse)
/// resolves it fine — so callers use this guard to skip only the doomed hickory
/// arms for such names, never the DoH lookup, and to avoid surfacing the misleading
/// IDNA error as the headline failure. `is_valid_domain` (which permits underscores
/// for the DoH/SPF path) is intentionally left untouched.
pub(crate) fn hickory_resolvable(domain: &str) -> bool {
    domain
        .split('.')
        .all(|label| label.starts_with('_') || !label.contains('_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // ── Per-transport circuit breaker (TransportHealth) + transport ladder ───────────

    #[test]
    fn doh_health_attempts_doh_while_healthy() {
        let h = TransportHealth::default();
        assert!(h.should_attempt(), "fresh state attempts DoH");
        // A few failures below the threshold do NOT flip it, and none returns the warn-once true.
        for _ in 0..(TRANSPORT_DOWN_THRESHOLD - 1) {
            assert!(!h.record_failure(), "no warn before the threshold");
            assert!(h.should_attempt(), "still healthy below threshold");
        }
    }

    #[test]
    fn doh_health_marks_down_at_threshold_and_warns_once() {
        let h = TransportHealth::default();
        let mut warned = 0;
        for _ in 0..TRANSPORT_DOWN_THRESHOLD {
            if h.record_failure() {
                warned += 1;
            }
        }
        assert_eq!(warned, 1, "warns exactly once, on the transition into down");
        // Now down: further failures never re-warn, and DoH is skipped (reprobe is in the future).
        assert!(!h.record_failure(), "no repeat warn once down");
        assert!(
            !h.should_attempt(),
            "DoH skipped while down and not yet re-probe time"
        );
    }

    #[test]
    fn doh_health_success_resets_to_healthy() {
        let h = TransportHealth::default();
        for _ in 0..TRANSPORT_DOWN_THRESHOLD {
            h.record_failure();
        }
        assert!(!h.should_attempt(), "down before success");
        h.record_success();
        assert!(
            h.should_attempt(),
            "success clears the streak -> DoH resumes"
        );
    }

    // ── The 2026-07-29 false-demotion regression ─────────────────────────────────────
    //
    // A depth-3 scan declared DoH "blocked" six times in fourteen minutes while DoH was
    // demonstrably answering (a live probe mid-outage returned HTTP 200 in 35ms). Each false
    // demotion moved the scan's DNS onto raw UDP/53, and sustained plain-port DNS got the WAN IP
    // throttled upstream for ~2h08m — taking every non-443 DNS transport on the LAN with it.
    //
    // The mechanism: one `TransportHealth` covers the whole DoH tier, so eight consecutive
    // failures could all belong to a single sick provider while its siblings were healthy.

    #[test]
    fn one_sick_provider_never_demotes_a_multi_provider_transport() {
        let h = TransportHealth::default();
        const PROVIDERS: usize = 6;

        // Provider 0 fails far past the threshold. Every other provider is fine.
        for _ in 0..(TRANSPORT_DOWN_THRESHOLD * 5) {
            assert!(
                !h.record_failure_from(0, PROVIDERS),
                "a single provider's streak must never announce the transport as down"
            );
            assert!(
                h.should_attempt_with_sources(PROVIDERS),
                "DoH must stay eligible while five of six providers are untested"
            );
        }
        assert!(!h.is_down(PROVIDERS));
    }

    #[test]
    fn transport_demotes_only_once_every_provider_has_failed() {
        let h = TransportHealth::default();
        const PROVIDERS: usize = 3;

        // Cover the streak length first, all on one provider — not down.
        for _ in 0..TRANSPORT_DOWN_THRESHOLD {
            h.record_failure_from(0, PROVIDERS);
        }
        assert!(
            h.should_attempt_with_sources(PROVIDERS),
            "one provider only"
        );

        // Second provider fails — still a provider left untested.
        h.record_failure_from(1, PROVIDERS);
        assert!(h.should_attempt_with_sources(PROVIDERS), "two of three");

        // The last provider fails: now the transport itself is unusable, and it says so once.
        assert!(
            h.record_failure_from(2, PROVIDERS),
            "warns on the transition once every provider has failed"
        );
        assert!(!h.should_attempt_with_sources(PROVIDERS), "now down");
        assert!(
            !h.record_failure_from(2, PROVIDERS),
            "never re-warns while down"
        );
    }

    #[test]
    fn any_provider_success_clears_the_implicated_set() {
        let h = TransportHealth::default();
        const PROVIDERS: usize = 3;
        for i in 0..PROVIDERS {
            for _ in 0..TRANSPORT_DOWN_THRESHOLD {
                h.record_failure_from(i, PROVIDERS);
            }
        }
        assert!(h.is_down(PROVIDERS), "all providers failed -> down");

        h.record_success();
        assert!(
            h.should_attempt_with_sources(PROVIDERS),
            "success revives it"
        );

        // And the implicated set is genuinely cleared, not merely the counter: one provider
        // failing again must not instantly re-trip the breaker on the stale mask.
        for _ in 0..(TRANSPORT_DOWN_THRESHOLD * 2) {
            h.record_failure_from(0, PROVIDERS);
        }
        assert!(
            h.should_attempt_with_sources(PROVIDERS),
            "stale failed-source bits must not survive a success"
        );
    }

    #[test]
    fn single_source_transports_are_unaffected_by_provider_awareness() {
        // DoT and UDP/53 have one upstream each; their behaviour must be byte-identical to before.
        let h = TransportHealth::default();
        let mut warned = 0;
        for _ in 0..TRANSPORT_DOWN_THRESHOLD {
            if h.record_failure() {
                warned += 1;
            }
        }
        assert_eq!(warned, 1);
        assert!(!h.should_attempt());
    }

    #[test]
    fn just_went_down_reports_the_transition_exactly_once() {
        let h = TransportHealth::default();
        const PROVIDERS: usize = 2;
        for i in 0..PROVIDERS {
            for _ in 0..TRANSPORT_DOWN_THRESHOLD {
                h.record_failure_from(i, PROVIDERS);
            }
        }
        assert!(h.just_went_down(PROVIDERS), "first observation reports");
        assert!(!h.just_went_down(PROVIDERS), "subsequent ones do not");
        h.record_success();
        for i in 0..PROVIDERS {
            for _ in 0..TRANSPORT_DOWN_THRESHOLD {
                h.record_failure_from(i, PROVIDERS);
            }
        }
        assert!(h.just_went_down(PROVIDERS), "a NEW outage reports again");
    }

    /// One pathological DOMAIN must never demote a healthy TRANSPORT.
    ///
    /// The per-provider breaker (above) assumed provider failures are independent. A name that
    /// SERVFAILs at its own authoritative servers is not: it fails identically on every provider,
    /// so it satisfies "all providers failed" by itself. Observed live on 2026-07-29 —
    /// `client-gateway.prod-ca-central-1.metrics.…` returned RCODE 2 from Cloudflare, Google and
    /// dns.sb alike, and the ladder demoted DoH seven times while DoH was answering in 42ms.
    ///
    /// The fix is classification, not counting: a DoH response carrying a well-formed dns-json
    /// body proves the transport works, whatever RCODE it reports.
    #[test]
    fn a_name_that_fails_on_every_provider_is_not_a_transport_failure() {
        // Model the two error classes exactly as the lookup paths emit them.
        let name_failure = "DNS_NAME: DoH provider X returned DNS RCODE 2 for broken.example";
        let endpoint_failure =
            "DNS_ENDPOINT: DoH provider X returned HTTP 400 for broken.example — endpoint does \
             not serve the JSON DoH API";

        assert!(
            name_failure.contains("DNS_NAME"),
            "the RCODE path must emit DNS_NAME so the rotation loop can credit the transport"
        );
        assert!(
            !name_failure.contains("DNS_ENDPOINT"),
            "DNS_NAME must not also match DNS_ENDPOINT — the rotation loop discriminates on \
             substring, so an overlapping tag would re-create the conflation"
        );
        assert!(
            endpoint_failure.contains("DNS_ENDPOINT") && !endpoint_failure.contains("DNS_NAME"),
            "a genuinely broken endpoint must stay DNS_ENDPOINT and keep tripping the breaker"
        );

        // And the breaker itself: crediting a success must clear a streak that spans every
        // provider, which is what makes an all-provider name failure survivable.
        let h = TransportHealth::default();
        const PROVIDERS: usize = 6;
        for i in 0..PROVIDERS {
            for _ in 0..TRANSPORT_DOWN_THRESHOLD {
                h.record_failure_from(i, PROVIDERS);
            }
        }
        assert!(h.is_down(PROVIDERS), "precondition: every provider failed");
        h.record_success();
        assert!(
            h.should_attempt_with_sources(PROVIDERS),
            "one answering provider must revive the transport — this is the path a DNS_NAME error \
             now takes, and it is what stops a single broken domain from demoting DoH"
        );
    }

    /// The governor must not read a name failure as network congestion, or one broken domain
    /// throttles the whole scan.
    #[test]
    fn a_name_failure_is_unrelated_to_the_governor_not_rejected() {
        use crate::dns_governor::DnsOutcome;
        let name_err: std::result::Result<(), String> =
            Err("DNS_NAME: DoH provider X returned DNS RCODE 2 for broken.example".to_string());
        let cname_err: std::result::Result<(), String> = Err("DNS_NAME: ditto".to_string());
        assert_eq!(
            classify_pair(&name_err, &cname_err),
            DnsOutcome::Unrelated,
            "a name failure must be Unrelated: the link is healthy, so the adaptive controller \
             has nothing to back off from"
        );

        let throttled: std::result::Result<(), String> =
            Err("DNS_THROTTLE: provider returned 429".to_string());
        assert_eq!(
            classify_pair(&throttled, &throttled),
            DnsOutcome::Rejected,
            "a genuine throttle must still be Rejected so the governor backs off"
        );
    }

    /// The single-error twin of the pair rule, for the root TXT race. `.ok()` used to erase the
    /// class here, so every SERVFAIL name cost the whole scan 30% of its concurrency. Wave 1
    /// narrowed what counts as congestion to what actually IS congestion evidence: an explicit
    /// provider refusal (`DNS_THROTTLE`) or a measured-deadline exhaustion (`DNS_TIMEOUT`). A
    /// broken endpoint, a dead ladder, and an unclassified decode error say nothing about load —
    /// reading them as refusals is what parked the governor at its floor for 61% of the Phase-1
    /// baseline (21,139 "rejections" against zero observed 429s).
    #[rstest]
    #[case::name_failure(
        Some("DNS_NAME: DoH provider X returned DNS RCODE 2 for broken.example"),
        crate::dns_governor::DnsOutcome::Unrelated
    )]
    #[case::throttle(
        Some("DNS_THROTTLE: DoH provider X returned HTTP 429 for a.example"),
        crate::dns_governor::DnsOutcome::Rejected
    )]
    #[case::deadline_exhausted(
        Some("DNS_TIMEOUT: DoH TXT rotation deadline (3000ms) exhausted for a.example"),
        crate::dns_governor::DnsOutcome::TimedOut
    )]
    #[case::broken_endpoint(
        Some("DNS_ENDPOINT: DoH provider X returned HTTP 400 for a.example"),
        crate::dns_governor::DnsOutcome::Unrelated
    )]
    #[case::dead_ladder(
        Some("DNS_ENDPOINT: no DNS transport could resolve TXT for a.example"),
        crate::dns_governor::DnsOutcome::Unrelated
    )]
    #[case::local_resource(
        Some("DNS_LOCAL: error sending request: Too many open files (os error 24)"),
        crate::dns_governor::DnsOutcome::Unrelated
    )]
    #[case::unclassified(
        Some("no DoH servers configured for TXT lookup of a.example"),
        crate::dns_governor::DnsOutcome::Unrelated
    )]
    #[case::no_class_at_all(None, crate::dns_governor::DnsOutcome::Unrelated)]
    fn governor_verdict_turns_on_the_failure_class(
        #[case] err: Option<&str>,
        #[case] expected: crate::dns_governor::DnsOutcome,
    ) {
        assert_eq!(
            failure_outcome_for_governor(err),
            expected,
            "the governor's reading of {err:?} must follow the class, not the fact of failure"
        );
    }

    /// A memo replay must not testify about a network it never touched — in either direction.
    #[test]
    fn a_memoized_arm_never_speaks_for_the_network() {
        use crate::dns_governor::DnsOutcome;

        let answered: Result<Vec<String>> = Ok(vec!["v=spf1 -all".to_string()]);
        let throttled: Result<Vec<String>> =
            Err(anyhow::anyhow!("DNS_THROTTLE: provider returned 429"));

        // The regression this exists for: one arm replayed from the memo, the other genuinely
        // throttled. Reading the replay as an answer would leave the governor at full concurrency
        // while the only query actually issued was being rejected.
        assert_eq!(
            classify_pair(
                &governor_view(true, &answered),
                &governor_view(false, &throttled),
            ),
            DnsOutcome::Rejected,
            "a remembered success must not mask a live throttle"
        );

        // And the mirror: a remembered failure must not make the controller back off over a name
        // no packet was sent for.
        let name_failure: Result<Vec<String>> =
            Err(anyhow::anyhow!("DNS_NAME: provider returned DNS RCODE 2"));
        assert_eq!(
            classify_pair(
                &governor_view(true, &name_failure),
                &governor_view(false, &answered),
            ),
            DnsOutcome::Answered,
            "a live answer decides alone when the other arm came from the memo"
        );

        // A live arm is passed through unchanged, so the existing pair rules still apply.
        assert_eq!(
            classify_pair(
                &governor_view(false, &name_failure),
                &governor_view(false, &name_failure),
            ),
            DnsOutcome::Unrelated,
            "two live name failures stay Unrelated — the link is healthy"
        );
    }

    // ── The negative memo's write gate ───────────────────────────────────────────────
    //
    // One rule, stated once: an outage must never memoize as absence. A throttle or a transport
    // failure means "we could not look", never "there is nothing there" — memoizing either would
    // turn one transient outage into a scan-wide false negative and would suppress the per-attempt
    // counting the exit-3 guard reads (GRC-367).

    #[rstest]
    // The ONLY memoizable class: a provider returned a well-formed dns-json body over a working
    // transport, reporting that this name's own authoritative servers failed it.
    #[case::servfail(
        "DNS_NAME: DoH provider X returned DNS RCODE 2 for broken.example",
        true
    )]
    #[case::refused(
        "DNS_NAME: DoH provider X returned DNS RCODE 5 for broken.example",
        true
    )]
    // "We could not look" — every one of these must be forgotten.
    #[case::throttle("DNS_THROTTLE: DoH provider X returned HTTP 429 for a.example", false)]
    #[case::broken_endpoint("DNS_ENDPOINT: DoH provider X returned HTTP 400 for a.example", false)]
    #[case::no_transport(
        "DNS_ENDPOINT: no DNS transport could resolve TXT for a.example",
        false
    )]
    #[case::timeout("error sending request: operation timed out", false)]
    #[case::local_fd_exhaustion("error sending request: Too many open files (os error 24)", false)]
    #[case::no_providers("no DoH servers configured for TXT lookup of a.example", false)]
    #[case::empty("", false)]
    // Mixed messages are refused rather than guessed at: a message carrying both tags is not a
    // clean verdict about the name, and the safe direction is to re-query.
    #[case::name_and_throttle("DNS_NAME … DNS_THROTTLE …", false)]
    #[case::name_and_endpoint("DNS_NAME … DNS_ENDPOINT …", false)]
    fn only_a_clean_name_verdict_may_be_memoized_as_absence(
        #[case] msg: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            may_memoize_failure(msg),
            expected,
            "may_memoize_failure({msg:?}) must be {expected}: remembering a failure that was \
             about our reach rather than about the zone is how one outage becomes a scan-wide \
             false negative"
        );
    }

    /// The write gate is enforced at the memo, not left to the caller's discipline — so a caller
    /// that hands it the wrong class writes nothing rather than poisoning the scan.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn memo_stores_an_authoritative_empty_but_refuses_an_outage() {
        let pool = DnsServerPool::with_test_urls(vec![]);

        // An authoritative empty IS a fact about the zone: the name has no records of this kind.
        pool.remember_answer(RecordKind::Txt, "norecords.example", &[])
            .await;
        assert!(
            matches!(
                pool.recall_memo(RecordKind::Txt, "norecords.example").await,
                Some(MemoEntry::Answer(ref records)) if records.is_empty()
            ),
            "an authoritative empty must be reusable — it is an answer, not a degradation marker"
        );

        // A throttle is not. It means we could not look.
        pool.remember_name_failure(
            RecordKind::Txt,
            "throttled.example",
            "DNS_THROTTLE: DoH provider X returned HTTP 429 for throttled.example",
        )
        .await;
        assert!(
            pool.recall_memo(RecordKind::Txt, "throttled.example")
                .await
                .is_none(),
            "a throttle must leave NO memo entry: the next lookup has to re-attempt and re-count"
        );

        // A name verdict is, and it comes back as a failure — not as an absence — so the caller
        // still counts it and the governor still reads it as Unrelated.
        let verdict = "DNS_NAME: DoH provider X returned DNS RCODE 2 for broken.example";
        pool.remember_name_failure(RecordKind::Txt, "broken.example", verdict)
            .await;
        let recalled = pool
            .recall_memo(RecordKind::Txt, "broken.example")
            .await
            .expect("a clean name verdict is memoized");
        assert!(matches!(recalled, MemoEntry::NameFailure(ref m) if m == verdict));
        let as_result = DnsServerPool::memo_as_result(&recalled);
        assert!(
            as_result.is_err(),
            "a remembered name failure must be served as a FAILURE, never as an empty answer — \
             otherwise the exit-3 guard stops seeing a name the scan never resolved"
        );
        assert_eq!(
            failure_outcome_for_governor(Some(&as_result.unwrap_err().to_string())),
            crate::dns_governor::DnsOutcome::Unrelated,
            "and serving it must not tell the governor a healthy link is congested"
        );
    }

    // ── CNAME-from-TXT extraction (P2.10b) ───────────────────────────────────────────

    #[test]
    fn cname_chain_is_read_out_of_a_txt_answer_section() {
        // A real dns-json TXT answer for an aliased name: the resolver had to follow the alias, so
        // the chain precedes the target's TXT records in the same answer section.
        let aliased = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "www.example.com", "type": 16}],
            "Answer": [
                {"name": "www.example.com", "type": 5, "TTL": 300, "data": "edge.cdn.net."},
                {"name": "edge.cdn.net", "type": 16, "TTL": 300, "data": "\"v=spf1 -all\""}
            ]
        });
        assert_eq!(
            cname_chain_from_dns_json(&aliased),
            vec!["edge.cdn.net".to_string()],
            "the alias must be extracted and its trailing dot trimmed, exactly as a dedicated \
             CNAME lookup would have rendered it"
        );

        // The no-CNAME case is the one that carries information: an authoritative answer with no
        // type-5 records PROVES the name is not aliased, which is what lets the fast path drop
        // its paired query rather than merely defer it.
        let plain = serde_json::json!({
            "Status": 0,
            "Answer": [
                {"name": "example.com", "type": 16, "TTL": 300, "data": "\"v=spf1 -all\""}
            ]
        });
        assert!(
            cname_chain_from_dns_json(&plain).is_empty(),
            "a TXT-only answer section means no alias"
        );

        // NXDOMAIN / NODATA shapes carry no Answer key at all.
        let no_answer_key = serde_json::json!({"Status": 3});
        assert!(cname_chain_from_dns_json(&no_answer_key).is_empty());
        let null_answer = serde_json::json!({"Status": 0, "Answer": serde_json::Value::Null});
        assert!(cname_chain_from_dns_json(&null_answer).is_empty());

        // A multi-hop chain keeps every hop, in resolution order. A dedicated CNAME query returns
        // only the first hop; the followed chain names more of the infrastructure actually in the
        // path, which for this scanner is the point.
        let chained = serde_json::json!({
            "Status": 0,
            "Answer": [
                {"name": "www.example.com", "type": 5, "data": "a.cdn.net."},
                {"name": "a.cdn.net", "type": 5, "data": "b.cdn.net."},
                {"name": "b.cdn.net", "type": 1, "data": "1.2.3.4"},
                {"name": "b.cdn.net", "type": 16, "data": "\"unrelated\""}
            ]
        });
        assert_eq!(
            cname_chain_from_dns_json(&chained),
            vec!["a.cdn.net".to_string(), "b.cdn.net".to_string()],
            "every alias hop is kept, and A/TXT answers in the same section are ignored"
        );

        // Malformed entries are skipped rather than stringified into junk vendor names.
        let malformed = serde_json::json!({
            "Status": 0,
            "Answer": [
                {"name": "x.example.com", "type": 5, "data": 42},
                {"name": "x.example.com", "type": 5, "data": "good.cdn.net."}
            ]
        });
        assert_eq!(
            cname_chain_from_dns_json(&malformed),
            vec!["good.cdn.net".to_string()],
            "a non-string data field must be dropped, not coerced"
        );
    }

    // ── UDP/53 emission ceiling ──────────────────────────────────────────────────────

    /// The one that actually matters: the ceiling must be WIRED INTO the UDP/53 admission path.
    ///
    /// Unit-testing `Do53Budget` alone is not enough — it stays green if the tier stops consulting
    /// the budget, which is precisely the regression that would re-enable the flood. This drives
    /// the real admission decision the tier uses.
    #[test]
    fn udp53_tier_admission_is_bounded_by_the_budget() {
        let pool = DnsServerPool::new();
        let admitted = (0..1000).filter(|_| pool.admit_do53_query()).count() as u64;
        assert_eq!(
            admitted, DO53_BURST,
            "the UDP/53 tier must admit at most the burst allowance before shedding; if this \
             equals 1000 the budget is no longer consulted by the admission path and a DoH \
             outage will again dump the whole scan onto port 53"
        );
        assert!(
            !pool.admit_do53_query(),
            "further queries stay shed until the budget refills"
        );
    }

    #[test]
    fn do53_budget_bounds_a_burst_then_sheds() {
        let b = Do53Budget::new();
        let granted = (0..1000).filter(|_| b.try_take()).count() as u64;
        assert_eq!(
            granted, DO53_BURST,
            "a cold burst may spend exactly the burst allowance, then every further \
             request is shed rather than queued"
        );
        assert!(!b.try_take(), "budget stays closed until it refills");
    }

    #[test]
    fn do53_budget_refills_at_the_configured_rate() {
        let b = Do53Budget::new();
        while b.try_take() {}
        // Rewind the refill clock by one second instead of sleeping: same arithmetic, no wall time.
        {
            let mut st = b.state.lock().unwrap();
            st.last_refill_ms = st.last_refill_ms.saturating_sub(1000);
        }
        let granted = (0..1000).filter(|_| b.try_take()).count() as u64;
        assert_eq!(
            granted, DO53_MAX_QPS,
            "one second of elapsed time yields exactly DO53_MAX_QPS tokens"
        );
    }

    #[test]
    fn do53_budget_cannot_be_refilled_by_a_backwards_clock() {
        let b = Do53Budget::new();
        while b.try_take() {}
        {
            let mut st = b.state.lock().unwrap();
            // A clock that jumped forward then back must not manufacture budget.
            st.last_refill_ms = st.last_refill_ms.saturating_add(60_000);
        }
        assert!(
            !b.try_take(),
            "a backwards clock step must not grant tokens (saturating_sub)"
        );
    }

    #[test]
    fn doh_health_reprobe_admits_exactly_one() {
        let h = TransportHealth::default();
        for _ in 0..TRANSPORT_DOWN_THRESHOLD {
            h.record_failure();
        }
        // Force the re-probe clock into the past: one lookup may probe DoH, the next may not.
        h.reprobe_after_ms.store(0, Ordering::Relaxed);
        assert!(h.should_attempt(), "one re-probe is admitted when due");
        assert!(
            !h.should_attempt(),
            "the next lookup is denied until the interval elapses again"
        );
    }

    #[test]
    fn transport_health_empty_answers_never_trip_the_breaker() {
        // The ladder calls record_success() on an authoritative Empty (the NORM for CNAME) and
        // record_failure() ONLY on a real transport failure. So any number of consecutive empties
        // must leave the transport healthy — otherwise the shared do53_health would false-trip on
        // empty-CNAME scanning and wrongly disable direct DNS for TXT too.
        let h = TransportHealth::default();
        for _ in 0..(TRANSPORT_DOWN_THRESHOLD * 3) {
            h.record_success();
            assert!(
                h.should_attempt(),
                "an authoritative empty keeps the transport healthy"
            );
        }
    }

    #[test]
    fn net_error_classifier_separates_authoritative_negatives_from_transport_failures() {
        use hickory_resolver::proto::op::ResponseCode;
        // A DNS-level response (the server spoke DNS) is an authoritative negative — the transport
        // WORKS → Empty. This is the exact case a Display-string classifier gets WRONG: hickory
        // renders the error with the queried name embedded, so `mtls.example.com` (or
        // `connection.foo.com`, `certificate.bar.com`) would false-match a substring and be counted
        // as a transport failure, false-tripping the shared breaker on an authoritative empty.
        assert!(net_error_is_authoritative_negative(&NetError::Dns(
            hickory_resolver::net::DnsError::ResponseCode(ResponseCode::NXDomain)
        )));
        // Genuine transport-level failures → NOT authoritative negatives; these advance the breaker.
        assert!(!net_error_is_authoritative_negative(&NetError::Timeout));
        assert!(!net_error_is_authoritative_negative(
            &NetError::NoConnections
        ));
        assert!(!net_error_is_authoritative_negative(&NetError::Busy));
    }

    #[test]
    fn dot_server_table_is_the_well_known_trio() {
        assert_eq!(DOT_SERVERS.len(), 3, "Cloudflare + Quad9 + Google");
        for (ip, name) in DOT_SERVERS {
            assert!(
                ip.parse::<std::net::IpAddr>().is_ok(),
                "{ip} parses as an IP"
            );
            assert!(name.contains('.'), "{name} is a TLS server name");
        }
    }

    #[tokio::test]
    async fn build_dot_resolver_is_constructible() {
        // No network I/O at build time — asserts only that the DoT resolver constructs over the
        // static 853 endpoints (feature `tls-ring` present, addresses parse, TLS names attach).
        assert!(
            build_dot_resolver().is_some(),
            "DoT resolver builds over DOT_SERVERS"
        );
    }

    // Live DoT (853) probe — real network; excluded from CI (no network) and from coverage (the
    // outcome helper is cfg(not(coverage))). Run locally with `--ignored` to prove the transport
    // actually resolves end-to-end.
    #[cfg(not(coverage))]
    #[tokio::test]
    #[ignore = "live network: requires outbound DNS-over-TLS on 853"]
    async fn dot_resolver_resolves_a_known_txt_live() {
        let resolver = build_dot_resolver().expect("DoT resolver builds");
        // cloudflare.com reliably publishes TXT records; resolve them over DoT and require >=1.
        let outcome = direct_txt_outcome(&resolver, "cloudflare.com", 6000).await;
        assert!(
            matches!(outcome, DirectOutcome::Answered(ref r) if !r.is_empty()),
            "DoT (853) should resolve cloudflare.com TXT to at least one record"
        );
    }

    #[test]
    fn test_is_local_resource_error_typed_and_text() {
        use std::io;
        // Typed path: an io::Error carrying EMFILE(24)/ENFILE(23) anywhere in the chain is caught
        // even if the rendered text does NOT contain the "too many open files" bytes — the robust
        // case a pure string match would miss.
        let emfile = anyhow::Error::new(io::Error::from_raw_os_error(24))
            .context("error trying to connect: tcp connect error");
        assert!(DnsServerPool::is_local_resource_error(&emfile));
        let enfile = anyhow::Error::new(io::Error::from_raw_os_error(23));
        assert!(DnsServerPool::is_local_resource_error(&enfile));

        // Text fallback: a wrapper that only stringified the OS error still classifies.
        assert!(DnsServerPool::is_local_resource_error(&anyhow::anyhow!(
            "error sending request: Too many open files (os error 24)"
        )));

        // The critical case the plain-Display match missed: a reqwest-shaped error whose TOP-LEVEL
        // Display omits the errno (it lives only in the source chain) and carries no downcastable
        // io::Error. `to_string()` must NOT see it, but `is_local_resource_error` (via `{:#}`) must.
        let reqwest_shaped = anyhow::anyhow!("inner: Too many open files (os error 24)")
            .context("error sending request for url (https://doh.sb/dns-query)");
        assert!(
            !reqwest_shaped.to_string().contains("os error 24"),
            "top-level Display should hide the errno — the trap a plain match falls into"
        );
        assert!(
            DnsServerPool::is_local_resource_error(&reqwest_shaped),
            "must classify via the alternate-Display fallback even when to_string() hides the errno"
        );

        // Provider-side failures are NOT local resource errors — they must still rotate/count.
        assert!(!DnsServerPool::is_local_resource_error(&anyhow::anyhow!(
            "DNS_THROTTLE: DoH provider Cloudflare returned HTTP 429 for example.com"
        )));
        // A different OS error (connection refused, errno 61) is not FD exhaustion.
        let refused = anyhow::Error::new(io::Error::from_raw_os_error(61));
        assert!(!DnsServerPool::is_local_resource_error(&refused));
    }

    #[rstest]
    // leading-underscore service labels stay resolvable (hickory's from_ascii path)
    #[case("_spf.google.com", true)]
    #[case("_dmarc.vanta.com", true)]
    #[case("selector1._domainkey.example.com", true)]
    #[case("_spf1.canva.com", true)]
    // plain names with no underscore stay resolvable
    #[case("google.com", true)]
    #[case("mail.oraclecloud.com", true)]
    // mid-label underscore is rejected by hickory's IDNA path — the failing class
    #[case("spf_s2.oraclecloud.com", false)]
    #[case("spf_c.oraclecloud.com", false)]
    #[case("a_b.example.com", false)]
    // a leading-underscore label with a *further* underscore is still fine (from_ascii)
    #[case("_x_y.example.com", true)]
    // any single bad label taints the whole name
    #[case("ok.bad_label.example.com", false)]
    fn test_hickory_resolvable(#[case] domain: &str, #[case] expected: bool) {
        assert_eq!(
            hickory_resolvable(domain),
            expected,
            "hickory_resolvable({domain:?}) should be {expected}"
        );
    }

    #[test]
    fn test_extract_spf_records() {
        let records = vec!["v=spf1 include:_spf.google.com include:sendgrid.net ~all".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        assert!(!results.is_empty());
        let domains: Vec<&str> = results.iter().map(|r| r.domain.as_str()).collect();
        assert!(domains.iter().any(|d| d.contains("google")));
        assert!(domains.iter().any(|d| d.contains("sendgrid")));
    }

    #[test]
    fn test_extract_verification_records() {
        let records = vec![
            "google-site-verification=abc123".to_string(),
            "MS=ms12345678".to_string(),
            "docusign=abcdef-1234-5678".to_string(),
            "atlassian-domain-verification=abc123".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_extract_dmarc_record() {
        let records = vec![
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com"
                .to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        let _ = results;
    }

    #[test]
    fn test_extract_dkim_record() {
        let records =
            vec!["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ...".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        let _ = results;
    }

    #[test]
    fn test_extract_empty_records() {
        let results = extract_vendor_domains_with_source(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_no_match_records() {
        let records = vec!["just some random text".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_with_logger() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "random-unmatched-record".to_string(),
        ];
        let results = extract_vendor_domains_with_source_and_logger(&records, None, "example.com");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_extract_dedup() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "v=spf1 include:_spf.google.com ~all".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        let google_count = results
            .iter()
            .filter(|r| r.domain.contains("google"))
            .count();
        assert_eq!(google_count, 1);
    }

    #[test]
    fn test_extract_spf_multiple_includes() {
        let records = vec![
            "v=spf1 include:_spf.google.com include:amazonses.com include:mailgun.org -all"
                .to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        assert!(results.len() >= 3);
    }

    #[test]
    fn test_unescape_dns_txt() {
        assert_eq!(unescape_dns_txt("hello"), "hello");
        assert_eq!(unescape_dns_txt("he\\llo"), "hello");
        assert_eq!(unescape_dns_txt("test\\\\value"), "test\\value");
    }

    #[rstest]
    #[case("google.com", true)]
    #[case("sub.domain.co.uk", true)]
    #[case("_spf.google.com", true)]
    #[case("", false)]
    #[case("x", false)]
    #[case("no-dot", false)]
    #[case("a..b.com", false)]
    fn test_is_valid_domain(#[case] domain: &str, #[case] expected: bool) {
        assert_eq!(is_valid_domain(domain), expected, "domain: {}", domain);
    }

    #[test]
    fn test_dns_server_pool_new() {
        let pool = DnsServerPool::new();
        let _ = pool;
    }

    #[test]
    fn test_vendor_domain_source_types() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "google-site-verification=abc123".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        let spf_results: Vec<_> = results
            .iter()
            .filter(|r| r.source_type == RecordType::DnsTxtSpf)
            .collect();
        let verification_results: Vec<_> = results
            .iter()
            .filter(|r| r.source_type == RecordType::DnsTxtVerification)
            .collect();
        assert!(!spf_results.is_empty());
        assert!(!verification_results.is_empty());
    }

    // ====================================================================
    // Additional inline tests for private helper functions
    // ====================================================================

    // --- unescape_dns_txt edge cases ---

    #[test]
    fn test_unescape_dns_txt_empty() {
        assert_eq!(unescape_dns_txt(""), "");
    }

    #[test]
    fn test_unescape_dns_txt_trailing_backslash() {
        // Trailing backslash with nothing after it
        assert_eq!(unescape_dns_txt("test\\"), "test");
    }

    #[test]
    fn test_unescape_dns_txt_escaped_quote() {
        assert_eq!(unescape_dns_txt(r#"say \"hello\""#), r#"say "hello""#);
    }

    #[test]
    fn test_unescape_dns_txt_escaped_underscore() {
        assert_eq!(unescape_dns_txt("test\\_value"), "test_value");
    }

    // --- strip_spf_macros ---

    #[test]
    fn test_strip_spf_macros_simple() {
        assert_eq!(strip_spf_macros("%{ir}.%{v}.domain.com"), "domain.com");
    }

    #[test]
    fn test_strip_spf_macros_no_macros() {
        assert_eq!(strip_spf_macros("_spf.google.com"), "_spf.google.com");
    }

    #[test]
    fn test_strip_spf_macros_with_numbers() {
        // SPF macros can have optional digit modifiers
        assert_eq!(strip_spf_macros("%{d4r}.example.com"), "example.com");
    }

    // --- is_valid_domain edge cases ---

    #[test]
    fn test_is_valid_domain_trailing_dot() {
        assert!(!is_valid_domain("example.com."));
    }

    #[test]
    fn test_is_valid_domain_consecutive_dots() {
        assert!(!is_valid_domain("example..com"));
    }

    #[test]
    fn test_is_valid_domain_too_long() {
        let long_domain = format!("{}.com", "a".repeat(250));
        assert!(!is_valid_domain(&long_domain));
    }

    #[test]
    fn test_is_valid_domain_underscore_prefix() {
        assert!(is_valid_domain("_spf.google.com"));
        assert!(is_valid_domain("_dmarc.example.com"));
    }

    #[test]
    fn test_is_valid_domain_minimum_length() {
        // 4 chars minimum: a.co
        assert!(is_valid_domain("a.co"));
        // 3 chars: too short
        assert!(!is_valid_domain("a.c"));
    }

    // --- extract_from_spf_record ---

    #[test]
    fn test_extract_from_spf_non_spf_record() {
        assert!(extract_from_spf_record("not an spf record", None, "", "").is_none());
    }

    #[test]
    fn test_extract_from_spf_case_insensitive() {
        // RFC compliance: V=SPF1 should also match
        let result = extract_from_spf_record(
            "V=SPF1 include:_spf.google.com ~all",
            None,
            "test.com",
            "V=SPF1 include:_spf.google.com ~all",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_spf_redirect() {
        let result = extract_from_spf_record(
            "v=spf1 redirect=_spf.example.com",
            None,
            "test.com",
            "v=spf1 redirect=_spf.example.com",
        );
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain.contains("example")));
    }

    #[test]
    fn test_extract_from_spf_a_mechanism() {
        let result = extract_from_spf_record(
            "v=spf1 a:mail.example.com ~all",
            None,
            "test.com",
            "v=spf1 a:mail.example.com ~all",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_spf_mx_mechanism() {
        let result = extract_from_spf_record(
            "v=spf1 mx:mx.example.com ~all",
            None,
            "test.com",
            "v=spf1 mx:mx.example.com ~all",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_spf_exists_mechanism() {
        let result = extract_from_spf_record(
            "v=spf1 exists:example.com ~all",
            None,
            "test.com",
            "v=spf1 exists:example.com ~all",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_spf_ptr_mechanism() {
        let result = extract_from_spf_record(
            "v=spf1 ptr:example.com ~all",
            None,
            "test.com",
            "v=spf1 ptr:example.com ~all",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_spf_with_macros() {
        let result = extract_from_spf_record(
            "v=spf1 exists:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
            None,
            "test.com",
            "v=spf1 exists:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
        );
        assert!(result.is_some());
        let domains = result.unwrap();
        // After macro stripping, should extract pphosted.com base domain
        assert!(domains.iter().any(|d| d.domain.contains("pphosted")));
    }

    #[test]
    fn test_extract_from_spf_no_domains() {
        // SPF record with only ip4/ip6 mechanisms - no domains to extract
        let result = extract_from_spf_record(
            "v=spf1 ip4:192.168.1.0/24 ip6:::1 ~all",
            None,
            "test.com",
            "v=spf1 ip4:192.168.1.0/24 ~all",
        );
        assert!(result.is_none());
    }

    // --- extract_from_dkim_record ---

    #[test]
    fn test_extract_from_dkim_non_dkim() {
        assert!(extract_from_dkim_record("not a dkim record", None, "", "").is_none());
    }

    #[test]
    fn test_extract_from_dkim_no_domains() {
        // DKIM record with public key but no domain references
        let result = extract_from_dkim_record(
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBA; h=sha256; s=email",
            None,
            "test.com",
            "DKIM record",
        );
        // h=sha256 and s=email don't contain dots, so no domains extracted
        assert!(result.is_none());
    }

    // --- extract_from_dmarc_record ---

    #[test]
    fn test_extract_from_dmarc_non_dmarc() {
        assert!(extract_from_dmarc_record("not a dmarc record", None, "", "").is_none());
    }

    #[test]
    fn test_extract_from_dmarc_case_insensitive() {
        let result = extract_from_dmarc_record(
            "V=DMARC1; p=reject; rua=mailto:reports@example.com",
            None,
            "test.com",
            "V=DMARC1; p=reject; rua=mailto:reports@example.com",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_dmarc_multiple_mailto() {
        let result = extract_from_dmarc_record(
            "v=DMARC1; p=reject; rua=mailto:a@domain1.com,mailto:b@domain2.com; ruf=mailto:c@domain3.com",
            None,
            "test.com",
            "dmarc record",
        );
        assert!(result.is_some());
        let domains = result.unwrap();
        let domain_strs: Vec<&str> = domains.iter().map(|d| d.domain.as_str()).collect();
        assert!(domain_strs.contains(&"domain1.com"));
        assert!(domain_strs.contains(&"domain2.com"));
        assert!(domain_strs.contains(&"domain3.com"));
    }

    #[test]
    fn test_extract_from_dmarc_no_mailto() {
        let result = extract_from_dmarc_record(
            "v=DMARC1; p=none; sp=none",
            None,
            "test.com",
            "v=DMARC1; p=none",
        );
        assert!(result.is_none());
    }

    // --- extract_from_verification_record ---

    #[test]
    fn test_extract_from_verification_record_no_match() {
        assert!(extract_from_verification_record("random text", None, "", "").is_none());
    }

    // --- try_static_verification_patterns ---

    #[rstest]
    #[case("facebook-domain-verification=abc123", "facebook.com")]
    #[case("apple-domain-verification=abc123", "apple.com")]
    #[case("adobe-idp-site-verification=abc123", "adobe.com")]
    #[case("stripe-verification=abc123", "stripe.com")]
    #[case("docusign=abc123", "docusign.com")]
    #[case("dropbox-domain-verification=abc123", "dropbox.com")]
    #[case("ZOOM_verify_abc123", "zoom.us")]
    #[case("atlassian-domain-verification=abc123", "atlassian.com")]
    #[case("slack-domain-verification=abc123", "slack.com")]
    #[case("hubspot-domain-verification=abc123", "hubspot.com")]
    #[case("openai-domain-verification=abc123", "openai.com")]
    #[case("notion-domain-verification=abc123", "notion.so")]
    #[case("anthropic-domain-verification=abc123", "anthropic.com")]
    #[case("jetbrains-domain-verification=abc123", "jetbrains.com")]
    #[case("heroku-domain-verification=abc123", "heroku.com")]
    #[case("jamf-site-verification=abc123", "jamf.com")]
    #[case("intacct-esk=abc123", "sage.com")]
    #[case("mgverify=abc123", "mailgun.com")]
    #[case("have-i-been-pwned-verification=abc123", "haveibeenpwned.com")]
    fn test_static_verification_patterns(#[case] record: &str, #[case] expected_domain: &str) {
        let result = try_static_verification_patterns(record, None, "", record);
        assert!(result.is_some(), "Should match pattern: {}", record);
        let domains = result.unwrap();
        assert!(
            domains.iter().any(|d| d.domain == expected_domain),
            "Expected {} for record {}, got {:?}",
            expected_domain,
            record,
            domains.iter().map(|d| &d.domain).collect::<Vec<_>>()
        );
    }

    // --- infer_provider_domain ---

    #[rstest]
    #[case("google", Some("google.com"))]
    #[case("zoom", Some("zoom.us"))]
    #[case("notion", Some("notion.so"))]
    #[case("datadome", Some("datadome.co"))]
    #[case("aws", Some("amazon.com"))]
    #[case("azure", Some("microsoft.com"))]
    #[case("sendgrid", Some("sendgrid.com"))]
    #[case("mailchimp", Some("mailchimp.com"))]
    #[case("intercom", Some("intercom.com"))]
    fn test_infer_provider_domain(#[case] provider: &str, #[case] expected: Option<&str>) {
        assert_eq!(
            infer_provider_domain(provider),
            expected.map(|s| s.to_string()),
            "provider: {}",
            provider
        );
    }

    #[test]
    fn test_infer_provider_domain_unknown() {
        // Short names or unknown providers
        assert_eq!(infer_provider_domain("ab"), None);
        assert_eq!(infer_provider_domain("unknown_xyz"), None);
    }

    #[test]
    fn test_infer_provider_domain_known_fallback() {
        // Providers that get .com appended as fallback
        assert_eq!(
            infer_provider_domain("freshdesk"),
            Some("freshdesk.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("typeform"),
            Some("typeform.com".to_string())
        );
    }

    // --- try_dynamic_verification_patterns ---

    #[test]
    fn test_dynamic_verification_known_provider() {
        let result = try_dynamic_verification_patterns(
            "github-domain-verification=abc123",
            None,
            "",
            "github-domain-verification=abc123",
        );
        assert!(result.is_some());
        assert!(result.unwrap().iter().any(|d| d.domain == "github.com"));
    }

    #[test]
    fn test_dynamic_verification_site_verification_pattern() {
        let result = try_dynamic_verification_patterns(
            "okta-site-verification=abc123",
            None,
            "",
            "okta-site-verification=abc123",
        );
        assert!(result.is_some());
        assert!(result.unwrap().iter().any(|d| d.domain == "okta.com"));
    }

    #[test]
    fn test_dynamic_verification_prefix_pattern() {
        let result = try_dynamic_verification_patterns(
            "verification-sentry=abc123",
            None,
            "",
            "verification-sentry=abc123",
        );
        assert!(result.is_some());
        assert!(result.unwrap().iter().any(|d| d.domain == "sentry.io"));
    }

    // --- collect_spf_targets ---

    #[test]
    fn test_collect_spf_targets_basic() {
        let mut targets = Vec::new();
        let mut visited = std::collections::HashSet::new();
        collect_spf_targets(
            "v=spf1 include:spf.protection.outlook.com redirect=_spf.example.com ~all",
            &mut targets,
            &mut visited,
        );
        assert!(targets.contains(&"spf.protection.outlook.com".to_string()));
        assert!(targets.contains(&"_spf.example.com".to_string()));
    }

    #[test]
    fn test_collect_spf_targets_dedup() {
        let mut targets = Vec::new();
        let mut visited = std::collections::HashSet::new();
        collect_spf_targets(
            "v=spf1 include:spf.google.com include:spf.google.com ~all",
            &mut targets,
            &mut visited,
        );
        // Should only appear once
        assert_eq!(targets.iter().filter(|t| t.contains("google")).count(), 1);
    }

    // --- LogFailure trait with logger ---

    struct TestLogger {
        failures: std::sync::Mutex<Vec<String>>,
    }

    impl TestLogger {
        fn new() -> Self {
            Self {
                failures: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl LogFailure for TestLogger {
        fn log_failure(
            &self,
            source_domain: &str,
            record_type: &str,
            raw_record: &str,
            extracted_service: Option<&str>,
            failure_reason: &str,
        ) {
            self.failures.lock().unwrap().push(format!(
                "{}:{}:{}:{}:{}",
                source_domain,
                record_type,
                raw_record,
                extracted_service.unwrap_or("none"),
                failure_reason
            ));
        }
    }

    #[test]
    fn test_extract_with_logger_logs_unmatched() {
        let logger = TestLogger::new();
        let records = vec!["some-unmatched-but-long-enough-record".to_string()];
        let _ =
            extract_vendor_domains_with_source_and_logger(&records, Some(&logger), "example.com");
        let failures = logger.failures.lock().unwrap();
        assert!(!failures.is_empty(), "Should log unmatched records");
        assert!(failures[0].contains("UNMATCHED_TXT"));
    }

    #[test]
    fn test_extract_with_logger_skips_short_unmatched() {
        let logger = TestLogger::new();
        let records = vec!["short".to_string()];
        let _ =
            extract_vendor_domains_with_source_and_logger(&records, Some(&logger), "example.com");
        let failures = logger.failures.lock().unwrap();
        assert!(
            failures.is_empty(),
            "Should not log short unmatched records"
        );
    }

    // --- DnsServerPool default ---

    #[test]
    fn test_dns_server_pool_default() {
        let pool = DnsServerPool::default();
        assert!(!pool.doh_servers.is_empty());
        assert!(!pool.dns_servers.is_empty());
    }

    #[test]
    fn test_dns_server_pool_with_test_urls() {
        let pool = DnsServerPool::with_test_urls(vec![
            "http://localhost:8080/dns".to_string(),
            "http://localhost:8081/dns".to_string(),
        ]);
        assert_eq!(pool.doh_servers.len(), 2);
        assert_eq!(pool.doh_servers[0].name, "Test DoH Server 1");
        assert_eq!(pool.doh_servers[1].name, "Test DoH Server 2");
    }

    // --- DnsServerPool rotation ---

    #[test]
    fn test_dns_server_pool_rotation() {
        let pool = DnsServerPool::new();
        let first = pool.next_doh_server().name.clone();
        let second = pool.next_doh_server().name.clone();
        // Should rotate to different servers
        assert_ne!(first, second, "Should rotate between servers");
    }

    #[test]
    fn test_dns_server_pool_dns_rotation() {
        let pool = DnsServerPool::new();
        let first = pool.next_dns_server().name.clone();
        let second = pool.next_dns_server().name.clone();
        assert_ne!(first, second, "DNS servers should rotate");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // is_valid_domain — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_is_valid_domain_empty() {
        assert!(!is_valid_domain(""));
    }

    #[test]
    fn test_is_valid_domain_single_label() {
        assert!(!is_valid_domain("localhost"));
    }

    #[test]
    fn test_is_valid_domain_length_253() {
        let label = "a".repeat(60);
        let domain = format!("{}.{}.{}.{}.com", label, label, label, label);
        assert!(
            domain.len() <= 253,
            "60*4 + separators = 247, within 253 limit"
        );
        assert!(is_valid_domain(&domain));
    }

    #[test]
    fn test_is_valid_domain_length_too_long() {
        let label = "a".repeat(63);
        let domain = format!("{}.{}.{}.{}.com", label, label, label, label);
        assert!(
            domain.len() > 253,
            "63*4 + separators = 259, exceeds 253 limit"
        );
        assert!(!is_valid_domain(&domain));
    }

    #[test]
    fn test_is_valid_domain_spf_underscore_prefix() {
        // SPF delegation domains use underscore prefixes
        assert!(is_valid_domain("_spf.google.com"));
        assert!(is_valid_domain("_dmarc.example.com"));
        assert!(is_valid_domain("_domainkey.example.com"));
    }

    #[test]
    fn test_is_valid_domain_three_char_minimum() {
        assert!(!is_valid_domain("a.b")); // len < 4
        assert!(is_valid_domain("ab.cd")); // len == 5
    }

    #[test]
    fn test_is_valid_domain_hyphen_in_label() {
        assert!(is_valid_domain("my-domain.com"));
        assert!(is_valid_domain("sub-domain.example.com"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // unescape_dns_txt — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_unescape_dns_txt_no_escapes() {
        assert_eq!(unescape_dns_txt("hello world"), "hello world");
    }

    #[test]
    fn test_unescape_dns_txt_double_backslash() {
        assert_eq!(unescape_dns_txt("path\\\\file"), "path\\file");
    }

    #[test]
    fn test_unescape_dns_txt_mixed_escapes() {
        assert_eq!(
            unescape_dns_txt(r#"v=spf1 include:\_spf.google.com"#),
            "v=spf1 include:_spf.google.com"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // strip_spf_macros — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_strip_spf_macros_multiple_macros() {
        let input = "%{ir}.%{v}.%{d}.spf.has.pphosted.com";
        let result = strip_spf_macros(input);
        assert_eq!(result, "spf.has.pphosted.com");
    }

    #[test]
    fn test_strip_spf_macros_empty() {
        assert_eq!(strip_spf_macros(""), "");
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_strip_spf_macros_only_macros() {
        let result = strip_spf_macros("%{ir}.%{v}.");
        assert!(result.is_empty() || result == ".");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_from_spf_record — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_from_spf_record_with_macros() {
        let record = "v=spf1 exists:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all";
        let result = extract_from_spf_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain.contains("pphosted.com")));
    }

    #[test]
    fn test_extract_from_spf_all_mechanism_types() {
        let record = "v=spf1 include:spf.protection.outlook.com a:mail.example.com mx:mx.example.com ptr:ptr.example.com redirect=redirect.example.com ~all";
        let result = extract_from_spf_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        // Should have extracted from include, a, mx, ptr, and redirect
        assert!(domains.len() >= 4);
    }

    #[test]
    fn test_extract_from_spf_empty_record() {
        let record = "v=spf1 ~all";
        let result = extract_from_spf_record(record, None, "test.com", record);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_from_spf_with_ip4_mechanisms() {
        // ip4 mechanisms should be ignored (they're IPs, not domains)
        let record = "v=spf1 ip4:192.168.1.0/24 include:_spf.google.com ~all";
        let result = extract_from_spf_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        // Should only extract from include, not from ip4
        assert!(domains.iter().all(|d| !d.domain.contains("192.168")));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_from_dkim_record — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_from_dkim_record_rsa_only() {
        let record = "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        // The p= value is a base64 key, not a domain, so should be None
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_from_dkim_record_ed25519() {
        let record = "k=ed25519; p=dGVzdA==";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        assert!(result.is_none()); // No valid domains in key material
    }

    #[test]
    fn test_extract_from_dkim_record_not_dkim() {
        let record = "This is not a DKIM record at all";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        assert!(result.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_from_dmarc_record — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_from_dmarc_record_rua_and_ruf() {
        let record = "v=DMARC1; p=quarantine; rua=mailto:dmarc@agari.com; ruf=mailto:forensics@proofpoint.com";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "agari.com"));
        assert!(domains.iter().any(|d| d.domain == "proofpoint.com"));
    }

    #[test]
    fn test_extract_from_dmarc_record_sp_tag_not_extracted() {
        // sp= contains policy values, not domains
        let record = "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        // sp=quarantine should NOT produce a domain
        assert!(domains.iter().all(|d| d.domain != "quarantine"));
    }

    #[test]
    fn test_extract_from_dmarc_record_mixed_case() {
        let record = "V=DMARC1; p=reject; RUA=mailto:report@dmarcian.com";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "dmarcian.com"));
    }

    #[test]
    fn test_extract_from_dmarc_record_no_mailto() {
        let record = "v=DMARC1; p=none";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_from_verification_record — static patterns
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verification_record_stripe() {
        let record = "stripe-verification=abc123def";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "stripe.com"));
    }

    #[test]
    fn test_verification_record_zoom() {
        let record = "ZOOM_verify_abc123";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "zoom.us"));
    }

    #[test]
    fn test_verification_record_anthropic() {
        let record = "anthropic-domain-verification=xyz789";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "anthropic.com"));
    }

    #[test]
    fn test_verification_record_whimsical_angle_bracket() {
        let record = "<whimsical=abc123>";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "whimsical.com"));
    }

    #[test]
    fn test_verification_record_mailgun() {
        let record = "mgverify=abc123";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "mailgun.com"));
    }

    #[test]
    fn test_verification_record_sage_intacct() {
        let record = "intacct-esk=abc123";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "sage.com"));
    }

    #[test]
    fn test_verification_record_no_match() {
        let record = "some-random-text-not-a-verification-record";
        let result = extract_from_verification_record(record, None, "test.com", record);
        assert!(result.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // infer_provider_domain — additional cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_infer_provider_domain_cloud_providers() {
        assert_eq!(infer_provider_domain("aws"), Some("amazon.com".to_string()));
        assert_eq!(infer_provider_domain("gcp"), Some("google.com".to_string()));
        assert_eq!(
            infer_provider_domain("azure"),
            Some("microsoft.com".to_string())
        );
    }

    #[test]
    fn test_infer_provider_domain_common_saas() {
        assert_eq!(
            infer_provider_domain("salesforce"),
            Some("salesforce.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("shopify"),
            Some("shopify.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("zendesk"),
            Some("zendesk.com".to_string())
        );
    }

    #[test]
    fn test_infer_provider_domain_known_fallback_com_providers() {
        assert_eq!(
            infer_provider_domain("sendgrid"),
            Some("sendgrid.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("mailchimp"),
            Some("mailchimp.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("intercom"),
            Some("intercom.com".to_string())
        );
        assert_eq!(
            infer_provider_domain("typeform"),
            Some("typeform.com".to_string())
        );
    }

    #[test]
    fn test_infer_provider_domain_returns_none_for_unknown() {
        assert_eq!(infer_provider_domain("xyzunknownprovider"), None);
        assert_eq!(infer_provider_domain("ab"), None); // too short
    }

    #[test]
    fn test_infer_provider_domain_security_vendors() {
        assert_eq!(
            infer_provider_domain("sentry"),
            Some("sentry.io".to_string())
        );
        assert_eq!(infer_provider_domain("okta"), Some("okta.com".to_string()));
        assert_eq!(
            infer_provider_domain("auth0"),
            Some("auth0.com".to_string())
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // try_dynamic_verification_patterns — edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_dynamic_verification_domain_verification_pattern() {
        let record = "hubspot-domain-verification=abc123";
        let result = try_dynamic_verification_patterns(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "hubspot.com"));
    }

    #[test]
    fn test_dynamic_verification_verification_prefix() {
        let record = "verification-sentry=abc123";
        let result = try_dynamic_verification_patterns(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "sentry.io"));
    }

    #[test]
    fn test_dynamic_verification_provider_verify_uppercase() {
        let record = "TWILIO_verify_abc123";
        let result = try_dynamic_verification_patterns(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "twilio.com"));
    }

    #[test]
    fn test_dynamic_verification_unknown_provider() {
        let record = "unknownxyz-domain-verification=abc123";
        let result = try_dynamic_verification_patterns(record, None, "test.com", record);
        // Unknown provider should not produce results
        assert!(result.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // collect_spf_targets — additional edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_collect_spf_targets_with_macros() {
        // RFC 7208 §7: a macro-bearing include:/redirect= target is a runtime
        // construct, not a static delegation. It must NOT be recursed into (the
        // stripped residual is non-resolvable). A static target alongside it is
        // still collected.
        let record = "v=spf1 include:%{ir}._spf.google.com redirect=_spf.salesforce.com ~all";
        let mut to_resolve = Vec::new();
        let mut visited = HashSet::new();
        collect_spf_targets(record, &mut to_resolve, &mut visited);
        // The macro-bearing include is skipped...
        assert!(
            !to_resolve.iter().any(|t| t.contains("google.com")),
            "macro-bearing include must not be enqueued, got {:?}",
            to_resolve
        );
        // ...but the static redirect is still collected.
        assert!(to_resolve.iter().any(|t| t.contains("salesforce.com")));
    }

    #[test]
    fn test_collect_spf_targets_skips_valimail_agari_macro_artifacts() {
        // Regression for the vanta.com run: Valimail/Agari publish macro-based
        // exists/include mechanisms. Their stripped residuals (_ip._ehlo._spf.vali.email,
        // 55.spf-protect.agari.com) previously got DNS-queried -> RCODE 2 noise.
        let record = "v=spf1 include:%{ir}._ip.%{v}._ehlo._spf.vali.email redirect=%{ir}.55.spf-protect.agari.com ~all";
        let mut to_resolve = Vec::new();
        let mut visited = HashSet::new();
        collect_spf_targets(record, &mut to_resolve, &mut visited);
        assert!(
            to_resolve.is_empty(),
            "no macro-bearing targets should be enqueued, got {:?}",
            to_resolve
        );
    }

    #[test]
    fn test_collect_spf_targets_no_targets() {
        let record = "v=spf1 ip4:192.168.1.0/24 ~all";
        let mut to_resolve = Vec::new();
        let mut visited = HashSet::new();
        collect_spf_targets(record, &mut to_resolve, &mut visited);
        assert!(to_resolve.is_empty());
    }

    #[test]
    fn test_collect_spf_targets_visited_dedup() {
        let record = "v=spf1 include:_spf.google.com include:_spf.google.com ~all";
        let mut to_resolve = Vec::new();
        let mut visited = HashSet::new();
        collect_spf_targets(record, &mut to_resolve, &mut visited);
        // Should only have one entry despite duplicate includes
        let google_count = to_resolve.iter().filter(|t| t.contains("google")).count();
        assert_eq!(google_count, 1);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // extract_vendor_domains_with_source — integration edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_vendor_domains_multiple_record_types() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "google-site-verification=abc123".to_string(),
            "v=DMARC1; p=reject; rua=mailto:report@proofpoint.com".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        assert!(results.len() >= 3); // At least one from each record type
        let source_types: Vec<String> = results
            .iter()
            .map(|r| r.source_type.as_hierarchy_string())
            .collect();
        assert!(source_types.iter().any(|t| t.contains("SPF")));
        assert!(source_types.iter().any(|t| t.contains("VERIFICATION")));
        assert!(source_types.iter().any(|t| t.contains("DMARC")));
    }

    #[test]
    fn test_extract_vendor_domains_empty_records() {
        let records: Vec<String> = vec![];
        let results = extract_vendor_domains_with_source(&records);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_vendor_domains_quoted_records() {
        // DNS TXT records are often wrapped in quotes
        let records = vec!["\"v=spf1 include:_spf.google.com ~all\"".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_extract_vendor_domains_dedup_same_entry() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "v=spf1 include:_spf.google.com ~all".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        // Should deduplicate identical entries
        let google_count = results
            .iter()
            .filter(|r| r.domain.contains("google"))
            .count();
        assert_eq!(google_count, 1);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VendorDomain struct and RecordType coverage
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_vendor_domain_debug() {
        let vd = VendorDomain {
            domain: "stripe.com".to_string(),
            source_type: RecordType::DnsTxtSpf,
            raw_record: "v=spf1 include:stripe.com".to_string(),
        };
        let debug_str = format!("{:?}", vd);
        assert!(debug_str.contains("stripe.com"));
    }

    #[test]
    fn test_vendor_domain_fields() {
        let vd = VendorDomain {
            domain: "stripe.com".to_string(),
            source_type: RecordType::DnsTxtSpf,
            raw_record: "v=spf1 include:stripe.com".to_string(),
        };
        assert_eq!(vd.domain, "stripe.com");
        assert_eq!(vd.raw_record, "v=spf1 include:stripe.com");
        assert_eq!(
            vd.source_type.as_hierarchy_string(),
            RecordType::DnsTxtSpf.as_hierarchy_string()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DnsServerPool — additional coverage
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_dns_server_pool_wraps_around() {
        let pool = DnsServerPool::new();
        let server_count = pool.doh_servers.len();
        // Access one more than the total to trigger wrap-around
        let mut names: Vec<String> = Vec::new();
        for _ in 0..=server_count {
            names.push(pool.next_doh_server().name.clone());
        }
        // The (server_count+1)th should wrap back to the first
        assert_eq!(names[0], names[server_count]);
    }

    #[test]
    fn test_dns_server_pool_dns_wraps_around() {
        let pool = DnsServerPool::new();
        let server_count = pool.dns_servers.len();
        let mut names: Vec<String> = Vec::new();
        for _ in 0..=server_count {
            names.push(pool.next_dns_server().name.clone());
        }
        assert_eq!(names[0], names[server_count]);
    }

    #[test]
    fn test_dns_server_pool_test_urls_empty() {
        let pool = DnsServerPool::with_test_urls(vec![]);
        assert!(pool.doh_servers.is_empty());
    }

    #[test]
    fn test_doh_server_config_fields() {
        let config = DohServerConfig {
            url: "https://dns.google/dns-query".to_string(),
            name: "Google DoH".to_string(),
            timeout_secs: 3,
        };
        assert_eq!(config.url, "https://dns.google/dns-query");
        assert_eq!(config.name, "Google DoH");
        assert_eq!(config.timeout_secs, 3);
    }

    #[test]
    fn test_dns_server_config_fields() {
        let config = DnsServerConfig {
            address: "1.1.1.1:53".to_string(),
            name: "Cloudflare".to_string(),
            timeout_secs: 2,
        };
        assert_eq!(config.address, "1.1.1.1:53");
        assert_eq!(config.name, "Cloudflare");
        assert_eq!(config.timeout_secs, 2);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Async DNS tests using wiremock for DoH mocking
    // ═══════════════════════════════════════════════════════════════════════════

    /// Helper: build a DoH JSON response for TXT records
    #[cfg(not(coverage))]
    fn build_doh_txt_response(domain: &str, txt_records: &[&str]) -> serde_json::Value {
        let answers: Vec<serde_json::Value> = txt_records
            .iter()
            .map(|txt| {
                serde_json::json!({
                    "name": domain,
                    "type": 16,
                    "TTL": 300,
                    "data": format!("\"{}\"", txt)
                })
            })
            .collect();
        serde_json::json!({
            "Status": 0,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [{"name": domain, "type": 16}],
            "Answer": answers
        })
    }

    /// Helper: build a DoH JSON response for CNAME records
    #[cfg(not(coverage))]
    fn build_doh_cname_response(domain: &str, cnames: &[&str]) -> serde_json::Value {
        let answers: Vec<serde_json::Value> = cnames
            .iter()
            .map(|cname| {
                serde_json::json!({
                    "name": domain,
                    "type": 5,
                    "TTL": 300,
                    "data": format!("{}.", cname)
                })
            })
            .collect();
        serde_json::json!({
            "Status": 0,
            "Question": [{"name": domain, "type": 5}],
            "Answer": answers
        })
    }

    /// Helper: build an empty DoH response (no answers)
    fn build_doh_empty_response(domain: &str) -> serde_json::Value {
        serde_json::json!({
            "Status": 0,
            "Question": [{"name": domain, "type": 16}],
            "Answer": []
        })
    }

    // --- doh_txt_lookup tests ---

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_success() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response =
            build_doh_txt_response("example.com", &["v=spf1 include:_spf.google.com ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "example.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool
            .doh_txt_lookup(
                "example.com",
                0,
                doh_server,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap()
            .txt;

        assert_eq!(records.len(), 1);
        assert!(records[0].contains("spf1"));
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_multiple_records() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response(
            "multi.com",
            &[
                "v=spf1 include:sendgrid.net ~all",
                "google-site-verification=abc123",
                "v=DMARC1; p=reject; rua=mailto:dmarc@multi.com",
            ],
        );

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "multi.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool
            .doh_txt_lookup(
                "multi.com",
                0,
                doh_server,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap()
            .txt;

        assert_eq!(records.len(), 3);
    }

    #[tokio::test]
    async fn test_doh_txt_lookup_empty_response() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_empty_response("empty.com");

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "empty.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool
            .doh_txt_lookup(
                "empty.com",
                0,
                doh_server,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap()
            .txt;

        assert!(records.is_empty());
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_non_txt_type_ignored() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Answer with type=1 (A record) instead of type=16 (TXT)
        let response = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "mix.com", "type": 16}],
            "Answer": [
                {"name": "mix.com", "type": 1, "TTL": 300, "data": "1.2.3.4"},
                {"name": "mix.com", "type": 16, "TTL": 300, "data": "\"v=spf1 ~all\""}
            ]
        });

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "mix.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let answer = pool
            .doh_txt_lookup("mix.com", 0, doh_server, std::time::Duration::from_secs(5))
            .await
            .unwrap();

        // Should only have the TXT record, not the A record
        assert_eq!(answer.txt.len(), 1);
        assert!(answer.txt[0].contains("spf1"));
        // …and the A record must not be mistaken for an alias hop either: only type 5 counts.
        assert_eq!(
            answer.cname,
            Some(vec![]),
            "an authoritative answer with no type-5 records proves the name is NOT aliased, \
             which is what lets the fast path skip its paired CNAME query"
        );
    }

    // --- doh_cname_lookup tests ---

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_cname_lookup_success() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_cname_response("alias.com", &["target.example.com"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "alias.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool
            .doh_cname_lookup(
                "alias.com",
                0,
                doh_server,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        // Trailing dot should be removed
        assert_eq!(records[0], "target.example.com");
    }

    #[tokio::test]
    async fn test_doh_cname_lookup_empty() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "nocname.com", "type": 5}],
            "Answer": []
        });

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "nocname.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool
            .doh_cname_lookup(
                "nocname.com",
                0,
                doh_server,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn test_doh_cname_lookup_non_cname_type_ignored() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Answer has type=1 (A record) but not type=5 (CNAME)
        let response = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "nocname.com", "type": 5}],
            "Answer": [
                {"name": "nocname.com", "type": 1, "TTL": 300, "data": "1.2.3.4"}
            ]
        });

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "nocname.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool
            .doh_cname_lookup(
                "nocname.com",
                0,
                doh_server,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert!(records.is_empty());
    }

    // --- get_txt_records_with_pool tests ---

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_pool_via_doh() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("test.com", &["v=spf1 include:_spf.google.com ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "test.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_txt_records_with_pool("test.com", &pool).await.unwrap();

        assert!(!records.is_empty());
        assert!(records[0].contains("spf1"));
    }

    #[tokio::test]
    async fn test_get_txt_records_with_pool_doh_failure_fallback() {
        // DoH server returns error, should fall back to traditional DNS then system
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        // This will fail DoH, try DNS fallback (which will also likely fail on 127.0.0.1:53),
        // then try system resolver. End result: either records or empty vec.
        let records = get_txt_records_with_pool("nonexistent-domain-xyz.invalid", &pool)
            .await
            .unwrap();
        // Just verify it doesn't panic and returns a result
        let _ = records;
    }

    // --- get_cname_records_with_pool tests ---

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_cname_records_with_pool_via_doh() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_cname_response("alias.example.com", &["target.cdn.com"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "alias.example.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_cname_records_with_pool("alias.example.com", &pool)
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0], "target.cdn.com");
    }

    #[tokio::test]
    async fn test_get_cname_records_with_pool_empty() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "nocname.test", "type": 5}],
            "Answer": []
        });

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "nocname.test"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_cname_records_with_pool("nocname.test", &pool)
            .await
            .unwrap();

        assert!(records.is_empty());
    }

    // --- get_txt_and_cname_fast tests ---

    // P2.10b: the CNAME chain rides along in the TXT response, so the fast path issues ONE query
    // for an aliased name where it used to issue two. The mock expectations are the assertion —
    // `expect(1)` on TXT and `expect(0)` on a fully working CNAME endpoint, both verified when the
    // server drops — so a regression that reinstates the paired query fails here rather than
    // silently doubling the busiest DNS path in the program.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_and_cname_fast_derives_cname_from_the_txt_response() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // A real dns-json TXT answer for an ALIASED name: the resolver had to follow the alias to
        // answer, so the chain is in the answer section ahead of the target's TXT records.
        let txt_response = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "fast.com", "type": 16}],
            "Answer": [
                {"name": "fast.com", "type": 5, "TTL": 300, "data": "cdn.fast.com."},
                {"name": "cdn.fast.com", "type": 16, "TTL": 300, "data": "\"v=spf1 ~all\""}
            ]
        });
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "fast.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(txt_response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .expect(1)
            .mount(&server)
            .await;

        // A perfectly good CNAME endpoint that must never be reached. `expect(0)` is verified on
        // drop, so a regression that reinstates the paired query fails this test rather than
        // quietly doubling the fast path's DNS volume again.
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "fast.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(build_doh_cname_response("fast.com", &["cdn.fast.com"]))
                    .insert_header("content-type", "application/dns-json"),
            )
            .expect(0)
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);
        let (txt_records, cname_records) = pool.get_txt_and_cname_fast("fast.com", &counter).await;

        assert!(!txt_records.is_empty());
        assert_eq!(
            cname_records,
            vec!["cdn.fast.com".to_string()],
            "the alias must be read out of the TXT response, with no CNAME query issued"
        );
        // A successful lookup must NOT register a DNS failure.
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "successful fast lookup must not increment the failure counter"
        );
    }

    // The other half of the same contract: a TXT answer with no type-5 records PROVES the name is
    // not aliased, so the CNAME query is skipped there too and the caller gets an honest empty.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_and_cname_fast_skips_cname_query_for_an_unaliased_name() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "plain.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(build_doh_txt_response("plain.com", &["v=spf1 ~all"]))
                    .insert_header("content-type", "application/dns-json"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);
        let (txt_records, cname_records) = pool.get_txt_and_cname_fast("plain.com", &counter).await;

        assert_eq!(txt_records.len(), 1);
        assert!(
            cname_records.is_empty(),
            "an answer carrying no type-5 records means the name is not aliased"
        );
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "a proven absence of aliasing is not a DNS failure"
        );
    }

    // The memo must serve the fast path too — it was the one high-volume caller that bypassed it.
    // `expect(1)` fails the test on drop if the second call puts a second query on the wire.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_and_cname_fast_second_lookup_is_served_from_the_memo() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "repeat.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(build_doh_txt_response("repeat.com", &["v=spf1 ~all"]))
                    .insert_header("content-type", "application/dns-json"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);
        let first = pool.get_txt_and_cname_fast("repeat.com", &counter).await;
        let second = pool.get_txt_and_cname_fast("repeat.com", &counter).await;

        assert_eq!(
            first, second,
            "the memo must reproduce the first lookup's answer verbatim"
        );
        assert_eq!(first.0.len(), 1);
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "a memo hit on a successful answer is not a failure"
        );
    }

    // The negative memo, end to end on the fast path: a name whose own servers SERVFAIL is
    // rotated over once, then remembered — but it is still COUNTED on every hit, because the memo
    // may remove the query and never the failure's visibility.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_and_cname_fast_memoizes_a_name_failure_but_keeps_counting_it() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // HTTP 200 carrying a well-formed dns-json body whose RCODE is SERVFAIL: the transport
        // demonstrably works, this NAME is broken. That is the only class the memo may keep.
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "Status": 2,
                        "Question": [{"name": "broken.example", "type": 16}]
                    }))
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);

        let (txt, cname) = pool
            .get_txt_and_cname_fast("broken.example", &counter)
            .await;
        assert!(txt.is_empty() && cname.is_empty());
        let after_first = counter.load(Ordering::Relaxed);
        assert!(
            after_first >= 1,
            "a name failure must be counted, never silently emptied"
        );
        let requests_after_first = server
            .received_requests()
            .await
            .expect("the mock server records requests")
            .len();

        let (txt, cname) = pool
            .get_txt_and_cname_fast("broken.example", &counter)
            .await;
        assert!(txt.is_empty() && cname.is_empty());
        assert!(
            counter.load(Ordering::Relaxed) > after_first,
            "a negative memo HIT must still count: the scan really did fail to resolve this name, \
             and the exit-3 guard and coverage summary must keep seeing it"
        );
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("the mock server records requests")
                .len(),
            requests_after_first,
            "the second lookup must issue NO query — this is the saving a shared broken SPF \
             include is supposed to produce across the thousands of domains referencing it"
        );
    }

    // GRC-367 (fix 6): the old assertion-free `test_get_txt_and_cname_fast_doh_failure`
    // mounted a 500 and asserted NOTHING (`let _ = …`) — it locked in the very bug the audit
    // found (a throttle silently collapsing to empty on the subdomain fast path). Rewritten to
    // assert the POST-FIX behavior: a 429/5xx that survives all DoH providers (and the dead
    // 127.0.0.1 DNS fallback in tests) is SURFACED via the failure counter, never silently empty.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_and_cname_fast_throttle_increments_failure_counter() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Single DoH provider that always 5xx-throttles (a DNS_THROTTLE per the doh_*_lookup
        // contract). The test DNS fallback target (127.0.0.1:53) won't answer, so the throttle
        // cannot be masked by a fallback success.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);
        let (txt_records, cname_records) = pool
            .get_txt_and_cname_fast("failing.invalid", &counter)
            .await;

        // Records are empty (analysis still continues), but the throttle is NOT silent: the
        // shared counter is incremented so the exit-3 guard can see it. One increment per
        // record type (TXT + CNAME) that was throttled across all providers.
        assert!(txt_records.is_empty());
        assert!(cname_records.is_empty());
        assert!(
            counter.load(Ordering::Relaxed) >= 1,
            "a throttle surviving all providers on the subdomain fast path MUST increment the \
             DNS failure counter, not collapse silently into an empty result"
        );
    }

    // --- get_txt_records_with_rate_limit tests ---

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_rate_limit_no_limiter() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("ratelimit.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "ratelimit.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_txt_records_with_rate_limit("ratelimit.com", &pool, None, None)
            .await
            .unwrap();

        assert!(!records.is_empty());
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_rate_limit_with_limiter() {
        use crate::config::RateLimitConfig;
        use crate::rate_limit::RateLimitContext;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("limited.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "limited.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let rate_config = RateLimitConfig {
            dns_queries_per_second: 100,
            dns_max_concurrency: None,
            http_requests_per_second: 10,
            whois_queries_per_second: 2,
            backoff_strategy: Default::default(),
            max_retries: 3,
            backoff_base_delay_ms: 100,
            backoff_max_delay_ms: 1000,
        };
        let ctx = RateLimitContext::from_config(&rate_config);
        let records = get_txt_records_with_rate_limit("limited.com", &pool, Some(&ctx), None)
            .await
            .unwrap();

        assert!(!records.is_empty());
    }

    // --- get_cname_records_with_rate_limit tests ---

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_cname_records_with_rate_limit_no_limiter() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_cname_response("cname-rl.com", &["target.cdn.com"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "cname-rl.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_cname_records_with_rate_limit("cname-rl.com", &pool, None, None)
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0], "target.cdn.com");
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_cname_records_with_rate_limit_with_limiter() {
        use crate::config::RateLimitConfig;
        use crate::rate_limit::RateLimitContext;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_cname_response("cname-limited.com", &["target.example.com"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "cname-limited.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let rate_config = RateLimitConfig {
            dns_queries_per_second: 100,
            dns_max_concurrency: None,
            http_requests_per_second: 10,
            whois_queries_per_second: 2,
            backoff_strategy: Default::default(),
            max_retries: 3,
            backoff_base_delay_ms: 100,
            backoff_max_delay_ms: 1000,
        };
        let ctx = RateLimitContext::from_config(&rate_config);
        let records =
            get_cname_records_with_rate_limit("cname-limited.com", &pool, Some(&ctx), None)
                .await
                .unwrap();

        assert_eq!(records.len(), 1);
    }

    // --- create_dns_resolver tests ---

    #[test]
    fn test_create_dns_resolver_valid_address() {
        let pool = DnsServerPool::new();
        let server = &pool.dns_servers[0];
        let resolver = pool.create_dns_resolver(server, false);
        assert!(resolver.is_ok());
    }

    #[test]
    fn test_create_dns_resolver_tcp() {
        let pool = DnsServerPool::new();
        let server = &pool.dns_servers[0];
        let resolver = pool.create_dns_resolver(server, true);
        assert!(resolver.is_ok());
    }

    #[test]
    fn test_create_dns_resolver_invalid_address() {
        let pool = DnsServerPool::new();
        let bad_server = DnsServerConfig {
            address: "not-an-ip-address".to_string(),
            name: "Bad Server".to_string(),
            timeout_secs: 2,
        };
        let resolver = pool.create_dns_resolver(&bad_server, false);
        assert!(resolver.is_err());
        let err = resolver.unwrap_err().to_string();
        assert!(err.contains("Invalid DNS server address"));
        assert!(err.contains("Bad Server"));
    }

    // --- resolve_spf_includes_recursive tests ---

    #[tokio::test]
    async fn test_resolve_spf_includes_recursive_no_spf() {
        let pool = DnsServerPool::new();
        let records = vec!["not an spf record".to_string()];
        let result = resolve_spf_includes_recursive(&records, &pool, "test.com").await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_spf_includes_recursive_no_includes() {
        let pool = DnsServerPool::new();
        let records = vec!["v=spf1 ip4:192.168.1.0/24 ~all".to_string()];
        let result = resolve_spf_includes_recursive(&records, &pool, "test.com").await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_resolve_spf_includes_recursive_with_mock() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // First level: initial SPF includes _spf.nested.com
        // When we resolve _spf.nested.com, it returns another SPF with a vendor
        let nested_response =
            build_doh_txt_response("_spf.nested.com", &["v=spf1 include:spf.vendor.com ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "_spf.nested.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(nested_response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        // Second level: spf.vendor.com has a simple SPF
        let vendor_response =
            build_doh_txt_response("spf.vendor.com", &["v=spf1 ip4:10.0.0.0/8 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "spf.vendor.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(vendor_response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let initial_records = vec!["v=spf1 include:_spf.nested.com ~all".to_string()];
        let result = resolve_spf_includes_recursive(&initial_records, &pool, "test.com").await;

        // Should have found vendor.com from the nested SPF
        assert!(result.iter().any(|d| d.domain.contains("vendor")));
    }

    #[tokio::test]
    async fn test_resolve_spf_includes_recursive_failed_lookup() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // DoH server always returns 500
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let initial_records = vec!["v=spf1 include:_spf.fails.com ~all".to_string()];
        let result = resolve_spf_includes_recursive(&initial_records, &pool, "test.com").await;

        // Should handle failures gracefully
        let _ = result;
    }

    // --- DnsServerPool from_config test ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_dns_server_pool_from_config() {
        use crate::config::AppConfig;

        // Try config-based pool; fall back to default if config unavailable.
        // Both paths must produce non-empty server lists.
        let pool = AppConfig::load()
            .map(|c| DnsServerPool::from_config(&c))
            .unwrap_or_else(|_| DnsServerPool::new());
        assert!(!pool.doh_servers.is_empty());
        assert!(!pool.dns_servers.is_empty());
    }

    // --- fast_txt_lookup and fast_cname_lookup tests ---

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_fast_txt_lookup_doh_success() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("fast-txt.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "fast-txt.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let result = pool.fast_txt_lookup("fast-txt.com").await.unwrap();

        assert!(!result.txt.is_empty());
        // A DoH answer settles the alias chain too, which is what the caller keys the
        // drop-the-paired-CNAME-query decision on.
        assert_eq!(
            result.cname,
            Some(vec![]),
            "a dns-json answer must report the chain (here: not aliased), not leave it unknown"
        );
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_fast_txt_lookup_doh_failure_dns_fallback() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Only DoH provider returns 500 (a throttle/5xx); no healthy provider to rotate to and
        // the test UDP fallback (127.0.0.1:53) is unreachable.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        // GRC-367 fix 1: a surviving throttle on the subdomain fast path MUST surface as a
        // DNS_THROTTLE error (so get_txt_and_cname_fast counts it toward the exit-3 guard),
        // never be silently swallowed into an empty answer.
        let result = pool.fast_txt_lookup("nonexistent.invalid").await;
        assert!(
            result.is_err(),
            "5xx throttle must surface, not be swallowed into Ok(empty)"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_THROTTLE"),
            "surfaced error must be tagged DNS_THROTTLE"
        );
    }

    /// A SERVFAIL name must keep its class all the way out of the fast path.
    ///
    /// It used to be relabelled `DNS_ENDPOINT` by the bottom of the ladder, which had two costs:
    /// the governor read a broken domain as a congested network and cut scan-wide concurrency for
    /// it, and the name could never enter the negative memo — so every one of the (potentially
    /// thousands of) domains referencing a shared broken name re-paid the full provider rotation.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_fast_txt_lookup_keeps_the_name_class_when_the_ladder_also_fails() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // HTTP 200 with a well-formed dns-json body reporting SERVFAIL: the transport worked, the
        // NAME did not. The test UDP fallback (127.0.0.1:53) then fails, as in the sibling test.
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "Status": 2,
                        "Question": [{"name": "servfail.invalid", "type": 16}]
                    }))
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let err = pool
            .fast_txt_lookup("servfail.invalid")
            .await
            .expect_err("no transport resolved the name, so this must be a failure")
            .to_string();

        assert!(
            err.contains("DNS_NAME"),
            "the name verdict must survive the ladder, got: {err}"
        );
        assert!(
            !err.contains("DNS_ENDPOINT"),
            "re-labelling it DNS_ENDPOINT is the regression: it makes the governor throttle a \
             healthy link and locks the name out of the negative memo. Got: {err}"
        );
        assert!(
            may_memoize_failure(&err),
            "and the surfaced class must be one the memo will actually accept"
        );
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_fast_cname_lookup_doh_success() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_cname_response("fast-cname.com", &["target.cdn.com"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "fast-cname.com"))
            .and(query_param("type", "CNAME"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let result = pool.fast_cname_lookup("fast-cname.com").await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "target.cdn.com");
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_fast_cname_lookup_doh_failure_dns_fallback() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        // GRC-367 fix 2: a CNAME-path throttle must surface as DNS_THROTTLE, not Ok(empty).
        let result = pool.fast_cname_lookup("nonexistent.invalid").await;
        assert!(
            result.is_err(),
            "5xx throttle must surface, not be swallowed into Ok(empty)"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_THROTTLE"),
            "surfaced error must be tagged DNS_THROTTLE"
        );
    }

    // --- get_txt_records (without pool) ---

    #[tokio::test]
    async fn test_get_txt_records_creates_default_pool() {
        // This will use the real DNS pool and make actual DNS queries
        // Test with a domain that definitely won't have TXT records
        let result = get_txt_records("this-domain-does-not-exist-xyz.invalid").await;
        // Should not panic, should return Ok (possibly empty)
        assert!(result.is_ok());
    }

    // --- DoH with escaped TXT records ---

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_with_escaped_data() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Response with escaped characters in TXT data
        let response = serde_json::json!({
            "Status": 0,
            "Question": [{"name": "escaped.com", "type": 16}],
            "Answer": [
                {
                    "name": "escaped.com",
                    "type": 16,
                    "TTL": 300,
                    "data": "\"v=spf1 include:\\_spf.google.com ~all\""
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "escaped.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = &pool.doh_servers[0];
        let records = pool
            .doh_txt_lookup(
                "escaped.com",
                0,
                doh_server,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap()
            .txt;

        assert_eq!(records.len(), 1);
        // The unescape function should handle \_ -> _
        assert!(records[0].contains("_spf.google.com"));
    }

    // --- DMARC with logger for invalid domain ---

    #[test]
    fn test_extract_from_dmarc_record_with_logger_invalid_domain() {
        let logger = TestLogger::new();
        let record = "v=DMARC1; p=reject; rua=mailto:x@a";
        let result = extract_from_dmarc_record(record, Some(&logger), "test.com", record);
        // "a" is not a valid domain (too short, no dot), so logger should capture failure
        let _failures = logger.failures.lock().unwrap();
        assert!(result.is_none(), "invalid domain should yield no results");
    }

    // --- SPF with logger for invalid domain ---

    #[test]
    fn test_extract_from_spf_with_logger_invalid_domain() {
        let logger = TestLogger::new();
        let record = "v=spf1 include:x ~all";
        let result = extract_from_spf_record(record, Some(&logger), "test.com", record);
        // "x" is not a valid domain, so logger should be called
        assert!(result.is_none());
        let failures = logger.failures.lock().unwrap();
        assert!(
            !failures.is_empty(),
            "Should log failure for invalid SPF domain"
        );
        assert!(failures[0].contains("SPF"));
    }

    // --- Comprehensive vendor domain extraction with all record types ---

    #[test]
    fn test_extract_vendor_domains_comprehensive() {
        let records = vec![
            // SPF with multiple mechanisms using unique domains to avoid dedup
            "v=spf1 include:_spf.google.com a:mail.sendgrid.net mx:mx.outlook.com ptr:ptr.mailgun.org ~all".to_string(),
            // DMARC with rua and ruf
            "v=DMARC1; p=reject; rua=mailto:dmarc@proofpoint.com; ruf=mailto:forensics@agari.com".to_string(),
            // Multiple verification records
            "google-site-verification=abc123".to_string(),
            "facebook-domain-verification=xyz789".to_string(),
            "apple-domain-verification=def456".to_string(),
            "MS=msxxxxxxxx".to_string(),
            "stripe-verification=stripe123".to_string(),
            "slack-domain-verification=slack456".to_string(),
            // DKIM record
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3".to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        // Should have extracted from SPF, DMARC, and verification records
        assert!(results.len() >= 8);

        // Check record types are correct
        let spf_count = results
            .iter()
            .filter(|r| r.source_type == RecordType::DnsTxtSpf)
            .count();
        let dmarc_count = results
            .iter()
            .filter(|r| r.source_type == RecordType::DnsTxtDmarc)
            .count();
        let verif_count = results
            .iter()
            .filter(|r| r.source_type == RecordType::DnsTxtVerification)
            .count();
        assert!(
            spf_count >= 3,
            "Should have at least 3 SPF domains, got {}",
            spf_count
        );
        assert!(
            dmarc_count >= 2,
            "Should have at least 2 DMARC domains, got {}",
            dmarc_count
        );
        assert!(
            verif_count >= 4,
            "Should have at least 4 verification domains, got {}",
            verif_count
        );
    }

    // --- Additional static verification patterns ---

    #[rstest]
    #[case("globalsign-domain-verification=abc", "globalsign.com")]
    #[case("browserstack-domain-verification=abc", "browserstack.com")]
    #[case("canva-site-verification=abc", "canva.com")]
    #[case("cursor-domain-verification=abc", "cursor.com")]
    #[case("datadome-domain-verify=abc", "datadome.co")]
    #[case("drift-domain-verification=abc", "drift.com")]
    #[case("klaviyo-site-verification=abc", "klaviyo.com")]
    #[case("onetrust-domain-verification=abc", "onetrust.com")]
    #[case("postman-domain-verification=abc", "postman.com")]
    #[case("teamviewer-sso-verification=abc", "teamviewer.com")]
    #[case("wework-site-verification=abc", "wework.com")]
    #[case("webex-domain-verification=abc", "webex.com")]
    #[case("zoom-domain-verification=abc", "zoom.us")]
    #[case("neat-pulse-domain-verification=abc", "neat.co")]
    #[case("gc-ai-domain-verification=abc", "gc-ai.com")]
    fn test_additional_static_verification_patterns(
        #[case] record: &str,
        #[case] expected_domain: &str,
    ) {
        let result = try_static_verification_patterns(record, None, "", record);
        assert!(result.is_some(), "Should match pattern: {}", record);
        let domains = result.unwrap();
        assert!(
            domains.iter().any(|d| d.domain == expected_domain),
            "Expected {} for record {}, got {:?}",
            expected_domain,
            record,
            domains.iter().map(|d| &d.domain).collect::<Vec<_>>()
        );
    }

    // --- infer_provider_domain: additional providers ---

    #[rstest]
    #[case("constantcontact", Some("constantcontact.com"))]
    #[case("pardot", Some("pardot.com"))]
    #[case("marketo", Some("marketo.com"))]
    #[case("github", Some("github.com"))]
    #[case("gitlab", Some("gitlab.com"))]
    #[case("bitbucket", Some("bitbucket.org"))]
    #[case("twilio", Some("twilio.com"))]
    #[case("segment", Some("segment.com"))]
    #[case("pagerduty", Some("pagerduty.com"))]
    fn test_infer_provider_domain_additional(
        #[case] provider: &str,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(
            infer_provider_domain(provider),
            expected.map(|s| s.to_string()),
            "provider: {}",
            provider
        );
    }

    // --- infer_provider_domain: special cases ---

    #[test]
    fn test_infer_provider_domain_special_char_in_name() {
        // Provider with non-alphanumeric chars - should return None
        assert_eq!(infer_provider_domain("test-provider"), None);
        assert_eq!(infer_provider_domain("test_provider"), None);
    }

    #[test]
    fn test_infer_provider_domain_single_char() {
        assert_eq!(infer_provider_domain("a"), None);
    }

    // --- DMARC edge cases ---

    #[test]
    fn test_extract_from_dmarc_record_ruf_only() {
        let record = "v=DMARC1; p=reject; ruf=mailto:forensics@mimecast.com";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "mimecast.com"));
    }

    #[test]
    fn test_extract_from_dmarc_record_rua_without_at_sign() {
        // mailto:domain (without user@)
        let record = "v=DMARC1; p=reject; rua=mailto:reporting.example.com";
        let result = extract_from_dmarc_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "reporting.example.com"));
    }

    // --- extract_vendor_domains with quoted and escaped records ---

    #[test]
    fn test_extract_vendor_domains_backslash_escaped() {
        let records = vec!["v=spf1 include:\\_spf.google.com ~all".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_extract_vendor_domains_double_quoted() {
        let records = vec!["\"v=spf1 include:_spf.google.com ~all\"".to_string()];
        let results = extract_vendor_domains_with_source(&records);
        assert!(!results.is_empty());
    }

    // --- DnsServerPool with single server ---

    #[test]
    fn test_dns_server_pool_with_single_test_url() {
        let pool =
            DnsServerPool::with_test_urls(vec!["http://localhost:1234/dns-query".to_string()]);
        assert_eq!(pool.doh_servers.len(), 1);
        assert_eq!(pool.dns_servers.len(), 1);
        // Rotation with single server should always return the same
        let first = pool.next_doh_server().name.clone();
        let second = pool.next_doh_server().name.clone();
        assert_eq!(first, second);
    }

    // --- DohServerConfig and DnsServerConfig debug ---

    #[test]
    fn test_doh_server_config_debug() {
        let config = DohServerConfig {
            url: "https://dns.example.com/dns-query".to_string(),
            name: "Test".to_string(),
            timeout_secs: 5,
        };
        let debug = format!("{:?}", config);
        assert!(debug.contains("Test"));
        assert!(debug.contains("dns.example.com"));
    }

    #[test]
    fn test_dns_server_config_debug() {
        let config = DnsServerConfig {
            address: "8.8.8.8:53".to_string(),
            name: "Google".to_string(),
            timeout_secs: 2,
        };
        let debug = format!("{:?}", config);
        assert!(debug.contains("Google"));
        assert!(debug.contains("8.8.8.8"));
    }

    // --- DohServerConfig and DnsServerConfig clone ---

    #[test]
    fn test_doh_server_config_clone() {
        let config = DohServerConfig {
            url: "https://dns.test.com/dns-query".to_string(),
            name: "Clone Test".to_string(),
            timeout_secs: 3,
        };
        let cloned = config.clone();
        assert_eq!(config.url, cloned.url);
        assert_eq!(config.name, cloned.name);
        assert_eq!(config.timeout_secs, cloned.timeout_secs);
    }

    #[test]
    fn test_dns_server_config_clone() {
        let config = DnsServerConfig {
            address: "1.1.1.1:53".to_string(),
            name: "Clone Test".to_string(),
            timeout_secs: 2,
        };
        let cloned = config.clone();
        assert_eq!(config.address, cloned.address);
        assert_eq!(config.name, cloned.name);
        assert_eq!(config.timeout_secs, cloned.timeout_secs);
    }

    // ═══════════════════════════════════════════════════════════════════
    // DKIM record extraction with domain references
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_from_dkim_record_with_domain_in_s_tag() {
        // DKIM record where s= tag contains a valid domain
        let record = "v=DKIM1; k=rsa; s=mail.vendor.com; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "mail.vendor.com"));
        assert!(domains
            .iter()
            .all(|d| d.source_type == RecordType::DnsTxtDkim));
    }

    #[test]
    fn test_extract_from_dkim_record_with_domain_in_h_tag() {
        // DKIM record where h= tag contains a valid domain (unusual but possible)
        let record = "v=DKIM1; k=rsa; h=hash.provider.org; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "hash.provider.org"));
    }

    #[test]
    fn test_dkim_record_through_full_extraction_pipeline() {
        // Test that DKIM records with domain references flow through the full pipeline
        let records = vec![
            "v=DKIM1; k=rsa; s=selector.mailservice.com; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ"
                .to_string(),
        ];
        let results = extract_vendor_domains_with_source(&records);
        assert!(results
            .iter()
            .any(|d| d.domain == "selector.mailservice.com"));
    }

    #[test]
    fn test_dkim_record_ed25519_with_domain() {
        let record = "v=DKIM1; k=ed25519; s=dkim.thirdparty.net; p=abcdef1234567890";
        let result = extract_from_dkim_record(record, None, "test.com", record);
        assert!(result.is_some());
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "dkim.thirdparty.net"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Dynamic verification patterns — cover all 4 pattern branches
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_dynamic_verification_all_four_patterns_in_one() {
        // Pattern 1: *-domain-verification=
        let r1 = "stripe-domain-verification=abc123";
        let res1 = try_dynamic_verification_patterns(r1, None, "test.com", r1);
        assert!(res1.is_some());
        assert!(res1.unwrap().iter().any(|d| d.domain == "stripe.com"));

        // Pattern 2: verification-*=
        let r2 = "verification-okta=abc123";
        let res2 = try_dynamic_verification_patterns(r2, None, "test.com", r2);
        assert!(res2.is_some());
        assert!(res2.unwrap().iter().any(|d| d.domain == "okta.com"));

        // Pattern 3: *-site-verification=
        let r3 = "adobe-site-verification=abc123";
        let res3 = try_dynamic_verification_patterns(r3, None, "test.com", r3);
        assert!(res3.is_some());
        assert!(res3.unwrap().iter().any(|d| d.domain == "adobe.com"));

        // Pattern 4: PROVIDER_verify_
        let r4 = "ZOOM_verify_abc123";
        let res4 = try_dynamic_verification_patterns(r4, None, "test.com", r4);
        assert!(res4.is_some());
        assert!(res4.unwrap().iter().any(|d| d.domain == "zoom.us"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // try_system_dns_resolver — previously coverage(off)
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_try_system_dns_resolver_valid_domain() {
        let result = try_system_dns_resolver("google.com").await;
        match result {
            Ok(records) => {
                // google.com has TXT records (SPF, verification, etc.)
                assert!(!records.is_empty(), "google.com should have TXT records");
                let has_spf = records.iter().any(|r| r.contains("spf"));
                assert!(
                    has_spf,
                    "google.com TXT records should include SPF: {:?}",
                    records
                );
            }
            Err(e) => {
                // DNS resolution may fail in sandboxed/offline environments
                let msg = e.to_string();
                assert!(
                    !msg.is_empty(),
                    "Error message should be descriptive: {}",
                    msg
                );
            }
        }
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_try_system_dns_resolver_nonexistent_domain() {
        let result = try_system_dns_resolver("zzz-nonexistent.invalid").await;
        // .invalid TLD should fail DNS resolution
        assert!(
            result.is_err(),
            "Nonexistent domain should fail DNS resolution"
        );
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_try_system_dns_resolver_no_txt_records() {
        let result = try_system_dns_resolver("zzz-no-txt-records-test.com").await;
        if let Ok(records) = result {
            let _ = records;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Coverage gap tests — exercise untested production code paths
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_spf_logger_invalid_domain() {
        let logger = TestLogger::new();
        let record = "v=spf1 include:a ~all";
        let result = extract_from_spf_record(record, Some(&logger), "example.com", record);
        assert!(result.is_none());
        let failures = logger.failures.lock().unwrap();
        assert!(
            !failures.is_empty(),
            "Logger should capture invalid SPF domain 'a'"
        );
        assert!(failures[0].contains("Invalid domain format"));
    }

    #[test]
    fn test_collect_spf_targets_include() {
        let mut to_resolve = Vec::new();
        let mut visited = std::collections::HashSet::new();
        collect_spf_targets(
            "v=spf1 include:_spf.google.com redirect=_spf.example.com ~all",
            &mut to_resolve,
            &mut visited,
        );
        assert!(
            !to_resolve.is_empty(),
            "Should collect SPF include/redirect targets"
        );
        assert!(to_resolve.iter().any(|d| d.contains("google.com")));
        assert!(to_resolve.iter().any(|d| d.contains("example.com")));
    }

    #[test]
    fn test_dkim_record_with_domain_value() {
        let record = "v=DKIM1; k=rsa; h=mail.sendgrid.net; s=selector; p=MIGfMA0";
        let result = extract_from_dkim_record(record, None, "example.com", record);
        assert!(
            result.is_some(),
            "DKIM h= with a domain-like value should extract"
        );
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain.contains("sendgrid")));
    }

    #[test]
    fn test_dmarc_logger_invalid_domain() {
        let logger = TestLogger::new();
        let record = "v=DMARC1; rua=mailto:report@x";
        let result = extract_from_dmarc_record(record, Some(&logger), "example.com", record);
        assert!(result.is_none());
        let failures = logger.failures.lock().unwrap();
        assert!(
            !failures.is_empty(),
            "Logger should capture invalid DMARC domain 'x'"
        );
        assert!(failures[0].contains("DMARC"));
    }

    #[test]
    fn test_verification_record_prefix_pattern() {
        let record = "verification-google=abc123";
        let result = extract_from_verification_record(record, None, "example.com", record);
        assert!(
            result.is_some(),
            "verification-google= should infer google.com"
        );
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "google.com"));
    }

    #[test]
    fn test_verification_record_site_pattern() {
        let record = "hubspot-site-verification=def456";
        let result = extract_from_verification_record(record, None, "example.com", record);
        assert!(
            result.is_some(),
            "hubspot-site-verification= should infer hubspot.com"
        );
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "hubspot.com"));
    }

    #[test]
    fn test_verification_record_provider_verify_pattern() {
        let record = "ZOOM_verify_xyz789";
        let result = extract_from_verification_record(record, None, "example.com", record);
        assert!(result.is_some(), "ZOOM_verify_ should infer zoom.us");
        let domains = result.unwrap();
        assert!(domains.iter().any(|d| d.domain == "zoom.us"));
    }

    #[test]
    fn test_verification_record_domain_equals_pattern() {
        let record = "atlassian-domain-verification=abc";
        let result = extract_from_verification_record(record, None, "example.com", record);
        assert!(
            result.is_some(),
            "atlassian-domain-verification should infer atlassian.com"
        );
    }

    #[tokio::test]
    #[cfg(coverage)]
    async fn test_try_system_dns_resolver_coverage_stub() {
        let result = try_system_dns_resolver("example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[cfg(coverage)]
    async fn test_get_cname_records_with_rate_limit_coverage_stub() {
        let pool = DnsServerPool::default();
        let result = get_cname_records_with_rate_limit("example.com", &pool, None, None).await;
        assert!(result.is_ok());
    }

    // ── DNS failure counter tracking (wiremock, no live DNS) ─────────

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_pool_tracked_no_failures() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("tracked.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "tracked.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);
        let result = get_txt_records_with_pool_tracked("tracked.com", &pool, &counter).await;
        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_rate_limit_counter_none() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("counter-none.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "counter-none.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let result = get_txt_records_with_rate_limit("counter-none.com", &pool, None, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_rate_limit_counter_some() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let response = build_doh_txt_response("counter-some.com", &["v=spf1 ~all"]);

        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "counter-some.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);
        let result =
            get_txt_records_with_rate_limit("counter-some.com", &pool, None, Some(&counter)).await;
        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    // ── GRC-367: throttle (429) must never masquerade as an empty answer ──────────

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_throttle_returns_error_not_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // DoH provider is throttling (HTTP 429) — must surface as an error, NOT Ok(empty).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = pool.next_doh_server().clone();
        let result = pool
            .doh_txt_lookup(
                "throttled.example",
                0,
                &doh_server,
                std::time::Duration::from_secs(5),
            )
            .await;
        assert!(
            result.is_err(),
            "a 429 throttle must surface as an error, never a silent Ok(empty)"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_THROTTLE"),
            "throttle error must be tagged DNS_THROTTLE so the caller can retry/rotate"
        );
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_resilient_rotates_past_throttle() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Provider 1 always throttles (429); provider 2 returns a valid TXT answer.
        let throttling = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&throttling)
            .await;

        let healthy = MockServer::start().await;
        let body = build_doh_txt_response(
            "rotated.example",
            &["v=spf1 include:mail.rotated.example ~all"],
        );
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&healthy)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", throttling.uri()),
            format!("{}/dns-query", healthy.uri()),
        ]);
        // First provider 429s; resilient lookup must back off and rotate to the healthy one.
        let result = pool.doh_txt_lookup_resilient("rotated.example").await;
        assert!(
            result.is_ok(),
            "resilient lookup must rotate past the 429 provider to a healthy one"
        );
        assert!(
            !result.unwrap().txt.is_empty(),
            "rotation to the healthy provider must return TXT records, not a false-negative empty"
        );
    }

    // ── GRC-367 (fix 2 + fix 6): CNAME throttle handling ──────────────────────────

    // doh_cname_lookup must surface a 429 throttle as a DNS_THROTTLE error (mirroring the
    // TXT path), never silently as Ok(empty) — that's the distinction the resilient layer
    // and the failure counter depend on.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_cname_lookup_throttle_429_returns_error_not_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = pool.next_doh_server().clone();
        let result = pool
            .doh_cname_lookup(
                "throttled.example",
                0,
                &doh_server,
                std::time::Duration::from_secs(5),
            )
            .await;
        assert!(
            result.is_err(),
            "a 429 CNAME throttle must surface as an error, never a silent Ok(empty)"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_THROTTLE"),
            "CNAME throttle error must be tagged DNS_THROTTLE so the caller can rotate/count"
        );
    }

    // Same contract for a provider 5xx (server error).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_cname_lookup_throttle_5xx_returns_error_not_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let doh_server = pool.next_doh_server().clone();
        let result = pool
            .doh_cname_lookup(
                "err5xx.example",
                0,
                &doh_server,
                std::time::Duration::from_secs(5),
            )
            .await;
        assert!(
            result.is_err(),
            "a 5xx CNAME response must surface as an error, never a silent Ok(empty)"
        );
        assert!(result.unwrap_err().to_string().contains("DNS_THROTTLE"));
    }

    // doh_cname_lookup_resilient must rotate past a throttling provider to a healthy one,
    // mirroring the TXT resilient path.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_cname_lookup_resilient_rotates_past_throttle() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let throttling = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&throttling)
            .await;

        let healthy = MockServer::start().await;
        let body = build_doh_cname_response("rotated.example", &["cdn.rotated.example"]);
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&healthy)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", throttling.uri()),
            format!("{}/dns-query", healthy.uri()),
        ]);
        let result = pool.doh_cname_lookup_resilient("rotated.example").await;
        assert!(
            result.is_ok(),
            "resilient CNAME lookup must rotate past the 429 provider"
        );
        let records = result.unwrap();
        assert_eq!(
            records,
            vec!["cdn.rotated.example".to_string()],
            "rotation must return the healthy provider's CNAME, not a false-negative empty"
        );
    }

    // get_cname_records_with_rate_limit must NOT return Ok(empty) "CNAME absent" on an
    // all-providers-throttle — it must record the failure via the counter (the core fix 2 bug).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_cname_records_with_rate_limit_throttle_counts_not_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Both providers 429 → throttle survives rotation.
        let p1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p1)
            .await;
        let p2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p2)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", p1.uri()),
            format!("{}/dns-query", p2.uri()),
        ]);
        let counter = AtomicUsize::new(0);
        let result =
            get_cname_records_with_rate_limit("throttled.example", &pool, None, Some(&counter))
                .await;
        // It still returns Ok(empty) so analysis continues, but the throttle is NOT silent.
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "an all-providers-throttle on the CNAME root path must increment the failure \
             counter, NOT be mistaken for a genuine 'CNAME absent' (Ok(empty)) result"
        );
    }

    // A GENUINE no-CNAME (provider answers 200 with an empty Answer) must map to Ok(empty)
    // WITHOUT touching the counter — "CNAME absence is normal".
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_cname_records_with_rate_limit_genuine_absence_no_count() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = build_doh_empty_response("no-cname.example");
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);
        let result =
            get_cname_records_with_rate_limit("no-cname.example", &pool, None, Some(&counter))
                .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "a genuine no-CNAME answer is normal and must NOT increment the failure counter"
        );
    }

    // GRC-367 (fix 2): a throttle that survives ALL DoH providers must (a) surface as a
    // DNS_THROTTLE error and (b) increment the pool's choke-point counter — verified WITHOUT
    // touching the system resolver. The previous version of this test drove the outer
    // `get_txt_records_with_rate_limit`, which on an all-throttle falls through to
    // `try_system_dns_resolver("throttled.invalid")` — a REAL network query that violated the
    // no-live-DNS invariant. We now drive `doh_txt_lookup_resilient` directly against a
    // wiremock 429, so the only DNS traffic is to the in-process mock and the choke-point count
    // is observed at its source.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_rate_limit_all_throttled_counts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let p1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p1)
            .await;
        let p2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p2)
            .await;

        let test_counter = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", p1.uri()),
            format!("{}/dns-query", p2.uri()),
        ])
        .with_failure_counter(std::sync::Arc::clone(&test_counter));

        // Drive the resilient DoH lookup directly: both providers 429, so the throttle survives
        // rotation and surfaces as a DNS_THROTTLE error. No DNS/system fallback is reached.
        let result = pool.doh_txt_lookup_resilient("throttled.invalid").await;
        assert!(
            result.is_err(),
            "an all-providers 429 must surface as an error"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("DNS_THROTTLE"),
            "the surfaced error must be a DNS_THROTTLE, got: {err}"
        );
        // Wave 1 (defect E): per-attempt throttles live in the per-provider tallies only — two
        // provider rotations must NOT read as two scan-level failures.
        assert_eq!(
            test_counter.load(Ordering::Relaxed),
            0,
            "provider attempts must not inflate the scan-level counter (4 rotations used to \
             count as 4 scan failures)"
        );
        // The LOGICAL lookup is counted exactly once, at its terminal, where the surviving
        // classified error settles into an empty result — this is what the exit-3 guard reads.
        let terminal = AtomicUsize::new(0);
        assert!(pool
            .settle_arm(Err(anyhow::anyhow!("{}", err)), &terminal)
            .is_empty());
        assert_eq!(
            terminal.load(Ordering::Relaxed),
            1,
            "a throttle defeating every DoH provider counts once — at the lookup's terminal — \
             so the exit-3 guard still sees it, without per-attempt inflation"
        );
    }

    // ── GRC-500: non-throttle endpoint failures (4xx / bad RCODE) must surface as ──
    // ── DNS_ENDPOINT, never a silent Ok(empty). These pin THE incident: 3 of 4    ──
    // ── default providers returned HTTP 400 (wrong /dns-query-vs-/resolve path)   ──
    // ── and were read as "0 TXT records", producing false-negative 0-vendor scans.──

    // THE incident regression: a 400 with a *valid JSON error body* (so it is NOT a
    // JSON-parse failure that could mask the bug) must (a) surface as a DNS_ENDPOINT
    // error — never Ok(empty) — and (b) increment the pool's choke-point counter.
    // Previously this exact case returned Ok(vec![]) and silently dropped every vendor.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_400_valid_json_body_returns_dns_endpoint_and_counts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // A 400 with a well-formed JSON body — if the guard relied on a parse failure it
        // would slip through; the status check must reject it BEFORE parsing.
        let error_body = serde_json::json!({
            "error": "Invalid request: this endpoint does not serve application/dns-json"
        });
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(error_body)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let test_counter = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())])
            .with_failure_counter(std::sync::Arc::clone(&test_counter));
        let doh_server = pool.next_doh_server().clone();
        let result = pool
            .doh_txt_lookup(
                "incident.example",
                0,
                &doh_server,
                std::time::Duration::from_secs(5),
            )
            .await;

        assert!(
            result.is_err(),
            "a 400 (wrong endpoint) must surface as an error, never the false-negative Ok(empty) \
             that dropped every vendor in the incident"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_ENDPOINT"),
            "a non-throttle 4xx must be tagged DNS_ENDPOINT so the resilient loop rotates without backoff"
        );
        // Wave 1 (defect E): the choke point attributes the 4xx to the provider's tally only;
        // the scan-level counter is owned by the lookup's terminal.
        assert_eq!(
            test_counter.load(Ordering::Relaxed),
            0,
            "a provider attempt must not bump the scan-level counter at the choke point"
        );
        let terminal = AtomicUsize::new(0);
        pool.settle_arm(
            Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider X returned HTTP 400 for incident.example"
            )),
            &terminal,
        );
        assert_eq!(
            terminal.load(Ordering::Relaxed),
            1,
            "a DNS_ENDPOINT arm that ends unresolved counts exactly once at its terminal, so \
             the exit-3 guard still sees the broken endpoint"
        );
    }

    // The CNAME path mirrors the TXT path: a 400 must surface as DNS_ENDPOINT, not Ok(empty).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_cname_lookup_400_returns_dns_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;

        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())])
            .with_failure_counter(counter.clone());
        let doh_server = pool.next_doh_server().clone();
        let result = pool
            .doh_cname_lookup(
                "incident.example",
                0,
                &doh_server,
                std::time::Duration::from_secs(5),
            )
            .await;

        assert!(
            result.is_err(),
            "a 400 on the CNAME path must surface as an error, never a silent Ok(empty)"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_ENDPOINT"),
            "a non-throttle 4xx on the CNAME path must be tagged DNS_ENDPOINT (mirrors the TXT path)"
        );
        // Wave 1 (defect E): per-provider tally at the choke; scan-level count at the terminal.
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a provider attempt must not bump the scan-level counter at the choke point"
        );
        let terminal = AtomicUsize::new(0);
        pool.settle_arm(
            Err(anyhow::anyhow!(
                "DNS_ENDPOINT: DoH provider X returned HTTP 400 for incident.example"
            )),
            &terminal,
        );
        assert_eq!(
            terminal.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the unresolved CNAME arm counts once at its terminal, like the TXT path"
        );
    }

    // dns-json `Status` (RCODE) 2 = SERVFAIL with no Answer is a resolver-side failure, NOT a
    // genuine "no records". It must surface as DNS_ENDPOINT and increment the counter — never
    // be parsed into an empty answer that reads as "this domain has no TXT records".
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_rcode_servfail_returns_dns_endpoint_and_counts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // HTTP 200 but DNS RCODE 2 (SERVFAIL), no Answer — the subtle case the status check
        // alone would miss; the RCODE gate must catch it.
        let body = serde_json::json!({
            "Status": 2,
            "Question": [{"name": "servfail.example", "type": 16}],
            "Answer": []
        });
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let test_counter = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())])
            .with_failure_counter(std::sync::Arc::clone(&test_counter));
        let doh_server = pool.next_doh_server().clone();
        let result = pool
            .doh_txt_lookup(
                "servfail.example",
                0,
                &doh_server,
                std::time::Duration::from_secs(5),
            )
            .await;

        assert!(
            result.is_err(),
            "RCODE 2 (SERVFAIL) is a resolver failure, not a genuine empty — must surface as an error"
        );
        assert!(
            result.unwrap_err().to_string().contains("DNS_NAME"),
            "a non-0/3 RCODE must be tagged DNS_NAME, NOT DNS_ENDPOINT: the provider ANSWERED over \
             a working transport, so this is a fact about the NAME. Classing it as an endpoint \
             fault let one pathological domain — which SERVFAILs identically on every provider — \
             satisfy the breaker's all-providers-failed test and demote healthy DoH onto UDP/53"
        );
        // Wave 1 (defect E): the RCODE is attributed to the provider tally at the choke; the
        // scan-level count (and its name attribution) belongs to the lookup's terminal.
        assert_eq!(
            test_counter.load(Ordering::Relaxed),
            0,
            "a provider attempt must not bump the scan-level counter at the choke point"
        );
    }

    // A SERVFAIL is a real DNS failure (so the exit-3 guard must still see it) but it is the
    // NAME's fault, not the link's. Both facts have to be recorded separately, or the summary
    // tells the user to "re-run on a stable network" for a domain whose own authoritative servers
    // are broken — advice that cannot work, since the same SERVFAIL comes back from every resolver
    // on every network (klaviyo.com's `buywithprime` delegation, 2026-07-31).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn servfail_counts_as_a_dns_failure_but_is_attributed_to_the_name_not_the_link() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "Status": 2,
                        "Question": [{"name": "servfail.example", "type": 16}],
                        "Answer": []
                    }))
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let all = std::sync::Arc::new(AtomicUsize::new(0));
        let by_name = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())])
            .with_failure_counter(std::sync::Arc::clone(&all))
            .with_name_failure_counter(std::sync::Arc::clone(&by_name));
        let doh_server = pool.next_doh_server().clone();
        let result = pool
            .doh_txt_lookup(
                "servfail.example",
                0,
                &doh_server,
                std::time::Duration::from_secs(5),
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // Wave 1 (defect E): nothing counts at the choke — a DNS_NAME verdict used to count
        // general+name at the choke AND again at settle, double-counting every broken name.
        assert_eq!(all.load(Ordering::Relaxed), 0);
        assert_eq!(by_name.load(Ordering::Relaxed), 0);
        // The terminal counts it once — general (the exit-3 guard must not stop seeing it) AND
        // name-attributed (what lets the summary stop blaming the user's network for the
        // target's broken delegation).
        let terminal = AtomicUsize::new(0);
        pool.settle_arm(Err(anyhow::anyhow!("{}", err)), &terminal);
        assert_eq!(
            terminal.load(Ordering::Relaxed),
            1,
            "a SERVFAIL is still a DNS failure — counted once, at the terminal"
        );
        assert_eq!(
            by_name.load(Ordering::Relaxed),
            1,
            "…and it must ALSO land in the name-attributed tally"
        );
    }

    // The choke points are not the only place a classified failure is counted: paths that receive a
    // failure as a propagated *error message* count it too. Those must keep the two tallies
    // consistent, because the summary derives transport failures by SUBTRACTION
    // (`transport = general - name`). A DNS_NAME error counted into the general tally alone shows up
    // as a degraded local link — silently undoing the attribution split for every name failure that
    // travels this route.
    #[test]
    fn a_propagated_name_failure_is_attributed_to_the_name_not_just_counted() {
        let pool_general = std::sync::Arc::new(AtomicUsize::new(0));
        let by_name = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec!["http://127.0.0.1:1/dns-query".to_string()])
            .with_failure_counter(std::sync::Arc::clone(&pool_general))
            .with_name_failure_counter(std::sync::Arc::clone(&by_name));

        // The caller on this path owns its own general counter and passes it in.
        let caller_counter = AtomicUsize::new(0);

        pool.note_classified_failure(
            "DNS_NAME: DoH provider X returned DNS RCODE 2 for broken.example",
            &caller_counter,
        );
        assert_eq!(caller_counter.load(Ordering::Relaxed), 1);
        assert_eq!(
            by_name.load(Ordering::Relaxed),
            1,
            "a propagated DNS_NAME failure must reach the name tally, or `general - name` reports \
             it as a degraded local link"
        );

        pool.note_classified_failure(
            "DNS_THROTTLE: provider X returned HTTP 429",
            &caller_counter,
        );
        assert_eq!(caller_counter.load(Ordering::Relaxed), 2);
        assert_eq!(
            by_name.load(Ordering::Relaxed),
            1,
            "a throttle is transport-side and must not be attributed to the name"
        );

        // Wave 1: an UNCLASSIFIED error arm is still a lookup the scan lost — under logical
        // counting it counts in the general tally (it used to be counted per-attempt at the
        // choke instead), but never in the name tally.
        pool.note_classified_failure("some unrelated error", &caller_counter);
        assert_eq!(caller_counter.load(Ordering::Relaxed), 3);
        assert_eq!(by_name.load(Ordering::Relaxed), 1);

        // The subtraction the summary performs must never claim a transport failure that did not
        // happen: one name failure, one throttle, one unclassified — exactly two transport-side.
        assert_eq!(
            caller_counter.load(Ordering::Relaxed) - by_name.load(Ordering::Relaxed),
            2
        );
    }

    // The mirror image: a transport failure must NOT be attributed to the name, or the summary
    // would excuse a genuinely degraded link as somebody else's DNS problem.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn a_throttled_provider_is_never_attributed_to_the_name() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let all = std::sync::Arc::new(AtomicUsize::new(0));
        let by_name = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())])
            .with_failure_counter(std::sync::Arc::clone(&all))
            .with_name_failure_counter(std::sync::Arc::clone(&by_name));
        let doh_server = pool.next_doh_server().clone();
        let result = pool
            .doh_txt_lookup(
                "throttled.example",
                0,
                &doh_server,
                std::time::Duration::from_secs(5),
            )
            .await;

        assert!(result.is_err());
        // Wave 1 (defect E): the 429 lands in the provider tally, not the scan-level counter —
        // the logical lookup counts at its terminal instead.
        assert_eq!(all.load(Ordering::Relaxed), 0);
        assert_eq!(
            by_name.load(Ordering::Relaxed),
            0,
            "a throttled provider says nothing about the queried name — attributing it there would \
             suppress the one warning whose remedy (retry elsewhere) actually works"
        );
    }

    // RCODE 3 = NXDOMAIN with no Answer is a GENUINE absence (the domain truly has no records).
    // It must map to Ok(vec![]) WITHOUT touching the counter — the boundary case that proves the
    // RCODE gate distinguishes "resolver failed" (count) from "genuinely absent" (don't count).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_rcode_nxdomain_returns_ok_empty_no_count() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // HTTP 200, RCODE 3 (NXDOMAIN), no Answer — a real "this domain has no TXT records".
        let body = serde_json::json!({
            "Status": 3,
            "Question": [{"name": "nxdomain.example", "type": 16}],
            "Answer": []
        });
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let test_counter = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())])
            .with_failure_counter(std::sync::Arc::clone(&test_counter));
        let doh_server = pool.next_doh_server().clone();
        let records = pool
            .doh_txt_lookup(
                "nxdomain.example",
                0,
                &doh_server,
                std::time::Duration::from_secs(5),
            )
            .await
            .expect("NXDOMAIN (RCODE 3) is a genuine absence and must be Ok, not an error")
            .txt;

        assert!(
            records.is_empty(),
            "NXDOMAIN must return an empty record set"
        );
        assert_eq!(
            test_counter.load(Ordering::Relaxed),
            0,
            "a genuine NXDOMAIN absence must NOT increment the failure counter"
        );
    }

    // The resilient loop must rotate to the next provider on a DNS_ENDPOINT failure (the
    // incident scenario: one provider 400s, the next serves real records). This pins the
    // "rotate immediately, no backoff" behavior for the DNS_ENDPOINT class specifically.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_txt_lookup_resilient_rotates_past_400_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Provider 1 always 400s (DNS_ENDPOINT); provider 2 serves a valid TXT answer.
        let broken = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&broken)
            .await;

        let healthy = MockServer::start().await;
        let body = build_doh_txt_response(
            "rotated.example",
            &["v=spf1 include:mail.rotated.example ~all"],
        );
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&healthy)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", broken.uri()),
            format!("{}/dns-query", healthy.uri()),
        ]);
        let result = pool.doh_txt_lookup_resilient("rotated.example").await;
        assert!(
            result.is_ok(),
            "resilient lookup must rotate past the 400 (DNS_ENDPOINT) provider to a healthy one"
        );
        let records = result.unwrap().txt;
        assert_eq!(
            records.len(),
            1,
            "rotation must return the healthy provider's TXT records, not a false-negative empty"
        );
        assert!(
            records[0].contains("spf1"),
            "the rotated-to record must be the healthy provider's real answer"
        );
    }

    // get_txt_records_with_pool on a single DoH server answering 200 / RCODE 0 / no Answer
    // must treat the authoritative empty as FINAL: Ok(vec![]) with no system-resolver
    // fallthrough (the recordless subdomain skips the extra UDP/system lookup entirely).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_get_txt_records_with_pool_authoritative_empty_is_final() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 200, Status 0 (NOERROR), empty Answer — an authoritative "no TXT records".
        let body = build_doh_empty_response("authoritative-empty.example");
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "authoritative-empty.example"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let records = get_txt_records_with_pool("authoritative-empty.example", &pool)
            .await
            .expect("an authoritative empty (2xx / RCODE 0 / no Answer) must be Ok, not an error");

        assert!(
            records.is_empty(),
            "an authoritative empty answer is final and must return Ok(vec![]) — no records, \
             and (the DoH future resolving first) no system-resolver fallthrough"
        );
        // Prove the mock actually served this lookup: the total-failure fallback
        // path also yields Ok(vec![]), so without this assertion the test passes
        // even when the mock is never reached (demonstrated under a MITM proxy).
        let hits = server
            .received_requests()
            .await
            .expect("wiremock request recording enabled");
        assert!(
            !hits.is_empty(),
            "the DoH mock must have served the lookup — otherwise this exercised the \
             total-failure fallback, not the authoritative-empty short-circuit"
        );
    }

    // Config validation accepts "at least one DoH OR DNS server", so single-kind
    // pools are legal — the rotation helpers index with `% len` and previously
    // panicked (div-by-zero) on the empty side. These pin the no-panic guarantee.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_doh_only_pool_no_dns_servers_does_not_panic() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = build_doh_txt_response("doh-only.example", &["v=spf1 include:vendor.test ~all"]);
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "doh-only.example"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("content-type", "application/dns-json"),
            )
            .mount(&server)
            .await;

        let mut pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        pool.dns_servers.clear(); // legal DoH-only configuration

        let records = get_txt_records_with_pool("doh-only.example", &pool)
            .await
            .expect("a DoH-only pool must resolve without touching the (empty) DNS pool");
        assert_eq!(records.len(), 1, "the DoH answer must come through intact");
        assert!(records[0].contains("spf1"));
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn test_dns_only_pool_no_doh_servers_does_not_panic() {
        // DNS-only configuration: empty DoH pool, only the (unreachable) test
        // DNS fallback. The lookup must complete without panicking — result
        // content is environment-dependent (system resolver final fallback),
        // so the assertion is the absence of a panic plus a well-formed Ok.
        let mut pool = DnsServerPool::with_test_urls(vec!["http://127.0.0.1:1/dns-query".into()]);
        pool.doh_servers.clear(); // legal DNS-only configuration

        let result = get_txt_records_with_pool("dns-only-nonexistent.invalid", &pool).await;
        assert!(
            result.is_ok(),
            "an empty DoH pool must degrade gracefully, never index-panic: {result:?}"
        );
    }

    // ── Answer memo (scan-lifetime DNS deduplication) ────────────────────────────
    //
    // The memo's whole safety story is *what it refuses to remember*. A resolver's answer —
    // including an authoritative "no records" — is a fact about the zone and may be reused.
    // An empty vector produced because every resolution path failed is not; caching it would
    // convert one transient outage into a scan-wide false negative and would suppress the
    // `dns_failure_counter` increments that the exit-3 guard reads (GRC-367).

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn memo_serves_repeat_txt_query_without_a_second_request() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // `expect(1)` is the assertion: a second outbound request fails the test on drop.
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "memo.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(build_doh_txt_response("memo.com", &["v=spf1 -all"]))
                    .insert_header("content-type", "application/dns-json"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);

        let first = get_txt_records_with_rate_limit("memo.com", &pool, None, None)
            .await
            .expect("first lookup succeeds");
        let second = get_txt_records_with_rate_limit("memo.com", &pool, None, None)
            .await
            .expect("second lookup served from memo");

        assert_eq!(
            first, second,
            "memo must return the recorded answer verbatim"
        );
        assert_eq!(first.len(), 1);
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn memo_remembers_authoritative_empty_txt_answer() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // RCODE 0 with no Answer section: the name exists and genuinely has no TXT records.
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "norecords.com"))
            .and(query_param("type", "TXT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(build_doh_empty_response("norecords.com"))
                    .insert_header("content-type", "application/dns-json"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);

        let first = get_txt_records_with_rate_limit("norecords.com", &pool, None, None)
            .await
            .expect("authoritative empty is a successful lookup");
        assert!(first.is_empty());

        let second = get_txt_records_with_rate_limit("norecords.com", &pool, None, None)
            .await
            .expect("second lookup served from memo");
        assert!(second.is_empty(), "authoritative empty is reusable");
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn memo_never_caches_an_empty_result_produced_by_total_dns_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Every DoH attempt is a hard endpoint error, and the traditional/system resolvers
        // cannot answer this reserved-for-testing name either. The lookup therefore degrades
        // to `Ok(vec![])` while incrementing the failure counter.
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())]);
        let counter = AtomicUsize::new(0);

        let first =
            get_txt_records_with_rate_limit("invalid.invalid", &pool, None, Some(&counter)).await;
        let second =
            get_txt_records_with_rate_limit("invalid.invalid", &pool, None, Some(&counter)).await;

        assert!(
            first.is_ok() && second.is_ok(),
            "failures degrade, never panic"
        );
        assert!(first.unwrap().is_empty() && second.unwrap().is_empty());

        // The load-bearing assertion: the second call re-attempted resolution and re-counted
        // the failure. Had the degraded empty been memoized, this counter would read 1 and the
        // exit-3 guard would under-report DNS failures for every later lookup of this name.
        assert_eq!(
            counter.load(Ordering::Relaxed),
            2,
            "a failure-produced empty must not be memoized: each attempt must re-count"
        );
    }

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn memo_keys_on_record_kind_so_txt_and_cname_do_not_collide() {
        let pool = DnsServerPool::with_test_urls(vec![]);

        pool.remember_answer(RecordKind::Txt, "collide.com", &["txt-answer".to_string()])
            .await;

        assert!(
            matches!(
                pool.recall_memo(RecordKind::Txt, "collide.com").await,
                Some(MemoEntry::Answer(ref records)) if records == &["txt-answer".to_string()]
            ),
            "the TXT answer must come back verbatim under its own kind"
        );
        assert!(
            pool.recall_memo(RecordKind::Cname, "collide.com")
                .await
                .is_none(),
            "a TXT answer must never satisfy a CNAME query"
        );
    }

    // ── Wave-1 falsifiers (defects A, B, E, F — Plans/zesty-tinkering-falcon.md §Phase 2) ──

    /// Defect A: one slow provider must never consume the whole lookup budget. Provider 1 hangs
    /// past its per-attempt slice; the deadline-owned rotation must reach provider 2 and answer
    /// INSIDE the 3 s deadline. Red on the old code, where the outer 3 s wrapper equalled the
    /// per-attempt 3 s and fired while attempt 0 was still in flight (7,032 of 7,988 measured
    /// cancellations).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn a_provider_rotation_completes_inside_the_outer_lookup_budget() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let slow = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"Status": 0, "Answer": [
                        {"name": "slowfast.example", "type": 16, "data": "\"slow-answer\""}
                    ]}))
                    .set_delay(std::time::Duration::from_millis(2500)),
            )
            .mount(&slow)
            .await;
        let fast = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Status": 0,
                "Answer": [{"name": "slowfast.example", "type": 16, "data": "\"fast-answer\""}]
            })))
            .mount(&fast)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", slow.uri()),
            format!("{}/dns-query", fast.uri()),
        ]);
        // Warm the RTO the way a running scan does: the budget slicer only cuts an in-flight
        // attempt short once the network's real RTT is known (see `attempt_budget`'s cold-start
        // contract, and the cold-start falsifier below).
        for _ in 0..12 {
            pool.governor()
                .record_rtt(std::time::Duration::from_millis(50));
        }
        let t0 = std::time::Instant::now();
        let result = pool.doh_txt_lookup_resilient("slowfast.example").await;
        let elapsed = t0.elapsed();

        let answer = result.expect("rotation must reach the healthy provider");
        assert_eq!(answer.txt, vec!["fast-answer".to_string()]);
        assert!(
            elapsed < DOH_LOOKUP_DEADLINE,
            "rotation took {elapsed:?} — the deadline-owned loop must complete inside {:?}",
            DOH_LOOKUP_DEADLINE
        );
    }

    /// Defect B, timeout-evidence half: attempt-budget timeouts at a HEALTHY governor limit must
    /// never demote DoH, however many burst at once. Red on the pre-fix Wave-1 code: the r2
    /// validation A/B measured 10 false DoH demotions, every one a timeout burst at 64 in-flight
    /// with zero connect errors.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn attempt_budget_timeouts_at_a_healthy_limit_never_demote_doh() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Two providers that both answer far slower than the warmed attempt budget.
        let mut urls = Vec::new();
        let mut farms = Vec::new();
        for _ in 0..2 {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/dns-query"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"Status": 0, "Answer": []}))
                        // Comfortably above every possible attempt budget (the widest is the
                        // final attempt's full remaining ~2 s), so no attempt can flakily land.
                        .set_delay(std::time::Duration::from_millis(3500)),
                )
                .mount(&server)
                .await;
            urls.push(format!("{}/dns-query", server.uri()));
            farms.push(server);
        }
        let pool = DnsServerPool::with_test_urls(urls);
        // Warm the RTO with fast samples so every attempt budget is the 1 s floor — well under
        // the providers' 2 s answers, guaranteeing DNS_TIMEOUT on every attempt.
        for _ in 0..12 {
            pool.governor()
                .record_rtt(std::time::Duration::from_millis(50));
        }
        // 8 rounds x 2 attempts = 16 consecutive timeout-failures across both providers —
        // double the streak threshold, with the full implication mask covered.
        for _ in 0..TRANSPORT_DOWN_THRESHOLD {
            let result = pool.doh_txt_lookup_resilient("slowpool.example").await;
            let err = result.expect_err("3.5 s answers against <=2 s budgets must fail");
            assert!(err.to_string().contains("DNS_TIMEOUT"), "got: {err}");
        }
        let snap = pool.transport_snapshot();
        assert_eq!(
            snap.doh.down_transitions, 0,
            "timeout evidence at a healthy limit must never demote the transport"
        );

        // The counter-falsifier: the SAME silence once the governor has retreated to its floor
        // IS breaker-relevant — the network was given every concession and still does not answer.
        let floor_pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", farms[0].uri()),
            format!("{}/dns-query", farms[1].uri()),
        ])
        .with_governor(crate::dns_governor::DnsGovernor::new(
            crate::dns_governor::MIN_LIMIT,
        ));
        for _ in 0..12 {
            floor_pool
                .governor()
                .record_rtt(std::time::Duration::from_millis(50));
        }
        for _ in 0..(TRANSPORT_DOWN_THRESHOLD - 2) {
            let _ = floor_pool
                .doh_txt_lookup_resilient("floorpool.example")
                .await;
        }
        let snap = floor_pool.transport_snapshot();
        assert!(
            snap.doh.down_transitions >= 1,
            "sustained silence at the governor floor must still trip the breaker"
        );
    }

    /// The cold-start half of the budget contract (contention-gate P1's unit twin): before ANY
    /// RTT evidence exists, an attempt must get the full remaining deadline — slicing it to
    /// deadline/attempts locks a slow-but-healthy network out permanently, because no attempt
    /// ever completes to seed the RTO that would widen the budget.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn a_slow_but_healthy_network_is_not_locked_out_before_its_rtt_is_learned() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"Status": 0, "Answer": [
                        {"name": "slowok.example", "type": 16, "data": "\"slow-but-real\""}
                    ]}))
                    // Slower than deadline/attempts would allow, well inside the deadline.
                    .set_delay(std::time::Duration::from_millis(1200)),
            )
            .mount(&server)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", server.uri()),
            format!("{}/dns-query", server.uri()),
            format!("{}/dns-query", server.uri()),
            format!("{}/dns-query", server.uri()),
        ]);
        let result = pool.doh_txt_lookup_resilient("slowok.example").await;
        let answer = result.expect(
            "a fresh pool must not cancel a 1.2s answer: cold-start budgets are the full deadline",
        );
        assert_eq!(answer.txt, vec!["slow-but-real".to_string()]);
    }

    /// Defect A's constant relation: the outer guard is a hang backstop, so it must sit far above
    /// the deadline the loop owns — never equal to it (the old code's exact bug).
    #[test]
    fn the_outer_backstop_is_strictly_larger_than_the_rotation_deadline() {
        assert!(
            DOH_WRAPPER_BACKSTOP >= DOH_LOOKUP_DEADLINE.saturating_mul(2),
            "the backstop ({DOH_WRAPPER_BACKSTOP:?}) must be a multiple of the deadline \
             ({DOH_LOOKUP_DEADLINE:?}), or it cancels in-flight rotations again"
        );
    }

    /// Defect F: an attempt that exceeds its budget is classified DNS_TIMEOUT — typed at the
    /// source from `reqwest::Error::is_timeout()` — and costs the scan-level counter nothing at
    /// the choke point. Red on the old code, whose reqwest Display ("error sending request…")
    /// carried no "timeout" substring for the classifier to find.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn a_timed_out_attempt_is_classified_dns_timeout_and_not_counted_at_the_choke() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"Status": 0, "Answer": []}))
                    .set_delay(std::time::Duration::from_millis(1500)),
            )
            .mount(&server)
            .await;

        let counter = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![format!("{}/dns-query", server.uri())])
            .with_failure_counter(std::sync::Arc::clone(&counter));
        let doh_server = pool.next_doh_server().clone();
        let result = pool
            .doh_txt_lookup(
                "hang.example",
                0,
                &doh_server,
                std::time::Duration::from_millis(80),
            )
            .await;

        let err = result.expect_err("an 80ms budget against a 1500ms server must time out");
        assert!(
            err.to_string().contains("DNS_TIMEOUT"),
            "the class must travel in the message, typed at the source: {err}"
        );
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "a per-attempt timeout is a provider-tally fact, not a scan-level failure"
        );
    }

    /// Defect F, classifier side: DNS_TIMEOUT reads as TimedOut to the governor — and a queried
    /// NAME containing the word "timeout" no longer reads as congestion.
    #[test]
    fn timed_out_is_reported_to_the_governor_as_timed_out_not_rejected() {
        use crate::dns_governor::DnsOutcome;
        let timed: std::result::Result<(), String> = Err(
            "DNS_TIMEOUT: DoH provider X exceeded its 400ms attempt budget for a.example"
                .to_string(),
        );
        let ok: std::result::Result<(), String> = Ok(());
        assert_eq!(classify_pair(&timed, &timed), DnsOutcome::TimedOut);
        assert_eq!(classify_pair(&ok, &timed), DnsOutcome::Answered);

        // A name that merely CONTAINS "timeout" is not congestion evidence (the old substring
        // match read `timeout.example.com`'s unrelated failure as a rejection).
        let name_shaped: std::result::Result<(), String> =
            Err("no DoH servers configured for TXT lookup of connect-timeout.example".to_string());
        assert_eq!(
            classify_pair(&name_shaped, &name_shaped),
            DnsOutcome::Unrelated
        );
    }

    /// Defect B (Wave-1 half): an all-provider 429 burst is positive transport evidence — the
    /// providers ANSWERED — so it must clear the breaker streak, never advance it. Phase 1
    /// measured a 2 s all-429 burst demoting DoH for 30 s (contention-gate profile P4).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn an_all_provider_throttle_burst_does_not_demote_doh() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let p1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p1)
            .await;
        let p2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p2)
            .await;

        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", p1.uri()),
            format!("{}/dns-query", p2.uri()),
        ]);
        // Far more rounds than TRANSPORT_DOWN_THRESHOLD, across every provider.
        for _ in 0..(TRANSPORT_DOWN_THRESHOLD * 3) {
            let _ = pool.doh_txt_lookup_resilient("burst.example").await;
        }
        let snap = pool.transport_snapshot();
        assert_eq!(
            snap.doh.down_transitions, 0,
            "a throttle burst must never demote the transport that is demonstrably delivering"
        );
        assert!(!snap.doh.is_down);
    }

    /// Defect E, the invariant the 08-19 screenshot violated (66,988 failures > 57,286 queries):
    /// with logical counting, N unresolved lookup arms count exactly N — one per arm, however
    /// many provider rotations each burned.
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn dns_failures_counts_logical_arms_not_provider_attempts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let p1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p1)
            .await;
        let p2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&p2)
            .await;

        let counter = AtomicUsize::new(0);
        let pool = DnsServerPool::with_test_urls(vec![
            format!("{}/dns-query", p1.uri()),
            format!("{}/dns-query", p2.uri()),
        ]);
        const DOMAINS: usize = 3;
        for i in 0..DOMAINS {
            // Mid-label underscore keeps every name structurally outside the hickory/system
            // paths, so the test stays hermetic (same trick as the contention gate).
            let name = format!("all_throttled{i}.example");
            let (txt, cname) = pool.get_txt_and_cname_fast(&name, &counter).await;
            assert!(txt.is_empty() && cname.is_empty());
        }
        // TXT and CNAME arms each ended unresolved: exactly 2 counts per domain — never
        // 2 × attempts (the old per-attempt counting would have read ≥ 4 per domain here).
        assert_eq!(
            counter.load(Ordering::Relaxed),
            DOMAINS * 2,
            "dns_failures must count logical arms, not provider attempts"
        );
    }

    /// Defect E: a negative-memo hit on the root path counts exactly ONE dns failure — through
    /// the SAME atomic production wires for both the pool counter and the explicit counter (the
    /// double-increment this test pins was live at dns.rs:2526-2528 until Wave 1).
    #[tokio::test]
    #[cfg(not(coverage))]
    async fn a_negative_memo_hit_counts_exactly_one_dns_failure_on_the_root_path() {
        let shared = std::sync::Arc::new(AtomicUsize::new(0));
        let by_name = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = DnsServerPool::with_test_urls(vec![])
            .with_failure_counter(std::sync::Arc::clone(&shared))
            .with_name_failure_counter(std::sync::Arc::clone(&by_name));
        pool.remember_name_failure(
            RecordKind::Txt,
            "broken.example",
            "DNS_NAME: DoH provider X returned DNS RCODE 2 for broken.example",
        )
        .await;

        // Production shape: the explicit counter IS the pool-wired atomic (app.rs wires both to
        // the logger's counter).
        let result =
            get_txt_records_with_rate_limit("broken.example", &pool, None, Some(shared.as_ref()))
                .await;
        assert!(result.expect("memo hit degrades to empty").is_empty());
        assert_eq!(
            shared.load(Ordering::Relaxed),
            1,
            "one negative-memo hit is ONE logical name failure — the old code counted it twice \
             (name + an extra transport-side increment)"
        );
        assert_eq!(by_name.load(Ordering::Relaxed), 1);
    }
}
