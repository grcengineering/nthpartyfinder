//! Shared construction of connection-hardened `reqwest` clients.
//!
//! Every subsystem builds its own HTTP client, and historically none of them bounded connection
//! establishment or the idle-connection pool — only the total per-request timeout was set. That
//! is the wrong bound for the failure mode that took down local WiFi during deep scans:
//!
//! * A consumer router tracks every flow — including half-open and timed-out ones — in a
//!   NAT/conntrack table of only a few thousand entries. Under a large fan-out, an untuned client
//!   opens a fresh TCP+TLS handshake per attempt with no cap on how long a *stalled* handshake may
//!   sit before it is abandoned, so each failed connection lingers as a conntrack entry for the
//!   full request timeout (or the OS default, tens of seconds). Enough of them fills the table and
//!   every device on the LAN loses connectivity.
//! * `connect_timeout` bounds exactly that: a handshake that has not completed quickly is dropped,
//!   so a saturated network sheds abandoned flows fast instead of accumulating them.
//! * `pool_idle_timeout` + `pool_max_idle_per_host` bound the keep-alive sockets left idle after a
//!   request, so they return to the OS promptly instead of pinning conntrack slots.
//!
//! This is the code-level complement to `app::raise_open_file_limit`'s own hard OS ceiling on open
//! file descriptors: these bounds keep the steady-state socket footprint far under that ceiling on
//! every code path, no external wrapper script required — all scan safety is binary-native.

use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// What this scanner calls itself on every outbound HTTP request.
///
/// It identifies the tool and its version and links somewhere a site operator can read what it
/// does. That is the honest thing for a scanner to send — and, unexpectedly, also the thing that
/// *works*: impersonating a browser is what got requests blocked.
///
/// Three clients used to send a hardcoded `Chrome/120.0.0.0` string, commented "Realistic browser
/// user agent". A pinned browser version is only realistic on the day it is written. Chrome 120
/// shipped in 2023, no real user runs it now, and bot-management services score an outdated browser
/// claim as an automation signal. Measured 2026-07-31: `trust.drata.com/subprocessors` returns
/// **403 with `cf-mitigated: challenge`** for `Chrome/120` and for `Chrome/131`, and **200** for
/// both a current Chrome string and this one. Across twelve real trust-centre and subprocessor
/// URLs plus seven SaaS-tenant probes, this UA was never worse than the browser strings and was
/// the only one that got Drata's list at all.
///
/// Deriving the version from `CARGO_PKG_VERSION` is the point: there is no browser version here to
/// go stale, so this cannot rot back into a bot signature the way the string it replaces did.
pub const USER_AGENT: &str = concat!(
    "nthpartyfinder/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/grcengineering/nthpartyfinder)"
);

const _: () = {
    // Guard the property that actually matters, so a future edit cannot quietly reintroduce the
    // failure: no claim to be a browser. `konst`-free byte scan because this runs at compile time.
    const fn contains(haystack: &str, needle: &str) -> bool {
        let (h, n) = (haystack.as_bytes(), needle.as_bytes());
        if n.len() > h.len() {
            return false;
        }
        let mut i = 0;
        while i <= h.len() - n.len() {
            let mut j = 0;
            while j < n.len() && h[i + j] == n[j] {
                j += 1;
            }
            if j == n.len() {
                return true;
            }
            i += 1;
        }
        false
    }
    assert!(
        !contains(USER_AGENT, "Mozilla") && !contains(USER_AGENT, "Chrome"),
        "the user agent must not impersonate a browser: a pinned browser version rots into an \
         automation signal (Chrome/120 => HTTP 403 cf-mitigated:challenge on real trust centres)"
    );
    assert!(
        contains(USER_AGENT, "nthpartyfinder/"),
        "the user agent must identify this tool so site operators can attribute the traffic"
    );
};

/// Abandon a TCP+TLS handshake that has not completed within this long.
///
/// Short enough that a stalled handshake on a saturated network is shed before it lingers in the
/// router's conntrack table, long enough for a real handshake to a slow-but-live host to succeed.
pub const CONNECT_TIMEOUT_SECS: u64 = 5;

/// Evict a keep-alive socket left idle for this long, returning it to the OS.
///
/// Well under reqwest's 90s default so idle sockets do not pin conntrack entries between the
/// bursts of a fan-out.
pub const POOL_IDLE_TIMEOUT_SECS: u64 = 15;

/// Keep at most this many idle keep-alive sockets per host — **zero: no idle pooling**.
///
/// This is the load-bearing half of the socket ceiling, and a hard-won correction. The
/// `CONNECTION_SEMAPHORE` bounds only *in-flight* sends, but the quantity that exhausts a router's
/// NAT/conntrack table is the peak count of *simultaneously-open* sockets — in-flight **plus** idle
/// keep-alive sockets, which stay in the ESTABLISHED state (holding a conntrack entry) for
/// `POOL_IDLE_TIMEOUT_SECS` after their request completes. A guarded depth-3 measurement showed the
/// idle pool, not in-flight sends, is the dominant term: at a ceiling of 16 in-flight, the process
/// held ~670 ESTABLISHED sockets spread across ~250 one-off vendor/CT/SaaS hosts (each contributing
/// up to `4` idle sockets across the ~8 discovery clients), and the count grew unbounded with the
/// number of distinct hosts a deep scan discovers.
///
/// Setting this to 0 disables idle pooling: a connection closes as soon as its request finishes, so
/// a socket no longer lingers in ESTABLISHED for `POOL_IDLE_TIMEOUT_SECS` after its response, and the
/// process's open-socket count collapses toward the in-flight count that the semaphore bounds — no
/// longer growing with the number of distinct hosts the scan touches. (It is not a strict ≤-ceiling
/// bound: reqwest's `.send()` resolves at response *headers*, so the semaphore permit is released
/// while the response *body* is still downloading; that socket stays ESTABLISHED, outside the permit,
/// until the body drains. Bodies here are small JSON/HTML read immediately, so the residual is a
/// short close-lag tail, not an unbounded pool — a guarded depth-3 run held in the low hundreds and
/// plateaued rather than the pre-fix thousands.) The price is HTTP keep-alive reuse (mainly
/// re-handshaking the DoH resolvers); acceptable because network safety is the floor and DNS is not
/// the scan's critical path. A short idle timeout would only bound the footprint by rate; 0 removes
/// the host-count-scaled idle pool entirely, which is what the conntrack failure mode needed.
pub const POOL_MAX_IDLE_PER_HOST: usize = 0;

/// Idle keep-alive sockets per host for the **DoH resolver client only**.
///
/// `POOL_MAX_IDLE_PER_HOST = 0` is correct for the discovery clients and wrong for DoH, and the
/// distinction is the *host count*, which is exactly what that const's own measurement identified
/// as the problem: "~670 ESTABLISHED sockets spread across **~250 one-off vendor/CT/SaaS hosts**
/// … the count grew unbounded with the number of distinct hosts a deep scan discovers". Discovery
/// visits an unbounded, ever-growing set of hosts, so a per-host idle pool scales with the scan.
/// DoH visits a **fixed, tiny, configured set** — 6 endpoints — so its idle pool has a hard
/// ceiling of `6 × 2 = 12` sockets no matter how deep the scan goes. That is ~9% of the 128
/// in-flight ceiling and 0.02% of the 65,536-entry conntrack table measured on the reference
/// router. It cannot grow, so it cannot reproduce the failure mode the zero was chosen for.
///
/// Why it must be nonzero (2026-07-29 incident): with no pooling, **every single DoH query pays a
/// fresh TCP+TLS handshake** — the price the const's doc comment names and accepts ("mainly
/// re-handshaking the DoH resolvers"). Under a depth-3 fan-out that becomes a handshake storm:
/// handshakes miss `CONNECT_TIMEOUT_SECS`, `TRANSPORT_DOWN_THRESHOLD` consecutive misses mark DoH
/// "blocked", and the ladder demotes the whole scan onto DoT and then raw UDP/53. Sustained
/// plain-port DNS then got the WAN IP throttled upstream for ~2h08m, taking every non-443 DNS
/// transport on the LAN down with it — including the router's own encrypted upstream on :8443 —
/// while 443 kept answering in 35ms throughout. The measured router conntrack peak during that
/// scan was **1,089 / 65,536 with zero drops**, so the conntrack pressure the zero defends against
/// was never remotely in play, while the handshake cost it imposed started the outage.
///
/// In short: the zero traded a real, measured cost (DoH handshake amplification) for protection
/// against a cost that was measured at 1.7% of capacity. For DoH, and only for DoH, that trade is
/// inverted here. Keep it small — this is connection *reuse*, not a connection *cache*.
pub const DOH_POOL_MAX_IDLE_PER_HOST: usize = 2;

/// Build-time guard on the DoH pool. A compile error rather than a test failure, because both
/// directions are load-bearing and neither should be able to drift in unnoticed: dropping it to 0
/// restores the handshake-per-query behaviour that started the 2026-07-29 outage, and raising it
/// turns connection *reuse* into a connection *cache* whose footprint scales with the endpoint list.
const _: () = {
    assert!(
        DOH_POOL_MAX_IDLE_PER_HOST >= 1,
        "DoH keep-alive must stay enabled: at 0, every DoH query pays a fresh TCP+TLS handshake"
    );
    // The safety case is that `endpoints x pool` stays negligible against the in-flight ceiling.
    // Assert that product against a generous endpoint count rather than the pool size alone.
    assert!(
        8 * DOH_POOL_MAX_IDLE_PER_HOST < DEFAULT_MAX_CONNECTIONS / 4,
        "worst-case DoH idle footprint must stay far under the in-flight connection ceiling"
    );
};

/// A `reqwest::ClientBuilder` pre-configured with the connection bounds above.
///
/// Callers chain their own `.timeout(..)`, `.user_agent(..)`, etc. and then `.build()`. Use this
/// in place of `reqwest::Client::builder()` at every subsystem's client-construction site so the
/// connection footprint is bounded uniformly, no matter which discovery path is running.
pub fn hardened_builder() -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .pool_idle_timeout(Duration::from_secs(POOL_IDLE_TIMEOUT_SECS))
        .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST);
    // Wave 3 (6b): once app startup installs the governed resolver, every discovery client
    // resolves through the memoized, permit-bounded DoH path with getaddrinfo kept only as a
    // counted transport-failure fallback. Before installation (library callers, tests, auxiliary
    // commands) the CountingResolver preserves today's behaviour exactly while closing the
    // Phase-0 observation gap (`http.getaddrinfo` read 0 because this was never wired).
    // Never applied to `doh_builder` — its endpoints are IP literals, and resolving DoH via DoH
    // would be circular.
    #[cfg(not(coverage))]
    {
        match GOVERNED_RESOLVER.get() {
            Some(resolver) => builder.dns_resolver(std::sync::Arc::clone(resolver)),
            None => builder.dns_resolver(std::sync::Arc::new(CountingResolver)),
        }
    }
    #[cfg(coverage)]
    builder
}

/// The process-wide governed DNS resolver, installed once at app startup after the DNS pool is
/// constructed (Wave 3, 6b). Clients built BEFORE installation keep the counting system resolver.
#[cfg(not(coverage))]
static GOVERNED_RESOLVER: OnceLock<std::sync::Arc<crate::dns::GovernedResolver>> = OnceLock::new();

/// Install the governed resolver for every subsequently-built discovery client. First call wins;
/// later calls are ignored (mirrors `init_connection_ceiling`).
#[cfg(not(coverage))]
pub fn install_governed_resolver(resolver: std::sync::Arc<crate::dns::GovernedResolver>) {
    let _ = GOVERNED_RESOLVER.set(resolver);
}

/// Like [`hardened_builder`], but with keep-alive reuse enabled for the fixed DoH endpoint set.
///
/// Use this **only** for clients whose destination hosts are a small bounded list known at
/// construction time. Using it for a discovery client — whose host set grows with what the scan
/// finds — re-opens the unbounded idle-pool growth that [`POOL_MAX_IDLE_PER_HOST`] exists to
/// prevent. See [`DOH_POOL_MAX_IDLE_PER_HOST`] for the full rationale and the measurements.
pub fn doh_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .pool_idle_timeout(Duration::from_secs(POOL_IDLE_TIMEOUT_SECS))
        .pool_max_idle_per_host(DOH_POOL_MAX_IDLE_PER_HOST)
}

// ── Global connection ceiling ────────────────────────────────────────────────
//
// The `hardened_builder` bounds above shape each client's *steady-state* footprint, but they are
// per-client: a scan constructs ~8 independent clients across DNS, subprocessor, CT, SaaS-tenant,
// web-traffic, and web-org discovery, so their pool bounds multiply rather than cap the peak. And
// the per-request rate limiters pace requests *per second*, not the number open *at once*. Neither
// bounds the quantity that actually exhausts a consumer router's NAT/conntrack table: the peak
// count of simultaneously-open sockets, which the scanner's fan-out (many discovery methods × many
// vendors × recursion depth) drives into the thousands.
//
// This is that missing bound — one process-global semaphore whose permit is held only across a
// single leaf network send, never across recursion (a task releases its permit before descending).
// A task may briefly hold two permits when it `join!`s two gated leaf ops, but neither release waits
// on the other, so there is no wait-for cycle. It caps peak concurrency directly, so a deep scan
// stays safe without throttling anyone's request *rate*.
//
// DNS is deliberately NOT under this semaphore (Wave 1, 2026-08-21). Every DNS transport —
// DoH sends, DoT/UDP hickory exchanges, the system-resolver rescue — is bounded by the DNS
// governor's own adaptive permit instead. Sharing this ceiling put DoH sends in the same FIFO as
// 30 s subprocessor fetches and 120 s subfinder HTTP, INSIDE each lookup's own budget: Phase 1
// measured 22.8% of DNS permit time spent waiting here, half of all per-attempt timeouts firing
// before a byte was sent, and 100%-false transport demotions downstream of that starvation. The
// compile-time guard in dns.rs (`DEFAULT_MAX_LIMIT <= DEFAULT_MAX_CONNECTIONS / 2`) keeps the
// decoupled DNS socket count small against this ceiling by construction.

/// Default ceiling on network sends in flight at once, across the whole process.
///
/// 128 keeps the scanner well under a typical 2000-4000 entry conntrack table (leaving headroom for
/// every other device on the LAN), stays under the `ulimit -n` floor even after browser and idle
/// keep-alive sockets, and still allows enough parallelism that a deep scan runs fast rather than
/// serialized. Override with `--max-connections` or the `NTHPARTYFINDER_MAX_CONNECTIONS` env var;
/// tune against a guarded deep-scan measurement before treating any value as final.
pub const DEFAULT_MAX_CONNECTIONS: usize = 128;

static CONNECTION_SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();

/// Install the global connection ceiling. Call once at startup, before any scan work begins.
///
/// The first initializer wins (this call, or the lazy env fallback in [`connection_semaphore`]);
/// later calls are ignored, so startup must run this before any send. `permits` is floored at 1.
#[cfg_attr(coverage_nightly, coverage(off))] // coverage: installs a process-global OnceLock at startup; a racy set under parallel unit tests, exercised via app.rs startup and the guarded deep-scan run
pub fn init_connection_ceiling(permits: usize) {
    let permits = permits.max(1);
    if CONNECTION_SEMAPHORE.set(Semaphore::new(permits)).is_ok() {
        let _ = CONNECTION_CAP.set(permits);
    }
}

/// The global connection semaphore, lazily initialized from the environment (or the default) if
/// [`init_connection_ceiling`] was never called — covering library callers, tests, and auxiliary
/// commands that never run full startup.
#[cfg_attr(coverage_nightly, coverage(off))] // coverage: OnceLock singleton + env-parse fallback — the get-vs-init branches are not both reachable under the injected-semaphore tests
fn connection_semaphore() -> &'static Semaphore {
    CONNECTION_SEMAPHORE.get_or_init(|| {
        let permits = std::env::var("NTHPARTYFINDER_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_CONNECTIONS);
        let _ = CONNECTION_CAP.set(permits);
        Semaphore::new(permits)
    })
}

/// Run one async network op while holding a single connection permit.
///
/// The permit is acquired immediately before the op and released the instant it returns — held
/// across exactly one leaf send, never across recursion or another permit whose acquisition it must
/// wait for. That is the whole deadlock-safety argument: a held permit is always released on its own
/// op's completion, never conditionally on acquiring a *further* permit, so no task can wait for a
/// permit while blocking one another task needs — there is no wait-for cycle (see the module tests).
/// (A task may briefly hold two permits when it `tokio::join!`s two gated ops — e.g. the concurrent
/// TXT+CNAME lookup in `dns::get_txt_and_cname_fast` — but each of those releases on its own I/O, so
/// the no-wait-for-cycle property still holds.)
async fn gated<F>(semaphore: &Semaphore, op: F) -> F::Output
where
    F: std::future::Future,
{
    gated_timed(semaphore, op).await.1
}

/// [`gated`], but returning how long the permit acquisition waited alongside the op's output.
///
/// The wait is also recorded into `perf::METRICS.conn_permit_wait` for every caller — the
/// all-consumer denominator that Phase-0 DNS attribution compares `dns.conn_permit_wait` against.
/// Observation only: the acquire-then-run ordering is byte-identical to what [`gated`] always did
/// (the op future is constructed by the caller before this is awaited, so e.g. a `reqwest` timeout
/// deadline is still armed before the permit wait — measuring that inversion is the point).
async fn gated_timed<F>(semaphore: &Semaphore, op: F) -> (Duration, F::Output)
where
    F: std::future::Future,
{
    let t0 = Instant::now();
    let _permit = semaphore
        .acquire()
        .await
        .expect("connection semaphore is never closed");
    let wait = t0.elapsed();
    crate::perf::METRICS.conn_permit_wait.record(wait);
    credit_shared_wait(wait);
    (wait, op.await)
}

// ── Shared-wait crediting (2026-08-23 lovable.dev RCA) ──────────────────────────────────────────
//
// A per-operation time budget that runs on wall clock silently measures CONTENTION instead of
// work: the subprocessor per-vendor budget credited browser-permit queueing (its known shared
// wait) but not connection-permit waits — nor, after Wave 3 routed discovery DNS through the
// governed resolver, DNS-permit waits — so at a depth-1 fan-out dozens of vendors' "working
// time" clocks climbed in lockstep (20 s → 53 s in ninety seconds, browser queue 0.0 s) while
// they all drained the same queues, and every one of them was declared budget-starved. This is
// the same defect class as DNS defect C (a shared semaphore inside a per-attempt timeout) and
// the 2026-08-17 domain-ceiling incident (uncredited browser waits) — third occurrence, one
// mechanism now: any task may arm a task-local accumulator around a bounded piece of work, and
// every shared-permit acquisition credits its wait into it, so budgets can subtract queueing
// they cannot otherwise see. Un-armed tasks pay nothing (try_with on an unset task-local).

tokio::task_local! {
    /// The current task's shared-wait sink STACK, when armed by [`scope_shared_wait`]. A stack,
    /// not a single cell: budgets nest — a vendor budget runs inside a domain work ceiling — and
    /// a nested scope that SHADOWED its outer sink would silently stop crediting the outer
    /// budget, which is the exact uncredited-queue class this mechanism exists to kill (the
    /// 2026-08-25 domain-ceiling census: 849 subfinder phases cut with queue billed as work).
    static SHARED_WAIT_SINKS: Vec<std::sync::Arc<std::sync::atomic::AtomicU64>>;

    /// The current domain's queue sink (its `DomainWorkClock` counter), when a phase runs under
    /// a domain work ceiling. A separate channel from `SHARED_WAIT_SINKS` for the waits that
    /// must credit the DOMAIN clock only: render-permit waits are subtracted from vendor budgets
    /// through their own explicit plumbing (`browser_pool::RenderBudgetCtx`), so crediting them
    /// into the shared stack too would subtract the same wait twice from the vendor budget.
    static DOMAIN_QUEUE_SINK: std::sync::Arc<std::sync::atomic::AtomicU64>;
}

/// Run `op` with `acc` collecting every shared-permit wait (connection semaphore, DNS governor +
/// rate bucket) incurred on this task, in addition to any outer scopes already armed. Inherited
/// across `.await`s within the task; NOT across `tokio::spawn` (a spawned subtask is its own
/// budget domain — the browser render path already accounts its queueing separately via the
/// browser-wait counter).
pub async fn scope_shared_wait<F: std::future::Future>(
    acc: std::sync::Arc<std::sync::atomic::AtomicU64>,
    op: F,
) -> F::Output {
    let mut stack = SHARED_WAIT_SINKS.try_with(Clone::clone).unwrap_or_default();
    stack.push(acc);
    SHARED_WAIT_SINKS.scope(stack, op).await
}

/// Run `op` with `sink` armed as the current domain's queue sink (see [`DOMAIN_QUEUE_SINK`]).
pub async fn scope_domain_queue<F: std::future::Future>(
    sink: std::sync::Arc<std::sync::atomic::AtomicU64>,
    op: F,
) -> F::Output {
    DOMAIN_QUEUE_SINK.scope(sink, op).await
}

/// Credit one shared-permit wait to every armed accumulator scope, if any.
pub(crate) fn credit_shared_wait(wait: Duration) {
    if wait.is_zero() {
        return;
    }
    let nanos = u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX);
    let _ = SHARED_WAIT_SINKS.try_with(|sinks| {
        for acc in sinks {
            acc.fetch_add(nanos, std::sync::atomic::Ordering::Relaxed);
        }
    });
}

/// Credit a wait to the current domain's queue sink only (see [`DOMAIN_QUEUE_SINK`] for why this
/// channel exists apart from the shared stack).
pub(crate) fn credit_domain_queue(wait: Duration) {
    if wait.is_zero() {
        return;
    }
    let _ = DOMAIN_QUEUE_SINK.try_with(|acc| {
        acc.fetch_add(
            u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    });
}

/// The armed domain queue sink, for contexts that must carry it across a spawn seam (the render
/// paths read it on the async task and move the clone into their blocking closure).
pub(crate) fn current_domain_queue_sink() -> Option<std::sync::Arc<std::sync::atomic::AtomicU64>> {
    DOMAIN_QUEUE_SINK.try_with(Clone::clone).ok()
}

/// A monotonic "the machinery worked recently" witness — the differential-evidence primitive.
///
/// The DNS layer's name-vs-transport split generalized: silence from ONE remote is never, by
/// itself, evidence about who failed — but silence from one remote while the same machinery
/// demonstrably succeeded elsewhere within the same timeout-length IS host-specific, the way an
/// authoritative SERVFAIL is name-specific. One witness instance per machinery class (HTTP
/// transport, browser capture); `note_ok` on every success, `ok_within(window)` at a failure's
/// classification site with the operation's own timeout as the window.
pub(crate) struct HealthWitness {
    anchor: OnceLock<Instant>,
    /// Nanos-since-anchor of the last success, +1 so `0` means "never".
    last_ok: std::sync::atomic::AtomicU64,
}

impl HealthWitness {
    pub(crate) const fn new() -> Self {
        Self {
            anchor: OnceLock::new(),
            last_ok: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn now_nanos(&self) -> u64 {
        let anchor = self.anchor.get_or_init(Instant::now);
        u64::try_from(anchor.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// Record one success of this machinery class.
    pub(crate) fn note_ok(&self) {
        let stamp = self.now_nanos().saturating_add(1);
        self.last_ok
            .store(stamp, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether this machinery class succeeded within the last `window`.
    pub(crate) fn ok_within(&self, window: Duration) -> bool {
        let last = self.last_ok.load(std::sync::atomic::Ordering::Relaxed);
        if last == 0 {
            return false;
        }
        let elapsed_since = self.now_nanos().saturating_sub(last - 1);
        u128::from(elapsed_since) <= window.as_nanos()
    }
}

/// The HTTP-transport witness: any successful gated send notes it.
pub(crate) static TRANSPORT_WITNESS: HealthWitness = HealthWitness::new();

/// Credit `wait` into a carried sink, if present — the blocking-thread counterpart of
/// [`credit_domain_queue`] for closures that captured the sink before the spawn seam.
pub(crate) fn credit_carried_sink(
    sink: &Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    wait: Duration,
) {
    if wait.is_zero() {
        return;
    }
    if let Some(sink) = sink {
        sink.fetch_add(
            u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// Send a `reqwest` request under the global connection ceiling.
///
/// Drop-in for `.send()`: replace `builder.send().await` with `builder.send_gated().await` at every
/// production send site so the number of connection establishments in flight at once is globally
/// bounded no matter which discovery path is running. The permit covers connection establishment and
/// the in-flight request — the peak concurrency that, together with the disabled idle pool
/// (`POOL_MAX_IDLE_PER_HOST == 0`, so a socket closes right after its request), keeps the total open
/// socket count far under a consumer router's conntrack table on a deep fan-out.
pub trait GatedSend {
    /// Send while holding one global connection permit (see [`gated`]).
    fn send_gated(
        self,
    ) -> impl std::future::Future<Output = reqwest::Result<reqwest::Response>> + Send;

    /// [`GatedSend::send_gated`], returning the permit wait alongside the response.
    ///
    /// Also classifies the target host (IP-literal vs hostname) into
    /// `http.send_ip_host`/`http.send_nonip_host` — every hostname send implies a `getaddrinfo`
    /// resolution the DNS governor never sees (Phase-0 attribution, hypothesis D's cheap proxy).
    /// Behaviour-identical to [`GatedSend::send_gated`]: the request future (and any per-request
    /// timeout deadline inside it) is constructed BEFORE the permit is awaited, exactly as the
    /// eager `self.send()` argument always was.
    fn send_gated_timed(
        self,
    ) -> impl std::future::Future<Output = (Duration, reqwest::Result<reqwest::Response>)> + Send;
}

impl GatedSend for reqwest::RequestBuilder {
    fn send_gated(
        self,
    ) -> impl std::future::Future<Output = reqwest::Result<reqwest::Response>> + Send {
        let fut = gated(connection_semaphore(), self.send());
        async move {
            let result = fut.await;
            if result.is_ok() {
                TRANSPORT_WITNESS.note_ok();
            }
            result
        }
    }

    async fn send_gated_timed(self) -> (Duration, reqwest::Result<reqwest::Response>) {
        let (client, req) = self.build_split();
        match req {
            Ok(req) => {
                match req.url().host() {
                    Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)) => {
                        crate::perf::METRICS.http_send_ip_host.hit();
                    }
                    _ => crate::perf::METRICS.http_send_nonip_host.hit(),
                }
                // Construct the send future BEFORE the permit wait — `client.execute` arms
                // the per-request timeout at call time, matching `send_gated`'s eager
                // `self.send()` argument. Phase 0 measures that inversion; it must not fix it.
                let fut = client.execute(req);
                let (wait, result) = gated_timed(connection_semaphore(), fut).await;
                if result.is_ok() {
                    TRANSPORT_WITNESS.note_ok();
                }
                (wait, result)
            }
            Err(e) => (Duration::ZERO, Err(e)),
        }
    }
}

/// Run any async network op under the global connection ceiling.
///
/// For non-`reqwest` sockets that cannot use [`GatedSend`] (WHOIS port-43, for one) so every
/// non-DNS socket-opening path shares the one ceiling. DNS transports must NOT be wrapped in
/// this — they are governed by the DNS governor's own permit (see the module docs).
pub async fn with_connection_permit<F: std::future::Future>(op: F) -> F::Output {
    gated(connection_semaphore(), op).await
}

/// [`with_connection_permit`], returning the permit wait alongside the op's output.
pub async fn with_connection_permit_timed<F: std::future::Future>(op: F) -> (Duration, F::Output) {
    gated_timed(connection_semaphore(), op).await
}

/// The connection ceiling's `(capacity, currently_available)` — sampled for telemetry events so a
/// transport-demotion record carries who was holding the 128 at the moment it fired.
///
/// Capacity is reconstructed as `available + in_flight` is not observable directly; instead the
/// installed cap is remembered at init. Before any init, both read as the lazy default path would
/// install them.
pub fn connection_ceiling_state() -> (usize, usize) {
    let sem = connection_semaphore();
    let cap = *CONNECTION_CAP.get_or_init(|| DEFAULT_MAX_CONNECTIONS);
    (cap, sem.available_permits())
}

static CONNECTION_CAP: OnceLock<usize> = OnceLock::new();

// ── getaddrinfo observation (Phase-0 DNS attribution, hypothesis D) ─────────────────────────────
//
// Every `hardened_builder` client resolves hostnames through the system resolver (`getaddrinfo`),
// which on macOS routes via mDNSResponder — invisible to per-process tools AND to the DNS
// governor/breaker/UDP budget. This resolver delegates to the exact same system path
// (`tokio::net::lookup_host` → `getaddrinfo` on a blocking thread) while counting each resolution
// and remembering a bounded set of distinct hosts, so a scan can report how much un-governed DNS
// it induced. Observation only: same syscall, same semantics, same failure behaviour.

/// Cap on the distinct-host set so a pathological scan cannot grow it unbounded.
const GETADDRINFO_HOST_SET_CAP: usize = 5000;

static GETADDRINFO_HOSTS: OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    OnceLock::new();

fn note_getaddrinfo_host(host: &str) {
    let set =
        GETADDRINFO_HOSTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    if let Ok(mut set) = set.lock() {
        if set.len() < GETADDRINFO_HOST_SET_CAP {
            set.insert(host.to_ascii_lowercase());
        }
    }
}

/// How many distinct hostnames the counting resolver has resolved this scan (capped).
pub fn getaddrinfo_distinct_hosts() -> usize {
    GETADDRINFO_HOSTS
        .get()
        .and_then(|m| m.lock().ok().map(|s| s.len()))
        .unwrap_or(0)
}

/// A `reqwest` DNS resolver that counts every `getaddrinfo` resolution it performs.
///
/// Installed by [`hardened_builder`] (never the DoH client — its endpoints are IP literals and
/// must not recurse through any resolver). Delegates to the system resolver via
/// `tokio::net::lookup_host`, recording `http.getaddrinfo` (count + duration) and the distinct
/// host set. Failure behaviour is the system resolver's own.
#[derive(Debug, Clone, Copy)]
pub struct CountingResolver;

impl reqwest::dns::Resolve for CountingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let t0 = Instant::now();
            let result = tokio::net::lookup_host((host.as_str(), 0)).await;
            crate::perf::METRICS.http_getaddrinfo.record(t0.elapsed());
            note_getaddrinfo_host(&host);
            match result {
                Ok(addrs) => {
                    let addrs: Vec<std::net::SocketAddr> = addrs.collect();
                    Ok(Box::new(addrs.into_iter())
                        as Box<dyn Iterator<Item = std::net::SocketAddr> + Send>)
                }
                Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn health_witness_reports_recent_success_and_never_before_any() {
        // A fresh witness has no evidence: silence must not classify as target-side.
        let w = HealthWitness::new();
        assert!(!w.ok_within(Duration::from_secs(3600)));
        // After a success it is evidence within the window…
        w.note_ok();
        assert!(w.ok_within(Duration::from_secs(60)));
        // …but not within a window that has already passed (zero-length window: the elapsed
        // nanos since note_ok are strictly positive by the time we re-read).
        std::thread::sleep(Duration::from_millis(5));
        assert!(!w.ok_within(Duration::from_millis(1)));
    }

    /// The hardened builder must still produce a working client after a caller layers on the
    /// per-request timeout and user agent it always sets.
    #[test]
    fn test_hardened_builder_builds_a_usable_client() {
        let client = hardened_builder()
            .timeout(Duration::from_secs(5))
            .user_agent("nthpartyfinder-test")
            .build();
        assert!(
            client.is_ok(),
            "hardened builder must produce a valid client"
        );
    }

    /// Guard the bounds against a careless future edit: a connect timeout that drifts up to the
    /// old unbounded regime, or an idle window back near reqwest's 90s default, re-opens the
    /// conntrack-exhaustion risk this module exists to close.
    #[test]
    fn the_user_agent_identifies_the_tool_and_never_impersonates_a_browser() {
        // The regression: three clients sent a pinned `Chrome/120.0.0.0` string commented
        // "Realistic browser user agent". It was realistic in 2023. By 2026 no real user runs
        // Chrome 120, so bot management scores the claim as automation — measured 2026-07-31,
        // trust.drata.com/subprocessors answered 403 with `cf-mitigated: challenge` for Chrome/120
        // AND Chrome/131, but 200 for this UA. Impersonating a browser is what got us blocked.
        assert!(
            !USER_AGENT.contains("Mozilla") && !USER_AGENT.contains("Chrome"),
            "user agent must not claim to be a browser, got {USER_AGENT:?}"
        );
        assert!(
            USER_AGENT.starts_with("nthpartyfinder/"),
            "a site operator must be able to attribute this traffic, got {USER_AGENT:?}"
        );
        // Version tracks the package, so there is no pinned version left to rot. Pinning any
        // version — browser or our own — is how this broke the first time.
        assert!(
            USER_AGENT.contains(env!("CARGO_PKG_VERSION")),
            "user agent must carry the live crate version, got {USER_AGENT:?}"
        );
        assert!(
            USER_AGENT.contains("https://github.com/grcengineering/nthpartyfinder"),
            "user agent must link somewhere an operator can read what this tool does, got {USER_AGENT:?}"
        );
    }

    #[test]
    fn test_connection_bounds_stay_conservative() {
        assert!(
            (2..=10).contains(&CONNECT_TIMEOUT_SECS),
            "connect timeout {CONNECT_TIMEOUT_SECS}s must abandon stalled handshakes promptly"
        );
        assert!(
            (5..=60).contains(&POOL_IDLE_TIMEOUT_SECS),
            "idle sockets (if any are ever re-enabled) must be evicted well before reqwest's 90s default"
        );
        assert_eq!(
            POOL_MAX_IDLE_PER_HOST, 0,
            "idle pooling must stay disabled for clients whose destination host set GROWS WITH THE \
             SCAN: a nonzero idle pool there re-opens the conntrack-exhaustion failure mode by \
             leaving ESTABLISHED sockets across every host a deep scan touches, which the in-flight \
             connection ceiling does not bound (see the const's doc comment). This says nothing \
             about clients with a fixed endpoint list — see DOH_POOL_MAX_IDLE_PER_HOST"
        );
    }

    /// The DoH builder must actually differ from the general one — the whole fix is that DoH gets
    /// connection reuse while discovery does not. A future refactor that collapses the two builders
    /// would silently restore the handshake-per-query behaviour with every test still green, so
    /// assert the observable difference rather than only the constants.
    #[test]
    fn test_doh_builder_differs_from_hardened_builder() {
        // Both must build successfully with the same downstream configuration a caller applies.
        let general = hardened_builder().build();
        let doh = doh_builder().build();
        assert!(general.is_ok(), "general client must build");
        assert!(doh.is_ok(), "DoH client must build");
        assert_ne!(
            POOL_MAX_IDLE_PER_HOST, DOH_POOL_MAX_IDLE_PER_HOST,
            "the DoH client exists precisely because its pooling differs from the general one; if \
             these ever converge, either discovery grew an unbounded idle pool or DoH lost its \
             connection reuse and every query pays a fresh TLS handshake again"
        );
    }

    /// The ceiling must be a sane, conservative default: large enough for real parallelism, far
    /// below a consumer conntrack table so a deep scan cannot exhaust it.
    #[test]
    fn test_default_max_connections_is_conservative() {
        assert!(
            (32..=512).contains(&DEFAULT_MAX_CONNECTIONS),
            "default ceiling {DEFAULT_MAX_CONNECTIONS} must stay well under a conntrack table"
        );
    }

    /// Core safety property: no matter how many sends are launched, `gated` never lets more than the
    /// permit count run at once, and every permit is returned afterward (no leak).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gated_bounds_peak_concurrency_and_never_leaks() {
        const CEILING: usize = 3;
        let sem = Arc::new(Semaphore::new(CEILING));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..24 {
            let (sem, in_flight, peak) = (sem.clone(), in_flight.clone(), peak.clone());
            handles.push(tokio::spawn(async move {
                gated(&sem, async {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                })
                .await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let observed_peak = peak.load(Ordering::SeqCst);
        assert!(
            observed_peak <= CEILING,
            "peak concurrency {observed_peak} exceeded the ceiling of {CEILING}"
        );
        assert!(
            observed_peak >= 2,
            "expected genuine concurrency up to the ceiling, saw only {observed_peak} — the bound assertion would be meaningless"
        );
        assert_eq!(
            sem.available_permits(),
            CEILING,
            "permits leaked: all ops finished but the pool did not refill"
        );
    }

    /// Deadlock guard mirroring the scanner's recursion shape: a parent gates one op, then spawns
    /// children that also gate — against a pool smaller than the fan-out. Because a permit is
    /// released before the parent recurses, this must complete; if a permit were held across the
    /// recursion it would deadlock. The timeout is the falsifier.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gated_does_not_deadlock_under_recursive_acquire() {
        let sem = Arc::new(Semaphore::new(2)); // fewer permits than the 4×4 fan-out below
        let completed = tokio::time::timeout(Duration::from_secs(5), async {
            let mut parents = Vec::new();
            for _ in 0..4 {
                let sem = sem.clone();
                parents.push(tokio::spawn(async move {
                    gated(&sem, async {}).await; // parent's leaf op — permit released here
                    let mut kids = Vec::new();
                    for _ in 0..4 {
                        let sem = sem.clone();
                        kids.push(tokio::spawn(async move { gated(&sem, async {}).await }));
                    }
                    for k in kids {
                        k.await.unwrap();
                    }
                }));
            }
            for p in parents {
                p.await.unwrap();
            }
        })
        .await;

        assert!(
            completed.is_ok(),
            "recursive gated acquires deadlocked (held a permit across recursion)"
        );
        assert_eq!(sem.available_permits(), 2, "permits leaked after recursion");
    }

    /// One task `tokio::join!`s two gated ops at once — the `dns::get_txt_and_cname_fast` shape, the
    /// one place a single task transiently holds two permits. Neither op's completion depends on the
    /// other acquiring, so there is no wait-for cycle: this must complete and return both permits.
    /// Uses a 2-permit pool so both branches run concurrently (the real double-hold), plus a 1-permit
    /// pool to prove it still completes when the branches must serialize on the single permit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gated_join_of_two_ops_in_one_task_does_not_deadlock() {
        for permits in [2usize, 1usize] {
            let sem = Semaphore::new(permits);
            let completed = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(
                    gated(&sem, async {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }),
                    gated(&sem, async {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }),
                )
            })
            .await;
            assert!(
                completed.is_ok(),
                "join! of two gated ops deadlocked with {permits} permit(s)"
            );
            assert_eq!(
                sem.available_permits(),
                permits,
                "permits leaked after a two-op join with {permits} permit(s)"
            );
        }
    }

    /// End-to-end through the global `.send_gated()`: a real request completes and its body reads.
    #[tokio::test]
    async fn send_gated_completes_a_request() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let resp = reqwest::Client::new()
            .get(server.uri())
            .send_gated()
            .await
            .expect("gated send to a live mock should succeed");
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "ok");
    }

    /// `with_connection_permit` runs the wrapped op and returns its output (the raw-UDP DNS path).
    #[tokio::test]
    async fn with_connection_permit_runs_the_op() {
        let out = with_connection_permit(async { 7_u32 }).await;
        assert_eq!(out, 7);
    }

    /// A permit must be returned even when the send fails, or an early error would slowly starve the
    /// pool. Uses a closed local port (connection refused immediately, no network egress).
    #[tokio::test]
    async fn gated_releases_the_permit_when_the_send_errors() {
        let sem = Semaphore::new(1);
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(200))
            .build()
            .unwrap();

        let result = gated(&sem, client.get("http://127.0.0.1:1/").send()).await;

        assert!(
            result.is_err(),
            "a send to a closed local port must error, not hang"
        );
        assert_eq!(
            sem.available_permits(),
            1,
            "the permit must be released even on the error path"
        );
    }
}
