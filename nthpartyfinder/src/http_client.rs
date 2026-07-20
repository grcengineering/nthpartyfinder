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
use std::time::Duration;
use tokio::sync::Semaphore;

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

/// A `reqwest::ClientBuilder` pre-configured with the connection bounds above.
///
/// Callers chain their own `.timeout(..)`, `.user_agent(..)`, etc. and then `.build()`. Use this
/// in place of `reqwest::Client::builder()` at every subsystem's client-construction site so the
/// connection footprint is bounded uniformly, no matter which discovery path is running.
pub fn hardened_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .pool_idle_timeout(Duration::from_secs(POOL_IDLE_TIMEOUT_SECS))
        .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
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
    let _ = CONNECTION_SEMAPHORE.set(Semaphore::new(permits.max(1)));
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
    let _permit = semaphore
        .acquire()
        .await
        .expect("connection semaphore is never closed");
    op.await
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
}

impl GatedSend for reqwest::RequestBuilder {
    fn send_gated(
        self,
    ) -> impl std::future::Future<Output = reqwest::Result<reqwest::Response>> + Send {
        gated(connection_semaphore(), self.send())
    }
}

/// Run any async network op under the global connection ceiling.
///
/// For non-`reqwest` sockets that cannot use [`GatedSend`] — e.g. the raw-UDP DNS resolver — so
/// every socket-opening path shares the one ceiling.
pub async fn with_connection_permit<F: std::future::Future>(op: F) -> F::Output {
    gated(connection_semaphore(), op).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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
            "idle pooling must stay disabled: a nonzero idle pool re-opens the conntrack-exhaustion \
             failure mode by leaving ESTABLISHED sockets across every host a deep scan touches, which \
             the in-flight connection ceiling does not bound (see the const's doc comment)"
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
