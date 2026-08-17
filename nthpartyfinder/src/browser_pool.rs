//! Browser concurrency pool for headless Chrome instances.
//!
//! Two separate things are bounded here, and conflating them is what made depth-3 scans slow:
//!
//! * **How many renders may run at once** — the semaphore. This is the scan's render
//!   parallelism.
//! * **How many Chrome processes exist** — the idle pool. Chrome costs ~200–300 MB of
//!   *child-process* RSS and ~2.2s to cold-start.
//!
//! Historically a permit *was* a Chrome process: every render launched one, used it once, and
//! killed it. Measurement (`perf.rs`, m1 run) showed 272 renders spending 3878.9s of real work
//! but 14594.6s queued for a permit — the render path was the critical path at 84% of wall,
//! and 611.9s of the work was nothing but relaunching Chrome. So a permit now means "a render
//! slot", and Chrome processes are reused across renders, recycled periodically to bound the
//! leak that a long-lived browser accumulates.
//!
//! Isolation is preserved by giving every render a **fresh tab**, closing it afterwards, and
//! resetting the browser's shared network state before the render begins — see [`isolate_tab`].
//! `Browser::new_context()` (an incognito context) would give stronger isolation, but
//! headless_chrome 1.0.22's `Context` has no `Drop` and exposes no `Target.disposeBrowserContext`,
//! so contexts would accumulate for the life of the process with no way to free them.
//!
//! The render slot is a `tokio::sync::Semaphore` permit, acquired from async context *before* the
//! caller enters `spawn_blocking` — see [`acquire_render_permit`] for why waiting on a thread was
//! the more expensive of the two ways to wait.

use std::sync::Arc;

/// Floor on concurrent renders. A small CI runner must never end up with a *smaller* pool than
/// the historical fixed value.
const MIN_RENDER_PERMITS: usize = 4;

/// Hard ceiling on concurrent renders regardless of host size.
///
/// Measured, not assumed. Once Chrome processes are reused, raising this from 8 to 16 made the
/// depth-3 vanta.com scan *slower* (515s vs 434s): the render queue emptied, but the extra
/// concurrency inflated every other latency (mean DNS query 0.164s → 0.860s, mean page fetch
/// 2.77s → 4.42s) and starved more vendors of their subprocessor budget (175 vs 165). Render
/// parallelism is not the scan's throughput limit; it was only ever the launch cost — so lowering
/// the ceiling costs little throughput.
///
/// Lowered 8 → 6: each concurrent browser is the dominant open-socket consumer (a page render
/// opens a connection to every resource origin), so the ceiling directly bounds the scan's peak
/// socket footprint. A guarded depth-3 measurement put the system's peak ESTABLISHED sockets near
/// ~950 at 8 browsers vs ~790 at 6 — the latter leaves comfortable headroom under a consumer
/// router's NAT/conntrack table on the sensitive networks this fix targets, at little throughput
/// cost. This is the *auto-sized* ceiling; an operator can override in EITHER direction with
/// `NTHPARTYFINDER_MAX_BROWSERS` (raising it on a robust network to recover render parallelism, up
/// to [`HARD_MAX_RENDER_PERMITS`]).
const MAX_RENDER_PERMITS: usize = 6;

/// Absolute ceiling on an explicit `NTHPARTYFINDER_MAX_BROWSERS` override — so a robust-network
/// operator can raise concurrency above the auto-sized default, but never past a sane cap (raising
/// it from 8 to 16 was measured to make the scan slower, so 16 is a hard upper bound).
const HARD_MAX_RENDER_PERMITS: usize = 16;

/// Gigabytes of headroom assumed per concurrent Chrome. Deliberately conservative: Chrome's
/// renderer processes live outside this process's RSS, so we cannot measure them from here.
const GB_PER_BROWSER: u64 = 3;

/// Renders one Chrome process serves before it is retired and relaunched — and, crucially, before
/// its accumulated network sockets are released.
///
/// This is the load-bearing bound on the scan's peak socket footprint. A pooled browser keeps an
/// idle keep-alive socket open to every origin its renders contacted, and clearing cache/cookies
/// between renders does NOT close them — they live in Chrome's process-global connection pool, out
/// of reach of any per-session CDP call. The only guaranteed release is the graceful `Browser.Close`
/// that runs when the browser is retired (it tears down the whole Chrome process tree and every
/// socket). A guarded depth-3 measurement showed pooled browsers left at the old quota of 50
/// accumulate ESTABLISHED sockets until the system count reaches a consumer router's NAT/conntrack
/// ceiling and local WiFi drops; at 6 the socket count instead oscillates and plateaus (peak ~790,
/// leaving headroom under the table).
///
/// The cost is real, not free: a depth-3 scan does a few hundred renders, so a quota of 6 relaunches
/// Chrome several times more than 50 did — on the order of tens of extra ~2s launches (partly
/// overlapped across browsers, so the wall-clock hit is a fraction of the naive sum, but it is not
/// negligible). Recall is unaffected (every render still runs to completion). The default is chosen
/// to protect the sensitive networks this fix targets; raising it trades that socket headroom back
/// for launch speed and is safe only on a network with a large conntrack table. Override with
/// `NTHPARTYFINDER_RENDERS_PER_BROWSER`.
const DEFAULT_MAX_RENDERS_PER_BROWSER: usize = 6;

/// Resolve the per-browser render quota from the environment, falling back to the default.
fn resolve_max_renders_per_browser() -> usize {
    std::env::var("NTHPARTYFINDER_RENDERS_PER_BROWSER")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MAX_RENDERS_PER_BROWSER)
}

/// Cached render quota (read once; consulted on the hot `TabGuard::drop` path per render).
static MAX_RENDERS_PER_BROWSER: once_cell::sync::Lazy<usize> =
    once_cell::sync::Lazy::new(resolve_max_renders_per_browser);

fn total_memory_gb() -> u64 {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_memory();
    sys.total_memory() / (1024 * 1024 * 1024)
}

/// Resolve how many renders may run concurrently on this host.
///
/// Bounded by whichever is scarcer — memory (each concurrent Chrome costs child-process RSS we
/// cannot see from here) or cores — then clamped into `[MIN_RENDER_PERMITS, MAX_RENDER_PERMITS]`.
/// `NTHPARTYFINDER_MAX_BROWSERS` overrides for constrained hosts, still capped by the ceiling.
///
/// The clamp, not the formula, is what matters on a big host: see `MAX_RENDER_PERMITS` for why
/// more render slots is not more throughput.
fn resolve_max_browser_instances() -> usize {
    if let Some(n) = std::env::var("NTHPARTYFINDER_MAX_BROWSERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
    {
        return n.min(HARD_MAX_RENDER_PERMITS);
    }
    let by_memory =
        usize::try_from(total_memory_gb() / GB_PER_BROWSER).unwrap_or(MIN_RENDER_PERMITS);
    let by_cpu = std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(MIN_RENDER_PERMITS);
    by_memory
        .min(by_cpu)
        .clamp(MIN_RENDER_PERMITS, MAX_RENDER_PERMITS)
}

/// A launched Chrome process that deregisters its PID from the reap registry when dropped.
///
/// The inner `Browser`'s own `Drop` kills the Chrome process; this wrapper's `Drop` runs first and
/// removes the PID from `CHROME_PIDS`, so a *cleanly* retired browser can never be reaped later by
/// PID — closing the window where the OS recycles that PID onto an unrelated process (e.g. the
/// user's own Chrome on a long scan) before the terminal reap. A browser leaked by a hard exit
/// (whose `Drop` never runs) stays registered and is reaped, exactly as intended.
struct TrackedBrowser {
    inner: headless_chrome::Browser,
    pid: Option<u32>,
}

impl TrackedBrowser {
    /// Wrap a freshly launched browser, registering its PID for reaping.
    fn new(inner: headless_chrome::Browser) -> Self {
        let pid = inner.get_process_id();
        if let Some(pid) = pid {
            register_chrome_pid(pid);
        }
        Self { inner, pid }
    }
}

impl std::ops::Deref for TrackedBrowser {
    type Target = headless_chrome::Browser;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for TrackedBrowser {
    fn drop(&mut self) {
        // Runs before the inner `Browser::drop` kills the process: forget the PID so a later reap
        // cannot target whatever the OS recycles it onto.
        if let Some(pid) = self.pid {
            deregister_chrome_pid(pid);
        }
    }
}

/// A Chrome process plus how many renders it has already served.
struct PooledBrowser {
    browser: TrackedBrowser,
    served: usize,
}

/// Idle Chrome processes available for reuse. Never longer than the permit count, because a
/// browser only returns here when its render finished, and a render holds a permit.
static IDLE_BROWSERS: once_cell::sync::Lazy<std::sync::Mutex<Vec<PooledBrowser>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(Vec::new()));

fn lock_idle() -> std::sync::MutexGuard<'static, Vec<PooledBrowser>> {
    IDLE_BROWSERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// PIDs of every Chrome process this scanner has launched and not yet reaped.
///
/// The idle pool holds the `Browser` objects whose `Drop` kills the process, but only for
/// *idle* browsers. A browser handed out to a render lives inside a `TabGuard` owned by the
/// render task — and a hard exit (`process::exit` on timeout, Ctrl-C, or a `panic = "abort"`
/// build) runs no destructors, so those in-flight browsers are leaked. Tracking every launched
/// PID lets [`reap_registered_chrome`] kill them by PID on any exit path, even the ones that
/// skip `Drop`. This is what stopped depth-3 scans from leaving hundreds of orphaned Chrome
/// trees pinned to `launchd` for days.
static CHROME_PIDS: once_cell::sync::Lazy<std::sync::Mutex<std::collections::HashSet<u32>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

fn lock_pids() -> std::sync::MutexGuard<'static, std::collections::HashSet<u32>> {
    CHROME_PIDS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Record a freshly launched Chrome's PID so it can be reaped on any exit path.
fn register_chrome_pid(pid: u32) {
    lock_pids().insert(pid);
}

/// Forget a Chrome PID once its `Browser` has been dropped (which kills the process cleanly).
///
/// Deregistering on clean drop keeps the reap registry to *genuinely in-flight* PIDs. A browser
/// retired mid-scan (recycled at the render quota, or evicted as unhealthy) has its process killed
/// by `Browser::drop`; leaving its PID registered would let the terminal reap SIGKILL whatever
/// unrelated process the OS later recycled that PID onto — including the user's own Chrome on a
/// long scan. Removing it shrinks that reuse window from a whole scan to a single render.
fn deregister_chrome_pid(pid: u32) {
    lock_pids().remove(&pid);
}

/// Whether a still-alive process at a registered PID actually looks like a browser we launched.
///
/// A registered PID is only reaped if the process currently at that PID looks like the browser we
/// started — the guard against the OS having recycled the PID for something unrelated between the
/// launch and the reap. Chrome reports itself as `chrome`, `Chromium`, `Google Chrome for
/// Testing`, or `chrome-headless-shell` (all contain `chrom`); the older standalone headless
/// distributable is `headless_shell` (matched by `headless`).
fn looks_like_chrome(process_name: &str) -> bool {
    let name = process_name.to_ascii_lowercase();
    name.contains("chrom") || name.contains("headless")
}

/// The prefix `headless_chrome` gives every temp profile directory it creates (baked into Chrome's
/// own `--user-data-dir=` argument by the crate — `tempfile::Builder::new().prefix(..)` in
/// `headless_chrome::browser::process`). This, not the process name alone, is what safely
/// identifies a Chrome process as ours: `looks_like_chrome` matches "chrome"/"headless" far too
/// broadly to system-sweep on (it would equally match the user's own real browser, or any other
/// automation tool's headless Chrome).
const CHROME_PROFILE_SIGNATURE: &str = "rust-headless-chrome-profile";

/// True when a system process's command line marks it as a Chrome instance this scanner's crate
/// launched (carries our profile-dir signature) AND it has no living parent — i.e. it was orphaned
/// by a scanner process that exited without cleanly killing it (a hard `kill -9`, a crash that
/// bypassed the panic hook, or any exit this codebase cannot itself intercept). Pure predicate over
/// already-fetched process facts, so it is unit-testable without touching the real process table.
fn is_orphaned_chrome_of_ours(cmd_joined: &str, has_live_parent: bool) -> bool {
    !has_live_parent && cmd_joined.contains(CHROME_PROFILE_SIGNATURE)
}

/// Sweep the WHOLE system process table (not just this run's own registry) for Chrome instances
/// orphaned by a *previous* nthpartyfinder invocation that exited hard enough to skip every
/// in-process reap path (`shutdown()`, the Ctrl-C handler, the panic hook — all of which only know
/// about PIDs *this* run itself launched). A `kill -9` of a prior scan, or a crash before any of
/// those handlers could run, leaves such an orphan reparented to PID 1 (macOS/Linux) forever
/// holding its sockets — exactly the failure mode `scripts/safe-scan.sh`'s pre-scan sweep used to
/// close from outside the binary. Call once at startup, before any new Chrome is launched, so a
/// prior hard-killed run's leftovers cannot compound with this run's own footprint.
///
/// Unix only (PID-1 reparenting is a POSIX process-model concept); a no-op elsewhere. Returns the
/// number of orphans killed, purely so the caller can log it — never treated as an error.
#[cfg(unix)]
#[cfg_attr(coverage_nightly, coverage(off))] // coverage: scans and kills real OS processes; the decision logic is unit-tested via is_orphaned_chrome_of_ours
pub fn sweep_orphaned_chrome() -> usize {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        false,
        ProcessRefreshKind::everything(),
    );

    let init = Pid::from_u32(1);
    let mut killed = 0usize;
    for process in system.processes().values() {
        if !looks_like_chrome(&process.name().to_string_lossy()) {
            continue;
        }
        let cmd_joined = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        // A dead/absent parent is also an orphan (the more common signal on Linux containers,
        // where a reparented child may land on PID 1 OR simply have no resolvable parent).
        let has_live_parent = process
            .parent()
            .is_some_and(|ppid| ppid != init && system.process(ppid).is_some());
        if is_orphaned_chrome_of_ours(&cmd_joined, has_live_parent) {
            process.kill();
            killed += 1;
        }
    }
    killed
}

#[cfg(not(unix))]
pub fn sweep_orphaned_chrome() -> usize {
    0
}

/// Take and clear the set of registered Chrome PIDs. Pure so the drain semantics are testable
/// without touching the process table.
fn drain_pids(pids: &mut std::collections::HashSet<u32>) -> Vec<u32> {
    std::mem::take(pids).into_iter().collect()
}

/// SIGKILL a set of Chrome PIDs whose processes are still alive and still look like Chrome.
///
/// Split out so the normal reap and the panic-hook reap share one kill implementation and differ
/// only in how they acquire the PID set (a blocking lock vs. `try_lock`).
///
/// Only the *main* browser process PID is tracked (that is all `headless_chrome` exposes). Killing
/// it severs the CDP/IPC pipe its renderer and GPU helpers depend on, so they exit on their own
/// shortly after; [`sweep_orphaned_chrome`] (run at the start of every new scan) sweeps any
/// straggler that outlives its parent as a backstop.
// coverage(off): queries and kills real OS processes; the decision logic is tested via
// looks_like_chrome and drain_pids.
#[cfg_attr(coverage_nightly, coverage(off))]
fn kill_chrome_pids(pids: Vec<u32>) {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    if pids.is_empty() {
        return;
    }
    let targets: Vec<Pid> = pids.iter().map(|p| Pid::from_u32(*p)).collect();
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&targets),
        false,
        ProcessRefreshKind::everything(),
    );
    for pid in targets {
        if let Some(process) = system.process(pid) {
            if looks_like_chrome(&process.name().to_string_lossy()) {
                process.kill();
            }
        }
    }
}

/// Drain the registry and SIGKILL every still-alive Chrome it named. The registry is drained
/// regardless of kill outcome, so a second call is a no-op.
// coverage(off): delegates to kill_chrome_pids (also coverage-off).
#[cfg_attr(coverage_nightly, coverage(off))]
fn reap_registered_chrome() {
    kill_chrome_pids(drain_pids(&mut lock_pids()));
}

/// Reap Chrome from a panic hook without ever blocking.
///
/// A panicking thread must not deadlock the abort. This never touches the idle-pool lock — every
/// launched PID, idle *and* in-flight, is in the registry, so a PID-only reap covers them all —
/// and it takes the registry lock with `try_lock`: if that lock were somehow held (a future edit
/// that panics inside a `lock_pids()` section), it skips rather than hangs. A poisoned-but-free
/// lock is still drained. A `kill -9` never runs the killed process's own destructors either, so
/// its temp profile dir is left on disk regardless of which reap path fires — nothing sweeps
/// directory contents, only processes; a hung network beats a clean `/tmp`.
// coverage(off): only invoked from the panic hook under `panic = "abort"`; unreachable from a unit
// test without aborting the process. Verified empirically.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn reap_on_panic() {
    let pids = match CHROME_PIDS.try_lock() {
        Ok(mut guard) => drain_pids(&mut guard),
        Err(std::sync::TryLockError::Poisoned(p)) => drain_pids(&mut p.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => return,
    };
    kill_chrome_pids(pids);
}

/// Kill every Chrome process this scanner launched — idle *and* in-flight.
///
/// `IDLE_BROWSERS` is a `Lazy` static and statics never run `Drop`, so clearing it is the only
/// thing that reaps *idle* Chrome. In-flight browsers live in `TabGuard`s owned by render tasks
/// that a hard exit tears down without running destructors, so clearing the idle pool is not
/// enough — [`reap_registered_chrome`] kills the in-flight ones by PID. Call it on every exit
/// path from a scan; it is idempotent and recovers from a poisoned pool lock.
///
/// A `panic = "abort"` build still runs no `Drop`, but the panic *hook* installed in
/// `app::run` calls this before the abort, so even a panic reaps Chrome now.
pub fn shutdown() {
    {
        let mut idle = lock_idle();
        // Dropping each `Browser` kills its process and removes its temp profile dir.
        idle.clear();
    }
    // Kill any in-flight Chrome whose `TabGuard` was detached by a hard exit and never dropped.
    // Idle browsers cleared above are already dead, so their drained PIDs are simply skipped.
    reap_registered_chrome();
}

/// Runs `shutdown()` when dropped, so every return path from a scan reaps Chrome.
pub struct PoolShutdownGuard;

impl Drop for PoolShutdownGuard {
    fn drop(&mut self) {
        shutdown();
    }
}

/// How many renders may run at once. Resolved once, and reported by [`permits`] — deliberately
/// held separately from the semaphore, whose `available_permits()` counts what is *free right now*
/// rather than the capacity the perf table needs.
static MAX_RENDER_SLOTS: once_cell::sync::Lazy<usize> =
    once_cell::sync::Lazy::new(resolve_max_browser_instances);

/// Build a render-slot semaphore. Split out from the static so the unit tests exercise the same
/// constructor the scan does instead of a hand-built stand-in.
fn new_render_semaphore(slots: usize) -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(slots))
}

/// Global render-slot semaphore.
///
/// This was a hand-rolled `Mutex` + `Condvar` counter, and *both* of its properties were wrong for
/// the way this scan queues:
///
/// * It handed a freed slot off with `notify_one`, which wakes an arbitrary waiter. With
///   `browser.permit_wait` averaging 201.6s across 1,113 acquisitions on the 2026-08-15 depth-3
///   run, queue depth — not render speed — was the render path's cost, and an unlucky render could
///   be skipped over repeatedly with no bound on its wait.
/// * It could only be waited on by *blocking a thread*. Every render site waits inside
///   `spawn_blocking`, so each queued render pinned one of tokio's 512 blocking-pool threads for
///   the whole wait. Past ~512 queued renders the pool is exhausted, and NER inference, WHOIS and
///   HTML extraction — which share that pool — stop being scheduled at all: a priority inversion
///   in which the render *queue* starves the work it is queued behind.
///
/// `tokio::sync::Semaphore` is FIFO by contract, and is waited on by suspending a future rather
/// than parking a thread, so a render can queue before it ever touches the blocking pool.
static RENDER_PERMITS: once_cell::sync::Lazy<Arc<tokio::sync::Semaphore>> =
    once_cell::sync::Lazy::new(|| new_render_semaphore(*MAX_RENDER_SLOTS));

/// How many renders this process can run concurrently.
///
/// The perf attribution table divides serialized render time by this to get the floor the
/// render path imposes on the scan's wall clock.
pub fn permits() -> usize {
    *MAX_RENDER_SLOTS
}

/// A held render slot, plus how long its holder queued for it.
///
/// The slot is owned, not borrowed, so it can be moved into a `spawn_blocking` closure — that
/// move is the whole point: the wait happens in async context and only the *held* slot crosses
/// onto the blocking pool. `OwnedSemaphorePermit` returns the slot from `Drop`, so it is released
/// on every exit path that runs destructors — normal return, `?`, and a panic that unwinds.
///
/// A `panic = "abort"` build runs no destructors, but the process is already dying and the slot
/// dies with it; Chrome itself is still reaped there by the panic hook, which works off
/// `CHROME_PIDS` rather than off this permit.
pub struct RenderPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    waited: std::time::Duration,
}

impl RenderPermit {
    /// How long this caller queued for its render slot.
    ///
    /// Not diagnostic decoration: callers with a time budget must be able to subtract time they
    /// spent queued behind *other* vendors' browsers, or their budget measures how busy the scan
    /// is rather than how much work they did. See
    /// `subprocessor::analyze_domain_with_full_options`.
    pub fn waited(&self) -> std::time::Duration {
        self.waited
    }
}

/// Record the wait and wrap the raw slot. The single place the metric is recorded, so a slot can
/// never be counted twice — which would silently halve the mean the perf table reports.
fn into_render_permit(
    permit: tokio::sync::OwnedSemaphorePermit,
    waited: std::time::Duration,
) -> RenderPermit {
    crate::perf::METRICS.browser_permit_wait.record(waited);
    RenderPermit {
        _permit: permit,
        waited,
    }
}

/// Refuse a render when a launch earlier this run already proved Chrome unlaunchable.
///
/// Callers (subprocessor → static HTML, web-org → HTTP-only, web-traffic → skipped) already
/// degrade gracefully on this `Err`. Checked *before* queueing so a Chrome-less scan does not
/// serialize every render site behind a semaphore it can only fail on, and again after queueing
/// because the latch can flip while a render waits.
fn refuse_if_chrome_unavailable() -> anyhow::Result<()> {
    if chrome_known_unavailable() {
        return Err(anyhow::anyhow!(
            "Chrome/Chromium not installed — skipping browser-based rendering for this target"
        ));
    }
    Ok(())
}

/// Acquire a render slot from async context, **before** entering `spawn_blocking`.
///
/// This is the half of the fix that keeps the render queue off the blocking pool: waiting here
/// suspends a future, so a thousand queued renders cost a thousand cheap wakers instead of a
/// thousand of tokio's 512 blocking threads. Move the returned permit into the `spawn_blocking`
/// closure and hand it to [`acquire_tab_with_permit`]; the slot is released when the blocking work
/// finishes and the resulting [`TabGuard`] drops.
///
/// A site that acquires here must NOT also subtract [`RenderPermit::waited`] from its
/// `RenderTimer`: the wait now happens before the timer is started, so excluding it again
/// subtracts time the timer never counted.
pub async fn acquire_render_permit() -> anyhow::Result<RenderPermit> {
    refuse_if_chrome_unavailable()?;
    let started = std::time::Instant::now();
    let permit = Arc::clone(&*RENDER_PERMITS)
        .acquire_owned()
        .await
        // Unreachable in practice: nothing ever closes a process-global `Lazy` semaphore. Reported
        // rather than unwrapped so a future edit that does close it degrades instead of panicking.
        .map_err(|e| anyhow::anyhow!("render-slot semaphore closed: {e}"))?;
    Ok(into_render_permit(permit, started.elapsed()))
}

/// How a *synchronous* caller must wait for a render slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncWait {
    /// A slot was already free: take it, no waiting and no runtime needed.
    Immediate,
    /// Contended, with a tokio runtime in scope: park on the semaphore's FIFO queue, keeping this
    /// caller's place in line among the async callers queued alongside it.
    ParkOnRuntime,
    /// Contended with no runtime at all: poll. `Handle::block_on` needs a runtime to block on, so
    /// parking here would panic — and with no async callers in existence there is no ordering left
    /// to preserve anyway.
    PollWithoutRuntime,
}

/// Pick the waiting strategy for a synchronous caller. Pure, so the routing rule is exhaustively
/// testable without a runtime or a browser — which matters because two of the three arms are only
/// reachable under conditions a unit test cannot easily stage at the call site.
fn sync_wait_strategy(slot_was_free: bool, runtime_available: bool) -> SyncWait {
    match (slot_was_free, runtime_available) {
        (true, _) => SyncWait::Immediate,
        (false, true) => SyncWait::ParkOnRuntime,
        (false, false) => SyncWait::PollWithoutRuntime,
    }
}

/// Poll interval for the runtime-less fallback. Only ever reached by a synchronous caller with no
/// tokio runtime anywhere (today: `web_org`'s `fetch_page_with_headless` invoked directly from a
/// plain `#[test]`), which is uncontended in practice — so this never spins in a real scan.
const SYNC_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// Block the current thread until a render slot is free.
///
/// **Must be called from a blocking context, never from a runtime worker thread** —
/// `Handle::block_on` panics if the thread it is on is already driving async tasks. Every render
/// site reaches this from inside `spawn_blocking`, which runs on the blocking pool rather than on
/// a worker, so this holds today; [`acquire_render_permit`] exists so that new call sites need not
/// come through here at all.
fn wait_for_slot_blocking(
    sem: Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<tokio::sync::OwnedSemaphorePermit> {
    let handle = tokio::runtime::Handle::try_current().ok();
    // One non-blocking attempt first, so the strategy is chosen on whether this caller is actually
    // contended rather than on whether it might be.
    let free_slot = Arc::clone(&sem).try_acquire_owned().ok();

    match sync_wait_strategy(free_slot.is_some(), handle.is_some()) {
        // Both `expect`s below restate `sync_wait_strategy`'s contract, which its truth-table test
        // pins: `Immediate` is returned only for a taken slot, `ParkOnRuntime` only with a handle.
        SyncWait::Immediate => Ok(free_slot.expect("Immediate implies a slot was taken")),
        SyncWait::ParkOnRuntime => handle
            .expect("ParkOnRuntime implies a runtime handle")
            .block_on(sem.acquire_owned())
            .map_err(|e| anyhow::anyhow!("render-slot semaphore closed: {e}")),
        SyncWait::PollWithoutRuntime => loop {
            std::thread::sleep(SYNC_POLL_INTERVAL);
            if let Ok(permit) = Arc::clone(&sem).try_acquire_owned() {
                return Ok(permit);
            }
        },
    }
}

/// A fresh Chrome tab holding a render permit.
///
/// On drop the tab is closed and its Chrome process is returned to the idle pool for the next
/// render (or killed, if it has served its quota). The permit is released either way.
pub struct TabGuard {
    tab: Arc<headless_chrome::Tab>,
    /// `None` only transiently, while `Drop` moves the browser back into the pool.
    browser: Option<TrackedBrowser>,
    served: usize,
    /// Declared last on purpose. `Drop for TabGuard` runs first (closing the tab and returning or
    /// killing its Chrome), then fields drop in declaration order — so the render slot is released
    /// only once this render has fully let go of its browser, never while a Chrome process is
    /// still being torn down. Moving this field up would let the next render start against a pool
    /// this one has not finished handing back to.
    permit: RenderPermit,
}

impl TabGuard {
    /// The tab this render should drive.
    pub fn tab(&self) -> &headless_chrome::Tab {
        &self.tab
    }

    /// How long this caller waited for a render permit.
    ///
    /// Time-budgeted callers subtract this so their budget bounds their own work rather
    /// than the depth of the queue they happened to land in.
    pub fn permit_wait(&self) -> std::time::Duration {
        self.permit.waited()
    }
}

impl Drop for TabGuard {
    fn drop(&mut self) {
        // Close the tab so its renderer process goes away and `TargetDestroyed` prunes it from
        // the browser's tab vector. A failure here means the browser is unhealthy, so it is not
        // returned to the pool.
        let tab_closed = self.tab.close(false).is_ok();

        if let Some(browser) = self.browser.take() {
            let served = self.served;
            if tab_closed && served < *MAX_RENDERS_PER_BROWSER {
                lock_idle().push(PooledBrowser { browser, served });
            }
            // else: dropping the `TrackedBrowser` deregisters its PID, then the inner `Browser`
            // kills the Chrome process and removes its temp profile.
        }
    }
}

/// Check if running inside a container (Docker, CI, etc.)
fn is_container_env() -> bool {
    is_container_env_inner(
        std::env::var("NTHPARTYFINDER_CONTAINER").is_ok(),
        std::path::Path::new("/.dockerenv").exists(),
    )
}

fn is_container_env_inner(env_var_set: bool, dockerenv_exists: bool) -> bool {
    env_var_set || dockerenv_exists
}

/// Find Chrome/Chromium binary path from env var or well-known locations.
fn find_chrome_binary() -> Option<std::path::PathBuf> {
    find_chrome_binary_inner(
        std::env::var("CHROME_PATH").ok(),
        std::path::Path::new("/mnt/c/Program Files/Google/Chrome/Application/chrome.exe"),
    )
}

fn find_chrome_binary_inner(
    env_path: Option<String>,
    wsl_path: &std::path::Path,
) -> Option<std::path::PathBuf> {
    env_path.map(std::path::PathBuf::from).or_else(|| {
        if wsl_path.exists() {
            Some(wsl_path.to_path_buf())
        } else {
            None
        }
    })
}

/// Atomic counter for assigning unique debug ports to Chrome instances.
static PORT_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(9222);

fn next_debug_port() -> u16 {
    let port = PORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if port > 9322 {
        PORT_COUNTER.store(9222, std::sync::atomic::Ordering::Relaxed);
    }
    port
}

/// Latch recording whether Chrome has proven UNavailable during this run. `0` = not yet determined,
/// `2` = a real launch attempt timed out (a present-but-wedged install, or absent-and-slow). Set
/// ONLY by an actual failed launch ([`note_chrome_unavailable`]), never by a heuristic path probe —
/// so a Chrome the launcher can find (via `PATH`, a snap, a WSL mount, `~/Applications`, or any path
/// `headless_chrome`'s own detection reaches) is never wrongly disabled. Once latched, [`acquire_tab`]
/// fails fast so the rest of the scan doesn't each re-pay the launch timeout. A genuinely absent
/// Chrome fails the launch quickly on its own (no executable to auto-detect), so the common
/// not-installed case degrades without ever waiting the full timeout.
static CHROME_AVAILABILITY: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Record that a real Chrome launch attempt timed out, so subsequent [`acquire_tab`] calls fail fast
/// instead of each re-paying [`BROWSER_LAUNCH_TIMEOUT`]. Idempotent.
fn note_chrome_unavailable() {
    CHROME_AVAILABILITY.store(2, std::sync::atomic::Ordering::Relaxed);
}

/// Whether a prior launch this run proved Chrome unavailable. A container is never treated as
/// unavailable — headless Chrome may find a binary at a path outside our view. Decision logic split
/// out so it is unit-testable.
fn chrome_known_unavailable() -> bool {
    chrome_unavailable_decision(
        CHROME_AVAILABILITY.load(std::sync::atomic::Ordering::Relaxed),
        is_container_env(),
    )
}

fn chrome_unavailable_decision(availability: u8, is_container: bool) -> bool {
    availability == 2 && !is_container
}

/// Hard ceiling on a single Chrome launch. Bounds a *present-but-wedged* Chrome (partial install,
/// missing shared library) so a launch can never hang the scan forever; the first launch that hits
/// this latches [`chrome_known_unavailable`] so the rest of the scan fails fast rather than each
/// waiting the full timeout. A genuinely absent Chrome fails the launch quickly on its own.
const BROWSER_LAUNCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// Build Chrome launch options from the resolved parameters.
fn build_launch_options(
    is_container: bool,
    chrome_path: Option<&std::path::Path>,
    debug_port: u16,
) -> anyhow::Result<headless_chrome::LaunchOptions<'_>> {
    // coverage(off): default_builder().build() always succeeds — error path unreachable
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn map_build_err(e: impl std::fmt::Display) -> anyhow::Error {
        anyhow::anyhow!("Failed to build Chrome launch options: {}", e)
    }
    match (is_container, chrome_path) {
        (true, Some(path)) => headless_chrome::LaunchOptions::default_builder()
            .sandbox(false)
            .path(Some(path.to_path_buf()))
            .port(Some(debug_port))
            .build()
            .map_err(map_build_err),
        (true, None) => headless_chrome::LaunchOptions::default_builder()
            .sandbox(false)
            .port(Some(debug_port))
            .build()
            .map_err(map_build_err),
        (false, Some(path)) => headless_chrome::LaunchOptions::default_builder()
            .path(Some(path.to_path_buf()))
            .port(Some(debug_port))
            .build()
            .map_err(map_build_err),
        (false, None) => headless_chrome::LaunchOptions::default_builder()
            .port(Some(debug_port))
            .build()
            .map_err(map_build_err),
    }
}

/// Launch a fresh Chrome process, timing the launch.
// coverage(off): launches real Chrome processes — all preparation logic is tested via
// is_container_env_inner, find_chrome_binary_inner, next_debug_port, build_launch_options
#[cfg_attr(coverage_nightly, coverage(off))]
fn launch_browser() -> anyhow::Result<TrackedBrowser> {
    let is_container = is_container_env();
    let chrome_path = find_chrome_binary();
    let debug_port = next_debug_port();

    let launch_started = std::time::Instant::now();
    // Bound the launch with a hard timeout: build the options and construct the Browser on a helper
    // thread so a present-but-wedged Chrome can never block the scan forever. On timeout the thread
    // is left to finish on its own; if it eventually produces a Browser the receiver is gone, so the
    // Browser is dropped — and `Browser::drop` kills the Chrome process — leaving nothing leaked.
    // A panic in the thread drops `tx`, which surfaces here as a disconnect → a normal launch error.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = (|| -> anyhow::Result<TrackedBrowser> {
            let browser = if is_container || chrome_path.is_some() {
                let options =
                    build_launch_options(is_container, chrome_path.as_deref(), debug_port)?;
                headless_chrome::Browser::new(options)
                    .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))?
            } else {
                headless_chrome::Browser::default()
                    .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))?
            };
            // Wrap so the PID is registered for reaping now (so every exit path can kill this Chrome
            // by PID even if its `Drop` never runs — timeout `process::exit`, Ctrl-C, or a
            // `panic = "abort"` build) and deregistered when the browser is cleanly dropped.
            Ok(TrackedBrowser::new(browser))
        })();
        let _ = tx.send(result);
    });
    let browser = match rx.recv_timeout(BROWSER_LAUNCH_TIMEOUT) {
        Ok(result) => result?,
        Err(_) => {
            // A launch that hits the hard timeout is a wedged (or absent-and-slow) Chrome. Latch it
            // so the rest of the scan fails fast instead of each render waiting the full timeout.
            note_chrome_unavailable();
            anyhow::bail!(
                "Chrome launch timed out after {:?} — treating it as unavailable for this render",
                BROWSER_LAUNCH_TIMEOUT
            )
        }
    };
    crate::perf::METRICS
        .browser_launch
        .record(launch_started.elapsed());
    Ok(browser)
}

/// The retry rule, isolated from Chrome so it can be tested.
///
/// A retry that pops the pool again gets a *second* dead browser when several died while idle
/// (laptop sleep, OOM-kill), so `acquire_tab` fails where a fresh launch would have succeeded.
/// `force_fresh` must therefore bypass the pool entirely, not merely prefer a launch.
fn take_from_pool<T>(force_fresh: bool, pool: &mut Vec<T>) -> Option<T> {
    if force_fresh {
        return None;
    }
    pool.pop()
}

/// Take a browser from the idle pool, unless the caller demands a freshly launched one.
fn take_pooled(force_fresh: bool) -> Option<PooledBrowser> {
    take_from_pool(force_fresh, &mut lock_idle())
}

/// Synchronous [`acquire_tab_with_permit`], for render sites that have not yet been converted to
/// take their permit in async context.
///
/// Prefer [`acquire_render_permit`] + [`acquire_tab_with_permit`]: this entry point still parks a
/// blocking-pool thread for the whole queue wait, which is the exhaustion this change exists to
/// remove. It is kept correct (and FIFO, since it queues on the same semaphore) so an unconverted
/// site is merely slower, never wrong.
// coverage(off): drives real Chrome processes.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn acquire_tab() -> anyhow::Result<TabGuard> {
    // Before queueing, so a Chrome-less scan does not serialize on the semaphore.
    refuse_if_chrome_unavailable()?;
    let started = std::time::Instant::now();
    let permit = wait_for_slot_blocking(Arc::clone(&*RENDER_PERMITS))?;
    acquire_tab_with_permit(into_render_permit(permit, started.elapsed()))
}

/// Open a fresh Chrome tab against an already-held render slot, reusing a pooled Chrome process
/// when one is available.
///
/// Call this inside `spawn_blocking` with the permit from [`acquire_render_permit`]. The permit
/// moves into the returned [`TabGuard`], so the slot stays held for exactly as long as the tab and
/// its browser do, and is returned however the render ends — success, `?`, or an unwinding panic.
///
/// Opening the tab doubles as the liveness probe for a reused browser: if `new_tab()` fails, that
/// Chrome is discarded and a fresh one is launched. A caller therefore never receives a tab on a
/// wedged process.
// coverage(off): drives real Chrome processes.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn acquire_tab_with_permit(permit: RenderPermit) -> anyhow::Result<TabGuard> {
    // Re-checked after queueing: a render that waited minutes for a slot can find that some other
    // render meanwhile latched Chrome as unlaunchable, and `launch_browser` does not consult the
    // latch itself — so without this it would re-pay the full 45s launch timeout.
    refuse_if_chrome_unavailable()?;

    // At most two attempts: one that may reuse a pooled browser, then one on a guaranteed-fresh
    // launch. `force_fresh` is what makes the second attempt actually fresh — popping the pool
    // again would hand back a second corpse if several pooled browsers died while idle (laptop
    // sleep, OOM-kill), and `acquire_tab` would fail where a fresh launch would have worked.
    // A fresh Chrome that cannot open or isolate a tab is a real failure and is reported.
    let mut last_err: Option<anyhow::Error> = None;
    let mut force_fresh = false;
    for _ in 0..2 {
        let pooled = take_pooled(force_fresh);
        let reused = pooled.is_some();
        let (browser, served) = match pooled {
            Some(p) => (p.browser, p.served),
            None => match launch_browser() {
                Ok(b) => (b, 0),
                Err(e) => {
                    last_err = Some(e);
                    force_fresh = true;
                    continue;
                }
            },
        };

        match browser
            .new_tab()
            .map_err(|e| anyhow::anyhow!("Failed to create browser tab: {e}"))
        {
            Ok(tab) => {
                // A reused browser carries the previous render's cookies, and any browser can be
                // asked to serve a response out of its cache. If we cannot establish those
                // isolation invariants we must NOT render on it — both silently change what the
                // response interceptors read. Fail over to a fresh process instead.
                if let Err(e) = isolate_tab(&tab) {
                    last_err = Some(e.context("failed to reset browser network state"));
                    force_fresh = true;
                    continue; // dropping `browser` kills it
                }
                if reused {
                    crate::perf::METRICS.browser_reuse.hit();
                }
                return Ok(TabGuard {
                    tab,
                    browser: Some(browser),
                    served: served + 1,
                    permit,
                });
            }
            Err(e) => {
                // Dropping `browser` kills it. Next attempt must launch, not pop another corpse.
                last_err = Some(e);
                force_fresh = true;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Failed to acquire a headless Chrome tab")))
}

/// Restore the cold-profile invariant that per-render Chrome processes used to provide for free.
///
/// A pooled `Browser` serves up to [`MAX_RENDERS_PER_BROWSER`] renders across *different vendors*,
/// sharing one HTTP cache and one cookie jar. Two consequences, both accuracy bugs rather than
/// performance ones:
///
/// * `trust_center::discovery` and `discovery::web_traffic` extract subprocessors by intercepting
///   network responses and calling CDP `getResponseBody`. A response served from the disk cache
///   may carry no retrievable body, and the handler skips it silently — so a vendor whose
///   subprocessor JSON was already fetched on this browser could under-report. Fresh-per-render
///   made this structurally impossible; reuse does not.
/// * A dismissed cookie wall or pre-populated storage from a previous vendor can change which
///   organisation strings a page renders.
///
/// A service worker registered by an earlier render can serve a later same-origin response out of
/// Cache Storage, which reproduces the `getResponseBody` failure even with the HTTP cache off —
/// so it is bypassed too.
///
/// The first is handled by *ignoring* the cache for the render's whole session rather than by
/// emptying it — see `setCacheDisabled` below for why that distinction cost every render in the
/// scan when it was got wrong. The second needs the cookie jar genuinely emptied, so that clear
/// stays. Each of these calls costs ~ms against a 14s mean render. The browser is exclusively held
/// here — it was popped off the idle pool — so the browser-wide cookie clear cannot race another
/// render.
///
/// **Residual, stated rather than papered over:** `localStorage`, `sessionStorage`, and IndexedDB
/// still persist per-origin across renders on a reused browser. Total isolation would need a
/// disposable incognito context, and headless_chrome 1.0.22 exposes no way to *send*
/// `Target.disposeBrowserContext` (`Browser` has no `call_method`; `Context` has no `Drop`), so
/// per-render contexts would accumulate for the life of the process — a worse leak than the bug.
/// The residual cannot cause the interceptors to miss a response body (the silent-data-loss
/// class); it can at most change page-rendered org strings if a site persists dismissal state in
/// web storage. Tracked as TF-POOL-WEBSTORAGE.
// coverage(off): drives real Chrome processes.
#[cfg_attr(coverage_nightly, coverage(off))]
fn isolate_tab(tab: &Arc<headless_chrome::Tab>) -> anyhow::Result<()> {
    use headless_chrome::protocol::cdp::Network;

    // Every call here is O(1) against Chrome's in-memory state, so each is synchronous and fatal:
    // a Chrome that cannot answer one of these is broken, not busy, and failing over to a fresh
    // process is the right response. That property is what `Network.clearBrowserCache` — removed
    // below — did not have.
    //
    // `setCacheDisabled` requires the Network domain. Enabling twice is a no-op; the response
    // handlers enable it again themselves.
    tab.call_method(Network::Enable {
        max_total_buffer_size: None,
        max_resource_buffer_size: None,
        max_post_data_size: None,
        report_direct_socket_traffic: None,
        enable_durable_messages: None,
    })
    .map_err(|e| anyhow::anyhow!("Network.enable failed: {e}"))?;

    // THIS is what keeps a cached body from reaching `getResponseBody`. With the cache ignored for
    // every request on this session, no response can be served from — or written to — the disk
    // cache, so the interceptors always see a real body.
    //
    // A `Network.clearBrowserCache` call used to follow, on the theory that a reused browser's warm
    // cache could still poison a render. It cannot: measured against a browser whose cache had been
    // warmed by a full render, a second render in a new tab with only `setCacheDisabled` retrieved
    // 38/38 response bodies with zero failures and zero responses served `fromDiskCache`. The clear
    // was redundant — and expensive in a way that broke everything: it is disk-backend-bound and
    // costs ~4-8s on the FIRST call against a given profile (measured 4038ms and 8471ms cold, then
    // 89-578ms warm). Every render launches Chrome with a fresh temp profile, so every render paid
    // the cold cost, and under scan load that exceeded the 30s `idle_browser_timeout` bounding every
    // `call_method`. Since the failure was fatal here, *every render in the scan died* (Chrome 150,
    // 2026-07-31: web-traffic capture, trust-center render-capture and the subprocessor SPA fallback
    // all returned "failed to reset browser network state", collapsing subprocessor recall to zero).
    //
    // Deleting it — rather than making it best-effort or conditional on reuse — is deliberate. Any
    // scheme that still issues it merely relocates the cold call: skipping fresh launches moves the
    // first-ever call to the browser's first *reuse*, i.e. inside the render path, where a late
    // completion can mutate browser state mid-render.
    tab.call_method(Network::SetCacheDisabled {
        cache_disabled: true,
    })
    .map_err(|e| anyhow::anyhow!("Network.setCacheDisabled failed: {e}"))?;
    tab.call_method(Network::SetBypassServiceWorker { bypass: true })
        .map_err(|e| anyhow::anyhow!("Network.setBypassServiceWorker failed: {e}"))?;

    // Cookies stay cleared, synchronously and before the render, exactly as before. This is not
    // redundant the way the cache clear was: `setCacheDisabled` says nothing about the cookie jar,
    // and a pooled browser serves several vendors that can share one origin — every Vanta-hosted
    // trust centre is `trust.vanta.com/{company}` — so a previous vendor's consent state or session
    // cookie really can change what the next one renders. It is also cheap enough to keep on the
    // critical path: measured 0-1ms even as the first call against a cold profile.
    tab.call_method(Network::ClearBrowserCookies(None))
        .map_err(|e| anyhow::anyhow!("Network.clearBrowserCookies failed: {e}"))?;

    // NB: none of this closes Chrome's accumulated idle keep-alive sockets — those live in Chrome's
    // process-global connection pool, out of reach of a per-session CDP call. Bounding that
    // accumulation is the job of the low per-browser render quota (MAX_RENDERS_PER_BROWSER), whose
    // full-teardown retirement is the only guaranteed socket release.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────
    // Render-slot semaphore
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_render_semaphore_starts_with_every_slot_free() {
        let sem = new_render_semaphore(3);
        assert_eq!(sem.available_permits(), 3);
    }

    /// The ceiling is the whole point of the semaphore: each concurrent browser is the scan's
    /// dominant open-socket consumer, so handing out an extra slot directly inflates the peak
    /// socket footprint that `MAX_RENDER_PERMITS` was lowered to bound.
    #[test]
    fn test_render_semaphore_hands_out_no_more_slots_than_it_has() {
        let sem = new_render_semaphore(2);
        let _first = Arc::clone(&sem).try_acquire_owned().expect("slot 1 of 2");
        let _second = Arc::clone(&sem).try_acquire_owned().expect("slot 2 of 2");
        assert!(
            Arc::clone(&sem).try_acquire_owned().is_err(),
            "a third concurrent render must not get a slot"
        );
    }

    #[test]
    fn test_render_slot_is_returned_on_drop() {
        let sem = new_render_semaphore(2);
        let first = Arc::clone(&sem).try_acquire_owned().expect("slot 1 of 2");
        let second = Arc::clone(&sem).try_acquire_owned().expect("slot 2 of 2");
        assert_eq!(sem.available_permits(), 0);
        drop(second);
        assert_eq!(sem.available_permits(), 1);
        drop(first);
        assert_eq!(sem.available_permits(), 2);
    }

    /// A render that panics mid-flight must still hand its slot back. If it did not, every panic
    /// would permanently shrink the scan's render parallelism — the same class of leak that
    /// `CHROME_PIDS` exists to prevent for the Chrome process itself.
    #[test]
    fn test_render_slot_is_returned_when_its_holder_panics() {
        let sem = new_render_semaphore(1);
        let holder = Arc::clone(&sem);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _slot = holder.try_acquire_owned().expect("the only slot");
            panic!("render panicked while holding a slot");
        }));
        assert!(outcome.is_err(), "the closure must actually have panicked");
        assert_eq!(
            sem.available_permits(),
            1,
            "a panicking render must not strand its slot"
        );
    }

    /// The property the hand-rolled `Condvar` semaphore did NOT have, and the reason
    /// `browser.permit_wait` had an unbounded tail: `notify_one` wakes an arbitrary waiter, so a
    /// queued render could be skipped over repeatedly while later arrivals went first. Renders
    /// must be served strictly in the order they queued.
    #[tokio::test]
    async fn test_render_slots_are_served_first_come_first_served() {
        let sem = new_render_semaphore(1);
        let held = Arc::clone(&sem)
            .acquire_owned()
            .await
            .expect("the only slot");

        let served = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut waiters = Vec::new();
        for position in 0..6 {
            let sem = Arc::clone(&sem);
            let served = Arc::clone(&served);
            waiters.push(tokio::spawn(async move {
                let _slot = sem.acquire_owned().await.expect("a slot once one frees");
                served.lock().expect("served log").push(position);
            }));
            // `#[tokio::test]` runs a current-thread runtime, so yielding lets the task just
            // spawned run until it parks on the semaphore — which is what fixes its place in the
            // queue before the next one is spawned. Without this the enqueue order is undefined
            // and the assertion below would be testing nothing.
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
        }

        drop(held);
        for waiter in waiters {
            waiter.await.expect("waiter task");
        }

        assert_eq!(
            *served.lock().expect("served log"),
            vec![0, 1, 2, 3, 4, 5],
            "renders must be served in the order they queued"
        );
    }

    /// The wait is the measurement `subprocessor::analyze_domain_with_full_options` subtracts from
    /// its per-domain budget, so a silently-zero wait re-introduces concurrency-dependent recall
    /// loss. It must reflect the real time queued, and the slot must outlive the report.
    #[tokio::test]
    async fn test_render_permit_reports_time_queued_and_frees_its_slot_on_drop() {
        let sem = new_render_semaphore(1);
        let held = Arc::clone(&sem)
            .acquire_owned()
            .await
            .expect("the only slot");

        let queued = Arc::clone(&sem);
        let waiter = tokio::spawn(async move {
            let started = std::time::Instant::now();
            let slot = queued.acquire_owned().await.expect("a slot once one frees");
            into_render_permit(slot, started.elapsed())
        });

        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        drop(held);

        let permit = waiter.await.expect("waiter task");
        assert!(
            permit.waited() >= std::time::Duration::from_millis(100),
            "a queued render must report the time it spent waiting, got {:?}",
            permit.waited()
        );
        assert_eq!(
            sem.available_permits(),
            0,
            "the slot is still held while the permit is alive"
        );
        drop(permit);
        assert_eq!(
            sem.available_permits(),
            1,
            "dropping the permit returns the slot"
        );
    }

    /// An uncontended acquire must report ~nothing, so the perf table's mean is not inflated by
    /// renders that never actually queued.
    #[tokio::test]
    async fn test_uncontended_render_permit_reports_no_meaningful_wait() {
        let sem = new_render_semaphore(2);
        let started = std::time::Instant::now();
        let slot = Arc::clone(&sem).acquire_owned().await.expect("a free slot");
        let permit = into_render_permit(slot, started.elapsed());
        assert!(
            permit.waited() < std::time::Duration::from_millis(50),
            "uncontended acquire should not report a meaningful wait, got {:?}",
            permit.waited()
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // sync_wait_strategy — how a synchronous caller waits for a slot
    // ──────────────────────────────────────────────────────────────────

    /// Getting any arm wrong is a panic or a stall, not a slow path: parking without a runtime
    /// panics inside `Handle::block_on`, and polling when a runtime *is* available silently drops
    /// this caller out of the FIFO queue it shares with the async callers.
    #[test]
    fn sync_wait_strategy_truth_table() {
        assert_eq!(
            sync_wait_strategy(true, true),
            SyncWait::Immediate,
            "a free slot is taken outright, runtime or not"
        );
        assert_eq!(
            sync_wait_strategy(true, false),
            SyncWait::Immediate,
            "a free slot never needs a runtime"
        );
        assert_eq!(
            sync_wait_strategy(false, true),
            SyncWait::ParkOnRuntime,
            "contended with a runtime must queue in FIFO order alongside the async callers"
        );
        assert_eq!(
            sync_wait_strategy(false, false),
            SyncWait::PollWithoutRuntime,
            "contended with no runtime must poll — block_on has no runtime to block on"
        );
    }

    /// `web_org::fetch_page_with_headless` is called directly from a plain `#[test]`, with no
    /// tokio runtime anywhere. That caller must still be served.
    #[test]
    fn test_wait_for_slot_blocking_serves_an_uncontended_caller_with_no_runtime() {
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "this test must run outside a runtime for the fallback to be the path under test"
        );
        let sem = new_render_semaphore(1);
        let permit = wait_for_slot_blocking(Arc::clone(&sem)).expect("an uncontended slot");
        assert_eq!(sem.available_permits(), 0);
        drop(permit);
        assert_eq!(sem.available_permits(), 1);
    }

    /// The runtime-less *contended* path — the poll loop. Two plain threads, no runtime: the
    /// waiter must still be handed the slot once it frees rather than spinning forever.
    #[test]
    fn test_wait_for_slot_blocking_polls_to_completion_with_no_runtime() {
        let sem = new_render_semaphore(1);
        let held = Arc::clone(&sem).try_acquire_owned().expect("the only slot");

        let queued = Arc::clone(&sem);
        let waiter = std::thread::spawn(move || wait_for_slot_blocking(queued));

        std::thread::sleep(std::time::Duration::from_millis(80));
        drop(held);

        let permit = waiter
            .join()
            .expect("waiter thread")
            .expect("a slot once one frees");
        drop(permit);
        assert_eq!(sem.available_permits(), 1);
    }

    /// The unconverted sync path parks with `Handle::block_on`, which panics if it is called on a
    /// thread already driving async tasks. Every render site reaches it from inside
    /// `spawn_blocking`, so this pins that this really is a legal place to block — and that the
    /// caller genuinely waits rather than being handed a slot that is still held.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_wait_for_slot_blocking_parks_inside_spawn_blocking_until_a_slot_frees() {
        let sem = new_render_semaphore(1);
        let held = Arc::clone(&sem)
            .acquire_owned()
            .await
            .expect("the only slot");

        let queued = Arc::clone(&sem);
        let waiter = tokio::task::spawn_blocking(move || wait_for_slot_blocking(queued));

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !waiter.is_finished(),
            "must still be queued while the only slot is held"
        );

        drop(held);
        let permit = waiter
            .await
            .expect("blocking task")
            .expect("a slot once one frees");
        drop(permit);
        assert_eq!(sem.available_permits(), 1);
    }

    /// The auto-sized pool must stay inside its bounds on any host. The floor exists so a small
    /// CI runner never ends up with fewer render slots than the historical fixed 4; the ceiling
    /// bounds Chrome's child-process memory.
    #[test]
    fn test_resolve_max_browser_instances_bounds() {
        let auto = resolve_max_browser_instances();
        assert!(
            (MIN_RENDER_PERMITS..=MAX_RENDER_PERMITS).contains(&auto),
            "auto-sized pool {auto} outside [{MIN_RENDER_PERMITS}, {MAX_RENDER_PERMITS}] \
             — a small host must never get a smaller pool than the historical default"
        );
    }

    /// The floor is the historical fixed pool size. Lowering it would silently reduce render
    /// parallelism on small hosts relative to the version this replaced.
    #[test]
    fn test_render_permit_floor_matches_historical_pool_size() {
        assert_eq!(MIN_RENDER_PERMITS, 4);
    }

    /// Recycling bounds BOTH the memory a long-lived Chrome accumulates and (the reason the quota
    /// is now low) its accumulated ESTABLISHED sockets: a full retire is the only guaranteed socket
    /// release. The quota must stay low enough to bound the socket high-water mark yet high enough
    /// that a ~2s launch is still amortised across several renders.
    #[test]
    fn test_renders_per_browser_bounds_sockets_yet_amortises_launch() {
        assert!(
            (2..=20).contains(&DEFAULT_MAX_RENDERS_PER_BROWSER),
            "recycle quota {DEFAULT_MAX_RENDERS_PER_BROWSER} should be low enough to bound socket \
             accumulation while still amortising the launch across several renders"
        );
    }

    #[test]
    fn test_resolve_max_renders_per_browser_default() {
        if std::env::var("NTHPARTYFINDER_RENDERS_PER_BROWSER").is_err() {
            assert_eq!(
                resolve_max_renders_per_browser(),
                DEFAULT_MAX_RENDERS_PER_BROWSER
            );
        }
        assert!(resolve_max_renders_per_browser() >= 1);
    }

    /// `shutdown()` is the only thing that reaps pooled Chrome processes, because the pool is a
    /// `Lazy` static and statics never run `Drop`. It must be safe to call on an empty pool and
    /// must leave the pool empty.
    #[test]
    fn test_shutdown_empties_the_idle_pool_and_is_idempotent() {
        shutdown();
        assert_eq!(lock_idle().len(), 0);
        shutdown();
        assert_eq!(lock_idle().len(), 0, "shutdown must be idempotent");
    }

    /// The PID reap only fires on a process that still looks like a browser we launched — the guard
    /// against the OS recycling a dead Chrome's PID for something unrelated before shutdown runs.
    /// Chrome names contain `chrom`; the standalone `headless_shell` distributable is matched by
    /// `headless`.
    #[test]
    fn test_looks_like_chrome_matches_browser_process_names() {
        for name in [
            "chrome",
            "Chromium",
            "Google Chrome for Testing",
            "chrome_crashpad_handler",
            "CHROME",
            "chrome-headless-shell",
            "headless_shell",
        ] {
            assert!(
                looks_like_chrome(name),
                "{name} should be treated as a launched browser"
            );
        }
    }

    /// A registered PID recycled onto a non-browser process must never be killed.
    #[test]
    fn test_looks_like_chrome_rejects_non_browser_process_names() {
        for name in ["firefox", "bash", "nthpartyfinder", "", "com.apple.WebKit"] {
            assert!(
                !looks_like_chrome(name),
                "{name} must not be mistaken for Chrome"
            );
        }
    }

    /// The startup orphan sweep must ONLY ever match a process that both (a) carries our exact
    /// profile-dir signature — never just "looks like Chrome" by name, which would equally match
    /// the operator's own real browser or another tool's headless Chrome — AND (b) has no living
    /// parent. Either condition failing must refuse the match.
    #[test]
    fn test_is_orphaned_chrome_of_ours_requires_signature_and_no_parent() {
        let our_cmdline = "/usr/bin/chrome --headless --user-data-dir=/tmp/rust-headless-chrome-profileAB12cd --remote-debugging-port=9222";
        assert!(
            is_orphaned_chrome_of_ours(our_cmdline, false),
            "our signature + no living parent = a genuine orphan to reap"
        );
        assert!(
            !is_orphaned_chrome_of_ours(our_cmdline, true),
            "our signature but a LIVE parent means a concurrent scan (or this run itself) still owns it — must not kill"
        );
        let real_browser_cmdline =
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --profile-directory=Default";
        assert!(
            !is_orphaned_chrome_of_ours(real_browser_cmdline, false),
            "the operator's own real Chrome must never match, even if it happens to have no living parent"
        );
        let other_tool_cmdline =
            "/usr/bin/chrome --headless --user-data-dir=/tmp/puppeteer_dev_chrome_profile-xyz";
        assert!(
            !is_orphaned_chrome_of_ours(other_tool_cmdline, false),
            "another automation tool's headless Chrome (different profile-dir convention) must not match"
        );
    }

    /// Draining takes every PID and leaves the set empty, so a second reap is a no-op and no PID
    /// is killed twice.
    #[test]
    fn test_drain_pids_returns_all_and_empties() {
        let mut set = std::collections::HashSet::from([101u32, 202, 303]);
        let mut drained = drain_pids(&mut set);
        drained.sort_unstable();
        assert_eq!(drained, vec![101, 202, 303]);
        assert!(set.is_empty(), "drain must leave the set empty");
        assert!(
            drain_pids(&mut set).is_empty(),
            "draining an empty set yields nothing"
        );
    }

    /// A launched PID is recorded so a later reap can find it, and deregistering on clean drop
    /// removes it so the terminal reap can never target a recycled PID. This is the only unit test
    /// that touches the process-global registry, so its drains are race-free.
    #[test]
    fn test_register_then_deregister_chrome_pid() {
        // Implausibly high values: never live PIDs on the test host, so nothing real is at risk.
        let registered = 4_000_000_001u32;
        let retired = 4_000_000_002u32;

        register_chrome_pid(registered);
        register_chrome_pid(retired);
        // A cleanly-dropped browser deregisters its PID; the reap must then not see it.
        deregister_chrome_pid(retired);

        let drained = drain_pids(&mut lock_pids());
        assert!(
            drained.contains(&registered),
            "an in-flight registered PID must remain drainable for reaping"
        );
        assert!(
            !drained.contains(&retired),
            "a deregistered PID must not remain for reaping"
        );
    }

    /// `acquire_tab` retries once after a pooled browser fails. If the retry pops the pool again
    /// it collects a *second* corpse whenever several browsers died while idle (laptop sleep,
    /// OOM-kill), and the render fails where a fresh launch would have succeeded. `force_fresh`
    /// must bypass the pool entirely, even when the pool is full.
    #[test]
    fn test_forced_fresh_retry_never_takes_another_pooled_browser() {
        let mut pool = vec!["corpse-a", "corpse-b"];

        assert_eq!(
            take_from_pool(true, &mut pool),
            None,
            "a forced-fresh retry must not pop, even with browsers available"
        );
        assert_eq!(
            pool.len(),
            2,
            "a forced-fresh retry must not disturb the pool"
        );

        assert_eq!(
            take_from_pool(false, &mut pool),
            Some("corpse-b"),
            "the normal path still reuses the most-recently-returned browser"
        );
        assert_eq!(pool.len(), 1);
    }

    /// An empty pool yields nothing on either path, so `acquire_tab` falls through to a launch.
    #[test]
    fn test_take_from_empty_pool_yields_none_on_both_paths() {
        let mut pool: Vec<&str> = Vec::new();
        assert_eq!(take_from_pool(false, &mut pool), None);
        assert_eq!(take_from_pool(true, &mut pool), None);
    }

    /// The guard exists so every exit path from a scan reaps Chrome, including `?` and `bail!`.
    #[test]
    fn test_pool_shutdown_guard_drains_on_drop() {
        {
            let _g = PoolShutdownGuard;
        }
        assert_eq!(lock_idle().len(), 0);
    }

    /// A poisoned mutex must not take down the browser pool: the guarded value is a plain Vec
    /// of idle processes, so recovering the inner value is always safe.
    #[test]
    fn test_lock_idle_recovers_from_poison() {
        let _ = std::panic::catch_unwind(|| {
            let _guard = lock_idle();
            panic!("poison the idle-pool mutex");
        });
        // Must not panic.
        let guard = lock_idle();
        drop(guard);
    }

    /// Every slot must come back after a burst of contended renders — a leak of even one would
    /// permanently narrow the render path for the rest of the scan.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_every_slot_returns_after_a_contended_burst() {
        let sem = new_render_semaphore(4);
        let mut renders = Vec::new();
        for _ in 0..16 {
            let sem = Arc::clone(&sem);
            renders.push(tokio::spawn(async move {
                let _slot = sem.acquire_owned().await.expect("a slot");
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }));
        }
        for render in renders {
            render.await.expect("render task");
        }
        assert_eq!(
            sem.available_permits(),
            4,
            "all four slots must be free once every render has finished"
        );
    }

    /// A single-slot semaphore is the degenerate case that serializes every render; it must still
    /// hand the slot back rather than deadlocking the scan on its own first render.
    #[test]
    fn test_single_slot_semaphore_recycles_its_only_slot() {
        let sem = new_render_semaphore(1);
        for _ in 0..10 {
            let slot = Arc::clone(&sem).try_acquire_owned().expect("the only slot");
            assert_eq!(sem.available_permits(), 0);
            drop(slot);
        }
        assert_eq!(sem.available_permits(), 1);
    }

    /// `permits()` must report the *configured* capacity, not what is free right now — the perf
    /// attribution table divides serialized render time by it to get the render path's floor, so
    /// reading `available_permits()` instead would make that floor drift with live load.
    #[test]
    fn test_permits_reports_capacity_not_currently_free_slots() {
        assert_eq!(permits(), *MAX_RENDER_SLOTS);

        let sem = new_render_semaphore(3);
        let _held = Arc::clone(&sem).try_acquire_owned().expect("a slot");
        assert_eq!(
            sem.available_permits(),
            2,
            "available_permits() shrinks under load, which is exactly why permits() must not use it"
        );
        assert_eq!(permits(), *MAX_RENDER_SLOTS, "capacity is load-independent");
    }

    /// The global semaphore must initialise to the same capacity `permits()` advertises, or the
    /// perf table's divisor describes a pool that does not exist.
    #[test]
    fn test_global_render_semaphore_is_sized_to_permits() {
        assert!(
            RENDER_PERMITS.available_permits() <= permits(),
            "the global semaphore can never have more free slots than its capacity"
        );
        assert!(
            permits() > 0,
            "a zero-slot pool would deadlock every render"
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // is_container_env_inner
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_container_env_inner_both_false() {
        assert!(!is_container_env_inner(false, false));
    }

    #[test]
    fn test_is_container_env_inner_env_var_set() {
        assert!(is_container_env_inner(true, false));
    }

    #[test]
    fn test_is_container_env_inner_dockerenv_exists() {
        assert!(is_container_env_inner(false, true));
    }

    #[test]
    fn test_is_container_env_inner_both_true() {
        assert!(is_container_env_inner(true, true));
    }

    #[test]
    fn test_is_container_env_returns_bool() {
        // On a dev machine, should be false; in CI/Docker, true.
        // Either way, should not panic.
        let _result = is_container_env();
    }

    // ──────────────────────────────────────────────────────────────────
    // chrome_unavailable_decision — fail-fast gate for a missing Chrome
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn chrome_unavailable_decision_truth_table() {
        // availability: 0 = unprobed, 1 = available, 2 = unavailable.
        // Only a positive "unavailable" probe (2) outside a container fails fast; everything else
        // still attempts a launch (unprobed and available never fail fast; a container never does).
        assert!(
            chrome_unavailable_decision(2, false),
            "probed-absent, no container → fail fast"
        );
        assert!(
            !chrome_unavailable_decision(2, true),
            "container is never treated as unavailable"
        );
        assert!(
            !chrome_unavailable_decision(1, false),
            "probed-present → attempt"
        );
        assert!(
            !chrome_unavailable_decision(0, false),
            "unprobed → attempt (never over-block)"
        );
        assert!(
            !chrome_unavailable_decision(0, true),
            "unprobed in container → attempt"
        );
    }

    #[test]
    fn note_chrome_unavailable_latches_fast_fail() {
        // A real launch timeout latches so subsequent acquire_tab calls fail fast instead of each
        // re-paying the launch timeout. The latch is driven ONLY by an actual failed launch — never
        // a heuristic probe — so a launchable Chrome is never wrongly disabled.
        CHROME_AVAILABILITY.store(0, std::sync::atomic::Ordering::Relaxed); // unprobed
        assert!(!chrome_known_unavailable(), "unprobed → still attempt");
        note_chrome_unavailable();
        // Only meaningful off a container host; is_container_env() is false on the test box.
        if !is_container_env() {
            assert!(
                chrome_known_unavailable(),
                "after a launch timeout → fail fast"
            );
        }
        // Restore the unprobed default so test ordering can't leak this state.
        CHROME_AVAILABILITY.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    // ──────────────────────────────────────────────────────────────────
    // find_chrome_binary_inner
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_find_chrome_binary_inner_env_path() {
        let result = find_chrome_binary_inner(
            Some("/usr/bin/chrome".to_string()),
            std::path::Path::new("/nonexistent"),
        );
        assert_eq!(result, Some(std::path::PathBuf::from("/usr/bin/chrome")));
    }

    #[test]
    fn test_find_chrome_binary_inner_no_env_wsl_missing() {
        let result =
            find_chrome_binary_inner(None, std::path::Path::new("/nonexistent/wsl/chrome.exe"));
        assert!(result.is_none());
    }

    #[test]
    fn test_find_chrome_binary_inner_no_env_wsl_exists() {
        let dir = tempfile::tempdir().unwrap();
        let fake_wsl = dir.path().join("chrome.exe");
        std::fs::write(&fake_wsl, b"fake").unwrap();

        let result = find_chrome_binary_inner(None, &fake_wsl);
        assert_eq!(result, Some(fake_wsl));
    }

    #[test]
    fn test_find_chrome_binary_inner_env_takes_priority_over_wsl() {
        let dir = tempfile::tempdir().unwrap();
        let fake_wsl = dir.path().join("chrome.exe");
        std::fs::write(&fake_wsl, b"fake").unwrap();

        let result = find_chrome_binary_inner(Some("/custom/chrome".to_string()), &fake_wsl);
        // env var path wins (even if WSL path exists)
        assert_eq!(result, Some(std::path::PathBuf::from("/custom/chrome")));
    }

    #[test]
    fn test_find_chrome_binary_returns_option() {
        let _result = find_chrome_binary();
    }

    // ──────────────────────────────────────────────────────────────────
    // next_debug_port
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_next_debug_port_increments() {
        let p1 = next_debug_port();
        let p2 = next_debug_port();
        // Ports should differ (monotonic increment, ignoring wraparound)
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_next_debug_port_wraparound() {
        // Force the counter to 9323 (above threshold)
        PORT_COUNTER.store(9323, std::sync::atomic::Ordering::Relaxed);
        let port = next_debug_port();
        // fetch_add returns 9323, which is > 9322, so store(9222) fires
        assert_eq!(port, 9323);
        // Counter was reset to 9222; next call returns 9222
        let port2 = next_debug_port();
        assert_eq!(port2, 9222);
    }

    // ──────────────────────────────────────────────────────────────────
    // build_launch_options
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_build_launch_options_no_container_no_path() {
        let opts = build_launch_options(false, None, 9222);
        assert!(opts.is_ok());
    }

    #[test]
    fn test_build_launch_options_container_no_path() {
        let opts = build_launch_options(true, None, 9250);
        assert!(opts.is_ok());
    }

    #[test]
    fn test_build_launch_options_no_container_with_path() {
        let opts = build_launch_options(false, Some(std::path::Path::new("/usr/bin/chrome")), 9260);
        assert!(opts.is_ok());
    }

    #[test]
    fn test_build_launch_options_container_with_path() {
        let opts = build_launch_options(true, Some(std::path::Path::new("/usr/bin/chrome")), 9270);
        assert!(opts.is_ok());
    }
}
