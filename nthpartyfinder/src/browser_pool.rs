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
//! Uses std::sync primitives so it works in both async and sync (spawn_blocking) contexts.

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
/// parallelism is not the scan's throughput limit; it was only ever the launch cost.
const MAX_RENDER_PERMITS: usize = 8;

/// Gigabytes of headroom assumed per concurrent Chrome. Deliberately conservative: Chrome's
/// renderer processes live outside this process's RSS, so we cannot measure them from here.
const GB_PER_BROWSER: u64 = 3;

/// Renders one Chrome process serves before it is retired and relaunched.
///
/// A long-lived headless Chrome accumulates memory and eventually degrades: operators running
/// this at scale recycle every ~100 renders. 50 is half that, chosen because a depth-3 scan
/// does only ~270 renders in total, so the launch cost is still amortised ~50× while the
/// process never gets near the degradation regime.
const MAX_RENDERS_PER_BROWSER: usize = 50;

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
        return n.min(MAX_RENDER_PERMITS);
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
/// shortly after; `scripts/safe-scan.sh` sweeps any straggler that outlives its parent as a
/// backstop.
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
/// lock is still drained. Temp profile dirs are left for `scripts/safe-scan.sh` to sweep; a hung
/// network beats a clean `/tmp`.
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

/// Global counting semaphore for browser instances.
static BROWSER_SEMAPHORE: once_cell::sync::Lazy<BrowserSemaphore> =
    once_cell::sync::Lazy::new(|| BrowserSemaphore::new(resolve_max_browser_instances()));

/// How many renders this process can run concurrently.
///
/// The perf attribution table divides serialized render time by this to get the floor the
/// render path imposes on the scan's wall clock.
pub fn permits() -> usize {
    BROWSER_SEMAPHORE.max
}

/// A simple counting semaphore using std::sync primitives.
/// Unlike tokio::sync::Semaphore, this works in synchronous contexts
/// (e.g., inside spawn_blocking closures).
struct BrowserSemaphore {
    state: std::sync::Mutex<usize>,
    condvar: std::sync::Condvar,
    max: usize,
}

impl BrowserSemaphore {
    fn new(max: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(0),
            condvar: std::sync::Condvar::new(),
            max,
        }
    }

    /// Acquire a permit, blocking until one is available. Returns the permit and how long
    /// the caller was blocked waiting for it.
    ///
    /// The wait duration is not diagnostic decoration: callers with a time budget must be
    /// able to subtract time they spent queued behind *other* vendors' browsers, or their
    /// budget measures how busy the scan is rather than how much work they did. See
    /// `subprocessor::analyze_domain_with_full_options`.
    ///
    /// Mutex/Condvar poison is recovered (not unwrapped): the guarded value is a
    /// simple permit counter, so a peer thread panicking while holding the lock
    /// must not take down the whole browser pool. `into_inner()` returns the
    /// still-valid counter so acquisition continues.
    fn acquire(&self) -> (BrowserPermit<'_>, std::time::Duration) {
        let started = std::time::Instant::now();
        let mut count = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *count >= self.max {
            count = self
                .condvar
                .wait(count)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        *count += 1;
        (BrowserPermit { semaphore: self }, started.elapsed())
    }

    fn release(&self) {
        let mut count = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *count -= 1;
        self.condvar.notify_one();
    }
}

/// RAII guard that releases a browser semaphore permit on drop.
struct BrowserPermit<'a> {
    semaphore: &'a BrowserSemaphore,
}

impl<'a> Drop for BrowserPermit<'a> {
    fn drop(&mut self) {
        self.semaphore.release();
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
    _permit: BrowserPermit<'static>,
    permit_wait: std::time::Duration,
}

impl TabGuard {
    /// The tab this render should drive.
    pub fn tab(&self) -> &headless_chrome::Tab {
        &self.tab
    }

    /// How long this caller blocked waiting for a render permit.
    ///
    /// Time-budgeted callers subtract this so their budget bounds their own work rather
    /// than the depth of the queue they happened to land in.
    pub fn permit_wait(&self) -> std::time::Duration {
        self.permit_wait
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
            if tab_closed && served < MAX_RENDERS_PER_BROWSER {
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
    let browser = if is_container || chrome_path.is_some() {
        let options = build_launch_options(is_container, chrome_path.as_deref(), debug_port)?;
        headless_chrome::Browser::new(options)
            .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))?
    } else {
        headless_chrome::Browser::default()
            .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))?
    };
    crate::perf::METRICS
        .browser_launch
        .record(launch_started.elapsed());
    // Wrap so the PID is registered for reaping now (so every exit path can kill this Chrome by PID
    // even if its `Drop` never runs — timeout `process::exit`, Ctrl-C, or a `panic = "abort"` build)
    // and deregistered when the browser is cleanly dropped.
    Ok(TrackedBrowser::new(browser))
}

/// Acquire a render permit and a fresh Chrome tab, reusing a pooled Chrome process when one is
/// available. Blocks until a permit is free.
///
/// Opening the tab doubles as the liveness probe for a reused browser: if `new_tab()` fails,
/// that Chrome is discarded and a fresh one is launched. A caller therefore never receives a
/// tab on a wedged process.
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

// coverage(off): drives real Chrome processes.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn acquire_tab() -> anyhow::Result<TabGuard> {
    let (permit, permit_wait) = BROWSER_SEMAPHORE.acquire();
    crate::perf::METRICS.browser_permit_wait.record(permit_wait);

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
                // A reused browser carries the previous render's cache and cookies. If we cannot
                // reset them we must NOT render on it: a warm cache silently changes what the
                // response interceptors can read. Fail over to a fresh process instead.
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
                    _permit: permit,
                    permit_wait,
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
/// These four CDP calls cost ~ms against a 14s mean render, and make every render see the network
/// state it saw before pooling. The browser is exclusively held here — it was popped off the idle
/// pool — so the browser-wide clears cannot race another render.
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
    tab.call_method(Network::SetCacheDisabled {
        cache_disabled: true,
    })
    .map_err(|e| anyhow::anyhow!("Network.setCacheDisabled failed: {e}"))?;
    tab.call_method(Network::SetBypassServiceWorker { bypass: true })
        .map_err(|e| anyhow::anyhow!("Network.setBypassServiceWorker failed: {e}"))?;
    tab.call_method(Network::ClearBrowserCache(None))
        .map_err(|e| anyhow::anyhow!("Network.clearBrowserCache failed: {e}"))?;
    tab.call_method(Network::ClearBrowserCookies(None))
        .map_err(|e| anyhow::anyhow!("Network.clearBrowserCookies failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────
    // BrowserSemaphore unit tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_browser_semaphore_new() {
        let sem = BrowserSemaphore::new(3);
        assert_eq!(sem.max, 3);
        let count = sem.state.lock().unwrap();
        assert_eq!(*count, 0);
    }

    #[test]
    fn test_browser_semaphore_acquire_increments_count() {
        let sem = BrowserSemaphore::new(4);
        let (_p1, _) = sem.acquire();
        assert_eq!(*sem.state.lock().unwrap(), 1);
        let (_p2, _) = sem.acquire();
        assert_eq!(*sem.state.lock().unwrap(), 2);
    }

    #[test]
    fn test_browser_semaphore_release_decrements_count() {
        let sem = BrowserSemaphore::new(4);
        let (_p1, _) = sem.acquire();
        let (p2, _) = sem.acquire();
        assert_eq!(*sem.state.lock().unwrap(), 2);
        drop(p2);
        assert_eq!(*sem.state.lock().unwrap(), 1);
    }

    #[test]
    fn test_browser_permit_drop_releases() {
        let sem = BrowserSemaphore::new(2);
        {
            let (_p, _) = sem.acquire();
            assert_eq!(*sem.state.lock().unwrap(), 1);
        }
        // After permit is dropped, count should be back to 0
        assert_eq!(*sem.state.lock().unwrap(), 0);
    }

    #[test]
    fn test_browser_semaphore_acquire_up_to_max() {
        let sem = BrowserSemaphore::new(3);
        let (_p1, _) = sem.acquire();
        let (_p2, _) = sem.acquire();
        let (_p3, _) = sem.acquire();
        assert_eq!(*sem.state.lock().unwrap(), 3);
    }

    #[test]
    fn test_browser_semaphore_blocks_at_max_then_releases() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let sem = Arc::new(BrowserSemaphore::new(1));

        // Acquire the only permit
        let (p1, _) = sem.acquire();
        assert_eq!(*sem.state.lock().unwrap(), 1);

        let sem2 = Arc::clone(&sem);
        let handle = thread::spawn(move || {
            // This should block until p1 is dropped
            let (_p2, _) = sem2.acquire();
            assert_eq!(*sem2.state.lock().unwrap(), 1);
        });

        // Give the thread a moment to start blocking
        thread::sleep(Duration::from_millis(50));
        // Count should still be 1 (thread is blocked)
        assert_eq!(*sem.state.lock().unwrap(), 1);

        // Drop p1 to unblock the thread
        drop(p1);
        handle.join().unwrap();
        // After thread exits, count is back to 0
        assert_eq!(*sem.state.lock().unwrap(), 0);
    }

    #[test]
    fn test_browser_semaphore_multiple_acquire_release_cycles() {
        let sem = BrowserSemaphore::new(2);
        for _ in 0..10 {
            let (_p, _) = sem.acquire();
            assert_eq!(*sem.state.lock().unwrap(), 1);
        }
        assert_eq!(*sem.state.lock().unwrap(), 0);
    }

    #[test]
    fn test_browser_semaphore_release_notifies_waiters() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let sem = Arc::new(BrowserSemaphore::new(1));
        let acquired = Arc::new(AtomicBool::new(false));

        let (p1, _) = sem.acquire();

        let sem2 = Arc::clone(&sem);
        let acquired2 = Arc::clone(&acquired);
        let handle = thread::spawn(move || {
            let (_p2, _) = sem2.acquire();
            acquired2.store(true, Ordering::SeqCst);
        });

        thread::sleep(Duration::from_millis(50));
        assert!(!acquired.load(Ordering::SeqCst), "Thread should be blocked");

        drop(p1); // release, which calls notify_one
        handle.join().unwrap();
        assert!(
            acquired.load(Ordering::SeqCst),
            "Thread should have acquired after release"
        );
    }

    /// A contended acquire must report a wait that reflects the block, and an uncontended one
    /// must report ~nothing. This is the measurement the subprocessor budget subtracts, so a
    /// silently-zero wait would re-introduce concurrency-dependent recall loss.
    #[test]
    fn test_acquire_reports_permit_wait() {
        use std::sync::Arc;
        let sem = Arc::new(BrowserSemaphore::new(1));
        let (held, first_wait) = sem.acquire();
        assert!(
            first_wait < std::time::Duration::from_millis(50),
            "uncontended acquire should not report a meaningful wait, got {first_wait:?}"
        );

        let sem2 = Arc::clone(&sem);
        let waiter = std::thread::spawn(move || {
            let (_p, waited) = sem2.acquire();
            waited
        });

        std::thread::sleep(std::time::Duration::from_millis(120));
        drop(held);
        let waited = waiter.join().expect("waiter thread panicked");
        assert!(
            waited >= std::time::Duration::from_millis(100),
            "blocked acquire must report the time it was queued, got {waited:?}"
        );
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

    /// Recycling is what bounds the memory a long-lived Chrome accumulates. A depth-3 scan does
    /// ~270 renders, so this must be well under that or the launch cost is not amortised.
    #[test]
    fn test_renders_per_browser_amortises_launch_but_bounds_leak() {
        assert!(
            (10..=100).contains(&MAX_RENDERS_PER_BROWSER),
            "recycle quota {MAX_RENDERS_PER_BROWSER} should amortise a ~2.2s launch across many \
             renders while staying under the ~100-render degradation regime"
        );
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

    #[test]
    fn test_browser_semaphore_concurrent_acquire_release() {
        use std::sync::Arc;
        use std::thread;

        let sem = Arc::new(BrowserSemaphore::new(4));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let sem_clone = Arc::clone(&sem);
            handles.push(thread::spawn(move || {
                let (_permit, _) = sem_clone.acquire();
                // Hold the permit briefly
                thread::sleep(std::time::Duration::from_millis(10));
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(*sem.state.lock().unwrap(), 0);
    }

    #[test]
    fn test_browser_semaphore_max_one() {
        // Edge case: semaphore with max=1 acts like a mutex
        let sem = BrowserSemaphore::new(1);
        let (_p, _) = sem.acquire();
        assert_eq!(*sem.state.lock().unwrap(), 1);
        drop(_p);
        assert_eq!(*sem.state.lock().unwrap(), 0);
    }

    #[test]
    fn test_global_semaphore_exists() {
        // Verify the lazy static is accessible without panicking
        let _ = &*BROWSER_SEMAPHORE;
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
