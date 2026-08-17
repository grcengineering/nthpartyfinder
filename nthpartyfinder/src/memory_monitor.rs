// memory_monitor.rs - Memory pressure monitoring and concurrency throttling
//
// Monitors system memory usage and dynamically reduces concurrency when
// memory pressure is high. NEVER stops processing — only slows down.
// This prevents virtual memory exhaustion that caused Windows BSODs.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use sysinfo::System;
use tokio::sync::{Mutex, Semaphore};

/// Memory pressure levels with corresponding throttle actions.
///
/// Keyed on *available* memory as a fraction of total — NOT machine-wide used/total. A box whose
/// baseline sits ~80% used from unrelated workloads (e.g. this 64 GB Mac, which idled at 51/64 GB
/// with 41 GB still available) stays Normal, while genuine exhaustion drives the available
/// fraction toward zero and trips Warning then Critical. `available_memory` is the true exhaustion
/// signal on both macOS (Apple's AVAILABLE_NON_COMPRESSED) and Windows (ullAvailPhys), so this
/// still protects the original Windows-BSOD scenario. Asymmetric enter/exit thresholds (a Schmitt
/// trigger) debounce the level so it cannot chatter warn→relieve→warn while hovering at a boundary.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PressureLevel {
    /// Available memory ample (≥ ~17% of total): no pacing.
    Normal,
    /// Available memory low (< ~15% of total): pace new admissions.
    Warning,
    /// Available memory critically low (< ~8% of total): pace hard.
    Critical,
}

// Enter thresholds are stricter (lower) than exit thresholds so a level latches until memory has
// clearly recovered — this hysteresis is what kills the warn/relieve chatter. Percentage-only (no
// absolute-byte floor): an absolute floor like "< 4 GB" would false-fire on small machines where
// a few GB free is a healthy majority of RAM, whereas the fraction is correct at every machine
// size and still reaches zero under genuine exhaustion.
const WARN_ENTER_PCT: f64 = 15.0;
const WARN_EXIT_PCT: f64 = 17.0;
const CRIT_ENTER_PCT: f64 = 8.0;
const CRIT_EXIT_PCT: f64 = 10.0;

/// The limiter may never withhold the last admission permit.
///
/// A backpressure controller that can drive admissions to zero is not backpressure, it is a
/// deadlock: the scan would sit at zero in-flight tasks waiting for memory that may never come
/// back, and the run would end with an empty result set that is indistinguishable from "this
/// domain has no vendors". Pressure must make the scan *smaller*, never silently *emptier* — the
/// same discipline `throttle_for` already encodes with its `.max(1)`.
const MIN_ADMISSION_PERMITS: usize = 1;

/// Monitors system memory and provides throttled concurrency values.
pub struct MemoryMonitor {
    system: System,
    /// Original (configured) concurrency value
    base_concurrency: usize,
    /// Current effective concurrency after throttling
    effective_concurrency: Arc<AtomicUsize>,
    /// Last reported level, threaded through `next_level` so de-escalation is hysteretic.
    current_level: PressureLevel,
}

impl MemoryMonitor {
    pub fn new(base_concurrency: usize) -> Self {
        let mut system = System::new();
        system.refresh_memory();

        let effective = Arc::new(AtomicUsize::new(base_concurrency));

        Self {
            system,
            base_concurrency,
            effective_concurrency: effective,
            current_level: PressureLevel::Normal,
        }
    }

    /// Check current memory pressure and update effective concurrency.
    /// Returns the current pressure level and effective concurrency.
    pub fn check(&mut self) -> (PressureLevel, usize) {
        self.system.refresh_memory();

        let total = self.system.total_memory();
        let available = self.system.available_memory();

        let level = Self::next_level(self.current_level, total, available);
        self.current_level = level;
        let new_concurrency = Self::throttle_for(level, self.base_concurrency);

        self.effective_concurrency
            .store(new_concurrency, Ordering::Relaxed);
        (level, new_concurrency)
    }

    /// Pure pressure-level transition from the current level and the latest memory reading.
    /// Available-fraction based, with asymmetric enter/exit bands for hysteresis: escalation is
    /// immediate; de-escalation waits until the available fraction has clearly recovered.
    fn next_level(current: PressureLevel, total: u64, available: u64) -> PressureLevel {
        if total == 0 {
            return PressureLevel::Normal;
        }

        let available_pct = (available as f64 / total as f64) * 100.0;
        let crit_enter = available_pct < CRIT_ENTER_PCT;
        let warn_enter = available_pct < WARN_ENTER_PCT;
        let above_crit_exit = available_pct >= CRIT_EXIT_PCT;
        let above_warn_exit = available_pct >= WARN_EXIT_PCT;

        match current {
            PressureLevel::Normal => {
                if crit_enter {
                    PressureLevel::Critical
                } else if warn_enter {
                    PressureLevel::Warning
                } else {
                    PressureLevel::Normal
                }
            }
            PressureLevel::Warning => {
                if crit_enter {
                    PressureLevel::Critical
                } else if above_warn_exit {
                    PressureLevel::Normal
                } else {
                    // Latched: don't drop back to Normal until clearly above the exit band.
                    PressureLevel::Warning
                }
            }
            PressureLevel::Critical => {
                if !above_crit_exit {
                    PressureLevel::Critical
                } else if above_warn_exit {
                    PressureLevel::Normal
                } else {
                    // Recovered past the critical band but still in the warning band: step down.
                    PressureLevel::Warning
                }
            }
        }
    }

    /// Pure mapping from a pressure level to the throttled concurrency value.
    fn throttle_for(level: PressureLevel, base_concurrency: usize) -> usize {
        match level {
            PressureLevel::Normal => base_concurrency,
            PressureLevel::Warning => (base_concurrency / 2).max(1),
            PressureLevel::Critical => 1,
        }
    }

    /// How many admission permits to hold out of circulation at `level`, for a limiter whose
    /// ceiling is `max_permits`.
    ///
    /// This is `throttle_for` expressed as the limiter's control input: permits *withheld* rather
    /// than concurrency *allowed*, because a tokio semaphore can only grow — the only way to
    /// shrink one is to take permits out and never give them back until pressure lifts (the
    /// mechanism `DnsGovernor` already uses for network congestion). Clamped so the limiter can
    /// never withhold everything; see `MIN_ADMISSION_PERMITS`.
    pub fn permits_to_withhold(level: PressureLevel, max_permits: usize) -> usize {
        let target = Self::throttle_for(level, max_permits)
            .max(MIN_ADMISSION_PERMITS)
            .min(max_permits);
        max_permits - target
    }

    /// One hysteretic step of the admission limiter: given the level we were last at and the
    /// latest memory reading, return the level we are now at and how many permits that level
    /// wants withheld.
    ///
    /// This is the whole API an admission semaphore needs. The hysteresis lives in `next_level`'s
    /// asymmetric enter/exit bands, so a reading parked in the dead band (say 16% available,
    /// between the 15% enter and 17% exit thresholds) returns the *same* withhold count tick
    /// after tick. That matters more here than it did for logging: a
    /// level that chattered warn→relieve→warn would resize the live semaphore on every 5s tick,
    /// and each shrink can only revoke permits that happen to be free at that instant, so a
    /// flapping target would leave the limiter permanently mid-convergence and never actually
    /// reduce the in-flight set.
    pub fn next_withhold(
        current: PressureLevel,
        total: u64,
        available: u64,
        max_permits: usize,
    ) -> (PressureLevel, usize) {
        let level = Self::next_level(current, total, available);
        (level, Self::permits_to_withhold(level, max_permits))
    }

    /// Get the current effective concurrency without refreshing memory stats.
    pub fn effective_concurrency(&self) -> usize {
        self.effective_concurrency.load(Ordering::Relaxed)
    }

    /// Get the base (unthrottled) concurrency.
    pub fn base_concurrency(&self) -> usize {
        self.base_concurrency
    }

    /// Get current memory usage as a percentage.
    pub fn memory_usage_pct(&mut self) -> f64 {
        self.system.refresh_memory();
        let total = self.system.total_memory();
        let used = self.system.used_memory();
        Self::compute_usage_pct(total, used)
    }

    fn compute_usage_pct(total: u64, used: u64) -> f64 {
        if total == 0 {
            return 0.0;
        }
        (used as f64 / total as f64) * 100.0
    }

    /// Get a human-readable memory status string.
    pub fn status_string(&mut self) -> String {
        self.system.refresh_memory();
        let total_gb = self.system.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
        let used_gb = self.system.used_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
        let avail_gb = self.system.available_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
        format!(
            "{:.1}/{:.1} GB used ({:.1} GB available)",
            used_gb, total_gb, avail_gb
        )
    }

    /// Get a shared handle to the effective concurrency for use in async contexts.
    pub fn effective_concurrency_handle(&self) -> Arc<AtomicUsize> {
        self.effective_concurrency.clone()
    }
}

/// What a ballast reconcile should do this tick.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BallastAction {
    /// Take this many more permits out of circulation.
    Withhold(usize),
    /// Hand this many permits back.
    Release(usize),
    /// Already reconciled, or nothing is free to revoke right now.
    Steady,
}

/// Reconcile `have` withheld permits toward `want`, given `free` permits available this instant.
///
/// Growing the limit is unconditional — handing permits back always succeeds. Shrinking is
/// best-effort: a permit held by an in-flight task cannot be revoked, and blocking here would
/// stall the monitor behind whatever network I/O that task is doing. We take what is free and
/// leave the rest to the next tick, so the limiter converges as tasks complete rather than
/// stalling. Same trade `DnsGovernor::resize` makes.
fn ballast_action(want: usize, have: usize, free: usize) -> BallastAction {
    if want > have {
        match (want - have).min(free) {
            0 => BallastAction::Steady,
            takeable => BallastAction::Withhold(takeable),
        }
    } else if have > want {
        BallastAction::Release(have - want)
    } else {
        BallastAction::Steady
    }
}

/// Live memory backpressure for an admission semaphore.
///
/// The mechanism this replaces was a 25ms/250ms sleep *inside already-admitted tasks*
/// (`analysis::compute_pressure_delay_ms`), which is the opposite of backpressure: every task
/// still got admitted, still allocated, and still held its memory for the whole scan — it merely
/// finished later. Under genuine pressure the scan got slower without getting smaller, so the
/// pacing added latency and relieved nothing. Withholding permits is the mechanism that actually
/// shrinks the in-flight set.
///
/// The semaphore is created at its ceiling and shrunk by holding permits out of circulation,
/// because tokio semaphores can only grow — there is no `remove_permits`. This is the pattern
/// `DnsGovernor` has been using for network congestion since P1.
pub struct MemoryBackpressure {
    semaphore: Arc<Semaphore>,
    /// Permits currently out of circulation. Only the control path touches this, under the mutex,
    /// so two reconciles cannot race each other into a double-withhold.
    ballast: Mutex<usize>,
    max_permits: usize,
    /// Mirrors `ballast` for lock-free reads by the reporting path.
    withheld: AtomicUsize,
    /// Permits this level wanted withheld but could not revoke, because in-flight tasks hold them.
    /// Non-zero means the limiter has not converged yet — surfaced rather than swallowed, so a
    /// limiter that never reaches its target is visible instead of looking like it worked.
    shortfall: AtomicUsize,
}

impl MemoryBackpressure {
    /// Wrap an admission semaphore that was constructed with `max_permits` permits.
    ///
    /// `max_permits` must be the value the semaphore was built with: it is the ceiling the ballast
    /// is measured against, and a wrong value would make the limiter withhold the wrong amount.
    pub fn new(semaphore: Arc<Semaphore>, max_permits: usize) -> Self {
        Self {
            semaphore,
            ballast: Mutex::new(0),
            max_permits,
            withheld: AtomicUsize::new(0),
            shortfall: AtomicUsize::new(0),
        }
    }

    /// Drive the limiter to `level`. Returns the permits still owed (0 once converged).
    ///
    /// Synchronous and non-blocking by design so the 5s monitor tick can call it without ever
    /// waiting on a scan task. Safe to call every tick: it is idempotent at a steady level.
    pub fn apply(&self, level: PressureLevel) -> usize {
        let want = MemoryMonitor::permits_to_withhold(level, self.max_permits);

        let Ok(mut ballast) = self.ballast.try_lock() else {
            // Another reconcile is in flight; it will observe the newer level when it runs.
            return self.shortfall.load(Ordering::Relaxed);
        };

        let have = *ballast;
        match ballast_action(want, have, self.semaphore.available_permits()) {
            BallastAction::Withhold(n) => {
                crate::perf::METRICS.mem_backpressure_withhold.hit();
                if let Ok(permits) = self
                    .semaphore
                    .clone()
                    .try_acquire_many_owned(n.min(u32::MAX as usize) as u32)
                {
                    let got = permits.num_permits();
                    // `forget` is what takes them out of circulation: dropping the guard would
                    // hand them straight back and the limit would never actually move.
                    permits.forget();
                    *ballast = have + got;
                }
            }
            BallastAction::Release(n) => {
                crate::perf::METRICS.mem_backpressure_release.hit();
                self.semaphore.add_permits(n);
                *ballast = have - n;
            }
            BallastAction::Steady => {}
        }

        let now_withheld = *ballast;
        self.withheld.store(now_withheld, Ordering::Relaxed);
        let shortfall = want.saturating_sub(now_withheld);
        self.shortfall.store(shortfall, Ordering::Relaxed);
        crate::perf::METRICS.mem_backpressure_shortfall.hit();
        shortfall
    }

    /// Permits currently out of circulation.
    pub fn withheld(&self) -> usize {
        self.withheld.load(Ordering::Relaxed)
    }

    /// Permits the last `apply` wanted but could not revoke. Non-zero means not yet converged.
    pub fn shortfall(&self) -> usize {
        self.shortfall.load(Ordering::Relaxed)
    }

    /// Concurrency the limiter is currently enforcing.
    pub fn effective_permits(&self) -> usize {
        self.max_permits - self.withheld()
    }

    /// The ceiling this limiter reconciles against.
    pub fn max_permits(&self) -> usize {
        self.max_permits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_monitor_creation() {
        let monitor = MemoryMonitor::new(10);
        assert_eq!(monitor.base_concurrency(), 10);
        assert_eq!(monitor.effective_concurrency(), 10);
    }

    #[test]
    fn test_check_returns_valid_level() {
        let mut monitor = MemoryMonitor::new(10);
        let (_, concurrency) = monitor.check();
        assert!((1..=10).contains(&concurrency));
    }

    #[test]
    fn test_status_string() {
        let mut monitor = MemoryMonitor::new(10);
        let status = monitor.status_string();
        assert!(status.contains("GB"));
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    #[test]
    fn test_memory_usage_pct() {
        let mut monitor = MemoryMonitor::new(10);
        let pct = monitor.memory_usage_pct();
        // Should be between 0 and 100 on any real system
        assert!(pct >= 0.0, "Memory usage should be >= 0");
        assert!(pct <= 100.0, "Memory usage should be <= 100");
    }

    #[test]
    fn test_effective_concurrency_handle() {
        let monitor = MemoryMonitor::new(20);
        let handle = monitor.effective_concurrency_handle();
        assert_eq!(handle.load(std::sync::atomic::Ordering::Relaxed), 20);
    }

    #[test]
    fn test_pressure_level_equality() {
        assert_eq!(PressureLevel::Normal, PressureLevel::Normal);
        assert_eq!(PressureLevel::Warning, PressureLevel::Warning);
        assert_eq!(PressureLevel::Critical, PressureLevel::Critical);
        assert_ne!(PressureLevel::Normal, PressureLevel::Warning);
        assert_ne!(PressureLevel::Warning, PressureLevel::Critical);
    }

    #[test]
    fn test_base_concurrency_one() {
        let mut monitor = MemoryMonitor::new(1);
        assert_eq!(monitor.base_concurrency(), 1);
        let (_, concurrency) = monitor.check();
        assert_eq!(concurrency, 1);
    }

    #[test]
    fn test_effective_concurrency_updates_after_check() {
        let mut monitor = MemoryMonitor::new(50);
        let handle = monitor.effective_concurrency_handle();

        // Initial value
        assert_eq!(handle.load(std::sync::atomic::Ordering::Relaxed), 50);

        // After check, it should be updated based on memory pressure
        let (_, new_concurrency) = monitor.check();
        assert_eq!(
            handle.load(std::sync::atomic::Ordering::Relaxed),
            new_concurrency
        );
    }

    #[test]
    fn test_status_string_format() {
        let mut monitor = MemoryMonitor::new(10);
        let status = monitor.status_string();
        // Should contain "used" and "available" info
        assert!(
            status.contains("used"),
            "Status should mention 'used': {}",
            status
        );
        assert!(
            status.contains("available"),
            "Status should mention 'available': {}",
            status
        );
    }

    #[test]
    fn test_pressure_level_debug() {
        // Verify Debug trait works for PressureLevel
        let level = PressureLevel::Normal;
        let debug_str = format!("{:?}", level);
        assert_eq!(debug_str, "Normal");

        let debug_str = format!("{:?}", PressureLevel::Warning);
        assert_eq!(debug_str, "Warning");

        let debug_str = format!("{:?}", PressureLevel::Critical);
        assert_eq!(debug_str, "Critical");
    }

    #[test]
    fn test_pressure_level_clone() {
        let level = PressureLevel::Warning;
        let cloned = level;
        assert_eq!(level, cloned);
    }

    #[test]
    fn test_pressure_level_copy() {
        let level = PressureLevel::Critical;
        let copied = level;
        // Both should still be usable (Copy trait)
        assert_eq!(level, copied);
    }

    #[test]
    fn test_multiple_checks_consistent() {
        let mut monitor = MemoryMonitor::new(10);
        // Run check multiple times to verify consistency
        let (level1, conc1) = monitor.check();
        let (level2, conc2) = monitor.check();
        // In the same instant, results should be consistent
        // (system memory shouldn't change drastically between calls)
        assert_eq!(level1, level2);
        assert_eq!(conc1, conc2);
    }

    #[test]
    fn test_large_base_concurrency() {
        let monitor = MemoryMonitor::new(1000);
        assert_eq!(monitor.base_concurrency(), 1000);
        assert_eq!(monitor.effective_concurrency(), 1000);
    }

    // ── next_level: available-fraction based, with hysteresis ──

    #[test]
    fn test_next_level_ample_available_is_normal() {
        // 41 GB available on a 64 GB box (64%): Normal, even though used/total would read ~80%.
        // This is the exact false positive the old used/total signal produced 12× in one scan.
        const GIB: u64 = 1024 * 1024 * 1024;
        let level = MemoryMonitor::next_level(PressureLevel::Normal, 64 * GIB, 41 * GIB);
        assert_eq!(level, PressureLevel::Normal);
        // And it recovers to Normal even from a previously-alarmed level.
        let level = MemoryMonitor::next_level(PressureLevel::Critical, 64 * GIB, 41 * GIB);
        assert_eq!(level, PressureLevel::Normal);
    }

    #[test]
    fn test_next_level_warning_on_low_available() {
        // 14% available (< 15 enter) → Warning.
        assert_eq!(
            MemoryMonitor::next_level(PressureLevel::Normal, 100, 14),
            PressureLevel::Warning
        );
    }

    #[test]
    fn test_next_level_critical_on_very_low_available() {
        // 7% available (< 8 enter) → Critical.
        assert_eq!(
            MemoryMonitor::next_level(PressureLevel::Normal, 100, 7),
            PressureLevel::Critical
        );
    }

    #[test]
    fn test_next_level_zero_total_is_normal() {
        assert_eq!(
            MemoryMonitor::next_level(PressureLevel::Warning, 0, 0),
            PressureLevel::Normal
        );
    }

    #[test]
    fn test_next_level_hysteresis_latches_warning() {
        // 16% available sits in the dead band (≥15 enter, <17 exit): a monitor already in Warning
        // stays Warning (no chatter); a monitor in Normal does not enter.
        assert_eq!(
            MemoryMonitor::next_level(PressureLevel::Warning, 100, 16),
            PressureLevel::Warning
        );
        assert_eq!(
            MemoryMonitor::next_level(PressureLevel::Normal, 100, 16),
            PressureLevel::Normal
        );
        // Clearly recovered (18% ≥ 17 exit) → back to Normal.
        assert_eq!(
            MemoryMonitor::next_level(PressureLevel::Warning, 100, 18),
            PressureLevel::Normal
        );
    }

    #[test]
    fn test_next_level_critical_steps_down_through_warning() {
        // From Critical: 9% (dead band 8..10) latches Critical; 11% steps to Warning; 20% → Normal.
        assert_eq!(
            MemoryMonitor::next_level(PressureLevel::Critical, 100, 9),
            PressureLevel::Critical
        );
        assert_eq!(
            MemoryMonitor::next_level(PressureLevel::Critical, 100, 11),
            PressureLevel::Warning
        );
        assert_eq!(
            MemoryMonitor::next_level(PressureLevel::Critical, 100, 20),
            PressureLevel::Normal
        );
    }

    #[test]
    fn test_throttle_for_levels() {
        assert_eq!(MemoryMonitor::throttle_for(PressureLevel::Normal, 10), 10);
        assert_eq!(MemoryMonitor::throttle_for(PressureLevel::Warning, 10), 5);
        assert_eq!(MemoryMonitor::throttle_for(PressureLevel::Critical, 10), 1);
        // Warning floors at 1 for a tiny base.
        assert_eq!(MemoryMonitor::throttle_for(PressureLevel::Warning, 1), 1);
    }

    // ── P3.5: permit-withholding backpressure ──

    #[test]
    fn test_permits_to_withhold_mirrors_throttle() {
        // The withhold count is the exact complement of the concurrency the level allows.
        for max in [2usize, 10, 64] {
            for level in [
                PressureLevel::Normal,
                PressureLevel::Warning,
                PressureLevel::Critical,
            ] {
                let allowed = MemoryMonitor::throttle_for(level, max);
                assert_eq!(
                    MemoryMonitor::permits_to_withhold(level, max),
                    max - allowed,
                    "level {:?} at ceiling {} must withhold exactly what it disallows",
                    level,
                    max
                );
            }
        }
        assert_eq!(
            MemoryMonitor::permits_to_withhold(PressureLevel::Normal, 10),
            0
        );
        assert_eq!(
            MemoryMonitor::permits_to_withhold(PressureLevel::Warning, 10),
            5
        );
        assert_eq!(
            MemoryMonitor::permits_to_withhold(PressureLevel::Critical, 10),
            9
        );
    }

    #[test]
    fn test_permits_to_withhold_never_strangles_to_zero() {
        // The deadlock guard: at any ceiling, at the worst pressure level, at least one permit
        // stays in circulation. A limiter that withheld all of them would park the scan at zero
        // in-flight and produce an empty result set that reads as "no vendors found".
        for max in 0..=8usize {
            for level in [
                PressureLevel::Normal,
                PressureLevel::Warning,
                PressureLevel::Critical,
            ] {
                let withheld = MemoryMonitor::permits_to_withhold(level, max);
                assert!(
                    withheld <= max,
                    "cannot withhold more than the ceiling ({} of {})",
                    withheld,
                    max
                );
                if max > 0 {
                    assert!(
                        max - withheld >= MIN_ADMISSION_PERMITS,
                        "level {:?} at ceiling {} left {} permits — the scan would deadlock",
                        level,
                        max,
                        max - withheld
                    );
                }
            }
        }
        // A single-permit limiter can never withhold anything at all.
        assert_eq!(
            MemoryMonitor::permits_to_withhold(PressureLevel::Critical, 1),
            0
        );
        assert_eq!(
            MemoryMonitor::permits_to_withhold(PressureLevel::Critical, 0),
            0
        );
    }

    #[test]
    fn test_next_withhold_is_stable_inside_the_dead_band() {
        // The oscillation guard. 16% available sits between the 15% enter and 17% exit thresholds.
        // Ticking repeatedly at that reading must return an unchanging withhold count — a target
        // that flapped every 5s would resize the live semaphore constantly, and since each shrink
        // can only revoke permits that are free at that instant, the limiter would sit permanently
        // mid-convergence and never actually reduce the in-flight set.
        let mut level = PressureLevel::Normal;
        for _ in 0..5 {
            let (next, withhold) = MemoryMonitor::next_withhold(level, 100, 16, 10);
            assert_eq!(next, PressureLevel::Normal);
            assert_eq!(withhold, 0, "not entered: nothing should be withheld");
            level = next;
        }

        // Now enter Warning at 14%, then hover back into the dead band: the withhold count latches.
        let (mut level, withhold) = MemoryMonitor::next_withhold(level, 100, 14, 10);
        assert_eq!(level, PressureLevel::Warning);
        assert_eq!(withhold, 5);
        for _ in 0..5 {
            let (next, withhold) = MemoryMonitor::next_withhold(level, 100, 16, 10);
            assert_eq!(
                next,
                PressureLevel::Warning,
                "must not chatter back to Normal"
            );
            assert_eq!(withhold, 5, "withhold target must hold steady in the band");
            level = next;
        }

        // Clearly recovered (18% ≥ 17% exit): permits are handed back.
        let (level, withhold) = MemoryMonitor::next_withhold(level, 100, 18, 10);
        assert_eq!(level, PressureLevel::Normal);
        assert_eq!(withhold, 0);
    }

    #[test]
    fn test_next_withhold_escalates_and_recovers() {
        let (level, withhold) = MemoryMonitor::next_withhold(PressureLevel::Normal, 100, 7, 20);
        assert_eq!(level, PressureLevel::Critical);
        assert_eq!(
            withhold, 19,
            "critical leaves exactly one permit in circulation"
        );

        // Steps down through Warning as memory returns, not straight to Normal.
        let (level, withhold) = MemoryMonitor::next_withhold(level, 100, 11, 20);
        assert_eq!(level, PressureLevel::Warning);
        assert_eq!(withhold, 10);

        let (level, withhold) = MemoryMonitor::next_withhold(level, 100, 60, 20);
        assert_eq!(level, PressureLevel::Normal);
        assert_eq!(withhold, 0);
    }

    #[test]
    fn test_ballast_action_grid() {
        // Nothing to do.
        assert_eq!(ballast_action(0, 0, 10), BallastAction::Steady);
        assert_eq!(ballast_action(5, 5, 10), BallastAction::Steady);
        // Shrink with room: take the whole deficit.
        assert_eq!(ballast_action(9, 0, 10), BallastAction::Withhold(9));
        assert_eq!(ballast_action(9, 4, 10), BallastAction::Withhold(5));
        // Shrink with in-flight tasks holding permits: take only what is free.
        assert_eq!(ballast_action(9, 0, 2), BallastAction::Withhold(2));
        // Nothing free at all: do not block, retry next tick.
        assert_eq!(ballast_action(9, 0, 0), BallastAction::Steady);
        // Grow: always unconditional, free-permit count is irrelevant.
        assert_eq!(ballast_action(0, 9, 0), BallastAction::Release(9));
        assert_eq!(ballast_action(3, 9, 0), BallastAction::Release(6));
    }

    #[test]
    fn test_backpressure_shrinks_and_restores_a_live_semaphore() {
        let sem = Arc::new(Semaphore::new(10));
        let bp = MemoryBackpressure::new(sem.clone(), 10);
        assert_eq!(bp.effective_permits(), 10);

        assert_eq!(
            bp.apply(PressureLevel::Critical),
            0,
            "should converge at once"
        );
        assert_eq!(
            sem.available_permits(),
            1,
            "critical pressure must leave exactly one admission slot"
        );
        assert_eq!(bp.withheld(), 9);
        assert_eq!(bp.effective_permits(), 1);

        assert_eq!(bp.apply(PressureLevel::Warning), 0);
        assert_eq!(sem.available_permits(), 5);
        assert_eq!(bp.effective_permits(), 5);

        assert_eq!(bp.apply(PressureLevel::Normal), 0);
        assert_eq!(
            sem.available_permits(),
            10,
            "recovery must restore the ceiling"
        );
        assert_eq!(bp.withheld(), 0);
    }

    #[test]
    fn test_backpressure_is_idempotent_at_a_steady_level() {
        let sem = Arc::new(Semaphore::new(8));
        let bp = MemoryBackpressure::new(sem.clone(), 8);
        for _ in 0..4 {
            bp.apply(PressureLevel::Warning);
        }
        assert_eq!(
            sem.available_permits(),
            4,
            "repeated ticks at one level must not compound the withhold"
        );
        assert_eq!(bp.withheld(), 4);
    }

    #[test]
    fn test_backpressure_cannot_revoke_in_flight_permits_and_reports_the_shortfall() {
        let sem = Arc::new(Semaphore::new(10));
        let bp = MemoryBackpressure::new(sem.clone(), 10);

        // Eight tasks already admitted; only two permits are free to revoke.
        let held = sem.clone().try_acquire_many_owned(8).unwrap();

        let shortfall = bp.apply(PressureLevel::Critical);
        assert_eq!(bp.withheld(), 2, "only the free permits can be taken");
        assert_eq!(shortfall, 7, "the rest is owed, and must be visible");
        assert_eq!(bp.shortfall(), 7);
        assert_eq!(
            sem.available_permits(),
            0,
            "no new admissions while the limiter is still owed permits"
        );

        // Those tasks finish; the next tick converges rather than stalling.
        drop(held);
        assert_eq!(bp.apply(PressureLevel::Critical), 0);
        assert_eq!(bp.withheld(), 9);
        assert_eq!(bp.effective_permits(), 1);
        assert_eq!(sem.available_permits(), 1);
    }

    #[test]
    fn test_backpressure_never_deadlocks_a_single_permit_limiter() {
        // The floor holds end-to-end, not just in the pure function: a one-slot limiter under
        // critical pressure still admits work.
        let sem = Arc::new(Semaphore::new(1));
        let bp = MemoryBackpressure::new(sem.clone(), 1);
        assert_eq!(bp.apply(PressureLevel::Critical), 0);
        assert_eq!(sem.available_permits(), 1);
        assert_eq!(bp.effective_permits(), 1);
    }

    #[test]
    fn test_compute_usage_pct_zero_total() {
        assert_eq!(MemoryMonitor::compute_usage_pct(0, 0), 0.0);
    }

    #[test]
    fn test_compute_usage_pct_normal() {
        let pct = MemoryMonitor::compute_usage_pct(100, 50);
        assert!((pct - 50.0).abs() < 0.01);
    }
}
