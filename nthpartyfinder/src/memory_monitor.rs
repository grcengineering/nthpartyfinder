// memory_monitor.rs - Memory pressure monitoring and concurrency throttling
//
// Monitors system memory usage and dynamically reduces concurrency when
// memory pressure is high. NEVER stops processing — only slows down.
// This prevents virtual memory exhaustion that caused Windows BSODs.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use sysinfo::System;

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
