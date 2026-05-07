// memory_monitor.rs - Memory pressure monitoring and concurrency throttling
//
// Monitors system memory usage and dynamically reduces concurrency when
// memory pressure is high. NEVER stops processing — only slows down.
// This prevents virtual memory exhaustion that caused Windows BSODs.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use sysinfo::System;

/// Memory pressure levels with corresponding throttle actions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PressureLevel {
    /// < 80% used: no throttling
    Normal,
    /// 80-92% used: reduce concurrency by half
    Warning,
    /// > 92% used: reduce concurrency to 1
    Critical,
}

/// Monitors system memory and provides throttled concurrency values.
pub struct MemoryMonitor {
    system: System,
    /// Original (configured) concurrency value
    base_concurrency: usize,
    /// Current effective concurrency after throttling
    effective_concurrency: Arc<AtomicUsize>,
    /// Threshold percentages
    warning_threshold: f64,
    critical_threshold: f64,
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
            warning_threshold: 80.0,
            critical_threshold: 92.0,
        }
    }

    /// Check current memory pressure and update effective concurrency.
    /// Returns the current pressure level and effective concurrency.
    pub fn check(&mut self) -> (PressureLevel, usize) {
        self.system.refresh_memory();

        let total = self.system.total_memory();
        let used = self.system.used_memory();

        let (level, new_concurrency) = Self::compute_pressure(
            total,
            used,
            self.base_concurrency,
            self.warning_threshold,
            self.critical_threshold,
        );

        self.effective_concurrency
            .store(new_concurrency, Ordering::Relaxed);
        (level, new_concurrency)
    }

    fn compute_pressure(
        total: u64,
        used: u64,
        base_concurrency: usize,
        warning_threshold: f64,
        critical_threshold: f64,
    ) -> (PressureLevel, usize) {
        if total == 0 {
            return (PressureLevel::Normal, base_concurrency);
        }

        let usage_pct = (used as f64 / total as f64) * 100.0;
        let level = if usage_pct >= critical_threshold {
            PressureLevel::Critical
        } else if usage_pct >= warning_threshold {
            PressureLevel::Warning
        } else {
            PressureLevel::Normal
        };

        let new_concurrency = match level {
            PressureLevel::Normal => base_concurrency,
            PressureLevel::Warning => (base_concurrency / 2).max(1),
            PressureLevel::Critical => 1,
        };

        (level, new_concurrency)
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
        assert!(concurrency >= 1 && concurrency <= 10);
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

    #[test]
    fn test_compute_pressure_normal() {
        let (level, conc) = MemoryMonitor::compute_pressure(100, 50, 10, 80.0, 92.0);
        assert_eq!(level, PressureLevel::Normal);
        assert_eq!(conc, 10);
    }

    #[test]
    fn test_compute_pressure_warning() {
        let (level, conc) = MemoryMonitor::compute_pressure(100, 85, 10, 80.0, 92.0);
        assert_eq!(level, PressureLevel::Warning);
        assert_eq!(conc, 5);
    }

    #[test]
    fn test_compute_pressure_critical() {
        let (level, conc) = MemoryMonitor::compute_pressure(100, 95, 10, 80.0, 92.0);
        assert_eq!(level, PressureLevel::Critical);
        assert_eq!(conc, 1);
    }

    #[test]
    fn test_compute_pressure_zero_total() {
        let (level, conc) = MemoryMonitor::compute_pressure(0, 0, 10, 80.0, 92.0);
        assert_eq!(level, PressureLevel::Normal);
        assert_eq!(conc, 10);
    }

    #[test]
    fn test_compute_pressure_warning_small_base() {
        let (level, conc) = MemoryMonitor::compute_pressure(100, 85, 1, 80.0, 92.0);
        assert_eq!(level, PressureLevel::Warning);
        assert_eq!(conc, 1); // (1/2).max(1) = 1
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
