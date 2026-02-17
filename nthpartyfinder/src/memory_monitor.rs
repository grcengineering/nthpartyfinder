// memory_monitor.rs - Memory pressure monitoring and concurrency throttling
//
// Monitors system memory usage and dynamically reduces concurrency when
// memory pressure is high. NEVER stops processing — only slows down.
// This prevents virtual memory exhaustion that caused Windows BSODs.

use sysinfo::System;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

        if total == 0 {
            // Can't determine memory state — don't throttle
            return (PressureLevel::Normal, self.base_concurrency);
        }

        let usage_pct = (used as f64 / total as f64) * 100.0;
        let level = if usage_pct >= self.critical_threshold {
            PressureLevel::Critical
        } else if usage_pct >= self.warning_threshold {
            PressureLevel::Warning
        } else {
            PressureLevel::Normal
        };

        let new_concurrency = match level {
            PressureLevel::Normal => self.base_concurrency,
            PressureLevel::Warning => (self.base_concurrency / 2).max(1),
            PressureLevel::Critical => 1,
        };

        self.effective_concurrency.store(new_concurrency, Ordering::Relaxed);
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
        let (level, concurrency) = monitor.check();

        // We can't control system memory, but we can verify the contract
        match level {
            PressureLevel::Normal => assert_eq!(concurrency, 10),
            PressureLevel::Warning => assert_eq!(concurrency, 5),
            PressureLevel::Critical => assert_eq!(concurrency, 1),
        }
    }

    #[test]
    fn test_status_string() {
        let mut monitor = MemoryMonitor::new(10);
        let status = monitor.status_string();
        assert!(status.contains("GB"));
    }
}
