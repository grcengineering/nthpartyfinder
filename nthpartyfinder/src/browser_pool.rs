//! Browser concurrency pool for headless Chrome instances.
//!
//! Each Chrome process consumes ~100-300 MB RAM. This module limits
//! concurrent browser instances to prevent memory exhaustion during
//! depth-3+ scans with hundreds of vendors.
//!
//! Uses std::sync primitives so it works in both async and sync
//! (spawn_blocking) contexts.

/// Maximum concurrent headless Chrome instances.
/// Increased from 2→4 to reduce browser serialization bottleneck during depth-2+ scans.
/// At ~200-300 MB per instance, 4 instances ≈ 1.2 GB peak — acceptable given our memory fixes.
const MAX_BROWSER_INSTANCES: usize = 4;

/// Global counting semaphore for browser instances.
static BROWSER_SEMAPHORE: once_cell::sync::Lazy<BrowserSemaphore> =
    once_cell::sync::Lazy::new(|| BrowserSemaphore::new(MAX_BROWSER_INSTANCES));

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

    /// Acquire a permit, blocking until one is available.
    fn acquire(&self) -> BrowserPermit<'_> {
        let mut count = self.state.lock().unwrap();
        while *count >= self.max {
            count = self.condvar.wait(count).unwrap();
        }
        *count += 1;
        BrowserPermit { semaphore: self }
    }

    fn release(&self) {
        let mut count = self.state.lock().unwrap();
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

/// A Chrome browser instance with an attached semaphore permit.
/// When the BrowserGuard is dropped, the Chrome process is killed AND
/// the semaphore permit is released, allowing another browser to be created.
pub struct BrowserGuard {
    pub browser: headless_chrome::Browser,
    _permit: BrowserPermit<'static>,
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
    env_path
        .map(std::path::PathBuf::from)
        .or_else(|| {
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
) -> anyhow::Result<headless_chrome::LaunchOptions> {
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

/// Create a headless Chrome browser instance, gated by a global semaphore.
/// At most MAX_BROWSER_INSTANCES Chrome processes can exist simultaneously.
/// Blocks until a permit is available.
/// Automatically disables sandbox when running inside a container
/// (detected via /.dockerenv or NTHPARTYFINDER_CONTAINER env var).
///
/// Returns a BrowserGuard that releases the semaphore permit when dropped.
// coverage(off): launches real Chrome processes — all preparation logic is tested via
// is_container_env_inner, find_chrome_binary_inner, next_debug_port, build_launch_options
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn create_browser() -> anyhow::Result<BrowserGuard> {
    let permit = BROWSER_SEMAPHORE.acquire();
    let is_container = is_container_env();
    let chrome_path = find_chrome_binary();
    let debug_port = next_debug_port();

    let browser = if is_container || chrome_path.is_some() {
        let options = build_launch_options(is_container, chrome_path.as_deref(), debug_port)?;
        headless_chrome::Browser::new(options)
            .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))?
    } else {
        headless_chrome::Browser::default()
            .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))?
    };

    Ok(BrowserGuard {
        browser,
        _permit: permit,
    })
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
        let _p1 = sem.acquire();
        assert_eq!(*sem.state.lock().unwrap(), 1);
        let _p2 = sem.acquire();
        assert_eq!(*sem.state.lock().unwrap(), 2);
    }

    #[test]
    fn test_browser_semaphore_release_decrements_count() {
        let sem = BrowserSemaphore::new(4);
        let _p1 = sem.acquire();
        let p2 = sem.acquire();
        assert_eq!(*sem.state.lock().unwrap(), 2);
        drop(p2);
        assert_eq!(*sem.state.lock().unwrap(), 1);
    }

    #[test]
    fn test_browser_permit_drop_releases() {
        let sem = BrowserSemaphore::new(2);
        {
            let _p = sem.acquire();
            assert_eq!(*sem.state.lock().unwrap(), 1);
        }
        // After permit is dropped, count should be back to 0
        assert_eq!(*sem.state.lock().unwrap(), 0);
    }

    #[test]
    fn test_browser_semaphore_acquire_up_to_max() {
        let sem = BrowserSemaphore::new(3);
        let _p1 = sem.acquire();
        let _p2 = sem.acquire();
        let _p3 = sem.acquire();
        assert_eq!(*sem.state.lock().unwrap(), 3);
    }

    #[test]
    fn test_browser_semaphore_blocks_at_max_then_releases() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let sem = Arc::new(BrowserSemaphore::new(1));

        // Acquire the only permit
        let p1 = sem.acquire();
        assert_eq!(*sem.state.lock().unwrap(), 1);

        let sem2 = Arc::clone(&sem);
        let handle = thread::spawn(move || {
            // This should block until p1 is dropped
            let _p2 = sem2.acquire();
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
            let _p = sem.acquire();
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

        let p1 = sem.acquire();

        let sem2 = Arc::clone(&sem);
        let acquired2 = Arc::clone(&acquired);
        let handle = thread::spawn(move || {
            let _p2 = sem2.acquire();
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

    #[test]
    fn test_max_browser_instances_constant() {
        assert_eq!(MAX_BROWSER_INSTANCES, 4);
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
                let _permit = sem_clone.acquire();
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
        let _p = sem.acquire();
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
        let result = find_chrome_binary_inner(
            None,
            std::path::Path::new("/nonexistent/wsl/chrome.exe"),
        );
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

        let result = find_chrome_binary_inner(
            Some("/custom/chrome".to_string()),
            &fake_wsl,
        );
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
        let opts = build_launch_options(
            false,
            Some(std::path::Path::new("/usr/bin/chrome")),
            9260,
        );
        assert!(opts.is_ok());
    }

    #[test]
    fn test_build_launch_options_container_with_path() {
        let opts = build_launch_options(
            true,
            Some(std::path::Path::new("/usr/bin/chrome")),
            9270,
        );
        assert!(opts.is_ok());
    }
}
