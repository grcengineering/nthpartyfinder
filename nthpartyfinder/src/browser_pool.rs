//! Browser concurrency pool for headless Chrome instances.
//!
//! Each Chrome process consumes ~100-300 MB RAM. This module limits
//! concurrent browser instances to prevent memory exhaustion during
//! depth-3+ scans with hundreds of vendors.
//!
//! Uses std::sync primitives so it works in both async and sync
//! (spawn_blocking) contexts.

/// Maximum concurrent headless Chrome instances.
const MAX_BROWSER_INSTANCES: usize = 2;

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

/// Create a headless Chrome browser instance, gated by a global semaphore.
/// At most MAX_BROWSER_INSTANCES Chrome processes can exist simultaneously.
/// Blocks until a permit is available.
/// Automatically disables sandbox when running inside a container
/// (detected via /.dockerenv or NTHPARTYFINDER_CONTAINER env var).
///
/// Returns a BrowserGuard that releases the semaphore permit when dropped.
pub fn create_browser() -> anyhow::Result<BrowserGuard> {
    let permit = BROWSER_SEMAPHORE.acquire();

    let is_container = std::env::var("NTHPARTYFINDER_CONTAINER").is_ok()
        || std::path::Path::new("/.dockerenv").exists();

    let browser = if is_container {
        let options = headless_chrome::LaunchOptions::default_builder()
            .sandbox(false)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build Chrome launch options: {}", e))?;
        headless_chrome::Browser::new(options)
            .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome (container mode): {}", e))?
    } else {
        headless_chrome::Browser::default()
            .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))?
    };

    Ok(BrowserGuard {
        browser,
        _permit: permit,
    })
}
