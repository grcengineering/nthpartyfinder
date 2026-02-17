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

    // Try to find Chrome binary: check env var, then well-known paths
    let chrome_path: Option<std::path::PathBuf> = std::env::var("CHROME_PATH").ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            // WSL: Windows Chrome installation
            let wsl_path = std::path::Path::new("/mnt/c/Program Files/Google/Chrome/Application/chrome.exe");
            if wsl_path.exists() { Some(wsl_path.to_path_buf()) } else { None }
        });

    // Assign a unique debug port per browser instance to avoid port conflicts.
    // Uses an atomic counter starting at 9222 (Chrome's default debug port).
    static PORT_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(9222);
    let debug_port = PORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Wrap around if we exceed reasonable range
    if debug_port > 9322 {
        PORT_COUNTER.store(9222, std::sync::atomic::Ordering::Relaxed);
    }

    let browser = match (is_container, &chrome_path) {
        (true, Some(path)) => {
            let options = headless_chrome::LaunchOptions::default_builder()
                .sandbox(false)
                .path(Some(path.clone()))
                .port(Some(debug_port))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build Chrome launch options: {}", e))?;
            headless_chrome::Browser::new(options)
                .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))?
        }
        (true, None) => {
            let options = headless_chrome::LaunchOptions::default_builder()
                .sandbox(false)
                .port(Some(debug_port))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build Chrome launch options: {}", e))?;
            headless_chrome::Browser::new(options)
                .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))?
        }
        (false, Some(path)) => {
            let options = headless_chrome::LaunchOptions::default_builder()
                .path(Some(path.clone()))
                .port(Some(debug_port))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build Chrome launch options: {}", e))?;
            headless_chrome::Browser::new(options)
                .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))?
        }
        (false, None) => {
            headless_chrome::Browser::default()
                .map_err(|e| anyhow::anyhow!("Failed to launch headless Chrome: {}", e))?
        }
    };

    Ok(BrowserGuard {
        browser,
        _permit: permit,
    })
}
