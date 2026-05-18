//! Rate limiting module for DNS and HTTP requests
//!
//! Provides configurable rate limiting using token bucket algorithm
//! with support for different backoff strategies on retries.

use crate::config::{BackoffStrategy, RateLimitConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};
use tracing::{debug, warn};

/// A token bucket rate limiter for controlling request rates
#[derive(Debug)]
pub struct RateLimiter {
    /// Tokens available in the bucket
    tokens: f64,
    /// Maximum tokens (bucket capacity)
    max_tokens: f64,
    /// Tokens added per second (refill rate)
    refill_rate: f64,
    /// Last time tokens were updated
    last_update: Instant,
    /// Whether rate limiting is enabled (false if rate is 0/unlimited)
    enabled: bool,
}

impl RateLimiter {
    /// Create a new rate limiter with the specified requests per second
    /// If requests_per_second is 0, rate limiting is disabled
    pub fn new(requests_per_second: u32) -> Self {
        let enabled = requests_per_second > 0;
        let max_tokens = if enabled {
            // Allow burst of up to 1 second worth of requests
            requests_per_second as f64
        } else {
            f64::INFINITY
        };

        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate: requests_per_second as f64,
            last_update: Instant::now(),
            enabled,
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        if !self.enabled {
            return;
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_update = now;
    }

    /// Try to acquire a token, returning time to wait if not available
    pub fn try_acquire(&mut self) -> Option<Duration> {
        if !self.enabled {
            return None; // No wait needed
        }

        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            None // Token acquired, no wait
        } else {
            // Calculate wait time for next token
            let wait_secs = (1.0 - self.tokens) / self.refill_rate;
            Some(Duration::from_secs_f64(wait_secs))
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn acquire(&mut self) {
        loop {
            match self.try_acquire() {
                None => return, // Permit acquired
                Some(wait_duration) => {
                    debug!("Rate limiter waiting {:?} for permit", wait_duration);
                    sleep(wait_duration).await;
                    // Re-check after sleep - permit may still not be available
                    // if other tasks consumed permits during our sleep
                }
            }
        }
    }
}

/// Thread-safe rate limiter wrapper
#[derive(Debug, Clone)]
pub struct SharedRateLimiter {
    inner: Arc<Mutex<RateLimiter>>,
}

impl SharedRateLimiter {
    /// Create a new shared rate limiter
    pub fn new(requests_per_second: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RateLimiter::new(requests_per_second))),
        }
    }

    /// Acquire a token, waiting if necessary
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn acquire(&self) {
        let mut limiter = self.inner.lock().await;
        limiter.acquire().await;
    }

    /// Check if rate limiting is enabled
    pub async fn is_enabled(&self) -> bool {
        let limiter = self.inner.lock().await;
        limiter.enabled
    }
}

/// Per-domain HTTP rate limiter manager
#[derive(Debug, Clone)]
pub struct DomainRateLimiter {
    /// Rate limiters by domain
    limiters: Arc<Mutex<HashMap<String, SharedRateLimiter>>>,
    /// Requests per second per domain
    requests_per_second: u32,
}

impl DomainRateLimiter {
    /// Create a new domain rate limiter manager
    pub fn new(requests_per_second: u32) -> Self {
        Self {
            limiters: Arc::new(Mutex::new(HashMap::new())),
            requests_per_second,
        }
    }

    /// Acquire a rate limit token for the specified domain
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn acquire(&self, domain: &str) -> () {
        if self.requests_per_second == 0 {
            return; // Rate limiting disabled
        }

        let limiter = {
            let mut limiters = self.limiters.lock().await;
            limiters
                .entry(domain.to_string())
                .or_insert_with(|| SharedRateLimiter::new(self.requests_per_second))
                .clone()
        };

        limiter.acquire().await;
    }
}

/// Retry helper with configurable backoff
pub struct RetryHelper {
    config: RateLimitConfig,
}

impl RetryHelper {
    /// Create a new retry helper from config
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Execute an async operation with retries and backoff
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn with_retry<T, E, F, Fut>(&self, operation: F) -> Result<T, E>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let mut attempt = 0;

        loop {
            attempt += 1;

            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if attempt > self.config.max_retries {
                        warn!(
                            "All {} retry attempts exhausted, giving up",
                            self.config.max_retries
                        );
                        return Err(e);
                    }

                    let delay = self.config.calculate_backoff_delay(attempt);
                    debug!(
                        "Attempt {} failed ({:?}), retrying in {:?} with {:?} backoff",
                        attempt, e, delay, self.config.backoff_strategy
                    );

                    sleep(delay).await;
                }
            }
        }
    }

    /// Get the maximum number of retries
    pub fn max_retries(&self) -> u32 {
        self.config.max_retries
    }

    /// Get the backoff strategy
    pub fn backoff_strategy(&self) -> &BackoffStrategy {
        &self.config.backoff_strategy
    }
}

/// Global rate limiting context for an analysis session
#[derive(Debug, Clone)]
pub struct RateLimitContext {
    /// DNS query rate limiter (shared across all DNS operations)
    pub dns_limiter: SharedRateLimiter,
    /// HTTP rate limiter (per-domain)
    pub http_limiter: DomainRateLimiter,
    /// WHOIS query rate limiter (shared across all WHOIS operations)
    pub whois_limiter: SharedRateLimiter,
    /// Retry configuration
    pub config: RateLimitConfig,
}

impl RateLimitContext {
    /// Create a new rate limit context from configuration
    pub fn from_config(config: &RateLimitConfig) -> Self {
        Self {
            dns_limiter: SharedRateLimiter::new(config.dns_queries_per_second),
            http_limiter: DomainRateLimiter::new(config.http_requests_per_second),
            whois_limiter: SharedRateLimiter::new(config.whois_queries_per_second),
            config: config.clone(),
        }
    }

    /// Create a retry helper for this context
    pub fn retry_helper(&self) -> RetryHelper {
        RetryHelper::new(&self.config)
    }

    /// Log rate limit configuration
    pub fn log_config(&self) {
        let dns_status = if self.config.dns_queries_per_second > 0 {
            format!("{} qps", self.config.dns_queries_per_second)
        } else {
            "unlimited".to_string()
        };

        let http_status = if self.config.http_requests_per_second > 0 {
            format!("{} rps/domain", self.config.http_requests_per_second)
        } else {
            "unlimited".to_string()
        };

        let whois_status = if self.config.whois_queries_per_second > 0 {
            format!("{} qps", self.config.whois_queries_per_second)
        } else {
            "unlimited".to_string()
        };

        debug!(
            "Rate limiting: DNS={}, HTTP={}, WHOIS={}, Backoff={:?}, Max retries={}",
            dns_status,
            http_status,
            whois_status,
            self.config.backoff_strategy,
            self.config.max_retries
        );
    }
}

impl Default for RateLimitContext {
    fn default() -> Self {
        Self::from_config(&RateLimitConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_disabled() {
        let mut limiter = RateLimiter::new(0);
        assert!(!limiter.enabled);
        assert!(limiter.try_acquire().is_none());
    }

    #[test]
    fn test_rate_limiter_enabled() {
        let mut limiter = RateLimiter::new(10);
        assert!(limiter.enabled);
        // First request should succeed immediately
        assert!(limiter.try_acquire().is_none());
    }

    #[test]
    fn test_backoff_calculation_linear() {
        let config = RateLimitConfig {
            dns_queries_per_second: 10,
            http_requests_per_second: 5,
            whois_queries_per_second: 2,
            backoff_strategy: BackoffStrategy::Linear,
            max_retries: 3,
            backoff_base_delay_ms: 1000,
            backoff_max_delay_ms: 30000,
        };

        assert_eq!(config.calculate_backoff_delay(0), Duration::ZERO);
        assert_eq!(
            config.calculate_backoff_delay(1),
            Duration::from_millis(1000)
        );
        assert_eq!(
            config.calculate_backoff_delay(2),
            Duration::from_millis(2000)
        );
        assert_eq!(
            config.calculate_backoff_delay(3),
            Duration::from_millis(3000)
        );
    }

    #[test]
    fn test_backoff_calculation_exponential() {
        let config = RateLimitConfig {
            dns_queries_per_second: 10,
            http_requests_per_second: 5,
            whois_queries_per_second: 2,
            backoff_strategy: BackoffStrategy::Exponential,
            max_retries: 3,
            backoff_base_delay_ms: 1000,
            backoff_max_delay_ms: 30000,
        };

        assert_eq!(config.calculate_backoff_delay(0), Duration::ZERO);
        assert_eq!(
            config.calculate_backoff_delay(1),
            Duration::from_millis(1000)
        ); // 1000 * 2^0
        assert_eq!(
            config.calculate_backoff_delay(2),
            Duration::from_millis(2000)
        ); // 1000 * 2^1
        assert_eq!(
            config.calculate_backoff_delay(3),
            Duration::from_millis(4000)
        ); // 1000 * 2^2
    }

    #[test]
    fn test_backoff_max_cap() {
        let config = RateLimitConfig {
            dns_queries_per_second: 10,
            http_requests_per_second: 5,
            whois_queries_per_second: 2,
            backoff_strategy: BackoffStrategy::Exponential,
            max_retries: 10,
            backoff_base_delay_ms: 1000,
            backoff_max_delay_ms: 5000,
        };

        // 1000 * 2^9 = 512000, but should be capped at 5000
        assert_eq!(
            config.calculate_backoff_delay(10),
            Duration::from_millis(5000)
        );
    }

    #[tokio::test]
    async fn test_shared_rate_limiter() {
        let limiter = SharedRateLimiter::new(100);
        assert!(limiter.is_enabled().await);

        let disabled_limiter = SharedRateLimiter::new(0);
        assert!(!disabled_limiter.is_enabled().await);
    }

    #[tokio::test]
    async fn test_domain_rate_limiter() {
        let limiter = DomainRateLimiter::new(100);
        // Should not block for high rate
        limiter.acquire("example.com").await;
        limiter.acquire("example.org").await;
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    // --- RateLimiter token exhaustion ---

    #[test]
    fn test_rate_limiter_exhaust_tokens() {
        let mut limiter = RateLimiter::new(5);
        // Consume all 5 tokens
        for _ in 0..5 {
            assert!(limiter.try_acquire().is_none(), "Should get token");
        }
        // 6th request should need to wait
        let wait = limiter.try_acquire();
        assert!(
            wait.is_some(),
            "Should need to wait after exhausting tokens"
        );
        let duration = wait.unwrap();
        assert!(duration.as_millis() > 0, "Wait duration should be positive");
    }

    #[test]
    fn test_rate_limiter_refill_disabled() {
        let mut limiter = RateLimiter::new(0);
        limiter.refill(); // Should be a no-op
        assert!(!limiter.enabled);
    }

    // --- SharedRateLimiter ---

    #[tokio::test]
    async fn test_shared_rate_limiter_acquire() {
        let limiter = SharedRateLimiter::new(1000);
        // High rate, should not block
        limiter.acquire().await;
        limiter.acquire().await;
    }

    #[tokio::test]
    async fn test_shared_rate_limiter_disabled_acquire() {
        let limiter = SharedRateLimiter::new(0);
        assert!(!limiter.is_enabled().await);
        // Should return immediately
        limiter.acquire().await;
    }

    // --- DomainRateLimiter ---

    #[tokio::test]
    async fn test_domain_rate_limiter_disabled() {
        let limiter = DomainRateLimiter::new(0);
        // Should return immediately (no-op)
        limiter.acquire("example.com").await;
    }

    #[tokio::test]
    async fn test_domain_rate_limiter_same_domain() {
        let limiter = DomainRateLimiter::new(1000);
        // High rate, same domain, should not block
        limiter.acquire("example.com").await;
        limiter.acquire("example.com").await;
    }

    #[tokio::test]
    async fn test_domain_rate_limiter_creates_per_domain() {
        let limiter = DomainRateLimiter::new(100);
        limiter.acquire("a.com").await;
        limiter.acquire("b.com").await;
        limiter.acquire("c.com").await;

        // Check that each domain has its own limiter
        let limiters = limiter.limiters.lock().await;
        assert_eq!(limiters.len(), 3);
        assert!(limiters.contains_key("a.com"));
        assert!(limiters.contains_key("b.com"));
        assert!(limiters.contains_key("c.com"));
    }

    // --- RetryHelper ---

    #[test]
    fn test_retry_helper_accessors() {
        let config = RateLimitConfig {
            max_retries: 5,
            backoff_strategy: BackoffStrategy::Exponential,
            ..RateLimitConfig::default()
        };
        let helper = RetryHelper::new(&config);
        assert_eq!(helper.max_retries(), 5);
        assert_eq!(*helper.backoff_strategy(), BackoffStrategy::Exponential);
    }

    #[tokio::test]
    async fn test_retry_helper_success_first_try() {
        let config = RateLimitConfig::default();
        let helper = RetryHelper::new(&config);

        let result: Result<i32, String> = helper.with_retry(|| async { Ok(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retry_helper_all_failures() {
        let config = RateLimitConfig {
            max_retries: 2,
            backoff_base_delay_ms: 1, // Very short delay for test speed
            backoff_max_delay_ms: 10,
            ..RateLimitConfig::default()
        };
        let helper = RetryHelper::new(&config);

        let result: Result<i32, String> = helper
            .with_retry(|| async { Err("always fails".to_string()) })
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "always fails");
    }

    // --- RateLimitContext ---

    #[test]
    fn test_rate_limit_context_default() {
        let ctx = RateLimitContext::default();
        assert_eq!(ctx.config.dns_queries_per_second, 50);
        assert_eq!(ctx.config.http_requests_per_second, 10);
        assert_eq!(ctx.config.whois_queries_per_second, 2);
    }

    #[test]
    fn test_rate_limit_context_from_config() {
        let config = RateLimitConfig {
            dns_queries_per_second: 100,
            http_requests_per_second: 50,
            whois_queries_per_second: 10,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);
        assert_eq!(ctx.config.dns_queries_per_second, 100);
    }

    #[test]
    fn test_rate_limit_context_retry_helper() {
        let ctx = RateLimitContext::default();
        let helper = ctx.retry_helper();
        assert_eq!(helper.max_retries(), ctx.config.max_retries);
    }

    #[test]
    fn test_rate_limit_context_log_config() {
        // Just verify it doesn't panic
        let ctx = RateLimitContext::default();
        ctx.log_config();

        // Also test with unlimited rates
        let config = RateLimitConfig {
            dns_queries_per_second: 0,
            http_requests_per_second: 0,
            whois_queries_per_second: 0,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);
        ctx.log_config();
    }

    // --- RateLimiter::acquire async tests ---

    #[tokio::test]
    async fn test_rate_limiter_acquire_disabled() {
        let mut limiter = RateLimiter::new(0);
        // Should return immediately
        limiter.acquire().await;
        assert!(!limiter.enabled);
    }

    #[tokio::test]
    async fn test_rate_limiter_acquire_enabled() {
        let mut limiter = RateLimiter::new(1000);
        // High rate, should not wait
        limiter.acquire().await;
        limiter.acquire().await;
    }

    #[tokio::test]
    async fn test_rate_limiter_acquire_waits_then_succeeds() {
        let mut limiter = RateLimiter::new(100);
        // Exhaust all tokens
        for _ in 0..100 {
            limiter.try_acquire();
        }
        // Next acquire should wait and then succeed
        limiter.acquire().await;
        // If we got here, the acquire loop worked
    }

    // --- log_config with mixed rates ---

    #[test]
    fn test_rate_limit_context_log_config_mixed() {
        // Some limited, some unlimited
        let config = RateLimitConfig {
            dns_queries_per_second: 50,
            http_requests_per_second: 0, // unlimited
            whois_queries_per_second: 2,
            ..RateLimitConfig::default()
        };
        let ctx = RateLimitContext::from_config(&config);
        ctx.log_config(); // Should not panic
    }

    #[tokio::test]
    async fn test_retry_helper_eventual_success() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let config = RateLimitConfig {
            max_retries: 5,
            backoff_base_delay_ms: 1,
            backoff_max_delay_ms: 10,
            ..RateLimitConfig::default()
        };
        let helper = RetryHelper::new(&config);
        let counter = std::sync::Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();
        let result: Result<i32, String> = helper
            .with_retry(|| {
                let c = counter_clone.clone();
                async move {
                    let count = c.fetch_add(1, Ordering::SeqCst);
                    if count < 2 {
                        Err("transient error".to_string())
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }
}
