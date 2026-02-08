//! Rate limiting module for DNS and HTTP requests
//!
//! Provides configurable rate limiting using token bucket algorithm
//! with support for different backoff strategies on retries.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep};
use tracing::{debug, warn};
use crate::config::{RateLimitConfig, BackoffStrategy};

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

    /// Acquire a token, waiting if necessary (M010 fix: retry loop after sleep)
    pub async fn acquire(&mut self) {
        loop {
            match self.try_acquire() {
                None => return, // Token acquired
                Some(wait_duration) => {
                    debug!("Rate limiter waiting {:?} for token", wait_duration);
                    sleep(wait_duration).await;
                    // Re-check after sleep - token may still not be available
                    // if other tasks consumed tokens during our sleep
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
        assert_eq!(config.calculate_backoff_delay(1), Duration::from_millis(1000));
        assert_eq!(config.calculate_backoff_delay(2), Duration::from_millis(2000));
        assert_eq!(config.calculate_backoff_delay(3), Duration::from_millis(3000));
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
        assert_eq!(config.calculate_backoff_delay(1), Duration::from_millis(1000)); // 1000 * 2^0
        assert_eq!(config.calculate_backoff_delay(2), Duration::from_millis(2000)); // 1000 * 2^1
        assert_eq!(config.calculate_backoff_delay(3), Duration::from_millis(4000)); // 1000 * 2^2
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
        assert_eq!(config.calculate_backoff_delay(10), Duration::from_millis(5000));
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
}
