//! Shared construction of connection-hardened `reqwest` clients.
//!
//! Every subsystem builds its own HTTP client, and historically none of them bounded connection
//! establishment or the idle-connection pool — only the total per-request timeout was set. That
//! is the wrong bound for the failure mode that took down local WiFi during deep scans:
//!
//! * A consumer router tracks every flow — including half-open and timed-out ones — in a
//!   NAT/conntrack table of only a few thousand entries. Under a large fan-out, an untuned client
//!   opens a fresh TCP+TLS handshake per attempt with no cap on how long a *stalled* handshake may
//!   sit before it is abandoned, so each failed connection lingers as a conntrack entry for the
//!   full request timeout (or the OS default, tens of seconds). Enough of them fills the table and
//!   every device on the LAN loses connectivity.
//! * `connect_timeout` bounds exactly that: a handshake that has not completed quickly is dropped,
//!   so a saturated network sheds abandoned flows fast instead of accumulating them.
//! * `pool_idle_timeout` + `pool_max_idle_per_host` bound the keep-alive sockets left idle after a
//!   request, so they return to the OS promptly instead of pinning conntrack slots.
//!
//! This is the code-level complement to the hard OS ceiling (`ulimit -n`) that `scripts/safe-scan.sh`
//! imposes: the wrapper guarantees the process can never hold more than N sockets; these bounds
//! keep the steady-state footprint far under that on every code path.

use std::time::Duration;

/// Abandon a TCP+TLS handshake that has not completed within this long.
///
/// Short enough that a stalled handshake on a saturated network is shed before it lingers in the
/// router's conntrack table, long enough for a real handshake to a slow-but-live host to succeed.
pub const CONNECT_TIMEOUT_SECS: u64 = 5;

/// Evict a keep-alive socket left idle for this long, returning it to the OS.
///
/// Well under reqwest's 90s default so idle sockets do not pin conntrack entries between the
/// bursts of a fan-out.
pub const POOL_IDLE_TIMEOUT_SECS: u64 = 15;

/// Keep at most this many idle keep-alive sockets per host.
///
/// Bounds the total idle-socket footprint when a scan touches many distinct hosts, while still
/// allowing reuse to the handful of DoH endpoints that are hit repeatedly.
pub const POOL_MAX_IDLE_PER_HOST: usize = 4;

/// A `reqwest::ClientBuilder` pre-configured with the connection bounds above.
///
/// Callers chain their own `.timeout(..)`, `.user_agent(..)`, etc. and then `.build()`. Use this
/// in place of `reqwest::Client::builder()` at every subsystem's client-construction site so the
/// connection footprint is bounded uniformly, no matter which discovery path is running.
pub fn hardened_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .pool_idle_timeout(Duration::from_secs(POOL_IDLE_TIMEOUT_SECS))
        .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hardened builder must still produce a working client after a caller layers on the
    /// per-request timeout and user agent it always sets.
    #[test]
    fn test_hardened_builder_builds_a_usable_client() {
        let client = hardened_builder()
            .timeout(Duration::from_secs(5))
            .user_agent("nthpartyfinder-test")
            .build();
        assert!(
            client.is_ok(),
            "hardened builder must produce a valid client"
        );
    }

    /// Guard the bounds against a careless future edit: a connect timeout that drifts up to the
    /// old unbounded regime, or an idle window back near reqwest's 90s default, re-opens the
    /// conntrack-exhaustion risk this module exists to close.
    #[test]
    fn test_connection_bounds_stay_conservative() {
        assert!(
            (2..=10).contains(&CONNECT_TIMEOUT_SECS),
            "connect timeout {CONNECT_TIMEOUT_SECS}s must abandon stalled handshakes promptly"
        );
        assert!(
            (5..=60).contains(&POOL_IDLE_TIMEOUT_SECS),
            "idle sockets must be evicted well before reqwest's 90s default"
        );
        assert!(
            (1..=16).contains(&POOL_MAX_IDLE_PER_HOST),
            "per-host idle pool must stay small enough to bound the total footprint"
        );
    }
}
