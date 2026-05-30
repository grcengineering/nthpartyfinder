# Changelog

## [1.0.1] - 2026-05-30

### Fixed
- GRC-367: DNS-under-concurrency false negatives. DoH throttling (429/5xx) is now detected and
  surfaced as a distinct error (never parsed into an empty answer); the per-process DNS rate
  limiter is wired onto the production hot path; provider rotation + backoff on throttle; and
  throttles are counted at the DoH choke-point so every path (TXT, CNAME, subdomain fan-out,
  SPF include-chain recursion) feeds the exit-3 false-negative guard. `SharedRateLimiter` no
  longer holds its lock across an `await`.
- GRC-368: bumped hickory-resolver 0.25.2 → 0.26.1, clearing RUSTSEC-2026-0118 and the
  resolver path of RUSTSEC-2026-0119 (the whois-rs 1.6.1 transitive path has no upstream fix
  and remains documented in deny.toml).

### Changed
- `--dns-rate-limit` is now enforced (was previously dead config) and forwarded to batch-mode
  child processes.

### Known issues
- Batch mode lacks an exit-3 DNS-throttle guard (tracked as GRC-497).

## [1.0.0] - 2026-04-28

### Fixed
- BUG-001/002/004/005/009: domain validation, _org: prefix, garbled text
- BUG-006: TLD registry operators rejected as WHOIS org names
- BUG-007/012: dedup count clarification, --dns-only flag
- BUG-011: social media links excluded from vendor relationships

### Added
- Comprehensive E2E test suite (assert_cmd-based)
- BUG-006/011/012 regression tests
- Compound TLD support (32 regional variants added)
- NER load test on Windows CI
- Release workflow with cargo-binstall artifacts

### Changed
- Live-DNS in tests replaced with wiremock fixtures
- Coverage gate set to 70% lines minimum
