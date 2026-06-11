# Changelog

## [Unreleased]

### Fixed
- Default DoH server list replaced with verified JSON-API endpoints. Google's
  JSON DoH API lives at `/resolve` — `/dns-query` is RFC-8484 wire format and
  returns HTTP 400 for `application/dns-json`; Quad9 and OpenDNS do not serve
  the JSON GET API at all. 3 of 4 default DoH servers therefore failed every
  query, degrading DNS performance and risking false-negative vendor results.
  Cloudflare/Google IP-literal endpoints added (no DNS bootstrap dependency
  when UDP/53 is blocked).
- GRC-500: `cleanup_orphans` deleted the live result-sink files of
  concurrently-running scans on macOS/Windows. `is_process_running` checked
  `/proc/{pid}` (Linux-only), so every PID read as "not running" off Linux and
  a sibling run's startup cleanup removed an active scan's `/tmp` sink. The
  victim then panicked in `drain_all()` with ENOENT (exit 101) before writing
  output — surfacing as HTML/JSON/markdown "crashes" and silently-empty
  reports in the format matrix while CSV got lucky on timing. Liveness now uses
  `sysinfo` for correct cross-platform detection.
- The disk-sink read path no longer panics when results can't be read back; it
  fails loudly with a clear message and a dedicated exit code (4) instead of
  emitting a silently-empty report.

### Changed
- `--timeout` help now explains that depth-3+/cold-cache scans routinely exceed
  the 600s default (raise it or use `--timeout 0`) and that the output format
  does not affect discovery time.

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
