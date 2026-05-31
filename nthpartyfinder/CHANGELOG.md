# Changelog

## [Unreleased]

### Fixed
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
