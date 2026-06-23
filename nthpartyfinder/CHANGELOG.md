# Changelog

## [Unreleased]

### Security
- Frontend vendor-graph build toolchain upgraded to clear its 7 Dependabot
  alerts (esbuild RCE GHSA-gv7w-rqvm-qjhr, svelte XSS ×2, postcss XSS, vite ×3):
  svelte 4→5.56, vite 5→6.4.3, esbuild→0.28.1, @sveltejs/vite-plugin-svelte 3→5,
  @xyflow/svelte 0.1→1.6. The Svelte 4 components were migrated to Svelte 5
  runes + the @xyflow/svelte 1.x API (`bind:nodes`/`bind:edges`, callback-prop
  events, `mount()`); the rebuilt `static/vendor-graph.{js,css}` was visually
  verified rendering in a report. `npm audit` is clean (0 vulnerabilities).
- Removed the `whois-rs` dependency (replaced with a small in-process TCP WHOIS
  client using IANA referral, `src/whois.rs`). `whois-rs` 1.6.1 (latest) pinned
  `hickory-client 0.24` → `hickory-proto 0.24` (RUSTSEC-2026-0119) and
  `validators 0.25` → `idna 0.5` (RUSTSEC-2024-0421); both vulnerable crates are
  now out of the tree entirely — a code-level remediation rather than a risk
  acceptance. The two corresponding `deny.toml` ignore entries were deleted.
  System `whois` remains a fallback.
- Opengrep SARIF is now filtered (`scripts/filter-opengrep-sarif.sh`) to drop the
  report-only `no-unwrap`/`no-eprintln` WARNING findings located in inline
  `#[cfg(test)]` test code before upload to code scanning — Opengrep's Rust
  matcher cannot exclude inline test modules, so ~1.7k test-code false positives
  were flooding the dashboard. Production findings and the ERROR gate are kept.
- Docker base images in all Dockerfiles pinned by digest (OpenSSF Scorecard
  Pinned-Dependencies); a Dependabot `docker` ecosystem keeps the pins current.

### Fixed
- Default DoH server list replaced with verified JSON-API endpoints. Google's
  JSON DoH API lives at `/resolve` — `/dns-query` is RFC-8484 wire format and
  returns HTTP 400 for `application/dns-json`; Quad9 and OpenDNS do not serve
  the JSON GET API at all. 3 of 4 default DoH servers therefore failed every
  query, degrading DNS performance and risking false-negative vendor results.
  Cloudflare/Google IP-literal endpoints added (no DNS bootstrap dependency
  when UDP/53 is blocked).
- DoH responses with a non-2xx status other than 429/5xx (e.g. HTTP 400 from an
  endpoint that does not serve the JSON DoH API) and dns-json RCODEs other than
  NOERROR/NXDOMAIN now surface as `DNS_ENDPOINT` errors counted toward the
  exit-3 guard — never parsed as "0 records". Resilient lookups rotate past
  broken endpoints immediately (no backoff); each failing provider warns once,
  then logs at debug.
- Authoritative empty DoH answers (2xx, RCODE NOERROR/NXDOMAIN, no records) are
  now final: no system-resolver fallthrough and no spurious "All DNS resolution
  failed" warning for domains that genuinely have no TXT records.
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
- Dependency updates (clears the open Dependabot maintenance PRs): tokio
  1.52.1→1.52.3, serde_json 1.0.149→1.0.150, http 1.4.0→1.4.2, thiserror
  1.0→2.0, colored 2.1→3.1, which 6→8, zip 0.6→8.6, toml 0.8→1.1, sysinfo
  0.32→0.39, askama 0.12→0.16. Code touched by API changes: `sysinfo`
  `ProcessRefreshKind::new()`→`nothing()` (process-liveness check); the askama
  0.13+ removal of the generated `EXTENSION`/`MIME_TYPE` template constants
  (the affected unit test now verifies HTML output by rendering instead).
- Second dependency-update batch (clears the routine Dependabot PRs opened during
  the cleanup): reqwest 0.12→0.13 (added the `query` cargo feature, which 0.13
  gates behind it), sha2 0.10→0.11, dirs 5→6, scraper 0.26→0.27, fancy-regex
  0.13→0.18, chrono→0.4.45, which→8.0.4, headless_chrome→1.0.22, insta→1.48,
  assert_cmd→2.2.2. No source changes required beyond the reqwest feature.

## [1.1.1] - 2026-06-02

### Security
- Patched transitive dependency CVEs: openssl 0.10.78 → 0.10.80 (CVE-2026-42327 [high] OCSP UB,
  CVE-2026-44662 + CVE-2026-45784 AES-KW heap/OOB) and tar 0.4.45 → 0.4.46 (GHSA-3pv8-6f4r-ffg2).
- Eliminated all 62 production `.unwrap()` calls (panic-safety): poison-recovery for locks,
  graceful fallbacks on malformed DNS/WHOIS/web input, documented `.expect()` for provable
  invariants. Test-code unwraps are unchanged (idiomatic).

### Changed
- CI/supply-chain hardening: least-privilege `permissions:` on all workflows; Opengrep SAST now
  gates on ERROR-severity findings; the `no-unwrap-in-prod` lint is scoped to production code
  (excludes `#[cfg(test)]` modules); added SECURITY.md and a pre-push git hook
  (`scripts/install-git-hooks.sh`) that runs fmt/clippy/cargo-deny/gitleaks before every push.

## [1.1.0] - 2026-06-01

### Added
- **Runtime-fetched NER model (crates.io publishability).** A new `runtime-ner` feature (now the
  default) fetches the ~183 MB GLiNER model at runtime from our own GitHub release
  (`model-gliner-small-v1`) instead of embedding it via `include_bytes!`. This keeps the published
  crate small enough for crates.io so `cargo install nthpartyfinder` works. The download is
  **consent-gated** (explicit `[y/N]` prompt on an interactive terminal; never auto-downloads) and
  **integrity-controlled**: each file is verified against a compiled-in SHA-256 anchor over an
  HTTPS-only, `github.com`-only request, written atomically, and re-verified from cache on load —
  unverified bytes are never loaded.
- `--download-ner-model` flag to consent to the model download non-interactively (CI/headless).

### Changed
- Default feature is now `runtime-ner` (was `embedded-ner`). Downloadable release binaries remain
  **self-contained** — CI builds them with `--no-default-features --features embedded-ner` so the
  model stays baked in and they work offline. `--disable-slm` still skips NER entirely.

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
