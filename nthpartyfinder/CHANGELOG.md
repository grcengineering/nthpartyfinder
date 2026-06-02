# Changelog

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
