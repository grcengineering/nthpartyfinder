# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x: (superseded)   |
| < 1.0   | :x:                |

Always use the latest published release. Older versions do not receive security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via GitHub's [private vulnerability reporting](https://github.com/grcengineering/nthpartyfinder/security/advisories/new)
("Report a vulnerability" under the Security tab). Include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal proof-of-concept if possible).
- Affected version(s) and environment.

We aim to acknowledge reports within 3 business days and to ship a fix or mitigation
for confirmed, in-scope vulnerabilities as a priority.

## Our security controls

This project gates security at multiple layers (see `.github/workflows/`):

- **SCA / dependency CVEs** — `cargo-deny` (blocking) over the RustSec DB, plus
  `osv-scanner` (broader DB) for breadth. Risk-accepted advisories are documented
  with rationale in `deny.toml`.
- **SAST** — CodeQL (Rust + others) and Opengrep. ERROR-severity findings are blocking.
- **Secret scanning** — gitleaks (blocking) over full history.
- **Supply-chain** — SHA-pinned GitHub Actions, least-privilege workflow permissions,
  SLSA build provenance on release artifacts, and a runtime NER model fetched only from
  our own release with a compiled-in SHA-256 integrity anchor.
- **Pre-PR** — a local `pre-push` git hook (`scripts/install-git-hooks.sh`) runs
  fmt/clippy/cargo-deny/gitleaks so issues are caught before a pull request is opened.

## Accepted findings (documented posture)

A small number of scanner findings are intentionally accepted; each has a concrete,
evidence-based rationale. No *fixable* true-positive is suppressed — fixes are the
default (e.g. `whois-rs` was removed outright to clear RUSTSEC-2026-0119 + RUSTSEC-2024-0421
rather than risk-accept them).

**Dependency advisories (tracked in `deny.toml` with `unused-ignored-advisory = "warn"`):**

- **RUSTSEC-2025-0119** (`number_prefix`, *unmaintained*) — transitive via `indicatif`
  for human-readable byte counts; no security surface; no maintained alternative in
  `indicatif`'s tree. Informational, not a vulnerability.
- **RUSTSEC-2024-0436** (`paste`, *unmaintained*) — compile-time proc-macro only; emits
  no runtime code; no known CVE; 14k+ reverse-dependents. No runtime attack surface.

These are the *no-fix / unmaintained-dependency* carve-out: there is no upstream patch and
no reachable security impact. Revisit if a maintained replacement appears.

**OpenSSF Scorecard (repo-maturity signals, not code vulnerabilities):**

- **Pinned-Dependencies** — all GitHub Actions are 40-char-SHA pinned and all Docker base
  images are digest-pinned. The sole non-SHA `uses:` is
  `slsa-framework/slsa-github-generator`, which **must** be referenced by a version tag —
  its TUF trust model rejects commit-SHA pins. Sanctioned exception.
- **Branch-Protection** — the default branch is governed by a repository ruleset that
  blocks force-pushes (`non_fast_forward`), blocks deletion, restricts direct updates to
  bypass actors (org admins), and **requires the core CI checks to pass before a pull
  request can merge** (Lint, Unit/Integration Tests, the 95% Coverage gate, Cargo Deny,
  SAST/Opengrep, Secret Scan, CodeQL, and the four cross-platform Builds). Required *human*
  review is intentionally not enforced — see Code-Review.
- **Code-Review** — every change lands through a pull request with the full CI gate suite,
  but this is a single-maintainer project, so a second human approver is not always
  available. Accepted for the current maintainer model (requiring a second reviewer would
  deadlock the sole maintainer's ability to merge).
- **Fuzzing** — a `cargo-fuzz` (libFuzzer) harness lives in `nthpartyfinder/fuzz/` with
  targets over the highest-exposure untrusted-input parsers: PSL domain normalization
  (`domain_base`), DNS TXT/SPF/DKIM/DMARC record parsing (`dns_txt_spf`), third-party HTML
  and JSON-LD organization extraction (`html_org`), resource-URL extraction from HTML
  (`web_traffic_html`), and the PSL pseudo-host classifier (`finalize_host`). The `Fuzz` CI
  workflow builds all targets and smoke-runs each on every change to the parsers; run
  locally with `cargo +nightly fuzz run <target>`.
- **CII-Best-Practices** — the OpenSSF Best Practices badge has not been applied for; this
  is an external self-certification process tracked as a follow-up, not a code change.
