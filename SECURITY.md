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
