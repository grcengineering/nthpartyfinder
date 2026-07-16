# Contributing to Nth Party Finder

Thanks for your interest in improving `nthpartyfinder`. This guide covers the local workflow and the gates a change must pass before it can merge.

## Repository layout

The Rust crate lives in the [`nthpartyfinder/`](nthpartyfinder/) subdirectory, **not** the repo root. Run all `cargo` commands from there:

```bash
git clone https://github.com/grcengineering/nthpartyfinder.git
cd nthpartyfinder/nthpartyfinder   # the crate dir
```

## Building

```bash
# Default build: embeds the GLiNER NER model (~175 MB binary)
cargo build --release

# Slim build: no NER (~15 MB)
cargo build --release --no-default-features
```

Rust edition 2021. A `whois` client must be on `PATH` for organization resolution at runtime.

## Running tests

```bash
cargo test          # from the crate dir (nthpartyfinder/nthpartyfinder/)
```

**No live network in the test suite.** Tests use `wiremock`; any test that touches the real internet is `#[ignore]`-gated. Don't add live-DNS or live-HTTP calls to unit or integration tests — mock them.

## Quality gates (must pass before opening a PR)

CI runs these exactly; run them locally first. The repo's `scripts/pre-push.sh` bundles them:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings   # warnings are errors
cargo deny check advisories                                # dependency/advisory SCA
```

Plus:

- **Test suite** — `cargo test`, zero failures.
- **Coverage** — **95% line and 95% function minimum** (`scripts/coverage.sh`). 100% is explicitly not the goal; the last few percent is genuinely-unreachable defensive code. New behavior needs meaningful tests that assert an observable outcome — not coverage padding. Structurally-untestable infra (browser pool, memory monitor, interactive prompts) is documented in the coverage `--ignore-filename-regex`.
- **Security** — never suppress a scanner finding (`// codeql`, `#[allow(...)]`, query exclusions) to make a change pass. Fix the code. A true-positive finding is a blocker, not tech debt.

Install the git hooks to run the gates automatically on push:

```bash
./scripts/install-git-hooks.sh
```

## Pull requests

- `master` is protected — all changes land via PR; direct pushes are blocked.
- CI must be fully green (build, tests, coverage, CodeQL, `cargo-deny`, secret scanning, Scorecard) before merge.
- Keep discovery-behavior changes and their evidence in the same PR: if a change alters what the scanner finds, include a before/after on a real or fixtured scan.
- Additive-only for output: JSON fields and CSV columns are appended, never renamed or reordered — downstream consumers depend on the schema.

## Reporting bugs & security issues

- **Bugs / features** — [open an issue](https://github.com/grcengineering/nthpartyfinder/issues). For a scan bug, include the domain, depth, flags, and the observed vs expected output.
- **Security vulnerabilities** — do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Scanning ethics

`nthpartyfinder` reads only public signals, but a deep multi-method scan is real traffic. When testing, scan domains you're authorized to assess, keep rate limiting on, and prefer bounded depth. Don't use the tool to attack, overwhelm, or exfiltrate from third-party infrastructure.

By contributing, you agree your contributions are licensed under the project's [MIT License](LICENSE).
