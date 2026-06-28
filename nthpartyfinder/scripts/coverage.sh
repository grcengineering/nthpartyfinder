#!/usr/bin/env bash
# Local coverage gate — MUST stay byte-identical (threshold + ignore-regex) to
# the "Run coverage and print summary" step in .github/workflows/build.yml.
# Floor = 95% line + 95% function (NOT 100%; see build.yml comment for why).
# Run from the crate dir: nthpartyfinder/scripts/coverage.sh
set -euo pipefail

cd "$(dirname "$0")/.."

REGEX='(browser_pool|memory_monitor|interactive)\.rs$'
TOOLCHAIN="${COV_TOOLCHAIN:-nightly-2026-04-29}"
# Invoke cargo by its absolute path so the run skips the Socket Firewall (sfw)
# shell wrapper and its per-invocation overhead. Override (e.g. CARGO=cargo to
# route through sfw). Threshold + ignore-regex stay byte-identical to CI.
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"

RUSTFLAGS="" "$CARGO" "+${TOOLCHAIN}" llvm-cov \
  --locked --all-features --workspace --lib \
  --ignore-filename-regex "${REGEX}" \
  --fail-under-lines 95 --fail-under-functions 95

echo "coverage gate OK (>=95% line & function, regex='${REGEX}')"
