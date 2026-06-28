#!/usr/bin/env bash
# Pre-push security + quality gate — mirrors the CI gates so problems are caught
# LOCALLY, before a pull request is ever opened. Install with:
#   nthpartyfinder/scripts/install-git-hooks.sh
# Bypass intentionally (rare) with: git push --no-verify
set -uo pipefail

CRATE_DIR="$(cd "$(dirname "$0")/.." && pwd)"      # nthpartyfinder/
REPO_ROOT="$(cd "$CRATE_DIR/.." && pwd)"
fail=0
run() { echo "▶ $*"; if ! "$@"; then echo "✖ FAILED: $*"; fail=1; fi; }

cd "$CRATE_DIR"

# Invoke cargo by its absolute path so each call skips the Socket Firewall (sfw)
# shell wrapper and its per-invocation overhead. Override with CARGO=cargo to
# route through sfw.
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"

# Quality + lint (clippy -D warnings is also the CI gate)
run "$CARGO" fmt --check
run "$CARGO" clippy --all-targets --all-features -- -D warnings

# SCA: dependency advisories (blocking gate in CI)
run "$CARGO" deny check advisories

# Secret scan over full history (same policy as CI gitleaks gate)
if command -v gitleaks >/dev/null 2>&1; then
  run gitleaks detect --source "$REPO_ROOT" --config "$REPO_ROOT/.gitleaks.toml" \
    --no-banner --redact --exit-code 1
else
  echo "⚠ gitleaks not installed — secret scan SKIPPED. Install: https://github.com/gitleaks/gitleaks/releases"
fi

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "✖ pre-push checks FAILED. Fix the issues above before pushing."
  echo "  (To bypass intentionally — discouraged: git push --no-verify)"
  exit 1
fi
echo "✔ pre-push checks passed."
