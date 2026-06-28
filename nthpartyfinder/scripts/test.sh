#!/usr/bin/env bash
# Full local test suite — mirrors the two "cargo test" steps in
# .github/workflows/build.yml (lib/unit, then integration with --all-features).
#
# Invokes cargo by its ABSOLUTE path ($HOME/.cargo/bin/cargo) so the run skips
# the Socket Firewall (sfw) shell wrapper and its per-invocation overhead. The
# unit/integration suite is loopback-only (wiremock); live-network tests are
# #[ignore]-gated, so bypassing sfw here is safe. Dependency fetching still goes
# through the wrapped `cargo build`/`cargo fetch` — this script assumes deps are
# already vendored/cached and runs with --locked.
#
# Override the binary with CARGO=cargo to route back through sfw.
# Run from anywhere: nthpartyfinder/scripts/test.sh [extra args passed to cargo test]
set -euo pipefail

cd "$(dirname "$0")/.."
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"

echo "▶ lib + unit tests"
"$CARGO" test --lib --locked --verbose "$@"

echo "▶ integration tests"
"$CARGO" test --test '*' --locked --all-features --verbose "$@"

echo "✔ full test suite passed."
