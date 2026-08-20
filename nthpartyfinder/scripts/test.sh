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

# ── Advisory: assertion-less test scan (heuristic, NEVER fails the run) ────
# Flags #[test]/#[tokio::test] functions whose next 30 lines contain no
# assert/unwrap_err/expect_err/should_panic — a rough signal for tests that
# only exercise code without checking an outcome. Purely informational.
echo ""
echo "advisory: assertion-less tests (not failing the run):"
for f in tests/*.rs; do
    [ -f "$f" ] || continue
    total_lines=$(wc -l < "$f" | tr -d '[:space:]')
    { grep -n -E '^[[:space:]]*#\[(test|tokio::test)\]' "$f" 2>/dev/null | cut -d: -f1 | while read -r ln; do
        end=$((ln + 30))
        if [ "$end" -gt "$total_lines" ]; then
            end=$total_lines
        fi
        block=$(sed -n "${ln},${end}p" "$f")
        if ! printf '%s\n' "$block" | grep -qE 'assert|unwrap_err|expect_err|should_panic'; then
            fname=$(printf '%s\n' "$block" | grep -oE 'fn [A-Za-z0-9_]+' | head -1 | awk '{print $2}')
            echo "  ${f}:${ln} :: ${fname:-<unknown>}"
        fi
    done ; } || true
done
echo "(heuristic: fixed 30-line window from the attribute line; may false-positive/negative — never fails the build)"
