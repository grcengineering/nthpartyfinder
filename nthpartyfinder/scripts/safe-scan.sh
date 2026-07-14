#!/usr/bin/env bash
#
# safe-scan.sh — run an nthpartyfinder scan inside a hard resource envelope so a
# deep scan can never exhaust the local router's NAT/conntrack table and take the
# whole WiFi network down (observed on two networks during depth-3 testing).
#
# Why this exists, in one paragraph:
#   nthpartyfinder's per-subsystem concurrency knobs multiply rather than share a
#   global budget (vendors-in-flight × 5 joined discovery phases × per-method
#   concurrency × subfinder subprocesses × headless-Chrome page loads), so a deep
#   scan can open low-thousands of simultaneous flows. Consumer routers track every
#   flow — including timed-out and half-open ones — in a table of a few thousand
#   entries; once it fills, EVERY device on the LAN loses connectivity. Separately,
#   abnormal scan exits (timeout / Ctrl-C / panic) used to orphan headless-Chrome
#   trees that sat for days pinning connections. The in-code fixes address both, but
#   this wrapper is the belt-and-suspenders OS-level guarantee that holds regardless
#   of which code path misbehaves.
#
# What it does:
#   1. Pre-sweep: SIGKILL orphaned (re-parented to PID 1) headless-Chrome trees left
#      by earlier runs, matched by the rust-headless-chrome-profile signature. Only
#      orphans — never a Chrome that is still a child of a live process, so a
#      concurrent scan (or your real Chrome) is untouched.
#   2. Run the scan under `ulimit -n 512`: a hard OS ceiling on open file
#      descriptors. The process (and its children, which inherit the cap) physically
#      cannot hold more than ~512 simultaneous sockets no matter what the code does —
#      far under the few-thousand-entry conntrack table this exists to protect, yet
#      high enough not to starve a legitimate capped scan (a scan multiplexes DNS +
#      HTTP + one CDP socket per browser + log/result files; 256 risked EMFILE on
#      Linux, where the default is already 1024). This is the actual guarantee;
#      everything else is defense in depth.
#   3. Inject conservative rate/concurrency caps (only ones you did not set yourself).
#   4. Post-sweep on exit (via trap, so it runs even on Ctrl-C).
#
# Usage:
#   scripts/safe-scan.sh -d vanta.com --depth 3 -f html -o report ...
#   (pass exactly the args you would pass to nthpartyfinder; safety caps are added)
#
# Override a cap by passing it yourself, e.g. `--dns-rate-limit 25` wins over the
# default 10. Loosening a cap re-opens the risk this wrapper exists to close — do it
# knowingly, and never above what `ulimit -n 512` can physically back.

set -uo pipefail

# ── Locate the binary ──────────────────────────────────────────────────────────
CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${NTHPARTYFINDER_BIN:-$CRATE_DIR/target/release/nthpartyfinder}"

if [[ ! -x "$BIN" ]]; then
  echo "safe-scan: binary not found at $BIN" >&2
  echo "safe-scan: build it first (cargo build --release) or set NTHPARTYFINDER_BIN." >&2
  exit 1
fi

# ── Orphaned-Chrome sweep ────────────────────────────────────────────────────────
# An orphan is a headless-Chrome process carrying our profile signature whose parent
# is PID 1 (re-parented to init/launchd because the scanner that launched it died).
# The parent-is-dead test is the discriminator: a Chrome still owned by a live
# scanner has that scanner as its parent, not PID 1, so live work is never touched.
SIGNATURE='rust-headless-chrome-profile'

sweep_orphaned_chrome() {
  local phase="$1" pids
  # macOS + Linux: pid, ppid, full command. `-ww` disables command-column truncation so the
  # signature (Chrome's --user-data-dir arg) is never cut off. Match signature, keep only ppid==1.
  pids="$(ps -ww -axo pid=,ppid=,command= 2>/dev/null \
    | awk -v sig="$SIGNATURE" '$0 ~ sig && $2 == 1 { print $1 }')"
  if [[ -z "$pids" ]]; then
    echo "safe-scan: $phase sweep — no orphaned Chrome found."
    return 0
  fi
  local count
  count="$(echo "$pids" | wc -l | tr -d ' ')"
  echo "safe-scan: $phase sweep — killing $count orphaned Chrome process(es)."
  # shellcheck disable=SC2086
  echo "$pids" | xargs -r kill -9 2>/dev/null || true
}

# ── Inject a cap only if the user did not already set it ─────────────────────────
ALL_ARGS=("$@")
have_flag() {
  local needle="$1" a
  for a in "${ALL_ARGS[@]}"; do
    [[ "$a" == "$needle" || "$a" == "$needle="* ]] && return 0
  done
  return 1
}

SAFETY=()
add_cap() { have_flag "$1" || SAFETY+=("$1" "$2"); }

# Conservative envelope for local testing. Each is a politeness/concurrency cap that
# keeps total in-flight flows far under what `ulimit -n 512` allows.
add_cap --parallel-jobs     4    # cap per-depth vendor concurrency (default [50,20,10,5])
add_cap --dns-rate-limit    10   # DoH/UDP queries per second (default higher)
add_cap --http-rate-limit   10   # HTTP requests/sec per domain
add_cap --whois-concurrency 3    # concurrent WHOIS lookups (default 5)
add_cap --max-retries       2    # bound per-request retry fan-out

echo "safe-scan: binary   $BIN"
echo "safe-scan: fd limit ulimit -n 512 (hard socket ceiling)"
echo "safe-scan: caps     ${SAFETY[*]:-(none — all set by caller)}"
echo "safe-scan: args     ${ALL_ARGS[*]}"
echo

# Post-sweep runs even if the scan is interrupted.
trap 'echo; sweep_orphaned_chrome post' EXIT

sweep_orphaned_chrome pre
echo

# The subshell applies the fd ceiling to the scan and everything it spawns. If the
# ulimit itself fails we refuse to run rather than scan uncapped.
(
  ulimit -n 512 || { echo "safe-scan: could not set ulimit -n 512; refusing to run uncapped." >&2; exit 1; }
  exec "$BIN" "${ALL_ARGS[@]}" "${SAFETY[@]}"
)
rc=$?

echo
echo "safe-scan: scan exited with code $rc"
exit "$rc"
