#!/bin/bash
# check-dns-canary.sh — compare one scan-summary.json against tests/canary/baseline.json.
#
# Usage: scripts/check-dns-canary.sh <scan-summary.json> <probe-domain> <baseline.json>
#
# Prints one line per checked bound; breaches are prefixed "BREACH". Exit 0 = all bounds hold,
# exit 1 = at least one breach, exit 2 = unreadable input. Shares its field extraction with
# scripts/diff-scan-summary.sh (the pre-merge dns-probe renderer) by construction: both read the
# same sidecar paths, so the canary and the PR rule cannot drift apart on what a metric means.
# bash 3.2 compatible; requires jq.
set -euo pipefail

if [ $# -ne 3 ]; then
  echo "usage: $0 <scan-summary.json> <probe-domain> <baseline.json>" >&2
  exit 2
fi
SUMMARY="$1"
PROBE="$2"
BASELINE="$3"

for f in "$SUMMARY" "$BASELINE"; do
  if ! jq -e . "$f" >/dev/null 2>&1; then
    echo "error: $f is not readable JSON" >&2
    exit 2
  fi
done

# Extract the canary metrics from the sidecar (same paths as diff-scan-summary.sh).
metrics=$(jq -r '
  def perf_count(name): ([.perf[]? | select(.name == name) | .count] | first) // 0;
  def tier(name): ([.dns.telemetry.tiers[]? | select(.name == name)] | first) // {};
  {
    status: .meta.status,
    wall_secs: (.meta.wall_secs // 0),
    relationships: (.analysis_summary.vendor_relationships // 0),
    dns_queries: (.dns.governor.total_queries // 0),
    dns_failures: (.dns.failures // 0),
    backoff_ratio: (if (.dns.governor.total_queries // 0) > 0
      then (.dns.governor.backoff_events / .dns.governor.total_queries)
      else 0 end),
    failures_per_query: (if (.dns.governor.total_queries // 0) > 0
      then (.dns.failures / .dns.governor.total_queries)
      else 0 end),
    demotions: ((tier("doh").demotions // 0) + (tier("dot").demotions // 0) + (tier("udp53").demotions // 0)),
    all_failed: perf_count("dns.all_failed"),
    backstop_fired: perf_count("dns.deadline_backstop_fired")
  } | to_entries[] | "\(.key)=\(.value)"
' "$SUMMARY")

get() { echo "$metrics" | grep "^$1=" | head -1 | cut -d= -f2-; }

bound() { jq -r ".bounds.$1" "$BASELINE"; }

breaches=0
check_max() {
  # check_max <metric> <bound-name>
  value=$(get "$1")
  limit=$(bound "$2")
  if [ "$(echo "$value $limit" | awk '{print ($1 <= $2) ? "ok" : "breach"}')" = "breach" ]; then
    echo "BREACH $PROBE: $1 = $value (max $limit)"
    breaches=$((breaches + 1))
  else
    echo "ok     $PROBE: $1 = $value (max $limit)"
  fi
}

status=$(get status)
if [ "$status" != "success" ]; then
  echo "BREACH $PROBE: status = $status (expected success)"
  breaches=$((breaches + 1))
fi

check_max backoff_ratio backoff_ratio_max
check_max demotions demotions_max
check_max failures_per_query failures_per_query_max
check_max all_failed all_failed_max
check_max backstop_fired backstop_fired_max
check_max wall_secs wall_secs_max

rel=$(get relationships)
rel_min=$(jq -r --arg p "$PROBE" '.relationships_min[$p] // 0' "$BASELINE")
if [ "$(echo "$rel $rel_min" | awk '{print ($1 >= $2) ? "ok" : "breach"}')" = "breach" ]; then
  echo "BREACH $PROBE: relationships = $rel (min $rel_min)"
  breaches=$((breaches + 1))
else
  echo "ok     $PROBE: relationships = $rel (min $rel_min)"
fi

[ "$breaches" -eq 0 ]
