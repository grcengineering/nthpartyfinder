#!/bin/bash
# diff-scan-summary.sh — render the machine-diffable `dns-probe:` block from a scan-summary.json,
# optionally against a baseline sidecar. The SAME renderer serves the pre-merge DNS-probe rule
# (repo CLAUDE.md) and the daily canary's comparison, so the two cannot drift.
#
# Usage:
#   scripts/diff-scan-summary.sh <new-scan-summary.json> [baseline-scan-summary.json]
#
# Output: one `dns-probe:` header plus `key: value` lines (with `(baseline: value)` appended when
# a baseline is given). Pure read-only; exit 1 only on unreadable/invalid input files.
# bash 3.2 compatible (macOS system bash); requires jq.
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 <new-scan-summary.json> [baseline-scan-summary.json]" >&2
  exit 1
fi

NEW="$1"
BASE="${2:-}"

for f in "$NEW" ${BASE:+"$BASE"}; do
  if ! jq -e '.schema_version' "$f" >/dev/null 2>&1; then
    echo "error: $f is not a readable scan-summary.json" >&2
    exit 1
  fi
done

# One jq program computes every probe field from a sidecar, so new and baseline cannot be
# extracted differently. Fields:
#   backoff_ratio      governor.backoff_events / governor.total_queries (0 when no queries)
#   demotions          per-tier telemetry demotion counts, doh/dot/udp53
#   failures_per_query dns.failures / governor.total_queries — the defect-E headline invariant
#   backstop_fired     perf dns.deadline_backstop_fired (expected 0; absent in old sidecars)
extract() {
  jq -r '
    def perf_count(name): ([.perf[]? | select(.name == name) | .count] | first) // 0;
    def tier(name): ([.dns.telemetry.tiers[]? | select(.name == name)] | first) // {};
    {
      status: .meta.status,
      wall_secs: .meta.wall_secs,
      relationships: .analysis_summary.vendor_relationships,
      unique_vendors: .analysis_summary.unique_vendors,
      dns_queries: .dns.governor.total_queries,
      dns_failures: .dns.failures,
      name_failures: .dns.name_failures,
      failures_per_query: (if .dns.governor.total_queries > 0
        then ((.dns.failures / .dns.governor.total_queries * 10000 | round) / 10000)
        else 0 end),
      backoff_ratio: (if .dns.governor.total_queries > 0
        then ((.dns.governor.backoff_events / .dns.governor.total_queries * 10000 | round) / 10000)
        else 0 end),
      timeouts: .dns.governor.timeouts,
      rejections: .dns.governor.rejections,
      demotions_doh: (tier("doh").demotions // 0),
      demotions_dot: (tier("dot").demotions // 0),
      demotions_udp53: (tier("udp53").demotions // 0),
      governor_min: .dns.governor.min_limit_seen,
      governor_peak: .dns.governor.peak_limit,
      governor_end: .dns.governor.current_limit,
      floor_ms: (.dns.governor.floor_ms // 0),
      rtt_baseline_ms: ((.dns.governor.rtt_baseline_us // 0) / 1000 | round),
      doh_rtt_p95_ms: (tier("doh").rtt_p95_ms // "n/a"),
      backstop_fired: perf_count("dns.deadline_backstop_fired"),
      wrapper_timeouts: perf_count("dns.wrapper_timeout"),
      all_failed: perf_count("dns.all_failed")
    }
    | to_entries[] | "\(.key)=\(.value)"
  ' "$1"
}

echo "dns-probe: $(jq -r '.meta.args // "?"' "$NEW" | tr '\n' ' ' | sed 's/ $//')"
if [ -n "$BASE" ]; then
  # Join new and baseline values per key. Field order follows the extractor.
  extract "$NEW" >/tmp/dns-probe-new.$$
  extract "$BASE" >/tmp/dns-probe-base.$$
  while IFS='=' read -r key value; do
    base_value=$(grep "^${key}=" /tmp/dns-probe-base.$$ | head -1 | cut -d= -f2-)
    printf '  %s: %s (baseline: %s)\n' "$key" "$value" "${base_value:-n/a}"
  done </tmp/dns-probe-new.$$
  rm -f /tmp/dns-probe-new.$$ /tmp/dns-probe-base.$$
else
  extract "$NEW" | while IFS='=' read -r key value; do
    printf '  %s: %s\n' "$key" "$value"
  done
fi
