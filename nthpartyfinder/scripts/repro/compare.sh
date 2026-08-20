#!/usr/bin/env bash
set -euo pipefail

# compare.sh <matrix_output_root>
#
# Observe-only. For every arm directory under <matrix_output_root> that has
# a scan-summary.json (found via `find <arm_dir> -name scan-summary.json`),
# prints one aligned table row summarizing that arm's DNS/perf outcome.
# Read-only against the matrix output tree; no network activity.

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <matrix_output_root>" >&2
  exit 1
fi

ROOT="$1"

if [[ ! -d "$ROOT" ]]; then
  echo "compare: no such directory: ${ROOT}" >&2
  exit 1
fi

command -v jq >/dev/null 2>&1 || {
  echo "compare: jq is required" >&2
  exit 1
}

# scan-summary.json paths given in the task spec may not exist yet on any
# real sidecar — every leaf is defensively wrapped in `// "n/a"`.
#
# NOTE(orchestrator): the spec's literal wrapper_timeouts expression
# (".dns.wrapper_timeouts // .perf.rows[]?|select(.name==\"dns.wrapper_timeout\").count")
# parses in jq (pipe is lower-precedence than `//`) as
# "(.dns.wrapper_timeouts // .perf.rows[]?) | select(...).count" — i.e. it
# would pipe whichever scalar wrapper_timeouts resolves to *into* a
# select() expecting an object, which is not the evident intent (sum the
# matching perf-row counts as a fallback). Implemented defensively below:
# prefer .dns.wrapper_timeouts; if absent, sum perf.rows[] entries named
# "dns.wrapper_timeout"; else "n/a". Also added `?` after every bare `[]`
# iteration (.dns.providers[], .dns.tiers[], .perf.rows[]) since those
# throw (not just null) when the parent key is missing, which `// "n/a"`
# alone would not catch.
JQ_FILTER='
  [
    (.meta.wall_s // "n/a"),
    (.analysis_summary.vendor_relationships // "n/a"),
    (.dns.governor.backoff_ratio // "n/a"),
    (.dns.permit_wait_share // "n/a"),
    (.dns.providers[0].rtt_p95_ms // "n/a"),
    ([.dns.providers[]?.timeout_before_send] | add // "n/a"),
    ((.dns.tiers[]? | select(.name=="doh") | .demotions) // "n/a"),
    ((.dns.tiers[]? | select(.name=="dot") | .demotions) // "n/a"),
    ((.dns.tiers[]? | select(.name=="udp53") | .demotions) // "n/a"),
    ((.dns.wrapper_timeouts // ([.perf.rows[]? | select(.name=="dns.wrapper_timeout") | .count] | add)) // "n/a"),
    (.dns.all_resolution_failed_warns // "n/a"),
    (.dns.inflation_factor // "n/a")
  ] | map(tostring) | @tsv
'

HEADER_FMT="%-22s %10s %14s %14s %10s %12s %14s %22s %18s %16s %10s\n"
ROW_FMT="%-22s %10s %14s %14s %10s %12s %14s %22s %18s %16s %10s\n"

# shellcheck disable=SC2059
printf "$HEADER_FMT" "ARM" "WALL_S" "RELATIONSHIPS" "BACKOFF_RATIO" "S_WAIT" "DOH_P95_MS" "T_BEFORE_SEND" "DEMOTIONS_DOH/DOT/UDP" "WRAPPER_TIMEOUTS" "ALL_FAILED" "INFLATION"

FOUND_ANY=false
for arm_dir in "$ROOT"/*/; do
  [[ -d "$arm_dir" ]] || continue
  arm_name=$(basename "$arm_dir")

  summary_path=""
  summary_path=$(find "$arm_dir" -name scan-summary.json 2>/dev/null | head -n1 || true)
  [[ -n "$summary_path" ]] || continue
  FOUND_ANY=true

  tmp_err=$(mktemp)
  row=""
  if ! row=$(jq -r --arg srcfile "$summary_path" "$JQ_FILTER" "$summary_path" 2>"$tmp_err"); then
    echo "compare: jq failed on ${summary_path}:" >&2
    cat "$tmp_err" >&2
    row=$(printf 'n/a\tn/a\tn/a\tn/a\tn/a\tn/a\tn/a\tn/a\tn/a\tn/a\tn/a\tn/a')
  fi
  rm -f "$tmp_err"

  IFS=$'\t' read -r -a fields <<<"$row"
  # fields: 0 wall_s 1 relationships 2 backoff_ratio 3 s_wait 4 doh_p95_ms
  #         5 t_before_send 6 doh_demotions 7 dot_demotions 8 udp_demotions
  #         9 wrapper_timeouts 10 all_failed 11 inflation
  demotions_combined="${fields[6]:-n/a}/${fields[7]:-n/a}/${fields[8]:-n/a}"

  # shellcheck disable=SC2059
  printf "$ROW_FMT" \
    "$arm_name" "${fields[0]:-n/a}" "${fields[1]:-n/a}" "${fields[2]:-n/a}" \
    "${fields[3]:-n/a}" "${fields[4]:-n/a}" "${fields[5]:-n/a}" \
    "$demotions_combined" "${fields[9]:-n/a}" "${fields[10]:-n/a}" "${fields[11]:-n/a}"
done

if [[ "$FOUND_ANY" == false ]]; then
  echo "compare: no scan-summary.json found under ${ROOT}" >&2
fi
