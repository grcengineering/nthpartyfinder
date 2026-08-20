#!/usr/bin/env bash
set -euo pipefail

# recheck-names.sh <scan-summary.json> [out=recheck.jsonl]
#
# Observe-only. Pulls the unique failed-name sample out of a
# scan-summary.json sidecar and re-resolves each one over DoH (1.1.1.1),
# recording per-name resolvability. No mutation, no router calls.

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <scan-summary.json> [out=recheck.jsonl]" >&2
  exit 1
fi

SUMMARY_JSON="$1"
OUT="${2:-recheck.jsonl}"

if [[ ! -f "$SUMMARY_JSON" ]]; then
  echo "recheck-names: no such file: ${SUMMARY_JSON}" >&2
  exit 1
fi

command -v jq >/dev/null 2>&1 || {
  echo "recheck-names: jq is required" >&2
  exit 1
}

: >"$OUT"

# NOTE(orchestrator): "emit ... and a final summary line resolvable/total"
# — a bare "N/M" line is not valid JSON, so appending it to a .jsonl file
# would break that file for any downstream jq consumer. Conservative
# reading: per-name JSON objects go to $OUT (keeps it a clean JSONL file);
# the human-readable resolvable/total summary line goes to stdout only.

DIG_HTTPS_SUPPORTED=false
if dig +https +tries=1 +time=2 @1.1.1.1 example.com TXT >/dev/null 2>&1; then
  DIG_HTTPS_SUPPORTED=true
fi
echo "recheck-names: dig +https support=${DIG_HTTPS_SUPPORTED}" >&2

extract_status_curl() {
  local json="$1"
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$json" | jq -r '.Status // empty' 2>/dev/null
  else
    printf '%s' "$json" | grep -oE '"Status":[0-9]+' | head -n1 | grep -oE '[0-9]+$'
  fi
}

RESOLVABLE_COUNT=0
TOTAL_COUNT=0

recheck_name() {
  local name="$1" resolvable="false" rcode="unknown"

  if [[ "$DIG_HTTPS_SUPPORTED" == true ]]; then
    local out rc=0
    out=$(dig +https @1.1.1.1 "$name" TXT +tries=1 +time=3 2>/dev/null) || rc=$?
    if [[ $rc -ne 0 ]]; then
      rcode="dig_err_${rc}"
      resolvable="false"
    else
      rcode=$(printf '%s\n' "$out" | awk '/status:/{for(i=1;i<=NF;i++){if($i=="status:"){print $(i+1);exit}}}')
      rcode=${rcode%,}
      [[ -z "$rcode" ]] && rcode="UNKNOWN"
      if [[ "$rcode" == "NOERROR" ]]; then
        resolvable="true"
      else
        resolvable="false"
      fi
    fi
  else
    local resp rc=0
    resp=$(curl -sS -m 3 -H 'accept: application/dns-json' \
      "https://1.1.1.1/dns-query?name=${name}&type=TXT" 2>/dev/null) || rc=$?
    if [[ $rc -ne 0 || -z "$resp" ]]; then
      rcode="curl_err_${rc}"
      resolvable="false"
    else
      local status
      status=$(extract_status_curl "$resp")
      if [[ -z "$status" ]]; then
        rcode="unknown"
        resolvable="false"
      elif [[ "$status" == "0" ]]; then
        rcode="NOERROR"
        resolvable="true"
      else
        rcode="STATUS_${status}"
        resolvable="false"
      fi
    fi
  fi

  printf '{"name":"%s","resolvable":%s,"rcode":"%s"}\n' "$name" "$resolvable" "$rcode" >>"$OUT"
  TOTAL_COUNT=$((TOTAL_COUNT + 1))
  if [[ "$resolvable" == "true" ]]; then
    RESOLVABLE_COUNT=$((RESOLVABLE_COUNT + 1))
  fi
}

NAMES=()
while IFS= read -r line; do
  [[ -n "$line" ]] && NAMES+=("$line")
done < <(jq -r '.dns.failed_names_sample[]?.name // empty' "$SUMMARY_JSON" | sort -u)

if [[ ${#NAMES[@]} -eq 0 ]]; then
  echo "recheck-names: no names found at .dns.failed_names_sample[]?.name in ${SUMMARY_JSON}" >&2
else
  for name in "${NAMES[@]}"; do
    recheck_name "$name"
  done
fi

echo "recheck-names: wrote ${OUT}"
echo "${RESOLVABLE_COUNT}/${TOTAL_COUNT}"
