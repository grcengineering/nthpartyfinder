#!/usr/bin/env bash
set -euo pipefail

# summarize-pcap.sh <in.pcap> [from_epoch] [to_epoch]
#
# Observe-only. Reads a pcap captured by capture-dns53.sh, classifies
# packets into the DNS-tier buckets the repro matrix cares about, and prints
# a fixed-width table plus a machine-readable <in>.summary.json next to the
# pcap. Read-only against the pcap file; no network activity.
#
# Uses `tcpdump -r <pcap> -n -tt` for text decoding (available on the same
# macOS boxes tcpdump-capturing already requires). If tcpdump ever isn't
# available where this needs to run, `tshark -r <pcap> -n -t e` is a decent
# drop-in for producing similarly-shaped per-packet text lines, but that
# substitution is NOT implemented here — this script hard-requires tcpdump.

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <in.pcap> [from_epoch] [to_epoch]" >&2
  exit 1
fi

IN_PCAP="$1"
FROM_EPOCH="${2:-}"
TO_EPOCH="${3:-}"

if [[ ! -f "$IN_PCAP" ]]; then
  echo "summarize-pcap: no such file: ${IN_PCAP}" >&2
  exit 1
fi

command -v tcpdump >/dev/null 2>&1 || {
  echo "summarize-pcap: tcpdump not found on PATH" >&2
  exit 1
}

TMPDIR_WORK=$(mktemp -d)
cleanup() { rm -rf "$TMPDIR_WORK"; }
trap cleanup EXIT

ALL_LINES="${TMPDIR_WORK}/all.txt"
TCPDUMP_ERR="${TMPDIR_WORK}/tcpdump.err"

if ! tcpdump -r "$IN_PCAP" -n -tt >"$ALL_LINES" 2>"$TCPDUMP_ERR"; then
  echo "summarize-pcap: tcpdump failed reading ${IN_PCAP}:" >&2
  cat "$TCPDUMP_ERR" >&2
  exit 1
fi

FILTERED="${TMPDIR_WORK}/filtered.txt"
if [[ -n "$FROM_EPOCH" || -n "$TO_EPOCH" ]]; then
  awk -v from="${FROM_EPOCH:-0}" -v to="${TO_EPOCH:-99999999999}" \
    '{ if (($1+0) >= from && ($1+0) <= to) print }' "$ALL_LINES" >"$FILTERED"
else
  cp "$ALL_LINES" "$FILTERED"
fi

TOTAL_LINES=$(wc -l <"$FILTERED" | awk '{print $1}')

if [[ "$TOTAL_LINES" -gt 0 ]]; then
  FIRST_TS=$(awk 'NR==1{print $1}' "$FILTERED")
  LAST_TS=$(awk 'END{print $1}' "$FILTERED")
else
  FIRST_TS=0
  LAST_TS=0
fi

if [[ -n "$FROM_EPOCH" && -n "$TO_EPOCH" ]]; then
  WINDOW=$(awk -v a="$FROM_EPOCH" -v b="$TO_EPOCH" 'BEGIN{d=b-a; if(d<=0)d=1; print d}')
else
  WINDOW=$(awk -v a="$FIRST_TS" -v b="$LAST_TS" 'BEGIN{d=b-a; if(d<=0)d=1; print d}')
fi

qps() { awk -v c="$1" -v w="$WINDOW" 'BEGIN{printf "%.4f", c/w}'; }

count_matches() {
  # count_matches <ERE> <file> — grep -c that never trips set -e on a
  # zero-match (exit 1) result.
  local pattern="$1" file="$2" n
  n=$(grep -cE "$pattern" "$file" 2>/dev/null || true)
  echo "${n:-0}"
}

# --- classification patterns -------------------------------------------
GETADDR_RE='> 192\.168\.1\.1\.53: [0-9]+\+? (A|AAAA)\? '
SYSRES_RE='> 192\.168\.1\.1\.53: [0-9]+\+? (TXT|CNAME)\? '
HICKORY_RE='> (1\.1\.1\.1|8\.8\.8\.8|9\.9\.9\.9|208\.67\.222\.222)\.53: [0-9]+\+? (TXT|CNAME)\? '
DOT_SYN_RE='> [0-9.]+\.853: Flags \[S\],'
DOH_SYN_RE='> (1\.1\.1\.1|1\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|185\.222\.222\.222|45\.11\.45\.11)\.443: Flags \[S\],'
SERVFAIL_RE='192\.168\.1\.1\.53 > .*ServFail'

GETADDR_TOTAL=$(count_matches "$GETADDR_RE" "$FILTERED")
SYSRES_TOTAL=$(count_matches "$SYSRES_RE" "$FILTERED")
HICKORY_TOTAL=$(count_matches "$HICKORY_RE" "$FILTERED")
DOT_SYN_TOTAL=$(count_matches "$DOT_SYN_RE" "$FILTERED")
DOH_SYN_TOTAL=$(count_matches "$DOH_SYN_RE" "$FILTERED")
SERVFAIL_TOTAL=$(grep -icE "$SERVFAIL_RE" "$FILTERED" 2>/dev/null || true)
SERVFAIL_TOTAL=${SERVFAIL_TOTAL:-0}

# --- getaddrinfo sub-classification by qname bucket ---------------------
# probe-noise (contains "probe."), CT (crt.sh|certspotter), else "other".
# Deeper sub-classing of "other" is deliberately left for manual review —
# TODO(human): break "other" down further once real qname patterns are seen.
GETADDR_LINES="${TMPDIR_WORK}/getaddr_lines.txt"
{ grep -E "$GETADDR_RE" "$FILTERED" || true; } >"$GETADDR_LINES"

read -r GETADDR_PROBE GETADDR_CT GETADDR_OTHER < <(awk '
  /probe\./ { probe++; next }
  /crt\.sh|certspotter/ { ct++; next }
  { other++ }
  END { printf "%d %d %d\n", probe+0, ct+0, other+0 }
' "$GETADDR_LINES")

# --- best-effort "query to 192.168.1.1 with no response seen" -----------
# NOTE(orchestrator): true request/response correlation would need full
# transaction-state tracking. Best-effort here: tcpdump's default (non -v)
# text format puts the 16-bit DNS transaction ID at a stable whitespace
# field (6th token) for both queries and responses, so we diff the query-ID
# set against the response-ID set. This is approximate — 16-bit IDs can
# collide within a busy window, which would under-count "no response" — so
# treat this figure as a lower bound, not an exact count.
QIDS_QUERY="${TMPDIR_WORK}/qids_query.txt"
QIDS_RESP="${TMPDIR_WORK}/qids_resp.txt"
{ grep -E '> 192\.168\.1\.1\.53: [0-9]+\+' "$FILTERED" || true; } \
  | awk '{print $6}' | sed 's/\+$//' | sort -u >"$QIDS_QUERY"
{ grep -E '^[0-9.]+ IP 192\.168\.1\.1\.53 >' "$FILTERED" || true; } \
  | awk '{print $6}' | sort -u >"$QIDS_RESP"
NO_RESPONSE_TOTAL=$(comm -23 "$QIDS_QUERY" "$QIDS_RESP" | wc -l | awk '{print $1}')

# --- output: fixed-width table ------------------------------------------
printf "%-30s %10s %10s\n" "CLASS" "COUNT" "QPS"
printf "%-30s %10s %10s\n" "------------------------------" "----------" "----------"
printf "%-30s %10s %10s\n" "getaddrinfo_A_AAAA_total" "$GETADDR_TOTAL" "$(qps "$GETADDR_TOTAL")"
printf "%-30s %10s %10s\n" "  getaddrinfo_probe_noise" "$GETADDR_PROBE" "$(qps "$GETADDR_PROBE")"
printf "%-30s %10s %10s\n" "  getaddrinfo_ct" "$GETADDR_CT" "$(qps "$GETADDR_CT")"
printf "%-30s %10s %10s\n" "  getaddrinfo_other" "$GETADDR_OTHER" "$(qps "$GETADDR_OTHER")"
printf "%-30s %10s %10s\n" "system_resolver_TXT_CNAME" "$SYSRES_TOTAL" "$(qps "$SYSRES_TOTAL")"
printf "%-30s %10s %10s\n" "hickory_udp_TXT_CNAME" "$HICKORY_TOTAL" "$(qps "$HICKORY_TOTAL")"
printf "%-30s %10s %10s\n" "dot_syn" "$DOT_SYN_TOTAL" "$(qps "$DOT_SYN_TOTAL")"
printf "%-30s %10s %10s\n" "doh_syn" "$DOH_SYN_TOTAL" "$(qps "$DOH_SYN_TOTAL")"
printf "%-30s %10s %10s\n" "servfail_from_192.168.1.1" "$SERVFAIL_TOTAL" "$(qps "$SERVFAIL_TOTAL")"
printf "%-30s %10s %10s\n" "no_response_seen_192.168.1.1*" "$NO_RESPONSE_TOTAL" "$(qps "$NO_RESPONSE_TOTAL")"
echo "* best-effort txn-ID correlation, lower bound only — see NOTE(orchestrator) in script"
echo
echo "window_seconds=${WINDOW} total_lines=${TOTAL_LINES} first_ts=${FIRST_TS} last_ts=${LAST_TS}"

# --- output: machine-readable summary json -------------------------------
BASE="${IN_PCAP%.pcap}"
SUMMARY_JSON="${BASE}.summary.json"

printf '{\n' >"$SUMMARY_JSON"
printf '  "pcap":"%s",\n' "$IN_PCAP" >>"$SUMMARY_JSON"
printf '  "from_epoch":"%s",\n' "$FROM_EPOCH" >>"$SUMMARY_JSON"
printf '  "to_epoch":"%s",\n' "$TO_EPOCH" >>"$SUMMARY_JSON"
printf '  "window_seconds":%s,\n' "$WINDOW" >>"$SUMMARY_JSON"
printf '  "total_lines":%s,\n' "$TOTAL_LINES" >>"$SUMMARY_JSON"
printf '  "classes":{\n' >>"$SUMMARY_JSON"
printf '    "getaddrinfo_total":{"count":%s,"qps":%s},\n' "$GETADDR_TOTAL" "$(qps "$GETADDR_TOTAL")" >>"$SUMMARY_JSON"
printf '    "getaddrinfo_probe_noise":{"count":%s,"qps":%s},\n' "$GETADDR_PROBE" "$(qps "$GETADDR_PROBE")" >>"$SUMMARY_JSON"
printf '    "getaddrinfo_ct":{"count":%s,"qps":%s},\n' "$GETADDR_CT" "$(qps "$GETADDR_CT")" >>"$SUMMARY_JSON"
printf '    "getaddrinfo_other":{"count":%s,"qps":%s},\n' "$GETADDR_OTHER" "$(qps "$GETADDR_OTHER")" >>"$SUMMARY_JSON"
printf '    "system_resolver_txt_cname":{"count":%s,"qps":%s},\n' "$SYSRES_TOTAL" "$(qps "$SYSRES_TOTAL")" >>"$SUMMARY_JSON"
printf '    "hickory_udp_txt_cname":{"count":%s,"qps":%s},\n' "$HICKORY_TOTAL" "$(qps "$HICKORY_TOTAL")" >>"$SUMMARY_JSON"
printf '    "dot_syn":{"count":%s,"qps":%s},\n' "$DOT_SYN_TOTAL" "$(qps "$DOT_SYN_TOTAL")" >>"$SUMMARY_JSON"
printf '    "doh_syn":{"count":%s,"qps":%s},\n' "$DOH_SYN_TOTAL" "$(qps "$DOH_SYN_TOTAL")" >>"$SUMMARY_JSON"
printf '    "servfail_from_192_168_1_1":{"count":%s,"qps":%s},\n' "$SERVFAIL_TOTAL" "$(qps "$SERVFAIL_TOTAL")" >>"$SUMMARY_JSON"
printf '    "no_response_seen_192_168_1_1_best_effort":{"count":%s,"qps":%s}\n' "$NO_RESPONSE_TOTAL" "$(qps "$NO_RESPONSE_TOTAL")" >>"$SUMMARY_JSON"
printf '  }\n' >>"$SUMMARY_JSON"
printf '}\n' >>"$SUMMARY_JSON"

echo "summarize-pcap: wrote ${SUMMARY_JSON}"
