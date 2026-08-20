#!/usr/bin/env bash
set -euo pipefail

# probe-providers.sh [interval_secs=5] [out=probes.jsonl]
#
# Observe-only. Loops forever (until SIGINT) probing the 6 DoH endpoints,
# 3 DoT servers, and 5 public/1 LAN UDP/53 servers used by the nthpartyfinder
# DNS reliability repro matrix (Plans/zesty-tinkering-falcon.md, Phase 1).
# Appends one JSON line per probe to the output file. Never kills anything,
# never modifies config, never calls the router beyond the plain DNS probes
# the matrix already relies on.

INTERVAL="${1:-5}"
OUT="${2:-probes.jsonl}"

# NOTE(orchestrator): "interval_secs" — assumed to be the delay between full
# probe cycles (all endpoints), not between individual probes within a cycle.
# Conservative reading: one full sweep, then sleep $INTERVAL, repeat.

DOH_ENDPOINTS=(
  "https://1.1.1.1/dns-query"
  "https://8.8.8.8/resolve"
  "https://185.222.222.222/dns-query"
  "https://1.0.0.1/dns-query"
  "https://8.8.4.4/resolve"
  "https://45.11.45.11/dns-query"
)

DOT_SERVERS=(
  "1.1.1.1"
  "9.9.9.9"
  "8.8.8.8"
)

UDP53_SERVERS=(
  "1.1.1.1"
  "8.8.8.8"
  "9.9.9.9"
  "208.67.222.222"
  "192.168.1.1"
)

# NOTE(orchestrator): BSD `date` has no %N / sub-second precision, so a
# millisecond epoch timestamp isn't directly available from `date` alone.
# Prefer python3 (present via Xcode CLT on most macOS dev boxes) when
# available; conservative fallback is whole-second epoch padded to ms
# (".000" resolution only) rather than inventing a fake sub-second value.
ts_ms() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import time; print(f"{time.time()*1000:.0f}")'
  else
    echo "$(date +%s)000"
  fi
}

# emit_probe target transport ok code ms
emit_probe() {
  local target="$1" transport="$2" ok="$3" code="$4" ms="$5" ts
  ts=$(ts_ms)
  printf '{"ts":%s,"target":"%s","transport":"%s","ok":%s,"code":"%s","ms":%s}\n' \
    "$ts" "$target" "$transport" "$ok" "$code" "$ms" >>"$OUT"
}

probe_doh() {
  local url="$1"
  local out rc=0
  out=$(curl -sS -o /dev/null -m 3 -w '%{http_code} %{time_total}' \
    -H 'accept: application/dns-json' \
    "${url}?name=example.com&type=TXT" 2>/dev/null) || rc=$?

  if [[ $rc -ne 0 || -z "$out" ]]; then
    emit_probe "$url" "doh" false "curl_err_${rc}" 0
    return
  fi

  local code time_total ms ok
  code=$(awk '{print $1}' <<<"$out")
  time_total=$(awk '{print $2}' <<<"$out")
  ms=$(awk -v t="$time_total" 'BEGIN{printf "%.1f", t*1000}')
  ok=false
  [[ "$code" == "200" ]] && ok=true
  emit_probe "$url" "doh" "$ok" "$code" "$ms"
}

# Probed once at startup: does the local `dig` support DoT (+tls)?
DIG_TLS_SUPPORTED=false
if dig +tls +tries=1 +time=2 @1.1.1.1 example.com TXT >/dev/null 2>&1; then
  DIG_TLS_SUPPORTED=true
fi

probe_dot_dig() {
  local ip="$1" start end ms rc=0
  start=$(ts_ms)
  if ! dig +tls +tries=1 +time=2 "@${ip}" example.com TXT >/dev/null 2>&1; then
    rc=$?
  fi
  end=$(ts_ms)
  ms=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.1f", e-s}')
  local ok=false code="dig_err_${rc}"
  if [[ $rc -eq 0 ]]; then
    ok=true
    code="ok"
  fi
  emit_probe "$ip" "dot" "$ok" "$code" "$ms"
}

# Fallback when `dig +tls` isn't supported: raw TLS reachability via
# openssl s_client, guarded by a shell-implemented watchdog since macOS
# lacks GNU `timeout`.
probe_dot_openssl() {
  local ip="$1" start end ms rc=0 tmp pid watchdog_pid
  tmp=$(mktemp)
  start=$(ts_ms)
  ( openssl s_client -connect "${ip}:853" -brief </dev/null >"$tmp" 2>&1 ) &
  pid=$!
  ( sleep 4; kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null ) &
  watchdog_pid=$!
  wait "$pid" 2>/dev/null || rc=$?
  kill "$watchdog_pid" 2>/dev/null || true
  wait "$watchdog_pid" 2>/dev/null || true
  end=$(ts_ms)
  ms=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.1f", e-s}')
  local ok=false code="openssl_err_${rc}"
  if [[ $rc -eq 0 ]]; then
    ok=true
    code="ok"
  fi
  rm -f "$tmp"
  emit_probe "$ip" "dot" "$ok" "$code" "$ms"
}

probe_dot() {
  local ip="$1"
  if [[ "$DIG_TLS_SUPPORTED" == true ]]; then
    probe_dot_dig "$ip"
  else
    probe_dot_openssl "$ip"
  fi
}

# NOTE(orchestrator): "ok" for udp53/dot is transport reachability (did we
# get *a* response / clean handshake at all), not whether the DNS answer
# itself was NOERROR — the "code" field carries the rcode/http_code/err so
# a caller can tell the two apart without us guessing NXDOMAIN-vs-error
# semantics on the probe.grc.engineering / probe.example.com throwaway names.
probe_udp53() {
  local ip="$1" epoch qname start end ms rc=0 out rcode
  epoch=$(date +%s)
  if [[ "$ip" == "192.168.1.1" ]]; then
    qname="r${epoch}.probe.grc.engineering"
  else
    qname="r${epoch}.probe.example.com"
  fi
  start=$(ts_ms)
  out=$(dig +tries=1 +time=2 "@${ip}" txt "$qname" 2>/dev/null) || rc=$?
  end=$(ts_ms)
  ms=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.1f", e-s}')

  local ok=false
  if [[ $rc -ne 0 ]]; then
    rcode="dig_err_${rc}"
  else
    ok=true
    rcode=$(printf '%s\n' "$out" | awk '/status:/{for(i=1;i<=NF;i++){if($i=="status:"){print $(i+1);exit}}}')
    rcode=${rcode%,}
    [[ -z "$rcode" ]] && rcode="UNKNOWN"
  fi
  emit_probe "$ip" "udp53" "$ok" "$rcode" "$ms"
}

on_sigint() {
  echo "probe-providers: received SIGINT, exiting." >&2
  exit 0
}
trap on_sigint INT

echo "probe-providers: writing to ${OUT}, interval=${INTERVAL}s, dig+tls support=${DIG_TLS_SUPPORTED}" >&2

while true; do
  for url in "${DOH_ENDPOINTS[@]}"; do
    probe_doh "$url"
  done
  for ip in "${DOT_SERVERS[@]}"; do
    probe_dot "$ip"
  done
  for ip in "${UDP53_SERVERS[@]}"; do
    probe_udp53 "$ip"
  done
  sleep "$INTERVAL"
done
