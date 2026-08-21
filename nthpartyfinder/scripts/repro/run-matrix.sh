#!/usr/bin/env bash
set -euo pipefail

# run-matrix.sh <binary> <matrix_output_root>
#
# Drives the 14-arm DNS reliability repro matrix by invoking the already
# built nthpartyfinder binary with different flag sets, one arm at a time,
# waiting for DNS-forwarder recovery between arms. Observe-only from this
# script's own point of view: it never builds anything (the binary must
# already exist), never touches config, and never starts/stops capture —
# it only launches/waits-on the scanner binary and records results.
#
# This script does NOT start or stop tcpdump / probe-providers.sh. Start
# capture-dns53.sh and probe-providers.sh yourself, in separate terminals,
# BEFORE running this matrix, and stop them yourself afterward.

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <binary> <matrix_output_root>" >&2
  exit 1
fi

BINARY="$1"
ROOT="$2"

if [[ ! -x "$BINARY" ]]; then
  echo "run-matrix: ${BINARY} is not an executable file" >&2
  exit 1
fi

mkdir -p "$ROOT"
MATRIX_JSONL="${ROOT}/matrix.jsonl"

# name|extra-args, exactly as specified. IDLE / DEPTH2 are sentinels
# handled specially below, not literal CLI flags.
ARMS=(
  "arm0-idle|IDLE"
  "arm-i-baseline|"
  "arm-iv-dnsonly|--dns-only"
  "arm-iiia-conn512|--max-connections 512"
  "arm-iiib-conn32|--max-connections 32"
  "arm-ii-pin16|--dns-max-concurrency 16"
  "arm-d2-depth2|DEPTH2"
  "arm-v-nosaas|--disable-saas-tenant-discovery"
  "arm-v-nosubproc|--disable-subprocessor-analysis"
  "arm-v-nowebtraffic|--disable-web-traffic-discovery"
  "arm-v-nosubdomain|--disable-subdomain-discovery"
  "arm-ii-pin8|--dns-max-concurrency 8"
  "arm-ii-pin32|--dns-max-concurrency 32"
  "arm-ii-pin64|--dns-max-concurrency 64"
)

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

run_arm() {
  local name="$1" extra="$2"
  local arm_dir="${ROOT}/${name}"
  mkdir -p "$arm_dir"

  # Resume guard: an arm already recorded with exit 0 is not re-run (a crashed or
  # edited runner can be relaunched without burning completed arms' network cost).
  if [[ -f "$MATRIX_JSONL" ]] && grep -q "\"arm\":\"${name}\".*\"exit\":0" "$MATRIX_JSONL"; then
    echo "run-matrix: [${name}] already completed (matrix.jsonl) — skipping"
    return 0
  fi

  local start_iso end_iso exit_code=0 cmd_display
  start_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "run-matrix: [${name}] starting at ${start_iso}"

  if [[ "$extra" == "IDLE" ]]; then
    cmd_display="sleep 600"
    echo "run-matrix: [${name}] IDLE arm — sleeping 600s (no scan invoked)"
    sleep 600
    exit_code=0
  else
    local depth=3 timeout_val=900
    local extra_args=()

    if [[ "$extra" == "DEPTH2" ]]; then
      depth=2
    elif [[ -n "$extra" ]]; then
      # Intentional word-splitting: entries like "--max-connections 512"
      # must become two separate argv tokens for the binary.
      # shellcheck disable=SC2206
      extra_args=( $extra )
    fi

    if [[ "$name" == "arm-i-baseline" ]]; then
      timeout_val=0
    fi

    local base_args=(
      -d vanta.com -r "$depth" -f html --no-resume -v
      --timeout "$timeout_val"
      --log-file "${arm_dir}/scan.log"
      --output-dir "${arm_dir}"
    )
    # bash 3.2 (macOS default): "${arr[@]}" on an EMPTY array trips `set -u`.
    # The ${arr[@]+...} guard expands to nothing when the array is empty.
    local full_args=("${base_args[@]}" ${extra_args[@]+"${extra_args[@]}"})

    cmd_display="${BINARY} ${full_args[*]}"
    echo "run-matrix: [${name}] cmd: ${cmd_display}"

    set +e
    "${BINARY}" "${full_args[@]}" >"${arm_dir}/console.log" 2>&1
    exit_code=$?
    set -e
  fi

  end_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf '{"arm":"%s","start":"%s","end":"%s","cmd":"%s","exit":%d}\n' \
    "$name" "$start_iso" "$end_iso" "$(json_escape "$cmd_display")" "$exit_code" >>"$MATRIX_JSONL"
  echo "run-matrix: [${name}] finished at ${end_iso} (exit=${exit_code})"
}

wait_for_recovery() {
  echo "run-matrix: waiting for DNS forwarder recovery (5 consecutive successful probes, 10s apart)..."
  local consecutive=0
  while true; do
    if dig @192.168.1.1 +time=2 +tries=1 example.com >/dev/null 2>&1; then
      consecutive=$((consecutive + 1))
    else
      consecutive=0
    fi
    echo "run-matrix: forwarder probe — consecutive successes: ${consecutive}/5"
    if [[ "$consecutive" -ge 5 ]]; then
      break
    fi
    sleep 10
  done
  echo "run-matrix: forwarder recovered — 300s cooldown before next arm"
  sleep 300
}

echo "run-matrix: REMINDER — this script does not start/stop tcpdump or"
echo "run-matrix: probe-providers.sh. Start capture-dns53.sh and"
echo "run-matrix: probe-providers.sh yourself in separate terminals first."
echo "run-matrix: binary=${BINARY}"
echo "run-matrix: output root=${ROOT}"
echo "run-matrix: matrix log=${MATRIX_JSONL}"

TOTAL_ARMS=${#ARMS[@]}
IDX=0
for entry in "${ARMS[@]}"; do
  IDX=$((IDX + 1))
  NAME="${entry%%|*}"
  EXTRA="${entry#*|}"
  echo "run-matrix: === arm ${IDX}/${TOTAL_ARMS}: ${NAME} ==="
  run_arm "$NAME" "$EXTRA"
  if [[ "$IDX" -lt "$TOTAL_ARMS" ]]; then
    wait_for_recovery
  fi
done

echo "run-matrix: all arms complete. Results in ${MATRIX_JSONL}"
