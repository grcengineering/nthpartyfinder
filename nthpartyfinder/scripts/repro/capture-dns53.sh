#!/usr/bin/env bash
set -euo pipefail

# capture-dns53.sh <out.pcap>
#
# Observe-only packet capture for the DNS reliability repro matrix. Resolves
# the default-route interface, prints the exact tcpdump command it is about
# to run, refreshes sudo once, keeps the sudo timestamp alive in the
# background for the duration of the capture, then runs tcpdump in the
# foreground until SIGINT. Never kills unrelated processes, never touches
# config, never talks to the router beyond the passive capture itself.

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <out.pcap>" >&2
  exit 1
fi

OUT_PCAP="$1"

# Spec-literal awk pattern: `route -n get` prints a line like
# "  interface: en0" — $1 is "interface:" and $2 is the interface name.
IFACE=$(route -n get 192.168.1.1 | awk '/interface/{print $2}')

if [[ -z "${IFACE:-}" ]]; then
  echo "capture-dns53: could not resolve default-route interface via 'route -n get 192.168.1.1'" >&2
  exit 1
fi

TCPDUMP_FILTER='port 53 or port 853 or (tcp port 443 and (host 1.1.1.1 or host 1.0.0.1 or host 8.8.8.8 or host 8.8.4.4 or host 185.222.222.222 or host 45.11.45.11))'

echo "capture-dns53: interface = ${IFACE}"
echo "capture-dns53: about to run:"
echo "  sudo tcpdump -i ${IFACE} -n -s 0 -U -w ${OUT_PCAP} '${TCPDUMP_FILTER}'"

# Prompt for/refresh sudo credentials once, up front.
sudo -v

# NOTE(orchestrator): once `sudo tcpdump` is actually running, the kernel
# already holds the elevated capture privilege for that process — the sudo
# timestamp cache expiring mid-capture would only matter if we needed to
# invoke `sudo` *again* (e.g. to stop/restart). Spec asks for the keep-alive
# loop verbatim, so it's included exactly as specified; it's cheap and
# harmless even though it's not strictly load-bearing for a capture that's
# already underway.
KEEPALIVE_PID=""
cleanup() {
  if [[ -n "$KEEPALIVE_PID" ]]; then
    kill "$KEEPALIVE_PID" 2>/dev/null || true
    wait "$KEEPALIVE_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

( while true; do sudo -n -v; sleep 50; done ) &
KEEPALIVE_PID=$!

echo "capture-dns53: capturing to ${OUT_PCAP} — press Ctrl-C to stop."
sudo tcpdump -i "${IFACE}" -n -s 0 -U -w "${OUT_PCAP}" "${TCPDUMP_FILTER}"
