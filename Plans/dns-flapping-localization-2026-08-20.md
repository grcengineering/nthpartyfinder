# DNS flapping — localized (Phase 1 of Plans/zesty-tinkering-falcon.md)

**Date:** 2026-08-20 · **Binary:** v1.7.0 + Phase-0 telemetry (master `5531911`) · **Matrix:** 14 arms, ~5 h, unattended · **Sidecars:** `~/Desktop/npf-dns-matrix/` (13 scan-summary.json + probes.jsonl 3,007 samples + matrix.pcap 166 MB + matrix.summary.json)

This closes d646b7c's "48% flapping, not yet localized" (2026-07-29). Every number below is from a scan's own sidecar, the independent 5 s provider probes, or the packet capture.

## Verdicts

| Hyp | Verdict | Decisive evidence |
|---|---|---|
| **C — connection-semaphore coupling** | **CONFIRMED** | Backoff ratio 0.439 (baseline) → **0.010** (`--dns-only`) → **0.003** (`--disable-saas-tenant-discovery`). Connection sweep monotonic: **0.837 @32 conns > 0.439 @128 > 0.273 @512**. S_wait (share of DNS-permit time spent waiting on the shared semaphore) 0.228 baseline → 0.000 in both clean arms. Half of all observed per-attempt timeouts fired **before any byte was sent** (timeout_before_send 412 vs after 429). **The SaaS-tenant phase is the dominant semaphore hog.** |
| **A — wrapper budget = per-attempt budget** | **CONFIRMED** | Wrapper timeouts 6,386 vs per-attempt timeouts 841 on baseline (7.6×); at 32 conns wrapper = **11,547**. Cancellation matrix: **7,032 of 7,988 cancellations caught attempt 0 still in flight** — the outer 3 s fires while the first 3 s attempt is mid-air; rotation to providers 2–4 never happens. |
| **B — breaker false trips** | **CONFIRMED** | Probes: **every one of 3,007 samples healthy** (all DoH 200, DoT TLS-OK, UDP NOERROR) and pcap shows **0 SERVFAIL / 0 unanswered from the forwarder** → D_false/D_total = **100%**. Adaptive baseline: 8 DoH + 1 DoT + 5 UDP demotions anyway. Pinned arms (suppression off, as designed): breakers latch almost immediately and **all four pinned arms end with 0 relationships** — ~25 k lookups rejected instantly with only ~1.4 k DoH attempts ever made (the dead-ladder spin). |
| **D — invisible UDP/53 flood** | **REFUTED** | Wire truth over the whole matrix: getaddrinfo A/AAAA to the forwarder **219 packets in 5 h (0.012 qps)**; system-resolver TXT/CNAME **0**; hickory UDP tier **0**. The router was never pressured. (DoT tier: 3,109 SYNs — the ladder's churn is the only real plain-port cost.) |
| **E — counting amplification** | **CONFIRMED, quantified** | failure-site decomposition (baseline): `settle_arm` **42,784** counts vs ~2,918 genuinely-classified provider failures — ≈**93 % of "DNS Failures" are memo replays** of ~1,960 genuinely broken names, re-counted once per referencing subdomain. |
| **F — timeout misclassification** | **CONFIRMED (mechanism refined)** | Congestion split: rejections **21,139** vs timeouts 1,212. **429s observed: 0 across every arm** — there is no real throttling. The "Rejected" flood is the dead-ladder's `DNS_ENDPOINT: no DNS transport` string classifying as an explicit refusal → multiplicative decrease → **governor at floor 2 for 24 of the baseline's 39 minutes (61 %)**. |
| **G — backoff sleeps in RTT** | **MINOR** | With zero 429s, the throttle-only sleep almost never fires (25 sleep-phase cancellations total). Not a driver. |

## The causal chain (one sentence)
SaaS-tenant HTTP probes saturate the shared 128-permit connection semaphore → DoH attempts stall inside their own 3 s budgets (half the timeouts never sent a byte) and the equal outer wrapper cancels rotation (A) → the failures trip per-transport breakers that 3,007 healthy probes prove false (B) → every lookup then falls through a dead ladder to an instant `DNS_ENDPOINT` failure that the classifier reads as an explicit refusal (F) → the governor multiplicatively collapses and parks at concurrency 2 for 61 % of the scan, while memo replays inflate the failure count ~15× (E).

## Cross-arm table (from scan-summary.json)

| arm | status | wall s | rel | backoff ratio | timeouts | rejections | floor s | DoH att | ok | t_before | t_after | 5xx | S_wait | wrapper | dem (doh/dot/udp) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| i-baseline | ok | 2321 | 10,476 | 0.439 | 1,212 | 21,139 | 1,431 | 40,051 | 28,304 | 412 | 429 | 958 | 0.228 | 6,386 | 8/1/5 |
| iv-dnsonly | ok | 14 | 387 | 0.010 | 1 | 1 | 0 | 210 | 195 | 0 | 0 | 2 | 0.000 | 0 | 0/0/0 |
| iiia-conn512 | TO900 | 901 | — | 0.273 | 686 | 3,447 | 420 | 12,024 | 8,893 | 324 | 836 | 5 | 0.219 | 1,176 | 10/14/3 |
| iiib-conn32 | TO900 | 900 | — | **0.837** | 1,130 | 5,604 | 819 | 14,772 | 1,311 | 132 | 101 | 0 | 0.049 | **11,547** | 0/1/2 |
| ii-pin8 | TO900 | 900 | **0** | 0* | 847 | 7,446 | 0 | 6,795 | 5,556 | 35 | 41 | 0 | 0.113 | 275 | 3/1/3 |
| ii-pin16 | TO900 | 900 | **0** | 0* | 1,168 | **26,559** | 0 | **1,437** | 222 | 13 | 7 | 0 | 0.024 | 23 | 1/1/2 |
| ii-pin32 | TO900 | 900 | **0** | 0* | 1,131 | 22,172 | 0 | 3,003 | 250 | 16 | 25 | 0 | 0.022 | 1,579 | 2/1/2 |
| ii-pin64 | TO900 | 900 | **0** | 0* | 1,058 | 23,173 | 0 | 1,396 | 195 | 8 | 5 | 0 | 0.013 | 122 | 1/1/2 |
| d2-depth2 | TO900 | 900 | — | 0.174 | 115 | 5,776 | 286 | 29,958 | 28,033 | 175 | 211 | 50 | 0.350 | 1,242 | 3/1/3 |
| v-nosaas | TO900 | 900 | — | **0.003** | 66 | 4 | 22 | 22,614 | 21,571 | 0 | 357 | 28 | 0.000 | 287 | 3/0/0 |
| v-nosubproc | TO900 | 900 | — | 0.972 | 1,001 | 26,814 | 818 | 2,647 | 812 | 81 | 78 | 0 | 0.186 | 667 | 1/1/1 |
| v-nowebtraffic | TO900 | 900 | — | 0.291 | 321 | 5,571 | 483 | 19,253 | 14,242 | 280 | 288 | 1 | 0.310 | 3,740 | 5/1/3 |
| v-nosubdomain | TO900 | 900 | — | 0.860 | 973 | 0 | 649 | 1,138 | 157 | 2 | 5 | 0 | 0.019 | 0 | 0/0/1 |

\* pinned governors never step down, so backoff_events stays 0 by construction; congestion_signals still count. TO900 arms ran under the matrix's uniform `--timeout 900` and their sidecars carry `status: timeout` — their ratios are valid; their relationship counts are not comparable.

## New findings beyond the hypothesis set
1. **H — pinned mode is catastrophically broken.** `--dns-max-concurrency` (any value) disables the breaker's congestion suppression, breakers latch on the initial burst, and the scan spends its life rejecting lookups instantly: **all four pinned arms produced zero relationships.** Our own CLI advice ("pin for reproducible benchmarks") currently produces empty scans. Fixed by Wave 2's evidence-based breaker (suppression no longer keyed on `is_backing_off`).
2. **Disabling subprocessor or subdomain discovery makes DNS *worse*** (0.972 / 0.860) — those phases act as accidental pacing; removing them raises the concurrent pressure of what remains. Confirms the fix must be structural (C), not method-toggling.
3. **Zero 429s anywhere.** All prior "DNS_THROTTLE" reasoning about provider rate-limits was reasoning about a phantom; the only real provider failures are 5xx bursts (958 on baseline) and slow responses under our own contention.
4. **Gap:** the Phase-0 `CountingResolver` was defined but never wired into `hardened_builder`, so `http.getaddrinfo` read 0. The pcap answered the question anyway (219 packets / 5 h); wiring it stays worthwhile for the canary and lands with Wave 3.

## Decision
Owner's Phase-1→2 gate: proceed autonomously iff ≥2 of {A, B, C} confirm. **A, B, C all confirmed** → Wave 1 begins now: DNS transports off the shared semaphore (C), deadline-owned rotation with RTO budgets (A), leaf-RTT governor samples (G, cheap while in there), logical failure counting + double-increment fix (E), typed timeout classification (F). Wave 2 (evidence-based breaker + one-decrease-per-epoch + deferred retry) then also closes H.
