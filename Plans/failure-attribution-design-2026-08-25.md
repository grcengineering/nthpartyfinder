# Failure-vs-No-op Attribution — design (2026-08-25)

Goal (owner, verbatim intent): a scan must answer, per degradation-looking signal, whether
(a) nthpartyfinder or an intermediary actually failed, or (b) the target itself is not
legitimately scannable — which is a **successful scan producing a no-op**, not a failure.
Test beds: vanta.com and lovable.dev at depth 3. End state: zero (a)-class signals on both,
fullest results preserved.

## Current state (survey, ISA Log 2026-08-25)

Every `SCAN_COVERAGE.<phase>.record_failure()` site collapses a rich error chain into a unit
counter + stringified warn; `PhaseCoverage` = found/failed/degraded; `degradation_summary`
reports six per-phase "failed on N domain(s)" buckets with no origin. DNS is the one phase
already attributed (name-at-fault vs transport — `DnsSection`), and it is the pattern this
design generalizes. Clean-empty outcomes (vendor publishes no subprocessor list; domain has
no web presence) are silent `debug!`s — the no-op is never positively reported.

## Taxonomy — five origins, one contract

| origin | meaning | verdict effect |
|---|---|---|
| `target_noop` | Target has nothing to find here; **completeness proven** (all probes definitively answered) | SUCCESS; reported as verified no-op |
| `target_limited` | Target exists but capped coverage itself (refused, bot-blocked, throttled us, unresponsive while scan-wide health green) | not a tool failure; reported as target-limited coverage with evidence |
| `upstream` | Intermediary failed: subfinder passive sources, DoH provider, CT log API, WHOIS | degradation (ours to route around) |
| `tool` | nthpartyfinder or local env: browser crash/panic, spawn failure, binary missing, local network down | degradation (ours to fix) |
| `policy` | Designed budget/ceiling truncated genuine work | degradation of coverage; eliminated or owner-ratified, never silent |

Anti-laundering invariants:
- `target_noop` requires completeness evidence recorded at classification time (e.g. "N candidates,
  all definitive misses", "authoritative NXDOMAIN/NOERROR-no-answer"). Ambiguity NEVER lands in
  `target_*`; the conservative default is the failure side (`tool`/`upstream`).
- Unresponsive-host → `target_limited` only on differential evidence: scan-wide transport health
  green in the same window (the DNS name-vs-transport move, generalized).
- Every classification carries a machine-readable `reason` code; the census can re-derive the
  attribution from the sidecar alone.

## Changes

1. **coverage.rs** — `Origin` enum (serde snake_case); `PhaseCoverage` gains per-origin
   `AtomicU64`s + bounded per-origin evidence samples `(domain, reason)` (cap per phase;
   counts never capped). New `record_attributed(origin, domain, reason)` replaces bare
   `record_failure()` at all 11 production sites; new `record_noop(domain, reason)`.
2. **Per-phase classifiers** (each with unit falsifiers):
   - *subprocessor*: per-candidate outcome tally (found / definitive-miss / errored /
     abandoned). Complete + all-definitive-miss + zero found → `target_noop`
     `no_disclosure_found` (the positive "verified: no subprocessor disclosure" — today a
     silent debug). Budget/envelope zero-yield → `policy`. Browser render-fail/panic →
     `tool`. Candidate errors → by error kind (refused/tls/4xx/5xx → `target_limited`).
   - *webtraffic*: root-cause pre-classification: no A/AAAA → `target_noop`
     `no_web_presence`; connect refused / TLS / HTTP error → `target_limited`;
     browser/CDP → `tool`; timeout → differential.
   - *subfinder*: spawn/stdout-pipe errors → `tool`; **binary-missing → `tool`** (today:
     warn + clean `Ok(vec![])`, phase silently absent); **run timeout → `upstream`
     `partial_timeout`** (today: partial results returned as clean); zero subdomains →
     `target_noop`.
   - *saas*: phase Err → classified; zero tenants → `target_noop` (probe NXDOMAINs are the
     mechanism, not failures).
   - *ct*: ThrottledEmpty → `upstream` `provider_throttled` (closes TF-CT-THROTTLE-WORDING);
     transport errors → `upstream`; zero certs → `target_noop`.
   - *dns*: existing split relabeled — name-attributed → `target_limited`
     (`authoritative_servfail`), transport → `upstream`/`tool`. No behavior change.
3. **scan_summary.rs** — `CoverageSection` gains per-phase origin counts + noop counts +
   samples; `SCHEMA_VERSION` bump.
4. **degradation_summary / verdict** — only `upstream`/`tool`/`policy` trigger DEGRADED;
   DEGRADED detail decomposes by origin. New no-op/target-limited summary lines render under
   SUCCESS ("N vendors verified: no subprocessor disclosure (no-op)"). Existing wording pins
   updated with the tests, honestly (no silent string drift — the pinned tests change in the
   same commit with the rationale).
5. **Log lines** — phase warns gain a trailing `[origin=… reason=…]` token; per-vendor no-op
   INFO at `-v`.
6. **HTML report** — health section shows the decomposition and the no-op lines.

## Verification

- Unit falsifiers per classifier (red-before/green-after where behavior changes).
- Snapshot/pinned tests for summary + verdict wording updated deliberately.
- Ground-truth sample (ISC-644): for every `target_*` class appearing in the validation
  scans, out-of-band probes (dig @authoritative, direct curl, real browser) agree; false
  attribution count = 0.
- A/B validation scans on both test domains BEFORE merge (recall-sensitive rule):
  relationships ≥ baseline within variance; zero `tool` signals; DNS bars green.
