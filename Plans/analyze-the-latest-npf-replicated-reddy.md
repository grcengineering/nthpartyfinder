# Two-scan divergence: full account + determinism remediation

> **IMPLEMENTATION STATUS — P0 + Step 3 COMPLETE & FULLY GATED (uncommitted; owner away → awaiting
> Secretive-key tap, not self-signed).** Gates all green: `cargo fmt --check`, `cargo clippy
> --all-targets`, full lib suite **4289 passed / 0 failed / 2 ignored**, coverage **99.25% lines /
> 98.63% functions** (≥95/95; new `coverage.rs` 99.48%/100%). **Live-validated** with a real dns-only
> scan: the discovery-coverage manifest renders, and the verdict correctly flips to **DEGRADED**
> ("Completed with 722 vendor relationships, but coverage was DEGRADED — DNS degraded on 6 lookup(s)")
> instead of the old silent SUCCESS. Live validation also caught + fixed one cosmetic bug (a doubled
> "disabled (disabled …)" in the manifest — the reason already carries the state). **Steps 4–7 remain
> deferred into the perf campaign (goal 2), which needs a quiet machine** — see the status line's tail.
> Shipped: new `src/coverage.rs`
> (`SCAN_COVERAGE` report + pure `feature_status`/`degradation_summary`/`render_manifest`, unit-tested);
> per-phase found/failure recording wired into all five phase helpers + the subprocessor budget-exhaust
> site + the web-traffic Phase-2 swallow; a discovery-coverage manifest printed before the summary; a
> health-aware **DEGRADED** verdict replacing the bare SUCCESS; and `laddered_direct` now returns
> `DirectOutcome` so a tripped DoH breaker with an unresolvable fallback is COUNTED, not returned as a
> silent empty. **Steps 4–7 (subprocessor-budget/DNS-latency decoupling, bounded retries, web-traffic
> floor, DNS-ladder timeout tuning) are deferred into the performance campaign (the user's 2nd goal)**
> because they live in `cfg(not(coverage))` live-network code and can only be validated by real scans —
> which need a QUIET machine (this box is at load 233; measuring now would be meaningless, per the repo's
> 2026-07-14 lesson). They are not dropped: they'll be implemented as *measured* changes there.


> Investigation only (plan-mode). No code changed. Evidence: run-1 `scan.log`, both HTML reports, and three
> code-mapping passes over `nthpartyfinder/src`. All line refs are under `nthpartyfinder/src/`.

## Context

Justin ran two back-to-back `nthpartyfinder` scans of `vanta.com` (branch `fix/binary-native-orphan-sweep`, v1.3.0)
and got very different results. He wants: (1) a complete account of **every** difference — configured vs.
actually-ran vs. ran-*successfully* vs. found vs. *should-have-been* found; (2) the cause of each; (3) what to fix
so **identically-configured** scans stop diverging in unintended ways.

- **Run 1** (many flags: `--enable-subprocessor-analysis --enable-subdomain-discovery --enable-saas-tenant-discovery --enable-ct-discovery --enable-web-traffic-discovery --enable-web-org --enable-slm --download-ner-model --timeout 0 --no-resume`) → **130 relationships / 117 vendors**, 3 DNS failures, 210 s.
- **Run 2** (`-d vanta.com -r 1 -f html`) → **83 relationships / 68 vendors**, 16 DNS failures, 69 s.

His premise — those flag differences "should not result in an actual difference in scanning features" — **is true
for 8 of the 9 flags. One flag is real, and everything else in the gap is unintended, silent nondeterminism.**

---

## PART 1 — What actually differed (configured → ran → succeeded → found)

### 1a. The ONE intended, flag-driven difference: CT discovery
`compute_feature_flags` (`app.rs:87-107`): `feature = !dns_only && (enable_flag || (!disable_flag && config.<f>_enabled))`.
So an `--enable-*` flag only changes anything when the config default is `false`; otherwise the `||` short-circuits
and the flag is a pure no-op. Shipped defaults (`config/nthpartyfinder.toml`, embedded via `include_str!` `config.rs:18`):

| Feature | Default | Run-1 flag |
|---|---|---|
| subprocessor `:467` | true | NO-OP |
| subdomain `:481` | true | NO-OP |
| saas_tenant `:514` | true | NO-OP |
| **ct_discovery `:538`** | **false** | **REAL — only default-off method** |
| web_org `:559` | true | NO-OP |
| web_traffic (serde `config.rs:359-361`) | true | NO-OP |
| ner `:585` | true | `--enable-slm` NO-OP (only gates NER org-naming) |

- `--download-ner-model`: no-op when cached (`decide_model_action` returns `AlreadyCached` before consulting it,
  `app.rs:458-475`); both runs logged "NER model loaded."
- `--timeout 0` / `--no-resume`: behavioral but **did not bite** — run 2 finished in 69 s (never hit the 600 s cap),
  and the resume `settings_hash` (`checkpoint.rs:257-278`) includes the CT flag, so run 1's checkpoint was
  incompatible anyway, and a clean run deletes its checkpoint (`app.rs:2539`).

**CT is the only legitimate flag-caused difference.** `run_ct_phase` (`analysis.rs:719-746`) returns empty when the
option is `None`; only the flag makes it `Some`. There is no "CT enabled" init line (`app.rs:1384-1398` covers the
other five, not CT), which is exactly why it's easy to miss.

### 1b. CT is a MULTIPLIER, not a +34 (the cascade)
Orchestration (`analysis::discover_nth_parties` `:786`): DNS/DMARC/SPF, then **five phases concurrently** via one
`tokio::join!` (`:1034-1061`: subprocessor, subfinder, saas, ct, web-traffic) → merged into one `all_vendor_domains`
(`:1065-1069`) → dedup → limit → **depth-1 fan-out `buffer_unordered(50)`** (`:1163-1265`) where **each vendor
recurses into the full five-phase suite again**. CT's 34 vendors each seed a recursive subtree, so the CT flag moves
totals far more than 34 (196→155 identified; 130/117→83/68 final). **This part of the gap is intended.**

### 1c. The UNINTENDED nondeterminism (empirically proven)
- **Subprocessor 37 → 2.** Timing smoking gun from `scan.log`: run 1's subprocessor phase ran **~2 m 37 s**; run 2's
  ran **~9 s**.
- **Web-traffic 13 → 42** (opposite direction — run 2 found more).
- **Subfinder 139 → 122; SaaS 14 → 13.**
- **Vendor-list diff (from the two reports):** run 2 **missed ~46 real vendors** run 1 found (acculynx, appzen,
  datadoghq, merge.dev, openzeppelin, secoda, snowflake, tableau, zapier, wistia, + infra amazon/google/microsoft —
  CT-log + subprocessor-page vendors); run 2 **added ~29** run 1 lacked — almost all web-traffic ad/tracking noise
  (6sense, hubapi, hs-scripts, stackadapt, linkedin, spotify, reddit) **plus 6 malformed URL-encoding-artifact
  tokens** (`2fcohere.com`, `entityriskey.io`, `20entityriskey.io` from raw `https%3A%2F%2Fcohere.com%2F…`; run 1
  had zero).

---

## PART 2 — Root causes

### The unified causal chain (why run 2 collapsed)
Run 2 hit a patch of DoH throttling → the **shared** `Arc<DnsServerPool>` circuit breaker tripped at 8 consecutive
failures (`dns.rs:216,292-303`) → the fast subdomain path then **skips DoH and stops counting**, returning
`Ok(vec![])` silent empties when the DoT/UDP53 ladder can't resolve in its tight per-tier timeouts
(`dns.rs:1340-1344,1252-1271`) → **fewer subdomain-derived vendors** (the largest source), AND slower per-vendor DNS
→ the **20 s subprocessor working-time budget** starves (it includes DNS+HTTP+render latency) → **subprocessor
collapses 37→2** → less total work → 69 s wall-clock → and the summary still printed **SUCCESS**. Independently, CT
was genuinely off (flag) removing 34 seeds + their cascade, and the web-traffic capture window is a timing race that
happened to catch more ad-beacons. Four mechanical root causes underlie this:

**RC-1 — subprocessor silently degrades to near-empty.** `SubprocessorAnalyzer::analyze_domain_with_full_options`
(`subprocessor.rs:1517`) is headless-Chrome based; every failure funnels to `Err → Ok(Vec::new())`
(`analysis.rs:505-514`) — a *failure* is indistinguishable from "no subprocessors." Paths: Vanta GraphQL live path
has **6 silent `None` returns** (`subprocessor.rs:1277-1356`) — one 429/timeout drops the entire Vanta list;
render-capture window misses the late ~74 KB report (`trust_center/discovery.rs:193-308`, own comment
`:222-226` "intermittently missed"); **20 s per-vendor budget starvation** (`subprocessor.rs:1607,1655-1674`, comment:
"chargify.com once lost all 28 of its rows while the scan-wide total went UP"); persistent `cache/{domain}.json` has
**no TTL on working URLs** (`subprocessor.rs:736-748`) so run 2 is path-dependent on run 1's writes (crate-dir
`cache/` mtime 19:56 confirms run 1 wrote it).

**RC-2 — web-traffic capture is a timing race.** `analyze_network_traffic` (`web_traffic.rs:167-300`) captures every
network response during an adaptive network-idle window (min 600 ms, idle 800 ms, cap 5000 ms; `:252-275`). The set =
whatever beacons happen to fire that load: many → 42, early-quiet → 13. Phase-2 render errors are swallowed to
static-only (`:142-146`). The "Suppressed 4 social/ad-network" line is a deterministic **downstream effect**
(`app.rs:209-227,2505-2508`), not a separate cause.

**RC-3 — DNS transport degradation is real, shared, and mostly UNCOUNTED.** One `Arc<DnsServerPool>` with atomic
health fields is cloned into every task (`app.rs:1926`, `dns.rs:158-168`), so one bad patch degrades the whole run.
"DNS Failures: N" (`logger.rs:88,725`) **plateaus once the breaker trips** — the fast path stops attempting DoH and
converts unresolved lookups into uncounted `Ok(vec![])` (`dns.rs:1340-1344,1252-1271`). **So 16 is a floor; the true
recall loss (117→68) is larger and mostly uncounted.** Asymmetry: the ladder/breaker governs **only the fast
subdomain path**; the root SPF/TXT/DMARC path has **no DoT tier and never consults the breaker**
(`dns.rs:1575-1652`) — so a tripped breaker silently thins subdomain vendors (the big source) while root recall looks
fine. Providers are deterministic round-robin, no RNG (`dns.rs:739-747`); the nondeterminism is entirely
network/breaker/wall-clock driven.

**RC-4 — shared browser pool + wall-clock pacing amplify RC-1/RC-2.** `MAX_RENDER_PERMITS = 6`
(`browser_pool.rs:29,48`) shared by subprocessor renders + trust-center captures + web-traffic captures; their own
doc records that raising permits 8→16 "starved more vendors of their subprocessor budget (175 vs 165)"
(`browser_pool.rs:34-38`) — contention directly changes recall. Memory-pressure pacing sleeps 250 ms/25 ms per
admission based on host state (`analysis.rs:426-434`), which differed between the two runs (the box runs 6+ concurrent
sessions). `buffer_unordered` order also drives the shared `subprocessor_attempted_orgs` skip set (`analysis.rs:1013-1031`).

**RC-5 (systemic) — failure is invisible.** Every phase maps failure/timeout to `Ok(empty)`/`None` and only
`debug!`s it, so "ran-but-failed" reports identically to "ran-and-found-nothing," and the summary prints SUCCESS with
a lower count. This is the same class the repo already fixed for DNS (the GRC-367 failure-visibility contract) — it
was just never extended to subprocessor / web-traffic / subfinder / saas / ct. Resume/cache is a latent-but-here-
inactive factor (run 1 completed cleanly → checkpoint deleted → run 2 fresh; subprocessor cache never caches empties).

---

## PART 3 — What to fix (tiered; each item respects the repo's standing constraints)

**Constraints every fix must honor:** no external wrapper scripts — binary-native only (owner directive
2026-07-18); must NOT reintroduce the connection-storm/WiFi-collapse (bounded, `http_client`-hardened retries only);
extend, never weaken, the GRC-367 DNS failure-visibility contract and the exit-3 guard; 95% coverage floor with
meaningful assertions.

**Goal framing:** byte-identical output is impossible (CT/subfinder/web-traffic draw on time-varying external
sources). "No *unintended* differences" is achieved by (a) making every divergence **visible and correctly
attributed** so an intended difference (CT off) is instantly distinguishable from an unintended one (subprocessor
starved), and (b) removing the mechanical couplings that let a transient network blip silently collapse recall.

### P0 — Visibility & honest reporting (direct answer to the ask; safe, high-value, makes P1 verifiable)
1. **Replace bare-`Vec` phase returns with a `PhaseOutcome { found, attempted, failed, degraded, reason }`** at the
   five orchestration seams (`analysis.rs:505-514` subprocessor, `:627-630` subfinder, `:707-713` saas, `:741-744`
   ct, `:762-769` web-traffic; `web_traffic.rs:142-146`). Stop collapsing failure into empty. Extends GRC-367 to all
   phases.
2. **Per-run "coverage manifest"** in the summary and the HTML report: for each method — enabled? (and *why*: flag
   vs config-default vs dns-only), ran?, found N, failed M, degraded?. CT then self-documents:
   "CT discovery: disabled (default — enable with `--enable-ct-discovery`)". Subprocessor shows "2 found / 12 vendors
   starved by 20 s budget / 8 render timeouts" instead of a silent 2. The metrics already exist
   (`subproc_budget_exhausted`, `subproc_zero_yield`, `browser_wait_nanos`) — surface them.
3. **Health-aware final verdict.** If any phase is `degraded`, print "COMPLETED WITH DEGRADED COVERAGE — results may
   undercount (subprocessor starved on N vendors; DNS degraded)" instead of plain SUCCESS. *This is the single most
   important fix for the stated goal: an unintended difference now announces itself.*
4. **Close the uncounted-empty DNS hole (RC-3).** When the DoH breaker is tripped AND the DoT/UDP53 ladder fails to
   resolve, count it as a classified failure (per GRC-367) instead of a silent `Ok(vec![])` — so "DNS Failures"
   reflects the true magnitude (16 was a floor). Guard the exit-3 contract stays correct.

### P1 — Determinism hardening at the mechanical sources
1. **Decouple the 20 s subprocessor budget from DNS latency (the RC-1←RC-3 link — highest-leverage single fix).**
   The budget is meant to bound *subprocessor* work, but currently includes upstream DNS resolution time, so degraded
   DNS starves subprocessor recall. Resolve the subprocessor host's DNS *before* starting the budget clock (or
   subtract DNS-wait from working-time, as it already does for browser-permit-wait via `browser_wait_nanos`
   `subprocessor.rs:1635-1654`). Directly prevents "DNS blip → subprocessor 37→2."
2. **Harden the Vanta GraphQL / render-capture path (RC-1).** Bounded, backoff'd retry (via hardened `http_client`,
   small cap — no storm) on the manifest + graphql fetches so one 429 doesn't drop the whole list; treat a
   render-capture miss as a *retryable degraded* outcome, not a silent empty.
3. **DNS ladder correctness (RC-3).** Ensure the fast-path per-tier budgets (3 s DoH / 4 s DoT / 2 s UDP53) actually
   accommodate the first DoT TLS handshake so the fallback *resolves* rather than times out into empty; evaluate
   extending the DoT tier to the root TXT/SPF path so a tripped breaker doesn't thin the largest vendor source.
4. **Tighten the web-traffic capture window (RC-2).** Add a minimum-capture floor + fixed settle so a fast-quiet load
   doesn't truncate to 13; variance shrinks (won't be identical — external beacons vary).

### P2 — Deferred follow-ups (NOT in this build)
1. **Sanitize the fallback extractor** so the `2fcohere.com` / `entityriskey.io` URL-encoding artifacts can't be
   emitted (decode + domain-shape validation in the static-HTML/NER fallback path).
2. **Checkpoint TTL + degraded-marker** (RC-4 latent): age-gate auto-resume and don't silently resume a partial from
   a network-degraded run as authoritative.
3. **Optional `--reproducible` mode**: pin provider order, disable the web-traffic early-exit, fix browser-permit
   count — for when max reproducibility is wanted over speed.

---

## Committed build (P0 + P1) — concrete implementation steps

**Scope decision:** P0 + P1 hardening. P2 deferred. Order below is the build order (visibility first so P1 is
verifiable; the most delicate DNS-resilience change last, measurement-driven).

### Step 1 — `PhaseOutcome` type + kill the silent `Ok(empty)` (P0.1)
- New struct (in `analysis.rs` or a small `coverage.rs`): `PhaseOutcome { found: Vec<…>, attempted: usize,
  failed: usize, degraded: bool, reason: Option<String> }`, with `found()`-only accessor used at the merge site.
- Change the five phase helpers (`run_subprocessor_phase` `:575`, `run_subfinder_phase` `:612`, `run_saas_phase`
  `:686`, `run_ct_phase` `:719`, `run_webtraffic_phase` `:750`) to return `PhaseOutcome`. Merge site `:1065-1069`
  consumes `.found`; a new scan-level `CoverageReport` accumulates the outcomes.
- **Delete the failure-masking maps:** `subprocessor_analysis_with_logging` `Err → Ok(Vec::new())`
  (`analysis.rs:505-514`) → `PhaseOutcome{ degraded:true, reason, .. }`; thread the existing analyzer metrics
  (`subproc_budget_exhausted`, `subproc_zero_yield`) into `reason`. web-traffic Phase-2 swallow
  (`web_traffic.rs:142-146`) → `degraded:true`. Same for subfinder/saas/ct `Vec::new()` fallbacks.

### Step 2 — Coverage manifest (P0.2) + health-aware verdict (P0.3)
- Compute a per-feature `enabled + why` alongside `compute_feature_flags` (`app.rs:87-107`): `EnabledByFlag /
  OnByConfigDefault / OffByDefaultUseFlag / DisabledByFlag / DnsOnly`. CT-off renders "disabled (default — enable
  with `--enable-ct-discovery`)".
- Emit a "Coverage" block in the logger summary (`logger.rs` near the "DNS Failures" line ~`:812-879`) and a small
  table in the askama HTML report. Each phase: enabled+why / found / failed / degraded.
- Final verdict (`app.rs` summary, where "SUCCESS: Analysis completed with N …" prints): if
  `CoverageReport.any_degraded()`, print "COMPLETED WITH DEGRADED COVERAGE — results may undercount (subprocessor
  starved on N vendors; DNS degraded on M lookups)". **Exit code logic unchanged.**

### Step 3 — Close the uncounted-empty DNS hole (P0.4)
- `laddered_direct` (`dns.rs:1355-1426`) already knows `DirectOutcome{Answered,Empty,TransportFailed}`. Return that
  distinction to the callers instead of collapsing to `Option<Vec>`.
- In `fast_txt_lookup`/`fast_cname_lookup` (`:1286-1345`,`:1435-1484`): when the DoH breaker is tripped and all
  fallback tiers end in `TransportFailed`/exhausted (NOT authoritative `Empty`), classify + count via the failure
  counter (GRC-367 contract). **Authoritative `Empty` stays uncounted** — preserves exit-3 correctness. So the
  "DNS Failures" number stops plateauing at the breaker-trip and reflects true magnitude.

### Step 4 — Decouple the 20 s subprocessor budget from DNS latency (P1.1, highest-leverage)
- In the working-time accounting (`subprocessor.rs:1634-1674`), which already subtracts `browser_wait_nanos`, also
  subtract the DNS/connect duration for the subprocessor host (instrument it the same way). Net effect: a slow-DNS
  vendor still gets its full 20 s of *subprocessor* work → breaks the "DNS blip → 37→2" chain. No new connections
  (accounting change only).

### Step 5 — Bounded GraphQL/render retry (P1.2)
- Vanta GraphQL 6× `None` (`subprocessor.rs:1277-1356`) + render-capture single retry (`discovery.rs:520-540`): add
  a small, backoff'd, **bounded** retry via the hardened `http_client` (connect_timeout 5 s + pool caps already in
  place from the 2026-07-14 connectivity work). Exhausted retries → `degraded` (feeds Step 1). **Bounded only — no
  storm.**

### Step 6 — Web-traffic capture window floor (P1.4)
- `web_traffic.rs:252-275`: add a minimum-capture floor + fixed minimum settle so a fast-quiet load can't truncate
  to 13. Reduces variance (external beacons still vary; not identical). No new connections.

### Step 7 — DNS ladder timeout correctness (P1.3, most delicate — measurement-driven, last)
- Measure the first-DoT TLS-handshake latency vs the 4 s DoT budget (`dns.rs:1367-1368`); pre-warm the pooled DoT
  resolver or raise the budget if it times out into empty. Evaluate extending the DoT tier to the root TXT/SPF path
  (`dns.rs:1575-1652`, currently DoH-only) so a tripped breaker doesn't thin subdomain vendors while root recall is
  fine. **Conservative changes only — the `do53_health` flood-guard stays; don't reintroduce port-53 flooding.**

### Review + gates before ship
- In-family adversarial review of the diff (codex is installed but **unauthenticated**, so Forge/Cato are blocked —
  a fresh-context skeptic pass substitutes, as in the prior NPF sessions).
- `cargo fmt --check`, `clippy -D warnings`, full suite, `cargo deny`, coverage **≥95/95** with meaningful tests.
- Commit staged + message ready for Justin's Secretive-key tap (code-commit signing rule); do not self-sign code.

---

## GOAL 2 — Performance/speed campaign: measured results (2026-07-19, quiet-ish box)

**Actively tested**: 3 back-to-back release-binary scans of `vanta.com -r 1` (default methods), instrumented with
`-v` (perf attribution) + the new coverage manifest, network + Chrome-orphan monitored throughout.

**Determinism — VALIDATED & massively improved (the headline).** Vendors across 3 identical runs: **122 / 122 / 116
(±5%)** vs the user's original **117 vs 68 (44% silent swing)**. And the residual variance is now *explained and
visible*: run 2 had 0 DNS failures → **SUCCESS** (122); runs 1 & 3 had 14/12 → **DEGRADED** (122/116). The
degradation the user hit is no longer silent.

**Stability — VALIDATED.** Network healthy across all 3 (ping 17–53 ms, 0% loss); Chrome procs swept to 5 after
settle; no WiFi collapse. The binary-native hardening holds.

**Perf characterization (wall ≈ 54s, rock-consistent):**
- Critical path = the **discovery join (36s)**, bounded by **`phase.subfinder` (36s, consistent)** — the other 4
  phases finish under its shadow (saas 15.7s, web-traffic 13.4s, subproc 12.1s, ct 0). Fan-out adds ~17s after.
- `phase.subfinder` (36s) = subfinder subprocess (~13s standalone) **+ the per-subdomain DNS fan-out of ~123
  subdomains** — and it's 36s *whether DNS fails or not*, so it's not ladder-bound.
- **Renders are NOT the bottleneck** on a quiet box: `browser.permit_wait` = 0.0s, only 2 renders vs 6 permits.
- **`subproc.budget_exhausted` = 0**; subprocessor found the full 37 — the user's 37→2 collapse was transient
  contention/DNS degradation, NOT steady-state.
- The 50/s DNS rate limiter is not the throttle (123 subdomains ≈ 2.5s).

**Instrumented decomposition (added, ships) settled the strategy.** New `-v` line splits `phase.subfinder` into
subfinder-subprocess vs subdomain-DNS fan-out. Result: **subprocess 31.0s vs DNS fan-out 4.3s** — so the phase is
88% the external subfinder subprocess, and the "pipeline the two halves" idea I was weighing would save only ~4s
(measuring first saved a risky refactor for nothing).

**SHIPPED optimization (measured, recall-neutral):** capped subfinder's per-source timeout — `-timeout 15`
(`discovery/subfinder.rs`; its own default is 30s). Under five-phase in-scan contention the subprocess had stretched
to ~31s; the cap cut it to **16.6s with ZERO recall loss** (123→123 subdomains, 122→122 vendors), dropping wall
**53.7s → 48.6s (~10%)**. The win is "only" 10% because cutting subfinder exposed **saas-tenant discovery as the new
co-bottleneck (28.8s)** — the phases are all external-latency-bound in the 12–29s band, so it's whack-a-mole.

**Remaining levers (not shipped — each a refactor or an owner's-call tradeoff):**
1. **saas-tenant timeout/concurrency tuning** — now the pole (28.8s); its own per-provider timeout/concurrency is the
   next cap to test (recall tradeoff, needs measurement).
2. **Transport-aware DNS concurrency** — raise fan-out rate for pooled DoH (conntrack-safe), keep UDP/53 throttled.
   Safe but a rate-limiter refactor. (Note: DNS fan-out is only 4.3s, so low priority now.)
3. **Steps 4 & 7** (subprocessor-budget↔DNS decoupling, DNS-ladder timeout tuning) — reliability for the *degraded*
   case; need a degraded network to tune safely.
4. **Making `-timeout` configurable** (`subfinder_source_timeout_secs`) so power users can trade back to max recall.

**Conclusion: the tool is external-latency-bound and already well-architected; the one clean speed win (`-timeout
15`, ~10%, recall-neutral) is shipped, and the rest are deliberate tradeoffs the owner should choose.**

## Verification
- Instrument, then re-run **identical configs back-to-back** with fixed `--timeout 0`, warm vs cold cache, **on a
  quiet machine** (repo lesson 2026-07-14: contention invalidates measurements). Assert the coverage manifest is
  emitted and per-phase found/failed counts are stable within external-source variance.
- Unit tests: a phase *failure* is no longer indistinguishable from *empty* (each `PhaseOutcome`); a tripped DoH
  breaker with unresolvable fallback increments the classified failure counter (closes the RC-3 hole); the
  health-aware verdict flips to DEGRADED when a phase reports `degraded`.
- `cargo fmt --check`, `clippy -D warnings`, full suite, `cargo deny`, coverage ≥95/95 — the standard gates.
