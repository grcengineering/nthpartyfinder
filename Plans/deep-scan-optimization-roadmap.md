# Deep-Scan Optimization Roadmap

**Date:** 2026-08-13 · **Baseline:** v1.6.2 (master `73eeb5f`) · **Status:** analysis complete, implementation not started
**Method:** live depth-3 vanta.com scan (cold cache, `--timeout 0`, `-f html`, all default methods, shipped Homebrew binary) inspected end-to-end + nine-lens read-only code investigation (83 findings, every one file:line-cited) + prior-art verification against ISA.md/CHANGELOG/git so nothing already fixed or already rejected is re-proposed.
**Scan evidence:** `/tmp/npf-d3-scan/scan.raw` (pty capture), report at `/tmp/npf-d3-scan/report/`. Measured numbers appear in the Appendix; each roadmap item is tagged **[measured]** (tied to this scan's data) or **[static]** (provable from code; magnitude needs the Phase-0 counters).

> **Implementation status (2026-08-14, branch `perf/deep-scan-dedup-roadmap`):** Wave A landed — P1.6 (canary-once), P1.8 (SaaS apex/junk-name gate), P2.5 (subprocessor dead-host short-circuit), P4.2 (min-layer merge), P4.3 (root canonicalization), P4.5 (distinct-vendor per-layer stats), plus Phase-0 dedup counters (`dedup.*`, `whois.cache_hit`, `saas.apex_skip`, `subproc.dead_host_skip`, `subfinder/ct.apex_skip`). P2.11 (DNS root-path hygiene) moved from Wave A into the DNS wave to be validated alongside P2.10b in the sensitive `dns.rs` file rather than piecemeal. P1.5 (per-method apex memos for subfinder/CT/SaaS) landed next via a scan-global ScanDedup struct threaded like subprocessor_attempted_orgs, claim-before-run, apex-scoped: subdomains skip (apex always queued), and an apex reached via a second parent skips. This attacks the scan's measured #1 cost (subfinder 99.3% queue wait from duplicate runs). Remaining dedup-core items (P1.1 dispatch dedup, P1.2 base recursion, P1.3 depth-aware gate + P1.9 checkpoint, P1.4 org singleflight) and Waves C/D/E are documented continuation; a depth-3 validation scan runs on the Wave-A+P1.5 binary to prove the apex-memo counters and confirm no recall regression.
>
> **Implementation status (2026-08-15 update, same branch):** The full dedup-core landed — **P1.3** (atomic depth-aware `processed_domains` gate, HashSet→HashMap<String,u32>, min-depth re-expansion) + **P1.9** (checkpoint seeds depth 0), **P1.4** (org-resolution singleflight via a keyed `OnceCell` in `ScanDedup`), and the accuracy set **P4.1** (BFS layer recompute at export), **P4.7** (depth-aware subprocessor org claims), **P4.4** (prune subtrees orphaned by infra/marketing filtering), plus **P2.2-core** (adaptive network-idle decision extracted to shared pure fns). Then **P2.7** (subprocessor negative cache — the measured 63%-no-page vendors skip the full probe on warm rescan, with a strict full-clean-empty write gate) and the **P2.1-prerequisite `render.retry_rescued` counter** + **P0.4** `report.dedup`/`report.export` timers (instrument-first, unblocking the render wave). ~18 items now implemented + gated (fmt/clippy -D/full suite via the real cargo binary/coverage-cfg); a fresh depth-3 vanta.com validation scan runs on this binary. **Remaining (~18) are all scan- or user-gated:** the render pipeline (P2.1/P2.3/P2.4 — CDP plumbing, not unit-testable, needs the retry_rescued/settle telemetry this scan produces), scheduling (P3.1–P3.6 — concurrency rewrites needing A/B scans), the DNS-sensitive wave (P2.9/P2.10/P2.11 — incident-sensitive `dns.rs`, one owner-gated on the open flapping investigation), the dedup-core harder half (P1.1/P1.2/P1.7 — need recall A/B diffs), and backend items with proven scan dependencies (P2.12: the WHOIS limiter defaults to 2 QPS — routing 4,549 lookups through it would add ~38min pure pacing wall, so its own A/B-scan probe is required to size it; P4.6 touches the frontend; P4.8 is recall-A/B-gated). These land with the user present for the validation scans, per the repo's network-safety history.
>
> **Implementation status (2026-08-16 update):** The 2026-08-15 batch MERGED to master (`ca133e3`, all 8 push-CI workflows green) after validation on a fresh depth-3 vanta.com scan (22,482 relationships; P4.4 orphan-invariant holds on real data, P2.7 write+hit lifecycle proven, P2.1 `render.retry_rescued=0` across 9h, P0.4 report-gen ~0.4s). **P4.8 (hyperscaler fanout gate) now landed** on branch `perf/p48-fanout-gate`: `should_gate_infra_enumeration(current_depth, base) = depth>=2 && is_common_denominator(base)` skips subfinder/CT enumeration for infra/CMS roots at depth>=2 (edge kept as leaf, fan-out skipped), counter `fanout.gate_skip`, +2 tests. Directly targets the validation scan's dominant cost (279k subdomains, adobe/twitter/aws.dev 5-10k each). A/B recall scan (with-gate vs the 22,482-edge baseline) is the pending validation — dropped edges must be infra-sprawl only.


---

## The one structural root cause

Almost every depth-2+ inefficiency in this codebase is a face of a single design decision:

> **The scan is a concurrent depth-first traversal whose only dedup structures are string-keyed completion memos, checked *inside* the spawned task — never at dispatch, never keyed on the registrable base, and never depth-aware.**

Its faces:

1. **Dispatch-time duplication** — `dedup_vendor_domains` keys on `(base, source_type, raw_record)`, and subfinder/CT deliberately embed the *discovering* subdomain / per-certificate info into `raw_record`. The same vendor base survives K times, spawns K tasks, and K−1 die at the child's `processed_domains` gate — after paying task setup, sink locks, budget slots, and possibly a duplicate org lookup. *(Observed live: `md02.com`, `looker.com`, `amazonwebservices.com` each ran ≥3 full 245-probe SaaS sequences; 9 duplicate probe sequences within the first 28 minutes.)*
2. **Host-keyed, not base-keyed** — `processed_domains` treats `vendor.com`, `www.vendor.com`, `api.vendor.com` as three domains; each runs the **full 5-phase discovery join** (2 Chrome renders + subfinder subprocess + ~290 SaaS probes + CT query + DNS suite). *(Observed live: `mongodb.com` + `cloud.mongodb.com`, `google.com` + `admin.google.com` each fully scanned.)*
3. **Check-then-act races** — both `processed_domains` (two lock acquisitions around a pure depth check) and the org-resolution memo (seconds-wide window over WHOIS+web+NER) admit concurrent duplicate work.
4. **Depth-blind first-wins memo** — a vendor first reached at depth 3 is never re-expanded when later reached at depth 1: children get wrong (inflated) layers, grandchildren are silently never discovered. Dedup here isn't just wasteful — it's a **recall and determinism defect**.
5. **No per-method apex memos** — subfinder/CT/SaaS work is apex-scoped by nature, but gated per full hostname, so sibling subdomains re-run all apex-scoped work.

The fix set is correspondingly unified: **claim work at dispatch time, key on the registrable base, make claims atomic, record the claim's depth, and hoist apex-scoped methods behind apex-keyed scan-lifetime memos.** Phases 1 and 3 below implement exactly that; everything else is per-method waste that compounds multiplicatively with it.

---

## Item schema

Every item: **Problem → Root cause (file:line) → Change → Impact → Probe → Effort/Risk.**
Effort: S (<½ day) / M (1–2 days) / L (3+ days). Risk: how likely the change regresses recall or behavior.

---

## Phase 0 — Instrumentation first (prerequisite for honest before/after)

Several items below are *instrument-first by design*: their mechanism is certain but their magnitude decides priority. These counters are cheap (`Relaxed` atomics matching `perf.rs` doctrine) and make the whole roadmap verifiable.

**P0.1 — Dedup visibility counters** *(S, no risk)*
Problem: duplicate-vendor work at depth 2+ is invisible — the attribution table has exactly one dedup-ish counter (`dns.memo_hit`) in the whole program.
Root cause: `perf.rs:62-127` metric inventory; skips at `analysis.rs:871-877` and `analysis.rs:1054-1068` are debug-log-only.
Change: add per-depth counters — `dedup.domain_hit` (recursion target already processed), `dedup.org_subproc_skip`, `dedup.dispatch_avoided`, `vendor_tasks.admitted` vs `vendor_tasks.ran_discovery`, `whois.cache_hit/miss`, `saas.probes_sent`, `subfinder.permit_wait`, `render.settle` split by path.
Probe: attribution table shows duplicate fraction per depth on the next deep scan.

**P0.2 — Per-tier attribution telemetry** *(S, no risk)*
Problem: no counter says which evidence tier (curated / WHOIS / web / NER / fallback) resolved what share of orgs — every org-pipeline optimization is unverifiable without it.
Root cause: `whois.rs` chain has no per-tier counters (whoisNerOrg lens).
Change: one counter per tier + one for chain wall-time; surface in the perf table.

**P0.3 — Recursion-seed provenance log** *(S, no risk)*
Problem: nothing records which source contributed each processed domain per depth, so fan-out shape (e.g. CT SAN explosions) can't be attributed.
Change: at dispatch, log/count `(depth, source_type, base)`; aggregate into the scan summary.

**P0.4 — Measure report generation itself** *(S, no risk)*
Problem: HTML export (multi-MB embedded-data reports; 9.6MB observed at 2,870 relationships) has correctness items in Phase 4 but zero performance data — the only stone the nine lenses left unturned.
Change: one timer around export + one around `deduplicate_results`; if either is material at 15k+ relationships (the O(S²)-ish evidence `contains` merge in `app.rs:127-148` is the suspect), file a follow-on; otherwise close the stone as measured-immaterial.

---

## Phase 1 — The depth-2+ dedup core (the mandate)

**P1.1 — Depth-aware registration-at-dispatch singleflight, keyed on registrable base** *(M, low risk)* **[measured]** *(implements the open TF-PREFIRE item — ISA: "discovery batches fire all 4 sub-phases before the dedup/cache check collapses them")*
Problem: same vendor base dispatched K times per parent; K−1 tasks spawn, occupy `buffer_unordered` slots (only 20/10/5 wide at depths 2/3/4+), then die at the child gate. Observed live (≥3× full SaaS sequences for several vendors within 30 min of scan start).
Root cause: `analysis.rs:58-74` key = `(base, source_key, raw_record)`; `analysis.rs:330-345` embeds discovering subdomain into `raw_record`; `analysis.rs:370-379` uses per-cert info; dispatch loop `analysis.rs:1200-1302` has no pre-dispatch filter.
Change: split **edge-recording** from **dispatch**. Keep all evidence rows; build the recursion dispatch list keyed on base — claimed in a scan-global `dispatched_bases: Mutex<HashMap<String, u32>>` (base → min dispatch depth) *at stream-construction time*. **The claim is depth-aware and shares ONE primitive with P1.3's gate: dispatch when `current_depth < stored_min_depth` (updating the stored min), skip otherwise.** A depth-blind first-wins claim here would re-create P1.3's truncation defect one layer up — P1.1 and P1.3 are one semantic, landed together, not two independent items. Duplicates at ≥ the stored depth append their relationship edge via a cheap `record_edge` path and never construct the recursion frame.
Impact: eliminates every spawn-then-die recursion attempt; frees the narrow depth-2+ budgets for distinct vendors. Prior data bounds multiplicity: v1.3.0 depth-3 scan had 15,210 relationships over ~2,226 orgs (≥6.8 edges/org mean).
Probe: `dedup.dispatch_avoided` counter; duplicate SaaS-sequence census (grep `(1/245` per vendor) must drop to 1 per vendor (re-dispatches at shallower depth counted separately, expected small).

**P1.2 — Recurse on the registrable base, not the discovered hostname** *(M, low-medium risk)* **[measured]**
Problem: `www.`/`api.`/subdomain variants of one vendor each run the full 5-phase suite; child edges are base-attributed anyway, so variant subtrees are near-identical and merge away at output — near-pure duplicate cost at the most expensive tier.
Root cause: `analysis.rs:1611` recurses on `normalize_for_dns_lookup(&vendor_domain)` (strips only `_spf.`/`_dmarc.` — `domain_utils.rs:232-249`) while edges use `extract_base_domain` (`analysis.rs:1484`); `add_base_domain_if_subdomain` (`analysis.rs:1021-1027`) *also* queues the apex, guaranteeing both run.
Change: recurse on `extract_base_domain(&vendor_domain)`. Coverage is a superset for subfinder (apex enumeration includes the discovered subdomain's siblings); keep the raw FQDN in evidence.
Risk note (**material — the A/B must target these specifically**): the recursion string feeds more than DNS. `run_webtraffic_phase` renders `https://{domain}` with the full hostname, and web_org/subprocessor also receive it — rendering `cloud.mongodb.com` (a product console) captures a *different* third-party network set than `mongodb.com` (a marketing page), and under this change the subdomain's render never happens if the apex was already processed. Subdomain-apex TXT records are the second delta. The "variant subtrees are near-identical" claim is a hypothesis (the live scan proved both get *scanned*, not that their results are identical) — the A/B relationship-set diff must specifically examine subdomain-vs-apex render yield before this ships. Mitigation option if the delta is real: recurse on base for DNS/subfinder/CT/SaaS but keep the web-traffic render on the discovered hostname (one render per distinct hostname, other phases per base).
Probe: count of distinct `processed_domains` keys sharing one `extract_base_domain` → must go to ~1; A/B diff of web-traffic-sourced edges for subdomain seeds.

**P1.3 — Atomic, depth-aware processed gate (min-depth re-expansion)** *(S code + M validation, medium risk — changes recall upward)* **[static]**
Problem: (a) check-then-insert across two lock acquisitions admits concurrent duplicate full discovery; (b) depth-blind first-wins truncates subtrees: a vendor first crawled at depth 3 is never re-expanded when found at depth 1 — children carry inflated layers, grandchildren are **never discovered**, and results differ run to run.
Root cause: `analysis.rs:871-877` (check) vs `:894-897` (insert); `HashSet<String>` stores no depth.
Change: single lock section doing test-and-set; store `HashMap<String, u32>` (domain → crawl depth); re-expand when `current_depth < stored_depth`. Output dedup already absorbs re-recorded edges. **Shares its depth-compare primitive with P1.1's dispatch claim — one semantic, landed together.**
Impact: correctness (deterministic, complete subtrees) + closes the concurrency window. This is the single highest-leverage *accuracy* item for deep scans, and it makes scan-to-scan comparisons meaningful — a precondition for measuring everything else.
Probe: identical *layer assignments* over the intersection of two identical scans' relationship sets, plus the `re-expanded at shallower depth` event counter. (Full set-identity across runs is NOT achievable from this change alone — crt.sh throttle nondeterminism (P2.9), arbitrary vendor-limit truncation (P4.8), and render variance all remain; do not use set-identity as the acceptance gate.)

**P1.4 — Org-resolution singleflight keyed on base** *(M, low risk)* **[static]** *(implements the open TF-SINGLEFLIGHT item for the org map)*
Problem: `vendor_needed` check-then-act spans the seconds-long WHOIS→web→NER chain; concurrent same-base discoverers (popular vendors appear in most parents' SPF/CT/traffic sets — exactly the depth-2/3 wavefront shape) each run the full chain. WHOIS itself has **no** per-domain cache (`whois.rs` has only the TLD→server map at `:720-729`).
Root cause: `analysis.rs:1496` (check) … `:1548-1549` (insert); comment at `:1493-1495` defends correctness, not cost.
Change: `discovered_vendors` becomes `HashMap<String, Arc<OnceCell<ResolvedOrg>>>` (or DashMap); all concurrent requesters await one in-flight chain (`get_or_try_init`). Store failures too (today's insert-on-Err behavior preserved). Write-through to the checkpointed map unchanged.
Probe: `whois.cache_hit` + a duplicate-chain counter (today: grep `Looking up organization for domain:` vs unique domains).

**P1.5 — Per-method apex memos: subfinder / CT / SaaS** *(M, low risk)* **[measured]**
Problem: all three methods do apex-scoped work but are gated per full hostname: sibling subdomains re-run subfinder (~16s of a 3-permit pool per run), re-query crt.sh `%.<apex>` (a strict superset already fetched), and re-fire the ~245-probe SaaS matrix.
Root cause: only gate is `processed_domains` on the exact string (`analysis.rs:871-897`, seeded at `:1611`); the codebase already has the correct pattern in `subprocessor_attempted_orgs` (`analysis.rs:546-576`) — claim-before-run under one lock.
Change: three scan-lifetime memos threaded like `subprocessor_attempted_orgs`: `subfinder_enumerated_apexes` (key `extract_base_domain`), `ct_queried_apexes` (same), `saas_probed_labels` (key: apex first label — the only input `generate_tenant_names` uses; note today's input is the raw recursion string, so this key is only correct once P1.2 lands — sequence accordingly).
Impact: 100% of duplicate apex-scoped runs at depth 2+ removed. Each avoided duplicate returns ~16s of subfinder pool, one CT round-trip (and its 429 pressure), ~245 SaaS probes.
Probe: distinct processed keys sharing an apex (from any deep-scan checkpoint) × per-method cost.

**P1.6 — SaaS canary baselines once per scan** *(S, no risk)* **[static, certain]**
Problem: the 42 baseline canary probes (fixed tenant `nthparty-canary-8f3a2b`) are a pure function of the platform pattern — completely domain-invariant — yet rebuilt and re-fetched for **every** domain at **every** depth.
Root cause: `saas_tenant.rs:223-249` — `baselines` is a local per-invocation HashMap; the `SaasTenantDiscovery` instance is already scan-global (`app.rs` constructs once).
Change: `tokio::sync::OnceCell<HashMap<String, BaselineResponse>>` field; compute once.
Impact: eliminates 42 × (N_recursed−1) HTTP requests ≈ 20k–80k requests on a depth-3 scan (~17% of SaaS-phase volume), frees connection-semaphore permits for latency-critical sends.
Probe: `grep -c "Baseline established"` in a -vv log → must equal 42, not 42×N.

**P1.7 — DNS negative memo + fast-path memo routing** *(M, low risk)* **[static]** *(implements the open TF-SINGLEFLIGHT item for the DNS memo)*
Problem: (a) the subfinder fast path — the program's highest-volume DNS path — bypasses `answer_memo` entirely (no reuse, no negative caching, no metrics); (b) SERVFAIL-class (`DNS_NAME`) failures are never memoized, so one broken *shared* name (an SPF include referenced by thousands of scanned domains) pays full 4-provider rotation per referencing domain for the whole scan.
Root cause: `dns.rs:1736-1768` (`get_txt_and_cname_fast` never calls `recall_answer`/`remember_answer`); memo consulted only at `:2107`/`:2346`; failures deliberately un-memoized at `:2066-2074` — right for transport errors, wrong for zone-authoritative SERVFAIL.
Change: route the fast path through the (sharded, if contention demands) memo including authoritative empties; add a scan-lifetime negative memo keyed `(kind, name)` for `DNS_NAME`-classed failures only — never THROTTLE/ENDPOINT/transport; report `Unrelated` to the governor on hit.
Probe: memo hit/miss counters (new); ratio of `name_failure_counter` to distinct failing names (≫1 today proves the amplification).

**P1.8 — Skip SaaS phase (and junk tenant names) for non-apex inputs** *(S, low risk)* **[measured]**
Problem: recursion seeds like `spf.protection.outlook.com` generate tenant names `spf`/`spf-inc`/… and fire the full matrix; generic labels (`www`, `api`, `mail`) exist as *other people's* tenants on real platforms → wasted requests **and** a false-positive attribution channel.
Root cause: `saas_tenant.rs:374-385` derives names from `domain.split('.').next()`; `run_saas_phase` receives the raw recursion string.
Change: gate the phase to apex inputs (subsumed by P1.2; keep as independent guard), and require a matched success indicator (not bare 200 → `Likely`) when the tenant name is a generic dictionary label.
Probe: count SaaS edges whose tenant name ∈ {www, api, app, mail, dev, staging} in existing scan JSONs — each is a suspect row today.

**P1.9 — Checkpoint/resume reconciliation for every new dedup structure** *(S-M, low risk, REQUIRED with P1.1/P1.3/P1.5)* **[static]**
Problem: the new structures change persisted-state semantics. P1.3 turns `processed_domains` into `HashMap<String, u32>` — but `cp.completed_domains = processed.clone()` (`analysis.rs:1331/:1375`) means a checkpoint schema change, and a legacy depthless checkpoint restored into a depth-aware gate has undefined re-expansion behavior. P1.1's `dispatched_bases` and P1.5's apex memos are scan-global and unserialized — a resumed scan re-dispatches every base and re-runs apex-scoped work done pre-interrupt.
Change: version the checkpoint schema (migrate legacy `HashSet` entries as depth=0 → never re-expanded, the conservative reading); serialize `dispatched_bases` + the three apex memos into the checkpoint, or explicitly document re-dispatch-on-resume as accepted (and make the child gate still correct under it). Add a resume regression test per structure.
Probe: interrupt+resume a bounded scan before/after; resumed scan must not re-run apex-scoped work already completed.

---

## Phase 2 — Per-method efficiency

**P2.1 — Kill the futile-SPA quadruple render** *(M, low risk)* **[static, certain]**
Problem: a candidate URL that is an SPA shell with no subprocessor JSON (the *common* case: marketing sites catch-all-200 every path) is rendered up to **4×** serially: network-capture, blind capture-retry (fires precisely when the page has no subprocessor array — i.e. always for futile pages), SPA DOM render, headless re-render. ~28–35s per futile URL.
Root cause: `trust_center/discovery.rs:520-542` (retry on "no subprocessor array"); `subprocessor.rs:2798+` (DOM fallback re-render).
Change: (a) capture returns the settled DOM too (tab is alive and exclusively held) so the DOM fallback reuses it; (b) gate the capture retry on transport error/truncation, not on "no array" (the `retry_rescued` counter is MANDATORY first — the retry was a deliberate reliability mechanism per its own doc comment; prove it never rescues before removing it); (c) skip the headless re-render when the DOM was already captured.
Impact: futile-SPA per-URL cost ~28–35s → ~7–10s. The render path was 84% of scan wall in the last full measurement — **a pre-1.6.1 figure** (the render fix removed an ~8s cold-cache stall per render and cut a reference scan 223.8s→41.4s), so re-rank against this scan's fresh perf table before letting it drive sequencing; plausibly still the largest wall-clock lever.
Probe: `render.*` class totals in the perf table before/after; per-URL render count histogram.

**P2.2 — Port the adaptive network-idle wait to subprocessor renders (TF-SUBPROC-SETTLE)** *(S-M, low risk)* **[measured — re-size first]**
Problem: fixed 5s and 2s post-navigation sleeps on every subprocessor render; `web_traffic` already ships the proven in-flight-counter idle-exit (recall-neutral, 5s hard cap).
Root cause: `subprocessor.rs:2869-2871`, `:3983`, `:6512-6514`; donor: `discovery/web_traffic.rs:251-279`.
Change: extract the idle-wait into a shared helper; use in both sites with the current fixed value as hard cap (worst case unchanged, recall can't regress). **Re-size from this scan's `render.settle` numbers first** — all prior sizing predates the 1.6.1 render fix.
Probe: `render.settle` mean before/after.

**P2.3 — Trust-center capture floor: 8s → ~2-3s** *(S, low risk)* **[static]**
Root cause: `trust_center/discovery.rs:270` (fixed 2s), `:282` (1s round granularity), `:299-303` (6-round stagnation exit) → 8s minimum for pages with zero JSON traffic; analytics beacons (`/api/` substring match at `:217-219`) reset stagnation up to the 20s cap.
Change: same network-idle primitive as P2.2; exit when nothing in flight and no new JSON for ~1.5s; tighten the `is_json` predicate.

**P2.4 — Dead-host state shared across subsystems** *(M, low risk)* **[static]**
Problem: a dead-web vendor is probed up to 4× over HTTP plus one Chrome render: org chain (4s box), NER refetch (**unboxed**, up to 10s+HTTP fallback), web-traffic static pass, Chrome navigate.
Root cause: `web_org.rs:245-263` returns `(None,None)` on error — indistinguishable from "never tried"; `whois.rs:135-143` refetches on `None`; no shared outcome state.
Change: (a) tri-state fetch outcome (`NotAttempted / Body / FailedFast(class)`) so NER never refetches after a terminal failure; (b) scan-lifetime per-URL outcome memo (bounded, ~2MB/entry cap) shared by web_org + web_traffic static pass — which also removes the **duplicate homepage fetch** every vendor pays today (`web_org` fetch + `web_traffic` fetch + Chrome render of the same URL).
Impact: ~10–20s serial chain latency per dead domain; one duplicate homepage download per live vendor; halved politeness footprint per vendor homepage.
Probe: per-URL fetch-count histogram (expect exactly 1 reqwest fetch per homepage).

**P2.5 — Subprocessor candidate loop: per-host short-circuit + no NXDOMAIN retries** *(S, low risk)* **[static]**
Root cause: `subprocessor.rs:2543-2592` retries **deterministic** failures (NXDOMAIN, connection-refused, SYN-blackhole) 3× with backoff — 3×5s connect timeout = 15.3s of the 20s budget on one dead URL; failure knowledge not shared across candidates on the same host (first 25 candidates span ~3-4 hosts).
Change: per-call `HashMap<host, ConnectFailure>` — skip same-host candidates after a connect-class failure; retry only timeouts, once.
Impact: dead-host vendors: 20s budget-exhausted zero-yield → ~5-6s.

**P2.6 — Per-URL working-time envelope inside the vendor budget** *(S, low risk)* **[static]**
Root cause: 20s budget checked only at loop top (`subprocessor.rs:1695-1700`); one futile-SPA URL overshoots ~1.5×, truncating the candidate list to 1 — the vendor's real page at position 2+ is never probed (recall). (Truncation is classified and counted since 1.6.1 — `subprocessor.rs:1699+` — so this is no longer *silent*; the recall gap itself is what remains.)
Change: ~12s per-URL envelope checked between render stages.

**P2.7 — Subprocessor negative cache** *(M, low risk)* **[static]**
Problem: the *majority* of vendors have no discoverable subprocessor page, and exactly those pay maximum cost (full 25-URL probe + futile-SPA path) — **on every scan**, because only successes are cached.
Root cause: `subprocessor.rs:1837-1840` returns before the `:1844-1849` cache write when empty; cache doc `:661-668`.
Change: negative entry (`no_sources_found`, `probed_at`, TTL 7–14d) written only when the loop completed without budget exhaustion and without transport errors (reuse the `cached_urls_are_provably_stale` "every source actually reached" discipline — an outage must never memoize as absence).
Impact: warm re-scan subprocessor wall collapses for the no-page majority.

**P2.8 — Candidate-URL list: delete the dead tail, rank by measured hit-rate** *(S, no risk)* **[static]**
Root cause: ~290 URLs generated (`subprocessor.rs:1929-2502`), first 25 probed (`:1651-1660`) — a ~265-pattern dead tail maintained but unreachable; the 25 live slots are allocated by authoring order, not hit-rate.
Change: offline tally of `working_subprocessor_urls` across historical `cache/` dirs → empirical ordering; delete/demote the tail.

**P2.9 — CT: exclude expired certs, cap shared-cert SANs, 429 cooldown, pooled client** *(M, medium risk on the SAN cap)* **[static + measured]**
Problems: (a) crt.sh queried with full unbounded cert history (expired included, multi-MB payloads); (b) every SAN of every cert seeds recursion — co-tenancy on a shared cert is **not** a vendor relationship (accuracy), and under the shipped `strategy = "unlimited"` nothing bounds the fan-out; (c) 429 → clean-empty (not retried, not recorded as degraded — silent recall loss; **still open TF-RATELIMIT half**); (d) the CT client uses the zero-idle-pool builder meant for unbounded host sets, paying a TLS handshake per query against ~1 fixed host.
Root causes: `ct_logs.rs:521-525` (query), `:536-542`+`:483-488` (Soft→empty), `analysis.rs:761-779` (no `record_failure` on soft-empty), `http_client.rs:117` vs `:119-162` (doh_builder precedent).
Changes: `exclude=expired`; SAN-count threshold (cert with >~20 distinct SAN bases = shared-infra cert — **corroborated-only**: keep SANs confirmed by a second source, never "take none" — legitimate single-org cert families (Google ccTLDs, Wikimedia, Automattic) routinely exceed 20 genuinely-owned bases, and dropping them wholesale loses true relationships; the A/B diff must specifically examine multi-brand orgs); per-provider cooldown honoring Retry-After + a distinct SCAN_COVERAGE outcome for throttled-empty; small fixed idle pool for the CT client.
**Prior-art constraint (empirically falsified alternative):** do **not** re-propose per-provider rate-pacing gates — built 2026-07-19, measured 0/17 → 1/51 CT completions, reverted (`ISA.md` ISC-510). The decoupling direction (TF-CT-DECOUPLE: background CT aggregation off the per-vendor critical path, short fail-fast timeouts) is the recorded way forward.

**P2.10 — DNS: revisit the 50-QPS fixed bucket (owner decision, gated); CNAME-from-TXT** *(S-M, medium-high risk — owner-visible policy change)* **[static]**
Problems: (a) the fixed 50-QPS token bucket sits *in front of* the adaptive governor built explicitly because "a fixed rate cannot be safe" — clamping fan-out starts to 50/s (~15 min floor per 45k-lookup enumeration) while the governor could safely discover 1200-2500 QPS at healthy RTTs; (b) every subdomain pays a TXT **and** a CNAME query, but the dns-json TXT response already carries the CNAME chain (type-5 answers), which `doh_txt_lookup` filters out — the second query re-fetches data already in hand.
Root causes: `dns.rs:1655-1661` (rate-then-governor stacking), `config.rs:142-144` (default 50); `dns.rs:1271-1282` (type-16 filter discards type-5), `:1744-1745` (paired queries).
Changes — **(b) first, (a) gated**: (b) collect type-5 answers from the TXT response, drop `fast_cname_lookup` on the subdomain path (explicit CNAME query only when the TXT arm failed) — halves fast-path DNS volume with no policy change. (a) raising/disabling the fixed bucket is an **owner-visible decision, not a default flip**: the 1.6.0 doctrine argues a fixed rate is unsafe as the *primary* control, not that a flat ceiling atop the adaptive governor is unsafe; GRC-367 *deliberately* armed this limiter on the hot path (`dns.rs:1646-1648` — "the limiter was previously dead code"), so unbinding partially reverts a recorded remediation; and the 1.6.1 CHANGELOG's own note — depth-3 transient DNS flapping "remains under investigation" — is an open counter-signal. Gate (a) on closing that investigation. Note the governor bounds *concurrency* (64), not rate — the 1200-2500 QPS figure is a derived rate at healthy RTT that brushes documented public-resolver soft limits; do not treat it as a safe target.
Probe: A/B bounded scan; `subfinder`-phase wall; DoH provider throttle counters (politeness check is part of the A/B).

**P2.11 — Root-path DNS hygiene: budget the UDP race arm, classify name failures as Unrelated** *(S, low risk)* **[static, certain]**
Problems: (a) the root TXT path races DoH against a raw UDP/53 arm that bypasses `Do53Budget` and `do53_health` entirely — the only unbudgeted UDP emission point left after the 2026-07-29 network-safety work, and it fires on essentially every non-memoized call; (b) `.ok()` erases the DoH arm's error class so SERVFAIL domains classify as `Rejected` → governor cuts scan-wide concurrency 30% + 1.5s cooldown per broken name.
Root causes: `dns.rs:2150-2177` (ungated arm, per-call resolver construction), `:2145` (`.ok()`), `:2220-2224` (`Ok(None) => Rejected`); correct pattern exists at `:1160-1162` and `:569-578`.
Changes: gate the UDP arm on `admit_do53_query() && do53_health.should_attempt()`; cache one resolver per server (OnceCell, like `dot_resolver`); preserve error class into the race and classify DNS_NAME → `Unrelated`.

**P2.12 — WHOIS pacing + global-ceiling enrollment** *(S-M, low risk)* **[static, certain]**
Problem: the WHOIS rate limiter and batch/prewarm APIs are **dead code on the scan path** — every live call site calls the unpaced function; WHOIS runs at stream concurrency (50-wide at depth 1), port-43 sockets sit outside the global connection ceiling, and registry throttling silently downgrades attribution to weaker evidence tiers (accuracy, not just speed).
Root cause: `whois.rs:90-104` (paced wrapper, zero production callers — only `whois.rs:1218`, itself uncalled); live sites `analysis.rs:1509`, `:1724`, `app.rs:2012`, `:2984`.
Change: route scan paths through the existing paced wrapper (already curated-hit-exempt) or a dedicated 4-8-permit semaphore; wrap the TCP exchange in `with_connection_permit`; add per-stage failure counters (P0.2).

**P2.13 — NER: cap/batch the subprocessor fallback; fix the permit monopoly** *(M, medium risk — recall check on cap)* **[static]**
Problem: the subprocessor NER fallback chunks the FULL page text (~40 inferences for 100KB) and runs them serially while holding one of only ~2 global inference permits — 10-30s permit monopoly stalling every other NER user.
Root cause: `ner_org.rs:637-647` (cores/4 permits), `:672-684` (permit across whole call), `:517-547` (serial chunk loop, no cap); `subprocessor.rs:3286-3339`.
Change: cap fallback input (~20-30KB — measure recall on cached real pages first); batch chunks into one GLiNER call (`TextInput::from_str` already accepts a slice); release/reacquire the permit between chunks.

**P2.14 — Cross-scan persistence beyond the subprocessor cache** *(M, medium risk — staleness policy)* **[static]**
Problem: warm-rescan economics are addressed for exactly one subsystem (P2.7). WHOIS/org resolution has no per-domain disk cache (only the TLD→server map), DNS answers are per-scan in-memory, so every re-scan re-pays the seconds-per-vendor org chain for thousands of stable facts (domain ownership churns on months-years timescales).
Change: a versioned on-disk org-resolution cache (registrable base → org, source tier, resolved_at, TTL ~30d) consulted before the P1.4 singleflight; same "an outage must never memoize as absence" discipline as P2.7 (cache only authoritative resolutions, never transport failures). DNS disk-caching deliberately excluded (TTL semantics + staleness risk outweigh the win; the in-scan memo P1.7 captures most of it).
Probe: warm-rescan wall-clock + `whois.cache_hit` (disk tier) on a repeat scan.

**P2.15 — Batch-mode dedup sharing** *(S scope line now, M later)* **[static]**
Problem: `batch.rs`/`--input-file` runs N roots with per-scan dedup structures — every shared vendor is re-scanned N times, squarely inside the dedup mandate. (Prior audit: batch entries get fresh `discovered_vendors`/`processed_domains`/`dns_pool` per entry — `app.rs:2897-2906`.)
Change: share the P1 structures (dispatched_bases, apex memos, org resolver, DNS memo) across batch entries; edges stay per-root. Scoped as follow-on — depends on P1 landing first; P2.14's disk cache gives most of the benefit meanwhile.

---

## Phase 3 — Scheduling & structure

**P3.1 — Real admission control (the dead semaphores)** *(M-L, medium risk)* **[static, certain]**
Problem: `semaphore` and `recursive_semaphore` are constructed, threaded through every signature — and **never acquired** (`rg acquire src/analysis.rs` → 0). Actual concurrency is the *product* of nested `buffer_unordered` widths (50 × 30 × 15…): thousands of in-flight tasks, which is what drove browser `permit_wait` to a 224s mean and makes every per-vendor budget measure queue depth instead of work.
Root cause: `app.rs:2070`, `:2159` (construction); `analysis.rs:1298-1302` (the only real shaping); `:1613-1647` (slot held across entire subtree).
Change: acquire a global permit around each vendor task's *local work* and release before recursive descent (leaf-held-only doctrine, already articulated at `http_client.rs:244-259`) — or adopt P3.2 which subsumes this.
Impact: peak in-flight O(10⁴) → O(10²); queue depths collapse on every downstream gate.

**P3.2 — Level-synchronized BFS frontier (the structural end-state)** *(L, medium-high risk, staged behind P1/P3.1)* **[static]**
Problem: concurrent DFS is the root cause behind four separate defects: wrong layers + truncated subtrees (P1.3), subprocessor org-claim races (a deep satellite domain claims an org before its shallower primary, suppressing the **strongest evidence source** — `analysis.rs:546-576` claim, `accuracyReport.6`), depth-semantics fuzziness, and the end-of-scan straggler collapse (depth-1 slots held for whole subtrees).
Change: explicit per-level frontier — collect next-level bases, dedup, process level-by-level. Makes `concurrency_per_depth` truthful (today it's per-parent-stream width: effective depth-2 cap = #parents × 30, not 30 — `config.rs:219-221` documents a lie), makes org-claim ordering correct by construction, and turns per-depth caps into trivial admission policy.
Note: land P1.1-P1.5 first — they're compatible with the current traversal and de-risk the frontier rewrite.

**P3.3 — Async browser permits (blocking-pool exhaustion + FIFO)** *(S-M, low risk)* **[static, certain]**
Problem: browser permit waits park OS threads in tokio's 512-thread blocking pool (`acquire_tab` blocks inside `spawn_blocking` at all four render sites); >512 queued render demands exhaust the pool and stall NER/WHOIS/extraction — priority inversion. Handoff is `notify_one` on a std Condvar: no FIFO, unbounded `permit_wait` variance, starvation tails.
Root cause: `browser_pool.rs:414-465`; `main.rs:5` default runtime; contrast `tokio::sync::Semaphore` used correctly everywhere else.
Change: `tokio::sync::Semaphore` (FIFO by contract), acquire `OwnedSemaphorePermit` in async context *before* `spawn_blocking`, move it into the closure (the `ner_org.rs` pattern). Record p99 permit_wait, not just mean.

**P3.4 — Checkpoint saves off the driver hot path** *(S, low risk)* **[static]**
Problem: every 5 depth-1 completions, the stream-driving task clones the entire `discovered_vendors`+`processed_domains` under their mutexes, pretty-prints, writes, and **fsyncs synchronously** — freezing the whole depth-1 pipeline and spiking the very locks every org resolution needs.
Root cause: `analysis.rs:1364-1390`; `checkpoint.rs:137-152` (`sync_all` in async context).
Change: snapshot cheaply, serialize+write in `spawn_blocking`, debounce by time (~30s) instead of every 5 completions.

**P3.5 — Make memory backpressure real** *(S-M, low risk)* **[static]**
Problem: pressure computes an `effective_concurrency` that is "not wired to any live limiter" (the code says so itself); the actual mechanism is a 25/250ms sleep *inside already-admitted tasks* — pure latency, zero concurrency reduction.
Root cause: `app.rs:2202-2205` (the admission comment), `analysis.rs:1220-1225`, `memory_monitor.rs:131-138`.
Change: permit-withholding against the P3.1 admission semaphore — the pattern already proven in `dns_governor.rs:302-316` (shrink live semaphore, re-add on recovery). Delete the sleeps.

**P3.6 — Whole-domain wall-clock ceiling (the open residual of TF-CONN-CEILING/ISC-439)** *(M, low risk)* **[static]**
Status split (verified): connection ceiling **shipped** (`http_client.rs:212`); per-method subprocessor budget **shipped** (`subprocessor.rs:1652`); what remains: no single ceiling across ALL methods for one domain — a multi-method-slow origin still accumulates per-method sums (93s worst observed).
Change: one permit-wait-subtracting ceiling around the whole per-vendor unit (phase join + org resolution), classified and reported — never silently truncating.

---

## Phase 4 — Accuracy & report correctness

**P4.1 — BFS-distance layer recompute at export** *(S, no risk)* **[static, certain]**
Problem: layers are stamped with the crawl depth at edge-recording time; combined with first-wins traversal they are wrong and nondeterministic (P1.3's second half).
Change: post-pass before export recomputing every edge's layer as BFS distance from root over the final deduped edge set. Independent of the traversal fix — cheap and lands first.

**P4.2 — Output dedup keeps arbitrary layer** *(S, no risk)* **[static, certain]**
Root cause: `app.rs:127-148` — dedup key omits `nth_party_layer`; first-written row wins → run-to-run diffs.
Change: `existing.nth_party_layer = existing.min(r.nth_party_layer)`. Two lines + a test. Subsumed by P4.1, worth landing independently.

**P4.3 — Root node identity: canonicalize the scan target** *(S, no risk)* **[static, certain]**
Problem: a `www.`/mixed-case/subdomain target produces a **fully disconnected HTML graph** (root id = raw string; children keyed on base-collapsed customer).
Root cause: `app.rs:1784-1787`/`:2058` (raw), `analysis.rs:1484` (base-collapsed), `export.rs:668` + `frontend/src/main.ts:43`/`transform.ts:112-124`.
Change: canonicalize once at intake (trim, lowercase, PSL-collapse); keep raw for display.

**P4.4 — Infra filter orphans subtrees** *(M, medium risk — UX decision)* **[static, certain]**
Problem: dropping X→google.com rows while keeping google.com→Y rows leaves customers that never appear as vendors: whole subtrees unreachable in the graph, counts inconsistent.
Root cause: `app.rs:160-172` filters vendor side only; recursion doesn't stop at common denominators when max_depth is set (`analysis.rs:461-463`).
Change: transitive prune, or keep infra as flagged pass-through nodes (recommended — preserves connectivity, de-emphasizes noise).
Probe (runnable on this scan's JSON): `customers − vendors − root` set must be empty.

**P4.5 — Per-layer stats count rows, not vendors** *(S, no risk)* **[static, certain]**
Root cause: `export.rs:227-236`, `:324-330` — "Layer N vendors" counts (parent,child,source) rows; multi-source vendors count 3×, layer-duplicated vendors count in both bands.
Change: distinct `nth_party_domain` per min-layer band, or relabel to "relationships".

**P4.6 — Edge evidence merging at export (TF-EDGEDEDUP)** *(M, low risk)* **[static]**
Problem: the same parent→child edge via DNS + web-traffic + CT survives as 3+ report rows (207 duplicate rows in the 2026-07-17 census).
Change: merge per (source_base, target_base) at the export boundary — one edge carrying an evidence list `{source_type, raw_record}[]`; JSON keeps full provenance. Pairs with W4/W6 provenance threading (still fully open, ISA's own #1 report-honesty priority).

**P4.7 — Depth-aware subprocessor org claims** *(S, low risk)* **[static]**
Problem: first-come org claim lets a depth-3 satellite suppress the depth-2 primary's subprocessor fetch — losing the tool's highest-evidence-tier disclosures.
Root cause: `analysis.rs:546-576` claim has no depth; comment assumes ordering the concurrent DFS doesn't provide.
Change: store claim depth; run when `current_depth < claimed_depth`. (Correct by construction under P3.2.)
Probe: extend the skip debug log with (org, claimed_depth, current_depth); count inversions on a depth-3 run.

**P4.8 — Hyperscaler/CMS enumeration gate at depth ≥2 (TF-FANOUT)** *(M, medium risk — recall constraint)* **[static]**
Problem: nothing stops subfinder/CT enumeration *against* wordpress.org-class roots at depth 2+ (6,841 discovered subdomains in the 2026-07-17 census); `vendor_limits_per_depth` caps how many recurse but not the enumeration cost, and its truncation is arbitrary (which 5 survive at depth 3 is unspecified — itself an accuracy smell).
Change: consult the existing org_role/infrastructure classification before firing enumeration phases at depth ≥2 against classified infra roots — the domain stays as a leaf edge (recall preserved), enumeration is skipped. Do **not** re-derive the per-depth caps; they exist (`config.rs:225-250`).

---

## Anti-roadmap (verified prior art — do not re-solve, do not re-propose)

**Already shipped (cite, don't redo):** IP-literal DoH defaults + adaptive DNS governor + end-of-scan DNS summary (1.6.0, `465ed5c`); shipped-config hostname-endpoint fix (`3691df0`); DoH-only idle pooling + per-provider all-must-fail breaker + SERVFAIL-with-JSON-classified-as-transport-success + bounded UDP/53 shed tier + subfinder concurrency 3 + rate-limit (1.6.1, `d646b7c`); Network.clearBrowserCache removal + honest-UA unblocking (+38 subprocessors on drata.com) + render-failure-as-coverage-failure (1.6.1, `b6847ee`); global connection ceiling 128 + zero-idle-pool discovery clients (`126bad2` line); per-domain subprocessor working-time budget (ISC-439 core); subprocessor per-org dedup gate (`bb0135b`); orphan-process startup sweeps; raw-metric flattening (TF-RAWMETRIC); DoT resolver caching.

**Empirically falsified (never re-propose):** CT per-provider rate/concurrency pacing gates — built, measured 0/17 → 1/51 completions (crt.sh hangs rather than 429s, holding permits to timeout), reverted (ISC-510). The decoupling direction is the recorded way forward.

**Rejected by recorded decision:** DoQ/DoH3 (dependency surface); per-provider DNS buckets + hedged UDP racing (multiplies egress — advisor veto); `request_delay_ms` 100→0 (politeness contract); ORT intra-op thread bump (accuracy risk); any external scan-safety wrapper (owner directive 2026-07-18 — all safety binary-native).

**Deliberately tombstoned:** Ctrl-C message overdraw (TF-CTRLC-MSG — fixing it would deadlock the handler against a suspended prompt).

**Open but out of scope here:** TF-REDIRECT-LOGS (post-bar logger lines dropped on non-TTY — bit this very investigation; fix separately), TF-WT-BLOCK / TF-WT-REQCAPTURE (render resource-blocking + request-time capture — deliberately deferred with recorded recall rationale; revisit after P2.1-P2.3 re-measure the render class), browser_oxide/lightpanda replacement track, W4/W6 full provenance threading (pairs with P4.6).

---

## Sequencing

```
Phase 0 (counters)  ──────────────────────────────┐
P1.6 canary-once  P1.8 apex-gate  P2.5 P2.11 P4.2 P4.3 P4.5   [quick wins, days]
        │
P1.1+P1.3 depth-aware claim (ONE semantic) ── P1.2 base-recursion ── P1.9 checkpoint reconciliation
        │                                    │
P1.4 org-singleflight   P1.5 apex memos      P4.1 layer recompute
        │                                    │
P2.1-P2.3 render pipeline    P2.4 dead-host  P2.7 negative cache
        │
P3.3 async browser permits ── P3.1 admission control ── P3.5 backpressure
        │
P2.9 CT overhaul   P2.10b CNAME-from-TXT (P2.10a gated on flapping investigation)   P2.12 WHOIS pacing   P2.13 NER   P2.14 org disk cache
        │
P3.2 BFS frontier  (subsumes P3.1 residuals, P4.7; makes P1.3 semantics exact)
        │
P4.4 infra filter   P4.6+W4/W6 evidence merging   P4.8 fanout gate   P3.6 domain ceiling
```

Every item ships behind the existing gates (fmt/clippy -D/full suite via the real cargo binary/deny/coverage ≥95/95) with its named probe measured before/after on a bounded reference scan. Recall-sensitive items (P1.2, P2.9 SAN cap, P2.13 cap, P4.8) additionally require an A/B relationship-set diff against a baseline scan.

---

## Appendix — measured evidence from the 2026-08-13 depth-3 run

**Run:** `nthpartyfinder -d vanta.com -r 3 --timeout 0 -f html -v`, shipped Homebrew v1.6.2 binary, cold cache, fresh default config, pty-attached. **Completed cleanly.** Wall clock **10,416s (2h 53.6m)**; report: 32.8MB HTML, **14,836 relationships exported** (17,566 unique after dedup − 1,892 infra-filtered − remainder = default filters). Raw pty log: 74,521 lines. *Caveat: the first ~25 min overlapped a 9-agent analysis workflow on this machine (load avg peaked 326); counts are load-independent, absolute wall-clock is contended for that window.*

### The dedup mandate, measured

- **112,872 raw relationships → 17,566 unique (84.4% of recorded edges were duplicates; 6.4× raw-to-unique).** The scan paid task-dispatch, sink writes, and evidence-merge cost for every one of the ~95k duplicate rows before output dedup collapsed them (P1.1, P4.6).
- **Duplicate full SaaS probe sequences: 13 vendors ran ≥2 complete ~245-probe sequences; 20 wasted sequences ≈ ~4,900 wasted probes** — `mint.rs` ×6, `md02.com`/`looker.com`/`amazonwebservices.com` ×3 (P1.1 observed at census level). **Lower bound**: the census keys on a progress-bar frame sampled at redraw time; phase.saas ran 820× vs only 264 domains captured by the census line.
- **Apex+subdomain double full-suite passes observed** (`mongodb.com` + `cloud.mongodb.com`; earlier in-flight: `google.com` + `admin.google.com`, `easydmarc.us` + `rua.easydmarc.us`) (P1.2).
- **Depth-pass arithmetic consistent with the first-wins layer defect at scale (P1.3/P4.1):** 195 direct vendors identified for vanta.com, but only **63 depth-2 discovery passes** ran vs **756 at depth-3** — i.e. ~132 of the root's direct vendors appear to have been first claimed deeper in the DFS (their children mis-layered, their grandchildren never expanded). Needs the P0.1 re-expansion counter for proof; the arithmetic and the DFS mechanics both point the same way.

### Perf attribution table (verbatim highlights)

| counter | count | total | mean | %wall |
|---|---|---|---|---|
| browser.permit_wait | 1,113 | 224,333.5s | **201.6s** | 2,153.7% |
| render.total | 1,113 | 15,267.9s | 13.7s | 146.6% |
| render.webtraffic | 820 | 11,409.1s | 13.9s | 109.5% |
| render.trustcenter | 157 | 2,641.8s | 16.8s | 25.4% |
| render.settle | 134 tracked | 451.7s | 3.4s | — |
| http.fetch | 5,734 | 32,785.5s | 5.7s | 314.8% |
| subproc.probe | 853 | 79,786.9s | **93.5s** | 766.0% |
| whois.lookup | 4,549 | 5,893.1s | 1.3s | 56.6% |
| dns.query (root path only) | 1,953 | 130,193.2s | **66.7s** | 1,249.9% |
| dns.memo_hit | 667 | — | — | — |
| phase.subfinder | 820 | **2,072,168.8s** | 2,527.0s | 19,893.9% |
| phase.saas | 820 | 121,546.5s | 148.2s | 1,166.9% |
| phase.webtraffic | 820 | 187,709.8s | 228.9s | 1,802.1% |
| phase.ct | 820 | 0.0s | — | — |
| depth passes | d1: 1 · d2: 63 · d3: 756 | | | |

### What the numbers confirm, item by item

- **P1.5/P3.1 (subfinder convoy):** phase.subfinder cumulative **2.07M seconds** across 820 passes (mean 42 min *per pass*) against ~13.6k s of actual subprocess work (820 × ~16.6s) on a 3-permit pool → **~99.3% of the subfinder phase is queue wait**, the single largest cumulative phase cost by 10×. Cutting run *count* (apex memos, base-keyed recursion) is exactly the right lever; the pool size is a deliberate WAN bound and stays.
- **P3.1/P3.3 (browser queue):** browser.permit_wait mean **201.6s** over 1,113 acquisitions on 6 permits — reproduces the July 224s pathology on 1.6.2; queue depth, not render speed, dominates.
- **P2.7 (negative cache):** **515 of ~820 vendors (63%) exhausted the 20s subprocessor budget having found nothing** (594 budget-exhausted total; the scan's own closing WARNING calls the under-reporting out). Matches the ~60-70% estimate; every one of those vendors re-pays full price on the next scan today.
- **P2.5 (dead-host retries):** subproc.probe mean 93.5s against a 20s working budget — waits and retries dominate the probe loop.
- **dnsLayer.7 (observability):** dns.query mean **66.7s** — limiter+governor wait blended into query time, unmeasurable separately; and the fast path (the volume path) has **no timer at all**: 1,953 counted queries vs a fan-out that is orders larger.
- **browserSubproc.8 (observability):** render sub-timings cover only **134 of 1,113 renders** — the table itself prints the caveat.
- **P2.10a gate (DNS flapping is REAL on 1.6.2):** **343 "All DNS resolution failed" WARNs** (by class: 153 protocol, 105 request, 85 DNS) plus visible ladder demotions — **13× "DoH appears blocked" → 9× "DoT appears blocked" → 7× "no DNS transport"** — during the depth-3 run. The 1.6.1 "transient flapping remains under investigation" residual, now with data. Do not unbind the fixed DNS bucket while this is open.
- **phase.ct = 0.0s over 820 passes:** CT-log discovery is off in the shipped default config — every CT item (P2.9) applies only to CT-enabled runs, and the P4.8-class depth-3 fan-out in *this* scan came from subfinder/SPF/web-traffic, not CT.
- **49 Vanta trust-centre GraphQL 401 fallbacks** — each pays a full render (known 1.6.1 behavior change, working as designed, but a per-scan cost worth a curated-strategy revisit).
- **Post-scan interactive review prompt held the process** after export with **1,887 inferred org names** awaiting A/R/S — fine interactively, but an unattended pty-attached run parks forever *after* the report is written. Small UX item: non-interactive default or `--yes`-style flag for the post-scan review (same prompt-class discipline as the v1.6.2 first-run fix).

### Network-health anti-claim (ISC-553)

Interactive use of the machine remained normal throughout; the scan's own transport ladder degraded (above) but recovered, and zero orphaned Chrome/subfinder processes remained after exit (verified post-SIGINT: 0/0/0).
