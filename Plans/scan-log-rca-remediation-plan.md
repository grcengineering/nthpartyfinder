# NPF Vanta.com Scan Log — Categorical Issues + RCA/Remediation Plan

**Source scan:** `/Users/p4gs/Desktop/reports/vanta_com/scan.log` (+ `reports/vanta_com/vanta-latest.html`), depth-3 vanta.com.
**Method:** every distinct error/warning class in the log was traced to its emitting code path (file:line) via a 7-agent parallel RCA against the live source tree. Each category below is *confirmed* — root cause located in code, not inferred from the log text.
**Status vs shipped work:** none of these seven were fixed by PR #80 (FD/conntrack + Chrome/subfinder reaping) or PR #81 (safe-scan retirement). PR #80's connection ceiling *aggravates* one of them (CT transport). Where a shipped fix touched an adjacent path, it's noted.

---

## The seven categorical issues (deduplicated)

| # | Category | Log symptom | Root cause (file:line) | Effort | Risk | Addressed? |
|---|----------|-------------|------------------------|--------|------|-----------|
| 1 | **DNS-failure opacity** | `DNS Failures: 70593` (console only — absent from scan.log) | Per-*attempt* counting (~5–10× amplified; real ≈7–14k) + failures routed to a log sink scan.log never sees | M | low | No (only EMFILE sub-class, in #80) |
| 2 | **CT-log transport collapse** | 1034 CT failures, only 15 successes (~1%); 665 crt.sh / 369 certspotter / 1×429 | CT discovery has **zero** rate-limiting/retry/backoff/concurrency cap — unlike DNS/subprocessor/whois | M | low | No (aggravated by #80's `pool_max_idle=0`) |
| 3 | **Malformed inputs into lookups** | non-domains fed to network lookups: `anysphere, inc.`, `hostmaster@slack.com`, `org/web/20250601085143/https://cursor.com/` | The correct guard exists (`finalize::is_non_registrable_host`) but runs only at *output*, not at the discovery→recursion *input* boundary | S | low | No |
| 4 | **Org-extraction garbage** | junk org names in report evidence: `Measures Mailchimp Security MessageBird USA`, `Google Play logo are trademarks of Google Inc.`, `Product`, `PunHub` | Over-broad self-generated regexes + whole-doc text join erasing DOM boundaries + weak `is_valid_org_name` | M | **medium** | No |
| 5 | **Domain inference `.com` default** | wrong layer-3 domains: `e2b.com` (real: e2b.dev), guesses recursed as if confirmed | Hardcoded `format!("{}.com", …)` fallback; embedded AdGuard org→domain DB not consulted; guesses enter recursion unflagged | M | low | No |
| 6 | **Whois hangs, no timeout** | (no log line — observed live: 8h47m stuck process) | `std::process::Command::output()` (blocking, no timeout/kill) inside `spawn_blocking` — `tokio::timeout` detaches the handle but can't cancel the child; runtime Drop joins it → blocks exit | S | low | No (subfinder was fixed in #80; whois is the same bug, untouched) |
| 7 | **Memory-pressure false alarm** | 12× `memory pressure … reducing concurrency` at 51–52 / 64 GB | Keys off whole-machine used/total ≥80% with no hysteresis; this 64 GB Mac idles ~80% from other workloads. Message also lies (concurrency value is discarded; only a 25 ms admission delay applies) | S | low | No |

**One-line reading of the scan's health:** the run wasn't broken — it was *loud*. Two categories degraded results (4 org garbage, 5 wrong domains); two were pure noise misreported as problems (1 inflated DNS count, 7 phantom memory pressure); one silently throttled a whole discovery source (2 CT); one is a genuine reliability bug that can wedge exit (6 whois); one is a cheap correctness guard applied at the wrong end of the pipe (3).

---

## Root cause + remediation, per category

### 1 — DNS-failure opacity (M / low)
**Why the number is wrong and invisible.** `note_throttle()` increments at ~14 call sites across the DoH choke points and resilient-loop transport branches (`dns.rs:490,505,520,534,599,610,623,633,750,841,951,961,1319,1462`). A single failing name can trip the TXT+CNAME fast path and rotate up to `min(max_dns_retries+1=4, 6 providers)=4` providers → up to ~10 increments for *one* failed lookup. Failures are never memoized (`answer_memo` caches successes only), so a hot failing name re-amplifies on every revisit. Meanwhile the count never reaches scan.log: scan.log is the `AnalysisLogger --log-file` sink (`logger.rs:460/513`), DoH warnings go to `tracing`→`ProgressAwareWriter`/stderr (`app.rs:1110-1117`), and the summary is a `println!` to stdout. `logger.log_dns_lookup_failed` has **zero callers**; `analysis.rs:908-913` swallows the error via `unwrap_or_default()` and logs a *success* line at DEBUG.

**Remediation (three coordinated changes; retry/rotation/fallback semantics untouched):**
1. **Count once per terminal failure.** Remove the per-attempt `note_throttle()` calls; increment exactly once at each terminal-failure boundary (`get_txt_and_cname_fast` Err arms, `get_txt_records_with_rate_limit:1319`, CNAME wrapper `:1462`, the `is_local_resource_error` break path). The exit-3 `>0` guard is preserved (any all-providers-and-fallback failure still lands on a terminal site); a lookup rescued by UDP fallback honestly stops counting.
2. **Structured stats on `AnalysisLogger`:** per-provider × per-class (THROTTLE/ENDPOINT/TRANSPORT/LOCAL) counts + a bounded distinct-failed-domain set. Render as *"N failed lookups across M domains (provider/class breakdown)"* instead of the bare integer.
3. **Wire the dead file-sink hook:** call `logger.log_dns_lookup_failed(domain, classed_err)` at the terminal sites (replacing the `unwrap_or_default` swallow), rate-capped (first K per class at warn, rest at debug) so a throttle wave can't flood the file. Optionally bridge `tracing` WARN+ into the file sink so `log_doh_failure`'s warn-once lines land in `--log-file`.

Update the ~dozen counter-assertion tests (`dns.rs:4042, 5400-5600`) to the once-per-terminal-failure semantics.

### 2 — CT-log transport collapse (M / low)
**Why it stampedes.** `CtLogDiscovery` has none of the rate_limit.rs machinery DNS/subprocessor/whois use. 1427 CT phases fire concurrently (`tokio::join!` at `analysis.rs:1034-1061` × `buffer_unordered` fan-out at `analysis.rs:1263-1265`), all hammering crt.sh from one IP → throttled for the whole run (15 successes, 10 of them in the first 41 s before the throttle bites). `fetch_entries_round_robin` (`ct_logs.rs:451-489`) makes exactly one attempt per provider, so a transient reset is discarded rather than retried. PR #80's global `pool_max_idle_per_host=0` made it worse for CT specifically: fresh TLS handshake per request is exactly what crt.sh throttles on.

**Remediation (reuse the GRC-367 pattern DNS already uses):**
1. Per-provider `SharedRateLimiter` + a small per-provider concurrency semaphore in `CtLogDiscovery`; pace crt.sh to ~1 rps / 1–2 concurrent, acquired before each send in `fetch_crtsh`/`fetch_certspotter`. Parallel domains serialize onto each aggregator instead of stampeding it.
2. Bounded retry-with-jittered-backoff (`RetryHelper`/`BackoffStrategy`) on `CtFetchError::Transport` and 429/5xx in `fetch_entries_round_robin`.
3. Wire the orphaned `http_requests_per_second` config (or add `ct_queries_per_second`) so the pace is tunable.
4. **Highest-leverage, safety-neutral:** for the CT client *only*, override the global pool to a tiny keep-alive pool (`hardened_builder().pool_max_idle_per_host(2)`) in `with_providers` — 2 CT hosts → 4 idle sockets max, negligible against the 128 ceiling, restores crt.sh connection reuse.

**Recall improves, doesn't regress:** same providers/parse, going from 1% success toward the high recall crt.sh delivers when paced (its 34/414/319/284-vendor hits show its value when it responds).

### 3 — Malformed inputs into lookups (S / low)
**Why garbage recurses.** Discovery emits non-domain strings (org names, `hostmaster@…` emails, wayback-wrapped URLs) that are fed straight into WHOIS/org lookups *and* recursive CT/DNS/subfinder/SaaS lookups. The right predicate already exists and is already tested — `finalize::is_non_registrable_host` (`finalize.rs:67-89`, PSL `typ()==None` + non-hostname-char + no-dot checks) — but it only runs at output assembly (`app.rs:635`).

**Remediation:** reuse it as an **input** guard. Highest-leverage single spot — top of `process_vendor_domain` (`analysis.rs:1416`, right after the `should_skip_self_reference` early-return):
```rust
if finalize::is_non_registrable_host(&vendor_domain) { logger.debug(...); return; }
```
This stops both the attribution lookups and the recursive fan-out on garbage. Optionally also filter `all_vendor_domains` at `analysis.rs:~1075` (before dedup/limit) so the per-depth vendor budget isn't eaten by junk. Keep `finalize_report` as the belt-and-suspenders output gate. **Must** use `is_non_registrable_host`, not `icann_suffix()==None`, to preserve platform-tenancy vendors (github.io, s3.amazonaws.com). Reuse finalize's existing regression tests. Longer-term: run each subprocessor candidate through the same guard (or `dns::is_valid_domain`) at extraction time so a non-domain never becomes a `SubprocessorDomain`.

**Risk is low by construction:** finalize already drops these exact strings at output via the identical predicate — moving it earlier cannot newly drop anything that currently survives; recall unchanged, speed strictly improves.

### 4 — Org-extraction garbage (M / **medium**)
**Where junk names come from.** Three compounding sources in `subprocessor.rs`:
- Over-broad self-generated regexes: the table-cell pattern `<td>([^<,]+(?:,\s*(?:Inc|LLC|Corp|Ltd)\.?)?)</td>` (`5820-5826`) has an *optional* suffix, so it matches any comma-free `<td>` (`Product`, `PunHub`); the prose regex (`5833-5841`) is similarly loose.
- The plain-text blob join (`5389-5395`) uses a global `" "` join across block-level nodes, erasing DOM boundaries so `[a-zA-Z ]` classes span unrelated cells → `Measures Mailchimp Security MessageBird USA`.
- `is_valid_org_name` (`6815-6876`) only checks length 3–80 + a small list; `Google Play logo are trademarks of Google Inc.` (8 words) passes. The fallback then synthesizes `{word}.com` (`5091-5097`).

**Remediation (three parts at the existing choke points):**
1. **Strengthen `is_valid_org_name` (`6815`):** reject names with >1 interior lowercase boilerplate word (`are, of, with, together, trademarks, logo, rights, reserved, registered, measures…`); reject ≥2 distinct word-bounded curated-org tokens (multi-entity concatenation); unify the singular/plural generic-word denylist (`product`/`products`) and share it across the exclusion patterns, `navigation_terms`, and `is_valid_org_name` so they can't drift.
2. **Stop cross-element sweeps:** join the plain-text blob (`5389-5395`) with `"\n"` between block-level nodes (keep the raw-HTML pass and inline-sibling space-joins so SPA recall like `<div>Name</div><div>•</div>` survives) — the char class then can't cross a boundary.
3. **Gate the fallback synthesizer downstream:** for rows whose domain was `{word}.com`-synthesized (already `is_fallback`), add a consistency check at `finalize.rs`'s `reconcile_org_per_domain` — require token agreement between the extracted org name and the attribution-resolved owner (`groq.com→Groq` keeps; `product.com→CollegeNET` vs `Product` drops; unresolvable/privacy-proxied → downgrade to unverified, not drop).

**Do NOT make the table-cell suffix mandatory** — the same pattern legitimately extracted `Slack, Meta, Shopify, Groq, Deepgram, FireCrawl` from suffix-less cells in *this* scan; that would cost real recall. The finalize-time owner-agreement gate is the recall-safe way to kill synthesized-domain junk. **This is the one medium-risk item** (a too-aggressive stop-word list could reject legitimate names) → gate it behind a recall check against this scan's known-good extractions before merge.

### 5 — Domain inference `.com` default (M / low)
**Why guesses go wrong and get trusted.** `map_organization_to_domain` hardcodes `format!("{}.com", cleaned)` (`subprocessor.rs:5092`); legacy `company_name_to_domain` (`5989`) does the same. The curated `KNOWN_ORG_DOMAIN_MAPPINGS` (`6483`, ~48 entries) misses the affected orgs. Worse, guesses enter depth recursion **unconfirmed**: `sentry.com/agora.com/keybase.com/openrouter.com` were fully scanned (log 3302-3305, 6389-6391, 804-807, 4208-4211) as if real — a DNS-existence check alone won't save you, because `agora.com`, `sentry.com`, `keybase.com` all resolve to *unrelated* companies. The report shows `e2b.com` (real: `e2b.dev`) as a layer-3 leaf.

**Remediation (three layers, cheapest first):**
1. **Reverse-index the already-embedded AdGuard companiesdb** (`org_dataset.rs`; verified to contain `sentry.io→Sentry`) into an org→domain map, consulted in `map_organization_to_domain` **before** the `.com` fallback — it sits at exactly the right trust tier per its own module doc.
2. **Core fix — make every generic guess carry low confidence end-to-end:** return `DomainExtractionResult` (not bare `Option<String>`) from all extraction paths, add a provenance/confidence field to `SubprocessorDomain` and `dns::VendorDomain`, register **all** fallback guesses as `PendingOrgMapping` (today only the custom-rules path does), label them in the report/review export, and gate depth recursion in `analysis.rs` so an unconfirmed `.com` guess is **reported-but-never-recursed** until confirmed via the existing interactive / `review apply` flow. This alone kills both failure modes: wasted full scans of the wrong company, and confident wrong attributions.
3. **Optional accuracy upgrade:** at guess time, probe `{slug}.com/.io/.dev/.ai/.co` with the hardened HTTP client + `web_org` title/OG/schema.org (or TLS cert `O=`) and accept only a candidate whose content matches the org name, else emit domain-less into the review export. Bounded cost: ~15 orgs/scan × ≤5 cheap requests.

### 6 — Whois hangs, no timeout (S / low)
**The actual bug.** `try_system_whois` (`whois.rs:788-802`) wraps `execute_whois_command` in `tokio::time::timeout(4s, spawn_blocking(...))`, but the inner call is `std::process::Command::new(cmd).arg(domain).output()` (`whois.rs:814`, `use std::process::Command` at `:10`) — a blocking `waitpid` with no timeout. `tokio::timeout` only drops the `JoinHandle`; it cannot cancel the blocking task or kill the child, so on a hung whois server the child runs forever, and `#[tokio::main]`'s runtime Drop *joins* the still-running blocking task → the process can't exit (the 8h47m hang observed live; it also blocked the Chrome reap → 63 orphans).

**Remediation:** rewrite the fallback on the exact subfinder pattern (`discovery/subfinder.rs:730-760`):
```rust
let mut child = tokio::process::Command::new(cmd).arg(domain)
    .stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true).spawn()?;
match tokio::time::timeout(Duration::from_secs(4), child.wait_with_output()).await {
    Ok(out) => …,
    Err(_) => { child.kill().await.ok(); Err(…) }   // kill_on_drop covers other paths
}
```
Iterate the `whois_commands` candidate list the same way the current loop does (`whois.rs:807-822`). No caller change needed (`whois.rs:399`/`:594` already treat Err as fall-through). Optionally register the PID in a small guard (mirroring `SubfinderPidGuard`, `subfinder.rs:745`) so the Ctrl-C `process::exit` path can reap an in-flight whois child — but the window is only ~4 s, so this is nice-to-have. **Zero recall/accuracy footprint:** the caller already sees the 4 s Err path today; the fix only makes the abandonment real by killing the child. (whois runs *per-domain during attribution*, not at exit, already bounded by `whois_limiter` + the 4 s deadline + only fires when native TCP/43 yields no org — its scheduling is fine; the defect is solely the un-killed child.)

### 7 — Memory-pressure false alarm (S / low)
**Why it fires at 51/64 GB.** `compute_pressure` keys off whole-machine `used/total ≥ 80%` with no hysteresis (`memory_monitor.rs:45-56`). This 64 GB Mac's baseline (other workloads) sits ~80%, so all 12 events landed at 51.2–51.8 GB — with **41 GB free**. The "reducing concurrency" message is also misleading: the computed halved-concurrency value is discarded; only a 25 ms admission delay applies.

**Remediation (three small changes in `memory_monitor.rs` + 1 line in `app.rs`):**
1. **Key on `available_memory`, not used/total** — Warning when `available < 15%` (or `< 4 GB` absolute), Critical when `< 8%` (or `< 2 GB`). sysinfo's `available_memory` is the correct exhaustion signal on macOS (Apple `AVAILABLE_NON_COMPRESSED`) and Windows (`ullAvailPhys`), so it still protects the original Windows-BSOD scenario while never firing with 41 GB free.
2. **Add hysteresis/debounce:** exit Warning only 2+ points below entry or after N consecutive Normal samples — kills the warn/relieve chatter (12 pairs, ~11 s each).
3. **Fix the message** from `reducing concurrency` to `pacing new vendor-task admissions` (the honest minimal change), or wire the discarded halved-concurrency into a real limiter. Update the `compute_pressure` unit tests (`memory_monitor.rs:287-319`).

**This is observability-correctness, not a leak or backpressure:** the 25 ms pacing never drops work, so recall was unaffected; the cost is a log that reads like a memory problem when there isn't one. After the fix, a warning would actually mean the machine is running out of memory.

---

## Suggested remediation sequence

Ordered by *leverage ÷ cost*, and by dependency (fix the things that corrupt data or wedge the process before the things that merely mislead).

**Tier A — cheap, high-leverage, near-zero risk (do first, can share one PR):**
- **#6 whois timeout** (S) — the only bug that can *wedge the process*; a mechanical port of an already-shipped pattern.
- **#3 input guard** (S) — one `if` at `analysis.rs:1416` reusing a tested predicate; stops garbage recursion, frees vendor budget, strictly faster.
- **#7 memory signal** (S) — stops the most misleading log noise; pure observability correctness.

**Tier B — medium effort, restores a whole discovery source / fixes wrong data (one PR each):**
- **#2 CT rate-limiting** (M) — biggest *recall* win (1% → paced high-recall); reuses the DNS GRC-367 machinery. Includes reverting #80's pool churn for the CT client only.
- **#5 domain-inference confidence** (M) — biggest *accuracy* win; the report-but-don't-recurse gate is the load-bearing change. Layer 1 (AdGuard reverse-index) is cheap and can land first as a sub-step.

**Tier C — medium effort, medium risk, needs a recall gate before merge:**
- **#4 org-name validation** (M/medium) — do last; the stop-word/boundary changes need validation against this scan's known-good extractions to prove no recall loss. The finalize-time owner-agreement gate (part 3) is the safest single piece and pairs naturally with #5.

**Tier D — observability, do alongside Tier A:**
- **#1 DNS counting + logging** (M) — recount-once + structured stats + wire the dead `log_dns_lookup_failed`. No behavior change, makes every other DNS investigation legible. Pairs with #7 as a "logs now tell the truth" PR.

**Cross-cutting verification for every tier:**
- fmt + `clippy --all-targets --all-features -D warnings` + full test suite + `cargo deny` + the 95/95 coverage gate (repo standard) must stay green.
- **Behavioral proof, not just unit tests:** re-run a depth-3 vanta.com scan (through the binary-native safety, on a *quiet* machine — the prior campaign's numbers are invalid because the scan collapsed its own network) and diff against this baseline: DNS-failure count should drop to the real distinct-domain figure and appear *in scan.log*; CT success rate should rise well above 1%; `e2b.com`-class wrong domains and `Product`/`PunHub`-class org junk should be absent or flagged-unverified; zero memory-pressure events with >4 GB free; clean process exit with no orphaned whois/Chrome.
- **Recall regression guard for #4/#5:** assert the known-good extractions from this scan (`Slack, Meta, Shopify, Groq, Deepgram, FireCrawl`, `sentry.io→Sentry`) still resolve correctly.

---

## Notes / non-issues surfaced during RCA
- The scan **was not failing** — it completed and produced a full report. Five of seven categories are either noise (1, 7), a correctness guard at the wrong end (3), or a throttled-but-recovering source (2). Only 4 and 5 degraded the delivered data; only 6 can wedge the run.
- Evidence-location correction: the org-garbage strings (#4) and fallback domains (#5) are in the **HTML report's evidence fields** (`Custom regex match: …`) and the interactive `pending_mappings` confirmation set (`app.rs:2552-2605`), not scan.log. whois (#6) logs at debug so it left no line at the default WARN level.
- These findings are independent of the interactive domain→org confirmation pass already completed for this scan (147 mappings saved to `cache/*.json`); #4 and #5 are precisely *why* that confirmation step exists, and #5's remediation makes the low-confidence guesses route to it automatically instead of silently recursing.
