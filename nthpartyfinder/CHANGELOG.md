# Changelog

## [1.7.0] - 2026-08-18

### Changed
- **A depth-3 scan that took 9 hours now takes well under an hour, without losing recall.** A code investigation (83 file:line-cited findings) found the entire discovery pipeline shared one root cause: dedup was checked *inside* each spawned task, never at dispatch, never keyed on the registrable domain, and never depth-aware — so `mongodb.com` and `cloud.mongodb.com` each paid for a full 5-phase discovery run, and a vendor first reached at depth 3 could never be correctly re-expanded when a shallower path to it appeared later. That one defect compounded multiplicatively across every discovery method.

  Fixed at the root: recursion dispatch now claims work atomically, keyed on the registrable base, with the claim recording its dispatch depth (so a vendor found later at a shallower depth still re-expands correctly instead of silently truncating). Subfinder, CT-log, and SaaS-tenant probing — apex-scoped by nature — now share one scan-lifetime memo instead of re-running per subdomain. Org resolution (WHOIS → web → NER) is now singleflight per vendor instead of racing duplicate lookups. A negative cache lets a vendor confirmed to have no subprocessor page skip the full probe on a warm rescan. Layer/depth bookkeeping is recomputed once at export via BFS instead of trusted from first-touch, closing a class of layer-assignment bugs the old first-wins memo could produce.

  Measured on the reference network, same target, same discovery methods, cold cache: **22,482 relationships in 9.15 hours → 16,560 relationships in 42 minutes.** (Run-to-run relationship counts vary ±50% on this network from live DNS/CT/trust-center churn — the wall-clock improvement is the reliable number; recall stayed in the same order of magnitude, which is the bar that matters.)

- **Per-tier attribution telemetry now actually reports which evidence tier resolved each vendor's organization** (curated / self-declared / WHOIS / system WHOIS / NER / domain-fallback) — previously invisible, now surfaced as six independent counters, letting future org-pipeline changes be measured instead of guessed at.

- Discovery-coverage instrumentation is more honest under contention: cut phases, budget exhaustion, and dead-host short-circuits are now individually counted and named in the scan summary rather than folding into an undifferentiated "degraded" state.

### Fixed
- **A silently-discarded DNS failure could read as a clean empty result.** When a DoH-sourced lookup returned an authoritative failure (e.g. SERVFAIL) but zero records, the failure was dropped on one code path while an equivalent path correctly preserved it — meaning a genuinely broken name and a genuinely empty one were indistinguishable in some cases. Both TXT and CNAME lookup paths now classify and count the failure consistently.

- Sixteen dead candidate subprocessor-page URL patterns were removed from the discovery ranking, including one (`privacyportal.{company}.com`) that unconditionally appended `.com` to a vendor's label regardless of the vendor's actual TLD — aiming live scan traffic at an unrelated third-party domain for any non-`.com` vendor. The remaining patterns are now ranked by a real tally across 187 cached scan results rather than by intuition.

- **A whole-domain wall-clock ceiling, added during this release's own development, briefly turned into a recall regression before it ever shipped.** Internal validation caught it: a 90-second per-domain ceiling — intended as a rare backstop — instead fired on the majority of depth-2+ domains, because all five discovery phases raced the same shared clock (one expiry cut every still-running phase) and the clock never credited time domains spent legitimately queued for a browser permit (measured 155s mean). Root-caused and fixed before this tag: the ceiling is now a 600-second backstop sized from that field measurement, with a regression test pinning the fix. Full post-mortem: `Plans/postmortem-2026-08-17-domain-ceiling-regression.md`. This never reached a published release — v1.6.2 users were unaffected.

## [1.6.2] - 2026-08-13

### Fixed
- **A first run asked you a question you could not see, and then looked like it had hung.** On a freshly installed copy the scan appeared to stop dead at `10% Starting vendor discovery...` and stay there indefinitely. Nothing was scanning. The process was parked in a `read_line`, waiting for an answer to the first-run analysis-timeout prompt — and that prompt had been wiped off the screen before it could be read.

  The prompt printed with raw `eprintln!` while the progress bar was live. indicatif clears the last N terminal lines before every redraw, and with the main bar plus the detail bar N is two — so within one 250 ms tick the last two lines of the prompt, the `<n> d` option and the `>` caret, were erased and painted over by the bar. What survived was a truncated block of text sitting above a bar that claimed a scan was running. It was not: `start_scan_progress` sets that message one statement *before* the prompt, so the interface announced a phase the program had not entered, and the analysis future is not even constructed until afterwards. The 600 s analysis timeout starts later still, so nothing ever rescued the wait — it was unbounded. Escaping with Ctrl-C did not help either: the flag that records "already onboarded" is written after the read, so the next run behaved identically.

  The prompt now renders inside `suspend_for_io` — the helper this codebase already documents as mandatory for interactive I/O, and which both neighbouring prompts already used — and it asks before the bar claims discovery has started. Measured on a first-run state at a pty: bar frames painted over the prompt **175 → 0**, false `Starting vendor discovery...` frames shown before the prompt **2 → 0**. Answering it still works, and a non-interactive run still never prompts, never blocks, and persists nothing.

  Every other interactive prompt was checked against the same question — *can a live bar erase this?* The dependency, ONNX-runtime, NER-model and browser-install prompts all fire before the bar starts. The output-directory and checkpoint-resume prompts already suspended. The post-scan vendor-confirmation prompts are safe only because `analysis.rs` clears the bar first, which is a dependency across two files, so that is now pinned by a test. A further guard test fails if any future stdin read in `app.rs` lands outside a bar-suspending function; it was checked by reintroducing the original defect and confirming the test fails on it.

  Two known instances of the same class are deliberately left alone, with reasons recorded: the Ctrl-C handler's own "Interrupt received" line can still be overdrawn (both fixes for it would take indicatif's lock from a signal-handler thread, which would break Ctrl-C at exactly the prompt where people reach for it), and log lines emitted after the bar starts are dropped when stderr is redirected to a file rather than a terminal (a different failure mode on a different code path, which gets its own change).

## [1.6.1] - 2026-07-31

### Fixed
- **Every headless-browser render was failing, on every scan, against current Chrome — and it looked like "this vendor has no subprocessors".** A depth-1 scan of `vanta.com` returned 63 relationships with **zero** subprocessor rows and a `DEGRADED` banner naming both web-traffic and subprocessor analysis. DNS was perfect throughout that scan (0 backoff events across 159 queries), so nothing about it was a network problem.

  Before each render, the browser pool resets the tab's network state so an interceptor can never read a body out of Chrome's disk cache. One of those five CDP calls, `Network.clearBrowserCache`, is a cold-start operation on Chrome 150: measured at **8471 / 578 / 89 / 154 / 102 ms** across five sequential calls on a fresh profile — that is, ~8s the *first* time a profile is touched and milliseconds thereafter. Every render launched a browser with a fresh profile, so every render paid the cold cost, and under scan load it exceeded the 30s ceiling that bounds every `headless_chrome` method call. The failure was treated as fatal, so the tab was never handed out. Three separate features are built on that tab — runtime web-traffic capture, trust-centre render-capture, and the subprocessor SPA fallback — and all three died together, each degrading quietly to whatever it could do without a browser.

  The cache clear is now gone entirely, because it was redundant: `setCacheDisabled(true)` — issued on the same session, and kept — is what actually stops a cached body reaching the interceptors. Measured against a browser whose cache had been warmed by a full render, a second render with only `setCacheDisabled` retrieved 38 of 38 response bodies with zero failures and zero responses served from the disk cache. Everything else is unchanged: the three O(1) network-agent toggles and the cookie clear all still run synchronously before the render and still fail it if they fail. The cookie clear stays because it is not redundant — a pooled browser serves several vendors that can share one origin (every Vanta-hosted trust centre is `trust.vanta.com/{company}`) — and it is cheap enough to keep on the critical path at 0–1 ms even cold.

  **Verified** on the same scan, same machine: subprocessor rows `0 → 38`, web-traffic `15 found, 1 failed` → `48 found, 0 failed`, total relationships `62 → 126`, unique vendors `53 → 106`, wall clock `223.8s → 41.4s`, and browser failures `3 → 0`. Across `vanta.com`, `klaviyo.com`, `drata.com`, `optro.com` and `onetrust.com`: **zero** browser failures.

- **Impersonating a browser is what got the scanner blocked.** Six HTTP clients sent a hardcoded user agent, three of them claiming to be `Chrome/120.0.0.0` under the comment "Realistic browser user agent". A pinned browser version is only realistic on the day it is written: Chrome 120 shipped in 2023, no real user runs it now, and bot-management services score an outdated browser claim as an automation signal. `trust.drata.com/subprocessors` returned **403 with `cf-mitigated: challenge`** for that string — and for `Chrome/131` — while returning 200 for an honest `nthpartyfinder/<version> (+repo-url)` identifier. Every client now shares that one identifier, whose version comes from the crate itself, so there is no browser version left to go stale. Tested across twelve real trust-centre and subprocessor URLs plus seven SaaS-tenant probes: never worse than the browser strings, and the only one that got Drata's list at all. **drata.com goes from 0 to 46 subprocessors and 43 to 89 relationships**, and from DEGRADED to SUCCESS.

- **A vendor's own broken DNS was reported as your network being unstable.** A name that answers SERVFAIL from its own authoritative servers was counted the same as a connection failure, so a scan of `klaviyo.com` ended with "DNS degraded on 29 lookup(s) … re-run on a stable network for full recall". Those 29 were `buywithprime.klaviyo.com` and its children, which SERVFAIL from 1.1.1.1 and 8.8.8.8 alike while `klaviyo.com` itself resolves fine — a broken delegation in the target's DNS that no re-run on any network will change. Name-side failures are now counted separately and reported as what they are.

- **A vendor that found its subprocessors could still be reported as "starved".** The per-vendor time budget bounds a list of 25 candidate URLs whose tail is low-probability spelling guesses. Expiring it flagged the whole scan `DEGRADED` even when an authoritative source had already answered — advising a re-run that would expire identically. Budget expiry now only counts as lost recall when the vendor yielded **nothing**, which is the case the warning was written for; that warning is unchanged and still fires (it did, correctly, on `optro.com`).

- **A browser outage could permanently delete a learned trust-centre extraction strategy.** When cached subprocessor URLs returned nothing, the cache entry was cleared as stale — including the `trust_center_strategy` that a full headless render had worked out. But "returned nothing" and "could not be reached" are the same empty result, so a scan that happened to run while Chrome was unavailable erased that work from disk. The entry is now only cleared when every cached URL was actually reached.

- **A failed render no longer reports as an authoritative empty.** When a page is detected as a single-page app and cannot be rendered, extraction runs against a script-only skeleton and finds nothing — indistinguishable from a vendor that publishes no subprocessors. That now records a coverage failure and says so, instead of contributing a clean zero. Related: browser errors were logged with only their outermost context, so the actual failing CDP call never reached the log; the full error chain is now printed.


- **A deep scan no longer takes the network down for hours — and no longer talks itself onto port 53 to do it.** 1.6.0 attacked this as a *concurrency* problem. Measuring the actual failure on the reference network showed that was the wrong model: the router's connection-tracking table peaked at **1,089 of 65,536 entries with zero drops**, while every non-443 DNS transport on the LAN — including the router's own encrypted upstream on port 8443 — went dead for **2 hours 8 minutes**, of which 2 hours 3 minutes were *after* the scan process had already exited. Throughout, DoH over 443 kept answering in 35ms. The cause was not too many connections; it was the scan demoting its own DNS onto plain port 53 and keeping it there:

  **1. DoH queries now reuse connections.** Idle pooling was globally disabled to protect that conntrack table, which meant *every* DoH query paid a fresh TCP+TLS handshake. Under a depth-3 fan-out that becomes a handshake storm: handshakes miss the connect timeout, consecutive misses mark DoH "blocked", and the ladder demotes the whole scan to DNS-over-TLS and then to raw UDP/53. Pooling is now enabled for the DoH client only — its endpoint list is fixed and small, so its idle footprint is capped at a dozen sockets no matter how deep the scan goes, whereas discovery visits an unbounded set of hosts and correctly keeps pooling off.

  **2. One sick DoH provider can no longer disable DoH.** A single circuit breaker covered the whole DoH tier, so eight consecutive failures could all belong to one struggling endpoint while its siblings were healthy. The breaker now requires *every* configured provider to have failed, and any provider answering clears the streak.

  **3. One broken domain can no longer disable DoH either.** A name that fails at its own authoritative servers returns SERVFAIL from every provider alike, which trivially satisfied "every provider failed". A DoH response carrying a well-formed JSON body is proof the transport works, whatever DNS response code it reports; those are now classified separately and count as transport *success*.

  **4. The raw UDP/53 tier has a hard emission ceiling.** Previously, demotion handed it the entire scan's DNS load — the most heavily rate-limited transport on the internet. It is now bounded to a few queries per second and *sheds* rather than queues, because a waiting limiter converts a flood into a backlog that emits the same volume later. This bound holds even when DoH is genuinely blocked.

  **5. subfinder's request volume is bounded, not just its parallelism.** Up to ten subfinder subprocesses ran with **no rate limit at all** — its global default is unlimited, and nothing was passed. The process ceiling bounded how many ran, never how much they emitted. Concurrency is now 3 and each subprocess is rate-limited. Across a monitored scan, mean concurrent subfinders was 8.2 during samples where DNS was failing versus 1.9 where it was healthy.

  **Verified:** DNS now recovers within ~20 seconds of a scan ending rather than staying dead for hours; a depth-2 scan with every discovery method enabled shows zero transport demotions and no DNS degradation at all. A depth-3 scan still causes transient DNS flapping while it runs (it recovers immediately), which remains under investigation.

### Added
- Three more default DoH endpoints — the second anycast address of each operator already in use, so endpoint capacity doubles with no new party to trust and no new filtering policy. Each was verified to serve the JSON API with byte-identical answer counts and, critically, **not** to filter the ad/tracker domains this scanner exists to discover: a filtering resolver returns NXDOMAIN rather than an error, which reads as "this vendor does not exist".

- **1.6.0's headline network fix was not actually reaching anyone.** 1.6.0 replaced the hostname DoH endpoints with IP literals in the source, but the default config file shipped inside the binary still listed all three hostnames — and since 1.5.0 a first run silently writes that default config and then uses it. So essentially every user still got `cloudflare-dns.com`, `dns.google` and `doh.sb`, and with them the A+AAAA lookup pair fired at the LAN router before each encrypted query even left the machine. That was the dominant source of forwarder load on a deep scan. The shipped config now lists IP literals only. **If you installed 1.6.0 and have a `config/nthpartyfinder.toml`, delete it (or replace its `doh_servers` list) — an existing config is never rewritten.**

- **Report filters were silently defeated by pagination.** Filtering a table to a search term and then paging forward showed rows that did not match, while the search box still displayed the term and the pager still counted the whole table ("1-50 of 7070") no matter what was filtered. Pagination decided what to show purely by row index because it read a marker that the filter code never wrote. Filters and pagination now share one contract: pagination operates on the surviving rows, the page count is computed from them, and the counter reports matches.

- **Sorting compared domains as numbers.** A prefix-parse made `1mind.com` and `1password.com` both evaluate to `1` and sort as equal. Columns now sort numerically only when the whole cell is a number.

- **The resume banner under-reported progress on every deep scan.** The depth a checkpoint had reached was recorded only in test builds, so every checkpoint written in a real run claimed depth 0.

### Changed
- The Vanta trust-centre GraphQL fast path now reports its own failure instead of falling back silently. Vanta signs each GraphQL operation's query document and validates the signature server-side; this code hand-wrote its own query text, so it worked only while that text happened to match, and it now returns `401 "Invalid signature"`. Chasing the document is an arms race, and it is unnecessary: rendering the trust centre makes the page issue that request with Vanta's *own* valid signature, which is the route every other SPA trust centre already uses. With the render path working again, `vanta.com` yields its full 43-entry subprocessor list through it.

- The HTML report no longer carries ~287 lines of dead graph-bootstrap code. It referenced three CDN URLs and an element that does not exist, and it displayed a message claiming the graph needs an internet connection — untrue, since the graph ships embedded and the report makes no external requests at all. A regression test now asserts that.
- The swatch legend and the graph's own legend no longer describe the same layer band with two different vocabularies.

## [1.6.0] - 2026-07-25

### Fixed
- **A deep scan can no longer take down the network it runs on.** Two independent causes, both fixed:

  **1. DoH endpoints no longer trigger a router lookup per query.** Half the default DoH endpoints were hostnames (`cloudflare-dns.com`, `dns.google`, `doh.sb`) alternating round-robin with their IP-literal twins. Because the HTTP clients run with no idle connection pooling and `reqwest` uses the system `getaddrinfo` resolver, *every* request to a hostname endpoint first emitted an A+AAAA pair to the LAN router — before the encrypted query even left the machine. On a depth-3 scan (45,398 subdomain lookups × 2 record types) that is order 10^5 unbudgeted UDP/53 queries aimed squarely at the consumer DNS forwarder. All default endpoints are now IP literals covering the same three providers, so provider diversity is unchanged and the bootstrap lookups are gone.

  **2. DNS concurrency now adapts to the network instead of being a fixed guess.** A new controller (`src/dns_governor.rs`) bounds *how many* DNS lookups may be outstanding and learns that bound at runtime, modeled on TCP Vegas and Netflix's `Gradient2Limit`: it starts conservatively, probes upward while latency stays flat, brakes proportionally when latency inflates past a 25% tolerance, and applies an immediate multiplicative decrease on timeouts or rejections. Bounding concurrency rather than rate matters because by Little's Law the emitted rate then falls automatically as the network slows, whereas a fixed rate keeps pushing and lets outstanding queries pile up without bound — the state that exhausts a forwarder or NAT table. No configuration required.

- **A congested network no longer disables a working DNS transport.** Congestion-induced timeouts were counted toward the per-transport circuit breaker, so eight of them marked DoH "blocked" and the ladder fell through DoT to raw UDP/53 — pushing *more* load at the resolver path that was already collapsing, while reporting "Results are unaffected". The breaker now ignores failures that occur while the adaptive controller is visibly backing off, since those are self-inflicted load rather than a broken transport.

### Added
- **`--dns-max-concurrency <N>`** pins DNS concurrency instead of adapting, for fragile networks or reproducible benchmarks. Also settable as `dns_max_concurrency` under `[rate_limits]`. Adaptation is the default and needs no configuration; pinning disables it, so a value that is too high will not be corrected for you.
- The end-of-scan summary reports what the controller did — the range it adapted across, where it ended, and how many times it backed off — so a constrained network is visible without enabling debug logging.
- **Unified runtime dependency prompt — one prompt for all optional tools, however you installed nthpartyfinder.** The three optional dependencies (a browser for web-content/web-traffic/subprocessor-render discovery, `subfinder` for subdomain discovery, `whois` for organization-name lookups) are now offered by a SINGLE consolidated prompt instead of three separate flows. When a run could use tools it's missing, the prompt lists every one of them — each with exactly which capability is DISABLED or DEGRADED without it — and installs them for your platform from one keystroke (Homebrew/winget/`apt`/`dnf`/`pacman`/`zypper`; subfinder via a package-manager-free direct download). You can pick a subset by number, and for anything you decline you choose to be reminded next run or **never again** (persisted). This is install-method-agnostic (Homebrew, WinGet, direct package, `cargo` all reach it) and never hangs — a non-interactive/CI run warns and continues with reduced coverage. New `--install-deps` flag installs everything unattended; `--install-browser` (from the prior browser-install work) remains as the browser-only subset. Any already-installed dependency is detected and used.

### Changed
- **First run is now fully promptless.** A first run with no config file no longer asks *"Configuration file not found. Create default config? [Y/n]"* — nthpartyfinder silently creates the default `./config/nthpartyfinder.toml` and continues the scan in the same invocation, whether or not stdin is a terminal. If the config can't be written (e.g. a read-only working directory) the run falls back to the embedded defaults rather than failing. `--init` remains the explicit create-only path. (Completes the "first run just works" change in 1.5.0, which still showed the prompt.)

### Documentation
- **macOS Gatekeeper — "Apple could not verify … is free of malware".** The README now explains that a binary downloaded through a browser is quarantined by macOS, how to clear it (`xattr -dr com.apple.quarantine`, or System Settings → "Open Anyway"), and points to the install methods that are never quarantined (`brew install`, `cargo install`, Docker). The downloadable binaries are cosign/SLSA-signed for supply-chain integrity but not Apple-notarized (which would require a paid Apple Developer account).

## [1.5.0] - 2026-07-20

### Added
- **Self-contained binary — no `config/` directory required.** The vendor registry (218 curated vendors), the known-vendors database, and the SaaS-platforms list are now embedded in the binary at build time. Previously they were loaded from a `config/` directory relative to the working directory, so a Homebrew / crates.io / Docker / raw-tarball install (which ships no such directory) silently degraded to an empty registry — `"No config/vendors directory found, using empty registry"` and `"Failed to load SaaS platforms: No such file or directory"` — falling back to WHOIS/domain inference and disabling SaaS discovery. A user-provided `config/` still overrides the embedded defaults.

### Changed
- **Homebrew installs the formula dependencies automatically.** The formula now declares `subfinder` and `whois` as dependencies, so `brew install nthpartyfinder` installs them with no manual steps and no mid-scan install prompts. Google Chrome is optional (browser-based discovery) and recommended via caveats rather than a dependency — Homebrew formulae cannot depend on a cask — and the binary degrades gracefully without it.
- **First run just works.** Creating the default config on first run no longer exits and asks you to re-run; the scan proceeds with the freshly-created defaults in one invocation. `--init` remains the explicit create-only path.

### Fixed
- **Missing Chrome no longer hangs the scan.** The dependency check now detects a missing Chrome/Chromium on a *default* run (previously it only checked when the explicit `--enable-web-*` flags were passed, so a default run never noticed). When Chrome is absent the browser pool fails fast instead of attempting a launch that could hang at "Starting vendor discovery": web-traffic discovery is disabled, subprocessor falls back to static HTML, and web-content extraction to HTTP-only — all with a clear "reduced coverage" message. A hard launch timeout bounds any residual present-but-wedged Chrome so a scan can never hang on it.

## [1.4.0] - 2026-07-20

### Added
- **Distribution: OS-specific installers.** Release artifacts now include `.deb` and `.rpm` packages (Linux), a `.msi` installer and `.zip` archive (Windows, alongside the existing `.tgz`), in addition to the existing tarballs for all 4 platform targets.
- **Distribution: crates.io.** Publishable via `cargo install nthpartyfinder` — package metadata completed (`homepage`, `documentation`, bundled `LICENSE`), verified under crates.io's 10MB size limit (1.2MiB compressed). Publishing wired via crates.io Trusted Publishing (OIDC) — no long-lived registry token.
- **Distribution: Homebrew.** `brew tap grcengineering/grcengineering && brew install nthpartyfinder` via a maintained shared tap, replacing the previously stale/placeholder formula.
- **Distribution: WinGet.** Manifest set prepared for submission to the community `winget-pkgs` repository.
- **Supply chain: SBOM.** Every release artifact and Docker image now ships a CycloneDX SBOM (Syft).
- **Supply chain: artifact signing.** Every release artifact is signed keylessly via Sigstore/cosign, verifiable independently of the existing SLSA provenance attestation.
- **Docs:** `RELEASING.md` documents the full release process across all 5 distribution channels for the first time.

### Security
- Docker images now carry `provenance`/SBOM attestation (previously the Docker build path had neither, unlike the binary release path's SLSA provenance).

## [1.3.0] - 2026-07-10

### Added
- **Vendor-mapping review contract + Claude Code plugin.** New `nthpartyfinder review` subcommand (`--review-json`, `apply|list|revert|path`) lets Claude accept/modify/save uncertain domain↔org mappings under a deterministic, evidence-gated writer: a mapping is written only with a machine source, ≥2 quoted signals from ≥2 distinct discovery layers, and cross-layer agreement on the same organization name. Ships with a `vendor-mapping-review` Claude Code Skill and `/npf-*` commands (`plugin/`).

### Performance
- Depth-3 scans now complete within the default 600s timeout (was ~1070s) via a pooled, per-render-isolated headless Chrome browser pool (`src/browser_pool.rs`, `src/perf.rs`) — Chrome launches dropped from ~272 to ~8 on a depth-3 `vanta.com` run. Each render disables the HTTP cache, bypasses service workers, and clears cache/cookies before use so pooled reuse cannot silently drop response bodies.

### Security
- Removed a provably-safe-but-scanner-flagged `.unwrap()` in `src/discovery/subfinder.rs` (`child.stdout.take()`) in favor of a proper `Result` propagation.
- Dependency bumps: `base64` 0.21.7→0.22.1, `sysinfo` 0.39.3→0.39.5, `indicatif` 0.18.4→0.18.6, plus the GitHub Actions group and Docker base image (chainguard/wolfi-base, rust, debian) digest bumps.

## [1.2.1] - 2026-07-08

<!-- 1.2.0 was never released: GitHub's immutable-releases feature permanently
     reserved the v1.2.0 tag when a broken release run auto-published it, so the
     tag was unusable. The identical contents ship as 1.2.1. -->

### Added
- **Multi-source subprocessor discovery.** Subprocessor lists are now extracted
  from multiple discovery sources and merged; the former Trust Center view is
  unified into a single Subprocessor Page.
- **SPA subprocessor extraction (render-and-capture).** Subprocessor tables
  rendered client-side by single-page apps are captured via a headless render
  pass instead of being missed.

### Performance
- Depth-1 scans up to ~10× faster (e.g. `vanta.com` ~8 min → ~48 s) with recall
  preserved.

### Security
- Frontend vendor-graph build toolchain upgraded to clear its 7 Dependabot
  alerts (esbuild RCE GHSA-gv7w-rqvm-qjhr, svelte XSS ×2, postcss XSS, vite ×3):
  svelte 4→5.56, vite 5→6.4.3, esbuild→0.28.1, @sveltejs/vite-plugin-svelte 3→5,
  @xyflow/svelte 0.1→1.6. The Svelte 4 components were migrated to Svelte 5
  runes + the @xyflow/svelte 1.x API (`bind:nodes`/`bind:edges`, callback-prop
  events, `mount()`); the rebuilt `static/vendor-graph.{js,css}` was visually
  verified rendering in a report. `npm audit` is clean (0 vulnerabilities).
- Removed the `whois-rs` dependency (replaced with a small in-process TCP WHOIS
  client using IANA referral, `src/whois.rs`). `whois-rs` 1.6.1 (latest) pinned
  `hickory-client 0.24` → `hickory-proto 0.24` (RUSTSEC-2026-0119) and
  `validators 0.25` → `idna 0.5` (RUSTSEC-2024-0421); both vulnerable crates are
  now out of the tree entirely — a code-level remediation rather than a risk
  acceptance. The two corresponding `deny.toml` ignore entries were deleted.
  System `whois` remains a fallback.
- Opengrep SARIF is now filtered (`scripts/filter-opengrep-sarif.py`) to drop the
  report-only `no-unwrap`/`no-eprintln` WARNING findings located in inline
  `#[cfg(test)]` test code before upload to code scanning — Opengrep's Rust
  matcher cannot exclude inline test modules, so ~1.7k test-code false positives
  were flooding the dashboard. The filter scopes by the *enclosing `#[cfg(test)]`/
  `#[test]` item's brace span* (a `use`/`const` spans only its line; a `mod`/`impl`/
  `fn` to its matching `}`), so a production finding is never dropped even when it
  sits below an early `#[cfg(test)] use`. ERROR findings and the gate are untouched.
- Bumped `quinn-proto` 0.11.14 → 0.11.15 to clear RUSTSEC-2026-0185 (high; remote
  memory exhaustion via unbounded out-of-order QUIC stream reassembly), a freshly
  published advisory on a transitive of reqwest 0.13.
- Hardened the in-process WHOIS client: the query is rejected before any network
  I/O if it contains CR/LF/whitespace, so a discovered (not pre-validated) domain
  cannot inject a second WHOIS protocol line.
- Docker base images in all Dockerfiles pinned by digest (OpenSSF Scorecard
  Pinned-Dependencies); a Dependabot `docker` ecosystem keeps the pins current.
- Bumped `crossbeam-epoch` 0.9.18 → 0.9.20 to clear RUSTSEC-2026-0204 (invalid
  pointer dereference in the `fmt::Pointer`/`Display` impl for `Atomic`/`Shared`),
  a freshly published advisory on a transitive of rayon / tokenizers / hickory.

### Fixed
- Default DoH server list replaced with verified JSON-API endpoints. Google's
  JSON DoH API lives at `/resolve` — `/dns-query` is RFC-8484 wire format and
  returns HTTP 400 for `application/dns-json`; Quad9 and OpenDNS do not serve
  the JSON GET API at all. 3 of 4 default DoH servers therefore failed every
  query, degrading DNS performance and risking false-negative vendor results.
  Cloudflare/Google IP-literal endpoints added (no DNS bootstrap dependency
  when UDP/53 is blocked).
- DoH responses with a non-2xx status other than 429/5xx (e.g. HTTP 400 from an
  endpoint that does not serve the JSON DoH API) and dns-json RCODEs other than
  NOERROR/NXDOMAIN now surface as `DNS_ENDPOINT` errors counted toward the
  exit-3 guard — never parsed as "0 records". Resilient lookups rotate past
  broken endpoints immediately (no backoff); each failing provider warns once,
  then logs at debug.
- Authoritative empty DoH answers (2xx, RCODE NOERROR/NXDOMAIN, no records) are
  now final: no system-resolver fallthrough and no spurious "All DNS resolution
  failed" warning for domains that genuinely have no TXT records.
- GRC-500: `cleanup_orphans` deleted the live result-sink files of
  concurrently-running scans on macOS/Windows. `is_process_running` checked
  `/proc/{pid}` (Linux-only), so every PID read as "not running" off Linux and
  a sibling run's startup cleanup removed an active scan's `/tmp` sink. The
  victim then panicked in `drain_all()` with ENOENT (exit 101) before writing
  output — surfacing as HTML/JSON/markdown "crashes" and silently-empty
  reports in the format matrix while CSV got lucky on timing. Liveness now uses
  `sysinfo` for correct cross-platform detection.
- The disk-sink read path no longer panics when results can't be read back; it
  fails loudly with a clear message and a dedicated exit code (4) instead of
  emitting a silently-empty report.
- Six CLI/UX/DNS defects surfaced by a live `vanta.com` run.
- HTML report: data-driven Discovery Source filter with unified source values
  across all report types; atomic light/dark theme toggle (no partial
  transitions during switch).

### Changed
- `--timeout` help now explains that depth-3+/cold-cache scans routinely exceed
  the 600s default (raise it or use `--timeout 0`) and that the output format
  does not affect discovery time.
- Dependency updates (clears the open Dependabot maintenance PRs): tokio
  1.52.1→1.52.3, serde_json 1.0.149→1.0.150, http 1.4.0→1.4.2, thiserror
  1.0→2.0, colored 2.1→3.1, which 6→8, zip 0.6→8.6, toml 0.8→1.1, sysinfo
  0.32→0.39, askama 0.12→0.16. Code touched by API changes: `sysinfo`
  `ProcessRefreshKind::new()`→`nothing()` (process-liveness check); the askama
  0.13+ removal of the generated `EXTENSION`/`MIME_TYPE` template constants
  (the affected unit test now verifies HTML output by rendering instead).
- Second dependency-update batch (clears the routine Dependabot PRs opened during
  the cleanup): reqwest 0.12→0.13 (added the `query` cargo feature, which 0.13
  gates behind it), sha2 0.10→0.11, dirs 5→6, scraper 0.26→0.27, fancy-regex
  0.13→0.18, chrono→0.4.45, which→8.0.4, headless_chrome→1.0.22, insta→1.48,
  assert_cmd→2.2.2. No source changes required beyond the reqwest feature.
- HTML report icons migrated from emoji to the GRCE Design System (Lucide) icon
  set for a consistent, professional look.

## [1.1.1] - 2026-06-02

### Security
- Patched transitive dependency CVEs: openssl 0.10.78 → 0.10.80 (CVE-2026-42327 [high] OCSP UB,
  CVE-2026-44662 + CVE-2026-45784 AES-KW heap/OOB) and tar 0.4.45 → 0.4.46 (GHSA-3pv8-6f4r-ffg2).
- Eliminated all 62 production `.unwrap()` calls (panic-safety): poison-recovery for locks,
  graceful fallbacks on malformed DNS/WHOIS/web input, documented `.expect()` for provable
  invariants. Test-code unwraps are unchanged (idiomatic).

### Changed
- CI/supply-chain hardening: least-privilege `permissions:` on all workflows; Opengrep SAST now
  gates on ERROR-severity findings; the `no-unwrap-in-prod` lint is scoped to production code
  (excludes `#[cfg(test)]` modules); added SECURITY.md and a pre-push git hook
  (`scripts/install-git-hooks.sh`) that runs fmt/clippy/cargo-deny/gitleaks before every push.

## [1.1.0] - 2026-06-01

### Added
- **Runtime-fetched NER model (crates.io publishability).** A new `runtime-ner` feature (now the
  default) fetches the ~183 MB GLiNER model at runtime from our own GitHub release
  (`model-gliner-small-v1`) instead of embedding it via `include_bytes!`. This keeps the published
  crate small enough for crates.io so `cargo install nthpartyfinder` works. The download is
  **consent-gated** (explicit `[y/N]` prompt on an interactive terminal; never auto-downloads) and
  **integrity-controlled**: each file is verified against a compiled-in SHA-256 anchor over an
  HTTPS-only, `github.com`-only request, written atomically, and re-verified from cache on load —
  unverified bytes are never loaded.
- `--download-ner-model` flag to consent to the model download non-interactively (CI/headless).

### Changed
- Default feature is now `runtime-ner` (was `embedded-ner`). Downloadable release binaries remain
  **self-contained** — CI builds them with `--no-default-features --features embedded-ner` so the
  model stays baked in and they work offline. `--disable-slm` still skips NER entirely.

## [1.0.1] - 2026-05-30

### Fixed
- GRC-367: DNS-under-concurrency false negatives. DoH throttling (429/5xx) is now detected and
  surfaced as a distinct error (never parsed into an empty answer); the per-process DNS rate
  limiter is wired onto the production hot path; provider rotation + backoff on throttle; and
  throttles are counted at the DoH choke-point so every path (TXT, CNAME, subdomain fan-out,
  SPF include-chain recursion) feeds the exit-3 false-negative guard. `SharedRateLimiter` no
  longer holds its lock across an `await`.
- GRC-368: bumped hickory-resolver 0.25.2 → 0.26.1, clearing RUSTSEC-2026-0118 and the
  resolver path of RUSTSEC-2026-0119 (the whois-rs 1.6.1 transitive path has no upstream fix
  and remains documented in deny.toml).

### Changed
- `--dns-rate-limit` is now enforced (was previously dead config) and forwarded to batch-mode
  child processes.

### Known issues
- Batch mode lacks an exit-3 DNS-throttle guard (tracked as GRC-497).

## [1.0.0] - 2026-04-28

### Fixed
- BUG-001/002/004/005/009: domain validation, _org: prefix, garbled text
- BUG-006: TLD registry operators rejected as WHOIS org names
- BUG-007/012: dedup count clarification, --dns-only flag
- BUG-011: social media links excluded from vendor relationships

### Added
- Comprehensive E2E test suite (assert_cmd-based)
- BUG-006/011/012 regression tests
- Compound TLD support (32 regional variants added)
- NER load test on Windows CI
- Release workflow with cargo-binstall artifacts

### Changed
- Live-DNS in tests replaced with wiremock fixtures
- Coverage gate set to 70% lines minimum
