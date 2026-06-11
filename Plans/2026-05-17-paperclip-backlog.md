# nthpartyfinder — Paperclip Delegation Backlog (2026-05-17)

Ready-to-load work items for the Paperclip CEO/orchestrator agent. Loader:
`Plans/load-paperclip-issues.sh` (needs `COMPANY_ID` + `PAPERCLIP_API_KEY`).

Status legend: ✅ done/committed · 🔴 blocker · 🟡 open · ⏸ sequenced (deferred by design)

## Already done (committed on `feat/GRC-149-100pct-coverage`, not pushed)
- ✅ SSCS hardening `7b0386c` (coverage 100→95 + ignore-regex + local script; stale `cargo audit --ignore` removed; deny.toml `unused-ignored-advisory`; Opengrep/OSV/gitleaks/Scorecard/Dependabot/SLSA; codeql comment; gitignore creds; B2 research logged)
- ✅ TF-3 result-sink concurrent-deletion panic `7927d7f` (40 tests; 0 panics across full ~2h campaign)
- ✅ ISA finalized (`ISA.md`, 142 ISC)

## Issues to delegate

### ISSUE-1 · TF-5 — Silent DNS false-negative (CRITICAL · v1.0.0 NO-GO · blocks FP/FN)
The scanner hits a DNS failure, collapses the whole run to 0 vendors, but prints
`SUCCESS` and **exits 0**. Proven: `bamboohr.com d1` → 1601 vendors; `bamboohr.com d3`
(same domain) → `0 vendors found (possible DNS failure)`. 7/10 domains affected;
run-to-run non-determinism ~2× (vanta 34↔65/75, klaviyo 74↔134); non-monotonic depth.
**Fix:** (a) robust DNS resolution — retry + fallback resolver in the hickory/DoH
path; (b) NEVER return exit-0/"SUCCESS" when DNS failed — fail loud, non-zero,
distinct exit code, explicit "results unreliable" banner. Priority: CRITICAL.
Blocks: ISSUE-5.

### ISSUE-2 · TF-1 — Config-missing hard-exit (HIGH · independent)
`nthpartyfinder -d X` with no `./config/nthpartyfinder.toml` in CWD hard-exits 1,
contradicting README zero-config "Basic Usage" examples. Tool ships a full 26 KB
default via `--init`. **Fix:** fall back to embedded defaults (or auto-init) when
no config present; regression test. Independent — parallelizable.

### ISSUE-3 · TF-2 — NER/ONNX hard-fail (HIGH · independent)
`--enable-slm` (default NER build) exits 1 "ONNX Runtime not found" even with
`ORT_DYLIB_PATH` exported. **Fix:** correct dylib resolution (honor
`ORT_DYLIB_PATH`/in-repo `onnxruntime/`); graceful-degrade — warn + continue
without NER instead of `exit 1`; regression test. Independent — parallelizable.

### ISSUE-4 · TF-4 — Scan-timeout default truncates deep scans (MEDIUM)
Shipped `--timeout` default is 600 s; deep scans silently truncate (campaign only
worked via `--timeout 0`). **Fix:** raise/remove the default OR make timeout
truncation a loud non-success signal (shares ISSUE-1's "fail loud" principle).

### ISSUE-5 · FP/FN triage campaign (HIGH · BLOCKED by ISSUE-1)
Re-run 10-domain depth 1/3/5 + feature-flag + format matrix once TF-5 fixed;
classify false-positives (social-media-as-vendor, registrar/TLD orgs, self-ref),
false-negatives, duplicate rows; re-baseline vanta/klaviyo oracles. Cannot be
trusted until ISSUE-1 lands. Depends-on: ISSUE-1.

### ISSUE-6 · SSCS hickory-proto bump RUSTSEC-2026-0119 (MEDIUM · ⏸ sequenced)
True-positive, fixable. Advisor-sequenced: land as its own change AFTER a clean
FP/FN baseline, then re-baseline (dep bump changes DNS behavior). Depends-on: ISSUE-5.

### ISSUE-7 · SSCS SAST gate-flip (MEDIUM · ⏸ sequenced)
Opengrep report-only → `--severity ERROR --error` ONLY after a clean baseline on
master proves rule-count>0 and a known-bad fixture trips. Never flip before
baseline (blocks bugfix merges). Depends-on: clean SAST baseline.

### ISSUE-8 · TF-COV — verify coverage ≥95% (LOW)
Run `nthpartyfinder/scripts/coverage.sh`; confirm ≥95% line+function with the
documented `--ignore-filename-regex`. Never measured this session.

### ISSUE-9 · TF-SLSA — provenance tag dry-run (LOW)
Push a throwaway `v*` tag, confirm `slsa-github-generator` job runs and
`slsa-verifier` validates; check the digest-aggregation format.

### ISSUE-10 · TF-CATO — E4 Cato audit + pre-complete advisor (LOW)
Re-run the cross-vendor Cato audit + pre-complete advisor (infra-blocked this
session) before any v1.0.0 tag.

### ISSUE-11 · GO_NO_GO update — record TF-5 NO-GO (HIGH)
Update `GO_NO_GO.md`: v1.0.0 is **NO-GO** until ISSUE-1 (TF-5) is fixed — a
vendor-risk tool cannot silently report "no vendors" on a DNS hiccup.

## Critical path
ISSUE-1 (TF-5) → ISSUE-5 (FP/FN) → ISSUE-6 (hickory) → re-baseline.
Parallelizable now (independent, isolated worktrees): ISSUE-1, ISSUE-2, ISSUE-3, ISSUE-4, ISSUE-11.

## CEO/orchestrator dispatch
Once issues exist and an orchestrator ("CEO") agent is assigned in the Paperclip
board: it should claim/checkout issues, spawn worker agents in **isolated git
worktrees** (one per issue — zero cross-conflict, and zero conflict with the
main-tree campaign binary), gate merges through `paperclip approval`, and keep
workers on task against the dependency graph above (don't start ISSUE-5 until
ISSUE-1 merges; ISSUE-6 only after ISSUE-5's baseline).
