#!/usr/bin/env bash
# Load the nthpartyfinder backlog into Paperclip as issues.
#
# WHY THIS IS A SCRIPT (not already run): the local Paperclip CLI returns
# 403 "Board access required" — issue/company ops need a provisioned
# company-id + an agent API key. Provide them, then run this once:
#
#   export COMPANY_ID=<company id from Paperclip board>
#   export PAPERCLIP_API_KEY=<agent key: `paperclipai agent local-cli <agentRef> -C <COMPANY_ID>`>
#   bash Plans/load-paperclip-issues.sh
#
# Optional: export CEO_AGENT_ID=<orchestrator agent id> to auto-assign every
# issue to the CEO/orchestrator agent so it can begin delegating immediately.
set -euo pipefail

: "${COMPANY_ID:?set COMPANY_ID (Paperclip board company id)}"
: "${PAPERCLIP_API_KEY:?set PAPERCLIP_API_KEY (paperclipai agent local-cli ... )}"
API_BASE="${API_BASE:-http://127.0.0.1:3100}"
PCJS="${PCJS:-$(ls /Users/p4gs/Library/Caches/pnpm/dlx/*/node_modules/.pnpm/paperclipai@*/node_modules/paperclipai/dist/index.js 2>/dev/null | head -1)}"
[ -n "$PCJS" ] && [ -f "$PCJS" ] || { echo "paperclipai dist not found; set PCJS=" >&2; exit 1; }

mk() { # title | description
  local title="$1" desc="$2" extra=()
  [ -n "${CEO_AGENT_ID:-}" ] && extra=(--assignee-agent-id "$CEO_AGENT_ID")
  local out id
  out=$(node "$PCJS" issue create \
        -C "$COMPANY_ID" --api-base "$API_BASE" --api-key "$PAPERCLIP_API_KEY" \
        --title "$title" --description "$desc" "${extra[@]}" --json 2>&1) || {
    echo "FAILED: $title" >&2; echo "$out" >&2; return 1; }
  id=$(printf '%s' "$out" | jq -r '.id // .issue.id // .identifier // "?"' 2>/dev/null || echo "?")
  echo "created  $id  $title"
}

mk "TF-5 [CRITICAL] Silent DNS false-negative — scanner reports exit-0 SUCCESS/0-vendors on DNS failure" \
"v1.0.0 NO-GO. Scanner collapses a DNS failure to 0 vendors yet exits 0 / prints SUCCESS. Proven: bamboohr.com d1=1601 vendors, d3='0 vendors found (possible DNS failure)'. 7/10 domains; ~2x run-to-run nondeterminism. FIX: (a) robust DNS retry+fallback resolver in hickory/DoH path; (b) never exit-0/SUCCESS on DNS failure — non-zero + 'results unreliable'. BLOCKS the FP/FN triage issue. Isolate in own git worktree."

mk "TF-1 [HIGH] Config-missing hard-exit contradicts README zero-config usage" \
"nthpartyfinder -d X with no ./config/nthpartyfinder.toml hard-exits 1. README Basic Usage implies zero-config works. FIX: embedded-default fallback or auto-init + regression test. INDEPENDENT — parallelizable. Own worktree."

mk "TF-2 [HIGH] NER/ONNX hard-fails exit 1 even with ORT_DYLIB_PATH set" \
"--enable-slm exits 1 'ONNX Runtime not found' despite ORT_DYLIB_PATH. FIX: honor ORT_DYLIB_PATH / in-repo onnxruntime/; graceful-degrade (warn+continue, not exit 1); regression test. INDEPENDENT — parallelizable. Own worktree."

mk "TF-4 [MEDIUM] Scan --timeout default 600s silently truncates deep scans" \
"Shipped default 600s; deep scans only completed via --timeout 0. FIX: raise/remove default OR make truncation a loud non-success (shares TF-5 fail-loud principle)."

mk "FP/FN triage campaign [HIGH] (BLOCKED by TF-5)" \
"After TF-5: re-run 10-domain depth 1/3/5 + feature-flag + format matrix; classify FP (social-media-as-vendor, registrar/TLD orgs, self-ref), FN, duplicate rows; re-baseline vanta/klaviyo oracles. DEPENDS-ON TF-5."

mk "SSCS hickory-proto bump RUSTSEC-2026-0119 [MEDIUM] (sequenced)" \
"True-positive fixable advisory. Land AFTER a clean FP/FN baseline as its own change, then re-baseline (dep bump alters DNS behavior). DEPENDS-ON FP/FN baseline."

mk "SSCS SAST gate-flip Opengrep --severity ERROR --error [MEDIUM] (sequenced)" \
"Flip from report-only ONLY after a clean master baseline proves rule-count>0 and a known-bad fixture trips. Never before baseline (blocks bugfix merges)."

mk "TF-COV verify coverage >=95% [LOW]" \
"Run nthpartyfinder/scripts/coverage.sh; confirm >=95% line+function with documented --ignore-filename-regex. Never measured this session."

mk "TF-SLSA provenance tag dry-run [LOW]" \
"Push throwaway v* tag; confirm slsa-github-generator job runs and slsa-verifier validates; check digest-aggregation format."

mk "TF-CATO E4 Cato audit + pre-complete advisor [LOW]" \
"Re-run cross-vendor Cato audit + pre-complete advisor (infra-blocked this session) before any v1.0.0 tag."

mk "GO_NO_GO update — record TF-5 NO-GO [HIGH]" \
"Update GO_NO_GO.md: v1.0.0 is NO-GO until TF-5 fixed. A vendor-risk tool cannot silently report 'no vendors' on a DNS hiccup."

echo
echo "Done. Critical path: TF-5 -> FP/FN -> hickory -> re-baseline."
echo "Parallel-now (independent worktrees): TF-5, TF-1, TF-2, TF-4, GO_NO_GO."
[ -n "${CEO_AGENT_ID:-}" ] && echo "All issues assigned to CEO_AGENT_ID=$CEO_AGENT_ID — it can begin delegating." \
  || echo "Set CEO_AGENT_ID and re-run, or assign the orchestrator agent in the Paperclip board to start delegation."
