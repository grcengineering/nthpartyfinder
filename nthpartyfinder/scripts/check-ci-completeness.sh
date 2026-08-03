#!/usr/bin/env bash
# Detect a push to master whose always-on CI workflows never even started.
#
# Incident (2026-08-02): PR #111's squash-merge commit triggered exactly one check —
# GitHub's native `copilot_code_review` ruleset feature — while CI, CodeQL, Docker Build,
# Security, and OpenSSF Scorecard never queued at all. Not a config problem (every one of
# those workflows has an unconditional `push: branches: [master]` trigger, no path filter,
# no concurrency group that could have cancelled it) and not a platform incident (status.github.com
# was green throughout). The one thing that DID fire uses a different delivery path entirely
# (a ruleset-driven native check, not an Actions `on: push` trigger) — which narrows the failure
# to Actions' own push-to-workflow-run pipeline specifically. An empty commit produced a fresh
# push event and all 5 fired normally, so whatever happened was transient. It went unnoticed for
# ~20 minutes because nothing was watching for a workflow that never starts — a failed run pages
# you; a run that never exists makes no noise at all.
#
# This script is the detector, factored out so it's testable standalone (same idiom as
# check-distribution-sync.sh) rather than only runnable inside the Action. It does NOT remediate;
# ci-completeness-monitor.yml calls this, then acts on a non-empty result.
#
# Usage:
#   scripts/check-ci-completeness.sh [--repo owner/name] [--lookback-hours N] [--grace-minutes N] [--json]
#
#   --repo            Defaults to $CI_REPO or grcengineering/nthpartyfinder.
#   --lookback-hours  How far back to examine master commits. Default 3.
#   --grace-minutes   Ignore commits younger than this — their workflows may still be queued,
#                     not missing. Default 12 (comfortably past this repo's slowest job on a cold
#                     runner; a false "missing" here is worse than a few-minute detection lag).
#   --json            Emit machine-readable results instead of a table.
#
# Exit codes:
#   0  every commit in the window has every expected workflow (or is too young to judge)
#   1  at least one commit is missing an expected workflow entirely
#   2  the check itself could not run (network, missing tool, bad arguments)
#
# EXPECTED-WORKFLOW SET
# Deliberately hand-maintained, not derived by parsing `on:` blocks. A path-filtered workflow
# (fuzz.yml watches only nthpartyfinder/src|fuzz/**) legitimately does NOT fire on most commits,
# and correctly emulating GitHub's path-filter matching in a shell script is real work whose only
# payoff is avoiding false positives on ONE workflow — not worth the risk of getting the glob
# semantics subtly wrong and eroding trust in every other alert this produces. These five are
# the ones with an unconditional `push: branches: [master]` and nothing else that could suppress
# them for a given commit, verified by reading each file directly (2026-08-02):
EXPECTED_WORKFLOWS=("CI" "CodeQL" "Docker Build" "Security" "OpenSSF Scorecard")

REPO="${CI_REPO:-grcengineering/nthpartyfinder}"
LOOKBACK_HOURS=3
GRACE_MINUTES=12
JSON=0

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="${2:?--repo needs a value}"; shift 2 ;;
    --lookback-hours) LOOKBACK_HOURS="${2:?--lookback-hours needs a value}"; shift 2 ;;
    --grace-minutes) GRACE_MINUTES="${2:?--grace-minutes needs a value}"; shift 2 ;;
    --json) JSON=1; shift ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for tool in gh jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 2; }
done

GRACE_CUTOFF_ISO="$(date -u -d "${GRACE_MINUTES} minutes ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
  || date -u -v-"${GRACE_MINUTES}"M +%Y-%m-%dT%H:%M:%SZ)"

# The commits that deserve their own push-triggered CI run are the ones where master's tip
# genuinely CHANGED — not every commit reachable from master. `/commits?sha=master` was tried
# first and rejected: it lists every ancestor, including a feature branch's own prior commits
# that enter master's history as a MERGE PARENT under a non-squash `--merge` (never themselves
# the target of a master push event, so of course no workflow ever ran against them alone —
# that's not an anomaly, it's how a fast-forwardable merge commit works). Confirmed against a
# real false positive during development: PR #115's source commit showed up as "missing every
# workflow" purely because it became a master ancestor via `gh pr merge --merge`, never a push.
#
# The Activity API's `after` field is the correct source: each entry is one genuine master-tip
# update, however it happened (direct push, squash-merge, or plain merge), which is exactly the
# set GitHub's `on: push` triggers should have fired for. Non-`pr_merge` activity types (a direct
# `git push`, a force-push) are included too, not just `pr_merge` — an unfiltered pull, then a
# client-side date filter, since the endpoint accepts `time_period` but not an arbitrary `--since`.
ACTIVITY_JSON="$(gh api "repos/${REPO}/activity?ref=master&per_page=100" --paginate \
  --jq '[.[] | {sha: .after, date: .timestamp}]')"
COMMITS_JSON="$(printf '%s' "$ACTIVITY_JSON" | jq --arg since "$(date -u -d "${LOOKBACK_HOURS} hours ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-"${LOOKBACK_HOURS}"H +%Y-%m-%dT%H:%M:%SZ)" \
  '[.[] | select(.date > $since)] | sort_by(.date)')"
# Commit messages are cosmetic (report only), fetched separately so a lookup failure never blocks
# detection — the exit code depends only on the workflow-presence check below.
COMMITS_JSON="$(printf '%s' "$COMMITS_JSON" | jq -c '.[]' | while IFS= read -r c; do
  sha="$(printf '%s' "$c" | jq -r '.sha')"
  msg="$(gh api "repos/${REPO}/commits/${sha}" --jq '.commit.message | split("\n")[0]' 2>/dev/null || echo "(message unavailable)")"
  printf '%s' "$c" | jq --arg msg "$msg" '. + {message: $msg}'
done | jq -s '.')"

FAILED=0
ROWS=()

while IFS= read -r commit; do
  [ -z "$commit" ] && continue
  sha="$(printf '%s' "$commit" | jq -r '.sha')"
  date="$(printf '%s' "$commit" | jq -r '.date')"
  message="$(printf '%s' "$commit" | jq -r '.message')"

  # Skip commits still inside the grace window — their workflows may be legitimately queued.
  if [[ "$date" > "$GRACE_CUTOFF_ISO" ]]; then
    continue
  fi

  RUNS_JSON="$(gh api "repos/${REPO}/actions/runs?head_sha=${sha}" --jq '[.workflow_runs[].name]')"

  MISSING=()
  for wf in "${EXPECTED_WORKFLOWS[@]}"; do
    if ! printf '%s' "$RUNS_JSON" | jq -e --arg wf "$wf" 'index($wf) != null' >/dev/null 2>&1; then
      MISSING+=("$wf")
    fi
  done

  if [ "${#MISSING[@]}" -gt 0 ]; then
    FAILED=1
    missing_csv="$(IFS=,; echo "${MISSING[*]}")"
    ROWS+=("${sha}|${date}|${missing_csv}|${message}")
  fi
done < <(printf '%s' "$COMMITS_JSON" | jq -c '.[]')

if [ "$JSON" = "1" ]; then
  python3 - "$FAILED" "${ROWS[@]}" <<'PY'
import json, sys
failed, *rows = sys.argv[1:]
out = {"failed": failed == "1", "gaps": []}
for r in rows:
    sha, date, missing_csv, message = r.split("|", 3)
    out["gaps"].append({
        "sha": sha, "date": date,
        "missing_workflows": missing_csv.split(","),
        "message": message,
    })
print(json.dumps(out, indent=2))
PY
else
  printf '\nCI completeness check against %s (lookback %sh, grace %smin)\n\n' "$REPO" "$LOOKBACK_HOURS" "$GRACE_MINUTES"
  if [ "${#ROWS[@]}" -eq 0 ]; then
    echo "All commits in the window have every expected workflow (or are too young to judge)."
  else
    printf '  %-10s %-22s %-40s %s\n' "SHA" "DATE" "MISSING" "MESSAGE"
    for r in "${ROWS[@]}"; do
      IFS='|' read -r sha date missing_csv message <<< "$r"
      printf '  %-10s %-22s %-40s %s\n' "${sha:0:10}" "$date" "$missing_csv" "${message:0:60}"
    done
    echo
    echo "At least one commit on master never triggered an always-on workflow."
    echo "Fix: re-fire the missing workflow(s) via 'gh workflow run <file> --ref master'"
    echo "(workflow_dispatch was added to all five for exactly this)."
  fi
fi

exit $FAILED
