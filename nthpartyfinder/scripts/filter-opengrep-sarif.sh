#!/usr/bin/env bash
#
# filter-opengrep-sarif.sh — drop idiomatic test-code findings of the report-only
# WARNING rules (no-unwrap-in-prod / no-eprintln-in-prod) from the Opengrep SARIF
# before it is uploaded to GitHub code scanning.
#
# WHY: these rules target PRODUCTION code, but Opengrep v1.21.0's (experimental)
# Rust matcher does not reliably exclude `.unwrap()` / `eprintln!` inside inline
# `#[cfg(test)] mod tests { ... }` blocks — the `pattern-not-inside` guard in
# .opengrep/rules.yml does not fire on large inline test modules. The result was
# ~1.7k code-scanning alerts that are 100% test code (verified: every alert lay
# below the file's `#[cfg(test)]` marker) with zero production unwraps. This is
# the documented "scanner fundamentally cannot model the pattern" carve-out, not
# a convenience suppression: production findings are PRESERVED and the
# ERROR-severity gate (sensitive-data-in-logs) is untouched.
#
# HOW: a finding of a target rule is treated as test code — and dropped — iff it
# lies at or after the first `#[cfg(test)]` line of its file (Rust convention
# places unit tests in a trailing `#[cfg(test)] mod tests`). Findings above the
# test module (i.e. real production code) are kept, so a genuine prod unwrap
# still surfaces on the dashboard.
#
# Run from the crate directory (paths in the SARIF are crate-relative, e.g.
# `src/foo.rs`). Idempotent. Requires: bash, jq, grep.
set -euo pipefail

SARIF="${1:-opengrep.sarif}"
TARGET_RULES='no-unwrap-in-prod|no-eprintln-in-prod'

if [ ! -s "$SARIF" ]; then
  echo "filter-opengrep-sarif: no SARIF at '$SARIF'; nothing to do"
  exit 0
fi

# Map each file referenced by a target-rule finding -> first #[cfg(test)] line
# (0 if the file has no test module or is missing). Portable (no `mapfile`).
map='{}'
while IFS= read -r f; do
  [ -n "${f:-}" ] || continue
  line=0
  if [ -f "$f" ]; then
    n="$(grep -n -m1 '#\[cfg(test)\]' "$f" | cut -d: -f1 || true)"
    [ -n "$n" ] && line="$n"
  fi
  map="$(jq --arg k "$f" --argjson v "$line" '. + {($k): $v}' <<<"$map")"
done < <(jq -r --arg re "$TARGET_RULES" '
  [ .runs[]?.results[]?
    | select((.ruleId // "") | test($re))
    | .locations[0].physicalLocation.artifactLocation.uri // empty ]
  | unique | .[]' "$SARIF")

before="$(jq '[.runs[]?.results[]?] | length' "$SARIF")"
jq --arg re "$TARGET_RULES" --argjson cfg "$map" '
  .runs[]?.results |= map(
    select(
      if ((.ruleId // "") | test($re)) then
        (.locations[0].physicalLocation.artifactLocation.uri // "") as $u
        | (.locations[0].physicalLocation.region.startLine // 0) as $ln
        | ($cfg[$u] // 0) as $c
        | ($c == 0) or ($ln < $c)
      else true end
    )
  )
' "$SARIF" > "$SARIF.filtered"
mv "$SARIF.filtered" "$SARIF"
after="$(jq '[.runs[]?.results[]?] | length' "$SARIF")"

echo "filter-opengrep-sarif: $before -> $after results ($((before - after)) test-code WARNING findings dropped)"
