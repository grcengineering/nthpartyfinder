#!/usr/bin/env bash
# Verify every package-manager channel actually serves the latest GitHub release.
#
# A release is not "shipped" when the tarballs land on GitHub — it is shipped when the commands
# in the README give a user that version. Those are different events, and the gap between them is
# silent: `brew install nthpartyfinder` happily installs a year-old build and reports success.
# This script closes that gap by making drift loud.
#
# Usage:
#   scripts/check-distribution-sync.sh [--tag vX.Y.Z] [--strict] [--json]
#
#   --tag     Expected version. Defaults to the repo's latest GitHub release.
#   --strict  Treat OPTIONAL channels as failures too (see CHANNEL POLICY below).
#   --json    Emit machine-readable results instead of a table.
#
# Exit codes:
#   0  every REQUIRED channel matches (and, under --strict, every optional one too)
#   1  at least one channel is stale or missing
#   2  the check itself could not run (network, missing tool, bad arguments)
#
# CHANNEL POLICY
#   REQUIRED — advertised in the README as a working install path, so lag is a user-facing bug:
#     * homebrew-formula   (brew install nthpartyfinder)
#     * homebrew-cask      (brew install --cask nthpartyfinder)
#   OPTIONAL — published by a deliberate, separate decision, so lag is expected between releases:
#     * crates.io          (publish-crate is workflow_dispatch-only, intentionally)
#     * winget             (a PR into microsoft/winget-pkgs is a third-party review process)
#
# Requires: curl, python3. `gh` is used when available (higher rate limits); falls back to
# unauthenticated API calls otherwise.
set -uo pipefail

REPO="${NPF_REPO:-grcengineering/nthpartyfinder}"
TAP_REPO="${NPF_TAP_REPO:-grcengineering/homebrew-grcengineering}"
WINGET_REPO="microsoft/winget-pkgs"
WINGET_PKG_PATH="manifests/g/GRCEngineering/NthPartyFinder"

TAG=""
STRICT=0
JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="${2:?--tag needs a value}"; shift 2 ;;
    --strict) STRICT=1; shift ;;
    --json) JSON=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for tool in curl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 2; }
done

# Prefer gh (authenticated, 5000 req/hr) but never require it.
api() {
  local path="$1"
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    gh api "$path" 2>/dev/null
  else
    curl -fsSL -H "Accept: application/vnd.github+json" "https://api.github.com/${path}" 2>/dev/null
  fi
}

raw() {
  # $1 = owner/repo, $2 = path. Raw file contents, or empty on 404.
  curl -fsSL "https://raw.githubusercontent.com/${1}/HEAD/${2}" 2>/dev/null
}

if [ -z "$TAG" ]; then
  TAG="$(api "repos/${REPO}/releases/latest" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("tag_name",""))
except Exception: pass' 2>/dev/null)"
fi
if [ -z "$TAG" ]; then
  echo "could not determine the latest release tag for ${REPO} (network or rate limit?)" >&2
  exit 2
fi
VERSION="${TAG#v}"

# Each row: name|required|found-version|detail
ROWS=()
FAILED=0
WARNED=0

record() {
  local name="$1" required="$2" found="$3" detail="$4"
  ROWS+=("${name}|${required}|${found}|${detail}")
  if [ "$found" = "$VERSION" ]; then return; fi
  if [ "$required" = "required" ] || [ "$STRICT" = "1" ]; then
    FAILED=1
  else
    WARNED=1
  fi
}

# --- Homebrew formula: version is scanned from the download URL path, by design ---------------
FORMULA="$(raw "$TAP_REPO" "Formula/nthpartyfinder.rb")"
if [ -z "$FORMULA" ]; then
  record "homebrew-formula" "required" "absent" "Formula/nthpartyfinder.rb not found in ${TAP_REPO}"
else
  F_VER="$(printf '%s' "$FORMULA" | grep -oE 'download/v[0-9]+\.[0-9]+\.[0-9]+/' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
  # A formula whose checksums are still placeholders installs nothing — treat it as broken even
  # when the version string looks right.
  if printf '%s' "$FORMULA" | grep -q 'sha256 "0\{64\}"'; then
    record "homebrew-formula" "required" "${F_VER:-unknown}" "PLACEHOLDER checksums — brew install would fail"
  else
    record "homebrew-formula" "required" "${F_VER:-unknown}" "${TAP_REPO}"
  fi
fi

# --- Homebrew cask (macOS; pulls Chrome + subfinder + whois as dependencies) -------------------
CASK="$(raw "$TAP_REPO" "Casks/nthpartyfinder.rb")"
if [ -z "$CASK" ]; then
  record "homebrew-cask" "required" "absent" "Casks/nthpartyfinder.rb not found in ${TAP_REPO}"
else
  C_VER="$(printf '%s' "$CASK" | grep -oE '^[[:space:]]*version "[0-9]+\.[0-9]+\.[0-9]+"' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
  record "homebrew-cask" "required" "${C_VER:-unknown}" "${TAP_REPO}"
fi

# --- crates.io ---------------------------------------------------------------------------------
CRATE_VER="$(curl -fsSL "https://crates.io/api/v1/crates/nthpartyfinder" 2>/dev/null | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get("crate", {}).get("max_stable_version") or d.get("crate", {}).get("max_version") or "")
except Exception: pass' 2>/dev/null)"
record "crates.io" "optional" "${CRATE_VER:-absent}" "cargo install nthpartyfinder"

# --- WinGet (upstream microsoft/winget-pkgs) ----------------------------------------------------
WINGET_DIRS="$(api "repos/${WINGET_REPO}/contents/${WINGET_PKG_PATH}" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    if isinstance(d, list):
        print("\n".join(e["name"] for e in d if e.get("type") == "dir"))
except Exception: pass' 2>/dev/null)"
if [ -z "$WINGET_DIRS" ]; then
  record "winget" "optional" "absent" "never submitted to ${WINGET_REPO}"
else
  W_VER="$(printf '%s\n' "$WINGET_DIRS" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)"
  record "winget" "optional" "${W_VER:-unknown}" "${WINGET_REPO}"
fi

# --- Report -------------------------------------------------------------------------------------
if [ "$JSON" = "1" ]; then
  python3 - "$VERSION" "$FAILED" "$WARNED" "${ROWS[@]}" <<'PY'
import json, sys
version, failed, warned, *rows = sys.argv[1:]
out = {"expected": version, "failed": failed == "1", "warned": warned == "1", "channels": []}
for r in rows:
    name, required, found, detail = r.split("|", 3)
    out["channels"].append({
        "channel": name, "policy": required, "found": found,
        "in_sync": found == version, "detail": detail,
    })
print(json.dumps(out, indent=2))
PY
else
  printf '\nDistribution sync against %s (release %s)\n\n' "$REPO" "$TAG"
  printf '  %-20s %-10s %-12s %s\n' "CHANNEL" "POLICY" "SERVING" "NOTE"
  for r in "${ROWS[@]}"; do
    IFS='|' read -r name required found detail <<< "$r"
    if [ "$found" = "$VERSION" ]; then mark="ok  "; else
      if [ "$required" = "required" ]; then mark="FAIL"; else mark="warn"; fi
    fi
    printf '  %-4s %-15s %-10s %-12s %s\n' "$mark" "$name" "$required" "$found" "$detail"
  done
  echo
  if [ "$FAILED" = "1" ]; then
    echo "At least one REQUIRED channel does not serve ${VERSION}."
    echo "Users following the README's install instructions get a different version than the latest release."
    echo "Fix: nthpartyfinder/scripts/sync-homebrew-formula.sh ${TAG}"
  elif [ "$WARNED" = "1" ]; then
    echo "All required channels are current. Optional channels lag (expected between releases; --strict to enforce)."
  else
    echo "All channels serve ${VERSION}."
  fi
fi

exit $FAILED
