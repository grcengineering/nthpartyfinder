#!/usr/bin/env bash
# Fill in the real sha256 checksums for a released version's macOS/Linux tarballs into the
# Homebrew formula, and — if a tap remote is configured — stage the formula on a release
# branch there for a signed commit. Run this AFTER a release's GitHub Actions build-release
# matrix has finished (the tarballs must exist to hash).
#
# Usage:
#   scripts/sync-homebrew-formula.sh v1.5.0 [tap-repo]
#
# tap-repo defaults to grcengineering/homebrew-grcengineering (a shared tap for all GRC
# Engineering tools, not a project-specific one). Requires `gh` auth with access to that
# repo if staging; without it, the formula is still updated locally (in packaging/homebrew/)
# and the tap step is skipped with a note.
#
# The tap ships BOTH a formula and a cask:
#   * formula — cross-platform (macOS + Linux). Cannot depend on a cask, so it does not pull
#     Chrome; the binary offers to install a browser at runtime instead.
#   * cask — macOS only, and the only kind of package that may depend on another cask, which is
#     what lets `brew install --cask nthpartyfinder` also install Google Chrome.
# Both are tracked in packaging/homebrew/ in this repo; this script fills in a release's version
# and checksums and syncs them to the tap.
#
# NOTE ON SIGNING: the tap enforces `required_signatures`, so an unsigned `git push` is rejected.
# Two ways to satisfy that:
#   * default (no --push): stage a release branch locally and print the exact signed-commit
#     command for the maintainer's verified key.
#   * --push: create the commits through the GitHub API on a release branch, then squash-merge.
#     The branch commits themselves are NOT signed when the API call authenticates as a user —
#     web-flow signing applies to the web UI and to GitHub Apps, not to a user token (confirmed on
#     v1.6.0: `verified: false, reason: unsigned`). That is fine, because required_signatures
#     protects the tap's DEFAULT BRANCH and only the squash commit lands there — and GitHub signs
#     the squash commit it creates. So: SQUASH-merge the PR this opens. A plain merge commit would
#     carry the unsigned commits onto main and be rejected.
#     Requires GH_TOKEN/TAP_TOKEN with Contents: read+write on the tap.
set -uo pipefail

usage() { sed -n '2,20p' "$0"; exit 2; }

TAG=""; TAP_REPO=""; PUSH=0
while [ $# -gt 0 ]; do
  case "$1" in
    --push) PUSH=1; shift ;;
    -h|--help) usage ;;
    -*) echo "unknown flag: $1" >&2; usage ;;
    *) if [ -z "$TAG" ]; then TAG="$1"; elif [ -z "$TAP_REPO" ]; then TAP_REPO="$1"; fi; shift ;;
  esac
done
[ -n "$TAG" ] || { echo "usage: sync-homebrew-formula.sh <tag> [tap-repo] [--push]" >&2; exit 2; }

VERSION="${TAG#v}"
TAP_REPO="${TAP_REPO:-grcengineering/homebrew-grcengineering}"
REPO="grcengineering/nthpartyfinder"
FORMULA="$(dirname "$0")/../packaging/homebrew/nthpartyfinder.rb"
CASK="$(dirname "$0")/../packaging/homebrew/nthpartyfinder-cask.rb"
set -e

sha_for() {
  local target="$1"
  local url="https://github.com/${REPO}/releases/download/${TAG}/nthpartyfinder-${target}.tgz"
  curl -fsSL "$url" | shasum -a 256 | awk '{print $1}'
}

echo "Fetching checksums for ${TAG}..."
ARM_SHA="$(sha_for aarch64-apple-darwin)"
X86_MAC_SHA="$(sha_for x86_64-apple-darwin)"
LINUX_SHA="$(sha_for x86_64-unknown-linux-gnu)"

echo "  aarch64-apple-darwin:      $ARM_SHA"
echo "  x86_64-apple-darwin:       $X86_MAC_SHA"
echo "  x86_64-unknown-linux-gnu:  $LINUX_SHA"

# Formula: 3 bare `sha256 "…"` lines in URL order arm-mac, x86-mac, linux; the version is
# scanned from the URL path (no explicit `version` line — that would be a `brew audit` error).
python3 - "$FORMULA" "$VERSION" "$ARM_SHA" "$X86_MAC_SHA" "$LINUX_SHA" <<'PYEOF'
import re, sys
path, version, arm_sha, x86_mac_sha, linux_sha = sys.argv[1:6]
with open(path) as f:
    text = f.read()

text = re.sub(r'(v)\d+\.\d+\.\d+(/nthpartyfinder-)', rf'\g<1>{version}\g<2>', text)

blocks = list(re.finditer(r'sha256 "[0-9a-f]{64}"', text))
if len(blocks) != 3:
    print(f"expected 3 sha256 lines, found {len(blocks)} — formula structure changed, not auto-updating", file=sys.stderr)
    sys.exit(1)
new_shas = [arm_sha, x86_mac_sha, linux_sha]
out = []
last = 0
for m, sha in zip(blocks, new_shas):
    out.append(text[last:m.start()])
    out.append(f'sha256 "{sha}"')
    last = m.end()
out.append(text[last:])
with open(path, 'w') as f:
    f.write(''.join(out))
print("formula updated")
PYEOF

# Cask: version lives in a `version "x.y.z"` line and the two macOS checksums in a keyed
# `sha256 arm: ..., intel: ...` pair (Linux has no cask support, so no Linux sha here).
python3 - "$CASK" "$VERSION" "$ARM_SHA" "$X86_MAC_SHA" <<'PYEOF'
import re, sys
path, version, arm_sha, x86_mac_sha = sys.argv[1:5]
with open(path) as f:
    text = f.read()

text, n_ver = re.subn(r'^(\s*version )"[^"]+"', rf'\g<1>"{version}"', text, count=1, flags=re.M)
if n_ver != 1:
    print("expected exactly one version line in the cask - structure changed, not auto-updating", file=sys.stderr)
    sys.exit(1)

text, n_arm = re.subn(r'(sha256 arm:\s*)"[0-9a-f]{64}"', rf'\g<1>"{arm_sha}"', text, count=1)
text, n_intel = re.subn(r'(intel:\s*)"[0-9a-f]{64}"', rf'\g<1>"{x86_mac_sha}"', text, count=1)
if n_arm != 1 or n_intel != 1:
    print(f"expected one arm + one intel sha256 in the cask, found {n_arm}/{n_intel} - not auto-updating", file=sys.stderr)
    sys.exit(1)

with open(path, 'w') as f:
    f.write(text)
print("cask updated")
PYEOF

echo; echo "── verifying with brew style ──"
# Report-only: brew style exits non-zero even for purely cosmetic, autocorrectable findings
# (e.g. the Sorbet-sigil suggestions this formula doesn't need), which — under set -e above —
# would abort the script BEFORE it reaches the tap step. A real structural break (the kind that
# would fail `brew install`) is still caught by the "expected 3 sha256 lines" guard above, which
# hard-exits.
brew style "$FORMULA" "$CASK" || true

# ── --push: commit through the GitHub API so the commits are GitHub-signed ───────────────────
# The tap requires signed commits. Commits created via the contents API are signed with GitHub's
# own key and land Verified, so CI can update the tap without ever holding a signing key. This is
# what turns "someone remembers to run this script" into a step of the release pipeline.
if [ "$PUSH" = "1" ]; then
  : "${GH_TOKEN:=${TAP_TOKEN:-}}"
  export GH_TOKEN
  if [ -z "${GH_TOKEN:-}" ]; then
    echo "--push needs GH_TOKEN (or TAP_TOKEN) with Contents: read+write on $TAP_REPO" >&2
    exit 2
  fi

  BRANCH="nthpartyfinder-${VERSION}"
  DEFAULT_BRANCH="$(gh api "repos/${TAP_REPO}" -q .default_branch)"
  BASE_SHA="$(gh api "repos/${TAP_REPO}/git/ref/heads/${DEFAULT_BRANCH}" -q .object.sha)"

  # Reuse the branch if a previous attempt created it; a re-run must be safe.
  if ! gh api "repos/${TAP_REPO}/git/ref/heads/${BRANCH}" >/dev/null 2>&1; then
    gh api "repos/${TAP_REPO}/git/refs" -X POST \
      -f ref="refs/heads/${BRANCH}" -f sha="${BASE_SHA}" >/dev/null
  fi

  put_file() {
    local src="$1" dest="$2" message="$3" sha_arg=()
    local existing
    existing="$(gh api "repos/${TAP_REPO}/contents/${dest}?ref=${BRANCH}" -q .sha 2>/dev/null || true)"
    [ -n "$existing" ] && sha_arg=(-f sha="$existing")
    gh api "repos/${TAP_REPO}/contents/${dest}" -X PUT \
      -f message="$message" \
      -f branch="$BRANCH" \
      -f content="$(base64 < "$src" | tr -d '\n')" \
      "${sha_arg[@]}" >/dev/null
  }

  echo; echo "Pushing formula + cask to ${TAP_REPO}@${BRANCH} via the GitHub API (signed by GitHub)..."
  put_file "$FORMULA" "Formula/nthpartyfinder.rb" "nthpartyfinder ${VERSION} (formula)"
  put_file "$CASK"    "Casks/nthpartyfinder.rb"   "nthpartyfinder ${VERSION} (cask)"

  if gh pr list --repo "$TAP_REPO" --head "$BRANCH" --state open --json number -q '.[0].number' | grep -q .; then
    echo "PR already open for ${BRANCH}."
  else
    gh pr create --repo "$TAP_REPO" --head "$BRANCH" --base "$DEFAULT_BRANCH" \
      --title "nthpartyfinder ${VERSION}" \
      --body "Automated sync from ${REPO}@${TAG}. Formula + cask updated to ${VERSION} with checksums taken from the published release artifacts."
  fi
  echo "Done. SQUASH-merge the PR once the tap's test-bot is green (squash gives the"
  echo "GitHub-signed commit that required_signatures needs; a merge commit would not)."
  exit 0
fi

if gh repo view "$TAP_REPO" >/dev/null 2>&1; then
  echo; echo "Staging formula on a release branch in $TAP_REPO..."
  TMPDIR="$(mktemp -d)"
  trap 'rm -rf "$TMPDIR"' EXIT
  gh repo clone "$TAP_REPO" "$TMPDIR" -- -q
  BRANCH="nthpartyfinder-${VERSION}"
  git -C "$TMPDIR" checkout -q -B "$BRANCH" origin/main
  mkdir -p "$TMPDIR/Formula"
  cp "$FORMULA" "$TMPDIR/Formula/nthpartyfinder.rb"
  git -C "$TMPDIR" add Formula/nthpartyfinder.rb
  if git -C "$TMPDIR" diff --cached --quiet; then
    echo "Tap formula already up to date — nothing to stage."
  else
    cat <<EOS

Staged on branch '$BRANCH' in $TMPDIR (clone of $TAP_REPO).

The tap enforces required_signatures, so an unsigned push is rejected. Create the commit
with the maintainer's GitHub-verified key, then open/merge the PR — for example:

  cd "$TMPDIR"
  git -c user.name="p4gs" -c user.email="10093271+p4gs@users.noreply.github.com" \\
      -c gpg.format=ssh -c user.signingkey=~/.ssh/git_signing_key.pub \\
      -c commit.gpgsign=true commit -S -m "nthpartyfinder ${VERSION}"
  git push -u origin "$BRANCH"
  gh pr create --repo $TAP_REPO --head "$BRANCH" --title "nthpartyfinder ${VERSION}" --fill

After test-bot goes green, merge the PR. Then:
  brew install ${TAP_REPO#grcengineering/homebrew-}/nthpartyfinder   # macOS + Linux
EOS
    # Keep the staged clone for the maintainer to sign; don't auto-clean it.
    trap - EXIT
  fi
else
  echo; echo "Tap repo $TAP_REPO not found/accessible — formula updated locally only."
  echo "Create the tap repo, then re-run this script to stage it."
fi
