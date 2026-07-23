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
# The tap is a single FORMULA — no cask. A browser (Chrome/Chromium/Edge) is not a formula
# dependency: Homebrew formulae cannot depend on a cask, and shipping a cask would break
# `brew install --cask` on machines that already have Chrome and would not work on Linux.
# nthpartyfinder installs a browser at runtime instead (see the binary's --install-browser
# flag), so `brew install nthpartyfinder` is the single, cross-platform install path.
#
# NOTE ON SIGNING: the tap enforces `required_signatures`, so this script does NOT push an
# (unsigned) commit — that push is rejected. It stages the formula on a release branch and
# prints the exact signed-commit command to run with the maintainer's verified key.
set -euo pipefail

TAG="${1:?usage: sync-homebrew-formula.sh <tag> [tap-repo]}"
VERSION="${TAG#v}"
TAP_REPO="${2:-grcengineering/homebrew-grcengineering}"
REPO="grcengineering/nthpartyfinder"
FORMULA="$(dirname "$0")/../packaging/homebrew/nthpartyfinder.rb"

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

echo; echo "── verifying with brew style ──"
# Report-only: brew style exits non-zero even for purely cosmetic, autocorrectable findings
# (e.g. the Sorbet-sigil suggestions this formula doesn't need), which — under set -e above —
# would abort the script BEFORE it reaches the tap step. A real structural break (the kind that
# would fail `brew install`) is still caught by the "expected 3 sha256 lines" guard above, which
# hard-exits.
brew style "$FORMULA" || true

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
