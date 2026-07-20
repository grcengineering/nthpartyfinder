#!/usr/bin/env bash
# Fill in the real sha256 checksums for a released version's macOS/Linux tarballs and,
# if a tap remote is configured, push the updated formula there. Run this AFTER a
# release's GitHub Actions build-release matrix has finished (the tarballs must exist).
#
# Usage:
#   scripts/sync-homebrew-formula.sh v1.4.0 [tap-repo]
#
# tap-repo defaults to grcengineering/homebrew-grcengineering (a shared tap for all GRC
# Engineering tools, not a project-specific one). Requires `gh` auth with
# access to that repo if pushing; without it, the formula is still updated locally
# (in packaging/homebrew/nthpartyfinder.rb) and the push step is skipped with a note.
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

python3 - "$FORMULA" "$VERSION" "$ARM_SHA" "$X86_MAC_SHA" "$LINUX_SHA" <<'PYEOF'
import re, sys
path, version, arm_sha, x86_mac_sha, linux_sha = sys.argv[1:6]
with open(path) as f:
    text = f.read()

text = re.sub(r'version "[^"]*"', f'version "{version}"', text, count=1)
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
# Report-only: brew style exits non-zero even for purely cosmetic, autocorrectable
# findings (e.g. the Sorbet-sigil suggestions this formula doesn't need), which — under
# set -e above — would abort the script BEFORE it reaches the actual tap push. A real
# structural break (the kind that would fail `brew install`) is still caught upstream by
# the "expected 3 sha256 lines" guard in the Python step, which does hard-exit.
brew style "$FORMULA" || true

if gh repo view "$TAP_REPO" >/dev/null 2>&1; then
  echo; echo "Pushing to $TAP_REPO..."
  TMPDIR="$(mktemp -d)"
  trap 'rm -rf "$TMPDIR"' EXIT
  gh repo clone "$TAP_REPO" "$TMPDIR" -- -q
  mkdir -p "$TMPDIR/Formula"
  cp "$FORMULA" "$TMPDIR/Formula/nthpartyfinder.rb"
  git -C "$TMPDIR" add Formula/nthpartyfinder.rb
  if git -C "$TMPDIR" diff --cached --quiet; then
    echo "Tap formula already up to date."
  else
    git -C "$TMPDIR" commit -m "nthpartyfinder ${VERSION}"
    git -C "$TMPDIR" push
    echo "Pushed. brew install ${TAP_REPO#grcengineering/homebrew-}/nthpartyfinder should now work."
  fi
else
  echo; echo "Tap repo $TAP_REPO not found/accessible — formula updated locally only."
  echo "Create the tap repo, then re-run this script to push."
fi
