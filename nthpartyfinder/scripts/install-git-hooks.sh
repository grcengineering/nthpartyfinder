#!/usr/bin/env bash
# Install the repo's git hooks. Run once after cloning:
#   nthpartyfinder/scripts/install-git-hooks.sh
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_SRC="$REPO_ROOT/nthpartyfinder/scripts/pre-push.sh"
HOOK_DST="$REPO_ROOT/.git/hooks/pre-push"

chmod +x "$HOOK_SRC"
ln -sf "$HOOK_SRC" "$HOOK_DST"
echo "✔ Installed pre-push hook: $HOOK_DST -> $HOOK_SRC"
echo "  It runs fmt + clippy(-D warnings) + cargo-deny + gitleaks before every push."
