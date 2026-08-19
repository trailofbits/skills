#!/usr/bin/env bash
# Fetch gradio at a pinned commit and inject the eval's vulnerabilities.
#
# The codebase is NOT vendored: it is ~283 MB with 772 Python files, which is the
# point — the eval needs a codebase large enough that a single linear read cannot
# hold it. Only the patch and the ground truth live in this repo.
#
# The SHA is pinned because ground truth records absolute line numbers. Track main
# and the patch stops applying, the line numbers drift, and the eval silently
# grades against the wrong code.
#
# Usage:
#   ./setup-gradio.sh            # fetch into ./work/gradio (idempotent)
#   ./setup-gradio.sh --force    # discard and re-fetch
#   ./setup-gradio.sh --clean    # delete the checkout

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="https://github.com/gradio-app/gradio.git"
SHA="45c11d52e518a59ffaf1d688e13ceaafd7f1477c"
DEST="$TESTS_DIR/work/gradio"
PATCH="$TESTS_DIR/gradio-vulns.patch"

FORCE=0
case "${1:-}" in
  --force) FORCE=1 ;;
  --clean)
    rm -rf "$TESTS_DIR/work"
    echo "removed $TESTS_DIR/work"
    exit 0
    ;;
  "") ;;
  *)
    echo "unknown option: $1" >&2
    exit 2
    ;;
esac

if [ -d "$DEST/.git" ] && [ "$FORCE" -eq 0 ]; then
  if git -C "$DEST" diff --quiet --exit-code -- gradio/processing_utils.py 2>/dev/null; then
    echo "checkout exists but is unpatched; re-applying"
  else
    echo "gradio already present and patched at $DEST"
    exit 0
  fi
else
  rm -rf "$DEST"
  mkdir -p "$(dirname "$DEST")"
  echo "→ cloning gradio at ${SHA:0:12}"
  git clone -q --filter=blob:none --no-checkout "$REPO" "$DEST"
  git -C "$DEST" fetch -q --depth 1 origin "$SHA"
  git -C "$DEST" checkout -q FETCH_HEAD
fi

echo "→ applying vulnerability patch"
# Two different failures land here and the old message only named one of them: a checkout
# at the wrong SHA, and a checkout at the RIGHT SHA whose patch is already partly applied
# (the unpatched check above only looks at processing_utils.py, so a half-reverted tree
# reaches this point). --force is the recovery for both.
git -C "$DEST" apply --check "$PATCH" || {
  echo "patch does not apply to $DEST" >&2
  echo "  either the checkout is not at $SHA, or the patch is already partly applied." >&2
  echo "  recover with: $0 --force" >&2
  exit 1
}
git -C "$DEST" apply "$PATCH"

echo "→ verifying"
python3 "$TESTS_DIR/verify_fixtures.py"
