#!/usr/bin/env bash
set -euo pipefail

git -c init.defaultBranch=main init -q
git config user.name "PPV Eval"
git config user.email "ppv-eval@example.invalid"

cat >renderer.py <<'PY'
def render(value: str) -> str:
    return value
PY

git add renderer.py
GIT_AUTHOR_DATE="2026-01-01T00:00:00Z" GIT_COMMITTER_DATE="2026-01-01T00:00:00Z" \
  git -c commit.gpgsign=false commit -q -m "vulnerable renderer"
git tag vulnerable

cat >renderer.py <<'PY'
def render(value: str) -> str:
    return value.replace("<", "&lt;").strip()
PY

git add renderer.py
GIT_AUTHOR_DATE="2026-01-02T00:00:00Z" GIT_COMMITTER_DATE="2026-01-02T00:00:00Z" \
  git -c commit.gpgsign=false commit -q -m "escape markup"
