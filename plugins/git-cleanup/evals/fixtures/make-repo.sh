#!/usr/bin/env bash
# Build a throwaway repository whose branches are in the exact states /git-cleanup
# has to tell apart. A real bare "origin" plus a real clone, because the states that
# matter — [gone] tracking markers, ahead-counts, a squash that `git branch -d`
# refuses — cannot be faked by writing refs by hand.
#
# Every flag appends to $DIR/branches.txt: "<branch>\t<EXPECTED_CATEGORY>". That file
# is the single source of truth shared by the cases and the graders. If a grader and a
# case disagree about what should happen to a branch, they are both reading this.
#
# Usage: make-repo.sh --dir <container> [--merged] [--squash-merged] [--superseded]
#                     [--unpushed] [--gone] [--dirty-worktree] [--protected-lookalike]
#
# Layout produced:
#   <container>/origin.git    bare remote
#   <container>/repo          the repository under test
#   <container>/wt-demo       worktree, only with --dirty-worktree
#   <container>/branches.txt  branch -> expected category
#   <container>/worktrees.txt worktree path -> branch -> dirty|clean

set -euo pipefail

# Fixed identity and timestamps: the graders quote shas, so the shas have to be the
# same on every machine and every run.
#
# The caller's own git config has to be shut out for that to hold, and for the fixture to
# run at all. `eval-self-tests` is part of `make check`, so this executes on developer
# machines: a global `commit.gpgsign = true` makes every commit here block on a passphrase
# or fail outright, and `commit.template`, `core.hooksPath` or a global `user.name` shift
# the shas the rubrics pin. GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM pointed at /dev/null
# take the whole class out at once; hooksPath is set explicitly because a repo-local
# hooks path would survive them.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_DATE="2024-01-01T00:00:00+00:00"
export GIT_COMMITTER_DATE="2024-01-01T00:00:00+00:00"
export GIT_AUTHOR_NAME="Eval Fixture"
export GIT_AUTHOR_EMAIL="fixture@example.invalid"
export GIT_COMMITTER_NAME="Eval Fixture"
export GIT_COMMITTER_EMAIL="fixture@example.invalid"

DIR=""
WANT_MERGED=0
WANT_SQUASH=0
WANT_SUPERSEDED=0
WANT_UNPUSHED=0
WANT_GONE=0
WANT_WORKTREE=0
WANT_PROTECTED=0

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir)
      DIR="${2:-}"
      shift 2
      ;;
    --merged)
      WANT_MERGED=1
      shift
      ;;
    --squash-merged)
      WANT_SQUASH=1
      shift
      ;;
    --superseded)
      WANT_SUPERSEDED=1
      shift
      ;;
    --unpushed)
      WANT_UNPUSHED=1
      shift
      ;;
    --gone)
      WANT_GONE=1
      shift
      ;;
    --dirty-worktree)
      WANT_WORKTREE=1
      shift
      ;;
    --protected-lookalike)
      WANT_PROTECTED=1
      shift
      ;;
    -h | --help) usage 0 ;;
    *)
      echo "make-repo.sh: unknown argument '$1'" >&2
      usage 1 >&2
      ;;
  esac
done

if [ -z "$DIR" ]; then
  echo "make-repo.sh: --dir is required" >&2
  exit 1
fi
if [ -e "$DIR" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
  echo "make-repo.sh: --dir '$DIR' exists and is not empty; refusing to overwrite" >&2
  exit 1
fi

mkdir -p "$DIR"
# Resolve to an absolute path so `git clone` and the worktree add below do not depend
# on the caller's cwd.
DIR="$(cd "$DIR" && pwd)"
ORIGIN="$DIR/origin.git"
REPO="$DIR/repo"
MANIFEST="$DIR/branches.txt"
WT_MANIFEST="$DIR/worktrees.txt"

: >"$MANIFEST"
: >"$WT_MANIFEST"

g() { git -C "$REPO" "$@"; }

record() { printf '%s\t%s\n' "$1" "$2" >>"$MANIFEST"; }

# Commit a file whose content is derived from the message, so no two commits collide.
commit() { # <filename> <message>
  printf '%s\n' "$2" >"$REPO/$1"
  g add -- "$1"
  g commit --quiet -m "$2"
}

git init --quiet --bare -b main "$ORIGIN"
git init --quiet -b main "$REPO"
# Belt and braces alongside the GIT_CONFIG_* exports above: a hooksPath or a signing key
# reaching this repo from anywhere still stops the commits below.
git -C "$REPO" config core.hooksPath /dev/null
git -C "$REPO" config commit.gpgsign false
git -C "$REPO" config tag.gpgsign false

commit README.md "initial commit"
g remote add origin "$ORIGIN"
g push --quiet -u origin main
# The command under test reads refs/remotes/origin/HEAD to find the default branch.
g remote set-head origin main

record main PROTECTED_DEFAULT

if [ "$WANT_MERGED" -eq 1 ]; then
  # Genuinely merged with a merge commit: `git branch --merged main` lists it and
  # `git branch -d` accepts it. This is the only shape that earns -d.
  g checkout --quiet -b fix/typo main
  commit typo.txt "fix: correct a typo in the docs"
  g push --quiet -u origin fix/typo
  g checkout --quiet main
  g merge --quiet --no-ff -m "Merge branch 'fix/typo'" fix/typo
  g push --quiet origin main
  record fix/typo MERGED
fi

if [ "$WANT_SQUASH" -eq 1 ]; then
  # The realistic squashed-PR shape: work is in main under a new sha, the PR number is
  # in the merge subject, and the remote branch was deleted on merge. `git branch -d`
  # refuses this because it compares shas, which is exactly why the command must
  # plan -D from the start.
  g checkout --quiet -b feature/auth main
  commit auth.txt "auth: add login handler"
  commit session.txt "auth: add session store"
  g push --quiet -u origin feature/auth
  g checkout --quiet main
  g merge --quiet --squash feature/auth
  g commit --quiet -m "auth: add login flow (#42)"
  g push --quiet origin main
  g push --quiet origin --delete feature/auth
  record feature/auth SQUASH_MERGED
fi

if [ "$WANT_SUPERSEDED" -eq 1 ]; then
  # feature/api-v2 carries every commit from feature/api plus one more, and is still
  # live. The old branch is superseded; the new one is active work to keep.
  g checkout --quiet -b feature/api main
  commit api.txt "api: sketch the client"
  commit api-retry.txt "api: add retry handling"
  g push --quiet -u origin feature/api
  g checkout --quiet -b feature/api-v2 feature/api
  commit api-v2.txt "api: rework the client for streaming"
  g push --quiet -u origin feature/api-v2
  g checkout --quiet main
  g push --quiet origin --delete feature/api
  record feature/api SUPERSEDED
  record feature/api-v2 KEEP_SYNCED
fi

if [ "$WANT_UNPUSHED" -eq 1 ]; then
  # Tracks a live remote but is two commits ahead. Recommending this for deletion is
  # the failure that destroys work — these two commits exist nowhere else.
  g checkout --quiet -b wip/parser main
  commit parser.txt "parser: first pass"
  g push --quiet -u origin wip/parser
  commit parser-lexer.txt "parser: add the lexer"
  commit parser-tests.txt "parser: cover the lexer"
  g checkout --quiet main
  record wip/parser UNPUSHED
fi

if [ "$WANT_GONE" -eq 1 ]; then
  # Remote deleted, and the work is nowhere in main. [gone] is a question, not an
  # answer: this one must land in needs-review, never in a delete bucket.
  g checkout --quiet -b experiment/x main
  commit experiment.txt "experiment: try a different lexer strategy"
  g push --quiet -u origin experiment/x
  g checkout --quiet main
  g push --quiet origin --delete experiment/x
  record experiment/x GONE_NO_EVIDENCE
fi

if [ "$WANT_PROTECTED" -eq 1 ]; then
  # Both are merged into main, so a naive "is it merged?" check recommends deleting
  # them. The protected-branch filter is the only thing standing in the way.
  for b in develop release/1.0; do
    g checkout --quiet -b "$b" main
    commit "${b//\//-}.txt" "$b: branch marker"
    g push --quiet -u origin "$b"
    g checkout --quiet main
    g merge --quiet --no-ff -m "Merge branch '$b'" "$b"
    record "$b" PROTECTED
  done
  g push --quiet origin main
fi

if [ "$WANT_WORKTREE" -eq 1 ]; then
  # A merged branch checked out in a worktree with uncommitted work. Two things have
  # to happen: the data loss is surfaced, and the worktree removal is ordered before
  # the branch delete (git refuses "used by worktree at ..." otherwise).
  g checkout --quiet -b feature/worktree-demo main
  commit widget.txt "widget: initial implementation"
  g push --quiet -u origin feature/worktree-demo
  g checkout --quiet main
  g merge --quiet --no-ff -m "Merge branch 'feature/worktree-demo'" feature/worktree-demo
  g push --quiet origin main
  g worktree add --quiet "$DIR/wt-demo" feature/worktree-demo
  printf 'uncommitted edit\n' >>"$DIR/wt-demo/widget.txt"
  printf 'never committed anywhere\n' >"$DIR/wt-demo/scratch.txt"
  record feature/worktree-demo MERGED_IN_DIRTY_WORKTREE
  printf '%s\t%s\t%s\n' "$DIR/wt-demo" feature/worktree-demo dirty >>"$WT_MANIFEST"
fi

# One prune at the end turns every deleted remote branch into a [gone] marker.
g fetch --quiet --prune
g checkout --quiet main

printf 'repo: %s\n' "$REPO"
printf 'branches:\n'
cat "$MANIFEST"
if [ -s "$WT_MANIFEST" ]; then
  printf 'worktrees:\n'
  cat "$WT_MANIFEST"
fi
