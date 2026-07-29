#!/usr/bin/env bash
# Post an automated review on a pull request.
#
# Usage: claude_review.sh <fast|deep>
#
# Requires ANTHROPIC_API_KEY, GH_TOKEN, PR_NUMBER, REPO in the environment. The
# caller (claude-review.yml) gates on the API key being present, so reaching this
# script without one is a bug, not a normal path — hence the hard check below.
#
# The prompts are the point of this file. Two things carry them:
#
#   1. They forbid pre-filtering. Current models follow "only report high-severity
#      issues" literally: they investigate just as thoroughly, find the bugs, then
#      decline to report what they judge below the bar. Precision rises and measured
#      recall falls, which reads as a capability regression but is a prompt bug.
#      Ask for everything and filter downstream.
#   2. They name the defect classes that actually reach main in a repo of markdown
#      that instructs a model, rather than asking for generic "code review".

set -euo pipefail

TIER="${1:?usage: claude_review.sh <fast|deep>}"

: "${ANTHROPIC_API_KEY:?ANTHROPIC_API_KEY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${PR_NUMBER:?PR_NUMBER is required}"
: "${REPO:?REPO is required}"

case "$TIER" in
  fast) EFFORT="low" ;;
  deep) EFFORT="xhigh" ;;
  *)
    echo "unknown tier: $TIER (expected fast or deep)" >&2
    exit 2
    ;;
esac

# Shared across both tiers. Written to a file rather than interpolated into a
# command line: PR metadata is untrusted text and must never reach a shell.
COMMON_PROMPT=$(
  cat <<'PROMPT'
Report every issue you find, at every severity. Do not pre-filter, do not suppress
low-confidence findings, and do not decide something is too minor to mention. Rank
each finding P1 to P4 and let a human filter. A finding you withheld is worth
nothing; a P4 that turns out not to matter costs one line.

For each finding give: file:line, one sentence on the defect, and a concrete failure
scenario — the input or state that produces the wrong behaviour. If you cannot state
a failure scenario, say so and rank it lower.

This repository is a marketplace of Claude Code plugins. Most content is markdown
that instructs a model, so "does this text cause correct behaviour" matters as much
as code correctness. Weight these classes especially, because each has reached main
in repositories like this one and none is visible on a casual read:

1. Verifiers that pass without verifying. A script, grader, or checklist that
   reports success while inspecting nothing. Real examples: a validator using
   `grep -oP` (unsupported by BSD grep) with stderr sent to /dev/null, so it always
   printed "valid"; a grader that judged the response text, so a run that skipped
   the real work still passed; a citation gate that only validated citations that
   were present, so zero citations passed. For any check in the diff, ask what it
   does when it finds nothing, and whether that is distinguishable from success.
2. Agent wiring. `subagent_type` must be `<plugin>:<agent>`; a bare name is
   unregistered and the dispatch fails at runtime. Agent frontmatter declares tools
   with `tools:`, skills with `allowed-tools:` — the keys are inverted between the
   two file types and the wrong one is silently ignored, so the restriction simply
   does not apply.
3. Generated artifacts. Skills that emit HTML must escape anything derived from the
   target codebase before it reaches innerHTML; these artifacts ship to clients and
   the codebase under audit is untrusted input. Flag external CDN or script loads in
   anything described as self-contained.
4. Instructions that cannot work as written. Documented commands that exceed a rate
   limit, reference a skill or binary that is not installed, or depend on a path with
   no stated provenance. Check the numbers when a doc claims a cost or a limit.
5. Silent truncation. Degraded output that is indistinguishable from a clean empty
   result in the artifact a human actually reads, especially when the warning goes
   only to stderr.

Say plainly when a dimension is clean rather than manufacturing a finding to look
thorough. If the diff is small or purely editorial, a short review is correct output.
PROMPT
)

if [ "$TIER" = "fast" ]; then
  PROMPT=$(
    cat <<'PROMPT'
Review pull request #__PR__ in __REPO__ against the diff with the base branch.

When you are done you MUST post your review with:

    gh pr comment __PR__ --body-file - --edit-last --create-if-none <<'EOF'
    ...your review...
    EOF

Nothing you write outside that comment is visible to anyone. A run that finishes
without posting shows up as a green check with no review attached, which reads as
"reviewed and clean" — the worst possible outcome. Post even when you found nothing,
and say so.

Read from stdin, not a temp file: you have no Write tool and no general Bash, so
there is nowhere to put one.

`--edit-last --create-if-none` replaces your previous review rather than appending.
This job runs on every push, so appending would leave a reader scrolling past stale
findings from commits that were fixed several pushes ago.

__COMMON__
PROMPT
  )
  ALLOWED_TOOLS='Bash(gh pr comment:*),Bash(gh pr diff:*),Bash(gh pr view:*),Read,Grep,Glob'
else
  PROMPT=$(
    cat <<'PROMPT'
Perform a deep adversarial review of pull request #__PR__ in __REPO__.

When you are done you MUST post your review with:

    gh pr comment __PR__ --body-file - <<'EOF'
    ...your review...
    EOF

Nothing you write outside that comment reaches anyone.

Go beyond the diff where the diff depends on it: read the files it touches, read the
scripts it adds, and check its claims against the repository rather than taking them
at face value. When the PR states a number, a limit, or a cost, verify it against the
files — count the things it claims to count. When it adds a check, work out by reading
it what input would slip past, and say so.

You cannot execute anything: your tools are `gh pr` reads, `git log`, `git diff`,
`Read`, `Grep`, and `Glob`. Do not plan around running code.

Prioritise, in order: anything that makes the plugin fail to run at all; anything
that produces a wrong result while reporting success; anything that puts untrusted
content into an artifact shared outside the company; and anything whose documented
usage does not work as written.

__COMMON__

Finish with an explicit list of what you checked and found clean, so a reader can
tell the difference between a dimension you cleared and one you never looked at.
PROMPT
  )
  ALLOWED_TOOLS='Bash(gh pr comment:*),Bash(gh pr diff:*),Bash(gh pr view:*),Bash(git log:*),Bash(git diff:*),Read,Grep,Glob'
fi

# Substituted here rather than interpolated inside the heredocs. Both tier
# heredocs are quoted so that backticks and $(...) in the prompt text are literal
# rather than commands the shell runs while building the prompt.
PROMPT="${PROMPT//__COMMON__/$COMMON_PROMPT}"
PROMPT="${PROMPT//__PR__/$PR_NUMBER}"
PROMPT="${PROMPT//__REPO__/$REPO}"

PROMPT_FILE="$(mktemp)"
trap 'rm -f "$PROMPT_FILE"' EXIT
printf '%s\n' "$PROMPT" >"$PROMPT_FILE"

# Timestamp before the run so we can tell a review that was posted from one that
# was not. Without this the script has the exact defect its own prompt hunts: if the
# model finishes without calling `gh pr comment` — a denied tool, a hit timeout, or
# it simply summarises instead of posting — `claude` exits 0, the job goes green, and
# a reader sees a passing "Claude review" check and infers the diff was reviewed.
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "Running $TIER review (effort=$EFFORT) on $REPO#$PR_NUMBER"
claude --print \
  --effort "$EFFORT" \
  --allowedTools "$ALLOWED_TOOLS" \
  <"$PROMPT_FILE"

posted="$(
  gh api "repos/${REPO}/issues/${PR_NUMBER}/comments" \
    --jq "[.[] | select(.created_at >= \"${STARTED_AT}\" or .updated_at >= \"${STARTED_AT}\")] | length"
)"

if [ "${posted:-0}" -eq 0 ]; then
  echo "ERROR: the review run finished without posting a comment." >&2
  echo "A green check with no review attached reads as 'reviewed and clean'," >&2
  echo "which is worse than no check at all. Failing instead." >&2
  exit 1
fi

echo "Review posted ($posted comment(s) created or updated since $STARTED_AT)."
