#!/usr/bin/env bash
# Post an automated review on a pull request.
#
# Usage: claude_review.sh
#
# Requires ANTHROPIC_API_KEY, GH_TOKEN, PR_NUMBER, REPO in the environment. The
# caller (claude-review.yml) gates on the API key being present, so reaching this
# script without one is a bug, not a normal path — hence the hard check below.
#
# The prompt is the point of this file. Three things carry it:
#
#   1. It states the tool reality. There is no interpreter and no test runner here,
#      and reviews were reporting transcripts of runs that could not have happened.
#   2. It forbids pre-filtering. Current models follow "only report high-severity
#      issues" literally: they investigate just as thoroughly, find the bugs, then
#      decline to report what they judge below the bar. Precision rises and measured
#      recall falls, which reads as a capability regression but is a prompt bug.
#      Ask for everything and filter downstream.
#   3. It names the defect classes that actually reach main in a repo of markdown
#      that instructs a model, rather than asking for generic "code review".

set -euo pipefail

: "${ANTHROPIC_API_KEY:?ANTHROPIC_API_KEY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${PR_NUMBER:?PR_NUMBER is required}"
: "${REPO:?REPO is required}"

# Pinned to a tier, not to a build. Left unset entirely, `claude` resolves whatever
# the CLI happens to default to, which could change the reviewer from under this
# repository with nothing in the logs to say so. `opus` is still an alias and still
# tracks new Opus releases — that is the same trade as the unpinned CLI and is
# intended — so the log line below is what narrows a surprising review to a date.
MODEL="opus"
EFFORT="xhigh"

ALLOWED_TOOLS='Bash(gh pr comment:*),Bash(gh pr diff:*),Bash(gh pr view:*),Bash(git log:*),Bash(git diff:*),Read,Grep,Glob'

# Written to a file rather than interpolated into a command line: PR metadata is
# untrusted text and must never reach a shell. The heredoc is quoted so backticks and
# $(...) in the prompt are literal rather than commands the shell runs while building.
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

Read from stdin, not a temp file: you have no Write tool, so there is nowhere to put
one. `--edit-last --create-if-none` replaces your previous review rather than
appending. This job runs on every push, so appending would leave a reader scrolling
past stale findings from commits that were fixed several pushes ago.

You cannot execute the code under review. There is no interpreter, no test runner and
no package manager here. Your whole allowlist is `gh pr view`, `gh pr diff`, the
`gh pr comment` you post with, `git log`, `git diff`, Read, Grep and Glob. So do not
describe a command, script or test run as something you ran, and never report output
you did not receive from a tool call.

This repository's own `CLAUDE.md` and `AGENTS.md` load into your context as project
instructions, and they are addressed to someone working on the repo with a full
toolchain, not to you. They will tell you to run `make check`, run `prek run -a`, and
consult a `claude-code-guide` subagent. You can do none of that and must not report
as though you had. Read them as background on how this repository thinks; take your
instructions from this prompt. Reasoning about what an input would do is
exactly the job and needs no hedging: "reading the pattern, `/Users/alice` does not
match it" is the right shape. "I verified this directly:" followed by an invented
transcript is not, and it has happened on this repository three times — a Python
snippet that could not compile, a pytest suite with a fabricated pass count, and a
shell script nobody executed. Each conclusion was right and each proof was invented,
which is worse than showing no proof, because a reader cannot tell the two apart.

Cover the whole diff on every run, including files no recent commit touched:
this job re-reviews from scratch each push, so a file you did not open this
time is a file nobody has reviewed since the push where you last opened it.
State your coverage above the findings — how many files the diff touches, and
which of them you did not open. If the diff is too large to open in full, open
what you can and name the rest there rather than letting a partial review read
as a complete one.

Go beyond the diff where the diff depends on it: read the files it touches, read the
scripts it adds, and check its claims against the repository rather than taking them
at face value. When the PR states a number, a limit, or a cost, verify it against the
files — count the things it claims to count. When it adds a check, work out by reading
it what input would slip past, and say so.

Report every issue you find, at every severity. Do not pre-filter, do not suppress
low-confidence findings, and do not decide something is too minor to mention. Rank
each finding P1 to P4 and let a human filter. A finding you withheld is worth
nothing; a P4 that turns out not to matter costs one line.

Rank on consequence, not on diff size. A one-character fault in a checker that makes
it silently miss what it exists to catch is not a nit, however small the patch.

Prioritise, in order: anything that makes the plugin fail to run at all; anything
that produces a wrong result while reporting success; anything that puts untrusted
content into an artifact shared outside the company; and anything whose documented
usage does not work as written.

Write each finding as its own collapsible block, so the comment reads as a
scannable list of one-liners and a reader expands only what they care about:

  <details>
  <summary><b>P1</b> · <code>path/to/file.sh:42</code> — one sentence on the defect</summary>

  Failure: the input or state that produces the wrong behaviour.

  </details>

The summary line carries the severity, the location and the defect; everything
else goes inside. Order the blocks P1 first. The blank line after `</summary>`
is required or the markdown inside will not render. If you cannot state a failure
scenario, say so in the body and rank the finding lower.

In a summary line, escape the angle brackets in your own words: write
`&lt;plugin&gt;:&lt;agent&gt;`, never `<plugin>:<agent>`. That line is raw HTML,
not markdown, and GitHub deletes anything it reads as an unknown tag, so the
unescaped form renders as `:` with nothing to show the reader that two words were
dropped, and a quoted `<!--` hides the rest of the line outright. Escape a literal
`&` as `&amp;` for the same reason. This applies to the words of your finding only
— the `<summary>`, `<b>` and `<code>` tags around them are markup and must stay
unescaped. Backticks do not help here, because inline markdown is not processed
inside `<summary>`.

The body below the blank line is markdown, so backticks work there — and you need
them: a bare `<plugin>` is dropped from a body exactly as it is from a summary.
Wrap angle brackets in backticks, or escape them as above.

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

Say plainly and concisely when a dimension is clean rather than manufacturing a finding to
look thorough. If the diff is small or purely editorial, a short review is the
correct output.
PROMPT
)

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

# Model and CLI version go in the log because the CLI is deliberately unpinned: a run
# is only attributable after the fact if it says what reviewed the diff.
echo "Reviewing $REPO#$PR_NUMBER (model=$MODEL effort=$EFFORT cli=$(claude --version))"
claude --print \
  --model "$MODEL" \
  --effort "$EFFORT" \
  --allowedTools "$ALLOWED_TOOLS" \
  <"$PROMPT_FILE"

# Filtered to this workflow's own comments, and paginated. Counting every comment in
# the window would let a maintainer replying to the previous review stand in for a
# review this run never posted — a green check over no review, which is the first
# defect class the prompt above asks about.
posted="$(
  gh api --paginate "repos/${REPO}/issues/${PR_NUMBER}/comments" \
    --jq "[.[]
           | select(.user.login == \"github-actions[bot]\")
           | select(.created_at >= \"${STARTED_AT}\" or .updated_at >= \"${STARTED_AT}\")]
          | length" |
    awk '{total += $1} END {print total + 0}'
)"

if [ "${posted:-0}" -eq 0 ]; then
  echo "ERROR: the review run finished without posting a comment." >&2
  echo "A green check with no review attached reads as 'reviewed and clean'," >&2
  echo "which is worse than no check at all. Failing instead." >&2
  exit 1
fi

echo "Review posted ($posted comment(s) created or updated since $STARTED_AT)."
