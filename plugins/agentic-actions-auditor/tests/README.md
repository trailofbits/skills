# Measuring what this skill is for

The question this harness answers is whether the skill has anything to add over
[zizmor](https://github.com/zizmorcore/zizmor), a mature static analyser for GitHub
Actions. A finding zizmor already reports is not evidence that loading a skill was
worth it.

## Running it

```
pip install zizmor
python3 vectors.py            # signature self-test, 13 checks
node workflow_smoke.mjs       # drives the workflow with stubbed agents, 7 checks
python3 corpus.py 60          # collects into corpus/, needs gh auth
python3 measure.py            # the table below
python3 measure.py --fixtures # same, offline, against tests/fixtures
```

`workflow_smoke.mjs` exists because three of the workflow's four exits are refusals:
an unreadable target, a repository with no agent in it, and a sweep that found nothing.
Each has to be reachable and distinguishable, since a run that fell through to `ok` with
an empty report would read as a clean audit. It also checks that all four sweep families
are dispatched and that a family returning nothing is reported, so a vector class cannot
drop out of the audit while the report still reads as complete.

`measure.py` refuses to print anything if the signature self-test fails. A signature
that quietly stops matching would report a clean corpus forever.

## What it measured

60 workflows invoking `anthropics/claude-code-action`,
`google-github-actions/run-gemini-cli`, `openai/codex-action` or `actions/ai-inference`,
each pinned by content SHA.

zizmor covers the general surface heavily and the agent surface not at all:

| zizmor rule | findings | files | |
|---|---|---|---|
| `unpinned-uses` | 87 | 46 (76%) | hygiene |
| `artipacked` | 49 | 43 (71%) | hygiene |
| `template-injection` | 12 | 4 (6%) | |
| `github-app` | 11 | 11 (18%) | hygiene |
| no finding at all | | 8 (13%) | |

Findings and files are counted separately on purpose. zizmor reports `unpinned-uses` once
per unpinned step, so an earlier version of this table divided findings by file count and
printed 145%, which is the sort of number that should stop a reader rather than be read
past.

Of the six vectors with a static signature, three occur in this corpus:

| Vector | Workflows | |
|---|---|---|
| `F` subshell in tool allowlist | 16 (26%) | the most common by a wide margin |
| `B` direct expression injection | 2 (3%) | |
| `H` sandbox disabled | 1 | |
| `A`, `D`, `I` | 0 | |

Vectors C, E and G have no signature here on purpose, because deciding them needs the
meaning of a prompt or the behaviour of a downstream step.

The vectors are not independent. Both workflows carrying `B` also carry `F`, so 17
workflows hold at least one agent-specific vector rather than the 19 a naive sum gives.

**The two sets do not overlap.** All 12 `template-injection` findings point at `run:`
steps. Not one points at a prompt field. Neither of the two workflows where a
`github.event.*` expression reaches an agent prompt drew that rule: one drew nothing at
all, the other drew `unpinned-uses` and `github-app`, which are about pinning and token
choice rather than about the prompt. On a synthetic pair, the same split holds: a workflow with
expression-in-prompt and `pull_request_target` + head checkout draws 5 zizmor findings
including `template-injection` at high confidence, while one carrying only the env-var
intermediary, a subshell-capable allowlist, `Bash(*)` and a wildcard user allowlist
draws a single low-confidence `artipacked` that is about none of them.

## Reading it honestly

The corpus is 60 files drawn from GitHub code search ranking, which favours small
repositories copying the official template, so it is not a random sample of agentic CI.
The rare vectors being rare here is a statement about this sample.

Absence of a signature is not absence of a vector. The `A` signature wants an `env:`
entry holding `github.event.*` whose name then appears in the prompt; a workflow routing
the same data through `steps.*.outputs` slips past it. Treat the counts as a floor.

Two signatures have already been wrong here, and both times the wrong number looked
plausible enough to build on.

An earlier and looser version of `B` scanned 800 characters after `prompt:` and reported
7 rather than 2, counting expressions in `run:` steps as prompt injection. Scoping it to
the prompt's own block scalar is what dropped it.

`F` reported **0** until it was keyed on the fields the actions actually take. It had
been looking for an `allowed_tools:` input, which `claude-code-action` carried in v0.0.32
and dropped by v0.1.0, and which the vector-f reference never named: that reference says
`claude_args` with `--allowedTools` for Claude Code Action and `settings` with `coreTools`
for Gemini CLI. Corrected, `F` is 16 of 60 and the most common vector in the corpus. A
signature keyed on a field that does not exist reports a clean corpus forever, which is
the failure this file's self-test exists to prevent and did not catch, because the
fixture had been written against the same wrong field.

## Why the corpus is not committed

`corpus/` is gitignored. Shipping a third party's exploitable workflow as a test fixture
publishes a list of live targets. The corpus produces aggregate counts with no
repository named; every fixture under `fixtures/` is written by hand.
