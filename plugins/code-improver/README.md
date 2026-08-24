# Code Improver Plugin

Improves a code target through an autonomous review→fix loop.
`/code-improver:improve` — a dynamic workflow that dispatches a **pluggable reviewer**
(any installed skill or agent) and the plugin's own fixer agent until a review comes
back with zero critical/major findings or the loop starts oscillating.

The plugin's final pass strips its own residue (loop narration, stale docs, version churn),
and is itself scope-checked and read for regressions before the run reports success.

## Usage

Three entry skills wire the loop to a target kind:

```
/code-improver:skill-improver ./plugins/my-plugin/skills/my-skill   # reviewer: plugin-dev:skill-reviewer agent
/code-improver:pr-improver main                                     # base branch; reviewer: pr-review-toolkit:review-pr skill
/code-improver:code-improver ./src --reviewer my-plugin:my-reviewer --scope 'src/**'
```

Natural language works too ("fix my skill", "clean up this branch until review
passes"). The session resolves the target and starts the workflow in the background.
Stop it at any time by stopping the workflow task; every round persists its state
first.

## What the loop guarantees

- **Completion means a clean review.** The loop can only end on a review with zero
  blocking findings. At the round cap it runs one final review-only round and, if that
  is not clean, exits loudly with **capped, NOT converged** and the open-findings list —
  never an unreviewed fix presented as done. The finalize pass edits the tree after that
  review, so its own edits are scope-checked and read for regressions too: a narration
  strip that rewrote legitimate content, a docs pass that made a statement false, or a
  version that is not exactly one increment exits with `halted: "finalize-regression"`
  rather than convergence.
- **A findings ledger is the cross-round memory.** Every finding gets a stable id and
  one verdict (`fixed` / `rejected: reason` / `deferred`). Reviewers verify fixes instead
  of trusting them, and may not re-file a rejected finding without new evidence. The
  ledger is written to disk every round (`.code-improver/<target>/ledger.json`), so an
  interrupted or escalated run continues without re-deriving anything.
- **Oscillation escalates instead of looping.** Non-decreasing blocking counts over
  three rounds, the same finding open three consecutive rounds, or a finding "fixed"
  twice all stop the loop with a structural-escalation report. Continuing is a fresh run
  carrying the user's decision (`decision` arg) plus the reloaded ledger.
- **A mechanical scope guard runs after every fix round and after finalize.** `git diff`
  against the baseline snapshot, matched against the declared scope globs: any
  out-of-scope change *inside the repository* halts the loop on the spot. `git diff`
  cannot see a file git does not track, so out-of-scope untracked files are guarded by
  content instead — the baseline hashes each one (up to 50; the rest are named in the
  run's notes as unguarded) and a hash that moved, a file that vanished, or a hash the
  check failed to report all count as violations. Completion additionally requires no
  unregistered new files in scope. The fixer contract bans `git checkout --` /
  `git stash` / `git reset` / `git commit` outright.
- **Fixes carry pins and the next review verifies them.** Behavior-changing fixes need a
  test that fails against the pre-fix code; nothing self-verifies.
- **A finalize pass removes loop residue, then answers for it.** Session narration is
  stripped, version churn collapses to exactly one bump (when the target sits inside a
  plugin — finalize is configurable per run), and a docs-match-code pass runs before
  completion. When a marketplace manifest repeats the plugin's version, the loop brings
  that file into scope and the one bump lands in both places — a `plugin.json` and a
  marketplace entry that disagree fail the repository's metadata validator. A check then
  reads every finalize edit and writes the run's final artifacts.
- **An unavailable reviewer halts, never improvises.** The loop probes the named
  reviewer and exits with `halted: "reviewer-unavailable"` and the install instruction
  when it does not resolve. An inline imitation of the review has none of the
  guarantees above, so the loop refuses to substitute one.
- **Reviewer skills that orchestrate specialists keep their specialists.** Workflow
  agents cannot spawn subagents, so the review wrapper returns the dispatches its skill
  prescribes and the loop executes them (up to 3 waves of 8 agents), feeding the
  reports back until the review finishes. A specialist that does not resolve halts the
  run like any missing reviewer; a failed one is reported to the merge, never dropped.

## Requirements

- **Claude Code with dynamic-workflow support** — the loop is a workflow script. Other
  clients (e.g. Codex) are not supported: the skills may still load through marketplace
  compatibility, but the loop is unavailable.
- **A reviewer.** The `skill-improver` entry needs the `plugin-dev` plugin
  (`claude-plugins-official` marketplace); `pr-improver`'s default needs
  `pr-review-toolkit`; the generic `code-improver` entry uses whatever skill or agent
  you name. A missing reviewer is a loud halt.
- **A git repository.** The scope guard and fix verification diff against a baseline
  commit. If the target is not in a repository, the run initializes one (with an
  explicit `code-improver-baseline` identity) and says so loudly.

## Artifacts

Each run writes to `.code-improver/<target-name>/` in the working directory:

| File | Contents |
|---|---|
| `ledger.json` | Findings, verdicts, rounds, and the run result — the loop's memory |
| `ledger.md` / `status.md` | Human-readable summary |
| `fixes-round-N.diff` | Cumulative diff after each fix round |
| `pre-finalize.diff` / `post-finalize.diff` | Cumulative diffs either side of the finalize pass — their difference is what finalize changed |
| `metrics.json` | Machine-countable run metrics from `scripts/collect_metrics.py` |

Nothing is committed; all changes stay in the working tree for you to review.

## Layout

```
workflows/improve.js      # the loop: ledger, reviewer dispatch, oscillation detectors, scope guard
agents/fixer.md           # fixer contract: verdicts, pins, git safety, no narration
scripts/collect_metrics.py# metrics.json producer; fails on missing/zero artifacts
skills/skill-improver/    # entry: skills, reviewed by plugin-dev:skill-reviewer
skills/pr-improver/       # entry: the current branch, scope from its diff
skills/code-improver/     # entry: any target, reviewer and scope named by the user
tests/                    # offline harness for the loop logic + mutation self-test
evals/                    # paid `claude plugin eval` cases (see evals/README.md)
```

## Troubleshooting

- **"escalation" result** — the loop decided iteration cannot resolve the findings.
  Decide the design question it names, then re-run with your ruling; the ledger carries
  everything forward.
- **"capped, NOT converged"** — raise `--max-rounds`, or fix the listed findings
  manually; a re-run reloads the ledger.
- **"reviewer-unavailable" halt** — install the plugin providing the named reviewer
  (see Requirements), then re-run; nothing was reviewed or edited.
- **Scope violation halt** — inspect the named paths, revert or widen `scope`, re-run.
- **"finalize-regression" halt** — the finalize pass rewrote something it should not
  have. `finalize_regressions` names each site; `diff -u pre-finalize.diff
  post-finalize.diff` shows the whole pass. Revert the named sites, or re-run with
  `finalize: {"narration_strip": false}` / `{"docs_pass": false}` to skip the pass that
  overreached. The review-and-fix work is already on disk; nothing is lost.
- **No metrics.json** — the run could not find `scripts/collect_metrics.py`; pass
  `pluginRoot` (the skill does this automatically when `${CLAUDE_PLUGIN_ROOT}` is
  substituted).
