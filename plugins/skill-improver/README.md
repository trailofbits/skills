# Skill Improver Plugin

Improves a Claude Code skill through an autonomous review→fix loop,
`/skill-improver:improve` — a dynamic workflow that dispatches the plugin's own
reviewer and fixer agents until a review comes back with zero critical/major
findings, then strips its own residue and exits.

## Usage

Natural language ("fix my skill", "improve this skill until it passes review") or the
skill directly:

```
/skill-improver ./plugins/my-plugin/skills/my-skill
/skill-improver my-skill --max-rounds 3
```

The session resolves the path and starts the workflow in the background. Stop it at any
time by stopping the workflow task; every round persists its state first.

## What the loop guarantees

Each of these exists because a manually-run review/fix loop was observed failing without
it:

- **Completion means a clean review.** The loop can only end on a review with zero
  blocking findings. At the round cap it runs one final review-only round and, if that
  is not clean, exits loudly with **capped, NOT converged** and the open-findings list —
  never an unreviewed fix presented as done.
- **A findings ledger is the cross-round memory.** Every finding gets a stable id and
  one verdict (`fixed` / `rejected: reason` / `deferred`). Reviewers verify fixes instead
  of trusting them, and may not re-file a rejected finding without new evidence. The
  ledger is written to disk every round (`.skill-improver/<skill>/ledger.json`), so an
  interrupted or escalated run continues without re-deriving anything.
- **Oscillation escalates instead of looping.** Non-decreasing blocking counts over
  three rounds, the same finding open three consecutive rounds, or a finding "fixed"
  twice all stop the loop with a structural-escalation report. Continuing is a fresh run
  carrying the user's decision (`decision` arg) plus the reloaded ledger.
- **A mechanical scope guard runs after every fix round.** `git diff` against the
  baseline snapshot, matched against the declared scope globs: any out-of-scope change
  halts the loop on the spot. Completion additionally requires no unregistered new files
  in scope. The fixer contract bans `git checkout --` / `git stash` / `git reset` /
  `git commit` outright.
- **Fixes carry pins and the next review verifies them.** Behavior-changing fixes need a
  test that fails against the pre-fix code; nothing self-verifies.
- **A finalize pass removes loop residue.** Session narration is stripped, version churn
  collapses to exactly one bump, and a docs-match-code pass runs before completion.

## Requirements

- **Claude Code with dynamic-workflow support** — the loop is a workflow script; under
  Codex the plugin's skills load but the loop is unavailable.
- **A git repository.** The scope guard and fix verification diff against a baseline
  commit. If the target is not in a repository, the run initializes one (with an
  explicit `skill-improver-baseline` identity) and says so loudly.

## Artifacts

Each run writes to `.skill-improver/<skill-name>/` in the working directory:

| File | Contents |
|---|---|
| `ledger.json` | Findings, verdicts, rounds, and the run result — the loop's memory |
| `ledger.md` / `status.md` | Human-readable summary |
| `fixes-round-N.diff` | Cumulative diff after each fix round |
| `metrics.json` | Machine-countable run metrics from `scripts/collect_metrics.py` |

Nothing is committed; all changes stay in the working tree for you to review.

## Layout

```
workflows/improve.js      # the loop: ledger, oscillation detectors, scope guard, cap semantics
agents/reviewer.md        # read-only reviewer: severities, ledger discipline, report-everything
agents/fixer.md           # fixer contract: verdicts, pins, git safety, no narration
scripts/collect_metrics.py# metrics.json producer; fails on missing/zero artifacts
skills/skill-improver/    # entry point: resolve path, invoke workflow, relay outcome
tests/                    # offline harness for the loop logic + mutation self-test
evals/                    # paid `claude plugin eval` cases (see evals/README.md)
```

## Troubleshooting

- **"escalation" result** — the loop decided iteration cannot resolve the findings.
  Decide the design question it names, then re-run with your ruling; the ledger carries
  everything forward.
- **"capped, NOT converged"** — raise `--max-rounds`, or fix the listed findings
  manually; a re-run reloads the ledger.
- **Scope violation halt** — inspect the named paths, revert or widen `scope`, re-run.
- **No metrics.json** — the run could not find `scripts/collect_metrics.py`; pass
  `pluginRoot` (the skill does this automatically when `${CLAUDE_PLUGIN_ROOT}` is
  substituted).
