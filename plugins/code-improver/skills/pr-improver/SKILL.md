---
name: pr-improver
description: "Runs an autonomous review-and-fix improvement loop over the current branch's changes until a PR review comes back clean, scoped mechanically to the directories the branch touched. Reviews are performed by an installed PR-review skill (default: pr-review-toolkit's review-pr). Use to fix review findings on a branch before opening or updating a pull request ('clean up this branch', 'fix this PR until review passes', 'run review-and-fix on my changes'). NOT for a one-time review — run the PR-review skill directly."
argument-hint: "[BASE_BRANCH] [--reviewer <skill-or-agent>] [--max-rounds N]"
allowed-tools: Bash Glob Read TaskOutput TaskStop Workflow
---

# PR Improver

Improve the current branch by running `/code-improver:improve` — a dynamic workflow that
loops a PR reviewer and a fixer subagent over the branch's changes until a review
reports zero critical/major findings. The loop, its ledger, and its guards live in the
workflow; this skill derives the scope from the branch diff and relays the outcome.

## Starting the loop

The user provided: `$ARGUMENTS` (if empty, take base branch and preferences from the
conversation).

### 1. Resolve the branch and its change surface

1. Repo root: `git rev-parse --show-toplevel`. Fail loudly outside a repository.
2. Base: the argument if given, else the repository's default branch
   (`git symbolic-ref refs/remotes/origin/HEAD` → its short name, falling back to
   `main`). Refuse to run when the current branch IS the base — there is no diff to
   improve.
3. Changed files: `git diff --name-only <base>...HEAD`. If empty, say so and stop.
4. Scope: the changed files' **directories**, widened — per-file globs are too tight
   (PR fixes legitimately add tests next to changed code). Map each changed file to its
   repo-relative directory glob `<dir>/**` (`**` at the repo root only if files at the
   root changed), then deduplicate and drop globs covered by another.

### 2. Resolve the loop script

The loop is the dynamic workflow `workflows/improve.js` in this plugin. Launch it by
path: `scriptPath` takes a resolved absolute path, and the Workflow tool's `name` resolves
built-in and project workflows, so a marketplace-installed one may not answer to
`code-improver:improve`. Try in order, first hit wins — the home directories come before
`.` so an installed copy beats a checkout of this marketplace:

1. `Bash: ls -d -- "${CLAUDE_PLUGIN_ROOT}/workflows/improve.js"`
2. `Bash: ls -d -- "${CODEX_PLUGIN_ROOT}/workflows/improve.js"` (if that variable is set instead)
3. `Bash: find ~/.claude ~/.codex . -maxdepth 7 -path '*/code-improver/workflows/improve.js' -print -quit 2>/dev/null`

Use the path exactly as printed. Its plugin directory — the path with
`/workflows/improve.js` removed — is `pluginRoot`. If all three come back empty, try
`{name: "code-improver:improve"}` once; if that is unavailable too, stop and say the loop
could not be located. Do not assemble a path by hand and do not improvise the loop.

### 3. Invoke the workflow

Run it with the Workflow tool, `{scriptPath: "<the path from step 2>", args: {...}}`:

```json
{
  "target": "<repo root>",
  "reviewer": {
    "kind": "skill",
    "name": "pr-review-toolkit:review-pr",
    "notes": "Review the working tree's changes against <base> as a pull request: correctness, tests, error handling, and the review dimensions the skill prescribes."
  },
  "scope": ["<derived-dir-glob>/**"],
  "pluginRoot": "<the plugin directory from step 2>",
  "maxRounds": 5
}
```

- `reviewer` — the default above requires the `pr-review-toolkit` plugin. When the user
  names a different PR reviewer (skill or agent), use it, with kind set accordingly.
- `maxRounds` only if the user asked for a different cap.
- `pluginRoot` lets the run find its metrics collector; omit the key only if step 2 fell
  through to the workflow name — the workflow then searches for itself.
- `finalize` defaults are right for PRs: no version bump unless the branch sits inside a
  plugin, narration strip and docs pass on.
- `decision` only on continuation (below).

The loop's baseline snapshot is the tree at loop start — its scope guard protects the
branch's uncommitted work; the PR's own commits are what the reviewer reviews.

The workflow runs in the background and needs no babysitting: it reviews, fixes,
re-reviews, checks scope after every fix round, and can only complete on a clean review.
It never commits; all changes stay in the working tree.

**If the Workflow tool is unavailable or denied, stop and say so.** Do not improvise the
loop inline with direct edits — the ledger, scope guard, and escalation guarantees live
in the workflow, and an inline imitation has none of them.

**If the result is `halted: "reviewer-unavailable"`, relay it and stop.** The reviewer
is not installed in this session; tell the user which plugin provides it (the default
needs `pr-review-toolkit`) and re-run after installing. Do not review the branch
yourself.

**Do not end your turn while the loop is running.** The Workflow tool returns a task id
immediately; the result comes later. In an interactive session the completion
notification re-invokes you — wait for it. In a non-interactive run (scripted, CI, eval)
there is no later turn: stopping abandons the loop mid-round, so after launching, poll
the task (TaskOutput with the returned task id, or sleep-and-recheck) until it completes,
then relay the result. A session that answers "the loop is running, I'll report later"
has lost the run.

## Relaying the result

The workflow returns a structured result. Report it honestly — the distinctions matter:

- **`converged: true`** — the last action was a review with zero critical/major findings.
  Report rounds used, remaining minor findings (`open_minor_count`), and the artifact
  paths (`ledger_path`, `metrics`).
- **`capped: true`** — the fix budget ran out and the FINAL review still found blocking
  issues. Say plainly: **capped, NOT converged**, and list `open_blocking`. Do not
  present this as success.
- **`escalation`** — the loop detected it was not converging (recurring findings,
  non-decreasing counts, or a fix relocating a problem). Relay the escalation message and
  finding ids to the user: this needs a design decision, not more rounds.
- **`halted`** — a guard fired (scope violation, unregistered new files, a dead or
  unavailable reviewer, or a finalize pass whose own edits failed the check that follows
  it). Relay the paths in `violations`/`new_untracked_files`, the sites in
  `finalize_regressions`, and the notes.
- **`notes`** always travel with the result — surface them; they include loud warnings
  such as "a git repository was initialized".

## Continuing after an escalation

The loop stops on escalation by design. When the user decides, start a fresh run with
the same args plus:

```json
{ "decision": "<the user's ruling, verbatim>" }
```

The new run reloads the on-disk ledger, so every finding, rejection, and verdict carries
over — rounds restart, re-derivation does not.

To stop a running loop, stop the workflow task (TaskStop); the ledger on disk is current
to the last round and a re-run resumes from it.

## When NOT to use

- **One-time review**: run the PR-review skill directly; the loop's value is iteration
- **A skill**: use the `skill-improver` entry — it wires the right reviewer
- **Unpushed exploratory work**: review-and-fix loops harden a diff; while the shape is
  fluid, manual iteration gives more control
