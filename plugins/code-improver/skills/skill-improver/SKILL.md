---
name: skill-improver
description: "Runs an autonomous review-and-fix improvement loop over a Claude Code skill until a review comes back clean, with a cross-round findings ledger, escalation when fixes stop converging, and a mechanical scope guard. Reviews are performed by the plugin-dev skill-reviewer agent. Use to fix skill quality issues, iteratively refine a skill, or resume a loop after an escalation ('fix my skill', 'improve this skill until it passes review', 'skill improvement loop'). NOT for a one-time review — use the plugin-dev skill-reviewer agent directly."
argument-hint: "<SKILL_NAME_OR_PATH> [--max-rounds N]"
allowed-tools: Bash Glob Read TaskOutput TaskStop Workflow
---

# Skill Improver

Improve a Claude Code skill by running `/code-improver:improve` — a dynamic workflow
that loops a reviewer and a fixer subagent until a review reports zero critical/major
findings, then strips its own residue. This entry point wires the loop to the
`plugin-dev:skill-reviewer` agent, so the **plugin-dev plugin must be installed**
(marketplace `claude-plugins-official`). The loop, its ledger, and its guards live in
the workflow; this skill resolves the target and relays the outcome.

## Starting the loop

The user provided: `$ARGUMENTS` (if empty, take the target skill from the conversation).

### 1. Resolve the skill path

1. If the input ends with `/SKILL.md` and the file exists, use its directory
2. If the input is a directory containing `SKILL.md`, use that path
3. Otherwise `Glob(pattern="**/SKILL.md")` and filter by skill name or path substring:
   - **Multiple matches:** ask the user to choose
   - **No matches:** report the available skills
   - **Single match:** proceed

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
  "target": "<resolved absolute path>",
  "reviewer": {
    "kind": "agent",
    "name": "plugin-dev:skill-reviewer",
    "notes": "The target is a Claude Code skill directory; review it as a skill (frontmatter, triggering description, progressive disclosure, referenced files)."
  },
  "pluginRoot": "<the plugin directory from step 2>",
  "maxRounds": 5
}
```

- `maxRounds` only if the user asked for a different cap (`--max-rounds N`).
- `pluginRoot` lets the run find its metrics collector; omit the key only if step 2 fell
  through to the workflow name — the workflow then searches for itself.
- `scope` (repo-relative globs) only if the user restricted or widened what the loop may
  touch; by default the workflow scopes to the skill's plugin directory.
- `decision` only on continuation (below).

The workflow runs in the background and needs no babysitting: it reviews, fixes,
re-reviews, checks scope after every fix round, and can only complete on a clean review.
It never commits; all changes stay in the working tree.

**If the Workflow tool is unavailable or denied, stop and say so.** Do not improvise the
loop inline with direct edits — the ledger, scope guard, and escalation guarantees live
in the workflow, and an inline imitation has none of them (observed failure: an inline
fallback "fixed" a finding by weakening the documented guarantee, exactly what the loop
exists to prevent).

**If the result is `halted: "reviewer-unavailable"`, relay it and stop.** The reviewer
this skill names is not installed; tell the user to install the `plugin-dev` plugin from
the `claude-plugins-official` marketplace and re-run. Do not review the skill yourself.

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

The loop stops on escalation by design. When the user decides (e.g. "keep the blocklist
and document the limitation"), start a fresh run with the same `target` plus:

```json
{ "decision": "<the user's ruling, verbatim>" }
```

The new run reloads the on-disk ledger, so every finding, rejection, and verdict carries
over — rounds restart, re-derivation does not.

To stop a running loop, stop the workflow task (TaskStop); the ledger on disk is current
to the last round and a re-run resumes from it.

## What the loop enforces (so you do not have to)

- **Fix verification** — the next review verifies every fix; fixes to executable
  behavior carry pins that fail against the pre-fix code.
- **Scope** — a mechanical git-diff check after every fix round, and after the finalize
  pass, halts on any out-of-scope change; out-of-scope files git does not track are
  guarded by content hash, since no diff would show them; completion also requires no
  unregistered new files in scope.
- **Report everything** — reviewers report all findings with severity; filtering happens
  once, at the ledger verdict, and rejections are not re-litigated without new evidence.
- **Finalize** — before completion the loop strips narration comments, collapses version
  churn to exactly one bump (in `plugin.json` and the marketplace entry that repeats it),
  and runs a docs-match-code pass. Those edits land after the last review, so a check
  reads them: an over-eager narration strip or a false docs claim halts with
  `finalize-regression` instead of passing as done.

## When NOT to use

- **One-time review**: dispatch the `plugin-dev:skill-reviewer` agent directly
- **Quick single fixes**: edit the file directly
- **Non-skill targets**: use the `code-improver` skill with a reviewer that fits the
  target, or `pr-improver` for a branch
- **Exploratory drafting**: manual iteration gives more control while the shape is fluid
