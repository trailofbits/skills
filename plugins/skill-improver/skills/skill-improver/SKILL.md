---
name: skill-improver
description: "Runs an autonomous review-and-fix improvement loop over a Claude Code skill until a review comes back clean, with a cross-round findings ledger, escalation when fixes stop converging, and a mechanical scope guard. Use to fix skill quality issues, iteratively refine a skill, or resume a loop after an escalation ('fix my skill', 'improve this skill until it passes review', 'skill improvement loop'). NOT for a one-time review — use the plugin-dev skill-reviewer agent directly."
argument-hint: "<SKILL_NAME_OR_PATH> [--max-rounds N]"
allowed-tools: Glob Read Workflow
---

# Skill Improver

Improve a Claude Code skill by running `/skill-improver:improve` — a dynamic workflow
that loops reviewer and fixer subagents until a review reports zero critical/major
findings, then strips its own residue. The loop, its ledger, and its guards live in the
workflow; this skill resolves the target and relays the outcome.

## Starting the loop

The user provided: `$ARGUMENTS` (if empty, take the target skill from the conversation).

### 1. Resolve the skill path

1. If the input ends with `/SKILL.md` and the file exists, use its directory
2. If the input is a directory containing `SKILL.md`, use that path
3. Otherwise `Glob(pattern="**/SKILL.md")` and filter by skill name or path substring:
   - **Multiple matches:** ask the user to choose
   - **No matches:** report the available skills
   - **Single match:** proceed

### 2. Invoke the workflow

Run the `improve` workflow (Workflow tool, `{name: "improve"}`; installed as
`/skill-improver:improve`) with args as a JSON object:

```json
{
  "skill": "<resolved absolute path>",
  "pluginRoot": "${CLAUDE_PLUGIN_ROOT}",
  "maxRounds": 5
}
```

- `maxRounds` only if the user asked for a different cap (`--max-rounds N`).
- `pluginRoot` lets the run find its metrics collector; if the placeholder above was not
  substituted, omit the key — the workflow searches for itself.
- `scope` (repo-relative globs) only if the user restricted or widened what the loop may
  touch; by default the workflow scopes to the skill's plugin directory.
- `decision` only on continuation (below).

The workflow runs in the background and needs no babysitting: it reviews, fixes,
re-reviews, checks scope after every fix round, and can only complete on a clean review.
It never commits; all changes stay in the working tree.

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
- **`halted`** — a guard fired (scope violation, unregistered new files, a dead
  reviewer). Relay the paths in `violations`/`new_untracked_files` and the notes.
- **`notes`** always travel with the result — surface them; they include loud warnings
  such as "a git repository was initialized".

## Continuing after an escalation

The loop stops on escalation by design. When the user decides (e.g. "keep the blocklist
and document the limitation"), start a fresh run with the same `skill` plus:

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
- **Scope** — a mechanical git-diff check after every fix round halts on any
  out-of-scope change; completion also requires no unregistered new files in scope.
- **Report everything** — reviewers report all findings with severity; filtering happens
  once, at the ledger verdict, and rejections are not re-litigated without new evidence.
- **Finalize** — before completion the loop strips narration comments, collapses version
  churn to exactly one bump, and runs a docs-match-code pass.

## When NOT to use

- **One-time review**: dispatch the `plugin-dev:skill-reviewer` agent directly
- **Quick single fixes**: edit the file directly
- **Non-skill targets**: the reviewer's standards are skill-specific
- **Exploratory drafting**: manual iteration gives more control while the shape is fluid
