---
name: code-improver
description: "Runs an autonomous review-and-fix improvement loop over any code target — a skill, plugin, module, or directory — using a reviewer the user names: any installed skill or agent. Keeps a cross-round findings ledger, escalates when fixes stop converging, and guards scope mechanically. Use when asked to 'improve this code until review passes', 'run an improvement loop with <reviewer>', or to iterate review-and-fix with a specific reviewer. For skills prefer the skill-improver entry; for a branch prefer pr-improver."
argument-hint: "<TARGET_PATH> --reviewer <agent-or-skill-name> --scope <globs> [--max-rounds N]"
allowed-tools: Bash Glob Read TaskOutput TaskStop Workflow
---

# Code Improver

Improve any code target by running `/code-improver:improve` — a dynamic workflow that
loops the named reviewer and a fixer subagent until a review reports zero critical/major
findings, then strips its own residue. The loop, its ledger, and its guards live in the
workflow; this skill collects the three inputs the generic entry requires and relays the
outcome.

## Starting the loop

The user provided: `$ARGUMENTS` (if empty, take the details from the conversation).

### 1. Collect the three required inputs — no guessing

1. **Target**: the absolute path to the directory under improvement. Resolve relative
   paths against the working directory; verify the directory exists.
2. **Reviewer**: the installed skill or agent that performs every review. The user must
   name it — there is no default and no bundled reviewer. Determine the kind:
   - a namespaced agent (e.g. `plugin-dev:skill-reviewer`) → `"kind": "agent"`
   - an installed skill (e.g. `pr-review-toolkit:review-pr`) → `"kind": "skill"`
   If the name could be either, check the session's skill listing; if still ambiguous,
   ask the user. If no reviewer was named, ask — do not pick one.
3. **Scope**: repo-relative globs the loop may touch. The generic entry requires it
   explicitly; if the user did not give one, propose the target directory
   (`<repo-relative-target>/**`) and confirm before launching.

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
  "target": "<absolute target path>",
  "reviewer": { "kind": "agent|skill", "name": "<namespaced-name>", "notes": "<what the reviewer should know about the target>" },
  "scope": ["<repo-relative-glob>/**"],
  "pluginRoot": "<the plugin directory from step 2>",
  "maxRounds": 5
}
```

- `maxRounds` only if the user asked for a different cap.
- `pluginRoot` lets the run find its metrics collector; omit the key only if step 2 fell
  through to the workflow name — the workflow then searches for itself.
- `finalize` (`{"version_bump": bool, "narration_strip": bool, "docs_pass": bool}`) only
  to override the defaults: version bump when the target sits inside a plugin, narration
  strip and docs pass always.
- `decision` only on continuation (below).

The workflow runs in the background and needs no babysitting: it reviews, fixes,
re-reviews, checks scope after every fix round, and can only complete on a clean review.
It never commits; all changes stay in the working tree.

**If the Workflow tool is unavailable or denied, stop and say so.** Do not improvise the
loop inline with direct edits — the ledger, scope guard, and escalation guarantees live
in the workflow, and an inline imitation has none of them.

**If the result is `halted: "reviewer-unavailable"`, relay it and stop.** The named
reviewer is not installed in this session; tell the user which plugin provides it and
re-run after installing. Do not review the target yourself.

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
the same `target` and `reviewer` plus:

```json
{ "decision": "<the user's ruling, verbatim>" }
```

The new run reloads the on-disk ledger, so every finding, rejection, and verdict carries
over — rounds restart, re-derivation does not.

To stop a running loop, stop the workflow task (TaskStop); the ledger on disk is current
to the last round and a re-run resumes from it.

## When NOT to use

- **A Claude Code skill**: use the `skill-improver` entry — it wires the right reviewer
- **A branch / pull request**: use the `pr-improver` entry — it derives scope from the diff
- **One-time review**: dispatch the reviewer directly; the loop's value is iteration
- **Quick single fixes**: edit the file directly
