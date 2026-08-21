---
name: goal-prompt
description: "Drafts copy-paste-ready /goal commands for goal mode in Claude Code and Codex. Use when the user asks to create, write, rewrite, improve, compress, clean up, or prepare a goal prompt, goal condition, /goal command, goal-mode objective, or copy-ready long-running task objective."
allowed-tools: Bash Read Write
---

# Goal Prompt

`/goal` keeps the agent working until a completion condition is met. Both Claude Code and Codex take it as one line, max 4,000 characters. In Claude Code a small model re-judges the condition after each turn from the transcript alone — it cannot run commands.

Draft a condition that can terminate, then format it. A goal fits work bigger than one turn with a checkable finish line; chain small goals with review between them rather than writing one giant goal.

## Draft

Include, joined with AND — never "or", the loop takes the cheaper branch:

1. **End state, not activity** — "all `legacyAuth()` call sites use `auth.verify()`", not "migrate the auth code". An activity can be claimed; an end state is true or false.
2. **Scope to read first** — the files, issue, logs, or plan to read before acting.
3. **Stated check** — the exact command and its observable result ("`npm test` exits 0"), plus an instruction to run it and show the output; a result that never lands in the transcript does not exist to the evaluator.
4. **Invariants** — what must not change ("without modifying vendor/"), always including "do not weaken, skip, or edit the checks themselves".
5. **Stop bound or blocked clause** — "or stop after 20 turns", "if blocked, stop and report the blocker". Without one, a mis-stated condition loops forever; the formatter warns when it is missing. (Claude Code resets the turn counter on session resume, so a turn bound silently extends across resumes.)

**Keep it small.** Every constraint narrows the state space the model can explore. Collapse to one terminating criterion when possible, move scope and definitions into a referenced file, and drop non-goals — a constraint earns its place only by closing a real easy-out.

For long goals, also name the final evidence (diff, report, artifact) and require a progress log file — durable state across compaction and resume. If the brief exceeds 4,000 characters, put the details in a `GOAL.md` and reference that file from the objective.

**Never invent missing elements.** Ground every element in the user's request, the conversation, or the repository — look things up rather than guessing. If an element cannot be filled from available information, still optimize and format what the user provided, leave the element out, and flag it as missing (see Format). A goal with an invented success condition terminates on the wrong contract.

## Close the easy-outs

Before formatting, reread the drafted condition as a lazy model would: what is the cheapest way to make every check pass without doing the intended work? Close the cheapest ones — prefer pairing checks you already have over adding constraints, and do not enumerate every conceivable out into a non-goal list. The recurring outs:

- **Delete or stub instead of fix** — "search prints nothing" also holds when the callers are gone; pair such checks with one that proves the feature still works.
- **Pass on a subset** — running one test file, narrowing the search path, excluding directories from the check.
- **Game the gate** — skipping/xfail-ing tests, hardcoding expected outputs, special-casing the test inputs, editing the check (the invariants rule).
- **Claim without running** — declaring done or blocked with no check output in the transcript (the show-the-output rule).

Same discipline as above: an out you cannot close from available information goes in the `Missing:` list as a warning — an invented or absurd constraint is worse than a flagged gap.

## Security research goals

Collapse audit goals to one terminating criterion, such as identifying, triggering, and validating one high-severity vulnerability valid under a referenced threat-model file. That file, not the goal, carries scope, attacker powers, severity baseline, and known findings to skip. Use neutral wording ("trigger and validate", not "prove this is exploitable"), require demonstrated preconditions — assumed attacker access is the most common false positive — and stop for human review after each finding rather than piling up untriaged reports. Validate findings with a second pass by a fresh agent, never the finder alone.

## Format

Run `uv run --no-project {baseDir}/scripts/format_goal_prompt.py --fenced` on the draft (file or stdin). It collapses whitespace to one line, strips `/goal` prefixes, quotes, and fences, warns on a missing stop clause, and rejects output over 4,000 characters — shorten or move detail to a file and rerun.

Return exactly one fenced `text` block, one line:

```text
/goal <single normalized objective>
```

Add no prose around it — except when checklist elements could not be grounded: then follow the block with a `Missing:` list, one line per gap, telling the user what to supply.

## Example

Draft:

```
/goal Migrate the auth module:
  - replace legacyAuth() with auth.verify()
  - make sure the tests still work
```

Redrafted and formatted:

```text
/goal All legacyAuth() call sites use auth.verify(): `rg "legacyAuth\(" -t ts` prints nothing AND `npm test` exits 0 (run both, show the output), without modifying vendor/ or weakening any test. If blocked, stop and report attempted paths and the blocker, or stop after 20 turns.
```

Here `npm test` came from the repo's package.json — not a guess — and pairing it with the zero-matches check closes the cheapest out: deleting the call sites instead of migrating them. When nothing grounds an element, format what exists and flag the gaps:

Draft: `make checkout faster`, with no metric or benchmark anywhere in context:

```text
/goal Make checkout faster
```

Missing:
- measurable end state — which metric and threshold count as "faster"
- verification — the benchmark or command that proves it
- stop bound — e.g. "or stop after 20 turns"
