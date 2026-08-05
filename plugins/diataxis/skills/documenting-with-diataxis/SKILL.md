---
name: documenting-with-diataxis
description: "Generates a complete Diataxis-structured documentation set for a codebase — tutorials, how-to guides, generated code reference, and explanation — by running a dynamic workflow that distills the framework from its upstream source, surveys the code in parallel, and authors each quadrant. Use when asked to write, generate, restructure, or organize project documentation, when a project has only a README, or when documentation needs to be split by reader need rather than by module."
allowed-tools: Bash Read Grep Glob Workflow Agent AskUserQuestion
---

# Documenting with Diátaxis

[Diátaxis](https://diataxis.fr) splits documentation into four kinds by what the reader is doing: **tutorial** (studying, by doing), **how-to** (working, on a goal they brought), **reference** (working, needs a fact), **explanation** (studying, building understanding). Most projects fuse all four into a README and serve none of them.

This skill runs an eleven-agent workflow that produces each kind separately, with reference generated from the code rather than written beside it.

## Workflow

```
Phase 1  Framework   1 agent   clone the framework repo, distill its rules
Phase 2  Survey      5 agents  inventory, api-surface, onboarding, operations, architecture
Phase 3  Author      4 agents  one per quadrant, disjoint output paths
Phase 4  Assemble    1 agent   index, cross-links, navigation
```

The agent briefs live in [references/agent-prompts.md](references/agent-prompts.md) — the single source of truth for both execution paths below. The workflow does not restate them; its agents read that file at run time.

## Step 1 — Preflight

Run these checks before launching. Do not skip them: phase 3 edits source files to add doc comments, and workflow agents run in `acceptEdits` mode, so their writes are auto-approved.

```bash
git rev-parse --show-toplevel && git status --porcelain
```

- **Not a git repo** → stop and say so. Without version control there is no way to review or undo an eleven-agent run that touches source.
- **Dirty worktree** → stop and ask the user to commit or stash first. A clean tree is the entire review mechanism: afterwards, `git diff` is exactly what the run did.
- **Clean** → continue.

Then resolve the arguments, asking only if the answer is genuinely ambiguous:

| Argument | Default | Notes |
|----------|---------|-------|
| `target` | repository root | A single package is a good first run — it bounds the cost |
| `docsDir` | `docs` | If the project already has a docs root (`doc/`, `website/`, `site/`), use that instead |

Check for an existing docs root before defaulting:

```bash
ls -d docs doc website site documentation 2>/dev/null
```

## Step 2 — Launch the workflow

```
Workflow({
  name: "diataxis:document",
  args: {
    target: "<resolved target>",
    docsDir: "<resolved docs dir>",
    referencesDir: "{baseDir}/references"
  }
})
```

`referencesDir` is required — the workflow aborts immediately without it, because every agent reads its brief from there. `{baseDir}` resolves to this skill's directory; do not hardcode a path.

These instructions are themselves the opt-in for running a workflow, so no `ultracode` keyword is needed.

The run takes a while and reports progress in `/workflows`. When it returns, go to [Step 4](#step-4--report).

## Step 3 — Fallback when workflows are unavailable

Dynamic workflows can be off per-user (`/config`), off organization-wide (managed settings or `disableWorkflows`), or absent on a non-Claude Code runtime. If the `Workflow` tool is unavailable or the launch is refused, run the same four phases with the `Agent` tool instead. Say plainly that you are doing this — the fallback is slower and holds intermediate results in context, so it is a degraded path, not an equivalent one.

1. **Framework** — one agent, following the "Phase 1" brief. Apply the same guards the workflow applies: if it returns no commit SHA, or read fewer than 8 framework source files, **stop**. A distillation written from memory is the failure this phase exists to catch.
2. **Survey** — five agents in a single message so they run concurrently, one per brief in "Phase 2". Stop if `inventory` fails or reports zero source files.
3. **Author** — four agents in a single message, one per brief in "Phase 3". Pass each the framework spec, its quadrant, the full survey, and the other three quadrant names. Note any survey dimension that failed so writers record a gap instead of inventing.
4. **Assemble** — one agent, the "Phase 4" brief.

Report any quadrant that wrote zero files. Do not quietly omit it.

## Step 4 — Report

Summarize from the workflow's return value:

- Files written per quadrant, and the reference generator chosen with its build command
- **Source files edited** — call these out separately. They are the part a reviewer must actually read.
- Everything in `incomplete`: failed survey dimensions, failed or empty quadrants
- Everything the writers put in `redirected` and `gaps`

Then tell the user to review with `git diff` and to run the reference build command to confirm it produces output.

Report gaps plainly. A run that hides what it could not do is worse than one that names it — the user will find out when a reader does.

## Adapting the workflow

The bundled script is a sensible default, not a fixed pipeline. Adapt it when the target warrants, by editing the script the run writes to the session directory and relaunching with `scriptPath`:

- **Small project** (one module, a few hundred lines) — drop `operations` and `architecture` from the survey; there is unlikely to be enough material for either, and an agent with nothing to find pads. Five agents beats eleven here.
- **Large or polyglot project** — split the reference writer per language or per package, and the how-to writer per subsystem. Keep the survey as is; it is what makes the split coherent.
- **Docs already partly exist** — bias the writers toward integrating rather than authoring, and consider running only the quadrants that are missing.
- **Cost** — the survey phase is mechanical reading and routes well to a cheaper model via `opts.model`. Do not economize on phase 3; that is where the quality is.

Keep the guards when you adapt. They are what stop the run from producing confident, empty documentation.

## What this skill will not do

- **Restructure an existing mature docs site.** It adds the four quadrants; it does not migrate or delete what is there. Reorganizing someone's docs is their call.
- **Change code.** The reference agent writes comments and generator config only — never a signature, a name, a default, or a statement.
- **Invent behavior.** Every claim traces to a survey finding with a path. A gap is recorded as a gap.

## Rationalizations to reject

| Rationalization | Why it is wrong |
|---|---|
| "I know Diátaxis, I can skip the clone." | The clone is a correctness gate, not a formality. The workflow checks the commit SHA precisely because a plausible recollection is indistinguishable from a reading — until it is wrong. |
| "Reference as Markdown is faster than setting up Doxygen." | Hand-written reference is wrong within a release and then actively misleads. Generated-from-source is the entire point of the quadrant. |
| "This how-to would be clearer if I explained the design first." | That is explanation. Put it there and link. Mixing them is the failure Diátaxis exists to name. |
| "The project has no explanation material." | Usually it means the rationale lives only in maintainers' heads and commit messages — the case where writing it down is most valuable. |
| "Three quadrants is enough, the fourth is thin." | Report it as thin. Silently shipping three quadrants under a four-quadrant index tells the reader something false. |
| "The worktree is only a little dirty." | Then `git diff` no longer separates the run's changes from the user's, and the review mechanism is gone. Stop and ask. |

## References

- [references/diataxis-quadrants.md](references/diataxis-quadrants.md) — deciding which quadrant a page belongs to, and the acceptance checks per quadrant
- [references/reference-toolchains.md](references/reference-toolchains.md) — language to generator, doc-comment requirements, constraints on editing source
- [references/agent-prompts.md](references/agent-prompts.md) — the eleven agent briefs
