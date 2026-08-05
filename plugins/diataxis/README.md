# diataxis

Generates a complete [Diátaxis](https://diataxis.fr)-structured documentation set for a codebase, using a [dynamic workflow](https://code.claude.com/docs/en/workflows) that orchestrates eleven agents across four phases.

## What It Does

Diátaxis splits documentation into four kinds, each serving a different user need. Most projects blur them together — a README that is part tutorial, part reference, part rationale, and reliably wrong about all three. This plugin generates each kind separately, with the boundaries enforced.

```
Phase 1  Framework   1 agent   clones diataxis-documentation-framework, distills the rules
Phase 2  Survey      5 agents  parallel readers map the codebase
Phase 3  Author      4 agents  one per quadrant, writing to disjoint paths
Phase 4  Assemble    1 agent   index, cross-links, build wiring
```

Output lands in `docs/` in the Diátaxis layout:

| Directory | Kind | Serves |
|-----------|------|--------|
| `docs/tutorials/` | Tutorial | A newcomer learning by doing |
| `docs/how-to/` | How-to guide | A competent user with a task to finish |
| `docs/reference/` | Reference | Someone who needs a fact, fast |
| `docs/explanation/` | Explanation | Someone building a mental model |

**Reference is generated from the code, not written beside it.** The reference agent detects the language, scaffolds the appropriate generator (Doxygen, Sphinx + autodoc, rustdoc, godoc, TypeDoc, Javadoc, YARD, NatSpec), and fills in the missing doc comments in the source so the generated output is actually complete. Reference that lives anywhere but the code drifts from it within a release.

## Why It Clones the Framework

The Diátaxis framework is published under CC-BY-SA 4.0. Rather than vendoring its text — which would carry a ShareAlike obligation into every repository this plugin runs against — the first agent clones [evildmp/diataxis-documentation-framework](https://github.com/evildmp/diataxis-documentation-framework) at run time and distills the rules it needs. The plugin ships only its own guidance.

That first phase also acts as a correctness gate: it must return the resolved commit SHA and a count of source files it actually read. An agent that failed to clone and answered from memory fails the run instead of quietly producing a plausible-looking framework spec.

## When to Use

- A project with a sprawling README and nothing else
- Documentation that exists but is organized by module rather than by reader need
- Before a public release, when `open-sourcing` flags documentation as a gap

Not a good fit for a project with a mature, deliberately-structured docs site — the workflow adds to `docs/`, it does not reorganize what is already there.

## Usage

```
/diataxis:document
```

Or describe the task and let the skill trigger: *"write Diátaxis documentation for this repo"*.

The workflow takes optional arguments:

| Argument | Default | Meaning |
|----------|---------|---------|
| `target` | `.` | Path to the codebase to document |
| `docsDir` | `docs` | Where the four quadrants are written |

```
Run /diataxis:document on src/parser with docs in website/content
```

## Before You Run It

**Commit or stash first.** The reference agent edits source files to add doc comments, and workflow agents run in `acceptEdits` mode — their file writes are auto-approved. A clean worktree is what makes the entire run reviewable with `git diff`.

The run needs network access for the framework clone, and it spawns eleven agents, so it costs meaningfully more than a single-turn task. To gauge it, point `target` at one package first.

## Installation

```bash
claude plugins:add trailofbits/skills/diataxis
```

## If Dynamic Workflows Are Unavailable

Workflows can be turned off per-user (`/config`), per-organization (managed settings), or be absent on a non-Claude Code runtime. The skill detects this and runs the same four phases sequentially with the `Agent` tool instead. Both paths read the same agent briefs from `skills/documenting-with-diataxis/references/agent-prompts.md`, so they stay in step.

## Components

| Path | Purpose |
|------|---------|
| `workflows/document.js` | The dynamic workflow — runs as `/diataxis:document` |
| `skills/documenting-with-diataxis/SKILL.md` | Entry point, preflight, adaptation guidance, fallback |
| `references/diataxis-quadrants.md` | Boundary discipline: which kind a given page is |
| `references/reference-toolchains.md` | Language to doc generator, config, and build command |
| `references/agent-prompts.md` | The eleven agent briefs, shared by both execution paths |
