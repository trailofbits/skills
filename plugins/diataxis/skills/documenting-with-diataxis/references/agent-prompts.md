# Agent briefs

The eleven agent briefs, in one place. Both execution paths read them: `workflows/document.js` spawns agents whose prompts point here, and the sequential fallback in `SKILL.md` follows the same sections in order. Editing a brief changes both.

Each brief below states what the agent reads, what it does, and what it must return. Return shapes are enforced by JSON schema in the workflow; the fallback path should follow them anyway so the phases compose.

---

## Phase 1 — Framework

**One agent. Everything downstream depends on it, so it fails loudly rather than approximately.**

Clone the framework and distill it:

```bash
git clone --depth 1 https://github.com/evildmp/diataxis-documentation-framework.git "$SCRATCH/diataxis"
git -C "$SCRATCH/diataxis" rev-parse HEAD
```

Read these files under `source/`: `index.rst`, `tutorials.rst`, `how-to-guides.rst`, `reference.rst`, `explanation.rst`, `compass.rst`, `quality.rst`, `foundations.rst`, `map.rst`, `how-to-use-diataxis.rst`. Ignore `translation/` and `images/`.

Then read `<referencesDir>/diataxis-quadrants.md`, which carries the boundary discipline this run enforces on top of the framework.

**Do not answer from prior knowledge.** If the clone fails — no network, DNS, proxy — report the failure and stop. Returning a plausible framework spec you already knew is the specific failure this phase exists to prevent, and the workflow checks the commit SHA and file count to catch it.

Return:

- `sourceCommit` — the resolved SHA. Must be non-empty.
- `rstFilesRead` — how many of the listed files you actually opened.
- `readBrief` — whether `<referencesDir>/diataxis-quadrants.md` was readable.
- `quadrants` — exactly four entries, each with `name` (`tutorial` | `how-to` | `reference` | `explanation`), `userNeed`, `purpose`, `form`, `voice`, `antiPatterns[]`, `acceptanceChecks[]`.
- `compass` — the rules for deciding which quadrant a page belongs to.
- `qualityChecks` — the framework's own tests for whether documentation is working.

---

## Phase 2 — Survey

**Five agents in parallel over the target. Read-only: none of them writes anything.**

All five: report what you found and what you looked for and did not find. An empty result is a finding — "no CI configuration" tells the how-to writer something real. Cite paths for every claim so the writers can follow up.

### 2a. `inventory`

Map the shape of the project. Languages with rough LOC split, build system and package manifests, entry points (binaries, CLI, library root, service handlers), test layout, and — critically — **existing documentation**: every docs directory, README, site config (`mkdocs.yml`, `docusaurus.config.js`, `conf.py`, `book.toml`), and any doc generator already configured.

Also report the project's own conventions: line width, comment style per language, task runner (`Makefile`, `justfile`, npm scripts).

Return `languages[]` with `{name, approxLoc, isPublicSurface}`, `buildSystem`, `entryPoints[]`, `existingDocs[]` with `{path, kind, quadrantIfAny}`, `existingDocToolchain`, `conventions`, and `sourceFileCount`. If `sourceFileCount` is zero the run stops — there is nothing to document.

### 2b. `api-surface` → feeds reference

Enumerate the public surface a consumer touches: exported functions, types, classes, methods, constants; CLI commands and every flag; configuration keys and environment variables with defaults; error and exception types; public network or IPC endpoints.

For each, record whether it currently has a doc comment, and whether that comment is substantive or a restatement of the name. Report the coverage ratio.

Deliberately exclude private and internal symbols. Getting the public boundary right matters more than volume — if the boundary is ambiguous (no `__all__`, no explicit exports), say how you decided.

Return `symbols[]` with `{path, name, kind, signature, documented, commentQuality}`, `cliCommands[]`, `configKeys[]`, `publicBoundaryRule`, and `docCoverage`.

### 2c. `onboarding` → feeds tutorials

Find the shortest real path from nothing to a working result. Installation and its prerequisites, the first command that produces visible output, the examples directory, quickstart material in the README, and the tests — integration tests are often the only honest record of how the software is meant to be driven.

Report where a newcomer would actually get stuck: undeclared prerequisites, steps that assume credentials, examples that no longer run against the current API.

Return `install`, `firstRunPath[]` as ordered steps with expected output, `examples[]`, `testsAsExamples[]`, `knownStumblingBlocks[]`, and `candidateTutorials[]` — each a concrete achievable outcome, not a topic.

### 2d. `operations` → feeds how-to

Find the tasks real users actually perform. Mine the scripts and task runner targets, CI workflows, deployment and container configuration, migration and maintenance tooling, troubleshooting notes, and recurring themes in issues and commit messages if the history is available.

The output is goals, not features. "Rotate the signing key" is a goal. "The `crypto` module" is not.

Return `tasks[]` with `{goal, evidencePaths[], variations[], frequency}`, `troubleshooting[]`, and `operationalSurface`.

### 2e. `architecture` → feeds explanation

Recover the reasoning. The module graph and how data moves through it, the boundaries and why they sit where they do, design decisions recorded in ADRs, long comments, docstrings on modules, and commit messages. Constraints the design answers to — performance, compatibility, security, a protocol spec. Alternatives that were tried and abandoned; deprecated code and migration paths are strong evidence.

Distinguish what is documented from what you inferred, and mark the confidence. An inferred rationale presented as fact is worse than an open question.

Return `modules[]` with `{name, responsibility, dependsOn[]}`, `dataFlow`, `decisions[]` with `{decision, rationale, evidence, confidence}`, `constraints[]`, `rejectedAlternatives[]`, and `openQuestions[]`.

---

## Phase 3 — Author

**Four agents in parallel. Each owns one directory and writes nowhere else.** They run concurrently, so a writer that strays outside its subtree corrupts another's work.

Every writer receives the framework spec, its own quadrant definition, the full survey, and the names of the other three quadrants.

Shared rules:

- Read `<referencesDir>/diataxis-quadrants.md` first. Apply the acceptance checks to your own draft before returning.
- **Never delete or overwrite an existing documentation file.** If content exists at your target path, integrate with it and record that you did. The user's prose outranks yours.
- Ground every claim in the survey, citing the path. If you need a fact the survey does not have, read the source yourself — do not invent it. Documentation that describes software that does not exist is the most expensive possible output.
- Out-of-quadrant material goes in `redirected[]` with the quadrant it belongs to. Do not absorb it, do not discard it.
- Match the project's existing documentation conventions — format, heading style, file naming — from `inventory.conventions`.
- Return a manifest: `filesWritten[]`, `filesIntegrated[]`, `redirected[]`, `gaps[]`. Zero files written is a failure, not a clean result.

### 3a. `tutorials` → `docs/tutorials/`

Write from `onboarding.candidateTutorials`. A learner follows a tutorial literally and must not fail: give every command, show every expected output, make every choice for them, never branch. It must end in something visibly real.

No design rationale, no exhaustive options, no "configure appropriately." Link to explanation at the end for the reader who now wants to know why.

Prefer one excellent tutorial over three thin ones.

### 3b. `how-to` → `docs/how-to/`

Write from `operations.tasks`. One guide per goal, titled with a verb. Address a competent user who arrived with the goal: no teaching, no justifying. Cover the realistic variations, stop when the goal is met.

Do not write a how-to for a task you have no evidence anyone performs.

### 3c. `reference` → `docs/reference/` and doc comments in source

**This is the code-documentation agent.** Read `<referencesDir>/reference-toolchains.md` and follow it — it holds the generator table, the doc-comment requirements, and the hard constraints on editing source.

In outline: pick the generator from `inventory.languages` and `api-surface.publicBoundaryRule`, adopt an existing toolchain if one is configured rather than replacing it, scaffold its config, then write doc comments for the public symbols in `api-surface.symbols` — prioritizing the undocumented ones and those whose comment merely restates the name. Write `docs/reference/index.md` with the build command, gitignore the generated output, and wire the build into the project's existing task runner.

Comments and configuration only. Never change behavior, a signature, a name, or a default.

### 3d. `explanation` → `docs/explanation/`

Write from `architecture`. Topic- or question-titled. The irreplaceable content is the reasoning: why the design is this way, what constraints forced it, what alternatives were rejected and why.

Carry `confidence` through honestly — write inferred rationale as inference, and turn `openQuestions` into a section rather than papering over them. No instructions; a reader should be able to read this away from the keyboard.

---

## Phase 4 — Assemble

**One agent, after all four writers return.**

Write `<docsDir>/index.md` as the entry point: name the four kinds, say plainly who each serves, and link into them. This is what makes the structure legible to a reader who has never heard of Diátaxis — without it they see four folders and guess.

Then cross-link: tutorials point onward to explanation, how-tos point to the reference pages for the symbols they use, explanation points back to the tutorial that makes it concrete. Verify the links resolve.

If the project has a docs site config (`existingDocToolchain`), add the four sections to its navigation. Do not restructure the existing site.

Return `indexPath`, `crossLinksAdded`, `navigationUpdated`, `brokenLinks[]`, and a `summary` covering: files written per quadrant, the reference generator chosen and its build command, source files edited, everything in the writers' `redirected[]` and `gaps[]`, and any quadrant that came back thin and why. Report the gaps plainly — a run that hides what it could not do is worse than one that names it.
