# Tests

Offline tests for the `workflows/` scripts. `run_seeds.sh` runs all three, and CI's shell-suite job discovers it by name (`run_*.sh`). Locally, `make shell-suites` — not `make check`, which excludes that target for unrelated reasons (see the Makefile note and #207).

```sh
bash plugins/insecure-defaults/tests/run_seeds.sh      # everything below

cd plugins/insecure-defaults
node tests/harness.js workflows/audit.js               # run the scenarios
node tests/harness.js workflows/audit.js --self-test   # prove the scenarios bite
node tests/seed-coverage.js .                          # documented == scanned
```

All exit non-zero on failure. Requires `node` and `grep`; no agents are spawned and nothing touches the network.

## `seed-coverage.js`

Checks the three places a category is defined against each other: the `{ id, title }` row in `workflows/audit.js`, `references/<id>.json`, and `references/<id>.md`:

| Check | Why |
|---|---|
| Both files exist for every row, and every file belongs to a row | A stray file looks like a category that will never be swept |
| `.json` id and title match the row | The sweep prompt uses the row's title; a mismatch means the files disagree about what the category is |
| `.json` has seeds, none using `\s`/`\d`/`\b` | Some grep builds silently fail to match those, and a pattern matching nothing looks exactly like a clean result |
| `.md` has a heading and both rule lines | The **Report when** / **Skip when** rule is what the sweep applies |
| Every VULNERABLE example is matched by a seed | See below |

Nothing at runtime can do any of this: the workflow has no filesystem access, so it cannot read either file, and a sweep handed a bad definition only reports it after the run has started.

The corpus states what the plugin detects; the seeds are what goes looking. They drifted apart silently once already: **8 of 18 documented examples matched no seed in any category**, including `getenv(K, "default")`, the most common shape in Python. Nothing in the workflow could notice: a pattern that matches nothing returns the same empty result as a clean repo.

Matching goes through `grep -E`, not JS RegExp, because the seeds are POSIX ERE (`[[:space:]]` has no JS equivalent), so this exercises them the way an agent running `grep -rE` would.

Three outcomes per example:

| | |
|---|---|
| `ok` | matched by its own category's seeds |
| `via` | matched only by a sibling category, acceptable since sweeps run in parallel and dedup merges by `file:line` |
| `GAP` | matched by nothing → **fails** |

It also fails if it finds zero examples or zero seeds, since a vacuous pass is the same bug it exists to catch.

## What the harness does

The workflow runtime hands a script its globals (`agent`, `parallel`, `pipeline`, `phase`, `log`, `args`, `budget`, `workflow`) and wraps the body in an async function, which is why a script can use a top-level `return`. The harness reproduces that: strips the `export`, wraps, and injects stubs that return canned agent responses keyed off each agent's `label`.

It deliberately does **not** inject a `workflow` global. All four phases are inlined in `audit.js`, so a reintroduced `await workflow(...)` throws `ReferenceError` rather than quietly resolving, and one scenario asserts none remain.

That makes the parts of the workflow that aren't prompt text directly testable: argument parsing, cross-category dedup, directory-aware batching, which corpus each agent is handed, and every abort status.

A few scenarios do assert on prompt *content*, where a wording change would quietly narrow scope, notably that the verifier still carries the "unconditional candidates cannot be refuted at step 2" branch. Half the target set has no config fallback, so losing that sentence would silently discard it.

What it does **not** test: whether the prompts elicit good behaviour from a real model. Only a live run tells you that.

## The `--self-test` mode, and why it exists

A test suite that has silently stopped checking anything reports success forever. So `--self-test` mutates the workflow source in memory and asserts the scenarios **fail** for each mutation. A sample:

| Mutation | Should break |
|---|---|
| Rule id dropped from the dedup key | unique-candidate count |
| Adjudication and candidates both keyed on `file:line` | one category's verdict masking another's omission |
| Verdict sets filtered before their batch is attached | the category stamp that keying depends on |
| `batches_verified` counts dead batches too | a partial run reading as complete |
| Per-category scan accounting dropped | a category that searched 0 files reading as covered |
| Unsearched categories counted only over sweeps that returned | a dead sweep being absent rather than at 0 |
| Total verify failure no longer aborts | `verify-failed` status, so a dead verify phase cannot read as clean |
| `verify-failed` widened to any unadjudicated candidate | a partial verify still producing its report |
| Oversized directory no longer split on its own | the over-cap branch of the packer |
| Genuine-negative status collapsed into the generic one | an honest negative staying distinguishable from a failure |
| Directory packing replaced by blind sort-then-chunk | whole-directory batching |
| Batch cap removed | chunking a category wider than 16 |
| `if (!pluginRoot)` gate removed | entry-guard abort |
| Recon no longer told to keep the target out of `exclude_paths` | auditing a scope that looks non-production |
| `meta.phases` model drifts from the `MODELS` table | per-phase model agreement |
| Corpus-unreadable abort removed | `corpus-unreadable` status |
| Full `recon` leaked into a sweep prompt | context scoping |
| `\|\| "."` becomes `?? "."` | empty-string scope defaulting |
| Zero-scanned guard removed | `search-failed` status |
| Seed-only detection disabled | `seed_only_sweeps` reporting |
| Verify downgraded off Opus in `MODELS` | per-phase model pinning |
| Unconditional branch dropped from the ladder | config-free findings staying in scope |

Every mutation is caught, and a mutation that matches nothing is itself a failure. Otherwise a renamed variable, or reformatted code, would quietly turn a mutation into a no-op and the self-test would pass while checking nothing. That has already fired three times in practice: once when a mutated phrase also appeared in `meta.whenToUse` and got replaced there instead, once when the corpus-scoping line changed shape, and once when the verify agent's options were collapsed onto one line.

## Adding a scenario

Append to `SCENARIOS` in `harness.js`. Each entry is `{ name, run(src) }` returning an array of `[label, boolean, detail?]`. Then add a mutation to `MUTATIONS` that your scenario is the one to catch. A scenario with no corresponding mutation isn't proven to check anything.

A sweep fixture of `null` is a sweep that returned nothing and an `Error` is one that died; a category the fixture omits returns a default that scanned 0 files.

Fixtures derive category ids from `CATEGORIES` in `audit.js` and seeds from `references/<id>.json` rather than hardcoding either, so editing a category doesn't quietly make the fixtures vacuous. The suite fails if it parses zero categories.
