# writing-lean-proofs

Structured Lean 4 proof writing and library design following Mathlib
conventions — for proofs and libraries that humans *and* LLMs can review,
repair, and extend.

## What it does

Guides Claude (and Codex, via marketplace compatibility) through a
design-top-down, prove-bottom-up workflow:

1. **Design definitions and their API first** — total functions with junk
   values, bundled morphisms/subobjects, simp-normal forms, API lemmas in
   the same file before first use.
2. **Build a sorry skeleton** — state the theorem and its lemmas as
   compiling `sorry` stubs (spec-driven development, as practiced by the
   Liquid Tensor Experiment, PFR, and FLT projects), then the
   `have`/`suffices`/`calc` skeleton inside each proof.
3. **Fill goals one at a time** — focusing dots, honest `show` lines,
   calc chains, simp discipline.
4. **Verify mechanically** — compile and lint; never eyeball-check style.

Plus: the extraction ladder (when a `have` graduates to a lemma), Mathlib
naming so lemma names are guessable, an anti-pattern catalog mapped to the
linters that catch each one, and evidence-based techniques specific to
LLM-written proofs (goal-state annotation, typed-`have` skeletons,
verification in the loop).

## Why these rules

Every principle is sourced from Mathlib's style/review/naming guides, the
Mathlib maintenance papers, retrospectives of large formalizations
(perfectoid spaces, LTE, PFR, FLT), Mathematics in Lean, Theorem Proving in
Lean 4, and the ImProver paper (ICLR 2025) for LLM-specific techniques. The
claims were verified against the primary sources; commonly overstated rules
(e.g. turning Mathlib's general one-tactic-per-line recommendation into an
absolute requirement) are qualified in the anti-patterns reference.

## Contents

All paths below are relative to `skills/writing-lean-proofs/`:

- `SKILL.md` — workflow, extraction ladder, quick-reference rules
- `references/library-design.md` — definitions, APIs, abstraction
  boundaries, project decomposition
- `references/proof-style.md` — tactic proof structure
- `references/naming-conventions.md` — Mathlib naming
- `references/anti-patterns.md` — anti-patterns → rationale → enforcing
  linter
- `references/llm-techniques.md` — LLM-specific drafting techniques
- `references/linting.md` — axiom audits, library versus self-contained CI
  linter profiles, and project-specific linters
- `references/performance.md` — proof and reduction-cost diagnosis
- `references/tactics.md` — safe, bounded, traceable tactic metaprogramming

## Evals

`evals/` contains a review-flow eval suite: Lean fixtures (derived from a
real formal-verification project) with known planted flaws and known
non-flaws, natural review prompts, per-case rubrics, and a runner that
compares a baseline arm against a skill arm using an LLM judge. See
[evals/README.md](evals/README.md); `evals/run.sh --self-test` verifies the
grader still detects a known-bad review.

## When not to use

Lean-as-programming-language work without proofs, other proof assistants
(Coq/Isabelle/Agda), Lean 3 codebases, or projects with a conflicting house
style (defer to their CONTRIBUTING).

## Calcifier recipe for `writing-lean-proofs`

The [`writing-lean-proofs` Python recipe](skills/writing-lean-proofs/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/writing-lean-proofs/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/writing-lean-proofs/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `project_directory` | `str` | Required |
| `task` | `str` | Required |
| `modules` | `list[str]` | Required |
| `intent` | `Literal['finish', 'skeleton', 'review', 'diagnose']` | `'finish'` |
| `build_targets` | `list[str] \| None` | `None` |
| `expected_axioms` | `list[str] \| None` | `None` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
