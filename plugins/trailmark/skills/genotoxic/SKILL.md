---
name: genotoxic
description: "Graph-informed mutation testing triage. Parses codebases with Trailmark, runs mutation testing and necessist, then uses survived mutants, unnecessary test statements, and call graph data to identify false positives, missing test coverage, and fuzzing targets. Use when triaging survived mutants, analyzing mutation testing results, identifying test gaps, finding fuzzing targets from weak tests, running mutation frameworks (including circomvent and cairo-mutants), or using necessist."
---

# Genotoxic

Combines mutation testing and necessist (test statement removal) with
code graph analysis to triage findings into actionable categories:
false positives, missing unit tests, and fuzzing targets.

## When to Use

- After mutation testing reveals survived mutants that need triage
- Identifying where unit tests would have the highest impact
- Finding functions that need fuzz harnesses instead of unit tests
- Prioritizing test improvements using data flow context
- Filtering out harmless mutants from actionable ones
- Finding unnecessary test statements that indicate weak assertions (necessist)

## When NOT to Use

- Codebase has no existing test suite (write tests first)
- Pure documentation or configuration changes
- Single-file scripts with trivial logic

## Prerequisites

- **trailmark** installed — if `uv run trailmark` fails, run:
  ```bash
  uv pip install trailmark
  ```
  **DO NOT** fall back to "manual verification" or "manual analysis"
  as a substitute for running trailmark. Install it first. If installation
  fails, report the error instead of switching to manual analysis.
- A **mutation testing framework** for the target language — if the framework
  command fails (not found, not installed), install it using the instructions
  in [references/mutation-frameworks.md](references/mutation-frameworks.md).
  **DO NOT** fall back to "manual mutation analysis" or skip mutation testing.
  Install the framework first. If installation fails, report the error
  instead of switching to manual mutation analysis.
- **necessist** (optional, recommended) — if the target language is
  supported (Go, Rust, Solidity/Foundry, TypeScript/Hardhat,
  TypeScript/Vitest, Rust/Anchor), install with `cargo install necessist`.
  See [references/mutation-frameworks.md](references/mutation-frameworks.md)
  for details.
- An existing test suite that passes
- **macOS environment**: Run `ulimit -n 1024` before any `mull-runner`
  invocation. macOS Tahoe (26+) sets unlimited file descriptors by
  default, which crashes Mull's subprocess spawning. See
  [references/mutation-frameworks.md](references/mutation-frameworks.md)
  for details.

---

## Rationalizations to Reject

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "All survived mutants need tests" | Many are harmless or equivalent | Triage before writing tests |
| "Mutation testing is too noisy" | Noise means you're not triaging | Use graph data to filter |
| "Unit tests cover everything" | Complex data flows need fuzzing | Check entrypoint reachability |
| "Dead code mutants don't matter" | Dead code should be removed | Flag for cleanup |
| "Low complexity = low risk" | Boundary bugs hide in simple code | Check mutant location |
| "Tool isn't installed, I'll do it manually" | Manual analysis misses what tooling catches | Install the tool first |
| "Necessist isn't mutation testing, skip it" | Necessist finds what mutation testing misses: weak tests | Run both when the language supports it |

---

## Quick Start

```bash
# 1. Build the code graph
uv run trailmark analyze --language auto --summary {targetDir}

# 2. Run mutation testing (language-dependent)
# Python:
uv run mutmut run --paths-to-mutate {targetDir}/src
uv run mutmut results

# 2b. Run necessist (if language supported)
necessist

# 3. Analyze results with this skill's workflow (Phase 3)
```

---

## Workflow Overview

```
Phase 1: Graph Build      → Parse codebase with trailmark
      ↓
Phase 2: Mutation Run     → Execute mutation testing framework
Phase 2b: Necessist Run   → Remove test statements (optional, parallel)
      ↓
Phase 3: Triage           → Classify findings using graph data
      ↓
Output: Categorized Report
  ├── Corroborated         (both tools flag same function — highest value)
  ├── False Positives      (harmless, skip)
  ├── Missing Tests        (write unit tests)
  └── Fuzzing Targets      (set up fuzz harnesses)
```

---

## Decision Tree

```
├─ Need to set up mutation testing for a language?
│  └─ Read: references/mutation-frameworks.md
│
├─ Need to set up necessist or find weak test statements?
│  └─ Read: references/mutation-frameworks.md (Necessist section)
│
├─ Need to understand the triage criteria in depth?
│  └─ Read: references/triage-methodology.md
│
├─ Need to understand how graph data informs triage?
│  └─ Read: references/graph-analysis.md
│
└─ Already have results + graph? Use Phase 3 below.
```

---

## Phase 1: Build Code Graph and Run Pre-Analysis

Parse the target codebase with trailmark and run pre-analysis **before**
mutation testing. Pre-analysis computes blast radius, entry points, privilege
boundaries, and taint propagation, which Phase 3 uses for triage.

```bash
uv run trailmark analyze --language auto --summary {targetDir}
```

Use the `QueryEngine` API to build the graph and run pre-analysis:
1. `QueryEngine.from_directory("{targetDir}", language="auto")`
2. Call `engine.preanalysis()` — **mandatory** before triage
3. Export with `engine.to_json()` for cross-referencing with mutation results

If auto-detection is wrong for the target, rerun with an explicit language or
comma-separated list such as `python,rust`.

See [references/graph-analysis.md](references/graph-analysis.md) for the
full API: node mapping, reachability queries, blast radius, and
pre-analysis subgraph lookups.

---

## Phase 2: Run Mutation Testing

Select and run the appropriate framework. See
[references/mutation-frameworks.md](references/mutation-frameworks.md) for
language-specific setup.

**Capture survived mutants.** Each framework reports differently, but
extract these fields per mutant:

| Field | Description |
|-------|-------------|
| File path | Source file containing the mutant |
| Line number | Line where mutation was applied |
| Mutation type | What was changed (operator, value, etc.) |
| Status | survived, killed, timeout, error |

Filter to **survived** mutants only for Phase 3.

---

## Phase 2b: Run Necessist (Optional)

If the target language is supported (Go, Rust, Solidity/Foundry,
TypeScript/Hardhat, TypeScript/Vitest, Rust/Anchor), run necessist to
find unnecessary test statements. This runs independently of Phase 2 and
can execute in parallel.

```bash
# Auto-detect framework
necessist

# Or target specific test files
necessist tests/test_parser.rs

# Export results
necessist --dump
```

Filter to findings where the test **passed after removal**. See
[references/mutation-frameworks.md](references/mutation-frameworks.md)
for framework-specific configuration and the normalized record format.

Map each removal to a production function using the algorithm in
[references/graph-analysis.md](references/graph-analysis.md).

---

## Phase 3: Triage Findings

For each survived mutant and each necessist removal, determine its
triage bucket using graph data. Necessist removals must first be mapped
to a production function (see
[references/graph-analysis.md](references/graph-analysis.md)).

### Quick Classification (Mutation Testing)

| Signal | Bucket | Reasoning |
|--------|--------|-----------|
| No callers in graph | **False Positive** | Dead code, mutant is unreachable |
| Only test callers | **False Positive** | Test infrastructure, not production |
| Logging/display string | **False Positive** | Cosmetic, no behavioral impact |
| Equivalent mutant | **False Positive** | Behavior unchanged despite mutation |
| Simple function, low CC, no entrypoint path | **Missing Tests** | Unit test is straightforward |
| Error handling path | **Missing Tests** | Should have negative test cases |
| Boundary condition (off-by-one) | **Missing Tests** | Property-based test candidate |
| Pure function, deterministic | **Missing Tests** | Easy to test, high value |
| High CC (>10), entrypoint reachable | **Fuzzing Target** | Complex + exposed = fuzz it |
| Parser/validator/deserializer | **Fuzzing Target** | Structured input handling |
| Many callers (>10) + moderate CC | **Fuzzing Target** | High blast radius |
| Binary/wire protocol handling | **Fuzzing Target** | Fuzzers excel at format testing |

### Quick Classification (Necessist)

| Signal | Bucket | Reasoning |
|--------|--------|-----------|
| Redundant setup or debug call | **False Positive** | Statement genuinely unnecessary |
| Cannot map to production function | **False Positive** | No graph context for triage |
| Call removed, no assertion checks its effect | **Missing Tests** | Test has weak assertions |
| Assertion removed, test still passes | **Missing Tests** | Redundant or insufficient coverage |
| Maps to high-CC entrypoint-reachable function | **Fuzzing Target** | Complex + exposed + weak test |

When both mutation testing and necessist flag the same production
function, mark as **corroborated** — highest confidence finding.

For detailed criteria, see
[references/triage-methodology.md](references/triage-methodology.md).

### Graph Queries for Triage

For each mutant, map it to its containing graph node and use pre-analysis
subgraphs (tainted, high_blast_radius, privilege_boundary) from Phase 1
to classify it. The classification logic checks: no callers → false
positive, privilege boundary → fuzzing, high CC + tainted → fuzzing,
high blast radius → fuzzing, otherwise → missing tests.

See [references/graph-analysis.md](references/graph-analysis.md) for
the `batch_triage` implementation and node mapping functions.

---

## Output Format

Generate a markdown report:

```markdown
# Genotoxic Triage Report

## Summary
- Total survived mutants: N
- Total necessist removals: N
- Corroborated findings: N
- False positives: N (N%)
- Missing test coverage: N (N%)
- Fuzzing targets: N (N%)

## Corroborated Findings
| File | Line | Function | Mutation Signal | Necessist Signal | Action |
|------|------|----------|----------------|------------------|--------|

## False Positives
| File | Line | Mutation | Reason | Source |
|------|------|----------|--------|--------|

## Missing Test Coverage
| File | Line | Function | CC | Callers | Suggested Test | Source |
|------|------|----------|----|---------|----------------|--------|

## Fuzzing Targets
| File | Line | Function | CC | Entrypoint Path | Blast Radius | Source |
|------|------|----------|----|-----------------|--------------|--------|
```

The `Source` column is `mutation`, `necessist`, or `corroborated`.

Write the report to `GENOTOXIC_REPORT.md` in the working directory.

---

## Quality Checklist

Before delivering:

- [ ] Trailmark graph built for target language
- [ ] Mutation framework ran to completion
- [ ] Necessist ran (if language supported) or noted as not applicable
- [ ] All survived mutants triaged (none unclassified)
- [ ] All necessist removals triaged (if applicable)
- [ ] Corroborated findings identified (if both tools ran)
- [ ] False positives have clear justifications
- [ ] Missing test items include suggested test type
- [ ] Fuzzing targets include entrypoint paths and blast radius
- [ ] Report file written to `GENOTOXIC_REPORT.md`
- [ ] User notified with summary statistics

---

## Integration

**trailmark skill:**
- Phase 1: Build code graph, query complexity and entrypoints
- Phase 3: Caller analysis, reachability, blast radius

**property-based-testing skill:**
- Missing test coverage items involving boundary conditions
- Roundtrip/idempotence properties for serialization mutants

**testing-handbook-skills (fuzzing):**
- Fuzzing target items: use `harness-writing`, `cargo-fuzz`, `atheris`

---

## Supporting Documentation

- **[references/mutation-frameworks.md](references/mutation-frameworks.md)** -
  Language-specific framework setup, output parsing, and necessist configuration
- **[references/triage-methodology.md](references/triage-methodology.md)** -
  Detailed triage criteria, edge cases, and worked examples for both
  mutation testing and necessist
- **[references/graph-analysis.md](references/graph-analysis.md)** -
  Graph query patterns, test-to-production mapping, and result merging

---

**First-time users:** Start with Phase 1 (graph build), then run mutations,
then use the Quick Classification table in Phase 3.

**Experienced users:** Jump to Phase 3 and use the Decision Tree to load
specific reference material.
